import "react-native-get-random-values";
import { useMemo, useRef, useState } from "react";
import * as Crypto from "expo-crypto";
import * as FileSystem from "expo-file-system";
import * as SecureStore from "expo-secure-store";
import * as SQLite from "expo-sqlite";
import { Pressable, SafeAreaView, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { unzip } from "react-native-zip-archive";
import {
  AuthV2ZKProvider,
  CircuitArtifactDownloader,
  CircuitArtifactStore,
  CircuitId,
  CircomWitnessNativeCalculator,
  DevelopmentOnlyHolderDidProvider,
  EncryptedCredentialStorage,
  EncryptedIdentityStorage,
  ExpoSecureKeyStore,
  MobileBjjKmsAdapter,
  RapidsnarkNativeProver,
  ReadOnlyMobileGistProofSource,
  SQLiteCredentialRecordStore,
  SQLiteKeyValueStore,
  createPrivadoExpoClient,
  safeCredentialDiagnostics,
  type HolderDidSummary,
  type ImportedCredentialSummary,
  type PrivadoExpoClient,
  type PrivadoExpoConfig,
  type CircuitArtifactDescriptor,
  type CircuitArtifactDownloadStatus,
  type CircuitArtifactFileSystemAdapter,
  type ZipExtractor,
  type SQLiteDatabaseLike
} from "@privado-id/expo-sdk";

const config: PrivadoExpoConfig = {
  network: {
    name: "amoy",
    chainId: 80002,
    rpcUrl: "https://rpc-amoy.polygon.technology"
  },
  contracts: {
    stateContractAddress: "0x0000000000000000000000000000000000000001",
    universalVerifierAddress: "0x0000000000000000000000000000000000000002"
  },
  didResolver: {
    didResolverUrl: "https://resolver.privado.id"
  },
  issuer: {
    issuerDid: "did:iden3:polygon:amoy:x00000000000000000000000000000000",
    issuerBaseUrl: "https://issuer.example"
  },
  credential: {
    credentialType: "KYCAgeCredential",
    credentialSchema: "https://schema.example/kyc-age.json",
    credentialContext: ["https://www.w3.org/2018/credentials/v1"]
  },
  verifier: {
    verifierDid: "did:iden3:polygon:amoy:x00000000000000000000000000000001",
    verifierAddress: "0x0000000000000000000000000000000000000002"
  },
  circuits: {
    artifacts: []
  }
};

const sampleCredential = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  id: "urn:uuid:demo-credential-1",
  type: ["VerifiableCredential", "KYCAgeCredential"],
  issuer: "did:iden3:polygon:amoy:x00000000000000000000000000000000",
  issuanceDate: "2026-01-01T00:00:00.000Z",
  expirationDate: "2027-01-01T00:00:00.000Z",
  credentialSubject: {
    id: "did:iden3:polygon:amoy:x00000000000000000000000000000002",
    birthday: 19900101
  },
  proof: [
    {
      type: "Iden3SparseMerkleTreeProof",
      issuerData: {},
      coreClaim: "0x00"
    }
  ]
};

const sampleCredentialOfferMessage = JSON.stringify(
  {
    id: "demo-offer-message",
    typ: "application/iden3comm-plain-json",
    type: "https://iden3-communication.io/credentials/1.0/offer",
    thid: "demo-offer-thread",
    from: config.issuer?.issuerDid,
    body: {
      url: `${config.issuer?.issuerBaseUrl}/v1/agent`,
      credentials: [
        {
          id: "demo-credential-offer-id",
          description: "Demo credential offer"
        }
      ]
    }
  },
  null,
  2
);

const defaultCircuitZipUrl = "https://gateway.wirawallet.com/circuits/keys.zip";
const requiredDemoCircuits = [
  CircuitId.AuthV2,
  CircuitId.CredentialAtomicQuerySigV2,
  CircuitId.CredentialAtomicQuerySigV2OnChain
];

export default function App() {
  const sdkRef = useMemo<{ current?: PrivadoExpoClient }>(() => ({}), []);
  const circuitArtifactStore = useMemo(() => new CircuitArtifactStore(), []);
  const circuitDownloadLockRef = useRef(false);
  const [importedCredential, setImportedCredential] = useState<unknown>();
  const [summaries, setSummaries] = useState<ImportedCredentialSummary[]>([]);
  const [holderDid, setHolderDid] = useState<HolderDidSummary>();
  const [claimOfferMessage, setClaimOfferMessage] = useState(sampleCredentialOfferMessage);
  const [circuitZipUrl, setCircuitZipUrl] = useState(defaultCircuitZipUrl);
  const [circuitSummaries, setCircuitSummaries] = useState<CircuitSummary[]>([]);
  const [circuitDownloadPhase, setCircuitDownloadPhase] = useState<CircuitDownloadPhase>("idle");
  const [status, setStatus] = useState("Ready");

  async function getSdk(): Promise<PrivadoExpoClient> {
    if (sdkRef.current) {
      return sdkRef.current;
    }

    const database = await SQLite.openDatabaseAsync("privado_id_credentials.db");
    const secureKeyStore = new ExpoSecureKeyStore({
      secureStore: SecureStore,
      secureStoreOptions: {
        keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY
      },
      randomBytes: Crypto.getRandomBytes
    });
    const sqliteDatabase = toSQLiteDatabaseLike(database);
    const recordStore = new SQLiteCredentialRecordStore({
      database: sqliteDatabase
    });
    const mobileMetadataStore = new SQLiteKeyValueStore({
      database: sqliteDatabase
    });
    const credentialStorage = new EncryptedCredentialStorage({
      secureKeyStore,
      recordStore,
      randomBytes: Crypto.getRandomBytes
    });
    const identityStorage = new EncryptedIdentityStorage({
      secureKeyStore
    });
    const kmsAdapter = new MobileBjjKmsAdapter({
      secureKeyStore,
      randomBytes: Crypto.getRandomBytes
    });
    const witnessCalculator = new CircomWitnessNativeCalculator({
      graphReader: createExpoWitnessGraphReader()
    });
    const nativeProver = new RapidsnarkNativeProver({
      fileInspector: createExpoProverFileInspector()
    });
    const zkProvider = new AuthV2ZKProvider({
      witnessCalculator,
      prover: nativeProver
    });

    sdkRef.current = createPrivadoExpoClient(config, {
      secureKeyStore,
      mobileMetadataStore,
      credentialStorage,
      identityStorage,
      kmsAdapter,
      circuitArtifactStore,
      zkProvider,
      authV2WitnessCalculator: witnessCalculator,
      authV2NativeProver: nativeProver,
      developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider()
    });
    return sdkRef.current;
  }

  async function run(label: string, action: () => Promise<unknown> | unknown) {
    try {
      const result = await action();
      setStatus(`${label}: ${formatResult(result)}`);
    } catch (error) {
      setStatus(`${label}: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async function downloadCircuits(): Promise<unknown> {
    if (circuitDownloadLockRef.current) {
      return "Circuit download is already running.";
    }
    circuitDownloadLockRef.current = true;
    setCircuitDownloadPhase("downloading");
    try {
      const downloader = new CircuitArtifactDownloader({
        zipUrl: circuitZipUrl,
        requiredCircuits: requiredDemoCircuits,
        fileSystem: createExpoCircuitFileSystemAdapter(),
        zipExtractor: createReactNativeZipExtractor(),
        artifactStore: circuitArtifactStore,
        version: "downloaded",
        onStatus: (phase) => setCircuitDownloadPhase(phase)
      });
      const result = await downloader.prepare();
      const summaries = result.descriptors.map(toCircuitSummary);
      setCircuitSummaries(summaries);
      setCircuitDownloadPhase("registered");
      return {
        status: result.status,
        circuits: summaries,
        zipPath: summarizePath(result.zipPath),
        extractDir: summarizePath(result.extractDir)
      };
    } catch (error) {
      setCircuitDownloadPhase("error");
      throw error;
    } finally {
      circuitDownloadLockRef.current = false;
    }
  }

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.container}>
        <Text style={styles.title}>Privado ID SDK Demo</Text>
        <Text style={styles.note}>Encrypted SQLite payloads with the encryption key in SecureStore.</Text>
        <View style={styles.toolbar}>
          <DemoButton
            label="Init SDK"
            onPress={() =>
              run("Init", async () => {
                const sdk = await getSdk();
                await sdk.init();
                return "initialized";
              })
            }
          />
          <DemoButton
            label="Import VC JSON"
            onPress={() =>
              run("Import", async () => {
                const sdk = await getSdk();
                const imported = sdk.importCredentialFromJson(JSON.stringify(sampleCredential));
                setImportedCredential(imported.credential);
                return imported.summary;
              })
            }
          />
          <DemoButton
            label="Save credential securely"
            onPress={() =>
              run("Save", async () => {
                const sdk = await getSdk();
                const imported = importedCredential ?? sdk.importCredentialFromJson(JSON.stringify(sampleCredential)).credential;
                const summary = await sdk.saveCredential(imported);
                setSummaries(await sdk.getCredentials());
                return summary;
              })
            }
          />
          <DemoButton
            label="List credentials"
            onPress={() =>
              run("List", async () => {
                const sdk = await getSdk();
                const list = await sdk.getCredentials();
                setSummaries(list);
                return list;
              })
            }
          />
          <DemoButton
            label="Get credential by ID"
            onPress={() =>
              run("Get", async () => {
                const sdk = await getSdk();
                const id = summaries[0]?.id ?? sampleCredential.id;
                const credential = await sdk.getCredentialById(id);
                return credential ? safeCredentialDiagnostics(credential) : "not found";
              })
            }
          />
          <DemoButton
            label="Delete credential"
            onPress={() =>
              run("Delete", async () => {
                const sdk = await getSdk();
                const id = summaries[0]?.id ?? sampleCredential.id;
                await sdk.deleteCredential(id);
                const list = await sdk.getCredentials();
                setSummaries(list);
                return { deleted: id, remaining: list.length };
              })
            }
          />
          <DemoButton
            label="Clear credentials"
            onPress={() =>
              run("Clear", async () => {
                const sdk = await getSdk();
                await sdk.clearCredentials();
                setSummaries([]);
                return "cleared";
              })
            }
          />
          <DemoButton
            label="Download circuits"
            disabled={isCircuitDownloadBusy(circuitDownloadPhase)}
            onPress={() => run("Download circuits", downloadCircuits)}
          />
          <DemoButton
            label="Check circuits"
            onPress={() =>
              run("Check circuits", async () => {
                const results = requiredDemoCircuits.map((circuitId) => ({
                  circuitId,
                  validation: circuitArtifactStore.validate(circuitId, "native"),
                  artifact: circuitArtifactStore.resolve(circuitId)
                }));
                const summaries = results
                  .filter((item) => item.artifact)
                  .map((item) => toCircuitSummary(item.artifact as CircuitArtifactDescriptor));
                setCircuitSummaries(summaries);
                return results.map((item) => ({
                  circuitId: item.circuitId,
                  valid: item.validation.valid,
                  missing: item.validation.missing
                }));
              })
            }
          />
          <DemoButton
            label="Check native prover"
            onPress={() =>
              run("Native prover", async () => {
                const authV2 = circuitArtifactStore.resolve(CircuitId.AuthV2);
                const zkeyPath = authV2?.zkey?.localPath ?? authV2?.zkeyPath;
                if (!zkeyPath) {
                  throw new Error("AuthV2 zkeyPath is required to check native prover.");
                }
                const prover = new RapidsnarkNativeProver();
                const result = await prover.checkAvailable(toNativeFilePath(zkeyPath));
                return {
                  available: result.available,
                  publicBufferSize: result.publicBufferSize
                };
              })
            }
          />
          <DemoButton
            label="Check witness calculator"
            onPress={() =>
              run("Witness calculator", async () => {
                const calculator = new CircomWitnessNativeCalculator();
                const result = await calculator.isAvailable();
                return {
                  available: result.available,
                  message: result.message
                };
              })
            }
          />
          <TextInput
            accessibilityLabel="Circuit ZIP URL"
            value={circuitZipUrl}
            onChangeText={setCircuitZipUrl}
            style={styles.singleLineInput}
            autoCapitalize="none"
          />
          <DemoButton
            label="Create/load real Holder DID"
            onPress={() =>
              run("Real Holder DID", async () => {
                ensureCryptoGetRandomValues();
                if (!hasSecureRandomProvider()) {
                  throw new Error("Secure random provider is not available in this Expo runtime.");
                }
                const sdk = await getSdk();
                const result = await sdk.createOrLoadHolderDid({
                  mode: "real",
                  method: "iden3",
                  network: config.network.name
                });
                setHolderDid(result);
                return result;
              })
            }
          />
          <DemoButton
            label="Create/load development Holder DID"
            onPress={() =>
              run("Development Holder DID", async () => {
                const sdk = await getSdk();
                const result = await sdk.createOrLoadHolderDid({
                  mode: "development",
                  method: "development",
                  network: config.network.name
                });
                setHolderDid(result);
                return result;
              })
            }
          />
          <DemoButton
            label="Get Holder DID"
            onPress={() =>
              run("Get Holder", async () => {
                const sdk = await getSdk();
                const result = await sdk.getHolderDid();
                setHolderDid(result);
                return result ?? "not found";
              })
            }
          />
          <DemoButton
            label="Sign test challenge"
            onPress={() =>
              run("Sign", async () => {
                const sdk = await getSdk();
                const identity = holderDid ?? (await sdk.createOrLoadHolderDid({
                  mode: "development",
                  method: "development",
                  network: config.network.name
                }));
                setHolderDid(identity);
                const signature = await sdk.signChallenge({
                  challenge: "privado-id-demo-challenge",
                  keyId: identity.keyId
                });
                return summarizeSignature(signature);
              })
            }
          />
          <DemoButton
            label="Delete Holder Identity"
            onPress={() =>
              run("Delete Holder", async () => {
                const sdk = await getSdk();
                const result = await sdk.deleteHolderIdentity();
                setHolderDid(undefined);
                return result;
              })
            }
          />
          <TextInput
            accessibilityLabel="Credential offer message"
            multiline
            value={claimOfferMessage}
            onChangeText={setClaimOfferMessage}
            style={styles.input}
          />
          <DemoButton
            label="Claim VC from offer"
            onPress={() =>
              run("Claim", async () => {
                ensureCryptoGetRandomValues();
                if (!hasSecureRandomProvider()) {
                  throw new Error("Secure random provider is not available in this Expo runtime.");
                }
                const sdk = await getSdk();
                const identity = holderDid ?? (await sdk.createOrLoadHolderDid({
                  mode: "real",
                  method: "iden3",
                  network: config.network.name
                }));
                setHolderDid(identity);
                const result = await sdk.claimCredentialFromOffer({
                  message: claimOfferMessage,
                  holderDid: identity.did
                });
                const list = await sdk.getCredentials();
                setSummaries(list);
                return result;
              })
            }
          />
          <DemoButton
            label="Check AuthV2 inputs"
            onPress={() =>
              run("AuthV2 inputs", async () => {
                const sdk = await getSdk();
                const identity = holderDid ?? (await sdk.createOrLoadHolderDid({
                  mode: "real",
                  method: "iden3",
                  network: config.network.name
                }));
                setHolderDid(identity);
                const preview = await sdk.buildAuthV2InputsPreview({
                  message: claimOfferMessage,
                  holderDid: identity.did
                });
                return {
                  status: preview.ready ? "AuthV2 inputs: native-ready" : "AuthV2 inputs: not ready",
                  nativeReady: preview.nativeReady,
                  fields: preview.fields.length,
                  authClaimSlots: preview.authClaimSlots,
                  challenge: preview.challenge,
                  authClaimIncMtpSiblings: preview.siblingsCount,
                  authClaimNonRevMtpSiblings: preview.nonRevSiblingsCount,
                  gistMtpSiblings: preview.gistSiblingsCount,
                  rootsStatePresent: preview.rootsStatePresent,
                  signaturePresent: preview.signaturePresent
                };
              })
            }
          />
          <DemoButton
            label="Generate AuthV2 witness only"
            onPress={() =>
              run("AuthV2 witness", async () => {
                const sdk = await getSdk();
                const identity = holderDid ?? (await sdk.createOrLoadHolderDid({
                  mode: "real",
                  method: "iden3",
                  network: config.network.name
                }));
                setHolderDid(identity);
                return sdk.generateAuthV2WitnessOnly({
                  message: claimOfferMessage,
                  holderDid: identity.did
                });
              })
            }
          />
          <DemoButton
            label="Generate AuthV2 proof only"
            onPress={() =>
              run("AuthV2 proof", async () => {
                const sdk = await getSdk();
                const identity = holderDid ?? (await sdk.createOrLoadHolderDid({
                  mode: "real",
                  method: "iden3",
                  network: config.network.name
                }));
                setHolderDid(identity);
                return sdk.generateAuthV2ProofOnly({
                  message: claimOfferMessage,
                  holderDid: identity.did
                });
              })
            }
          />
          <DemoButton
            label="Check GIST proof"
            onPress={() =>
              run("GIST", async () => {
                const sdk = await getSdk();
                const identity = holderDid ?? (await sdk.getHolderDid());
                if (!identity) {
                  throw new Error("No holder identity loaded.");
                }
                const gistProofSource = new ReadOnlyMobileGistProofSource({
                  didResolverUrl: config.didResolver.didResolverUrl,
                  chainId: config.network.chainId,
                  rpcUrl: config.network.rpcUrl,
                  stateContractAddress: config.contracts.stateContractAddress
                });
                const proof = await gistProofSource.getGISTProof(identity.did, {
                  network: identity.network,
                  isStateGenesis: true
                });
                if (!proof) {
                  throw new Error("AuthV2 GIST proof could not be generated safely.");
                }
                return {
                  source: proof.source,
                  root: proof.root,
                  existence: proof.existence,
                  siblings: proof.siblings.length
                };
              })
            }
          />
        </View>

        <Text style={styles.sectionTitle}>Status</Text>
        <Text style={styles.status}>{status}</Text>

        <Text style={styles.sectionTitle}>Credential summaries</Text>
        {summaries.map((summary) => (
          <View key={summary.id} style={styles.summary}>
            <Text style={styles.summaryTitle}>{summary.id}</Text>
            <Text style={styles.summaryLine}>Types: {summary.type.join(", ")}</Text>
            <Text style={styles.summaryLine}>Issuer: {summary.issuer ?? "Unknown"}</Text>
            <Text style={styles.summaryLine}>Subject: {summary.credentialSubjectId ?? "Unknown"}</Text>
            <Text style={styles.summaryLine}>Proofs: {summary.proofTypes.join(", ") || "None"}</Text>
            <Text style={styles.summaryLine}>Created: {summary.createdAt ?? "Unknown"}</Text>
            <Text style={styles.summaryLine}>Updated: {summary.updatedAt ?? "Unknown"}</Text>
          </View>
        ))}

        <Text style={styles.sectionTitle}>Holder DID</Text>
        {holderDid ? (
          <View style={styles.summary}>
            <Text style={styles.summaryTitle}>{holderDid.did}</Text>
            <Text style={styles.summaryLine}>Key: {holderDid.keyId}</Text>
            <Text style={styles.summaryLine}>Method: {holderDid.method ?? "Unknown"}</Text>
            <Text style={styles.summaryLine}>Network: {holderDid.network ?? "Unknown"}</Text>
            <Text style={styles.summaryLine}>Created: {holderDid.createdAt}</Text>
            <Text style={styles.summaryLine}>Updated: {holderDid.updatedAt}</Text>
            <Text style={styles.summaryLine}>Development only: {holderDid.developmentOnly ? "Yes" : "No"}</Text>
          </View>
        ) : (
          <Text style={styles.status}>No holder identity loaded.</Text>
        )}

        <Text style={styles.sectionTitle}>Circuit assets</Text>
        <Text style={styles.status}>Circuit download: {circuitDownloadPhase}</Text>
        <Text style={styles.status}>ZKProvider: AuthV2 configured with witness calculator and native prover.</Text>
        {circuitSummaries.length > 0 ? (
          circuitSummaries.map((summary) => (
            <View key={summary.circuitId} style={styles.summary}>
              <Text style={styles.summaryTitle}>{summary.circuitId}</Text>
              <Text style={styles.summaryLine}>Version: {summary.version ?? "Unknown"}</Text>
              <Text style={styles.summaryLine}>Graph: {summary.graphPath ?? "Missing"}</Text>
              <Text style={styles.summaryLine}>ZKey: {summary.zkeyPath ?? "Missing"}</Text>
              <Text style={styles.summaryLine}>Dat: {summary.datPath ?? "Optional missing"}</Text>
            </View>
          ))
        ) : (
          <Text style={styles.status}>No circuit assets registered.</Text>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

type CircuitSummary = {
  circuitId: string;
  version?: string;
  graphPath?: string;
  zkeyPath?: string;
  datPath?: string;
};

type CircuitDownloadPhase =
  | "idle"
  | CircuitArtifactDownloadStatus
  | "error";

function DemoButton({ label, onPress, disabled = false }: { label: string; onPress: () => void; disabled?: boolean }) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled }}
      disabled={disabled}
      style={({ pressed }) => [styles.button, pressed && styles.buttonPressed, disabled && styles.buttonDisabled]}
      onPress={onPress}
    >
      <Text style={styles.buttonText}>{label}</Text>
    </Pressable>
  );
}

function formatResult(value: unknown): string {
  if (value === undefined) {
    return "done";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value, null, 2);
}

function summarizeSignature(value: {
  keyId: string;
  algorithm: string;
  signature: string;
  signatureEncoding: string;
  developmentOnly?: boolean;
}) {
  return {
    keyId: value.keyId,
    algorithm: value.algorithm,
    signatureEncoding: value.signatureEncoding,
    signaturePreview: `${value.signature.slice(0, 12)}...`,
    signatureLength: value.signature.length,
    developmentOnly: value.developmentOnly
  };
}

function createExpoCircuitFileSystemAdapter(): CircuitArtifactFileSystemAdapter {
  return {
    cacheDirectory: FileSystem.cacheDirectory ?? undefined,
    documentDirectory: FileSystem.documentDirectory ?? undefined,
    exists: async (path) => (await FileSystem.getInfoAsync(path)).exists,
    makeDirectory: async (path) => {
      const info = await FileSystem.getInfoAsync(path);
      if (!info.exists) {
        await FileSystem.makeDirectoryAsync(path, { intermediates: true });
      }
    },
    downloadFile: async (url, destinationPath) => {
      const result = await FileSystem.downloadAsync(url, destinationPath);
      return { path: result.uri };
    },
    deleteFile: async (path) => {
      const info = await FileSystem.getInfoAsync(path);
      if (info.exists) {
        await FileSystem.deleteAsync(path, { idempotent: true });
      }
    }
  };
}

function createReactNativeZipExtractor(): ZipExtractor {
  return {
    extract: async (zipPath, destinationDir) => {
      await unzip(toNativeFilePath(zipPath), toNativeFilePath(destinationDir));
    }
  };
}

function createExpoWitnessGraphReader() {
  return {
    readGraphBase64: async (graphPath: string) => {
      if (!graphPath.endsWith(".wcd")) {
        throw new Error("AuthV2 witness graph must be a .wcd artifact.");
      }
      const info = await FileSystem.getInfoAsync(graphPath, { size: true });
      if (!info.exists) {
        throw new Error("AuthV2 witness graph file does not exist.");
      }
      const sizeBytes = "size" in info && typeof info.size === "number" ? info.size : undefined;
      if (sizeBytes !== undefined && sizeBytes <= 0) {
        throw new Error("AuthV2 witness graph file is empty.");
      }
      const base64 = await FileSystem.readAsStringAsync(graphPath, {
        encoding: FileSystem.EncodingType.Base64
      });
      return {
        base64,
        sizeBytes
      };
    }
  };
}

function createExpoProverFileInspector() {
  return {
    inspectFile: async (path: string) => {
      const info = await FileSystem.getInfoAsync(path, { size: true });
      return {
        exists: info.exists,
        sizeBytes: info.exists && "size" in info && typeof info.size === "number" ? info.size : undefined
      };
    }
  };
}

function toCircuitSummary(descriptor: CircuitArtifactDescriptor): CircuitSummary {
  return {
    circuitId: descriptor.circuitId,
    version: descriptor.version,
    graphPath: summarizePath(descriptor.graph?.localPath ?? descriptor.graphPath),
    zkeyPath: summarizePath(descriptor.zkey?.localPath ?? descriptor.zkeyPath),
    datPath: summarizePath(descriptor.dat?.localPath ?? descriptor.datPath)
  };
}

function summarizePath(path: string | undefined): string | undefined {
  if (!path) {
    return undefined;
  }
  const parts = path.split("/");
  return parts.slice(Math.max(0, parts.length - 3)).join("/");
}

function summarizeError(message: string): string {
  return message.split(/\r?\n/)[0]?.slice(0, 160) ?? "validation failed";
}

function toNativeFilePath(path: string): string {
  return path.replace(/^file:\/\//, "");
}

function isCircuitDownloadBusy(phase: CircuitDownloadPhase): boolean {
  return phase === "downloading" || phase === "extracting" || phase === "validating";
}

function hasSecureRandomProvider(): boolean {
  return typeof globalThis.crypto?.getRandomValues === "function";
}

function ensureCryptoGetRandomValues(): void {
  if (hasSecureRandomProvider()) {
    return;
  }

  const target = globalThis as typeof globalThis & {
    crypto?: {
      getRandomValues?: <T extends ArrayBufferView | null>(array: T) => T;
    };
  };
  target.crypto = target.crypto ?? {};
  target.crypto.getRandomValues = <T extends ArrayBufferView | null>(array: T): T => {
    if (!array || !ArrayBuffer.isView(array)) {
      throw new TypeError("crypto.getRandomValues requires a typed array.");
    }
    const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
    let offset = 0;
    while (offset < view.byteLength) {
      const chunkLength = Math.min(65536, view.byteLength - offset);
      view.set(Crypto.getRandomBytes(chunkLength), offset);
      offset += chunkLength;
    }
    return array;
  };
}

function toSQLiteDatabaseLike(database: SQLite.SQLiteDatabase): SQLiteDatabaseLike {
  return {
    execAsync: (source) => database.execAsync(source),
    runAsync: (source, params = []) => database.runAsync(source, params as never),
    getAllAsync: <T,>(source: string, params = []) => database.getAllAsync<T>(source, params as never),
    getFirstAsync: <T,>(source: string, params = []) => database.getFirstAsync<T>(source, params as never)
  };
}

const styles = StyleSheet.create({
  safe: {
    flex: 1,
    backgroundColor: "#f7f8fa"
  },
  container: {
    padding: 20,
    gap: 14
  },
  title: {
    fontSize: 24,
    fontWeight: "700",
    color: "#111827"
  },
  note: {
    color: "#4b5563",
    fontSize: 13,
    lineHeight: 18
  },
  toolbar: {
    gap: 10
  },
  button: {
    minHeight: 44,
    justifyContent: "center",
    borderRadius: 8,
    backgroundColor: "#1f2937",
    paddingHorizontal: 14
  },
  buttonPressed: {
    opacity: 0.72
  },
  buttonDisabled: {
    opacity: 0.45
  },
  buttonText: {
    color: "#ffffff",
    fontSize: 15,
    fontWeight: "600"
  },
  sectionTitle: {
    marginTop: 10,
    fontSize: 16,
    fontWeight: "700",
    color: "#111827"
  },
  status: {
    borderRadius: 8,
    backgroundColor: "#ffffff",
    color: "#111827",
    padding: 12,
    fontSize: 13
  },
  input: {
    minHeight: 130,
    borderRadius: 8,
    backgroundColor: "#ffffff",
    color: "#111827",
    padding: 12,
    fontSize: 13,
    textAlignVertical: "top"
  },
  singleLineInput: {
    minHeight: 44,
    borderRadius: 8,
    backgroundColor: "#ffffff",
    color: "#111827",
    paddingHorizontal: 12,
    fontSize: 13
  },
  summary: {
    borderRadius: 8,
    backgroundColor: "#ffffff",
    padding: 12,
    gap: 4
  },
  summaryTitle: {
    color: "#111827",
    fontSize: 14,
    fontWeight: "700"
  },
  summaryLine: {
    color: "#4b5563",
    fontSize: 13
  }
});
