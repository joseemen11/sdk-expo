import "react-native-get-random-values";
import { useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
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
  JsonLdContextStore,
  MobileBjjKmsAdapter,
  RapidsnarkNativeProver,
  ReadOnlyMobileGistProofSource,
  SQLiteCredentialRecordStore,
  SQLiteKeyValueStore,
  createPrivadoExpoClient,
  prepareUniversalVerifierCalldataDebug,
  safeCredentialDiagnostics,
  type HolderDidSummary,
  type ImportedCredentialSummary,
  type IssuerClaimDebugStep,
  type GeneratedProof,
  type PrivadoExpoClient,
  type PrivadoExpoConfig,
  type CircuitArtifactDescriptor,
  type CircuitArtifactDownloadStatus,
  type CircuitArtifactFileSystemAdapter,
  type ZipExtractor,
  type SQLiteDatabaseLike
} from "@privado-id/expo-sdk";
import { bundledJsonLdContexts } from "./BundledJsonLdContexts";
import { SigV2JsonLdValueProofProvider } from "./SigV2JsonLdValueProofProvider";

declare const process: { env?: Record<string, string | undefined> };

function expoPublicEnv(key: string, fallback: string): string {
  const value = process.env?.[`EXPO_PUBLIC_${key}`];
  return value && value.trim() ? value.trim() : fallback;
}

function expoPublicEnvNumber(key: string, fallback: number): number {
  const value = process.env?.[`EXPO_PUBLIC_${key}`];
  if (!value || !value.trim()) {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeDemoNetworkName(value: string): string {
  return value === "polygon-amoy" ? "amoy" : value;
}

const defaultNetworkName = normalizeDemoNetworkName(expoPublicEnv("NETWORK", "amoy"));
const defaultChainId = expoPublicEnvNumber("CHAIN_ID", 80002);
const defaultRpcUrl = expoPublicEnv("RPC_URL", "https://polygon-amoy.g.alchemy.com/v2/6EZHDQVUhsjL9XoYhmhXg");
const defaultUniversalVerifierAddress = expoPublicEnv(
  "UNIVERSAL_VERIFIER_ADDRESS",
  "0xfcc86A79fCb057A8e55C6B853dff9479C3cf607c"
);
const defaultStateContractAddress = expoPublicEnv(
  "STATE_CONTRACT_ADDRESS",
  "0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124"
);
const defaultDidResolverUrl = expoPublicEnv("DID_RESOLVER_URL", "https://resolver.privado.id");
const defaultIssuerAdminBase = expoPublicEnv("ISSUER_ADMIN_BASE", "https://issuer.wirawallet.com");
const defaultIssuerDid = expoPublicEnv(
  "ISSUER_DID",
  "did:polygonid:polygon:amoy:2qTUPXNF422khVhMArC491vwLE6eEbMUvRgXj5EHdX"
);
const defaultIssuerBasicUser = expoPublicEnv("ISSUER_BASIC_USER", "user-issuer");
const defaultIssuerBasicPass = expoPublicEnv("ISSUER_BASIC_PASS", "");
const defaultCredentialSchema = expoPublicEnv(
  "CREDENTIAL_SCHEMA",
  "https://ipfs.io/ipfs/QmeQhwtwP6XNG155M49yV6TFmm6s8er13WfeU7tcuM8eat"
);
const defaultCredentialContext = expoPublicEnv(
  "CREDENTIAL_CONTEXT",
  "https://ipfs.io/ipfs/QmbaL4bG16tTYqAzn35qztT6cqTRZT1FMRfkcp5SLTDW2T"
);
const defaultCredentialType = expoPublicEnv("CREDENTIAL_TYPE", "PersonCredential");
const defaultCredentialValue = expoPublicEnvNumber("CREDENTIAL_VALUE", 946684800);
const defaultCredentialExpirationDays = expoPublicEnvNumber("CREDENTIAL_EXPIRATION_DAYS", 365);
const defaultOnchainRequestId = expoPublicEnv("ONCHAIN_REQUEST_ID", "1782204596");
const defaultOnchainValidatorAddress = expoPublicEnv(
  "VALIDATOR_V3_ADDRESS",
  "0xC616963610A5545EF89b373e1fEAE8A1e505FaFF"
);
const defaultOnchainChallengeAddress = expoPublicEnv(
  "ONCHAIN_CHALLENGE_ADDRESS",
  "0x176A3cd0e7d9B0936f594015eADF313Fd46558E7"
);

const config: PrivadoExpoConfig = {
  network: {
    name: defaultNetworkName,
    chainId: defaultChainId,
    rpcUrl: defaultRpcUrl
  },
  contracts: {
    stateContractAddress: defaultStateContractAddress,
    universalVerifierAddress: defaultUniversalVerifierAddress
  },
  didResolver: {
    didResolverUrl: defaultDidResolverUrl
  },
  issuer: {
    issuerDid: defaultIssuerDid,
    issuerBaseUrl: defaultIssuerAdminBase
  },
  credential: {
    credentialType: defaultCredentialType,
    credentialSchema: defaultCredentialSchema,
    credentialContext: defaultCredentialContext,
    credentialExpirationDays: defaultCredentialExpirationDays
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
const evmPrivateKeySecureStoreKey = "privado-id.demo.evm-private-key";
const issuerBasicPasswordSecureStoreKey = "privado-id.demo.issuer-basic-password";
const requiredDemoCircuits = [
  CircuitId.AuthV2,
  CircuitId.CredentialAtomicQuerySigV2,
  CircuitId.CredentialAtomicQuerySigV2OnChain
];

export default function App() {
  const sdkRef = useMemo<{ current?: PrivadoExpoClient }>(() => ({}), []);
  const circuitArtifactStore = useMemo(() => new CircuitArtifactStore(), []);
  const circuitDownloadLockRef = useRef(false);
  const onchainPreparedProofRef = useRef<{
    preparedProof: GeneratedProof;
    requestId: string;
    challengeAddress: string;
    directVerifierDebugPath?: string;
    circuitInputsDebugPath?: string;
  } | undefined>(undefined);
  const [importedCredential, setImportedCredential] = useState<unknown>();
  const [summaries, setSummaries] = useState<ImportedCredentialSummary[]>([]);
  const [holderDid, setHolderDid] = useState<HolderDidSummary>();
  const [claimOfferMessage, setClaimOfferMessage] = useState(sampleCredentialOfferMessage);
  const [circuitZipUrl, setCircuitZipUrl] = useState(defaultCircuitZipUrl);
  const [issuerAdminBase, setIssuerAdminBase] = useState(defaultIssuerAdminBase);
  const [issuerDid, setIssuerDid] = useState(defaultIssuerDid);
  const [issuerBasicUser, setIssuerBasicUser] = useState(defaultIssuerBasicUser);
  const [issuerBasicPass, setIssuerBasicPass] = useState(defaultIssuerBasicPass);
  const [issuerCredentialType, setIssuerCredentialType] = useState(defaultCredentialType);
  const [issuerCredentialSchema, setIssuerCredentialSchema] = useState(defaultCredentialSchema);
  const [issuerCredentialContext, setIssuerCredentialContext] = useState(defaultCredentialContext);
  const [evmPrivateKey, setEvmPrivateKey] = useState("");
  const [circuitSummaries, setCircuitSummaries] = useState<CircuitSummary[]>([]);
  const [circuitDownloadPhase, setCircuitDownloadPhase] = useState<CircuitDownloadPhase>("idle");
  const [status, setStatus] = useState("Ready");
  const [runningAction, setRunningAction] = useState<string>();

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

    sdkRef.current = createPrivadoExpoClient(createConfiguredDemoConfig({
      issuerAdminBase,
      issuerDid,
      issuerBasicUser,
      issuerBasicPass,
      credentialType: issuerCredentialType,
      credentialSchema: issuerCredentialSchema,
      credentialContext: issuerCredentialContext
    }), {
      secureKeyStore,
      mobileMetadataStore,
      credentialStorage,
      identityStorage,
      kmsAdapter,
      circuitArtifactStore,
      zkProvider,
      authV2WitnessCalculator: witnessCalculator,
      authV2NativeProver: nativeProver,
      credentialAtomicQuerySigV2ValueProofProvider: new SigV2JsonLdValueProofProvider({
        contextStore: createDemoJsonLdContextStore(),
        contextUrls: normalizeContextUrls(issuerCredentialContext)
      }),
      developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider()
    });
    return sdkRef.current;
  }

  async function run(label: string, action: () => Promise<unknown> | unknown) {
    if (runningAction) {
      setStatus(`${label}: ${runningAction} is already running.`);
      return;
    }
    setRunningAction(label);
    try {
      const result = await action();
      setStatus(`${label}: ${formatResult(result)}`);
    } catch (error) {
      setStatus(`${label}: ${error instanceof Error ? error.message : "Unknown error"}`);
    } finally {
      setRunningAction((current) => (current === label ? undefined : current));
    }
  }

  async function refreshCredentialSummaries(): Promise<ImportedCredentialSummary[]> {
    const sdk = await getSdk();
    const list = await sdk.getCredentials();
    setSummaries(list);
    return list;
  }

  async function loadIssuerBasicPassword(): Promise<string> {
    // Demo-only secret handling: production apps should inject issuer credentials from their own secure config.
    const password = await SecureStore.getItemAsync(issuerBasicPasswordSecureStoreKey);
    if (!password) {
      return "No issuer password saved in SecureStore.";
    }
    resetSdkValue(sdkRef, setIssuerBasicPass, password);
    return "Issuer password loaded from SecureStore.";
  }

  async function saveIssuerBasicPassword(): Promise<string> {
    if (!issuerBasicPass) {
      throw new Error("Issuer Basic password is required before saving.");
    }
    await SecureStore.setItemAsync(issuerBasicPasswordSecureStoreKey, issuerBasicPass, {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY
    });
    return "Issuer password saved in SecureStore.";
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

  async function ensureSigV2CircuitArtifacts(
    circuitId: CircuitId.CredentialAtomicQuerySigV2 | CircuitId.CredentialAtomicQuerySigV2OnChain =
      CircuitId.CredentialAtomicQuerySigV2
  ): Promise<unknown> {
    let validation = circuitArtifactStore.validate(circuitId, "native");
    if (!validation.valid) {
      await downloadCircuits();
      validation = circuitArtifactStore.validate(circuitId, "native");
    }
    const artifact = circuitArtifactStore.resolve(circuitId);
    if (!artifact || !validation.valid) {
      throw new Error(`${circuitId} artifacts are missing: ${validation.missing.join(", ") || "descriptor"}.`);
    }
    const graphPath = artifact.graph?.localPath ?? artifact.graphPath;
    const zkeyPath = artifact.zkey?.localPath ?? artifact.zkeyPath;
    if (!graphPath || !zkeyPath) {
      throw new Error(`${circuitId} artifacts are incomplete.`);
    }
    const [graphInfo, zkeyInfo] = await Promise.all([
      FileSystem.getInfoAsync(graphPath, { size: true }),
      FileSystem.getInfoAsync(zkeyPath, { size: true })
    ]);
    const graphSize = graphInfo.exists ? (graphInfo as { size?: number }).size ?? 0 : 0;
    const zkeySize = zkeyInfo.exists ? (zkeyInfo as { size?: number }).size ?? 0 : 0;
    if (!graphInfo.exists || graphSize <= 0) {
      throw new Error(`${circuitId} graph artifact is missing or empty.`);
    }
    if (!zkeyInfo.exists || zkeySize <= 0) {
      throw new Error(`${circuitId} zkey artifact is missing or empty.`);
    }
    const summaries = requiredDemoCircuits
      .map((requiredCircuitId) => circuitArtifactStore.resolve(requiredCircuitId))
      .filter((descriptor): descriptor is CircuitArtifactDescriptor => Boolean(descriptor))
      .map(toCircuitSummary);
    setCircuitSummaries(summaries);
    return {
      circuitId,
      graphExists: true,
      graphSizeBytes: graphSize,
      zkeyExists: true,
      zkeySizeBytes: zkeySize
    };
  }

  async function ensureJsonLdContextsForLatestCredential(): Promise<unknown> {
    const sdk = await getSdk();
    const list = summaries.length > 0 ? summaries : await refreshCredentialSummaries();
    const summary = selectLatestCredentialSummary(list);
    if (!summary) {
      throw new Error("No saved credential available for JSON-LD context check.");
    }
    const credential = await sdk.getCredentialById(summary.id);
    if (!credential) {
      throw new Error("Saved credential was not found for JSON-LD context check.");
    }
    const contextStore = createDemoJsonLdContextStore();
    const result = await ensureContextsForCredentialWithSummary(
      contextStore,
      credential,
      normalizeContextUrls(issuerCredentialContext)
    );
    return {
      credentialId: summary.id,
      totalContexts: result.totalContexts,
      bundled: result.bundled,
      cached: result.cached,
      fetched: result.fetched,
      missing: result.missing.length
    };
  }

  async function prepareOnchainProofForLatestCredential(): Promise<{
    preparedProof: GeneratedProof;
    summary: Awaited<ReturnType<PrivadoExpoClient["generateCredentialAtomicQuerySigV2OnChainProof"]>>;
    requestId: string;
    challengeAddress: string;
    directVerifierDebugPath?: string;
    circuitInputsDebugPath?: string;
  }> {
    const sdk = await getSdk();
    await ensureSigV2CircuitArtifacts(CircuitId.CredentialAtomicQuerySigV2OnChain);
    const list = summaries.length > 0 ? summaries : await refreshCredentialSummaries();
    const summary = selectLatestCredentialSummary(list);
    if (!summary) {
      throw new Error("No saved credential available for credential proof.");
    }
    const prepared = await sdk.generateCredentialAtomicQuerySigV2OnChainPreparedProof({
      credentialId: summary.id,
      credentialType: summary.type.find((item) => item !== "VerifiableCredential") ?? issuerCredentialType,
      issuerDid: summary.issuer,
      schema: issuerCredentialSchema,
      query: {
        field: "birthDate",
        operator: "lt",
        value: defaultCredentialValue
      },
      mode: "onchain",
      onchain: {
        requestId: defaultOnchainRequestId,
        universalVerifierAddress: config.contracts.universalVerifierAddress,
        validatorAddress: defaultOnchainValidatorAddress,
        challengeAddress: defaultOnchainChallengeAddress
      }
    });
    const directVerifierDebugPath = FileSystem.documentDirectory
      ? `${FileSystem.documentDirectory}sigv2-onchain-direct-verifier-debug.json`
      : undefined;
    if (directVerifierDebugPath) {
      await FileSystem.writeAsStringAsync(
        directVerifierDebugPath,
        JSON.stringify({
          preparedProof: prepared.preparedProof,
          proofSource: prepared.summary.proofSource,
          publicSignalsSource: prepared.summary.publicSignalsSource
        })
      );
    }
    const circuitInputsDebugPath = FileSystem.documentDirectory
      ? `${FileSystem.documentDirectory}sigv2-onchain-circuit-inputs-debug.json`
      : undefined;
    if (circuitInputsDebugPath && prepared.debugCircuitInputs) {
      const artifact = circuitArtifactStore.resolve(CircuitId.CredentialAtomicQuerySigV2OnChain);
      await FileSystem.writeAsStringAsync(
        circuitInputsDebugPath,
        JSON.stringify({
          metadata: {
            circuitId: prepared.debugCircuitInputs.circuitId,
            requestId: prepared.debugCircuitInputs.requestId,
            credentialType: prepared.debugCircuitInputs.credentialType,
            field: prepared.debugCircuitInputs.field,
            operator: prepared.debugCircuitInputs.operator,
            value: prepared.debugCircuitInputs.value,
            wcdSha256:
              artifact?.hashes?.graph ??
              artifact?.graph?.sha256 ??
              "not-computed-in-demo",
            zkeySha256:
              artifact?.hashes?.zkey ??
              artifact?.zkey?.sha256 ??
              "not-computed-in-demo",
            graphPath: prepared.debugCircuitInputs.graphPath,
            zkeyPath: prepared.debugCircuitInputs.zkeyPath,
            inputKeys: prepared.debugCircuitInputs.inputKeys,
            challengeEncoding: prepared.debugCircuitInputs.challengeEncoding,
            challengeSignatureValid: prepared.debugCircuitInputs.challengeSignatureValid,
            issuerClaimSignatureValid: prepared.debugCircuitInputs.issuerClaimSignatureValid,
            inputBuilderFailureLayer: prepared.debugCircuitInputs.inputBuilderFailureLayer
          },
          inputs: prepared.debugCircuitInputs.inputs
        })
      );
    }
    onchainPreparedProofRef.current = {
      preparedProof: prepared.preparedProof,
      requestId: String(prepared.preparedProof.request.id),
      challengeAddress: prepared.summary.challengeAddress ?? defaultOnchainChallengeAddress.toLowerCase(),
      directVerifierDebugPath,
      circuitInputsDebugPath
    };
    return {
      ...prepared,
      requestId: String(prepared.preparedProof.request.id),
      challengeAddress: prepared.summary.challengeAddress ?? defaultOnchainChallengeAddress.toLowerCase(),
      directVerifierDebugPath,
      circuitInputsDebugPath
    };
  }

  const isActionRunning = Boolean(runningAction);
  const buttonState = (actionLabel: string, loadingLabel: string) => ({
    disabled: isActionRunning,
    loading: runningAction === actionLabel,
    loadingLabel
  });

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.container}>
        <Text style={styles.title}>Privado ID SDK Demo</Text>
        <Text style={styles.note}>Encrypted SQLite payloads with the encryption key in SecureStore.</Text>
        <View style={styles.toolbar}>
          <StepSection title="Paso 1: Init SDK / Holder DID">
            <DemoButton
              label="Init SDK"
              {...buttonState("Init", "Loading...")}
              onPress={() =>
                run("Init", async () => {
                  const sdk = await getSdk();
                  await sdk.init();
                  return "initialized";
                })
              }
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
          </StepSection>

          <StepSection title="Paso 2: Circuits">
            <TextInput
              accessibilityLabel="Circuit ZIP URL"
              value={circuitZipUrl}
              onChangeText={setCircuitZipUrl}
              style={styles.singleLineInput}
              autoCapitalize="none"
            />
            <DemoButton
              label="Download circuits"
              disabled={isActionRunning || isCircuitDownloadBusy(circuitDownloadPhase)}
              loading={runningAction === "Download circuits" || isCircuitDownloadBusy(circuitDownloadPhase)}
              loadingLabel="Loading..."
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
          </StepSection>

          <StepSection title="Paso 3: AuthV2 proof">
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
                    siblings: proof.siblings.length,
                    debug: gistProofSource.getLastDebugInfo()
                  };
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
              label="Generate AuthV2 proof only"
              {...buttonState("AuthV2 proof", "Generating...")}
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
          </StepSection>

          <StepSection title="Paso 4: Claim VC from issuer">
            <TextInput
              accessibilityLabel="Issuer admin base"
              value={issuerAdminBase}
              onChangeText={(value) => resetSdkValue(sdkRef, setIssuerAdminBase, value)}
              style={styles.singleLineInput}
              autoCapitalize="none"
            />
            <TextInput
              accessibilityLabel="Issuer DID"
              value={issuerDid}
              onChangeText={(value) => resetSdkValue(sdkRef, setIssuerDid, value)}
              style={styles.singleLineInput}
              autoCapitalize="none"
            />
            <TextInput
              accessibilityLabel="Issuer Basic user"
              value={issuerBasicUser}
              onChangeText={(value) => resetSdkValue(sdkRef, setIssuerBasicUser, value)}
              style={styles.singleLineInput}
              autoCapitalize="none"
            />
            <TextInput
              accessibilityLabel="Issuer Basic password"
              value={issuerBasicPass}
              onChangeText={(value) => resetSdkValue(sdkRef, setIssuerBasicPass, value)}
              secureTextEntry
              style={styles.singleLineInput}
              autoCapitalize="none"
            />
            <DemoButton
              label="Load issuer password"
              {...buttonState("Load password", "Loading...")}
              onPress={() => run("Load password", loadIssuerBasicPassword)}
            />
            <DemoButton
              label="Save issuer password"
              {...buttonState("Save password", "Saving...")}
              onPress={() => run("Save password", saveIssuerBasicPassword)}
            />
            <TextInput
              accessibilityLabel="Credential type"
              value={issuerCredentialType}
              onChangeText={(value) => resetSdkValue(sdkRef, setIssuerCredentialType, value)}
              style={styles.singleLineInput}
              autoCapitalize="none"
            />
            <TextInput
              accessibilityLabel="Credential schema"
              value={issuerCredentialSchema}
              onChangeText={(value) => resetSdkValue(sdkRef, setIssuerCredentialSchema, value)}
              style={styles.singleLineInput}
              autoCapitalize="none"
            />
            <DemoButton
              label="Claim VC from issuer"
              {...buttonState("Claim issuer", "Claiming...")}
              onPress={() =>
                run("Claim issuer", async () => {
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
                  const result = await sdk.claimCredentialFromIssuer({
                    holderDid: identity.did,
                    credentialType: issuerCredentialType,
                    credentialSchema: issuerCredentialSchema,
                    credentialSubject: {
                      fullName: "Juan Perez Prueba",
                      nationalIdNumber: "12345678",
                      birthDate: defaultCredentialValue
                    }
                  });
                  await refreshCredentialSummaries();
                  return {
                    credentialSaved: result.credentialSaved,
                    credentialType: result.credentialType,
                    issuerDid: result.issuerDid,
                    storageId: result.storageId
                  };
                })
              }
            />
            <DemoButton
              label="Debug: Claim issuer"
              onPress={() =>
                run("Claim issuer debug", async () => {
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
                  const result = await sdk.claimCredentialFromIssuerDebug({
                    holderDid: identity.did,
                    offer: claimOfferMessage !== sampleCredentialOfferMessage ? claimOfferMessage : undefined,
                    credentialType: issuerCredentialType,
                    credentialSchema: issuerCredentialSchema,
                    credentialSubject: {
                      fullName: "Juan Perez Prueba",
                      nationalIdNumber: "12345678",
                      birthDate: defaultCredentialValue
                    }
                  });
                  if (result.credentialSaved) {
                    await refreshCredentialSummaries();
                  }
                  return {
                    credentialSaved: result.credentialSaved,
                    credentialType: result.credentialType,
                    issuerDid: result.issuerDid,
                    storageId: result.storageId,
                    steps: summarizeIssuerDebugSteps(result.steps)
                  };
                })
              }
            />
          </StepSection>

          <StepSection title="Paso 5: Saved Credentials">
            <DemoButton
              label="Refresh saved credentials"
              {...buttonState("Refresh saved credentials", "Loading...")}
              onPress={() => run("Refresh saved credentials", refreshCredentialSummaries)}
            />
            <DemoButton
              label="Get credential summary by ID"
              onPress={() =>
                run("Get summary", async () => {
                  const sdk = await getSdk();
                  const id = summaries[0]?.id ?? sampleCredential.id;
                  const credential = await sdk.getCredentialById(id);
                  return credential ? safeCredentialDiagnostics(credential) : "not found";
                })
              }
            />
          </StepSection>

          <StepSection title="Paso 6: Credential proofs">
            <DemoButton
              label="Ensure JSON-LD contexts"
              {...buttonState("Ensure JSON-LD contexts", "Loading...")}
              onPress={() => run("Ensure JSON-LD contexts", ensureJsonLdContextsForLatestCredential)}
            />
            <DemoButton
              label="Generate credential proof off-chain"
              {...buttonState("Credential proof", "Generating...")}
              onPress={() =>
                run("Credential proof", async () => {
                  const sdk = await getSdk();
                  await ensureSigV2CircuitArtifacts();
                  const list = summaries.length > 0 ? summaries : await refreshCredentialSummaries();
                  const summary = selectLatestCredentialSummary(list);
                  if (!summary) {
                    throw new Error("No saved credential available for credential proof.");
                  }
                  const result = await sdk.generateCredentialAtomicQuerySigV2Proof({
                    credentialId: summary.id,
                    credentialType: summary.type.find((item) => item !== "VerifiableCredential") ?? issuerCredentialType,
                    issuerDid: summary.issuer,
                    schema: issuerCredentialSchema,
                    query: {
                      field: "birthDate",
                      operator: "lt",
                      value: defaultCredentialValue
                    },
                    mode: "offchain"
                  });
                  return {
                    proofGenerated: result.proofGenerated,
                    circuitId: result.circuitId,
                    credentialType: result.credentialType,
                    field: result.field,
                    operator: result.operator,
                    proofRoute: result.proofRoute,
                    publicSignalsCount: result.publicSignalsCount,
                    publicSignalsSource: result.publicSignalsSource,
                    proofSource: result.proofSource
                  };
                })
              }
            />
            <DemoButton
              label="Generate credential proof on-chain"
              {...buttonState("Credential proof on-chain", "Generating...")}
              onPress={() =>
                run("Credential proof on-chain", async () => {
                  const { summary: result, directVerifierDebugPath, circuitInputsDebugPath } =
                    await prepareOnchainProofForLatestCredential();
                  return {
                    proofGenerated: result.proofGenerated,
                    mode: result.mode,
                    circuitId: result.circuitId,
                    credentialType: result.credentialType,
                    field: result.field,
                    operator: result.operator,
                    proofRoute: result.proofRoute,
                    requestId: result.requestId,
                    challengeAddress: result.challengeAddress,
                    publicSignalsCount: result.publicSignalsCount,
                    publicSignalsSource: result.publicSignalsSource,
                    proofSource: result.proofSource,
                    directVerifierDebugPath,
                    circuitInputsDebugPath
                  };
                })
              }
            />
            <TextInput
              accessibilityLabel="EVM private key"
              value={evmPrivateKey}
              onChangeText={setEvmPrivateKey}
              secureTextEntry
              style={styles.singleLineInput}
              autoCapitalize="none"
            />
            <DemoButton
              label="Load EVM private key"
              {...buttonState("Load EVM key", "Loading...")}
              onPress={() =>
                run("Load EVM key", async () => {
                  const privateKey = await SecureStore.getItemAsync(evmPrivateKeySecureStoreKey);
                  if (!privateKey) {
                    return "No EVM private key saved in SecureStore.";
                  }
                  setEvmPrivateKey(privateKey);
                  return "EVM private key loaded from SecureStore.";
                })
              }
            />
            <DemoButton
              label="Save EVM private key"
              {...buttonState("Save EVM key", "Saving...")}
              onPress={() =>
                run("Save EVM key", async () => {
                  if (!evmPrivateKey) {
                    throw new Error("EVM private key is required before saving.");
                  }
                  await SecureStore.setItemAsync(evmPrivateKeySecureStoreKey, evmPrivateKey, {
                    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY
                  });
                  return "EVM private key saved in SecureStore.";
                })
              }
            />
            <DemoButton
              label="Submit proof to Universal Verifier"
              {...buttonState("Submit proof", "Submitting...")}
              onPress={() =>
                run("Submit proof", async () => {
                  if (!evmPrivateKey) {
                    throw new Error("EVM private key is required for Universal Verifier submit.");
                  }
                  const sdk = await getSdk();
                  const cached = onchainPreparedProofRef.current;
                  if (cached && cached.requestId !== defaultOnchainRequestId) {
                    onchainPreparedProofRef.current = undefined;
                    throw new Error("Prepared on-chain proof was generated for a stale requestId. Generate credential proof on-chain again.");
                  }
                  const prepared = cached ?? (await prepareOnchainProofForLatestCredential());
                  if (String(prepared.preparedProof.request.id) !== defaultOnchainRequestId) {
                    throw new Error("Prepared on-chain proof requestId does not match current Universal Verifier requestId.");
                  }
                  const submitInput = {
                    preparedProof: prepared.preparedProof,
                    requestId: String(prepared.preparedProof.request.id),
                    evmPrivateKey,
                    challengeAddress: prepared.challengeAddress,
                    validatorAddress: defaultOnchainValidatorAddress,
                    rpcUrl: config.network.rpcUrl,
                    universalVerifierAddress: config.contracts.universalVerifierAddress,
                    chainId: config.network.chainId
                  };
                  const debug = await prepareUniversalVerifierCalldataDebug(submitInput);
                  if (!debug.canStaticCall) {
                    return {
                      txSubmitted: false,
                      requestIdUsedForProof: debug.requestIdUsedForProof,
                      requestIdUsedForSubmit: debug.requestIdUsedForSubmit,
                      requestIdMatchesPublicSignal: debug.requestIdMatchesPublicSignal,
                      queryHashFromRequest: debug.queryHashFromRequest,
                      queryHashFromPublicSignal: debug.queryHashFromPublicSignal,
                      queryHashMatches: debug.queryHashMatches,
                      challengeAddress: debug.challengeAddress,
                      signerAddress: debug.signerAddress,
                      challengeFromPublicSignal: debug.challengeFromPublicSignal,
                      challengeMatchesSigner: debug.challengeMatchesSigner,
                      registeredValidator: debug.registeredValidator,
                      registeredCircuitId: debug.registeredCircuitId,
                      registeredOperator: debug.registeredOperator,
                      registeredValue: debug.registeredValue,
                      proofCircuitId: debug.proofCircuitId,
                      publicSignalsCount: debug.publicSignalsCount,
                      calldataProofFormat: debug.calldataProofFormat,
                      piBOrder: debug.piBOrder,
                      canStaticCall: debug.canStaticCall,
                      staticCallError: debug.staticCallError,
                      failureLayer: debug.failureLayer
                    };
                  }
                  const result = await sdk.submitOnchainProofToUniversalVerifier(submitInput);
                  return {
                    txSubmitted: result.txSubmitted,
                    txHash: result.txHash,
                    receiptStatus: result.receiptStatus,
                    blockNumber: result.blockNumber,
                    gasUsed: result.gasUsed,
                    requestId: result.requestId,
                    challengeAddress: result.challengeAddress,
                    universalVerifierAddress: result.universalVerifierAddress,
                    eventName: result.eventName,
                    verificationResult: result.verificationResult,
                    requestMatchesProof: result.calldataDebug?.requestMatchesProof,
                    requestIdUsedForProof: result.calldataDebug?.requestIdUsedForProof,
                    requestIdUsedForSubmit: result.calldataDebug?.requestIdUsedForSubmit,
                    requestIdMatchesPublicSignal: result.calldataDebug?.requestIdMatchesPublicSignal,
                    queryHashFromRequest: result.calldataDebug?.queryHashFromRequest,
                    queryHashFromPublicSignal: result.calldataDebug?.queryHashFromPublicSignal,
                    queryHashMatches: result.calldataDebug?.queryHashMatches,
                    registeredValidator: result.calldataDebug?.registeredValidator,
                    registeredCircuitId: result.calldataDebug?.registeredCircuitId,
                    registeredOperator: result.calldataDebug?.registeredOperator,
                    registeredValue: result.calldataDebug?.registeredValue,
                    proofCircuitId: result.calldataDebug?.proofCircuitId,
                    proofOperator: result.calldataDebug?.proofOperator,
                    proofValue: result.calldataDebug?.proofValue,
                    challengeFromPublicSignal: result.calldataDebug?.challengeFromPublicSignal,
                    challengeMatchesExpected: result.calldataDebug?.challengeMatchesExpected,
                    challengeMatchesSigner: result.calldataDebug?.challengeMatchesSigner,
                    signerMatchesChallenge: result.calldataDebug?.signerMatchesChallenge,
                    publicSignalsCount: result.calldataDebug?.publicSignalsCount,
                    calldataProofFormat: result.calldataDebug?.calldataProofFormat,
                    piBOrder: result.calldataDebug?.piBOrder,
                    canStaticCall: result.calldataDebug?.canStaticCall,
                    failureLayer: result.calldataDebug?.failureLayer
                  };
                })
              }
            />
          </StepSection>

          <StepSection title="Developer utilities">
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
              label="Import sample VC JSON"
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
              label="Save sample credential securely"
              onPress={() =>
                run("Save", async () => {
                  const sdk = await getSdk();
                  const imported = importedCredential ?? sdk.importCredentialFromJson(JSON.stringify(sampleCredential)).credential;
                  const summary = await sdk.saveCredential(imported);
                  await refreshCredentialSummaries();
                  return summary;
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
          </StepSection>
        </View>

        <Text style={styles.sectionTitle}>Status</Text>
        <Text style={styles.status}>{status}</Text>

        <Text style={styles.sectionTitle}>Saved Credentials</Text>
        <Text style={styles.savedCount}>Saved credentials: {summaries.length}</Text>
        {summaries.length === 0 ? (
          <Text style={styles.emptyState}>No credentials saved yet</Text>
        ) : (
          summaries.map((summary) => <SavedCredentialCard key={summary.id} summary={summary} />)
        )}

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

type IssuerDemoConfig = {
  issuerAdminBase: string;
  issuerDid: string;
  issuerBasicUser: string;
  issuerBasicPass: string;
  credentialType: string;
  credentialSchema: string;
  credentialContext: string;
};

function createConfiguredDemoConfig(input: IssuerDemoConfig): PrivadoExpoConfig {
  return {
    ...config,
    issuer: {
      issuerDid: input.issuerDid,
      issuerBaseUrl: config.issuer?.issuerBaseUrl,
      issuerAdminBase: input.issuerAdminBase,
      basicAuth:
        input.issuerBasicUser && input.issuerBasicPass
          ? {
              username: input.issuerBasicUser,
              password: input.issuerBasicPass
            }
          : undefined
    },
    credential: {
      credentialType: input.credentialType,
      credentialSchema: input.credentialSchema,
      credentialContext: input.credentialContext,
      credentialExpirationDays: defaultCredentialExpirationDays
    }
  };
}

function resetSdkValue<T>(
  sdkRef: { current?: PrivadoExpoClient },
  setter: (value: T) => void,
  value: T
): void {
  sdkRef.current = undefined;
  setter(value);
}

function DemoButton({
  label,
  onPress,
  disabled = false,
  loading = false,
  loadingLabel
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
  loading?: boolean;
  loadingLabel?: string;
}) {
  const effectiveDisabled = disabled || loading;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: effectiveDisabled, busy: loading }}
      disabled={effectiveDisabled}
      style={({ pressed }) => [styles.button, pressed && styles.buttonPressed, effectiveDisabled && styles.buttonDisabled]}
      onPress={onPress}
    >
      <Text style={styles.buttonText}>{loading ? loadingLabel ?? `${label}...` : label}</Text>
    </Pressable>
  );
}

function StepSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <View style={styles.stepSection}>
      <Text style={styles.stepTitle}>{title}</Text>
      {children}
    </View>
  );
}

function SavedCredentialCard({ summary }: { summary: ImportedCredentialSummary }) {
  return (
    <View style={styles.savedCredentialCard}>
      <View style={styles.savedCredentialHeader}>
        <Text style={styles.savedCredentialTitle}>{summary.type.join(", ") || "Credential"}</Text>
        <Text style={styles.encryptedBadge}>Stored encrypted</Text>
      </View>
      <Text style={styles.summaryLine}>Storage ID: {summary.id}</Text>
      <Text style={styles.summaryLine}>Credential ID: {summary.id}</Text>
      <Text style={styles.summaryLine}>Credential type: {summary.type.join(", ") || "Unknown"}</Text>
      <Text style={styles.summaryLine}>Issuer DID: {summary.issuer ?? "Unknown"}</Text>
      <Text style={styles.summaryLine}>Subject DID/id: {summary.credentialSubjectId ?? "Unknown"}</Text>
      <Text style={styles.summaryLine}>Proof types: {summary.proofTypes.join(", ") || "None"}</Text>
      <Text style={styles.summaryLine}>Created: {summary.createdAt ?? "Unknown"}</Text>
      <Text style={styles.summaryLine}>Updated: {summary.updatedAt ?? "Unknown"}</Text>
    </View>
  );
}

function formatResult(value: unknown): string {
  if (value === undefined) {
    return "done";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(sanitizeStatusValue(value), null, 2);
}

function sanitizeStatusValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sanitizeStatusValue);
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const sanitized: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (isSensitiveStatusKey(key)) {
      sanitized[key] = "[hidden]";
      continue;
    }
    sanitized[key] = sanitizeStatusValue(entry);
  }
  return sanitized;
}

function isSensitiveStatusKey(key: string): boolean {
  return [
    "authorization",
    "basicAuth",
    "credentialSubject",
    "encryptedPayload",
    "evmPrivateKey",
    "password",
    "privateKey",
    "proof",
    "pub_signals",
    "publicSignals",
    "responsePreview",
    "seed",
    "token",
    "vc",
    "verifiableCredential",
    "witness"
  ].includes(key);
}

function summarizeIssuerDebugSteps(steps: IssuerClaimDebugStep[]) {
  return steps.map((step) => ({
    step: step.step,
    status: step.status,
    local: step.claimLocalStep,
    httpStatus: step.httpStatus,
    postExecuted: step.postExecuted,
    messageIdFormat: step.messageIdFormat,
    threadIdFormat: step.threadIdFormat,
    credentialSummary: step.credentialSummary,
    error: typeof step.error === "string" ? summarizeError(step.error) : undefined
  }));
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

function createExpoJsonLdContextFileSystem() {
  return {
    cacheDirectory: FileSystem.cacheDirectory ?? undefined,
    getInfo: async (path: string) => {
      const info = await FileSystem.getInfoAsync(path);
      return { exists: info.exists };
    },
    makeDirectory: async (path: string) => {
      const info = await FileSystem.getInfoAsync(path);
      if (!info.exists) {
        await FileSystem.makeDirectoryAsync(path, { intermediates: true });
      }
    },
    readAsString: async (path: string) => FileSystem.readAsStringAsync(path),
    writeAsString: async (path: string, value: string) => {
      await FileSystem.writeAsStringAsync(path, value);
    }
  };
}

function createDemoJsonLdContextStore(): JsonLdContextStore {
  return new JsonLdContextStore({
    fileSystem: createExpoJsonLdContextFileSystem(),
    fetch: (url) => fetch(url),
    bundledContexts: bundledJsonLdContexts
  });
}

function normalizeContextUrls(value: string | string[]): string[] {
  return Array.isArray(value) ? value : [value];
}

function selectLatestCredentialSummary(summaries: ImportedCredentialSummary[]): ImportedCredentialSummary | undefined {
  return [...summaries].sort((left, right) => {
    const rightTime = Date.parse(right.updatedAt ?? right.createdAt ?? "");
    const leftTime = Date.parse(left.updatedAt ?? left.createdAt ?? "");
    return (Number.isNaN(rightTime) ? 0 : rightTime) - (Number.isNaN(leftTime) ? 0 : leftTime);
  })[0];
}

async function ensureContextsForCredentialWithSummary(
  store: JsonLdContextStore,
  credential: unknown,
  contextUrls: string[]
): Promise<{
  totalContexts: number;
  bundled?: number;
  cached: number;
  fetched: number;
  missing: unknown[];
}> {
  const maybeNewStore = store as JsonLdContextStore & {
    ensureContextsForCredential?: (
      credential: unknown,
      extraContextUrls?: string[]
    ) => Promise<{
      totalContexts: number;
      cached: number;
      fetched: number;
      missing: unknown[];
    }>;
  };
  if (typeof maybeNewStore.ensureContextsForCredential === "function") {
    return maybeNewStore.ensureContextsForCredential(credential, contextUrls);
  }
  await store.ensureContextsFromCredential(credential, contextUrls);
  return {
    totalContexts: contextUrls.length,
    bundled: 0,
    cached: 0,
    fetched: 0,
    missing: []
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
  stepSection: {
    gap: 10,
    borderRadius: 8,
    backgroundColor: "#eef2f7",
    padding: 10
  },
  stepTitle: {
    color: "#111827",
    fontSize: 14,
    fontWeight: "700"
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
  savedCount: {
    borderRadius: 8,
    backgroundColor: "#ffffff",
    color: "#111827",
    padding: 12,
    fontSize: 14,
    fontWeight: "700"
  },
  emptyState: {
    borderRadius: 8,
    backgroundColor: "#ffffff",
    color: "#6b7280",
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
  },
  savedCredentialCard: {
    borderRadius: 8,
    backgroundColor: "#ffffff",
    borderColor: "#d1d5db",
    borderWidth: 1,
    padding: 12,
    gap: 5
  },
  savedCredentialHeader: {
    gap: 6
  },
  savedCredentialTitle: {
    color: "#111827",
    fontSize: 14,
    fontWeight: "700"
  },
  encryptedBadge: {
    alignSelf: "flex-start",
    borderRadius: 6,
    backgroundColor: "#dcfce7",
    color: "#166534",
    fontSize: 12,
    fontWeight: "700",
    paddingHorizontal: 8,
    paddingVertical: 4
  }
});
