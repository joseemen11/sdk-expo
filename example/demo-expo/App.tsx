import { useMemo, useState } from "react";
import { Pressable, SafeAreaView, ScrollView, StyleSheet, Text, View } from "react-native";
import { createPrivadoExpoClient, type ImportedCredentialSummary, type PrivadoExpoConfig } from "@privado-id/expo-sdk";

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

export default function App() {
  const sdk = useMemo(() => createPrivadoExpoClient(config), []);
  const [importedCredential, setImportedCredential] = useState<unknown>();
  const [summaries, setSummaries] = useState<ImportedCredentialSummary[]>([]);
  const [status, setStatus] = useState("Ready");

  async function run(label: string, action: () => Promise<unknown> | unknown) {
    try {
      const result = await action();
      setStatus(`${label}: ${formatResult(result)}`);
    } catch (error) {
      setStatus(`${label}: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.container}>
        <Text style={styles.title}>Privado ID SDK Demo</Text>
        <View style={styles.toolbar}>
          <DemoButton label="Init SDK" onPress={() => run("Init", () => sdk.init().then(() => "initialized"))} />
          <DemoButton
            label="Import VC JSON"
            onPress={() =>
              run("Import", () => {
                const imported = sdk.importCredentialFromJson(JSON.stringify(sampleCredential));
                setImportedCredential(imported.credential);
                return imported.summary;
              })
            }
          />
          <DemoButton
            label="Save credential"
            onPress={() =>
              run("Save", async () => {
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
                const list = await sdk.getCredentials();
                setSummaries(list);
                return list;
              })
            }
          />
          <DemoButton
            label="Build off-chain MTP request"
            onPress={() =>
              run("Off-chain MTP", () =>
                sdk.buildOffchainProofRequest({
                  proofKind: "mtp",
                  credentialType: "KYCAgeCredential",
                  credentialSchema: "https://schema.example/kyc-age.json"
                })
              )
            }
          />
          <DemoButton
            label="Build on-chain MTP request"
            onPress={() =>
              run("On-chain MTP", () =>
                sdk.buildOnchainProofRequest({
                  proofKind: "mtp",
                  credentialType: "KYCAgeCredential",
                  credentialSchema: "https://schema.example/kyc-age.json",
                  verifierAddress: config.contracts.universalVerifierAddress
                })
              )
            }
          />
          <DemoButton
            label="Prepare UniversalVerifier payload"
            onPress={() =>
              run("Payload", () =>
                sdk.prepareUniversalVerifierPayload({
                  requestId: 1,
                  proof: {
                    circuitId: "credentialAtomicQueryMTPV2OnChain" as never,
                    proof: { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"] },
                    publicSignals: ["0"],
                    request: sdk.buildOnchainProofRequest({
                      proofKind: "mtp",
                      verifierAddress: config.contracts.universalVerifierAddress
                    })
                  }
                })
              )
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
          </View>
        ))}
      </ScrollView>
    </SafeAreaView>
  );
}

function DemoButton({ label, onPress }: { label: string; onPress: () => void }) {
  return (
    <Pressable accessibilityRole="button" style={({ pressed }) => [styles.button, pressed && styles.buttonPressed]} onPress={onPress}>
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
