const {
  addressToUint256LE,
  createPrivadoExpoClient
} = require("../dist/index.js");

async function main() {
  const sdk = createPrivadoExpoClient({
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
    circuits: {
      artifacts: []
    }
  });

  await sdk.init();

  const imported = sdk.importCredentialFromJson(
    JSON.stringify({
      id: "urn:test",
      type: ["VerifiableCredential", "Demo"],
      issuer: "did:iden3:test",
      credentialSubject: {
        id: "did:iden3:holder",
        age: 21
      },
      proof: {
        type: "Iden3SparseMerkleTreeProof"
      }
    })
  );

  await sdk.saveCredential(imported.credential);
  const credentials = await sdk.getCredentials();
  const offchainRequest = sdk.buildOffchainProofRequest({
    proofKind: "mtp",
    credentialType: "Demo"
  });
  const onchainRequest = sdk.buildOnchainProofRequest({
    proofKind: "mtp",
    verifierAddress: "0x0000000000000000000000000000000000000002"
  });
  const challenge = addressToUint256LE("0x0000000000000000000000000000000000000002");

  assert(credentials.length === 1, "expected one credential summary");
  assert(credentials[0].id === "urn:test", "expected safe credential id");
  assert(credentials[0].credentialSubjectId === "did:iden3:holder", "expected subject id summary");
  assert(!("age" in credentials[0]), "summary must not include claims");
  assert(offchainRequest.circuitId === "credentialAtomicQueryMTPV2", "expected off-chain MTP circuit");
  assert(onchainRequest.circuitId === "credentialAtomicQueryMTPV2OnChain", "expected on-chain MTP circuit");
  assert(challenge.length > 0, "expected address challenge");

  console.info("smoke ok");
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
