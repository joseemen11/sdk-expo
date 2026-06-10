const {
  DevelopmentOnlyHolderDidProvider,
  DevelopmentOnlyKmsAdapter,
  DevelopmentSecureKeyStore,
  EncryptedCredentialStorage,
  EncryptedIdentityStorage,
  InMemoryCredentialRecordStore,
  SecurePrivateKeyStore,
  addressToUint256LE,
  createPrivadoExpoClient
} = require("../dist/index.js");

async function main() {
  const secureKeyStore = new DevelopmentSecureKeyStore();
  const recordStore = new InMemoryCredentialRecordStore();
  const credentialStorage = new EncryptedCredentialStorage({
    secureKeyStore,
    recordStore
  });
  const identityStorage = new EncryptedIdentityStorage({
    secureKeyStore
  });
  const privateKeyStore = new SecurePrivateKeyStore({
    secureKeyStore
  });
  const kmsAdapter = new DevelopmentOnlyKmsAdapter({
    privateKeyStore
  });
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
  }, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider()
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
  const storedRecords = await recordStore.list();
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
  assert(credentials[0].createdAt, "expected createdAt in summary");
  assert(credentials[0].updatedAt, "expected updatedAt in summary");
  assert(!("age" in credentials[0]), "summary must not include claims");
  assert(storedRecords.length === 1, "expected one stored encrypted record");
  assert(!storedRecords[0].encryptedPayload.includes("did:iden3:holder"), "encrypted payload must not contain subject id");
  assert(!storedRecords[0].encryptedPayload.includes("age"), "encrypted payload must not contain claim names");
  const credential = await sdk.getCredentialById("urn:test");
  assert(Boolean(credential), "expected credential lookup by id");
  assert(offchainRequest.circuitId === "credentialAtomicQueryMTPV2", "expected off-chain MTP circuit");
  assert(onchainRequest.circuitId === "credentialAtomicQueryMTPV2OnChain", "expected on-chain MTP circuit");
  assert(challenge.length > 0, "expected address challenge");
  await sdk.deleteCredential("urn:test");
  assert((await sdk.getCredentials()).length === 0, "expected delete credential");
  await sdk.saveCredential(imported.credential);
  await sdk.clearCredentials();
  assert((await sdk.getCredentials()).length === 0, "expected clear credentials");

  await expectRejects(
    () => sdk.createOrLoadHolderDid({ mode: "real", method: "iden3", network: "amoy" }),
    "Real Privado ID holder creation is not configured."
  );

  const holder = await sdk.createOrLoadHolderDid({
    mode: "development",
    method: "development",
    network: "amoy"
  });
  const loaded = await sdk.createOrLoadHolderDid({
    mode: "development",
    method: "development",
    network: "amoy"
  });
  const summary = await sdk.getHolderDid();
  assert(holder.isNew === true, "expected first holder DID call to create identity");
  assert(loaded.isNew === false, "expected second holder DID call to load identity");
  assert(holder.did === loaded.did, "expected holder DID to persist between calls");
  assert(summary && summary.did === holder.did, "expected getHolderDid to return active identity");
  assert(holder.developmentOnly === true, "expected smoke holder DID to be developmentOnly");
  assert(!("privateKey" in holder), "holder result must not expose private key");
  assert(!("seed" in holder), "holder result must not expose seed");

  const signature = await sdk.signChallenge({
    challenge: "smoke-challenge"
  });
  assert(signature.keyId === holder.keyId, "expected challenge signature to use holder key");
  assert(signature.signature.length > 0, "expected challenge signature");
  assert(signature.developmentOnly === true, "expected smoke signature to be developmentOnly");

  const deleted = await sdk.deleteHolderIdentity();
  assert(deleted.deleted === true, "expected delete holder identity");
  assert((await sdk.getHolderDid()) === undefined, "expected holder DID to be removed");

  console.info("smoke ok");
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function expectRejects(action, expectedMessage) {
  try {
    await action();
  } catch (error) {
    assert(error instanceof Error, "expected controlled error");
    assert(error.message === expectedMessage, `expected error message: ${expectedMessage}`);
    return;
  }
  throw new Error("expected action to reject");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
