const {
  AuthV2ZKProvider,
  AuthV2InputBuilder,
  authV2RequiredWitnessFields,
  buildAuthV2InputsPreview,
  coerceAuthV2NativeWitnessInputs,
  CircuitArtifactStore,
  CircuitArtifactDownloader,
  CircuitId,
  CircomWitnessNativeCalculator,
  DevelopmentOnlyHolderDidProvider,
  DevelopmentOnlyKmsAdapter,
  DevelopmentSecureKeyStore,
  EncryptedCredentialStorage,
  EncryptedIdentityStorage,
  ExpoCircuitArtifactStore,
  InMemoryCredentialRecordStore,
  IssuerClaimProvider,
  JsonLdContextStore,
  MobileAuthV2ChallengeSigner,
  MobileAuthV2IdentityProofSource,
  MobileBjjKmsAdapter,
  MobileCredentialAtomicQuerySigV2InputBuilder,
  ReadOnlyMobileGistProofSource,
  RapidsnarkNativeProver,
  SecurePrivateKeyStore,
  addressToUint256LE,
  deriveEvmAddressFromPrivateKey,
  prepareUniversalVerifierCalldata,
  prepareUniversalVerifierCalldataDebug,
  submitOnchainProofToUniversalVerifier,
  createPrivadoExpoClient,
  joinUri,
  loadMobileSafePolygonIdIdentityKms,
  parseCredentialOffer,
  normalizeJsonLdContextUrl,
  supportedCredentialProofOperators,
  toAuthV2GistProof,
  toDecimalBigIntString,
  validateSigV2OnChainInputsBeforeWitness
} = require("../dist/index.js");
const fs = require("fs");
const path = require("path");

async function main() {
  assertNoRootPolygonIdSdkImport();
  const secureKeyStore = new TrackingSecureKeyStore(new DevelopmentSecureKeyStore());
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
  const mobileBjjKmsAdapter = new MobileBjjKmsAdapter({
    secureKeyStore
  });
  const baseConfig = {
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
  };
  const sdk = createPrivadoExpoClient(baseConfig, {
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
        type: "BJJSignature2021"
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
  const artifactStore = new CircuitArtifactStore();
  artifactStore.register(authV2Artifact());
  const authArtifacts = artifactStore.require(CircuitId.AuthV2);
  const authValidation = artifactStore.validate(CircuitId.AuthV2, "native");
  const incompleteArtifactStore = new CircuitArtifactStore({
    artifacts: [
      {
        circuitId: CircuitId.AuthV2,
        version: "smoke",
        zkeyPath: "file:///circuits/AuthV2/AuthV2.zkey"
      }
    ]
  });
  const incompleteValidation = incompleteArtifactStore.validate(CircuitId.AuthV2);
  const expoArtifactStore = new ExpoCircuitArtifactStore({
    manifest: {
      artifacts: [authV2Artifact()]
    }
  });

  assert(credentials.length === 1, "expected one credential summary");
  assert(credentials[0].id === "urn:test", "expected safe credential id");
  assert(credentials[0].credentialSubjectId === "did:iden3:holder", "expected subject id summary");
  assert(credentials[0].createdAt, "expected createdAt in summary");
  assert(credentials[0].updatedAt, "expected updatedAt in summary");
  assert(!("age" in credentials[0]), "summary must not include claims");
  assert(!("credentialSubject" in credentials[0]), "summary must not expose full credentialSubject");
  assert(!("proof" in credentials[0]), "summary must not expose full proof");
  const credentialSummaryJson = JSON.stringify(credentials);
  assert(!credentialSummaryJson.includes("\"age\""), "summary JSON must not include claim names");
  assert(!credentialSummaryJson.includes("coreClaim"), "summary JSON must not include full proof payload");
  assert(!credentialSummaryJson.includes("issuerData"), "summary JSON must not include full proof issuer data");
  assert(storedRecords.length === 1, "expected one stored encrypted record");
  assert(!storedRecords[0].encryptedPayload.includes("did:iden3:holder"), "encrypted payload must not contain subject id");
  assert(!storedRecords[0].encryptedPayload.includes("age"), "encrypted payload must not contain claim names");
  const credential = await sdk.getCredentialById("urn:test");
  assert(Boolean(credential), "expected credential lookup by id");
  assert(supportedCredentialProofOperators.includes("eq"), "expected eq credential proof operator");
  assert(supportedCredentialProofOperators.includes("noop"), "expected noop credential proof operator");
  const credentialProofPlan = await sdk.generateCredentialProof({
    credentialId: "urn:test",
    credentialType: "Demo",
    issuerDid: "did:iden3:test",
    query: {
      field: "age",
      operator: "gt",
      value: 18
    },
    mode: "offchain"
  });
  assert(credentialProofPlan.proofGenerated === false, "expected credential proof plan not to generate proof yet");
  assert(credentialProofPlan.circuitId === CircuitId.CredentialAtomicQuerySigV2, "expected offchain credential proof to use SigV2 circuit");
  assert(credentialProofPlan.request.query.credentialSubject.age.operator === "gt", "expected configurable field/operator query");
  assert(credentialProofPlan.nextBoundary.includes("credentialAtomicQuerySigV2"), "expected SigV2 builder boundary");
  const credentialProofPlanJson = JSON.stringify(credentialProofPlan);
  assert(!credentialProofPlanJson.includes("\"age\":21"), "credential proof plan must not expose full VC claim value");
  assert(!credentialProofPlanJson.includes("coreClaim"), "credential proof plan must not expose full proof payload");
  await expectRejectsIncludes(
    () => sdk.generateCredentialProof({
      credentialId: "urn:test",
      credentialType: "OtherCredential",
      query: { field: "age", operator: "gt", value: 18 },
      mode: "offchain"
    }),
    "credential type does not match"
  );
  await expectRejectsIncludes(
    () => sdk.generateCredentialProof({
      credentialId: "urn:test",
      credentialType: "Demo",
      query: { field: "missingField", operator: "eq", value: 1 },
      mode: "offchain"
    }),
    "query field is not present"
  );
  await expectRejectsIncludes(
    () => sdk.generateCredentialProof({
      credentialId: "urn:test",
      credentialType: "Demo",
      query: { field: "age", operator: "between", value: [18, 65] },
      mode: "offchain"
    }),
    "operator is not supported"
  );
  await expectRejectsIncludes(
    () => sdk.generateCredentialAtomicQuerySigV2Proof({
      credentialId: "urn:missing",
      credentialType: "Demo",
      query: { field: "age", operator: "gt", value: 18 },
      mode: "offchain"
    }),
    "credential was not found"
  );
  await expectRejectsIncludes(
    () => createPrivadoExpoClient(baseConfig, {
      secureKeyStore,
      credentialStorage,
      identityStorage: new SmokeIdentityStorage(),
      kmsAdapter,
      credentialAtomicQuerySigV2InputBuilder: new SmokeCredentialAtomicQuerySigV2InputBuilder(),
      authV2WitnessCalculator: new SmokeCredentialWitnessCalculator(),
      authV2NativeProver: new SmokeCredentialProver()
    }).generateCredentialAtomicQuerySigV2Proof({
      credentialId: "urn:test",
      credentialType: "Demo",
      query: { field: "age", operator: "gt", value: 18 },
      mode: "offchain"
    }),
    "credentialAtomicQuerySigV2 circuit artifacts are required"
  );
  assert(
    normalizeJsonLdContextUrl("https://ipfs.io/ipfs/QmSmokeContext") === "ipfs://QmSmokeContext",
    "expected IPFS gateway context normalization"
  );
  await assertJsonLdContextStoreSmoke();
  const credentialProofArtifactStore = new CircuitArtifactStore({
    artifacts: [
      {
        circuitId: CircuitId.CredentialAtomicQuerySigV2,
        graphPath: "file:///circuits/credentialAtomicQuerySigV2/credentialAtomicQuerySigV2.wcd",
        zkeyPath: "file:///circuits/credentialAtomicQuerySigV2/credentialAtomicQuerySigV2.zkey"
      },
      {
        circuitId: CircuitId.CredentialAtomicQuerySigV2OnChain,
        graphPath: "file:///circuits/credentialAtomicQuerySigV2OnChain/credentialAtomicQuerySigV2OnChain.wcd",
        zkeyPath: "file:///circuits/credentialAtomicQuerySigV2OnChain/credentialAtomicQuerySigV2OnChain.zkey"
      }
    ]
  });
  const slotSigV2Credential = createSmokeSlotBasedSigV2Credential({ birthDateSlotValue: 946684799 });
  await sdk.saveCredential(slotSigV2Credential);
  const smokeHolderDid = await new SmokeIdentityStorage().getHolderDid();
  const slotInputs = await new MobileCredentialAtomicQuerySigV2InputBuilder({
    httpClient: new SmokeRevocationHttpClient()
  }).buildInputs({
    plan: smokeCredentialSigV2Plan({
      credentialId: "urn:slot-sigv2",
      credentialType: "PersonCredential",
      issuerDid: slotSigV2Credential.issuer,
      field: "birthDate",
      operator: "lt",
      value: 946684800
    }),
    credential: slotSigV2Credential,
    holderDid: smokeHolderDid,
    config: baseConfig
  });
  assert(slotInputs.slotIndex === 2, "expected birthDate to resolve to a slot-based claim path");
  assert(slotInputs.operator === 2, "expected lt operator in SigV2 inputs");
  assert(slotInputs.value[0] === "946684800", "expected query value in SigV2 inputs");
  assert(slotInputs.__proofRoute === "slot-based", "expected slot-based proof route");
  const missingIssuerRevocationRootCredential = createSmokeSlotBasedSigV2Credential({
    birthDateSlotValue: 946684799,
    omitIssuerRevocationTreeRoot: true
  });
  const fallbackIssuerStateInputs = await new MobileCredentialAtomicQuerySigV2InputBuilder({
    httpClient: new SmokeRevocationHttpClient()
  }).buildInputs({
    plan: smokeCredentialSigV2Plan({
      credentialId: "urn:slot-sigv2",
      credentialType: "PersonCredential",
      issuerDid: missingIssuerRevocationRootCredential.issuer,
      field: "birthDate",
      operator: "lt",
      value: 946684800
    }),
    credential: missingIssuerRevocationRootCredential,
    holderDid: smokeHolderDid,
    config: baseConfig
  });
  assert(fallbackIssuerStateInputs.issuerAuthRevTreeRoot === "0", "expected issuer revocation root fallback from resolver");
  await expectRejectsIncludes(
    () => new MobileCredentialAtomicQuerySigV2InputBuilder({
      httpClient: new SmokeBrokenRevocationHttpClient()
    }).buildInputs({
      plan: smokeCredentialSigV2Plan({
        credentialId: "urn:slot-sigv2",
        credentialType: "PersonCredential",
        issuerDid: missingIssuerRevocationRootCredential.issuer,
        field: "birthDate",
        operator: "lt",
        value: 946684800
      }),
      credential: missingIssuerRevocationRootCredential,
      holderDid: smokeHolderDid,
      config: baseConfig
    }),
    "Unable to resolve issuer revocation state"
  );
  const iden3commCredential = createSmokeSlotBasedSigV2Credential({
    birthDateSlotValue: 946684799,
    credentialStatusType: "Iden3commRevocationStatusV1.0"
  });
  const iden3commRevocationHttpClient = new SmokeIden3commRevocationHttpClient();
  const iden3commInputs = await new MobileCredentialAtomicQuerySigV2InputBuilder({
    httpClient: iden3commRevocationHttpClient
  }).buildInputs({
    plan: smokeCredentialSigV2Plan({
      credentialId: "urn:slot-sigv2",
      credentialType: "PersonCredential",
      issuerDid: iden3commCredential.issuer,
      field: "birthDate",
      operator: "lt",
      value: 946684800
    }),
    credential: iden3commCredential,
    holderDid: smokeHolderDid,
    config: baseConfig
  });
  assert(iden3commInputs.issuerClaimNonRevRevTreeRoot === "0", "expected iden3comm claim revocation root");
  assert(iden3commRevocationHttpClient.requests.length === 2, "expected claim and auth iden3comm revocation requests");
  const merklizedCredential = await createSmokeMerklizedSigV2Credential();
  const merklizedInputs = await new MobileCredentialAtomicQuerySigV2InputBuilder({
    httpClient: new SmokeRevocationHttpClient(),
    valueProofProvider: new SmokeJsonLdValueProofProvider()
  }).buildInputs({
    plan: smokeCredentialSigV2Plan({
      credentialId: "urn:merklized-sigv2",
      credentialType: "PersonCredential",
      issuerDid: merklizedCredential.issuer,
      field: "birthDate",
      operator: "lt",
      value: 946684800
    }),
    credential: merklizedCredential,
    holderDid: smokeHolderDid,
    config: baseConfig
  });
  assert(merklizedInputs.__proofRoute === "merklized", "expected merklized proof route");
  assert(merklizedInputs.slotIndex === 0, "expected merklized SigV2 slot index 0");
  assert(merklizedInputs.claimPathKey !== "0", "expected merklized claim path key");
  assert(merklizedInputs.claimPathValue !== "0", "expected merklized claim path value");
  await expectRejectsIncludes(
    () => new MobileCredentialAtomicQuerySigV2InputBuilder({
      httpClient: new SmokeRevocationHttpClient(),
      valueProofProvider: new SmokeJsonLdValueProofProvider()
    }).buildInputs({
      plan: smokeCredentialSigV2Plan({
        credentialId: "urn:merklized-sigv2",
        credentialType: "PersonCredential",
        issuerDid: merklizedCredential.issuer,
        field: "missingDate",
        operator: "lt",
        value: 946684800
      }),
      credential: merklizedCredential,
      holderDid: smokeHolderDid,
      config: baseConfig
    }),
    "slot-based builder only supports numeric credentialSubject.missingDate"
  );
  const defaultSlotSigV2Proof = await createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage: new SmokeIdentityStorage(),
    kmsAdapter,
    circuitArtifactStore: credentialProofArtifactStore,
    httpClient: new SmokeRevocationHttpClient(),
    authV2WitnessCalculator: new SmokeCredentialWitnessCalculator(),
    authV2NativeProver: new SmokeCredentialProver()
  }).generateCredentialAtomicQuerySigV2Proof({
    credentialId: "urn:slot-sigv2",
    credentialType: "PersonCredential",
    issuerDid: slotSigV2Credential.issuer,
    query: { field: "birthDate", operator: "lt", value: 946684800 },
    mode: "offchain"
  });
  assert(defaultSlotSigV2Proof.proofGenerated === true, "expected default slot-based SigV2 builder to generate proof");
  assert(defaultSlotSigV2Proof.proofRoute === "slot-based", "expected slot-based proof result route");
  const onchainPlan = await sdk.generateCredentialProof({
    credentialId: "urn:slot-sigv2",
    credentialType: "PersonCredential",
    issuerDid: slotSigV2Credential.issuer,
    query: { field: "birthDate", operator: "lt", value: 946684800 },
    mode: "onchain",
    onchain: {
      requestId: "1782204596",
      challengeAddress: "0x176A3cd0e7d9B0936f594015eADF313Fd46558E7"
    }
  });
  assert(onchainPlan.circuitId === CircuitId.CredentialAtomicQuerySigV2OnChain, "expected on-chain credential proof circuit");
  const expectedOnchainChallenge = addressToUint256LE("0x176A3cd0e7d9B0936f594015eADF313Fd46558E7");
  assert(onchainPlan.request.challenge === expectedOnchainChallenge, "expected EVM address challenge decimal");
  assert(onchainPlan.request.challenge !== BigInt("0x176A3cd0e7d9B0936f594015eADF313Fd46558E7").toString(), "expected challenge to use PolygonID little-endian address conversion");
  await expectRejectsIncludes(
    () => sdk.generateCredentialProof({
      credentialId: "urn:slot-sigv2",
      credentialType: "PersonCredential",
      issuerDid: slotSigV2Credential.issuer,
      query: { field: "birthDate", operator: "lt", value: 946684800 },
      mode: "onchain",
      onchain: { requestId: "1782204596", challengeAddress: "not-an-address" }
    }),
    "challengeAddress must be a valid EVM address"
  );
  await expectRejectsIncludes(
    () => sdk.generateCredentialProof({
      credentialId: "urn:slot-sigv2",
      credentialType: "PersonCredential",
      issuerDid: slotSigV2Credential.issuer,
      query: { field: "birthDate", operator: "lt", value: 946684800 },
      mode: "onchain",
      onchain: { challengeAddress: "0x176A3cd0e7d9B0936f594015eADF313Fd46558E7" }
    }),
    "requestId is required"
  );
  const defaultSlotSigV2OnchainProof = await createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage: new SmokeIdentityStorage(),
    kmsAdapter,
    circuitArtifactStore: credentialProofArtifactStore,
    httpClient: new SmokeRevocationHttpClient(),
    authV2InputBuilder: new SmokeAuthV2InputBuilder(),
    authV2WitnessCalculator: new SmokeCredentialWitnessCalculator(),
    authV2NativeProver: new SmokeCredentialProver()
  }).generateCredentialAtomicQuerySigV2OnChainProof({
    credentialId: "urn:slot-sigv2",
    credentialType: "PersonCredential",
    issuerDid: slotSigV2Credential.issuer,
    query: { field: "birthDate", operator: "lt", value: 946684800 },
    mode: "onchain",
    onchain: {
      requestId: "1782204596",
      challengeAddress: "0x176A3cd0e7d9B0936f594015eADF313Fd46558E7"
    }
  });
  assert(defaultSlotSigV2OnchainProof.proofGenerated === true, "expected default SigV2 on-chain builder to generate proof");
  assert(defaultSlotSigV2OnchainProof.circuitId === CircuitId.CredentialAtomicQuerySigV2OnChain, "expected on-chain proof circuit");
  assert(defaultSlotSigV2OnchainProof.mode === "onchain", "expected on-chain proof mode summary");
  assert(defaultSlotSigV2OnchainProof.requestId === "1782204596", "expected on-chain request id summary");
  assert(defaultSlotSigV2OnchainProof.challengeAddress === "0x176a3cd0e7d9b0936f594015eadf313fd46558e7", "expected normalized challenge address");
  assert(defaultSlotSigV2OnchainProof.publicSignalsCount === 2, "expected safe on-chain public signals count");
  assert(!JSON.stringify(defaultSlotSigV2OnchainProof).includes("smoke-proof"), "on-chain proof result must not expose full proof");
  const preparedUniversalVerifierCalldata = prepareUniversalVerifierCalldata(smokeGeneratedOnchainProof(), "1782204596");
  assert(preparedUniversalVerifierCalldata.method === "submitZKPResponse", "expected legacy UniversalVerifier submit method");
  assert(preparedUniversalVerifierCalldata.inputs.length === 11, "expected on-chain public signals as inputs");
  assert(preparedUniversalVerifierCalldata.inputs[4] === "1782204596", "expected requestId in SigV2OnChain public signal index 4");
  assert(
    preparedUniversalVerifierCalldata.inputs[5] === expectedOnchainChallenge,
    "expected challenge in SigV2OnChain public signal index 5"
  );
  validateSigV2OnChainInputsBeforeWitness(
    { challenge: expectedOnchainChallenge },
    { challengeAddress: "0x176A3cd0e7d9B0936f594015eADF313Fd46558E7" }
  );
  await expectRejectsIncludes(
    () => Promise.resolve(validateSigV2OnChainInputsBeforeWitness(
      { challenge: BigInt("0x176A3cd0e7d9B0936f594015eADF313Fd46558E7").toString() },
      { challengeAddress: "0x176A3cd0e7d9B0936f594015eADF313Fd46558E7" }
    )),
    "challenge does not match challengeAddress"
  );
  assert(preparedUniversalVerifierCalldata.a[0] === "1", "expected pi_a to map to Solidity a");
  assert(preparedUniversalVerifierCalldata.b[0][0] === "4" && preparedUniversalVerifierCalldata.b[0][1] === "3", "expected pi_b inner coordinates to be swapped for Solidity");
  assert(preparedUniversalVerifierCalldata.c[1] === "8", "expected pi_c to map to Solidity c");
  assert(typeof prepareUniversalVerifierCalldataDebug === "function", "expected safe UniversalVerifier calldata debug export");
  await expectRejectsIncludes(
    () => Promise.resolve(prepareUniversalVerifierCalldata({ ...smokeGeneratedOnchainProof(), publicSignals: [] }, "1782204596")),
    "requires publicSignals"
  );
  await expectRejectsIncludes(
    () => Promise.resolve(prepareUniversalVerifierCalldata({
      ...smokeGeneratedOnchainProof(),
      request: { ...smokeGeneratedOnchainProof().request, id: "" }
    })),
    "requires requestId"
  );
  const smokeEvmPrivateKey = "0x59c6995e998f97a5a0044966f094538b2927a122b6b2f9d36c90e3f4d16e7c2f";
  const smokeEvmAddress = deriveEvmAddressFromPrivateKey(smokeEvmPrivateKey);
  assert(/^0x[0-9a-f]{40}$/.test(smokeEvmAddress), "expected EVM private key to derive address");
  await expectRejectsIncludes(
    () => submitOnchainProofToUniversalVerifier({
      preparedProof: smokeGeneratedOnchainProof(),
      requestId: "1782204596",
      evmPrivateKey: smokeEvmPrivateKey,
      rpcUrl: "https://rpc.example",
      universalVerifierAddress: "0xfcc86A79fCb057A8e55C6B853dff9479C3cf607c",
      chainId: 80002,
      challengeAddress: "0x0000000000000000000000000000000000000000"
    }),
    "signer address does not match challengeAddress"
  );
  assert(!JSON.stringify({ smokeEvmAddress }).includes(smokeEvmPrivateKey.slice(2)), "submit summaries must not expose private key");
  const credentialProofSdk = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage: new SmokeIdentityStorage(),
    kmsAdapter,
    circuitArtifactStore: credentialProofArtifactStore,
    credentialAtomicQuerySigV2InputBuilder: new SmokeCredentialAtomicQuerySigV2InputBuilder(),
    authV2WitnessCalculator: new SmokeCredentialWitnessCalculator(),
    authV2NativeProver: new SmokeCredentialProver()
  });
  const credentialAtomicProof = await credentialProofSdk.generateCredentialAtomicQuerySigV2Proof({
    credentialId: "urn:test",
    credentialType: "Demo",
    issuerDid: "did:iden3:test",
    query: { field: "age", operator: "gt", value: 18 },
    mode: "offchain"
  });
  assert(credentialAtomicProof.proofGenerated === true, "expected credentialAtomicQuerySigV2 proof summary");
  assert(credentialAtomicProof.circuitId === CircuitId.CredentialAtomicQuerySigV2, "expected credential SigV2 circuit");
  assert(credentialAtomicProof.publicSignalsCount === 2, "expected safe public signals count");
  const credentialAtomicProofJson = JSON.stringify(credentialAtomicProof);
  assert(!credentialAtomicProofJson.includes("\"age\":21"), "credential proof result must not expose full VC claim value");
  assert(!credentialAtomicProofJson.includes("smoke-proof"), "credential proof result must not expose full proof");
  await sdk.deleteCredential("urn:slot-sigv2");
  assert(offchainRequest.circuitId === "credentialAtomicQueryMTPV2", "expected off-chain MTP circuit");
  assert(onchainRequest.circuitId === "credentialAtomicQueryMTPV2OnChain", "expected on-chain MTP circuit");
  assert(challenge.length > 0, "expected address challenge");
  assert(authArtifacts.zkeyPath === "file:///circuits/AuthV2/AuthV2.zkey", "expected AuthV2 zkey path");
  assert(!("zkeyBytes" in authArtifacts), "artifact store must not load zkey bytes into JS");
  assert(authValidation.valid === true, "expected complete AuthV2 artifact descriptor");
  assert(incompleteValidation.valid === false, "expected incomplete AuthV2 descriptor to fail validation");
  assert(incompleteValidation.missing.includes("wasmOrGraph"), "expected missing witness artifact");
  assert(expoArtifactStore.resolve(CircuitId.AuthV2), "expected Expo artifact store to resolve AuthV2");
  await expectRejectsIncludes(
    () => new AuthV2ZKProvider().generateProof(authV2GenerateProofInput(authArtifacts)),
    "Mobile witness calculator is required to generate AuthV2 proof."
  );
  await expectRejectsIncludes(
    () => new AuthV2ZKProvider({
      witnessCalculator: new SmokeWitnessCalculator()
    }).generateProof(authV2GenerateProofInput(authArtifacts, completeAuthV2WitnessInputs())),
    "Native prover is required to generate AuthV2 proof."
  );
  const authProof = await new AuthV2ZKProvider({
    witnessCalculator: new SmokeWitnessCalculator(),
    prover: new SmokeNativeProver()
  }).generateProof(authV2GenerateProofInput(authArtifacts, completeAuthV2WitnessInputs()));
  assert(authProof.circuitId === CircuitId.AuthV2, "expected AuthV2 proof circuit id");
  assert(authProof.proof.smokeNativeProof === true, "expected native prover proof result");
  const witnesscalcFake = new CircomWitnessNativeCalculator({
    module: new SmokeCircomWitnesscalcModule(),
    graphReader: new SmokeGraphReader()
  });
  const witnessAvailability = await witnesscalcFake.checkAvailable();
  assert(witnessAvailability.available === true, "expected fake witness calculator availability");
  assert(
    witnessAvailability.message.includes("Real witness calculation requires complete circuit inputs"),
    "expected witness availability to avoid fake witness execution"
  );
  const nativeWitnessResult = await witnesscalcFake.calculateWitness({
    circuitId: CircuitId.AuthV2,
    graphPath: "file:///circuits/AuthV2/authV2.wcd",
    inputs: completeAuthV2WitnessInputs()
  });
  assert(nativeWitnessResult.witness === Buffer.from("smoke-witness").toString("base64"), "expected fake native witness result");
  const graphInfo = await witnesscalcFake.inspectGraph("file:///circuits/AuthV2/authV2.wcd");
  assert(graphInfo.graphSource === "base64", "expected witness graph source to be base64");
  assert(graphInfo.graphExtension === ".wcd", "expected witness graph extension summary");
  assert(graphInfo.graphExists === true, "expected witness graph to be readable");
  assert(graphInfo.graphSizeBytes === 10, "expected witness graph size");
  const nativeOnchainWitnessResult = await witnesscalcFake.calculateWitness({
    circuitId: CircuitId.CredentialAtomicQuerySigV2OnChain,
    graphPath: "file:///circuits/credentialAtomicQuerySigV2OnChain/credentialAtomicQuerySigV2OnChain.wcd",
    inputs: {
      requestID: "1782204596",
      userGenesisID: "1",
      challenge: "1337",
      authClaim: ["0", "0", "0", "0", "0", "0", "0", "0"],
      userClaimsTreeRoot: "0",
      gistRoot: "0"
    }
  });
  assert(nativeOnchainWitnessResult.witness === Buffer.from("smoke-witness").toString("base64"), "expected fake native on-chain witness result");
  await expectRejectsIncludes(
    () => witnesscalcFake.calculateWitness({
      circuitId: CircuitId.AuthV2,
      graphPath: "file:///circuits/AuthV2/authV2.wcd",
      inputs: {
        ...completeAuthV2WitnessInputs(),
        profileNonce: "0",
        challenge: undefined,
        requestId: "smoke-auth-v2"
      }
    }),
    "AuthV2 inputs are not ready for native witness: challenge must be a decimal bigint string."
  );
  await expectRejectsIncludes(
    () => new CircomWitnessNativeCalculator({
      loadModule: () => {
        throw new Error("not linked");
      }
    }).checkAvailable(),
    "Native witness calculator module is not available in this build."
  );
  const rapidsnarkFake = new RapidsnarkNativeProver({
    module: new SmokeRapidsnarkModule(),
    fileInspector: new SmokeProverFileInspector()
  });
  const rapidsnarkAvailability = await rapidsnarkFake.checkAvailable("file:///circuits/AuthV2/AuthV2.zkey");
  assert(rapidsnarkAvailability.available === true, "expected fake Rapidsnark module availability");
  assert(rapidsnarkAvailability.publicBufferSize === 128, "expected fake public buffer size");
  const rapidsnarkProof = await rapidsnarkFake.generateProof({
    circuitId: CircuitId.AuthV2,
    zkeyPath: "file:///circuits/AuthV2/AuthV2.zkey",
    witness: Buffer.from("smoke-witness").toString("base64")
  });
  assert(rapidsnarkProof.proof.proof === "smoke-proof", "expected fake Rapidsnark proof envelope");
  const rapidsnarkOnchainProof = await rapidsnarkFake.generateProof({
    circuitId: CircuitId.CredentialAtomicQuerySigV2OnChain,
    zkeyPath: "file:///circuits/credentialAtomicQuerySigV2OnChain/credentialAtomicQuerySigV2OnChain.zkey",
    witness: Buffer.from("smoke-witness").toString("base64")
  });
  assert(rapidsnarkOnchainProof.publicSignals.length === 1, "expected fake on-chain Rapidsnark public signals");
  await expectRejectsIncludes(
    () => new RapidsnarkNativeProver({
      loadModule: () => {
        throw new Error("not linked");
      }
    }).checkAvailable("file:///circuits/AuthV2/AuthV2.zkey"),
    "Native Rapidsnark module is not available in this build."
  );
  await expectRejectsIncludes(
    () => Promise.resolve(new CircuitArtifactStore().require(CircuitId.AuthV2)),
    "AuthV2 circuit artifacts are required"
  );
  await expectRejectsIncludes(
    () => runCircuitDownloadSmoke({ includeOnChain: false }),
    "Missing required circuit artifact: credentialAtomicQuerySigV2OnChain.zkey"
  );
  const downloadSmoke = await runCircuitDownloadSmoke({ includeOnChain: true });
  assert(downloadSmoke.status === "downloaded", "expected mock circuit zip download");
  assert(downloadSmoke.descriptors.length === 3, "expected three circuit descriptors from zip");
  assert(
    downloadSmoke.descriptors.every((descriptor) => descriptor.graphPath?.endsWith(".wcd")),
    "expected zip descriptors to use graphPath for wcd files"
  );
  assert(
    downloadSmoke.descriptors.every((descriptor) => descriptor.zkeyPath?.endsWith(".zkey")),
    "expected zip descriptors to use zkeyPath for zkey files"
  );
  assert(!("zkeyBytes" in downloadSmoke.descriptors[0]), "downloader must not load zkey bytes into JS");
  const cachedDownloadSmoke = await runCircuitAlreadyCachedSmoke();
  assert(cachedDownloadSmoke.status === "already-cached", "expected completed extracted cache to avoid redownload");
  assert(cachedDownloadSmoke.downloads === 0, "expected no download for completed extracted cache");
  await expectRejectsIncludes(
    () => runCorruptZipSmoke(),
    "Circuit ZIP is incomplete or corrupted. Please retry download."
  );
  await sdk.deleteCredential("urn:test");
  assert((await sdk.getCredentials()).length === 0, "expected delete credential");
  await sdk.saveCredential(imported.credential);
  await sdk.clearCredentials();
  assert((await sdk.getCredentials()).length === 0, "expected clear credentials");

  const mobileSafeImports = await loadMobileSafePolygonIdIdentityKms();
  assert(typeof mobileSafeImports.IdentityWallet === "function", "expected mobile-safe IdentityWallet import");
  assert(typeof mobileSafeImports.KMS === "function", "expected mobile-safe KMS import");
  assert(typeof mobileSafeImports.BjjProvider === "function", "expected mobile-safe BjjProvider import");
  assert(typeof mobileSafeImports.CredentialWallet === "function", "expected mobile-safe CredentialWallet import");
  assertNoLoadedModule("snarkjs");
  assertNoLoadedModule("ffjavascript");

  const realHolder = await sdk.createOrLoadHolderDid({ mode: "real", method: "iden3", network: "amoy" });
  const loadedRealHolder = await sdk.createOrLoadHolderDid({ mode: "real", method: "iden3", network: "amoy" });
  assert(realHolder.developmentOnly === false, "expected real holder DID to be marked developmentOnly false");
  assert(realHolder.did.startsWith("did:iden3:polygon:amoy:"), "expected real holder DID on iden3 polygon amoy");
  assert(realHolder.isNew === true, "expected first real holder DID call to create identity");
  assert(loadedRealHolder.isNew === false, "expected second real holder DID call to load identity");
  assert(realHolder.did === loadedRealHolder.did, "expected real holder DID to persist between calls");
  assert(realHolder.keyId.startsWith("BJJ:"), "expected real holder DID to keep an internal BJJ KMS key reference");
  assert(!("privateKey" in realHolder), "real holder result must not expose private key");
  assert(!("seed" in realHolder), "real holder result must not expose seed");
  const bjjSignature = await mobileBjjKmsAdapter.sign(new Uint8Array([1, 2, 3]), realHolder.keyId);
  assert(bjjSignature.byteLength === 64, "expected BJJ KMS to return compressed signature bytes");
  const authV2ChallengeSignature = await new MobileAuthV2ChallengeSigner({
    kmsAdapter: mobileBjjKmsAdapter
  }).signAuthV2Challenge({
    request: {
      challenge: "21888242871839275222246405745257275088548364400416034343698204186575808495616"
    },
    runtime: {
      holderDid: realHolder,
      keyId: realHolder.keyId
    }
  });
  assert(authV2ChallengeSignature?.challengeSignature?.R8?.length === 2, "expected AuthV2 signer to sign large decimal challenge safely");
  assert(
    !secureKeyStore.usedKeys.some((key) => key === realHolder.keyId || key.includes("BJJ:")),
    "SecureStore physical keys must not contain raw BJJ key id"
  );
  const authV2ProofSource = new MobileAuthV2IdentityProofSource({ secureKeyStore });
  const authV2Context = smokeAuthV2Context(realHolder);
  const authClaimProof = await authV2ProofSource.getAuthClaimProof(authV2Context);
  const treeState = await authV2ProofSource.getTreeState(authV2Context);
  assert(authClaimProof?.authClaim, "expected auth claim material to be persisted for AuthV2");
  assert(Array.isArray(authClaimProof.authClaim), "expected auth claim to be marshaled for circuit");
  assert(authClaimProof.authClaim.length === 8, "expected auth claim marshal to contain 8 slots");
  assert(authClaimProof.authClaim.every((item) => /^(0|[1-9][0-9]*)$/.test(item)), "expected auth claim marshal slots to be decimal strings");
  assert(authClaimProof.authClaimIncMtp, "expected auth claim inclusion MTP to be generated");
  assert(
    authClaimProof.authClaimIncMtp.root === treeState?.claimsTreeRoot,
    "expected inclusion proof root to match claims tree root"
  );
  assert(authClaimProof.authClaimIncMtp.existence === true, "expected auth claim inclusion proof to exist");
  assert(authClaimProof.authClaimNonRevMtp, "expected auth claim non-revocation MTP to be generated");
  assert(authClaimProof.authClaimNonRevMtp.existence === false, "expected non-revocation proof to be non-existence proof");
  assert(
    authClaimProof.authClaimNonRevMtp.root === treeState?.revTreeRoot,
    "expected non-revocation proof root to match revocation tree root"
  );
  assert(treeState?.state, "expected identity state material to be persisted for AuthV2");
  await expectRejectsIncludes(
    () => new ReadOnlyMobileGistProofSource().getGISTProof(realHolder.did),
    "AuthV2 GIST resolver is not configured."
  );
  const fakeGistProof = await new ReadOnlyMobileGistProofSource({
    didResolverUrl: "https://resolver.example",
    httpClient: new SmokeGistProofHttpClient()
  }).getGISTProof(realHolder.did);
  assert(fakeGistProof?.source === "did-resolver", "expected fake GIST proof to use did resolver source");
  assert(fakeGistProof.root === "9", "expected fake GIST root to be normalized");
  assert(fakeGistProof.siblings.length === 2, "expected fake GIST siblings to be normalized");
  const decimalGistProof = toAuthV2GistProof(fakeGistProof);
  assert(decimalGistProof.gistRoot === "9", "expected decimal GIST root to remain decimal");
  const hexGistRoot = "b73135ea8c9efb85d098a255a8ba51470ba42f28823c149368e89ef12fcb011";
  const hexGistProof = toAuthV2GistProof({
    ...fakeGistProof,
    root: hexGistRoot,
    siblings: [hexGistRoot, "0x01"],
    auxIndex: "0x02",
    auxValue: "3"
  });
  const expectedMerkleTreeRoot = "8002023259901180240986772175488614922639946340578510705318573273993058677515";
  assert(hexGistProof.gistRoot === expectedMerkleTreeRoot, "expected hex GIST root to use merkletree Hash.fromHex conversion");
  assert(hexGistProof.gistMtp.siblings[0] === expectedMerkleTreeRoot, "expected hex GIST sibling to use merkletree Hash.fromHex conversion");
  assert(
    toDecimalBigIntString(hexGistRoot) !== BigInt(`0x${hexGistRoot}`).toString(10),
    "expected direct BigInt hex conversion to be avoided"
  );
  assert(
    hexGistProof.gistMtpAuxHi === "904625697166532776746648320380374280103671755200316906558262375061821325312",
    "expected hex GIST aux index to use merkletree Hash.fromHex conversion"
  );
  assert(hexGistProof.gistMtpNoAux === "0", "expected GIST NoAux to be numeric string when aux exists");
  const numericOnlyHexHash = "1".repeat(64);
  const numericOnlyHexGistProof = toAuthV2GistProof({
    ...fakeGistProof,
    root: numericOnlyHexHash,
    siblings: [numericOnlyHexHash],
    auxIndex: numericOnlyHexHash,
    auxValue: "0"
  });
  assert(
    numericOnlyHexGistProof.gistRoot === numericOnlyHexHash,
    "expected numeric-only GIST string to remain decimal"
  );
  const hexGistPreview = buildAuthV2InputsPreview({
    ...completeAuthV2WitnessInputs(),
    gistRoot: hexGistProof.gistRoot,
    gistMtp: hexGistProof.gistMtp,
    gistMtpAuxHi: hexGistProof.gistMtpAuxHi,
    gistMtpAuxHv: hexGistProof.gistMtpAuxHv,
    gistMtpNoAux: hexGistProof.gistMtpNoAux
  });
  assert(hexGistPreview.nativeReady === true, "expected preflight to accept normalized hex GIST proof");
  await expectRejectsIncludes(
    () => Promise.resolve(buildAuthV2InputsPreview({
      ...completeAuthV2WitnessInputs(),
      gistRoot: BigInt(`0x${"f".repeat(64)}`).toString(10)
    })),
    "AuthV2 inputs overflow before witness: gistRoot"
  );
  const offerMessage = {
    id: "smoke-offer-message",
    typ: "application/iden3comm-plain-json",
    type: "https://iden3-communication.io/credentials/1.0/offer",
    from: "did:iden3:polygon:amoy:issuer",
    body: {
      url: "https://issuer.example/v1/agent",
      credentials: [
        {
          id: "smoke-credential-offer-id",
          description: "Smoke credential offer"
        }
      ]
    }
  };
  const parsedOffer = parseCredentialOffer(JSON.stringify(offerMessage));
  assert(parsedOffer.message.type === offerMessage.type, "expected JSON credential offer parsing");
  await expectRejectsIncludes(
    () => sdk.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "ZKProvider is required to generate AuthV2 proof for credential claim."
  );
  const sdkWithZkNoArtifacts = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new SmokeZkProvider()
  });
  await sdkWithZkNoArtifacts.init();
  await expectRejectsIncludes(
    () => sdkWithZkNoArtifacts.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "AuthV2 circuit artifacts are required to claim a credential from offer."
  );
  const sdkWithInjectedArtifactStore = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new SmokeZkProvider(),
    httpClient: new SmokeGistMissingHttpClient(),
    circuitArtifactStore: artifactStore
  });
  await sdkWithInjectedArtifactStore.init();
  await expectRejectsIncludes(
    () => sdkWithInjectedArtifactStore.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "AuthV2 GIST proof is not available for genesis identity on network amoy."
  );
  const sdkWithCompleteAuthV2Inputs = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new SmokeZkProvider(),
    authV2InputBuilder: new SmokeAuthV2InputBuilder(),
    circuitArtifactStore: artifactStore
  });
  await sdkWithCompleteAuthV2Inputs.init();
  await expectRejectsIncludes(
    () => sdkWithCompleteAuthV2Inputs.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "Iden3comm claim provider is required to fetch credentials from offer after AuthV2 proof creation."
  );
  const sdkWithAuthV2Boundary = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter: mobileBjjKmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new AuthV2ZKProvider(),
    authV2InputBuilder: new SmokeAuthV2InputBuilder(),
    circuitArtifactStore: artifactStore
  });
  await sdkWithAuthV2Boundary.init();
  const preview = await sdkWithAuthV2Boundary.buildAuthV2InputsPreview({
    message: JSON.stringify(offerMessage),
    holderDid: realHolder.did
  });
  assert(preview.ready === true, "expected fake AuthV2 preview to be ready");
  assert(preview.nativeReady === true, "expected fake AuthV2 preview to be native-ready");
  assert(preview.fields.length > 0, "expected AuthV2 preview fields");
  assert(preview.authClaimSlots === 8, "expected AuthV2 preview auth claim slots");
  assert(preview.challenge === "decimal bigint string", "expected AuthV2 preview challenge shape");
  assert(preview.siblingsCount === 40, "expected AuthV2 preview auth claim siblings to be padded to circuit level");
  assert(preview.nonRevSiblingsCount === 40, "expected AuthV2 preview auth claim non-rev siblings to be padded to circuit level");
  assert(preview.gistSiblingsCount === 64, "expected AuthV2 preview gist siblings to be padded to on-chain circuit level");
  assert(preview.rootsStatePresent === true, "expected AuthV2 preview roots/state summary");
  assert(preview.signaturePresent === true, "expected AuthV2 preview signature summary");
  assert(!("nativeInputs" in preview), "AuthV2 preview must not expose full native witness inputs");
  const directPreview = buildAuthV2InputsPreview(completeAuthV2WitnessInputs());
  assert(directPreview.nativeReady === true, "expected direct AuthV2 preflight to be native-ready");
  assert(directPreview.siblingsCount === 40, "expected direct AuthV2 preflight to pad auth MTP siblings");
  assert(directPreview.gistSiblingsCount === 64, "expected direct AuthV2 preflight to pad GIST siblings");
  const nativeInputs = coerceAuthV2NativeWitnessInputs(completeAuthV2WitnessInputs());
  assert(nativeInputs.authClaimNonRevMtpNoAux === "1", "expected auth non-rev NoAux to be numeric string");
  assert(nativeInputs.gistMtpNoAux === "1", "expected GIST NoAux to be numeric string");
  assert(nativeInputs.authClaimNonRevMtpAuxHi === "0", "expected auth non-rev aux hi to be decimal string");
  assert(nativeInputs.gistMtpAuxHv === "0", "expected GIST aux hv to be decimal string");
  assert(!authV2RequiredWitnessFields.includes("requestId"), "AuthV2 native witness must not require requestId");
  await expectRejectsIncludes(
    () => Promise.resolve(buildAuthV2InputsPreview({
      ...completeAuthV2WitnessInputs(),
      challenge: "textual-challenge"
    })),
    "AuthV2 inputs are not ready for native witness: challenge must be a decimal bigint string."
  );
  await expectRejectsIncludes(
    () => sdkWithAuthV2Boundary.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "Mobile witness calculator is required to generate AuthV2 proof."
  );
  const sdkWithDefaultAuthV2Builder = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new AuthV2ZKProvider({
      witnessCalculator: new SmokeWitnessCalculator()
    }),
    httpClient: new SmokeGistMissingHttpClient(),
    circuitArtifactStore: artifactStore
  });
  await sdkWithDefaultAuthV2Builder.init();
  await expectRejectsIncludes(
    () => sdkWithDefaultAuthV2Builder.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "AuthV2 GIST proof is not available for genesis identity on network amoy."
  );
  const sdkWithFakeGistSource = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter: mobileBjjKmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new AuthV2ZKProvider(),
    gistProofSource: new ReadOnlyMobileGistProofSource({
      didResolverUrl: "https://resolver.example",
      httpClient: new SmokeGistProofHttpClient()
    }),
    circuitArtifactStore: artifactStore
  });
  await sdkWithFakeGistSource.init();
  const defaultBuilderPreview = await sdkWithFakeGistSource.buildAuthV2InputsPreview({
    message: JSON.stringify(offerMessage),
    holderDid: realHolder.did
  });
  assert(defaultBuilderPreview.nativeReady === true, "expected default AuthV2 builder with fake GIST to be native-ready");
  assert(defaultBuilderPreview.authClaimSlots === 8, "expected default builder auth claim slots");
  assert(defaultBuilderPreview.challenge === "decimal bigint string", "expected default builder decimal challenge");
  await expectRejectsIncludes(
    () => sdkWithFakeGistSource.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "Mobile witness calculator is required to generate AuthV2 proof."
  );
  const sdkWithWitnessOnly = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter: mobileBjjKmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    authV2InputBuilder: new SmokeAuthV2InputBuilder(),
    authV2WitnessCalculator: witnesscalcFake,
    authV2NativeProver: rapidsnarkFake,
    circuitArtifactStore: artifactStore
  });
  await sdkWithWitnessOnly.init();
  const witnessOnly = await sdkWithWitnessOnly.generateAuthV2WitnessOnly({
    message: JSON.stringify(offerMessage),
    holderDid: realHolder.did
  });
  assert(witnessOnly.witnessGenerated === true, "expected witness-only flow to generate witness");
  assert(witnessOnly.graphSource === "base64", "expected witness-only graph source summary");
  assert(witnessOnly.graphExtension === ".wcd", "expected witness-only graph extension summary");
  assert(witnessOnly.graphExists === true, "expected witness-only graph exists summary");
  assert(witnessOnly.graphSizeBytes === 10, "expected witness-only graph size summary");
  assert(witnessOnly.inputsKeysCount === 21, "expected witness-only native input key count");
  assert(witnessOnly.authClaimIncMtpSiblings === 40, "expected witness-only auth claim MTP siblings count");
  assert(witnessOnly.gistMtpSiblings === 64, "expected witness-only GIST MTP siblings count");
  assert(!("witness" in witnessOnly), "witness-only summary must not expose witness");
  const proofOnly = await sdkWithWitnessOnly.generateAuthV2ProofOnly({
    message: JSON.stringify(offerMessage),
    holderDid: realHolder.did
  });
  assert(proofOnly.proofGenerated === true, "expected proof-only flow to generate proof");
  assert(proofOnly.zkeyPathExists === true, "expected proof-only zkey exists summary");
  assert(proofOnly.zkeySizeBytes === 12, "expected proof-only zkey size summary");
  assert(proofOnly.publicSignalsCount === 1, "expected proof-only public signals count");
  assert(!("proof" in proofOnly), "proof-only summary must not expose proof");
  const sdkWithWitnessNoProver = createPrivadoExpoClient(baseConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new AuthV2ZKProvider({
      witnessCalculator: new SmokeWitnessCalculator()
    }),
    authV2InputBuilder: new SmokeAuthV2InputBuilder(),
    circuitArtifactStore: artifactStore
  });
  await sdkWithWitnessNoProver.init();
  await expectRejectsIncludes(
    () => sdkWithWitnessNoProver.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "Native prover is required to generate AuthV2 proof."
  );
  const sdkWithAuthV2 = createPrivadoExpoClient({
    ...baseConfig,
    circuits: {
      artifacts: [authV2Artifact()]
    }
  }, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new SmokeZkProvider(),
    authV2InputBuilder: new SmokeAuthV2InputBuilder()
  });
  await sdkWithAuthV2.init();
  await expectRejectsIncludes(
    () => sdkWithAuthV2.claimCredentialFromOffer({ message: JSON.stringify(offerMessage), holderDid: realHolder.did }),
    "Iden3comm claim provider is required to fetch credentials from offer after AuthV2 proof creation."
  );
  const issuerConfig = {
    ...baseConfig,
    issuer: {
      issuerDid: "did:iden3:polygon:amoy:issuer",
      issuerAdminBase: "https://issuer.example",
      basicAuth: {
        username: "user",
        password: "pass"
      }
    },
    credential: {
      credentialType: "PersonCredential",
      credentialSchema: "https://schema.example/person.json",
      credentialContext: "https://context.example/person.json",
      credentialExpirationDays: 365
    },
    circuits: {
      artifacts: [authV2Artifact()]
    }
  };
  const issuerFetch = new SmokeIssuerFetch(realHolder.did);
  const issuerZkProvider = new TrackingZkProvider();
  const sdkWithIssuerProvider = createPrivadoExpoClient(issuerConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: issuerZkProvider,
    authV2InputBuilder: new SmokeAuthV2InputBuilder(),
    iden3commClaimProvider: new IssuerClaimProvider({
      config: issuerConfig,
      fetchFn: issuerFetch.fetch.bind(issuerFetch),
      uuid: () => "11111111-1111-4111-8111-111111111111"
    })
  });
  await sdkWithIssuerProvider.init();
  const issuerClaim = await sdkWithIssuerProvider.claimCredentialFromIssuer({
    holderDid: realHolder.did,
    credentialSubject: {
      fullName: "Smoke Holder",
      nationalIdNumber: "12345678",
      birthDate: 946684800
    }
  });
  assert(issuerClaim.credentialSaved === true, "expected issuer claim to save credential");
  assert(issuerClaim.credentialType === "PersonCredential", "expected issuer claim credential type summary");
  assert(issuerClaim.issuerDid === issuerConfig.issuer.issuerDid, "expected issuer DID summary");
  assert(typeof issuerClaim.storageId === "string", "expected issuer claim storage id");
  assert(issuerFetch.createdCredential === true, "expected issuer provider to create credential through Admin API");
  assert(issuerFetch.requestedOffer === true, "expected issuer provider to request raw offer");
  assert(issuerFetch.claimedCredential === true, "expected issuer provider to POST fetch request to agent");
  assert(issuerZkProvider.lastChallenge && issuerZkProvider.lastChallenge !== "12345678901234567890", "expected issuer claim to use JWZ message hash challenge");
  assert(!JSON.stringify(issuerClaim).includes("Smoke Holder"), "issuer claim result must not expose full VC subject");
  assert(!JSON.stringify(issuerClaim).includes("pass"), "issuer claim result must not expose Basic Auth secret");
  const issuerDebugFetch = new SmokeIssuerFetch(realHolder.did);
  const sdkWithIssuerDebug = createPrivadoExpoClient(issuerConfig, {
    secureKeyStore,
    credentialStorage,
    identityStorage,
    kmsAdapter,
    developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
    zkProvider: new SmokeZkProvider(),
    authV2InputBuilder: new SmokeAuthV2InputBuilder()
  });
  await sdkWithIssuerDebug.init();
  const previousFetch = globalThis.fetch;
  globalThis.fetch = issuerDebugFetch.fetch.bind(issuerDebugFetch);
  let debugResult;
  try {
    debugResult = await sdkWithIssuerDebug.claimCredentialFromIssuerDebug({
      holderDid: realHolder.did,
      credentialSubject: {
        fullName: "Smoke Holder",
        nationalIdNumber: "12345678",
        birthDate: 946684800
      }
    });
  } finally {
    globalThis.fetch = previousFetch;
  }
  assert(debugResult.steps.some((step) => step.step === "createCredential" && step.status === "ok"), "expected debug createCredential ok step");
  assert(debugResult.steps.some((step) => step.step === "offer" && step.status === "ok"), "expected debug offer ok step");
  assert(debugResult.steps.some((step) => step.step === "claim" && step.status === "ok"), "expected debug claim ok step");
  assert(debugResult.steps.some((step) => step.step === "claim" && step.claimLocalStep === "build-fetch-request" && step.messageIdFormat === "uuid" && step.threadIdFormat === "uuid"), "expected debug to report UUID id formats");
      assert(debugResult.steps.some((step) => step.step === "claim" && step.claimLocalStep === "compute-jwz-challenge" && step.challengeUnderField === true), "expected debug to report JWZ challenge computation");
  assert(debugResult.steps.some((step) => step.step === "claim" && step.claimLocalStep === "generate-authv2-proof" && step.postExecuted === false), "expected debug to report local AuthV2 proof step before POST");
  assert(debugResult.steps.some((step) => step.step === "claim" && step.claimLocalStep === "post-agent" && step.postExecuted === true), "expected debug to report POST execution");
  const receivedCredentialStep = debugResult.steps.find((step) => step.step === "claim" && step.claimLocalStep === "receive-credential");
  assert(receivedCredentialStep, "expected debug to report received credential summary");
  assert(receivedCredentialStep.credentialSummary.proofTypes.includes("BJJSignature2021"), "expected debug credential summary proof types");
  assert(receivedCredentialStep.credentialSummary.mtpViable === false, "expected BJJ-only issuer response to mark MTP unavailable");
  assert(receivedCredentialStep.credentialSummary.mtpUnavailableReason === "Issuer returned only BJJSignature2021; MTP unavailable.", "expected MTP unavailable reason");
  assert(receivedCredentialStep.credentialSummary.credentialStatus.type === "Iden3commRevocationStatusV1.0", "expected credentialStatus type summary");
  assert(!receivedCredentialStep.credentialSummary.credentialStatus.url.includes("?"), "credentialStatus debug URL must not include query");
  assert(debugResult.steps.some((step) => step.step === "save" && step.status === "saved"), "expected debug save saved step");
  const debugJson = JSON.stringify(debugResult);
  assert(!debugJson.includes("Basic "), "issuer debug must not expose Authorization header");
  assert(!debugJson.includes("smoke-fetch-request-debug."), "issuer debug must not expose JWZ token");
  assert(!debugJson.includes("authv2-fetch-"), "issuer debug must not use timestamp fetch-request ids");
  assert(!debugJson.includes("Smoke Holder"), "issuer debug must not expose full VC subject");
  const localChallengeSteps = [];
  const localChallengeProvider = new IssuerClaimProvider({
    config: issuerConfig,
    fetchFn: new SmokeIssuerFetch(realHolder.did).fetch,
    uuid: () => "22222222-2222-4222-8222-222222222222",
    onDebug: (step) => localChallengeSteps.push(step),
    challengeCalculator: async () => "21888242871839275222246405745257275088548364400416034343698204186575808495617"
  });
  await expectRejectsIncludes(
    () => localChallengeProvider.prepareClaimRequests({
      input: { message: issuerOfferMessage(realHolder.did) },
      message: issuerOfferMessage(realHolder.did),
      holderDid: realHolder,
      keyId: realHolder.keyId,
      profileNonce: "0"
    }),
    "JWZ challenge is outside the BN254 field."
  );
  assert(localChallengeSteps.some((step) => step.step === "claim" && step.claimLocalStep === "compute-jwz-challenge" && step.status === "error" && step.httpStatus === undefined && step.postExecuted === false), "expected local challenge error not to be reported as HTTP");
  const invalidIdFetch = new SmokeIssuerFetch(realHolder.did);
  const invalidIdSteps = [];
  const invalidIdProvider = new IssuerClaimProvider({
    config: issuerConfig,
    fetchFn: invalidIdFetch.fetch.bind(invalidIdFetch),
    uuid: () => "authv2-fetch-1781272183581",
    onDebug: (step) => invalidIdSteps.push(step),
    challengeCalculator: async () => "123"
  });
  await expectRejectsIncludes(
    () => invalidIdProvider.prepareClaimRequests({
      input: { message: issuerOfferMessage() },
      message: issuerOfferMessage(),
      holderDid: realHolder,
      keyId: realHolder.keyId,
      profileNonce: "0"
    }),
    "Iden3comm fetch-request id must be a UUID."
  );
  assert(invalidIdFetch.claimedCredential === false, "expected invalid fetch-request id not to POST");
  assert(invalidIdSteps.some((step) => step.step === "claim" && step.claimLocalStep === "build-fetch-request" && step.status === "error" && step.postExecuted === false), "expected invalid UUID to stop at build-fetch-request");
  const packFailureFetch = new SmokeIssuerFetch(realHolder.did);
  const packFailureSteps = [];
  const packFailureProvider = new IssuerClaimProvider({
    config: issuerConfig,
    fetchFn: packFailureFetch.fetch.bind(packFailureFetch),
    uuid: () => "33333333-3333-4333-8333-333333333333",
    onDebug: (step) => packFailureSteps.push(step),
    challengeCalculator: async () => "123"
  });
  const preparedPackFailure = await packFailureProvider.prepareClaimRequests({
    input: { message: issuerOfferMessage(realHolder.did) },
    message: issuerOfferMessage(realHolder.did),
    holderDid: realHolder,
    keyId: realHolder.keyId,
    profileNonce: "0"
  });
  await expectRejectsIncludes(
    () => packFailureProvider.claimPreparedCredentialRequests(preparedPackFailure, { proof: {} }),
    "AuthV2 proof is incomplete for issuer claim."
  );
  assert(packFailureFetch.claimedCredential === false, "expected issuer POST not to run when JWZ pack fails");
  assert(packFailureSteps.some((step) => step.step === "claim" && step.claimLocalStep === "pack-jwz" && step.status === "error" && step.postExecuted === false), "expected pack JWZ local error before POST");
  const createIssuerDebugSdk = (config) => createPrivadoExpoClient(config, {
      secureKeyStore,
      credentialStorage,
      identityStorage,
      kmsAdapter,
      developmentHolderDidProvider: new DevelopmentOnlyHolderDidProvider(),
      zkProvider: new SmokeZkProvider(),
      authV2InputBuilder: new SmokeAuthV2InputBuilder()
    });
  const runIssuerDebugFailure = async (mode) => {
    const sdk = createIssuerDebugSdk(issuerConfig);
    const fetch = new SmokeIssuerFetch(realHolder.did, mode);
    globalThis.fetch = fetch.fetch.bind(fetch);
    try {
      return await sdk.claimCredentialFromIssuerDebug({
        holderDid: realHolder.did,
        credentialSubject: {
          fullName: "Smoke Holder",
          nationalIdNumber: "12345678",
          birthDate: 946684800
        }
      });
    } finally {
      globalThis.fetch = previousFetch;
    }
  };
  const countBeforeIssuerFailures = (await sdkWithIssuerDebug.getCredentials()).length;
  const issuer401 = await runIssuerDebugFailure("create-401");
  assert(issuer401.credentialSaved === false, "expected 401 issuer debug not to save credential");
  assert(issuer401.steps.some((step) => step.step === "createCredential" && step.status === "error" && step.httpStatus === 401), "expected issuer 401 controlled create step");
  assert(issuer401.steps.some((step) => step.step === "save" && step.status === "skipped"), "expected issuer 401 save skipped");
  const missingUrl = await runIssuerDebugFailure("offer-missing-url");
  assert(missingUrl.credentialSaved === false, "expected missing offer url not to save credential");
  assert(missingUrl.steps.some((step) => step.step === "claim" && step.status === "error"), "expected missing offer url claim error");
  assert(missingUrl.steps.some((step) => step.step === "save" && step.status === "skipped"), "expected missing offer url save skipped");
  const invalidVc = await runIssuerDebugFailure("invalid-credential");
  assert(invalidVc.credentialSaved === false, "expected invalid credential not to save");
  assert(invalidVc.steps.some((step) => step.step === "save" && step.status === "skipped"), "expected invalid credential save skipped");
  const claim400 = await runIssuerDebugFailure("claim-400");
  assert(claim400.credentialSaved === false, "expected claim 400 not to save");
  assert(claim400.steps.some((step) => step.step === "claim" && step.status === "error" && step.httpStatus === 400), "expected issuer 400 controlled claim step");
  assert(claim400.steps.some((step) => step.step === "claim" && step.challengeSource === "jwz-message-hash"), "expected debug claim step to report JWZ challenge source");
  assert(claim400.steps.some((step) => step.step === "save" && step.status === "skipped"), "expected claim 400 save skipped");
  assert((await sdkWithIssuerDebug.getCredentials()).length === countBeforeIssuerFailures, "expected issuer failures not to save extra credentials");
  await sdk.deleteHolderIdentity();
  assert((await sdk.getHolderDid()) === undefined, "expected real holder DID to be removed before development smoke");

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

function assertNoLoadedModule(pattern) {
  const lowerPattern = pattern.toLowerCase();
  const loaded = Object.keys(require.cache).find((modulePath) =>
    modulePath.toLowerCase().includes(lowerPattern)
  );
  assert(!loaded, `expected ${pattern} not to be loaded, found ${loaded}`);
}

function assertNoRootPolygonIdSdkImport() {
  const offenders = [];
  for (const root of [path.resolve(__dirname, "../src"), path.resolve(__dirname, "../dist")]) {
    for (const filePath of walkFiles(root)) {
      if (!/\.(ts|tsx|js)$/.test(filePath)) {
        continue;
      }
      const source = fs.readFileSync(filePath, "utf8");
      if (
        /from\s+["']@0xpolygonid\/js-sdk["']/.test(source) ||
        /require\(\s*["']@0xpolygonid\/js-sdk["']\s*\)/.test(source) ||
        source.includes("@0xpolygonid/js-sdk/dist/node/cjs/index.cjs") ||
        source.includes("@0xpolygonid/js-sdk/dist/browser") ||
        source.includes("@iden3/js-jsonld-merklization")
      ) {
        offenders.push(path.relative(path.resolve(__dirname, ".."), filePath));
      }
    }
  }
  assert(offenders.length === 0, `Metro-unsafe proof builder import found: ${offenders.join(", ")}`);
}

function walkFiles(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    if (entry.name === "node_modules" || entry.name === ".expo") {
      return [];
    }
    const fullPath = path.join(dir, entry.name);
    return entry.isDirectory() ? walkFiles(fullPath) : [fullPath];
  });
}

class SmokeZkProvider {
  async generateProof(input) {
    return {
      circuitId: input.request.circuitId,
      proof: {
        smoke: true
      },
      publicSignals: [],
      request: input.request
    };
  }
}

class TrackingZkProvider extends SmokeZkProvider {
  async generateProof(input) {
    this.lastChallenge = input.request.challenge;
    return super.generateProof(input);
  }
}

class SmokeIdentityStorage {
  async getHolderDid() {
    return {
      did: "did:polygonid:polygon:amoy:2qTUPXNF422khVhMArC491vwLE6eEbMUvRgXj5EHdX",
      keyId: "BJJ:smoke",
      method: "iden3",
      network: "amoy",
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
      developmentOnly: false
    };
  }

  async saveHolderDid(record) {
    return record;
  }

  async deleteHolderIdentity() {
    return { deleted: true };
  }
}

class SmokeCredentialAtomicQuerySigV2InputBuilder {
  async buildInputs(input) {
    assert(input.plan.circuitId === CircuitId.CredentialAtomicQuerySigV2, "expected SigV2 proof plan");
    assert(input.plan.query.field === "age", "expected configurable query field");
    assert(input.plan.query.operator === "gt", "expected configurable query operator");
    assert(input.credential.id === "urn:test", "expected builder to receive stored credential internally");
    return {
      requestID: input.plan.request.id,
      userGenesisID: "1",
      profileNonce: "0",
      claimSubjectProfileNonce: "0",
      issuerID: "2",
      issuerClaim: ["0", "0", "0", "0", "0", "0", "0", "0"],
      issuerClaimNonRevClaimsTreeRoot: "0",
      issuerClaimNonRevRevTreeRoot: "0",
      issuerClaimNonRevRootsTreeRoot: "0",
      issuerClaimNonRevState: "0",
      issuerClaimNonRevMtp: ["0"],
      issuerClaimNonRevMtpNoAux: "1",
      issuerClaimSignatureR8x: "1",
      issuerClaimSignatureR8y: "2",
      issuerClaimSignatureS: "3",
      issuerAuthClaim: ["0", "0", "0", "0", "0", "0", "0", "0"],
      issuerAuthClaimMtp: ["0"],
      issuerAuthClaimNonRevMtp: ["0"],
      issuerAuthClaimNonRevMtpNoAux: "1",
      issuerAuthClaimsTreeRoot: "0",
      issuerAuthRevTreeRoot: "0",
      issuerAuthRootsTreeRoot: "0",
      claimSchema: "0",
      claimPathMtp: ["0"],
      claimPathMtpNoAux: "1",
      claimPathKey: "0",
      claimPathValue: "21",
      operator: 3,
      slotIndex: 2,
      timestamp: 1781272183,
      value: ["18"],
      isRevocationChecked: 1
    };
  }
}

class SmokeRevocationHttpClient {
  async request() {
    const { Proof, ZERO_HASH } = require("@iden3/js-merkletree");
    const zero = ZERO_HASH.hex();
    return {
      issuer: {
        state: zero,
        claimsTreeRoot: zero,
        revocationTreeRoot: zero,
        rootOfRoots: zero
      },
      mtp: new Proof().toJSON()
    };
  }
}

class SmokeBrokenRevocationHttpClient {
  async request() {
    const { Proof, ZERO_HASH } = require("@iden3/js-merkletree");
    const zero = ZERO_HASH.hex();
    return {
      issuer: {
        state: zero,
        claimsTreeRoot: zero,
        rootOfRoots: zero
      },
      mtp: new Proof().toJSON()
    };
  }
}

class SmokeIden3commRevocationHttpClient {
  constructor() {
    this.requests = [];
  }

  async request(input) {
    const { Proof, ZERO_HASH } = require("@iden3/js-merkletree");
    assert(input.method === "POST", "expected iden3comm revocation resolver to POST");
    assert(input.url === "https://issuer.example/agent/revocation", "expected iden3comm revocation endpoint");
    assert(input.body?.typ === "application/iden3comm-plain-json", "expected iden3comm plain json typ");
    assert(input.body?.type === "https://iden3-communication.io/revocation/1.0/request-status", "expected revocation request type");
    assert(input.body?.body?.revocation_nonce === 1 || input.body?.body?.revocation_nonce === 2, "expected revocation nonce");
    assert(typeof input.body?.from === "string" && input.body.from.startsWith("did:"), "expected from DID");
    assert(typeof input.body?.to === "string" && input.body.to.startsWith("did:"), "expected to DID");
    this.requests.push(input);
    const zero = ZERO_HASH.hex();
    return {
      body: {
        issuer: {
          state: zero,
          claimsTreeRoot: zero,
          revocationTreeRoot: zero,
          rootOfRoots: zero
        },
        mtp: new Proof().toJSON()
      }
    };
  }
}

function createSmokeSlotBasedSigV2Credential({
  birthDateSlotValue,
  omitIssuerRevocationTreeRoot = false,
  credentialStatusType = "SparseMerkleTreeProof"
}) {
  const { Claim, ClaimOptions, SchemaHash } = require("@iden3/js-iden3-core");
  const { PrivateKey, poseidon } = require("@iden3/js-crypto");
  const { Proof, ZERO_HASH } = require("@iden3/js-merkletree");
  const issuerDid = "did:polygonid:polygon:amoy:2qTUPXNF422khVhMArC491vwLE6eEbMUvRgXj5EHdX";
  const holderDid = "did:polygonid:polygon:amoy:2qTUPXNF422khVhMArC491vwLE6eEbMUvRgXj5EHdX";
  const issuerPrivateKey = new PrivateKey(Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1)));
  const issuerPublicKey = issuerPrivateKey.public().p;
  const coreClaim = Claim.newClaim(
    SchemaHash.authSchemaHash,
    ClaimOptions.withIndexDataInts(BigInt(birthDateSlotValue), null)
  );
  const authCoreClaim = Claim.newClaim(
    SchemaHash.authSchemaHash,
    ClaimOptions.withIndexDataInts(issuerPublicKey[0], issuerPublicKey[1])
  );
  const { hi, hv } = coreClaim.hiHv();
  const signature = issuerPrivateKey.signPoseidon(poseidon.hash([hi, hv])).hex();
  const zero = ZERO_HASH.hex();
  const mtp = new Proof().toJSON();
  const issuerState = {
    rootOfRoots: zero,
    claimsTreeRoot: zero,
    revocationTreeRoot: zero,
    value: zero
  };
  if (omitIssuerRevocationTreeRoot) {
    delete issuerState.revocationTreeRoot;
  }
  return {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    id: "urn:slot-sigv2",
    type: "PersonCredential",
    issuer: issuerDid,
    credentialSubject: {
      birthDate: 946684799
    },
    credentialStatus: {
      id: credentialStatusType === "Iden3commRevocationStatusV1.0"
        ? "https://issuer.example/agent/revocation"
        : "https://issuer.example/status/claim",
      type: credentialStatusType,
      revocationNonce: 1
    },
    proof: {
      type: "BJJSignature2021",
      coreClaim: coreClaim.hex(),
      signature,
      issuerData: {
        id: issuerDid,
        state: issuerState,
        mtp,
        authCoreClaim: authCoreClaim.hex(),
        credentialStatus: {
          id: credentialStatusType === "Iden3commRevocationStatusV1.0"
            ? "https://issuer.example/agent/revocation"
            : "https://issuer.example/status/auth",
          type: credentialStatusType,
          revocationNonce: 2
        }
      }
    }
  };
}

async function createSmokeMerklizedSigV2Credential() {
  const { Claim, ClaimOptions, SchemaHash } = require("@iden3/js-iden3-core");
  const { PrivateKey, poseidon } = require("@iden3/js-crypto");
  const { Proof, ZERO_HASH } = require("@iden3/js-merkletree");
  const { Merklizer } = require("@iden3/js-jsonld-merklization");
  const issuerDid = "did:polygonid:polygon:amoy:2qTUPXNF422khVhMArC491vwLE6eEbMUvRgXj5EHdX";
  const unsignedCredential = {
    "@context": [smokePersonCredentialContext()],
    id: "urn:merklized-sigv2",
    type: "PersonCredential",
    issuer: issuerDid,
    credentialSubject: {
      birthDate: 946684799
    },
    credentialStatus: {
      id: "https://issuer.example/status/claim",
      type: "SparseMerkleTreeProof",
      revocationNonce: 1
    }
  };
  const issuerPrivateKey = new PrivateKey(Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1)));
  const issuerPublicKey = issuerPrivateKey.public().p;
  const merklizer = await Merklizer.merklizeJSONLD(JSON.stringify(unsignedCredential));
  const coreClaim = Claim.newClaim(
    SchemaHash.authSchemaHash,
    ClaimOptions.withIndexMerklizedRoot((await merklizer.root()).bigInt())
  );
  const authCoreClaim = Claim.newClaim(
    SchemaHash.authSchemaHash,
    ClaimOptions.withIndexDataInts(issuerPublicKey[0], issuerPublicKey[1])
  );
  const { hi, hv } = coreClaim.hiHv();
  const signature = issuerPrivateKey.signPoseidon(poseidon.hash([hi, hv])).hex();
  const zero = ZERO_HASH.hex();
  return {
    ...unsignedCredential,
    proof: {
      type: "BJJSignature2021",
      coreClaim: coreClaim.hex(),
      signature,
      issuerData: {
        id: issuerDid,
        state: {
          rootOfRoots: zero,
          claimsTreeRoot: zero,
          revocationTreeRoot: zero,
          value: zero
        },
        mtp: new Proof().toJSON(),
        authCoreClaim: authCoreClaim.hex(),
        credentialStatus: {
          id: "https://issuer.example/status/auth",
          type: "SparseMerkleTreeProof",
          revocationNonce: 2
        }
      }
    }
  };
}

function smokePersonCredentialContext() {
  return {
    "@version": 1.1,
    "@vocab": "https://schema.example/vocab#",
    id: "@id",
    type: "@type",
    issuer: {
      "@id": "https://www.w3.org/2018/credentials#issuer",
      "@type": "@id"
    },
    credentialStatus: {
      "@id": "https://www.w3.org/2018/credentials#credentialStatus",
      "@context": {
        "@version": 1.1,
        "@vocab": "https://schema.example/status#",
        id: "@id",
        type: "@type",
        revocationNonce: {
          "@id": "https://schema.example/vocab#revocationNonce",
          "@type": "http://www.w3.org/2001/XMLSchema#integer"
        }
      }
    },
    credentialSubject: {
      "@id": "https://www.w3.org/2018/credentials#credentialSubject",
      "@context": {
        "@version": 1.1,
        birthDate: {
          "@id": "https://schema.example/PersonCredential#birthDate",
          "@type": "http://www.w3.org/2001/XMLSchema#integer"
        }
      }
    },
    VerifiableCredential: "https://www.w3.org/2018/credentials#VerifiableCredential",
    PersonCredential: "https://schema.example/PersonCredential"
  };
}

function smokeCredentialSigV2Plan({ credentialId, credentialType, issuerDid, field, operator, value }) {
  return {
    credentialId,
    credentialType,
    issuerDid,
    mode: "offchain",
    circuitId: CircuitId.CredentialAtomicQuerySigV2,
    query: { field, operator, value },
    request: { id: "123" },
    credentialSummary: { id: credentialId, type: ["VerifiableCredential", credentialType], issuer: issuerDid },
    proofGenerated: false,
    nextBoundary: "credentialAtomicQuerySigV2"
  };
}

function smokeGeneratedOnchainProof() {
  return {
    circuitId: CircuitId.CredentialAtomicQuerySigV2OnChain,
    request: {
      id: "1782204596",
      circuitId: CircuitId.CredentialAtomicQuerySigV2OnChain,
      query: {},
      scope: []
    },
    proof: {
      pi_a: ["1", "2", "1"],
      pi_b: [["3", "4"], ["5", "6"], ["1", "0"]],
      pi_c: ["7", "8", "1"]
    },
    publicSignals: [
      "1",
      "2",
      "3",
      "4",
      "1782204596",
      addressToUint256LE("0x176A3cd0e7d9B0936f594015eADF313Fd46558E7"),
      "7",
      "8",
      "9",
      "10",
      "11"
    ]
  };
}

async function assertJsonLdContextStoreSmoke() {
  const contextCid = "QmbaL4bG16tTYqAzn35qztT6cqTRZT1FMRfkcp5SLTDW2T";
  const contextUrl = `ipfs://${contextCid}`;
  const fetchUrls = [];
  const store = new JsonLdContextStore({
    fileSystem: new SmokeJsonLdContextFileSystem(),
    fetch: async (url) => ({
      ok: true,
      status: 200,
      text: async () => {
        fetchUrls.push(url);
        return JSON.stringify({ "@context": smokePersonCredentialContext() });
      }
    })
  });
  const credential = {
    "@context": [contextUrl],
    id: "urn:remote-context",
    type: "PersonCredential",
    issuer: "did:example:issuer",
    credentialSubject: {
      birthDate: 946684799
    }
  };
  assert(
    normalizeJsonLdContextUrl(contextCid) === contextUrl,
    "expected bare IPFS CID context normalization"
  );
  const bundledStore = new JsonLdContextStore({
    fileSystem: new SmokeJsonLdContextFileSystem(),
    bundledContexts: {
      [contextCid]: { "@context": smokePersonCredentialContext() }
    },
    fetch: async () => ({
      ok: false,
      status: 403,
      text: async () => "forbidden"
    })
  });
  const bundledEnsure = await bundledStore.ensureContextsForCredential({
    ...credential,
    "@context": [`https://ipfs.io/ipfs/${contextCid}`]
  });
  assert(bundledEnsure.bundled === 1, "expected bundled JSON-LD context to be used before fetch");
  const firstEnsure = await store.ensureContextsForCredential(credential);
  assert(firstEnsure.fetched === 1 && firstEnsure.cached === 0, "expected first JSON-LD context ensure to fetch");
  const secondEnsure = await store.ensureContextsForCredential({
    ...credential,
    "@context": [`https://ipfs.io/ipfs/${contextCid}`]
  });
  assert(secondEnsure.cached === 1 && secondEnsure.fetched === 0, "expected normalized IPFS context to be cached");
  assert(fetchUrls.length === 1, "expected JSON-LD context to be fetched once and then served from cache");
  const { Merklizer } = require("@iden3/js-jsonld-merklization");
  const merklizer = await Merklizer.merklizeJSONLD(JSON.stringify(credential), {
    documentLoader: store.createDocumentLoader()
  });
  const path = await merklizer.resolveDocPath("credentialSubject.birthDate", merklizer.options);
  const proofResult = await merklizer.proof(path);
  assert(Boolean(proofResult.value), "expected cached JSON-LD context to resolve birthDate ValueProof");
  await expectRejectsIncludes(
    () => new JsonLdContextStore({
      fileSystem: new SmokeJsonLdContextFileSystem(),
      fetch: async () => ({
        ok: false,
        status: 503,
        text: async () => "unavailable"
      })
    }).ensureContextsForCredential({ "@context": ["ipfs://missing-context"] }),
    "HTTP 503"
  );
}

class SmokeJsonLdValueProofProvider {
  async buildValueProof(input) {
    const { Merklizer, Path } = require("@iden3/js-jsonld-merklization");
    const credential = JSON.parse(JSON.stringify(input.credential));
    delete credential.proof;
    const merklizer = await Merklizer.merklizeJSONLD(JSON.stringify(credential));
    let path;
    try {
      path = await Path.getContextPathKey(
        JSON.stringify({ "@context": credential["@context"] }),
        input.credentialType,
        input.field,
        merklizer.options
      );
      path.prepend(["https://www.w3.org/2018/credentials#credentialSubject"]);
    } catch {
      path = await merklizer.resolveDocPath(`credentialSubject.${input.field}`, merklizer.options);
    }
    const proofResult = await merklizer.proof(path);
    if (!proofResult.value) {
      throw new Error(`ValueProof is missing for credentialSubject.${input.field}.`);
    }
    const datatype = await merklizer.jsonLDType(path);
    const values = input.operator === "noop" ? [] : Array.isArray(input.queryValue) ? input.queryValue : [input.queryValue];
    const queryValues = [];
    for (const value of values) {
      queryValues.push((await Merklizer.hashValue(datatype, value)).toString());
    }
    return {
      proof: proofResult.proof,
      pathKey: (await path.mtEntry()).toString(),
      pathValue: (await proofResult.value.mtEntry()).toString(),
      queryValues
    };
  }
}

class SmokeJsonLdContextFileSystem {
  constructor() {
    this.cacheDirectory = "memory://cache";
    this.files = new Map();
    this.directories = new Set();
  }

  async getInfo(path) {
    return {
      exists: this.files.has(path) || this.directories.has(path)
    };
  }

  async makeDirectory(path) {
    this.directories.add(path);
  }

  async readAsString(path) {
    const value = this.files.get(path);
    if (value === undefined) {
      throw new Error(`missing file ${path}`);
    }
    return value;
  }

  async writeAsString(path, value) {
    this.files.set(path, value);
  }
}

class SmokeCredentialWitnessCalculator {
  async calculateWitness(input) {
    assert(
      input.circuitId === CircuitId.CredentialAtomicQuerySigV2 ||
        input.circuitId === CircuitId.CredentialAtomicQuerySigV2OnChain,
      "expected SigV2 witness circuit"
    );
    assert(
      input.graphPath.includes("credentialAtomicQuerySigV2.wcd") ||
        input.graphPath.includes("credentialAtomicQuerySigV2OnChain.wcd"),
      "expected SigV2 graph path"
    );
    assert(input.inputs.requestID, "expected SigV2 witness inputs");
    if (input.circuitId === CircuitId.CredentialAtomicQuerySigV2OnChain) {
      assert(input.graphPath.includes("credentialAtomicQuerySigV2OnChain.wcd"), "expected SigV2 on-chain graph path");
      assert(input.inputs.challenge, "expected SigV2 on-chain challenge");
      assert(input.inputs.userClaimsTreeRoot, "expected SigV2 on-chain user state roots");
      assert(input.inputs.gistRoot, "expected SigV2 on-chain GIST root");
    }
    assert(!("credentialSubject" in input.inputs), "SigV2 native inputs must not include full credentialSubject");
    assert(!("__proofRoute" in input.inputs), "SigV2 native inputs must not include proof route metadata");
    return {
      witness: Buffer.from("credential-sigv2-witness").toString("base64")
    };
  }

  async inspectGraph(graphPath) {
    assert(graphPath.includes("credentialAtomicQuerySigV2.wcd") || graphPath.includes("credentialAtomicQuerySigV2OnChain.wcd"), "expected SigV2 graph inspect path");
    return {
      graphSource: "base64",
      graphExtension: ".wcd",
      graphExists: true,
      graphSizeBytes: 20
    };
  }
}

class SmokeCredentialProver {
  async generateProof(input) {
    assert(
      input.circuitId === CircuitId.CredentialAtomicQuerySigV2 ||
        input.circuitId === CircuitId.CredentialAtomicQuerySigV2OnChain,
      "expected SigV2 prover circuit"
    );
    assert(input.zkeyPath.includes("credentialAtomicQuerySigV2.zkey") || input.zkeyPath.includes("credentialAtomicQuerySigV2OnChain.zkey"), "expected SigV2 zkey path");
    assert(input.witness === Buffer.from("credential-sigv2-witness").toString("base64"), "expected SigV2 witness base64");
    return {
      proof: { proof: "smoke-proof" },
      publicSignals: ["signal-1", "signal-2"]
    };
  }

  async inspectZkey(zkeyPath) {
    assert(zkeyPath.includes("credentialAtomicQuerySigV2.zkey") || zkeyPath.includes("credentialAtomicQuerySigV2OnChain.zkey"), "expected SigV2 zkey inspect path");
    return {
      exists: true,
      sizeBytes: 20
    };
  }
}

function authV2Artifact() {
  return {
    circuitId: "AuthV2",
    version: "smoke",
    graphPath: "file:///circuits/AuthV2/authV2.wcd",
    zkeyPath: "file:///circuits/AuthV2/AuthV2.zkey",
    verificationKeyPath: "file:///circuits/AuthV2/verification_key.json",
    hashes: {
      graph: "smoke-authv2-graph",
      zkey: "smoke-authv2-zkey",
      verificationKey: "smoke-authv2-vkey"
    },
    sizes: {
      graph: 1,
      zkey: 1,
      verificationKey: 1
    }
  };
}

function authV2GenerateProofInput(circuitArtifacts, witnessInputs) {
  return {
    request: {
      id: "smoke-auth-v2",
      circuitId: CircuitId.AuthV2,
      challenge: "smoke-challenge",
      query: {
        type: "AuthV2"
      },
      scope: []
    },
    holderDid: "did:iden3:polygon:amoy:smoke",
    profileNonce: "0",
    circuitArtifacts,
    witnessInputs,
    metadata: {
      keyId: "BJJ:smoke"
    }
  };
}

class SmokeAuthV2InputBuilder extends AuthV2InputBuilder {
  async build(input) {
    return completeAuthV2WitnessInputs(input?.request?.challenge ?? "123");
  }
}

class TrackingSecureKeyStore {
  constructor(delegate) {
    this.delegate = delegate;
    this.usedKeys = [];
  }

  async getItem(key) {
    this.usedKeys.push(key);
    return this.delegate.getItem(key);
  }

  async setItem(key, value) {
    this.usedKeys.push(key);
    return this.delegate.setItem(key, value);
  }

  async deleteItem(key) {
    this.usedKeys.push(key);
    return this.delegate.deleteItem(key);
  }

  async getOrCreateEncryptionKey(alias) {
    this.usedKeys.push(alias);
    return this.delegate.getOrCreateEncryptionKey(alias);
  }

  async getOrCreateKey(alias) {
    this.usedKeys.push(alias);
    return this.delegate.getOrCreateKey(alias);
  }

  async deleteKey(alias) {
    this.usedKeys.push(alias);
    return this.delegate.deleteKey(alias);
  }
}

class SmokeGistMissingHttpClient {
  async request() {
    throw new Error("GIST proof not found");
  }
}

class SmokeGistProofHttpClient {
  async request() {
    return {
      didDocument: {
        verificationMethod: [
          {
            type: "Iden3StateInfo2023",
            global: {
              root: "9",
              proof: {
                existence: false,
                siblings: ["1", "2"],
                node_aux: {
                  key: "3",
                  value: "4"
                }
              }
            }
          }
        ]
      }
    };
  }
}

function completeAuthV2WitnessInputs(challenge = "123") {
  const { Claim, ClaimOptions, SchemaHash } = require("@iden3/js-iden3-core");
  const { PrivateKey, poseidon } = require("@iden3/js-crypto");
  const authPrivateKey = new PrivateKey(Uint8Array.from(Array.from({ length: 32 }, (_, index) => 32 - index)));
  const authPublicKey = authPrivateKey.public().p;
  const authClaim = Claim.newClaim(
    SchemaHash.authSchemaHash,
    ClaimOptions.withIndexDataInts(authPublicKey[0], authPublicKey[1]),
    ClaimOptions.withRevocationNonce(0n)
  );
  const authClaimHiHv = authClaim.hiHv();
  const authClaimLeafRoot = poseidon.hash([authClaimHiHv.hi, authClaimHiHv.hv, 1n]).toString();
  const challengeSignature = authPrivateKey.signPoseidon(BigInt(challenge));
  return {
    circuitId: CircuitId.AuthV2,
    genesisID: "1",
    profileNonce: "0",
    challenge,
    requestId: "smoke-auth-v2",
    authClaim: authClaim.marshalJson(),
    authClaimIncMtp: [],
    authClaimNonRevMtp: [],
    claimsTreeRoot: authClaimLeafRoot,
    revTreeRoot: "0",
    rootsTreeRoot: "0",
    state: "2",
    gistRoot: "0",
    gistMtp: [],
    authClaimNonRevMtpAuxHi: "0",
    authClaimNonRevMtpAuxHv: "0",
    authClaimNonRevMtpNoAux: "1",
    gistMtpAuxHi: "0",
    gistMtpAuxHv: "0",
    gistMtpNoAux: "1",
    challengeSignature: {
      r8x: challengeSignature.R8[0].toString(),
      r8y: challengeSignature.R8[1].toString(),
      s: challengeSignature.S.toString()
    }
  };
}

function smokeAuthV2Context(holder) {
  return {
    runtime: {
      input: {},
      message: {
        id: "smoke-offer-message"
      },
      holderDid: holder,
      keyId: holder.keyId,
      profileNonce: "0"
    },
    request: {
      id: "smoke-auth-v2",
      circuitId: CircuitId.AuthV2,
      challenge: "smoke-challenge",
      query: {
        type: "AuthV2"
      },
      scope: []
    }
  };
}

class SmokeWitnessCalculator {
  async calculateWitness(input) {
    assert(input.circuitId === CircuitId.AuthV2, "expected AuthV2 witness circuit");
    assert(input.graphPath.endsWith(".wcd"), "expected witness calculator to receive graphPath");
    assert(input.inputs.genesisID, "expected witness inputs to include genesis ID");
    assert(input.inputs.challengeSignatureR8x, "expected witness inputs to include split signature");
    return {
      witnessPath: "file:///tmp/authV2.wtns",
      publicSignals: ["smoke-public-signal"]
    };
  }
}

class SmokeCircomWitnesscalcModule {
  async calculateWitness(inputs, graph) {
    assert(graph === Buffer.from("graph-data").toString("base64"), "expected witnesscalc to receive graph base64");
    assert(!graph.includes(".wcd"), "witnesscalc must not receive graph path as graph data");
    const parsed = JSON.parse(inputs);
    assert(parsed.genesisID || parsed.userGenesisID, "expected witnesscalc inputs to include user identity id");
    if (parsed.genesisID) {
      assert(!("requestId" in parsed), "AuthV2 witnesscalc inputs must not include requestId");
      assert(parsed.authClaimNonRevMtpNoAux === "1", "expected auth NoAux to be numeric string");
      assert(parsed.gistMtpNoAux === "1", "expected GIST NoAux to be numeric string");
    } else {
      assert(parsed.requestID === "1782204596", "expected SigV2 on-chain requestID");
      assert(parsed.challenge === "1337", "expected SigV2 on-chain challenge");
    }
    return Buffer.from("smoke-witness").toString("base64");
  }
}

class SmokeGraphReader {
  async readGraphBase64(graphPath) {
    assert(
      graphPath === "file:///circuits/AuthV2/authV2.wcd" ||
        graphPath === "file:///circuits/credentialAtomicQuerySigV2OnChain/credentialAtomicQuerySigV2OnChain.wcd",
      "expected graph reader to receive graph path"
    );
    return {
      base64: Buffer.from("graph-data").toString("base64"),
      sizeBytes: 10
    };
  }
}

class SmokeNativeProver {
  async generateProof(input) {
    assert(input.circuitId === CircuitId.AuthV2, "expected AuthV2 prover circuit");
    assert(input.zkeyPath.endsWith(".zkey"), "expected prover to receive zkeyPath");
    assert(input.witnessPath.endsWith(".wtns"), "expected prover to receive witness path");
    return {
      proof: {
        smokeNativeProof: true
      },
      publicSignals: ["smoke-prover-public-signal"]
    };
  }
}

class SmokeRapidsnarkModule {
  async groth16PublicBufferSize(zkeyPath) {
    assert(zkeyPath.endsWith(".zkey"), "expected public buffer check to receive zkey path");
    assert(!zkeyPath.startsWith("file://"), "expected rapidsnark zkey path to be native path");
    return 128;
  }

  async groth16Prove(zkeyPath, witness) {
    assert(zkeyPath.endsWith(".zkey"), "expected rapidsnark prove to receive zkey path");
    assert(!zkeyPath.startsWith("file://"), "expected rapidsnark prove zkey path to be native path");
    assert(witness === Buffer.from("smoke-witness").toString("base64"), "expected rapidsnark prove to receive witness base64");
    return {
      proof: JSON.stringify({ proof: "smoke-proof" }),
      pub_signals: JSON.stringify(["smoke-public"])
    };
  }
}

class SmokeProverFileInspector {
  async inspectFile(path) {
    assert(path === "file:///circuits/AuthV2/AuthV2.zkey", "expected zkey inspector to receive original file URI");
    return {
      exists: true,
      sizeBytes: 12
    };
  }
}

class SmokeIssuerFetch {
  constructor(holderDid, mode = "valid") {
    this.holderDid = holderDid;
    this.mode = mode;
    this.createdCredential = false;
    this.requestedOffer = false;
    this.claimedCredential = false;
  }

  async fetch(url, init = {}) {
    if (url === "https://issuer.example/v2/identities/did%3Aiden3%3Apolygon%3Aamoy%3Aissuer/credentials") {
      this.createdCredential = true;
      if (this.mode === "create-401") {
        return responseJson({ message: "cannot proceed with the given request" }, 401);
      }
      assert(init.method === "POST", "expected issuer credential creation to use POST");
      assert(init.headers.Authorization === `Basic ${Buffer.from("user:pass").toString("base64")}`, "expected issuer admin Basic Auth header");
      const body = JSON.parse(init.body);
      assert(body.credentialSchema === "https://schema.example/person.json", "expected issuer credential schema in body");
      assert(body.type === "PersonCredential", "expected issuer credential type in body");
      assert(body.credentialSubject.id === this.holderDid, "expected holder DID as credentialSubject.id");
      return responseJson({ id: "issuer-credential-id" });
    }

    if (url === "https://issuer.example/v2/identities/did%3Aiden3%3Apolygon%3Aamoy%3Aissuer/credentials/issuer-credential-id/offer?type=raw") {
      this.requestedOffer = true;
      assert(init.method === "GET", "expected issuer offer request to use GET");
      assert(init.headers.Authorization === `Basic ${Buffer.from("user:pass").toString("base64")}`, "expected issuer offer Basic Auth header");
      return responseJson({
        universalLink: JSON.stringify({
          id: "d6d0e296-c34d-4081-937f-9fa0c8ab4082",
          thid: "d6d0e296-c34d-4081-937f-9fa0c8ab4082",
          typ: "application/iden3comm-plain-json",
          type: "https://iden3-communication.io/credentials/1.0/offer",
          from: "did:iden3:polygon:amoy:issuer",
          body: {
            ...(this.mode === "offer-missing-url" ? {} : { url: "https://issuer.example/v2/agent" }),
            credentials: [
              {
                id: "issuer-credential-id"
              }
            ]
          }
        })
      });
    }

    if (url === "https://issuer.example/v2/agent") {
      this.claimedCredential = true;
      if (this.mode === "claim-400") {
        return responseJson({ message: "cannot proceed with the given request" }, 400);
      }
      assert(init.method === "POST", "expected issuer agent claim to use POST");
      assert(init.headers["Content-Type"] === "text/plain", "expected iden3comm ZKP content type");
      assert(typeof init.body === "string" && init.body.split(".").length === 3, "expected compact JWZ token body");
      const decodedToken = decodeCompactJwz(init.body);
      assert(decodedToken.header.typ === "application/iden3-zkp-json", "expected JWZ header typ to match web flow");
      assert(decodedToken.header.alg === "groth16", "expected JWZ header alg to match web flow");
      assert(decodedToken.header.circuitId === "authV2", "expected JWZ circuit id to match web flow");
      assert(isUuid(decodedToken.payload.id), "expected JWZ fetch-request id to be UUID");
      assert(!decodedToken.payload.id.startsWith("authv2-fetch-"), "expected JWZ fetch-request id not to use timestamp prefix");
      assert(decodedToken.payload.thid === "d6d0e296-c34d-4081-937f-9fa0c8ab4082", "expected JWZ fetch-request thid to come from offer");
      assert(decodedToken.payload.type === "https://iden3-communication.io/credentials/1.0/fetch-request", "expected JWZ payload to be credential fetch request");
      assert(decodedToken.payload.from === this.holderDid, "expected JWZ payload from holder DID");
      assert(decodedToken.payload.body.id === "issuer-credential-id", "expected JWZ payload credential id");
      assert(!("challenge" in decodedToken.payload.body), "JWZ fetch-request payload must not embed proof challenge");
      const credential = {
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://context.example/person.json"],
        id: "urn:uuid:issuer-smoke-credential",
        type: ["VerifiableCredential", "PersonCredential"],
        issuer: "did:iden3:polygon:amoy:issuer",
        issuanceDate: "2026-01-01T00:00:00.000Z",
        credentialSubject: {
          id: this.holderDid,
          fullName: "Smoke Holder",
          nationalIdNumber: "12345678",
          birthDate: 946684800
        },
        credentialStatus: {
          id: "https://issuer.example/status?id=secret",
          type: "Iden3commRevocationStatusV1.0",
          revocationNonce: 1
        },
        proof: {
          type: "BJJSignature2021"
        }
      };
      return responseJson({
        id: "issuer-response",
        typ: "application/iden3comm-plain-json",
        type: "https://iden3-communication.io/credentials/1.0/issuance-response",
        body: {
          credential: this.mode === "invalid-credential" ? { id: "invalid" } : credential
        }
      });
    }

    throw new Error(`unexpected issuer URL ${url}`);
  }
}

function issuerOfferMessage() {
  return {
    id: "d6d0e296-c34d-4081-937f-9fa0c8ab4082",
    thid: "d6d0e296-c34d-4081-937f-9fa0c8ab4082",
    typ: "application/iden3comm-plain-json",
    type: "https://iden3-communication.io/credentials/1.0/offer",
    from: "did:iden3:polygon:amoy:issuer",
    body: {
      url: "https://issuer.example/v2/agent",
      credentials: [
        {
          id: "issuer-credential-id"
        }
      ]
    }
  };
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function responseJson(value, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        return name.toLowerCase() === "content-type" ? "application/json" : undefined;
      }
    },
    async text() {
      return JSON.stringify(value);
    }
  };
}

function decodeCompactJwz(token) {
  const [header, payload, proof] = token.split(".");
  assert(header && payload && proof, "expected compact JWZ with three parts");
  return {
    header: JSON.parse(Buffer.from(toBase64(header), "base64").toString("utf8")),
    payload: JSON.parse(Buffer.from(toBase64(payload), "base64").toString("utf8")),
    proof: JSON.parse(Buffer.from(toBase64(proof), "base64").toString("utf8"))
  };
}

function toBase64(value) {
  return value.replace(/-/g, "+").replace(/_/g, "/").padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
}

async function runCircuitDownloadSmoke({ includeOnChain }) {
  const fileSystem = new MockCircuitFileSystem();
  const files = [
    "authV2.dat",
    "authV2.wcd",
    "authV2.zkey",
    "credentialAtomicQuerySigV2.dat",
    "credentialAtomicQuerySigV2.wcd",
    "credentialAtomicQuerySigV2.zkey"
  ];
  if (includeOnChain) {
    files.push(
      "credentialAtomicQuerySigV2OnChain.dat",
      "credentialAtomicQuerySigV2OnChain.wcd",
      "credentialAtomicQuerySigV2OnChain.zkey"
    );
  }
  const downloader = new CircuitArtifactDownloader({
    zipUrl: "https://circuits.example/keys.zip",
    requiredCircuits: [
      CircuitId.AuthV2,
      CircuitId.CredentialAtomicQuerySigV2,
      CircuitId.CredentialAtomicQuerySigV2OnChain
    ],
    fileSystem,
    zipExtractor: new MockZipExtractor(fileSystem, files),
    version: "smoke"
  });
  return downloader.prepare();
}

class MockCircuitFileSystem {
  constructor() {
    this.cacheDirectory = "file:///cache/";
    this.files = new Set();
    this.directories = new Set();
  }

  async exists(path) {
    return this.files.has(path) || this.directories.has(path);
  }

  async makeDirectory(path) {
    this.directories.add(path);
  }

  async downloadFile(_url, destinationPath) {
    this.files.add(destinationPath);
    this.downloads = (this.downloads ?? 0) + 1;
    return { path: destinationPath };
  }

  async deleteFile(path) {
    this.files.delete(path);
  }
}

class MockZipExtractor {
  constructor(fileSystem, files) {
    this.fileSystem = fileSystem;
    this.files = files;
  }

  async extract(_zipPath, destinationDir) {
    for (const file of this.files) {
      this.fileSystem.files.add(joinUri(destinationDir, file));
    }
  }
}

async function runCircuitAlreadyCachedSmoke() {
  const fileSystem = new MockCircuitFileSystem();
  const extractDir = "file:///cache/privado-id-circuits/extracted";
  await new MockZipExtractor(fileSystem, [
    "authV2.dat",
    "authV2.wcd",
    "authV2.zkey",
    "credentialAtomicQuerySigV2.dat",
    "credentialAtomicQuerySigV2.wcd",
    "credentialAtomicQuerySigV2.zkey",
    "credentialAtomicQuerySigV2OnChain.dat",
    "credentialAtomicQuerySigV2OnChain.wcd",
    "credentialAtomicQuerySigV2OnChain.zkey"
  ]).extract("file:///cache/privado-id-circuits/keys.zip", extractDir);
  const downloader = new CircuitArtifactDownloader({
    zipUrl: "https://circuits.example/keys.zip",
    requiredCircuits: [
      CircuitId.AuthV2,
      CircuitId.CredentialAtomicQuerySigV2,
      CircuitId.CredentialAtomicQuerySigV2OnChain
    ],
    fileSystem,
    zipExtractor: new ThrowingZipExtractor("should not extract cached files"),
    version: "smoke"
  });
  const result = await downloader.prepare();
  return {
    ...result,
    downloads: fileSystem.downloads ?? 0
  };
}

async function runCorruptZipSmoke() {
  const fileSystem = new MockCircuitFileSystem();
  const downloader = new CircuitArtifactDownloader({
    zipUrl: "https://circuits.example/keys.zip",
    requiredCircuits: [CircuitId.AuthV2],
    fileSystem,
    zipExtractor: new ThrowingZipExtractor("Failed to extract file Zip headers not found. Probably not a zip file"),
    version: "smoke"
  });
  try {
    await downloader.prepare();
  } finally {
    assert(
      !(await fileSystem.exists("file:///cache/privado-id-circuits/keys.zip")),
      "expected corrupt zip to be removed from cache"
    );
  }
}

class ThrowingZipExtractor {
  constructor(message) {
    this.message = message;
  }

  async extract() {
    throw new Error(this.message);
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

async function expectRejectsIncludes(action, expectedMessagePart) {
  try {
    await action();
  } catch (error) {
    assert(error instanceof Error, "expected controlled error");
    assert(
      error.message.includes(expectedMessagePart),
      `expected error message to include: ${expectedMessagePart}; actual: ${error.message}`
    );
    return;
  }
  throw new Error("expected action to reject");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
