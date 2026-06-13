import { CircuitId } from "../circuits/CircuitId";
import { coerceAuthV2NativeWitnessInputs } from "../auth/AuthV2InputPreflight";
import { bjjSignatureFromCompressed } from "../kms/MobileBjjKmsAdapter";
import { FetchHttpClient, type HttpClient } from "../network/HttpClient";
import { addressToUint256LE } from "../onchain/challengeEncoding";
import type { AuthV2InputBuilder } from "../auth/AuthV2InputBuilder";
import type {
  ClaimCredentialRuntimeContext,
  CredentialAtomicQuerySigV2InputBuilder,
  CredentialAtomicQuerySigV2ValueProofProvider,
  CredentialProofPlan,
  HolderDidSummary,
  PrivadoExpoConfig
} from "../types";

declare function require(moduleName: string): unknown;

interface Iden3CoreRuntime {
  DID: {
    parse(value: string): unknown;
    idFromDID(did: unknown): { bigInt(): bigint };
  };
  Claim: new () => {
    fromHex(value: string): {
      marshalJson(): string[];
      rawSlotsAsInts(): bigint[];
      getSchemaHash(): { bigInt(): bigint };
      getMerklizedRoot(): bigint;
      hiHv(): { hi: bigint; hv: bigint };
    };
  };
}

interface Iden3CryptoRuntime {
  PublicKey: new (point: [bigint, bigint]) => {
    verifyPoseidon(message: bigint, signature: unknown): boolean;
  };
  Signature: new (r8: [bigint, bigint], s: bigint) => unknown;
  poseidon: {
    hash(values: bigint[]): bigint;
  };
}

interface MerkletreeRuntime {
  ZERO_HASH: HashLike;
  Hash: {
    fromHex(value: string): HashLike;
    fromBigInt(value: bigint): HashLike;
  };
  Proof: new (input?: { existence?: boolean; siblings?: HashLike[]; nodeAux?: NodeAuxLike }) => ProofLike;
  verifyProof(rootKey: HashLike, proof: ProofLike, k: bigint, v: bigint): Promise<boolean>;
  rootFromProof(proof: ProofLike, k: bigint, v: bigint): Promise<HashLike>;
}

interface HashLike {
  bigInt(): bigint;
}

interface NodeAuxLike {
  key: HashLike;
  value: HashLike;
}

interface ProofLike {
  existence?: boolean;
  nodeAux?: NodeAuxLike;
  allSiblings(): HashLike[];
}

const Iden3Core = require("@iden3/js-iden3-core") as Iden3CoreRuntime;
const Iden3Crypto = require("@iden3/js-crypto") as Iden3CryptoRuntime;
const Merkletree = require("@iden3/js-merkletree") as MerkletreeRuntime;

export class MobileCredentialAtomicQuerySigV2InputBuilder implements CredentialAtomicQuerySigV2InputBuilder {
  private readonly httpClient: HttpClient;
  private readonly valueProofProvider?: CredentialAtomicQuerySigV2ValueProofProvider;
  private readonly authV2InputBuilder?: AuthV2InputBuilder;

  constructor(options: {
    httpClient?: HttpClient;
    valueProofProvider?: CredentialAtomicQuerySigV2ValueProofProvider;
    authV2InputBuilder?: AuthV2InputBuilder;
  } = {}) {
    this.httpClient = options.httpClient ?? new FetchHttpClient();
    this.valueProofProvider = options.valueProofProvider;
    this.authV2InputBuilder = options.authV2InputBuilder;
  }

  async buildInputs(input: {
    plan: CredentialProofPlan;
    credential: unknown;
    holderDid: HolderDidSummary;
    config: PrivadoExpoConfig;
  }): Promise<Record<string, unknown>> {
    if (
      (input.plan.mode === "offchain" && input.plan.circuitId !== CircuitId.CredentialAtomicQuerySigV2) ||
      (input.plan.mode === "onchain" && input.plan.circuitId !== CircuitId.CredentialAtomicQuerySigV2OnChain)
    ) {
      throw new Error("credentialAtomicQuerySigV2 builder received an invalid circuit for the selected mode.");
    }
    if (!input.credential) {
      throw new Error("credentialAtomicQuerySigV2 requires a stored credential.");
    }
    if (!input.holderDid.did || input.holderDid.developmentOnly) {
      throw new Error("A real Holder DID is required to generate credential proofs.");
    }

    const sigInputs = await this.buildSlotBasedInputs(input);
    if (input.plan.mode === "offchain") {
      return sigInputs;
    }
    return this.buildOnchainInputs(input, sigInputs);
  }

  private async buildSlotBasedInputs(input: {
    plan: CredentialProofPlan;
    credential: unknown;
    holderDid: HolderDidSummary;
    config: PrivadoExpoConfig;
  }): Promise<Record<string, unknown>> {
    const credential = asCredentialRecord(input.credential);
    const signatureProof = getBjjSignatureProof(credential);
    const issuerClaim = claimFromHex(readRequiredString(signatureProof, "coreClaim"));
    const fieldValue = readCredentialSubjectFieldAsBigInt(credential, input.plan.query.field);
    const operator = toCircuitOperator(input.plan.query.operator);
    const merklizedValueProof = await resolveCredentialQueryProof({
      credential,
      issuerClaim,
      field: input.plan.query.field,
      fieldValue,
      operator: input.plan.query.operator,
      queryValue: input.plan.query.value,
      valueProofProvider: this.valueProofProvider
    });
    const issuerData = asRecord(signatureProof.issuerData, "BJJSignature2021 issuerData is missing.");
    const issuerAuthClaim = claimFromHex(readRequiredString(issuerData, "authCoreClaim"));
    const issuerAuthIncProof = proofFromJson(issuerData.mtp);
    const issuerDid = readIssuerDid(credential);
    const issuerId = Iden3Core.DID.idFromDID(Iden3Core.DID.parse(issuerDid)).bigInt().toString();
    const userGenesisId = Iden3Core.DID.idFromDID(Iden3Core.DID.parse(input.holderDid.did)).bigInt().toString();
    const credentialStatus = asRecord(
      credential.credentialStatus,
      "credentialAtomicQuerySigV2 requires credentialStatus for claim non-revocation."
    );
    const issuerClaimNonRev = await this.resolveNonRevocationStatus(
      credentialStatus,
      { issuerDid, userDid: input.holderDid.did }
    );
    const issuerAuthCredentialStatus = asRecord(issuerData.credentialStatus, "credentialAtomicQuerySigV2 requires issuer auth credentialStatus.");
    const issuerAuthNonRev = await this.resolveNonRevocationStatus(
      issuerAuthCredentialStatus,
      { issuerDid, userDid: input.holderDid.did }
    );
    const issuerState = toTreeState(optionalRecord(issuerData.state), "issuerData.state", issuerAuthNonRev.treeState);
    const signature = bjjSignatureFromCompressed(hexToBytes(readRequiredString(signatureProof, "signature")).slice(0, 64));
    verifyIssuerClaimSignatureBeforeWitness({
      issuerClaim,
      issuerAuthClaim,
      signature
    });

    const sigInputs = assertCredentialAtomicQuerySigV2InputsReady({
      __proofRoute: merklizedValueProof.route,
      requestID: toDecimalString(input.plan.request.id, "requestID"),
      userGenesisID: userGenesisId,
      profileNonce: "0",
      claimSubjectProfileNonce: "0",
      issuerID: issuerId,
      issuerClaim: issuerClaim.marshalJson(),
      issuerClaimNonRevClaimsTreeRoot: issuerClaimNonRev.treeState.claimsRoot.bigInt().toString(),
      issuerClaimNonRevRevTreeRoot: issuerClaimNonRev.treeState.revocationRoot.bigInt().toString(),
      issuerClaimNonRevRootsTreeRoot: issuerClaimNonRev.treeState.rootOfRoots.bigInt().toString(),
      issuerClaimNonRevState: issuerClaimNonRev.treeState.state.bigInt().toString(),
      issuerClaimNonRevMtp: prepareSiblingsStr(issuerClaimNonRev.proof, 40),
      issuerClaimNonRevMtpAuxHi: getNodeAuxValue(issuerClaimNonRev.proof).key.bigInt().toString(),
      issuerClaimNonRevMtpAuxHv: getNodeAuxValue(issuerClaimNonRev.proof).value.bigInt().toString(),
      issuerClaimNonRevMtpNoAux: getNodeAuxValue(issuerClaimNonRev.proof).noAux,
      issuerClaimSignatureR8x: signature.R8[0],
      issuerClaimSignatureR8y: signature.R8[1],
      issuerClaimSignatureS: signature.S,
      issuerAuthClaim: issuerAuthClaim.marshalJson(),
      issuerAuthClaimMtp: prepareSiblingsStr(issuerAuthIncProof, 40),
      issuerAuthClaimNonRevMtp: prepareSiblingsStr(issuerAuthNonRev.proof, 40),
      issuerAuthClaimNonRevMtpAuxHi: getNodeAuxValue(issuerAuthNonRev.proof).key.bigInt().toString(),
      issuerAuthClaimNonRevMtpAuxHv: getNodeAuxValue(issuerAuthNonRev.proof).value.bigInt().toString(),
      issuerAuthClaimNonRevMtpNoAux: getNodeAuxValue(issuerAuthNonRev.proof).noAux,
      issuerAuthClaimsTreeRoot: issuerState.claimsRoot.bigInt().toString(),
      issuerAuthRevTreeRoot: issuerState.revocationRoot.bigInt().toString(),
      issuerAuthRootsTreeRoot: issuerState.rootOfRoots.bigInt().toString(),
      claimSchema: issuerClaim.getSchemaHash().bigInt().toString(),
      claimPathMtp: prepareSiblingsStr(merklizedValueProof.proof, 32),
      claimPathNotExists: existenceToInt(merklizedValueProof.proof.existence),
      claimPathMtpAuxHi: getNodeAuxValue(merklizedValueProof.proof).key.bigInt().toString(),
      claimPathMtpAuxHv: getNodeAuxValue(merklizedValueProof.proof).value.bigInt().toString(),
      claimPathMtpNoAux: getNodeAuxValue(merklizedValueProof.proof).noAux,
      claimPathKey: merklizedValueProof.pathKey,
      claimPathValue: merklizedValueProof.pathValue,
      operator,
      slotIndex: merklizedValueProof.slotIndex,
      timestamp: Math.floor(Date.now() / 1000),
      value: prepareCircuitArrayValues(merklizedValueProof.queryValues, 64),
      isRevocationChecked: 1
    });
    await validateSigV2MerkleRelationsBeforeWitness({
      inputs: sigInputs,
      issuerClaim,
      issuerAuthClaim,
      issuerAuthIncProof,
      issuerClaimNonRevProof: issuerClaimNonRev.proof,
      issuerAuthNonRevProof: issuerAuthNonRev.proof,
      credentialStatus,
      issuerAuthCredentialStatus,
      valueProof: merklizedValueProof
    });
    return sigInputs;
  }

  private async resolveNonRevocationStatus(
    credentialStatus: Record<string, unknown>,
    context: { issuerDid: string; userDid: string }
  ): Promise<{
    proof: ProofLike;
    treeState: TreeStateLike;
  }> {
    const statusType = readRequiredString(credentialStatus, "type");
    if (statusType === "SparseMerkleTreeProof") {
      return this.resolveSparseMerkleTreeProofStatus(credentialStatus);
    }
    if (statusType === "Iden3commRevocationStatusV1.0") {
      return this.resolveIden3commRevocationStatus(credentialStatus, context);
    }
    throw new Error(
      `credentialAtomicQuerySigV2 revocation resolver only supports SparseMerkleTreeProof and Iden3commRevocationStatusV1.0; received ${statusType}.`
    );
  }

  private async resolveSparseMerkleTreeProofStatus(credentialStatus: Record<string, unknown>): Promise<{
    proof: ProofLike;
    treeState: TreeStateLike;
  }> {
    const statusUrl = readRequiredString(credentialStatus, "id");
    const response = await this.httpClient.request<unknown>({ url: statusUrl, method: "GET" });
    return normalizeRevocationStatusResponse(response);
  }

  private async resolveIden3commRevocationStatus(
    credentialStatus: Record<string, unknown>,
    context: { issuerDid: string; userDid: string }
  ): Promise<{
    proof: ProofLike;
    treeState: TreeStateLike;
  }> {
    const statusUrl = readRequiredString(credentialStatus, "id");
    const revocationNonce = readRevocationNonce(credentialStatus);
    const response = await this.httpClient.request<unknown>({
      url: statusUrl,
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: buildIden3commRevocationStatusRequest({
        from: context.userDid,
        to: context.issuerDid,
        revocationNonce
      })
    });
    const responseRecord = asRecord(response, "credentialAtomicQuerySigV2 iden3comm revocation response is unsupported.");
    return normalizeRevocationStatusResponse(responseRecord.body ?? responseRecord);
  }

  private async buildOnchainInputs(input: {
    plan: CredentialProofPlan;
    credential: unknown;
    holderDid: HolderDidSummary;
    config: PrivadoExpoConfig;
  }, sigInputs: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (!this.authV2InputBuilder) {
      throw new Error("credentialAtomicQuerySigV2OnChain requires an AuthV2 input builder.");
    }
    const challenge = input.plan.request.challenge;
    if (!challenge) {
      throw new Error("credentialAtomicQuerySigV2OnChain requires challenge.");
    }
    if (!input.plan.onchain?.requestId) {
      throw new Error("credentialAtomicQuerySigV2OnChain requires requestId.");
    }
    if (!input.plan.onchain?.challengeAddress) {
      throw new Error("credentialAtomicQuerySigV2OnChain requires challengeAddress.");
    }
    const challengeAddress = input.plan.onchain.challengeAddress;
    const authWitnessInputs = await this.authV2InputBuilder.build({
      request: input.plan.request,
      runtime: {
        input: {},
        message: {
          id: String(input.plan.request.id),
          type: "https://iden3-communication.io/proofs/1.0/credential-proof",
          body: {
            challenge
          }
        },
        holderDid: input.holderDid,
        keyId: input.holderDid.keyId,
        profileNonce: "0"
      } satisfies ClaimCredentialRuntimeContext
    });
    const authInputs = coerceAuthV2NativeWitnessInputs(authWitnessInputs);
    const onchainInputs = assertCredentialAtomicQuerySigV2InputsReady({
      ...sigInputs,
      authClaim: authInputs.authClaim,
      authClaimIncMtp: authInputs.authClaimIncMtp,
      authClaimNonRevMtp: authInputs.authClaimNonRevMtp,
      authClaimNonRevMtpAuxHi: authInputs.authClaimNonRevMtpAuxHi,
      authClaimNonRevMtpAuxHv: authInputs.authClaimNonRevMtpAuxHv,
      authClaimNonRevMtpNoAux: authInputs.authClaimNonRevMtpNoAux,
      challenge: authInputs.challenge,
      challengeSignatureR8x: authInputs.challengeSignatureR8x,
      challengeSignatureR8y: authInputs.challengeSignatureR8y,
      challengeSignatureS: authInputs.challengeSignatureS,
      userClaimsTreeRoot: authInputs.claimsTreeRoot,
      userRevTreeRoot: authInputs.revTreeRoot,
      userRootsTreeRoot: authInputs.rootsTreeRoot,
      userState: authInputs.state,
      gistRoot: authInputs.gistRoot,
      gistMtp: authInputs.gistMtp,
      gistMtpAuxHi: authInputs.gistMtpAuxHi,
      gistMtpAuxHv: authInputs.gistMtpAuxHv,
      gistMtpNoAux: authInputs.gistMtpNoAux
    });
    validateSigV2OnChainInputsBeforeWitness(onchainInputs, {
      challengeAddress,
      verifySignatures: true
    });
    await validateSigV2OnChainMerkleRelationsBeforeWitness(onchainInputs);
    return onchainInputs;
  }
}

export function validateSigV2OnChainInputsBeforeWitness(
  inputs: Record<string, unknown>,
  options: { challengeAddress?: string; verifySignatures?: boolean } = {}
): void {
  if (options.challengeAddress) {
    const expectedChallenge = addressToUint256LE(options.challengeAddress);
    if (inputs.challenge !== expectedChallenge) {
      throw new Error("credentialAtomicQuerySigV2OnChain inputs are invalid before witness: challenge does not match challengeAddress.");
    }
  }
  if (options.verifySignatures) {
    verifyChallengeSignatureBeforeWitness(inputs);
  }
}

function verifyChallengeSignatureBeforeWitness(inputs: Record<string, unknown>): void {
  const authClaim = decimalStringArray(inputs.authClaim, "authClaim", 8);
  const signature = signatureFromFields({
    r8x: inputs.challengeSignatureR8x,
    r8y: inputs.challengeSignatureR8y,
    s: inputs.challengeSignatureS
  });
  const publicKey = publicKeyFromClaimSlots(authClaim, "authClaim");
  const challenge = BigInt(toDecimalString(inputs.challenge, "challenge"));
  if (!publicKey.verifyPoseidon(challenge, signature)) {
    throw new Error("credentialAtomicQuerySigV2OnChain inputs are invalid before witness: challenge signature is not valid.");
  }
}

function verifyIssuerClaimSignatureBeforeWitness(input: {
  issuerClaim: ReturnType<InstanceType<Iden3CoreRuntime["Claim"]>["fromHex"]>;
  issuerAuthClaim: ReturnType<InstanceType<Iden3CoreRuntime["Claim"]>["fromHex"]>;
  signature: { R8: [string, string]; S: string };
}): void {
  const issuerAuthSlots = input.issuerAuthClaim.marshalJson();
  const publicKey = publicKeyFromClaimSlots(issuerAuthSlots, "issuerAuthClaim");
  const signature = signatureFromFields({
    r8x: input.signature.R8[0],
    r8y: input.signature.R8[1],
    s: input.signature.S
  });
  const { hi, hv } = input.issuerClaim.hiHv();
  const claimHash = Iden3Crypto.poseidon.hash([hi, hv]);
  if (!publicKey.verifyPoseidon(claimHash, signature)) {
    throw new Error("credentialAtomicQuerySigV2 inputs are invalid before witness: issuer claim signature is not valid.");
  }
}

async function validateSigV2MerkleRelationsBeforeWitness(input: {
  inputs: Record<string, unknown>;
  issuerClaim: ReturnType<InstanceType<Iden3CoreRuntime["Claim"]>["fromHex"]>;
  issuerAuthClaim: ReturnType<InstanceType<Iden3CoreRuntime["Claim"]>["fromHex"]>;
  issuerAuthIncProof: ProofLike;
  issuerClaimNonRevProof: ProofLike;
  issuerAuthNonRevProof: ProofLike;
  credentialStatus: Record<string, unknown>;
  issuerAuthCredentialStatus: Record<string, unknown>;
  valueProof: {
    route: "slot-based" | "merklized";
    proof: ProofLike;
    pathKey: string;
    pathValue: string;
  };
}): Promise<void> {
  const issuerAuthHiHv = input.issuerAuthClaim.hiHv();
  await assertMerkleProof(
    "issuerAuthClaimMtp",
    input.inputs.issuerAuthClaimsTreeRoot,
    input.issuerAuthIncProof,
    issuerAuthHiHv.hi,
    issuerAuthHiHv.hv
  );
  await assertMerkleProof(
    "issuerClaimNonRevMtp",
    input.inputs.issuerClaimNonRevRevTreeRoot,
    input.issuerClaimNonRevProof,
    BigInt(readRevocationNonce(input.credentialStatus)),
    0n
  );
  await assertMerkleProof(
    "issuerAuthClaimNonRevMtp",
    input.inputs.issuerAuthRevTreeRoot,
    input.issuerAuthNonRevProof,
    BigInt(readRevocationNonce(input.issuerAuthCredentialStatus)),
    0n
  );
  if (input.valueProof.route === "merklized") {
    await assertMerkleProof(
      "claimPathMtp",
      input.issuerClaim.getMerklizedRoot(),
      input.valueProof.proof,
      BigInt(input.valueProof.pathKey),
      BigInt(input.valueProof.pathValue)
    );
  }
}

async function validateSigV2OnChainMerkleRelationsBeforeWitness(inputs: Record<string, unknown>): Promise<void> {
  const authClaim = decimalStringArray(inputs.authClaim, "authClaim", 8);
  const authClaimHiHv = claimHiHvFromMarshal(authClaim);
  await assertMerkleProof(
    "authClaimIncMtp",
    inputs.userClaimsTreeRoot,
    proofFromCircuitFields({
      siblings: inputs.authClaimIncMtp,
      existence: true
    }),
    authClaimHiHv.hi,
    authClaimHiHv.hv
  );
  await assertMerkleProof(
    "authClaimNonRevMtp",
    inputs.userRevTreeRoot,
    proofFromCircuitFields({
      siblings: inputs.authClaimNonRevMtp,
      existence: false,
      auxHi: inputs.authClaimNonRevMtpAuxHi,
      auxHv: inputs.authClaimNonRevMtpAuxHv,
      noAux: inputs.authClaimNonRevMtpNoAux
    }),
    revocationNonceFromClaimMarshal(authClaim),
    0n
  );
  await assertMerkleProof(
    "gistMtp",
    inputs.gistRoot,
    proofFromCircuitFields({
      siblings: inputs.gistMtp,
      existence: false,
      auxHi: inputs.gistMtpAuxHi,
      auxHv: inputs.gistMtpAuxHv,
      noAux: inputs.gistMtpNoAux
    }),
    BigInt(toDecimalString(inputs.userGenesisID, "userGenesisID")),
    BigInt(toDecimalString(inputs.userState, "userState")),
    {
      source: typeof inputs.gistMtp === "object" && inputs.gistMtp && !Array.isArray(inputs.gistMtp)
        ? String((inputs.gistMtp as { source?: unknown }).source ?? "unknown")
        : "circuit-inputs",
      auxHi: inputs.gistMtpAuxHi,
      auxHv: inputs.gistMtpAuxHv,
      noAux: inputs.gistMtpNoAux
    }
  );
}

async function assertMerkleProof(
  field: string,
  root: unknown,
  proof: ProofLike,
  key: bigint,
  value: bigint,
  debug?: { source?: string; auxHi?: unknown; auxHv?: unknown; noAux?: unknown }
): Promise<void> {
  const rootHash = hashFromValue(root);
  const ok = await Merkletree.verifyProof(rootHash, proof, key, value);
  if (!ok) {
    let computedRoot: string | undefined;
    try {
      computedRoot = (await Merkletree.rootFromProof(proof, key, value)).bigInt().toString();
    } catch {
      computedRoot = undefined;
    }
    const details = {
      field,
      gistRoot: rootHash.bigInt().toString(),
      computedRoot,
      keyUsed: key.toString(),
      valueUsed: value.toString(),
      siblingsCount: proof.allSiblings().length,
      auxHi: debug?.auxHi === undefined ? proof.nodeAux?.key.bigInt().toString() : String(debug.auxHi),
      auxHv: debug?.auxHv === undefined ? proof.nodeAux?.value.bigInt().toString() : String(debug.auxHv),
      noAux: debug?.noAux === undefined ? (proof.nodeAux ? "0" : "1") : String(debug.noAux),
      source: debug?.source
    };
    throw new Error(
      `credentialAtomicQuerySigV2 inputs are invalid before witness: ${field} does not match its root. ${JSON.stringify(details)}`
    );
  }
}

function proofFromCircuitFields(input: {
  siblings: unknown;
  existence: boolean;
  auxHi?: unknown;
  auxHv?: unknown;
  noAux?: unknown;
}): ProofLike {
  const siblings = arrayOfHashes(input.siblings, "mtp siblings");
  const noAux = input.noAux === undefined ? "1" : toDecimalString(input.noAux, "mtp noAux");
  const auxHi = input.auxHi === undefined ? "0" : toDecimalString(input.auxHi, "mtp auxHi");
  const auxHv = input.auxHv === undefined ? "0" : toDecimalString(input.auxHv, "mtp auxHv");
  const hasAux = noAux === "0" && (auxHi !== "0" || auxHv !== "0");
  return new Merkletree.Proof({
    existence: input.existence,
    siblings,
    nodeAux: hasAux
      ? {
          key: hashFromValue(auxHi),
          value: hashFromValue(auxHv)
        }
      : undefined
  });
}

function arrayOfHashes(value: unknown, field: string): HashLike[] {
  if (!Array.isArray(value)) {
    throw new Error(`credentialAtomicQuerySigV2 ${field} must be an array.`);
  }
  return value.map(hashFromValue);
}

function claimHiHvFromMarshal(slots: string[]): { hi: bigint; hv: bigint } {
  return {
    hi: Iden3Crypto.poseidon.hash(slots.slice(0, 4).map((entry) => BigInt(entry))),
    hv: Iden3Crypto.poseidon.hash(slots.slice(4, 8).map((entry) => BigInt(entry)))
  };
}

function revocationNonceFromClaimMarshal(slots: string[]): bigint {
  return BigInt(slots[4]) & ((1n << 64n) - 1n);
}

function normalizeRevocationStatusResponse(response: unknown): {
  proof: ProofLike;
  treeState: TreeStateLike;
} {
    const revocation = asRecord(response, "credentialAtomicQuerySigV2 revocation response is unsupported.");
    const issuer = asRecord(revocation.issuer, "credentialAtomicQuerySigV2 revocation response is missing issuer.");
    return {
      proof: proofFromJson(revocation.mtp),
      treeState: {
        state: hashFromValue(readRequiredTreeStateValue(issuer, "issuer revocation status", ["state", "value"])),
        claimsRoot: hashFromValue(readRequiredTreeStateValue(issuer, "issuer revocation status", ["claimsTreeRoot", "claimsRoot"])),
        revocationRoot: hashFromValue(readRequiredTreeStateValue(issuer, "issuer revocation status", [
          "revocationTreeRoot",
          "revTreeRoot",
          "revocationRoot"
        ])),
        rootOfRoots: hashFromValue(readRequiredTreeStateValue(issuer, "issuer revocation status", [
          "rootOfRoots",
          "rootsTreeRoot",
          "rootOfRootsTreeRoot"
        ]))
      }
    };
}

export function assertCredentialAtomicQuerySigV2InputsReady(inputs: Record<string, unknown>): Record<string, unknown> {
  for (const field of credentialAtomicQuerySigV2RequiredFields) {
    const value = inputs[field];
    if (value === undefined || value === null) {
      throw new Error(`credentialAtomicQuerySigV2 inputs are not ready for native witness: ${field} is missing.`);
    }
    if (Array.isArray(value)) {
      if (!value.every(isDecimalBigIntString)) {
        throw new Error(
          `credentialAtomicQuerySigV2 inputs are not ready for native witness: ${field} must contain decimal strings.`
        );
      }
      continue;
    }
    if (typeof value === "number") {
      continue;
    }
    if (!isDecimalBigIntString(value)) {
      throw new Error(
        `credentialAtomicQuerySigV2 inputs are not ready for native witness: ${field} must be a decimal bigint string.`
      );
    }
  }
  if (inputs.requestID !== undefined && typeof inputs.requestID === "string" && !/^(0|[1-9][0-9]*)$/.test(inputs.requestID)) {
    throw new Error("credentialAtomicQuerySigV2 inputs are not ready for native witness: requestID must be a decimal bigint string.");
  }
  if (inputs.challenge !== undefined) {
    assertOnchainCredentialAtomicQuerySigV2InputsReady(inputs);
  }
  return inputs;
}

const credentialAtomicQuerySigV2RequiredFields = [
  "requestID",
  "userGenesisID",
  "profileNonce",
  "claimSubjectProfileNonce",
  "issuerID",
  "issuerClaim",
  "issuerClaimNonRevClaimsTreeRoot",
  "issuerClaimNonRevRevTreeRoot",
  "issuerClaimNonRevRootsTreeRoot",
  "issuerClaimNonRevState",
  "issuerClaimNonRevMtp",
  "issuerClaimNonRevMtpNoAux",
  "issuerClaimSignatureR8x",
  "issuerClaimSignatureR8y",
  "issuerClaimSignatureS",
  "issuerAuthClaim",
  "issuerAuthClaimMtp",
  "issuerAuthClaimNonRevMtp",
  "issuerAuthClaimNonRevMtpNoAux",
  "issuerAuthClaimsTreeRoot",
  "issuerAuthRevTreeRoot",
  "issuerAuthRootsTreeRoot",
  "claimSchema",
  "claimPathMtp",
  "claimPathMtpNoAux",
  "claimPathKey",
  "claimPathValue",
  "operator",
  "slotIndex",
  "timestamp",
  "value",
  "isRevocationChecked"
] as const;

const credentialAtomicQuerySigV2OnchainRequiredFields = [
  "authClaim",
  "authClaimIncMtp",
  "authClaimNonRevMtp",
  "authClaimNonRevMtpAuxHi",
  "authClaimNonRevMtpAuxHv",
  "authClaimNonRevMtpNoAux",
  "challenge",
  "challengeSignatureR8x",
  "challengeSignatureR8y",
  "challengeSignatureS",
  "userClaimsTreeRoot",
  "userRevTreeRoot",
  "userRootsTreeRoot",
  "userState",
  "gistRoot",
  "gistMtp",
  "gistMtpAuxHi",
  "gistMtpAuxHv",
  "gistMtpNoAux"
] as const;

function assertOnchainCredentialAtomicQuerySigV2InputsReady(inputs: Record<string, unknown>): void {
  for (const field of credentialAtomicQuerySigV2OnchainRequiredFields) {
    const value = inputs[field];
    if (value === undefined || value === null) {
      throw new Error(`credentialAtomicQuerySigV2OnChain inputs are not ready for native witness: ${field} is missing.`);
    }
    if (Array.isArray(value)) {
      if (!value.every(isDecimalBigIntString)) {
        throw new Error(
          `credentialAtomicQuerySigV2OnChain inputs are not ready for native witness: ${field} must contain decimal strings.`
        );
      }
      continue;
    }
    if (!isDecimalBigIntString(value)) {
      throw new Error(
        `credentialAtomicQuerySigV2OnChain inputs are not ready for native witness: ${field} must be a decimal bigint string.`
      );
    }
  }
}

function isDecimalBigIntString(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

interface TreeStateLike {
  state: HashLike;
  claimsRoot: HashLike;
  revocationRoot: HashLike;
  rootOfRoots: HashLike;
}

function asCredentialRecord(value: unknown): Record<string, unknown> {
  return asRecord(value, "credentialAtomicQuerySigV2 requires a stored credential object.");
}

function asRecord(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(message);
  }
  return value as Record<string, unknown>;
}

function optionalRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function getBjjSignatureProof(credential: Record<string, unknown>): Record<string, unknown> {
  const proof = credential.proof;
  const proofs = Array.isArray(proof) ? proof : proof ? [proof] : [];
  const signatureProof = proofs.find(
    (item) => item && typeof item === "object" && (item as { type?: unknown }).type === "BJJSignature2021"
  );
  if (!signatureProof) {
    throw new Error("credentialAtomicQuerySigV2 requires a BJJSignature2021 credential proof.");
  }
  return signatureProof as Record<string, unknown>;
}

function claimFromHex(value: string): ReturnType<InstanceType<Iden3CoreRuntime["Claim"]>["fromHex"]> {
  return new Iden3Core.Claim().fromHex(value);
}

function readRequiredString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`credentialAtomicQuerySigV2 requires ${key}.`);
  }
  return value;
}

function readRevocationNonce(record: Record<string, unknown>): number {
  const value = record.revocationNonce;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    const numeric = Number(value);
    if (Number.isSafeInteger(numeric)) {
      return numeric;
    }
  }
  throw new Error("credentialAtomicQuerySigV2 Iden3commRevocationStatusV1.0 requires revocationNonce.");
}

function buildIden3commRevocationStatusRequest(input: {
  from: string;
  to: string;
  revocationNonce: number;
}): Record<string, unknown> {
  return {
    id: randomUuid(),
    typ: "application/iden3comm-plain-json",
    type: "https://iden3-communication.io/revocation/1.0/request-status",
    body: {
      revocation_nonce: input.revocationNonce
    },
    thid: randomUuid(),
    from: input.from,
    to: input.to
  };
}

function readIssuerDid(credential: Record<string, unknown>): string {
  const issuer = credential.issuer;
  if (typeof issuer === "string") {
    return issuer;
  }
  if (issuer && typeof issuer === "object" && typeof (issuer as { id?: unknown }).id === "string") {
    return (issuer as { id: string }).id;
  }
  throw new Error("credentialAtomicQuerySigV2 requires issuer DID.");
}

function readCredentialSubjectFieldAsBigInt(credential: Record<string, unknown>, field: string): bigint {
  const subject = asRecord(credential.credentialSubject, "credentialAtomicQuerySigV2 requires credentialSubject.");
  const value = subject[field];
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    return BigInt(value);
  }
  throw new Error(`credentialAtomicQuerySigV2 slot-based builder only supports numeric credentialSubject.${field}.`);
}

async function resolveCredentialQueryProof(input: {
  credential: Record<string, unknown>;
  issuerClaim: ReturnType<InstanceType<Iden3CoreRuntime["Claim"]>["fromHex"]>;
  field: string;
  fieldValue: bigint;
  operator: CredentialProofPlan["query"]["operator"];
  queryValue: unknown;
  valueProofProvider?: CredentialAtomicQuerySigV2ValueProofProvider;
}): Promise<{
  route: "slot-based" | "merklized";
  proof: ProofLike;
  pathKey: string;
  pathValue: string;
  slotIndex: number;
  queryValues: string[];
}> {
  const slotIndex = findSlotIndexForField(input.issuerClaim.rawSlotsAsInts(), input.fieldValue);
  if (slotIndex !== undefined) {
    return {
      route: "slot-based",
      proof: emptyProof(),
      pathKey: "0",
      pathValue: "0",
      slotIndex,
      queryValues: toCircuitValues(input.queryValue, input.operator)
    };
  }
  return buildMerklizedValueProof(input);
}

async function buildMerklizedValueProof(input: {
  credential: Record<string, unknown>;
  field: string;
  operator: CredentialProofPlan["query"]["operator"];
  queryValue: unknown;
  valueProofProvider?: CredentialAtomicQuerySigV2ValueProofProvider;
}): Promise<{
  route: "merklized";
  proof: ProofLike;
  pathKey: string;
  pathValue: string;
  slotIndex: number;
  queryValues: string[];
}> {
  if (!input.valueProofProvider) {
    throw new Error(
      `credentialAtomicQuerySigV2 merklized ValueProof provider is required for field ${input.field}. ` +
        "Inject a mobile-safe CredentialAtomicQuerySigV2ValueProofProvider."
    );
  }
  const credentialForMerklization = structuredCloneWithoutProof(input.credential);
  let valueProof: Awaited<ReturnType<CredentialAtomicQuerySigV2ValueProofProvider["buildValueProof"]>>;
  try {
    valueProof = await input.valueProofProvider.buildValueProof({
      credential: credentialForMerklization,
      credentialType: getCredentialTypeForMerklizedPath(credentialForMerklization),
      field: input.field,
      operator: input.operator,
      queryValue: input.queryValue
    });
  } catch (error) {
    throw new Error(`credentialAtomicQuerySigV2 ValueProof is missing for field ${input.field}: ${errorMessage(error)}`);
  }
  return {
    route: "merklized",
    proof: proofLikeFromUnknown(valueProof.proof),
    pathKey: toDecimalString(valueProof.pathKey, "claimPathKey"),
    pathValue: toDecimalString(valueProof.pathValue, "claimPathValue"),
    slotIndex: 0,
    queryValues: valueProof.queryValues.map((entry) => toDecimalString(entry, "query value"))
  };
}

function getCredentialTypeForMerklizedPath(credential: Record<string, unknown>): string {
  const type = credential.type;
  if (Array.isArray(type)) {
    const selected = [...type].reverse().find((entry) => typeof entry === "string" && entry !== "VerifiableCredential");
    if (selected) {
      return selected;
    }
  }
  if (typeof type === "string") {
    return type;
  }
  throw new Error("credentialAtomicQuerySigV2 requires credential type for merklized path.");
}

function findSlotIndexForField(slots: bigint[], fieldValue: bigint): number | undefined {
  const candidateIndexes = [2, 3, 6, 7];
  const matches = candidateIndexes.filter((index) => slots[index] === fieldValue);
  if (matches.length === 1) {
    return matches[0];
  }
  if (matches.length > 1) {
    throw new Error("credentialAtomicQuerySigV2 query field matches multiple core claim slots.");
  }
  return undefined;
}

function toCircuitOperator(operator: CredentialProofPlan["query"]["operator"]): number {
  switch (operator) {
    case "eq":
      return 1;
    case "lt":
      return 2;
    case "gt":
      return 3;
    case "in":
      return 4;
    case "noop":
      return 1;
    default:
      throw new Error(`credentialAtomicQuerySigV2 operator is not supported: ${String(operator)}`);
  }
}

function toCircuitValues(value: unknown, operator: CredentialProofPlan["query"]["operator"]): string[] {
  if (operator === "noop") {
    return [];
  }
  const values = Array.isArray(value) ? value : [value];
  return values.map((entry) => toDecimalString(entry, "query value"));
}

function structuredCloneWithoutProof(credential: Record<string, unknown>): Record<string, unknown> {
  const clone = JSON.parse(JSON.stringify(credential)) as Record<string, unknown>;
  delete clone.proof;
  return clone;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function toDecimalString(value: unknown, field: string): string {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  if (typeof value === "bigint" && value >= 0n) {
    return value.toString();
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    return value;
  }
  throw new Error(`credentialAtomicQuerySigV2 ${field} must be a decimal bigint string.`);
}

function decimalStringArray(value: unknown, field: string, expectedLength: number): string[] {
  if (!Array.isArray(value) || value.length !== expectedLength) {
    throw new Error(`credentialAtomicQuerySigV2 ${field} must be a decimal bigint string array of length ${expectedLength}.`);
  }
  return value.map((entry, index) => toDecimalString(entry, `${field}[${index}]`));
}

function publicKeyFromClaimSlots(slots: string[], field: string): InstanceType<Iden3CryptoRuntime["PublicKey"]> {
  if (slots.length < 4) {
    throw new Error(`credentialAtomicQuerySigV2 ${field} does not contain BJJ public key slots.`);
  }
  return new Iden3Crypto.PublicKey([
    BigInt(toDecimalString(slots[2], `${field}[2]`)),
    BigInt(toDecimalString(slots[3], `${field}[3]`))
  ]);
}

function signatureFromFields(input: { r8x: unknown; r8y: unknown; s: unknown }): InstanceType<Iden3CryptoRuntime["Signature"]> {
  return new Iden3Crypto.Signature(
    [
      BigInt(toDecimalString(input.r8x, "signature.R8[0]")),
      BigInt(toDecimalString(input.r8y, "signature.R8[1]"))
    ],
    BigInt(toDecimalString(input.s, "signature.S"))
  );
}

function prepareCircuitArrayValues(values: string[], size: number): string[] {
  if (values.length > size) {
    throw new Error(`credentialAtomicQuerySigV2 value array size ${values.length} is bigger than ${size}.`);
  }
  return [...values, ...Array.from({ length: size - values.length }, () => "0")];
}

function toTreeState(
  state: Record<string, unknown> | undefined,
  source: string,
  fallback?: TreeStateLike
): TreeStateLike {
  return {
    state: hashFromValue(readTreeStateValue(state, source, ["value", "state"], fallback?.state)),
    claimsRoot: hashFromValue(readTreeStateValue(state, source, ["claimsTreeRoot", "claimsRoot"], fallback?.claimsRoot)),
    revocationRoot: hashFromValue(
      readTreeStateValue(state, source, ["revocationTreeRoot", "revTreeRoot", "revocationRoot"], fallback?.revocationRoot)
    ),
    rootOfRoots: hashFromValue(
      readTreeStateValue(state, source, ["rootOfRoots", "rootsTreeRoot", "rootOfRootsTreeRoot"], fallback?.rootOfRoots)
    )
  };
}

function readTreeStateValue(
  state: Record<string, unknown> | undefined,
  source: string,
  keys: string[],
  fallback?: HashLike
): unknown {
  if (state) {
    for (const key of keys) {
      const value = state[key];
      if (value !== undefined && value !== null && value !== "") {
        return value;
      }
    }
  }
  if (fallback) {
    return fallback.bigInt();
  }
  const canonicalKey = keys[0];
  if (source === "issuerData.state" && canonicalKey === "revocationTreeRoot") {
    throw new Error("Missing issuerData.state.revocationTreeRoot in BJJSignature2021 proof");
  }
  throw new Error(`Unable to resolve issuer revocation state: ${source}.${canonicalKey}`);
}

function readRequiredTreeStateValue(record: Record<string, unknown>, source: string, keys: string[]): unknown {
  return readTreeStateValue(record, source, keys);
}

function proofFromJson(value: unknown): ProofLike {
  const proofCtor = Merkletree.Proof as unknown as {
    fromJSON?: (value: unknown) => ProofLike;
    new (input?: { existence?: boolean; siblings?: HashLike[]; nodeAux?: NodeAuxLike }): ProofLike;
  };
  if (value === undefined || value === null) {
    return emptyProof();
  }
  if (typeof proofCtor.fromJSON === "function") {
    return proofCtor.fromJSON(value);
  }
  const record = asRecord(value, "credentialAtomicQuerySigV2 proof response is unsupported.");
  const siblings = Array.isArray(record.siblings) ? record.siblings.map(hashFromValue) : [];
  const nodeAuxRecord = record.nodeAux ?? record.node_aux;
  const nodeAux =
    nodeAuxRecord && typeof nodeAuxRecord === "object"
      ? {
          key: hashFromValue((nodeAuxRecord as { key?: unknown }).key ?? "0"),
          value: hashFromValue((nodeAuxRecord as { value?: unknown }).value ?? "0")
        }
      : undefined;
  return new Merkletree.Proof({
    existence: Boolean(record.existence),
    siblings,
    nodeAux
  });
}

function proofLikeFromUnknown(value: unknown): ProofLike {
  if (value && typeof value === "object" && typeof (value as { allSiblings?: unknown }).allSiblings === "function") {
    return value as ProofLike;
  }
  return proofFromJson(value);
}

function emptyProof(): ProofLike {
  return new Merkletree.Proof();
}

function prepareSiblingsStr(proof: ProofLike, levels: number): string[] {
  const siblings = [...proof.allSiblings()];
  for (let index = siblings.length; index < levels; index += 1) {
    siblings.push(Merkletree.ZERO_HASH);
  }
  return siblings.slice(0, levels).map((sibling) => sibling.bigInt().toString());
}

function getNodeAuxValue(proof: ProofLike | undefined): { key: HashLike; value: HashLike; noAux: string } {
  if (proof?.existence) {
    return { key: Merkletree.ZERO_HASH, value: Merkletree.ZERO_HASH, noAux: "0" };
  }
  if (proof?.nodeAux?.value !== undefined && proof.nodeAux.key !== undefined) {
    return { key: proof.nodeAux.key, value: proof.nodeAux.value, noAux: "0" };
  }
  return { key: Merkletree.ZERO_HASH, value: Merkletree.ZERO_HASH, noAux: "1" };
}

function existenceToInt(value: unknown): number {
  return value ? 0 : 1;
}

function hashFromValue(value: unknown): HashLike {
  if (typeof value === "bigint") {
    return Merkletree.Hash.fromBigInt(value);
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return Merkletree.Hash.fromBigInt(BigInt(value));
  }
  if (typeof value !== "string") {
    throw new Error("credentialAtomicQuerySigV2 hash value is unsupported.");
  }
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (/^[0-9a-fA-F]+$/.test(normalized) && /[a-fA-F]/.test(normalized)) {
    return Merkletree.Hash.fromHex(normalized);
  }
  if (/^(0|[1-9][0-9]*)$/.test(value)) {
    return Merkletree.Hash.fromBigInt(BigInt(value));
  }
  return Merkletree.Hash.fromHex(normalized);
}

function hexToBytes(value: string): Uint8Array {
  const normalized = value.startsWith("0x") ? value.slice(2) : value;
  if (normalized.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new Error("credentialAtomicQuerySigV2 signature must be hex.");
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function randomUuid(): string {
  const cryptoLike = globalThis as unknown as {
    crypto?: {
      randomUUID?: () => string;
      getRandomValues?: <T extends Uint8Array>(array: T) => T;
    };
  };
  const randomUUID = cryptoLike.crypto?.randomUUID?.();
  if (randomUUID) {
    return randomUUID;
  }
  const bytes = new Uint8Array(16);
  if (!cryptoLike.crypto?.getRandomValues) {
    return `00000000-0000-4000-8000-${Date.now().toString(16).padStart(12, "0").slice(-12)}`;
  }
  cryptoLike.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10, 16).join("")
  ].join("-");
}
