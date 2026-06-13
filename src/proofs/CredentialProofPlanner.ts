import { CircuitId } from "../circuits/CircuitId";
import { buildCredentialSummary, isRecord } from "../credentials/diagnostics";
import { buildOffchainSigV2Request } from "../proofRequests/buildOffchainSigV2Request";
import { buildOnchainSigV2Request } from "../proofRequests/buildOnchainSigV2Request";
import { evmAddressToChallenge, normalizeEvmAddress } from "../onchain/evmChallenge";
import type {
  CredentialProofMode,
  CredentialProofOnchainOptions,
  CredentialProofOperator,
  CredentialProofPlan,
  CredentialStorageAdapter,
  GenerateCredentialProofInput,
  PrivadoExpoConfig,
  ProofRequest
} from "../types";

export const supportedCredentialProofOperators: readonly CredentialProofOperator[] = [
  "eq",
  "lt",
  "gt",
  "in",
  "noop"
];

export async function prepareCredentialProofPlan(input: GenerateCredentialProofInput, options: {
  credentialStorage: CredentialStorageAdapter;
  config: PrivadoExpoConfig;
}): Promise<CredentialProofPlan> {
  const mode = input.mode ?? "offchain";
  const circuitId = resolveCredentialProofCircuit(mode, input.circuitId);
  const credential = await options.credentialStorage.getCredentialById(input.credentialId);
  if (!credential) {
    throw new Error("Credential proof cannot be prepared: credential was not found.");
  }

  const summary = buildCredentialSummary(credential);
  if (!summary.type.includes(input.credentialType)) {
    throw new Error("Credential proof cannot be prepared: credential type does not match.");
  }
  if (input.issuerDid && summary.issuer !== input.issuerDid) {
    throw new Error("Credential proof cannot be prepared: issuer DID does not match.");
  }
  if (input.schema) {
    const actualSchema = extractCredentialSchema(credential);
    if (!actualSchema || actualSchema !== input.schema) {
      throw new Error("Credential proof cannot be prepared: credential schema does not match.");
    }
  }

  validateCredentialProofQuery(input.query, credential);
  const issuerDid = input.issuerDid ?? summary.issuer;
  const proofQuery = buildCredentialProofQuery({
    credentialType: input.credentialType,
    issuerDid,
    schema: input.schema,
    context: normalizeCredentialContext(options.config.credential?.credentialContext),
    field: input.query.field,
    operator: input.query.operator,
    value: input.query.value
  });
  const onchain = mode === "onchain" ? normalizeOnchainOptions(input.onchain, options.config) : undefined;
  const request = buildCredentialProofRequest({
    mode,
    circuitId,
    credentialId: input.credentialId,
    credentialType: input.credentialType,
    schema: input.schema,
    query: proofQuery,
    onchain,
    config: options.config
  });

  return {
    credentialId: input.credentialId,
    credentialType: input.credentialType,
    issuerDid,
    schema: input.schema,
    mode,
    circuitId,
    query: { ...input.query },
    request,
    credentialSummary: summary,
    onchain,
    proofGenerated: false,
    nextBoundary: "credentialAtomicQuerySigV2 input builder is not implemented yet."
  };
}

function resolveCredentialProofCircuit(
  mode: CredentialProofMode,
  circuitId?: CircuitId.CredentialAtomicQuerySigV2 | CircuitId.CredentialAtomicQuerySigV2OnChain
): CircuitId.CredentialAtomicQuerySigV2 | CircuitId.CredentialAtomicQuerySigV2OnChain {
  const expected =
    mode === "onchain" ? CircuitId.CredentialAtomicQuerySigV2OnChain : CircuitId.CredentialAtomicQuerySigV2;
  if (circuitId && circuitId !== expected) {
    throw new Error(`Credential proof circuit ${circuitId} is not valid for ${mode} mode.`);
  }
  return circuitId ?? expected;
}

function validateCredentialProofQuery(query: GenerateCredentialProofInput["query"], credential: unknown): void {
  if (!query.field || typeof query.field !== "string") {
    throw new Error("Credential proof query field is required.");
  }
  if (!supportedCredentialProofOperators.includes(query.operator)) {
    throw new Error(`Credential proof operator is not supported: ${String(query.operator)}`);
  }
  if (query.operator === "in" && !Array.isArray(query.value)) {
    throw new Error("Credential proof query value must be an array for operator in.");
  }
  if (query.operator !== "noop" && query.value === undefined) {
    throw new Error("Credential proof query value is required.");
  }
  if (query.operator !== "noop" && readCredentialField(credential, query.field) === undefined) {
    throw new Error("Credential proof query field is not present in the credential.");
  }
}

function buildCredentialProofQuery(input: {
  credentialType: string;
  issuerDid?: string;
  schema?: string;
  context?: string;
  field: string;
  operator: CredentialProofOperator;
  value: unknown;
}): Record<string, unknown> {
  // Issuer emits the VC/schema. The verifier or app owns this query. Universal Verifier
  // registration for on-chain mode must use the same query shape later.
  return {
    type: input.credentialType,
    ...(input.schema ? { credentialSchema: input.schema } : {}),
    ...(input.context ? { context: input.context } : {}),
    ...(input.issuerDid ? { allowedIssuers: [input.issuerDid] } : {}),
    credentialSubject: {
      [normalizeCredentialSubjectField(input.field)]: {
        operator: input.operator,
        value: input.value
      }
    }
  };
}

function buildCredentialProofRequest(input: {
  mode: CredentialProofMode;
  circuitId: CircuitId.CredentialAtomicQuerySigV2 | CircuitId.CredentialAtomicQuerySigV2OnChain;
  credentialId: string;
  credentialType: string;
  schema?: string;
  query: Record<string, unknown>;
  onchain?: CredentialProofOnchainOptions;
  config: PrivadoExpoConfig;
}): ProofRequest {
  const requestId = input.onchain?.requestId === undefined ? Date.now().toString() : String(input.onchain.requestId);
  const requestInput = {
    requestId,
    credentialType: input.credentialType,
    credentialSchema: input.schema,
    verifierAddress: input.onchain?.challengeAddress,
    challenge: input.mode === "onchain" ? evmAddressToChallenge(requireChallengeAddress(input.onchain)) : undefined,
    proofKind: "sig" as const,
    query: input.query,
    metadata: {
      credentialId: input.credentialId,
      mode: input.mode,
      universalVerifierAddress: input.onchain?.universalVerifierAddress ?? input.config.contracts.universalVerifierAddress,
      validatorAddress: input.onchain?.validatorAddress,
      challengeAddress: input.onchain?.challengeAddress,
      challenge: input.mode === "onchain" ? evmAddressToChallenge(requireChallengeAddress(input.onchain)) : undefined,
      signer: input.onchain?.signer,
      paymaster: input.onchain?.paymaster
    }
  };
  return input.mode === "onchain" ? buildOnchainSigV2Request(requestInput) : buildOffchainSigV2Request(requestInput);
}

function normalizeCredentialContext(context: string | string[] | undefined): string | undefined {
  if (Array.isArray(context)) {
    return [...context].reverse().find((item) => typeof item === "string" && !item.includes("credentials/v1"));
  }
  return context;
}

function normalizeOnchainOptions(
  onchain: CredentialProofOnchainOptions | undefined,
  config: PrivadoExpoConfig
): CredentialProofOnchainOptions {
  if (onchain?.evmPrivateKey) {
    throw new Error(
      "EVM private key derivation is not available in the SDK core. Pass challengeAddress from the app wallet."
    );
  }
  if (!onchain?.requestId && onchain?.requestId !== 0) {
    throw new Error("On-chain credential proof requestId is required.");
  }
  if (!onchain.challengeAddress) {
    throw new Error("On-chain credential proof challengeAddress is required.");
  }
  return {
    universalVerifierAddress: onchain?.universalVerifierAddress ?? config.contracts.universalVerifierAddress,
    validatorAddress: onchain?.validatorAddress,
    requestId: onchain?.requestId,
    challengeAddress: normalizeEvmAddress(onchain.challengeAddress),
    evmPrivateKey: onchain.evmPrivateKey,
    signer: onchain?.signer,
    paymaster: onchain?.paymaster
  };
}

function requireChallengeAddress(onchain: CredentialProofOnchainOptions | undefined): string {
  if (!onchain?.challengeAddress) {
    throw new Error("On-chain credential proof challengeAddress is required.");
  }
  return onchain.challengeAddress;
}

function readCredentialField(credential: unknown, field: string): unknown {
  if (!isRecord(credential)) {
    return undefined;
  }
  const subject = isRecord(credential.credentialSubject) ? credential.credentialSubject : undefined;
  if (!subject) {
    return undefined;
  }
  return readPath(subject, normalizeCredentialSubjectField(field));
}

function normalizeCredentialSubjectField(field: string): string {
  return field.replace(/^credentialSubject\./, "");
}

function readPath(value: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((current, part) => {
    if (!isRecord(current)) {
      return undefined;
    }
    return current[part];
  }, value);
}

function extractCredentialSchema(credential: unknown): string | undefined {
  if (!isRecord(credential)) {
    return undefined;
  }
  const schema = credential.credentialSchema;
  if (typeof schema === "string") {
    return schema;
  }
  if (isRecord(schema) && typeof schema.id === "string") {
    return schema.id;
  }
  return undefined;
}
