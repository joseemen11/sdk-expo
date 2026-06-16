import { universalVerifierAbi } from "./universalVerifierAbi";
import { isEvmAddress, normalizeEvmAddress } from "./evmChallenge";
import { addressToUint256LE } from "./challengeEncoding";
import type {
  GeneratedProof,
  SubmitOnchainProofToUniversalVerifierInput,
  UniversalVerifierCalldata,
  UniversalVerifierCalldataDebug,
  UniversalVerifierRequestStatus,
  UniversalVerifierSubmitResult
} from "../types";

declare function require(moduleName: string): unknown;

interface EthersRuntime {
  AbiCoder: {
    defaultAbiCoder(): AbiCoderLike;
  };
  JsonRpcProvider: new (url: string) => JsonRpcProviderLike;
  Wallet: new (privateKey: string, provider?: JsonRpcProviderLike) => WalletLike;
  Contract: new (address: string, abi: readonly unknown[], signerOrProvider: unknown) => UniversalVerifierContractLike;
}

interface AbiCoderLike {
  decode(types: string[], data: string): unknown[];
}

interface JsonRpcProviderLike {
  getNetwork(): Promise<{ chainId: bigint | number | string }>;
  getBalance(address: string): Promise<bigint>;
}

interface WalletLike {
  address: string;
}

interface UniversalVerifierContractLike {
  submitZKPResponse: {
    staticCall(
      requestId: string | bigint,
      inputs: string[],
      a: [string, string],
      b: [[string, string], [string, string]],
      c: [string, string]
    ): Promise<unknown>;
    (
      requestId: string | bigint,
      inputs: string[],
      a: [string, string],
      b: [[string, string], [string, string]],
      c: [string, string]
    ): Promise<{
      hash: string;
      wait(): Promise<{
        status?: number;
        blockNumber?: number;
        gasUsed?: { toString(): string };
        logs?: unknown[];
      }>;
    }>;
  };
  isProofVerified?(sender: string, requestId: string | bigint): Promise<boolean>;
  requestIdExists?(requestId: string | bigint): Promise<boolean>;
  isZKPRequestEnabled?(requestId: string | bigint): Promise<boolean>;
  getRequestOwner?(requestId: string | bigint): Promise<string>;
  owner?(): Promise<string>;
  getZKPRequest?(requestId: string | bigint): Promise<{
    metadata?: string;
    validator?: string;
    data?: string;
  }>;
  interface?: {
    parseLog(log: unknown): { name?: string } | null;
  };
}

const SIG_V2_ONCHAIN_QUERY_HASH_SIGNAL_INDEX = 2;
const SIG_V2_ONCHAIN_REQUEST_ID_SIGNAL_INDEX = 4;
const SIG_V2_ONCHAIN_CHALLENGE_SIGNAL_INDEX = 5;
const MTP_V2_ONCHAIN_QUERY_HASH_SIGNAL_INDEX = 2;
const MTP_V2_ONCHAIN_REQUEST_ID_SIGNAL_INDEX = 3;
const MTP_V2_ONCHAIN_CHALLENGE_SIGNAL_INDEX = 4;
const SUBMIT_ZKP_RESPONSE_LEGACY_SELECTOR = "0xb68967e2";

export async function submitOnchainProofToUniversalVerifier(
  input: SubmitOnchainProofToUniversalVerifierInput
): Promise<UniversalVerifierSubmitResult> {
  const rpcUrl = input.rpcUrl;
  if (!rpcUrl) {
    throw new Error("Universal Verifier submit requires rpcUrl.");
  }
  const universalVerifierAddress = input.universalVerifierAddress;
  if (!universalVerifierAddress || !isEvmAddress(universalVerifierAddress)) {
    throw new Error("Universal Verifier submit requires a valid universalVerifierAddress.");
  }
  if (!input.evmPrivateKey) {
    throw new Error("Universal Verifier submit requires evmPrivateKey for PoC/dev submit.");
  }

  const calldata = prepareUniversalVerifierCalldata(input.preparedProof, input.requestId);
  const ethers = loadEthers();
  const signerAddress = normalizeEvmAddress(new ethers.Wallet(input.evmPrivateKey).address);
  const challengeAddress = input.challengeAddress ? normalizeEvmAddress(input.challengeAddress) : undefined;
  if (challengeAddress && signerAddress !== challengeAddress) {
    throw new Error("Universal Verifier submit signer address does not match challengeAddress.");
  }
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const network = await provider.getNetwork();
  if (input.chainId !== undefined && Number(network.chainId) !== input.chainId) {
    throw new Error(`Universal Verifier submit chainId mismatch: expected ${input.chainId}, got ${String(network.chainId)}.`);
  }

  const signer = new ethers.Wallet(input.evmPrivateKey, provider);
  const balance = await provider.getBalance(signerAddress);
  if (balance <= 0n) {
    throw new Error("Universal Verifier submit wallet has no native token balance.");
  }

  const contract = new ethers.Contract(universalVerifierAddress, universalVerifierAbi, signer);
  const requestStatus = await readUniversalVerifierRequestStatus(contract, universalVerifierAddress, calldata.requestId);
  assertRequestStatusMatchesProof(requestStatus, input.preparedProof, input.validatorAddress);
  const calldataDebug = await buildUniversalVerifierCalldataDebug({
    input,
    calldata,
    contract,
    signerAddress,
    challengeAddress,
    requestStatus
  });
  assertCalldataDebugReady(calldataDebug);
  const tx = await contract.submitZKPResponse(
    BigInt(calldata.requestId),
    calldata.inputs,
    calldata.a,
    calldata.b,
    calldata.c
  );
  const receipt = await tx.wait();
  const verificationResult = contract.isProofVerified
    ? await safeIsProofVerified(contract, signerAddress, calldata.requestId)
    : undefined;

  return {
    txSubmitted: true,
    txHash: tx.hash,
    receiptStatus: receipt.status,
    blockNumber: receipt.blockNumber,
    gasUsed: receipt.gasUsed?.toString(),
    requestId: calldata.requestId,
    challengeAddress: challengeAddress ?? signerAddress,
    universalVerifierAddress: normalizeEvmAddress(universalVerifierAddress),
    eventName: firstEventName(contract, receipt.logs),
    verificationResult,
    signerAddress,
    staticCallOk: true,
    calldataDebug
  };
}

export function prepareUniversalVerifierCalldata(
  preparedProof: GeneratedProof,
  requestId?: string | number
): UniversalVerifierCalldata {
  const resolvedRequestId = requestId ?? preparedProof.request.id;
  if (resolvedRequestId === undefined || resolvedRequestId === null || String(resolvedRequestId).length === 0) {
    throw new Error("Universal Verifier calldata requires requestId.");
  }
  const proof = asRecord(preparedProof.proof);
  const inputs = arrayOfDecimalStrings(preparedProof.publicSignals, "publicSignals");
  if (inputs.length === 0) {
    throw new Error("Universal Verifier calldata requires publicSignals.");
  }
  const piA = arrayOfDecimalStrings(proof.pi_a ?? proof.piA ?? proof.a, "proof.pi_a");
  const piB = proof.pi_b ?? proof.piB ?? proof.b;
  const piC = arrayOfDecimalStrings(proof.pi_c ?? proof.piC ?? proof.c, "proof.pi_c");

  return {
    method: "submitZKPResponse",
    requestId: decimalString(resolvedRequestId, "requestId"),
    inputs,
    a: tuple2(piA, "proof.pi_a"),
    b: normalizePiB(piB),
    c: tuple2(piC, "proof.pi_c")
  };
}

export async function getUniversalVerifierRequestStatus(input: {
  rpcUrl: string;
  universalVerifierAddress: string;
  requestId: string | number;
}): Promise<UniversalVerifierRequestStatus> {
  if (!input.rpcUrl) {
    throw new Error("Universal Verifier request status requires rpcUrl.");
  }
  if (!isEvmAddress(input.universalVerifierAddress)) {
    throw new Error("Universal Verifier request status requires a valid universalVerifierAddress.");
  }
  const ethers = loadEthers();
  const provider = new ethers.JsonRpcProvider(input.rpcUrl);
  const contract = new ethers.Contract(input.universalVerifierAddress, universalVerifierAbi, provider);
  return readUniversalVerifierRequestStatus(contract, input.universalVerifierAddress, decimalString(input.requestId, "requestId"));
}

export async function prepareUniversalVerifierCalldataDebug(
  input: SubmitOnchainProofToUniversalVerifierInput
): Promise<UniversalVerifierCalldataDebug> {
  const rpcUrl = input.rpcUrl;
  if (!rpcUrl) {
    throw new Error("Universal Verifier calldata debug requires rpcUrl.");
  }
  const universalVerifierAddress = input.universalVerifierAddress;
  if (!universalVerifierAddress || !isEvmAddress(universalVerifierAddress)) {
    throw new Error("Universal Verifier calldata debug requires a valid universalVerifierAddress.");
  }
  if (!input.evmPrivateKey) {
    throw new Error("Universal Verifier calldata debug requires evmPrivateKey for signer/challenge validation.");
  }
  const calldata = prepareUniversalVerifierCalldata(input.preparedProof, input.requestId);
  const ethers = loadEthers();
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const network = await provider.getNetwork();
  if (input.chainId !== undefined && Number(network.chainId) !== input.chainId) {
    throw new Error(`Universal Verifier calldata debug chainId mismatch: expected ${input.chainId}, got ${String(network.chainId)}.`);
  }
  const signerAddress = normalizeEvmAddress(new ethers.Wallet(input.evmPrivateKey).address);
  const challengeAddress = input.challengeAddress ? normalizeEvmAddress(input.challengeAddress) : undefined;
  const signer = new ethers.Wallet(input.evmPrivateKey, provider);
  const contract = new ethers.Contract(universalVerifierAddress, universalVerifierAbi, signer);
  const requestStatus = await readUniversalVerifierRequestStatus(contract, universalVerifierAddress, calldata.requestId);
  return buildUniversalVerifierCalldataDebug({
    input,
    calldata,
    contract,
    signerAddress,
    challengeAddress,
    requestStatus
  });
}

export function deriveEvmAddressFromPrivateKey(evmPrivateKey: string): string {
  if (!evmPrivateKey) {
    throw new Error("EVM private key is required.");
  }
  const ethers = loadEthers();
  return normalizeEvmAddress(new ethers.Wallet(evmPrivateKey).address);
}

function loadEthers(): EthersRuntime {
  try {
    return require("ethers") as EthersRuntime;
  } catch {
    throw new Error("ethers is required to submit Universal Verifier transactions.");
  }
}

function safeIsProofVerified(
  contract: UniversalVerifierContractLike,
  signerAddress: string,
  requestId: string
): Promise<boolean | undefined> {
  return contract.isProofVerified?.(signerAddress, BigInt(requestId)).catch(() => undefined) ?? Promise.resolve(undefined);
}

async function readUniversalVerifierRequestStatus(
  contract: UniversalVerifierContractLike,
  universalVerifierAddress: string,
  requestId: string
): Promise<UniversalVerifierRequestStatus> {
  const base = {
    requestId,
    universalVerifierAddress: normalizeEvmAddress(universalVerifierAddress)
  };
  try {
    const exists = contract.requestIdExists ? await contract.requestIdExists(BigInt(requestId)) : true;
    const contractOwner = contract.owner ? normalizeEvmAddress(await contract.owner()) : undefined;
    if (!exists) {
      return {
        ...base,
        exists,
        contractOwner
      };
    }
    const [enabled, requestOwner, request] = await Promise.all([
      contract.isZKPRequestEnabled?.(BigInt(requestId)),
      contract.getRequestOwner?.(BigInt(requestId)),
      contract.getZKPRequest?.(BigInt(requestId))
    ]);
    const metadata = typeof request?.metadata === "string" ? request.metadata : undefined;
    const parsedMetadata = parseMetadata(metadata);
    const data = typeof request?.data === "string" ? request.data : undefined;
    const dataSummary = decodeSigV2OnchainRequestData(data);
    return {
      ...base,
      exists,
      enabled,
      requestOwner: requestOwner ? normalizeEvmAddress(requestOwner) : undefined,
      contractOwner,
      validator: request?.validator ? normalizeEvmAddress(request.validator) : undefined,
      metadata,
      metadataCircuitId: typeof parsedMetadata?.circuitId === "string" ? parsedMetadata.circuitId : undefined,
      metadataQuery: parsedMetadata?.query,
      dataLength: data?.length,
      ...dataSummary
    };
  } catch (error) {
    return {
      ...base,
      exists: false,
      readError: error instanceof Error ? error.message : String(error)
    };
  }
}

async function buildUniversalVerifierCalldataDebug(input: {
  input: SubmitOnchainProofToUniversalVerifierInput;
  calldata: UniversalVerifierCalldata;
  contract: UniversalVerifierContractLike;
  signerAddress: string;
  challengeAddress?: string;
  requestStatus: UniversalVerifierRequestStatus;
}): Promise<UniversalVerifierCalldataDebug> {
  const proofQuery = extractQuerySummary(input.input.preparedProof.request.query);
  const registeredQuery = extractQuerySummary(input.requestStatus.metadataQuery);
  const proofRequestId = decimalString(input.input.preparedProof.request.id, "preparedProof.request.id");
  const signalIndexes = getOnchainSignalIndexes(input.input.preparedProof.request.circuitId);
  const proofSignalRequestId = input.calldata.inputs[signalIndexes.requestId];
  const proofCircuitQueryHash = input.calldata.inputs[signalIndexes.queryHash];
  const proofChallenge = input.calldata.inputs[signalIndexes.challenge];
  const expectedChallenge = input.challengeAddress ? addressToUint256LE(input.challengeAddress) : undefined;
  const signerChallenge = addressToUint256LE(input.signerAddress);
  const queryHashMatches = input.requestStatus.registeredQueryHash
    ? input.requestStatus.registeredQueryHash === proofCircuitQueryHash
    : undefined;
  const requestMatchesProof =
    input.requestStatus.exists !== false &&
    input.calldata.requestId === proofRequestId &&
    (!input.requestStatus.metadataCircuitId || input.requestStatus.metadataCircuitId === input.input.preparedProof.request.circuitId) &&
    (!input.requestStatus.registeredQueryHash ||
      input.requestStatus.registeredQueryHash === proofCircuitQueryHash) &&
    (!registeredQuery.field || !proofQuery.field || registeredQuery.field === proofQuery.field) &&
    (!registeredQuery.operator || !proofQuery.operator || registeredQuery.operator === proofQuery.operator) &&
    (!registeredQuery.value || !proofQuery.value || registeredQuery.value === proofQuery.value);
  const publicSignalsCount = input.calldata.inputs.length;
  const debug: UniversalVerifierCalldataDebug = {
    requestIdUsedForProof: proofRequestId,
    requestIdUsedForSubmit: input.calldata.requestId,
    requestIdFromPublicSignals: proofSignalRequestId,
    requestMatchesProof,
    requestIdMatchesPublicSignal: proofSignalRequestId === input.calldata.requestId,
    registeredValidator: input.requestStatus.validator,
    registeredCircuitId: input.requestStatus.metadataCircuitId,
    registeredOperator: input.requestStatus.registeredOperator ?? registeredQuery.operator,
    registeredValue: input.requestStatus.registeredValue ?? registeredQuery.value,
    registeredQueryHash: input.requestStatus.registeredQueryHash,
    queryHashFromRequest: input.requestStatus.registeredQueryHash,
    proofCircuitId: input.input.preparedProof.request.circuitId,
    proofOperator: proofQuery.operator,
    proofValue: proofQuery.value,
    proofCircuitQueryHash,
    queryHashFromPublicSignal: proofCircuitQueryHash,
    queryHashMatches,
    challengeAddress: input.challengeAddress,
    signerAddress: input.signerAddress,
    signerMatchesChallenge: input.challengeAddress ? input.signerAddress === input.challengeAddress : undefined,
    proofChallenge,
    challengeFromPublicSignal: proofChallenge,
    expectedChallenge,
    challengeMatchesExpected: expectedChallenge ? proofChallenge === expectedChallenge : undefined,
    challengeMatchesSigner: proofChallenge === signerChallenge,
    publicSignalsCount,
    challengeMode: "senderAddressLittleEndian",
    submitMethod: "submitZKPResponse legacy",
    selector: SUBMIT_ZKP_RESPONSE_LEGACY_SELECTOR,
    proofResponsesCount: 1,
    pubSignalsLength: publicSignalsCount,
    requestParamsChallenge: input.input.preparedProof.request.challenge === undefined
      ? undefined
      : String(input.input.preparedProof.request.challenge),
    signalIndexes,
    calldataProofFormat: "web-compatible",
    piBOrder: "swapped",
    canStaticCall: false,
    failureLayer: determineFailureLayer({
      publicSignalsCount,
      requestMatchesProof,
      requestIdMatchesPublicSignal: proofSignalRequestId === input.calldata.requestId,
      queryHashMatches,
      signerMatchesChallenge: input.challengeAddress ? input.signerAddress === input.challengeAddress : undefined,
      challengeMatchesExpected: expectedChallenge ? proofChallenge === expectedChallenge : undefined,
      challengeMatchesSigner: proofChallenge === signerChallenge,
      canStaticCall: false
    })
  };
  try {
    await input.contract.submitZKPResponse.staticCall(
      BigInt(input.calldata.requestId),
      input.calldata.inputs,
      input.calldata.a,
      input.calldata.b,
      input.calldata.c
    );
    return {
      ...debug,
      canStaticCall: true,
      failureLayer: determineFailureLayer({
        publicSignalsCount,
        requestMatchesProof,
        requestIdMatchesPublicSignal: proofSignalRequestId === input.calldata.requestId,
        queryHashMatches,
        signerMatchesChallenge: input.challengeAddress ? input.signerAddress === input.challengeAddress : undefined,
        challengeMatchesExpected: expectedChallenge ? proofChallenge === expectedChallenge : undefined,
        challengeMatchesSigner: proofChallenge === signerChallenge,
        canStaticCall: true
      })
    };
  } catch (error) {
    return {
      ...debug,
      canStaticCall: false,
      staticCallError: safeErrorMessage(error),
      failureLayer: determineFailureLayer({
        publicSignalsCount,
        requestMatchesProof,
        requestIdMatchesPublicSignal: proofSignalRequestId === input.calldata.requestId,
        queryHashMatches,
        signerMatchesChallenge: input.challengeAddress ? input.signerAddress === input.challengeAddress : undefined,
        challengeMatchesExpected: expectedChallenge ? proofChallenge === expectedChallenge : undefined,
        challengeMatchesSigner: proofChallenge === signerChallenge,
        canStaticCall: false
      })
    };
  }
}

function getOnchainSignalIndexes(circuitId: string | undefined): {
  queryHash: number;
  requestId: number;
  challenge: number;
} {
  if (circuitId === "credentialAtomicQueryMTPV2OnChain") {
    return {
      queryHash: MTP_V2_ONCHAIN_QUERY_HASH_SIGNAL_INDEX,
      requestId: MTP_V2_ONCHAIN_REQUEST_ID_SIGNAL_INDEX,
      challenge: MTP_V2_ONCHAIN_CHALLENGE_SIGNAL_INDEX
    };
  }
  return {
    queryHash: SIG_V2_ONCHAIN_QUERY_HASH_SIGNAL_INDEX,
    requestId: SIG_V2_ONCHAIN_REQUEST_ID_SIGNAL_INDEX,
    challenge: SIG_V2_ONCHAIN_CHALLENGE_SIGNAL_INDEX
  };
}

function assertCalldataDebugReady(debug: UniversalVerifierCalldataDebug): void {
  if (!debug.requestMatchesProof) {
    throw new Error("Universal Verifier proof/request mismatch before submit.");
  }
  if (!debug.requestIdMatchesPublicSignal) {
    throw new Error("Universal Verifier proof was generated for a stale requestId.");
  }
  if (debug.signerMatchesChallenge === false) {
    throw new Error("Universal Verifier submit signer address does not match challengeAddress.");
  }
  if (debug.challengeMatchesExpected === false) {
    throw new Error("Universal Verifier proof challenge does not match challengeAddress.");
  }
  if (!debug.canStaticCall) {
    throw new Error(`Universal Verifier staticCall failed (${debug.failureLayer}): ${debug.staticCallError ?? "unknown error"}`);
  }
}

function determineFailureLayer(input: {
  publicSignalsCount: number;
  requestMatchesProof: boolean;
  requestIdMatchesPublicSignal: boolean;
  queryHashMatches?: boolean;
  signerMatchesChallenge?: boolean;
  challengeMatchesExpected?: boolean;
  challengeMatchesSigner?: boolean;
  canStaticCall: boolean;
}): UniversalVerifierCalldataDebug["failureLayer"] {
  if (input.publicSignalsCount !== 11) {
    return "calldata-format";
  }
  if (!input.requestIdMatchesPublicSignal || !input.requestMatchesProof) {
    return "request-publicsignal-mismatch";
  }
  if (input.queryHashMatches === false) {
    return "queryhash-mismatch";
  }
  if (
    input.signerMatchesChallenge === false ||
    input.challengeMatchesExpected === false ||
    input.challengeMatchesSigner === false
  ) {
    return "signer-challenge-mismatch";
  }
  return input.canStaticCall ? "none" : "cryptographic-verification";
}

function assertRequestStatusMatchesProof(
  status: UniversalVerifierRequestStatus,
  preparedProof: GeneratedProof,
  validatorAddress?: string
): void {
  if (status.readError) {
    throw new Error(`Universal Verifier request status could not be read: ${status.readError}`);
  }
  if (!status.exists) {
    throw new Error(`Universal Verifier requestId does not exist: ${status.requestId}`);
  }
  if (status.enabled === false) {
    throw new Error(`Universal Verifier requestId is not enabled: ${status.requestId}`);
  }
  if (validatorAddress && status.validator && normalizeEvmAddress(validatorAddress) !== status.validator) {
    throw new Error(
      `Universal Verifier request validator mismatch: expected ${normalizeEvmAddress(validatorAddress)}, got ${status.validator}.`
    );
  }
  if (status.metadataCircuitId && status.metadataCircuitId !== preparedProof.request.circuitId) {
    throw new Error(
      `Universal Verifier request circuit mismatch: expected ${preparedProof.request.circuitId}, got ${status.metadataCircuitId}.`
    );
  }
}

function parseMetadata(metadata: string | undefined): Record<string, unknown> | undefined {
  if (!metadata) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(metadata);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function decodeSigV2OnchainRequestData(data: string | undefined): Partial<UniversalVerifierRequestStatus> {
  if (!data || data === "0x") {
    return {};
  }
  const abiCoder = loadEthers().AbiCoder.defaultAbiCoder();
  try {
    const decoded = abiCoder.decode(
      ["tuple(uint256 schema,uint256 claimPathKey,uint256 operator,uint256[] value,uint256 queryHash)"],
      data
    );
    const tuple = Array.isArray(decoded) ? decoded[0] : undefined;
    if (!Array.isArray(tuple)) {
      return {};
    }
    const values = Array.isArray(tuple[3]) ? tuple[3] : [];
    return {
      registeredSchema: decimalString(tuple[0], "registered schema"),
      registeredClaimPathKey: decimalString(tuple[1], "registered claimPathKey"),
      registeredOperator: operatorNameFromValue(decimalString(tuple[2], "registered operator")),
      registeredValue: values.length > 0 ? decimalString(values[0], "registered value[0]") : undefined,
      registeredQueryHash: decimalString(tuple[4], "registered queryHash")
    };
  } catch {
    return {};
  }
}

function extractQuerySummary(query: unknown): {
  field?: string;
  operator?: string;
  value?: string;
  issuerDid?: string;
  credentialType?: string;
} {
  const record = query && typeof query === "object" && !Array.isArray(query) ? (query as Record<string, unknown>) : {};
  const credentialType = typeof record.type === "string" ? record.type : undefined;
  const allowedIssuers = Array.isArray(record.allowedIssuers) ? record.allowedIssuers : undefined;
  const issuerDid = typeof allowedIssuers?.[0] === "string" ? allowedIssuers[0] : undefined;
  const credentialSubject =
    record.credentialSubject && typeof record.credentialSubject === "object" && !Array.isArray(record.credentialSubject)
      ? (record.credentialSubject as Record<string, unknown>)
      : {};
  const firstField = Object.keys(credentialSubject)[0];
  const fieldQuery =
    firstField && credentialSubject[firstField] && typeof credentialSubject[firstField] === "object"
      ? (credentialSubject[firstField] as Record<string, unknown>)
      : undefined;
  if (!firstField || !fieldQuery) {
    return { issuerDid, credentialType };
  }
  if (typeof fieldQuery.operator === "string") {
    return {
      field: firstField,
      operator: normalizeOperatorName(fieldQuery.operator),
      value: optionalDecimalString(fieldQuery.value),
      issuerDid,
      credentialType
    };
  }
  const operatorKey = Object.keys(fieldQuery).find((key) => key.startsWith("$"));
  return {
    field: firstField,
    operator: operatorKey ? normalizeOperatorName(operatorKey) : undefined,
    value: operatorKey ? optionalDecimalString(fieldQuery[operatorKey]) : undefined,
    issuerDid,
    credentialType
  };
}

function normalizeOperatorName(operator: string): string {
  return operator.startsWith("$") ? operator.slice(1) : operator;
}

function operatorNameFromValue(value: string): string {
  switch (value) {
    case "0":
      return "noop";
    case "1":
      return "eq";
    case "2":
      return "lt";
    case "3":
      return "gt";
    case "4":
      return "in";
    default:
      return value;
  }
}

function optionalDecimalString(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return decimalString(value, "query value");
}

function safeErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.length > 300 ? `${message.slice(0, 300)}...` : message;
}

function firstEventName(contract: UniversalVerifierContractLike, logs: unknown[] | undefined): string | undefined {
  if (!contract.interface?.parseLog || !logs) {
    return undefined;
  }
  for (const log of logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed?.name) {
        return parsed.name;
      }
    } catch {
      // Ignore unrelated logs.
    }
  }
  return undefined;
}

function normalizePiB(value: unknown): [[string, string], [string, string]] {
  if (!Array.isArray(value) || value.length < 2 || !Array.isArray(value[0]) || !Array.isArray(value[1])) {
    throw new Error("Universal Verifier calldata requires proof.pi_b.");
  }
  const first = arrayOfDecimalStrings(value[0], "proof.pi_b[0]");
  const second = arrayOfDecimalStrings(value[1], "proof.pi_b[1]");
  return [
    [first[1] ?? required(first[1], "proof.pi_b[0][1]"), first[0] ?? required(first[0], "proof.pi_b[0][0]")],
    [second[1] ?? required(second[1], "proof.pi_b[1][1]"), second[0] ?? required(second[0], "proof.pi_b[1][0]")]
  ];
}

function tuple2(values: string[], field: string): [string, string] {
  if (values.length < 2) {
    throw new Error(`Universal Verifier calldata requires ${field}.`);
  }
  return [values[0], values[1]];
}

function arrayOfDecimalStrings(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`Universal Verifier calldata requires ${field}.`);
  }
  return value.map((entry, index) => decimalString(entry, `${field}[${index}]`));
}

function decimalString(value: unknown, field: string): string {
  if (typeof value === "bigint" && value >= 0n) {
    return value.toString();
  }
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    return value;
  }
  throw new Error(`Universal Verifier calldata ${field} must be a decimal bigint string.`);
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Universal Verifier calldata requires proof object.");
  }
  return value as Record<string, unknown>;
}

function required(value: unknown, field: string): never {
  throw new Error(`Universal Verifier calldata requires ${field}.`);
}
