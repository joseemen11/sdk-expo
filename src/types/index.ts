import type { CircuitId } from "../circuits/CircuitId";
import type { AuthV2InputBuilder } from "../auth/AuthV2InputBuilder";
import type { MobileGistProofSource } from "../auth/MobileGistProofSource";
import type { HttpClient } from "../network/HttpClient";
import type { NativeProver, NativeWitnessCalculator } from "../zk/AuthV2ZKProvider";

export interface NetworkConfig {
  name: string;
  chainId: number;
  rpcUrl?: string;
}

export interface IssuerConfig {
  issuerDid: string;
  issuerBaseUrl?: string;
  issuerAdminBase?: string;
  basicAuth?: {
    username: string;
    password: string;
  };
}

export interface CredentialConfig {
  credentialType: string;
  credentialSchema: string;
  credentialContext: string | string[];
  credentialExpirationDays?: number;
}

export interface VerifierConfig {
  verifierDid?: string;
  verifierUrl?: string;
  verifierAddress?: string;
}

export interface ContractConfig {
  stateContractAddress: string;
  universalVerifierAddress: string;
}

export interface DidResolverConfig {
  didResolverUrl: string;
}

export interface CircuitArtifactFile {
  url?: string;
  localPath?: string;
  path?: string;
  sha256?: string;
  sizeBytes?: number;
}

export interface CircuitArtifactDescriptor {
  circuitId: CircuitId;
  version?: string;
  wasm?: CircuitArtifactFile;
  graph?: CircuitArtifactFile;
  dat?: CircuitArtifactFile;
  zkey?: CircuitArtifactFile;
  verificationKey?: CircuitArtifactFile;
  wasmPath?: string;
  graphPath?: string;
  datPath?: string;
  zkeyPath?: string;
  verificationKeyPath?: string;
  hashes?: {
    wasm?: string;
    graph?: string;
    dat?: string;
    zkey?: string;
    verificationKey?: string;
  };
  sizes?: {
    wasm?: number;
    graph?: number;
    dat?: number;
    zkey?: number;
    verificationKey?: number;
  };
}

export interface CircuitArtifactManifest {
  artifacts: CircuitArtifactDescriptor[];
}

export type CircuitWitnessMode = "wasm" | "native";

export interface CircuitArtifactValidationResult {
  circuitId: CircuitId;
  valid: boolean;
  missing: string[];
}

export interface CircuitArtifactResolver {
  register(descriptor: CircuitArtifactDescriptor): void;
  resolve(circuitId: CircuitId): CircuitArtifactDescriptor | undefined;
  require(circuitId: CircuitId): CircuitArtifactDescriptor;
  validate(circuitId: CircuitId, witnessMode?: CircuitWitnessMode): CircuitArtifactValidationResult;
}

export interface PrivadoExpoConfig {
  network: NetworkConfig;
  contracts: ContractConfig;
  didResolver: DidResolverConfig;
  issuer?: IssuerConfig;
  credential?: CredentialConfig;
  verifier?: VerifierConfig;
  circuits?: CircuitArtifactManifest;
}

export interface StorageAdapter<TRecord = unknown> {
  init?(): Promise<void>;
  get(key: string): Promise<TRecord | undefined>;
  set(key: string, value: TRecord): Promise<void>;
  remove(key: string): Promise<void>;
}

export interface SecureKeyStore {
  getItem(key: string): Promise<string | undefined>;
  setItem(key: string, value: string): Promise<void>;
  deleteItem(key: string): Promise<void>;
  getOrCreateEncryptionKey(alias: string): Promise<Uint8Array>;
  getOrCreateKey(alias: string): Promise<Uint8Array>;
  deleteKey(alias: string): Promise<void>;
}

export interface StoredCredentialRecord {
  id: string;
  encryptedPayload: string;
  summary: ImportedCredentialSummary;
  createdAt: string;
  updatedAt: string;
}

export interface CredentialStorageAdapter {
  init?(): Promise<void>;
  saveCredential(credential: unknown): Promise<ImportedCredentialSummary>;
  getCredentials(): Promise<ImportedCredentialSummary[]>;
  getCredentialById(id: string): Promise<unknown | undefined>;
  deleteCredential(id: string): Promise<void>;
  clearCredentials(): Promise<void>;
}

export interface HolderIdentity {
  did: string;
  keyId: string;
  method?: string;
  network?: string;
  createdAt: string;
  updatedAt: string;
  developmentOnly?: boolean;
}

export interface HolderDidRecord {
  did: string;
  keyId: string;
  method?: string;
  network?: string;
  createdAt: string;
  updatedAt: string;
  developmentOnly?: boolean;
}

export interface HolderDidSummary {
  did: string;
  keyId: string;
  method?: string;
  network?: string;
  createdAt: string;
  updatedAt: string;
  developmentOnly?: boolean;
}

export interface IdentityStorageAdapter {
  init?(): Promise<void>;
  getHolderDid(): Promise<HolderDidSummary | undefined>;
  saveHolderDid(record: HolderDidRecord): Promise<HolderDidSummary>;
  deleteHolderIdentity(): Promise<DeleteHolderIdentityResult>;
}

export interface PrivateKeyStoreAdapter {
  ensureKey(keyId: string): Promise<{ keyId: string; created: boolean }>;
  deleteKey(keyId: string): Promise<void>;
}

export interface KMSKeyHandle {
  keyId: string;
  algorithm: string;
  created: boolean;
  developmentOnly?: boolean;
}

export interface KMSAdapter {
  createOrLoadKey?(input: { keyId?: string; algorithm?: string }): Promise<KMSKeyHandle>;
  signChallenge?(input: SignChallengeInput): Promise<SignChallengeResult>;
  deleteKey?(keyId: string): Promise<void>;
  sign(payload: Uint8Array, keyId?: string): Promise<Uint8Array>;
  getPublicKey?(keyId?: string): Promise<Uint8Array>;
}

export interface CreateOrLoadHolderDidInput {
  mode?: "real" | "development";
  keyId?: string;
  method?: string;
  network?: string;
}

export interface CreateOrLoadHolderDidResult extends HolderDidSummary {
  isNew: boolean;
}

export interface SignChallengeInput {
  challenge: string | Uint8Array;
  keyId?: string;
}

export interface SignChallengeResult {
  keyId: string;
  algorithm: string;
  signature: string;
  signatureEncoding: "base64";
  developmentOnly?: boolean;
}

export interface DeleteHolderIdentityResult {
  deleted: boolean;
  did?: string;
  keyId?: string;
}

export interface HolderDidProvider {
  readonly developmentOnly?: boolean;
  createHolderIdentity?(input: {
    keyId?: string;
    method?: string;
    network?: string;
  }): Promise<{
    did: string;
    keyId: string;
    method?: string;
    network?: string;
    developmentOnly?: boolean;
  }>;
  createDid(input: {
    keyId: string;
    method?: string;
    network?: string;
  }): Promise<{
    did: string;
    method?: string;
    network?: string;
    developmentOnly?: boolean;
  }>;
}

export interface ProofRequest {
  id: string;
  circuitId: CircuitId;
  query: Record<string, unknown>;
  scope: Record<string, unknown>[];
  challenge?: string;
  metadata?: Record<string, unknown>;
}

export interface GeneratedProof {
  circuitId: CircuitId;
  proof: unknown;
  publicSignals: unknown;
  request: ProofRequest;
}

export interface ZKProvider {
  generateProof(input: GenerateProofInput): Promise<GeneratedProof>;
}

export interface RPCAdapter {
  readContract<T = unknown>(input: {
    chainId: number;
    rpcUrl?: string;
    contractAddress: string;
    abi: readonly unknown[];
    functionName: string;
    args: readonly unknown[];
  }): Promise<T>;
}

export interface SignerAdapter {
  getAddress(): Promise<string>;
  signTypedData?(payload: unknown): Promise<string>;
  sendTransaction?(payload: unknown): Promise<string>;
}

export interface ZkpTxSubmitter {
  submitProof(input: SubmitProofInput): Promise<{ txHash: string; raw?: unknown }>;
}

export interface SubmitOnchainProofToUniversalVerifierInput {
  preparedProof: GeneratedProof;
  requestId?: string | number;
  evmPrivateKey: string;
  rpcUrl?: string;
  universalVerifierAddress?: string;
  chainId?: number;
  challengeAddress?: string;
  validatorAddress?: string;
}

export interface UniversalVerifierCalldata {
  method: "submitZKPResponse";
  requestId: string;
  inputs: string[];
  a: [string, string];
  b: [[string, string], [string, string]];
  c: [string, string];
}

export interface UniversalVerifierSubmitResult {
  txSubmitted: boolean;
  txHash?: string;
  receiptStatus?: number;
  blockNumber?: number;
  gasUsed?: string;
  requestId: string;
  challengeAddress?: string;
  universalVerifierAddress: string;
  eventName?: string;
  verificationResult?: boolean;
  signerAddress?: string;
  staticCallOk?: boolean;
  calldataDebug?: UniversalVerifierCalldataDebug;
}

export interface UniversalVerifierRequestStatus {
  requestId: string;
  universalVerifierAddress: string;
  exists: boolean;
  enabled?: boolean;
  requestOwner?: string;
  contractOwner?: string;
  validator?: string;
  metadata?: string;
  metadataCircuitId?: string;
  metadataQuery?: unknown;
  dataLength?: number;
  registeredQueryHash?: string;
  registeredOperator?: string;
  registeredValue?: string;
  registeredSchema?: string;
  registeredClaimPathKey?: string;
  readError?: string;
}

export interface UniversalVerifierCalldataDebug {
  requestIdUsedForProof: string;
  requestIdUsedForSubmit: string;
  requestIdFromPublicSignals?: string;
  requestMatchesProof: boolean;
  requestIdMatchesPublicSignal: boolean;
  registeredValidator?: string;
  registeredCircuitId?: string;
  registeredOperator?: string;
  registeredValue?: string;
  registeredQueryHash?: string;
  queryHashFromRequest?: string;
  proofCircuitId: string;
  proofOperator?: string;
  proofValue?: string;
  proofCircuitQueryHash?: string;
  queryHashFromPublicSignal?: string;
  queryHashMatches?: boolean;
  challengeAddress?: string;
  signerAddress?: string;
  signerMatchesChallenge?: boolean;
  proofChallenge?: string;
  challengeFromPublicSignal?: string;
  expectedChallenge?: string;
  challengeMatchesExpected?: boolean;
  challengeMatchesSigner?: boolean;
  publicSignalsCount: number;
  calldataProofFormat: "web-compatible";
  piBOrder: "swapped";
  canStaticCall: boolean;
  staticCallError?: string;
  failureLayer:
    | "none"
    | "signer-challenge-mismatch"
    | "request-publicsignal-mismatch"
    | "queryhash-mismatch"
    | "calldata-format"
    | "artifact-validator-mismatch"
    | "cryptographic-verification";
}

export interface OnchainSubmitStrategy {
  submit(input: SubmitProofInput, submitter: ZkpTxSubmitter): Promise<{ txHash: string; raw?: unknown }>;
}

export interface ImportedCredentialSummary {
  id: string;
  type: string[];
  issuer?: string;
  credentialSubjectId?: string;
  expirationDate?: string;
  proofTypes: string[];
  createdAt?: string;
  updatedAt?: string;
}

export interface ClaimCredentialInput {
  offer?: string | Record<string, unknown>;
  message?: string | Record<string, unknown>;
  holderDid?: string;
}

export interface ClaimCredentialFromIssuerInput {
  holderDid?: string;
  offer?: string | Record<string, unknown>;
  credentialSubject: Record<string, unknown>;
  credentialType?: string;
  credentialSchema?: string;
  credentialExpirationDays?: number;
}

export type IssuerClaimDebugStepName = "createCredential" | "offer" | "claim" | "save";

export interface IssuerClaimDebugStep {
  step: IssuerClaimDebugStepName;
  status: "ok" | "error" | "skipped" | "saved";
  method?: string;
  url?: string;
  httpStatus?: number;
  contentType?: string;
  responsePreview?: string;
  challengeSource?: "jwz-message-hash" | "offer-or-fallback";
  challengeLength?: number;
  challengeUnderField?: boolean;
  claimLocalStep?:
    | "build-fetch-request"
    | "compute-jwz-challenge"
    | "generate-authv2-proof"
    | "pack-jwz"
    | "post-agent"
    | "receive-credential";
  postExecuted?: boolean;
  jwzHeader?: {
    typ?: string;
    alg?: string;
    circuitId?: string;
  };
  messageId?: string;
  messageIdFormat?: "uuid" | "invalid";
  threadId?: string;
  threadIdFormat?: "uuid" | "invalid";
  messageType?: string;
  credentialSummary?: {
    id?: string;
    type: string[];
    issuer?: string;
    proofTypes: string[];
    credentialStatus?: {
      type?: string;
      url?: string;
    };
    mtpViable: boolean;
    mtpUnavailableReason?: string;
  };
  error?: string;
}

export interface ClaimCredentialRuntimeContext {
  input: ClaimCredentialInput;
  message: Record<string, unknown>;
  holderDid: HolderDidSummary;
  keyId: string;
  profileNonce: string;
  authProof?: unknown;
}

export interface ClaimCredentialResult {
  holderDid: string;
  credentialIds: string[];
  credentials: ImportedCredentialSummary[];
}

export interface ClaimCredentialFromIssuerResult extends ClaimCredentialResult {
  credentialSaved: boolean;
  credentialType?: string;
  issuerDid?: string;
  storageId?: string;
}

export interface ClaimCredentialFromIssuerDebugResult extends ClaimCredentialFromIssuerResult {
  steps: IssuerClaimDebugStep[];
}

export interface AuthV2WitnessOnlyResult {
  graphSource?: string;
  graphExtension?: string;
  graphExists: boolean;
  graphSizeBytes?: number;
  inputsKeysCount: number;
  authClaimIncMtpSiblings: number;
  authClaimNonRevMtpSiblings: number;
  gistMtpSiblings: number;
  witnessGenerated: boolean;
  witnessEncoding?: string;
  witnessSizeBytes?: number;
}

export interface AuthV2ProofOnlyResult extends AuthV2WitnessOnlyResult {
  zkeyPathExists: boolean;
  zkeySizeBytes?: number;
  proofGenerated: boolean;
  publicSignalsCount?: number;
}

export interface Iden3commClaimProvider {
  claimCredentialFromOffer(input: ClaimCredentialRuntimeContext): Promise<unknown>;
}

export type ProofKind = "sig" | "mtp";
export type CredentialProofMode = "offchain" | "onchain";
export type CredentialProofOperator = "eq" | "lt" | "gt" | "in" | "noop";

export interface CredentialProofQuery {
  field: string;
  operator: CredentialProofOperator;
  value?: unknown;
}

export interface CredentialProofOnchainOptions {
  universalVerifierAddress?: string;
  validatorAddress?: string;
  requestId?: string | number;
  challengeAddress?: string;
  evmPrivateKey?: string;
  signer?: "external" | "injected";
  paymaster?: string;
}

export interface GenerateCredentialProofInput {
  credentialId: string;
  credentialType: string;
  issuerDid?: string;
  schema?: string;
  query: CredentialProofQuery;
  circuitId?: CircuitId.CredentialAtomicQuerySigV2 | CircuitId.CredentialAtomicQuerySigV2OnChain;
  mode?: CredentialProofMode;
  onchain?: CredentialProofOnchainOptions;
}

export interface CredentialProofPlan {
  credentialId: string;
  credentialType: string;
  issuerDid?: string;
  schema?: string;
  mode: CredentialProofMode;
  circuitId: CircuitId.CredentialAtomicQuerySigV2 | CircuitId.CredentialAtomicQuerySigV2OnChain;
  query: CredentialProofQuery;
  request: ProofRequest;
  credentialSummary: ImportedCredentialSummary;
  onchain?: CredentialProofOnchainOptions;
  proofGenerated: false;
  nextBoundary: string;
}

export interface CredentialAtomicQuerySigV2ProofResult {
  proofGenerated: boolean;
  mode?: CredentialProofMode;
  circuitId: CircuitId.CredentialAtomicQuerySigV2 | CircuitId.CredentialAtomicQuerySigV2OnChain;
  credentialId: string;
  credentialType: string;
  issuerDid?: string;
  field: string;
  operator: CredentialProofOperator;
  proofRoute?: "slot-based" | "merklized";
  requestId?: string;
  challengeAddress?: string;
  challenge?: string;
  publicSignalsCount?: number;
  inputsKeysCount: number;
  graphSource?: string;
  graphExtension?: string;
  graphExists: boolean;
  graphSizeBytes?: number;
  zkeyPathExists: boolean;
  zkeySizeBytes?: number;
  proofSource?: "rapidsnark";
  publicSignalsSource?: "rapidsnark" | "missing";
}

export interface PreparedCredentialAtomicQuerySigV2OnChainProof {
  summary: CredentialAtomicQuerySigV2ProofResult;
  preparedProof: GeneratedProof;
  debugCircuitInputs?: {
    circuitId: CircuitId.CredentialAtomicQuerySigV2OnChain;
    requestId?: string;
    credentialType: string;
    field: string;
    operator: CredentialProofOperator;
    value?: unknown;
    graphPath: string;
    zkeyPath: string;
    inputKeys: string[];
    challengeEncoding: "addressToUint256LE";
    challengeSignatureValid: boolean;
    issuerClaimSignatureValid: boolean;
    inputBuilderFailureLayer: "none" | "challenge-signature" | "issuer-claim-signature" | "query-value-proof" | "unknown";
    inputs: Record<string, unknown>;
  };
}

export interface BuildProofRequestInput {
  requestId?: string;
  credentialType?: string;
  credentialSchema?: string;
  credentialSubjectId?: string;
  verifierDid?: string;
  verifierAddress?: string;
  challenge?: string;
  query?: Record<string, unknown>;
  proofKind?: ProofKind;
  metadata?: Record<string, unknown>;
}

export interface GenerateProofInput {
  request: ProofRequest;
  credential?: unknown;
  holderDid?: string;
  profileNonce?: number | string;
  circuitArtifacts?: CircuitArtifactDescriptor;
  witnessInputs?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface SubmitProofInput {
  payload: UniversalVerifierPayload;
  signer?: SignerAdapter;
  metadata?: Record<string, unknown>;
}

export interface CheckProofVerifiedInput {
  requestId: string | number;
  userAddress: string;
}

export interface UniversalVerifierPayload {
  contractAddress: string;
  requestId: string | number;
  inputs: unknown;
  piA: unknown;
  piB: unknown;
  piC: unknown;
  queryHash?: string;
  metadata?: Record<string, unknown>;
}

export interface AuthV2Provider {
  createAuthProof(input: ClaimCredentialInput | ClaimCredentialRuntimeContext): Promise<unknown>;
}

export interface PrivadoExpoClientAdapters {
  secureKeyStore?: SecureKeyStore;
  mobileMetadataStore?: StorageAdapter<string>;
  circuitArtifactStore?: CircuitArtifactResolver;
  credentialStorage?: CredentialStorageAdapter;
  identityStorage?: IdentityStorageAdapter;
  kmsAdapter?: KMSAdapter;
  holderDidProvider?: HolderDidProvider;
  realHolderDidProvider?: HolderDidProvider;
  developmentHolderDidProvider?: HolderDidProvider;
  zkProvider?: ZKProvider;
  authV2WitnessCalculator?: NativeWitnessCalculator;
  authV2NativeProver?: NativeProver;
  authV2InputBuilder?: AuthV2InputBuilder;
  gistProofSource?: MobileGistProofSource;
  httpClient?: HttpClient;
  rpcAdapter?: RPCAdapter;
  txSubmitter?: ZkpTxSubmitter;
  authV2Provider?: AuthV2Provider;
  iden3commClaimProvider?: Iden3commClaimProvider;
  credentialAtomicQuerySigV2InputBuilder?: CredentialAtomicQuerySigV2InputBuilder;
  credentialAtomicQuerySigV2ValueProofProvider?: CredentialAtomicQuerySigV2ValueProofProvider;
}

export interface CredentialAtomicQuerySigV2InputBuilder {
  buildInputs(input: {
    plan: CredentialProofPlan;
    credential: unknown;
    holderDid: HolderDidSummary;
    config: PrivadoExpoConfig;
  }): Promise<Record<string, unknown>>;
}

export interface CredentialAtomicQuerySigV2ValueProofProvider {
  buildValueProof(input: {
    credential: unknown;
    credentialType: string;
    field: string;
    operator: CredentialProofQuery["operator"];
    queryValue: unknown;
  }): Promise<{
    proof: unknown;
    pathKey: string;
    pathValue: string;
    queryValues: string[];
  }>;
}
