import type { CircuitId } from "../circuits/CircuitId";

export interface NetworkConfig {
  name: string;
  chainId: number;
  rpcUrl?: string;
}

export interface IssuerConfig {
  issuerDid: string;
  issuerBaseUrl?: string;
}

export interface CredentialConfig {
  credentialType: string;
  credentialSchema: string;
  credentialContext: string | string[];
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
  sha256: string;
  sizeBytes: number;
}

export interface CircuitArtifactDescriptor {
  circuitId: CircuitId;
  wasm: CircuitArtifactFile;
  zkey: CircuitArtifactFile;
  verificationKey: CircuitArtifactFile;
}

export interface CircuitArtifactManifest {
  artifacts: CircuitArtifactDescriptor[];
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

export interface KMSAdapter {
  sign(payload: Uint8Array, keyId?: string): Promise<Uint8Array>;
  getPublicKey?(keyId?: string): Promise<Uint8Array>;
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
  offer: string | Record<string, unknown>;
  holderDid?: string;
}

export type ProofKind = "sig" | "mtp";

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
  createAuthProof(input: ClaimCredentialInput): Promise<unknown>;
}

export interface PrivadoExpoClientAdapters {
  secureKeyStore?: SecureKeyStore;
  credentialStorage?: CredentialStorageAdapter;
  zkProvider?: ZKProvider;
  rpcAdapter?: RPCAdapter;
  txSubmitter?: ZkpTxSubmitter;
  authV2Provider?: AuthV2Provider;
}
