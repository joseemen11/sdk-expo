import { CircuitArtifactRegistry } from "../circuits/CircuitArtifactRegistry";
import { CircuitId } from "../circuits/CircuitId";
import { validatePrivadoExpoConfig } from "../config/validatePrivadoExpoConfig";
import { clearCredentials } from "../credentials/clearCredentials";
import { deleteCredential } from "../credentials/deleteCredential";
import { getCredentialById } from "../credentials/getCredentialById";
import { getCredentials } from "../credentials/getCredentials";
import { importCredentialFromJson } from "../credentials/importCredentialFromJson";
import { saveCredential } from "../credentials/saveCredential";
import { claimCredentialFromOffer } from "../issuer/claimCredentialFromOffer";
import { checkProofVerified } from "../onchain/checkProofVerified";
import { prepareUniversalVerifierPayload as preparePayload } from "../onchain/prepareUniversalVerifierPayload";
import { generateOffchainProof } from "../proofs/generateOffchainProof";
import { generateOnchainProof } from "../proofs/generateOnchainProof";
import { buildOffchainMtpV2Request } from "../proofRequests/buildOffchainMtpV2Request";
import { buildOffchainSigV2Request } from "../proofRequests/buildOffchainSigV2Request";
import { buildOnchainMtpV2Request } from "../proofRequests/buildOnchainMtpV2Request";
import { buildOnchainSigV2Request } from "../proofRequests/buildOnchainSigV2Request";
import { DevelopmentSecureKeyStore } from "../storage/SecureKeyStore";
import { EncryptedCredentialStorage } from "../storage/EncryptedCredentialStorage";
import { submitProof } from "../tx/submitProof";
import type {
  BuildProofRequestInput,
  CheckProofVerifiedInput,
  ClaimCredentialInput,
  CredentialStorageAdapter,
  GenerateProofInput,
  GeneratedProof,
  ImportedCredentialSummary,
  PrivadoExpoClientAdapters,
  PrivadoExpoConfig,
  ProofRequest,
  SubmitProofInput,
  UniversalVerifierPayload
} from "../types";

export class PrivadoExpoClient {
  readonly config: PrivadoExpoConfig;
  readonly circuitRegistry: CircuitArtifactRegistry;
  private readonly credentialStorage: CredentialStorageAdapter;
  private readonly adapters: PrivadoExpoClientAdapters;
  private initialized = false;

  constructor(config: PrivadoExpoConfig, adapters: PrivadoExpoClientAdapters = {}) {
    this.config = validatePrivadoExpoConfig(config);
    this.adapters = adapters;
    const secureKeyStore = adapters.secureKeyStore ?? new DevelopmentSecureKeyStore();
    this.credentialStorage =
      adapters.credentialStorage ?? new EncryptedCredentialStorage({ secureKeyStore });
    this.circuitRegistry = new CircuitArtifactRegistry(this.config.circuits);
  }

  async init(): Promise<void> {
    this.circuitRegistry.validate();
    await this.credentialStorage.init?.();
    this.initialized = true;
  }

  importCredentialFromJson(rawJson: string | Record<string, unknown>): {
    credential: unknown;
    summary: ImportedCredentialSummary;
  } {
    return importCredentialFromJson(rawJson);
  }

  async saveCredential(credential: unknown): Promise<ImportedCredentialSummary> {
    await this.ensureInitialized();
    return saveCredential(credential, this.credentialStorage);
  }

  async getCredentials(): Promise<ImportedCredentialSummary[]> {
    await this.ensureInitialized();
    return getCredentials(this.credentialStorage);
  }

  async getCredentialById(id: string): Promise<unknown | undefined> {
    await this.ensureInitialized();
    return getCredentialById(id, this.credentialStorage);
  }

  async deleteCredential(id: string): Promise<void> {
    await this.ensureInitialized();
    await deleteCredential(id, this.credentialStorage);
  }

  async clearCredentials(): Promise<void> {
    await this.ensureInitialized();
    await clearCredentials(this.credentialStorage);
  }

  async claimCredentialFromOffer(input: ClaimCredentialInput): Promise<unknown> {
    await this.ensureInitialized();
    return claimCredentialFromOffer(input, this.adapters.authV2Provider);
  }

  buildOffchainProofRequest(input: BuildProofRequestInput): ProofRequest {
    return input.proofKind === "sig" ? buildOffchainSigV2Request(input) : buildOffchainMtpV2Request(input);
  }

  async generateOffchainProof(input: GenerateProofInput): Promise<GeneratedProof> {
    await this.ensureInitialized();
    return generateOffchainProof(input, this.adapters.zkProvider);
  }

  buildOnchainProofRequest(input: BuildProofRequestInput): ProofRequest {
    return input.proofKind === "sig" ? buildOnchainSigV2Request(input) : buildOnchainMtpV2Request(input);
  }

  async generateOnchainProof(input: GenerateProofInput): Promise<GeneratedProof> {
    await this.ensureInitialized();
    const artifacts = input.circuitArtifacts ?? this.circuitRegistry.get(input.request.circuitId as CircuitId);
    return generateOnchainProof({ ...input, circuitArtifacts: artifacts }, this.adapters.zkProvider);
  }

  prepareUniversalVerifierPayload(input: {
    requestId: string | number;
    proof: GeneratedProof;
    queryHash?: string;
    metadata?: Record<string, unknown>;
  }): UniversalVerifierPayload {
    return preparePayload({ ...input, config: this.config });
  }

  async submitProof(input: SubmitProofInput): Promise<{ txHash: string; raw?: unknown }> {
    await this.ensureInitialized();
    return submitProof(input, this.adapters.txSubmitter);
  }

  async checkProofVerified(input: CheckProofVerifiedInput): Promise<boolean> {
    await this.ensureInitialized();
    return checkProofVerified(input, this.config, this.adapters.rpcAdapter);
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }
  }
}
