import { MobileAuthV2Provider } from "../auth/MobileAuthV2Provider";
import { AuthV2InputBuilder } from "../auth/AuthV2InputBuilder";
import type { AuthV2InputsPreview } from "../auth/AuthV2InputPreflight";
import {
  MobileAuthV2ChallengeSigner,
  MobileAuthV2IdentityProofSource
} from "../auth/MobileAuthV2IdentityProofSource";
import { ReadOnlyMobileGistProofSource } from "../auth/MobileGistProofSource";
import { CircuitArtifactRegistry } from "../circuits/CircuitArtifactRegistry";
import { CircuitId } from "../circuits/CircuitId";
import { ExpoCircuitArtifactStore } from "../circuits/ExpoCircuitArtifactStore";
import { formatCircuitArtifactMissingError, getMissingCircuitArtifactPaths } from "../circuits/CircuitArtifactStore";
import { validatePrivadoExpoConfig } from "../config/validatePrivadoExpoConfig";
import { clearCredentials } from "../credentials/clearCredentials";
import { deleteCredential } from "../credentials/deleteCredential";
import { getCredentialById } from "../credentials/getCredentialById";
import { getCredentials } from "../credentials/getCredentials";
import { importCredentialFromJson } from "../credentials/importCredentialFromJson";
import { saveCredential } from "../credentials/saveCredential";
import { claimCredentialFromOffer } from "../credentials/claimCredentialFromOffer";
import { assertValidCredentialForStorage } from "../credentials/credentialValidation";
import { parseCredentialOffer } from "../issuer/offerParser";
import {
  IssuerClaimProvider,
  type CreateIssuerCredentialInput,
  type PreparedIssuerClaimRequest
} from "../issuer/IssuerClaimProvider";
import { extractCredentialId } from "../issuer/extractCredentialId";
import { createOrLoadHolderDid } from "../identity/createOrLoadHolderDid";
import { deleteHolderIdentity } from "../identity/deleteHolderIdentity";
import { EncryptedIdentityStorage } from "../identity/EncryptedIdentityStorage";
import { getHolderDid } from "../identity/getHolderDid";
import { RealPrivadoIdentityProvider } from "../identity/RealPrivadoIdentityProvider";
import { BjjKmsAdapter } from "../kms/BjjKmsAdapter";
import { signChallenge } from "../kms/signChallenge";
import { checkProofVerified } from "../onchain/checkProofVerified";
import { prepareUniversalVerifierPayload as preparePayload } from "../onchain/prepareUniversalVerifierPayload";
import {
  prepareUniversalVerifierCalldata,
  submitOnchainProofToUniversalVerifier as submitUniversalVerifierProof
} from "../onchain/universalVerifierSubmit";
import { prepareCredentialProofPlan } from "../proofs/CredentialProofPlanner";
import { generateOffchainProof } from "../proofs/generateOffchainProof";
import { generateOnchainProof } from "../proofs/generateOnchainProof";
import { buildOffchainMtpV2Request } from "../proofRequests/buildOffchainMtpV2Request";
import { buildOffchainSigV2Request } from "../proofRequests/buildOffchainSigV2Request";
import { buildOnchainMtpV2Request } from "../proofRequests/buildOnchainMtpV2Request";
import { buildOnchainSigV2Request } from "../proofRequests/buildOnchainSigV2Request";
import { DevelopmentSecureKeyStore } from "../storage/SecureKeyStore";
import { EncryptedCredentialStorage } from "../storage/EncryptedCredentialStorage";
import { submitProof } from "../tx/submitProof";
import { MobileCredentialAtomicQuerySigV2InputBuilder } from "../proofs/CredentialAtomicQuerySigV2Builder";
import type {
  BuildProofRequestInput,
  CheckProofVerifiedInput,
  AuthV2WitnessOnlyResult,
  AuthV2ProofOnlyResult,
  ClaimCredentialInput,
  ClaimCredentialFromIssuerInput,
  ClaimCredentialFromIssuerDebugResult,
  ClaimCredentialFromIssuerResult,
  ClaimCredentialResult,
  ClaimCredentialRuntimeContext,
  IssuerCredentialResolver,
  IssuerClaimDebugStep,
  CircuitArtifactResolver,
  CredentialAtomicQuerySigV2ProofResult,
  CredentialStorageAdapter,
  CreateOrLoadHolderDidInput,
  CreateOrLoadHolderDidResult,
  CredentialProofPlan,
  PreparedCredentialAtomicQuerySigV2OnChainProof,
  RefetchMtpCredentialFromIssuerInput,
  RefetchMtpCredentialFromIssuerResult,
  DeleteHolderIdentityResult,
  GenerateCredentialProofInput,
  GenerateProofInput,
  GeneratedProof,
  HolderDidSummary,
  IdentityStorageAdapter,
  ImportedCredentialSummary,
  KMSAdapter,
  PrivadoExpoClientAdapters,
  PrivadoExpoConfig,
  ProofRequest,
  SecureKeyStore,
  SignChallengeInput,
  SignChallengeResult,
  StorageAdapter,
  SubmitOnchainProofToUniversalVerifierInput,
  SubmitProofInput,
  UniversalVerifierSubmitResult,
  UniversalVerifierPayload
} from "../types";

export class PrivadoExpoClient {
  readonly config: PrivadoExpoConfig;
  readonly circuitRegistry: CircuitArtifactRegistry;
  readonly circuitArtifactStore: CircuitArtifactResolver;
  private readonly secureKeyStore: SecureKeyStore;
  private readonly credentialStorage: CredentialStorageAdapter;
  private readonly identityStorage: IdentityStorageAdapter;
  private readonly mobileMetadataStore?: StorageAdapter<string>;
  private readonly kmsAdapter: KMSAdapter;
  private readonly adapters: PrivadoExpoClientAdapters;
  private initialized = false;

  constructor(config: PrivadoExpoConfig, adapters: PrivadoExpoClientAdapters = {}) {
    this.config = validatePrivadoExpoConfig(config);
    this.adapters = adapters;
    const secureKeyStore = adapters.secureKeyStore ?? new DevelopmentSecureKeyStore();
    this.secureKeyStore = secureKeyStore;
    this.credentialStorage =
      adapters.credentialStorage ?? new EncryptedCredentialStorage({ secureKeyStore });
    this.identityStorage =
      adapters.identityStorage ?? new EncryptedIdentityStorage({ secureKeyStore });
    this.mobileMetadataStore = adapters.mobileMetadataStore;
    this.kmsAdapter = adapters.kmsAdapter ?? new BjjKmsAdapter();
    this.circuitRegistry = new CircuitArtifactRegistry(this.config.circuits);
    this.circuitArtifactStore =
      adapters.circuitArtifactStore ?? new ExpoCircuitArtifactStore({ manifest: this.config.circuits });
  }

  async init(): Promise<void> {
    this.circuitRegistry.validate();
    await this.mobileMetadataStore?.init?.();
    await this.credentialStorage.init?.();
    await this.identityStorage.init?.();
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

  async createOrLoadHolderDid(input: CreateOrLoadHolderDidInput = {}): Promise<CreateOrLoadHolderDidResult> {
    await this.ensureInitialized();
    return createOrLoadHolderDid({
      request: input,
      identityStorage: this.identityStorage,
      kmsAdapter: this.kmsAdapter,
      holderDidProvider: this.adapters.holderDidProvider,
      realHolderDidProvider:
        this.adapters.realHolderDidProvider ??
        new RealPrivadoIdentityProvider({
          secureKeyStore: this.secureKeyStore,
          metadataStore: this.mobileMetadataStore,
          credentialStorage: this.credentialStorage,
          identityStorage: this.identityStorage,
          method: input.method,
          network: input.network ?? this.config.network.name
        }),
      developmentHolderDidProvider: this.adapters.developmentHolderDidProvider
    });
  }

  async getHolderDid(): Promise<HolderDidSummary | undefined> {
    await this.ensureInitialized();
    return getHolderDid(this.identityStorage);
  }

  async signChallenge(input: SignChallengeInput): Promise<SignChallengeResult> {
    await this.ensureInitialized();
    return signChallenge({
      request: input,
      kmsAdapter: this.kmsAdapter,
      identityStorage: this.identityStorage
    });
  }

  async deleteHolderIdentity(): Promise<DeleteHolderIdentityResult> {
    await this.ensureInitialized();
    return deleteHolderIdentity(this.identityStorage, this.kmsAdapter);
  }

  async claimCredentialFromOffer(input: ClaimCredentialInput): Promise<ClaimCredentialResult> {
    await this.ensureInitialized();
    const authV2Provider =
      this.adapters.authV2Provider ??
      this.createDefaultMobileAuthV2Provider();
    return claimCredentialFromOffer(input, {
      identityStorage: this.identityStorage,
      credentialStorage: this.credentialStorage,
      authV2Provider,
      iden3commClaimProvider: this.getIden3commClaimProvider(),
      issuerCredentialResolver: this.getIssuerCredentialResolver()
    });
  }

  async claimCredentialFromIssuer(input: ClaimCredentialFromIssuerInput): Promise<ClaimCredentialFromIssuerResult> {
    return this.claimCredentialFromIssuerInternal(input, false);
  }

  async claimCredentialFromIssuerDebug(input: ClaimCredentialFromIssuerInput): Promise<ClaimCredentialFromIssuerDebugResult> {
    return this.claimCredentialFromIssuerInternal(input, true);
  }

  async refetchMtpCredentialFromIssuer(
    input: RefetchMtpCredentialFromIssuerInput = {}
  ): Promise<RefetchMtpCredentialFromIssuerResult> {
    await this.ensureInitialized();
    const steps: IssuerClaimDebugStep[] = [];
    const holderDid = await this.identityStorage.getHolderDid();
    if (!holderDid) {
      throw new Error("A real Holder DID must be created before hydrating an MTP credential.");
    }
    const storedSummary = input.storageId
      ? (await this.credentialStorage.getCredentials()).find((summary) => summary.id === input.storageId)
      : selectLatestPendingMtpSummary(await this.credentialStorage.getCredentials());
    const storedCredential = storedSummary?.id
      ? await this.credentialStorage.getCredentialById(storedSummary.id)
      : undefined;
    const issuerCredentialId =
      input.credentialId ??
      storedSummary?.issuerCredentialId ??
      extractIssuerCredentialIdFromMetadata(storedCredential) ??
      extractCredentialId(storedCredential);
    if (!issuerCredentialId) {
      throw new Error("No issuer credentialId is available for MTP hydration.");
    }
    const resolver = this.getIssuerCredentialResolverForDebug(steps);
    if (!resolver) {
      throw new Error("Issuer credential resolver is required to hydrate MTP credential.");
    }
    const result = await resolver.resolveCredentialWithProof({
      issuerDid: this.config.issuer?.issuerDid ?? storedSummary?.issuer,
      credentialId: issuerCredentialId,
      holderDid: input.holderDid ?? holderDid.did,
      credentialType: input.credentialType ?? firstCredentialType(storedSummary) ?? this.config.credential?.credentialType,
      credentialSchema: input.credentialSchema ?? extractCredentialSchema(storedCredential) ?? this.config.credential?.credentialSchema,
      requiredProofType: "Iden3SparseMerkleTreeProof",
      claimedCredential: storedCredential,
      allowExistingMtpCredentialFallback: input.allowExistingMtpCredentialFallback
    });
    const proofTypes = result.credential ? extractCredentialProofTypes(result.credential) : result.proofTypes;
    if (!result.credential || !proofTypes.includes("Iden3SparseMerkleTreeProof")) {
      return {
        credentialSaved: false,
        storageId: storedSummary?.id,
        issuerCredentialId,
        mtpReady: false,
        mtpStatus: "pending-mtp-hydration",
        proofTypes,
        message: "Credential still pending MTP. Publish/wait issuer state and retry hydration.",
        steps
      };
    }
    assertValidCredentialForStorage(result.credential);
    const saved = await this.credentialStorage.saveCredential(withMtpMetadata(result.credential, {
      issuerCredentialId,
      mtpReady: true,
      mtpStatus: "mtp-ready"
    }));
    steps.push({
      step: "save",
      status: "saved",
      responsePreview: "saved hydrated MTP credential"
    });
    return {
      credentialSaved: true,
      storageId: saved.id,
      issuerCredentialId,
      mtpReady: true,
      mtpStatus: "mtp-ready",
      proofTypes: saved.proofTypes,
      message: "MTP credential hydrated and saved.",
      summary: saved,
      steps
    };
  }

  private async claimCredentialFromIssuerInternal(
    input: ClaimCredentialFromIssuerInput,
    debug: boolean
  ): Promise<ClaimCredentialFromIssuerDebugResult> {
    await this.ensureInitialized();
    const steps: IssuerClaimDebugStep[] = [];
    const holderDid = await this.identityStorage.getHolderDid();
    if (!holderDid) {
      throw new Error("A real Holder DID must be created before claiming a credential from issuer.");
    }
    if (holderDid.developmentOnly) {
      throw new Error("A real Holder DID is required to claim a credential from issuer.");
    }
    if (input.holderDid && input.holderDid !== holderDid.did) {
      throw new Error("Requested holderDid does not match the active local Holder DID.");
    }
    try {
      const provider = this.getIssuerCredentialProvider(debug ? steps : undefined);
      const offer: { offer: string | Record<string, unknown>; raw?: unknown } = input.offer
        ? (steps.push({ step: "createCredential", status: "skipped" }, { step: "offer", status: "skipped" }), { offer: input.offer })
        : await provider.createCredentialOffer({
            holderDid: holderDid.did,
            credentialSubject: input.credentialSubject,
            credentialType: input.credentialType,
            credentialSchema: input.credentialSchema,
            credentialExpirationDays: input.credentialExpirationDays
          });
      const createdCredentialId = isRecord(offer.raw)
        ? extractCredentialId(offer.raw.credential ?? offer.raw)
        : undefined;
      const baseContext = await this.createClaimCredentialRuntimeContext({
        message: offer.offer,
        holderDid: holderDid.did
      });
      const preparedRequests =
        typeof provider.prepareClaimRequests === "function"
          ? await provider.prepareClaimRequests(baseContext)
          : undefined;
      const authContext = preparedRequests?.[0]
        ? {
            ...baseContext,
            message: {
              ...preparedRequests[0].fetchRequest,
              body: {
                ...(isRecord(preparedRequests[0].fetchRequest.body) ? preparedRequests[0].fetchRequest.body : {}),
                challenge: preparedRequests[0].challenge
              }
            }
          }
        : baseContext;
      const authV2Provider =
        this.adapters.authV2Provider ??
        this.createDefaultMobileAuthV2Provider();
      let authProof: unknown;
      try {
        authProof = await authV2Provider.createAuthProof(authContext);
        if (preparedRequests?.[0]) {
          steps.push({
            step: "claim",
            status: "ok",
            claimLocalStep: "generate-authv2-proof",
            challengeSource: "jwz-message-hash",
            challengeLength: preparedRequests[0].challenge.length,
            challengeUnderField: isDecimalFieldElement(preparedRequests[0].challenge),
            postExecuted: false
          });
        }
      } catch (error) {
        pushStepError(steps, "claim", error, "error", "generate-authv2-proof", false);
        throw error;
      }
      const providerResult =
        preparedRequests && typeof provider.claimPreparedCredentialRequests === "function"
          ? await provider.claimPreparedCredentialRequests(preparedRequests, authProof)
          : await provider.claimCredentialFromOffer({
              ...baseContext,
              authProof
            });
      const credentials = extractCredentials(providerResult);
      if (credentials.length === 0) {
        pushStepError(steps, "save", new Error("Issuer did not return a valid credential."), "skipped");
        throw new Error("Issuer did not return a valid credential.");
      }
      for (const credential of credentials) {
        try {
          assertValidCredentialForStorage(credential);
        } catch (error) {
          pushStepError(steps, "save", error, "skipped");
          throw error;
        }
      }
      const resolver =
        typeof (provider as IssuerCredentialProvider & Partial<IssuerCredentialResolver>).resolveCredentialWithProof === "function"
          ? provider as IssuerCredentialProvider & IssuerCredentialResolver
          : this.getIssuerCredentialResolver();
      const hydratedCredentials = await hydrateIssuerCredentialsForMtp(credentials, {
        resolver,
        holderDid: holderDid.did,
        issuerDid: this.config.issuer?.issuerDid,
        credentialId: createdCredentialId,
        credentialType: input.credentialType ?? this.config.credential?.credentialType,
        credentialSchema: input.credentialSchema ?? this.config.credential?.credentialSchema,
        steps: debug ? steps : undefined
      });
      const summaries: ImportedCredentialSummary[] = [];
      for (const credential of hydratedCredentials) {
        try {
          assertValidCredentialForStorage(credential);
        } catch (error) {
          pushStepError(steps, "save", error, "skipped");
          throw error;
        }
      }
      for (const credential of hydratedCredentials) {
        summaries.push(await this.credentialStorage.saveCredential(credential));
      }
      steps.push({ step: "save", status: "saved", responsePreview: `saved ${summaries.length} credential(s)` });
      const result = {
        holderDid: holderDid.did,
        credentialIds: summaries.map((summary) => summary.id),
        credentials: summaries,
        credentialSaved: summaries.length > 0,
        credentialType: input.credentialType ?? this.config.credential?.credentialType ?? summaries[0]?.type[0],
        issuerDid: this.config.issuer?.issuerDid ?? summaries[0]?.issuer,
        storageId: summaries[0]?.id,
        issuerCredentialId: summaries[0]?.issuerCredentialId ?? createdCredentialId,
        mtpReady: summaries[0]?.mtpReady ?? false,
        mtpStatus: summaries[0]?.mtpStatus ?? "pending-mtp-hydration",
        steps
      };
      return result;
    } catch (error) {
      if (debug) {
        if (!steps.some((step) => step.step === "save")) {
          steps.push({ step: "save", status: "skipped", error: errorMessage(error) });
        }
        return {
          holderDid: holderDid.did,
          credentialIds: [],
          credentials: [],
          credentialSaved: false,
          credentialType: input.credentialType ?? this.config.credential?.credentialType,
          issuerDid: this.config.issuer?.issuerDid,
          mtpReady: false,
          mtpStatus: "pending-mtp-hydration",
          steps: steps.length > 0 ? steps : [{ step: "createCredential", status: "error", error: errorMessage(error) }]
        };
      }
      throw error;
    }
  }

  async buildAuthV2InputsPreview(input: ClaimCredentialInput): Promise<AuthV2InputsPreview> {
    await this.ensureInitialized();
    const provider = this.createDefaultMobileAuthV2Provider();
    const context = await this.createClaimCredentialRuntimeContext(input);
    return provider.buildAuthV2InputsPreview(context);
  }

  async generateAuthV2WitnessOnly(input: ClaimCredentialInput): Promise<AuthV2WitnessOnlyResult> {
    await this.ensureInitialized();
    return (await this.prepareAuthV2Witness(input)).summary;
  }

  async generateAuthV2ProofOnly(input: ClaimCredentialInput): Promise<AuthV2ProofOnlyResult> {
    await this.ensureInitialized();
    const witnessCalculator = this.adapters.authV2WitnessCalculator;
    const prover = this.adapters.authV2NativeProver;
    if (!witnessCalculator) {
      throw new Error("Mobile witness calculator is required to generate AuthV2 witness.");
    }
    if (!prover) {
      throw new Error("Native prover is required to generate AuthV2 proof.");
    }
    const artifacts = this.circuitArtifactStore.resolve(CircuitId.AuthV2);
    const zkeyPath = artifacts?.zkey?.localPath ?? artifacts?.zkeyPath;
    if (!zkeyPath) {
      throw new Error("AuthV2 proof is not ready: zkey is missing.");
    }
    const zkeyInfo = await inspectProverFile(prover, zkeyPath);
    if (zkeyInfo && (!zkeyInfo.exists || (zkeyInfo.sizeBytes ?? 0) <= 0)) {
      throw new Error("AuthV2 proof is not ready: zkey file is missing or empty.");
    }
    const witness = await this.prepareAuthV2Witness(input);
    if (typeof witness.result.witness !== "string" || witness.result.witness.length === 0) {
      throw new Error("AuthV2 proof is not ready: witness base64 is missing.");
    }
    const proofResult = await prover.generateProof({
      circuitId: CircuitId.AuthV2,
      zkeyPath,
      witnessPath: witness.result.witnessPath,
      witness: witness.result.witness,
      witnessByteLength: witness.result.witnessByteLength,
      witnessSha256: witness.result.witnessSha256
    });
    const publicSignals = Array.isArray(proofResult.publicSignals) ? proofResult.publicSignals : undefined;
    return {
      ...witness.summary,
      zkeyPathExists: zkeyInfo?.exists ?? true,
      zkeySizeBytes: zkeyInfo?.sizeBytes,
      proofGenerated: true,
      publicSignalsCount: publicSignals?.length
    };
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

  async generateCredentialProof(input: GenerateCredentialProofInput): Promise<CredentialProofPlan> {
    await this.ensureInitialized();
    return prepareCredentialProofPlan(input, {
      credentialStorage: this.credentialStorage,
      config: this.config
    });
  }

  async generateCredentialAtomicQuerySigV2Proof(
    input: GenerateCredentialProofInput
  ): Promise<CredentialAtomicQuerySigV2ProofResult> {
    return this.generateCredentialAtomicQueryV2ProofForCircuit({
      ...input,
      mode: "offchain",
      circuitId: CircuitId.CredentialAtomicQuerySigV2
    });
  }

  async generateCredentialAtomicQuerySigV2OnChainProof(
    input: GenerateCredentialProofInput
  ): Promise<CredentialAtomicQuerySigV2ProofResult> {
    const prepared = await this.generateCredentialAtomicQuerySigV2OnChainPreparedProof(input);
    return prepared.summary;
  }

  async generateCredentialAtomicQuerySigV2OnChainPreparedProof(
    input: GenerateCredentialProofInput
  ): Promise<PreparedCredentialAtomicQuerySigV2OnChainProof> {
    return this.generateCredentialAtomicQueryV2ProofForCircuit({
      ...input,
      mode: "onchain",
      circuitId: CircuitId.CredentialAtomicQuerySigV2OnChain
    });
  }

  async generateCredentialAtomicQueryMTPV2Proof(
    input: GenerateCredentialProofInput
  ): Promise<CredentialAtomicQuerySigV2ProofResult> {
    return this.generateCredentialAtomicQueryV2ProofForCircuit({
      ...input,
      mode: "offchain",
      circuitId: CircuitId.CredentialAtomicQueryMTPV2
    });
  }

  async generateCredentialAtomicQueryMTPV2OnChainProof(
    input: GenerateCredentialProofInput
  ): Promise<CredentialAtomicQuerySigV2ProofResult> {
    const prepared = await this.generateCredentialAtomicQueryMTPV2OnChainPreparedProof(input);
    return prepared.summary;
  }

  async generateCredentialAtomicQueryMTPV2OnChainPreparedProof(
    input: GenerateCredentialProofInput
  ): Promise<PreparedCredentialAtomicQuerySigV2OnChainProof> {
    return this.generateCredentialAtomicQueryV2ProofForCircuit({
      ...input,
      mode: "onchain",
      circuitId: CircuitId.CredentialAtomicQueryMTPV2OnChain
    });
  }

  private async generateCredentialAtomicQueryV2ProofForCircuit(
    input: GenerateCredentialProofInput & {
      mode: "onchain";
      circuitId: CircuitId.CredentialAtomicQuerySigV2OnChain | CircuitId.CredentialAtomicQueryMTPV2OnChain;
    }
  ): Promise<PreparedCredentialAtomicQuerySigV2OnChainProof>;
  private async generateCredentialAtomicQueryV2ProofForCircuit(
    input: GenerateCredentialProofInput
  ): Promise<CredentialAtomicQuerySigV2ProofResult>;
  private async generateCredentialAtomicQueryV2ProofForCircuit(
    input: GenerateCredentialProofInput
  ): Promise<CredentialAtomicQuerySigV2ProofResult | PreparedCredentialAtomicQuerySigV2OnChainProof> {
    await this.ensureInitialized();
    const plan = await prepareCredentialProofPlan(input, {
      credentialStorage: this.credentialStorage,
      config: this.config
    });
    if (
      plan.circuitId !== CircuitId.CredentialAtomicQuerySigV2 &&
      plan.circuitId !== CircuitId.CredentialAtomicQuerySigV2OnChain &&
      plan.circuitId !== CircuitId.CredentialAtomicQueryMTPV2 &&
      plan.circuitId !== CircuitId.CredentialAtomicQueryMTPV2OnChain
    ) {
      throw new Error("Only credentialAtomicQuerySigV2 and credentialAtomicQueryMTPV2 proofs are supported by this method.");
    }
    const credential = await this.credentialStorage.getCredentialById(plan.credentialId);
    if (!credential) {
      throw new Error("Credential proof cannot be generated: credential was not found.");
    }
    assertMtpFlowNotRoutedToSigV2(plan.circuitId, credential);
    assertCredentialSupportsCredentialAtomicQueryV2(credential, plan.circuitId);
    const holderDid = await this.identityStorage.getHolderDid();
    if (!holderDid || holderDid.developmentOnly) {
      throw new Error("A real Holder DID is required to generate credential proofs.");
    }
    const witnessCalculator = this.adapters.authV2WitnessCalculator;
    const prover = this.adapters.authV2NativeProver;
    if (!witnessCalculator) {
      throw new Error("Mobile witness calculator is required to generate credentialAtomicQuerySigV2 proof.");
    }
    if (!prover) {
      throw new Error("Native prover is required to generate credentialAtomicQuerySigV2 proof.");
    }
    const artifacts = this.circuitArtifactStore.resolve(plan.circuitId);
    if (!artifacts) {
      throw new Error(formatCircuitArtifactMissingError(plan.circuitId, []));
    }
    const missing = getMissingCircuitArtifactPaths(artifacts, "native");
    if (missing.length > 0) {
      throw new Error(formatCircuitArtifactMissingError(plan.circuitId, missing));
    }
    const graphPath = artifacts.graph?.localPath ?? artifacts.graphPath;
    const zkeyPath = artifacts.zkey?.localPath ?? artifacts.zkeyPath;
    if (!graphPath || !zkeyPath) {
      throw new Error(`${plan.circuitId} circuit artifacts are incomplete.`);
    }
    const graphInfo = await inspectWitnessGraph(witnessCalculator, graphPath);
    if (graphInfo && (!graphInfo.graphExists || (graphInfo.graphSizeBytes ?? 0) <= 0)) {
      throw new Error(`${plan.circuitId} proof is not ready: graph file is missing or empty.`);
    }
    const zkeyInfo = await inspectProverFile(prover, zkeyPath);
    if (zkeyInfo && (!zkeyInfo.exists || (zkeyInfo.sizeBytes ?? 0) <= 0)) {
      throw new Error(`${plan.circuitId} proof is not ready: zkey file is missing or empty.`);
    }
    const inputBuilder =
      this.adapters.credentialAtomicQuerySigV2InputBuilder ??
      new MobileCredentialAtomicQuerySigV2InputBuilder({
        httpClient: this.adapters.httpClient,
        valueProofProvider: this.adapters.credentialAtomicQuerySigV2ValueProofProvider,
        authV2InputBuilder: this.adapters.authV2InputBuilder ?? this.createDefaultAuthV2InputBuilder()
      });
    let witnessInputs: Record<string, unknown>;
    try {
      witnessInputs = await inputBuilder.buildInputs({
        plan,
        credential,
        holderDid,
        config: this.config
      });
    } catch (error) {
      throw rewriteMtpRoutingError(error, plan.circuitId);
    }
    const proofRoute =
      witnessInputs.__proofRoute === "slot-based" || witnessInputs.__proofRoute === "merklized"
        ? witnessInputs.__proofRoute
        : undefined;
    delete witnessInputs.__proofRoute;
    const witnessResult = await witnessCalculator.calculateWitness({
      circuitId: plan.circuitId,
      graphPath,
      inputs: witnessInputs
    });
    const proofResult = await prover.generateProof({
      circuitId: plan.circuitId,
      zkeyPath,
      witnessPath: witnessResult.witnessPath,
      witness: witnessResult.witness,
      witnessByteLength: witnessResult.witnessByteLength,
      witnessSha256: witnessResult.witnessSha256
    });
    const publicSignals = Array.isArray(proofResult.publicSignals) ? proofResult.publicSignals : undefined;
    const generatedProof: GeneratedProof = {
      circuitId: plan.circuitId,
      proof: proofResult.proof,
      publicSignals: proofResult.publicSignals ?? [],
      request: plan.request
    };
    const proofCalldata =
      plan.mode === "onchain"
        ? tryPrepareUniversalVerifierCalldata(generatedProof, String(plan.onchain?.requestId ?? plan.request.id))
        : undefined;
    const summary: CredentialAtomicQuerySigV2ProofResult = {
      proofGenerated: true,
      mode: plan.mode,
      circuitId: plan.circuitId,
      credentialId: plan.credentialId,
      credentialType: plan.credentialType,
      issuerDid: plan.issuerDid,
      field: plan.query.field,
      operator: plan.query.operator,
      proofRoute,
      requestId: plan.mode === "onchain" ? String(plan.onchain?.requestId ?? plan.request.id) : undefined,
      challengeAddress: plan.mode === "onchain" ? plan.onchain?.challengeAddress : undefined,
      challenge: plan.mode === "onchain" ? plan.request.challenge : undefined,
      publicSignalsCount: publicSignals?.length,
      inputsKeysCount: Object.keys(witnessInputs).length,
      graphSource: graphInfo?.graphSource,
      graphExtension: graphInfo?.graphExtension,
      graphExists: graphInfo?.graphExists ?? false,
      graphSizeBytes: graphInfo?.graphSizeBytes,
      zkeyPathExists: zkeyInfo?.exists ?? true,
      zkeySizeBytes: zkeyInfo?.sizeBytes,
      proofSource: "rapidsnark",
      publicSignalsSource: publicSignals ? "rapidsnark" : "missing"
    };
    if (plan.mode === "onchain") {
      return {
        summary,
        preparedProof: generatedProof,
        debugProverOutputs: {
          runId: proofResult.runId,
          startedAt: proofResult.startedAt,
          finishedAt: proofResult.finishedAt,
          zkeyPath: proofResult.zkeyPath,
          witnessSource: proofResult.witnessSource,
          witnessPath: proofResult.witnessPath,
          witnessByteLength: proofResult.witnessByteLength,
          witnessSha256: proofResult.witnessSha256,
          inputByteLength: witnessResult.inputByteLength,
          inputSha256: witnessResult.inputSha256,
          rawProof: proofResult.rawProof,
          rawPublicSignals: proofResult.rawPublicSignals,
          proofSnarkjs: proofResult.proof,
          publicSignals: proofResult.publicSignals ?? [],
          proofCalldata: proofCalldata?.calldata,
          proofCalldataError: proofCalldata?.error
        },
        debugCircuitInputs: {
          circuitId: plan.circuitId as CircuitId.CredentialAtomicQuerySigV2OnChain | CircuitId.CredentialAtomicQueryMTPV2OnChain,
          requestId: String(plan.onchain?.requestId ?? plan.request.id),
          credentialType: plan.credentialType,
          field: plan.query.field,
          operator: plan.query.operator,
          value: plan.query.value,
          graphPath,
          datPath: artifacts.dat?.localPath ?? artifacts.datPath,
          zkeyPath,
          inputKeys: Object.keys(witnessInputs),
          inputSha256: witnessResult.inputSha256,
          challengeEncoding: "addressToUint256LE",
          challengeSignatureValid: true,
          issuerClaimSignatureValid: true,
          inputBuilderFailureLayer: "none",
          inputs: witnessInputs
        }
      };
    }
    return summary;
  }

  async submitOnchainProofToUniversalVerifier(
    input: Omit<SubmitOnchainProofToUniversalVerifierInput, "rpcUrl" | "universalVerifierAddress" | "chainId"> &
      Partial<Pick<SubmitOnchainProofToUniversalVerifierInput, "rpcUrl" | "universalVerifierAddress" | "chainId">>
  ): Promise<UniversalVerifierSubmitResult> {
    await this.ensureInitialized();
    return submitUniversalVerifierProof({
      ...input,
      rpcUrl: input.rpcUrl ?? this.config.network.rpcUrl,
      universalVerifierAddress: input.universalVerifierAddress ?? this.config.contracts.universalVerifierAddress,
      chainId: input.chainId ?? this.config.network.chainId
    });
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

  private createDefaultAuthV2InputBuilder(): AuthV2InputBuilder {
    return new AuthV2InputBuilder({
      identityProofSource: new MobileAuthV2IdentityProofSource({
        metadataStore: this.mobileMetadataStore,
        secureKeyStore: this.secureKeyStore,
        gistProofSource:
          this.adapters.gistProofSource ??
          new ReadOnlyMobileGistProofSource({
            didResolverUrl: this.config.didResolver.didResolverUrl,
            httpClient: this.adapters.httpClient,
            rpcAdapter: this.adapters.rpcAdapter,
            chainId: this.config.network.chainId,
            rpcUrl: this.config.network.rpcUrl,
            stateContractAddress: this.config.contracts.stateContractAddress
          })
      }),
      challengeSigner: new MobileAuthV2ChallengeSigner({
        kmsAdapter: this.kmsAdapter
      })
    });
  }

  private createDefaultMobileAuthV2Provider(): MobileAuthV2Provider {
    return new MobileAuthV2Provider({
      zkProvider: this.adapters.zkProvider,
      circuitArtifacts: this.circuitArtifactStore.resolve(CircuitId.AuthV2),
      inputBuilder: this.adapters.authV2InputBuilder ?? this.createDefaultAuthV2InputBuilder()
    });
  }

  private getIden3commClaimProvider() {
    return this.adapters.iden3commClaimProvider ?? (this.config.issuer ? new IssuerClaimProvider({ config: this.config }) : undefined);
  }

  private getIssuerCredentialResolver(): IssuerCredentialResolver | undefined {
    if (this.adapters.issuerCredentialResolver) {
      return this.adapters.issuerCredentialResolver;
    }
    const provider = this.getIden3commClaimProvider() as unknown as Partial<IssuerCredentialResolver> | undefined;
    return typeof provider?.resolveCredentialWithProof === "function"
      ? provider as IssuerCredentialResolver
      : undefined;
  }

  private getIssuerCredentialResolverForDebug(steps: IssuerClaimDebugStep[]): IssuerCredentialResolver | undefined {
    if (this.adapters.issuerCredentialResolver) {
      return this.adapters.issuerCredentialResolver;
    }
    if (this.config.issuer) {
      return new IssuerClaimProvider({
        config: this.config,
        onDebug: (step) => steps.push(step)
      });
    }
    return this.getIssuerCredentialResolver();
  }

  private getIssuerCredentialProvider(debugSteps?: IssuerClaimDebugStep[]): IssuerCredentialProvider {
    const claimProvider = debugSteps && !this.adapters.iden3commClaimProvider && this.config.issuer
      ? new IssuerClaimProvider({
          config: this.config,
          onDebug: (step) => debugSteps.push(step)
        })
      : this.getIden3commClaimProvider();
    if (!claimProvider) {
      throw new Error("Issuer claim provider is required to create credential offer.");
    }
    const provider = claimProvider as unknown as IssuerCredentialProvider;
    if (typeof provider.createCredentialOffer !== "function") {
      throw new Error("Issuer claim provider is required to create credential offer.");
    }
    return provider;
  }

  private async prepareAuthV2Witness(input: ClaimCredentialInput) {
    const witnessCalculator = this.adapters.authV2WitnessCalculator;
    if (!witnessCalculator) {
      throw new Error("Mobile witness calculator is required to generate AuthV2 witness.");
    }
    const artifacts = this.circuitArtifactStore.resolve(CircuitId.AuthV2);
    const graphPath = artifacts?.graph?.localPath ?? artifacts?.graphPath;
    if (!graphPath) {
      throw new Error("AuthV2 circuit artifacts are incomplete: missing graph.");
    }
    const provider = this.createDefaultMobileAuthV2Provider();
    const context = await this.createClaimCredentialRuntimeContext(input);
    const { inputs } = await provider.buildAuthV2NativeWitnessInputs(context);
    const graphInfo = await inspectWitnessGraph(witnessCalculator, graphPath);
    const result = await witnessCalculator.calculateWitness({
      circuitId: CircuitId.AuthV2,
      graphPath,
      inputs
    });
    return {
      result,
      summary: {
        graphSource: graphInfo?.graphSource,
        graphExtension: graphInfo?.graphExtension,
        graphExists: graphInfo?.graphExists ?? false,
        graphSizeBytes: graphInfo?.graphSizeBytes,
        inputsKeysCount: Object.keys(inputs).length,
        authClaimIncMtpSiblings: inputs.authClaimIncMtp.length,
        authClaimNonRevMtpSiblings: inputs.authClaimNonRevMtp.length,
        gistMtpSiblings: inputs.gistMtp.length,
        witnessGenerated: true,
        witnessEncoding: typeof result.witness === "string" ? "base64" : undefined,
        witnessSizeBytes: typeof result.witness === "string" ? decodedBase64Size(result.witness) : undefined
      } satisfies AuthV2WitnessOnlyResult
    };
  }

  private async createClaimCredentialRuntimeContext(input: ClaimCredentialInput): Promise<ClaimCredentialRuntimeContext> {
    const messageInput = input.message ?? input.offer;
    if (!messageInput) {
      throw new Error("Credential offer message is required.");
    }
    const parsed = parseCredentialOffer(messageInput);
    const holderDid = await this.identityStorage.getHolderDid();
    if (!holderDid) {
      throw new Error("A real Holder DID must be created before claiming a credential from offer.");
    }
    if (holderDid.developmentOnly) {
      throw new Error("A real Holder DID is required to claim a credential from offer.");
    }
    if (input.holderDid && input.holderDid !== holderDid.did) {
      throw new Error("Requested holderDid does not match the active local Holder DID.");
    }
    if (!holderDid.keyId) {
      throw new Error("Active Holder DID is missing its KMS key reference.");
    }
    return {
      input,
      message: parsed.message,
      holderDid,
      keyId: holderDid.keyId,
      profileNonce: "0"
    };
  }
}

async function inspectWitnessGraph(
  witnessCalculator: NonNullable<PrivadoExpoClientAdapters["authV2WitnessCalculator"]>,
  graphPath: string
): Promise<{ graphSource?: string; graphExtension?: string; graphExists: boolean; graphSizeBytes?: number } | undefined> {
  const inspectable = witnessCalculator as typeof witnessCalculator & {
    inspectGraph?: (graphPath: string) => Promise<{
      graphSource?: string;
      graphExtension?: string;
      graphExists: boolean;
      graphSizeBytes?: number;
    }>;
  };
  return inspectable.inspectGraph?.(graphPath);
}

async function inspectProverFile(
  prover: NonNullable<PrivadoExpoClientAdapters["authV2NativeProver"]>,
  zkeyPath: string
): Promise<{ exists: boolean; sizeBytes?: number } | undefined> {
  const inspectable = prover as typeof prover & {
    inspectZkey?: (zkeyPath: string) => Promise<{ exists: boolean; sizeBytes?: number } | undefined>;
  };
  return inspectable.inspectZkey?.(zkeyPath);
}

function tryPrepareUniversalVerifierCalldata(
  proof: GeneratedProof,
  requestId: string
): { calldata?: unknown; error?: string } {
  try {
    return { calldata: prepareUniversalVerifierCalldata(proof, requestId) };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function decodedBase64Size(value: string): number {
  const normalized = value.replace(/\s/g, "");
  if (!normalized) {
    return 0;
  }
  const padding = normalized.endsWith("==") ? 2 : normalized.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - padding);
}

function assertCredentialSupportsCredentialAtomicQueryV2(credential: unknown, circuitId: CircuitId): void {
  const proofTypes = extractCredentialProofTypes(credential);
  if (circuitId === CircuitId.CredentialAtomicQueryMTPV2 || circuitId === CircuitId.CredentialAtomicQueryMTPV2OnChain) {
    if (!proofTypes.includes("Iden3SparseMerkleTreeProof")) {
      throw new Error("credentialAtomicQueryMTPV2 requires an Iden3SparseMerkleTreeProof credential proof.");
    }
    return;
  }
  if (!proofTypes.includes("BJJSignature2021")) {
    throw new Error("credentialAtomicQuerySigV2 requires a BJJSignature2021 credential proof.");
  }
}

function assertMtpFlowNotRoutedToSigV2(credentialCircuitId: CircuitId, credential: unknown): void {
  const isMtpCircuit =
    credentialCircuitId === CircuitId.CredentialAtomicQueryMTPV2 ||
    credentialCircuitId === CircuitId.CredentialAtomicQueryMTPV2OnChain;
  if (!isMtpCircuit) {
    return;
  }
  if (credentialCircuitId !== CircuitId.CredentialAtomicQueryMTPV2 && credentialCircuitId !== CircuitId.CredentialAtomicQueryMTPV2OnChain) {
    throw new Error("MTP flow routed to SigV2 by mistake");
  }
  const proofTypes = extractCredentialProofTypes(credential);
  if (!proofTypes.includes("Iden3SparseMerkleTreeProof")) {
    throw new Error("MTP flow routed to SigV2 by mistake: selected credential does not contain Iden3SparseMerkleTreeProof.");
  }
  if (proofTypes.includes("BJJSignature2021") && !proofTypes.includes("Iden3SparseMerkleTreeProof")) {
    throw new Error("MTP flow routed to SigV2 by mistake");
  }
}

function rewriteMtpRoutingError(error: unknown, circuitId: CircuitId): Error {
  const isMtpCircuit =
    circuitId === CircuitId.CredentialAtomicQueryMTPV2 ||
    circuitId === CircuitId.CredentialAtomicQueryMTPV2OnChain;
  if (!isMtpCircuit) {
    return error instanceof Error ? error : new Error(String(error));
  }
  const raw = error instanceof Error ? error.message : String(error);
  if (raw.includes("BJJSignature2021") || raw.includes("getBjjSignatureProof")) {
    return new Error(`MTP flow routed to SigV2 by mistake: ${raw}`);
  }
  return new Error(raw.replace(/credentialAtomicQuerySigV2OnChain/g, String(circuitId)).replace(/credentialAtomicQuerySigV2/g, String(circuitId)));
}

function extractCredentialProofTypes(credential: unknown): string[] {
  if (!credential || typeof credential !== "object") {
    return [];
  }
  const proof = (credential as { proof?: unknown }).proof;
  const proofs = Array.isArray(proof) ? proof : proof ? [proof] : [];
  const types: string[] = [];
  for (const item of proofs) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const type = (item as { type?: unknown }).type;
    if (typeof type === "string") {
      types.push(type);
    } else if (Array.isArray(type)) {
      types.push(...type.filter((entry): entry is string => typeof entry === "string"));
    }
  }
  return types;
}

async function hydrateIssuerCredentialsForMtp(
  credentials: unknown[],
  options: {
    resolver?: IssuerCredentialResolver;
    holderDid: string;
    issuerDid?: string;
    credentialId?: string;
    credentialType?: string;
    credentialSchema?: string;
    steps?: IssuerClaimDebugStep[];
  }
): Promise<unknown[]> {
  const output: unknown[] = [];
  for (const credential of credentials) {
    const claimedProofTypes = extractCredentialProofTypes(credential);
    if (claimedProofTypes.includes("Iden3SparseMerkleTreeProof")) {
      options.steps?.push({
        step: "hydrate",
        status: "skipped",
        hydration: {
          credentialId: options.credentialId,
          claimedCredentialId: extractCredentialId(credential),
          claimedProofTypes,
          hydrated: false,
          hydratedProofTypes: claimedProofTypes,
          credentialSubjectId: extractCredentialSubjectId(credential),
          issuer: extractCredentialIssuer(credential) ?? options.issuerDid,
          schema: extractCredentialSchema(credential) ?? options.credentialSchema,
          selectedProofType: "Iden3SparseMerkleTreeProof"
        },
        responsePreview: "claimed credential already contains Iden3SparseMerkleTreeProof"
      });
      output.push(credential);
      continue;
    }
    if (!options.resolver) {
      throw new Error(formatMissingMtpProofError(claimedProofTypes));
    }
    let result;
    try {
      result = await options.resolver.resolveCredentialWithProof({
        issuerDid: extractCredentialIssuer(credential) ?? options.issuerDid,
        credentialId: options.credentialId ?? extractCredentialId(credential),
        holderDid: options.holderDid,
        credentialType: extractCredentialType(credential) ?? options.credentialType,
        credentialSchema: extractCredentialSchema(credential) ?? options.credentialSchema,
        requiredProofType: "Iden3SparseMerkleTreeProof",
        claimedCredential: credential
      });
    } catch (error) {
      pushStepError(options.steps ?? [], "hydrate", error);
      throw error;
    }
    const hydratedProofTypes = result.credential ? extractCredentialProofTypes(result.credential) : result.proofTypes;
    options.steps?.push({
      step: "hydrate",
      status: result.credential && hydratedProofTypes.includes("Iden3SparseMerkleTreeProof") ? "ok" : "skipped",
      hydration: {
        credentialId: options.credentialId,
        claimedCredentialId: extractCredentialId(credential),
        claimedProofTypes,
        hydrated: Boolean(result.credential),
        hydratedCredentialId: result.credential ? extractCredentialId(result.credential) : result.credentialId,
        hydratedProofTypes,
        credentialSubjectId: extractCredentialSubjectId(result.credential) ?? extractCredentialSubjectId(credential),
        issuer: extractCredentialIssuer(result.credential) ?? extractCredentialIssuer(credential) ?? options.issuerDid,
        schema: extractCredentialSchema(result.credential) ?? extractCredentialSchema(credential) ?? options.credentialSchema,
        selectedProofType: hydratedProofTypes.includes("Iden3SparseMerkleTreeProof") ? "Iden3SparseMerkleTreeProof" : undefined
      },
      responsePreview: hydratedProofTypes.includes("Iden3SparseMerkleTreeProof")
        ? "hydrated credential contains Iden3SparseMerkleTreeProof"
        : "hydration did not return Iden3SparseMerkleTreeProof"
    });
    if (!result.credential || !hydratedProofTypes.includes("Iden3SparseMerkleTreeProof")) {
      output.push(withMtpMetadata(credential, {
        issuerCredentialId: options.credentialId ?? extractCredentialId(credential),
        mtpReady: false,
        mtpStatus: "pending-mtp-hydration"
      }));
      continue;
    }
    output.push(withMtpMetadata(result.credential, {
      issuerCredentialId: options.credentialId ?? result.credentialId ?? extractCredentialId(result.credential),
      mtpReady: true,
      mtpStatus: "mtp-ready"
    }));
  }
  return output;
}

function formatMissingMtpProofError(proofTypes: string[]): string {
  return `No MTP proof in saved credential. Claim/hydration did not return a VC with Iden3SparseMerkleTreeProof. proofTypes: ${
    proofTypes.length > 0 ? proofTypes.join(", ") : "none"
  }`;
}

function extractCredentialType(credential: unknown): string | undefined {
  if (!isRecord(credential)) {
    return undefined;
  }
  const types = Array.isArray(credential.type) ? credential.type : [credential.type];
  return [...types].reverse().find((type): type is string => typeof type === "string" && type !== "VerifiableCredential");
}

function extractCredentialSchema(credential: unknown): string | undefined {
  if (!isRecord(credential)) {
    return undefined;
  }
  if (typeof credential.credentialSchema === "string") {
    return credential.credentialSchema;
  }
  return isRecord(credential.credentialSchema) && typeof credential.credentialSchema.id === "string"
    ? credential.credentialSchema.id
    : undefined;
}

function extractCredentialIssuer(credential: unknown): string | undefined {
  if (!isRecord(credential)) {
    return undefined;
  }
  if (typeof credential.issuer === "string") {
    return credential.issuer;
  }
  return isRecord(credential.issuer) && typeof credential.issuer.id === "string" ? credential.issuer.id : undefined;
}

function extractCredentialSubjectId(credential: unknown): string | undefined {
  const subject = isRecord(credential) ? credential.credentialSubject : undefined;
  const record = Array.isArray(subject) ? subject.find(isRecord) : subject;
  return isRecord(record) && typeof record.id === "string" ? record.id : undefined;
}

function extractIssuerCredentialIdFromMetadata(credential: unknown): string | undefined {
  const metadata = isRecord(credential) && isRecord(credential.privadoId) ? credential.privadoId : undefined;
  return typeof metadata?.issuerCredentialId === "string" && metadata.issuerCredentialId.length > 0
    ? metadata.issuerCredentialId
    : undefined;
}

function selectLatestPendingMtpSummary(summaries: ImportedCredentialSummary[]): ImportedCredentialSummary | undefined {
  const pending = summaries.filter((summary) =>
    !summary.proofTypes.includes("Iden3SparseMerkleTreeProof") &&
    (summary.issuerCredentialId || summary.mtpStatus === "pending-mtp-hydration" || summary.mtpStatus === "claimed-bjj-only")
  );
  return selectNewestSummary(pending.length > 0 ? pending : summaries);
}

function selectNewestSummary(summaries: ImportedCredentialSummary[]): ImportedCredentialSummary | undefined {
  return [...summaries].sort((left, right) => {
    const rightTime = Date.parse(right.updatedAt ?? right.createdAt ?? "");
    const leftTime = Date.parse(left.updatedAt ?? left.createdAt ?? "");
    return (Number.isNaN(rightTime) ? 0 : rightTime) - (Number.isNaN(leftTime) ? 0 : leftTime);
  })[0];
}

function firstCredentialType(summary: ImportedCredentialSummary | undefined): string | undefined {
  return summary?.type.find((type) => type !== "VerifiableCredential");
}

function withMtpMetadata(
  credential: unknown,
  metadata: {
    issuerCredentialId?: string;
    mtpReady: boolean;
    mtpStatus: ImportedCredentialSummary["mtpStatus"];
  }
): unknown {
  if (!isRecord(credential)) {
    return credential;
  }
  const previous = isRecord(credential.privadoId) ? credential.privadoId : {};
  return {
    ...credential,
    privadoId: {
      ...previous,
      issuerCredentialId: metadata.issuerCredentialId,
      mtpReady: metadata.mtpReady,
      mtpStatus: metadata.mtpStatus
    }
  };
}

interface IssuerCredentialProvider {
  createCredentialOffer(input: CreateIssuerCredentialInput): Promise<{ offer: string; raw: unknown }>;
  claimCredentialFromOffer(input: ClaimCredentialRuntimeContext): Promise<unknown>;
  prepareClaimRequests?(input: ClaimCredentialRuntimeContext): Promise<PreparedIssuerClaimRequest[]>;
  claimPreparedCredentialRequests?(prepared: PreparedIssuerClaimRequest[], authProof: unknown): Promise<unknown>;
}

function pushStepError(
  steps: IssuerClaimDebugStep[],
  step: IssuerClaimDebugStep["step"],
  error: unknown,
  status: "error" | "skipped" = "error",
  claimLocalStep?: IssuerClaimDebugStep["claimLocalStep"],
  postExecuted?: boolean
): void {
  steps.push({
    step,
    status,
    claimLocalStep,
    postExecuted,
    error: errorMessage(error)
  });
}

function errorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.length <= 300 ? message : `${message.slice(0, 300)}...`;
}

function extractCredentials(result: unknown): unknown[] {
  if (Array.isArray(result)) {
    return result;
  }
  if (!isRecord(result)) {
    return [];
  }
  const candidates = [
    result.credential,
    result.vc,
    result.verifiableCredential,
    result.credentials,
    result.vcs,
    result.verifiableCredentials
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      return candidate;
    }
    if (isRecord(candidate)) {
      return [candidate];
    }
  }
  return isCredentialLike(result) ? [result] : [];
}

function isCredentialLike(value: Record<string, unknown>): boolean {
  return typeof value.id === "string" && Boolean(value.credentialSubject);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDecimalFieldElement(value: string): boolean {
  if (!/^[0-9]+$/.test(value)) {
    return false;
  }
  return BigInt(value) < BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
}
