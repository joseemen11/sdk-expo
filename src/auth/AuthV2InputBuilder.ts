import { CircuitId } from "../circuits/CircuitId";
import type { ClaimCredentialRuntimeContext, ProofRequest } from "../types";

export interface AuthV2InputBuilderContext {
  runtime: ClaimCredentialRuntimeContext;
  request: ProofRequest;
}

export interface AuthV2AuthClaimProof {
  authClaim: unknown;
  authClaimIncMtp: unknown;
  authClaimNonRevMtp: unknown;
}

export interface AuthV2TreeState {
  claimsTreeRoot: unknown;
  revTreeRoot: unknown;
  rootsTreeRoot: unknown;
  state: unknown;
}

export interface AuthV2GistProof {
  gistRoot: unknown;
  gistMtp: unknown;
  gistMtpAuxHi?: unknown;
  gistMtpAuxHv?: unknown;
  gistMtpNoAux?: unknown;
}

export interface AuthV2ChallengeSignature {
  challengeSignature: unknown;
}

export interface AuthV2IdentityProofSource {
  getAuthClaimProof(input: AuthV2InputBuilderContext): Promise<AuthV2AuthClaimProof | undefined>;
  getTreeState(input: AuthV2InputBuilderContext): Promise<AuthV2TreeState | undefined>;
  getGistProof(input: AuthV2InputBuilderContext): Promise<AuthV2GistProof | undefined>;
}

export interface AuthV2ChallengeSigner {
  signAuthV2Challenge(input: AuthV2InputBuilderContext): Promise<AuthV2ChallengeSignature | undefined>;
}

export interface AuthV2InputBuilderOptions {
  identityProofSource?: AuthV2IdentityProofSource;
  challengeSigner?: AuthV2ChallengeSigner;
}

export interface AuthV2WitnessInputs extends Record<string, unknown> {
  circuitId: CircuitId.AuthV2;
  genesisID: string;
  profileNonce: string;
  challenge: string;
  requestId?: string;
  authClaim: unknown;
  authClaimIncMtp: unknown;
  authClaimNonRevMtp: unknown;
  claimsTreeRoot: unknown;
  revTreeRoot: unknown;
  rootsTreeRoot: unknown;
  state: unknown;
  gistRoot: unknown;
  gistMtp: unknown;
  gistMtpAuxHi?: unknown;
  gistMtpAuxHv?: unknown;
  gistMtpNoAux?: unknown;
  challengeSignature: unknown;
}

export const authV2RequiredWitnessFields = [
  "genesisID",
  "profileNonce",
  "challenge",
  "authClaim",
  "authClaimIncMtp",
  "authClaimNonRevMtp",
  "claimsTreeRoot",
  "revTreeRoot",
  "rootsTreeRoot",
  "state",
  "gistRoot",
  "gistMtp",
  "challengeSignature"
] as const;

export class AuthV2InputBuilder {
  private readonly identityProofSource?: AuthV2IdentityProofSource;
  private readonly challengeSigner?: AuthV2ChallengeSigner;

  constructor(options: AuthV2InputBuilderOptions = {}) {
    this.identityProofSource = options.identityProofSource;
    this.challengeSigner = options.challengeSigner;
  }

  async build(input: AuthV2InputBuilderContext): Promise<AuthV2WitnessInputs> {
    const challenge = stringValue(input.request.challenge);
    if (!challenge) {
      throw new Error("AuthV2 challenge is missing.");
    }

    const authClaimProof = await this.identityProofSource?.getAuthClaimProof(input);
    if (!authClaimProof) {
      throw new Error("AuthV2 auth claim proof is missing.");
    }
    requireValue(authClaimProof.authClaim, "authClaim", "AuthV2 auth claim proof is missing.");
    requireValue(authClaimProof.authClaimIncMtp, "authClaimIncMtp", "AuthV2 auth claim inclusion proof is missing.");
    requireValue(authClaimProof.authClaimNonRevMtp, "authClaimNonRevMtp", "AuthV2 auth claim non-revocation proof is missing.");

    const treeState = await this.identityProofSource?.getTreeState(input);
    if (!treeState) {
      throw new Error("AuthV2 state proof is missing.");
    }
    requireValue(treeState.claimsTreeRoot, "claimsTreeRoot", "AuthV2 state proof is missing.");
    requireValue(treeState.revTreeRoot, "revTreeRoot", "AuthV2 state proof is missing.");
    requireValue(treeState.rootsTreeRoot, "rootsTreeRoot", "AuthV2 state proof is missing.");
    requireValue(treeState.state, "state", "AuthV2 state proof is missing.");

    const gistProof = await this.identityProofSource?.getGistProof(input);
    if (!gistProof) {
      throw new Error(`AuthV2 GIST proof is not available for network ${input.runtime.holderDid.network ?? "unknown"}.`);
    }
    requireValue(gistProof.gistRoot, "gistRoot", "AuthV2 GIST proof is missing.");
    requireValue(gistProof.gistMtp, "gistMtp", "AuthV2 GIST proof is missing.");

    const signature = await this.challengeSigner?.signAuthV2Challenge(input);
    if (!signature) {
      throw new Error("AuthV2 challenge signature is missing.");
    }
    requireValue(signature.challengeSignature, "challengeSignature", "AuthV2 challenge signature is missing.");

    const witnessInputs: AuthV2WitnessInputs = {
      circuitId: CircuitId.AuthV2,
      genesisID: input.runtime.holderDid.did,
      profileNonce: input.runtime.profileNonce,
      challenge,
      requestId: input.request.id,
      authClaim: authClaimProof.authClaim,
      authClaimIncMtp: authClaimProof.authClaimIncMtp,
      authClaimNonRevMtp: authClaimProof.authClaimNonRevMtp,
      claimsTreeRoot: treeState.claimsTreeRoot,
      revTreeRoot: treeState.revTreeRoot,
      rootsTreeRoot: treeState.rootsTreeRoot,
      state: treeState.state,
      gistRoot: gistProof.gistRoot,
      gistMtp: gistProof.gistMtp,
      gistMtpAuxHi: gistProof.gistMtpAuxHi,
      gistMtpAuxHv: gistProof.gistMtpAuxHv,
      gistMtpNoAux: gistProof.gistMtpNoAux,
      challengeSignature: signature.challengeSignature
    };

    validateAuthV2WitnessInputs(witnessInputs);
    return witnessInputs;
  }
}

export function validateAuthV2WitnessInputs(inputs: Record<string, unknown> | undefined): void {
  if (!inputs) {
    throw new Error("AuthV2 input builder is not implemented for field: authClaim");
  }
  for (const field of authV2RequiredWitnessFields) {
    const value = inputs[field];
    if (value === undefined || value === null || value === "") {
      throw new Error(`AuthV2 input builder is not implemented for field: ${field}`);
    }
  }
}

function requireValue(value: unknown, field: string, message: string): void {
  if (value === undefined || value === null || value === "") {
    throw new Error(message || `AuthV2 input builder is not implemented for field: ${field}`);
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
