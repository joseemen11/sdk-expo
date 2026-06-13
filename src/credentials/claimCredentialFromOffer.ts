import { parseCredentialOffer } from "../issuer/offerParser";
import { assertValidCredentialForStorage } from "./credentialValidation";
import type {
  AuthV2Provider,
  ClaimCredentialInput,
  ClaimCredentialResult,
  ClaimCredentialRuntimeContext,
  CredentialStorageAdapter,
  Iden3commClaimProvider,
  IdentityStorageAdapter,
  ImportedCredentialSummary
} from "../types";

export interface ClaimCredentialFromOfferOptions {
  identityStorage: IdentityStorageAdapter;
  credentialStorage: CredentialStorageAdapter;
  authV2Provider?: AuthV2Provider;
  iden3commClaimProvider?: Iden3commClaimProvider;
}

export async function claimCredentialFromOffer(
  input: ClaimCredentialInput,
  options: ClaimCredentialFromOfferOptions
): Promise<ClaimCredentialResult> {
  const messageInput = input.message ?? input.offer;
  if (!messageInput) {
    throw new Error("Credential offer message is required.");
  }

  const parsed = parseCredentialOffer(messageInput);
  const holderDid = await resolveHolderDid(input, options.identityStorage);
  const baseContext: ClaimCredentialRuntimeContext = {
    input,
    message: parsed.message,
    holderDid,
    keyId: holderDid.keyId,
    profileNonce: "0"
  };

  if (!options.authV2Provider) {
    throw new Error(
      "AuthV2 provider is required to claim a credential from offer after resolving Holder DID and KMS key reference."
    );
  }

  const authProof = await createAuthProof(options.authV2Provider, baseContext);
  const context = {
    ...baseContext,
    authProof
  };

  if (!options.iden3commClaimProvider) {
    throw new Error(
      "Iden3comm claim provider is required to fetch credentials from offer after AuthV2 proof creation."
    );
  }

  const providerResult = await options.iden3commClaimProvider.claimCredentialFromOffer(context);
  const credentials = extractCredentials(providerResult);
  if (credentials.length === 0) {
    throw new Error("Iden3comm claim provider did not return any credentials.");
  }

  const summaries: ImportedCredentialSummary[] = [];
  for (const credential of credentials) {
    assertValidCredentialForStorage(credential);
    summaries.push(await options.credentialStorage.saveCredential(credential));
  }

  return {
    holderDid: holderDid.did,
    credentialIds: summaries.map((summary) => summary.id),
    credentials: summaries
  };
}

async function resolveHolderDid(
  input: ClaimCredentialInput,
  identityStorage: IdentityStorageAdapter
): Promise<NonNullable<Awaited<ReturnType<IdentityStorageAdapter["getHolderDid"]>>>> {
  const holderDid = await identityStorage.getHolderDid();
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
  return holderDid;
}

async function createAuthProof(
  authV2Provider: AuthV2Provider,
  context: ClaimCredentialRuntimeContext
): Promise<unknown> {
  return authV2Provider.createAuthProof(context);
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
