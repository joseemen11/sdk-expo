import type { ImportedCredentialSummary } from "../types";

export function buildCredentialSummary(credential: unknown): ImportedCredentialSummary {
  if (!isRecord(credential)) {
    throw new Error("Credential must be a JSON object.");
  }

  const id = stringValue(credential.id) ?? stringValue(credential["credentialId"]);
  if (!id) {
    throw new Error("Credential id is required.");
  }

  const type = normalizeTypes(credential.type);
  const issuer = extractIssuer(credential.issuer);
  const subject = isRecord(credential.credentialSubject) ? credential.credentialSubject : undefined;
  const proofTypes = extractProofTypes(credential.proof);
  const metadata = isRecord(credential.privadoId) ? credential.privadoId : undefined;

  return {
    id,
    type,
    issuer,
    credentialSubjectId: subject ? stringValue(subject.id) : undefined,
    expirationDate: stringValue(credential.expirationDate),
    proofTypes,
    issuerCredentialId: stringValue(metadata?.issuerCredentialId),
    mtpReady: typeof metadata?.mtpReady === "boolean" ? metadata.mtpReady : proofTypes.includes("Iden3SparseMerkleTreeProof"),
    mtpStatus: mtpStatusValue(metadata?.mtpStatus, proofTypes)
  };
}

export function safeCredentialDiagnostics(credential: unknown): ImportedCredentialSummary {
  return buildCredentialSummary(credential);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeTypes(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string");
  }
  return typeof value === "string" ? [value] : [];
}

function extractIssuer(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (isRecord(value)) {
    return stringValue(value.id);
  }
  return undefined;
}

function extractProofTypes(value: unknown): string[] {
  const proofs = Array.isArray(value) ? value : value ? [value] : [];
  return proofs
    .filter(isRecord)
    .map((proof) => stringValue(proof.type))
    .filter((type): type is string => Boolean(type));
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function mtpStatusValue(value: unknown, proofTypes: string[]): ImportedCredentialSummary["mtpStatus"] {
  if (
    value === "claimed-bjj-only" ||
    value === "pending-mtp-hydration" ||
    value === "mtp-hydrated" ||
    value === "mtp-ready"
  ) {
    return value;
  }
  return proofTypes.includes("Iden3SparseMerkleTreeProof") ? "mtp-ready" : undefined;
}
