export function assertValidCredentialForStorage(credential: unknown): void {
  if (!isRecord(credential)) {
    throw new Error("Issuer did not return a valid credential.");
  }
  if (!hasContext(credential["@context"])) {
    throw new Error("Issuer did not return a valid credential.");
  }
  if (!hasType(credential.type)) {
    throw new Error("Issuer did not return a valid credential.");
  }
  if (!hasIssuer(credential.issuer)) {
    throw new Error("Issuer did not return a valid credential.");
  }
  if (!isRecord(credential.credentialSubject)) {
    throw new Error("Issuer did not return a valid credential.");
  }
  const id = typeof credential.id === "string" && credential.id.length > 0 ? credential.id : undefined;
  const credentialId =
    typeof credential.credentialId === "string" && credential.credentialId.length > 0
      ? credential.credentialId
      : undefined;
  if (!id && !credentialId) {
    throw new Error("Issuer did not return a valid credential.");
  }
}

function hasContext(value: unknown): boolean {
  if (typeof value === "string") {
    return value.length > 0;
  }
  return Array.isArray(value) && value.some((item) => typeof item === "string" && item.length > 0);
}

function hasType(value: unknown): boolean {
  if (typeof value === "string") {
    return value.length > 0;
  }
  return Array.isArray(value) && value.some((item) => typeof item === "string" && item.length > 0);
}

function hasIssuer(value: unknown): boolean {
  if (typeof value === "string") {
    return value.length > 0;
  }
  return isRecord(value) && typeof value.id === "string" && value.id.length > 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
