import type { CredentialStorageAdapter, ImportedCredentialSummary } from "../types";

export async function saveCredential(
  credential: unknown,
  storage: CredentialStorageAdapter
): Promise<ImportedCredentialSummary> {
  return storage.saveCredential(credential);
}
