import type { CredentialStorageAdapter, ImportedCredentialSummary } from "../types";

export async function getCredentials(storage: CredentialStorageAdapter): Promise<ImportedCredentialSummary[]> {
  return storage.getCredentials();
}
