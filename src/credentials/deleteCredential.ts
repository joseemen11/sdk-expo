import type { CredentialStorageAdapter } from "../types";

export async function deleteCredential(id: string, storage: CredentialStorageAdapter): Promise<void> {
  await storage.deleteCredential(id);
}
