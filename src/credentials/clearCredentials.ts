import type { CredentialStorageAdapter } from "../types";

export async function clearCredentials(storage: CredentialStorageAdapter): Promise<void> {
  await storage.clearCredentials();
}
