import type { CredentialStorageAdapter } from "../types";

export async function getCredentialById(id: string, storage: CredentialStorageAdapter): Promise<unknown | undefined> {
  return storage.getCredentialById(id);
}
