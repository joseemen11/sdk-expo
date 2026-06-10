import type { HolderDidSummary, IdentityStorageAdapter } from "../types";

export async function getHolderDid(identityStorage: IdentityStorageAdapter): Promise<HolderDidSummary | undefined> {
  return identityStorage.getHolderDid();
}
