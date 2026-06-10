import type { DeleteHolderIdentityResult, IdentityStorageAdapter, KMSAdapter } from "../types";

export async function deleteHolderIdentity(
  identityStorage: IdentityStorageAdapter,
  kmsAdapter?: KMSAdapter
): Promise<DeleteHolderIdentityResult> {
  const existing = await identityStorage.getHolderDid();
  const result = await identityStorage.deleteHolderIdentity();

  if (existing?.keyId && kmsAdapter?.deleteKey) {
    await kmsAdapter.deleteKey(existing.keyId);
  }

  return result;
}
