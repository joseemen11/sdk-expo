import type {
  CreateOrLoadHolderDidInput,
  CreateOrLoadHolderDidResult,
  HolderDidProvider,
  IdentityStorageAdapter,
  KMSAdapter
} from "../types";

export async function createOrLoadHolderDid(input: {
  request?: CreateOrLoadHolderDidInput;
  identityStorage: IdentityStorageAdapter;
  kmsAdapter?: KMSAdapter;
  holderDidProvider?: HolderDidProvider;
  realHolderDidProvider?: HolderDidProvider;
  developmentHolderDidProvider?: HolderDidProvider;
}): Promise<CreateOrLoadHolderDidResult> {
  const mode = input.request?.mode ?? "real";
  const existing = await input.identityStorage.getHolderDid();
  if (existing && (mode === "development" || existing.developmentOnly !== true)) {
    return {
      ...existing,
      isNew: false
    };
  }

  const holderDidProvider =
    mode === "development"
      ? input.developmentHolderDidProvider
      : input.realHolderDidProvider ?? input.holderDidProvider;

  if (mode === "real" && !holderDidProvider) {
    throw new Error("Real Privado ID holder creation is not configured.");
  }

  if (mode === "development" && !holderDidProvider) {
    throw new Error("Development holder DID provider is required to create a development holder DID.");
  }

  if (!holderDidProvider) {
    throw new Error("Holder DID provider is required to create a holder DID.");
  }

  const method = input.request?.method;
  const network = input.request?.network;
  if (mode === "real" && holderDidProvider.createHolderIdentity) {
    const holder = await holderDidProvider.createHolderIdentity({
      keyId: input.request?.keyId,
      method,
      network
    });
    const now = new Date().toISOString();
    const summary = await input.identityStorage.saveHolderDid({
      did: holder.did,
      keyId: holder.keyId,
      method: holder.method ?? method,
      network: holder.network ?? network,
      createdAt: now,
      updatedAt: now,
      developmentOnly: false
    });

    return {
      ...summary,
      isNew: true
    };
  }

  if (!input.kmsAdapter?.createOrLoadKey) {
    throw new Error("KMS adapter with createOrLoadKey is required to create a holder DID.");
  }

  const key = await input.kmsAdapter.createOrLoadKey({
    keyId: input.request?.keyId,
    algorithm: mode === "development" ? "development-hmac-sha256" : "BJJ"
  });
  const did = await holderDidProvider.createDid({
    keyId: key.keyId,
    method,
    network
  });
  const now = new Date().toISOString();
  const summary = await input.identityStorage.saveHolderDid({
    did: did.did,
    keyId: key.keyId,
    method: did.method ?? method,
    network: did.network ?? network,
    createdAt: now,
    updatedAt: now,
    developmentOnly: did.developmentOnly ?? key.developmentOnly
  });

  return {
    ...summary,
    isNew: true
  };
}
