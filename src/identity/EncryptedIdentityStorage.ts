import type {
  DeleteHolderIdentityResult,
  HolderDidRecord,
  HolderDidSummary,
  IdentityStorageAdapter,
  SecureKeyStore
} from "../types";

export interface EncryptedIdentityStorageOptions {
  secureKeyStore: SecureKeyStore;
  recordAlias?: string;
}

export class EncryptedIdentityStorage implements IdentityStorageAdapter {
  private readonly secureKeyStore: SecureKeyStore;
  private readonly recordAlias: string;

  constructor(options: EncryptedIdentityStorageOptions) {
    this.secureKeyStore = options.secureKeyStore;
    this.recordAlias = options.recordAlias ?? "privado-id.holder.identity.v1";
  }

  async getHolderDid(): Promise<HolderDidSummary | undefined> {
    const value = await this.secureKeyStore.getItem(this.recordAlias);
    if (!value) {
      return undefined;
    }
    return toSummary(JSON.parse(value) as HolderDidRecord);
  }

  async saveHolderDid(record: HolderDidRecord): Promise<HolderDidSummary> {
    await this.secureKeyStore.setItem(this.recordAlias, JSON.stringify(record));
    return toSummary(record);
  }

  async deleteHolderIdentity(): Promise<DeleteHolderIdentityResult> {
    const existing = await this.getHolderDid();
    await this.secureKeyStore.deleteItem(this.recordAlias);
    return {
      deleted: Boolean(existing),
      did: existing?.did,
      keyId: existing?.keyId
    };
  }
}

function toSummary(record: HolderDidRecord): HolderDidSummary {
  return {
    did: record.did,
    keyId: record.keyId,
    method: record.method,
    network: record.network,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    developmentOnly: record.developmentOnly
  };
}
