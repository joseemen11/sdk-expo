import type { HolderDidRecord, IdentityStorageAdapter, SecureKeyStore, StorageAdapter } from "../types";

export interface MobileIdentityStorageOptions {
  identityStorage?: IdentityStorageAdapter;
  secureKeyStore?: SecureKeyStore;
  recordStore?: StorageAdapter<string>;
  namespace?: string;
}

type MobileIdentity = {
  did: string;
  state?: unknown;
  isStatePublished?: boolean;
  isStateGenesis?: boolean;
};

export type MobileAuthV2IdentityMaterial = {
  did: string;
  keyId: string;
  authClaim: unknown;
  authClaimMarshal?: string[];
  authClaimHi: string;
  authClaimHv: string;
  authClaimRevocationNonce: string;
  claimsTreeRoot: string;
  revTreeRoot: string;
  rootsTreeRoot: string;
  state: string;
  isStateGenesis: boolean;
  createdAt: string;
  updatedAt: string;
};

type MobileProfile = {
  id: string;
  nonce: number | string;
  genesisIdentifier: string;
  verifier: string;
  tags?: string[];
  did_doc?: unknown;
  metadata?: unknown;
};

export class MobileIdentityStorage {
  private readonly identityStorage?: IdentityStorageAdapter;
  private readonly secureKeyStore?: SecureKeyStore;
  private readonly recordStore?: StorageAdapter<string>;
  private readonly namespace: string;

  constructor(options: MobileIdentityStorageOptions = {}) {
    this.identityStorage = options.identityStorage;
    this.secureKeyStore = options.secureKeyStore;
    this.recordStore = options.recordStore;
    this.namespace = options.namespace ?? "privado-id.mobile-identity";
  }

  async saveIdentity(identity: MobileIdentity): Promise<void> {
    if (!identity.did) {
      throw new Error("MobileIdentityStorage.saveIdentity requires did.");
    }
    await this.saveMapItem("identities", identity.did, identity);
  }

  async saveAuthV2IdentityMaterial(material: MobileAuthV2IdentityMaterial): Promise<void> {
    if (!material.did) {
      throw new Error("MobileIdentityStorage.saveAuthV2IdentityMaterial requires did.");
    }
    await this.saveMapItem("authV2", material.did, material);
  }

  async getAuthV2IdentityMaterial(did: string): Promise<MobileAuthV2IdentityMaterial | undefined> {
    return this.getMapItem<MobileAuthV2IdentityMaterial>("authV2", did);
  }

  async getIdentity(identifier: string): Promise<MobileIdentity | undefined> {
    return this.getMapItem<MobileIdentity>("identities", identifier);
  }

  async getAllIdentities(): Promise<MobileIdentity[]> {
    return Object.values(await this.readMap<MobileIdentity>("identities"));
  }

  async saveProfile(profile: MobileProfile): Promise<void> {
    if (!profile.id) {
      throw new Error("MobileIdentityStorage.saveProfile requires id.");
    }
    await this.saveMapItem("profiles", profile.id, profile);
  }

  async getProfileByVerifier(verifier: string): Promise<MobileProfile | undefined> {
    return (await this.getProfilesByVerifier(verifier))[0];
  }

  async getProfilesByVerifier(verifier: string, tags?: string[]): Promise<MobileProfile[]> {
    return Object.values(await this.readMap<MobileProfile>("profiles")).filter((profile) => {
      const verifierMatches = profile.verifier === verifier;
      const tagsMatch = !tags?.length || tags.every((tag) => profile.tags?.includes(tag));
      return verifierMatches && tagsMatch;
    });
  }

  async getProfileById(identifier: string): Promise<MobileProfile | undefined> {
    return this.getMapItem<MobileProfile>("profiles", identifier);
  }

  async getProfilesByGenesisIdentifier(genesisIdentifier: string): Promise<MobileProfile[]> {
    return Object.values(await this.readMap<MobileProfile>("profiles")).filter(
      (profile) => profile.genesisIdentifier === genesisIdentifier
    );
  }

  async saveHolderDid(record: HolderDidRecord): Promise<void> {
    if (!this.identityStorage) {
      throw new Error("MobileIdentityStorage requires IdentityStorageAdapter to save holder DID metadata.");
    }
    await this.identityStorage.saveHolderDid(record);
  }

  private async saveMapItem<T>(collection: string, id: string, value: T): Promise<void> {
    const map = await this.readMap<T>(collection);
    map[id] = value;
    await this.writeMap(collection, map);
  }

  private async getMapItem<T>(collection: string, id: string): Promise<T | undefined> {
    const map = await this.readMap<T>(collection);
    return map[id];
  }

  private async readMap<T>(collection: string): Promise<Record<string, T>> {
    const raw = await this.readValue(this.keyFor(collection));
    if (!raw) {
      return {};
    }
    try {
      const parsed = JSON.parse(raw) as unknown;
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? (parsed as Record<string, T>)
        : {};
    } catch {
      throw new Error(`MobileIdentityStorage ${collection} metadata is invalid.`);
    }
  }

  private async writeMap<T>(collection: string, value: Record<string, T>): Promise<void> {
    await this.writeValue(this.keyFor(collection), JSON.stringify(value));
  }

  private keyFor(collection: string): string {
    return `${this.namespace}.${collection}`;
  }

  private async readValue(key: string): Promise<string | undefined> {
    if (this.recordStore) {
      return this.recordStore.get(key);
    }
    if (this.secureKeyStore) {
      return this.secureKeyStore.getItem(key);
    }
    return undefined;
  }

  private async writeValue(key: string, value: string): Promise<void> {
    if (this.recordStore) {
      await this.recordStore.set(key, value);
      return;
    }
    if (this.secureKeyStore) {
      await this.secureKeyStore.setItem(key, value);
      return;
    }
    throw new Error("MobileIdentityStorage requires a mobile metadata store.");
  }
}
