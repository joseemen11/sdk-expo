import type { CredentialStorageAdapter, IdentityStorageAdapter, SecureKeyStore, StorageAdapter } from "../types";
import { loadMobileSafePolygonIdIdentityKms } from "../privado-js-sdk-mobile/mobileSafeImports";
import { MobilePrivateKeyStore } from "../kms/MobilePrivateKeyStore";
import { MobileCredentialStorage } from "./MobileCredentialStorage";
import { MobileIdentityStorage } from "./MobileIdentityStorage";
import { MobileMerkleTreeStorage } from "./MobileMerkleTreeStorage";
import { MobileStateStorage } from "./MobileStateStorage";

export interface MobileIdentityWalletFactoryOptions {
  secureKeyStore?: SecureKeyStore;
  metadataStore?: StorageAdapter<string>;
  identityStorage?: IdentityStorageAdapter;
  credentialStorage?: CredentialStorageAdapter;
  merkleTreeStorage?: unknown;
  stateStorage?: unknown;
  kms?: unknown;
  randomBytes?: (byteLength: number) => Uint8Array;
  method?: string;
  network?: string;
  revocationStatusUrl?: string;
}

export class MobileIdentityWalletFactory {
  constructor(readonly options: MobileIdentityWalletFactoryOptions) {}

  async createIdentityWallet(): Promise<{
    identityWallet: unknown;
    kms: unknown;
    credentialWallet: unknown;
    dataStorage: unknown;
  }> {
    const imports = await this.loadImports();
    const privateKeyStore = this.createPrivateKeyStore();
    const kms = this.createKms(imports, privateKeyStore);
    const credentialStorage = new MobileCredentialStorage({
      credentialStorage: this.options.credentialStorage
    });
    const dataStorage = {
      credential: credentialStorage,
      identity: new MobileIdentityStorage({
        identityStorage: this.options.identityStorage,
        secureKeyStore: this.options.secureKeyStore,
        recordStore: this.options.metadataStore
      }),
      mt: this.options.merkleTreeStorage ?? new MobileMerkleTreeStorage({
        secureKeyStore: this.options.secureKeyStore,
        recordStore: this.options.metadataStore
      }),
      states: this.options.stateStorage ?? new MobileStateStorage()
    };
    const credentialWallet = this.construct(imports.CredentialWallet, [dataStorage], "CredentialWallet");
    const identityWallet = this.construct(imports.IdentityWallet, [kms, dataStorage, credentialWallet], "IdentityWallet");

    return {
      identityWallet,
      kms,
      credentialWallet,
      dataStorage
    };
  }

  async createIdentity(input: {
    method?: string;
    network?: string;
    seed?: Uint8Array;
  }): Promise<{
    did: string;
    credential: unknown;
    keyId?: string;
  }> {
    const { identityWallet } = await this.createIdentityWallet();
    const wallet = identityWallet as {
      createIdentity(options: Record<string, unknown>): Promise<{ did: unknown; credential: unknown; keyId?: unknown }>;
    };
    if (typeof wallet.createIdentity !== "function") {
      throw new Error("IdentityWallet.createIdentity is not available.");
    }

    const result = await wallet.createIdentity({
      method: input.method ?? this.options.method ?? "iden3",
      blockchain: blockchainForNetwork(input.network ?? this.options.network),
      networkId: input.network ?? this.options.network,
      revocationOpts: {
        id: this.options.revocationStatusUrl ?? "urn:privado-id:mobile-holder:revocation",
        type: "SparseMerkleTreeProof",
        genesisPublishingDisabled: true
      },
      seed: input.seed
    });

    return {
      did: formatDid(result.did),
      credential: result.credential,
      keyId: typeof result.keyId === "string" ? result.keyId : undefined
    };
  }

  private async loadImports() {
    try {
      return await loadMobileSafePolygonIdIdentityKms();
    } catch (error) {
      throw new Error(`MobileIdentityWalletFactory.createIdentityWallet failed at mobileSafeImports: ${formatDetailedError(error)}`);
    }
  }

  private createPrivateKeyStore(): MobilePrivateKeyStore {
    if (!this.options.secureKeyStore) {
      throw new Error("MobileIdentityWalletFactory requires SecureKeyStore for private key material.");
    }
    return new MobilePrivateKeyStore({
      secureKeyStore: this.options.secureKeyStore,
      randomBytes: this.options.randomBytes
    });
  }

  private createKms(
    imports: { KMS: unknown; BjjProvider: unknown; KmsKeyType?: { BabyJubJub?: unknown } },
    privateKeyStore: MobilePrivateKeyStore
  ): unknown {
    try {
      const kms = this.construct(imports.KMS, [], "KMS") as {
        registerKeyProvider?: (keyType: unknown, provider: unknown) => void;
      };
      const keyType = imports.KmsKeyType?.BabyJubJub ?? "BJJ";
      const provider = this.construct(imports.BjjProvider, [keyType, privateKeyStore], "BjjProvider");
      kms.registerKeyProvider?.(keyType, provider);
      return kms;
    } catch (error) {
      throw new Error(`MobileIdentityWalletFactory.createIdentityWallet failed at KMS/BJJ construction: ${formatDetailedError(error)}`);
    }
  }

  private construct(value: unknown, args: unknown[], label: string): unknown {
    if (typeof value !== "function") {
      throw new Error(`${label} constructor is not available.`);
    }
    return Reflect.construct(value, args);
  }
}

function formatDid(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value && typeof value === "object" && "string" in value && typeof value.string === "function") {
    return (value.string as () => string)();
  }
  return String(value);
}

function blockchainForNetwork(network?: string): string {
  if (!network) {
    return "polygon";
  }
  const normalized = network.toLowerCase();
  if (normalized === "polygon" || normalized === "ethereum") {
    return normalized;
  }
  return "polygon";
}

function formatDetailedError(error: unknown): string {
  if (!(error instanceof Error)) {
    return String(error);
  }

  const name = error.name || "Error";
  const message = error.message || "Unknown error";
  const rawCause = (error as { cause?: unknown }).cause;
  const cause = rawCause instanceof Error ? ` Cause: ${rawCause.message}` : "";
  const stack = typeof error.stack === "string" ? ` Stack: ${safeStack(error.stack)}` : "";
  return `${name}: ${message}${cause}${stack}`;
}

function safeStack(stack: string): string {
  return stack
    .split(/\r?\n/)
    .slice(0, 3)
    .map((line) => line.trim())
    .join(" | ");
}
