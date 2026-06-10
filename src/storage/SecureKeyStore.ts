import type { SecureKeyStore } from "../types";
import { base64ToBytes, bytesToBase64 } from "../network/Base64UrlCodec";
import { createEncryptionKey } from "./createEncryptionKey";

export type { SecureKeyStore } from "../types";

export class DevelopmentSecureKeyStore implements SecureKeyStore {
  private readonly items = new Map<string, string>();

  async getItem(key: string): Promise<string | undefined> {
    return this.items.get(key);
  }

  async setItem(key: string, value: string): Promise<void> {
    this.items.set(key, value);
  }

  async deleteItem(key: string): Promise<void> {
    this.items.delete(key);
  }

  async getOrCreateEncryptionKey(alias: string): Promise<Uint8Array> {
    const existing = await this.getItem(alias);
    if (existing) {
      return decodeStoredEncryptionKey(existing);
    }

    const key = createEncryptionKey();
    await this.setItem(alias, encodeStoredEncryptionKey(key));
    return key;
  }

  async getOrCreateKey(alias: string): Promise<Uint8Array> {
    return this.getOrCreateEncryptionKey(alias);
  }

  async deleteKey(alias: string): Promise<void> {
    await this.deleteItem(alias);
  }
}

export interface SecureStoreLike {
  getItemAsync(key: string, options?: unknown): Promise<string | null>;
  setItemAsync(key: string, value: string, options?: unknown): Promise<void>;
  deleteItemAsync(key: string, options?: unknown): Promise<void>;
}

export interface ExpoSecureKeyStoreOptions {
  secureStore: SecureStoreLike;
  secureStoreOptions?: unknown;
  randomBytes?: (byteLength: number) => Uint8Array;
}

export class ExpoSecureKeyStore implements SecureKeyStore {
  private readonly secureStore: SecureStoreLike;
  private readonly secureStoreOptions?: unknown;
  private readonly randomBytes?: (byteLength: number) => Uint8Array;

  constructor(options: ExpoSecureKeyStoreOptions) {
    this.secureStore = options.secureStore;
    this.secureStoreOptions = options.secureStoreOptions;
    this.randomBytes = options.randomBytes;
  }

  async getItem(key: string): Promise<string | undefined> {
    return (await this.secureStore.getItemAsync(key, this.secureStoreOptions)) ?? undefined;
  }

  async setItem(key: string, value: string): Promise<void> {
    await this.secureStore.setItemAsync(key, value, this.secureStoreOptions);
  }

  async deleteItem(key: string): Promise<void> {
    await this.secureStore.deleteItemAsync(key, this.secureStoreOptions);
  }

  async getOrCreateEncryptionKey(alias: string): Promise<Uint8Array> {
    const existing = await this.getItem(alias);
    if (existing) {
      return decodeStoredEncryptionKey(existing);
    }

    const key = this.randomBytes ? this.randomBytes(32) : createEncryptionKey();
    if (key.byteLength !== 32) {
      throw new Error("Encryption key must be 32 bytes.");
    }
    await this.setItem(alias, encodeStoredEncryptionKey(key));
    return key;
  }

  async getOrCreateKey(alias: string): Promise<Uint8Array> {
    return this.getOrCreateEncryptionKey(alias);
  }

  async deleteKey(alias: string): Promise<void> {
    await this.deleteItem(alias);
  }
}

export function encodeStoredEncryptionKey(key: Uint8Array): string {
  if (key.byteLength !== 32) {
    throw new Error("Encryption key must be 32 bytes.");
  }
  return `v1:${bytesToBase64(key)}`;
}

export function decodeStoredEncryptionKey(value: string): Uint8Array {
  const encoded = value.startsWith("v1:") ? value.slice(3) : value;
  const key = base64ToBytes(encoded);
  if (key.byteLength !== 32) {
    throw new Error("Stored encryption key is invalid.");
  }
  return key;
}
