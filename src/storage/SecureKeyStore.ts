import type { SecureKeyStore } from "../types";
import { createEncryptionKey } from "./createEncryptionKey";

export type { SecureKeyStore } from "../types";

export class DevelopmentSecureKeyStore implements SecureKeyStore {
  private readonly keys = new Map<string, Uint8Array>();

  async getOrCreateKey(alias: string): Promise<Uint8Array> {
    const existing = this.keys.get(alias);
    if (existing) {
      return existing;
    }

    const key = createEncryptionKey({ allowDevelopmentFallback: true });
    this.keys.set(alias, key);
    return key;
  }

  async deleteKey(alias: string): Promise<void> {
    this.keys.delete(alias);
  }
}
