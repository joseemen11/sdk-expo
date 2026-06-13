import { base64ToBytes, bytesToBase64, textToBytes } from "../network/Base64UrlCodec";
import { createEncryptionKey } from "../storage/createEncryptionKey";
import type { PrivateKeyStoreAdapter, SecureKeyStore } from "../types";

export interface MobilePrivateKeyStoreOptions {
  secureKeyStore: SecureKeyStore;
  namespace?: string;
  randomBytes?: (byteLength: number) => Uint8Array;
}

export class MobilePrivateKeyStore implements PrivateKeyStoreAdapter {
  private readonly secureKeyStore: SecureKeyStore;
  private readonly namespace: string;
  private readonly randomBytes?: (byteLength: number) => Uint8Array;

  constructor(options: MobilePrivateKeyStoreOptions) {
    this.secureKeyStore = options.secureKeyStore;
    this.namespace = options.namespace ?? "privado-id.mobile-kms";
    this.randomBytes = options.randomBytes;
  }

  async ensureKey(keyId: string): Promise<{ keyId: string; created: boolean }> {
    const existing = await this.secureKeyStore.getItem(this.aliasFor(keyId));
    if (existing) {
      return { keyId, created: false };
    }

    const key = this.randomBytes ? this.randomBytes(32) : createEncryptionKey();
    if (key.byteLength !== 32) {
      throw new Error("Private key material must be 32 bytes.");
    }
    await this.secureKeyStore.setItem(this.aliasFor(keyId), `v1:${bytesToBase64(key)}`);
    await this.addAlias(keyId);
    return { keyId, created: true };
  }

  async importKey(args: { alias: string; key: string }): Promise<void> {
    if (!args.alias || !args.key) {
      throw new Error("MobilePrivateKeyStore import requires alias and key.");
    }
    await this.secureKeyStore.setItem(this.aliasFor(args.alias), `v1:${args.key}`);
    await this.addAlias(args.alias);
  }

  async get(args: { alias: string }): Promise<string> {
    const value = await this.secureKeyStore.getItem(this.aliasFor(args.alias));
    if (!value) {
      throw new Error("KMS key material is not available.");
    }
    return value.startsWith("v1:") ? value.slice(3) : value;
  }

  async list(): Promise<{ alias: string; key: string }[]> {
    const aliases = await this.getAliases();
    const keys: { alias: string; key: string }[] = [];
    for (const alias of aliases) {
      const value = await this.secureKeyStore.getItem(this.aliasFor(alias));
      if (value) {
        keys.push({
          alias,
          key: value.startsWith("v1:") ? value.slice(3) : value
        });
      }
    }
    return keys;
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.secureKeyStore.deleteItem(this.aliasFor(keyId));
    await this.removeAlias(keyId);
  }

  async signDevelopmentChallenge(input: { keyId: string; challenge: string | Uint8Array }): Promise<Uint8Array> {
    const key = await this.readKeyMaterial(input.keyId);
    const challengeBytes = typeof input.challenge === "string" ? textToBytes(input.challenge) : input.challenge;
    const { hmac } = await import("@noble/hashes/hmac.js");
    const { sha256 } = await import("@noble/hashes/sha2.js");
    return hmac(sha256, key, challengeBytes);
  }

  private async addAlias(alias: string): Promise<void> {
    const aliases = await this.getAliases();
    if (!aliases.includes(alias)) {
      aliases.push(alias);
      await this.secureKeyStore.setItem(this.indexKey(), JSON.stringify(aliases));
    }
  }

  private async removeAlias(alias: string): Promise<void> {
    const aliases = (await this.getAliases()).filter((item) => item !== alias);
    await this.secureKeyStore.setItem(this.indexKey(), JSON.stringify(aliases));
  }

  private async getAliases(): Promise<string[]> {
    const raw = await this.secureKeyStore.getItem(this.indexKey());
    if (!raw) {
      return [];
    }
    try {
      const parsed = JSON.parse(raw) as unknown;
      return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
    } catch {
      throw new Error("MobilePrivateKeyStore alias index is invalid.");
    }
  }

  private aliasFor(alias: string): string {
    return `${safeSecureStoreKeySegment(this.namespace)}.${safeAliasKey(alias)}`;
  }

  private indexKey(): string {
    return `${safeSecureStoreKeySegment(this.namespace)}.aliases`;
  }

  private async readKeyMaterial(keyId: string): Promise<Uint8Array> {
    const value = await this.secureKeyStore.getItem(this.aliasFor(keyId));
    if (!value) {
      throw new Error("KMS key material is not available.");
    }
    const encoded = value.startsWith("v1:") ? value.slice(3) : value;
    const key = base64ToBytes(encoded);
    if (key.byteLength !== 32) {
      throw new Error("Stored KMS key material is invalid.");
    }
    return key;
  }
}

function safeSecureStoreKeySegment(value: string): string {
  const sanitized = value.replace(/[^a-zA-Z0-9._-]/g, "_");
  return sanitized.length > 0 ? sanitized : "key";
}

function safeAliasKey(alias: string): string {
  return `k_${hashString(alias)}`;
}

function hashString(value: string): string {
  let first = 0x811c9dc5;
  let second = 0x01000193;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    first ^= code;
    first = Math.imul(first, 0x01000193) >>> 0;
    second ^= code + index;
    second = Math.imul(second, 0x85ebca6b) >>> 0;
  }
  return `${first.toString(16).padStart(8, "0")}${second.toString(16).padStart(8, "0")}`;
}
