import { bytesToBase64, base64ToBytes, textToBytes } from "../network/Base64UrlCodec";
import type { PrivateKeyStoreAdapter, SecureKeyStore } from "../types";
import { createEncryptionKey } from "../storage/createEncryptionKey";

export interface SecurePrivateKeyStoreOptions {
  secureKeyStore: SecureKeyStore;
  namespace?: string;
  randomBytes?: (byteLength: number) => Uint8Array;
}

export class SecurePrivateKeyStore implements PrivateKeyStoreAdapter {
  private readonly secureKeyStore: SecureKeyStore;
  private readonly namespace: string;
  private readonly randomBytes?: (byteLength: number) => Uint8Array;

  constructor(options: SecurePrivateKeyStoreOptions) {
    this.secureKeyStore = options.secureKeyStore;
    this.namespace = options.namespace ?? "privado-id.kms";
    this.randomBytes = options.randomBytes;
  }

  async ensureKey(keyId: string): Promise<{ keyId: string; created: boolean }> {
    const alias = this.aliasForKeyId(keyId);
    const existing = await this.secureKeyStore.getItem(alias);
    if (existing) {
      return { keyId, created: false };
    }

    const key = this.randomBytes ? this.randomBytes(32) : createEncryptionKey();
    if (key.byteLength !== 32) {
      throw new Error("Private key material must be 32 bytes.");
    }
    await this.secureKeyStore.setItem(alias, `v1:${bytesToBase64(key)}`);
    return { keyId, created: true };
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.secureKeyStore.deleteItem(this.aliasForKeyId(keyId));
  }

  async signDevelopmentChallenge(input: { keyId: string; challenge: string | Uint8Array }): Promise<Uint8Array> {
    const key = await this.readKeyMaterial(input.keyId);
    const challengeBytes = typeof input.challenge === "string" ? textToBytes(input.challenge) : input.challenge;
    const { hmac } = await import("@noble/hashes/hmac.js");
    const { sha256 } = await import("@noble/hashes/sha2.js");
    return hmac(sha256, key, challengeBytes);
  }

  private async readKeyMaterial(keyId: string): Promise<Uint8Array> {
    const value = await this.secureKeyStore.getItem(this.aliasForKeyId(keyId));
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

  private aliasForKeyId(keyId: string): string {
    return `${this.namespace}.${keyId}`;
  }
}
