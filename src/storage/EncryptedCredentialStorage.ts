import { buildCredentialSummary } from "../credentials/diagnostics";
import { bytesToBase64, base64ToBytes, bytesToText, textToBytes } from "../network/Base64UrlCodec";
import type { CredentialStorageAdapter, ImportedCredentialSummary, SecureKeyStore, StoredCredentialRecord } from "../types";

export interface EncryptedCredentialStorageOptions {
  keyAlias?: string;
  secureKeyStore: SecureKeyStore;
}

export class EncryptedCredentialStorage implements CredentialStorageAdapter {
  private readonly records = new Map<string, StoredCredentialRecord>();
  private key?: Uint8Array;
  private readonly keyAlias: string;
  private readonly secureKeyStore: SecureKeyStore;

  constructor(options: EncryptedCredentialStorageOptions) {
    this.keyAlias = options.keyAlias ?? "privado-id.credentials.v1";
    this.secureKeyStore = options.secureKeyStore;
  }

  async init(): Promise<void> {
    this.key = await this.secureKeyStore.getOrCreateKey(this.keyAlias);
  }

  async saveCredential(credential: unknown): Promise<ImportedCredentialSummary> {
    const key = await this.requireKey();
    const summary = buildCredentialSummary(credential);
    const now = new Date().toISOString();
    const encryptedPayload = encryptDevelopmentPayload(JSON.stringify(credential), key);
    const existing = this.records.get(summary.id);

    this.records.set(summary.id, {
      id: summary.id,
      encryptedPayload,
      summary,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    });

    return summary;
  }

  async getCredentials(): Promise<ImportedCredentialSummary[]> {
    return [...this.records.values()].map((record) => ({ ...record.summary }));
  }

  async getCredentialById(id: string): Promise<unknown | undefined> {
    const record = this.records.get(id);
    if (!record) {
      return undefined;
    }
    const key = await this.requireKey();
    return JSON.parse(decryptDevelopmentPayload(record.encryptedPayload, key)) as unknown;
  }

  private async requireKey(): Promise<Uint8Array> {
    if (!this.key) {
      await this.init();
    }
    if (!this.key) {
      throw new Error("Credential encryption key is not available.");
    }
    return this.key;
  }
}

function encryptDevelopmentPayload(value: string, key: Uint8Array): string {
  const plain = textToBytes(value);
  return bytesToBase64(xorBytes(plain, key));
}

function decryptDevelopmentPayload(value: string, key: Uint8Array): string {
  return bytesToText(xorBytes(base64ToBytes(value), key));
}

function xorBytes(input: Uint8Array, key: Uint8Array): Uint8Array {
  const output = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i += 1) {
    output[i] = input[i] ^ key[i % key.length];
  }
  return output;
}
