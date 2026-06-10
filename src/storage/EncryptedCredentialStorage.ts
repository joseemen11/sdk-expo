import { buildCredentialSummary } from "../credentials/diagnostics";
import type { CredentialStorageAdapter, ImportedCredentialSummary, SecureKeyStore, StoredCredentialRecord } from "../types";
import { encryptCredentialPayload, decryptCredentialPayload } from "./CredentialCipher";
import { InMemoryCredentialRecordStore, type CredentialRecordStore } from "./CredentialRecordStore";
import { createEncryptionKey } from "./createEncryptionKey";

export interface EncryptedCredentialStorageOptions {
  keyAlias?: string;
  secureKeyStore: SecureKeyStore;
  recordStore?: CredentialRecordStore;
  randomBytes?: (byteLength: number) => Uint8Array;
}

export class EncryptedCredentialStorage implements CredentialStorageAdapter {
  private key?: Uint8Array;
  private readonly keyAlias: string;
  private readonly secureKeyStore: SecureKeyStore;
  private readonly recordStore: CredentialRecordStore;
  private readonly randomBytes?: (byteLength: number) => Uint8Array;

  constructor(options: EncryptedCredentialStorageOptions) {
    this.keyAlias = options.keyAlias ?? "privado-id.credentials.v1";
    this.secureKeyStore = options.secureKeyStore;
    this.recordStore = options.recordStore ?? new InMemoryCredentialRecordStore();
    this.randomBytes = options.randomBytes;
  }

  async init(): Promise<void> {
    await this.recordStore.init?.();
    this.key = await this.secureKeyStore.getOrCreateEncryptionKey(this.keyAlias);
  }

  async saveCredential(credential: unknown): Promise<ImportedCredentialSummary> {
    const key = await this.requireKey();
    const baseSummary = buildCredentialSummary(credential);
    const now = new Date().toISOString();
    const existing = await this.recordStore.get(baseSummary.id);
    const createdAt = existing?.createdAt ?? now;
    const updatedAt = now;
    const summary = withTimestamps(baseSummary, createdAt, updatedAt);
    const encryptedPayload = await encryptCredentialPayload({
      credential,
      key,
      nonce: this.createNonce(),
      associatedData: associatedDataForCredential(baseSummary.id)
    });

    await this.recordStore.upsert({
      id: summary.id,
      encryptedPayload,
      summary,
      createdAt,
      updatedAt
    });

    return summary;
  }

  async getCredentials(): Promise<ImportedCredentialSummary[]> {
    const records = await this.recordStore.list();
    return records.map((record) => withTimestamps(record.summary, record.createdAt, record.updatedAt));
  }

  async getCredentialById(id: string): Promise<unknown | undefined> {
    const record = await this.recordStore.get(id);
    if (!record) {
      return undefined;
    }
    const key = await this.requireKey();
    return decryptCredentialPayload({
      encryptedPayload: record.encryptedPayload,
      key,
      associatedData: associatedDataForCredential(id)
    });
  }

  async deleteCredential(id: string): Promise<void> {
    await this.recordStore.delete(id);
  }

  async clearCredentials(): Promise<void> {
    await this.recordStore.clear();
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

  private createNonce(): Uint8Array {
    if (this.randomBytes) {
      return this.randomBytes(24);
    }
    return createEncryptionKey({ byteLength: 24 });
  }
}

function associatedDataForCredential(id: string): string {
  return `privado-id-expo-sdk:credential:${id}`;
}

function withTimestamps(
  summary: ImportedCredentialSummary,
  createdAt: string,
  updatedAt: string
): ImportedCredentialSummary {
  return {
    ...summary,
    type: [...summary.type],
    proofTypes: [...summary.proofTypes],
    createdAt,
    updatedAt
  };
}
