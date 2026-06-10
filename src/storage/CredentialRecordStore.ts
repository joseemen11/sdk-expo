import type { StoredCredentialRecord } from "../types";

export interface CredentialRecordStore {
  init?(): Promise<void>;
  upsert(record: StoredCredentialRecord): Promise<void>;
  list(): Promise<StoredCredentialRecord[]>;
  get(id: string): Promise<StoredCredentialRecord | undefined>;
  delete(id: string): Promise<void>;
  clear(): Promise<void>;
}

export class InMemoryCredentialRecordStore implements CredentialRecordStore {
  private readonly records = new Map<string, StoredCredentialRecord>();

  async upsert(record: StoredCredentialRecord): Promise<void> {
    this.records.set(record.id, cloneRecord(record));
  }

  async list(): Promise<StoredCredentialRecord[]> {
    return [...this.records.values()].map(cloneRecord);
  }

  async get(id: string): Promise<StoredCredentialRecord | undefined> {
    const record = this.records.get(id);
    return record ? cloneRecord(record) : undefined;
  }

  async delete(id: string): Promise<void> {
    this.records.delete(id);
  }

  async clear(): Promise<void> {
    this.records.clear();
  }
}

function cloneRecord(record: StoredCredentialRecord): StoredCredentialRecord {
  return {
    ...record,
    summary: {
      ...record.summary,
      type: [...record.summary.type],
      proofTypes: [...record.summary.proofTypes]
    }
  };
}
