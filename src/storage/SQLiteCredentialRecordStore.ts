import type { StoredCredentialRecord } from "../types";
import type { CredentialRecordStore } from "./CredentialRecordStore";

export interface SQLiteDatabaseLike {
  execAsync(source: string): Promise<void>;
  runAsync(source: string, params?: unknown[] | Record<string, unknown>): Promise<unknown>;
  getAllAsync<T>(source: string, params?: unknown[] | Record<string, unknown>): Promise<T[]>;
  getFirstAsync<T>(source: string, params?: unknown[] | Record<string, unknown>): Promise<T | null>;
}

export interface SQLiteCredentialRecordStoreOptions {
  database: SQLiteDatabaseLike;
  tableName?: string;
}

interface CredentialRecordRow {
  id: string;
  summary_json: string;
  encrypted_payload: string;
  created_at: string;
  updated_at: string;
}

const DEFAULT_TABLE = "privado_credentials";

export class SQLiteCredentialRecordStore implements CredentialRecordStore {
  private readonly database: SQLiteDatabaseLike;
  private readonly tableName: string;

  constructor(options: SQLiteCredentialRecordStoreOptions) {
    this.database = options.database;
    this.tableName = options.tableName ?? DEFAULT_TABLE;
    assertSafeIdentifier(this.tableName);
  }

  async init(): Promise<void> {
    await this.database.execAsync(`
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        id TEXT PRIMARY KEY NOT NULL,
        summary_json TEXT NOT NULL,
        encrypted_payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ${this.tableName}_updated_at_idx
        ON ${this.tableName} (updated_at);
    `);
  }

  async upsert(record: StoredCredentialRecord): Promise<void> {
    await this.database.runAsync(
      `INSERT INTO ${this.tableName}
        (id, summary_json, encrypted_payload, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
        summary_json = excluded.summary_json,
        encrypted_payload = excluded.encrypted_payload,
        updated_at = excluded.updated_at`,
      [
        record.id,
        JSON.stringify(record.summary),
        record.encryptedPayload,
        record.createdAt,
        record.updatedAt
      ]
    );
  }

  async list(): Promise<StoredCredentialRecord[]> {
    const rows = await this.database.getAllAsync<CredentialRecordRow>(
      `SELECT id, summary_json, encrypted_payload, created_at, updated_at
       FROM ${this.tableName}
       ORDER BY updated_at DESC`,
      []
    );
    return rows.map(rowToRecord);
  }

  async get(id: string): Promise<StoredCredentialRecord | undefined> {
    const row = await this.database.getFirstAsync<CredentialRecordRow>(
      `SELECT id, summary_json, encrypted_payload, created_at, updated_at
       FROM ${this.tableName}
       WHERE id = ?`,
      [id]
    );
    return row ? rowToRecord(row) : undefined;
  }

  async delete(id: string): Promise<void> {
    await this.database.runAsync(`DELETE FROM ${this.tableName} WHERE id = ?`, [id]);
  }

  async clear(): Promise<void> {
    await this.database.runAsync(`DELETE FROM ${this.tableName}`, []);
  }
}

function rowToRecord(row: CredentialRecordRow): StoredCredentialRecord {
  return {
    id: row.id,
    summary: JSON.parse(row.summary_json) as StoredCredentialRecord["summary"],
    encryptedPayload: row.encrypted_payload,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function assertSafeIdentifier(value: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
    throw new Error("SQLite table name is invalid.");
  }
}
