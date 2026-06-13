import type { StorageAdapter } from "../types";
import type { SQLiteDatabaseLike } from "./SQLiteCredentialRecordStore";

export interface SQLiteKeyValueStoreOptions {
  database: SQLiteDatabaseLike;
  tableName?: string;
}

interface KeyValueRow {
  key: string;
  value: string;
}

const DEFAULT_TABLE = "privado_mobile_metadata";

export class SQLiteKeyValueStore implements StorageAdapter<string> {
  private readonly database: SQLiteDatabaseLike;
  private readonly tableName: string;

  constructor(options: SQLiteKeyValueStoreOptions) {
    this.database = options.database;
    this.tableName = options.tableName ?? DEFAULT_TABLE;
    assertSafeIdentifier(this.tableName);
  }

  async init(): Promise<void> {
    await this.database.execAsync(`
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS ${this.tableName}_updated_at_idx
        ON ${this.tableName} (updated_at);
    `);
  }

  async get(key: string): Promise<string | undefined> {
    const row = await this.database.getFirstAsync<KeyValueRow>(
      `SELECT key, value
       FROM ${this.tableName}
       WHERE key = ?`,
      [key]
    );
    return row?.value;
  }

  async set(key: string, value: string): Promise<void> {
    await this.database.runAsync(
      `INSERT INTO ${this.tableName}
        (key, value, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
        value = excluded.value,
        updated_at = excluded.updated_at`,
      [key, value, new Date().toISOString()]
    );
  }

  async remove(key: string): Promise<void> {
    await this.database.runAsync(`DELETE FROM ${this.tableName} WHERE key = ?`, [key]);
  }
}

function assertSafeIdentifier(value: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
    throw new Error("SQLite table name is invalid.");
  }
}
