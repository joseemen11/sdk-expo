import type { SecureKeyStore, StorageAdapter } from "../types";

declare function require(moduleName: string): unknown;

interface MerkleTreeRuntime {
  InMemoryDB: new (prefix: Uint8Array) => unknown;
  Merkletree: new (
    db: unknown,
    writable: boolean,
    maxLevels: number
  ) => {
    add(k: bigint, v: bigint): Promise<void>;
    root(): Promise<{ bigInt(): bigint; toJSON(): string }>;
    generateProof(k: bigint): Promise<{
      proof: {
        existence: boolean;
        toJSON(): unknown;
        allSiblings(): Array<{ toJSON(): string }>;
      };
      value: bigint;
    }>;
  };
  str2Bytes(value: string): Uint8Array;
  hashElems(values: bigint[]): { bigInt(): bigint };
}

const MerkleTree = require("@iden3/js-merkletree") as MerkleTreeRuntime;

export interface MobileMerkleTreeStorageOptions {
  secureKeyStore?: SecureKeyStore;
  recordStore?: StorageAdapter<string>;
  namespace?: string;
  treeDepth?: number;
}

export interface MobileMerkleTreeMetaInformation {
  treeId: string;
  identifier: string;
  type: number;
}

export interface MobileMerkleInclusionProof {
  existence: boolean;
  key: string;
  value: string;
  root: string;
  siblings: string[];
  proof: unknown;
}

export type MobileMerkleProof = MobileMerkleInclusionProof;

interface StoredMerkleTreeRecord extends MobileMerkleTreeMetaInformation {
  root: string;
  entries: Array<{
    hindex: string;
    hvalue: string;
  }>;
  createdAt: string;
  updatedAt: string;
}

export class MobileMerkleTreeStorage {
  private readonly secureKeyStore?: SecureKeyStore;
  private readonly recordStore?: StorageAdapter<string>;
  private readonly namespace: string;
  private readonly treeDepth: number;

  constructor(options: MobileMerkleTreeStorageOptions = {}) {
    this.secureKeyStore = options.secureKeyStore;
    this.recordStore = options.recordStore;
    this.namespace = options.namespace ?? "privado-id.mobile-merkle";
    this.treeDepth = options.treeDepth ?? 40;
  }

  async createIdentityMerkleTrees(identifier: string): Promise<MobileMerkleTreeMetaInformation[]> {
    if (!identifier) {
      throw new Error("MobileMerkleTreeStorage.createIdentityMerkleTrees requires identifier.");
    }
    const records = await this.readRecords();
    const existing = Object.values(records).filter((record) => record.identifier === identifier);
    if (existing.length === 3) {
      return existing.map(toMetaInformation);
    }

    const now = new Date().toISOString();
    for (const type of [0, 1, 2]) {
      const treeId = this.treeId(identifier, type);
      records[treeId] = records[treeId] ?? {
        treeId,
        identifier,
        type,
        root: "0",
        entries: [],
        createdAt: now,
        updatedAt: now
      };
    }
    await this.writeRecords(records);
    return [0, 1, 2].map((type) => toMetaInformation(records[this.treeId(identifier, type)]));
  }

  async addToMerkleTree(
    identifier: string,
    mtType: unknown,
    hindex: bigint,
    hvalue: bigint
  ): Promise<void> {
    const type = normalizeTreeType(mtType);
    const records = await this.readRecords();
    const treeId = this.treeId(identifier, type);
    const record = records[treeId];
    if (!record) {
      throw new Error("MobileMerkleTreeStorage.addToMerkleTree requires existing tree metadata.");
    }
    const existingIndex = record.entries.findIndex((entry) => entry.hindex === hindex.toString());
    const entry = {
      hindex: hindex.toString(),
      hvalue: hvalue.toString()
    };
    if (existingIndex >= 0) {
      record.entries[existingIndex] = entry;
    } else {
      record.entries.push(entry);
    }
    record.root = await calculateEntriesRoot(record.treeId, record.entries, this.treeDepth);
    record.updatedAt = new Date().toISOString();
    records[treeId] = record;
    await this.writeRecords(records);
  }

  async getMerkleTreeByIdentifierAndType(identifier: string, mtType: unknown): Promise<{
    root(): Promise<{ bigInt(): bigint }>;
  }> {
    const type = normalizeTreeType(mtType);
    const records = await this.readRecords();
    const record = records[this.treeId(identifier, type)];
    if (!record) {
      throw new Error("MobileMerkleTreeStorage.getMerkleTreeByIdentifierAndType requires existing tree metadata.");
    }
    return {
      root: async () => ({
        bigInt: () => BigInt(record.root)
      })
    };
  }

  async generateInclusionProof(
    identifier: string,
    mtType: unknown,
    hindex: bigint
  ): Promise<MobileMerkleInclusionProof> {
    const proof = await this.generateProof(identifier, mtType, hindex);
    if (!proof.existence) {
      throw new Error(`AuthV2 auth claim inclusion proof could not be generated for key ${safeKeySummary(hindex)}.`);
    }
    return proof;
  }

  async generateProof(identifier: string, mtType: unknown, hindex: bigint): Promise<MobileMerkleProof> {
    const type = normalizeTreeType(mtType);
    const records = await this.readRecords();
    const record = records[this.treeId(identifier, type)];
    if (!record) {
      throw new Error(
        type === 1
          ? "AuthV2 revocation tree is not available for holder DID."
          : "AuthV2 claims tree is not available for holder DID."
      );
    }

    const tree = await rebuildMerkleTree(record.treeId, record.entries, this.treeDepth);
    const root = await tree.root();
    const { proof, value } = await tree.generateProof(hindex);
    return {
      existence: proof.existence,
      key: hindex.toString(),
      value: value.toString(),
      root: root.bigInt().toString(),
      siblings: proof.allSiblings().map((sibling) => sibling.toJSON()),
      proof: proof.toJSON()
    };
  }

  async bindMerkleTreeToNewIdentifier(oldIdentifier: string, newIdentifier: string): Promise<void> {
    const records = await this.readRecords();
    const matching = Object.values(records).filter((record) => record.identifier === oldIdentifier);
    if (matching.length === 0) {
      throw new Error("MobileMerkleTreeStorage.bindMerkleTreeToNewIdentifier requires existing tree metadata.");
    }
    for (const record of matching) {
      delete records[record.treeId];
      const treeId = this.treeId(newIdentifier, record.type);
      records[treeId] = {
        ...record,
        treeId,
        identifier: newIdentifier,
        updatedAt: new Date().toISOString()
      };
    }
    await this.writeRecords(records);
  }

  private async readRecords(): Promise<Record<string, StoredMerkleTreeRecord>> {
    const raw = await this.readValue(this.recordsKey());
    if (!raw) {
      return {};
    }
    try {
      const parsed = JSON.parse(raw) as unknown;
      return parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? (parsed as Record<string, StoredMerkleTreeRecord>)
        : {};
    } catch {
      throw new Error("MobileMerkleTreeStorage records are invalid.");
    }
  }

  private async writeRecords(records: Record<string, StoredMerkleTreeRecord>): Promise<void> {
    await this.writeValue(this.recordsKey(), JSON.stringify(records));
  }

  private treeId(identifier: string, type: number): string {
    return `${identifier}:${type}`;
  }

  private recordsKey(): string {
    return `${this.namespace}.trees`;
  }

  private async readValue(key: string): Promise<string | undefined> {
    if (this.recordStore) {
      return this.recordStore.get(key);
    }
    if (this.secureKeyStore) {
      return this.secureKeyStore.getItem(key);
    }
    throw new Error("MobileMerkleTreeStorage requires a mobile metadata store.");
  }

  private async writeValue(key: string, value: string): Promise<void> {
    if (this.recordStore) {
      await this.recordStore.set(key, value);
      return;
    }
    if (this.secureKeyStore) {
      await this.secureKeyStore.setItem(key, value);
      return;
    }
    throw new Error("MobileMerkleTreeStorage requires a mobile metadata store.");
  }
}

function toMetaInformation(record: StoredMerkleTreeRecord): MobileMerkleTreeMetaInformation {
  return {
    treeId: record.treeId,
    identifier: record.identifier,
    type: record.type
  };
}

function normalizeTreeType(value: unknown): number {
  if (typeof value === "number") {
    return value;
  }
  if (typeof value === "bigint") {
    return Number(value);
  }
  if (typeof value === "string" && value.length > 0) {
    return Number(value);
  }
  throw new Error("MobileMerkleTreeStorage tree type is invalid.");
}

async function calculateEntriesRoot(
  treeId: string,
  entries: StoredMerkleTreeRecord["entries"],
  treeDepth: number
): Promise<string> {
  if (entries.length === 0) {
    return "0";
  }
  const tree = await rebuildMerkleTree(treeId, entries, treeDepth);
  const root = await tree.root();
  return root.bigInt().toString();
}

async function rebuildMerkleTree(
  treeId: string,
  entries: StoredMerkleTreeRecord["entries"],
  treeDepth: number
): Promise<InstanceType<MerkleTreeRuntime["Merkletree"]>> {
  const tree = new MerkleTree.Merkletree(
    new MerkleTree.InMemoryDB(MerkleTree.str2Bytes(treeId)),
    true,
    treeDepth
  );
  const sorted = [...entries].sort((a, b) => (BigInt(a.hindex) < BigInt(b.hindex) ? -1 : 1));
  for (const entry of sorted) {
    await tree.add(BigInt(entry.hindex), BigInt(entry.hvalue));
  }
  return tree;
}

function safeKeySummary(value: bigint): string {
  const text = value.toString();
  return `${text.slice(0, 8)}...${text.slice(-6)}`;
}
