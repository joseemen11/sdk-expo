import type { HttpClient } from "../network/HttpClient";
import { FetchHttpClient } from "../network/HttpClient";
import type { RPCAdapter } from "../types";
import type { AuthV2GistProof } from "./AuthV2InputBuilder";

declare function require(moduleName: string): unknown;

interface Iden3CoreRuntime {
  DID: {
    parse(value: string): unknown;
    idFromDID(did: unknown): { bigInt(): bigint };
  };
}

interface MerkletreeRuntime {
  Hash: {
    fromHex(value: string): { bigInt(): bigint };
  };
}

interface EthersRuntime {
  JsonRpcProvider: new (url: string) => unknown;
  Contract: new (address: string, abi: readonly unknown[], provider: unknown) => {
    getGISTProof(id: string | bigint): Promise<unknown>;
  };
}

const iden3Core = require("@iden3/js-iden3-core") as Iden3CoreRuntime;
const merkletree = require("@iden3/js-merkletree") as MerkletreeRuntime;

export interface MobileGistProofRequest {
  network?: string;
  isStateGenesis?: boolean;
}

export interface MobileGistProof {
  root: string;
  existence: boolean;
  siblings: string[];
  index: string;
  value: string;
  auxExistence: boolean;
  auxIndex: string;
  auxValue: string;
  source: "did-resolver" | "state-contract";
}

export interface MobileGistProofSource {
  getGISTProof(holderDid: string, request?: MobileGistProofRequest): Promise<MobileGistProof | undefined>;
  getGISTRootInfo?(root: string, holderDid: string): Promise<unknown>;
}

export interface MobileGistProofSourceDebugInfo {
  hasRpcUrl: boolean;
  rpcUrlHost?: string;
  stateContractAddress?: string;
  selectedSource?: MobileGistProof["source"];
  stateContractAttempted: boolean;
  stateContractErrorMessage?: string;
  fallbackReason?: string;
}

export interface ReadOnlyMobileGistProofSourceOptions {
  didResolverUrl?: string;
  httpClient?: HttpClient;
  rpcAdapter?: RPCAdapter;
  chainId?: number;
  rpcUrl?: string;
  stateContractAddress?: string;
  preferStateContract?: boolean;
}

export class ReadOnlyMobileGistProofSource implements MobileGistProofSource {
  private readonly didResolverUrl?: string;
  private readonly httpClient: HttpClient;
  private readonly rpcAdapter?: RPCAdapter;
  private readonly chainId?: number;
  private readonly rpcUrl?: string;
  private readonly stateContractAddress?: string;
  private readonly preferStateContract: boolean;
  private lastDebugInfo: MobileGistProofSourceDebugInfo;

  constructor(options: ReadOnlyMobileGistProofSourceOptions = {}) {
    this.didResolverUrl = normalizeBaseUrl(options.didResolverUrl);
    this.httpClient = options.httpClient ?? new FetchHttpClient();
    this.rpcAdapter = options.rpcAdapter;
    this.chainId = options.chainId;
    this.rpcUrl = options.rpcUrl;
    this.stateContractAddress = options.stateContractAddress;
    this.preferStateContract = options.preferStateContract ?? true;
    this.lastDebugInfo = createInitialDebugInfo(this.rpcUrl, this.stateContractAddress);
  }

  async getGISTProof(holderDid: string, request: MobileGistProofRequest = {}): Promise<MobileGistProof | undefined> {
    this.lastDebugInfo = createInitialDebugInfo(this.rpcUrl, this.stateContractAddress);
    if (!this.didResolverUrl && !this.canReadStateContract()) {
      throw new Error("AuthV2 GIST resolver is not configured.");
    }

    if (this.preferStateContract && this.canReadStateContract()) {
      try {
        this.lastDebugInfo.stateContractAttempted = true;
        const proof = await this.getStateContractGistProof(holderDid);
        this.lastDebugInfo.selectedSource = proof.source;
        return proof;
      } catch (error) {
        this.lastDebugInfo.stateContractErrorMessage = summarizeDebugError(error);
        if (!this.didResolverUrl) {
          throw normalizeGistError(error, request);
        }
        this.lastDebugInfo.fallbackReason = `state-contract failed: ${summarizeDebugError(error)}`;
      }
    } else if (this.preferStateContract && this.hasStateContractConfig()) {
      this.lastDebugInfo.fallbackReason = "state-contract missing chainId";
    } else if (this.preferStateContract && !this.canReadStateContract()) {
      this.lastDebugInfo.fallbackReason = "state-contract not configured";
    }

    if (this.didResolverUrl) {
      try {
        const proof = await this.getResolverGistProof(holderDid);
        this.lastDebugInfo.selectedSource = proof.source;
        return proof;
      } catch (error) {
        if (!this.canReadStateContract()) {
          throw normalizeGistError(error, request);
        }
        this.lastDebugInfo.fallbackReason = `did-resolver failed: ${summarizeDebugError(error)}`;
      }
    }

    if (this.canReadStateContract()) {
      try {
        this.lastDebugInfo.stateContractAttempted = true;
        const proof = await this.getStateContractGistProof(holderDid);
        this.lastDebugInfo.selectedSource = proof.source;
        return proof;
      } catch (error) {
        this.lastDebugInfo.stateContractErrorMessage = summarizeDebugError(error);
        throw normalizeGistError(error, request);
      }
    }

    return undefined;
  }

  getLastDebugInfo(): MobileGistProofSourceDebugInfo {
    return { ...this.lastDebugInfo };
  }

  async getGISTRootInfo(root: string, holderDid: string): Promise<unknown> {
    if (this.didResolverUrl) {
      const url = `${this.didResolverUrl}/1.0/identifiers/${encodeURIComponent(holderDid)}?gist=${encodeURIComponent(root)}`;
      const response = await this.httpClient.request<unknown>({ url });
      return extractResolverGlobalInfo(response);
    }

    if (this.canReadStateContract()) {
      return this.rpcAdapter?.readContract({
        chainId: this.chainId as number,
        rpcUrl: this.rpcUrl,
        contractAddress: this.stateContractAddress as string,
        abi: stateContractGistAbi,
        functionName: "getGISTRootInfo",
        args: [root]
      });
    }

    throw new Error("AuthV2 GIST resolver is not configured.");
  }

  private async getResolverGistProof(holderDid: string): Promise<MobileGistProof> {
    const url = `${this.didResolverUrl}/1.0/identifiers/${encodeURIComponent(holderDid)}`;
    const response = await this.httpClient.request<unknown>({ url });
    return normalizeResolverGistProof(response);
  }

  private async getStateContractGistProof(holderDid: string): Promise<MobileGistProof> {
    const id = deriveHolderId(holderDid);
    const response = this.rpcAdapter
      ? await this.rpcAdapter.readContract<unknown>({
          chainId: this.chainId as number,
          rpcUrl: this.rpcUrl,
          contractAddress: this.stateContractAddress as string,
          abi: stateContractGistAbi,
          functionName: "getGISTProof",
          args: [id]
        })
      : await this.readStateContractGistProof(id);
    return normalizeStateContractGistProof(response);
  }

  private canReadStateContract(): boolean {
    return Boolean((this.rpcAdapter || this.rpcUrl) && this.chainId && this.stateContractAddress);
  }

  private hasStateContractConfig(): boolean {
    return Boolean((this.rpcAdapter || this.rpcUrl) && this.stateContractAddress);
  }

  private async readStateContractGistProof(id: string): Promise<unknown> {
    if (!this.rpcUrl || !this.stateContractAddress) {
      throw new Error("AuthV2 GIST state contract reader is not configured.");
    }
    const ethers = require("ethers") as EthersRuntime;
    const provider = new ethers.JsonRpcProvider(this.rpcUrl);
    const contract = new ethers.Contract(this.stateContractAddress, stateContractGistAbi, provider);
    return contract.getGISTProof(id);
  }
}

export function toAuthV2GistProof(proof: MobileGistProof): AuthV2GistProof {
  const root = toGistHashDecimalString(proof.root, proof.source);
  const siblings = proof.siblings.map((sibling) => toGistHashDecimalString(sibling, proof.source));
  const index = toGistHashDecimalString(proof.index, proof.source);
  const value = toGistHashDecimalString(proof.value, proof.source);
  const auxIndex = toGistHashDecimalString(proof.auxIndex, proof.source);
  const auxValue = toGistHashDecimalString(proof.auxValue, proof.source);
  return {
    gistRoot: root,
    gistMtp: {
      existence: proof.existence,
      siblings,
      index,
      value,
      auxExistence: proof.auxExistence,
      auxIndex,
      auxValue,
      source: proof.source
    },
    gistMtpAuxHi: auxIndex,
    gistMtpAuxHv: auxValue,
    gistMtpNoAux: proof.auxExistence ? "0" : "1"
  };
}

function toGistHashDecimalString(value: string | number | bigint, source: MobileGistProof["source"]): string {
  if (source !== "did-resolver" || typeof value !== "string") {
    return toDecimalBigIntString(value);
  }
  const normalized = value.trim();
  if (/^0x[0-9a-fA-F]{64}$/.test(normalized)) {
    return hashHexToDecimalString(normalized.slice(2));
  }
  if (/^[0-9a-fA-F]{64}$/.test(normalized) && /[a-fA-F]/.test(normalized)) {
    return hashHexToDecimalString(normalized);
  }
  return toDecimalBigIntString(value);
}

export function toDecimalBigIntString(value: string | number | bigint): string {
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new Error("AuthV2 GIST proof response shape is unsupported.");
    }
    return value.toString(10);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("AuthV2 GIST proof response shape is unsupported.");
    }
    return String(value);
  }
  const normalized = value.trim();
  if (/^(0|[1-9][0-9]*)$/.test(normalized)) {
    return normalized;
  }
  if (/^0x[0-9a-fA-F]+$/.test(normalized)) {
    return hashHexToDecimalString(normalized.slice(2));
  }
  if (/^[0-9a-fA-F]+$/.test(normalized) && /[a-fA-F]/.test(normalized)) {
    return hashHexToDecimalString(normalized);
  }
  throw new Error("AuthV2 GIST proof response shape is unsupported.");
}

function hashHexToDecimalString(value: string): string {
  if (value.length > 64) {
    throw new Error("AuthV2 GIST proof response shape is unsupported.");
  }
  const normalized = value.padStart(64, "0");
  return merkletree.Hash.fromHex(normalized).bigInt().toString(10);
}

export function deriveHolderId(holderDid: string): string {
  try {
    const did = iden3Core.DID.parse(holderDid);
    return iden3Core.DID.idFromDID(did).bigInt().toString();
  } catch (error) {
    throw new Error(`AuthV2 holder DID id could not be derived: ${messageFrom(error)}`);
  }
}

function normalizeResolverGistProof(response: unknown): MobileGistProof {
  const global = extractResolverGlobalInfo(response);
  const proof = recordValue(global, "proof");
  if (!proof) {
    throw new Error("AuthV2 GIST proof is not available for resolver response.");
  }

  const root = stringField(global, "root");
  const siblings = stringArrayField(proof, "siblings");
  const nodeAux = recordValue(proof, "node_aux");
  return {
    root,
    existence: booleanField(proof, "existence"),
    siblings,
    index: "0",
    value: "0",
    auxExistence: Boolean(nodeAux),
    auxIndex: nodeAux ? stringField(nodeAux, "key") : "0",
    auxValue: nodeAux ? stringField(nodeAux, "value") : "0",
    source: "did-resolver"
  };
}

function normalizeStateContractGistProof(response: unknown): MobileGistProof {
  const record = normalizeContractResponse(response);
  return {
    root: stringField(record, "root"),
    existence: booleanField(record, "existence"),
    siblings: stringArrayField(record, "siblings"),
    index: stringField(record, "index"),
    value: stringField(record, "value"),
    auxExistence: booleanField(record, "auxExistence"),
    auxIndex: stringField(record, "auxIndex"),
    auxValue: stringField(record, "auxValue"),
    source: "state-contract"
  };
}

function extractResolverGlobalInfo(response: unknown): Record<string, unknown> {
  const top = asRecord(response);
  const didDocument = asRecord(top.didDocument);
  const verificationMethods = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : [];
  const stateInfo = verificationMethods
    .map((item) => (isRecord(item) ? item : undefined))
    .find((item) => item?.type === "Iden3StateInfo2023");
  const global = stateInfo ? recordValue(stateInfo, "global") : undefined;
  if (!global) {
    throw new Error("AuthV2 GIST proof response shape is unsupported.");
  }
  return global;
}

function normalizeContractResponse(response: unknown): Record<string, unknown> {
  if (isRecord(response)) {
    return response;
  }
  if (Array.isArray(response)) {
    const [root, existence, siblings, index, value, auxExistence, auxIndex, auxValue] = response;
    return {
      root,
      existence,
      siblings,
      index,
      value,
      auxExistence,
      auxIndex,
      auxValue
    };
  }
  throw new Error("AuthV2 GIST proof response shape is unsupported.");
}

function normalizeGistError(error: unknown, request: MobileGistProofRequest): Error {
  const message = messageFrom(error);
  if (message.includes("response shape is unsupported")) {
    return new Error("AuthV2 GIST proof response shape is unsupported.");
  }
  if (
    message.includes("GIST proof") ||
    message.includes("GIST root") ||
    message.includes("404") ||
    message.includes("BAD_DATA") ||
    message.includes("could not decode result data")
  ) {
    if (request.isStateGenesis) {
      return new Error(
        `AuthV2 GIST proof is not available for genesis identity on network ${request.network ?? "unknown"}.`
      );
    }
    return new Error("AuthV2 GIST proof could not be generated safely.");
  }
  if (message.includes("state") && message.includes("not")) {
    return new Error("AuthV2 state must be published before AuthV2 proof generation.");
  }
  return new Error(`AuthV2 GIST proof could not be generated safely: ${message}`);
}

function recordValue(record: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  const value = record[key];
  return isRecord(value) ? value : undefined;
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (value === undefined || value === null || value === "") {
    throw new Error("AuthV2 GIST proof response shape is unsupported.");
  }
  return String(value);
}

function booleanField(record: Record<string, unknown>, key: string): boolean {
  const value = record[key];
  if (typeof value === "boolean") {
    return value;
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  throw new Error("AuthV2 GIST proof response shape is unsupported.");
}

function stringArrayField(record: Record<string, unknown>, key: string): string[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw new Error("AuthV2 GIST proof response shape is unsupported.");
  }
  return value.map((item) => String(item));
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error("AuthV2 GIST proof response shape is unsupported.");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function messageFrom(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function summarizeDebugError(error: unknown): string {
  return messageFrom(error).split(/\r?\n/)[0]?.slice(0, 180) ?? "unknown error";
}

function createInitialDebugInfo(
  rpcUrl: string | undefined,
  stateContractAddress: string | undefined
): MobileGistProofSourceDebugInfo {
  return {
    hasRpcUrl: Boolean(rpcUrl),
    rpcUrlHost: rpcUrl ? safeUrlHost(rpcUrl) : undefined,
    stateContractAddress,
    stateContractAttempted: false
  };
}

function safeUrlHost(value: string): string | undefined {
  try {
    return new URL(value).host;
  } catch {
    return undefined;
  }
}

function normalizeBaseUrl(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  return value.replace(/\/+$/, "");
}

export const stateContractGistAbi = [
  {
    inputs: [{ internalType: "uint256", name: "id", type: "uint256" }],
    name: "getGISTProof",
    outputs: [
      {
        components: [
          { internalType: "uint256", name: "root", type: "uint256" },
          { internalType: "bool", name: "existence", type: "bool" },
          { internalType: "uint256[]", name: "siblings", type: "uint256[]" },
          { internalType: "uint256", name: "index", type: "uint256" },
          { internalType: "uint256", name: "value", type: "uint256" },
          { internalType: "bool", name: "auxExistence", type: "bool" },
          { internalType: "uint256", name: "auxIndex", type: "uint256" },
          { internalType: "uint256", name: "auxValue", type: "uint256" }
        ],
        internalType: "struct StateInfo.GistProof",
        name: "",
        type: "tuple"
      }
    ],
    stateMutability: "view",
    type: "function"
  },
  {
    inputs: [{ internalType: "uint256", name: "root", type: "uint256" }],
    name: "getGISTRootInfo",
    outputs: [
      {
        components: [
          { internalType: "uint256", name: "root", type: "uint256" },
          { internalType: "uint256", name: "replacedByRoot", type: "uint256" },
          { internalType: "uint256", name: "createdAtTimestamp", type: "uint256" },
          { internalType: "uint256", name: "replacedAtTimestamp", type: "uint256" },
          { internalType: "uint256", name: "createdAtBlock", type: "uint256" },
          { internalType: "uint256", name: "replacedAtBlock", type: "uint256" }
        ],
        internalType: "struct StateInfo.RootInfo",
        name: "",
        type: "tuple"
      }
    ],
    stateMutability: "view",
    type: "function"
  }
] as const;
