export interface JsonLdContextFileSystem {
  cacheDirectory?: string;
  getInfo(path: string): Promise<{ exists: boolean }>;
  makeDirectory(path: string): Promise<void>;
  readAsString(path: string): Promise<string>;
  writeAsString(path: string, value: string): Promise<void>;
}

export interface JsonLdContextStoreOptions {
  fileSystem: JsonLdContextFileSystem;
  fetch?: (url: string) => Promise<{
    ok: boolean;
    status: number;
    text(): Promise<string>;
  }>;
  cacheDirectory?: string;
  ipfsGatewayUrl?: string;
  bundledContexts?: Record<string, unknown>;
}

export interface JsonLdRemoteDocument {
  contextUrl?: string;
  documentUrl: string;
  document: unknown;
}

export interface JsonLdContextEnsureSummary {
  totalContexts: number;
  bundled: number;
  cached: number;
  fetched: number;
  missing: Array<{
    contextUrl: string;
    httpStatus?: number;
    reason: string;
  }>;
}

interface JsonLdContextEnsureResult {
  context: unknown;
  status: "bundled" | "cached" | "fetched";
}

const defaultIpfsGatewayUrl = "https://ipfs.io/ipfs";

export class JsonLdContextStore {
  private readonly fileSystem: JsonLdContextFileSystem;
  private readonly fetchImpl: NonNullable<JsonLdContextStoreOptions["fetch"]>;
  private readonly cacheDirectory: string;
  private readonly ipfsGatewayUrl: string;
  private readonly bundledContexts: Map<string, unknown>;

  constructor(options: JsonLdContextStoreOptions) {
    const cacheRoot = options.cacheDirectory ?? options.fileSystem.cacheDirectory;
    if (!cacheRoot) {
      throw new Error("JSON-LD context cache directory is not configured.");
    }
    this.fileSystem = options.fileSystem;
    this.fetchImpl = options.fetch ?? defaultFetch;
    this.cacheDirectory = joinUri(cacheRoot, "jsonld-contexts");
    this.ipfsGatewayUrl = trimRightSlash(options.ipfsGatewayUrl ?? defaultIpfsGatewayUrl);
    this.bundledContexts = createBundledContextMap(options.bundledContexts ?? {});
  }

  async ensureContextsForCredential(
    credential: unknown,
    extraContextUrls: string[] = []
  ): Promise<JsonLdContextEnsureSummary> {
    const urls = new Set([...extraContextUrls, ...collectContextUrls(credential)]);
    const summary: JsonLdContextEnsureSummary = {
      totalContexts: urls.size,
      bundled: 0,
      cached: 0,
      fetched: 0,
      missing: []
    };
    for (const url of urls) {
      try {
        const result = await this.ensureContextWithStatus(url);
        summary[result.status] += 1;
      } catch (error) {
        summary.missing.push(toMissingContext(url, error));
      }
    }
    if (summary.missing.length > 0) {
      const first = summary.missing[0];
      const status = first.httpStatus === undefined ? "" : ` HTTP ${first.httpStatus}`;
      throw new Error(`Missing JSON-LD context in local cache: ${first.contextUrl};${status} ${first.reason}`.trim());
    }
    return summary;
  }

  async ensureContextsFromCredential(credential: unknown, extraContextUrls: string[] = []): Promise<void> {
    await this.ensureContextsForCredential(credential, extraContextUrls);
  }

  async loadDocument(url: string): Promise<JsonLdRemoteDocument> {
    return {
      contextUrl: undefined,
      documentUrl: url,
      document: await this.ensureContext(url)
    };
  }

  createDocumentLoader(): (url: string) => Promise<JsonLdRemoteDocument> {
    return async (url: string) => this.loadDocument(url);
  }

  async ensureContext(url: string): Promise<unknown> {
    return (await this.ensureContextWithStatus(url)).context;
  }

  async ensureContextWithStatus(url: string): Promise<JsonLdContextEnsureResult> {
    const normalizedUrl = normalizeJsonLdContextUrl(url);
    const bundled = this.bundledContexts.get(normalizedUrl);
    if (bundled !== undefined) {
      return {
        context: validateJsonLdContextObject(bundled, url),
        status: "bundled"
      };
    }
    const cachePath = this.cachePathFor(normalizedUrl);
    await this.fileSystem.makeDirectory(this.cacheDirectory);
    const info = await this.fileSystem.getInfo(cachePath);
    if (info.exists) {
      return {
        context: parseJsonLdContext(await this.fileSystem.readAsString(cachePath), url),
        status: "cached"
      };
    }
    const context = await this.fetchContext(url, normalizedUrl);
    await this.fileSystem.writeAsString(cachePath, JSON.stringify(context));
    return { context, status: "fetched" };
  }

  private async fetchContext(originalUrl: string, normalizedUrl: string): Promise<unknown> {
    const fetchUrl = normalizedUrl.startsWith("ipfs://")
      ? `${this.ipfsGatewayUrl}/${normalizedUrl.slice("ipfs://".length)}`
      : normalizedUrl;
    try {
      const response = await this.fetchImpl(fetchUrl);
      if (!response.ok) {
        throw new JsonLdContextFetchError(`fetch failed`, response.status);
      }
      return parseJsonLdContext(await response.text(), originalUrl);
    } catch (error) {
      if (error instanceof JsonLdContextFetchError) {
        throw error;
      }
      throw new JsonLdContextFetchError(errorMessage(error));
    }
  }

  private cachePathFor(normalizedUrl: string): string {
    return joinUri(this.cacheDirectory, `${toStableCacheKey(normalizedUrl)}.json`);
  }
}

class JsonLdContextFetchError extends Error {
  readonly httpStatus?: number;

  constructor(message: string, httpStatus?: number) {
    super(message);
    this.httpStatus = httpStatus;
  }
}

export function normalizeJsonLdContextUrl(url: string): string {
  if (url.startsWith("ipfs://")) {
    return `ipfs://${trimLeftSlash(url.slice("ipfs://".length))}`;
  }
  if (isBareIpfsCid(url)) {
    return `ipfs://${url}`;
  }
  const ipfsGatewayMatch = /^https:\/\/[^/]+\/ipfs\/(.+)$/i.exec(url);
  if (ipfsGatewayMatch) {
    return `ipfs://${trimLeftSlash(ipfsGatewayMatch[1])}`;
  }
  return url;
}

function collectContextUrls(value: unknown): string[] {
  const contexts = asRecord(value)?.["@context"];
  return collectContextUrlsFromValue(contexts);
}

function collectContextUrlsFromValue(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.flatMap(collectContextUrlsFromValue);
  }
  if (value && typeof value === "object") {
    return collectContextUrlsFromValue((value as { "@context"?: unknown })["@context"]);
  }
  return [];
}

function parseJsonLdContext(text: string, url: string): unknown {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!isValidJsonLdContext(parsed)) {
      throw new Error("unsupported shape");
    }
    return parsed;
  } catch {
    throw new Error(`Missing JSON-LD context in local cache: ${url}`);
  }
}

function validateJsonLdContextObject(value: unknown, url: string): unknown {
  if (!isValidJsonLdContext(value)) {
    throw new Error(`Missing JSON-LD context in local cache: ${url}`);
  }
  return value;
}

function toMissingContext(url: string, error: unknown): { contextUrl: string; httpStatus?: number; reason: string } {
  return {
    contextUrl: url,
    httpStatus: error instanceof JsonLdContextFetchError ? error.httpStatus : undefined,
    reason: errorMessage(error)
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isValidJsonLdContext(value: unknown): boolean {
  if (!value || typeof value !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  return "@context" in value || Object.keys(value).length > 0;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function createBundledContextMap(contexts: Record<string, unknown>): Map<string, unknown> {
  const map = new Map<string, unknown>();
  for (const [url, context] of Object.entries(contexts)) {
    map.set(normalizeJsonLdContextUrl(url), context);
  }
  return map;
}

function isBareIpfsCid(value: string): boolean {
  return !value.includes(":") && !value.includes("/") && /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[1-9A-HJ-NP-Za-km-z]+)$/i.test(value);
}

function toStableCacheKey(value: string): string {
  return Array.from(value)
    .map((char) => char.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("");
}

function trimRightSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function trimLeftSlash(value: string): string {
  return value.replace(/^\/+/, "");
}

function joinUri(base: string, path: string): string {
  return `${trimRightSlash(base)}/${trimLeftSlash(path)}`;
}

async function defaultFetch(url: string): Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}> {
  if (typeof fetch !== "function") {
    throw new Error("fetch is not available.");
  }
  return fetch(url);
}
