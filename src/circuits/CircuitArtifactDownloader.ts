import { CircuitArtifactStore } from "./CircuitArtifactStore";
import { CircuitId } from "./CircuitId";
import {
  formatMissingZipCircuitArtifacts,
  joinUri,
  resolveZipCircuitArtifacts,
  type ZipCircuitExpectedFileMap
} from "./ZipCircuitArtifactResolver";
import type { CircuitArtifactDescriptor } from "../types";

export interface CircuitArtifactFileSystemAdapter {
  cacheDirectory?: string;
  documentDirectory?: string;
  exists(path: string): Promise<boolean> | boolean;
  makeDirectory(path: string): Promise<void>;
  downloadFile(url: string, destinationPath: string): Promise<{ path: string }>;
  deleteFile?(path: string): Promise<void>;
  sha256?(path: string): Promise<string> | string;
}

export interface ZipExtractor {
  extract(zipPath: string, destinationDir: string): Promise<void>;
}

export interface CircuitArtifactDownloadConfig {
  zipUrl: string;
  cacheDir?: string;
  zipFileName?: string;
  extractDirName?: string;
  requiredCircuits: CircuitId[];
  expectedFiles?: ZipCircuitExpectedFileMap;
  checksums?: Record<string, string>;
  version?: string;
  forceRefresh?: boolean;
  onStatus?: (status: CircuitArtifactDownloadStatus) => void;
}

export type CircuitArtifactDownloadStatus =
  | "downloading"
  | "extracting"
  | "validating"
  | "registered";

export interface CircuitArtifactDownloadResult {
  status: "downloaded" | "already-cached";
  zipPath: string;
  extractDir: string;
  descriptors: CircuitArtifactDescriptor[];
  store: CircuitArtifactStore;
}

export interface CircuitArtifactDownloaderOptions extends CircuitArtifactDownloadConfig {
  fileSystem: CircuitArtifactFileSystemAdapter;
  zipExtractor: ZipExtractor;
  artifactStore?: CircuitArtifactStore;
}

export class CircuitArtifactDownloader {
  private readonly options: CircuitArtifactDownloaderOptions;

  constructor(options: CircuitArtifactDownloaderOptions) {
    if (!options.zipUrl) {
      throw new Error("CircuitArtifactDownloader requires zipUrl.");
    }
    if (!options.requiredCircuits.length) {
      throw new Error("CircuitArtifactDownloader requires at least one required circuit.");
    }
    this.options = options;
  }

  async prepare(): Promise<CircuitArtifactDownloadResult> {
    const cacheDir = this.cacheDir();
    const zipPath = joinUri(cacheDir, this.zipFileName());
    const extractDir = joinUri(cacheDir, this.options.extractDirName ?? "extracted");

    await this.options.fileSystem.makeDirectory(cacheDir);
    await this.options.fileSystem.makeDirectory(extractDir);

    if (this.options.forceRefresh) {
      await this.options.fileSystem.deleteFile?.(zipPath);
      await this.options.fileSystem.deleteFile?.(extractDir);
      await this.options.fileSystem.makeDirectory(cacheDir);
      await this.options.fileSystem.makeDirectory(extractDir);
    }

    this.emitStatus("validating");
    let resolved = await this.resolveExtracted(extractDir);
    if (resolved.missing.length === 0) {
      const store = this.registerDescriptors(resolved.descriptors);
      this.emitStatus("registered");
      return {
        status: "already-cached",
        zipPath,
        extractDir,
        descriptors: resolved.descriptors,
        store
      };
    }

    let status: CircuitArtifactDownloadResult["status"] = "already-cached";
    if (!(await this.options.fileSystem.exists(zipPath))) {
      this.emitStatus("downloading");
      await this.options.fileSystem.downloadFile(this.options.zipUrl, zipPath);
      status = "downloaded";
    }

    this.emitStatus("extracting");
    try {
      await this.options.zipExtractor.extract(zipPath, extractDir);
    } catch (error) {
      if (isZipCorruptionError(error)) {
        await this.options.fileSystem.deleteFile?.(zipPath);
        throw new Error("Circuit ZIP is incomplete or corrupted. Please retry download.");
      }
      throw error;
    }

    this.emitStatus("validating");
    resolved = await this.resolveExtracted(extractDir);
    if (resolved.missing.length > 0) {
      throw new Error(formatMissingZipCircuitArtifacts(resolved.missing));
    }

    const store = this.registerDescriptors(resolved.descriptors);
    this.emitStatus("registered");

    return {
      status,
      zipPath,
      extractDir,
      descriptors: resolved.descriptors,
      store
    };
  }

  private async resolveExtracted(extractDir: string) {
    return resolveZipCircuitArtifacts({
      extractDir,
      requiredCircuits: this.options.requiredCircuits,
      expectedFiles: this.options.expectedFiles,
      checksums: this.options.checksums,
      version: this.options.version,
      fileExists: (path) => this.options.fileSystem.exists(path),
      sha256: this.options.fileSystem.sha256
    });
  }

  private cacheDir(): string {
    const baseDir =
      this.options.cacheDir ??
      this.options.fileSystem.cacheDirectory ??
      this.options.fileSystem.documentDirectory;
    if (!baseDir) {
      throw new Error("CircuitArtifactDownloader requires cacheDir or FileSystem cache/document directory.");
    }
    return joinUri(baseDir, "privado-id-circuits");
  }

  private zipFileName(): string {
    if (this.options.zipFileName) {
      return this.options.zipFileName;
    }
    const parsed = this.options.zipUrl.split("?")[0]?.split("/").pop();
    return parsed && parsed.endsWith(".zip") ? parsed : "circuits.zip";
  }

  private registerDescriptors(descriptors: CircuitArtifactDescriptor[]): CircuitArtifactStore {
    const store = this.options.artifactStore ?? new CircuitArtifactStore();
    for (const descriptor of descriptors) {
      store.register(descriptor);
    }
    return store;
  }

  private emitStatus(status: CircuitArtifactDownloadStatus): void {
    this.options.onStatus?.(status);
  }
}

function isZipCorruptionError(error: unknown): boolean {
  const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  return message.includes("zip headers not found") || message.includes("not a zip file");
}
