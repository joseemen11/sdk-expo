import { CircuitId } from "./CircuitId";
import type { CircuitArtifactDescriptor } from "../types";

export interface ZipCircuitExpectedFiles {
  dat?: string;
  wcd?: string;
  zkey: string;
  verificationKey?: string;
}

export type ZipCircuitExpectedFileMap = Partial<Record<CircuitId, ZipCircuitExpectedFiles>>;

export interface ZipCircuitArtifactResolverOptions {
  extractDir: string;
  requiredCircuits: CircuitId[];
  expectedFiles?: ZipCircuitExpectedFileMap;
  version?: string;
  fileExists: (path: string) => Promise<boolean> | boolean;
  checksums?: Record<string, string>;
  sha256?: (path: string) => Promise<string> | string;
}

export interface ZipCircuitArtifactResolveResult {
  descriptors: CircuitArtifactDescriptor[];
  missing: string[];
}

export const defaultZipCircuitExpectedFiles: ZipCircuitExpectedFileMap = {
  [CircuitId.AuthV2]: {
    dat: "authV2.dat",
    wcd: "authV2.wcd",
    zkey: "authV2.zkey"
  },
  [CircuitId.CredentialAtomicQuerySigV2]: {
    dat: "credentialAtomicQuerySigV2.dat",
    wcd: "credentialAtomicQuerySigV2.wcd",
    zkey: "credentialAtomicQuerySigV2.zkey"
  },
  [CircuitId.CredentialAtomicQuerySigV2OnChain]: {
    dat: "credentialAtomicQuerySigV2OnChain.dat",
    wcd: "credentialAtomicQuerySigV2OnChain.wcd",
    zkey: "credentialAtomicQuerySigV2OnChain.zkey"
  },
  [CircuitId.CredentialAtomicQueryMTPV2]: {
    dat: "credentialAtomicQueryMTPV2.dat",
    wcd: "credentialAtomicQueryMTPV2.wcd",
    zkey: "credentialAtomicQueryMTPV2.zkey"
  },
  [CircuitId.CredentialAtomicQueryMTPV2OnChain]: {
    dat: "credentialAtomicQueryMTPV2OnChain.dat",
    wcd: "credentialAtomicQueryMTPV2OnChain.wcd",
    zkey: "credentialAtomicQueryMTPV2OnChain.zkey"
  }
};

export async function resolveZipCircuitArtifacts(
  options: ZipCircuitArtifactResolverOptions
): Promise<ZipCircuitArtifactResolveResult> {
  const expectedFiles = {
    ...defaultZipCircuitExpectedFiles,
    ...options.expectedFiles
  };
  const descriptors: CircuitArtifactDescriptor[] = [];
  const missing: string[] = [];

  for (const circuitId of options.requiredCircuits) {
    const files = expectedFiles[circuitId];
    if (!files) {
      missing.push(`Missing expected file mapping for circuit: ${circuitId}`);
      continue;
    }

    const datPath = files.dat ? joinUri(options.extractDir, files.dat) : undefined;
    const graphPath = files.wcd ? joinUri(options.extractDir, files.wcd) : undefined;
    const zkeyPath = joinUri(options.extractDir, files.zkey);
    const verificationKeyPath = files.verificationKey
      ? joinUri(options.extractDir, files.verificationKey)
      : undefined;

    await requireExistingFile(options, zkeyPath, files.zkey, missing);
    if (graphPath) {
      await requireExistingFile(options, graphPath, files.wcd as string, missing);
    } else {
      missing.push(`Missing required circuit artifact: ${circuitId}.wcd`);
    }
    if (verificationKeyPath) {
      await requireExistingFile(options, verificationKeyPath, files.verificationKey as string, missing);
    }

    descriptors.push({
      circuitId,
      version: options.version,
      datPath,
      graphPath,
      zkeyPath,
      verificationKeyPath,
      hashes: await resolveHashes(options, [
        ["dat", datPath],
        ["graph", graphPath],
        ["zkey", zkeyPath],
        ["verificationKey", verificationKeyPath]
      ])
    });
  }

  return {
    descriptors,
    missing
  };
}

export function formatMissingZipCircuitArtifacts(missing: readonly string[]): string {
  return missing.join("\n");
}

export function joinUri(base: string, path: string): string {
  return `${base.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

async function requireExistingFile(
  options: ZipCircuitArtifactResolverOptions,
  path: string,
  fileName: string,
  missing: string[]
): Promise<void> {
  if (!(await options.fileExists(path))) {
    missing.push(`Missing required circuit artifact: ${fileName}`);
    return;
  }
  await verifyChecksum(options, path, fileName);
}

async function verifyChecksum(
  options: ZipCircuitArtifactResolverOptions,
  path: string,
  fileName: string
): Promise<void> {
  const expected = options.checksums?.[fileName];
  if (!expected) {
    return;
  }
  if (!options.sha256) {
    throw new Error(`Checksum configured for ${fileName}, but no sha256 adapter was provided.`);
  }
  const actual = await options.sha256(path);
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`Checksum mismatch for circuit artifact: ${fileName}.`);
  }
}

async function resolveHashes(
  options: ZipCircuitArtifactResolverOptions,
  entries: Array<[keyof NonNullable<CircuitArtifactDescriptor["hashes"]>, string | undefined]>
) {
  const hashes: NonNullable<CircuitArtifactDescriptor["hashes"]> = {};
  for (const [label, path] of entries) {
    if (!path) {
      continue;
    }
    const fileName = path.split("/").pop();
    if (fileName && options.checksums?.[fileName]) {
      hashes[label] = options.checksums[fileName];
    }
  }
  return Object.keys(hashes).length > 0 ? hashes : undefined;
}
