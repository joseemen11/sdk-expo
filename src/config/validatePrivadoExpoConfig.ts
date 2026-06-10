import { CircuitArtifactRegistry } from "../circuits/CircuitArtifactRegistry";
import type { PrivadoExpoConfig } from "../types";

const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;

export function validatePrivadoExpoConfig(config: PrivadoExpoConfig): PrivadoExpoConfig {
  requireString(config.network?.name, "network.name");
  requirePositiveInteger(config.network?.chainId, "network.chainId");
  requireAddress(config.contracts?.stateContractAddress, "contracts.stateContractAddress");
  requireAddress(config.contracts?.universalVerifierAddress, "contracts.universalVerifierAddress");
  requireString(config.didResolver?.didResolverUrl, "didResolver.didResolverUrl");

  if (config.network.rpcUrl !== undefined) {
    requireString(config.network.rpcUrl, "network.rpcUrl");
  }

  if (config.issuer) {
    requireString(config.issuer.issuerDid, "issuer.issuerDid");
  }

  if (config.credential) {
    requireString(config.credential.credentialType, "credential.credentialType");
    requireString(config.credential.credentialSchema, "credential.credentialSchema");
    if (Array.isArray(config.credential.credentialContext)) {
      config.credential.credentialContext.forEach((context, index) =>
        requireString(context, `credential.credentialContext[${index}]`)
      );
    } else {
      requireString(config.credential.credentialContext, "credential.credentialContext");
    }
  }

  if (config.circuits) {
    new CircuitArtifactRegistry(config.circuits).validate();
  }

  return {
    ...config,
    network: { ...config.network },
    contracts: { ...config.contracts },
    didResolver: { ...config.didResolver },
    issuer: config.issuer ? { ...config.issuer } : undefined,
    credential: config.credential ? { ...config.credential } : undefined,
    verifier: config.verifier ? { ...config.verifier } : undefined,
    circuits: config.circuits ? { artifacts: [...config.circuits.artifacts] } : undefined
  };
}

function requireString(value: unknown, path: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`Invalid PrivadoExpoConfig: ${path} is required.`);
  }
}

function requirePositiveInteger(value: unknown, path: string): asserts value is number {
  if (!Number.isInteger(value) || Number(value) <= 0) {
    throw new Error(`Invalid PrivadoExpoConfig: ${path} must be a positive integer.`);
  }
}

function requireAddress(value: unknown, path: string): asserts value is string {
  requireString(value, path);
  if (!ADDRESS_PATTERN.test(value)) {
    throw new Error(`Invalid PrivadoExpoConfig: ${path} must be an EVM address.`);
  }
}
