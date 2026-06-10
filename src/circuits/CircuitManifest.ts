import { CircuitId } from "./CircuitId";
import type { CircuitArtifactManifest } from "../types";

export const requiredCircuitIds: readonly CircuitId[] = [
  CircuitId.AuthV2,
  CircuitId.CredentialAtomicQuerySigV2,
  CircuitId.CredentialAtomicQuerySigV2OnChain,
  CircuitId.CredentialAtomicQueryMTPV2,
  CircuitId.CredentialAtomicQueryMTPV2OnChain
];

export function createEmptyCircuitManifest(): CircuitArtifactManifest {
  return { artifacts: [] };
}
