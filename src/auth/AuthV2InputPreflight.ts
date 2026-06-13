import { deriveHolderId } from "./MobileGistProofSource";
import type { AuthV2WitnessInputs } from "./AuthV2InputBuilder";

const authV2MtLevel = 40;
const authV2OnChainMtLevel = 64;
const bn254FieldModulus = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

export interface AuthV2NativeWitnessInputs extends Record<string, unknown> {
  genesisID: string;
  profileNonce: string;
  authClaim: string[];
  authClaimIncMtp: string[];
  authClaimNonRevMtp: string[];
  challenge: string;
  challengeSignatureR8x: string;
  challengeSignatureR8y: string;
  challengeSignatureS: string;
  claimsTreeRoot: string;
  revTreeRoot: string;
  rootsTreeRoot: string;
  state: string;
  gistRoot: string;
  gistMtp: string[];
  authClaimNonRevMtpAuxHi: string;
  authClaimNonRevMtpAuxHv: string;
  authClaimNonRevMtpNoAux: string;
  gistMtpAuxHi: string;
  gistMtpAuxHv: string;
  gistMtpNoAux: string;
}

export interface AuthV2InputsPreview {
  ready: boolean;
  nativeReady: boolean;
  fields: string[];
  authClaimSlots: number;
  challenge: "decimal bigint string";
  siblingsCount: number;
  nonRevSiblingsCount: number;
  gistSiblingsCount: number;
  signaturePresent: boolean;
  rootsStatePresent: boolean;
}

export const authV2NativeRequiredFields = [
  "genesisID",
  "profileNonce",
  "authClaim",
  "authClaimIncMtp",
  "authClaimNonRevMtp",
  "challenge",
  "challengeSignatureR8x",
  "challengeSignatureR8y",
  "challengeSignatureS",
  "claimsTreeRoot",
  "revTreeRoot",
  "rootsTreeRoot",
  "state",
  "gistRoot",
  "gistMtp",
  "authClaimNonRevMtpAuxHi",
  "authClaimNonRevMtpAuxHv",
  "authClaimNonRevMtpNoAux",
  "gistMtpAuxHi",
  "gistMtpAuxHv",
  "gistMtpNoAux"
] as const;

export function buildAuthV2InputsPreview(inputs: AuthV2WitnessInputs): AuthV2InputsPreview {
  const nativeInputs = assertAuthV2InputsReadyForNativeWitness(inputs);
  return {
    ready: true,
    nativeReady: true,
    fields: [...authV2NativeRequiredFields],
    authClaimSlots: nativeInputs.authClaim.length,
    challenge: "decimal bigint string",
    siblingsCount: nativeInputs.authClaimIncMtp.length,
    nonRevSiblingsCount: nativeInputs.authClaimNonRevMtp.length,
    gistSiblingsCount: nativeInputs.gistMtp.length,
    signaturePresent: Boolean(
      nativeInputs.challengeSignatureR8x && nativeInputs.challengeSignatureR8y && nativeInputs.challengeSignatureS
    ),
    rootsStatePresent: Boolean(
      nativeInputs.claimsTreeRoot && nativeInputs.revTreeRoot && nativeInputs.rootsTreeRoot && nativeInputs.state
    )
  };
}

export function assertAuthV2InputsReadyForNativeWitness(inputs: AuthV2WitnessInputs): AuthV2NativeWitnessInputs {
  try {
    const nativeInputs = toAuthV2NativeWitnessInputs(inputs);
    assertAuthV2InputsWithinField(nativeInputs);
    return nativeInputs;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.startsWith("AuthV2 inputs overflow before witness:")) {
      throw error;
    }
    throw new Error(`AuthV2 inputs are not ready for native witness: ${message}`);
  }
}

export function coerceAuthV2NativeWitnessInputs(inputs: Record<string, unknown> | undefined): AuthV2NativeWitnessInputs {
  if (!inputs) {
    throw new Error("AuthV2 inputs are not ready for native witness: witness inputs are missing.");
  }
  if ("challengeSignatureR8x" in inputs || "challengeSignatureR8y" in inputs || "challengeSignatureS" in inputs) {
    return validateNativeWitnessInputs(inputs);
  }
  return assertAuthV2InputsReadyForNativeWitness(inputs as AuthV2WitnessInputs);
}

function toAuthV2NativeWitnessInputs(inputs: AuthV2WitnessInputs): AuthV2NativeWitnessInputs {
  const genesisID = normalizeGenesisId(inputs.genesisID);
  const authClaimNonRevAux = auxFromProofLike(
    inputs.authClaimNonRevMtp,
    inputs.authClaimNonRevMtpAuxHi,
    inputs.authClaimNonRevMtpAuxHv,
    inputs.authClaimNonRevMtpNoAux,
    "authClaimNonRevMtp"
  );
  const gistAux = auxFromProofLike(
    inputs.gistMtp,
    inputs.gistMtpAuxHi,
    inputs.gistMtpAuxHv,
    inputs.gistMtpNoAux,
    "gistMtp"
  );
  const signature = normalizeSignature(inputs.challengeSignature);

  return {
    genesisID,
    profileNonce: decimalString(inputs.profileNonce, "profileNonce"),
    authClaim: stringArray(inputs.authClaim, "authClaim", 8),
    authClaimIncMtp: siblingsArray(inputs.authClaimIncMtp, "authClaimIncMtp", authV2MtLevel),
    authClaimNonRevMtp: siblingsArray(inputs.authClaimNonRevMtp, "authClaimNonRevMtp", authV2MtLevel),
    challenge: decimalString(inputs.challenge, "challenge"),
    challengeSignatureR8x: decimalString(signature.R8[0], "challengeSignatureR8x"),
    challengeSignatureR8y: decimalString(signature.R8[1], "challengeSignatureR8y"),
    challengeSignatureS: decimalString(signature.S, "challengeSignatureS"),
    claimsTreeRoot: decimalString(inputs.claimsTreeRoot, "claimsTreeRoot"),
    revTreeRoot: decimalString(inputs.revTreeRoot, "revTreeRoot"),
    rootsTreeRoot: decimalString(inputs.rootsTreeRoot, "rootsTreeRoot"),
    state: decimalString(inputs.state, "state"),
    gistRoot: decimalString(inputs.gistRoot, "gistRoot"),
    gistMtp: siblingsArray(inputs.gistMtp, "gistMtp", authV2OnChainMtLevel),
    authClaimNonRevMtpAuxHi: authClaimNonRevAux.hi,
    authClaimNonRevMtpAuxHv: authClaimNonRevAux.hv,
    authClaimNonRevMtpNoAux: authClaimNonRevAux.noAux,
    gistMtpAuxHi: gistAux.hi,
    gistMtpAuxHv: gistAux.hv,
    gistMtpNoAux: gistAux.noAux
  };
}

function validateNativeWitnessInputs(inputs: Record<string, unknown>): AuthV2NativeWitnessInputs {
  try {
    const nativeInputs: AuthV2NativeWitnessInputs = {
      genesisID: decimalString(inputs.genesisID, "genesisID"),
      profileNonce: decimalString(inputs.profileNonce, "profileNonce"),
      authClaim: stringArray(inputs.authClaim, "authClaim", 8),
      authClaimIncMtp: siblingsArray(inputs.authClaimIncMtp, "authClaimIncMtp", authV2MtLevel),
      authClaimNonRevMtp: siblingsArray(inputs.authClaimNonRevMtp, "authClaimNonRevMtp", authV2MtLevel),
      challenge: decimalString(inputs.challenge, "challenge"),
      challengeSignatureR8x: decimalString(inputs.challengeSignatureR8x, "challengeSignatureR8x"),
      challengeSignatureR8y: decimalString(inputs.challengeSignatureR8y, "challengeSignatureR8y"),
      challengeSignatureS: decimalString(inputs.challengeSignatureS, "challengeSignatureS"),
      claimsTreeRoot: decimalString(inputs.claimsTreeRoot, "claimsTreeRoot"),
      revTreeRoot: decimalString(inputs.revTreeRoot, "revTreeRoot"),
      rootsTreeRoot: decimalString(inputs.rootsTreeRoot, "rootsTreeRoot"),
      state: decimalString(inputs.state, "state"),
      gistRoot: decimalString(inputs.gistRoot, "gistRoot"),
      gistMtp: siblingsArray(inputs.gistMtp, "gistMtp", authV2OnChainMtLevel),
      authClaimNonRevMtpAuxHi: decimalString(inputs.authClaimNonRevMtpAuxHi, "authClaimNonRevMtpAuxHi"),
      authClaimNonRevMtpAuxHv: decimalString(inputs.authClaimNonRevMtpAuxHv, "authClaimNonRevMtpAuxHv"),
      authClaimNonRevMtpNoAux: noAuxString(inputs.authClaimNonRevMtpNoAux, "authClaimNonRevMtpNoAux"),
      gistMtpAuxHi: decimalString(inputs.gistMtpAuxHi, "gistMtpAuxHi"),
      gistMtpAuxHv: decimalString(inputs.gistMtpAuxHv, "gistMtpAuxHv"),
      gistMtpNoAux: noAuxString(inputs.gistMtpNoAux, "gistMtpNoAux")
    };
    assertAuthV2InputsWithinField(nativeInputs);
    return nativeInputs;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.startsWith("AuthV2 inputs overflow before witness:")) {
      throw error;
    }
    throw new Error(`AuthV2 inputs are not ready for native witness: ${message}`);
  }
}

export function assertAuthV2InputsWithinField(inputs: AuthV2NativeWitnessInputs): void {
  for (const [field, value] of Object.entries(inputs)) {
    if (Array.isArray(value)) {
      value.forEach((item, index) => assertFieldValue(item, `${field}[${index}]`));
    } else if (typeof value === "string") {
      assertFieldValue(value, field);
    }
  }
}

function assertFieldValue(value: string, field: string): void {
  const parsed = BigInt(decimalString(value, field));
  if (parsed < 0n || parsed >= bn254FieldModulus) {
    throw new Error(`AuthV2 inputs overflow before witness: ${field}`);
  }
}

function normalizeGenesisId(value: unknown): string {
  if (typeof value === "string" && value.startsWith("did:")) {
    return deriveHolderId(value);
  }
  return decimalString(value, "genesisID");
}

function normalizeSignature(value: unknown): { R8: [unknown, unknown]; S: unknown } {
  if (!isRecord(value)) {
    throw new Error("challengeSignature must be an object with R8 and S.");
  }
  if (Array.isArray(value.R8) && value.R8.length === 2) {
    return {
      R8: [value.R8[0], value.R8[1]],
      S: value.S
    };
  }
  const r8x = value.r8x ?? value.R8x;
  const r8y = value.r8y ?? value.R8y;
  const s = value.s ?? value.S;
  if (r8x !== undefined && r8y !== undefined && s !== undefined) {
    return {
      R8: [r8x, r8y],
      S: s
    };
  }
  throw new Error("challengeSignature must include R8[0], R8[1], and S.");
}

function auxFromProofLike(
  proofLike: unknown,
  explicitHi: unknown,
  explicitHv: unknown,
  explicitNoAux: unknown,
  field: string
): { hi: string; hv: string; noAux: string } {
  if (explicitHi !== undefined && explicitHv !== undefined && explicitNoAux !== undefined) {
    return {
      hi: decimalString(explicitHi, `${field}AuxHi`),
      hv: decimalString(explicitHv, `${field}AuxHv`),
      noAux: noAuxString(explicitNoAux, `${field}NoAux`)
    };
  }

  const record = isRecord(proofLike) ? proofLike : undefined;
  const proof = record && isRecord(record.proof) ? record.proof : undefined;
  const nodeAux = proof && (isRecord(proof.node_aux) ? proof.node_aux : isRecord(proof.nodeAux) ? proof.nodeAux : undefined);
  if (nodeAux) {
    return {
      hi: decimalString(nodeAux.key, `${field}AuxHi`),
      hv: decimalString(nodeAux.value, `${field}AuxHv`),
      noAux: "0"
    };
  }

  return {
    hi: "0",
    hv: "0",
    noAux: "1"
  };
}

function siblingsArray(value: unknown, field: string, expectedLevels: number): string[] {
  let siblings: string[];
  if (Array.isArray(value)) {
    siblings = value.map((item, index) => decimalString(item, `${field}[${index}]`));
  } else if (isRecord(value) && Array.isArray(value.siblings)) {
    siblings = value.siblings.map((item, index) => decimalString(item, `${field}.siblings[${index}]`));
  } else {
    throw new Error(`${field} must be an array of sibling bigint strings.`);
  }
  if (siblings.length > expectedLevels) {
    throw new Error(`${field} must have at most ${expectedLevels} siblings.`);
  }
  while (siblings.length < expectedLevels) {
    siblings.push("0");
  }
  return siblings;
}

function stringArray(value: unknown, field: string, expectedLength?: number): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be a circuit marshal array.`);
  }
  if (expectedLength !== undefined && value.length !== expectedLength) {
    throw new Error(`${field} must be a circuit marshal array.`);
  }
  return value.map((item, index) => decimalString(item, `${field}[${index}]`));
}

function decimalString(value: unknown, field: string): string {
  const normalized = typeof value === "bigint" ? value.toString() : typeof value === "number" ? String(value) : value;
  if (typeof normalized !== "string" || !/^(0|[1-9][0-9]*)$/.test(normalized)) {
    throw new Error(`${field} must be a decimal bigint string.`);
  }
  return normalized;
}

function noAuxString(value: unknown, field: string): string {
  if (typeof value === "boolean") {
    throw new Error(`${field} must be a decimal bigint string.`);
  }
  const normalized = decimalString(value, field);
  if (normalized !== "0" && normalized !== "1") {
    throw new Error(`${field} must be 0 or 1.`);
  }
  return normalized;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
