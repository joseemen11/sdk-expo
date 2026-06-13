import { bytesToBase64, textToBytes } from "../network/Base64UrlCodec";
import { MobileIdentityStorage, type MobileAuthV2IdentityMaterial } from "../identity/MobileIdentityStorage";
import { MobileMerkleTreeStorage } from "../identity/MobileMerkleTreeStorage";
import { bjjSignatureFromCompressed } from "../kms/MobileBjjKmsAdapter";
import type { KMSAdapter, SecureKeyStore, StorageAdapter } from "../types";
import type {
  AuthV2AuthClaimProof,
  AuthV2ChallengeSignature,
  AuthV2ChallengeSigner,
  AuthV2GistProof,
  AuthV2IdentityProofSource,
  AuthV2InputBuilderContext,
  AuthV2TreeState
} from "./AuthV2InputBuilder";
import type { MobileGistProofSource } from "./MobileGistProofSource";
import { toAuthV2GistProof } from "./MobileGistProofSource";

declare function require(moduleName: string): unknown;

interface Iden3CoreRuntime {
  Claim: {
    newClaim(schemaHash: unknown, ...args: unknown[]): {
      marshalJson(): string[];
    };
  };
  ClaimOptions: {
    withIndexDataInts(slotA: bigint | null, slotB: bigint | null): unknown;
    withRevocationNonce(nonce: bigint): unknown;
  };
  SchemaHash: { authSchemaHash: unknown };
}

const Iden3Core = require("@iden3/js-iden3-core") as Iden3CoreRuntime;
const UINT256_BYTES = 32;

export interface MobileAuthV2IdentityProofSourceOptions {
  metadataStore?: StorageAdapter<string>;
  secureKeyStore?: SecureKeyStore;
  identityStorage?: MobileIdentityStorage;
  merkleTreeStorage?: MobileMerkleTreeStorage;
  gistProofSource?: MobileGistProofSource;
}

export class MobileAuthV2IdentityProofSource implements AuthV2IdentityProofSource {
  private readonly identityStorage: MobileIdentityStorage;
  private readonly merkleTreeStorage: MobileMerkleTreeStorage;
  private readonly gistProofSource?: MobileGistProofSource;

  constructor(options: MobileAuthV2IdentityProofSourceOptions = {}) {
    this.identityStorage =
      options.identityStorage ??
      new MobileIdentityStorage({
        recordStore: options.metadataStore,
        secureKeyStore: options.secureKeyStore
      });
    this.merkleTreeStorage =
      options.merkleTreeStorage ??
      new MobileMerkleTreeStorage({
        recordStore: options.metadataStore,
        secureKeyStore: options.secureKeyStore
      });
    this.gistProofSource = options.gistProofSource;
  }

  async getAuthClaimProof(input: AuthV2InputBuilderContext): Promise<AuthV2AuthClaimProof | undefined> {
    const material = await this.getMaterial(input);
    if (!material) {
      return undefined;
    }
    const inclusionProof = await this.merkleTreeStorage.generateInclusionProof(
      input.runtime.holderDid.did,
      0,
      BigInt(material.authClaimHi)
    );
    if (!material.authClaimRevocationNonce) {
      throw new Error("AuthV2 revocation nonce source could not be determined safely.");
    }
    const nonRevocationProof = await this.merkleTreeStorage.generateProof(
      input.runtime.holderDid.did,
      1,
      BigInt(material.authClaimRevocationNonce)
    );
    if (nonRevocationProof.root !== material.revTreeRoot) {
      throw new Error("AuthV2 revocation root mismatch.");
    }
    if (nonRevocationProof.existence) {
      throw new Error("AuthV2 non-revocation proof could not be generated for auth claim.");
    }
    return {
      authClaim: marshalAuthClaimForCircuit(material),
      authClaimIncMtp: inclusionProof,
      authClaimNonRevMtp: nonRevocationProof
    };
  }

  async getTreeState(input: AuthV2InputBuilderContext): Promise<AuthV2TreeState | undefined> {
    const material = await this.getMaterial(input);
    if (!material) {
      return undefined;
    }
    return {
      claimsTreeRoot: material.claimsTreeRoot,
      revTreeRoot: material.revTreeRoot,
      rootsTreeRoot: material.rootsTreeRoot,
      state: material.state
    };
  }

  async getGistProof(input: AuthV2InputBuilderContext): Promise<AuthV2GistProof | undefined> {
    const material = await this.getMaterial(input);
    if (!material) {
      return undefined;
    }
    if (!this.gistProofSource) {
      throw new Error("AuthV2 GIST resolver is not configured.");
    }
    const gistProof = await this.gistProofSource.getGISTProof(input.runtime.holderDid.did, {
      network: input.runtime.holderDid.network,
      isStateGenesis: material.isStateGenesis
    });
    return gistProof ? toAuthV2GistProof(gistProof) : undefined;
  }

  private async getMaterial(input: AuthV2InputBuilderContext): Promise<MobileAuthV2IdentityMaterial | undefined> {
    return this.identityStorage.getAuthV2IdentityMaterial(input.runtime.holderDid.did);
  }
}

export function marshalAuthClaimForCircuit(material: MobileAuthV2IdentityMaterial): string[] {
  if (isDecimalStringArray(material.authClaimMarshal, 8)) {
    return material.authClaimMarshal;
  }
  if (!isRecord(material.authClaim)) {
    throw new Error("AuthV2 auth claim cannot be marshaled for circuit.");
  }
  const publicKeyX = decimalBigInt(material.authClaim.publicKeyX, "authClaim.publicKeyX");
  const publicKeyY = decimalBigInt(material.authClaim.publicKeyY, "authClaim.publicKeyY");
  const revocationNonce = decimalBigInt(
    material.authClaim.revocationNonce ?? material.authClaimRevocationNonce,
    "authClaim.revocationNonce"
  );
  const claim = Iden3Core.Claim.newClaim(
    Iden3Core.SchemaHash.authSchemaHash,
    Iden3Core.ClaimOptions.withIndexDataInts(publicKeyX, publicKeyY),
    Iden3Core.ClaimOptions.withRevocationNonce(revocationNonce)
  );
  return claim.marshalJson();
}

export interface MobileAuthV2ChallengeSignerOptions {
  kmsAdapter?: KMSAdapter;
}

export class MobileAuthV2ChallengeSigner implements AuthV2ChallengeSigner {
  private readonly kmsAdapter?: KMSAdapter;

  constructor(options: MobileAuthV2ChallengeSignerOptions = {}) {
    this.kmsAdapter = options.kmsAdapter;
  }

  async signAuthV2Challenge(input: AuthV2InputBuilderContext): Promise<AuthV2ChallengeSignature | undefined> {
    if (!this.kmsAdapter?.sign) {
      return undefined;
    }
    const challenge = input.request.challenge;
    if (!challenge) {
      return undefined;
    }
    const signature = await this.kmsAdapter.sign(challengeToKmsPayload(challenge), input.runtime.keyId);
    return {
      challengeSignature: signature.byteLength === 64 ? bjjSignatureFromCompressed(signature) : bytesToBase64(signature)
    };
  }
}

function challengeToKmsPayload(value: string): Uint8Array {
  if (/^(0|[1-9][0-9]*)$/.test(value)) {
    return bigIntToFixedLengthBytes(BigInt(value), UINT256_BYTES);
  }
  return textToBytes(value);
}

function bigIntToFixedLengthBytes(value: bigint, byteLength: number): Uint8Array {
  if (value < 0n) {
    throw new Error("AuthV2 challenge must be non-negative.");
  }
  const bytes = new Uint8Array(byteLength);
  let remaining = value;
  for (let index = byteLength - 1; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining > 0n) {
    throw new Error("AuthV2 challenge does not fit in 32 bytes.");
  }
  return bytes;
}

function isDecimalStringArray(value: unknown, expectedLength: number): value is string[] {
  return Array.isArray(value) && value.length === expectedLength && value.every(isDecimalString);
}

function decimalBigInt(value: unknown, field: string): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (typeof value === "string" && isDecimalString(value)) {
    return BigInt(value);
  }
  throw new Error(`${field} must be a decimal bigint string.`);
}

function isDecimalString(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
