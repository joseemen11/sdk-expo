import { bytesToBase64 } from "../network/Base64UrlCodec";
import { createEncryptionKey } from "../storage/createEncryptionKey";
import type { KMSAdapter, KMSKeyHandle, SignChallengeInput, SignChallengeResult } from "../types";
import { SecurePrivateKeyStore } from "./SecurePrivateKeyStore";

export class BjjKmsAdapter implements KMSAdapter {
  async createOrLoadKey(_input: { keyId?: string; algorithm?: string }): Promise<KMSKeyHandle> {
    throw new Error("BJJ KMS integration is required to create a real Privado ID holder DID.");
  }

  async signChallenge(_input: SignChallengeInput): Promise<SignChallengeResult> {
    throw new Error("BJJ KMS integration is required to sign challenges.");
  }

  async deleteKey(_keyId: string): Promise<void> {
    return undefined;
  }

  async sign(_payload: Uint8Array, _keyId?: string): Promise<Uint8Array> {
    throw new Error("BJJ KMS integration is required to sign payloads.");
  }
}

export interface DevelopmentOnlyKmsAdapterOptions {
  privateKeyStore: SecurePrivateKeyStore;
  randomBytes?: (byteLength: number) => Uint8Array;
}

export class DevelopmentOnlyKmsAdapter implements KMSAdapter {
  private readonly privateKeyStore: SecurePrivateKeyStore;
  private readonly randomBytes?: (byteLength: number) => Uint8Array;

  constructor(options: DevelopmentOnlyKmsAdapterOptions) {
    this.privateKeyStore = options.privateKeyStore;
    this.randomBytes = options.randomBytes;
  }

  async createOrLoadKey(input: { keyId?: string; algorithm?: string }): Promise<KMSKeyHandle> {
    const keyId = input.keyId ?? `dev-${bytesToHex(this.createRandomBytes(16))}`;
    const result = await this.privateKeyStore.ensureKey(keyId);
    return {
      keyId,
      algorithm: input.algorithm ?? "development-hmac-sha256",
      created: result.created,
      developmentOnly: true
    };
  }

  async signChallenge(input: SignChallengeInput): Promise<SignChallengeResult> {
    if (!input.keyId) {
      throw new Error("keyId is required to sign a challenge.");
    }
    const signature = await this.privateKeyStore.signDevelopmentChallenge({
      keyId: input.keyId,
      challenge: input.challenge
    });
    return {
      keyId: input.keyId,
      algorithm: "development-hmac-sha256",
      signature: bytesToBase64(signature),
      signatureEncoding: "base64",
      developmentOnly: true
    };
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.privateKeyStore.deleteKey(keyId);
  }

  async sign(payload: Uint8Array, keyId?: string): Promise<Uint8Array> {
    if (!keyId) {
      throw new Error("keyId is required to sign a payload.");
    }
    return this.privateKeyStore.signDevelopmentChallenge({ keyId, challenge: payload });
  }

  private createRandomBytes(byteLength: number): Uint8Array {
    return this.randomBytes ? this.randomBytes(byteLength) : createEncryptionKey({ byteLength });
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
