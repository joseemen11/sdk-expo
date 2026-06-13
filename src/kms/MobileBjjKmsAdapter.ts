import { bytesToBase64 } from "../network/Base64UrlCodec";
import { createEncryptionKey } from "../storage/createEncryptionKey";
import type { KMSAdapter, KMSKeyHandle, SecureKeyStore, SignChallengeInput, SignChallengeResult } from "../types";
import { MobilePrivateKeyStore } from "./MobilePrivateKeyStore";

declare function require(moduleName: string): unknown;

interface Iden3CryptoRuntime {
  PrivateKey: new (seed: Uint8Array) => {
    hex(): string;
    public(): { hex(): string };
    signPoseidon(message: bigint): {
      R8: [bigint, bigint];
      S: bigint;
      compress(): Uint8Array;
    };
  };
  Signature: { newFromCompressed(value: Uint8Array): { R8: [bigint, bigint]; S: bigint } };
  Hex: { decodeString(value: string): Uint8Array };
}

const Iden3Crypto = require("@iden3/js-crypto") as Iden3CryptoRuntime;

export interface MobileBjjKmsAdapterOptions {
  secureKeyStore: SecureKeyStore;
  privateKeyStore?: MobilePrivateKeyStore;
  randomBytes?: (byteLength: number) => Uint8Array;
}

export class MobileBjjKmsAdapter implements KMSAdapter {
  private readonly privateKeyStore: MobilePrivateKeyStore;
  private readonly randomBytes?: (byteLength: number) => Uint8Array;

  constructor(options: MobileBjjKmsAdapterOptions) {
    this.privateKeyStore =
      options.privateKeyStore ??
      new MobilePrivateKeyStore({
        secureKeyStore: options.secureKeyStore,
        randomBytes: options.randomBytes
      });
    this.randomBytes = options.randomBytes;
  }

  async createOrLoadKey(input: { keyId?: string; algorithm?: string }): Promise<KMSKeyHandle> {
    if (input.keyId) {
      try {
        await this.privateKeyStore.get({ alias: input.keyId });
        return {
          keyId: input.keyId,
          algorithm: input.algorithm ?? "babyjubjub-poseidon",
          created: false,
          developmentOnly: false
        };
      } catch {
        throw new Error("KMS key material is not available for keyId.");
      }
    }

    const privateKey = new Iden3Crypto.PrivateKey(this.createRandomBytes(32));
    const keyId = `BJJ:${privateKey.public().hex()}`;
    await this.privateKeyStore.importKey({
      alias: keyId,
      key: privateKey.hex()
    });
    return {
      keyId,
      algorithm: input.algorithm ?? "babyjubjub-poseidon",
      created: true,
      developmentOnly: false
    };
  }

  async signChallenge(input: SignChallengeInput): Promise<SignChallengeResult> {
    if (!input.keyId) {
      throw new Error("keyId is required to sign a challenge.");
    }
    const payload = typeof input.challenge === "string" ? stringToBytes(input.challenge) : input.challenge;
    const signature = await this.sign(payload, input.keyId);
    return {
      keyId: input.keyId,
      algorithm: "babyjubjub-poseidon",
      signature: bytesToBase64(signature),
      signatureEncoding: "base64",
      developmentOnly: false
    };
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.privateKeyStore.deleteKey(keyId);
  }

  async sign(payload: Uint8Array, keyId?: string): Promise<Uint8Array> {
    if (!keyId) {
      throw new Error("keyId is required to sign a payload.");
    }
    const privateKeyHex = await this.getPrivateKeyHex(keyId);
    const privateKey = new Iden3Crypto.PrivateKey(Iden3Crypto.Hex.decodeString(privateKeyHex));
    return privateKey.signPoseidon(bytesToBigInt(payload)).compress();
  }

  async getPublicKey(keyId?: string): Promise<Uint8Array> {
    if (!keyId) {
      throw new Error("keyId is required to get a public key.");
    }
    const privateKeyHex = await this.getPrivateKeyHex(keyId);
    const privateKey = new Iden3Crypto.PrivateKey(Iden3Crypto.Hex.decodeString(privateKeyHex));
    return Iden3Crypto.Hex.decodeString(privateKey.public().hex());
  }

  private async getPrivateKeyHex(keyId: string): Promise<string> {
    try {
      return await this.privateKeyStore.get({ alias: keyId });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("KMS key material is not available")) {
        throw new Error("KMS key material is not available for keyId.");
      }
      throw error;
    }
  }

  private createRandomBytes(byteLength: number): Uint8Array {
    return this.randomBytes ? this.randomBytes(byteLength) : createEncryptionKey({ byteLength });
  }
}

export function bjjSignatureFromCompressed(signature: Uint8Array): {
  R8: [string, string];
  S: string;
} {
  if (signature.byteLength !== 64) {
    throw new Error("BJJ signature must be 64 bytes.");
  }
  const decoded = decodeBjjCompressedSignature(signature);
  return {
    R8: [decoded.R8[0].toString(), decoded.R8[1].toString()],
    S: decoded.S.toString()
  };
}

function decodeBjjCompressedSignature(signature: Uint8Array): {
  R8: [bigint, bigint];
  S: bigint;
} {
  const decoded = Iden3Crypto.Signature.newFromCompressed(signature);
  return {
    R8: decoded.R8,
    S: decoded.S
  };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) + BigInt(byte);
  }
  return value;
}

function stringToBytes(value: string): Uint8Array {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(value);
  }
  return Uint8Array.from(Array.from(value, (char) => char.charCodeAt(0)));
}
