import { base64ToBytes, bytesToBase64, bytesToText, textToBytes } from "../network/Base64UrlCodec";

export interface EncryptedPayloadEnvelope {
  v: 1;
  alg: "XChaCha20-Poly1305";
  nonce: string;
  ciphertext: string;
}

export async function encryptCredentialPayload(input: {
  credential: unknown;
  key: Uint8Array;
  nonce: Uint8Array;
  associatedData: string;
}): Promise<string> {
  assertKey(input.key);
  assertNonce(input.nonce);
  const { xchacha20poly1305 } = await import("@noble/ciphers/chacha.js");
  const cipher = xchacha20poly1305(input.key, input.nonce, textToBytes(input.associatedData));
  const ciphertext = cipher.encrypt(textToBytes(JSON.stringify(input.credential)));
  const envelope: EncryptedPayloadEnvelope = {
    v: 1,
    alg: "XChaCha20-Poly1305",
    nonce: bytesToBase64(input.nonce),
    ciphertext: bytesToBase64(ciphertext)
  };
  return JSON.stringify(envelope);
}

export async function decryptCredentialPayload(input: {
  encryptedPayload: string;
  key: Uint8Array;
  associatedData: string;
}): Promise<unknown> {
  assertKey(input.key);
  const envelope = JSON.parse(input.encryptedPayload) as EncryptedPayloadEnvelope;
  if (envelope.v !== 1 || envelope.alg !== "XChaCha20-Poly1305") {
    throw new Error("Encrypted credential payload version is not supported.");
  }
  const nonce = base64ToBytes(envelope.nonce);
  assertNonce(nonce);
  const { xchacha20poly1305 } = await import("@noble/ciphers/chacha.js");
  const cipher = xchacha20poly1305(input.key, nonce, textToBytes(input.associatedData));
  const plain = cipher.decrypt(base64ToBytes(envelope.ciphertext));
  return JSON.parse(bytesToText(plain)) as unknown;
}

function assertKey(key: Uint8Array): void {
  if (key.byteLength !== 32) {
    throw new Error("Credential encryption key must be 32 bytes.");
  }
}

function assertNonce(nonce: Uint8Array): void {
  if (nonce.byteLength !== 24) {
    throw new Error("Credential encryption nonce must be 24 bytes.");
  }
}
