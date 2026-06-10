export interface Base64UrlCodec {
  encode(input: string | Uint8Array): string;
  decode(input: string): string;
  decodeToBytes(input: string): Uint8Array;
}

type BufferLike = Uint8Array & { toString(encoding: string): string };
type BufferConstructorLike = {
  from(input: Uint8Array | string, encoding?: string): BufferLike;
};

export const portableBase64UrlCodec: Base64UrlCodec = {
  encode(input) {
    const bytes = typeof input === "string" ? textToBytes(input) : input;
    return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  },
  decode(input) {
    return bytesToText(this.decodeToBytes(input));
  },
  decodeToBytes(input) {
    return base64ToBytes(toBase64(input));
  }
};

export function textToBytes(value: string): Uint8Array {
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(value);
  }
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i += 1) {
    out[i] = value.charCodeAt(i) & 0xff;
  }
  return out;
}

export function bytesToText(bytes: Uint8Array): string {
  if (typeof TextDecoder !== "undefined") {
    return new TextDecoder().decode(bytes);
  }
  let out = "";
  for (const byte of bytes) {
    out += String.fromCharCode(byte);
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  const maybeBuffer = getBuffer();
  if (maybeBuffer) {
    return maybeBuffer.from(bytes).toString("base64");
  }
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  const btoa = (globalThis as unknown as { btoa?: (value: string) => string }).btoa;
  if (!btoa) {
    throw new Error("Base64 encoder is not available.");
  }
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const maybeBuffer = getBuffer();
  if (maybeBuffer) {
    return new Uint8Array(maybeBuffer.from(value, "base64"));
  }
  const atob = (globalThis as unknown as { atob?: (encoded: string) => string }).atob;
  if (!atob) {
    throw new Error("Base64 decoder is not available.");
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toBase64(value: string): string {
  const padded = value.padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
  return padded.replace(/-/g, "+").replace(/_/g, "/");
}

function getBuffer(): BufferConstructorLike | undefined {
  const candidate = (globalThis as unknown as { Buffer?: BufferConstructorLike }).Buffer;
  if (candidate?.from) {
    return candidate;
  }
  return undefined;
}
