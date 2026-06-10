export interface CreateEncryptionKeyOptions {
  byteLength?: number;
  allowDevelopmentFallback?: boolean;
}

export function createEncryptionKey(options: CreateEncryptionKeyOptions = {}): Uint8Array {
  const byteLength = options.byteLength ?? 32;
  const key = new Uint8Array(byteLength);
  const cryptoLike = (globalThis as unknown as { crypto?: { getRandomValues?: (array: Uint8Array) => Uint8Array } }).crypto;

  if (cryptoLike?.getRandomValues) {
    return cryptoLike.getRandomValues(key);
  }

  if (!options.allowDevelopmentFallback) {
    throw new Error("A secure random byte provider is required to create an encryption key.");
  }

  for (let i = 0; i < byteLength; i += 1) {
    key[i] = Math.floor(Math.random() * 256);
  }
  return key;
}
