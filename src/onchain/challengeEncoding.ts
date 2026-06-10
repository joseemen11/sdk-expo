const EVM_ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;

export function addressToUint256LE(address: string): string {
  if (!EVM_ADDRESS_PATTERN.test(address)) {
    throw new Error("Address must be a 20-byte hex string.");
  }

  const hex = address.slice(2).toLowerCase();
  const bytes = hex.match(/.{2}/g);
  if (!bytes || bytes.length !== 20) {
    throw new Error("Address must be a 20-byte hex string.");
  }

  const littleEndianHex = bytes.reverse().join("");
  return BigInt(`0x${littleEndianHex}`).toString(10);
}
