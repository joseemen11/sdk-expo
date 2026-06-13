import { addressToUint256LE } from "./challengeEncoding";

const evmAddressPattern = /^0x[0-9a-fA-F]{40}$/;

export function isEvmAddress(value: unknown): value is string {
  return typeof value === "string" && evmAddressPattern.test(value);
}

export function evmAddressToChallenge(address: string): string {
  if (!isEvmAddress(address)) {
    throw new Error("On-chain credential proof challengeAddress must be a valid EVM address.");
  }
  return addressToUint256LE(address);
}

export function normalizeEvmAddress(address: string): string {
  if (!isEvmAddress(address)) {
    throw new Error("On-chain credential proof challengeAddress must be a valid EVM address.");
  }
  return `0x${address.slice(2).toLowerCase()}`;
}

export async function deriveEvmChallengeAddressFromPrivateKey(_evmPrivateKey: string): Promise<string> {
  throw new Error(
    "EVM private key derivation is not available in the SDK core. Inject or pass the EVM challengeAddress from the app wallet."
  );
}
