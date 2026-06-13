const EXPECTED_EXPORTS = [
  "IdentityWallet",
  "KMS",
  "BjjProvider",
  "CredentialWallet",
  "W3CCredential",
  "core"
] as const;

const RISK_EXPORTS = [
  "BrowserDataSource",
  "LocalStoragePrivateKeyStore",
  "MerkleTreeLocalStorage",
  "NativeProver"
] as const;

async function main() {
  const sdk = await import("@0xpolygonid/js-sdk");
  const expected = Object.fromEntries(EXPECTED_EXPORTS.map((name) => [name, typeof sdk[name]]));
  const risks = Object.fromEntries(RISK_EXPORTS.map((name) => [name, typeof sdk[name]]));

  console.log(JSON.stringify({ expected, risks }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
