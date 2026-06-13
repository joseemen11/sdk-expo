import { loadMobileSafePolygonIdIdentityKms } from "../../src/privado-js-sdk-mobile/mobileSafeImports";

async function main(): Promise<void> {
  const imports = await loadMobileSafePolygonIdIdentityKms();

  assert(typeof imports.IdentityWallet === "function", "IdentityWallet import is not available.");
  assert(typeof imports.KMS === "function", "KMS import is not available.");
  assert(typeof imports.BjjProvider === "function", "BjjProvider import is not available.");
  assert(typeof imports.CredentialWallet === "function", "CredentialWallet import is not available.");
  assert(typeof imports.W3CCredential === "function", "W3CCredential import is not available.");

  assertNoLoadedModule("snarkjs");
  assertNoLoadedModule("ffjavascript");
  assertNoLoadedModule("NativeProver");

  console.info("mobile-safe imports ok");
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function assertNoLoadedModule(pattern: string): void {
  const loaded = Object.keys(require.cache).find((modulePath) =>
    modulePath.toLowerCase().includes(pattern.toLowerCase())
  );
  assert(!loaded, `Unexpected loaded module: ${loaded}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
