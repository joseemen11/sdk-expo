# Holder DID and KMS Test

## Implemented

- `EncryptedIdentityStorage` persists holder DID metadata.
- `SecurePrivateKeyStore` stores key material through `SecureKeyStore`.
- `BjjKmsAdapter` provides a controlled production boundary for future BJJ integration.
- `DevelopmentOnlyKmsAdapter` signs test challenges for demo and smoke tests.
- `DevelopmentOnlyHolderDidProvider` creates an explicitly development-only DID for persistence testing.

## Public API

- `sdk.createOrLoadHolderDid(input?)`
- `sdk.getHolderDid()`
- `sdk.signChallenge(input)`
- `sdk.deleteHolderIdentity()`

The APIs return DID, keyId, method, network, timestamps, and developmentOnly status. They do not return private keys, seeds, encryption keys, or raw key material.

## Verification

- `npm run build` passed.
- `npm run test:smoke` passed.
- `cd example/demo-expo && npm run typecheck` passed.

The smoke test validates:

- first `createOrLoadHolderDid` creates a holder record;
- second `createOrLoadHolderDid` loads the same DID;
- `getHolderDid` returns the active summary;
- `signChallenge` returns a summarized development-only signature result;
- `deleteHolderIdentity` deletes metadata and associated key reference;
- after deletion, `getHolderDid` returns no active identity.

## Android Manual Check

1. Run `cd example/demo-expo`.
2. Run `npm install`.
3. Run `npx expo start -c`.
4. If port 8081 is busy, run `npx expo start -c --port 8082` or another free port.
5. Open the Android development build.
6. Tap `Init SDK`.
7. Tap `Create or load Holder DID`.
8. Tap `Get Holder DID`.
9. Confirm the DID, keyId, method, network, and developmentOnly status are shown.
10. Close and reopen the app or reload Metro.
11. Tap `Init SDK`, then `Get Holder DID`.
12. Confirm the same DID is still present.
13. Tap `Sign test challenge`.
14. Confirm only a signature preview and length are shown.
15. Tap `Delete Holder Identity`.
16. Tap `Get Holder DID` and confirm no identity is active.

## Blocker

The holder DID produced by the demo is not a real Privado ID holder DID. Real BJJ identity creation requires integrating the Privado ID JS identity wallet with mobile-safe storage and KMS adapters. That integration must be checked carefully to avoid browser storage, browser key stores, and proving dependencies.
