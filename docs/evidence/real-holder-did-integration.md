# Real Holder DID Integration Evidence

## Result

Real Privado ID holder DID creation now completes through the experimental mobile-safe layer.

`createOrLoadHolderDid({ mode: "real", method: "iden3", network: "amoy" })` returns a real iden3 DID and marks the result as:

```json
{
  "developmentOnly": false
}
```

The smoke test confirmed a DID with the shape `did:iden3:polygon:amoy:<identifier>`.

## Dependency Check

Initial installed root dependencies before the spike:

- `@noble/ciphers`
- `@noble/hashes`
- `typescript`

The identity spike installed `@0xpolygonid/js-sdk@1.44.0`. The experimental mobile-safe layer now uses a local identity/KMS runtime wrapper without using the package root runtime entrypoint. See `docs/evidence/unblock-polygonid-identity-kms-imports.md`.

## Prohibited Imports Check

No prohibited browser storage, browser wallet, prover, or public-env patterns were found in source, demo, scripts, package metadata, or docs.

## Implemented Boundaries

- `RealPrivadoIdentityProvider`
- `MobileIdentityWalletFactory`
- `MobileBjjKmsAdapter`
- `MobilePrivateKeyStore`
- `MobileMerkleTreeStorage`
- `MobileCredentialStorage`
- `MobileIdentityStorage`
- `MobileStateStorage`

These classes now complete the first real holder identity path without using browser storage, browser key stores, or the broad package root runtime entrypoint.

## DID Finalization

The mobile-safe runtime now performs the post-BJJ key creation steps:

- obtains the BJJ public key from the KMS provider;
- creates an auth core claim with `SchemaHash.authSchemaHash`;
- inserts the auth claim `hi` / `hv` into the claims tree;
- calculates the claims root and genesis identity state;
- derives the iden3 DID for Polygon Amoy;
- binds the temporary Merkle trees to the final DID;
- persists holder identity metadata through the configured identity storage.

The returned SDK result does not expose private key material, seed material, encryption keys, private inputs, or raw Merkle records.

## Verification

- `npm run build` passed.
- `npm run test:smoke` passed.
- `cd example/demo-expo && npm run typecheck` passed.

The smoke test validates:

- `mode: "real"` creates a real holder DID with `developmentOnly: false`;
- a second real-mode call loads the same DID instead of creating a new one;
- `mode: "development"` still creates and loads the same development-only holder DID;
- `getHolderDid`, `signChallenge`, and `deleteHolderIdentity` continue to work in development mode.

## Android Demo

The demo has separate buttons:

- `Create/load real Holder DID`
- `Create/load development Holder DID`
- `Get Holder DID`
- `Sign test challenge`
- `Delete Holder Identity`

The real button should now attempt the same real holder DID creation path. The UI must still display only DID metadata and controlled errors.
