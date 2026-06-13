# 0007 Real Privado ID Holder DID Integration

## Decision

Real Privado ID holder DID creation now completes through the experimental mobile-safe layer.

The SDK now supports `createOrLoadHolderDid({ mode })`:

- `mode: "real"` creates or loads the real Privado ID holder identity path.
- `mode: "development"` uses the explicit development-only provider.

After DID finalization completes, the SDK returns an iden3 DID for Polygon Amoy and marks the result as:

```json
{
  "developmentOnly": false
}
```

## Technical Validation

At the time of the first real-mode boundary, the repository did not include `@0xpolygonid/js-sdk` or another Privado ID identity SDK package.

The later identity spike installed `@0xpolygonid/js-sdk@1.44.0` and found root exports for:

- `IdentityWallet`
- `KMS`
- `BjjProvider`

However, the same root package entrypoint also exposes browser storage and prover surfaces, and identity-only/KMS-only deep imports are not exported by package metadata.

The current mobile-safe layer provides the storage interfaces required for the first holder identity creation path:

- identity wallet storage;
- credential wallet storage;
- Merkle tree storage;
- BJJ private key store.

## Imports Used

The SDK source uses a controlled mobile-safe import wrapper backed by a local identity/KMS runtime surface. It does not import the broad package root entrypoint for runtime identity creation.

The SDK adds boundary classes only:

- `RealPrivadoIdentityProvider`
- `MobileIdentityWalletFactory`
- `MobileBjjKmsAdapter`
- `MobilePrivateKeyStore`
- `MobileMerkleTreeStorage`
- `MobileCredentialStorage`
- `MobileIdentityStorage`
- `MobileStateStorage`

These boundaries do not create dummy identities and do not import the broad runtime root package.

## Remaining Scope

The holder DID path now wires:

- `IdentityWallet.createIdentity`
- BJJ KMS provider
- mobile private key store backed by `SecureKeyStore`
- mobile Merkle tree storage
- mobile credential wallet storage

Claim issuance, proof generation, and on-chain submit remain outside this decision.
