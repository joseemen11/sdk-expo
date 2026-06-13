# First Block Checklist

- SDK package structure created.
- Public API exported from `src/index.ts`.
- Explicit `PrivadoExpoConfig` validation created.
- VC JSON import implemented.
- Credential save, list, and lookup implemented through an adapter.
- Credential listing returns safe summaries only.
- MTP proof selection utility implemented.
- Credential offer parsing uses a portable codec.
- Claim flow returns a controlled AuthV2 provider error when missing.
- Circuit IDs, manifest, registry, and presets created.
- Off-chain SigV2 and MTPV2 builders created.
- On-chain SigV2 and MTPV2 builders created.
- On-chain MTP challenge derives from verifier address using little-endian encoding.
- Replaceable `ZKProvider` boundary created.
- Proof generation returns a controlled provider error when missing.
- UniversalVerifier payload preparation created.
- RPC-based proof-status check created.
- Transaction submitter boundary and submit strategies created.
- Demo Expo app imports the SDK as a local dependency.
- Secure storage status documented in `docs/evidence/secure-storage-blocker.md`.
- Persistent encrypted credential storage added through SecureStore-backed keys and SQLite-backed encrypted records.
- Holder DID and KMS boundary documented in `docs/decisions/0006-holder-did-kms.md`.
- Holder DID/KMS test evidence documented in `docs/evidence/holder-did-kms-test.md`.
- Real holder DID integration decision documented in `docs/decisions/0007-real-privado-holder-did.md`.
- Real holder DID integration evidence documented in `docs/evidence/real-holder-did-integration.md`.
- Mobile-safe JS SDK identity layer documented in `docs/decisions/0008-mobile-safe-js-sdk-identity-layer.md`.
- Mobile-safe JS SDK identity evidence documented in `docs/evidence/mobile-safe-js-sdk-identity-layer.md`.
- PolygonID identity/KMS import unblock documented in `docs/decisions/0009-unblock-polygonid-identity-kms-imports.md`.
- PolygonID identity/KMS import unblock evidence documented in `docs/evidence/unblock-polygonid-identity-kms-imports.md`.

## Known Blockers

- SQLCipher is not enabled in this repository; encrypted per-record storage is used instead.
- Real BJJ-backed Privado ID holder identity creation reaches `IdentityWallet.createIdentity`, creates mobile Merkle metadata, and reaches BJJ key creation.
- `createOrLoadHolderDid({ mode: "real" })` returns a controlled technical error before DID finalization until the local identity runtime completes the remaining identity creation steps.
- Native proof generation is not implemented in this block.
- Mobile wallet submission is not implemented in this block.

## Verification

- Root commands:
  - `npm install`
  - `npm run build`
  - `npm run test:smoke`
- Demo commands:
  - `cd example/demo-expo`
  - `npm install`
  - `npx expo start`
  - If port 8081 is busy, run `npx expo start -c --port 8082` or another free port.
- `npm run build` passed from the root package.
- `npm run test:smoke` passed from the root package for `init`, VC import/save/list/get/delete/clear, encrypted payload storage, MTP request builders, and `addressToUint256LE`.
- `npm run test:smoke` also passed for development-only holder DID create/load/get/sign/delete.
- `npm run test:smoke` passed for real-mode mobile-safe import boundary handling.
- `npm run typecheck` passed from `example/demo-expo` after installing demo dependencies.
- `npx expo start -c --port 8082` started Metro from `example/demo-expo`.
- `npx expo start -c --port 8083` also started Metro when 8082 was busy.
- `npx expo start -c --port 8085` started Metro for the mobile-safe identity layer check.
- `npx expo start -c --port 8086` started Metro for the PolygonID identity/KMS import unblock check.
- Android bundle verification returned HTTP 200 for the Expo virtual Metro entry.
- Pattern checks found no prohibited imports or browser-wallet globals in source or docs.
