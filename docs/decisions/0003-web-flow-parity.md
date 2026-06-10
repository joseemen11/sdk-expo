# 0003 Web Flow Parity

## Decision

The SDK mirrors the validated Privado ID flow as mobile-friendly modules:

- Credential offer parsing and claim flow boundary.
- Credential import and safe summary generation.
- MTP proof selection inside SDK credential utilities.
- Pure SigV2 and MTPV2 request builders.
- UniversalVerifier payload preparation.
- Adapter-based transaction submission and proof-status checks.

## Rationale

Flow logic should live in the SDK instead of the UI. The demo app should exercise the public API but not own proof selection, on-chain challenge encoding, or payload assembly rules.

## Consequences

The client API can stay stable while proof generation, native storage, and mobile signing are implemented behind adapters.
