# Privado ID Expo SDK

This repository contains an independent Privado ID SDK for Expo and React Native. The `example/demo-expo` app is only a test harness for Android integration work.

The first target is Android with an Expo development build. Expo Go is not a target for real proof generation because the ZK proving boundary is expected to use replaceable native capabilities behind `ZKProvider`.

## Current Scope

- Explicit SDK configuration through `PrivadoExpoConfig`.
- Secure-storage interfaces and adapters for encryption keys and credentials.
- Persistent encrypted credential storage through SecureStore-backed keys and SQLite-backed encrypted records in the demo app.
- VC JSON import, save, list, and lookup.
- Credential delete and clear operations.
- Holder DID API boundary for create/load/get/sign/delete.
- Experimental mobile-safe identity layer for `@0xpolygonid/js-sdk` identity/KMS imports.
- Safe credential summaries that exclude full claims.
- Pure builders for SigV2 and MTPV2 proof requests.
- Path-based circuit artifact registration and validation for AuthV2, SigV2, and SigV2 on-chain.
- On-chain challenge encoding with little-endian address conversion.
- Replaceable `ZKProvider`, `RPCAdapter`, and `ZkpTxSubmitter` boundaries.
- Controlled errors for claim, proof generation, transaction submit, and proof-status checks when required adapters are missing.

## Install

```sh
npm install
npm run build
```

## Basic Usage

```ts
import { createPrivadoExpoClient } from "@privado-id/expo-sdk";

const sdk = createPrivadoExpoClient({
  network: {
    name: "amoy",
    chainId: 80002,
    rpcUrl: "https://rpc-amoy.polygon.technology"
  },
  contracts: {
    stateContractAddress: "0x0000000000000000000000000000000000000001",
    universalVerifierAddress: "0x0000000000000000000000000000000000000002"
  },
  didResolver: {
    didResolverUrl: "https://resolver.privado.id"
  },
  circuits: {
    artifacts: []
  }
});

await sdk.init();
const imported = sdk.importCredentialFromJson(rawVcJson);
await sdk.saveCredential(imported.credential);
const summaries = await sdk.getCredentials();
```

## Holder DID

The SDK exposes holder identity methods. Real BJJ-backed Privado ID holder creation is attempted through an experimental mobile-safe identity layer. The import boundary is unblocked through a local identity/KMS runtime surface because the installed JS SDK package does not publish separate runtime submodules for the identity/KMS pieces needed by Expo.

```ts
const holder = await sdk.createOrLoadHolderDid({ mode: "real" });
const summary = await sdk.getHolderDid();
```

Real holder DID creation uses mobile storage adapters for private keys, identity metadata, credentials, Merkle trees, and state. The current real path creates a BJJ-backed iden3 DID for Polygon Amoy and returns `developmentOnly: false` only after that flow completes. The demo app also exposes an explicit development mode to test persistence and challenge signing. Those demo identities are marked with `developmentOnly: true` and are not production Privado ID identities.

## Claim From Offer

```ts
const result = await sdk.claimCredentialFromOffer({
  message,
  holderDid: holder.did
});
```

The claim API resolves the holder key internally through KMS references. It does not accept a private key parameter. Returned credentials are saved through the configured credential storage and the method returns safe summaries only. AuthV2 claim authorization is prepared by `MobileAuthV2Provider`; without a configured `ZKProvider` or AuthV2 circuit artifacts, the method fails with controlled boundary errors.

## Storage

Credential material must not be persisted in unencrypted app storage. `EncryptedCredentialStorage` encrypts each credential payload with XChaCha20-Poly1305 before it reaches the record store. The demo app stores the encryption key through `expo-secure-store` and stores encrypted records through `expo-sqlite`.

The SDK core stays adapter-based. Mobile apps can inject `ExpoSecureKeyStore`, `SQLiteCredentialRecordStore`, or stricter production adapters without changing the public client API.

## ZK Boundary

The SDK does not bundle a proving engine in this block. Real proof generation must be implemented behind `ZKProvider`, and circuit artifacts must be resolved from a manifest instead of shipping every artifact in the application bundle.

Circuit artifacts can be registered as paths without loading large files into JavaScript memory:

```ts
import { CircuitArtifactStore, CircuitId, createPrivadoExpoClient } from "@privado-id/expo-sdk";

const circuitArtifactStore = new CircuitArtifactStore({
  artifacts: [
    {
      circuitId: CircuitId.AuthV2,
      version: "v1",
      wasmPath: "file:///app/circuits/AuthV2/AuthV2.wasm",
      zkeyPath: "file:///app/circuits/AuthV2/AuthV2.zkey",
      verificationKeyPath: "file:///app/circuits/AuthV2/verification_key.json"
    }
  ]
});

const sdk = createPrivadoExpoClient(config, { circuitArtifactStore });
```

Native witness integrations can use `graphPath` instead of `wasmPath`. This layer only resolves and validates paths; it does not calculate witnesses or generate proofs.

Circuit ZIPs can also be downloaded and extracted through app-provided adapters:

```ts
import { CircuitArtifactDownloader, CircuitId } from "@privado-id/expo-sdk";

const downloader = new CircuitArtifactDownloader({
  zipUrl,
  requiredCircuits: [
    CircuitId.AuthV2,
    CircuitId.CredentialAtomicQuerySigV2,
    CircuitId.CredentialAtomicQuerySigV2OnChain
  ],
  fileSystem,
  zipExtractor,
  artifactStore: circuitArtifactStore
});

await downloader.prepare();
```

The SDK core does not hardcode the URL. The ZIP path is cached by the app FileSystem adapter, `.wcd` files are registered as `graphPath`, `.zkey` files are registered as `zkeyPath`, and `.dat` files are optional compatibility artifacts.

An experimental AuthV2 ZK boundary is available for native integration spikes:

```ts
import { AuthV2ZKProvider } from "@privado-id/expo-sdk";

const zkProvider = new AuthV2ZKProvider({
  witnessCalculator,
  prover
});
```

Without a witness calculator it fails with `Mobile witness calculator is required to generate AuthV2 proof.` Without a native prover it fails with `Native prover is required to generate AuthV2 proof.` It still does not generate real proofs unless native adapters are provided.

AuthV2 witness inputs are prepared outside the ZK provider through `AuthV2InputBuilder`. The builder requires auth claim proof, non-revocation proof, tree state, GIST proof, and challenge signature before any native witness calculation is attempted. Holder DID creation now persists auth claim and state material for AuthV2, and `MobileMerkleTreeStorage` can generate auth claim inclusion and non-revocation proofs from persisted entries. The auth claim is marshaled through `Claim.marshalJson()` as 8 decimal bigint string slots before native preflight. `ReadOnlyMobileGistProofSource` can read real GIST proof material from the configured DID resolver or a read-only state contract adapter; it does not fabricate genesis proofs. `MobileBjjKmsAdapter` signs AuthV2 challenges using the logical `BJJ:<...>` key id while resolving the physical SecureStore key through the safe mobile key alias. AuthV2 preflight validates the native witness input shape before `calculateWitness`; it serializes the challenge as a decimal bigint string and pads AuthV2 MTP siblings to the circuit levels expected by `AuthV2Inputs.inputsMarshal()`. If a field is not native-ready, claim stops with `AuthV2 inputs are not ready for native witness: <field/reason>`. The current claim boundary remains `AuthV2 GIST proof is not available for genesis identity on network amoy.` when no external source returns a valid GIST proof; when GIST is available, `Check AuthV2 inputs` should report `AuthV2 inputs: native-ready` before claim enters the native witness path. Existing Android identities created before this persistence change should be deleted and recreated before testing AuthV2 claim again.

The demo includes a native prover spike using `@iden3/react-native-rapidsnark`. `RapidsnarkNativeProver` passes `zkeyPath` and witness path/string to the native module. The demo button `Check native prover` validates that the module is linked in the Android development build; it does not generate a real proof.

The demo also includes a witness calculator spike using `@iden3/react-native-circom-witnesscalc`. `CircomWitnessNativeCalculator` passes stringified inputs and `graphPath` (`.wcd`) to the native module only when proof generation is explicitly attempted. The demo button `Check witness calculator` only verifies that the module is linked and does not run witness calculation with fake inputs.

## Demo App

```sh
cd example/demo-expo
npm install
npm run android
```

The demo imports `react-native-get-random-values` before the SDK so Android/Hermes has `crypto.getRandomValues` for BJJ key creation. It uses `expo-file-system` and `react-native-zip-archive` to download and unzip circuit assets in a development build. The Android project pins Kotlin `1.9.25` for compatibility with Compose Compiler `1.5.15`. It shows SDK status, controlled errors, circuit paths, and credential summaries only. It does not display full VCs.
