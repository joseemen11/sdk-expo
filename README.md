# Privado ID Expo SDK

This repository contains an independent Privado ID SDK for Expo and React Native. The `example/demo-expo` app is only a test harness for Android integration work.

The first target is Android with an Expo development build. Expo Go is not a target for real proof generation because the ZK proving boundary is expected to use replaceable native capabilities behind `ZKProvider`.

## Current Scope

- Explicit SDK configuration through `PrivadoExpoConfig`.
- Secure-storage interfaces and adapters for encryption keys and credentials.
- Persistent encrypted credential storage through SecureStore-backed keys and SQLite-backed encrypted records in the demo app.
- VC JSON import, save, list, and lookup.
- Credential delete and clear operations.
- Safe credential summaries that exclude full claims.
- Pure builders for SigV2 and MTPV2 proof requests.
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

## Storage

Credential material must not be persisted in unencrypted app storage. `EncryptedCredentialStorage` encrypts each credential payload with XChaCha20-Poly1305 before it reaches the record store. The demo app stores the encryption key through `expo-secure-store` and stores encrypted records through `expo-sqlite`.

The SDK core stays adapter-based. Mobile apps can inject `ExpoSecureKeyStore`, `SQLiteCredentialRecordStore`, or stricter production adapters without changing the public client API.

## ZK Boundary

The SDK does not bundle a proving engine in this block. Real proof generation must be implemented behind `ZKProvider`, and circuit artifacts must be resolved from a manifest instead of shipping every artifact in the application bundle.

## Demo App

```sh
cd example/demo-expo
npm install
npm run android
```

The demo shows SDK status, controlled errors, and credential summaries only. It does not display full VCs.
