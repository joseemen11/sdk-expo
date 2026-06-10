# Secure Storage Test

## Implemented

- `ExpoSecureKeyStore` stores the 32-byte credential encryption key through SecureStore.
- `EncryptedCredentialStorage` encrypts each VC payload with XChaCha20-Poly1305.
- `SQLiteCredentialRecordStore` stores id, safe summary JSON, encrypted payload, createdAt, and updatedAt.
- The demo app wires SecureStore, SQLite, and Expo Crypto into the SDK.

## Key Location

The encryption key is stored through `expo-secure-store` in the demo app. It is not stored in SQLite and is not printed.

## Credential Location

Credential records are stored in `privado_id_credentials.db` through `expo-sqlite`. The full VC payload is stored only as an encrypted envelope. The list operation reads safe summaries only.

## Verification

- `npm run build` passed.
- `npm run test:smoke` passed.
- `npm run typecheck` passed in `example/demo-expo`.
- The smoke test confirms the stored encrypted payload does not contain the subject id or claim names from the test VC.

## Manual Android Persistence Check

1. Run `cd example/demo-expo`.
2. Run `npm install`.
3. Run `npx expo start -c`.
   If port 8081 is busy, run `npx expo start -c --port 8082` or another free port.
4. Open the Android development build.
5. Tap `Init SDK`.
6. Tap `Import VC JSON`.
7. Tap `Save credential securely`.
8. Tap `List credentials` and confirm one safe summary is shown.
9. Close and reopen the app, or restart Metro and reload the app.
10. Tap `Init SDK`, then `List credentials`.
11. Confirm the same safe summary is still present.

## Limitations

- SQLCipher is not enabled in the current Expo SQLite setup.
- The SDK does not log full VCs, claims, encryption keys, private inputs, seeds, or encrypted payload contents.
- Holder DID, BJJ KMS, and ZK provider work are outside this storage block.
