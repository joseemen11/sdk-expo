# 0005 Persistent Encrypted Storage

## Decision

Credential payloads are encrypted per record with XChaCha20-Poly1305 before persistence. The encryption key is created once and stored through a `SecureKeyStore` implementation. The demo app uses `expo-secure-store` for key storage and `expo-sqlite` for encrypted credential records.

The SDK exposes adapter classes instead of importing Expo modules directly:

- `ExpoSecureKeyStore`
- `SQLiteCredentialRecordStore`
- `EncryptedCredentialStorage`

## Rationale

The SDK must not store full VCs in clear text and must not store encryption keys in SQLite or normal files. Expo SecureStore maps to platform secure storage on Android and iOS, while SQLite gives a durable local record store. Encrypting each credential payload in the SDK keeps credential confidentiality independent of whether the SQLite build has SQLCipher enabled.

## SQLCipher

SQLCipher is not implemented in this block. The installed Expo SQLite module does not expose a SQLCipher setup in the current demo configuration. The selected alternative is authenticated encryption per credential record, with SQLite storing ciphertext and safe summaries.

## Consequences

- Credential summaries can be listed without decrypting full VC payloads.
- Full credential payloads are decrypted only for `getCredentialById`.
- Delete and clear operations are part of the storage adapter contract.
- A future SQLCipher record store can replace `SQLiteCredentialRecordStore` without changing the client API.
