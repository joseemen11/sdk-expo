# Secure Storage Status

The SDK now includes persistent encrypted credential storage for Expo development builds through injected mobile adapters.

## Current State

- `SecureKeyStore` defines the key-store boundary.
- `CredentialStorageAdapter` defines the credential persistence boundary.
- `ExpoSecureKeyStore` adapts `expo-secure-store` without coupling the SDK core to Expo imports.
- `SQLiteCredentialRecordStore` adapts `expo-sqlite` without storing full VCs in clear text.
- `EncryptedCredentialStorage` encrypts each credential payload before it reaches the record store.
- The demo app stores the encryption key in SecureStore/Keystore/Keychain and stores encrypted credential records in SQLite.
- Stored credential payloads are not exposed through summaries.

## SQLCipher Status

SQLCipher is not enabled in this repository. The Expo SQLite package used by the demo does not provide a SQLCipher configuration in the current setup. Instead, the selected strategy is authenticated encryption per credential record using XChaCha20-Poly1305, with the database storing only ciphertext plus safe metadata.

## Security Properties

- The encryption key is generated once and stored through SecureStore.
- The encryption key is not written to SQLite.
- Credential payloads are encrypted before persistence.
- Credential summaries contain only id, type, issuer, subject id, expiration date, proof types, createdAt, and updatedAt.
- Full VCs, claims, private inputs, and encryption keys are not logged by the SDK or demo.

## Remaining Work

- Review whether a SQLCipher-backed store is required for the final production threat model.
- Add platform hardening policy for backup, device lock, and biometric requirements.
- Add migration/versioning tests before changing the encrypted envelope format.
