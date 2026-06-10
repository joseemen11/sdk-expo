# 0002 Secure Storage

## Decision

Credential storage is exposed through `CredentialStorageAdapter`, and encryption keys are exposed through `SecureKeyStore`.

The default implementation in this block is `EncryptedCredentialStorage` with `DevelopmentSecureKeyStore`. It is memory-only and marked for development. It is not suitable for production persistence.

## Rationale

Mobile credential storage needs a native-backed key store and encrypted persistence. Those pieces require app configuration and native dependencies, so the SDK defines the final boundary now without locking the package to one native database.

## Consequences

Production apps must inject native-backed adapters. The SDK can already import, summarize, and save credentials through the same API that production storage will use.
