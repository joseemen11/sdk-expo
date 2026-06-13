import type { CredentialStorageAdapter } from "../types";

export interface MobileCredentialStorageOptions {
  credentialStorage?: CredentialStorageAdapter;
}

export class MobileCredentialStorage {
  private readonly credentialStorage?: CredentialStorageAdapter;

  constructor(options: MobileCredentialStorageOptions = {}) {
    this.credentialStorage = options.credentialStorage;
  }

  async saveCredential(credential: unknown): Promise<void> {
    await this.requireStorage().saveCredential(credential);
  }

  async saveAllCredentials(credentials: unknown[]): Promise<void> {
    for (const credential of credentials) {
      await this.saveCredential(credential);
    }
  }

  async listCredentials(): Promise<unknown[]> {
    const storage = this.requireStorage();
    const summaries = await storage.getCredentials();
    const credentials: unknown[] = [];
    for (const summary of summaries) {
      const credential = await storage.getCredentialById(summary.id);
      if (credential) {
        credentials.push(credential);
      }
    }
    return credentials;
  }

  async removeCredential(id: string): Promise<void> {
    await this.requireStorage().deleteCredential(id);
  }

  async findCredentialsByQuery(_query: unknown): Promise<unknown[]> {
    return this.listCredentials();
  }

  async findCredentialById(id: string): Promise<unknown | undefined> {
    return this.requireStorage().getCredentialById(id);
  }

  private requireStorage(): CredentialStorageAdapter {
    if (!this.credentialStorage) {
      throw new Error("MobileCredentialStorage requires encrypted credential storage.");
    }
    return this.credentialStorage;
  }
}
