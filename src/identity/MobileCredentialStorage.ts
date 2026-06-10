export class MobileCredentialStorage {
  async init(): Promise<void> {
    throw new Error("Real Privado ID credential wallet storage is not configured.");
  }
}
