export interface UuidProvider {
  randomId(): string;
}

export class TimestampUuidProvider implements UuidProvider {
  randomId(): string {
    const random = Math.floor(Math.random() * Number.MAX_SAFE_INTEGER).toString(16);
    return `privado-${Date.now().toString(16)}-${random}`;
  }
}
