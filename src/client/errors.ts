export class PrivadoExpoSdkError extends Error {
  override readonly name = "PrivadoExpoSdkError";

  constructor(message: string, readonly cause?: unknown) {
    super(message);
  }
}
