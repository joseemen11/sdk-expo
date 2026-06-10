import { PrivadoExpoClient } from "./PrivadoExpoClient";
import type { PrivadoExpoClientAdapters, PrivadoExpoConfig } from "../types";

export function createPrivadoExpoClient(
  config: PrivadoExpoConfig,
  adapters: PrivadoExpoClientAdapters = {}
): PrivadoExpoClient {
  return new PrivadoExpoClient(config, adapters);
}
