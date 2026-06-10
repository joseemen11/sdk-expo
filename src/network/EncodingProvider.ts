import { portableBase64UrlCodec, type Base64UrlCodec } from "./Base64UrlCodec";

export interface EncodingProvider {
  base64Url: Base64UrlCodec;
}

export const defaultEncodingProvider: EncodingProvider = {
  base64Url: portableBase64UrlCodec
};
