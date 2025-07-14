import type { CryptoConfigOptional } from "./simple.d.ts";
import {
  base64ToBuffer,
  bufferToBase64,
  bufferToHex,
  hexToBuffer,
} from "../utils.ts";

export const transformHex: CryptoConfigOptional = {
  transformCode: "Hex",
  bufferToCode: bufferToHex,
  codeToBuffer: hexToBuffer,
};

export const transformBase64: CryptoConfigOptional = {
  transformCode: "Base64",
  bufferToCode: bufferToBase64,
  codeToBuffer: base64ToBuffer,
};
