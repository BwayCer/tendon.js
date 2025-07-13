import type { CryptoConfigOptional } from "./simple/simple.d.ts";
import { createCryptoConfig, Simple } from "./simple/Simple.ts";

export type { CryptoConfig, CryptoConfigOptional } from "./simple/simple.d.ts";

export { transformBase64, transformHex } from "./simple/transformConfig.ts";
export {
  deriveHkdfSha256,
  derivePbkdf2Sha256e6,
  encryptAesGcm256,
  signHmacSha256,
  signHmacSha512,
} from "./simple/v202507.ts";

export class MySimple extends Simple {
  constructor(...args: CryptoConfigOptional[]) {
    super();

    const config_ = Object.assign(
      // default
      createCryptoConfig([]),
      // user
      ...args,
    );

    this._simpleBuf.config = config_;
    this._config = config_;
    this._bufferToCode = config_.bufferToCode;
    this._codeToBuffer = config_.codeToBuffer;
  }
}
