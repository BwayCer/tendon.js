import type { CryptoConfigOptional } from "./simple/simple.d.ts";
import { createCryptoConfig, Simple } from "./simple/Simple.ts";

export type { CryptoConfig, CryptoConfigOptional } from "./simple/simple.d.ts";

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
