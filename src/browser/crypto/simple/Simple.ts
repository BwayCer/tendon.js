import { Result } from "../../../types/strongLang.ts";
import { generateSalt } from "../base.ts";
import {
  BufferToCode,
  bufferToText,
  CodeToBuffer,
  dataToText,
  textToBuffer,
  textToData,
} from "../utils.ts";
import type { CryptoConfig } from "./simple.d.ts";

import { transformBase64, transformHex } from "./transformConfig.ts";
import {
  deriveHkdfSha256,
  derivePbkdf2Sha256e6,
  encryptAesGcm256,
  signHmacSha256,
  signHmacSha512,
} from "./v202507.ts";

export type CryptoConfigOption = keyof typeof cryptoConfigList;

const cryptoConfigList = {
  Pbkdf2Sha256e6: derivePbkdf2Sha256e6,
  HkdfSha256: deriveHkdfSha256,
  AesGcm256: encryptAesGcm256,
  HmacSha256: signHmacSha256,
  HmacSha512: signHmacSha512,
  TransformHex: transformHex,
  TransformBase64: transformBase64,
};

export function createCryptoConfig(
  cryptoConfigOptions: CryptoConfigOption[],
): CryptoConfig {
  return Object.assign(
    {},
    // default
    cryptoConfigList.Pbkdf2Sha256e6,
    cryptoConfigList.AesGcm256,
    cryptoConfigList.HmacSha256,
    cryptoConfigList.TransformHex,
    // user
    ...cryptoConfigOptions.map((item) => cryptoConfigList[item]),
  );
}

export class SimpleBuffer {
  config: CryptoConfig;

  constructor(config: CryptoConfig) {
    this.config = config;
  }

  async exportKey(key: CryptoKey) {
    const rawKey = await crypto.subtle.exportKey("raw", key);
    return new Uint8Array(rawKey);
  }

  generateEncryptKey() {
    const { encryptGenerateKey } = this.config;
    return crypto.subtle.generateKey(
      encryptGenerateKey[0],
      true,
      ["encrypt", "decrypt"],
    );
  }

  importEncryptKey(keyBuf: Uint8Array): Promise<CryptoKey> {
    const { encryptImportKey } = this.config;
    return crypto.subtle.importKey(
      "raw",
      keyBuf,
      encryptImportKey[2],
      true,
      ["encrypt", "decrypt"],
    );
  }

  async deriveEncryptKey(
    key: Uint8Array,
    salt: Uint8Array,
  ): Promise<CryptoKey> {
    const {
      deriveImportKey,
      deriveDeriveKeyAlgorithm,
      encryptDeriveKey,
    } = this.config;
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      key,
      deriveImportKey[2],
      false,
      ["deriveKey"],
    );
    const newKey = await crypto.subtle.deriveKey(
      deriveDeriveKeyAlgorithm(salt),
      keyMaterial,
      encryptDeriveKey[2],
      true,
      ["encrypt", "decrypt"],
    );
    return newKey;
  }

  async encrypt(
    key: CryptoKey,
    iv: Uint8Array,
    plainBuf: Uint8Array,
  ) {
    const { encryptEncryptAlgorithm } = this.config;
    const algorithm = encryptEncryptAlgorithm(iv);
    const encrypted = await crypto.subtle.encrypt(
      algorithm,
      key,
      plainBuf,
    );
    return new Uint8Array(encrypted);
  }

  async decrypt(
    key: CryptoKey,
    iv: Uint8Array,
    byteArray: Uint8Array,
  ) {
    const { encryptEncryptAlgorithm } = this.config;
    const algorithm = encryptEncryptAlgorithm(iv);
    const decrypted = await crypto.subtle.decrypt(
      algorithm,
      key,
      byteArray,
    );
    return new Uint8Array(decrypted);
  }

  generateSignKey() {
    const { signGenerateKey } = this.config;
    return crypto.subtle.generateKey(
      signGenerateKey[0],
      true,
      ["sign", "verify"],
    );
  }

  importSignKey(keyBuf: Uint8Array): Promise<CryptoKey> {
    const { signImportKey } = this.config;
    return crypto.subtle.importKey(
      "raw",
      keyBuf,
      signImportKey[2],
      true,
      ["sign", "verify"],
    );
  }

  async deriveSignKey(
    key: Uint8Array,
    salt: Uint8Array,
  ): Promise<CryptoKey> {
    const {
      deriveImportKey,
      deriveDeriveKeyAlgorithm,
      signDeriveKey,
    } = this.config;
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      key,
      deriveImportKey[2],
      false,
      ["deriveKey"],
    );
    const newKey = await crypto.subtle.deriveKey(
      deriveDeriveKeyAlgorithm(salt),
      keyMaterial,
      signDeriveKey[2],
      true,
      ["sign", "verify"],
    );
    return newKey;
  }

  async sign(key: CryptoKey, data: Uint8Array) {
    const { signSign } = this.config;
    const signature = await crypto.subtle.sign(signSign[0], key, data);
    return new Uint8Array(signature);
  }

  verify(key: CryptoKey, signature: Uint8Array, data: Uint8Array) {
    const { signSign } = this.config;
    return crypto.subtle.verify(signSign[0], key, signature, data);
  }

  async getAlgorithm(
    makeAlgorithm: (salt: Uint8Array) => Promise<unknown> | null,
    fixArgs: unknown[] | null,
    index: number,
    salt: Uint8Array,
  ): Promise<unknown | null> {
    return typeof makeAlgorithm === "function"
      ? await makeAlgorithm(salt)
      : fixArgs !== null
      ? fixArgs[index]
      : null;
  }
}

export class Simple {
  protected _simpleBuf: SimpleBuffer;
  protected _config: CryptoConfig;
  protected _bufferToCode: BufferToCode;
  protected _codeToBuffer: CodeToBuffer;

  constructor(...args: CryptoConfigOption[]) {
    const config = createCryptoConfig(args);
    this._simpleBuf = new SimpleBuffer(config);
    this._config = config;
    this._bufferToCode = config.bufferToCode;
    this._codeToBuffer = config.codeToBuffer;
  }

  name(mode?: "encrypt" | "sign"): string {
    const { encryptName, signName, deriveName, transformCode } = this._config;
    const suffix = `${deriveName}+${transformCode}`;
    switch (mode) {
      case "encrypt":
        return `${encryptName}+${suffix}`;
      case "sign":
        return `${signName}+${suffix}`;
      default:
        return `${encryptName}+${signName}+${suffix}`;
    }
  }

  private async _importKey(
    methodName: "importEncryptKey" | "importSignKey",
    keyTxt: string,
  ): Promise<Result<CryptoKey>> {
    try {
      const buf = this._codeToBuffer(keyTxt);
      const key = await this._simpleBuf[methodName](buf);
      return { ok: true, value: key };
    } catch (error) {
      return { ok: false, error };
    }
  }

  private async _deriveKey(
    methodName: "deriveEncryptKey" | "deriveSignKey",
    keyPass: string | CryptoKey | Uint8Array,
    saltPass: string | number | Uint8Array,
  ): Promise<Result<CryptoKey>> {
    try {
      const key = await this._toUint8Array(keyPass);
      const salt = await this._toUint8Array(saltPass);
      const newKey = await this._simpleBuf[methodName](key, salt);
      return { ok: true, value: newKey };
    } catch (error) {
      return { ok: false, error };
    }
  }

  async exportKey(key: CryptoKey): Promise<string> {
    const keyBuf = await this._simpleBuf.exportKey(key);
    return this._bufferToCode(keyBuf);
  }

  generateEncryptKey() {
    return this._simpleBuf.generateEncryptKey();
  }

  importEncryptKey(keyTxt: string): Promise<Result<CryptoKey>> {
    return this._importKey("importEncryptKey", keyTxt);
  }

  /**
   * @param keyPass
   * 類型為 `String` 時是密碼;
   * 為 `CryptoKey` 時是金鑰;
   * 為 `Uint8Array` 時是任意資料;
   */
  deriveEncryptKey(
    keyPass: string | CryptoKey | Uint8Array,
    saltPass: string | number | Uint8Array,
  ): Promise<Result<CryptoKey>> {
    return this._deriveKey("deriveEncryptKey", keyPass, saltPass);
  }

  /**
   * @param keyPass
   * 類型為 `String` 時是密碼;
   * 為 `CryptoKey` 時是金鑰.
   */
  async encrypt(
    keyPass: string | CryptoKey,
    plainData: string | Uint8Array,
  ): Promise<Result<string>> {
    try {
      const iv = generateSalt(this._config.encryptIvLength);
      const plainBuf = await this._toUint8Array(plainData);
      const keyResult = await this._toCryptoKey(
        keyPass,
        iv,
        "deriveEncryptKey",
      );
      if (!keyResult.ok) {
        return keyResult;
      }
      const encrypted = await this._simpleBuf.encrypt(
        keyResult.value,
        iv,
        plainBuf,
      );
      const ciphertext = dataToText([iv, encrypted], this._bufferToCode);
      return { ok: true, value: ciphertext };
    } catch (error) {
      return { ok: false, error };
    }
  }

  /**
   * @param keyPass
   * 類型為 `String` 時是密碼;
   * 為 `CryptoKey` 時是金鑰.
   */
  async decrypt(
    keyPass: string | CryptoKey,
    ciphertext: string,
  ): Promise<Result<string>> {
    try {
      const [iv, encrypted] = textToData(ciphertext, this._codeToBuffer);
      const keyResult = await this._toCryptoKey(
        keyPass,
        iv,
        "deriveEncryptKey",
      );
      if (!keyResult.ok) {
        return keyResult;
      }
      const decrypted = await this._simpleBuf.decrypt(
        keyResult.value,
        iv,
        encrypted,
      );
      const plainText = bufferToText(decrypted);
      return { ok: true, value: plainText };
    } catch (error) {
      return { ok: false, error };
    }
  }

  generateSignKey() {
    return this._simpleBuf.generateSignKey();
  }

  importSignKey(keyTxt: string): Promise<Result<CryptoKey>> {
    return this._importKey("importSignKey", keyTxt);
  }

  /**
   * @param keyPass
   * 類型為 `String` 時是密碼;
   * 為 `CryptoKey` 時是金鑰;
   * 為 `Uint8Array` 時是任意資料;
   */
  deriveSignKey(
    keyPass: string | CryptoKey | Uint8Array,
    saltPass: string | number | Uint8Array,
  ): Promise<Result<CryptoKey>> {
    return this._deriveKey("deriveSignKey", keyPass, saltPass);
  }

  async sign(
    key: CryptoKey,
    data: string | Uint8Array,
  ): Promise<Result<string>> {
    try {
      const dataBuf = await this._toUint8Array(data);
      const signature = await this._simpleBuf.sign(key, dataBuf);
      const signTxt = this._bufferToCode(signature);
      return { ok: true, value: signTxt };
    } catch (error) {
      return { ok: false, error };
    }
  }

  async verify(
    key: CryptoKey,
    signature: string,
    data: string | Uint8Array,
  ): Promise<Result<boolean>> {
    try {
      const signatureBuf = this._codeToBuffer(signature);
      const dataBuf = await this._toUint8Array(data);
      const isValid = await this._simpleBuf.verify(key, signatureBuf, dataBuf);
      return { ok: true, value: isValid };
    } catch (error) {
      return { ok: false, error };
    }
  }

  /**
   * @param pass
   * 類型為 `String` 時 `TextEncoder#encode`;
   * 為 `number` 時 `crypto.getRandomValues()`;
   * 為 `CryptoKey` 時 `crypto.subtle.exportKey()`;
   * 為 `Uint8Array` 時不處理.
   */
  private async _toUint8Array(
    pass: string | number | CryptoKey | Uint8Array,
  ): Promise<Uint8Array> {
    switch (pass && pass.constructor) {
      case String:
        return textToBuffer(pass as string);
      case Number:
        return generateSalt(pass as number);
      case CryptoKey:
        return await this._simpleBuf.exportKey(pass as CryptoKey);
      default:
        return pass as Uint8Array;
    }
  }

  private async _toCryptoKey(
    pass: string | CryptoKey,
    salt: Uint8Array,
    methodKey: "deriveEncryptKey",
  ): Promise<Result<CryptoKey>> {
    switch (pass && pass.constructor) {
      case String: {
        const buf = textToBuffer(pass as string);
        return await this[methodKey](buf, salt);
      }
      default:
        return { ok: true, value: pass as CryptoKey };
    }
  }
}
