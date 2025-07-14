import { dataToText, textDec, textEnc, textToData } from "./utils.ts";
import { generateSalt } from "./base.ts";

export type DeriveSaltedKeyHash = "SHA-256";

export interface CryptoAesGcm256Config {
  saltLength?: number;
  ivLength?: number;
  iterations?: number;
  hash?: DeriveSaltedKeyHash;
}

export class CryptoAesGcm256 {
  protected saltLength: number;
  protected ivLength: number;
  protected iterations: number;
  protected hash: DeriveSaltedKeyHash;

  constructor(config?: CryptoAesGcm256Config) {
    // NOTE: 原本 16, 但轉為 base64 會有 "=" 而改 18. XD
    this.saltLength = config?.saltLength ?? 18;
    this.ivLength = config?.ivLength ?? 12;
    this.iterations = config?.iterations ?? 1_000_000; // 約 100ms 的 PBKDF2
    this.hash = config?.hash ?? "SHA-256";
  }

  nameByMode(mode: "all" | "short"): string {
    const iterationExponent = this.iterations.toString().length - 1;
    const mustName = `AES-GCM-256`;
    switch (mode) {
      case "short":
        return `${mustName}+${this.hash}+s${this.saltLength}+i${this.ivLength}+e${iterationExponent}`;
      case "all":
        return `${mustName}+derive-${this.hash}+salt-${this.saltLength}+iv-${this.ivLength}+iter-e${iterationExponent}`;
    }
  }

  get name(): string {
    return this.nameByMode("all");
  }

  // Uint8Array 轉為 AES-GCM Key
  static async bufferToKey(buf: Uint8Array): Promise<CryptoKey> {
    const key = await crypto.subtle.importKey(
      "raw",
      buf,
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"],
    );
    return key;
  }

  // AES-GCM Key 轉為 Uint8Array
  static async keyToBuffer(key: CryptoKey): Promise<Uint8Array> {
    const rawKey = await crypto.subtle.exportKey("raw", key);
    return new Uint8Array(rawKey);
  }

  // 推導混合鹽的金鑰
  static async deriveSaltedKey(
    key: CryptoKey,
    hash: DeriveSaltedKeyHash,
    salt: Uint8Array,
  ): Promise<CryptoKey> {
    const origKeyBuf = await this.keyToBuffer(key);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      origKeyBuf,
      "HKDF",
      false,
      ["deriveKey"],
    );
    // 類似附註功能, 可留白
    // same as textEnc.encode("")
    const info = new Uint8Array();
    const newKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash, salt, info },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
    return newKey;
  }

  // 產生 AES 金鑰
  static generateKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
  }

  static async encryptText(
    text: string,
    key: CryptoKey,
    iv: Uint8Array,
  ): Promise<Uint8Array> {
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      textEnc.encode(text),
    );
    return new Uint8Array(encrypted);
  }

  static async decryptText(
    byteArray: Uint8Array,
    key: CryptoKey,
    iv: Uint8Array,
  ): Promise<string> {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      byteArray,
    );
    return textDec.decode(decrypted);
  }

  async encryptByKey(
    plainText: string,
    key: CryptoKey,
  ): Promise<string> {
    const salt = generateSalt(this.saltLength);
    const iv = generateSalt(this.ivLength);
    const saltKey = await CryptoAesGcm256.deriveSaltedKey(
      key,
      this.hash,
      salt,
    );
    const encrypted = await CryptoAesGcm256.encryptText(
      plainText,
      saltKey,
      iv,
    );
    const ciphertext = dataToText([salt, iv, encrypted]);
    return ciphertext;
  }

  async decryptByKey(
    ciphertext: string,
    key: CryptoKey,
  ): Promise<{ ok: boolean; error: unknown | null; text: string }> {
    const [salt, iv, encrypted] = textToData(ciphertext);
    try {
      const saltKey = await CryptoAesGcm256.deriveSaltedKey(
        key,
        this.hash,
        salt,
      );
      const text = await CryptoAesGcm256.decryptText(encrypted, saltKey, iv);
      return { ok: true, error: null, text };
    } catch (error) {
      return { ok: false, error, text: "" };
    }
  }
}

export class CryptoAesGcm256Pbkdf2 extends CryptoAesGcm256 {
  constructor(config?: CryptoAesGcm256Config) {
    super(config);
  }

  // 自定義密碼取得 AES 金鑰
  static async passwordToKey(
    password: string,
    hash: DeriveSaltedKeyHash,
    salt: Uint8Array,
    iterations = 1000_000,
  ): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      textEnc.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", hash, salt, iterations },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"],
    );
    return key;
  }

  async encryptByPassword(
    plainText: string,
    password: string,
  ): Promise<string> {
    const salt = generateSalt(this.saltLength);
    const iv = generateSalt(this.ivLength);
    const key = await CryptoAesGcm256Pbkdf2.passwordToKey(
      password,
      this.hash,
      salt,
      this.iterations,
    );
    const encrypted = await CryptoAesGcm256.encryptText(plainText, key, iv);
    const ciphertext = dataToText([salt, iv, encrypted]);
    return ciphertext;
  }

  async decryptByPassword(
    ciphertext: string,
    password: string,
  ): Promise<{ ok: boolean; error: unknown | null; text: string }> {
    const [salt, iv, encrypted] = textToData(ciphertext);
    try {
      const key = await CryptoAesGcm256Pbkdf2.passwordToKey(
        password,
        this.hash,
        salt,
        this.iterations,
      );
      const text = await CryptoAesGcm256.decryptText(encrypted, key, iv);
      return { ok: true, error: null, text };
    } catch (error) {
      return { ok: false, error, text: "" };
    }
  }
}
