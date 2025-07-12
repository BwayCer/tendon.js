import type { CryptoConfigOptional } from "./simple.d.ts";

export const derivePbkdf2Sha256e6: CryptoConfigOptional = {
  // IterE6 的 E 是 Exponent
  deriveName: "PBKDF2-SHA-256-IterE6",
  deriveImportKey: [
    undefined,
    undefined,
    "PBKDF2",
  ],
  deriveDeriveKeyAlgorithm: (salt: Uint8Array): Pbkdf2Params => {
    // 每次計算可耗時約 100ms. (AI 評價)
    const iterations = 1_000_000;
    return { name: "PBKDF2", hash: "SHA-256", salt, iterations };
  },
};

export const deriveHkdfSha256: CryptoConfigOptional = {
  deriveName: "HKDF-SHA-256",
  deriveImportKey: [
    undefined,
    undefined,
    "HKDF",
  ],
  deriveDeriveKeyAlgorithm: (salt: Uint8Array): HkdfParams => {
    // 類似附註功能, 可留白
    // same as textEnc.encode("")
    const info = new Uint8Array();
    return { name: "HKDF", hash: "SHA-256", salt, info };
  },
};

export const encryptAesGcm256: CryptoConfigOptional = {
  encryptName: "AES-GCM-256",
  encryptIvLength: 12,
  encryptGenerateKey: [
    { name: "AES-GCM", length: 256 },
  ],
  encryptImportKey: [
    undefined,
    undefined,
    { name: "AES-GCM", length: 256 },
  ],
  encryptDeriveKey: [
    undefined,
    undefined,
    { name: "AES-GCM", length: 256 },
  ],
  encryptEncryptAlgorithm: (iv: Uint8Array) => ({ name: "AES-GCM", iv }),
};

export const signHmacSha512: CryptoConfigOptional = {
  signName: "HMAC-SHA-512",
  signGenerateKey: [
    { name: "HMAC", hash: "SHA-512" },
  ],
  signImportKey: [
    undefined,
    undefined,
    { name: "HMAC", hash: "SHA-512" },
  ],
  signDeriveKey: [
    undefined,
    undefined,
    { name: "HMAC", hash: "SHA-512" },
  ],
  signSign: [
    "HMAC",
  ],
};
