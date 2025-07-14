import type { BufferToCode, CodeToBuffer } from "../utils.ts";

export interface CryptoConfig {
  // derive
  deriveName: string;
  deriveImportKey: [
    undefined,
    undefined,
    AlgorithmIdentifier | HmacImportParams,
  ];
  deriveDeriveKeyAlgorithm: (salt: Uint8Array) => HkdfParams | Pbkdf2Params;

  // encrypt
  encryptName: string;
  encryptIvLength: number;
  encryptImportKey: [
    undefined,
    undefined,
    AesDerivedKeyParams,
  ];
  encryptDeriveKey: [
    undefined,
    undefined,
    AesDerivedKeyParams,
  ];
  encryptGenerateKey: [AesKeyGenParams];
  encryptEncryptAlgorithm: (iv: Uint8Array) => AesGcmParams;

  // sign
  signName: string;
  signImportKey: [
    undefined,
    undefined,
    HmacImportParams,
  ];
  signDeriveKey: [
    undefined,
    undefined,
    HmacImportParams,
  ];
  signGenerateKey: [
    HmacKeyGenParams,
  ];
  // signSignAlgorithm?: () => AlgorithmIdentifier;
  signSign: [AlgorithmIdentifier];

  // transformCode
  transformCode: string;
  bufferToCode: BufferToCode;
  codeToBuffer: CodeToBuffer;
}

export type CryptoConfigOptional = Partial<CryptoConfig>;
