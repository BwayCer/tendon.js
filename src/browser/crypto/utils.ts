export const textEnc = new TextEncoder();
export const textDec = new TextDecoder();

// BufferTool ---

/// Uint8Array 轉為 Hex
export function bufferToHex(byteArray: Uint8Array): string {
  return Array.from(byteArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// 將 hex 字串轉為 Uint8Array
export function hexToBuffer(hex: string): Uint8Array | null {
  // Invalid hex length
  if (hex.length % 2 !== 0) {
    return null;
  }

  const bufLength = hex.length / 2;
  const byteArray = new Uint8Array(bufLength);
  for (let idx = 0; idx < bufLength; idx++) {
    const hexIndex = idx * 2;
    byteArray[idx] = parseInt(hex.slice(hexIndex, hexIndex + 2), 16);
  }
  return byteArray;
}

// Uint8Array 轉為 Base64
export function bufferToBase64(byteArray: Uint8Array): string {
  return btoa(String.fromCharCode(...byteArray));
}

// Base64 轉為 Uint8Array
export function base64ToBuffer(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

// Uint8Array List 轉為文字 (以 ";" 分隔的Base64)
export function dataToText(encryptedData: Uint8Array[]): string {
  return encryptedData
    .map((item) => bufferToBase64(item))
    .join(";");
}

// 文字轉為 Uint8Array List
export function textToData(ciphertext: string): Uint8Array[] {
  return ciphertext
    .split(";")
    .map((item) => base64ToBuffer(item) ?? new Uint8Array());
}
