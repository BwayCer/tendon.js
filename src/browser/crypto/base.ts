import { textEnc } from "./utils.ts";

// 產生 salt
export function generateSalt(len = 8): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(len));
}

// 雜湊 ---

export async function hashSha256(text: string): Promise<Uint8Array> {
  const textByteArray = textEnc.encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", textByteArray);
  return new Uint8Array(hashBuffer);
}
