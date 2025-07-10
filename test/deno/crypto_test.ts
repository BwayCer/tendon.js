import { assert, assertEquals } from "@std/assert";
import { crypto } from "../../mod.deno.ts";

Deno.test(async function cryptoAes256Test() {
  const plainText = `
    🇸🇦 ar_SA     مرحباً         (name: العربية)
    🇬🇧 en_GB     Hello         English
    🇮🇳 hi_IN     नमस्ते           (name: हिन्दी)
    🇯🇵 ja_JP     こんにちは    日本語
    🇰🇷 ko_KR     안녕하세요    한국어
    🇷🇺 ru_RU     Привет        Русский
    🇹🇭 th_TH     สวัสดี          ไทย
    🇹🇷 tr_TR     Merhaba       Türkçe
    🇻🇳 vi_VN     Xin chào      Tiếng Việt
    🇹🇼 zh_TW     你好          中文
  `;
  const password = "my very long string that I want to use";

  const cryptoAes256 = new crypto.CryptoAesGcm256Pbkdf2();
  console.log("crypto name: " + cryptoAes256.nameByMode("short"));

  let marktime;
  marktime = performance.now();
  const ciphertext = await cryptoAes256.encryptByPassword(plainText, password);
  console.log("加密耗時:", performance.now() - marktime);
  console.log("密文: 🔓" + ciphertext);

  marktime = performance.now();
  const result = await cryptoAes256.decryptByPassword(ciphertext, password);
  console.log("解密耗時:", performance.now() - marktime);

  assert(result.ok, `解密錯誤: ${result.error}`);
  assertEquals(result.text, plainText);
  // console.log("Return text: " + result.text);
});
