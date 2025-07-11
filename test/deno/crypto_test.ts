import { assert, assertEquals } from "@std/assert";
import { crypto } from "../../mod.deno.ts";

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

Deno.test(async function crypto_aes_gcm_256_by_key_test() {
  const cryptoAes256 = new crypto.CryptoAesGcm256();
  console.log("crypto name: " + cryptoAes256.nameByMode("short"));

  const privateKey = await crypto.CryptoAesGcm256.generateKey();

  let marktime;
  marktime = performance.now();
  const ciphertext = await cryptoAes256.encryptByKey(plainText, privateKey);
  console.log("加密耗時:", performance.now() - marktime);
  // console.log("密文: 🔓" + ciphertext);

  marktime = performance.now();
  const result = await cryptoAes256.decryptByKey(ciphertext, privateKey);
  console.log("解密耗時:", performance.now() - marktime);

  assert(result.ok, `解密錯誤: ${result.error}`);
  assertEquals(result.text, plainText);
  // console.log("Return text: " + result.text);
});

Deno.test(async function crypto_aes_gcm_256_by_password_test() {
  const cryptoAes256 = new crypto.CryptoAesGcm256Pbkdf2();
  console.log("crypto name: " + cryptoAes256.nameByMode("short"));

  const password = "my very long string that I want to use";

  let marktime;
  marktime = performance.now();
  const ciphertext = await cryptoAes256.encryptByPassword(plainText, password);
  console.log("加密耗時:", performance.now() - marktime);
  // console.log("密文: 🔓" + ciphertext);

  marktime = performance.now();
  const result = await cryptoAes256.decryptByPassword(ciphertext, password);
  console.log("解密耗時:", performance.now() - marktime);

  assert(result.ok, `解密錯誤: ${result.error}`);
  assertEquals(result.text, plainText);
  // console.log("Return text: " + result.text);
});
