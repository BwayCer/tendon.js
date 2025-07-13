import { assert, assertEquals } from "@std/assert";
import { crypto as tendonCrypto } from "../../mod.deno.ts";
import {
  CryptoConfigOption,
  Simple as CryptoSimple,
} from "../../src/browser/crypto/simple.ts";

const isPreciseTestEnabled = false;
const isVerificationEnabled = true;
const isAvailabilityCheckEnabled = true;

// ## 共享明文

const plainShortText = `Ke la kodo estu fidinda. 🙏`;
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

// ## 動作

async function simple_encrypt_action(
  cryptoSimple: CryptoSimple,
  keyPass: string | CryptoKey,
  plainText: string,
  isShowLog = false,
) {
  const marktime = performance.now();
  const encryptResult = await cryptoSimple.encrypt(keyPass, plainText);
  if (!encryptResult.ok) {
    assert(encryptResult.ok, `加密錯誤: ${encryptResult.error}`);
  }
  console.log(`加密耗時: ${performance.now() - marktime} ms`);
  const ciphertext = encryptResult.value;
  if (isShowLog) {
    if (keyPass.constructor === CryptoKey) {
      console.log("金鑰: " + await cryptoSimple.exportKey(keyPass));
    }
    console.log("密文: " + ciphertext);
    // console.log("密文: 🔓" + ciphertext);
  }

  await simple_verify_encrypt_action(
    cryptoSimple,
    keyPass,
    plainText,
    ciphertext,
    isShowLog,
  );
}

async function simple_verify_encrypt_action(
  cryptoSimple: CryptoSimple,
  keyPass: string | CryptoKey,
  plainText: string,
  ciphertext: string,
  isShowLog = false,
) {
  const marktime = performance.now();
  const decryptResult = await cryptoSimple.decrypt(keyPass, ciphertext);
  console.log(`解密耗時: ${performance.now() - marktime} ms`);
  if (!decryptResult.ok) {
    assert(decryptResult.ok, `解密錯誤: ${decryptResult.error}`);
  }
  assertEquals(decryptResult.value, plainText);
  if (isShowLog) {
    console.log("Return text: " + decryptResult.value);
  }
}

async function simple_sign_action(
  cryptoSimple: CryptoSimple,
  key: CryptoKey,
  plainText: string,
  isShowLog = false,
) {
  const marktime = performance.now();
  const signResult = await cryptoSimple.sign(key, plainText);
  if (!signResult.ok) {
    assert(signResult.ok, `簽章錯誤: ${signResult.error}`);
  }
  console.log(`簽章耗時: ${performance.now() - marktime} ms`);
  const signature = signResult.value;
  if (isShowLog) {
    console.log("金鑰: " + await cryptoSimple.exportKey(key));
    console.log("簽章雜湊: " + signature);
  }

  await simple_verify_sign_action(cryptoSimple, key, plainText, signature);
}

async function simple_verify_sign_action(
  cryptoSimple: CryptoSimple,
  key: CryptoKey,
  plainText: string,
  signature: string,
) {
  const marktime = performance.now();
  const verifyResult = await cryptoSimple.verify(key, signature, plainText);
  console.log(`驗證簽章耗時: ${performance.now() - marktime} ms`);
  if (!verifyResult.ok) {
    assert(verifyResult.ok, `驗證簽章錯誤: ${verifyResult.error}`);
  }
  assert(verifyResult.value, "簽章不匹配");
}

// NOTE: 解決第一次的耗時測試特別久問題
if (isPreciseTestEnabled) {
  Deno.test(
    async function heat_engine_simple_AesGcm256_Pbkdf2Sha256e6_byKey_test() {
      const cryptoSimple = new CryptoSimple();
      const privateKey = await cryptoSimple.generateEncryptKey();
      await simple_encrypt_action(cryptoSimple, privateKey, plainText);
    },
  );
}

// ## 驗證
if (isVerificationEnabled) {
  Deno.test(
    "驗證加解密結果是否匹配",
    async function simple_verify_encrypt_byKey_test() {
      const encryptOptions = [
        {
          inputArgs: ["AesGcm256", "Pbkdf2Sha256e6", "TransformHex"],
          keyText:
            "e5e2eee90446eca6c10f0cd1f579fe15e282ab660253ed8954ea802d1356ea9b",
          ciphertext:
            "c91e30bddb74410d03f8fb32;b3f8bb98d65474a41c558fbd8be89913d984a26e52efcd447340c51a62f79277bbb3dc1e0c539f3aa2a6a608d1",
        },
        {
          inputArgs: ["AesGcm256", "HkdfSha256", "TransformHex"],
          keyText:
            "db4569068ab43dda7f6d7e770490813cb8f43bbb354fc3ec553badee60077543",
          ciphertext:
            "c30c6a100e984a34136ca2ca;8dace637f0a3c4362c41f6e4f749a86d06e0113feffd53f2bfc9fd6a6636d1e2acae957de6872153ea788732eb",
        },
        {
          inputArgs: ["AesGcm256", "Pbkdf2Sha256e6", "TransformBase64"],
          keyText: "CzpG7lw4/pB7SmO2f/lwmwtGAX2hBTiQDdpi8eXJUrU=",
          ciphertext:
            "AaoGl3Irca7sYnfj;z8KgOhcolNDMY9YSG+dcLnLsG3gzz+QXyfyBDbe+lXhV590lF+UCVA1aFRAW",
        },
        {
          inputArgs: ["AesGcm256", "HkdfSha256", "TransformBase64"],
          keyText: "w2LTu3yqkgk1suLv1z4eedT798hmhxn7dIQ1hT+yOo8=",
          ciphertext:
            "FJXA0fvFSDmR20dL;qm2hgrZWJ0zY/djAdzqh/0dzfh3x520bClZuC+H1qcfv1ckn0flYAKXt4JT2",
        },
      ];
      for (const { inputArgs, keyText, ciphertext } of encryptOptions) {
        const cryptoSimple = new CryptoSimple(
          ...inputArgs as CryptoConfigOption[],
        );
        console.log("crypto full name: " + cryptoSimple.name());
        console.log("crypto mode name: " + cryptoSimple.name("encrypt"));

        // const privateKey = await cryptoSimple.generateEncryptKey();
        // await simple_encrypt_action(cryptoSimple, privateKey, plainShortText, true);
        const importKeyResult = await cryptoSimple.importEncryptKey(keyText);
        if (!importKeyResult.ok) {
          assert(importKeyResult.ok, `匯入金鑰錯誤: ${importKeyResult.error}`);
        }
        await simple_verify_encrypt_action(
          cryptoSimple,
          importKeyResult.value,
          plainShortText,
          ciphertext,
        );
      }
    },
  );

  Deno.test(
    "驗證簽章結果是否匹配",
    async function simple_verify_encrypt_byKey_test() {
      const encryptOptions = [
        {
          inputArgs: ["HmacSha512", "Pbkdf2Sha256e6", "TransformHex"],
          keyText:
            "411f2d3f117325c286014f11011d93f9128c66ad8c1fc6f15adf68056b393c4d6624cc1f495f2e602867877a84dd137e3300e056d37b3a8edc36b654682d5e14dc8faf48fcf20bfc84b82d1fccf7470272d3f06af989098130b02df8db1a458e36c7866a30ec2d05173ae3a300260d64023aac101353bfa0570b079e56f1dd0d",
          ciphertext:
            "8ef819b8cf5ca92d7df339901f5557860206dc3cac82da78c6fcfca0762376f3832183d47b22acb0a4ee6f8be5e6f9a1b71f0522b02e2093db16e91f685ee445",
        },
        {
          inputArgs: ["HmacSha512", "Pbkdf2Sha256e6", "TransformBase64"],
          keyText:
            "QxytFFCBiVFW1dGaSbDBxtrnwsW7ISPuXU5YRh6ATD4Q9uOQQiJhMta8nRpfx3F9ZubcdiIZ4t2NtG4kY/8+Unap9IiJIDA7rZt1JGe5GFveVk5KuH2I28cDtYQJQNkGhfgC2ZoEPSAl08FkyehrXDm7wbm+/JKp1chrENoF5Jw=",
          ciphertext:
            "Z/yXZ8odJvECaT4g8T+2BgBvVAGmZDjv3kCdGE6E0Zh/dinS6U/chNzy+gNL6vg9dMLKXIbTNtNn2Zep9aV+5w==",
        },
      ];
      for (const { inputArgs, keyText, ciphertext } of encryptOptions) {
        const cryptoSimple = new CryptoSimple(
          ...inputArgs as CryptoConfigOption[],
        );
        console.log("crypto full name: " + cryptoSimple.name());
        console.log("crypto mode name: " + cryptoSimple.name("sign"));

        // const privateKey = await cryptoSimple.generateSignKey();
        // await simple_sign_action(cryptoSimple, privateKey, plainShortText, true);
        const importKeyResult = await cryptoSimple.importSignKey(keyText);
        if (!importKeyResult.ok) {
          assert(importKeyResult.ok, `匯入金鑰錯誤: ${importKeyResult.error}`);
        }
        await simple_verify_sign_action(
          cryptoSimple,
          importKeyResult.value,
          plainShortText,
          ciphertext,
        );
      }
    },
  );

  Deno.test(
    "驗證派生金鑰是否匹配",
    async function simple_verify_derive_test() {
      const salt = tendonCrypto.utils.hexToBuffer(
        "aa283fb8465990e5ec6e46a1da66b6e5",
      );

      const encryptOptions = [
        {
          mode: "encrypt",
          inputArgs: ["AesGcm256", "Pbkdf2Sha256e6", "TransformHex"],
          seedKeyTxt:
            "508bca04e5cad976c4136f6e8b72696ad28042943c3b424d3e91675a282dceee",
          verifyKeyTxts: [
            "78e0ccc33ef4d76bee7e6f405e536770b5d0793ccd6f989c4154afbaf9a826a5",
            "bc123a4baa8e5d0cff07240719b9e83bf986ad7af97a049b365152cb74424d2a",
            "aba4c6df26b57e7ffb1738cd4624195ef14d7810cea993dd166ea9ca3b78751e",
          ],
        },
        {
          mode: "encrypt",
          inputArgs: ["AesGcm256", "HkdfSha256", "TransformHex"],
          seedKeyTxt:
            "306fbb6ae56ed328bd8c3501daa9b062fb81f9b0cdc302e58a2d1743d0c28d6b",
          verifyKeyTxts: [
            "63b64f282042b46e18e925533ecf06e0395fc84123f0b864cb9e0d24b31a1e37",
            "64469e4100af0646c28a94ab24479a447b2bc3b341f4307a1e72974aa2716293",
            "173a08010a88a833e3d49900976680628b10c51bfd653263ffa044a2d9140605",
          ],
        },
        {
          mode: "sign",
          inputArgs: ["HmacSha512", "HkdfSha256", "TransformHex"],
          seedKeyTxt:
            "e1bdaee98423e5a951204ea71bb050d3a0a66ec58e867cd0b55f386673a05be0",
          verifyKeyTxts: [
            "de23722ea5bdf768dc73198834c3c79a7720bd2f0f4772de8ba4da806a898e42",
            "6985eae38deff65c7d7cc75028f1901b03ef54c6baa4e25872adfcba7bcf620c",
            "d474d00b2fd172fcc1ff544698d6324f36983f9ad7cd370d5b174b9ca22acb46",
          ],
        },
        // {
        //   mode: "encrypt",
        //   // generateKey: "generateEncryptKey",
        //   inputArgs: ["AesGcm256", "Pbkdf2Sha256e6", "TransformHex"],
        //   seedKeyTxt: "",
        //   verifyKeyTxts: [],
        // },
      ];
      for (
        const {
          mode,
          // @ts-ignore: 省事
          generateKey,
          inputArgs,
          seedKeyTxt,
          verifyKeyTxts,
        } of encryptOptions
      ) {
        const cryptoSimple = new CryptoSimple(
          ...inputArgs as CryptoConfigOption[],
        );
        console.log(
          "crypto mode name: " + cryptoSimple.name(mode as "encrypt" | "sign"),
        );

        // 以 seedKeyTxt === null 為訊號作為開啟製作資料的判斷
        const isMakeInfo = generateKey !== undefined;
        const loopTimes = isMakeInfo ? 7 : verifyKeyTxts.length;

        let seedKey;
        if (isMakeInfo) {
          // @ts-ignore: 省事
          seedKey = await cryptoSimple[generateKey]();
          console.log("種子金鑰: " + await cryptoSimple.exportKey(seedKey));
        } else {
          const importKeyResult = await cryptoSimple.importEncryptKey(
            seedKeyTxt,
          );
          if (!importKeyResult.ok) {
            assert(
              importKeyResult.ok,
              `匯入金鑰錯誤: ${importKeyResult.error}`,
            );
          }
          seedKey = importKeyResult.value;
        }

        let endkey = seedKey;
        for (let idx = 0; idx < loopTimes; idx++) {
          const deriveKeyResult = await cryptoSimple.deriveEncryptKey(
            endkey,
            salt,
          );
          if (!deriveKeyResult.ok) {
            assert(
              deriveKeyResult.ok,
              `第 ${idx} 次派生金鑰錯誤: ${deriveKeyResult.error}`,
            );
          }
          endkey = deriveKeyResult.value;

          const endkeyTxt = await cryptoSimple.exportKey(endkey);
          if (isMakeInfo) {
            console.log(`第 ${idx} 次派生金鑰: ${endkeyTxt}`);
          } else {
            assertEquals(endkeyTxt, verifyKeyTxts[idx], "派生金鑰不匹配");
          }
        }
      }
    },
  );
}

// ## 應用
if (isAvailabilityCheckEnabled) {
  Deno.test(async function simple_encrypt_byKey_test() {
    const encryptOptions = [
      ["AesGcm256", "Pbkdf2Sha256e6", "TransformHex"],
      ["AesGcm256", "HkdfSha256", "TransformHex"],
      ["AesGcm256", "Pbkdf2Sha256e6", "TransformBase64"],
      ["AesGcm256", "HkdfSha256", "TransformBase64"],
    ];
    for (const inputArgs of encryptOptions) {
      const cryptoSimple = new CryptoSimple(
        ...inputArgs as CryptoConfigOption[],
      );
      console.log("crypto full name: " + cryptoSimple.name());
      console.log("crypto mode name: " + cryptoSimple.name("encrypt"));

      const privateKey = await cryptoSimple.generateEncryptKey();
      await simple_encrypt_action(cryptoSimple, privateKey, plainText);
    }
  });

  Deno.test(async function simple_AesGcm256_Pbkdf2Sha256e6_byPassword_test() {
    const cryptoSimple = new CryptoSimple("AesGcm256", "Pbkdf2Sha256e6");
    console.log("crypto full name: " + cryptoSimple.name());
    console.log("crypto mode name: " + cryptoSimple.name("encrypt"));

    const password = "my very long string that I want to use";
    await simple_encrypt_action(cryptoSimple, password, plainText);
  });

  Deno.test(async function simple_HmacSha512_Pbkdf2Sha256e6_test() {
    const cryptoSimple = new CryptoSimple("HmacSha512", "Pbkdf2Sha256e6");
    console.log("crypto full name: " + cryptoSimple.name());
    console.log("crypto mode name: " + cryptoSimple.name("sign"));

    const privateKey = await cryptoSimple.generateSignKey();
    await simple_sign_action(cryptoSimple, privateKey, plainText);
  });
}
