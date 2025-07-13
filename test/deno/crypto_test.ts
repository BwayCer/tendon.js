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
  // AesGcm256,  Pbkdf2Sha256e6, TransformHex
  // AesGcm256,  HkdfSha256,     TransformHex
  // HmacSha256, Pbkdf2Sha256e6, TransformHex
  // HmacSha512, Pbkdf2Sha256e6, TransformHex
  // HmacSha256, HkdfSha256,     TransformHex
  // HmacSha512, HkdfSha256,     TransformHex
  // AesGcm256,  Pbkdf2Sha256e6, TransformBase64
  // AesGcm256,  HkdfSha256,     TransformBase64
  // HmacSha512, Pbkdf2Sha256e6, TransformBase64
  Deno.test(
    "驗證 加解密/簽章 結果是否匹配",
    async function simple_verify_byKey_test() {
      const verifyInfos = [
        {
          mode: "encrypt",
          inputArgs: ["AesGcm256", "Pbkdf2Sha256e6", "TransformHex"],
          keyText:
            "e5e2eee90446eca6c10f0cd1f579fe15e282ab660253ed8954ea802d1356ea9b",
          ciphertext:
            "c91e30bddb74410d03f8fb32;b3f8bb98d65474a41c558fbd8be89913d984a26e52efcd447340c51a62f79277bbb3dc1e0c539f3aa2a6a608d1",
        },
        {
          mode: "encrypt",
          inputArgs: ["AesGcm256", "HkdfSha256", "TransformHex"],
          keyText:
            "db4569068ab43dda7f6d7e770490813cb8f43bbb354fc3ec553badee60077543",
          ciphertext:
            "c30c6a100e984a34136ca2ca;8dace637f0a3c4362c41f6e4f749a86d06e0113feffd53f2bfc9fd6a6636d1e2acae957de6872153ea788732eb",
        },
        {
          mode: "sign",
          inputArgs: ["HmacSha256", "Pbkdf2Sha256e6", "TransformHex"],
          keyText:
            "fe13be0f52a2504b5ba88b90c5214987d3928bd8168944d6d1f90cfa8e5d55f5b096f66249669201d26eccac917969dab39bc66b957283cc3c3a6ce74327c875",
          ciphertext:
            "43c7b6c6507a41fabb6ff2f9aa213e7bf90fa3c6f9559761f79bed4b92ebe307",
        },
        {
          mode: "sign",
          inputArgs: ["HmacSha512", "Pbkdf2Sha256e6", "TransformHex"],
          keyText:
            "411f2d3f117325c286014f11011d93f9128c66ad8c1fc6f15adf68056b393c4d6624cc1f495f2e602867877a84dd137e3300e056d37b3a8edc36b654682d5e14dc8faf48fcf20bfc84b82d1fccf7470272d3f06af989098130b02df8db1a458e36c7866a30ec2d05173ae3a300260d64023aac101353bfa0570b079e56f1dd0d",
          ciphertext:
            "8ef819b8cf5ca92d7df339901f5557860206dc3cac82da78c6fcfca0762376f3832183d47b22acb0a4ee6f8be5e6f9a1b71f0522b02e2093db16e91f685ee445",
        },
        {
          mode: "sign",
          inputArgs: ["HmacSha256", "HkdfSha256", "TransformHex"],
          keyText:
            "9d6af153a86208080fb7cee2e020630070f10434600144dd67d93c7d40a4c7be17720639d8041d72093f152c1a3075c3ead17edbc32af1c77f90a819f85b417c",
          ciphertext:
            "3daf62af40bc293bf0911fa93c713485e50519aecce3675095eb26adab8a739c",
        },
        {
          mode: "sign",
          inputArgs: ["HmacSha512", "HkdfSha256", "TransformHex"],
          keyText:
            "8dc66c8d1f73593877f60c63f6009130b64a3df90bae022d45eb08fbe95098d96bd896230ce8699a2ee56a91e4c13f4e170c6f307b7aae7ac4e3f84bf0b63959f0f82d7692092204ff76c270e1e2ffb1c987a94d8288431a74d0c2e86203c9442d2c81fef7e8e3844619cef549248a1cfbea768fdaf1e3e86c16ed314e22babe",
          ciphertext:
            "4e1be02e31fb972f1740d15bb3209a66dbd8a2c3e04881b4e087af010c9416512ee5737b7bd930196f4699ef53cb36ad53727f75e1d36d2a7b9bb09960ea8c59",
        },
        {
          mode: "encrypt",
          inputArgs: ["AesGcm256", "Pbkdf2Sha256e6", "TransformBase64"],
          keyText: "CzpG7lw4/pB7SmO2f/lwmwtGAX2hBTiQDdpi8eXJUrU=",
          ciphertext:
            "AaoGl3Irca7sYnfj;z8KgOhcolNDMY9YSG+dcLnLsG3gzz+QXyfyBDbe+lXhV590lF+UCVA1aFRAW",
        },
        {
          mode: "encrypt",
          inputArgs: ["AesGcm256", "HkdfSha256", "TransformBase64"],
          keyText: "w2LTu3yqkgk1suLv1z4eedT798hmhxn7dIQ1hT+yOo8=",
          ciphertext:
            "FJXA0fvFSDmR20dL;qm2hgrZWJ0zY/djAdzqh/0dzfh3x520bClZuC+H1qcfv1ckn0flYAKXt4JT2",
        },
        {
          mode: "sign",
          inputArgs: ["HmacSha512", "Pbkdf2Sha256e6", "TransformBase64"],
          keyText:
            "QxytFFCBiVFW1dGaSbDBxtrnwsW7ISPuXU5YRh6ATD4Q9uOQQiJhMta8nRpfx3F9ZubcdiIZ4t2NtG4kY/8+Unap9IiJIDA7rZt1JGe5GFveVk5KuH2I28cDtYQJQNkGhfgC2ZoEPSAl08FkyehrXDm7wbm+/JKp1chrENoF5Jw=",
          ciphertext:
            "Z/yXZ8odJvECaT4g8T+2BgBvVAGmZDjv3kCdGE6E0Zh/dinS6U/chNzy+gNL6vg9dMLKXIbTNtNn2Zep9aV+5w==",
        },
        // {
        //   isMake: true,
        //   mode: "sign",
        //   inputArgs: ["HmacSha256", "Pbkdf2Sha256e6", "TransformHex"],
        //   keyText: "",
        //   ciphertext: "",
        // },
      ];
      for (const verifyInfo of verifyInfos) {
        let {
          // @ts-ignore: 省事
          isMake,
        } = verifyInfo;
        const {
          mode,
          inputArgs,
          keyText,
          ciphertext,
        } = verifyInfo;

        // ## 創建

        const cryptoSimple = new CryptoSimple(
          ...inputArgs as CryptoConfigOption[],
        );
        console.log(
          "crypto mode name: " + cryptoSimple.name(mode as "encrypt" | "sign"),
        );

        // ## 準備

        isMake = isMake === true;

        let generateKey!: "generateEncryptKey" | "generateSignKey";
        let importKey!: "importEncryptKey" | "importSignKey";
        let simple_action!:
          | typeof simple_encrypt_action
          | typeof simple_sign_action;
        let simple_verify_action!:
          | typeof simple_verify_encrypt_action
          | typeof simple_verify_sign_action;
        switch (mode) {
          case "encrypt":
            generateKey = "generateEncryptKey";
            importKey = "importEncryptKey";
            simple_action = simple_encrypt_action;
            simple_verify_action = simple_verify_encrypt_action;
            break;
          case "sign":
            generateKey = "generateSignKey";
            importKey = "importSignKey";
            simple_action = simple_sign_action;
            simple_verify_action = simple_verify_sign_action;
            break;
        }
        const makeVerifyInfo = {
          mode,
          inputArgs,
          keyText: "",
          ciphertext: "",
        };

        // ## 開始驗證

        let privateKey;
        if (isMake) {
          privateKey = await cryptoSimple[generateKey]();
          makeVerifyInfo.keyText = await cryptoSimple.exportKey(privateKey);
        } else {
          const importKeyResult = await cryptoSimple[importKey](keyText);
          if (!importKeyResult.ok) {
            assert(
              importKeyResult.ok,
              `匯入金鑰錯誤: ${importKeyResult.error}`,
            );
          }
          privateKey = importKeyResult.value;
        }

        if (isMake) {
          console.log(JSON.stringify(makeVerifyInfo, null, 2));

          await simple_action(
            cryptoSimple,
            privateKey,
            plainShortText,
            true,
          );
        } else {
          await simple_verify_action(
            cryptoSimple,
            privateKey,
            plainShortText,
            ciphertext,
          );
        }
      }
    },
  );

  // AesGcm256,  Pbkdf2Sha256e6, TransformHex
  // AesGcm256,  HkdfSha256,     TransformHex
  // HmacSha256, HkdfSha256,     TransformHex
  // HmacSha512, HkdfSha256,     TransformHex
  Deno.test(
    "驗證派生金鑰是否匹配",
    async function simple_verify_derive_test() {
      const salt = tendonCrypto.utils.hexToBuffer(
        "aa283fb8465990e5ec6e46a1da66b6e5",
      );

      const verifyInfos = [
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
          "mode": "sign",
          "inputArgs": ["HmacSha256", "HkdfSha256", "TransformHex"],
          "seedKeyTxt":
            "a911b7345cb2d38bde77182ffb4ed31a712040f9c8019416c0294ffd9bb48284962dc9b21eee6d646ef8640b7c38f3cfa95c48e4d38552a83a71162402f147b6",
          "verifyKeyTxts": [
            "49a9b93b4de1d3b8093096a55173b562cccff7b2e914fcc21d1838c093ffca5a2fd76ae76e5a619d57149e79a0a744878245ac724b4cb4b898d4e21b99397c1c",
            "960b1a0a8fcd14d82771fad7be8e8d01ee91d075bca53a8ca0ccb4c9a8f601683c27821af6b970959feb75cf38802dcfc8c63993e893c6b763b9aa66c6deb52f",
            "e31b094a2845adfa0bbd93bf251c3a5b7a35047228a5b157440cd2c39f92d97a728b52e9efa14bf2a41256d163c8808c4c5ec99af4b2e19b8c3a89f7401d77a9",
          ],
        },
        {
          "mode": "sign",
          "inputArgs": ["HmacSha512", "HkdfSha256", "TransformHex"],
          "seedKeyTxt":
            "fcd4ea76776c455d81b85c857b24a0d66933e8bc961a60c7d7add3da1f89fd3471319bdbdeb4829b9d7846cd78225b1aa14d59ac130bb92fefcdc087156f303103ab24ee20f334091ab68ed0f91a18f4fe9d30b48838cd30acaf1ab6d3873090936f99c25e7f0a700a2bc2144ae7643248510777741078a86ad35b1c8e936275",
          "verifyKeyTxts": [
            "f40a218d9398176de092d3fb91beeafc173120fc208873ec872f1dc24582f0138ff6def18d7a46a9eb18a9d5638eb0c32d7f2d900e9387a2339086ff1ca5d42be505bfc9c5b6fc26a1a29cc1e1689e1a9d87030fc8b92d496d16dac34ab77cf48f1fdd6564be66e5bb3537f8ffec8fb7845ee880ceeeafe9176154f1dbb64316",
            "67871b5a0aee6e8cf77af90ea79e5ce671f905e32eb9de08050ec23e9d3a1da57d9957e5ae16b26a0c8afa3537561e09d071b23770431011f9f81a00bc22f19cbbdbb3af3582918a6b016200c24948609be2d89d975bc1f94a7f2e339d2ce9abafa6b157c2bc7afb3098191c9b8cbcbc242d4c7ba71bb14d722e40780ed07710",
            "7a7e476acdf7f9e945c35a6a72b369522716e3bf6c2ea296fbc904da8aa2e76452267d4cf89cd447ae1e07f3acd9eb9a3226c2b1c405fe022bd1ae076a0f797eeb4c901ffd4670bb706e6a4e4f7cb7d98b54b9f2668bfdff723819096353f17599675acb05ff634b298fe70ecd61d7af3fda75bff27774d5fcebb1c0e316699e",
            "a65a4ded64c69c14547199a40da4dc454d4512e856521db022ed48ccc02d062b1a9220fc7d23ed5fd35ede997b1a582e201a8157b8ab418b583a50380553f10647528e229eb13c156145367c08b3472b60c24ecda4691b421f4128fba37363b0f19f0eabbb86b40e388e35986f0533ae725106b09fcc5714a1f5bdcd86f11b89",
          ],
        },
        // {
        //   isMake: true,
        //   mode: "encrypt",
        //   inputArgs: ["AesGcm256", "Pbkdf2Sha256e6", "TransformHex"],
        //   seedKeyTxt: "",
        //   verifyKeyTxts: [],
        // },
      ];
      for (const verifyInfo of verifyInfos) {
        let {
          // @ts-ignore: 省事
          isMake,
        } = verifyInfo;
        const {
          mode,
          inputArgs,
          seedKeyTxt,
          verifyKeyTxts,
        } = verifyInfo;

        // ## 創建

        const cryptoSimple = new CryptoSimple(
          ...inputArgs as CryptoConfigOption[],
        );
        console.log(
          "crypto mode name: " + cryptoSimple.name(mode as "encrypt" | "sign"),
        );

        // ## 準備

        isMake = isMake === true;
        const loopTimes = isMake ? 3 : verifyKeyTxts.length;

        let generateKey!: "generateEncryptKey" | "generateSignKey";
        let importKey!: "importEncryptKey" | "importSignKey";
        let deriveKey!: "deriveEncryptKey" | "deriveSignKey";
        switch (mode) {
          case "encrypt":
            generateKey = "generateEncryptKey";
            importKey = "importEncryptKey";
            deriveKey = "deriveEncryptKey";
            break;
          case "sign":
            generateKey = "generateSignKey";
            importKey = "importSignKey";
            deriveKey = "deriveSignKey";
            break;
        }
        const makeVerifyInfo = {
          mode,
          inputArgs,
          seedKeyTxt: "",
          verifyKeyTxts: [] as string[],
        };

        // ## 開始驗證

        let seedKey;
        if (isMake) {
          seedKey = await cryptoSimple[generateKey]();
          makeVerifyInfo.seedKeyTxt = await cryptoSimple.exportKey(seedKey);
        } else {
          const importKeyResult = await cryptoSimple[importKey](seedKeyTxt);
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
          const deriveKeyResult = await cryptoSimple[deriveKey](endkey, salt);
          if (!deriveKeyResult.ok) {
            assert(
              deriveKeyResult.ok,
              `第 ${idx} 次派生金鑰錯誤: ${deriveKeyResult.error}`,
            );
          }
          endkey = deriveKeyResult.value;

          const endkeyTxt = await cryptoSimple.exportKey(endkey);
          if (isMake) {
            makeVerifyInfo.verifyKeyTxts.push(endkeyTxt);
          } else {
            assertEquals(endkeyTxt, verifyKeyTxts[idx], "派生金鑰不匹配");
          }
        }

        // ## 如果有需要製作材料

        if (isMake) {
          console.log(JSON.stringify(makeVerifyInfo, null, 2));
        }
      }
    },
  );
}

// ## 應用

async function runAvailabilityCheck(
  mode: "encrypt" | "sign",
  cryptoOptions: string[][],
  isPasswordKey = false,
) {
  for (const cryptoOption of cryptoOptions) {
    // ## 創建

    const cryptoSimple = new CryptoSimple(
      ...cryptoOption as CryptoConfigOption[],
    );
    console.log(
      "crypto mode name: " + cryptoSimple.name(mode as "encrypt" | "sign"),
    );

    // ## 開始驗證

    switch (mode) {
      case "encrypt": {
        let keyPsss!: CryptoKey | string;
        if (isPasswordKey) {
          keyPsss = "my very long string that I want to use";
        } else {
          keyPsss = await cryptoSimple.generateEncryptKey();
        }

        await simple_encrypt_action(
          cryptoSimple,
          keyPsss,
          plainShortText,
        );
        break;
      }
      case "sign": {
        const randKey = await cryptoSimple.generateSignKey();
        await simple_sign_action(
          cryptoSimple,
          randKey,
          plainShortText,
        );
        break;
      }
    }
  }
}

if (isAvailabilityCheckEnabled) {
  Deno.test(async function simple_byKey_test() {
    await runAvailabilityCheck("encrypt", [
      ["AesGcm256", "Pbkdf2Sha256e6", "TransformHex"],
      ["AesGcm256", "HkdfSha256", "TransformHex"],
      ["AesGcm256", "Pbkdf2Sha256e6", "TransformBase64"],
      ["AesGcm256", "HkdfSha256", "TransformBase64"],
    ]);
    await runAvailabilityCheck("sign", [
      ["HmacSha512", "Pbkdf2Sha256e6", "TransformHex"],
    ]);
  });

  Deno.test(async function simple_byPassword_test() {
    await runAvailabilityCheck("encrypt", [
      ["AesGcm256", "Pbkdf2Sha256e6", "TransformHex"],
    ], true);
  });
}
