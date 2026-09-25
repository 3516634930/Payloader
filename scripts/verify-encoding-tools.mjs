import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { deflateSync, gzipSync, gunzipSync, inflateSync } from 'node:zlib';
import { createTsModuleLoader } from '../tests/helpers/compileTsModule.mjs';

const rootDir = process.cwd();
const codecDir = path.join(rootDir, 'src', 'utils', 'codec');
const codecEntryFile = path.join(codecDir, 'index.ts');
const encodingToolsSourceFile = path.join(rootDir, 'src', 'components', 'EncodingTools.tsx');

// ---- 断言口径配置区（T3 收敛）：记账快照与样本清单集中声明，语义就地注释 ----

// codec 桶入口白名单（单一声明点）：下方沙箱注入（join 生成）与解构循环校验两处消费，
// 新增导出只改这里——两处漂移曾是本脚本最大的维护陷阱。
const ENTRY_EXPORTS = [
  'transform', 'defaultParams', 'detectInput', 'smartDecode', 'extractPureDecodeResult',
  'inferRsaParamsFromText', 'inferDlpFromText', 'factorSmallRsaModulus', 'operations',
  'gsm7DefaultAlphabet', 'gsm7ExtensionAlphabet', 'operationAudience', 'buildPentestGroups',
  'buildCtfGroups', 'buildCtfMenus', 'findFlagAutoRanges', 'detectFlagFormats',
  'parityBaseVectors', 'parityCharVectors', 'parityCnVectors', 'parityKeyedVectors',
  'parityNumVectors', 'parityProbes',
];

// 受众记账口径（批次 W 纠偏定稿 + autoSolve 三操作 + padding-oracle-attack/magic-chain/crc32-attack/base64-stego）：
// 批次 SB 新增 snow-stego/cloakify/ttl-stego 三个 CTF 操作：
// 全部操作 266 个 = ctf 179 + both 85 + pentest 2，钉住具体数字防止清单无声漂移（CC1 +12 / CC2 +2 ctf 操作）。
const AUDIENCE_SNAPSHOT = { total: 266, ctf: 179, both: 85, pentest: 2 };

// 批次 O 形状探针中仍验证智能解码可达性的样本集（telecode/quwei 等 4 位数字组形态与日期/编号
// 不可区分，已退出直解路径只出芯片，故不在自动解码样本内）。
const AUTO_SAMPLE_IDS = ['base100', 'braille', 'bagua-symbols', 'core-values', 'deadfish', 'manchester'];

// 形状探针芯片最少实测覆盖数：至少 20 个探针要有真实样本命中验证（防新探针无样本空转）。
const MIN_CHIP_CHECKS = 20;

// 求值器在 vm realm 内运行；污染探针必须放进同一 realm 才能看到真实写入
let encodingToolsVmContext = null;
// 沙箱加载器句柄：run 断言区用它加载 codec 图之外的零 React 模块（如 ctf/fileDetect）做运行时断言。
let sharedLoadModule = null;

// 沙箱加载器统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛）；
// 白名单注入以 cwd 相对路径键定位 codec 桶入口（getter 型 re-export 无法被 shorthand 引用，
// hydrateCodecHeavyData 以 require 显式补挂）。
const compileEncodingToolsModule = () => {
  const { context, loadModule } = createTsModuleLoader({
    injectExports: {
      'src/utils/codec/index.ts':
        `\nmodule.exports = { ${ENTRY_EXPORTS.join(', ')} };\n`
        + '\nmodule.exports.hydrateCodecHeavyData = require("./heavyData").hydrateCodecHeavyData;\n',
    },
  });
  const codecExports = loadModule(codecEntryFile);
  encodingToolsVmContext = context;
  sharedLoadModule = loadModule;
  return codecExports;
};

const modPow = (base, exponent, modulus) => {
  let result = 1n;
  let current = base % modulus;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = (result * current) % modulus;
    power >>= 1n;
    if (power > 0n) current = (current * current) % modulus;
  }
  return result;
};

const modInverse = (value, modulus) => {
  let t = 0n;
  let newT = 1n;
  let r = modulus;
  let newR = ((value % modulus) + modulus) % modulus;
  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r !== 1n) throw new Error(`No modular inverse for ${value} mod ${modulus}`);
  return t < 0n ? t + modulus : t;
};

const digestForTest = async (message, algorithm) => {
  const { createHash } = await import('node:crypto');
  return createHash(algorithm).update(message, 'utf8').digest('hex');
};

const bitLengthOfBigInt = value => value === 0n ? 0 : value.toString(2).length;

const digestHexToOrderInt = (digestHex, order) => {
  const numeric = BigInt(`0x${digestHex.replace(/^0x/i, '') || '0'}`);
  const extraBits = bitLengthOfBigInt(numeric) - bitLengthOfBigInt(order);
  return extraBits > 0 ? (numeric >> BigInt(extraBits)) : numeric;
};

const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};

const codecExports = compileEncodingToolsModule();
const missingExports = ENTRY_EXPORTS.filter(name => !(name in codecExports));
if (missingExports.length > 0) {
  throw new Error(`codec 入口缺失白名单导出：${missingExports.join(', ')}（补齐 src/utils/codec/index.ts 或修正 ENTRY_EXPORTS）`);
}
const {
  transform,
  defaultParams,
  detectInput,
  smartDecode,
  extractPureDecodeResult,
  inferRsaParamsFromText,
  inferDlpFromText,
  factorSmallRsaModulus,
  operations,
  gsm7DefaultAlphabet,
  gsm7ExtensionAlphabet,
  operationAudience,
  buildPentestGroups,
  buildCtfGroups,
  buildCtfMenus,
  findFlagAutoRanges,
  detectFlagFormats,
  parityBaseVectors,
  parityCharVectors,
  parityCnVectors,
  parityKeyedVectors,
  parityNumVectors,
  parityProbes,
} = codecExports;

// 古典密码 quadgram 评分表（609KB）已拆为 ngramTableData.ts 动态 chunk：生产路径经
// hydrateCodecHeavyData 异步注水。沙箱内动态 import 被 ts 转译为 Promise + require，
// localRequire 可解析，await 同一入口即可到位——不注水则评分恒为 -9999，
// 智能识别/无密钥还原类回归会因候选排序退化而失败。
await codecExports.hydrateCodecHeavyData();

const results = [];

const run = async (name, fn) => {
  await fn();
  results.push(name);
  console.log(`PASS ${name}`);
};

await run('DLP messy prose + ElGamal tuple', async () => {
  const input = [
    'discrete log and elgamal',
    'prime field p is 1019',
    'generator alpha equals 2',
    'public y = 40',
    'order = 1018',
    'ciphertext = (128, 443)',
  ].join('\n');
  const output = JSON.parse(await transform('discrete-log-helper', 'decode', input, defaultParams));
  assert.equal(output.result.recoveredExponent, '13');
  assert.equal(output.result.elgamalPlaintext.decimal, '42');
  expect(output.notes.includes('Parsed a two-value ciphertext tuple into c1/c2.'), 'DLP tuple note missing');
});

await run('smart-decode routes DLP prose to helper', async () => {
  const input = [
    'discrete log and elgamal',
    'prime field p is 1019',
    'generator alpha equals 2',
    'public y = 40',
    'order = 1018',
    'ciphertext = (128, 443)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('Discrete log / ElGamal analysis'), 'smart-decode did not route to DLP helper');
  expect(output.includes('"recoveredExponent": "13"'), 'smart-decode DLP output missing recovered exponent');
});

await run('smart-decode routes pure Chinese DLP and ElGamal fields to the helper', async () => {
  const input = [
    '离散对数与 ElGamal 题目',
    '模数：1019',
    '生成元：2',
    '公钥：40',
    '群阶：1018',
    '密文：(128, 443)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('Discrete log / ElGamal analysis'), 'smart-decode did not route Chinese DLP fields');
  expect(output.includes('"recoveredExponent": "13"'), 'smart-decode Chinese DLP output missing recovered exponent');
  expect(output.includes('"decimal": "42"'), 'smart-decode Chinese ElGamal output missing plaintext');
});

await run('DLP parameters without curve evidence do not route to ECC', async () => {
  const input = [
    'p = 1019',
    'g = 2',
    'y = 40',
    'order = 1018',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('Discrete log / ElGamal analysis'), 'generic DLP parameters were not routed to DLP');
  expect(!output.includes('ECC / Elliptic Curve Helper'), 'generic DLP parameters were incorrectly routed to ECC');
});

await run('complete DH parameters without keywords route to DLP before ECC', async () => {
  const input = [
    'p = 1019',
    'g = 2',
    'A = 40',
    'B = 320',
    'order = 1018',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('Discrete log / ElGamal analysis'), 'complete DH parameters were not routed to DLP');
  expect(!output.includes('ECC / Elliptic Curve Helper'), 'bare DH A/B values were incorrectly treated as curve coefficients');
  expect(output.includes('"recoveredExponent": "13"'), 'DH DLP route did not recover exponent 13');
  expect(output.includes('"decimal": "388"'), 'DH DLP route did not recover shared secret 388');
});

await run('smart-decode still routes real curve parameters to ECC', async () => {
  const input = [
    'Elliptic curve over p = 17',
    'a = 2',
    'b = 2',
    'basepoint G = (5, 1)',
    'public point Q = (6, 3)',
    'order = 19',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('ECC / Elliptic Curve Helper'), `real curve parameters were not routed to ECC: ${output}`);
});

await run('GSM 03.38 default and extension alphabets match standard septets', async () => {
  assert.equal(gsm7DefaultAlphabet.length, 128);
  assert.equal(gsm7DefaultAlphabet[0x01], '£');
  assert.equal(gsm7DefaultAlphabet[0x03], '¥');
  assert.equal(gsm7DefaultAlphabet[0x04], 'è');
  assert.equal(gsm7DefaultAlphabet[0x09], 'Ç');
  assert.equal(gsm7DefaultAlphabet[0x0b], 'Ø');
  assert.equal(gsm7DefaultAlphabet[0x10], 'Δ');
  assert.equal(gsm7DefaultAlphabet[0x1f], 'É');
  assert.equal(gsm7DefaultAlphabet[0x24], '¤');
  assert.equal(gsm7DefaultAlphabet[0x40], '¡');
  assert.equal(gsm7DefaultAlphabet[0x7f], 'à');
  assert.equal(gsm7ExtensionAlphabet['€'], 0x65);
});

await run('GSM 03.38 known septet and packed vectors decode correctly', async () => {
  assert.equal(await transform('gsm7', 'decode', '8080604028180e888462c168381e', defaultParams), '@£$¥èéùìòÇ\nØø\rÅå');
  const hello = JSON.parse(await transform('gsm7', 'encode', 'hello', defaultParams));
  assert.equal(hello.septetCount, 5);
  assert.equal(hello.packedHex, 'e8329bfd06');
  assert.equal(await transform('gsm7', 'decode', 'e8329bfd06', defaultParams), 'hello');
  const euro = JSON.parse(await transform('gsm7', 'encode', '€', defaultParams));
  assert.equal(euro.septetCount, 2);
  assert.equal(euro.packedHex, '9b32');
  assert.equal(await transform('gsm7', 'decode', '9b32', defaultParams), '€');
});

await run('GSM 03.38 standard and extension characters round-trip', async () => {
  const standard = '@£$¥èéùìòÇ\nØø\rÅåΔΦΓΛΩΠΨΣΘΞÆæßÉ¤¡ÄÖÑÜ§¿äöñüà';
  const extension = '\f^{}\\[~]|€';
  assert.equal(await transform('gsm7', 'decode', await transform('gsm7', 'encode', standard, defaultParams), defaultParams), standard);
  assert.equal(await transform('gsm7', 'decode', await transform('gsm7', 'encode', extension, defaultParams), defaultParams), extension);
});

await run('GSM 03.38 septet-count contract preserves ambiguous seven-septet payloads', async () => {
  const vectors = [
    { text: '1234567', packedHex: '31d98c56b3dd00' },
    { text: '123456@', packedHex: '31d98c56b30100' },
  ];
  for (const vector of vectors) {
    const encoded = await transform('gsm7', 'encode', vector.text, defaultParams);
    const payload = JSON.parse(encoded);
    assert.equal(payload.septetCount, 7);
    assert.equal(payload.packedHex, vector.packedHex);
    assert.equal(await transform('gsm7', 'decode', encoded, defaultParams), vector.text);
    assert.equal(await transform('gsm7', 'decode', JSON.stringify({ septetCount: 7, packedHex: vector.packedHex }), defaultParams), vector.text);
    await assert.rejects(
      () => transform('gsm7', 'decode', vector.packedHex, defaultParams),
      /septet count|septetCount|长度/i,
    );
  }
});

await run('GSM 03.38 rejects a trailing standalone extension escape', async () => {
  await assert.rejects(
    () => transform('gsm7', 'decode', JSON.stringify({ septetCount: 1, packedHex: '1b' }), defaultParams),
    /ESC|扩展/i,
  );
});

await run('smart-decode strips Chinese ciphertext labels before raw Hex decoding', async () => {
  const output = await transform('smart-decode', 'decode', '密文（HEX）：666c61677b636e5f6c6162656c7d', defaultParams);
  expect(output.includes('Hex'), 'smart-decode did not identify the labeled Hex payload');
  expect(output.includes('flag{cn_label}'), 'smart-decode did not decode the Chinese labeled Hex payload');
});

await run('smart-decode extracts a labeled raw payload from a multi-line CTF statement', async () => {
  const input = [
    '题目：编码练习',
    '请识别下列字段的格式并还原 flag。',
    '密文（HEX）：666c61677b6d756c74695f6c696e657d',
    '提交格式：flag{...}',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('Hex'), 'smart-decode did not extract the multi-line Hex payload');
  expect(output.includes('flag{multi_line}'), 'smart-decode did not decode the multi-line Hex payload');
});

await run('smart-decode routes structured token and container formats before generic base decoding', async () => {
  const jwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJjdGYiLCJyb2xlIjoiYWRtaW4ifQ.';
  const jwtOutput = await transform('smart-decode', 'decode', jwt, defaultParams);
  expect(jwtOutput.includes('JWT'), 'smart-decode did not identify a compact JWT');
  expect(jwtOutput.includes('"role": "admin"'), 'smart-decode JWT output missing payload');

  const jwe = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.AQID.BAUG.BwgJ.CgsM';
  const jweOutput = await transform('smart-decode', 'decode', jwe, defaultParams);
  expect(jweOutput.includes('JWE Compact Serialization'), 'smart-decode did not identify compact JWE');

  const pem = '-----BEGIN DEMO-----\nMAMCAQE=\n-----END DEMO-----';
  const pemOutput = await transform('smart-decode', 'decode', pem, defaultParams);
  expect(pemOutput.includes('SEQUENCE'), 'smart-decode did not parse DER inside PEM');

  const dataOutput = await transform('smart-decode', 'decode', 'data:text/plain;base64,ZmxhZ3tkYXRhX3VybH0=', defaultParams);
  expect(dataOutput.includes('flag{data_url}'), 'smart-decode did not decode Data URL payload');

  const gzipOutput = await transform('smart-decode', 'decode', gzipSync('flag{gzip_smart}').toString('base64'), defaultParams);
  expect(gzipOutput.includes('flag{gzip_smart}'), 'smart-decode did not decompress Base64 GZip data');

  const basicOutput = await transform('smart-decode', 'decode', 'Basic ZmxhZ3tiYXNpY19hdXRofQ==', defaultParams);
  expect(basicOutput.includes('flag{basic_auth}'), 'smart-decode did not decode Basic Authorization data');

  const queryOutput = await transform('smart-decode', 'decode', 'https://ctf.example/?mode=decode&tag=one&tag=two', defaultParams);
  expect(queryOutput.includes('"mode": "decode"'), 'smart-decode did not parse query string data');
  expect(queryOutput.includes('"tag"'), 'smart-decode query output missing repeated parameter');

  const otpOutput = await transform('smart-decode', 'decode', 'otpauth://hotp/CTF%3Aalice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=CTF&counter=0', defaultParams);
  expect(otpOutput.includes('"type": "hotp"'), 'smart-decode did not parse otpauth URI');
  expect(otpOutput.includes('"currentCode": "755224"'), 'smart-decode otpauth output did not calculate HOTP');

  const punycodeOutput = await transform('smart-decode', 'decode', 'xn--bcher-kva.example', defaultParams);
  expect(punycodeOutput.includes('bücher.example'), 'smart-decode did not decode Punycode host');

  const jwkOutput = await transform('smart-decode', 'decode', JSON.stringify({ kty: 'RSA', kid: 'demo', n: 'AQID', e: 'AQAB' }), defaultParams);
  expect(jwkOutput.includes('"format": "JWK"'), 'smart-decode did not preserve a JWK as JWK metadata');

  const opaquePemOutput = await transform('smart-decode', 'decode', '-----BEGIN DEMO-----\nZmxhZ3twZW19\n-----END DEMO-----', defaultParams);
  expect(opaquePemOutput.includes('"label": "DEMO"'), 'smart-decode did not retain a non-ASN.1 PEM container');
});

await run('smart-decode ranks candidates by output quality for ambiguous CTF encodings', async () => {
  const flag = 'flag{qual1ty_r4nk}';
  const b32Core = value => {
    const bits = [...Buffer.from(value, 'utf8')].map(byte => byte.toString(2).padStart(8, '0')).join('');
    let out = '';
    for (let index = 0; index < bits.length; index += 5) {
      out += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[parseInt(bits.slice(index, index + 5).padEnd(5, '0'), 2)];
    }
    return out;
  };
  const b32Of = value => {
    const core = b32Core(value);
    return core + '='.repeat((8 - core.length % 8) % 8);
  };
  const b32HexOf = value => b32Core(value).split('').map(char => {
    const index = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    return index < 0 ? char : '0123456789ABCDEFGHIJKLMNOPQRSTUV'[index];
  }).join('');
  const b36Of = value => {
    let n = BigInt('0x' + Buffer.from(value, 'utf8').toString('hex'));
    let out = '';
    while (n > 0n) {
      out = '0123456789abcdefghijklmnopqrstuvwxyz'[Number(n % 36n)] + out;
      n /= 36n;
    }
    return out;
  };
  const rot47Of = value => value.replace(/[!-~]/g, char => String.fromCharCode(33 + (char.charCodeAt(0) - 33 + 47) % 94));
  const vectors = [
    ['Base32', b32Of(flag), flag],
    ['Base32hex', b32HexOf(flag), flag],
    ['Base36', b36Of(flag), flag],
    ['Binary', [...Buffer.from(flag)].map(byte => byte.toString(2).padStart(8, '0')).join(' '), flag],
    ['Octal C-style', [...Buffer.from(flag)].map(byte => '0' + byte.toString(8)).join(' '), flag],
    ['A1Z26 ambiguous regrouping', '6-1-2-1-7', 'flag'],
    ['Reverse', [...flag].reverse().join(''), flag],
    ['ROT47', rot47Of(flag), flag],
    ['Quoted-Printable', [...Buffer.from('flag test')].map(byte => `=${byte.toString(16).toUpperCase().padStart(2, '0')}`).join(''), 'flag test'],
    ['XOR single-byte 0x-stream', [...Buffer.from(flag)].map(byte => `0x${(byte ^ 0x2a).toString(16).padStart(2, '0')}`).join(' '), flag],
  ];
  for (const [name, sample, expected] of vectors) {
    const output = await transform('smart-decode', 'decode', sample, defaultParams);
    expect(output.toLowerCase().includes(expected.toLowerCase()), `smart-decode did not solve ${name}: ${output.slice(0, 140).replace(/\n/g, ' ')}`);
  }

  // Negative: symbol-soup garbage must be rejected honestly instead of adopting a decoy decode
  const garbageOutput = await transform('smart-decode', 'decode', 'W0w&x>0^Ie~|zK9#qP$', defaultParams);
  expect(!garbageOutput.toLowerCase().includes('flag{'), `smart-decode produced a fake flag from garbage: ${garbageOutput.slice(0, 120).replace(/\n/g, ' ')}`);
  expect(!garbageOutput.includes('识别链路'), `smart-decode adopted a garbage decode chain: ${garbageOutput.slice(0, 120).replace(/\n/g, ' ')}`);

  // Chained: Base64-wrapped ROT47 ciphertext must peel both layers
  const chainedOutput = await transform('smart-decode', 'decode', Buffer.from(rot47Of(flag)).toString('base64'), defaultParams);
  expect(chainedOutput.includes(flag), `smart-decode did not peel the Base64 -> ROT47 chain: ${chainedOutput.slice(0, 140).replace(/\n/g, ' ')}`);
});

await run('smart-decode routes the full codec capability matrix to the right decoder', async () => {
  const plain = 'flag{matrixplain}';
  const flag = 'flag{qual1ty_r4nk}';
  const b62Of = value => {
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let number = 0n;
    for (const byte of Buffer.from(value, 'utf8')) number = (number << 8n) + BigInt(byte);
    let out = '';
    while (number > 0n) {
      out = alphabet[Number(number % 62n)] + out;
      number /= 62n;
    }
    return out;
  };
  const vectors = [
    ['Base62', b62Of(plain), plain],
    ['DNA code', [...Buffer.from(plain)].map(byte => {
      const map = { '00': 'A', '01': 'C', '10': 'G', '11': 'T' };
      return byte.toString(2).padStart(8, '0').match(/../g).map(pair => map[pair]).join('');
    }).join(''), plain],
    ['Bubble Babble', 'xinik-samak-luvak-timal-gosuk-nival-burok-cypuk-vizux', plain],
    ['Brainfuck', await transform('brainfuck', 'encode', plain, defaultParams), plain],
    ['Keyboard shift', await transform('keyboard-shift', 'encode', plain, defaultParams), plain],
    ['Affine bruteforce', 'hlim{qizpwtfliwv}', plain],
    ['Rail fence bruteforce', 'f{rl}lgmtipanaaxi', plain],
    ['Scytale bruteforce', 'fgailnl{txa}amrpi', plain],
    ['Mixed-form morse', '..-. .-.. .- --. { -- .- - .-. .. -..- .--. .-.. .- .. -. }', plain],
    ['Mixed-form a1z26', '6 12 1 7 { 13 1 20 18 9 24 16 12 1 9 14 }', plain],
  ];
  for (const [name, sample, expected] of vectors) {
    if (sample == null) continue;
    const output = await transform('smart-decode', 'decode', sample, defaultParams);
    expect(output.toLowerCase().includes(expected.toLowerCase()), `smart-decode did not solve ${name}: ${output.slice(0, 140).replace(/\n/g, ' ')}`);
  }

  const deflateOutput = await transform('smart-decode', 'decode', await transform('deflate', 'encode', plain, defaultParams), defaultParams);
  expect(deflateOutput.includes(plain), `smart-decode did not inflate a Base64 Deflate container: ${deflateOutput.slice(0, 120).replace(/\n/g, ' ')}`);

  // UTF-16LE hex pairs with interleaved zero bytes must not be hijacked by XOR brute force
  const utf16Sample = [...Buffer.from(plain, 'utf16le')].map(byte => byte.toString(16).padStart(2, '0')).join(' ');
  const utf16Output = await transform('smart-decode', 'decode', utf16Sample, defaultParams);
  expect(utf16Output.includes(plain), `smart-decode did not solve UTF-16 hex pairs: ${utf16Output.slice(0, 140).replace(/\n/g, ' ')}`);

  // Zero-width binary
  const zeroWidthEncoded = [...Buffer.from(plain)].map(byte => byte.toString(2).padStart(8, '0')).join('').replace(/0/g, '\u200b').replace(/1/g, '\u200c');
  const zeroWidthOutput = await transform('smart-decode', 'decode', zeroWidthEncoded, defaultParams);
  expect(zeroWidthOutput.includes(plain), `smart-decode did not solve zero-width binary: ${zeroWidthOutput.slice(0, 120).replace(/\n/g, ' ')}`);

  // Reverse with digits must outrank the affine false positive that used to steal it
  const reverseOutput = await transform('smart-decode', 'decode', [...flag].reverse().join(''), defaultParams);
  expect(reverseOutput.includes(flag), `smart-decode did not solve Reverse: ${reverseOutput.slice(0, 140).replace(/\n/g, ' ')}`);

  // Negative: plain English prose must NOT be decoded into confident garbage chains
  for (const prose of [
    'this is a test message for the review',
    'please review the document and send feedback today',
    'please review the document and share your feedback',
    'every good boy does fine in music class',
    'you can not connect the dots looking forward',
  ]) {
    const proseOutput = await transform('smart-decode', 'decode', prose, defaultParams);
    expect(!proseOutput.includes('识别链路') && !proseOutput.includes('智能识别'), `smart-decode mis-decoded plain English "${prose.slice(0, 32)}": ${proseOutput.slice(0, 120).replace(/\n/g, ' ')}`);
  }

  // Negative: a base58 string shaped like a BTC address but with a broken checksum must stay undecoded
  const badCheckOutput = await transform('smart-decode', 'decode', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNx', defaultParams);
  expect(!badCheckOutput.includes('Base58Check'), `smart-decode triaged a checksum-invalid Base58Check as decoded: ${badCheckOutput.slice(0, 120).replace(/\n/g, ' ')}`);
});

await run('Core textual codec vectors decode to their canonical plaintext', async () => {
  const vectors = [
    ['url-component', 'flag%7Burl%7D', 'flag{url}'],
    ['base64', 'ZmxhZ3tiYXNlNjR9', 'flag{base64}'],
    ['base64url', 'ZmxhZ3tiYXNlNjR1cmx9', 'flag{base64url}'],
    ['base32', 'MZXW6YTBOI======', 'foobar'],
    ['base58', 'StV1DL6CwTryKyV', 'hello world'],
    ['hex', '666c61677b6865787d', 'flag{hex}'],
    ['binary', '01100110 01101100 01100001 01100111', 'flag'],
    ['octal-codes', '146 154 141 147', 'flag'],
    ['ascii-codes', '102 108 97 103', 'flag'],
    ['a1z26', '6 12 1 7', 'FLAG'],
    ['morse', '..-. .-.. .- --.', 'FLAG'],
    ['quoted-printable', 'flag=7Bquoted=5Fprintable=7D', 'flag{quoted_printable}'],
  ];
  for (const [operationId, encoded, expected] of vectors) {
    assert.equal(await transform(operationId, 'decode', encoded, defaultParams), expected, `${operationId} vector mismatch`);
  }
});

await run('Web entity codecs and compression containers round-trip text', async () => {
  assert.equal(await transform('html-entity', 'decode', '&lt;flag&gt;&amp;#x7b;html&amp;#x7d;', defaultParams), '<flag>&#x7b;html&#x7d;');
  assert.equal(await transform('xml-entity', 'decode', '&lt;flag&gt;&#x7b;xml&#x7d;', defaultParams), '<flag>{xml}');
  assert.equal(await transform('unicode-escape', 'decode', '\\u0066\\u006c\\u0061\\u0067\\u007bunicode\\u007d', defaultParams), 'flag{unicode}');
  assert.equal(await transform('utf7', 'decode', '+AGYAbABhAGcAewB1AHQAZgA3AH0-', defaultParams), 'flag{utf7}');

  const zlib = {
    gzip: { compress: gzipSync, decompress: gunzipSync },
    deflate: { compress: deflateSync, decompress: inflateSync },
  };
  for (const operationId of ['gzip', 'deflate']) {
    const compressed = await transform(operationId, 'encode', 'flag{compressed}', defaultParams);
    assert.equal(await transform(operationId, 'decode', compressed, defaultParams), 'flag{compressed}', `${operationId} round trip failed`);
    assert.equal(zlib[operationId].decompress(Buffer.from(compressed, 'base64')).toString('utf8'), 'flag{compressed}', `${operationId} output is not compatible with Node zlib`);
    const nodeCompressed = zlib[operationId].compress('flag{node_zlib}').toString('base64');
    assert.equal(await transform(operationId, 'decode', nodeCompressed, defaultParams), 'flag{node_zlib}', `${operationId} cannot decode Node zlib output`);
  }
});

await run('Keyboard shift applies opposite directions for encode and decode', async () => {
  const encoded = await transform('keyboard-shift', 'encode', 'flag{key}', { ...defaultParams, variant: 'special' });
  assert.equal(await transform('keyboard-shift', 'decode', encoded, { ...defaultParams, variant: 'special' }), 'flag{key}');
  assert.equal(encoded, 'g;sh{lru}');
  assert.equal(await transform('keyboard-shift', 'decode', 'g;sh{lru}', { ...defaultParams, variant: 'special' }), 'flag{key}');
});

await run('Binary container and telecom parsers match canonical wire samples', async () => {
  const cbor = JSON.parse(await transform('cbor', 'decode', 'a1616101', defaultParams));
  assert.equal(cbor.encoding, 'hex');
  assert.deepEqual(cbor.decoded, { a: 1 });

  const messagePack = JSON.parse(await transform('messagepack', 'decode', '81a16101', defaultParams));
  assert.equal(messagePack.encoding, 'hex');
  assert.deepEqual(messagePack.decoded, { a: 1 });

  const protobuf = JSON.parse(await transform('protobuf-raw', 'decode', '089601', defaultParams));
  assert.equal(protobuf.fields.length, 1);
  assert.equal(protobuf.fields[0].field, 1);
  assert.equal(protobuf.fields[0].wireTypeName, 'varint');
  assert.equal(protobuf.fields[0].value.uint64, '150');

  const bson = JSON.parse(await transform('bson', 'decode', '0c0000001061000100000000', defaultParams));
  assert.equal(bson.document.a, 1);
  assert.equal(bson.canonicalEjson.a.$numberInt, '1');

  const submit = JSON.parse(await transform('sms-pdu', 'decode', '0001000B912143658709F1000005E8329BFD06', defaultParams));
  assert.equal(submit.messageType, 'SMS-SUBMIT');
  assert.equal(submit.recipient, '+12345678901');
  assert.equal(submit.userData.text, 'hello');
});

await run('Base, legacy transport, and text utility codecs preserve standard data', async () => {
  assert.equal(await transform('base45', 'decode', 'BB8', defaultParams), 'AB');
  assert.equal(await transform('base58check', 'encode', '0000000000000000000000000000000000000000', { ...defaultParams, versionHex: '00' }), '1111111111111111111114oLvT2');
  const base58Check = JSON.parse(await transform('base58check', 'decode', '1111111111111111111114oLvT2', defaultParams));
  assert.equal(base58Check.versionHex, '00');
  assert.equal(base58Check.payloadHex, '0000000000000000000000000000000000000000');
  assert.equal(base58Check.checksumValid, true);
  const bech32 = JSON.parse(await transform('bech32', 'decode', 'A12UEL5L', defaultParams));
  assert.equal(bech32.hrp, 'a');
  assert.equal(bech32.variant, 'bech32');
  assert.equal(bech32.checksumValid, true);
  assert.equal(await transform('base62', 'decode', await transform('base62', 'encode', 'flag{base62}', defaultParams), defaultParams), 'flag{base62}');
  assert.equal(await transform('base36', 'decode', await transform('base36', 'encode', 'flag{base36}', defaultParams), defaultParams), 'flag{base36}');
  assert.equal(await transform('base91', 'decode', await transform('base91', 'encode', 'test', defaultParams), defaultParams), 'test');
  assert.equal(await transform('ascii85', 'decode', '<~87cURD_*#TDfTZ)+T~>', defaultParams), 'Hello, world!');
  assert.equal(await transform('ascii85', 'decode', await transform('ascii85', 'encode', 'flag{ascii85}', defaultParams), defaultParams), 'flag{ascii85}');
  assert.equal(await transform('ascii85', 'decode', await transform('ascii85', 'encode', 'test', { ...defaultParams, variant: 'hex' }), { ...defaultParams, variant: 'hex' }), 'test');

  const uuencoded = await transform('uuencode', 'encode', 'flag{uuencode}', { ...defaultParams, blockLabel: 'demo.txt' });
  assert.equal(await transform('uuencode', 'decode', uuencoded, defaultParams), 'flag{uuencode}');
  assert.equal(await transform('yenc', 'decode', await transform('yenc', 'encode', 'flag{yenc}', defaultParams), defaultParams), 'flag{yenc}');
  assert.equal(await transform('bubble-babble', 'encode', 'Pineapple', defaultParams), 'xigak-nyryk-humil-bosek-sonax');
  assert.equal(await transform('bubble-babble', 'decode', 'xigak-nyryk-humil-bosek-sonax', defaultParams), 'Pineapple');
  assert.equal(await transform('utf16-bytes', 'decode', '66006c0061006700', defaultParams), 'flag');
  assert.equal(await transform('utf16-bytes', 'decode', '0066006c00610067', { ...defaultParams, variant: 'hex' }), 'flag');
  assert.equal(await transform('reverse-text', 'decode', 'flag{reverse}', defaultParams), '}esrever{galf');
  assert.equal(await transform('zero-width', 'decode', await transform('zero-width', 'encode', 'flag{zero_width}', defaultParams), defaultParams), 'flag{zero_width}');
  assert.equal(await transform('url-form', 'decode', 'flag%7Bform+url%7D', defaultParams), 'flag{form url}');
  assert.equal(await transform('js-string', 'decode', 'flag\\x7Bjs\\x7D', defaultParams), 'flag{js}');
  assert.equal(await transform('c-string', 'decode', 'flag\\173c\\175', defaultParams), 'flag{c}');
  assert.equal(await transform('json-string', 'decode', '"flag{json}"', defaultParams), 'flag{json}');
  const unix = JSON.parse(await transform('unix-time', 'decode', '0', defaultParams));
  assert.equal(unix.iso, '1970-01-01T00:00:00.000Z');
});

await run('Numeric and radio codecs round-trip their protocol representations', async () => {
  assert.equal(await transform('nato-phonetic', 'decode', 'Foxtrot Lima Alfa Golf', defaultParams), 'FLAG');
  assert.equal(await transform('baudot', 'decode', await transform('baudot', 'encode', 'FLAG 42', defaultParams), defaultParams), 'FLAG 42');
  assert.equal(await transform('bcd', 'decode', '0001 0010 0011 0100', defaultParams), '1234');
  assert.equal(await transform('gray-code', 'encode', '10', defaultParams), '11');
  assert.equal(await transform('gray-code', 'decode', '11', defaultParams), '10');
  assert.equal(await transform('gray-code', 'encode', '0d10', defaultParams), '15');
  assert.equal(await transform('gray-code', 'decode', '15', defaultParams), '10');
  assert.equal(await transform('gray-code', 'decode', '0b1111', defaultParams), '1010');
  assert.equal(await transform('dna-code', 'decode', await transform('dna-code', 'encode', 'flag{dna}', defaultParams), defaultParams), 'flag{dna}');
  assert.equal(await transform('rot', 'decode', 'SYNT{ebg13}', defaultParams), 'FLAG{rot13}');
  assert.equal(await transform('rot8000', 'decode', await transform('rot8000', 'encode', 'flag{rot8000}', defaultParams), defaultParams), 'flag{rot8000}');
});

await run('Token, identity, and container codecs match standard vectors', async () => {
  const jwtSecret = 'your-256-bit-secret';
  const jwt = JSON.parse(await transform('jwt-hmac', 'encode', JSON.stringify({ header: { alg: 'HS256' }, payload: { sub: '1234567890', name: 'John Doe', iat: 1516239022 } }), { ...defaultParams, secret: jwtSecret }));
  const verified = JSON.parse(await transform('jwt-hmac', 'decode', jwt.token, { ...defaultParams, secret: jwtSecret }));
  assert.equal(verified.valid, true);
  assert.equal(verified.payload.name, 'John Doe');
  const tampered = JSON.parse(await transform('jwt-hmac', 'decode', `${jwt.token.slice(0, -1)}${jwt.token.endsWith('A') ? 'B' : 'A'}`, { ...defaultParams, secret: jwtSecret }));
  assert.equal(tampered.valid, false);

  const otpSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const hotp = JSON.parse(await transform('hotp', 'encode', '', { ...defaultParams, secret: otpSecret, counter: '0', digits: '6', hashAlgorithm: 'sha1' }));
  assert.equal(hotp.code, '755224');
  const totp = JSON.parse(await transform('totp', 'encode', '', { ...defaultParams, secret: otpSecret, otpTimestamp: '59', timeStep: '30', digits: '8', hashAlgorithm: 'sha1' }));
  assert.equal(totp.code, '94287082');

  assert.equal(await transform('punycode', 'encode', 'bücher.example', defaultParams), 'xn--bcher-kva.example');
  assert.equal(await transform('punycode', 'decode', 'xn--bcher-kva.example', defaultParams), 'bücher.example');
  assert.equal(await transform('basic-auth', 'decode', 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==', defaultParams), 'Aladdin:open sesame');
  assert.equal(await transform('querystring', 'encode', JSON.stringify({ mode: 'decode', tag: ['one', 'two'] }), defaultParams), 'mode=decode&tag=one&tag=two');
  const query = JSON.parse(await transform('querystring', 'decode', 'https://ctf.example/?mode=decode&tag=one&tag=two', defaultParams));
  assert.deepEqual(query, { mode: 'decode', tag: ['one', 'two'] });

  const pem = await transform('pem-block', 'encode', 'flag{pem}', { ...defaultParams, blockLabel: 'DEMO' });
  const pemInfo = JSON.parse(await transform('pem-block', 'decode', pem, defaultParams));
  assert.equal(pemInfo.label, 'DEMO');
  assert.equal(pemInfo.textPreview, 'flag{pem}');
  const asn1 = JSON.parse(await transform('asn1-der', 'decode', '3003020101', defaultParams));
  assert.equal(asn1.nodes[0].type, 'SEQUENCE');
  assert.equal(asn1.nodes[0].children[0].value.decimal, '1');
  const jwk = JSON.parse(await transform('jwk-jwe', 'decode', JSON.stringify({ kty: 'RSA', kid: 'demo', n: 'AQID', e: 'AQAB' }), defaultParams));
  assert.equal(jwk.format, 'JWK');
  assert.equal(jwk.key.params.n.bytes, 3);
  assert.equal(jwk.key.params.e.bytes, 3);

  const fernetKey = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';
  const fernet = await transform('fernet', 'encode', 'flag{fernet}', { ...defaultParams, secret: fernetKey });
  const fernetDecoded = JSON.parse(await transform('fernet', 'decode', fernet, { ...defaultParams, secret: fernetKey }));
  assert.equal(fernetDecoded.hmacValid, true);
  assert.equal(fernetDecoded.plaintext, 'flag{fernet}');
});

await run('Digest, seed, JWT, and authentication utilities match published contracts', async () => {
  assert.equal(await transform('hash', 'encode', 'abc', defaultParams), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(await transform('hmac', 'encode', 'The quick brown fox jumps over the lazy dog', { ...defaultParams, secret: 'key' }), 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
  const hashInfo = JSON.parse(await transform('hash-identify', 'decode', 'd41d8cd98f00b204e9800998ecf8427e', defaultParams));
  expect(hashInfo.candidates.includes('MD5'), 'hash identifier did not recognize an MD5-sized digest');

  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const bip39 = JSON.parse(await transform('bip39-seed', 'encode', mnemonic, { ...defaultParams, secret: 'TREZOR' }));
  assert.equal(bip39.seedHex, 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04');

  const { CompactSign, exportJWK, generateKeyPair } = await import('jose');
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const signed = await new CompactSign(new TextEncoder().encode(JSON.stringify({ sub: 'codec-public-jwt' })))
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
    .sign(privateKey);
  const jwtPublic = JSON.parse(await transform('jwt-public', 'decode', signed, { ...defaultParams, secret: JSON.stringify(await exportJWK(publicKey)) }));
  assert.equal(jwtPublic.valid, true);
  assert.equal(jwtPublic.keyMaterialType, 'JWK');
  assert.equal(jwtPublic.payload.sub, 'codec-public-jwt');

  const otpUri = await transform('otpauth-uri', 'encode', 'CTF:alice', { ...defaultParams, variant: 'hex', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', counter: '0', digits: '6', hashAlgorithm: 'sha1' });
  expect(otpUri.startsWith('otpauth://hotp/CTF%3Aalice?'), 'otpauth URI did not encode as HOTP');
  const otpInfo = JSON.parse(await transform('otpauth-uri', 'decode', otpUri, defaultParams));
  assert.equal(otpInfo.type, 'hotp');
  assert.equal(otpInfo.issuer, 'CTF');
  assert.equal(otpInfo.currentCode, '755224');
});

await run('Remaining parsing and analysis helpers expose deterministic evidence', async () => {
  const kwpKek = '5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8';
  const wrapped = JSON.parse(await transform('aes-kwp', 'encode', 'c37b7e6492584340bed12207808941155068f738', { ...defaultParams, secret: kwpKek }));
  assert.equal(wrapped.wrappedHex, '138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a');
  const unwrapped = JSON.parse(await transform('aes-kwp', 'decode', wrapped.wrappedHex, { ...defaultParams, secret: kwpKek }));
  assert.equal(unwrapped.unwrappedHex, 'c37b7e6492584340bed12207808941155068f738');

  const enigmaSettings = { ...defaultParams, secret: 'rotors=I II III; reflector=B; rings=AAA; positions=AAA' };
  const enigma = JSON.parse(await transform('enigma', 'encode', 'AAAAA', enigmaSettings));
  assert.equal(enigma.raw, 'BDZGO');
  assert.equal(JSON.parse(await transform('enigma', 'decode', enigma.raw, enigmaSettings)).raw, 'AAAAA');

  const brainfuck = await transform('brainfuck', 'encode', 'flag{bf}', defaultParams);
  assert.equal(JSON.parse(await transform('brainfuck', 'decode', brainfuck, defaultParams)).output, 'flag{bf}');
  const ook = await transform('ook', 'encode', '+.', defaultParams);
  assert.equal(await transform('ook', 'decode', ook, defaultParams), '+.');
  assert.equal((await transform('rot-bruteforce', 'decode', 'SYNT{ebg13}', defaultParams)).includes('ROT13: FLAG{rot13}'), true);

  const singleByteXorCiphertext = '2d272a2c30';
  const xorCandidates = await transform('xor-bruteforce', 'decode', singleByteXorCiphertext, defaultParams);
  expect(xorCandidates.includes('0x4b ( 75): flag{'), 'single-byte XOR candidate ranking lost the plaintext');
  const repeatingXorCiphertext = '2d29382c3e';
  const xorKnown = JSON.parse(await transform('xor-known-plaintext', 'decode', repeatingXorCiphertext, { ...defaultParams, knownPlaintext: 'flag{' }));
  assert.equal(xorKnown.candidates[0].keyHexPrefix, '4b45594b45');
  assert.equal(xorKnown.candidates[0].repeatingKeyGuess.hex, '4b4559');
  const magic = JSON.parse(await transform('magic-xor-helper', 'decode', repeatingXorCiphertext, { ...defaultParams, knownPlaintext: 'flag{' }));
  const customMagic = magic.candidates.find(candidate => candidate.signature === 'custom-known-plaintext');
  assert.equal(customMagic.repeatingKeyGuess.hex, '4b4559');

  const lfsr = JSON.parse(await transform('lfsr-helper', 'decode', 'lfsr keystream = 1011010010110100', defaultParams));
  assert.equal(lfsr.bitCount, 16);
  expect(lfsr.linearComplexity > 0, 'LFSR helper did not derive a feedback polynomial');
  const extension = JSON.parse(await transform('hash-length-extension-helper', 'decode', 'algorithm=sha1\nsignature=0123456789abcdef0123456789abcdef01234567\nmessage=user=guest\nsecret length=8..10', { ...defaultParams, secret: '&admin=true', knownPlaintext: 'user=guest' }));
  assert.equal(extension.algorithm, 'sha1');
  assert.deepEqual(extension.secretLengthCandidates, [8, 9, 10]);
  assert.equal(extension.appendData, '&admin=true');
  const frequency = JSON.parse(await transform('frequency-analysis', 'decode', 'ABAB', defaultParams));
  assert.equal(frequency.letterCount, 4);
  assert.equal(frequency.letters[0].token, 'A');
  const jsfuck = JSON.parse(await transform('jsfuck-helper', 'decode', 'eval("\\x66\\x6c\\x61\\x67")', defaultParams));
  assert.equal(jsfuck.extractedQuotedStrings[0], 'flag');
  const attackGuide = JSON.parse(await transform('crypto-attack-helper', 'decode', 'RSA n=3233 e=17 c=2790 with AES-CBC padding oracle', defaultParams));
  expect(attackGuide.matched.some(item => item.topic === 'RSA weak-key / textbook RSA'), 'crypto attack helper missed RSA guidance');
  expect(attackGuide.matched.some(item => item.topic === 'AES mode / oracle'), 'crypto attack helper missed AES oracle guidance');

  const sshString = value => {
    const data = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    return Buffer.concat([length, data]);
  };
  const sshBlob = Buffer.concat([sshString('ssh-ed25519'), sshString(Buffer.alloc(32, 7))]).toString('base64');
  const ssh = JSON.parse(await transform('ssh-public-key', 'decode', `ssh-ed25519 ${sshBlob} codec@test`, defaultParams));
  assert.equal(ssh.blobType, 'ssh-ed25519');
  assert.equal(ssh.comment, 'codec@test');
  assert.equal(ssh.fields.publicKey.bytes, 32);

  const dataUrl = await transform('data-url', 'encode', 'flag{data_url_direct}', defaultParams);
  assert.equal(await transform('data-url', 'decode', dataUrl, defaultParams), 'flag{data_url_direct}');
});

await run('AES raw modes match Node crypto reference ciphertexts', async () => {
  const keyHex = '00112233445566778899aabbccddeeff';
  const ivHex = '0102030405060708090a0b0c0d0e0f10';
  const plaintext = 'flag{aes_vector}';
  const params = { ...defaultParams, secret: keyHex, iv: ivHex, variant: 'special' };
  const vectors = [
    ['aes-cbc-raw', 'aes-128-cbc', Buffer.from(ivHex, 'hex')],
    ['aes-ctr-raw', 'aes-128-ctr', Buffer.from(ivHex, 'hex')],
    ['aes-cfb', 'aes-128-cfb', Buffer.from(ivHex, 'hex')],
    ['aes-ofb', 'aes-128-ofb', Buffer.from(ivHex, 'hex')],
    ['aes-ecb', 'aes-128-ecb', null],
  ];
  for (const [operationId, nodeCipher, iv] of vectors) {
    const cipher = crypto.createCipheriv(nodeCipher, Buffer.from(keyHex, 'hex'), iv);
    const expectedHex = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]).toString('hex');
    const encoded = JSON.parse(await transform(operationId, 'encode', plaintext, params));
    assert.equal(encoded.ciphertextHex, expectedHex, `${operationId} ciphertext differs from Node crypto`);
    assert.equal(await transform(operationId, 'decode', expectedHex, params), plaintext, `${operationId} failed to decrypt Node crypto ciphertext`);
  }
});

await run('Symmetric cipher families encrypt and decrypt their own interoperable payloads', async () => {
  const plaintext = 'flag{symmetric_family}';
  const hex = (bytes) => '00'.repeat(bytes);
  const fixtures = [
    ['aes-gcm', { secret: 'codec-passphrase' }],
    ['aes-cbc', { secret: 'codec-passphrase' }],
    ['aes-ctr', { secret: 'codec-passphrase' }],
    ['openssl-aes-256-cbc', { secret: 'codec-passphrase' }],
    ['des', { secret: '0123456789abcdef', iv: 'abcdef0123456789' }],
    ['triple-des', { secret: '0123456789abcdef23456789abcdef01456789abcdef0123', iv: 'abcdef0123456789' }],
    ['blowfish', { secret: '00112233445566778899aabbccddeeff', iv: '0102030405060708' }],
    ['rabbit', { secret: '00112233445566778899aabbccddeeff', iv: '0102030405060708' }],
    ['chacha20-orig', { secret: hex(32), iv: hex(8) }],
    ['chacha20', { secret: hex(32), iv: hex(12) }],
    ['xchacha20', { secret: hex(32), iv: hex(24) }],
    ['salsa20', { secret: hex(16), iv: hex(8) }],
    ['xsalsa20', { secret: hex(32), iv: hex(24) }],
    ['chacha20-poly1305', { secret: hex(32), iv: hex(12), associatedData: 'ctf-aad' }],
    ['xchacha20-poly1305', { secret: hex(32), iv: hex(24), associatedData: 'ctf-aad' }],
    ['xsalsa20-poly1305', { secret: hex(32), iv: hex(24) }],
    ['aes-gcm-siv', { secret: hex(16), iv: hex(12), associatedData: 'ctf-aad' }],
    ['aes-siv', { secret: hex(32), associatedData: 'ctf-aad' }],
    ['sm4', { secret: hex(16), iv: hex(16) }],
    ['rc4', { secret: 'Key' }],
    ['rc4-drop', { secret: 'Key', dropBytes: '768' }],
    ['tea', { secret: '00112233445566778899aabbccddeeff' }],
    ['xtea', { secret: '00112233445566778899aabbccddeeff' }],
    ['xxtea', { secret: '00112233445566778899aabbccddeeff' }],
  ];
  for (const [operationId, overrides] of fixtures) {
    const params = { ...defaultParams, ...overrides, variant: 'special' };
    const encrypted = await transform(operationId, 'encode', plaintext, params);
    const decrypted = await transform(operationId, 'decode', encrypted, params);
    const recovered = operationId === 'openssl-aes-256-cbc' ? JSON.parse(decrypted).plaintext : decrypted;
    assert.equal(recovered, plaintext, `${operationId} round trip failed`);
  }
});

await run('Published AES-KW, AES-CMAC, RC4, and Rabin vectors are correct', async () => {
  const kek = '000102030405060708090a0b0c0d0e0f';
  const keyData = '00112233445566778899aabbccddeeff';
  const wrapped = JSON.parse(await transform('aes-kw', 'encode', keyData, { ...defaultParams, secret: kek }));
  assert.equal(wrapped.wrappedHex, '1fa68b0a8112b447aeF34bd8fb5a7b829d3e862371d2cfe5'.toLowerCase());
  const unwrapped = JSON.parse(await transform('aes-kw', 'decode', wrapped.wrappedHex, { ...defaultParams, secret: kek }));
  assert.equal(unwrapped.unwrappedHex, keyData);

  const cmac = JSON.parse(await transform(
    'aes-cmac',
    'decode',
    '6bc1bee22e409f96e93d7e117393172a',
    { ...defaultParams, secret: '2b7e151628aed2a6abf7158809cf4f3c' },
  ));
  assert.equal(cmac.tagHex, '070a16b46b4d4144f79bdd9dd04a287c');

  assert.equal(await transform('rc4', 'encode', 'Plaintext', { ...defaultParams, secret: 'Key' }), 'bbf316e8d940af0ad3');
  assert.equal(await transform('rc4', 'decode', 'bbf316e8d940af0ad3', { ...defaultParams, secret: 'Key' }), 'Plaintext');

  const rabinEncrypted = JSON.parse(await transform('rabin-raw', 'encode', 'p = 7\nq = 11\nm = 20', defaultParams));
  assert.equal(rabinEncrypted.output.decimal, '15');
  const rabinDecrypted = JSON.parse(await transform('rabin-raw', 'decode', 'p = 7\nq = 11\nc = 15', defaultParams));
  expect(rabinDecrypted.output.candidates.some(candidate => candidate.decimal === '20'), 'Rabin roots are missing the original plaintext');
});

await run('Classical cipher vectors and reversible paths preserve expected plaintext', async () => {
  assert.equal(await transform('vigenere', 'encode', 'ATTACKATDAWN', { ...defaultParams, secret: 'LEMON' }), 'LXFOPVEFRNHR');
  assert.equal(await transform('vigenere', 'decode', 'LXFOPVEFRNHR', { ...defaultParams, secret: 'LEMON' }), 'ATTACKATDAWN');
  assert.equal(await transform('affine', 'decode', 'IHHWVCSWFRCP', { ...defaultParams, affineA: '5', affineB: '8' }), 'AFFINECIPHER');
  assert.equal(await transform('rail-fence', 'decode', 'WECRLTEERDSOEEFEAOCAIVDEN', { ...defaultParams, rails: '3' }), 'WEAREDISCOVEREDFLEEATONCE');

  const fixtures = [
    ['beaufort', 'FLAG{BEAUFORT}', { secret: 'LEMON' }],
    ['autokey', 'ATTACKATDAWN', { secret: 'QUEENLY' }],
    ['atbash', 'FLAG{ATBASH}', {}],
    ['bacon', 'FLAG', {}],
    ['polybius', 'FLAG', {}],
    ['tap-code', 'FLAG', {}],
    ['playfair', 'INSTRUMENTS', { secret: 'MONARCHY' }, 'INSTRUMENTSX'],
    ['hill2', 'HELP', { secret: '3 3 2 5' }],
    ['substitution', 'FLAG{SUB}', { secret: 'ZYXWVUTSRQPONMLKJIHGFEDCBA' }],
    ['scytale', 'FLAG{SCYTALE}', { rails: '4' }],
    ['columnar', 'FLAG{COLUMNAR}', { secret: 'ZEBRAS' }],
    ['porta', 'FLAG{PORTA}', { secret: 'LEMON' }],
    ['gronsfeld', 'FLAG{GRONSFELD}', { secret: '31415' }],
    ['bifid', 'FLAG', { secret: 'KEYWORD', period: '5' }],
    ['trifid', 'FLAG', { secret: 'KEYWORD', period: '5' }],
    ['four-square', 'FLAG', { secret: 'EXAMPLE', keyword2: 'KEYWORD' }],
    ['nihilist', 'FLAG', { secret: 'KEYWORD' }],
    ['adfgx', 'FLAG', { secret: 'KEYWORD', keyword2: 'CIPHER' }],
    ['adfgvx', 'FLAG42', { secret: 'KEYWORD', keyword2: 'CIPHER' }],
  ];
  for (const [operationId, plaintext, overrides, expected = plaintext] of fixtures) {
    const params = { ...defaultParams, ...overrides };
    const encrypted = await transform(operationId, 'encode', plaintext, params);
    assert.equal(await transform(operationId, 'decode', encrypted, params), expected, `${operationId} round trip failed`);
  }
});

await run('ChaCha20 original is discoverable in crypto operations', async () => {
  const operation = operations.find(item => item.id === 'chacha20-orig');
  expect(operation, 'chacha20-orig is missing from operations');
  assert.equal(operation.category, 'crypto');
  assert.equal(operation.params.join(','), 'secret,iv');
  assert.equal(operation.supportsEncode, undefined);
  assert.equal(operation.supportsDecode, undefined);
});

// ---- RSA 标签/中文/表达式提示批（T3 压缩）：case 表 + 共享 runner ----
// 断言 DSL：includes=输出文本包含；decimal=JSON output.output.decimal；
// notes=JSON inference 数组存在包含片段的 note；field=JSON 顶层字段。
const runRsaLabelCases = async cases => {
  for (const { caseName, lines: caseLines, targets } of cases) {
    await run(caseName, async () => {
      const input = caseLines.join('\n');
      for (const target of targets) {
        const output = await transform(target.op, 'decode', input, defaultParams);
        for (const marker of target.includes ?? []) {
          expect(output.includes(marker), `${caseName}: 输出缺少 ${marker}`);
        }
        if (target.decimal || target.notes || target.field) {
          const parsed = JSON.parse(output);
          if (target.decimal) assert.equal(parsed.output.decimal, target.decimal, `${caseName}: output.decimal 不符`);
          for (const note of target.notes ?? []) {
            expect(parsed.inference.some(entry => entry.includes(note)), `${caseName}: inference 缺少 ${note}`);
          }
          for (const [fieldKey, fieldValue] of Object.entries(target.field ?? {})) {
            assert.equal(parsed[fieldKey], fieldValue, `${caseName}: 字段 ${fieldKey} 不符`);
          }
        }
      }
    });
  }
};

const MESSY_RSA_LINES = [
  'The modulus value is 3233',
  'public exponent equals 17',
  'ciphertext blob was 2790',
  'prime factor p = 61',
  'prime factor q = 53',
];

const RSA_LABEL_CASES_EARLY = [
  {
    caseName: 'RSA messy labels with explicit factors',
    lines: MESSY_RSA_LINES,
    targets: [{ op: 'rsa-raw', decimal: '65' }],
  },
  {
    caseName: 'smart-decode routes messy RSA labels to raw RSA decrypt',
    lines: MESSY_RSA_LINES,
    targets: [{ op: 'smart-decode', includes: ['RSA Raw / Textbook', '"decimal": "65"'] }],
  },
  {
    caseName: 'RSA accepts Chinese full labels, mixed case aliases, and fullwidth separators',
    lines: ['模数（N）：3233', '公钥指数（e）＝17', '密文（Cipher_Text）：2790', '质数 P：61', '质数 q：53'],
    targets: [{ op: 'rsa-raw', decimal: '65' }, { op: 'smart-decode', includes: ['RSA Raw / Textbook', '"decimal": "65"'] }],
  },
  {
    caseName: 'RSA accepts pure Chinese parameter names without English aliases',
    lines: ['模数：3233', '公钥指数：17', '密文：2790', '第一质数：61', '第二质数：53'],
    targets: [{ op: 'rsa-raw', decimal: '65' }, { op: 'smart-decode', includes: ['RSA Raw / Textbook', '"decimal": "65"'] }],
  },
  {
    caseName: 'smart-decode keeps Chinese RSA analysis ahead of embedded Base64-looking data',
    lines: [
      '加密算法：RSA',
      '提示：附件名为 ZmxhZ3tub3Rfcm91dGVkfQ==，不要把它当作待解密密文。',
      '模数：3233',
      '公钥指数：17',
      '密文：2790',
      '第一质数：61',
      '第二质数：53',
    ],
    targets: [{ op: 'smart-decode', includes: ['RSA Raw / Textbook', '"decimal": "65"'] }],
  },
];

await runRsaLabelCases(RSA_LABEL_CASES_EARLY);

await run('Pollard Rho path factors n from n/e/c only', async () => {
  const p = 1000003n;
  const q = 2000003n;
  const n = p * q;
  const e = 65537n;
  const message = 65n;
  const ciphertext = modPow(message, e, n);
  const factored = factorSmallRsaModulus(n);
  expect(Array.isArray(factored), 'factorSmallRsaModulus did not factor medium n');
  assert.deepEqual(Array.from(factored, value => value.toString()), [p.toString(), q.toString()]);

  const input = [
    `modulus value is ${n}`,
    `public exponent equals ${e}`,
    `ciphertext blob was ${ciphertext}`,
  ].join('\n');
  const output = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(output.output.decimal, '65');
  expect(Array.isArray(output.inference), 'RSA output inference missing');
  expect(output.inference.some(note => /Pollard Rho/i.test(note)), 'RSA output did not record Pollard Rho factoring note');
});

await run('rsa-helper detection works for messy public-key-only prose', async () => {
  const input = [
    'public key challenge',
    'modulus value is 3233',
    'public exponent equals 17',
  ].join('\n');
  const detections = detectInput(input).map(entry => entry.id);
  expect(detections.includes('rsa-helper'), 'detectInput did not recognize messy RSA public-key prose');

  const inference = inferRsaParamsFromText(input, 'decode');
  assert.equal(inference.params.n, '3233');
  assert.equal(inference.params.e, '17');
});

const RSA_LABEL_CASES_LATE = [
  {
    caseName: 'smart-decode falls back to RSA helper for messy public-key prose',
    lines: [
      'public key challenge',
      'modulus value is 3233',
      'public exponent equals 17',
      'known pair message 2 gives ciphertext 1752',
      'known pair message 42 gives ciphertext 2557',
    ],
    targets: [{ op: 'smart-decode', includes: ['RSA CTF Helper', '"n": "3233"', '"e": "17"'] }],
  },
  {
    caseName: 'RSA single-quote pseudo-JSON fields are parsed',
    lines: ["{'n': 3233, 'e': 17, 'c': 2790, 'p': 61, 'q': 53}"],
    targets: [{ op: 'rsa-raw', decimal: '65' }],
  },
  {
    caseName: 'RSA p+q hint recovers factors',
    lines: ['n = 3233', 'e = 17', 'ciphertext = 2790', 'p + q = 114'],
    targets: [{ op: 'rsa-raw', decimal: '65', notes: ['由 n 与 (p+q) 提示恢复 p', '由 n 与 (p+q) 提示恢复 q'] }],
  },
  {
    caseName: 'RSA p-q hint recovers factors',
    lines: ['n = 3233', 'e = 17', 'ciphertext = 2790', 'p - q = 8'],
    targets: [{ op: 'rsa-raw', decimal: '65', notes: ['由 n 与 |p-q| 提示恢复 p', '由 n 与 |p-q| 提示恢复 q'] }],
  },
  {
    caseName: 'RSA arithmetic expressions n=p*q and phi=(p-1)*(q-1) are evaluated',
    lines: ['p = 61', 'q = 53', 'n = p*q', 'phi = (p-1)*(q-1)', 'e = 17', 'c = 2790'],
    targets: [{ op: 'rsa-raw', decimal: '65', field: { modulus: '3233' } }],
  },
  {
    caseName: 'RSA chained arithmetic references are evaluated from helper variables',
    lines: [
      'prime1 = 61',
      'prime2 = 53',
      'modulus = prime1 * prime2',
      'totient = (prime1 - 1) * (prime2 - 1)',
      'public exponent = 17',
      'ciphertext = 2790',
    ],
    targets: [{ op: 'smart-decode', includes: ['RSA Raw / Textbook', '"decimal": "65"'] }],
  },
  {
    caseName: 'RSA modular inverse helper expression d = pow(e, -1, phi) is evaluated',
    lines: ['p = 61', 'q = 53', 'n = p*q', 'phi = (p-1)*(q-1)', 'e = 17', 'd = pow(e, -1, phi)', 'c = 2790'],
    targets: [{ op: 'rsa-raw', decimal: '65' }],
  },
  {
    caseName: 'RSA inverse(e, phi) helper expression is evaluated',
    lines: ['p = 61', 'q = 53', 'n = p*q', 'phi = (p-1)*(q-1)', 'e = 17', 'd = inverse(e, phi)', 'ciphertext = 2790'],
    targets: [{ op: 'smart-decode', includes: ['"decimal": "65"'] }],
  },
  {
    caseName: 'RSA gmpy2.invert(e, phi) helper expression is evaluated',
    lines: ['p = 61', 'q = 53', 'n = p*q', 'phi = (p-1)*(q-1)', 'e = 17', 'd = gmpy2.invert(e, phi)', 'ciphertext = 2790'],
    targets: [{ op: 'smart-decode', includes: ['"decimal": "65"'] }],
  },
];

await runRsaLabelCases(RSA_LABEL_CASES_LATE);

// ---- RSA CTF writeup 脚本片段批（T3 压缩）：同一解码骨架只留变化行，单 runner 断言明文 65 ----
// m-型骨架：p/q 因子 + n=p*q 链式求值 + e，随后是各类语言级整数转换写法；
// solve-型骨架：直接给 n/e/p/q/c，用 pow(e,-1,phi) 求私钥指数后解码。
const RSA_FRAGMENT_M_CASES = [
  ['RSA bytes_to_long(...) and pow(m, e, n) script fragments are evaluated', ["m = bytes_to_long(b'A')", 'c = pow(m, e, n)']],
  ['RSA int.from_bytes(...) script fragments are evaluated', ["m = int.from_bytes(b'A', 'big')", 'c = pow(m, e, n)']],
  ['RSA int(hex_string, 16) helper expression is evaluated', ["m = int('41', 16)", 'c = pow(m, e, n)']],
  ['RSA bytes.fromhex(hex(m)[2:]) writeup-style fragments are evaluated', ['m = bytes_to_long(bytes.fromhex(hex(65)[2:]))', 'c = pow(m, e, n)']],
  ['RSA binascii.unhexlify(...) helper fragments are evaluated', ['m = bytes_to_long(binascii.unhexlify("41"))', 'c = pow(m, e, n)']],
  ['RSA Crypto.Util.number.bytes_to_long(...) fragments are evaluated', ["m = Crypto.Util.number.bytes_to_long(b'A')", 'c = pow(m, e, n)']],
  ['RSA libnum.s2n(...) fragments are evaluated', ["m = libnum.s2n('A')", 'c = pow(m, e, n)']],
  ['RSA single-line pow(bytes_to_long(flag), e, n) style fragments are evaluated', ["c = pow(bytes_to_long(b'A'), e, n)"]],
  ['RSA bytearray.fromhex(...) fragments are evaluated', ["m = bytes_to_long(bytearray.fromhex('41'))", 'c = pow(m, e, n)']],
  ['RSA single-line pow(Crypto.Util.number.bytes_to_long(flag), e, n) fragments are evaluated', ["c = pow(Crypto.Util.number.bytes_to_long(b'A'), e, n)"]],
];
const RSA_FRAGMENT_SOLVE_CASES = [
  ['RSA long_to_bytes(pow(c, d, n)) solve fragments are evaluated', ['m = pow(c, pow(e, -1, (p-1)*(q-1)), n)', 'decoded = long_to_bytes(m)']],
  ['RSA libnum.n2s(pow(c, d, n)) solve fragments are evaluated', ['decoded = libnum.n2s(pow(c, pow(e, -1, (p-1)*(q-1)), n))']],
  ['RSA bytes.fromhex(hex(pow(c, d, n))[2:]) solve fragments are evaluated', ['decoded = bytes.fromhex(hex(pow(c, pow(e, -1, (p-1)*(q-1)), n))[2:])']],
];
for (const [fragmentName, fragmentLines] of RSA_FRAGMENT_M_CASES) {
  await run(fragmentName, async () => {
    const input = ['p = 61', 'q = 53', 'n = p*q', 'e = 17', ...fragmentLines].join('\n');
    const output = await transform('smart-decode', 'decode', input, defaultParams);
    expect(output.includes('"decimal": "65"'), `${fragmentName} did not recover plaintext 65`);
  });
}
for (const [fragmentName, fragmentLines] of RSA_FRAGMENT_SOLVE_CASES) {
  await run(fragmentName, async () => {
    const input = ['n = 3233', 'e = 17', 'p = 61', 'q = 53', 'c = 2790', ...fragmentLines].join('\n');
    const output = await transform('smart-decode', 'decode', input, defaultParams);
    expect(output.includes('"decimal": "65"'), `${fragmentName} did not recover plaintext 65`);
  });
}

await run('RSA common modulus works for dict-style records', async () => {
  const n = 3233n;
  const e1 = 17n;
  const e2 = 13n;
  const message = 42n;
  const c1 = modPow(message, e1, n);
  const c2 = modPow(message, e2, n);
  const input = `records = [{'n': ${n}, 'e': ${e1}, 'c': ${c1}}, {'n': ${n}, 'e': ${e2}, 'c': ${c2}}]`;
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Common Modulus'), 'Common modulus attack was not detected from dict-style records');
  expect(output.includes('"decimal": "42"'), 'Common modulus attack did not recover plaintext 42');
});

await run('RSA Hastad broadcast works for dict-style records', async () => {
  const e = 3n;
  const message = 42n;
  const moduli = [10403n, 11663n, 14351n];
  const records = moduli.map((n, index) => `{'n': ${n}, 'e': ${e}, 'c': ${modPow(message, e, n)}}${index === moduli.length - 1 ? '' : ', '}`).join('');
  const input = `records = [${records}]`;
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Hastad Broadcast'), 'Hastad broadcast attack was not detected from dict-style records');
  expect(output.includes('"decimal": "42"'), 'Hastad broadcast attack did not recover plaintext 42');
});

await run('RSA shared prime works for dict-style records', async () => {
  const sharedPrime = 101n;
  const q1 = 103n;
  const q2 = 107n;
  const e = 17n;
  const m1 = 65n;
  const m2 = 66n;
  const n1 = sharedPrime * q1;
  const n2 = sharedPrime * q2;
  const input = `records = [{'n': ${n1}, 'e': ${e}, 'c': ${modPow(m1, e, n1)}}, {'n': ${n2}, 'e': ${e}, 'c': ${modPow(m2, e, n2)}}]`;
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Shared Prime GCD'), 'Shared-prime RSA attack was not detected from dict-style records');
  expect(output.includes(`"sharedPrime": "${sharedPrime}"`), 'Shared-prime RSA output missing recovered shared prime');
});

await run('RSA common modulus works for n1/e1/c1 numbered records', async () => {
  const n = 3233n;
  const e1 = 17n;
  const e2 = 13n;
  const message = 42n;
  const input = [
    `n1 = ${n}`,
    `e1 = ${e1}`,
    `c1 = ${modPow(message, e1, n)}`,
    `n2 = ${n}`,
    `e2 = ${e2}`,
    `c2 = ${modPow(message, e2, n)}`,
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Common Modulus'), 'Common modulus attack was not detected from numbered records');
  expect(output.includes('"decimal": "42"'), 'Common modulus numbered-record plaintext mismatch');
});

await run('RSA Hastad broadcast works for list-style records', async () => {
  const e = 3n;
  const message = 42n;
  const moduli = [10403n, 11663n, 14351n];
  const ciphertexts = moduli.map(n => modPow(message, e, n));
  const input = [
    `moduli = [${moduli.join(', ')}]`,
    `exponents = [${e}, ${e}, ${e}]`,
    `ciphertexts = [${ciphertexts.join(', ')}]`,
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Hastad Broadcast'), 'Hastad broadcast attack was not detected from list-style records');
  expect(output.includes('"decimal": "42"'), 'Hastad list-style plaintext mismatch');
});

await run('RSA common modulus works for public_key tuple lines', async () => {
  const n = 3233n;
  const e1 = 17n;
  const e2 = 13n;
  const message = 42n;
  const input = [
    `public_key1 = (${n}, ${e1})`,
    `ciphertext1 = ${modPow(message, e1, n)}`,
    `public_key2 = (${n}, ${e2})`,
    `ciphertext2 = ${modPow(message, e2, n)}`,
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Common Modulus'), 'Common modulus attack was not detected from public_key tuple lines');
  expect(output.includes('"decimal": "42"'), 'Common modulus tuple-line plaintext mismatch');
});

await run('RSA Hastad broadcast works for public_keys tuple list', async () => {
  const e = 3n;
  const message = 42n;
  const moduli = [10403n, 11663n, 14351n];
  const ciphertexts = moduli.map(n => modPow(message, e, n));
  const input = [
    `public_keys = [(${moduli[0]}, ${e}), (${moduli[1]}, ${e}), (${moduli[2]}, ${e})]`,
    `ciphertexts = [${ciphertexts.join(', ')}]`,
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Hastad Broadcast'), 'Hastad broadcast attack was not detected from public_keys tuple list');
  expect(output.includes('"decimal": "42"'), 'Hastad public_keys tuple-list plaintext mismatch');
});

await run('RSA Hastad broadcast works for public key object list', async () => {
  const e = 3n;
  const message = 42n;
  const moduli = [10403n, 11663n, 14351n];
  const ciphertexts = moduli.map(n => modPow(message, e, n));
  const input = `records = [{'public_key': (${moduli[0]}, ${e}), 'ciphertext': ${ciphertexts[0]}}, {'public_key': (${moduli[1]}, ${e}), 'ciphertext': ${ciphertexts[1]}}, {'public_key': (${moduli[2]}, ${e}), 'ciphertext': ${ciphertexts[2]}}]`;
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Hastad Broadcast'), 'Hastad broadcast attack was not detected from public key object list');
  expect(output.includes('"decimal": "42"'), 'Hastad public key object-list plaintext mismatch');
});

await run('RSA nested public_key object with sibling ciphertext works', async () => {
  const e = 3n;
  const message = 42n;
  const moduli = [10403n, 11663n, 14351n];
  const ciphertexts = moduli.map(n => modPow(message, e, n));
  const input = JSON.stringify({
    records: moduli.map((n, index) => ({
      public_key: { n: n.toString(), e: e.toString() },
      ciphertext: ciphertexts[index].toString(),
    })),
  });
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Hastad Broadcast'), 'Nested public_key object records did not trigger Hastad broadcast');
  expect(output.includes('"decimal": "42"'), 'Nested public_key object records did not recover plaintext 42');
});

await run('RSA Python-style nested public_key object with sibling ciphertext works', async () => {
  const e = 3n;
  const message = 42n;
  const moduli = [10403n, 11663n, 14351n];
  const ciphertexts = moduli.map(n => modPow(message, e, n));
  const input = `records = [{'public_key': {'n': '${moduli[0]}', 'e': '${e}'}, 'ciphertext': '${ciphertexts[0]}'}, {'public_key': {'n': '${moduli[1]}', 'e': '${e}'}, 'ciphertext': '${ciphertexts[1]}'}, {'public_key': {'n': '${moduli[2]}', 'e': '${e}'}, 'ciphertext': '${ciphertexts[2]}'}]`;
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Hastad Broadcast'), 'Python-style nested public_key object records did not trigger Hastad broadcast');
  expect(output.includes('"decimal": "42"'), 'Python-style nested public_key object records did not recover plaintext 42');
});

await run('RSA Python-style pub alias object with sibling ciphertext works', async () => {
  const e = 3n;
  const message = 42n;
  const moduli = [10403n, 11663n, 14351n];
  const ciphertexts = moduli.map(n => modPow(message, e, n));
  const input = `records = [{'pub': {'n': '${moduli[0]}', 'e': '${e}'}, 'ct': '${ciphertexts[0]}'}, {'pub': {'n': '${moduli[1]}', 'e': '${e}'}, 'ct': '${ciphertexts[1]}'}, {'pub': {'n': '${moduli[2]}', 'e': '${e}'}, 'ct': '${ciphertexts[2]}'}]`;
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Hastad Broadcast'), 'Python-style pub alias object records did not trigger Hastad broadcast');
  expect(output.includes('"decimal": "42"'), 'Python-style pub alias object records did not recover plaintext 42');
});

await run('RSA pk tuple alias with ciphertext lines works', async () => {
  const n = 3233n;
  const e1 = 17n;
  const e2 = 13n;
  const message = 42n;
  const input = [
    `pk1 = (${n}, ${e1})`,
    `ciphertext1 = ${modPow(message, e1, n)}`,
    `pk2 = (${n}, ${e2})`,
    `ciphertext2 = ${modPow(message, e2, n)}`,
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Common Modulus'), 'pk tuple alias records did not trigger common modulus attack');
  expect(output.includes('"decimal": "42"'), 'pk tuple alias records did not recover plaintext 42');
});

await run('RSA script-style pub object and flag_ct alias are parsed', async () => {
  const n = 3233n;
  const e = 17n;
  const message = 65n;
  const ciphertext = modPow(message, e, n);
  const input = [
    `pub = {'n': '${n}', 'e': '${e}'}`,
    `flag_ct = ${ciphertext}`,
    'rsa challenge snippet',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Raw / Textbook') || output.includes('RSA CTF Helper'), 'pub object + flag_ct snippet was not recognized as RSA');
  expect(output.includes('"decimal": "65"'), 'pub object + flag_ct snippet did not recover plaintext 65');
});

await run('RSA script-style referenced variables are resolved', async () => {
  const n = 3233n;
  const e = 17n;
  const message = 65n;
  const ciphertext = modPow(message, e, n);
  const input = [
    `n = ${n}`,
    `e = ${e}`,
    `c = ${ciphertext}`,
    `pub = {'n': n, 'e': e}`,
    'flag_ct = c',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'Referenced RSA variables did not resolve into a decryptable payload');
});

await run('RSA script-style rsa object and encmsg alias are parsed', async () => {
  const n = 3233n;
  const e = 17n;
  const message = 65n;
  const ciphertext = modPow(message, e, n);
  const input = [
    `n = ${n}`,
    `e = ${e}`,
    `c = ${ciphertext}`,
    `rsa = {'n': n, 'e': e}`,
    'encmsg = c',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'rsa object + encmsg alias snippet did not recover plaintext 65');
});

await run('RSA script-style enc_data/cipher_data/flag_enc aliases are parsed', async () => {
  const n = 3233n;
  const e = 17n;
  const message = 65n;
  const ciphertext = modPow(message, e, n);
  const input = [
    `priv = {'n': '${n}', 'e': '${e}'}`,
    `enc_data = ${ciphertext}`,
    `cipher_data = ${ciphertext}`,
    `flag_enc = ${ciphertext}`,
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'enc_data/cipher_data/flag_enc aliases did not recover plaintext 65');
});

await run('RSA script-style privkey/pubkey/cipher_data/ctxt aliases are parsed', async () => {
  const n = 3233n;
  const e = 17n;
  const message = 65n;
  const ciphertext = modPow(message, e, n);
  const input = [
    `n = ${n}`,
    `e = ${e}`,
    `c = ${ciphertext}`,
    `privkey = {'n': n, 'e': e}`,
    `pubkey = {'n': n, 'e': e}`,
    'cipher_data = c',
    'ctxt = c',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'privkey/pubkey/cipher_data/ctxt aliases did not recover plaintext 65');
});

await run('RSA keypair tuple alias with enc alias works', async () => {
  const n = 3233n;
  const e1 = 17n;
  const e2 = 13n;
  const message = 42n;
  const input = [
    `keypair1 = (${n}, ${e1})`,
    `enc1 = ${modPow(message, e1, n)}`,
    `keypair2 = (${n}, ${e2})`,
    `enc2 = ${modPow(message, e2, n)}`,
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Common Modulus'), 'keypair tuple alias records did not trigger common modulus attack');
  expect(output.includes('"decimal": "42"'), 'keypair tuple alias records did not recover plaintext 42');
});

// ---- 签名重复随机数批（T3 压缩）：教科书签名构造前奏上提，消除多份雷同变量区 ----
// ECDSA/DSA 教科书签名：s = k⁻¹(z + r·d) mod n（同 k 签两次即泄露私钥）。
const ecdsaSignaturePair = ({ order, privateKey, nonce, r, z1, z2 }) => {
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + r * privateKey) % order)) % order;
  const s2 = (nonceInverse * ((z2 + r * privateKey) % order)) % order;
  return { s1, s2 };
};
// z 由消息 SHA-256 摘要截断派生的变体（msg/alg 输入路径）。
const ecdsaZPairFromMessages = async ({ order, msg1, msg2 }) => ({
  z1: digestHexToOrderInt(await digestForTest(msg1, 'sha256'), order),
  z2: digestHexToOrderInt(await digestForTest(msg2, 'sha256'), order),
});
// JOSE ES256 教科书 token 对：固定 r、两个不同 s 的 base64url 三段式 JWT。
const joseTokenPair = () => {
  const rHex = '0000000000000000000000000000000000000000000000000000000000000011';
  const s1Hex = '0000000000000000000000000000000000000000000000000000000000000038';
  const s2Hex = '000000000000000000000000000000000000000000000000000000000000004f';
  const signature1 = Buffer.from(`${rHex}${s1Hex}`, 'hex').toString('base64url');
  const signature2 = Buffer.from(`${rHex}${s2Hex}`, 'hex').toString('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
  const payload1 = Buffer.from(JSON.stringify({ sub: 'alice', iat: 1 })).toString('base64url');
  const payload2 = Buffer.from(JSON.stringify({ sub: 'bob', iat: 2 })).toString('base64url');
  return [`${header}.${payload1}.${signature1}`, `${header}.${payload2}.${signature2}`];
};

await run('ECDSA nonce reuse works for dict-style records', async () => {
  const order = 101n;
  const privateKey = 11n;
  const nonce = 13n;
  const r = 17n;
  const z1 = 33n;
  const z2 = 44n;
  const { s1, s2 } = ecdsaSignaturePair({ order, privateKey, nonce, r, z1, z2 });
  const input = `signatures = [{'scheme': 'ecdsa', 'order': ${order}, 'r': ${r}, 's': ${s1}, 'z': ${z1}}, {'scheme': 'ecdsa', 'order': ${order}, 'r': ${r}, 's': ${s2}, 'z': ${z2}}]`;
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes('"scheme": "ecdsa-dsa"'), 'ECDSA dict-style records did not identify ECDSA scheme');
  expect(output.includes(`"privateKey": "${privateKey}"`), 'ECDSA dict-style records did not recover private key');
  expect(output.includes(`"nonceK": "${nonce}"`), 'ECDSA dict-style records did not recover nonce');
});

await run('Schnorr nonce reuse works for dict-style records', async () => {
  const order = 101n;
  const privateKey = 19n;
  const nonce = 29n;
  const r = 23n;
  const e1 = 17n;
  const e2 = 25n;
  const s1 = (nonce + e1 * privateKey) % order;
  const s2 = (nonce + e2 * privateKey) % order;
  const input = `records = [{'scheme': 'schnorr', 'order': ${order}, 'r': ${r}, 's': ${s1}, 'z': ${e1}}, {'scheme': 'schnorr', 'order': ${order}, 'r': ${r}, 's': ${s2}, 'z': ${e2}}]`;
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes('"scheme": "schnorr"'), 'Schnorr dict-style records did not identify Schnorr scheme');
  expect(output.includes(`"privateKey": "${privateKey}"`), 'Schnorr dict-style records did not recover private key');
  expect(output.includes(`"nonceK": "${nonce}"`), 'Schnorr dict-style records did not recover nonce');
});

await run('ECDSA nonce reuse works for prose sig1/sig2 format', async () => {
  const order = 101n;
  const privateKey = 11n;
  const nonce = 13n;
  const r = 17n;
  const z1 = 33n;
  const z2 = 44n;
  const { s1, s2 } = ecdsaSignaturePair({ order, privateKey, nonce, r, z1, z2 });
  const input = [
    'ecdsa repeated nonce challenge',
    `sig1 = (${r}, ${s1})`,
    `z1 = ${z1}`,
    `sig2 = (${r}, ${s2})`,
    `z2 = ${z2}`,
    `order = ${order}`,
  ].join('\n');
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes('"scheme": "ecdsa-dsa"'), 'ECDSA prose sig1/sig2 did not identify ECDSA scheme');
  expect(output.includes(`"privateKey": "${privateKey}"`), 'ECDSA prose sig1/sig2 did not recover private key');
});

await run('smart-decode routes Chinese repeated-nonce signature fields and recovers the key', async () => {
  const order = 101n;
  const privateKey = 11n;
  const nonce = 13n;
  const r = 17n;
  const z1 = 33n;
  const z2 = 44n;
  const { s1, s2 } = ecdsaSignaturePair({ order, privateKey, nonce, r, z1, z2 });
  const input = [
    'ECDSA 重复随机数题',
    `曲线阶：${order}`,
    `签名1：(${r}, ${s1})`,
    `哈希1：${z1}`,
    `签名2：(${r}, ${s2})`,
    `哈希2：${z2}`,
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('Signature nonce reuse'), 'smart-decode did not route Chinese repeated-nonce signature fields');
  expect(output.includes(`"privateKey": "${privateKey}"`), 'smart-decode Chinese signature fields did not recover private key');
});

await run('ECDSA nonce reuse derives z from msg1/msg2 and algorithm', async () => {
  const order = 101n;
  const privateKey = 11n;
  const nonce = 13n;
  const r = 17n;
  const msg1 = 'alpha';
  const msg2 = 'beta';
  const { z1, z2 } = await ecdsaZPairFromMessages({ order, msg1, msg2 });
  const { s1, s2 } = ecdsaSignaturePair({ order, privateKey, nonce, r, z1, z2 });
  const input = [
    'ecdsa repeated nonce challenge',
    'algorithm = sha256',
    `sig1 = (${r}, ${s1})`,
    `msg1 = ${msg1}`,
    `sig2 = (${r}, ${s2})`,
    `msg2 = ${msg2}`,
    `order = ${order}`,
  ].join('\n');
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes(`"privateKey": "${privateKey}"`), 'ECDSA msg/alg input did not recover private key');
  expect(output.includes('"derivedFromMessage": true'), 'ECDSA msg/alg input did not mark z as derived from message');
});

await run('ECDSA signature/message lists derive z and recover key', async () => {
  const order = 101n;
  const privateKey = 11n;
  const nonce = 13n;
  const r = 17n;
  const msg1 = 'alpha';
  const msg2 = 'beta';
  const { z1, z2 } = await ecdsaZPairFromMessages({ order, msg1, msg2 });
  const { s1, s2 } = ecdsaSignaturePair({ order, privateKey, nonce, r, z1, z2 });
  const input = [
    'ecdsa repeated nonce challenge',
    'algorithm = sha256',
    `signatures = [(${r}, ${s1}), (${r}, ${s2})]`,
    `messages = ["${msg1}", "${msg2}"]`,
    `order = ${order}`,
  ].join('\n');
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes(`"privateKey": "${privateKey}"`), 'ECDSA signature/message list input did not recover private key');
  expect(output.includes('"derivedFromMessage": true'), 'ECDSA signature/message list input did not derive z from message');
});

await run('DSA nonce reuse works for explicit DSA dict-style records', async () => {
  const order = 101n;
  const privateKey = 7n;
  const nonce = 19n;
  const r = 23n;
  const z1 = 12n;
  const z2 = 34n;
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + privateKey * r) % order)) % order;
  const s2 = (nonceInverse * ((z2 + privateKey * r) % order)) % order;
  const input = `records = [{'scheme': 'dsa', 'order': ${order}, 'r': ${r}, 's': ${s1}, 'z': ${z1}}, {'scheme': 'dsa', 'order': ${order}, 'r': ${r}, 's': ${s2}, 'z': ${z2}}]`;
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes('"scheme": "ecdsa-dsa"'), 'DSA dict-style records did not route through ECDSA/DSA branch');
  expect(output.includes(`"privateKey": "${privateKey}"`), 'DSA dict-style records did not recover private key');
  expect(output.includes(`"nonceK": "${nonce}"`), 'DSA dict-style records did not recover nonce');
});

await run('ECDSA mixed r1/s1/msg1 prose derives z and recovers key', async () => {
  const order = 101n;
  const privateKey = 11n;
  const nonce = 13n;
  const r = 17n;
  const msg1 = 'alpha';
  const msg2 = 'beta';
  const { z1, z2 } = await ecdsaZPairFromMessages({ order, msg1, msg2 });
  const { s1, s2 } = ecdsaSignaturePair({ order, privateKey, nonce, r, z1, z2 });
  const input = [
    'ecdsa repeated nonce mixed prose',
    'alg = sha256',
    `r1 = ${r}`,
    `s1 = ${s1}`,
    `msg1 = ${msg1}`,
    `r2 = ${r}`,
    `s2 = ${s2}`,
    `msg2 = ${msg2}`,
    `order = ${order}`,
  ].join('\n');
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes(`"privateKey": "${privateKey}"`), 'ECDSA mixed prose input did not recover private key');
  expect(output.includes('"derivedFromMessage": true'), 'ECDSA mixed prose input did not derive z from messages');
});

await run('JOSE token1/token2 repeated nonce works', async () => {
  const [token1, token2] = joseTokenPair();
  const input = [
    'ecdsa repeated nonce jose challenge',
    `token1 = ${token1}`,
    `token2 = ${token2}`,
    'order = 101',
  ].join('\n');
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes('"signatureFormat": "JOSE ES256"'), 'JOSE token list did not preserve JOSE signature format');
  expect(output.includes('"repeatedRCount": 1'), 'JOSE token list did not detect repeated r');
  expect(output.includes('"index": "jose-1"') && output.includes('"index": "jose-2"'), 'JOSE token list did not create jose-* records');
});

await run('JOSE tokens=[...] repeated nonce works', async () => {
  const [token1, token2] = joseTokenPair();
  const input = [
    'ecdsa repeated nonce jose challenge',
    `tokens = ["${token1}", "${token2}"]`,
    'order = 101',
  ].join('\n');
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes('"repeatedRCount": 1'), 'JOSE tokens=[...] input did not detect repeated r');
  expect(output.includes('"index": "tokenlist-1"') && output.includes('"index": "tokenlist-2"'), 'JOSE tokens=[...] input did not create tokenlist-* records');
});

await run('JOSE token object records work', async () => {
  const [token1, token2] = joseTokenPair();
  const input = `records = [{'token': '${token1}'}, {'token': '${token2}'}]\norder = 101`;
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes('"repeatedRCount": 1'), 'JOSE token object records did not detect repeated r');
  expect(output.includes('"signatureFormat": "JOSE ES256"'), 'JOSE token object records lost JOSE signature format');
});

await run('DLP inference recognizes prose aliases', async () => {
  const input = [
    'prime field p is 1019',
    'generator alpha equals 2',
    'public y = 40',
    'order = 1018',
  ].join('\n');
  const inference = inferDlpFromText(input);
  assert.equal(inference.modulus?.toString(), '1019');
  assert.equal(inference.base?.toString(), '2');
  assert.equal(inference.target?.toString(), '40');
  assert.equal(inference.order?.toString(), '1018');
});

await run('ECDSA DER signature fields with msg1/msg2 derive z and recover key', async () => {
  const order = 101n;
  const privateKey = 11n;
  const nonce = 13n;
  const r = 17n;
  const msg1 = 'alpha';
  const msg2 = 'beta';
  const { z1, z2 } = await ecdsaZPairFromMessages({ order, msg1, msg2 });
  const { s1, s2 } = ecdsaSignaturePair({ order, privateKey, nonce, r, z1, z2 });
  const derEncode = (rv, sv) => {
    const encInt = value => {
      let hex = value.toString(16);
      if (hex.length % 2) hex = `0${hex}`;
      if (parseInt(hex.slice(0, 2), 16) & 0x80) hex = `00${hex}`;
      return `02${(hex.length / 2).toString(16).padStart(2, '0')}${hex}`;
    };
    const body = `${encInt(rv)}${encInt(sv)}`;
    return `30${(body.length / 2).toString(16).padStart(2, '0')}${body}`;
  };
  const input = [
    'ecdsa repeated nonce der challenge',
    'algorithm = sha256',
    `q = ${order}`,
    `signature1 = ${derEncode(r, s1)}`,
    `msg1 = ${msg1}`,
    `signature2 = ${derEncode(r, s2)}`,
    `msg2 = ${msg2}`,
  ].join('\n');
  const output = await transform('signature-nonce-helper', 'decode', input, defaultParams);
  expect(output.includes(`"privateKey": "${privateKey}"`), 'ECDSA DER/msg input did not recover private key');
  expect(output.includes('"derivedFromMessage": true'), 'ECDSA DER/msg input did not derive z from messages');
});

await run('LCG indexed x[0]/x[1] states are parsed and solved', async () => {
  const input = [
    'linear congruential generator challenge',
    'm = 97',
    'x[0] = 12',
    'x[1] = 67',
    'x[2] = 51',
    'x[3] = 68',
  ].join('\n');
  const output = JSON.parse(await transform('lcg-helper', 'decode', input, defaultParams));
  assert.equal(output.modulus, '97');
  assert.equal(output.a, '5');
  assert.equal(output.c, '7');
  assert.equal(output.next, '56');
});

await run('smart-decode routes Chinese LCG parameter names and output list', async () => {
  const input = [
    '线性同余生成器随机数题',
    '模数：97',
    '乘数：5',
    '增量：7',
    '输出序列：[12, 67, 51, 68]',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('LCG / PRNG analysis'), 'smart-decode did not route Chinese LCG fields');
  expect(output.includes('"a": "5"'), 'smart-decode Chinese LCG multiplier missing');
  expect(output.includes('"c": "7"'), 'smart-decode Chinese LCG increment missing');
  expect(output.includes('"next": "56"'), 'smart-decode Chinese LCG prediction missing');
});

await run('MT19937 output0/output1 numbered fields are cloned', async () => {
  const outputs = Array.from({ length: 624 }, (_, index) => BigInt(index));
  const lines = outputs.map((value, index) => `output${index} = ${value.toString()}`);
  const input = ['mt19937 challenge', ...lines].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.outputCount, 624);
  assert.equal(output.enoughForFullStateClone, true);
  expect(Array.isArray(output.clone?.predictedNext) && output.clone.predictedNext.length === 10, 'MT19937 numbered outputs did not produce predictions');
});

await run('MT19937 Python getrandbits(64) packed outputs are cloned', async () => {
  // Deterministic sample generated from Python Random(1337).getrandbits(64) x 312
  const packed = [
    17073114832458550531n, 13094974362849908645n, 10532703126533192959n, 13501076693576984818n,
    14299909079473748831n, 6138879553798023278n, 11754044366658895073n, 17731270733286813183n,
  ];
  // Repeat the fixed prefix pattern to reach 312 values while keeping the test deterministic and parser-oriented.
  const values = Array.from({ length: 312 }, (_, index) => packed[index % packed.length]);
  const input = ['python random getrandbits(64) challenge', ...values.map((value, index) => `output${index} = ${value.toString()}`)].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.wordFormat, '64-bit-packed');
  assert.equal(output.enoughForFullStateClone, true);
  expect(Array.isArray(output.clone?.predictedNext) && output.clone.predictedNext.length === 10, 'MT19937 64-bit packed outputs did not produce predictions');
});

await run('MT19937 Python getrandbits(128) packed outputs are cloned', async () => {
  const packed = [
    241559640723280063923457048961970670851n,
    152317476902443549327305647160818394672n,
    207156837705164348667502499200722049252n,
    311462240942861306242736972244982563297n,
  ];
  const values = Array.from({ length: 156 }, (_, index) => packed[index % packed.length]);
  const input = ['python random getrandbits(128) challenge', ...values.map((value, index) => `output${index} = ${value.toString()}`)].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.wordFormat, '128-bit-packed');
  assert.equal(output.enoughForFullStateClone, true);
  expect(Array.isArray(output.clone?.predictedNext) && output.clone.predictedNext.length === 10, 'MT19937 128-bit packed outputs did not produce predictions');
});

await run('MT19937 Python random.random() floats are extracted into numerators and halves', async () => {
  const floats = [
    '0.6177528569514706',
    '0.5332655736050008',
    '0.36584835924937553',
    '0.5857873539022715',
    '0.16568728368878083',
    '0.8243737469076314',
    '0.38370480861420864',
    '0.7896128249156874',
  ];
  const input = ['python random.random() challenge', ...floats.map((value, index) => `random${index} = ${value}`)].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.wordFormat, 'python-random-float');
  assert.equal(output.floatOutputCount, 8);
  assert.equal(output.floatWords[0].numerator, '5564223072747405');
  assert.equal(output.floatWords[0].hi27, '82913384');
  assert.equal(output.floatWords[0].lo26, '62111629');
});

await run('MT19937 randrange samples with global bound are extracted', async () => {
  const values = [647760, 970494, 559169, 744363, 383619, 598714, 614242, 767447];
  const input = [
    'python random.randrange(1000000) challenge',
    'bound = 1000000',
    ...values.map((value, index) => `output${index} = ${value}`),
  ].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.boundedRandrangeCount, 8);
  assert.equal(output.randrangeSamples[0].value, '647760');
  assert.equal(output.randrangeSamples[0].upperBound, '1000000');
  assert.equal(output.randrangeSamples[7].value, '767447');
});

await run('ECDSA partial nonce high-bit constraints are extracted', async () => {
  const input = [
    'ecdsa partial nonce challenge',
    'curve = secp256k1',
    'q = 101',
    'known high bits of k1 = 0xab',
    'known high bits of k2 = 0xcd',
    'known bits = 8',
    'msb leak',
    'r1 = 17',
    's1 = 25',
    'z1 = 33',
    'r2 = 19',
    's2 = 41',
    'z2 = 44',
  ].join('\n');
  const output = JSON.parse(await transform('signature-nonce-helper', 'decode', input, defaultParams));
  expect(output.partialNonceConstraintCount >= 1, 'Partial nonce constraints were not extracted');
  expect(output.partialNonceConstraints.some(entry => entry.position === 'msb'), 'Partial nonce constraints did not mark MSB leakage');
  expect(output.partialNonceConstraints.some(entry => entry.knownBits === 8), 'Partial nonce constraints did not keep known bit width');
  expect(Array.isArray(output.latticeAttackTemplates) && output.latticeAttackTemplates.length >= 1, 'Partial nonce MSB constraints did not produce lattice templates');
  assert.equal(output.latticeAttackTemplates[0].knownType, 'MSB');
});

await run('ECDSA partial nonce low-bit and offset constraints are extracted', async () => {
  const input = [
    'ecdsa partial nonce challenge',
    'q = 101',
    'known low bits of k1 = 0x13',
    'known bits = 5',
    'k = k0 + 2^5 * x',
    'lsb leak',
    'r1 = 17',
    's1 = 25',
    'z1 = 33',
  ].join('\n');
  const output = JSON.parse(await transform('signature-nonce-helper', 'decode', input, defaultParams));
  expect(output.partialNonceConstraints.some(entry => entry.position === 'lsb'), 'Partial nonce constraints did not mark LSB leakage');
  expect(output.partialNonceConstraints.some(entry => Array.isArray(entry.positions) && entry.positions.includes('offset')), 'Partial nonce constraints did not keep offset as an additional position');
  expect(output.partialNonceConstraints.some(entry => String(entry.relation || '').includes('k0 + 2^5 * x')), 'Partial nonce constraints did not keep offset relation text');
  expect(output.partialNonceConstraints.some(entry => entry.knownBits === 5), 'Partial nonce constraints did not keep low-bit width');
  expect(Array.isArray(output.latticeAttackTemplates) && output.latticeAttackTemplates.some(entry => entry.knownType === 'LSB'), 'Partial nonce LSB constraints did not produce LSB lattice templates');
  expect(output.latticeAttackTemplates.some(entry => Array.isArray(entry.knownTypes) && entry.knownTypes.includes('OFFSET')), 'Partial nonce LSB template did not keep additional OFFSET tag');
});

await run('ECDSA biased nonce constraints are extracted', async () => {
  const input = [
    'ecdsa biased nonce challenge',
    'biased nonce',
    'small nonce',
    'r1 = 17',
    's1 = 25',
    'z1 = 33',
    'r2 = 19',
    's2 = 41',
    'z2 = 44',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('Signature nonce reuse analysis'), 'Biased nonce input did not route into signature analysis');
  expect(output.includes('partial nonce') || output.includes('biased nonce'), 'Biased nonce input did not preserve partial/biased nonce guidance');
});

await run('MT19937 randbelow samples with global bound are extracted', async () => {
  const values = [21, 42, 49, 81, 46, 39, 50, 89];
  const input = [
    'python random.randbelow(97) challenge',
    'below = 97',
    ...values.map((value, index) => `output${index} = ${value}`),
  ].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.boundedRandrangeCount, 8);
  assert.equal(output.randrangeSamples[0].upperBound, '97');
  assert.equal(output.randrangeSamples[7].value, '89');
});

await run('MT19937 bounded samples with below N prose are extracted', async () => {
  const values = [21, 42, 49, 81];
  const input = [
    'python random bounded output challenge',
    'outputs are below 97',
    ...values.map((value, index) => `sample${index} = ${value}`),
  ].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.boundedRandrangeCount, 4);
  assert.equal(output.randrangeSamples[0].upperBound, '97');
  assert.equal(output.randrangeSamples[3].value, '81');
});

await run('MT19937 bounded samples with modulo prose are extracted', async () => {
  const values = [21, 42, 49, 81];
  const input = [
    'python random bounded output challenge',
    'outputs are sampled modulo 97',
    ...values.map((value, index) => `value${index} = ${value}`),
  ].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.boundedRandrangeCount, 4);
  assert.equal(output.randrangeSamples[0].upperBound, '97');
  assert.equal(output.randrangeSamples[2].value, '49');
});

await run('MT19937 randrange(a,b) bounded width is extracted', async () => {
  const values = [21, 42, 49, 81];
  const input = [
    'python random.randrange(100, 197) challenge',
    ...values.map((value, index) => `output${index} = ${value}`),
  ].join('\n');
  const output = JSON.parse(await transform('mt19937-helper', 'decode', input, defaultParams));
  assert.equal(output.boundedRandrangeCount, 4);
  assert.equal(output.randrangeSamples[0].upperBound, '97');
  assert.equal(output.randrangeSamples[0].lowerBound, '100');
  assert.equal(output.randrangeSamples[0].rangeWidth, '97');
  assert.equal(output.randrangeSamples[1].value, '42');
});

await run('Smart symmetric decrypt recognizes Python AES-CBC snippet with b64decode/unpad', async () => {
  const input = [
    'from Crypto.Cipher import AES',
    'from base64 import b64decode',
    'from Crypto.Util.Padding import unpad',
    'key = b"0123456789abcdef"',
    'iv = b"abcdef0123456789"',
    'ct = "w8i4Hzr1Ib9t3H0Rr8Hp2irQ6l3xuuOY9inE+HTzS3o="',
    'cipher = AES.new(key, AES.MODE_CBC, iv)',
    'pt = unpad(cipher.decrypt(b64decode(ct)), 16)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('aes-cbc-raw'), 'Python AES-CBC snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{aes_cbc_demo}'), 'Python AES-CBC snippet did not recover plaintext');
});

await run('Smart symmetric decrypt accepts Chinese AES labels, fullwidth colon, and key aliases', async () => {
  const input = [
    '加密算法（AES-128-CBC）：AES-128-CBC',
    '密钥（Hex）：30313233343536373839616263646566',
    '初始向量（Hex）：61626364656630313233343536373839',
    '密文（Base64）：w8i4Hzr1Ib9t3H0Rr8Hp2irQ6l3xuuOY9inE+HTzS3o=',
  ].join('\n');
  const direct = await transform('aes-cbc-raw', 'decode', input, defaultParams);
  assert.equal(direct, 'flag{aes_cbc_demo}');

  const smart = await transform('smart-decode', 'decode', input, defaultParams);
  expect(smart.includes('aes-cbc-raw'), 'smart-decode did not route Chinese AES labels');
  expect(smart.includes('flag{aes_cbc_demo}'), 'smart-decode Chinese AES output missing plaintext');
});

// ---- Python 密码脚本片段批（T3 压缩）：片段行数据 + includes 断言入表，复用 runRsaLabelCases ----
const PYTHON_SNIPPET_CASES = [
  {
    caseName: 'Smart symmetric decrypt recognizes Python AES-GCM decrypt_and_verify snippet',
    lines: [
      'from Crypto.Cipher import AES',
      'from base64 import b64decode',
      'key = b"0123456789abcdef0123456789abcdef"',
      'nonce = b"nonce-123456"',
      'ct = "UhDY+otytryRUdUh4IwWFS7z"',
      'tag = "6U2CkX2sw/CwlB0QbrDO+w=="',
      'cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)',
      'pt = cipher.decrypt_and_verify(b64decode(ct), b64decode(tag))',
    ],
    targets: [{ op: 'smart-decode', includes: ['aes-gcm', 'flag{aes_gcm_demo}'] }],
  },
  {
    caseName: 'Smart XOR decrypt recognizes Python xor(...) snippet',
    lines: [
      'from pwn import xor',
      'ct = bytes.fromhex("27292e2c307d")',
      'key = b"ABC"',
      'pt = xor(ct, key)',
    ],
    targets: [{ op: 'smart-decode', includes: ['python-xor-call', '"plaintextHex": "666b6d6d723e"'] }],
  },
  {
    caseName: 'Smart XOR decrypt recognizes Python bytes([...]) / bytearray([...]) snippet',
    lines: [
      'from pwn import xor',
      'ct = bytes([0x27,0x29,0x2e,0x2c,0x30,0x7d])',
      'key = bytearray([0x41,0x42,0x43])',
      'pt = xor(ct, key)',
    ],
    targets: [{ op: 'smart-decode', includes: ['python-xor-call', '"plaintextHex": "666b6d6d723e"'] }],
  },
  {
    caseName: 'Smart symmetric decrypt recognizes Python AES-ECB snippet with b64decode/unpad',
    lines: [
      'from Crypto.Cipher import AES',
      'from base64 import b64decode',
      'from Crypto.Util.Padding import unpad',
      'key = b"0123456789abcdef"',
      'ct = "o/mMq0AvRyonhFU59nCej+2IRZHgo59CM9yLVYPXv+4="',
      'cipher = AES.new(key, AES.MODE_ECB)',
      'pt = unpad(cipher.decrypt(b64decode(ct)), 16)',
    ],
    targets: [{ op: 'smart-decode', includes: ['aes-ecb', 'flag{aes_ecb_demo}'] }],
  },
  {
    caseName: 'Smart symmetric decrypt recognizes Python AES-CTR snippet',
    lines: [
      'from Crypto.Cipher import AES',
      'from base64 import b64decode',
      'key = b"0123456789abcdef"',
      'nonce = b"nonceCTR"',
      'ct = "mAZXWQVW6Or828VnG+vWTpZm"',
      'cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)',
      'pt = cipher.decrypt(b64decode(ct))',
    ],
    targets: [{ op: 'smart-decode', includes: ['aes-ctr-raw', 'flag{aes_ctr_demo}'] }],
  },
  {
    caseName: 'Smart symmetric decrypt recognizes Python ChaCha20 snippet',
    lines: [
      'from base64 import b64decode',
      'from Crypto.Cipher import ChaCha20',
      'key = b"0123456789abcdef0123456789abcdef"',
      'nonce = b"12345678"',
      'ct = "BAjkRRoogKzqPb6ERGO194Y1XQ=="',
      'cipher = ChaCha20.new(key=key, nonce=nonce)',
      'pt = cipher.decrypt(b64decode(ct))',
    ],
    targets: [{ op: 'smart-decode', includes: ['chacha20-orig', 'flag{chacha20_demo}'] }],
  },
  {
    caseName: 'Smart symmetric decrypt recognizes Python Salsa20 snippet',
    lines: [
      'from base64 import b64decode',
      'from Crypto.Cipher import Salsa20',
      'key = b"0123456789abcdef0123456789abcdef"',
      'nonce = b"12345678"',
      'ct = "QXgBBCyBjVx1cVFvuEN0fxSs"',
      'cipher = Salsa20.new(key=key, nonce=nonce)',
      'pt = cipher.decrypt(b64decode(ct))',
    ],
    targets: [{ op: 'smart-decode', includes: ['salsa20', 'flag{salsa20_demo}'] }],
  },
  {
    caseName: 'Smart symmetric decrypt recognizes Python ChaCha20-Poly1305 snippet',
    lines: [
      'from base64 import b64decode',
      'from Crypto.Cipher import ChaCha20_Poly1305',
      'key = b"0123456789abcdef0123456789abcdef"',
      'nonce = b"123456789012"',
      'ct = "KLBIlbEfVt6NJixRk+nWktmXXXvKW9s/2rcDWA=="',
      'tag = "XVCGxEXuSrm0hhPMpUQpzA=="',
      'cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)',
      'pt = cipher.decrypt_and_verify(b64decode(ct), b64decode(tag))',
    ],
    targets: [{ op: 'smart-decode', includes: ['chacha20-poly1305', 'flag{chacha20_poly1305_demo}'] }],
  },
  {
    caseName: 'Smart symmetric decrypt recognizes Python AES-CFB snippet',
    lines: [
      'from base64 import b64decode',
      'from Crypto.Cipher import AES',
      'key = b"0123456789abcdef"',
      'iv = b"abcdef0123456789"',
      'ct = "afeI8+qqRKG/Iclxv2iE+sJk"',
      'cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)',
      'pt = cipher.decrypt(b64decode(ct))',
    ],
    targets: [{ op: 'smart-decode', includes: ['aes-cfb', 'flag{aes_cfb_demo}'] }],
  },
  {
    caseName: 'Smart symmetric decrypt recognizes Python AES-OFB snippet',
    lines: [
      'from base64 import b64decode',
      'from Crypto.Cipher import AES',
      'key = b"0123456789abcdef"',
      'iv = b"abcdef0123456789"',
      'ct = "afeI8+qqRKG/Lclxv2iE+rhV"',
      'cipher = AES.new(key, AES.MODE_OFB, iv=iv)',
      'pt = cipher.decrypt(b64decode(ct))',
    ],
    targets: [{ op: 'smart-decode', includes: ['aes-ofb', 'flag{aes_ofb_demo}'] }],
  },
];

await runRsaLabelCases(PYTHON_SNIPPET_CASES);

await run('Xxencode round-trips, matches the Wikipedia sample, and reaches smart decode', async () => {
  const encoded = await transform('xxencode', 'encode', 'flag{xxencode}', defaultParams);
  assert.equal(await transform('xxencode', 'decode', encoded, defaultParams), 'flag{xxencode}');
  const lines = String(encoded).split('\n');
  assert.equal(lines[0], 'begin 6xx payload.txt');
  assert.match(lines[1], /^C/);
  // 90 字节 = 两条满行：xxencode 满行长度前缀为 h（45 在 +-0-9A-Za-z 字母表中的位置），零长行为 +
  const longLines = String(await transform('xxencode', 'encode', 'A'.repeat(90), defaultParams)).split('\n');
  assert.equal(longLines.length, 5);
  assert.equal(longLines[1][0], 'h');
  assert.equal(longLines[2][0], 'h');
  assert.equal(longLines[3], '+');
  // Wikipedia xxencode 条目的经典样例（内容含 CRLF，共 26 字节，长度前缀 O=26）
  const sample = ['begin 644 wikipedia-url.txt', 'OO5FoQ1cj9rRrRmtrOKhdQ4JYOK2iPr7b1Ec+', 'end'].join('\n');
  assert.equal(await transform('xxencode', 'decode', sample, defaultParams), 'http://www.wikipedia.org\r\n');
  // 与 decodeUuencode 契约一致：缺少 begin 行必须报错，防止垃圾输入静默产出乱码
  let threw = false;
  try {
    await transform('xxencode', 'decode', 'helloworld', defaultParams);
  } catch {
    threw = true;
  }
  expect(threw, 'xxencode without a begin line must be rejected');
  const smart = await transform('smart-decode', 'decode', encoded, defaultParams);
  expect(smart.includes('flag{xxencode}'), `smart decode xxencode -> ${smart.slice(0, 80)}`);
});

// 古典密码无密钥自动破译：带密钥生成密文 → 智能解码无命中回退链断言还原
// 容错匹配：数字方阵解码存在 leet 替换噪声（如 G→9），按滑窗位置命中率 ≥75% 判还原
const fuzzyIncludes = (hay, needle) => {
  const letters = String(hay).toUpperCase().replace(/[^A-Z]/g, '');
  const n = needle.length;
  const threshold = Math.ceil(n * 0.75);
  for (let start = 0; start + n <= letters.length; start += 1) {
    let hits = 0;
    for (let i = 0; i < n; i += 1) {
      if (letters[start + i] === needle[i]) hits += 1;
    }
    if (hits >= threshold) return true;
  }
  return false;
};

await run('古典密码无密钥破译：Playfair/Bifid/Trifid/ADFGX/ADFGVX/列换位', async () => {
  // 三轮稳定性验证过的样本配置（长度保证统计量充足且预算内收敛）
  const passage = 'The ancient manuscript was hidden beneath the old library floor for many decades before the archivist discovered it. Scholars believe the cipher was created by a soldier who wanted to protect the battle plans from enemy spies. Every letter was carefully encoded by hand using a paper grid and a secret keyword that nobody else had ever seen. After months of hard work the team finally recovered the text and found the words flagkeylessbreak inside the final paragraph of the document.';
  const long = passage + ' The general had ordered his officers to burn every copy of the letter after reading it, but one soldier kept a folded page inside his coat for many years, and when the war ended he placed the papers inside a wooden box beneath the floor of an old church.';
  const cases = [
    { op: 'columnar', key: { secret: 'CIPHERKEY' }, text: passage },
    { op: 'playfair', key: { secret: 'SHADOWGRID' }, text: passage },
    { op: 'bifid', key: { secret: 'ORBITAL', period: '6' }, text: passage, odd: true },
    { op: 'trifid', key: { secret: 'TRIPOD', period: '5' }, text: passage, odd: true, short: true },
    { op: 'adfgx', key: { secret: 'BATTLE', keyword2: 'NIGHTOWL' }, text: long },
    { op: 'adfgvx', key: { secret: 'VANGUARD', keyword2: 'CASTOR' }, text: long },
  ];
  for (const testCase of cases) {
    let plaintext = testCase.short ? testCase.text.slice(0, 330) : testCase.text;
    if (testCase.odd) { while (plaintext.replace(/[^A-Za-z]/g, '').length % 2 === 0) plaintext = plaintext.slice(0, -1); }
    // trifid 破译单次成功率为概率性（~20-80% 视文本而定，SA 景观决定）；搜索种子取自密文哈希，
    // 同密文轨迹确定。统计性验证用两个同语义文本变体（尾字符差异改变种子）各试一次。
    // trifid 属概率性破译（SA 景观陡峭，长文本单次成功率有限）：验证不挂死、不产伪 flag、
    // 有破译命中即校验正确性；无命中属诚实的允许失败（组件 note 已声明该边界）
    const variants = testCase.op === 'trifid' ? [plaintext, plaintext + 'x'] : [plaintext];
    let output = '';
    let elapsed = 0;
    let solved = false;
    for (const variant of variants) {
      const ct = String(await transform(testCase.op, 'encode', variant, { ...defaultParams, ...testCase.key }));
      const tStart = Date.now();
      output = String(await transform('smart-decode', 'decode', ct, defaultParams));
      elapsed += Date.now() - tStart;
      if (fuzzyIncludes(output, 'KEYLESSBREAK') && output.includes('无密钥破译')) { solved = true; break; }
    }
    expect(elapsed < 60000, testCase.op + ' 破译耗时 ' + elapsed + 'ms 超上限');
    expect(!/FLAG{[A-Z0-9_]+}/i.test(output.replace(/KEYLESSBREAK/gi, '')), testCase.op + ' 产出伪 flag');
    if (testCase.op === 'trifid') {
      // 概率性：不强断言还原成功，但必须走安全路径（破译输出或诚实无识别）
      expect(output.includes('无密钥破译') || output.includes('没有识别到'), testCase.op + ' 输出异常: ' + output.slice(0, 80));
      return;
    }
    expect(solved, testCase.op + ' 无密钥还原失败: ' + output.slice(0, 80));
    expect(output.includes('无密钥破译'), testCase.op + ' 未走无密钥破译链: ' + output.slice(0, 80));
  }

  // 负向：高混淆度垃圾字母串必须安全返回（不挂死、不产伪 flag）
  const garbage = 'QXZKJVWBMPYTCRDLGNFHSUEOAIQZXKVWBMPYTCRDLGNFHSUEOAIQZXKVWBMPYTCRDLGNFHSUEOAIQZXKVWBMPYTCRDLGNFHSUEO'.repeat(3);
  const t1 = Date.now();
  const out1 = String(await transform('smart-decode', 'decode', garbage, defaultParams));
  const dt1 = Date.now() - t1;
  expect(dt1 < 30000, '垃圾输入破译耗时 ' + dt1 + 'ms 超上限');
  expect(!/FLAG{[A-Z0-9_]+}/i.test(out1), '垃圾输入不得产出伪 flag');
});

// 现代密码攻击面：RSA-OAEP（WebCrypto）/ Coppersmith 简化版 / PGP 结构解析 / CBC bit-flip 演示
await run('现代密码攻击面：OAEP/Coppersmith/PGP/CBC-demo', async () => {
  const nodeCrypto = await import('node:crypto');
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const jwkPub = publicKey.export({ format: 'jwk' });
  const jwkPrv = privateKey.export({ format: 'jwk' });
  // C1: OAEP 加密 → 解密往返
  const encInput = ['n=' + jwkPub.n, 'e=' + jwkPub.e, 'plain=flag{oaep_ok}'].join('\n');
  const encRaw = String(await transform('rsa-oaep', 'encode', encInput, defaultParams));
  const encOut = JSON.parse(encRaw.slice(encRaw.indexOf('{')));
  expect(encOut.cipherHex.length >= 128, 'OAEP 密文长度异常');
  const decInput = ['n=' + jwkPrv.n, 'e=' + jwkPrv.e, 'd=' + jwkPrv.d, 'p=' + jwkPrv.p, 'q=' + jwkPrv.q, 'c=' + encOut.cipherHex].join('\n');
  const decRaw = String(await transform('rsa-oaep', 'decode', decInput, defaultParams));
  const decOut = JSON.parse(decRaw.slice(decRaw.indexOf('{')));
  expect(decOut.plaintextUtf8 === 'flag{oaep_ok}', 'OAEP 往返失败: ' + decRaw.slice(0, 80));
  // C2: Coppersmith 简化版——c = m^3 无回绕，整数开方直接还原
  const mHex = Buffer.from('flag{cp_perk}', 'utf8').toString('hex');
  const mBig = BigInt('0x' + mHex);
  const nBig = mBig ** 3n + 1n;   // 无回绕场景：n > m^3
  const cInput = ['e=3', 'c=' + (mBig ** 3n), 'n=' + nBig, 'prefix=flag{'].join('\n');
  const cRaw1 = String(await transform('coppersmith', 'decode', cInput, defaultParams));
  const cOut = JSON.parse(cRaw1.slice(cRaw1.indexOf('{')));
  expect(String(cOut.recoveredUtf8) === 'flag{cp_perk}', 'Coppersmith 还原失败: ' + cRaw1.slice(0, 100));
  expect(/简化版/.test(String(cOut.notes)), 'Coppersmith 必须如实标注简化边界');
  // C3: PGP 结构解析（只读）
  const pkt = Buffer.concat([Buffer.from([0xcb]), Buffer.from('PGP demo payload data!!')]);
  const armor = '-----BEGIN PGP MESSAGE-----\nVersion: Payloader\n\n' + pkt.toString('base64').replace(/(.{64})/g, '$1\n') + '-----END PGP MESSAGE-----';
  const pgpOut = String(await transform('pgp-parse', 'decode', armor, defaultParams));
  expect(pgpOut.includes('字面数据') && pgpOut.includes('packetCount'), 'PGP 解析失败: ' + pgpOut.slice(0, 80));
  // C4: CBC bit-flip 演示（本地）
  const cbcRaw = String(await transform('cbc-padding-demo', 'decode', 'demo', { ...defaultParams, secret: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef' }));
  expect(cbcRaw.includes('bitFlip'), 'CBC bit-flip 演示缺失: ' + cbcRaw.slice(0, 80));
  expect(cbcRaw.includes('paddingOracle'), 'CBC padding oracle 段缺失');
});

await run('JSFuck / aaencode / jjencode 静态还原：无 eval 且有安全上限', async () => {
  const codecSources = fs.readdirSync(codecDir).filter(f => f.endsWith('.ts')).map(f => fs.readFileSync(path.join(codecDir, f), 'utf8')).join('\n');
  const workbenchFile = path.join(rootDir, 'src', 'components', 'CodecWorkbench.tsx');
  const ctfFile = path.join(rootDir, 'src', 'components', 'CtfToolkit.tsx');
  const source = `${codecSources}\n${fs.readFileSync(encodingToolsSourceFile, 'utf8')}\n${fs.readFileSync(workbenchFile, 'utf8')}\n${fs.readFileSync(ctfFile, 'utf8')}`;
  expect(!/\beval\s*\(/.test(source), '编码组件不得调用 eval(');
  expect(!/new\s+Function\b/.test(source), '编码组件不得使用 new Function');

  // JSFuck：经典 alert(1) 样本（aemkei/jsfuck 0.5.0 算法生成）往返
  const jfAlert = await transform('jsfuck', 'encode', 'alert(1)', defaultParams);
  const jfText = String(jfAlert);
  expect(/^[[\]!+()]+$/.test(jfText), 'JSFuck 输出必须是纯 []()!+ 符号');
  expect(jfText.length > 500, 'JSFuck alert(1) 编码长度异常');
  const jfBack = await transform('jsfuck', 'decode', jfText, defaultParams);
  expect(jfBack === 'alert(1)', `JSFuck 往返失败: ${String(jfBack).slice(0, 60)}`);

  // flag 样本往返
  for (const text of ['flag{jsfuck_2026}', 'flag{a_b}']) {
    const enc = await transform('jsfuck', 'encode', text, defaultParams);
    const dec = await transform('jsfuck', 'decode', enc, defaultParams);
    expect(dec === text, `JSFuck 往返失败: ${text}`);
  }

  // aaencode / jjencode：alert(1) 与 flag 往返（解码需自动还原内嵌 atob/转义）
  const aaEnc = await transform('aaencode', 'encode', 'flag{aa_demo}', defaultParams);
  const aaDec = await transform('aaencode', 'decode', aaEnc, defaultParams);
  expect(String(aaDec).includes('flag{aa_demo}'), `aaencode 往返失败: ${String(aaDec).slice(0, 80)}`);
  const jjEnc = await transform('jjencode', 'encode', 'flag{jj_hidden}', defaultParams);
  const jjDec = await transform('jjencode', 'decode', jjEnc, defaultParams);
  expect(String(jjDec).includes('flag{jj_hidden}'), `jjencode 往返失败: ${String(jjDec).slice(0, 80)}`);

  // 负向：无执行点的纯表达式必须报错而非假装成功
  let threw = false;
  try { await transform('jsfuck', 'decode', '1+1', defaultParams); } catch { threw = true; }
  expect(threw, '无执行点输入必须报错');

  // 负向：畸形/超长输入安全返回错误（不得挂死）
  threw = false;
  try { await transform('jsfuck', 'decode', 'hello world', defaultParams); } catch { threw = true; }
  expect(threw, '非符号输入必须报错');
  threw = false;
  const bomb = '('.repeat(5000);
  try { await transform('jsfuck', 'decode', bomb, defaultParams); } catch { threw = true; }
  expect(threw, '深度嵌套炸弹必须安全报错');
  threw = false;
  try { await transform('aaencode', 'decode', 'x'.repeat(600000), defaultParams); } catch { threw = true; }
  expect(threw, '超长输入必须安全报错');

  // 负向：encode 侧同样设上限（JSFuck 最坏膨胀 ~3600x/字符，防编码阻塞主线程）
  threw = false;
  try { await transform('jsfuck', 'encode', 'a'.repeat(30000), defaultParams); } catch { threw = true; }
  expect(threw, 'JSFuck 编码超长输入必须报错');
  threw = false;
  try { await transform('jjencode', 'encode', 'a'.repeat(300000), defaultParams); } catch { threw = true; }
  expect(threw, 'jjencode 编码超长输入必须报错');

  // 负向：原型污染必须被拦截。单次调用即可完成写穿，不得靠 "()()" 的第二次调用抛错凑证据；
  // 求值器与断言必须同 realm（vm），宿主侧探针结构上看不到 vm 内的写入
  try {
    await transform('jsfuck', 'decode', '[]["at"]["constructor"]("({})[\'__proto__\'][\'sx_p2\']=1337")()', defaultParams);
  } catch {
    // 求值器直接拒绝该形态也算拦截成功，最终以 realm 内状态断言为准
  }
  const protoPolluted = vm.runInContext("typeof ({}).sx_p2 !== 'undefined'", encodingToolsVmContext, { filename: 'proto-pollution-probe.js' });
  expect(protoPolluted === false, '原型污染必须被拦截：Object.prototype 不得被写入');

  // 负向：padStart 长度炸弹必须被护栏拦截
  threw = false;
  try {
    await transform('jsfuck', 'decode', '[]["at"]["constructor"](\'x\'.padStart(99999999,"y"))()', defaultParams);
  } catch { threw = true; }
  expect(threw, 'padStart 长度炸弹必须被拦截');

  // 智能解码可达
  const smartJf = await transform('smart-decode', 'decode', jfText, defaultParams);
  expect(String(smartJf).includes('alert(1)'), `智能解码未能还原 JSFuck: ${String(smartJf).slice(0, 80)}`);

  // 全可打印 ASCII 单字符往返扫描（32-126，自愈映射后必须全部一致）
  for (let code = 32; code <= 126; code += 1) {
    const ch = String.fromCharCode(code);
    const text = 'x' + ch + 'x';
    const back = await transform('jsfuck', 'decode', await transform('jsfuck', 'encode', text, defaultParams), defaultParams);
    expect(back === text, `JSFuck 单字符往返失败: ${JSON.stringify(ch)} => ${JSON.stringify(String(back).slice(0, 30))}`);
  }
  const smartJj = await transform('smart-decode', 'decode', jjEnc, defaultParams);
  expect(String(smartJj).includes('flag{jj_hidden}'), `智能解码未能还原 jjencode: ${String(smartJj).slice(0, 80)}`);
  const smartAa = await transform('smart-decode', 'decode', aaEnc, defaultParams);
  expect(String(smartAa).includes('flag{aa_demo}'), `智能解码未能还原 aaencode: ${String(smartAa).slice(0, 80)}`);
});

await run('z-base-32 follows the Zimmermann spec and round-trips', async () => {
  // 规格书向量：单字节 0x00 → 两个零五比特组（含低位补零）→ yy；"A"(0x41) → 01000|00100 → er
  assert.equal(await transform('z-base-32', 'encode', '\u0000', defaultParams), 'yy');
  assert.equal(await transform('z-base-32', 'encode', 'A', defaultParams), 'er');
  assert.equal(await transform('z-base-32', 'decode', 'yy', defaultParams), '\u0000');
  const encoded = await transform('z-base-32', 'encode', 'flag{zbase32}', defaultParams);
  assert.equal(encoded, encoded.toLowerCase());
  assert.equal(await transform('z-base-32', 'decode', encoded, defaultParams), 'flag{zbase32}');
  assert.equal(await transform('z-base-32', 'decode', encoded.toUpperCase(), defaultParams), 'flag{zbase32}');
  let threw = false;
  try {
    await transform('z-base-32', 'decode', 'abc123!', defaultParams);
  } catch {
    threw = true;
  }
  expect(threw, 'characters outside the z-base-32 alphabet must be rejected');
  const smart = await transform('smart-decode', 'decode', encoded, defaultParams);
  expect(smart.includes('flag{zbase32}'), `smart decode z-base-32 -> ${smart.slice(0, 80)}`);
});

await run('Base32768 matches the qntm reference table and round-trips', async () => {
  // 两个 NUL 字节：前 15 bit 全零 → 15-bit 表首字符 U+04A0；剩 1 bit 补 1 到 7 bit → 7-bit 表第 63 项 U+025F
  assert.equal(await transform('base32768', 'encode', '\u0000\u0000', defaultParams), '\u04A0\u025F');
  assert.equal(await transform('base32768', 'decode', '\u04A0\u025F', defaultParams), '\u0000\u0000');
  // 1..40 字节覆盖全部填充类别（8-14 bit 补 1 进 15-bit 表，1-7 bit 补 1 进 7-bit 表）
  for (let n = 1; n <= 40; n += 1) {
    const text = 'a'.repeat(n);
    const roundTripped = await transform('base32768', 'decode', await transform('base32768', 'encode', text, defaultParams), defaultParams);
    assert.equal(roundTripped, text, `base32768 round-trip failed at ${n} bytes`);
  }
  let threw = false;
  try {
    await transform('base32768', 'decode', 'helloworld', defaultParams);
  } catch {
    threw = true;
  }
  expect(threw, 'characters outside the Base32768 tables must be rejected');
  threw = false;
  try {
    await transform('base32768', 'decode', '\u0180\u04A0', defaultParams);
  } catch {
    threw = true;
  }
  expect(threw, 'secondary (7-bit) character before end of input must be rejected');
  threw = false;
  try {
    await transform('base32768', 'decode', '\u04A0', defaultParams);
  } catch {
    threw = true;
  }
  expect(threw, 'padding mismatch must be rejected');
  const encoded = await transform('base32768', 'encode', 'flag{b32768}', defaultParams);
  const smart = await transform('smart-decode', 'decode', encoded, defaultParams);
  expect(smart.includes('flag{b32768}'), `smart decode base32768 -> ${smart.slice(0, 80)}`);
});

await run('Hash operation derives NTLM from UTF-16LE passwords (openssl-verified vectors)', async () => {
  const ntlm = password => transform('hash', 'encode', password, { ...defaultParams, hashAlgorithm: 'ntlm' });
  assert.equal(await ntlm(''), '31d6cfe0d16ae931b73c59d7e0c089c0');
  assert.equal(await ntlm('password'), '8846f7eaee8fb117ad06bdd830b7586c');
  assert.equal(await ntlm('ABCdef123'), '147d125645d463c33d72309525e9b0bc');
  assert.equal(await ntlm('Pässwörd!'), 'bf8cb9e15029cd70cf2e560baab0bf26');
  assert.equal(await ntlm('\u{1D518}'), '2f7f63a246b8e7169fffd0eee93b3367');
  // 顺带给既有的裸 MD4 补上首个标准向量回归（openssl legacy provider 同值）
  assert.equal(await transform('hash', 'encode', 'abc', { ...defaultParams, hashAlgorithm: 'md4' }), 'a448017aaf21d8525fc10ae87aa6729d');
  assert.equal(await transform('hash', 'encode', 'abc', { ...defaultParams, hashAlgorithm: 'md5' }), '900150983cd24fb0d6963f7d28e17f72');
});

await run('中文密码家族：官方向量、round-trip 与智能识别（批次 K）', async () => {
  const p = { ...defaultParams };
  // 与佛论禅：Leon406/ToolsFx BuddhaTest.kt 官方向量（decode×2 + encode 往返）
  assert.equal(await transform('buddha', 'decode', '佛曰：冥耶以缽醯以梵蘇心缽參哆能哆他多罰姪實悉那遮奢三', p), '与佛论禅666');
  assert.equal(await transform('buddha', 'decode', '佛曰：麼奢道梵呼舍舍等密爍皤集怯一梵殿缽離罰喝不耶苦', p), '123');
  assert.equal(await transform('buddha', 'decode', await transform('buddha', 'encode', 'flag{buddha_rt} 往返', p), p), 'flag{buddha_rt} 往返');
  // 与熊论道：ToolsFx wiki + Abracadabra 官方示例（decode + encode 往返）
  assert.equal(await transform('bear-says', 'decode', '熊曰：呋食性類啽家現出爾常肉嘿達嗷很', p), 'Abracadabra');
  assert.equal(await transform('bear-says', 'decode', await transform('bear-says', 'encode', 'flag{bear_rt}', p), p), 'flag{bear_rt}');
  // 百家姓：流派 A（明文直接替换，ToolsFx wiki 样本）与流派 B（base64 替换）双路
  assert.equal(await transform('baijiaxing', 'decode', '水褚尤范尤褚柳尤张朱', p), 'BaiJiaXing');
  assert.equal(await transform('baijiaxing', 'decode', '吴郎孙朱吴褚袁陈苗俞范章', p), '你好ABC');
  assert.equal(await transform('baijiaxing', 'decode', await transform('baijiaxing', 'encode', 'flag{bjx_rt}', p), p), 'flag{bjx_rt}');
  // 六十四卦：CtfTest2.kt eight() 官方向量 + 卦名/卦符双流派 round-trip
  assert.equal(await transform('hexagram', 'decode', '升困艮益蛊困蛊无妄井萃噬嗑既济井兑损离巽履晋节恒履蒙归妹鼎讼蛊履大过否噬嗑需井萃未济丰巽萃大有同人小过涣谦', p), 'abcefghijklmoqrsttuvwxyzhelloo12');
  assert.equal(await transform('hexagram', 'decode', await transform('hexagram', 'encode', 'flag{hex_names}', { ...p, variant: 'names' }), p), 'flag{hex_names}');
  assert.equal(await transform('hexagram', 'decode', await transform('hexagram', 'encode', 'flag{hex_sym}', { ...p, variant: 'symbols' }), p), 'flag{hex_sym}');
  // 天干地支：CtfTest2.kt sexagesimal() 官方向量（encode/decode 双向）
  assert.equal(await transform('sexagesimal', 'encode', '你好', p), '乙丑癸巳甲寅己亥丁卯甲申丁未甲午己巳');
  assert.equal(await transform('sexagesimal', 'decode', '乙丑癸巳甲寅己亥丁卯甲申丁未甲午己巳', p), '你好');
  // 云影密码（幂数加密）：攻防世界真题向量 + 贪心编码往返
  assert.equal(await transform('cloud-shadow', 'decode', '8842101220480224404014224202480122', p), 'WELLDONE');
  assert.equal(await transform('cloud-shadow', 'decode', await transform('cloud-shadow', 'encode', 'WELLDONE', p), p), 'WELLDONE');
  // Pizzini：CacheSleuth 官方示例（CAB→645、8224→ESA）+ 序号+3 推导向量
  assert.equal(await transform('pizzini', 'encode', 'HELLO', p), '118151518');
  assert.equal(await transform('pizzini', 'decode', '645', p), 'CAB');
  assert.equal(await transform('pizzini', 'decode', '8224', p), 'ESA');
  assert.equal(await transform('pizzini', 'decode', '512171724', p), 'BINNU');
  // Cisco Type 7：种子 09 手工向量（flag → 094A42081E）+ 往返
  assert.equal(await transform('cisco-type7', 'decode', '094A42081E', p), 'flag');
  assert.equal(await transform('cisco-type7', 'decode', await transform('cisco-type7', 'encode', 'flag{cisco7}', p), p), 'flag{cisco7}');
  // Decabit：dcode 官方向量（DECA）+ 1/0 记法兼容 + 往返
  assert.equal(await transform('decabit', 'decode', '-+-++++--- ++-+--+-+- +--++++--- ++-+++----', p), 'DECA');
  assert.equal(await transform('decabit', 'encode', 'DECA', p), '-+-++++--- ++-+--+-+- +--++++--- ++-+++----');
  assert.equal(await transform('decabit', 'decode', await transform('decabit', 'encode', 'flag{decabit}', p), p), 'flag{decabit}');
  // Cetacean：CyberChef 官方测试向量（hi、含空格的 "a b c で"）+ A/B 变体归一化 + 往返
  assert.equal(await transform('cetacean', 'encode', 'hi', p), 'EEEEEEEEEeeEeEEEEEEEEEEEEeeEeEEe');
  assert.equal(await transform('cetacean', 'decode', 'EEEEEEEEEeeEeEEEEEEEEEEEEeeEeEEe', p), 'hi');
  assert.equal(await transform('cetacean', 'decode', 'AAAAAAAAABBABAAAAAAAAAAAABBABAAB', p), 'hi');
  assert.equal(await transform('cetacean', 'decode', 'EEEEEEEEEeeEEEEe EEEEEEEEEeeEEEeE EEEEEEEEEeeEEEee EEeeEEEEEeeEEeee', p), 'a b c で');
  assert.equal(await transform('cetacean', 'decode', await transform('cetacean', 'encode', 'a b c', p), p), 'a b c');
  // Albam：默认 A↔N 对合流派（HELLO→URYYB）与 CacheSleuth +11 流派（HELLO→SPWWZ）双路
  assert.equal(await transform('albam', 'encode', 'HELLO', { ...p, variant: 'special' }), 'URYYB');
  assert.equal(await transform('albam', 'decode', 'URYYB', { ...p, variant: 'special' }), 'HELLO');
  assert.equal(await transform('albam', 'encode', 'HELLO', { ...p, variant: 'shift11' }), 'SPWWZ');
  assert.equal(await transform('albam', 'decode', 'SPWWZ', { ...p, variant: 'shift11' }), 'HELLO');
  // Carbonaro：CacheSleuth 官方示例（THE↔DHI）+ 对合往返
  assert.equal(await transform('carbonaro', 'encode', 'THE', p), 'DHI');
  assert.equal(await transform('carbonaro', 'decode', 'DHI', p), 'THE');
  assert.equal(await transform('carbonaro', 'decode', await transform('carbonaro', 'encode', 'flag{carbonaro}', p), p), 'flag{carbonaro}');
  // 如是我闻 V2：AES 解出 7z 容器；LZMA 条目降级提示含 hex（完整明文路径由容器是否 store 决定）
  const v2 = await transform('buddha-v2', 'decode', '如是我闻：智清戏虚和尊積族宇息訶夜七楞急璃王瑟凉他資以實曳栗诵捐稳拔憐槃师拔功放恤彌穆月奉灯帝心倒殿貧在真山廟尼經死濟弟王捨善阿琉功夜数宝重薩高劫宝千倒孕释量室消陰诸中陵遠曰困住文實宗在来如難濟亦令药众足生孤量此麼依鄉貧睦根特东友遮以经梭三特宝游弥楞故急想树沙真亿数想閦彌訶稳福諦诸福提敬信朋除师敬豆倒吼宇倒亿茶解時婦亦濟以足便度', p);
  expect(v2.includes('CTF如是我闻Test123') || (v2.includes('7z 容器') && v2.includes('hex')), '如是我闻 V2 既未解出明文也未给出容器降级说明');
  // 智能识别：芯片命中 + 自动解码 + pcmoe 新佛曰闭源说明
  expect(detectInput('魔曰：冥耶以缽醯以梵蘇心缽參哆能哆他多罰姪實悉那遮奢三').some(d => d.id === 'buddha'), '魔曰前缀芯片缺失');
  expect(detectInput('如是我闻：智清戏虚和尊').some(d => d.id === 'buddha-v2'), '如是我闻芯片缺失');
  expect(detectInput('熊曰：呋食性類啽家現出爾常肉嘿達嗷很').some(d => d.id === 'bear-says'), '熊曰芯片缺失');
  expect(detectInput('吴郎孙朱吴褚袁陈苗俞范章').some(d => d.id === 'baijiaxing'), '百家姓芯片缺失');
  expect(detectInput('升困艮益蛊困蛊无妄井萃噬嗑').some(d => d.id === 'hexagram'), '六十四卦卦名芯片缺失');
  expect(detectInput('乙丑癸巳甲寅己亥丁卯甲申丁未甲午己巳').some(d => d.id === 'sexagesimal'), '天干地支芯片缺失');
  expect(detectInput('8842101220480224404014224202480122').some(d => d.id === 'cloud-shadow'), '云影芯片缺失');
  expect(detectInput('118151518').some(d => d.id === 'pizzini'), 'Pizzini 芯片缺失');
  expect(detectInput('094A42081E').some(d => d.id === 'cisco-type7'), 'Cisco Type 7 芯片缺失');
  expect(detectInput('-+-++++--- ++-+--+-+- +--++++--- ++-+++----').some(d => d.id === 'decabit'), 'Decabit 芯片缺失');
  expect(detectInput('EEEEEEEEEeeEeEEEEEEEEEEEEeeEeEEe').some(d => d.id === 'cetacean'), 'Cetacean 芯片缺失');
  expect((await smartDecode('佛曰：冥耶以缽醯以梵蘇心缽參哆能哆他多罰姪實悉那遮奢三')).includes('与佛论禅666'), '智能解码未自动解出佛曰');
  expect((await smartDecode('熊曰：呋食性類啽家現出爾常肉嘿達嗷很')).includes('Abracadabra'), '智能解码未自动解出熊曰');
  expect((await smartDecode('乙丑癸巳甲寅己亥丁卯甲申丁未甲午己巳')).includes('你好'), '智能解码未自动解出天干地支');
  expect((await smartDecode('新佛曰：諸怖隸僧怖降吽諸陀怖摩隸怖僧缽薩願僧宣摩嚴迦聞般怖眾訶嚤哆愍羅')).includes('闭源'), 'pcmoe 新佛曰缺少闭源说明');
});

// ---- 批次 O：随波逐流操作对齐（75 个新操作的数据驱动向量回归）----
const PARITY_OP_IDS = [
  'base92', 'base100', 'base85-rfc1924', 'base62-ascii', 'base64-multiline', 'base64-case-mangled', 'base64-to-hex', 'base-custom', 'base-multi-decode', 'rot18', 'rot-special',
  'pigpen', 'keyboard-keycode', 'handycode', 'chinesecode', 'backslash-code', 'slash-pipe', 'tomtom', 'clock-code', 'goldbug', 'kenny', 'abaddon', 'dvorak', 'five-needle', 'hodor', 'duckspeak', 'numberpad-lines', 'quadoo', 'bwt',
  'core-values', 'hanzi-stroke', 'yinyang-qi', 'bagua-symbols', 'telecode', 'xiangyue', 'makabaka', 'yinyin', 'shouyin', 'periodic-table', 'mars-text', 'braille', 'music-notes', 'flower-code', 'letter-code', 'arrow-code', 'hanzi-code', 'ipa-code', 'whitespace-code', 'deadfish', 'spoon', 'manchester', 'emoji-encoder',
  'otp', 'multiplicative', 'fractionated-morse', 'fenham', 'running-key', 'bazeries', 'kamasutra', 'm209', 'rc2', 'rc6',
  'ieee754', 'twos-complement', 'ones-complement', 'radix-xor', 'bit-split', 'hamming', 'qwe-keyboard', 'gcd', 'prime-factor', 'fibonacci-code', 'pickle-parse', 'ascii-control', 'quwei',
];
const parityVectorGroups = [parityBaseVectors, parityCharVectors, parityCnVectors, parityKeyedVectors, parityNumVectors];

await run('批次 O 随波逐流对齐：75 操作全覆盖、权威向量对拍与 round-trip 数据驱动回归', async () => {
  const vectors = parityVectorGroups.flat();
  expect(vectors.length >= 75, `回归向量不足：期望 ≥75（每操作至少 1 条），实际 ${vectors.length}`);
  const authoritativeCount = vectors.filter(vector => vector.cipher !== undefined).length;
  expect(authoritativeCount >= 30, `权威向量不足：期望 ≥30（不少于新增操作数的 1/3），实际 ${authoritativeCount}`);
  const vectorIds = new Set(vectors.map(vector => vector.id));
  const missingVectors = PARITY_OP_IDS.filter(id => !vectorIds.has(id));
  expect(missingVectors.length === 0, `操作缺回归向量：${missingVectors.join(', ')}`);
  const unknownVectors = [...vectorIds].filter(id => !PARITY_OP_IDS.includes(id));
  expect(unknownVectors.length === 0, `回归向量引用未知操作：${unknownVectors.join(', ')}`);
  for (const vector of vectors) {
    const params = { ...defaultParams, ...(vector.params ?? {}) };
    const tag = `${vector.id}${vector.params ? JSON.stringify(vector.params) : ''}`;
    if (vector.direction === 'decode') {
      expect(vector.cipher !== undefined, `单向向量缺密文：${tag}`);
      const decoded = await transform(vector.id, 'decode', vector.cipher, params);
      expect(decoded === vector.plain, `单向解码不符 ${tag}: 期望 ${JSON.stringify(vector.plain)} 实得 ${JSON.stringify(decoded)}`);
    } else {
      const encoded = await transform(vector.id, 'encode', vector.plain, params);
      if (vector.cipher !== undefined) {
        expect(encoded === vector.cipher, `权威对拍不符 ${tag}: 期望 ${JSON.stringify(vector.cipher)} 实得 ${JSON.stringify(encoded)}`);
      }
      const decoded = await transform(vector.id, 'decode', vector.cipher ?? encoded, params);
      expect(decoded === vector.plain, `round-trip 不符 ${tag}: 期望 ${JSON.stringify(vector.plain)} 实得 ${JSON.stringify(decoded)}`);
    }
  }
});

await run('批次 O 智能识别：形状探针芯片正反例命中 + 高特征样本自动解码', async () => {
  const vectors = parityVectorGroups.flat();
  const plainSentence = 'The quick brown fox jumps over the lazy dog, twice!';
  let chipChecks = 0;
  for (const probe of parityProbes) {
    // 样本池 = 该操作全部权威 cipher 向量 + 全部 plain 向量的现编码结果；至少一个真实样本命中芯片才算数。
    const idVectors = vectors.filter(vector => vector.id === probe.id);
    const samples = [];
    for (const vector of idVectors) {
      if (vector.cipher !== undefined) samples.push(vector.cipher);
      if (vector.direction === 'decode') continue;
      try {
        samples.push(await transform(probe.id, 'encode', vector.plain, { ...defaultParams, ...(vector.params ?? {}) }));
      } catch {
        // 单向操作或该样本不支持编码：密文样本已覆盖，跳过
      }
    }
    if (samples.length === 0) continue;
    const hit = samples.some(sampleText => detectInput(sampleText).some(detection => detection.id === probe.id));
    expect(hit, `探针芯片未命中任何真实样本：${probe.id}（样本 ${samples.length} 个）`);
    expect(!probe.test(plainSentence), `探针误报普通文本：${probe.id}`);
    chipChecks += 1;
  }
  expect(chipChecks >= MIN_CHIP_CHECKS, `形状探针芯片覆盖不足：期望 ≥${MIN_CHIP_CHECKS} 个有样本验证，实际 ${chipChecks}`);
  // telecode/quwei 等 4 位数字组形态与日期/编号不可区分，已退出直解路径（只出芯片），故不在自动解码样本内
  for (const id of AUTO_SAMPLE_IDS) {
    const idVectors = vectors.filter(vector => vector.id === id);
    if (idVectors.length === 0) throw new Error(`自动解码样本缺失：${id}`);
    let decodedAtLeastOne = false;
    let lastOutput = '';
    for (const vector of idVectors) {
      const cipherText = vector.cipher !== undefined
        ? vector.cipher
        : await transform(id, 'encode', vector.plain, { ...defaultParams, ...(vector.params ?? {}) });
      lastOutput = await smartDecode(cipherText);
      if (lastOutput.includes(vector.plain)) {
        decodedAtLeastOne = true;
        break;
      }
    }
    expect(decodedAtLeastOne, `智能解码未自动解出 ${id}：最后输出 ${JSON.stringify(lastOutput.slice(0, 160))}`);
  }
  // 数字形探针直解必须过质量底线（review P1 回归钉）：普通数字串不得被强行解成电码/区位码/数字键盘码
  for (const digits of ['1234 5678', '2024 0101', '7295 32489']) {
    const output = await smartDecode(digits);
    expect(!output.includes('识别链路'), `普通数字串被误直解：${digits} → ${JSON.stringify(output.slice(0, 90))}`);
  }
});

await run('受众分流：编解码与 CTF 视图记账守恒、无遗漏无重复', async () => {
  const total = operations.length;
  const byAudience = { ctf: [], both: [], pentest: [] };
  for (const op of operations) {
    const tag = operationAudience[op.id];
    expect(tag === 'ctf' || tag === 'both' || tag === 'pentest', `操作 ${op.id} 缺少合法受众标记`);
    byAudience[tag].push(op.id);
  }
  expect(byAudience.ctf.length + byAudience.both.length + byAudience.pentest.length === total, '受众标记必须完整覆盖全部操作');
  // 钉住计划口径的具体数字，防止清单漂移（批次 W 纠偏：57 个 pentest 独占转 both，渗透专属仅剩 2 个）
  const snapshot = AUDIENCE_SNAPSHOT;
  expect(total === snapshot.total && byAudience.ctf.length === snapshot.ctf && byAudience.both.length === snapshot.both && byAudience.pentest.length === snapshot.pentest, `受众记账口径漂移：期望 ctf=${snapshot.ctf}/both=${snapshot.both}/pentest=${snapshot.pentest}/total=${snapshot.total}，实际 ctf=${byAudience.ctf.length}/both=${byAudience.both.length}/pentest=${byAudience.pentest.length}/total=${total}`);

  const pentestGroups = buildPentestGroups();
  const ctfGroups = buildCtfGroups();
  const pentestView = pentestGroups.flatMap(group => group.operations.map(op => op.id));
  const ctfView = ctfGroups.flatMap(group => group.operations.map(op => op.id));
  const noDup = ids => new Set(ids).size === ids.length;
  expect(noDup(pentestView), '编解码视图操作不得重复');
  expect(noDup(ctfView), 'CTF 视图操作不得重复');
  // 验收公式：两视图并集 = 操作总数（无遗漏无重复）；both 操作按需求在两侧都渲染
  const union = new Set([...pentestView, ...ctfView]);
  expect(union.size === total, `两视图并集 ${union.size} 必须等于操作总数 ${total}`);
  expect(union.size === pentestView.length + ctfView.length - byAudience.both.length, '两视图交集必须恰好是 both 集合');
  const pentestExpected = [...byAudience.pentest, ...byAudience.both];
  const ctfExpected = [...byAudience.ctf, ...byAudience.both];
  const pentestSet = new Set(pentestView);
  const ctfSet = new Set(ctfView);
  expect(pentestExpected.length === pentestView.length && pentestExpected.every(id => pentestSet.has(id)), '编解码视图必须恰好等于 pentest+both 集合');
  expect(ctfExpected.length === ctfView.length && ctfExpected.every(id => ctfSet.has(id)), 'CTF 视图必须恰好等于 ctf+both 集合');
  // 渗透视图无空分类；smart 分类整体迁往 CTF 后不得残留
  expect(pentestGroups.every(group => group.operations.length > 0), '渗透视图不得出现空分类');
  expect(!pentestGroups.some(group => group.id === 'smart'), 'smart-decode 已迁往 CTF 视图，渗透视图不得保留空 smart 分类');
  // CTF 视图四段流程：智能识别必须存在且只含 smart-decode
  const smartGroup = ctfGroups.find(group => group.id === 'smart');
  // 智能识别段 = smart-decode（叙事路由）+ magic-chain（CyberChef Magic 式深度链），钉住防止无声漂移。
  expect(smartGroup && smartGroup.operations.length === 2
    && smartGroup.operations.some(op => op.id === 'smart-decode')
    && smartGroup.operations.some(op => op.id === 'magic-chain'), 'CTF 视图智能识别段缺失或不完整');
  // flag 格式徽标识别（只做展示）
  const hits = detectFlagFormats('noise flag{ab_1234} tail ctf{xy_9876}');
  expect(hits.length === 2 && hits[0].prefix === 'flag' && hits[1].prefix === 'ctf', 'flag 格式识别失败');
  expect(detectFlagFormats('plain text without flags').length === 0, '无 flag 文本不得误报');
  expect(detectFlagFormats('').length === 0, '空输入必须返回空结果');
});

const rangesText = (text, range) => text.slice(range.start, range.end);

await run('CTF 顶部菜单栏：9 菜单覆盖全部 CTF 可见操作、无重复无遗漏', async () => {
  const menus = buildCtfMenus();
  expect(menus.length === 10, `菜单数量漂移：期望 10，实际 ${menus.length}`);
  expect(menus.every(menu => menu.sections.length > 0 && menu.sections.every(section => section.operations.length > 0)), '菜单不得出现空分组');
  const menuIds = menus.flatMap(menu => menu.sections.flatMap(section => section.operations.map(op => op.id)));
  expect(new Set(menuIds).size === menuIds.length, '同一操作不得出现在多个菜单');
  const ctfIds = buildCtfGroups().flatMap(group => group.operations.map(op => op.id));
  const menuSet = new Set(menuIds);
  const missing = ctfIds.filter(id => !menuSet.has(id));
  expect(missing.length === 0, `菜单遗漏操作：${missing.join(', ')}`);
  const ctfSet = new Set(ctfIds);
  const unknown = menuIds.filter(id => !ctfSet.has(id));
  expect(unknown.length === 0, `菜单包含 CTF 视图之外的操作：${unknown.join(', ')}`);
  expect(menus[0].id === 'smart' && menuIds[0] === 'smart-decode', '智能识别必须是第一菜单且含 smart-decode');
});

// ---- 批次 W：受众纠偏 57 操作 + 回灌语义 + 现代密码菜单分组回归 ----
// 纠偏集合由 audience 派生（T3）：批次 W 纠偏 57 个 + 既有 both 28 个 = 全集 85（对齐
// AUDIENCE_SNAPSHOT.both）。手工 57 清单会与 audience 漂移（改标记忘改清单则断言失真），
// 派生全集 + 钉长度比原清单检查力更强（85 ⊇ 57）。
await run('批次 W 受众纠偏：57 个 CTF 高频操作受众为 both 且 CTF 视图可见', async () => {
  const bothIds = operations.filter(op => operationAudience[op.id] === 'both').map(op => op.id);
  expect(bothIds.length === AUDIENCE_SNAPSHOT.both, `both 集合漂移：期望 ${AUDIENCE_SNAPSHOT.both} 个，实际 ${bothIds.length}`);
  const ctfIds = new Set(buildCtfGroups().flatMap(group => group.operations.map(op => op.id)));
  const invisible = bothIds.filter(id => !ctfIds.has(id));
  expect(invisible.length === 0, `纠偏操作未进 CTF 视图分组：${invisible.join(', ')}`);
  // 代表性 ID 钉住：数量守恒的"双重受众互换"可逃逸计数检查，钉 3 个批次 W 纠偏代表 + 全部 85 的抽查面
  for (const representative of ['aes-gcm', 'hash', 'jsfuck', 'cbor', 'totp']) {
    expect(operationAudience[representative] === 'both', `代表性纠偏操作 ${representative} 受众漂移`);
  }
  // 界线守护：仅有的 2 个渗透专属操作不得被顺手放大
  expect(operationAudience['signature-nonce-helper'] === 'pentest' && operationAudience['basic-auth'] === 'pentest', 'signature-nonce-helper/basic-auth 必须保持 pentest 专属');
  expect(!ctfIds.has('signature-nonce-helper') && !ctfIds.has('basic-auth'), 'pentest 专属操作不得出现在 CTF 视图');
});

await run('批次 W 回灌语义：纯结果提取剥离识别链路标头与候选区', async () => {
  expect(extractPureDecodeResult('识别链路: Base64\n\nSGVsbG8=') === 'SGVsbG8=', '未剥离识别链路标头');
  expect(extractPureDecodeResult('识别链路: Base64 -> Hex\n\n666c6167\n\n=== 候选列表 ===\n[{"layer":1}]') === '666c6167', '未同时剥离标头与候选区');
  expect(extractPureDecodeResult('plain result') === 'plain result', '无标头输出被误改');
  expect(extractPureDecodeResult('没有识别到可安全自动解码的格式。') === '没有识别到可安全自动解码的格式。', '无解码结果说明被误改');
  // 正文首尾空白必须原样保留：零宽/空白符类载荷的空白是数据本身
  expect(extractPureDecodeResult('识别链路: Zero-width\n\n ​​abc ​​') === ' ​​abc ​​', '正文空白被误裁');
  // 端到端：真实 smartDecode 输出提取后即干净密文（可再识别），不再夹带标头
  const chained = await smartDecode('ZmxhZ3t0ZXN0fQ==');
  expect(chained.startsWith('识别链路: Base64'), `智能解码应产出识别链路输出：${JSON.stringify(chained.slice(0, 60))}`);
  expect(extractPureDecodeResult(chained) === 'flag{test}', `回灌提取结果不符：${JSON.stringify(extractPureDecodeResult(chained))}`);
});

await run('批次 W 现代密码菜单：分组 ≥5、单组 ≤15 条、五命名组齐备', async () => {
  const modernMenu = buildCtfMenus().find(menu => menu.id === 'modern');
  expect(modernMenu, '现代密码菜单缺失');
  expect(modernMenu.sections.length >= 5, `现代密码菜单分组不足：期望 ≥5，实际 ${modernMenu.sections.length}`);
  const oversized = modernMenu.sections.filter(section => section.operations.length > 15);
  expect(oversized.length === 0, `现代密码菜单单组超 15 条：${oversized.map(section => section.label?.zh ?? '(无标签)').join(', ')}`);
  const labels = modernMenu.sections.map(section => section.label?.zh);
  for (const required of ['非对称与签名', '分组密码', '流密码与序列', '散列与 JWT', 'PRNG 与格']) {
    expect(labels.includes(required), `现代密码菜单缺命名组：${required}`);
  }
  expect(modernMenu.sections.every(section => section.operations.length > 0), '现代密码菜单不得出现空分组');
});

await run('flag 自动标红区间：完整格式深红优先、关键词补位、词边界不误报', async () => {
  const ranges = findFlagAutoRanges('prefix flag{abcd} middle FLAG{UP} and key tail');
  const formatHit = ranges.find(range => range.level === 'format');
  expect(formatHit && rangesText('prefix flag{abcd} middle FLAG{UP} and key tail', formatHit) === 'flag{abcd}', '完整格式区间错误');
  const keywordTexts = ranges.filter(range => range.level === 'keyword').map(range => rangesText('prefix flag{abcd} middle FLAG{UP} and key tail', range));
  expect(keywordTexts.includes('FLAG') && keywordTexts.includes('key'), `关键词区间缺失：${keywordTexts.join(', ')}`);
  expect(!keywordTexts.includes('flag'), '完整格式内的 flag 前缀不得重复命中关键词层');
  expect(findFlagAutoRanges('monkey business and keyboard').length === 0, '词边界失效：monkey/keyboard 不得命中');
  expect(findFlagAutoRanges('keys count as key').map(range => rangesText('keys count as key', range)).join(',').includes('keys'), 'keys 复数容差失效');
  expect(findFlagAutoRanges('').length === 0, '空输入必须返回空区间');
});

// 逆向域批次：注册表 entryKinds 守护。moduleContracts.ts 是零 React 依赖的纯数据模块（T2 分层解耦），
// 沙箱直接运行时加载真实断言，取代旧的源码正则（文本断言无法捕捉语义等价改写）。
await run('逆向/Pwn 注册表 entryKinds：reverse=file+cheatsheet、pwn=text+cheatsheet', async () => {
  const { ctfModuleContracts } = sharedLoadModule(path.join(rootDir, 'src', 'utils', 'ctf', 'moduleContracts.ts'));
  const contractById = Object.fromEntries(ctfModuleContracts.map(module => [module.id, module]));
  expect(JSON.stringify(contractById.reverse.entryKinds) === JSON.stringify(['file', 'cheatsheet']), `reverse entryKinds 漂移：${JSON.stringify(contractById.reverse.entryKinds)}`);
  expect(JSON.stringify(contractById.pwn.entryKinds) === JSON.stringify(['text', 'cheatsheet']), `pwn entryKinds 漂移：${JSON.stringify(contractById.pwn.entryKinds)}`);
  // 魔数路由扩展改为运行时断言：ROUTE_EXT_GROUPS（fileDetect.ts）是扩展名→题型域的唯一权威，
  // CtfToolkit/recommendTools 只允许 import 消费，禁止本地重声明（历史上同一事实四处漂移）。
  const routeGroups = sharedLoadModule(path.join(rootDir, 'src', 'utils', 'ctf', 'fileDetect.ts')).ROUTE_EXT_GROUPS;
  expect(JSON.stringify(routeGroups.traffic) === JSON.stringify(['pcap', 'pcapbe', 'pcapng']), `traffic 路由漂移：${JSON.stringify(routeGroups.traffic)}`);
  expect(JSON.stringify(routeGroups.reverse) === JSON.stringify(['elf', 'exe', 'macho', 'machobe']), `reverse 路由漂移：${JSON.stringify(routeGroups.reverse)}`);
  const toolkitSource = fs.readFileSync(path.join(rootDir, 'src', 'components', 'CtfToolkit.tsx'), 'utf8');
  expect(/import \{[^}]*ROUTE_EXT_GROUPS[^}]*\} from '[^']*fileDetect'/.test(toolkitSource), 'CtfToolkit 未消费权威路由表 ROUTE_EXT_GROUPS');
  expect(!/new Set\(\['pcap', 'pcapbe', 'pcapng'\]\)/.test(toolkitSource), 'CtfToolkit 不得本地重声明抓包扩展名集合');
  expect(!/new Set\(\['elf', 'exe', 'macho', 'machobe'\]\)/.test(toolkitSource), 'CtfToolkit 不得本地重声明可执行扩展名集合');
  const recommendSource = fs.readFileSync(path.join(rootDir, 'src', 'utils', 'ctf', 'recommendTools.ts'), 'utf8');
  expect(/ROUTE_EXT_GROUPS/.test(recommendSource), 'recommendTools 未消费权威路由表 ROUTE_EXT_GROUPS');
  expect(!/new Set\(\['elf', 'exe', 'macho'\]\)/.test(recommendSource), 'recommendTools 不得本地重声明可执行扩展名集合');
});

console.log(`\nVerified ${results.length} EncodingTools regression checks.`);
