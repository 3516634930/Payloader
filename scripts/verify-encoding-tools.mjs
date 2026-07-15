import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { deflateSync, gzipSync, gunzipSync, inflateSync } from 'node:zlib';
import ts from 'typescript';

const rootDir = process.cwd();
const sourceFile = path.join(rootDir, 'src', 'components', 'EncodingTools.tsx');
const nodeRequire = createRequire(import.meta.url);

const compileEncodingToolsModule = () => {
  let source = fs.readFileSync(sourceFile, 'utf8').replace(/^\uFEFF/, '');
  source = source.replace(/^import .*?;\r?\n/gm, '');
  source += '\nmodule.exports = { transform, defaultParams, detectInput, inferRsaParamsFromText, inferDlpFromText, factorSmallRsaModulus, operations, gsm7DefaultAlphabet, gsm7ExtensionAlphabet };\n';

  const compiled = ts.transpileModule(source, {
    compilerOptions: {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.CommonJS,
      jsx: ts.JsxEmit.ReactJSX,
      esModuleInterop: true,
    },
    fileName: sourceFile,
  }).outputText;

  const context = {
    module: { exports: {} },
    exports: {},
    require: nodeRequire,
    console,
    process,
    Buffer,
    crypto: globalThis.crypto || crypto.webcrypto,
    atob: value => Buffer.from(value, 'base64').toString('binary'),
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    TextEncoder,
    TextDecoder,
    Uint8Array,
    URL,
    URLSearchParams,
    Blob,
    CompressionStream,
    DecompressionStream,
    setTimeout,
    clearTimeout,
    globalThis: { Blob, CompressionStream, DecompressionStream },
  };
  context.global = context;
  vm.createContext(context);
  vm.runInContext(compiled, context, { filename: 'EncodingTools.compiled.js' });
  return context.module.exports;
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

const {
  transform,
  defaultParams,
  detectInput,
  inferRsaParamsFromText,
  inferDlpFromText,
  factorSmallRsaModulus,
  operations,
  gsm7DefaultAlphabet,
  gsm7ExtensionAlphabet,
} = compileEncodingToolsModule();

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

await run('RSA messy labels with explicit factors', async () => {
  const input = [
    'The modulus value is 3233',
    'public exponent equals 17',
    'ciphertext blob was 2790',
    'prime factor p = 61',
    'prime factor q = 53',
  ].join('\n');
  const output = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(output.output.decimal, '65');
});

await run('smart-decode routes messy RSA labels to raw RSA decrypt', async () => {
  const input = [
    'The modulus value is 3233',
    'public exponent equals 17',
    'ciphertext blob was 2790',
    'prime factor p = 61',
    'prime factor q = 53',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Raw / Textbook'), 'smart-decode did not route messy RSA labels');
  expect(output.includes('"decimal": "65"'), 'smart-decode RSA output missing plaintext');
});

await run('RSA accepts Chinese full labels, mixed case aliases, and fullwidth separators', async () => {
  const input = [
    '模数（N）：3233',
    '公钥指数（e）＝17',
    '密文（Cipher_Text）：2790',
    '质数 P：61',
    '质数 q：53',
  ].join('\n');
  const direct = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(direct.output.decimal, '65');

  const smart = await transform('smart-decode', 'decode', input, defaultParams);
  expect(smart.includes('RSA Raw / Textbook'), 'smart-decode did not route Chinese RSA labels');
  expect(smart.includes('"decimal": "65"'), 'smart-decode Chinese RSA output missing plaintext');
});

await run('RSA accepts pure Chinese parameter names without English aliases', async () => {
  const input = [
    '模数：3233',
    '公钥指数：17',
    '密文：2790',
    '第一质数：61',
    '第二质数：53',
  ].join('\n');
  const direct = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(direct.output.decimal, '65');

  const smart = await transform('smart-decode', 'decode', input, defaultParams);
  expect(smart.includes('RSA Raw / Textbook'), 'smart-decode did not route pure Chinese RSA labels');
  expect(smart.includes('"decimal": "65"'), 'smart-decode pure Chinese RSA output missing plaintext');
});

await run('smart-decode keeps Chinese RSA analysis ahead of embedded Base64-looking data', async () => {
  const input = [
    '加密算法：RSA',
    '提示：附件名为 ZmxhZ3tub3Rfcm91dGVkfQ==，不要把它当作待解密密文。',
    '模数：3233',
    '公钥指数：17',
    '密文：2790',
    '第一质数：61',
    '第二质数：53',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Raw / Textbook'), 'smart-decode extracted an unrelated Base64-looking field before RSA');
  expect(output.includes('"decimal": "65"'), 'smart-decode RSA result missing after embedded Base64-looking data');
});

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

await run('smart-decode falls back to RSA helper for messy public-key prose', async () => {
  const input = [
    'public key challenge',
    'modulus value is 3233',
    'public exponent equals 17',
    'known pair message 2 gives ciphertext 1752',
    'known pair message 42 gives ciphertext 2557',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA CTF Helper'), 'smart-decode did not fall back to RSA helper');
  expect(output.includes('"n": "3233"'), 'RSA helper output missing inferred modulus');
  expect(output.includes('"e": "17"'), 'RSA helper output missing inferred exponent');
});

await run('RSA single-quote pseudo-JSON fields are parsed', async () => {
  const input = "{'n': 3233, 'e': 17, 'c': 2790, 'p': 61, 'q': 53}";
  const output = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(output.output.decimal, '65');
});

await run('RSA p+q hint recovers factors', async () => {
  const input = [
    'n = 3233',
    'e = 17',
    'ciphertext = 2790',
    'p + q = 114',
  ].join('\n');
  const output = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(output.output.decimal, '65');
  expect(output.inference.some(note => note.includes('由 n 与 (p+q) 提示恢复 p')), 'RSA sum hint did not recover p');
  expect(output.inference.some(note => note.includes('由 n 与 (p+q) 提示恢复 q')), 'RSA sum hint did not recover q');
});

await run('RSA p-q hint recovers factors', async () => {
  const input = [
    'n = 3233',
    'e = 17',
    'ciphertext = 2790',
    'p - q = 8',
  ].join('\n');
  const output = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(output.output.decimal, '65');
  expect(output.inference.some(note => note.includes('由 n 与 |p-q| 提示恢复 p')), 'RSA diff hint did not recover p');
  expect(output.inference.some(note => note.includes('由 n 与 |p-q| 提示恢复 q')), 'RSA diff hint did not recover q');
});

await run('RSA arithmetic expressions n=p*q and phi=(p-1)*(q-1) are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'phi = (p-1)*(q-1)',
    'e = 17',
    'c = 2790',
  ].join('\n');
  const output = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(output.output.decimal, '65');
  assert.equal(output.modulus, '3233');
});

await run('RSA chained arithmetic references are evaluated from helper variables', async () => {
  const input = [
    'prime1 = 61',
    'prime2 = 53',
    'modulus = prime1 * prime2',
    'totient = (prime1 - 1) * (prime2 - 1)',
    'public exponent = 17',
    'ciphertext = 2790',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('RSA Raw / Textbook'), 'Chained arithmetic RSA was not routed to raw decrypt');
  expect(output.includes('"decimal": "65"'), 'Chained arithmetic RSA did not recover plaintext 65');
});

await run('RSA modular inverse helper expression d = pow(e, -1, phi) is evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'phi = (p-1)*(q-1)',
    'e = 17',
    'd = pow(e, -1, phi)',
    'c = 2790',
  ].join('\n');
  const output = JSON.parse(await transform('rsa-raw', 'decode', input, defaultParams));
  assert.equal(output.output.decimal, '65');
});

await run('RSA inverse(e, phi) helper expression is evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'phi = (p-1)*(q-1)',
    'e = 17',
    'd = inverse(e, phi)',
    'ciphertext = 2790',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'inverse(e, phi) RSA did not recover plaintext 65');
});

await run('RSA gmpy2.invert(e, phi) helper expression is evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'phi = (p-1)*(q-1)',
    'e = 17',
    'd = gmpy2.invert(e, phi)',
    'ciphertext = 2790',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'gmpy2.invert(e, phi) RSA did not recover plaintext 65');
});

await run('RSA bytes_to_long(...) and pow(m, e, n) script fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    "m = bytes_to_long(b'A')",
    'c = pow(m, e, n)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'bytes_to_long(...) RSA script did not recover plaintext 65');
});

await run('RSA int.from_bytes(...) script fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    "m = int.from_bytes(b'A', 'big')",
    'c = pow(m, e, n)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'int.from_bytes(...) RSA script did not recover plaintext 65');
});

await run('RSA int(hex_string, 16) helper expression is evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    "m = int('41', 16)",
    'c = pow(m, e, n)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'int(hex_string, 16) RSA script did not recover plaintext 65');
});

await run('RSA bytes.fromhex(hex(m)[2:]) writeup-style fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    'm = bytes_to_long(bytes.fromhex(hex(65)[2:]))',
    'c = pow(m, e, n)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'bytes.fromhex(hex(m)[2:]) RSA script did not recover plaintext 65');
});

await run('RSA binascii.unhexlify(...) helper fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    'm = bytes_to_long(binascii.unhexlify("41"))',
    'c = pow(m, e, n)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'binascii.unhexlify(...) RSA script did not recover plaintext 65');
});

await run('RSA Crypto.Util.number.bytes_to_long(...) fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    "m = Crypto.Util.number.bytes_to_long(b'A')",
    'c = pow(m, e, n)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'Crypto.Util.number.bytes_to_long(...) RSA script did not recover plaintext 65');
});

await run('RSA libnum.s2n(...) fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    "m = libnum.s2n('A')",
    'c = pow(m, e, n)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'libnum.s2n(...) RSA script did not recover plaintext 65');
});

await run('RSA single-line pow(bytes_to_long(flag), e, n) style fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    "c = pow(bytes_to_long(b'A'), e, n)",
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'pow(bytes_to_long(flag), e, n) style RSA fragment did not recover plaintext 65');
});

await run('RSA bytearray.fromhex(...) fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    "m = bytes_to_long(bytearray.fromhex('41'))",
    'c = pow(m, e, n)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'bytearray.fromhex(...) RSA script did not recover plaintext 65');
});

await run('RSA single-line pow(Crypto.Util.number.bytes_to_long(flag), e, n) fragments are evaluated', async () => {
  const input = [
    'p = 61',
    'q = 53',
    'n = p*q',
    'e = 17',
    "c = pow(Crypto.Util.number.bytes_to_long(b'A'), e, n)",
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'pow(Crypto.Util.number.bytes_to_long(flag), e, n) RSA fragment did not recover plaintext 65');
});

await run('RSA long_to_bytes(pow(c, d, n)) solve fragments are evaluated', async () => {
  const input = [
    'n = 3233',
    'e = 17',
    'p = 61',
    'q = 53',
    'c = 2790',
    'm = pow(c, pow(e, -1, (p-1)*(q-1)), n)',
    'decoded = long_to_bytes(m)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'long_to_bytes(pow(c, d, n)) RSA solve fragment did not recover plaintext 65');
});

await run('RSA libnum.n2s(pow(c, d, n)) solve fragments are evaluated', async () => {
  const input = [
    'n = 3233',
    'e = 17',
    'p = 61',
    'q = 53',
    'c = 2790',
    'decoded = libnum.n2s(pow(c, pow(e, -1, (p-1)*(q-1)), n))',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'libnum.n2s(pow(c, d, n)) RSA solve fragment did not recover plaintext 65');
});

await run('RSA bytes.fromhex(hex(pow(c, d, n))[2:]) solve fragments are evaluated', async () => {
  const input = [
    'n = 3233',
    'e = 17',
    'p = 61',
    'q = 53',
    'c = 2790',
    'decoded = bytes.fromhex(hex(pow(c, pow(e, -1, (p-1)*(q-1)), n))[2:])',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('"decimal": "65"'), 'bytes.fromhex(hex(pow(c, d, n))[2:]) RSA solve fragment did not recover plaintext 65');
});

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

await run('ECDSA nonce reuse works for dict-style records', async () => {
  const order = 101n;
  const privateKey = 11n;
  const nonce = 13n;
  const r = 17n;
  const z1 = 33n;
  const z2 = 44n;
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + r * privateKey) % order)) % order;
  const s2 = (nonceInverse * ((z2 + r * privateKey) % order)) % order;
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
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + r * privateKey) % order)) % order;
  const s2 = (nonceInverse * ((z2 + r * privateKey) % order)) % order;
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
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + r * privateKey) % order)) % order;
  const s2 = (nonceInverse * ((z2 + r * privateKey) % order)) % order;
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
  const digest1 = await digestForTest(msg1, 'sha256');
  const digest2 = await digestForTest(msg2, 'sha256');
  const z1 = digestHexToOrderInt(digest1, order);
  const z2 = digestHexToOrderInt(digest2, order);
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + r * privateKey) % order)) % order;
  const s2 = (nonceInverse * ((z2 + r * privateKey) % order)) % order;
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
  const digest1 = await digestForTest(msg1, 'sha256');
  const digest2 = await digestForTest(msg2, 'sha256');
  const z1 = digestHexToOrderInt(digest1, order);
  const z2 = digestHexToOrderInt(digest2, order);
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + r * privateKey) % order)) % order;
  const s2 = (nonceInverse * ((z2 + r * privateKey) % order)) % order;
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
  const digest1 = await digestForTest(msg1, 'sha256');
  const digest2 = await digestForTest(msg2, 'sha256');
  const z1 = digestHexToOrderInt(digest1, order);
  const z2 = digestHexToOrderInt(digest2, order);
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + r * privateKey) % order)) % order;
  const s2 = (nonceInverse * ((z2 + r * privateKey) % order)) % order;
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
  const rHex = '0000000000000000000000000000000000000000000000000000000000000011';
  const s1Hex = '0000000000000000000000000000000000000000000000000000000000000038';
  const s2Hex = '000000000000000000000000000000000000000000000000000000000000004f';
  const signature1 = Buffer.from(`${rHex}${s1Hex}`, 'hex').toString('base64url');
  const signature2 = Buffer.from(`${rHex}${s2Hex}`, 'hex').toString('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
  const payload1 = Buffer.from(JSON.stringify({ sub: 'alice', iat: 1 })).toString('base64url');
  const payload2 = Buffer.from(JSON.stringify({ sub: 'bob', iat: 2 })).toString('base64url');
  const token1 = `${header}.${payload1}.${signature1}`;
  const token2 = `${header}.${payload2}.${signature2}`;
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
  const rHex = '0000000000000000000000000000000000000000000000000000000000000011';
  const s1Hex = '0000000000000000000000000000000000000000000000000000000000000038';
  const s2Hex = '000000000000000000000000000000000000000000000000000000000000004f';
  const signature1 = Buffer.from(`${rHex}${s1Hex}`, 'hex').toString('base64url');
  const signature2 = Buffer.from(`${rHex}${s2Hex}`, 'hex').toString('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
  const payload1 = Buffer.from(JSON.stringify({ sub: 'alice', iat: 1 })).toString('base64url');
  const payload2 = Buffer.from(JSON.stringify({ sub: 'bob', iat: 2 })).toString('base64url');
  const token1 = `${header}.${payload1}.${signature1}`;
  const token2 = `${header}.${payload2}.${signature2}`;
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
  const rHex = '0000000000000000000000000000000000000000000000000000000000000011';
  const s1Hex = '0000000000000000000000000000000000000000000000000000000000000038';
  const s2Hex = '000000000000000000000000000000000000000000000000000000000000004f';
  const signature1 = Buffer.from(`${rHex}${s1Hex}`, 'hex').toString('base64url');
  const signature2 = Buffer.from(`${rHex}${s2Hex}`, 'hex').toString('base64url');
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
  const payload1 = Buffer.from(JSON.stringify({ sub: 'alice', iat: 1 })).toString('base64url');
  const payload2 = Buffer.from(JSON.stringify({ sub: 'bob', iat: 2 })).toString('base64url');
  const token1 = `${header}.${payload1}.${signature1}`;
  const token2 = `${header}.${payload2}.${signature2}`;
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
  const digest1 = await digestForTest(msg1, 'sha256');
  const digest2 = await digestForTest(msg2, 'sha256');
  const z1 = digestHexToOrderInt(digest1, order);
  const z2 = digestHexToOrderInt(digest2, order);
  const nonceInverse = modInverse(nonce, order);
  const s1 = (nonceInverse * ((z1 + r * privateKey) % order)) % order;
  const s2 = (nonceInverse * ((z2 + r * privateKey) % order)) % order;
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

await run('Smart symmetric decrypt recognizes Python AES-GCM decrypt_and_verify snippet', async () => {
  const input = [
    'from Crypto.Cipher import AES',
    'from base64 import b64decode',
    'key = b"0123456789abcdef0123456789abcdef"',
    'nonce = b"nonce-123456"',
    'ct = "UhDY+otytryRUdUh4IwWFS7z"',
    'tag = "6U2CkX2sw/CwlB0QbrDO+w=="',
    'cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)',
    'pt = cipher.decrypt_and_verify(b64decode(ct), b64decode(tag))',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('aes-gcm'), 'Python AES-GCM snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{aes_gcm_demo}'), 'Python AES-GCM snippet did not recover plaintext');
});

await run('Smart XOR decrypt recognizes Python xor(...) snippet', async () => {
  const input = [
    'from pwn import xor',
    'ct = bytes.fromhex("27292e2c307d")',
    'key = b"ABC"',
    'pt = xor(ct, key)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('python-xor-call'), 'Python xor(...) snippet was not routed to XOR script analysis');
  expect(output.includes('"plaintextHex": "666b6d6d723e"'), 'Python xor(...) snippet did not preserve decoded XOR plaintext');
});

await run('Smart XOR decrypt recognizes Python bytes([...]) / bytearray([...]) snippet', async () => {
  const input = [
    'from pwn import xor',
    'ct = bytes([0x27,0x29,0x2e,0x2c,0x30,0x7d])',
    'key = bytearray([0x41,0x42,0x43])',
    'pt = xor(ct, key)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('python-xor-call'), 'Python bytes([...]) xor snippet was not routed to XOR script analysis');
  expect(output.includes('"plaintextHex": "666b6d6d723e"'), 'Python bytes([...]) xor snippet did not preserve decoded XOR plaintext');
});

await run('Smart symmetric decrypt recognizes Python AES-ECB snippet with b64decode/unpad', async () => {
  const input = [
    'from Crypto.Cipher import AES',
    'from base64 import b64decode',
    'from Crypto.Util.Padding import unpad',
    'key = b"0123456789abcdef"',
    'ct = "o/mMq0AvRyonhFU59nCej+2IRZHgo59CM9yLVYPXv+4="',
    'cipher = AES.new(key, AES.MODE_ECB)',
    'pt = unpad(cipher.decrypt(b64decode(ct)), 16)',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('aes-ecb'), 'Python AES-ECB snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{aes_ecb_demo}'), 'Python AES-ECB snippet did not recover plaintext');
});

await run('Smart symmetric decrypt recognizes Python AES-CTR snippet', async () => {
  const input = [
    'from Crypto.Cipher import AES',
    'from base64 import b64decode',
    'key = b"0123456789abcdef"',
    'nonce = b"nonceCTR"',
    'ct = "mAZXWQVW6Or828VnG+vWTpZm"',
    'cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)',
    'pt = cipher.decrypt(b64decode(ct))',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('aes-ctr-raw'), 'Python AES-CTR snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{aes_ctr_demo}'), 'Python AES-CTR snippet did not recover plaintext');
});

await run('Smart symmetric decrypt recognizes Python ChaCha20 snippet', async () => {
  const input = [
    'from base64 import b64decode',
    'from Crypto.Cipher import ChaCha20',
    'key = b"0123456789abcdef0123456789abcdef"',
    'nonce = b"12345678"',
    'ct = "BAjkRRoogKzqPb6ERGO194Y1XQ=="',
    'cipher = ChaCha20.new(key=key, nonce=nonce)',
    'pt = cipher.decrypt(b64decode(ct))',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('chacha20-orig'), 'Python ChaCha20 snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{chacha20_demo}'), 'Python ChaCha20 snippet did not recover plaintext');
});

await run('Smart symmetric decrypt recognizes Python Salsa20 snippet', async () => {
  const input = [
    'from base64 import b64decode',
    'from Crypto.Cipher import Salsa20',
    'key = b"0123456789abcdef0123456789abcdef"',
    'nonce = b"12345678"',
    'ct = "QXgBBCyBjVx1cVFvuEN0fxSs"',
    'cipher = Salsa20.new(key=key, nonce=nonce)',
    'pt = cipher.decrypt(b64decode(ct))',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('salsa20'), 'Python Salsa20 snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{salsa20_demo}'), 'Python Salsa20 snippet did not recover plaintext');
});

await run('Smart symmetric decrypt recognizes Python ChaCha20-Poly1305 snippet', async () => {
  const input = [
    'from base64 import b64decode',
    'from Crypto.Cipher import ChaCha20_Poly1305',
    'key = b"0123456789abcdef0123456789abcdef"',
    'nonce = b"123456789012"',
    'ct = "KLBIlbEfVt6NJixRk+nWktmXXXvKW9s/2rcDWA=="',
    'tag = "XVCGxEXuSrm0hhPMpUQpzA=="',
    'cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)',
    'pt = cipher.decrypt_and_verify(b64decode(ct), b64decode(tag))',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('chacha20-poly1305'), 'Python ChaCha20-Poly1305 snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{chacha20_poly1305_demo}'), 'Python ChaCha20-Poly1305 snippet did not recover plaintext');
});

await run('Smart symmetric decrypt recognizes Python AES-CFB snippet', async () => {
  const input = [
    'from base64 import b64decode',
    'from Crypto.Cipher import AES',
    'key = b"0123456789abcdef"',
    'iv = b"abcdef0123456789"',
    'ct = "afeI8+qqRKG/Iclxv2iE+sJk"',
    'cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)',
    'pt = cipher.decrypt(b64decode(ct))',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('aes-cfb'), 'Python AES-CFB snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{aes_cfb_demo}'), 'Python AES-CFB snippet did not recover plaintext');
});

await run('Smart symmetric decrypt recognizes Python AES-OFB snippet', async () => {
  const input = [
    'from base64 import b64decode',
    'from Crypto.Cipher import AES',
    'key = b"0123456789abcdef"',
    'iv = b"abcdef0123456789"',
    'ct = "afeI8+qqRKG/Lclxv2iE+rhV"',
    'cipher = AES.new(key, AES.MODE_OFB, iv=iv)',
    'pt = cipher.decrypt(b64decode(ct))',
  ].join('\n');
  const output = await transform('smart-decode', 'decode', input, defaultParams);
  expect(output.includes('aes-ofb'), 'Python AES-OFB snippet was not routed to smart symmetric decrypt');
  expect(output.includes('flag{aes_ofb_demo}'), 'Python AES-OFB snippet did not recover plaintext');
});

console.log(`\nVerified ${results.length} EncodingTools regression checks.`);
