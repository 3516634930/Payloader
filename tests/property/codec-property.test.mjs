// T7 fast-check 属性测试：四个高性价比域的任意输入 round-trip / 互逆 / 交叉对拍。
// 域①math 纯数学互逆 ②bases 族 round-trip ③tokens otpauth-uri/JWT 结构互逆 ④crc 与 node:zlib 对拍。
// runCount 压在 100 控制 CI 时长（fc.configureGlobal）。
import assert from 'node:assert/strict';
import test from 'node:test';
import zlib from 'node:zlib';
import fc from 'fast-check';
import { createTsModuleLoader } from '../helpers/compileTsModule.mjs';

fc.configureGlobal({ numRuns: 100 });

const { loadModule } = createTsModuleLoader();
const math = loadModule('src/utils/codec/math.ts');
const bases = loadModule('src/utils/codec/bases.ts');
const { crc32, crc16, adler32 } = loadModule('src/utils/codec/textEncodings.ts');
const tokens = loadModule('src/utils/codec/tokens.ts');

// 可打印 ASCII 文本域：bases 族编码器面向文本，任意 Unicode 的直解域各有专属形状约束，
// 不在本轮属性范围（批次 T7 聚焦任意字节/常见文本的 round-trip 保真）。
const asciiText = fc.string({ minLength: 1, maxLength: 128 }).filter(v => /^[\x20-\x7e]+$/.test(v));
const bytesDomain = fc.uint8Array({ minLength: 1, maxLength: 256 });
// 小素数池：modInverse 属性需要可逆模（素数模下任意非零元可逆）。
const SMALL_PRIMES = [1013n, 1019n, 1021n, 1033n, 1049n, 1051n, 1061n, 1063n, 5003n, 5009n, 7919n, 10007n];

test('property: math modInverse × modPow are inverse operations over prime fields', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.constantFrom(...SMALL_PRIMES),
      fc.bigInt({ min: 2n, max: 10000n }),
      fc.bigInt({ min: 1n, max: 999999n }),
      async (prime, aSeed, exponent) => {
        const base = aSeed % prime;
        fc.pre(base !== 0n, '逆元定义在非零元');
        const inverse = math.bigintModInverse(base, prime);
        assert.ok(inverse !== null, '素数域内元素必有逆元');
        assert.equal((base * inverse) % prime, 1n, 'a·a⁻¹ ≡ 1 (mod p)');
        // 幂的互逆：(a^e)·(a⁻¹)^e ≡ 1 (mod p)
        const powA = math.bigintModPow(base, exponent % prime, prime);
        const powInv = math.bigintModPow(inverse, exponent % prime, prime);
        assert.equal((powA * powInv) % prime, 1n, '(a^e)·(a⁻¹)^e ≡ 1 (mod p)');
      },
    ),
  );
});

test('property: math bigIntSqrt squares back and bounds the true root', async () => {
  await fc.assert(
    fc.property(fc.bigInt({ min: 0n, max: 10n ** 24n }), k => {
      // 完全平方回代
      assert.equal(math.bigIntSqrt(k * k), k, '√(k²) === k');
      // 任意 n：s² ≤ n < (s+1)²（下取整平方根的定义性质）
      const s = math.bigIntSqrt(k);
      assert.ok(s * s <= k, 's² ≤ n');
      assert.ok(k < (s + 1n) * (s + 1n), 'n < (s+1)²');
    }),
  );
});

test('property: math crtCombinePair reconstructs the simultaneous congruence', async () => {
  await fc.assert(
    fc.property(
      fc.constantFrom(...SMALL_PRIMES),
      fc.constantFrom(...SMALL_PRIMES),
      fc.bigInt({ min: 0n, max: 100000n }),
      fc.bigInt({ min: 0n, max: 100000n }),
      (m1, m2, a1Seed, a2Seed) => {
        fc.pre(m1 !== m2, '互质模对');
        const a1 = a1Seed % m1;
        const a2 = a2Seed % m2;
        const combined = math.crtCombinePair(a1, m1, a2, m2);
        assert.equal(combined % m1, a1 % m1, 'x ≡ a1 (mod m1)');
        assert.equal(combined % m2, a2 % m2, 'x ≡ a2 (mod m2)');
      },
    ),
  );
});

test('property: bases round-trip arbitrary bytes and ascii text losslessly', async () => {
  await fc.assert(
    fc.property(bytesDomain, bytes => {
      // base64 / base58 提供字节级接口：任意 1-256 字节必须无损
      assert.deepEqual(bases.base64ToBytes(bases.bytesToBase64(bytes)), bytes, 'base64 bytes round-trip');
      assert.deepEqual(bases.decodeBase58Bytes(bases.encodeBase58Bytes(bytes)), bytes, 'base58 bytes round-trip');
    }),
  );
  await fc.assert(
    fc.property(asciiText, text => {
      assert.equal(bases.decodeBase32(bases.encodeBase32(text)), text, 'base32 round-trip');
      assert.equal(bases.decodeBase91(bases.encodeBase91(text)), text, 'base91 round-trip');
      assert.equal(bases.decodeAscii85(bases.encodeAscii85(text)), text, 'ascii85 round-trip');
      assert.equal(bases.decodeBase62(bases.encodeBase62(text)), text, 'base62 round-trip');
      // bech32 的文本通道在其 charset 域内无损（空格/符号有损是其规范外行为），故限定域采样
      // 以非 hex 字符 'z' 收尾，避开 encodeBech32 对偶数长纯 hex 文本的 hex 字节语义（既有设计）
      const bech32Sample = text.replace(/[^a-zA-Z0-9]/g, '').slice(0, 63) + 'z';
      const bech32 = JSON.parse(bases.decodeBech32(bases.encodeBech32(bech32Sample, 'ctf', 'bech32')));
      assert.equal(bech32.checksumValid, true, 'bech32 校验和有效');
      assert.equal(bech32.dataText, bech32Sample, 'bech32 round-trip');
    }),
  );
});

test('property: tokens otpauth-uri and JWT structures round-trip', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.tuple(fc.constantFrom('CTF', 'demo', 'acme corp'), fc.constantFrom('alice', 'bob.2', 'user_3')),
      fc.constantFrom('6', '8'),
      async ([issuer, account], digits) => {
        const label = `${issuer}:${account}`;
        const uri = tokens.encodeOtpAuthUri(label, {
          secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
          counter: '0',
          digits,
          hashAlgorithm: 'sha1',
          variant: 'hex',
        });
        const parsed = JSON.parse(await tokens.decodeOtpAuthUri(uri));
        assert.equal(parsed.type, 'hotp', 'otpauth 往返保持 hotp 类型');
        assert.equal(parsed.issuer, issuer, 'otpauth 往返保持 issuer');
        assert.equal(String(parsed.digits), digits, 'otpauth 往返保持位数');
        assert.match(parsed.currentCode, /^\d{6}$|^\d{8}$/, 'otpauth 产出合法位数验证码');
      },
    ),
  );
  await fc.assert(
    fc.asyncProperty(
      fc.record({
        sub: fc.constantFrom('user-1', 'user-2'),
        name: fc.constantFrom('Alice', 'Bob Chen'),
        iat: fc.integer({ min: 0, max: 2 ** 31 - 1 }),
      }),
      fc.constantFrom('secret-a', 'your-256-bit-secret'),
      async (payloadRecord, secret) => {
        // fc.record 产出 null 原型对象：deepStrictEqual 对原型敏感，展开为普通对象再断言
        const payload = { ...payloadRecord };
        const signed = JSON.parse(
          await tokens.jwtHmacTransform('encode', JSON.stringify({ header: { alg: 'HS256' }, payload }), { secret }),
        ).token;
        const verified = JSON.parse(await tokens.jwtHmacTransform('decode', signed, { secret }));
        assert.equal(verified.valid, true, 'JWT 签名往返必须有效');
        assert.deepEqual(verified.payload, payload, 'JWT payload 无损往返');
        // 篡改签名首字符必须失效：末字符带未用低位 bit，末位替换可能解码出完全相同的签名字节
        const [jwtHeader, jwtPayload, jwtSignature] = signed.split('.');
        const tampered = `${jwtHeader}.${jwtPayload}.${jwtSignature[0] === 'A' ? 'B' : 'A'}${jwtSignature.slice(1)}`;
        const bad = JSON.parse(await tokens.jwtHmacTransform('decode', tampered, { secret }));
        assert.equal(bad.valid, false, '被篡改的 JWT 必须判定无效');
      },
    ),
  );
});

test('property: crc32 matches node:zlib on arbitrary input, crc16/adler32 hold reference vectors', async () => {
  await fc.assert(
    fc.property(fc.string({ minLength: 0, maxLength: 512 }), text => {
      const expected = zlib.crc32(Buffer.from(text, 'utf8')).toString(16).padStart(8, '0');
      assert.equal(crc32(text), expected, `crc32 与 node:zlib 对拍不符: ${JSON.stringify(text.slice(0, 32))}`);
    }),
  );
  // 标准校验向量（CRC-32 与 Adler-32 的 "123456789"/"Wikipedia" 权威值；crc16 为 CCITT-FALSE 变体）
  assert.equal(crc32('123456789'), 'cbf43926', 'CRC-32 标准向量');
  assert.equal(crc16('123456789'), '4b37', 'CRC-16/CCITT-FALSE 标准向量');
  assert.equal(adler32('Wikipedia'), '11e60398', 'Adler-32 标准向量');
});
