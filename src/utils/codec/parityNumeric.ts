// 批次 O Lane E：进制/工具类 13 操作（parityNumeric）。
// 全部纯计算：零动态代码执行、零联网、零新依赖；算法定义与来源以区块注释写在各实现之前。
import type { Direction, Operation, OperationId, ParamKey } from './types';
import type { ParityShapeProbe, ParityVector } from './parityTypes';

// ==================== ieee754 ====================
// 算法定义：IEEE 754 二进制浮点 = 1 符号位 + 指数域 + 尾数域（float32=1+8+23、float64=1+11+52），
// 用 DataView 以大端序在十进制数与位模式之间互转；解码接受 hex（float32 为 8 字符、float64 为 16 字符）
// 或等长 0/1 二进制位串，编码接受十进制数与 NaN/±Infinity。
// 来源：IEEE 754-2019 规范（https://en.wikipedia.org/wiki/IEEE_754）。

interface IeeeShape { totalBits: number; hexChars: number }

const IEEE_SHAPES: Record<string, IeeeShape> = {
  float32: { totalBits: 32, hexChars: 8 },
  float64: { totalBits: 64, hexChars: 16 },
};

const pickIeeeShape = (variant: string): IeeeShape => IEEE_SHAPES[variant === 'float32' ? 'float32' : 'float64'];

const bytesToHexText = (bytes: Uint8Array): string => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

const parseIeeeSpecial = (text: string): number | null => {
  const lower = text.trim().toLowerCase();
  if (lower === 'nan') return Number.NaN;
  if (lower === 'inf' || lower === '+inf' || lower === 'infinity' || lower === '+infinity') return Number.POSITIVE_INFINITY;
  if (lower === '-inf' || lower === '-infinity') return Number.NEGATIVE_INFINITY;
  return null;
};

const ieee754Encode = (input: string, variant: string): string => {
  const shape = pickIeeeShape(variant);
  const special = parseIeeeSpecial(input);
  const value = special !== null ? special : Number(input.trim());
  if (Number.isNaN(value) && special === null) {
    throw new Error(`无法把「${input.trim()}」解析为数字：ieee754 编码接受十进制数与 NaN/±Infinity。`);
  }
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  if (shape.totalBits === 32) view.setFloat32(0, value, false);
  else view.setFloat64(0, value, false);
  return bytesToHexText(new Uint8Array(buffer, 0, shape.totalBits / 8));
};

const ieee754Decode = (input: string, variant: string): string => {
  const shape = pickIeeeShape(variant);
  const compact = input.replace(/\s+/g, '').replace(/^0x/i, '');
  const isBinary = /^[01]+$/.test(compact);
  const isHex = /^[0-9a-f]+$/i.test(compact);
  if (!isBinary && !isHex) {
    throw new Error('IEEE754 位模式只能包含 hex 字符或 0/1 二进制位（0x 前缀与空白会自动忽略）。');
  }
  const expected = isBinary ? shape.totalBits : shape.hexChars;
  if (compact.length !== expected) {
    const label = shape.totalBits === 32 ? 'float32' : 'float64';
    throw new Error(`IEEE754 ${label} 位模式需要 ${expected} 个${isBinary ? '二进制位' : 'hex 字符'}，实际输入 ${compact.length} 个。`);
  }
  const bytes = new Uint8Array(shape.totalBits / 8);
  if (isBinary) {
    for (let index = 0; index < compact.length; index += 1) {
      bytes[index >> 3] = (bytes[index >> 3] << 1) | (compact[index] === '1' ? 1 : 0);
    }
  } else {
    for (let index = 0; index < compact.length; index += 2) bytes[index >> 1] = Number.parseInt(compact.slice(index, index + 2), 16);
  }
  const view = new DataView(bytes.buffer);
  const value = shape.totalBits === 32 ? view.getFloat32(0, false) : view.getFloat64(0, false);
  if (Number.isNaN(value)) return 'NaN';
  if (value === Number.POSITIVE_INFINITY) return 'Infinity';
  if (value === Number.NEGATIVE_INFINITY) return '-Infinity';
  return String(value);
};

// ==================== twos-complement / ones-complement ====================
// 算法定义：w 位补码把整数 v 表示为 (2^w + v) mod 2^w 的位型；w 位反码把负数 v 表示为
// (2^w - 1 + v) 的位型（绝对值按位取反）。解码按最高位区分符号；超出位宽的输入按位宽回绕。
// 来源：https://en.wikipedia.org/wiki/Two%27s_complement 、 https://en.wikipedia.org/wiki/Ones%27_complement

const pickWidth = (variant: string): number => (variant === '16' ? 16 : variant === '32' ? 32 : 8);

const parseSignedDecimal = (text: string, label: string): bigint => {
  const trimmed = text.trim();
  if (!/^[+-]?\d+$/.test(trimmed)) throw new Error(`「${trimmed}」不是合法的十进制整数，无法做${label}。`);
  return BigInt(trimmed);
};

const wrapSignedBits = (input: string, variant: string, label: string): { width: number; wrapped: bigint } => {
  const width = pickWidth(variant);
  const value = parseSignedDecimal(input, label);
  const modulus = 1n << BigInt(width);
  return { width, wrapped: ((value % modulus) + modulus) % modulus };
};

const twosComplementEncode = (input: string, variant: string): string => {
  const { width, wrapped } = wrapSignedBits(input, variant, '补码编码');
  return wrapped.toString(2).padStart(width, '0');
};

const twosComplementDecode = (input: string, variant: string): string => {
  const width = pickWidth(variant);
  const bits = input.replace(/\s+/g, '');
  if (!/^[01]+$/.test(bits)) throw new Error('补码解码输入只能包含 0/1（空白会自动忽略）。');
  if (bits.length > width) throw new Error(`位宽不匹配：variant 位宽为 ${width} 位，输入有 ${bits.length} 位。`);
  const padded = bits.padStart(width, '0');
  const unsigned = BigInt(`0b${padded}`);
  const signed = unsigned >= (1n << BigInt(width - 1)) ? unsigned - (1n << BigInt(width)) : unsigned;
  return signed.toString();
};

const onesComplementEncode = (input: string, variant: string): string => {
  const { width, wrapped } = wrapSignedBits(input, variant, '反码编码');
  const modulus = 1n << BigInt(width);
  const pattern = wrapped < (modulus >> 1n) ? wrapped : wrapped - 1n;
  return pattern.toString(2).padStart(width, '0');
};

const onesComplementDecode = (input: string, variant: string): string => {
  const width = pickWidth(variant);
  const bits = input.replace(/\s+/g, '');
  if (!/^[01]+$/.test(bits)) throw new Error('反码解码输入只能包含 0/1（空白会自动忽略）。');
  if (bits.length > width) throw new Error(`位宽不匹配：variant 位宽为 ${width} 位，输入有 ${bits.length} 位。`);
  const padded = bits.padStart(width, '0');
  const unsigned = BigInt(`0b${padded}`);
  const mask = (1n << BigInt(width)) - 1n;
  return (padded[0] === '1' ? unsigned - mask : unsigned).toString();
};

// ==================== radix-xor ====================
// 算法定义：把输入按空白/逗号切成的数值 token（variant 指定进制 2/8/10/16）逐个与密钥 token
// 做 BigInt 异或，密钥按 token 位置循环，结果以同一进制输出；XOR 自逆，编解码为同一函数。
// 来源：XOR 加密定义（https://en.wikipedia.org/wiki/XOR_cipher），数值手算可验证。

const RADIX_PATTERNS: Record<number, RegExp> = {
  2: /^[01]+$/,
  8: /^[0-7]+$/,
  10: /^\d+$/,
  16: /^[0-9a-f]+$/i,
};

const pickRadix = (variant: string): number => (variant === '2' || variant === '8' || variant === '10' ? Number(variant) : 16);

const parseRadixToken = (token: string, radix: number): bigint => {
  if (!RADIX_PATTERNS[radix].test(token)) throw new Error(`「${token}」不是合法的 ${radix} 进制数值。`);
  if (radix === 10) return BigInt(token);
  const prefixes: Record<number, string> = { 2: '0b', 8: '0o', 16: '0x' };
  return BigInt(`${prefixes[radix]}${token}`);
};

const splitValueTokens = (value: string): string[] => value.trim().split(/[\s,，]+/).filter(Boolean);

const radixXorCompute = (input: string, variant: string, secret: string): string => {
  const radix = pickRadix(variant);
  const keyTokens = splitValueTokens(secret);
  if (!keyTokens.length) throw new Error('缺少密钥：radix-xor 需要同进制的密钥值（多个密钥值用空格分隔，按 token 位置循环）。');
  const keys = keyTokens.map(token => parseRadixToken(token, radix));
  const tokens = splitValueTokens(input);
  // 输出按输入 token 的位数补零，保持同进制排版稳定（XOR 自逆 ⇒ round-trip 一致）。
  return tokens.map((token, index) => (parseRadixToken(token, radix) ^ keys[index % keys.length]).toString(radix).padStart(token.length, '0')).join(' ');
};

// ==================== bit-split ====================
// 算法定义：把 0/1 位串按固定宽度（variant 2/3/4/7）切分成多行，每行一位组；解码忽略全部
// 空白（含换行）拼接还原。来源：随波逐流「位分割」工具语义（进制转换类通用做法）。

const pickSplitWidth = (variant: string): number => {
  if (variant === '3' || variant === '4' || variant === '7') return Number(variant);
  return 2;
};

const requireBitString = (input: string, label: string): string => {
  const bits = input.replace(/\s+/g, '');
  if (!bits || !/^[01]+$/.test(bits)) throw new Error(`位分割${label}输入必须是 0/1 位串（空白会自动忽略）。`);
  return bits;
};

const bitSplitEncode = (input: string, variant: string): string => {
  const bits = requireBitString(input, '编码');
  const width = pickSplitWidth(variant);
  const rows: string[] = [];
  for (let position = 0; position < bits.length; position += width) rows.push(bits.slice(position, position + width));
  return rows.join('\n');
};

const bitSplitDecode = (input: string): string => requireBitString(input, '解码');

// ==================== hamming ====================
// 算法定义：Hamming(7,4) 把 4 个数据位 d1-d4 放在码字第 3/5/6/7 位，第 1/2/4 位为偶校验位
// p1=d1⊕d2⊕d4、p2=d1⊕d3⊕d4、p4=d2⊕d3⊕d4；解码计算三位 syndrome（s4s2s1 二进制值即出错
// 位置，0 表示无错），翻转该位并抽取数据位，纠错时在结果后附报告行。
// 来源：https://en.wikipedia.org/wiki/Hamming(7,4)

const hammingEncode = (input: string): string => {
  const bits = input.replace(/\s+/g, '');
  if (!/^[01]{4}$/.test(bits)) throw new Error('海明码编码输入必须是 4 个 0/1 数据位（空白会自动忽略）。');
  const d1 = Number(bits[0]);
  const d2 = Number(bits[1]);
  const d3 = Number(bits[2]);
  const d4 = Number(bits[3]);
  const p1 = d1 ^ d2 ^ d4;
  const p2 = d1 ^ d3 ^ d4;
  const p4 = d2 ^ d3 ^ d4;
  return `${p1}${p2}${d1}${p4}${d2}${d3}${d4}`;
};

const hammingDecode = (input: string): string => {
  const bits = input.replace(/\s+/g, '');
  if (!/^[01]{7}$/.test(bits)) throw new Error('海明码解码输入必须是 7 个 0/1 码字位（空白会自动忽略）。');
  const b = Array.from(bits, char => Number(char));
  const s1 = b[0] ^ b[2] ^ b[4] ^ b[6];
  const s2 = b[1] ^ b[2] ^ b[5] ^ b[6];
  const s4 = b[3] ^ b[4] ^ b[5] ^ b[6];
  const syndrome = (s4 << 2) | (s2 << 1) | s1;
  const corrected = [...bits];
  if (syndrome) corrected[syndrome - 1] = corrected[syndrome - 1] === '1' ? '0' : '1';
  const data = `${corrected[2]}${corrected[4]}${corrected[5]}${corrected[6]}`;
  return syndrome ? `${data}\n纠错：第 ${syndrome} 位已纠正` : data;
};

// ==================== qwe-keyboard ====================
// 算法定义：键盘序映射 QWERTYUIOPASDFGHJKLZXCVBNM 逐位对应 ABCDEFGHIJKLMNOPQRSTUVWXYZ，
// 是 26 字母上的双射（非对合）：编码 QWE→ABC，解码取逆映射 ABC→QWE；保留大小写，非字母原样保留。
// 来源：https://www.dcode.fr/qwerty-abc-cipher

const QWE_ROW = 'QWERTYUIOPASDFGHJKLZXCVBNM';
const ALPHA_ROW = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const qweToAlpha = new Map(Array.from(QWE_ROW, (char, index) => [char, ALPHA_ROW[index]]));
const alphaToQwe = new Map(Array.from(ALPHA_ROW, (char, index) => [char, QWE_ROW[index]]));

const qweKeyboardMap = (input: string, table: Map<string, string>): string => {
  let output = '';
  for (const char of input) {
    const mapped = table.get(char.toUpperCase());
    output += mapped !== undefined ? (char >= 'A' && char <= 'Z' ? mapped : mapped.toLowerCase()) : char;
  }
  return output;
};

const qweKeyboardEncode = (input: string): string => qweKeyboardMap(input, qweToAlpha);
const qweKeyboardDecode = (input: string): string => qweKeyboardMap(input, alphaToQwe);

// ==================== gcd / prime-factor ====================
// 算法定义：gcd 用辗转相除法（欧几里得算法）gcd(a,b)=gcd(b,a mod b)；
// 素数分解先试除小素数，再用 Miller-Rabin 素性检测（确定性底数组，覆盖 <2^70）与
// Pollard rho（f(x)=x²+c，Floyd 判环）递归拆分，输入上限 2^70。
// 来源：https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm 、 https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

const gcdBig = (a: bigint, b: bigint): bigint => {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) {
    const rest = x % y;
    x = y;
    y = rest;
  }
  return x;
};

const gcdCompute = (input: string): string => {
  const numbers = input.match(/-?\d+/g);
  if (!numbers || numbers.length < 2) throw new Error('GCD 需要输入两个整数（用空格/逗号分隔，支持任意大整数）。');
  return gcdBig(BigInt(numbers[0]), BigInt(numbers[1])).toString();
};

const PRIME_FACTOR_LIMIT = 1n << 70n;
const MR_BASES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

const modPowBig = (base: bigint, exponent: bigint, modulus: bigint): bigint => {
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

const isProbablePrime = (n: bigint): boolean => {
  if (n < 2n) return false;
  for (const small of MR_BASES) {
    if (n % small === 0n) return n === small;
  }
  let d = n - 1n;
  let rounds = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    rounds += 1n;
  }
  for (const base of MR_BASES) {
    let x = modPowBig(base, d, n);
    if (x === 1n || x === n - 1n) continue;
    let probablyPrime = false;
    for (let round = 1n; round < rounds; round += 1n) {
      x = (x * x) % n;
      if (x === n - 1n) {
        probablyPrime = true;
        break;
      }
    }
    if (!probablyPrime) return false;
  }
  return true;
};

const pollardRho = (n: bigint): bigint => {
  if (n % 2n === 0n) return 2n;
  for (let c = 1n; ; c += 1n) {
    let x = 2n;
    let y = 2n;
    let divisor = 1n;
    while (divisor === 1n) {
      x = (x * x + c) % n;
      y = (y * y + c) % n;
      y = (y * y + c) % n;
      divisor = gcdBig(x > y ? x - y : y - x, n);
    }
    if (divisor !== n) return divisor;
  }
};

const factorBigInt = (n: bigint, factors: bigint[]): void => {
  if (n === 1n) return;
  if (isProbablePrime(n)) {
    factors.push(n);
    return;
  }
  const divisor = pollardRho(n);
  factorBigInt(divisor, factors);
  factorBigInt(n / divisor, factors);
};

const primeFactorCompute = (input: string): string => {
  const match = input.match(/-?\d+/);
  if (!match) throw new Error('素数分解需要一个整数输入（支持大整数，上限 2^70）。');
  let n = BigInt(match[0]);
  if (n < 0n) n = -n;
  if (n < 2n) throw new Error('素数分解需要 ≥2 的整数。');
  if (n > PRIME_FACTOR_LIMIT) throw new Error('输入超过素数分解上限 2^70，请先缩小数值。');
  const factors: bigint[] = [];
  for (const small of [2n, 3n, 5n]) {
    while (n % small === 0n) {
      factors.push(small);
      n /= small;
    }
  }
  factorBigInt(n, factors);
  factors.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const groups: string[] = [];
  for (let index = 0; index < factors.length;) {
    let end = index;
    while (end < factors.length && factors[end] === factors[index]) end += 1;
    const count = end - index;
    groups.push(count === 1 ? factors[index].toString() : `${factors[index]}^${count}`);
    index = end;
  }
  return groups.join(' × ');
};

// ==================== fibonacci-code ====================
// 算法定义：Fibonacci coding（Zeckendorf 表示，斐波那契数列 1,2,3,5,8…）：把整数写成不重复
// 相邻斐波那契数之和，系数位按 LSB（F2）在前排列，末尾追加 1 形成「11」终止符；解码按
// 终止符切分逐码字还原。来源：https://en.wikipedia.org/wiki/Fibonacci_coding

const fibEncodeOne = (value: bigint): string => {
  if (value < 1n) throw new Error('斐波那契编码只支持 ≥1 的整数（0 没有 Zeckendorf 表示）。');
  const fibs: bigint[] = [1n, 2n];
  while (fibs[fibs.length - 1] <= value) fibs.push(fibs[fibs.length - 1] + fibs[fibs.length - 2]);
  const usable = fibs.slice(0, -1);
  const digits: number[] = new Array(usable.length).fill(0);
  let rest = value;
  for (let index = usable.length - 1; index >= 0; index -= 1) {
    if (rest >= usable[index]) {
      digits[index] = 1;
      rest -= usable[index];
    }
  }
  return `${digits.join('')}1`;
};

const fibEncode = (input: string): string => {
  const tokens = input.trim().split(/[\s,，、]+/).filter(Boolean);
  if (!tokens.length) throw new Error('斐波那契编码需要至少一个整数。');
  return tokens.map(token => {
    if (!/^\d+$/.test(token)) throw new Error(`「${token}」不是非负十进制整数，无法做斐波那契编码。`);
    return fibEncodeOne(BigInt(token));
  }).join('');
};

const fibDecode = (input: string): string => {
  const bits = input.replace(/\s+/g, '');
  if (!bits) throw new Error('斐波那契解码输入不能为空。');
  if (!/^[01]+$/.test(bits)) throw new Error('斐波那契码只能包含 0/1（空白会自动忽略）。');
  const fibs: bigint[] = [1n, 2n];
  const values: bigint[] = [];
  let accumulator = '';
  for (const bit of bits) {
    accumulator += bit;
    if (accumulator.length >= 2 && accumulator.endsWith('11')) {
      const digits = accumulator.slice(0, -1);
      while (fibs.length < digits.length) fibs.push(fibs[fibs.length - 1] + fibs[fibs.length - 2]);
      let value = 0n;
      for (let index = 0; index < digits.length; index += 1) {
        if (digits[index] === '1') value += fibs[index];
      }
      values.push(value);
      accumulator = '';
    }
  }
  if (accumulator) throw new Error('斐波那契比特流缺少 11 终止符（或尾部不完整），无法完成解码。');
  return values.map(value => value.toString()).join(' ');
};

// ==================== pickle-parse ====================
// 算法定义：手写 pickle 协议 0-5 基础 opcode 栈状态机（绝无代码执行）：MARK 栈切片构造
// 列表/元组/字典，BININT*/LONG*/BINFLOAT 读定长字段，STRING/BINUNICODE 读长度前缀字节，
// MEMO/PUT/GET/BINGET 备忘录共享引用，FRAME/PROTO 跳过；GLOBAL/REDUCE/NEWOBJ 等涉及
// 代码执行的 opcode 一律拒绝。输出为 Python 字面量风格稳定文本（单引号字符串、[列表]、
// (元组,)、{键: 值}、b'字节串'）。来源：https://docs.python.org/3/library/pickletools.html

type PickleValue =
  | { t: 'int'; v: bigint }
  | { t: 'float'; v: number }
  | { t: 'str'; v: string }
  | { t: 'bytes'; v: Uint8Array }
  | { t: 'bool'; v: boolean }
  | { t: 'none' }
  | { t: 'list'; items: PickleValue[] }
  | { t: 'tuple'; items: PickleValue[] }
  | { t: 'dict'; entries: Array<{ key: PickleValue; value: PickleValue }> };

interface PickleCursor { position: number }

const utf8PickleDecoder = new TextDecoder('utf-8');

const latin1Decode = (bytes: Uint8Array): string => Array.from(bytes, byte => String.fromCharCode(byte)).join('');

const readPickleSlice = (bytes: Uint8Array, cursor: PickleCursor, count: number): Uint8Array => {
  if (cursor.position + count > bytes.length) throw new Error('pickle 流意外结束：定长字段不完整。');
  const slice = bytes.subarray(cursor.position, cursor.position + count);
  cursor.position += count;
  return slice;
};

const readPickleLine = (bytes: Uint8Array, cursor: PickleCursor): string => {
  const end = bytes.indexOf(0x0a, cursor.position);
  if (end < 0) throw new Error('pickle 流意外结束：缺少换行终止。');
  const text = latin1Decode(bytes.subarray(cursor.position, end));
  cursor.position = end + 1;
  return text;
};

const readPickleLength = (bytes: Uint8Array, cursor: PickleCursor, count: number): number => {
  const slice = readPickleSlice(bytes, cursor, count);
  let length = 0;
  for (let index = 0; index < slice.length; index += 1) length += slice[index] * 256 ** index;
  return length;
};

const PYTHON_SIMPLE_ESCAPES: Record<string, number> = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11 };

// 手写 Python 字符串转义还原（协议 0 STRING 的 repr 文本），绝不执行任何代码语义。
const unescapePythonString = (line: string): string => {
  const quote = line[0];
  if ((quote !== '\'' && quote !== '"') || line[line.length - 1] !== quote || line.length < 2) {
    throw new Error(`pickle 协议 0 STRING 格式异常：${line}`);
  }
  const body = line.slice(1, line.length - 1);
  let output = '';
  for (let index = 0; index < body.length; index += 1) {
    const char = body[index];
    if (char !== '\\') {
      output += char;
      continue;
    }
    const next = body[index + 1];
    if (next === undefined) throw new Error('pickle STRING 转义序列在行尾截断。');
    index += 1;
    if (next === '\\' || next === '\'' || next === '"') {
      output += next;
      continue;
    }
    const simple = PYTHON_SIMPLE_ESCAPES[next];
    if (simple !== undefined) {
      output += String.fromCharCode(simple);
      continue;
    }
    if (next === 'x' && /^[0-9a-fA-F]{2}$/.test(body.slice(index + 1, index + 3))) {
      output += String.fromCharCode(Number.parseInt(body.slice(index + 1, index + 3), 16));
      index += 2;
      continue;
    }
    if ((next === 'u' || next === 'U') && next === 'u' && /^[0-9a-fA-F]{4}$/.test(body.slice(index + 1, index + 5))) {
      output += String.fromCodePoint(Number.parseInt(body.slice(index + 1, index + 5), 16));
      index += 4;
      continue;
    }
    if (next >= '0' && next <= '7') {
      let octal = next;
      while (octal.length < 3 && body[index + 1] >= '0' && body[index + 1] <= '7') {
        index += 1;
        octal += body[index];
      }
      output += String.fromCharCode(Number.parseInt(octal, 8) & 0xff);
      continue;
    }
    output += `\\${next}`;
  }
  return output;
};

// 输入兼容两种形态：原始 pickle 字节粘贴，或 \xHH / \n / \t / \\ 转义文本。
const unescapePickleInput = (text: string): Uint8Array => {
  const out: number[] = [];
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === '\\' && index + 1 < text.length) {
      const next = text[index + 1];
      if (next === 'x' && /^[0-9a-fA-F]{2}$/.test(text.slice(index + 2, index + 4))) {
        out.push(Number.parseInt(text.slice(index + 2, index + 4), 16));
        index += 3;
        continue;
      }
      const simple: Record<string, number> = { n: 10, r: 13, t: 9, '\\': 92, '\'': 39, '"': 34, '0': 0 };
      if (next in simple) {
        out.push(simple[next]);
        index += 1;
        continue;
      }
      out.push(char.charCodeAt(0));
      continue;
    }
    const code = char.charCodeAt(0);
    if (code > 0xff) throw new Error(`输入含无法映射为字节的字符「${char}」：请粘贴 pickle 原始字节或 \\xHH 转义文本。`);
    out.push(code);
  }
  return new Uint8Array(out);
};

const escapePickleText = (value: string): string => {
  let output = '';
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (char === '\\') output += '\\\\';
    else if (char === '\'') output += '\\\'';
    else if (code === 0x0a) output += '\\n';
    else if (code === 0x0d) output += '\\r';
    else if (code === 0x09) output += '\\t';
    else if (code >= 0x20 && code !== 0x7f) output += char;
    else output += `\\x${code.toString(16).padStart(2, '0')}`;
  }
  return output;
};

const escapePickleBytes = (bytes: Uint8Array): string => {
  let output = '';
  for (const byte of bytes) {
    if (byte >= 0x20 && byte <= 0x7e) {
      const char = String.fromCharCode(byte);
      output += char === '\\' || char === '\'' ? `\\${char}` : char;
    } else if (byte === 0x0a) output += '\\n';
    else if (byte === 0x0d) output += '\\r';
    else if (byte === 0x09) output += '\\t';
    else output += `\\x${byte.toString(16).padStart(2, '0')}`;
  }
  return output;
};

const renderPickleFloat = (value: number): string => {
  if (Number.isNaN(value)) return 'nan';
  if (value === Number.POSITIVE_INFINITY) return 'inf';
  if (value === Number.NEGATIVE_INFINITY) return '-inf';
  if (Number.isInteger(value)) return `${value}.0`;
  return String(value);
};

const renderPickleValue = (value: PickleValue): string => {
  switch (value.t) {
    case 'none': return 'None';
    case 'bool': return value.v ? 'True' : 'False';
    case 'int': return value.v.toString();
    case 'float': return renderPickleFloat(value.v);
    case 'str': return `'${escapePickleText(value.v)}'`;
    case 'bytes': return `b'${escapePickleBytes(value.v)}'`;
    case 'list': return `[${value.items.map(renderPickleValue).join(', ')}]`;
    case 'tuple': {
      const inner = value.items.map(renderPickleValue).join(', ');
      return value.items.length === 1 ? `(${inner},)` : `(${inner})`;
    }
    case 'dict': return `{${value.entries.map(entry => `${renderPickleValue(entry.key)}: ${renderPickleValue(entry.value)}`).join(', ')}}`;
    default: throw new Error('未知的 pickle 值类型。');
  }
};

// 涉及代码执行 / 全局引用 / 持久化的 opcode：一律拒绝（受限解析只支持基础类型）。
const PICKLE_RESTRICTED = new Map<number, string>([
  [0x63, 'GLOBAL'], [0x69, 'INST'], [0x6f, 'OBJ'], [0x52, 'REDUCE'], [0x62, 'BUILD'],
  [0x6e, 'NEWOBJ'], [0x92, 'NEWOBJ_EX'], [0x93, 'STACK_GLOBAL'], [0x50, 'PERSID'], [0x51, 'BINPERSID'],
  [0x82, 'EXTENSION1'], [0x83, 'EXTENSION2'], [0x84, 'EXTENSION4'],
]);

const runPickleMachine = (bytes: Uint8Array): string => {
  const stack: PickleValue[] = [];
  const marks: number[] = [];
  const memo = new Map<number, PickleValue>();
  const cursor: PickleCursor = { position: 0 };
  while (cursor.position < bytes.length) {
    const opcode = bytes[cursor.position];
    cursor.position += 1;
    const restrictedName = PICKLE_RESTRICTED.get(opcode);
    if (restrictedName !== undefined) {
      throw new Error(`受限解析只支持基础类型：拒绝 pickle 操作码 ${restrictedName}（0x${opcode.toString(16)}），它涉及代码执行或全局对象引用。`);
    }
    switch (opcode) {
      case 0x80: { // PROTO
        readPickleSlice(bytes, cursor, 1);
        break;
      }
      case 0x95: { // FRAME
        readPickleLength(bytes, cursor, 4);
        break;
      }
      case 0x2e: { // STOP
        if (stack.length !== 1) throw new Error('pickle 流结束时栈上应有且仅有一个对象，数据可能不完整。');
        return renderPickleValue(stack[0]);
      }
      case 0x49: { // INT（协议 0 行文本整数）
        const line = readPickleLine(bytes, cursor);
        if (!/^-?\d+$/.test(line)) throw new Error(`pickle INT 内容不是整数：${line}`);
        stack.push({ t: 'int', v: BigInt(line) });
        break;
      }
      case 0x4c: { // LONG（协议 0，尾缀 L）
        const line = readPickleLine(bytes, cursor).replace(/[Ll]$/, '');
        if (!/^-?\d+$/.test(line)) throw new Error(`pickle LONG 内容不是整数：${line}`);
        stack.push({ t: 'int', v: BigInt(line) });
        break;
      }
      case 0x46: { // FLOAT（协议 0）
        stack.push({ t: 'float', v: Number(readPickleLine(bytes, cursor)) });
        break;
      }
      case 0x4a: { // BININT（4 字节小端有符号）
        const slice = readPickleSlice(bytes, cursor, 4);
        const unsigned = slice[0] | (slice[1] << 8) | (slice[2] << 16) | (slice[3] << 24);
        stack.push({ t: 'int', v: BigInt(BigInt.asIntN(32, BigInt(unsigned))) });
        break;
      }
      case 0x4b: { // BININT1
        stack.push({ t: 'int', v: BigInt(readPickleSlice(bytes, cursor, 1)[0]) });
        break;
      }
      case 0x4d: { // BININT2（2 字节小端无符号）
        const slice = readPickleSlice(bytes, cursor, 2);
        stack.push({ t: 'int', v: BigInt(slice[0] | (slice[1] << 8)) });
        break;
      }
      case 0x47: { // BINFLOAT（8 字节大端 float64）
        stack.push({ t: 'float', v: new DataView(readPickleSlice(bytes, cursor, 8).buffer).getFloat64(0, false) });
        break;
      }
      case 0x53: { // STRING（协议 0 repr 文本）
        stack.push({ t: 'str', v: unescapePythonString(readPickleLine(bytes, cursor)) });
        break;
      }
      case 0x54: { // BINSTRING（4 字节长度 + latin1）
        stack.push({ t: 'str', v: latin1Decode(readPickleSlice(bytes, cursor, readPickleLength(bytes, cursor, 4))) });
        break;
      }
      case 0x55: { // SHORT_BINSTRING（1 字节长度 + latin1）
        stack.push({ t: 'str', v: latin1Decode(readPickleSlice(bytes, cursor, readPickleSlice(bytes, cursor, 1)[0])) });
        break;
      }
      case 0x58: { // BINUNICODE（4 字节长度 + UTF-8）
        stack.push({ t: 'str', v: utf8PickleDecoder.decode(readPickleSlice(bytes, cursor, readPickleLength(bytes, cursor, 4))) });
        break;
      }
      case 0x8c: { // SHORT_BINUNICODE（1 字节长度 + UTF-8）
        stack.push({ t: 'str', v: utf8PickleDecoder.decode(readPickleSlice(bytes, cursor, readPickleSlice(bytes, cursor, 1)[0])) });
        break;
      }
      case 0x56: { // UNICODE（协议 0，行内按 latin1 字节原样保留）
        stack.push({ t: 'str', v: readPickleLine(bytes, cursor) });
        break;
      }
      case 0x4e: { // NONE
        stack.push({ t: 'none' });
        break;
      }
      case 0x88: stack.push({ t: 'bool', v: true }); break; // NEWTRUE
      case 0x89: stack.push({ t: 'bool', v: false }); break; // NEWFALSE
      case 0x29: stack.push({ t: 'tuple', items: [] }); break; // EMPTY_TUPLE
      case 0x5d: stack.push({ t: 'list', items: [] }); break; // EMPTY_LIST
      case 0x7d: stack.push({ t: 'dict', entries: [] }); break; // EMPTY_DICT
      case 0x28: marks.push(stack.length); break; // MARK
      case 0x74: { // TUPLE
        stack.push({ t: 'tuple', items: popToMark(stack, marks) });
        break;
      }
      case 0x6c: { // LIST
        stack.push({ t: 'list', items: popToMark(stack, marks) });
        break;
      }
      case 0x64: { // DICT
        const items = popToMark(stack, marks);
        if (items.length % 2 !== 0) throw new Error('pickle DICT 的 MARK 切片不是键值成对结构。');
        const entries: Array<{ key: PickleValue; value: PickleValue }> = [];
        for (let index = 0; index < items.length; index += 2) entries.push({ key: items[index], value: items[index + 1] });
        stack.push({ t: 'dict', entries });
        break;
      }
      case 0x85: { // TUPLE1
        stack.push({ t: 'tuple', items: popCount(stack, 1) });
        break;
      }
      case 0x86: { // TUPLE2
        stack.push({ t: 'tuple', items: popCount(stack, 2) });
        break;
      }
      case 0x87: { // TUPLE3
        stack.push({ t: 'tuple', items: popCount(stack, 3) });
        break;
      }
      case 0x61: { // APPEND
        const item = stack.pop();
        if (item === undefined) throw new Error('pickle 流栈已空：APPEND 缺少对象。');
        appendPickleItem(stack, item);
        break;
      }
      case 0x65: { // APPENDS：先弹 MARK 切片，再向新栈顶列表追加
        const items = popToMark(stack, marks);
        const target = stack[stack.length - 1];
        if (!target || target.t !== 'list') throw new Error('pickle APPENDS 的目标不是列表。');
        for (const item of items) target.items.push(item);
        break;
      }
      case 0x73: { // SETITEM
        const value = stack.pop();
        const key = stack.pop();
        if (value === undefined || key === undefined) throw new Error('pickle 流栈已空：SETITEM 缺少键或值。');
        const target = stack[stack.length - 1];
        if (!target || target.t !== 'dict') throw new Error('pickle SETITEM 的目标不是字典。');
        target.entries.push({ key, value });
        break;
      }
      case 0x75: { // SETITEMS：先弹 MARK 切片，再写入新栈顶字典
        const items = popToMark(stack, marks);
        const target = stack[stack.length - 1];
        if (!target || target.t !== 'dict') throw new Error('pickle SETITEMS 的目标不是字典。');
        if (items.length % 2 !== 0) throw new Error('pickle SETITEMS 的 MARK 切片不是键值成对结构。');
        for (let index = 0; index < items.length; index += 2) target.entries.push({ key: items[index], value: items[index + 1] });
        break;
      }
      case 0x70: { // PUT（协议 0 备忘录）
        const index = Number(readPickleLine(bytes, cursor));
        if (!Number.isInteger(index) || index < 0) throw new Error('pickle PUT 备忘录编号异常。');
        const top = stack[stack.length - 1];
        if (!top) throw new Error('pickle PUT 时栈为空，无法登记备忘录。');
        memo.set(index, top);
        break;
      }
      case 0x67: { // GET（协议 0 备忘录）
        const index = Number(readPickleLine(bytes, cursor));
        pushMemoValue(memo, index, stack);
        break;
      }
      case 0x71: { // BINPUT（1 字节编号写入备忘录，栈不弹出）
        const index = readPickleSlice(bytes, cursor, 1)[0];
        const top = stack[stack.length - 1];
        if (!top) throw new Error('pickle BINPUT 时栈为空，无法登记备忘录。');
        memo.set(index, top);
        break;
      }
      case 0x72: { // LONG_BINPUT（4 字节小端编号写入备忘录）
        const index = readPickleLength(bytes, cursor, 4);
        const top = stack[stack.length - 1];
        if (!top) throw new Error('pickle LONG_BINPUT 时栈为空，无法登记备忘录。');
        memo.set(index, top);
        break;
      }
      case 0x68: { // BINGET（1 字节编号读取备忘录）
        pushMemoValue(memo, readPickleSlice(bytes, cursor, 1)[0], stack);
        break;
      }
      case 0x6a: { // LONG_BINGET（4 字节小端编号读取备忘录）
        pushMemoValue(memo, readPickleLength(bytes, cursor, 4), stack);
        break;
      }
      case 0x94: { // MEMOIZE
        const top = stack[stack.length - 1];
        if (!top) throw new Error('pickle MEMOIZE 时栈为空。');
        memo.set(memo.size, top);
        break;
      }
      case 0x30: { // POP
        if (stack.pop() === undefined) throw new Error('pickle 流栈已空：POP 无法弹出。');
        break;
      }
      case 0x31: { // POP_MARK
        popToMark(stack, marks);
        break;
      }
      case 0x42: { // BINBYTES（4 字节长度）
        stack.push({ t: 'bytes', v: readPickleSlice(bytes, cursor, readPickleLength(bytes, cursor, 4)) });
        break;
      }
      case 0x43: { // SHORT_BINBYTES（1 字节长度）
        stack.push({ t: 'bytes', v: readPickleSlice(bytes, cursor, readPickleSlice(bytes, cursor, 1)[0]) });
        break;
      }
      case 0x8e: { // BYTEARRAY8（8 字节长度）
        stack.push({ t: 'bytes', v: readPickleSlice(bytes, cursor, readPickleLength(bytes, cursor, 8)) });
        break;
      }
      default:
        throw new Error(`遇到未支持的 pickle 操作码 0x${opcode.toString(16)}：受限解析只支持基础类型（数字/字符串/布尔/None/列表/元组/字典/字节串）。`);
    }
  }
  throw new Error('pickle 流缺少 STOP 结束符，数据可能不完整。');
};

const popToMark = (stack: PickleValue[], marks: number[]): PickleValue[] => {
  if (!marks.length) throw new Error('pickle 流缺少 MARK 标记，无法收集对象集合。');
  const start = marks[marks.length - 1];
  marks.length -= 1;
  const items = stack.slice(start);
  stack.length = start;
  return items;
};

const popCount = (stack: PickleValue[], count: number): PickleValue[] => {
  if (stack.length < count) throw new Error(`pickle 流栈上对象不足 ${count} 个，无法构造元组。`);
  return stack.splice(stack.length - count, count);
};

const appendPickleItem = (stack: PickleValue[], item: PickleValue): void => {
  const target = stack[stack.length - 1];
  if (!target || target.t !== 'list') throw new Error('pickle APPEND 的目标不是列表。');
  target.items.push(item);
};

const pushMemoValue = (memo: Map<number, PickleValue>, index: number, stack: PickleValue[]): void => {
  const value = memo.get(index);
  if (value === undefined) throw new Error(`pickle 备忘录缺少条目 ${index}，数据可能不完整。`);
  stack.push(value);
};

const pickleDecode = (input: string): string => runPickleMachine(unescapePickleInput(input));

// ==================== ascii-control ====================
// 算法定义：C0 控制字符（0x00-0x1F）与 DEL（0x7F）的脱字符记法 = '^' + (0x40+code) 对应的
// @、A-Z、[、\、]、^、_（DEL 记作 ^?）；名称记法用官方缩写 NUL…US、DEL。
// 编码输出脱字符记法，解码同时接受 ^A 与 [SOH] 两种记法。
// 来源：https://en.wikipedia.org/wiki/Caret_notation 、 https://en.wikipedia.org/wiki/ASCII_control_characters

const ASCII_CONTROL_NAMES = ['NUL', 'SOH', 'STX', 'ETX', 'EOT', 'ENQ', 'ACK', 'BEL', 'BS', 'HT', 'LF', 'VT', 'FF', 'CR', 'SI', 'DLE', 'DC1', 'DC2', 'DC3', 'DC4', 'NAK', 'SYN', 'ETB', 'CAN', 'EM', 'SUB', 'ESC', 'FS', 'GS', 'RS', 'US', 'DEL'];
const asciiControlNameToCode = new Map(ASCII_CONTROL_NAMES.map((name, index) => [name, index < 31 ? index : 0x7f]));

const caretForCode = (code: number): string => (code === 0x7f ? '^?' : `^${String.fromCharCode(0x40 + code)}`);

const codeForCaret = (char: string): number => {
  const code = char.toUpperCase().charCodeAt(0);
  return code >= 0x40 && code <= 0x5f ? code - 0x40 : -1;
};

const asciiControlEncode = (input: string): string => {
  let output = '';
  for (const char of input) {
    const code = char.charCodeAt(0);
    output += code <= 0x1f || code === 0x7f ? caretForCode(code) : char;
  }
  return output;
};

const asciiControlDecode = (input: string): string => {
  let output = '';
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (char === '^' && index + 1 < input.length) {
      const code = codeForCaret(input[index + 1]);
      if (code >= 0) {
        output += String.fromCharCode(code);
        index += 1;
        continue;
      }
    }
    if (char === '[') {
      const end = input.indexOf(']', index);
      if (end > index) {
        const code = asciiControlNameToCode.get(input.slice(index + 1, end));
        if (code !== undefined) {
          output += String.fromCharCode(code);
          index = end;
          continue;
        }
      }
    }
    output += char;
  }
  return output;
};

// ==================== quwei（GB2312 区位码）====================
// 算法定义：GB2312 双字节码本按「区/位」定位，字节 1 = 0xA0+区、字节 2 = 0xA0+位，区/位均 1-94；
// 解码用 TextDecoder('gb2312')，编码惰性构建 94×94 反查 Map（跳过解码为 U+FFFD 的空码位）。
// 来源：GB2312-1980 区位码表（https://en.wikipedia.org/wiki/GB_2312）

const QUWEI_MAX = 94;
let quweiReverseMap: Map<string, string> | null = null;
const quweiGbDecoder = new TextDecoder('gb2312');
const quweiGbStrictDecoder = new TextDecoder('gb2312', { fatal: true });

const ensureQuweiReverse = (): Map<string, string> => {
  if (quweiReverseMap) return quweiReverseMap;
  const map = new Map<string, string>();
  const bytes = new Uint8Array(2);
  for (let qu = 1; qu <= QUWEI_MAX; qu += 1) {
    for (let wei = 1; wei <= QUWEI_MAX; wei += 1) {
      bytes[0] = 0xa0 + qu;
      bytes[1] = 0xa0 + wei;
      try {
        const char = quweiGbStrictDecoder.decode(bytes);
        if (char !== '\uFFFD' && !map.has(char)) map.set(char, `${String(qu).padStart(2, '0')}${String(wei).padStart(2, '0')}`);
      } catch {
        // GB2312 未定义的空码位：跳过，不进入反查表。
      }
    }
  }
  quweiReverseMap = map;
  return map;
};

const quweiEncode = (input: string): string => {
  const reverse = ensureQuweiReverse();
  const groups: string[] = [];
  for (const char of input) {
    const code = reverse.get(char);
    if (code === undefined) throw new Error(`「${char}」不在 GB2312 区位码表内：区位码只能表示 GB2312 汉字与符号。`);
    groups.push(code);
  }
  return groups.join(' ');
};

const quweiDecode = (input: string): string => {
  const compact = input.replace(/\s+/g, '');
  if (!/^\d+$/.test(compact) || compact.length % 4 !== 0) {
    throw new Error('区位码必须是 4 位一组的数字（区 2 位 + 位 2 位），组间可有空格。');
  }
  const bytes = new Uint8Array(2);
  let output = '';
  for (let position = 0; position < compact.length; position += 4) {
    const qu = Number(compact.slice(position, position + 2));
    const wei = Number(compact.slice(position + 2, position + 4));
    if (qu < 1 || qu > QUWEI_MAX || wei < 1 || wei > QUWEI_MAX) {
      throw new Error(`区位「${compact.slice(position, position + 4)}」越界：区/位都必须在 1-94。`);
    }
    bytes[0] = 0xa0 + qu;
    bytes[1] = 0xa0 + wei;
    const char = quweiGbDecoder.decode(bytes);
    if (char === '\uFFFD') throw new Error(`区位「${compact.slice(position, position + 4)}」是 GB2312 未定义的空码位。`);
    output += char;
  }
  return output;
};

// ==================== 操作元数据 ====================

export const parityNumOperations: Operation[] = [
  {
    id: 'ieee754',
    category: 'binary',
    name: { zh: 'IEEE754 浮点互转', en: 'IEEE754 Float Conversion' },
    summary: { zh: '在十进制数与 IEEE754 位模式间互转：编码=十进制→hex 位模式，解码=hex（或等长 0/1 二进制）→十进制；variant 选 float32/float64，支持 NaN/±Infinity。', en: 'Converts between decimal numbers and IEEE754 bit patterns: encode decimal to hex, decode hex (or equal-length binary) back to decimal; variant picks float32/float64, NaN/±Infinity supported.' },
    params: ['variant'],
  },
  {
    id: 'twos-complement',
    category: 'binary',
    name: { zh: '二进制补码', en: 'Two\u2019s Complement' },
    summary: { zh: '十进制整数 ↔ 8/16/32 位二进制补码（variant 选位宽）：编码把负数按位宽回绕成补码位型，解码按最高位还原带符号十进制。', en: 'Decimal integers ↔ 8/16/32-bit two\u2019s complement binary (variant picks width): negatives wrap within the width, decode restores the signed decimal from the sign bit.' },
    params: ['variant'],
  },
  {
    id: 'ones-complement',
    category: 'binary',
    name: { zh: '二进制反码', en: 'One\u2019s Complement' },
    summary: { zh: '十进制整数 ↔ 8/16/32 位二进制反码（variant 选位宽）：负数编码为绝对值按位取反的位型，超出位宽按位宽回绕；全 1 视为 -0 输出 0。', en: 'Decimal integers ↔ 8/16/32-bit one\u2019s complement binary (variant picks width): negatives encode as bitwise-inverted magnitude, wrap within the width; all-ones reads back as 0.' },
    params: ['variant'],
  },
  {
    id: 'radix-xor',
    category: 'binary',
    name: { zh: '进制异或', en: 'Radix XOR' },
    summary: { zh: '把同进制（2/8/10/16，variant 选择）的数值 token 与密钥逐位循环 XOR，输出保持同进制；XOR 自逆，编解码同函数。secret 为同进制密钥值，多值用空格分隔并按 token 位置循环。', en: 'XORs radix tokens (2/8/10/16 via variant) with a key token stream cyclically, keeping the same radix; XOR is self-inverse so both directions share one function. secret holds same-radix key values, space-separated and cycled by token position.' },
    params: ['variant', 'secret'],
  },
  {
    id: 'bit-split',
    category: 'binary',
    name: { zh: '位分割', en: 'Bit Split' },
    summary: { zh: '把 0/1 位串按 2/3/4/7 位（variant 选择）宽度分行显示：编码=按宽度分组成多行，解码=忽略空白拼接还原。', en: 'Splits a 0/1 bit string into rows of 2/3/4/7 bits (via variant): encode groups bits into lines, decode ignores whitespace and joins them back.' },
    params: ['variant'],
  },
  {
    id: 'hamming',
    category: 'binary',
    name: { zh: '海明码校验', en: 'Hamming Code' },
    summary: { zh: '(7,4) 海明码（偶校验）：编码把 4 个数据位编成 7 位码字；解码计算 syndrome、定位并纠正单比特错误，纠错时结果附「纠错：第 N 位已纠正」。输入非 0/1 或长度不符会报错。', en: '(7,4) Hamming code with even parity: encode turns 4 data bits into a 7-bit codeword; decode computes the syndrome, locates and corrects a single-bit error and appends a correction note. Non-bit or wrong-length input raises an error.' },
  },
  {
    id: 'qwe-keyboard',
    category: 'binary',
    name: { zh: 'QWE=ABC 键盘对应', en: 'QWE=ABC Mapping' },
    summary: { zh: 'QWERTYUIOPASDFGHJKLZXCVBNM 逐位对应 ABCDEFGHIJKLMNOPQRSTUVWXYZ 的键盘序映射（双射）：编码 QWE→ABC，解码 ABC→QWE 逆映射；保留大小写，非字母原样保留。', en: 'Keyboard-order mapping QWERTYUIOPASDFGHJKLZXCVBNM ↔ ABCDEFGHIJKLMNOPQRSTUVWXYZ as a bijection: encode maps QWE to ABC, decode applies the inverse. Case preserved, non-letters untouched.' },
  },
  {
    id: 'gcd',
    category: 'binary',
    name: { zh: 'GCD 最大公约数', en: 'GCD' },
    summary: { zh: '解析输入中的前两个整数（支持任意大整数，正负均可），用辗转相除法求最大公约数并输出十进制结果。', en: 'Parses the first two integers in the input (arbitrary precision, signs allowed) and outputs their greatest common divisor via the Euclidean algorithm.' },
  },
  {
    id: 'prime-factor',
    category: 'binary',
    name: { zh: '素数分解', en: 'Prime Factorization' },
    summary: { zh: '整数质因数分解（小素数试除 + Pollard rho，支持大整数，上限 2^70），输出「底^指数 × …」形式，如 360 → 2^3 × 3^2 × 5。', en: 'Integer factorization via small-prime trial division plus Pollard rho (arbitrary precision, capped at 2^70); outputs base^exponent groups like 360 → 2^3 × 3^2 × 5.' },
  },
  {
    id: 'fibonacci-code',
    category: 'binary',
    name: { zh: '斐波那契数列解密', en: 'Fibonacci Decoding' },
    summary: { zh: 'Zeckendorf 斐波那契编码（1,2,3,5,8…）：编码把整数列表转成「系数位+1」码流（LSB 在前、以 11 终止），解码按终止符切分还原整数列表。', en: 'Zeckendorf Fibonacci coding (1,2,3,5,8…): encode turns an integer list into a bitstream of coefficient words (LSB first, terminated by 11); decode splits on terminators back into integers.' },
  },
  {
    id: 'pickle-parse',
    category: 'binary',
    name: { zh: 'Pickle 反序列化', en: 'Pickle Deserialization' },
    summary: { zh: '受限解析 Python pickle（协议 0-5）为 Python 字面量风格文本（单引号字符串、[列表]、(元组,)、{键: 值}、b\'字节串\'）；只支持基础类型 opcode，遇到 GLOBAL/REDUCE/NEWOBJ 等代码执行类 opcode 立即拒绝，绝不执行任何代码语义。仅解码，接受原始字节或 \\xHH 转义文本。', en: 'Restricted parsing of Python pickle (protocols 0-5) into Python-literal-style text (single-quoted strings, [lists], (tuples,), {dicts}, b\'bytes\'); only basic-type opcodes are allowed, and GLOBAL/REDUCE/NEWOBJ-style code-execution opcodes are rejected outright. Decode only; accepts raw bytes or \\xHH escaped text.' },
    supportsEncode: false,
    supportsDecode: true,
  },
  {
    id: 'ascii-control',
    category: 'binary',
    name: { zh: 'ASCII 控制字符', en: 'ASCII Control Chars' },
    summary: { zh: 'ASCII 控制字符互转：编码把 C0/DEL 控制字符替换为脱字符记法（\\x01→^A、DEL→^?），解码同时识别 ^A 记法与 [SOH] 名称记法并还原为真实控制字符。', en: 'Converts ASCII control characters: encode replaces C0/DEL controls with caret notation (\\x01→^A, DEL→^?), decode accepts both ^A caret notation and [SOH] name notation back into real control characters.' },
  },
  {
    id: 'quwei',
    category: 'binary',
    name: { zh: '区位码 ↔ 汉字', en: 'GB2312 Qu-Wei Code' },
    summary: { zh: 'GB2312 区位码 ↔ 汉字：编码把 GB2312 字符转成 4 位区位码（区 2 位 + 位 2 位，1-94，多字空格分隔），解码用 TextDecoder gb2312 还原；越界区位或空码位会报错。', en: 'GB2312 qu-wei code ↔ characters: encode turns GB2312 characters into 4-digit groups (qu 2 digits + wei 2 digits, 1-94, space-separated), decode restores them via TextDecoder gb2312; out-of-range or empty cells raise errors.' },
  },
];

export const parityNumDefaultParams: Partial<Record<ParamKey, string>> = {
  // variant 是全局共享键（operations.ts 字面量统一给 'special'），各操作的取值回退由 pick* 帮手处理。
};

export async function parityNumTransform(id: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): Promise<string> {
  if (!input.trim()) return '';
  const variant = params.variant ?? '';
  const secret = params.secret ?? '';
  switch (id) {
    case 'ieee754':
      return direction === 'encode' ? ieee754Encode(input, variant) : ieee754Decode(input, variant);
    case 'twos-complement':
      return direction === 'encode' ? twosComplementEncode(input, variant) : twosComplementDecode(input, variant);
    case 'ones-complement':
      return direction === 'encode' ? onesComplementEncode(input, variant) : onesComplementDecode(input, variant);
    case 'radix-xor':
      return radixXorCompute(input, variant, secret);
    case 'bit-split':
      return direction === 'encode' ? bitSplitEncode(input, variant) : bitSplitDecode(input);
    case 'hamming':
      return direction === 'encode' ? hammingEncode(input) : hammingDecode(input);
    case 'qwe-keyboard':
      return direction === 'encode' ? qweKeyboardEncode(input) : qweKeyboardDecode(input);
    case 'gcd':
      return gcdCompute(input);
    case 'prime-factor':
      return primeFactorCompute(input);
    case 'fibonacci-code':
      return direction === 'encode' ? fibEncode(input) : fibDecode(input);
    case 'pickle-parse':
      if (direction === 'encode') throw new Error('pickle-parse 是只读解析操作，不支持编码：请把 pickle 字节粘贴到解码方向。');
      return pickleDecode(input);
    case 'ascii-control':
      return direction === 'encode' ? asciiControlEncode(input) : asciiControlDecode(input);
    case 'quwei':
      return direction === 'encode' ? quweiEncode(input) : quweiDecode(input);
    default:
      throw new Error(`未知的进制/工具操作：${id}`);
  }
}

// ==================== 智能识别形状探针（与各码表/谓词同源）====================

export const parityNumLooksLike: ParityShapeProbe[] = [
  {
    id: 'quwei',
    label: 'GB2312 区位码（4 位区地位码组）',
    test: (value: string): boolean => {
      const compact = value.trim().replace(/\s+/g, '');
      if (!/^\d{4,}$/.test(compact) || compact.length % 4 !== 0) return false;
      for (let position = 0; position < compact.length; position += 4) {
        const qu = Number(compact.slice(position, position + 2));
        const wei = Number(compact.slice(position + 2, position + 4));
        if (qu < 1 || qu > QUWEI_MAX || wei < 1 || wei > QUWEI_MAX) return false;
      }
      return true;
    },
  },
  {
    id: 'ascii-control',
    label: 'ASCII 控制字符记法（^A / [SOH]）',
    test: (value: string): boolean => {
      const bracket = new RegExp(`\\[(?:${ASCII_CONTROL_NAMES.join('|')})\\]`);
      if (bracket.test(value)) return true;
      // 单个脱字符记法（如乱码里恰好出现 ^I/^M）不构成信号，两处以上才是控制字符密文。
      let caretHits = 0;
      for (let index = 0; index < value.length - 1; index += 1) {
        if (value[index] === '^' && codeForCaret(value[index + 1]) >= 0) caretHits += 1;
        if (caretHits >= 2) return true;
      }
      return false;
    },
  },
  {
    id: 'hamming',
    label: '海明码（0/1 七位组）',
    test: (value: string): boolean => {
      const bits = value.replace(/\s+/g, '');
      return /^[01]+$/.test(bits) && bits.length >= 7 && bits.length % 7 === 0;
    },
  },
  {
    id: 'fibonacci-code',
    label: '斐波那契码（11 终止比特流）',
    test: (value: string): boolean => {
      const bits = value.replace(/\s+/g, '');
      if (!/^[01]{3,}$/.test(bits) || !bits.endsWith('11')) return false;
      try {
        return /^\d+( \d+)*$/.test(fibDecode(bits));
      } catch {
        return false;
      }
    },
  },
  {
    id: 'pickle-parse',
    label: 'Pickle 字节流（PROTO 头或协议 0 集合开头）',
    test: (value: string): boolean => {
      const text = value.trim();
      if (!text) return false;
      if (text.startsWith('\\x80')) return true;
      if (text.charCodeAt(0) === 0x80) return true;
      return /^\([ld]/.test(text);
    },
  },
];

// ==================== 回归向量 ====================
// cipher 有值 = 权威对拍（来源见行内注释）；无来源说明 = 自造样本 round-trip。
export const parityNumVectors: ParityVector[] = [
  // 权威：IEEE 754 位模式规范值（https://en.wikipedia.org/wiki/IEEE_754；1.0=0x3FF0…、-2.5=0xC004…、3.14=0x4009…）
  { id: 'ieee754', plain: '1', cipher: '3ff0000000000000' },
  { id: 'ieee754', plain: '-2.5', cipher: 'c004000000000000' },
  { id: 'ieee754', plain: '3.14', cipher: '40091eb851eb851f' },
  { id: 'ieee754', plain: '1', cipher: '3f800000', params: { variant: 'float32' } },
  { id: 'ieee754', plain: '-2.5', cipher: 'c0200000', params: { variant: 'float32' } },
  // 权威：补码表（https://en.wikipedia.org/wiki/Two%27s_complement）
  { id: 'twos-complement', plain: '-1', cipher: '11111111', params: { variant: '8' } },
  { id: 'twos-complement', plain: '5', cipher: '00000101', params: { variant: '8' } },
  { id: 'twos-complement', plain: '-32768', cipher: '1000000000000000', params: { variant: '16' } },
  // 权威：反码定义（https://en.wikipedia.org/wiki/Ones%27_complement）
  { id: 'ones-complement', plain: '-1', cipher: '11111110', params: { variant: '8' } },
  { id: 'ones-complement', plain: '5', cipher: '00000101', params: { variant: '8' } },
  // 权威：XOR 手算可验证值（0xff^0xaa=0x55、0x0f^0xaa=0xa5、0o110^0o5=0o115、0o25^0o5=0o20）
  { id: 'radix-xor', plain: 'ff 0f', cipher: '55 a5', params: { variant: '16', secret: 'aa' } },
  { id: 'radix-xor', plain: '110 25', cipher: '115 20', params: { variant: '8', secret: '5' } },
  // 自造 round-trip：16 位按 4 位分行 / 16 位按 7 位分行
  { id: 'bit-split', plain: '0100000101000010', cipher: '0100\n0001\n0100\n0010', params: { variant: '4' } },
  { id: 'bit-split', plain: '0110100001101001', cipher: '0110100\n0011010\n01', params: { variant: '7' } },
  // 权威：Wikipedia Hamming(7,4) 教材例 1011→0110011；纠错向量为第 5 位单比特翻转的手推结果
  { id: 'hamming', plain: '1011', cipher: '0110011' },
  { id: 'hamming', plain: '1011\n纠错：第 5 位已纠正', cipher: '0110111', direction: 'decode' },
  // 权威：QWE=ABC 键盘序映射（https://www.dcode.fr/qwerty-abc-cipher）
  { id: 'qwe-keyboard', plain: 'QWERTY', cipher: 'ABCDEF' },
  // 权威：gcd(48,36)=12 辗转相除手算
  { id: 'gcd', plain: '12', cipher: '48 36', direction: 'decode' },
  // 权威：360 = 2^3·3^2·5 手算
  { id: 'prime-factor', plain: '2^3 × 3^2 × 5', cipher: '360', direction: 'decode' },
  // 权威：Fibonacci coding 表（https://en.wikipedia.org/wiki/Fibonacci_coding；4→1011、10→010011）
  { id: 'fibonacci-code', plain: '4', cipher: '1011' },
  { id: 'fibonacci-code', plain: '10', cipher: '010011' },
  // 自造 round-trip：多整数码流拼接（'11'+'011'+'0011'）
  { id: 'fibonacci-code', plain: '1 2 3', cipher: '110110011' },
  // 权威：CPython pickle 标准输出形态（https://docs.python.org/3/library/pickletools.html）
  // 协议 0 列表：MARK+LIST+PUT+INT+APPEND+INT+APPEND+STOP
  { id: 'pickle-parse', plain: '[1, 2]', cipher: '(lp0\\nI1\\naI2\\na.', direction: 'decode' },
  // 协议 2 列表：PROTO+EMPTY_LIST+PUT+MARK+BININT1×2+APPENDS+STOP
  { id: 'pickle-parse', plain: '[1, 2]', cipher: '\\x80\\x02]q\\x00(K\\x01K\\x02e.', direction: 'decode' },
  // 协议 2 字典：PROTO+EMPTY_DICT+PUT+MARK+SHORT_BINSTRING+PUT+BININT1+SETITEMS+STOP
  { id: 'pickle-parse', plain: "{'a': 1}", cipher: '\\x80\\x02}q\\x00(U\\x01aq\\x01K\\x01u.', direction: 'decode' },
  // 协议 2 二元组：PROTO+BININT1×2+TUPLE2+PUT+STOP
  { id: 'pickle-parse', plain: '(2, 3)', cipher: '\\x80\\x02K\\x02K\\x03\\x86q\\x00.', direction: 'decode' },
  // 自造 round-trip：脱字符记法（^A 为脱字符记法标准定义，https://en.wikipedia.org/wiki/Caret_notation）
  { id: 'ascii-control', plain: 'A\x01B', cipher: 'A^AB' },
  { id: 'ascii-control', plain: 'A\x01B', cipher: 'A[SOH]B', direction: 'decode' },
  // 权威：GB2312 区位码本样例（汉=2626、中=5448、文=4636）
  { id: 'quwei', plain: '汉', cipher: '2626' },
  { id: 'quwei', plain: '中文', cipher: '5448 4636' },
];
