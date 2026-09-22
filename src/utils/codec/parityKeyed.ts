// 批次 O Lane D：带 key / 多 key 类 10 操作（otp / multiplicative / fractionated-morse / fenham / running-key / bazeries / kamasutra / m209 / rc2 / rc6）。
// 密钥统一读取全局密钥栏 params.secret；空输入一律返回空串；错误全部抛中文 Error。
// CODEC-IMPORTS
import { modInverse } from './textEncodings';
import { utf8Decoder, utf8Encoder } from './alphabets';
import { bytesToHex, hexToBytes } from './bases';
// CODEC-IMPORTS-END
import type { Direction, Operation, OperationId, ParamKey } from './types';
import type { ParityShapeProbe, ParityVector } from './parityTypes';

const upperLetters = (value: string) => value.toUpperCase().replace(/[^A-Z]/g, '');

// 密钥字节解析：纯偶长十六进制串按原始字节，否则按 UTF-8 文本（在 summary 中向用户说明）。
const parseKeyBytes = (secret: string, label: string) => {
  const trimmed = secret.trim();
  if (!trimmed) throw new Error(`${label} 需要在顶部密钥栏输入密钥`);
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) return hexToBytes(trimmed);
  return utf8Encoder.encode(trimmed);
};

// 本模块内自备 PKCS#7 填充（避免引入 crypto.ts 造成与 operations.ts 的循环依赖）。
const padToBlock = (bytes: Uint8Array, blockSize: number) => {
  const pad = blockSize - (bytes.length % blockSize);
  const output = new Uint8Array(bytes.length + pad);
  output.set(bytes);
  output.fill(pad, bytes.length);
  return output;
};

const unpadFromBlock = (bytes: Uint8Array, blockSize: number) => {
  if (bytes.length === 0 || bytes.length % blockSize !== 0) throw new Error('密文长度必须是分块大小的整数倍');
  const pad = bytes[bytes.length - 1];
  if (pad < 1 || pad > blockSize || pad > bytes.length) throw new Error('PKCS#7 填充不合法，密钥可能错误');
  for (let index = bytes.length - pad; index < bytes.length; index += 1) {
    if (bytes[index] !== pad) throw new Error('PKCS#7 填充不合法，密钥可能错误');
  }
  return bytes.slice(0, bytes.length - pad);
};

// ---------------------------------------------------------------- otp ----------------------------------------------------------------
// 算法定义：一次一密 = 明文与密钥按字节 XOR（Vernam 1917），密钥长度不得小于数据长度，否则不具备一次一密语义。
// 来源：https://en.wikipedia.org/wiki/One-time_pad 、https://www.dcode.fr/vernam-cipher
const otpTransform = (value: string, secret: string, decode: boolean) => {
  if (!value) return '';
  const dataBytes = decode ? hexToBytes(value.trim()) : utf8Encoder.encode(value);
  const keyBytes = parseKeyBytes(secret, '一次一密');
  if (keyBytes.length < dataBytes.length) {
    throw new Error(`一次一密要求密钥长度不小于数据长度：数据 ${dataBytes.length} 字节，密钥仅 ${keyBytes.length} 字节`);
  }
  const output = new Uint8Array(dataBytes.length);
  for (let index = 0; index < dataBytes.length; index += 1) {
    output[index] = dataBytes[index] ^ keyBytes[index];
  }
  return decode ? utf8Decoder.decode(output) : bytesToHex(output);
};

// --------------------------------------------------------- multiplicative ------------------------------------------------------------
// 算法定义：乘法密码 = c = (p × k) mod 26，k 必须与 26 互素，解码用模逆元 p = (c × k^-1) mod 26。
// 来源：https://www.dcode.fr/multiplicative-cipher 、https://en.wikipedia.org/wiki/Multiplicative_cipher
const multiplicativeTransform = (value: string, secret: string, decode: boolean) => {
  if (!value) return '';
  const multiplier = Number.parseInt((secret || '7').trim(), 10);
  if (!Number.isInteger(multiplier) || multiplier < 1 || multiplier > 25) {
    throw new Error('乘法密码密钥必须是 1-25 的整数（在顶部密钥栏输入，默认 7）');
  }
  if (multiplier % 2 === 0 || multiplier === 13) {
    throw new Error('乘法密码密钥必须与 26 互素，可选 1,3,5,7,9,11,15,17,19,21,23,25');
  }
  const inverse = decode ? modInverse(multiplier, 26) : 1;
  const factor = decode ? inverse : multiplier;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const mapped = (((code - base) * factor) % 26 + 26) % 26;
    return String.fromCharCode(base + mapped);
  }).join('');
};

// -------------------------------------------------------- fractionated morse ---------------------------------------------------------
// 算法定义：分组摩斯 = 先把明文按标准摩斯电码展开（字母间插入分隔符 x，词间再多一个 x），流按 3 个一组切分（不足补 '.'），
// 再按混合字母表把 27 种三元组中的 26 种替换成密文字母。三元组表按 dcode 给出的列序（A=... 到 Z=xx-，xxx 不会出现）。
// 来源：https://www.dcode.fr/fractionated-morse （权威例句 DCODE MORSE → JVLNVGZQODSGY 已逐组核对）
const fractionatedMorseTable: Record<string, string> = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---',
  K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-',
  U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
};
const fractionatedTrigrams = [
  '...', '..-', '..x', '.-.', '.--', '.-x', '.x.', '.x-', '.xx',
  '-..', '-.-', '-.x', '--.', '---', '--x', '-x.', '-x-', '-xx',
  'x..', 'x.-', 'x.x', 'x-.', 'x--', 'x-x', 'xx.', 'xx-',
];
const buildMixedAlphabet = (keyword: string) => {
  const raw = `${keyword.toUpperCase().replace(/[^A-Z]/g, '')}ABCDEFGHIJKLMNOPQRSTUVWXYZ`;
  let output = '';
  for (const char of raw) {
    if (!output.includes(char)) output += char;
  }
  return output.slice(0, 26);
};
const fractionatedEncode = (value: string, secret: string) => {
  const mixed = buildMixedAlphabet(secret);
  let stream = '';
  let afterLetter = false;
  for (const char of value.toUpperCase()) {
    if (/[A-Z]/.test(char)) {
      stream += `${fractionatedMorseTable[char]}x`;
      afterLetter = true;
    } else if (/\s/.test(char)) {
      if (afterLetter) stream += 'x';
      afterLetter = false;
    } else {
      throw new Error(`分组摩斯仅支持字母与空格，遇到不支持的字符：${char}`);
    }
  }
  while (stream.length % 3 !== 0) stream += '.';
  let output = '';
  for (let index = 0; index < stream.length; index += 3) {
    const position = fractionatedTrigrams.indexOf(stream.slice(index, index + 3));
    output += mixed[position];
  }
  return output;
};
const fractionatedDecode = (value: string, secret: string) => {
  const mixed = buildMixedAlphabet(secret);
  let stream = '';
  for (const char of value.toUpperCase()) {
    const index = mixed.indexOf(char);
    if (index < 0) throw new Error(`分组摩斯解码遇到无法识别的字符：${char}`);
    stream += fractionatedTrigrams[index];
  }
  const groups = stream.split('x');
  const output: string[] = [];
  groups.forEach((group, index) => {
    if (group === '') {
      if (index < groups.length - 1 && output.length && output[output.length - 1] !== ' ') output.push(' ');
      return;
    }
    const letter = Object.entries(fractionatedMorseTable).find(([, code]) => code === group)?.[0];
    if (!letter) throw new Error(`分组摩斯解码遇到无法识别的电码片段：${group}（可能是补位伪迹或密文有误）`);
    output.push(letter);
  });
  return output.join('').trim();
};

// ---------------------------------------------------------------- fenham -------------------------------------------------------------
// 算法定义：费娜姆 = Vernam 五比特异或的字母流版：明文字母（A=00000..Z=11001）逐个与密钥字母的五比特码异或，
// 输出 5 位二进制分组（空格分隔）；解码把二进制组与同一密钥再次异或还原字母。XOR 对合，编解码同一运算。
// 来源：https://en.wikipedia.org/wiki/Gilbert_Vernam 、https://www.dcode.fr/vernam-cipher
const fenhamToBits = (index: number) => index.toString(2).padStart(5, '0');
const fenhamEncode = (value: string, secret: string) => {
  const letters = upperLetters(value);
  if (!letters) return '';
  const key = upperLetters(secret);
  if (!key) throw new Error('费娜姆需要在顶部密钥栏输入字母密钥');
  return Array.from(letters).map((char, index) => fenhamToBits((char.charCodeAt(0) - 65) ^ (key.charCodeAt(index % key.length) - 65))).join(' ');
};
const fenhamDecode = (value: string, secret: string) => {
  const bits = value.replace(/[^01]/g, '');
  if (!bits) return '';
  const key = upperLetters(secret);
  if (!key) throw new Error('费娜姆需要在顶部密钥栏输入字母密钥');
  if (bits.length % 5 !== 0) throw new Error('费娜姆解码输入的二进制位数必须是 5 的倍数');
  const groups = bits.match(/.{5}/g) || [];
  return groups.map((group, index) => {
    const code = Number.parseInt(group, 2) ^ (key.charCodeAt(index % key.length) - 65);
    if (code > 25) throw new Error(`费娜姆解码第 ${index + 1} 组二进制 ${group} 超出 A-Z 范围，密钥或密文可能有误`);
    return String.fromCharCode(65 + code);
  }).join('');
};

// ------------------------------------------------------------ running key ------------------------------------------------------------
// 算法定义：滚动密钥 = 维吉涅变体，密钥为一段长文本且不循环：明文字母逐个消耗密钥字母（非字母不消耗），
// 密钥耗尽即报错。c = (p + k) mod 26。
// 来源：https://www.dcode.fr/running-key-cipher 、https://en.wikipedia.org/wiki/Running_key_cipher
const runningKeyTransform = (value: string, secret: string, decode: boolean) => {
  if (!value) return '';
  const key = upperLetters(secret);
  if (!key) throw new Error('滚动密钥需要在顶部密钥栏输入长文本密钥（密钥不循环）');
  const totalLetters = upperLetters(value).length;
  if (totalLetters > key.length) {
    throw new Error(`滚动密钥密钥长度不足：明文需要 ${totalLetters} 个密钥字母，密钥仅 ${key.length} 个（密钥不循环）`);
  }
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const shift = key.charCodeAt(keyIndex) - 65;
    keyIndex += 1;
    const offset = decode ? -shift : shift;
    return String.fromCharCode(base + ((((code - base) + offset) % 26) + 26) % 26);
  }).join('');
};

// -------------------------------------------------------------- bazeries -------------------------------------------------------------
// 算法定义：Bazeries = 数字键 N 两个用途：① 把 N 写成英文单词作为关键词按行填入第二张 5x5 波利比奥斯方格（I/J 合并），
// 第一张为字母表按列填入的标准方格；② 明文按 N 的各位数字循环分组，每组倒序后做第一格→第二格的同位替换。
// 来源：https://www.dcode.fr/bazeries-cipher （DCODE/N=23 → DLSLO：第一格按列填字母表、第二格按行填
// 数字键英文 TWENTYTHREE，明文按 2,3 分组倒序后两格同位替换；其解码示例 DLSLO → DCODE 互为逆运算）
const bazeriesOnes = ['', 'ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN', 'ELEVEN', 'TWELVE', 'THIRTEEN', 'FOURTEEN', 'FIFTEEN', 'SIXTEEN', 'SEVENTEEN', 'EIGHTEEN', 'NINETEEN'];
const bazeriesTens = ['', '', 'TWENTY', 'THIRTY', 'FORTY', 'FIFTY', 'SIXTY', 'SEVENTY', 'EIGHTY', 'NINETY'];
const spellBazeriesNumber = (n: number): string => {
  if (n >= 1000000) return `${spellBazeriesNumber(Math.floor(n / 1000000))}MILLION${spellBazeriesNumber(n % 1000000)}`;
  if (n >= 1000) return `${spellBazeriesNumber(Math.floor(n / 1000))}THOUSAND${spellBazeriesNumber(n % 1000)}`;
  if (n >= 100) return `${bazeriesOnes[Math.floor(n / 100)]}HUNDRED${spellBazeriesNumber(n % 100)}`;
  if (n >= 20) return bazeriesTens[Math.floor(n / 10)] + bazeriesOnes[n % 10];
  return bazeriesOnes[n];
};
const buildRowMajorGrid = (keyword: string) => {
  const source = `${keyword.toUpperCase().replace(/[^A-Z]/g, '')}ABCDEFGHIKLMNOPQRSTUVWXYZ`;
  let output = '';
  for (const char of source) {
    if (!output.includes(char)) output += char;
  }
  return output.slice(0, 25);
};
const bazeriesTransform = (value: string, secret: string, decode: boolean) => {
  if (!value) return '';
  const digits = secret.trim();
  if (!/^[0-9]{1,9}$/.test(digits)) throw new Error('Bazeries 需要在顶部密钥栏输入 1-9 位数字密钥（各位数字 1-9，不能为 0）');
  if (digits.includes('0')) throw new Error('Bazeries 数字键的各位数字需为 1-9，不能为 0');
  const grid1 = Array.from({ length: 25 }, (_, index) => 'ABCDEFGHIKLMNOPQRSTUVWXYZ'[(index % 5) * 5 + Math.floor(index / 5)]);
  const grid2 = Array.from(buildRowMajorGrid(spellBazeriesNumber(Number.parseInt(digits, 10))));
  const from = decode ? grid2 : grid1;
  const to = decode ? grid1 : grid2;
  const letters = upperLetters(value).replace(/J/g, 'I');
  const sizes = Array.from(digits).map(Number);
  const groups: string[] = [];
  let offset = 0;
  let sizeIndex = 0;
  while (offset < letters.length) {
    const size = sizes[sizeIndex % sizes.length];
    sizeIndex += 1;
    groups.push(letters.slice(offset, offset + size).split('').reverse().join(''));
    offset += size;
  }
  return groups.map(group => Array.from(group).map(char => to[from.indexOf(char)] || char).join('')).join('');
};

// -------------------------------------------------------------- kamasutra ------------------------------------------------------------
// 算法定义：迦玛索罗（Kamasutra / 古典替代）= 密钥给出 8 对互异字母，加密时每对字母互换（自逆）。
// 来源：https://en.wikipedia.org/wiki/Substitution_cipher#Kamasutra_cipher 、https://www.dcode.fr/kamasutra-cipher
const kamasutraTransform = (value: string, secret: string) => {
  if (!value) return '';
  const key = upperLetters(secret || 'ABCDEFGHIJKLMNOP');
  if (key.length !== 16 || new Set(key).size !== 16) {
    throw new Error('迦玛索罗密钥必须是 16 个互不重复的字母（8 对），默认 ABCDEFGHIJKLMNOP');
  }
  const map = new Map<string, string>();
  for (let index = 0; index < 16; index += 2) {
    map.set(key[index], key[index + 1]);
    map.set(key[index + 1], key[index]);
  }
  return Array.from(value).map(char => {
    const upper = char.toUpperCase();
    const mapped = map.get(upper);
    if (!mapped) return char;
    return char === upper ? mapped : mapped.toLowerCase();
  }).join('');
};

// ---------------------------------------------------------------- m209 ---------------------------------------------------------------
// 算法定义：M-209（Hagelin C-52）= 六个互素引钉轮（26/25/23/21/19/17）+ 27 根双凸柱杆；每根杆若任一凸柱对上
// 有效引钉则位移计数 +1，输出 c = (25 + 位移 - 明文) mod 26（反转字母表 Beaufort），每编码一个字母六轮各进一格；
// 机器自逆，解密同运算。轮内指示字母与导杆对应引钉存在固定后移偏移（11/10/10/9/8/7）。
// 来源：https://en.wikipedia.org/wiki/M-209 （其示例全键：引钉/凸柱如下，编码 26 个 A 得校验串
// TNJUWAUQTKCZKNUTOTBCWARWIO，本实现以它为内置主流参数档与权威向量；注意该页轮 2 引钉表中
// M 位的长破折号为渲染错误，按校验串反推 M 为有效引钉）
const m209Rings = ['ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'ABCDEFGHIJKLMNOPQRSTUVXYZ', 'ABCDEFGHIJKLMNOPQRSTUVX', 'ABCDEFGHIJKLMNOPQRSTU', 'ABCDEFGHIJKLMNOPQRS', 'ABCDEFGHIJKLMNOPQ'];
const m209Offsets = [11, 11, 10, 9, 8, 7];
const m209DefaultActive = ['ABDHIKMNSTVW', 'ADEGJKLMORSUX', 'ABGHJLMNRSTUX', 'CEFHIMNPSTU', 'BDEFHIMNPS', 'ABDHKNOQ'];
interface M209Profile {
  pins: boolean[][];
  bars: Array<[number, number]>;
}
const m209ProfileFromActive = () => ({
  pins: m209Rings.map((ring, index) => Array.from(ring).map(letter => m209DefaultActive[index].includes(letter))),
  bars: [
    [3, 6], [0, 6], [1, 6], [1, 5], [4, 5], [0, 4], [0, 4], [0, 4], [0, 4],
    [2, 0], [2, 0], [2, 0], [2, 0], [2, 0], [2, 0], [2, 0], [2, 0], [2, 0], [2, 0],
    [2, 5], [2, 5],
    [0, 5], [0, 5], [0, 5], [0, 5], [0, 5], [0, 5],
  ] as Array<[number, number]>,
});
const m209ParseProfile = (secret: string): M209Profile => {
  const description = secret.trim();
  if (!description) return m209ProfileFromActive();
  const parts = description.split('|');
  if (parts.length !== 2 || !parts[0].startsWith('p:') || !parts[1].startsWith('l:')) {
    throw new Error('M-209 密钥描述格式应为 p:引钉段|l:凸柱段，例如 p:1011...,110...|l:3-6,0-6,...（留空使用内置主流参数档）');
  }
  const pinGroups = parts[0].slice(2).split(',');
  if (pinGroups.length !== 6) throw new Error('M-209 引钉段必须是 6 组，用逗号分隔（对应 26/25/23/21/19/17 个 0/1）');
  const pins = pinGroups.map((group, index) => {
    const ringLength = m209Rings[index].length;
    if (!/^[01]+$/.test(group) || group.length !== ringLength) {
      throw new Error(`M-209 第 ${index + 1} 轮引钉必须是 ${ringLength} 个 0/1，收到：${group}`);
    }
    return Array.from(group).map(bit => bit === '1');
  });
  const barTexts = parts[1].slice(2).split(/[\s,]+/).filter(Boolean);
  if (barTexts.length !== 27) throw new Error(`M-209 凸柱段必须是 27 根杆，收到 ${barTexts.length} 根`);
  const bars = barTexts.map(text => {
    const matched = text.match(/^([0-6])-([0-6])$/);
    if (!matched) throw new Error(`M-209 凸柱杆格式应为 轮号-轮号（0 表示空），收到：${text}`);
    return [Number(matched[1]), Number(matched[2])] as [number, number];
  });
  return { pins, bars };
};
const m209Transform = (value: string, secret: string) => {
  if (!value) return '';
  const profile = m209ParseProfile(secret);
  const positions = [0, 0, 0, 0, 0, 0];
  const output: string[] = [];
  for (const raw of value) {
    const char = raw.toUpperCase();
    if (!/[A-Z]/.test(char)) throw new Error(`M-209 只能处理字母 A-Z，遇到：${raw}`);
    const plainValue = char.charCodeAt(0) - 65;
    const engaged = [false, false, false, false, false, false];
    for (let wheel = 0; wheel < 6; wheel += 1) {
      const ringLength = m209Rings[wheel].length;
      const pinIndex = (positions[wheel] - m209Offsets[wheel] + ringLength * 2) % ringLength;
      engaged[wheel] = profile.pins[wheel][pinIndex];
    }
    let shift = 0;
    for (const [left, right] of profile.bars) {
      if ((left > 0 && engaged[left - 1]) || (right > 0 && engaged[right - 1])) shift += 1;
    }
    output.push(String.fromCharCode(65 + (25 + shift - plainValue + 26 * 2) % 26));
    for (let wheel = 0; wheel < 6; wheel += 1) {
      positions[wheel] = (positions[wheel] + 1) % m209Rings[wheel].length;
    }
  }
  return output.join('');
};

// ---------------------------------------------------------------- rc2 ----------------------------------------------------------------
// 算法定义：RC2（RFC 2268）= 64 位分组、16/32 位字混合轮（5+1 捣碎+6+1 捣碎+5）与 PITABLE 密钥展开
//（含 T1 有效密钥位掩码 PKBS）。本实现为 ECB 模式 + PKCS#7 填充，输出 Hex；密钥按纯偶长 hex 或 UTF-8 解析。
// 来源：https://www.rfc-editor.org/rfc/rfc2268 （PITABLE 与测试向量取自 RFC 正文/附录）
const rc2PiTable = [
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];
const rc2RotateLeft = (word: number, bits: number) => ((word << bits) | (word >>> (16 - bits))) & 0xffff;
const rc2ExpandKey = (keyBytes: Uint8Array, t1: number) => {
  const t = keyBytes.length;
  if (t < 1 || t > 128) throw new Error('RC2 密钥长度需为 1-128 字节');
  if (!Number.isInteger(t1) || t1 < 1 || t1 > 1024) throw new Error('RC2 有效密钥位 keyBits 需为 1-1024 的整数');
  const l = new Uint8Array(128);
  l.set(keyBytes);
  for (let index = t; index < 128; index += 1) {
    l[index] = rc2PiTable[(l[index - 1] + l[index - t]) & 255];
  }
  const t8 = Math.floor((t1 + 7) / 8);
  const tm = 255 % (2 ** (8 + t1 - 8 * t8));
  l[128 - t8] = rc2PiTable[l[128 - t8] & tm];
  for (let index = 127 - t8; index >= 0; index -= 1) {
    l[index] = rc2PiTable[l[index + 1] ^ l[index + t8]];
  }
  const k = new Uint16Array(64);
  for (let index = 0; index < 64; index += 1) {
    k[index] = l[2 * index] + 256 * l[2 * index + 1];
  }
  return k;
};
const rc2EncryptBlock = (block: Uint8Array, k: Uint16Array) => {
  const r = [0, 0, 0, 0];
  for (let index = 0; index < 4; index += 1) {
    r[index] = block[2 * index] | (block[2 * index + 1] << 8);
  }
  const s = [1, 2, 3, 5];
  let j = 0;
  const mixRound = () => {
    for (let i = 0; i < 4; i += 1) {
      const previous = r[(i + 3) % 4];
      r[i] = (r[i] + k[j] + (previous & r[(i + 2) % 4]) + ((~previous) & r[(i + 1) % 4])) & 0xffff;
      j += 1;
      r[i] = rc2RotateLeft(r[i], s[i]);
    }
  };
  const mashRound = () => {
    for (let i = 0; i < 4; i += 1) {
      r[i] = (r[i] + k[r[(i + 3) % 4] & 63]) & 0xffff;
    }
  };
  for (let round = 0; round < 5; round += 1) mixRound();
  mashRound();
  for (let round = 0; round < 6; round += 1) mixRound();
  mashRound();
  for (let round = 0; round < 5; round += 1) mixRound();
  const output = new Uint8Array(8);
  for (let index = 0; index < 4; index += 1) {
    output[2 * index] = r[index] & 255;
    output[2 * index + 1] = (r[index] >>> 8) & 255;
  }
  return output;
};
const rc2DecryptBlock = (block: Uint8Array, k: Uint16Array) => {
  const r = [0, 0, 0, 0];
  for (let index = 0; index < 4; index += 1) {
    r[index] = block[2 * index] | (block[2 * index + 1] << 8);
  }
  const s = [1, 2, 3, 5];
  let j = 63;
  const rMixRound = () => {
    for (let i = 3; i >= 0; i -= 1) {
      r[i] = ((r[i] >>> s[i]) | (r[i] << (16 - s[i]))) & 0xffff;
      const previous = r[(i + 3) % 4];
      r[i] = (r[i] - k[j] - (previous & r[(i + 2) % 4]) - ((~previous) & r[(i + 1) % 4])) & 0xffff;
      j -= 1;
    }
  };
  const rMashRound = () => {
    for (let i = 3; i >= 0; i -= 1) {
      r[i] = (r[i] - k[r[(i + 3) % 4] & 63]) & 0xffff;
    }
  };
  for (let round = 0; round < 5; round += 1) rMixRound();
  rMashRound();
  for (let round = 0; round < 6; round += 1) rMixRound();
  rMashRound();
  for (let round = 0; round < 5; round += 1) rMixRound();
  const output = new Uint8Array(8);
  for (let index = 0; index < 4; index += 1) {
    output[2 * index] = r[index] & 255;
    output[2 * index + 1] = (r[index] >>> 8) & 255;
  }
  return output;
};
const rc2Transform = (value: string, secret: string, keyBitsValue: string, decode: boolean, variant: string) => {
  if (!value) return '';
  const rawMode = variant === 'raw';
  const keyBytes = parseKeyBytes(secret, 'RC2');
  const keyBits = Number.parseInt((keyBitsValue || '64').trim(), 10) || 64;
  const k = rc2ExpandKey(keyBytes, keyBits);
  if (!decode) {
    const dataBytes = utf8Encoder.encode(value);
    if (rawMode && dataBytes.length % 8 !== 0) throw new Error('RC2 raw 模式要求明文为 8 字节整块（不自动填充），请改用 pkcs7 模式或手动补齐');
    const padded = rawMode ? dataBytes : padToBlock(dataBytes, 8);
    const output = new Uint8Array(padded.length);
    for (let offset = 0; offset < padded.length; offset += 8) {
      output.set(rc2EncryptBlock(padded.slice(offset, offset + 8), k), offset);
    }
    return bytesToHex(output);
  }
  const cipherBytes = hexToBytes(value.trim());
  if (cipherBytes.length % 8 !== 0) throw new Error('RC2 解密输入的 Hex 长度必须是 8 字节块的整数倍');
  const output = new Uint8Array(cipherBytes.length);
  for (let offset = 0; offset < cipherBytes.length; offset += 8) {
    output.set(rc2DecryptBlock(cipherBytes.slice(offset, offset + 8), k), offset);
  }
  return utf8Decoder.decode(rawMode ? output : unpadFromBlock(output, 8));
};

// ---------------------------------------------------------------- rc6 ----------------------------------------------------------------
// 算法定义：RC6-32/20/b（Rivest/Robshaw/Sidney/Yin 1998）= 128 位分组 4 寄存器、20 轮数据相关循环移位、
// 44 字密钥表（P32=0xB7E15163，Q32=0x9E3779B9），密钥 ≤255 字节。本实现为 ECB + PKCS#7，输出 Hex；
// 密钥按纯偶长 hex 或 UTF-8 解析。
// 来源：Rivest, Robshaw, Sidney, Yin, "The RC6 Block Cipher" v1.1, 1998（https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf），
// 测试向量取自 IETF draft-krovetz-rc6-rc5-vectors-00（https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00）
const rc6RotateLeft = (word: number, bits: number) => {
  const count = bits % 32;
  return ((word << count) | (word >>> (32 - count))) >>> 0;
};
const rc6RotateRight = (word: number, bits: number) => {
  const count = bits % 32;
  return ((word >>> count) | (word << (32 - count))) >>> 0;
};
const rc6KeySchedule = (keyBytes: Uint8Array) => {
  if (keyBytes.length < 1 || keyBytes.length > 255) throw new Error('RC6 密钥长度需为 1-255 字节（在顶部密钥栏输入）');
  const c = Math.max(1, Math.ceil(keyBytes.length / 4));
  const l = new Uint32Array(c);
  keyBytes.forEach((byte, index) => {
    l[Math.floor(index / 4)] |= byte << (8 * (index % 4));
  });
  const s = new Uint32Array(44);
  s[0] = 0xb7e15163;
  for (let index = 1; index < 44; index += 1) {
    s[index] = (s[index - 1] + 0x9e3779b9) >>> 0;
  }
  let a = 0;
  let b = 0;
  let i = 0;
  let j = 0;
  // RC6 规范混合次数为 3*max(2r+4, c)：r=20 时 S 表 44 字，但密钥超过 176 字节（c>44）时必须混满 c，
  // 否则与标准 RC6 不互通（The RC6 Block Cipher §2.2 Key Schedule）。
  const mixSteps = 3 * Math.max(44, c);
  for (let step = 0; step < mixSteps; step += 1) {
    a = s[i] = rc6RotateLeft((s[i] + a + b) >>> 0, 3);
    b = l[j] = rc6RotateLeft((l[j] + a + b) >>> 0, (a + b) % 32);
    i = (i + 1) % 44;
    j = (j + 1) % c;
  }
  return { s, l };
};
const rc6Quarter = (block: Uint8Array, offset: number) => [
  block[offset] | (block[offset + 1] << 8) | (block[offset + 2] << 16) | (block[offset + 3] << 24),
  block[offset + 4] | (block[offset + 5] << 8) | (block[offset + 6] << 16) | (block[offset + 7] << 24),
  block[offset + 8] | (block[offset + 9] << 8) | (block[offset + 10] << 16) | (block[offset + 11] << 24),
  block[offset + 12] | (block[offset + 13] << 8) | (block[offset + 14] << 16) | (block[offset + 15] << 24),
];
const rc6WriteQuarter = (target: Uint8Array, offset: number, words: number[]) => {
  words.forEach((word, index) => {
    target[offset + 4 * index] = word & 255;
    target[offset + 4 * index + 1] = (word >>> 8) & 255;
    target[offset + 4 * index + 2] = (word >>> 16) & 255;
    target[offset + 4 * index + 3] = (word >>> 24) & 255;
  });
};
const rc6F = (word: number) => rc6RotateLeft(Math.imul(word, ((word << 1) | 1) >>> 0) >>> 0, 5);
// RC6 轮：(A,B,C,D) ← (B, (C^u)<<<t + S[2i+1], D, (A^t)<<<u + S[2i])，轮末白化 A+=S[42]、C+=S[43]。
const rc6EncryptBlock = (block: Uint8Array, s: Uint32Array) => {
  const [p0, p1, p2, p3] = rc6Quarter(block, 0);
  let a = p0;
  let b = (p1 + s[0]) >>> 0;
  let c = p2;
  let d = (p3 + s[1]) >>> 0;
  for (let round = 1; round <= 20; round += 1) {
    const t = rc6F(b);
    const u = rc6F(d);
    const newA = (rc6RotateLeft((a ^ t) >>> 0, u % 32) + s[2 * round]) >>> 0;
    const newC = (rc6RotateLeft((c ^ u) >>> 0, t % 32) + s[2 * round + 1]) >>> 0;
    const oldB = b;
    const oldD = d;
    a = oldB;
    b = newC;
    c = oldD;
    d = newA;
  }
  const output = new Uint8Array(16);
  rc6WriteQuarter(output, 0, [(a + s[42]) >>> 0, b, (c + s[43]) >>> 0, d]);
  return output;
};
const rc6DecryptBlock = (block: Uint8Array, s: Uint32Array) => {
  const [w0, w1, w2, w3] = rc6Quarter(block, 0);
  let a = (w0 - s[42]) >>> 0;
  let b = w1;
  let c = (w2 - s[43]) >>> 0;
  let d = w3;
  for (let round = 20; round >= 1; round -= 1) {
    const oldA = a;
    const oldB = b;
    const oldC = c;
    const oldD = d;
    a = oldD;
    b = oldA;
    c = oldB;
    d = oldC;
    const u = rc6F(d);
    const t = rc6F(b);
    c = (rc6RotateRight((c - s[2 * round + 1]) >>> 0, t % 32) ^ u) >>> 0;
    a = (rc6RotateRight((a - s[2 * round]) >>> 0, u % 32) ^ t) >>> 0;
  }
  const output = new Uint8Array(16);
  rc6WriteQuarter(output, 0, [a, (b - s[0]) >>> 0, c, (d - s[1]) >>> 0]);
  return output;
};
const rc6Transform = (value: string, secret: string, decode: boolean, variant: string) => {
  if (!value) return '';
  const rawMode = variant === 'raw';
  const keyBytes = parseKeyBytes(secret, 'RC6');
  const { s } = rc6KeySchedule(keyBytes);
  if (!decode) {
    const dataBytes = utf8Encoder.encode(value);
    if (rawMode && dataBytes.length % 16 !== 0) throw new Error('RC6 raw 模式要求明文为 16 字节整块（不自动填充），请改用 pkcs7 模式或手动补齐');
    const padded = rawMode ? dataBytes : padToBlock(dataBytes, 16);
    const output = new Uint8Array(padded.length);
    for (let offset = 0; offset < padded.length; offset += 16) {
      output.set(rc6EncryptBlock(padded.slice(offset, offset + 16), s), offset);
    }
    return bytesToHex(output);
  }
  const cipherBytes = hexToBytes(value.trim());
  if (cipherBytes.length % 16 !== 0) throw new Error('RC6 解密输入的 Hex 长度必须是 16 字节的整数倍');
  const output = new Uint8Array(cipherBytes.length);
  for (let offset = 0; offset < cipherBytes.length; offset += 16) {
    output.set(rc6DecryptBlock(cipherBytes.slice(offset, offset + 16), s), offset);
  }
  return utf8Decoder.decode(rawMode ? output : unpadFromBlock(output, 16));
};

export const parityKeyedOperations: Operation[] = [
  {
    id: 'otp',
    category: 'crypto',
    name: { zh: '一次一密', en: 'One-Time Pad' },
    summary: {
      zh: '字节级 XOR 一次一密：数据与密钥逐字节异或，编码输出 Hex，解码输入 Hex。密钥在顶部密钥栏输入（UTF-8），长度必须不小于数据，否则按一次一密语义报错。',
      en: 'Byte-wise XOR one-time pad: XOR data with the key, hex output/input. Enter the key (UTF-8) in the top key bar; it must be at least as long as the data.',
    },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret'],
  },
  {
    id: 'multiplicative',
    category: 'crypto',
    name: { zh: '乘法密码', en: 'Multiplicative Cipher' },
    summary: {
      zh: 'mod 26 乘数密码：c = p×k mod 26，解码用模逆元。密钥在顶部密钥栏输入（默认 7，必须与 26 互素），非字母原样保留。',
      en: 'Multiplicative cipher mod 26: c = p*k mod 26 with modular inverse for decoding. Key in the top key bar (default 7, coprime with 26).',
    },
    params: ['secret'],
  },
  {
    id: 'fractionated-morse',
    category: 'crypto',
    name: { zh: '分组摩斯', en: 'Fractionated Morse' },
    summary: {
      zh: '先展开为摩斯流（字母间插 x、词间 xx，按 3 分组补 .），再用 26 字母混合表替换三元组。密钥在顶部密钥栏输入混合表关键词，可空=标准字母表；解码末尾可能多出补位伪迹字母（dcode 同此说明）。',
      en: 'Expands to a Morse stream (x between letters, xx between words, pad to 3) then substitutes trigrams via a mixed alphabet. Keyword in the top key bar, empty = standard alphabet; a padded trailing letter may appear on decode.',
    },
    params: ['secret'],
  },
  {
    id: 'fenham',
    category: 'crypto',
    name: { zh: '费娜姆（Vernam）', en: 'Fenham (Vernam)' },
    summary: {
      zh: 'Vernam 五比特异或（字母流）：字母转 5bit（A=00000）与密钥字母逐位异或，编码输出空格分隔的 5bit 二进制组，解码输入二进制组还原字母。密钥在顶部密钥栏输入字母密钥。',
      en: 'Vernam 5-bit XOR on letters (A=00000): encode outputs space-separated 5-bit groups, decode restores letters from bit groups. Letter key in the top key bar.',
    },
    params: ['secret'],
  },
  {
    id: 'running-key',
    category: 'crypto',
    name: { zh: '滚动密钥', en: 'Running Key' },
    summary: {
      zh: '滚动密钥维吉涅：密钥是一段长文本且不循环，非字母不消耗密钥，密钥不够长时报错。密钥在顶部密钥栏输入。',
      en: 'Vigenere variant with a long non-repeating key; non-letters skip key consumption and a short key raises an error. Key in the top key bar.',
    },
    params: ['secret'],
  },
  {
    id: 'bazeries',
    category: 'crypto',
    name: { zh: 'Bazeries', en: 'Bazeries' },
    summary: {
      zh: '数字键双用途：N 写成英文单词按行填第二张 5x5 方格（标准方格按列），明文按 N 的各位数字循环分组、组内倒序后做两格同位替换。数字密钥在顶部密钥栏输入（1-9 位，各位 1-9）。',
      en: 'Numeric key used twice: N spelled in English keys the second 5x5 grid (first grid is the alphabet column-wise), text is split by the digits of N, reversed per group, then substituted between grids. Numeric key in the top key bar.',
    },
    params: ['secret'],
  },
  {
    id: 'kamasutra',
    category: 'crypto',
    name: { zh: '迦玛索罗', en: 'Kamasutra' },
    summary: {
      zh: '8 对字母互换（自逆替换）：密钥在顶部密钥栏输入 16 个互异字母（默认 ABCDEFGHIJKLMNOP），每对字母互相映射。',
      en: 'Eight reciprocal letter pairs: enter 16 distinct letters in the top key bar (default ABCDEFGHIJKLMNOP); each pair swaps letters.',
    },
    params: ['secret'],
  },
  {
    id: 'm209',
    category: 'crypto',
    name: { zh: 'M-209', en: 'M-209' },
    summary: {
      zh: 'Hagelin M-209：六引钉轮（26/25/23/21/19/17）+27 凸柱杆，反转 Beaufort 输出，自逆。密钥在顶部密钥栏可空=内置主流参数档（维基百科示例全键）；也可填描述串 p:6 组 0/1 引钉（26/25/23/21/19/17）|l:27 根 杆如 3-6,0-6（0=空，轮号 1-6）。',
      en: 'Hagelin M-209: six pin wheels (26/25/23/21/19/17) plus 27 lug bars, reversed Beaufort output, reciprocal. Empty key = built-in profile (Wikipedia example); or a description p:<six 0/1 pin groups>|l:<27 bars like 3-6,0-6> in the top key bar.',
    },
    params: ['secret'],
  },
  {
    id: 'rc2',
    category: 'crypto',
    name: { zh: 'RC2', en: 'RC2' },
    summary: {
      zh: 'RC2（RFC 2268）ECB，输入输出 Hex。密钥在顶部密钥栏输入（纯偶长 hex 按原始字节，否则按 UTF-8），有效密钥位由 keyBits 控制（默认 64）；variant=pkcs7（默认，自动填充/剥除）或 raw（明文须为 8 字节整块、不填充不剥除，适配裸测试向量）。',
      en: 'RC2 (RFC 2268) ECB, hex in/out. Key in the top key bar (pure even-length hex = raw bytes, otherwise UTF-8); effective key bits via keyBits (default 64); variant=pkcs7 (default) or raw for bare test vectors.',
    },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'keyBits', 'variant'],
  },
  {
    id: 'rc6',
    category: 'crypto',
    name: { zh: 'RC6', en: 'RC6' },
    summary: {
      zh: 'RC6-32/20/b ECB（128 位分组，密钥 1-255 字节），输入输出 Hex。密钥在顶部密钥栏输入（纯偶长 hex 按原始字节，否则按 UTF-8）；variant=pkcs7（默认，自动填充/剥除）或 raw（明文须为 16 字节整块、不填充不剥除，适配裸测试向量）。',
      en: 'RC6-32/20/b ECB (128-bit blocks, keys 1-255 bytes), hex in/out. Key in the top key bar (pure even-length hex = raw bytes, otherwise UTF-8); variant=pkcs7 (default) or raw for bare test vectors.',
    },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'variant'],
  },
];

export const parityKeyedDefaultParams: Partial<Record<ParamKey, string>> = {
  // variant/secret 是全局共享键（默认值由 operations.ts 字面量统一给），这里只放本组特有键。
  keyBits: '64',
};

// 带 key 密文无稳定形状特征，本组形状探针为空（契约允许）。
export const parityKeyedLooksLike: ParityShapeProbe[] = [];

const nul8 = '\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000';
const bytes00To0f = Array.from({ length: 16 }, (_, index) => String.fromCharCode(index)).join('');

export const parityKeyedVectors: ParityVector[] = [
  // 自造 round-trip 向量（密钥长度满足一次一密语义）
  { id: 'otp', plain: 'ATTACKATDAWN', params: { secret: 'CRYPTIIQUEEN' } },
  { id: 'multiplicative', plain: 'ATTACKATDAWN', params: { secret: '7' } },
  // 权威向量：https://www.dcode.fr/fractionated-morse （DCODE MORSE → JVLNVGZQODSGY，标准字母表）。
  // 编码方向补位 1 个 '.'，解码会按确定性规则产出补位伪迹 "DCODE MORSE E"，故按 decode 方向断言。
  { id: 'fractionated-morse', plain: 'DCODE MORSE E', cipher: 'JVLNVGZQODSGY', direction: 'decode' },
  // 自造 round-trip：无补位伪迹的样本（摩斯流长恰为 3 的倍数）
  { id: 'fractionated-morse', plain: 'OTPAD', params: { secret: 'KAPPA' } },
  { id: 'fenham', plain: 'ATTACKATDAWN', params: { secret: 'QUEENLY' } },
  { id: 'running-key', plain: 'ATTACKATDAWN', params: { secret: 'THISISALONGSECRETKEYTEXT' } },
  // 权威向量：https://www.dcode.fr/bazeries-cipher （N=23、单词 TWENTYTHREE、DCODE → DLSLO，解码互逆）
  { id: 'bazeries', plain: 'DCODE', cipher: 'DLSLO', params: { secret: '23' } },
  { id: 'kamasutra', plain: 'ATTACKATDAWN', params: { secret: 'QWERTYUIOPASDFGH' } },
  // 权威向量：https://en.wikipedia.org/wiki/M-209 示例全键（内置主流参数档）编码 26 个 A 的校验串
  { id: 'm209', plain: 'AAAAAAAAAAAAAAAAAAAAAAAAAA', cipher: 'TNJUWAUQTKCZKNUTOTBCWARWIO' },
  { id: 'm209', plain: 'ATTACKATDAWN' },
  // 权威向量：https://www.rfc-editor.org/rfc/rfc2268（T=8、PKBS=63；裸块无填充，走 variant=raw）
  { id: 'rc2', plain: nul8, cipher: 'ebb773f993278eff', direction: 'decode', params: { secret: '0000000000000000', keyBits: '63', variant: 'raw' } },
  // 权威向量：https://www.rfc-editor.org/rfc/rfc2268（T=8、PKBS=64、明文 ff×8；0xff 字节经 UTF-8 解码为替换符）
  { id: 'rc2', plain: '\ufffd'.repeat(8), cipher: '278b27e42e2f0d49', direction: 'decode', params: { secret: 'ffffffffffffffff', keyBits: '64', variant: 'raw' } },
  // 权威向量：https://www.rfc-editor.org/rfc/rfc2268（T=8、PKBS=64、明文 10 00 00 00 00 00 00 01）
  { id: 'rc2', plain: '\u0010\u0000\u0000\u0000\u0000\u0000\u0000\u0001', cipher: '30649edf9be7d2c2', direction: 'decode', params: { secret: '3000000000000000', keyBits: '64', variant: 'raw' } },
  // 权威向量：https://www.rfc-editor.org/rfc/rfc2268（T=1、PKBS=64）
  { id: 'rc2', plain: nul8, cipher: '61a8a244adacccf0', direction: 'decode', params: { secret: '88', keyBits: '64', variant: 'raw' } },
  // 权威向量：https://www.rfc-editor.org/rfc/rfc2268（T=7、PKBS=64）
  { id: 'rc2', plain: nul8, cipher: '6ccf4308974c267f', direction: 'decode', params: { secret: '88bca90e90875a', keyBits: '64', variant: 'raw' } },
  { id: 'rc2', plain: 'SECRETMESSAGE', params: { secret: 'passphrase', keyBits: '64' } },
  // 权威向量：RC6-32/20/16，https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00（裸块，走 variant=raw）
  { id: 'rc6', plain: bytes00To0f, cipher: '3a96f9c7f6755cfe46f00e3dcd5d2a3c', direction: 'decode', params: { secret: '000102030405060708090a0b0c0d0e0f', variant: 'raw' } },
  { id: 'rc6', plain: 'ATTACKATDAWN', params: { secret: 'hexor-text-key' } },
];

const transformById = (id: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): string => {
  switch (id) {
    case 'otp':
      return otpTransform(input, params.secret, direction === 'decode');
    case 'multiplicative':
      return multiplicativeTransform(input, params.secret, direction === 'decode');
    case 'fractionated-morse':
      return direction === 'decode' ? fractionatedDecode(input, params.secret) : fractionatedEncode(input, params.secret);
    case 'fenham':
      return direction === 'decode' ? fenhamDecode(input, params.secret) : fenhamEncode(input, params.secret);
    case 'running-key':
      return runningKeyTransform(input, params.secret, direction === 'decode');
    case 'bazeries':
      return bazeriesTransform(input, params.secret, direction === 'decode');
    case 'kamasutra':
      return kamasutraTransform(input, params.secret);
    case 'm209':
      return m209Transform(input, params.secret);
    case 'rc2':
      return rc2Transform(input, params.secret, params.keyBits, direction === 'decode', params.variant);
    case 'rc6':
      return rc6Transform(input, params.secret, direction === 'decode', params.variant);
    default:
      throw new Error(`parityKeyed 不支持的操作：${id}`);
  }
};

export async function parityKeyedTransform(id: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): Promise<string> {
  return transformById(id, direction, input, params);
}
