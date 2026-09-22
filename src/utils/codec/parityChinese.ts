// 批次 O Lane C：中文类 23 操作（社会主义核心价值观、笔画码、阴阳怪气、八卦符、中文电码、
// 想曰、玛卡巴卡、音音、兽音、元素周期表、火星文、盲文、音符、花朵、字母、箭头、汉字密码、
// 国际音标、空白符、Deadfish、Spoon、曼彻斯特、Emoji）。
// 风格对齐 chineseCiphers.ts：码表 + 纯函数编解码 + 与码表同源的形状探针。
// 全部纯文本进出、零联网、零动态代码执行；超大码表拆在 parityChineseTables.ts 惰性构建。
import type { Direction, Operation, OperationId, ParamKey } from './types';
import type { ParityShapeProbe, ParityVector } from './parityTypes';
import { utf8Encoder, utf8Decoder } from './alphabets';
import { bytesToBase64, base64ToBytes } from './bases';
import { getTelecodeMaps, getMarsMaps, MAKKAPAKKA_RULES, ELEMENT_SYMBOLS } from './parityChineseTables';

const strictUtf8 = new TextDecoder('utf-8', { fatal: true });

const bytesToText = (bytes: Uint8Array): string => {
  try {
    return strictUtf8.decode(bytes);
  } catch {
    throw new Error('解码结果不是合法的 UTF-8 文本：密文可能不完整或被二次编码。');
  }
};

const bitsToBytes = (bits: number[]): Uint8Array => {
  const usable = bits.length - (bits.length % 8);
  const bytes: number[] = [];
  for (let position = 0; position < usable; position += 8) {
    let byte = 0;
    for (let offset = 0; offset < 8; offset += 1) byte = (byte << 1) | bits[position + offset];
    bytes.push(byte);
  }
  return new Uint8Array(bytes);
};

const bytesToBits = (bytes: Uint8Array): number[] => {
  const bits: number[] = [];
  for (const byte of bytes) for (let offset = 7; offset >= 0; offset -= 1) bits.push((byte >>> offset) & 1);
  return bits;
};

// ---- 社会主义核心价值观编码 ----
// 算法：UTF-8 字节流 → 大写 hex；每个 hex 数字转十二进制数字（0-9 单数字；A-F 拆为
// [10,n-10] 或 [11,n-6] 两数字，编码取确定性分支 [10,n-10]，解码两分支都兼容）；每个
// 十二进制数字 d 输出 24 字表中第 2d/2d+1 两字组成的词。
// 来源：https://github.com/sym233/core-values-encoder（src/index.js）
const CORE_VALUES = '富强民主文明和谐自由平等公正法治爱国敬业诚信友善';

const coreValuesEncode = (input: string): string => {
  if (!input) return '';
  let hex = '';
  for (const byte of utf8Encoder.encode(input)) hex += byte.toString(16).padStart(2, '0').toUpperCase();
  let output = '';
  for (const char of hex) {
    const value = Number.parseInt(char, 16);
    const digits = value < 10 ? [value] : [10, value - 10];
    for (const digit of digits) output += CORE_VALUES[2 * digit] + CORE_VALUES[2 * digit + 1];
  }
  return output;
};

const coreValuesDecode = (input: string): string => {
  const body = input.trim().replace(/\s+/g, '');
  if (!body) return '';
  const duo: number[] = [];
  for (const char of body) {
    const index = CORE_VALUES.indexOf(char);
    if (index === -1 || index % 2 === 1) continue;
    duo.push(index >> 1);
  }
  if (!duo.length) throw new Error('输入不含核心价值观编码字符（富强民主文明和谐…），无法按核心价值观解码。');
  let hex = '';
  let position = 0;
  while (position < duo.length) {
    const digit = duo[position];
    if (digit < 10) {
      hex += digit.toString(16);
    } else {
      if (position + 1 >= duo.length) throw new Error('核心价值观编码长度异常：A-F 拆分缺少后随数字。');
      const follower = duo[position + 1];
      hex += (digit === 10 ? follower + 10 : follower + 6).toString(16);
      position += 1;
    }
    position += 1;
  }
  if (hex.length % 2 !== 0) throw new Error('核心价值观编码还原出的 hex 位数异常，请确认密文完整。');
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return bytesToText(bytes);
};

// ---- 汉字笔画码 ----
// 最佳可得定义（无公开权威实现）：UTF-8 每字节按 5 进制展开为固定 4 位（5^4=625 ≥ 256），
// 每位映射汉字五种基本笔画字形（横竖撇点折）：乙=0 一=1 丨=2 丿=3 丶=4。
const STROKE_DIGITS = '乙一丨丿丶';

const strokeEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const byte of utf8Encoder.encode(input)) {
    let value = byte;
    for (let power = 125; power >= 1; power /= 5) {
      const digit = Math.floor(value / power);
      output += STROKE_DIGITS[digit];
      value -= digit * power;
    }
  }
  return output;
};

const strokeDecode = (input: string): string => {
  const body = input.trim().replace(/\s+/g, '');
  if (!body) return '';
  const chars = [...body];
  if (chars.length % 4 !== 0) throw new Error('汉字笔画码密文长度须为 4 的倍数（每字节 4 个笔画位）。');
  const bytes: number[] = [];
  for (let position = 0; position < chars.length; position += 4) {
    let value = 0;
    for (let offset = 0; offset < 4; offset += 1) {
      const digit = STROKE_DIGITS.indexOf(chars[position + offset]);
      if (digit === -1) throw new Error(`密文含非法笔画符「${chars[position + offset]}」：只接受 乙/一/丨/丿/丶。`);
      value = value * 5 + digit;
    }
    if (value > 255) throw new Error('汉字笔画码出现超出字节范围的笔画组，密文可能不完整。');
    bytes.push(value);
  }
  return bytesToText(new Uint8Array(bytes));
};

// ---- 阴阳怪气编码 ----
// 算法（ToolsFx/WhatsInYourClipboard ctfExtra.js 流派逐位复刻）：每字符码点 <127 → 标志位
// 0 + 8bit；否则标志位 1 + 16bit（增补平面字符拆为高低代理各 1+16bit）。位流逐位映射
// 0 →「就 这 ¿ 」、1 →「不 会 吧 ？ 」。解码只扫每 token 首字（就=0/不=1），免疫空格差异。
// 来源：https://github.com/Henglie/EBCTFCodeBox src/core/fancy2.js
const YYGQ_ZERO = '就 这 ¿ ';
const YYGQ_ONE = '不 会 吧 ？ ';

const yygqEncode = (input: string): string => {
  if (!input) return '';
  let bits = '';
  for (const char of input) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 127) {
      bits += '0' + code.toString(2).padStart(8, '0');
    } else if (code <= 0xffff) {
      bits += '1' + code.toString(2).padStart(16, '0');
    } else {
      const high = 0xd800 + ((code - 0x10000) >> 10);
      const low = 0xdc00 + ((code - 0x10000) & 0x3ff);
      bits += '1' + high.toString(2).padStart(16, '0');
      bits += '1' + low.toString(2).padStart(16, '0');
    }
  }
  let output = '';
  for (const bit of bits) output += bit === '0' ? YYGQ_ZERO : YYGQ_ONE;
  return output;
};

const yygqDecode = (input: string): string => {
  if (!input.trim()) return '';
  let bits = '';
  for (const char of input) {
    if (char === '就') bits += '0';
    else if (char === '不') bits += '1';
  }
  if (!bits) throw new Error('输入不含「就/不」标志字，无法按阴阳怪气编码解码。');
  let position = 0;
  let output = '';
  while (position < bits.length) {
    const need = bits[position] === '0' ? 9 : 17;
    if (position + need > bits.length) throw new Error('阴阳怪气位流不完整：密文可能被截断或复制缺字。');
    output += String.fromCharCode(Number.parseInt(bits.slice(position + 1, position + need), 2));
    position += need;
  }
  return output;
};

// ---- 八卦符编码 ----
// 八卦符流：UTF-8 位流按 3bit 分组映射 Unicode 八卦符号 ☰☱☲☳☴☵☶☷（U+2630-2637，
// 000-111 与爻位一一对应，☰=000 … ☷=111），尾部不足 3 位补 0；与既有六十四卦（6bit）互补。
// 来源：Unicode「Trigram Symbols」U+2630-2637 顺序。
const BAGUA_SYMBOLS = '☰☱☲☳☴☵☶☷';

const baguaEncode = (input: string): string => {
  if (!input) return '';
  const bits = bytesToBits(utf8Encoder.encode(input));
  while (bits.length % 3 !== 0) bits.push(0);
  let output = '';
  for (let position = 0; position < bits.length; position += 3) {
    const value = (bits[position] << 2) | (bits[position + 1] << 1) | bits[position + 2];
    output += BAGUA_SYMBOLS[value];
  }
  return output;
};

const baguaDecode = (input: string): string => {
  const chars = [...input.trim()];
  if (!chars.length) return '';
  const bits: number[] = [];
  for (const char of chars) {
    const index = BAGUA_SYMBOLS.indexOf(char);
    if (index === -1) throw new Error(`密文含八卦符（☰-☷）之外的字符「${char}」，请确认输入为八卦符流。`);
    bits.push((index >> 2) & 1, (index >> 1) & 1, index & 1);
  }
  return bytesToText(bitsToBytes(bits));
};

// ---- 中文电码 ----
// 中文商用电码：汉字 ↔ 4 位数字组，编码输出以空格分隔；码本（1981 大陆标准，7085 条）
// 见 parityChineseTables.ts，惰性构建正反 Map。
// 来源：https://github.com/milkcask/ChineseTelegraphCode（cn 表）
const telecodeEncode = (input: string): string => {
  const body = input.trim();
  if (!body) return '';
  const { byChar } = getTelecodeMaps();
  const groups: string[] = [];
  for (const char of body) {
    if (/\s/.test(char)) continue;
    const code = byChar.get(char);
    if (code === undefined) throw new Error(`汉字「${char}」不在中文电码本（1981 大陆标准本）中，无法编码。`);
    groups.push(code);
  }
  if (!groups.length) throw new Error('输入不含可编码的汉字，中文电码只接受码本内汉字。');
  return groups.join(' ');
};

const telecodeDecode = (input: string): string => {
  const body = input.trim();
  if (!body) return '';
  const { byCode } = getTelecodeMaps();
  const tokens = body.split(/[\s,，、]+/).filter(Boolean);
  let output = '';
  for (const token of tokens) {
    if (!/^[0-9]{4}$/.test(token)) throw new Error(`电码「${token}」不是 4 位数字组，请确认密文格式（如 0022 0948）。`);
    const char = byCode.get(token);
    if (char === undefined) throw new Error(`电码 ${token} 不在中文电码本中，请确认密文完整。`);
    output += char;
  }
  return output;
};

// ---- 想曰（词典流派） ----
// 最佳可得定义：在线想曰（fzxx/XiangYue）与 Abracadabra（魔曰）内核均为 AES/ChaCha20 加密
// 流，无法纯词典复刻；此处按 Abracadabra 词典流派自建 65 词古文小词典，与 base64 字符表
// 一一对应：UTF-8 → base64 → 逐字符映射两字短语，前缀「想曰：」。仅保证本模块互逆，
// 与在线想曰密文不兼容（词典为常用子集，覆盖率即 65 词全集）。
// 流派参考：https://github.com/SheepChef/Abracadabra、https://github.com/fzxx/XiangYue
const XIANGYUE_PREFIX = '想曰：';
const XIANGYUE_BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const XIANGYUE_DICT = [
  '思君', '忆昔', '闻钟', '观澜', '抚琴', '听雨', '醉月', '折柳', '踏雪', '寻梅',
  '问天', '采薇', '牧云', '归舟', '点灯', '煮酒', '焚香', '扫叶', '挑灯', '执笔',
  '研墨', '铺纸', '落子', '斟茶', '拂尘', '掩卷', '凭栏', '倚楼', '临江', '登山',
  '涉水', '穿林', '打渔', '砍柴', '负薪', '悬梁', '刺股', '囊萤', '映雪', '凿壁',
  '偷光', '闻鸡', '起舞', '枕戈', '待旦', '破釜', '沉舟', '卧薪', '尝胆', '朝露',
  '晚霞', '春花', '秋月', '夏荷', '冬雪', '晨钟', '暮鼓', '青山', '绿水', '白云',
  '苍狗', '沧海', '桑田', '南柯', '一梦',
];

const xiangyueByChar = new Map(XIANGYUE_BASE64.split('').map((char, index) => [char, XIANGYUE_DICT[index] ?? '']));
const xiangyueByPhrase = new Map(XIANGYUE_DICT.map((phrase, index) => [phrase, XIANGYUE_BASE64[index] ?? '']));

const xiangyueEncode = (input: string): string => {
  if (!input) return '';
  const base64 = bytesToBase64(utf8Encoder.encode(input));
  let output = '';
  for (const char of base64) output += xiangyueByChar.get(char) ?? char;
  return XIANGYUE_PREFIX + output;
};

const xiangyueDecode = (input: string): string => {
  const trimmed = input.trim();
  if (!trimmed) return '';
  const body = trimmed.startsWith(XIANGYUE_PREFIX) ? trimmed.slice(XIANGYUE_PREFIX.length) : trimmed;
  if (!body) throw new Error('想曰密文缺少「想曰：」前缀后的密文主体。');
  const glyphs = [...body];
  if (glyphs.length % 2 !== 0) throw new Error('想曰密文长度须为偶数（每词两字），请确认复制完整。');
  const chars: string[] = [];
  for (let position = 0; position < glyphs.length; position += 2) {
    const phrase = glyphs[position] + glyphs[position + 1];
    const mapped = xiangyueByPhrase.get(phrase);
    if (mapped === undefined) throw new Error(`想曰密文含词典外词组「${phrase}」：本实现只接受内置 65 词古文词典。`);
    chars.push(mapped);
  }
  const padded = chars.join('') + '='.repeat((4 - (chars.length % 4)) % 4);
  try {
    return utf8Decoder.decode(base64ToBytes(padded));
  } catch {
    throw new Error('想曰密文解码失败：短语序列无法还原为合法 base64/UTF-8，请确认复制完整。');
  }
};

// ---- 玛卡巴卡 ----
// 玛卡巴卡语言：base64 字符集（A-Z a-z 0-9 + / =）→ 音节段（均以「轰」结尾），规则表见
// parityChineseTables.ts；编码仅接受表内字符（其余提示先做 Base64），解码按段长降序贪婪
// 匹配、跳过未知字符。
// 来源：https://github.com/Henglie/EBCTFCodeBox src/core/exclusiveCodec.js
const makabakaEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const char of input) {
    const segment = MAKKAPAKKA_RULES[char];
    if (segment === undefined) {
      throw new Error(`玛卡巴卡编码仅接受字母、数字与 +/= 字符（密文出现「${char}」）；如需编码任意文本请先做 Base64。`);
    }
    output += segment;
  }
  return output;
};

interface MakabakaOrder {
  segments: string[];
  keysBySegment: Map<string, string>;
}

let makabakaCache: MakabakaOrder | null = null;

const makabakaDecodeOrder = (): MakabakaOrder => {
  if (makabakaCache) return makabakaCache;
  const segments = Object.keys(MAKKAPAKKA_RULES)
    .map(key => MAKKAPAKKA_RULES[key])
    .sort((left, right) => right.length - left.length);
  const keysBySegment = new Map<string, string>();
  for (const key of Object.keys(MAKKAPAKKA_RULES)) {
    const segment = MAKKAPAKKA_RULES[key];
    if (!keysBySegment.has(segment)) keysBySegment.set(segment, key);
  }
  makabakaCache = { segments, keysBySegment };
  return makabakaCache;
};

const makabakaDecode = (input: string): string => {
  const body = input.trim();
  if (!body) return '';
  const { segments, keysBySegment } = makabakaDecodeOrder();
  let output = '';
  let position = 0;
  while (position < body.length) {
    let matched = false;
    for (const segment of segments) {
      if (body.startsWith(segment, position)) {
        output += keysBySegment.get(segment) ?? '';
        position += segment.length;
        matched = true;
        break;
      }
    }
    if (!matched) position += 1;
  }
  return output;
};

// ---- 兽音 / 音音（4 字符 codec 家族） ----
// 算法（sgdrg15rdg/beast_js 权威实现）：每 UTF-16 码元 → 4 位 hex；逐位加位置偏移
// （s%16 回绕）后按 4*商+余 拆为 codec 两字符；前缀 codec[3]+codec[1]+codec[0]、
// 后缀 codec[2]。兽音 codec 固定「嗷呜啊~」（https://github.com/sgdrg15rdg/beast_js、
// https://github.com/SycAlright/beast_sdk）；音音译者无公开权威字符集，按 CSDN《兽音译器
// 的编码原理》所述 4 字符可自定义，取「叮咚嘟锵」最佳可得定义。
const BEAST_CODEC = '嗷呜啊~';
const YIN_CODEC = '叮咚嘟锵';

const beastFamilyEncode = (input: string, codec: string): string => {
  if (!input) return '';
  let hex = '';
  for (let index = 0; index < input.length; index += 1) hex += input.charCodeAt(index).toString(16).padStart(4, '0');
  let middle = '';
  for (let position = 0; position < hex.length; position += 1) {
    let value = Number.parseInt(hex[position], 16) + (position % 16);
    if (value >= 16) value -= 16;
    middle += codec[Math.floor(value / 4)] + codec[value % 4];
  }
  return codec[3] + codec[1] + codec[0] + middle + codec[2];
};

const beastFamilyDecode = (input: string, codec: string, label: string): string => {
  const trimmed = input.trim();
  if (!trimmed) return '';
  const prefix = codec[3] + codec[1] + codec[0];
  const start = trimmed.indexOf(prefix);
  const end = trimmed.lastIndexOf(codec[2]);
  if (start === -1 || end === -1 || end <= start + prefix.length) {
    throw new Error(`${label}密文须形如「${prefix}…${codec[2]}」，未找到前后缀，请确认复制完整。`);
  }
  const middle = trimmed.slice(start + prefix.length, end);
  if (middle.length % 2 !== 0) throw new Error(`${label}密文中间部分长度须为偶数，密文可能不完整。`);
  let hex = '';
  for (let position = 0; position < middle.length; position += 2) {
    const high = codec.indexOf(middle[position]);
    const low = codec.indexOf(middle[position + 1]);
    if (high === -1 || low === -1) throw new Error(`${label}密文含 ${label}字符集（${codec}）之外的字符。`);
    let value = high * 4 + low - (position / 2) % 16;
    if (value < 0) value += 16;
    hex += value.toString(16);
  }
  let output = '';
  for (let position = 0; position + 4 <= hex.length; position += 4) {
    output += String.fromCharCode(Number.parseInt(hex.slice(position, position + 4), 16));
  }
  return output;
};

const shouyinEncode = (input: string): string => beastFamilyEncode(input, BEAST_CODEC);
const shouyinDecode = (input: string): string => beastFamilyDecode(input, BEAST_CODEC, '兽音');
const yinyinEncode = (input: string): string => beastFamilyEncode(input, YIN_CODEC);
const yinyinDecode = (input: string): string => beastFamilyDecode(input, YIN_CODEC, '音音');

// ---- 元素周期表编码 ----
// 字符 Unicode 码点 ↔ 原子序数（1-118），输出元素符号以空格分隔；118 符号表见
// parityChineseTables.ts。
// 来源：https://github.com/Henglie/EBCTFCodeBox src/core/cn.js（修正 53 号 I/30 号 Zn 误写版）
const elementEncode = (input: string): string => {
  if (!input) return '';
  const symbols: string[] = [];
  for (const char of input) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 1 || code > ELEMENT_SYMBOLS.length) {
      throw new Error(`字符「${char}」（码点 ${code}）超出元素周期表编码范围 1-${ELEMENT_SYMBOLS.length}。`);
    }
    symbols.push(ELEMENT_SYMBOLS[code - 1]);
  }
  return symbols.join(' ');
};

const elementDecode = (input: string): string => {
  const body = input.trim();
  if (!body) return '';
  let output = '';
  for (const token of body.split(/\s+/).filter(Boolean)) {
    const index = ELEMENT_SYMBOLS.indexOf(token);
    if (index === -1) throw new Error(`「${token}」不是合法元素符号，元素周期表编码只接受 118 个元素符号。`);
    output += String.fromCodePoint(index + 1);
  }
  return output;
};

// ---- 火星文 ----
// 火星文映射层：简体 ↔ 火星文逐字替换（3508 对映射表见 parityChineseTables.ts，惰性
// 构建正反 Map），表外字符双向原样透传（与公开转换器行为一致）。
// 来源：https://github.com/zhanyuzhang/text-convert（常用字表索引对齐提取）
const marsEncode = (input: string): string => {
  if (!input) return '';
  const { toMars } = getMarsMaps();
  let output = '';
  for (const char of input) output += toMars.get(char) ?? char;
  return output;
};

const marsDecode = (input: string): string => {
  if (!input) return '';
  const { toPlain } = getMarsMaps();
  let output = '';
  for (const char of input) output += toPlain.get(char) ?? char;
  return output;
};

// ---- 盲文 ----
// 盲文（UEB 一级盲文，Unicode U+2800-28FF 六点位型，dot1=1…dot6=32 → U+2800+点阵掩码）：
// a-z 用标准字母点阵；大写前缀 ⠠（第 6 点）；数字前缀 ⠼（第 3456 点）后接 a-j 表 1-9/0；
// 空格 → ⠀（U+2800 空点阵）；其余字符不支持（明确报错）。
// 点位表来源：Wikipedia「Braille」/ Unicode「Braille Patterns」。
const BRAILLE_LETTERS = '⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵';
const BRAILLE_CAPITAL = '⠠';
const BRAILLE_NUMBER = '⠼';
const BRAILLE_BLANK = '⠀';

const brailleEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const char of input) {
    if (char === ' ') {
      output += BRAILLE_BLANK;
      continue;
    }
    if (char >= 'a' && char <= 'z') {
      output += BRAILLE_LETTERS[char.charCodeAt(0) - 97];
      continue;
    }
    if (char >= 'A' && char <= 'Z') {
      output += BRAILLE_CAPITAL + BRAILLE_LETTERS[char.charCodeAt(0) - 65];
      continue;
    }
    if (char >= '0' && char <= '9') {
      output += BRAILLE_NUMBER + BRAILLE_LETTERS[char === '0' ? 9 : char.charCodeAt(0) - 49];
      continue;
    }
    throw new Error(`盲文编码仅支持英文字母、数字与空格（出现「${char}」）。`);
  }
  return output;
};

const brailleDecode = (input: string): string => {
  const chars = [...input.trim()];
  if (!chars.length) return '';
  let output = '';
  for (let position = 0; position < chars.length; position += 1) {
    const char = chars[position];
    if (char === BRAILLE_BLANK) {
      output += ' ';
      continue;
    }
    if (char === BRAILLE_CAPITAL || char === BRAILLE_NUMBER) {
      const next = chars[position + 1];
      const letterIndex = next === undefined ? -1 : BRAILLE_LETTERS.indexOf(next);
      if (letterIndex === -1) throw new Error(`盲文前缀符（${char === BRAILLE_CAPITAL ? '大写 ⠠' : '数字 ⠼'}）后须紧跟字母点阵。`);
      output += char === BRAILLE_CAPITAL ? String.fromCharCode(65 + letterIndex) : (letterIndex === 9 ? '0' : String(letterIndex + 1));
      position += 1;
      continue;
    }
    const letterIndex = BRAILLE_LETTERS.indexOf(char);
    if (letterIndex === -1) throw new Error(`密文含无法识别的盲文点阵「${char}」（U+${char.codePointAt(0)?.toString(16).toUpperCase()}），本实现只支持一级字母/数字/空格。`);
    output += String.fromCharCode(97 + letterIndex);
  }
  return output;
};

// ---- 音符密码 ----
// 最佳可得定义（无公开权威实现）：字母序号 n（1-26）→ 七音符 ♩♪♫♬♭♮♯ 取 (n-1)%7、
// 四下标 ₁₂₃₄ 取 (n-1)/7，两字符一组；解码反向。大小写不区分，输出小写。
const NOTE_HEADS = '♩♪♫♬♭♮♯';
const NOTE_SUBS = '₁₂₃₄';

const noteEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const char of input) {
    const upper = char.toUpperCase();
    if (upper < 'A' || upper > 'Z') throw new Error(`音符密码仅支持字母 A-Z（出现「${char}」）。`);
    const index = upper.charCodeAt(0) - 65;
    output += NOTE_HEADS[index % 7] + NOTE_SUBS[Math.floor(index / 7)];
  }
  return output;
};

const noteDecode = (input: string): string => {
  const chars = [...input.trim()];
  if (!chars.length) return '';
  if (chars.length % 2 !== 0) throw new Error('音符密码密文长度须为偶数（每字母 = 音符头 + 下标两字符）。');
  let output = '';
  for (let position = 0; position < chars.length; position += 2) {
    const head = NOTE_HEADS.indexOf(chars[position]);
    const sub = NOTE_SUBS.indexOf(chars[position + 1]);
    if (head === -1 || sub === -1) throw new Error(`音符密码组「${chars[position]}${chars[position + 1]}」非法：须为 ♩♪♫♬♭♮♯ 加下标 ₁₂₃₄。`);
    output += String.fromCharCode(97 + sub * 7 + head);
  }
  return output;
};

// ---- 花朵密码 ----
// 最佳可得定义（无公开权威实现）：UTF-8 字节 → 十六进制半字节，映射 16 个花形符号
// ❀❁✿✾✃✄❃❊✴✵✶✷✸✹✺❋（0-f），每字节两符号。
const FLOWER_DIGITS = '❀❁✿✾✃✄❃❊✴✵✶✷✸✹✺❋';

const flowerEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const byte of utf8Encoder.encode(input)) {
    output += FLOWER_DIGITS[byte >>> 4] + FLOWER_DIGITS[byte & 15];
  }
  return output;
};

const flowerDecode = (input: string): string => {
  const chars = [...input.trim()];
  if (!chars.length) return '';
  if (chars.length % 2 !== 0) throw new Error('花朵密码密文长度须为偶数（每字节两枚花形符）。');
  const bytes: number[] = [];
  for (let position = 0; position < chars.length; position += 2) {
    const high = FLOWER_DIGITS.indexOf(chars[position]);
    const low = FLOWER_DIGITS.indexOf(chars[position + 1]);
    if (high === -1 || low === -1) throw new Error('花朵密码密文只能包含 ❀❁✿✾✃✄❃❊✴✵✶✷✸✹✺❋ 十六个花形符。');
    bytes.push(high * 16 + low);
  }
  return bytesToText(new Uint8Array(bytes));
};

// ---- 字母密码 ----
// 字母密码（带圈字母/数字）：A-Z → Ⓐ-Ⓩ（U+24B6 起）、a-z → ⓐ-ⓩ（U+24D0 起）、
// 0-9 → ⓪①-⑨（U+24EA、U+2460 起）；其余字符双向原样透传。
// 字符表来源：Unicode「Enclosed Alphanumerics」标准顺序。
const CIRCLED_UPPER_BASE = 0x24b6;
const CIRCLED_LOWER_BASE = 0x24d0;
const CIRCLED_ZERO = '⓪';
const CIRCLED_DIGIT_BASE = 0x2460;

const circledFor = (char: string): string | null => {
  const code = char.charCodeAt(0);
  if (char >= 'A' && char <= 'Z') return String.fromCharCode(CIRCLED_UPPER_BASE + code - 65);
  if (char >= 'a' && char <= 'z') return String.fromCharCode(CIRCLED_LOWER_BASE + code - 97);
  if (char === '0') return CIRCLED_ZERO;
  if (char >= '1' && char <= '9') return String.fromCharCode(CIRCLED_DIGIT_BASE + code - 49);
  return null;
};

const letterEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const char of input) output += circledFor(char) ?? char;
  return output;
};

const letterDecode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const char of input) {
    const code = char.codePointAt(0) ?? 0;
    if (code >= CIRCLED_UPPER_BASE && code <= CIRCLED_UPPER_BASE + 25) output += String.fromCharCode(65 + code - CIRCLED_UPPER_BASE);
    else if (code >= CIRCLED_LOWER_BASE && code <= CIRCLED_LOWER_BASE + 25) output += String.fromCharCode(97 + code - CIRCLED_LOWER_BASE);
    else if (char === CIRCLED_ZERO) output += '0';
    else if (code >= CIRCLED_DIGIT_BASE && code <= CIRCLED_DIGIT_BASE + 8) output += String(code - CIRCLED_DIGIT_BASE + 1);
    else output += char;
  }
  return output;
};

// ---- 箭头密码 ----
// 最佳可得定义（无公开权威实现）：UTF-8 位流每 2bit 映射一个箭头 ↑=00 →=01 ↓=10 ←=11，
// 尾部不足 2 位补 0。
const ARROW_DIGITS = '↑→↓←';

const arrowEncode = (input: string): string => {
  if (!input) return '';
  const bits = bytesToBits(utf8Encoder.encode(input));
  while (bits.length % 2 !== 0) bits.push(0);
  let output = '';
  for (let position = 0; position < bits.length; position += 2) output += ARROW_DIGITS[bits[position] * 2 + bits[position + 1]];
  return output;
};

const arrowDecode = (input: string): string => {
  const chars = [...input.trim()];
  if (!chars.length) return '';
  const bits: number[] = [];
  for (const char of chars) {
    const index = ARROW_DIGITS.indexOf(char);
    if (index === -1) throw new Error(`箭头密码密文含「${char}」：只接受 ↑ → ↓ ← 四个箭头符。`);
    bits.push((index >> 1) & 1, index & 1);
  }
  return bytesToText(bitsToBytes(bits));
};

// ---- 汉字密码 ----
// 最佳可得定义：汉语拼音字母表呼读音（a 啊 b 玻 c 雌 d 得 e 鹅 f 佛 g 哥 h 喝 i 衣 j 基
// k 科 l 勒 m 摸 n 讷 o 喔 p 坡 q 欺 r 日 s 思 t 特 u 乌 v 迂 w 屋 x 希 y 医 z 资），每字母
// 映射一个汉字；非字母输入明确报错。
const HANZI_LETTERS = '啊玻雌得鹅佛哥喝衣基科勒摸讷喔坡欺日思特乌迂屋希医资';

const hanziEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const char of input) {
    const lower = char.toLowerCase();
    if (lower < 'a' || lower > 'z') throw new Error(`汉字密码仅支持字母 A-Z（出现「${char}」）。`);
    output += HANZI_LETTERS[lower.charCodeAt(0) - 97];
  }
  return output;
};

const hanziDecode = (input: string): string => {
  const chars = [...input.trim()];
  if (!chars.length) return '';
  let output = '';
  for (const char of chars) {
    const index = HANZI_LETTERS.indexOf(char);
    if (index === -1) throw new Error(`汉字密码密文含「${char}」：只接受拼音呼读音汉字（啊玻雌得鹅佛哥…资）。`);
    output += String.fromCharCode(97 + index);
  }
  return output;
};

// ---- 国际音标密码 ----
// 最佳可得定义：26 字母映射 26 个互不相同的国际音标字符（大小写同映射，解码输出小写）。
// 符号取自国际音标扩展区与希腊字母区（IPA 标准字符集）。
const IPA_SYMBOLS = 'ɑβçðəɸɡɦɪʝʞʎɱŋɵœɶʀʃθʊʋʍχʏʒ';

const ipaEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const char of input) {
    const lower = char.toLowerCase();
    if (lower < 'a' || lower > 'z') throw new Error(`国际音标密码仅支持字母 A-Z（出现「${char}」）。`);
    output += IPA_SYMBOLS[lower.charCodeAt(0) - 97];
  }
  return output;
};

const ipaDecode = (input: string): string => {
  const chars = [...input.trim()];
  if (!chars.length) return '';
  let output = '';
  for (const char of chars) {
    const index = IPA_SYMBOLS.indexOf(char);
    if (index === -1) throw new Error(`国际音标密码密文含「${char}」：只接受本实现的 26 个音标字符（ɑβçðə…）。`);
    output += String.fromCharCode(97 + index);
  }
  return output;
};

// ---- Whitespace 空白符编码 ----
// 最佳可得定义（随波逐流「空白符加密」语境：空格/Tab 二元编码，非完整 Whitespace 语言）：
// UTF-8 位流 0→空格、1→Tab；解码剔除换行后按位还原，不足一字节的尾位丢弃。
const whitespaceEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const bit of bytesToBits(utf8Encoder.encode(input))) output += bit === 0 ? ' ' : '\t';
  return output;
};

const whitespaceDecode = (input: string): string => {
  const compact = input.replace(/[\r\n]/g, '');
  if (!compact) return '';
  const bits: number[] = [];
  for (const char of compact) {
    if (char === ' ') bits.push(0);
    else if (char === '\t') bits.push(1);
    else throw new Error(`空白符编码密文含「${char}」：只接受空格（0）与 Tab（1）。`);
  }
  return bytesToText(bitsToBytes(bits));
};

// ---- Deadfish ----
// Deadfish（Jonathan Todd Skinner，esolangs.org/wiki/Deadfish）：累加器 + i/d/s/o 四指令，
// 每步执行后累加器为 -1 或 256 归零。本实现输出为字符模式（o 输出当前累加器值对应字符，
// 原版为数值输出）；编码按 i/d 差值直达目标码点（限 0-255，>255 需平方指令构造不予支持），
// 解码完整执行含 s 的程序，非指令字符按原版语义忽略。步数上限 1e6。
const DEADFISH_STEP_LIMIT = 1000000;

const deadfishEncode = (input: string): string => {
  if (!input) return '';
  let acc = 0;
  let output = '';
  for (const char of input) {
    const target = char.codePointAt(0) ?? 0;
    if (target === 256 || target > 255) throw new Error(`字符「${char}」码点 ${target} 超出 Deadfish 字符编码支持范围 0-255（256 会触发归零）。`);
    if (target > acc) {
      while (acc < target) {
        const step = Math.min(target - acc, 256 - acc);
        output += 'i'.repeat(step);
        acc += step;
        if (acc === 256) acc = 0;
      }
    } else if (target < acc) {
      output += 'd'.repeat(acc - target);
      acc = target;
    }
    output += 'o';
  }
  return output;
};

const deadfishDecode = (input: string): string => {
  if (!input.trim()) return '';
  let acc = 0;
  let steps = 0;
  let output = '';
  const normalize = (value: number): number => (value === -1 || value === 256 ? 0 : value);
  for (const command of input) {
    if (command === 'i' || command === 'd' || command === 's' || command === 'o') {
      steps += 1;
      if (steps > DEADFISH_STEP_LIMIT) throw new Error('Deadfish 超过步数上限（1000000），可能是死循环程序。');
    }
    if (command === 'i') acc = normalize(acc + 1);
    else if (command === 'd') acc = normalize(acc - 1);
    else if (command === 's') acc = normalize(acc * acc);
    else if (command === 'o') {
      if (acc < 1 || acc > 0x10ffff) throw new Error(`Deadfish 输出值 ${acc} 无法按字符模式输出（须为 1-1114111）。`);
      output += String.fromCodePoint(acc);
    }
  }
  return output;
};

// ---- Spoon（BrainFuck 前缀码变体） ----
// Spoon（Steven Goodwin 1998，esolangs.org/wiki/Spoon）：BrainFuck 八指令映射为可变长前缀码
// （+ =1、- =000、> =010、< =011、] =0011、[ =00100、. =001010、, =0010110；另有 00101110
// Debug / 00101111 停机码，解码消费不产出）。编码：文本 → BF（+/- 差值 + .）→ 位流；解码：
// 0/1 位流贪婪匹配前缀码 → 受限 BF 执行（30000 格 8bit 纸带、步数上限 1e6、括号嵌套上限 256）。
const SPOON_CODES: Record<string, string> = {
  '+': '1',
  '-': '000',
  '>': '010',
  '<': '011',
  ']': '0011',
  '[': '00100',
  '.': '001010',
  ',': '0010110',
};

const SPOON_TO_BF: Record<string, string> = {
  '1': '+',
  '000': '-',
  '010': '>',
  '011': '<',
  '0011': ']',
  '00100': '[',
  '001010': '.',
  '0010110': ',',
  '00101110': '',
  '00101111': '',
};

const SPOON_PREFIXES = new Set<string>();
for (const code of Object.keys(SPOON_TO_BF)) {
  for (let length = 1; length < code.length; length += 1) SPOON_PREFIXES.add(code.slice(0, length));
}

const BF_CELL_COUNT = 30000;
const BF_STEP_LIMIT = 1000000;
const BF_DEPTH_LIMIT = 256;

const brainfuckExecute = (program: string): string => {
  const jump = new Map<number, number>();
  const stack: number[] = [];
  for (let position = 0; position < program.length; position += 1) {
    const command = program[position];
    if (command === '[') {
      if (stack.length >= BF_DEPTH_LIMIT) throw new Error('Spoon 程序括号嵌套超过上限（256），已中止执行。');
      stack.push(position);
    } else if (command === ']') {
      const open = stack.pop();
      if (open === undefined) throw new Error('Spoon 程序括号不匹配：多余的 ]。');
      jump.set(open, position);
      jump.set(position, open);
    }
  }
  if (stack.length) throw new Error('Spoon 程序括号不匹配：缺少对应的 ]。');
  const tape = new Uint8Array(BF_CELL_COUNT);
  let pointer = 0;
  let steps = 0;
  let output = '';
  for (let position = 0; position < program.length; position += 1) {
    steps += 1;
    if (steps > BF_STEP_LIMIT) throw new Error('Spoon 超过步数上限（1000000），可能是死循环程序。');
    switch (program[position]) {
      case '>': pointer = (pointer + 1) % BF_CELL_COUNT; break;
      case '<': pointer = (pointer + BF_CELL_COUNT - 1) % BF_CELL_COUNT; break;
      case '+': tape[pointer] = (tape[pointer] + 1) & 255; break;
      case '-': tape[pointer] = (tape[pointer] + 255) & 255; break;
      case '.': output += String.fromCharCode(tape[pointer]); break;
      case '[': if (tape[pointer] === 0) position = jump.get(position) ?? position; break;
      case ']': if (tape[pointer] !== 0) position = jump.get(position) ?? position; break;
      default: break;
    }
  }
  return bytesToText(utf8Encoder.encode(output));
};

const spoonParse = (bits: string): string => {
  let program = '';
  let buffer = '';
  for (const bit of bits) {
    buffer += bit;
    const command = SPOON_TO_BF[buffer];
    if (command !== undefined) {
      program += command;
      buffer = '';
    } else if (!SPOON_PREFIXES.has(buffer)) {
      throw new Error(`Spoon 位流无法解析（非法比特序列「${buffer}」）。`);
    }
  }
  if (buffer) throw new Error(`Spoon 位流末尾有不完整比特「${buffer}」，请确认密文完整。`);
  return program;
};

const spoonEncode = (input: string): string => {
  if (!input) return '';
  const bytes = utf8Encoder.encode(input);
  let program = '';
  let current = 0;
  for (const byte of bytes) {
    let diff = byte - current;
    if (diff > 128) diff -= 256;
    else if (diff < -128) diff += 256;
    program += (diff >= 0 ? '+' : '-').repeat(Math.abs(diff)) + '.';
    current = byte;
  }
  let output = '';
  for (const command of program) output += SPOON_CODES[command] ?? '';
  return output;
};

const spoonDecode = (input: string): string => {
  const bits = input.replace(/[^01]/g, '');
  if (!bits) return '';
  return brainfuckExecute(spoonParse(bits));
};

// ---- 曼彻斯特编码 ----
// 曼彻斯特编码：每比特映射为两比特电平对（1=高电平，0=低电平）。IEEE 802.3 中 1=低→高
// （01）、0=高→低（10）；G.E. Thomas 极性相反（1=10、0=01）。输入按 UTF-8 字节高位在先取比特。
// 极性定义来源：https://www.dcode.fr/manchester-code
const manchesterVariantIsGe = (variant: string): boolean =>
  // 仅 'ge-thomas' 走 G.E. Thomas 极性；空串/全局默认 'special'/显式 'ieee-8023' 及其他取值一律回退 IEEE 802.3 默认极性。
  variant === 'ge-thomas';

const manchesterEncode = (input: string, variant: string): string => {
  if (!input) return '';
  const ge = manchesterVariantIsGe(variant);
  let output = '';
  for (const bit of bytesToBits(utf8Encoder.encode(input))) {
    output += (ge ? bit === 1 : bit === 0) ? '10' : '01';
  }
  return output;
};

const manchesterDecode = (input: string, variant: string): string => {
  const compact = input.replace(/\s+/g, '');
  if (!compact) return '';
  const ge = manchesterVariantIsGe(variant);
  if (compact.length % 2 !== 0) throw new Error('曼彻斯特编码密文长度须为偶数（每比特两电平）。');
  const bits: number[] = [];
  for (let position = 0; position < compact.length; position += 2) {
    const pair = compact.slice(position, position + 2);
    if (pair === '01') bits.push(ge ? 0 : 1);
    else if (pair === '10') bits.push(ge ? 1 : 0);
    else throw new Error(`曼彻斯特编码第 ${position / 2 + 1} 组「${pair}」非法：每 2 位须为相反电平对（01/10）。`);
  }
  return bytesToText(bitsToBytes(bits));
};

// ---- Emoji 编码器 ----
// 最佳可得定义（随波逐流「Emoji 编码」语境）：UTF-8 字节先转标准 base64，再逐字符映射
// U+1F600 起连续 64 个 Emoji（😀-😿 对应 0-63），填充「=」映射 ⬛（U+2B1B）。
const EMOJI_BASE = 0x1f600;
const EMOJI_PAD = '⬛';

const emojiEncode = (input: string): string => {
  if (!input) return '';
  let output = '';
  for (const char of bytesToBase64(utf8Encoder.encode(input))) {
    output += char === '=' ? EMOJI_PAD : String.fromCodePoint(EMOJI_BASE + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.indexOf(char));
  }
  return output;
};

const emojiDecode = (input: string): string => {
  const chars = [...input.trim()];
  if (!chars.length) return '';
  let base64 = '';
  for (const char of chars) {
    if (char === EMOJI_PAD) {
      base64 += '=';
      continue;
    }
    const code = char.codePointAt(0) ?? 0;
    if (code < EMOJI_BASE || code > EMOJI_BASE + 63) throw new Error(`Emoji 编码密文含「${char}」：只接受 😀-😿 区间 Emoji 与 ⬛ 填充。`);
    const value = code - EMOJI_BASE;
    base64 += 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'[value];
  }
  return bytesToText(base64ToBytes(base64));
};

// ---- 操作元数据 ----
export const parityCnOperations: Operation[] = [
  {
    id: 'core-values',
    category: 'crypto',
    name: { zh: '社会主义核心价值观编码', en: 'Core Socialist Values Encoding' },
    summary: { zh: '把 UTF-8 字节转成十二进制并映射为「富强民主文明和谐…」24 字词流，密文看似正能量语录，解码兼容 A-F 两种随机拆分。', en: 'Maps UTF-8 bytes through base-12 onto the 24-character core-values lexicon; decoding accepts both random A-F splits.' },
  },
  {
    id: 'hanzi-stroke',
    category: 'crypto',
    name: { zh: '汉字笔画码', en: 'Hanzi Stroke Code' },
    summary: { zh: '每字节按五进制展开为四个基本笔画字形（乙一丨丿丶），自造码表的双向笔画流编码。', en: 'Expands each byte to four basic-stroke glyphs (乙一丨丿丶) in base-5; bidirectional self-consistent codec.' },
  },
  {
    id: 'yinyang-qi',
    category: 'crypto',
    name: { zh: '阴阳怪气编码', en: 'Passive-Aggressive Encoding' },
    summary: { zh: '把文本比特流伪装成「就这¿」「不会吧？」弹幕体：ASCII 前标志位 0+8bit、其余 1+16bit，解码只认就/不首字，免疫空格与标点变体。', en: 'Disguises bits as「就这¿/不会吧？」danmu tokens: 0+8bit for ASCII, 1+16bit otherwise; decode scans only 就/不 marker chars.' },
  },
  {
    id: 'bagua-symbols',
    category: 'crypto',
    name: { zh: '八卦符编码', en: 'Eight Trigram Symbols' },
    summary: { zh: 'UTF-8 位流按 3bit 映射 Unicode 八卦符 ☰☱☲☳☴☵☶☷（U+2630-2637），与六十四卦编码互补。', en: 'Maps every 3 bits onto Unicode trigram symbols ☰☱☲☳☴☵☶☷ (U+2630-2637), complementing the hexagram codec.' },
  },
  {
    id: 'telecode',
    category: 'crypto',
    name: { zh: '中文电码', en: 'Chinese Telegraph Code' },
    summary: { zh: '汉字 ↔ 4 位数字组（1981 大陆标准电码本，7085 条：中=0022 国=0948），编码输出空格分隔。', en: 'Han characters to 4-digit groups per the 1981 PRC telegraph codebook (7085 entries: 中=0022 国=0948), space separated.' },
  },
  {
    id: 'xiangyue',
    category: 'crypto',
    name: { zh: '想曰（词典流）', en: 'Xiangyue' },
    summary: { zh: 'Abracadabra 词典流派：base64 逐字符映射 65 词古文小词典并冠以「想曰：」前缀；在线想曰为加密流，本实现仅保证本地互逆。', en: 'Dictionary-style: base64 chars mapped onto a 65-phrase classical lexicon with 想曰： prefix; the online Xiangyue is an encrypted stream, so this is locally self-consistent only.' },
  },
  {
    id: 'makabaka',
    category: 'crypto',
    name: { zh: '玛卡巴卡', en: 'Makka Pakka' },
    summary: { zh: '《花园宝宝》玛卡巴卡语：base64 字符映射为「玛卡巴卡轰」式音节段（65 键规则表），解码贪婪最长匹配；非表字符建议先做 Base64。', en: 'In-the-Night-Garden Makka Pakka speak: base64 chars mapped to syllable segments ending in 轰 (65-key table); decode greedily longest-matches.' },
  },
  {
    id: 'yinyin',
    category: 'crypto',
    name: { zh: '音音译者', en: 'Yinyin Translator' },
    summary: { zh: '兽音译者同族 4 字符 codec 变体（叮咚嘟锵）：码点 4 位 hex 逐位加位置偏移后两字符一组，前后缀「锵咚叮/嘟」包裹。', en: 'Beast-speak family with a custom 4-char codec (叮咚嘟锵): per code point 4-hex digits position-shifted and packed two chars per nibble with 锵咚叮/嘟 wrapping.' },
  },
  {
    id: 'shouyin',
    category: 'crypto',
    name: { zh: '兽音译者', en: 'Beast-Speak Translator' },
    summary: { zh: '嗷呜啊~ 兽语：码点 4 位 hex 逐位加位置偏移（s%16 回绕）后按 4 进制拆两字符，「~呜嗷…啊」包裹，与 beast_js 权威实现互通。', en: 'Beast speak with 嗷呜啊~: 4-hex digits per code point shifted by position (mod 16) and packed in base-4, wrapped as ~呜嗷…啊; interoperable with beast_js.' },
  },
  {
    id: 'periodic-table',
    category: 'crypto',
    name: { zh: '元素周期表编码', en: 'Periodic Table Encoding' },
    summary: { zh: '字符 Unicode 码点 ↔ 原子序数（1-118），输出元素符号空格分隔（A→H…），118 元素符号全表。', en: 'Character code points to atomic numbers 1-118, output as space-separated element symbols (A→H…), full 118-element table.' },
  },
  {
    id: 'mars-text',
    category: 'text',
    name: { zh: '火星文转换', en: 'Martian Text' },
    summary: { zh: '简体 ↔ 火星文逐字替换（3508 对映射：你→沵 我→莪 爱→嬡），表外字符透传；多对一映射，反向可能取同形字。', en: 'Simplified Chinese to Martian text substitution (3508 pairs: 你→沵 我→莪 爱→嬡); unmapped characters pass through; many-to-one mapping may pick homographs in reverse.' },
  },
  {
    id: 'braille',
    category: 'crypto',
    name: { zh: '盲文', en: 'Braille' },
    summary: { zh: 'UEB 一级盲文（U+2800-28FF 六点位型）：字母/数字（⠼ 前缀）/大写（⠠ 前缀）/空格（⠀）双向转换。', en: 'UEB Grade-1 braille (U+2800-28FF six-dot patterns): letters, digits (⠼ prefix), capitals (⠠ prefix) and spaces (⠀), both ways.' },
  },
  {
    id: 'music-notes',
    category: 'crypto',
    name: { zh: '音符密码', en: 'Music Notes Code' },
    summary: { zh: '字母序号映射七音符 ♩♪♫♬♭♮♯ 加下标 ₁₂₃₄ 两字符一组（a=♩₁…z=♯₄），自造双向音符流。', en: 'Letter index onto seven note heads ♩♪♫♬♭♮♯ with subscripts ₁₂₃₄ as pairs (a=♩₁…z=♯₄); bidirectional note stream.' },
  },
  {
    id: 'flower-code',
    category: 'crypto',
    name: { zh: '花朵密码', en: 'Flower Code' },
    summary: { zh: 'UTF-8 字节半字节映射 16 枚花形符（❀❁✿✾…❋），每字节两符号，自造双向花语流。', en: 'UTF-8 nibbles onto sixteen flower glyphs (❀❁✿✾…❋), two per byte; bidirectional floral stream.' },
  },
  {
    id: 'letter-code',
    category: 'crypto',
    name: { zh: '字母密码', en: 'Letter Symbols Code' },
    summary: { zh: '字母数字映射带圈字符（Ⓐ-Ⓩ ⓐ-ⓩ ⓪①-⑨），其余字符双向透传。', en: 'Letters and digits onto enclosed alphanumerics (Ⓐ-Ⓩ ⓐ-ⓩ ⓪①-⑨); other characters pass through.' },
  },
  {
    id: 'arrow-code',
    category: 'crypto',
    name: { zh: '箭头密码', en: 'Arrow Code' },
    summary: { zh: 'UTF-8 位流每 2bit 映射一个箭头（↑=00 →=01 ↓=10 ←=11），尾部不足补 0。', en: 'Every 2 bits onto one arrow (↑=00 →=01 ↓=10 ←=11), zero-padded tail.' },
  },
  {
    id: 'hanzi-code',
    category: 'crypto',
    name: { zh: '汉字密码', en: 'Hanzi Cipher' },
    summary: { zh: '拼音字母表呼读音：每字母映射一个汉字（a啊 b玻 c雌…z资），非字母明确报错。', en: 'Pinyin letter names: each letter mapped to one hanzi (a啊 b玻 c雌…z资); non-letters raise errors.' },
  },
  {
    id: 'ipa-code',
    category: 'crypto',
    name: { zh: '国际音标密码', en: 'IPA Code' },
    summary: { zh: '26 字母映射 26 个互不相同的国际音标字符（a→ɑ b→β … z→ʒ），解码输出小写。', en: '26 letters onto 26 distinct IPA characters (a→ɑ b→β … z→ʒ); decode emits lowercase.' },
  },
  {
    id: 'whitespace-code',
    category: 'crypto',
    name: { zh: 'Whitespace 空白符编码', en: 'Whitespace Encoding' },
    summary: { zh: '空格/Tab 二元编码：UTF-8 位流 0→空格 1→Tab（随波逐流空白符加密语境，非完整 Whitespace 语言）。', en: 'Binary space/tab encoding: UTF-8 bits mapped 0→space 1→tab (sbzl-style whitespace cipher, not the full esolang).' },
  },
  {
    id: 'deadfish',
    category: 'crypto',
    name: { zh: 'Deadfish', en: 'Deadfish' },
    summary: { zh: 'esolang 四指令极简语言（i/d/s/o，-1/256 归零）：编码按 i/d 差值直达码点，解码字符模式完整执行含平方的程序，步数上限防死循环。', en: 'Minimal i/d/s/o esolang with -1/256 reset: encoding walks i/d diffs, decoding executes fully (incl. square) in char mode with a step cap.' },
  },
  {
    id: 'spoon',
    category: 'crypto',
    name: { zh: 'Spoon（BrainFuck 变体）', en: 'Spoon (BrainFuck Derivative)' },
    summary: { zh: 'BrainFuck 八指令的霍夫曼式 0/1 前缀码（esolangs 权威码表）；解码走受限解释器（30000 格纸带、步数 1e6、嵌套 256 上限）。', en: 'Huffman-style 0/1 prefix code for the eight BrainFuck ops (esolangs table); decode runs a sandboxed interpreter (30k cells, 1e6 steps, depth 256).' },
  },
  {
    id: 'manchester',
    category: 'crypto',
    name: { zh: '曼彻斯特编码', en: 'Manchester Encoding' },
    summary: { zh: '每比特映射为两电平对：IEEE 802.3（1=01）与 G.E. Thomas（1=10）两种极性，variant 参数切换，UTF-8 字节高位在先。', en: 'Each bit becomes a two-level pair: IEEE 802.3 (1=01) vs G.E. Thomas (1=10) polarity via variant; UTF-8 bytes MSB first.' },
    params: ['variant'],
  },
  {
    id: 'emoji-encoder',
    category: 'text',
    name: { zh: 'Emoji 编码器', en: 'Emoji Encoder' },
    summary: { zh: 'UTF-8 字节转 base64 后逐字符映射 U+1F600 起连续 64 个 Emoji（😀-😿），填充位映射 ⬛。', en: 'Base64 of UTF-8 bytes mapped onto 64 consecutive emoji from U+1F600 (😀-😿) with ⬛ padding.' },
  },
];

export const parityCnDefaultParams: Partial<Record<ParamKey, string>> = {};

// ---- 分发 ----
export const parityCnTransform = async (id: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): Promise<string> => {
  const encoding = direction === 'encode';
  switch (id) {
    case 'core-values': return encoding ? coreValuesEncode(input) : coreValuesDecode(input);
    case 'hanzi-stroke': return encoding ? strokeEncode(input) : strokeDecode(input);
    case 'yinyang-qi': return encoding ? yygqEncode(input) : yygqDecode(input);
    case 'bagua-symbols': return encoding ? baguaEncode(input) : baguaDecode(input);
    case 'telecode': return encoding ? telecodeEncode(input) : telecodeDecode(input);
    case 'xiangyue': return encoding ? xiangyueEncode(input) : xiangyueDecode(input);
    case 'makabaka': return encoding ? makabakaEncode(input) : makabakaDecode(input);
    case 'yinyin': return encoding ? yinyinEncode(input) : yinyinDecode(input);
    case 'shouyin': return encoding ? shouyinEncode(input) : shouyinDecode(input);
    case 'periodic-table': return encoding ? elementEncode(input) : elementDecode(input);
    case 'mars-text': return encoding ? marsEncode(input) : marsDecode(input);
    case 'braille': return encoding ? brailleEncode(input) : brailleDecode(input);
    case 'music-notes': return encoding ? noteEncode(input) : noteDecode(input);
    case 'flower-code': return encoding ? flowerEncode(input) : flowerDecode(input);
    case 'letter-code': return encoding ? letterEncode(input) : letterDecode(input);
    case 'arrow-code': return encoding ? arrowEncode(input) : arrowDecode(input);
    case 'hanzi-code': return encoding ? hanziEncode(input) : hanziDecode(input);
    case 'ipa-code': return encoding ? ipaEncode(input) : ipaDecode(input);
    case 'whitespace-code': return encoding ? whitespaceEncode(input) : whitespaceDecode(input);
    case 'deadfish': return encoding ? deadfishEncode(input) : deadfishDecode(input);
    case 'spoon': return encoding ? spoonEncode(input) : spoonDecode(input);
    case 'manchester': return encoding ? manchesterEncode(input, params.variant ?? '') : manchesterDecode(input, params.variant ?? '');
    case 'emoji-encoder': return encoding ? emojiEncode(input) : emojiDecode(input);
    default: throw new Error(`parityChinese 未实现的操作：${id}`);
  }
};

// ---- 形状探针 ----
// 与码表同源；全部带最低长度阈值防误报，供智能识别 detectInput 接入。
const charsOf = (value: string): string[] => [...value.replace(/\s+/g, '')];

const ratioIn = (chars: string[], set: string): number => {
  if (!chars.length) return 0;
  let hits = 0;
  for (const char of chars) if (set.includes(char)) hits += 1;
  return hits / chars.length;
};

const makabakaSyllables = (): string => {
  let syllables = '轰';
  for (const segment of Object.values(MAKKAPAKKA_RULES)) syllables += segment;
  return syllables;
};

export const parityCnLooksLike: ParityShapeProbe[] = [
  {
    id: 'core-values',
    label: '核心价值观编码',
    test: value => {
      const chars = charsOf(value);
      return chars.length >= 12 && chars.every(char => CORE_VALUES.includes(char));
    },
  },
  {
    id: 'bagua-symbols',
    label: '八卦符流',
    test: value => {
      const chars = charsOf(value);
      return chars.length >= 8 && ratioIn(chars, BAGUA_SYMBOLS) >= 0.9;
    },
  },
  {
    id: 'braille',
    label: '盲文',
    test: value => {
      const chars = [...value.replace(/\s+/g, '')];
      if (chars.length < 8) return false;
      const hits = chars.filter(char => {
        const code = char.codePointAt(0) ?? 0;
        return code >= 0x2800 && code <= 0x28ff;
      }).length;
      return hits / chars.length >= 0.8;
    },
  },
  {
    id: 'music-notes',
    label: '音符密码',
    test: value => {
      const chars = charsOf(value);
      return chars.length >= 8 && ratioIn(chars, NOTE_HEADS + NOTE_SUBS) >= 0.9;
    },
  },
  {
    id: 'flower-code',
    label: '花朵密码',
    test: value => {
      const chars = charsOf(value);
      return chars.length >= 8 && ratioIn(chars, FLOWER_DIGITS) >= 0.95;
    },
  },
  {
    id: 'arrow-code',
    label: '箭头密码',
    test: value => {
      const chars = charsOf(value);
      return chars.length >= 8 && chars.every(char => ARROW_DIGITS.includes(char));
    },
  },
  {
    id: 'telecode',
    label: '中文电码',
    test: value => /^\s*\d{4}(\s+\d{4})+\s*$/.test(value),
  },
  {
    id: 'shouyin',
    label: '兽音译者',
    test: value => {
      const trimmed = value.trim();
      return trimmed.length >= 12 && trimmed.startsWith('~呜嗷') && trimmed.endsWith('啊') && ratioIn([...trimmed.slice(3, -1)], BEAST_CODEC) === 1;
    },
  },
  {
    id: 'yinyin',
    label: '音音译者',
    test: value => {
      const trimmed = value.trim();
      return trimmed.length >= 12 && trimmed.startsWith('锵咚叮') && trimmed.endsWith('嘟') && ratioIn([...trimmed.slice(3, -1)], YIN_CODEC) === 1;
    },
  },
  {
    id: 'makabaka',
    label: '玛卡巴卡',
    test: value => {
      const trimmed = value.trim();
      if (trimmed.length < 12 || (trimmed.match(/轰/g) ?? []).length < 2) return false;
      return ratioIn([...trimmed], makabakaSyllables()) >= 0.9;
    },
  },
  {
    id: 'xiangyue',
    label: '想曰',
    test: value => {
      const trimmed = value.trim();
      return trimmed.startsWith(XIANGYUE_PREFIX) && trimmed.length >= XIANGYUE_PREFIX.length + 8;
    },
  },
  {
    id: 'whitespace-code',
    label: 'Whitespace 空白符编码',
    test: value => {
      if (value.length < 16) return false;
      let hasSpace = false;
      let hasTab = false;
      for (const char of value) {
        if (char === ' ') hasSpace = true;
        else if (char === '\t') hasTab = true;
        else if (char !== '\n' && char !== '\r') return false;
      }
      return hasSpace && hasTab;
    },
  },
  {
    id: 'manchester',
    label: '曼彻斯特编码',
    test: value => {
      const compact = value.replace(/\s+/g, '');
      if (!/^[01]{16,}$/.test(compact) || compact.length % 2 !== 0) return false;
      for (let position = 0; position < compact.length; position += 2) {
        if (compact[position] === compact[position + 1]) return false;
      }
      return true;
    },
  },
  {
    id: 'letter-code',
    label: '字母密码（带圈）',
    test: value => {
      const chars = [...value];
      if (chars.length < 4) return false;
      let hits = 0;
      for (const char of chars) {
        const code = char.codePointAt(0) ?? 0;
        if ((code >= 0x24b6 && code <= 0x24cf) || (code >= 0x24d0 && code <= 0x24e9) || char === '⓪' || (code >= 0x2460 && code <= 0x2468)) hits += 1;
      }
      return hits / chars.length >= 0.5;
    },
  },
  {
    id: 'emoji-encoder',
    label: 'Emoji 编码',
    test: value => {
      const chars = [...value.trim()];
      if (chars.length < 4) return false;
      const hits = chars.filter(char => {
        const code = char.codePointAt(0) ?? 0;
        return (code >= 0x1f600 && code <= 0x1f63f) || char === EMOJI_PAD;
      }).length;
      return hits / chars.length >= 0.8;
    },
  },
  {
    id: 'deadfish',
    label: 'Deadfish（i/d/s/o）',
    test: value => {
      const compact = value.replace(/\s+/g, '');
      if (compact.length < 8 || !/^[idos]+$/i.test(compact)) return false;
      // 至少含 i（自增）与 o（输出）才是可执行程序骨架；英文单词几乎不可能全部由 i/d/s/o 构成。
      return /[iI]/.test(compact) && /[oO]/.test(compact);
    },
  },
];

// ---- 回归向量 ----
// cipher 有值 = 权威对拍（来源见注释 URL）；无值 = 自造 round-trip。
export const parityCnVectors: ParityVector[] = [
  // 权威：sym233/core-values-encoder 算法确定性分支推导（1024 → hex 31303234 → base12）。
  { id: 'core-values', plain: '1024', cipher: '和谐民主和谐富强和谐文明和谐自由' },
  { id: 'hanzi-stroke', plain: 'hi' },
  // 权威：ToolsFx/WhatsInYourClipboard ctfExtra.js 阴阳怪气流派（EBCTFCodeBox fancy2.js 移植），
  // "hi" → 标志位 0+01101000 0+01101001 → 位流映射 就这¿/不会吧？。
  { id: 'yinyang-qi', plain: 'hi', cipher: '就 这 ¿ 就 这 ¿ 不 会 吧 ？ 不 会 吧 ？ 就 这 ¿ 不 会 吧 ？ 就 这 ¿ 就 这 ¿ 就 这 ¿ 就 这 ¿ 就 这 ¿ 不 会 吧 ？ 不 会 吧 ？ 就 这 ¿ 不 会 吧 ？ 就 这 ¿ 就 这 ¿ 不 会 吧 ？ ' },
  // 权威：Unicode 八卦符 U+2630-2637 顺序，"A"(0x41=01000001) 补 1 位 → 010|000|010。
  { id: 'bagua-symbols', plain: 'A', cipher: '☲☰☲' },
  { id: 'bagua-symbols', plain: 'bagua trigram flag' },
  // 权威：milkcask/ChineseTelegraphCode cn 表（1981 大陆标准）：中=0022 国=0948 人=0086 民=3046。
  { id: 'telecode', plain: '中国', cipher: '0022 0948' },
  { id: 'telecode', plain: '人民', cipher: '0086 3046' },
  { id: 'xiangyue', plain: '秘密' },
  // 权威：EBCTFCodeBox exclusiveCodec.js 玛卡巴卡规则表：a/b/c 段。
  { id: 'makabaka', plain: 'abc', cipher: '玛卡巴卡轰阿巴雅卡轰伊卡阿卡噢轰' },
  { id: 'yinyin', plain: '你好' },
  // 权威：sgdrg15rdg/beast_js 算法 + SycAlright/beast_sdk README 样例 encode("你好")。
  { id: 'shouyin', plain: '你好', cipher: '~呜嗷呜嗷嗷嗷啊嗷嗷~啊呜~啊~呜呜嗷啊' },
  // 权威：元素周期表 118 符号（EBCTFCodeBox cn.js）：A=65→Tb(65) B=66→Dy(66)。
  { id: 'periodic-table', plain: 'AB', cipher: 'Tb Dy' },
  // 权威：zhanyuzhang/text-convert 火星文映射表（反向取唯一映射字保证回转）：你→沵 好→恏。
  { id: 'mars-text', plain: '你好', cipher: '沵恏' },
  // 权威：UEB 一级盲文标准点阵 hello → ⠓⠑⠇⠇⠕（Wikipedia Braille / Unicode Braille Patterns）。
  { id: 'braille', plain: 'hello', cipher: '⠓⠑⠇⠇⠕' },
  { id: 'braille', plain: 'the quick brown fox jumps over a lazy dog 2026' },
  { id: 'music-notes', plain: 'code' },
  { id: 'flower-code', plain: 'CTF' },
  { id: 'flower-code', plain: 'flower code long sample' },
  { id: 'letter-code', plain: 'Flag{2026}' },
  { id: 'arrow-code', plain: 'hi' },
  { id: 'hanzi-code', plain: 'xyz' },
  { id: 'ipa-code', plain: 'cipher' },
  { id: 'whitespace-code', plain: 'hi' },
  // 权威：esolangs.org/wiki/Deadfish 语义构造：10i→10 s→100 4i→104 o→'h'。
  { id: 'deadfish', plain: 'h', cipher: 'iiiiiiiiiisiiiio', direction: 'decode' },
  { id: 'deadfish', plain: 'CTF' },
  { id: 'spoon', plain: 'hi' },
  // 权威：IEEE 802.3 极性定义（https://www.dcode.fr/manchester-code）：H(0x48)+i(0x69) 逐位 0→10/1→01。
  { id: 'manchester', plain: 'Hi', cipher: '10011010011010101001011001101001', params: { variant: 'ieee-8023' } },
  { id: 'emoji-encoder', plain: 'hi' },
];
