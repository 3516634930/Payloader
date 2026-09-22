import type { Direction, Operation, OperationId, ParamKey } from './types';
import type { ParityShapeProbe, ParityVector } from './parityTypes';

// 批次 O · Lane B：字符类 18 操作（猪圈/KeyCode/九宫格/汉码/反斜杠/斜杠管道/汤姆/表盘/金甲虫/肯尼/深渊天使/Dvorak/五针电报/阿多语/鸭语/数字键盘线/Quadoo/BWT）。
// 码表与规则来源（调研交叉验证）：
// - CacheSleuth（随波逐流同源实现族）：https://www.cachesleuth.com/tools/{backslash,slashandpipe,tomtom,clockcode,goldbug,kenny,abaddon,fiveneedletelegraph,hodor,nak,quadoo,numberpadlines}/
//   对应 JS 资产 /assets/js/tools/*.js（v=0fcb35ae，表数据逐项提取核对）。
// - Pigpen Unicode 近似表：din4e/p4rs3lt0ngv3 src/transformers/cipher/pigpen.js（自述取 dCode.fr 原版三格布局）。
// - Keyboard KeyCode：MDN UI 事件 keyCode 遗留表 https://developer.mozilla.org/zh-CN/docs/Web/API/KeyboardEvent/keyCode（US 布局标点位）。
// - Handycode（手机九宫格 键位+位次）：CTF-Wiki 其它类型加密·手机键盘密码 https://ctf-wiki.org/reverse/identify-encode-encryption/introduction
// - Dvorak：Dvorak Simplified Keyboard 标准布局 https://en.wikipedia.org/wiki/Dvorak_keyboard_layout
// - Five-Needle：Cooke & Wheatstone 五针电报 20 字母表（Wikipedia https://en.wikipedia.org/wiki/Cooke_and_Wheatstone_telegraph；字母集按 CacheSleuth 实现，含 U 无 V）。
// - Gold-Bug：Edgar Allan Poe《The Gold-Bug》(1843) 频度破译表（8=e、;=t 等，与故事密文一致）。
// - BWT：Burrows & Wheeler 1994 + https://en.wikipedia.org/wiki/Burrows%E2%80%93Wheeler_transform（BANANA$ → ANNB$AA 教材例）。
// - 汉码（中文数字码）：无公开权威向量，按中文数字记数法实现（字母序号 1-26 → 一…二十六，数字与其余字符原样保留）。
// 全部纯文本进出，不执行任何输入内容；空输入一律返回空串。

// ---- 猪圈密码（Pigpen）：A-Z → Unicode 几何符号图形对照（dCode 原版三格布局近似） ----
const PIGPEN_SYMBOLS = ['ᒧ', '⊔', 'ᒪ', '⊐', '☐', '⊏', 'ᒣ', '⊓', 'ᒥ', '⟓', '⨃', 'ᒷ', '⪾', '🝕', '⪽', 'ᒬ', '⩀', '⟔', 'ᐯ', 'ᐳ', 'ᐸ', 'ᐱ', '⟇', 'ᑀ', 'ᑅ', '⟑'];

const pigpenByLetter = new Map(PIGPEN_SYMBOLS.map((symbol, index) => [String.fromCharCode(97 + index), symbol]));
const pigpenBySymbol = new Map(PIGPEN_SYMBOLS.map((symbol, index) => [symbol, String.fromCharCode(65 + index)]));

const pigpenEncode = (value: string): string => [...value]
  .map(char => char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ? pigpenByLetter.get(char.toLowerCase()) ?? char : char)
  .join('');

const pigpenDecode = (value: string): string => [...value].map(char => pigpenBySymbol.get(char) ?? char).join('');

// ---- 键盘 KeyCode：字符 ↔ JS 键盘事件 keyCode（MDN 遗留表，US 布局；大小写共享键码，解码输出小写字母） ----
const KEYCODE_BY_CHAR = new Map<string, number>([
  ...[...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'].map((char, index) => [char, 65 + index] as const),
  ...[...'abcdefghijklmnopqrstuvwxyz'].map((char, index) => [char, 65 + index] as const),
  ...[...'0123456789'].map((char, index) => [char, 48 + index] as const),
  [' ', 32], [';', 186], ['=', 187], [',', 188], ['-', 189], ['.', 190], ['/', 191], ['`', 192],
  ['[', 219], ['\\', 220], [']', 221], ["'", 222],
]);
const KEYCODE_CHAR_BY_CODE = new Map([...KEYCODE_BY_CHAR].map(([char, code]) => [code, char]));

const keycodeEncode = (value: string): string => {
  const codes: number[] = [];
  for (const char of value) {
    const code = KEYCODE_BY_CHAR.get(char);
    if (code === undefined) throw new Error(`键盘 KeyCode 仅支持字母、数字与 US 键盘标点，字符 "${char}" 无对应键码`);
    codes.push(code);
  }
  return codes.join(' ');
};

const keycodeDecode = (value: string): string => value
  .split(/\s+/)
  .filter(Boolean)
  .map(token => {
    const code = Number(token);
    if (!Number.isInteger(code) || code < 0) throw new Error(`键盘 KeyCode 键码必须是十进制整数，遇到 "${token}"`);
    const char = KEYCODE_CHAR_BY_CODE.get(code);
    if (char === undefined) throw new Error(`键码 ${token} 不在支持的打印键范围（字母/数字/空格/标点），功能键码无法还原为字符`);
    return char;
  })
  .join('');

// ---- 九宫格 Handycode：字母 → 电话键盘（键位+位次）两位数字（2=ABC … 9=WXYZ），其余字符原样 ----
const HANDY_GROUPS: Record<string, string> = { 2: 'ABC', 3: 'DEF', 4: 'GHI', 5: 'JKL', 6: 'MNO', 7: 'PQRS', 8: 'TUV', 9: 'WXYZ' };
const handyByLetter = new Map<string, string>(Object.entries(HANDY_GROUPS).flatMap(([key, letters]) => [...letters].map((letter, index) => [letter.toLowerCase(), `${key}${index + 1}`])));
const handyByCode = new Map([...handyByLetter].map(([letter, code]) => [code, letter]));

const handycodeEncode = (value: string): string => [...value].map(char => handyByLetter.get(char) ?? char).join('');

const handycodeDecode = (value: string): string => {
  let output = '';
  let index = 0;
  while (index < value.length) {
    const pair = value.slice(index, index + 2);
    if (/^[2-9][1-4]$/.test(pair)) {
      output += handyByCode.get(pair) ?? '';
      index += 2;
      continue;
    }
    output += value[index];
    index += 1;
  }
  return output;
};

// ---- 汉码（中文数字码）：字母序号 1-26 → 中文数字（一…二十六），数字/其余字符原样，编码按空格分隔 ----
const CN_DIGITS = '零一二三四五六七八九'.split('');

const chineseNumeral = (value: number): string => {
  if (value <= 9) return CN_DIGITS[value];
  if (value === 10) return '十';
  if (value < 20) return `十${CN_DIGITS[value % 10]}`;
  return `${CN_DIGITS[Math.floor(value / 10)]}十${value % 10 ? CN_DIGITS[value % 10] : ''}`;
};

const chineseNumeralParse = (token: string): number => {
  if (token.length === 1) return CN_DIGITS.indexOf(token);
  if (token === '十') return 10;
  const teen = token.match(/^十([一二三四五六七八九])$/);
  if (teen) return 10 + CN_DIGITS.indexOf(teen[1]);
  const tens = token.match(/^([一二三四五六七八九])十([一二三四五六七八九])?$/);
  if (tens) return CN_DIGITS.indexOf(tens[1]) * 10 + (tens[2] ? CN_DIGITS.indexOf(tens[2]) : 0);
  return -1;
};

const chinesecodeEncode = (value: string): string => [...value]
  .map(char => {
    const lower = char.toLowerCase();
    return lower >= 'a' && lower <= 'z' ? chineseNumeral(lower.charCodeAt(0) - 96) : /\s/.test(char) ? null : char;
  })
  .filter((token): token is string => token !== null)
  .join(' ');

const chinesecodeDecode = (value: string): string => value
  .split(/\s+/)
  .filter(Boolean)
  .map(token => {
    if ([...token].every(char => '零一二三四五六七八九十'.includes(char))) {
      const number = chineseNumeralParse(token);
      if (number < 1 || number > 26) throw new Error(`汉码中文数字 "${token}" 超出字母范围（一至二十六）`);
      return String.fromCharCode(96 + number);
    }
    if (token.length === 1) return token;
    throw new Error(`汉码无法识别的分段 "${token}"，编码应为空格分隔的中文数字`);
  })
  .join('');

// ---- 反斜杠密码：a-z → |/ \ 三字符三元组（3^3=27 组合取 26），字母连写，解码剔除杂字符后按 3 位切分 ----
const BACKSLASH_CODES = ['|||', '||/', '||\\', '|/|', '|//', '|/\\', '|\\|', '|\\/', '|\\\\', '/||', '/|/', '/|\\', '//|', '///', '//\\', '/\\|', '/\\/', '/\\\\', '\\||', '\\|/', '\\|\\', '\\/|', '\\//', '\\/\\', '\\\\|', '\\\\/'];

const backslashEncode = (value: string): string => [...value.toLowerCase()]
  .map(char => char >= 'a' && char <= 'z' ? BACKSLASH_CODES[char.charCodeAt(0) - 97] : char)
  .join('');

const backslashDecode = (value: string): string => {
  const compact = [...value].filter(char => '|/\\'.includes(char)).join('');
  if (compact.length % 3 !== 0) throw new Error(`反斜杠密码符号数必须是 3 的倍数，当前 ${compact.length} 个`);
  let output = '';
  for (let index = 0; index < compact.length; index += 3) {
    const code = BACKSLASH_CODES.indexOf(compact.slice(index, index + 3));
    if (code < 0) throw new Error(`未知反斜杠密码三元组：${compact.slice(index, index + 3)}`);
    output += String.fromCharCode(97 + code);
  }
  return output;
};

// ---- 斜杠管道密码：a-z → |/ \ 变长组合（1-4 符号，空格分隔），解码对每组做 4 位贪心最长匹配 ----
const SLASH_PIPE_CODES = ['|', '|\\', '||', '|/', '\\', '||\\', '|||', '\\\\', '/', '|\\\\', '//||', '|\\/', '|\\|', '|/|', '||/|', '|\\|\\', '/\\', '\\/', '/|', '|//', '//', '||\\\\', '\\/||', '||/', '|||\\', '||||'];

const slashPipeEncode = (value: string): string => [...value.toLowerCase()]
  .filter(char => !/\s/.test(char))
  .map(char => char >= 'a' && char <= 'z' ? SLASH_PIPE_CODES[char.charCodeAt(0) - 97] : char)
  .join(' ');

const greedyGroupDecode = (codes: string[], token: string): string => {
  let output = '';
  let position = 0;
  while (position < token.length) {
    const candidate = token.slice(position, position + 4);
    const code = codes.indexOf(candidate);
    if (code >= 0) {
      output += String.fromCharCode(97 + code);
      position += candidate.length;
      continue;
    }
    output += token[position];
    position += 1;
  }
  return output;
};

const slashPipeDecode = (value: string): string => value
  .split(/\s+/)
  .filter(Boolean)
  .map(token => greedyGroupDecode(SLASH_PIPE_CODES, token))
  .join('');

// ---- 汤姆码（Tomtom）：a-z → / \ 斜杠组合（1-4 符号，空格分隔），解码对每组做 4 位贪心最长匹配 ----
const TOMTOM_CODES = ['/', '//', '///', '////', '/\\', '//\\', '///\\', '/\\\\', '/\\\\\\', '\\/', '\\\\/', '\\\\\\/', '\\//', '\\///', '/\\/', '//\\/', '/\\\\/', '/\\//', '\\/\\', '\\\\/\\', '\\//\\', '\\/\\\\', '//\\\\', '\\\\//', '\\/\\/', '/\\/\\'];

const tomtomEncode = (value: string): string => [...value.toLowerCase()]
  .filter(char => !/\s/.test(char))
  .map(char => char >= 'a' && char <= 'z' ? TOMTOM_CODES[char.charCodeAt(0) - 97] : char)
  .join(' ');

const tomtomDecode = (value: string): string => value
  .split(/\s+/)
  .filter(Boolean)
  .map(token => greedyGroupDecode(TOMTOM_CODES, token))
  .join('');

// ---- 表盘码（Clock）：a=AM、b=1 … y=24、z=PM、空格=00，24 小时刻度，冒号分隔 ----
const CLOCK_CODES = ['AM', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', 'PM', '00'];
const CLOCK_TOKEN_PATTERN = /^[0-9AMP]+$/;

const clockEncode = (value: string): string => {
  const chars = [...value.toLowerCase()].filter(char => /[a-z ]/.test(char));
  return chars
    .map((char, index) => `${CLOCK_CODES[char === ' ' ? 26 : char.charCodeAt(0) - 97]}${index === chars.length - 1 ? '' : ':'}`)
    .join('');
};

const clockDecode = (value: string): string => value
  .toUpperCase()
  .replace(/[^0-9AMP:]/g, '')
  .split(':')
  .filter(Boolean)
  .map(token => {
    const code = CLOCK_CODES.indexOf(token);
    return code >= 0 ? code === 26 ? ' ' : String.fromCharCode(97 + code) : CLOCK_TOKEN_PATTERN.test(token) ? token : '';
  })
  .join('');

// ---- 金甲虫密码（Gold-Bug）：爱伦·坡 1843 年《金甲虫》单表符号（8=e、;=t 等），字母→符号连写，空格保留 ----
const GOLDBUG_SYMBOLS = ['5', '2', '-', '†', '8', '1', '3', '4', '6', ',', '7', '0', '9', '*', '‡', '.', '$', '(', ')', ';', '?', '¶', ']', '¢', ':', '['];

const goldbugEncode = (value: string): string => [...value]
  .map(char => {
    const lower = char.toLowerCase();
    return lower >= 'a' && lower <= 'z' ? GOLDBUG_SYMBOLS[lower.charCodeAt(0) - 97] : char;
  })
  .join('');

const goldbugDecode = (value: string): string => value
  .split(' ')
  .map(group => [...group]
    .map(symbol => {
      const code = GOLDBUG_SYMBOLS.indexOf(symbol);
      return code >= 0 ? String.fromCharCode(97 + code) : symbol;
    })
    .join(''))
  .join(' ');

// ---- 肯尼密码（Kenny Speak）：a-z → m/p/f 三元组（base-3 序 mmm…ffp，无分隔连写），解码剔除杂字符后按 3 位切分 ----
const KENNY_CODES = ['mmm', 'mmp', 'mmf', 'mpm', 'mpp', 'mpf', 'mfm', 'mfp', 'mff', 'pmm', 'pmp', 'pmf', 'ppm', 'ppp', 'ppf', 'pfm', 'pfp', 'pff', 'fmm', 'fmp', 'fmf', 'fpm', 'fpp', 'fpf', 'ffm', 'ffp'];

const kennyEncode = (value: string): string => [...value.toLowerCase()]
  .map(char => char >= 'a' && char <= 'z' ? KENNY_CODES[char.charCodeAt(0) - 97] : char)
  .join('');

const kennyDecode = (value: string): string => {
  const compact = [...value].filter(char => 'mpf'.includes(char)).join('');
  if (compact.length % 3 !== 0) throw new Error(`肯尼密码 m/p/f 符号数必须是 3 的倍数，当前 ${compact.length} 个`);
  let output = '';
  for (let index = 0; index < compact.length; index += 3) {
    const code = KENNY_CODES.indexOf(compact.slice(index, index + 3));
    if (code < 0) throw new Error(`未知肯尼密码三元组：${compact.slice(index, index + 3)}`);
    output += String.fromCharCode(97 + code);
  }
  return output;
};

// ---- 深渊天使（Abaddon）：a-z+空格 → ¥/µ/þ 三元组（3^3=27 组合），编码空格分隔，解码按 3 位切分（兼容大写 Þ/Μ 变体） ----
const ABADDON_CODES = ['¥¥µ', '¥þ¥', 'þµµ', 'µµþ', 'µ¥µ', 'µµ¥', 'µþþ', 'þµ¥', '¥¥¥', 'µþµ', '¥þµ', 'µ¥¥', 'þ¥¥', '¥¥þ', 'þþþ', 'þþ¥', '¥þþ', 'þþµ', 'þµþ', 'þ¥µ', 'µµµ', '¥µ¥', 'µþ¥', 'µ¥þ', '¥µþ', 'þ¥þ', '¥µµ'];

const abaddonEncode = (value: string): string => [...value.toLowerCase()]
  .map(char => {
    const index = char === ' ' ? 26 : char >= 'a' && char <= 'z' ? char.charCodeAt(0) - 97 : -1;
    return index < 0 ? null : ABADDON_CODES[index];
  })
  .filter((code): code is string => code !== null)
  .join(' ');

const abaddonDecode = (value: string): string => {
  const compact = [...value]
    .map(char => char === 'Þ' ? 'þ' : char === 'Μ' ? 'µ' : char)
    .filter(char => '¥µþ'.includes(char))
    .join('');
  if (compact.length % 3 !== 0) throw new Error(`深渊天使符号数必须是 3 的倍数，当前 ${compact.length} 个`);
  let output = '';
  for (let index = 0; index < compact.length; index += 3) {
    const code = ABADDON_CODES.indexOf(compact.slice(index, index + 3));
    if (code < 0) throw new Error(`未知深渊天使三元组：${compact.slice(index, index + 3)}`);
    output += code === 26 ? ' ' : String.fromCharCode(97 + code);
  }
  return output;
};

// ---- Dvorak 键盘：QWERTY 物理键位 ↔ Dvorak 字符逐位映射（encode=QWERTY→Dvorak，decode 反向；大小写保持） ----
const QWERTY_ROW = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./";
const DVORAK_ROW = "`1234567890[]',.pyfgcrl/=\\aoeuidhtns\\;qjkxbmwvz";

const dvorakByQwerty = new Map([...QWERTY_ROW].map((char, index) => [char, DVORAK_ROW[index] ?? char]));
const dvorakByDvorak = new Map([...dvorakByQwerty].map(([qwerty, dvorak]) => [dvorak, qwerty]));

const dvorakMapText = (value: string, table: Map<string, string>): string => [...value]
  .map(char => {
    const mapped = table.get(char.toLowerCase());
    if (mapped === undefined) return char;
    return char === char.toLowerCase() ? mapped : mapped.toUpperCase();
  })
  .join('');

// ---- 五针电报（Cooke & Wheatstone）：20 字母（无 C/J/Q/V/X/Z），每字母 = 5 针中一左(/)一右(\)两针位置 ----
const FIVE_NEEDLE_LETTERS = 'abdefghiklmnoprstuwy';
const FIVE_NEEDLE_CODES = ['/|||\\', '/||\\|', '|/||\\', '/|\\||', '|/|\\|', '||/|\\', '/\\|||', '|/\\||', '||/\\|', '|||/\\', '\\/|||', '|\\/||', '||\\/|', '|||\\/', '\\|/||', '|\\|/|', '||\\|/', '\\||/|', '|\\||/', '\\|||/'];

const fiveNeedleEncode = (value: string): string => [...value.toLowerCase()]
  .map(char => {
    const code = FIVE_NEEDLE_LETTERS.indexOf(char);
    if (code >= 0) return FIVE_NEEDLE_CODES[code];
    if ('cjqvxz'.includes(char)) throw new Error(`五针电报 20 字母表不含字母 "${char.toUpperCase()}"（历史机型省略 C/J/Q/V/X/Z）`);
    return null;
  })
  .filter((code): code is string => code !== null)
  .join(' ');

const fiveNeedleDecode = (value: string): string => {
  const compact = [...value].filter(char => '|/\\'.includes(char)).join('');
  if (compact.length % 5 !== 0) throw new Error(`五针电报符号数必须是 5 的倍数，当前 ${compact.length} 个`);
  let output = '';
  for (let index = 0; index < compact.length; index += 5) {
    const code = FIVE_NEEDLE_CODES.indexOf(compact.slice(index, index + 5));
    if (code < 0) throw new Error(`未知五针电报针位组合：${compact.slice(index, index + 5)}`);
    output += FIVE_NEEDLE_LETTERS[code];
  }
  return output;
};

// ---- Hodor 语（阿多语）：逐字符 → Hodor 大小写/标点变体词（源表缺 D/H/O/R 四字母，编码时先剥离），空格分隔 ----
const HODOR_WORDS: Record<string, string> = {
  a: 'HODOR', b: 'Hodor!', c: 'hodor', e: 'hodor?', f: 'HODOR!', g: 'hodor!', i: 'Hodor?', j: 'HODOR?!', k: 'hodor?!', l: 'Hodor!?', m: 'Hodor.', n: 'HODOR?', p: 'HODOR.', q: 'Hodor!?!', s: 'Hodor', t: 'hodor.', u: 'hodor!?', v: 'Hodor?!', w: 'HODOR!?', x: 'Hodor?!?', y: 'HODOR!?!', z: 'hodor!?!',
  A: 'hodor?!?', B: 'HODOR-', C: 'Hodor...', E: 'HooodorrHodor', F: 'hodor-', G: 'HoOodoOorHodor', I: 'HoOodoOorHODOR', J: 'hodorHooodorr', K: 'HodorHoOodoOor', L: 'HooodorrHODOR', M: 'HODOR...', N: 'HoOodoOorhodor', P: 'hodor...', Q: 'HODORHoOodoOor', S: 'HODOR?!?', T: 'Hodor-', U: 'HodorHooodorr', V: 'HODORHooodorr', W: 'Hooodorrhodor', X: 'HoOodoOorHooodorrHODOR', Y: 'hodorHoOodoOor', Z: 'HoOodoOorHooodorrHodor',
};
const HODOR_BY_WORD = new Map(Object.entries(HODOR_WORDS).map(([letter, word]) => [word, letter]));

const hodorEncode = (value: string): string => [...value]
  .filter(char => !'HODRhodr'.includes(char))
  .map(char => HODOR_WORDS[char] ?? null)
  .filter((word): word is string => word !== null)
  .join(' ');

const hodorDecode = (value: string): string => value
  .split(/\s+/)
  .filter(Boolean)
  .map(word => {
    const letter = HODOR_BY_WORD.get(word);
    if (letter === undefined) throw new Error(`无法识别的 Hodor 词：${word}`);
    return letter;
  })
  .join('');

// ---- 鸭语（Duckspeak / Nak Nak）：逐字节 → 两位十六进制 → Nak 词表（0-9a-f），空格分隔，解码按两词一组还原 ----
const NAK_WORDS: Record<string, string> = {
  0: 'Nak', 1: 'Nanak', 2: 'Nananak', 3: 'Nanananak', 4: 'Nak?', 5: 'nak?', 6: 'Naknak', 7: 'Naknaknak', 8: 'Nak.', 9: 'Naknak.',
  a: 'Naknaknaknak', b: 'nanak', c: 'naknak', d: 'nak!', e: 'nak.', f: 'naknaknak',
};
const NAK_BY_WORD = new Map(Object.entries(NAK_WORDS).map(([digit, word]) => [word, digit]));

const duckspeakEncode = (value: string): string => {
  const hex = [...value]
    .map(char => {
      const code = char.charCodeAt(0);
      if (code > 0xff) throw new Error(`鸭语（Nak Nak）仅支持单字节字符，"${char}" 超出范围`);
      return code.toString(16).padStart(2, '0');
    })
    .join('');
  return [...hex].map(digit => NAK_WORDS[digit] ?? digit).join(' ');
};

const duckspeakDecode = (value: string): string => {
  const tokens = value.split(/\s+/).filter(Boolean);
  if (tokens.length % 2 !== 0) throw new Error(`鸭语词数必须为偶数（每两词一个字节），当前 ${tokens.length} 个`);
  let output = '';
  for (let index = 0; index < tokens.length; index += 2) {
    const high = NAK_BY_WORD.get(tokens[index]);
    const low = NAK_BY_WORD.get(tokens[index + 1]);
    if (high === undefined || low === undefined) throw new Error(`无法识别的鸭语词：${high === undefined ? tokens[index] : tokens[index + 1]}`);
    output += String.fromCharCode(Number.parseInt(high + low, 16));
  }
  return output;
};

// ---- NumberPadLines：a-z0-9 → 数字小键盘连线经过的键位数字串，空格分隔 ----
const NUMBERPAD_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'.split('');
const NUMBERPAD_CODES = ['7295', '71354597', '32489', '178621', '3145479', '314547', '317965', '174639', '132879', '3984', '174349', '179', '71539', '7193', '71397', '71354', '971395', '7135459', '3245687', '1328', '1793', '183', '17593', '19537', '15358', '1379', '713973', '539', '136479', '1365697', '14639', '314697', '317964', '137', '3179364', '793146'];
const NUMBERPAD_BY_CODE = new Map(NUMBERPAD_CODES.map((code, index) => [code, NUMBERPAD_CHARS[index] ?? '']));

const numberpadLinesEncode = (value: string): string => [...value.toLowerCase()]
  .map(char => {
    const index = NUMBERPAD_CHARS.indexOf(char);
    return index >= 0 ? NUMBERPAD_CODES[index] : null;
  })
  .filter((code): code is string => code !== null)
  .join(' ');

const numberpadLinesDecode = (value: string): string => value
  .split(/\s+/)
  .filter(Boolean)
  .map(token => {
    const char = NUMBERPAD_BY_CODE.get(token);
    if (char !== undefined && char !== '') return char;
    if (token.length === 1 && NUMBERPAD_CHARS.includes(token)) return token;
    throw new Error(`NumberPadLines 无法识别的分段 "${token}"`);
  })
  .join('');

// ---- Quadoo：六点位字键盘（1-6 点位，同盲文读法）字母/数字/常用符号码表，编码转大写、空格分隔 ----
const QUADOO_CODES: Record<string, string> = {
  A: '25', B: '1235', C: '35', D: '235', E: '134', F: '14', G: '16', H: '24', I: '5', J: '23', K: '345', L: '34', M: '1245', N: '246', O: '1234', P: '145', Q: '12346', R: '146', S: '36', T: '12', U: '234', V: '45', W: '2345', X: '56', Y: '236', Z: '135',
  '1': '2', '2': '123', '3': '125', '4': '156', '5': '136', '6': '1346', '7': '15', '8': '1356', '9': '1236', '0': '12345',
  ' ': '0', '\n': '0', '-': '1', '+': '356', '*': '2456', '#': '124', '?': '126', '/': '6', '=': '13', '_': '3', '€': '1345', '&': '3456', '(': '456', ')': '256', '<': '1456', '>': '1256', '[': '13456', ']': '12356', '@': '123456',
};
const QUADOO_BY_CODE = new Map(Object.entries(QUADOO_CODES).map(([char, code]) => [code, char]));

const quadooEncode = (value: string): string => [...value.toUpperCase()]
  .map(char => QUADOO_CODES[char] ?? null)
  .filter((code): code is string => code !== null)
  .join(' ');

const quadooDecode = (value: string): string => value
  .split(/\s+/)
  .filter(Boolean)
  .map(token => {
    const char = QUADOO_BY_CODE.get(token);
    if (char === undefined) throw new Error(`Quadoo 无法识别的点位组合 "${token}"`);
    return char;
  })
  .join('');

// ---- Burrows-Wheeler 变换：追加 '$' 哨兵后按全部循环移位字典序排序，取末列；解码用 LF 映射逆变换 ----
const bwtEncode = (value: string): string => {
  if (value.includes('$')) throw new Error('BWT 明文不能包含 "$" 哨兵字符："$" 保留用于标记旋转起点，请先替换或转义');
  const text = `${value}$`;
  const size = text.length;
  const rotations = [...Array(size).keys()].map(offset => text.slice(offset) + text.slice(0, offset));
  rotations.sort();
  return rotations.map(rotation => rotation[size - 1]).join('');
};

const bwtDecode = (value: string): string => {
  if (!value.includes('$')) throw new Error('BWT 密文缺少 "$" 哨兵字符，无法定位原始串的旋转位置');
  if (value.split('$').length - 1 !== 1) throw new Error('BWT 密文必须恰好包含一个 "$" 哨兵字符');
  const size = value.length;
  const counts = new Map<string, number>();
  const ranks: number[] = [];
  for (const char of value) {
    ranks.push(counts.get(char) ?? 0);
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  const starts = new Map<string, number>();
  let accumulated = 0;
  for (const char of [...new Set(value)].sort()) {
    starts.set(char, accumulated);
    accumulated += counts.get(char) ?? 0;
  }
  const output: string[] = [];
  let row = 0;
  for (let index = size - 1; index >= 0; index -= 1) {
    const char = value[row];
    output[index] = char;
    row = (starts.get(char) ?? 0) + (ranks[row] ?? 0);
  }
  const restored = output.join('');
  if (!restored.startsWith('$')) throw new Error('BWT 密文校验失败：逆变换结果未以 "$" 哨兵开头，密文可能损坏');
  return restored.slice(1);
};

// ---- 操作元数据 ----
export const parityCharOperations: Operation[] = [
  {
    id: 'pigpen',
    category: 'crypto',
    name: { zh: '猪圈密码', en: 'Pigpen Cipher' },
    summary: { zh: '共济会猪圈密码：A-Z 按九宫格+X 三格几何符号替换，此处用 Unicode 近似符号输出图形对照（dCode 原版布局），非字母原样保留。', en: 'Masonic pigpen cipher: A-Z mapped to Unicode lookalike grid glyphs (dCode original layout); a graphical approximation, non-letters kept.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'keyboard-keycode',
    category: 'text',
    name: { zh: '键盘 KeyCode', en: 'Keyboard KeyCode' },
    summary: { zh: '字符 ↔ JS 键盘事件 keyCode（MDN 遗留表，US 布局）：字母 65-90、数字 48-57、标点 186-222；键码无大小写信息，解码输出小写字母。', en: 'Chars to/from JS keyboard event keyCodes (MDN legacy table, US layout); codes are case-insensitive, decoding yields lowercase letters.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'handycode',
    category: 'crypto',
    name: { zh: '九宫格 Handycode', en: 'Keypad Handycode' },
    summary: { zh: '手机九宫格键盘码：字母 →（键位+位次）两位数字（2=ABC…9=WXYZ，A=21、B=22…Z=94），其余字符原样。', en: 'Mobile keypad code: letters to two-digit (key, position) pairs (2=ABC...9=WXYZ, A=21 ... Z=94); other chars kept.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'chinesecode',
    category: 'crypto',
    name: { zh: '汉码', en: 'Chinese Handy Code' },
    summary: { zh: '中文数字键码：字母序号 1-26 写作中文数字（A=一…Z=二十六），空格分隔；数字与其余字符原样。无公开权威向量，按中文数字记数法实现。', en: 'Chinese numeral code: letter index 1-26 written in Chinese numerals (A=一 ... Z=二十六), space separated; digits and other chars kept. No public authoritative vectors.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'backslash-code',
    category: 'crypto',
    name: { zh: '反斜杠密码', en: 'Backslash Code' },
    summary: { zh: 'a-z 映射为 |、/、\\ 组成的 3 符号三元组（27 组合取 26），字母连写；解码剔除杂字符后按 3 位切分。', en: 'a-z mapped to 3-symbol triplets over | / \\ (26 of 27 combos), letters concatenated; decode strips noise then chunks by 3.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'slash-pipe',
    category: 'crypto',
    name: { zh: '斜杠管道密码', en: 'Slash and Pipe' },
    summary: { zh: 'a-z 映射为 |、/、\\ 变长组合（1-4 符号，空格分隔），解码对每组做 4 位贪心最长匹配。', en: 'a-z mapped to variable-length combos over | / \\ (1-4 symbols, space separated); decode greedily matches up to 4 symbols per group.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'tomtom',
    category: 'crypto',
    name: { zh: '汤姆码', en: 'Tomtom Code' },
    summary: { zh: 'a-z 映射为 / 与 \\ 组成的变长斜杠组（1-4 符号，空格分隔，地理藏宝常用），解码做 4 位贪心最长匹配。', en: 'a-z mapped to variable-length slash/backslash groups (1-4 symbols, space separated, popular in geocaching); greedy 4-symbol decode.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'clock-code',
    category: 'crypto',
    name: { zh: '表盘码', en: 'Clock Code' },
    summary: { zh: '24 小时表盘刻度：a=AM、b=1 … y=24、z=PM、空格=00，冒号分隔；解码只接受合法刻度值。', en: '24-hour clock dial: a=AM, b=1 ... y=24, z=PM, space=00, colon separated; decode accepts valid dial tokens only.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'goldbug',
    category: 'crypto',
    name: { zh: '金甲虫密码', en: 'Gold-Bug Cipher' },
    summary: { zh: '爱伦·坡《金甲虫》单表符号（8=e、;=t、‡=o…），字母→符号连写、空格保留；频度破译名局的原表。', en: 'Poe Gold-Bug substitution symbols (8=e, ;=t, ‡=o...), letters concatenated with spaces kept; the table from the famous frequency-analysis tale.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'kenny',
    category: 'crypto',
    name: { zh: '肯尼密码', en: 'Kenny Speak' },
    summary: { zh: '《南方公园》Kenny 语：a-z → m/p/f 三元组（mmm…ffp 共 26 组），连写输出；解码剔除杂字符后按 3 位切分。', en: 'South Park Kenny-speak: a-z to m/p/f triplets (mmm...ffp, 26 combos), concatenated; decode strips noise then chunks by 3.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'abaddon',
    category: 'crypto',
    name: { zh: '深渊天使', en: 'Abaddon' },
    summary: { zh: 'Abaddon 三符号码：a-z+空格 → ¥/µ/þ 三元组（27 组合），空格分隔；兼容大写 Þ/Μ 变体，解码按 3 位切分。', en: 'Abaddon three-symbol code: a-z+space to ¥/µ/þ triplets (27 combos), space separated; accepts Þ/Μ variants, decode chunks by 3.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'dvorak',
    category: 'text',
    name: { zh: 'Dvorak 键盘', en: 'Dvorak Layout' },
    summary: { zh: 'QWERTY ↔ Dvorak 键位错位还原：按物理键位逐字符映射（encode=QWERTY 文本读作 Dvorak，decode 反向），大小写与非键位字符保持。', en: 'QWERTY to/from Dvorak per-key remap (encode reads QWERTY text as Dvorak, decode reverses); case and off-layout chars preserved.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'five-needle',
    category: 'crypto',
    name: { zh: '五针电报', en: 'Five-Needle Telegraph' },
    summary: { zh: 'Cooke-Wheatstone 五针电报 20 字母表（无 C/J/Q/V/X/Z）：每字母 = 5 针中一左(/)一右(\\)针位，空格分隔；含缺省字母报错。', en: 'Cooke & Wheatstone five-needle 20-letter code (no C/J/Q/V/X/Z): each letter is one left(/) and one right(\\) needle position; missing letters error.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'hodor',
    category: 'crypto',
    name: { zh: 'Hodor 语', en: 'Hodor Speak' },
    summary: { zh: '《权力的游戏》阿多语：逐字符 → Hodor 大小写/标点变体词（源表缺 D/H/O/R，编码时先剥离），空格分隔。', en: 'Game of Thrones Hodor language: chars to Hodor case/punctuation variants (source table lacks D/H/O/R, stripped first), space separated.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'duckspeak',
    category: 'crypto',
    name: { zh: '鸭语', en: 'Duckspeak' },
    summary: { zh: '鸭语 Nak Nak：逐字节 → 两位十六进制 → Nak/Nanak 词表（0-9a-f），空格分隔，解码按两词一组还原字节。', en: 'Duck speak Nak Nak: byte to two hex digits to Nak/Nanak word table (0-9a-f), space separated; decode pairs words into bytes.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'numberpad-lines',
    category: 'crypto',
    name: { zh: 'NumberPadLines', en: 'NumberPadLines' },
    summary: { zh: '数字小键盘连线码：a-z0-9 → 连线经过的键位数字串（如 a=7295），空格分隔；解码兼容单字符 token。', en: 'Numpad line code: a-z0-9 to sequences of keypad digits crossed by the stroke (a=7295), space separated; decode accepts bare chars.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'quadoo',
    category: 'text',
    name: { zh: 'Quadoo 点字键盘', en: 'Quadoo' },
    summary: { zh: 'Quadoo 六点位码（1-6 点位，盲文同源读法）：字母/数字/常用符号 → 点位组合，编码转大写、空格分隔。', en: 'Quadoo six-dot code (positions 1-6, braille-style): letters/digits/common symbols to dot combos, uppercased on encode, space separated.' },
    supportsEncode: true,
    supportsDecode: true,
  },
  {
    id: 'bwt',
    category: 'text',
    name: { zh: 'Burrows-Wheeler 变换', en: 'Burrows-Wheeler Transform' },
    summary: { zh: '经典 BWT：输入含 "$" 时报错；编码追加 "$" 哨兵做循环移位排序取末列（BANANA→ANNB$AA），解码 LF 映射还原，缺哨兵报中文错。', en: 'Classic BWT: input containing "$" errors; encode appends "$" sentinel, sorts rotations, takes last column (BANANA→ANNB$AA); decode via LF-mapping.' },
    supportsEncode: true,
    supportsDecode: true,
  },
];

// 本 lane 十八个操作全部零参数；签名与五个 parity 模块统一，params 仅作占位以匹配共享契约。
export const parityCharDefaultParams: Partial<Record<ParamKey, string>> = {};

export async function parityCharTransform(id: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): Promise<string> {
  void params;
  if (input === '') return '';
  const encode = direction === 'encode';
  switch (id) {
    case 'pigpen':
      return encode ? pigpenEncode(input) : pigpenDecode(input);
    case 'keyboard-keycode':
      return encode ? keycodeEncode(input) : keycodeDecode(input);
    case 'handycode':
      return encode ? handycodeEncode(input) : handycodeDecode(input);
    case 'chinesecode':
      return encode ? chinesecodeEncode(input) : chinesecodeDecode(input);
    case 'backslash-code':
      return encode ? backslashEncode(input) : backslashDecode(input);
    case 'slash-pipe':
      return encode ? slashPipeEncode(input) : slashPipeDecode(input);
    case 'tomtom':
      return encode ? tomtomEncode(input) : tomtomDecode(input);
    case 'clock-code':
      return encode ? clockEncode(input) : clockDecode(input);
    case 'goldbug':
      return encode ? goldbugEncode(input) : goldbugDecode(input);
    case 'kenny':
      return encode ? kennyEncode(input) : kennyDecode(input);
    case 'abaddon':
      return encode ? abaddonEncode(input) : abaddonDecode(input);
    case 'dvorak':
      return encode ? dvorakMapText(input, dvorakByQwerty) : dvorakMapText(input, dvorakByDvorak);
    case 'five-needle':
      return encode ? fiveNeedleEncode(input) : fiveNeedleDecode(input);
    case 'hodor':
      return encode ? hodorEncode(input) : hodorDecode(input);
    case 'duckspeak':
      return encode ? duckspeakEncode(input) : duckspeakDecode(input);
    case 'numberpad-lines':
      return encode ? numberpadLinesEncode(input) : numberpadLinesDecode(input);
    case 'quadoo':
      return encode ? quadooEncode(input) : quadooDecode(input);
    case 'bwt':
      return encode ? bwtEncode(input) : bwtDecode(input);
    default:
      throw new Error(`字符类 parity 模块不支持的操作：${id}`);
  }
}

// ---- 智能识别谓词：与实现同源，供 detectInput 判定高特征密文（最低长度 + 占比/集合双重防误报） ----
export const parityCharLooksLike: ParityShapeProbe[] = [
  {
    id: 'pigpen',
    label: '猪圈密码（Unicode 符号）',
    test: value => {
      const chars = [...value.replace(/\s+/g, '')];
      if (chars.length < 4) return false;
      const hits = chars.filter(char => pigpenBySymbol.has(char)).length;
      return hits / chars.length >= 0.6;
    },
  },
  {
    id: 'kenny',
    label: '肯尼密码（m/p/f 三元组）',
    test: value => {
      const compact = [...value].filter(char => 'mpf'.includes(char)).length;
      return value.length >= 6 && compact === [...value.replace(/\s+/g, '')].length && compact >= 6 && compact % 3 === 0;
    },
  },
  {
    id: 'hodor',
    label: 'Hodor 语（hodor 词密集）',
    test: value => {
      const words = value.split(/\s+/).filter(Boolean);
      if (words.length < 2) return false;
      const hits = words.filter(word => HODOR_BY_WORD.has(word)).length;
      return hits / words.length >= 0.8;
    },
  },
  {
    id: 'duckspeak',
    label: '鸭语（Nak 词密集）',
    test: value => {
      const words = value.split(/\s+/).filter(Boolean);
      if (words.length < 4) return false;
      const hits = words.filter(word => {
        const core = word.replace(/[!?.]+$/, '');
        return NAK_BY_WORD.has(core);
      }).length;
      return hits / words.length >= 0.8;
    },
  },
  {
    id: 'abaddon',
    label: '深渊天使（¥/µ/þ 三元组）',
    test: value => {
      const chars = [...value.replace(/\s+/g, '')];
      if (chars.length < 6) return false;
      const hits = chars.filter(char => '¥µþ'.includes(char)).length;
      return hits / chars.length >= 0.9 && hits % 3 === 0;
    },
  },
  {
    id: 'backslash-code',
    label: '反斜杠密码（|\\/ 三元组）',
    test: value => {
      const chars = [...value.replace(/\s+/g, '')];
      if (chars.length < 6) return false;
      const hits = chars.filter(char => '|/\\'.includes(char)).length;
      return hits === chars.length && chars.filter(char => char === '|').length > 0 && chars.length % 3 === 0;
    },
  },
  {
    id: 'slash-pipe',
    label: '斜杠管道密码（|\\/ 组合）',
    test: value => {
      const chars = [...value.replace(/\s+/g, '')];
      if (chars.length < 4) return false;
      const hits = chars.filter(char => '|/\\'.includes(char)).length;
      return hits === chars.length && chars.includes('|') && /\s/.test(value);
    },
  },
  {
    id: 'tomtom',
    label: '汤姆码（\\/ 斜杠组）',
    test: value => {
      const chars = [...value.replace(/\s+/g, '')];
      if (chars.length < 4) return false;
      const hits = chars.filter(char => '/\\'.includes(char)).length;
      return hits === chars.length && !value.includes('|') && /\s/.test(value);
    },
  },
  {
    id: 'five-needle',
    label: '五针电报（5 针位组）',
    test: value => {
      const chars = [...value.replace(/\s+/g, '')];
      if (chars.length < 10 || chars.length % 5 !== 0) return false;
      const hits = chars.filter(char => '|/\\'.includes(char)).length;
      return hits === chars.length && chars.includes('/') && chars.includes('\\');
    },
  },
  {
    id: 'goldbug',
    label: '金甲虫密码（†‡¶¢ 符号）',
    test: value => {
      const chars = [...value.replace(/\s+/g, '')];
      if (chars.length < 4) return false;
      const inTable = chars.every(char => GOLDBUG_SYMBOLS.includes(char));
      const distinctive = chars.some(char => '†‡¶¢'.includes(char));
      return inTable && distinctive;
    },
  },
  {
    id: 'clock-code',
    label: '表盘码（刻度冒号串）',
    test: value => {
      const text = value.trim();
      if (!/^[0-9AMP:]{3,}$/.test(text)) return false;
      const tokens = text.split(':').filter(Boolean);
      return tokens.length >= 2 && tokens.every(token => CLOCK_CODES.includes(token));
    },
  },
  {
    id: 'numberpad-lines',
    label: 'NumberPadLines（键位数字串）',
    test: value => {
      const tokens = value.trim().split(/\s+/).filter(Boolean);
      if (tokens.length < 2) return false;
      return tokens.every(token => NUMBERPAD_BY_CODE.get(token) !== undefined && NUMBERPAD_BY_CODE.get(token) !== '');
    },
  },
  {
    id: 'quadoo',
    label: 'Quadoo（点位数字串）',
    test: value => {
      const tokens = value.trim().split(/\s+/).filter(Boolean);
      if (tokens.length < 2) return false;
      return tokens.every(token => QUADOO_BY_CODE.has(token));
    },
  },
];

// ---- 回归向量：cipher 有值 = 对拍样本（来源见各条注释）；无来源标注 = 自造 round-trip 样本 ----
export const parityCharVectors: ParityVector[] = [
  // 猪圈：表来源 din4e/p4rs3lt0ngv3 pigpen.js（dCode 原版布局 Unicode 近似）
  { id: 'pigpen', plain: 'PIGPEN', cipher: 'ᒬᒥᒣᒬ☐🝕' },
  // KeyCode：MDN 遗留 keyCode 表（h=72 i=73 空格=32 9=57 ;=186）
  { id: 'keyboard-keycode', plain: 'hi 9;', cipher: '72 73 32 57 186' },
  { id: 'keyboard-keycode', plain: 'ok', cipher: '79 75' },
  // Handycode：CTF-Wiki 手机键盘密码（键位+位次）
  { id: 'handycode', plain: 'handycode', cipher: '422162319323633132' },
  // 汉码：无公开权威向量，按中文数字记数法自造 round-trip
  { id: 'chinesecode', plain: 'banana', cipher: '二 一 十四 一 十四 一' },
  { id: 'chinesecode', plain: 'z', cipher: '二十六' },
  // 反斜杠：CacheSleuth /assets/js/tools/backslash.js 表（h=|\/ i=|\\；hihi 全字母 round-trip）
  { id: 'backslash-code', plain: 'hihi', cipher: '|\\/|\\\\|\\/|\\\\' },
  { id: 'backslash-code', plain: 'thequick', cipher: '\\|/|\\/|///\\/\\|\\|\\\\||\\/|/' },
  // 斜杠管道：CacheSleuth slashandpipe.js 表（h=\\ i=/ t=|// e=\ r=\/；词内空格不保留）
  { id: 'slash-pipe', plain: 'hithere', cipher: '\\\\ / |// \\\\ \\ \\/ \\' },
  // v 码（||\\）曾与 j 重复导致 round-trip 破坏（review P1 回归钉）：含 v 的向量防止再犯
  { id: 'slash-pipe', plain: 'viva' },
  // 汤姆码：CacheSleuth tomtom.js 表（q=/\\/ u=\//\ i=/\\\ c=/// k=\\/）
  { id: 'tomtom', plain: 'quick', cipher: '/\\\\/ \\//\\ /\\\\\\ /// \\\\/' },
  // 表盘码：CacheSleuth clockcode.js 表（h=7 i=8；a=AM 空格=00 z=PM）
  { id: 'clock-code', plain: 'hi', cipher: '7:8' },
  { id: 'clock-code', plain: 'a z', cipher: 'AM:00:PM' },
  // 金甲虫：Poe《金甲虫》破译表（8=e、;=t，与故事密文 ";48"=the 一致）；CacheSleuth goldbug.js 全表
  { id: 'goldbug', plain: 'the quick brown fox', cipher: ';48 $?6-7 2(‡]* 1‡¢' },
  { id: 'goldbug', plain: 'the', cipher: ';48' },
  // 肯尼：CacheSleuth kenny.js / dcode.fr / particleflux/kenny 同一 base-3 表（a=mmm b=mmp c=mmf）
  { id: 'kenny', plain: 'abc', cipher: 'mmmmmpmmf' },
  { id: 'kenny', plain: 'kenny', cipher: 'pmpmppppppppffm' },
  // 深渊天使：CacheSleuth abaddon.js 表（h=þµ¥ i=¥¥¥ 空格=¥µµ）
  { id: 'abaddon', plain: 'hi', cipher: 'þµ¥ ¥¥¥' },
  { id: 'abaddon', plain: 'hi hi', cipher: 'þµ¥ ¥¥¥ ¥µµ þµ¥ ¥¥¥' },
  // Dvorak：标准布局主键位行（asdfghjkl; → aoeuidhtns，Wikipedia Dvorak 键位）
  { id: 'dvorak', plain: 'asdfghjkl;', cipher: 'aoeuidhtns' },
  { id: 'dvorak', plain: 'dvorak', cipher: 'ekrpat' },
  // 五针电报：CacheSleuth fiveneedletelegraph.js 表（t=||\|/ e=/|\|| l=|||/\ g=||/|\ r=\|/|| a=/|||\ p=|||\/ h=/\|||）
  { id: 'five-needle', plain: 'telegraph', cipher: '||\\|/ /|\\|| |||/\\ /|\\|| ||/|\\ \\|/|| /|||\\ |||\\/ /\\|||' },
  // Hodor：CacheSleuth hodor.js 变体词表（q=Hodor!?! u=hodor!? i=Hodor? c=hodor k=hodor?!）
  { id: 'hodor', plain: 'quick', cipher: 'Hodor!?! hodor!? Hodor? hodor hodor?!' },
  // 鸭语：CacheSleuth nak.js 词表（h=0x68 → 6,8；i=0x69 → 6,9）
  { id: 'duckspeak', plain: 'hi', cipher: 'Naknak Nak. Naknak Naknak.' },
  // NumberPadLines：CacheSleuth numberpadlines.js 表（g=317965 e=3145479 o=71397）
  { id: 'numberpad-lines', plain: 'geo', cipher: '317965 3145479 71397' },
  // Quadoo：CacheSleuth quadoo.js 表（G=16 E=134 O=1234 C=35 A=25 H=24）
  { id: 'quadoo', plain: 'GEOCACHE', cipher: '16 134 1234 35 25 35 24 134' },
  // BWT：教材权威例（Wikipedia Burrows–Wheeler transform：BANANA$ 末列 ANNB$AA）；mississippi 为经典验证串
  { id: 'bwt', plain: 'BANANA', cipher: 'ANNB$AA' },
  { id: 'bwt', plain: 'a', cipher: 'a$' },
  { id: 'bwt', plain: 'mississippi', cipher: 'ipssm$pissii' },
];
