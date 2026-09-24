// 字表映射与脉冲类密码（批次 M）：Pizzini、Decabit、Cetacean、Albam、Carbonaro、Cisco Type 7。
// 码表与规则来源（调研交叉验证，见 docs/updates/v2.0.1-workbench-density.md）：
// - Decabit：dcode.fr/decabit-code 全 127 行表（kryptografie.de 抽样一致），ASCII 映射，兼容 1/0 记法。
// - Pizzini：CacheSleuth pizzini.js 实装规则（序号+3 拼接，贪心自分隔），兼容历史流派 1-3→X/Y/Z。
// - Cetacean：CyberChef CetaceanCipherEncode/Decode（16bit，1→e 0→E，空格原样），解码兼容 A/B 变体。
// - Albam：默认 A↔N 半表互换（+13 对合，catencode/fidonode/GC Wizard 多源）；variant 切换 CacheSleuth +11 流派。
// - Carbonaro：CacheSleuth carbonaro.js 对合表（10 个不动点 H/J/K/M/N/Q/U/W/X/Y）。
// - Cisco Type 7：IOS 弱混淆，固定密钥表 dsfd;kfoA,.iyewrkldJKDHSUB 与种子异或，可逆。
// 全部纯文本进出，不执行任何输入内容。

const PIZZINI_OFFSET = 3;

export const pizziniEncode = (value: string): string => {
  let output = '';
  for (const char of value) {
    const upper = char.toUpperCase();
    if (upper >= 'A' && upper <= 'Z') {
      output += String(upper.charCodeAt(0) - 64 + PIZZINI_OFFSET);
    } else {
      output += char;
    }
  }
  return output;
};

// 贪心自分隔：1/2 开头必为两位（10-29），其余一位（3-9）；1-3 兼容历史流派 X/Y/Z，0 无映射保留。
export const pizziniDecode = (value: string): string => {
  let output = '';
  let index = 0;
  while (index < value.length) {
    const char = value[index];
    if (!/[0-9]/.test(char)) {
      output += char;
      index += 1;
      continue;
    }
    const twoDigit = value.slice(index, index + 2);
    if ((char === '1' || char === '2') && /^[12][0-9]$/.test(twoDigit)) {
      const code = Number(twoDigit);
      output += String.fromCharCode(code - PIZZINI_OFFSET + 64);
      index += 2;
      continue;
    }
    const code = Number(char);
    if (code >= 4 && code <= 9) {
      output += String.fromCharCode(code - PIZZINI_OFFSET + 64);
    } else if (code >= 1 && code <= 3) {
      output += String.fromCharCode(code + 87); // 1→X, 2→Y, 3→Z（历史流派）
    } else {
      output += char; // 0 无映射，原样保留
    }
    index += 1;
  }
  return output;
};

// dcode.fr/decabit-code 全表：0-126 → 10 脉冲（5+/5-，唯一例外 126 = 全 +）。
const DECABIT_PATTERNS = [
  '--+-+++-+-','+--+++--+-','+--++-+-+-','+--+-++-+-','----+++-++','++--+++---','++--++--+-','++--+-+-+-','++---++-+-','---++++-+-',
  '+-+-+++---','+-+-+-+-+-','+-+--++-+-','+---++-++-','+---++--++','--+++-++--','---++-+++-','+---+-++-+','+--++--+-+','+--++-+--+',
  '+-+++--+--','+--+++-+--','++--+-++--','-+-++-++--','+--++--++-','+-+++-+---','++-+--++--','+-+-+-++--','+--+-+++--','+--+--++-+',
  '+-++-++---','+-++-+-+--','+-+-++-+--','+---++++--','+-+--+-++-','+++--++---','+++--+-+--','+++---++--','++---+++--','--+-++++--',
  '++--++-+--','-+-+-+-++-','++----+++-','+----+-+++','++---+-+-+','++-+-+-+--','++-+-+--+-','+++----++-','++--+--++-','+--+-+-++-',
  '++++----+-','++-++---+-','+-+++---+-','-++++---+-','+-+-+---++','+++-++----','+++-+-+---','+-+-+--++-','-++-+--++-','+++-+----+',
  '++++-+----','-+++-++---','-+-+-++-+-','++---++--+','++-+--+--+','++-+++----','++++--+---','+--++++---','-+-++++---','++-+--+-+-',
  '-++---+++-','+---+-+++-','--+-+-+++-','+----++++-','--+--++++-','+++---+-+-','+-++---++-','+--+--+++-','--++--+++-','+-+---+-++',
  '-+++--+-+-','-+-++-+-+-','-+++---++-','-+-++--++-','-+---++++-','-++++--+--','-++-++-+--','--++++-+--','--++-+++--','--++-+-++-',
  '+-++++----','--++++--+-','--++-++-+-','+--+-+--++','+-++----++','-+-+++--+-','-++-+-+-+-','-+--++-++-','---+++-++-','-+--+-+++-',
  '+---+++-+-','-+--+++-+-','+-+-++--+-','+--++-++--','++-++--+--','+-++--++--','+-+--+++--','-++--+++--','++---+-++-','++-+---++-',
  '+++-+---+-','+++-+--+--','++-+-++---','++-++-+---','+-+---+++-','+-++--+-+-','-+-+--+++-','-+++-+-+--','+-++-+--+-','-++-+++---',
  '+++--+--+-','+++++-----','-+++++----','--+++++---','---+++++--','----+++++-','++++++++++',
];
const decabitByPattern = new Map<string, number>(DECABIT_PATTERNS.map((pattern, code) => [pattern, code]));
const DECABIT_CHUNK = 10;

export const decabitEncode = (value: string): string => {
  const codes: number[] = [];
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code > 126) throw new Error(`Decabit 仅支持 ASCII（0-126），字符 "${char}" 超出范围`);
    codes.push(code);
  }
  return codes.map(code => DECABIT_PATTERNS[code]).join(' ');
};

const normalizePulse = (char: string): '+' | '-' => {
  if (char === '+' || char === '1') return '+';
  if (char === '-' || char === '0') return '-';
  throw new Error(`Decabit 脉冲只能包含 +/-（或 1/0），遇到 "${char}"`);
};

export const decabitDecode = (value: string): string => {
  const compact = value.replace(/\s+/g, '');
  if (!compact) return '';
  if (compact.length % DECABIT_CHUNK !== 0) {
    throw new Error(`Decabit 脉冲数必须是 ${DECABIT_CHUNK} 的倍数，当前 ${compact.length} 个`);
  }
  let output = '';
  for (let offset = 0; offset < compact.length; offset += DECABIT_CHUNK) {
    const pattern = [...compact.slice(offset, offset + DECABIT_CHUNK)].map(normalizePulse).join('');
    const code = decabitByPattern.get(pattern);
    if (code === undefined) throw new Error(`未知 Decabit 脉冲组：${pattern}`);
    output += String.fromCharCode(code);
  }
  return output;
};

// Cetacean（CyberChef 官方）：UTF-16 码元 16bit，1→e 0→E，空格原样保留；解码兼容 KC7 实战的 A/B 变体。
const cetaceanBit = (char: string): string => [...char.charCodeAt(0).toString(2).padStart(16, '0')].map(bit => (bit === '1' ? 'e' : 'E')).join('');

export const cetaceanEncode = (value: string): string => {
  let output = '';
  for (const char of value) {
    output += char === ' ' ? ' ' : cetaceanBit(char);
  }
  return output;
};

const cetaceanNormalize = (char: string): 'E' | 'e' | ' ' => {
  if (char === ' ' || char === '\n' || char === '\t' || char === '\r') return ' ';
  if (char === 'E' || char === 'A' || char === 'a' || char === '0') return 'E';
  if (char === 'e' || char === 'B' || char === 'b' || char === '1') return 'e';
  throw new Error(`Cetacean 密文只能包含 E/e（或 A/B、1/0 变体）与空白，遇到 "${char}"`);
};

export const cetaceanDecode = (value: string): string => {
  // 尾部不足 16 位的残位按 CyberChef 原版语义静默丢弃（勿改成报错，与上游保持一致）。
  const bits = [...value].map(cetaceanNormalize).map(symbol => (symbol === ' ' ? '0000000000100000' : symbol === 'E' ? '0' : '1')).join('');
  let output = '';
  for (let offset = 0; offset + 16 <= bits.length; offset += 16) {
    output += String.fromCharCode(Number.parseInt(bits.slice(offset, offset + 16), 2));
  }
  return output;
};

// Albam：默认流派 A↔N 半表互换（+13 对合）；'shift11' 切换 CacheSleuth +11 流派（加密 +11、解密 -11）。
const ALBAM_SHIFT11 = 11;
const shiftLetter = (char: string, shift: number): string => {
  if (char >= 'A' && char <= 'Z') return String.fromCharCode(((char.charCodeAt(0) - 65 + shift + 26) % 26) + 65);
  if (char >= 'a' && char <= 'z') return String.fromCharCode(((char.charCodeAt(0) - 97 + shift + 26) % 26) + 97);
  return char;
};

export const albamTransform = (value: string, direction: 'encode' | 'decode', variant: string): string => {
  if (variant === 'shift11') {
    const shift = direction === 'encode' ? ALBAM_SHIFT11 : 26 - ALBAM_SHIFT11;
    return [...value].map(char => shiftLetter(char, shift)).join('');
  }
  return [...value].map(char => shiftLetter(char, 13)).join('');
};

// Carbonaro：烧炭党对合表（CacheSleuth 实装），加解同表；不动点 H/J/K/M/N/Q/U/W/X/Y 为该表指纹。
const CARBONARO_UPPER = 'OPGTIVCHEJKRNMABQLZDUFWXYS';
const carbonaroByUpper = new Map<string, string>([...CARBONARO_UPPER].map((mapped, index) => [String.fromCharCode(65 + index), mapped]));
const carbonaroByLower = new Map<string, string>([...CARBONARO_UPPER.toLowerCase()].map((mapped, index) => [String.fromCharCode(97 + index), mapped]));

export const carbonaroTransform = (value: string): string => [...value].map(char => carbonaroByUpper.get(char) ?? carbonaroByLower.get(char) ?? char).join('');

// Cisco Type 7：种子（两位十进制）定位固定密钥表起点，逐 hex 字节与密钥表异或；可逆弱混淆。
const CISCO_TYPE7_KEY = 'dsfd;kfoA,.iyewrkldJKDHSUB';

export const ciscoType7Decode = (value: string): string => {
  const text = value.trim();
  const match = /^(\d{2})([0-9A-F]*)$/i.exec(text);
  if (!match) throw new Error('Cisco Type 7 格式应为「两位十进制种子 + 偶长十六进制」，例如 094F479A4A');
  if (match[2].length % 2 !== 0) throw new Error('Cisco Type 7 十六进制部分长度必须为偶数');
  const seed = Number(match[1]) % CISCO_TYPE7_KEY.length;
  let output = '';
  for (let index = 0; index < match[2].length; index += 2) {
    const byte = Number.parseInt(match[2].slice(index, index + 2), 16);
    output += String.fromCharCode(byte ^ CISCO_TYPE7_KEY.charCodeAt((seed + index / 2) % CISCO_TYPE7_KEY.length));
  }
  return output;
};

// 编码用固定种子 09（Cisco 实机最常见取值，可与其他工具结果对照）。
export const ciscoType7Encode = (value: string): string => {
  const seed = 9;
  let hex = '';
  for (let index = 0; index < value.length; index += 1) {
    const byte = value.charCodeAt(index);
    if (byte > 255) throw new Error('Cisco Type 7 仅支持单字节字符');
    hex += (byte ^ CISCO_TYPE7_KEY.charCodeAt((seed + index) % CISCO_TYPE7_KEY.length)).toString(16).padStart(2, '0').toUpperCase();
  }
  return `${String(seed).padStart(2, '0')}${hex}`;
};

// ---- 智能识别谓词：与实现同源，供 detectInput 结构判定 ----

// Pizzini 形状：纯数字，贪心可完整切分（1/2 开头两位 10-29，其余一位 4-9；0 仅允许夹在两位段内）。
// 拒绝结尾孤立 1/2 而 decode 兼容为 X/Y/Z：检测刻意严于解码（数字串误报率优先），勿"对齐"。
export const looksLikePizziniShape = (value: string): boolean => {
  const text = value.trim();
  if (!/^\d{4,}$/.test(text)) return false;
  let index = 0;
  while (index < text.length) {
    if ((text[index] === '1' || text[index] === '2') && index + 1 < text.length) {
      const code = Number(text.slice(index, index + 2));
      if (code < 10 || code > 29) return false;
      index += 2;
    } else {
      const code = Number(text[index]);
      if (code < 4 || code > 9) return false;
      index += 1;
    }
  }
  return true;
};

// Decabit 形状：仅 +/- 与空白，去空白后 10 脉冲整倍数（≥2 组），且两种符号都出现。
export const looksLikeDecabitShape = (value: string): boolean => {
  const text = value.trim();
  if (!text || !/^[+\-\s]+$/.test(text)) return false;
  const compact = text.replace(/\s+/g, '');
  return compact.length >= 20 && compact.length % 10 === 0 && compact.includes('+') && compact.includes('-');
};

// Cetacean 形状（CyberChef 识别口径）：空格分隔的 E/e 段，每段 ≥16 位。
export const looksLikeCetaceanShape = (value: string): boolean => {
  const text = value.trim();
  if (!/^[eE\s]+$/.test(text)) return false;
  const segments = text.split(/\s+/).filter(Boolean);
  return segments.length >= 1 && segments.every(segment => segment.length >= 16);
};

// Cisco Type 7 形状：两位种子（≤25）+ 偶长 hex（≥2 字节）。
export const looksLikeCiscoType7Shape = (value: string): boolean => {
  const text = value.trim().replace(/\s+/g, '');
  const match = /^(\d{2})([0-9A-F]+)$/i.exec(text);
  if (!match) return false;
  return Number(match[1]) <= 25 && match[2].length >= 4 && match[2].length % 2 === 0;
};
