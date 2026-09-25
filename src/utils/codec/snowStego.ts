// SNOW 空白隐写引擎（文本类隐写批次，对标随波逐流"TTL隐写解码 / snow雪花隐写提取"族）。
// 格式调研来源（交叉验证，逐位核对过 C 源码）：
// - 官方主页/说明：http://www.darkside.com.au/snow/ 与 description.html（作者 Matthew Kwan，Apache-2.0）。
// - 作者 GitHub 镜像源码：github.com/mattkwan-zz/snow 的 encode.c（encode_write_value / decode_bits /
//   decode_whitespace / message_extract），版权 1999 Matthew Kwan。
// 官方 snow 规范要点：
// 1. 载体是每行行尾的空格/制表符序列（\r 属于行终止符，不是载体字符）。
// 2. 消息以"行尾第一个 tab"为起始标记；在找到该 tab 之前，行尾以空格开头的行被跳过（防御邮件头污染）。
// 3. 数据每 3 bit 一组，编码成"0-7 个空格 + tab 分隔符"：组值 nspc = bit1 | bit2<<1 | bit3<<2
//    （C 源码注释 "Reverse the bit ordering"，解码端 decode_bits 同序还原）；nspc=0 的组仅输出一个
//    裸 tab；行末最后一组非零时不补 tab。消息长度不是字段的 3 倍数时补 0 对齐，解码端自然丢弃余位。
// 4. 官方还支持 Huffman 压缩（-C）与 ICE 加密（-p）；两者与本引擎无关，若提取出的比特流疑似压缩/加密
//    层，输出诊断提示（本模块不实现 inflate/ICE）。
// CTF 场景大量题目并非用官方 snow.exe 生成，而是"空格=0/tab=1 每 8 字符 1 字节"的朴素映射（含倒置
// 映射、全文空白而非行尾空白两种不规范变体），以及位序未反转的简化 3bit 生成器——全部作为变体并列
// 尝试并按可打印率排名。纯函数、零依赖浏览器 API、同步、node --test 可跑；输入上限 20MB。

import { utf8Decoder, utf8Encoder } from './alphabets';

export const SNOW_MAX_TEXT_BYTES = 20 * 1024 * 1024;

export interface SnowVariant {
  mapping: string; // 变体名（映射 + 提取范围 + 位序）
  bits: number; // 提取出的总比特数
  bytes: Uint8Array; // 比特流按 8bit 组字节（floor）
  text: string; // 字节流的可读文本（UTF-8 优先，含替换符时退 latin1）
  printable: boolean; // 可打印率是否达标（≥0.85）
  printableRatio: number; // 可打印字节占比 0-1
  note: string; // 变体说明/异常（如超 7 空格截断）
}

export interface SnowResult {
  bytes: Uint8Array; // 最优变体的字节流（无任何比特时为空数组）
  variants: SnowVariant[]; // 全部变体，按 可打印率+flag 形态 降序
}

const FLAG_SHAPE = /flag\{|ctf\{|picoctf\{|key[=: ]|pass(word)?[=: ]|\{.*?\}/i;

const bitsToBytes = (bits: string): Uint8Array => {
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes[index / 8] = Number.parseInt(bits.slice(index, index + 8), 2);
  }
  return bytes;
};

const decodeBytesText = (bytes: Uint8Array): string => {
  if (!bytes.length) return '';
  const utf8 = utf8Decoder.decode(bytes);
  return utf8.includes('\uFFFD') ? Array.from(bytes, byte => String.fromCharCode(byte)).join('') : utf8;
};

const printableRatioOf = (bytes: Uint8Array): number => {
  if (!bytes.length) return 0;
  let printable = 0;
  for (const byte of bytes) {
    if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) printable += 1;
  }
  return printable / bytes.length;
};

const makeVariant = (mapping: string, bits: string, note: string): SnowVariant => {
  const bytes = bitsToBytes(bits);
  const text = decodeBytesText(bytes);
  const printableRatio = printableRatioOf(bytes);
  return { mapping, bits: bits.length, bytes, text, printable: bytes.length > 0 && printableRatio >= 0.85, printableRatio, note };
};

// 行尾空白载体提取：\r\n / \n 均按行终止符处理（\r 不算载体），返回每行的行尾 [ \t]+ 序列。
const trailingWhitespacePerLine = (text: string): string[] => {
  const runs: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const run = /[\t ]+$/.exec(line);
    if (run) runs.push(run[0]);
  }
  return runs;
};

// 朴素 1bit 映射：carrier 内空格/tab 分别映射 0/1（或倒置）。
const naiveBits = (carrier: string, spaceIsZero: boolean): string => {
  let bits = '';
  for (const char of carrier) {
    if (char === ' ') bits += spaceIsZero ? '0' : '1';
    else if (char === '\t') bits += spaceIsZero ? '1' : '0';
  }
  return bits;
};

// 官方 3bit 语义：每组 = 空格数 nspc + tab 分隔；位序 b1=nspc&1 先出（C 源码反转序）。
// strictStart=true 时要求起始 tab 标记（官方 message_extract 语义）；false 为宽容模式（常见不规范题）。
// reversed=false 表示生成器未做位反转（简化实现，nspc 高位对应先出的 bit）。
const snow3Bits = (runs: string[], strictStart: boolean, reversed: boolean): { bits: string; note: string } => {
  let bits = '';
  let started = !strictStart;
  let illegal = false;
  for (const run of runs) {
    let cursor = 0;
    if (!started) {
      // 官方规则：行尾以空格开头的行在起始标记前被跳过
      if (run[0] !== '\t') continue;
      started = true;
      cursor = 1;
      if (cursor >= run.length) continue;
    }
    let spaces = 0;
    for (; cursor < run.length; cursor += 1) {
      const char = run[cursor];
      if (char === ' ') {
        spaces += 1;
      } else {
        // tab：一组结束
        if (spaces > 7) illegal = true;
        if (illegal) break;
        bits += reversed
          ? `${spaces & 1}${(spaces >> 1) & 1}${(spaces >> 2) & 1}`
          : `${(spaces >> 2) & 1}${(spaces >> 1) & 1}${spaces & 1}`;
        spaces = 0;
      }
    }
    if (illegal) break;
    // 行末：剩余空格即最后一组（官方 decode_whitespace：spc>0 时收尾成组）
    if (spaces > 0) {
      if (spaces > 7) illegal = true;
      else bits += reversed
        ? `${spaces & 1}${(spaces >> 1) & 1}${(spaces >> 2) & 1}`
        : `${(spaces >> 2) & 1}${(spaces >> 1) & 1}${spaces & 1}`;
    }
  }
  const note = illegal ? '存在超过 7 个连续空格的非法组，已在该处截断' : '';
  return { bits, note };
};

export const extractSnow = (text: string): SnowResult => {
  if (text.length > SNOW_MAX_TEXT_BYTES) {
    throw new Error(`输入 ${text.length} 字符超过 snow 引擎上限 ${SNOW_MAX_TEXT_BYTES}（20MB）`);
  }
  const lineRuns = trailingWhitespacePerLine(text);
  const lineCarrier = lineRuns.join('');
  const allCarrier = (text.match(/[\t ]+/g) || []).join('');
  const variants: SnowVariant[] = [
    makeVariant('space=0,tab=1（行尾空白）', naiveBits(lineCarrier, true), '朴素映射：8 个空白字符 1 字节，仅取各行行尾'),
    makeVariant('tab=0,space=1（行尾空白）', naiveBits(lineCarrier, false), '朴素映射倒置：8 个空白字符 1 字节，仅取各行行尾'),
    makeVariant('space=0,tab=1（全文空白）', naiveBits(allCarrier, true), '不规范变体：忽略"仅行尾"约束，全文空白连读'),
    makeVariant('tab=0,space=1（全文空白）', naiveBits(allCarrier, false), '不规范变体倒置：全文空白连读'),
    (() => {
      const { bits, note } = snow3Bits(lineRuns, true, true);
      return makeVariant('snow 3bit（官方规范·严格起始tab）', bits, note || '官方 snow.exe 语义：tab 起始标记 + 3bit/组（位序反转）+ tab 分隔');
    })(),
    (() => {
      const { bits, note } = snow3Bits(lineRuns, false, true);
      return makeVariant('snow 3bit（官方位序·无起始tab）', bits, note || '宽容模式：不要求起始 tab 标记，位序仍按官方反转');
    })(),
    (() => {
      const { bits, note } = snow3Bits(lineRuns, true, false);
      return makeVariant('snow 3bit（简化生成器·严格起始tab）', bits, note || '简化实现位序：空格数按高位在前直接读 3bit');
    })(),
    (() => {
      const { bits, note } = snow3Bits(lineRuns, false, false);
      return makeVariant('snow 3bit（简化生成器·无起始tab）', bits, note || '简化实现位序 + 宽容起始');
    })(),
  ];
  variants.sort((left, right) => {
    const flagDelta = Number(FLAG_SHAPE.test(right.text)) - Number(FLAG_SHAPE.test(left.text));
    if (flagDelta !== 0) return flagDelta;
    if (right.printableRatio !== left.printableRatio) return right.printableRatio - left.printableRatio;
    return right.bits - left.bits;
  });
  const best = variants.find(variant => variant.bits > 0) ?? variants[0];
  return { bytes: best.bits > 0 ? best.bytes : new Uint8Array(0), variants };
};

export interface SnowExtractReport {
  tool: string;
  bestMapping: string;
  hiddenText: string;
  hiddenBytesHex: string;
  variants: Array<{ mapping: string; bits: number; bytes: number; printableRatio: number; preview: string; note: string }>;
  gzipLayer: boolean;
}

export const snowStegoReport = (value: string): string => {
  const result = extractSnow(value);
  const best = result.variants.find(variant => variant.bits > 0);
  // gzip 检测扫全部变体：gzip 载荷是二进制，按可打印率挑"最优变体"并无意义，
  // 任一变体解出 1f 8b 魔数即值得提示（压缩层在官方 snow -C / PacketWhisper 链路里常见）。
  const gzipVariant = result.variants.find(variant => variant.bytes.length >= 2 && variant.bytes[0] === 0x1f && variant.bytes[1] === 0x8b);
  const report: SnowExtractReport = {
    tool: 'snow-whitespace-stego',
    bestMapping: best?.mapping ?? '',
    hiddenText: best ? best.text.replace(/\p{Cc}/gu, '.') : '',
    hiddenBytesHex: best ? Array.from(best.bytes, byte => byte.toString(16).padStart(2, '0')).join('') : '',
    variants: result.variants.map(variant => ({
      mapping: variant.mapping,
      bits: variant.bits,
      bytes: variant.bytes.length,
      printableRatio: Number(variant.printableRatio.toFixed(4)),
      preview: variant.text.slice(0, 120).replace(/\p{Cc}/gu, '.'),
      note: variant.note,
    })),
    gzipLayer: !!gzipVariant,
  };
  return JSON.stringify(report, null, 2);
};

// ---- 编码方向（出题/自测闭环） ----

const bytesToBits = (bytes: Uint8Array): string => {
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  return bits;
};

// 简单换行处理：把空白追加到最后一行行尾（原行尾已有空白则先清掉，避免破坏起始标记语义）。
const appendCarrier = (text: string, carrier: string): string => {
  const cleaned = text.replace(/[\t ]+(\r?\n)?$/, (_match, newline: string | undefined) => newline ?? '');
  return cleaned + carrier;
};

export const embedSnow = (text: string, payload: string | Uint8Array, mode: 'bit' | 'snow3' = 'bit'): string => {
  if (text.length > SNOW_MAX_TEXT_BYTES) {
    throw new Error(`载体 ${text.length} 字符超过 snow 引擎上限 ${SNOW_MAX_TEXT_BYTES}（20MB）`);
  }
  const bytes = typeof payload === 'string' ? utf8Encoder.encode(payload) : payload;
  if (!bytes.length) throw new Error('snow 编码需要非空 payload');
  if (mode === 'bit') {
    // 朴素映射：space=0 / tab=1，每字节 8 个空白字符，整体追加在最后一行行尾
    const bits = bytesToBits(bytes);
    const carrier = Array.from(bits, bit => (bit === '0' ? ' ' : '\t')).join('');
    return appendCarrier(text, carrier);
  }
  // 官方规范：起始 tab 标记 + 每 3bit 一组（位序反转）+ tab 分隔；末组空格数非 0 时不补 tab
  const bits = bytesToBits(bytes);
  const padded = bits + '0'.repeat((3 - (bits.length % 3)) % 3);
  let carrier = '\t';
  let needsTab = false;
  for (let index = 0; index < padded.length; index += 3) {
    const b1 = padded[index] === '1' ? 1 : 0;
    const b2 = padded[index + 1] === '1' ? 1 : 0;
    const b3 = padded[index + 2] === '1' ? 1 : 0;
    const nspc = b1 | (b2 << 1) | (b3 << 2);
    if (needsTab) carrier += '\t'; // 上一组空格与这一组之间的分隔符（C 源码无条件先补）
    if (nspc === 0) {
      carrier += '\t'; // 零值组：单独一个裸 tab 表示该组存在
      needsTab = false;
    } else {
      carrier += ' '.repeat(nspc);
      needsTab = true;
    }
  }
  return appendCarrier(text, carrier);
};
