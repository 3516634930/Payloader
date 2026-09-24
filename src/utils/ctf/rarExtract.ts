// RAR4 条目解压器（真题缺口：SimpleRAR/进制反转修复头后需要解出条目内容）：
// 与 rarInspect（只读依赖，绝不改动）配套，单条目解出——METHOD 0x30 存储直取；
// 0x31-0x35 走 RAR3（UNP_VER=29）Huffman-LZ 解压。LZ 语义按 unrar unpack30.cpp 的
// 算法结构自写（其许可特殊，禁止逐行翻译），并与 libarchive
// archive_read_support_format_rar.c（BSD-2-Clause）逐条交叉核对：
// 位流 MSB-first；canonical Huffman（码长 1-15，16 位左对齐上限码比较）；表头 2 位
// 标志（PPM 块/沿用旧表）+ 20 个 4 位预表长（0xF 转义零串）+ 404 项主表（值相对上
// 一张表 4 位增量，16/17 重复前值、18/19 零串）；LD 字号 0-255 字面量/256 块结束/
// 257 VM 过滤器/258 复用上次匹配/259-262 老距离/263-270 短距离/271-298 完整匹配；
// 距离槽位表/长度槽位表/低位距离表（LDD，16 为重复哨兵）与两参考一致。
// 范围决策：流内 PPM 块与 VM 过滤器如实返回 unsupported（CTF 文本/flag 文件不用它们），
// 旧版 RAR（UNP_VER 15/20/26）压缩流不支持；存储路径不受版本限制。
// 红线：输入只读（输出一律新副本）；解压输出上限 64MB、Huffman 解码步数上限 2^27
// （炸弹流防护，超限抛中文错误）；解压距离不得越过已解码数据（solid 档案或损坏即抛错）；
// 解压后按文件头 FILE_CRC 做 CRC32 校验（头值为 0 时跳过——目录/空文件天然为 0）。

import { RAR4_SIGNATURE, type RarEntry } from './rarInspect';

export interface RarExtractResult {
  name: string;
  bytes: Uint8Array | null;
  method: number;
  unsupported?: string;
}

// 内存与时间预算：超过即抛错（RAR 炸弹防护），测试引用同款常量。
export const RAR_EXTRACT_MAX_OUTPUT = 64 * 1024 * 1024;
export const RAR_EXTRACT_MAX_STEPS = 2 ** 27;

// RAR3（UNP_VER=29）Huffman 表规模（unrar compress.hpp PackDef 口径，两参考一致）。
const NC30 = 299; // LD：字面量 + 长度槽位
const DC30 = 60; // DD：距离槽位
const LDC30 = 17; // LDD：长距离的低位 4 比特（0-15，16=重复哨兵）
const RC30 = 28; // RD：老距离匹配的长度槽位
const BC30 = 20; // 预表（表长编码）字母表
const HUFF_TABLE_SIZE30 = NC30 + DC30 + LDC30 + RC30; // 404
const LOW_DIST_REP_COUNT = 16;

const L_DECODE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224];
const L_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5];
const D_DECODE = [
  0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072,
  4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144, 327680,
  393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040, 1048576, 1310720,
  1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872, 3670016, 3932160,
];
const D_BITS = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
  14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18, 18,
  18, 18, 18, 18, 18, 18,
];
const SD_DECODE = [0, 4, 8, 16, 32, 64, 128, 192];
const SD_BITS = [2, 2, 3, 4, 5, 6, 6, 6];

const u16le = (bytes: Uint8Array, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);

const u32le = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

// 标准 CRC32（多项式 0xEDB88320）——RAR4 FILE_CRC 即解压后数据的 CRC32 低 32 位。
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

const crc32 = (data: Uint8Array): number => {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) c = CRC_TABLE[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

// canonical Huffman 解码表（与 unrar MakeDecodeTables 等价的自写实现）：
// decodeLen[L] 为码长 L 的左对齐（16 位）上限码，decodePos[L] 为该码长在码表中的起点。
interface HuffTable {
  decodeLen: Uint32Array;
  decodePos: Uint32Array;
  decodeNum: Uint16Array;
  maxNum: number;
}

const buildHuffTable = (lengths: ArrayLike<number>, size: number): HuffTable => {
  const counts = new Uint32Array(16);
  for (let i = 0; i < size; i += 1) counts[lengths[i] & 0xf] += 1;
  counts[0] = 0;
  const decodeLen = new Uint32Array(16);
  const decodePos = new Uint32Array(16);
  const decodeNum = new Uint16Array(size);
  let upper = 0;
  for (let len = 1; len < 16; len += 1) {
    upper += counts[len];
    decodeLen[len] = (upper << (16 - len)) >>> 0;
    upper *= 2;
    decodePos[len] = decodePos[len - 1] + counts[len - 1];
  }
  const cursor = Uint32Array.from(decodePos);
  for (let i = 0; i < size; i += 1) {
    const len = lengths[i] & 0xf;
    if (len !== 0) {
      decodeNum[cursor[len]] = i;
      cursor[len] += 1;
    }
  }
  return { decodeLen, decodePos, decodeNum, maxNum: size };
};

type LzOutcome = { kind: 'ok'; bytes: Uint8Array } | { kind: 'unsupported'; reason: string };

// RAR3（UNP_VER=29）LZ 解压：packed 为该条目数据区（UNP_VER/预算已由调用方校验）。
const unpackRar3 = (packed: Uint8Array, unpSize: number): LzOutcome => {
  const limit = packed.length;
  let inAddr = 0;
  let inBit = 0;
  let steps = 0;

  // MSB-first 位读取：越界字节按 0 补齐（与 unrar BitInput::getbits 的 24 位窗口一致）。
  const peek16 = (): number => {
    const b0 = inAddr < limit ? packed[inAddr] : 0;
    const b1 = inAddr + 1 < limit ? packed[inAddr + 1] : 0;
    const b2 = inAddr + 2 < limit ? packed[inAddr + 2] : 0;
    return ((((b0 << 16) | (b1 << 8) | b2) >>> (8 - inBit)) & 0xffff) >>> 0;
  };
  const skip = (bits: number): void => {
    const total = bits + inBit;
    inAddr += total >> 3;
    inBit = total & 7;
  };
  const readBits = (bits: number): number => {
    if (bits === 0) return 0;
    const value = peek16() >>> (16 - bits);
    skip(bits);
    return value;
  };

  const decode = (table: HuffTable): number => {
    steps += 1;
    if (steps > RAR_EXTRACT_MAX_STEPS) {
      throw new Error(`解压步数超出预算上限 ${RAR_EXTRACT_MAX_STEPS}（RAR 炸弹流防护），条目已中止`);
    }
    const bitField = peek16() & 0xfffe;
    let bits = 15;
    for (let len = 1; len < 15; len += 1) {
      if (bitField < table.decodeLen[len]) {
        bits = len;
        break;
      }
    }
    skip(bits);
    const dist = (bitField - table.decodeLen[bits - 1]) >>> (16 - bits);
    const pos = table.decodePos[bits] + dist;
    if (pos >= table.maxNum) {
      throw new Error(`RAR LZ 流损坏：Huffman 解码越界（码长 ${bits}，位置 ${pos} ≥ ${table.maxNum}）`);
    }
    return table.decodeNum[pos];
  };

  let oldTable = new Uint8Array(HUFF_TABLE_SIZE30);
  // 先建空表占位（首次 readTables 之前不会解码，且空表解码会在越界检查处抛错）。
  let ld: HuffTable = buildHuffTable(oldTable.subarray(0, NC30), NC30);
  let dd: HuffTable = buildHuffTable(oldTable.subarray(NC30, NC30 + DC30), DC30);
  let ldd: HuffTable = buildHuffTable(oldTable.subarray(NC30 + DC30, NC30 + DC30 + LDC30), LDC30);
  let rd: HuffTable = buildHuffTable(oldTable.subarray(NC30 + DC30 + LDC30), RC30);
  let prevLowDist = 0;
  let lowDistRepCount = 0;

  const readTables = (): LzOutcome | null => {
    skip((8 - inBit) & 7); // 表头恒按字节对齐
    const bitField = peek16();
    if ((bitField & 0x8000) !== 0) {
      return { kind: 'unsupported', reason: 'PPMd 压缩流（RAR3 -m5 best 常见形态）：本引擎不支持' };
    }
    const keepOld = (bitField & 0x4000) !== 0;
    skip(2);
    prevLowDist = 0;
    lowDistRepCount = 0;
    if (!keepOld) oldTable.fill(0);

    const bitLength = new Uint8Array(BC30);
    let i = 0;
    while (i < BC30) {
      const length = readBits(4);
      if (length !== 15) {
        bitLength[i] = length;
        i += 1;
        continue;
      }
      const zeroCount = readBits(4);
      if (zeroCount === 0) {
        bitLength[i] = 15; // 转义后的字面 15
        i += 1;
      } else {
        for (let k = 0; k < zeroCount + 2 && i < BC30; k += 1) {
          bitLength[i] = 0;
          i += 1;
        }
      }
    }
    const bd = buildHuffTable(bitLength, BC30);

    const table = new Uint8Array(HUFF_TABLE_SIZE30);
    i = 0;
    while (i < HUFF_TABLE_SIZE30) {
      const symbol = decode(bd);
      if (symbol < 16) {
        table[i] = (symbol + oldTable[i]) & 0xf; // 相对上一张表的 4 位增量
        i += 1;
      } else if (symbol < 18) {
        const count = symbol === 16 ? readBits(3) + 3 : readBits(7) + 11;
        if (i === 0) throw new Error('RAR LZ 流损坏：表首部出现重复前值码（16/17）');
        for (let k = 0; k < count && i < HUFF_TABLE_SIZE30; k += 1) {
          table[i] = table[i - 1];
          i += 1;
        }
      } else {
        const count = symbol === 18 ? readBits(3) + 3 : readBits(7) + 11;
        for (let k = 0; k < count && i < HUFF_TABLE_SIZE30; k += 1) {
          table[i] = 0;
          i += 1;
        }
      }
    }
    oldTable = table;
    ld = buildHuffTable(table.subarray(0, NC30), NC30);
    dd = buildHuffTable(table.subarray(NC30, NC30 + DC30), DC30);
    ldd = buildHuffTable(table.subarray(NC30 + DC30, NC30 + DC30 + LDC30), LDC30);
    rd = buildHuffTable(table.subarray(NC30 + DC30 + LDC30), RC30);
    return null;
  };

  const out = new Uint8Array(unpSize);
  let outLen = 0;
  let lastLength = 0;
  const oldDist = [0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];

  const insertOldDist = (distance: number): void => {
    oldDist[3] = oldDist[2];
    oldDist[2] = oldDist[1];
    oldDist[1] = oldDist[0];
    oldDist[0] = distance;
  };

  // 非压缩流（单文件条目）距离只能指向已解码区：越过即 solid 档案或损坏，抛错。
  const copyString = (length: number, distance: number): void => {
    if (distance > outLen) {
      throw new Error(`RAR LZ 流损坏：解压距离 ${distance} 越过已解码的 ${outLen} 字节（solid 档案跨文件引用或数据损坏）`);
    }
    let capped = length;
    if (capped > unpSize - outLen) capped = unpSize - outLen;
    const src = outLen - distance;
    for (let k = 0; k < capped; k += 1) out[outLen + k] = out[src + k];
    outLen += capped;
  };

  const first = readTables();
  if (first !== null) return first;

  while (outLen < unpSize) {
    if (inAddr >= limit) break; // 输入耗尽
    const symbol = decode(ld);

    if (symbol < 256) {
      out[outLen] = symbol;
      outLen += 1;
      continue;
    }
    if (symbol >= 271) {
      let length = L_DECODE[symbol - 271] + 3;
      const lBits = L_BITS[symbol - 271];
      if (lBits > 0) length += readBits(lBits);

      const distSymbol = decode(dd);
      let distance = D_DECODE[distSymbol] + 1;
      const dBits = D_BITS[distSymbol];
      if (dBits > 0) {
        if (distSymbol > 9) {
          if (dBits > 4) distance += readBits(dBits - 4) << 4;
          if (lowDistRepCount > 0) {
            lowDistRepCount -= 1;
            distance += prevLowDist;
          } else {
            const low = decode(ldd);
            if (low === 16) {
              lowDistRepCount = LOW_DIST_REP_COUNT - 1;
              distance += prevLowDist;
            } else {
              distance += low;
              prevLowDist = low;
            }
          }
        } else {
          distance += readBits(dBits);
        }
      }
      if (distance >= 0x2000) length += 1;
      if (distance >= 0x40000) length += 1;
      insertOldDist(distance);
      lastLength = length;
      copyString(length, distance);
      continue;
    }
    if (symbol === 256) {
      const bitField = peek16();
      if ((bitField & 0x8000) !== 0) {
        skip(1); // "1"：本文件内紧跟新表
        const next = readTables();
        if (next !== null) return next;
        continue;
      }
      skip(2); // "00"/"01"：本文件数据结束（第二位是下一文件的表标志，与本文件无关）
      break;
    }
    if (symbol === 257) {
      return { kind: 'unsupported', reason: 'RAR3 VM 过滤器流（delta/E8 等预处理）：本引擎不支持' };
    }
    if (symbol === 258) {
      if (lastLength !== 0) copyString(lastLength, oldDist[0]);
      continue;
    }
    if (symbol < 263) {
      const distNum = symbol - 259;
      const distance = oldDist[distNum];
      for (let k = distNum; k > 0; k -= 1) oldDist[k] = oldDist[k - 1];
      oldDist[0] = distance;
      const lenSymbol = decode(rd);
      let length = L_DECODE[lenSymbol] + 2;
      const lBits = L_BITS[lenSymbol];
      if (lBits > 0) length += readBits(lBits);
      lastLength = length;
      copyString(length, distance);
      continue;
    }
    const index = symbol - 263; // 263-270：短距离匹配，长度恒为 2
    let distance = SD_DECODE[index] + 1;
    const sBits = SD_BITS[index];
    if (sBits > 0) distance += readBits(sBits);
    insertOldDist(distance);
    lastLength = 2;
    copyString(2, distance);
  }

  if (outLen !== unpSize) {
    throw new Error(`RAR 数据截断：解出 ${outLen}/${unpSize} 字节（数据区不完整）`);
  }
  return { kind: 'ok', bytes: out };
};

const verifyCrc = (name: string, bytes: Uint8Array, fileCrc: number): void => {
  if (fileCrc === 0) return;
  const actual = crc32(bytes);
  if (actual !== fileCrc) {
    throw new Error(`条目 "${name}" CRC32 校验失败：文件头 FILE_CRC=0x${fileCrc.toString(16)} ≠ 解出数据 0x${actual.toString(16)}（数据损坏）`);
  }
};

export const extractRarEntry = (bytes: Uint8Array, entry: RarEntry): RarExtractResult => {
  for (let i = 0; i < 7; i += 1) {
    if (bytes[i] !== RAR4_SIGNATURE[i]) {
      throw new Error('不是 RAR4 数据：签名 52 61 72 21 1A 07 00 不完好（RAR5 或签名被改，可先运行 fixRarSignature 修复后重试）');
    }
  }
  const { name, method } = entry;
  if (entry.offset < 0 || entry.offset + 32 > bytes.length) {
    throw new Error(`条目 "${name}" 文件头偏移 ${entry.offset} 越界或头不完整（输入共 ${bytes.length} 字节）`);
  }
  const flags = u16le(bytes, entry.offset + 3);
  const headSize = u16le(bytes, entry.offset + 5);
  if (headSize < 32) {
    throw new Error(`条目 "${name}" 文件头 HEAD_SIZE=${headSize} < 32，字段不完整`);
  }

  if (entry.isDirectory) return { name, bytes: null, method, unsupported: '目录条目：无文件数据' };
  if (entry.encrypted) {
    return { name, bytes: null, method, unsupported: '条目置加密位（0x0004）：需口令才能解压；若为伪加密可先运行 fixRarPseudoEncryption 清位后重试' };
  }
  if ((flags & 0x0003) !== 0) {
    return { name, bytes: null, method, unsupported: '分卷条目（SPLIT 位置位）：跨卷数据在本卷内不完整' };
  }
  if (method < 0x30 || method > 0x35) {
    return { name, bytes: null, method, unsupported: `METHOD=0x${method.toString(16)} 越界（合法 0x30 存储-0x35 最佳）` };
  }

  const unpSize = u32le(bytes, entry.offset + 11) + ((flags & 0x0100) !== 0 ? u32le(bytes, entry.offset + 36) * 0x100000000 : 0);
  if (unpSize > RAR_EXTRACT_MAX_OUTPUT) {
    throw new Error(`解压输出预算超限：UNP_SIZE=${unpSize} > ${RAR_EXTRACT_MAX_OUTPUT}（RAR 炸弹防护）`);
  }
  const fileCrc = u32le(bytes, entry.offset + 16);
  const unpVer = bytes[entry.offset + 24];
  const dataStart = entry.offset + headSize;
  if (dataStart > bytes.length || dataStart + entry.packedSize > bytes.length) {
    throw new Error(`条目 "${name}" 数据区越界：声明 ${entry.packedSize} 字节起于 ${dataStart}，输入仅剩 ${bytes.length - dataStart} 字节（文件截断）`);
  }

  if (method === 0x30) {
    if (entry.packedSize !== unpSize) {
      throw new Error(`条目 "${name}" 存储尺寸不一致：PACK_SIZE=${entry.packedSize} ≠ UNP_SIZE=${unpSize}（头被改动或数据损坏）`);
    }
    const out = bytes.slice(dataStart, dataStart + unpSize);
    verifyCrc(name, out, fileCrc);
    return { name, bytes: out, method };
  }

  if (unpVer !== 29) {
    return { name, bytes: null, method, unsupported: `旧版 RAR 解压流（UNP_VER=${unpVer}）：本引擎仅支持 RAR3 的 29` };
  }
  if (unpSize === 0) return { name, bytes: new Uint8Array(0), method };

  const outcome = unpackRar3(bytes.subarray(dataStart, dataStart + entry.packedSize), unpSize);
  if (outcome.kind === 'unsupported') return { name, bytes: null, method, unsupported: outcome.reason };
  verifyCrc(name, outcome.bytes, fileCrc);
  return { name, bytes: outcome.bytes, method };
};
