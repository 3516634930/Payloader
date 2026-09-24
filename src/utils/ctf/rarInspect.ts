// RAR4 取证解析引擎（真题缺口：攻防世界 SimpleRAR 头字节损坏 + 祥云杯 RAR 伪加密）：
// marker/主头/文件头逐头遍历出条目清单（HEAD_CRC 不校验——修复题的 CRC 本身就是坏的），
// 附签名重写与文件头加密位清除两个修复器（返回新副本，绝不改入参）。
// 头类型按 unrar headers.hpp 实际映射（0x72 marker/0x73 主头/0x74 文件头/0x75 旧注释/0x76 AV/
// 0x77 旧子块/0x78 恢复记录/0x79 签名/0x7A 新子块/0x7B 归档结束）；文件头布局：
// PACK_SIZE@7/UNP_SIZE@11/HOST_OS@15/METHOD@25/NAME_SIZE@26/ATTR@28（LARGE 0x100 时
// HIGH_PACK@32/HIGH_UNP@36，名区顺延 8 字节；SALT 0x400 时名区后随 8 字节盐值，均在 HEAD_SIZE 内）。
// 加密位口径（重要）：RAR4 文件头真实加密位是 HEAD_FLAGS 的 0x0004（unrar FHFL_ENCRYPTED，置位
// 即令解压器索要口令——伪加密题置的就是它）；0x0008 是 RAR<2.0 遗留注释位（RAR3 恒不置位）。
// fixRarPseudoEncryption 对两位都清（同时覆盖题面 bit3 口径与真实格式口径），卷位/SFX/solid/
// SALT/EXT 时间位一律不动。主头头部加密位（0x0080）只标注不清——头真被加密时遍历本就停止。
// RAR5（签名尾字节 01 00）块格式与 RAR4 完全不同：version 返回 null 并标注，不解析；
// SFX/附加数据前缀由 fixRarSignature 的前 512 字节窗口搜索处理（命中即重写 marker 并丢弃前缀）。
// 纯函数、同步、只读输入、无 DOM/eval/网络/依赖。红线：头数 10 万、异常标注 500 条封顶。

export const RAR_MAX_HEADS = 100000;

export interface RarEntry {
  name: string;
  offset: number; // 文件头起始偏移（数据区 = offset + HEAD_SIZE 起 PACK_SIZE 字节）
  packedSize: number; // 含 LARGE 高 32 位合成的 64 位值（double 精度内）
  method: number; // 0x30=存储，0x31-0x35=压缩档位（fastest→best）
  encrypted: boolean; // HEAD_FLAGS 0x0004 加密位
  isDirectory: boolean; // Win/DOS 系 HOST_OS 下 ATTR 0x10、Unix 系 ATTR 0x4000，或名尾随分隔符
}

export interface RarInspectResult {
  version: 'rar4' | null; // null：RAR5 或签名尾字节损坏（后者仍尽力遍历并标注）
  entries: RarEntry[];
  anomalies: string[];
}

export const RAR4_SIGNATURE: readonly number[] = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];

const MAIN_HEAD = 0x73;
const FILE_HEAD = 0x74;
const NEWSUB_HEAD = 0x7a;
const ENDARC_HEAD = 0x7b;

const KNOWN_HEAD_TYPES = new Set<number>([0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b]);

// 文件头 HEAD_FLAGS 位（unrar file.hpp 口径）
const FH_SPLIT_BEFORE = 0x0001;
const FH_SPLIT_AFTER = 0x0002;
const FH_ENCRYPTED = 0x0004;
const FH_COMMENT_LEGACY = 0x0008;
const FH_LARGE = 0x0100;
const FH_UNICODE = 0x0200;
const FH_SALT = 0x0400;

// 主头 HEAD_FLAGS 位
const MH_VOLUME = 0x0001;
const MH_ENCRYPTVER = 0x0080;

const u16le = (bytes: Uint8Array, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);

const u32le = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

// 真·latin1 解码（与 pdfInspect/gifInspect 同口径）：字节↔字符一一对应，分块 fromCharCode。
const latin1ToString = (bytes: Uint8Array): string => {
  let out = '';
  const CHUNK = 8192;
  for (let start = 0; start < bytes.length; start += CHUNK) {
    out += String.fromCharCode(...bytes.subarray(start, Math.min(start + CHUNK, bytes.length)));
  }
  return out;
};

// 签名前 6 字节匹配（第 7 字节区分 RAR4=0x00 / RAR5=0x01，单独判）。
const matchesRarPrefix = (bytes: Uint8Array, offset: number): boolean => {
  if (offset < 0 || offset + 7 > bytes.length) return false;
  for (let index = 0; index < 6; index += 1) {
    if (bytes[offset + index] !== RAR4_SIGNATURE[index]) return false;
  }
  return true;
};

interface HeadVisit {
  offset: number;
  type: number;
  flags: number;
  size: number;
  addedSize: number; // 头后数据区字节数（文件头即 PACK_SIZE，含 LARGE 高 32 位）
}

// 逐头遍历：marker 恒按 7 字节跳过（签名已校验，不信任其 SIZE 字段）；HEAD_CRC 不校验。
// 坏头/截断/未知类型只标注并停止，已解析的头照常返回（修复题要的正是"坏之前的部分"）。
const walkHeads = (bytes: Uint8Array, note: (message: string) => void): HeadVisit[] => {
  const heads: HeadVisit[] = [];
  let position = 7;
  while (position + 7 <= bytes.length) {
    const type = bytes[position + 2];
    const flags = u16le(bytes, position + 3);
    const size = u16le(bytes, position + 5);
    if (!KNOWN_HEAD_TYPES.has(type)) {
      note(`偏移 ${position} 出现未知头类型 0x${type.toString(16).padStart(2, '0')}，停止遍历（头损坏或非 RAR4 数据）`);
      break;
    }
    if (size < 7) {
      note(`偏移 ${position} 的头 HEAD_SIZE=${size} < 7，停止遍历（头损坏）`);
      break;
    }
    if (position + size > bytes.length) {
      note(`偏移 ${position} 的头越过文件末尾（文件截断），停止遍历`);
      break;
    }
    let addedSize = 0;
    if (type === FILE_HEAD || type === NEWSUB_HEAD) {
      // 文件头/新子块共享文件头布局：数据区长度在 PACK_SIZE（+LARGE 高 32 位）
      addedSize = u32le(bytes, position + 7);
      if (flags & FH_LARGE) addedSize += u32le(bytes, position + 32) * 0x100000000;
    } else if (flags & 0x0001) {
      // 通用 LONG_BLOCK 位：头后数据区长度在 +7 的 4 字节
      addedSize = u32le(bytes, position + 7);
    }
    heads.push({ offset: position, type, flags, size, addedSize });
    if (heads.length >= RAR_MAX_HEADS) {
      note(`头数量达到 ${RAR_MAX_HEADS} 上限，停止遍历`);
      break;
    }
    if (type === MAIN_HEAD && (flags & MH_ENCRYPTVER) !== 0) {
      note(`偏移 ${position} 主头置头部加密位（0x0080）：后续头本身被加密，遍历到此为止，条目清单不完整`);
      break;
    }
    const next = position + size + addedSize;
    if (next > bytes.length) {
      note(`偏移 ${position} 的数据区越过文件末尾（声明 ${addedSize} 字节，实际仅剩 ${bytes.length - position - size} 字节，文件截断）`);
      position = next;
      break;
    }
    position = next;
    if (type === ENDARC_HEAD) {
      if (position < bytes.length) {
        note(`ENDARC 之后仍有 ${bytes.length - position} 字节尾附数据（binwalk 式嵌入高发位）`);
      }
      break;
    }
  }
  return heads;
};

// 文件名定位（LARGE 偏移/NUL 双名截 ASCII 段/越界裁剪到可得部分）。
const readEntryName = (bytes: Uint8Array, offset: number, flags: number, size: number): string => {
  const nameSize = u16le(bytes, offset + 26);
  const nameOffset = offset + 32 + (flags & FH_LARGE ? 8 : 0);
  const nameEnd = Math.min(nameOffset + nameSize, offset + size, bytes.length);
  const raw = nameEnd > nameOffset ? bytes.subarray(nameOffset, nameEnd) : bytes.subarray(nameOffset, nameOffset);
  if (flags & FH_UNICODE) {
    const nul = raw.indexOf(0);
    if (nul >= 0) return latin1ToString(raw.subarray(0, nul));
  }
  return latin1ToString(raw);
};

export const inspectRar = (bytes: Uint8Array): RarInspectResult => {
  if (bytes.length < 7 || !matchesRarPrefix(bytes, 0)) {
    throw new Error(`不是 RAR 文件：缺少 RAR4 签名前缀 52 61 72 21 1A 07（总长 ${bytes.length} 字节）；签名被改的修复题可先运行 fixRarSignature`);
  }
  // RAR5 完整签名为 8 字节（尾两字节 01 00）：第 7 字节 0x01 但第 8 字节非 0x00 视为 marker
  // SIZE 字段被改（SimpleRAR 型尾字节损坏），按 marker 恒 7 字节继续遍历并标注。
  if (bytes[6] === 0x01 && bytes[7] === 0x00) {
    return {
      version: null,
      entries: [],
      anomalies: ['检测到 RAR5 签名（52 61 72 21 1A 07 01 00）：RAR5 块格式与 RAR4 完全不同，本引擎不解析'],
    };
  }
  const anomalies: string[] = [];
  const note = (message: string): void => {
    if (anomalies.length < 500) anomalies.push(message);
  };
  if (bytes[6] !== 0x00) {
    note(`签名第 7 字节为 0x${bytes[6].toString(16).padStart(2, '0')}（RAR4 应为 0x00，marker SIZE 字段被改）：已按 marker 恒 7 字节继续遍历，可运行 fixRarSignature 重写`);
  }

  const heads = walkHeads(bytes, note);
  const entries: RarEntry[] = [];
  let sawEndarc = false;
  for (const head of heads) {
    if (head.type === MAIN_HEAD) {
      if (head.flags & MH_VOLUME) note('偏移 ' + head.offset + ' 主头置分卷位（0x0001）：多卷档案，本卷可能不含完整数据');
      continue;
    }
    if (head.type === ENDARC_HEAD) { sawEndarc = true; continue; }
    if (head.type !== FILE_HEAD) continue; // 旧注释/AV/子块/恢复记录等：遍历已跳过，条目不收
    if (head.size < 32) {
      note(`偏移 ${head.offset} 的文件头 HEAD_SIZE=${head.size} < 32，字段不完整，跳过条目记录`);
      continue;
    }
    const hostOs = bytes[head.offset + 15];
    const method = bytes[head.offset + 25];
    const nameSize = u16le(bytes, head.offset + 26);
    const attr = u32le(bytes, head.offset + 28);
    const nameOffset = head.offset + 32 + (head.flags & FH_LARGE ? 8 : 0);
    if (nameOffset + nameSize > head.offset + head.size) {
      note(`偏移 ${head.offset} 的文件名声明 ${nameSize} 字节越过头边界，已按可得部分截取`);
    }
    const name = readEntryName(bytes, head.offset, head.flags, head.size);
    if (head.flags & FH_UNICODE) {
      note(`文件 "${name}" 带 Unicode 双名，仅取 ASCII 段（增量 Unicode 编码不还原，边界声明）`);
    }
    let isDirectory = name.endsWith('\\') || name.endsWith('/');
    if (hostOs <= 2) isDirectory = isDirectory || (attr & 0x10) !== 0;
    else if (hostOs === 3) isDirectory = isDirectory || (attr & 0x4000) !== 0;
    const encrypted = (head.flags & FH_ENCRYPTED) !== 0;
    if (encrypted && (head.flags & FH_SALT) === 0) {
      note(`文件 "${name}" 置加密位（0x0004）但无 SALT：高概率伪加密，可运行 fixRarPseudoEncryption 清位验证`);
    } else if (encrypted) {
      note(`文件 "${name}" 置加密位且带 SALT：真加密形态，清位无用（需密码）`);
    }
    if (head.flags & FH_COMMENT_LEGACY) {
      note(`文件 "${name}" 置 RAR<2.0 遗留注释位（0x0008，RAR3 恒不置位）：疑似手工置位痕迹`);
    }
    if (head.flags & (FH_SPLIT_BEFORE | FH_SPLIT_AFTER)) {
      note(`文件 "${name}" 置分卷位（跨卷数据，本卷可能不完整）`);
    }
    if (method < 0x30 || method > 0x35) {
      note(`文件 "${name}" METHOD=0x${method.toString(16)} 越界（合法 0x30 存储-0x35 最佳）`);
    }
    entries.push({ name, offset: head.offset, packedSize: head.addedSize, method, encrypted, isDirectory });
  }
  if (!sawEndarc) note('未遇到 ENDARC 归档结束头：文件被截断或手工拼接');
  return { version: bytes[6] === 0x00 ? 'rar4' : null, entries, anomalies };
};

// —— 签名修复（SimpleRAR 型）——

const signatureScore = (bytes: Uint8Array, offset: number): number => {
  let score = 0;
  for (let index = 0; index < 7; index += 1) {
    if (bytes[offset + index] === RAR4_SIGNATURE[index]) score += 1;
  }
  return score;
};

// 候选 marker 之后紧跟的块结构是否像 RAR4 头（类型已知 + 尺寸合法且在文件内）。
const looksLikeKnownHeadAt = (bytes: Uint8Array, offset: number): boolean => {
  if (offset < 0 || offset + 7 > bytes.length) return false;
  if (!KNOWN_HEAD_TYPES.has(bytes[offset + 2])) return false;
  const size = u16le(bytes, offset + 5);
  return size >= 7 && offset + size <= bytes.length;
};

// 签名修复策略：完好直接返回 null；否则在前 512 字节窗口内找"最像 marker"的候选——
// 接受条件 = 字节命中 ≥6（结构不可验证的短文件也敢修），或 命中 ≥3 且 marker SIZE 字段为 7
// 且（类型字节 0x72 完好 或 紧随块结构可识别）。取分最高者（同分取最小偏移），
// 重写标准 7 字节并丢弃其前的前缀（SFX 模块/附加数据，原件未动）。
export const fixRarSignature = (bytes: Uint8Array): { fixed: Uint8Array | null; changes: string[] } => {
  if (bytes.length < 7) return { fixed: null, changes: [] };
  if (matchesRarPrefix(bytes, 0) && bytes[6] === 0x00) return { fixed: null, changes: [] };
  let bestOffset = -1;
  let bestScore = 0;
  const windowEnd = Math.min(bytes.length - 7, 511);
  for (let candidate = 0; candidate <= windowEnd; candidate += 1) {
    const score = signatureScore(bytes, candidate);
    const acceptable =
      score >= 6 ||
      (score >= 3 &&
        u16le(bytes, candidate + 5) === 7 &&
        (bytes[candidate + 2] === 0x72 || looksLikeKnownHeadAt(bytes, candidate + 7)));
    if (!acceptable) continue;
    if (score > bestScore) {
      bestScore = score;
      bestOffset = candidate;
    }
  }
  if (bestOffset < 0) return { fixed: null, changes: [] };
  const before = Array.from(bytes.subarray(bestOffset, bestOffset + 7))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join(' ');
  const fixed = bytes.slice(bestOffset);
  for (let index = 0; index < 7; index += 1) fixed[index] = RAR4_SIGNATURE[index];
  const changes = [`偏移 ${bestOffset}：签名 ${before} → 52 61 72 21 1a 07 00（重写 RAR4 marker 7 字节）`];
  if (bestOffset > 0) {
    changes.push(`丢弃偏移 0-${bestOffset - 1} 的 ${bestOffset} 字节前缀（SFX 模块/附加数据；仅丢弃修复副本，原件未动）`);
  }
  return { fixed, changes };
};

// —— 伪加密修复（进制反转型）——

// 逐文件头清加密位：0x0004（真实加密位）与 0x0008（题面 bit3 口径的遗留注释位）都清，
// 卷位（0x0001/0x0002）/SOLID/SALT/UNICODE/EXT 时间位一律不动；签名必须完好（否则头遍历无意义，
// 先跑 fixRarSignature）。未命中任何加密位时返回 fixed=null（不是伪加密形态）。
export const fixRarPseudoEncryption = (bytes: Uint8Array): { fixed: Uint8Array | null; changes: string[] } => {
  if (bytes.length < 7 || !matchesRarPrefix(bytes, 0) || bytes[6] !== 0x00) {
    throw new Error('缺少完好的 RAR4 签名：先运行 fixRarSignature 修复签名再清加密位');
  }
  const sink: string[] = [];
  const heads = walkHeads(bytes, message => sink.push(message));
  const changes: string[] = [];
  const fixed = bytes.slice();
  const clearMask = FH_ENCRYPTED | FH_COMMENT_LEGACY;
  for (const head of heads) {
    if (head.type !== FILE_HEAD) continue;
    if ((head.flags & clearMask) === 0) continue;
    const newFlags = head.flags & ~clearMask;
    fixed[head.offset + 3] = newFlags & 0xff;
    fixed[head.offset + 4] = (newFlags >> 8) & 0xff;
    const clearedBits: string[] = [];
    if (head.flags & FH_ENCRYPTED) clearedBits.push('0x0004 加密位');
    if (head.flags & FH_COMMENT_LEGACY) clearedBits.push('0x0008 遗留注释位（题面 bit3 口径）');
    const name = readEntryName(bytes, head.offset, head.flags, head.size);
    changes.push(`偏移 ${head.offset}（文件 "${name || ''}"）：HEAD_FLAGS 0x${head.flags.toString(16)} → 0x${newFlags.toString(16)}，清除 ${clearedBits.join(' 与 ')}；卷位/SALT/其余位不动`);
  }
  return changes.length > 0 ? { fixed, changes } : { fixed: null, changes: [] };
};
