// RAR3（RAR4 容器）密码爆破引擎（离线 CTF 工具箱：对标随波逐流"rar密码字典爆破"）：
// detectRarEncryptedEntries 在 rarInspect 的遍历结果上补齐加密要素（salt/数据区偏移/
// CRC/UNP_SIZE），bruteRarPassword 走"内置字典 → 数字掩码"两段候选（复用 zipBrute 的
// dictionaryCandidates/maskCandidates，不重复造生成器），逐口令两段验证：
// ① rarCrypt.checkRar3Password 快筛（存储条目 CRC 终验零误报；压缩条目首块结构早筛，
//   误报率约千分之一）；② 压缩条目结构早筛命中后升级终验——克隆档案清加密位、回填解密流，
//   直接调 rarExtract.extractRarEntry 走真实 RAR3 LZ 解压 + FILE_CRC 校验（零误报，并
//   顺带回传解压内容；解压抛错或返回 unsupported 的流形态——错误口令的垃圾流与真 PPM/VM
//   档案——一律否决，真 PPM 加密档案因此不在爆破支持范围）。
// 口径说明：RAR3 派生是 0x40000 轮 SHA-1 链（每口令约 15-40ms，比 ZipCrypto 慢 4-5 个
// 数级），故让步粒度 YIELD_EVERY=8（zipBrute 为 512——它每口令微秒级），缺省时间预算
// 60s（内置字典 165 条自身约需 5-10s）。纯本地执行，不联网/不 eval/零新依赖。
// 红线：输入 ≤20MB（入口函数超限抛错）；只读输入；命中返回 { password, tried, content }，
// 耗尽/超预算返回 null（进度经 onProgress 回调流出）。

import { inspectRar, type RarEntry } from './rarInspect';
import { extractRarEntry } from './rarExtract';
import { checkRar3Password, decryptRar3Stream } from './rarCrypt';
import { dictionaryCandidates, maskCandidates } from './zipBrute';

// 文件解析限量：超过 20MB 的输入直接抛错（与全站文件工具同口径）
export const RAR_BRUTE_MAX_INPUT = 20 * 1024 * 1024;

// 每口令一次 0x40000 轮 SHA-1 派生（~15-40ms）：每 8 个口令让出主线程并回报进度
const YIELD_EVERY = 8;
const DEFAULT_TIME_BUDGET_MS = 60000;
const DEFAULT_MASK_CHARSET = '0123456789';
const DEFAULT_MASK_MIN_LENGTH = 1;
const DEFAULT_MASK_MAX_LENGTH = 6;

// RAR3 文件头布局常量（对齐 rarInspect 注释：HEAD_FLAGS@3/HEAD_SIZE@5/PACK_SIZE@7/
// UNP_SIZE@11/FILE_CRC@16/UNP_VER@24/METHOD@25/NAME_SIZE@26；LARGE 0x100 时
// HIGH_PACK@32/HIGH_UNP@36，名区顺延 8 字节；SALT 0x400 时名区后随 8 字节盐）
const FH_ENCRYPTED = 0x0004;
const FH_LARGE = 0x0100;
const FH_SALT = 0x0400;

const u16le = (bytes: Uint8Array, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);

const u32le = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

// 加密条目（rarInspect 的 RarEntry + 加密要素；checkRar3Password 的 Rar3QuickCheck
// 结构性满足——salt/dataOffset/packedSize/unpSize/method/fileCrc 全携带）
export interface RarEncryptedEntry extends RarEntry {
  salt: Uint8Array; // 8 字节盐（文件头名区之后）
  headSize: number; // 文件头长（数据区 = offset + headSize 起）
  dataOffset: number; // 加密数据区起始偏移
  unpSize: number; // 原始大小（含 LARGE 高 32 位合成）
  fileCrc: number; // 解压后内容 CRC32
  unpVer: number; // 压缩流版本（29 = RAR3；接线解压时 rarExtract 需要）
}

// 加密条目探测：复用 inspectRar 的头遍历（不重写解析器），对置加密位（0x0004）的条目
// 补读 salt/数据区/CRC。无加密条目、RAR5、加密无盐（伪加密形态）均抛中文错误说明去向。
export const detectRarEncryptedEntries = (bytes: Uint8Array): RarEncryptedEntry[] => {
  if (bytes.length > RAR_BRUTE_MAX_INPUT) {
    throw new Error(`输入 ${bytes.length} 字节超过 ${RAR_BRUTE_MAX_INPUT}（20MB）上限：RAR3 派生为 CPU 密集运算，请先截取目标条目所在片段`);
  }
  const result = inspectRar(bytes);
  if (result.version !== 'rar4') {
    throw new Error('不是 RAR4（RAR3 格式）档案：RAR5 加密（PBKDF2-HMAC-SHA256 + AES-256）本引擎不支持');
  }
  const entries: RarEncryptedEntry[] = [];
  for (const entry of result.entries) {
    if (!entry.encrypted) continue;
    const flags = u16le(bytes, entry.offset + 3);
    const headSize = u16le(bytes, entry.offset + 5);
    if ((flags & FH_SALT) === 0) {
      throw new Error(
        `文件 "${entry.name}" 置加密位（0x0004）但无 SALT：高概率伪加密，先用 fixRarPseudoEncryption 清位验证（真 RAR3 加密恒带 8 字节盐）`,
      );
    }
    const nameSize = u16le(bytes, entry.offset + 26);
    const saltOffset = entry.offset + 32 + (flags & FH_LARGE ? 8 : 0) + nameSize;
    if (saltOffset + 8 > entry.offset + headSize || entry.offset + headSize > bytes.length) {
      throw new Error(`文件 "${entry.name}" 的 salt 越出文件头边界（头损坏或截断）：无法爆破`);
    }
    const unpSize = u32le(bytes, entry.offset + 11) + (flags & FH_LARGE ? u32le(bytes, entry.offset + 36) * 0x100000000 : 0);
    const dataOffset = entry.offset + headSize;
    if (dataOffset + entry.packedSize > bytes.length) {
      throw new Error(
        `文件 "${entry.name}" 加密数据区越界：声明 ${entry.packedSize} 字节起于 ${dataOffset}，实际仅剩 ${bytes.length - dataOffset} 字节（文件截断）`,
      );
    }
    entries.push({
      ...entry,
      salt: bytes.slice(saltOffset, saltOffset + 8),
      headSize,
      dataOffset,
      unpSize,
      fileCrc: u32le(bytes, entry.offset + 16),
      unpVer: bytes[entry.offset + 24],
    });
  }
  if (entries.length === 0) {
    throw new Error('未发现 RAR3 加密条目（置加密位 0x0004 的文件头）：无需爆破；伪加密题请用 fixRarPseudoEncryption');
  }
  return entries;
};

// 已知口令解密条目数据区：返回明文 packed 流（块对齐长，尾块零填充保留），
// 接 rarExtract 解压（存储条目取前 unpSize 字节；压缩条目解压至流结束标志自然停）。
export const decryptRarEncryptedEntry = (bytes: Uint8Array, entry: RarEncryptedEntry, password: string): Uint8Array | null => {
  if (bytes.length > RAR_BRUTE_MAX_INPUT) {
    throw new Error(`输入 ${bytes.length} 字节超过 ${RAR_BRUTE_MAX_INPUT}（20MB）上限`);
  }
  return decryptRar3Stream(bytes.subarray(entry.dataOffset, entry.dataOffset + entry.packedSize), password, entry.salt);
};

export interface RarBruteProgress {
  tried: number;
  total: number; // 候选总数（掩码空间大时为 Infinity）
  stage: 'dictionary' | 'mask' | 'custom'; // 两段式：内置字典跑完转数字掩码
  password: string | null;
}

export interface RarBruteOptions {
  entry?: RarEncryptedEntry; // 缺省取探测到的第一个加密条目
  candidates?: Iterable<string>; // 自定义候选（用户字典等）；缺省 = 内置字典 + 数字掩码
  charset?: string; // 掩码字符集，缺省 '0123456789'
  minLength?: number; // 掩码最小长度，缺省 1
  maxLength?: number; // 掩码最大长度，缺省 6
  timeBudgetMs?: number; // 时间预算，缺省 60000（RAR3 派生每口令 ~15-40ms）
  onProgress?: (progress: RarBruteProgress) => void;
}

export interface RarBruteHit {
  password: string;
  tried: number;
  // 命中条目的明文内容（存储条目 = 内容本身；压缩条目 = rarExtract 解压并过 CRC 的产物）
  content: Uint8Array | null;
}

// 两段式默认候选：先 zipBrute 内置 165 条 CTF 高频弱口令表，再数字掩码逐长度枚举
// （maskCandidates 惰性生成器，95^n 空间不落内存）。
function* defaultRarCandidates(
  charset: string,
  minLength: number,
  maxLength: number,
): Generator<string, void, unknown> {
  const dictionary = dictionaryCandidates();
  for (const password of dictionary) yield password;
  yield* maskCandidates(charset, minLength, maxLength);
}

// node:vm 跨 realm 迭代口径（与 zipBrute.iterateCandidates 同语义）：Array.isArray 跨
// realm 可靠（宿主/沙箱数组都走下标迭代），其余对象取其 realm 的 Symbol.iterator。
const iterateCandidates = (candidates: Iterable<string>): Iterator<string> => {
  if (Array.isArray(candidates)) {
    const array = candidates as string[];
    let index = 0;
    const iterator: Iterator<string> = {
      next: () => {
        if (index < array.length) {
          const value = array[index];
          index += 1;
          return { done: false, value };
        }
        return { done: true, value: undefined };
      },
    };
    return iterator;
  }
  const factory = (candidates as { [Symbol.iterator]?: () => Iterator<string> })[Symbol.iterator];
  if (typeof factory !== 'function') {
    throw new Error('candidates 必须是字符串数组或可迭代对象（数组/本模块生成器）');
  }
  return factory.call(candidates);
};

const candidateTotal = (candidates: Iterable<string>, stage: RarBruteProgress['stage'], charsetSize: number, minLength: number, maxLength: number): number => {
  if (Array.isArray(candidates)) return (candidates as string[]).length;
  if (stage === 'custom') return Number.POSITIVE_INFINITY;
  // 两段式：字典 165 + Σ charset^len（超出 2^53 视作无穷）
  let total = dictionaryCandidates().length;
  for (let length = minLength; length <= maxLength; length += 1) {
    total += charsetSize ** length;
    if (!Number.isFinite(total)) return Number.POSITIVE_INFINITY;
  }
  return total;
};

const yieldToMainThread = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

// 压缩条目终验：结构早筛命中后升级为确定结论。克隆档案（绝不改入参）清加密位、回填
// 解密流，按偏移找回条目后走 rarExtract 真实 RAR3 LZ 解压 + FILE_CRC 终验：
// 解压抛错（流损坏/CRC 不符）或返回 unsupported（PPM/VM/旧版流——错误口令的垃圾流
// 大量呈现为这类形态）→ 早筛误报，否决并继续；正常解出内容 → 确定命中并回传内容。
// 边界：rarExtract 不解压的流（真 PPM/VM 加密档案）任何口令都无法终验 → 全部否决返回
// null；解压预算超限（>64MB 炸弹防护）或 solid 跨文件引用对任何口令一致抛错，同返回
// null——20MB 输入上限下属可接受边界。
const verifyCompressedHit = (
  bytes: Uint8Array,
  entry: RarEncryptedEntry,
  password: string,
): { hit: boolean; content: Uint8Array | null } => {
  let plain: Uint8Array | null;
  try {
    plain = decryptRar3Stream(bytes.subarray(entry.dataOffset, entry.dataOffset + entry.packedSize), password, entry.salt);
  } catch {
    return { hit: false, content: null };
  }
  if (plain === null) return { hit: false, content: null };
  const clone = bytes.slice();
  const flags = u16le(clone, entry.offset + 3);
  const cleared = flags & ~FH_ENCRYPTED;
  clone[entry.offset + 3] = cleared & 0xff;
  clone[entry.offset + 4] = (cleared >> 8) & 0xff;
  clone.set(plain, entry.dataOffset);
  try {
    const reinspect = inspectRar(clone);
    const cloneEntry = reinspect.entries.find((item) => item.offset === entry.offset);
    if (cloneEntry === undefined) return { hit: false, content: null };
    const result = extractRarEntry(clone, cloneEntry);
    return result.bytes !== null ? { hit: true, content: result.bytes } : { hit: false, content: null };
  } catch {
    return { hit: false, content: null };
  }
};

// RAR3 密码爆破：字典 + 数字掩码，分批让步防卡 UI；命中返回 { password, tried }，
// 候选耗尽或超时间预算返回 null。每批（8 个口令）经 onProgress 回报进度。
export const bruteRarPassword = async (
  bytes: Uint8Array,
  options?: RarBruteOptions,
): Promise<RarBruteHit | null> => {
  if (bytes.length > RAR_BRUTE_MAX_INPUT) {
    throw new Error(`输入 ${bytes.length} 字节超过 ${RAR_BRUTE_MAX_INPUT}（20MB）上限：RAR3 派生为 CPU 密集运算，请先截取目标条目所在片段`);
  }
  const budget = options?.timeBudgetMs ?? DEFAULT_TIME_BUDGET_MS;
  if (!Number.isFinite(budget) || budget < 0) {
    throw new Error(`timeBudgetMs 必须为非负有限数字，当前 ${String(options?.timeBudgetMs)}`);
  }
  const charset = options?.charset ?? DEFAULT_MASK_CHARSET;
  const minLength = options?.minLength ?? DEFAULT_MASK_MIN_LENGTH;
  const maxLength = options?.maxLength ?? DEFAULT_MASK_MAX_LENGTH;
  const stage: RarBruteProgress['stage'] = options?.candidates !== undefined ? 'custom' : 'dictionary';
  let candidates: Iterable<string>;
  if (options?.candidates !== undefined) {
    candidates = options.candidates;
  } else {
    candidates = defaultRarCandidates(charset, minLength, maxLength);
  }
  const entry = options?.entry ?? detectRarEncryptedEntries(bytes)[0];
  const dictionarySize = options?.candidates !== undefined ? 0 : dictionaryCandidates().length;
  const total = candidateTotal(candidates, stage, new Set(Array.from(charset)).size, minLength, maxLength);
  const onProgress = options?.onProgress;
  const iterator = iterateCandidates(candidates);
  const deadline = Date.now() + budget;
  let tried = 0;
  // 阶段判定：自定义候选恒 'custom'；两段式按字典长度（165）划界，其后为掩码段
  const stageNow = (): RarBruteProgress['stage'] => {
    if (stage === 'custom') return 'custom';
    return tried <= dictionarySize ? 'dictionary' : 'mask';
  };
  for (;;) {
    const next = iterator.next();
    if (next.done === true) break;
    const candidate = next.value;
    tried += 1;
    if (checkRar3Password(bytes, entry, candidate)) {
      // 存储条目快筛即 CRC 终验（零误报），直接解密取内容；
      // 压缩条目快筛是概率性早筛，须 rarExtract 解压 CRC 终验否决误报后才算命中
      if (entry.method === 0x30) {
        const plain = decryptRar3Stream(bytes.subarray(entry.dataOffset, entry.dataOffset + entry.packedSize), candidate, entry.salt);
        if (plain !== null && plain.length >= entry.unpSize) {
          onProgress?.({ tried, total, stage: stageNow(), password: candidate });
          return { password: candidate, tried, content: plain.subarray(0, entry.unpSize) };
        }
      } else {
        const verdict = verifyCompressedHit(bytes, entry, candidate);
        if (verdict.hit) {
          onProgress?.({ tried, total, stage: stageNow(), password: candidate });
          return { password: candidate, tried, content: verdict.content };
        }
      }
    }
    if (Date.now() >= deadline) break;
    if (tried % YIELD_EVERY === 0) {
      onProgress?.({ tried, total, stage: stageNow(), password: null });
      await yieldToMainThread();
      if (Date.now() >= deadline) break;
    }
  }
  onProgress?.({ tried, total, stage, password: null });
  return null;
};
