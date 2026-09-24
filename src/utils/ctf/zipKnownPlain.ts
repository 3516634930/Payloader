// ZipCrypto 已知明文攻击（Biham-Kocher，bkcrack 同构移植，纯 JS 零依赖单线程）。
// 约束：本模块只恢复"加密该条目"的三把内部 keys（key0/key1/key2 于 12+offset 处的状态），
// 不恢复口令；跨条目 keys 不可复用（各条目独立用口令重新 init，除非单文件 zip）。
// 算法阶段：①z[10,32) 候选枚举（末位 keystream 反查 2^22 空间）→ ②逐字节回推缩减
// → ③z[2,32) 根扩展（升序）→ ④8 字节窗口递归（z 链 + y/x 链重建，与 bkcrack Attack.cpp 逐语句对应）
// → ⑤窗口前后已知明文与可选 header[10]/[11] 校验字节终验。
// 性能约束（node 单线程实测）：缩减阶段约 1-2s；攻击耗时 ≈ 真根在升序根表中的位次 × 单根成本（毫秒级）。
// 已知明文每多 1 字节根表约 ×0.93 收缩（12 字节→~140 万根，88 字节→~10 万根，16K 字节→数千根）；
// 8-11 字节走启发式路径（秒级、多解取结构最优、不保证唯一），≥12 字节（含校验字节折算）走精确路径。
// 默认预算 20s 内未及真根则预算截断返回 null，可加大 timeBudgetMs 重试。
// 本函数同步阻塞至预算耗尽，浏览器侧请在 Worker 中调用。
import { crc32Table } from '../codec/alphabets';

export interface KnownPlainResult {
  keys: [number, number, number] | null;
  plaintext: Uint8Array | null;
  tried: number;
  elapsedMs: number;
}

export interface KnownPlainOptions {
  offset?: number;
  timeBudgetMs?: number;
  onProgress?: (tried: number) => void;
  // header[10]/header[11] 明文（来自中央目录 CRC32 高 16 位；flag bit3 置位时 byte11 为 DOS 时间高字节）
  // 仅用于终验增强：提供后等效已知明文 +1/+2 字节，K+校验字节 ≥12 时走精确模式
  checkByte10?: number;
  checkByte11?: number;
}

const ZIPCRYPTO_HEADER_SIZE = 12;
const CONTIGUOUS_SIZE = 8;
const ATTACK_SIZE = 12;
const DEFAULT_TIME_BUDGET_MS = 20000;
const HEURISTIC_SOLUTION_CAP = 24;
const MASK24 = 0xff000000;
const MAXDIFF24 = 0xffffff + 0xff;
const MAXDIFF26 = 0x3ffffff + 0xff;
const MULT = 0x08088405;
const MULTINV = 0xd94fa8cd; // MULT * MULTINV ≡ 1 (mod 2^32)

interface AttackTables {
  crcTab: Uint32Array;
  crcInvTab: Uint32Array;
  ksExists: Uint8Array;
  ksOff: Uint32Array;
  ksItem: Uint16Array;
  ksByte: Uint8Array;
  fiber2Off: Uint32Array;
  fiber2Item: Uint8Array;
  pb: Uint32Array;
  pb2: Uint32Array;
  sortM: Uint32Array;
  sortT: Uint32Array;
  m8: Uint32Array;
  mul8: Uint32Array;
}

let tables: AttackTables | null = null;

const buildTables = (): AttackTables => {
  const crcTab = new Uint32Array(256);
  const crcInvTab = new Uint32Array(256);
  for (let b = 0; b < 256; b += 1) {
    const crc = crc32Table[b] >>> 0;
    crcTab[b] = crc;
    crcInvTab[(crc >>> 24) & 0xff] = ((crc << 8) ^ b) >>> 0;
  }
  // keystream 反查表：(流字节, z[10,16)) → z[2,16) 候选（z 低 2 位不影响流字节）
  const ksExists = new Uint8Array(256 * 64);
  const ksOff = new Uint32Array(256 * 64 + 1);
  const ksItem = new Uint16Array(1 << 14);
  const ksByte = new Uint8Array(1 << 14);
  {
    const counts = new Uint32Array(256 * 64);
    for (let z = 0; z < 1 << 16; z += 4) {
      const temp = z | 2;
      const k = ((temp * (temp ^ 1)) >>> 8) & 0xff;
      counts[(k << 6) | (z >> 10)] += 1;
      ksExists[(k << 6) | (z >> 10)] = 1;
      ksByte[z >> 2] = k;
    }
    let acc = 0;
    for (let i = 0; i < 256 * 64; i += 1) {
      ksOff[i] = acc;
      acc += counts[i];
    }
    ksOff[256 * 64] = acc;
    const cursor = ksOff.slice(0, 256 * 64);
    for (let z = 0; z < 1 << 16; z += 4) {
      const temp = z | 2;
      const k = ((temp * (temp ^ 1)) >>> 8) & 0xff;
      ksItem[cursor[(k << 6) | (z >> 10)]++] = z;
    }
  }
  // fiber2：msb(x·MULTINV) ∈ {idx, idx-1} 的字节 x（y 回推的首层候选预筛）
  const fiber2Off = new Uint32Array(257);
  const fiber2Item = new Uint8Array(512);
  const pb = new Uint32Array(256);
  {
    const counts = new Uint32Array(256);
    for (let x = 0; x < 256; x += 1) {
      const p = Math.imul(x, MULTINV) >>> 0;
      pb[x] = p;
      const m = (p >>> 24) & 0xff;
      counts[m] += 1;
      counts[(m + 1) & 0xff] += 1;
    }
    let acc = 0;
    for (let i = 0; i < 256; i += 1) {
      fiber2Off[i] = acc;
      acc += counts[i];
    }
    fiber2Off[256] = acc;
    const cursor = fiber2Off.slice(0, 256);
    for (let x = 0; x < 256; x += 1) {
      const p = Math.imul(x, MULTINV) >>> 0;
      const m = (p >>> 24) & 0xff;
      fiber2Item[cursor[m]++] = x;
      fiber2Item[cursor[(m + 1) & 0xff]++] = x;
    }
  }
  // 可达 m 表：m(t) = t·MULTINV mod 2^24（t ∈ [0,2^16)），按 m 排序用于叶窗口二分；
  // m8/mul8 预计算 fy/ffy 的线性分量（乘法对 2^32 分配律），叶热路径免 imul
  const sortM = new Uint32Array(1 << 16);
  const sortT = new Uint32Array(1 << 16);
  const m8 = new Uint32Array(1 << 16);
  const mul8 = new Uint32Array(1 << 16);
  {
    const pairs: Array<[number, number]> = [];
    for (let t = 0; t < 1 << 16; t += 1) pairs.push([Math.imul(t, MULTINV) & 0xffffff, t]);
    pairs.sort((a, b) => a[0] - b[0]);
    for (let i = 0; i < 1 << 16; i += 1) {
      const m = pairs[i][0];
      sortM[i] = m;
      sortT[i] = pairs[i][1];
      m8[i] = (m << 8) >>> 0;
      mul8[i] = (Math.imul(m, MULTINV) << 8) >>> 0;
    }
  }
  // PB[b] 的二次乘积表：ffy = imul(prod0-1, MULTINV) + mul8[i] + pb2[b]（mod 2^32）
  const pb2 = new Uint32Array(256);
  for (let b = 0; b < 256; b += 1) pb2[b] = Math.imul(pb[b], MULTINV) >>> 0;
  return { crcTab, crcInvTab, ksExists, ksOff, ksItem, ksByte, fiber2Off, fiber2Item, pb, pb2, sortM, sortT, m8, mul8 };
};

// ---- 攻击上下文（同步执行，onProgress 内禁止重入）----
let inAttack = false;
let T: AttackTables;
let ctxCipher: Uint8Array;
let ctxPlain: Uint8Array;
let ctxKeys: Uint8Array;
let ctxKnown: number;
let ctxWStart: number;
let ctxDeadline: number;
let ctxTried: number;
let ctxEarlyExit: boolean;
let ctxSolCap: number;
let ctxCheck10: number;
let ctxCheck11: number;
let ctxExactMode: boolean;
const ctxSolutions: Array<[number, number, number]> = [];
const zlist = new Uint32Array(8);
const ylist = new Uint32Array(8);
const xlist = new Uint32Array(8);

const crc32Step = (pval: number, b: number): number => ((pval >>> 8) ^ T.crcTab[(pval & 0xff) ^ b]) >>> 0;
const crc32Inv = (crc: number, b: number): number =>
  (((crc << 8) >>> 0) ^ T.crcInvTab[(crc >>> 24) & 0xff] ^ b) >>> 0;
const keystreamOf = (z: number): number => T.ksByte[(z & 0xffff) >> 2];

interface CipherState {
  x: number;
  y: number;
  z: number;
}

const updateForward = (st: CipherState, p: number): void => {
  st.x = crc32Step(st.x, p);
  st.y = (Math.imul(st.y + (st.x & 0xff), MULT) + 1) >>> 0;
  st.z = crc32Step(st.z, (st.y >>> 24) & 0xff);
};

const updateBackward = (st: CipherState, c: number): void => {
  st.z = crc32Inv(st.z, (st.y >>> 24) & 0xff);
  st.y = (Math.imul((st.y - 1) >>> 0, MULTINV) - (st.x & 0xff)) >>> 0;
  st.x = crc32Inv(st.x, (c ^ keystreamOf(st.z)) & 0xff);
};

const checkDeadline = (): boolean => {
  if (Date.now() >= ctxDeadline) {
    ctxEarlyExit = true;
    return false;
  }
  return true;
};

// ---- 递归攻击：z 链回推（与 bkcrack exploreZlists 对应）----
const exploreZlists = (i: number): void => {
  if (i !== 0) {
    const zim1High = crc32Inv(zlist[i], 0) & 0xfffffc00;
    const kb = (ctxKeys[i - 1] << 6) | ((zim1High >>> 10) & 63);
    for (let j = T.ksOff[kb]; j < T.ksOff[kb + 1]; j += 1) {
      zlist[i - 1] = zim1High | T.ksItem[j];
      zlist[i] &= 0xfffffffc;
      zlist[i] |= (crc32Inv(zlist[i], 0) ^ zlist[i - 1]) >>> 8 & 3;
      if (i < 7) ylist[i + 1] = ((crc32Inv(zlist[i + 1], 0) ^ zlist[i]) << 24) >>> 0;
      exploreZlists(i - 1);
      if (ctxEarlyExit) return;
    }
  } else {
    enumerateLeaf();
  }
};

// ---- 叶：y7 全枚举的窗口化实现 ----
// bkcrack 逐 t 扫 2^16 次 fiber3；此处改为按 b 求解 (prod + PB[b] - y6mask) ∈ [0, MAXDIFF24]
// 的 m 窗口（m = t·MULTINV mod 2^24，prod = prod0 + m<<8），在有序可达 m 表上二分，
// 结果集合与逐 t 全扫严格一致（含 2^32 回绕拆两段）。
const lowerBoundM = (target: number): number => {
  let lo = 0;
  let hi = 1 << 16;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (T.sortM[mid] < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
};

const enumerateLeaf = (): void => {
  const y7top = ylist[7] & MASK24;
  const y6m = (ylist[6] >>> 24) & 0xff;
  const y6mask = ylist[6] & MASK24;
  const y5mask = ylist[5] & MASK24;
  const y4mask = ylist[4] & MASK24;
  const y5m = (ylist[5] >>> 24) & 0xff;
  const prod0 = (((Math.imul(MULTINV, (ylist[7] >>> 24) & 0xff) >>> 0) << 24) - MULTINV) >>> 0;
  const c0 = Math.imul((prod0 - 1) >>> 0, MULTINV) >>> 0;
  const q = (y6mask - prod0) >>> 0;
  const pb = T.pb;
  for (let b = 0; b < 256; b += 1) {
    const a = (q - pb[b]) >>> 0;
    const mLo = (a + 255) >>> 8;
    const mHi = (a + MAXDIFF24) >>> 8;
    const lo = lowerBoundM(mLo);
    const end = mHi >= mLo ? lowerBoundM(mHi + 1) : 1 << 16;
    for (let i = lo; i < end; i += 1) {
      processSurvivor(i, b, prod0, c0, y7top, y6m, y5mask, y4mask, y5m);
      if (ctxEarlyExit) return;
    }
    if (mHi < mLo) {
      const wrapEnd = lowerBoundM(mHi + 1);
      for (let i = 0; i < wrapEnd; i += 1) {
        processSurvivor(i, b, prod0, c0, y7top, y6m, y5mask, y4mask, y5m);
        if (ctxEarlyExit) return;
      }
    }
  }
};

// 幸存 (t,b)：加法重构 fy/ffy（乘法 mod 2^32 分配律）+ 内联 y 链第 7、6 两层过滤
const processSurvivor = (
  i: number,
  b: number,
  prod0: number,
  c0: number,
  y7top: number,
  y6m: number,
  y5mask: number,
  y4mask: number,
  y5m: number,
): void => {
  const { sortT, m8, mul8, pb, pb2, fiber2Off, fiber2Item } = T;
  const fy = (prod0 + m8[i] + pb[b]) >>> 0;
  const ffy = (c0 + mul8[i] + pb2[b]) >>> 0;
  // 第 7 层：xi = lsb(x7) 候选（fiber2 预筛 + maxdiff 窗口 + msb）
  const idx7 = ((ffy - y5mask) >>> 24) & 0xff;
  for (let j = fiber2Off[idx7]; j < fiber2Off[idx7 + 1]; j += 1) {
    const xi7 = fiber2Item[j];
    if (((ffy - pb[xi7] - y5mask) >>> 0) > MAXDIFF24) continue;
    const y6 = (fy - xi7) >>> 0;
    if (((y6 >>> 24) & 0xff) !== y6m) continue;
    // 第 6 层：xi6 = lsb(x6)
    const fy6 = Math.imul((y6 - 1) >>> 0, MULTINV) >>> 0;
    const ffy6 = Math.imul((fy6 - 1) >>> 0, MULTINV) >>> 0;
    const idx6 = ((ffy6 - y4mask) >>> 24) & 0xff;
    for (let j6 = fiber2Off[idx6]; j6 < fiber2Off[idx6 + 1]; j6 += 1) {
      const xi6 = fiber2Item[j6];
      if (((ffy6 - pb[xi6] - y4mask) >>> 0) > MAXDIFF24) continue;
      const y5 = (fy6 - xi6) >>> 0;
      if (((y5 >>> 24) & 0xff) !== y5m) continue;
      ylist[7] = (b | (sortT[i] << 8) | y7top) >>> 0;
      ylist[6] = y6;
      xlist[7] = xi7;
      ylist[5] = y5;
      xlist[6] = xi6;
      exploreYlists(5);
      if (ctxEarlyExit) return;
    }
  }
};

// ---- y 链回推（与 bkcrack exploreYlists 对应）----
const exploreYlists = (i: number): void => {
  if (i !== 3) {
    const fy = Math.imul((ylist[i] - 1) >>> 0, MULTINV) >>> 0;
    const ffy = Math.imul((fy - 1) >>> 0, MULTINV) >>> 0;
    const prevMask = ylist[i - 2] & MASK24;
    const idx2 = ((ffy - prevMask) >>> 24) & 0xff;
    for (let j = T.fiber2Off[idx2]; j < T.fiber2Off[idx2 + 1]; j += 1) {
      const xi = T.fiber2Item[j];
      const yim1 = (fy - xi) >>> 0;
      if (
        ((ffy - T.pb[xi] - prevMask) >>> 0) <= MAXDIFF24 &&
        ((yim1 >>> 24) & 0xff) === ((ylist[i - 1] >>> 24) & 0xff)
      ) {
        ylist[i - 1] = yim1;
        xlist[i] = xi;
        exploreYlists(i - 1);
      }
      if (ctxEarlyExit) return;
    }
  } else {
    testXlist();
  }
};

// ---- x 链重建 + 全部已知约束终验 ----
const testXlist = (): void => {
  // x 误差按字节右移自愈：从 lsb(x4) 前推两步后 x7 精确（低 8 位由 y 链给出）
  for (let i = 5; i <= 7; i += 1) {
    xlist[i] = ((crc32Step(xlist[i - 1], ctxPlain[i - 1]) & 0xffffff00) | (xlist[i] & 0xff)) >>> 0;
  }
  let x = xlist[7];
  for (let i = 6; i >= 3; i -= 1) x = crc32Inv(x, ctxPlain[i]);
  const y1Top = (((crc32Inv(zlist[1], 0) ^ zlist[0]) << 24) >>> 0) & 0xfc000000;
  const lhs = (Math.imul((ylist[3] - 1) >>> 0, MULTINV) >>> 0) - (x & 0xff) - 1;
  if ((((Math.imul(lhs, MULTINV) >>> 0) - y1Top) >>> 0) > MAXDIFF26) return;

  // 前向终验：窗口（首 8 字节）之后的全部已知明文
  const forward: CipherState = { x: xlist[7], y: ylist[7], z: zlist[7] };
  updateForward(forward, ctxPlain[7]);
  for (let i = 8; i < ctxKnown; i += 1) {
    if ((ctxCipher[ctxWStart + i] ^ keystreamOf(forward.z)) !== ctxPlain[i]) return;
    updateForward(forward, ctxPlain[i]);
  }
  // 反向终验：窗口前 3 字节 + 可选 header[10]/[11] 校验字节
  const backward: CipherState = { x, y: ylist[3], z: zlist[3] };
  for (let i = 2; i >= 0; i -= 1) {
    updateBackward(backward, ctxCipher[ctxWStart + i]);
    if ((ctxCipher[ctxWStart + i] ^ keystreamOf(backward.z)) !== ctxPlain[i]) return;
  }
  // 此处 backward 即窗口起点（12+offset）状态；校验字节的回推用副本，避免污染返回位置
  const windowStart: CipherState = { x: backward.x, y: backward.y, z: backward.z };
  if (ctxCheck11 >= 0 || ctxCheck10 >= 0) {
    const floor = ctxCheck10 >= 0 ? ZIPCRYPTO_HEADER_SIZE - 2 : ZIPCRYPTO_HEADER_SIZE - 1;
    for (let abs = ctxWStart - 1; abs >= floor; abs -= 1) {
      updateBackward(backward, ctxCipher[abs]);
      if (abs === ZIPCRYPTO_HEADER_SIZE - 1 && ctxCheck11 >= 0) {
        if ((ctxCipher[abs] ^ keystreamOf(backward.z)) !== ctxCheck11) return;
      }
      if (abs === ZIPCRYPTO_HEADER_SIZE - 2 && ctxCheck10 >= 0) {
        if ((ctxCipher[abs] ^ keystreamOf(backward.z)) !== ctxCheck10) return;
      }
    }
  }
  ctxSolutions.push([windowStart.x >>> 0, windowStart.y >>> 0, windowStart.z >>> 0]);
  if (ctxExactMode || ctxSolutions.length >= ctxSolCap) ctxEarlyExit = true;
};

// 从窗口起点 keys 解密整段数据（前向 + 自包含反向覆盖 offset 之前字节）
const decryptFromWindow = (windowKeys: [number, number, number]): Uint8Array => {
  const dataLength = ctxCipher.length - ZIPCRYPTO_HEADER_SIZE;
  const data = new Uint8Array(dataLength);
  const st: CipherState = { x: windowKeys[0], y: windowKeys[1], z: windowKeys[2] };
  const dataOffset = ctxWStart - ZIPCRYPTO_HEADER_SIZE;
  for (let i = dataOffset - 1; i >= 0; i -= 1) {
    updateBackward(st, ctxCipher[ZIPCRYPTO_HEADER_SIZE + i]);
    data[i] = ctxCipher[ZIPCRYPTO_HEADER_SIZE + i] ^ keystreamOf(st.z);
  }
  const st2: CipherState = { x: windowKeys[0], y: windowKeys[1], z: windowKeys[2] };
  for (let i = dataOffset; i < dataLength; i += 1) {
    data[i] = ctxCipher[ZIPCRYPTO_HEADER_SIZE + i] ^ keystreamOf(st2.z);
    updateForward(st2, data[i]);
  }
  return data;
};

// 启发式模式评分：已知明文之外的解密字节中可打印 ASCII 与 0x00 占比（真实文件的结构信号）
const scoreDecryption = (data: Uint8Array, knownStart: number, knownLength: number): number => {
  let structural = 0;
  let total = 0;
  for (let i = 0; i < data.length; i += 1) {
    if (i >= knownStart && i < knownStart + knownLength) continue;
    const byte = data[i];
    if (byte === 0) structural += 3;
    else if (byte === 9 || byte === 10 || byte === 13 || (byte >= 0x20 && byte <= 0x7e)) structural += 1;
    total += 1;
  }
  return total === 0 ? 0 : structural / total;
};

export const knownPlainTextAttack = (
  cipher: Uint8Array,
  knownPlain: Uint8Array,
  options?: KnownPlainOptions,
): KnownPlainResult => {
  if (inAttack) throw new Error('禁止在 onProgress 回调内重入已知明文攻击');
  const startedAt = Date.now();
  const offset = options?.offset ?? 0;
  const budget = options?.timeBudgetMs ?? DEFAULT_TIME_BUDGET_MS;
  if (!Number.isInteger(offset) || offset < 0) throw new Error(`offset 必须为非负整数，当前 ${String(offset)}`);
  if (!Number.isFinite(budget) || budget < 0) {
    throw new Error(`timeBudgetMs 必须为非负有限数字，当前 ${String(options?.timeBudgetMs)}`);
  }
  if (knownPlain.length < CONTIGUOUS_SIZE) {
    throw new Error(`已知明文不足：BK 攻击下限为 ${CONTIGUOUS_SIZE} 字节，当前 ${knownPlain.length} 字节（建议 ≥12 字节、PNG 等结构化文件 ≥24 字节）`);
  }
  if (cipher.length < ZIPCRYPTO_HEADER_SIZE + offset + knownPlain.length) {
    throw new Error('密文长度不足以覆盖加密头 + offset + 已知明文：请确认传入的是完整条目密文段（compressedSize 段，含 12 字节加密头）');
  }
  const check10 = options?.checkByte10 ?? -1;
  const check11 = options?.checkByte11 ?? -1;
  if (check10 !== -1 && (check10 < 0 || check10 > 255)) throw new Error('checkByte10 必须是 0-255 的字节值');
  if (check11 !== -1 && (check11 < 0 || check11 > 255)) throw new Error('checkByte11 必须是 0-255 的字节值');

  T = tables ?? (tables = buildTables());
  ctxCipher = cipher;
  ctxPlain = knownPlain;
  ctxKnown = knownPlain.length;
  ctxWStart = ZIPCRYPTO_HEADER_SIZE + offset;
  ctxDeadline = startedAt + budget;
  ctxTried = 0;
  ctxEarlyExit = false;
  ctxSolCap = HEURISTIC_SOLUTION_CAP;
  ctxCheck10 = check10;
  ctxCheck11 = check11;
  ctxExactMode = ctxKnown + (check10 >= 0 ? 1 : 0) + (check11 >= 0 ? 1 : 0) >= ATTACK_SIZE;
  ctxSolutions.length = 0;
  ctxKeys = new Uint8Array(ctxKnown);
  for (let i = 0; i < ctxKnown; i += 1) ctxKeys[i] = knownPlain[i] ^ cipher[ctxWStart + i];
  const onProgress = options?.onProgress;

  inAttack = true;
  try {
    // 阶段①：z[10,32) 候选（末位 keystream 反查），按保留桶直推枚举保持升序
    let candidates: number[] = [];
    const lastK = ctxKeys[ctxKnown - 1];
    const keptSet = new Uint8Array(64);
    for (let b = 0; b < 64; b += 1) keptSet[b] = T.ksExists[(lastK << 6) | b];
    for (let hi = 0; hi < 1 << 16 && !ctxEarlyExit; hi += 1) {
      const hiPart = hi << 16;
      for (let b = 0; b < 64; b += 1) {
        if (keptSet[b]) {
          candidates.push((hiPart | (b << 10)) >>> 0);
          ctxTried += 1;
        }
      }
      if ((hi & 0x7ff) === 0) {
        if (!checkDeadline()) break;
        onProgress?.(ctxTried);
      }
    }

    // 阶段②：逐字节回推缩减（i 从 K-1 降到 8，产出 index 7 的 z[10,32)）
    // seen 用版本戳去重：大 K 时上万次 pass 免 4MB 清零
    const seen = new Uint32Array(1 << 22);
    for (let i = ctxKnown - 1; i >= CONTIGUOUS_SIZE && !ctxEarlyExit; i -= 1) {
      const next: number[] = [];
      const stamp = i + 2;
      const kc = ctxKeys[i];
      const kprev = ctxKeys[i - 1];
      for (let ci = 0; ci < candidates.length; ci += 1) {
        const zi = candidates[ci];
        const kb = (kc << 6) | ((zi >>> 10) & 63);
        for (let j = T.ksOff[kb]; j < T.ksOff[kb + 1]; j += 1) {
          const zim1 = crc32Inv(zi | T.ksItem[j], 0) & 0xfffffc00;
          const slot = zim1 >>> 10;
          if (seen[slot] !== stamp && T.ksExists[(kprev << 6) | (slot & 63)]) {
            seen[slot] = stamp;
            next.push(zim1);
          }
        }
        ctxTried += 1;
        if ((ci & 0x3fff) === 0) {
          if (!checkDeadline()) break;
          onProgress?.(ctxTried);
        }
      }
      candidates = next;
    }

    // 阶段③：z[2,32) 根扩展（index 7），按值升序排序保证扫描顺序确定
    const roots: number[] = [];
    if (!ctxEarlyExit) {
      for (let ci = 0; ci < candidates.length; ci += 1) {
        const z10 = candidates[ci];
        const kb = (ctxKeys[7] << 6) | ((z10 >>> 10) & 63);
        for (let j = T.ksOff[kb]; j < T.ksOff[kb + 1]; j += 1) roots.push((z10 | T.ksItem[j]) >>> 0);
      }
      roots.sort((a, b) => a - b);
    }

    // 阶段④⑤：根扫描递归攻击
    for (let r = 0; r < roots.length && !ctxEarlyExit; r += 1) {
      zlist[7] = roots[r];
      exploreZlists(7);
      ctxTried += 1;
      if ((r & 0xf) === 0) {
        if (!checkDeadline()) break;
        onProgress?.(ctxTried);
      }
    }

    if (ctxSolutions.length === 0) {
      onProgress?.(ctxTried);
      return { keys: null, plaintext: null, tried: ctxTried, elapsedMs: Date.now() - startedAt };
    }
    if (ctxExactMode) {
      const best = ctxSolutions[0];
      return {
        keys: best,
        plaintext: decryptFromWindow(best),
        tried: ctxTried,
        elapsedMs: Date.now() - startedAt,
      };
    }
    // 启发式模式（8-11 字节）：按解密结构评分取最优，结果不保证唯一
    const dataOffset = ctxWStart - ZIPCRYPTO_HEADER_SIZE;
    let bestKeys = ctxSolutions[0];
    let bestScore = -1;
    for (let s = 0; s < ctxSolutions.length; s += 1) {
      const score = scoreDecryption(decryptFromWindow(ctxSolutions[s]), dataOffset, ctxKnown);
      if (score > bestScore) {
        bestScore = score;
        bestKeys = ctxSolutions[s];
      }
    }
    return {
      keys: bestKeys,
      plaintext: decryptFromWindow(bestKeys),
      tried: ctxTried,
      elapsedMs: Date.now() - startedAt,
    };
  } finally {
    inAttack = false;
  }
};
