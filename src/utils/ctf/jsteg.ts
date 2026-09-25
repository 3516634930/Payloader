// jsteg 提取器（批次 SI·A 线）：lukechampine/jsteg（MIT，https://github.com/lukechampine/jsteg）
// 语义复刻——遍历 MCU 顺序 DCT 系数流，只取扫描第 0 分量（通常 Y），跳过每块 DC
// 与值 0/±1 的系数，其余系数贡献 LSB，LSB-first 装配字节。includeMinusOne 开关
// 兼容原版 C jsteg 的 {0,+1} 跳过集（lukechampine 版额外跳过 -1，防 1↔-1 翻转歧义）。
import { JPEG_ZIGZAG, readJpegCoefficients } from './jpegCoeffs';

export interface JstegFinding {
  kind: string; // 'jsteg'（CLI 封装格式）/ 'png' / 'zip' / 'flag'
  offset: number; // 命中起始的比特位（= 贡献系数序号， LSB 流内字节位置 × 8）
  preview: string;
}

export interface JstegRevealResult {
  rawBits: Uint8Array; // LSB 装配出的原始字节流（LSB-first）
  findings: JstegFinding[];
  coefficientCount: number; // 实际贡献比特的可用 AC 系数个数
}

const MAX_FINDINGS_PER_KIND = 32;
const PREVIEW_LIMIT = 96;

const printableRun = (text: string, start: number, limit = PREVIEW_LIMIT): string => {
  let out = '';
  for (let i = start; i < text.length && out.length < limit; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) break;
    out += text[i];
  }
  return out;
};

const latin1 = (bytes: Uint8Array): string => {
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return out;
};

const matchesAt = (bytes: Uint8Array, offset: number, magic: number[]): boolean => {
  for (let i = 0; i < magic.length; i += 1) {
    if (bytes[offset + i] !== magic[i]) return false;
  }
  return true;
};

// 自动扫描魔数：jsteg CLI 封装（"jsteg" + le32 长度 + 载荷）、PNG、ZIP、可打印 flag 文本
const scanMagics = (rawBits: Uint8Array): JstegFinding[] => {
  const findings: JstegFinding[] = [];
  const text = latin1(rawBits);
  for (let i = 0; i + 9 <= rawBits.length; i += 1) {
    if (!matchesAt(rawBits, i, [0x6a, 0x73, 0x74, 0x65, 0x67])) continue; // "jsteg"
    const length =
      rawBits[i + 5] | (rawBits[i + 6] << 8) | (rawBits[i + 7] << 16) | (rawBits[i + 8] << 24);
    if (length <= 0 || length > rawBits.length - i - 9) continue;
    findings.push({
      kind: 'jsteg',
      offset: i * 8,
      preview: printableRun(text, i + 9, Math.min(PREVIEW_LIMIT, length)),
    });
    i += 8; // 跳过 magic + 长度字段，避免载荷内容再撞一次
  }
  const simpleMagic: Array<{ kind: string; magic: number[]; preview: string }> = [
    { kind: 'png', magic: [0x89, 0x50, 0x4e, 0x47], preview: 'PNG 文件镜像起始' },
    { kind: 'zip', magic: [0x50, 0x4b, 0x03, 0x04], preview: 'ZIP 文件镜像起始' },
  ];
  for (const { kind, magic, preview } of simpleMagic) {
    let hits = 0;
    for (let i = 0; i + magic.length <= rawBits.length && hits < MAX_FINDINGS_PER_KIND; i += 1) {
      if (!matchesAt(rawBits, i, magic)) continue;
      findings.push({ kind, offset: i * 8, preview });
      hits += 1;
      i += magic.length - 1;
    }
  }
  let flagHits = 0;
  for (let i = 0; i + 5 <= text.length && flagHits < MAX_FINDINGS_PER_KIND; i += 1) {
    const head = text.slice(i, i + 5);
    if (head !== 'flag{' && head !== 'FLAG{') continue;
    const end = text.indexOf('}', i);
    const preview =
      end > 0 && end - i + 1 <= 128 ? text.slice(i, end + 1) : printableRun(text, i, 120);
    if (preview.length < 6) continue;
    findings.push({ kind: 'flag', offset: i * 8, preview });
    flagHits += 1;
    i += preview.length - 1;
  }
  return findings;
};

export const jstegReveal = (
  bytes: Uint8Array,
  options: { includeMinusOne?: boolean } = {},
): JstegRevealResult => {
  const includeMinusOne = options.includeMinusOne === true;
  const { mcuOrderCoefficients: stream, mcuOrderComponentIndex: componentIndex } =
    readJpegCoefficients(bytes);
  const eachUsableAc = (visit: (ac: number) => void): number => {
    let count = 0;
    for (let base = 0; base + 63 < stream.length; base += 64) {
      if (componentIndex !== null && componentIndex[base] !== 0) continue; // 只取第 0 分量
      for (let k = 1; k < 64; k += 1) {
        const ac = stream[base + JPEG_ZIGZAG[k]];
        if (ac === 0 || ac === 1 || (ac === -1 && !includeMinusOne)) continue;
        count += 1;
        visit(ac);
      }
    }
    return count;
  };
  const coefficientCount = eachUsableAc(() => {});
  const rawBits = new Uint8Array(Math.ceil(coefficientCount / 8));
  let bit = 0;
  eachUsableAc((ac) => {
    rawBits[bit >> 3] |= (ac & 1) << (bit & 7);
    bit += 1;
  });
  return { rawBits, findings: scanMagics(rawBits), coefficientCount };
};
