// CyberChef 对标 CC2 批次：LZ-String 解压家族（官方 lz-string 1.5.0，MIT）+ ZIP 解包清单。
// lz-string 为 npm 正式依赖（非 vendor），纯 JS 零依赖；ZIP 清单与 apkParse 的 EOCD 解析同语义。

import { decompressFromBase64, decompressFromEncodedURIComponent, decompressFromUTF16 } from 'lz-string';

export type LzStringVariant = 'base64' | 'utf16' | 'uri';

export const lzStringDecompress = (input: string, variant: LzStringVariant): { text: string | null; error?: string } => {
  const trimmed = input.trim();
  if (!trimmed) return { text: null, error: '输入为空。' };
  const decompressed =
    variant === 'base64' ? decompressFromBase64(trimmed)
      : variant === 'utf16' ? decompressFromUTF16(trimmed)
        : decompressFromEncodedURIComponent(trimmed);
  if (decompressed === null || decompressed.length === 0) {
    return { text: null, error: '解压失败：输入不是该形态的 LZ-String 压缩串（试试切换形态）。' };
  }
  return { text: decompressed };
};

// ---- ZIP 解包清单（EOCD + 中央目录；提取/伪加密修复走杂项域既有卡）----

export interface ZipListingEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  method: string;
}

export const listZip = (bytes: Uint8Array): { entries: ZipListingEntry[] } | { error: string } => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  const minEocd = Math.max(0, bytes.length - 66_000);
  for (let i = bytes.length - 22; i >= minEocd; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return { error: '找不到 ZIP EOCD——不是 zip 文件。' };
  const entryCount = dv.getUint16(eocd + 10, true);
  const cdOffset = dv.getUint32(eocd + 16, true);
  const entries: ZipListingEntry[] = [];
  let p = cdOffset;
  for (let i = 0; i < entryCount && p + 46 <= bytes.length; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const compressedSize = dv.getUint32(p + 20, true);
    const uncompressedSize = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const name = new TextDecoder().decode(bytes.subarray(p + 46, p + 46 + nameLen));
    entries.push({
      name,
      compressedSize,
      uncompressedSize,
      method: method === 0 ? 'stored' : method === 8 ? 'deflate' : `m${method}`,
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  if (entries.length === 0) return { error: 'ZIP 中央目录为空。' };
  return { entries };
};

export const formatZipListing = (entries: ZipListingEntry[]): string =>
  entries.map(e => `${e.name}\t${e.method}\t${e.compressedSize} → ${e.uncompressedSize} B`).join('\n');
