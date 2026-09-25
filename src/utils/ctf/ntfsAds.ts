// ZIP 内 NTFS ADS（Alternate Data Stream，交替数据流）提取引擎：对标随波逐流"NTFS数据流"。
// 纯本地算法、只读字节、同步纯函数、无 eval/网络；20MB 红线与 fileDetect 同源。
//
// 载体与结构证据：
// - PKZIP APPNOTE.TXT 4.5.5 "NTFS Extra Field (0x000a)"（pkware.cachefly.net，LE 字节序）：
//   [2B tag=0x000a][2B size][4B Reserved] + 重复属性 [2B NTFS attribute tag][2B size][data]；
//   属性 tag 0x0001 目前唯一定义为 3×8B FILETIME（Mtime/Atime/Ctime）。
//   Apache Commons Compress X000A_NTFS javadoc 佐证："thought to store various attributes but
//   in reality only stores timestamps"——标准工具只用 0x000a 存时间戳。
// - 真实 ZIP ADS 形态：条目名含冒号的虚拟条目 `file:stream`（7-Zip/WinRAR/新版 Windows 与
//   unxed/zipper README "Alternative Data Streams (Win) | Find*StreamW | Virtual files (file:stream)"
//   同一约定；解压器在 NTFS 上还原为真实 ADS，对应 ACTF新生赛2020"NTFS数据流"等真题）。
// - 本模块同时兼容 CTF 私改形态：0x000a 内 tag 0x0001 属性被写入流描述
//   [2B 保留][2B 流名长][流名][流数据]（随波逐流系题目约定；nameLen 兼容 u16 主判 + u8 回退）。
//
// 为何不复用 zipBrute.ts 的 EOCD/中央目录解析：其 findEocdOffset/遍历循环均为模块私有未导出，
// 唯一公开入口 detectEncryptedEntries 语义是"只收集加密条目、无加密即抛错"，与本任务
// "遍历全部条目 + 读双份 extra 区 + 容错降级"语义不同，故按同一算法（EOCD 反向扫描 + 46B 定长头
// 步进）独立实现。
import { MAX_FILE_BYTES } from './fileDetect';
import { detectFlagFormats } from '../codec/smartDecode';

export interface NtfsAdsStream {
  // 宿主条目名（冒号前的主体文件；extra-field 形态即该条目自身）。
  entryName: string;
  streamName: string;
  // stored(method 0) 条目的流内容；压缩条目/属性越界时为 null（见 hint）。
  bytes: Uint8Array | null;
  // latin1 可打印预览（256B 截断）。
  preview: string;
  // 预览文本上的 flag 格式命中（复用智能解码格式清单，如 "flag{...}" 前缀）。
  flags: Array<{ prefix: string; sample: string }>;
  source: 'entry-name' | 'extra-field';
  hint?: string;
}

export interface NtfsAdsReport {
  streams: NtfsAdsStream[];
  diagnosis: string[];
  entryCount: number;
}

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const NTFS_EXTRA_ID = 0x000a;
const NTFS_ATTR_FILETIMES = 0x0001;
const PREVIEW_LIMIT = 256;

const readLe16 = (bytes: Uint8Array, offset: number): number => (bytes[offset] | (bytes[offset + 1] << 8)) & 0xffff;
const readLe32 = (bytes: Uint8Array, offset: number): number =>
  (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;

const latin1Decoder = new TextDecoder('latin1');
const utf8Decoder = new TextDecoder();

interface ZipEntry {
  name: string;
  localHeaderOffset: number;
  method: number;
  compressedSize: number;
  // extra 区两份来源（CD 与本地头各一份，真实 ZIP 常不一致——如 Info-ZIP 把 0x000a 只写在 CD）。
  centralExtra: { offset: number; length: number };
  localExtra: { offset: number; length: number } | null;
  fromCentral: boolean;
}

const decodeName = (bytes: Uint8Array, offset: number, length: number, utf8: boolean): string =>
  (utf8 ? utf8Decoder : latin1Decoder).decode(bytes.subarray(offset, offset + length));

// EOCD 反向扫描（算法同 zipBrute.findEocdOffset：注释区上限 0xFFFF → 搜索窗 22+65535）。
const findEocdOffset = (bytes: Uint8Array): number => {
  if (bytes.length < 22) return -1;
  const minOffset = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= minOffset; offset -= 1) {
    if (readLe32(bytes, offset) === EOCD_SIGNATURE) return offset;
  }
  return -1;
};

const parseCentralEntries = (bytes: Uint8Array): { entries: ZipEntry[]; notes: string[] } | null => {
  const eocdOffset = findEocdOffset(bytes);
  if (eocdOffset < 0) return null;
  const entryCount = readLe16(bytes, eocdOffset + 10);
  const notes: string[] = [];
  let cursor = readLe32(bytes, eocdOffset + 16);
  const entries: ZipEntry[] = [];
  for (let index = 0; index < entryCount; index += 1) {
    if (cursor + 46 > bytes.length || readLe32(bytes, cursor) !== CENTRAL_SIGNATURE) {
      notes.push(`第 ${index + 1} 个中央目录条目在偏移 ${cursor} 越界/签名损坏：改用本地头扫描兜底`);
      return null;
    }
    const flag = readLe16(bytes, cursor + 8);
    const method = readLe16(bytes, cursor + 10);
    const compressedSize = readLe32(bytes, cursor + 20);
    const nameLength = readLe16(bytes, cursor + 28);
    const extraLength = readLe16(bytes, cursor + 30);
    const commentLength = readLe16(bytes, cursor + 32);
    const localHeaderOffset = readLe32(bytes, cursor + 42);
    if (cursor + 46 + nameLength + extraLength + commentLength > bytes.length) {
      notes.push(`第 ${index + 1} 个条目的 name/extra/comment 区越界：改用本地头扫描兜底`);
      return null;
    }
    const name = decodeName(bytes, cursor + 46, nameLength, (flag & 0x800) !== 0);
    const localExtra = readLocalExtra(bytes, localHeaderOffset);
    entries.push({
      name,
      localHeaderOffset,
      method,
      compressedSize,
      centralExtra: { offset: cursor + 46 + nameLength, length: extraLength },
      localExtra,
      fromCentral: true,
    });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return { entries, notes };
};

// 本地头 extra 区（local header：nameLen@26/extraLen@28，extra 起点 30+nameLen）。
const readLocalExtra = (bytes: Uint8Array, offset: number): { offset: number; length: number } | null => {
  if (offset < 0 || offset + 30 > bytes.length || readLe32(bytes, offset) !== LOCAL_SIGNATURE) return null;
  const nameLength = readLe16(bytes, offset + 26);
  const extraLength = readLe16(bytes, offset + 28);
  const extraOffset = offset + 30 + nameLength;
  if (extraOffset + extraLength > bytes.length) return null;
  return { offset: extraOffset, length: extraLength };
};

// EOCD/CD 不可用时的兜底：全文件线性扫描本地头签名（前缀扫描天然跳过数据区误配对的极端碰撞）。
const scanLocalEntries = (bytes: Uint8Array): { entries: ZipEntry[]; notes: string[] } => {
  const entries: ZipEntry[] = [];
  for (let position = 0; position + 30 <= bytes.length; position += 1) {
    if (readLe32(bytes, position) !== LOCAL_SIGNATURE) continue;
    const flag = readLe16(bytes, position + 6);
    const method = readLe16(bytes, position + 8);
    const compressedSize = readLe16(bytes, position + 18) | (readLe16(bytes, position + 20) << 16);
    const nameLength = readLe16(bytes, position + 26);
    const extraLength = readLe16(bytes, position + 28);
    if (position + 30 + nameLength + extraLength > bytes.length) continue;
    entries.push({
      name: decodeName(bytes, position + 30, nameLength, (flag & 0x800) !== 0),
      localHeaderOffset: position,
      method,
      compressedSize,
      centralExtra: { offset: position + 30 + nameLength, length: 0 },
      localExtra: { offset: position + 30 + nameLength, length: extraLength },
      fromCentral: false,
    });
    position += 29 + nameLength + extraLength;
  }
  const notes = entries.length
    ? ['中央目录不可用：已按本地头签名扫描全部条目（data descriptor 条目的尺寸字段可能为 0）']
    : ['中央目录与本地头扫描均未发现 ZIP 条目'];
  return { entries, notes };
};

// NTFS FILETIME（1601-01-01 起 100ns 刻度）→ ISO 字符串；越界值返回原始 u64。
const filetimeToIso = (raw: number): string => {
  const adjusted = BigInt(raw) - 116444736000000000n;
  if (adjusted < 0n || adjusted > 8640000000000000000n) return `原始值 ${raw}`;
  return new Date(Number(adjusted / 10000n)).toISOString();
};

interface NtfsExtraParse {
  filetimes: string[];
  streams: Array<{ name: string; bytes: Uint8Array }>;
  notes: string[];
}

// 解析一个 extra 区内的全部 0x000a 块：官方 24B 时间戳照常读出；非 24B 的 0x0001 属性按
// CTF 流布局 [2B 保留][2B nameLen][name][data] 解（u16 主判，u8 回退）。
const parseNtfsExtras = (bytes: Uint8Array, region: { offset: number; length: number }): NtfsExtraParse => {
  const result: NtfsExtraParse = { filetimes: [], streams: [], notes: [] };
  let cursor = region.offset;
  const end = region.offset + region.length;
  while (cursor + 4 <= end) {
    const tag = readLe16(bytes, cursor);
    const size = readLe16(bytes, cursor + 2);
    if (size > end - cursor - 4) {
      result.notes.push(`偏移 ${cursor} 的 extra 块 size=${size} 越界：停止本区解析`);
      break;
    }
    if (tag === NTFS_EXTRA_ID && size >= 4) {
      // APPNOTE 4.5.5：[4B Reserved] 后逐属性 [2B tag][2B size][data]。
      const bodyEnd = cursor + 4 + size;
      let attrCursor = cursor + 4 + 4;
      while (attrCursor + 4 <= bodyEnd) {
        const attrTag = readLe16(bytes, attrCursor);
        const attrSize = readLe16(bytes, attrCursor + 2);
        if (attrSize > bodyEnd - attrCursor - 4) {
          result.notes.push(`偏移 ${attrCursor} 的 NTFS 属性 size=${attrSize} 越界：跳过该 0x000a 块`);
          break;
        }
        const dataStart = attrCursor + 4;
        if (attrTag === NTFS_ATTR_FILETIMES && attrSize === 24) {
          const mtime = filetimeToIso(readLe32(bytes, dataStart) + readLe32(bytes, dataStart + 4) * 0x100000000);
          const atime = filetimeToIso(readLe32(bytes, dataStart + 8) + readLe32(bytes, dataStart + 12) * 0x100000000);
          const ctime = filetimeToIso(readLe32(bytes, dataStart + 16) + readLe32(bytes, dataStart + 20) * 0x100000000);
          result.filetimes.push(`Mtime=${mtime} / Atime=${atime} / Ctime=${ctime}（官方 0x0001=24B 时间戳属性）`);
        } else if (attrTag === NTFS_ATTR_FILETIMES) {
          // 非标准长度：先按 u16 nameLen 的流布局解，失败回退 u8。
          const stream = parseStreamAttribute(bytes, dataStart, attrSize, 2) ?? parseStreamAttribute(bytes, dataStart, attrSize, 1);
          if (stream) result.streams.push(stream);
          else {
            const head = Array.from(bytes.subarray(dataStart, Math.min(dataStart + 8, dataStart + attrSize)))
              .map(byte => byte.toString(16).padStart(2, '0'))
              .join(' ');
            result.notes.push(`偏移 ${attrCursor} 的 0x0001 属性 size=${attrSize}（非官方 24B 时间戳）且不匹配流布局（头部 ${head}）：按未知属性记录`);
          }
        } else {
          result.notes.push(`偏移 ${attrCursor} 的未定义 NTFS 属性 tag=0x${attrTag.toString(16)} size=${attrSize}（APPNOTE 之外）`);
        }
        attrCursor += 4 + attrSize;
      }
    }
    cursor += 4 + size;
  }
  return result;
};

// 流属性布局：[nameLenWidth 字节保留][nameLenWidth 字节名长][name][data 到属性尾]。
const parseStreamAttribute = (
  bytes: Uint8Array,
  dataStart: number,
  attrSize: number,
  nameLenWidth: 1 | 2,
): { name: string; bytes: Uint8Array } | null => {
  const headerSize = 2 + nameLenWidth;
  if (attrSize < headerSize) return null;
  const nameLength = nameLenWidth === 2 ? readLe16(bytes, dataStart + 2) : bytes[dataStart + 2];
  if (nameLength <= 0 || attrSize < headerSize + nameLength) return null;
  const name = latin1Decoder.decode(bytes.subarray(dataStart + headerSize, dataStart + headerSize + nameLength));
  if (!/^[\x20-\x7e]+$/.test(name)) return null; // 流名限定可打印 ASCII（NTFS 流名字符集实践的保守子集）
  const streamBytes = bytes.slice(dataStart + headerSize + nameLength, dataStart + attrSize);
  if (!streamBytes.length) return null;
  return { name, bytes: streamBytes };
};

const buildPreview = (data: Uint8Array): string => {
  const limit = Math.min(data.length, PREVIEW_LIMIT);
  let preview = '';
  for (let index = 0; index < limit; index += 1) {
    const byte = data[index];
    preview += byte === 9 || byte === 10 || byte === 13 || (byte >= 0x20 && byte <= 0x7e) ? String.fromCharCode(byte) : '.';
  }
  return preview;
};

// 冒号条目名 → (宿主, 流名)：'note.txt:flag.txt' / 'note.txt:flag.txt:$DATA'。
// 冒号须在第 2 字节之后（排除 'C:\' 盘符形态的误配）。
const splitColonEntry = (name: string): { entryName: string; streamName: string } | null => {
  const colon = name.indexOf(':');
  if (colon < 2 || colon === name.length - 1) return null;
  let stream = name.slice(colon + 1);
  if (stream.toLowerCase().endsWith(':$data')) stream = stream.slice(0, -':$data'.length);
  if (!stream) return null;
  return { entryName: name.slice(0, colon), streamName: stream };
};

const storedEntryBytes = (bytes: Uint8Array, entry: ZipEntry): Uint8Array | null => {
  if (entry.localHeaderOffset < 0 || entry.localHeaderOffset + 30 > bytes.length || readLe32(bytes, entry.localHeaderOffset) !== LOCAL_SIGNATURE) return null;
  const nameLength = readLe16(bytes, entry.localHeaderOffset + 26);
  const extraLength = readLe16(bytes, entry.localHeaderOffset + 28);
  const dataOffset = entry.localHeaderOffset + 30 + nameLength + extraLength;
  const length = Math.min(entry.compressedSize, bytes.length - dataOffset);
  if (length <= 0) return null;
  return bytes.slice(dataOffset, dataOffset + length);
};

const methodHint = (method: number): string | undefined => {
  if (method === 8) return '条目为 deflate 压缩：流内容未解压（与 zipBrute 的 stored-only 策略一致），请用系统解压软件按流名提取';
  if (method !== 0) return `条目压缩方法 ${method} 非 stored：流内容未解压`;
  return undefined;
};

export const extractNtfsAds = (bytes: Uint8Array): NtfsAdsReport => {
  if (bytes.length > MAX_FILE_BYTES) {
    throw new Error(`NTFS ADS 提取输入 ${bytes.length} 字节超过 ${MAX_FILE_BYTES} 上限，拒绝解析`);
  }
  const diagnosis: string[] = [];

  // 7z/RAR 载体识别：ZIP 之外的常见流载体给出明确指引（7-Zip 存流时同为 file:stream 虚拟条目形态）。
  if (bytes.length >= 6 && bytes[0] === 0x37 && bytes[1] === 0x7a && bytes[2] === 0xbc && bytes[3] === 0xaf && bytes[4] === 0x27 && bytes[5] === 0x1c) {
    diagnosis.push('输入是 7-Zip 容器（魔数 37 7A BC AF 27 1C）：ADS 在 7z 内同样以 file:stream 条目形态存储，但解析需 7z 头部解码器（本模块仅解析 ZIP），请用新版 7-Zip 打开查看流条目');
    return { streams: [], diagnosis, entryCount: 0 };
  }
  if (bytes.length >= 7 && bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21 && bytes[4] === 0x1a && bytes[5] === 0x07 && (bytes[6] === 0x00 || bytes[6] === 0x01)) {
    diagnosis.push('输入是 RAR 容器：NTFS 流题的 RAR 载体需 WinRAR/RAR5 解析器提取（参考 rarInspect），本模块仅解析 ZIP');
    return { streams: [], diagnosis, entryCount: 0 };
  }

  const central = parseCentralEntries(bytes);
  const { entries, notes } = central ?? scanLocalEntries(bytes);
  diagnosis.push(...notes);
  diagnosis.push(`共解析 ${entries.length} 个 ZIP 条目${central ? '（中央目录路径）' : '（本地头扫描路径）'}`);

  const streams: NtfsAdsStream[] = [];
  for (const entry of entries) {
    // 形态一：冒号虚拟条目（7-Zip/zipper/WinRAR 的标准 ADS 存储）。
    const colon = splitColonEntry(entry.name);
    if (colon) {
      const data = entry.method === 0 ? storedEntryBytes(bytes, entry) : null;
      const preview = data ? buildPreview(data) : '';
      streams.push({
        entryName: colon.entryName,
        streamName: colon.streamName,
        bytes: data,
        preview,
        flags: preview ? detectFlagFormats(preview).map(hit => ({ prefix: hit.prefix, sample: hit.sample })) : [],
        source: 'entry-name',
        hint: methodHint(entry.method),
      });
      diagnosis.push(`条目 "${entry.name}" 为冒号虚拟条目：宿主 "${colon.entryName}" 上的 ADS "${colon.streamName}"`);
    }
    // 形态二：0x000a extra field（CD 与本地头两份都读，去重合并）。
    const regions = [entry.centralExtra, entry.localExtra].filter(
      (region): region is { offset: number; length: number } => region !== null && region.length > 0,
    );
    const seen = new Set<string>();
    for (const region of regions) {
      const parsed = parseNtfsExtras(bytes, region);
      for (const line of parsed.filetimes) diagnosis.push(`条目 "${entry.name}" 的 NTFS 时间戳：${line}`);
      for (const stream of parsed.streams) {
        const key = `${entry.name}#${stream.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const preview = buildPreview(stream.bytes);
        streams.push({
          entryName: entry.name,
          streamName: stream.name,
          bytes: stream.bytes,
          preview,
          flags: preview ? detectFlagFormats(preview).map(hit => ({ prefix: hit.prefix, sample: hit.sample })) : [],
          source: 'extra-field',
        });
        diagnosis.push(`条目 "${entry.name}" 的 0x000a extra field 内 0x0001 属性携带 ADS "${stream.name}"（${stream.bytes.length} 字节）`);
      }
      for (const note of parsed.notes) diagnosis.push(`条目 "${entry.name}"：${note}`);
    }
  }

  if (!streams.length) {
    diagnosis.push('未发现 NTFS 交替数据流（无冒号条目、0x000a 内亦无流属性）：该 ZIP 不是流载体');
  }
  return { streams, diagnosis, entryCount: entries.length };
};
