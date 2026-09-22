// pcap/pcapng 容器解析（批次 L 流量分析域）：纯函数，输入只读字节。
// 格式规范：libpcap savefile（magic 0xa1b2c3d4 家族）与 IETF draft-tuexen-opsawg-pcapng。
// 限量策略：包数达到上限即停止并标记 truncated；头部长度非法立即停止并标记 corrupt，两层独立。

export const MAX_PARSE_PACKETS = 50000;
// 单条包记录的防御上限：snaplen 常见 65535/262144，超此值视为头已损坏而非超大包。
const MAX_RECORD_BYTES = 16 * 1024 * 1024;

export interface RawPacket {
  index: number;
  tsSeconds: number;
  capturedLen: number;
  originalLen: number;
  // 帧字节引用原文件缓冲，不复制；调用方不得持有其引用后修改原缓冲。
  data: Uint8Array;
  linkType: number;
}

export interface CaptureCorruption {
  packetIndex: number;
  reason: string;
}

export interface ParsedCapture {
  format: 'pcap' | 'pcapng';
  byteOrder: 'le' | 'be';
  nanosecond: boolean;
  linkType: number;
  linkTypeCount: number;
  packets: RawPacket[];
  truncated: boolean;
  corrupt: CaptureCorruption | null;
  packetLimit: number;
}

interface PcapngInterface {
  linkType: number;
  // if_tsresol：bit7=0 表示 10^-n 秒（默认 n=6 微秒），bit7=1 表示 2^-n 秒。
  tsresol: number;
}

const readU16 = (bytes: Uint8Array, offset: number, little: boolean): number => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint16(offset, little);
};

const readU32 = (bytes: Uint8Array, offset: number, little: boolean): number => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset, little);
};

// pcap 全局头 magic 四种序列：小/大端 × 微秒/纳秒（0xa1b23c4d 家族）。
const PCAP_MAGICS: Array<{ bytes: number[]; little: boolean; nanosecond: boolean }> = [
  { bytes: [0xd4, 0xc3, 0xb2, 0xa1], little: true, nanosecond: false },
  { bytes: [0xa1, 0xb2, 0xc3, 0xd4], little: false, nanosecond: false },
  { bytes: [0x4d, 0x3c, 0xb2, 0xa1], little: true, nanosecond: true },
  { bytes: [0xa1, 0xb2, 0x3c, 0x4d], little: false, nanosecond: true },
];

const PCAPNG_SHB_TYPE = 0x0a0d0d0a;

const isPcapngShb = (bytes: Uint8Array): boolean =>
  bytes.length >= 4 && bytes[0] === 0x0a && bytes[1] === 0x0d && bytes[2] === 0x0d && bytes[3] === 0x0a;

const detectPcapMagic = (bytes: Uint8Array) =>
  PCAP_MAGICS.find(magic => bytes.length >= 4 && bytes[0] === magic.bytes[0] && bytes[1] === magic.bytes[1] && bytes[2] === magic.bytes[2] && bytes[3] === magic.bytes[3]);

const fracToSeconds = (frac: number, nanosecond: boolean): number => frac / (nanosecond ? 1e9 : 1e6);

const parsePcap = (bytes: Uint8Array, magic: { little: boolean; nanosecond: boolean }, maxPackets: number): ParsedCapture => {
  const packets: RawPacket[] = [];
  const little = magic.little;
  const linkType = bytes.length >= 24 ? readU32(bytes, 20, little) : 0;
  let truncated = false;
  let corrupt: CaptureCorruption | null = null;
  let position = 24;
  while (position + 16 <= bytes.length) {
    const tsSeconds = readU32(bytes, position, little) + fracToSeconds(readU32(bytes, position + 4, little), magic.nanosecond);
    const capturedLen = readU32(bytes, position + 8, little);
    const originalLen = readU32(bytes, position + 12, little);
    if (capturedLen > MAX_RECORD_BYTES) {
      corrupt = { packetIndex: packets.length, reason: `包记录声明长度 ${capturedLen} 超过防御上限，记录头可能已损坏` };
      break;
    }
    if (position + 16 + capturedLen > bytes.length) {
      corrupt = { packetIndex: packets.length, reason: '文件在包数据中途被截断' };
      break;
    }
    packets.push({
      index: packets.length,
      tsSeconds,
      capturedLen,
      originalLen,
      data: bytes.subarray(position + 16, position + 16 + capturedLen),
      linkType,
    });
    position += 16 + capturedLen;
    if (packets.length >= maxPackets) {
      truncated = position + 16 <= bytes.length;
      break;
    }
  }
  return { format: 'pcap', byteOrder: little ? 'le' : 'be', nanosecond: magic.nanosecond, linkType, linkTypeCount: 1, packets, truncated, corrupt, packetLimit: maxPackets };
};

// 块体里的选项区解析：code(2) length(2) value(pad 到 4 字节)，返回目标 code 的首个值。
const findOption = (body: Uint8Array, offset: number, end: number, targetCode: number, little: boolean): number | null => {
  let position = offset;
  while (position + 4 <= end) {
    const code = readU16(body, position, little);
    const length = readU16(body, position + 2, little);
    if (code === 0) break;
    if (position + 4 + length > end) break;
    if (code === targetCode && length >= 1) return body[position + 4];
    position += 4 + length + ((4 - (length % 4)) % 4);
  }
  return null;
};

const parsePcapng = (bytes: Uint8Array, maxPackets: number): ParsedCapture => {
  const packets: RawPacket[] = [];
  const interfaces: PcapngInterface[] = [];
  let truncated = false;
  let corrupt: CaptureCorruption | null = null;
  let little = true;
  let linkType = 0;
  let position = 0;
  while (position + 12 <= bytes.length) {
    let blockType = readU32(bytes, position, little);
    let headLength = readU32(bytes, position + 4, little);
    if (blockType === PCAPNG_SHB_TYPE) {
      // SHB 前四字节 byte-order magic 固定 0x1A2B3C4D：按小端读出该值即小端，否则大端。
      // SHB 类型号是回文，字节序未知也可进入本分支；校正后必须用新字节序重读块长。
      little = position + 12 <= bytes.length && readU32(bytes, position + 8, true) === 0x1a2b3c4d;
      blockType = readU32(bytes, position, little);
      headLength = readU32(bytes, position + 4, little);
      // 新 section：接口列表与链路层类型随之失效（简化：单 section 场景为主，跨 section 重置）。
      interfaces.length = 0;
      linkType = 0;
    }
    if (headLength < 12 || position + headLength > bytes.length) {
      corrupt = { packetIndex: packets.length, reason: `块长度 ${headLength} 非法，块结构可能已损坏` };
      break;
    }
    if (readU32(bytes, position + headLength - 4, little) !== headLength) {
      corrupt = { packetIndex: packets.length, reason: '块尾部长度与块头不一致，块结构可能已损坏' };
      break;
    }
    const bodyStart = position + 8;
    const bodyEnd = position + headLength - 4;
    if (blockType === 0x00000001 && bodyEnd - bodyStart >= 8) {
      const interfaceLinkType = readU16(bytes, bodyStart, little);
      let tsresol = 6;
      const optionValue = findOption(bytes, bodyStart + 8, bodyEnd, 9, little);
      if (optionValue !== null) tsresol = optionValue;
      interfaces.push({ linkType: interfaceLinkType, tsresol });
      if (interfaces.length === 1) linkType = interfaceLinkType;
    } else if (blockType === 0x00000006 && bodyEnd - bodyStart >= 20) {
      const interfaceId = readU32(bytes, bodyStart, little);
      const tsHigh = readU32(bytes, bodyStart + 4, little);
      const tsLow = readU32(bytes, bodyStart + 8, little);
      const capturedLen = readU32(bytes, bodyStart + 12, little);
      const originalLen = readU32(bytes, bodyStart + 16, little);
      const config = interfaces[interfaceId];
      if (capturedLen > MAX_RECORD_BYTES || bodyStart + 20 + capturedLen > bodyEnd) {
        corrupt = { packetIndex: packets.length, reason: `EPB 声明数据长度 ${capturedLen} 超出块体，块可能已损坏` };
        break;
      }
      if (!config) {
        corrupt = { packetIndex: packets.length, reason: `EPB 引用了不存在的接口 ${interfaceId}` };
        break;
      }
      const raw = tsHigh * 4294967296 + tsLow;
      const resolution = config.tsresol & 0x80
        ? Math.pow(2, -(config.tsresol & 0x7f))
        : Math.pow(10, -(config.tsresol & 0x7f));
      packets.push({
        index: packets.length,
        tsSeconds: raw * resolution,
        capturedLen,
        originalLen,
        data: bytes.subarray(bodyStart + 20, bodyStart + 20 + capturedLen),
        linkType: config.linkType,
      });
      if (packets.length >= maxPackets) {
        truncated = position + headLength < bytes.length;
        break;
      }
    } else if (blockType === 0x00000003 && bodyEnd - bodyStart >= 4) {
      // SPB 无 captured_len：抓取长度 = min(original_len, 首接口 snaplen 语义上的上限)，数据区 pad 到 4 字节。
      const originalLen = readU32(bytes, bodyStart, little);
      const capturedLen = Math.min(originalLen, MAX_RECORD_BYTES, bodyEnd - bodyStart - 4);
      packets.push({
        index: packets.length,
        tsSeconds: 0,
        capturedLen,
        originalLen,
        data: bytes.subarray(bodyStart + 4, bodyStart + 4 + capturedLen),
        linkType: interfaces[0]?.linkType ?? 0,
      });
      if (packets.length >= maxPackets) {
        truncated = position + headLength < bytes.length;
        break;
      }
    }
    position += headLength;
  }
  if (!corrupt && packets.length === 0) {
    corrupt = { packetIndex: 0, reason: '未找到任何包含数据包的块' };
  }
  return { format: 'pcapng', byteOrder: little ? 'le' : 'be', nanosecond: false, linkType, linkTypeCount: interfaces.length || 1, packets, truncated, corrupt, packetLimit: maxPackets };
};

export const parseCapture = (bytes: Uint8Array, options?: { maxPackets?: number }): ParsedCapture => {
  const maxPackets = options?.maxPackets ?? MAX_PARSE_PACKETS;
  if (isPcapngShb(bytes)) return parsePcapng(bytes, maxPackets);
  const magic = detectPcapMagic(bytes);
  if (magic) return parsePcap(bytes, magic, maxPackets);
  return {
    format: 'pcap',
    byteOrder: 'le',
    nanosecond: false,
    linkType: -1,
    linkTypeCount: 0,
    packets: [],
    truncated: false,
    corrupt: { packetIndex: 0, reason: '文件头既不是 pcap 魔数也不是 pcapng SHB，无法识别为抓包文件' },
    packetLimit: maxPackets,
  };
};
