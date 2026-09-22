// 流量分析（批次 L）：TCP 流重组、HTTP 报文级解析（Content-Length / chunked / 读到流尾）、
// 请求-响应配对、协议统计与 flag 定位扫描（复用智能解码 flag 格式清单）。
// 输入只读；输出中的字节均为切片/拷贝，组件层可直接持有。
import { detectFlagFormats } from '../../codec/smartDecode';
import type { PacketView } from './protocols';

// 单方向流拼接上限：超过即丢弃越界段并标记 truncated（防超大流吃内存）。
export const MAX_STREAM_BYTES = 2 * 1024 * 1024;
const MAX_HTTP_MESSAGES_PER_DIRECTION = 200;
const MAX_STREAMS = 500;
const MAX_HEADER_BYTES = 64 * 1024;

export interface FlagHit {
  prefix: string;
  sample: string;
  source: string;
}

export interface HttpHeader {
  name: string;
  value: string;
}

export interface HttpMessage {
  direction: 'req' | 'res';
  streamId: number;
  packetIndex: number;
  startLine: string;
  method: string;
  path: string;
  query: Array<[string, string]>;
  status: number | null;
  headers: HttpHeader[];
  bodyBytes: Uint8Array;
  bodyText: string;
  bodyTruncated: boolean;
  hasFlag: boolean;
}

export interface HttpTransaction {
  streamId: number;
  request: HttpMessage | null;
  response: HttpMessage | null;
}

export interface TcpStream {
  id: number;
  endpointA: string;
  endpointB: string;
  packetCount: number;
  byteCount: number;
  bufferAtoB: Uint8Array;
  bufferBtoA: Uint8Array;
  truncated: boolean;
  hasFlag: boolean;
  packetIndexes: number[];
}

export interface CaptureAnalysis {
  stats: Array<{ key: string; count: number }>;
  streams: TcpStream[];
  streamTotal: number;
  transactions: HttpTransaction[];
  httpTotal: number;
  flags: FlagHit[];
}

interface StreamSide {
  segments: Array<{ rawSeq: number; length: number; packetIndex: number; bytes: Uint8Array }>;
}

const endpointOf = (view: PacketView, side: 'src' | 'dst'): string => {
  const ip = side === 'src' ? view.src : view.dst;
  const port = side === 'src' ? view.srcPort : view.dstPort;
  return port === null ? ip : `${ip}:${port}`;
};

// 相对 seq：以方向最小 seq 为基线（无符号差值）。乱序到达时"首个到达的包"未必 seq 最小，
// 因此基线在重组阶段统一取最小值；跨回绕窗口的极端场景会产生巨大相对值并被上限丢弃（标记 truncated）。
const relativeSeq = (seq: number, base: number): number => (seq - base) >>> 0;

interface DirectionBuffer {
  buffer: Uint8Array;
  offsets: Array<{ start: number; packetIndex: number }>;
  truncated: boolean;
}

const reassembleDirection = (side: StreamSide): DirectionBuffer => {
  const sorted = [...side.segments].sort((left, right) => left.rawSeq - right.rawSeq);
  const baseSeq = sorted.length ? sorted[0].rawSeq : 0;
  const ordered = sorted
    .map(segment => ({ relSeq: relativeSeq(segment.rawSeq, baseSeq), length: segment.length, packetIndex: segment.packetIndex, bytes: segment.bytes }))
    .sort((left, right) => left.relSeq - right.relSeq);
  let end = 0;
  for (const segment of ordered) {
    if (segment.relSeq >= MAX_STREAM_BYTES) continue;
    end = Math.max(end, Math.min(segment.relSeq + segment.length, MAX_STREAM_BYTES));
  }
  const buffer = new Uint8Array(end);
  const offsets: Array<{ start: number; packetIndex: number }> = [];
  const written = new Set<number>();
  let truncated = false;
  for (const segment of ordered) {
    if (segment.relSeq >= MAX_STREAM_BYTES) {
      truncated = true;
      continue;
    }
    if (segment.relSeq + segment.length > MAX_STREAM_BYTES) truncated = true;
    const copyLength = Math.min(segment.length, MAX_STREAM_BYTES - segment.relSeq);
    buffer.set(segment.bytes.subarray(0, copyLength), segment.relSeq);
    if (!written.has(segment.relSeq)) {
      offsets.push({ start: segment.relSeq, packetIndex: segment.packetIndex });
      written.add(segment.relSeq);
    }
  }
  offsets.sort((left, right) => left.start - right.start);
  return { buffer, offsets, truncated };
};

const packetIndexOf = (offsets: Array<{ start: number; packetIndex: number }>, offset: number): number => {
  let best = 0;
  for (const entry of offsets) {
    if (entry.start <= offset) best = entry.packetIndex;
    else break;
  }
  return best;
};

const REQUEST_LINE_STICKY = /([A-Za-z]{3,10}) ([^ \r\n]+) HTTP\/1\.[01]\r\n/y;
const STATUS_LINE_STICKY = /HTTP\/1\.[01] (\d{3})[^\r\n]*\r\n/y;
const NEXT_MESSAGE = /\r\n(?=(?:[A-Za-z]{3,10} [^ \r\n]+ HTTP\/1\.[01]\r\n)|(?:HTTP\/1\.[01] \d{3}\r\n))/g;

interface HttpHeaderPair {
  name: string;
  value: string;
}

interface RawHttpMessage {
  direction: 'req' | 'res';
  offset: number;
  bodyStart: number;
  bodyEnd: number;
  chunkedText: string | null;
  method: string;
  path: string;
  status: number | null;
  startLine: string;
  headers: HttpHeaderPair[];
}

const parseHeaderBlock = (text: string, cursor: number): { headers: HttpHeaderPair[]; end: number } | null => {
  const headers: HttpHeaderPair[] = [];
  let position = cursor;
  for (let guard = 0; guard < 128; guard += 1) {
    const lineEnd = text.indexOf('\r\n', position);
    if (lineEnd < 0 || lineEnd > position + MAX_HEADER_BYTES) return null;
    if (lineEnd === position) return { headers, end: position + 2 };
    const line = text.slice(position, lineEnd);
    const colon = line.indexOf(':');
    if (colon > 0) headers.push({ name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1).trim() });
    position = lineEnd + 2;
  }
  return null;
};

// chunked 解码：返回 [结束偏移, 解码文本]；结构非法时结束偏移为 -1。
const decodeChunkedBody = (text: string, start: number): [number, string] => {
  let position = start;
  const parts: string[] = [];
  for (let guard = 0; guard < 4096; guard += 1) {
    const lineEnd = text.indexOf('\r\n', position);
    if (lineEnd < 0) return [-1, ''];
    const size = parseInt(text.slice(position, lineEnd).split(';')[0].trim(), 16);
    if (!Number.isFinite(size) || size < 0) return [-1, ''];
    if (size === 0) return [lineEnd + 2, parts.join('')];
    const dataStart = lineEnd + 2;
    if (dataStart + size + 2 > text.length) return [-1, ''];
    parts.push(text.slice(dataStart, dataStart + size));
    position = dataStart + size + 2;
  }
  return [-1, ''];
};

const findNextMessageOffset = (text: string, from: number): number => {
  NEXT_MESSAGE.lastIndex = from;
  const match = NEXT_MESSAGE.exec(text);
  return match ? match.index + 2 : text.length;
};

const parseHttpDirection = (text: string): RawHttpMessage[] => {
  const messages: RawHttpMessage[] = [];
  let position = 0;
  while (messages.length < MAX_HTTP_MESSAGES_PER_DIRECTION) {
    const beforeSkip = position;
    let found: { direction: 'req' | 'res'; method: string; path: string; status: number | null; startLine: string; headerStart: number } | null = null;
    // 报文起点前允许有限行的前置噪声（重传尾巴、banner）：最多跳 16 行。
    for (let skip = 0; skip < 16 && !found; skip += 1) {
      REQUEST_LINE_STICKY.lastIndex = position;
      const requestMatch = REQUEST_LINE_STICKY.exec(text);
      if (requestMatch) {
        found = { direction: 'req', method: requestMatch[1].toUpperCase(), path: requestMatch[2], status: null, startLine: requestMatch[0].trim(), headerStart: REQUEST_LINE_STICKY.lastIndex };
        break;
      }
      STATUS_LINE_STICKY.lastIndex = position;
      const statusMatch = STATUS_LINE_STICKY.exec(text);
      if (statusMatch) {
        found = { direction: 'res', method: '', path: '', status: Number(statusMatch[1]), startLine: statusMatch[0].trim(), headerStart: STATUS_LINE_STICKY.lastIndex };
        break;
      }
      const nextNewline = text.indexOf('\n', position);
      if (nextNewline < 0) break;
      position = nextNewline + 1;
    }
    if (!found) break;
    const headerBlock = parseHeaderBlock(text, found.headerStart);
    if (!headerBlock) break;
    const headerMap = new Map(headerBlock.headers.map(header => [header.name, header.value]));
    const transferEncoding = headerMap.get('transfer-encoding') ?? '';
    const contentLength = headerMap.get('content-length');
    const bodyStart = headerBlock.end;
    let bodyEnd = bodyStart;
    let chunkedText: string | null = null;
    if (/chunked/i.test(transferEncoding)) {
      const [consumed, decoded] = decodeChunkedBody(text, bodyStart);
      if (consumed >= 0) {
        bodyEnd = consumed;
        chunkedText = decoded;
      } else {
        bodyEnd = text.length;
      }
    } else if (contentLength !== undefined) {
      const length = parseInt(contentLength, 10);
      bodyEnd = Number.isFinite(length) && length >= 0 ? Math.min(text.length, bodyStart + length) : text.length;
    } else if (found.direction === 'res') {
      bodyEnd = findNextMessageOffset(text, bodyStart);
    }
    messages.push({ ...found, offset: beforeSkip, bodyStart, bodyEnd, chunkedText, headers: headerBlock.headers });
    if (bodyEnd <= position && chunkedText === null && bodyEnd <= found.headerStart) break;
    position = Math.max(bodyEnd, found.headerStart);
  }
  return messages;
};

const decodeQuery = (path: string): Array<[string, string]> => {
  const questionMark = path.indexOf('?');
  if (questionMark < 0) return [];
  const params = new URLSearchParams(path.slice(questionMark + 1));
  const pairs: Array<[string, string]> = [];
  for (const [key, value] of params) {
    pairs.push([key, value]);
    if (pairs.length >= 64) break;
  }
  return pairs;
};

const latin1Encode = (text: string): Uint8Array => {
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index += 1) bytes[index] = text.charCodeAt(index) & 0xff;
  return bytes;
};

export const analyzeCapture = (views: PacketView[]): CaptureAnalysis => {
  // ---- 协议统计（HTTP/DNS 作为 TCP/UDP 内的细分标签，允许重叠计数） ----
  const statOrder = ['TCP', 'HTTP', 'UDP', 'DNS', 'ICMP', 'ICMPv6', 'ARP', 'other'] as const;
  const statCounts = new Map<string, number>();
  for (const view of views) {
    const keys: string[] = [];
    if (view.proto === 'TCP') {
      keys.push('TCP');
      if (view.isHttpRequest || view.isHttpResponse) keys.push('HTTP');
    } else if (view.proto === 'UDP') {
      keys.push('UDP');
      if (view.isDns) keys.push('DNS');
    } else if (view.proto === 'ICMP') keys.push('ICMP');
    else if (view.proto === 'ICMPv6') keys.push('ICMPv6');
    else if (view.proto === 'ARP') keys.push('ARP');
    else keys.push('other');
    for (const key of keys) statCounts.set(key, (statCounts.get(key) ?? 0) + 1);
  }
  const stats = statOrder.filter(key => (statCounts.get(key) ?? 0) > 0).map(key => ({ key, count: statCounts.get(key) ?? 0 }));

  // ---- TCP 流分组 ----
  const groups = new Map<string, { endpoints: [string, string]; sides: [StreamSide, StreamSide]; packetIndexes: Set<number>; byteCount: number }>();
  for (const view of views) {
    if (view.proto !== 'TCP') continue;
    const endpointSrc = endpointOf(view, 'src');
    const endpointDst = endpointOf(view, 'dst');
    const ordered = endpointSrc <= endpointDst ? [endpointSrc, endpointDst] : [endpointDst, endpointSrc];
    const key = `${ordered[0]}|${ordered[1]}`;
    let group = groups.get(key);
    if (!group) {
      group = { endpoints: [ordered[0], ordered[1]], sides: [{ segments: [] }, { segments: [] }], packetIndexes: new Set(), byteCount: 0 };
      groups.set(key, group);
    }
    // 全部 TCP 包（含握手/挥手）计入流包数；仅数据段参与重组与基线计算。
    group.packetIndexes.add(view.index);
    if (view.payload === null || view.payload.length === 0 || view.tcpSeq === null) continue;
    const forward = endpointSrc === group.endpoints[0];
    const side = group.sides[forward ? 0 : 1];
    side.segments.push({ rawSeq: view.tcpSeq, length: view.payload.length, packetIndex: view.index, bytes: view.payload });
    group.byteCount += view.payload.length;
  }

  // ---- 流重组 + HTTP 解析 + flag 定位 ----
  const sortedGroups = [...groups.values()].sort((left, right) => right.byteCount - left.byteCount);
  const streamTotal = sortedGroups.length;
  const streams: TcpStream[] = [];
  const transactions: HttpTransaction[] = [];
  // 未响应请求按流建栈：响应到达 O(1) 弹出配对（管线化语义 = 最新请求优先应答），
  // 避免"[...transactions].reverse().find()"在大量微报文下的 O(T²) 主线程冻结。
  const openRequests = new Map<number, HttpTransaction[]>();
  const flags: FlagHit[] = [];
  const flagSeen = new Set<string>();
  let httpTotal = 0;

  const pushFlag = (hit: { prefix: string; sample: string }, source: string) => {
    const dedupeKey = `${hit.prefix}|${hit.sample}|${source}`;
    if (flagSeen.has(dedupeKey)) return;
    flagSeen.add(dedupeKey);
    flags.push({ prefix: hit.prefix, sample: hit.sample, source });
  };

  for (const [streamIndex, group] of sortedGroups.entries()) {
    if (streamIndex >= MAX_STREAMS) break;
    const forward = reassembleDirection(group.sides[0]);
    const reverse = reassembleDirection(group.sides[1]);
    const truncated = forward.truncated || reverse.truncated;
    const stream: TcpStream = {
      id: streamIndex,
      endpointA: group.endpoints[0],
      endpointB: group.endpoints[1],
      packetCount: group.packetIndexes.size,
      byteCount: group.byteCount,
      bufferAtoB: forward.buffer,
      bufferBtoA: reverse.buffer,
      truncated,
      hasFlag: false,
      packetIndexes: [...group.packetIndexes].sort((left, right) => left - right),
    };

    const sideTexts: Array<{ direction: 'req' | 'res'; buffer: Uint8Array; offsets: DirectionBuffer['offsets'] }> = [
      { direction: 'req', buffer: forward.buffer, offsets: forward.offsets },
      { direction: 'res', buffer: reverse.buffer, offsets: reverse.offsets },
    ];

    for (const side of sideTexts) {
      const text = new TextDecoder('latin1').decode(side.buffer);
      const rawMessages = parseHttpDirection(text);
      for (const raw of rawMessages) {
        const bodyText = raw.chunkedText ?? text.slice(raw.bodyStart, raw.bodyEnd);
        const bodyBytes = raw.chunkedText !== null ? latin1Encode(raw.chunkedText) : new Uint8Array(side.buffer.slice(raw.bodyStart, raw.bodyEnd));
        const hits = detectFlagFormats(`${raw.startLine}\n${bodyText}`);
        const message: HttpMessage = {
          direction: raw.direction,
          streamId: stream.id,
          packetIndex: packetIndexOf(side.offsets, raw.offset),
          startLine: raw.startLine,
          method: raw.method,
          path: raw.path,
          query: raw.direction === 'req' ? decodeQuery(raw.path) : [],
          status: raw.status,
          headers: raw.headers,
          bodyBytes,
          bodyText,
          bodyTruncated: raw.bodyEnd - raw.bodyStart > 1024 * 1024,
          hasFlag: hits.length > 0,
        };
        httpTotal += 1;
        for (const hit of hits) pushFlag(hit, `HTTP ${raw.direction === 'req' ? '请求' : '响应'} · 包 #${message.packetIndex}`);
        if (hits.length > 0) stream.hasFlag = true;
        if (raw.direction === 'req') {
          const transaction: HttpTransaction = { streamId: stream.id, request: message, response: null };
          transactions.push(transaction);
          const queue = openRequests.get(stream.id);
          if (queue) queue.push(transaction);
          else openRequests.set(stream.id, [transaction]);
        } else {
          const queue = openRequests.get(stream.id);
          const pending = queue && queue.length > 0 ? queue[queue.length - 1] : undefined;
          if (pending) {
            queue!.pop();
            pending.response = message;
          } else {
            transactions.push({ streamId: stream.id, request: null, response: message });
          }
        }
      }
      const sideHits = detectFlagFormats(text);
      if (sideHits.length > 0) {
        stream.hasFlag = true;
        for (const hit of sideHits) pushFlag(hit, `TCP 流 #${stream.id}（${stream.endpointA} → ${stream.endpointB}，${side.direction === 'req' ? 'A→B' : 'B→A'}）`);
      }
    }
    streams.push(stream);
  }

  return { stats, streams, streamTotal, transactions, httpTotal, flags };
};
