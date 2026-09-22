// 协议剥离（批次 L）：Ethernet/VLAN → IPv4/IPv6（含基础扩展头）→ TCP/UDP/ICMP。
// 输入为 parser.ts 的 ParsedCapture，输出只读的包视图；payload 是帧内 subarray 引用。
import type { ParsedCapture } from './parser';

export type PacketProto = 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'ARP' | 'IPv6' | 'other';

export interface PacketView {
  index: number;
  tsSeconds: number;
  linkType: number;
  linkSupported: boolean;
  proto: PacketProto;
  src: string;
  dst: string;
  srcPort: number | null;
  dstPort: number | null;
  length: number;
  info: string;
  isHttpRequest: boolean;
  isHttpResponse: boolean;
  isDns: boolean;
  // TCP/UDP 载荷（帧内偏移切片）；无载荷为 null。
  payload: Uint8Array | null;
  tcpFlags: number | null;
  tcpSeq: number | null;
  // 整帧字节（原文件内 subarray 引用），供 hexdump 详情。
  frame: Uint8Array;
}

const LINK_ETHERNET = 1;
const ETH_TYPE_IPV4 = 0x0800;
const ETH_TYPE_IPV6 = 0x86dd;
const ETH_TYPE_ARP = 0x0806;
const ETH_TYPE_VLAN = 0x8100;
const ETH_TYPE_QINQ = 0x88a8;

const IP_PROTO_ICMP = 1;
const IP_PROTO_TCP = 6;
const IP_PROTO_UDP = 17;
const IP_PROTO_ICMPV6 = 58;

const TCP_FLAG_NAMES: Array<[number, string]> = [
  [0x02, 'SYN'], [0x10, 'ACK'], [0x01, 'FIN'], [0x04, 'RST'], [0x08, 'PSH'], [0x20, 'URG'],
];

const TCP_METHOD_PATTERN = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) /;
const HTTP_STATUS_PATTERN = /^HTTP\/1\.[01] \d{3}/;

const formatMac = (bytes: Uint8Array, offset: number): string =>
  Array.from(bytes.subarray(offset, offset + 6), byte => byte.toString(16).padStart(2, '0')).join(':');

const formatIpv4 = (bytes: Uint8Array, offset: number): string =>
  Array.from(bytes.subarray(offset, offset + 4), byte => String(byte)).join('.');

const formatIpv6 = (bytes: Uint8Array, offset: number): string => {
  const groups: string[] = [];
  for (let index = 0; index < 8; index += 1) {
    groups.push(((bytes[offset + index * 2] << 8) | bytes[offset + index * 2 + 1]).toString(16));
  }
  // RFC 5952：最长全零段压缩为 ::（仅压缩一段，避免歧义）。
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    if (index < groups.length && groups[index] === '0') {
      if (runStart < 0) runStart = index;
    } else if (runStart >= 0) {
      if (index - runStart > bestLength) {
        bestLength = index - runStart;
        bestStart = runStart;
      }
      runStart = -1;
    }
  }
  if (bestLength >= 2) {
    groups.splice(bestStart, bestLength, ':');
  }
  return groups.join(':').replace(/:::/, '::').replace(/^:($|:)/, '::');
};

const tcpFlagsText = (flags: number): string =>
  TCP_FLAG_NAMES.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name).join(', ') || '-';

const icmpSummary = (type: number, code: number): string => {
  if (type === 8 && code === 0) return 'Echo (ping) request';
  if (type === 0 && code === 0) return 'Echo (ping) reply';
  if (type === 3) return 'Destination unreachable';
  if (type === 11) return 'Time exceeded';
  return `type=${type} code=${code}`;
};

// 以 IP 头声明的总长收尾，避免以太网 padding 被当作载荷。
const trimPayloadByIpTotal = (data: Uint8Array, l4Offset: number, ipTotalLength: number, ipHeaderLength: number): Uint8Array => {
  const end = Math.min(data.length, l4Offset + Math.max(0, ipTotalLength - ipHeaderLength));
  return end > l4Offset ? data.subarray(l4Offset, end) : data.subarray(l4Offset, l4Offset);
};

// IPv6 扩展头跳过：hop-by-hop/routing/dest opts 长度 = 8 + hdr_ext_len*8，AH = 4*(len+2)，fragment 固定 8。
const ipv6NextHeader = (data: Uint8Array, offset: number, initial: number, limit: number): { proto: number; l4Offset: number } => {
  let proto = initial;
  let cursor = offset;
  for (let hop = 0; hop < 8; hop += 1) {
    if (proto === 0 || proto === 60 || proto === 43) {
      if (cursor + 2 > limit) return { proto: -1, l4Offset: cursor };
      proto = data[cursor];
      cursor += 8 + data[cursor + 1] * 8;
    } else if (proto === 51) {
      if (cursor + 2 > limit) return { proto: -1, l4Offset: cursor };
      proto = data[cursor];
      cursor += (data[cursor + 1] + 2) * 4;
    } else if (proto === 44) {
      if (cursor + 8 > limit) return { proto: -1, l4Offset: cursor };
      proto = data[cursor];
      cursor += 8;
    } else {
      return { proto, l4Offset: cursor };
    }
  }
  return { proto: -1, l4Offset: cursor };
};

interface BuildOutcome {
  proto: PacketProto;
  src: string;
  dst: string;
  srcPort: number | null;
  dstPort: number | null;
  info: string;
  payload: Uint8Array | null;
  tcpFlags: number | null;
  tcpSeq: number | null;
  isHttpRequest: boolean;
  isHttpResponse: boolean;
}

const none: BuildOutcome = {
  proto: 'other', src: '-', dst: '-', srcPort: null, dstPort: null,
  info: '', payload: null, tcpFlags: null, tcpSeq: null, isHttpRequest: false, isHttpResponse: false,
};

const decodeHead = (payload: Uint8Array, maxBytes: number): string =>
  new TextDecoder('latin1').decode(payload.subarray(0, Math.min(payload.length, maxBytes)));

const firstLine = (payload: Uint8Array): string => {
  const text = decodeHead(payload, 96);
  const lineEnd = text.indexOf('\r');
  return (lineEnd > 0 ? text.slice(0, lineEnd) : text).slice(0, 72);
};

const parseFrame = (data: Uint8Array): BuildOutcome => {
  if (data.length < 14) return { ...none, info: data.length ? `过短帧（${data.length} 字节）` : '空帧' };
  let ethertype = (data[12] << 8) | data[13];
  let cursor = 14;
  for (let vlan = 0; vlan < 2 && (ethertype === ETH_TYPE_VLAN || ethertype === ETH_TYPE_QINQ); vlan += 1) {
    if (cursor + 4 > data.length) return { ...none, info: 'VLAN 头截断' };
    ethertype = (data[cursor + 2] << 8) | data[cursor + 3];
    cursor += 4;
  }
  if (ethertype === ETH_TYPE_ARP) {
    return { ...none, proto: 'ARP', src: formatMac(data, 6), dst: formatMac(data, 0), info: data.length >= cursor + 28 ? 'ARP' : 'ARP（截断）' };
  }
  if (ethertype !== ETH_TYPE_IPV4 && ethertype !== ETH_TYPE_IPV6) {
    return { ...none, src: formatMac(data, 6), dst: formatMac(data, 0), info: `EtherType 0x${ethertype.toString(16).padStart(4, '0')}` };
  }
  if (ethertype === ETH_TYPE_IPV4) {
    if (cursor + 20 > data.length) return { ...none, src: formatMac(data, 6), dst: formatMac(data, 0), info: 'IPv4 头截断' };
    const ihl = (data[cursor] & 0x0f) * 4;
    if (ihl < 20) return { ...none, src: formatMac(data, 6), dst: formatMac(data, 0), info: `IPv4 IHL 非法（${ihl}）` };
    const totalLength = (data[cursor + 2] << 8) | data[cursor + 3];
    const fragmentOffset = ((data[cursor + 6] << 8) | data[cursor + 7]) & 0x1fff;
    const protocol = data[cursor + 9];
    const srcIp = formatIpv4(data, cursor + 12);
    const dstIp = formatIpv4(data, cursor + 16);
    const l4 = cursor + ihl;
    const base = { src: srcIp, dst: dstIp, srcPort: null as number | null, dstPort: null as number | null, tcpFlags: null as number | null };
    if (fragmentOffset > 0) {
      return { ...none, ...base, proto: 'other', info: `IPv4 分片 offset=${fragmentOffset * 8}（不重组）` };
    }
    if (protocol === IP_PROTO_TCP && l4 + 20 <= data.length) {
      const srcPort = (data[l4] << 8) | data[l4 + 1];
      const dstPort = (data[l4 + 2] << 8) | data[l4 + 3];
      const seq = ((data[l4 + 4] << 24) | (data[l4 + 5] << 16) | (data[l4 + 6] << 8) | data[l4 + 7]) >>> 0;
      const flags = data[l4 + 13];
      const headerLength = ((data[l4 + 12] >> 4) & 0x0f) * 4;
      const payloadStart = headerLength >= 20 ? l4 + headerLength : l4 + 20;
      const trimmed = trimPayloadByIpTotal(data, payloadStart, totalLength || data.length, ihl + (headerLength >= 20 ? headerLength : 20));
      // 无数据包（SYN/纯 ACK）载荷置 null：流重组与 HTTP 解析都据此跳过。
      const payload = trimmed.length > 0 ? trimmed : null;
      const head = payload ? decodeHead(payload, 16) : '';
      const isHttpRequest = head.length >= 4 && TCP_METHOD_PATTERN.test(head);
      const isHttpResponse = head.length >= 12 && HTTP_STATUS_PATTERN.test(head);
      const info = payload && (isHttpRequest || isHttpResponse) ? firstLine(payload) : `${tcpFlagsText(flags)}, seq ${seq}`;
      return { ...none, ...base, srcPort, dstPort, proto: 'TCP', info, payload, tcpFlags: flags, tcpSeq: seq, isHttpRequest, isHttpResponse };
    }
    if (protocol === IP_PROTO_UDP && l4 + 8 <= data.length) {
      const srcPort = (data[l4] << 8) | data[l4 + 1];
      const dstPort = (data[l4 + 2] << 8) | data[l4 + 3];
      const payload = trimPayloadByIpTotal(data, l4 + 8, totalLength || data.length, ihl + 8);
      return {
        ...none, ...base, srcPort, dstPort, proto: 'UDP', payload,
        info: srcPort === 53 || dstPort === 53 ? 'DNS' : `${payload.length} 字节载荷`,
      };
    }
    if (protocol === IP_PROTO_ICMP && l4 + 4 <= data.length) {
      return { ...none, ...base, proto: 'ICMP', info: icmpSummary(data[l4], data[l4 + 1]) };
    }
    return { ...none, ...base, proto: 'other', info: `IPv4 协议号 ${protocol}` };
  }
  // IPv6
  if (cursor + 40 > data.length) return { ...none, src: formatMac(data, 6), dst: formatMac(data, 0), info: 'IPv6 头截断' };
  const nextHeader = data[cursor + 6];
  const payloadLength = (data[cursor + 4] << 8) | data[cursor + 5];
  const srcIp = formatIpv6(data, cursor + 8);
  const dstIp = formatIpv6(data, cursor + 24);
  const limit = payloadLength > 0 ? Math.min(data.length, cursor + 40 + payloadLength) : data.length;
  const base = { src: srcIp, dst: dstIp, srcPort: null as number | null, dstPort: null as number | null, tcpFlags: null as number | null };
  const { proto, l4Offset } = ipv6NextHeader(data, cursor + 40, nextHeader, limit);
  if (proto === IP_PROTO_TCP && l4Offset + 20 <= data.length) {
    const srcPort = (data[l4Offset] << 8) | data[l4Offset + 1];
    const dstPort = (data[l4Offset + 2] << 8) | data[l4Offset + 3];
    const seq = ((data[l4Offset + 4] << 24) | (data[l4Offset + 5] << 16) | (data[l4Offset + 6] << 8) | data[l4Offset + 7]) >>> 0;
    const flags = data[l4Offset + 13];
    const headerLength = ((data[l4Offset + 12] >> 4) & 0x0f) * 4;
    const payloadStart = headerLength >= 20 ? l4Offset + headerLength : l4Offset + 20;
    const trimmedV6 = data.subarray(payloadStart, limit);
    const payload = trimmedV6.length > 0 ? trimmedV6 : null;
    const headV6 = payload ? decodeHead(payload, 16) : '';
    const isHttpRequestV6 = headV6.length >= 4 && TCP_METHOD_PATTERN.test(headV6);
    const isHttpResponseV6 = headV6.length >= 12 && HTTP_STATUS_PATTERN.test(headV6);
    const infoV6 = isHttpRequestV6 || isHttpResponseV6 ? firstLine(payload!) : `${tcpFlagsText(flags)}, seq ${seq}`;
    return { ...none, ...base, srcPort, dstPort, proto: 'TCP', payload, tcpFlags: flags, tcpSeq: seq, info: infoV6, isHttpRequest: isHttpRequestV6, isHttpResponse: isHttpResponseV6 };
  }
  if (proto === IP_PROTO_UDP && l4Offset + 8 <= data.length) {
    const srcPort = (data[l4Offset] << 8) | data[l4Offset + 1];
    const dstPort = (data[l4Offset + 2] << 8) | data[l4Offset + 3];
    return { ...none, ...base, srcPort, dstPort, proto: 'UDP', payload: data.subarray(l4Offset + 8, limit), info: 'UDPv6' };
  }
  if (proto === IP_PROTO_ICMPV6 && l4Offset + 4 <= data.length) {
    return { ...none, ...base, proto: 'ICMPv6', info: icmpSummary(data[l4Offset], data[l4Offset + 1]) };
  }
  return { ...none, ...base, proto: 'IPv6', info: `IPv6 next header ${nextHeader}` };
};

export const buildPacketViews = (capture: ParsedCapture): PacketView[] => {
  return capture.packets.map(packet => {
    const supported = packet.linkType === LINK_ETHERNET;
    const decoded = supported && packet.capturedLen > 0 ? parseFrame(packet.data) : null;
    return {
      index: packet.index,
      tsSeconds: packet.tsSeconds,
      linkType: packet.linkType,
      linkSupported: supported,
      proto: decoded?.proto ?? 'other',
      src: decoded?.src ?? '-',
      dst: decoded?.dst ?? '-',
      srcPort: decoded?.srcPort ?? null,
      dstPort: decoded?.dstPort ?? null,
      length: packet.originalLen,
      info: supported
        ? decoded?.info || ''
        : `链路层类型 ${packet.linkType}（仅支持 Ethernet，未解析）`,
      isHttpRequest: decoded?.isHttpRequest ?? false,
      isHttpResponse: decoded?.isHttpResponse ?? false,
      isDns: decoded?.proto === 'UDP' && (decoded.srcPort === 53 || decoded.dstPort === 53),
      payload: decoded?.payload ?? null,
      tcpFlags: decoded?.tcpFlags ?? null,
      tcpSeq: decoded?.tcpSeq ?? null,
      frame: packet.data,
    };
  });
};
