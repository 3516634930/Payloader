// 批次 L 流量分析域引擎测试：全部抓包样本程序化自造（无外部 fixture、无网络依赖），
// 逐条验证容器解析、协议剥离、流重组、HTTP 提取、flag 定位与限量/损坏容错。
// 加载方式统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

// 加载方式统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛：同一加载语义只写一遍）。
const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();

const parser = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'parser.ts'));
const protocols = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'protocols.ts'));
const analyze = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'analyze.ts'));

// ---- 样本构造工具（按规范手工拼字节） ----

const u16be = value => Uint8Array.from([(value >> 8) & 0xff, value & 0xff]);
const u32be = value => Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
const u32le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
const u16le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
const ipToBytes = dotted => Uint8Array.from(dotted.split('.').map(Number));
const ascii = text => Uint8Array.from(Buffer.from(text, 'latin1'));
const concat = parts => {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const MAC = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

const ethFrame = (payload, ethertype = 0x0800) => concat([Uint8Array.from(MAC), Uint8Array.from(MAC, byte => byte + 1), u16be(ethertype), payload]);

const ipv4Packet = (protocol, srcIp, dstIp, payload, ident = 1) => {
  const header = concat([
    Uint8Array.from([0x45, 0x00]),
    u16be(20 + payload.length),
    u16be(ident),
    u16be(0x4000),
    Uint8Array.from([64, protocol, 0, 0]),
    ipToBytes(srcIp),
    ipToBytes(dstIp),
  ]);
  return concat([header, payload]);
};

const tcpSegment = (seq, ack, flags, sport, dport, payload) => concat([
  u16be(sport),
  u16be(dport),
  u32be(seq),
  u32be(ack),
  Uint8Array.from([0x50, flags]),
  u16be(0x2000),
  u16be(0),
  u16be(0),
  payload,
]);

const udpDatagram = (sport, dport, payload) => concat([u16be(sport), u16be(dport), u16be(8 + payload.length), u16be(0), payload]);

const icmpMessage = (type, code) => concat([Uint8Array.from([type, code, 0, 0, 0, 0, 0, 0])]);

const CLIENT = '192.168.1.10';
const SERVER = '93.184.216.34';
const SPORT = 51000;
const DPORT = 80;

// 标准 HTTP 会话：握手 3 包 + GET + 200 响应 + FIN。
const httpSessionFrames = (flagText, method = 'GET', target = '/flag.html') => {
  const request = `${method} ${target} HTTP/1.1\r\nHost: ctf.example\r\nUser-Agent: ctf\r\n\r\n`;
  const body = flagText;
  const response = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
  const syn = ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(1000, 0, 0x02, SPORT, DPORT, Buffer.alloc(0))));
  const synAck = ethFrame(ipv4Packet(6, SERVER, CLIENT, tcpSegment(5000, 1001, 0x12, DPORT, SPORT, Buffer.alloc(0))));
  const ack = ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(1001, 5001, 0x10, SPORT, DPORT, Buffer.alloc(0))));
  const get = ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(1001, 5001, 0x18, SPORT, DPORT, ascii(request))));
  const resp = ethFrame(ipv4Packet(6, SERVER, CLIENT, tcpSegment(5001, 1001 + request.length, 0x18, DPORT, SPORT, ascii(response))));
  const fin = ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(1001 + request.length, 5001 + response.length, 0x11, SPORT, DPORT, Buffer.alloc(0))));
  return { syn, synAck, ack, get, resp, fin, request, response };
};

const pcapFromFrames = (frames, { little = true, nanosecond = false, linkType = 1, tsSec = 1700000000, tsFrac = 0 } = {}) => {
  const magic = nanosecond ? (little ? [0x4d, 0x3c, 0xb2, 0xa1] : [0xa1, 0xb2, 0x3c, 0x4d]) : little ? [0xd4, 0xc3, 0xb2, 0xa1] : [0xa1, 0xb2, 0xc3, 0xd4];
  const header = concat([
    Uint8Array.from(magic),
    u16(2, little),
    u16(4, little),
    u32(0, little),
    u32(0, little),
    u32(262144, little),
    u32(linkType, little),
  ]);
  const records = frames.map(frame => concat([u32(tsSec, little), u32(tsFrac, little), u32(frame.length, little), u32(frame.length, little), frame]));
  return concat([header, ...records]);
};
const u16 = (value, little) => (little ? u16le(value) : u16be(value));
const u32 = (value, little) => (little ? u32le(value) : u32be(value));

const pcapngBlocks = {
  // 块类型号按文件自身字节序编码（SHB 类型 0x0a0d0d0a 是回文，两种字节序字节相同）。
  // section_length 惯例写全 1（未指定）：按高低两个 32 位拆开写，避免 64 位字面量精度丢失。
  shb: littleEndian => concat([u32be(0x0a0d0d0a), u32(28, littleEndian), u32(0x1a2b3c4d, littleEndian), u16(1, littleEndian), u16(0, littleEndian), u64(0xffffffff, 0xffffffff, littleEndian), u32(28, littleEndian)]),
  idb: (littleEndian, linkType = 1, tsresol = null) => {
    const options = tsresol === null ? Buffer.alloc(0) : concat([u16(9, littleEndian), u16(1, littleEndian), Uint8Array.from([tsresol, 0, 0, 0])]);
    const padded = options.length % 4 ? concat([options, Buffer.alloc(4 - (options.length % 4))]) : options;
    const body = concat([u16(linkType, littleEndian), u16(0, littleEndian), u32(262144, littleEndian), padded, u16(0, littleEndian), u16(0, littleEndian)]);
    const total = 12 + body.length;
    return concat([u32(0x00000001, littleEndian), u32(total, littleEndian), body, u32(total, littleEndian)]);
  },
  epb: (littleEndian, interfaceId, timestamp, data, originalLen = null) => {
    // 时间戳 raw 值可超 Number.MAX_SAFE_INTEGER，用 BigInt 拆高低位保证精确。
    const raw = typeof timestamp === 'bigint' ? timestamp : BigInt(Math.round(timestamp));
    const tsHigh = Number(raw >> 32n);
    const tsLow = Number(raw & 0xffffffffn);
    const pad = (4 - (data.length % 4)) % 4;
    const body = concat([
      u32(interfaceId, littleEndian),
      u32(tsHigh, littleEndian),
      u32(tsLow, littleEndian),
      u32(data.length, littleEndian),
      u32(originalLen === null ? data.length : originalLen, littleEndian),
      data,
      Buffer.alloc(pad),
      u16(0, littleEndian),
      u16(0, littleEndian),
    ]);
    const total = 12 + body.length;
    return concat([u32(0x00000006, littleEndian), u32(total, littleEndian), body, u32(total, littleEndian)]);
  },
};
const u64 = (high, low, littleEndian) => (littleEndian ? concat([u32le(low), u32le(high)]) : concat([u32be(high), u32be(low)]));

const parseAndAnalyze = (bytes, options) => {
  const capture = parser.parseCapture(bytes, options);
  const views = protocols.buildPacketViews(capture);
  const analysis = analyze.analyzeCapture(views);
  return { capture, views, analysis };
};

// ---- 容器层：pcap ----

test('pcap 小端微秒：HTTP 会话包数、时间戳与全局头字段', () => {
  const { syn, synAck, ack, get, resp, fin } = httpSessionFrames('flag{pcap_easy_123}');
  const bytes = pcapFromFrames([syn, synAck, ack, get, resp, fin], { tsSec: 1700000000, tsFrac: 123456 });
  const { capture } = parseAndAnalyze(bytes);
  assert.equal(capture.format, 'pcap');
  assert.equal(capture.byteOrder, 'le');
  assert.equal(capture.nanosecond, false);
  assert.equal(capture.linkType, 1);
  assert.equal(capture.packets.length, 6);
  assert.equal(capture.truncated, false);
  assert.equal(capture.corrupt, null);
  assert.equal(capture.packets[3].tsSeconds, 1700000000.123456);
});

test('pcap 大端：字节序正确翻转', () => {
  const frame = ethFrame(ipv4Packet(1, '10.0.0.1', '10.0.0.2', icmpMessage(8, 0)));
  const bytes = pcapFromFrames([frame], { little: false });
  const { capture, views } = parseAndAnalyze(bytes);
  assert.equal(capture.byteOrder, 'be');
  assert.equal(capture.packets.length, 1);
  assert.equal(views[0].proto, 'ICMP');
});

test('pcap 纳秒精度（0xa1b23c4d 家族）', () => {
  const frame = ethFrame(ipv4Packet(17, '10.0.0.1', '10.0.0.2', udpDatagram(40000, 53, ascii('dnspayload'))));
  const bytes = pcapFromFrames([frame], { nanosecond: true, tsSec: 1700000001, tsFrac: 999999999 });
  const { capture, views } = parseAndAnalyze(bytes);
  assert.equal(capture.nanosecond, true);
  assert.ok(Math.abs(capture.packets[0].tsSeconds - (1700000001 + 0.999999999)) < 1e-9);
  assert.equal(views[0].proto, 'UDP');
  assert.equal(views[0].isDns, true);
});

// ---- 协议剥离 ----

test('包列表字段：五元组、长度与 TCP 摘要', () => {
  const { syn, get } = httpSessionFrames('flag{x}');
  const { capture, views } = parseAndAnalyze(pcapFromFrames([syn, get]));
  assert.equal(views[0].proto, 'TCP');
  assert.equal(views[0].src, CLIENT);
  assert.equal(views[0].dst, SERVER);
  assert.equal(views[0].srcPort, SPORT);
  assert.equal(views[0].dstPort, DPORT);
  assert.equal(views[0].length, syn.length);
  assert.match(views[0].info, /SYN, seq 1000/);
  assert.equal(views[1].isHttpRequest, true);
  assert.match(views[1].info, /GET \/flag\.html/);
  assert.equal(capture.packets.length, 2);
});

test('IPv6 地址压缩与 TCP 剥离', () => {
  const srcIp = concat([Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])]);
  const dstIp = concat([Uint8Array.from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01])]);
  const ipv6 = concat([
    Uint8Array.from([0x60, 0x00, 0x00, 0x00]),
    u16be(38),
    Uint8Array.from([6, 64]),
    srcIp,
    dstIp,
    tcpSegment(7, 8, 0x18, 40000, 80, ascii('GET / HTTP/1.1\r\n\r\n')),
  ]);
  const { views } = parseAndAnalyze(pcapFromFrames([ethFrame(ipv6, 0x86dd)]));
  assert.equal(views[0].proto, 'TCP');
  assert.equal(views[0].src, '::1');
  assert.equal(views[0].dst, '2001:db8::1');
  assert.equal(views[0].isHttpRequest, true);
});

test('VLAN 与 ARP 帧', () => {
  const vlanFrame = ethFrame(concat([u16be(10), u16be(0x0800), ipv4Packet(17, '10.0.0.1', '10.0.0.2', udpDatagram(53, 53, ascii('x')))]), 0x8100);
  const arp = ethFrame(concat([u16be(1), u16be(0x0800), Uint8Array.from([6, 4, 0, 1]), Uint8Array.from(MAC), ipToBytes('10.0.0.1'), Uint8Array.from([0, 0, 0, 0, 0, 0]), ipToBytes('10.0.0.2'), Buffer.alloc(18)]), 0x0806);
  const { views } = parseAndAnalyze(pcapFromFrames([vlanFrame, arp]));
  assert.equal(views[0].proto, 'UDP');
  assert.equal(views[1].proto, 'ARP');
});

// ---- 流重组与 HTTP ----

test('TCP 流重组：HTTP 事务、参数与 flag 提取', () => {
  const { syn, synAck, ack, get, resp, fin } = httpSessionFrames('flag{pcap_easy_123}', 'GET', '/search?q=flag%20me&page=2');
  const { capture, views, analysis } = parseAndAnalyze(pcapFromFrames([syn, synAck, ack, get, resp, fin]));
  assert.equal(analysis.streams.length, 1);
  const stream = analysis.streams[0];
  assert.equal(stream.endpointA, `${CLIENT}:${SPORT}`);
  assert.equal(stream.endpointB, `${SERVER}:80`);
  assert.equal(stream.packetCount, 6);
  assert.equal(analysis.transactions.length, 1);
  const transaction = analysis.transactions[0];
  assert.equal(transaction.request.method, 'GET');
  assert.equal(transaction.request.path, '/search?q=flag%20me&page=2');
  // query 数组产自 vm 沙箱 realm，deepEqual 跨 realm 误判，用 JSON 比较。
  assert.equal(JSON.stringify(transaction.request.query), JSON.stringify([['q', 'flag me'], ['page', '2']]));
  assert.equal(transaction.response.status, 200);
  assert.equal(transaction.response.bodyText, 'flag{pcap_easy_123}');
  assert.equal(transaction.response.hasFlag, true);
  assert.ok(analysis.flags.some(hit => hit.source.includes('HTTP 响应') && hit.sample === 'flag{pcap_easy_123}'));
  const statMap = Object.fromEntries(analysis.stats.map(row => [row.key, row.count]));
  assert.equal(statMap.TCP, 6);
  assert.equal(statMap.HTTP, 2);
  assert.equal(capture.packets.length, views.length);
});

test('流重组乱序到达：按 seq 而非到达顺序拼接', () => {
  const head = 'HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nflag{';
  const part1 = ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(5001, 2000, 0x18, DPORT, SPORT, ascii(head))));
  const part2 = ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(5001 + head.length, 2000, 0x18, DPORT, SPORT, ascii('out_of_ord'))));
  // 到达顺序故意颠倒：先到后段（seq 更大）。
  const { analysis } = parseAndAnalyze(pcapFromFrames([part2, part1]));
  assert.equal(analysis.transactions.length, 1);
  assert.equal(analysis.transactions[0].response.bodyText, 'flag{out_of_ord');
});

test('chunked 响应体解码', () => {
  const request = 'GET /chunk HTTP/1.1\r\nHost: ctf.example\r\n\r\n';
  // chunk 长度为十六进制：'flag{' 5 字符 = 0x5、'chunked!!}' 10 字符 = 0xa。
  const response = 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nflag{\r\na\r\nchunked!!}\r\n0\r\n\r\n';
  const get = ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(1001, 5001, 0x18, SPORT, DPORT, ascii(request))));
  const resp = ethFrame(ipv4Packet(6, SERVER, CLIENT, tcpSegment(5001, 1001 + request.length, 0x18, DPORT, SPORT, ascii(response))));
  const { analysis } = parseAndAnalyze(pcapFromFrames([get, resp]));
  assert.equal(analysis.transactions.length, 1);
  assert.equal(analysis.transactions[0].response.bodyText, 'flag{chunked!!}');
  assert.equal(analysis.transactions[0].response.hasFlag, true);
});

test('POST 请求体 flag 与多条事务配对', () => {
  const req1 = 'POST /submit HTTP/1.1\r\nHost: ctf.example\r\nContent-Length: 18\r\n\r\nanswer=flag{post1}';
  const resp1 = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok';
  const seqBase = 1001;
  const get1 = ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(seqBase, 5001, 0x18, SPORT, DPORT, ascii(req1))));
  const r1 = ethFrame(ipv4Packet(6, SERVER, CLIENT, tcpSegment(5001, seqBase + req1.length, 0x18, DPORT, SPORT, ascii(resp1))));
  const { analysis } = parseAndAnalyze(pcapFromFrames([get1, r1]));
  assert.equal(analysis.transactions.length, 1);
  assert.equal(analysis.transactions[0].request.bodyText, 'answer=flag{post1}');
  assert.ok(analysis.flags.some(hit => hit.sample === 'flag{post1}'));
});

test('多条流按字节量排序且 HTTP 分流归属正确', () => {
  const { syn, synAck, ack, get, resp } = httpSessionFrames('flag{two_streams}', 'GET', '/a');
  const other = ethFrame(ipv4Packet(6, '10.0.0.9', '10.0.0.8', tcpSegment(1, 2, 0x18, 1234, 8080, ascii('A'.repeat(200)))));
  const { analysis } = parseAndAnalyze(pcapFromFrames([syn, synAck, ack, get, resp, other]));
  assert.equal(analysis.streamTotal, 2);
  assert.equal(analysis.streams.length, 2);
  // 字节量多的流排前：other（200 字节）领先 HTTP 会话。
  assert.equal(analysis.streams[0].endpointA, '10.0.0.8:8080');
  assert.equal(analysis.streams[0].byteCount >= analysis.streams[1].byteCount, true);
});

// ---- pcapng ----

test('pcapng：SHB/IDB/EPB、跨段响应重组与 flag', () => {
  const request = 'GET /ng HTTP/1.1\r\nHost: ctf.example\r\n\r\n';
  const body = 'flag{pcapng_99}';
  const head = `HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n`;
  const responsePart1 = head + body.slice(0, 8);
  const responsePart2 = body.slice(8);
  const blocks = [
    pcapngBlocks.shb(true),
    pcapngBlocks.idb(true, 1, 6),
    pcapngBlocks.epb(true, 0, 1234567890, ethFrame(ipv4Packet(6, CLIENT, SERVER, tcpSegment(1001, 5001, 0x18, SPORT, DPORT, ascii(request))))),
    pcapngBlocks.epb(true, 0, 1234567900, ethFrame(ipv4Packet(6, SERVER, CLIENT, tcpSegment(5001, 1001 + request.length, 0x18, DPORT, SPORT, ascii(responsePart1))))),
    pcapngBlocks.epb(true, 0, 1234567910, ethFrame(ipv4Packet(6, SERVER, CLIENT, tcpSegment(5001 + responsePart1.length, 2000, 0x18, DPORT, SPORT, ascii(responsePart2))))),
  ];
  const { capture, analysis } = parseAndAnalyze(concat(blocks));
  assert.equal(capture.format, 'pcapng');
  assert.equal(capture.packets.length, 3);
  assert.equal(capture.linkType, 1);
  assert.equal(analysis.transactions.length, 1);
  assert.equal(analysis.transactions[0].response.bodyText, body);
  assert.equal(analysis.transactions[0].response.hasFlag, true);
  assert.ok(analysis.flags.some(hit => hit.sample === body));
});

test('大端 pcapng 与 if_tsresol 纳秒时间戳', () => {
  const frame = ethFrame(ipv4Packet(1, '10.0.0.1', '10.0.0.2', icmpMessage(8, 0)));
  const blocks = [
    pcapngBlocks.shb(false),
    pcapngBlocks.idb(false, 1, 9),
    pcapngBlocks.epb(false, 0, 1700000001500000000n, frame),
  ];
  const { capture } = parseAndAnalyze(concat(blocks));
  assert.equal(capture.format, 'pcapng');
  assert.equal(capture.byteOrder, 'be');
  assert.ok(Math.abs(capture.packets[0].tsSeconds - 1700000001.5) < 1e-6);
});

// ---- 统计与扫描 ----

test('协议统计：UDP/DNS/ICMP 分类计数', () => {
  const dns = ethFrame(ipv4Packet(17, '10.0.0.1', '10.0.0.2', udpDatagram(40000, 53, ascii('querydata'))));
  const plainUdp = ethFrame(ipv4Packet(17, '10.0.0.1', '10.0.0.2', udpDatagram(40001, 9000, ascii('otherdata'))));
  const ping = ethFrame(ipv4Packet(1, '10.0.0.1', '10.0.0.2', icmpMessage(8, 0)));
  const { analysis } = parseAndAnalyze(pcapFromFrames([dns, plainUdp, ping]));
  const statMap = Object.fromEntries(analysis.stats.map(row => [row.key, row.count]));
  assert.equal(statMap.UDP, 2);
  assert.equal(statMap.DNS, 1);
  assert.equal(statMap.ICMP, 1);
});

test('链路层不支持时给出提示而不崩溃', () => {
  const bytes = pcapFromFrames([Buffer.alloc(60)], { linkType: 113 });
  const { views } = parseAndAnalyze(bytes);
  assert.equal(views[0].linkSupported, false);
  assert.match(views[0].info, /113/);
});

// ---- 限量与损坏容错 ----

test('包数限量：达到上限停止并标记 truncated', () => {
  const frame = ethFrame(ipv4Packet(1, '10.0.0.1', '10.0.0.2', icmpMessage(8, 0)));
  const bytes = pcapFromFrames(Array.from({ length: 5 }, () => frame));
  const capture = parser.parseCapture(bytes, { maxPackets: 3 });
  const views = protocols.buildPacketViews(capture);
  assert.equal(capture.packets.length, 3);
  assert.equal(capture.truncated, true);
  assert.equal(views.length, 3);
});

test('损坏 pcap：记录头声明长度非法时停止且不抛异常', () => {
  const frame = ethFrame(ipv4Packet(1, '10.0.0.1', '10.0.0.2', icmpMessage(8, 0)));
  const goodBytes = pcapFromFrames([frame]);
  const badRecord = concat([u32le(1700000000), u32le(0), u32le(0xfffffff0), u32le(0xfffffff0)]);
  const { capture } = parseAndAnalyze(concat([goodBytes, badRecord]));
  assert.equal(capture.packets.length, 1);
  assert.notEqual(capture.corrupt, null);
  assert.equal(capture.corrupt.packetIndex, 1);
});

test('损坏 pcapng：块尾长度不一致时停止', () => {
  const shb = pcapngBlocks.shb(true);
  const broken = concat([u32be(0x00000001), u32le(40), Buffer.alloc(24), u32le(999)]);
  const { capture } = parseAndAnalyze(concat([shb, broken]));
  assert.equal(capture.packets.length, 0);
  assert.notEqual(capture.corrupt, null);
});

test('随机字节：无法识别为抓包文件', () => {
  const { capture } = parseAndAnalyze(ascii('this is not a capture file at all........'));
  assert.equal(capture.packets.length, 0);
  assert.notEqual(capture.corrupt, null);
  assert.match(capture.corrupt.reason, /无法识别/);
});

test('截断文件：包数据中途结束', () => {
  const frame = ethFrame(ipv4Packet(1, '10.0.0.1', '10.0.0.2', icmpMessage(8, 0)));
  const full = pcapFromFrames([frame, frame]);
  const { capture } = parseAndAnalyze(full.subarray(0, full.length - 5));
  assert.equal(capture.packets.length, 1);
  assert.notEqual(capture.corrupt, null);
  assert.match(capture.corrupt.reason, /截断/);
});
