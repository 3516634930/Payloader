// 批次 L 浏览器实测样本生成器：与 tests/pcap-analysis.test.mjs 同规范手工构造字节。
// 产出到 audit-workspace/pcap-samples/，供流量分析工作区实测（拖入验证）。
import fs from 'node:fs';
import path from 'node:path';

const outDir = path.resolve('audit-workspace', 'pcap-samples');
fs.mkdirSync(outDir, { recursive: true });

const u16be = value => Uint8Array.from([(value >> 8) & 0xff, value & 0xff]);
const u32be = value => Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
const u16le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
const u32le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
const u16 = (v, le) => (le ? u16le(v) : u16be(v));
const u32 = (v, le) => (le ? u32le(v) : u32be(v));
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
const ethFrame = (payload, ethertype = 0x0800) => concat([Uint8Array.from(MAC), Uint8Array.from(MAC.map(b => b + 1)), u16be(ethertype), payload]);
const ip4 = (proto, src, dst, payload) => concat([
  Uint8Array.from([0x45, 0]),
  u16be(20 + payload.length),
  u16be(1),
  u16be(0x4000),
  Uint8Array.from([64, proto, 0, 0]),
  Uint8Array.from(src.split('.').map(Number)),
  Uint8Array.from(dst.split('.').map(Number)),
  payload,
]);
const tcpSeg = (seq, ack, flags, sport, dport, payload) => concat([
  u16be(sport), u16be(dport), u32be(seq), u32be(ack),
  Uint8Array.from([0x50, flags]), u16be(0x2000), u16be(0), u16be(0), payload,
]);
const udpDatagram = (sport, dport, payload) => concat([u16be(sport), u16be(dport), u16be(8 + payload.length), u16be(0), payload]);
const icmpMsg = (type, code) => Uint8Array.from([type, code, 0, 0, 0, 0, 0, 0]);

const CLIENT = '192.168.1.10';
const SERVER = '93.184.216.34';
const SPORT = 51000;
const DPORT = 80;

const pcapFile = (frames, { little = true, linkType = 1 } = {}) => {
  const header = concat([
    Uint8Array.from(little ? [0xd4, 0xc3, 0xb2, 0xa1] : [0xa1, 0xb2, 0xc3, 0xd4]),
    u16(2, little), u16(4, little), u32(0, little), u32(0, little), u32(262144, little), u32(linkType, little),
  ]);
  let tsSec = 1700000000;
  const records = frames.map(frame => concat([u32(tsSec++, little), u32(123456, little), u32(frame.length, little), u32(frame.length, little), frame]));
  return concat([header, ...records]);
};

const shb = le => concat([u32be(0x0a0d0d0a), u32(28, le), u32(0x1a2b3c4d, le), u16(1, le), u16(0, le), concat(le ? [u32le(0xffffffff), u32le(0xffffffff)] : [u32be(0xffffffff), u32be(0xffffffff)]), u32(28, le)]);
const idb = (le, linkType = 1) => {
  const body = concat([u16(linkType, le), u16(0, le), u32(262144, le), u16(0, le), u16(0, le)]);
  const total = 12 + body.length;
  return concat([u32(0x00000001, le), u32(total, le), body, u32(total, le)]);
};
const epb = (le, ts, data) => {
  const pad = (4 - (data.length % 4)) % 4;
  const body = concat([u32(0, le), u32(0, le), u32(ts, le), u32(data.length, le), u32(data.length, le), data, Buffer.alloc(pad), u16(0, le), u16(0, le)]);
  const total = 12 + body.length;
  return concat([u32(0x00000006, le), u32(total, le), body, u32(total, le)]);
};

// ---- 样本 1：pcap 完整 HTTP 会话，flag 在响应体 ----
const request = 'GET /secret/flag.html HTTP/1.1\r\nHost: ctf.example\r\nUser-Agent: ctf-browser\r\nAccept: */*\r\n\r\n';
const flagBody = 'flag{pc4p_4n4lys1s_1s_fun}';
const response = `HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: ${flagBody.length}\r\n\r\n${flagBody}`;
const framesHttp = [
  ethFrame(ip4(6, CLIENT, SERVER, tcpSeg(1000, 0, 0x02, SPORT, DPORT, new Uint8Array(0)))),
  ethFrame(ip4(6, SERVER, CLIENT, tcpSeg(5000, 1001, 0x12, DPORT, SPORT, new Uint8Array(0)))),
  ethFrame(ip4(6, CLIENT, SERVER, tcpSeg(1001, 5001, 0x10, SPORT, DPORT, new Uint8Array(0)))),
  ethFrame(ip4(6, CLIENT, SERVER, tcpSeg(1001, 5001, 0x18, SPORT, DPORT, ascii(request)))),
  ethFrame(ip4(6, SERVER, CLIENT, tcpSeg(5001, 1001 + request.length, 0x18, DPORT, SPORT, ascii(response)))),
  ethFrame(ip4(6, CLIENT, SERVER, tcpSeg(1001 + request.length, 5001 + response.length, 0x11, SPORT, DPORT, new Uint8Array(0)))),
];
fs.writeFileSync(path.join(outDir, 'http-flag.pcap'), pcapFile(framesHttp));

// ---- 样本 2：pcapng，跨段响应 + flag + 一次 DNS ----
const dnsFrame = ethFrame(ip4(17, CLIENT, '10.0.0.2', udpDatagram(40000, 53, ascii('dnsquerydata'))));
const reqNg = 'POST /upload HTTP/1.1\r\nHost: ctf.example\r\nContent-Length: 21\r\n\r\nanswer=flag{pcapng_rox}';
const resHead = 'HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nflag{';
const resPart1 = ethFrame(ip4(6, SERVER, CLIENT, tcpSeg(8001, 1001 + reqNg.length, 0x18, DPORT, SPORT, ascii(resHead))));
const resPart2 = ethFrame(ip4(6, SERVER, CLIENT, tcpSeg(8001 + resHead.length, 2000, 0x18, DPORT, SPORT, ascii('pcapng_rock}'))));
const pingFrame = ethFrame(ip4(1, CLIENT, SERVER, icmpMsg(8, 0)));
const blocks = [
  shb(true),
  idb(true, 1),
  epb(true, 1, dnsFrame),
  epb(true, 2, ethFrame(ip4(6, CLIENT, SERVER, tcpSeg(1001, 8001, 0x18, SPORT, DPORT, ascii(reqNg))))),
  epb(true, 3, resPart1),
  epb(true, 4, resPart2),
  epb(true, 5, pingFrame),
];
fs.writeFileSync(path.join(outDir, 'http-flag.pcapng'), concat(blocks));

// ---- 样本 3：混合流量（协议统计演示：TCP/UDP/DNS/ICMP/ARP/HTTP）----
const arpPayload = concat([
  u16be(1), u16be(0x0800), Uint8Array.from([6, 4, 0, 1]),
  Uint8Array.from(MAC), Uint8Array.from(CLIENT.split('.').map(Number)),
  Uint8Array.from([0, 0, 0, 0, 0, 0]), Uint8Array.from(SERVER.split('.').map(Number)),
  Buffer.alloc(18),
]);
const framesMixed = [
  ethFrame(arpPayload, 0x0806),
  dnsFrame,
  pingFrame,
  ethFrame(ip4(17, CLIENT, '10.0.0.9', udpDatagram(40001, 9000, ascii('plain-udp-payload')))),
  ...framesHttp,
];
fs.writeFileSync(path.join(outDir, 'mixed-traffic.pcap'), pcapFile(framesMixed));

// ---- 样本 4：超限大文件（50500 包，触发 50000 上限）----
const tinyFrame = pcapFile([pingFrame]).subarray(24);
const bigRecords = [];
for (let index = 0; index < 50500; index += 1) {
  bigRecords.push(concat([u32le(1700000000 + (index % 100)), u32le(index), u32le(tinyFrame.length), u32le(tinyFrame.length), tinyFrame]));
}
fs.writeFileSync(path.join(outDir, 'oversized.pcap'), concat([pcapFile([pingFrame]).subarray(0, 24), ...bigRecords]));

// ---- 样本 5：截断损坏文件 ----
const good = pcapFile(framesHttp);
fs.writeFileSync(path.join(outDir, 'truncated.pcap'), good.subarray(0, good.length - 17));

console.log('samples written to', outDir);
for (const file of fs.readdirSync(outDir)) {
  console.log(' -', file, fs.statSync(path.join(outDir, file)).size, 'bytes');
}
