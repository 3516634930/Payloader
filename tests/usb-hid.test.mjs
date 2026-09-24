// USB HID 流量恢复测试（sweep2 缺口 #17）：全部 pcap/pcapng 向量程序化自造
// （24B 全局头 linkType=220 + 16B 记录头 + 64B usbmon 头 + HID 数据），无外部 fixture。
// 加载方式统一走 tests/helpers/compileTsModule.mjs（T4 测试基建收敛）。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const parser = loadModule(path.join(srcDir, 'utils', 'ctf', 'pcap', 'parser.ts'));
const usbHid = loadModule(path.join(srcDir, 'utils', 'ctf', 'usbHid.ts'));

// ---- pcap / usbmon 构造工具 ----

const u16le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
const u32le = value => Uint8Array.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
const u32be = value => Uint8Array.from([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);

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

// pcap 容器：小端微秒全局头（linkType 默认 220 = LINKTYPE_USB_LINUX_MMAPPED）+ 记录序列。
const pcapFromRecords = (records, { linkType = 220 } = {}) => {
  const header = concat([
    Uint8Array.from([0xd4, 0xc3, 0xb2, 0xa1]),
    u16le(2), u16le(4), u32le(0), u32le(0), u32le(262144), u32le(linkType),
  ]);
  return concat([header, ...records.map(record => concat([u32le(1700000000), u32le(0), u32le(record.length), u32le(record.length), record]))]);
};

// usbmon 64 字节头 + 数据段（默认模拟 IN 端点 0x81 的中断完成事件 'E'）。
const usbmonFrame = (report, { eventType = 0x45, epnum = 0x81, devnum = 3, busnum = 1, xferType = 1 } = {}) => {
  const head = Buffer.alloc(64);
  head.writeUInt8(eventType, 8);
  head.writeUInt8(xferType, 9);
  head.writeUInt8(epnum, 10);
  head.writeUInt8(devnum, 11);
  head.writeUInt16LE(busnum, 12);
  head.writeUInt16LE(report.length, 36); // len_cap
  return concat([head, report]);
};

// 键盘 boot 报文：[modifier, 0, usage, 0,0,0,0,0]；modifier 0x02 = 左 Shift。
const keyReport = (usage, modifiers = 0) => Uint8Array.from([modifiers, 0, usage, 0, 0, 0, 0, 0]);

// 测试侧字符 → (usage, shift) 反查表（与引擎 KEYMAP 同口径）。
const charUsage = ch => {
  if (ch >= 'a' && ch <= 'z') return { usage: 0x04 + ch.charCodeAt(0) - 0x61, shift: false };
  if (ch >= 'A' && ch <= 'Z') return { usage: 0x04 + ch.charCodeAt(0) - 0x41, shift: true };
  const symbols = {
    '!': [0x1e, 1], '@': [0x1f, 1], '#': [0x20, 1], '$': [0x21, 1], '%': [0x22, 1], '^': [0x23, 1],
    '&': [0x24, 1], '*': [0x25, 1], '(': [0x26, 1], ')': [0x27, 1], '-': [0x2d, 0], '_': [0x2d, 1],
    '=': [0x2e, 0], '+': [0x2e, 1], '[': [0x2f, 0], '{': [0x2f, 1], ']': [0x30, 0], '}': [0x30, 1],
    ';': [0x33, 0], ':': [0x33, 1], "'": [0x34, 0], '"': [0x34, 1], ',': [0x36, 0], '<': [0x36, 1],
    '.': [0x37, 0], '>': [0x37, 1], '/': [0x38, 0], '?': [0x38, 1], ' ': [0x2c, 0],
  };
  const entry = symbols[ch];
  if (!entry) throw new Error(`测试字符未映射: ${ch}`);
  return { usage: entry[0], shift: !!entry[1] };
};

// 逐字符生成 按下+释放 报文序列（真实键盘只在状态变化时上报）。
const typeFrames = (text, options = {}) => {
  const frames = [];
  for (const ch of text) {
    const { usage, shift } = charUsage(ch);
    frames.push(usbmonFrame(keyReport(usage, shift ? 0x02 : 0x00), options));
    frames.push(usbmonFrame(keyReport(0x00, 0x00), options));
  }
  return frames;
};

// pcapng 最小块集：SHB + IDB(linkType) + EPB。
const pcapngShb = () => concat([u32be(0x0a0d0d0a), u32le(28), u32le(0x1a2b3c4d), u16le(1), u16le(0), u32le(0xffffffff), u32le(0xffffffff), u32le(28)]);
const pcapngIdb = linkType => {
  const body = concat([u16le(linkType), u16le(0), u32le(262144), u16le(0), u16le(0)]);
  const total = 12 + body.length;
  return concat([u32le(0x00000001), u32le(total), body, u32le(total)]);
};
const pcapngEpb = data => {
  const pad = (4 - (data.length % 4)) % 4;
  const body = concat([u32le(0), u32le(1700000000), u32le(0), u32le(data.length), u32le(data.length), data, Buffer.alloc(pad), u16le(0), u16le(0)]);
  const total = 12 + body.length;
  return concat([u32le(0x00000006), u32le(total), body, u32le(total)]);
};

const extract = bytes => usbHid.extractUsbHid(parser.parseCapture(bytes));

// ---- ① 键盘击键序列：flag 完整还原（含 Shift 分支） ----

test('键盘逐键报文：flag{usb_hid_ok} 完整还原，{ 走 Shift 分支', () => {
  const result = extract(pcapFromRecords(typeFrames('flag{usb_hid_ok}')));
  assert.equal(result.text, 'flag{usb_hid_ok}');
  assert.equal(result.keyboard.length, 16);
  assert.equal(result.dataPackets, 32); // 16 次按下 + 16 次释放（释放也计入识别的 IN 报文）
  const braceOpen = result.keyboard.find(event => event.key === '{');
  assert.equal(braceOpen.shift, true);
  const letterF = result.keyboard.find(event => event.key === 'f');
  assert.equal(letterF.shift, false);
  assert.equal(letterF.ctrl, false);
  assert.equal(letterF.alt, false);
});

// ---- ② Shift 符号映射与控制字符 ----

test('Shift 变符号映射：a→A、1→!，回车/Tab 控制字符', () => {
  const reports = [
    keyReport(0x04, 0x00), keyReport(0x00), // a
    keyReport(0x04, 0x02), keyReport(0x00), // A
    keyReport(0x1e, 0x00), keyReport(0x00), // 1
    keyReport(0x1e, 0x02), keyReport(0x00), // !
    keyReport(0x28, 0x00), keyReport(0x00), // Enter
    keyReport(0x2b, 0x02), keyReport(0x00), // Shift+Tab 仍为 \t
  ];
  const result = extract(pcapFromRecords(reports.map(report => usbmonFrame(report))));
  assert.equal(result.text, 'aA1!\n\t');
  assert.equal(result.keyboard[0].shift, false);
  assert.equal(result.keyboard[1].shift, true);
  assert.equal(result.keyboard[3].shift, true);
  assert.equal(result.keyboard[4].key, '\n');
  assert.equal(result.keyboard[5].key, '\t');
});

// ---- ③ 静默键码 0x00 不产生字符 ----

test('静默键码 0x00：释放/空报文不产生字符但计入报文数', () => {
  const reports = [keyReport(0x16), keyReport(0x00), keyReport(0x00), keyReport(0x00), keyReport(0x17)];
  const result = extract(pcapFromRecords(reports.map(report => usbmonFrame(report))));
  assert.equal(result.text, 'st');
  assert.equal(result.keyboard.length, 2);
  assert.equal(result.dataPackets, 5);
});

// ---- ④ 鼠标 L 形轨迹归一化 ----

test('鼠标位移序列：累计坐标 + min/max 归一化到 0..999 的 L 形顶点', () => {
  const frames = [
    usbmonFrame(Uint8Array.from([0, 100, 0]), { devnum: 5 }), // 右移 100
    usbmonFrame(Uint8Array.from([0, 0, 50]), { devnum: 5 }),  // 下移 50
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.mouse.length, 2);
  const points = Array.from(result.mouseTrack.points, point => ({ x: point.x, y: point.y }));
  assert.equal(points.length, 3); // 原点 + 两个采样
  assert.deepEqual(points, [{ x: 0, y: 0 }, { x: 999, y: 0 }, { x: 999, y: 999 }]);
  assert.equal(result.mouseTrack.width, 1000);
  assert.equal(result.mouseTrack.height, 1000);
});

// ---- ⑤ 非 USB 链路层 ----

test('linkType=1（以太网）：notes 提示非 USB 抓包且不产出', () => {
  const result = extract(pcapFromRecords([Buffer.alloc(60)], { linkType: 1 }));
  assert.equal(result.keyboard.length, 0);
  assert.equal(result.text, '');
  assert.equal(result.mouse.length, 0);
  assert.equal(result.mouseTrack.points.length, 0);
  assert.ok(result.notes.some(note => note.includes('220')));
});

// ---- ⑥ 空 packets 不崩 ----

test('空 packets：仅 24 字节全局头不崩溃', () => {
  const result = extract(pcapFromRecords([], { linkType: 220 }));
  assert.equal(result.text, '');
  assert.equal(result.dataPackets, 0);
  assert.ok(result.notes.some(note => note.includes('未解析到任何数据包')));
});

// ---- ⑦ 鼠标按键位图与 int8 位移解码 ----

test('鼠标按键位图原样传递，位移按 int8 解码负值', () => {
  const frames = [
    usbmonFrame(Uint8Array.from([0x02, 5, 250]), { devnum: 5 }), // 右键 + dx=5 + dy=-6
    usbmonFrame(Uint8Array.from([0x05, 0, 0]), { devnum: 5 }),   // 左+中键按住不动
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.mouse.length, 2);
  assert.equal(result.mouse[0].buttons, 2);
  assert.equal(result.mouse[0].dx, 5);
  assert.equal(result.mouse[0].dy, -6);
  assert.equal(result.mouse[1].buttons, 5);
  assert.equal(result.mouse[1].dx, 0);
  // 纯空闲报文（全零）不进入样本序列。
  const idle = extract(pcapFromRecords([usbmonFrame(Uint8Array.from([0, 0, 0]), { devnum: 5 })]));
  assert.equal(idle.mouse.length, 0);
});

// ---- ⑧ 键鼠混合按设备分流 ----

test('键鼠混合抓包：按 usbmon 设备字段分流互不污染，事件保持包序', () => {
  const keyboardFrames = typeFrames('ok'); // devnum 默认 3
  const mouseFrames = [
    usbmonFrame(Uint8Array.from([1, 10, 0]), { devnum: 5 }),
    usbmonFrame(Uint8Array.from([0, 0, 20]), { devnum: 5 }),
  ];
  const frames = [
    keyboardFrames[0], mouseFrames[0], keyboardFrames[1], keyboardFrames[2], mouseFrames[1], keyboardFrames[3],
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, 'ok');
  assert.equal(result.keyboard.length, 2);
  assert.equal(result.mouse.length, 2);
  assert.equal(result.keyboard[0].packetIndex, 0);
  assert.equal(result.keyboard[1].packetIndex, 3); // 'k' 按下报文（交错序列中的第 4 包）
  assert.equal(result.mouse[0].packetIndex, 1);
  assert.equal(result.mouse[0].buttons, 1);
});

// ---- ⑨ pcapng 接口 linkType=220 ----

test('pcapng IDB linkType=220：接口映射后照常恢复击键', () => {
  const blocks = [pcapngShb(), pcapngIdb(220), ...typeFrames('ng').map(frame => pcapngEpb(frame))];
  const result = extract(concat(blocks));
  assert.equal(result.text, 'ng');
  assert.equal(result.keyboard.length, 2);
  assert.equal(result.dataPackets, 4);
});

// ---- ⑩ 兜底口径：事件/方向字段不可信 ----

test('兜底口径：非完成事件/OUT 端点时按数据段形态启发式提取并写 notes', () => {
  const frames = [
    usbmonFrame(keyReport(0x13), { eventType: 0x53 }), // 'S' 提交事件携带键盘报文（严格口径拒收）
    usbmonFrame(keyReport(0x00), { eventType: 0x53 }),
    usbmonFrame(Uint8Array.from([0, 3, 4]), { eventType: 0x53, epnum: 0x01, devnum: 0, busnum: 0 }), // OUT 端点鼠标报文
  ];
  const result = extract(pcapFromRecords(frames));
  assert.equal(result.text, 'p');
  assert.equal(result.mouse.length, 1);
  assert.equal(result.mouse[0].dx, 3);
  assert.equal(result.mouse[0].dy, 4);
  assert.ok(result.notes.some(note => note.includes('兜底')));
});

// ---- 附加：识别不到 HID 报文时的 notes ----

test('usbmon 抓包但无 3..8 字节载荷：notes 说明未找到 HID 报文', () => {
  const frame = usbmonFrame(Buffer.alloc(0)); // len_cap=0
  const result = extract(pcapFromRecords([frame]));
  assert.equal(result.text, '');
  assert.equal(result.dataPackets, 0);
  assert.ok(result.notes.some(note => note.includes('未找到可识别的 HID 中断报文')));
});
