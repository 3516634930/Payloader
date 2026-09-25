// USB HID 击键/鼠标流量恢复（流量取证域，sweep2 缺口 #17）：usbmon 抓包
// （LINKTYPE_USB_LINUX_MMAPPED=220）里还原键盘输入文本与鼠标相对位移轨迹。
// 纯函数、只读 ParsedCapture、无 DOM/eval/网络。usbmon 头布局按内核
// Documentation/usb/usbmon.rst：64 字节固定头，数据在偏移 64 起，长度取 len_cap
// （偏移 36，u32 小端）。键盘按 boot 协议 8 字节报文（[0]=修饰键位图、[1]恒 0、
// [2..7]=键码槽），鼠标按 boot 布局（[0]=按键位图、[1..2]=int8 位移）。
import type { ParsedCapture } from './pcap/parser';

export const USBMON_LINKTYPE = 220;
// USBPcap（Windows）原生链路层类型（desowin/usbpcap USBPcap.h：USBPCAP_BUFFER_PACKET_HEADER
// 27 字节变长头，数据起于 headerLen 而非固定 64）。
export const USBPCAP_LINKTYPE = 239;
const USBMON_HEADER_BYTES = 64;
const TRACK_CANVAS = 999; // 轨迹归一化画布坐标上界（0..999）

export interface UsbKeyboardEvent {
  shift: boolean;
  ctrl: boolean;
  alt: boolean;
  key: string;
  packetIndex: number;
}

export interface UsbMouseSample {
  buttons: number;
  dx: number;
  dy: number;
  packetIndex: number;
}

export interface UsbHidResult {
  keyboard: UsbKeyboardEvent[];
  text: string;
  mouse: UsbMouseSample[];
  mouseTrack: { points: Array<{ x: number; y: number; buttons: number }>; width: number; height: number };
  dataPackets: number;
  notes: string[];
}

// HID Usage ID → [常态字符, Shift 字符]；undefined = 不产生字符（0x00 静默、Esc/F 键/
// 方向键/锁定键等）。F 键与锁定键按任务口径略过；小键盘 0x54-0x63 按 NumLock 开启映射
// （数字串/PIN 码题面不丢字符）。
const KEYMAP: Array<[string, string] | undefined> = (() => {
  const map: Array<[string, string] | undefined> = new Array(256).fill(undefined);
  for (let i = 0; i < 26; i += 1) {
    const lower = String.fromCharCode(0x61 + i);
    map[0x04 + i] = [lower, String.fromCharCode(0x41 + i)];
  }
  const digits: Array<[string, string]> = [
    ['1', '!'], ['2', '@'], ['3', '#'], ['4', '$'], ['5', '%'],
    ['6', '^'], ['7', '&'], ['8', '*'], ['9', '('], ['0', ')'],
  ];
  for (let i = 0; i < 10; i += 1) map[0x1e + i] = digits[i];
  map[0x28] = ['\n', '\n'];
  map[0x2a] = ['\b', '\b'];
  map[0x2b] = ['\t', '\t'];
  map[0x2c] = [' ', ' '];
  map[0x2d] = ['-', '_'];
  map[0x2e] = ['=', '+'];
  map[0x2f] = ['[', '{'];
  map[0x30] = [']', '}'];
  map[0x31] = ['\\', '|'];
  map[0x32] = ['#', '~'];
  map[0x33] = [';', ':'];
  map[0x34] = ["'", '"'];
  map[0x35] = ['`', '~'];
  map[0x36] = [',', '<'];
  map[0x37] = ['.', '>'];
  map[0x38] = ['/', '?'];
  map[0x54] = ['/', '/'];
  map[0x55] = ['*', '*'];
  map[0x56] = ['-', '-'];
  map[0x57] = ['+', '+'];
  map[0x58] = ['\n', '\n'];
  const keypad = '1234567890';
  for (let i = 0; i < 10; i += 1) map[0x59 + i] = [keypad[i], keypad[i]];
  map[0x63] = ['.', '.'];
  return map;
})();

const u32le = (bytes: Uint8Array, offset: number): number =>
  bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);

const u16le = (bytes: Uint8Array, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);

const int8 = (value: number): number => (value >= 128 ? value - 256 : value);

// 键盘 boot 报文形态：8 字节、保留位 [1] 恒 0、六个键码槽全为 0 或落在键区 Usage 范围 0x04..0xE7。
const looksLikeKeyboardReport = (report: Uint8Array): boolean => {
  if (report.length !== 8 || report[1] !== 0) return false;
  for (let slot = 2; slot < 8; slot += 1) {
    const code = report[slot];
    if (code !== 0 && (code < 0x04 || code > 0xe7)) return false;
  }
  return true;
};

// 鼠标报文形态：3..8 字节、[0] 按键位图只占低 5 位（左/右/中 + 两个侧键，标准鼠标不会更高）。
const looksLikeMouseReport = (report: Uint8Array): boolean =>
  report.length >= 3 && report.length <= 8 && (report[0] & 0xe0) === 0;

interface HidCandidate {
  report: Uint8Array;
  packetIndex: number;
  // 严格模式为 "bus:dev:endpoint"；兜底模式无设备身份，统一 '*'（逐报文分流）。
  deviceKey: string;
}

// 鼠标轨迹：累计相对位移得原始坐标序列（原点代表抓包起点指针位置，画图从原点起笔），
// 再按每轴 min/max 归一到 0..999；width/height 为画布逻辑尺寸 1000。原始范围写入 notes
// 供渲染层保纵横比参考。零跨度轴上所有点落 0。
const buildMouseTrack = (samples: UsbMouseSample[]): {
  points: Array<{ x: number; y: number; buttons: number }>;
  width: number;
  height: number;
  minX: number; maxX: number; minY: number; maxY: number;
} => {
  if (samples.length === 0) return { points: [], width: TRACK_CANVAS + 1, height: TRACK_CANVAS + 1, minX: 0, maxX: 0, minY: 0, maxY: 0 };
  const raw: Array<{ x: number; y: number; buttons: number }> = [{ x: 0, y: 0, buttons: 0 }];
  let x = 0;
  let y = 0;
  for (const sample of samples) {
    x += sample.dx;
    y += sample.dy;
    raw.push({ x, y, buttons: sample.buttons });
  }
  let minX = 0;
  let maxX = 0;
  let minY = 0;
  let maxY = 0;
  for (const point of raw) {
    if (point.x < minX) minX = point.x;
    if (point.x > maxX) maxX = point.x;
    if (point.y < minY) minY = point.y;
    if (point.y > maxY) maxY = point.y;
  }
  const spanX = maxX - minX;
  const spanY = maxY - minY;
  const points = raw.map(point => ({
    x: spanX > 0 ? Math.round(((point.x - minX) / spanX) * TRACK_CANVAS) : 0,
    y: spanY > 0 ? Math.round(((point.y - minY) / spanY) * TRACK_CANVAS) : 0,
    buttons: point.buttons,
  }));
  return { points, width: TRACK_CANVAS + 1, height: TRACK_CANVAS + 1, minX, maxX, minY, maxY };
};

export const extractUsbHid = (parseResult: ParsedCapture): UsbHidResult => {
  const notes: string[] = [];
  const keyboard: UsbKeyboardEvent[] = [];
  const mouse: UsbMouseSample[] = [];
  const emptyResult = (): UsbHidResult => ({
    keyboard,
    text: '',
    mouse,
    mouseTrack: { points: [], width: TRACK_CANVAS + 1, height: TRACK_CANVAS + 1 },
    dataPackets: 0,
    notes,
  });

  if (parseResult.corrupt) notes.push(`容器解析中止于包 #${parseResult.corrupt.packetIndex}：${parseResult.corrupt.reason}`);
  if (parseResult.truncated) notes.push(`包数达到解析上限 ${parseResult.packetLimit}，其后包未参与恢复`);
  if (parseResult.packets.length === 0) {
    notes.push('未解析到任何数据包');
    return emptyResult();
  }
  const isUsbPcap = parseResult.linkType === USBPCAP_LINKTYPE;
  const usbPackets = parseResult.packets.filter(packet => packet.linkType === USBMON_LINKTYPE || packet.linkType === USBPCAP_LINKTYPE);
  if (usbPackets.length === 0) {
    notes.push(`抓包链路层非 USB（linkType=${parseResult.linkType}，需 usbmon 220 或 USBPcap 239），无法恢复 HID`);
    return emptyResult();
  }
  if (usbPackets.length < parseResult.packets.length) {
    notes.push(`${parseResult.packets.length - usbPackets.length} 包链路层非 USB，已跳过`);
  }

  // USBPcap 头（27 字节中断/批量，变长）：headerLen u16@0 | irpId u64@2 | status u32@10 |
  // function u16@14 | info u8@16（bit0=completion）| bus u16@17 | device u16@19 |
  // endpoint u8@21（bit7=IN）| transfer u8@22 | dataLength u32@23。数据起于 headerLen。
  const readUsbPcapReport = (data: Uint8Array): { report: Uint8Array; deviceKey: string; isHidIn: boolean } | null => {
    if (data.length < 27) return null;
    const headerLen = u16le(data, 0);
    const status = u32le(data, 10);
    const info = data[16];
    const bus = u16le(data, 17);
    const device = u16le(data, 19);
    const endpoint = data[21];
    const transfer = data[22];
    const dataLength = u32le(data, 23);
    if (headerLen < 27 || headerLen > data.length) return null;
    const start = headerLen;
    const end = Math.min(start + dataLength, data.length);
    if (end <= start) return null;
    // HID 中断 IN：中断传输 + URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER + completion + IN 端点 + 成功
    const isHidIn = transfer === 1
      && (u16le(data, 14)) === 0x0009
      && (info & 1) === 1
      && (endpoint & 0x80) !== 0
      && status === 0;
    return { report: data.subarray(start, end), deviceKey: `${bus}:${device}:${endpoint & 0x7f}`, isHidIn };
  };

  const readReport = (data: Uint8Array): Uint8Array | null => {
    if (data.length < USBMON_HEADER_BYTES) return null;
    const lenCap = u32le(data, 36);
    const end = Math.min(USBMON_HEADER_BYTES + lenCap, data.length);
    return data.subarray(USBMON_HEADER_BYTES, end);
  };

  const candidates: HidCandidate[] = [];
  if (isUsbPcap) {
    for (const packet of usbPackets) {
      const parsed = readUsbPcapReport(packet.data);
      if (!parsed || parsed.report.length < 3 || parsed.report.length > 8) continue;
      if (!parsed.isHidIn) continue;
      candidates.push({ report: parsed.report, packetIndex: packet.index, deviceKey: parsed.deviceKey });
    }
    if (candidates.length === 0) {
      // 兜底：USBPcap 头字段被改写时退化为数据段形态校验。
      for (const packet of usbPackets) {
        const parsed = readUsbPcapReport(packet.data);
        if (!parsed) continue;
        if (looksLikeKeyboardReport(parsed.report) || looksLikeMouseReport(parsed.report)) {
          candidates.push({ report: parsed.report, packetIndex: packet.index, deviceKey: '*' });
        }
      }
      if (candidates.length > 0) notes.push('USBPcap 头字段未命中 HID 判据，已按数据段形态启发式兜底提取');
    }
  } else {
  for (const packet of usbPackets) {
    const report = readReport(packet.data);
    if (!report || report.length < 3 || report.length > 8) continue;
    const eventType = packet.data[8];
    const epnum = packet.data[10];
    // 方向判定（关键假设）：只收 IN 方向（epnum bit7）的完成事件 'E'——IN 数据只在完成事件
    // 出现、提交事件 'S' 无数据，两者都收会把每次击键记两遍。不校验 xfer_type：sanitized
    // 抓包常把该字段清零，IN+完成+3..8 字节载荷在 usbmon 里已几乎唯一对应 HID 中断报文。
    if (eventType !== 0x45 || (epnum & 0x80) === 0) continue;
    const deviceKey = `${packet.data[12] | (packet.data[13] << 8)}:${packet.data[11]}:${epnum & 0x7f}`;
    candidates.push({ report, packetIndex: packet.index, deviceKey });
  }

  if (candidates.length === 0) {
    // 兜底口径：usbmon 头事件/方向字段不可信时，退化为"数据段形态合法才收"——
    // 8 字节过键盘校验、3..8 字节过鼠标校验；无设备身份，键鼠逐报文分流。
    for (const packet of usbPackets) {
      const report = readReport(packet.data);
      if (!report) continue;
      if (looksLikeKeyboardReport(report) || looksLikeMouseReport(report)) {
        candidates.push({ report, packetIndex: packet.index, deviceKey: '*' });
      }
    }
    if (candidates.length > 0) notes.push('未识别到 IN 方向完成事件（usbmon 头字段缺失或被改写），已按数据段形态启发式兜底提取');
  }
  }

  // 设备级键/鼠仲裁：8 字节报文在键盘与鼠标间存在逐包歧义（鼠标 [1] 为位移、键盘 [1] 恒 0），
  // 按 (bus,dev,endpoint) 分组投票、多数票整组定性，混合键鼠抓包（无线接收器/键鼠套装）不互串。
  const groups = new Map<string, HidCandidate[]>();
  for (const candidate of candidates) {
    const list = groups.get(candidate.deviceKey);
    if (list) list.push(candidate);
    else groups.set(candidate.deviceKey, [candidate]);
  }
  const keyboardReports: HidCandidate[] = [];
  const mouseReports: HidCandidate[] = [];
  for (const list of groups.values()) {
    if (list[0].deviceKey === '*') {
      for (const candidate of list) (looksLikeKeyboardReport(candidate.report) ? keyboardReports : mouseReports).push(candidate);
      continue;
    }
    let keyboardScore = 0;
    let mouseScore = 0;
    for (const candidate of list) {
      if (looksLikeKeyboardReport(candidate.report)) keyboardScore += 1;
      else if (looksLikeMouseReport(candidate.report)) mouseScore += 1;
    }
    (keyboardScore > mouseScore ? keyboardReports : mouseReports).push(...list);
  }
  // 跨设备统一按抓包顺序输出（分组聚合会打乱到达序）。
  keyboardReports.sort((left, right) => left.packetIndex - right.packetIndex);
  mouseReports.sort((left, right) => left.packetIndex - right.packetIndex);

  let text = '';
  for (const { report, packetIndex } of keyboardReports) {
    const modifiers = report[0];
    const shift = (modifiers & 0x22) !== 0; // LShift 0x02 | RShift 0x20
    const ctrl = (modifiers & 0x11) !== 0; // LCtrl 0x01 | RCtrl 0x10
    const alt = (modifiers & 0x44) !== 0; // LAlt 0x04 | RAlt 0x40
    for (let slot = 2; slot < report.length; slot += 1) {
      const entry = KEYMAP[report[slot]];
      if (!entry) continue; // 0x00 静默与未映射键（Esc/F 键/方向键/锁定键）不产生字符
      const key = entry[shift ? 1 : 0];
      keyboard.push({ shift, ctrl, alt, key, packetIndex });
      text += key;
    }
  }

  for (const { report, packetIndex } of mouseReports) {
    const buttons = report[0]; // 位图原样传递：bit0 左 / bit1 右 / bit2 中 / bit3-4 侧键
    const dx = int8(report[1]);
    const dy = int8(report[2]);
    if (buttons === 0 && dx === 0 && dy === 0) continue; // 纯空闲报文无信息量
    mouse.push({ buttons, dx, dy, packetIndex });
  }

  const track = buildMouseTrack(mouse);
  if (candidates.length === 0) {
    notes.push('未找到可识别的 HID 中断报文（usbmon 数据段无 3..8 字节载荷）');
  } else {
    notes.push(`识别 HID 报文 ${candidates.length} 个（键盘 ${keyboardReports.length} / 鼠标 ${mouseReports.length}）`);
  }
  if (mouse.length > 0) {
    notes.push(`鼠标位移原始范围 X ${track.minX}..${track.maxX} / Y ${track.minY}..${track.maxY}（相对位移单位；轨迹已按每轴 min/max 归一到 0..${TRACK_CANVAS}）`);
  }

  return {
    keyboard,
    text,
    mouse,
    mouseTrack: { points: track.points, width: track.width, height: track.height },
    dataPackets: candidates.length,
    notes,
  };
};
