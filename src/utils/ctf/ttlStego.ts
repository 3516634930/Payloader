// TTL 隐写解码引擎（流量取证域，文本类隐写批次，对标随波逐流"TTL隐写解码"）。
// 载体是 pcap 中 IP 包的 TTL 值序列（pcap 侧由 pcap/ 模块提列后传入，本模块只吃数字数组；
// 也支持从 Wireshark TTL 列直接复制粘贴的文本，extractTtlFromText 按行/逗号/空格抽数字）。
// 题型调研（交叉验证的主流形态）：
// 1. 四值 2bit：TTL 只取 4 个值，每个值携带 2 bit。经典题（如 ISG/各类国内赛，写法见
//    cnblogs《BlueTeam 取证- TTL隐写》等 writeup）用 63/127/191/255（即 00/01/10/11 + 111111，
//    "解密时只取前两位"）；也见 3/2/1/0 变体（值本身就是 2bit 载荷）。升序映射 00/01/10/11 同时
//    覆盖两者（63<127<191<255 与 0<1<2<3），另试降序映射防出题人反排。
// 2. chr(ttl)：TTL 值直接是 ASCII 码（常见 32-126 可见字符流）。
// 3. 低 4 位：每 TTL 贡献 1 个 nibble——两两拼字节，或直接当 hex 数字符流（"666c6167" 式）。
// 纯函数、只读输入、零依赖、同步，node --test 直跑；输入上限 20MB。

export const TTL_MAX_INPUT_BYTES = 20 * 1024 * 1024;

export interface TtlDecodeResult {
  method: string;
  text: string;
  printable: number; // 可打印率 0-1
  bits: number; // 该方法产出的比特数（chr 法按 8bit/字符计）
  bytesHex: string;
}

const FLAG_SHAPE = /flag\{|ctf\{|picoctf\{/i;

const bytesToText = (bytes: Uint8Array): string => {
  if (!bytes.length) return '';
  const utf8 = new TextDecoder().decode(bytes);
  return utf8.includes('\uFFFD') ? Array.from(bytes, byte => String.fromCharCode(byte)).join('') : utf8;
};

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

const printableRatioOf = (text: string): number => {
  if (!text.length) return 0;
  let printable = 0;
  for (const char of text) {
    const code = char.charCodeAt(0);
    if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) printable += 1;
  }
  return printable / text.length;
};

const bitsToBytes = (bits: string): Uint8Array => {
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes[index / 8] = Number.parseInt(bits.slice(index, index + 8), 2);
  }
  return bytes;
};

const makeResult = (method: string, bits: string): TtlDecodeResult | null => {
  const bytes = bitsToBytes(bits);
  if (!bytes.length) return null; // 不足一个字节的方法不产出候选
  const text = bytesToText(bytes);
  return { method, text, printable: printableRatioOf(text), bits: bits.length, bytesHex: bytesToHex(bytes) };
};

const NIBBLE_HEX = '0123456789abcdef';

export const decodeTtl = (values: number[]): TtlDecodeResult[] => {
  const ttls = values.filter(value => Number.isInteger(value) && value >= 0 && value <= 255);
  const results: TtlDecodeResult[] = [];

  // 方法 1：四值 2bit（升序 ↔ 00/01/10/11，覆盖 63/127/191/255 与 3/2/1/0 两族）
  const distinct = Array.from(new Set(ttls)).sort((left, right) => left - right);
  if (distinct.length === 4) {
    for (const [label, order] of [
      ['2bit 四值升序（63/127/191/255 型：小值=00）', distinct] as const,
      ['2bit 四值降序（大值=00，防反排）', [...distinct].reverse()] as const,
    ]) {
      let bits = '';
      for (const ttl of ttls) {
        bits += order.indexOf(ttl).toString(2).padStart(2, '0');
      }
      const result = makeResult(label, bits);
      if (result) results.push(result);
    }
  }

  // 方法 2：TTL 值直接作 ASCII 码
  if (ttls.length) {
    const text = ttls.map(ttl => String.fromCharCode(ttl)).join('');
    results.push({
      method: 'chr(ttl)（TTL 即 ASCII 码）',
      text,
      printable: printableRatioOf(text),
      bits: ttls.length * 8,
      bytesHex: bytesToHex(new Uint8Array(ttls)),
    });
  }

  // 方法 3：低 4 位两两拼字节
  if (ttls.length >= 2) {
    let bits = '';
    for (const ttl of ttls) bits += (ttl & 0xf).toString(2).padStart(4, '0');
    const result = makeResult('低 4 位拼字节（两 TTL 一字节）', bits);
    if (result) results.push(result);
  }

  // 方法 4：低 4 位当 hex 数字符流（nibble 值即 '0'-'f' 字符）
  if (ttls.length) {
    let bits = '';
    for (const ttl of ttls) {
      const nibble = ttl & 0xf;
      bits += NIBBLE_HEX.charCodeAt(nibble).toString(2).padStart(8, '0');
    }
    const result = makeResult('低 4 位 → hex 字符流（nibble 即十六进制字符）', bits);
    if (result) results.push(result);
  }

  results.sort((left, right) => {
    const flagDelta = Number(FLAG_SHAPE.test(right.text)) - Number(FLAG_SHAPE.test(left.text));
    if (flagDelta !== 0) return flagDelta;
    if (right.printable !== left.printable) return right.printable - left.printable;
    return right.bits - left.bits;
  });
  return results;
};

// 从粘贴文本提取 TTL 序列：Wireshark TTL 列导出/复制场景，按行、逗号、空格、制表符混排切分，
// 只保留 0-255 的整数（TTL 是单字节字段，更大的数字是粘连的端口/长度列，丢弃）。
export const extractTtlFromText = (text: string): number[] => {
  if (text.length > TTL_MAX_INPUT_BYTES) {
    throw new Error(`输入 ${text.length} 字符超过 TTL 引擎上限 ${TTL_MAX_INPUT_BYTES}（20MB）`);
  }
  return (text.match(/\d+/g) || []).map(Number).filter(value => Number.isInteger(value) && value <= 255);
};

// 编码方向（出题/自测闭环）：文本 → UTF-8 字节 → 每 2bit 一个 TTL（默认 63/127/191/255）。
export const encodeTtl2bit = (text: string | Uint8Array, ttls: number[] = [63, 127, 191, 255]): number[] => {
  if (ttls.length !== 4) throw new Error('encodeTtl2bit 需要恰好 4 个 TTL 值');
  const bytes = typeof text === 'string' ? new TextEncoder().encode(text) : text;
  const values: number[] = [];
  for (const byte of bytes) {
    for (let shift = 6; shift >= 0; shift -= 2) {
      values.push(ttls[(byte >> shift) & 0x3]);
    }
  }
  return values;
};

export interface TtlReport {
  tool: string;
  count: number;
  distinct: number[];
  candidates: TtlDecodeResult[];
  note: string;
}

export const ttlStegoReport = (value: string): string => {
  const values = extractTtlFromText(value);
  const candidates = decodeTtl(values).slice(0, 6);
  const report: TtlReport = {
    tool: 'ttl-stego',
    count: values.length,
    distinct: Array.from(new Set(values)).sort((left, right) => left - right),
    candidates,
    note: candidates.length
      ? '候选按可打印率 + flag 形态排序；四值 2bit 法需 TTL 恰好取 4 个不同值。'
      : '未提取到可用 TTL 序列（需至少 8 个 0-255 数字）；若数据在 pcap 中，请先经流量解析取 TTL 列。',
  };
  return JSON.stringify(report, null, 2);
};
