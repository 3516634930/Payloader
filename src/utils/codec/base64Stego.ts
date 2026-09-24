// Base64 padding 隐写解码（攻防世界 base64stego 型）：含 '=' 的行，其 padding 前那个字符的
// 码表索引低 2*i 位（i 为 '=' 个数）是编码时被忽略的冗余位——逐行拼接即隐藏比特流。
// 语义对齐社区通行 base64stego 脚本（b64table.index(last) % 2^(2i)，2bit/1 个 '='，4bit/2 个 '='）。
// 纯函数零依赖；行解析容忍 \r\n 与空行。

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export interface Base64StegoResult {
  bits: string;
  text: string; // 比特流按 8 位组字节还原的 latin1 文本
  stegoLines: number; // 参与提取的含 padding 行数
  totalLines: number;
}

const decodeByteBits = (bits: string): string => {
  let text = '';
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    text += String.fromCharCode(parseInt(bits.slice(index, index + 8), 2));
  }
  return text;
};

export const base64StegoDecode = (value: string): Base64StegoResult => {
  const lines = value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  let bits = '';
  let stegoLines = 0;
  for (const line of lines) {
    if (!/^[A-Za-z0-9+/]+=*$/.test(line)) continue;
    let padding = 0;
    for (let index = line.length - 1; index >= 0 && line[index] === '='; index -= 1) padding += 1;
    if (padding === 0) continue;
    const last = line[line.length - 1 - padding];
    const alphabetIndex = B64_ALPHABET.indexOf(last);
    if (alphabetIndex < 0) continue;
    const width = 2 * padding;
    bits += (alphabetIndex % (2 ** width)).toString(2).padStart(width, '0');
    stegoLines += 1;
  }
  return { bits, text: decodeByteBits(bits), stegoLines, totalLines: lines.length };
};

export const base64StegoReport = (value: string): string => {
  const result = base64StegoDecode(value);
  return JSON.stringify({
    tool: 'base64-stego',
    stegoLines: result.stegoLines,
    totalLines: result.totalLines,
    bits: result.bits.length,
    hiddenText: result.text.replace(/\p{Cc}/gu, '.'),
    note: '隐藏位在含 = 行的 padding 前字符索引低 2i 位（i 为 = 个数）；无 = 的行不携带信息。',
  }, null, 2);
};
