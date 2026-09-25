// 批次 O 新操作的 variant 下拉选项与默认值归一：variant 是全局共享参数键（默认 'special'），
// 这些操作首次进入工作台时 params.variant 尚未落到自己的取值域，用 defaults 表归一显示与提交值。
export const parityVariantOptions: Record<string, Array<{ value: string; zh: string; en: string }>> = {
  'manchester': [
    { value: 'ieee-8023', zh: 'IEEE 802.3（1→01）', en: 'IEEE 802.3 (1→01)' },
    { value: 'ge-thomas', zh: 'G.E. Thomas（1→10）', en: 'G.E. Thomas (1→10)' },
  ],
  'ieee754': [
    { value: 'float64', zh: '双精度 float64', en: 'double float64' },
    { value: 'float32', zh: '单精度 float32', en: 'single float32' },
  ],
  'twos-complement': [
    { value: '8', zh: '8 位', en: '8-bit' },
    { value: '16', zh: '16 位', en: '16-bit' },
    { value: '32', zh: '32 位', en: '32-bit' },
  ],
  'ones-complement': [
    { value: '8', zh: '8 位', en: '8-bit' },
    { value: '16', zh: '16 位', en: '16-bit' },
    { value: '32', zh: '32 位', en: '32-bit' },
  ],
  'radix-xor': [
    { value: '16', zh: '十六进制', en: 'Hex' },
    { value: '10', zh: '十进制', en: 'Decimal' },
    { value: '8', zh: '八进制', en: 'Octal' },
    { value: '2', zh: '二进制', en: 'Binary' },
  ],
  'bit-split': [
    { value: '2', zh: '每 2 字符一组', en: '2 chars per group' },
    { value: '3', zh: '每 3 字符一组', en: '3 chars per group' },
    { value: '4', zh: '每 4 字符一组', en: '4 chars per group' },
    { value: '7', zh: '每 7 字符一组', en: '7 chars per group' },
  ],
  'bitwise-op': [
    { value: 'xor', zh: 'XOR（异或）', en: 'XOR' },
    { value: 'and', zh: 'AND（与）', en: 'AND' },
    { value: 'or', zh: 'OR（或）', en: 'OR' },
    { value: 'add', zh: 'ADD（加，mod 256）', en: 'ADD (mod 256)' },
    { value: 'sub', zh: 'SUB（减，mod 256）', en: 'SUB (mod 256)' },
  ],
  'bit-shift': [
    { value: 'left', zh: '左移', en: 'Left' },
    { value: 'right', zh: '右移', en: 'Right' },
  ],
  'bit-rotate': [
    { value: '8', zh: '8 位宽', en: '8-bit words' },
    { value: '16', zh: '16 位宽', en: '16-bit words' },
    { value: '32', zh: '32 位宽', en: '32-bit words' },
  ],
  'swap-endianness': [
    { value: '2', zh: '2 字节一组', en: '2-byte words' },
    { value: '4', zh: '4 字节一组', en: '4-byte words' },
    { value: '8', zh: '8 字节一组', en: '8-byte words' },
  ],
  'extract-data': [
    { value: 'ips', zh: 'IPv4 地址', en: 'IPv4 addresses' },
    { value: 'urls', zh: 'URL 链接', en: 'URLs' },
    { value: 'emails', zh: '邮箱', en: 'Emails' },
    { value: 'domains', zh: '域名', en: 'Domains' },
    { value: 'ipv4-hex', zh: 'IPv6 地址', en: 'IPv6 addresses' },
  ],
  'strings-op': [
    { value: '4', zh: '≥4 字符（默认）', en: '≥4 chars (default)' },
    { value: '3', zh: '≥3 字符', en: '≥3 chars' },
    { value: '6', zh: '≥6 字符', en: '≥6 chars' },
    { value: '8', zh: '≥8 字符', en: '≥8 chars' },
  ],
  'text-line-tool': [
    { value: 'unique', zh: '去重', en: 'Unique' },
    { value: 'sort', zh: '排序', en: 'Sort' },
    { value: 'head', zh: '前 N 行', en: 'Head (N lines)' },
    { value: 'tail', zh: '后 N 行', en: 'Tail (N lines)' },
    { value: 'strip-blank', zh: '去空行', en: 'Strip blank lines' },
    { value: 'reverse-lines', zh: '行反转', en: 'Reverse lines' },
    { value: 'shuffle-order', zh: '拼音排序', en: 'Pinyin sort' },
  ],
  'rc2': [
    { value: 'pkcs7', zh: 'PKCS#7 自动填充', en: 'PKCS#7 padding' },
    { value: 'raw', zh: 'raw（8 字节整块，不填充）', en: 'raw (aligned 8-byte blocks, no padding)' },
  ],
  'rc6': [
    { value: 'pkcs7', zh: 'PKCS#7 自动填充', en: 'PKCS#7 padding' },
    { value: 'raw', zh: 'raw（16 字节整块，不填充）', en: 'raw (aligned 16-byte blocks, no padding)' },
  ],
};

export const parityVariantDefaults: Record<string, string> = Object.fromEntries(
  Object.entries(parityVariantOptions).map(([id, optionList]) => [id, optionList[0].value]),
);
