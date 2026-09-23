// codec CTF 字段解析叶子层（T5 解环下沉）：宽松字段提取/规范化/bytes 解码工具，
// 仅依赖 bases/alphabets 字节工具，供 crypto/rsa/prng/attacks 共同消费。
import { base64ToBytes, hexToBytes } from './bases';
import { utf8Encoder } from './alphabets';

export const concatBytes = (...chunks: Uint8Array[]) => {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
};

export const parseHexBase64OrUtf8Bytes = (value: string, labelText: string) => {
  const raw = String(value || '');
  const text = raw.trim();
  if (!text) throw new Error(`${labelText} 不能为空`);
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
    return { bytes: hexToBytes(compactHex), format: 'hex' };
  }
  try {
    return { bytes: base64ToBytes(text), format: 'base64' };
  } catch {
    return { bytes: utf8Encoder.encode(raw), format: 'utf8' };
  }
};

export const normalizeCtfFieldName = (value: string) => {
  const normalized = value.normalize('NFKC').toLowerCase();
  const compact = normalized.replace(/[\s_.()-]/g, '');
  for (const [pattern, alias] of chineseCtfFieldAliases) {
    if (pattern.test(compact)) return alias;
  }
  return normalized.replace(/[^a-z0-9]+/g, '');
};

export const cleanLooseFieldValue = (value: unknown) => {
  let result = String(value ?? '')
    .trim()
    .replace(/^b(['"`])([\s\S]*)\1$/i, '$2')
    .replace(/^(['"`])([\s\S]*)\1$/, '$2')
    .trim()
    .replace(/[,;]+$/g, '')
    .trim();

  for (const [open, close] of [['(', ')'], ['[', ']'], ['{', '}']] as const) {
    result = stripTrailingUnbalancedDelimiter(result, open, close);
  }

  return result.trim();
};

export const cleanSymmetricFieldValue = (value: unknown) => cleanLooseFieldValue(value);

export const normalizeLooseFieldName = (value: string) => normalizeCtfFieldName(value);

export const isArithmeticFieldMatch = (source: string, index: number) => {
  let cursor = index - 1;
  while (cursor >= 0 && /\s/.test(source[cursor])) cursor -= 1;
  return cursor >= 0 && /[+\-*/(]/.test(source[cursor]);
};

export const rememberLooseField = (fields: Record<string, string>, rawKey: string, rawValue: unknown) => {
  const key = normalizeLooseFieldName(rawKey);
  const fieldValue = cleanSymmetricFieldValue(rawValue);
  if (!key || !fieldValue) return;
  const existing = fields[key];
  const existingLooksSelfReferential = Boolean(existing) && normalizeLooseFieldName(existing) === key;
  const nextLooksSelfReferential = normalizeLooseFieldName(fieldValue) === key;
  if (!existing || (existingLooksSelfReferential && !nextLooksSelfReferential)) fields[key] = fieldValue;
  if (/[+*/()]|\s-\s/.test(String(rawKey))) return;

  const tokens = String(rawKey)
    .toLowerCase()
    .match(/[a-z0-9]+/g) || [];
  for (const token of tokens) {
    const normalized = normalizeLooseFieldName(token);
    if (!normalized || normalized === key) continue;
    if (normalized.length > 1 || looseSingleCharTokens.has(normalized)) {
      if (!fields[normalized]) fields[normalized] = fieldValue;
    }
  }
};

export const flattenLooseJson = (fields: Record<string, string>, value: unknown, prefix = '') => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const fieldName = prefix ? `${prefix}_${key}` : key;
    if (Array.isArray(entry)) {
      rememberLooseField(fields, fieldName, entry.join(' '));
      rememberLooseField(fields, key, entry.join(' '));
    } else if (typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean') {
      rememberLooseField(fields, fieldName, entry);
      rememberLooseField(fields, key, entry);
    } else if (entry && typeof entry === 'object') {
      flattenLooseJson(fields, entry, fieldName);
    }
  }
};

export const parseLooseCtfFields = (value: string) => {
  const fields: Record<string, string> = {};
  try {
    flattenLooseJson(fields, JSON.parse(value));
  } catch {
    // Plain CTF statements often use prose, Python repr, or one field per line.
  }
  // Normalize backslash line continuations before other parsing
  const text = value.normalize('NFKC')
    .replace(/\r\n/g, '\n')
    .replace(/\\\n\s*/g, '')
    .replace(/`([^`]+)`/g, '$1')   // Strip markdown backticks
    .replace(/^#[^\n]*/gm, '');    // Strip comment lines starting with #
  // Handle int("hex_or_dec", base) expressions: key = int("abc123", 16)
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*int\s*\(\s*['"`]([0-9a-fA-F_]+)['"`]\s*,\s*(\d+)\s*\)/g)) {
    try {
      const base = Number(match[3]);
      const num = parseInt(match[2].replace(/_/g, ''), base);
      if (Number.isFinite(num)) rememberLooseField(fields, match[1], String(num));
      else rememberLooseField(fields, match[1], match[2]);
    } catch { /* ignore */ }
  }
  // Handle bytes_to_long(b'...hex...') or bytes_to_long(bytes.fromhex('...'))
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*bytes_to_long\s*\(\s*(?:bytes\.fromhex\s*\(\s*)?['"`]([0-9a-fA-F]+)['"`]/g)) {
    rememberLooseField(fields, match[1], `0x${match[2]}`);
  }
  // Handle pow(c, e, n) or pow(c, d, n) patterns — extract the three arguments
  for (const match of text.matchAll(/\bpow\s*\(\s*(0x[0-9a-fA-F_]+|\d[\d_]*)\s*,\s*(0x[0-9a-fA-F_]+|\d[\d_]*)\s*,\s*(0x[0-9a-fA-F_]+|\d[\d_]*)\s*\)/g)) {
    rememberLooseField(fields, 'pow_base', match[1]);
    rememberLooseField(fields, 'pow_exp', match[2]);
    rememberLooseField(fields, 'pow_mod', match[3]);
  }
  // Handle subscript/parenthesis notation: "Cipher (C₁):", "Modulus (N₁):", "C_1 =", "N1 =", "c1:", "n1:"
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_]*)\s*\([^)]{0,20}\)\s*[:=]\s*(0x[0-9a-fA-F_]+|\d[\d_]*)/g)) {
    rememberLooseField(fields, match[1], match[2]);
  }
  // Handle zero-width subscript chars like C₁ → c1
  const normalized = text.replace(/[₀₁₂₃₄₅₆₇₈₉]/g, d => String('₀₁₂₃₄₅₆₇₈₉'.indexOf(d)));
  if (normalized !== text) {
    for (const match of normalized.matchAll(/\b([A-Za-z][A-Za-z0-9_]*)\s*[:=]\s*(0x[0-9a-fA-F_]+|\d[\d_]*)/g)) {
      rememberLooseField(fields, match[1], match[2]);
    }
  }
  for (const match of text.matchAll(/['"`]([A-Za-z][A-Za-z0-9_. -]{0,40})['"`]\s*:\s*(\[[^\]]+\]|(?:0x[0-9a-fA-F:_-]+|(?:\\x[0-9a-fA-F]{2})+|[A-Za-z0-9+/_=.^-]{1,}|['"`][\s\S]*?['"`]))/g)) {
    rememberLooseField(fields, match[1], cleanSymmetricFieldValue(match[2]));
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*\[([^\]]+)\]/g)) {
    if (isArithmeticFieldMatch(text, match.index || 0)) continue;
    rememberLooseField(fields, match[1], match[2]);
  }
  // Chinese CTF prose: 密钥/秘钥 是/为/：X、密文 是/为/：X（中文题面的字段提取）
  for (const match of text.matchAll(/(?:密钥|秘钥|密匙)\s*(?:是|为)?\s*[:：]?\s*([A-Za-z0-9+/=]{2,64})/g)) {
    rememberLooseField(fields, 'key', match[1]);
  }
  for (const match of text.matchAll(/(?:密文|明文)\s*(?:是|为)?\s*[:：]\s*([^\n]+)/g)) {
    rememberLooseField(fields, 'ciphertext', match[1].trim());
  }
  for (const line of text.split('\n')) {
    const proseField = line.match(/^\s*(?:the\s+)?([A-Za-z][A-Za-z0-9_. -]{0,40}?)\s+(?:is|was|are|equals?)\s*(.+?)\s*$/i);
    if (proseField && /(?:0x[0-9a-f]+|\d|[([{]|[A-Za-z0-9+/_=-]{6,})/i.test(proseField[2])) {
      rememberLooseField(fields, proseField[1], proseField[2]);
    }
    const lineField = line.match(/^\s*([^:=\r\n]{1,80}?)\s*[:=]\s*(.+?)\s*$/u);
    if (lineField) rememberLooseField(fields, lineField[1], lineField[2]);
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*b?(['"`])([\s\S]*?)\2/g)) {
    if (isArithmeticFieldMatch(text, match.index || 0)) continue;
    rememberLooseField(fields, match[1], match[3]);
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*(0x[0-9a-fA-F:_-]+|(?:\\x[0-9a-fA-F]{2})+|[A-Za-z0-9+/_=.^-]{1,})/g)) {
    if (isArithmeticFieldMatch(text, match.index || 0)) continue;
    rememberLooseField(fields, match[1], match[2]);
  }
  for (const line of text.split('\n')) {
    const listLine = line.match(/\b(outputs?|states?|samples?|values?|leaks?|sequence|keystream|bits)\b\s*[:=]?\s*(.+)$/i);
    if (listLine && /(?:0x[0-9a-f]+|\d|\b[01]{8,}\b)/i.test(listLine[2])) {
      rememberLooseField(fields, listLine[1], listLine[2]);
    }
  }
  return fields;
};

export const looseField = (fields: Record<string, string>, aliases: string[]) => {
  for (const alias of aliases) {
    const value = fields[normalizeLooseFieldName(alias)];
    if (value) return value;
  }
  return '';
};

export const parseLooseIndexedRecords = (
  fields: Record<string, string>,
  aliases: Record<string, string[]>,
  maxRecords = 80,
) => {
  const indexes = new Set<number>();
  for (const key of Object.keys(fields)) {
    for (const aliasList of Object.values(aliases)) {
      for (const alias of aliasList) {
        const normalized = normalizeLooseFieldName(alias);
        const prefix = key.match(new RegExp(`^${normalized}(\\d+)$`));
        const suffix = key.match(new RegExp(`^(\\d+)${normalized}$`));
        const wrapped = key.match(new RegExp(`^(?:sig|signature|sample|record|item)(\\d+)${normalized}$`));
        const match = prefix || suffix || wrapped;
        if (match) indexes.add(Number(match[1]));
      }
    }
  }
  return Array.from(indexes)
    .filter(index => Number.isInteger(index) && index >= 0 && index <= maxRecords)
    .sort((left, right) => left - right)
    .map(index => {
      const record: Record<string, string> = {};
      for (const [field, aliasList] of Object.entries(aliases)) {
        const indexedAliases = aliasList.flatMap(alias => [
          `${alias}${index}`,
          `${index}${alias}`,
          `sig${index}${alias}`,
          `signature${index}${alias}`,
          `sample${index}${alias}`,
          `record${index}${alias}`,
          `item${index}${alias}`,
        ]);
        const value = looseField(fields, indexedAliases);
        if (value) record[field] = value;
      }
      return { index, record };
    })
    .filter(entry => Object.keys(entry.record).length > 0);
};

export const parseLooseObjectBlocks = (value: string, maxBlocks = 80) => {
  const blocks: Array<{ index: string; fields: Record<string, string> }> = [];
  for (const match of value.matchAll(/\{[^{}]{1,4000}\}/g)) {
    if (blocks.length >= maxBlocks) break;
    const fields: Record<string, string> = {};
    const body = match[0].slice(1, -1);
    for (const entry of body.matchAll(/['"`]?([A-Za-z][A-Za-z0-9_. -]{0,40})['"`]?\s*:\s*(\[[^\]]*\]|\([^)]*\)|(?:0x[0-9a-fA-F:_-]+|\d[\d_]*[nNlL]?|[A-Za-z0-9+/_=-]+={0,2}|['"`][\s\S]*?['"`]))/g)) {
      rememberLooseField(fields, entry[1], cleanSymmetricFieldValue(entry[2]));
    }
    if (Object.keys(fields).length) {
      blocks.push({
        index: `dict-${blocks.length}`,
        fields,
      });
    }
  }
  return blocks;
};

export const chineseCtfFieldAliases: Array<[RegExp, string]> = [
  [/(?:加密)?算法|算法类型|工作算法/, 'algorithm'],
  [/(?:私钥|私有)指数/, 'privateexponent'],
  [/(?:公钥|公开)指数/, 'publicexponent'],
  [/(?:模数|模)/, 'modulus'],
  [/(?:密钥|秘钥|口令|密码)/, 'key'],
  [/(?:初始(?:化)?向量|初始化向量|向量)/, 'iv'],
  [/(?:一次性)?随机数|随机向量/, 'nonce'],
  [/(?:密文|加密数据|加密后的数据)/, 'ciphertext'],
  [/(?:明文|原文|未加密数据)/, 'plaintext'],
  [/(?:认证|验证)标签|标签/, 'tag'],
  [/(?:附加认证数据|关联数据|附加数据)/, 'associateddata'],
  [/(?:盐值?|加盐)/, 'salt'],
  [/(?:计数器)/, 'counter'],
  [/(?:欧拉函数|欧拉值)/, 'phi'],
  [/(?:生成元|基元|底数)/, 'generator'],
  [/(?:曲线阶|椭圆曲线阶|群阶|子群阶|阶数)/, 'order'],
  [/(?:公钥|公开密钥)/, 'publickey'],
  [/(?:乘数|乘法器|系数)/, 'multiplier'],
  [/(?:增量|增值|常数项)/, 'increment'],
  [/(?:输出序列|状态序列|随机序列|输出值|状态值)/, 'outputs'],
  [/(?:种子)/, 'seed'],
  [/(?:第一|质数一|素数一|质数1|素数1)(?:个)?(?:质数|素数)?/, 'prime1'],
  [/(?:第二|质数二|素数二|质数2|素数2)(?:个)?(?:质数|素数)?/, 'prime2'],
  [/(?:签名)/, 'signature'],
  [/(?:曲线)/, 'curve'],
  [/(?:消息|报文)/, 'message'],
];

export const stripTrailingUnbalancedDelimiter = (value: string, open: string, close: string) => {
  let result = value;
  const countDelimiter = (text: string, delimiter: string) => (
    Array.from(text).reduce((count, char) => count + Number(char === delimiter), 0)
  );

  while (result.endsWith(close) && countDelimiter(result, close) > countDelimiter(result, open)) {
    result = result.slice(0, -1).trimEnd().replace(/[,;]+$/g, '').trimEnd();
  }

  return result;
};

export const looseSingleCharTokens = new Set(['a', 'b', 'c', 'd', 'e', 'g', 'h', 'k', 'm', 'n', 'p', 'q', 'r', 's', 'u', 'v', 'x', 'y', 'z']);
