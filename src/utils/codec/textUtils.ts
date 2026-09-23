// codec 文本解析叶子层（T5 解环下沉）：表达式/数值/Python 片段解析与正则工具，
// 依赖 ctfFields（token 清洗）/math（bigint 工具）/bases，无 React、无反向 codec 依赖。
import { cleanLooseFieldValue, normalizeLooseFieldName } from './ctfFields';
import { bigintFromBytes, bigintGcd, bigintModInverse, bigintModPow, bigintToBytes } from './math';
import { base64ToBytes, bytesToHex, hexToBytes } from './bases';
import { utf8Decoder, utf8Encoder } from './alphabets';
import { cStringDecode } from './textEncodings';
import type { Asn1Node } from './binaryFormats';

export const cleanRsaToken = (value: string) => cleanLooseFieldValue(value);

export const rsaExpressionMaxTokens = 128;

export const parseNumericValue = (value: string) => {
  const trimmed = cleanRsaToken(value).replace(/_/g, '').replace(/[nNlL]$/g, '');
  const colonHex = trimmed.replace(/:/g, '');
  if (/^[0-9a-f]{4,}$/i.test(colonHex) && /:/.test(trimmed)) return BigInt(`0x${colonHex}`);
  if (/^0x[0-9a-f]+$/i.test(trimmed)) return BigInt(trimmed);
  if (/^0b[01]+$/i.test(trimmed)) return BigInt(trimmed);
  if (/^0o[0-7]+$/i.test(trimmed)) return BigInt(trimmed);
  if (/^[0-9a-f]{2,}$/i.test(trimmed) && /[a-f]/i.test(trimmed)) return BigInt(`0x${trimmed}`);
  if (/^\d+$/.test(trimmed)) return BigInt(trimmed);
  return null;
};

export const parseFunctionLikeCall = (value: string) => {
  const text = cleanRsaToken(value);
  const openIndex = text.indexOf('(');
  if (openIndex <= 0 || !text.endsWith(')')) return null;
  const name = text.slice(0, openIndex).trim();
  if (!/^[A-Za-z_][A-Za-z0-9_.]*$/.test(name)) return null;
  const inner = text.slice(openIndex + 1, -1);
  const args: string[] = [];
  let depth = 0;
  let quote = '';
  let escaped = false;
  let start = 0;
  for (let index = 0; index < inner.length; index += 1) {
    const char = inner[index];
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === '\\') {
        escaped = true;
        continue;
      }
      if (char === quote) {
        quote = '';
      }
      continue;
    }
    if (char === '"' || char === '\'') {
      quote = char;
      continue;
    }
    if (char === '(' || char === '[' || char === '{') {
      depth += 1;
      continue;
    }
    if (char === ')' || char === ']' || char === '}') {
      depth -= 1;
      if (depth < 0) return null;
      continue;
    }
    if (char === ',' && depth === 0) {
      args.push(inner.slice(start, index).trim());
      start = index + 1;
    }
  }
  if (quote || depth !== 0) return null;
  const tail = inner.slice(start).trim();
  if (tail) args.push(tail);
  return { name, args };
};

export const parsePythonByteLikeValue = (
  value: string,
  fields: Record<string, string> = {},
  seen = new Set<string>(),
): Uint8Array | null => {
  const rawText = String(value || '').trim();
  const text = cleanRsaToken(value);
  if (!rawText || !text) return null;

  const arrayBytes = parsePythonByteArrayLiteral(rawText, fields, seen);
  if (arrayBytes) return arrayBytes;

  const sliced = parsePythonSliceSuffix(rawText);
  if (sliced) {
    const sourceBytes = parsePythonByteLikeValue(sliced.source, fields, seen);
    if (sourceBytes) {
      const normalized = applyPythonSlice(String.fromCharCode(...sourceBytes), sliced);
      return new Uint8Array(Array.from(normalized, char => char.codePointAt(0) || 0));
    }
    const sourceText = parsePythonQuotedText(sliced.source);
    if (sourceText != null) {
      return utf8Encoder.encode(applyPythonSlice(sourceText, sliced));
    }
  }

  const directBytes = parsePythonBytesLiteral(rawText);
  if (directBytes) return directBytes;

  const quoted = parsePythonQuotedText(rawText);
  if (quoted != null) {
    const compactHex = quoted.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
    if (compactHex.length >= 4 && compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
      try {
        return hexToBytes(compactHex);
      } catch {
        return utf8Encoder.encode(quoted);
      }
    }
    if (/^[A-Za-z0-9+/_=-]{8,}$/.test(quoted.replace(/\s+/g, ''))) {
      try {
        return base64ToBytes(quoted);
      } catch {
        return utf8Encoder.encode(quoted);
      }
    }
    return utf8Encoder.encode(quoted);
  }

  const normalized = normalizeLooseFieldName(text);
  if (normalized && !seen.has(normalized) && fields[normalized]) {
    seen.add(normalized);
    const nested = parsePythonByteLikeValue(fields[normalized], fields, seen);
    seen.delete(normalized);
    if (nested) return nested;
  }

  const call = parseFunctionLikeCall(text);
  if (!call) return null;
  const callable = normalizeLooseFieldName(call.name);

  if ((callable === 'bytesfromhex' || callable === 'bytearrayfromhex' || callable.endsWith('unhexlify')) && call.args.length >= 1) {
    const source = parsePythonQuotedText(call.args[0]) || parsePythonTextLikeValue(call.args[0], fields, seen);
    if (source == null) return null;
    try {
      return hexToBytes(source);
    } catch {
      return null;
    }
  }

  if ((callable === 'longtobytes' || callable.endsWith('longtobytes') || callable === 'n2s' || callable.endsWith('n2s')) && call.args.length >= 1) {
    const numeric = parsePythonNumberishValue(call.args[0], fields, seen);
    if (numeric == null || numeric < 0n) return null;
    return bigintToBytes(numeric);
  }

  return null;
};

export const parsePythonTextLikeValue = (
  value: string,
  fields: Record<string, string> = {},
  seen = new Set<string>(),
): string | null => {
  const rawText = String(value || '').trim();
  if (!rawText) return null;

  const quoted = parsePythonQuotedText(rawText);
  if (quoted != null) return quoted;

  const sliced = parsePythonSliceSuffix(rawText);
  if (sliced) {
    const source = parsePythonTextLikeValue(sliced.source, fields, seen);
    return source == null ? null : applyPythonSlice(source, sliced);
  }

  const call = parseFunctionLikeCall(rawText);
  if (!call) return null;
  const callable = normalizeLooseFieldName(call.name);

  if (callable === 'hex' && call.args.length === 1) {
    const numeric = parsePythonNumberishValue(call.args[0], fields, seen);
    if (numeric == null) return null;
    return numeric < 0n ? `-0x${(-numeric).toString(16)}` : `0x${numeric.toString(16)}`;
  }

  const byteLike = parsePythonByteLikeValue(rawText, fields, seen);
  if (byteLike) {
    try {
      return utf8Decoder.decode(byteLike);
    } catch {
      return String.fromCharCode(...byteLike);
    }
  }

  return null;
};

export const parseNumericTuple = (value: string) => {
  const items = Array.from(String(value || '').matchAll(/0x[0-9a-f_]+|\d[\d_]*[nNlL]?/gi))
    .map(match => parseNumericValue(match[0]))
    .filter((entry): entry is bigint => typeof entry === 'bigint');
  return items.length === 2 ? [items[0], items[1]] as const : null;
};

export const parseRsaFieldNumericValue = (key: string, value: string, fields: Record<string, string> = {}) => {
  const numeric = parseNumericValue(value);
  if (typeof numeric === 'bigint') return numeric;
  const pythonic = parsePythonNumberishValue(value, fields);
  if (typeof pythonic === 'bigint') return pythonic;
  const expression = evaluateRsaArithmeticExpression(value, fields);
  if (typeof expression === 'bigint') return expression;
  if (!rsaBase64NumberishKeys.has(key)) return null;
  const text = cleanRsaToken(value).replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/_=-]{2,}$/.test(text)) return null;
  try {
    return bigintFromBytes(base64ToBytes(text));
  } catch {
    return null;
  }
};

export const parseNumericList = (value: string) => (value.match(/0x[0-9a-f]+|\d+/gi) || [])
  .map(entry => parseNumericValue(entry))
  .filter((entry): entry is bigint => typeof entry === 'bigint');

export const parsePowerOrNumeric = (value: string | undefined) => {
  const text = String(value ?? '');
  const mersenne = text.match(/\b2\s*(?:\^|\*\*)\s*(\d+)\s*-\s*1\b/i);
  if (mersenne) return (1n << BigInt(Number(mersenne[1]))) - 1n;
  const power = text.match(/\b2\s*(?:\^|\*\*)\s*(\d+)\b/i);
  if (power) return 1n << BigInt(Number(power[1]));
  const numeric = text.match(/0x[0-9a-f]+|\d+/i)?.[0];
  return numeric ? parseNumericValue(numeric) : null;
};

export const parseOptionalModulus = (value: string) => {
  return parsePowerOrNumeric(value);
};

export const parseIndexedSequence = (value: string, prefixPattern = '[xs]') => {
  const entries = Array.from(value.matchAll(new RegExp(`\\b${prefixPattern}\\s*\\[?\\s*(\\d+)\\s*\\]?\\s*[:=]\\s*(0x[0-9a-f]+|\\d+)`, 'gi')))
    .map(match => ({ index: Number(match[1]), value: parseNumericValue(match[2]) }))
    .filter((entry): entry is { index: number; value: bigint } => typeof entry.value === 'bigint')
    .sort((left, right) => left.index - right.index);
  return entries.filter((entry, index) => index === 0 || entry.index !== entries[index - 1].index).map(entry => entry.value);
};

export const parseNamedIndexedSequence = (value: string, aliases: string[]) => {
  const aliasPattern = aliases.map(alias => alias.split('').map(char => escapeRegexLiteral(char)).join('[_\\s-]*')).join('|');
  const entries = Array.from(value.matchAll(new RegExp(`\\b(?:${aliasPattern})\\s*\\[?\\s*(\\d+)\\s*\\]?\\s*[:=]\\s*(0x[0-9a-f]+|\\d+)`, 'gi')))
    .map(match => ({ index: Number(match[1]), value: parseNumericValue(match[2]) }))
    .filter((entry): entry is { index: number; value: bigint } => typeof entry.value === 'bigint')
    .sort((left, right) => left.index - right.index);
  return entries.filter((entry, index) => index === 0 || entry.index !== entries[index - 1].index).map(entry => entry.value);
};

export const stripPrngScalarAssignments = (value: string) => value
  .replace(/\b(?:m|mod|modulus|modulo|a|multiplier|c|increment|seed)\s*[:=]\s*(?:2\s*(?:\^|\*\*)\s*\d+(?:\s*-\s*1)?|0x[0-9a-f]+|\d+)/gi, ' ')
  .replace(/\b\d+\s+outputs?\b/gi, ' ');

export const asn1IntegerValue = (node: Asn1Node) => {
  if (node.type !== 'INTEGER' || typeof node.value !== 'object' || node.value == null) return null;
  const value = node.value as { decimal?: unknown; hex?: unknown };
  if (typeof value.decimal === 'string') return parseNumericValue(value.decimal);
  if (typeof value.hex === 'string' && value.hex) return BigInt(`0x${value.hex.replace(/^00/, '') || '0'}`);
  return null;
};

export const parseNumberishUnknown = (value: unknown, fields: Record<string, string> = {}) => {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string') return parseRsaFieldNumericValue('n', value, fields);
  return null;
};

export const getObjectAliasValue = (value: Record<string, unknown>, aliases: string[]) => {
  for (const [key, entry] of Object.entries(value)) {
    if (aliases.some(alias => normalizeLooseFieldName(alias) === normalizeLooseFieldName(key))) return entry;
  }
  return undefined;
};

export const escapeRegexLiteral = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export const extractBracketedAssignment = (value: string, aliases: string[]) => {
  for (const alias of aliases) {
    const aliasPattern = alias.split('').map(char => escapeRegexLiteral(char)).join('[_\\s-]*');
    const pattern = new RegExp(`\\b${aliasPattern}\\b\\s*[:=]\\s*\\[`, 'i');
    const match = pattern.exec(value);
    if (!match) continue;
    let cursor = match.index + match[0].length;
    let depth = 1;
    while (cursor < value.length) {
      const char = value[cursor];
      if (char === '[') depth += 1;
      else if (char === ']') {
        depth -= 1;
        if (depth === 0) return value.slice(match.index + match[0].length, cursor);
      }
      cursor += 1;
    }
  }
  return '';
};

export const rsaBase64NumberishKeys = new Set(['n', 'e', 'd', 'p', 'q', 'phi', 'c', 'm', 'dp', 'dq', 'qinv', 'pinv']);

export const parsePythonQuotedText = (value: string) => {
  const text = String(value || '').trim();
  const match = text.match(/^([rRuU]{0,2})(['"])([\s\S]*)\2$/);
  if (!match) return null;
  const prefix = match[1].toLowerCase();
  const raw = prefix.includes('r');
  return raw ? match[3] : cStringDecode(match[3]);
};

export const parsePythonSliceSuffix = (value: string) => {
  const text = String(value || '').trim();
  const match = text.match(/^([\s\S]+)\[\s*(\d+)?\s*:\s*(\d+)?\s*\]$/);
  if (!match) return null;
  return {
    source: match[1].trim(),
    start: match[2] ? Number.parseInt(match[2], 10) : null,
    end: match[3] ? Number.parseInt(match[3], 10) : null,
  };
};

export const applyPythonSlice = (value: string, slice: { start: number | null; end: number | null }) => {
  const length = value.length;
  const normalizeIndex = (index: number | null, fallback: number) => {
    if (index == null) return fallback;
    return index < 0 ? Math.max(0, length + index) : Math.min(length, index);
  };
  const start = normalizeIndex(slice.start, 0);
  const end = normalizeIndex(slice.end, length);
  return value.slice(start, end);
};

export const parsePythonByteArrayLiteral = (
  value: string,
  fields: Record<string, string> = {},
  seen = new Set<string>(),
): Uint8Array | null => {
  const text = String(value || '').trim();
  const call = parseFunctionLikeCall(text);
  if (!call) return null;
  const callable = normalizeLooseFieldName(call.name);
  if (callable !== 'bytes' && callable !== 'bytearray') return null;
  if (!call.args.length) return new Uint8Array();
  if (call.args.length !== 1) return null;

  const arg = call.args[0].trim();
  if (!arg.startsWith('[') || !arg.endsWith(']')) return null;
  const body = arg.slice(1, -1).trim();
  if (!body) return new Uint8Array();

  const parts = body.split(',').map(part => part.trim()).filter(Boolean);
  if (!parts.length) return new Uint8Array();
  const bytes: number[] = [];
  for (const part of parts) {
    const numeric = parsePythonNumberishValue(part, fields, seen);
    if (numeric == null || numeric < 0n || numeric > 255n) return null;
    bytes.push(Number(numeric));
  }
  return new Uint8Array(bytes);
};

export const parsePythonNumberishValue = (
  value: string,
  fields: Record<string, string> = {},
  seen = new Set<string>(),
): bigint | null => {
  const text = cleanRsaToken(value);
  if (!text) return null;

  const sliced = parsePythonSliceSuffix(text);
  if (sliced) {
    const sourceText = parsePythonTextLikeValue(sliced.source, fields, seen);
    if (sourceText != null) {
      return parsePythonNumberishValue(JSON.stringify(applyPythonSlice(sourceText, sliced)), fields, seen);
    }
  }

  const expressionLike = /[()'",+\-*/%<>\s]/.test(text);
  const direct = parseNumericValue(text);
  if (typeof direct === 'bigint') return direct;

  const call = parseFunctionLikeCall(text);
  if (call) {
    const callable = normalizeLooseFieldName(call.name);

    if (callable === 'pow') {
      const args = call.args.map(arg => parsePythonNumberishValue(arg, fields, seen));
      if (args.some(arg => arg == null)) return null;
      if (args.length === 2) return bigintPowInRsaExpression(args[0]!, args[1]!);
      if (args.length === 3) {
        const [base, exponent, modulus] = args as [bigint, bigint, bigint];
        if (modulus <= 0n) return null;
        if (exponent >= 0n) return bigintModPow(base, exponent, modulus);
        const inverseBase = bigintModInverse(base, modulus);
        return inverseBase == null ? null : bigintModPow(inverseBase, -exponent, modulus);
      }
      return null;
    }

    if (callable === 'inverse' || callable === 'invert' || callable === 'modinverse' || callable === 'modinv' || callable.endsWith('inverse') || callable.endsWith('invert')) {
      if (call.args.length !== 2) return null;
      const left = parsePythonNumberishValue(call.args[0], fields, seen);
      const right = parsePythonNumberishValue(call.args[1], fields, seen);
      return left == null || right == null ? null : bigintModInverse(left, right);
    }

    if (callable === 'gcd' || callable.endsWith('gcd')) {
      if (call.args.length !== 2) return null;
      const left = parsePythonNumberishValue(call.args[0], fields, seen);
      const right = parsePythonNumberishValue(call.args[1], fields, seen);
      return left == null || right == null ? null : bigintGcd(left, right);
    }

    if (callable === 'int' || callable === 'mpz') {
      if (!call.args.length) return null;
      if (call.args.length === 1) {
        const nested = parsePythonNumberishValue(call.args[0], fields, seen);
        if (nested != null) return nested;
        const sourceText = parsePythonQuotedText(call.args[0]);
        return sourceText == null ? null : parseNumericValue(sourceText);
      }
      const sourceText = parsePythonQuotedText(call.args[0]);
      const base = parsePythonNumberishValue(call.args[1], fields, seen);
      if (sourceText == null || base == null || base < 0n || base > 36n) return null;
      if (base === 0n) return parseNumericValue(sourceText);
      return parseBigIntFromBaseString(sourceText, base);
    }

    if (callable === 'bytestolong' || callable.endsWith('bytestolong') || callable === 's2n' || callable.endsWith('s2n')) {
      if (!call.args.length) return null;
      const bytes = parsePythonByteLikeValue(call.args[0], fields, seen);
      return bytes ? bigintFromBytes(bytes) : null;
    }

    if (callable === 'intfrombytes' || callable.endsWith('intfrombytes')) {
      if (call.args.length < 2) return null;
      const bytes = parsePythonByteLikeValue(call.args[0], fields, seen);
      const byteOrder = parsePythonQuotedText(call.args[1])?.toLowerCase();
      if (!bytes || (byteOrder !== 'big' && byteOrder !== 'little')) return null;
      const ordered = byteOrder === 'little' ? Uint8Array.from(bytes).reverse() : bytes;
      return bigintFromBytes(ordered);
    }

    if (callable === 'hex') {
      if (call.args.length !== 1) return null;
      const numeric = parsePythonNumberishValue(call.args[0], fields, seen);
      if (numeric == null) return null;
      return parsePythonNumberishValue(JSON.stringify(numeric < 0n ? `-0x${(-numeric).toString(16)}` : `0x${numeric.toString(16)}`), fields, seen);
    }
  }

  const normalized = normalizeLooseFieldName(text);
  if (
    normalized
    && !expressionLike
    && !seen.has(normalized)
    && fields[normalized]
    && cleanRsaToken(fields[normalized]) !== text
  ) {
    seen.add(normalized);
    const nested = parsePythonNumberishValue(fields[normalized], fields, seen)
      ?? evaluateRsaArithmeticExpression(fields[normalized], fields, seen);
    seen.delete(normalized);
    if (nested != null) return nested;
  }

  return evaluateRsaArithmeticExpression(text, fields, seen);
};

export const evaluateRsaArithmeticExpression = (
  value: string,
  fields: Record<string, string> = {},
  seen = new Set<string>(),
): bigint | null => {
  const text = cleanRsaToken(value);
  if (!text || text.length > rsaExpressionMaxLength) return null;

  const tokens = tokenizeRsaExpression(text);
  if (!tokens) return null;

  let cursor = 0;

  const resolveIdentifier = (name: string) => {
    const normalized = normalizeLooseFieldName(name);
    if (!normalized || seen.has(normalized)) return null;
    const raw = fields[normalized];
    if (!raw) return null;
    seen.add(normalized);
    const direct = parsePythonNumberishValue(raw, fields, seen);
    if (typeof direct === 'bigint') return direct;
    const cleaned = cleanRsaToken(raw);
    if (!cleaned || cleaned === text) {
      seen.delete(normalized);
      return null;
    }
    const evaluated = evaluateRsaArithmeticExpression(cleaned, fields, seen);
    seen.delete(normalized);
    return evaluated;
  };

  const parseFunctionCall = (name: string): bigint | null => {
    if (tokens[cursor]?.type !== 'lparen') return null;
    cursor += 1;
    const args: bigint[] = [];
    if (tokens[cursor]?.type !== 'rparen') {
      while (true) {
        const argument = parseShift();
        if (argument == null) return null;
        args.push(argument);
        if (tokens[cursor]?.type === 'comma') {
          cursor += 1;
          continue;
        }
        break;
      }
    }
    if (tokens[cursor]?.type !== 'rparen') return null;
    cursor += 1;

    const normalized = normalizeLooseFieldName(name);
    if (normalized === 'pow') {
      if (args.length === 2) return bigintPowInRsaExpression(args[0], args[1]);
      if (args.length === 3) {
        const [base, exponent, modulus] = args;
        if (modulus <= 0n) return null;
        if (exponent >= 0n) return bigintModPow(base, exponent, modulus);
        const inverseBase = bigintModInverse(base, modulus);
        return inverseBase == null ? null : bigintModPow(inverseBase, -exponent, modulus);
      }
      return null;
    }
    if (normalized === 'inverse' || normalized === 'invert' || normalized === 'modinverse' || normalized === 'modinv' || normalized.endsWith('inverse') || normalized.endsWith('invert')) {
      if (args.length !== 2) return null;
      return bigintModInverse(args[0], args[1]);
    }
    if (normalized === 'gcd' || normalized.endsWith('gcd')) {
      if (args.length !== 2) return null;
      return bigintGcd(args[0], args[1]);
    }
    return null;
  };

  const parsePrimary = (): bigint | null => {
    const token = tokens[cursor];
    if (!token) return null;
    if (token.type === 'number') {
      cursor += 1;
      return parseNumericValue(token.value);
    }
    if (token.type === 'identifier') {
      cursor += 1;
      if (tokens[cursor]?.type === 'lparen') return parseFunctionCall(token.value);
      return resolveIdentifier(token.value);
    }
    if (token.type === 'lparen') {
      cursor += 1;
      const nested = parseShift();
      if (nested == null || tokens[cursor]?.type !== 'rparen') return null;
      cursor += 1;
      return nested;
    }
    return null;
  };

  const parseUnary = (): bigint | null => {
    const token = tokens[cursor];
    if (token?.type === 'operator' && (token.value === '+' || token.value === '-')) {
      cursor += 1;
      const next = parseUnary();
      if (next == null) return null;
      return token.value === '-' ? guardRsaExpressionValue(-next) : next;
    }
    return parsePrimary();
  };

  const parsePower = (): bigint | null => {
    const left = parseUnary();
    if (left == null) return null;
    const token = tokens[cursor];
    if (token?.type === 'operator' && token.value === '**') {
      cursor += 1;
      const right = parsePower();
      if (right == null) return null;
      return bigintPowInRsaExpression(left, right);
    }
    return left;
  };

  const parseMultiplicative = (): bigint | null => {
    let left = parsePower();
    if (left == null) return null;
    while (true) {
      const token = tokens[cursor];
      if (!token || token.type !== 'operator' || !['*', '/', '%'].includes(token.value)) break;
      cursor += 1;
      const right = parsePower();
      if (right == null) return null;
      if (token.value === '*') {
        const next = guardRsaExpressionValue(left * right);
        if (next == null) return null;
        left = next;
        continue;
      }
      if (right === 0n) return null;
      left = token.value === '/' ? left / right : left % right;
    }
    return left;
  };

  const parseAdditive = (): bigint | null => {
    let left = parseMultiplicative();
    if (left == null) return null;
    while (true) {
      const token = tokens[cursor];
      if (!token || token.type !== 'operator' || !['+', '-'].includes(token.value)) break;
      cursor += 1;
      const right = parseMultiplicative();
      if (right == null) return null;
      const next = token.value === '+' ? left + right : left - right;
      const guarded = guardRsaExpressionValue(next);
      if (guarded == null) return null;
      left = guarded;
    }
    return left;
  };

  const parseShift = (): bigint | null => {
    let left = parseAdditive();
    if (left == null) return null;
    while (true) {
      const token = tokens[cursor];
      if (!token || token.type !== 'operator' || !['<<', '>>'].includes(token.value)) break;
      cursor += 1;
      const right = parseAdditive();
      if (right == null || right < 0n || right > rsaExpressionMaxShift) return null;
      const next = token.value === '<<' ? left << right : left >> right;
      const guarded = guardRsaExpressionValue(next);
      if (guarded == null) return null;
      left = guarded;
    }
    return left;
  };

  const result = parseShift();
  if (result == null || cursor !== tokens.length) return null;
  return result;
};

export const rsaNumberResult = (value: bigint) => {
  const bytes = bigintToBytes(value);
  const utf8Preview = utf8Decoder.decode(bytes);
  const flagMatch = utf8Preview.match(/(?:flag|ctf|picoctf|htb|thm|ductf|corctf|dice|wctf|utflag|pctf|uiuctf|sekai|key|crypto)\{[^}]*\}/i);
  return {
    decimal: value.toString(),
    hex: bytesToHex(bytes),
    bytes: bytes.length,
    utf8Preview,
    ...(flagMatch ? { flag: flagMatch[0] } : {}),
  };
};

export const parsePythonBytesLiteral = (value: string) => {
  const text = String(value || '').trim();
  const match = text.match(/^((?:br|rb|b|r))?(["'])([\s\S]*)\2$/i);
  if (!match) return null;
  const prefix = String(match[1] || '').toLowerCase();
  if (!prefix.includes('b')) return null;
  const raw = prefix.includes('r');
  const body = match[3];
  const bytes: number[] = [];
  for (let index = 0; index < body.length; index += 1) {
    const char = body[index];
    if (!raw && char === '\\' && index + 1 < body.length) {
      const next = body[index + 1];
      if (next === 'x' && /^[0-9a-fA-F]{2}$/.test(body.slice(index + 2, index + 4))) {
        bytes.push(Number.parseInt(body.slice(index + 2, index + 4), 16));
        index += 3;
        continue;
      }
      if (/[0-7]/.test(next)) {
        const octal = body.slice(index + 1).match(/^[0-7]{1,3}/)?.[0] || next;
        bytes.push(Number.parseInt(octal, 8) & 0xff);
        index += octal.length;
        continue;
      }
      const simpleMap: Record<string, number> = {
        '\\': 0x5c,
        '\'': 0x27,
        '"': 0x22,
        n: 0x0a,
        r: 0x0d,
        t: 0x09,
        b: 0x08,
        f: 0x0c,
        v: 0x0b,
        a: 0x07,
        '0': 0x00,
      };
      if (next in simpleMap) {
        bytes.push(simpleMap[next]);
        index += 1;
        continue;
      }
    }
    const code = char.codePointAt(0);
    if (code == null || code > 0xff) return null;
    bytes.push(code);
  }
  return new Uint8Array(bytes);
};

export const bigintPowInRsaExpression = (base: bigint, exponent: bigint) => {
  if (exponent < 0n || exponent > rsaExpressionMaxExponent) return null;
  if (base === 0n && exponent === 0n) return null;
  const estimatedBits = rsaExpressionBitLength(base) * Number(exponent);
  if (estimatedBits > rsaExpressionMaxBits) return null;
  let result = 1n;
  let current = base;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) {
      result *= current;
      if (rsaExpressionBitLength(result) > rsaExpressionMaxBits) return null;
    }
    power >>= 1n;
    if (power > 0n) {
      current *= current;
      if (rsaExpressionBitLength(current) > rsaExpressionMaxBits) return null;
    }
  }
  return guardRsaExpressionValue(result);
};

export const rsaExpressionMaxLength = 256;

export const guardRsaExpressionValue = (value: bigint) => (
  rsaExpressionBitLength(value) <= rsaExpressionMaxBits ? value : null
);

export const tokenizeRsaExpression = (value: string): RsaExpressionToken[] | null => {
  const source = cleanRsaToken(value);
  const tokens: RsaExpressionToken[] = [];
  let cursor = 0;

  while (cursor < source.length) {
    const char = source[cursor];
    if (/\s/.test(char)) {
      cursor += 1;
      continue;
    }
    if (char === '(') {
      tokens.push({ type: 'lparen', value: char });
      cursor += 1;
      continue;
    }
    if (char === ')') {
      tokens.push({ type: 'rparen', value: char });
      cursor += 1;
      continue;
    }
    if (char === ',') {
      tokens.push({ type: 'comma', value: char });
      cursor += 1;
      continue;
    }
    if (source.startsWith('**', cursor) || source.startsWith('<<', cursor) || source.startsWith('>>', cursor)) {
      tokens.push({ type: 'operator', value: source.slice(cursor, cursor + 2) });
      cursor += 2;
      continue;
    }
    if ('+-*/%'.includes(char)) {
      tokens.push({ type: 'operator', value: char });
      cursor += 1;
      continue;
    }
    if (/[0-9]/.test(char)) {
      let end = cursor + 1;
      if (char === '0' && /[xX]/.test(source[end] || '')) {
        end += 1;
        while (end < source.length && /[0-9a-fA-F_]/.test(source[end])) end += 1;
      } else {
        while (end < source.length && /[\d_]/.test(source[end])) end += 1;
      }
      if (end < source.length && /[nNlL]/.test(source[end])) end += 1;
      tokens.push({ type: 'number', value: source.slice(cursor, end) });
      cursor = end;
      continue;
    }
    if (/[A-Za-z_]/.test(char)) {
      let end = cursor + 1;
      while (end < source.length && /[A-Za-z0-9_.]/.test(source[end])) end += 1;
      tokens.push({ type: 'identifier', value: source.slice(cursor, end) });
      cursor = end;
      continue;
    }
    return null;
  }

  return tokens.length && tokens.length <= rsaExpressionMaxTokens ? tokens : null;
};

export const parseBigIntFromBaseString = (value: string, base: bigint) => {
  const text = value.trim();
  if (!text) return null;
  const negative = text.startsWith('-');
  const positive = text.startsWith('+');
  const digits = (negative || positive) ? text.slice(1) : text;
  if (!digits) return null;
  let result = 0n;
  for (const char of digits.toLowerCase()) {
    const code = char.codePointAt(0) || 0;
    const digit = code >= 48 && code <= 57 ? code - 48 : code >= 97 && code <= 122 ? code - 87 : -1;
    if (digit < 0 || BigInt(digit) >= base) return null;
    result = result * base + BigInt(digit);
    if (rsaExpressionBitLength(result) > rsaExpressionMaxBits) return null;
  }
  return negative ? -result : result;
};

export type RsaExpressionToken = {
  type: 'number' | 'identifier' | 'operator' | 'lparen' | 'rparen' | 'comma';
  value: string;
};

export const rsaExpressionMaxShift = 32768n;

export const rsaExpressionMaxExponent = 4096n;

export const rsaExpressionBitLength = (value: bigint) => {
  const abs = value < 0n ? -value : value;
  return abs === 0n ? 0 : abs.toString(2).length;
};

export const rsaExpressionMaxBits = 131072;
