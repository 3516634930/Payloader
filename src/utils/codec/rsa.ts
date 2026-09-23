// CODEC-IMPORTS
import { cleanSymmetricFieldValue, concatBytes, isArithmeticFieldMatch, looseField, normalizeCtfFieldName, normalizeLooseFieldName, parseHexBase64OrUtf8Bytes, parseLooseCtfFields, parseLooseIndexedRecords, parseLooseObjectBlocks } from './crypto';
import { utf8Decoder } from './alphabets';
import { base64ToBytes, bytesToHex } from './bases';
import { extractBracketedAssignment, getObjectAliasValue, parseNumberishUnknown } from './textUtils';
import type { Asn1Node } from './binaryFormats';
import { parseAsn1Input, parseAsn1TopLevel, readSshString } from './binaryFormats';
import { bigIntSqrt } from './math';
import type { Direction } from './types';
// CODEC-IMPORTS-END

export {
  rsaExpressionBitLength,
  rsaExpressionMaxBits,
  rsaExpressionMaxExponent,
  rsaExpressionMaxShift,
} from './textUtils';

export {
  guardRsaExpressionValue,
  parseBigIntFromBaseString,
  rsaExpressionMaxLength,
  tokenizeRsaExpression,
} from './textUtils';
export type { RsaExpressionToken } from './textUtils';

export {
  bigintPowInRsaExpression,
  parsePythonBytesLiteral,
} from './textUtils';

import { rsaNumberResult } from './textUtils';

export {
  rsaBase64NumberishKeys,
  parsePythonQuotedText,
  parsePythonSliceSuffix,
  applyPythonSlice,
  parsePythonByteArrayLiteral,
  parsePythonNumberishValue,
  evaluateRsaArithmeticExpression,
} from './textUtils';

import {
  asn1IntegerValue,
  cleanRsaToken,
  parseNumericList,
  parseNumericValue,
  parseRsaFieldNumericValue,
} from './textUtils';

// 以下函数已下沉 src/utils/codec/textUtils.ts（T5 解环）；re-export 保持既有导出面。
export {
  asn1IntegerValue,
  cleanRsaToken,
  parseFunctionLikeCall,
  parseIndexedSequence,
  parseNamedIndexedSequence,
  parseNumericList,
  parseNumericTuple,
  parseNumericValue,
  parseOptionalModulus,
  parsePowerOrNumeric,
  parsePythonByteLikeValue,
  parsePythonTextLikeValue,
  parseRsaFieldNumericValue,
  rsaExpressionMaxTokens,
  stripPrngScalarAssignments,
} from './textUtils';
import {
  bigintAbs,
  bigintEgcd,
  bigintFromBytes,
  bigintGcd,
  bigintMod,
  bigintModInverse,
  bigintModPow,
  bigintPow,
  bigintToBytes,
  bitLength,
  crtCombinePair,
  factorSmallCompositeModulus,
  factorSmallRsaModulus,
  rsaModPowSigned,
} from './math';

// 纯数学叶子函数已下沉 codec/math.ts（T5 解环）；re-export 保持既有导出面。
export {
  bigintAbs,
  bigintEgcd,
  bigintFromBytes,
  bigintGcd,
  bigintMod,
  bigintModInverse,
  bigintModPow,
  bigintPow,
  bigintToBytes,
  bitLength,
  crtCombinePair,
  factorSmallCompositeModulus,
  factorSmallRsaModulus,
  rsaModPowSigned,
} from './math';


























export const rsaParamAliases: Record<string, string> = {
  n: 'n',
  mod: 'n',
  modulus: 'n',
  modulusn: 'n',
  modulushex: 'n',
  modulo: 'n',
  publicn: 'n',
  publicmodulus: 'n',
  publickeymodulus: 'n',
  rsamodulus: 'n',
  rsan: 'n',
  publicmod: 'n',
  pubn: 'n',
  pubkeyn: 'n',
  publickeyn: 'n',
  privkeyn: 'n',
  nvalue: 'n',
  e: 'e',
  ee: 'e',
  exp: 'e',
  exponent: 'e',
  publice: 'e',
  publicexponent: 'e',
  publickeyexponent: 'e',
  publicexp: 'e',
  pubexp: 'e',
  pube: 'e',
  pubkeye: 'e',
  publickeye: 'e',
  privkeye: 'e',
  exponentpublic: 'e',
  d: 'd',
  privateexponent: 'd',
  privatekeyexponent: 'd',
  privkeyexponent: 'd',
  privexp: 'd',
  p: 'p',
  prime1: 'p',
  primeone: 'p',
  primep: 'p',
  q: 'q',
  prime2: 'q',
  primetwo: 'q',
  primeq: 'q',
  phi: 'phi',
  phin: 'phi',
  phi_n: 'phi',
  eulerphi: 'phi',
  eulertotient: 'phi',
  totient: 'phi',
  c: 'c',
  ct: 'c',
  cts: 'c',
  enc: 'c',
  encdata: 'c',
  encrypted: 'c',
  encryptedmessage: 'c',
  encryptedvalues: 'c',
  ciphered: 'c',
  cipher: 'c',
  ciphers: 'c',
  ciphertext: 'c',
  ciphertexts: 'c',
  cipherblocks: 'c',
  cyphertext: 'c',
  cryptogram: 'c',
  crypt: 'c',
  ctflag: 'c',
  flagct: 'c',
  encflag: 'c',
  encryptedflag: 'c',
  flagciphertext: 'c',
  cipherflag: 'c',
  encmsg: 'c',
  encryptedmsg: 'c',
  encmessage: 'c',
  cipherdata: 'c',
  flagenc: 'c',
  ciphermsg: 'c',
  ctxt: 'c',
  m: 'm',
  msg: 'm',
  msgs: 'm',
  message: 'm',
  messages: 'm',
  cleartext: 'm',
  plain: 'm',
  plains: 'm',
  plaintext: 'm',
  plaintexts: 'm',
  pt: 'm',
  dp: 'dp',
  dmp1: 'dp',
  dmp: 'dp',
  exponent1: 'dp',
  dmodp1: 'dp',
  dmodp: 'dp',
  dq: 'dq',
  dmq1: 'dq',
  dmq: 'dq',
  exponent2: 'dq',
  dmodq1: 'dq',
  dmodq: 'dq',
  qinv: 'qinv',
  iqmp: 'qinv',
  qi: 'qinv',
  coefficient: 'qinv',
  crtcoefficient: 'qinv',
  inverseq: 'qinv',
  pinv: 'pinv',
  u: 'pinv',
  inversep: 'pinv',
};

export const normalizeRsaParamName = (key: string) => rsaParamAliases[normalizeCtfFieldName(key)] || null;

export const isCommonRsaPublicExponent = (value: bigint) => [3n, 5n, 17n, 257n, 65537n].includes(value);

export const isLikelyRsaPublicExponent = (value: bigint) => isCommonRsaPublicExponent(value) || (value > 1n && value < 1_000_000n && (value & 1n) === 1n);

export const parseKeyValueNumbers = (value: string) => {
  const params: Record<string, string> = {};
  const looseNumbers: string[] = [];
  const indexedCipherBlocks: string[] = [];
  let looseFields: Record<string, string> = {};
  const rememberParam = (key: string, rawValue: string) => {
    const normalized = normalizeRsaParamName(key);
    const token = cleanRsaToken(rawValue);
    if (!token) return;
    if (!normalized) {
      const compactKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (/^(?:c|ct|cipher|ciphertext|enc|block)\d+$/.test(compactKey)) indexedCipherBlocks.push(token);
      return;
    }
    const contextFields = {
      ...looseFields,
      ...Object.fromEntries(Object.entries(params).map(([paramKey, paramValue]) => [normalizeLooseFieldName(paramKey), paramValue])),
    };
    const existing = params[normalized];
    if (!existing) {
      params[normalized] = token;
      return;
    }
    const existingNumeric = parseRsaFieldNumericValue(normalized, existing, contextFields);
    const candidateNumeric = parseRsaFieldNumericValue(normalized, token, contextFields);
    if (candidateNumeric != null && existingNumeric == null) {
      params[normalized] = token;
      return;
    }
    if (candidateNumeric == null && existingNumeric != null) return;
    if (
      existing.length > token.length
      && existing.startsWith(token)
      && /[(),+\-*/%<>\s]/.test(existing)
      && !/[(),+\-*/%<>\s]/.test(token)
    ) {
      return;
    }
    if (normalized === key.toLowerCase()) params[normalized] = token;
  };

  try {
    looseFields = parseLooseCtfFields(value);
    for (const [key, entry] of Object.entries(looseFields)) rememberParam(key, entry);
  } catch {
    // Fall through to regex-based parsing for prose or non-JSON challenge text.
  }

  for (const match of value.matchAll(/\b([a-zA-Z][\w-]*)\s*[:=]\s*(['"]?)(0x[0-9a-f_]+|\d[\d_]*[nNlL]?|[A-Za-z0-9+/_-]+={0,2})\2/gi)) {
    if (isArithmeticFieldMatch(value, match.index || 0)) continue;
    const assignmentEnd = (match.index || 0) + match[0].length;
    if (/^\s*\(/.test(value.slice(assignmentEnd))) continue;
    rememberParam(match[1], match[3]);
  }
  const lines = value.replace(/\r\n/g, '\n').split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const label = lines[index].match(/^\s*([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*$/);
    if (!label || !normalizeRsaParamName(label[1])) continue;
    const hexParts: string[] = [];
    let plainDecimalOrHex = '';
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const line = lines[cursor].trim();
      if (!line) break;
      if (/^[A-Za-z][A-Za-z0-9_. -]{0,40}\s*[:=]/.test(line)) break;
      // colon-hex: aa:bb:cc style multi-line DER values
      if (/^(?:[0-9a-f]{2}:){1,}[0-9a-f]{2}$/i.test(line)) { hexParts.push(line); continue; }
      // plain decimal or 0x-hex on its own line
      if (!plainDecimalOrHex && /^(?:0x[0-9a-f]+|\d+)$/i.test(line)) { plainDecimalOrHex = line; break; }
      break;
    }
    if (hexParts.length) rememberParam(label[1], `0x${hexParts.join('').replace(/:/g, '')}`);
    else if (plainDecimalOrHex) rememberParam(label[1], plainDecimalOrHex);
  }
  for (const match of value.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*(0x[0-9a-fA-F:_-]+|(?:[0-9a-fA-F]{2}:){2,}[0-9a-fA-F]{2})/g)) {
    if (isArithmeticFieldMatch(value, match.index || 0)) continue;
    rememberParam(match[1], match[2]);
  }
  for (const match of value.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*\((0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\)/g)) {
    if (isArithmeticFieldMatch(value, match.index || 0)) continue;
    rememberParam(match[1], match[2]);
  }
  for (const rawLine of value.split(/\r?\n|[,;]/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = line.match(/^([a-zA-Z][\w-]*)\s*[:=]\s*(.+)$/);
    if (match && !/\b[a-zA-Z][\w-]*\s*[:=]/.test(match[2])) rememberParam(match[1], match[2]);
  }
  for (const match of value.matchAll(/(^|[^A-Za-z0-9_])(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)(?![A-Za-z0-9_])/gi)) {
    looseNumbers.push(cleanRsaToken(match[2]));
  }
  const resolverFields: Record<string, string> = {
    ...looseFields,
    ...Object.fromEntries(Object.entries(params).map(([key, entry]) => [normalizeLooseFieldName(key), entry])),
  };
  const resolveLooseReference = (paramKey: string, token: string, seen = new Set<string>()): string => {
    const cleaned = cleanRsaToken(token);
    const direct = parseRsaFieldNumericValue(paramKey, cleaned, resolverFields);
    if (typeof direct === 'bigint') return direct.toString();

    const normalized = normalizeLooseFieldName(cleaned);
    if (!normalized || seen.has(normalized) || !resolverFields[normalized]) return '';

    const next = cleanRsaToken(resolverFields[normalized]);
    if (!next || next === cleaned) return '';

    seen.add(normalized);
    const resolved = resolveLooseReference(paramKey, next, seen);
    seen.delete(normalized);
    return resolved || next;
  };
  for (const [key, rawValue] of Object.entries(params)) {
    const resolved = resolveLooseReference(key, rawValue);
    if (resolved) {
      params[key] = resolved;
      resolverFields[normalizeLooseFieldName(key)] = resolved;
    }
  }
  if (!params.c && indexedCipherBlocks.length) params.c = `[${indexedCipherBlocks.join(',')}]`;
  return { params, looseNumbers };
};

export type RsaInference = {
  params: Record<string, string>;
  looseNumbers: string[];
  confidence: number;
  notes: string[];
  knownPairs: RsaKnownPair[];
};

export type RsaKnownPair = {
  index: string;
  m: bigint;
  c: bigint;
};

export type RsaCipherRecord = {
  index: string;
  n: bigint | null;
  e: bigint | null;
  c: bigint | null;
  m: bigint | null;
  raw: Record<string, string>;
};

export type RsaPublicKeyRecord = {
  index: string;
  n: bigint;
  e: bigint;
  raw: Record<string, string>;
};

export type RsaAutomatedAttackResult = {
  attack: string;
  title: string;
  output: unknown;
  details?: Record<string, unknown>;
};

export const rsaParamNumber = (params: Record<string, string>, key: string) => params[key] ? parseRsaFieldNumericValue(key, params[key], params) : null;

export const rememberInferredRsaParam = (
  params: Record<string, string>,
  key: string,
  value: bigint | string,
  notes: string[],
  note: string,
) => {
  if (params[key]) return false;
  params[key] = typeof value === 'bigint' ? value.toString() : cleanRsaToken(value);
  notes.push(note);
  return true;
};

export const uniqueRsaNumbers = (numbers: string[]) => {
  const seen = new Set<string>();
  return numbers
    .map(raw => ({ raw, value: parseNumericValue(raw) }))
    .filter((entry): entry is { raw: string; value: bigint } => typeof entry.value === 'bigint')
    .filter(entry => {
      const key = entry.value.toString();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
};

export const rsaKnownPairAliases = {
  m: ['m', 'msg', 'message', 'plain', 'plaintext', 'pt', 'cleartext'],
  c: ['c', 'ct', 'cipher', 'ciphertext', 'cyphertext', 'enc', 'encrypted', 'cryptogram'],
};

export const parseRsaKnownPairs = (value: string, params: Record<string, string>) => {
  const fields = parseLooseCtfFields(value);
  const pairs: RsaKnownPair[] = [];
  const addPair = (index: string, rawM: string | undefined, rawC: string | undefined, scopedFields: Record<string, string> = fields) => {
    if (!rawM || !rawC) return;
    const m = parseRsaRecordFieldValue('m', rawM, scopedFields);
    const c = parseRsaRecordFieldValue('c', rawC, scopedFields);
    if (m == null || c == null) return;
    pairs.push({ index, m, c });
  };

  addPair('direct', params.m, params.c);

  for (const { index, fields: blockFields } of parseLooseObjectBlocks(value, 200)) {
    addPair(index, looseField(blockFields, rsaKnownPairAliases.m), looseField(blockFields, rsaKnownPairAliases.c), blockFields);
  }

  for (const { index, record } of parseLooseIndexedRecords(fields, rsaKnownPairAliases, 200)) {
    addPair(String(index), record.m, record.c, record);
  }

  const messageList = looseField(fields, ['messages', 'msgs', 'plaintexts', 'plains', 'mvalues', 'm_list']);
  const cipherList = looseField(fields, ['ciphertexts', 'ciphers', 'cts', 'encryptedvalues', 'cvalues', 'c_list']);
  const messages = messageList ? parseNumericList(messageList) : [];
  const ciphers = cipherList ? parseNumericList(cipherList) : [];
  for (let index = 0; index < Math.min(messages.length, ciphers.length, 200); index += 1) {
    pairs.push({ index: `list-${index}`, m: messages[index], c: ciphers[index] });
  }

  for (const [lineIndex, line] of value.split(/\r?\n/).entries()) {
    if (!/\b(?:m|msg|message|plain|plaintext|pt)\s*[:=]/i.test(line) || !/\b(?:c|ct|cipher|ciphertext|enc)\s*[:=]/i.test(line)) continue;
    const lineFields = parseKeyValueNumbers(line).params;
    addPair(`line-${lineIndex + 1}`, lineFields.m, lineFields.c);
  }

  for (const [lineIndex, line] of value.split(/\r?\n/).entries()) {
    const prosePair = line.match(/\b(?:known\s+pair\s+)?(?:message|msg|plaintext|plain|m)\s*(?:is|=|:|was|equals?)?\s*(0x[0-9a-f_]+|\d[\d_]*)\b[\s\S]*?\b(?:ciphertext|cipher|ct|enc)\s*(?:is|=|:|was|equals?)?\s*(0x[0-9a-f_]+|\d[\d_]*)/i);
    if (prosePair) {
      addPair(`prose-${lineIndex + 1}`, prosePair[1], prosePair[2]);
      continue;
    }
    const reverseProsePair = line.match(/\b(?:ciphertext|cipher|ct|enc)\s*(?:is|=|:|was|equals?)?\s*(0x[0-9a-f_]+|\d[\d_]*)\b[\s\S]*?\b(?:message|msg|plaintext|plain|m)\s*(?:is|=|:|was|equals?)?\s*(0x[0-9a-f_]+|\d[\d_]*)/i);
    if (reverseProsePair) addPair(`prose-rev-${lineIndex + 1}`, reverseProsePair[2], reverseProsePair[1]);
  }

  const unique = new Map<string, RsaKnownPair>();
  for (const pair of pairs) {
    const key = `${pair.m.toString()}:${pair.c.toString()}`;
    if (!unique.has(key)) unique.set(key, pair);
  }
  return Array.from(unique.values());
};

export const rsaCipherRecordAliases = {
  n: ['n', 'mod', 'modulus', 'publicmodulus', 'pubn'],
  e: ['e', 'exp', 'exponent', 'publicexponent', 'pubexp'],
  c: ['c', 'ct', 'cipher', 'ciphertext', 'encrypted', 'cryptogram'],
  m: ['m', 'msg', 'message', 'plain', 'plaintext', 'pt'],
};

export const parseRsaRecordFieldValue = (key: 'n' | 'e' | 'c' | 'm', value: string | undefined, fields: Record<string, string> = {}) => {
  if (!value) return null;
  return parseRsaFieldNumericValue(key, value, fields);
};

export const resolveRsaNumberishToken = (token: string, fields: Record<string, string>) => {
  const cleaned = cleanRsaToken(token);
  const direct = parseRsaFieldNumericValue('n', cleaned, fields);
  if (direct != null) return direct;
  const referenced = fields[normalizeLooseFieldName(cleaned)];
  if (!referenced) return null;
  return parseRsaFieldNumericValue('n', referenced, fields);
};

export const pushRsaCipherRecord = (records: RsaCipherRecord[], record: RsaCipherRecord) => {
  if (record.n == null && record.e == null && record.c == null && record.m == null) return;
  records.push(record);
};

export const collectRsaJsonRecords = (value: unknown, output: RsaCipherRecord[], path = 'json') => {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectRsaJsonRecords(entry, output, `${path}[${index}]`));
    return;
  }
  const object = value as Record<string, unknown>;
  const raw: Record<string, string> = {};
  const record: RsaCipherRecord = {
    index: path,
    n: null,
    e: null,
    c: null,
    m: null,
    raw,
  };
  for (const [key, entry] of Object.entries(object)) {
    const normalized = normalizeRsaParamName(key);
    if (!normalized || !['n', 'e', 'c', 'm'].includes(normalized)) continue;
    const text = cleanSymmetricFieldValue(entry);
    if (!text) continue;
    raw[normalized] = text;
  }
  for (const normalized of ['n', 'e', 'c', 'm'] as const) {
    if (!raw[normalized]) continue;
    record[normalized] = parseRsaRecordFieldValue(normalized, raw[normalized], raw);
  }
  const nestedPublicKey = extractNestedRsaPublicKeyFromObject(object);
  if (nestedPublicKey) {
    record.n ??= nestedPublicKey.n;
    record.e ??= nestedPublicKey.e;
    raw.publickey = cleanSymmetricFieldValue(object[nestedPublicKey.sourceKey]);
  }
  if ((record.n != null || record.e != null) && (record.c != null || record.m != null)) pushRsaCipherRecord(output, record);
  for (const [key, entry] of Object.entries(object)) {
    if (entry && typeof entry === 'object') collectRsaJsonRecords(entry, output, `${path}.${key}`);
  }
};

export const parseRsaNumberishList = (key: 'n' | 'e' | 'c' | 'm', value: string) => {
  const source = String(value || '');
  const tokens = Array.from(source.matchAll(/0x[0-9a-f_]+|\d[\d_]*[nNlL]?|[A-Za-z0-9+/_-]+={0,2}/gi))
    .map(match => match[0])
    .map(token => parseRsaRecordFieldValue(key, token))
    .filter((entry): entry is bigint => typeof entry === 'bigint');
  return tokens;
};

export const parseRsaPublicKeyTuple = (value: string, fields: Record<string, string> = {}) => {
  const tupleMatch = String(value || '').trim().match(/^\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)$/);
  const numbers = tupleMatch
    ? [resolveRsaNumberishToken(tupleMatch[1], fields), resolveRsaNumberishToken(tupleMatch[2], fields)]
    : Array.from(String(value || '').matchAll(/0x[0-9a-f_]+|\d[\d_]*[nNlL]?/gi))
        .map(match => parseNumericValue(match[0]));
  const filtered = numbers.filter((entry): entry is bigint => typeof entry === 'bigint');
  if (filtered.length !== 2) return null;
  const [left, right] = filtered;
  if (isLikelyRsaPublicExponent(left) && right > left) {
    return { n: right, e: left };
  }
  if (isLikelyRsaPublicExponent(right) && left > right) {
    return { n: left, e: right };
  }
  return null;
};

export const rsaStructuredParamKeys = new Set(['n', 'e', 'd', 'p', 'q', 'phi', 'c', 'm', 'dp', 'dq', 'qinv', 'pinv']);

export const tryParseLoosePythonLikeJson = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed || (!trimmed.includes('{') && !trimmed.includes('['))) return null;
  const firstBrace = trimmed.indexOf('{');
  const firstBracket = trimmed.indexOf('[');
  const start = firstBrace < 0 ? firstBracket : firstBracket < 0 ? firstBrace : Math.min(firstBrace, firstBracket);
  if (start < 0) return null;
  const candidate = trimmed.slice(start)
    .replace(/\bTrue\b/g, 'true')
    .replace(/\bFalse\b/g, 'false')
    .replace(/\bNone\b/g, 'null')
    .replace(/'([^'\\]*(?:\\.[^'\\]*)*)'/g, (_, inner) => `"${String(inner).replace(/"/g, '\\"')}"`);
  try {
    return JSON.parse(candidate);
  } catch {
    return null;
  }
};

export const extractNestedRsaPublicKeyFromObject = (object: Record<string, unknown>) => {
  for (const [key, entry] of Object.entries(object)) {
    if (!rsaPublicKeyAliases.some(alias => normalizeLooseFieldName(alias) === normalizeLooseFieldName(key))) continue;
    if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
      const child = entry as Record<string, unknown>;
      const childFields = Object.fromEntries(
        Object.entries(child).map(([childKey, childValue]) => [normalizeLooseFieldName(childKey), cleanSymmetricFieldValue(childValue)])
      );
      const n = parseNumberishUnknown(getObjectAliasValue(child, ['n', 'modulus', 'mod', 'publicn', 'pubn']), childFields);
      const e = parseNumberishUnknown(getObjectAliasValue(child, ['e', 'exponent', 'publicexponent', 'pube', 'pubexp']), childFields);
      if (n != null && e != null) return { n, e, sourceKey: key };
    }
    const tupleText = cleanSymmetricFieldValue(entry);
    const tuple = tupleText ? parseRsaPublicKeyTuple(tupleText) : null;
    if (tuple) return { ...tuple, sourceKey: key };
  }
  return null;
};

export const extractRsaParamsFromStructuredObject = (value: unknown): Record<string, string> | null => {
  if (!value || typeof value !== 'object') return null;
  if (Array.isArray(value)) {
    let merged: Record<string, string> = {};
    for (const entry of value) {
      const nested = extractRsaParamsFromStructuredObject(entry);
      if (!nested) continue;
      merged = { ...nested, ...merged };
    }
    return Object.keys(merged).length ? merged : null;
  }
  const object = value as Record<string, unknown>;
  const params: Record<string, string> = {};
  for (const [key, entry] of Object.entries(object)) {
    const normalized = normalizeRsaParamName(key);
    if (!normalized || !rsaStructuredParamKeys.has(normalized)) continue;
    const text = cleanSymmetricFieldValue(entry);
    if (text) params[normalized] = text;
  }
  const nestedPublicKey = extractNestedRsaPublicKeyFromObject(object);
  if (nestedPublicKey) {
    if (!params.n) params.n = nestedPublicKey.n.toString();
    if (!params.e) params.e = nestedPublicKey.e.toString();
  }
  for (const entry of Object.values(object)) {
    const nested = extractRsaParamsFromStructuredObject(entry);
    if (!nested) continue;
    for (const [key, text] of Object.entries(nested)) {
      if (!params[key]) params[key] = text;
    }
  }
  return Object.keys(params).length ? params : null;
};

export const parseRsaPublicKeyTupleList = (value: string, fields: Record<string, string> = {}) => {
  const records: Array<{ n: bigint; e: bigint }> = [];
  for (const match of String(value || '').matchAll(/\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)/gi)) {
    const parsed = parseRsaPublicKeyTuple(match[0], fields);
    if (parsed) records.push(parsed);
  }
  return records;
};

export const rsaPublicKeyAliases = ['publickey', 'pubkey', 'key', 'pub', 'pk', 'public', 'rsa', 'keypair', 'priv', 'privkey'];

export const collectRsaPublicKeyJsonRecords = (value: unknown, output: RsaPublicKeyRecord[], path = 'json') => {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectRsaPublicKeyJsonRecords(entry, output, `${path}[${index}]`));
    return;
  }
  const object = value as Record<string, unknown>;
  const raw = Object.fromEntries(Object.entries(object).map(([key, entry]) => [key, cleanSymmetricFieldValue(entry)]));
  const normalizedRaw = Object.fromEntries(Object.entries(raw).map(([key, entry]) => [normalizeLooseFieldName(key), entry]));
  const directN = parseNumberishUnknown(getObjectAliasValue(object, ['n', 'modulus', 'mod', 'publicn', 'pubn']), normalizedRaw);
  const directE = parseNumberishUnknown(getObjectAliasValue(object, ['e', 'exponent', 'publicexponent', 'pube', 'pubexp']), normalizedRaw);
  if (directN != null && directE != null) {
    output.push({ index: path, n: directN, e: directE, raw });
  } else {
    const nested = extractNestedRsaPublicKeyFromObject(object);
    if (nested) output.push({ index: path, n: nested.n, e: nested.e, raw });
  }
  for (const [key, entry] of Object.entries(object)) {
    if (entry && typeof entry === 'object') collectRsaPublicKeyJsonRecords(entry, output, `${path}.${key}`);
  }
};

export const parseRsaPublicKeyRecords = (value: string) => {
  const records: RsaPublicKeyRecord[] = [];
  const fields = parseLooseCtfFields(value);

  try {
    collectRsaPublicKeyJsonRecords(JSON.parse(value), records);
  } catch {
    // Many challenge statements are prose or Python-like literals.
  }
  const looseParsed = tryParseLoosePythonLikeJson(value);
  if (looseParsed) collectRsaPublicKeyJsonRecords(looseParsed, records, 'pyjson');

  for (const { index, fields: blockFields } of parseLooseObjectBlocks(value, 200)) {
    const directN = parseRsaRecordFieldValue('n', looseField(blockFields, ['n', 'modulus', 'mod', 'publicn', 'pubn']), blockFields);
    const directE = parseRsaRecordFieldValue('e', looseField(blockFields, ['e', 'exponent', 'publicexponent', 'pube', 'pubexp']), blockFields);
    if (directN != null && directE != null) {
      records.push({
        index,
        n: directN,
        e: directE,
        raw: blockFields,
      });
      continue;
    }
    const tupleText = looseField(blockFields, rsaPublicKeyAliases);
    const tuple = tupleText ? parseRsaPublicKeyTuple(tupleText) : null;
    if (tuple) {
      records.push({
        index,
        n: tuple.n,
        e: tuple.e,
        raw: {
          ...blockFields,
          c: looseField(blockFields, ['c', 'ct', 'cipher', 'ciphertext', 'enc']),
          m: looseField(blockFields, ['m', 'msg', 'message', 'plain', 'plaintext']),
        },
      });
    }
  }

  const tupleListSource = extractBracketedAssignment(value, ['publickeys', 'pubkeys', 'keys', 'keylist', 'publickeylist'])
    || looseField(fields, ['publickeys', 'pubkeys', 'keys', 'keylist', 'publickeylist']);
  parseRsaPublicKeyTupleList(tupleListSource).forEach((entry, index) => {
    records.push({
      index: `pubkeylist-${index}`,
      n: entry.n,
      e: entry.e,
      raw: {},
    });
  });

  for (const [lineIndex, line] of value.split(/\r?\n/).entries()) {
    const compactPublicKey = line.match(/\b(?:public[_\s-]?key|pubkey|key)\s*[:=]\s*\(([^)]+)\)/i);
    if (!compactPublicKey) continue;
    const parsed = parseRsaPublicKeyTuple(compactPublicKey[1]);
    if (!parsed) continue;
    const lineFields = parseLooseCtfFields(line);
    records.push({
      index: `pubkey-line-${lineIndex + 1}`,
      n: parsed.n,
      e: parsed.e,
      raw: {
        publickey: compactPublicKey[1],
        ...lineFields,
      },
    });
  }

  for (let index = 0; index <= 200; index += 1) {
    const tupleText = looseField(fields, [
      `publickey${index}`,
      `pubkey${index}`,
      `pk${index}`,
      `keypair${index}`,
      `key${index}`,
      `${index}publickey`,
      `${index}pubkey`,
      `${index}pk`,
      `${index}keypair`,
      `${index}key`,
    ]);
    if (!tupleText) continue;
    const parsed = parseRsaPublicKeyTuple(tupleText);
    if (!parsed) continue;
    records.push({
      index: `tuple-${index}`,
      n: parsed.n,
      e: parsed.e,
      raw: {
        publickey: tupleText,
        ciphertext: looseField(fields, [`ciphertext${index}`, `cipher${index}`, `ct${index}`, `enc${index}`, `${index}ciphertext`, `${index}cipher`, `${index}ct`]),
        message: looseField(fields, [`message${index}`, `msg${index}`, `plaintext${index}`, `plain${index}`, `m${index}`, `${index}message`, `${index}msg`]),
      },
    });
  }

  const unique = new Map<string, RsaPublicKeyRecord>();
  for (const record of records) {
    const key = `${record.n.toString()}:${record.e.toString()}`;
    const existing = unique.get(key);
    const score = Number(Boolean(record.raw.ciphertext || record.raw.c || record.raw.message || record.raw.m))
      + Object.keys(record.raw).length;
    const existingScore = existing
      ? Number(Boolean(existing.raw.ciphertext || existing.raw.c || existing.raw.message || existing.raw.m))
        + Object.keys(existing.raw).length
      : -1;
    if (!existing || score > existingScore) unique.set(key, record);
  }
  return Array.from(unique.values());
};

export const parseRsaCipherRecords = (value: string, params: Record<string, string>) => {
  const fields = parseLooseCtfFields(value);
  const records: RsaCipherRecord[] = [];
  const sharedDirect = {
    n: parseRsaRecordFieldValue('n', params.n, params),
    e: parseRsaRecordFieldValue('e', params.e, params),
    c: parseRsaRecordFieldValue('c', params.c, params),
    m: parseRsaRecordFieldValue('m', params.m, params),
  };

  try {
    collectRsaJsonRecords(JSON.parse(value), records);
  } catch {
    // Most RSA challenge statements are prose or flat snippets.
  }
  const looseParsed = tryParseLoosePythonLikeJson(value);
  if (looseParsed) collectRsaJsonRecords(looseParsed, records, 'pyjson');

  if (params.n || params.e || params.c || params.m) {
    pushRsaCipherRecord(records, {
      index: 'direct',
      n: parseRsaRecordFieldValue('n', params.n, params),
      e: parseRsaRecordFieldValue('e', params.e, params),
      c: parseRsaRecordFieldValue('c', params.c, params),
      m: parseRsaRecordFieldValue('m', params.m, params),
      raw: Object.fromEntries(Object.entries(params).filter(([key]) => ['n', 'e', 'c', 'm'].includes(key))),
    });
  }

  for (const { index, fields: blockFields } of parseLooseObjectBlocks(value, 200)) {
    const raw: Record<string, string> = {};
    const record: RsaCipherRecord = {
      index,
      n: null,
      e: null,
      c: null,
      m: null,
      raw,
    };
    for (const [key, entry] of Object.entries(blockFields)) {
      const normalized = normalizeRsaParamName(key);
      if (!normalized || !['n', 'e', 'c', 'm'].includes(normalized)) continue;
      const normalizedRecordKey = normalized as 'n' | 'e' | 'c' | 'm';
      raw[normalizedRecordKey] = entry;
      record[normalizedRecordKey] = parseRsaRecordFieldValue(normalizedRecordKey, entry, blockFields);
    }
    if ((record.n != null || record.e != null) && (record.c != null || record.m != null)) pushRsaCipherRecord(records, record);
  }

  for (const { index, record } of parseLooseIndexedRecords(fields, rsaCipherRecordAliases, 200)) {
    pushRsaCipherRecord(records, {
      index: String(index),
      n: parseRsaRecordFieldValue('n', record.n),
      e: parseRsaRecordFieldValue('e', record.e, record),
      c: parseRsaRecordFieldValue('c', record.c, record),
      m: parseRsaRecordFieldValue('m', record.m, record),
      raw: record,
    });
  }

  const nList = parseRsaNumberishList('n', looseField(fields, ['ns', 'moduli', 'nvalues', 'n_list', 'moduluslist']));
  const eList = parseRsaNumberishList('e', looseField(fields, ['es', 'exponents', 'evalues', 'e_list', 'explist']));
  const cList = parseRsaNumberishList('c', looseField(fields, ['cs', 'ciphertexts', 'ciphers', 'cvalues', 'c_list', 'cts']));
  const mList = parseRsaNumberishList('m', looseField(fields, ['ms', 'messages', 'plaintexts', 'mvalues', 'm_list']));
  const publicKeyRecords = parseRsaPublicKeyRecords(value);
  const maxListLength = Math.max(nList.length, eList.length, cList.length, mList.length);
  if (maxListLength >= 2) {
    for (let index = 0; index < maxListLength; index += 1) {
      pushRsaCipherRecord(records, {
        index: `list-${index}`,
        n: nList[index] ?? null,
        e: eList[index] ?? null,
        c: cList[index] ?? null,
        m: mList[index] ?? null,
        raw: {},
      });
    }
  }
  if (publicKeyRecords.length >= 1) {
    const pairCount = Math.max(publicKeyRecords.length, cList.length, mList.length);
    for (let index = 0; index < pairCount; index += 1) {
      const keyPair = publicKeyRecords[index] || null;
      const inlineCipher = keyPair ? parseRsaRecordFieldValue('c', looseField(keyPair.raw, ['c', 'ct', 'cipher', 'ciphertext', 'enc']), keyPair.raw) : null;
      const inlineMessage = keyPair ? parseRsaRecordFieldValue('m', looseField(keyPair.raw, ['m', 'msg', 'message', 'plain', 'plaintext']), keyPair.raw) : null;
      pushRsaCipherRecord(records, {
        index: `pubkeylist-${index}`,
        n: keyPair?.n ?? null,
        e: keyPair?.e ?? null,
        c: inlineCipher ?? cList[index] ?? null,
        m: inlineMessage ?? mList[index] ?? null,
        raw: keyPair?.raw || {},
      });
    }
  }

  for (const [lineIndex, line] of value.split(/\r?\n/).entries()) {
    if (!/\bn\s*[:=]/i.test(line) || !/\be\s*[:=]/i.test(line) || !/\bc\s*[:=]/i.test(line)) continue;
    const lineFields = parseKeyValueNumbers(line).params;
    pushRsaCipherRecord(records, {
      index: `line-${lineIndex + 1}`,
      n: parseRsaRecordFieldValue('n', lineFields.n),
      e: parseRsaRecordFieldValue('e', lineFields.e),
      c: parseRsaRecordFieldValue('c', lineFields.c),
      m: parseRsaRecordFieldValue('m', lineFields.m),
      raw: lineFields,
    });
  }

  for (const [lineIndex, line] of value.split(/\r?\n/).entries()) {
    const compactPublicKey = line.match(/\b(?:public[_\s-]?key|pubkey|key)\s*[:=]\s*\(([^)]+)\)/i);
    if (!compactPublicKey) continue;
    const parsed = parseRsaPublicKeyTuple(compactPublicKey[1]);
    if (!parsed) continue;
    const lineFields = parseLooseCtfFields(line);
    pushRsaCipherRecord(records, {
      index: `pubkey-line-${lineIndex + 1}`,
      n: parsed.n,
      e: parsed.e,
      c: parseRsaRecordFieldValue('c', looseField(lineFields, ['c', 'ct', 'cipher', 'ciphertext', 'enc']), lineFields),
      m: parseRsaRecordFieldValue('m', looseField(lineFields, ['m', 'msg', 'message', 'plain', 'plaintext']), lineFields),
      raw: {
        publickey: compactPublicKey[1],
        ...lineFields,
      },
    });
  }

  for (const record of records) {
    if (record.index === 'direct') continue;
    record.n ??= sharedDirect.n;
    record.e ??= sharedDirect.e;
    record.c ??= sharedDirect.c;
    record.m ??= sharedDirect.m;
  }

  const unique = new Map<string, RsaCipherRecord>();
  for (const record of records) {
    const key = [
      record.n?.toString() || '',
      record.e?.toString() || '',
      record.c?.toString() || '',
      record.m?.toString() || '',
    ].join(':');
    if (!unique.has(key)) unique.set(key, record);
  }
  return Array.from(unique.values());
};

export const bigintPowIfReasonable = (base: bigint, exponent: bigint, maxBits = 16384) => {
  if (exponent < 0n) return null;
  if (base === 0n || base === 1n || exponent <= 1n) return base ** exponent;
  if (exponent > 65537n) return null;
  const estimatedBits = bitLength(base) * Number(exponent);
  if (estimatedBits > maxBits) return null;
  let result = 1n;
  let current = base;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result *= current;
    power >>= 1n;
    if (power > 0n) current *= current;
    if (bitLength(result) > maxBits || bitLength(current) > maxBits) return null;
  }
  return result;
};

export const inferRsaModulusFromKnownPairs = (pairs: RsaKnownPair[], exponent: bigint) => {
  const diffs: Array<{ index: string; diff: bigint }> = [];
  for (const pair of pairs) {
    const powered = bigintPowIfReasonable(pair.m, exponent);
    if (powered == null) continue;
    const diff = bigintAbs(powered - pair.c);
    if (diff > 1n) diffs.push({ index: pair.index, diff });
  }
  if (diffs.length < 2) return null;
  const modulus = diffs.reduce((current, entry) => current === 0n ? entry.diff : bigintGcd(current, entry.diff), 0n);
  const maxObserved = pairs.reduce((current, pair) => pair.m > current ? pair.m : pair.c > current ? pair.c : current, 0n);
  if (modulus <= 1n || modulus <= maxObserved) return null;
  return {
    modulus,
    pairCount: diffs.length,
    evidence: diffs.map(entry => entry.index),
  };
};

export const normalizeRsaJwkField = (value: unknown) => {
  if (typeof value !== 'string') return '';
  return cleanRsaToken(value).replace(/\s+/g, '');
};

export const extractRsaParamsFromJwkObject = (value: unknown): Record<string, string> | null => {
  if (!value || typeof value !== 'object') return null;
  if (Array.isArray(value)) {
    for (const entry of value) {
      const nested = extractRsaParamsFromJwkObject(entry);
      if (nested) return nested;
    }
    return null;
  }
  const record = value as Record<string, unknown>;
  if (Array.isArray(record.keys)) {
    const fromKeys = extractRsaParamsFromJwkObject(record.keys);
    if (fromKeys) return fromKeys;
  }
  const looksLikeRsa = record.kty === 'RSA' || ('n' in record && 'e' in record);
  if (looksLikeRsa) {
    const params: Record<string, string> = {};
    for (const [sourceKey, targetKey] of [['n', 'n'], ['e', 'e'], ['d', 'd'], ['p', 'p'], ['q', 'q'], ['dp', 'dp'], ['dq', 'dq'], ['qi', 'qinv']] as const) {
      const raw = normalizeRsaJwkField(record[sourceKey]);
      if (raw) params[targetKey] = raw;
    }
    if (params.n || params.e || params.d) return params;
  }
  for (const nestedValue of Object.values(record)) {
    const nested = extractRsaParamsFromJwkObject(nestedValue);
    if (nested) return nested;
  }
  return null;
};

export const extractRsaParamsFromJwkLike = (value: string) => {
  const candidates = [value.trim()];
  const fenced = value.match(/```(?:json|jwk|jwks)?\s*([\s\S]+?)```/i);
  if (fenced?.[1]) candidates.push(fenced[1].trim());
  const firstBrace = value.indexOf('{');
  const lastBrace = value.lastIndexOf('}');
  if (firstBrace >= 0 && lastBrace > firstBrace) candidates.push(value.slice(firstBrace, lastBrace + 1).trim());

  for (const candidate of candidates.filter(Boolean)) {
    try {
      const parsed = JSON.parse(candidate);
      const params = extractRsaParamsFromJwkObject(parsed);
      if (params) return params;
    } catch {
      // Keep trying looser JSON candidates extracted from prose or code blocks.
    }
  }
  return null;
};

export const sshMpintToBigInt = (bytes: Uint8Array) => {
  const stripped = bytes.length > 1 && bytes[0] === 0 ? bytes.slice(1) : bytes;
  return bigintFromBytes(stripped);
};

export const extractRsaParamsFromOpenSsh = (value: string) => {
  try {
    const tokens = value.trim().split(/\s+/);
    const keyIndex = tokens.findIndex(token => token === 'ssh-rsa');
    if (keyIndex < 0 || !tokens[keyIndex + 1]) return null;
    const blob = base64ToBytes(tokens[keyIndex + 1]);
    const typeField = readSshString(blob, 0);
    if (typeField.text !== 'ssh-rsa') return null;
    const exponent = readSshString(blob, typeField.next);
    const modulus = readSshString(blob, exponent.next);
    return {
      e: sshMpintToBigInt(exponent.data).toString(),
      n: sshMpintToBigInt(modulus.data).toString(),
    };
  } catch {
    return null;
  }
};


export const findRsaIntegerSequences = (nodes: Asn1Node[]) => {
  const sequences: bigint[][] = [];
  const visit = (node: Asn1Node) => {
    const integerChildren = (node.children || []).map(child => asn1IntegerValue(child)).filter((entry): entry is bigint => typeof entry === 'bigint');
    if (integerChildren.length >= 2) sequences.push(integerChildren);
    for (const child of node.children || []) visit(child);
  };
  for (const node of nodes) visit(node);
  return sequences;
};

export const extractRsaParamsFromPem = (value: string) => {
  if (!/-----BEGIN (?:(?:RSA )?(?:PUBLIC|PRIVATE) KEY|CERTIFICATE)-----/.test(value)) return null;
  try {
    const input = parseAsn1Input(value);
    const state = { count: 0 };
    const sequences = findRsaIntegerSequences(parseAsn1TopLevel(input.bytes, 0, state));
    const params: Record<string, string> = {};
    for (const integers of sequences) {
      if (integers.length >= 9 && integers[0] === 0n && isLikelyRsaPublicExponent(integers[2])) {
        [params.n, params.e, params.d, params.p, params.q, params.dp, params.dq, params.qinv] = integers.slice(1, 9).map(entry => entry.toString());
        return params;
      }
      if (integers.length >= 2 && integers[0] > integers[1] && isLikelyRsaPublicExponent(integers[1])) {
        params.n = integers[0].toString();
        params.e = integers[1].toString();
        return params;
      }
    }
  } catch {
    return null;
  }
  return null;
};

export const inferRsaParamsFromText = (value: string, direction: Direction = 'decode'): RsaInference => {
  const parsed = parseKeyValueNumbers(value);
  const params: Record<string, string> = { ...parsed.params };
  const notes: string[] = [];
  let confidence = Object.keys(params).length * 2;
  const looseFields = parseLooseCtfFields(value);

  const jwkParams = extractRsaParamsFromJwkLike(value);
  if (jwkParams) {
    for (const [key, entry] of Object.entries(jwkParams)) {
      if (!params[key]) params[key] = entry;
    }
    confidence += 4;
    notes.push('从 JWK / JWKS 中提取了可用 RSA 参数');
  }

  const sshParams = extractRsaParamsFromOpenSsh(value);
  if (sshParams) {
    for (const [key, entry] of Object.entries(sshParams)) {
      if (!params[key]) params[key] = entry;
    }
    confidence += 4;
    notes.push('从 OpenSSH ssh-rsa 公钥中提取了 n 和 e');
  }

  const pemParams = extractRsaParamsFromPem(value);
  if (pemParams) {
    for (const [key, entry] of Object.entries(pemParams)) {
      if (!params[key]) params[key] = entry;
    }
    confidence += 4;
    notes.push('从 PEM/ASN.1 RSA key 中提取了可用参数');
  }

  try {
    const structuredParams = extractRsaParamsFromStructuredObject(JSON.parse(value));
    if (structuredParams) {
      for (const [key, entry] of Object.entries(structuredParams)) {
        if (!params[key]) params[key] = entry;
      }
      confidence += 3;
      notes.push('从嵌套 JSON / 代码风格对象中提取了可用 RSA 参数');
    }
  } catch {
    // Many challenge texts are not strict JSON.
  }
  const looseStructured = tryParseLoosePythonLikeJson(value);
  if (looseStructured) {
    const structuredParams = extractRsaParamsFromStructuredObject(looseStructured);
    if (structuredParams) {
      for (const [key, entry] of Object.entries(structuredParams)) {
        if (!params[key]) params[key] = entry;
      }
      confidence += 3;
      notes.push('从 Python 风格单引号对象中提取了可用 RSA 参数');
    }
  }

  const tuplePattern = /\(\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*,\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*\)/gi;
  // Extract pow(c, e_or_d, n) — common in CTF challenge scripts
  for (const match of value.matchAll(/\bpow\s*\(\s*(0x[0-9a-f_]+|\d[\d_]*)\s*,\s*(0x[0-9a-f_]+|\d[\d_]*)\s*,\s*(0x[0-9a-f_]+|\d[\d_]*)\s*\)/gi)) {
    const arg0 = parseNumericValue(match[1]);
    const arg1 = parseNumericValue(match[2]);
    const arg2 = parseNumericValue(match[3]);
    if (typeof arg0 !== 'bigint' || typeof arg1 !== 'bigint' || typeof arg2 !== 'bigint') continue;
    if (!params.n && !params.c && !params.e && isLikelyRsaPublicExponent(arg1) && arg2 > arg1 && arg0 < arg2) {
      params.c = arg0.toString(); params.e = arg1.toString(); params.n = arg2.toString();
      confidence += 3; notes.push('从 pow(c, e, n) 表达式中提取 c/e/n');
    } else if (!params.n && !params.c && !params.d && arg1 > 100n && arg2 > arg1 && arg0 < arg2) {
      if (!params.c) params.c = arg0.toString();
      if (!params.n) params.n = arg2.toString();
      confidence += 2; notes.push('从 pow(c, d, n) 表达式中推断 c/n');
    }
  }
  for (const match of value.matchAll(tuplePattern)) {
    const left = parseNumericValue(match[1]);
    const right = parseNumericValue(match[2]);
    if (typeof left !== 'bigint' || typeof right !== 'bigint') continue;
    if (!params.n && !params.e && isLikelyRsaPublicExponent(left) && right > left) {
      params.e = left.toString();
      params.n = right.toString();
      confidence += 3;
      notes.push('从 tuple 中按 (e, n) 推断公钥');
    } else if (!params.n && !params.e && isLikelyRsaPublicExponent(right) && left > right) {
      params.n = left.toString();
      params.e = right.toString();
      confidence += 3;
      notes.push('从 tuple 中按 (n, e) 推断公钥');
    }
  }

  const numbers = uniqueRsaNumbers(parsed.looseNumbers);
  const usedValues = () => new Set(Object.values(params)
    .map(entry => parseNumericValue(entry))
    .filter((entry): entry is bigint => typeof entry === 'bigint')
    .map(entry => entry.toString()));

  let n = rsaParamNumber(params, 'n');
  if (!params.e) {
    const exponentCandidates = numbers.filter(entry => isCommonRsaPublicExponent(entry.value));
    if (exponentCandidates.length === 1 && rememberInferredRsaParam(params, 'e', exponentCandidates[0].value, notes, `从未标注数字中推断 e=${exponentCandidates[0].value.toString()}。`)) {
      confidence += 2;
    }
  }

  n = rsaParamNumber(params, 'n');
  const publicExponent = rsaParamNumber(params, 'e');
  const knownPairs = parseRsaKnownPairs(value, params);
  if (knownPairs.length >= 2) confidence += 2;
  if (!params.n && publicExponent && knownPairs.length >= 2) {
    const modulusFromPairs = inferRsaModulusFromKnownPairs(knownPairs, publicExponent);
    if (modulusFromPairs && rememberInferredRsaParam(params, 'n', modulusFromPairs.modulus, notes, `从 ${modulusFromPairs.pairCount} 组 m/c 明密文对计算 gcd(m^e-c)，推断 n 候选。`)) {
      confidence += 4;
    }
  }
  if (n && (!params.p || !params.q)) {
    const sumHint = (() => {
      const explicit = looseField(looseFields, ['pplusq', 'sumofprimes', 'primesum', 'sumprimes', 'pqsum']);
      if (explicit) return parseNumericValue(explicit);
      const inline = value.match(/\bp\s*\+\s*q\s*(?:is|=|:|was|equals?)\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)/i);
      if (inline) return parseNumericValue(inline[1]);
      const reverse = value.match(/\b(?:sum|hint)\s*(?:is|=|:|was|equals?)\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)[^\n]*\bp\s*\+\s*q\b/i);
      return reverse ? parseNumericValue(reverse[1]) : null;
    })();
    if (typeof sumHint === 'bigint') {
      const discriminant = sumHint * sumHint - 4n * n;
      if (discriminant >= 0n) {
        const root = bigIntSqrt(discriminant);
        if (root * root === discriminant) {
          const left = sumHint + root;
          const right = sumHint - root;
          if ((left & 1n) === 0n && (right & 1n) === 0n) {
            const pCandidate = left / 2n;
            const qCandidate = right / 2n;
            if (pCandidate > 1n && qCandidate > 1n && pCandidate * qCandidate === n) {
              if (rememberInferredRsaParam(params, 'p', pCandidate, notes, '由 n 与 (p+q) 提示恢复 p')) confidence += 3;
              if (rememberInferredRsaParam(params, 'q', qCandidate, notes, '由 n 与 (p+q) 提示恢复 q')) confidence += 3;
            }
          }
        }
      }
    }

    const diffHint = (() => {
      const explicit = looseField(looseFields, ['pminusq', 'qminusp', 'differenceofprimes', 'primediff', 'pqdiff']);
      if (explicit) return parseNumericValue(explicit);
      const inline = value.match(/\b(?:p\s*-\s*q|q\s*-\s*p)\s*(?:is|=|:|was|equals?)\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)/i);
      if (inline) return parseNumericValue(inline[1]);
      const reverse = value.match(/\b(?:difference|diff|hint)\s*(?:is|=|:|was|equals?)\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)[^\n]*\b(?:p\s*-\s*q|q\s*-\s*p)\b/i);
      return reverse ? parseNumericValue(reverse[1]) : null;
    })();
    if (typeof diffHint === 'bigint') {
      const normalizedDiff = bigintAbs(diffHint);
      const discriminant = normalizedDiff * normalizedDiff + 4n * n;
      const root = bigIntSqrt(discriminant);
      if (root * root === discriminant) {
        const left = root + normalizedDiff;
        const right = root - normalizedDiff;
        if ((left & 1n) === 0n && (right & 1n) === 0n) {
          const pCandidate = left / 2n;
          const qCandidate = right / 2n;
          if (pCandidate > 1n && qCandidate > 1n && pCandidate * qCandidate === n) {
            if (rememberInferredRsaParam(params, 'p', pCandidate, notes, '由 n 与 |p-q| 提示恢复 p')) confidence += 3;
            if (rememberInferredRsaParam(params, 'q', qCandidate, notes, '由 n 与 |p-q| 提示恢复 q')) confidence += 3;
          }
        }
      }
    }

    for (let left = 0; left < numbers.length; left += 1) {
      for (let right = left + 1; right < numbers.length; right += 1) {
        if (numbers[left].value * numbers[right].value === n) {
          if (rememberInferredRsaParam(params, 'p', numbers[left].value, notes, '从未标注数字中识别 p*q=n')) confidence += 2;
          if (rememberInferredRsaParam(params, 'q', numbers[right].value, notes, '从未标注数字中识别 p*q=n')) confidence += 2;
        }
      }
    }
  }

  if (!params.n && (!params.p || !params.q) && publicExponent) {
    const remaining = numbers.filter(entry => entry.value !== publicExponent);
    let best: { p: bigint; q: bigint; c: bigint; product: bigint } | null = null;
    for (let left = 0; left < remaining.length; left += 1) {
      for (let right = left + 1; right < remaining.length; right += 1) {
        const product = remaining[left].value * remaining[right].value;
        const ciphertext = remaining
          .filter((_, index) => index !== left && index !== right)
          .map(entry => entry.value)
          .sort((a, b) => Number(b - a))[0];
        if (ciphertext && product > ciphertext) {
          if (!best || product < best.product) best = { p: remaining[left].value, q: remaining[right].value, c: ciphertext, product };
        }
      }
    }
    if (best) {
      if (rememberInferredRsaParam(params, 'p', best.p, notes, '从 p/q/e/c 形态的未标注数字中推断 p')) confidence += 2;
      if (rememberInferredRsaParam(params, 'q', best.q, notes, '从 p/q/e/c 形态的未标注数字中推断 q')) confidence += 2;
      if (direction === 'decode' && rememberInferredRsaParam(params, 'c', best.c, notes, '从 p/q/e/c 形态的未标注数字中推断 c')) confidence += 2;
    }
  }

  n = rsaParamNumber(params, 'n') || (rsaParamNumber(params, 'p') && rsaParamNumber(params, 'q') ? rsaParamNumber(params, 'p')! * rsaParamNumber(params, 'q')! : null);
  if (n && direction === 'decode' && !params.c) {
    const consumed = usedValues();
    const ciphertext = numbers
      .filter(entry => !consumed.has(entry.value.toString()) && entry.value < n)
      .sort((left, right) => Number(right.value - left.value))[0];
    if (ciphertext && rememberInferredRsaParam(params, 'c', ciphertext.value, notes, '从未标注数字中按 c<n 推断 ciphertext')) confidence += 2;
  }

  if (!params.n && !params.p && !params.q && publicExponent && direction === 'decode' && !params.c) {
    const remaining = numbers
      .filter(entry => entry.value !== publicExponent)
      .sort((left, right) => Number(right.value - left.value));
    if (remaining.length >= 2) {
      if (rememberInferredRsaParam(params, 'n', remaining[0].value, notes, '从 n/e/c 三元数字中按最大值推断 n')) confidence += 2;
      if (rememberInferredRsaParam(params, 'c', remaining[1].value, notes, '从 n/e/c 三元数字中按 c<n 推断 ciphertext')) confidence += 2;
    }
  }

  if (Object.keys(parsed.params).length === 0 && notes.length) confidence += 1;
  return { params, looseNumbers: parsed.looseNumbers, confidence, notes, knownPairs };
};

export const parseRsaMessageValue = (value: string, labelText: string) => {
  const numeric = parseNumericValue(value);
  if (typeof numeric === 'bigint') return { value: numeric, source: 'number' };
  const parsed = parseHexBase64OrUtf8Bytes(value, labelText);
  return { value: bigintFromBytes(parsed.bytes), source: parsed.format };
};

export type RsaMessageValue = ReturnType<typeof parseRsaMessageValue>;

export const parseRsaMessageValues = (value: string, labelText: string): RsaMessageValue[] => {
  const text = String(value || '').trim();
  const numeric = parseNumericValue(text);
  if (typeof numeric === 'bigint') return [{ value: numeric, source: 'number' }];
  const numericTokens = parseNumericList(text);
  const looksLikeList = numericTokens.length > 1
    || (numericTokens.length === 1 && /[[\],;\n]/.test(text));
  if (looksLikeList && numericTokens.length) {
    return numericTokens.map((entry, index) => ({ value: entry, source: `number-list-${index}` }));
  }
  return [parseRsaMessageValue(text, labelText)];
};


export const rsaValuesResult = (values: bigint[]) => {
  const blockResults = values.map((value, index) => ({
    index,
    ...rsaNumberResult(value),
  }));
  const combinedBytes = concatBytes(...values.map(value => bigintToBytes(value)));
  const combinedUtf8 = utf8Decoder.decode(combinedBytes).replace(/\p{Cc}/gu, '.');
  const flagMatch = combinedUtf8.match(/(?:flag|ctf|picoctf|htb|thm|ductf|corctf|dice|wctf|utflag|pctf|uiuctf|sekai|key|crypto)\{[^}]*\}/i);
  return {
    blockCount: values.length,
    blocks: blockResults,
    combined: {
      bytes: combinedBytes.length,
      hex: bytesToHex(combinedBytes),
      utf8Preview: combinedUtf8,
      ...(flagMatch ? { flag: flagMatch[0] } : {}),
    },
  };
};



export const tonelliShanksRoot = (value: bigint, prime: bigint) => {
  const n = bigintMod(value, prime);
  if (prime === 2n) return n;
  if (n === 0n) return 0n;
  const legendre = bigintModPow(n, (prime - 1n) / 2n, prime);
  if (legendre !== 1n) return null;
  if (prime % 4n === 3n) return bigintModPow(n, (prime + 1n) / 4n, prime);

  let q = prime - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s += 1n;
  }

  let z = 2n;
  while (bigintModPow(z, (prime - 1n) / 2n, prime) !== prime - 1n) z += 1n;

  let c = bigintModPow(z, q, prime);
  let x = bigintModPow(n, (q + 1n) / 2n, prime);
  let t = bigintModPow(n, q, prime);
  let m = s;

  while (t !== 1n) {
    let i = 1n;
    let t2i = bigintModPow(t, 2n, prime);
    while (i < m && t2i !== 1n) {
      t2i = bigintModPow(t2i, 2n, prime);
      i += 1n;
    }
    if (i === m) return null;
    const b = bigintModPow(c, 1n << (m - i - 1n), prime);
    x = bigintMod(x * b, prime);
    t = bigintMod(t * b * b, prime);
    c = bigintMod(b * b, prime);
    m = i;
  }

  return bigintMod(x, prime);
};

export const rabinRootsModPrime = (value: bigint, prime: bigint) => {
  const root = tonelliShanksRoot(value, prime);
  if (root == null) return [];
  const other = bigintMod(prime - root, prime);
  return root === other ? [root] : [root, other];
};

export const uniqueBigints = (values: bigint[]) => {
  const seen = new Set<string>();
  return values.filter(value => {
    const key = value.toString();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

export const rabinRawTransform = (direction: Direction, value: string) => {
  const inference = inferRsaParamsFromText(value, direction);
  const { params } = inference;

  let p = rsaParamNumber(params, 'p');
  let q = rsaParamNumber(params, 'q');
  const explicitN = rsaParamNumber(params, 'n');
  const factoredN = explicitN && (!p || !q) ? factorSmallRsaModulus(explicitN) : null;
  if (factoredN) {
    [p, q] = factoredN;
    inference.notes.push('Factored small n locally for Rabin decryption using bounded trial division, Fermat, or Pollard Rho.');
  }
  const n = explicitN || (typeof p === 'bigint' && typeof q === 'bigint' ? p * q : null);
  if (typeof n !== 'bigint') throw new Error('Rabin raw requires n, or p and q');

  if (direction === 'encode') {
    if (!params.m) throw new Error('Rabin encrypt requires m/message/plaintext');
    const inputBlocks = parseRsaMessageValues(params.m, 'message');
    for (const input of inputBlocks) {
      if (input.value >= n) throw new Error('Rabin input must be smaller than modulus n');
    }
    const outputs = inputBlocks.map(input => bigintMod(input.value * input.value, n));
    return JSON.stringify({
      alg: 'Rabin Raw',
      direction,
      nBits: bitLength(n),
      modulus: n.toString(),
      inference: inference.notes,
      input: inputBlocks.map((block, index) => ({
        index,
        source: block.source,
        ...rsaNumberResult(block.value),
      })),
      output: outputs.length === 1 ? rsaNumberResult(outputs[0]) : rsaValuesResult(outputs),
      warning: 'Rabin raw returns multiple roots on decrypt; you must validate which candidate matches the challenge context.',
    }, null, 2);
  }

  if (!params.c) throw new Error('Rabin decrypt requires c/ciphertext');
  if (typeof p !== 'bigint' || typeof q !== 'bigint') {
    throw new Error('Rabin decrypt requires p and q, or a factorable small n');
  }
  const inputBlocks = parseRsaMessageValues(params.c, 'ciphertext');
  for (const input of inputBlocks) {
    if (input.value >= n) throw new Error('Rabin input must be smaller than modulus n');
  }

  const outputs = inputBlocks.map(input => {
    const rootsP = rabinRootsModPrime(input.value, p as bigint);
    const rootsQ = rabinRootsModPrime(input.value, q as bigint);
    if (!rootsP.length || !rootsQ.length) {
      throw new Error('Ciphertext is not a quadratic residue modulo p or q');
    }
    const roots = uniqueBigints(
      rootsP.flatMap(rootP => rootsQ.map(rootQ => crtCombinePair(rootP, p as bigint, rootQ, q as bigint))),
    ).sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    return {
      source: input.source,
      ciphertext: rsaNumberResult(input.value),
      candidates: roots.map((root, index) => ({
        index,
        ...rsaNumberResult(root),
      })),
    };
  });

  return JSON.stringify({
    alg: 'Rabin Raw',
    direction,
    nBits: bitLength(n),
    modulus: n.toString(),
    factors: {
      p: p.toString(),
      q: q.toString(),
    },
    inference: inference.notes,
    input: inputBlocks.map((block, index) => ({
      index,
      source: block.source,
      ...rsaNumberResult(block.value),
    })),
    output: outputs.length === 1 ? outputs[0] : outputs,
    warning: 'Rabin decryption returns multiple valid roots; identify the right plaintext by format, flag prefix, padding, or challenge metadata.',
  }, null, 2);
};

export const bigintPowCompare = (base: bigint, exponent: bigint, limit: bigint) => {
  let result = 1n;
  let current = base;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) {
      result *= current;
      if (result > limit) return 1;
    }
    power >>= 1n;
    if (power > 0n) {
      current *= current;
      if (current > limit && power > 1n) current = limit + 1n;
    }
  }
  return result === limit ? 0 : -1;
};

export const bigintNthRootExact = (value: bigint, degree: bigint) => {
  if (degree <= 0n) return null;
  if (value < 0n) return null;
  if (value < 2n || degree === 1n) return { root: value, exact: true };
  let low = 0n;
  let high = 1n;
  while (bigintPowCompare(high, degree, value) <= 0) high <<= 1n;
  while (high - low > 1n) {
    const mid = (low + high) >> 1n;
    const comparison = bigintPowCompare(mid, degree, value);
    if (comparison <= 0) low = mid;
    else high = mid;
  }
  return { root: low, exact: bigintPowCompare(low, degree, value) === 0 };
};

export const tryRsaLowExponentRoots = (blocks: RsaMessageValue[], exponent: bigint, n?: bigint | null) => {
  if (exponent < 2n || exponent > 17n) return null;
  // Try exact root first
  const exactRoots = blocks.map(block => bigintNthRootExact(block.value, exponent));
  if (exactRoots.every(r => r?.exact)) return exactRoots.map(r => r!.root);
  // miniRSA / padded: try (c + k*n)^(1/e) for k = 0..2000
  if (!n || blocks.length !== 1) return null;
  const c = blocks[0].value;
  for (let k = 1n; k <= 2000n; k++) {
    const candidate = c + k * n;
    const result = bigintNthRootExact(candidate, exponent);
    if (result?.exact) return [result.root];
  }
  return null;
};

export const rsaCrtDecrypt = (
  ciphertext: bigint,
  p: bigint,
  q: bigint,
  dp: bigint,
  dq: bigint,
  qInvInput: bigint | null,
  pInvInput: bigint | null,
) => {
  const m1 = bigintModPow(ciphertext, dp, p);
  const m2 = bigintModPow(ciphertext, dq, q);
  const validQInv = qInvInput != null && (q * qInvInput) % p === 1n ? qInvInput : null;
  const validPInv = pInvInput != null && (p * pInvInput) % q === 1n ? pInvInput : null;
  const fallbackQInv = validQInv || bigintModInverse(q, p);
  if (fallbackQInv != null) {
    const h = (((m1 - m2) * fallbackQInv) % p + p) % p;
    return {
      value: (m2 + q * h) % (p * q),
      crt: {
        convention: 'qInv = q^-1 mod p',
        m1: m1.toString(),
        m2: m2.toString(),
      },
    };
  }
  const fallbackPInv = validPInv || (qInvInput != null && (p * qInvInput) % q === 1n ? qInvInput : null) || bigintModInverse(p, q);
  if (fallbackPInv != null) {
    const h = (((m2 - m1) * fallbackPInv) % q + q) % q;
    return {
      value: (m1 + p * h) % (p * q),
      crt: {
        convention: 'pInv = p^-1 mod q',
        m1: m1.toString(),
        m2: m2.toString(),
      },
    };
  }
  throw new Error('RSA CRT decrypt requires qInv/iqmp or invertible p/q');
};




export const rsaPhiFromPrimeFactors = (factors: bigint[]) => {
  if (!factors.length) return null;
  const counts = new Map<string, { prime: bigint; count: bigint }>();
  for (const factor of factors) {
    const key = factor.toString();
    const existing = counts.get(key);
    if (existing) existing.count += 1n;
    else counts.set(key, { prime: factor, count: 1n });
  }
  let phi = 1n;
  for (const { prime, count } of counts.values()) {
    phi *= (prime - 1n) * bigintPow(prime, count - 1n);
  }
  return phi;
};

export const tryRsaExponentReduction = (
  blocks: RsaMessageValue[],
  exponent: bigint,
  phi: bigint,
  modulus: bigint,
) => {
  const gcd = bigintGcd(exponent, phi);
  if (gcd <= 1n) return null;
  const reducedExponent = exponent / gcd;
  const reducedPrivate = bigintModInverse(reducedExponent, phi);
  if (reducedPrivate == null) return null;
  const powered = blocks.map(block => bigintModPow(block.value, reducedPrivate, modulus));
  const roots = powered.map(value => bigintNthRootExact(value, gcd));
  const exact = roots.every(root => root?.exact);
  return {
    gcd,
    reducedExponent,
    reducedPrivate,
    powered,
    roots: exact ? roots.map(root => root!.root) : null,
    exact,
  };
};

export const rsaRawTransform = (direction: Direction, value: string) => {
  const inference = inferRsaParamsFromText(value, direction);
  const { params } = inference;

  let p = rsaParamNumber(params, 'p');
  let q = rsaParamNumber(params, 'q');
  const explicitN = rsaParamNumber(params, 'n');
  const factoredN = direction === 'decode' && explicitN && (!p || !q) ? factorSmallRsaModulus(explicitN) : null;
  if (factoredN) {
    [p, q] = factoredN;
    inference.notes.push('Factored small n locally by bounded trial division, Fermat search, or Pollard Rho.');
  }
  const n = explicitN || (typeof p === 'bigint' && typeof q === 'bigint' ? p * q : null);
  const factorList = direction === 'decode' && typeof n === 'bigint'
    ? (typeof p === 'bigint' && typeof q === 'bigint' ? [p, q] : factorSmallCompositeModulus(n))
    : (typeof p === 'bigint' && typeof q === 'bigint' ? [p, q] : null);
  const phi = params.phi
    ? rsaParamNumber(params, 'phi')
    : (factorList ? rsaPhiFromPrimeFactors(factorList) : null);
  const e = rsaParamNumber(params, 'e');
  const explicitD = rsaParamNumber(params, 'd');
  const derivedD = !explicitD && typeof e === 'bigint' && typeof phi === 'bigint' ? bigintModInverse(e, phi) : null;
  const d = explicitD || derivedD;
  const dp = rsaParamNumber(params, 'dp');
  const dq = rsaParamNumber(params, 'dq');
  const qInv = rsaParamNumber(params, 'qinv');
  const pInv = rsaParamNumber(params, 'pinv');
  const canUseCrt = direction === 'decode'
    && typeof p === 'bigint'
    && typeof q === 'bigint'
    && typeof dp === 'bigint'
    && typeof dq === 'bigint';
  const inputSource = direction === 'encode'
    ? params.m
    : params.c;
  if (!inputSource) throw new Error(direction === 'encode' ? 'RSA encrypt requires m/message/plaintext' : 'RSA decrypt requires c/ciphertext');
  const inputBlocks = parseRsaMessageValues(inputSource, direction === 'encode' ? 'message' : 'ciphertext');
  const exponent = direction === 'encode' ? e : d;

  if (direction === 'decode' && typeof exponent !== 'bigint' && !canUseCrt && typeof e === 'bigint') {
    const lowExponentRoots = tryRsaLowExponentRoots(inputBlocks, e, n);
    if (lowExponentRoots) {
      return JSON.stringify({
        alg: 'RSA Raw / Textbook',
        direction,
        attack: 'low-public-exponent exact integer root',
        nBits: typeof n === 'bigint' ? bitLength(n) : null,
        modulus: typeof n === 'bigint' ? n.toString() : null,
        publicExponent: e.toString(),
        inference: inference.notes,
        input: inputBlocks.map((block, index) => ({
          index,
          source: block.source,
          ...rsaNumberResult(block.value),
        })),
        output: lowExponentRoots.length === 1 ? rsaNumberResult(lowExponentRoots[0]) : rsaValuesResult(lowExponentRoots),
        warning: 'Recovered by exact e-th root, which applies to unpadded textbook RSA when m^e is not reduced modulo n.',
      }, null, 2);
    }
    if (typeof phi === 'bigint' && typeof n === 'bigint') {
      const reduced = tryRsaExponentReduction(inputBlocks, e, phi, n);
      if (reduced) {
        return JSON.stringify({
          alg: 'RSA Raw / Textbook',
          direction,
          attack: 'gcd(e,phi) exponent reduction',
          nBits: bitLength(n),
          modulus: n.toString(),
          publicExponent: e.toString(),
          gcdEphi: reduced.gcd.toString(),
          reducedExponent: reduced.reducedExponent.toString(),
          reducedPrivateExponent: reduced.reducedPrivate.toString(),
          inference: inference.notes,
          input: inputBlocks.map((block, index) => ({
            index,
            source: block.source,
            ...rsaNumberResult(block.value),
          })),
          partialOutput: reduced.powered.length === 1 ? rsaNumberResult(reduced.powered[0]) : rsaValuesResult(reduced.powered),
          output: reduced.roots
            ? (reduced.roots.length === 1 ? rsaNumberResult(reduced.roots[0]) : rsaValuesResult(reduced.roots))
            : null,
          warning: reduced.roots
            ? 'Recovered by reducing e with gcd(e,phi) and taking an exact integer root of m^g.'
            : 'Recovered m^g modulo n, but no exact integer g-th root was found locally; this challenge may need modular root enumeration per prime factor.',
        }, null, 2);
      }
    }
  }

  if (typeof n !== 'bigint') throw new Error('RSA Raw requires n, or p and q');
  if (typeof exponent !== 'bigint' && !canUseCrt) {
    throw new Error(direction === 'encode' ? 'RSA encrypt requires e' : 'RSA decrypt requires d, p/q/e, low-e exact root, or p/q/dp/dq CRT parameters');
  }
  for (const input of inputBlocks) {
    if (input.value >= n) throw new Error('RSA input must be smaller than modulus n');
  }

  const crtOutputs: Array<ReturnType<typeof rsaCrtDecrypt> | null> = [];
  const outputs = inputBlocks.map(input => {
    const crtOutput = canUseCrt && typeof exponent !== 'bigint'
      ? rsaCrtDecrypt(input.value, p as bigint, q as bigint, dp as bigint, dq as bigint, qInv, pInv)
      : null;
    crtOutputs.push(crtOutput);
    return crtOutput ? crtOutput.value : bigintModPow(input.value, exponent as bigint, n);
  });

  return JSON.stringify({
    alg: 'RSA Raw / Textbook',
    direction,
    nBits: bitLength(n),
    modulus: n.toString(),
    exponent: typeof exponent === 'bigint' ? exponent.toString() : null,
    derivedPrivateExponent: !explicitD && !!derivedD,
    crt: crtOutputs.find(Boolean)?.crt || null,
    inference: inference.notes,
    input: inputBlocks.map((block, index) => ({
      index,
      source: block.source,
      ...rsaNumberResult(block.value),
    })),
    output: outputs.length === 1 ? rsaNumberResult(outputs[0]) : rsaValuesResult(outputs),
    warning: 'Textbook RSA has no padding and is only appropriate for CTF/lab recovery or legacy analysis; do not use it as a secure protocol.',
  }, null, 2);
};

export const canRabinRawDecryptFromText = (value: string) => {
  const inference = inferRsaParamsFromText(value, 'decode');
  const { params } = inference;
  const hasCiphertext = Boolean(params.c);
  const hasFactors = Boolean(params.p && params.q);
  const n = rsaParamNumber(params, 'n');
  const canFactorSmallN = typeof n === 'bigint' && factorSmallRsaModulus(n, { maxBits: 128, allowPollardRho: true, trialLimit: 2_000_000n, rhoIterations: 50_000 }) != null;
  return hasCiphertext && (hasFactors || canFactorSmallN);
};

export const trySmartRabinDecrypt = (value: string) => {
  const lower = value.toLowerCase();
  if (!/\brabin\b/.test(lower) && !/\bquadratic residue\b/.test(lower)) return null;
  if (!canRabinRawDecryptFromText(value)) return null;
  try {
    return `智能识别: Rabin Raw 可直接解密\n\n${rabinRawTransform('decode', value)}`;
  } catch {
    return null;
  }
};

export const canRsaRawDecryptFromText = (value: string) => {
  const inference = inferRsaParamsFromText(value, 'decode');
  const { params } = inference;
  const hasCiphertext = Boolean(params.c);
  const hasModulus = Boolean(params.n);
  const hasPrivateExponent = Boolean(params.d);
  const hasPublicExponent = Boolean(params.e);
  const hasFactors = Boolean(params.p && params.q);
  const hasCrt = Boolean(params.p && params.q && params.dp && params.dq);
  const n = rsaParamNumber(params, 'n');
  const canFactorSmallN = hasModulus && hasPublicExponent && typeof n === 'bigint'
    && factorSmallRsaModulus(n, { maxBits: 96, allowPollardRho: false, trialLimit: 1_000_000n }) != null;
  let canUseLowExponentRoot = false;
  if (hasCiphertext && hasPublicExponent) {
    try {
      const exponent = rsaParamNumber(params, 'e');
      const blocks = parseRsaMessageValues(params.c, 'ciphertext');
      canUseLowExponentRoot = typeof exponent === 'bigint' && tryRsaLowExponentRoots(blocks, exponent, rsaParamNumber(params, 'n')) != null;
    } catch {
      canUseLowExponentRoot = false;
    }
  }
  return hasCiphertext && (
    (inference.confidence >= 4 && canUseLowExponentRoot)
    || (inference.confidence >= 5 && ((hasModulus && (hasPrivateExponent || canFactorSmallN)) || (hasFactors && (hasPrivateExponent || hasPublicExponent || hasCrt))))
  );
};


export const chooseRsaRecordSubsets = <T,>(items: T[], size: number, limit = 40) => {
  const results: T[][] = [];
  const visit = (start: number, current: T[]) => {
    if (results.length >= limit) return;
    if (current.length === size) {
      results.push([...current]);
      return;
    }
    for (let index = start; index < items.length; index += 1) {
      current.push(items[index]);
      visit(index + 1, current);
      current.pop();
      if (results.length >= limit) return;
    }
  };
  if (size > 0 && size <= items.length) visit(0, []);
  return results;
};

export const arePairwiseCoprimeRsaRecords = (records: Array<{ n: bigint }>) => {
  for (let left = 0; left < records.length; left += 1) {
    for (let right = left + 1; right < records.length; right += 1) {
      if (bigintGcd(records[left].n, records[right].n) !== 1n) return false;
    }
  }
  return true;
};

export const serializeRsaCipherRecord = (record: RsaCipherRecord) => ({
  index: record.index,
  n: record.n?.toString() || null,
  e: record.e?.toString() || null,
  c: record.c?.toString() || null,
  m: record.m?.toString() || null,
});

export const continuedFractionTerms = (numerator: bigint, denominator: bigint) => {
  const terms: bigint[] = [];
  let a = numerator;
  let b = denominator;
  while (b !== 0n) {
    terms.push(a / b);
    [a, b] = [b, a % b];
    if (terms.length > 4096) break;
  }
  return terms;
};

export const continuedFractionConvergents = (terms: bigint[]) => {
  const convergents: Array<{ numerator: bigint; denominator: bigint }> = [];
  let h1 = 1n;
  let h0 = 0n;
  let k1 = 0n;
  let k0 = 1n;
  for (const term of terms) {
    const h = term * h1 + h0;
    const k = term * k1 + k0;
    convergents.push({ numerator: h, denominator: k });
    [h0, h1] = [h1, h];
    [k0, k1] = [k1, k];
    if (convergents.length > 4096) break;
  }
  return convergents;
};

export const normalizePolyMod = (coefficients: bigint[], modulo: bigint) => {
  const normalized = coefficients.map(coefficient => bigintMod(coefficient, modulo));
  while (normalized.length > 1 && normalized[normalized.length - 1] === 0n) normalized.pop();
  return normalized;
};

export const polyIsZero = (coefficients: bigint[]) => coefficients.length === 0 || coefficients.every(coefficient => coefficient === 0n);

export const polyMulMod = (left: bigint[], right: bigint[], modulo: bigint) => {
  const result = Array.from({ length: Math.max(1, left.length + right.length - 1) }, () => 0n);
  for (let leftIndex = 0; leftIndex < left.length; leftIndex += 1) {
    for (let rightIndex = 0; rightIndex < right.length; rightIndex += 1) {
      result[leftIndex + rightIndex] = bigintMod(result[leftIndex + rightIndex] + left[leftIndex] * right[rightIndex], modulo);
    }
  }
  return normalizePolyMod(result, modulo);
};

export const polyMakeMonic = (coefficients: bigint[], modulo: bigint) => {
  const normalized = normalizePolyMod(coefficients, modulo);
  if (polyIsZero(normalized)) return [0n];
  const leading = normalized[normalized.length - 1];
  const inverse = bigintModInverse(leading, modulo);
  if (inverse == null) return null;
  return normalizePolyMod(normalized.map(coefficient => bigintMod(coefficient * inverse, modulo)), modulo);
};

export const polyDivRemMod = (dividendInput: bigint[], divisorInput: bigint[], modulo: bigint) => {
  const dividend = normalizePolyMod([...dividendInput], modulo);
  const divisor = normalizePolyMod([...divisorInput], modulo);
  if (polyIsZero(divisor)) return null;
  const divisorDegree = divisor.length - 1;
  const divisorLead = divisor[divisorDegree];
  const divisorLeadInv = bigintModInverse(divisorLead, modulo);
  if (divisorLeadInv == null) return null;
  const quotient = Array.from({ length: Math.max(1, dividend.length - divisor.length + 1) }, () => 0n);
  const remainder = [...dividend];
  while (remainder.length >= divisor.length && !polyIsZero(remainder)) {
    const degreeDiff = remainder.length - divisor.length;
    const scale = bigintMod(remainder[remainder.length - 1] * divisorLeadInv, modulo);
    quotient[degreeDiff] = scale;
    for (let index = 0; index < divisor.length; index += 1) {
      remainder[index + degreeDiff] = bigintMod(remainder[index + degreeDiff] - scale * divisor[index], modulo);
    }
    while (remainder.length > 1 && remainder[remainder.length - 1] === 0n) remainder.pop();
  }
  return {
    quotient: normalizePolyMod(quotient, modulo),
    remainder: normalizePolyMod(remainder, modulo),
  };
};

export const polyGcdCompositeModulus = (left: bigint[], right: bigint[], modulo: bigint) => {
  let a = polyMakeMonic(left, modulo);
  let b = polyMakeMonic(right, modulo);
  if (!a || !b) return null;
  let guard = 0;
  while (!polyIsZero(b) && guard < 64) {
    const division = polyDivRemMod(a, b, modulo);
    if (!division) return null;
    a = b;
    b = polyMakeMonic(division.remainder, modulo);
    if (!b) return null;
    guard += 1;
  }
  return polyMakeMonic(a, modulo);
};

export const polyPowLinearMod = (a: bigint, b: bigint, exponent: bigint, modulo: bigint) => {
  let result = [1n];
  const base = normalizePolyMod([b, a], modulo);
  for (let index = 0n; index < exponent; index += 1n) {
    result = polyMulMod(result, base, modulo);
  }
  return normalizePolyMod(result, modulo);
};

export type RsaRelatedMessageRelation = {
  a: bigint;
  b: bigint;
  source: string;
};

export const parseRsaRelatedMessageRelation = (value: string): RsaRelatedMessageRelation | null => {
  const fields = parseLooseCtfFields(value);
  const lower = value.toLowerCase();
  const parseNumber = (candidate: string | undefined) => candidate ? parseNumericValue(candidate) : null;

  const explicitA = parseNumber(looseField(fields, ['a', 'alpha', 'multiplier', 'scale', 'coeffa']));
  const explicitB = parseNumber(looseField(fields, ['b', 'beta', 'delta', 'difference', 'offset', 'shift', 'k']));
  if (explicitA != null && explicitB != null) return { a: explicitA, b: explicitB, source: 'explicit a/b fields' };
  if (explicitB != null) return { a: 1n, b: explicitB, source: 'explicit additive delta field' };

  const pad1 = parseNumber(looseField(fields, ['pad1', 'padding1', 'r1']));
  const pad2 = parseNumber(looseField(fields, ['pad2', 'padding2', 'r2']));
  if (pad1 != null && pad2 != null && pad1 !== pad2) return { a: 1n, b: pad2 - pad1, source: 'pad2 - pad1' };

  const additive = value.match(/\bm2\s*=\s*m1\s*([+-])\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)/i);
  if (additive) {
    const delta = parseNumericValue(additive[2]);
    if (delta != null) return { a: 1n, b: additive[1] === '-' ? -delta : delta, source: 'm2 = m1 +/- k' };
  }

  const scaled = value.match(/\bm2\s*=\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*\*\s*m1(?:\s*([+-])\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?))?/i);
  if (scaled) {
    const a = parseNumericValue(scaled[1]);
    const b = scaled[4] ? parseNumericValue(scaled[4]) : 0n;
    if (a != null && b != null) return { a, b: scaled[3] === '-' ? -b : b, source: 'm2 = a*m1 + b' };
  }

  const reverseAdditive = value.match(/\bm1\s*=\s*m2\s*([+-])\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)/i);
  if (reverseAdditive) {
    const delta = parseNumericValue(reverseAdditive[2]);
    if (delta != null) return { a: 1n, b: reverseAdditive[1] === '+' ? -delta : delta, source: 'rewritten from m1 = m2 +/- k' };
  }

  if (/\bfranklin\b|\breiter\b|\brelated message\b/.test(lower)) {
    const sourceDelta = parseNumber(looseField(fields, ['r', 'diff']));
    if (sourceDelta != null) return { a: 1n, b: sourceDelta, source: 'Franklin-Reiter style r/diff field' };
  }
  return null;
};

export const buildRsaCipherPolynomial = (degree: bigint, ciphertext: bigint, modulo: bigint) => {
  const size = Number(degree) + 1;
  const coefficients = Array.from({ length: size }, () => 0n);
  coefficients[0] = bigintMod(-ciphertext, modulo);
  coefficients[size - 1] = 1n;
  return normalizePolyMod(coefficients, modulo);
};

export const tryLinearPolynomialRootMod = (polynomial: bigint[], modulo: bigint) => {
  if (polynomial.length !== 2) return null;
  const inverse = bigintModInverse(polynomial[1], modulo);
  if (inverse == null) return null;
  return bigintMod(-polynomial[0] * inverse, modulo);
};

export const tryRsaFranklinReiterAttack = (value: string, records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
  const relation = parseRsaRelatedMessageRelation(value);
  if (!relation) return null;
  const usable = records.filter((record): record is RsaCipherRecord & { n: bigint; e: bigint; c: bigint } => (
    typeof record.n === 'bigint' && typeof record.e === 'bigint' && typeof record.c === 'bigint'
  ));
  const attempt = (
    first: RsaCipherRecord & { n: bigint; e: bigint; c: bigint },
    second: RsaCipherRecord & { n: bigint; e: bigint; c: bigint },
    a: bigint,
    b: bigint,
    source: string,
  ): RsaAutomatedAttackResult | null => {
    if (first.n !== second.n || first.e !== second.e) return null;
    if (first.e < 2n || first.e > 11n) return null;
    if (bigintGcd(a, first.n) !== 1n) return null;
    const poly1 = buildRsaCipherPolynomial(first.e, first.c, first.n);
    const poly2 = polyPowLinearMod(a, b, first.e, first.n);
    poly2[0] = bigintMod((poly2[0] || 0n) - second.c, first.n);
    const gcd = polyGcdCompositeModulus(poly1, poly2, first.n);
    if (!gcd || gcd.length !== 2) return null;
    const m1 = tryLinearPolynomialRootMod(gcd, first.n);
    if (m1 == null) return null;
    const m2 = bigintMod(a * m1 + b, first.n);
    if (bigintModPow(m1, first.e, first.n) !== first.c) return null;
    if (bigintModPow(m2, first.e, first.n) !== second.c) return null;
    return {
      attack: 'rsa-franklin-reiter',
      title: 'RSA Franklin-Reiter Related Message',
      output: {
        firstMessage: rsaNumberResult(m1),
        secondMessage: rsaNumberResult(m2),
      },
      details: {
        relation: {
          a: a.toString(),
          b: b.toString(),
          source,
        },
        recordPair: [serializeRsaCipherRecord(first), serializeRsaCipherRecord(second)],
        modulus: first.n.toString(),
        exponent: first.e.toString(),
      },
    };
  };

  for (let left = 0; left < usable.length; left += 1) {
    for (let right = left + 1; right < usable.length; right += 1) {
      const direct = attempt(usable[left], usable[right], relation.a, relation.b, relation.source);
      if (direct) return direct;
      const inverseA = bigintModInverse(relation.a, usable[left].n);
      if (inverseA == null) continue;
      const reverseB = bigintMod(-inverseA * relation.b, usable[left].n);
      const reverse = attempt(usable[right], usable[left], inverseA, reverseB, `${relation.source} (reversed)`);
      if (reverse) return reverse;
    }
  }
  return null;
};

export const enumerateRsaPrimeFromCrtExponent = (crtExponent: bigint, publicExponent: bigint, modulus: bigint | null) => {
  const numerator = publicExponent * crtExponent - 1n;
  if (numerator <= 0n) return [];
  const limit = Number(publicExponent > 262144n ? 262144n : publicExponent);
  const primes: bigint[] = [];
  for (let k = 1; k <= limit; k += 1) {
    const divisor = BigInt(k);
    if (numerator % divisor !== 0n) continue;
    const candidate = numerator / divisor + 1n;
    if (candidate <= 1n) continue;
    if (modulus != null && modulus % candidate !== 0n) continue;
    primes.push(candidate);
  }
  return uniqueBigints(primes);
};

export const tryRsaCrtExponentLeakAttack = (params: Record<string, string>): RsaAutomatedAttackResult | null => {
  const e = rsaParamNumber(params, 'e');
  const c = rsaParamNumber(params, 'c');
  const n = rsaParamNumber(params, 'n');
  const dp = rsaParamNumber(params, 'dp');
  const dq = rsaParamNumber(params, 'dq');
  const qInv = rsaParamNumber(params, 'qinv');
  const pInv = rsaParamNumber(params, 'pinv');
  if (typeof e !== 'bigint' || typeof c !== 'bigint' || (dp == null && dq == null)) return null;

  const pCandidates = dp != null ? enumerateRsaPrimeFromCrtExponent(dp, e, n) : [];
  const qCandidates = dq != null ? enumerateRsaPrimeFromCrtExponent(dq, e, n) : [];

  const attempt = (p: bigint, q: bigint, source: string) => {
    if (p <= 1n || q <= 1n || p === q) return null;
    const modulus = p * q;
    if (n != null && modulus !== n) return null;
    if (qInv != null && bigintMod(q * qInv, p) !== 1n && bigintMod(p * qInv, q) !== 1n) return null;
    if (pInv != null && bigintMod(p * pInv, q) !== 1n && bigintMod(q * pInv, p) !== 1n) return null;
    const phi = (p - 1n) * (q - 1n);
    const d = bigintModInverse(e, phi);
    if (d == null) return null;
    const message = bigintModPow(c, d, modulus);
    return {
      attack: 'rsa-crt-exponent-leak',
      title: 'RSA CRT Exponent Leak',
      output: {
        recoveredMessage: rsaNumberResult(message),
      },
      details: {
        source,
        n: modulus.toString(),
        e: e.toString(),
        d: d.toString(),
        p: p.toString(),
        q: q.toString(),
        dp: dp?.toString() || null,
        dq: dq?.toString() || null,
        qinv: qInv?.toString() || null,
        pinv: pInv?.toString() || null,
      },
    } satisfies RsaAutomatedAttackResult;
  };

  if (n != null) {
    for (const p of pCandidates) {
      const result = attempt(p, n / p, 'Recovered p from dp and n');
      if (result) return result;
    }
    for (const q of qCandidates) {
      const result = attempt(n / q, q, 'Recovered q from dq and n');
      if (result) return result;
    }
  }

  for (const p of pCandidates) {
    for (const q of qCandidates) {
      const result = attempt(p, q, 'Recovered p from dp and q from dq');
      if (result) return result;
    }
  }
  return null;
};

export const tryRsaWienerAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
  const usable = records.filter((record): record is RsaCipherRecord & { n: bigint; e: bigint; c: bigint } => (
    typeof record.n === 'bigint' && typeof record.e === 'bigint' && typeof record.c === 'bigint'
  ));
  for (const record of usable) {
    const terms = continuedFractionTerms(record.e, record.n);
    const convergents = continuedFractionConvergents(terms);
    for (const convergent of convergents) {
      const k = convergent.numerator;
      const d = convergent.denominator;
      if (k === 0n || d <= 0n) continue;
      const edMinus1 = record.e * d - 1n;
      if (edMinus1 <= 0n || edMinus1 % k !== 0n) continue;
      const phi = edMinus1 / k;
      const s = record.n - phi + 1n;
      const discriminant = s * s - 4n * record.n;
      if (discriminant < 0n) continue;
      const root = bigIntSqrt(discriminant);
      if (root * root !== discriminant) continue;
      const p = (s + root) / 2n;
      const q = (s - root) / 2n;
      if (p <= 1n || q <= 1n || p * q !== record.n) continue;
      const message = bigintModPow(record.c, d, record.n);
      return {
        attack: 'rsa-wiener-small-d',
        title: 'RSA Wiener Small-d',
        output: {
          recoveredMessage: rsaNumberResult(message),
        },
        details: {
          record: serializeRsaCipherRecord(record),
          d: d.toString(),
          k: k.toString(),
          phi: phi.toString(),
          p: p.toString(),
          q: q.toString(),
        },
      };
    }
  }
  return null;
};

export const tryRsaCommonModulusAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
  const usable = records.filter((record): record is RsaCipherRecord & { n: bigint; e: bigint; c: bigint } => (
    typeof record.n === 'bigint' && typeof record.e === 'bigint' && typeof record.c === 'bigint'
  ));
  for (let left = 0; left < usable.length; left += 1) {
    for (let right = left + 1; right < usable.length; right += 1) {
      const first = usable[left];
      const second = usable[right];
      if (first.n !== second.n || first.e === second.e) continue;
      const [gcd, coeffLeft, coeffRight] = bigintEgcd(first.e, second.e);
      if (gcd !== 1n) continue;
      const leftValue = rsaModPowSigned(first.c, coeffLeft, first.n);
      const rightValue = rsaModPowSigned(second.c, coeffRight, first.n);
      if (leftValue == null || rightValue == null) continue;
      const message = bigintMod(leftValue * rightValue, first.n);
      return {
        attack: 'rsa-common-modulus',
        title: 'RSA Common Modulus',
        output: {
          recoveredMessage: rsaNumberResult(message),
        },
        details: {
          sharedModulus: first.n.toString(),
          pair: [serializeRsaCipherRecord(first), serializeRsaCipherRecord(second)],
          bezout: [coeffLeft.toString(), coeffRight.toString()],
        },
      };
    }
  }
  return null;
};

export const tryRsaBroadcastAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
  const usable = records.filter((record): record is RsaCipherRecord & { n: bigint; e: bigint; c: bigint } => (
    typeof record.n === 'bigint' && typeof record.e === 'bigint' && typeof record.c === 'bigint'
  ));
  const groups = new Map<string, Array<RsaCipherRecord & { n: bigint; e: bigint; c: bigint }>>();
  for (const record of usable) {
    const key = record.e.toString();
    groups.set(key, [...(groups.get(key) || []), record]);
  }
  for (const [exponentKey, group] of groups.entries()) {
    const exponent = BigInt(exponentKey);
    const degree = Number(exponent);
    if (exponent < 2n || exponent > 7n || !Number.isInteger(degree) || group.length < degree) continue;
    for (const subset of chooseRsaRecordSubsets(group, degree, 24)) {
      if (!arePairwiseCoprimeRsaRecords(subset)) continue;
      let combinedCipher = subset[0].c;
      let combinedModulus = subset[0].n;
      for (let index = 1; index < subset.length; index += 1) {
        combinedCipher = crtCombinePair(combinedCipher, combinedModulus, subset[index].c, subset[index].n);
        combinedModulus *= subset[index].n;
      }
      const root = bigintNthRootExact(combinedCipher, exponent);
      if (!root?.exact) continue;
      return {
        attack: 'rsa-hastad-broadcast',
        title: 'RSA Hastad Broadcast',
        output: {
          recoveredMessage: rsaNumberResult(root.root),
        },
        details: {
          exponent: exponent.toString(),
          records: subset.map(serializeRsaCipherRecord),
          combinedCipherBits: bitLength(combinedCipher),
          combinedModulusBits: bitLength(combinedModulus),
        },
      };
    }
  }
  return null;
};

export const tryRsaSharedPrimeAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
  const usable = records.filter((record): record is RsaCipherRecord & { n: bigint; e: bigint; c: bigint } => (
    typeof record.n === 'bigint' && typeof record.e === 'bigint' && typeof record.c === 'bigint'
  ));
  for (let left = 0; left < usable.length; left += 1) {
    for (let right = left + 1; right < usable.length; right += 1) {
      const first = usable[left];
      const second = usable[right];
      const sharedPrime = bigintGcd(first.n, second.n);
      if (sharedPrime <= 1n || sharedPrime === first.n || sharedPrime === second.n) continue;
      const recoveries = [first, second].flatMap(record => {
        const otherPrime = record.n / sharedPrime;
        const phi = (sharedPrime - 1n) * (otherPrime - 1n);
        const d = bigintModInverse(record.e, phi);
        if (d == null) return [];
        const message = bigintModPow(record.c, d, record.n);
        return [{
          record: serializeRsaCipherRecord(record),
          p: sharedPrime.toString(),
          q: otherPrime.toString(),
          recoveredMessage: rsaNumberResult(message),
        }];
      });
      if (!recoveries.length) continue;
      return {
        attack: 'rsa-shared-prime-gcd',
        title: 'RSA Shared Prime GCD',
        output: {
          recoveries,
        },
        details: {
          sharedPrime: sharedPrime.toString(),
          pair: [serializeRsaCipherRecord(first), serializeRsaCipherRecord(second)],
        },
      };
    }
  }
  return null;
};

export const tryRsaBatchGcdAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
  const usable = records.filter((record): record is RsaCipherRecord & { n: bigint; e: bigint; c: bigint } => (
    typeof record.n === 'bigint' && typeof record.e === 'bigint' && typeof record.c === 'bigint'
  ));
  if (usable.length < 3) return null;
  const recoveries: Array<{
    record: ReturnType<typeof serializeRsaCipherRecord>;
    sharedPrime: string;
    otherPrime: string;
    recoveredMessage: ReturnType<typeof rsaNumberResult>;
  }> = [];
  const seenRecovery = new Set<string>();
  const sharedFactors = new Set<string>();

  for (let left = 0; left < usable.length; left += 1) {
    for (let right = left + 1; right < usable.length; right += 1) {
      const first = usable[left];
      const second = usable[right];
      const sharedPrime = bigintGcd(first.n, second.n);
      if (sharedPrime <= 1n || sharedPrime === first.n || sharedPrime === second.n) continue;
      sharedFactors.add(sharedPrime.toString());
      for (const record of [first, second]) {
        const otherPrime = record.n / sharedPrime;
        const phi = (sharedPrime - 1n) * (otherPrime - 1n);
        const d = bigintModInverse(record.e, phi);
        if (d == null) continue;
        const message = bigintModPow(record.c, d, record.n);
        const key = `${record.index}:${sharedPrime.toString()}`;
        if (seenRecovery.has(key)) continue;
        seenRecovery.add(key);
        recoveries.push({
          record: serializeRsaCipherRecord(record),
          sharedPrime: sharedPrime.toString(),
          otherPrime: otherPrime.toString(),
          recoveredMessage: rsaNumberResult(message),
        });
      }
    }
  }

  if (recoveries.length < 3 || sharedFactors.size === 0) return null;
  return {
    attack: 'rsa-batch-gcd-shared-prime',
    title: 'RSA Batch GCD Shared Prime Scan',
    output: {
      recoveries,
    },
    details: {
      sharedPrimes: Array.from(sharedFactors.values()),
      recordCount: usable.length,
      vulnerableRecordCount: recoveries.length,
    },
  };
};

export const collectRsaAutomatedAttacks = (value: string) => {
  const inference = inferRsaParamsFromText(value, 'decode');
  const records = parseRsaCipherRecords(value, inference.params);
  const attacks = [
    tryRsaCrtExponentLeakAttack(inference.params),
    tryRsaWienerAttack(records),
    tryRsaFranklinReiterAttack(value, records),
    tryRsaCommonModulusAttack(records),
    tryRsaBroadcastAttack(records),
    tryRsaBatchGcdAttack(records),
    tryRsaSharedPrimeAttack(records),
  ].filter((entry): entry is RsaAutomatedAttackResult => Boolean(entry));
  return { records, attacks };
};

export const trySmartRsaDecrypt = (value: string) => {
  const lower = value.toLowerCase();
  if (!/\brsa\b/.test(lower) && /\b(?:lcg|linear congruential|lfsr|mt19937|mersenne|keystream|outputs?|states?|samples?)\b|线性同余|同余生成器|伪随机|随机数|输出序列|状态序列/.test(lower)) return null;
  if (!/\brsa\b/.test(lower) && /\b(?:ecdsa|dsa|schnorr|signature|nonce reuse|same nonce|reused nonce)\b/.test(lower)) return null;
  const inference = inferRsaParamsFromText(value, 'decode');
  const advanced = collectRsaAutomatedAttacks(value);
  const multiRecordLike = advanced.records.length >= 2
    || /\b(?:public[_\s-]?keys?|pubkeys?|ciphertexts?|moduli|records?)\b/i.test(value);
  const inferredCipherOnly = inference.notes.some(note => /推断 ciphertext/i.test(note));
  const directRecordCount = advanced.records.filter(record => (
    typeof record.n === 'bigint'
    && typeof record.e === 'bigint'
    && (typeof record.c === 'bigint' || typeof record.m === 'bigint')
  )).length;
  const hasSingleExplicitCipher = directRecordCount === 1
    && typeof rsaParamNumber(inference.params, 'n') === 'bigint'
    && typeof rsaParamNumber(inference.params, 'e') === 'bigint'
    && typeof rsaParamNumber(inference.params, 'c') === 'bigint'
    && !inferredCipherOnly;
  if (advanced.attacks.length) {
    return `智能识别: ${advanced.attacks[0].title}\n\n${JSON.stringify(advanced.attacks[0], null, 2)}`;
  }
  const looksLikeRsa = canRsaRawDecryptFromText(value) || canSmartRsaHelper(value);
  if (!looksLikeRsa) return null;
  const hasPrivateMaterial = ['d', 'phi', 'p', 'q', 'dp', 'dq', 'qinv', 'pinv']
    .some(key => typeof rsaParamNumber(inference.params, key) === 'bigint');
  const shouldPreferHelper = canSmartRsaHelper(value)
    && !hasPrivateMaterial
    && !hasSingleExplicitCipher
    && (
      (inference.knownPairs.length >= 2 && inferredCipherOnly)
      || multiRecordLike
    );
  if (shouldPreferHelper) {
    try {
      return `智能识别: RSA CTF Helper\n\n${rsaHelper(value)}`;
    } catch {
      return null;
    }
  }
  try {
    return `智能识别: RSA Raw / Textbook 可直接解密\n\n${rsaRawTransform('decode', value)}`;
  } catch {
    if (!canSmartRsaHelper(value)) return null;
    try {
      return `智能识别: RSA CTF Helper\n\n${rsaHelper(value)}`;
    } catch {
      return null;
    }
  }
};

export const canSmartRsaHelper = (value: string) => {
  const lower = value.toLowerCase();
  if (!/\brsa\b/.test(lower) && /\b(?:lcg|linear congruential|lfsr|mt19937|mersenne|keystream|outputs?|states?|samples?)\b/.test(lower)) return false;
  if (!/\brsa\b/.test(lower) && /\b(?:ecdsa|dsa|schnorr|signature|nonce reuse|same nonce|reused nonce)\b/.test(lower)) return false;
  const inference = inferRsaParamsFromText(value, 'decode');
  const numericKeys = Object.keys(inference.params)
    .filter(key => typeof rsaParamNumber(inference.params, key) === 'bigint');
  const hasCorePublicKey = numericKeys.includes('n') && numericKeys.includes('e');
  const hasFactorization = numericKeys.includes('n') && (numericKeys.includes('p') || numericKeys.includes('q'));
  const hasPrivateMaterial = numericKeys.includes('d') || numericKeys.includes('phi') || (numericKeys.includes('dp') && numericKeys.includes('dq'));
  const hasKnownPairs = inference.knownPairs.length >= 2;
  const hasLabeledCipher = numericKeys.includes('c');
  // 孤立 c= 标签不足以触发（A1Z26 数字串 6-12-1-7 会被误解析成 e/p/q/c）：
  // 无 rsa 关键词时必须同时有 n/因子/私钥材料或 ≥2 组已知对
  const explicitRsa = /\brsa\b/.test(lower);
  const minimumConfidence = hasCorePublicKey || hasFactorization || hasPrivateMaterial ? 4 : 5;
  return (
    inference.confidence >= minimumConfidence
    && (hasCorePublicKey || hasFactorization || hasPrivateMaterial || hasKnownPairs
      || (hasLabeledCipher && explicitRsa))
  );
};

export const rsaHelper = (value: string) => {
  const inference = inferRsaParamsFromText(value, 'decode');
  const { params, looseNumbers, knownPairs } = inference;
  const automated = collectRsaAutomatedAttacks(value);
  const numeric = Object.fromEntries(Object.keys(params).map(key => [key, rsaParamNumber(params, key)]));
  const notes: string[] = [...inference.notes];
  const normalized = Object.fromEntries(
    Object.keys(params)
      .map(key => [key, rsaParamNumber(params, key)])
      .filter((entry): entry is [string, bigint] => typeof entry[1] === 'bigint')
      .map(([key, entry]) => [key, entry.toString()])
  );
  const n = numeric.n;
  const e = numeric.e;
  if (typeof n === 'bigint') {
    notes.push(`n bits: ${bitLength(n)}`);
    const root = bigIntSqrt(n);
    if (root * root === n) notes.push('n 是完全平方，检查 p=q 或 Rabin/RSA 生成错误。');
  }
  if (typeof e === 'bigint') {
    if (e === 3n || e === 5n || e === 17n) notes.push(`低指数 e=${e.toString()}，优先检查小明文、Hastad broadcast、Franklin-Reiter。`);
    if (e === 65537n) notes.push('e=65537 是常规公钥指数。');
    if (e === 1n) notes.push('e=1 时，签名或验签题可能存在显然绕过。');
  }
  if (params.p && params.q && !params.phi) notes.push('已有 p/q，可直接计算 phi 并恢复私钥。');
  if (params.dp || params.dq || params.qinv) notes.push('检测到 CRT 参数，可尝试 RSA partial key recovery 或 CRT fault 相关路径。');
  if (typeof e === 'bigint' && e === 2n) notes.push('e=2 是 Rabin 密码系统，解密需要 p/q，结果有4 个候选根，需用明文特征（如 pkcs 填充）区分。建议切换到 Rabin Raw 操作。');
  if (typeof n === 'bigint' && typeof e === 'bigint' && e > n) notes.push('e > n，这不是标准RSA，可能是 e 和 phi 互质时的大指数变体或出题错误。');
  if (typeof n === 'bigint' && typeof e === 'bigint' && bitLength(n) <= 512) notes.push('n 较小（≤512 bit），可尝试 factordb.com 或 yafu/msieve 在线/本地分解。');
  if (typeof n === 'bigint' && typeof e === 'bigint' && e > 1n << BigInt(Math.floor(bitLength(n) * 3 / 4))) {
    notes.push(`e 非常大（${bitLength(e)} bit），d 可能较小，Boneh-Durfee (d < n^0.292) 值得尝试。SageMath: load("boneh_durfee.sage")。`);
  }
  let directRecovery: unknown = null;
  if (params.c && typeof e === 'bigint') {
    try {
      const blocks = parseRsaMessageValues(params.c, 'ciphertext');
      const roots = tryRsaLowExponentRoots(blocks, e, rsaParamNumber(params, 'n'));
      if (roots) {
        notes.push('low public exponent exact root is recoverable locally; textbook RSA likely did not reduce m^e modulo n.');
        directRecovery = {
          attack: 'low-public-exponent exact integer root',
          output: roots.length === 1 ? rsaNumberResult(roots[0]) : rsaValuesResult(roots),
        };
      }
    } catch {
      // Keep helper output focused on parseable fields and commands.
    }
  }
  if (!directRecovery && automated.attacks.length) {
    directRecovery = automated.attacks[0];
    notes.push(`检测到 ${automated.attacks[0].title} 可直接恢复明文。`);
  }
  const commands = [
    normalized.n && normalized.e && normalized.c ? `python RsaCtfTool.py -n ${normalized.n} -e ${normalized.e} --uncipher ${normalized.c}` : '',
    normalized.n ? `python -c "from sympy import factorint; n=${normalized.n}; print(factorint(n))"` : '',
    normalized.n && normalized.e ? `sage -c "n=${normalized.n}; e=${normalized.e}; print(n.nbits(), e)"` : '',
    normalized.e && normalized.c ? `python -c "import gmpy2; e=${normalized.e}; c=${normalized.c}; m, ok = gmpy2.iroot(c, e); print(bytes.fromhex(hex(int(m))[2:]) if ok else 'not an exact low-e root')"` : '',
    normalized.p && normalized.q && normalized.e && normalized.c ? `python -c "from Crypto.Util.number import long_to_bytes; p=${normalized.p}; q=${normalized.q}; e=${normalized.e}; c=${normalized.c}; phi=(p-1)*(q-1); d=pow(e,-1,phi); print(long_to_bytes(pow(c,d,p*q)))"` : '',
    normalized.n && normalized.phi && normalized.e && normalized.c ? `python -c "from Crypto.Util.number import long_to_bytes; n=${normalized.n}; phi=${normalized.phi}; e=${normalized.e}; c=${normalized.c}; d=pow(e,-1,phi); print(long_to_bytes(pow(c,d,n)))"` : '',
    normalized.n && normalized.d && normalized.c ? `python -c "from Crypto.Util.number import long_to_bytes; n=${normalized.n}; d=${normalized.d}; c=${normalized.c}; print(long_to_bytes(pow(c,d,n)))"` : '',
    normalized.p && normalized.q && normalized.dp && normalized.dq && normalized.c ? `python -c "from Crypto.Util.number import long_to_bytes; p=${normalized.p}; q=${normalized.q}; dp=${normalized.dp}; dq=${normalized.dq}; c=${normalized.c}; qinv=pow(q,-1,p); m2=pow(c,dq,q); h=(qinv*(pow(c,dp,p)-m2))%p; print(long_to_bytes(m2+h*q))"` : '',
    normalized.n && normalized.e ? `python -c "from Crypto.Util.number import long_to_bytes; n=${normalized.n}; e=${normalized.e}\nfrom sympy import factorint\nf=factorint(n); phi=1\nfor p,k in f.items(): phi*=(p-1)*p**(k-1)\nprint('phi=',phi)"` : '',
    automated.records.length >= 2 ? `python RsaCtfTool.py --attack common_modulus -n ${automated.records[0]?.n || ''} -e ${automated.records[0]?.e || ''} --uncipher ${automated.records[0]?.c || ''}` : '',
    automated.records.length >= 3 ? `# Hastad broadcast: CRT + e-th root\npython -c "\nfrom functools import reduce\nfrom gmpy2 import iroot\ndef crt(a,m): M=reduce(lambda x,y:x*y,m); return sum(a[i]*M//m[i]*pow(M//m[i],-1,m[i]) for i in range(len(a)))%M\nn=[${automated.records.slice(0,3).map(r=>r.n).join(',')}]\nc=[${automated.records.slice(0,3).map(r=>r.c).join(',')}]\ne=${automated.records[0]?.e||3}\nm,ok=iroot(crt(c,n),e); print(bytes.fromhex(hex(int(m))[2:]) if ok else m)"` : '',
  ].filter(Boolean);
  return JSON.stringify({
    parsed: params,
    normalizedNumeric: normalized,
    looseNumbers,
    knownPlainCipherPairs: knownPairs.map(pair => ({ index: pair.index, m: pair.m.toString(), c: pair.c.toString() })),
    rsaCipherRecords: automated.records.map(serializeRsaCipherRecord),
    inferenceConfidence: inference.confidence,
    notes,
    directRecovery,
    automatedAttacks: automated.attacks,
    commands,
    externalTools: ['RsaCtfTool', 'SageMath', 'sympy', 'PyCryptodome'],
  }, null, 2);
};










