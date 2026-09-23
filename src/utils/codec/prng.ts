// CODEC-IMPORTS
import { cleanSymmetricFieldValue, digest, looseField, normalizeLooseBytesLabel, normalizeLooseFieldName, parseHexBase64OrUtf8Bytes, parseLooseCtfFields, parseLooseIndexedRecords, parseLooseObjectBlocks } from './crypto';
import { asn1IntegerValue, parseNamedIndexedSequence, parseNumericList, parseNumericTuple, parseNumericValue, rsaNumberResult, stripPrngScalarAssignments } from './textUtils';
import { bigintFromBytes, bigintMod, bigintModInverse, bigintModPow, bigintPow, bitLength, crtCombinePair, factorSmallCompositeModulus, rsaModPowSigned } from './math';
import { decodeBase64UrlJson, parseAsn1Input, parseAsn1TopLevel } from './binaryFormats';
import { base64ToBytes, bytesToHex } from './bases';
import { utf8Decoder } from './alphabets';
import { inferLcgFromText, inferLfsrBitsFromText, lcgHelper, lfsrHelper } from './attacks';
// CODEC-IMPORTS-END



import {
  extractBracketedAssignment,
  getObjectAliasValue,
  parseNumberishUnknown,
} from './textUtils';

// 以下函数已下沉 src/utils/codec/textUtils.ts（T5 解环）；re-export 保持既有导出面。
export {
  escapeRegexLiteral,
  extractBracketedAssignment,
  getObjectAliasValue,
  parseNumberishUnknown,
} from './textUtils';
export const splitPackedMtWords = (value: bigint, wordBits: number) => {
  if (value < 0n) return [];
  if (wordBits <= 32 || wordBits % 32 !== 0) return [];
  const wordCount = wordBits / 32;
  if (wordCount < 2 || wordCount > 8) return [];
  const upperBound = 1n << BigInt(wordBits);
  if (value >= upperBound) return [];
  return Array.from({ length: wordCount }, (_, index) => (value >> BigInt(index * 32)) & 0xffffffffn);
};

export const expandMt19937WordCandidates = (numbers: bigint[]) => {
  const outputs32 = numbers.filter(number => number >= 0n && number <= 0xffffffffn);
  const packedOutputs = numbers.filter(number => number > 0xffffffffn);
  const maxPacked = packedOutputs.reduce((current, value) => value > current ? value : current, 0n);
  const inferredWordBits = maxPacked === 0n
    ? 0
    : [64, 96, 128, 160, 192, 224, 256].find(bits => maxPacked < (1n << BigInt(bits))) || 0;
  const expandedPacked = inferredWordBits ? packedOutputs.flatMap(number => splitPackedMtWords(number, inferredWordBits)) : [];
  return {
    outputs32,
    packedOutputs,
    expandedPacked,
    inferredWordBits,
  };
};

export const inferMt19937FromText = (value: string) => {
  const fields = parseLooseCtfFields(value);
  const fieldSequence = looseField(fields, ['outputs', 'output', 'states', 'state', 'samples', 'values', 'leaks', 'sequence', 'randoms']);
  const indexed = parseNamedIndexedSequence(value, ['output', 'outputs', 'state', 'states', 'sample', 'samples', 'value', 'values', 'rand', 'random']);
  const rawNumbers = (fieldSequence
    ? parseNumericList(fieldSequence)
    : indexed.length >= 2
      ? indexed
      : parseNumericList(stripPrngScalarAssignments(value)))
    .filter(number => number >= 0n);
  const expanded = expandMt19937WordCandidates(rawNumbers);
  const numbers = expanded.outputs32.length >= 624
    ? expanded.outputs32
    : expanded.expandedPacked.length >= 624
      ? expanded.expandedPacked
      : expanded.outputs32;
  const lower = value.toLowerCase();
  const floatMatches = Array.from(value.matchAll(/\b0\.\d{6,17}\b/g)).map(match => Number(match[0])).filter(number => Number.isFinite(number) && number >= 0 && number < 1);
  let confidence = 0;
  if (/mt19937|mersenne|twister|randcrack|python random|random\.getrandbits|random\.randrange/.test(lower)) confidence += 6;
  // Truncated bit detection: getrandbits(31) gives values < 2^31 (0x80000000)
  const truncatedBits = /getrandbits\s*\(\s*(\d+)\s*\)/.exec(lower);
  const truncBitSize = truncatedBits ? Number(truncatedBits[1]) : null;
  if (truncBitSize && truncBitSize < 32 && truncBitSize > 0) confidence += 4;
  if (numbers.length >= 624) confidence += 6;
  else if (numbers.length >= 16) confidence += 2;
  if (expanded.packedOutputs.length >= 78) confidence += 2;
  if (/\brandom\.random\b|getrandbits\(\s*53\s*\)|python random float/.test(lower)) confidence += 5;
  if (floatMatches.length >= 8) confidence += 3;
  const wordFormat = expanded.outputs32.length >= 624
    ? '32-bit'
    : expanded.expandedPacked.length >= 624
      ? `${expanded.inferredWordBits}-bit-packed`
      : floatMatches.length >= 8
        ? 'python-random-float'
        : 'insufficient';
  return { numbers, confidence, fields, wordFormat, floatOutputs: floatMatches };
};

export const extractPythonRandomFloatWords = (values: number[]) => values
  .filter(value => Number.isFinite(value) && value >= 0 && value < 1)
  .map(value => {
    const numerator = BigInt(Math.round(value * 2 ** 53));
    const hi27 = numerator >> 26n;
    const lo26 = numerator & ((1n << 26n) - 1n);
    return {
      value,
      numerator: numerator.toString(),
      hi27: hi27.toString(),
      lo26: lo26.toString(),
    };
  });

export const extractPythonRandrangeSamples = (value: string) => {
  const samples: Array<{ index: number; value: string; upperBound: string; lowerBound?: string | null; rangeWidth?: string | null }> = [];
  const rangeCall = value.match(/\brandrange\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)/i);
  const indexed = Array.from(value.matchAll(/\b(?:rand|random|output|sample|value)\s*\[?\s*(\d+)\s*\]?\s*[:=]\s*(\d+)\s*(?:\/\s*(\d+)|<\s*(\d+)|bound\s*[:=]\s*(\d+)|mod\s*[:=]\s*(\d+)|%\s*(\d+))?/gi));
  for (const match of indexed) {
    const upperBound = match[3] || match[4] || match[5] || match[6] || match[7] || '';
    if (!upperBound) continue;
    samples.push({
      index: Number(match[1]),
      value: match[2],
      upperBound,
      lowerBound: null,
      rangeWidth: upperBound || null,
    });
  }
  if (samples.length) {
    return samples
      .sort((left, right) => left.index - right.index)
      .filter((entry, index) => index === 0 || entry.index !== samples[index - 1].index);
  }

  const globalBound = value.match(/\b(?:randrange|randbelow)\s*\(\s*(\d+)\s*\)/i)?.[1]
    || (rangeCall ? String(Number(rangeCall[2]) - Number(rangeCall[1])) : '')
    || value.match(/\b(?:upper|bound|range|max)\s*[:=]\s*(\d+)\b/i)?.[1]
    || value.match(/\b(?:outputs?|samples?|values?)\s+are\s+below\s+(\d+)\b/i)?.[1]
    || value.match(/\bmod(?:ulo)?\s+(\d+)\b/i)?.[1]
    || value.match(/%\s*(\d+)\b/i)?.[1]
    || '';
  if (!globalBound) return [];
  const numbered = parseNamedIndexedSequence(value, ['output', 'outputs', 'sample', 'samples', 'value', 'values', 'rand', 'random']);
  if (!numbered.length) return [];
  return numbered.map((entry, index) => ({
    index,
    value: entry.toString(),
    upperBound: globalBound,
    lowerBound: rangeCall ? rangeCall[1] : null,
    rangeWidth: rangeCall ? String(Number(rangeCall[2]) - Number(rangeCall[1])) : globalBound,
  }));
};

export const uint32 = (value: number) => value >>> 0;

export const mt19937Temper = (value: number) => {
  let y = uint32(value);
  y = uint32(y ^ (y >>> 11));
  y = uint32(y ^ ((y << 7) & 0x9d2c5680));
  y = uint32(y ^ ((y << 15) & 0xefc60000));
  y = uint32(y ^ (y >>> 18));
  return y;
};

export const undoRightShiftXor = (value: number, shift: number) => {
  let x = uint32(value);
  for (let index = 0; index < 6; index += 1) x = uint32(value ^ (x >>> shift));
  return x;
};

export const undoLeftShiftXorMask = (value: number, shift: number, mask: number) => {
  let x = uint32(value);
  for (let index = 0; index < 6; index += 1) x = uint32(value ^ ((x << shift) & mask));
  return x;
};

export const mt19937Untemper = (value: number) => {
  let y = uint32(value);
  y = undoRightShiftXor(y, 18);
  y = undoLeftShiftXorMask(y, 15, 0xefc60000);
  y = undoLeftShiftXorMask(y, 7, 0x9d2c5680);
  y = undoRightShiftXor(y, 11);
  return y;
};

export const mt19937PredictFromOutputs = (outputs: bigint[], count = 10) => {
  if (outputs.length < 624) return null;
  const mt = outputs.slice(0, 624).map(output => mt19937Untemper(Number(output) >>> 0));
  let index = 624;
  const twist = () => {
    for (let i = 0; i < 624; i += 1) {
      const y = uint32((mt[i] & 0x80000000) + (mt[(i + 1) % 624] & 0x7fffffff));
      mt[i] = uint32(mt[(i + 397) % 624] ^ (y >>> 1));
      if (y % 2 !== 0) mt[i] = uint32(mt[i] ^ 0x9908b0df);
    }
    index = 0;
  };
  const extract = () => {
    if (index >= 624) twist();
    const y = mt[index];
    index += 1;
    return mt19937Temper(y);
  };
  return {
    recoveredStatePreview: mt.slice(0, 12).map(entry => entry.toString()),
    predictedNext: Array.from({ length: count }, () => extract().toString()),
  };
};

export type SignatureNonceRecord = {
  index: string;
  r: bigint | null;
  s: bigint | null;
  z: bigint | null;
  message?: string | null;
  raw: Record<string, string>;
};

export type SignaturePartialNonceConstraint = {
  index: string;
  knownValue: string | null;
  knownBits: number | null;
  position: 'msb' | 'lsb' | 'biased' | 'offset' | 'unknown';
  positions?: Array<'msb' | 'lsb' | 'biased' | 'offset'>;
  relation: string | null;
};

export type SignatureScheme = 'ecdsa-dsa' | 'schnorr';

export const signatureRecordAliases = {
  r: ['r'],
  s: ['s'],
  z: ['z', 'h', 'hash', 'digest', 'messagehash', 'msghash', 'msgdigest', 'm'],
  message: ['message', 'msg', 'plaintext', 'plain', 'data', 'payload'],
  signature: ['signature', 'sig', 'dersignature', 'der', 'sighex', 'signaturehex', 'rawsignature'],
};
export const signatureTokenAliases = ['token', 'jwt', 'jws', 'compactjwt', 'compactjws', 'compacttoken'];

export const signatureCurveOrders: Record<string, bigint> = {
  secp256k1: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'),
  secp256r1: BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),
  prime256v1: BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),
  p256: BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),
  nistp256: BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'),
  secp224r1: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D'),
  p224: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D'),
  nistp224: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D'),
  secp384r1: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973'),
  p384: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973'),
  nistp384: BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973'),
  secp521r1: BigInt('0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'),
  p521: BigInt('0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'),
  nistp521: BigInt('0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'),
  ed25519: BigInt('0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED'),
};
export const signatureCurveExportNames: Record<string, string> = {
  secp256k1: 'SECP256K1',
  secp256r1: 'SECP256R1',
  prime256v1: 'SECP256R1',
  p256: 'SECP256R1',
  nistp256: 'SECP256R1',
  secp384r1: 'SECP384R1',
  p384: 'SECP384R1',
  nistp384: 'SECP384R1',
  secp521r1: 'SECP521R1',
  p521: 'SECP521R1',
  nistp521: 'SECP521R1',
};

export const joseEcdsaConfigs: Record<string, { hashAlgorithm: 'sha256' | 'sha384' | 'sha512'; curve: string; bytesPerScalar: number }> = {
  ES256: { hashAlgorithm: 'sha256', curve: 'secp256r1', bytesPerScalar: 32 },
  ES384: { hashAlgorithm: 'sha384', curve: 'secp384r1', bytesPerScalar: 48 },
  ES512: { hashAlgorithm: 'sha512', curve: 'secp521r1', bytesPerScalar: 66 },
};

export const inferSignatureHashAlgorithm = (value: string, fields: Record<string, string>) => {
  const explicit = looseField(fields, ['algorithm', 'alg', 'hashalgorithm', 'digestalgorithm']).toLowerCase().replace(/[^a-z0-9-]/g, '');
  const normalizedExplicit = explicit.replace('-', '');
  if (['md5', 'sha1', 'sha256', 'sha384', 'sha512'].includes(normalizedExplicit)) return normalizedExplicit;
  if (['es256', 'hs256', 'rs256', 'ps256'].includes(normalizedExplicit)) return 'sha256';
  if (['es384', 'hs384', 'rs384', 'ps384'].includes(normalizedExplicit)) return 'sha384';
  if (['es512', 'hs512', 'rs512', 'ps512'].includes(normalizedExplicit)) return 'sha512';
  const inline = value.match(/\b(md5|sha1|sha-1|sha256|sha-256|sha384|sha-384|sha512|sha-512)\b/i)?.[1].toLowerCase().replace('-', '') || '';
  return ['md5', 'sha1', 'sha256', 'sha384', 'sha512'].includes(inline) ? inline : 'sha256';
};

export const inferSignatureOrder = (fields: Record<string, string>) => {
  const explicit = parseNumericValue(looseField(fields, ['n', 'q', 'order', 'curveorder', 'grouporder', 'subgrouporder', 'modulus']));
  if (explicit != null) return explicit;
  const curve = normalizeLooseFieldName(looseField(fields, ['curve', 'crv', 'group', 'domain', 'params']));
  if (curve && signatureCurveOrders[curve]) return signatureCurveOrders[curve];
  const algorithm = normalizeLooseFieldName(looseField(fields, ['algorithm', 'alg']));
  if (['es256', 'rs256', 'ps256', 'hs256'].includes(algorithm)) return signatureCurveOrders.secp256r1;
  if (['es384', 'rs384', 'ps384', 'hs384'].includes(algorithm)) return signatureCurveOrders.secp384r1;
  if (['es512', 'rs512', 'ps512', 'hs512'].includes(algorithm)) return signatureCurveOrders.secp521r1;
  return null;
};

export const inferSignatureScheme = (value: string, fields: Record<string, string>): SignatureScheme => {
  const explicit = looseField(fields, ['scheme', 'signaturescheme', 'type', 'sigtype']).toLowerCase();
  const alg = looseField(fields, ['algorithm', 'alg']).toLowerCase();
  const source = `${explicit} ${alg} ${value}`.toLowerCase();
  if (/\bschnorr\b|bip340|taproot/.test(source)) return 'schnorr';
  return 'ecdsa-dsa';
};

export const digestHexToSignatureZ = (digestHex: string, order: bigint | null) => {
  const numeric = BigInt(`0x${digestHex.replace(/^0x/i, '') || '0'}`);
  if (order == null) return numeric;
  const extraBits = bitLength(numeric) - bitLength(order);
  return extraBits > 0 ? (numeric >> BigInt(extraBits)) : numeric;
};



export const parseSignatureBlobToRS = (value: string) => {
  const text = String(value || '').trim();
  if (!text) return null;
  try {
    const input = parseAsn1Input(text);
    const state = { count: 0 };
    const nodes = parseAsn1TopLevel(input.bytes, 0, state);
    const sequence = nodes.find(node => node.type === 'SEQUENCE' && (node.children || []).length >= 2);
    const integerChildren = (sequence?.children || [])
      .map(child => asn1IntegerValue(child))
      .filter((entry): entry is bigint => typeof entry === 'bigint');
    if (integerChildren.length >= 2) {
      return {
        r: integerChildren[0],
        s: integerChildren[1],
        format: `DER ${input.encoding}`,
      };
    }
  } catch {
    // Fall back to compact raw signatures below.
  }

  const decimalTuple = text.match(/^\(\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*,\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*\)$/i);
  if (decimalTuple) {
    const r = parseNumericValue(decimalTuple[1]);
    const s = parseNumericValue(decimalTuple[2]);
    if (r != null && s != null) {
      return {
        r,
        s,
        format: 'tuple r,s',
      };
    }
  }

  const rawHex = text.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  if (/^[0-9a-f]+$/i.test(rawHex) && rawHex.length >= 80 && rawHex.length % 2 === 0 && rawHex.length % 4 === 0) {
    const half = rawHex.length / 2;
    const left = rawHex.slice(0, half);
    const right = rawHex.slice(half);
    const r = parseNumericValue(`0x${left}`);
    const s = parseNumericValue(`0x${right}`);
    if (r != null && s != null) {
      return {
        r,
        s,
        format: 'raw r||s hex',
      };
    }
  }
  return null;
};

export const parseCompactJoseSignatureRecord = (token: string, index: string): SignatureNonceRecord | null => {
  const parts = token.trim().split('.');
  if (parts.length !== 3) return null;
  try {
    const header = decodeBase64UrlJson(parts[0]) as { alg?: string };
    const alg = String(header?.alg || '');
    const config = joseEcdsaConfigs[alg];
    if (!config) return null;
    const signatureBytes = base64ToBytes(parts[2]);
    if (signatureBytes.length !== config.bytesPerScalar * 2) return null;
    const r = bigintFromBytes(signatureBytes.slice(0, config.bytesPerScalar));
    const s = bigintFromBytes(signatureBytes.slice(config.bytesPerScalar));
    return {
      index,
      r,
      s,
      z: null,
      message: `${parts[0]}.${parts[1]}`,
      raw: {
        token,
        algorithm: alg,
        curve: config.curve,
        signatureformat: `JOSE ${alg}`,
      },
    };
  } catch {
    return null;
  }
};

export const parseSignatureTupleList = (value: string) => Array.from(String(value || '').matchAll(/\(\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*,\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*\)/gi))
  .map(match => ({
    r: parseNumericValue(match[1]),
    s: parseNumericValue(match[2]),
  }))
  .filter((entry): entry is { r: bigint; s: bigint } => entry.r != null && entry.s != null);

export const parseLooseTextList = (value: string) => {
  const text = String(value || '').trim();
  if (!text) return [];
  const quoted = Array.from(text.matchAll(/(['"`])([\s\S]*?)\1/g)).map(match => match[2]);
  if (quoted.length) return quoted;
  return text
    .split(',')
    .map(entry => cleanSymmetricFieldValue(entry))
    .filter(Boolean);
};

export const parseJoseTokenList = (value: string) => {
  const direct = Array.from(String(value || '').matchAll(/\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g)).map(match => match[0]);
  if (direct.length) return direct;
  return parseLooseTextList(value).flatMap(entry => entry.match(/\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g) || []);
};

export const mergeSignatureTokenRecord = (
  index: string,
  token: string,
  extraRaw: Record<string, string>,
  z: bigint | null,
  message: string | null,
): SignatureNonceRecord | null => {
  const record = parseCompactJoseSignatureRecord(token, index);
  if (!record) return null;
  return {
    ...record,
    z: z ?? record.z,
    message: message || record.message || null,
    raw: {
      ...record.raw,
      ...extraRaw,
    },
  };
};


export const collectSignatureLooseObjectBlocks = (value: string, output: SignatureNonceRecord[]) => {
  for (const { index, fields } of parseLooseObjectBlocks(value, 200)) {
    const signatureText = looseField(fields, signatureRecordAliases.signature);
    const parsedSignature = signatureText ? parseSignatureBlobToRS(signatureText) : null;
    const tokenText = looseField(fields, signatureTokenAliases);
    const r = parseNumericValue(looseField(fields, ['r'])) ?? parsedSignature?.r ?? null;
    const s = parseNumericValue(looseField(fields, ['s'])) ?? parsedSignature?.s ?? null;
    const z = parseNumericValue(looseField(fields, signatureRecordAliases.z));
    const message = looseField(fields, signatureRecordAliases.message);
    if (r != null && s != null) {
      output.push({
        index,
        r,
        s,
        z,
        message: message || null,
        raw: {
          ...fields,
          ...(parsedSignature?.format ? { signatureformat: parsedSignature.format } : {}),
        },
      });
      continue;
    }
    const tokenRecord = tokenText ? mergeSignatureTokenRecord(index, tokenText, fields, z, message || null) : null;
    if (tokenRecord) {
      output.push(tokenRecord);
    }
  }
};

export const collectSignatureJsonRecords = (value: unknown, output: SignatureNonceRecord[], path = 'json') => {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectSignatureJsonRecords(entry, output, `${path}[${index}]`));
    return;
  }
  const object = value as Record<string, unknown>;
  const signatureText = cleanSymmetricFieldValue(getObjectAliasValue(object, signatureRecordAliases.signature));
  const parsedSignature = signatureText ? parseSignatureBlobToRS(signatureText) : null;
  const tokenText = cleanSymmetricFieldValue(getObjectAliasValue(object, signatureTokenAliases));
  const r = parseNumberishUnknown(getObjectAliasValue(object, signatureRecordAliases.r)) ?? parsedSignature?.r ?? null;
  const s = parseNumberishUnknown(getObjectAliasValue(object, signatureRecordAliases.s)) ?? parsedSignature?.s ?? null;
  const z = parseNumberishUnknown(getObjectAliasValue(object, signatureRecordAliases.z));
  const message = cleanSymmetricFieldValue(getObjectAliasValue(object, signatureRecordAliases.message));
  const raw = {
    ...Object.fromEntries(Object.entries(object).map(([key, entry]) => [key, cleanSymmetricFieldValue(entry)])),
    ...(parsedSignature?.format ? { signatureformat: parsedSignature.format } : {}),
  };
  if (r != null && s != null) {
    output.push({
      index: path,
      r,
      s,
      z,
      message: message || null,
      raw,
    });
  } else {
    const tokenRecord = tokenText ? mergeSignatureTokenRecord(path, tokenText, raw, z, message || null) : null;
    if (tokenRecord) output.push(tokenRecord);
  }
  for (const [key, entry] of Object.entries(object)) {
    if (entry && typeof entry === 'object') collectSignatureJsonRecords(entry, output, `${path}.${key}`);
  }
};

export const scoreSignatureRecordSpecificity = (record: SignatureNonceRecord) => {
  let score = Object.keys(record.raw || {}).length;
  if (record.z != null) score += 16;
  if (record.message) score += 10;
  if (record.raw.signatureformat) score += 6;
  if (/^tokenlist-/i.test(record.index)) score += 14;
  else if (/^siglist-/i.test(record.index)) score += 12;
  else if (/^json/i.test(record.index)) score += 10;
  else if (/^\d+$/i.test(record.index)) score += 8;
  else if (/^jose-/i.test(record.index)) score += 2;
  else if (/^line-/i.test(record.index)) score += 1;
  return score;
};

export const parseSignatureNonceRecords = (value: string) => {
  const fields = parseLooseCtfFields(value);
  const records: SignatureNonceRecord[] = [];
  try {
    collectSignatureJsonRecords(JSON.parse(value), records);
  } catch {
    // Most challenge statements are prose or Python-style snippets.
  }
  collectSignatureLooseObjectBlocks(value, records);
  const joseTokens = Array.from(value.matchAll(/\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g)).map(match => match[0]);
  joseTokens.forEach((token, index) => {
    const record = parseCompactJoseSignatureRecord(token, `jose-${index + 1}`);
    if (record) records.push(record);
  });
  for (const [key, entry] of Object.entries(fields)) {
    if (!/^(?:token|jws|jwt|sig|signature)\d+$/i.test(key)) continue;
    const record = parseCompactJoseSignatureRecord(entry, key);
    if (record) records.push(record);
  }
  const tokenListSource = extractBracketedAssignment(value, ['tokens', 'jwts', 'jwss', 'tokenlist', 'jwtlist', 'jwslist']) || looseField(fields, ['tokens', 'jwts', 'jwss', 'tokenlist', 'jwtlist', 'jwslist']);
  const tokenList = parseJoseTokenList(tokenListSource);
  tokenList.forEach((token, index) => {
    const record = parseCompactJoseSignatureRecord(token, `tokenlist-${index + 1}`);
    if (record) records.push(record);
  });
  const signatureListSource = extractBracketedAssignment(value, ['signatures', 'sigs', 'signaturelist', 'siglist']) || looseField(fields, ['signatures', 'sigs', 'signaturelist', 'siglist']);
  const messageListSource = extractBracketedAssignment(value, ['messages', 'msgs', 'messagelist', 'msglist', 'payloads', 'texts']) || looseField(fields, ['messages', 'msgs', 'messagelist', 'msglist', 'payloads', 'texts']);
  const signatureList = parseSignatureTupleList(signatureListSource);
  const messageList = parseLooseTextList(messageListSource);
  const zList = parseNumericList(looseField(fields, ['zs', 'zlist', 'digests', 'hashes', 'messagehashes']));
  if (signatureList.length >= 2) {
    for (let index = 0; index < signatureList.length; index += 1) {
      records.push({
        index: `siglist-${index + 1}`,
        r: signatureList[index].r,
        s: signatureList[index].s,
        z: zList[index] ?? null,
        message: messageList[index] || null,
        raw: {
          signatures: signatureListSource,
          messages: messageListSource,
          zs: looseField(fields, ['zs', 'zlist', 'digests', 'hashes', 'messagehashes']),
          algorithm: looseField(fields, ['algorithm', 'alg']),
          scheme: looseField(fields, ['scheme', 'type']),
          order: looseField(fields, ['n', 'q', 'order', 'curveorder', 'grouporder', 'subgrouporder', 'modulus']),
        },
      });
    }
  }
  for (const { index, record } of parseLooseIndexedRecords(fields, signatureRecordAliases)) {
    const parsedSignature = record.signature ? parseSignatureBlobToRS(record.signature) : null;
    records.push({
      index: String(index),
      r: record.r ? parseNumericValue(record.r) : parsedSignature?.r ?? null,
      s: record.s ? parseNumericValue(record.s) : parsedSignature?.s ?? null,
      z: record.z ? parseNumericValue(record.z) : null,
      message: record.message || null,
      raw: {
        ...record,
        ...(parsedSignature?.format ? { signatureformat: parsedSignature.format } : {}),
      },
    });
  }
  const chineseSignatureRecords = new Map<string, { r?: bigint; s?: bigint; z?: bigint; raw: Record<string, string> }>();
  for (const line of value.normalize('NFKC').split(/\r?\n/)) {
    const match = line.match(/^\s*(签名|哈希|摘要|消息哈希)\s*(\d+)\s*[:=]\s*(.+?)\s*$/u);
    if (!match) continue;
    const index = match[2];
    const entry = chineseSignatureRecords.get(index) || { raw: {} };
    const label = match[1];
    const content = cleanSymmetricFieldValue(match[3]);
    if (label === '签名') {
      const parsed = parseSignatureBlobToRS(content);
      if (parsed) {
        entry.r = parsed.r;
        entry.s = parsed.s;
        entry.raw.signature = content;
        entry.raw.signatureformat = parsed.format;
      }
    } else {
      const numeric = parseNumericValue(content);
      if (numeric != null) {
        entry.z = numeric;
        entry.raw.z = content;
      }
    }
    chineseSignatureRecords.set(index, entry);
  }
  for (const [index, record] of chineseSignatureRecords) {
    if (record.r != null && record.s != null) {
      records.push({
        index: `cn-${index}`,
        r: record.r,
        s: record.s,
        z: record.z ?? null,
        message: null,
        raw: record.raw,
      });
    }
  }
  for (const [lineIndex, line] of value.split(/\r?\n/).entries()) {
    if (!/\br\s*[:=]/i.test(line) && !/\bs\s*[:=]/i.test(line) && !/\b(?:signature|sig|der)\s*[:=]/i.test(line)) continue;
    const lineFields = parseLooseCtfFields(line);
    const signatureText = looseField(lineFields, signatureRecordAliases.signature);
    const parsedSignature = signatureText ? parseSignatureBlobToRS(signatureText) : null;
    const r = parseNumericValue(looseField(lineFields, ['r'])) ?? parsedSignature?.r ?? null;
    const s = parseNumericValue(looseField(lineFields, ['s'])) ?? parsedSignature?.s ?? null;
    const z = parseNumericValue(looseField(lineFields, signatureRecordAliases.z));
    const message = looseField(lineFields, signatureRecordAliases.message);
    if (r != null && s != null) {
      records.push({
        index: `line-${lineIndex + 1}`,
        r,
        s,
        z,
        message: message || null,
        raw: {
          ...lineFields,
          ...(parsedSignature?.format ? { signatureformat: parsedSignature.format } : {}),
        },
      });
    }
  }
  const unique = new Map<string, SignatureNonceRecord>();
  for (const record of records) {
    const key = `${record.r?.toString() || ''}:${record.s?.toString() || ''}:${record.z?.toString() || ''}`;
    const existing = unique.get(key);
    if (!existing || scoreSignatureRecordSpecificity(record) > scoreSignatureRecordSpecificity(existing)) {
      unique.set(key, record);
    }
  }
  return { fields, records: Array.from(unique.values()) };
};

export const inferSignatureNonceReuseFromText = (value: string) => {
  const { fields, records } = parseSignatureNonceRecords(value);
  const globalOrder = inferSignatureOrder(fields);
  const globalScheme = inferSignatureScheme(value, fields);
  const lower = value.toLowerCase();
  const repeatedPairs: Array<{ left: SignatureNonceRecord; right: SignatureNonceRecord }> = [];
  for (let left = 0; left < records.length; left += 1) {
    for (let right = left + 1; right < records.length; right += 1) {
      if (records[left].r != null && records[right].r != null && records[left].r === records[right].r) {
        repeatedPairs.push({ left: records[left], right: records[right] });
      }
    }
  }
  const recoveries = repeatedPairs.map(({ left, right }) => {
    const order = globalOrder || inferSignatureOrder(left.raw) || inferSignatureOrder(right.raw);
    const scheme = globalScheme === 'schnorr' || inferSignatureScheme('', left.raw) === 'schnorr' || inferSignatureScheme('', right.raw) === 'schnorr'
      ? 'schnorr'
      : 'ecdsa-dsa';
    if (order == null || left.r == null || left.s == null || right.s == null || left.z == null || right.z == null) {
      return { left: left.index, right: right.index, repeatedR: left.r?.toString() || null, recoverable: false };
    }
    if (scheme === 'schnorr') {
      const challengeDelta = ((left.z - right.z) % order + order) % order;
      const challengeInv = bigintModInverse(challengeDelta, order);
      if (!challengeInv) return { left: left.index, right: right.index, repeatedR: left.r.toString(), recoverable: false, reason: 'non-invertible challenge delta', scheme };
      const privateKey = (((left.s - right.s) % order + order) * challengeInv) % order;
      const nonceK = ((left.s - left.z * privateKey) % order + order) % order;
      return {
        left: left.index,
        right: right.index,
        repeatedR: left.r.toString(),
        recoverable: true,
        scheme,
        nonceK: nonceK.toString(),
        privateKey: privateKey.toString(),
        privateKeyHex: `0x${privateKey.toString(16)}`,
      };
    }
    const sDelta = ((left.s - right.s) % order + order) % order;
    const zDelta = ((left.z - right.z) % order + order) % order;
    const sDeltaInv = bigintModInverse(sDelta, order);
    const rInv = bigintModInverse(left.r, order);
    if (!sDeltaInv || !rInv) return { left: left.index, right: right.index, repeatedR: left.r.toString(), recoverable: false, reason: 'non-invertible denominator or r', scheme };
    const k = (zDelta * sDeltaInv) % order;
    const privateKey = (((left.s * k - left.z) % order + order) * rInv) % order;
    return {
      left: left.index,
      right: right.index,
      repeatedR: left.r.toString(),
      recoverable: true,
      scheme,
      nonceK: k.toString(),
      privateKey: privateKey.toString(),
      privateKeyHex: `0x${privateKey.toString(16)}`,
    };
  });
  let confidence = 0;
  if (/\b(?:ecdsa|dsa|schnorr|signature|nonce reuse|same nonce|reused nonce)\b|重复随机数|随机数复用|重复 nonce|nonce 复用|签名重复/.test(lower)) confidence += 6;
  if (records.length >= 2) confidence += 2;
  if (repeatedPairs.length) confidence += 5;
  if (globalOrder != null || records.some(record => inferSignatureOrder(record.raw) != null)) confidence += 2;
  if (records.some(record => record.z != null)) confidence += 1;
  const resolvedOrder = globalOrder || records.map(record => inferSignatureOrder(record.raw)).find((entry): entry is bigint => entry != null) || null;
  return { fields, records, order: resolvedOrder, scheme: globalScheme, repeatedPairs, recoveries, confidence };
};

export const inferSignaturePartialNonceConstraints = (value: string, records: SignatureNonceRecord[]) => {
  const fields = parseLooseCtfFields(value);
  const lines = value.split(/\r?\n/);
  const constraints: SignaturePartialNonceConstraint[] = [];
  const pushConstraint = (constraint: SignaturePartialNonceConstraint) => {
    if (!constraint.knownValue && !constraint.relation && constraint.knownBits == null) return;
    constraints.push(constraint);
  };

  for (const record of records) {
    const indexedFields = parseLooseCtfFields(lines.join('\n'));
    const knownBitsText = looseField(indexedFields, [
      `knownbits${record.index}`, `noncebits${record.index}`, `kbits${record.index}`, `bits${record.index}`,
      `${record.index}knownbits`, `${record.index}noncebits`, `${record.index}kbits`,
    ]) || looseField(record.raw, ['knownbits', 'noncebits', 'kbits', 'bits']);
    const knownValueText = looseField(indexedFields, [
      `knownk${record.index}`, `nonce${record.index}`, `k${record.index}`, `partialnonce${record.index}`,
      `${record.index}knownk`, `${record.index}nonce`, `${record.index}k`,
    ]) || looseField(record.raw, ['knownk', 'nonce', 'k', 'partialnonce']);
    const relationText = looseField(record.raw, ['relation', 'formula', 'expr', 'equation']) || '';
    const bitMatch = knownBitsText.match(/\d+/);
    const lower = `${JSON.stringify(record.raw)} ${lines.join('\n')}`.toLowerCase();
    let position: SignaturePartialNonceConstraint['position'] = 'unknown';
    const positions: Array<'msb' | 'lsb' | 'biased' | 'offset'> = [];
    if (/\bmsb|high bits|top bits|prefix\b/.test(lower)) positions.push('msb');
    if (/\blsb|low bits|lower bits|suffix\b/.test(lower)) positions.push('lsb');
    if (/\bbiased|small nonce|short nonce\b/.test(lower)) positions.push('biased');
    if (/\boffset|k\s*=\s*k0\s*\+|2\^\d+\s*\*/.test(lower)) positions.push('offset');
    if (positions.length) position = positions[0];
    pushConstraint({
      index: record.index,
      knownValue: knownValueText || null,
      knownBits: bitMatch ? Number(bitMatch[0]) : null,
      position,
      positions: positions.length ? positions : undefined,
      relation: relationText || null,
    });
  }

  const globalKnownBits = looseField(fields, ['knownbits', 'noncebits', 'kbits', 'bits']);
  const globalKnownValue = looseField(fields, ['knownk', 'nonce', 'partialnonce']);
  const relationLine = lines.find(line => /\bk\s*=\s*k0\s*\+\s*2\^\d+\s*\*/i.test(line) || /\brelation\b|\bformula\b|\bequation\b/i.test(line)) || '';
  const globalRelation = looseField(fields, ['relation', 'formula', 'expr', 'equation']) || relationLine.trim();
  const bitMatch = globalKnownBits.match(/\d+/);
  const globalLower = value.toLowerCase();
  let globalPosition: SignaturePartialNonceConstraint['position'] = 'unknown';
  const globalPositions: Array<'msb' | 'lsb' | 'biased' | 'offset'> = [];
  if (/\bmsb|high bits|top bits|prefix\b/.test(globalLower)) globalPositions.push('msb');
  if (/\blsb|low bits|lower bits|suffix\b/.test(globalLower)) globalPositions.push('lsb');
  if (/\bbiased|small nonce|short nonce\b/.test(globalLower)) globalPositions.push('biased');
  if (/\boffset|k\s*=\s*k0\s*\+|2\^\d+\s*\*/.test(globalLower)) globalPositions.push('offset');
  if (globalPositions.length) globalPosition = globalPositions[0];
  if (globalKnownBits || globalKnownValue || globalRelation) {
    constraints.push({
      index: 'global',
      knownValue: globalKnownValue || null,
      knownBits: bitMatch ? Number(bitMatch[0]) : null,
      position: globalPosition,
      positions: globalPositions.length ? globalPositions : undefined,
      relation: globalRelation || null,
    });
  }

  const unique = new Map<string, SignaturePartialNonceConstraint>();
  for (const constraint of constraints) {
    const key = `${constraint.index}:${constraint.knownValue || ''}:${constraint.knownBits || ''}:${constraint.position}:${constraint.relation || ''}`;
    if (!unique.has(key)) unique.set(key, constraint);
  }
  return Array.from(unique.values());
};

export const guessSignatureCurveExportName = (order: bigint | null, records: Array<{ raw: Record<string, string> }>, fields: Record<string, string>) => {
  const explicitCurve = normalizeLooseFieldName(looseField(fields, ['curve', 'crv', 'domain', 'params']));
  if (explicitCurve && signatureCurveExportNames[explicitCurve]) return signatureCurveExportNames[explicitCurve];
  for (const record of records) {
    const curve = normalizeLooseFieldName(looseField(record.raw, ['curve', 'crv', 'domain', 'params']));
    if (curve && signatureCurveExportNames[curve]) return signatureCurveExportNames[curve];
  }
  if (order != null) {
    for (const [name, curveOrder] of Object.entries(signatureCurveOrders)) {
      if (curveOrder === order && signatureCurveExportNames[name]) return signatureCurveExportNames[name];
    }
  }
  return '';
};

export const buildBitlogikLatticeTemplates = (
  order: bigint | null,
  fields: Record<string, string>,
  records: Array<{ index: string; r: bigint | null; s: bigint | null; z: bigint | null; raw: Record<string, string> }>,
  constraints: SignaturePartialNonceConstraint[],
) => {
  const curveName = guessSignatureCurveExportName(order, records, fields);
  const globalByPosition = new Map<string, SignaturePartialNonceConstraint>();
  for (const constraint of constraints) {
    if (constraint.index === 'global') globalByPosition.set(constraint.position, constraint);
  }
  const normalizedConstraints = constraints
    .filter(constraint => constraint.index !== 'global')
    .map(constraint => {
      const global = globalByPosition.get(constraint.position);
      return {
        ...constraint,
        knownBits: constraint.knownBits ?? global?.knownBits ?? null,
        relation: constraint.relation ?? global?.relation ?? null,
      };
    });
  const supported = normalizedConstraints.filter(constraint => (
    constraint.knownValue
    && constraint.knownBits != null
    && constraint.knownBits >= 4
    && (constraint.position === 'msb' || constraint.position === 'lsb')
  ));
  const grouped = new Map<string, SignaturePartialNonceConstraint[]>();
  for (const constraint of supported) {
    const key = `${constraint.position}:${constraint.knownBits}`;
    grouped.set(key, [...(grouped.get(key) || []), constraint]);
  }
  return Array.from(grouped.entries()).map(([key, group]) => {
    const [position, bitsText] = key.split(':');
    const knownTypes = Array.from(new Set(group.flatMap(item => item.positions?.map(entry => entry.toUpperCase()) || [position.toUpperCase()])));
    const signatureRows = group.map(constraint => {
      const record = records.find(entry => entry.index === constraint.index);
      const kp = constraint.knownValue || '0';
      return record && record.r != null && record.s != null
        ? {
            index: record.index,
            r: record.r.toString(),
            s: record.s.toString(),
            hash: record.z?.toString() || null,
            kp,
          }
        : null;
    }).filter(Boolean) as Array<{ index: string; r: string; s: string; hash: string | null; kp: string }>;
    const template = {
      curve: curveName || 'SECP256K1',
      public_key: ['<pub_x>', '<pub_y>'],
      known_type: position.toUpperCase(),
      known_bits: Number(bitsText),
      signatures: signatureRows.map(row => ({
        r: row.r,
        s: row.s,
        kp: row.kp,
        hash: row.hash,
      })),
    };
    return {
      format: 'bitlogik/lattice-attack',
      curveGuess: curveName || null,
      knownType: position.toUpperCase(),
      knownTypes,
      knownBits: Number(bitsText),
      signatureCount: signatureRows.length,
      note: 'bitlogik/lattice-attack expects integer values. Fill in the public key coordinates if you have them; keep hash per signature when messages differ.',
      template,
    };
  }).filter(entry => entry.signatureCount > 0);
};

export const trySmartSignatureNonceReuse = (value: string) => {
  const inference = inferSignatureNonceReuseFromText(value);
  const hasStrongHint = /\b(?:ecdsa|dsa|schnorr|signature|nonce reuse|same nonce|reused nonce)\b/i.test(value);
  if (inference.confidence < 8 || (!inference.repeatedPairs.length && !hasStrongHint)) return null;
  return `智能识别: Signature nonce reuse analysis\n\n${JSON.stringify({
    signatureCount: inference.records.length,
    scheme: inference.scheme,
    order: inference.order?.toString() || null,
    repeatedRCount: inference.repeatedPairs.length,
    recoveries: inference.recoveries,
    records: inference.records.map(record => ({
      index: record.index,
      r: record.r?.toString() || null,
      s: record.s?.toString() || null,
      z: record.z?.toString() || null,
    })),
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    formulas: {
      'ecdsa-dsa': 'k=(z1-z2)/(s1-s2) mod n; d=(s1*k-z1)/r mod n',
      schnorr: 'x=(s1-s2)/(e1-e2) mod n; k=s1-e1*x mod n',
    },
    notes: [
      'Needs two signatures over the same subgroup order with the same nonce commitment / repeated r.',
      'z is the integer message digest used by the signer; raw messages must be hashed exactly as the challenge code does.',
      'If only partial nonce bits are known, switch to HNP/lattice tooling such as Sage/fpylll.',
    ],
  }, null, 2)}`;
};

export const canSmartSignatureNonceReuse = (value: string) => Boolean(trySmartSignatureNonceReuse(value));

export const trySmartSignatureNonceReuseAsync = async (value: string) => {
  const inference = inferSignatureNonceReuseFromText(value);
  const hasStrongHint = /\b(?:ecdsa|dsa|schnorr|signature|nonce reuse|same nonce|reused nonce)\b/i.test(value);
  const partialConstraints = inferSignaturePartialNonceConstraints(value, inference.records);
  const hasPartialHint = /\b(?:partial nonce|biased nonce|known bits|msb|lsb|hnp|hidden number)\b/i.test(value) || partialConstraints.length > 0;
  if (inference.confidence < 8 || (!inference.repeatedPairs.length && !hasStrongHint && !hasPartialHint)) return null;
  return `智能识别: Signature nonce reuse analysis\n\n${await signatureNonceReuseHelper(value)}`;
};

export const signatureNonceReuseHelper = async (value: string) => {
  const { fields, records } = parseSignatureNonceRecords(value);
  const globalOrder = inferSignatureOrder(fields);
  const globalHashAlgorithm = inferSignatureHashAlgorithm(value, fields);
  const globalScheme = inferSignatureScheme(value, fields);
  const partialConstraints = inferSignaturePartialNonceConstraints(value, records);
  const enrichedRecords = await Promise.all(records.map(async record => {
    const recordOrder = globalOrder || inferSignatureOrder(record.raw);
    const recordHashAlgorithm = globalHashAlgorithm || inferSignatureHashAlgorithm('', record.raw);
    let z = record.z;
    let derivedDigestHex: string | null = null;
    if (z == null && record.message) {
      try {
        derivedDigestHex = await digest(record.message, recordHashAlgorithm);
        z = digestHexToSignatureZ(derivedDigestHex, recordOrder);
      } catch {
        derivedDigestHex = null;
      }
    }
    return {
      ...record,
      resolvedOrder: recordOrder,
      resolvedHashAlgorithm: recordHashAlgorithm,
      z,
      derivedDigestHex,
      derivedFromMessage: record.z == null && z != null && record.message != null,
    };
  }));
  const order = globalOrder || enrichedRecords.map(record => record.resolvedOrder).find((entry): entry is bigint => entry != null) || null;
  const hashAlgorithm = globalHashAlgorithm || enrichedRecords.map(record => record.resolvedHashAlgorithm).find(Boolean) || 'sha256';
  const bitlogikTemplates = buildBitlogikLatticeTemplates(order, fields, enrichedRecords, partialConstraints);
  const repeatedPairs: Array<{ left: typeof enrichedRecords[number]; right: typeof enrichedRecords[number] }> = [];
  for (let left = 0; left < enrichedRecords.length; left += 1) {
    for (let right = left + 1; right < enrichedRecords.length; right += 1) {
      if (enrichedRecords[left].r != null && enrichedRecords[right].r != null && enrichedRecords[left].r === enrichedRecords[right].r) {
        repeatedPairs.push({ left: enrichedRecords[left], right: enrichedRecords[right] });
      }
    }
  }
  const recoveries = repeatedPairs.map(({ left, right }) => {
    const pairOrder = order || left.resolvedOrder || right.resolvedOrder;
    const scheme = globalScheme === 'schnorr' || inferSignatureScheme('', left.raw) === 'schnorr' || inferSignatureScheme('', right.raw) === 'schnorr'
      ? 'schnorr'
      : 'ecdsa-dsa';
    if (pairOrder == null || left.r == null || left.s == null || right.s == null || left.z == null || right.z == null) {
      return { left: left.index, right: right.index, repeatedR: left.r?.toString() || null, recoverable: false };
    }
    if (scheme === 'schnorr') {
      const challengeDelta = ((left.z - right.z) % pairOrder + pairOrder) % pairOrder;
      const challengeInv = bigintModInverse(challengeDelta, pairOrder);
      if (!challengeInv) {
        return { left: left.index, right: right.index, repeatedR: left.r.toString(), recoverable: false, reason: 'non-invertible challenge delta', scheme };
      }
      const privateKey = (((left.s - right.s) % pairOrder + pairOrder) * challengeInv) % pairOrder;
      const nonceK = ((left.s - left.z * privateKey) % pairOrder + pairOrder) % pairOrder;
      return {
        left: left.index,
        right: right.index,
        repeatedR: left.r.toString(),
        recoverable: true,
        scheme,
        nonceK: nonceK.toString(),
        privateKey: privateKey.toString(),
        privateKeyHex: `0x${privateKey.toString(16)}`,
      };
    }
    const sDelta = ((left.s - right.s) % pairOrder + pairOrder) % pairOrder;
    const zDelta = ((left.z - right.z) % pairOrder + pairOrder) % pairOrder;
    const sDeltaInv = bigintModInverse(sDelta, pairOrder);
    const rInv = bigintModInverse(left.r, pairOrder);
    if (!sDeltaInv || !rInv) {
      return { left: left.index, right: right.index, repeatedR: left.r.toString(), recoverable: false, reason: 'non-invertible denominator or r', scheme };
    }
    const k = (zDelta * sDeltaInv) % pairOrder;
    const privateKey = (((left.s * k - left.z) % pairOrder + pairOrder) * rInv) % pairOrder;
    return {
      left: left.index,
      right: right.index,
      repeatedR: left.r.toString(),
      recoverable: true,
      scheme,
      nonceK: k.toString(),
      privateKey: privateKey.toString(),
      privateKeyHex: `0x${privateKey.toString(16)}`,
    };
  });
  return JSON.stringify({
    signatureCount: enrichedRecords.length,
    scheme: globalScheme,
    hashAlgorithm,
    order: order?.toString() || null,
    repeatedRCount: repeatedPairs.length,
    partialNonceConstraintCount: partialConstraints.length,
    partialNonceConstraints: partialConstraints,
    latticeAttackTemplates: bitlogikTemplates,
    recoveries,
    records: enrichedRecords.map(record => ({
      index: record.index,
      r: record.r?.toString() || null,
      s: record.s?.toString() || null,
      z: record.z?.toString() || null,
      message: record.message || null,
      signatureFormat: record.raw.signatureformat || null,
      derivedDigestHex: record.derivedDigestHex,
      derivedFromMessage: record.derivedFromMessage,
    })),
    inferredFields: fields,
    notes: [
      'Supports repeated-r recovery for both ECDSA/DSA and Schnorr-style signatures.',
      'When z is missing but message text is present, the helper hashes the message locally with the inferred digest algorithm.',
      'If only partial nonce bits are known, this still needs HNP/lattice tooling rather than direct algebra.',
      partialConstraints.length ? 'The helper extracted partial nonce / biased nonce constraints so you can feed them into Sage/fpylll/crypto-attacks HNP workflows.' : '',
      bitlogikTemplates.length ? 'A lattice-attack template compatible with bitlogik/lattice-attack style inputs was generated from the extracted MSB/LSB constraints.' : '',
    ],
  }, null, 2);
};

export const trySmartDiscreteLog = (value: string) => {
  const inference = inferDlpFromText(value);
  const hasStrongHint = /\b(discrete log|dlog|diffie|elgamal|generator|baby-step|bsgs|pohlig)\b|离散对数|迪菲|Diffie|ElGamal|生成元|椭圆曲线密码/i.test(value);
  if (inference.confidence < 6 || (!hasStrongHint && (inference.modulus == null || inference.base == null || inference.target == null))) return null;
  try {
    return `智能识别: Discrete log / ElGamal analysis\n\n${discreteLogHelper(value)}`;
  } catch {
    return null;
  }
};

export const canSmartDiscreteLog = (value: string) => Boolean(trySmartDiscreteLog(value));

export type DlpInference = {
  fields: Record<string, string>;
  modulus: bigint | null;
  base: bigint | null;
  target: bigint | null;
  order: bigint | null;
  c1: bigint | null;
  c2: bigint | null;
  confidence: number;
  notes: string[];
  dhB?: bigint | null;
};

export const parseDlpField = (fields: Record<string, string>, aliases: string[]) => {
  const raw = looseField(fields, aliases);
  return raw ? parseNumericValue(raw) : null;
};

export const inferDlpFromText = (value: string): DlpInference => {
  const fields = parseLooseCtfFields(value);
  const modulus = parseDlpField(fields, ['p', 'prime', 'mod', 'modulus']);
  const base = parseDlpField(fields, ['g', 'generator', 'base', 'alpha']);
  const target = parseDlpField(fields, ['h', 'y', 'public', 'publickey', 'pubkey', 'beta', 'value', 'ya', 'pub_a', 'alice_public', 'alice_key']);
  const explicitOrder = looseField(fields, ['q', 'order', 'grouporder', 'subgrouporder']);
  const order = (explicitOrder ? parseNumericValue(explicitOrder) : null) || (modulus != null ? modulus - 1n : null);
  const ciphertextTuple = parseNumericTuple(looseField(fields, ['ciphertext', 'cipher', 'ct', 'enc', 'elgamalcipher', 'pair', 'tuple']));
  const c1 = parseDlpField(fields, ['c1', 'u', 'leftcipher', 'cipher1']) || ciphertextTuple?.[0] || null;
  const c2 = parseDlpField(fields, ['c2', 'v', 'rightcipher', 'cipher2']) || ciphertextTuple?.[1] || null;
  // DH: A = g^a mod p, B = g^b mod p — treat A as target for recovering a
  const dhA = parseDlpField(fields, ['a', 'alice', 'alice_pub', 'pub_alice', 'shared_a']);
  const dhB = parseDlpField(fields, ['b', 'bob', 'bob_pub', 'pub_bob', 'shared_b']);
  const effectiveTarget = target || (dhA ?? null);
  const lower = value.toLowerCase();
  let confidence = 0;
  if (/\b(discrete log|dlog|diffie|elgamal|generator|pohlig|baby-step|bsgs)\b/.test(lower)) confidence += 6;
  if (modulus != null) confidence += 2;
  if (base != null) confidence += 2;
  if (effectiveTarget != null) confidence += 2;
  if (order != null) confidence += 1;
  if (c1 != null && c2 != null) confidence += 2;
  if (dhA != null) confidence += 2;
  const notes = [
    !explicitOrder && modulus != null && order != null && order === modulus - 1n ? 'No explicit order field was provided; defaulted to p-1.' : '',
    c1 != null && c2 != null ? 'Ciphertext fields suggest an ElGamal challenge.' : '',
    ciphertextTuple ? 'Parsed a two-value ciphertext tuple into c1/c2.' : '',
    dhA != null && dhB != null ? `Diffie-Hellman: A=g^a and B=g^b detected. Solving for a (Alice private key). Shared secret = B^a mod p.` : '',
  ].filter(Boolean);
  return { fields, modulus, base, target: effectiveTarget, order, c1, c2, confidence, notes, dhB };
};

export const bigintToSafeNumber = (value: bigint) => {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(value);
};

export const discreteLogBsgs = (
  base: bigint,
  target: bigint,
  modulus: bigint,
  order: bigint,
  maxBabySteps = 300000,
) => {
  const orderNumber = bigintToSafeNumber(order);
  if (orderNumber == null) return { solved: false as const, reason: 'order too large for safe Number arithmetic in BSGS' };
  const m = Math.ceil(Math.sqrt(orderNumber));
  if (m > maxBabySteps) return { solved: false as const, reason: `sqrt(order)=${m} exceeds local BSGS budget ${maxBabySteps}` };
  const baby = new Map<string, number>();
  let current = 1n;
  for (let j = 0; j < m; j += 1) {
    const key = current.toString();
    if (!baby.has(key)) baby.set(key, j);
    current = bigintMod(current * base, modulus);
  }
  const factor = rsaModPowSigned(base, -BigInt(m), modulus);
  if (factor == null) return { solved: false as const, reason: 'base is not invertible modulo p' };
  let gamma = bigintMod(target, modulus);
  for (let i = 0; i <= m; i += 1) {
    const match = baby.get(gamma.toString());
    if (match != null) {
      const candidate = BigInt(i * m + match);
      if (candidate < order && bigintModPow(base, candidate, modulus) === bigintMod(target, modulus)) {
        return { solved: true as const, exponent: candidate, method: 'bsgs', steps: m };
      }
    }
    gamma = bigintMod(gamma * factor, modulus);
  }
  return { solved: false as const, reason: 'no discrete log found in declared subgroup' };
};

export const discreteLogPohligHellman = (
  base: bigint,
  target: bigint,
  modulus: bigint,
  order: bigint,
) => {
  const factors = factorSmallCompositeModulus(order);
  if (!factors || !factors.length) return { solved: false as const, reason: 'order factoring failed locally' };
  const counts = new Map<string, { prime: bigint; count: bigint }>();
  for (const factor of factors) {
    const key = factor.toString();
    const existing = counts.get(key);
    if (existing) existing.count += 1n;
    else counts.set(key, { prime: factor, count: 1n });
  }
  let combinedX = 0n;
  let combinedModulus = 1n;
  const invBase = bigintModInverse(base, modulus);
  if (invBase == null) return { solved: false as const, reason: 'base is not invertible modulo p' };
  const residues: Array<{ primePower: string; residue: string }> = [];
  for (const { prime, count } of counts.values()) {
    const subgroupOrderNum = bigintToSafeNumber(prime);
    if (subgroupOrderNum == null || subgroupOrderNum > 100000) {
      return { solved: false as const, reason: `prime factor ${prime.toString()} is too large for local subgroup BSGS` };
    }
    const primePower = bigintPow(prime, count);
    const gamma = bigintModPow(base, order / prime, modulus);
    let residue = 0n;
    for (let j = 0n; j < count; j += 1n) {
      const exponent = order / bigintPow(prime, j + 1n);
      const adjusted = bigintMod(target * bigintModPow(invBase, residue, modulus), modulus);
      const h = bigintModPow(adjusted, exponent, modulus);
      const sub = discreteLogBsgs(gamma, h, modulus, prime, 100000);
      if (!sub.solved) return { solved: false as const, reason: `subgroup discrete log failed for factor ${prime.toString()}: ${sub.reason}` };
      residue += sub.exponent * bigintPow(prime, j);
    }
    residues.push({ primePower: primePower.toString(), residue: residue.toString() });
    if (combinedModulus === 1n) {
      combinedX = residue;
      combinedModulus = primePower;
    } else {
      combinedX = crtCombinePair(combinedX, combinedModulus, residue, primePower);
      combinedModulus *= primePower;
    }
  }
  if (bigintModPow(base, combinedX, modulus) !== bigintMod(target, modulus)) {
    return { solved: false as const, reason: 'CRT-combined exponent failed verification' };
  }
  return {
    solved: true as const,
    exponent: bigintMod(combinedX, order),
    method: 'pohlig-hellman',
    residues,
  };
};

export const discreteLogHelper = (value: string) => {
  const inference = inferDlpFromText(value);
  const { modulus, base, target, order, c1, c2, dhB } = inference;
  if (modulus == null || base == null || target == null || order == null) {
    throw new Error('DLP helper 至少需要 p/modulus、g/base、h/public value，以及可选的 q/order');
  }
  const ph = discreteLogPohligHellman(base, target, modulus, order);
  const solved = ph.solved ? ph : discreteLogBsgs(base, target, modulus, order);
  let elgamalPlaintext: ReturnType<typeof rsaNumberResult> | null = null;
  if (solved.solved && c1 != null && c2 != null) {
    const shared = bigintModPow(c1, solved.exponent, modulus);
    const sharedInv = bigintModInverse(shared, modulus);
    if (sharedInv != null) elgamalPlaintext = rsaNumberResult(bigintMod(c2 * sharedInv, modulus));
  }
  let dhSharedSecret: ReturnType<typeof rsaNumberResult> | null = null;
  if (solved.solved && dhB != null) {
    dhSharedSecret = rsaNumberResult(bigintModPow(dhB, solved.exponent, modulus));
  }
  return JSON.stringify({
    modulus: modulus.toString(),
    base: base.toString(),
    target: target.toString(),
    order: order.toString(),
    c1: c1?.toString() || null,
    c2: c2?.toString() || null,
    inferenceConfidence: inference.confidence,
    inferredFields: inference.fields,
    notes: inference.notes,
    result: solved.solved ? {
      recoveredExponent: solved.exponent.toString(),
      method: solved.method,
      subgroupResidues: 'residues' in solved ? solved.residues : undefined,
      elgamalPlaintext,
      dhSharedSecret,
    } : {
      method: 'unsolved',
      reason: solved.reason,
    },
  }, null, 2);
};

export type NonceReuseRecord = {
  index: string;
  nonce: string;
  ciphertext: Uint8Array | null;
  plaintext: Uint8Array | null;
  tag: string;
  raw: Record<string, string>;
};

export const nonceReuseRecordAliases = {
  nonce: ['nonce', 'iv', 'counter', 'ctr'],
  ciphertext: ['ciphertext', 'cipher', 'ct', 'encrypted', 'enc', 'sealed'],
  plaintext: ['plaintext', 'plain', 'pt', 'knownplaintext', 'knownplain'],
  tag: ['tag', 'authtag', 'mac'],
};

export const parseOptionalChallengeBytes = (value: string | undefined, labelText: string) => {
  if (!value) return null;
  try {
    return parseHexBase64OrUtf8Bytes(value, labelText).bytes;
  } catch {
    return null;
  }
};

export const collectNonceReuseJsonRecords = (value: unknown, output: NonceReuseRecord[], path = 'json') => {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectNonceReuseJsonRecords(entry, output, `${path}[${index}]`));
    return;
  }
  const object = value as Record<string, unknown>;
  const nonce = cleanSymmetricFieldValue(getObjectAliasValue(object, nonceReuseRecordAliases.nonce));
  const ciphertext = cleanSymmetricFieldValue(getObjectAliasValue(object, nonceReuseRecordAliases.ciphertext));
  const plaintext = cleanSymmetricFieldValue(getObjectAliasValue(object, nonceReuseRecordAliases.plaintext));
  const tag = cleanSymmetricFieldValue(getObjectAliasValue(object, nonceReuseRecordAliases.tag));
  if (nonce && (ciphertext || plaintext)) {
    output.push({
      index: path,
      nonce: normalizeLooseBytesLabel(nonce),
      ciphertext: parseOptionalChallengeBytes(ciphertext, 'ciphertext'),
      plaintext: parseOptionalChallengeBytes(plaintext, 'plaintext'),
      tag,
      raw: Object.fromEntries(Object.entries(object).map(([key, entry]) => [key, cleanSymmetricFieldValue(entry)])),
    });
  }
  for (const [key, entry] of Object.entries(object)) {
    if (entry && typeof entry === 'object') collectNonceReuseJsonRecords(entry, output, `${path}.${key}`);
  }
};

export const parseNonceReuseRecords = (value: string) => {
  const fields = parseLooseCtfFields(value);
  const records: NonceReuseRecord[] = [];
  try {
    collectNonceReuseJsonRecords(JSON.parse(value), records);
  } catch {
    // Fall through to loose CTF field parsing.
  }
  for (const { index, record } of parseLooseIndexedRecords(fields, nonceReuseRecordAliases, 200)) {
    const nonce = record.nonce ? normalizeLooseBytesLabel(record.nonce) : '';
    if (!nonce || (!record.ciphertext && !record.plaintext)) continue;
    records.push({
      index: String(index),
      nonce,
      ciphertext: parseOptionalChallengeBytes(record.ciphertext, 'ciphertext'),
      plaintext: parseOptionalChallengeBytes(record.plaintext, 'plaintext'),
      tag: record.tag || '',
      raw: record,
    });
  }
  return { fields, records };
};

export const xorBytes = (left: Uint8Array, right: Uint8Array) => {
  const length = Math.min(left.length, right.length);
  const output = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) output[index] = left[index] ^ right[index];
  return output;
};

export const bytesPreview = (bytes: Uint8Array) => ({
  hex: bytesToHex(bytes.slice(0, 96)),
  utf8: utf8Decoder.decode(bytes.slice(0, 160)).replace(/\p{Cc}/gu, '.'),
  bytes: bytes.length,
});

export const inferNonceReuseFromText = (value: string) => {
  const { fields, records } = parseNonceReuseRecords(value);
  const lower = value.toLowerCase();
  const groups = new Map<string, NonceReuseRecord[]>();
  for (const record of records) {
    if (!record.nonce) continue;
    const group = groups.get(record.nonce) || [];
    group.push(record);
    groups.set(record.nonce, group);
  }
  const repeated = Array.from(groups.entries()).filter(([, group]) => group.length >= 2);
  const analyses = repeated.map(([nonce, group]) => {
    const pairs = [];
    for (let left = 0; left < group.length; left += 1) {
      for (let right = left + 1; right < group.length; right += 1) {
        const leftRecord = group[left];
        const rightRecord = group[right];
        const pair: Record<string, unknown> = {
          left: leftRecord.index,
          right: rightRecord.index,
          nonce,
        };
        if (leftRecord.ciphertext && rightRecord.ciphertext) {
          const xoredCiphertexts = xorBytes(leftRecord.ciphertext, rightRecord.ciphertext);
          pair.ciphertextXor = bytesPreview(xoredCiphertexts);
          pair.meaning = 'For CTR/OFB/stream reuse, C1 xor C2 = P1 xor P2.';
        }
        if (leftRecord.ciphertext && rightRecord.ciphertext && leftRecord.plaintext) {
          pair.recoveredRightPlaintextPrefix = bytesPreview(xorBytes(xorBytes(leftRecord.ciphertext, rightRecord.ciphertext), leftRecord.plaintext));
        }
        if (leftRecord.ciphertext && rightRecord.ciphertext && rightRecord.plaintext) {
          pair.recoveredLeftPlaintextPrefix = bytesPreview(xorBytes(xorBytes(leftRecord.ciphertext, rightRecord.ciphertext), rightRecord.plaintext));
        }
        pairs.push(pair);
      }
    }
    return { nonce, records: group.map(record => record.index), pairs };
  });
  let confidence = 0;
  if (/\b(?:nonce reuse|iv reuse|same nonce|same iv|many[- ]time pad|otp reuse|two[- ]time pad)\b/.test(lower)) confidence += 6;
  if (/\b(?:aes[-_ ]?gcm|gcm|ctr|ofb|chacha20|salsa20|stream cipher|xor stream|otp)\b/.test(lower)) confidence += 4;
  if (records.length >= 2) confidence += 2;
  if (repeated.length) confidence += 5;
  return { fields, records, repeated, analyses, confidence };
};

export const trySmartNonceReuse = (value: string) => {
  const inference = inferNonceReuseFromText(value);
  const explicit = /\b(?:nonce reuse|iv reuse|same nonce|same iv|many[- ]time pad|otp reuse|two[- ]time pad)\b/i.test(value);
  if (inference.confidence < 8 || (!inference.repeated.length && !explicit)) return null;
  return `智能识别: nonce/key reuse stream analysis\n\n${JSON.stringify({
    recordCount: inference.records.length,
    repeatedNonceCount: inference.repeated.length,
    repeatedNonces: inference.repeated.map(([nonce, group]) => ({ nonce, count: group.length, records: group.map(record => record.index) })),
    analyses: inference.analyses,
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    notes: [
      'CTR/OFB/ChaCha20/Salsa20/OTP reuse leaks C1 xor C2 = P1 xor P2; known plaintext on one side recovers the other side prefix.',
      'AES-GCM nonce reuse also breaks authentication; this helper surfaces the reuse and XOR leakage, while GHASH-key recovery still needs a dedicated GF(2^128) script.',
      'CBC with repeated IV is weaker than fresh IV but does not create the same stream-XOR equation unless the construction is custom.',
    ],
  }, null, 2)}`;
};

export const canSmartNonceReuse = (value: string) => Boolean(trySmartNonceReuse(value));

export const trySmartPrngAnalyze = (value: string) => {
  const lcg = inferLcgFromText(value);
  if (lcg.confidence >= 8 && (lcg.states.length >= 4 || (lcg.modulus && lcg.multiplier != null && lcg.increment != null))) {
    try {
      return `智能识别: LCG / PRNG analysis\n\n${lcgHelper(value, '')}`;
    } catch {
      // Continue to other PRNG families.
    }
  }
  const lfsr = inferLfsrBitsFromText(value);
  if (lfsr.confidence >= 8 && lfsr.bits.length >= 16) {
    try {
      return `智能识别: LFSR / Berlekamp-Massey analysis\n\n${lfsrHelper(value)}`;
    } catch {
      // Continue to MT19937 triage.
    }
  }
  const mt = inferMt19937FromText(value);
  if (mt.confidence >= 8) {
    const clone = mt19937PredictFromOutputs(mt.numbers);
    return `智能识别: MT19937 / Python random triage\n\n${JSON.stringify({
      outputCount: mt.numbers.length,
      enoughForFullStateClone: mt.numbers.length >= 624,
      firstOutputs: mt.numbers.slice(0, 12).map(number => number.toString()),
      clone,
      notes: [
        clone ? 'Recovered MT19937 internal state from the first 624 consecutive 32-bit outputs and predicted following outputs locally.' : 'MT19937 state cloning needs 624 consecutive 32-bit outputs.',
        'If outputs are truncated, floats, or randrange() values, use constraint solving or a randcrack variant for the leakage model.',
      ],
      localPythonTemplate: [
        'from randcrack import RandCrack',
        'rc = RandCrack()',
        'for x in outputs[:624]:',
        '    rc.submit(x)',
        'print(rc.predict_getrandbits(32))',
      ].join('\n'),
      inferredFields: mt.fields,
    }, null, 2)}`;
  }
  return null;
};

export const canSmartPrngAnalyze = (value: string) => {
  const lcg = inferLcgFromText(value);
  if (lcg.confidence >= 8 && (lcg.states.length >= 4 || (lcg.modulus && lcg.multiplier != null && lcg.increment != null))) return true;
  const lfsr = inferLfsrBitsFromText(value);
  if (lfsr.confidence >= 8 && lfsr.bits.length >= 16) return true;
  return inferMt19937FromText(value).confidence >= 8;
};
