// CODEC-IMPORTS
import { decodeAaencode, decodeJjencode, decodeJsfuck, trySmartSymbolObfuscation } from './sandbox';
import { canSmartHashLengthExtension, extractSmartRawPayloadCandidate, looksLikeResolvedSmartDecodeText, trySmartClassicalKeylessBreak, trySmartCrtSolver, trySmartEccHelper, trySmartHashLengthExtension, trySmartModDecode, trySmartStructuredDecode, trySmartSubstitutionBruteforce } from './smartHelpers';
import { canSmartDiscreteLog, canSmartNonceReuse, canSmartPrngAnalyze, canSmartSignatureNonceReuse, inferMt19937FromText, trySmartDiscreteLog, trySmartNonceReuse, trySmartPrngAnalyze, trySmartSignatureNonceReuseAsync } from './prng';
import { canRabinRawDecryptFromText, canRsaRawDecryptFromText, canSmartRsaHelper, trySmartRabinDecrypt, trySmartRsaDecrypt } from './rsa';
import { SMART_DECODE_ADOPT_FLOOR, canSmartSymmetricDecryptFromText, printableRatio, smartDecodeOutputScore, smartTextScore, tryDecode, trySmartSymmetricDecrypt, trySmartXorDecrypt } from './smartBase';
import { trySmartClassicDecrypt, trySmartVigenereBruteforce, validAffineMultipliers } from './smartClassical';
import { a1z26Decode, affineTransform, atbashTransform, baudotDecode, binaryDecode, bubbleBabbleDecode, caesar, decodeUtf16Bytes, dnaDecode, htmlDecode, keyboardShift, morseDecode, natoDecode, octalDecode, polluxDecode, quotedPrintableDecode, rot47, unicodeDecode, utf7Decode, yEncDecode, zeroWidthDecode } from './textEncodings';
import { base64ToText, decodeAscii85, decodeBase32, decodeBase32768, decodeBase36, decodeBase45, decodeBase58, decodeBase58Check, decodeBase62, decodeBase91, decodeBech32, decodeXxencode, decodeZBase32, hexToBytes, looksLikeBase32768 } from './bases';
import { alphabet, utf8Decoder, zeroWidthOne, zeroWidthZero } from './alphabets';
import { baconDecode, polybiusDecode } from './classical';
import { runBrainfuck } from './attacks';
import { parseFernetRaw } from './tokens';
import { looksLikeBson, looksLikeProtobufWire, looksLikeSmsPdu } from './binaryFormats';
import { baijiaxingDecode, bearDecode, buddhaDecode, buddhaV2Decode, hexagramDecode, looksLikeBaijiaxing, looksLikeCloudShadow, looksLikeHexagramNames, looksLikeHexagramSymbols, looksLikeSexagesimal, sexagesimalDecode } from './chineseCiphers';
import { looksLikeCetaceanShape, looksLikeCiscoType7Shape, looksLikeDecabitShape, looksLikePizziniShape } from './mapCiphers';
import { parityBaseLooksLike, parityBaseOperations, parityBaseTransform } from './parityBases';
import { parityCharLooksLike, parityCharOperations, parityCharTransform } from './parityCharCodes';
import { parityCnLooksLike, parityCnOperations, parityCnTransform } from './parityChinese';
import { parityKeyedOperations, parityKeyedTransform } from './parityKeyed';
import { parityNumLooksLike, parityNumOperations, parityNumTransform } from './parityNumeric';
import { defaultParams } from './operations';
import type { Detection, Direction, OperationId, ParamKey } from './types';
// CODEC-IMPORTS-END

// 批次 O（随波逐流操作对齐）智能识别接入：五个 parity 模块的形状探针（与各自码表同源）
// 同时供给 detectInput 芯片与 smartDecode 候选链；带key 类（parityKeyed）无形状特征不参与。
type ParityDispatch = (id: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>) => Promise<string>;

export const parityProbes = [...parityBaseLooksLike, ...parityCharLooksLike, ...parityCnLooksLike, ...parityNumLooksLike];

// 数字形态探针（4 位数字组/纯数字组）：形状本身不特异——日期、编号、坐标都会命中，且输出分
//（单个合法汉字即可过线）无法区分「中国」与「仡」。这类探针不进直解路径，只出识别芯片 +
// 在候选层与打分同台，普通数字串保持批次 O 之前的原有行为（review P1 回归项）。
const WEAK_SHAPE_PROBE_IDS = new Set<string>(['telecode', 'quwei', 'numberpad-lines']);

const parityDispatchById = (() => {
  const byId = new Map<OperationId, ParityDispatch>();
  const groups = [
    [parityBaseTransform, parityBaseOperations],
    [parityCharTransform, parityCharOperations],
    [parityCnTransform, parityCnOperations],
    [parityKeyedTransform, parityKeyedOperations],
    [parityNumTransform, parityNumOperations],
  ] as const;
  for (const [dispatch, operations] of groups) {
    for (const operation of operations) byId.set(operation.id, dispatch);
  }
  return byId;
})();
// 完整 flag 格式清单（前缀{4+位内容}）：智能解码强信号判定与 flag 徽标展示共用同一清单。
// 带 g 标志，只能用于 matchAll（内部克隆正则）；.test() 场景用 flagFormatPattern() 克隆，避免 lastIndex 漂移。
const FLAG_FORMAT_PATTERN = /\b(?:flag|ctf|picoctf|htb|thm|key|crypto|dice|wctf|utflag|sekai|actf|seccon|ritsec|lactf|crew|nahamcon|hsctf|justctf|b01lers|wanictf|jerseyctf|mapna)\{[A-Za-z0-9_!@#$%^&*.-]{4,}\}/gi;

const flagFormatPattern = () => new RegExp(FLAG_FORMAT_PATTERN.source, FLAG_FORMAT_PATTERN.flags);

// flag/ctf/key 关键词级识别（展示层自动标红用）：比完整格式宽松，只要求独立成词（\b 边界，monkey 不命中）。
// 与 FLAG_FORMAT_PATTERN 同源维护：完整格式覆盖短内容（如 FLAG{UP}）不足 4 字符的场景。
const FLAG_KEYWORD_PATTERN = /\b(?:flag|ctf|key)s?\b/gi;

const flagKeywordPattern = () => new RegExp(FLAG_KEYWORD_PATTERN.source, FLAG_KEYWORD_PATTERN.flags);

export interface FlagAutoRange {
  start: number;
  end: number;
  // format = 前缀{...} 完整格式（深红）；keyword = flag/ctf/key 独立词（红色）
  level: 'format' | 'keyword';
}

// 展示层自动标红区间：完整格式优先，关键词只补格式没覆盖的位置（重叠处让位）。
// 供富输出面板与文件取证报告共用；纯函数、无状态，返回区间按起点有序且互不重叠。
// 区间数封顶（对抗构造的超长关键词文本可产出数万命中，扫描线性恶化）。
const MAX_FLAG_AUTO_RANGES = 5000;

export const findFlagAutoRanges = (text: string): FlagAutoRange[] => {
  if (!text) return [];
  const ranges: FlagAutoRange[] = [];
  for (const match of text.matchAll(flagFormatPattern())) {
    if (ranges.length >= MAX_FLAG_AUTO_RANGES) break;
    if (match[0].length) ranges.push({ start: match.index, end: match.index + match[0].length, level: 'format' });
  }
  for (const match of text.matchAll(flagKeywordPattern())) {
    if (ranges.length >= MAX_FLAG_AUTO_RANGES) break;
    const start = match.index;
    const end = start + match[0].length;
    const covered = ranges.some(range => start < range.end && end > range.start);
    if (!covered) ranges.push({ start, end, level: 'keyword' });
  }
  return ranges.sort((a, b) => a.start - b.start || a.end - b.end);
};

export const smartDecode = async (value: string): Promise<string> => {
  const symbolObfuscated = trySmartSymbolObfuscation(value);
  if (symbolObfuscated) return symbolObfuscated;
  if (/^\s*新佛曰\s*[:：]/.test(value)) {
    return '检测到「新佛曰：」前缀（pcmoe「新约佛论禅」）：该变体算法闭源且其在线服务已下线，无法离线解码。\n密文字符集与 keyfc 佛曰/如是我闻不兼容，请先确认前缀后改用对应工具。';
  }
  // Strip common CTF output noise prefixes: "Flag: ", "[*] Encrypted: ", ">>> cipher =", etc.
  const normalizedValue = value.normalize('NFKC');
  const stripped = /^\s*data:/i.test(normalizedValue)
    ? normalizedValue.trim()
    : normalizedValue
    .replace(/^\s*\[[*+\-!]\]\s*/i, '')                            // [*] [+] [-] [!] tool output prefix
    .replace(/^\s*>>>\s*/i, '')                                   // Python REPL prompt
    .replace(/^\s*(?:\w+[ \t]+){0,3}(?:flag|output|ciphertext|encrypted|decrypted|result|enc|ct|cipher|answer|solution|plaintext|decode|decoded|hex|base64|b64|binary|b32|octal|ascii|encoded|ciphered|secret|text|message|data|rot|xor|aes|key|token|hash|mac|sig|digest|signature|nonce|iv|salt|seed|pt|value|flag_enc|flag_hex)\b[ \t]*(?:\w+[ \t]*)?(?:\([^\r\n)]*\)[ \t]*)?(?:is[ \t]*)?[:=][ \t]*/i, '')
    .replace(/^\s*(?:(?:题目(?:内容|附件)?|挑战|附件|任务)[ \t_-]*)?(?:密文|加密数据|编码(?:内容|数据)?|输出|结果|答案|十六进制|二进制|八进制|明文)(?:[ \t]*(?:\([^\r\n)]{0,40}\)|\[[^\r\n\]]{0,40}\]))?[ \t]*(?:为|是)?[ \t]*[:=][ \t]*/iu, '')
    .trim();
  const input = stripped !== normalizedValue.trim() ? stripped : normalizedValue;
  const smartStructured = await trySmartStructuredDecode(input);
  if (smartStructured) return smartStructured;
  const smartDlp = trySmartDiscreteLog(input);
  if (smartDlp) return smartDlp;
  const smartEcc = trySmartEccHelper(input);
  if (smartEcc) return smartEcc;
  const smartRabin = trySmartRabinDecrypt(input);
  if (smartRabin) return smartRabin;
  const smartRsa = trySmartRsaDecrypt(input);
  if (smartRsa) return smartRsa;
  const smartMod = trySmartModDecode(input);
  if (smartMod) return smartMod;
  const smartCrt = trySmartCrtSolver(input);
  if (smartCrt) return smartCrt;
  const smartSymmetric: string | null = await trySmartSymmetricDecrypt(input);
  if (smartSymmetric) return smartSymmetric;
  // AES ECB block-repeat detection: repeated 16-byte blocks in hex ciphertext signal ECB mode
  const ecbDetect = (() => {
    const hex = input.replace(/\s/g, '');
    if (!/^[0-9a-f]+$/i.test(hex) || hex.length < 64 || hex.length % 32 !== 0) return null;
    const blocks: string[] = [];
    for (let i = 0; i < hex.length; i += 32) blocks.push(hex.slice(i, i + 32));
    const seen = new Set<string>();
    const repeated = blocks.filter(b => { const dup = seen.has(b); seen.add(b); return dup; });
    if (!repeated.length) return null;
    return `智能识别: AES-ECB 重复块检测\n\n${JSON.stringify({ totalBlocks: blocks.length, repeatedBlocks: repeated.length, repeatedValues: [...new Set(repeated)], note: 'Repeated 16-byte blocks detected — AES-ECB mode likely. Use ECB cut-and-paste or block analysis to exploit. Provide the key to decrypt with AES-ECB tool.' }, null, 2)}`;
  })();
  if (ecbDetect) return ecbDetect;
  const smartPrng = trySmartPrngAnalyze(input);
  if (smartPrng) return smartPrng;
  const smartSignatureNonceReuse = await trySmartSignatureNonceReuseAsync(input);
  if (smartSignatureNonceReuse) return smartSignatureNonceReuse;
  const smartNonceReuse = trySmartNonceReuse(input);
  if (smartNonceReuse) return smartNonceReuse;
  const smartHashLengthExtension = trySmartHashLengthExtension(input);
  if (smartHashLengthExtension) return smartHashLengthExtension;
  // 批次 O 字表类：高特异形状探针（码表占比/前缀门控）命中且解码成功时直接返回，
  // 先于 XOR/古典等泛化启发式——否则短数字/hex 形态（电码、云影类）会被泛化路径抢先。
  // 探针误报由各解码器内部的严格字符校验兜底（失败即跳过，继续走泛化路径）。
  for (const probe of parityProbes) {
    if (WEAK_SHAPE_PROBE_IDS.has(probe.id)) continue;
    if (!probe.test(input)) continue;
    const dispatch = parityDispatchById.get(probe.id);
    if (!dispatch) continue;
    try {
      const output = await dispatch(probe.id, 'decode', input, defaultParams);
      if (output && output !== input) return `识别链路: ${probe.label}\n\n${output}`;
    } catch {
      // 形状命中但解码失败：继续尝试其它探针与泛化路径
    }
  }
  const smartXor = trySmartXorDecrypt(input);
  if (smartXor) return smartXor;
  const smartVigenere = trySmartVigenereBruteforce(input);
  if (smartVigenere) return smartVigenere;
  const smartSubstitution = trySmartSubstitutionBruteforce(input);
  if (smartSubstitution) return smartSubstitution;
  const smartClassic = trySmartClassicDecrypt(input);
  if (smartClassic) return smartClassic;
  // Pollux: digit-only string → Morse via digit-to-dot/dash mapping
  const polluxResult = (() => {
    const digits = input.trim().replace(/\s+/g, '');
    if (!/^\d+$/.test(digits) || digits.length < 8) return null;
    // Binary/octal-shaped digit groups belong to the encoding loop's Binary/Octal decoders
    const rawTrimmed = input.trim();
    if (/^[01\s,;|]+$/.test(rawTrimmed) && (rawTrimmed.match(/[01]{8}/g) || []).length > 0) return null;
    const rawTokens = rawTrimmed.split(/[\s,;|]+/);
    if (rawTokens.length >= 4 && rawTokens.every(token => /^0[0-7]{1,3}$/.test(token))) return null;
    // Short space-separated code lists (Octal/ASCII-code/A1Z26 shapes) are not Pollux either
    if (rawTokens.length >= 4 && rawTokens.every(token => /^\d{1,3}$/.test(token))) return null;
    const decoded = polluxDecode(input);
    const letters = decoded.replace(/[^a-z]/gi, '');
    if (letters.length >= 3 && /[a-z]{2,}/i.test(decoded)) return `智能识别: Pollux cipher\n\n${JSON.stringify({ decoded, note: 'Digits mapped to Morse: evens=dot, odds=dash, 6-9=separator. Result may need further flag extraction.' }, null, 2)}`;
    return null;
  })();
  if (polluxResult) return polluxResult;
  // Strip Python bytes wrapper: b'\x66...' or bytes.fromhex('...') → raw content for further decoding
  const bytesFromHexMatch = input.match(/^bytes\.fromhex\s*\(\s*['"]([0-9a-fA-F\s]+)['"]\s*\)/i);
  const pythonBytesMatch = !bytesFromHexMatch && input.match(/^(?:br|rb|b)\s*(['"])([\s\S]*)\1$/i);
  // Convert Python hex array [0x1b, 0x37, ...] → decimal array [27, 55, ...]
  const pyHexArrayConverted = (() => {
    if (!/\[\s*0x[0-9a-fA-F]/.test(input)) return null;
    const clean = input.replace(/\[\s*((?:0x[0-9a-fA-F]{1,2}\s*,\s*)+0x[0-9a-fA-F]{1,2})\s*\]/g,
      (_, g) => '[' + g.split(',').map((s: string) => parseInt(s.trim(), 16)).join(', ') + ']');
    return clean !== input ? clean : null;
  })();
  // Strip xxd/hexdump address columns: "00000000: 666c 6167  |flag|" → "666c6167"
  const hexdumpCleaned = (() => {
    if (!/^[0-9a-f]{4,}[:\s]/im.test(input)) return null;
    // Real hexdumps carry a colon after the address (xxd) or an address column wider than the data
    // groups (od); equal-width leading groups mean this is another encoding, e.g. octal C-style tokens.
    const firstLine = input.split(/\r?\n/).find(line => /^[0-9a-f]{4,}[:\s]/i.test(line)) ?? '';
    const colonStyle = /^[0-9a-f]{4,}:/i.test(firstLine);
    const widths = firstLine.trim().split(/[\s:]+/).filter(Boolean).map(token => token.length);
    const addressWider = widths.length >= 2 && widths[0] > widths[1];
    if (!colonStyle && !addressWider) return null;
    const stripped = input.replace(/^[0-9a-fA-F]{4,}[:\s]+/gm, '').replace(/\|.*\|/g, '').replace(/\s+/g, '');
    return /^[0-9a-fA-F]+$/.test(stripped) && stripped.length >= 4 ? stripped : null;
  })();
  const labeledPayload = extractSmartRawPayloadCandidate(input);
  // Top-N 多候选：记录每层与 best 分差 ≤15 的接近候选，输出尾部附带机读段落供可折叠列表渲染
  const layerCandidates: Array<{ layer: number; chosen: string; options: Array<{ name: string; score: number; preview: string }> }> = [];
  const appendCandidatesSection = (text: string) => {
    if (layerCandidates.length === 0) return text;
    return `${text}\n\n=== 候选列表 ===\n${JSON.stringify(layerCandidates)}`;
  };
  let current = hexdumpCleaned ?? (pyHexArrayConverted ?? (bytesFromHexMatch ? bytesFromHexMatch[1].replace(/\s/g, '') : pythonBytesMatch ? pythonBytesMatch[2] : labeledPayload ?? input));
  const steps: string[] = [];
  // Base58Check (BTC address style): version byte + payload + double-SHA256 checksum — async decoder, so it
  // runs here rather than inside the synchronous candidate loop.
  try {
    const clean = current.replace(/\s+/g, '');
    if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,62}$/.test(clean)) {
      const summary = JSON.parse(await decodeBase58Check(clean)) as { checksumValid?: boolean; payloadText?: string };
      // Only a VALID checksum yields the payload; invalid ones stay with the honest "no decode" answer.
      if (summary.checksumValid === true && summary.payloadText) {
        const output = summary.payloadText;
        if (output !== current && smartDecodeOutputScore(output, current) >= 60) {
          steps.push('Base58Check');
          current = output;
        }
      }
    }
  } catch { /* not a Base58Check payload */ }
  // 中文密码家族（批次 K）：前缀特征直接解一层，解码失败（复制缺字等）静默留给其他候选。
  try {
    if (/^(?:佛曰|魔曰)\s*[:：]/.test(current.trim())) {
      const output = await buddhaDecode(current);
      if (output && output !== current && smartDecodeOutputScore(output, current) >= SMART_DECODE_ADOPT_FLOOR) {
        steps.push('与佛论禅');
        current = output;
      }
    } else if (/^如是我闻\s*[:：]/.test(current.trim())) {
      const output = await buddhaV2Decode(current);
      // V2 解码失败时返回容器降级说明（不推进 current）；解出明文时剥掉容器尾注后采纳。
      if (output && !output.startsWith('如是我闻解码：') && output !== current) {
        const plain = output.split('\n\n（已从')[0];
        if (plain && smartDecodeOutputScore(plain, current) >= SMART_DECODE_ADOPT_FLOOR) {
          steps.push('如是我闻');
          current = plain;
        }
      }
    } else if (/^熊曰\s*[:：]/.test(current.trim())) {
      const output = await bearDecode(current);
      if (output && output !== current && smartDecodeOutputScore(output, current) >= SMART_DECODE_ADOPT_FLOOR) {
        steps.push('与熊论道');
        current = output;
      }
    }
  } catch { /* 中文密码前缀但解码失败：复制不完整或非官方码表，交给其他候选 */ }
  for (let depth = 0; depth < 12; depth += 1) {
    if (depth > 0 && looksLikeResolvedSmartDecodeText(current)) break;
    const candidates = [
      current.includes('%') ? tryDecode('URL', current, decodeURIComponent) : null,
      /&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(current) ? tryDecode('HTML Entity', current, htmlDecode) : null,
      /\\u\{?[0-9a-fA-F]{2,}/.test(current) || /\\x[0-9a-fA-F]{2}/.test(current) ? tryDecode('Unicode/Hex Escape', current, unicodeDecode) : null,
      /\+[A-Za-z0-9/]+-|\+-/.test(current) ? tryDecode('UTF-7', current, utf7Decode) : null,
      /^[0-9a-fA-Fx\\\s]+$/.test(current) && current.replace(/[^0-9a-fA-F]/g, '').length >= 4
        && !/^(\d{1,2}[\s,;|/.-]+)*\d{1,2}$/.test(current.trim())
        ? tryDecode('Hex', current, decoded => utf8Decoder.decode(hexToBytes(decoded))) : null,
      // Space/comma-separated 0x-prefixed hex bytes: 0x70 0x69 ... or 0x70, 0x69, ...
      /(?:0x[0-9a-fA-F]{1,2}[\s,]+){1,}0x[0-9a-fA-F]{1,2}/.test(current) ? tryDecode('0x-Hex bytes', current, v => utf8Decoder.decode(hexToBytes(v.replace(/[\s,]+/g, '').replace(/0x/gi, '')))) : null,
      // XOR single-byte bruteforce: hex/byte-stream ciphertext whose direct decode is not readable text
      (() => {
        // Binary/Bacon 0-1 digit payloads belong to their own decoders
        if (/^[01\s,;|/+-]+$/.test(current.trim())) return null;
        const compact = current.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
        if (compact.length < 8 || compact.length % 2 !== 0 || compact.length > 65536) return null;
        // Hex density is measured after stripping 0x/\x markers (they are decoration, not data)
        const rawCompact = current.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/\s+/g, '');
        // Engage only when the payload is essentially hex/byte-stream shaped
        if (compact.length < Math.max(8, Math.floor(rawCompact.length * 0.6))) return null;
        let bytes: Uint8Array;
        try {
          bytes = hexToBytes(current);
        } catch {
          return null;
        }
        let best: { text: string; score: number } | null = null;
        for (let key = 1; key < 256; key += 1) {
          const text = utf8Decoder.decode(bytes.map(byte => byte ^ key));
          const score = smartDecodeOutputScore(text, current);
          if (!best || score > best.score) best = { text, score };
        }
        // Only offer XOR when the winning key produced a strong text signal: a known flag prefix, non-Latin
        // text, or at least TWO common English words — arbitrary 3+ letter runs are not words.
        if (!best || best.score < 60) return null;
        const xorWordHits = (best.text.match(/\b(?:flag|the|and|that|this|you|with|from|have|not|for|key|secret|password|admin|test|hello|world|message|value|data|code|name|user|error|success|welcome|http|https)\b/gi) || []).length;
        if (xorWordHits < 2 && !/flag\{|ctf\{|\bkey\b|\bpass\w*/i.test(best.text) && !/\P{ASCII}/u.test(best.text)) return null;
        return { name: 'XOR 单字节', output: best.text };
      })(),
      /^[A-Za-z0-9+/_=-\s]+$/.test(current) && current.replace(/\s+/g, '').length >= 8 ? tryDecode('Base64', current, base64ToText) : null,
      /^[A-Z2-7=\s]+$/i.test(current) && current.replace(/\s+/g, '').length >= 8 ? tryDecode('Base32', current, decodeBase32) : null,
      /^[0-9A-V=\s]+$/i.test(current) && current.replace(/\s+/g, '').length >= 8 && /[G-Vg-v]/.test(current) ? tryDecode('Base32hex', current, decoded => decodeBase32(decoded, 'hex')) : null,
      // z-base-32（Zimmermann）——小写字母表、无填充；字符集与 RFC Base32 不同（l/v/0/2 互斥），重叠部分由评分层裁决
      /^[ybndrfg8ejkmcpqxot1uwisza345h769\s]+$/i.test(current) && current.replace(/\s+/g, '').length >= 10 ? tryDecode('z-base-32', current, decodeZBase32) : null,
      /^[0-9A-HJ-KM-NP-TV-Z=\-\s]+$/i.test(current) && current.replace(/[\s-]/g, '').length >= 8 && /[G-HJ-KM-NP-Tg-hj-km-np-t]/.test(current) ? tryDecode('Crockford Base32', current, decoded => decodeBase32(decoded, 'decimal')) : null,
      /^[a-z0-9]{1,83}1[02-9ac-hj-np-z]{6,}$/i.test(current) ? tryDecode('Bech32', current, decodeBech32) : null,
      /^[0-9A-Z $%*+\-./:]+$/i.test(current) && current.replace(/\s+/g, '').length >= 4 ? tryDecode('Base45', current, decodeBase45) : null,
      /^[0-9A-Z\s]+$/i.test(current) && /[A-Z]/i.test(current) && /\d/.test(current) && current.replace(/\s+/g, '').length >= 6 && !/^[0-9a-f\s]+$/i.test(current) ? tryDecode('Base36', current, decodeBase36) : null,
      /^[A-Za-z0-9!#$%&()*+,./:;<=>?@[\]^_`{|}~"\s]+$/.test(current) && /[!#$%&()*+,./:;<=>?@[\]^_`{|}~"]/.test(current) && current.length >= 8 ? tryDecode('Base91', current, decodeBase91) : null,
      // Base32768 —— 码点表含大量常用 CJK，用 looksLikeBase32768 收窄后再交给严格解码（未知字符/填充校验）
      looksLikeBase32768(current, false) ? tryDecode('Base32768', current, decodeBase32768) : null,
      /^[01\s,;|]+$/.test(current) && (current.match(/[01]{8}/g) || []).length > 0 ? tryDecode('Binary', current, binaryDecode) : null,
      /^(\\[0-7]{1,3}|0o[0-7]+|0[0-7]{1,3}|[0-7]{3}|[\s,;|])+$/i.test(current) ? tryDecode('Octal', current, octalDecode) : null,
      ...(/^(\d{1,2}[\s,;|/.-]+)*\d{1,2}$/.test(current.trim().replace(/[{}_"']/g, '').trim()) ? (() => {
        // A1Z26 with embedded literal skeleton chars — a1z26Decode passes unknown tokens through untouched
        const outputs: string[] = [];
        try {
          const naive = a1z26Decode(current);
          if (naive && naive !== current) outputs.push(naive);
        } catch { /* fall through to digit regrouping */ }
        // Ambiguous digit runs (e.g. 6-1-2-1-7) need 1-vs-2-digit regrouping; enumerate splits and let scoring decide.
        const digits = current.replace(/\D/g, '');
        if (digits.length >= 2 && digits.length <= 96) {
          const parses: string[] = [];
          const walk = (index: number, acc: string) => {
            if (parses.length >= 64) return;
            if (index >= digits.length) {
              parses.push(acc);
              return;
            }
            const one = Number(digits.slice(index, index + 1));
            if (one >= 1 && one <= 9) walk(index + 1, acc + alphabet[one - 1]);
            if (index + 2 <= digits.length) {
              const two = Number(digits.slice(index, index + 2));
              if (two >= 10 && two <= 26) walk(index + 2, acc + alphabet[two - 1]);
            }
          };
          walk(0, '');
          outputs.push(...parses);
        }
        const scored = outputs
          .map(output => ({ output, score: smartDecodeOutputScore(output, current) }))
          .sort((left, right) => right.score - left.score)
          .slice(0, 2);
        // 歧义分组的最优解与次优解并列吐出：Top-N 候选列表据此展示同层多解
        return scored
          .filter(entry => entry.score > 0)
          .map((entry, index) => ({ name: index === 0 ? 'A1Z26' : 'A1Z26 备选', output: entry.output }));
      })() : []),
      // Morse
      // Morse — literal skeleton chars ({, }, _, quotes) may be embedded and pass through morseDecode untouched
      /^[-. /\s{}_"']*$/.test(current) && /[.-]{2,}/.test(current) ? tryDecode('Morse', current, morseDecode) : null,
      // Arbitrary base-N (3-11): space-separated digits, all within [0,base)
      (() => {
        const tokens = current.trim().split(/[\s,;|]+/);
        if (tokens.length < 4) return null;
        for (let base = 3; base <= 11; base++) {
          const alphabet = '0123456789abcdef'.slice(0, base);
          const re = new RegExp(`^[${alphabet}]+$`, 'i');
          if (!tokens.every(t => re.test(t))) continue;
          try {
            const bytes: number[] = [];
            let acc = 0n; const baseBig = BigInt(base);
            for (const t of tokens) acc = acc * baseBig + BigInt(parseInt(t, base));
            let h = acc.toString(16); if (h.length % 2) h = '0' + h;
            for (let i = 0; i < h.length; i += 2) bytes.push(parseInt(h.slice(i, i + 2), 16));
            const out = utf8Decoder.decode(new Uint8Array(bytes));
            if (printableRatio(new Uint8Array(bytes)) > 0.85) return { name: `Base${base}`, output: out };
          } catch { /* skip */ }
        }
        return null;
      })(),
      // Base58 — high-ambiguity brute candidate (any alnum-ish text decodes): only adopt genuinely text-like output
      (() => {
        const clean = current.replace(/\s+/g, '');
        if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(clean) || clean.length < 6 || clean.length > 4096) return null;
        const output = decodeBase58(clean);
        if (!output || output === current || smartDecodeOutputScore(output, current) < 60) return null;
        return { name: 'Base58', output };
      })(),
      // Base62 — same high-ambiguity gate as Base58; scoring arbitrates against Base36/Base58
      (() => {
        const clean = current.replace(/\s+/g, '');
        if (!/^[0-9A-Za-z]+$/.test(clean) || clean.length < 8 || clean.length > 4096) return null;
        const output = decodeBase62(clean);
        if (!output || output === current || smartDecodeOutputScore(output, current) < 60) return null;
        return { name: 'Base62', output };
      })(),
      // ASCII decimal codes (space/comma separated codepoints, including tab/LF/CR)
      (() => {
        const tokens = current.trim().split(/[\s,;|]+/);
        if (tokens.length < 2) return null;
        const nums = tokens.map(Number);
        if (nums.some(n => !Number.isInteger(n) || n < 0 || n > 127)) return null;
        if (nums.filter(n => n >= 32 && n <= 126).length < tokens.length * 0.7) return null;
        const out = String.fromCharCode(...nums);
        return out !== current ? { name: 'ASCII codes', output: out } : null;
      })(),
      // ROT/Caesar + Atbash auto (only at end to avoid false positives)
      (() => {
        const lts = current.replace(/[^a-z]/gi, '');
        // Use alphanumeric+space as denominator (exclude {}, symbols) to handle flag{...} format
        const alphanum = current.replace(/[^a-z0-9 ]/gi, '');
        const lettersUsable = lts.length >= 6 && alphanum.length > 0 && lts.length / alphanum.length >= 0.45;
        // ROT47-only path: letter-sparse but fully printable text (ROT47 keeps chars inside 33-126)
        const rot47Usable = !lettersUsable && current.trim().length >= 8
          && /^[\x21-\x7e\s]+$/.test(current)
          && /[^A-Za-z0-9\s]/.test(current);
        if (!lettersUsable && !rot47Usable) return null;
        const origScore = smartTextScore(current);
        const options: Array<{ d: string; score: number }> = [];
        if (lettersUsable) {
          for (let shift = 1; shift <= 25; shift += 1) {
            const d = caesar(current, shift);
            options.push({ d, score: smartTextScore(d) });
          }
          const atb = atbashTransform(current);
          options.push({ d: atb, score: smartTextScore(atb) });
        }
        const rot = rot47(current);
        options.push({ d: rot, score: smartTextScore(rot) });
        const best = options.sort((a, b) => b.score - a.score)[0];
        if (/flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|actf\{|seccon\{|ritsec\{|lactf\{|crew\{|crypto\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|mapna\{/i.test(best.d) || best.score - origScore > 8) return { name: 'ROT/Atbash', output: best.d };
        return null;
      })(),
      // Affine bruteforce (all 312 valid (a,b) pairs) — scored here so Reverse/ROT candidates compete fairly
      (() => {
        const lts = current.replace(/[^a-z]/gi, '');
        if (lts.length < 12 || current.length > 4096 || lts.length / Math.max(1, current.length) < 0.5) return null;
        let best: { output: string; score: number } | null = null;
        for (const a of validAffineMultipliers) {
          for (let b = 0; b < 26; b += 1) {
            const output = affineTransform(current, String(a), String(b), true);
            // Known-prefix flag + English scoring only: the generic word{...} shape is worthless here because
            // affine keeps the {..} skeleton in every one of the 312 outputs.
            const score = smartTextScore(output) + (/\b(?:flag|ctf|picoctf|htb|thm|key|crypto)\{/i.test(output) ? 40 : 0);
            if (!best || score > best.score) best = { output, score };
          }
        }
        if (!best) return null;
        // Adopt only with a real semantic signal: a word-boundary complete flag shape, or at least TWO
        // common English words. Bare readability and single-word substring hits must never pass here.
        const strongFlag = flagFormatPattern().test(best.output);
        const strongWords = (best.output.match(/\b(?:the|and|that|this|you|with|from|have|not|for|secret|password|admin|test|hello|world|message|welcome|flag)\b/gi) || []).length >= 2;
        return (strongFlag || strongWords) && smartDecodeOutputScore(best.output, current) >= 60 ? { name: 'Affine', output: best.output } : null;
      })(),
      // Reverse text
      (() => {
        const rev = Array.from(current).reverse().join('');
        if (/flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|actf\{|seccon\{|ritsec\{|lactf\{|crew\{|crypto\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|mapna\{/i.test(rev) || smartTextScore(rev) - smartTextScore(current) > 10) return { name: 'Reverse', output: rev };
        return null;
      })(),
      // UUencode
      /^begin\s+\d+\s+/mi.test(current) && /\nend\s*$/i.test(current) ? tryDecode('UUencode', current, (v) => { const lines = v.split(/\r?\n/).slice(1); const bytes: number[] = []; for (const line of lines) { if (/^end$/i.test(line.trim())) break; if (!line) continue; const chars = Array.from(line); const count = (chars[0].charCodeAt(0) - 32) & 63; for (let i = 1; i + 3 < chars.length && bytes.length < count; i += 4) { const a = (chars[i].charCodeAt(0)-32)&63, b = (chars[i+1].charCodeAt(0)-32)&63, c = (chars[i+2].charCodeAt(0)-32)&63, d = (chars[i+3].charCodeAt(0)-32)&63; bytes.push((a<<2)|(b>>4), ((b&15)<<4)|(c>>2), ((c&3)<<6)|d); } } return utf8Decoder.decode(new Uint8Array(bytes.slice(0, bytes.length))); }) : null,
      // Xxencode —— 与 UUencode 同构，字母表 +-0-9A-Za-z，头部 begin 6xx；与 UUencode 候选并存由评分层定胜负
      /^begin\s+[0-9x]{3}\s+/mi.test(current) && /\nend\s*$/i.test(current) ? tryDecode('Xxencode', current, decodeXxencode) : null,
      // NATO phonetic
      /\b(?:Alpha|Bravo|Charlie|Delta|Echo|Foxtrot|Golf|Hotel|India|Juliett|Kilo|Lima|Mike|November|Oscar|Papa|Quebec|Romeo|Sierra|Tango|Uniform|Victor|Whiskey|Xray|Yankee|Zulu)\b/i.test(current) ? tryDecode('NATO', current, natoDecode) : null,
      // Quoted-Printable
      /=\r?\n|=[0-9A-F]{2}/i.test(current) ? tryDecode('Quoted-Printable', current, quotedPrintableDecode) : null,
      // Ascii85
      /^<~/.test(current.trim()) || /~>$/.test(current.trim()) ? tryDecode('Ascii85', current, decodeAscii85) : null,
      // Bacon cipher (A/B or 0/1 groups of 5) — checked before Baudot to avoid 0/1 conflict
      (() => {
        const stripped = current.replace(/[\s,]/g, '');
        const core = stripped.replace(/[{}_"']/g, '').toUpperCase();
        if (core.length < 15 || core.length % 5 !== 0 || !/^[AB01]+$/.test(core)) return null;
        // Pure 0/1: only Bacon if no chunk exceeds 24 (Baudot shift codes are 25-31)
        if (!/[AB]/.test(core) && (core.match(/.{5}/g) || []).some(c => parseInt(c, 2) > 24)) return null;
        // Token-wise decode keeps embedded literal skeleton chars ({, _, quotes) in place
        const tokens = stripped.match(/[AB01ab01]+|[^AB01ab01]+/g) || [];
        let output = '';
        for (const token of tokens) {
          if (!/^[AB01ab01]+$/.test(token)) {
            output += token;
            continue;
          }
          if (token.length % 5 !== 0) return null;
          for (let index = 0; index < token.length; index += 5) {
            const chunk = token.slice(index, index + 5).toUpperCase();
            if (!/[AB]/.test(chunk) && parseInt(chunk, 2) > 24) return null;
            output += baconDecode(chunk);
          }
        }
        return output && output !== current ? { name: 'Bacon', output } : null;
      })(),
      // Baudot / ITA2
      /^(?:[01]{5}[\s,]+){4,}[01]{5}/.test(current.trim()) ? tryDecode('Baudot', current, baudotDecode) : null,
      // Polybius square (digit pairs 1-5, at least 4 pairs)
      (() => {
        const stripped = current.replace(/[\s,;|-]/g, '');
        const core = stripped.replace(/[{}_"']/g, '');
        if (!/^[1-5]+$/.test(core) || core.length < 8 || core.length % 2 !== 0) return null;
        // Token-wise decode keeps embedded literal skeleton chars in place
        const tokens = stripped.match(/[1-5]+|[^1-5]+/g) || [];
        let output = '';
        for (const token of tokens) {
          if (!/^[1-5]+$/.test(token)) {
            output += token;
            continue;
          }
          if (token.length % 2 !== 0) return null;
          output += polybiusDecode(token);
        }
        return output && output !== current ? { name: 'Polybius', output } : null;
      })(),
      // UTF-16 hex byte pairs (00 padding on every other byte)
      (() => {
        const clean = current.replace(/[\s,]+/g, '');
        if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length < 8 || clean.length % 4 !== 0) return null;
        const bytes = hexToBytes(clean);
        const oddZero = bytes.filter((_, index) => index % 2 === 1).every(byte => byte === 0);
        const evenZero = bytes.filter((_, index) => index % 2 === 0).every(byte => byte === 0);
        if (!oddZero && !evenZero) return null;
        const output = decodeUtf16Bytes(clean, oddZero ? 'le' : 'hex');
        return output && output !== current ? { name: 'UTF-16', output } : null;
      })(),
      // DNA code (ACGT → 2-bit pairs)
      (() => {
        const clean = current.toUpperCase().replace(/[^ACGT]/g, '');
        return clean.length >= 8 && clean.length % 4 === 0 && /^[ACGT\s,;|/-]+$/i.test(current)
          ? tryDecode('DNA', current, v => dnaDecode(v, 'special'))
          : null;
      })(),
      // Zero-width binary
      current.includes(zeroWidthZero) || current.includes(zeroWidthOne) ? tryDecode('Zero-width', current, zeroWidthDecode) : null,
      // Bubble Babble — x-anchored hyphen-separated groups; decode() validates the CVCVC structure strictly
      /^x(?:[a-z]{4,5}-){2,}[a-z]{3,4}x$/i.test(current.replace(/\s+/g, ''))
        ? tryDecode('Bubble Babble', current.replace(/\s+/g, ''), bubbleBabbleDecode) : null,
      // yEnc (high-byte dense text)
      (() => {
        if (current.length < 8) return null;
        let high = 0;
        for (const char of current) if (char.charCodeAt(0) >= 0x80) high += 1;
        return high > current.length * 0.3 ? tryDecode('yEnc', current, yEncDecode) : null;
      })(),
      // Brainfuck (bounded interpreter)
      /^[<>+\-.,[\]\s]+$/.test(current) && current.includes('.') && current.length <= 20000
        ? tryDecode('Brainfuck', current, v => runBrainfuck(v, '', '0')) : null,
      // JSFuck —— 纯 []()!+ 符号汤，形状独占无碰撞；静态求值器还原，绝不执行
      (() => {
        const compact = current.replace(/\s+/g, '');
        return compact.length >= 100 && /^[[\]!+()]+$/.test(compact) ? tryDecode('JSFuck', current, decodeJsfuck) : null;
      })(),
      // jjencode —— $=~[] 前缀形状独占
      /^\$=~\[\];/.test(current.trim()) ? tryDecode('jjencode', current, decodeJjencode) : null,
      // aaencode —— 半角片假名 ﾟ + 颜文字符号高频出现，普通文本不会命中
      (() => {
        if (current.length < 80) return null;
        const marks = (current.match(/[\uFF9F\uFF70\u0414\u0398\u03C9\u03B5]/gu) || []).length;
        return marks >= 20 ? tryDecode('aaencode', current, decodeAaencode) : null;
      })(),
      // 中文密码无前缀流派：码表覆盖率门控 + 严格解码（解码器内部再校验非法字符）
      looksLikeBaijiaxing(current) ? tryDecode('百家姓', current, baijiaxingDecode) : null,
      looksLikeHexagramSymbols(current) ? tryDecode('六十四卦（卦符）', current, hexagramDecode) : null,
      looksLikeHexagramNames(current) ? tryDecode('六十四卦（卦名）', current, hexagramDecode) : null,
      looksLikeSexagesimal(current) ? tryDecode('天干地支', current, sexagesimalDecode) : null,
      // Keyboard shift (QWERTY neighbours, both directions) — needs a strong text signal (flag / multiple
      // words / non-Latin text); printable-but-structureless shifts must never hijack an already-decoded layer
      (() => {
        if (current.length < 8 || current.length > 4096) return null;
        let best: { output: string; score: number } | null = null;
        for (const output of [keyboardShift(current, 'qwerty', true), keyboardShift(current, 'hex', true)]) {
          if (!output || output === current) continue;
          const score = smartDecodeOutputScore(output, current);
          if (!best || score > best.score) best = { output, score };
        }
        if (!best || best.score < 60) return null;
        const strongSignal = /flag\{|ctf\{|\bkey\b|\bpass\w*/i.test(best.output)
          || /\P{ASCII}/u.test(best.output)
          || /\b(?:flag|the|and|that|this|you|with|from|have|not|for|key|secret|password|admin|test|hello|world|message|value|data|code|name|user|error|success|welcome|http|https)\b/i.test(best.output);
        if (!strongSignal) return null;
        return { name: 'Keyboard shift', output: best.output };
      })(),
    ].filter(Boolean) as Array<{ name: string; output: string; bonus?: number }>;

    // 批次 O 字表类：形状探针命中的候选异步解码后同台打分；解码失败只跳过该候选
    //（形状命中≠必然可解，误报由 SMART_DECODE_ADOPT_FLOOR 与排序统一裁决）。
    // bonus：探针本身就是高特异形状门控（码表占比/前缀），同分时优先于泛化启发式（如短 hex 的 XOR 候选）。
    for (const probe of parityProbes) {
      if (!probe.test(current)) continue;
      const dispatch = parityDispatchById.get(probe.id);
      if (!dispatch) continue;
      try {
        const output = await dispatch(probe.id, 'decode', current, defaultParams);
        if (output && output !== current) candidates.push({ name: probe.label, output, bonus: 25 });
      } catch {
        // 形状命中但解码失败：跳过该候选
      }
    }

    // Rank every candidate by output quality and adopt only the best; never settle for the first non-empty decode.
    const ranked = candidates
      .map((candidate, index) => ({ ...candidate, index, score: smartDecodeOutputScore(candidate.output, current) + (candidate.bonus ?? 0) }))
      .sort((left, right) => right.score - left.score || left.index - right.index);
    const best = ranked[0];
    if (!best || best.score < SMART_DECODE_ADOPT_FLOOR) break;
    // Top-N 多候选：该层全部过线候选 top-5（不足 2 个时补上次优），列表展示相对分数，best 不变
    const closeOnes = ranked
      .filter(candidate => candidate.score >= SMART_DECODE_ADOPT_FLOOR)
      .slice(0, 5);
    if (closeOnes.length < 2 && ranked.length > 1) closeOnes.push(ranked[1]);
    if (closeOnes.length > 1) {
      layerCandidates.push({
        layer: steps.length + 1,
        chosen: best.name,
        options: closeOnes.map(candidate => ({
          name: candidate.name,
          score: Math.round(candidate.score),
          preview: candidate.output.replace(/[^\x20-\x7e]/g, '·').replace(/\s+/g, ' ').slice(0, 120),
        })),
      });
    }
    steps.push(best.name);
    current = best.output;
  }

  // Chained cipher: if the decoded layer is now classic-cipher-looking (e.g. Base64 -> Caesar text),
  // run one more classic/Vigenère/substitution pass on the result.
  if (steps.length && !looksLikeResolvedSmartDecodeText(current)) {
    const letters = current.replace(/[^a-z]/gi, '');
    if (letters.length >= 12 && letters.length / Math.max(1, current.length) > 0.5) {
      const chained = trySmartVigenereBruteforce(current) || trySmartClassicDecrypt(current) || trySmartSubstitutionBruteforce(current);
      if (chained) return appendCandidatesSection(`识别链路: ${steps.join(' -> ')} -> (classic)\n\n${chained}`);
    }
  }

  if (steps.length) {
    // 链路已有产出时不进入古典破译（破译只兜底完全无命中的输入）
    return appendCandidatesSection(`识别链路: ${steps.join(' -> ')}\n\n${current}`);
  }
  const keylessBreak = await trySmartClassicalKeylessBreak(current);
  if (keylessBreak) return keylessBreak;
  return '没有识别到可安全自动解码的格式。可以手动选择具体算法继续转换。';
};

export const detectInput = (value: string): Detection[] => {
  const text = value.trim();
  if (!text) {
    // 批次 O：纯空白符密文（whitespace-code）trim 后为空，探针改为看原始输入。
    const whitespaceHits = value ? parityProbes.filter(probe => probe.test(value)) : [];
    return whitespaceHits.map(probe => ({ id: probe.id, label: probe.label }));
  }
  const detections: Detection[] = [];
  const compactHex = text.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  const mnemonicWords = text.toLowerCase().normalize('NFKD').split(/\s+/);
  if (/^[\w-]+\.[\w-]+\.[\w-]+$/.test(text.replace(/^Bearer\s+/i, ''))) {
    detections.push({ id: 'jwt', label: 'JWT' });
    if (/-----BEGIN (?:CERTIFICATE|[A-Z ]*PUBLIC KEY)-----|\{\s*"kty"|\{\s*"keys"\s*:/.test(text)) detections.push({ id: 'jwt-public', label: 'JWT/JWS public verify' });
  }
  try {
    if (parseFernetRaw(text).version === 0x80) detections.push({ id: 'fernet', label: 'Fernet' });
  } catch {
    // Not a Fernet token.
  }
  if (/^U2FsdGVkX1/i.test(text.replace(/\s+/g, ''))) detections.push({ id: 'openssl-aes-256-cbc', label: 'OpenSSL Salted__ AES' });
  if (/^-----BEGIN PGP (MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----/.test(text)) detections.push({ id: 'pgp-parse', label: 'PGP/GPG' });
  if (/%[0-9a-fA-F]{2}/.test(text)) detections.push({ id: 'url-component', label: 'URL %XX' });
  if (/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(text)) detections.push({ id: 'html-entity', label: 'HTML Entity' });
  if (/\\u\{?[0-9a-fA-F]{2,}/.test(text) || /\\x[0-9a-fA-F]{2}/.test(text)) detections.push({ id: 'unicode-escape', label: 'Unicode/Hex Escape' });
  if (/\+[A-Za-z0-9/]+-|\+-/.test(text)) detections.push({ id: 'utf7', label: 'UTF-7' });
  if (/\\(U[0-9a-fA-F]{8}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{2,3}|[nrtbfv])/.test(text)) detections.push({ id: 'c-string', label: 'C/Python escapes' });
  if ([12, 15, 18, 21, 24].includes(mnemonicWords.length) && mnemonicWords.every(word => /^[a-z]+$/.test(word))) detections.push({ id: 'bip39-seed', label: 'BIP39' });
  if (looksLikeSmsPdu(text)) detections.push({ id: 'sms-pdu', label: 'SMS PDU' });
  if (/^-----BEGIN [^-]+-----/.test(text) || (compactHex.length >= 4 && compactHex.length % 2 === 0 && /^(30|31|02|03|04|06)/i.test(compactHex))) {
    detections.push({ id: 'asn1-der', label: 'ASN.1 DER/BER' });
  }
  if (/^(ssh-|ecdsa-|sk-)/m.test(text) || /\s(ssh-|ecdsa-|sk-)[A-Za-z0-9@._-]*\s+[A-Za-z0-9+/=]+/.test(text)) detections.push({ id: 'ssh-public-key', label: 'OpenSSH key' });
  if (/^\s*\{/.test(text) && /"kty"|"keys"|"protected"|"ciphertext"|"recipients"/.test(text)) detections.push({ id: 'jwk-jwe', label: 'JWK/JWE' });
  if (/^\s*\{/.test(text) && /"alg"|"sealedHex"|"tagHex"/.test(text)) {
    try {
      const alg = String((JSON.parse(text) as { alg?: unknown }).alg || '').toLowerCase();
      if (alg.includes('xchacha20-poly1305')) detections.push({ id: 'xchacha20-poly1305', label: 'XChaCha20-Poly1305 JSON' });
      else if (alg.includes('chacha20-poly1305')) detections.push({ id: 'chacha20-poly1305', label: 'ChaCha20-Poly1305 JSON' });
      else if (alg.includes('xsalsa20') || alg.includes('secretbox')) detections.push({ id: 'xsalsa20-poly1305', label: 'XSalsa20-Poly1305 JSON' });
    } catch {
      // Not an AEAD JSON payload.
    }
  }
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text)) detections.push({ id: 'jwk-jwe', label: 'JWE Compact' });
  if (compactHex.length >= 4 && compactHex.length % 2 === 0 && /^(a[0-9a-f]|b[0-9a-f]|8[0-9a-f]|9[0-9a-f]|d9d9f7|c[0-9a-f]|d[0-9a-f])/i.test(compactHex)) {
    detections.push({ id: 'cbor', label: 'CBOR/MsgPack candidate' });
    detections.push({ id: 'messagepack', label: 'MessagePack/CBOR candidate' });
  }
  if (looksLikeBson(text)) detections.push({ id: 'bson', label: 'BSON' });
  if (looksLikeProtobufWire(text)) detections.push({ id: 'protobuf-raw', label: 'Protobuf wire' });
  if (/^[0-9a-fA-Fx\\\s]+$/.test(text) && text.replace(/[^0-9a-fA-F]/g, '').length >= 4) detections.push({ id: 'hex', label: 'Hex' });
  // Pure hex ciphertext (≥16 bytes, even length) is a common XOR challenge format
  if (/^[0-9a-f]+$/i.test(text.replace(/\s/g,'')) && text.replace(/\s/g,'').length >= 32 && text.replace(/\s/g,'').length % 2 === 0)
    detections.push({ id: 'xor-bruteforce', label: 'XOR (hex ciphertext)' });
  if (/^[0-9a-f]{4}$|^[0-9a-f]{8}$|^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{96}$|^[0-9a-f]{128}$/i.test(text)) detections.push({ id: 'hash-identify', label: 'Hash' });
  if (/^[A-Za-z0-9+/_=-\s]+$/.test(text) && text.replace(/\s+/g, '').length >= 8) detections.push({ id: 'base64', label: 'Base64' });
  if (/^[1-9A-HJ-NP-Za-km-z]{26,64}$/.test(text)) detections.push({ id: 'base58check', label: 'Base58Check' });
  if (/^[a-z0-9]{1,83}1[02-9ac-hj-np-z]{6,}$/i.test(text) && (text === text.toLowerCase() || text === text.toUpperCase())) detections.push({ id: 'bech32', label: 'Bech32/Bech32m' });
  if (/^[0-9A-Z\s]+$/i.test(text) && /[A-Z]/i.test(text) && /\d/.test(text) && text.replace(/\s+/g, '').length >= 6) detections.push({ id: 'base36', label: 'Base36' });
  if (/^[0-9A-Z $%*+\-./:]+$/i.test(text) && text.replace(/\s+/g, '').length >= 4) detections.push({ id: 'base45', label: 'Base45' });
  if (/^[A-Za-z0-9!#$%&()*+,./:;<=>?@[\]^_`{|}~"\s]+$/.test(text) && /[!#$%&()*+,./:;<=>?@[\]^_`{|}~"]/.test(text) && text.length >= 8) detections.push({ id: 'base91', label: 'Base91' });
  if (/^begin\s+\d+\s+/mi.test(text) && /\nend\s*$/i.test(text)) detections.push({ id: 'uuencode', label: 'UUencode' });
  if (/^begin\s+[0-9x]{3}\s+/mi.test(text) && /\nend\s*$/i.test(text)) detections.push({ id: 'xxencode', label: 'Xxencode' });
  if (/^[ybndrfg8ejkmcpqxot1uwisza345h769\s]+$/i.test(text) && text.replace(/\s+/g, '').length >= 10) detections.push({ id: 'z-base-32', label: 'z-base-32' });
  if (looksLikeBase32768(text, true)) detections.push({ id: 'base32768', label: 'Base32768' });
  if (/^[-. /\s]+$/.test(text) && /[.-]{2,}/.test(text)) detections.push({ id: 'morse', label: 'Morse' });
  if (/\b(?:Alpha|Bravo|Charlie|Delta|Echo|Foxtrot|Golf|Hotel|India|Juliett|Kilo|Lima|Mike|November|Oscar|Papa|Quebec|Romeo|Sierra|Tango|Uniform|Victor|Whiskey|Xray|Yankee|Zulu)\b/i.test(text)) {
    detections.push({ id: 'nato-phonetic', label: 'NATO' });
  }
  if ((text.match(/[01]{5}/g) || []).length >= 3 && /^[01\s,;|/-]+$/.test(text)) detections.push({ id: 'baudot', label: 'Baudot/ITA2' });
  const bcdChunks = text.match(/[01]{4}/g) || [];
  if (bcdChunks.length >= 2 && /^[01\s,;|/-]+$/.test(text) && bcdChunks.every(chunk => Number.parseInt(chunk, 2) <= 9)) detections.push({ id: 'bcd', label: 'BCD' });
  if (/^[01\s,;|]+$/.test(text) && (text.match(/[01]{2,}/g) || []).length > 0) detections.push({ id: 'gray-code', label: 'Gray Code' });
  const dnaClean = text.toUpperCase().replace(/[^ACGT]/g, '');
  if (dnaClean.length >= 8 && dnaClean.length % 4 === 0 && /^[ACGT\s,;|/-]+$/i.test(text)) detections.push({ id: 'dna-code', label: 'DNA' });
  if (text.includes(zeroWidthZero) || text.includes(zeroWidthOne)) detections.push({ id: 'zero-width', label: 'Zero-width' });
  // 中文密码家族：前缀直接命中；无前缀流派按码表覆盖率判定（谓词与映射表同源）。
  if (/^(?:佛曰|魔曰)\s*[:：]/.test(text)) detections.push({ id: 'buddha', label: '与佛论禅' });
  if (/^如是我闻\s*[:：]/.test(text)) detections.push({ id: 'buddha-v2', label: '如是我闻' });
  if (/^熊曰\s*[:：]/.test(text)) detections.push({ id: 'bear-says', label: '与熊论道' });
  if (looksLikeHexagramSymbols(text)) detections.push({ id: 'hexagram', label: '六十四卦（卦符）' });
  else if (looksLikeHexagramNames(text)) detections.push({ id: 'hexagram', label: '六十四卦（卦名）' });
  if (looksLikeBaijiaxing(text)) detections.push({ id: 'baijiaxing', label: '百家姓' });
  if (looksLikeSexagesimal(text)) detections.push({ id: 'sexagesimal', label: '天干地支' });
  // 字表映射与脉冲类（批次 M）：结构可判的接入识别；纯字母替换类（albam/carbonaro）无静态特征，与 vigenere 同理不做静态检测。
  if (looksLikeCloudShadow(text)) detections.push({ id: 'cloud-shadow', label: '云影（幂数）' });
  if (looksLikePizziniShape(text)) detections.push({ id: 'pizzini', label: 'Pizzini' });
  if (looksLikeCiscoType7Shape(text)) detections.push({ id: 'cisco-type7', label: 'Cisco Type 7' });
  if (looksLikeDecabitShape(text)) detections.push({ id: 'decabit', label: 'Decabit' });
  if (looksLikeCetaceanShape(text)) detections.push({ id: 'cetacean', label: 'Cetacean' });
  // 批次 O 字表类高特征探针（码表同源谓词，自带最低长度/占比阈值）：命中即出芯片。
  for (const probe of parityProbes) {
    if (probe.test(text)) detections.push({ id: probe.id, label: probe.label });
  }
  if (/^=ybegin\b|^=ypart\b|^=yend\b/im.test(text)) detections.push({ id: 'yenc', label: 'yEnc' });
  if (/^x(?:[a-z]{4,5}-){2,}[a-z]{3,4}x$/i.test(text.replace(/\s+/g, ''))) detections.push({ id: 'bubble-babble', label: 'Bubble Babble' });
  if (/^(\d{1,2}[\s,;|/-]+)*\d{1,2}$/.test(text) && text.split(/[\s,;|/-]+/).some(token => Number(token) >= 1 && Number(token) <= 26)) detections.push({ id: 'a1z26', label: 'A1Z26' });
  if (/^[ABab01\s,;|/-]+$/.test(text) && text.replace(/[^ABab01]/g, '').length >= 10) detections.push({ id: 'bacon', label: 'Bacon' });
  if (/^[1-5\s,;|/-]+$/.test(text) && (text.match(/[1-5][1-5]/g) || []).length >= 2) detections.push({ id: 'polybius', label: 'Polybius' });
  if (/([.-]{1,5}\s+[.-]{1,5})(\s*\/\s*|\s+)/.test(`${text} `)) detections.push({ id: 'tap-code', label: 'Tap Code' });
  if (/^[<>+\-.,[\]\s]+$/.test(text) && /[.[\]]/.test(text)) detections.push({ id: 'brainfuck', label: 'Brainfuck' });
  if (/Ook[.!?]/.test(text)) detections.push({ id: 'ook', label: 'Ook!' });
  if (/^[()[\]{}!+\s]+$/.test(text) && text.replace(/\s+/g, '').length > 20) detections.push({ id: 'jsfuck-helper', label: 'JSFuck' });
  {
    const compact = text.replace(/\s+/g, '');
    if (compact.length >= 100 && /^[[\]!+()]+$/.test(compact)) detections.push({ id: 'jsfuck', label: 'JSFuck 还原' });
  }
  if (/^\$=~\[\];/.test(text.trim())) detections.push({ id: 'jjencode', label: 'jjencode' });
  {
    const marks = (text.match(/[\uFF9F\uFF70\u0414\u0398\u03C9\u03B5]/gu) || []).length;
    if (text.length >= 80 && marks >= 20) detections.push({ id: 'aaencode', label: 'aaencode' });
  }
  if (/^-----BEGIN [^-]+-----/.test(text)) detections.push({ id: 'pem-block', label: 'PEM' });
  if (/=\r?\n|=[0-9A-F]{2}/i.test(text)) detections.push({ id: 'quoted-printable', label: 'Quoted-Printable' });
  if (/^[01\s,;|]+$/.test(text) && (text.match(/[01]{8}/g) || []).length > 0) detections.push({ id: 'binary', label: 'Binary' });
  if (canRabinRawDecryptFromText(text)) detections.push({ id: 'rabin-raw', label: 'Rabin decryptable' });
  if (canRsaRawDecryptFromText(text)) detections.push({ id: 'rsa-raw', label: 'RSA decryptable' });
  else if (canSmartRsaHelper(text)) detections.push({ id: 'rsa-helper', label: 'RSA' });
  if (canSmartSymmetricDecryptFromText(text)) detections.push({ id: 'smart-decode', label: 'Symmetric decryptable' });
  if (canSmartPrngAnalyze(text)) detections.push({ id: 'smart-decode', label: 'PRNG analyzable' });
  if (canSmartSignatureNonceReuse(text)) {
    detections.push({ id: 'signature-nonce-helper', label: 'Signature nonce reuse' });
    detections.push({ id: 'smart-decode', label: 'Signature nonce reuse' });
  }
  if (canSmartNonceReuse(text)) detections.push({ id: 'smart-decode', label: 'Nonce reuse analyzable' });
  if (canSmartHashLengthExtension(text)) detections.push({ id: 'smart-decode', label: 'Length-extension analyzable' });
  if (canSmartDiscreteLog(text)) detections.push({ id: 'discrete-log-helper', label: 'Discrete log / ElGamal' });
  if (/lcg|x\s*\[\s*n\s*\+\s*1\s*\]|modulus|seed|rand\(/i.test(text)) detections.push({ id: 'lcg-helper', label: 'LCG' });
  if (/lfsr|berlekamp|keystream/i.test(text) || (/^[01\s]+$/.test(text) && text.replace(/\s+/g, '').length >= 32)) detections.push({ id: 'lfsr-helper', label: 'LFSR' });
  if (inferMt19937FromText(text).confidence >= 8) detections.push({ id: 'mt19937-helper', label: 'MT19937' });
  if (/length extension|hashpump|hash_extender|secret\s*\|\|\s*msg|md5|sha1|sha256/i.test(text)) detections.push({ id: 'hash-length-extension-helper', label: 'Length extension' });
  if (/rsa|ecdsa|lfsr|lcg|mt19937|padding oracle|coppersmith|lll|nonce reuse|length extension/i.test(text)) detections.push({ id: 'crypto-attack-helper', label: 'Attack helper' });
  if (/\b(ecc|ecdh|elliptic|curve|secp|weierstrass|ecdlp)\b/i.test(text)) detections.push({ id: 'smart-decode', label: 'ECC / Elliptic curve' });
  if (/≡|\bmod\b|\bmodulo\b|\bcongruent\b|x\s*%\s*\d+\s*[=≡]|\bCRT\b/i.test(text) && /\d{2,}/.test(text)) detections.push({ id: 'smart-decode', label: 'CRT / Modular equations' });
  if (/^\d[\d\s]*\d$/.test(text) && text.replace(/\s+/g, '').length >= 8) detections.push({ id: 'smart-decode', label: 'Pollux (digit Morse)' });
  if (/^otpauth:\/\//i.test(text)) detections.push({ id: 'otpauth-uri', label: 'otpauth URI' });
  if (/^(https?:|data:)/i.test(text)) detections.push({ id: 'data-url', label: text.startsWith('data:') ? 'Data URL' : 'URL' });  const priority = (id: string) => {
    if (id === 'rabin-raw') return 120;
    if (id === 'rsa-raw') return 118;
    if (id === 'rsa-helper') return 116;
    if (id === 'buddha' || id === 'buddha-v2' || id === 'bear-says') return 114;
    if (id === 'discrete-log-helper') return 112;
    if (id === 'signature-nonce-helper') return 110;
    if (id === 'mt19937-helper' || id === 'lcg-helper' || id === 'lfsr-helper') return 108;
    if (id === 'baijiaxing' || id === 'hexagram' || id === 'sexagesimal') return 94;
    // 字表映射与脉冲类（批次 M）：字符集强结构特征（01248/种子+hex/10 脉冲/Ee 位串/自分隔数字），误报率低，排在通用编码芯片之前。
    if (id === 'cloud-shadow' || id === 'cisco-type7' || id === 'decabit' || id === 'cetacean' || id === 'pizzini') return 96;
    // 批次 O 字表类探针命中的芯片：同等强结构特征，与批次 M 同档。
    if (parityProbes.some(probe => probe.id === id)) return 96;
    if (id === 'smart-decode') return 100;
    return 0;
  };
  const deduped = detections
    .map((entry, index) => ({ ...entry, index }))
    .filter((entry, index, items) => items.findIndex(candidate => candidate.id === entry.id) === index)
    .sort((left, right) => {
      const priorityDiff = priority(right.id) - priority(left.id);
      return priorityDiff !== 0 ? priorityDiff : left.index - right.index;
    })
    .slice(0, 6)
    .map(({ id, label }) => ({ id, label }));
  return deduped;
};

// flag 格式识别只做展示：复用智能解码内部已用的 flag 前缀清单，把命中结果以徽标形式显式呈现。
export interface FlagFormatHit {
  prefix: string;
  sample: string;
}

export const detectFlagFormats = (text: string): FlagFormatHit[] => {
  if (!text) return [];
  const hits = new Map<string, FlagFormatHit>();
  for (const match of text.matchAll(FLAG_FORMAT_PATTERN)) {
    const braceIndex = match[0].indexOf('{');
    if (braceIndex <= 0) continue;
    const prefix = match[0].slice(0, braceIndex).toLowerCase();
    if (!hits.has(prefix)) hits.set(prefix, { prefix, sample: match[0] });
    if (hits.size >= 4) break;
  }
  return [...hits.values()];
};

// 展示层辅助：剥掉 smartDecode 输出尾部追加的机读候选段落，只留人类可读结果。
export const stripCandidateSection = (output: string): string => {
  const sectionStart = output.indexOf('=== 候选列表 ===');
  return sectionStart >= 0 ? output.slice(0, sectionStart).trimEnd() : output;
};

// 回灌辅助：在 stripCandidateSection 之上再剥掉「识别链路: xxx」标头行（含其后的分隔空行），
// 只留结果正文——展示文本回灌输入时若带标头，二次识别必然失败，多层解码链第一步就断。
// 正文不额外 trim：零宽/空白符类解码结果的首尾空白是载荷本身，剥掉会破坏回灌。
export const extractPureDecodeResult = (output: string): string => {
  const text = stripCandidateSection(output);
  const headerMatch = text.match(/^识别链路:[^\n]*\n+/);
  return headerMatch ? text.slice(headerMatch[0].length) : text;
};
