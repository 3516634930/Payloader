// CODEC-IMPORTS
import type { CategoryId, Operation, OperationId } from './types';
import { categories } from './types';
import { operations } from './operations';
// CODEC-IMPORTS-END

// 受众分流：同一个操作在「编解码（渗透）」与「CTF 解题」两个视图间的展示归属。
// 引擎实现完全共用，这里只做展示层过滤与视图分组。
export type Audience = 'ctf' | 'pentest' | 'both';

export const operationAudience: Record<OperationId, Audience> = {
  'smart-decode': 'ctf',
  // ---- 渗透与 CTF 共用（both）----
  'base64': 'both',
  'base64url': 'both',
  'base32': 'both',
  'base36': 'both',
  'base62': 'both',
  'base58': 'both',
  'hex': 'both',
  'binary': 'both',
  'octal-codes': 'both',
  'ascii-codes': 'both',
  'ascii85': 'both',
  'url-component': 'both',
  'url-form': 'both',
  'unicode-escape': 'both',
  'js-string': 'both',
  'html-entity': 'both',
  'xml-entity': 'both',
  'utf7': 'both',
  'c-string': 'both',
  'json-string': 'both',
  'unix-time': 'both',
  'quoted-printable': 'both',
  'utf16-bytes': 'both',
  'gzip': 'both',
  'deflate': 'both',
  'data-url': 'both',
  'xor': 'both',
  'rot': 'both',
  // ---- CTF 解题专属（ctf）----
  'vigenere': 'ctf',
  'beaufort': 'ctf',
  'autokey': 'ctf',
  'atbash': 'ctf',
  'bacon': 'ctf',
  'polybius': 'ctf',
  'tap-code': 'ctf',
  'playfair': 'ctf',
  'hill2': 'ctf',
  'substitution': 'ctf',
  'affine': 'ctf',
  'rail-fence': 'ctf',
  'scytale': 'ctf',
  'columnar': 'ctf',
  'porta': 'ctf',
  'gronsfeld': 'ctf',
  'bifid': 'ctf',
  'trifid': 'ctf',
  'four-square': 'ctf',
  'nihilist': 'ctf',
  'adfgx': 'ctf',
  'adfgvx': 'ctf',
  'enigma': 'ctf',
  'frequency-analysis': 'ctf',
  'buddha': 'ctf',
  'buddha-v2': 'ctf',
  'bear-says': 'ctf',
  'baijiaxing': 'ctf',
  'hexagram': 'ctf',
  'sexagesimal': 'ctf',
  'cloud-shadow': 'ctf',
  'pizzini': 'ctf',
  'cisco-type7': 'ctf',
  'decabit': 'ctf',
  'cetacean': 'ctf',
  'albam': 'ctf',
  'carbonaro': 'ctf',
  'rot-bruteforce': 'ctf',
  'rot8000': 'ctf',
  'xor-bruteforce': 'ctf',
  'xor-known-plaintext': 'ctf',
  'magic-xor-helper': 'ctf',
  'brainfuck': 'ctf',
  'ook': 'ctf',
  'keyboard-shift': 'ctf',
  'reverse-text': 'ctf',
  'zero-width': 'ctf',
  'z-base-32': 'ctf',
  'base45': 'ctf',
  'base91': 'ctf',
  'base32768': 'ctf',
  'bech32': 'ctf',
  'base58check': 'ctf',
  'xxencode': 'ctf',
  'uuencode': 'ctf',
  'yenc': 'ctf',
  'bubble-babble': 'ctf',
  'a1z26': 'ctf',
  'morse': 'ctf',
  'nato-phonetic': 'ctf',
  'baudot': 'ctf',
  'bcd': 'ctf',
  'gray-code': 'ctf',
  'dna-code': 'ctf',
  'gsm7': 'ctf',
  'sms-pdu': 'ctf',
  'rsa-raw': 'ctf',
  'rabin-raw': 'ctf',
  'rsa-helper': 'ctf',
  'coppersmith': 'ctf',
  'discrete-log-helper': 'ctf',
  'mt19937-helper': 'ctf',
  'lcg-helper': 'ctf',
  'lfsr-helper': 'ctf',
  'hash-length-extension-helper': 'ctf',
  'crypto-attack-helper': 'ctf',
  'bip39-seed': 'ctf',
  'pgp-parse': 'ctf',
  'cbc-padding-demo': 'ctf',
  // ---- 批次 W 纠偏：渗透专属收缩为 2 个（其余 57 个均为 CTF 高频工具，转 both）----
  'signature-nonce-helper': 'pentest',
  'basic-auth': 'pentest',
  'hash': 'both',
  'hash-identify': 'both',
  'hmac': 'both',
  'aes-gcm': 'both',
  'aes-cbc': 'both',
  'aes-ctr': 'both',
  'openssl-aes-256-cbc': 'both',
  'aes-cbc-raw': 'both',
  'aes-ctr-raw': 'both',
  'aes-ofb': 'both',
  'aes-gcm-siv': 'both',
  'aes-siv': 'both',
  'aes-ecb': 'both',
  'aes-cfb': 'both',
  'aes-kw': 'both',
  'aes-kwp': 'both',
  'aes-cmac': 'both',
  'des': 'both',
  'triple-des': 'both',
  'blowfish': 'both',
  'rabbit': 'both',
  'chacha20-orig': 'both',
  'chacha20': 'both',
  'xchacha20': 'both',
  'chacha20-poly1305': 'both',
  'xchacha20-poly1305': 'both',
  'salsa20': 'both',
  'xsalsa20': 'both',
  'xsalsa20-poly1305': 'both',
  'sm4': 'both',
  'rc4': 'both',
  'rc4-drop': 'both',
  'tea': 'both',
  'xtea': 'both',
  'xxtea': 'both',
  'rsa-oaep': 'both',
  'jsfuck-helper': 'both',
  'jsfuck': 'both',
  'aaencode': 'both',
  'jjencode': 'both',
  'jwt': 'both',
  'jwt-hmac': 'both',
  'jwt-public': 'both',
  'fernet': 'both',
  'hotp': 'both',
  'totp': 'both',
  'otpauth-uri': 'both',
  'querystring': 'both',
  'punycode': 'both',
  'pem-block': 'both',
  'asn1-der': 'both',
  'jwk-jwe': 'both',
  'ssh-public-key': 'both',
  'cbor': 'both',
  'messagepack': 'both',
  'protobuf-raw': 'both',
  'bson': 'both',
  // ---- 批次 O：随波逐流操作对齐（全部 CTF 域）----
  'base92': 'ctf',
  'base100': 'ctf',
  'base85-rfc1924': 'ctf',
  'base62-ascii': 'ctf',
  'base64-multiline': 'ctf',
  'base64-case-mangled': 'ctf',
  'base64-to-hex': 'ctf',
  'base-custom': 'ctf',
  'base-multi-decode': 'ctf',
  'rot18': 'ctf',
  'rot-special': 'ctf',
  'pigpen': 'ctf',
  'keyboard-keycode': 'ctf',
  'handycode': 'ctf',
  'chinesecode': 'ctf',
  'backslash-code': 'ctf',
  'slash-pipe': 'ctf',
  'tomtom': 'ctf',
  'clock-code': 'ctf',
  'goldbug': 'ctf',
  'kenny': 'ctf',
  'abaddon': 'ctf',
  'dvorak': 'ctf',
  'five-needle': 'ctf',
  'hodor': 'ctf',
  'duckspeak': 'ctf',
  'numberpad-lines': 'ctf',
  'quadoo': 'ctf',
  'bwt': 'ctf',
  'core-values': 'ctf',
  'hanzi-stroke': 'ctf',
  'yinyang-qi': 'ctf',
  'bagua-symbols': 'ctf',
  'telecode': 'ctf',
  'xiangyue': 'ctf',
  'makabaka': 'ctf',
  'yinyin': 'ctf',
  'shouyin': 'ctf',
  'periodic-table': 'ctf',
  'mars-text': 'ctf',
  'braille': 'ctf',
  'music-notes': 'ctf',
  'flower-code': 'ctf',
  'letter-code': 'ctf',
  'arrow-code': 'ctf',
  'hanzi-code': 'ctf',
  'ipa-code': 'ctf',
  'whitespace-code': 'ctf',
  'deadfish': 'ctf',
  'spoon': 'ctf',
  'manchester': 'ctf',
  'emoji-encoder': 'ctf',
  'otp': 'ctf',
  'multiplicative': 'ctf',
  'fractionated-morse': 'ctf',
  'fenham': 'ctf',
  'running-key': 'ctf',
  'bazeries': 'ctf',
  'kamasutra': 'ctf',
  'm209': 'ctf',
  'rc2': 'ctf',
  'rc6': 'ctf',
  'ieee754': 'ctf',
  'twos-complement': 'ctf',
  'ones-complement': 'ctf',
  'radix-xor': 'ctf',
  'bit-split': 'ctf',
  'hamming': 'ctf',
  'qwe-keyboard': 'ctf',
  'gcd': 'ctf',
  'prime-factor': 'ctf',
  'fibonacci-code': 'ctf',
  'pickle-parse': 'ctf',
  'ascii-control': 'ctf',
  'quwei': 'ctf',
};

export const isOperationVisible = (id: OperationId, audience: Audience): boolean => {
  const tag = operationAudience[id];
  return tag === 'both' || tag === audience;
};

// 视图分组数据：两个视图共用同一工作台组件，分组结构由纯函数产出，方便门禁脚本直接断言。
export interface CodecGroupSubgroup {
  name: { zh: string; en: string };
  ids: OperationId[];
}

export interface CodecGroupData {
  id: string;
  name: { zh: string; en: string };
  note: { zh: string; en: string };
  operations: Operation[];
  subgroups?: Array<{ name: { zh: string; en: string }; operations: Operation[] }>;
}

const operationById = new Map<string, Operation>(operations.map(operation => [operation.id, operation]));
const operationsInOrder = (ids: OperationId[]): Operation[] =>
  ids.map(id => operationById.get(id)).filter((operation): operation is Operation => Boolean(operation));

// 渗透编解码视图：沿用既有七大分类，仅保留 pentest+both 操作；被搬空的分类自动移除。
export const buildPentestGroups = (): CodecGroupData[] =>
  categories
    .map(category => ({
      id: category.id as string,
      name: category.name,
      note: category.note,
      operations: operations.filter(
        operation => operation.category === (category.id as CategoryId) && isOperationVisible(operation.id, 'pentest'),
      ),
    }))
    .filter(group => group.operations.length > 0);

// CTF 解题视图：按解题流程四段组织（智能识别 → 古典密码 → 现代密码攻击 → 编码与取证杂项），
// 段内超过 15 个操作时按导航分组规则拆 optgroup 二级菜单。
export const buildCtfGroups = (): CodecGroupData[] => ctfSections
  .map(section => {
    if (!section.subgroups) {
      return {
        id: section.id,
        name: section.name,
        note: section.note,
        operations: operationsInOrder(section.ids ?? []),
      };
    }
    const subgroups = section.subgroups.map(subgroup => ({
      name: subgroup.name,
      operations: operationsInOrder(subgroup.ids),
    }));
    return {
      id: section.id,
      name: section.name,
      note: section.note,
      operations: subgroups.flatMap(subgroup => subgroup.operations),
      subgroups,
    };
  })
  .filter(group => group.operations.length > 0);

// CTF 顶部菜单栏（随波逐流形态：顶部菜单 + 下拉 + 点击即执行）：展示层分组，与 ctfSections
// 是两套视图组织，覆盖同一操作全集（verify 脚本断言并集守恒）。受众分流与本表无关。
// 注意：菜单分组与 ctfSections 视图分组**不要求一致**（如 AES 冷门变体菜单归「变体与助手」、
// 视图归「分组密码」）——菜单受单节 ≤15 条约束需重排，verify 只守恒集合，漂移属有意设计。
export interface CodecMenuSpec {
  id: string;
  name: { zh: string; en: string };
  // 下拉内小节标签（如古典密码的多表替换/换位）；label 为 null 的组紧跟上一节不留空隙。
  sections: Array<{ label: { zh: string; en: string } | null; ids: OperationId[] }>;
}

const ctfMenuSpec: CodecMenuSpec[] = [
  {
    id: 'smart',
    name: { zh: '智能识别', en: 'Smart' },
    sections: [{ label: null, ids: ['smart-decode'] }],
  },
  {
    id: 'base-rot',
    name: { zh: 'Base/Rot', en: 'Base/Rot' },
    sections: [{
      label: null,
      ids: ['base64', 'base64url', 'base32', 'z-base-32', 'base36', 'base62', 'base62-ascii', 'base58', 'base58check', 'bech32', 'base45', 'base91', 'base92', 'base100', 'base85-rfc1924', 'base32768', 'ascii85', 'base64-multiline', 'base64-case-mangled', 'base64-to-hex', 'base-custom', 'base-multi-decode', 'rot', 'rot-bruteforce', 'rot8000'],
    }],
  },
  {
    id: 'classical',
    name: { zh: '古典密码', en: 'Classical' },
    sections: [
      { label: { zh: '多表替换', en: 'Polyalphabetic' }, ids: ['vigenere', 'beaufort', 'autokey', 'porta', 'gronsfeld'] },
      { label: { zh: '单表与仿射', en: 'Mono & Affine' }, ids: ['atbash', 'substitution', 'affine'] },
      { label: { zh: '换位密码', en: 'Transposition' }, ids: ['rail-fence', 'scytale', 'columnar'] },
      { label: { zh: '坐标与对码', en: 'Coordinate & Digraph' }, ids: ['bacon', 'polybius', 'tap-code', 'playfair', 'hill2', 'bifid', 'trifid', 'four-square', 'nihilist', 'adfgx', 'adfgvx'] },
      { label: { zh: '机器与破译', en: 'Machines & Attacks' }, ids: ['enigma', 'frequency-analysis', 'cisco-type7', 'rot18', 'rot-special'] },
      { label: { zh: '带key与多key', en: 'Keyed & Multi-key' }, ids: ['multiplicative', 'fractionated-morse', 'fenham', 'running-key', 'bazeries', 'kamasutra', 'm209'] },
    ],
  },
  {
    id: 'cn-tables',
    name: { zh: '中文字表', en: 'CN & Tables' },
    sections: [{
      label: null,
      ids: ['buddha', 'buddha-v2', 'bear-says', 'baijiaxing', 'hexagram', 'sexagesimal', 'cloud-shadow', 'pizzini', 'decabit', 'cetacean', 'albam', 'carbonaro', 'core-values', 'hanzi-stroke', 'yinyang-qi', 'bagua-symbols', 'telecode', 'xiangyue', 'makabaka', 'yinyin', 'shouyin', 'periodic-table', 'mars-text', 'braille', 'music-notes', 'flower-code', 'letter-code', 'arrow-code', 'hanzi-code', 'ipa-code'],
    }],
  },
  {
    id: 'char-tables',
    name: { zh: '字表字符', en: 'Char Tables' },
    sections: [{
      label: null,
      ids: ['pigpen', 'keyboard-keycode', 'handycode', 'chinesecode', 'backslash-code', 'slash-pipe', 'tomtom', 'clock-code', 'goldbug', 'kenny', 'abaddon', 'dvorak', 'five-needle', 'hodor', 'duckspeak', 'numberpad-lines', 'quadoo', 'bwt'],
    }],
  },
  {
    id: 'telegraph',
    name: { zh: '电报编码', en: 'Telegraph' },
    sections: [{
      label: null,
      ids: ['morse', 'nato-phonetic', 'baudot', 'bcd', 'gray-code', 'dna-code', 'gsm7', 'sms-pdu', 'a1z26', 'manchester'],
    }],
  },
  {
    id: 'encodings',
    name: { zh: '编码转换', en: 'Encodings' },
    sections: [{
      label: null,
      ids: ['url-component', 'url-form', 'html-entity', 'xml-entity', 'utf7', 'unicode-escape', 'js-string', 'c-string', 'json-string', 'quoted-printable', 'utf16-bytes', 'xxencode', 'uuencode', 'yenc', 'bubble-babble', 'gzip', 'deflate', 'data-url', 'querystring', 'punycode', 'cbor', 'messagepack', 'protobuf-raw', 'bson'],
    }],
  },
  {
    id: 'radix',
    name: { zh: '进制转换', en: 'Radix' },
    sections: [{ label: null, ids: ['hex', 'binary', 'octal-codes', 'ascii-codes', 'ieee754', 'twos-complement', 'ones-complement', 'radix-xor', 'bit-split', 'hamming', 'qwe-keyboard', 'gcd', 'prime-factor', 'fibonacci-code', 'pickle-parse', 'ascii-control', 'quwei'] }],
  },
  {
    // 现代密码五组（+ 变体助手节）：纠偏后的全部对称/非对称/散列操作按解题主线分组，
    // 每节 ≤15 条；条目在 CodecWorkbench 只列解密方向（无解密侧的操作回退唯一方向），方向切换在工作台按钮。
    id: 'modern',
    name: { zh: '现代密码', en: 'Modern Crypto' },
    sections: [
      { label: { zh: '非对称与签名', en: 'Asymmetric & Signature' }, ids: ['rsa-raw', 'rabin-raw', 'rsa-helper', 'coppersmith', 'rsa-oaep', 'pgp-parse', 'pem-block', 'asn1-der', 'ssh-public-key', 'jwk-jwe'] },
      { label: { zh: '分组密码', en: 'Block Ciphers' }, ids: ['aes-gcm', 'aes-cbc', 'aes-ctr', 'openssl-aes-256-cbc', 'aes-cbc-raw', 'aes-ctr-raw', 'aes-ecb', 'aes-cfb', 'des', 'triple-des', 'blowfish', 'sm4', 'fernet', 'rc2', 'rc6'] },
      { label: { zh: '流密码与序列', en: 'Stream & Sequence' }, ids: ['rc4', 'rc4-drop', 'chacha20-orig', 'chacha20', 'xchacha20', 'chacha20-poly1305', 'xchacha20-poly1305', 'salsa20', 'xsalsa20', 'xsalsa20-poly1305', 'rabbit', 'tea', 'xtea', 'xxtea', 'otp'] },
      { label: { zh: '散列与 JWT', en: 'Hash & JWT' }, ids: ['hash', 'hash-identify', 'hmac', 'aes-cmac', 'jwt', 'jwt-hmac', 'jwt-public', 'hash-length-extension-helper', 'hotp', 'totp', 'otpauth-uri'] },
      { label: { zh: 'PRNG 与格', en: 'PRNG & Lattice' }, ids: ['mt19937-helper', 'lcg-helper', 'lfsr-helper', 'discrete-log-helper'] },
      { label: { zh: '变体与助手', en: 'Variants & Helpers' }, ids: ['xor', 'xor-bruteforce', 'xor-known-plaintext', 'magic-xor-helper', 'aes-ofb', 'aes-kw', 'aes-kwp', 'aes-gcm-siv', 'aes-siv', 'crypto-attack-helper', 'bip39-seed', 'cbc-padding-demo'] },
    ],
  },
  {
    id: 'misc-tools',
    name: { zh: '其他工具', en: 'Misc Tools' },
    sections: [{ label: null, ids: ['reverse-text', 'keyboard-shift', 'zero-width', 'brainfuck', 'ook', 'unix-time', 'deadfish', 'spoon', 'whitespace-code', 'emoji-encoder', 'jsfuck', 'jsfuck-helper', 'aaencode', 'jjencode'] }],
  },
];

export interface CodecMenu {
  id: string;
  name: { zh: string; en: string };
  sections: Array<{ label: { zh: string; en: string } | null; operations: Operation[] }>;
}

// 顶部菜单栏数据：按 ctfMenuSpec 解析出操作对象；ID 必须全部落在传入的操作全集里（CTF 可见集），
// 出现未知 ID 属于菜单表与受众表漂移，直接抛错让 verify 门禁第一时间抓住。
export const buildCtfMenus = (): CodecMenu[] => {
  const known = new Set<string>(operations.map(operation => operation.id));
  return ctfMenuSpec.map(spec => ({
    id: spec.id,
    name: spec.name,
    sections: spec.sections.map(section => {
      for (const id of section.ids) {
        if (!known.has(id)) throw new Error(`ctfMenuSpec references unknown operation: ${id}`);
      }
      return { label: section.label, operations: operationsInOrder(section.ids) };
    }),
  }));
};

interface CtfSectionSpec {
  id: 'smart' | 'classical' | 'modern' | 'misc';
  name: { zh: string; en: string };
  note: { zh: string; en: string };
  ids?: OperationId[];
  subgroups?: Array<{ name: { zh: string; en: string }; ids: OperationId[] }>;
}

const ctfSections: CtfSectionSpec[] = [
  {
    id: 'smart',
    name: { zh: '智能识别', en: 'Smart Identify' },
    note: { zh: '粘贴密文自动识别', en: 'Auto identify' },
    ids: ['smart-decode'],
  },
  {
    id: 'classical',    name: { zh: '古典密码', en: 'Classical Ciphers' },
    note: { zh: '替换、换位与转转子机', en: 'Substitution & transposition' },
    subgroups: [
      { name: { zh: '多表替换', en: 'Polyalphabetic' }, ids: ['vigenere', 'beaufort', 'autokey', 'porta', 'gronsfeld'] },
      { name: { zh: '单表与仿射', en: 'Monoalphabetic & Affine' }, ids: ['atbash', 'substitution', 'affine'] },
      { name: { zh: '换位密码', en: 'Transposition' }, ids: ['rail-fence', 'scytale', 'columnar'] },
      { name: { zh: '坐标与对码', en: 'Coordinate & Digraph' }, ids: ['bacon', 'polybius', 'tap-code', 'playfair', 'hill2', 'bifid', 'trifid', 'four-square', 'nihilist', 'adfgx', 'adfgvx'] },
      { name: { zh: '字表与脉冲', en: 'Substitution Tables & Pulses' }, ids: ['pizzini', 'decabit', 'cetacean', 'albam', 'carbonaro'] },
      { name: { zh: '字表与符号（批次 O）', en: 'Tables & Symbols (Batch O)' }, ids: ['pigpen', 'keyboard-keycode', 'handycode', 'chinesecode', 'backslash-code', 'slash-pipe', 'tomtom', 'clock-code', 'goldbug', 'kenny', 'abaddon', 'dvorak', 'five-needle', 'hodor', 'duckspeak', 'numberpad-lines', 'quadoo', 'bwt'] },
      { name: { zh: '机器与破译', en: 'Machines & Attacks' }, ids: ['enigma', 'rot', 'rot-bruteforce', 'rot8000', 'rot18', 'rot-special', 'frequency-analysis', 'cisco-type7'] },
      { name: { zh: '中文密码', en: 'Chinese Ciphers' }, ids: ['buddha', 'buddha-v2', 'bear-says', 'baijiaxing', 'hexagram', 'sexagesimal', 'cloud-shadow'] },
      { name: { zh: '中文字表扩展（批次 O）', en: 'CN Tables Extended (Batch O)' }, ids: ['core-values', 'hanzi-stroke', 'yinyang-qi', 'bagua-symbols', 'telecode', 'xiangyue', 'makabaka', 'yinyin', 'shouyin', 'periodic-table', 'mars-text', 'braille', 'music-notes', 'flower-code', 'letter-code', 'arrow-code', 'hanzi-code', 'ipa-code'] },
    ],
  },
  {
    id: 'modern',
    name: { zh: '现代密码攻击', en: 'Modern Crypto Attacks' },
    note: { zh: 'RSA、对称密码、散列与随机数', en: 'RSA, ciphers, hash & PRNG' },
    subgroups: [
      { name: { zh: 'RSA 与大数', en: 'RSA & BigInt' }, ids: ['rsa-raw', 'rabin-raw', 'rsa-helper', 'coppersmith', 'rsa-oaep'] },
      { name: { zh: '分组密码', en: 'Block Ciphers' }, ids: ['aes-gcm', 'aes-cbc', 'aes-ctr', 'openssl-aes-256-cbc', 'aes-cbc-raw', 'aes-ctr-raw', 'aes-ofb', 'aes-gcm-siv', 'aes-siv', 'aes-ecb', 'aes-cfb', 'aes-kw', 'aes-kwp', 'aes-cmac', 'des', 'triple-des', 'blowfish', 'sm4', 'fernet'] },
      { name: { zh: '流密码与序列', en: 'Stream & Sequence' }, ids: ['rc4', 'rc4-drop', 'rabbit', 'chacha20-orig', 'chacha20', 'xchacha20', 'chacha20-poly1305', 'xchacha20-poly1305', 'salsa20', 'xsalsa20', 'xsalsa20-poly1305', 'tea', 'xtea', 'xxtea'] },
      { name: { zh: '散列与 JWT', en: 'Hash & JWT' }, ids: ['hash', 'hash-identify', 'hmac', 'jwt', 'jwt-hmac', 'jwt-public', 'hotp', 'totp', 'otpauth-uri'] },
      { name: { zh: 'XOR 攻击', en: 'XOR Attacks' }, ids: ['xor', 'xor-bruteforce', 'xor-known-plaintext', 'magic-xor-helper'] },
      { name: { zh: '随机数与序列', en: 'PRNG & Sequences' }, ids: ['mt19937-helper', 'lcg-helper', 'lfsr-helper', 'discrete-log-helper'] },
      { name: { zh: '协议与取证助手', en: 'Protocol & Forensics Helpers' }, ids: ['hash-length-extension-helper', 'crypto-attack-helper', 'bip39-seed', 'pgp-parse', 'cbc-padding-demo', 'pem-block', 'asn1-der', 'ssh-public-key', 'jwk-jwe'] },
      { name: { zh: '带key与多key（批次 O）', en: 'Keyed & Multi-key (Batch O)' }, ids: ['otp', 'multiplicative', 'fractionated-morse', 'fenham', 'running-key', 'bazeries', 'kamasutra', 'm209', 'rc2', 'rc6'] },
    ],
  },
  {
    id: 'misc',
    name: { zh: '编码与取证杂项', en: 'Encodings & Forensics Misc' },
    note: { zh: 'Base 家族、电报码与隐写', en: 'Base families, telegraph & stego' },
    subgroups: [
      { name: { zh: 'Base 家族与进制', en: 'Base Families & Radix' }, ids: ['base64', 'base64url', 'base32', 'z-base-32', 'base36', 'base62', 'base58', 'base58check', 'bech32', 'base45', 'base91', 'base32768', 'hex', 'binary', 'octal-codes', 'ascii-codes', 'ascii85', 'base92', 'base100', 'base85-rfc1924', 'base62-ascii', 'base64-multiline', 'base64-case-mangled', 'base64-to-hex', 'base-custom', 'base-multi-decode'] },
      { name: { zh: '取证与电报编码', en: 'Forensics & Telegraph' }, ids: ['morse', 'nato-phonetic', 'baudot', 'bcd', 'gray-code', 'dna-code', 'gsm7', 'sms-pdu', 'a1z26', 'manchester', 'xxencode', 'uuencode', 'yenc', 'bubble-babble'] },
      { name: { zh: '文本与隐写杂项', en: 'Text & Stego Misc' }, ids: ['reverse-text', 'keyboard-shift', 'zero-width', 'brainfuck', 'ook', 'deadfish', 'spoon', 'whitespace-code', 'emoji-encoder', 'unicode-escape', 'js-string', 'c-string', 'json-string', 'quoted-printable', 'utf16-bytes', 'unix-time', 'jsfuck', 'jsfuck-helper', 'aaencode', 'jjencode'] },
      { name: { zh: 'Web 与封装', en: 'Web & Wrappers' }, ids: ['url-component', 'url-form', 'html-entity', 'xml-entity', 'utf7', 'gzip', 'deflate', 'data-url', 'querystring', 'punycode', 'cbor', 'messagepack', 'protobuf-raw', 'bson'] },
      { name: { zh: '进制工具与数学（批次 O）', en: 'Radix Tools & Math (Batch O)' }, ids: ['ieee754', 'twos-complement', 'ones-complement', 'radix-xor', 'bit-split', 'hamming', 'qwe-keyboard', 'gcd', 'prime-factor', 'fibonacci-code', 'pickle-parse', 'ascii-control', 'quwei'] },
    ],
  },
];
