import { useMemo, useState } from 'react';
import { useAppContext } from '../appContext';
import { useEffect } from 'react';

type Direction = 'encode' | 'decode';
type CategoryId = 'smart' | 'web' | 'binary' | 'crypto' | 'text' | 'token' | 'compress';
type OperationId =
  | 'smart-decode'
  | 'url-component'
  | 'url-form'
  | 'html-entity'
  | 'xml-entity'
  | 'unicode-escape'
  | 'utf7'
  | 'js-string'
  | 'c-string'
  | 'json-string'
  | 'unix-time'
  | 'base64'
  | 'base64url'
  | 'base32'
  | 'base45'
  | 'base58'
  | 'base58check'
  | 'bech32'
  | 'base62'
  | 'base36'
  | 'base91'
  | 'ascii85'
  | 'uuencode'
  | 'hex'
  | 'binary'
  | 'octal-codes'
  | 'ascii-codes'
  | 'a1z26'
  | 'morse'
  | 'nato-phonetic'
  | 'baudot'
  | 'bcd'
  | 'gray-code'
  | 'dna-code'
  | 'gsm7'
  | 'sms-pdu'
  | 'cbor'
  | 'messagepack'
  | 'protobuf-raw'
  | 'bson'
  | 'yenc'
  | 'bubble-babble'
  | 'quoted-printable'
  | 'utf16-bytes'
  | 'reverse-text'
  | 'keyboard-shift'
  | 'zero-width'
  | 'hash'
  | 'hash-identify'
  | 'hmac'
  | 'aes-gcm'
  | 'aes-cbc'
  | 'aes-ctr'
  | 'openssl-aes-256-cbc'
  | 'aes-cbc-raw'
  | 'aes-ctr-raw'
  | 'aes-ofb'
  | 'aes-gcm-siv'
  | 'aes-siv'
  | 'aes-ecb'
  | 'aes-cfb'
  | 'aes-kw'
  | 'aes-kwp'
  | 'aes-cmac'
  | 'des'
  | 'triple-des'
  | 'blowfish'
  | 'rabbit'
  | 'chacha20-orig'
  | 'chacha20'
  | 'xchacha20'
  | 'chacha20-poly1305'
  | 'xchacha20-poly1305'
  | 'salsa20'
  | 'xsalsa20'
  | 'xsalsa20-poly1305'
  | 'sm4'
  | 'rc4'
  | 'rc4-drop'
  | 'tea'
  | 'xtea'
  | 'xxtea'
  | 'bip39-seed'
  | 'vigenere'
  | 'beaufort'
  | 'autokey'
  | 'atbash'
  | 'bacon'
  | 'polybius'
  | 'tap-code'
  | 'playfair'
  | 'hill2'
  | 'substitution'
  | 'affine'
  | 'rail-fence'
  | 'scytale'
  | 'columnar'
  | 'porta'
  | 'gronsfeld'
  | 'bifid'
  | 'trifid'
  | 'four-square'
  | 'nihilist'
  | 'adfgx'
  | 'adfgvx'
  | 'xor'
  | 'xor-bruteforce'
  | 'xor-known-plaintext'
  | 'magic-xor-helper'
  | 'rot'
  | 'rot-bruteforce'
  | 'rot8000'
  | 'enigma'
  | 'rsa-raw'
  | 'rabin-raw'
  | 'rsa-helper'
  | 'signature-nonce-helper'
  | 'discrete-log-helper'
  | 'mt19937-helper'
  | 'lcg-helper'
  | 'lfsr-helper'
  | 'hash-length-extension-helper'
  | 'crypto-attack-helper'
  | 'frequency-analysis'
  | 'brainfuck'
  | 'ook'
  | 'jsfuck-helper'
  | 'jwt'
  | 'jwt-hmac'
  | 'jwt-public'
  | 'fernet'
  | 'hotp'
  | 'totp'
  | 'otpauth-uri'
  | 'querystring'
  | 'basic-auth'
  | 'punycode'
  | 'pem-block'
  | 'asn1-der'
  | 'jwk-jwe'
  | 'ssh-public-key'
  | 'gzip'
  | 'deflate'
  | 'data-url';

type ParamKey = 'variant' | 'hashAlgorithm' | 'secret' | 'iv' | 'keyword2' | 'associatedData' | 'hrp' | 'versionHex' | 'digits' | 'counter' | 'timeStep' | 'otpTimestamp' | 'period' | 'iterations' | 'shift' | 'separator' | 'mimeType' | 'blockLabel' | 'affineA' | 'affineB' | 'rails' | 'knownPlaintext' | 'dropBytes';

interface Operation {
  id: OperationId;
  category: CategoryId;
  name: { zh: string; en: string };
  summary: { zh: string; en: string };
  encodeLabel?: { zh: string; en: string };
  decodeLabel?: { zh: string; en: string };
  supportsEncode?: boolean;
  supportsDecode?: boolean;
  params?: ParamKey[];
}

interface Detection {
  id: OperationId;
  label: string;
}

const categories: Array<{ id: CategoryId; name: { zh: string; en: string }; note: { zh: string; en: string } }> = [
  { id: 'smart', name: { zh: '智能识别', en: 'Smart' }, note: { zh: '自动识别多层编码', en: 'Detect nested encodings' } },
  { id: 'web', name: { zh: 'Web 编码', en: 'Web' }, note: { zh: 'URL、HTML、Unicode、JS', en: 'URL, HTML, Unicode, JS' } },
  { id: 'binary', name: { zh: '进制与文本', en: 'Binary' }, note: { zh: 'Base 系列、Hex、Morse', en: 'Base families, Hex, Morse' } },
  { id: 'crypto', name: { zh: '加密与摘要', en: 'Crypto' }, note: { zh: 'Hash、HMAC、AES、XOR', en: 'Hash, HMAC, AES, XOR' } },
  { id: 'text', name: { zh: '文本处理', en: 'Text' }, note: { zh: 'JSON 字符串与转义', en: 'JSON strings and escaping' } },
  { id: 'token', name: { zh: '令牌与协议', en: 'Tokens' }, note: { zh: 'JWT、Query、Basic Auth', en: 'JWT, Query, Basic Auth' } },
  { id: 'compress', name: { zh: '压缩封装', en: 'Compress' }, note: { zh: 'GZip、Deflate、Data URL', en: 'GZip, Deflate, Data URL' } },
];

const operations: Operation[] = [
  {
    id: 'smart-decode',
    category: 'smart',
    name: { zh: '智能多层解码', en: 'Smart Decode' },
    summary: { zh: '自动尝试 URL、HTML、Unicode、Base64、Hex 等常见嵌套编码，并优先停在看起来像明文的结果。', en: 'Automatically tries URL, HTML, Unicode, Base64, Hex, and common nested encodings.' },
    supportsEncode: false,
    decodeLabel: { zh: '智能解码', en: 'Smart decode' },
  },
  {
    id: 'url-component',
    category: 'web',
    name: { zh: 'URL 组件编码', en: 'URL Component' },
    summary: { zh: '对参数值、路径片段和 payload 片段做百分号编码或解码。', en: 'Percent-encode or decode parameter values, path fragments, and payload snippets.' },
  },
  {
    id: 'url-form',
    category: 'web',
    name: { zh: '表单 URL 编码', en: 'Form URL Encoding' },
    summary: { zh: '适合 `application/x-www-form-urlencoded` 场景，空格会编码为 `+`。', en: 'Encodes or decodes application/x-www-form-urlencoded data, where spaces become +.' },
  },
  {
    id: 'html-entity',
    category: 'web',
    name: { zh: 'HTML 实体', en: 'HTML Entity' },
    summary: { zh: '支持命名实体、十进制实体和十六进制实体三种输出形式。', en: 'Supports named, decimal, and hexadecimal HTML entity output.' },
    params: ['variant'],
  },
  {
    id: 'xml-entity',
    category: 'web',
    name: { zh: 'XML 实体', en: 'XML Entity' },
    summary: { zh: '适合 XML、SOAP、SAML 场景，支持命名实体、十进制和十六进制实体输出。', en: 'For XML, SOAP, and SAML payloads with named, decimal, and hexadecimal entity output.' },
    params: ['variant'],
  },
  {
    id: 'unicode-escape',
    category: 'web',
    name: { zh: 'Unicode / Hex 转义', en: 'Unicode / Hex Escape' },
    summary: { zh: '在普通文本与 \\uXXXX、\\u{XXXX}、\\xHH 风格转义之间互转。', en: 'Converts between \\uXXXX, \\u{XXXX}, \\xHH, and normal text.' },
    params: ['variant'],
  },
  {
    id: 'utf7',
    category: 'web',
    name: { zh: 'UTF-7', en: 'UTF-7' },
    summary: { zh: '在文本与 UTF-7 之间互转，适合旧邮件、编码兼容和 CTF Unicode 题。', en: 'Converts text to and from UTF-7 for legacy mail, web encoding bypass, and CTF Unicode puzzles.' },
  },
  {
    id: 'js-string',
    category: 'web',
    name: { zh: 'JavaScript 字符串', en: 'JavaScript String' },
    summary: { zh: '把文本转成 JavaScript 字符串字面量安全转义，也支持反向还原。', en: 'Escapes text for JavaScript string literals and reverses it.' },
  },
  {
    id: 'c-string',
    category: 'text',
    name: { zh: 'C / Python 转义', en: 'C / Python Escapes' },
    summary: { zh: '在普通文本与 \\n、\\xHH、\\ooo、\\uXXXX、\\UXXXXXXXX 风格转义之间互转，适合 shellcode、日志和源码片段', en: 'Converts text to and from \\n, \\xHH, \\ooo, \\uXXXX, and \\UXXXXXXXX escapes for shellcode, logs, and source snippets.' },
  },
  {
    id: 'json-string',
    category: 'text',
    name: { zh: 'JSON 字符串 / 格式化', en: 'JSON String / Pretty' },
    summary: { zh: '编码时生成 JSON 字符串；解码时自动反转义或格式化 JSON。', en: 'Encodes as a JSON string; decodes by unescaping or pretty-printing JSON.' },
  },
  {
    id: 'unix-time',
    category: 'text',
    name: { zh: 'Unix 时间', en: 'Unix Time' },
    summary: { zh: '在 ISO 时间、秒级 / 毫秒级 Unix 时间戳之间互转，适合日志、JWT 和 API 时间字段分析。', en: 'Converts between ISO datetimes and second/millisecond Unix timestamps for logs, JWTs, and APIs.' },
  },
  {
    id: 'base64',
    category: 'binary',
    name: { zh: 'Base64', en: 'Base64' },
    summary: { zh: '在 UTF-8 文本与标准 Base64 之间互转。', en: 'Converts UTF-8 text to and from standard Base64.' },
  },
  {
    id: 'base64url',
    category: 'binary',
    name: { zh: 'Base64URL', en: 'Base64URL' },
    summary: { zh: '适合 JWT、URL 参数和无填充 Base64 场景', en: 'Useful for JWTs, URL parameters, and unpadded Base64.' },
  },
  {
    id: 'base32',
    category: 'binary',
    name: { zh: 'Base32', en: 'Base32' },
    summary: { zh: 'RFC 4648 风格的 Base32，常见于密钥、令牌和各类编码题。', en: 'RFC 4648-style Base32 for keys, tokens, and CTF encodings.' },
    params: ['variant'],
  },
  {
    id: 'base45',
    category: 'binary',
    name: { zh: 'Base45', en: 'Base45' },
    summary: { zh: 'RFC 9285 Base45，常见于二维码、数字证书和紧凑文本传输场景。', en: 'RFC 9285 Base45 for QR-oriented and compact transfer scenarios.' },
  },
  {
    id: 'base58',
    category: 'binary',
    name: { zh: 'Base58', en: 'Base58' },
    summary: { zh: '使用 Bitcoin 字母表的 Base58，避开 0/O/I/l 等易混字符。', en: 'Bitcoin alphabet Base58 without confusing 0/O/I/l characters.' },
  },
  {
    id: 'base58check',
    category: 'binary',
    name: { zh: 'Base58Check', en: 'Base58Check' },
    summary: { zh: 'Bitcoin 风格 Base58Check，带版本字节和双 SHA-256 校验，适合地址、WIF 和钱包类题目。', en: 'Bitcoin-style Base58Check with version byte and double-SHA256 checksum for addresses, WIF keys, and wallet CTFs.' },
    params: ['versionHex'],
  },
  {
    id: 'bech32',
    category: 'binary',
    name: { zh: 'Bech32 / Bech32m', en: 'Bech32 / Bech32m' },
    summary: { zh: 'BIP173 / BIP350 地址编码，支持 HRP、Bech32 和 Bech32m 校验。', en: 'BIP173/BIP350 address encoding with HRP, Bech32, and Bech32m checksums for blockchain and forensic CTFs.' },
    params: ['variant', 'hrp'],
  },
  {
    id: 'base62',
    category: 'binary',
    name: { zh: 'Base62', en: 'Base62' },
    summary: { zh: '常见于短链、邀请码和压缩数字 ID 场景。', en: 'Common for short URLs, invite codes, and compact numeric IDs.' },
  },
  {
    id: 'base36',
    category: 'binary',
    name: { zh: 'Base36', en: 'Base36' },
    summary: { zh: '使用 0-9A-Z 字母表的进制编码，常见于短 ID、序列号和自定义进制提示。', en: '0-9A-Z radix encoding for CTF short IDs, serials, and custom-base hints.' },
  },
  {
    id: 'base91',
    category: 'binary',
    name: { zh: 'Base91', en: 'Base91' },
    summary: { zh: '高密度二进制转文本编码，常被当作 Base 家族的混淆层。', en: 'High-density binary-to-text encoding often used as a Base-family CTF obfuscation layer.' },
  },
  {
    id: 'ascii85',
    category: 'binary',
    name: { zh: 'ASCII85 / Base85', en: 'ASCII85 / Base85' },
    summary: { zh: '适合 PostScript、PDF 和二进制转文本封装场景，支持 Adobe ASCII85 与 Z85。', en: 'Useful for PostScript, PDF, and binary-to-text wrappers with Adobe ASCII85 and Z85.' },
    params: ['variant'],
  },
  {
    id: 'uuencode',
    category: 'binary',
    name: { zh: 'UUencode', en: 'UUencode' },
    summary: { zh: '经典 Unix 邮件附件文本封装格式，CTF 杂项和取证题里仍会出现。', en: 'Legacy Unix mail attachment text wrapper that still appears in CTF misc and forensics tasks.' },
    params: ['blockLabel'],
  },
  {
    id: 'hex',
    category: 'binary',
    name: { zh: 'Hex 十六进制', en: 'Hex' },
    summary: { zh: '支持纯 Hex、0x 前缀、\\x 前缀和空格分隔格式。', en: 'Supports plain hex, 0x prefixes, \\x prefixes, and spaced hex.' },
    params: ['variant'],
  },
  {
    id: 'binary',
    category: 'binary',
    name: { zh: '二进制字', en: 'Binary Bytes' },
    summary: { zh: '在文本与 8 位二进制字节串之间互转。', en: 'Converts text to and from 8-bit binary byte strings.' },
    params: ['separator'],
  },
  {
    id: 'octal-codes',
    category: 'binary',
    name: { zh: 'Octal / 八进', en: 'Octal Codes' },
    summary: { zh: '在文本与八进制字符码之间互转，支持 \\ooo、0o 前缀和空格分隔格式。', en: 'Converts text and octal character codes, including \\ooo, 0o-prefixed, and spaced CTF forms.' },
    params: ['separator'],
  },
  {
    id: 'ascii-codes',
    category: 'binary',
    name: { zh: 'ASCII / Decimal', en: 'ASCII / Decimal' },
    summary: { zh: '文本与十进制字符编码互转', en: 'Converts text to and from decimal character codes.' },
    params: ['separator'],
  },
  {
    id: 'a1z26',
    category: 'binary',
    name: { zh: 'A1Z26 字母数字', en: 'A1Z26' },
    summary: { zh: 'A=1 到 Z=26 的字母编号，常见于入门 CTF 编码题。', en: 'Maps A=1 through Z=26, a common beginner CTF encoding.' },
    params: ['separator'],
  },
  {
    id: 'morse',
    category: 'binary',
    name: { zh: 'Morse 摩斯', en: 'Morse Code' },
    summary: { zh: '英文、数字和常见符号与摩斯码互转', en: 'Converts letters, digits, and common symbols to and from Morse code.' },
  },
  {
    id: 'nato-phonetic',
    category: 'binary',
    name: { zh: 'NATO 音标字母', en: 'NATO Phonetic' },
    summary: { zh: '在字母与 Alpha / Bravo / Charlie 这类 NATO 音标词之间互转。', en: 'Converts letters to and from Alpha/Bravo/Charlie words used in radio, voice, and beginner CTF puzzles.' },
    params: ['separator'],
  },
  {
    id: 'baudot',
    category: 'binary',
    name: { zh: 'Baudot / ITA2', en: 'Baudot / ITA2' },
    summary: { zh: '5-bit Baudot / ITA2 电传码，自动处理字母态与数字符号态之间的移位控制。', en: '5-bit Baudot/ITA2 teleprinter code with automatic Letters/Figures shift handling.' },
    params: ['separator'],
  },
  {
    id: 'bcd',
    category: 'binary',
    name: { zh: 'BCD 二进制十进制', en: 'BCD' },
    summary: { zh: '在十进制数字与 4-bit BCD 半字节之间互转，适合硬件、取证和杂项题。', en: 'Converts decimal digits to and from 4-bit BCD nibbles for hardware, forensics, and misc CTF tasks.' },
    params: ['separator'],
  },
  {
    id: 'gray-code',
    category: 'binary',
    name: { zh: 'Gray Code 格雷', en: 'Gray Code' },
    summary: { zh: '在二进制或十进制整数与 Gray Code 之间互转；裸 0/1 串按二进制，支持 0b / 0d 前缀消除歧义。', en: 'Converts binary or decimal integers to and from Gray code; bare 0/1 strings are binary, with 0b/0d prefixes for unambiguous input.' },
    params: ['separator'],
  },
  {
    id: 'dna-code',
    category: 'binary',
    name: { zh: 'DNA 编码', en: 'DNA Encoding' },
    summary: { zh: '用 A / C / G / T 表示 2-bit 数据，适合 DNA 编码层分析。', en: 'Represents 2-bit data with A/C/G/T for common CTF DNA binary encoding layers.' },
    params: ['variant', 'separator'],
  },
  {
    id: 'gsm7',
    category: 'binary',
    name: { zh: 'GSM 7-bit', en: 'GSM 7-bit' },
    summary: { zh: '在 GSM 03.38 默认字母表文本与 7-bit 打包 Hex 之间互转。', en: 'Converts GSM 03.38 default alphabet text to and from 7-bit packed hex for SMS PDU, mobile forensics, and misc CTF tasks.' },
  },
  {
    id: 'sms-pdu',
    category: 'binary',
    name: { zh: 'SMS PDU 解析', en: 'SMS PDU Parser' },
    summary: { zh: '解析 GSM SMS-DELIVER / SUBMIT PDU，包括 SMSC、号码、时间戳、DCS 和用户数据。', en: 'Parses GSM SMS-DELIVER/SUBMIT PDU fields including SMSC, address, timestamp, DCS, and user data for mobile-forensics and misc CTF tasks.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 PDU', en: 'Parse PDU' },
  },
  {
    id: 'cbor',
    category: 'binary',
    name: { zh: 'CBOR 解析', en: 'CBOR Parser' },
    summary: { zh: '把 Hex / Base64 形式的 CBOR 解析为主要类型、Tag、数组、Map 和文本值。', en: 'Parses CBOR from Hex/Base64 into major types, tags, arrays, maps, byte strings, and text values.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 CBOR', en: 'Parse CBOR' },
  },
  {
    id: 'messagepack',
    category: 'binary',
    name: { zh: 'MessagePack 解析', en: 'MessagePack Parser' },
    summary: { zh: '解析 Hex / Base64 形式的 MessagePack，适合 API 抓包、缓存文件和二进制对象题。', en: 'Parses MessagePack from Hex/Base64 for API captures, cache files, and binary-object misc challenges.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 MsgPack', en: 'Parse MsgPack' },
  },
  {
    id: 'protobuf-raw',
    category: 'binary',
    name: { zh: 'Protobuf Wire 解析', en: 'Protobuf Wire Parser' },
    summary: { zh: '基于 protobufjs Reader 解析无 schema 的 Protobuf wire 字段，展示 field、wire type、varint 和 length-delimited 预览。', en: 'Uses protobufjs Reader to parse schema-less Protobuf wire fields, showing field numbers, wire types, varints, fixed values, and length-delimited previews.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 Protobuf', en: 'Parse Protobuf' },
  },
  {
    id: 'bson',
    category: 'binary',
    name: { zh: 'BSON 解析', en: 'BSON Parser' },
    summary: { zh: '使用官方 `bson` 包把 MongoDB BSON 文档解析成 Extended JSON，适合导出、缓存和取证数据。', en: 'Uses the official bson package to parse MongoDB BSON documents into Extended JSON for database dumps, caches, and forensics challenges.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 BSON', en: 'Parse BSON' },
  },
  {
    id: 'yenc',
    category: 'binary',
    name: { zh: 'yEnc', en: 'yEnc' },
    summary: { zh: '在文本与 yEnc 转义流之间互转，适合旧格式附件和取证题。', en: 'Converts text to and from yEnc escaped streams used in newsgroup attachments, forensics, and legacy-format puzzles.' },
  },
  {
    id: 'bubble-babble',
    category: 'binary',
    name: { zh: 'Bubble Babble', en: 'Bubble Babble' },
    summary: { zh: '在 UTF-8 文本与 xigak-... 风格的 Bubble Babble 形式之间互转。', en: 'Converts UTF-8 text to and from the xigak-... Bubble Babble form often seen in OpenSSH fingerprints.' },
  },
  {
    id: 'quoted-printable',
    category: 'text',
    name: { zh: 'Quoted-Printable', en: 'Quoted-Printable' },
    summary: { zh: '邮件 MIME 中常见的编码格式，适合处理 =XX 转义和软换行。', en: 'Common MIME mail encoding for =XX escapes and soft line breaks.' },
  },
  {
    id: 'utf16-bytes',
    category: 'text',
    name: { zh: 'UTF-16 字节', en: 'UTF-16 Bytes' },
    summary: { zh: '在文本与 UTF-16 LE / BE 的十六进制字节序列之间互转。', en: 'Converts text to and from UTF-16 LE/BE hexadecimal byte sequences.' },
    params: ['variant', 'separator'],
  },
  {
    id: 'reverse-text',
    category: 'text',
    name: { zh: '反转 / 倒序', en: 'Reverse Text' },
    summary: { zh: '把文本整体倒序，适合反写 flag、镜像提示和简单倒序混淆。', en: 'Reverses text for backwards flags, reversed payloads, and simple mirror hints.' },
  },
  {
    id: 'keyboard-shift',
    category: 'text',
    name: { zh: '键盘偏移', en: 'Keyboard Shift' },
    summary: { zh: '还原左右偏移的 QWERTY 键盘误位输入，常见于杂项题和手工输入混淆。', en: 'Restores left/right QWERTY keyboard-shifted text common in CTF misc puzzles.' },
    params: ['variant'],
  },
  {
    id: 'zero-width',
    category: 'text',
    name: { zh: '零宽字符隐写', en: 'Zero-Width Stego' },
    summary: { zh: '用零宽字符隐藏或提取 UTF-8 文本，适合不可见字符隐写和文本混淆题。', en: 'Hides or extracts UTF-8 text using zero-width characters for invisible-character CTF puzzles.' },
  },
  {
    id: 'hash',
    category: 'crypto',
    name: { zh: 'Hash / Checksum', en: 'Hash / Checksum' },
    summary: { zh: '生成 MD5、SHA、CRC 等摘要或校验值；摘要本身不可逆。', en: 'Generates MD5, SHA, and CRC32 digests. Hashes are one-way.' },
    supportsDecode: false,
    encodeLabel: { zh: '生成摘要', en: 'Generate hash' },
    params: ['hashAlgorithm'],
  },
  {
    id: 'hash-identify',
    category: 'crypto',
    name: { zh: 'Hash 识别', en: 'Hash Identifier' },
    summary: { zh: '按长度和字符特征识别常见 MD5、SHA、NTLM、bcrypt、Argon2、CRC 等摘要格式。', en: 'Identifies common MD5, SHA, NTLM, bcrypt, Argon2, CRC, and related hash formats by shape.' },
    supportsEncode: false,
    decodeLabel: { zh: '识别格式', en: 'Identify' },
  },
  {
    id: 'hmac',
    category: 'crypto',
    name: { zh: 'HMAC', en: 'HMAC' },
    summary: { zh: '使用密钥生成 HMAC 摘要，适合接口签名校验和 token 完整性验证。', en: 'Generates HMAC-SHA digests with a secret key for API signatures.' },
    supportsDecode: false,
    encodeLabel: { zh: '生成 HMAC', en: 'Generate HMAC' },
    params: ['hashAlgorithm', 'secret'],
  },
  {
    id: 'bip39-seed',
    category: 'crypto',
    name: { zh: 'BIP39 助记词 Seed', en: 'BIP39 Mnemonic Seed' },
    summary: { zh: '按 BIP39 规范使用 PBKDF2-HMAC-SHA512，从助记词和可选 passphrase 派生 512-bit seed。', en: 'Derives the 512-bit BIP39 seed from a mnemonic and optional passphrase using PBKDF2-HMAC-SHA512 for wallet and seed-recovery challenges.' },
    supportsEncode: false,
    decodeLabel: { zh: '派生 Seed', en: 'Derive seed' },
    params: ['secret'],
  },
  {
    id: 'aes-gcm',
    category: 'crypto',
    name: { zh: 'AES-GCM', en: 'AES-GCM' },
    summary: { zh: '基于口令的 AES-GCM 加密/解密，输出包含 salt、IV 和 ciphertext 的 JSON 结构。', en: 'Password-based AES-GCM encryption/decryption with JSON salt, IV, and ciphertext output.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iterations'],
  },
  {
    id: 'aes-cbc',
    category: 'crypto',
    name: { zh: 'AES-CBC', en: 'AES-CBC' },
    summary: { zh: '基于口令派生 256-bit AES-CBC，输出包含 salt、IV 和 ciphertext 的 JSON 结构。', en: 'Password-derived 256-bit AES-CBC with JSON salt, IV, and ciphertext output.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iterations'],
  },
  {
    id: 'aes-ctr',
    category: 'crypto',
    name: { zh: 'AES-CTR', en: 'AES-CTR' },
    summary: { zh: '基于口令派生 AES-CTR，适合验证流模式、nonce 复用和已知明文分析。', en: 'Password-derived AES-CTR for validating stream-mode, nonce reuse, and known-plaintext analysis.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iterations'],
  },
  {
    id: 'openssl-aes-256-cbc',
    category: 'crypto',
    name: { zh: 'OpenSSL enc AES-256-CBC', en: 'OpenSSL enc AES-256-CBC' },
    summary: { zh: '兼容经典 `openssl enc` 的 `Salted__` / `U2FsdGVkX1` 格式，使用 MD5 `EVP_BytesToKey` 派生 key / IV。', en: 'Compatible with the classic openssl enc Salted__ / U2FsdGVkX1 format and MD5 EVP_BytesToKey derivation.' },
    encodeLabel: { zh: 'OpenSSL 加密', en: 'OpenSSL encrypt' },
    decodeLabel: { zh: 'OpenSSL 解密', en: 'OpenSSL decrypt' },
    params: ['secret'],
  },
  {
    id: 'aes-cbc-raw',
    category: 'crypto',
    name: { zh: 'AES-CBC Raw', en: 'AES-CBC Raw' },
    summary: { zh: '原始密钥 AES-CBC，使用 16-byte IV，支持 PKCS#7 padding 或精确分组无 padding 模式。', en: 'Raw-key AES-CBC with a 16-byte IV, supporting PKCS#7 padding or exact-block no-padding CTF data.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['variant', 'secret', 'iv'],
  },
  {
    id: 'aes-ctr-raw',
    category: 'crypto',
    name: { zh: 'AES-CTR Raw', en: 'AES-CTR Raw' },
    summary: { zh: '原始密钥 AES-CTR，使用 16-byte counter block，适合流模式密文还原和 nonce 复用检查。', en: 'Raw-key AES-CTR with a 16-byte counter block for stream-mode ciphertext recovery and nonce-reuse checks.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'aes-ofb',
    category: 'crypto',
    name: { zh: 'AES-OFB', en: 'AES-OFB' },
    summary: { zh: '原始密钥 AES-OFB，使用 16-byte IV，适合旧式流模式 AES 数据。', en: 'Raw-key AES-OFB with a 16-byte IV for legacy stream-style AES challenges.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'aes-ecb',
    category: 'crypto',
    name: { zh: 'AES-ECB', en: 'AES-ECB' },
    summary: { zh: '原始密钥 AES-ECB，支持 PKCS#7 padding 或精确分组无 padding 模式。', en: 'Raw-key AES-ECB with PKCS#7 padding or exact-block no-padding mode for basic CTF crypto tasks.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['variant', 'secret'],
  },
  {
    id: 'aes-cfb',
    category: 'crypto',
    name: { zh: 'AES-CFB', en: 'AES-CFB' },
    summary: { zh: '原始密钥 AES-CFB-128，使用 16-byte IV，适合反馈模式密文还原。', en: 'Raw-key AES-CFB-128 with a 16-byte IV for feedback-mode ciphertext recovery.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'aes-kw',
    category: 'crypto',
    name: { zh: 'AES-KW', en: 'AES-KW' },
    summary: { zh: 'RFC 3394 AES Key Wrap，用 KEK 包裹或解包至少 16 字节且按 8 字节对齐的密钥材料。', en: 'RFC 3394 AES Key Wrap for wrapping or unwrapping 8-byte-aligned key material of at least 16 bytes with a KEK.' },
    encodeLabel: { zh: '包裹密钥', en: 'Wrap key' },
    decodeLabel: { zh: '解包密钥', en: 'Unwrap key' },
    params: ['secret'],
  },
  {
    id: 'aes-kwp',
    category: 'crypto',
    name: { zh: 'AES-KWP', en: 'AES-KWP' },
    summary: { zh: 'RFC 5649 的 AES Key Wrap with Padding，适合较短或非 8 字节对齐的 key blob。', en: 'RFC 5649 AES Key Wrap with Padding for short or non-8-byte-aligned key blobs.' },
    encodeLabel: { zh: '包裹密钥', en: 'Wrap key' },
    decodeLabel: { zh: '解包密钥', en: 'Unwrap key' },
    params: ['secret'],
  },
  {
    id: 'aes-cmac',
    category: 'crypto',
    name: { zh: 'AES-CMAC', en: 'AES-CMAC' },
    summary: { zh: 'RFC 4493 AES-CMAC，输出 16-byte tag，适合协议 MAC 和固件校验题。', en: 'RFC 4493 AES-CMAC producing a 16-byte tag for protocol MACs and firmware verification tasks.' },
    encodeLabel: { zh: '计算 CMAC', en: 'Compute CMAC' },
    supportsDecode: false,
    params: ['secret'],
  },
  {
    id: 'aes-gcm-siv',
    category: 'crypto',
    name: { zh: 'AES-GCM-SIV', en: 'AES-GCM-SIV' },
    summary: { zh: 'RFC 8452 的 nonce-misuse-resistant AEAD，使用 12-byte nonce，并支持可选 AAD。', en: 'RFC 8452 nonce-misuse-resistant AEAD with a 12-byte nonce and optional AAD.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv', 'associatedData'],
  },
  {
    id: 'aes-siv',
    category: 'crypto',
    name: { zh: 'AES-SIV', en: 'AES-SIV' },
    summary: { zh: 'RFC 5297 Synthetic IV AEAD；留空 nonce 时为确定性模式，填写时会作为最终 AAD 组件。', en: 'RFC 5297 Synthetic IV AEAD; leave nonce empty for deterministic SIV or provide it as the final AAD component.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv', 'associatedData'],
  },
  {
    id: 'des',
    category: 'crypto',
    name: { zh: 'DES', en: 'DES' },
    summary: { zh: '支持 DES-CBC / ECB 和 OpenSSL Salted__ passphrase 格式，适合旧协议和基础密码题。', en: 'DES-CBC/ECB plus OpenSSL Salted__ passphrase format for legacy protocols, weak crypto, and CTF basics.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['variant', 'secret', 'iv'],
  },
  {
    id: 'triple-des',
    category: 'crypto',
    name: { zh: 'TripleDES / 3DES', en: 'TripleDES / 3DES' },
    summary: { zh: '支持 3DES-CBC / ECB 和 OpenSSL Salted__ passphrase 格式，适合旧系统和 DESede 数据。', en: '3DES-CBC/ECB plus OpenSSL Salted__ passphrase format for legacy systems and DESede-style CTF data.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['variant', 'secret', 'iv'],
  },
  {
    id: 'blowfish',
    category: 'crypto',
    name: { zh: 'Blowfish', en: 'Blowfish' },
    summary: { zh: '支持 Blowfish-CBC / ECB 和 OpenSSL Salted__ passphrase 格式，适合旧应用和取证样本。', en: 'Blowfish-CBC/ECB plus OpenSSL Salted__ passphrase format for legacy apps, forensics samples, and CTF symmetric crypto.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['variant', 'secret', 'iv'],
  },
  {
    id: 'rabbit',
    category: 'crypto',
    name: { zh: 'Rabbit', en: 'Rabbit' },
    summary: { zh: 'Rabbit 流密码，兼容 OpenSSL Salted__ passphrase 格式，适合旧式流密码数据。', en: 'Rabbit stream cipher plus OpenSSL Salted__ passphrase format for CyberChef and CTF legacy stream-cipher data.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['variant', 'secret', 'iv'],
  },
  {
    id: 'chacha20-orig',
    category: 'crypto',
    name: { zh: 'ChaCha20 原始版', en: 'ChaCha20 Original' },
    summary: { zh: '原始 ChaCha20 XOR 流密码，使用 32-byte key 和 8-byte nonce，兼容 PyCryptodome ChaCha20。', en: 'Original ChaCha20 XOR stream cipher with a 32-byte key and 8-byte nonce, compatible with PyCryptodome ChaCha20.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'chacha20',
    category: 'crypto',
    name: { zh: 'ChaCha20', en: 'ChaCha20' },
    summary: { zh: 'RFC 8439 的 ChaCha20 XOR 流密码，使用 32-byte key 和 12-byte nonce。', en: 'RFC 8439 ChaCha20 XOR stream cipher with a 32-byte key and 12-byte nonce.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'xchacha20',
    category: 'crypto',
    name: { zh: 'XChaCha20', en: 'XChaCha20' },
    summary: { zh: 'XChaCha20 扩展 nonce 变体，使用 32-byte key 和 24-byte nonce，常见于 libsodium 数据。', en: 'XChaCha20 extended-nonce variant with a 32-byte key and 24-byte nonce, commonly seen in libsodium data.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'chacha20-poly1305',
    category: 'crypto',
    name: { zh: 'ChaCha20-Poly1305', en: 'ChaCha20-Poly1305' },
    summary: { zh: 'RFC 8439 的 AEAD 实现，使用 32-byte key、12-byte nonce 和 16-byte tag，支持可选 AAD。', en: 'RFC 8439 AEAD with a 32-byte key, 12-byte nonce, 16-byte tag, and optional AAD.' },
    encodeLabel: { zh: '加密并认证', en: 'Encrypt + authenticate' },
    decodeLabel: { zh: '验证并解密', en: 'Verify + decrypt' },
    params: ['secret', 'iv', 'associatedData'],
  },
  {
    id: 'xchacha20-poly1305',
    category: 'crypto',
    name: { zh: 'XChaCha20-Poly1305', en: 'XChaCha20-Poly1305' },
    summary: { zh: '扩展 nonce 的 AEAD，使用 32-byte key、24-byte nonce 和 16-byte tag，常见于 libsodium 抓包。', en: 'Extended-nonce AEAD with a 32-byte key, 24-byte nonce, 16-byte tag, and optional AAD.' },
    encodeLabel: { zh: '加密并认证', en: 'Encrypt + authenticate' },
    decodeLabel: { zh: '验证并解密', en: 'Verify + decrypt' },
    params: ['secret', 'iv', 'associatedData'],
  },
  {
    id: 'salsa20',
    category: 'crypto',
    name: { zh: 'Salsa20', en: 'Salsa20' },
    summary: { zh: 'Salsa20 XOR 流密码，支持 16 / 32-byte key 和 8-byte nonce，适合旧式流密码场景。', en: 'Salsa20 XOR stream cipher with 16/32-byte keys and an 8-byte nonce for legacy and stream-cipher basics.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'xsalsa20',
    category: 'crypto',
    name: { zh: 'XSalsa20', en: 'XSalsa20' },
    summary: { zh: 'XSalsa20 扩展 nonce 变体，使用 32-byte key 和 24-byte nonce，常见于 NaCl secretbox 相关数据。', en: 'XSalsa20 extended-nonce variant with a 32-byte key and 24-byte nonce, common in NaCl secretbox-related tasks.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'xsalsa20-poly1305',
    category: 'crypto',
    name: { zh: 'XSalsa20-Poly1305 / secretbox', en: 'XSalsa20-Poly1305 / secretbox' },
    summary: { zh: '兼容 NaCl / libsodium `secretbox` 的 AEAD，使用 32-byte key、24-byte nonce 和 16-byte tag。', en: 'NaCl/libsodium secretbox-compatible AEAD with a 32-byte key, 24-byte nonce, and 16-byte tag.' },
    encodeLabel: { zh: '加密并认证', en: 'Encrypt + authenticate' },
    decodeLabel: { zh: '验证并解密', en: 'Verify + decrypt' },
    params: ['secret', 'iv'],
  },
  {
    id: 'sm4',
    category: 'crypto',
    name: { zh: 'SM4', en: 'SM4' },
    summary: { zh: '国密 SM4 分组密码，支持 ECB / CBC 和 Hex 密文，适合国密协议与取证样本。', en: 'Chinese SM4 block cipher with ECB/CBC and hex ciphertext for GM/T protocol, forensic sample, and CTF crypto tasks.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['variant', 'secret', 'iv'],
  },
  {
    id: 'rc4',
    category: 'crypto',
    name: { zh: 'RC4', en: 'RC4' },
    summary: { zh: '经典流密码，适合旧协议、弱加密流量和基础流密码题。', en: 'Classic stream cipher for learning legacy protocol and weak-crypto traffic structures.' },
    params: ['secret'],
  },
  {
    id: 'rc4-drop',
    category: 'crypto',
    name: { zh: 'RC4-drop', en: 'RC4-drop' },
    summary: { zh: '丢弃前期 keystream 的 RC4 变体，适合旧协议复现和流密码检查。', en: 'RC4 variant that drops early keystream bytes for legacy protocol reproduction and CTF stream-cipher checks.' },
    params: ['secret', 'dropBytes'],
  },
  {
    id: 'tea',
    category: 'crypto',
    name: { zh: 'TEA', en: 'TEA' },
    summary: { zh: 'Tiny Encryption Algorithm，常见于逆向和混合密码题；使用 16-byte key，密文输入输出为 Hex。', en: 'Tiny Encryption Algorithm, common in reverse and mixed crypto CTFs; hex ciphertext output/input with a 16-byte key.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret'],
  },
  {
    id: 'xtea',
    category: 'crypto',
    name: { zh: 'XTEA', en: 'XTEA' },
    summary: { zh: '改进版 TEA，使用 64-bit 分组和 128-bit 密钥，常见于轻量加密与逆向题。', en: 'Improved TEA with 64-bit blocks and a 128-bit key, common in lightweight crypto and reversing challenges.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret'],
  },
  {
    id: 'xxtea',
    category: 'crypto',
    name: { zh: 'XXTEA', en: 'XXTEA' },
    summary: { zh: 'Corrected Block TEA，支持可变长度块，常见于移动端和逆向题。', en: 'Corrected Block TEA with variable-length blocks, often seen in mobile and CTF reversing tasks.' },
    encodeLabel: { zh: '加密', en: 'Encrypt' },
    decodeLabel: { zh: '解密', en: 'Decrypt' },
    params: ['secret'],
  },
  {
    id: 'vigenere',
    category: 'crypto',
    name: { zh: 'Vigenere', en: 'Vigenere' },
    summary: { zh: '经典多表替换密码，适合 CTF、密码学入门和手工分析。', en: 'Classical polyalphabetic cipher for CTFs, crypto fundamentals, and manual analysis practice.' },
    params: ['secret'],
  },
  {
    id: 'beaufort',
    category: 'crypto',
    name: { zh: 'Beaufort', en: 'Beaufort' },
    summary: { zh: '与 Vigenere 接近，但公式为 key - plaintext，编码和解码互逆。', en: 'Vigenere-like cipher using key - plaintext; encryption and decryption are reciprocal.' },
    params: ['secret'],
  },
  {
    id: 'autokey',
    category: 'crypto',
    name: { zh: 'Autokey Vigenere', en: 'Autokey Vigenere' },
    summary: { zh: '把明文追加到密钥后的 Vigenere 变体，常用来绕开普通频率分析。', en: 'Vigenere variant that appends plaintext to the key, often used to evade basic frequency checks.' },
    params: ['secret'],
  },
  {
    id: 'atbash',
    category: 'crypto',
    name: { zh: 'Atbash', en: 'Atbash' },
    summary: { zh: 'A/Z、B/Y 对称替换，编码和解码相同', en: 'Mirrors A/Z and B/Y; encoding and decoding are identical.' },
  },
  {
    id: 'bacon',
    category: 'crypto',
    name: { zh: 'Bacon 培根密码', en: 'Bacon Cipher' },
    summary: { zh: '五位 A / B 分组古典密码，也支持 a/b 或 0/1 风格输入。', en: 'Five-symbol A/B classical cipher with a/b or 0/1 style input.' },
    params: ['separator'],
  },
  {
    id: 'polybius',
    category: 'crypto',
    name: { zh: 'Polybius 方阵', en: 'Polybius Square' },
    summary: { zh: '5x5 坐标方阵，I/J 合并，常见为 11 12 13 形式', en: '5x5 coordinate square with I/J merged, often seen as 11 12 13 pairs.' },
    params: ['separator'],
  },
  {
    id: 'tap-code',
    category: 'crypto',
    name: { zh: 'Tap Code 敲击', en: 'Tap Code' },
    summary: { zh: 'Polybius 风格敲击分组，支持数字坐标或点号坐标输入。', en: 'Polybius-style tap groups with numeric or dotted coordinate input.' },
    params: ['separator'],
  },
  {
    id: 'playfair',
    category: 'crypto',
    name: { zh: 'Playfair 双字', en: 'Playfair Cipher' },
    summary: { zh: '5x5 密钥方阵双字母替换，I/J 合并，并自动处理重复字母填充。', en: '5x5 keyed digraph substitution with I/J merged and automatic repeated-letter padding.' },
    params: ['secret'],
  },
  {
    id: 'hill2',
    category: 'crypto',
    name: { zh: 'Hill 2x2', en: 'Hill 2x2' },
    summary: { zh: '2x2 矩阵 Hill 密码，密钥支持 4 个数字或 4 个字母。', en: '2x2 matrix Hill cipher; key accepts four numbers or four letters.' },
    params: ['secret'],
  },
  {
    id: 'substitution',
    category: 'crypto',
    name: { zh: '单表替换', en: 'Monoalphabetic Substitution' },
    summary: { zh: '按 26 字母替换表做单表替换，适合验证频率分析结果。', en: 'Applies a 26-letter substitution alphabet for checking frequency-analysis results.' },
    params: ['secret'],
  },
  {
    id: 'affine',
    category: 'crypto',
    name: { zh: 'Affine 仿射密码', en: 'Affine Cipher' },
    summary: { zh: '仿射密码 E(x)=(a*x+b) mod 26，适合古典密码枚举和手工检查。', en: 'E(x)=(a*x+b) mod 26 for classical-cipher enumeration and manual checks.' },
    params: ['affineA', 'affineB'],
  },
  {
    id: 'rail-fence',
    category: 'crypto',
    name: { zh: 'Rail Fence 栅栏', en: 'Rail Fence' },
    summary: { zh: '按轨道数做栅栏换位，支持常见 rail fence 编码/解码', en: 'Rail-fence transposition by rail count with encode/decode support.' },
    params: ['rails'],
  },
  {
    id: 'scytale',
    category: 'crypto',
    name: { zh: 'Scytale 换位', en: 'Scytale' },
    summary: { zh: '按列数进行古典换位，适合 rail / columnar 类变体。', en: 'Classical transposition by column count for rail and columnar variants.' },
    params: ['rails'],
  },
  {
    id: 'columnar',
    category: 'crypto',
    name: { zh: 'Columnar 列换', en: 'Columnar Transposition' },
    summary: { zh: '按关键词排序列的换位密码，适合古典换位题检查。', en: 'Keyword-ordered column transposition for CTF classical transposition checks.' },
    params: ['secret'],
  },
  {
    id: 'porta',
    category: 'crypto',
    name: { zh: 'Porta 密码', en: 'Porta Cipher' },
    summary: { zh: '互逆型多表替换的 Porta 密码，适合 Vigenere 变体题检查。', en: 'Reciprocal polyalphabetic Porta cipher for Vigenere-variant checks.' },
    params: ['secret'],
  },
  {
    id: 'gronsfeld',
    category: 'crypto',
    name: { zh: 'Gronsfeld 密码', en: 'Gronsfeld Cipher' },
    summary: { zh: '数字密钥版 Vigenere，常由 PIN、序列号等提示触发。', en: 'Numeric-key Vigenere variant often hinted by PINs or serials.' },
    params: ['secret'],
  },
  {
    id: 'bifid',
    category: 'crypto',
    name: { zh: 'Bifid 双分密码', en: 'Bifid Cipher' },
    summary: { zh: 'Polybius 坐标分组再重排的古典密码，支持 period 参数。', en: 'Polybius coordinate fractionation cipher with configurable period.' },
    params: ['secret', 'period'],
  },
  {
    id: 'trifid',
    category: 'crypto',
    name: { zh: 'Trifid 三分密码', en: 'Trifid Cipher' },
    summary: { zh: '3x3x3 分组坐标密码，适合 27 字符方阵或立方体类古典谜题。', en: '3x3x3 fractionation cipher for 27-symbol classical puzzle grids.' },
    params: ['secret', 'period'],
  },
  {
    id: 'four-square',
    category: 'crypto',
    name: { zh: 'Four-Square 密码', en: 'Four-Square Cipher' },
    summary: { zh: '四方格双字母替换，需要两个关键词方阵', en: 'Digraph substitution using two keyed Polybius squares.' },
    params: ['secret', 'keyword2'],
  },
  {
    id: 'nihilist',
    category: 'crypto',
    name: { zh: 'Nihilist 密码', en: 'Nihilist Cipher' },
    summary: { zh: 'Polybius 数值与关键词数值相加，常见输出为数字组', en: 'Adds Polybius plaintext and keyword numbers, commonly emitted as numeric groups.' },
    params: ['secret', 'separator'],
  },
  {
    id: 'adfgx',
    category: 'crypto',
    name: { zh: 'ADFGX', en: 'ADFGX' },
    summary: { zh: 'Polybius 替换加列换位，一战时期密码，字符集为 ADFGX', en: 'WWI substitution plus columnar transposition using the ADFGX alphabet.' },
    params: ['secret', 'keyword2'],
  },
  {
    id: 'adfgvx',
    category: 'crypto',
    name: { zh: 'ADFGVX', en: 'ADFGVX' },
    summary: { zh: 'ADFGX 的 6x6 变体，同时支持字母和数字。', en: '6x6 ADFGX variant supporting letters and digits.' },
    params: ['secret', 'keyword2'],
  },
  {
    id: 'xor',
    category: 'crypto',
    name: { zh: 'XOR', en: 'XOR' },
    summary: { zh: '文本与密钥异或，编码输出 hex，解码从 hex 还原', en: 'XORs text with a key; encoding outputs hex and decoding restores text from hex.' },
    params: ['secret'],
  },
  {
    id: 'xor-bruteforce',
    category: 'crypto',
    name: { zh: '单字节 XOR 爆破', en: 'Single-byte XOR Brute Force' },
    summary: { zh: '对 Hex 密文尝试 0x00-0xff，并按可读性和 flag 特征给候选排序。', en: 'Tries 0x00-0xff over hex ciphertext and ranks candidates by readability/flag scoring.' },
    supportsEncode: false,
    decodeLabel: { zh: 'Brute force', en: 'Brute force' },
  },
  {
    id: 'xor-known-plaintext',
    category: 'crypto',
    name: { zh: 'XOR 已知明文求密', en: 'XOR Known Plaintext' },
    summary: { zh: '从 Hex 密文和已知明文片段中推导 keystream / key 片段，适合 flag{、PNG、ZIP 头。', en: 'Derives keystream/key fragments from hex ciphertext and known plaintext such as flag{, PNG, or ZIP headers.' },
    supportsEncode: false,
    decodeLabel: { zh: '推导密钥', en: 'Derive key' },
    params: ['knownPlaintext'],
  },
  {
    id: 'magic-xor-helper',
    category: 'crypto',
    name: { zh: '文件头 XOR 推钥', en: 'Magic-header XOR Helper' },
    summary: { zh: '从 Hex 密文与常见文件头签名中推导重复 XOR key 前缀。', en: 'Derives repeating XOR key prefixes from hex ciphertext and common file signatures.' },
    supportsEncode: false,
    decodeLabel: { zh: 'Derive candidates', en: 'Derive candidates' },
    params: ['knownPlaintext'],
  },
  {
    id: 'rot',
    category: 'crypto',
    name: { zh: 'ROT / Caesar', en: 'ROT / Caesar' },
    summary: { zh: '支持 ROT13、Caesar 位移和 ROT47。', en: 'Supports ROT13, Caesar shifts, and ROT47.' },
    params: ['variant', 'shift'],
  },
  {
    id: 'rot-bruteforce',
    category: 'crypto',
    name: { zh: 'ROT / Caesar 全枚', en: 'ROT / Caesar Brute Force' },
    summary: { zh: '一次列出 ROT1-25 和 ROT47，适合快速扫 Caesar 变体。', en: 'Lists ROT1-25 and ROT47 at once for quick Caesar-variant triage.' },
    supportsEncode: false,
    decodeLabel: { zh: '全枚', en: 'Enumerate' },
  },
  {
    id: 'rot8000',
    category: 'crypto',
    name: { zh: 'ROT8000', en: 'ROT8000' },
    summary: { zh: '对 BMP 字符做 0x8000 位移，适合高位 Unicode 混淆场景。', en: 'Applies a 0x8000 Unicode ROT over BMP characters for high-plane Unicode obfuscation in CTFs.' },
  },
  {
    id: 'enigma',
    category: 'crypto',
    name: { zh: 'Enigma I 转子', en: 'Enigma I Rotor Machine' },
    summary: { zh: '三转子 Enigma I 模拟器，支持 rotor、reflector、ring、position 和 plugboard 等完整设置。', en: 'Three-rotor Enigma I simulator with rotor, reflector, ring, position, and plugboard settings.' },
    encodeLabel: { zh: 'Enigma 变换', en: 'Enigma transform' },
    decodeLabel: { zh: 'Enigma 变换', en: 'Enigma transform' },
    params: ['secret'],
  },
  {
    id: 'rsa-raw',
    category: 'crypto',
    name: { zh: 'RSA Raw / Textbook', en: 'RSA Raw / Textbook' },
    summary: { zh: '基于 BigInt 的 textbook RSA 加解密；支持 n/e/d/p/q/phi/c/m，适合小明文、已分解 n 和无填充题。', en: 'Textbook RSA BigInt encrypt/decrypt from n/e/d/p/q/phi/c/m for CTF small-message, factored-n, and no-padding RSA tasks.' },
    encodeLabel: { zh: 'Encrypt m', en: 'Encrypt m' },
    decodeLabel: { zh: 'Decrypt c', en: 'Decrypt c' },
  },
  {
    id: 'rabin-raw',
    category: 'crypto',
    name: { zh: 'Rabin Raw', en: 'Rabin Raw' },
    summary: { zh: '基于 BigInt 的 Rabin 原始加解密；支持 n/p/q/c/m，解密时给出 CRT 合成后的 4 个候选明文。', en: 'BigInt Rabin raw encrypt/decrypt from n/p/q/c/m, returning up to four CRT plaintext candidates on decrypt.' },
    encodeLabel: { zh: 'Encrypt m^2', en: 'Encrypt m^2' },
    decodeLabel: { zh: 'Decrypt c', en: 'Decrypt c' },
  },
  {
    id: 'rsa-helper',
    category: 'crypto',
    name: { zh: 'RSA CTF 辅助', en: 'RSA CTF Helper' },
    summary: { zh: '解析 n/e/c/p/q/phi 风格参数，并给出 RsaCtfTool、Sage 和 Python 命令模板。', en: 'Parses n/e/c/p/q/phi-style parameters and emits RsaCtfTool, Sage, and Python command templates.' },
    supportsEncode: false,
    decodeLabel: { zh: '生成辅助命令', en: 'Build helpers' },
  },
  {
    id: 'signature-nonce-helper',
    category: 'crypto',
    name: { zh: '签名重复 nonce', en: 'Signature Nonce Reuse' },
    summary: { zh: '解析 ECDSA / DSA / Schnorr 的 r/s/z、DER 签名或 JOSE token，检测重复 nonce 并恢复 k 与私钥。', en: 'Parses ECDSA/DSA/Schnorr r/s/z values, DER signatures, or JOSE tokens, detects nonce reuse, and recovers k plus the private key.' },
    supportsEncode: false,
    decodeLabel: { zh: '分析签名', en: 'Analyze signatures' },
  },
  {
    id: 'discrete-log-helper',
    category: 'crypto',
    name: { zh: '离散对数 / ElGamal', en: 'Discrete Log / ElGamal' },
    summary: { zh: '解析 p/g/h/q 与可选 c1/c2，优先用 BSGS 和平滑阶 Pohlig-Hellman 恢复指数，并可顺带解 ElGamal。', en: 'Parses p/g/h/q with optional c1/c2, prefers BSGS and smooth-order Pohlig-Hellman to recover exponents, and can also decrypt ElGamal ciphertexts.' },
    supportsEncode: false,
    decodeLabel: { zh: '分析 DLP', en: 'Analyze DLP' },
  },
  {
    id: 'mt19937-helper',
    category: 'crypto',
    name: { zh: 'MT19937 状态恢复', en: 'MT19937 State Helper' },
    summary: { zh: '解析连续 32-bit 输出，判断能否克隆 Mersenne Twister 状态并预测后续值。', en: 'Parses consecutive 32-bit outputs to determine whether Mersenne Twister state cloning and next-value prediction are possible.' },
    supportsEncode: false,
    decodeLabel: { zh: '分析 MT19937', en: 'Analyze MT19937' },
  },
  {
    id: 'lcg-helper',
    category: 'crypto',
    name: { zh: 'LCG 参数恢复', en: 'LCG Parameter Helper' },
    summary: { zh: '根据连续输出和可选 modulus 推断或排查 LCG 的 a/c/m 参数。', en: 'Recovers or triages LCG a/c/m from consecutive outputs and optional modulus.' },
    supportsEncode: false,
    decodeLabel: { zh: '分析 LCG', en: 'Analyze LCG' },
    params: ['secret'],
  },
  {
    id: 'lfsr-helper',
    category: 'crypto',
    name: { zh: 'LFSR / Berlekamp-Massey', en: 'LFSR / Berlekamp-Massey' },
    summary: { zh: '对 bit keystream 运行 Berlekamp-Massey，估计线性复杂度并恢复反馈多项式。', en: 'Runs Berlekamp-Massey on bit keystreams to estimate linear complexity and feedback polynomial.' },
    supportsEncode: false,
    decodeLabel: { zh: '恢复 LFSR', en: 'Recover LFSR' },
  },
  {
    id: 'hash-length-extension-helper',
    category: 'crypto',
    name: { zh: 'Hash 长度扩展辅助', en: 'Hash Length-extension Helper' },
    summary: { zh: '识别 MD5/SHA1/SHA256 secret-prefix MAC 风险，并生成本地实验模板', en: 'Identifies MD5/SHA1/SHA256 secret-prefix MAC risk and builds local lab templates.' },
    supportsEncode: false,
    decodeLabel: { zh: '生成模板', en: 'Build template' },
    params: ['hashAlgorithm', 'secret', 'knownPlaintext'],
  },
  {
    id: 'crypto-attack-helper',
    category: 'crypto',
    name: { zh: 'CTF 密码攻击速查', en: 'CTF Crypto Attack Helper' },
    summary: { zh: '按题目材料生成 RSA、ECC、LCG、LFSR、LLL、长度扩展和 oracle 路径的工具链提示。', en: 'Builds toolchain hints for heavyweight RSA, ECC, LCG, LFSR, LLL, hash-extension, and oracle attacks.' },
    supportsEncode: false,
    decodeLabel: { zh: '生成速查', en: 'Build checklist' },
  },
  {
    id: 'frequency-analysis',
    category: 'crypto',
    name: { zh: '字母频率分析', en: 'Frequency Analysis' },
    summary: { zh: '统计字母、字符和 n-gram 频率，用于单表替换、Caesar、Vigenere 前置分析', en: 'Counts letters, characters, and n-grams for substitution, Caesar, and Vigenere triage.' },
    supportsEncode: false,
    decodeLabel: { zh: '分析频率', en: 'Analyze' },
  },
  {
    id: 'brainfuck',
    category: 'text',
    name: { zh: 'Brainfuck 运行/编码', en: 'Brainfuck Run / Encode' },
    summary: { zh: '运行 Brainfuck 程序，或把文本生成为简单的 Brainfuck 输出程序。', en: 'Runs Brainfuck programs or emits simple Brainfuck text-output programs for CTF misc puzzles.' },
    encodeLabel: { zh: '生成 BF', en: 'Generate BF' },
    decodeLabel: { zh: '运行 BF', en: 'Run BF' },
    params: ['secret', 'iterations'],
  },
  {
    id: 'ook',
    category: 'text',
    name: { zh: 'Ook! / Brainfuck', en: 'Ook! / Brainfuck' },
    summary: { zh: '在 Brainfuck 指令与 Ook! token 之间互转，适合 esolang 题目。', en: 'Converts Brainfuck instructions to and from Ook! tokens for esolang CTF misc puzzles.' },
    encodeLabel: { zh: 'BF to Ook!', en: 'BF to Ook!' },
    decodeLabel: { zh: 'Ook! to BF', en: 'Ook! to BF' },
  },
  {
    id: 'jsfuck-helper',
    category: 'text',
    name: { zh: 'JSFuck 安全分析', en: 'JSFuck Safe Inspector' },
    summary: { zh: '安全检查 JSFuck / 纯符号 JavaScript 混淆，提取可见字符串和转义片段而不执行可疑代码。', en: 'Inspects JSFuck/symbol-only JavaScript obfuscation, extracting visible strings and escapes without executing suspicious code.' },
    supportsEncode: false,
    decodeLabel: { zh: '安全分析', en: 'Inspect safely' },
  },
  {
    id: 'jwt',
    category: 'token',
    name: { zh: 'JWT 解析', en: 'JWT Parser' },
    summary: { zh: '解析 JWT 的 Header、Payload 和 Signature，并标出 `exp` / `iat` / `nbf` 时间字段。', en: 'Parses JWT header, payload, signature, and exp/iat/nbf timestamps.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 JWT', en: 'Parse JWT' },
  },
  {
    id: 'jwt-hmac',
    category: 'token',
    name: { zh: 'JWT HMAC 签名/验签', en: 'JWT HMAC Sign / Verify' },
    summary: { zh: '本地生成或校验 HS256 / HS384 / HS512 JWT，适合 token 题和课堂演示。', en: 'Creates or verifies HS256/HS384/HS512 JWTs locally for CTF token challenges and classroom demos.' },
    encodeLabel: { zh: '签名 JWT', en: 'Sign JWT' },
    decodeLabel: { zh: '验签 JWT', en: 'Verify JWT' },
    params: ['hashAlgorithm', 'secret'],
  },
  {
    id: 'jwt-public',
    category: 'token',
    name: { zh: 'JWT/JWS 公钥验签', en: 'JWT/JWS Public Verify' },
    summary: { zh: '使用 PEM、公钥证书、JWK 或 JWKS 验签 `RS256`、`PS256`、`ES256`、`EdDSA` 等 JWT / JWS。', en: 'Verifies RS256, PS256, ES256, EdDSA, and similar JWT/JWS signatures using PEM, certificates, JWK, or JWKS for CTF token challenges.' },
    supportsEncode: false,
    decodeLabel: { zh: '公钥验签', en: 'Verify with public key' },
    params: ['secret'],
  },
  {
    id: 'fernet',
    category: 'token',
    name: { zh: 'Fernet Token', en: 'Fernet Token' },
    summary: { zh: '解析和生成 Python cryptography Fernet token，包含时间戳、AES-128-CBC、HMAC-SHA256 校验与解密。', en: 'Parses and creates Python cryptography Fernet tokens with timestamp, AES-128-CBC, HMAC-SHA256 verification, and decryption.' },
    encodeLabel: { zh: '生成 token', en: 'Create token' },
    decodeLabel: { zh: '解析/解密', en: 'Parse / Decrypt' },
    params: ['secret'],
  },
  {
    id: 'hotp',
    category: 'token',
    name: { zh: 'HOTP', en: 'HOTP' },
    summary: { zh: '基于 Base32 secret、counter 和 HMAC 算法生成 HOTP，一次性验证码题里很常见。', en: 'Generates HOTP codes from a Base32 secret, counter, and HMAC algorithm for common OTP CTF challenges.' },
    encodeLabel: { zh: '生成 HOTP', en: 'Generate HOTP' },
    supportsDecode: false,
    params: ['secret', 'hashAlgorithm', 'digits', 'counter'],
  },
  {
    id: 'totp',
    category: 'token',
    name: { zh: 'TOTP', en: 'TOTP' },
    summary: { zh: '基于 Base32 secret、时间步长和时间戳生成 TOTP，适合 MFA / Authenticator 类题目。', en: 'Generates TOTP codes from a Base32 secret, time step, and timestamp for Google Authenticator or MFA-style challenges.' },
    encodeLabel: { zh: '生成 TOTP', en: 'Generate TOTP' },
    supportsDecode: false,
    params: ['secret', 'hashAlgorithm', 'digits', 'timeStep', 'otpTimestamp'],
  },
  {
    id: 'otpauth-uri',
    category: 'token',
    name: { zh: 'otpauth URI', en: 'otpauth URI' },
    summary: { zh: '解析或生成 otpauth:// URI，并用其中参数复算 HOTP / TOTP 验证码。', en: 'Parses or creates otpauth:// URIs and recalculates HOTP/TOTP codes from the embedded parameters.' },
    encodeLabel: { zh: '生成 URI', en: 'Create URI' },
    decodeLabel: { zh: '解析 URI', en: 'Parse URI' },
    params: ['variant', 'secret', 'hashAlgorithm', 'digits', 'timeStep', 'counter'],
  },
  {
    id: 'querystring',
    category: 'token',
    name: { zh: 'QueryString', en: 'QueryString' },
    summary: { zh: '在 URL 查询串与 JSON 对象之间互转，适合调试请求参数。', en: 'Converts URL query strings to and from JSON objects.' },
  },
  {
    id: 'basic-auth',
    category: 'token',
    name: { zh: 'Basic Auth', en: 'Basic Auth' },
    summary: { zh: '在 `username:password` 与 HTTP Basic `Authorization` 头之间互转。', en: 'Converts username:password to and from HTTP Basic Authorization headers.' },
  },
  {
    id: 'punycode',
    category: 'token',
    name: { zh: 'Punycode / IDN', en: 'Punycode / IDN' },
    summary: { zh: '在 Unicode 域名与 xn-- Punycode 标签之间互转。', en: 'Converts Unicode hostnames to and from xn-- Punycode labels.' },
  },
  {
    id: 'pem-block',
    category: 'token',
    name: { zh: 'PEM 封装', en: 'PEM Block' },
    summary: { zh: '在原始 Base64 材料与 PEM 头尾块之间互转，适合证书、公钥和私钥片段整理。', en: 'Converts between raw Base64 material and PEM header/footer blocks for certs and keys.' },
    params: ['blockLabel'],
  },
  {
    id: 'asn1-der',
    category: 'token',
    name: { zh: 'ASN.1 DER/BER 树', en: 'ASN.1 DER/BER Tree' },
    summary: { zh: '把 PEM、Base64 或 Hex 形式的 DER/BER 数据解析成 TLV 树，适合证书、公钥和签名结构分析。', en: 'Parses DER/BER data from PEM, Base64, or Hex into a TLV tree for certificates, public keys, signatures, and crypto containers.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 ASN.1', en: 'Parse ASN.1' },
  },
  {
    id: 'jwk-jwe',
    category: 'token',
    name: { zh: 'JWK / JWE 解析', en: 'JWK / JWE Parser' },
    summary: { zh: '解析 JWK、JWKS 和 compact JWE 结构，展开 Base64URL 字段、密钥尺寸和 protected header。', en: 'Parses JWK, JWKS, and compact JWE structures, expanding Base64URL fields, key sizes, and protected headers.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 JOSE', en: 'Parse JOSE' },
  },
  {
    id: 'ssh-public-key',
    category: 'token',
    name: { zh: 'OpenSSH 公钥解析', en: 'OpenSSH Public Key Parser' },
    summary: { zh: '解析 ssh-rsa、ssh-ed25519、ecdsa-* 等 OpenSSH 公钥 blob，输出字段、位数和 SHA256 指纹。', en: 'Parses ssh-rsa, ssh-ed25519, ecdsa-* and related OpenSSH public key blobs with fields, sizes, and SHA256 fingerprint.' },
    supportsEncode: false,
    decodeLabel: { zh: '解析 SSH Key', en: 'Parse SSH key' },
  },
  {
    id: 'gzip',
    category: 'compress',
    name: { zh: 'GZip', en: 'GZip' },
    summary: { zh: '把文本压缩成 Base64 GZip，或把 Base64 GZip 解压成文本。', en: 'Compresses text to Base64 GZip or decompresses Base64 GZip.' },
    encodeLabel: { zh: '压缩', en: 'Compress' },
    decodeLabel: { zh: '解压', en: 'Decompress' },
  },
  {
    id: 'deflate',
    category: 'compress',
    name: { zh: 'Deflate', en: 'Deflate' },
    summary: { zh: '把文本压缩成 Base64 Deflate，或把 Base64 Deflate 解压成文本。', en: 'Compresses text to Base64 Deflate or decompresses Base64 Deflate.' },
    encodeLabel: { zh: '压缩', en: 'Compress' },
    decodeLabel: { zh: '解压', en: 'Decompress' },
  },
  {
    id: 'data-url',
    category: 'compress',
    name: { zh: 'Data URL', en: 'Data URL' },
    summary: { zh: '在文本与 data:mime;base64,... 封装之间互转。', en: 'Converts text to and from data:mime;base64,... wrappers.' },
    params: ['mimeType'],
  },
];

const defaultParams: Record<ParamKey, string> = {
  variant: 'special',
  hashAlgorithm: 'sha256',
  secret: '',
  iv: '',
  keyword2: '',
  associatedData: '',
  hrp: 'bc',
  versionHex: '00',
  digits: '6',
  counter: '0',
  timeStep: '30',
  otpTimestamp: '',
  period: '5',
  iterations: '120000',
  shift: '13',
  separator: 'space',
  mimeType: 'text/plain;charset=utf-8',
  blockLabel: 'PUBLIC KEY',
  affineA: '5',
  affineB: '8',
  rails: '3',
  knownPlaintext: 'flag{',
  dropBytes: '768',
};

const otpOperationIds = new Set<OperationId>(['hotp', 'totp', 'otpauth-uri']);
const otpHashAlgorithms = new Set(['sha1', 'sha256', 'sha512']);
const jwtHmacHashAlgorithms = new Set(['sha256', 'sha384', 'sha512']);
const isOtpOperation = (operationId: OperationId) => otpOperationIds.has(operationId);
const cryptoJsCipherOperationIds = new Set<OperationId>(['des', 'triple-des', 'blowfish', 'rabbit']);
const cryptoJsBlockCipherOperationIds = new Set<OperationId>(['des', 'triple-des', 'blowfish']);
const isCryptoJsCipherOperation = (operationId: OperationId) => cryptoJsCipherOperationIds.has(operationId);
const nobleStreamCipherOperationIds = new Set<OperationId>(['chacha20-orig', 'chacha20', 'xchacha20', 'salsa20', 'xsalsa20']);
const isNobleStreamCipherOperation = (operationId: OperationId) => nobleStreamCipherOperationIds.has(operationId);
const nobleAeadOperationIds = new Set<OperationId>(['aes-gcm-siv', 'aes-siv', 'chacha20-poly1305', 'xchacha20-poly1305', 'xsalsa20-poly1305']);
const isNobleAeadOperation = (operationId: OperationId) => nobleAeadOperationIds.has(operationId);
const isNobleNonceOperation = (operationId: OperationId) => isNobleStreamCipherOperation(operationId) || isNobleAeadOperation(operationId);
const nobleAesOperationIds = new Set<OperationId>(['aes-cbc-raw', 'aes-ctr-raw', 'aes-ofb', 'aes-ecb', 'aes-cfb', 'aes-kw', 'aes-kwp', 'aes-cmac']);
const isNobleAesOperation = (operationId: OperationId) => nobleAesOperationIds.has(operationId);

const morseMap: Record<string, string> = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---',
  K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-',
  U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
  0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
  '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
  '$': '...-..-', '@': '.--.-.',
};

const reverseMorseMap = Object.fromEntries(Object.entries(morseMap).map(([key, value]) => [value, key]));
const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();
const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const base32HexAlphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
const crockfordBase32Alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const base45Alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const base62Alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const base91Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const polybiusAlphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
const tapCodeAlphabet = 'ABCDEFGHIJLMNOPQRSTUVWXYZ';
const keyboardRows = ['`1234567890-=', 'qwertyuiop[]\\', "asdfghjkl;'", 'zxcvbnm,./'];
const natoWords: Record<string, string> = {
  A: 'Alpha', B: 'Bravo', C: 'Charlie', D: 'Delta', E: 'Echo', F: 'Foxtrot', G: 'Golf', H: 'Hotel', I: 'India',
  J: 'Juliett', K: 'Kilo', L: 'Lima', M: 'Mike', N: 'November', O: 'Oscar', P: 'Papa', Q: 'Quebec', R: 'Romeo',
  S: 'Sierra', T: 'Tango', U: 'Uniform', V: 'Victor', W: 'Whiskey', X: 'Xray', Y: 'Yankee', Z: 'Zulu',
  0: 'Zero', 1: 'One', 2: 'Two', 3: 'Three', 4: 'Four', 5: 'Five', 6: 'Six', 7: 'Seven', 8: 'Eight', 9: 'Nine',
};
const reverseNatoWords = Object.fromEntries(Object.entries(natoWords).flatMap(([key, value]) => [[value.toLowerCase(), key], [value.replace('-', '').toLowerCase(), key]]));
reverseNatoWords.alfa = 'A';
reverseNatoWords['x-ray'] = 'X';
const baudotLetters: Record<string, string> = {
  A: '00011', B: '11001', C: '01110', D: '01001', E: '00001', F: '01101', G: '11010', H: '10100', I: '00110',
  J: '01011', K: '01111', L: '10010', M: '11100', N: '01100', O: '11000', P: '10110', Q: '10111', R: '01010',
  S: '00101', T: '10000', U: '00111', V: '11110', W: '10011', X: '11101', Y: '10101', Z: '10001',
  '\n': '00010', '\r': '01000', ' ': '00100',
};
const baudotFigures: Record<string, string> = {
  '-': '00011', '?': '11001', ':': '01110', '$': '01001', '3': '00001', '!': '01101', '&': '11010', '#': '10100',
  '8': '00110', "'": '01011', '(': '01111', ')': '10010', '.': '11100', ',': '01100', '9': '11000', '0': '10110',
  '1': '10111', '4': '01010', '\u0007': '00101', '5': '10000', '7': '00111', ';': '11110', '2': '10011', '/': '11101',
  '6': '10101', '"': '10001', '\n': '00010', '\r': '01000', ' ': '00100',
};
const baudotLettersShift = '11111';
const baudotFiguresShift = '11011';
const reverseBaudotLetters = Object.fromEntries(Object.entries(baudotLetters).map(([key, value]) => [value, key]));
const reverseBaudotFigures = Object.fromEntries(Object.entries(baudotFigures).map(([key, value]) => [value, key]));
const dnaMaps: Record<string, Record<string, string>> = {
  special: { '00': 'A', '01': 'C', '10': 'G', '11': 'T' },
  decimal: { '00': 'A', '01': 'G', '10': 'C', '11': 'T' },
  hex:     { '00': 'C', '01': 'A', '10': 'T', '11': 'G' },
  rule1:   { '00': 'A', '01': 'C', '10': 'G', '11': 'T' },
  rule2:   { '00': 'A', '01': 'C', '10': 'T', '11': 'G' },
  rule3:   { '00': 'A', '01': 'G', '10': 'C', '11': 'T' },
  rule4:   { '00': 'A', '01': 'G', '10': 'T', '11': 'C' },
  rule5:   { '00': 'A', '01': 'T', '10': 'C', '11': 'G' },
  rule6:   { '00': 'A', '01': 'T', '10': 'G', '11': 'C' },
  rule7:   { '00': 'C', '01': 'G', '10': 'A', '11': 'T' },
  rule8:   { '00': 'T', '01': 'A', '10': 'G', '11': 'C' },
};
const reverseDnaMaps = Object.fromEntries(Object.entries(dnaMaps).map(([key, value]) => [key, Object.fromEntries(Object.entries(value).map(([bits, base]) => [base, bits]))])) as Record<string, Record<string, string>>;
const zeroWidthZero = '\u200b';
const zeroWidthOne = '\u200c';
const bubbleBabbleVowels = 'aeiouy';
const bubbleBabbleConsonants = 'bcdfghklmnprstvzx';
const utf7DirectChars = new Set(Array.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'(),-./:? \t\r\n"));
const gsm7DefaultAlphabet = [
  '@', '£', '$', '¥', 'è', 'é', 'ù', 'ì', 'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å',
  'Δ', '_', 'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ', 'Σ', 'Θ', 'Ξ', '\u001b', 'Æ', 'æ', 'ß', 'É',
  ' ', '!', '"', '#', '¤', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
  '¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§',
  '¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
  'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
];
const gsm7ReverseAlphabet = new Map(gsm7DefaultAlphabet.map((char, index) => [char, index]));
const gsm7ExtensionAlphabet: Record<string, number> = {
  '\f': 0x0a,
  '^': 0x14,
  '{': 0x28,
  '}': 0x29,
  '\\': 0x2f,
  '[': 0x3c,
  '~': 0x3d,
  ']': 0x3e,
  '|': 0x40,
  '€': 0x65,
};
const reverseGsm7ExtensionAlphabet = Object.fromEntries(Object.entries(gsm7ExtensionAlphabet).map(([char, code]) => [code, char])) as Record<number, string>;
const brainfuckToOok: Record<string, string> = {
  '>': 'Ook. Ook?',
  '<': 'Ook? Ook.',
  '+': 'Ook. Ook.',
  '-': 'Ook! Ook!',
  '.': 'Ook! Ook.',
  ',': 'Ook. Ook!',
  '[': 'Ook! Ook?',
  ']': 'Ook? Ook!',
};
const ookToBrainfuck = Object.fromEntries(Object.entries(brainfuckToOok).map(([key, value]) => [value, key]));
const crc32Table = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
const crc16Table = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? (value >>> 1) ^ 0xa001 : value >>> 1;
  return value & 0xffff;
});

const label = (value: { zh: string; en: string }, language: 'zh' | 'en') => value[language] || value.zh;
const bytesToHex = (bytes: Uint8Array) => Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
const bytesToBuffer = (bytes: Uint8Array) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
const hexToBytes = (value: string) => {
  const clean = value.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  if (!clean) return new Uint8Array();
  if (clean.length % 2 !== 0) throw new Error('Hex 长度必须是偶数');
  return new Uint8Array(clean.match(/.{2}/g)?.map(byte => Number.parseInt(byte, 16)) || []);
};

const bytesToBase64 = (bytes: Uint8Array) => {
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.slice(index, index + 0x8000));
  }
  return btoa(binary);
};

const base64ToBase64Url = (value: string) => value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

const base64ToBytes = (value: string) => {
  const normalized = value.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
};

const textToBase64 = (value: string) => bytesToBase64(utf8Encoder.encode(value));
const base64ToText = (value: string) => utf8Decoder.decode(base64ToBytes(value));
const toBase64Url = (value: string) => textToBase64(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

const fromBase64Url = (value: string) => base64ToText(value);

const getBase32Alphabet = (variant: string) => {
  if (variant === 'hex') return base32HexAlphabet;
  if (variant === 'decimal') return crockfordBase32Alphabet;
  return base32Alphabet;
};

const normalizeBase32Input = (value: string, variant: string) => {
  const clean = value.toUpperCase().replace(/\s+/g, '').replace(/=+$/g, '');
  if (variant !== 'decimal') return clean;
  return clean.replace(/-/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
};

const encodeBase32 = (value: string, variant = 'special') => {
  const selectedAlphabet = getBase32Alphabet(variant);
  const bytes = utf8Encoder.encode(value);
  let bits = 0;
  let bitLength = 0;
  let output = '';
  for (const byte of bytes) {
    bits = (bits << 8) | byte;
    bitLength += 8;
    while (bitLength >= 5) {
      output += selectedAlphabet[(bits >>> (bitLength - 5)) & 31];
      bitLength -= 5;
    }
  }
  if (bitLength > 0) output += selectedAlphabet[(bits << (5 - bitLength)) & 31];
  return variant === 'decimal' ? output : output.padEnd(Math.ceil(output.length / 8) * 8, '=');
};

const decodeBase32Bytes = (value: string, variant = 'special') => {
  const selectedAlphabet = getBase32Alphabet(variant);
  const clean = normalizeBase32Input(value, variant);
  let bits = 0;
  let bitLength = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const index = selectedAlphabet.indexOf(char);
    if (index < 0) throw new Error(`Base32 非法字符: ${char}`);
    bits = (bits << 5) | index;
    bitLength += 5;
    if (bitLength >= 8) {
      bytes.push((bits >>> (bitLength - 8)) & 255);
      bitLength -= 8;
    }
  }
  return new Uint8Array(bytes);
};

const decodeBase32 = (value: string, variant = 'special') => utf8Decoder.decode(decodeBase32Bytes(value, variant));

const encodeBase45 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let output = '';
  for (let index = 0; index < bytes.length; index += 2) {
    if (index + 1 < bytes.length) {
      let number = bytes[index] * 256 + bytes[index + 1];
      output += base45Alphabet[number % 45];
      number = Math.floor(number / 45);
      output += base45Alphabet[number % 45];
      number = Math.floor(number / 45);
      output += base45Alphabet[number % 45];
    } else {
      let number = bytes[index];
      output += base45Alphabet[number % 45];
      number = Math.floor(number / 45);
      output += base45Alphabet[number % 45];
    }
  }
  return output;
};

const decodeBase45 = (value: string) => {
  const clean = value.trim().replace(/\s+/g, '');
  if (!clean) return '';
  const bytes: number[] = [];
  for (let index = 0; index < clean.length;) {
    const c1 = base45Alphabet.indexOf(clean[index]);
    const c2 = base45Alphabet.indexOf(clean[index + 1]);
    if (c1 < 0 || c2 < 0) throw new Error('Base45 包含非法字符');
    if (index + 2 < clean.length) {
      const c3 = base45Alphabet.indexOf(clean[index + 2]);
      if (c3 < 0) throw new Error('Base45 包含非法字符');
      const number = c1 + c2 * 45 + c3 * 2025;
      if (number > 0xffff) throw new Error('Base45 数据块超出范');
      bytes.push(Math.floor(number / 256), number % 256);
      index += 3;
    } else {
      const number = c1 + c2 * 45;
      if (number > 0xff) throw new Error('Base45 单字节数据块超出范围');
      bytes.push(number);
      index += 2;
    }
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const bytesFromTextOrHex = (value: string) => {
  const clean = value.trim().replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[\s,;:_-]/g, '');
  if (clean && clean.length % 2 === 0 && /^[0-9a-f]+$/i.test(clean)) return hexToBytes(clean);
  return utf8Encoder.encode(value);
};

const encodeBase58Bytes = (bytes: Uint8Array) => {
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  let output = '';
  while (number > 0n) {
    const remainder = Number(number % 58n);
    output = base58Alphabet[remainder] + output;
    number /= 58n;
  }
  for (const byte of bytes) {
    if (byte === 0) output = base58Alphabet[0] + output;
    else break;
  }
  return output || base58Alphabet[0];
};

const decodeBase58Bytes = (value: string) => {
  let number = 0n;
  const clean = value.trim();
  for (const char of clean) {
    const index = base58Alphabet.indexOf(char);
    if (index < 0) throw new Error(`Base58 非法字符: ${char}`);
    number = number * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const char of clean) {
    if (char === base58Alphabet[0]) bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
};

const encodeBase58 = (value: string) => encodeBase58Bytes(utf8Encoder.encode(value));
const decodeBase58 = (value: string) => { const bytes = decodeBase58Bytes(value); const text = utf8Decoder.decode(bytes); return text.includes('�') ? bytesToHex(bytes) : text; };

const sha256Bytes = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytesToBuffer(bytes)));

const base58CheckChecksum = async (payload: Uint8Array) => (await sha256Bytes(await sha256Bytes(payload))).slice(0, 4);

const encodeBase58Check = async (value: string, versionHex: string) => {
  const version = hexToBytes(versionHex || '00');
  if (!version.length) throw new Error('Base58Check 版本字节不能为空，例如 00、6f、80');
  const body = new Uint8Array([...version, ...bytesFromTextOrHex(value)]);
  const checksum = await base58CheckChecksum(body);
  return encodeBase58Bytes(new Uint8Array([...body, ...checksum]));
};

const decodeBase58Check = async (value: string) => {
  const bytes = decodeBase58Bytes(value);
  if (bytes.length < 5) throw new Error('Base58Check 数据过短，至少需要 1 字节版本和 4 字节 checksum');
  const body = bytes.slice(0, -4);
  const checksum = bytes.slice(-4);
  const expected = await base58CheckChecksum(body);
  const payload = body.slice(1);
  const checksumValid = bytesToHex(checksum) === bytesToHex(expected);
  return JSON.stringify({
    versionHex: bytesToHex(body.slice(0, 1)),
    payloadHex: bytesToHex(payload),
    payloadText: utf8Decoder.decode(payload).replace(/\p{Cc}/gu, '.'),
    checksumHex: bytesToHex(checksum),
    expectedChecksumHex: bytesToHex(expected),
    checksumValid,
    totalBytes: bytes.length,
  }, null, 2);
};

const bech32Charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const bech32Generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const bech32Constants = { special: 1, hex: 0x2bc830a3 } as const;

const bech32Polymod = (values: number[]) => {
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < 5; index += 1) {
      if ((top >>> index) & 1) checksum ^= bech32Generator[index];
    }
  }
  return checksum >>> 0;
};

const bech32HrpExpand = (hrp: string) => [
  ...Array.from(hrp, char => char.charCodeAt(0) >>> 5),
  0,
  ...Array.from(hrp, char => char.charCodeAt(0) & 31),
];

const convertBits = (data: number[], fromBits: number, toBits: number, pad: boolean) => {
  let accumulator = 0;
  let bits = 0;
  const maxValue = (1 << toBits) - 1;
  const output: number[] = [];
  for (const value of data) {
    if (value < 0 || value >> fromBits) throw new Error('Bech32 数据包含超出位宽的值');
    accumulator = (accumulator << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      output.push((accumulator >>> bits) & maxValue);
    }
  }
  if (pad) {
    if (bits > 0) output.push((accumulator << (toBits - bits)) & maxValue);
  } else if (bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue)) {
    throw new Error('Bech32 padding 非零或不完整');
  }
  return output;
};

const bech32CreateChecksum = (hrp: string, data: number[], variant: string) => {
  const constant = variant === 'hex' ? bech32Constants.hex : bech32Constants.special;
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ constant;
  return Array.from({ length: 6 }, (_, index) => (polymod >>> (5 * (5 - index))) & 31);
};

const bech32VerifyVariant = (hrp: string, data: number[]) => {
  const check = bech32Polymod([...bech32HrpExpand(hrp), ...data]);
  if (check === bech32Constants.special) return 'bech32';
  if (check === bech32Constants.hex) return 'bech32m';
  return null;
};

const normalizeBech32Hrp = (value: string) => {
  const hrp = value.trim().toLowerCase() || 'bc';
  if (!Array.from(hrp).every(char => {
    const code = char.charCodeAt(0);
    return code >= 33 && code <= 126;
  })) throw new Error('Bech32 HRP 只能包含 ASCII 33-126 范围字符');
  return hrp;
};

const encodeBech32 = (value: string, hrpValue: string, variant: string) => {
  const hrp = normalizeBech32Hrp(hrpValue);
  const data = convertBits(Array.from(bytesFromTextOrHex(value)), 8, 5, true);
  const checksum = bech32CreateChecksum(hrp, data, variant);
  const payload = [...data, ...checksum].map(item => bech32Charset[item]).join('');
  return `${hrp}1${payload}`;
};

const decodeBech32 = (value: string) => {
  const clean = value.trim();
  if (!clean) throw new Error('Bech32 输入为空');
  if (clean !== clean.toLowerCase() && clean !== clean.toUpperCase()) throw new Error('Bech32 不允许大小写混用');
  const lower = clean.toLowerCase();
  const separator = lower.lastIndexOf('1');
  if (separator < 1 || separator + 7 > lower.length) throw new Error('Bech32 分隔符或 checksum 长度无效');
  const hrp = lower.slice(0, separator);
  const data = Array.from(lower.slice(separator + 1), char => {
    const index = bech32Charset.indexOf(char);
    if (index < 0) throw new Error(`Bech32 非法字符: ${char}`);
    return index;
  });
  const variant = bech32VerifyVariant(hrp, data);
  const words = data.slice(0, -6);
  const bytes = new Uint8Array(convertBits(words, 5, 8, false));
  return JSON.stringify({
    hrp,
    variant: variant || 'checksum-invalid',
    checksumValid: Boolean(variant),
    dataWords: words,
    dataHex: bytesToHex(bytes),
    dataText: utf8Decoder.decode(bytes).replace(/\p{Cc}/gu, '.'),
  }, null, 2);
};

const encodeBase62 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  let output = '';
  while (number > 0n) {
    const remainder = Number(number % 62n);
    output = base62Alphabet[remainder] + output;
    number /= 62n;
  }
  for (const byte of bytes) {
    if (byte === 0) output = base62Alphabet[0] + output;
    else break;
  }
  return output || base62Alphabet[0];
};

const decodeBase62 = (value: string) => {
  let number = 0n;
  const clean = value.trim();
  for (const char of clean) {
    const index = base62Alphabet.indexOf(char);
    if (index < 0) throw new Error(`Base62 非法字符: ${char}`);
    number = number * 62n + BigInt(index);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const char of clean) {
    if (char === base62Alphabet[0]) bytes.unshift(0);
    else break;
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const encodeBase36 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  let output = number.toString(36).toUpperCase();
  const leadingZeros = Array.from(bytes).findIndex(byte => byte !== 0);
  const zeroCount = leadingZeros < 0 ? bytes.length : leadingZeros;
  if (zeroCount > 0) output = `${'0'.repeat(zeroCount)}${output === '0' ? '' : output}`;
  return output || '0';
};

const decodeBase36 = (value: string) => {
  const clean = value.trim().replace(/\s+/g, '').toUpperCase();
  if (!/^[0-9A-Z]+$/.test(clean)) throw new Error('Base36 非法字符，只允许 0-9A-Z');
  let number = 0n;
  for (const char of clean) number = number * 36n + BigInt(Number.parseInt(char, 36));
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const char of clean) {
    if (char === '0') bytes.unshift(0);
    else break;
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const encodeBase91 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let queue = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    queue |= byte << bits;
    bits += 8;
    if (bits > 13) {
      let entry = queue & 8191;
      if (entry > 88) {
        queue >>= 13;
        bits -= 13;
      } else {
        entry = queue & 16383;
        queue >>= 14;
        bits -= 14;
      }
      output += base91Alphabet[entry % 91] + base91Alphabet[Math.floor(entry / 91)];
    }
  }
  if (bits) {
    output += base91Alphabet[queue % 91];
    if (bits > 7 || queue > 90) output += base91Alphabet[Math.floor(queue / 91)];
  }
  return output;
};

const decodeBase91 = (value: string) => {
  let queue = 0;
  let bits = 0;
  let valueBuffer = -1;
  const bytes: number[] = [];
  for (const char of value.replace(/\s+/g, '')) {
    const digit = base91Alphabet.indexOf(char);
    if (digit < 0) throw new Error(`Base91 非法字符: ${char}`);
    if (valueBuffer < 0) {
      valueBuffer = digit;
    } else {
      valueBuffer += digit * 91;
      queue |= valueBuffer << bits;
      bits += (valueBuffer & 8191) > 88 ? 13 : 14;
      do {
        bytes.push(queue & 255);
        queue >>= 8;
        bits -= 8;
      } while (bits > 7);
      valueBuffer = -1;
    }
  }
  if (valueBuffer >= 0) bytes.push((queue | (valueBuffer << bits)) & 255);
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const encodeAscii85 = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let output = '';
  for (let index = 0; index < bytes.length; index += 4) {
    const chunk = bytes.slice(index, index + 4);
    const padded = new Uint8Array(4);
    padded.set(chunk);
    let number = new DataView(padded.buffer).getUint32(0, false);
    if (chunk.length === 4 && number === 0) {
      output += 'z';
      continue;
    }
    const chars = Array.from({ length: 5 }, () => {
      const char = String.fromCharCode((number % 85) + 33);
      number = Math.floor(number / 85);
      return char;
    }).reverse().join('');
    output += chars.slice(0, chunk.length + 1);
  }
  return `<~${output}~>`;
};

const decodeAscii85 = (value: string) => {
  const clean = value.trim().replace(/^<~/, '').replace(/~>$/, '').replace(/\s+/g, '');
  if (!clean) return '';
  const expanded = clean.replace(/z/g, '!!!!!');
  const bytes: number[] = [];
  for (let index = 0; index < expanded.length; index += 5) {
    const chunk = expanded.slice(index, index + 5);
    const padded = chunk.padEnd(5, 'u');
    let number = 0;
    for (const char of padded) {
      const code = char.charCodeAt(0);
      if (code < 33 || code > 117) throw new Error('ASCII85 包含非法字符');
      number = number * 85 + (code - 33);
    }
    const buffer = new Uint8Array(4);
    new DataView(buffer.buffer).setUint32(0, number >>> 0, false);
    const usefulBytes = chunk.length < 5 ? chunk.length - 1 : 4;
    for (let itemIndex = 0; itemIndex < usefulBytes; itemIndex += 1) bytes.push(buffer[itemIndex]);
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const encodeZ85 = (value: string) => {
  const z85Alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
  const bytes = utf8Encoder.encode(value);
  if (bytes.length % 4 !== 0) throw new Error('Z85 编码要求 UTF-8 字节长度是 4 的倍数');
  let output = '';
  for (let index = 0; index < bytes.length; index += 4) {
    let number = new DataView(bytes.buffer, bytes.byteOffset + index, 4).getUint32(0, false);
    const chars = Array.from({ length: 5 }, () => {
      const char = z85Alphabet[number % 85];
      number = Math.floor(number / 85);
      return char;
    }).reverse();
    output += chars.join('');
  }
  return output;
};

const decodeZ85 = (value: string) => {
  const z85Alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
  const clean = value.trim().replace(/\s+/g, '');
  if (clean.length % 5 !== 0) throw new Error('Z85 解码要求长度是 5 的倍数');
  const bytes: number[] = [];
  for (let index = 0; index < clean.length; index += 5) {
    let number = 0;
    for (const char of clean.slice(index, index + 5)) {
      const digit = z85Alphabet.indexOf(char);
      if (digit < 0) throw new Error(`Z85 非法字符: ${char}`);
      number = number * 85 + digit;
    }
    const buffer = new Uint8Array(4);
    new DataView(buffer.buffer).setUint32(0, number >>> 0, false);
    bytes.push(...buffer);
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const uuByte = (value: number) => value ? String.fromCharCode((value & 0x3f) + 32) : '`';

const uuLineEncode = (chunk: Uint8Array) => {
  let output = uuByte(chunk.length);
  for (let index = 0; index < chunk.length; index += 3) {
    const a = chunk[index] || 0;
    const b = chunk[index + 1] || 0;
    const c = chunk[index + 2] || 0;
    output += uuByte(a >> 2);
    output += uuByte(((a << 4) | (b >> 4)) & 0x3f);
    output += uuByte(((b << 2) | (c >> 6)) & 0x3f);
    output += uuByte(c & 0x3f);
  }
  return output;
};

const encodeUuencode = (value: string, blockLabel: string) => {
  const bytes = utf8Encoder.encode(value);
  const filename = (blockLabel || 'payload.txt').trim().replace(/\s+/g, '_') || 'payload.txt';
  const lines = [`begin 644 ${filename}`];
  for (let index = 0; index < bytes.length; index += 45) lines.push(uuLineEncode(bytes.slice(index, index + 45)));
  lines.push('`', 'end');
  return lines.join('\n');
};

const decodeUuencode = (value: string) => {
  const lines = value.trim().split(/\r?\n/);
  const begin = lines.findIndex(line => /^begin\s+\d+\s+/.test(line));
  if (begin < 0) throw new Error('UUencode 缺少 begin ');
  const bytes: number[] = [];
  for (const line of lines.slice(begin + 1)) {
    if (line === 'end') break;
    if (!line) continue;
    const length = (line.charCodeAt(0) - 32) & 0x3f;
    if (length === 0) continue;
    const data = line.slice(1);
    const decoded: number[] = [];
    for (let index = 0; index < data.length; index += 4) {
      const chunk = data.slice(index, index + 4).padEnd(4, '`');
      const values = Array.from(chunk).map(char => (char.charCodeAt(0) - 32) & 0x3f);
      decoded.push((values[0] << 2) | (values[1] >> 4));
      decoded.push(((values[1] & 15) << 4) | (values[2] >> 2));
      decoded.push(((values[2] & 3) << 6) | values[3]);
    }
    bytes.push(...decoded.slice(0, length));
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const htmlEncode = (value: string, variant: string) => {
  if (variant === 'decimal') return Array.from(value).map(char => `&#${char.codePointAt(0)};`).join('');
  if (variant === 'hex') return Array.from(value).map(char => `&#x${char.codePointAt(0)?.toString(16)};`).join('');
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
};

const htmlNamedEntities: Record<string, string> = {
  amp: '&',
  apos: "'",
  gt: '>',
  lt: '<',
  nbsp: '\u00a0',
  quot: '"',
};

const htmlDecodeFallback = (value: string) => value.replace(/&(?:(#x[0-9a-f]+)|(#\d+)|([a-z][a-z0-9]+));/gi, (match, hex, decimal, named) => {
  if (hex) {
    const codePoint = Number.parseInt(hex.slice(2), 16);
    return Number.isSafeInteger(codePoint) && codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : match;
  }
  if (decimal) {
    const codePoint = Number.parseInt(decimal.slice(1), 10);
    return Number.isSafeInteger(codePoint) && codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : match;
  }
  return htmlNamedEntities[String(named).toLowerCase()] || match;
});

const htmlDecode = (value: string) => {
  if (typeof document === 'undefined' || typeof document.createElement !== 'function') return htmlDecodeFallback(value);
  const textarea = document.createElement('textarea');
  textarea.innerHTML = value;
  return textarea.value;
};

const xmlDecode = (value: string) => value
  .replace(/&amp;/g, '&')
  .replace(/&lt;/g, '<')
  .replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"')
  .replace(/&apos;/g, "'")
  .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
  .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)));

const xmlEncode = (value: string, variant: string) => {
  if (variant === 'decimal') return Array.from(value).map(char => `&#${char.codePointAt(0)};`).join('');
  if (variant === 'hex') return Array.from(value).map(char => `&#x${char.codePointAt(0)?.toString(16)};`).join('');
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
};

const unicodeEncode = (value: string, variant: string) => {
  if (variant === 'hex') {
    return Array.from(utf8Encoder.encode(value)).map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join('');
  }
  if (variant === 'brace') {
    return Array.from(value).map(char => `\\u{${char.codePointAt(0)?.toString(16)}}`).join('');
  }
  return Array.from(value).map(char => {
    const units = [];
    for (let index = 0; index < char.length; index += 1) {
      units.push(`\\u${char.charCodeAt(index).toString(16).padStart(4, '0')}`);
    }
    return units.join('');
  }).join('');
};

const unicodeDecode = (value: string) => value
  .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
  .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
  .replace(/(?:\\x[0-9a-fA-F]{2})+/g, match => utf8Decoder.decode(hexToBytes(match)));

const utf16BeBytes = (value: string) => {
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    bytes.push((unit >>> 8) & 255, unit & 255);
  }
  return new Uint8Array(bytes);
};

const utf16BeToText = (bytes: Uint8Array) => {
  if (bytes.length % 2 !== 0) throw new Error('UTF-7 shifted sequence must decode to even UTF-16BE bytes');
  let output = '';
  for (let index = 0; index < bytes.length; index += 2) {
    output += String.fromCharCode((bytes[index] << 8) | bytes[index + 1]);
  }
  return output;
};

const utf7Encode = (value: string) => {
  let output = '';
  let shifted = '';
  const flush = () => {
    if (!shifted) return;
    output += `+${bytesToBase64(utf16BeBytes(shifted)).replace(/=+$/g, '')}-`;
    shifted = '';
  };
  for (const char of Array.from(value)) {
    if (char === '+') {
      flush();
      output += '+-';
    } else if (utf7DirectChars.has(char)) {
      flush();
      output += char;
    } else {
      shifted += char;
    }
  }
  flush();
  return output;
};

const utf7Decode = (value: string) => value.replace(/\+([A-Za-z0-9+/]*)(-?)/g, (_match, body: string) => {
  if (!body) return '+';
  const padded = body.padEnd(Math.ceil(body.length / 4) * 4, '=');
  return utf16BeToText(base64ToBytes(padded));
});

const cStringEncode = (value: string) => Array.from(value).map(char => {
  if (char === '\n') return '\\n';
  if (char === '\r') return '\\r';
  if (char === '\t') return '\\t';
  if (char === '\b') return '\\b';
  if (char === '\f') return '\\f';
  if (char === '\v') return '\\v';
  if (char === '\\') return '\\\\';
  if (char === '"') return '\\"';
  if (char === "'") return "\\'";
  const codePoint = char.codePointAt(0) || 0;
  if (codePoint >= 0x20 && codePoint <= 0x7e) return char;
  if (codePoint <= 0xff) return `\\x${codePoint.toString(16).padStart(2, '0')}`;
  if (codePoint <= 0xffff) return `\\u${codePoint.toString(16).padStart(4, '0')}`;
  return `\\U${codePoint.toString(16).padStart(8, '0')}`;
}).join('');

const cStringDecode = (value: string) => value.replace(/\\(U[0-9a-fA-F]{8}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|[nrtbfv0'"\\])/g, (_match, escape: string) => {
  if (escape === 'n') return '\n';
  if (escape === 'r') return '\r';
  if (escape === 't') return '\t';
  if (escape === 'b') return '\b';
  if (escape === 'f') return '\f';
  if (escape === 'v') return '\v';
  if (escape === '0') return '\0';
  if (escape === '"' || escape === "'" || escape === '\\') return escape;
  if (escape[0] === 'x') return String.fromCharCode(Number.parseInt(escape.slice(1), 16));
  if (escape[0] === 'u' || escape[0] === 'U') return String.fromCodePoint(Number.parseInt(escape.slice(1), 16));
  return String.fromCharCode(Number.parseInt(escape, 8));
});

const decodeJavaScriptEscapes = (value: string) => value
  .replace(/\\\r?\n/g, '')
  .replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|0(?!\d)|[nrtbfv"'\\`])/g, (_match, escape: string) => {
    if (escape === 'n') return '\n';
    if (escape === 'r') return '\r';
    if (escape === 't') return '\t';
    if (escape === 'b') return '\b';
    if (escape === 'f') return '\f';
    if (escape === 'v') return '\v';
    if (escape === '0') return '\0';
    if (escape === '"' || escape === "'" || escape === '`' || escape === '\\') return escape;
    if (escape.startsWith('u{')) return String.fromCodePoint(Number.parseInt(escape.slice(2, -1), 16));
    if (escape[0] === 'u' || escape[0] === 'x') return String.fromCodePoint(Number.parseInt(escape.slice(1), 16));
    return escape;
  });

const jsStringDecode = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return '';
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
    || (trimmed.startsWith("'") && trimmed.endsWith("'"))
    || (trimmed.startsWith('`') && trimmed.endsWith('`'))
  ) {
    const quote = trimmed[0];
    if (quote === '"') {
      return JSON.parse(trimmed);
    }
    return decodeJavaScriptEscapes(trimmed.slice(1, -1));
  }
  return decodeJavaScriptEscapes(trimmed);
};

const jsonStringDecode = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return '';
  try {
    const parsed = JSON.parse(trimmed);
    return typeof parsed === 'string' ? parsed : JSON.stringify(parsed, null, 2);
  } catch {
    return jsStringDecode(trimmed);
  }
};

const separatorValue = (separator: string) => {
  if (separator === 'comma') return ',';
  if (separator === 'newline') return '\n';
  return ' ';
};

const binaryEncode = (value: string, separator: string) => Array.from(utf8Encoder.encode(value))
  .map(byte => byte.toString(2).padStart(8, '0'))
  .join(separatorValue(separator));

const binaryDecode = (value: string) => {
  const chunks = value.match(/[01]{8}/g) || [];
  if (!chunks.length) throw new Error('没有找到 8 位二进制字节');
  return utf8Decoder.decode(new Uint8Array(chunks.map(chunk => Number.parseInt(chunk, 2))));
};

const asciiEncode = (value: string, separator: string) => Array.from(value)
  .map(char => String(char.codePointAt(0)))
  .join(separatorValue(separator));

const asciiDecode = (value: string) => value
  .split(/[\s,;|]+/)
  .filter(Boolean)
  .map(code => String.fromCodePoint(Number.parseInt(code, 10)))
  .join('');

const octalEncode = (value: string, separator: string) => Array.from(utf8Encoder.encode(value))
  .map(byte => byte.toString(8).padStart(3, '0'))
  .join(separatorValue(separator));

const octalDecode = (value: string) => {
  const clean = value.trim();
  const tokens = clean.match(/\\[0-7]{1,3}|0o[0-7]+|0[0-7]{1,3}|[0-7]{1,3}/gi) || [];
  const normalized = tokens.length
    ? tokens.map(token => token.replace(/^\\/u, '').replace(/^0o/iu, '').replace(/^0(?=[0-7])/u, ''))
    : /^[0-7]+$/.test(clean) && clean.length % 3 === 0
      ? clean.match(/.{3}/g) || []
      : [];
  if (!normalized.length) throw new Error('没有找到八进制字');
  return utf8Decoder.decode(new Uint8Array(normalized.map(token => Number.parseInt(token, 8))));
};

const a1z26Encode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const index = alphabet.indexOf(char);
    return index >= 0 ? String(index + 1) : char.trim() ? char : '/';
  })
  .join(separatorValue(separator));

const a1z26Decode = (value: string) => value
  .trim()
  .split(/[\s,;|/.-]+/)
  .filter(Boolean)
  .map(token => {
    const number = Number.parseInt(token, 10);
    return number >= 1 && number <= 26 ? alphabet[number - 1] : token;
  })
  .join('');

const morseEncode = (value: string) => Array.from(value.toUpperCase())
  .map(char => (char === ' ' ? '/' : morseMap[char] || char))
  .join(' ');

const morseDecode = (value: string) => value
  .trim()
  .split(/\s+/)
  .map(code => (code === '/' ? ' ' : reverseMorseMap[code] || code))
  .join('');

// Pollux cipher: digits represent ·  —  × (dot/dash/separator) based on a key
// Common CTF variant: 0=dot(·), 1=dash(—), 8/9=separator; others are noise
const polluxDecode = (value: string) => {
  // mapping[digit] → '.', '-', ' ', or noise (skip)
  // default mapping: 0→. 1→- 2→. 3→- 4→. 5→- 6→. 7→- 8→' ' 9→' '
  const dotChars = new Set('024');
  const dashChars = new Set('135');
  const sepChars = new Set('6789 ');
  let morse = '';
  for (const ch of value.replace(/[^0-9 ]/g, '')) {
    if (dotChars.has(ch)) morse += '.';
    else if (dashChars.has(ch)) morse += '-';
    else if (sepChars.has(ch)) morse += ' ';
  }
  return morseDecode(morse);
};

const natoEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => (char === ' ' ? '/' : natoWords[char] || char))
  .join(separatorValue(separator));

const natoDecode = (value: string) => value
  .trim()
  .replace(/\bx[-\s]ray\b/gi, 'Xray')  // normalize X-Ray / X Ray → Xray before splitting
  .split(/[\s,;|-]+/)
  .filter(Boolean)
  .map(token => (token === '/' ? ' ' : reverseNatoWords[token.toLowerCase()] || token))
  .join('');

const baudotEncode = (value: string, separator: string) => {
  let mode: 'letters' | 'figures' = 'letters';
  const output: string[] = [];
  for (const rawChar of Array.from(value)) {
    const char = rawChar.toUpperCase();
    if (baudotLetters[char]) {
      if (mode !== 'letters') {
        output.push(baudotLettersShift);
        mode = 'letters';
      }
      output.push(baudotLetters[char]);
      continue;
    }
    if (baudotFigures[rawChar]) {
      if (mode !== 'figures') {
        output.push(baudotFiguresShift);
        mode = 'figures';
      }
      output.push(baudotFigures[rawChar]);
      continue;
    }
    if (rawChar === '\t') output.push(baudotLetters[' ']);
  }
  return output.join(separatorValue(separator));
};

const baudotDecode = (value: string) => {
  const chunks = value.match(/[01]{5}/g) || [];
  if (!chunks.length) throw new Error('Baudot 解码需要 5-bit 二进制分组');
  let mode: 'letters' | 'figures' = 'letters';
  return chunks.map(chunk => {
    if (chunk === baudotLettersShift) {
      mode = 'letters';
      return '';
    }
    if (chunk === baudotFiguresShift) {
      mode = 'figures';
      return '';
    }
    return mode === 'letters'
      ? reverseBaudotLetters[chunk] || '?'
      : reverseBaudotFigures[chunk] || '?';
  }).join('');
};

const bcdEncode = (value: string, separator: string) => {
  const digits = value.replace(/\D/g, '');
  if (!digits) throw new Error('BCD 编码需要十进制数字');
  return Array.from(digits).map(digit => Number(digit).toString(2).padStart(4, '0')).join(separatorValue(separator));
};

const bcdDecode = (value: string) => {
  const chunks = value.match(/[01]{4}/g) || [];
  if (!chunks.length) throw new Error('BCD 解码需要 4-bit 二进制分组');
  return chunks.map(chunk => {
    const digit = Number.parseInt(chunk, 2);
    if (digit > 9) throw new Error(`BCD nibble ${chunk} 超出 0-9 范围`);
    return String(digit);
  }).join('');
};

const parseBinaryOrDecimalTokens = (value: string) => value
  .trim()
  .split(/[\s,;|]+/)
  .filter(Boolean)
  .map(token => {
    const binary = /^0b([01]+)$/i.exec(token);
    if (binary) return { raw: token, value: BigInt(`0b${binary[1]}`), width: binary[1].length, binary: true };
    const decimal = /^0d(\d+)$/i.exec(token);
    if (decimal) {
      const parsed = BigInt(decimal[1]);
      return { raw: token, value: parsed, width: Math.max(1, parsed.toString(2).length), binary: false };
    }
    if (/^[01]+$/.test(token)) return { raw: token, value: BigInt(`0b${token}`), width: token.length, binary: true };
    if (/^\d+$/.test(token)) {
      const parsed = BigInt(token);
      return { raw: token, value: parsed, width: Math.max(1, parsed.toString(2).length), binary: false };
    }
    throw new Error(`无法解析整数: ${token}；二进制可用 0b 前缀，十进制可用 0d 前缀`);
  });

const bigIntToBinary = (value: bigint, width: number) => value.toString(2).padStart(width, '0');

const grayEncode = (value: string, separator: string) => {
  const tokens = parseBinaryOrDecimalTokens(value);
  if (!tokens.length) throw new Error('Gray Code 编码需要二进制或十进制整数');
  return tokens
    .map(token => {
      const gray = token.value ^ (token.value >> 1n);
      return token.binary ? bigIntToBinary(gray, token.width) : gray.toString();
    })
    .join(separatorValue(separator));
};

const grayDecode = (value: string, separator: string) => {
  const tokens = parseBinaryOrDecimalTokens(value);
  if (!tokens.length) throw new Error('Gray Code 解码需要二进制或十进制整数');
  return tokens
    .map(token => {
      let binary = token.value;
      for (let shifted = binary >> 1n; shifted > 0n; shifted >>= 1n) binary ^= shifted;
      return token.binary ? bigIntToBinary(binary, token.width) : binary.toString();
    })
    .join(separatorValue(separator));
};

const dnaEncode = (value: string, variant: string, separator: string) => {
  const map = dnaMaps[variant] || dnaMaps.special;
  return Array.from(utf8Encoder.encode(value))
    .map(byte => byte.toString(2).padStart(8, '0').match(/../g)?.map(pair => map[pair]).join('') || '')
    .join(separatorValue(separator));
};

const dnaDecode = (value: string, variant: string) => {
  const map = reverseDnaMaps[variant] || reverseDnaMaps.special;
  const clean = value.toUpperCase().replace(/[^ACGT]/g, '');
  if (!clean || clean.length % 4 !== 0) throw new Error('DNA 解码需要 A/C/G/T，且长度为 4 的倍数');
  const bits = Array.from(clean).map(base => {
    const pair = map[base];
    if (!pair) throw new Error(`未知 DNA 碱基: ${base}`);
    return pair;
  }).join('');
  const bytes = bits.match(/.{8}/g)?.map(chunk => Number.parseInt(chunk, 2)) || [];
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const zeroWidthEncode = (value: string) => Array.from(utf8Encoder.encode(value))
  .map(byte => byte.toString(2).padStart(8, '0'))
  .join('')
  .replace(/0/g, zeroWidthZero)
  .replace(/1/g, zeroWidthOne);

const zeroWidthDecode = (value: string) => {
  const bits = Array.from(value)
    .filter(char => char === zeroWidthZero || char === zeroWidthOne)
    .map(char => (char === zeroWidthZero ? '0' : '1'))
    .join('');
  if (!bits || bits.length % 8 !== 0) throw new Error('零宽字符解码需要完整的 8-bit 字节序列');
  const bytes = bits.match(/.{8}/g)?.map(chunk => Number.parseInt(chunk, 2)) || [];
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const packGsm7Septets = (septets: number[]) => {
  const output: number[] = [];
  let accumulator = 0;
  let bitCount = 0;
  for (const septet of septets) {
    accumulator |= (septet & 0x7f) << bitCount;
    bitCount += 7;
    while (bitCount >= 8) {
      output.push(accumulator & 0xff);
      accumulator >>>= 8;
      bitCount -= 8;
    }
  }
  if (bitCount > 0) output.push(accumulator & 0xff);
  return new Uint8Array(output);
};

const unpackGsm7Septets = (bytes: Uint8Array) => {
  const septets: number[] = [];
  let accumulator = 0;
  let bitCount = 0;
  for (const byte of bytes) {
    accumulator |= byte << bitCount;
    bitCount += 8;
    while (bitCount >= 7) {
      septets.push(accumulator & 0x7f);
      accumulator >>>= 7;
      bitCount -= 7;
    }
  }
  return septets;
};

const gsm7SeptetsToText = (septets: number[]) => {
  let output = '';
  for (let index = 0; index < septets.length; index += 1) {
    const septet = septets[index];
    if (septet === 0x1b) {
      const next = septets[index + 1];
      if (next == null) throw new Error('GSM 7-bit 格式错误：末尾 ESC 缺少扩展字符');
      const extended = reverseGsm7ExtensionAlphabet[next];
      if (extended == null) throw new Error(`GSM 7-bit 格式错误：未知扩展码 0x${next.toString(16).padStart(2, '0')}`);
      output += extended;
      index += 1;
      continue;
    }
    output += gsm7DefaultAlphabet[septet] || '?';
  }
  return output;
};

type Gsm7PackedPayload = {
  encoding?: string;
  septetCount: number;
  packedHex: string;
};

const parseGsm7SeptetCount = (value: unknown) => {
  const numeric = typeof value === 'number'
    ? value
    : typeof value === 'string' && /^\d+$/.test(value.trim())
      ? Number(value.trim())
      : Number.NaN;
  if (!Number.isSafeInteger(numeric) || numeric < 0) throw new Error('GSM 7-bit septetCount 必须是非负整数');
  return numeric;
};

const unpackCountedGsm7Septets = (bytes: Uint8Array, septetCount: number) => {
  const expectedByteLength = Math.ceil((septetCount * 7) / 8);
  if (bytes.length !== expectedByteLength) {
    throw new Error(`GSM 7-bit 长度不一致：${septetCount} septets 应为 ${expectedByteLength} bytes，实际为 ${bytes.length}`);
  }
  const unpacked = unpackGsm7Septets(bytes);
  if (septetCount > unpacked.length) throw new Error('GSM 7-bit septetCount 超出 packed 数据容量');
  const septets = unpacked.slice(0, septetCount);
  if (bytesToHex(packGsm7Septets(septets)) !== bytesToHex(bytes)) {
    throw new Error('GSM 7-bit packed 数据包含非零填充位或与 septetCount 不一致');
  }
  return septets;
};

const parseCountedGsm7Payload = (value: string): Gsm7PackedPayload | null => {
  const text = value.trim();
  if (text.startsWith('{')) {
    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error('GSM 7-bit JSON 格式错误');
    }
    const packedHex = payload.packedHex ?? payload.hex;
    const septetCount = payload.septetCount ?? payload.septets ?? payload.length;
    if (typeof packedHex !== 'string' || septetCount == null) {
      throw new Error('GSM 7-bit JSON 需要 packedHex 和 septetCount');
    }
    return {
      encoding: typeof payload.encoding === 'string' ? payload.encoding : undefined,
      septetCount: parseGsm7SeptetCount(septetCount),
      packedHex,
    };
  }

  if (/\b(?:septetCount|septets|packedHex)\b/i.test(text)) {
    const countMatch = text.match(/\b(?:septetCount|septets)\s*[:=]\s*(\d+)/i);
    const hexMatch = text.match(/\b(?:packedHex|hex)\s*[:=]\s*((?:0x)?[0-9a-f][0-9a-f\s:_-]*)/i);
    if (!countMatch || !hexMatch) throw new Error('GSM 7-bit 显式长度格式需要 septetCount 和 packedHex');
    return {
      septetCount: parseGsm7SeptetCount(countMatch[1]),
      packedHex: hexMatch[1],
    };
  }
  return null;
};

const gsm7Encode = (value: string) => {
  const septets: number[] = [];
  for (const char of Array.from(value)) {
    const direct = gsm7ReverseAlphabet.get(char);
    if (direct != null) {
      septets.push(direct);
      continue;
    }
    const extended = gsm7ExtensionAlphabet[char];
    if (extended != null) {
      septets.push(0x1b, extended);
      continue;
    }
    throw new Error(`GSM 7-bit 不支持字符: ${char}`);
  }
  return JSON.stringify({
    encoding: 'gsm7-packed',
    septetCount: septets.length,
    packedHex: bytesToHex(packGsm7Septets(septets)),
  }, null, 2);
};

const gsm7Decode = (value: string) => {
  const counted = parseCountedGsm7Payload(value);
  if (counted) {
    const bytes = hexToBytes(counted.packedHex);
    return gsm7SeptetsToText(unpackCountedGsm7Septets(bytes, counted.septetCount));
  }

  const bytes = hexToBytes(value);
  const septets = unpackGsm7Septets(bytes);
  if (bytes.length > 0 && bytes.length % 7 === 0 && septets[septets.length - 1] === 0) {
    throw new Error('GSM 7-bit 裸 Hex 的 septet count 存在歧义；请提供包含 septetCount 和 packedHex 的格式');
  }
  if (bytesToHex(packGsm7Septets(septets)) !== bytesToHex(bytes)) {
    throw new Error('GSM 7-bit packed 数据包含非零填充位；请提供正确的 septetCount');
  }
  return gsm7SeptetsToText(septets);
};

const yEncEncode = (value: string) => Array.from(utf8Encoder.encode(value))
  .map(byte => {
    const encoded = (byte + 42) & 0xff;
    if (encoded === 0 || encoded === 10 || encoded === 13 || encoded === 61) {
      return `=${String.fromCharCode((encoded + 64) & 0xff)}`;
    }
    return String.fromCharCode(encoded);
  })
  .join('');

const yEncDecode = (value: string) => {
  const body = value
    .split(/\r?\n/)
    .filter(line => !/^=y(?:begin|part|end)\b/i.test(line))
    .join('\n');
  const bytes: number[] = [];
  for (let index = 0; index < body.length; index += 1) {
    let encoded = body.charCodeAt(index) & 0xff;
    if (body[index] === '=') {
      index += 1;
      if (index >= body.length) throw new Error('yEnc 转义序列不完');
      encoded = (body.charCodeAt(index) - 64) & 0xff;
    }
    bytes.push((encoded - 42) & 0xff);
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const bubbleIndex = (alphabet: string, char: string, label: string) => {
  const index = alphabet.indexOf(char);
  if (index < 0) throw new Error(`Bubble Babble ${label} 字符不合法: ${char}`);
  return index;
};

const bubbleBabbleEncode = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let seed = 1;
  let output = 'x';
  const rounds = Math.floor(bytes.length / 2) + 1;
  for (let round = 0; round < rounds; round += 1) {
    if (round + 1 < rounds || bytes.length % 2 !== 0) {
      const byte1 = bytes[round * 2];
      output += bubbleBabbleVowels[(((byte1 >>> 6) & 3) + seed) % 6];
      output += bubbleBabbleConsonants[(byte1 >>> 2) & 15];
      output += bubbleBabbleVowels[((byte1 & 3) + Math.floor(seed / 6)) % 6];
      if (round + 1 < rounds) {
        const byte2 = bytes[round * 2 + 1];
        output += bubbleBabbleConsonants[(byte2 >>> 4) & 15];
        output += '-';
        output += bubbleBabbleConsonants[byte2 & 15];
        seed = (seed * 5 + byte1 * 7 + byte2) % 36;
      }
    } else {
      output += bubbleBabbleVowels[seed % 6];
      output += bubbleBabbleConsonants[16];
      output += bubbleBabbleVowels[Math.floor(seed / 6)];
    }
  }
  return `${output}x`;
};

const bubbleBabbleDecode = (value: string) => {
  const clean = value.trim().toLowerCase().replace(/-/g, '');
  if (!/^x[a-z]+x$/.test(clean)) throw new Error('Bubble Babble 必须以 x 开头并以 x 结束');
  const body = clean.slice(1, -1);
  const bytes: number[] = [];
  let seed = 1;
  for (let offset = 0; offset < body.length; offset += 5) {
    const chunk = body.slice(offset, offset + 5);
    if (chunk.length === 3) {
      const c1 = bubbleIndex(bubbleBabbleConsonants, chunk[1], 'consonant');
      if (c1 === 16) break;
      const b1 = (((bubbleIndex(bubbleBabbleVowels, chunk[0], 'vowel') - (seed % 6) + 6) % 6) << 6)
        | (c1 << 2)
        | ((bubbleIndex(bubbleBabbleVowels, chunk[2], 'vowel') - Math.floor(seed / 6) + 6) % 6);
      bytes.push(b1 & 0xff);
      break;
    }
    if (chunk.length !== 5) throw new Error('Bubble Babble 分组长度不合法');
    const b1 = (((bubbleIndex(bubbleBabbleVowels, chunk[0], 'vowel') - (seed % 6) + 6) % 6) << 6)
      | (bubbleIndex(bubbleBabbleConsonants, chunk[1], 'consonant') << 2)
      | ((bubbleIndex(bubbleBabbleVowels, chunk[2], 'vowel') - Math.floor(seed / 6) + 6) % 6);
    const b2 = (bubbleIndex(bubbleBabbleConsonants, chunk[3], 'consonant') << 4)
      | bubbleIndex(bubbleBabbleConsonants, chunk[4], 'consonant');
    bytes.push(b1 & 0xff, b2 & 0xff);
    seed = (seed * 5 + b1 * 7 + b2) % 36;
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const quotedPrintableEncode = (value: string) => {
  const bytes = utf8Encoder.encode(value);
  let line = '';
  let output = '';
  const push = (segment: string) => {
    if (line.length + segment.length > 73) {
      output += `${line}=\r\n`;
      line = '';
    }
    line += segment;
  };
  for (const byte of bytes) {
    const safe =
      (byte >= 33 && byte <= 60) ||
      (byte >= 62 && byte <= 126) ||
      byte === 9 ||
      byte === 32;
    push(safe ? String.fromCharCode(byte) : `=${byte.toString(16).toUpperCase().padStart(2, '0')}`);
  }
  return output + line;
};

const quotedPrintableDecode = (value: string) => {
  const normalized = value.replace(/=\r?\n/g, '');
  const bytes: number[] = [];
  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index];
    if (char === '=') {
      const hex = normalized.slice(index + 1, index + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new Error('Quoted-Printable 十六进制片段不完');
      bytes.push(Number.parseInt(hex, 16));
      index += 2;
    } else {
      bytes.push(char.charCodeAt(0));
    }
  }
  return utf8Decoder.decode(new Uint8Array(bytes));
};

const encodeUtf16Bytes = (value: string, variant: string, separator: string) => {
  const littleEndian = variant !== 'hex';
  const bytes = Array.from(value).flatMap(char => {
    const unit = char.charCodeAt(0);
    return littleEndian ? [unit & 0xff, unit >> 8] : [unit >> 8, unit & 0xff];
  });
  return bytes.map(byte => byte.toString(16).padStart(2, '0')).join(separatorValue(separator));
};

const decodeUtf16Bytes = (value: string, variant: string) => {
  const bytes = Array.from(hexToBytes(value));
  if (bytes.length % 2 !== 0) throw new Error('UTF-16 字节序列长度必须为偶数');
  const littleEndian = variant !== 'hex';
  let output = '';
  for (let index = 0; index < bytes.length; index += 2) {
    const unit = littleEndian ? bytes[index] | (bytes[index + 1] << 8) : (bytes[index] << 8) | bytes[index + 1];
    output += String.fromCharCode(unit);
  }
  return output;
};

const keyboardShift = (value: string, variant: string, decode = false) => {
  const baseDirection = variant === 'hex' ? -1 : 1;
  const direction = decode ? -baseDirection : baseDirection;
  const lookup = new Map<string, string>();
  for (const row of keyboardRows) {
    Array.from(row).forEach((char, index, chars) => {
      const next = chars[index + direction];
      if (next) lookup.set(char, next);
    });
  }
  return Array.from(value).map(char => {
    const lower = char.toLowerCase();
    const mapped = lookup.get(lower);
    if (!mapped) return char;
    return char === lower ? mapped : mapped.toUpperCase();
  }).join('');
};

const encodeUnixTime = (value: string) => {
  const input = value.trim();
  if (!input) return '';
  const date = new Date(input);
  if (Number.isNaN(date.getTime())) throw new Error('无法解析输入时间，请使用 ISO 时间或浏览器可识别的时间格式');
  return JSON.stringify({
    iso: date.toISOString(),
    unixSeconds: Math.floor(date.getTime() / 1000),
    unixMilliseconds: date.getTime(),
  }, null, 2);
};

const decodeUnixTime = (value: string) => {
  const input = value.trim();
  if (!input) return '';
  if (/^[[{]/.test(input)) {
    try {
      const parsed = JSON.parse(input) as Record<string, unknown>;
      const unixMilliseconds = Number(parsed.unixMilliseconds);
      const unixSeconds = Number(parsed.unixSeconds);
      if (Number.isFinite(unixMilliseconds)) return decodeUnixTime(String(Math.trunc(unixMilliseconds)));
      if (Number.isFinite(unixSeconds)) return decodeUnixTime(String(Math.trunc(unixSeconds)));
    } catch {
      // Fall through to raw timestamp parsing.
    }
  }
  if (!/^-?\d+$/.test(input)) throw new Error('时间戳必须是整数');
  const numeric = Number(input);
  const ms = input.length < 13 ? numeric * 1000 : numeric;
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) throw new Error('时间戳超出可解析范围');
  return JSON.stringify({
    iso: date.toISOString(),
    local: date.toLocaleString(),
    unixSeconds: Math.floor(ms / 1000),
    unixMilliseconds: ms,
  }, null, 2);
};

const rot47 = (value: string) => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  return code >= 33 && code <= 126 ? String.fromCharCode(33 + ((code + 14) % 94)) : char;
}).join('');

// ROT8000: rotates within each Unicode script block (Latin, Greek, Cyrillic, digits, etc.)
const rot8000Blocks: Array<[number, number]> = [
  [0x41, 0x5A], [0x61, 0x7A], [0x30, 0x39],  // A-Z, a-z, 0-9
  [0xC0, 0xD6], [0xD8, 0xF6], [0xF8, 0xFF],  // Latin extended
  [0x0391, 0x03A9], [0x03B1, 0x03C9],          // Greek upper/lower
  [0x0410, 0x042F], [0x0430, 0x044F],          // Cyrillic upper/lower
  [0x4E00, 0x9FFF],                             // CJK unified ideographs
];
const rot8000 = (value: string) => Array.from(value).map(char => {
  const cp = char.codePointAt(0);
  if (cp == null) return char;
  for (const [lo, hi] of rot8000Blocks) {
    if (cp >= lo && cp <= hi) {
      const size = hi - lo + 1;
      return String.fromCodePoint(lo + ((cp - lo + (size >> 1)) % size));
    }
  }
  return char;
}).join('');

const caesar = (value: string, shift: number) => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
  if (base == null) return char;
  return String.fromCharCode(base + ((((code - base) + shift) % 26) + 26) % 26);
}).join('');

// Trithemius / progressive Caesar: shift each alpha char by its ALL-character position index
const trithemiusDecode = (value: string) => {
  let result = '';
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) { result += value[i]; }
    else result += String.fromCharCode(base + (((code - base) - i) % 26 + 26) % 26);
  }
  return result;
};

const rot18 = (value: string) => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) return caesar(char, 13);
  if (code >= 48 && code <= 57) return String.fromCharCode(((code - 48 + 5) % 10) + 48);
  return char;
}).join('');

const rotBruteforce = (value: string) => [
  ...Array.from({ length: 25 }, (_, index) => `ROT${index + 1}: ${caesar(value, index + 1)}`),
  `ROT47: ${rot47(value)}`,
  `ROT18 (ROT13+ROT5): ${rot18(value)}`,
].join('\n');

type EnigmaRotorName = 'I' | 'II' | 'III' | 'IV' | 'V' | 'VI' | 'VII' | 'VIII';
type EnigmaReflectorName = 'B' | 'C';

const enigmaRotors: Record<EnigmaRotorName, { wiring: string; notches: string }> = {
  I: { wiring: 'EKMFLGDQVZNTOWYHXUSPAIBRCJ', notches: 'Q' },
  II: { wiring: 'AJDKSIRUXBLHWTMCQGZNPYFVOE', notches: 'E' },
  III: { wiring: 'BDFHJLCPRTXVZNYEIWGAKMUSQO', notches: 'V' },
  IV: { wiring: 'ESOVPZJAYQUIRHXLNFTGKDCMWB', notches: 'J' },
  V: { wiring: 'VZBRGITYUPSDNHLXAWMJQOFECK', notches: 'Z' },
  VI: { wiring: 'JPGVOUMFYQBENHZRDKASXLICTW', notches: 'ZM' },
  VII: { wiring: 'NZJHGRCXMYSWBOUFAIVLPEKQDT', notches: 'ZM' },
  VIII: { wiring: 'FKQHTLXOCBJSPDZRAMEWNIUYGV', notches: 'ZM' },
};

const enigmaReflectors: Record<EnigmaReflectorName, string> = {
  B: 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
  C: 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
};

const enigmaGroup = (value: string) => value.match(/.{1,5}/g)?.join(' ') || '';

const normalizeEnigmaLetters = (value: string, fallback: string, size = 3) => {
  const letters = value.toUpperCase().replace(/[^A-Z]/g, '');
  return (letters || fallback).padEnd(size, 'A').slice(0, size);
};

const parseEnigmaSettings = (secret: string) => {
  const fields: Record<string, string> = {};
  for (const rawPart of secret.split(/[;\n]/)) {
    const part = rawPart.trim();
    if (!part) continue;
    const match = part.match(/^([a-zA-Z][\w-]*)\s*[:=]\s*(.+)$/);
    if (match) fields[match[1].toLowerCase()] = match[2].trim();
  }
  const rotorSource = fields.rotors || fields.rotor || 'I II III';
  const rotorCandidates = rotorSource.toUpperCase().match(/VIII|VII|VI|IV|III|II|I|V/g) || [];
  const rotors = (rotorCandidates.length ? rotorCandidates : ['I', 'II', 'III']).slice(0, 3) as EnigmaRotorName[];
  if (rotors.length !== 3 || rotors.some(rotor => !enigmaRotors[rotor])) throw new Error('Enigma rotors 需要 3 个转子，例如 rotors=I II III');
  const reflector = ((fields.reflector || fields.ukw || 'B').trim().toUpperCase()[0] || 'B') as EnigmaReflectorName;
  if (!enigmaReflectors[reflector]) throw new Error('Enigma reflector 仅支持 B 或 C');
  const rings = normalizeEnigmaLetters(fields.rings || fields.ring || 'AAA', 'AAA');
  const positions = normalizeEnigmaLetters(fields.positions || fields.position || fields.pos || fields.initial || 'AAA', 'AAA');
  const plugboardPairs = Array.from((fields.plugboard || fields.plugs || '').toUpperCase().matchAll(/[A-Z]{2}/g), item => item[0]);
  const plugboard = new Map<string, string>();
  for (const pair of plugboardPairs) {
    const [left, right] = pair;
    if (left === right) throw new Error(`Plugboard pair ${pair} cannot connect the same letter`);
    if (plugboard.has(left) || plugboard.has(right)) throw new Error(`Plugboard 字母重复: ${pair}`);
    plugboard.set(left, right);
    plugboard.set(right, left);
  }
  return { rotors, reflector, rings, positions, plugboardPairs, plugboard };
};

const enigmaRotorPass = (value: number, wiring: string, position: number, ring: number, reverse = false) => {
  const shifted = (value + position - ring + 26) % 26;
  const mapped = reverse
    ? wiring.indexOf(alphabet[shifted])
    : alphabet.indexOf(wiring[shifted]);
  return (mapped - position + ring + 26) % 26;
};

const enigmaTransform = (value: string, secret: string) => {
  const settings = parseEnigmaSettings(secret);
  const rotorSpecs = settings.rotors.map(rotor => enigmaRotors[rotor]);
  const rings = Array.from(settings.rings).map(char => alphabet.indexOf(char));
  const positions = Array.from(settings.positions).map(char => alphabet.indexOf(char));
  let source = value.trim();
  if (source.startsWith('{')) {
    try {
      const parsed = JSON.parse(source) as Record<string, unknown>;
      if (typeof parsed.raw === 'string' && parsed.raw.trim()) source = parsed.raw.trim();
      else if (typeof parsed.output === 'string' && parsed.output.trim()) source = parsed.output.trim();
    } catch {
      // Fall back to raw text extraction.
    }
  }
  const input = source.toUpperCase().replace(/[^A-Z]/g, '');
  if (!input) throw new Error('Enigma 需要至少一个 A-Z 字母');
  const output: string[] = [];
  const plug = (char: string) => settings.plugboard.get(char) || char;

  for (const char of input) {
    const rightAtNotch = rotorSpecs[2].notches.includes(alphabet[positions[2]]);
    const middleAtNotch = rotorSpecs[1].notches.includes(alphabet[positions[1]]);
    if (middleAtNotch) positions[0] = (positions[0] + 1) % 26;
    if (rightAtNotch || middleAtNotch) positions[1] = (positions[1] + 1) % 26;
    positions[2] = (positions[2] + 1) % 26;

    let current = alphabet.indexOf(plug(char));
    for (let index = 2; index >= 0; index -= 1) current = enigmaRotorPass(current, rotorSpecs[index].wiring, positions[index], rings[index]);
    current = alphabet.indexOf(enigmaReflectors[settings.reflector][current]);
    for (let index = 0; index < 3; index += 1) current = enigmaRotorPass(current, rotorSpecs[index].wiring, positions[index], rings[index], true);
    output.push(plug(alphabet[current]));
  }

  const raw = output.join('');
  return JSON.stringify({
    output: enigmaGroup(raw),
    raw,
    inputLetters: input.length,
    settings: {
      rotors: settings.rotors.join(' '),
      reflector: settings.reflector,
      rings: settings.rings,
      initialPositions: settings.positions,
      plugboard: settings.plugboardPairs.join(' '),
    },
    note: 'Enigma 加密和解密是同一变换；保持相同设置并再次处理密文即可还原明文',
  }, null, 2);
};

const atbashTransform = (value: string) => Array.from(value).map(char => {
  const code = char.charCodeAt(0);
  if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code - 65));
  if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code - 97));
  return char;
}).join('');

const modInverse = (value: number, modulo: number) => {
  const normalized = ((value % modulo) + modulo) % modulo;
  for (let candidate = 1; candidate < modulo; candidate += 1) {
    if ((normalized * candidate) % modulo === 1) return candidate;
  }
  throw new Error(`${value} 在 mod ${modulo} 下没有乘法逆元`);
};

const affineTransform = (value: string, aValue: string, bValue: string, decode = false) => {
  const a = Number.parseInt(aValue, 10);
  const b = Number.parseInt(bValue, 10);
  if (!Number.isFinite(a) || !Number.isFinite(b)) throw new Error('Affine 参数 a/b 必须是整数');
  const aNorm = ((a % 26) + 26) % 26;
  if (![1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25].includes(aNorm)) throw new Error(`a=${a}（mod 26=${aNorm}）与 26 不互质，无法做仿射加解密`);
  const inverseA = decode ? modInverse(a, 26) : 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const x = code - base;
    const next = decode ? inverseA * (x - b) : a * x + b;
    return String.fromCharCode(base + ((((next % 26) + 26) % 26)));
  }).join('');
};

const crc32 = (value: string) => {
  let crc = 0xffffffff;
  for (const byte of utf8Encoder.encode(value)) crc = crc32Table[(crc ^ byte) & 255] ^ (crc >>> 8);
  return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0');
};

const crc16 = (value: string) => {
  let crc = 0xffff;
  for (const byte of utf8Encoder.encode(value)) crc = ((crc >>> 8) ^ crc16Table[(crc ^ byte) & 255]) & 0xffff;
  return crc.toString(16).padStart(4, '0');
};

const adler32 = (value: string) => {
  let a = 1;
  let b = 0;
  for (const byte of utf8Encoder.encode(value)) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return (((b << 16) | a) >>> 0).toString(16).padStart(8, '0');
};

const md5Bytes = (source: Uint8Array) => {
  const bitLength = source.length * 8;
  const paddedLength = (((source.length + 8) >>> 6) + 1) * 64;
  const bytes = new Uint8Array(paddedLength);
  bytes.set(source);
  bytes[source.length] = 0x80;
  const view = new DataView(bytes.buffer);
  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const shifts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const constants = Array.from({ length: 64 }, (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) >>> 0);
  const rotate = (number: number, count: number) => ((number << count) | (number >>> (32 - count))) >>> 0;

  for (let offset = 0; offset < paddedLength; offset += 64) {
    const words = Array.from({ length: 16 }, (_, index) => view.getUint32(offset + index * 4, true));
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let index = 0; index < 64; index += 1) {
      let f = 0;
      let g = 0;
      if (index < 16) {
        f = (b & c) | (~b & d);
        g = index;
      } else if (index < 32) {
        f = (d & b) | (~d & c);
        g = (5 * index + 1) % 16;
      } else if (index < 48) {
        f = b ^ c ^ d;
        g = (3 * index + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * index) % 16;
      }
      const next = d;
      d = c;
      c = b;
      b = (b + rotate((a + f + constants[index] + words[g]) >>> 0, shifts[index])) >>> 0;
      a = next;
    }

    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const digestBytes = new Uint8Array(16);
  [a0, b0, c0, d0].forEach((word, index) => {
    new DataView(digestBytes.buffer).setUint32(index * 4, word, true);
  });
  return digestBytes;
};

const md5 = (value: string) => bytesToHex(md5Bytes(utf8Encoder.encode(value)));

const md4 = (value: string) => {
  const source = utf8Encoder.encode(value);
  const bitLength = source.length * 8;
  const paddedLength = (((source.length + 8) >>> 6) + 1) * 64;
  const bytes = new Uint8Array(paddedLength);
  bytes.set(source);
  bytes[source.length] = 0x80;
  const view = new DataView(bytes.buffer);
  view.setUint32(paddedLength - 8, bitLength >>> 0, true);
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true);
  const rotate = (number: number, count: number) => ((number << count) | (number >>> (32 - count))) >>> 0;
  const f = (x: number, y: number, z: number) => (x & y) | (~x & z);
  const g = (x: number, y: number, z: number) => (x & y) | (x & z) | (y & z);
  const h = (x: number, y: number, z: number) => x ^ y ^ z;
  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  for (let offset = 0; offset < paddedLength; offset += 64) {
    const x = Array.from({ length: 16 }, (_, index) => view.getUint32(offset + index * 4, true));
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    const round1 = (k: number, s: number) => {
      const next = rotate((a + f(b, c, d) + x[k]) >>> 0, s);
      a = d; d = c; c = b; b = next;
    };
    const round2 = (k: number, s: number) => {
      const next = rotate((a + g(b, c, d) + x[k] + 0x5a827999) >>> 0, s);
      a = d; d = c; c = b; b = next;
    };
    const round3 = (k: number, s: number) => {
      const next = rotate((a + h(b, c, d) + x[k] + 0x6ed9eba1) >>> 0, s);
      a = d; d = c; c = b; b = next;
    };
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].forEach((k, index) => round1(k, [3, 7, 11, 19][index % 4]));
    [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15].forEach((k, index) => round2(k, [3, 5, 9, 13][index % 4]));
    [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15].forEach((k, index) => round3(k, [3, 9, 11, 15][index % 4]));
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }
  return [a0, b0, c0, d0].map(word => {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, word, true);
    return bytesToHex(out);
  }).join('');
};

const digest = async (value: string, algorithm: string) => {
  if (algorithm === 'md5') return md5(value);
  if (algorithm === 'crc16') return crc16(value);
  if (algorithm === 'crc32') return crc32(value);
  if (algorithm === 'adler32') return adler32(value);
  if (algorithm === 'md4') return md4(value);
  if (algorithm === 'ripemd160') return bytesToHex((await import('@noble/hashes/legacy.js')).ripemd160(utf8Encoder.encode(value)));
  if (algorithm === 'whirlpool') return (await import('whirlpool-js')).default.encSync(value);
  if (algorithm === 'sm3') return (await import('sm-crypto')).default.sm3(value);
  if (algorithm === 'blake2b-256') return bytesToHex((await import('@noble/hashes/blake2.js')).blake2b(utf8Encoder.encode(value), { dkLen: 32 }));
  if (algorithm === 'blake2b-512') return bytesToHex((await import('@noble/hashes/blake2.js')).blake2b(utf8Encoder.encode(value), { dkLen: 64 }));
  if (algorithm === 'blake2s-256') return bytesToHex((await import('@noble/hashes/blake2.js')).blake2s(utf8Encoder.encode(value), { dkLen: 32 }));
  if (algorithm === 'blake3') return bytesToHex((await import('@noble/hashes/blake3.js')).blake3(utf8Encoder.encode(value)));
  if (algorithm === 'xxhash32') return (await import('xxhashjs')).default.h32(value, 0).toString(16).padStart(8, '0');
  if (algorithm === 'xxhash64') return (await import('xxhashjs')).default.h64(value, 0).toString(16).padStart(16, '0');
  if (algorithm.startsWith('sha3-')) {
    const sha3 = await import('@noble/hashes/sha3.js');
    const map = { 'sha3-224': sha3.sha3_224, 'sha3-256': sha3.sha3_256, 'sha3-384': sha3.sha3_384, 'sha3-512': sha3.sha3_512 };
    return bytesToHex(map[algorithm as keyof typeof map](utf8Encoder.encode(value)));
  }
  if (algorithm.startsWith('keccak-')) {
    const sha3 = await import('@noble/hashes/sha3.js');
    const map = { 'keccak-256': sha3.keccak_256, 'keccak-512': sha3.keccak_512 };
    return bytesToHex(map[algorithm as keyof typeof map](utf8Encoder.encode(value)));
  }
  const map: Record<string, string> = {
    sha1: 'SHA-1',
    sha256: 'SHA-256',
    sha384: 'SHA-384',
    sha512: 'SHA-512',
  };
  const bytes = await crypto.subtle.digest(map[algorithm] || 'SHA-256', bytesToBuffer(utf8Encoder.encode(value)));
  return bytesToHex(new Uint8Array(bytes));
};

const identifyHash = (value: string) => {
  const text = value.trim();
  if (!text) throw new Error('请输入要识别的 Hash 或摘要字符串');
  type HashEntry = { name: string; hashcatMode?: number; johnFormat?: string };
  const candidates: HashEntry[] = [];
  const hexOnly = /^[0-9a-f]+$/i.test(text);
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(text)) candidates.push({ name: 'bcrypt', hashcatMode: 3200, johnFormat: 'bcrypt' });
  if (/^\$argon2(id|i|d)\$/.test(text)) candidates.push({ name: 'Argon2', hashcatMode: 13400 });
  if (/^\$[156]\$/.test(text)) candidates.push({ name: 'Unix crypt / shadow hash', hashcatMode: 1800, johnFormat: 'sha512crypt' });
  if (/^[a-f0-9]{32}:[a-f0-9]+$/i.test(text)) candidates.push({ name: 'Joomla / salted MD5-style hash', hashcatMode: 11 });
  if (hexOnly) {
    if (text.length === 4) candidates.push({ name: 'CRC16 / small checksum' });
    if (text.length === 8) candidates.push({ name: 'CRC32 / Adler32', hashcatMode: 11500, johnFormat: 'CRC32' });
    if (text.length === 32) candidates.push(
      { name: 'MD5', hashcatMode: 0, johnFormat: 'raw-md5' },
      { name: 'NTLM', hashcatMode: 1000, johnFormat: 'nt' },
      { name: 'MD4', hashcatMode: 900, johnFormat: 'raw-md4' },
    );
    if (text.length === 40) candidates.push(
      { name: 'SHA-1', hashcatMode: 100, johnFormat: 'raw-sha1' },
      { name: 'RIPEMD-160', hashcatMode: 6000 },
    );
    if (text.length === 56) candidates.push({ name: 'SHA-224', hashcatMode: 1300 });
    if (text.length === 64) candidates.push(
      { name: 'SHA-256', hashcatMode: 1400, johnFormat: 'raw-sha256' },
      { name: 'SHA3-256', hashcatMode: 17300 },
      { name: 'Keccak-256 (no padding)', hashcatMode: 17800 },
      { name: 'BLAKE2s-256', hashcatMode: 17100 },
    );
    if (text.length === 96) candidates.push({ name: 'SHA-384', hashcatMode: 10800, johnFormat: 'raw-sha384' });
    if (text.length === 128) candidates.push(
      { name: 'SHA-512', hashcatMode: 1700, johnFormat: 'raw-sha512' },
      { name: 'SHA3-512', hashcatMode: 17600 },
      { name: 'BLAKE2b-512', hashcatMode: 600 },
      { name: 'Whirlpool', hashcatMode: 6100 },
    );
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length >= 20) candidates.push({ name: 'Base64-encoded digest or token' });
  const firstCandidate = candidates[0];
  const hashcatCmd = firstCandidate?.hashcatMode !== undefined
    ? `hashcat -m ${firstCandidate.hashcatMode} '${text}' /path/to/wordlist.txt`
    : `hashcat --identify '${text}'`;
  const johnCmd = firstCandidate?.johnFormat
    ? `john --format=${firstCandidate.johnFormat} hash.txt`
    : `john --format=raw-* hash.txt  # try multiple formats`;
  return candidates.length
    ? JSON.stringify({ inputLength: text.length, candidates: candidates.map(c => c.name), hashcatMode: firstCandidate?.hashcatMode ?? null, hashcatCmd, johnCmd, crackingCommands: [`hashcat --identify '${text}'`, hashcatCmd, johnCmd, 'Use crackstation.net or hashes.com for quick lookups'] }, null, 2)
    : JSON.stringify({ inputLength: text.length, candidates: [], hashcatCmd: `hashcat --identify '${text}'`, note: '未匹配常见摘要形态，可尝试 hashid/hashcat --identify' }, null, 2);
};

const hmac = async (value: string, secret: string, algorithm: string) => {
  if (!secret) throw new Error('HMAC 需要填写密钥');
  const hash = algorithm === 'sha1' ? 'SHA-1' : algorithm === 'sha384' ? 'SHA-384' : algorithm === 'sha512' ? 'SHA-512' : 'SHA-256';
  const key = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), { name: 'HMAC', hash }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, bytesToBuffer(utf8Encoder.encode(value)));
  return bytesToHex(new Uint8Array(signature));
};

const bip39Seed = async (value: string, passphrase: string) => {
  const mnemonic = value.trim().toLowerCase().replace(/\s+/g, ' ').normalize('NFKD');
  if (!mnemonic) throw new Error('BIP39 需要输入助记词');
  const words = mnemonic.split(' ');
  const validWordCounts = new Set([12, 15, 18, 21, 24]);
  const salt = `mnemonic${passphrase || ''}`.normalize('NFKD');
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(mnemonic)), 'PBKDF2', false, ['deriveBits']);
  const seed = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: bytesToBuffer(utf8Encoder.encode(salt)), iterations: 2048, hash: 'SHA-512' },
    material,
    512,
  ));
  return JSON.stringify({
    standard: 'BIP39 mnemonic to seed',
    wordCount: words.length,
    expectedWordCount: validWordCounts.has(words.length),
    passphraseUsed: Boolean(passphrase),
    kdf: 'PBKDF2-HMAC-SHA512',
    iterations: 2048,
    seedHex: bytesToHex(seed),
    seedBase64: bytesToBase64(seed),
    note: '未内置完整 wordlist，因此这里只做规范派生，不做助记词校验和验证。',
  }, null, 2);
};

const deriveAesKey = async (secret: string, salt: Uint8Array, iterations: number) => {
  if (!secret) throw new Error('AES-GCM 需要填写口令');
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytesToBuffer(salt), iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
};

const deriveAesKeyForMode = async (secret: string, salt: Uint8Array, iterations: number, mode: 'AES-GCM' | 'AES-CBC' | 'AES-CTR') => {
  if (!secret) throw new Error(`${mode} 需要填写口令`);
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytesToBuffer(salt), iterations, hash: 'SHA-256' },
    material,
    { name: mode, length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
};

const aesEncrypt = async (value: string, secret: string, iterations: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const rounds = Math.max(10000, Number.parseInt(iterations, 10) || 120000);
  const key = await deriveAesKey(secret, salt, rounds);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: bytesToBuffer(iv) }, key, bytesToBuffer(utf8Encoder.encode(value)));
  return JSON.stringify({
    alg: 'AES-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations: rounds,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  }, null, 2);
};

const aesDecrypt = async (value: string, secret: string) => {
  const payload = JSON.parse(value);
  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const key = await deriveAesKey(secret, salt, Number(payload.iterations) || 120000);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesToBuffer(iv) }, key, bytesToBuffer(ciphertext));
  return utf8Decoder.decode(new Uint8Array(plaintext));
};

const aesEncryptCbc = async (value: string, secret: string, iterations: string) => {
  if (!secret) throw new Error('AES-CBC 需要填写口令');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const rounds = Math.max(10000, Number.parseInt(iterations, 10) || 120000);
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytesToBuffer(salt), iterations: rounds, hash: 'SHA-256' },
    material,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: bytesToBuffer(iv) }, key, bytesToBuffer(utf8Encoder.encode(value)));
  return JSON.stringify({
    alg: 'AES-CBC',
    kdf: 'PBKDF2-SHA256',
    iterations: rounds,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  }, null, 2);
};

const aesDecryptCbc = async (value: string, secret: string) => {
  if (!secret) throw new Error('AES-CBC 需要填写口令');
  const payload = JSON.parse(value);
  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const material = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: bytesToBuffer(salt), iterations: Number(payload.iterations) || 120000, hash: 'SHA-256' },
    material,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: bytesToBuffer(iv) }, key, bytesToBuffer(ciphertext));
  return utf8Decoder.decode(new Uint8Array(plaintext));
};

const concatBytes = (...chunks: Uint8Array[]) => {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
};

const opensslMagic = utf8Encoder.encode('Salted__');

const opensslEvpBytesToKey = (password: string, salt: Uint8Array) => {
  if (!password) throw new Error('OpenSSL enc 需要填写 passphrase');
  if (salt.length !== 8) throw new Error('OpenSSL Salted__ salt 必须是 8 字节');
  const passwordBytes = utf8Encoder.encode(password);
  const material: number[] = [];
  let previous = new Uint8Array();
  while (material.length < 48) {
    previous = md5Bytes(concatBytes(previous, passwordBytes, salt));
    material.push(...previous);
  }
  const derived = Uint8Array.from(material.slice(0, 48));
  return {
    key: derived.slice(0, 32),
    iv: derived.slice(32, 48),
  };
};

const parseOpenSslSaltedBlob = (value: string) => {
  let text = value.trim();
  if (text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      if (typeof parsed.opensslBase64 === 'string' && parsed.opensslBase64.trim()) text = parsed.opensslBase64.trim();
      else if (typeof parsed.opensslHex === 'string' && parsed.opensslHex.trim()) text = parsed.opensslHex.trim();
    } catch {
      // Fall through to raw text parsing.
    }
  }
  const compact = text.replace(/\s+/g, '');
  const bytes = /^[0-9a-f]+$/i.test(compact) && compact.length % 2 === 0
    ? hexToBytes(compact)
    : base64ToBytes(compact);
  if (bytes.length < 32) throw new Error('OpenSSL Salted__ 数据过短');
  const hasMagic = opensslMagic.every((byte, index) => bytes[index] === byte);
  if (!hasMagic) throw new Error('未找到 OpenSSL Salted__ 头，期望 Base64 以 U2FsdGVkX1 开头，或 hex 以 53616c7465645f5f 开头');
  return {
    salt: bytes.slice(8, 16),
    ciphertext: bytes.slice(16),
    blob: bytes,
  };
};

const importOpenSslAesCbcKey = (key: Uint8Array, usages: KeyUsage[]) => crypto.subtle.importKey(
  'raw',
  bytesToBuffer(key),
  { name: 'AES-CBC', length: 256 },
  false,
  usages,
);

const openSslAes256CbcTransform = async (direction: Direction, value: string, secret: string) => {
  if (direction === 'encode') {
    const salt = crypto.getRandomValues(new Uint8Array(8));
    const derived = opensslEvpBytesToKey(secret, salt);
    const key = await importOpenSslAesCbcKey(derived.key, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: bytesToBuffer(derived.iv) },
      key,
      bytesToBuffer(utf8Encoder.encode(value)),
    ));
    const blob = concatBytes(opensslMagic, salt, ciphertext);
    return JSON.stringify({
      format: 'OpenSSL enc Salted__',
      alg: 'AES-256-CBC',
      kdf: 'EVP_BytesToKey-MD5',
      saltHex: bytesToHex(salt),
      keyHex: bytesToHex(derived.key),
      ivHex: bytesToHex(derived.iv),
      ciphertextHex: bytesToHex(ciphertext),
      opensslBase64: bytesToBase64(blob),
      opensslHex: bytesToHex(blob),
      cliEquivalent: 'openssl enc -aes-256-cbc -salt -md md5 -base64',
      warning: 'EVP_BytesToKey-MD5 是历史兼容格式，适合 CTF/遗留样本分析；新系统应使用现代 KDF 和 AEAD',
    }, null, 2);
  }

  const parsed = parseOpenSslSaltedBlob(value);
  const derived = opensslEvpBytesToKey(secret, parsed.salt);
  const key = await importOpenSslAesCbcKey(derived.key, ['decrypt']);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: bytesToBuffer(derived.iv) },
    key,
    bytesToBuffer(parsed.ciphertext),
  ));
  return JSON.stringify({
    plaintext: utf8Decoder.decode(plaintext),
    plaintextHex: bytesToHex(plaintext),
    format: 'OpenSSL enc Salted__',
    alg: 'AES-256-CBC',
    kdf: 'EVP_BytesToKey-MD5',
    saltHex: bytesToHex(parsed.salt),
    keyHex: bytesToHex(derived.key),
    ivHex: bytesToHex(derived.iv),
    ciphertextHex: bytesToHex(parsed.ciphertext),
    inputBytes: parsed.blob.length,
  }, null, 2);
};

const aesEncryptCtr = async (value: string, secret: string, iterations: string) => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const counter = crypto.getRandomValues(new Uint8Array(16));
  const rounds = Math.max(10000, Number.parseInt(iterations, 10) || 120000);
  const key = await deriveAesKeyForMode(secret, salt, rounds, 'AES-CTR');
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CTR', counter: bytesToBuffer(counter), length: 64 }, key, bytesToBuffer(utf8Encoder.encode(value)));
  return JSON.stringify({
    alg: 'AES-CTR',
    kdf: 'PBKDF2-SHA256',
    iterations: rounds,
    salt: bytesToBase64(salt),
    counter: bytesToBase64(counter),
    length: 64,
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    warning: 'CTR 是流模式，同一 key/counter 复用会泄露明文异或关系',
  }, null, 2);
};

const aesDecryptCtr = async (value: string, secret: string) => {
  const payload = JSON.parse(value);
  const salt = base64ToBytes(payload.salt);
  const counter = base64ToBytes(payload.counter || payload.iv);
  const ciphertext = base64ToBytes(payload.ciphertext);
  const key = await deriveAesKeyForMode(secret, salt, Number(payload.iterations) || 120000, 'AES-CTR');
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-CTR', counter: bytesToBuffer(counter), length: Number(payload.length) || 64 }, key, bytesToBuffer(ciphertext));
  return utf8Decoder.decode(new Uint8Array(plaintext));
};

const loadCryptoJs = async () => (await import('crypto-js')).default;
type CryptoJsRuntime = Awaited<ReturnType<typeof loadCryptoJs>>;
type CryptoJsWordArray = ReturnType<CryptoJsRuntime['enc']['Utf8']['parse']>;
type CryptoJsCipherHelper = CryptoJsRuntime['DES'];
type StreamCipherPayload = { ciphertextHex?: string; ciphertext?: string; nonceHex?: string; nonce?: string };
type AesRawPayload = { ciphertextHex?: string; ciphertext?: string; wrappedHex?: string; wrapped?: string; ivHex?: string; iv?: string; mode?: string };
type AeadPayload = StreamCipherPayload & {
  ivHex?: string;
  iv?: string;
  sealedHex?: string;
  sealed?: string;
  tagHex?: string;
  tag?: string;
  aadHex?: string;
  aad?: string;
  associatedDataHex?: string;
  associatedData?: string;
};
type Sm4Payload = { ciphertextHex?: string; ciphertext?: string; ivHex?: string; iv?: string; mode?: string };

const parseCryptoJsWordArray = (CryptoJS: CryptoJsRuntime, value: string, labelText: string) => {
  const raw = String(value || '');
  const text = raw.trim();
  if (!text) throw new Error(`${labelText} 不能为空`);
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
    return { wordArray: CryptoJS.enc.Hex.parse(compactHex), format: 'hex' };
  }
  return { wordArray: CryptoJS.enc.Utf8.parse(raw), format: 'utf8' };
};

const optionalCryptoJsWordArray = (CryptoJS: CryptoJsRuntime, value: string, labelText: string) => {
  const text = String(value || '').trim();
  return text ? parseCryptoJsWordArray(CryptoJS, text, labelText) : null;
};

const cryptoJsWordArrayToText = (CryptoJS: CryptoJsRuntime, wordArray: CryptoJsWordArray) => {
  if (!wordArray.sigBytes) throw new Error('解密失败：密钥、IV、模式或密文可能不匹');
  try {
    return CryptoJS.enc.Utf8.stringify(wordArray);
  } catch {
    return JSON.stringify({
      plaintextHex: CryptoJS.enc.Hex.stringify(wordArray),
      note: '明文不是有效 UTF-8，已改为输出 Hex',
    }, null, 2);
  }
};

const parseCryptoJsCipherInput = (CryptoJS: CryptoJsRuntime, value: string) => {
  const text = String(value || '').trim();
  if (!text) throw new Error('密文不能为空');
  try {
    const payload = JSON.parse(text) as {
      ciphertext?: string;
      ciphertextHex?: string;
      ciphertextEncoding?: string;
      iv?: string;
      ivHex?: string;
      mode?: string;
      alg?: string;
    };
    if (payload && typeof payload === 'object' && (payload.ciphertext || payload.ciphertextHex)) {
      const ciphertextText = String(payload.ciphertextHex || payload.ciphertext).trim();
      const encoding = payload.ciphertextHex ? 'hex' : String(payload.ciphertextEncoding || '').toLowerCase();
      const ciphertext = encoding === 'hex'
        ? CryptoJS.enc.Hex.parse(ciphertextText)
        : CryptoJS.enc.Base64.parse(ciphertextText);
      return { ciphertext, payload };
    }
  } catch {
    // Fall through to raw ciphertext parsing.
  }
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  const ciphertext = compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)
    ? CryptoJS.enc.Hex.parse(compactHex)
    : CryptoJS.enc.Base64.parse(text);
  return { ciphertext, payload: null };
};

const cryptoJsCipherByOperation = (CryptoJS: CryptoJsRuntime, operationId: OperationId): { helper: CryptoJsCipherHelper; alg: string; stream: boolean } => {
  switch (operationId) {
    case 'des':
      return { helper: CryptoJS.DES, alg: 'DES', stream: false };
    case 'triple-des':
      return { helper: CryptoJS.TripleDES, alg: 'TripleDES', stream: false };
    case 'blowfish':
      return { helper: CryptoJS.Blowfish, alg: 'Blowfish', stream: false };
    case 'rabbit':
      return { helper: CryptoJS.Rabbit, alg: 'Rabbit', stream: true };
    default:
      throw new Error('不支持的 crypto-js cipher');
  }
};

const cryptoJsCipherTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput(operationId, direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const CryptoJS = await loadCryptoJs();
  const { helper, alg, stream } = cryptoJsCipherByOperation(CryptoJS, operationId);
  const variant = operationId === 'rabbit' && params.variant === 'hex' ? 'special' : params.variant;
  if (!params.secret) throw new Error(`${alg} 需要密钥或 passphrase`);

  if (variant === 'decimal') {
    if (direction === 'encode') {
      return helper.encrypt(value, params.secret).toString();
    }
    return cryptoJsWordArrayToText(CryptoJS, helper.decrypt(value.trim(), params.secret));
  }

  const key = parseCryptoJsWordArray(CryptoJS, params.secret, `${alg} key`);
  const parsedInput = direction === 'decode' ? parseCryptoJsCipherInput(CryptoJS, value) : null;
  const payloadIv = parsedInput?.payload?.ivHex || parsedInput?.payload?.iv;
  const iv = optionalCryptoJsWordArray(CryptoJS, payloadIv || params.iv, 'IV');
  const modeName = variant === 'hex' ? 'ECB' : 'CBC';
  if (!stream && modeName === 'CBC' && !iv) throw new Error(`${alg}-CBC 需要填写 IV`);

  const cipherConfig = stream
    ? (iv ? { iv: iv.wordArray } : {})
    : {
      mode: modeName === 'ECB' ? CryptoJS.mode.ECB : CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
      ...(modeName === 'CBC' && iv ? { iv: iv.wordArray } : {}),
    };

  if (direction === 'encode') {
    const encrypted = helper.encrypt(CryptoJS.enc.Utf8.parse(value), key.wordArray, cipherConfig);
    return JSON.stringify({
      alg,
      mode: stream ? 'stream' : modeName,
      kdf: 'raw',
      keyFormat: key.format,
      iv: iv ? params.iv.trim() : undefined,
      ivFormat: iv?.format,
      ciphertextEncoding: 'base64',
      ciphertext: CryptoJS.enc.Base64.stringify(encrypted.ciphertext),
    }, null, 2);
  }

  const decrypted = helper.decrypt(CryptoJS.lib.CipherParams.create({ ciphertext: parsedInput?.ciphertext }), key.wordArray, cipherConfig);
  return cryptoJsWordArrayToText(CryptoJS, decrypted);
};

const normalizeFixedBytes = (value: string, labelText: string, allowedLengths: number[]) => {
  const raw = String(value || '');
  const text = raw.trim();
  if (!text) throw new Error(`${labelText} 不能为空`);
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  const parsed = compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)
    ? { bytes: hexToBytes(compactHex), format: 'hex' }
    : { bytes: utf8Encoder.encode(raw), format: 'utf8' };
  if (allowedLengths.includes(parsed.bytes.length)) {
    return { ...parsed, normalized: false, normalizedLength: parsed.bytes.length };
  }
  const targetLength = allowedLengths.find(length => parsed.bytes.length <= length) || allowedLengths[allowedLengths.length - 1];
  const output = new Uint8Array(targetLength);
  output.set(parsed.bytes.slice(0, targetLength));
  return {
    bytes: output,
    format: `${parsed.format}-${parsed.bytes.length < targetLength ? 'zero-padded' : 'truncated'}`,
    normalized: true,
    normalizedLength: targetLength,
  };
};

const parseHexOrBase64Bytes = (value: string, labelText: string) => {
  const text = String(value || '').trim();
  if (!text) throw new Error(`${labelText} 不能为空`);
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) return hexToBytes(compactHex);
  return base64ToBytes(text);
};

const parseOptionalHexOrUtf8Bytes = (value: string) => {
  const raw = String(value || '');
  const text = raw.trim();
  if (!text) return { bytes: new Uint8Array(), format: 'empty' };
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
    return { bytes: hexToBytes(compactHex), format: 'hex' };
  }
  return { bytes: utf8Encoder.encode(raw), format: 'utf8' };
};

const parseHexBase64OrUtf8Bytes = (value: string, labelText: string) => {
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

type SymmetricInference = {
  operationId: OperationId | null;
  input: string;
  params: Record<ParamKey, string>;
  fields: Record<string, string>;
  confidence: number;
  notes: string[];
};

const chineseCtfFieldAliases: Array<[RegExp, string]> = [
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

const normalizeCtfFieldName = (value: string) => {
  const normalized = value.normalize('NFKC').toLowerCase();
  const compact = normalized.replace(/[\s_.()-]/g, '');
  for (const [pattern, alias] of chineseCtfFieldAliases) {
    if (pattern.test(compact)) return alias;
  }
  return normalized.replace(/[^a-z0-9]+/g, '');
};

const symmetricFieldAliases: Record<string, string> = {
  a: 'associatedData',
  ad: 'associatedData',
  aad: 'associatedData',
  additionaldata: 'associatedData',
  alg: 'alg',
  algorithm: 'alg',
  associateddata: 'associatedData',
  associated_data: 'associatedData',
  authtag: 'tag',
  auth_tag: 'tag',
  cipher: 'ciphertext',
  ciphertext: 'ciphertext',
  ciphertexthex: 'ciphertext',
  counter: 'iv',
  ct: 'ciphertext',
  data: 'ciphertext',
  enc: 'ciphertext',
  encrypted: 'ciphertext',
  encrypteddata: 'ciphertext',
  iv: 'iv',
  ivhex: 'iv',
  key: 'key',
  keyhex: 'key',
  keyword: 'key',
  keyword1: 'key',
  keyword2: 'keyword2',
  mac: 'tag',
  mode: 'mode',
  nonce: 'nonce',
  noncehex: 'nonce',
  password: 'key',
  passphrase: 'key',
  plaintext: 'plaintext',
  plain: 'plaintext',
  knownplaintext: 'knownPlaintext',
  known_plaintext: 'knownPlaintext',
  salt: 'salt',
  sealed: 'sealed',
  sealedhex: 'sealed',
  secret: 'key',
  tag: 'tag',
  taghex: 'tag',
};

const normalizeSymmetricFieldName = (value: string) => symmetricFieldAliases[normalizeCtfFieldName(value)] || null;

const stripTrailingUnbalancedDelimiter = (value: string, open: string, close: string) => {
  let result = value;
  const countDelimiter = (text: string, delimiter: string) => (
    Array.from(text).reduce((count, char) => count + Number(char === delimiter), 0)
  );

  while (result.endsWith(close) && countDelimiter(result, close) > countDelimiter(result, open)) {
    result = result.slice(0, -1).trimEnd().replace(/[,;]+$/g, '').trimEnd();
  }

  return result;
};

const cleanLooseFieldValue = (value: unknown) => {
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

const cleanSymmetricFieldValue = (value: unknown) => cleanLooseFieldValue(value);

const rememberSymmetricField = (fields: Record<string, string>, rawKey: string, rawValue: unknown) => {
  const key = normalizeSymmetricFieldName(rawKey);
  if (!key) return;
  const value = cleanSymmetricFieldValue(rawValue);
  if (value && !fields[key]) fields[key] = value;
};

const flattenSymmetricJson = (fields: Record<string, string>, value: unknown, prefix = '') => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const fieldName = prefix ? `${prefix}_${key}` : key;
    if (typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean') {
      rememberSymmetricField(fields, fieldName, entry);
      rememberSymmetricField(fields, key, entry);
    } else if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
      flattenSymmetricJson(fields, entry, fieldName);
    }
  }
};

const parseSymmetricFields = (value: string) => {
  const fields: Record<string, string> = {};
  try {
    flattenSymmetricJson(fields, JSON.parse(value));
  } catch {
    // Fall through to CTF writeup / Python output style parsing.
  }
  const text = value.normalize('NFKC').replace(/\r\n/g, '\n');
  for (const line of text.split('\n')) {
    const lineField = line.match(/^\s*([^:=\r\n]{1,80}?)\s*[:=]\s*(.+?)\s*$/u);
    if (lineField && normalizeSymmetricFieldName(lineField[1])) {
      rememberSymmetricField(fields, lineField[1], lineField[2]);
    }
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*b?(['"`])([\s\S]*?)\2/g)) {
    rememberSymmetricField(fields, match[1], match[3]);
  }
  for (const match of text.matchAll(/\b([A-Za-z][A-Za-z0-9_. -]{0,40})\s*[:=]\s*(0x[0-9a-fA-F:_-]+|(?:\\x[0-9a-fA-F]{2})+|[A-Za-z0-9+/_=-]{1,})/g)) {
    rememberSymmetricField(fields, match[1], match[2]);
  }
  return fields;
};

const normalizeLooseFieldName = (value: string) => normalizeCtfFieldName(value);
const looseSingleCharTokens = new Set(['a', 'b', 'c', 'd', 'e', 'g', 'h', 'k', 'm', 'n', 'p', 'q', 'r', 's', 'u', 'v', 'x', 'y', 'z']);
const isArithmeticFieldMatch = (source: string, index: number) => {
  let cursor = index - 1;
  while (cursor >= 0 && /\s/.test(source[cursor])) cursor -= 1;
  return cursor >= 0 && /[+\-*/(]/.test(source[cursor]);
};

const rememberLooseField = (fields: Record<string, string>, rawKey: string, rawValue: unknown) => {
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

const flattenLooseJson = (fields: Record<string, string>, value: unknown, prefix = '') => {
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

const parseLooseCtfFields = (value: string) => {
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

const looseField = (fields: Record<string, string>, aliases: string[]) => {
  for (const alias of aliases) {
    const value = fields[normalizeLooseFieldName(alias)];
    if (value) return value;
  }
  return '';
};

const parseLooseIndexedRecords = (
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

const parseLooseObjectBlocks = (value: string, maxBlocks = 80) => {
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

const normalizeLooseBytesLabel = (value: string) => cleanSymmetricFieldValue(value).toLowerCase().replace(/\s+/g, '');

const parseSymmetricFieldBytes = (value: string, labelText: string) => {
  const text = cleanSymmetricFieldValue(value);
  if (/^(?:\\x[0-9a-fA-F]{2})+$/.test(text)) return hexToBytes(text.replace(/\\x/g, ''));
  return parseHexBase64OrUtf8Bytes(text, labelText).bytes;
};

const symmetricFieldHex = (value: string | undefined, labelText: string) => (
  value ? bytesToHex(parseSymmetricFieldBytes(value, labelText)) : undefined
);

const parsePythonAssignmentFields = (value: string) => {
  const fields: Record<string, string> = {};
  for (const line of value.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.+?)\s*$/);
    if (!match) continue;
    const key = normalizeLooseFieldName(match[1]);
    if (!key || !match[2]) continue;
    fields[key] = match[2].trim();
  }
  return fields;
};

const extractNamedPythonCall = (value: string, marker: string) => {
  const start = value.indexOf(marker);
  if (start < 0) return '';
  let depth = 0;
  let quote = '';
  let escaped = false;
  for (let index = start; index < value.length; index += 1) {
    const char = value[index];
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === '\\') {
        escaped = true;
        continue;
      }
      if (char === quote) quote = '';
      continue;
    }
    if (char === '"' || char === '\'') {
      quote = char;
      continue;
    }
    if (char === '(') {
      depth += 1;
      continue;
    }
    if (char === ')') {
      depth -= 1;
      if (depth === 0) return value.slice(start, index + 1);
      continue;
    }
  }
  return '';
};

const stripPythonKwargPrefix = (value: string, names: string[]) => {
  const text = String(value || '').trim();
  const match = text.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/);
  if (!match) return text;
  return names.includes(match[1].toLowerCase()) ? match[2].trim() : text;
};

const parsePythonCiphertextBytes = (
  value: string,
  fields: Record<string, string> = {},
  seen = new Set<string>(),
): Uint8Array | null => {
  const text = String(value || '').trim();
  if (!text) return null;

  const call = parseFunctionLikeCall(text);
  if (call) {
    const callable = normalizeLooseFieldName(call.name);
    if (callable === 'b64decode' || callable.endsWith('b64decode')) {
      if (!call.args.length) return null;
      const source = parsePythonTextLikeValue(call.args[0], fields, seen);
      if (source == null) return null;
      try {
        return base64ToBytes(source);
      } catch {
        return null;
      }
    }
  }

  const pythonBytes = parsePythonByteLikeValue(text, fields, seen);
  if (pythonBytes) return pythonBytes;

  const source = parsePythonTextLikeValue(text, fields, seen);
  if (source == null) return null;
  try {
    return parseHexOrBase64Bytes(source, 'ciphertext');
  } catch {
    return utf8Encoder.encode(source);
  }
};

const inferPythonSymmetricSnippet = (
  value: string,
  baseParams: Record<ParamKey, string>,
): SymmetricInference | null => {
  if (!/(?:AES|ChaCha20|ChaCha20_Poly1305|Salsa20)\.new\s*\(/i.test(value)) return null;
  const assignmentFields = parsePythonAssignmentFields(value);
  const newCallMarker = value.match(/[A-Za-z0-9_.]+\.new\s*\(/)?.[0] || '';
  const cipherCallText = newCallMarker ? extractNamedPythonCall(value, newCallMarker.replace(/\s*$/, '')) : '';
  const cipherCall = cipherCallText ? parseFunctionLikeCall(cipherCallText) : null;
  if (!cipherCall) return null;
  const normalizedCall = normalizeLooseFieldName(cipherCall.name);
  const modeArg = cipherCall.args[1]?.toLowerCase() || '';
  const operationId = normalizedCall === 'aesnew'
    ? (/mode[_\s.]*cbc/.test(modeArg)
      ? 'aes-cbc-raw'
      : /mode[_\s.]*ecb/.test(modeArg)
        ? 'aes-ecb'
        : /mode[_\s.]*ctr/.test(modeArg)
          ? 'aes-ctr-raw'
          : /mode[_\s.]*cfb/.test(modeArg)
            ? 'aes-cfb'
            : /mode[_\s.]*ofb/.test(modeArg)
              ? 'aes-ofb'
              : /mode[_\s.]*gcm/.test(modeArg)
                ? 'aes-gcm'
                : null)
    : normalizedCall === 'chacha20new'
      ? 'chacha20-orig'
      : normalizedCall === 'chacha20poly1305new'
        ? 'chacha20-poly1305'
      : normalizedCall === 'salsa20new'
        ? 'salsa20'
      : null;
  if (!operationId) return null;

  const keyArg = stripPythonKwargPrefix(cipherCall.args[0], ['key']);
  const keyBytes = parsePythonByteLikeValue(keyArg, assignmentFields);
  if (!keyBytes) return null;

  const ivArg = cipherCall.args.slice(1).find(arg => /^(?:iv|nonce)\s*=/.test(arg))?.replace(/^(?:iv|nonce)\s*=\s*/, '')
    || cipherCall.args[2]
    || '';
  const ivBytes = ivArg ? parsePythonByteLikeValue(ivArg, assignmentFields) : null;

  const ciphertextExpression = assignmentFields.ct || assignmentFields.ciphertext || assignmentFields.enc || assignmentFields.data || '';
  const ciphertextBytes = ciphertextExpression ? (
    parsePythonCiphertextBytes(ciphertextExpression, assignmentFields)
    || (() => {
      const sourceText = parsePythonTextLikeValue(ciphertextExpression, assignmentFields);
      if (sourceText == null) return null;
      try {
        return parseHexOrBase64Bytes(sourceText, 'ciphertext');
      } catch {
        return utf8Encoder.encode(sourceText);
      }
    })()
  ) : null;
  if (!ciphertextBytes) return null;
  const tagExpression = assignmentFields.tag || assignmentFields.authtag || '';
  const tagBytes = tagExpression ? (
    parsePythonCiphertextBytes(tagExpression, assignmentFields)
    || (() => {
      const sourceText = parsePythonTextLikeValue(tagExpression, assignmentFields);
      if (sourceText == null) return null;
      try {
        return parseHexOrBase64Bytes(sourceText, 'tag');
      } catch {
        return utf8Encoder.encode(sourceText);
      }
    })()
  ) : null;

  const params = { ...baseParams };
  params.secret = bytesToHex(keyBytes);
  if (ivBytes?.length) params.iv = bytesToHex(ivBytes);
  params.variant = 'special';

  const input = JSON.stringify({
    ciphertextHex: bytesToHex(ciphertextBytes),
    ...(ivBytes?.length ? { ivHex: bytesToHex(ivBytes) } : {}),
    ...(tagBytes?.length ? { tagHex: bytesToHex(tagBytes) } : {}),
  });

  return {
    operationId,
    input,
    params,
    fields: {
      key: bytesToHex(keyBytes),
      ...(ivBytes?.length ? { iv: bytesToHex(ivBytes) } : {}),
      ciphertext: bytesToHex(ciphertextBytes),
      ...(tagBytes?.length ? { tag: bytesToHex(tagBytes) } : {}),
      mode: modeArg,
    },
    confidence: 12,
    notes: [
      `python snippet detected: ${operationId}`,
      'parsed key/iv/ciphertext from AES.new(...) style script',
    ],
  };
};

const detectSymmetricOperationHint = (value: string, fields: Record<string, string>): OperationId | null => {
  const text = `${fields.alg || ''} ${fields.mode || ''} ${value}`.toLowerCase();
  if (/xchacha20[\s_-]*poly1305/.test(text)) return 'xchacha20-poly1305';
  if (/chacha20[\s_-]*poly1305/.test(text)) return 'chacha20-poly1305';
  if (/xsalsa20[\s_-]*poly1305|secretbox/.test(text)) return 'xsalsa20-poly1305';
  if (/aes[\s_-]*gcm[\s_-]*siv|gcmsiv/.test(text)) return 'aes-gcm-siv';
  if (/aes[\s_-]*siv/.test(text)) return 'aes-siv';
  if (/aes[\s_-]*gcm/.test(text)) return 'aes-gcm';
  if (/aes/.test(text) && /\becb\b/.test(text)) return 'aes-ecb';
  if (/aes/.test(text) && /\bcbc\b/.test(text)) return 'aes-cbc-raw';
  if (/aes/.test(text) && /\bctr\b/.test(text)) return 'aes-ctr-raw';
  if (/aes/.test(text) && /\bcfb\b/.test(text)) return 'aes-cfb';
  if (/aes/.test(text) && /\bofb\b/.test(text)) return 'aes-ofb';
  if (/\bxchacha20\b/.test(text)) return 'xchacha20';
  if (/\bchacha20\b/.test(text)) return 'chacha20';
  if (/\bxsalsa20\b/.test(text)) return 'xsalsa20';
  if (/\bsalsa20\b/.test(text)) return 'salsa20';
  if (/\bsm4\b/.test(text)) return 'sm4';
  if (/\b3des\b|triple[\s_-]*des/.test(text)) return 'triple-des';
  if (/\bdes\b/.test(text)) return 'des';
  if (/\bblowfish\b/.test(text)) return 'blowfish';
  if (/\brabbit\b/.test(text)) return 'rabbit';
  return null;
};

const buildSymmetricPayload = (operationId: OperationId, fields: Record<string, string>, fallbackValue: string) => {
  const payload: Record<string, string> = {};
  const nonceSource = fields.nonce || fields.iv;
  if (fields.mode) payload.mode = fields.mode.toLowerCase();
  if (fields.associatedData) payload.aadHex = symmetricFieldHex(fields.associatedData, 'AAD') || '';

  if (operationId === 'aes-gcm' || isNobleAeadOperation(operationId)) {
    if (nonceSource) payload.nonceHex = symmetricFieldHex(nonceSource, 'nonce') || '';
    if (fields.iv) payload.ivHex = symmetricFieldHex(fields.iv, 'iv') || '';
    if (fields.sealed) payload.sealedHex = symmetricFieldHex(fields.sealed, 'sealed ciphertext') || '';
    if (fields.ciphertext) payload.ciphertextHex = symmetricFieldHex(fields.ciphertext, 'ciphertext') || '';
    if (fields.tag) payload.tagHex = symmetricFieldHex(fields.tag, 'authentication tag') || '';
  } else {
    if (fields.iv || nonceSource) payload.ivHex = symmetricFieldHex(fields.iv || nonceSource, 'iv') || '';
    if (fields.ciphertext) payload.ciphertextHex = symmetricFieldHex(fields.ciphertext, 'ciphertext') || '';
  }

  if (!payload.ciphertextHex && !payload.sealedHex) return fallbackValue;
  return JSON.stringify(payload);
};

const inferSymmetricCryptoFromText = (
  value: string,
  forcedOperationId: OperationId | null = null,
  baseParams: Record<ParamKey, string> = defaultParams,
): SymmetricInference => {
  if (!forcedOperationId) {
    const pythonSnippet = inferPythonSymmetricSnippet(value, baseParams);
    if (pythonSnippet) return pythonSnippet;
  }
  const fields = parseSymmetricFields(value);
  const operationId = forcedOperationId || detectSymmetricOperationHint(value, fields);
  const params = { ...baseParams };
  const notes: string[] = [];
  let confidence = Object.keys(fields).length;

  if (fields.key) {
    params.secret = fields.key;
    confidence += 2;
    notes.push('parsed key/secret from challenge text');
  }
  if (fields.iv || fields.nonce) {
    params.iv = fields.iv || fields.nonce;
    confidence += 1;
    notes.push(fields.nonce ? 'parsed nonce from challenge text' : 'parsed IV/counter from challenge text');
  }
  if (fields.associatedData) {
    params.associatedData = fields.associatedData;
    confidence += 1;
    notes.push('parsed AAD/associated data from challenge text');
  }
  if (operationId) {
    confidence += 3;
    notes.push(`operation hint: ${operationId}`);
  }
  if (fields.ciphertext || fields.sealed) confidence += 2;
  if (fields.tag) confidence += 1;
  if (operationId === 'sm4' && fields.mode) params.variant = fields.mode.toLowerCase() === 'ecb' ? 'hex' : 'special';

  const input = operationId ? buildSymmetricPayload(operationId, fields, value) : value;
  return { operationId, input, params, fields, confidence, notes };
};

const prepareSymmetricDecodeInput = (
  operationId: OperationId,
  direction: Direction,
  value: string,
  params: Record<ParamKey, string>,
) => direction === 'decode'
  ? inferSymmetricCryptoFromText(value, operationId, params)
  : { operationId, input: value, params, fields: {}, confidence: 0, notes: [] };

const bytesToUtf8OrHexJson = (bytes: Uint8Array) => {
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    return JSON.stringify({
      plaintextHex: bytesToHex(bytes),
      note: '明文不是有效 UTF-8，已改为输出 Hex',
    }, null, 2);
  }
};

const aesGcmTransform = async (direction: Direction, value: string, params: Record<ParamKey, string>) => {
  if (direction === 'encode') return aesEncrypt(value, params.secret, params.iterations);
  const inferred = inferSymmetricCryptoFromText(value, 'aes-gcm', params);
  try {
    const payload = JSON.parse(inferred.input) as AeadPayload & { key?: string; keyHex?: string };
    if (!('salt' in payload) && (payload.ivHex || payload.iv || payload.nonceHex || payload.nonce) && (payload.sealedHex || payload.sealed || payload.ciphertextHex || payload.ciphertext)) {
      const keySource = inferred.params.secret || payload.keyHex || payload.key;
      const key = normalizeFixedBytes(keySource || '', 'AES-GCM key', [16, 24, 32]);
      const ivSource = payload.ivHex || payload.iv || payload.nonceHex || payload.nonce || '';
      const iv = parseSymmetricFieldBytes(ivSource, 'AES-GCM IV');
      const aadSource = payload.aadHex || payload.associatedDataHex || payload.aad || payload.associatedData || inferred.params.associatedData;
      const aad = aadSource ? parseSymmetricFieldBytes(aadSource, 'AES-GCM AAD') : new Uint8Array();
      const sealed = payload.sealedHex || payload.sealed
        ? parseSymmetricFieldBytes(payload.sealedHex || payload.sealed || '', 'AES-GCM sealed ciphertext')
        : concatBytes(
          parseSymmetricFieldBytes(payload.ciphertextHex || payload.ciphertext || '', 'AES-GCM ciphertext'),
          payload.tagHex || payload.tag ? parseSymmetricFieldBytes(payload.tagHex || payload.tag || '', 'AES-GCM tag') : new Uint8Array(),
        );
      const cryptoKey = await crypto.subtle.importKey('raw', bytesToBuffer(key.bytes), { name: 'AES-GCM' }, false, ['decrypt']);
      const options: AesGcmParams = { name: 'AES-GCM', iv: bytesToBuffer(iv) };
      if (aad.length) options.additionalData = bytesToBuffer(aad);
      const plaintext = new Uint8Array(await crypto.subtle.decrypt(options, cryptoKey, bytesToBuffer(sealed)));
      return bytesToUtf8OrHexJson(plaintext);
    }
  } catch {
    // Fall through to the PBKDF2 JSON format used by this tool's AES-GCM operation.
  }
  return aesDecrypt(value, params.secret);
};

const nobleStreamSpec = (operationId: OperationId) => {
  switch (operationId) {
    case 'chacha20-orig':
      return { alg: 'ChaCha20 (8-byte nonce)', keyLengths: [32], nonceLength: 8 };
    case 'chacha20':
      return { alg: 'ChaCha20', keyLengths: [32], nonceLength: 12 };
    case 'xchacha20':
      return { alg: 'XChaCha20', keyLengths: [32], nonceLength: 24 };
    case 'salsa20':
      return { alg: 'Salsa20', keyLengths: [16, 32], nonceLength: 8 };
    case 'xsalsa20':
      return { alg: 'XSalsa20', keyLengths: [32], nonceLength: 24 };
    default:
      throw new Error('不支持的 noble stream cipher');
  }
};

const nobleStreamCipherBytes = async (operationId: OperationId, key: Uint8Array, nonce: Uint8Array, data: Uint8Array) => {
  if (operationId === 'chacha20-orig' || operationId === 'chacha20' || operationId === 'xchacha20') {
    const { chacha20orig, chacha20, xchacha20 } = await import('@noble/ciphers/chacha.js');
    if (operationId === 'chacha20-orig') return chacha20orig(key, nonce, data);
    return operationId === 'chacha20' ? chacha20(key, nonce, data) : xchacha20(key, nonce, data);
  }
  const { salsa20, xsalsa20 } = await import('@noble/ciphers/salsa.js');
  return operationId === 'salsa20' ? salsa20(key, nonce, data) : xsalsa20(key, nonce, data);
};

const nobleStreamTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput(operationId, direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const spec = nobleStreamSpec(operationId);
  const key = normalizeFixedBytes(params.secret, `${spec.alg} key`, spec.keyLengths);
  let payload: StreamCipherPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as StreamCipherPayload;
    } catch {
      payload = null;
    }
  }
  const nonceSource = direction === 'encode'
    ? params.iv || bytesToHex(crypto.getRandomValues(new Uint8Array(spec.nonceLength)))
    : payload?.nonceHex || payload?.nonce || params.iv;
  const nonce = normalizeFixedBytes(nonceSource || '', `${spec.alg} nonce`, [spec.nonceLength]);
  const inputBytes = direction === 'encode'
    ? utf8Encoder.encode(value)
    : parseHexOrBase64Bytes(payload?.ciphertextHex || payload?.ciphertext || value, '密文');
  const output = await nobleStreamCipherBytes(operationId, key.bytes, nonce.bytes, inputBytes);
  if (direction === 'decode') return bytesToUtf8OrHexJson(output);
  return JSON.stringify({
    alg: spec.alg,
    mode: 'xor-stream',
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    nonceHex: bytesToHex(nonce.bytes),
    nonceFormat: nonce.format,
    ciphertextEncoding: 'hex',
    ciphertextHex: bytesToHex(output),
    warning: 'XOR 流密码在同一 key/nonce 下复用会泄露明文关系',
  }, null, 2);
};

type NobleAeadSpec = {
  alg: string;
  keyLengths: number[];
  nonceLength: number | null;
  tagLength: number;
  supportsAad: boolean;
};

const nobleAeadSpec = (operationId: OperationId): NobleAeadSpec => {
  switch (operationId) {
    case 'aes-gcm-siv':
      return { alg: 'AES-GCM-SIV', keyLengths: [16, 24, 32], nonceLength: 12, tagLength: 16, supportsAad: true };
    case 'aes-siv':
      return { alg: 'AES-SIV', keyLengths: [32, 48, 64], nonceLength: null, tagLength: 16, supportsAad: true };
    case 'chacha20-poly1305':
      return { alg: 'ChaCha20-Poly1305', keyLengths: [32], nonceLength: 12, tagLength: 16, supportsAad: true };
    case 'xchacha20-poly1305':
      return { alg: 'XChaCha20-Poly1305', keyLengths: [32], nonceLength: 24, tagLength: 16, supportsAad: true };
    case 'xsalsa20-poly1305':
      return { alg: 'XSalsa20-Poly1305 / secretbox', keyLengths: [32], nonceLength: 24, tagLength: 16, supportsAad: false };
    default:
      throw new Error('不支持的 noble AEAD cipher');
  }
};

const nobleAeadCipherBytes = async (
  operationId: OperationId,
  direction: Direction,
  key: Uint8Array,
  nonce: Uint8Array | null,
  aad: Uint8Array,
  data: Uint8Array,
) => {
  if (operationId === 'aes-gcm-siv') {
    if (!nonce) throw new Error('AES-GCM-SIV requires a 12-byte nonce');
    const { gcmsiv } = await import('@noble/ciphers/aes.js');
    const cipher = gcmsiv(key, nonce, aad.length ? aad : undefined);
    return direction === 'encode' ? cipher.encrypt(data) : cipher.decrypt(data);
  }
  if (operationId === 'aes-siv') {
    const { aessiv } = await import('@noble/ciphers/aes.js');
    const aadComponents = [
      ...(aad.length ? [aad] : []),
      ...(nonce?.length ? [nonce] : []),
    ];
    const cipher = aessiv(key, ...aadComponents);
    return direction === 'encode' ? cipher.encrypt(data) : cipher.decrypt(data);
  }
  if (!nonce) throw new Error('AEAD nonce is required');
  if (operationId === 'chacha20-poly1305' || operationId === 'xchacha20-poly1305') {
    const { chacha20poly1305, xchacha20poly1305 } = await import('@noble/ciphers/chacha.js');
    const cipher = operationId === 'chacha20-poly1305'
      ? chacha20poly1305(key, nonce, aad.length ? aad : undefined)
      : xchacha20poly1305(key, nonce, aad.length ? aad : undefined);
    return direction === 'encode' ? cipher.encrypt(data) : cipher.decrypt(data);
  }
  if (aad.length) throw new Error('XSalsa20-Poly1305 / secretbox 不支持 AAD');
  const { xsalsa20poly1305 } = await import('@noble/ciphers/salsa.js');
  const cipher = xsalsa20poly1305(key, nonce);
  return direction === 'encode' ? cipher.encrypt(data) : cipher.decrypt(data);
};

const nobleAeadTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput(operationId, direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const spec = nobleAeadSpec(operationId);
  const key = normalizeFixedBytes(params.secret, `${spec.alg} key`, spec.keyLengths);
  let payload: AeadPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as AeadPayload;
    } catch {
      payload = null;
    }
  }
  const nonceSource = spec.nonceLength === null
    ? (direction === 'encode' ? params.iv : payload?.nonceHex || payload?.nonce || params.iv)
    : (direction === 'encode'
      ? params.iv || bytesToHex(crypto.getRandomValues(new Uint8Array(spec.nonceLength)))
      : payload?.nonceHex || payload?.nonce || params.iv);
  const nonce = spec.nonceLength === null
    ? parseOptionalHexOrUtf8Bytes(nonceSource || '')
    : normalizeFixedBytes(nonceSource || '', `${spec.alg} nonce`, [spec.nonceLength]);
  const nonceBytes = spec.nonceLength === null && nonce.bytes.length === 0 ? null : nonce.bytes;
  const payloadAadSource = payload?.aadHex || payload?.associatedDataHex || payload?.aad || payload?.associatedData;
  const aadSource = spec.supportsAad
    ? (direction === 'encode' ? params.associatedData : payloadAadSource || params.associatedData)
    : payloadAadSource;
  const aad = parseOptionalHexOrUtf8Bytes(aadSource || '');
  if (!spec.supportsAad && aad.bytes.length) throw new Error(`${spec.alg} 不支持 AAD`);
  const sealedSource = payload?.sealedHex || payload?.sealed || (
    payload?.ciphertextHex && payload?.tagHex
      ? `${payload.ciphertextHex}${payload.tagHex}`
      : payload?.ciphertextHex || payload?.ciphertext || value
  );
  const inputBytes = direction === 'encode'
    ? utf8Encoder.encode(value)
    : parseHexOrBase64Bytes(sealedSource, 'ciphertext+tag');
  if (direction === 'decode' && inputBytes.length < spec.tagLength) {
    throw new Error(`${spec.alg} 密文至少需要包含 ${spec.tagLength} 字节 authentication tag`);
  }
  const output = await nobleAeadCipherBytes(operationId, direction, key.bytes, nonceBytes, aad.bytes, inputBytes);
  if (direction === 'decode') return bytesToUtf8OrHexJson(output);
  const ciphertext = output.slice(0, Math.max(0, output.length - spec.tagLength));
  const tag = output.slice(Math.max(0, output.length - spec.tagLength));
  return JSON.stringify({
    alg: spec.alg,
    mode: 'aead',
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    nonceHex: nonceBytes ? bytesToHex(nonceBytes) : undefined,
    nonceFormat: nonce.format,
    nonceRole: operationId === 'aes-siv' && nonceBytes ? 'final-aad-component' : undefined,
    aadEncoding: aad.format,
    aadHex: aad.bytes.length ? bytesToHex(aad.bytes) : undefined,
    sealedEncoding: 'hex',
    sealedHex: bytesToHex(output),
    ciphertextEncoding: 'hex',
    ciphertextHex: bytesToHex(ciphertext),
    tagHex: bytesToHex(tag),
    tagBytes: spec.tagLength,
    warning: operationId === 'aes-gcm-siv' || operationId === 'aes-siv'
      ? 'SIV AEAD is nonce-misuse resistant, but identical key/input/AAD can still produce linkable output; decrypt failure usually means key, nonce/AAD, or tag mismatch.'
      : 'AEAD 在同一 key/nonce 下复用会破坏认证安全；解密失败通常表示 key、nonce、AAD 或 tag 不匹配',
  }, null, 2);
};

const aesRawBlockTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput(operationId, direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const { cbc, cfb, ctr, ecb } = await import('@noble/ciphers/aes.js');
  const alg = operationId === 'aes-ecb'
    ? 'AES-ECB'
    : operationId === 'aes-cbc-raw'
      ? 'AES-CBC Raw'
      : operationId === 'aes-ctr-raw'
        ? 'AES-CTR Raw'
        : 'AES-CFB';
  const mode = operationId === 'aes-ecb'
    ? 'ECB'
    : operationId === 'aes-cbc-raw'
      ? 'CBC'
      : operationId === 'aes-ctr-raw'
        ? 'CTR'
        : 'CFB-128';
  const key = normalizeFixedBytes(params.secret, `${alg} key`, [16, 24, 32]);
  const disablePadding = (operationId === 'aes-ecb' || operationId === 'aes-cbc-raw') && params.variant === 'hex';
  let payload: AesRawPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as AesRawPayload;
    } catch {
      payload = null;
    }
  }
  const ivSource = payload?.ivHex || payload?.iv || params.iv;
  const iv = operationId === 'aes-ecb' ? null : normalizeFixedBytes(ivSource || '', `${alg} IV/counter`, [16]);
  const makeCipher = () => {
    if (operationId === 'aes-ecb') return ecb(key.bytes, { disablePadding });
    if (operationId === 'aes-cbc-raw') return cbc(key.bytes, iv?.bytes || new Uint8Array(16), { disablePadding });
    if (operationId === 'aes-ctr-raw') return ctr(key.bytes, iv?.bytes || new Uint8Array(16));
    return cfb(key.bytes, iv?.bytes || new Uint8Array(16));
  };
  const inputBytes = direction === 'encode'
    ? (disablePadding ? parseHexBase64OrUtf8Bytes(value, 'plaintext').bytes : utf8Encoder.encode(value))
    : parseHexOrBase64Bytes(payload?.ciphertextHex || payload?.ciphertext || value, '密文');
  const output = direction === 'encode' ? makeCipher().encrypt(inputBytes) : makeCipher().decrypt(inputBytes);
  if (direction === 'decode') return bytesToUtf8OrHexJson(output);
  return JSON.stringify({
    alg,
    mode,
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    ivHex: iv ? bytesToHex(iv.bytes) : undefined,
    ivFormat: iv?.format,
    padding: operationId === 'aes-ecb' || operationId === 'aes-cbc-raw' ? (disablePadding ? 'none' : 'pkcs7') : 'none',
    ciphertextEncoding: 'hex',
    ciphertextHex: bytesToHex(output),
    warning: operationId === 'aes-ecb'
      ? 'ECB leaks repeated plaintext block patterns and should only be used for CTF recovery or legacy compatibility.'
      : operationId === 'aes-ctr-raw'
        ? 'CTR is a stream mode; reusing the same key/counter leaks plaintext XOR relationships.'
        : 'This AES mode is unauthenticated; validate recovered plaintext with a MAC, checksum, format marker, or known plaintext.',
  }, null, 2);
};

const aesOfbTransform = async (direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput('aes-ofb', direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const CryptoJS = await loadCryptoJs();
  const key = normalizeFixedBytes(params.secret, 'AES-OFB key', [16, 24, 32]);
  let payload: AesRawPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as AesRawPayload;
    } catch {
      payload = null;
    }
  }
  const ivSource = payload?.ivHex || payload?.iv || params.iv;
  const iv = normalizeFixedBytes(ivSource || '', 'AES-OFB IV', [16]);
  const keyWord = CryptoJS.enc.Hex.parse(bytesToHex(key.bytes));
  const ivWord = CryptoJS.enc.Hex.parse(bytesToHex(iv.bytes));
  const cipherConfig = { mode: CryptoJS.mode.OFB, padding: CryptoJS.pad.NoPadding, iv: ivWord };

  if (direction === 'encode') {
    const encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(value), keyWord, cipherConfig);
    return JSON.stringify({
      alg: 'AES-OFB',
      mode: 'OFB',
      keyFormat: key.format,
      keyLength: key.normalizedLength,
      ivHex: bytesToHex(iv.bytes),
      ivFormat: iv.format,
      padding: 'none',
      ciphertextEncoding: 'hex',
      ciphertextHex: CryptoJS.enc.Hex.stringify(encrypted.ciphertext),
      warning: 'OFB is a stream mode; reusing the same key/IV leaks plaintext XOR relationships.',
    }, null, 2);
  }

  const ciphertextBytes = parseHexOrBase64Bytes(payload?.ciphertextHex || payload?.ciphertext || value, 'ciphertext');
  const ciphertext = CryptoJS.enc.Hex.parse(bytesToHex(ciphertextBytes));
  const decrypted = CryptoJS.AES.decrypt(CryptoJS.lib.CipherParams.create({ ciphertext }), keyWord, cipherConfig);
  return cryptoJsWordArrayToText(CryptoJS, decrypted);
};

const aesKeyWrapTransform = async (operationId: OperationId, direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const { aeskw, aeskwp } = await import('@noble/ciphers/aes.js');
  const alg = operationId === 'aes-kw' ? 'AES-KW' : 'AES-KWP';
  const key = normalizeFixedBytes(params.secret, `${alg} KEK`, [16, 24, 32]);
  let payload: AesRawPayload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as AesRawPayload;
    } catch {
      payload = null;
    }
  }
  const cipher = operationId === 'aes-kw' ? aeskw(key.bytes) : aeskwp(key.bytes);
  const inputBytes = direction === 'encode'
    ? parseHexBase64OrUtf8Bytes(value, 'key material')
    : { bytes: parseHexOrBase64Bytes(payload?.wrappedHex || payload?.wrapped || payload?.ciphertextHex || payload?.ciphertext || value, 'wrapped key'), format: 'hex/base64' };
  const output = direction === 'encode' ? cipher.encrypt(inputBytes.bytes) : cipher.decrypt(inputBytes.bytes);
  if (direction === 'decode') {
    return JSON.stringify({
      alg,
      keyFormat: key.format,
      unwrappedEncoding: 'hex',
      unwrappedHex: bytesToHex(output),
      unwrappedBase64: bytesToBase64(output),
      unwrappedUtf8: utf8Decoder.decode(output),
    }, null, 2);
  }
  return JSON.stringify({
    alg,
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    inputEncoding: inputBytes.format,
    inputLength: inputBytes.bytes.length,
    wrappedEncoding: 'hex',
    wrappedHex: bytesToHex(output),
    wrappedBase64: bytesToBase64(output),
  }, null, 2);
};

const aesCmacTransform = async (value: string, params: Record<ParamKey, string>) => {
  const { cmac } = await import('@noble/ciphers/aes.js');
  const key = normalizeFixedBytes(params.secret, 'AES-CMAC key', [16, 24, 32]);
  const input = parseHexBase64OrUtf8Bytes(value, 'message');
  const tag = cmac(input.bytes, key.bytes);
  return JSON.stringify({
    alg: 'AES-CMAC',
    keyFormat: key.format,
    keyLength: key.normalizedLength,
    inputEncoding: input.format,
    inputLength: input.bytes.length,
    tagBytes: 16,
    tagHex: bytesToHex(tag),
    tagBase64: bytesToBase64(tag),
  }, null, 2);
};

const sm4Transform = async (direction: Direction, value: string, params: Record<ParamKey, string>) => {
  const inferred = prepareSymmetricDecodeInput('sm4', direction, value, params);
  value = inferred.input;
  params = inferred.params;
  const smCrypto = (await import('sm-crypto')).default;
  const mode = params.variant === 'hex' ? 'ecb' : 'cbc';
  const key = normalizeFixedBytes(params.secret, 'SM4 key', [16]);
  let payload: Sm4Payload | null = null;
  if (direction === 'decode') {
    try {
      payload = JSON.parse(value) as Sm4Payload;
    } catch {
      payload = null;
    }
  }
  const payloadMode = String(payload?.mode || mode).toLowerCase();
  const resolvedMode = payloadMode === 'ecb' ? 'ecb' : 'cbc';
  const ivSource = payload?.ivHex || payload?.iv || params.iv;
  const iv = resolvedMode === 'cbc' ? normalizeFixedBytes(ivSource || '', 'SM4 IV', [16]) : null;
  const options: { mode: 'cbc'; iv: string } | undefined = resolvedMode === 'cbc' && iv
    ? { mode: 'cbc', iv: bytesToHex(iv.bytes) }
    : undefined;
  if (direction === 'encode') {
    const ciphertextHex = options
      ? smCrypto.sm4.encrypt(value, bytesToHex(key.bytes), options)
      : smCrypto.sm4.encrypt(value, bytesToHex(key.bytes));
    return JSON.stringify({
      alg: 'SM4',
      mode: resolvedMode.toUpperCase(),
      keyFormat: key.format,
      ivHex: iv ? bytesToHex(iv.bytes) : undefined,
      ivFormat: iv?.format,
      ciphertextEncoding: 'hex',
      ciphertextHex,
    }, null, 2);
  }
  const ciphertextHex = payload?.ciphertextHex || payload?.ciphertext || value;
  return options
    ? smCrypto.sm4.decrypt(ciphertextHex, bytesToHex(key.bytes), options)
    : smCrypto.sm4.decrypt(ciphertextHex, bytesToHex(key.bytes));
};

const rc4Transform = (value: string, secret: string, decode = false, drop = 0) => {
  if (!secret) throw new Error('RC4 需要填写密钥');
  const inputBytes = decode ? hexToBytes(value) : utf8Encoder.encode(value);
  const keyBytes = utf8Encoder.encode(secret);
  const s = Array.from({ length: 256 }, (_, index) => index);
  let j = 0;
  for (let index = 0; index < 256; index += 1) {
    j = (j + s[index] + keyBytes[index % keyBytes.length]) & 255;
    [s[index], s[j]] = [s[j], s[index]];
  }
  let i = 0;
  j = 0;
  const nextKeyByte = () => {
    i = (i + 1) & 255;
    j = (j + s[i]) & 255;
    [s[i], s[j]] = [s[j], s[i]];
    return s[(s[i] + s[j]) & 255];
  };
  for (let index = 0; index < drop; index += 1) nextKeyByte();
  const output = new Uint8Array(inputBytes.length);
  for (let index = 0; index < inputBytes.length; index += 1) {
    output[index] = inputBytes[index] ^ nextKeyByte();
  }
  return decode ? utf8Decoder.decode(output) : bytesToHex(output);
};

const blockCipherKeyWords = (secret: string) => {
  if (!secret) throw new Error('TEA/XTEA/XXTEA 需要 16 字节密钥');
  const source = /^[0-9a-f]{32}$/i.test(secret.trim())
    ? hexToBytes(secret)
    : utf8Encoder.encode(secret);
  const key = new Uint8Array(16);
  key.set(source.slice(0, 16));
  const view = new DataView(key.buffer);
  return [0, 4, 8, 12].map(offset => view.getUint32(offset, false));
};

const pkcs7Pad = (bytes: Uint8Array, blockSize: number) => {
  const remainder = bytes.length % blockSize;
  const pad = remainder === 0 ? blockSize : blockSize - remainder;
  const output = new Uint8Array(bytes.length + pad);
  output.set(bytes);
  output.fill(pad, bytes.length);
  return output;
};

const pkcs7Unpad = (bytes: Uint8Array) => {
  if (!bytes.length) return bytes;
  const pad = bytes[bytes.length - 1];
  if (pad <= 0 || pad > 8 || pad > bytes.length) throw new Error('PKCS#7 padding 不合法');
  for (let index = bytes.length - pad; index < bytes.length; index += 1) {
    if (bytes[index] !== pad) throw new Error('PKCS#7 padding 不合法');
  }
  return bytes.slice(0, bytes.length - pad);
};

const readUint32Pair = (bytes: Uint8Array, offset: number) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 8);
  return [view.getUint32(0, false), view.getUint32(4, false)] as [number, number];
};

const writeUint32Pair = (target: Uint8Array, offset: number, left: number, right: number) => {
  const view = new DataView(target.buffer, target.byteOffset + offset, 8);
  view.setUint32(0, left >>> 0, false);
  view.setUint32(4, right >>> 0, false);
};

const teaBlock = (left: number, right: number, key: number[], decode = false) => {
  const delta = 0x9e3779b9;
  let v0 = left >>> 0;
  let v1 = right >>> 0;
  if (!decode) {
    let sum = 0;
    for (let round = 0; round < 32; round += 1) {
      sum = (sum + delta) >>> 0;
      v0 = (v0 + ((((v1 << 4) >>> 0) + key[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + key[1]))) >>> 0;
      v1 = (v1 + ((((v0 << 4) >>> 0) + key[2]) ^ (v0 + sum) ^ ((v0 >>> 5) + key[3]))) >>> 0;
    }
  } else {
    let sum = (delta * 32) >>> 0;
    for (let round = 0; round < 32; round += 1) {
      v1 = (v1 - (((((v0 << 4) >>> 0) + key[2]) ^ (v0 + sum) ^ ((v0 >>> 5) + key[3])) >>> 0)) >>> 0;
      v0 = (v0 - (((((v1 << 4) >>> 0) + key[0]) ^ (v1 + sum) ^ ((v1 >>> 5) + key[1])) >>> 0)) >>> 0;
      sum = (sum - delta) >>> 0;
    }
  }
  return [v0, v1] as [number, number];
};

const xteaBlock = (left: number, right: number, key: number[], decode = false) => {
  const delta = 0x9e3779b9;
  let v0 = left >>> 0;
  let v1 = right >>> 0;
  if (!decode) {
    let sum = 0;
    for (let round = 0; round < 32; round += 1) {
      v0 = (v0 + (((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
      sum = (sum + delta) >>> 0;
      v1 = (v1 + (((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
    }
  } else {
    let sum = (delta * 32) >>> 0;
    for (let round = 0; round < 32; round += 1) {
      v1 = (v1 - (((((v0 << 4) ^ (v0 >>> 5)) + v0) >>> 0) ^ ((sum + key[(sum >>> 11) & 3]) >>> 0))) >>> 0;
      sum = (sum - delta) >>> 0;
      v0 = (v0 - (((((v1 << 4) ^ (v1 >>> 5)) + v1) >>> 0) ^ ((sum + key[sum & 3]) >>> 0))) >>> 0;
    }
  }
  return [v0, v1] as [number, number];
};

const teaTransform = (value: string, secret: string, decode = false, xtea = false) => {
  const key = blockCipherKeyWords(secret);
  const inputBytes = decode ? hexToBytes(value) : pkcs7Pad(utf8Encoder.encode(value), 8);
  if (inputBytes.length % 8 !== 0) throw new Error('TEA/XTEA 解密需要 8 字节对齐的 hex 密文');
  const output = new Uint8Array(inputBytes.length);
  for (let offset = 0; offset < inputBytes.length; offset += 8) {
    const [left, right] = readUint32Pair(inputBytes, offset);
    const [nextLeft, nextRight] = xtea ? xteaBlock(left, right, key, decode) : teaBlock(left, right, key, decode);
    writeUint32Pair(output, offset, nextLeft, nextRight);
  }
  return decode ? utf8Decoder.decode(pkcs7Unpad(output)) : bytesToHex(output);
};

const bytesToUint32Words = (bytes: Uint8Array, includeLength = false) => {
  const words = Array.from({ length: Math.ceil(bytes.length / 4) || 1 }, () => 0);
  for (let index = 0; index < bytes.length; index += 1) words[index >>> 2] |= bytes[index] << ((index & 3) * 8);
  if (includeLength) words.push(bytes.length);
  return words.map(word => word >>> 0);
};

const uint32WordsToBytes = (words: number[], includeLength = false) => {
  const data = includeLength ? words.slice(0, -1) : words.slice();
  const length = includeLength ? words[words.length - 1] : data.length * 4;
  if (includeLength && (length < 0 || length > data.length * 4)) throw new Error('XXTEA 明文长度字段不合法');
  const output = new Uint8Array(data.length * 4);
  data.forEach((word, wordIndex) => {
    for (let byteIndex = 0; byteIndex < 4; byteIndex += 1) output[wordIndex * 4 + byteIndex] = (word >>> (byteIndex * 8)) & 255;
  });
  return output.slice(0, length);
};

const xxteaWords = (input: number[], key: number[], decode = false) => {
  const v = input.slice();
  const n = v.length;
  if (n < 2) return v;
  const delta = 0x9e3779b9;
  if (!decode) {
    let z = v[n - 1];
    let sum = 0;
    for (let q = Math.floor(6 + 52 / n); q > 0; q -= 1) {
      sum = (sum + delta) >>> 0;
      const e = (sum >>> 2) & 3;
      for (let p = 0; p < n - 1; p += 1) {
        const y = v[p + 1];
        const mx = (((z >>> 5) ^ ((y << 2) >>> 0)) + ((y >>> 3) ^ ((z << 4) >>> 0)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))) >>> 0;
        z = v[p] = (v[p] + mx) >>> 0;
      }
      const y = v[0];
      const mx = (((z >>> 5) ^ ((y << 2) >>> 0)) + ((y >>> 3) ^ ((z << 4) >>> 0)) ^ ((sum ^ y) + (key[((n - 1) & 3) ^ e] ^ z))) >>> 0;
      z = v[n - 1] = (v[n - 1] + mx) >>> 0;
    }
  } else {
    let y = v[0];
    let sum = (Math.floor(6 + 52 / n) * delta) >>> 0;
    while (sum !== 0) {
      const e = (sum >>> 2) & 3;
      for (let p = n - 1; p > 0; p -= 1) {
        const z = v[p - 1];
        const mx = (((z >>> 5) ^ ((y << 2) >>> 0)) + ((y >>> 3) ^ ((z << 4) >>> 0)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))) >>> 0;
        y = v[p] = (v[p] - mx) >>> 0;
      }
      const z = v[n - 1];
      const mx = (((z >>> 5) ^ ((y << 2) >>> 0)) + ((y >>> 3) ^ ((z << 4) >>> 0)) ^ ((sum ^ y) + (key[e] ^ z))) >>> 0;
      y = v[0] = (v[0] - mx) >>> 0;
      sum = (sum - delta) >>> 0;
    }
  }
  return v;
};

const xxteaTransform = (value: string, secret: string, decode = false) => {
  const key = blockCipherKeyWords(secret);
  if (!decode) {
    const words = bytesToUint32Words(utf8Encoder.encode(value), true);
    return bytesToHex(uint32WordsToBytes(xxteaWords(words, key), false));
  }
  const words = bytesToUint32Words(hexToBytes(value), false);
  return utf8Decoder.decode(uint32WordsToBytes(xxteaWords(words, key, true), true));
};

const vigenereTransform = (value: string, secret: string, decode = false) => {
  const key = secret.replace(/[^a-z]/gi, '').toUpperCase();
  if (!key) throw new Error('Vigenere 需要填写仅包含字母的密钥');
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const shift = key.charCodeAt(keyIndex % key.length) - 65;
    keyIndex += 1;
    const offset = decode ? -shift : shift;
    return String.fromCharCode(base + ((((code - base) + offset) % 26) + 26) % 26);
  }).join('');
};

const beaufortTransform = (value: string, secret: string) => {
  const key = secret.replace(/[^a-z]/gi, '').toUpperCase();
  if (!key) throw new Error('Beaufort 需要填写仅包含字母的密钥');
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const keyValue = key.charCodeAt(keyIndex % key.length) - 65;
    keyIndex += 1;
    return String.fromCharCode(base + ((((keyValue - (code - base)) % 26) + 26) % 26));
  }).join('');
};

const autokeyTransform = (value: string, secret: string, decode = false) => {
  const seed = secret.replace(/[^a-z]/gi, '').toUpperCase();
  if (!seed) throw new Error('Autokey 需要填写仅包含字母的初始密钥');
  const output: string[] = [];
  const plaintextKey: number[] = [];
  let keyIndex = 0;
  for (const char of value) {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) {
      output.push(char);
      continue;
    }
    const keyValue = keyIndex < seed.length ? seed.charCodeAt(keyIndex) - 65 : plaintextKey[keyIndex - seed.length] ?? 0;
    const sourceValue = code - base;
    const plainValue = decode ? (((sourceValue - keyValue) % 26) + 26) % 26 : sourceValue;
    const nextValue = decode ? plainValue : (sourceValue + keyValue) % 26;
    plaintextKey.push(plainValue);
    output.push(String.fromCharCode(base + nextValue));
    keyIndex += 1;
  }
  return output.join('');
};

const keyedSquare = (secret: string, baseAlphabet?: string) => {
  const base = baseAlphabet || 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
  const useJ = !baseAlphabet; // default 5x5 merges I/J
  const raw = `${secret}${base}`.toUpperCase();
  const cleaned = useJ ? raw.replace(/J/g, 'I').replace(/[^A-Z]/g, '') : raw.replace(/[^A-Z0-9]/g, '');
  let output = '';
  for (const char of cleaned) {
    if (!output.includes(char)) output += char;
  }
  const size = baseAlphabet ? Math.ceil(Math.sqrt(base.length)) : 5;
  const total = size * size;
  return output.padEnd(total, 'X').slice(0, total);
};

const playfairPairs = (value: string, alphabet?: string) => {
  const chars = alphabet ? value.toUpperCase().replace(new RegExp(`[^${alphabet.replace(/[[\]^\\]/g, '\\$&')}]`, 'g'), '') : value.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
  const filler = alphabet?.includes('X') ? 'X' : (alphabet?.[0] ?? 'X');
  const pairs: string[] = [];
  for (let index = 0; index < chars.length;) {
    const first = chars[index] || filler;
    const second = chars[index + 1] || filler;
    if (first === second) { pairs.push(`${first}${filler}`); index += 1; }
    else { pairs.push(`${first}${second}`); index += 2; }
  }
  if (pairs.length && pairs[pairs.length - 1].length === 1) pairs[pairs.length - 1] += filler;
  return pairs;
};

const playfairTransform = (value: string, secret: string, decode = false, customAlphabet?: string) => {
  const square = keyedSquare(secret || 'KEYWORD', customAlphabet);
  const sz = Math.round(Math.sqrt(square.length));
  const pairs = decode
    ? (customAlphabet ? value.toUpperCase().replace(new RegExp(`[^${square.replace(/[[\]^\\]/g, '\\$&')}]`, 'g'), '').match(/.{1,2}/g) || [] : value.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '').match(/.{1,2}/g) || [])
    : playfairPairs(value, customAlphabet);
  return pairs.map(pair => {
    const firstIndex = square.indexOf(pair[0]);
    const secondIndex = square.indexOf(pair[1] || square[0]);
    if (firstIndex < 0 || secondIndex < 0) return pair;
    const firstRow = Math.floor(firstIndex / sz);
    const firstCol = firstIndex % sz;
    const secondRow = Math.floor(secondIndex / sz);
    const secondCol = secondIndex % sz;
    const offset = decode ? -1 : 1;
    if (firstRow === secondRow) {
      return square[firstRow * sz + ((firstCol + offset + sz) % sz)] + square[secondRow * sz + ((secondCol + offset + sz) % sz)];
    }
    if (firstCol === secondCol) {
      return square[((firstRow + offset + sz) % sz) * sz + firstCol] + square[((secondRow + offset + sz) % sz) * sz + secondCol];
    }
    return square[firstRow * sz + secondCol] + square[secondRow * sz + firstCol];
  }).join('');
};

const parseHillKey = (secret: string) => {
  const numbers = secret.match(/-?\d+/g)?.map(Number);
  if (numbers?.length === 4) return numbers;
  const letters = secret.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length >= 4) return Array.from(letters.slice(0, 4)).map(char => char.charCodeAt(0) - 65);
  throw new Error('Hill 2x2 需要 4 个数字或 4 个字母作为密钥');
};

const hillTransform = (value: string, secret: string, decode = false) => {
  let [a, b, c, d] = parseHillKey(secret);
  if (decode) {
    const determinant = (((a * d - b * c) % 26) + 26) % 26;
    if (determinant === 0 || ![1,3,5,7,9,11,15,17,19,21,23,25].includes(determinant)) {
      throw new Error(`矩阵行列式 det=${a*d-b*c}，mod 26 = ${determinant}，与 26 不互质，矩阵不可逆，无法解密`);
    }
    const inverseDet = modInverse(determinant, 26);
    [a, b, c, d] = [d * inverseDet, -b * inverseDet, -c * inverseDet, a * inverseDet].map(entry => ((entry % 26) + 26) % 26);
  }
  const letters = value.toUpperCase().replace(/[^A-Z]/g, '');
  const padded = letters.length % 2 === 0 ? letters : `${letters}X`;
  let output = '';
  for (let index = 0; index < padded.length; index += 2) {
    const x = padded.charCodeAt(index) - 65;
    const y = padded.charCodeAt(index + 1) - 65;
    output += alphabet[(a * x + b * y) % 26] + alphabet[(c * x + d * y) % 26];
  }
  return output;
};

const substitutionTransform = (value: string, secret: string, decode = false) => {
  const mapAlphabet = secret.toUpperCase().replace(/[^A-Z]/g, '');
  if (mapAlphabet.length !== 26 || new Set(mapAlphabet).size !== 26) throw new Error('单表替换密钥必须是 26 个不重复字母');
  const from = decode ? mapAlphabet : alphabet;
  const to = decode ? alphabet : mapAlphabet;
  return Array.from(value).map(char => {
    const upper = char.toUpperCase();
    const index = from.indexOf(upper);
    if (index < 0) return char;
    const mapped = to[index];
    return char === upper ? mapped : mapped.toLowerCase();
  }).join('');
};

const baconEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const normalized = char === 'J' ? 'I' : char === 'V' ? 'U' : char;
    const index = 'ABCDEFGHIKLMNOPQRSTUWXYZ'.indexOf(normalized);
    if (index < 0) return char.trim() ? char : '/';
    return index.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B');
  })
  .join(separatorValue(separator));

const baconDecode = (value: string) => {
  const source = value.toUpperCase().replace(/0/g, 'A').replace(/1/g, 'B').replace(/[^AB]/g, '');
  if (source.length < 5) throw new Error('Bacon 解码需要 A/B 或 0/1 五位分组');
  const chunks = source.match(/.{5}/g) || [];
  return chunks.map(chunk => {
    const index = Number.parseInt(chunk.replace(/A/g, '0').replace(/B/g, '1'), 2);
    return 'ABCDEFGHIKLMNOPQRSTUWXYZ'[index] || '?';
  }).join('');
};

const polybiusEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const normalized = char === 'J' ? 'I' : char;
    const index = polybiusAlphabet.indexOf(normalized);
    if (index < 0) return char.trim() ? char : '/';
    return `${Math.floor(index / 5) + 1}${(index % 5) + 1}`;
  })
  .join(separatorValue(separator));

const polybiusDecode = (value: string) => {
  const pairs = value.match(/[1-5][1-5]/g) || [];
  if (!pairs.length) throw new Error('Polybius 解码需要 11-55 范围内的坐标');
  return pairs.map(pair => {
    const row = Number(pair[0]) - 1;
    const column = Number(pair[1]) - 1;
    return polybiusAlphabet[row * 5 + column] || '?';
  }).join('');
};

const tapCodeEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const normalized = char === 'K' ? 'C' : char;
    const index = tapCodeAlphabet.indexOf(normalized);
    if (index < 0) return char.trim() ? char : '/';
    return `${'.'.repeat(Math.floor(index / 5) + 1)} ${'.'.repeat((index % 5) + 1)}`;
  })
  .join(separatorValue(separator) === '\n' ? '\n' : ' / ');

const tapCodeDecode = (value: string) => {
  const numericPairs = value.match(/[1-5][1-5]/g);
  if (numericPairs?.length) {
    return numericPairs.map(pair => {
      const row = Number(pair[0]) - 1;
      const column = Number(pair[1]) - 1;
      return tapCodeAlphabet[row * 5 + column] || '?';
    }).join('');
  }
  const dottedPairs = value.match(/[.-]{1,5}\s+[.-]{1,5}/g) || [];
  if (!dottedPairs.length) throw new Error('Tap Code 解码需要 11-55 或点号坐标组');
  return dottedPairs.map(pair => {
    const [rowRaw, colRaw] = pair.trim().split(/\s+/);
    const row = rowRaw.replace(/-/g, '.').length - 1;
    const column = colRaw.replace(/-/g, '.').length - 1;
    return tapCodeAlphabet[row * 5 + column] || '?';
  }).join('');
};

const railPattern = (length: number, rails: number) => {
  if (rails < 2) throw new Error('Rail Fence 轨道数至少为 2');
  const pattern: number[] = [];
  let rail = 0;
  let step = 1;
  for (let index = 0; index < length; index += 1) {
    pattern.push(rail);
    if (rail === 0) step = 1;
    else if (rail === rails - 1) step = -1;
    rail += step;
  }
  return pattern;
};

const railFenceEncode = (value: string, railValue: string) => {
  const rails = Number.parseInt(railValue, 10) || 3;
  const rows = Array.from({ length: rails }, () => '');
  railPattern(Array.from(value).length, rails).forEach((rail, index) => {
    rows[rail] += Array.from(value)[index];
  });
  return rows.join('');
};

const railFenceDecode = (value: string, railValue: string) => {
  const rails = Number.parseInt(railValue, 10) || 3;
  const chars = Array.from(value);
  const pattern = railPattern(chars.length, rails);
  const counts = Array.from({ length: rails }, (_, rail) => pattern.filter(item => item === rail).length);
  const rows = counts.map(() => [] as string[]);
  let offset = 0;
  counts.forEach((count, rail) => {
    rows[rail] = chars.slice(offset, offset + count);
    offset += count;
  });
  const rowOffsets = Array.from({ length: rails }, () => 0);
  return pattern.map(rail => rows[rail][rowOffsets[rail]++]).join('');
};

const columnOrder = (secret: string) => {
  const key = secret.trim();
  if (!key) throw new Error('Columnar 需要关键词');
  return Array.from(key)
    .map((char, index) => ({ char: char.toUpperCase(), index }))
    .sort((left, right) => left.char.localeCompare(right.char) || left.index - right.index)
    .map(item => item.index);
};

const columnarEncode = (value: string, secret: string) => {
  const order = columnOrder(secret);
  const columns = Array.from({ length: order.length }, () => '');
  Array.from(value).forEach((char, index) => {
    columns[index % order.length] += char;
  });
  return order.map(index => columns[index]).join('');
};

const columnarDecode = (value: string, secret: string) => {
  const order = columnOrder(secret);
  const chars = Array.from(value);
  const rows = Math.ceil(chars.length / order.length);
  const shortColumns = (order.length - (chars.length % order.length)) % order.length;
  const columnLengths = Array.from({ length: order.length }, (_, index) => rows - (index >= order.length - shortColumns ? 1 : 0));
  const columns = Array.from({ length: order.length }, () => [] as string[]);
  let offset = 0;
  order.forEach(columnIndex => {
    const length = columnLengths[columnIndex];
    columns[columnIndex] = chars.slice(offset, offset + length);
    offset += length;
  });
  const output: string[] = [];
  for (let row = 0; row < rows; row += 1) {
    for (let column = 0; column < order.length; column += 1) {
      if (columns[column][row] != null) output.push(columns[column][row]);
    }
  }
  return output.join('');
};

const scytaleEncode = (value: string, railValue: string) => {
  const columns = Math.max(2, Number.parseInt(railValue, 10) || 3);
  const chars = Array.from(value);
  const rows = Math.ceil(chars.length / columns);
  const output: string[] = [];
  for (let column = 0; column < columns; column += 1) {
    for (let row = 0; row < rows; row += 1) {
      const index = row * columns + column;
      if (index < chars.length) output.push(chars[index]);
    }
  }
  return output.join('');
};

const scytaleDecode = (value: string, railValue: string) => {
  const columns = Math.max(2, Number.parseInt(railValue, 10) || 3);
  const chars = Array.from(value);
  const columnLengths = Array.from({ length: columns }, (_, column) => Math.floor((chars.length + columns - 1 - column) / columns));
  const grid = Array.from({ length: columns }, () => [] as string[]);
  let offset = 0;
  columnLengths.forEach((length, column) => {
    grid[column] = chars.slice(offset, offset + length);
    offset += length;
  });
  const output: string[] = [];
  const rows = Math.max(...columnLengths);
  for (let row = 0; row < rows; row += 1) {
    for (let column = 0; column < columns; column += 1) {
      if (grid[column][row] != null) output.push(grid[column][row]);
    }
  }
  return output.join('');
};

const portaTransform = (value: string, secret: string) => {
  const key = secret.replace(/[^a-z]/gi, '').toUpperCase();
  if (!key) throw new Error('Porta 需要字母密钥');
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const p = code - base;
    const k = Math.floor((key.charCodeAt(keyIndex % key.length) - 65) / 2);
    keyIndex += 1;
    const mapped = p < 13 ? 13 + ((p + k) % 13) : ((p - 13 - k + 13) % 13);
    return String.fromCharCode(base + mapped);
  }).join('');
};

const gronsfeldTransform = (value: string, secret: string, decode = false) => {
  const digits = secret.replace(/\D/g, '');
  if (!digits) throw new Error('Gronsfeld 需要数字密钥，例如 31415');
  let keyIndex = 0;
  return Array.from(value).map(char => {
    const code = char.charCodeAt(0);
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : null;
    if (base == null) return char;
    const shift = Number(digits[keyIndex % digits.length]) * (decode ? -1 : 1);
    keyIndex += 1;
    return String.fromCharCode(base + ((((code - base) + shift) % 26) + 26) % 26);
  }).join('');
};

const cleanClassicalLetters = (value: string) => value.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');

const bifidTransform = (value: string, secret: string, periodValue: string, decode = false) => {
  const square = keyedSquare(secret || 'KEYWORD');
  const period = Math.max(1, Number.parseInt(periodValue, 10) || 5);
  const letters = cleanClassicalLetters(value);
  const output: string[] = [];
  for (let offset = 0; offset < letters.length; offset += period) {
    const block = letters.slice(offset, offset + period);
    if (!decode) {
      const rows: number[] = [];
      const columns: number[] = [];
      for (const char of block) {
        const index = square.indexOf(char);
        rows.push(Math.floor(index / 5));
        columns.push(index % 5);
      }
      const stream = [...rows, ...columns];
      for (let index = 0; index < stream.length; index += 2) output.push(square[stream[index] * 5 + stream[index + 1]]);
    } else {
      const coords = Array.from(block).flatMap(char => {
        const index = square.indexOf(char);
        return [Math.floor(index / 5), index % 5];
      });
      const rows = coords.slice(0, block.length);
      const columns = coords.slice(block.length);
      for (let index = 0; index < block.length; index += 1) output.push(square[rows[index] * 5 + columns[index]]);
    }
  }
  return output.join('');
};

const keyedTrifidAlphabet = (secret: string) => {
  const raw = `${secret}ABCDEFGHIJKLMNOPQRSTUVWXYZ.`.toUpperCase().replace(/[^A-Z.]/g, '');
  let output = '';
  for (const char of raw) {
    if (!output.includes(char)) output += char;
  }
  return output.padEnd(27, '.').slice(0, 27);
};

const trifidTransform = (value: string, secret: string, periodValue: string, decode = false) => {
  const square = keyedTrifidAlphabet(secret || 'KEYWORD');
  const period = Math.max(1, Number.parseInt(periodValue, 10) || 5);
  const text = value.toUpperCase().replace(/[^A-Z.]/g, '');
  const output: string[] = [];
  for (let offset = 0; offset < text.length; offset += period) {
    const block = text.slice(offset, offset + period);
    if (!decode) {
      const first: number[] = [];
      const second: number[] = [];
      const third: number[] = [];
      for (const char of block) {
        const index = square.indexOf(char);
        first.push(Math.floor(index / 9));
        second.push(Math.floor((index % 9) / 3));
        third.push(index % 3);
      }
      const stream = [...first, ...second, ...third];
      for (let index = 0; index < stream.length; index += 3) output.push(square[stream[index] * 9 + stream[index + 1] * 3 + stream[index + 2]]);
    } else {
      const coords = Array.from(block).flatMap(char => {
        const index = square.indexOf(char);
        return [Math.floor(index / 9), Math.floor((index % 9) / 3), index % 3];
      });
      const first = coords.slice(0, block.length);
      const second = coords.slice(block.length, block.length * 2);
      const third = coords.slice(block.length * 2);
      for (let index = 0; index < block.length; index += 1) output.push(square[first[index] * 9 + second[index] * 3 + third[index]]);
    }
  }
  return output.join('');
};

const fourSquareTransform = (value: string, secret: string, keyword2: string, decode = false) => {
  const plain = polybiusAlphabet;
  const topRight = keyedSquare(secret || 'EXAMPLE');
  const bottomLeft = keyedSquare(keyword2 || 'KEYWORD');
  const letters = cleanClassicalLetters(value);
  const padded = letters.length % 2 === 0 ? letters : `${letters}X`;
  const output: string[] = [];
  for (let index = 0; index < padded.length; index += 2) {
    const first = padded[index];
    const second = padded[index + 1];
    if (!decode) {
      const a = plain.indexOf(first);
      const b = plain.indexOf(second);
      output.push(topRight[Math.floor(a / 5) * 5 + (b % 5)]);
      output.push(bottomLeft[Math.floor(b / 5) * 5 + (a % 5)]);
    } else {
      const a = topRight.indexOf(first);
      const b = bottomLeft.indexOf(second);
      output.push(plain[Math.floor(a / 5) * 5 + (b % 5)]);
      output.push(plain[Math.floor(b / 5) * 5 + (a % 5)]);
    }
  }
  return output.join('');
};

const nihilistTransform = (value: string, secret: string, separator: string, decode = false) => {
  const square = keyedSquare(secret || 'KEYWORD');
  const keyLetters = cleanClassicalLetters(secret || 'KEY');
  if (!keyLetters) throw new Error('Nihilist 需要关键词');
  const keyNumbers = Array.from(keyLetters).map(char => {
    const index = square.indexOf(char);
    return (Math.floor(index / 5) + 1) * 10 + (index % 5) + 1;
  });
  if (!decode) {
    const letters = cleanClassicalLetters(value);
    return Array.from(letters).map((char, index) => {
      const squareIndex = square.indexOf(char);
      const number = (Math.floor(squareIndex / 5) + 1) * 10 + (squareIndex % 5) + 1;
      return String(number + keyNumbers[index % keyNumbers.length]);
    }).join(separatorValue(separator));
  }
  const numbers = value.match(/\d+/g)?.map(Number) || [];
  if (!numbers.length) throw new Error('Nihilist 解码需要数字组');
  return numbers.map((number, index) => {
    const plainNumber = number - keyNumbers[index % keyNumbers.length];
    const row = Math.floor(plainNumber / 10) - 1;
    const column = (plainNumber % 10) - 1;
    return square[row * 5 + column] || '?';
  }).join('');
};

const keyedAlphabet = (secret: string, baseAlphabet: string) => {
  const raw = `${secret}${baseAlphabet}`.toUpperCase().replace(new RegExp(`[^${baseAlphabet.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}]`, 'g'), '');
  let output = '';
  for (const char of raw) {
    if (!output.includes(char)) output += char;
  }
  return output.padEnd(baseAlphabet.length, baseAlphabet).slice(0, baseAlphabet.length);
};

const adfgxTransform = (value: string, secret: string, keyword2: string, decode = false, variant: 'ADFGX' | 'ADFGVX' = 'ADFGX') => {
  const symbols = variant === 'ADFGVX' ? 'ADFGVX' : 'ADFGX';
  const baseAlphabet = variant === 'ADFGVX' ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' : polybiusAlphabet;
  const square = keyedAlphabet(secret || 'KEYWORD', baseAlphabet);
  const transpositionKey = keyword2 || secret || 'CIPHER';
  const substitute = (source: string) => Array.from(source.toUpperCase().replace(/J/g, 'I').replace(new RegExp(`[^${baseAlphabet}]`, 'g'), ''))
    .map(char => {
      const index = square.indexOf(char);
      return `${symbols[Math.floor(index / symbols.length)]}${symbols[index % symbols.length]}`;
    })
    .join('');
  const unsubstitute = (source: string) => {
    const clean = source.toUpperCase().replace(new RegExp(`[^${symbols}]`, 'g'), '');
    const pairs = clean.match(new RegExp(`.{1,2}`, 'g')) || [];
    return pairs.map(pair => {
      if (pair.length < 2) return '';
      const row = symbols.indexOf(pair[0]);
      const column = symbols.indexOf(pair[1]);
      return square[row * symbols.length + column] || '?';
    }).join('');
  };
  if (!decode) return columnarEncode(substitute(value), transpositionKey);
  return unsubstitute(columnarDecode(value, transpositionKey));
};

const xorTransform = (bytes: Uint8Array, secret: string) => {
  if (!secret) throw new Error('XOR 需要填写密钥');
  const key = utf8Encoder.encode(secret);
  return bytes.map((byte, index) => byte ^ key[index % key.length]);
};

const printableScore = (bytes: Uint8Array) => {
  let score = 0;
  for (const byte of bytes) {
    const char = String.fromCharCode(byte);
    if (byte >= 32 && byte <= 126) score += 1;
    else if (byte === 9 || byte === 10 || byte === 13) score += 0.25;
    else score -= 2;
    if (/[etaoin shrdlu]/i.test(char)) score += 0.7;
    if (/[-{}_]/.test(char)) score += 0.25;
  }
  const text = utf8Decoder.decode(bytes);
  if (/flag|ctf|picoctf|htb|thm|ductf|corctf|dice|wctf|utflag|sekai|actf|seccon|ritsec|crypto|lactf|crew|key|pass|admin/i.test(text)) score += 8;
  return score;
};

const singleByteXorBruteforce = (value: string) => {
  const bytes = hexToBytes(value);
  if (!bytes.length) throw new Error('单字节 XOR 爆破需要 hex 密文');
  return Array.from({ length: 256 }, (_, key) => {
    const decoded = bytes.map(byte => byte ^ key);
    return {
      key,
      score: printableScore(decoded),
      text: utf8Decoder.decode(decoded).replace(/\p{Cc}/gu, '.'),
    };
  })
    .sort((left, right) => right.score - left.score)
    .slice(0, 32)
    .map(item => `0x${item.key.toString(16).padStart(2, '0')} (${item.key.toString().padStart(3, ' ')}): ${item.text}`)
    .join('\n');
};

const xorKnownPlaintext = (value: string, knownPlaintext: string) => {
  const ciphertext = hexToBytes(value);
  if (!ciphertext.length) throw new Error('需要 hex 密文和已知明文片段');
  const ctfPrefixes = ['flag{', 'FLAG{', 'ctf{', 'CTF{', 'picoCTF{', 'THM{', 'HTB{', 'DUCTF{', 'corctf{', 'dice{', 'wctf{', 'utflag{', 'PCTF{', 'uiuctf{', 'sekai{'];
  const prefixesToTry = knownPlaintext ? [knownPlaintext] : ctfPrefixes;
  const results = prefixesToTry.map(kp => {
    const plain = utf8Encoder.encode(kp);
    if (plain.length > ciphertext.length) return null;
    const key = plain.map((byte, index) => byte ^ ciphertext[index]);
    const guess = guessRepeatingKey(key);
    return { knownPlaintext: kp, keyHexPrefix: bytesToHex(key), keyTextPreview: utf8Decoder.decode(key).replace(/\p{Cc}/gu, '.'), repeatingKeyGuess: guess };
  }).filter(Boolean);
  return JSON.stringify({
    candidates: results,
    note: '如果已知明文不在密文起点，请滑动偏移，或在脚本中做 offset 尝试',
  }, null, 2);
};

const magicXorHelper = (value: string, knownPlaintext: string) => {
  const ciphertext = hexToBytes(value);
  if (!ciphertext.length) throw new Error('Magic-header XOR 需要 hex 密文');
  const signatures: Array<{ name: string; bytes: Uint8Array }> = [
    knownPlaintext.trim() ? { name: 'custom-known-plaintext', bytes: utf8Encoder.encode(knownPlaintext) } : null,
    { name: 'PNG', bytes: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
    { name: 'JPG', bytes: new Uint8Array([0xff, 0xd8, 0xff]) },
    { name: 'GIF87a', bytes: utf8Encoder.encode('GIF87a') },
    { name: 'GIF89a', bytes: utf8Encoder.encode('GIF89a') },
    { name: 'PDF', bytes: utf8Encoder.encode('%PDF-') },
    { name: 'ZIP/JAR/DOCX', bytes: new Uint8Array([0x50, 0x4b, 0x03, 0x04]) },
    { name: 'ELF', bytes: new Uint8Array([0x7f, 0x45, 0x4c, 0x46]) },
    { name: 'PE/MZ', bytes: utf8Encoder.encode('MZ') },
    { name: 'RAR', bytes: new Uint8Array([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]) },
    { name: '7z', bytes: new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
    { name: 'GZip', bytes: new Uint8Array([0x1f, 0x8b, 0x08]) },
    { name: 'SQLite', bytes: utf8Encoder.encode('SQLite format 3\0') },
    { name: 'Java class', bytes: new Uint8Array([0xca, 0xfe, 0xba, 0xbe]) },
    ...['flag{', 'FLAG{', 'ctf{', 'CTF{', 'picoCTF{', 'THM{', 'HTB{', 'DUCTF{', 'corctf{', 'dice{', 'wctf{', 'utflag{', 'PCTF{', 'uiuctf{', 'sekai{']
      .map(prefix => ({ name: `CTF:${prefix}`, bytes: utf8Encoder.encode(prefix) })),
  ].filter(Boolean) as Array<{ name: string; bytes: Uint8Array }>;
  const candidates = signatures
    .filter(signature => signature.bytes.length <= ciphertext.length)
    .map(signature => {
      const key = signature.bytes.map((byte, index) => byte ^ ciphertext[index]);
      const repeating = guessRepeatingKey(key);
      const previewKey = repeating ? key.slice(0, repeating.length) : key;
      const preview = ciphertext.slice(0, Math.min(96, ciphertext.length)).map((byte, index) => byte ^ previewKey[index % previewKey.length]);
      return {
        signature: signature.name,
        keyHexPrefix: bytesToHex(key),
        repeatingKeyGuess: repeating,
        preview: utf8Decoder.decode(preview).replace(/\p{Cc}/gu, '.'),
      };
    });
  return JSON.stringify({
    ciphertextBytes: ciphertext.length,
    candidates,
    note: '这些候选假设文件头位于密文开头；实际题目可继续对 offset 做滑动搜索',
  }, null, 2);
};

const guessRepeatingKey = (key: Uint8Array) => {
  const max = Math.min(24, key.length);
  for (let length = 1; length <= max; length += 1) {
    let ok = true;
    for (let index = length; index < key.length; index += 1) {
      if (key[index] !== key[index % length]) {
        ok = false;
        break;
      }
    }
    if (ok) return {
      length,
      hex: bytesToHex(key.slice(0, length)),
      textPreview: utf8Decoder.decode(key.slice(0, length)).replace(/\p{Cc}/gu, '.'),
    };
  }
  return null;
};

const isJsonRecord = (value: unknown): value is Record<string, unknown> => (
  typeof value === 'object' && value !== null && !Array.isArray(value)
);

const jwtTimestamps = (payload: unknown) => {
  if (!isJsonRecord(payload)) return {};
  return Object.fromEntries(['iat', 'nbf', 'exp']
    .filter(key => typeof payload[key] === 'number')
    .map(key => [key, new Date((payload[key] as number) * 1000).toISOString()]));
};

const decodeJwt = (value: string) => {
  const token = value.trim().replace(/^Bearer\s+/i, '');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT 必须包含 Header.Payload.Signature 三段');
  const header = JSON.parse(fromBase64Url(parts[0]));
  const payload = JSON.parse(fromBase64Url(parts[1]));
  const timestamps = jwtTimestamps(payload);
  return JSON.stringify({ header, payload, timestamps, signature: parts[2] }, null, 2);
};

type JwtHmacSpec = { jwt: 'HS256' | 'HS384' | 'HS512'; subtle: 'SHA-256' | 'SHA-384' | 'SHA-512' };

const jwtHmacSpecFromHash = (algorithm: string): JwtHmacSpec => {
  if (algorithm === 'sha384') return { jwt: 'HS384', subtle: 'SHA-384' };
  if (algorithm === 'sha512') return { jwt: 'HS512', subtle: 'SHA-512' };
  return { jwt: 'HS256', subtle: 'SHA-256' };
};

const jwtHmacSpecFromAlg = (alg: unknown) => {
  if (typeof alg !== 'string') return null;
  const upper = alg.toUpperCase();
  if (upper === 'HS256') return { jwt: 'HS256', subtle: 'SHA-256' } as JwtHmacSpec;
  if (upper === 'HS384') return { jwt: 'HS384', subtle: 'SHA-384' } as JwtHmacSpec;
  if (upper === 'HS512') return { jwt: 'HS512', subtle: 'SHA-512' } as JwtHmacSpec;
  return null;
};

const bytesToBase64Url = (bytes: Uint8Array) => base64ToBase64Url(bytesToBase64(bytes));

const jwtHmacSignBytes = async (signingInput: string, secret: string, subtleHash: JwtHmacSpec['subtle']) => {
  if (!secret) throw new Error('JWT HMAC 需要填写 secret');
  const key = await crypto.subtle.importKey('raw', bytesToBuffer(utf8Encoder.encode(secret)), { name: 'HMAC', hash: subtleHash }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytesToBuffer(utf8Encoder.encode(signingInput))));
};

const jwtHmacTransform = async (direction: Direction, value: string, params: Record<ParamKey, string>) => {
  if (direction === 'encode') {
    const parsed = JSON.parse(value.trim() || '{}') as unknown;
    if (!isJsonRecord(parsed)) throw new Error('JWT HMAC 签名输入必须是 JSON 对象');
    const hasEnvelopePayload = Object.prototype.hasOwnProperty.call(parsed, 'payload');
    const headerSource = hasEnvelopePayload && isJsonRecord(parsed.header) ? parsed.header : {};
    const payload = hasEnvelopePayload ? parsed.payload : parsed;
    if (payload === undefined) throw new Error('JWT HMAC 签名输入缺少 payload');
    const spec = jwtHmacSpecFromAlg(headerSource.alg) || jwtHmacSpecFromHash(params.hashAlgorithm);
    const header = { alg: spec.jwt, typ: 'JWT', ...headerSource };
    header.alg = spec.jwt;
    const headerPart = bytesToBase64Url(utf8Encoder.encode(JSON.stringify(header)));
    const payloadPart = bytesToBase64Url(utf8Encoder.encode(JSON.stringify(payload)));
    const signingInput = `${headerPart}.${payloadPart}`;
    const signatureBytes = await jwtHmacSignBytes(signingInput, params.secret, spec.subtle);
    const signature = bytesToBase64Url(signatureBytes);
    return JSON.stringify({
      token: `${signingInput}.${signature}`,
      algorithm: spec.jwt,
      header,
      payload,
      signingInput,
      signature: {
        base64url: signature,
        hex: bytesToHex(signatureBytes),
      },
      warning: '仅支持 HS256/HS384/HS512 HMAC。本工具用于本地 CTF、课堂和兼容性分析，不负责生产密钥托管。',
    }, null, 2);
  }

  const trimmed = value.trim();
  let token = trimmed.replace(/^Bearer\s+/i, '');
  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      if (typeof parsed.token === 'string' && parsed.token.trim()) token = parsed.token.trim();
    } catch {
      // Keep the original token text path.
    }
  }
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT 必须包含 Header.Payload.Signature 三段');
  const header = JSON.parse(fromBase64Url(parts[0]));
  const payload = JSON.parse(fromBase64Url(parts[1]));
  const headerSpec = isJsonRecord(header) ? jwtHmacSpecFromAlg(header.alg) : null;
  const spec = headerSpec || jwtHmacSpecFromHash(params.hashAlgorithm);
  const signingInput = `${parts[0]}.${parts[1]}`;
  const expectedBytes = await jwtHmacSignBytes(signingInput, params.secret, spec.subtle);
  const providedBytes = base64ToBytes(parts[2]);
  return JSON.stringify({
    valid: constantTimeEqual(providedBytes, expectedBytes),
    algorithm: spec.jwt,
    algorithmSource: headerSpec ? 'jwt-header' : 'selected-option',
    header,
    payload,
    timestamps: jwtTimestamps(payload),
    signingInput,
    signature: {
      providedBase64Url: parts[2],
      expectedBase64Url: bytesToBase64Url(expectedBytes),
      providedHex: bytesToHex(providedBytes),
      expectedHex: bytesToHex(expectedBytes),
    },
    warning: '仅支持 HS256/HS384/HS512 HMAC。本工具用于本地 CTF、课堂和兼容性分析，不负责生产密钥托管。',
  }, null, 2);
};

const jwtSignatureSummary = (base64Url: string) => {
  const bytes = base64ToBytes(base64Url);
  return {
    base64url: base64Url,
    bytes: bytes.length,
    hex: bytesToHex(bytes),
  };
};

const jwtPayloadSummary = (bytes: Uint8Array) => {
  const text = utf8Decoder.decode(bytes);
  try {
    const payload = JSON.parse(text);
    return {
      payload,
      payloadText: text,
      payloadHex: bytesToHex(bytes),
      timestamps: jwtTimestamps(payload),
    };
  } catch {
    return {
      payload: text,
      payloadText: text,
      payloadHex: bytesToHex(bytes),
      timestamps: {},
    };
  }
};

const jwtPublicTransform = async (value: string, params: Record<ParamKey, string>) => {
  const token = value.trim().replace(/^Bearer\s+/i, '');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT/JWS compact token must have Header.Payload.Signature');
  const keyMaterial = String(params.secret || '').trim();
  if (!keyMaterial) throw new Error('Public verification requires PEM, certificate, JWK, or JWKS input');

  const jose = await import('jose');
  const protectedHeader = jose.decodeProtectedHeader(token);
  const alg = typeof protectedHeader.alg === 'string' ? protectedHeader.alg : '';
  if (!alg || alg.toLowerCase() === 'none') {
    return JSON.stringify({
      valid: false,
      algorithm: alg || null,
      header: protectedHeader,
      signature: jwtSignatureSummary(parts[2]),
      error: 'Unsecured or missing alg is not verifiable with a public key',
    }, null, 2);
  }

  let keyMaterialType = 'unknown';
  try {
    let verification;
    if (/^\s*\{/.test(keyMaterial)) {
      const parsed = JSON.parse(keyMaterial) as Record<string, unknown>;
      if (Array.isArray(parsed.keys)) {
        keyMaterialType = 'JWKS';
        verification = await jose.compactVerify(token, jose.createLocalJWKSet(parsed as never));
      } else if ('kty' in parsed) {
        keyMaterialType = 'JWK';
        const key = await jose.importJWK(parsed as never, alg);
        verification = await jose.compactVerify(token, key);
      } else {
        throw new Error('JSON key material must be a JWK or JWKS object');
      }
    } else if (/-----BEGIN CERTIFICATE-----/.test(keyMaterial)) {
      keyMaterialType = 'X.509 certificate';
      const key = await jose.importX509(keyMaterial, alg);
      verification = await jose.compactVerify(token, key);
    } else if (/-----BEGIN [^-]*PUBLIC KEY-----/.test(keyMaterial)) {
      keyMaterialType = 'PEM public key';
      const key = await jose.importSPKI(keyMaterial, alg);
      verification = await jose.compactVerify(token, key);
    } else {
      throw new Error('Key material must be PEM public key, X.509 certificate, JWK, or JWKS');
    }

    const payloadSummary = jwtPayloadSummary(verification.payload);
    return JSON.stringify({
      valid: true,
      algorithm: alg,
      keyMaterialType,
      header: protectedHeader,
      payload: payloadSummary.payload,
      payloadText: payloadSummary.payloadText,
      payloadHex: payloadSummary.payloadHex,
      timestamps: payloadSummary.timestamps,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: jwtSignatureSummary(parts[2]),
      warning: 'Signature verification only. Claim validation such as exp, nbf, aud, and iss is shown but not enforced.',
    }, null, 2);
  } catch (error) {
    return JSON.stringify({
      valid: false,
      algorithm: alg || null,
      keyMaterialType,
      header: protectedHeader,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: jwtSignatureSummary(parts[2]),
      error: error instanceof Error ? error.message : String(error),
      warning: 'The token structure may still parse correctly even when signature verification fails.',
    }, null, 2);
  }
};

const bytesToBase64UrlPadded = (bytes: Uint8Array) => bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_');

const fernetKeyParts = (secret: string) => {
  if (!secret.trim()) throw new Error('Fernet 需要填写 URL-safe Base64 32 字节 key');
  const key = base64ToBytes(secret.trim());
  if (key.length !== 32) throw new Error(`Fernet key 解码后必须是 32 字节，当前是 ${key.length} 字节`);
  return {
    signingKey: key.slice(0, 16),
    encryptionKey: key.slice(16),
  };
};

const uint64Be = (value: bigint) => {
  const bytes = new Uint8Array(8);
  let current = value;
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return bytes;
};

const readUint64Be = (bytes: Uint8Array) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

const fernetHmac = async (signingKey: Uint8Array, data: Uint8Array) => {
  const key = await crypto.subtle.importKey('raw', bytesToBuffer(signingKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, bytesToBuffer(data)));
};

const constantTimeEqual = (a: Uint8Array, b: Uint8Array) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a[index] ^ b[index];
  return diff === 0;
};

const importFernetAesKey = (encryptionKey: Uint8Array, usages: KeyUsage[]) => crypto.subtle.importKey(
  'raw',
  bytesToBuffer(encryptionKey),
  { name: 'AES-CBC', length: 128 },
  false,
  usages,
);

const parseFernetRaw = (value: string) => {
  const raw = base64ToBytes(value.trim().replace(/^Fernet\s+/i, ''));
  if (raw.length < 57) throw new Error('Fernet token 过短，至少需要 version、timestamp、IV、ciphertext、HMAC');
  const version = raw[0];
  const timestamp = readUint64Be(raw.slice(1, 9));
  const iv = raw.slice(9, 25);
  const ciphertext = raw.slice(25, -32);
  const hmacTag = raw.slice(-32);
  if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) throw new Error('Fernet ciphertext 长度必须是 16 字节块的倍数');
  return { raw, version, timestamp, iv, ciphertext, hmacTag, signedData: raw.slice(0, -32) };
};

const encodeFernet = async (value: string, secret: string) => {
  const { signingKey, encryptionKey } = fernetKeyParts(secret);
  const timestamp = BigInt(Math.floor(Date.now() / 1000));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await importFernetAesKey(encryptionKey, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: bytesToBuffer(iv) },
    key,
    bytesToBuffer(utf8Encoder.encode(value)),
  ));
  const signedData = new Uint8Array([0x80, ...uint64Be(timestamp), ...iv, ...ciphertext]);
  const hmacTag = await fernetHmac(signingKey, signedData);
  return bytesToBase64UrlPadded(new Uint8Array([...signedData, ...hmacTag]));
};

const decodeFernet = async (value: string, secret: string) => {
  const parsed = parseFernetRaw(value);
  const result: Record<string, unknown> = {
    versionHex: `0x${parsed.version.toString(16).padStart(2, '0')}`,
    versionValid: parsed.version === 0x80,
    timestamp: parsed.timestamp.toString(),
    timestampIso: new Date(Number(parsed.timestamp) * 1000).toISOString(),
    ivHex: bytesToHex(parsed.iv),
    ciphertextBytes: parsed.ciphertext.length,
    ciphertextHex: bytesToHex(parsed.ciphertext),
    hmacHex: bytesToHex(parsed.hmacTag),
  };

  if (!secret.trim()) {
    result.note = '未填写 Fernet key，仅解析结构；填写 key 后可校验 HMAC 并解密。';
    return JSON.stringify(result, null, 2);
  }

  const { signingKey, encryptionKey } = fernetKeyParts(secret);
  const expected = await fernetHmac(signingKey, parsed.signedData);
  const hmacValid = constantTimeEqual(expected, parsed.hmacTag);
  result.expectedHmacHex = bytesToHex(expected);
  result.hmacValid = hmacValid;
  if (!hmacValid) return JSON.stringify(result, null, 2);

  const key = await importFernetAesKey(encryptionKey, ['decrypt']);
  const plaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: bytesToBuffer(parsed.iv) },
    key,
    bytesToBuffer(parsed.ciphertext),
  ));
  result.plaintext = utf8Decoder.decode(plaintext);
  result.plaintextHex = bytesToHex(plaintext);
  return JSON.stringify(result, null, 2);
};

const normalizeOtpAlgorithm = (value: string) => {
  const normalized = String(value || 'sha1').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (normalized === 'sha256') return { subtle: 'SHA-256', label: 'SHA256' };
  if (normalized === 'sha512') return { subtle: 'SHA-512', label: 'SHA512' };
  return { subtle: 'SHA-1', label: 'SHA1' };
};

const parseOtpDigits = (value: string) => {
  const digits = Number.parseInt(String(value || '6'), 10);
  if (!Number.isFinite(digits) || digits < 4 || digits > 10) throw new Error('OTP 位数必须在 4 到 10 之间');
  return digits;
};

const parseOtpCounter = (value: string) => {
  const text = String(value ?? '').trim();
  if (!/^\d+$/.test(text)) throw new Error('HOTP counter 必须是非负整数');
  return BigInt(text);
};

const normalizeOtpSecret = (value: string) => {
  const secret = String(value || '').trim().replace(/\s+/g, '');
  if (!secret) throw new Error('OTP 需要 Base32 secret');
  return secret;
};

const hotpCode = async (secret: string, counterValue: bigint, algorithm: string, digitsValue: number) => {
  const secretBytes = decodeBase32Bytes(secret, 'special');
  const counterBytes = uint64Be(counterValue);
  const key = await crypto.subtle.importKey(
    'raw',
    bytesToBuffer(secretBytes),
    { name: 'HMAC', hash: normalizeOtpAlgorithm(algorithm).subtle },
    false,
    ['sign'],
  );
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, bytesToBuffer(counterBytes)));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24)
    | (mac[offset + 1] << 16)
    | (mac[offset + 2] << 8)
    | mac[offset + 3];
  const code = String(binary % (10 ** digitsValue)).padStart(digitsValue, '0');
  return {
    code,
    offset,
    digestHex: bytesToHex(mac),
  };
};

const generateHotp = async (secret: string, algorithm: string, digitsText: string, counterText: string) => {
  const digitsValue = parseOtpDigits(digitsText);
  const counterValue = parseOtpCounter(counterText);
  const algorithmInfo = normalizeOtpAlgorithm(algorithm);
  const result = await hotpCode(normalizeOtpSecret(secret), counterValue, algorithm, digitsValue);
  return JSON.stringify({
    type: 'HOTP',
    algorithm: algorithmInfo.label,
    digits: digitsValue,
    counter: counterValue.toString(),
    code: result.code,
    digestHex: result.digestHex,
    dynamicTruncationOffset: result.offset,
  }, null, 2);
};

const generateTotp = async (secret: string, algorithm: string, digitsText: string, stepText: string, timestampText: string) => {
  const digitsValue = parseOtpDigits(digitsText);
  const step = Math.max(1, Number.parseInt(String(stepText || '30'), 10) || 30);
  const timestamp = String(timestampText || '').trim()
    ? Number.parseInt(timestampText, 10)
    : Math.floor(Date.now() / 1000);
  if (!Number.isFinite(timestamp) || timestamp < 0) throw new Error('TOTP 时间戳必须是非负秒数');
  const counterValue = BigInt(Math.floor(timestamp / step));
  const algorithmInfo = normalizeOtpAlgorithm(algorithm);
  const result = await hotpCode(normalizeOtpSecret(secret), counterValue, algorithm, digitsValue);
  return JSON.stringify({
    type: 'TOTP',
    algorithm: algorithmInfo.label,
    digits: digitsValue,
    timeStep: step,
    timestamp,
    timestampIso: new Date(timestamp * 1000).toISOString(),
    counter: counterValue.toString(),
    validForSeconds: step - (timestamp % step),
    code: result.code,
    digestHex: result.digestHex,
    dynamicTruncationOffset: result.offset,
  }, null, 2);
};

const parseOtpLabel = (value: string) => {
  const decoded = decodeURIComponent(value.replace(/^\/+/, ''));
  const separator = decoded.indexOf(':');
  if (separator < 0) return { label: decoded, issuerFromLabel: '', accountName: decoded };
  return {
    label: decoded,
    issuerFromLabel: decoded.slice(0, separator).trim(),
    accountName: decoded.slice(separator + 1).trim(),
  };
};

const encodeOtpAuthUri = (label: string, params: Record<ParamKey, string>) => {
  const trimmedLabel = String(label || '').trim();
  if (!trimmedLabel) throw new Error('生成 otpauth URI 需要输入标签，例如 issuer:account');
  const secret = String(params.secret || '').trim().replace(/\s+/g, '');
  if (!secret) throw new Error('生成 otpauth URI 需要填写 Base32 secret');
  const type = params.variant === 'hex' ? 'hotp' : 'totp';
  const algorithm = normalizeOtpAlgorithm(params.hashAlgorithm).label;
  const digitsValue = parseOtpDigits(params.digits);
  const query = new URLSearchParams();
  query.set('secret', secret);
  query.set('algorithm', algorithm);
  query.set('digits', String(digitsValue));
  const labelInfo = parseOtpLabel(encodeURIComponent(trimmedLabel));
  if (labelInfo.issuerFromLabel) query.set('issuer', labelInfo.issuerFromLabel);
  if (type === 'hotp') {
    query.set('counter', parseOtpCounter(params.counter).toString());
  } else {
    query.set('period', String(Math.max(1, Number.parseInt(String(params.timeStep || '30'), 10) || 30)));
  }
  return `otpauth://${type}/${encodeURIComponent(trimmedLabel)}?${query.toString()}`;
};

const decodeOtpAuthUri = async (value: string) => {
  const uri = new URL(String(value || '').trim());
  if (uri.protocol !== 'otpauth:') throw new Error('输入必须是 otpauth:// URI');
  const type = uri.hostname.toLowerCase();
  if (type !== 'hotp' && type !== 'totp') throw new Error('otpauth URI 仅支持 hotp 或 totp');
  const labelInfo = parseOtpLabel(uri.pathname);
  const secret = String(uri.searchParams.get('secret') || '').trim();
  const algorithmRaw = uri.searchParams.get('algorithm') || 'SHA1';
  const algorithm = normalizeOtpAlgorithm(algorithmRaw).label;
  const digitsValue = parseOtpDigits(uri.searchParams.get('digits') || '6');
  const periodValue = Math.max(1, Number.parseInt(uri.searchParams.get('period') || '30', 10) || 30);
  const counterText = uri.searchParams.get('counter') || '0';
  const issuer = uri.searchParams.get('issuer') || labelInfo.issuerFromLabel || '';

  const result: Record<string, unknown> = {
    type,
    label: labelInfo.label,
    accountName: labelInfo.accountName,
    issuer,
    secret,
    algorithm,
    digits: digitsValue,
    counter: type === 'hotp' ? counterText : undefined,
    period: type === 'totp' ? periodValue : undefined,
  };

  if (!secret) {
    result.note = 'URI 中没有 secret，无法计算验证码';
    return JSON.stringify(result, null, 2);
  }

  if (type === 'hotp') {
    const counterValue = parseOtpCounter(counterText);
    const code = await hotpCode(secret, counterValue, algorithmRaw, digitsValue);
    result.currentCode = code.code;
    result.digestHex = code.digestHex;
    result.dynamicTruncationOffset = code.offset;
  } else {
    const timestamp = Math.floor(Date.now() / 1000);
    const counterValue = BigInt(Math.floor(timestamp / periodValue));
    const code = await hotpCode(secret, counterValue, algorithmRaw, digitsValue);
    result.timestamp = timestamp;
    result.timestampIso = new Date(timestamp * 1000).toISOString();
    result.timeStep = periodValue;
    result.counter = counterValue.toString();
    result.validForSeconds = periodValue - (timestamp % periodValue);
    result.currentCode = code.code;
    result.digestHex = code.digestHex;
    result.dynamicTruncationOffset = code.offset;
  }

  return JSON.stringify(result, null, 2);
};

const decodeOtpAuthUriCompat = async (value: string) => {
  try {
    return await decodeOtpAuthUri(value);
  } catch {
    // Fall through to the browser-stable parser below.
  }
  const text = String(value || '').trim();
  const match = /^otpauth:\/\/(hotp|totp)\/([^?]+)(?:\?(.*))?$/i.exec(text);
  if (!match) throw new Error('Input must be an otpauth:// URI');
  const [, rawType, rawLabel, rawQuery = ''] = match;
  const type = rawType.toLowerCase();
  if (type !== 'hotp' && type !== 'totp') throw new Error('otpauth URI only supports hotp and totp');
  const labelInfo = parseOtpLabel(rawLabel);
  const searchParams = new URLSearchParams(rawQuery);
  const secret = String(searchParams.get('secret') || '').trim();
  const algorithmRaw = searchParams.get('algorithm') || 'SHA1';
  const algorithm = normalizeOtpAlgorithm(algorithmRaw).label;
  const digitsValue = parseOtpDigits(searchParams.get('digits') || '6');
  const periodValue = Math.max(1, Number.parseInt(searchParams.get('period') || '30', 10) || 30);
  const counterText = searchParams.get('counter') || '0';
  const issuer = searchParams.get('issuer') || labelInfo.issuerFromLabel || '';

  const result: Record<string, unknown> = {
    type,
    label: labelInfo.label,
    accountName: labelInfo.accountName,
    issuer,
    secret,
    algorithm,
    digits: digitsValue,
    counter: type === 'hotp' ? counterText : undefined,
    period: type === 'totp' ? periodValue : undefined,
  };

  if (!secret) {
    result.note = 'URI is missing secret, so no OTP code can be calculated.';
    return JSON.stringify(result, null, 2);
  }

  if (type === 'hotp') {
    const counterValue = parseOtpCounter(counterText);
    const code = await hotpCode(secret, counterValue, algorithmRaw, digitsValue);
    result.currentCode = code.code;
    result.digestHex = code.digestHex;
    result.dynamicTruncationOffset = code.offset;
  } else {
    const timestamp = Math.floor(Date.now() / 1000);
    const counterValue = BigInt(Math.floor(timestamp / periodValue));
    const code = await hotpCode(secret, counterValue, algorithmRaw, digitsValue);
    result.timestamp = timestamp;
    result.timestampIso = new Date(timestamp * 1000).toISOString();
    result.timeStep = periodValue;
    result.counter = counterValue.toString();
    result.validForSeconds = periodValue - (timestamp % periodValue);
    result.currentCode = code.code;
    result.digestHex = code.digestHex;
    result.dynamicTruncationOffset = code.offset;
  }

  return JSON.stringify(result, null, 2);
};

const safeJsonValue = (value: unknown, depth = 0, seen = new WeakSet<object>()): unknown => {
  if (depth > 20) return '[Max depth reached]';
  if (typeof value === 'bigint') return `${value.toString()}n`;
  if (value == null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (value instanceof Date) return value.toISOString();
  if (value instanceof ArrayBuffer) return safeJsonValue(new Uint8Array(value), depth + 1, seen);
  if (ArrayBuffer.isView(value)) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let utf8Preview = '';
    try {
      utf8Preview = utf8Decoder.decode(bytes.slice(0, 120)).replace(/\p{Cc}/gu, '.');
    } catch {
      utf8Preview = '';
    }
    return {
      type: value.constructor.name,
      bytes: bytes.length,
      hex: bytesToHex(bytes.slice(0, 160)),
      utf8Preview,
    };
  }
  if (value instanceof Map) {
    return {
      type: 'Map',
      entries: Array.from(value.entries()).map(([key, entry]) => [safeJsonValue(key, depth + 1, seen), safeJsonValue(entry, depth + 1, seen)]),
    };
  }
  if (Array.isArray(value)) return value.map(entry => safeJsonValue(entry, depth + 1, seen));
  if (typeof value === 'object') {
    if (seen.has(value)) return '[Circular]';
    seen.add(value);
    const source = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    if (value.constructor?.name && value.constructor.name !== 'Object') result.type = value.constructor.name;
    for (const [key, entry] of Object.entries(source)) result[key] = safeJsonValue(entry, depth + 1, seen);
    return result;
  }
  return String(value);
};

const parseBinaryEncodedInput = (value: string, label: string) => {
  const text = value.trim();
  if (!text) throw new Error(`${label} 需要输入 Hex 或 Base64 数据`);
  const dataUrl = text.match(/^data:[^,]+,(.+)$/s);
  if (dataUrl) return { encoding: /;base64/i.test(text) ? 'data-url-base64' : 'data-url-percent', bytes: /;base64/i.test(text) ? base64ToBytes(dataUrl[1]) : utf8Encoder.encode(decodeURIComponent(dataUrl[1])) };
  const hexClean = text.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  if (/^[0-9a-fA-Fx\\\s:,_-]+$/.test(text) && hexClean.length >= 2 && hexClean.length % 2 === 0) {
    return { encoding: 'hex', bytes: hexToBytes(text) };
  }
  if (/^[A-Za-z0-9+/_=-\s]+$/.test(text)) return { encoding: 'base64/base64url', bytes: base64ToBytes(text) };
  throw new Error(`${label} 输入无法识别，请使用 Hex、Base64 或 Base64URL`);
};

const parseCbor = async (value: string) => {
  const input = parseBinaryEncodedInput(value, 'CBOR');
  const { decode } = await import('cbor-x');
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    decoded: safeJsonValue(decode(input.bytes)),
  }, null, 2);
};

const parseMessagePack = async (value: string) => {
  const input = parseBinaryEncodedInput(value, 'MessagePack');
  const { decode } = await import('@msgpack/msgpack');
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    decoded: safeJsonValue(decode(input.bytes, { useBigInt64: true })),
  }, null, 2);
};

type ProtobufField = {
  offset: number;
  field: number;
  wireType: number;
  wireTypeName: string;
  value?: unknown;
  error?: string;
};

const protobufWireTypeNames: Record<number, string> = {
  0: 'varint',
  1: 'fixed64',
  2: 'length-delimited',
  3: 'start-group',
  4: 'end-group',
  5: 'fixed32',
};

type ProtobufReaderClass = typeof import('protobufjs').Reader;

const looksLikeNestedProtobuf = (bytes: Uint8Array, Reader: ProtobufReaderClass) => {
  if (bytes.length < 2 || bytes.length > 512) return false;
  try {
    const fields = parseProtobufFields(bytes, Reader, 1);
    return fields.length > 0 && fields.every(field => !field.error);
  } catch {
    return false;
  }
};

const parseProtobufFields = (bytes: Uint8Array, Reader: ProtobufReaderClass, depth = 0): ProtobufField[] => {
  if (depth > 4) return [];
  const reader = Reader.create(bytes) as import('protobufjs').Reader;
  const fields: ProtobufField[] = [];
  while (reader.pos < reader.len && fields.length < 512) {
    const offset = reader.pos;
    try {
      const tag = reader.uint32();
      const field = tag >>> 3;
      const wireType = tag & 7;
      const entry: ProtobufField = {
        offset,
        field,
        wireType,
        wireTypeName: protobufWireTypeNames[wireType] || 'unknown',
      };
      if (!field) {
        entry.error = 'field number 0 is invalid';
        fields.push(entry);
        break;
      }
      if (wireType === 0) {
        const value = reader.uint64().toString();
        entry.value = { uint64: value, int64: value, boolCandidate: value === '0' ? false : value === '1' ? true : null };
      } else if (wireType === 1) {
        const start = reader.pos;
        const fixed64 = reader.fixed64().toString();
        entry.value = { fixed64, doubleCandidate: new DataView(reader.buf.buffer, reader.buf.byteOffset + start, 8).getFloat64(0, true), rawHex: bytesToHex(reader.buf.slice(start, start + 8)) };
      } else if (wireType === 2) {
        const length = reader.uint32();
        const start = reader.pos;
        const end = start + length;
        if (end > reader.len) throw new Error('length-delimited field exceeds buffer length');
        const data = reader.buf.slice(start, end);
        reader.pos = end;
        let utf8Preview = '';
        try { utf8Preview = utf8Decoder.decode(data).replace(/\p{Cc}/gu, '.'); } catch { utf8Preview = ''; }
        entry.value = {
          bytes: data.length,
          hexPreview: bytesToHex(data.slice(0, 128)),
          utf8Preview,
          nestedFields: depth < 3 && looksLikeNestedProtobuf(data, Reader) ? parseProtobufFields(data, Reader, depth + 1) : undefined,
        };
      } else if (wireType === 5) {
        const start = reader.pos;
        const fixed32 = reader.fixed32();
        entry.value = { fixed32, floatCandidate: new DataView(reader.buf.buffer, reader.buf.byteOffset + start, 4).getFloat32(0, true), rawHex: bytesToHex(reader.buf.slice(start, start + 4)) };
      } else if (wireType === 3 || wireType === 4) {
        entry.value = 'group wire types are deprecated; skipped as opaque group boundary';
        reader.skipType(wireType, depth, field);
      } else {
        entry.error = 'unsupported wire type';
        reader.skipType(wireType);
      }
      fields.push(entry);
    } catch (error) {
      fields.push({
        offset,
        field: -1,
        wireType: -1,
        wireTypeName: 'parse-error',
        error: error instanceof Error ? error.message : String(error),
      });
      break;
    }
  }
  return fields;
};

const parseProtobufRaw = async (value: string) => {
  const input = parseBinaryEncodedInput(value, 'Protobuf');
  const { Reader } = await import('protobufjs');
  const fields = parseProtobufFields(input.bytes, Reader);
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    fields,
  }, null, 2);
};

const parseBson = async (value: string) => {
  const input = parseBinaryEncodedInput(value, 'BSON');
  const { deserialize, EJSON } = await import('bson');
  const doc = deserialize(input.bytes, { promoteLongs: false, promoteBuffers: false });
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    document: JSON.parse(EJSON.stringify(doc, undefined, 2, { relaxed: true })),
    canonicalEjson: JSON.parse(EJSON.stringify(doc, undefined, 2, { relaxed: false })),
  }, null, 2);
};

const looksLikeBson = (value: string) => {
  try {
    const bytes = hexToBytes(value);
    if (bytes.length < 5) return false;
    const length = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
    return length === bytes.length && bytes[bytes.length - 1] === 0;
  } catch {
    return false;
  }
};

const looksLikeProtobufWire = (value: string) => {
  try {
    const bytes = parseBinaryEncodedInput(value, 'Protobuf').bytes;
    if (bytes.length < 2) return false;
    const first = bytes[0];
    const fieldNumber = first >>> 3;
    const wireType = first & 7;
    return fieldNumber > 0 && [0, 1, 2, 5].includes(wireType);
  } catch {
    return false;
  }
};

const decodeBase64UrlJson = (value: string) => JSON.parse(utf8Decoder.decode(base64ToBytes(value)));

const base64UrlFieldInfo = (value: unknown) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+={0,2}$/.test(value)) return value;
  try {
    const bytes = base64ToBytes(value);
    return {
      base64url: value,
      bytes: bytes.length,
      bits: bytes.length * 8,
      hexPreview: bytesToHex(bytes.slice(0, 64)),
    };
  } catch {
    return value;
  }
};

const summarizeJwk = (jwk: Record<string, unknown>) => {
  const keyFields = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'x', 'y', 'k'];
  const params = Object.fromEntries(keyFields
    .filter(key => key in jwk)
    .map(key => [key, base64UrlFieldInfo(jwk[key])]));
  const thumbprintMembers = Object.fromEntries(['crv', 'e', 'k', 'kty', 'n', 'x', 'y']
    .filter(key => key in jwk)
    .map(key => [key, jwk[key]]));
  return {
    kty: jwk.kty,
    use: jwk.use,
    keyOps: jwk.key_ops,
    alg: jwk.alg,
    kid: jwk.kid,
    crv: jwk.crv,
    params,
    thumbprintMembers,
  };
};

const parseJwkJwe = (value: string) => {
  const text = value.trim().replace(/^Bearer\s+/i, '');
  const compactParts = text.split('.');
  if (compactParts.length === 5) {
    const [protectedHeader, encryptedKey, iv, ciphertext, tag] = compactParts;
    return JSON.stringify({
      format: 'JWE Compact Serialization',
      protectedHeader: decodeBase64UrlJson(protectedHeader),
      encryptedKey: base64UrlFieldInfo(encryptedKey),
      iv: base64UrlFieldInfo(iv),
      ciphertext: base64UrlFieldInfo(ciphertext),
      authenticationTag: base64UrlFieldInfo(tag),
      note: '这里只解析 JOSE/JWE 结构和字段长度，不尝试解密内容。',
    }, null, 2);
  }

  const parsed = JSON.parse(text) as Record<string, unknown>;
  if (Array.isArray(parsed.keys)) {
    return JSON.stringify({
      format: 'JWKS',
      keys: parsed.keys.map(key => summarizeJwk(key as Record<string, unknown>)),
    }, null, 2);
  }
  if ('kty' in parsed) {
    return JSON.stringify({
      format: 'JWK',
      key: summarizeJwk(parsed),
    }, null, 2);
  }
  if ('protected' in parsed || 'ciphertext' in parsed || 'recipients' in parsed) {
    const protectedHeader = typeof parsed.protected === 'string' ? decodeBase64UrlJson(parsed.protected) : null;
    return JSON.stringify({
      format: 'JWE JSON Serialization',
      protectedHeader,
      iv: base64UrlFieldInfo(parsed.iv),
      ciphertext: base64UrlFieldInfo(parsed.ciphertext),
      tag: base64UrlFieldInfo(parsed.tag),
      encryptedKey: base64UrlFieldInfo(parsed.encrypted_key),
      recipients: safeJsonValue(parsed.recipients),
      note: '这里只解析 JWE JSON 字段结构，不尝试解密内容。',
    }, null, 2);
  }
  throw new Error('未识别为 JWK、JWKS 或 JWE');
};

const readSshUint32 = (bytes: Uint8Array, offset: number) => {
  if (offset + 4 > bytes.length) throw new Error('SSH blob 字段长度不完整');
  return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
};

const readSshString = (bytes: Uint8Array, offset: number) => {
  const length = readSshUint32(bytes, offset);
  const start = offset + 4;
  const end = start + length;
  if (end > bytes.length) throw new Error('SSH blob string 字段超出范围');
  const data = bytes.slice(start, end);
  return { data, text: utf8Decoder.decode(data), next: end };
};

const sshMpintInfo = (bytes: Uint8Array) => {
  const stripped = bytes[0] === 0 ? bytes.slice(1) : bytes;
  const value = stripped.length <= 8 ? asn1BytesToBigInt(stripped).toString() : undefined;
  return {
    bytes: bytes.length,
    bits: stripped.length ? bitLength(asn1BytesToBigInt(stripped)) : 0,
    hexPreview: bytesToHex(bytes.slice(0, 64)),
    decimal: value,
  };
};

const parseSshPublicKey = async (value: string) => {
  const tokens = value.trim().split(/\s+/);
  const keyIndex = tokens.findIndex(token => /^(ssh-|ecdsa-|sk-)/.test(token));
  if (keyIndex < 0 || !tokens[keyIndex + 1]) throw new Error('请输入 OpenSSH 公钥行，例如 ssh-ed25519 AAAA... comment');
  const declaredType = tokens[keyIndex];
  const blob = base64ToBytes(tokens[keyIndex + 1]);
  let offset = 0;
  const typeField = readSshString(blob, offset);
  offset = typeField.next;
  const fields: Record<string, unknown> = {};
  if (typeField.text === 'ssh-rsa') {
    const e = readSshString(blob, offset);
    const n = readSshString(blob, e.next);
    offset = n.next;
    fields.exponent = sshMpintInfo(e.data);
    fields.modulus = sshMpintInfo(n.data);
  } else if (typeField.text === 'ssh-ed25519' || typeField.text === 'sk-ssh-ed25519@openssh.com') {
    const key = readSshString(blob, offset);
    offset = key.next;
    fields.publicKey = { bytes: key.data.length, hex: bytesToHex(key.data) };
  } else if (typeField.text.startsWith('ecdsa-sha2-') || typeField.text === 'sk-ecdsa-sha2-nistp256@openssh.com') {
    const curve = readSshString(blob, offset);
    const point = readSshString(blob, curve.next);
    offset = point.next;
    fields.curve = curve.text;
    fields.publicPoint = { bytes: point.data.length, hexPreview: bytesToHex(point.data.slice(0, 96)) };
  } else {
    const rest: Array<{ bytes: number; textPreview: string; hexPreview: string }> = [];
    while (offset < blob.length) {
      const field = readSshString(blob, offset);
      rest.push({ bytes: field.data.length, textPreview: field.text.replace(/\p{Cc}/gu, '.'), hexPreview: bytesToHex(field.data.slice(0, 64)) });
      offset = field.next;
    }
    fields.remainingFields = rest;
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytesToBuffer(blob)));
  return JSON.stringify({
    declaredType,
    blobType: typeField.text,
    comment: tokens.slice(keyIndex + 2).join(' '),
    fingerprint: `SHA256:${base64ToBase64Url(bytesToBase64(digest))}`,
    blobBytes: blob.length,
    fields,
    trailingBytes: blob.length - offset,
  }, null, 2);
};

const punycodeAdapt = (delta: number, points: number, firstTime: boolean) => {
  let next = firstTime ? Math.floor(delta / 700) : Math.floor(delta / 2);
  next += Math.floor(next / points);
  let k = 0;
  while (next > 455) {
    next = Math.floor(next / 35);
    k += 36;
  }
  return k + Math.floor((36 * next) / (next + 38));
};

const punycodeDigitToBasic = (digit: number) => String.fromCharCode(digit + 22 + 75 * Number(digit < 26));
const punycodeBasicToDigit = (codePoint: number) => {
  if (codePoint >= 48 && codePoint <= 57) return codePoint - 22;
  if (codePoint >= 65 && codePoint <= 90) return codePoint - 65;
  if (codePoint >= 97 && codePoint <= 122) return codePoint - 97;
  return 36;
};

const punycodeEncodeLabel = (value: string) => {
  const codePoints = Array.from(value).map(char => char.codePointAt(0) || 0);
  const basic = codePoints.filter(point => point < 0x80).map(point => String.fromCodePoint(point)).join('');
  let output = basic;
  let handled = basic.length;
  if (basic.length) output += '-';
  let n = 128;
  let delta = 0;
  let bias = 72;
  while (handled < codePoints.length) {
    const m = Math.min(...codePoints.filter(point => point >= n));
    delta += (m - n) * (handled + 1);
    n = m;
    for (const point of codePoints) {
      if (point < n) delta += 1;
      if (point === n) {
        let q = delta;
        for (let k = 36; ; k += 36) {
          const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
          if (q < t) break;
          output += punycodeDigitToBasic(t + ((q - t) % (36 - t)));
          q = Math.floor((q - t) / (36 - t));
        }
        output += punycodeDigitToBasic(q);
        bias = punycodeAdapt(delta, handled + 1, handled === basic.length);
        delta = 0;
        handled += 1;
      }
    }
    delta += 1;
    n += 1;
  }
  return output;
};

const punycodeDecodeLabel = (value: string) => {
  const output = [];
  const delimiter = value.lastIndexOf('-');
  let index = 0;
  let n = 128;
  let i = 0;
  let bias = 72;
  if (delimiter >= 0) {
    for (const char of value.slice(0, delimiter)) output.push(char.codePointAt(0) || 0);
    index = delimiter + 1;
  }
  while (index < value.length) {
    const oldI = i;
    let weight = 1;
    for (let k = 36; ; k += 36) {
      if (index >= value.length) throw new Error('Punycode 数据不完整');
      const digit = punycodeBasicToDigit(value.charCodeAt(index++));
      i += digit * weight;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      weight *= 36 - t;
    }
    bias = punycodeAdapt(i - oldI, output.length + 1, oldI === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...output);
};

const encodePunycode = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return '';
  const url = /^https?:\/\//i.test(trimmed) ? new URL(trimmed) : new URL(`http://${trimmed}`);
  const host = url.hostname
    .split('.')
    .map(label => Array.from(label).some(char => char.codePointAt(0)! > 0x7f) ? `xn--${punycodeEncodeLabel(label)}` : label)
    .join('.');
  return /^https?:\/\//i.test(trimmed) ? trimmed.replace(url.hostname, host) : host;
};

const decodePunycode = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return '';
  const url = /^https?:\/\//i.test(trimmed) ? new URL(trimmed) : new URL(`http://${trimmed}`);
  const host = url.hostname
    .split('.')
    .map(label => label.startsWith('xn--') ? punycodeDecodeLabel(label.slice(4)) : label)
    .join('.');
  return /^https?:\/\//i.test(trimmed) ? trimmed.replace(url.hostname, host) : host;
};

const encodePemBlock = (value: string, blockLabel: string) => {
  const label = (blockLabel || 'PUBLIC KEY').trim().toUpperCase();
  const clean = value.replace(/\s+/g, '');
  const body = /^[A-Za-z0-9+/=]+$/.test(clean) ? clean : textToBase64(value);
  const wrapped = body.match(/.{1,64}/g)?.join('\n') || body;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
};

const decodePemBlock = (value: string) => {
  const match = value.trim().match(/-----BEGIN ([^-]+)-----\s*([\s\S]+?)\s*-----END \1-----/);
  if (!match) throw new Error('PEM 块格式不正确');
  const body = match[2].replace(/\s+/g, '');
  return JSON.stringify({
    label: match[1].trim(),
    base64: body,
    textPreview: (() => {
      try { return base64ToText(body); } catch { return ''; }
    })(),
  }, null, 2);
};

type Asn1Node = {
  offset: number;
  end: number;
  tag: string;
  tagClass: string;
  constructed: boolean;
  type: string;
  length: number | 'indefinite';
  value?: unknown;
  children?: Asn1Node[];
};

type Asn1ParseState = {
  count: number;
};

const asn1ClassNames = ['universal', 'application', 'context-specific', 'private'];
const asn1UniversalTypes: Record<number, string> = {
  0: 'EOC',
  1: 'BOOLEAN',
  2: 'INTEGER',
  3: 'BIT STRING',
  4: 'OCTET STRING',
  5: 'NULL',
  6: 'OBJECT IDENTIFIER',
  10: 'ENUMERATED',
  12: 'UTF8String',
  16: 'SEQUENCE',
  17: 'SET',
  18: 'NumericString',
  19: 'PrintableString',
  20: 'TeletexString',
  22: 'IA5String',
  23: 'UTCTime',
  24: 'GeneralizedTime',
  26: 'VisibleString',
  27: 'GeneralString',
  28: 'UniversalString',
  30: 'BMPString',
};

const parseAsn1Input = (value: string) => {
  const text = value.trim();
  const pem = text.match(/-----BEGIN ([^-]+)-----\s*([\s\S]+?)\s*-----END \1-----/);
  if (pem) return { encoding: `PEM ${pem[1].trim()}`, bytes: base64ToBytes(pem[2].replace(/\s+/g, '')) };
  const compact = text.replace(/\s+/g, '');
  const hexClean = text.replace(/\\x/gi, '').replace(/0x/gi, '').replace(/[^0-9a-f]/gi, '');
  if (/^[0-9a-fA-Fx\\\s:,-]+$/.test(text) && hexClean.length >= 2 && hexClean.length % 2 === 0) {
    return { encoding: 'hex', bytes: hexToBytes(text) };
  }
  if (/^[A-Za-z0-9+/_=-]+$/.test(compact)) return { encoding: 'base64', bytes: base64ToBytes(compact) };
  throw new Error('ASN.1 输入需要是 PEM、Base64 或 Hex DER/BER 数据');
};

const asn1BytesToBigInt = (bytes: Uint8Array) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

const decodeAsn1Integer = (bytes: Uint8Array) => {
  if (!bytes.length) return { hex: '', decimal: '0' };
  const unsigned = asn1BytesToBigInt(bytes);
  const bits = BigInt(bytes.length * 8);
  const signed = (bytes[0] & 0x80) ? unsigned - (1n << bits) : unsigned;
  return bytes.length <= 8
    ? { hex: bytesToHex(bytes), decimal: signed.toString() }
    : { hex: bytesToHex(bytes), bytes: bytes.length, note: '整数过长，仅显示 hex' };
};

const decodeAsn1Oid = (bytes: Uint8Array) => {
  const values: number[] = [];
  let current = 0;
  for (const byte of bytes) {
    current = current * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      values.push(current);
      current = 0;
    }
  }
  if (!values.length) return '';
  const firstValue = values[0];
  const first = firstValue < 40 ? 0 : firstValue < 80 ? 1 : 2;
  const second = first === 2 ? firstValue - 80 : firstValue - first * 40;
  return [first, second, ...values.slice(1)].join('.');
};

const decodeAsn1Text = (tagNumber: number, bytes: Uint8Array) => {
  if (tagNumber === 30) {
    const chars: string[] = [];
    for (let index = 0; index + 1 < bytes.length; index += 2) chars.push(String.fromCharCode((bytes[index] << 8) | bytes[index + 1]));
    return chars.join('');
  }
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    return Array.from(bytes, byte => String.fromCharCode(byte)).join('');
  }
};

const asn1Value = (tagClass: string, tagNumber: number, bytes: Uint8Array) => {
  if (tagClass !== 'universal') return bytes.length ? { hexPreview: bytesToHex(bytes.slice(0, 48)), bytes: bytes.length } : '';
  if (tagNumber === 1) return bytes[0] !== 0;
  if (tagNumber === 2 || tagNumber === 10) return decodeAsn1Integer(bytes);
  if (tagNumber === 3) return { unusedBits: bytes[0] || 0, hex: bytesToHex(bytes.slice(1)), bytes: Math.max(0, bytes.length - 1) };
  if (tagNumber === 4) return { hexPreview: bytesToHex(bytes.slice(0, 80)), bytes: bytes.length };
  if (tagNumber === 5) return null;
  if (tagNumber === 6) return decodeAsn1Oid(bytes);
  if ([12, 18, 19, 20, 22, 23, 24, 26, 27, 30].includes(tagNumber)) return decodeAsn1Text(tagNumber, bytes);
  return bytes.length ? { hexPreview: bytesToHex(bytes.slice(0, 48)), bytes: bytes.length } : '';
};

const readAsn1Tag = (bytes: Uint8Array, offset: number, limit: number) => {
  if (offset >= limit) throw new Error('ASN.1 tag 超出输入范围');
  const first = bytes[offset];
  let cursor = offset + 1;
  let tagNumber = first & 0x1f;
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    while (cursor < limit) {
      const byte = bytes[cursor];
      tagNumber = tagNumber * 128 + (byte & 0x7f);
      cursor += 1;
      if ((byte & 0x80) === 0) break;
    }
  }
  return {
    cursor,
    tagHex: bytesToHex(bytes.slice(offset, cursor)),
    tagClass: asn1ClassNames[(first >> 6) & 3],
    constructed: (first & 0x20) !== 0,
    tagNumber,
  };
};

const readAsn1Length = (bytes: Uint8Array, offset: number, limit: number) => {
  if (offset >= limit) throw new Error('ASN.1 length 超出输入范围');
  const first = bytes[offset];
  if (first < 0x80) return { cursor: offset + 1, length: first as number | 'indefinite' };
  if (first === 0x80) return { cursor: offset + 1, length: 'indefinite' as const };
  const count = first & 0x7f;
  if (count > 4) throw new Error('ASN.1 length 字段过长，已拒绝解析');
  if (offset + 1 + count > limit) throw new Error('ASN.1 length 字段不完整');
  let length = 0;
  for (let index = 0; index < count; index += 1) length = length * 256 + bytes[offset + 1 + index];
  return { cursor: offset + 1 + count, length };
};

const parseAsn1Node = (bytes: Uint8Array, offset: number, limit: number, depth: number, state: Asn1ParseState): Asn1Node => {
  if (depth > 16) throw new Error('ASN.1 嵌套超过 16 层，已停止解');
  state.count += 1;
  if (state.count > 512) throw new Error('ASN.1 节点超过 512 个，已停止解');
  const tag = readAsn1Tag(bytes, offset, limit);
  const length = readAsn1Length(bytes, tag.cursor, limit);
  const valueStart = length.cursor;
  const valueEnd = length.length === 'indefinite' ? limit : valueStart + length.length;
  if (valueEnd > limit) throw new Error('ASN.1 value 长度超出输入范围');
  const type = tag.tagClass === 'universal' ? asn1UniversalTypes[tag.tagNumber] || `Universal ${tag.tagNumber}` : `${tag.tagClass} ${tag.tagNumber}`;
  const node: Asn1Node = {
    offset,
    end: valueEnd,
    tag: tag.tagHex,
    tagClass: tag.tagClass,
    constructed: tag.constructed,
    type,
    length: length.length,
  };
  if (tag.constructed || length.length === 'indefinite') {
    const children: Asn1Node[] = [];
    let cursor = valueStart;
    while (cursor < valueEnd) {
      if (length.length === 'indefinite' && bytes[cursor] === 0 && bytes[cursor + 1] === 0) {
        cursor += 2;
        break;
      }
      const child = parseAsn1Node(bytes, cursor, valueEnd, depth + 1, state);
      if (child.end <= cursor) throw new Error('ASN.1 子节点没有推进游');
      children.push(child);
      cursor = child.end;
    }
    node.children = children;
    node.end = length.length === 'indefinite' ? cursor : valueEnd;
  } else {
    const rawValue = bytes.slice(valueStart, valueEnd);
    node.value = asn1Value(tag.tagClass, tag.tagNumber, rawValue);
    if ((tag.tagNumber === 3 && rawValue[0] === 0 && rawValue.length > 2) || (tag.tagNumber === 4 && rawValue.length > 2)) {
      const nestedBytes = tag.tagNumber === 3 ? rawValue.slice(1) : rawValue;
      try {
        const nestedState = { count: state.count };
        const nested = parseAsn1TopLevel(nestedBytes, depth + 1, nestedState);
        if (nested.length && nestedState.count > state.count) {
          state.count = nestedState.count;
          node.children = nested;
        }
      } catch {
        // Primitive BIT/OCTET STRING often contains arbitrary bytes; nested ASN.1 is best-effort only.
      }
    }
  }
  return node;
};

const parseAsn1TopLevel = (bytes: Uint8Array, depth: number, state: Asn1ParseState) => {
  const nodes: Asn1Node[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const node = parseAsn1Node(bytes, offset, bytes.length, depth, state);
    if (node.end <= offset) throw new Error('ASN.1 顶层节点没有推进游标');
    nodes.push(node);
    offset = node.end;
  }
  return nodes;
};

const parseAsn1Der = (value: string) => {
  const input = parseAsn1Input(value);
  const state = { count: 0 };
  return JSON.stringify({
    encoding: input.encoding,
    bytes: input.bytes.length,
    nodes: parseAsn1TopLevel(input.bytes, 0, state),
  }, null, 2);
};

const decodeSemiOctetAddress = (bytes: Uint8Array, digitCount?: number, typeOfAddress = 0x81) => {
  const digits: string[] = [];
  const map = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'a', 'b', 'c'];
  for (const byte of bytes) {
    for (const nibble of [byte & 0x0f, byte >> 4]) {
      if (nibble === 0x0f) continue;
      digits.push(map[nibble] || '?');
      if (digitCount != null && digits.length >= digitCount) break;
    }
    if (digitCount != null && digits.length >= digitCount) break;
  }
  const number = digits.join('');
  const international = (typeOfAddress & 0x70) === 0x10;
  return international && number ? `+${number}` : number;
};

const decodeSwappedBcd = (byte: number) => `${byte & 0x0f}${(byte >> 4) & 0x0f}`;

const decodeSmsTimestamp = (bytes: Uint8Array) => {
  if (bytes.length < 7) return { raw: bytesToHex(bytes), text: '' };
  const [yearByte, monthByte, dayByte, hourByte, minuteByte, secondByte, zoneByte] = bytes;
  const year = Number.parseInt(decodeSwappedBcd(yearByte), 10);
  const month = decodeSwappedBcd(monthByte).padStart(2, '0');
  const day = decodeSwappedBcd(dayByte).padStart(2, '0');
  const hour = decodeSwappedBcd(hourByte).padStart(2, '0');
  const minute = decodeSwappedBcd(minuteByte).padStart(2, '0');
  const second = decodeSwappedBcd(secondByte).padStart(2, '0');
  const low = zoneByte & 0x0f;
  const timezoneQuarters = ((low & 0x07) * 10) + ((zoneByte >> 4) & 0x0f);
  const timezoneMinutes = timezoneQuarters * 15;
  const sign = (low & 0x08) ? '-' : '+';
  const timezone = `${sign}${String(Math.floor(timezoneMinutes / 60)).padStart(2, '0')}:${String(timezoneMinutes % 60).padStart(2, '0')}`;
  return {
    raw: bytesToHex(bytes),
    text: `${year < 70 ? 2000 + year : 1900 + year}-${month}-${day} ${hour}:${minute}:${second} ${timezone}`,
  };
};

const decodeSmsDcs = (dcs: number) => {
  const alphabetBits = dcs & 0x0c;
  const alphabet = alphabetBits === 0x08 ? 'ucs2' : alphabetBits === 0x04 ? '8bit' : 'gsm7';
  return {
    value: `0x${dcs.toString(16).padStart(2, '0')}`,
    alphabet,
    compressed: (dcs & 0x20) !== 0,
    messageClass: (dcs & 0x10) ? dcs & 0x03 : null,
  };
};

const decodeSmsUserData = (bytes: Uint8Array, dcs: number, userDataLength: number, hasHeader: boolean) => {
  const dcsInfo = decodeSmsDcs(dcs);
  const headerLength = hasHeader && bytes.length ? bytes[0] + 1 : 0;
  const header = headerLength ? bytes.slice(0, headerLength) : new Uint8Array();
  const payload = headerLength ? bytes.slice(headerLength) : bytes;
  if (dcsInfo.alphabet === 'ucs2') {
    const chars: string[] = [];
    for (let index = 0; index + 1 < payload.length; index += 2) chars.push(String.fromCharCode((payload[index] << 8) | payload[index + 1]));
    return { dcs: dcsInfo, udh: headerLength ? bytesToHex(header) : null, text: chars.join('').slice(0, Math.floor(userDataLength / 2)), rawHex: bytesToHex(bytes) };
  }
  if (dcsInfo.alphabet === '8bit') {
    return { dcs: dcsInfo, udh: headerLength ? bytesToHex(header) : null, hex: bytesToHex(payload.slice(0, userDataLength)), asciiPreview: utf8Decoder.decode(payload.slice(0, userDataLength)).replace(/\p{Cc}/gu, '.') };
  }
  const septets = unpackGsm7Septets(bytes);
  const headerSeptets = headerLength ? Math.ceil((headerLength * 8) / 7) : 0;
  const textSeptets = septets.slice(headerSeptets, userDataLength);
  return { dcs: dcsInfo, udh: headerLength ? bytesToHex(header) : null, text: gsm7SeptetsToText(textSeptets), rawHex: bytesToHex(bytes) };
};

const parseSmsPdu = (value: string) => {
  const bytes = hexToBytes(value);
  if (bytes.length < 2) throw new Error('SMS PDU 太短');
  let offset = 0;
  const smscLength = bytes[offset];
  offset += 1;
  if (offset + smscLength > bytes.length) throw new Error('SMSC 长度超出 PDU 范围');
  const smscType = smscLength ? bytes[offset] : 0;
  const smscAddress = smscLength > 1 ? decodeSemiOctetAddress(bytes.slice(offset + 1, offset + smscLength), undefined, smscType) : '';
  offset += smscLength;
  if (offset >= bytes.length) throw new Error('缺少 TPDU first octet');
  const firstOctet = bytes[offset];
  offset += 1;
  const mti = firstOctet & 0x03;
  const hasUserDataHeader = (firstOctet & 0x40) !== 0;
  const base = {
    smsc: {
      length: smscLength,
      typeOfAddress: smscLength ? `0x${smscType.toString(16).padStart(2, '0')}` : null,
      address: smscAddress,
    },
    firstOctet: `0x${firstOctet.toString(16).padStart(2, '0')}`,
    hasUserDataHeader,
  };

  if (mti === 0) {
    const addressLength = bytes[offset];
    const addressType = bytes[offset + 1];
    const addressBytes = Math.ceil(addressLength / 2);
    offset += 2;
    const sender = decodeSemiOctetAddress(bytes.slice(offset, offset + addressBytes), addressLength, addressType);
    offset += addressBytes;
    const pid = bytes[offset];
    const dcs = bytes[offset + 1];
    const timestamp = decodeSmsTimestamp(bytes.slice(offset + 2, offset + 9));
    offset += 9;
    const userDataLength = bytes[offset];
    offset += 1;
    const userData = decodeSmsUserData(bytes.slice(offset), dcs, userDataLength, hasUserDataHeader);
    return JSON.stringify({ ...base, messageType: 'SMS-DELIVER', sender, pid: `0x${pid.toString(16).padStart(2, '0')}`, timestamp, userData }, null, 2);
  }

  if (mti === 1) {
    const messageReference = bytes[offset];
    const addressLength = bytes[offset + 1];
    const addressType = bytes[offset + 2];
    const addressBytes = Math.ceil(addressLength / 2);
    offset += 3;
    const recipient = decodeSemiOctetAddress(bytes.slice(offset, offset + addressBytes), addressLength, addressType);
    offset += addressBytes;
    const pid = bytes[offset];
    const dcs = bytes[offset + 1];
    offset += 2;
    const validityFormat = (firstOctet >> 3) & 0x03;
    const validityBytes = validityFormat === 0 ? 0 : validityFormat === 2 ? 1 : 7;
    const validityPeriod = validityBytes ? bytesToHex(bytes.slice(offset, offset + validityBytes)) : null;
    offset += validityBytes;
    const userDataLength = bytes[offset];
    offset += 1;
    const userData = decodeSmsUserData(bytes.slice(offset), dcs, userDataLength, hasUserDataHeader);
    return JSON.stringify({ ...base, messageType: 'SMS-SUBMIT', messageReference, recipient, pid: `0x${pid.toString(16).padStart(2, '0')}`, validityPeriod, userData }, null, 2);
  }

  return JSON.stringify({
    ...base,
    messageType: mti === 2 ? 'SMS-STATUS-REPORT' : 'reserved',
    note: '当前解析器重点覆盖 CTF/取证中最常见的 SMS-DELIVER 和 SMS-SUBMIT',
    remainingHex: bytesToHex(bytes.slice(offset)),
  }, null, 2);
};

const looksLikeSmsPdu = (value: string) => {
  try {
    const bytes = hexToBytes(value);
    if (bytes.length < 16) return false;
    const smscLength = bytes[0];
    if (smscLength + 1 >= bytes.length) return false;
    const firstOctet = bytes[smscLength + 1];
    const mti = firstOctet & 0x03;
    return mti === 0 || mti === 1;
  } catch {
    return false;
  }
};

const cleanRsaToken = (value: string) => cleanLooseFieldValue(value);

const rsaBase64NumberishKeys = new Set(['n', 'e', 'd', 'p', 'q', 'phi', 'c', 'm', 'dp', 'dq', 'qinv', 'pinv']);

const parseNumericValue = (value: string) => {
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

type RsaExpressionToken = {
  type: 'number' | 'identifier' | 'operator' | 'lparen' | 'rparen' | 'comma';
  value: string;
};

const rsaExpressionMaxLength = 256;
const rsaExpressionMaxTokens = 128;
const rsaExpressionMaxBits = 131072;
const rsaExpressionMaxExponent = 4096n;
const rsaExpressionMaxShift = 32768n;

const rsaExpressionBitLength = (value: bigint) => {
  const abs = value < 0n ? -value : value;
  return abs === 0n ? 0 : abs.toString(2).length;
};

const guardRsaExpressionValue = (value: bigint) => (
  rsaExpressionBitLength(value) <= rsaExpressionMaxBits ? value : null
);

const tokenizeRsaExpression = (value: string): RsaExpressionToken[] | null => {
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

const parseFunctionLikeCall = (value: string) => {
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

const parsePythonQuotedText = (value: string) => {
  const text = String(value || '').trim();
  const match = text.match(/^([rRuU]{0,2})(['"])([\s\S]*)\2$/);
  if (!match) return null;
  const prefix = match[1].toLowerCase();
  const raw = prefix.includes('r');
  return raw ? match[3] : cStringDecode(match[3]);
};

const parsePythonSliceSuffix = (value: string) => {
  const text = String(value || '').trim();
  const match = text.match(/^([\s\S]+)\[\s*(\d+)?\s*:\s*(\d+)?\s*\]$/);
  if (!match) return null;
  return {
    source: match[1].trim(),
    start: match[2] ? Number.parseInt(match[2], 10) : null,
    end: match[3] ? Number.parseInt(match[3], 10) : null,
  };
};

const applyPythonSlice = (value: string, slice: { start: number | null; end: number | null }) => {
  const length = value.length;
  const normalizeIndex = (index: number | null, fallback: number) => {
    if (index == null) return fallback;
    return index < 0 ? Math.max(0, length + index) : Math.min(length, index);
  };
  const start = normalizeIndex(slice.start, 0);
  const end = normalizeIndex(slice.end, length);
  return value.slice(start, end);
};

const parsePythonBytesLiteral = (value: string) => {
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

const parseBigIntFromBaseString = (value: string, base: bigint) => {
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

const parsePythonByteArrayLiteral = (
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

const parsePythonByteLikeValue = (
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

const parsePythonNumberishValue = (
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

const parsePythonTextLikeValue = (
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

const bigintPowInRsaExpression = (base: bigint, exponent: bigint) => {
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

const evaluateRsaArithmeticExpression = (
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

const parseNumericTuple = (value: string) => {
  const items = Array.from(String(value || '').matchAll(/0x[0-9a-f_]+|\d[\d_]*[nNlL]?/gi))
    .map(match => parseNumericValue(match[0]))
    .filter((entry): entry is bigint => typeof entry === 'bigint');
  return items.length === 2 ? [items[0], items[1]] as const : null;
};

const parseRsaFieldNumericValue = (key: string, value: string, fields: Record<string, string> = {}) => {
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

const bitLength = (value: bigint) => value === 0n ? 0 : value.toString(2).length;

const bigintToBytes = (value: bigint) => {
  if (value < 0n) throw new Error('BigInt byte conversion only supports non-negative values');
  if (value === 0n) return new Uint8Array([0]);
  const hex = value.toString(16).padStart(Math.ceil(value.toString(16).length / 2) * 2, '0');
  return hexToBytes(hex);
};

const bigintFromBytes = (bytes: Uint8Array) => {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
};

const bigintModPow = (base: bigint, exponent: bigint, modulo: bigint) => {
  if (modulo <= 0n) throw new Error('RSA modulus n must be positive');
  if (exponent < 0n) throw new Error('RSA exponent must be non-negative');
  let result = 1n;
  let current = ((base % modulo) + modulo) % modulo;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = (result * current) % modulo;
    current = (current * current) % modulo;
    power >>= 1n;
  }
  return result;
};

const rsaParamAliases: Record<string, string> = {
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

const normalizeRsaParamName = (key: string) => rsaParamAliases[normalizeCtfFieldName(key)] || null;

const isCommonRsaPublicExponent = (value: bigint) => [3n, 5n, 17n, 257n, 65537n].includes(value);

const isLikelyRsaPublicExponent = (value: bigint) => isCommonRsaPublicExponent(value) || (value > 1n && value < 1_000_000n && (value & 1n) === 1n);

const parseKeyValueNumbers = (value: string) => {
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

type RsaInference = {
  params: Record<string, string>;
  looseNumbers: string[];
  confidence: number;
  notes: string[];
  knownPairs: RsaKnownPair[];
};

type RsaKnownPair = {
  index: string;
  m: bigint;
  c: bigint;
};

type RsaCipherRecord = {
  index: string;
  n: bigint | null;
  e: bigint | null;
  c: bigint | null;
  m: bigint | null;
  raw: Record<string, string>;
};

type RsaPublicKeyRecord = {
  index: string;
  n: bigint;
  e: bigint;
  raw: Record<string, string>;
};

type RsaAutomatedAttackResult = {
  attack: string;
  title: string;
  output: unknown;
  details?: Record<string, unknown>;
};

const rsaParamNumber = (params: Record<string, string>, key: string) => params[key] ? parseRsaFieldNumericValue(key, params[key], params) : null;

const rememberInferredRsaParam = (
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

const uniqueRsaNumbers = (numbers: string[]) => {
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

const rsaKnownPairAliases = {
  m: ['m', 'msg', 'message', 'plain', 'plaintext', 'pt', 'cleartext'],
  c: ['c', 'ct', 'cipher', 'ciphertext', 'cyphertext', 'enc', 'encrypted', 'cryptogram'],
};

const parseRsaKnownPairs = (value: string, params: Record<string, string>) => {
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

const rsaCipherRecordAliases = {
  n: ['n', 'mod', 'modulus', 'publicmodulus', 'pubn'],
  e: ['e', 'exp', 'exponent', 'publicexponent', 'pubexp'],
  c: ['c', 'ct', 'cipher', 'ciphertext', 'encrypted', 'cryptogram'],
  m: ['m', 'msg', 'message', 'plain', 'plaintext', 'pt'],
};

const parseRsaRecordFieldValue = (key: 'n' | 'e' | 'c' | 'm', value: string | undefined, fields: Record<string, string> = {}) => {
  if (!value) return null;
  return parseRsaFieldNumericValue(key, value, fields);
};

const resolveRsaNumberishToken = (token: string, fields: Record<string, string>) => {
  const cleaned = cleanRsaToken(token);
  const direct = parseRsaFieldNumericValue('n', cleaned, fields);
  if (direct != null) return direct;
  const referenced = fields[normalizeLooseFieldName(cleaned)];
  if (!referenced) return null;
  return parseRsaFieldNumericValue('n', referenced, fields);
};

const pushRsaCipherRecord = (records: RsaCipherRecord[], record: RsaCipherRecord) => {
  if (record.n == null && record.e == null && record.c == null && record.m == null) return;
  records.push(record);
};

const collectRsaJsonRecords = (value: unknown, output: RsaCipherRecord[], path = 'json') => {
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

const parseRsaNumberishList = (key: 'n' | 'e' | 'c' | 'm', value: string) => {
  const source = String(value || '');
  const tokens = Array.from(source.matchAll(/0x[0-9a-f_]+|\d[\d_]*[nNlL]?|[A-Za-z0-9+/_-]+={0,2}/gi))
    .map(match => match[0])
    .map(token => parseRsaRecordFieldValue(key, token))
    .filter((entry): entry is bigint => typeof entry === 'bigint');
  return tokens;
};

const parseRsaPublicKeyTuple = (value: string, fields: Record<string, string> = {}) => {
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

const rsaStructuredParamKeys = new Set(['n', 'e', 'd', 'p', 'q', 'phi', 'c', 'm', 'dp', 'dq', 'qinv', 'pinv']);

const tryParseLoosePythonLikeJson = (value: string) => {
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

const extractNestedRsaPublicKeyFromObject = (object: Record<string, unknown>) => {
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

const extractRsaParamsFromStructuredObject = (value: unknown): Record<string, string> | null => {
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

const parseRsaPublicKeyTupleList = (value: string, fields: Record<string, string> = {}) => {
  const records: Array<{ n: bigint; e: bigint }> = [];
  for (const match of String(value || '').matchAll(/\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)/gi)) {
    const parsed = parseRsaPublicKeyTuple(match[0], fields);
    if (parsed) records.push(parsed);
  }
  return records;
};

const rsaPublicKeyAliases = ['publickey', 'pubkey', 'key', 'pub', 'pk', 'public', 'rsa', 'keypair', 'priv', 'privkey'];

const collectRsaPublicKeyJsonRecords = (value: unknown, output: RsaPublicKeyRecord[], path = 'json') => {
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

const parseRsaPublicKeyRecords = (value: string) => {
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

const parseRsaCipherRecords = (value: string, params: Record<string, string>) => {
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

const bigintPowIfReasonable = (base: bigint, exponent: bigint, maxBits = 16384) => {
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

const inferRsaModulusFromKnownPairs = (pairs: RsaKnownPair[], exponent: bigint) => {
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

const normalizeRsaJwkField = (value: unknown) => {
  if (typeof value !== 'string') return '';
  return cleanRsaToken(value).replace(/\s+/g, '');
};

const extractRsaParamsFromJwkObject = (value: unknown): Record<string, string> | null => {
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

const extractRsaParamsFromJwkLike = (value: string) => {
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

const sshMpintToBigInt = (bytes: Uint8Array) => {
  const stripped = bytes.length > 1 && bytes[0] === 0 ? bytes.slice(1) : bytes;
  return bigintFromBytes(stripped);
};

const extractRsaParamsFromOpenSsh = (value: string) => {
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

const asn1IntegerValue = (node: Asn1Node) => {
  if (node.type !== 'INTEGER' || typeof node.value !== 'object' || node.value == null) return null;
  const value = node.value as { decimal?: unknown; hex?: unknown };
  if (typeof value.decimal === 'string') return parseNumericValue(value.decimal);
  if (typeof value.hex === 'string' && value.hex) return BigInt(`0x${value.hex.replace(/^00/, '') || '0'}`);
  return null;
};

const findRsaIntegerSequences = (nodes: Asn1Node[]) => {
  const sequences: bigint[][] = [];
  const visit = (node: Asn1Node) => {
    const integerChildren = (node.children || []).map(child => asn1IntegerValue(child)).filter((entry): entry is bigint => typeof entry === 'bigint');
    if (integerChildren.length >= 2) sequences.push(integerChildren);
    for (const child of node.children || []) visit(child);
  };
  for (const node of nodes) visit(node);
  return sequences;
};

const extractRsaParamsFromPem = (value: string) => {
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

const inferRsaParamsFromText = (value: string, direction: Direction = 'decode'): RsaInference => {
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

const parseRsaMessageValue = (value: string, labelText: string) => {
  const numeric = parseNumericValue(value);
  if (typeof numeric === 'bigint') return { value: numeric, source: 'number' };
  const parsed = parseHexBase64OrUtf8Bytes(value, labelText);
  return { value: bigintFromBytes(parsed.bytes), source: parsed.format };
};

type RsaMessageValue = ReturnType<typeof parseRsaMessageValue>;

const parseRsaMessageValues = (value: string, labelText: string): RsaMessageValue[] => {
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

const rsaNumberResult = (value: bigint) => {
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

const rsaValuesResult = (values: bigint[]) => {
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

const bigintMod = (value: bigint, modulo: bigint) => ((value % modulo) + modulo) % modulo;

const crtCombinePair = (leftValue: bigint, leftMod: bigint, rightValue: bigint, rightMod: bigint) => {
  const leftInverse = bigintModInverse(leftMod, rightMod);
  const rightInverse = bigintModInverse(rightMod, leftMod);
  if (leftInverse == null || rightInverse == null) throw new Error('CRT combine requires coprime moduli');
  const modulus = leftMod * rightMod;
  return bigintMod(
    leftValue * rightMod * rightInverse + rightValue * leftMod * leftInverse,
    modulus,
  );
};

const tonelliShanksRoot = (value: bigint, prime: bigint) => {
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

const rabinRootsModPrime = (value: bigint, prime: bigint) => {
  const root = tonelliShanksRoot(value, prime);
  if (root == null) return [];
  const other = bigintMod(prime - root, prime);
  return root === other ? [root] : [root, other];
};

const uniqueBigints = (values: bigint[]) => {
  const seen = new Set<string>();
  return values.filter(value => {
    const key = value.toString();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

const rabinRawTransform = (direction: Direction, value: string) => {
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

const bigintPowCompare = (base: bigint, exponent: bigint, limit: bigint) => {
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

const bigintNthRootExact = (value: bigint, degree: bigint) => {
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

const tryRsaLowExponentRoots = (blocks: RsaMessageValue[], exponent: bigint, n?: bigint | null) => {
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

const rsaCrtDecrypt = (
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

const factorSmallRsaModulus = (
  n: bigint,
  options: {
    maxBits?: number;
    allowPollardRho?: boolean;
    trialLimit?: bigint;
    fermatSteps?: number;
    rhoIterations?: number;
  } = {},
) => {
  const {
    maxBits = 190,
    allowPollardRho = true,
    trialLimit = 100_000n,
    fermatSteps = 50_000,
    rhoIterations = 20_000,
  } = options;
  if (n <= 3n || bitLength(n) > maxBits) return null;
  if (n % 2n === 0n) return [2n, n / 2n] as const;

  const isProbablePrime = (value: bigint) => {
    if (value < 2n) return false;
    for (const smallPrime of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
      if (value === smallPrime) return true;
      if (value % smallPrime === 0n) return false;
    }
    let d = value - 1n;
    let s = 0n;
    while ((d & 1n) === 0n) {
      d >>= 1n;
      s += 1n;
    }
    const witnesses = [2n, 3n, 5n, 7n, 11n, 13n, 17n];
    for (const witness of witnesses) {
      if (witness >= value - 1n) continue;
      let x = bigintModPow(witness, d, value);
      if (x === 1n || x === value - 1n) continue;
      let composite = true;
      for (let round = 1n; round < s; round += 1n) {
        x = bigintModPow(x, 2n, value);
        if (x === value - 1n) {
          composite = false;
          break;
        }
      }
      if (composite) return false;
    }
    return true;
  };

  if (isProbablePrime(n)) return null;

  for (let divisor = 3n; divisor <= trialLimit && divisor * divisor <= n; divisor += 2n) {
    if (n % divisor === 0n) return [divisor, n / divisor] as const;
  }

  if (bitLength(n) <= 128) {
    let a = bigIntSqrt(n);
    if (a * a < n) a += 1n;
    for (let step = 0; step < fermatSteps; step += 1) {
      const b2 = a * a - n;
      const b = bigIntSqrt(b2);
      if (b * b === b2) {
        const p = a - b;
        const q = a + b;
        if (p > 1n && q > 1n && p * q === n) return [p, q] as const;
      }
      a += 1n;
    }
  }

  if (!allowPollardRho) return null;

  const pollardRhoFactor = (value: bigint) => {
    const f = (x: bigint, c: bigint) => bigintMod(x * x + c, value);
    const seeds = [
      [2n, 1n],
      [3n, 1n],
      [5n, 1n],
      [2n, 3n],
      [3n, 5n],
      [7n, 11n],
      [11n, 17n],
      [17n, 29n],
    ] as const;

    for (const [seed, constant] of seeds) {
      let x = seed % value;
      let y = x;
      let d = 1n;
      for (let iteration = 0; iteration < rhoIterations && d === 1n; iteration += 1) {
        x = f(x, constant);
        y = f(f(y, constant), constant);
        d = bigintGcd(bigintAbs(x - y), value);
      }
      if (d > 1n && d < value) return d;
    }
    return null;
  };

  const rhoFactor = pollardRhoFactor(n);
  if (rhoFactor && rhoFactor > 1n && rhoFactor < n) {
    const other = n / rhoFactor;
    return rhoFactor < other ? [rhoFactor, other] as const : [other, rhoFactor] as const;
  }

  return null;
};

const factorSmallCompositeModulus = (n: bigint) => {
  if (n <= 1n) return null;
  const factors: bigint[] = [];
  const visit = (current: bigint): boolean => {
    if (current <= 1n) return true;
    const pair = factorSmallRsaModulus(current);
    if (!pair) {
      factors.push(current);
      return true;
    }
    const [left, right] = pair;
    if (left <= 1n || right <= 1n || left * right !== current) {
      factors.push(current);
      return true;
    }
    if (left === current || right === current) {
      factors.push(current);
      return true;
    }
    return visit(left) && visit(right);
  };
  return visit(n)
    ? factors.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
    : null;
};

const bigintPow = (base: bigint, exponent: bigint) => {
  if (exponent < 0n) throw new Error('bigintPow only supports non-negative exponents');
  let result = 1n;
  let current = base;
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result *= current;
    power >>= 1n;
    if (power > 0n) current *= current;
  }
  return result;
};

const rsaPhiFromPrimeFactors = (factors: bigint[]) => {
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

const tryRsaExponentReduction = (
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

const rsaRawTransform = (direction: Direction, value: string) => {
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

const canRabinRawDecryptFromText = (value: string) => {
  const inference = inferRsaParamsFromText(value, 'decode');
  const { params } = inference;
  const hasCiphertext = Boolean(params.c);
  const hasFactors = Boolean(params.p && params.q);
  const n = rsaParamNumber(params, 'n');
  const canFactorSmallN = typeof n === 'bigint' && factorSmallRsaModulus(n, { maxBits: 128, allowPollardRho: true, trialLimit: 2_000_000n, rhoIterations: 50_000 }) != null;
  return hasCiphertext && (hasFactors || canFactorSmallN);
};

const trySmartRabinDecrypt = (value: string) => {
  const lower = value.toLowerCase();
  if (!/\brabin\b/.test(lower) && !/\bquadratic residue\b/.test(lower)) return null;
  if (!canRabinRawDecryptFromText(value)) return null;
  try {
    return `智能识别: Rabin Raw 可直接解密\n\n${rabinRawTransform('decode', value)}`;
  } catch {
    return null;
  }
};

const canRsaRawDecryptFromText = (value: string) => {
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

const rsaModPowSigned = (base: bigint, exponent: bigint, modulo: bigint) => {
  if (exponent >= 0n) return bigintModPow(base, exponent, modulo);
  const inverse = bigintModInverse(base, modulo);
  if (inverse == null) return null;
  return bigintModPow(inverse, -exponent, modulo);
};

const chooseRsaRecordSubsets = <T,>(items: T[], size: number, limit = 40) => {
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

const arePairwiseCoprimeRsaRecords = (records: Array<{ n: bigint }>) => {
  for (let left = 0; left < records.length; left += 1) {
    for (let right = left + 1; right < records.length; right += 1) {
      if (bigintGcd(records[left].n, records[right].n) !== 1n) return false;
    }
  }
  return true;
};

const serializeRsaCipherRecord = (record: RsaCipherRecord) => ({
  index: record.index,
  n: record.n?.toString() || null,
  e: record.e?.toString() || null,
  c: record.c?.toString() || null,
  m: record.m?.toString() || null,
});

const continuedFractionTerms = (numerator: bigint, denominator: bigint) => {
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

const continuedFractionConvergents = (terms: bigint[]) => {
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

const normalizePolyMod = (coefficients: bigint[], modulo: bigint) => {
  const normalized = coefficients.map(coefficient => bigintMod(coefficient, modulo));
  while (normalized.length > 1 && normalized[normalized.length - 1] === 0n) normalized.pop();
  return normalized;
};

const polyIsZero = (coefficients: bigint[]) => coefficients.length === 0 || coefficients.every(coefficient => coefficient === 0n);

const polyMulMod = (left: bigint[], right: bigint[], modulo: bigint) => {
  const result = Array.from({ length: Math.max(1, left.length + right.length - 1) }, () => 0n);
  for (let leftIndex = 0; leftIndex < left.length; leftIndex += 1) {
    for (let rightIndex = 0; rightIndex < right.length; rightIndex += 1) {
      result[leftIndex + rightIndex] = bigintMod(result[leftIndex + rightIndex] + left[leftIndex] * right[rightIndex], modulo);
    }
  }
  return normalizePolyMod(result, modulo);
};

const polyMakeMonic = (coefficients: bigint[], modulo: bigint) => {
  const normalized = normalizePolyMod(coefficients, modulo);
  if (polyIsZero(normalized)) return [0n];
  const leading = normalized[normalized.length - 1];
  const inverse = bigintModInverse(leading, modulo);
  if (inverse == null) return null;
  return normalizePolyMod(normalized.map(coefficient => bigintMod(coefficient * inverse, modulo)), modulo);
};

const polyDivRemMod = (dividendInput: bigint[], divisorInput: bigint[], modulo: bigint) => {
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

const polyGcdCompositeModulus = (left: bigint[], right: bigint[], modulo: bigint) => {
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

const polyPowLinearMod = (a: bigint, b: bigint, exponent: bigint, modulo: bigint) => {
  let result = [1n];
  const base = normalizePolyMod([b, a], modulo);
  for (let index = 0n; index < exponent; index += 1n) {
    result = polyMulMod(result, base, modulo);
  }
  return normalizePolyMod(result, modulo);
};

type RsaRelatedMessageRelation = {
  a: bigint;
  b: bigint;
  source: string;
};

const parseRsaRelatedMessageRelation = (value: string): RsaRelatedMessageRelation | null => {
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

const buildRsaCipherPolynomial = (degree: bigint, ciphertext: bigint, modulo: bigint) => {
  const size = Number(degree) + 1;
  const coefficients = Array.from({ length: size }, () => 0n);
  coefficients[0] = bigintMod(-ciphertext, modulo);
  coefficients[size - 1] = 1n;
  return normalizePolyMod(coefficients, modulo);
};

const tryLinearPolynomialRootMod = (polynomial: bigint[], modulo: bigint) => {
  if (polynomial.length !== 2) return null;
  const inverse = bigintModInverse(polynomial[1], modulo);
  if (inverse == null) return null;
  return bigintMod(-polynomial[0] * inverse, modulo);
};

const tryRsaFranklinReiterAttack = (value: string, records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
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

const enumerateRsaPrimeFromCrtExponent = (crtExponent: bigint, publicExponent: bigint, modulus: bigint | null) => {
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

const tryRsaCrtExponentLeakAttack = (params: Record<string, string>): RsaAutomatedAttackResult | null => {
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

const tryRsaWienerAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
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

const tryRsaCommonModulusAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
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

const tryRsaBroadcastAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
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

const tryRsaSharedPrimeAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
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

const tryRsaBatchGcdAttack = (records: RsaCipherRecord[]): RsaAutomatedAttackResult | null => {
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

const collectRsaAutomatedAttacks = (value: string) => {
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

const trySmartRsaDecrypt = (value: string) => {
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

const canSmartRsaHelper = (value: string) => {
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
  const minimumConfidence = hasCorePublicKey || hasFactorization || hasPrivateMaterial ? 4 : 5;
  return (
    inference.confidence >= minimumConfidence
    && (hasCorePublicKey || hasFactorization || hasPrivateMaterial || hasKnownPairs || hasLabeledCipher)
  );
};

const rsaHelper = (value: string) => {
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

const bigintAbs = (value: bigint) => value < 0n ? -value : value;

const bigintGcd = (left: bigint, right: bigint): bigint => {
  let a = bigintAbs(left);
  let b = bigintAbs(right);
  while (b !== 0n) {
    [a, b] = [b, a % b];
  }
  return a;
};

const bigintEgcd = (left: bigint, right: bigint): [bigint, bigint, bigint] => {
  if (right === 0n) return [bigintAbs(left), left < 0n ? -1n : 1n, 0n];
  const [gcd, x1, y1] = bigintEgcd(right, left % right);
  return [gcd, y1, x1 - (left / right) * y1];
};

const bigintModInverse = (value: bigint, modulo: bigint) => {
  const [gcd, x] = bigintEgcd(((value % modulo) + modulo) % modulo, modulo);
  if (gcd !== 1n) return null;
  return ((x % modulo) + modulo) % modulo;
};

const parseNumericList = (value: string) => (value.match(/0x[0-9a-f]+|\d+/gi) || [])
  .map(entry => parseNumericValue(entry))
  .filter((entry): entry is bigint => typeof entry === 'bigint');

const parsePowerOrNumeric = (value: string | undefined) => {
  const text = String(value ?? '');
  const mersenne = text.match(/\b2\s*(?:\^|\*\*)\s*(\d+)\s*-\s*1\b/i);
  if (mersenne) return (1n << BigInt(Number(mersenne[1]))) - 1n;
  const power = text.match(/\b2\s*(?:\^|\*\*)\s*(\d+)\b/i);
  if (power) return 1n << BigInt(Number(power[1]));
  const numeric = text.match(/0x[0-9a-f]+|\d+/i)?.[0];
  return numeric ? parseNumericValue(numeric) : null;
};

const parseOptionalModulus = (value: string) => {
  return parsePowerOrNumeric(value);
};

const parseIndexedSequence = (value: string, prefixPattern = '[xs]') => {
  const entries = Array.from(value.matchAll(new RegExp(`\\b${prefixPattern}\\s*\\[?\\s*(\\d+)\\s*\\]?\\s*[:=]\\s*(0x[0-9a-f]+|\\d+)`, 'gi')))
    .map(match => ({ index: Number(match[1]), value: parseNumericValue(match[2]) }))
    .filter((entry): entry is { index: number; value: bigint } => typeof entry.value === 'bigint')
    .sort((left, right) => left.index - right.index);
  return entries.filter((entry, index) => index === 0 || entry.index !== entries[index - 1].index).map(entry => entry.value);
};

const parseNamedIndexedSequence = (value: string, aliases: string[]) => {
  const aliasPattern = aliases.map(alias => alias.split('').map(char => escapeRegexLiteral(char)).join('[_\\s-]*')).join('|');
  const entries = Array.from(value.matchAll(new RegExp(`\\b(?:${aliasPattern})\\s*\\[?\\s*(\\d+)\\s*\\]?\\s*[:=]\\s*(0x[0-9a-f]+|\\d+)`, 'gi')))
    .map(match => ({ index: Number(match[1]), value: parseNumericValue(match[2]) }))
    .filter((entry): entry is { index: number; value: bigint } => typeof entry.value === 'bigint')
    .sort((left, right) => left.index - right.index);
  return entries.filter((entry, index) => index === 0 || entry.index !== entries[index - 1].index).map(entry => entry.value);
};

const stripPrngScalarAssignments = (value: string) => value
  .replace(/\b(?:m|mod|modulus|modulo|a|multiplier|c|increment|seed)\s*[:=]\s*(?:2\s*(?:\^|\*\*)\s*\d+(?:\s*-\s*1)?|0x[0-9a-f]+|\d+)/gi, ' ')
  .replace(/\b\d+\s+outputs?\b/gi, ' ');

type LcgInference = {
  states: bigint[];
  modulus: bigint | null;
  multiplier: bigint | null;
  increment: bigint | null;
  seed: bigint | null;
  confidence: number;
  notes: string[];
  fields: Record<string, string>;
};

const inferLcgFromText = (value: string, secret = ''): LcgInference => {
  const fields = parseLooseCtfFields(value);
  const modulus = parsePowerOrNumeric(looseField(fields, ['m', 'mod', 'modulus', 'modulo'])) || parseOptionalModulus(secret);
  const multiplier = parsePowerOrNumeric(looseField(fields, ['a', 'multiplier', 'mul']));
  const increment = parsePowerOrNumeric(looseField(fields, ['c', 'increment', 'inc']));
  const seed = parsePowerOrNumeric(looseField(fields, ['seed', 'x0', 'state0']));
  const fieldSequence = looseField(fields, ['outputs', 'output', 'states', 'state', 'samples', 'values', 'leaks', 'sequence', 'randoms']);
  const indexed = parseIndexedSequence(value);
  const states = fieldSequence
    ? parseNumericList(fieldSequence)
    : indexed.length >= 2
      ? indexed
      : parseNumericList(stripPrngScalarAssignments(value));
  const lower = value.toLowerCase();
  let confidence = 0;
  if (/\blcg\b|linear congruential|x\s*\[\s*n\s*\+\s*1\s*\]|x_?n\s*=|线性同余|同余生成器/.test(lower)) confidence += 6;
  if (states.length >= 4) confidence += 5;
  else if (states.length >= 2) confidence += 2;
  if (modulus) confidence += 2;
  if (multiplier != null || increment != null) confidence += 2;
  if (/rand|random|seed|next/.test(lower)) confidence += 1;
  const notes = [
    fieldSequence ? 'state sequence inferred from an outputs/states/samples-style field.' : '',
    indexed.length >= 2 ? 'indexed x0/x1/... assignments were sorted before analysis.' : '',
    modulus ? 'modulus inferred from m/mod/modulus or the helper parameter.' : '',
  ].filter(Boolean);
  return { states, modulus, multiplier, increment, seed, confidence, notes, fields };
};

const lcgHelper = (value: string, secret: string) => {
  const inference = inferLcgFromText(value, secret);
  const states = inference.states;
  if (states.length < 4 && !(inference.modulus && inference.multiplier != null && inference.increment != null && (states.length || inference.seed != null))) {
    throw new Error('LCG 分析至少需要 4 个连续输出，或提供 m/a/c 与 seed/state');
  }
  const diffs = states.slice(1).map((state, index) => state - states[index]);
  const zeroes: bigint[] = [];
  for (let index = 0; index + 2 < diffs.length; index += 1) {
    zeroes.push(diffs[index + 2] * diffs[index] - diffs[index + 1] * diffs[index + 1]);
  }
  const derivedModulus = zeroes.reduce((current, entry) => current === 0n ? bigintAbs(entry) : bigintGcd(current, entry), 0n);
  const modulus = inference.modulus || (derivedModulus > 1n ? derivedModulus : null);
  const result: Record<string, unknown> = {
    states: states.map(item => item.toString()),
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    differenceCount: diffs.length,
    derivedModulus: derivedModulus > 1n ? derivedModulus.toString() : null,
    modulus: modulus?.toString() || null,
    parsedMultiplier: inference.multiplier?.toString() || null,
    parsedIncrement: inference.increment?.toString() || null,
    parsedSeed: inference.seed?.toString() || null,
    notes: [
      '输入必须是同一个 LCG 的连续完整输出；截断输出需要 lattice/Z3，前台只做 triage。',
      '如果自动 m 不稳定，请在参数中填写 m=<modulus> 或 m=2^31。',
    ],
  };
  if (!modulus) return JSON.stringify(result, null, 2);
  if (inference.multiplier != null && inference.increment != null) {
    const baseState = states.length ? states[states.length - 1] : inference.seed;
    const next = baseState == null ? null : (inference.multiplier * baseState + inference.increment) % modulus;
    return JSON.stringify({
      ...result,
      a: inference.multiplier.toString(),
      c: inference.increment.toString(),
      next: next?.toString() || null,
      recurrence: `x[n+1] = (${inference.multiplier.toString()} * x[n] + ${inference.increment.toString()}) mod ${modulus.toString()}`,
    }, null, 2);
  }
  const inverse = bigintModInverse(states[1] - states[0], modulus);
  if (inverse == null) {
    result.warning = 'x1-x0 与 modulus 不互素，无法直接求 a；可换一组连续输出，或转 CRT/枚举。';
    return JSON.stringify(result, null, 2);
  }
  const a = (((states[2] - states[1]) * inverse) % modulus + modulus) % modulus;
  const c = ((states[1] - a * states[0]) % modulus + modulus) % modulus;
  const next = (a * states[states.length - 1] + c) % modulus;
  return JSON.stringify({
    ...result,
    a: a.toString(),
    c: c.toString(),
    next: next.toString(),
    recurrence: `x[n+1] = (${a.toString()} * x[n] + ${c.toString()}) mod ${modulus.toString()}`,
  }, null, 2);
};

const berlekampMassey = (bits: number[]) => {
  let c = [1];
  let b = [1];
  let l = 0;
  let m = 1;
  for (let n = 0; n < bits.length; n += 1) {
    let discrepancy = bits[n];
    for (let index = 1; index <= l; index += 1) discrepancy ^= c[index] & bits[n - index];
    if (discrepancy === 0) {
      m += 1;
      continue;
    }
    const previous = c.slice();
    if (c.length < b.length + m) c = c.concat(Array.from({ length: b.length + m - c.length }, () => 0));
    for (let index = 0; index < b.length; index += 1) c[index + m] ^= b[index];
    if (2 * l <= n) {
      l = n + 1 - l;
      b = previous;
      m = 1;
    } else {
      m += 1;
    }
  }
  return { complexity: l, polynomial: c.slice(0, l + 1) };
};

const bytesToBitArray = (bytes: Uint8Array) => Array.from(bytes).flatMap(byte => (
  Array.from({ length: 8 }, (_, bit) => (byte >> (7 - bit)) & 1)
));

type LfsrInference = {
  bits: number[];
  confidence: number;
  notes: string[];
  fields: Record<string, string>;
  masks?: bigint[];
};

const parseLfsrBitSource = (source: string) => {
  const compact = source.replace(/[^01]/g, '');
  return compact.length >= 4 ? Array.from(compact).map(bit => Number(bit)) : [];
};

const inferLfsrBitsFromText = (value: string): LfsrInference => {
  const fields = parseLooseCtfFields(value);
  const symmetricFields = parseSymmetricFields(value);
  const notes: string[] = [];
  let bits: number[] = [];
  const fieldSource = looseField(fields, ['keystream', 'key stream', 'bits', 'bitstream', 'stream', 'output', 'outputs', 'state', 'states']);
  if (fieldSource) {
    bits = parseLfsrBitSource(fieldSource);
    if (bits.length) notes.push('keystream bits inferred from a labelled field.');
  }
  if (!bits.length) {
    const binaryRuns = value.match(/[01][01\s,;|/_-]{14,}[01]/g) || [];
    const bestRun = binaryRuns
      .map(run => ({ run, bitCount: run.replace(/[^01]/g, '').length }))
      .sort((left, right) => right.bitCount - left.bitCount)[0];
    if (bestRun) {
      bits = parseLfsrBitSource(bestRun.run);
      notes.push('longest binary-looking run was used as keystream.');
    }
  }
  const knownPlaintext = symmetricFields.knownPlaintext || symmetricFields.plaintext || looseField(fields, ['knownplaintext', 'known plaintext', 'plaintext', 'plain']);
  const cipherSource = symmetricFields.ciphertext || looseField(fields, ['ciphertext', 'cipher', 'ct']);
  if (!bits.length && knownPlaintext && cipherSource) {
    try {
      const ciphertext = parseSymmetricFieldBytes(cipherSource, 'ciphertext');
      const known = utf8Encoder.encode(knownPlaintext);
      const length = Math.min(ciphertext.length, known.length);
      const keystream = ciphertext.slice(0, length).map((byte, index) => byte ^ known[index]);
      bits = bytesToBitArray(keystream);
      notes.push('keystream prefix inferred from ciphertext XOR known plaintext.');
    } catch {
      // Keep falling through to a plain "not enough bits" result.
    }
  }
  const lower = value.toLowerCase();
  let confidence = bits.length >= 32 ? 5 : bits.length >= 16 ? 3 : bits.length >= 4 ? 1 : 0;
  if (/lfsr|berlekamp|feedback|linear complexity|keystream/.test(lower)) confidence += 5;
  if (knownPlaintext && cipherSource) confidence += 2;
  // Extract LFSR mask constants from code (e.g. HITCON: MASK1 = 0x6D6AC812...)
  const maskMatches = Array.from(value.matchAll(/\bMASK\d*\s*=\s*(0x[0-9a-fA-F_]+)/gi));
  const masks = maskMatches.map(m => parseNumericValue(m[1])).filter((m): m is bigint => typeof m === 'bigint');
  if (masks.length) {
    notes.push(`Found ${masks.length} LFSR mask constant(s): ${masks.slice(0,4).map(m=>`0x${m.toString(16)}`).join(', ')}`);
    confidence += masks.length >= 2 ? 6 : 3;
  }
  return { bits, confidence, notes, fields, masks };
};

const lfsrHelper = (value: string) => {
  const inference = inferLfsrBitsFromText(value);
  const bits = inference.bits;
  if (bits.length < 4) throw new Error('LFSR 分析需要 0/1 keystream');
  const result = berlekampMassey(bits);
  const taps = result.polynomial
    .map((coefficient, index) => coefficient ? index : -1)
    .filter(index => index > 0);
  return JSON.stringify({
    bitCount: bits.length,
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    inferenceNotes: inference.notes,
    linearComplexity: result.complexity,
    feedbackPolynomial: result.polynomial.map((coefficient, index) => coefficient ? `x^${index}` : '').filter(Boolean).join(' + ').replace('x^0', '1'),
    taps,
    seedHint: `需要前 ${result.complexity} bit 作为状态，按反馈多项式继续生成。`,
    note: '组合 LFSR 或截断/扰动 keystream 需要结合 correlation attack、Z3 或 Sage/GF(2) 矩阵分析。',
  }, null, 2);
};

const supportedLengthExtensionAlgorithms = new Set(['md5', 'sha1', 'sha256']);

const inferHashAlgorithmFromDigest = (digest: string) => {
  const clean = digest.replace(/^0x/i, '').toLowerCase();
  if (!/^[a-f0-9]+$/.test(clean)) return '';
  if (clean.length === 32) return 'md5';
  if (clean.length === 40) return 'sha1';
  if (clean.length === 64) return 'sha256';
  return '';
};

const parseSecretLengthCandidates = (value: string, fields: Record<string, string>) => {
  const source = [
    looseField(fields, ['secretlength', 'secretlen', 'keylength', 'keylen']),
    value,
  ].filter(Boolean).join('\n');
  const range = source.match(/\b(?:secret|key)[-_ ]?(?:len|length)\b\D{0,12}(\d{1,3})\s*(?:\.\.|-|to)\s*(\d{1,3})/i);
  if (range) {
    const start = Number(range[1]);
    const end = Number(range[2]);
    if (Number.isFinite(start) && Number.isFinite(end) && end >= start && end - start <= 64) {
      return Array.from({ length: end - start + 1 }, (_, index) => start + index);
    }
  }
  const single = source.match(/\b(?:secret|key)[-_ ]?(?:len|length)\b\D{0,12}(\d{1,3})/i);
  if (single) return [Number(single[1])].filter(length => length > 0);
  return [8, 12, 16, 20, 24, 32];
};

type HashLengthExtensionInference = {
  algorithm: string;
  digest: string;
  originalMessage: string;
  appendData: string;
  secretLengths: number[];
  confidence: number;
  notes: string[];
  fields: Record<string, string>;
};

const inferHashLengthExtensionFromText = (
  value: string,
  algorithm: string,
  appendData: string,
  knownMessage: string,
): HashLengthExtensionInference => {
  const fields = parseLooseCtfFields(value);
  const digestFromField = looseField(fields, ['signature', 'sig', 'mac', 'hash', 'digest', 'hexdigest', 'token']);
  const digest = (digestFromField.match(/[a-f0-9]{32,128}/i)?.[0] || value.match(/[a-f0-9]{32,128}/i)?.[0] || value.trim()).replace(/^0x/i, '');
  const algorithmField = looseField(fields, ['algorithm', 'alg', 'hashalgorithm', 'hash']);
  const textAlgorithm = value.match(/\b(md5|sha1|sha-1|sha256|sha-256)\b/i)?.[1].toLowerCase().replace('-', '') || '';
  const digestAlgorithm = inferHashAlgorithmFromDigest(digest);
  const requestedAlgorithm = supportedLengthExtensionAlgorithms.has(algorithm) ? algorithm : '';
  const inferredAlgorithm = algorithmField.toLowerCase().replace('-', '');
  const alg = supportedLengthExtensionAlgorithms.has(inferredAlgorithm)
    ? inferredAlgorithm
    : textAlgorithm || digestAlgorithm || requestedAlgorithm || 'sha1';
  const original = knownMessage
    || looseField(fields, ['original', 'originalmessage', 'knownmessage', 'message', 'msg', 'data', 'payload'])
    || 'known-message';
  const append = appendData
    || looseField(fields, ['append', 'appenddata', 'extension', 'suffix', 'newdata', 'add'])
    || 'admin=true';
  const secretLengths = parseSecretLengthCandidates(value, fields);
  const lower = value.toLowerCase();
  let confidence = 0;
  if (digest && /^[a-f0-9]{32,64}$/i.test(digest)) confidence += 4;
  if (/(length extension|hashpump|hash_extender|secret\s*\|\||prefix mac|secret-prefix)/i.test(value)) confidence += 5;
  if (original !== 'known-message') confidence += 2;
  if (append !== 'admin=true') confidence += 2;
  if (/\bhmac\b/.test(lower)) confidence -= 4;
  return {
    algorithm: alg,
    digest,
    originalMessage: original,
    appendData: append,
    secretLengths,
    confidence,
    notes: [
      digestAlgorithm ? `digest length suggests ${digestAlgorithm}.` : '',
      /\bhmac\b/.test(lower) ? 'HMAC was mentioned; normal HMAC is not vulnerable to length extension.' : '',
    ].filter(Boolean),
    fields,
  };
};

const shellSingleQuote = (value: string) => value.replace(/'/g, `'"'"'`);

const hashLengthExtensionHelper = (value: string, algorithm: string, appendData: string, knownMessage: string) => {
  const inference = inferHashLengthExtensionFromText(value, algorithm, appendData, knownMessage);
  const { algorithm: alg, digest: digestCandidate, appendData: append, originalMessage: original, secretLengths } = inference;
  return JSON.stringify({
    algorithm: alg,
    digest: digestCandidate,
    originalMessage: original,
    appendData: append,
    secretLengthCandidates: secretLengths,
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    inferenceNotes: inference.notes,
    vulnerableWhen: '服务端 MAC 形如 hash(secret || message)，且使用 MD5/SHA1/SHA256 这类 Merkle-Damgard 摘要',
    notVulnerableWhen: 'HMAC、hash(message || secret)、带 AEAD/MAC 的现代协议通常不适用',
    localCommands: secretLengths.map(length => `hash_extender --data '${shellSingleQuote(original)}' --signature ${digestCandidate} --append '${shellSingleQuote(append)}' --format ${alg} --secret ${length}`),
    pythonTemplate: `import hashpumpy\nfor key_len in ${JSON.stringify(secretLengths)}:\n    new_sig, new_msg = hashpumpy.hashpump('${digestCandidate}', ${JSON.stringify(original)}, ${JSON.stringify(append)}, key_len)\n    print(key_len, new_sig, new_msg)`,
    safetyNote: '仅用于本地 CTF / lab 复现实验；不要对未授权系统发起请求。',
  }, null, 2);
};

const frequencyAnalysis = (value: string) => {
  const letters = value.toUpperCase().replace(/[^A-Z]/g, '');
  const countMap = (items: string[]) => {
    const counts = new Map<string, number>();
    items.forEach(item => counts.set(item, (counts.get(item) || 0) + 1));
    return Array.from(counts.entries())
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
      .slice(0, 40)
      .map(([token, count]) => ({ token, count, percent: items.length ? Number(((count / items.length) * 100).toFixed(2)) : 0 }));
  };
  const ngrams = (size: number) => Array.from({ length: Math.max(0, letters.length - size + 1) }, (_, index) => letters.slice(index, index + size));
  const chars = Array.from(value).filter(char => !/\s/.test(char));
  const ic = letters.length > 1
    ? Number((Array.from(new Set(letters)).reduce((sum, char) => {
      const count = letters.split(char).length - 1;
      return sum + count * (count - 1);
    }, 0) / (letters.length * (letters.length - 1))).toFixed(4))
    : 0;
  const cipherHint = ic >= 0.060 ? '单表替换/Caesar（IC≈0.066）——直接用频率对照 ETAOIN 推测替换表' :
    ic >= 0.045 ? '可能是短 key 多表替换（Vigenère）——试用 IC 分析推断 key 长度' :
    ic >= 0.030 ? '多表替换或随机密钥（IC≈0.038）——尝试 Vigenère 暴破或检查 key 重用' :
    ic < 0.030 ? '近似随机（可能是流密码/XOR/强分组密码）——尝试 XOR 工具或查找密文重复块' : '未知';
  return JSON.stringify({
    length: value.length,
    letterCount: letters.length,
    indexOfCoincidence: ic,
    cipherHint,
    letters: countMap(Array.from(letters)),
    characters: countMap(chars),
    bigrams: countMap(ngrams(2)).slice(0, 20),
    trigrams: countMap(ngrams(3)).slice(0, 20),
    hints: ['English ETAOIN 频率可辅助单表替换与 Caesar 分析。', 'IC 接近 0.066 常见于单表英文文本，接近 0.038 更像随机或多表替换。', 'Top bigrams EN: TH HE IN ER AN RE ON EN。'],
  }, null, 2);
};

const runBrainfuck = (program: string, input: string, maxStepsValue: string) => {
  const code = Array.from(program).filter(char => '<>+-.,[]'.includes(char));
  const bracketStack: number[] = [];
  const jump = new Map<number, number>();
  code.forEach((char, index) => {
    if (char === '[') bracketStack.push(index);
    if (char === ']') {
      const start = bracketStack.pop();
      if (start == null) throw new Error('Brainfuck bracket mismatch');
      jump.set(start, index);
      jump.set(index, start);
    }
  });
  if (bracketStack.length) throw new Error('Brainfuck bracket mismatch');
  const tape = new Uint8Array(30000);
  const inputBytes = utf8Encoder.encode(input);
  const output: number[] = [];
  let pointer = 0;
  let inputIndex = 0;
  let pc = 0;
  let steps = 0;
  const maxSteps = Math.min(5000000, Math.max(1000, Number.parseInt(maxStepsValue, 10) || 120000));
  while (pc < code.length) {
    steps += 1;
    if (steps > maxSteps) throw new Error(`Brainfuck 超过步数限制 ${maxSteps}`);
    const op = code[pc];
    if (op === '>') pointer = (pointer + 1) % tape.length;
    else if (op === '<') pointer = (pointer - 1 + tape.length) % tape.length;
    else if (op === '+') tape[pointer] = (tape[pointer] + 1) & 255;
    else if (op === '-') tape[pointer] = (tape[pointer] - 1) & 255;
    else if (op === '.') output.push(tape[pointer]);
    else if (op === ',') tape[pointer] = inputBytes[inputIndex++] || 0;
    else if (op === '[' && tape[pointer] === 0) pc = jump.get(pc) || pc;
    else if (op === ']' && tape[pointer] !== 0) pc = jump.get(pc) || pc;
    pc += 1;
  }
  return JSON.stringify({
    output: utf8Decoder.decode(new Uint8Array(output)),
    outputHex: bytesToHex(new Uint8Array(output)),
    steps,
    pointer,
  }, null, 2);
};

const encodeBrainfuckText = (value: string) => {
  let current = 0;
  const chunks: string[] = [];
  for (const byte of utf8Encoder.encode(value)) {
    const up = (byte - current + 256) % 256;
    const down = (current - byte + 256) % 256;
    chunks.push((up <= down ? '+'.repeat(up) : '-'.repeat(down)) + '.');
    current = byte;
  }
  return chunks.join('');
};

const brainfuckToOokText = (value: string) => Array.from(value)
  .filter(char => Object.prototype.hasOwnProperty.call(brainfuckToOok, char))
  .map(char => brainfuckToOok[char])
  .join(' ');

const ookToBrainfuckText = (value: string) => {
  const tokens = value.match(/Ook[.!?]/g) || [];
  if (!tokens.length || tokens.length % 2 !== 0) throw new Error('Ook! 解码需要成对的 Ook. / Ook? / Ook! token');
  const output: string[] = [];
  for (let index = 0; index < tokens.length; index += 2) {
    const pair = `${tokens[index]} ${tokens[index + 1]}`;
    const op = ookToBrainfuck[pair];
    if (!op) throw new Error(`未知 Ook! token: ${pair}`);
    output.push(op);
  }
  return output.join('');
};

const jsfuckInspector = (value: string) => {
  const compact = value.replace(/\s+/g, '');
  const jsfuckChars = compact.replace(/[()[\]{}!+]/g, '').length === 0;
  const symbolRatio = compact.length ? 1 - compact.replace(/[()[\]{}!+]/g, '').length / compact.length : 0;
  const quotedStrings = Array.from(value.matchAll(/(["'`])((?:\\.|(?!\1)[\s\S])*)\1/g)).map(match => {
    try {
      return cStringDecode(match[2]);
    } catch {
      return match[2];
    }
  });
  const escapeStrings = Array.from(value.matchAll(/(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})+/g)).map(match => cStringDecode(match[0]));
  const likelyWrappers = [
    ['eval wrapper', /eval|constructor|Function/i.test(value)],
    ['JSFuck alphabet only', jsfuckChars && compact.length > 20],
    ['symbol-heavy JavaScript', symbolRatio > 0.8 && compact.length > 20],
    ['escape-packed payload', escapeStrings.length > 0],
  ].filter(([, enabled]) => enabled).map(([name]) => name);
  return JSON.stringify({
    length: value.length,
    compactLength: compact.length,
    symbolRatio: Number(symbolRatio.toFixed(3)),
    jsfuckAlphabetOnly: jsfuckChars,
    likelyWrappers,
    extractedQuotedStrings: quotedStrings.slice(0, 20),
    extractedEscapeStrings: escapeStrings.slice(0, 20),
    safeNextSteps: [
      '不要直接在当前页面 eval 可疑 JSFuck；先在隔离的 VM 或 DevTools profile 中运行。',
      '如果是纯 JSFuck 字母表，可用 CyberChef JSFuck/Unescape JavaScript 或 de4js 离线还原。',
      '若包含 Function constructor，优先提取字符串常量和 escape 序列，再手工检查网络、DOM、cookie、localStorage 操作。',
    ],
  }, null, 2);
};

const cryptoAttackHelper = (value: string) => {
  const text = value.trim();
  const lower = text.toLowerCase();
  const checks: Array<{ topic: string; when: boolean; actions: string[] }> = [
    {
      topic: 'RSA weak-key / textbook RSA',
      when: /\bn\s*[:=]/i.test(text) || /\be\s*[:=]/i.test(text) || /\bc\s*[:=]/i.test(text) || /rsa/.test(lower),
      actions: [
        '先用 RSA CTF 辅助解析 n/e/c/p/q/phi，再交给 RsaCtfTool。',
        '检查 small e、Hastad broadcast、common modulus、Fermat、Wiener、p=q、dp/dq/qinv 泄露。',
        '命令方向: python RsaCtfTool.py -n <n> -e <e> --uncipher <c>',
      ],
    },
    {
      topic: 'ECC / DSA nonce issue',
      when: /ecdsa|ed25519|curve|elliptic|dsa|nonce|\br\s*[:=]|\bs\s*[:=]/.test(lower),
      actions: [
        '检查重复 r、低位 nonce、partial nonce、invalid curve、small subgroup、anomalous curve。',
        '重复 nonce 公式: k=(h1-h2)/(s1-s2) mod q, d=(s*k-h)/r mod q',
        '复杂 DLP 或曲线阶分解交给 SageMath / Pohlig-Hellman。',
      ],
    },
    {
      topic: 'LCG / MT19937 / PRNG',
      when: /lcg|mt19937|mersenne|random|seed|rand\(|xorshift|prng/.test(lower),
      actions: [
        'LCG 有连续输出时先求 a/c/m；截断输出时转 lattice/HNP。',
        'MT19937 有 624 个 32-bit 连续输出时可 untemper 恢复状态；少量约束可转 Z3。',
        '命令方向: randcrack, z3-solver, Sage lattice',
      ],
    },
    {
      topic: 'LFSR / stream cipher',
      when: /lfsr|berlekamp|keystream|stream|xor|otp|many.?time/.test(lower),
      actions: [
        '已知明文可先做 XOR / keystream 还原；LFSR 可用 Berlekamp-Massey 恢复反馈多项式。',
        '多次 OTP / CTR / RC4 key reuse 时，可做 crib dragging 与 ciphertext XOR。',
        '本工具可先用 XOR 已知明文和单字节 XOR 爆破做前置分析。',
      ],
    },
    {
      topic: 'AES mode / oracle',
      when: /aes|cbc|ecb|gcm|ctr|padding|oracle|nonce|iv/.test(lower),
      actions: [
        'ECB 看重复块与 cut-and-paste；CBC 看 padding oracle / IV bitflip；CTR/GCM 看 nonce reuse。',
        'CBC IV bitflip: plaintext[i] ^= (original_byte ^ target_byte) 在 IV/前一密文块对应位置。',
        'Padding oracle Python: from paddingoracle import BadPaddingException, PaddingOracle; 或用 padbuster/POET。',
        'GCM nonce reuse 会泄露 CTR keystream，并可能恢复 GHASH key，需要专门脚本。',
        '本工具可复现 AES-GCM/CBC/CTR 正常加解密，攻击链建议写 Python/Sage 脚本',
      ],
    },
    {
      topic: 'Hash length extension / MAC',
      when: /md5|sha1|sha256|mac|hmac|hash|crc|length extension|hashpump/.test(lower),
      actions: [
        '对 hash(secret || msg) 可尝试 length extension；正常 HMAC 不受该攻击影响。',
        '常用工具包括 hashpumpy / hash_extender；CRC 线性问题可转成 GF(2) 方程。',
        '先用 Hash 识别确认摘要形态，再判断是否带 secret-prefix 结构。',
      ],
    },
    {
      topic: 'Lattice / LLL / Coppersmith',
      when: /lll|lattice|coppersmith|small root|partial|knapsack|subset|hidden number|hnp|lwe/.test(lower),
      actions: [
        '部分已知 RSA prime/message、small root、多项式同余优先走 Sage small_roots。',
        'HNP / partial nonce / truncated LCG 先建 lattice，再用 LLL/BKZ/Babai。',
        '前台只做识别和模板提示，实际计算建议 SageMath/fpylll',
      ],
    },
  ];
  const matched = checks.filter(item => item.when);
  const fallback = [
    '没有匹配到明确攻击面。建议先粘贴题目参数名、密文片段、算法名、代码变量名或报错回显。',
    '常见 triage 顺序：编码层 -> 古典密码 -> XOR / 流模式 -> 分组模式 -> RSA / ECC / PRNG / LLL。',
  ];
  return JSON.stringify({
    matched: matched.map(({ topic, actions }) => ({ topic, actions })),
    fallback: matched.length ? [] : fallback,
    localTools: ['RsaCtfTool', 'SageMath', 'PyCryptodome', 'sympy', 'z3-solver', 'fpylll', 'hashpumpy', 'hashcat --identify'],
  }, null, 2);
};

const bigIntSqrt = (value: bigint) => {
  if (value < 0n) throw new Error('平方根输入不能为负数');
  if (value < 2n) return value;
  let small = 1n;
  let large = value;
  while (large - small > 1n) {
    const mid = (small + large) >> 1n;
    if (mid * mid <= value) small = mid;
    else large = mid;
  }
  return small;
};

const encodeQuery = (value: string) => {
  const parsed = JSON.parse(value);
  const params = new URLSearchParams();
  Object.entries(parsed).forEach(([key, entry]) => {
    if (Array.isArray(entry)) entry.forEach(item => params.append(key, String(item)));
    else if (entry != null) params.set(key, String(entry));
  });
  return params.toString();
};

const decodeQuery = (value: string) => {
  const clean = value.trim().replace(/^[^?]*\?/, '');
  const params = new URLSearchParams(clean);
  const result: Record<string, string | string[]> = {};
  params.forEach((entry, key) => {
    if (Object.prototype.hasOwnProperty.call(result, key)) {
      const current = result[key];
      result[key] = Array.isArray(current) ? [...current, entry] : [current, entry];
    } else {
      result[key] = entry;
    }
  });
  return JSON.stringify(result, null, 2);
};

const streamToBytes = async (stream: ReadableStream<Uint8Array>) => {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      size += value.length;
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
};

const compressText = async (value: string, format: CompressionFormat) => {
  const CompressionStreamCtor = globalThis.CompressionStream;
  if (!CompressionStreamCtor) throw new Error('当前运行环境不支持 CompressionStream');
  const stream = new Blob([value]).stream().pipeThrough(new CompressionStreamCtor(format));
  return bytesToBase64(await streamToBytes(stream));
};

const decompressText = async (value: string, format: CompressionFormat) => {
  const DecompressionStreamCtor = globalThis.DecompressionStream;
  if (!DecompressionStreamCtor) throw new Error('当前运行环境不支持 DecompressionStream');
  const stream = new Blob([base64ToBytes(value)]).stream().pipeThrough(new DecompressionStreamCtor(format));
  return utf8Decoder.decode(await streamToBytes(stream));
};

const tryDecode = (name: string, input: string, decoder: (value: string) => string) => {
  try {
    const output = decoder(input);
    if (output && output !== input) return { name, output };
  } catch {
    return null;
  }
  return null;
};

const smartSymmetricOperationIds = new Set<OperationId>([
  'aes-gcm',
  'aes-cbc-raw',
  'aes-ctr-raw',
  'aes-ecb',
  'aes-cfb',
  'aes-ofb',
  'aes-gcm-siv',
  'aes-siv',
  'chacha20-orig',
  'chacha20',
  'xchacha20',
  'salsa20',
  'xsalsa20',
  'chacha20-poly1305',
  'xchacha20-poly1305',
  'xsalsa20-poly1305',
  'sm4',
  'des',
  'triple-des',
  'blowfish',
  'rabbit',
]);

const trySmartSymmetricDecrypt = async (value: string): Promise<string | null> => {
  const inference = inferSymmetricCryptoFromText(value);
  if (!inference.operationId || !smartSymmetricOperationIds.has(inference.operationId)) return null;
  if (inference.confidence < 8 || !inference.fields.key || (!inference.fields.ciphertext && !inference.fields.sealed)) return null;
  try {
    const output: string = await transform(inference.operationId, 'decode', inference.input, inference.params);
    return `智能识别: ${inference.operationId} 可直接解密\n\n${output}\n\ninference: ${JSON.stringify(inference.notes)}`;
  } catch {
    return null;
  }
};

const canSmartSymmetricDecryptFromText = (value: string) => {
  const inference = inferSymmetricCryptoFromText(value);
  return Boolean(
    inference.operationId
    && smartSymmetricOperationIds.has(inference.operationId)
    && inference.confidence >= 8
    && inference.fields.key
    && (inference.fields.ciphertext || inference.fields.sealed),
  );
};

const smartCiphertextSource = (value: string) => {
  const fields = parseSymmetricFields(value);
  return {
    fields,
    source: fields.ciphertext || fields.sealed || value.trim(),
    labelled: Boolean(fields.ciphertext || fields.sealed),
  };
};

const parseSmartCipherBytes = (source: string, labelled = false) => {
  const text = cleanSymmetricFieldValue(source);
  // Python bytes literal: b'\x1b\x37...' or b"..."
  const pyBytesMatch = text.trim().match(/^(?:br|rb|b)\s*(['"])([\s\S]*)\1$/i);
  if (pyBytesMatch) {
    try { return { bytes: parsePythonBytesLiteral(text.trim()), encoding: 'python-bytes' }; } catch { /* fall through */ }
  }
  // JSON integer array: [91, 241, 101, ...] — common in CTF Python challenge scripts
  const arrayMatch = text.trim().match(/^\[[\d,\s]+\]$/);
  if (arrayMatch) {
    try {
      const nums = JSON.parse(text.trim()) as number[];
      if (Array.isArray(nums) && nums.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
        return { bytes: new Uint8Array(nums), encoding: 'decimal-array' };
      }
    } catch { /* fall through */ }
  }
  const compactHex = text.replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (compactHex.length >= 8 && compactHex.length % 2 === 0 && /^[0-9a-f]+$/i.test(compactHex)) {
    return { bytes: hexToBytes(compactHex), encoding: 'hex' };
  }
  if (labelled && /^[A-Za-z0-9+/_=-]{8,}$/.test(text.replace(/\s+/g, ''))) {
    try {
      return { bytes: base64ToBytes(text), encoding: 'base64/base64url' };
    } catch {
      return null;
    }
  }
  return null;
};

const printableRatio = (bytes: Uint8Array) => {
  if (!bytes.length) return 0;
  let printable = 0;
  for (const byte of bytes) {
    if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) printable += 1;
  }
  return printable / bytes.length;
};

const smartTextScore = (text: string) => {
  let score = 0;
  if (/flag\{|ctf\{|picoctf\{|htb\{|key\{|crypto\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|actf\{|seccon\{|ritsec\{|lactf\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{/i.test(text)) score += 50;
  if (/\b(the|and|that|you|this|with|from|have|not|for)\b/i.test(text)) score += 10;
  if (/[{}_-]/.test(text)) score += 2;
  const letters = text.replace(/[^a-z]/gi, '');
  if (letters.length >= Math.max(4, text.length * 0.45)) score += 4;
  score += printableRatio(utf8Encoder.encode(text)) * 10;
  return score;
};

const inferPythonXorSnippet = (value: string) => {
  if (!/\bxor\s*\(/i.test(value)) return null;
  const assignmentFields = parsePythonAssignmentFields(value);
  const xorCallText = extractNamedPythonCall(value, 'xor(');
  const xorCall = xorCallText ? parseFunctionLikeCall(xorCallText) : null;
  if (!xorCall || normalizeLooseFieldName(xorCall.name) !== 'xor' || xorCall.args.length < 2) return null;

  const leftBytes = parsePythonCiphertextBytes(xorCall.args[0], assignmentFields);
  const rightBytes = parsePythonCiphertextBytes(xorCall.args[1], assignmentFields);
  if (!leftBytes || !rightBytes || !rightBytes.length) return null;

  return {
    ciphertextHex: bytesToHex(leftBytes),
    keyHex: bytesToHex(rightBytes),
    notes: ['python snippet detected: xor(...)', 'parsed ciphertext/key from xor(...) style script'],
  };
};

const xorWithKeyBytes = (bytes: Uint8Array, key: Uint8Array) => {
  if (!key.length) throw new Error('XOR key cannot be empty');
  return bytes.map((byte, index) => byte ^ key[index % key.length]);
};

const trySmartXorDecrypt = (value: string) => {
  const pythonSnippet = inferPythonXorSnippet(value);
  if (pythonSnippet) {
    try {
      const ciphertext = hexToBytes(pythonSnippet.ciphertextHex);
      const key = hexToBytes(pythonSnippet.keyHex);
      const decoded = xorWithKeyBytes(ciphertext, key);
      const text = utf8Decoder.decode(decoded).replace(/\p{Cc}/gu, '.');
      return `智能识别: XOR 脚本片段\n\n${JSON.stringify({
        method: 'python-xor-call',
        ciphertextHex: pythonSnippet.ciphertextHex,
        keyHex: pythonSnippet.keyHex,
        plaintext: text,
        plaintextHex: bytesToHex(decoded),
        notes: pythonSnippet.notes,
      }, null, 2)}`;
    } catch {
      // Fall through to heuristic XOR recovery.
    }
  }

  const lowered = value.toLowerCase();
  const { fields, source, labelled } = smartCiphertextSource(value);
  // Also try to extract decimal integer arrays directly from the text (e.g. enc_flag = [91, 241, ...])
  const decimalArrayMatch = value.match(/(?:enc(?:rypted)?[_\s]?(?:flag|msg|message|data|text|ct|cipher|output)?\s*[:=]\s*)?\[(\s*\d+(?:\s*,\s*\d+)+\s*)\]/i)
    || value.match(/\b(?:ciphertext|cipher|ct|enc|output|encrypted)\s*[:=]\s*\[(\s*\d+(?:\s*,\s*\d+)+\s*)\]/i);
  const decimalArrayBytes = decimalArrayMatch ? (() => {
    try {
      const nums = decimalArrayMatch[1].split(',').map(s => Number(s.trim()));
      if (nums.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) return new Uint8Array(nums);
    } catch { /* ignore */ }
    return null;
  })() : null;
  const parsed = parseSmartCipherBytes(decimalArrayBytes ? `[${Array.from(decimalArrayBytes).join(',')}]` : source, labelled || /\bxor\b/.test(lowered) || Boolean(decimalArrayBytes));
  if (!parsed) return null;
  const bytes = parsed.bytes;
  if (!bytes || bytes.length < 4) return null;
  const candidates: Array<{ method: string; key: string; score: number; text: string }> = [];

  if (/\bxor\b/.test(lowered) && fields.key) {
    const key = parseOptionalHexOrUtf8Bytes(fields.key).bytes;
    const decoded = xorWithKeyBytes(bytes, key);
    candidates.push({
      method: 'explicit-key',
      key: bytesToHex(key),
      score: printableScore(decoded) + 20,
      text: utf8Decoder.decode(decoded).replace(/\p{Cc}/gu, '.'),
    });
  }

  for (let key = 1; key < 256; key += 1) {
    const decoded = bytes.map(byte => byte ^ key);
    const text = utf8Decoder.decode(decoded).replace(/\p{Cc}/gu, '.');
    candidates.push({
      method: 'single-byte',
      key: `0x${key.toString(16).padStart(2, '0')}`,
      score: printableScore(decoded),
      text,
    });
  }

  const knownPlaintexts = [
    fields.knownPlaintext,
    fields.plaintext,
    'flag{',
    'FLAG{',
    'ctf{',
    'CTF{',
    'picoCTF{',
    'THM{',
    'HTB{',
    'DUCTF{',
    'corctf{',
    'dice{',
    'wctf{',
    'utflag{',
    'PCTF{',
    'uiuctf{',
    'sekai{',
    'lactf{',
    'crypto{',
    'nahamcon{',
    'hsctf{',
    'sdctf{',
    'dctf{',
    'bcactf{',
    'pbctf{',
    'uoftctf{',
    'openctf{',
    'justctf{',
    'b01lers{',
    'wanictf{',
    'jerseyctf{',
    'squ1rrel{',
    'nitro{',
    'mapna{',
    'cakectf{',
    'dragonctf{',
  ].filter((entry): entry is string => Boolean(entry));
  const knownCandidates = knownPlaintexts.map(known => {
    const plain = utf8Encoder.encode(known);
    const key = plain.map((byte, index) => byte ^ bytes[index]);
    const repeating = guessRepeatingKey(key);
    const keyBytes = repeating ? key.slice(0, repeating.length) : key;
    const decoded = xorWithKeyBytes(bytes, keyBytes);
    return {
      method: 'known-plaintext-prefix',
      knownPlaintext: known,
      keyHexPrefix: bytesToHex(key),
      repeatingKeyGuess: repeating,
      preview: utf8Decoder.decode(decoded.slice(0, 160)).replace(/\p{Cc}/gu, '.'),
      score: printableScore(decoded),
    };
  });

  const ranked = candidates
    .sort((left, right) => right.score - left.score)
    .slice(0, 8);
  const best = ranked[0];
  const second = ranked[1];
  const confident = Boolean(best && (
    /\bxor\b/.test(lowered)
    || /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|actf\{|seccon\{|ritsec\{|crypto\{|lactf\{|crew\{|nahamcon\{|hsctf\{|sdctf\{|dctf\{|bcactf\{|pbctf\{|uoftctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|squ1rrel\{|mapna\{|cakectf\{|dragonctf\{/i.test(best.text)
    || (printableRatio(utf8Encoder.encode(best.text)) > 0.9 && (!second || best.score - second.score > 6))
  ));
  if (!confident && !knownCandidates.some(item => /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|actf\{|seccon\{|ritsec\{|crypto\{|lactf\{|crew\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{/i.test(item.preview))) return null;
  return `智能识别: XOR 候选\n\n${JSON.stringify({
    inputEncoding: parsed.encoding,
    ciphertextBytes: bytes.length,
    best,
    ranked,
    knownPlaintextCandidates: knownCandidates,
    repeatingKeyAnalysis: (() => {
      if (bytes.length < 16) return null;
      // IC-based key length detection for repeating-key XOR (Kasiski/IC method adapted for XOR)
      const maxKeyLen = Math.min(32, Math.floor(bytes.length / 3));
      const results: Array<{ keyLength: number; key: string; avgIC: number; preview: string; printable: number }> = [];
      for (let kl = 2; kl <= maxKeyLen; kl++) {
        const cols = Array.from({ length: kl }, (_, i) =>
          Array.from(bytes).filter((_, j) => j % kl === i)
        );
        const avgIC = cols.reduce((sum, col) => {
          const freq = new Array(256).fill(0);
          col.forEach(b => freq[b]++);
          const n = col.length;
          return sum + (n < 2 ? 0 : freq.reduce((s, f) => s + f * (f - 1), 0) / (n * (n - 1)));
        }, 0) / kl;
        // Recover key byte for each column by max score
        const keyBytes = cols.map(col => {
          let best = 0;
          let bestScore = -1;
          for (let k = 0; k < 256; k++) {
            const dec = new Uint8Array(col.map(b => b ^ k));
            const s = printableScore(dec);
            if (s > bestScore) { bestScore = s; best = k; }
          }
          return best;
        });
        const key = new Uint8Array(keyBytes);
        const decoded = xorWithKeyBytes(bytes, key);
        const pRatio = printableRatio(decoded);
        results.push({ keyLength: kl, key: bytesToHex(key), avgIC: Number(avgIC.toFixed(4)), preview: utf8Decoder.decode(decoded.slice(0, 80)).replace(/\p{Cc}/gu, '.'), printable: Number((pRatio * 100).toFixed(1)) });
      }
      results.sort((a, b) => b.printable - a.printable || b.avgIC - a.avgIC);
      const top = results[0];
      return { best: top, candidates: results.slice(0, 6) };
    })(),
    // Chained: try ROT/Caesar on the best XOR plaintext (e.g. Advent of CTF XOR+ROT pattern)
    chainedClassic: (() => {
      if (!best) return null;
      const txt = best.text;
      const letters = txt.replace(/[^a-z]/gi, '');
      if (letters.length < 6 || letters.length / Math.max(1, txt.length) < 0.25) return null;
      const origScore = smartTextScore(txt);
      const rotCandidates = Array.from({ length: 25 }, (_, i) => {
        const d = caesar(txt, i + 1); return { shift: i + 1, text: d, score: smartTextScore(d) };
      }).sort((a, b) => b.score - a.score);
      const bestRot = rotCandidates[0];
      if (/\b[a-z]{2,12}\{[^}]{4,}\}/i.test(bestRot.text) || bestRot.score - origScore > 8)
        return { method: `ROT${bestRot.shift}`, text: bestRot.text, score: bestRot.score };
      return null;
    })(),
    note: 'Single-byte XOR is auto-ranked. Repeating-key XOR uses IC analysis (key lengths 2-32) — check repeatingKeyAnalysis for best candidates.',
  }, null, 2)}`;
};

const extractClassicCipherSource = (value: string) => {
  const symmetricFields = parseSymmetricFields(value);
  const looseFields = parseLooseCtfFields(value);
  // Strip labeled field lines (key=X, password=X, etc.) so they don't pollute the cipher source
  const strippedSource = value.trim()
    .split('\n')
    .filter(line => !/^\s*[A-Za-z][A-Za-z0-9_. -]{0,40}\s*[:=]\s*.+$/.test(line) || !/^[A-Za-z]/.test(line.trim()))
    .join('\n')
    .trim();
  return {
    source: symmetricFields.ciphertext
      || looseField(looseFields, ['ciphertext', 'cipher', 'ct', 'encoded', 'text', 'message', 'msg'])
      || strippedSource
      || value.trim(),
    key: symmetricFields.key || looseField(looseFields, ['key', 'keyword', 'keyword1', 'password']),
    keyword2: looseField(looseFields, ['keyword2', 'key2', 'transpositionkey', 'columnkey']),
    fields: looseFields,
  };
};

const rankClassicCandidates = <T extends { text: string; score?: number }>(candidates: T[]) => candidates
  .map(candidate => ({ ...candidate, score: candidate.score ?? smartTextScore(candidate.text) }))
  .sort((left, right) => (right.score || 0) - (left.score || 0));

const validAffineMultipliers = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

const trySmartStructuredClassicDecrypt = (value: string) => {
  const { source, key, fields } = extractClassicCipherSource(value);
  const text = source.trim();
  const candidates: Array<{ method: string; params?: Record<string, unknown>; score?: number; text: string }> = [];
  const addCandidate = (method: string, decode: () => string, params?: Record<string, unknown>) => {
    try {
      const decoded = decode();
      if (decoded && decoded !== text) candidates.push({ method, params, text: decoded });
    } catch {
      // Keep ranking other candidates.
    }
  };

  if (/^[-. /\s]+$/.test(text) && /[.-]{2,}/.test(text)) addCandidate('morse', () => morseDecode(text));
  // Pollux cipher: digit-only strings where digits encode Morse dots/dashes
  if (/^[0-9\s]+$/.test(text) && text.replace(/\s/g, '').length >= 8) {
    addCandidate('pollux', () => polluxDecode(text));
  }
  if ((/\bbacon\b/i.test(value) || /^[ABab01\s,;|/-]+$/.test(text)) && text.replace(/[^ABab01]/gi, '').length >= 10) {
    addCandidate('bacon', () => baconDecode(text));
  }
  if ((/\bpolybius\b/i.test(value) || /^[1-5\s,;|/-]+$/.test(text)) && (text.match(/[1-5][1-5]/g) || []).length >= 2) {
    addCandidate('polybius', () => polybiusDecode(text));
  }
  if (/\btap\b|敲击|敲擊/i.test(value) || /([.-]{1,5}\s+[.-]{1,5})(\s*\/\s*|\s+)/.test(`${text} `)) {
    addCandidate('tap-code', () => tapCodeDecode(text));
  }

  if (/\baffine\b|仿射/i.test(value)) {
    const aField = looseField(fields, ['a', 'affinea']);
    const bField = looseField(fields, ['b', 'affineb']);
    if (aField && bField) addCandidate('affine-explicit', () => affineTransform(text, aField, bField, true), { a: aField, b: bField });
    for (const a of validAffineMultipliers) {
      for (let b = 0; b < 26; b += 1) addCandidate('affine-bruteforce', () => affineTransform(text, String(a), String(b), true), { a, b });
    }
  }

  const railHint = /\brail\b|fence|栅栏|栏栅|scytale|换位|置换/i.test(value);
  const explicitRails = Number.parseInt(looseField(fields, ['rails', 'rail', 'r', 'columns', 'cols']), 10);
  const hasExplicitRails = Number.isFinite(explicitRails) && explicitRails >= 2;
  if (railHint) {
    const rails = hasExplicitRails
      ? [explicitRails]
      : Array.from({ length: Math.min(10, Math.max(2, Math.floor(text.length / 2))) - 1 }, (_, index) => index + 2);
    for (const rail of rails) addCandidate('rail-fence', () => railFenceDecode(text, String(rail)), { rails: rail });
    if (/scytale|鍒梶column/i.test(value)) {
      for (const columns of rails) addCandidate('scytale', () => scytaleDecode(text, String(columns)), { columns });
    }
  }

  if (key && /\bcolumnar|transposition|列换位|列转位/i.test(value)) {
    addCandidate('columnar-keyed', () => columnarDecode(text, key), { key });
  }

  const ranked = rankClassicCandidates(candidates).slice(0, 16);
  const best = ranked[0];
  if (!best) return null;
  const originalScore = smartTextScore(text);
  const confident = /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|crypto\{|lactf\{|crew\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|the|attack|secret|message/i.test(best.text)
    || (best.score || 0) >= 18
    || (best.score || 0) - originalScore > 8
    || (railHint && hasExplicitRails && /^(rail-fence|scytale|columnar-keyed)$/.test(best.method))
    || /^(morse|bacon|polybius|tap-code)$/.test(best.method);
  if (!confident) return null;
  return `智能识别: structured classic cipher candidates\n\n${JSON.stringify({
    best,
    candidates: ranked,
    note: 'Structured formats are decoded directly; transposition and affine families are ranked candidates and should be verified.',
  }, null, 2)}`;
};

const trySmartClassicWithKey = (value: string) => {
  const { source, key, keyword2, fields } = extractClassicCipherSource(value);
  const lowered = value.toLowerCase();
  if (!source || !key) return null;
  const candidates: Array<{ method: string; key: string; score: number; text: string }> = [];
  if (/vigen[e猫]re|vigenere/.test(lowered)) {
    const text = vigenereTransform(source, key, true);
    candidates.push({ method: 'vigenere', key, score: smartTextScore(text), text });
  }
  if (/beaufort/.test(lowered)) {
    const text = beaufortTransform(source, key);
    candidates.push({ method: 'beaufort', key, score: smartTextScore(text), text });
  }
  if (/autokey/.test(lowered)) {
    const text = autokeyTransform(source, key, true);
    candidates.push({ method: 'autokey-vigenere', key, score: smartTextScore(text), text });
  }
  if (/playfair/.test(lowered)) {
    const text = playfairTransform(source, key, true);
    candidates.push({ method: 'playfair', key, score: smartTextScore(text), text });
  }
  if (/porta/.test(lowered)) {
    const text = portaTransform(source, key);
    candidates.push({ method: 'porta', key, score: smartTextScore(text), text });
  }
  if (/gronsfeld/.test(lowered)) {
    const text = gronsfeldTransform(source, key, true);
    candidates.push({ method: 'gronsfeld', key, score: smartTextScore(text), text });
  }
  if (/bifid/.test(lowered)) {
    const text = bifidTransform(source, key, looseField(fields, ['period']) || '5', true);
    candidates.push({ method: 'bifid', key, score: smartTextScore(text), text });
  }
  if (/trifid/.test(lowered)) {
    const text = trifidTransform(source, key, looseField(fields, ['period']) || '5', true);
    candidates.push({ method: 'trifid', key, score: smartTextScore(text), text });
  }
  if (/four[-\s]?square/.test(lowered)) {
    const text = fourSquareTransform(source, key, keyword2 || key, true);
    candidates.push({ method: 'four-square', key, score: smartTextScore(text), text });
  }
  if (/columnar|transposition/.test(lowered)) {
    const text = columnarDecode(source, key);
    candidates.push({ method: 'columnar', key, score: smartTextScore(text), text });
  }
  if (/adfgvx/.test(lowered)) {
    const text = adfgxTransform(source, key, keyword2 || key, true, 'ADFGVX');
    candidates.push({ method: 'adfgvx', key, score: smartTextScore(text), text });
  } else if (/adfgx/.test(lowered)) {
    const text = adfgxTransform(source, key, keyword2 || key, true, 'ADFGX');
    candidates.push({ method: 'adfgx', key, score: smartTextScore(text), text });
  }
  const ranked = candidates.sort((left, right) => right.score - left.score);
  // Fallback: if key is given but no cipher keyword matched, try Vigenère (most common keyed cipher in CTF)
  if (!ranked.length && key && /^[a-z]{2,}$/i.test(key.trim())) {
    try {
      const text = vigenereTransform(source, key, true);
      const score = smartTextScore(text);
      if (score >= 12) return `智能识别: classic-keyed cipher\n\n${JSON.stringify({ best: { method: 'vigenere', key, score, text }, candidates: [{ method: 'vigenere', key, score, text }] }, null, 2)}`;
    } catch { /* ignore */ }
  }
  if (!ranked.length || ranked[0].score < 12) return null;
  return `智能识别: classic-keyed cipher\n\n${JSON.stringify({ best: ranked[0], candidates: ranked }, null, 2)}`;
};

const ENGLISH_FREQ = [0.082,0.015,0.028,0.043,0.127,0.022,0.020,0.061,0.070,0.002,0.008,0.040,0.024,0.067,0.075,0.019,0.001,0.060,0.063,0.091,0.028,0.010,0.023,0.001,0.020,0.001];
const ENGLISH_IC = 0.0665;

const trySmartVigenereBruteforce = (value: string): string | null => {
  const { source } = extractClassicCipherSource(value);
  const text = source.trim() || value;
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length < 20) return null;
  const hasHint = /vigen[eè]re|polyalpha/i.test(value);
  const colIC = (col: string) => {
    const freq = new Array(26).fill(0);
    for (const c of col) freq[c.charCodeAt(0) - 65] += 1;
    const n = col.length;
    return n < 2 ? 0 : freq.reduce((s, f) => s + f * (f - 1), 0) / (n * (n - 1));
  };
  let bestKeyLen = 2;
  let bestScore = Infinity;
  const maxKeyLen = Math.min(20, Math.floor(letters.length / 3));
  const icCache = new Map<number, number>();
  const getAvgIC = (kl: number) => {
    if (icCache.has(kl)) return icCache.get(kl)!;
    const v = Array.from({ length: kl }, (_, i) => letters.split('').filter((_, j) => j % kl === i).join('')).reduce((s, c) => s + colIC(c), 0) / kl;
    icCache.set(kl, v);
    return v;
  };
  for (let kl = 2; kl <= maxKeyLen; kl += 1) {
    const score = Math.abs(getAvgIC(kl) - ENGLISH_IC) + kl * 0.0008;
    if (score < bestScore) { bestScore = score; bestKeyLen = kl; }
  }
  // Reduce to smallest divisor whose IC is close to English IC (absolute threshold)
  for (let d = 2; d < bestKeyLen; d++) {
    if (bestKeyLen % d === 0 && Math.abs(getAvgIC(d) - ENGLISH_IC) <= 0.01) {
      bestKeyLen = d; break;
    }
  }
  const bestDiff = Math.abs(getAvgIC(bestKeyLen) - ENGLISH_IC);
  if (!hasHint && bestDiff > 0.02) return null;
  const cols = Array.from({ length: bestKeyLen }, (_, i) => letters.split('').filter((_, j) => j % bestKeyLen === i).join(''));
  const key = cols.map(col => {
    let bestShift = 0;
    let bestChi = Infinity;
    for (let shift = 0; shift < 26; shift += 1) {
      const freq = new Array(26).fill(0);
      for (const c of col) freq[(c.charCodeAt(0) - 65 - shift + 26) % 26] += 1;
      const n = col.length;
      const chi2 = freq.reduce((s, f, i) => { const e = n * ENGLISH_FREQ[i]; return s + (e > 0 ? (f - e) ** 2 / e : 0); }, 0);
      if (chi2 < bestChi) { bestChi = chi2; bestShift = shift; }
    }
    return String.fromCharCode(65 + bestShift);
  }).join('');
  const decrypted = vigenereTransform(text, key, true);
  const score = smartTextScore(decrypted);
  const origScore = smartTextScore(text);
  const avgIC = cols.reduce((s, c) => s + colIC(c), 0) / bestKeyLen;
  if (!hasHint && score - origScore < 8 && !/flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|crypto\{|lactf\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{/i.test(decrypted)) return null;
  return `智能识别: Vigenère bruteforce (key length=${bestKeyLen})\n\n${JSON.stringify({ key, keyLength: bestKeyLen, avgColumnIC: Number(avgIC.toFixed(4)), decrypted, note: 'IC analysis + chi-squared column recovery. Verify manually.' }, null, 2)}`;
};

const trySmartClassicDecrypt = (value: string) => {
  const keyed = trySmartClassicWithKey(value);
  if (keyed) return keyed;
  const structured = trySmartStructuredClassicDecrypt(value);
  if (structured) return structured;
  const { source } = extractClassicCipherSource(value);
  const text = source.trim() || value.trim();
  const letters = text.replace(/[^a-z]/gi, '');
  if (letters.length < 6 || letters.length / Math.max(1, text.length) < 0.55) return null;
  const caesarCandidates = Array.from({ length: 25 }, (_, index) => {
    const shift = index + 1;
    const decoded = caesar(text, shift);
    return { method: 'caesar', shift, score: smartTextScore(decoded), text: decoded };
  });
  const atbashText = atbashTransform(text);
  const trithemiusText = trithemiusDecode(text);
  // Affine cipher bruteforce (all 312 valid (a,b) pairs) — only when text is sufficiently letter-heavy
  const affineCandidates = letters.length >= 20
    ? validAffineMultipliers.flatMap(a =>
        Array.from({ length: 26 }, (_, b) => {
          const decoded = affineTransform(text, String(a), String(b), true);
          return { method: 'affine', a, b, score: smartTextScore(decoded), text: decoded };
        })
      )
    : [];
  const candidates = [
    ...caesarCandidates,
    { method: 'atbash', shift: null, score: smartTextScore(atbashText), text: atbashText },
    { method: 'trithemius', shift: null, score: smartTextScore(trithemiusText), text: trithemiusText },
    ...affineCandidates,
  ].sort((left, right) => right.score - left.score);
  const best = candidates[0];
  const originalScore = smartTextScore(text);
  const confident = /flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|crypto\{|lactf\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{/i.test(best.text) || best.score - originalScore > 8;
  if (!confident) return null;
  return `智能识别: classic cipher candidates\n\n${JSON.stringify({
    best,
    candidates: candidates.slice(0, 10),
    note: 'Caesar/ROT and Atbash are ranked by CTF flag patterns plus English-like scoring.',
  }, null, 2)}`;
};

const splitPackedMtWords = (value: bigint, wordBits: number) => {
  if (value < 0n) return [];
  if (wordBits <= 32 || wordBits % 32 !== 0) return [];
  const wordCount = wordBits / 32;
  if (wordCount < 2 || wordCount > 8) return [];
  const upperBound = 1n << BigInt(wordBits);
  if (value >= upperBound) return [];
  return Array.from({ length: wordCount }, (_, index) => (value >> BigInt(index * 32)) & 0xffffffffn);
};

const expandMt19937WordCandidates = (numbers: bigint[]) => {
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

const inferMt19937FromText = (value: string) => {
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

const extractPythonRandomFloatWords = (values: number[]) => values
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

const extractPythonRandrangeSamples = (value: string) => {
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

const uint32 = (value: number) => value >>> 0;

const mt19937Temper = (value: number) => {
  let y = uint32(value);
  y = uint32(y ^ (y >>> 11));
  y = uint32(y ^ ((y << 7) & 0x9d2c5680));
  y = uint32(y ^ ((y << 15) & 0xefc60000));
  y = uint32(y ^ (y >>> 18));
  return y;
};

const undoRightShiftXor = (value: number, shift: number) => {
  let x = uint32(value);
  for (let index = 0; index < 6; index += 1) x = uint32(value ^ (x >>> shift));
  return x;
};

const undoLeftShiftXorMask = (value: number, shift: number, mask: number) => {
  let x = uint32(value);
  for (let index = 0; index < 6; index += 1) x = uint32(value ^ ((x << shift) & mask));
  return x;
};

const mt19937Untemper = (value: number) => {
  let y = uint32(value);
  y = undoRightShiftXor(y, 18);
  y = undoLeftShiftXorMask(y, 15, 0xefc60000);
  y = undoLeftShiftXorMask(y, 7, 0x9d2c5680);
  y = undoRightShiftXor(y, 11);
  return y;
};

const mt19937PredictFromOutputs = (outputs: bigint[], count = 10) => {
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

type SignatureNonceRecord = {
  index: string;
  r: bigint | null;
  s: bigint | null;
  z: bigint | null;
  message?: string | null;
  raw: Record<string, string>;
};

type SignaturePartialNonceConstraint = {
  index: string;
  knownValue: string | null;
  knownBits: number | null;
  position: 'msb' | 'lsb' | 'biased' | 'offset' | 'unknown';
  positions?: Array<'msb' | 'lsb' | 'biased' | 'offset'>;
  relation: string | null;
};

type SignatureScheme = 'ecdsa-dsa' | 'schnorr';

const signatureRecordAliases = {
  r: ['r'],
  s: ['s'],
  z: ['z', 'h', 'hash', 'digest', 'messagehash', 'msghash', 'msgdigest', 'm'],
  message: ['message', 'msg', 'plaintext', 'plain', 'data', 'payload'],
  signature: ['signature', 'sig', 'dersignature', 'der', 'sighex', 'signaturehex', 'rawsignature'],
};
const signatureTokenAliases = ['token', 'jwt', 'jws', 'compactjwt', 'compactjws', 'compacttoken'];

const signatureCurveOrders: Record<string, bigint> = {
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
const signatureCurveExportNames: Record<string, string> = {
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

const joseEcdsaConfigs: Record<string, { hashAlgorithm: 'sha256' | 'sha384' | 'sha512'; curve: string; bytesPerScalar: number }> = {
  ES256: { hashAlgorithm: 'sha256', curve: 'secp256r1', bytesPerScalar: 32 },
  ES384: { hashAlgorithm: 'sha384', curve: 'secp384r1', bytesPerScalar: 48 },
  ES512: { hashAlgorithm: 'sha512', curve: 'secp521r1', bytesPerScalar: 66 },
};

const inferSignatureHashAlgorithm = (value: string, fields: Record<string, string>) => {
  const explicit = looseField(fields, ['algorithm', 'alg', 'hashalgorithm', 'digestalgorithm']).toLowerCase().replace(/[^a-z0-9-]/g, '');
  const normalizedExplicit = explicit.replace('-', '');
  if (['md5', 'sha1', 'sha256', 'sha384', 'sha512'].includes(normalizedExplicit)) return normalizedExplicit;
  if (['es256', 'hs256', 'rs256', 'ps256'].includes(normalizedExplicit)) return 'sha256';
  if (['es384', 'hs384', 'rs384', 'ps384'].includes(normalizedExplicit)) return 'sha384';
  if (['es512', 'hs512', 'rs512', 'ps512'].includes(normalizedExplicit)) return 'sha512';
  const inline = value.match(/\b(md5|sha1|sha-1|sha256|sha-256|sha384|sha-384|sha512|sha-512)\b/i)?.[1].toLowerCase().replace('-', '') || '';
  return ['md5', 'sha1', 'sha256', 'sha384', 'sha512'].includes(inline) ? inline : 'sha256';
};

const inferSignatureOrder = (fields: Record<string, string>) => {
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

const inferSignatureScheme = (value: string, fields: Record<string, string>): SignatureScheme => {
  const explicit = looseField(fields, ['scheme', 'signaturescheme', 'type', 'sigtype']).toLowerCase();
  const alg = looseField(fields, ['algorithm', 'alg']).toLowerCase();
  const source = `${explicit} ${alg} ${value}`.toLowerCase();
  if (/\bschnorr\b|bip340|taproot/.test(source)) return 'schnorr';
  return 'ecdsa-dsa';
};

const digestHexToSignatureZ = (digestHex: string, order: bigint | null) => {
  const numeric = BigInt(`0x${digestHex.replace(/^0x/i, '') || '0'}`);
  if (order == null) return numeric;
  const extraBits = bitLength(numeric) - bitLength(order);
  return extraBits > 0 ? (numeric >> BigInt(extraBits)) : numeric;
};

const parseNumberishUnknown = (value: unknown, fields: Record<string, string> = {}) => {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string') return parseRsaFieldNumericValue('n', value, fields);
  return null;
};

const getObjectAliasValue = (value: Record<string, unknown>, aliases: string[]) => {
  for (const [key, entry] of Object.entries(value)) {
    if (aliases.some(alias => normalizeLooseFieldName(alias) === normalizeLooseFieldName(key))) return entry;
  }
  return undefined;
};

const parseSignatureBlobToRS = (value: string) => {
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

const parseCompactJoseSignatureRecord = (token: string, index: string): SignatureNonceRecord | null => {
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

const parseSignatureTupleList = (value: string) => Array.from(String(value || '').matchAll(/\(\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*,\s*(0x[0-9a-f_]+|\d[\d_]*[nNlL]?)\s*\)/gi))
  .map(match => ({
    r: parseNumericValue(match[1]),
    s: parseNumericValue(match[2]),
  }))
  .filter((entry): entry is { r: bigint; s: bigint } => entry.r != null && entry.s != null);

const parseLooseTextList = (value: string) => {
  const text = String(value || '').trim();
  if (!text) return [];
  const quoted = Array.from(text.matchAll(/(['"`])([\s\S]*?)\1/g)).map(match => match[2]);
  if (quoted.length) return quoted;
  return text
    .split(',')
    .map(entry => cleanSymmetricFieldValue(entry))
    .filter(Boolean);
};

const parseJoseTokenList = (value: string) => {
  const direct = Array.from(String(value || '').matchAll(/\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g)).map(match => match[0]);
  if (direct.length) return direct;
  return parseLooseTextList(value).flatMap(entry => entry.match(/\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g) || []);
};
const escapeRegexLiteral = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const mergeSignatureTokenRecord = (
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

const extractBracketedAssignment = (value: string, aliases: string[]) => {
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

const collectSignatureLooseObjectBlocks = (value: string, output: SignatureNonceRecord[]) => {
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

const collectSignatureJsonRecords = (value: unknown, output: SignatureNonceRecord[], path = 'json') => {
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

const scoreSignatureRecordSpecificity = (record: SignatureNonceRecord) => {
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

const parseSignatureNonceRecords = (value: string) => {
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

const inferSignatureNonceReuseFromText = (value: string) => {
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

const inferSignaturePartialNonceConstraints = (value: string, records: SignatureNonceRecord[]) => {
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

const guessSignatureCurveExportName = (order: bigint | null, records: Array<{ raw: Record<string, string> }>, fields: Record<string, string>) => {
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

const buildBitlogikLatticeTemplates = (
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

const trySmartSignatureNonceReuse = (value: string) => {
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

const canSmartSignatureNonceReuse = (value: string) => Boolean(trySmartSignatureNonceReuse(value));

const trySmartSignatureNonceReuseAsync = async (value: string) => {
  const inference = inferSignatureNonceReuseFromText(value);
  const hasStrongHint = /\b(?:ecdsa|dsa|schnorr|signature|nonce reuse|same nonce|reused nonce)\b/i.test(value);
  const partialConstraints = inferSignaturePartialNonceConstraints(value, inference.records);
  const hasPartialHint = /\b(?:partial nonce|biased nonce|known bits|msb|lsb|hnp|hidden number)\b/i.test(value) || partialConstraints.length > 0;
  if (inference.confidence < 8 || (!inference.repeatedPairs.length && !hasStrongHint && !hasPartialHint)) return null;
  return `智能识别: Signature nonce reuse analysis\n\n${await signatureNonceReuseHelper(value)}`;
};

const signatureNonceReuseHelper = async (value: string) => {
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

const trySmartDiscreteLog = (value: string) => {
  const inference = inferDlpFromText(value);
  const hasStrongHint = /\b(discrete log|dlog|diffie|elgamal|generator|baby-step|bsgs|pohlig)\b|离散对数|迪菲|Diffie|ElGamal|生成元|椭圆曲线密码/i.test(value);
  if (inference.confidence < 6 || (!hasStrongHint && (inference.modulus == null || inference.base == null || inference.target == null))) return null;
  try {
    return `智能识别: Discrete log / ElGamal analysis\n\n${discreteLogHelper(value)}`;
  } catch {
    return null;
  }
};

const canSmartDiscreteLog = (value: string) => Boolean(trySmartDiscreteLog(value));

type DlpInference = {
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

const parseDlpField = (fields: Record<string, string>, aliases: string[]) => {
  const raw = looseField(fields, aliases);
  return raw ? parseNumericValue(raw) : null;
};

const inferDlpFromText = (value: string): DlpInference => {
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

const bigintToSafeNumber = (value: bigint) => {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(value);
};

const discreteLogBsgs = (
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

const discreteLogPohligHellman = (
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

const discreteLogHelper = (value: string) => {
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

type NonceReuseRecord = {
  index: string;
  nonce: string;
  ciphertext: Uint8Array | null;
  plaintext: Uint8Array | null;
  tag: string;
  raw: Record<string, string>;
};

const nonceReuseRecordAliases = {
  nonce: ['nonce', 'iv', 'counter', 'ctr'],
  ciphertext: ['ciphertext', 'cipher', 'ct', 'encrypted', 'enc', 'sealed'],
  plaintext: ['plaintext', 'plain', 'pt', 'knownplaintext', 'knownplain'],
  tag: ['tag', 'authtag', 'mac'],
};

const parseOptionalChallengeBytes = (value: string | undefined, labelText: string) => {
  if (!value) return null;
  try {
    return parseHexBase64OrUtf8Bytes(value, labelText).bytes;
  } catch {
    return null;
  }
};

const collectNonceReuseJsonRecords = (value: unknown, output: NonceReuseRecord[], path = 'json') => {
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

const parseNonceReuseRecords = (value: string) => {
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

const xorBytes = (left: Uint8Array, right: Uint8Array) => {
  const length = Math.min(left.length, right.length);
  const output = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) output[index] = left[index] ^ right[index];
  return output;
};

const bytesPreview = (bytes: Uint8Array) => ({
  hex: bytesToHex(bytes.slice(0, 96)),
  utf8: utf8Decoder.decode(bytes.slice(0, 160)).replace(/\p{Cc}/gu, '.'),
  bytes: bytes.length,
});

const inferNonceReuseFromText = (value: string) => {
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

const trySmartNonceReuse = (value: string) => {
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

const canSmartNonceReuse = (value: string) => Boolean(trySmartNonceReuse(value));

const trySmartPrngAnalyze = (value: string) => {
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

const canSmartPrngAnalyze = (value: string) => {
  const lcg = inferLcgFromText(value);
  if (lcg.confidence >= 8 && (lcg.states.length >= 4 || (lcg.modulus && lcg.multiplier != null && lcg.increment != null))) return true;
  const lfsr = inferLfsrBitsFromText(value);
  if (lfsr.confidence >= 8 && lfsr.bits.length >= 16) return true;
  return inferMt19937FromText(value).confidence >= 8;
};

const mt19937Helper = (value: string) => {
  const inference = inferMt19937FromText(value);
  const clone = mt19937PredictFromOutputs(inference.numbers);
  const floatWords = extractPythonRandomFloatWords(inference.floatOutputs || []);
  const randrangeSamples = extractPythonRandrangeSamples(value);
  return JSON.stringify({
    outputCount: inference.numbers.length,
    wordFormat: inference.wordFormat,
    enoughForFullStateClone: inference.numbers.length >= 624,
    firstOutputs: inference.numbers.slice(0, 16).map(number => number.toString()),
    clone,
    floatOutputCount: floatWords.length,
    floatWords: floatWords.slice(0, 16),
    boundedRandrangeCount: randrangeSamples.length,
    randrangeSamples: randrangeSamples.slice(0, 32),
    inferredFields: inference.fields,
    inferenceConfidence: inference.confidence,
    notes: [
      clone ? 'Recovered MT19937 state from consecutive MT19937 words and predicted future values locally.' : 'MT19937 full state cloning requires 624 consecutive 32-bit outputs, or packed Python getrandbits(32*k) outputs such as 312 x 64-bit values.',
      floatWords.length ? 'Python random.random() outputs were converted into 53-bit numerators and split into the 27-bit / 26-bit halves used by CPython. Use these with a symbolic or lattice-aware MT recovery tool.' : '',
      randrangeSamples.length ? 'Bounded randrange/randbelow samples were extracted with their upper bounds. These are suitable as constraints for a leakage-aware MT solver, but not for direct local state cloning.' : '',
      'If the challenge gives floats, randrange outputs, or truncated bits, move to constraint solving / leakage-specific recovery.',
    ],
    localPythonTemplate: [
      'from randcrack import RandCrack',
      'rc = RandCrack()',
      'for x in outputs[:624]:',
      '    rc.submit(x)',
      'print(rc.predict_getrandbits(32))',
      '# random.random() leakage needs a float-aware MT solver; use the extracted numerators/halves above as constraints.',
    ].join('\\n'),
  }, null, 2);
};

const trySmartHashLengthExtension = (value: string) => {
  const inference = inferHashLengthExtensionFromText(value, '', '', '');
  const explicit = /(length extension|hashpump|hash_extender|secret\s*\|\||prefix mac|secret-prefix)/i.test(value);
  const hasDigest = /^[a-f0-9]{32,64}$/i.test(inference.digest);
  const hasMaterial = inference.originalMessage !== 'known-message' || inference.appendData !== 'admin=true';
  if (!hasDigest || inference.confidence < 7 || (!explicit && !hasMaterial)) return null;
  return `智能识别: Hash length-extension helper\n\n${hashLengthExtensionHelper(value, inference.algorithm, inference.appendData, inference.originalMessage)}`;
};

const canSmartHashLengthExtension = (value: string) => Boolean(trySmartHashLengthExtension(value));

const looksLikeResolvedSmartDecodeText = (value: string) => {
  const text = value.trim();
  if (!text) return false;
  if (/flag\{|ctf\{|picoctf\{|htb\{|thm\{|key\{|crypto\{|dice\{|wctf\{|utflag\{|hsctf\{|sdctf\{|dctf\{|nahamcon\{|ductf\{|bcactf\{|uiuctf\{|pbctf\{|corctf\{|sekai\{|idek\{|bi0s\{|glacierctf\{|rgbctf\{|zer0pts\{|watevr\{|darkctf\{|secureflag\{|actf\{|seccon\{|sunshine\{|ritsec\{|magpie\{|crew\{|squ1rrel\{|nitro\{|mapna\{|cakectf\{|dragonctf\{|lactf\{|wanictf\{|jerseyctf\{|b01lers\{|sunshinectf\{/i.test(text)) return true;
  // Generic CTF flag: word{ ... } but exclude common encoding/intermediate prefixes
  if (/\b[a-z]{2,12}\{[A-Za-z0-9_!@#$%^&*.-]{4,}\}/i.test(text) &&
    !/\b(?:b64|hex|url|rot|xor|enc|dec|utf|msg|str|txt|raw|out|res|key|val|data|base|code|text|byte|hash)\{/i.test(text))
    return true;
  if (/^<[a-z!?/][\s\S]*>$/i.test(text) && printableRatio(utf8Encoder.encode(text)) > 0.9) return true;
  if (/^(?:https?|ftp|file|mailto):\/\/\S+/i.test(text)) return true;
  if ((text.startsWith('{') && text.endsWith('}')) || (text.startsWith('[') && text.endsWith(']'))) {
    try {
      JSON.parse(text);
      return true;
    } catch {
      // Keep testing other heuristics.
    }
  }
  if (/%[0-9a-fA-F]{2}/.test(text)) return false;
  if (/&(#\d+|#x[0-9a-f]+|[a-z]+);/i.test(text)) return false;
  if (/\\u\{?[0-9a-fA-F]{2,}|\\x[0-9a-fA-F]{2}/.test(text)) return false;
  if (/\+[A-Za-z0-9/]+-|\+-/.test(text)) return false;
  const score = smartTextScore(text);
  if (text.length <= 12) return score >= 8 && printableRatio(utf8Encoder.encode(text)) > 0.9;
  return score >= 16 && printableRatio(utf8Encoder.encode(text)) > 0.94;
};

const trySmartSubstitutionBruteforce = (value: string): string | null => {
  const { source: _subSrc } = extractClassicCipherSource(value);
  const text = (_subSrc.trim() || value).trim();
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length < 20) return null;
  const hasHint = /substitut|monoalpha|single.?alpha|cipher.?text|plaintext/i.test(value);
  const icEnglish = 0.0665;
  const freq = new Array(26).fill(0);
  for (const c of letters) freq[c.charCodeAt(0) - 65] += 1;
  const n = letters.length;
  const ic = freq.reduce((s, f) => s + f * (f - 1), 0) / (n * (n - 1));
  if (!hasHint && ic < 0.055) return null; // too low IC → not monoalphabetic
  if (!hasHint && Math.abs(ic - icEnglish) > 0.012) return null;
  // Build substitution from ciphertext freq → English freq (ETAOIN order)
  const etaoin = 'ETAOINSHRDLCUMWFGYPBVKJXQZ';
  const sortedCipher = freq
    .map((f, i) => ({ f, c: String.fromCharCode(65 + i) }))
    .sort((a, b) => b.f - a.f)
    .map(x => x.c);
  const subTable: Record<string, string> = {};
  sortedCipher.forEach((c, i) => { subTable[c] = etaoin[i] ?? c; });
  const scoreText = text.length > 2000 ? text.slice(0, 2000) : text;
  const applySubTable = (t: string, tbl: Record<string, string>) =>
    Array.from(t).map(ch => { const u = ch.toUpperCase(); if (u >= 'A' && u <= 'Z') { const p = tbl[u] ?? ch; return ch === u ? p : p.toLowerCase(); } return ch; }).join('');
  let decoded = applySubTable(scoreText, subTable);
  // Greedy hill-climbing: try all pairwise swaps up to 12 rounds (capped at 2000 chars for perf)
  for (let round = 0; round < 12; round += 1) {
    let improved = false;
    const keys = Object.keys(subTable);
    for (let i = 0; i < keys.length; i += 1) {
      for (let j = i + 1; j < keys.length; j += 1) {
        const [a, b] = [keys[i], keys[j]];
        [subTable[a], subTable[b]] = [subTable[b], subTable[a]];
        const candidate = applySubTable(scoreText, subTable);
        if (smartTextScore(candidate) > smartTextScore(decoded)) { decoded = candidate; improved = true; }
        else [subTable[a], subTable[b]] = [subTable[b], subTable[a]];
      }
    }
    if (!improved) break;
  }
  const finalDecoded = applySubTable(text, subTable);
  const score = smartTextScore(finalDecoded);
  const origScore = smartTextScore(text);
  if (!hasHint && score - origScore < 8 && !/flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|actf\{|seccon\{|ritsec\{|crypto\{|lactf\{|crew\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{/i.test(finalDecoded)) return null;
  return `智能识别: Substitution cipher (frequency-rank mapping)\n\n${JSON.stringify({
    ic: Number(ic.toFixed(4)),
    substitutionTable: subTable,
    decoded: finalDecoded,
    score,
    note: 'Frequency-rank heuristic. Manual refinement via the Substitution tool may be needed.',
  }, null, 2)}`;
};

const trySmartCrtSolver = (value: string): string | null => {
  // Also handle single linear congruence: ax ≡ b (mod n) or ax = b mod n
  const linMatch = value.match(/(\d+)\s*\*?\s*x\s*[≡=]\s*(\d+)\s*(?:\(mod\b|mod\b)\s*(\d+)/i)
    || value.match(/ax?\s*[≡=]\s*b\s*\(?mod/i) && null; // hint only, no solve
  if (linMatch) {
    const a = BigInt(linMatch[1]);
    const b = BigInt(linMatch[2]);
    const n = BigInt(linMatch[3]);
    const g = bigintGcd(a, n);
    if (b % g === 0n) {
      const a1 = a / g; const b1 = b / g; const n1 = n / g;
      const inv = bigintModInverse(a1, n1);
      if (inv != null) {
        const x0 = bigintMod(b1 * inv, n1);
        const solutions = Array.from({ length: Number(g) }, (_, i) => (x0 + n1 * BigInt(i)).toString());
        return `智能识别: 线性同余方程 ${a}x ≡ ${b} (mod ${n})\n\n${JSON.stringify({ equation: `${a}x ≡ ${b} (mod ${n})`, gcd: g.toString(), solutions, note: `${g} solution(s) mod ${n}` }, null, 2)}`;
      }
    } else {
      return `智能识别: 线性同余方程无解 — gcd(${a},${n})=${g} 不整除 ${b}\n\n${JSON.stringify({ equation: `${a}x ≡ ${b} (mod ${n})`, gcd: g.toString(), hasSolution: false }, null, 2)}`;
    }
  }

  // Parse x ≡ a (mod m) or x = a mod m or a % m = r style lines
  const lines = value.split(/\n|;/).map(l => l.trim()).filter(Boolean);
  type CrtEq = { a: bigint; m: bigint };
  const equations: CrtEq[] = [];
  for (const line of lines) {
    let m = line.match(/(?:x\s*[≡=]\s*)?(0x[0-9a-f]+|\d+)\s*(?:\(mod\b|mod\b)\s*(0x[0-9a-f]+|\d+)\s*\)?/i);
    if (m) {
      const a = parseNumericValue(m[1]);
      const mod = parseNumericValue(m[2]);
      if (typeof a === 'bigint' && typeof mod === 'bigint' && mod > 1n) equations.push({ a, m: mod });
      continue;
    }
    m = line.match(/(0x[0-9a-f]+|\d+)\s*%\s*(0x[0-9a-f]+|\d+)\s*[=≡]+\s*(0x[0-9a-f]+|\d+)/i);
    if (m) {
      const mod = parseNumericValue(m[2]);
      const r = parseNumericValue(m[3]);
      if (typeof r === 'bigint' && typeof mod === 'bigint' && mod > 1n) equations.push({ a: r, m: mod });
    }
  }
  if (equations.length < 2) return null;
  for (let i = 0; i < equations.length; i++) {
    for (let j = i + 1; j < equations.length; j++) {
      if (bigintGcd(equations[i].m, equations[j].m) !== 1n) {
        return `智能识别: CRT 方程组 (模非互质，无法直接用 CRT)\n\n${JSON.stringify({ equations: equations.map(e => ({ a: e.a.toString(), mod: e.m.toString() })), note: 'Moduli are not pairwise coprime. Manual generalized CRT or direct solving required.' }, null, 2)}`;
      }
    }
  }
  const M = equations.reduce((acc, eq) => acc * eq.m, 1n);
  let x = 0n;
  for (const eq of equations) {
    const Mi = M / eq.m;
    const inv = bigintModInverse(Mi, eq.m);
    if (inv == null) return null;
    x = bigintMod(x + eq.a * Mi * inv, M);
  }
  return `智能识别: CRT 方程组求解\n\n${JSON.stringify({
    equations: equations.map(e => ({ a: e.a.toString(), mod: e.m.toString() })),
    M: M.toString(),
    x: x.toString(),
    xHex: '0x' + x.toString(16),
    asText: (() => { try { return utf8Decoder.decode(hexToBytes(x.toString(16).padStart(x.toString(16).length + (x.toString(16).length % 2), '0'))); } catch { return null; } })(),
  }, null, 2)}`;
};

const trySmartEccHelper = (value: string): string | null => {
  const lower = value.toLowerCase();
  const fields = parseLooseCtfFields(value);
  const getN = (aliases: string[]) => { const r = looseField(fields, aliases); return r ? parseNumericValue(r) : null; };
  const p   = getN(['p', 'prime', 'field', 'mod', 'modulus']);
  const a   = getN(['a', 'coeff_a', 'coeffa', 'curve_a']);
  const b   = getN(['b', 'coeff_b', 'coeffb', 'curve_b']);
  const n   = getN(['n', 'order', 'curve_order', 'group_order', 'grouporder']);
  const priv = getN(['k', 'priv', 'private', 'secret', 'privatekey', 'privkey', 'da', 'dk']);
  const c1Raw = looseField(fields, ['c1', 'r', 'point1', 'cipher1', 'leftcipher']);
  const c2Raw = looseField(fields, ['c2', 's', 'point2', 'cipher2', 'rightcipher']);
  const pub  = looseField(fields, ['q', 'pubkey', 'publickey', 'pub', 'point', 'qa', 'pk']);
  const g    = looseField(fields, ['g', 'generator', 'basepoint', 'base_point']);
  const hasCurveKeyword = /\b(?:ecc|ecdh|elliptic|curve|secp\w*|nist|weierstrass|point|basepoint|base[_ -]?point|ecdlp)\b/.test(lower);
  const hasCoordinateEvidence = /\b(?:g|q|p|r|generator|public(?:\s+key)?|base(?:\s+point)?)\s*[:=]\s*\(\s*(?:0x[0-9a-f]+|\d+)\s*,\s*(?:0x[0-9a-f]+|\d+)\s*\)/i.test(value);
  const hasCurveEquationEvidence = /\by\s*(?:\^|\*\*)\s*2\s*=\s*x\s*(?:\^|\*\*)\s*3\b/i.test(value)
    || /y²\s*=\s*x³/i.test(value);
  if (!hasCurveKeyword && !hasCoordinateEvidence && !hasCurveEquationEvidence) return null;
  let confidence = 0;
  if (p) confidence += 3;
  if (a != null) confidence += 2;
  if (b != null) confidence += 2;
  if (g || pub) confidence += 2;
  if (hasCoordinateEvidence) confidence += 2;
  if (/secp256k1|secp256r1|p-256|p-384|p-521|curve25519|ed25519/i.test(value)) confidence += 4;
  if (confidence < 5) return null;
  const nBits = p ? p.toString(2).length : null;
  const notes: string[] = [];
  if (nBits && nBits <= 64) notes.push('小域（≤64 bit），BSGS/Pohlig-Hellman 可直接在本地计算 ECDLP。');
  if (p && a != null && b != null) {
    const disc = (4n * a ** 3n + 27n * b ** 2n) % p;
    if (disc === 0n) notes.push('判别式 = 0：曲线是奇异曲线（singular），ECDLP 退化为有限域 DLP 或加法群，可用经典方法攻击。');
  }
  if (value.includes('anomalous') || (p && n && p === n)) notes.push('Anomalous 曲线（#E = p），Smart attack 可在 O(log p) 时间内解 ECDLP：使用 SageMath `E.lift(P)` + p-adic lifting。');
  if (value.includes('mov') || value.includes('supersingular')) notes.push('MOV/Frey-Rück attack：将 ECDLP 规约到有限域 DLP，使用 Weil/Tate pairing。');
  const sageTemplate = [
    p && a != null && b != null ? `p=${p}; a=${a}; b=${b}` : '# p, a, b 未完整识别',
    n ? `n=${n}` : '',
    'E = EllipticCurve(GF(p), [a, b])',
    g ? `G = E(${g})` : '# G 未识别，手动指定',
    pub ? `Q = E(${pub})` : '# Q (public key) 未识别',
    'k = discrete_log(Q, G, operation="+")  # ECDLP',
    priv && c1Raw && c2Raw ? `# Private key k=${priv} found — ElGamal decrypt:\nC1=E(${c1Raw}); C2=E(${c2Raw})\nM = C2 - k*C1; print(M)` : '',
  ].filter(Boolean).join('\n');
  return `智能识别: ECC / Elliptic Curve Helper\n\n${JSON.stringify({
    extracted: { p: p?.toString(), a: a?.toString(), b: b?.toString(), n: n?.toString(), generator: g || null, publicKey: pub || null, privateKey: priv?.toString() || null },
    confidence,
    notes,
    sageTemplate,
    commands: [
      p && a != null && b != null ? `sage -c "${sageTemplate.replace(/"/g, "'")}"` : '',
      `python -c "from tinyec import registry; # or manually define curve"`,
    ].filter(Boolean),
  }, null, 2)}`;
};

const trySmartModDecode = (value: string): string | null => {
  // Detect space-separated integers that map to characters via mod N
  // Common in picoCTF basic-mod1 (mod 37: A-Z/0-9/_) and basic-mod2 (mod 41)
  const tokens = value.trim().split(/[\s,;]+/).filter(Boolean);
  if (tokens.length < 4) return null;
  const nums = tokens.map(Number);
  if (nums.some(n => !Number.isInteger(n) || n < 0)) return null;
  const maxVal = Math.max(...nums);
  if (maxVal <= 127) return null; // Already covered by ASCII codes
  // Try common CTF mod alphabets: mod 37, 41, 40, 47, 97, 26+, ...
  const modAlphabets: Array<{ mod: number; map: (v: number) => string }> = [
    { mod: 37, map: v => v < 26 ? String.fromCharCode(65 + v) : v < 36 ? String(v - 26) : '_' },
    { mod: 41, map: v => v < 26 ? String.fromCharCode(65 + v) : v < 36 ? String(v - 26) : v === 36 ? '_' : v === 37 ? '!' : v === 38 ? '?' : v === 39 ? '@' : '#' },
    { mod: 40, map: v => v < 26 ? String.fromCharCode(65 + v) : v < 36 ? String(v - 26) : '_' },
  ];
  for (const { mod, map } of modAlphabets) {
    const decoded = nums.map(n => map(n % mod)).join('');
    if (/flag\{|ctf\{|picoctf\{|htb\{|thm\{|crypto\{|lactf\{|crew\{|[A-Z0-9_]{6,}/i.test(decoded)) {
      return `智能识别: Modular decode (mod ${mod})\n\n${JSON.stringify({ mod, decoded, note: `Each number taken mod ${mod}, mapped: 0-25→A-Z, 26-35→0-9, 36→_` }, null, 2)}`;
    }
  }
  return null;
};

const extractSmartRawPayloadCandidate = (value: string) => {
  const fields = parseLooseCtfFields(value);
  const aliases = [
    'hex', 'base64', 'b64', 'base32', 'b32', 'binary', 'octal',
    'ciphertext', 'cipher', 'encoded', 'encoding', 'ct', 'data', 'output', 'result', 'answer',
  ];
  for (const alias of aliases) {
    const candidate = cleanLooseFieldValue(looseField(fields, [alias]));
    const compact = candidate.replace(/\s+/g, '');
    if (compact.length < 4) continue;
    if (/^(?:0x)?[0-9a-f]+$/i.test(compact) || /^[A-Za-z0-9+/_=-]+$/.test(compact)) return candidate;
  }
  return null;
};

const trySmartStructuredDecode = async (value: string): Promise<string | null> => {
  const text = value.trim();
  if (!text) return null;
  try {
    if (/^data:[^,]*,/is.test(text)) {
      const output = await transform('data-url', 'decode', text, defaultParams);
      return `智能识别: Data URL\n\n${output}`;
    }
    if (/^Basic\s+[A-Za-z0-9+/=_-]+$/i.test(text)) {
      return `智能识别: HTTP Basic Authorization\n\n${await transform('basic-auth', 'decode', text, defaultParams)}`;
    }
    if (/^otpauth:\/\//i.test(text)) {
      return `智能识别: otpauth URI\n\n${await decodeOtpAuthUriCompat(text)}`;
    }
    if (/^(?:https?:\/\/)?(?:[\w-]+\.)?xn--[a-z0-9-]+(?:\.[\w.-]+)*\/?$/i.test(text)) {
      return `智能识别: Punycode / IDN\n\n${await transform('punycode', 'decode', text, defaultParams)}`;
    }
    if (/^(?:https?:\/\/)?[^\s?]+\?[^\s]+$/.test(text)) {
      return `智能识别: Query String\n\n${decodeQuery(text)}`;
    }
    if (/^[A-Za-z0-9+/_=-\s]+$/.test(text) && text.replace(/\s+/g, '').length >= 12) {
      try {
        const bytes = base64ToBytes(text);
        if (bytes.length >= 3 && bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 0x08) {
          return `智能识别: Base64 GZip\n\n${await decompressText(text, 'gzip')}`;
        }
      } catch {
        // Not a valid Base64-compressed container.
      }
    }
    if (/^[\w-]+\.[\w-]+\.[\w-]*$/i.test(text.replace(/^Bearer\s+/i, ''))) {
      return `智能识别: JWT\n\n${decodeJwt(text)}`;
    }
    if (/^[\w-]+\.[\w-]*\.[\w-]*\.[\w-]*\.[\w-]+$/i.test(text)) {
      return `智能识别: JWE Compact\n\n${parseJwkJwe(text)}`;
    }
    if (/^-----BEGIN [^-]+-----/m.test(text)) {
      try {
        return `智能识别: PEM / ASN.1\n\n${parseAsn1Der(text)}`;
      } catch {
        return `智能识别: PEM Block\n\n${decodePemBlock(text)}`;
      }
    }
    if (/^(?:ssh-|ecdsa-|sk-)/m.test(text) || /\s(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._-]*\s+[A-Za-z0-9+/=]+/.test(text)) {
      return `智能识别: OpenSSH Public Key\n\n${await parseSshPublicKey(text)}`;
    }
    if (/^\s*\{/.test(text) && /"(?:kty|keys|protected|ciphertext|recipients)"/.test(text)) {
      return `智能识别: JWK / JWE\n\n${parseJwkJwe(text)}`;
    }
    if (/^U2FsdGVkX1/i.test(text.replace(/\s+/g, ''))) {
      return `智能识别: OpenSSL Salted__ AES\n\n${JSON.stringify({
        format: 'OpenSSL enc Salted__',
        note: '识别到 OpenSSL EVP_BytesToKey-MD5 容器；请填写 passphrase 后使用 OpenSSL AES-256-CBC 解密。',
      }, null, 2)}`;
    }
    try {
      const parsed = parseFernetRaw(text);
      if (parsed.version === 0x80) {
        return `智能识别: Fernet\n\n${await decodeFernet(text, '')}`;
      }
    } catch {
      // Not a Fernet token.
    }
  } catch {
    // Keep the generic decoder available when a container is malformed.
  }
  return null;
};

const smartDecode = async (value: string): Promise<string> => {
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
    const stripped = input.replace(/^[0-9a-fA-F]{4,}[:\s]+/gm, '').replace(/\|.*\|/g, '').replace(/\s+/g, '');
    return /^[0-9a-fA-F]+$/.test(stripped) && stripped.length >= 4 ? stripped : null;
  })();
  const labeledPayload = extractSmartRawPayloadCandidate(input);
  let current = hexdumpCleaned ?? (pyHexArrayConverted ?? (bytesFromHexMatch ? bytesFromHexMatch[1].replace(/\s/g, '') : pythonBytesMatch ? pythonBytesMatch[2] : labeledPayload ?? input));
  const steps: string[] = [];
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
      /^[A-Za-z0-9+/_=-\s]+$/.test(current) && current.replace(/\s+/g, '').length >= 8 ? tryDecode('Base64', current, base64ToText) : null,
      /^[A-Z2-7=\s]+$/i.test(current) && current.replace(/\s+/g, '').length >= 8 ? tryDecode('Base32', current, decodeBase32) : null,
      /^[0-9A-V=\s]+$/i.test(current) && current.replace(/\s+/g, '').length >= 8 && /[G-Vg-v]/.test(current) ? tryDecode('Base32hex', current, decoded => decodeBase32(decoded, 'hex')) : null,
      /^[0-9A-HJ-KM-NP-TV-Z=\-\s]+$/i.test(current) && current.replace(/[\s-]/g, '').length >= 8 && /[G-HJ-KM-NP-Tg-hj-km-np-t]/.test(current) ? tryDecode('Crockford Base32', current, decoded => decodeBase32(decoded, 'decimal')) : null,
      /^[a-z0-9]{1,83}1[02-9ac-hj-np-z]{6,}$/i.test(current) ? tryDecode('Bech32', current, decodeBech32) : null,
      /^[0-9A-Z $%*+\-./:]+$/i.test(current) && current.replace(/\s+/g, '').length >= 4 ? tryDecode('Base45', current, decodeBase45) : null,
      /^[0-9A-Z\s]+$/i.test(current) && /[A-Z]/i.test(current) && /\d/.test(current) && current.replace(/\s+/g, '').length >= 6 && !/^[0-9a-f\s]+$/i.test(current) ? tryDecode('Base36', current, decodeBase36) : null,
      /^[A-Za-z0-9!#$%&()*+,./:;<=>?@[\]^_`{|}~"\s]+$/.test(current) && /[!#$%&()*+,./:;<=>?@[\]^_`{|}~"]/.test(current) && current.length >= 8 ? tryDecode('Base91', current, decodeBase91) : null,
      /^[01\s,;|]+$/.test(current) && (current.match(/[01]{8}/g) || []).length > 0 ? tryDecode('Binary', current, binaryDecode) : null,
      /^(\\[0-7]{1,3}|0o[0-7]+|0[0-7]{1,3}|[0-7]{3}|[\s,;|])+$/i.test(current) ? tryDecode('Octal', current, octalDecode) : null,
      /^(\d{1,2}[\s,;|/.-]+)*\d{1,2}$/.test(current.trim()) ? tryDecode('A1Z26', current, a1z26Decode) : null,
      // Morse
      /^[-. /\s]+$/.test(current) && /[.-]{2,}/.test(current) ? tryDecode('Morse', current, morseDecode) : null,
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
      // Base58
      /^[1-9A-HJ-NP-Za-km-z]+$/.test(current.replace(/\s+/g, '')) && current.replace(/\s+/g, '').length >= 6
        ? tryDecode('Base58', current.replace(/\s+/g, ''), decodeBase58) : null,
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
        if (lts.length < 6 || alphanum.length === 0 || lts.length / alphanum.length < 0.45) return null;
        const origScore = smartTextScore(current);
        const atb = atbashTransform(current);
        const best = Array.from({ length: 25 }, (_, i) => { const d = caesar(current, i + 1); return { d, score: smartTextScore(d) }; })
          .concat([{ d: atb, score: smartTextScore(atb) }, { d: rot47(current), score: smartTextScore(rot47(current)) }])
          .sort((a, b) => b.score - a.score)[0];
        if (/flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|actf\{|seccon\{|ritsec\{|lactf\{|crew\{|crypto\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|mapna\{/i.test(best.d) || best.score - origScore > 8) return { name: 'ROT/Atbash', output: best.d };
        return null;
      })(),
      // Reverse text
      (() => {
        const rev = Array.from(current).reverse().join('');
        if (/flag\{|ctf\{|picoctf\{|htb\{|thm\{|ductf\{|corctf\{|dice\{|wctf\{|utflag\{|sekai\{|actf\{|seccon\{|ritsec\{|lactf\{|crew\{|crypto\{|nahamcon\{|hsctf\{|justctf\{|b01lers\{|wanictf\{|jerseyctf\{|mapna\{/i.test(rev) || smartTextScore(rev) - smartTextScore(current) > 10) return { name: 'Reverse', output: rev };
        return null;
      })(),
      // UUencode
      /^begin\s+\d+\s+/mi.test(current) && /\nend\s*$/i.test(current) ? tryDecode('UUencode', current, (v) => { const lines = v.split(/\r?\n/).slice(1); const bytes: number[] = []; for (const line of lines) { if (/^end$/i.test(line.trim())) break; if (!line) continue; const chars = Array.from(line); const count = (chars[0].charCodeAt(0) - 32) & 63; for (let i = 1; i + 3 < chars.length && bytes.length < count; i += 4) { const a = (chars[i].charCodeAt(0)-32)&63, b = (chars[i+1].charCodeAt(0)-32)&63, c = (chars[i+2].charCodeAt(0)-32)&63, d = (chars[i+3].charCodeAt(0)-32)&63; bytes.push((a<<2)|(b>>4), ((b&15)<<4)|(c>>2), ((c&3)<<6)|d); } } return utf8Decoder.decode(new Uint8Array(bytes.slice(0, bytes.length))); }) : null,
      // NATO phonetic
      /\b(?:Alpha|Bravo|Charlie|Delta|Echo|Foxtrot|Golf|Hotel|India|Juliett|Kilo|Lima|Mike|November|Oscar|Papa|Quebec|Romeo|Sierra|Tango|Uniform|Victor|Whiskey|Xray|Yankee|Zulu)\b/i.test(current) ? tryDecode('NATO', current, natoDecode) : null,
      // Quoted-Printable
      /=\r?\n|=[0-9A-F]{2}/i.test(current) ? tryDecode('Quoted-Printable', current, quotedPrintableDecode) : null,
      // Ascii85
      /^<~/.test(current.trim()) || /~>$/.test(current.trim()) ? tryDecode('Ascii85', current, decodeAscii85) : null,
      // Bacon cipher (A/B or 0/1 groups of 5) — checked before Baudot to avoid 0/1 conflict
      (() => {
        const stripped = current.replace(/[\s,]/g, '').toUpperCase();
        if (stripped.length < 15 || stripped.length % 5 !== 0 || !/^[AB01]+$/.test(stripped)) return null;
        // Pure 0/1: only Bacon if no chunk exceeds 24 (Baudot shift codes are 25-31)
        if (!/[AB]/.test(stripped) && (stripped.match(/.{5}/g) || []).some(c => parseInt(c, 2) > 24)) return null;
        return tryDecode('Bacon', current, baconDecode);
      })(),
      // Baudot / ITA2
      /^(?:[01]{5}[\s,]+){4,}[01]{5}/.test(current.trim()) ? tryDecode('Baudot', current, baudotDecode) : null,
      // Polybius square (digit pairs 1-5, at least 4 pairs)
      (() => {
        const stripped = current.replace(/[\s,;|-]/g, '');
        if (/^[1-5]+$/.test(stripped) && stripped.length >= 8 && stripped.length % 2 === 0)
          return tryDecode('Polybius', current, polybiusDecode);
        return null;
      })(),
    ].filter(Boolean) as Array<{ name: string; output: string }>;

    const next = candidates.find(candidate => candidate.output && candidate.output !== current);
    if (!next) break;
    steps.push(next.name);
    current = next.output;
  }

  // Chained cipher: if the decoded layer is now classic-cipher-looking (e.g. Base64 -> Caesar text),
  // run one more classic/Vigenère/substitution pass on the result.
  if (steps.length && !looksLikeResolvedSmartDecodeText(current)) {
    const letters = current.replace(/[^a-z]/gi, '');
    if (letters.length >= 12 && letters.length / Math.max(1, current.length) > 0.5) {
      const chained = trySmartVigenereBruteforce(current) || trySmartClassicDecrypt(current) || trySmartSubstitutionBruteforce(current);
      if (chained) return `识别链路: ${steps.join(' -> ')} -> (classic)\n\n${chained}`;
    }
  }

  return steps.length
    ? `识别链路: ${steps.join(' -> ')}\n\n${current}`
    : '没有识别到可安全自动解码的格式。可以手动选择具体算法继续转换。';
};

const detectInput = (value: string): Detection[] => {
  const text = value.trim();
  if (!text) return [];
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
  if (/^=ybegin\b|^=ypart\b|^=yend\b/im.test(text)) detections.push({ id: 'yenc', label: 'yEnc' });
  if (/^x(?:[aeiouy][bcdfghklmnprstvzx][aeiouy][bcdfghklmnprstvzx][bcdfghklmnprstvzx]-?)*(?:[aeiouy][bcdfghklmnprstvzx][aeiouy])?x$/i.test(text.replace(/\s+/g, ''))) detections.push({ id: 'bubble-babble', label: 'Bubble Babble' });
  if (/^(\d{1,2}[\s,;|/-]+)*\d{1,2}$/.test(text) && text.split(/[\s,;|/-]+/).some(token => Number(token) >= 1 && Number(token) <= 26)) detections.push({ id: 'a1z26', label: 'A1Z26' });
  if (/^[ABab01\s,;|/-]+$/.test(text) && text.replace(/[^ABab01]/g, '').length >= 10) detections.push({ id: 'bacon', label: 'Bacon' });
  if (/^[1-5\s,;|/-]+$/.test(text) && (text.match(/[1-5][1-5]/g) || []).length >= 2) detections.push({ id: 'polybius', label: 'Polybius' });
  if (/([.-]{1,5}\s+[.-]{1,5})(\s*\/\s*|\s+)/.test(`${text} `)) detections.push({ id: 'tap-code', label: 'Tap Code' });
  if (/^[<>+\-.,[\]\s]+$/.test(text) && /[.[\]]/.test(text)) detections.push({ id: 'brainfuck', label: 'Brainfuck' });
  if (/Ook[.!?]/.test(text)) detections.push({ id: 'ook', label: 'Ook!' });
  if (/^[()[\]{}!+\s]+$/.test(text) && text.replace(/\s+/g, '').length > 20) detections.push({ id: 'jsfuck-helper', label: 'JSFuck' });
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
  if (/^(https?:|data:)/i.test(text)) detections.push({ id: 'data-url', label: text.startsWith('data:') ? 'Data URL' : 'URL' });
  const priority = (id: string) => {
    if (id === 'rabin-raw') return 120;
    if (id === 'rsa-raw') return 118;
    if (id === 'rsa-helper') return 116;
    if (id === 'discrete-log-helper') return 114;
    if (id === 'signature-nonce-helper') return 112;
    if (id === 'mt19937-helper' || id === 'lcg-helper' || id === 'lfsr-helper') return 108;
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

function EncodingTools() {
  const { language } = useAppContext();
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [activeCategory, setActiveCategory] = useState<CategoryId>('smart');
  const [activeOperation, setActiveOperation] = useState<OperationId>('smart-decode');
  const [params, setParams] = useState<Record<ParamKey, string>>(defaultParams);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [showOptions, setShowOptions] = useState(false);

  const categoryOperations = useMemo(
    () => operations.filter(operation => operation.category === activeCategory),
    [activeCategory],
  );
  const operation = operations.find(item => item.id === activeOperation) || operations[0];
  const hashAlgorithmValue = isOtpOperation(activeOperation) && !otpHashAlgorithms.has(params.hashAlgorithm)
    ? 'sha1'
    : activeOperation === 'jwt-hmac' && !jwtHmacHashAlgorithms.has(params.hashAlgorithm)
      ? 'sha256'
    : params.hashAlgorithm;
  const variantValue = activeOperation === 'rabbit' && params.variant === 'hex'
    ? 'special'
    : params.variant;
  const detections = useMemo(() => detectInput(input), [input]);

  useEffect(() => {
    if (typeof window === 'undefined' || !/^(localhost|127\.0\.0\.1|::1)$/i.test(window.location.hostname)) return;
    const devWindow = window as Window & {
      __PAYLOADER_CODEC_TEST_API?: {
        defaultParams: Record<ParamKey, string>;
        operations: Array<Pick<Operation, 'id' | 'supportsEncode' | 'supportsDecode' | 'params'>>;
        transform: typeof transform;
      };
    };
    devWindow.__PAYLOADER_CODEC_TEST_API = {
      defaultParams,
      operations: operations.map(operation => ({
        id: operation.id,
        supportsEncode: operation.supportsEncode,
        supportsDecode: operation.supportsDecode,
        params: operation.params,
      })),
      transform,
    };
    return () => {
      delete devWindow.__PAYLOADER_CODEC_TEST_API;
    };
  }, []);

  const selectCategory = (category: CategoryId) => {
    const firstOperation = operations.find(item => item.category === category);
    setActiveCategory(category);
    if (firstOperation) setActiveOperation(firstOperation.id);
    setError('');
    setOutput('');
  };

  const run = async (direction: Direction) => {
    setError('');
    setRunning(true);
    try {
      const result = await transform(activeOperation, direction, input, params);
      setOutput(result);
    } catch (reason) {
      setOutput('');
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setRunning(false);
    }
  };

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(error || output);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  const clearAll = () => {
    setInput('');
    setOutput('');
    setError('');
  };

  const applyDetection = (operationId: OperationId) => {
    const next = operations.find(item => item.id === operationId);
    if (!next) return;
    setActiveCategory(next.category);
    setActiveOperation(next.id);
    setError('');
    setOutput('');
  };

  return (
    <div className="encoding-tools">
      <div className="encoding-header">
        <h2>{language === 'zh' ? '智能编解码工具' : 'Smart Codec Tools'}</h2>
        <p>{language === 'zh' ? '参考 CyberChef、DevToys、IT-Tools 的工作流，覆盖 Web、进制、加密、摘要、令牌和压缩场景。' : 'A CyberChef-, DevToys-, and IT-Tools-inspired workflow for web, binary, crypto, token, and compression operations.'}</p>
      </div>

      <div className="encoding-workbench">
        <aside className="encoding-category-panel" aria-label={language === 'zh' ? '编解码分类' : 'Codec categories'}>
          <select
            className="category-select"
            value={activeCategory}
            onChange={event => selectCategory(event.target.value as CategoryId)}
            aria-label={language === 'zh' ? '选择分类' : 'Select category'}
          >
            {categories.map(category => (
              <option key={category.id} value={category.id}>{label(category.name, language)}</option>
            ))}
          </select>
          <div className="category-list" role="list">
            {categories.map(category => (
              <button
                key={category.id}
                type="button"
                className={`category-row ${activeCategory === category.id ? 'active' : ''}`}
                onClick={() => selectCategory(category.id)}
              >
                <span>{label(category.name, language)}</span>
                <small>{label(category.note, language)}</small>
              </button>
            ))}
          </div>
        </aside>

        <section className="encoding-main-panel">
          <div className="codec-toolbar">
            <label className="operation-select-field">
              <span>{language === 'zh' ? '算法 / 场景' : 'Operation'}</span>
              <select
                value={activeOperation}
                onChange={event => {
                  setActiveOperation(event.target.value as OperationId);
                  setError('');
                  setOutput('');
                }}
              >
                {categoryOperations.map(item => (
                  <option key={item.id} value={item.id}>{label(item.name, language)}</option>
                ))}
              </select>
            </label>

            <div className="mode-actions" aria-label={language === 'zh' ? '执行操作' : 'Actions'}>
              <button
                type="button"
                className="mode-btn primary"
                onClick={() => run('encode')}
                disabled={running || operation.supportsEncode === false}
              >
                {label(operation.encodeLabel || { zh: '编码/生成', en: 'Encode / Generate' }, language)}
              </button>
              <button
                type="button"
                className="mode-btn"
                onClick={() => run('decode')}
                disabled={running || operation.supportsDecode === false}
              >
                {label(operation.decodeLabel || { zh: '解码/解析', en: 'Decode / Parse' }, language)}
              </button>
              <button type="button" className="mode-btn subtle" onClick={() => run('decode')} disabled={running || activeOperation === 'smart-decode'}>
                {language === 'zh' ? '快速解码' : 'Quick decode'}
              </button>
            </div>
          </div>

          <div className="operation-summary">
            <div>
              <strong>{label(operation.name, language)}</strong>
              <span>{label(operation.summary, language)}</span>
            </div>
            {operation.params?.length ? (
              <button type="button" className="options-toggle" onClick={() => setShowOptions(value => !value)}>
                {showOptions ? (language === 'zh' ? '收起参数' : 'Hide options') : (language === 'zh' ? '展开参数' : 'Show options')}
              </button>
            ) : null}
          </div>

          {operation.params?.length ? (
            <div className={`codec-options ${showOptions ? 'open' : ''}`}>
              {operation.params.includes('variant') && (
                <label>
                  <span>{language === 'zh' ? '输出 / 算法变体' : 'Variant'}</span>
                  <select value={variantValue} onChange={event => setParams({ ...params, variant: event.target.value })}>
                    {(activeOperation === 'html-entity' || activeOperation === 'xml-entity') && (
                      <>
                        <option value="special">{language === 'zh' ? '命名实体' : 'Named entities'}</option>
                        <option value="decimal">{language === 'zh' ? '十进制实体' : 'Decimal entities'}</option>
                        <option value="hex">{language === 'zh' ? '十六进制实体' : 'Hex entities'}</option>
                      </>
                    )}
                    {activeOperation === 'unicode-escape' && (
                      <>
                        <option value="special">{language === 'zh' ? '\\uXXXX' : '\\uXXXX'}</option>
                        <option value="hex">{language === 'zh' ? '\\xHH' : '\\xHH'}</option>
                        <option value="brace">{language === 'zh' ? '\\u{...} 格式' : '\\u{...} format'}</option>
                      </>
                    )}
                    {activeOperation === 'base32' && (
                      <>
                        <option value="special">RFC 4648 Base32</option>
                        <option value="hex">Base32hex</option>
                        <option value="decimal">Crockford Base32</option>
                      </>
                    )}
                    {activeOperation === 'bech32' && (
                      <>
                        <option value="special">Bech32</option>
                        <option value="hex">Bech32m</option>
                      </>
                    )}
                    {activeOperation === 'otpauth-uri' && (
                      <>
                        <option value="special">TOTP</option>
                        <option value="hex">HOTP</option>
                      </>
                    )}
                    {isCryptoJsCipherOperation(activeOperation) && (
                      <>
                        <option value="special">{activeOperation === 'rabbit' ? 'Raw key + IV' : 'CBC raw key + IV'}</option>
                        {cryptoJsBlockCipherOperationIds.has(activeOperation) && <option value="hex">ECB raw key</option>}
                        <option value="decimal">OpenSSL Salted__ passphrase</option>
                      </>
                    )}
                    {(activeOperation === 'aes-ecb' || activeOperation === 'aes-cbc-raw') && (
                      <>
                        <option value="special">PKCS#7 padding</option>
                        <option value="hex">No padding exact block</option>
                      </>
                    )}
                    {activeOperation === 'sm4' && (
                      <>
                        <option value="special">CBC raw key + IV</option>
                        <option value="hex">ECB raw key</option>
                      </>
                    )}
                    {activeOperation === 'ascii85' && (
                      <>
                        <option value="special">ASCII85 / Adobe</option>
                        <option value="hex">Z85</option>
                      </>
                    )}
                    {activeOperation === 'hex' && (
                      <>
                        <option value="special">{language === 'zh' ? '纯 Hex' : 'Plain hex'}</option>
                        <option value="decimal">{language === 'zh' ? '0x 前缀' : '0x prefix'}</option>
                        <option value="hex">{language === 'zh' ? '\\x 前缀' : '\\x prefix'}</option>
                      </>
                    )}
                    {activeOperation === 'rot' && (
                      <>
                        <option value="special">ROT13 / Caesar</option>
                        <option value="hex">ROT47</option>
                      </>
                    )}
                    {activeOperation === 'utf16-bytes' && (
                      <>
                        <option value="special">UTF-16 LE</option>
                        <option value="hex">UTF-16 BE</option>
                      </>
                    )}
                    {activeOperation === 'dna-code' && (
                      <>
                        <option value="special">00=A 01=C 10=G 11=T</option>
                        <option value="decimal">00=A 01=G 10=C 11=T</option>
                        <option value="hex">00=C 01=A 10=T 11=G</option>
                      </>
                    )}
                    {activeOperation === 'keyboard-shift' && (
                      <>
                        <option value="special">{language === 'zh' ? '向右还原' : 'Shift right'}</option>
                        <option value="hex">{language === 'zh' ? '向左还原' : 'Shift left'}</option>
                      </>
                    )}
                  </select>
                </label>
              )}
              {operation.params.includes('hashAlgorithm') && (
                <label>
                  <span>{language === 'zh' ? '摘要算法' : 'Digest algorithm'}</span>
                  <select value={hashAlgorithmValue} onChange={event => setParams({ ...params, hashAlgorithm: event.target.value })}>
                    {isOtpOperation(activeOperation) ? (
                      <>
                        <option value="sha1">SHA-1</option>
                        <option value="sha256">SHA-256</option>
                        <option value="sha512">SHA-512</option>
                      </>
                    ) : activeOperation === 'jwt-hmac' ? (
                      <>
                        <option value="sha256">SHA-256 / HS256</option>
                        <option value="sha384">SHA-384 / HS384</option>
                        <option value="sha512">SHA-512 / HS512</option>
                      </>
                    ) : (
                      <>
                        {activeOperation !== 'hmac' && <option value="md5">MD5</option>}
                        <option value="sha1">SHA-1</option>
                        <option value="sha256">SHA-256</option>
                        <option value="sha384">SHA-384</option>
                        <option value="sha512">SHA-512</option>
                        {activeOperation !== 'hmac' && <option value="sha3-224">SHA3-224</option>}
                        {activeOperation !== 'hmac' && <option value="sha3-256">SHA3-256</option>}
                        {activeOperation !== 'hmac' && <option value="sha3-384">SHA3-384</option>}
                        {activeOperation !== 'hmac' && <option value="sha3-512">SHA3-512</option>}
                        {activeOperation !== 'hmac' && <option value="keccak-256">Keccak-256</option>}
                        {activeOperation !== 'hmac' && <option value="keccak-512">Keccak-512</option>}
                        {activeOperation !== 'hmac' && <option value="md4">MD4</option>}
                        {activeOperation !== 'hmac' && <option value="ripemd160">RIPEMD-160</option>}
                        {activeOperation !== 'hmac' && <option value="blake2b-256">BLAKE2b-256</option>}
                        {activeOperation !== 'hmac' && <option value="blake2b-512">BLAKE2b-512</option>}
                        {activeOperation !== 'hmac' && <option value="blake2s-256">BLAKE2s-256</option>}
                        {activeOperation !== 'hmac' && <option value="blake3">BLAKE3</option>}
                        {activeOperation !== 'hmac' && <option value="sm3">SM3</option>}
                        {activeOperation !== 'hmac' && <option value="whirlpool">Whirlpool</option>}
                        {activeOperation !== 'hmac' && <option value="xxhash32">xxHash32</option>}
                        {activeOperation !== 'hmac' && <option value="xxhash64">xxHash64</option>}
                        {activeOperation !== 'hmac' && <option value="crc16">CRC16</option>}
                        {activeOperation !== 'hmac' && <option value="crc32">CRC32</option>}
                        {activeOperation !== 'hmac' && <option value="adler32">Adler32</option>}
                      </>
                    )}
                  </select>
                </label>
              )}
              {operation.params.includes('secret') && (
                <label className={activeOperation === 'jwt-public' ? 'wide-option' : undefined}>
                  <span>{activeOperation === 'brainfuck'
                    ? (language === 'zh' ? 'Brainfuck 输入' : 'Brainfuck stdin')
                    : activeOperation === 'lcg-helper'
                      ? (language === 'zh' ? '可选 modulus' : 'Optional modulus')
                      : activeOperation === 'hash-length-extension-helper'
                        ? (language === 'zh' ? '追加数据' : 'Append data')
                      : isCryptoJsCipherOperation(activeOperation)
                        ? (variantValue === 'decimal' ? 'Passphrase' : 'Key')
                      : activeOperation === 'openssl-aes-256-cbc'
                        ? 'OpenSSL passphrase'
                      : isNobleNonceOperation(activeOperation) || isNobleAesOperation(activeOperation) || activeOperation === 'sm4'
                        ? 'Key'
                      : isOtpOperation(activeOperation)
                        ? 'Base32 secret'
                      : activeOperation === 'enigma'
                        ? 'Enigma settings'
                      : activeOperation === 'jwt-hmac'
                        ? 'JWT HMAC secret'
                      : activeOperation === 'jwt-public'
                        ? 'Public key material'
                      : activeOperation === 'fernet'
                        ? 'Fernet key'
                      : (language === 'zh' ? '密钥 / 口令' : 'Secret / password')}</span>
                  {activeOperation === 'jwt-public' ? (
                    <textarea
                      value={params.secret}
                      onChange={event => setParams({ ...params, secret: event.target.value })}
                      rows={6}
                      spellCheck={false}
                      placeholder={'-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n\nor paste JWK / JWKS JSON'}
                    />
                  ) : (
                    <input value={params.secret} onChange={event => setParams({ ...params, secret: event.target.value })} placeholder={activeOperation === 'lcg-helper' ? 'm=2^31 / m=2147483648' : activeOperation === 'hash-length-extension-helper' ? 'admin=true' : isCryptoJsCipherOperation(activeOperation) ? (params.variant === 'decimal' ? 'OpenSSL passphrase' : 'hex key or UTF-8 key') : activeOperation === 'openssl-aes-256-cbc' ? 'OpenSSL passphrase' : isNobleNonceOperation(activeOperation) || isNobleAesOperation(activeOperation) || activeOperation === 'sm4' ? 'hex key or UTF-8 key' : isOtpOperation(activeOperation) ? 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' : activeOperation === 'enigma' ? 'rotors=I II III; reflector=B; rings=AAA; positions=AAA; plugboard=AV BS' : activeOperation === 'jwt-hmac' ? 'secret' : activeOperation === 'fernet' ? 'URL-safe Base64 32-byte key' : (language === 'zh' ? '仅在本地浏览器使用' : 'Used locally in this browser')} />
                  )}
                </label>
              )}
              {operation.params.includes('iv') && (!operation.params.includes('variant') || activeOperation === 'aes-cbc-raw' || (variantValue !== 'hex' && variantValue !== 'decimal')) && (
                <label>
                  <span>{isNobleNonceOperation(activeOperation) ? 'Nonce' : activeOperation === 'rabbit' ? 'IV / nonce' : 'IV'}</span>
                  <input value={params.iv} onChange={event => setParams({ ...params, iv: event.target.value })} placeholder={isNobleNonceOperation(activeOperation) ? 'hex nonce or UTF-8 nonce' : activeOperation === 'rabbit' ? 'optional hex or UTF-8 IV' : 'hex IV or UTF-8 IV'} />
                </label>
              )}
              {operation.params.includes('hrp') && (
                <label>
                  <span>{language === 'zh' ? 'HRP 前缀' : 'HRP prefix'}</span>
                  <input value={params.hrp} onChange={event => setParams({ ...params, hrp: event.target.value })} placeholder="bc / tb / lnbc" />
                </label>
              )}
              {operation.params.includes('versionHex') && (
                <label>
                  <span>{language === 'zh' ? '版本字节 Hex' : 'Version bytes hex'}</span>
                  <input value={params.versionHex} onChange={event => setParams({ ...params, versionHex: event.target.value })} placeholder="00 / 05 / 80" />
                </label>
              )}
              {operation.params.includes('digits') && (
                <label>
                  <span>{language === 'zh' ? 'OTP 位数' : 'OTP digits'}</span>
                  <input type="number" min="4" max="10" step="1" value={params.digits} onChange={event => setParams({ ...params, digits: event.target.value })} />
                </label>
              )}
              {operation.params.includes('counter') && (activeOperation !== 'otpauth-uri' || params.variant === 'hex') && (
                <label>
                  <span>{language === 'zh' ? 'HOTP counter' : 'HOTP counter'}</span>
                  <input type="number" min="0" step="1" value={params.counter} onChange={event => setParams({ ...params, counter: event.target.value })} />
                </label>
              )}
              {operation.params.includes('timeStep') && (activeOperation !== 'otpauth-uri' || params.variant !== 'hex') && (
                <label>
                  <span>{language === 'zh' ? 'TOTP 步长秒数' : 'TOTP time step'}</span>
                  <input type="number" min="1" step="1" value={params.timeStep} onChange={event => setParams({ ...params, timeStep: event.target.value })} />
                </label>
              )}
              {operation.params.includes('otpTimestamp') && (
                <label>
                  <span>{language === 'zh' ? 'Unix 秒级时间' : 'Unix timestamp seconds'}</span>
                  <input inputMode="numeric" value={params.otpTimestamp} onChange={event => setParams({ ...params, otpTimestamp: event.target.value })} placeholder={language === 'zh' ? '留空表示当前时间' : 'Empty = current time'} />
                </label>
              )}
              {operation.params.includes('keyword2') && (
                <label>
                  <span>{language === 'zh' ? '第二关键词' : 'Second keyword'}</span>
                  <input value={params.keyword2} onChange={event => setParams({ ...params, keyword2: event.target.value })} placeholder="CIPHER / SECONDKEY" />
                </label>
              )}
              {operation.params.includes('associatedData') && (
                <label>
                  <span>{language === 'zh' ? 'AAD 关联数据' : 'AAD / associated data'}</span>
                  <input value={params.associatedData} onChange={event => setParams({ ...params, associatedData: event.target.value })} placeholder="optional UTF-8 or hex AAD" />
                </label>
              )}
              {operation.params.includes('period') && (
                <label>
                  <span>{language === 'zh' ? '周期' : 'Period'}</span>
                  <input type="number" min="1" max="64" value={params.period} onChange={event => setParams({ ...params, period: event.target.value })} />
                </label>
              )}
              {operation.params.includes('iterations') && (
                <label>
                  <span>{activeOperation === 'brainfuck' ? (language === 'zh' ? '最大步数' : 'Max steps') : (language === 'zh' ? 'PBKDF2 迭代次数' : 'PBKDF2 iterations')}</span>
                  <input type="number" min="10000" step="1000" value={params.iterations} onChange={event => setParams({ ...params, iterations: event.target.value })} />
                </label>
              )}
              {operation.params.includes('dropBytes') && (
                <label>
                  <span>{language === 'zh' ? '丢弃字节' : 'Drop bytes'}</span>
                  <input type="number" min="0" max="4096" step="1" value={params.dropBytes} onChange={event => setParams({ ...params, dropBytes: event.target.value })} />
                </label>
              )}
              {operation.params.includes('shift') && (
                <label>
                  <span>{language === 'zh' ? 'Caesar 位移' : 'Caesar shift'}</span>
                  <input type="number" value={params.shift} onChange={event => setParams({ ...params, shift: event.target.value })} />
                </label>
              )}
              {operation.params.includes('separator') && (
                <label>
                  <span>{language === 'zh' ? '分隔符' : 'Separator'}</span>
                  <select value={params.separator} onChange={event => setParams({ ...params, separator: event.target.value })}>
                    <option value="space">{language === 'zh' ? '空格' : 'Space'}</option>
                    <option value="comma">{language === 'zh' ? '逗号' : 'Comma'}</option>
                    <option value="newline">{language === 'zh' ? '换行' : 'New line'}</option>
                  </select>
                </label>
              )}
              {operation.params.includes('affineA') && (
                <label>
                  <span>{language === 'zh' ? 'Affine a' : 'Affine a'}</span>
                  <input type="number" value={params.affineA} onChange={event => setParams({ ...params, affineA: event.target.value })} />
                </label>
              )}
              {operation.params.includes('affineB') && (
                <label>
                  <span>{language === 'zh' ? 'Affine b' : 'Affine b'}</span>
                  <input type="number" value={params.affineB} onChange={event => setParams({ ...params, affineB: event.target.value })} />
                </label>
              )}
              {operation.params.includes('rails') && (
                <label>
                  <span>{language === 'zh' ? '轨道数' : 'Rails'}</span>
                  <input type="number" min="2" max="32" value={params.rails} onChange={event => setParams({ ...params, rails: event.target.value })} />
                </label>
              )}
              {operation.params.includes('knownPlaintext') && (
                <label>
                  <span>{language === 'zh' ? '已知明文' : 'Known plaintext'}</span>
                  <input value={params.knownPlaintext} onChange={event => setParams({ ...params, knownPlaintext: event.target.value })} placeholder="flag{ / PNG header / PK" />
                </label>
              )}
              {operation.params.includes('mimeType') && (
                <label>
                  <span>MIME</span>
                  <input value={params.mimeType} onChange={event => setParams({ ...params, mimeType: event.target.value })} />
                </label>
              )}
              {operation.params.includes('blockLabel') && (
                <label>
                  <span>{language === 'zh' ? 'PEM 块类型' : 'PEM block label'}</span>
                  <input value={params.blockLabel} onChange={event => setParams({ ...params, blockLabel: event.target.value })} placeholder="PUBLIC KEY / CERTIFICATE / PRIVATE KEY" />
                </label>
              )}
            </div>
          ) : null}

          {detections.length ? (
            <div className="detect-strip" aria-label={language === 'zh' ? '自动识别结果' : 'Detected formats'}>
              <span>{language === 'zh' ? '识别' : 'Detected'}</span>
              {detections.map(detection => (
                <button key={`${detection.id}-${detection.label}`} type="button" onClick={() => applyDetection(detection.id)}>
                  {detection.label}
                </button>
              ))}
            </div>
          ) : null}

          <div className="encoding-content">
            <div className="encoding-panel">
              <div className="panel-header">
                <label>{language === 'zh' ? '输入' : 'Input'}</label>
                <button className="clear-btn" onClick={clearAll} type="button">{language === 'zh' ? '清空' : 'Clear'}</button>
              </div>
              <textarea
                value={input}
                onChange={event => setInput(event.target.value)}
                placeholder={language === 'zh' ? '粘贴要处理的文本、Token、编码内容或 JSON...' : 'Paste text, tokens, encoded content, or JSON...'}
                spellCheck={false}
              />
            </div>

            <div className="encoding-panel">
              <div className="panel-header">
                <label>{language === 'zh' ? '输出' : 'Output'}</label>
                <div className="panel-actions">
                  <button type="button" className="copy-btn" onClick={() => { setInput(output); setOutput(''); setError(''); }} disabled={!output}>
                    {language === 'zh' ? '继续处理' : 'Use as input'}
                  </button>
                  <button type="button" className={`copy-btn ${copied ? 'copied' : ''}`} onClick={copyToClipboard} disabled={!output && !error}>
                    {copied ? (language === 'zh' ? '已复制' : 'Copied') : (language === 'zh' ? '复制' : 'Copy')}
                  </button>
                </div>
              </div>
              <textarea
                value={error || output}
                readOnly
                className={error ? 'error' : ''}
                placeholder={running ? (language === 'zh' ? '处理中...' : 'Processing...') : (language === 'zh' ? '转换结果会显示在这里...' : 'The result will appear here...')}
                spellCheck={false}
              />
            </div>
          </div>
        </section>
      </div>

      <style>{`
        .encoding-tools {
          width: min(100%, 1180px);
          min-width: 0;
          margin: 0 auto;
          padding: 20px;
          display: grid;
          gap: 16px;
        }

        .encoding-header {
          display: grid;
          gap: 6px;
        }

        .encoding-header h2 {
          margin: 0;
          font-size: 22px;
          line-height: 1.25;
          font-weight: 760;
          color: var(--text-primary);
        }

        .encoding-header p {
          margin: 0;
          max-width: 820px;
          font-size: 13px;
          line-height: 1.55;
          color: var(--text-muted);
        }

        .encoding-workbench {
          min-width: 0;
          display: grid;
          grid-template-columns: 230px minmax(0, 1fr);
          gap: 14px;
          align-items: start;
        }

        .encoding-category-panel,
        .encoding-main-panel {
          min-width: 0;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-card);
        }

        .encoding-category-panel {
          padding: 8px;
          position: sticky;
          top: 0;
        }

        .category-select {
          display: none;
          width: 100%;
        }

        .category-list {
          display: grid;
          gap: 4px;
        }

        .category-row {
          width: 100%;
          min-width: 0;
          border: 1px solid transparent;
          border-radius: 6px;
          background: transparent;
          color: var(--text-secondary);
          padding: 10px;
          display: grid;
          gap: 3px;
          text-align: left;
          transition: all var(--transition-fast);
        }

        .category-row:hover {
          background: var(--bg-hover);
          color: var(--text-primary);
        }

        .category-row.active {
          border-color: rgba(0, 240, 255, 0.45);
          background: rgba(0, 240, 255, 0.1);
          color: var(--neon-cyan);
        }

        .category-row span {
          min-width: 0;
          overflow-wrap: anywhere;
          font-size: 13px;
          font-weight: 700;
          line-height: 1.25;
        }

        .category-row small {
          min-width: 0;
          overflow-wrap: anywhere;
          color: var(--text-muted);
          font-size: 11px;
          line-height: 1.35;
        }

        .encoding-main-panel {
          padding: 14px;
          display: grid;
          gap: 12px;
        }

        .codec-toolbar {
          min-width: 0;
          display: grid;
          grid-template-columns: minmax(220px, 1fr) auto;
          gap: 12px;
          align-items: end;
        }

        .operation-select-field,
        .codec-options label {
          min-width: 0;
          display: grid;
          gap: 6px;
        }

        .operation-select-field span,
        .codec-options span {
          color: var(--text-muted);
          font-size: 12px;
          font-weight: 700;
        }

        .operation-select-field select,
        .codec-options select,
        .codec-options input,
        .codec-options textarea,
        .category-select {
          min-width: 0;
          width: 100%;
          min-height: 38px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 8px 10px;
          outline: none;
        }

        .operation-select-field select:focus,
        .codec-options select:focus,
        .codec-options input:focus,
        .codec-options textarea:focus,
        .category-select:focus {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
        }

        .codec-options textarea {
          min-height: 120px;
          resize: vertical;
          font-family: 'JetBrains Mono', 'Fira Code', monospace;
          line-height: 1.45;
        }

        .codec-options .wide-option {
          grid-column: 1 / -1;
        }

        .mode-actions {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          justify-content: flex-end;
          gap: 7px;
        }

        .mode-btn,
        .options-toggle,
        .detect-strip button,
        .clear-btn,
        .copy-btn {
          min-height: 36px;
          min-width: 0;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-secondary);
          padding: 8px 11px;
          font-size: 12px;
          font-weight: 700;
          white-space: nowrap;
          transition: all var(--transition-fast);
        }

        .mode-btn:hover:not(:disabled),
        .options-toggle:hover,
        .detect-strip button:hover,
        .clear-btn:hover,
        .copy-btn:hover:not(:disabled) {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .mode-btn.primary {
          border-color: var(--neon-cyan);
          background: rgba(0, 240, 255, 0.12);
          color: var(--neon-cyan);
        }

        .mode-btn.subtle {
          color: var(--text-muted);
        }

        .mode-btn:disabled,
        .copy-btn:disabled {
          opacity: 0.45;
          cursor: not-allowed;
        }

        .operation-summary {
          min-width: 0;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 8px;
          background: rgba(255, 255, 255, 0.025);
          padding: 11px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
        }

        .operation-summary div {
          min-width: 0;
          display: grid;
          gap: 4px;
        }

        .operation-summary strong {
          min-width: 0;
          overflow-wrap: anywhere;
          color: var(--text-primary);
          font-size: 13px;
        }

        .operation-summary span {
          min-width: 0;
          overflow-wrap: anywhere;
          color: var(--text-muted);
          font-size: 12px;
          line-height: 1.5;
        }

        .codec-options {
          display: none;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: rgba(0, 0, 0, 0.12);
          padding: 12px;
        }

        .codec-options.open {
          display: grid;
        }

        .detect-strip {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 7px;
          color: var(--text-muted);
          font-size: 12px;
        }

        .detect-strip span {
          font-weight: 700;
        }

        .detect-strip button {
          min-height: 30px;
          padding: 5px 9px;
          background: rgba(255, 255, 255, 0.035);
        }

        .encoding-content {
          min-width: 0;
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 12px;
          align-items: stretch;
        }

        .encoding-panel {
          min-width: 0;
          display: grid;
          grid-template-rows: auto minmax(220px, 1fr);
          gap: 8px;
        }

        .panel-header {
          min-width: 0;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 8px;
        }

        .panel-header label {
          color: var(--text-muted);
          font-size: 12px;
          font-weight: 800;
        }

        .panel-actions {
          min-width: 0;
          display: flex;
          flex-wrap: wrap;
          justify-content: flex-end;
          gap: 6px;
        }

        .copy-btn.copied {
          border-color: var(--neon-green);
          background: rgba(0, 255, 136, 0.1);
          color: var(--neon-green);
        }

        .encoding-panel textarea {
          min-width: 0;
          width: 100%;
          min-height: 220px;
          resize: vertical;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-secondary);
          color: var(--text-primary);
          padding: 13px;
          outline: none;
          font-family: var(--font-mono);
          font-size: 13px;
          line-height: 1.6;
          white-space: pre-wrap;
          overflow-wrap: anywhere;
          writing-mode: horizontal-tb;
        }

        .encoding-panel textarea:focus {
          border-color: var(--neon-cyan);
          box-shadow: 0 0 0 3px rgba(0, 240, 255, 0.12);
        }

        .encoding-panel textarea.error {
          border-color: var(--neon-red);
          color: var(--neon-red);
        }

        .encoding-panel textarea::placeholder {
          color: var(--text-muted);
        }

        @media (max-width: 900px) {
          .encoding-tools {
            padding: 14px;
          }

          .encoding-workbench {
            grid-template-columns: 1fr;
          }

          .encoding-category-panel {
            position: static;
          }

          .category-select {
            display: block;
          }

          .category-list {
            display: none;
          }

          .codec-toolbar {
            grid-template-columns: 1fr;
          }

          .mode-actions {
            justify-content: stretch;
          }

          .mode-btn {
            flex: 1 1 130px;
          }

          .codec-options {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
        }

        @media (max-width: 680px) {
          .encoding-tools {
            padding: 10px;
          }

          .encoding-header h2 {
            font-size: 18px;
          }

          .encoding-main-panel {
            padding: 10px;
          }

          .operation-select-field select,
          .codec-options select,
          .codec-options input,
          .category-select,
          .mode-btn,
          .options-toggle,
          .detect-strip button,
          .clear-btn,
          .copy-btn {
            min-height: 44px;
          }

          .operation-summary {
            align-items: stretch;
            flex-direction: column;
          }

          .options-toggle {
            width: 100%;
          }

          .codec-options,
          .encoding-content {
            grid-template-columns: 1fr;
          }

          .encoding-panel {
            grid-template-rows: auto minmax(170px, 1fr);
          }

          .encoding-panel textarea {
            min-height: 170px;
            font-size: 12px;
          }
        }

        @media (max-width: 420px) {
          .mode-actions,
          .panel-actions {
            display: grid;
            grid-template-columns: 1fr;
            width: 100%;
          }

          .panel-header {
            align-items: stretch;
            flex-direction: column;
          }

          .mode-btn,
          .clear-btn,
          .copy-btn {
            width: 100%;
            min-height: 44px;
            white-space: normal;
          }

          .detect-strip {
            display: grid;
            grid-template-columns: 1fr 1fr;
          }

          .detect-strip span {
            grid-column: 1 / -1;
          }
        }
      `}</style>
    </div>
  );
}

async function transform(operationId: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): Promise<string> {
  switch (operationId) {
    case 'smart-decode':
      return smartDecode(input);
    case 'url-component':
      return direction === 'encode' ? encodeURIComponent(input) : decodeURIComponent(input);
    case 'url-form':
      return direction === 'encode' ? encodeURIComponent(input).replace(/%20/g, '+') : decodeURIComponent(input.replace(/\+/g, ' '));
    case 'html-entity':
      return direction === 'encode' ? htmlEncode(input, params.variant) : htmlDecode(input);
    case 'xml-entity':
      return direction === 'encode' ? xmlEncode(input, params.variant) : xmlDecode(input);
    case 'unicode-escape':
      return direction === 'encode' ? unicodeEncode(input, params.variant) : unicodeDecode(input);
    case 'utf7':
      return direction === 'encode' ? utf7Encode(input) : utf7Decode(input);
    case 'js-string':
      return direction === 'encode' ? JSON.stringify(input).slice(1, -1) : jsStringDecode(input);
    case 'c-string':
      return direction === 'encode' ? cStringEncode(input) : cStringDecode(input);
    case 'json-string':
      return direction === 'encode' ? JSON.stringify(input) : jsonStringDecode(input);
    case 'unix-time':
      return direction === 'encode' ? encodeUnixTime(input) : decodeUnixTime(input);
    case 'base64':
      return direction === 'encode' ? textToBase64(input) : base64ToText(input);
    case 'base64url':
      return direction === 'encode' ? toBase64Url(input) : fromBase64Url(input);
    case 'base32':
      return direction === 'encode' ? encodeBase32(input, params.variant) : decodeBase32(input, params.variant);
    case 'base45':
      return direction === 'encode' ? encodeBase45(input) : decodeBase45(input);
    case 'base58':
      return direction === 'encode' ? encodeBase58(input) : decodeBase58(input);
    case 'base58check':
      return direction === 'encode' ? encodeBase58Check(input, params.versionHex) : decodeBase58Check(input);
    case 'bech32':
      return direction === 'encode' ? encodeBech32(input, params.hrp, params.variant) : decodeBech32(input);
    case 'base62':
      return direction === 'encode' ? encodeBase62(input) : decodeBase62(input);
    case 'base36':
      return direction === 'encode' ? encodeBase36(input) : decodeBase36(input);
    case 'base91':
      return direction === 'encode' ? encodeBase91(input) : decodeBase91(input);
    case 'ascii85':
      if (params.variant === 'hex') return direction === 'encode' ? encodeZ85(input) : decodeZ85(input);
      return direction === 'encode' ? encodeAscii85(input) : decodeAscii85(input);
    case 'uuencode':
      return direction === 'encode' ? encodeUuencode(input, params.blockLabel) : decodeUuencode(input);
    case 'hex':
      if (direction === 'decode') return utf8Decoder.decode(hexToBytes(input));
      if (params.variant === 'decimal') return Array.from(utf8Encoder.encode(input)).map(byte => `0x${byte.toString(16).padStart(2, '0')}`).join(' ');
      if (params.variant === 'hex') return Array.from(utf8Encoder.encode(input)).map(byte => `\\x${byte.toString(16).padStart(2, '0')}`).join('');
      return bytesToHex(utf8Encoder.encode(input));
    case 'binary':
      return direction === 'encode' ? binaryEncode(input, params.separator) : binaryDecode(input);
    case 'octal-codes':
      return direction === 'encode' ? octalEncode(input, params.separator) : octalDecode(input);
    case 'ascii-codes':
      return direction === 'encode' ? asciiEncode(input, params.separator) : asciiDecode(input);
    case 'a1z26':
      return direction === 'encode' ? a1z26Encode(input, params.separator) : a1z26Decode(input);
    case 'morse':
      return direction === 'encode' ? morseEncode(input) : morseDecode(input);
    case 'nato-phonetic':
      return direction === 'encode' ? natoEncode(input, params.separator) : natoDecode(input);
    case 'baudot':
      return direction === 'encode' ? baudotEncode(input, params.separator) : baudotDecode(input);
    case 'bcd':
      return direction === 'encode' ? bcdEncode(input, params.separator) : bcdDecode(input);
    case 'gray-code':
      return direction === 'encode' ? grayEncode(input, params.separator) : grayDecode(input, params.separator);
    case 'dna-code':
      return direction === 'encode' ? dnaEncode(input, params.variant, params.separator) : dnaDecode(input, params.variant);
    case 'gsm7':
      return direction === 'encode' ? gsm7Encode(input) : gsm7Decode(input);
    case 'sms-pdu':
      return parseSmsPdu(input);
    case 'cbor':
      return parseCbor(input);
    case 'messagepack':
      return parseMessagePack(input);
    case 'protobuf-raw':
      return parseProtobufRaw(input);
    case 'bson':
      return parseBson(input);
    case 'yenc':
      return direction === 'encode' ? yEncEncode(input) : yEncDecode(input);
    case 'bubble-babble':
      return direction === 'encode' ? bubbleBabbleEncode(input) : bubbleBabbleDecode(input);
    case 'quoted-printable':
      return direction === 'encode' ? quotedPrintableEncode(input) : quotedPrintableDecode(input);
    case 'utf16-bytes':
      return direction === 'encode' ? encodeUtf16Bytes(input, params.variant, params.separator) : decodeUtf16Bytes(input, params.variant);
    case 'reverse-text':
      return Array.from(input).reverse().join('');
    case 'keyboard-shift':
      return keyboardShift(input, params.variant, direction === 'decode');
    case 'zero-width':
      return direction === 'encode' ? zeroWidthEncode(input) : zeroWidthDecode(input);
    case 'hash':
      return digest(input, params.hashAlgorithm);
    case 'hash-identify':
      return identifyHash(input);
    case 'hmac':
      return hmac(input, params.secret, params.hashAlgorithm);
    case 'bip39-seed':
      return bip39Seed(input, params.secret);
    case 'aes-gcm':
      return aesGcmTransform(direction, input, params);
    case 'aes-cbc':
      return direction === 'encode' ? aesEncryptCbc(input, params.secret, params.iterations) : aesDecryptCbc(input, params.secret);
    case 'aes-ctr':
      return direction === 'encode' ? aesEncryptCtr(input, params.secret, params.iterations) : aesDecryptCtr(input, params.secret);
    case 'openssl-aes-256-cbc':
      return openSslAes256CbcTransform(direction, input, params.secret);
    case 'aes-cbc-raw':
    case 'aes-ctr-raw':
    case 'aes-ecb':
    case 'aes-cfb':
      return aesRawBlockTransform(operationId, direction, input, params);
    case 'aes-ofb':
      return aesOfbTransform(direction, input, params);
    case 'aes-kw':
    case 'aes-kwp':
      return aesKeyWrapTransform(operationId, direction, input, params);
    case 'aes-cmac':
      return aesCmacTransform(input, params);
    case 'des':
    case 'triple-des':
    case 'blowfish':
    case 'rabbit':
      return cryptoJsCipherTransform(operationId, direction, input, params);
    case 'chacha20-orig':
    case 'chacha20':
    case 'xchacha20':
    case 'salsa20':
    case 'xsalsa20':
      return nobleStreamTransform(operationId, direction, input, params);
    case 'chacha20-poly1305':
    case 'xchacha20-poly1305':
    case 'xsalsa20-poly1305':
    case 'aes-gcm-siv':
    case 'aes-siv':
      return nobleAeadTransform(operationId, direction, input, params);
    case 'sm4':
      return sm4Transform(direction, input, params);
    case 'rc4':
      return rc4Transform(input, params.secret, direction === 'decode');
    case 'rc4-drop':
      return rc4Transform(input, params.secret, direction === 'decode', Math.max(0, Number.parseInt(params.dropBytes, 10) || 0));
    case 'tea':
      return teaTransform(input, params.secret, direction === 'decode');
    case 'xtea':
      return teaTransform(input, params.secret, direction === 'decode', true);
    case 'xxtea':
      return xxteaTransform(input, params.secret, direction === 'decode');
    case 'vigenere':
      return vigenereTransform(input, params.secret, direction === 'decode');
    case 'beaufort':
      return beaufortTransform(input, params.secret);
    case 'autokey':
      return autokeyTransform(input, params.secret, direction === 'decode');
    case 'atbash':
      return atbashTransform(input);
    case 'bacon':
      return direction === 'encode' ? baconEncode(input, params.separator) : baconDecode(input);
    case 'polybius':
      return direction === 'encode' ? polybiusEncode(input, params.separator) : polybiusDecode(input);
    case 'tap-code':
      return direction === 'encode' ? tapCodeEncode(input, params.separator) : tapCodeDecode(input);
    case 'playfair':
      return playfairTransform(input, params.secret, direction === 'decode');
    case 'hill2':
      return hillTransform(input, params.secret, direction === 'decode');
    case 'substitution':
      return substitutionTransform(input, params.secret, direction === 'decode');
    case 'affine':
      return affineTransform(input, params.affineA, params.affineB, direction === 'decode');
    case 'rail-fence':
      return direction === 'encode' ? railFenceEncode(input, params.rails) : railFenceDecode(input, params.rails);
    case 'scytale':
      return direction === 'encode' ? scytaleEncode(input, params.rails) : scytaleDecode(input, params.rails);
    case 'columnar':
      return direction === 'encode' ? columnarEncode(input, params.secret) : columnarDecode(input, params.secret);
    case 'porta':
      return portaTransform(input, params.secret);
    case 'gronsfeld':
      return gronsfeldTransform(input, params.secret, direction === 'decode');
    case 'bifid':
      return bifidTransform(input, params.secret, params.period, direction === 'decode');
    case 'trifid':
      return trifidTransform(input, params.secret, params.period, direction === 'decode');
    case 'four-square':
      return fourSquareTransform(input, params.secret, params.keyword2, direction === 'decode');
    case 'nihilist':
      return nihilistTransform(input, params.secret, params.separator, direction === 'decode');
    case 'adfgx':
      return adfgxTransform(input, params.secret, params.keyword2, direction === 'decode', 'ADFGX');
    case 'adfgvx':
      return adfgxTransform(input, params.secret, params.keyword2, direction === 'decode', 'ADFGVX');
    case 'xor':
      return direction === 'encode'
        ? bytesToHex(xorTransform(utf8Encoder.encode(input), params.secret))
        : utf8Decoder.decode(xorTransform(hexToBytes(input), params.secret));
    case 'xor-bruteforce':
      return singleByteXorBruteforce(input);
    case 'xor-known-plaintext':
      return xorKnownPlaintext(input, params.knownPlaintext);
    case 'magic-xor-helper':
      return magicXorHelper(input, params.knownPlaintext);
    case 'rot':
      if (params.variant === 'hex') return rot47(input);
      return caesar(input, direction === 'encode' ? Number(params.shift || 13) : -Number(params.shift || 13));
    case 'rot-bruteforce':
      return rotBruteforce(input);
    case 'rot8000':
      return rot8000(input);
    case 'enigma':
      return enigmaTransform(input, params.secret);
    case 'rsa-raw':
      return rsaRawTransform(direction, input);
    case 'rabin-raw':
      return rabinRawTransform(direction, input);
    case 'rsa-helper':
      return rsaHelper(input);
    case 'signature-nonce-helper':
      return signatureNonceReuseHelper(input);
    case 'discrete-log-helper':
      return discreteLogHelper(input);
    case 'mt19937-helper':
      return mt19937Helper(input);
    case 'lcg-helper':
      return lcgHelper(input, params.secret);
    case 'lfsr-helper':
      return lfsrHelper(input);
    case 'hash-length-extension-helper':
      return hashLengthExtensionHelper(input, params.hashAlgorithm, params.secret, params.knownPlaintext);
    case 'crypto-attack-helper':
      return cryptoAttackHelper(input);
    case 'frequency-analysis':
      return frequencyAnalysis(input);
    case 'brainfuck':
      return direction === 'encode' ? encodeBrainfuckText(input) : runBrainfuck(input, params.secret, params.iterations);
    case 'ook':
      return direction === 'encode' ? brainfuckToOokText(input) : ookToBrainfuckText(input);
    case 'jsfuck-helper':
      return jsfuckInspector(input);
    case 'jwt':
      return decodeJwt(input);
    case 'jwt-hmac':
      return jwtHmacTransform(direction, input, params);
    case 'jwt-public':
      return jwtPublicTransform(input, params);
    case 'fernet':
      return direction === 'encode' ? encodeFernet(input, params.secret) : decodeFernet(input, params.secret);
    case 'hotp':
      return generateHotp(params.secret || input, params.hashAlgorithm, params.digits, params.counter);
    case 'totp':
      return generateTotp(params.secret || input, params.hashAlgorithm, params.digits, params.timeStep, params.otpTimestamp);
    case 'otpauth-uri':
      return direction === 'encode' ? encodeOtpAuthUri(input, params) : decodeOtpAuthUriCompat(input);
    case 'querystring':
      return direction === 'encode' ? encodeQuery(input) : decodeQuery(input);
    case 'basic-auth':
      return direction === 'encode'
        ? `Basic ${textToBase64(input)}`
        : base64ToText(input.replace(/^Basic\s+/i, ''));
    case 'punycode':
      return direction === 'encode' ? encodePunycode(input) : decodePunycode(input);
    case 'pem-block':
      return direction === 'encode' ? encodePemBlock(input, params.blockLabel) : decodePemBlock(input);
    case 'asn1-der':
      return parseAsn1Der(input);
    case 'jwk-jwe':
      return parseJwkJwe(input);
    case 'ssh-public-key':
      return parseSshPublicKey(input);
    case 'gzip':
      return direction === 'encode' ? compressText(input, 'gzip') : decompressText(input, 'gzip');
    case 'deflate':
      return direction === 'encode' ? compressText(input, 'deflate') : decompressText(input, 'deflate');
    case 'data-url': {
      if (direction === 'encode') return `data:${params.mimeType || 'text/plain;charset=utf-8'};base64,${textToBase64(input)}`;
      const match = input.match(/^data:([^;,]+(?:;[^,]+)*),(.+)$/s);
      if (!match) throw new Error('Data URL 格式不正');
      const isBase64 = /;base64/i.test(match[1]);
      return isBase64 ? base64ToText(match[2]) : decodeURIComponent(match[2]);
    }
    default:
      return input;
  }
}

export default EncodingTools;
