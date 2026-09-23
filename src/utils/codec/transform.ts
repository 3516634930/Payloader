// CODEC-IMPORTS
import { smartDecode } from './smartDecode';
import { a1z26Decode, a1z26Encode, affineTransform, asciiDecode, asciiEncode, atbashTransform, baudotDecode, baudotEncode, bcdDecode, bcdEncode, binaryDecode, binaryEncode, bubbleBabbleDecode, bubbleBabbleEncode, cStringDecode, cStringEncode, caesar, decodeUnixTime, decodeUtf16Bytes, dnaDecode, dnaEncode, encodeUnixTime, encodeUtf16Bytes, enigmaTransform, grayDecode, grayEncode, gsm7Decode, gsm7Encode, htmlDecode, htmlEncode, jsStringDecode, jsonStringDecode, keyboardShift, morseDecode, morseEncode, natoDecode, natoEncode, octalDecode, octalEncode, quotedPrintableDecode, quotedPrintableEncode, rot47, rot8000, rotBruteforce, unicodeDecode, unicodeEncode, utf7Decode, utf7Encode, xmlDecode, xmlEncode, yEncDecode, yEncEncode, zeroWidthDecode, zeroWidthEncode } from './textEncodings';
import { base64ToText, bytesToHex, decodeAscii85, decodeBase32, decodeBase32768, decodeBase36, decodeBase45, decodeBase58, decodeBase58Check, decodeBase62, decodeBase91, decodeBech32, decodeUuencode, decodeXxencode, decodeZ85, decodeZBase32, encodeAscii85, encodeBase32, encodeBase32768, encodeBase36, encodeBase45, encodeBase58, encodeBase58Check, encodeBase62, encodeBase91, encodeBech32, encodeUuencode, encodeXxencode, encodeZ85, encodeZBase32, fromBase64Url, hexToBytes, textToBase64, toBase64Url } from './bases';
import { utf8Decoder, utf8Encoder } from './alphabets';
import { decodePemBlock, decodePunycode, encodePemBlock, encodePunycode, parseAsn1Der, parseBson, parseCbor, parseJwkJwe, parseMessagePack, parseProtobufRaw, parseSmsPdu, parseSshPublicKey } from './binaryFormats';
import { aesCmacTransform, aesDecryptCbc, aesDecryptCtr, aesEncryptCbc, aesEncryptCtr, aesGcmTransform, aesKeyWrapTransform, aesOfbTransform, aesRawBlockTransform, bip39Seed, cryptoJsCipherTransform, digest, hmac, identifyHash, nobleAeadTransform, nobleStreamTransform, openSslAes256CbcTransform, rc4Transform, sm4Transform, teaTransform, xxteaTransform } from './crypto';
import { adfgxTransform, autokeyTransform, baconDecode, baconEncode, beaufortTransform, bifidTransform, columnarDecode, columnarEncode, fourSquareTransform, gronsfeldTransform, hillTransform, magicXorHelper, nihilistTransform, playfairTransform, polybiusDecode, polybiusEncode, portaTransform, railFenceDecode, railFenceEncode, scytaleDecode, scytaleEncode, singleByteXorBruteforce, substitutionTransform, tapCodeDecode, tapCodeEncode, trifidTransform, vigenereTransform, xorKnownPlaintext, xorTransform } from './classical';
import { rabinRawTransform, rsaHelper, rsaRawTransform } from './rsa';
import { cbcDemoTransform, coppersmithStereotypedSolve, parsePgpMessage, rsaOaepDecryptFromText, rsaOaepEncryptFromText } from './pgp';
import { discreteLogHelper, signatureNonceReuseHelper } from './prng';
import { mt19937Helper } from './smartDecode';
import { setSmartDecodeExecutor } from './smartBase';
import { brainfuckToOokText, cryptoAttackHelper, encodeBrainfuckText, frequencyAnalysis, hashLengthExtensionHelper, jsfuckInspector, lcgHelper, lfsrHelper, ookToBrainfuckText, runBrainfuck } from './attacks';
import { cloudShadowDecode, cloudShadowEncode, baijiaxingDecode, baijiaxingEncode, bearDecode, bearEncode, buddhaDecode, buddhaEncode, buddhaV2Decode, hexagramDecode, hexagramEncode, sexagesimalDecode, sexagesimalEncode } from './chineseCiphers';
import { albamTransform, carbonaroTransform, ciscoType7Decode, ciscoType7Encode, cetaceanDecode, cetaceanEncode, decabitDecode, decabitEncode, pizziniDecode, pizziniEncode } from './mapCiphers';
import { parityBaseTransform } from './parityBases';
import { parityCharTransform } from './parityCharCodes';
import { parityCnTransform } from './parityChinese';
import { parityKeyedTransform } from './parityKeyed';
import { parityNumTransform } from './parityNumeric';
import { decodeAaencode, decodeJjencode, decodeJsfuck, encodeAaencode, encodeJjencode, encodeJsfuck } from './sandbox';
import { decodeFernet, decodeJwt, decodeOtpAuthUriCompat, encodeFernet, encodeOtpAuthUri, generateHotp, generateTotp, jwtHmacTransform, jwtPublicTransform } from './tokens';
import { compressText, decodeQuery, decompressText, encodeQuery } from './smartBase';
import type { Direction, OperationId, ParamKey } from './types';
// CODEC-IMPORTS-END

// T6 解环：transform 作为解码执行器注入 smartBase——smartBase/smartHelpers 的按操作 id 解码
// 统一经该执行器（smart-decode 分支内部亦走 smartDecode），模块加载完成即生效。
setSmartDecodeExecutor((operationId, input, params) => transform(operationId as import('./types').OperationId, 'decode', input, params));
export async function transform(operationId: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): Promise<string> {

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
    case 'xxencode':
      return direction === 'encode' ? encodeXxencode(input) : decodeXxencode(input);
    case 'z-base-32':
      return direction === 'encode' ? encodeZBase32(input) : decodeZBase32(input);
    case 'base32768':
      return direction === 'encode' ? encodeBase32768(input) : decodeBase32768(input);
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
    case 'rsa-oaep':
      return direction === 'encode' ? rsaOaepEncryptFromText(input) : rsaOaepDecryptFromText(input);
    case 'coppersmith':
      return coppersmithStereotypedSolve(input, params.secret);
    case 'pgp-parse':
      return parsePgpMessage(input);
    case 'cbc-padding-demo':
      return cbcDemoTransform(input, params.secret);
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
    case 'buddha':
      return direction === 'encode' ? buddhaEncode(input) : buddhaDecode(input);
    case 'buddha-v2':
      return buddhaV2Decode(input);
    case 'bear-says':
      return direction === 'encode' ? bearEncode(input) : bearDecode(input);
    case 'baijiaxing':
      return direction === 'encode' ? baijiaxingEncode(input) : baijiaxingDecode(input);
    case 'hexagram':
      return direction === 'encode' ? hexagramEncode(input, params.variant) : hexagramDecode(input);
    case 'sexagesimal':
      return direction === 'encode' ? sexagesimalEncode(input) : sexagesimalDecode(input);
    case 'cloud-shadow':
      return direction === 'encode' ? cloudShadowEncode(input) : cloudShadowDecode(input);
    case 'pizzini':
      return direction === 'encode' ? pizziniEncode(input) : pizziniDecode(input);
    case 'cisco-type7':
      return direction === 'encode' ? ciscoType7Encode(input) : ciscoType7Decode(input);
    case 'decabit':
      return direction === 'encode' ? decabitEncode(input) : decabitDecode(input);
    case 'cetacean':
      return direction === 'encode' ? cetaceanEncode(input) : cetaceanDecode(input);
    case 'albam':
      return albamTransform(input, direction, params.variant);
    case 'carbonaro':
      return carbonaroTransform(input);
    case 'brainfuck':
      return direction === 'encode' ? encodeBrainfuckText(input) : runBrainfuck(input, params.secret, params.iterations);
    case 'ook':
      return direction === 'encode' ? brainfuckToOokText(input) : ookToBrainfuckText(input);
    case 'jsfuck':
      return direction === 'encode' ? encodeJsfuck(input) : decodeJsfuck(input);
    case 'aaencode':
      return direction === 'encode' ? encodeAaencode(input) : decodeAaencode(input);
    case 'jjencode':
      return direction === 'encode' ? encodeJjencode(input) : decodeJjencode(input);
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
    // ---- 批次 O：随波逐流操作对齐（五个 parity 模块分组委派）----
    case 'base92':
    case 'base100':
    case 'base85-rfc1924':
    case 'base62-ascii':
    case 'base64-multiline':
    case 'base64-case-mangled':
    case 'base64-to-hex':
    case 'base-custom':
    case 'base-multi-decode':
    case 'rot18':
    case 'rot-special':
      return parityBaseTransform(operationId, direction, input, params);
    case 'pigpen':
    case 'keyboard-keycode':
    case 'handycode':
    case 'chinesecode':
    case 'backslash-code':
    case 'slash-pipe':
    case 'tomtom':
    case 'clock-code':
    case 'goldbug':
    case 'kenny':
    case 'abaddon':
    case 'dvorak':
    case 'five-needle':
    case 'hodor':
    case 'duckspeak':
    case 'numberpad-lines':
    case 'quadoo':
    case 'bwt':
      return parityCharTransform(operationId, direction, input, params);
    case 'core-values':
    case 'hanzi-stroke':
    case 'yinyang-qi':
    case 'bagua-symbols':
    case 'telecode':
    case 'xiangyue':
    case 'makabaka':
    case 'yinyin':
    case 'shouyin':
    case 'periodic-table':
    case 'mars-text':
    case 'braille':
    case 'music-notes':
    case 'flower-code':
    case 'letter-code':
    case 'arrow-code':
    case 'hanzi-code':
    case 'ipa-code':
    case 'whitespace-code':
    case 'deadfish':
    case 'spoon':
    case 'manchester':
    case 'emoji-encoder':
      return parityCnTransform(operationId, direction, input, params);
    case 'otp':
    case 'multiplicative':
    case 'fractionated-morse':
    case 'fenham':
    case 'running-key':
    case 'bazeries':
    case 'kamasutra':
    case 'm209':
    case 'rc2':
    case 'rc6':
      return parityKeyedTransform(operationId, direction, input, params);
    case 'ieee754':
    case 'twos-complement':
    case 'ones-complement':
    case 'radix-xor':
    case 'bit-split':
    case 'hamming':
    case 'qwe-keyboard':
    case 'gcd':
    case 'prime-factor':
    case 'fibonacci-code':
    case 'pickle-parse':
    case 'ascii-control':
    case 'quwei':
      return parityNumTransform(operationId, direction, input, params);
    default:
      return input;
  }
}