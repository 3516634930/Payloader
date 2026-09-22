// CODEC-IMPORTS
import type { OperationId } from './types';
// CODEC-IMPORTS-END
export const otpOperationIds = new Set<OperationId>(['hotp', 'totp', 'otpauth-uri']);
export const otpHashAlgorithms = new Set(['sha1', 'sha256', 'sha512']);
export const jwtHmacHashAlgorithms = new Set(['sha256', 'sha384', 'sha512']);
export const isOtpOperation = (operationId: OperationId) => otpOperationIds.has(operationId);
export const cryptoJsCipherOperationIds = new Set<OperationId>(['des', 'triple-des', 'blowfish', 'rabbit']);
export const cryptoJsBlockCipherOperationIds = new Set<OperationId>(['des', 'triple-des', 'blowfish']);
export const isCryptoJsCipherOperation = (operationId: OperationId) => cryptoJsCipherOperationIds.has(operationId);
export const nobleStreamCipherOperationIds = new Set<OperationId>(['chacha20-orig', 'chacha20', 'xchacha20', 'salsa20', 'xsalsa20']);
export const isNobleStreamCipherOperation = (operationId: OperationId) => nobleStreamCipherOperationIds.has(operationId);
export const nobleAeadOperationIds = new Set<OperationId>(['aes-gcm-siv', 'aes-siv', 'chacha20-poly1305', 'xchacha20-poly1305', 'xsalsa20-poly1305']);
export const isNobleAeadOperation = (operationId: OperationId) => nobleAeadOperationIds.has(operationId);
export const isNobleNonceOperation = (operationId: OperationId) => isNobleStreamCipherOperation(operationId) || isNobleAeadOperation(operationId);
export const nobleAesOperationIds = new Set<OperationId>(['aes-cbc-raw', 'aes-ctr-raw', 'aes-ofb', 'aes-ecb', 'aes-cfb', 'aes-kw', 'aes-kwp', 'aes-cmac']);
export const isNobleAesOperation = (operationId: OperationId) => nobleAesOperationIds.has(operationId);

export const morseMap: Record<string, string> = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---',
  K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-',
  U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
  0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-',
  '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.',
  '$': '...-..-', '@': '.--.-.',
};

export const reverseMorseMap = Object.fromEntries(Object.entries(morseMap).map(([key, value]) => [value, key]));
export const utf8Encoder = new TextEncoder();
export const utf8Decoder = new TextDecoder();
export const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const base32HexAlphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
export const crockfordBase32Alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const base45Alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
export const base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export const base62Alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
export const base91Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
export const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const polybiusAlphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
export const tapCodeAlphabet = 'ABCDEFGHIJLMNOPQRSTUVWXYZ';
export const keyboardRows = ['`1234567890-=', 'qwertyuiop[]\\', "asdfghjkl;'", 'zxcvbnm,./'];
export const natoWords: Record<string, string> = {
  A: 'Alpha', B: 'Bravo', C: 'Charlie', D: 'Delta', E: 'Echo', F: 'Foxtrot', G: 'Golf', H: 'Hotel', I: 'India',
  J: 'Juliett', K: 'Kilo', L: 'Lima', M: 'Mike', N: 'November', O: 'Oscar', P: 'Papa', Q: 'Quebec', R: 'Romeo',
  S: 'Sierra', T: 'Tango', U: 'Uniform', V: 'Victor', W: 'Whiskey', X: 'Xray', Y: 'Yankee', Z: 'Zulu',
  0: 'Zero', 1: 'One', 2: 'Two', 3: 'Three', 4: 'Four', 5: 'Five', 6: 'Six', 7: 'Seven', 8: 'Eight', 9: 'Nine',
};
export const reverseNatoWords = Object.fromEntries(Object.entries(natoWords).flatMap(([key, value]) => [[value.toLowerCase(), key], [value.replace('-', '').toLowerCase(), key]]));
reverseNatoWords.alfa = 'A';
reverseNatoWords['x-ray'] = 'X';
export const baudotLetters: Record<string, string> = {
  A: '00011', B: '11001', C: '01110', D: '01001', E: '00001', F: '01101', G: '11010', H: '10100', I: '00110',
  J: '01011', K: '01111', L: '10010', M: '11100', N: '01100', O: '11000', P: '10110', Q: '10111', R: '01010',
  S: '00101', T: '10000', U: '00111', V: '11110', W: '10011', X: '11101', Y: '10101', Z: '10001',
  '\n': '00010', '\r': '01000', ' ': '00100',
};
export const baudotFigures: Record<string, string> = {
  '-': '00011', '?': '11001', ':': '01110', '$': '01001', '3': '00001', '!': '01101', '&': '11010', '#': '10100',
  '8': '00110', "'": '01011', '(': '01111', ')': '10010', '.': '11100', ',': '01100', '9': '11000', '0': '10110',
  '1': '10111', '4': '01010', '\u0007': '00101', '5': '10000', '7': '00111', ';': '11110', '2': '10011', '/': '11101',
  '6': '10101', '"': '10001', '\n': '00010', '\r': '01000', ' ': '00100',
};
export const baudotLettersShift = '11111';
export const baudotFiguresShift = '11011';
export const reverseBaudotLetters = Object.fromEntries(Object.entries(baudotLetters).map(([key, value]) => [value, key]));
export const reverseBaudotFigures = Object.fromEntries(Object.entries(baudotFigures).map(([key, value]) => [value, key]));
export const dnaMaps: Record<string, Record<string, string>> = {
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
export const reverseDnaMaps = Object.fromEntries(Object.entries(dnaMaps).map(([key, value]) => [key, Object.fromEntries(Object.entries(value).map(([bits, base]) => [base, bits]))])) as Record<string, Record<string, string>>;
export const zeroWidthZero = '\u200b';
export const zeroWidthOne = '\u200c';
export const bubbleBabbleVowels = 'aeiouy';
export const bubbleBabbleConsonants = 'bcdfghklmnprstvzx';
export const utf7DirectChars = new Set(Array.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'(),-./:? \t\r\n"));
export const gsm7DefaultAlphabet = [
  '@', '£', '$', '¥', 'è', 'é', 'ù', 'ì', 'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å',
  'Δ', '_', 'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ', 'Σ', 'Θ', 'Ξ', '\u001b', 'Æ', 'æ', 'ß', 'É',
  ' ', '!', '"', '#', '¤', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
  '¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§',
  '¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
  'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à',
];
export const gsm7ReverseAlphabet = new Map(gsm7DefaultAlphabet.map((char, index) => [char, index]));
export const gsm7ExtensionAlphabet: Record<string, number> = {
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
export const reverseGsm7ExtensionAlphabet = Object.fromEntries(Object.entries(gsm7ExtensionAlphabet).map(([char, code]) => [code, char])) as Record<number, string>;
export const brainfuckToOok: Record<string, string> = {
  '>': 'Ook. Ook?',
  '<': 'Ook? Ook.',
  '+': 'Ook. Ook.',
  '-': 'Ook! Ook!',
  '.': 'Ook! Ook.',
  ',': 'Ook. Ook!',
  '[': 'Ook! Ook?',
  ']': 'Ook? Ook!',
};
export const ookToBrainfuck = Object.fromEntries(Object.entries(brainfuckToOok).map(([key, value]) => [value, key]));
export const crc32Table = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
export const crc16Table = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? (value >>> 1) ^ 0xa001 : value >>> 1;
  return value & 0xffff;
});
