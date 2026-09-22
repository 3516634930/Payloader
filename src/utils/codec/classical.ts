// CODEC-IMPORTS
import { modInverse, separatorValue } from './textEncodings';
import { alphabet, polybiusAlphabet, tapCodeAlphabet, utf8Decoder, utf8Encoder } from './alphabets';
import { bytesToHex, hexToBytes } from './bases';
// CODEC-IMPORTS-END
export const vigenereTransform = (value: string, secret: string, decode = false) => {
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

export const beaufortTransform = (value: string, secret: string) => {
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

export const autokeyTransform = (value: string, secret: string, decode = false) => {
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

export const keyedSquare = (secret: string, baseAlphabet?: string) => {
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

export const playfairPairs = (value: string, alphabet?: string) => {
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

export const playfairTransform = (value: string, secret: string, decode = false, customAlphabet?: string) => {
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

export const parseHillKey = (secret: string) => {
  const numbers = secret.match(/-?\d+/g)?.map(Number);
  if (numbers?.length === 4) return numbers;
  const letters = secret.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length >= 4) return Array.from(letters.slice(0, 4)).map(char => char.charCodeAt(0) - 65);
  throw new Error('Hill 2x2 需要 4 个数字或 4 个字母作为密钥');
};

export const hillTransform = (value: string, secret: string, decode = false) => {
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

export const substitutionTransform = (value: string, secret: string, decode = false) => {
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

export const baconEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const normalized = char === 'J' ? 'I' : char === 'V' ? 'U' : char;
    const index = 'ABCDEFGHIKLMNOPQRSTUWXYZ'.indexOf(normalized);
    if (index < 0) return char.trim() ? char : '/';
    return index.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B');
  })
  .join(separatorValue(separator));

export const baconDecode = (value: string) => {
  const source = value.toUpperCase().replace(/0/g, 'A').replace(/1/g, 'B').replace(/[^AB]/g, '');
  if (source.length < 5) throw new Error('Bacon 解码需要 A/B 或 0/1 五位分组');
  const chunks = source.match(/.{5}/g) || [];
  return chunks.map(chunk => {
    const index = Number.parseInt(chunk.replace(/A/g, '0').replace(/B/g, '1'), 2);
    return 'ABCDEFGHIKLMNOPQRSTUWXYZ'[index] || '?';
  }).join('');
};

export const polybiusEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const normalized = char === 'J' ? 'I' : char;
    const index = polybiusAlphabet.indexOf(normalized);
    if (index < 0) return char.trim() ? char : '/';
    return `${Math.floor(index / 5) + 1}${(index % 5) + 1}`;
  })
  .join(separatorValue(separator));

export const polybiusDecode = (value: string) => {
  const pairs = value.match(/[1-5][1-5]/g) || [];
  if (!pairs.length) throw new Error('Polybius 解码需要 11-55 范围内的坐标');
  return pairs.map(pair => {
    const row = Number(pair[0]) - 1;
    const column = Number(pair[1]) - 1;
    return polybiusAlphabet[row * 5 + column] || '?';
  }).join('');
};

export const tapCodeEncode = (value: string, separator: string) => Array.from(value.toUpperCase())
  .map(char => {
    const normalized = char === 'K' ? 'C' : char;
    const index = tapCodeAlphabet.indexOf(normalized);
    if (index < 0) return char.trim() ? char : '/';
    return `${'.'.repeat(Math.floor(index / 5) + 1)} ${'.'.repeat((index % 5) + 1)}`;
  })
  .join(separatorValue(separator) === '\n' ? '\n' : ' / ');

export const tapCodeDecode = (value: string) => {
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

export const railPattern = (length: number, rails: number) => {
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

export const railFenceEncode = (value: string, railValue: string) => {
  const rails = Number.parseInt(railValue, 10) || 3;
  const rows = Array.from({ length: rails }, () => '');
  railPattern(Array.from(value).length, rails).forEach((rail, index) => {
    rows[rail] += Array.from(value)[index];
  });
  return rows.join('');
};

export const railFenceDecode = (value: string, railValue: string) => {
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

export const columnOrder = (secret: string) => {
  const key = secret.trim();
  if (!key) throw new Error('Columnar 需要关键词');
  return Array.from(key)
    .map((char, index) => ({ char: char.toUpperCase(), index }))
    .sort((left, right) => left.char.localeCompare(right.char) || left.index - right.index)
    .map(item => item.index);
};

export const columnarEncode = (value: string, secret: string) => {
  const order = columnOrder(secret);
  const columns = Array.from({ length: order.length }, () => '');
  Array.from(value).forEach((char, index) => {
    columns[index % order.length] += char;
  });
  return order.map(index => columns[index]).join('');
};

export const columnarDecode = (value: string, secret: string) => {
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

export const scytaleEncode = (value: string, railValue: string) => {
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

export const scytaleDecode = (value: string, railValue: string) => {
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

export const portaTransform = (value: string, secret: string) => {
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

export const gronsfeldTransform = (value: string, secret: string, decode = false) => {
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

export const cleanClassicalLetters = (value: string) => value.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');

export const bifidTransform = (value: string, secret: string, periodValue: string, decode = false) => {
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

export const keyedTrifidAlphabet = (secret: string) => {
  const raw = `${secret}ABCDEFGHIJKLMNOPQRSTUVWXYZ.`.toUpperCase().replace(/[^A-Z.]/g, '');
  let output = '';
  for (const char of raw) {
    if (!output.includes(char)) output += char;
  }
  return output.padEnd(27, '.').slice(0, 27);
};

export const trifidTransform = (value: string, secret: string, periodValue: string, decode = false) => {
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

export const fourSquareTransform = (value: string, secret: string, keyword2: string, decode = false) => {
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

export const nihilistTransform = (value: string, secret: string, separator: string, decode = false) => {
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

export const keyedAlphabet = (secret: string, baseAlphabet: string) => {
  const raw = `${secret}${baseAlphabet}`.toUpperCase().replace(new RegExp(`[^${baseAlphabet.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}]`, 'g'), '');
  let output = '';
  for (const char of raw) {
    if (!output.includes(char)) output += char;
  }
  return output.padEnd(baseAlphabet.length, baseAlphabet).slice(0, baseAlphabet.length);
};

export const adfgxTransform = (value: string, secret: string, keyword2: string, decode = false, variant: 'ADFGX' | 'ADFGVX' = 'ADFGX') => {
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

export const xorTransform = (bytes: Uint8Array, secret: string) => {
  if (!secret) throw new Error('XOR 需要填写密钥');
  const key = utf8Encoder.encode(secret);
  return bytes.map((byte, index) => byte ^ key[index % key.length]);
};

export const printableScore = (bytes: Uint8Array) => {
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

export const singleByteXorBruteforce = (value: string) => {
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

export const xorKnownPlaintext = (value: string, knownPlaintext: string) => {
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

export const magicXorHelper = (value: string, knownPlaintext: string) => {
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

export const guessRepeatingKey = (key: Uint8Array) => {
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
