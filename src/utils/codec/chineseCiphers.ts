import { bytesToBase64, base64ToBytes } from './bases';
import { utf8Decoder, utf8Encoder } from './alphabets';
import { compressText, decompressText } from './smartBase';
import { loadCryptoJs } from './crypto';

// 中文 CTF 编码家族（批次 K）：与佛论禅 V1/V2、熊曰、百家姓、六十四卦、天干地支。
// 映射表取自公开实现交叉验证（ToolsFx / EBCTFCodeBox / Abracadabra / keyfc），简繁混排为原版特性，不得整体转换。
// 全部纯文本进出，不执行任何输入内容。

const FO_KEY = 'XDXDtudou@KeyFansClub^_^Encode!!';
const FO_IV = 'Potato@Key@_@=_=';
const TUDOU = [...'滅苦婆娑耶陀跋多漫都殿悉夜爍帝吉利阿無南那怛喝羯勝摩伽謹波者穆僧室藝尼瑟地彌菩提蘇醯盧呼舍佛參沙伊隸麼遮闍度蒙孕薩夷迦他姪豆特逝朋輸楞栗寫數曳諦羅曰咒即密若般故不實真訶切一除能等是上明大神知三藐耨得依諸世槃涅竟究想夢倒顛離遠怖恐有礙心所以亦智道。集盡死老至'];
const BYTEMARK = [...'冥奢梵呐俱哆怯諳罰侄缽皤'];
const RSWW = [...('謹穆僧室藝瑟彌提蘇醯盧呼舍參沙伊隸麼遮闍度蒙孕薩夷他姪豆特逝輸楞栗寫數曳諦羅故實訶知三藐耨依槃涅竟究想夢倒顛遠怖恐礙以亦智盡老至' +
  '吼足幽王告须弥灯护金刚游戏宝胜通药师琉璃普功德山善住过去七未来贤' +
  '劫千五百万花亿定六方名号东月殿妙尊树根西皂焰北清数精进首下寂量诸' +
  '多释迦牟尼勒阿閦陀中央众生在界者行于及虚空慈忧各令安稳休息昼夜修' +
  '持心求诵此经能灭死消除毒害高开文殊利凉如念即说曰帝毘真陵乾梭哈敬' +
  '禮奉祖先孝雙親守重師愛兄弟信朋友睦宗族和鄉夫婦教孫時便廣積陰難濟' +
  '急恤孤憐貧創廟宇印造經捨藥施茶戒殺放橋路矜寡拔困粟惜福排解紛捐資')];
const XIONGYUE_DICT = [...('食性很雜既溫和會誘捕動物家住山洞沒有冬眠偶爾襲擊人類' +
  '呱哞嗄哈嘍啽唬咯呦嗷嗡哮嗥嗒嗚' +
  '吖吃嗅嘶噔咬噗嘿嚁噤囑非常喜歡' +
  '堅果魚肉蜂蜜註取象發達你覺出更' +
  '盜森氏我誒怎寶麼圖現破嚄告訴樣' +
  '呆萌笨拙意')];
const BJX_ASCII = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_+=/?#%&*';
const BJX_CHARS = [...'赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜戚谢邹喻福水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳唐罗薛伍余米贝姚孟顾尹江钟'];
const EIGHT_MAP = ('坤,剥,比,观,豫,晋,萃,否,谦,艮,蹇,渐,小过,旅,咸,遁,' +
  '师,蒙,坎,涣,解,未济,困,讼,升,蛊,井,巽,恒,鼎,大过,姤,' +
  '复,颐,屯,益,震,噬嗑,随,无妄,明夷,贲,既济,家人,丰,离,革,同人,' +
  '临,损,节,中孚,归妹,睽,兑,履,泰,大畜,需,小畜,大壮,大有,夬,乾').split(',');
const BASE64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const STEM = [...'甲乙丙丁戊己庚辛壬癸'];
const BRANCH = [...'子丑寅卯辰巳午未申酉戌亥'];
const GZ60 = Array.from({ length: 60 }, (_, index) => STEM[index % 10] + BRANCH[index % 12]);

const tudouIndex = new Map(TUDOU.map((char, index) => [char, index]));
const rswwIndex = new Map(RSWW.map((char, index) => [char, index]));
const bearIndex = new Map(XIONGYUE_DICT.map((char, index) => [char, index]));
const bjxByChar = new Map(BJX_CHARS.map((char, index) => [char, BJX_ASCII[index] ?? '']));
const bjxByAscii = new Map(BJX_ASCII.split('').map((char, index) => [char, BJX_CHARS[index] ?? '']));
const hexagramNames = new Map(EIGHT_MAP.map((name, index) => [name, BASE64_STD[index]]));
const hexagramDouble = new Set(EIGHT_MAP.filter(name => name.length >= 2).map(name => name));
const gzIndex = new Map(GZ60.map((pair, index) => [pair, index]));

// 智能识别谓词：与映射表同源，供 detectInput 判定无前缀流派（前缀流派用前缀正则直接命中）。
export const looksLikeBaijiaxing = (value: string): boolean => {
  const chars = [...value.replace(/\s+/g, '')];
  if (chars.length < 8) return false;
  const hits = chars.filter(char => bjxByChar.has(char)).length;
  return hits / chars.length >= 0.9;
};

export const looksLikeHexagramNames = (value: string): boolean => {
  const chars = [...value.replace(/\s+/g, '')];
  if (chars.length < 4) return false;
  let position = 0;
  while (position < chars.length) {
    const pair = chars.slice(position, position + 2).join('');
    if (hexagramDouble.has(pair)) {
      position += 2;
      continue;
    }
    if (hexagramNames.has(chars[position])) {
      position += 1;
      continue;
    }
    return false;
  }
  return true;
};

export const looksLikeHexagramSymbols = (value: string): boolean => {
  const chars = [...value.replace(/\s+/g, '')];
  if (chars.length < 8) return false;
  const hits = chars.filter(char => {
    const code = char.codePointAt(0) ?? 0;
    return code >= 0x4dc0 && code <= 0x4dff;
  }).length;
  return hits / chars.length >= 0.8;
};

export const looksLikeSexagesimal = (value: string): boolean => {
  const body = value.trim().replace(/\s+/g, '');
  if (body.length < 6 || body.length % 2 !== 0) return false;
  for (let position = 0; position < body.length; position += 2) {
    if (!gzIndex.has(body.slice(position, position + 2))) return false;
  }
  return true;
};

const stripPrefix = (value: string, pattern: RegExp): string => {
  const match = value.trim().match(pattern);
  return match ? value.trim().slice(match[0].length).trim() : value.trim();
};

const wordArrayToBytes = (wordArray: { words: number[]; sigBytes: number }): Uint8Array => {
  const bytes = new Uint8Array(wordArray.sigBytes);
  for (let index = 0; index < wordArray.sigBytes; index += 1) {
    bytes[index] = (wordArray.words[index >>> 2] >>> (24 - (index % 4) * 8)) & 255;
  }
  return bytes;
};

// 土豆码家族共用 AES-256-CBC；strictPadding=false 时不校验 PKCS7 填充（如是我闻解密端不去填充，容器容忍尾部垃圾）。
const tudouAes = async (bytes: Uint8Array, direction: 'encrypt' | 'decrypt', strictPadding: boolean): Promise<Uint8Array> => {
  const CryptoJS = await loadCryptoJs();
  const key = CryptoJS.enc.Utf8.parse(FO_KEY);
  const iv = CryptoJS.enc.Utf8.parse(FO_IV);
  const padding = strictPadding ? undefined : CryptoJS.pad.NoPadding;
  if (direction === 'encrypt') {
    const encrypted = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(bytes), key, { iv, mode: CryptoJS.mode.CBC, ...(padding ? { padding } : {}) });
    return wordArrayToBytes(CryptoJS.enc.Base64.parse(encrypted.toString()));
  }
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.lib.WordArray.create(bytes) });
  const decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv, mode: CryptoJS.mode.CBC, ...(padding ? { padding } : {}) });
  return wordArrayToBytes(decrypted);
};

const utf16leEncode = (value: string): Uint8Array => {
  const bytes = new Uint8Array(value.length * 2);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    bytes[index * 2] = code & 255;
    bytes[index * 2 + 1] = (code >>> 8) & 255;
  }
  return bytes;
};

const utf16leDecode = (bytes: Uint8Array): string => new TextDecoder('utf-16le').decode(bytes);

export const buddhaEncode = async (value: string): Promise<string> => {
  if (!value) return '';
  const cipherBytes = await tudouAes(utf16leEncode(value), 'encrypt', true);
  let output = '';
  for (const byte of cipherBytes) {
    if (byte < 128) {
      output += TUDOU[byte];
    } else {
      output += BYTEMARK[Math.floor(Math.random() * BYTEMARK.length)] + TUDOU[byte - 128];
    }
  }
  return `佛曰：${output}`;
};

export const buddhaDecode = async (value: string): Promise<string> => {
  const trimmed = value.trim();
  const reversed = /^魔曰[:：]/.test(trimmed);
  const body = stripPrefix(trimmed, /^\s*(?:佛曰|魔曰)\s*[:：]\s*/u);
  if (!body) throw new Error('未找到佛曰密文：请粘贴「佛曰：…」或「魔曰：…」开头的密文再解码。');
  const bytes: number[] = [];
  for (let index = 0; index < body.length; index += 1) {
    const char = body[index];
    const low = tudouIndex.get(char);
    if (low !== undefined) {
      bytes.push(low);
      continue;
    }
    // 不在码表内的佛字按高位标记字处理（兼容缺字的变体表），消费下一个码表字。
    const next = tudouIndex.get(body[index + 1]);
    if (next === undefined) {
      throw new Error(`密文含无法识别的字符「${char}」：与佛论禅只接受官方码表内的汉字，请确认复制完整（含繁体原样）。`);
    }
    bytes.push(128 + next);
    index += 1;
  }
  const ordered = reversed ? new Uint8Array(bytes).reverse() : new Uint8Array(bytes);
  const plainBytes = await tudouAes(ordered, 'decrypt', true);
  return utf16leDecode(plainBytes);
};

const toHex = (bytes: Uint8Array, limit = bytes.length): string => {
  const slice = bytes.subarray(0, Math.min(limit, bytes.length));
  return Array.from(slice, byte => byte.toString(16).padStart(2, '0')).join(' ');
};

const readVarint = (bytes: Uint8Array, cursor: { position: number }): number => {
  let result = 0;
  let shift = 0;
  for (;;) {
    if (cursor.position >= bytes.length) throw new Error('7z 头解析越界：容器可能不完整。');
    const byte = bytes[cursor.position];
    cursor.position += 1;
    result += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }
  return result;
};

// 7z/zip 浅解析：只支持未压缩（Copy/store）条目直取；LZMA 压缩条目输出 hex 供本地工具接手。
const unpackStoredContainer = (bytes: Uint8Array): { summary: string; payload: Uint8Array | null } => {
  if (bytes.length >= 6 && bytes[0] === 0x37 && bytes[1] === 0x7a && bytes[2] === 0xbc && bytes[3] === 0xaf && bytes[4] === 0x27 && bytes[5] === 0x1c) {
    return parseSevenZip(bytes);
  }
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b) {
    return parseZipStore(bytes);
  }
  return { summary: `解密结果不是已知的 7z/zip 容器（头部 ${toHex(bytes, 8)}），如是我闻密文可能被二次封装。`, payload: null };
};

const parseSevenZip = (bytes: Uint8Array): { summary: string; payload: Uint8Array | null } => {
  if (bytes.length < 32) {
    return { summary: `解密结果过短（${bytes.length} 字节），不构成有效 7z 容器；密文可能不完整。`, payload: null };
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerOffset = 32 + Number(view.getBigUint64(12, true));
  const headerSize = Number(view.getBigUint64(20, true));
  if (headerOffset < 32 || headerSize <= 0 || headerOffset + headerSize > bytes.length) {
    return { summary: '7z 容器头偏移越界：数据可能被截断或经过二次封装。', payload: null };
  }
  const header = bytes.subarray(headerOffset, Math.min(headerOffset + headerSize, bytes.length));
  if (!header.length || header[0] === 0x17) {
    return { summary: `已解出 7z 容器（${bytes.length} 字节），但其头部经 LZMA 压缩，浏览器端暂不支持解压。\n容器 hex（保存为 .7z 后可用本地 7-Zip 打包解出 default 条目）：\n${toHex(bytes)}`, payload: null };
  }
  const cursor = { position: 1 };
  let payload: Uint8Array | null = null;
  let coderNote = '未知压缩方式';
  let packPos = 0;
  let unpackSize = 0;
  let substreamSize: number | null = null;
  while (cursor.position < header.length) {
    const property = header[cursor.position];
    cursor.position += 1;
    if (property === 0x00) break;
    if (property === 0x04) {
      while (cursor.position < header.length) {
        const streamProperty = header[cursor.position];
        cursor.position += 1;
        if (streamProperty === 0x00) break;
        if (streamProperty === 0x06) {
          packPos = readVarint(header, cursor);
          const numPackStreams = readVarint(header, cursor);
          for (;;) {
            const sizeProperty = header[cursor.position];
            cursor.position += 1;
            if (sizeProperty === 0x00) break;
            if (sizeProperty === 0x09) {
              for (let index = 0; index < numPackStreams; index += 1) readVarint(header, cursor);
            } else if (sizeProperty === 0x0a) {
              for (let index = 0; index < numPackStreams; index += 1) readVarint(header, cursor);
            } else {
              throw new Error('7z 头含未支持的 PackInfo 属性，无法离线解析。');
            }
          }
        } else if (streamProperty === 0x07) {
          const folderMarker = header[cursor.position];
          cursor.position += 1;
          if (folderMarker !== 0x0b) throw new Error('7z 头格式异常：缺少 Folder 段。');
          const numFolders = readVarint(header, cursor);
          const external = readVarint(header, cursor);
          if (external !== 0 || numFolders !== 1) throw new Error('7z 容器为多文件夹或外部 Folder 表结构，浏览器端暂不支持。');
          const numCoders = readVarint(header, cursor);
          for (let coderIndex = 0; coderIndex < numCoders; coderIndex += 1) {
            const flags = header[cursor.position];
            cursor.position += 1;
            const idSize = flags & 0x0f;
            const isComplex = (flags & 0x10) !== 0;
            const hasAttrs = (flags & 0x20) !== 0;
            const id = Array.from(header.subarray(cursor.position, cursor.position + idSize));
            cursor.position += idSize;
            if (isComplex) readVarint(header, cursor);
            if (hasAttrs) {
              const propsSize = readVarint(header, cursor);
              cursor.position += propsSize;
            }
            const idKey = id.join(',');
            if (idKey === '0') coderNote = '未压缩（Copy）';
            else if (idKey === '3,1,1') coderNote = 'LZMA';
            else if (idKey === '33' || idKey === '0x21') coderNote = 'LZMA2';
            else coderNote = `编码器 0x${id.map(byte => byte.toString(16)).join(' ')}`;
          }
          const sizeMarker = header[cursor.position];
          cursor.position += 1;
          if (sizeMarker !== 0x0c) throw new Error('7z 头格式异常：缺少 UnPackSize 段。');
          unpackSize = readVarint(header, cursor);
          for (;;) {
            const tailProperty = header[cursor.position];
            cursor.position += 1;
            if (tailProperty === 0x00) break;
            if (tailProperty === 0x09 || tailProperty === 0x0a) {
              const count = tailProperty === 0x0a ? readVarint(header, cursor) : 1;
              for (let index = 0; index < count; index += 1) readVarint(header, cursor);
            } else if (tailProperty === 0x0c) {
              readVarint(header, cursor);
            }
          }
        } else if (streamProperty === 0x08) {
          // SubStreamsInfo：单文件夹场景常见，kSize 给出真实数据长度，kCRC 按位图跳过。
          for (;;) {
            const subProperty = header[cursor.position];
            cursor.position += 1;
            if (subProperty === 0x00) break;
            if (subProperty === 0x0d) {
              readVarint(header, cursor);
            } else if (subProperty === 0x09) {
              substreamSize = readVarint(header, cursor);
            } else if (subProperty === 0x0a) {
              const allDefined = readVarint(header, cursor);
              if (allDefined) {
                cursor.position += 4;
              } else {
                const bitmap = header[cursor.position];
                cursor.position += 1;
                if ((bitmap >>> 7) & 1) cursor.position += 4;
              }
            } else {
              throw new Error('7z 头含未支持的 SubStreamsInfo 属性，无法离线解析。');
            }
          }
        } else {
          throw new Error('7z 头含未支持的属性段，无法离线解析。');
        }
      }
    } else if (property === 0x05) {
      break;
    } else {
      throw new Error('7z 头含未支持的属性段，无法离线解析。');
    }
  }
  if (coderNote === '未压缩（Copy）') {
    const start = 32 + packPos;
    payload = bytes.subarray(start, Math.min(start + (substreamSize ?? unpackSize), bytes.length));
  }
  if (payload) return { summary: `7z 容器（${coderNote}，条目 default）`, payload };
  return { summary: `已解出 7z 容器（${bytes.length} 字节，${coderNote}）。${
    coderNote.includes('LZMA') ? '明文经 LZMA 压缩，浏览器端暂不支持解压。\n容器 hex（保存为 .7z 后可用本地 7-Zip 解出 default 条目）：\n' + toHex(bytes) : '未能定位未压缩数据。'
  }`, payload: null };
};

const parseZipStore = (bytes: Uint8Array): { summary: string; payload: Uint8Array | null } => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let position = bytes.length - 22; position >= Math.max(0, bytes.length - 22 - 65535); position -= 1) {
    if (bytes[position] === 0x50 && bytes[position + 1] === 0x4b && bytes[position + 2] === 0x05 && bytes[position + 3] === 0x06) {
      eocd = position;
      break;
    }
  }
  if (eocd < 0) return { summary: '解密结果是 zip 数据但缺少 End of Central Directory，容器可能不完整。', payload: null };
  const entryCount = view.getUint16(eocd + 10, true);
  const cdSize = view.getUint32(eocd + 12, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  let cursor = cdOffset;
  for (let entry = 0; entry < entryCount; entry += 1) {
    if (cursor + 46 > bytes.length || bytes[cursor] !== 0x50 || bytes[cursor + 1] !== 0x4b) break;
    const method = view.getUint16(cursor + 10, true);
    const compressedSize = view.getUint32(cursor + 20, true);
    const nameLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const commentLength = view.getUint16(cursor + 32, true);
    const localOffset = view.getUint32(cursor + 42, true);
    const name = new TextDecoder('utf-8').decode(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
    cursor += 46 + nameLength + extraLength + commentLength;
    if (name === 'default' || entryCount === 1) {
      if (method === 0) {
        if (localOffset + 30 > bytes.length) {
          return { summary: 'zip 容器本地文件头偏移越界：数据可能被截断。', payload: null };
        }
        const localNameLength = view.getUint16(localOffset + 26, true);
        const localExtraLength = view.getUint16(localOffset + 28, true);
        const dataStart = localOffset + 30 + localNameLength + localExtraLength;
        return { summary: `zip 容器（store，条目 ${name}）`, payload: bytes.subarray(dataStart, Math.min(dataStart + compressedSize, bytes.length)) };
      }
      return { summary: `已解出 zip 容器（条目 ${name}），明文经压缩方法 #${method} 压缩，浏览器端暂不支持解压。`, payload: null };
    }
  }
  void cdSize;
  return { summary: 'zip 容器内未找到名为 default 的条目。', payload: null };
};

export const buddhaV2Decode = async (value: string): Promise<string> => {
  const body = stripPrefix(value, /^\s*如是我闻\s*[:：]\s*/u);
  if (!body) throw new Error('未找到如是我闻密文：请粘贴「如是我闻：…」开头的密文再解码。');
  const bytes: number[] = [];
  for (const char of body) {
    const byte = rswwIndex.get(char);
    if (byte === undefined) {
      throw new Error(`密文含 256 字码表之外的字符「${char}」：如是我闻（keyfc V2）只接受官方码表内汉字，请确认复制完整。`);
    }
    bytes.push(byte);
  }
  const container = await tudouAes(new Uint8Array(bytes), 'decrypt', false);
  const { summary, payload } = unpackStoredContainer(container);
  if (payload) {
    const text = utf8Decoder.decode(payload);
    return text ? `${text}\n\n（已从${summary}解出明文）` : `（${summary}解出空明文）`;
  }
  return `如是我闻解码：${summary}`;
};

// basE91（Joachim Henke 规范，13/14bit 自适应）：熊曰的数值层。
const base91EncodeValues = (bytes: Uint8Array): number[] => {
  const values: number[] = [];
  let accumulator = 0;
  let bits = 0;
  for (const byte of bytes) {
    accumulator += byte * 2 ** bits;
    bits += 8;
    if (bits > 13) {
      let value = accumulator & 8191;
      if (value > 88) {
        accumulator >>= 13;
        bits -= 13;
      } else {
        value = accumulator & 16383;
        accumulator >>= 14;
        bits -= 14;
      }
      values.push(value % 91, Math.floor(value / 91));
    }
  }
  if (bits) {
    values.push(accumulator % 91);
    if (bits > 7 || accumulator > 90) values.push(Math.floor(accumulator / 91));
  }
  return values;
};

const base91DecodeValues = (values: number[]): Uint8Array => {
  const bytes: number[] = [];
  let accumulator = 0;
  let bits = 0;
  let pending = -1;
  for (const value of values) {
    if (pending < 0) {
      pending = value;
      continue;
    }
    const pair = pending + value * 91;
    pending = -1;
    accumulator += pair * 2 ** bits;
    bits += (pair & 8191) > 88 ? 13 : 14;
    do {
      bytes.push(accumulator & 255);
      accumulator >>= 8;
      bits -= 8;
    } while (bits > 7);
  }
  if (pending >= 0) bytes.push((accumulator + pending * 2 ** bits) & 255);
  return new Uint8Array(bytes);
};

export const bearEncode = async (value: string): Promise<string> => {
  if (!value) return '';
  const compressed = base64ToBytes(await compressText(value, 'deflate-raw'));
  const encoded = base91EncodeValues(compressed)
    .map(value => XIONGYUE_DICT[value])
    .reverse()
    .join('');
  return `熊曰：呋${encoded}`;
};

export const bearDecode = async (value: string): Promise<string> => {
  const body = stripPrefix(value, /^\s*熊曰\s*[:：]\s*/u);
  if (!body.startsWith('呋')) {
    throw new Error('熊曰密文缺少校验头「呋」：请确认复制完整（格式为「熊曰：呋…」）。');
  }
  const chars = [...body.slice(1)].reverse();
  const values: number[] = [];
  for (const char of chars) {
    const index = bearIndex.get(char);
    if (index === undefined) {
      throw new Error(`密文含熊语字典之外的字符「${char}」：与熊论道只接受官方 91 字熊语字典，请确认复制完整。`);
    }
    values.push(index);
  }
  const compressed = base91DecodeValues(values);
  try {
    return await decompressText(bytesToBase64(compressed), 'deflate-raw');
  } catch {
    throw new Error('熊曰密文解压失败：压缩数据已损坏或不完整，请确认密文没有缺字。');
  }
};

export const baijiaxingEncode = (value: string): string => {
  if (!value) return '';
  const encoded = bytesToBase64(utf8Encoder.encode(value));
  let output = '';
  for (const char of encoded) output += bjxByAscii.get(char) ?? char;
  return output;
};

export const baijiaxingDecode = (value: string): string => {
  const body = value.trim();
  if (!body) return '';
  let ascii = '';
  let tableHits = 0;
  for (const char of body) {
    const mapped = bjxByChar.get(char);
    if (mapped !== undefined) {
      ascii += mapped;
      tableHits += 1;
    } else {
      ascii += char;
    }
  }
  if (tableHits === 0) {
    throw new Error('输入不含百家姓码表内的姓氏字符，无法按百家姓解码。');
  }
  const compact = ascii.replace(/\s+/g, '');
  if (compact.length >= 8 && compact.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
    try {
      const strictUtf8 = new TextDecoder('utf-8', { fatal: true });
      return strictUtf8.decode(base64ToBytes(compact));
    } catch {
      // base64 形态但解码后非合法 UTF-8：按直接替换流派输出。
    }
  }
  return ascii;
};

const bitsToBytes = (bits: number[]): Uint8Array => {
  const bytes: number[] = [];
  for (let position = 0; position < bits.length; position += 8) {
    let byte = 0;
    for (let offset = 0; offset < 8; offset += 1) byte = (byte << 1) | (bits[position + offset] ?? 0);
    bytes.push(byte);
  }
  return new Uint8Array(bytes);
};

const bytesToSixBitValues = (bytes: Uint8Array): number[] => {
  const bits: number[] = [];
  for (const byte of bytes) for (let offset = 7; offset >= 0; offset -= 1) bits.push((byte >>> offset) & 1);
  while (bits.length % 6 !== 0) bits.push(0);
  const values: number[] = [];
  for (let position = 0; position < bits.length; position += 6) {
    let value = 0;
    for (let offset = 0; offset < 6; offset += 1) value = (value << 1) | bits[position + offset];
    values.push(value);
  }
  return values;
};

export const hexagramEncode = (value: string, variant: string): string => {
  if (!value) return '';
  const bytes = utf8Encoder.encode(value);
  if (variant === 'symbols') {
    return bytesToSixBitValues(bytes).map(sixBit => String.fromCharCode(0x4dc0 + sixBit)).join('');
  }
  const unpadded = bytesToBase64(bytes).replace(/=+$/, '');
  return [...unpadded].map(char => EIGHT_MAP[BASE64_STD.indexOf(char)] ?? char).join('');
};

export const hexagramDecode = (value: string): string => {
  const body = value.trim();
  if (!body) return '';
  const chars = [...body];
  const symbolChars = chars.filter(char => {
    const code = char.codePointAt(0) ?? 0;
    return code >= 0x4dc0 && code <= 0x4dff;
  });
  if (symbolChars.length >= chars.length * 0.8 && symbolChars.length > 0) {
    const sixBits = symbolChars.map(char => (char.codePointAt(0) ?? 0x4dc0) - 0x4dc0);
    const bits: number[] = [];
    for (const sixBit of sixBits) for (let offset = 5; offset >= 0; offset -= 1) bits.push((sixBit >>> offset) & 1);
    // 编码时右侧补 0 到 6 的倍数；解码只保留整字节部分，丢弃尾部补位。
    return utf8Decoder.decode(bitsToBytes(bits.slice(0, bits.length - (bits.length % 8))));
  }
  let base64Text = '';
  let position = 0;
  while (position < chars.length) {
    const pair = chars.slice(position, position + 2).join('');
    if (hexagramDouble.has(pair)) {
      base64Text += hexagramNames.get(pair) ?? '';
      position += 2;
      continue;
    }
    const single = chars[position];
    const mapped = hexagramNames.get(single);
    if (mapped === undefined) {
      throw new Error(`密文含六十四卦卦名之外的字符「${single}」：卦名流派只接受官方 64 卦名，请确认输入为卦名或 Unicode 卦符（䷀-䷿）。`);
    }
    base64Text += mapped;
    position += 1;
  }
  const padded = base64Text + '='.repeat((4 - (base64Text.length % 4)) % 4);
  return utf8Decoder.decode(base64ToBytes(padded));
};

export const sexagesimalEncode = (value: string): string => {
  if (!value) return '';
  const bytes = utf8Encoder.encode(value);
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) | BigInt(byte);
  if (number === 0n) return '甲子';
  const digits: string[] = [];
  while (number > 0n) {
    digits.unshift(GZ60[Number(number % 60n)]);
    number /= 60n;
  }
  return digits.join('');
};

export const sexagesimalDecode = (value: string): string => {
  const body = value.trim().replace(/\s+/g, '');
  if (!body) return '';
  if (body.length % 2 !== 0) {
    throw new Error('天干地支密文长度应为偶数（每 2 个汉字一组），请确认复制完整。');
  }
  let number = 0n;
  for (let position = 0; position < body.length; position += 2) {
    const pair = body.slice(position, position + 2);
    const index = gzIndex.get(pair);
    if (index === undefined) {
      throw new Error(`密文含非法干支组合「${pair}」（六十甲子中不存在），天干地支编码只接受甲子到癸亥的 60 组组合。`);
    }
    number = number * 60n + BigInt(index);
  }
  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  if (!bytes.length) return '';
  const strictUtf8 = new TextDecoder('utf-8', { fatal: true });
  try {
    return strictUtf8.decode(new Uint8Array(bytes));
  } catch {
    throw new Error('天干地支解码结果不是合法的 UTF-8 文本：密文可能不完整或被二次编码。');
  }
};

// ---- 云影密码（幂数加密 / 01248 密码，批次 M）----
// 规则：0 为分隔符，段内 1/2/4/8 求和得 1-26，按 A1Z26 映射字母（段内数字可重复，如 88421=23→W）。
// 解码唯一；编码不唯一（同一和有多种分解），此处按 8/4/2/1 贪心分解。
// 验证向量（攻防世界真题）：8842101220480224404014224202480122 → WELLDONE。

export const cloudShadowEncode = (value: string): string => {
  let output = '';
  for (const char of value) {
    const upper = char.toUpperCase();
    if (upper >= 'A' && upper <= 'Z') {
      let remaining = upper.charCodeAt(0) - 64;
      let segment = '';
      while (remaining > 0) {
        if (remaining >= 8) { segment += '8'; remaining -= 8; }
        else if (remaining >= 4) { segment += '4'; remaining -= 4; }
        else if (remaining >= 2) { segment += '2'; remaining -= 2; }
        else { segment += '1'; remaining -= 1; }
      }
      output += `${segment}0`;
    } else {
      throw new Error(`云影密码编码仅支持字母 A-Z（密文中出现「${char}」）；该密码没有数字/符号的非歧义表示。`);
    }
  }
  return output;
};

export const cloudShadowDecode = (value: string): string => {
  const compact = value.trim().replace(/\s+/g, '');
  if (!compact) return '';
  if (!/^[01248]+$/.test(compact)) {
    throw new Error('云影密码密文只能包含数字 0/1/2/4/8（0 为分隔符，1/2/4/8 段内求和）。');
  }
  const segments = compact.split('0').filter(Boolean);
  if (!segments.length) throw new Error('云影密码密文缺少有效数字段（只有分隔符 0）。');
  let output = '';
  for (const segment of segments) {
    let sum = 0;
    for (const char of segment) sum += Number(char);
    if (sum < 1 || sum > 26) {
      throw new Error(`云影密码段「${segment}」求和为 ${sum}，超出字母范围 1-26，请确认密文完整。`);
    }
    output += String.fromCharCode(64 + sum);
  }
  return output;
};

// 智能识别谓词：仅 0/1/2/4/8，按 0 分段后每段求和落在 1-26、段长 ≤8（手工出题的分解可能超出贪心 4 位）。
export const looksLikeCloudShadow = (value: string): boolean => {
  const text = value.trim().replace(/\s+/g, '');
  if (!/^[01248]{4,}$/.test(text)) return false;
  const segments = text.split('0').filter(Boolean);
  if (segments.length < 2) return false;
  return segments.every(segment => {
    let sum = 0;
    for (const char of segment) sum += Number(char);
    return segment.length <= 8 && sum >= 1 && sum <= 26;
  });
};
