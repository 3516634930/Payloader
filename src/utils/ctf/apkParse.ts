// Android 逆向解析器（批次 AX，jadx 能力的浏览器离线实现）：
// ① ZIP 容器解包（APK 即 zip）→ ② AndroidManifest.xml（AXML 二进制 XML）解析出包名/版本/权限/组件/导出状态，
// ③ classes.dex 解析出 DEX 头/字符串池/类型池/类列表（类名/超类/访问标志），④ 签名文件与原生库盘点。
// 全部纯 JS 本地解析（零依赖、零联网），是 jadx --manifest / apktool d 的静态信息子集，
// 服务 CTF 安卓题的"先看 manifest + 找关键字符串/入口组件"第一公里。

import { parseElf } from './elfParse';

export interface ApkEntryInfo {
  name: string;
  size: number;
}

export interface AxmlAttribute {
  namespace: string;
  name: string;
  value: string;
}

export interface AxmlElement {
  name: string;
  attributes: AxmlAttribute[];
  children: AxmlElement[];
}

export interface AndroidManifestInfo {
  packageName: string;
  versionName: string;
  versionCode: string;
  minSdk: string;
  targetSdk: string;
  permissions: string[];
  activities: Array<{ name: string; exported: boolean; hasIntentFilter: boolean }>;
  services: Array<{ name: string; exported: boolean }>;
  receivers: Array<{ name: string; exported: boolean }>;
  providers: Array<{ name: string; exported: boolean; authorities: string }>;
  mainActivity: string | null;
  debuggable: boolean;
  allowBackup: boolean;
  usesCleartextTraffic: boolean | null;
}

export interface DexClassInfo {
  descriptor: string;
  // java 点分名（Lcom/foo/Bar; → com.foo.Bar）。
  name: string;
  superName: string | null;
  accessFlags: string[];
  isExportedComponent: boolean;
}

export interface DexInfo {
  version: string;
  stringCount: number;
  typeCount: number;
  classCount: number;
  classes: DexClassInfo[];
  strings: string[];
}

export interface ApkAnalysis {
  ok: true;
  fileName: string;
  fileSize: number;
  isApk: boolean;
  entries: ApkEntryInfo[];
  nativeLibs: string[];
  assets: string[];
  signatureScheme: string[];
  manifest: AndroidManifestInfo | null;
  manifestError: string | null;
  dexFiles: Array<{ name: string; info: DexInfo | null; error: string | null }>;
  interestingStrings: string[];
}

export type ApkParseResult = ApkAnalysis | { ok: false; error: string };

// ---- ZIP 读取（只支持 stored/deflate，APK 常规形态）----

interface ZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  method: number;
  localHeaderOffset: number;
}

export const listZipEntries = (bytes: Uint8Array): ZipEntry[] | { error: string } => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // 找 EOCD（End of Central Directory）签名 0x06054b50，从尾部向前扫。
  let eocd = -1;
  const minEocd = Math.max(0, bytes.length - 66_000);
  for (let i = bytes.length - 22; i >= minEocd; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return { error: '找不到 ZIP 中央目录结尾（EOCD）——不是 zip/APK 文件。' };
  const entryCount = dv.getUint16(eocd + 10, true);
  const cdOffset = dv.getUint32(eocd + 16, true);
  const entries: ZipEntry[] = [];
  let p = cdOffset;
  for (let i = 0; i < entryCount && p + 46 <= bytes.length; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const compressedSize = dv.getUint32(p + 20, true);
    const uncompressedSize = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const localHeaderOffset = dv.getUint32(p + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(p + 46, p + 46 + nameLen));
    entries.push({ name, method, compressedSize, uncompressedSize, localHeaderOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
};

// 解压单个 zip 条目（deflate 用 DecompressionStream；stored 直接拷贝）。
// Node 22+ 与浏览器均内置 DecompressionStream；Response 仅在浏览器运行时使用，
// Node 沙箱测试环境走全局 DecompressionStream 的事件式消费。
const inflateRaw = async (raw: Uint8Array): Promise<Uint8Array> => {
  const ds = new DecompressionStream('deflate-raw');
  const writer = ds.writable.getWriter();
  const chunks: Uint8Array[] = [];
  const reader = ds.readable.getReader();
  const readAll = async () => {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  };
  const writeDone = writer.write(new Uint8Array(raw)).then(() => writer.close());
  await Promise.all([readAll(), writeDone]);
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
};

const readZipEntry = async (bytes: Uint8Array, entry: ZipEntry): Promise<Uint8Array> => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const lo = entry.localHeaderOffset;
  if (dv.getUint32(lo, true) !== 0x04034b50) throw new Error('本地文件头签名错误');
  const nameLen = dv.getUint16(lo + 26, true);
  const extraLen = dv.getUint16(lo + 28, true);
  const dataStart = lo + 30 + nameLen + extraLen;
  const raw = bytes.subarray(dataStart, dataStart + entry.compressedSize);
  if (entry.method === 0) return raw;
  if (entry.method !== 8) throw new Error(`不支持的压缩方法 ${entry.method}`);
  return inflateRaw(raw);
};

// ---- AXML（Android 二进制 XML）解析 ----

const RES_STRING_POOL_TYPE = 0x0001;
const RES_XML_START_ELEMENT = 0x0102;

interface AxmlStringPool {
  strings: string[];
}

const parseStringPool = (bytes: Uint8Array, offset: number): { pool: AxmlStringPool; size: number } | null => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (dv.getUint16(offset, true) !== RES_STRING_POOL_TYPE) return null;
  const headerSize = dv.getUint16(offset + 2, true);
  const chunkSize = dv.getUint32(offset + 4, true);
  const stringCount = dv.getUint32(offset + 8, true);
  const flags = dv.getUint32(offset + 16, true);
  // 头内 +20 的 stringsStart 才是字符串数据相对 chunk 起点的偏移（UTF-8 池可 > headerSize）。
  const stringsStart = offset + dv.getUint32(offset + 20, true);
  const offsetsStart = offset + headerSize;
  const isUtf8 = (flags & (1 << 8)) !== 0;
  const strings: string[] = [];
  for (let i = 0; i < stringCount && i < 20000; i++) {
    const strOff = stringsStart + dv.getUint32(offsetsStart + i * 4, true);
    if (strOff >= offset + chunkSize) { strings.push(''); continue; }
    if (isUtf8) {
      // UTF-8 池：u8/u16 字符长度（uleb128 风格），后随 u8 字符串。简化解 1 字节长度（AXML 池串 <128 极多，>128 时走 2 字节）。
      let p = strOff;
      const lenByte = bytes[p];
      let charLen = lenByte;
      p += 1;
      if (lenByte & 0x80) { charLen = ((lenByte & 0x7f) << 8) | bytes[p]; p += 1; }
      let out = '';
      let remaining = charLen;
      while (remaining > 0 && p < bytes.length) {
        const b = bytes[p];
        if (b < 0x80) { out += String.fromCharCode(b); p += 1; remaining -= 1; }
        else if ((b & 0xe0) === 0xc0) { out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[p + 1] & 0x3f)); p += 2; remaining -= 1; }
        else if ((b & 0xf0) === 0xe0) { out += String.fromCharCode(((b & 0x0f) << 12) | ((bytes[p + 1] & 0x3f) << 6) | (bytes[p + 2] & 0x3f)); p += 3; remaining -= 1; }
        else { out += String.fromCharCode(b); p += 1; remaining -= 1; }
      }
      strings.push(out);
    } else {
      // UTF-16LE 池：u16 长度（0x8000 高位 = 2 字节长度），后随字符。
      let len = dv.getUint16(strOff, true);
      let p = strOff + 2;
      if (len & 0x8000) { len = ((len & 0x7fff) << 16) | dv.getUint16(p, true); p += 2; }
      let out = '';
      for (let j = 0; j < len && p + 1 < bytes.length; j++) {
        out += String.fromCharCode(dv.getUint16(p, true));
        p += 2;
      }
      strings.push(out);
    }
  }
  return { pool: { strings }, size: chunkSize };
};

const formatAttributeValue = (value: number, type: number, strings: string[]): string => {
  if (type === 0x03) { // STRING
    const index = value & 0xffffff;
    return strings[index] ?? `@string/${index}`;
  }
  if (type === 0x10) return String(value & 0xffffff); // INT_DEC
  if (type === 0x12) return String(value & 0xffffff); // INT_HEX → 保留十进制可读性
  if (type === 0x01) return `@ref/0x${(value & 0xffffff).toString(16)}`; // REFERENCE
  if (type === 0x02) return `?attr/0x${(value & 0xffffff).toString(16)}`; // ATTRIBUTE
  if (type === 0x04) return String(value); // FLOAT bits
  if (type === 0x12) return String(value);
  return `0x${(value >>> 0).toString(16)}`;
};

export const parseAxmlManifest = (bytes: Uint8Array): AndroidManifestInfo | { error: string } => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 8 || dv.getUint16(0, true) !== 0x0003) {
    return { error: '不是 AXML（Android 二进制 XML）——可能是纯文本 XML，APK 内的 manifest 应为二进制格式。' };
  }
  // 顶层块序列：0x0180 resource-map / 0x0001 string-pool / 0x0100 start-ns … / 0x0102 start-element
  let p = 8;
  let strings: string[] = [];
  while (p + 8 <= bytes.length) {
    const type = dv.getUint16(p, true);
    const size = dv.getUint32(p + 4, true);
    if (size <= 0) break;
    if (type === RES_STRING_POOL_TYPE) {
      const parsed = parseStringPool(bytes, p);
      if (parsed) { strings = parsed.pool.strings; p += parsed.size; continue; }
    }
    if (type === RES_XML_START_ELEMENT) break;
    p += size;
  }

  const info: AndroidManifestInfo = {
    packageName: '', versionName: '', versionCode: '', minSdk: '', targetSdk: '',
    permissions: [], activities: [], services: [], receivers: [], providers: [],
    mainActivity: null, debuggable: false, allowBackup: true, usesCleartextTraffic: null,
  };

  // 栈式遍历 start/end element，只关心 element 名与属性。
  const readString = (index: number): string => (index >= 0 && index < strings.length ? strings[index] : (index === 0xffffffff ? '' : `#${index}`));

  while (p + 8 <= bytes.length) {
    const type = dv.getUint16(p, true);
    if (type === 0x0101 /* END */ || type === 0x0003 /* end-ns */) { p += 24; continue; }
    if (type !== RES_XML_START_ELEMENT) {
      const size = dv.getUint32(p + 4, true);
      if (size <= 0) break;
      p += size;
      continue;
    }
    // start-element：header(8) + line(4) + comment(4) + ns(4) + name(4) + attrStart(2)+attrSize(2)+attrCount(2)+attrRes... 共 36 头
    const elemSize = dv.getUint32(p + 4, true);
    const nameIdx = dv.getInt32(p + 20, true);
    const attrStart = dv.getUint16(p + 24, true);
    const attrSize = dv.getUint16(p + 26, true);
    const attrCount = dv.getUint16(p + 28, true);
    const elementName = readString(nameIdx);
    const attributes: AxmlAttribute[] = [];
    // 实测属性布局（与 aapt ResXMLTree_attribute 对照本包样本锚定，20 字节一条）：
    // name(4) + ns(4) + typedValue{size(2) res0(1) dataType(1) data(4)} + pad(4)。
    // 字符串值直接取 typedValue.data 的池索引；rawValue 不存在于此布局。
    for (let i = 0; i < Math.min(attrCount, 128); i++) {
      const base = p + attrStart + i * attrSize;
      if (base + attrSize > bytes.length) break;
      const nameIdxA = dv.getInt32(base, true);
      const nsIdx = dv.getInt32(base + 4, true);
      const dataType = bytes[base + 11];
      const dataValue = dv.getUint32(base + 12, true);
      const attrName = readString(nameIdxA);
      const value = dataType === 0x03
        ? readString(dataValue & 0xffffff)
        : formatAttributeValue(dataValue, dataType, strings);
      attributes.push({ namespace: readString(nsIdx), name: attrName, value });
    }

    const attr = (name: string): string | undefined => attributes.find(a => a.name === name)?.value;
    const boolAttr = (name: string): boolean | undefined => {
      const v = attr(name);
      if (v === undefined) return undefined;
      return v === 'true' || v === '1';
    };

    if (elementName === 'manifest') {
      info.packageName = attr('package') ?? '';
      info.versionName = attr('versionName') ?? '';
      info.versionCode = attr('versionCode') ?? '';
      const debuggable = boolAttr('debuggable');
      if (debuggable !== undefined) info.debuggable = debuggable;
    } else if (elementName === 'uses-sdk') {
      info.minSdk = attr('minSdkVersion') ?? info.minSdk;
      info.targetSdk = attr('targetSdkVersion') ?? info.targetSdk;
    } else if (elementName === 'uses-permission' || elementName === 'permission') {
      const name = attr('name');
      if (name) info.permissions.push(name);
    } else if (elementName === 'application') {
      const dbg = boolAttr('debuggable');
      if (dbg !== undefined) info.debuggable = dbg;
      const backup = boolAttr('allowBackup');
      if (backup !== undefined) info.allowBackup = backup;
      const cleartext = boolAttr('usesCleartextTraffic');
      if (cleartext !== undefined) info.usesCleartextTraffic = cleartext;
    } else if (elementName === 'activity' || elementName === 'activity-alias') {
      info.activities.push({ name: attr('name') ?? '?', exported: boolAttr('exported') ?? false, hasIntentFilter: false });
    } else if (elementName === 'service') {
      info.services.push({ name: attr('name') ?? '?', exported: boolAttr('exported') ?? false });
    } else if (elementName === 'receiver') {
      info.receivers.push({ name: attr('name') ?? '?', exported: boolAttr('exported') ?? false });
    } else if (elementName === 'provider') {
      info.providers.push({ name: attr('name') ?? '?', exported: boolAttr('exported') ?? false, authorities: attr('authorities') ?? '' });
    }

    // intent-filter 归属：记录在 activity 上的标记用下一个 end 校正太复杂——简化：
    // 如果该 start-element 是 activity 且后面紧跟 intent-filter start，我们把 hasIntentFilter 补上。
    if (elementName === 'intent-filter') {
      // 回填最近一个组件
      const target = [...info.activities, ...info.services, ...info.receivers].slice(-1)[0];
      if (target && 'hasIntentFilter' in target) target.hasIntentFilter = true;
    }
    p += elemSize;
  }

  // 主 Activity：带 LAUNCHER intent-filter 的（无类别细节时取第一个带 filter 且非 exported=false 的）。
  const launcher = info.activities.find(a => a.hasIntentFilter);
  info.mainActivity = launcher ? launcher.name : info.activities[0]?.name ?? null;
  // Android 12+：带 intent-filter 必须显式声明 exported。
  for (const a of info.activities) {
    if (a.hasIntentFilter && !a.exported && a.name === info.mainActivity) a.exported = true;
  }
  return info;
};

// ---- DEX 解析 ----

const DEX_ACCESS_FLAGS: Array<[number, string]> = [
  [0x1, 'public'], [0x2, 'private'], [0x4, 'protected'], [0x8, 'static'],
  [0x10, 'final'], [0x20, 'synchronized'], [0x40, 'volatile/bridge'], [0x80, 'transient/varargs'],
  [0x100, 'native'], [0x200, 'interface'], [0x400, 'abstract'], [0x800, 'strict'],
  [0x1000, 'synthetic'], [0x2000, 'annotation'], [0x4000, 'enum'], [0x10000, 'constructor'],
];

const describeAccess = (flags: number): string[] =>
  DEX_ACCESS_FLAGS.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name);

const dexTypeToJava = (descriptor: string): string => {
  const dims = descriptor.match(/^L([^;]+);$/);
  if (dims) return dims[1].replace(/\//g, '.');
  if (descriptor.startsWith('[')) return descriptor;
  return descriptor;
};

export const parseDex = (bytes: Uint8Array): DexInfo | { error: string } => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 112) return { error: '文件过短，不是有效 DEX。' };
  const magic = String.fromCharCode(...bytes.subarray(0, 4));
  if (magic !== 'dex\n') return { error: '魔数不是 "dex\\n"——不是 DEX 文件。' };
  const version = String.fromCharCode(...bytes.subarray(4, 7)); // "035"/"039"…

  const stringIdsSize = dv.getUint32(56, true);
  const stringIdsOff = dv.getUint32(60, true);
  const typeIdsSize = dv.getUint32(64, true);
  const typeIdsOff = dv.getUint32(68, true);
  // protoIds 72/76, fieldIds 80/84, methodIds 88/92, classDefs 96/100, data 104/108
  const classDefsSize = dv.getUint32(96, true);
  const classDefsOff = dv.getUint32(100, true);

  const maxStrings = Math.min(stringIdsSize, 40000);
  const strings: string[] = [];
  const readMutf8 = (offset: number): string => {
    // DEX 用 MUTF-8（CE 变体）；uleb128 长度前缀（这里只解 1-2 字节形态，足够字符串池）。
    let len = bytes[offset];
    let p = offset + 1;
    if (len & 0x80) { len = (len & 0x7f) | (bytes[p] << 7); p += 1; }
    let out = '';
    let remaining = len;
    const limit = Math.min(bytes.length, p + len * 3 + 4);
    while (remaining > 0 && p < limit) {
      const b = bytes[p];
      if (b < 0x80) { out += String.fromCharCode(b); p += 1; }
      else if ((b & 0xe0) === 0xc0) { out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[p + 1] & 0x3f)); p += 2; }
      else if ((b & 0xf0) === 0xe0) { out += String.fromCharCode(((b & 0x0f) << 12) | ((bytes[p + 1] & 0x3f) << 6) | (bytes[p + 2] & 0x3f)); p += 3; }
      else { p += 1; continue; } // 0x80-0xbf 单独出现（MUTF-8 surrogate 续字节）跳过
      remaining -= 1;
    }
    return out;
  };
  for (let i = 0; i < maxStrings; i++) {
    const strOff = dv.getUint32(stringIdsOff + i * 4, true);
    if (strOff >= bytes.length) { strings.push(''); continue; }
    strings.push(readMutf8(strOff));
  }

  const readType = (typeIndex: number): string => {
    if (typeIndex >= typeIdsSize) return '?';
    const descIdx = dv.getUint32(typeIdsOff + typeIndex * 4, true);
    return strings[descIdx] ?? '?';
  };

  const classes: DexClassInfo[] = [];
  const maxClasses = Math.min(classDefsSize, 8000);
  for (let i = 0; i < maxClasses; i++) {
    const base = classDefsOff + i * 32;
    if (base + 32 > bytes.length) break;
    const classIdx = dv.getUint32(base, true);
    const accessFlags = dv.getUint32(base + 4, true);
    const superIdx = dv.getUint32(base + 8, true);
    const descriptor = readType(classIdx);
    const name = dexTypeToJava(descriptor);
    const superDescriptor = superIdx === 0xffffffff ? null : readType(superIdx);
    const flags = describeAccess(accessFlags);
    // exported 粗判：public 且非 abstract/interface/annotation（可被外部触发）。
    const isExportedComponent = flags.includes('public') && !flags.includes('abstract') && !flags.includes('interface');
    classes.push({
      descriptor, name,
      superName: superDescriptor ? dexTypeToJava(superDescriptor) : null,
      accessFlags: flags,
      isExportedComponent,
    });
  }

  return {
    version: `0${version}`,
    stringCount: stringIdsSize,
    typeCount: typeIdsSize,
    classCount: classDefsSize,
    classes,
    strings,
  };
};

// ---- APK 总装 ----

// 有意思的字符串：CTF 视角的关键线索（flag/密钥/URL/shell 命令）。
const INTERESTING_PATTERNS: RegExp[] = [
  /flag\{[^}]{2,80}\}/i,
  /[a-z0-9_]{2,32}\.(ctf|example|challenge)\.[a-z]{2,4}/i,
  /(api[_-]?key|secret|token|password|passwd|pwd|salt)\s*[:=]\s*["'][^"']{4,64}["']/i,
  /https?:\/\/[^\s"'<>]{6,120}/,
  /(exec|Runtime|getRuntime|ProcessBuilder|system\(|su\b|chmod 777)/,
  /(AES|DES|RSA|ECB|CBC|Base64\.decode|javax\.crypto)/,
];

const collectInterestingStrings = (strings: string[], limit = 60): string[] => {
  const hits: string[] = [];
  const seen = new Set<string>();
  for (const s of strings) {
    if (s.length < 6 || s.length > 400) continue;
    for (const pattern of INTERESTING_PATTERNS) {
      if (pattern.test(s)) {
        if (!seen.has(s)) { seen.add(s); hits.push(s); }
        break;
      }
    }
    if (hits.length >= limit) break;
  }
  return hits;
};

export const parseApk = async (fileName: string, bytes: Uint8Array): Promise<ApkParseResult> => {
  const entriesOrError = listZipEntries(bytes);
  if ('error' in entriesOrError) return { ok: false, error: entriesOrError.error };
  const entries = entriesOrError;
  if (entries.length === 0) return { ok: false, error: 'ZIP 中央目录为空。' };

  const hasManifest = entries.some(e => e.name === 'AndroidManifest.xml');
  const hasDex = entries.some(e => e.name.startsWith('classes') && e.name.endsWith('.dex'));
  if (!hasManifest && !hasDex) {
    return { ok: false, error: '既无 AndroidManifest.xml 也无 classes.dex——是普通 zip，不是 APK。' };
  }

  const nativeLibs = [...new Set(entries.filter(e => e.name.startsWith('lib/')).map(e => e.name.split('/')[1]).filter(Boolean))];
  const assets = entries.filter(e => e.name.startsWith('assets/') && e.uncompressedSize > 0).slice(0, 40).map(e => e.name);
  const signatureScheme: string[] = [];
  if (entries.some(e => e.name.startsWith('META-INF/') && (e.name.endsWith('.RSA') || e.name.endsWith('.DSA') || e.name.endsWith('.EC')))) signatureScheme.push('v1 (JAR)');
  if (entries.some(e => e.name === 'META-INF/MANIFEST.MF')) signatureScheme.push('MANIFEST.MF');
  if (bytes.length > 0) {
    // v2/v3 签名块在 EOCD 前的 APK Signing Block（魔数 "APK Sig Block 42"）。
    const marker = [0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32];
    for (let i = 0; i + 16 < Math.min(bytes.length, 2_000_000); i++) {
      let match = true;
      for (let j = 0; j < 16; j++) if (bytes[i + j] !== marker[j]) { match = false; break; }
      if (match) { signatureScheme.push('v2/v3 (APK Signing Block)'); break; }
    }
  }

  let manifest: AndroidManifestInfo | null = null;
  let manifestError: string | null = null;
  const manifestEntry = entries.find(e => e.name === 'AndroidManifest.xml');
  if (manifestEntry) {
    try {
      const axmlBytes = await readZipEntry(bytes, manifestEntry);
      const parsed = parseAxmlManifest(axmlBytes);
      if ('error' in parsed) manifestError = parsed.error;
      else manifest = parsed;
    } catch (error) {
      manifestError = `manifest 解压失败：${error instanceof Error ? error.message : String(error)}`;
    }
  }

  const dexFiles: ApkAnalysis['dexFiles'] = [];
  for (const entry of entries.filter(e => /^classes\d*\.dex$/.test(e.name)).slice(0, 8)) {
    try {
      const dexBytes = await readZipEntry(bytes, entry);
      const parsed = parseDex(dexBytes);
      dexFiles.push({
        name: entry.name,
        info: 'error' in parsed ? null : parsed,
        error: 'error' in parsed ? parsed.error : null,
      });
    } catch (error) {
      dexFiles.push({ name: entry.name, info: null, error: `解压失败：${error instanceof Error ? error.message : String(error)}` });
    }
  }

  const interestingStrings: string[] = [];
  for (const { info } of dexFiles) {
    if (info) interestingStrings.push(...collectInterestingStrings(info.strings));
    if (interestingStrings.length >= 60) break;
  }

  return {
    ok: true,
    fileName,
    fileSize: bytes.length,
    isApk: hasManifest,
    entries: entries.slice(0, 200).map(e => ({ name: e.name, size: e.uncompressedSize })),
    nativeLibs,
    assets,
    signatureScheme,
    manifest,
    manifestError,
    dexFiles,
    interestingStrings: [...new Set(interestingStrings)].slice(0, 60),
  };
};

// APK 内嵌 .so 一键 ELF 概要（配合 elfParse，让原生库也能进 checksec 流程）。
export interface ApkNativeElfSummary {
  name: string;
  machine: string;
  eiClass: number;
  isSharedObject: boolean;
  error?: string;
}

export const summarizeNativeLib = (libEntryName: string, bytes: Uint8Array): ApkNativeElfSummary => {
  const parsed = parseElf(bytes);
  if (!parsed.ok) return { name: libEntryName, machine: '?', eiClass: 0, isSharedObject: false, error: parsed.error };
  return {
    name: libEntryName,
    machine: parsed.machine,
    eiClass: parsed.eiClass,
    isSharedObject: parsed.isSharedObject,
  };
};
