// Python pyc 深度解析引擎（CTF 逆向域）：pyc 文件头（magic→版本）+ marshal 反序列化 +
// code object 树遍历 + 面向 CTF 的常量/字符串摘要。对标随波逐流"pyc/pyo 分析 + pyc转py(常量面)"。
// 纯函数、只读字节、无 DOM/eval/网络；单文件上限 20MB。
//
// 字节格式证据（全部逐字节核实过，非二手资料）：
// 1) magic→版本对照：CPython Lib/importlib/_bootstrap_external.py 的 magic 历史注释表
//    （v3.12 分支文件尾 MAGIC_NUMBER = (3531).to_bytes(2,'little') + b'\r\n'）。
//    落地区间：3.5=3310-3351、3.6=3360-3379、3.7=3390-3394、3.8=3400-3413、3.9=3420-3425、
//    3.10=3430-3439、3.11=3450-3495、3.12=3500-3531；3.13 从 3550 起（布局按 3.12 尽力解析）。
// 2) 文件头：magic(2B LE)+0x0D0A；magic≥3392（"3392 (PEP 552 deterministic pycs)"）为 16B 头：
//    magic(4B)+flags(4B)+（时间戳模式: mtime(4B)+size(4B)｜哈希模式(flags&1): hash(8B)）；
//    之前为 12B 头：magic(4B)+mtime(4B)+size(4B)。3.11+ 头部字段无变化（变化在 code object 字段）。
// 3) marshal 类型码：CPython Python/marshal.c（本批核对 v3.6.15/v3.8.0/v3.10.7/v3.11.0/v3.12.0
//    五个 tag 的源文件，并用真实 CPython 3.10.11/3.11.16/3.12.14 编译出的 pyc 解到精确 EOF 双重验证）：
//    TYPE_CODE 'c' 字段序按 magic 分三档——
//    · legacy(≤3409，3.5-3.7)：argcount,kwonlyargcount,nlocals,stacksize,flags + code,consts,names,
//      varnames,freevars,cellvars,filename,name + firstlineno + lnotab
//    · posonly(3410-3449，3.8-3.10，PEP 570)：在 argcount 后加 posonlyargcount；3.10 起 lnotab 字段
//      语义改为 linetable（PEP 626），但字段位置/数量不变，本引擎按原始 bytes 透出不解码
//    · modern(≥3450，3.11+)：argcount,posonlyargcount,kwonlyargcount,stacksize,flags（删 nlocals）+
//      code,consts,names,localsplusnames,localspluskinds,filename,name,qualname,firstlineno,linetable,
//      exceptiontable（qualname 新增、varnames/freevars/cellvars 合并为 localsplus、异常表末位）
//    ref 机制（w_ref/r_ref_reserve）：类型码高位置 FLAG_REF(0x80) 的对象按先序保留索引、读完后回填，
//    后续 TYPE_REF 'r' 按索引复用——同一字符串/元组重复出现时必走 'r'，这是手写 marshal 最易翻车点。
// 4) Stegosaurus 隐写协议证据见 pycStego.ts 头注。

export const PYC_MAX_BYTES = 20 * 1024 * 1024; // 文件解析红线：20MB

/** magic 区间 → Python 版本（来源：_bootstrap_external.py magic 历史注释表）。 */
export interface PycMagicRange {
  min: number;
  max: number;
  version: string; // 显示用版本号
  layout: 'legacy' | 'posonly' | 'modern'; // code object 字段布局档位（按 magic 阈值，见头注 3）
  note?: string;
}

export const PYC_MAGIC_RANGES: readonly PycMagicRange[] = [
  { min: 3310, max: 3351, version: '3.5', layout: 'legacy', note: '3350=3.5b3 定稿，3351=3.5.2+' },
  { min: 3360, max: 3379, version: '3.6', layout: 'legacy', note: '3370=wordcode（2字节定长指令），3379=3.6 定稿' },
  { min: 3390, max: 3391, version: '3.7', layout: 'legacy', note: 'PEP 552 之前：12 字节头' },
  { min: 3392, max: 3394, version: '3.7', layout: 'legacy', note: '3392=PEP 552：16 字节头' },
  { min: 3400, max: 3409, version: '3.8', layout: 'legacy', note: '3.8 早期 alpha，PEP 570 之前' },
  { min: 3410, max: 3413, version: '3.8', layout: 'posonly', note: '3410=PEP 570 posonlyargcount' },
  { min: 3420, max: 3425, version: '3.9', layout: 'posonly' },
  { min: 3430, max: 3439, version: '3.10', layout: 'posonly', note: '3431=PEP 626 行表语义改 linetable' },
  { min: 3450, max: 3495, version: '3.11', layout: 'modern', note: '3450=异常表，3460=co_qualname，3495=3.11 定稿' },
  { min: 3500, max: 3531, version: '3.12', layout: 'modern', note: '3531=3.12 定稿' },
  { min: 3550, max: 3600, version: '3.13', layout: 'modern', note: '3550 起；布局按 3.12 档尽力解析（未经向量验证）' },
];

const PEP552_MAGIC = 3392; // "3392 (PEP 552 deterministic pycs)"：16 字节头起点

export interface PycHeader {
  magic: number; // 头 2 字节小端数值
  magicBytes: Uint8Array; // 原始 4 字节（magic+\r\n）
  version: string;
  versionNote: string | null;
  layout: PycMagicRange['layout'];
  headerSize: number; // 12（<3392）或 16（PEP 552）
  flags: number | null; // 3.7+（PEP 552 位字段），更早为 null
  hashBased: boolean; // PEP 552 哈希校验模式
  timestamp: number | null; // 时间戳模式：源码 mtime（UTC 秒）
  sourceSize: number | null;
  hash: Uint8Array | null; // 哈希模式：8 字节 SipHash
  dataOffset: number; // marshal 流起始偏移
}

/** marshal 反序列化后的值模型（覆盖 3.5-3.12 pyc 中实际会出现的全部分支）。 */
export type MarshalValue =
  | { kind: 'none' }
  | { kind: 'ellipsis' }
  | { kind: 'bool'; value: boolean }
  | { kind: 'int'; value: number }
  | { kind: 'bigint'; value: bigint } // TYPE_LONG 任意精度（|value| ≥ 2^31 走这里）
  | { kind: 'float'; value: number }
  | { kind: 'complex'; real: number; imag: number }
  | { kind: 'str'; value: string }
  | { kind: 'bytes'; value: Uint8Array }
  | { kind: 'tuple'; items: MarshalValue[] }
  | { kind: 'list'; items: MarshalValue[] }
  | { kind: 'set'; items: MarshalValue[] }
  | { kind: 'frozenset'; items: MarshalValue[] }
  | { kind: 'dict'; entries: Array<{ key: MarshalValue; value: MarshalValue }> }
  | { kind: 'code'; code: PycCodeObject };

/** 完整 code object（三档布局的字段并集；不适用的档位为 null/空，见头注 3）。 */
export interface PycCodeObject {
  argcount: number;
  posonlyargcount: number; // 3.5-3.8a 无此字段，恒 0
  kwonlyargcount: number;
  nlocals: number | null; // 3.11+ marshal 已删该字段
  stacksize: number;
  flags: number;
  code: Uint8Array; // co_code 原始字节（3.6+ 为 2 字节定长 wordcode）
  codeOffset: number; // co_code 数据在文件中的绝对偏移（字节级 patch/隐写嵌入用）
  exceptiontable: Uint8Array | null; // 3.11+
  consts: MarshalValue[];
  names: string[]; // co_names
  varnames: string[] | null; // 3.10-
  freevars: string[] | null; // 3.10-
  cellvars: string[] | null; // 3.10-
  localsplusnames: string[] | null; // 3.11+（varnames+freevars+cellvars 合并）
  localspluskinds: Uint8Array | null; // 3.11+（与 localsplusnames 等长的种类字节）
  filename: string;
  name: string;
  qualname: string | null; // 3.11+
  firstlineno: number;
  linetable: Uint8Array; // 原始行表字节（3.9- 名 lnotab，3.10+ 语义已变，本引擎不解码）
  startOffset: number; // 本 code object 序列化区间起点（类型码字节处）
  endOffset: number; // 本 code object 序列化区间终点（不含）
}

export interface PycParseResult {
  header: PycHeader;
  root: PycCodeObject; // 模块级 code object
  endOffset: number; // marshal 流结束偏移
  trailingBytes: number; // marshal 流之后的尾附字节数（binwalk 式嵌入高发位）
  anomalies: string[]; // 解析期异常（截断/未知类型码/宽松转换等），供 UI 展示
}

const latin1 = new TextDecoder('latin1');
const utf8Strict = new TextDecoder('utf-8', { fatal: true });
const utf8Lossy = new TextDecoder('utf-8');

const MARSHAL_MAX_DEPTH = 500; // 递归深度红线（CPython marshal.c MAX_MARSHAL_STACK_DEPTH=2000，CTF 场景 500 足够且防爆栈）

// pyc 头：校验 magic+\r\n 并映射版本区间；不做 marshal 之外的事。
const readHeader = (bytes: Uint8Array): PycHeader => {
  if (bytes.length < 12) throw new Error(`不是 pyc 文件：总长 ${bytes.length} 不足以容纳 12 字节头`);
  if (bytes[2] !== 0x0d || bytes[3] !== 0x0a) {
    throw new Error(`不是 pyc 文件：magic 后两字节应为 0D 0A，实际 ${bytes[2].toString(16)} ${bytes[3].toString(16)}`);
  }
  const magic = bytes[0] | (bytes[1] << 8);
  const range = PYC_MAGIC_RANGES.find(item => magic >= item.min && magic <= item.max);
  if (!range) {
    throw new Error(`未知 pyc magic：0x${magic.toString(16)}（${magic}），不在 3.5-3.13 已知区间（3310-3600）内`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const headerSize = magic >= PEP552_MAGIC ? 16 : 12;
  let flags: number | null = null;
  let hashBased = false;
  let timestamp: number | null = null;
  let sourceSize: number | null = null;
  let hash: Uint8Array | null = null;
  if (headerSize === 16) {
    flags = view.getUint32(4, true);
    hashBased = (flags & 1) !== 0;
    if (hashBased) {
      hash = bytes.slice(8, 16);
    } else {
      timestamp = view.getUint32(8, true);
      sourceSize = view.getUint32(12, true);
    }
  } else {
    timestamp = view.getUint32(4, true);
    sourceSize = view.getUint32(8, true);
  }
  return {
    magic,
    magicBytes: bytes.slice(0, 4),
    version: range.version,
    versionNote: range.note ?? null,
    layout: range.layout,
    headerSize,
    flags,
    hashBased,
    timestamp,
    sourceSize,
    hash,
    dataOffset: headerSize,
  };
};

// marshal 读取器：严格镜像 CPython r_object 的 ref 语义（先序保留索引、读完回填）。
class MarshalReader {
  private readonly bytes: Uint8Array;
  private readonly view: DataView;
  private readonly layout: PycMagicRange['layout'];
  private pos: number;
  private depth = 0;
  private readonly refs: MarshalValue[] = [];
  readonly warnings: string[] = [];
  endOffset = 0;

  constructor(bytes: Uint8Array, start: number, layout: PycMagicRange['layout']) {
    this.bytes = bytes;
    this.layout = layout;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = start;
  }

  readTop(): MarshalValue {
    const value = this.readObject();
    this.endOffset = this.pos;
    return value;
  }

  private u8(where: string): number {
    if (this.pos + 1 > this.bytes.length) throw new Error(`marshal 流在偏移 ${this.pos} 截断（读 ${where}）`);
    const value = this.bytes[this.pos];
    this.pos += 1;
    return value;
  }

  private i32(where: string): number {
    if (this.pos + 4 > this.bytes.length) throw new Error(`marshal 流在偏移 ${this.pos} 截断（读 ${where}）`);
    const value = this.view.getInt32(this.pos, true);
    this.pos += 4;
    return value;
  }

  private f64(where: string): number {
    if (this.pos + 8 > this.bytes.length) throw new Error(`marshal 流在偏移 ${this.pos} 截断（读 ${where}）`);
    const value = this.view.getFloat64(this.pos, true);
    this.pos += 8;
    return value;
  }

  private take(length: number, where: string): Uint8Array {
    if (length < 0 || this.pos + length > this.bytes.length) {
      throw new Error(`marshal 流在偏移 ${this.pos} 截断（读 ${where}，需 ${length} 字节，剩余 ${this.bytes.length - this.pos}）`);
    }
    const chunk = this.bytes.subarray(this.pos, this.pos + length);
    this.pos += length;
    return chunk;
  }

  private decodeUtf8(raw: Uint8Array, where: string): string {
    try {
      return utf8Strict.decode(raw);
    } catch {
      this.warnings.push(`${where} 的 UTF-8 字节非法，已按 U+FFFD 替换解码`);
      return utf8Lossy.decode(raw);
    }
  }

  // 容器字段（names/varnames/...）按 CPython 恒为字符串元组；宽容损坏流：非字符串项降级为其文本形态并记警告。
  private toStringList(value: MarshalValue, where: string): string[] {
    if (value.kind !== 'tuple' && value.kind !== 'list') {
      this.warnings.push(`${where} 期望字符串元组，实际 ${value.kind}`);
      return [];
    }
    return value.items.map(item => {
      if (item.kind === 'str') return item.value;
      this.warnings.push(`${where} 含非字符串项（${item.kind}），已降级展示`);
      return marshalToDisplay(item);
    });
  }

  private readObject(): MarshalValue {
    if (this.depth >= MARSHAL_MAX_DEPTH) throw new Error(`marshal 嵌套深度超过 ${MARSHAL_MAX_DEPTH} 红线（疑似恶意构造）`);
    this.depth += 1;
    try {
      return this.readObjectInner();
    } finally {
      this.depth -= 1;
    }
  }

  private readObjectInner(): MarshalValue {
    const typeByte = this.u8('类型码');
    const hasFlag = (typeByte & 0x80) !== 0;
    const type = typeByte & 0x7f;
    // FLAG_REF：先占索引（CPython r_ref_reserve 同序），对象读完回填——保证嵌套容器内子对象的
    // ref 编号与写入侧一致（后写父先占号），TYPE_REF 才能对上。
    let refIndex = -1;
    if (hasFlag) {
      refIndex = this.refs.length;
      this.refs.push({ kind: 'none' });
    }
    const value = this.readBody(type, typeByte);
    if (hasFlag) this.refs[refIndex] = value;
    return value;
  }

  private readBody(type: number, typeByte: number): MarshalValue {
    const ch = String.fromCharCode(type);
    switch (ch) {
      case 'N': return { kind: 'none' };
      case '.': return { kind: 'ellipsis' };
      case 'F': return { kind: 'bool', value: false };
      case 'T': return { kind: 'bool', value: true };
      case 'i': {
        return { kind: 'int', value: this.i32('TYPE_int') };
      }
      case 'g': return { kind: 'float', value: this.f64('TYPE_BINARY_FLOAT') };
      case 'y': {
        const real = this.f64('TYPE_BINARY_COMPLEX.real');
        const imag = this.f64('TYPE_BINARY_COMPLEX.imag');
        return { kind: 'complex', real, imag };
      }
      case 'l': {
        // TYPE_LONG：int32 符号+数量，随后 n 个 uint16 LE 位块，每位块仅低 15 位有效（基 2^15）。
        // 证据：CPython marshal.c w_PyLong 按掩码 0x7FFF 逐块写出；本机 Python 3.10
        // marshal.dumps(123456789012345678901234567890) 实测 7 块、按 2^16 重组不等于原值、按 2^15 重组还原。
        const signed = this.i32('TYPE_LONG.ndigits');
        const count = Math.abs(signed);
        if (this.pos + count * 2 > this.bytes.length) {
          throw new Error(`marshal 流在偏移 ${this.pos} 截断（TYPE_LONG 需 ${count} 个位块）`);
        }
        let magnitude = 0n;
        for (let index = count - 1; index >= 0; index -= 1) {
          const digit = this.view.getUint16(this.pos + index * 2, true);
          if ((digit & 0x8000) !== 0) this.warnings.push(`TYPE_LONG 位块 ${index} 的高位（bit15）非零（非 CPython 产物）`);
          magnitude = (magnitude << 15n) | BigInt(digit & 0x7fff);
        }
        this.pos += count * 2;
        const value = signed < 0 ? -magnitude : magnitude;
        const asNumber = Number(value);
        return Number.isSafeInteger(asNumber) ? { kind: 'int', value: asNumber } : { kind: 'bigint', value };
      }
      case 's': {
        const length = this.i32('TYPE_STRING.len');
        return { kind: 'bytes', value: this.take(length, 'TYPE_STRING').slice() };
      }
      case 't': // TYPE_INTERNED：长度前缀 UTF-8
      case 'u': {
        const length = this.i32(`TYPE_${ch === 't' ? 'INTERNED' : 'UNICODE'}.len`);
        return { kind: 'str', value: this.decodeUtf8(this.take(length, 'TYPE_UNICODE'), 'TYPE_UNICODE') };
      }
      case 'a':
      case 'A': {
        const length = this.i32(`TYPE_ASCII${ch === 'A' ? '_INTERNED' : ''}.len`);
        return { kind: 'str', value: latin1.decode(this.take(length, 'TYPE_ASCII')) };
      }
      case 'z':
      case 'Z': {
        const length = this.u8(`TYPE_SHORT_ASCII${ch === 'Z' ? '_INTERNED' : ''}.len`);
        return { kind: 'str', value: latin1.decode(this.take(length, 'TYPE_SHORT_ASCII')) };
      }
      case ')': {
        const count = this.u8('TYPE_SMALL_TUPLE.len');
        const items: MarshalValue[] = [];
        for (let index = 0; index < count; index += 1) items.push(this.readObject());
        return { kind: 'tuple', items };
      }
      case '(': {
        const count = this.readCount('TYPE_TUPLE');
        const items: MarshalValue[] = [];
        for (let index = 0; index < count; index += 1) items.push(this.readObject());
        return { kind: 'tuple', items };
      }
      case '[': {
        const count = this.readCount('TYPE_LIST');
        const items: MarshalValue[] = [];
        for (let index = 0; index < count; index += 1) items.push(this.readObject());
        return { kind: 'list', items };
      }
      case '<':
      case '>': {
        const count = this.readCount(`TYPE_${ch === '<' ? 'SET' : 'FROZENSET'}`);
        const items: MarshalValue[] = [];
        for (let index = 0; index < count; index += 1) items.push(this.readObject());
        return { kind: ch === '<' ? 'set' : 'frozenset', items };
      }
      case '{': {
        // Python3 marshal：键值对连读，键位 TYPE_NULL('0') 结束
        const entries: Array<{ key: MarshalValue; value: MarshalValue }> = [];
        for (;;) {
          if (this.pos >= this.bytes.length) throw new Error(`marshal 流在偏移 ${this.pos} 截断（TYPE_DICT 未闭合）`);
          if (this.bytes[this.pos] === 0x30) {
            this.pos += 1;
            break;
          }
          const key = this.readObject();
          const dictValue = this.readObject();
          entries.push({ key, value: dictValue });
        }
        return { kind: 'dict', entries };
      }
      case 'r': {
        const index = this.i32('TYPE_REF.index');
        if (index < 0 || index >= this.refs.length) {
          throw new Error(`marshal TYPE_REF 索引越界：${index}（已登记 ${this.refs.length} 个）`);
        }
        return this.refs[index];
      }
      case 'c':
        return { kind: 'code', code: this.readCode() };
      case '0':
        throw new Error("marshal TYPE_NULL 只能作为 dict 的结束标记出现（顶层独立 NULL 非法）");
      case 'f': {
        // 遗留文本浮点（3.5+ 编译器不再产出，兼容读取）
        const length = this.i32('TYPE_FLOAT.len');
        return { kind: 'float', value: Number.parseFloat(latin1.decode(this.take(length, 'TYPE_FLOAT'))) };
      }
      case 'x': {
        const real = this.readLegacyFloatText('TYPE_COMPLEX.real');
        const imag = this.readLegacyFloatText('TYPE_COMPLEX.imag');
        return { kind: 'complex', real, imag };
      }
      default:
        throw new Error(`marshal 未知类型码 0x${typeByte.toString(16)} 于偏移 ${this.pos - 1}（'${ch}'）`);
    }
  }

  private readCount(where: string): number {
    const count = this.i32(where);
    if (count < 0) throw new Error(`marshal ${where} 元素数为负：${count}`);
    // 元素数不可能超过剩余字节数（每个元素至少 1 字节类型码），防恶意声明撑爆内存
    if (count > this.bytes.length - this.pos) {
      throw new Error(`marshal ${where} 元素数 ${count} 超过剩余字节 ${this.bytes.length - this.pos}（损坏流）`);
    }
    return count;
  }

  private readLegacyFloatText(where: string): number {
    const length = this.i32(where);
    return Number.parseFloat(latin1.decode(this.take(length, where)));
  }

  // TYPE_CODE：字段序按 magic 布局档位（证据见头注 3）
  private readCode(): PycCodeObject {
    const startOffset = this.pos - 1;
    const argcount = this.i32('code.argcount');
    let posonlyargcount = 0;
    if (this.layout !== 'legacy') posonlyargcount = this.i32('code.posonlyargcount');
    const kwonlyargcount = this.i32('code.kwonlyargcount');
    let nlocals: number | null = null;
    if (this.layout === 'legacy' || this.layout === 'posonly') nlocals = this.i32('code.nlocals');
    const stacksize = this.i32('code.stacksize');
    const flags = this.i32('code.flags');

    const codeValue = this.readObject();
    if (codeValue.kind !== 'bytes') throw new Error(`code.co_code 期望 bytes，实际 ${codeValue.kind}`);
    const codeOffset = this.pos - codeValue.value.length;
    let exceptiontable: Uint8Array | null = null;

    const consts = this.readSeq('code.consts');
    const names = this.toStringList(this.readObject(), 'code.names');

    let varnames: string[] | null = null;
    let freevars: string[] | null = null;
    let cellvars: string[] | null = null;
    let localsplusnames: string[] | null = null;
    let localspluskinds: Uint8Array | null = null;
    if (this.layout === 'modern') {
      localsplusnames = this.toStringList(this.readObject(), 'code.localsplusnames');
      const kinds = this.readObject();
      if (kinds.kind !== 'bytes') throw new Error(`code.localspluskinds 期望 bytes，实际 ${kinds.kind}`);
      localspluskinds = kinds.value;
    } else {
      varnames = this.toStringList(this.readObject(), 'code.varnames');
      freevars = this.toStringList(this.readObject(), 'code.freevars');
      cellvars = this.toStringList(this.readObject(), 'code.cellvars');
    }

    const filename = this.stringOf(this.readObject(), 'code.filename');
    const name = this.stringOf(this.readObject(), 'code.name');
    let qualname: string | null = null;
    if (this.layout === 'modern') qualname = this.stringOf(this.readObject(), 'code.qualname');
    const firstlineno = this.i32('code.firstlineno');
    const linetableValue = this.readObject();
    if (linetableValue.kind !== 'bytes') throw new Error(`code.linetable 期望 bytes，实际 ${linetableValue.kind}`);
    const linetable = linetableValue.value;
    if (this.layout === 'modern') {
      const tableValue = this.readObject();
      if (tableValue.kind !== 'bytes') throw new Error(`code.exceptiontable 期望 bytes，实际 ${tableValue.kind}`);
      exceptiontable = tableValue.value;
    }

    return {
      argcount,
      posonlyargcount,
      kwonlyargcount,
      nlocals,
      stacksize,
      flags,
      code: codeValue.value,
      codeOffset,
      exceptiontable,
      consts,
      names,
      varnames,
      freevars,
      cellvars,
      localsplusnames,
      localspluskinds,
      filename,
      name,
      qualname,
      firstlineno,
      linetable,
      startOffset,
      endOffset: this.pos,
    };
  }

  private readSeq(where: string): MarshalValue[] {
    const value = this.readObject();
    if (value.kind !== 'tuple' && value.kind !== 'list') {
      this.warnings.push(`${where} 期望元组，实际 ${value.kind}，按空处理`);
      return [];
    }
    return value.items;
  }

  private stringOf(value: MarshalValue, where: string): string {
    if (value.kind === 'str') return value.value;
    this.warnings.push(`${where} 期望字符串，实际 ${value.kind}，降级展示`);
    return marshalToDisplay(value);
  }
}

/** 值 → 短文本形态（诊断/降级展示用，非反编译）。 */
export const marshalToDisplay = (value: MarshalValue): string => {
  switch (value.kind) {
    case 'none': return 'None';
    case 'ellipsis': return '...';
    case 'bool': return value.value ? 'True' : 'False';
    case 'int': return String(value.value);
    case 'bigint': return `${value.value}`;
    case 'float': return String(value.value);
    case 'complex': return `${value.real}${value.imag >= 0 ? '+' : ''}${value.imag}j`;
    case 'str': return value.value;
    case 'bytes': return `b'${latin1.decode(value.value)}'`;
    case 'tuple': return `(${value.items.map(marshalToDisplay).join(', ')})`;
    case 'list': return `[${value.items.map(marshalToDisplay).join(', ')}]`;
    case 'set': return `{${value.items.map(marshalToDisplay).join(', ')}}<set>`;
    case 'frozenset': return `{${value.items.map(marshalToDisplay).join(', ')}}<frozenset>`;
    case 'dict': return `{${value.entries.map(entry => `${marshalToDisplay(entry.key)}: ${marshalToDisplay(entry.value)}`).join(', ')}}`;
    case 'code': return `<code ${value.code.name}>`;
  }
};

/**
 * 独立 marshal 反序列化（测试与高级用途）：从 offset 起读一个对象。
 * magic 用于决定 code object 字段布局（3392 前后的头差异不影响 marshal 流本身）。
 */
export const unmarshalPython = (
  bytes: Uint8Array,
  options: { offset?: number; magic?: number } = {},
): { value: MarshalValue; endOffset: number; warnings: string[] } => {
  const magic = options.magic ?? 3439; // 缺省按 3.10（CTF 最常见）
  const range = PYC_MAGIC_RANGES.find(item => magic >= item.min && magic <= item.max);
  if (!range) throw new Error(`未知 magic：${magic}`);
  const reader = new MarshalReader(bytes, options.offset ?? 0, range.layout);
  const value = reader.readTop();
  return { value, endOffset: reader.endOffset, warnings: reader.warnings };
};

/** pyc 主入口：头解析 + marshal 流反序列化 + 尾附检测。 */
export const parsePyc = (bytes: Uint8Array): PycParseResult => {
  if (bytes.length > PYC_MAX_BYTES) {
    throw new Error(`pyc 大小 ${bytes.length} 超过 20MB 上限，拒绝解析`);
  }
  const header = readHeader(bytes);
  const reader = new MarshalReader(bytes, header.dataOffset, header.layout);
  const value = reader.readTop();
  const anomalies = [...reader.warnings];
  const trailingBytes = bytes.length - reader.endOffset;
  if (trailingBytes > 0) {
    anomalies.push(`marshal 流结束于偏移 ${reader.endOffset}，其后仍有 ${trailingBytes} 字节尾附数据（binwalk 式嵌入高发位）`);
  }
  if (value.kind !== 'code') {
    throw new Error(`pyc 顶层对象应是 code object，实际 ${value.kind}（不是编译产物或已损坏）`);
  }
  return { header, root: value.code, endOffset: reader.endOffset, trailingBytes, anomalies };
};

/** code object 树先序遍历（模块→按 co_consts 顺序递归子 code，与 Stegosaurus 建栈顺序一致）。 */
export const walkCodeObjects = (root: PycCodeObject): PycCodeObject[] => {
  const stack: PycCodeObject[] = [root];
  const out: PycCodeObject[] = [];
  while (stack.length > 0) {
    const current = stack.pop() as PycCodeObject;
    out.push(current);
    for (let index = current.consts.length - 1; index >= 0; index -= 1) {
      const item = current.consts[index];
      if (item.kind === 'code') stack.push(item.code);
    }
  }
  return out;
};

export interface PycStringItem { value: string; where: string }
export interface PycBytesItem { length: number; hex: string; latin1: string; where: string }
export interface PycFlagCandidate { value: string; where: string; pattern: string }

export interface PycCodeSummary {
  name: string;
  qualname: string | null;
  filename: string;
  firstlineno: number;
  argcount: number;
  kwonlyargcount: number;
  flags: number;
  codeBytes: number; // co_code 长度（wordcode 下=指令数×2）
  constCount: number;
}

/** CTF 摘要：版本 + 全部 code object 的常量/名字 + flag 候选。 */
export interface PycInfo {
  header: PycHeader;
  moduleDocstring: string | null;
  codeCount: number;
  totalCodeBytes: number;
  codes: PycCodeSummary[];
  strings: PycStringItem[]; // 全部 co_consts 中的字符串（flag 最常见藏点），按 code object 归属
  bytesConsts: PycBytesItem[]; // 全部 co_consts 中的 bytes（hex+latin1 并排）
  names: string[]; // co_names 合并去重（全局名/属性名）
  varnames: string[]; // 3.10- co_varnames；3.11+ 用 localsplusnames 兜底
  freevars: string[];
  cellvars: string[];
  flagCandidates: PycFlagCandidate[];
  anomalies: string[];
}

const FLAG_KV = /\b(?:flag|ctf|key|token|secret|pass(?:word)?|pwd)\s*[{=:]\s*[!-~]{1,180}/gi;
const FLAG_BRACED = /\b[A-Za-z][A-Za-z0-9_]{0,23}\{[!-~]{2,180}\}/g;

const scanFlagCandidates = (text: string, where: string, sink: Map<string, PycFlagCandidate>): void => {
  for (const pattern of [FLAG_KV, FLAG_BRACED]) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const value = match[0];
      if (!sink.has(value)) sink.set(value, { value, where, pattern: pattern === FLAG_KV ? '键词型 flag/ctf/key…{=:' : '花括号型 xxx{…}' });
    }
  }
};

const codeDisplayName = (code: PycCodeObject): string => code.qualname ?? code.name;

/** 面向 CTF 的 pyc 摘要提取（对标"pyc 常量/字符串提取"）。 */
export const extractPycInfo = (bytes: Uint8Array): PycInfo => {
  const { header, root, anomalies } = parsePyc(bytes);
  const codes = walkCodeObjects(root);
  const strings: PycStringItem[] = [];
  const bytesConsts: PycBytesItem[] = [];
  const names = new Set<string>();
  const varnames = new Set<string>();
  const freevars = new Set<string>();
  const cellvars = new Set<string>();
  const candidates = new Map<string, PycFlagCandidate>();
  let totalCodeBytes = 0;

  const collectConsts = (code: PycCodeObject, prefix: string): void => {
    code.consts.forEach((item, index) => {
      const where = `${prefix}.consts[${index}]`;
      if (item.kind === 'str') {
        strings.push({ value: item.value, where });
        scanFlagCandidates(item.value, where, candidates);
      } else if (item.kind === 'bytes') {
        bytesConsts.push({
          length: item.value.length,
          hex: Array.from(item.value, byte => byte.toString(16).padStart(2, '0')).join(''),
          latin1: latin1.decode(item.value),
          where,
        });
        scanFlagCandidates(latin1.decode(item.value), where, candidates);
      } else if (item.kind === 'code') {
        collectConsts(item.code, `${prefix}/<code:${codeDisplayName(item.code)}@${index}>`);
      }
    });
  };

  for (const code of codes) {
    for (const name of code.names) names.add(name);
    if (code.varnames) for (const name of code.varnames) varnames.add(name);
    if (code.freevars) for (const name of code.freevars) freevars.add(name);
    if (code.cellvars) for (const name of code.cellvars) cellvars.add(name);
    if (code.localsplusnames) for (const name of code.localsplusnames) varnames.add(name);
    totalCodeBytes += code.code.length;
    if (code.code.length % 2 === 1 && header.layout !== 'legacy') {
      anomalies.push(`code object ${codeDisplayName(code)} 的 co_code 长度 ${code.code.length} 为奇数（wordcode 应恒为偶数，疑似手工篡改）`);
    }
  }
  collectConsts(root, `<module:${root.name}>`);

  const first = root.consts[0];
  const moduleDocstring = first && first.kind === 'str' ? first.value : null;
  if (moduleDocstring !== null) scanFlagCandidates(moduleDocstring, '<module>.docstring', candidates);

  return {
    header,
    moduleDocstring,
    codeCount: codes.length,
    totalCodeBytes,
    codes: codes.map(code => ({
      name: code.name,
      qualname: code.qualname,
      filename: code.filename,
      firstlineno: code.firstlineno,
      argcount: code.argcount,
      kwonlyargcount: code.kwonlyargcount,
      flags: code.flags,
      codeBytes: code.code.length,
      constCount: code.consts.length,
    })),
    strings,
    bytesConsts,
    names: [...names],
    varnames: [...varnames],
    freevars: [...freevars],
    cellvars: [...cellvars],
    flagCandidates: [...candidates.values()],
    anomalies,
  };
};
