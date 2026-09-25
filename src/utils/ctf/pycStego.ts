// Stegosaurus pyc 隐写提取 + 隐写迹象检测（对标随波逐流"Stegosaurus pyc/pyo 隐写提取"）。
// 纯函数、只读字节、无 DOM/eval/网络；依赖 pycParse 的 marshal 反序列化。
//
// 嵌入协议证据（逐行核对 AngelKitty/stegosaurus 仓库 stegosaurus.py 全文，ISC 许可，作者 Jon Herron；
// 该文件为单文件自包含实现，本批直接 curl raw.githubusercontent.com 取回 8271 字节源码）：
// - 载体槽位：Python 3.6 起 wordcode 化（每条指令恒 2 字节：opcode+arg），无参指令
//   （opcode < opcode.HAVE_ARGUMENT，3.6-3.12 实测恒为 90）的 arg 字节永不执行——
//   `_bytesAvailableForPayload`：对每个 code object 的 co_code，凡偶偏移 i 且 bytes[i] < 90，
//   i+1 处即一个可用槽。无 archive 容器、无 magic 头：payload 就是按槽序原样写入的 UTF-8 字节，
//   写完剩下的槽全部清零（`_embedPayload`），提取侧遇 0x00 槽即终止（`_extractPayload`）——
//   0x00 终止符是协议唯一的边界标记。
// - 槽序：`_createMutableBytecodeStack` 按"模块→co_consts 顺序递归子 code"建栈，再 reversed 遍历——
//   即最深的 code object 先装、模块级最后装。提取必须复刻这个顺序才能读出正确 payload。
// - 防 strings 泄漏（-e explodeAfter）：槽前连续可打印字节数 ≥ explodeAfter 时跳过该槽并清零计数；
//   CLI 默认 math.inf（不跳过）。嵌入用了 -e N 时提取需同 N——本引擎默认 ∞，参数可传。
// - 原版 Jon Herron 工具（数据流死代码分析版）同样把 payload 放进无参指令的 arg 字节但不保证
//   0x00 终止：本引擎额外输出"全部非零槽字节"兜底读法，避免漏提原版格式。
import { parsePyc, walkCodeObjects } from './pycParse';
import type { PycCodeObject, PycParseResult } from './pycParse';

export const STEGO_HAVE_ARGUMENT = 90; // opcode.HAVE_ARGUMENT（3.6/3.10/3.11/3.12 本机实测均 90）

// Python string.printable：数字+大小写字母+标点+空白（空格 \t \n \r \x0b \x0c）
const PRINTABLE = new Uint8Array(256);
for (let byte = 0x30; byte <= 0x39; byte += 1) PRINTABLE[byte] = 1;
for (let byte = 0x41; byte <= 0x5a; byte += 1) PRINTABLE[byte] = 1;
for (let byte = 0x61; byte <= 0x7a; byte += 1) PRINTABLE[byte] = 1;
for (const byte of [
  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
  0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
  0x7b, 0x7c, 0x7d, 0x7e, 0x20, 0x09, 0x0a, 0x0d, 0x0b, 0x0c,
]) PRINTABLE[byte] = 1;

export interface StegoSlot {
  code: PycCodeObject;
  slotIndex: number; // 槽在 co_code 内的字节偏移（= 指令偏移 + 1）
}

/**
 * 协议槽位枚举：严格复刻 stegosaurus `_bytesAvailableForPayload` 的产出顺序。
 * codes 传先序遍历结果（walkCodeObjects），内部按 reversed 遍历（最深 code 先）。
 */
export const iterateStegoSlots = (codes: PycCodeObject[], explodeAfter = Infinity): StegoSlot[] => {
  const slots: StegoSlot[] = [];
  for (let index = codes.length - 1; index >= 0; index -= 1) {
    const code = codes[index];
    const bytes = code.code;
    let consecutivePrintable = 0;
    for (let i = 0; i < bytes.length; i += 1) {
      if (PRINTABLE[bytes[i]] === 1) consecutivePrintable += 1;
      else consecutivePrintable = 0;
      if (i % 2 === 0 && bytes[i] < STEGO_HAVE_ARGUMENT) {
        if (i + 1 >= bytes.length) break; // 奇数长度 co_code：最后一字节不构成完整指令
        if (consecutivePrintable >= explodeAfter) {
          consecutivePrintable = 0;
          continue;
        }
        slots.push({ code, slotIndex: i + 1 });
      }
    }
  }
  return slots;
};

export interface StegosaurusResult {
  payloads: string[]; // 协议读法（0x00 终止）优先；非零槽兜底读法（原版工具无终止符时）不同才追加
  detail: string[]; // 人审线索：每 code object 的槽位统计、非零槽位置、容量
  slotCount: number; // 载体总容量（等价 stegosaurus -r 报告值）
}

/**
 * Stegosaurus 隐写提取（协议读法 = AngelKitty 版 -x 的行为；兜底读法覆盖原版无终止符格式）。
 * 仅支持 wordcode 载体（Python 3.6+，magic ≥ 3360）：3.5 及更早指令变长，无死槽语义。
 */
export const extractStegosaurus = (bytes: Uint8Array, options: { explodeAfter?: number } = {}): StegosaurusResult => {
  const parsed = parsePyc(bytes);
  const detail: string[] = [];
  if (parsed.header.magic < 3360) {
    detail.push(`载体为 Python ${parsed.header.version}（3.6 之前指令变长），不存在 Stegosaurus 死槽，跳过提取`);
    return { payloads: [], detail, slotCount: 0 };
  }
  const codes = walkCodeObjects(parsed.root);
  const slots = iterateStegoSlots(codes, options.explodeAfter ?? Infinity);

  // 协议读法：依槽序收字节，遇 0x00 终止（stegosaurus `_extractPayload` 逐行为一致）
  const protocolBytes: number[] = [];
  for (const slot of slots) {
    const byte = slot.code.code[slot.slotIndex];
    if (byte === 0) break;
    protocolBytes.push(byte);
  }
  const decoder = new TextDecoder('utf-8', { fatal: false });
  const protocolPayload = decoder.decode(Uint8Array.from(protocolBytes));

  // 兜底读法：全部非零槽字节依序拼接（Jon Herron 原版数据流嵌入不写终止符时的形态）
  const allNonzero: number[] = [];
  for (const slot of slots) {
    const byte = slot.code.code[slot.slotIndex];
    if (byte !== 0) allNonzero.push(byte);
  }
  const fallbackPayload = decoder.decode(Uint8Array.from(allNonzero));

  const payloads: string[] = [];
  if (protocolPayload.length > 0) payloads.push(protocolPayload);
  if (fallbackPayload.length > 0 && fallbackPayload !== protocolPayload) payloads.push(fallbackPayload);

  // 人审线索：非零槽集中在哪些 code object、具体字节是什么
  let nonzeroTotal = 0;
  for (const code of codes) {
    const own = slots.filter(slot => slot.code === code && code.code[slot.slotIndex] !== 0);
    nonzeroTotal += own.length;
    if (own.length === 0) continue;
    const preview = own
      .slice(0, 16)
      .map(slot => `${slot.slotIndex}:0x${code.code[slot.slotIndex].toString(16).padStart(2, '0')}`)
      .join(' ');
    detail.push(
      `code object ${code.qualname ?? code.name} 有 ${own.length} 个非零死槽（槽位:字节）${own.length > 16 ? '（前 16 个）' : ''}：${preview}`,
    );
  }
  detail.unshift(
    `载体 Python ${parsed.header.version}，code object ${codes.length} 个，死槽总数 ${slots.length}（容量上限，等价 -r 报告），非零 ${nonzeroTotal} 个`,
  );
  if (protocolBytes.length === 0 && allNonzero.length === 0) {
    detail.push('全部死槽为零字节：未嵌入 payload（干净载体）');
  }
  return { payloads, detail, slotCount: slots.length };
};

export interface PycAnomalyReport {
  anomalies: string[]; // 全部异常/人审线索
  stegoSuspect: boolean; // 死槽非零 → Stegosaurus/手工篡改嫌疑
  slotTotal: number;
  slotNonzero: number;
  nonzeroHex: string; // 非零槽字节序列（hex），空串=全零
}

const OPCODE_EXTENDED_ARG = 144;
const OPCODE_JUMP_FORWARD = 110;
const OPCODE_JUMP_ABSOLUTE = 113; // 3.6-3.10（3.11 起移除）
const OPCODE_POP_JUMP_IF_FALSE = 114;
const OPCODE_POP_JUMP_IF_TRUE = 115;
const OPCODE_JUMP_BACKWARD = 140; // 3.11+
const OPCODE_JUMP_BACKWARD_NO_INTERRUPT = 141;

// 跳转目标边界检查（启发式，宁可漏报不误报）：
// 单位证据（本机 CPython 3.10.11/3.11.16/3.12.14 compile+dis 实测）——
// · 3.6-3.9：跳转参数以字节计（JUMP_ABSOLUTE arg=目标字节偏移；JUMP_FORWARD 目标=i+2+arg）
// · 3.10+：以 2 字节指令计（绝对目标=arg×2；相对目标=下条指令±arg×2；JUMP_BACKWARD=next−arg×2）
// · 3.11+ 的 POP_JUMP 族编号逐小版本漂移（3.11 拆 forward/backward 变体、3.12 回绝对式），
//   只检查编号稳定的 JUMP_FORWARD/JUMP_BACKWARD(_NO_INTERRUPT)，其余不查避免误报。
const checkJumpBounds = (code: PycCodeObject, magic: number, anomalies: string[]): void => {
  const bytes = code.code;
  const unitScale = magic >= 3435 ? 2 : 1; // 3435（3.10a4 "instruction offsets"）起跳转参数改为指令单位
  let extended = 0;
  let extendedRun = 0;
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const opcode = bytes[i];
    const arg = bytes[i + 1];
    if (opcode === OPCODE_EXTENDED_ARG) {
      extended = ((extended << 16) | arg) >>> 0;
      extendedRun += 1;
      if (extendedRun > 4) {
        anomalies.push(`code object ${code.qualname ?? code.name} 偏移 ${i} 处 EXTENDED_ARG 链超过 4 层（非法）`);
        extended = 0;
        extendedRun = 0;
      }
      continue;
    }
    const fullArg = ((extended << 16) | arg) >>> 0;
    extended = 0;
    extendedRun = 0;
    let target: number | null = null;
    if (opcode === OPCODE_JUMP_FORWARD) {
      target = i + 2 + fullArg * unitScale;
    } else if (magic < 3450 && (opcode === OPCODE_JUMP_ABSOLUTE || opcode === OPCODE_POP_JUMP_IF_FALSE || opcode === OPCODE_POP_JUMP_IF_TRUE)) {
      target = fullArg * unitScale;
    } else if (magic >= 3450 && (opcode === OPCODE_JUMP_BACKWARD || opcode === OPCODE_JUMP_BACKWARD_NO_INTERRUPT)) {
      target = i + 2 - fullArg * 2;
    }
    if (target !== null && (target < 0 || target >= bytes.length)) {
      anomalies.push(
        `code object ${code.qualname ?? code.name} 偏移 ${i} 的跳转目标 ${target} 越界（co_code 长度 ${bytes.length}，疑似篡改或损坏）`,
      );
    }
  }
};

// lnotab 一致性（仅 3.6-3.9，magic 3360-3419）：旧格式为 (地址增量, 行号增量) 无符号字节对，
// 地址累计值不得超出 co_code 长度。3.10+（PEP 626）行表改 varint 编码，不做（启发式记账）。
const checkLnotabBounds = (code: PycCodeObject, anomalies: string[]): void => {
  const table = code.linetable;
  let address = 0;
  for (let i = 0; i + 1 < table.length; i += 2) {
    address += table[i];
  }
  if (address > code.code.length) {
    anomalies.push(
      `code object ${code.qualname ?? code.name} 的 lnotab 地址累计 ${address} 超过 co_code 长度 ${code.code.length}（行表与指令流不一致）`,
    );
  }
};

/**
 * 隐写迹象检测（启发式组合）：
 * 1) 死槽非零（主信号：CPython 汇编器对无参指令 arg 恒写 0，本机 3.10/3.11/3.12 干净样本实测全零）
 * 2) marshal 流尾附数据；3) 奇数长度 co_code；4) 跳转目标越界；5) lnotab 地址越界（3.6-3.9）。
 */
export const detectPycAnomaly = (bytes: Uint8Array): PycAnomalyReport => {
  const parsed: PycParseResult = parsePyc(bytes);
  const anomalies = [...parsed.anomalies];
  const codes = walkCodeObjects(parsed.root);
  const magic = parsed.header.magic;

  let slotTotal = 0;
  let slotNonzero = 0;
  const nonzeroBytes: number[] = [];
  if (magic >= 3360) {
    for (const slot of iterateStegoSlots(codes)) {
      slotTotal += 1;
      const byte = slot.code.code[slot.slotIndex];
      if (byte !== 0) {
        slotNonzero += 1;
        nonzeroBytes.push(byte);
      }
    }
    if (slotNonzero > 0) {
      anomalies.push(
        `${slotNonzero}/${slotTotal} 个死槽（无参指令 arg 字节）非零——CPython 编译器恒写 0，Stegosaurus 隐写或手工篡改嫌疑`,
      );
    }
  }

  for (const code of codes) {
    if (code.code.length % 2 === 1 && magic >= 3360) {
      anomalies.push(`code object ${code.qualname ?? code.name} 的 co_code 长度 ${code.code.length} 为奇数（wordcode 恒偶数，疑似篡改）`);
    }
    checkJumpBounds(code, magic, anomalies);
    if (magic >= 3360 && magic < 3430) checkLnotabBounds(code, anomalies);
  }

  return {
    anomalies,
    stegoSuspect: slotNonzero > 0,
    slotTotal,
    slotNonzero,
    nonzeroHex: nonzeroBytes.map(byte => byte.toString(16).padStart(2, '0')).join(''),
  };
};
