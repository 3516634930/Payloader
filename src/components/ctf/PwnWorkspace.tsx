import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { useLanguage } from '../../appContext';
import { copyToClipboard } from '../../utils/clipboard';
import { useDebouncedCallback } from '../../utils/debounce';
import CheatsheetSection from './CheatsheetSection';
import {
  COMMON_BAD_CHARS,
  analyzeFormatStringLeak,
  checkBadChars,
  parseBadCharSet,
  parsePayloadBytes,
} from '../../utils/ctf/pwnTools';
import type { BadCharReport, FormatStringLeak } from '../../utils/ctf/pwnTools';
import { CYCLIC_PERIODS, buildDeBruijn, findCyclicOffset } from '../../utils/ctf/cyclic';
import type { CyclicLookupResult, CyclicLookupFailure, CyclicPeriod } from '../../utils/ctf/cyclic';
import { parseElf } from '../../utils/ctf/elfParse';
import type { ChecksecItem, ElfInfo } from '../../utils/ctf/elfParse';
import { scanElfGadgets, setCapstoneWasmUrl } from '../../utils/ctf/capstoneBridge';
import type { GadgetHit } from '../../utils/ctf/capstoneBridge';
import {
  collectLibcKeys, computeLibcAddress, computeLibcBase, isPageAligned, libcTailCode,
} from '../../utils/ctf/libcTools';
import {
  SHELLCODE_LIBRARY, buildFmtstrWrite, buildRopChain, buildExpTemplate, bytesToHexEscape,
} from '../../utils/ctf/pwnPayloads';
import { MAX_FILE_BYTES } from '../../utils/ctf/fileDetect';
import '../../styles/ctf-forensics.css';
import '../../styles/pwn-workspace.css';

const PAYLOAD_RENDER_LIMIT = 4096;

// capstone WASM 走应用本地静态资源（public/wasm/，随包分发，零联网）。
setCapstoneWasmUrl(() => new URL('../../wasm/capstone.wasm', document.baseURI).href);

const toHexByte = (value: number): string => `\\x${value.toString(16).padStart(2, '0')}`;
const toHexAddr = (value: number): string => `0x${value.toString(16)}`;
const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

const copyText = (text: string, zh: boolean, label?: string): void => {
  void copyToClipboard(text).then(ok => {
    if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本复制。' : 'Copy failed; select the text manually.', color: 'red' });
    else notifications.show({ message: `${label ?? ''}${zh ? '已复制' : 'Copied'}.`, color: 'teal', autoClose: 1400 });
  });
};

// ---- 文件加载 hook：Pwn 域与逆向域共用 ELF 拖入语义（20MB 上限）----

interface LoadedBinary {
  name: string;
  size: number;
  bytes: Uint8Array;
  elf: ElfInfo;
}

const useBinaryLoader = (zh: boolean): {
  binary: LoadedBinary | null;
  error: string | null;
  loading: boolean;
  loadFile: (file: File) => Promise<void>;
  clear: () => void;
  inputRef: React.RefObject<HTMLInputElement | null>;
} => {
  const [binary, setBinary] = useState<LoadedBinary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const loadFile = useCallback(async (file: File) => {
    if (file.size > MAX_FILE_BYTES) {
      notifications.show({
        title: zh ? '文件过大' : 'File too large',
        message: zh
          ? `「${file.name}」有 ${formatBytes(file.size)}，超过 20MB 上限。请先在本地裁剪后再试。`
          : `"${file.name}" is ${formatBytes(file.size)}, over the 20MB limit.`,
        color: 'red',
      });
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const parsed = parseElf(bytes);
      if (!parsed.ok) {
        setError(zh ? `「${file.name}」不是可解析的 ELF 文件（${parsed.error}）` : `"${file.name}" is not a parseable ELF (${parsed.error})`);
        setBinary(null);
        return;
      }
      setBinary({ name: file.name, size: file.size, bytes, elf: parsed });
    } catch {
      setError(zh ? '读取文件失败，请确认文件仍存在且可访问。' : 'Failed to read the file.');
      setBinary(null);
    } finally {
      setLoading(false);
    }
  }, [zh]);

  const clear = useCallback(() => { setBinary(null); setError(null); }, []);
  return { binary, error, loading, loadFile, clear, inputRef };
};

// ---- checksec 卡 ----

const SEVERITY_LABEL: Record<ChecksecItem['severity'], { zh: string; cls: string }> = {
  ok: { zh: '开启', cls: 'ff-badge-ok' },
  warn: { zh: '可乘', cls: 'ff-badge-warn' },
  info: { zh: '信息', cls: '' },
};

function ChecksecCard({ binary, zh }: { binary: LoadedBinary; zh: boolean }) {
  const { elf } = binary;
  return (
    <section id="pwn-card-checksec" className="ff-card ff-card-flag" aria-label={zh ? 'checksec 保护机制' : 'checksec'}>
      <div className="ff-card-head">
        <strong>{zh ? 'checksec 保护机制一览' : 'checksec'}</strong>
        <span className="ff-size">{binary.name} · {elf.machine} · {elf.eiType}</span>
        {elf.buildId && (
          <button type="button" className="ff-button" onClick={() => copyText(elf.buildId!, zh)} title={zh ? 'BuildID（匹配 libc 版本用）' : 'BuildID (for libc matching)'}>
            BuildID {elf.buildId.slice(0, 8)}… {zh ? '复制' : 'copy'}
          </button>
        )}
      </div>
      <div className="pwn-checksec-grid">
        {elf.checksec.map(item => (
          <article key={item.key} className="pwn-checksec-item">
            <header className="pwn-checksec-head">
              <strong>{item.label}</strong>
              <span className={`ff-badge ${SEVERITY_LABEL[item.severity].cls}`}>{item.value}</span>
            </header>
            <p className="ff-note">{item.advice}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

// ---- libc 工作台 ----

function LibcCard({ binary, zh }: { binary: LoadedBinary; zh: boolean }) {
  const [leakInput, setLeakInput] = useState('');
  const [symbolOffset, setSymbolOffset] = useState('');

  const keys = useMemo(() => collectLibcKeys(binary.elf, binary.bytes), [binary]);
  const leak = useMemo(() => {
    const text = leakInput.trim().replace(/^0[xX]/, '');
    return /^[0-9a-fA-F]{4,16}$/.test(text) ? Number.parseInt(text, 16) : NaN;
  }, [leakInput]);
  const offsetValue = useMemo(() => {
    const text = symbolOffset.trim().replace(/^0[xX]/, '');
    return /^[0-9a-fA-F]+$/.test(text) ? Number.parseInt(text, 16) : NaN;
  }, [symbolOffset]);
  const baseResult = useMemo(
    () => (Number.isFinite(leak) && Number.isFinite(offsetValue) && offsetValue > 0 ? computeLibcBase(leak, offsetValue) : null),
    [leak, offsetValue],
  );

  return (
    <section id="pwn-card-libc" className="ff-card" aria-label={zh ? 'libc 工作台' : 'libc workbench'}>
      <div className="ff-card-head">
        <strong>{zh ? 'libc 工作台：符号偏移 → 基址 → 目标地址' : 'libc workbench: offsets → base → targets'}</strong>
      </div>
      <p className="ff-note">
        {zh
          ? '第一步 ret2libc：puts(puts@got) 拿到泄漏地址；在这里查符号偏移、算基址、得 /bin/sh 与 system 地址。'
          : 'Step 1 of ret2libc: leak via puts(puts@got); look up symbol offsets, compute base, get /bin/sh and system addresses.'}
      </p>
      {keys.symbols.length > 0 ? (
        <div className="pwn-symbol-grid" role="list">
          {keys.symbols.map(sym => (
            <button
              key={sym.name}
              type="button"
              role="listitem"
              className="ff-button pwn-symbol-chip"
              title={zh ? '点击复制偏移' : 'Copy offset'}
              onClick={() => copyText(`0x${sym.offset.toString(16)}`, zh, sym.name + ' ')}
            >
              <span className="pwn-symbol-name">{sym.name}</span>
              <span className="pwn-symbol-offset">{toHexAddr(sym.offset)}</span>
            </button>
          ))}
        </div>
      ) : (
        <p className="ff-note">{zh ? '该文件没有导出符号（可能不是 libc）。' : 'No exported symbols (not a libc?).'}</p>
      )}
      {keys.binsh.length > 0 && (
        <div className="ff-row">
          <span className="ff-label">{zh ? '"/bin/sh" 字符串' : '"/bin/sh" string'}</span>
          {keys.binsh.map(hit => (
            <button
              key={hit.offset}
              type="button"
              className="ff-button"
              title={zh ? '点击复制地址' : 'Copy address'}
              onClick={() => copyText(toHexAddr(hit.offset), zh, '/bin/sh ')}
            >
              <span className="ff-mono">{toHexAddr(hit.offset)}</span>
              <span className="ff-size"> {hit.preview}</span>
            </button>
          ))}
        </div>
      )}
      <div className="ff-controls">
        <label className="ff-label" htmlFor="pwn-libc-leak">{zh ? '泄漏地址' : 'Leaked addr'}</label>
        <input
          id="pwn-libc-leak"
          className="ff-input ff-input-narrow"
          type="text"
          value={leakInput}
          placeholder="0x7f1234567890"
          onChange={event => setLeakInput(event.target.value)}
        />
        <label className="ff-label" htmlFor="pwn-libc-offset">{zh ? '符号偏移' : 'Symbol offset'}</label>
        <input
          id="pwn-libc-offset"
          className="ff-input ff-input-narrow"
          type="text"
          value={symbolOffset}
          placeholder={zh ? '点上方符号自动填入' : 'Click a symbol above'}
          onChange={event => setSymbolOffset(event.target.value)}
        />
        <span className="ff-label">{zh ? 'libc 基址' : 'libc base'}</span>
        {baseResult && !('error' in baseResult) && (
          <>
            <span className="ff-mono pwn-base">{toHexAddr(baseResult.base)}</span>
            {!isPageAligned(baseResult.base) && (
              <span className="ff-badge ff-badge-warn">{zh ? '基址未页对齐（低 12 位非 0）——核对泄漏的到底是哪个符号' : 'Base not page-aligned — verify which symbol leaked'}</span>
            )}
            <span className="ff-badge">{zh ? 'system →' : 'system →'} {computeLibcAddress(baseResult.base, keys.symbols.find(s => s.name === 'system')?.offset ?? 0)}</span>
          </>
        )}
        {baseResult && 'error' in baseResult && <span className="ff-badge ff-badge-warn">{baseResult.error}</span>}
        {Number.isFinite(leak) && (
          <span className="ff-label">{zh ? '尾码' : 'tail'} <span className="ff-mono">{libcTailCode(leak)}</span></span>
        )}
      </div>
      <p className="ff-note">
        {zh
          ? '点任意符号自动填入偏移。泄漏值 − 偏移 = 基址；基址必以 0x000 结尾，对不上就说明泄漏的不是这个符号（或泄漏的是返回地址=符号+N）。'
          : 'Click a symbol to fill its offset. leak − offset = base; the base must end in 0x000, otherwise the leak is a different symbol (or a return address = symbol + N).'}
      </p>
    </section>
  );
}

// ---- gadget 扫描卡 ----

function GadgetCard({ binary, zh }: { binary: LoadedBinary; zh: boolean }) {
  const [filter, setFilter] = useState('pop rdi');
  const [hits, setHits] = useState<GadgetHit[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  const scan = useCallback(async () => {
    setScanning(true);
    setError(null);
    try {
      const result = await scanElfGadgets(binary.elf, binary.bytes, {
        filter: filter.trim() || undefined,
        limit: 200,
      });
      if (result.error) setError(result.error);
      else setHits(result.hits);
    } catch {
      setError(zh ? '扫描失败（反汇编引擎错误）。' : 'Scan failed (disassembler error).');
    } finally {
      setScanning(false);
    }
  }, [binary, filter, zh]);

  return (
    <section id="pwn-card-gadgets" className="ff-card" aria-label={zh ? 'gadget 扫描' : 'gadget scanner'}>
      <div className="ff-card-head">
        <strong>{zh ? 'gadget 扫描（ROPgadget 语义）' : 'gadget scanner (ROPgadget semantics)'}</strong>
        <button type="button" className="ff-button ff-button-primary" onClick={() => { void scan(); }} disabled={scanning}>
          {scanning ? (zh ? '扫描中…' : 'Scanning…') : zh ? '开始扫描' : 'Scan'}
        </button>
      </div>
      <div className="ff-controls">
        <input
          className="ff-input"
          type="text"
          value={filter}
          placeholder={zh ? '关键词过滤，如 pop rdi / syscall / leave（空 = 全部）' : 'Filter, e.g. pop rdi / syscall / leave (empty = all)'}
          aria-label={zh ? 'gadget 过滤关键词' : 'Gadget filter'}
          onChange={event => setFilter(event.target.value)}
          onKeyDown={event => { if (event.key === 'Enter') void scan(); }}
        />
      </div>
      {error && <p className="ff-note">{error}</p>}
      {hits === null && !error && (
        <p className="ff-note">{zh ? '点「开始扫描」在可执行段里反汇编搜 gadget（x86/x64）；点击结果复制地址。' : 'Hit Scan to search gadgets in executable segments (x86/x64); click a result to copy its address.'}</p>
      )}
      {hits !== null && (
        <>
          <div className="ff-row">
            <span className="ff-badge">{zh ? `${hits.length} 条唯一 gadget` : `${hits.length} unique gadgets`}</span>
            <span className="ff-note">
              {zh ? '地址为相对 ELF 基址的偏移（PIE 需加基址）。' : 'Addresses are ELF-relative offsets (add base for PIE).'}
            </span>
          </div>
          <div className="pwn-gadget-list" role="list">
            {hits.slice(0, 120).map(hit => (
              <button
                key={`${hit.address}-${hit.gadgets}`}
                type="button"
                role="listitem"
                className="ff-button pwn-gadget"
                title={zh ? '点击复制地址' : 'Copy address'}
                onClick={() => copyText(toHexAddr(hit.address), zh)}
              >
                <span className="ff-mono pwn-gadget-addr">{toHexAddr(hit.address)}</span>
                <span className="pwn-gadget-text">{hit.gadgets}</span>
              </button>
            ))}
            {hits.length > 120 && <p className="ff-note">{zh ? `仅显示前 120 条（共 ${hits.length}）。` : `Showing first 120 of ${hits.length}.`}</p>}
          </div>
        </>
      )}
    </section>
  );
}

// ---- ROP 链组装卡 ----

function RopCard({ zh, bits }: { zh: boolean; bits: 32 | 64 }) {
  const [lines, setLines] = useState('');
  const chain = useMemo(
    () => buildRopChain(
      lines.split('\n').map(text => ({ value: text.split('#')[0].trim(), note: '' })),
      bits,
    ),
    [lines, bits],
  );

  return (
    <section id="pwn-card-rop" className="ff-card" aria-label={zh ? 'ROP 链组装' : 'ROP chain builder'}>
      <div className="ff-card-head">
        <strong>{zh ? 'ROP 链组装（一行一地址）' : 'ROP chain builder (one address per line)'}</strong>
        <span className="ff-badge">{bits}-bit · {zh ? '小端' : 'little-endian'}</span>
      </div>
      <textarea
        className="ff-textarea"
        value={lines}
        placeholder={'0x40123a  # pop rdi ; ret\n0x404018  # /bin/sh\n0x401030  # system'}
        aria-label={zh ? 'ROP 链地址列表' : 'ROP chain addresses'}
        onChange={event => setLines(event.target.value)}
      />
      {chain.ok ? (
        <>
          <div className="ff-row">
            <span className="ff-badge">{chain.totalLength} B</span>
            {chain.totalLength > 0 && (
              <>
                <button type="button" className="ff-button" onClick={() => copyText(chain.hexEscape, zh, '\\x 序列 ')}>{zh ? '复制 \x5cx 序列' : 'Copy \\x escape'}</button>
                <button type="button" className="ff-button" onClick={() => copyText(`b'${chain.hexEscape}'`, zh, 'python bytes ')}>{zh ? '复制 python bytes' : 'Copy python bytes'}</button>
                <button type="button" className="ff-button" onClick={() => copyText(chain.hex, zh, 'HEX ')}>{zh ? '复制裸 HEX' : 'Copy raw HEX'}</button>
              </>
            )}
          </div>
          {chain.totalLength > 0 && <div className="ff-code">{chain.hexEscape}</div>}
        </>
      ) : (
        <p className="ff-note">{chain.error}</p>
      )}
    </section>
  );
}

// ---- fmtstr 写入生成卡 ----

function FmtstrGenCard({ zh }: { zh: boolean }) {
  const [target, setTarget] = useState('');
  const [value, setValue] = useState('');
  const [argIndex, setArgIndex] = useState(7);
  const [bits, setBits] = useState<32 | 64>(32);

  const parsed = useMemo(() => {
    const parseHex = (text: string) => {
      const clean = text.trim().replace(/^0[xX]/, '');
      return /^[0-9a-fA-F]+$/.test(clean) ? Number.parseInt(clean, 16) : NaN;
    };
    return { target: parseHex(target), value: parseHex(value) };
  }, [target, value]);
  const result = useMemo(
    () => (Number.isFinite(parsed.target) && Number.isFinite(parsed.value)
      ? buildFmtstrWrite({ target: parsed.target, value: parsed.value, argIndex, bits, endian: 'little' })
      : null),
    [parsed, argIndex, bits],
  );

  return (
    <section id="pwn-card-fmtstr-gen" className="ff-card" aria-label={zh ? 'fmtstr 写入生成器' : 'fmtstr write generator'}>
      <div className="ff-card-head">
        <strong>{zh ? 'fmtstr 写入生成器（两段 %hn）' : 'fmtstr write generator (two %hn writes)'}</strong>
      </div>
      <p className="ff-note">
        {zh
          ? '配合下方"格式化字符串"卡：先用 %p 链实测参数序号，再在这里生成改写地址的 payload。'
          : 'Works with the format-string card: calibrate the arg index with %p first, then generate the write payload here.'}
      </p>
      <div className="ff-controls">
        <label className="ff-label" htmlFor="fmtstr-target">{zh ? '目标地址' : 'Target'}</label>
        <input id="fmtstr-target" className="ff-input ff-input-narrow" type="text" value={target} placeholder="0x804c010"
          onChange={event => setTarget(event.target.value)} />
        <label className="ff-label" htmlFor="fmtstr-value">{zh ? '写入值' : 'Value'}</label>
        <input id="fmtstr-value" className="ff-input ff-input-narrow" type="text" value={value} placeholder="0x8048579"
          onChange={event => setValue(event.target.value)} />
        <label className="ff-label" htmlFor="fmtstr-arg">{zh ? '参数序号' : 'Arg index'}</label>
        <input id="fmtstr-arg" className="ff-input" style={{ width: 52 }} type="number" min={1} max={60} value={argIndex}
          onChange={event => setArgIndex(Math.max(1, Math.min(60, Number(event.target.value) || 1)))} />
        <select className="ff-select" aria-label={zh ? '位数' : 'Bits'} value={bits} onChange={event => setBits(Number(event.target.value) as 32 | 64)}>
          <option value={32}>32-bit</option>
          <option value={64}>64-bit</option>
        </select>
      </div>
      {result && ('error' in result
        ? <p className="ff-note">{result.error}</p>
        : (
          <>
            <div className="ff-code pwn-code-copy" role="button" tabIndex={0} onClick={() => copyText(result.payload, zh)}>{result.payload}</div>
            <div className="ff-row">
              <button type="button" className="ff-button" onClick={() => copyText(result.python, zh, 'exp 片段 ')}>{zh ? '复制 python 片段' : 'Copy python snippet'}</button>
              <span className="ff-note">{result.note}</span>
            </div>
            {result.writes.map(w => (
              <span key={`${w.addr}-${w.half}`} className="ff-badge">{toHexAddr(w.addr)} ← {toHexAddr(w.value)}</span>
            ))}
          </>
        ))}
    </section>
  );
}

// ---- exp 模板卡 ----

function ExpTemplateCard({ zh }: { zh: boolean }) {
  const [scenario, setScenario] = useState<'stack-overflow' | 'ret2libc' | 'rop' | 'fmtstr'>('ret2libc');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const template = useMemo(
    () => buildExpTemplate({ arch: 64, scenario, host, port, leakSymbol: 'puts' }),
    [scenario, host, port],
  );

  const SCENARIOS: Array<{ id: typeof scenario; label: string }> = [
    { id: 'stack-overflow', label: zh ? '栈溢出' : 'Stack overflow' },
    { id: 'ret2libc', label: zh ? 'ret2libc' : 'ret2libc' },
    { id: 'rop', label: 'ROP' },
    { id: 'fmtstr', label: zh ? '格式化字符串' : 'Format string' },
  ];

  return (
    <section id="pwn-card-exp" className="ff-card" aria-label={zh ? 'exp 模板' : 'exp template'}>
      <div className="ff-card-head">
        <strong>{zh ? 'pwntools exp 模板' : 'pwntools exp template'}</strong>
        <button type="button" className="ff-button" onClick={() => copyText(template, zh, 'exp ')}>{zh ? '复制模板' : 'Copy template'}</button>
      </div>
      <div className="ff-controls">
        {SCENARIOS.map(item => (
          <button
            key={item.id}
            type="button"
            className={scenario === item.id ? 'ff-button ff-button-primary' : 'ff-button'}
            onClick={() => setScenario(item.id)}
          >
            {item.label}
          </button>
        ))}
        <input className="ff-input" style={{ maxWidth: 150 }} type="text" value={host} placeholder={zh ? '远程 host（可空）' : 'remote host (optional)'}
          aria-label={zh ? '远程主机' : 'Remote host'} onChange={event => setHost(event.target.value)} />
        <input className="ff-input" style={{ maxWidth: 70 }} type="text" value={port} placeholder="port"
          aria-label={zh ? '远程端口' : 'Remote port'} onChange={event => setPort(event.target.value)} />
      </div>
      <div className="ff-code pwn-exp">{template}</div>
    </section>
  );
}

// ---- shellcode 速查卡 ----

function ShellcodeCard({ zh }: { zh: boolean }) {
  return (
    <section id="pwn-card-shellcode" className="ff-card" aria-label={zh ? 'shellcode 速查' : 'shellcode reference'}>
      <div className="ff-card-head">
        <strong>{zh ? 'shellcode 速查（字节经反汇编核对）' : 'shellcode reference (byte-verified)'}</strong>
      </div>
      {SHELLCODE_LIBRARY.map(entry => (
        <article key={entry.id} className="pwn-shellcode">
          <div className="ff-row">
            <span className="ff-badge">{entry.arch}</span>
            <strong className="pwn-shellcode-title">{entry.title}</strong>
            <span className="ff-size">{entry.bytes.length} B</span>
            <span className="ff-label">{zh ? '坏字符' : 'avoid'} {entry.badChars.map(toHexByte).join(' ')}</span>
            <button type="button" className="ff-button" onClick={() => copyText(bytesToHexEscape(entry.bytes), zh, 'shellcode ')}>{zh ? '复制 \x5cx' : 'Copy \x5cx'}</button>
          </div>
          <p className="ff-note">{entry.summary}</p>
          <div className="ff-code">{bytesToHexEscape(entry.bytes)}</div>
        </article>
      ))}
    </section>
  );
}

// ---- cyclic pattern 生成 / 反查（Wiremask 双框联动）----

type CyclicLookup = { input: string; result: CyclicLookupResult | CyclicLookupFailure };

function CyclicCard() {
  const { language } = useLanguage();
  const zh = language === 'zh';
  const [length, setLength] = useState(200);
  const [period, setPeriod] = useState<CyclicPeriod>(4);
  const [crashInput, setCrashInput] = useState('');
  const [lookup, setLookup] = useState<CyclicLookup | null>(null);

  const pattern = useMemo(() => buildDeBruijn(period, Math.max(1, Math.min(length, 1_000_000))), [period, length]);

  // 反查防抖 350ms：深 offset 反查需要生成较长序列，不能每次按键同步跑（setState 仅在防抖回调内）。
  // lookup 带产生它的输入指纹：输入变化后的 350ms 窗口内渲染层显示"计算中"，不留陈旧结果。
  const debouncedLookup = useDebouncedCallback(() => {
    setLookup({ input: crashInput, result: findCyclicOffset(crashInput, period, { withinBytes: pattern.length }) });
  }, 350);
  useEffect(() => {
    if (!crashInput.trim()) {
      debouncedLookup.cancel();
      return;
    }
    debouncedLookup.run();
  }, [crashInput, period, pattern, debouncedLookup]);

  const copyPattern = () => copyText(pattern, zh, 'pattern ');

  const staleLookup = lookup !== null && lookup.input !== crashInput;
  const failed = lookup !== null && !staleLookup && 'error' in lookup.result ? lookup.result : null;
  const succeeded = lookup !== null && !staleLookup && !('error' in lookup.result) ? lookup.result : null;
  const beyondGenerated = succeeded !== null && succeeded.offset >= pattern.length;

  return (
    <section id="pwn-card-cyclic" className="ff-card" aria-label={zh ? 'cyclic pattern 生成与反查' : 'Cyclic pattern generator and offset lookup'}>
      <div className="ff-card-head">
        <strong>{zh ? 'cyclic pattern：生成 → 崩溃 → 反查 offset' : 'Cyclic pattern: generate → crash → find offset'}</strong>
      </div>
      <p className="ff-note">
        {zh
          ? '生成 pattern 作为填充发送直到崩溃，再把崩溃时的 EIP/RIP 值贴回下方，自动算出覆盖 offset。'
          : 'Send the pattern as filler until crash, then paste the crashed EIP/RIP below to get the overwrite offset.'}
      </p>
      <div className="ff-controls">
        <label className="ff-label" htmlFor="cyclic-length">{zh ? '长度' : 'Length'}</label>
        <input
          id="cyclic-length"
          className="ff-input ff-input-narrow"
          type="number"
          min={1}
          max={1000000}
          value={length}
          onChange={event => setLength(Math.max(1, Math.min(1_000_000, Number(event.target.value) || 0)))}
        />
        <label className="ff-label" htmlFor="cyclic-period">{zh ? '周期' : 'Period'}</label>
        <select
          id="cyclic-period"
          className="ff-select"
          value={period}
          onChange={event => setPeriod(Number(event.target.value) as CyclicPeriod)}
        >
          {CYCLIC_PERIODS.map(option => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
        <span className="ff-badge">{pattern.length} {zh ? '字符' : 'chars'}</span>
        <button type="button" className="ff-button" onClick={copyPattern}>{zh ? '复制 pattern' : 'Copy pattern'}</button>
      </div>
      <div className="pwn-pattern-output" aria-label={zh ? '生成的 pattern' : 'Generated pattern'}>{pattern}</div>

      <div className="ff-controls">
        <input
          className="ff-input"
          type="text"
          value={crashInput}
          placeholder={zh ? '粘贴崩溃寄存器值，如 0x61613768；也可粘原始子串如 h7aa' : 'Paste crashed register value e.g. 0x61613768, or a raw substring like h7aa'}
          aria-label={zh ? '崩溃寄存器值' : 'Crashed register value'}
          onChange={event => setCrashInput(event.target.value)}
        />
      </div>
      {(lookup === null || crashInput.trim() === '') && (
        <p className="ff-note">{zh ? '等待输入崩溃值……' : 'Waiting for the crash value…'}</p>
      )}
      {staleLookup && crashInput.trim() !== '' && (
        <p className="ff-note">{zh ? '正在反查……' : 'Looking up…'}</p>
      )}
      {failed && failed.error === 'format' && (
        <p className="ff-note">{failed.detail}</p>
      )}
      {failed && failed.error === 'not-found' && (
        <p className="ff-note">
          {failed.detail ?? (zh
            ? '在搜索范围内未找到该值：确认生成与发送用的是同一组长度/周期参数，寄存器值没有截断。'
            : 'Not found in the search range: make sure you generated and sent the same length/period, and the register value is not truncated.')}
        </p>
      )}
      {succeeded && (
        <div className="pwn-lookup-result">
          <div className="ff-row">
            <span className="pwn-offset">{succeeded.offset}</span>
            <span className="ff-badge ff-badge-ok">{zh ? 'offset（从 payload 起第 N 字节）' : 'offset (bytes into the payload)'}</span>
            {succeeded.endian && <span className="ff-badge">{succeeded.endian === 'little' ? (zh ? '小端' : 'little-endian') : (zh ? '大端' : 'big-endian')}</span>}
            {succeeded.width && <span className="ff-badge">{succeeded.width}-bit</span>}
            {succeeded.trimmedZeroBytes > 0 && (
              <span className="ff-badge ff-badge-warn">{zh ? `已忽略高位 ${succeeded.trimmedZeroBytes} 个零字节` : `${succeeded.trimmedZeroBytes} leading zero byte(s) ignored`}</span>
            )}
          </div>
          <p className="ff-note">
            {zh
              ? `匹配子串「${succeeded.raw}」（周期 ${period} 的 de Bruijn 序列）。`
              : `Matched "${succeeded.raw}" in the period-${period} de Bruijn sequence.`}
          </p>
          {succeeded.ambiguous && (
            <div className="ff-row">
              <span className="ff-label">{zh ? `该子串在生成长度内出现 ${succeeded.offsets.length} 处（高位被零覆盖导致无法唯一区分）：` : `Substring occurs ${succeeded.offsets.length} times within the generated length (zero-covered high bytes make it ambiguous):`}</span>
              {succeeded.offsets.map(offset => <span key={offset} className="ff-badge">{offset}</span>)}
              {succeeded.truncated && <span className="ff-badge ff-badge-warn">{zh ? '清单已截断' : 'list truncated'}</span>}
            </div>
          )}
          {beyondGenerated && (
            <p className="ff-note">
              {zh
                ? `注意：该 offset 超出你当前生成的 ${pattern.length} 字符——它仍是完整序列中的正确位置，但说明崩溃点在你发送内容之外，检查是否发够了长度。`
                : `Note: the offset exceeds your generated ${pattern.length} chars — still a valid position in the full sequence, but the crash lies beyond what you sent.`}
            </p>
          )}
        </div>
      )}
    </section>
  );
}

// ---- 坏字符检查 ----

function BadCharCard() {
  const { language } = useLanguage();
  const zh = language === 'zh';
  const [payload, setPayload] = useState('');
  const [selected, setSelected] = useState<number[]>(COMMON_BAD_CHARS.map(entry => entry.byte));
  const [custom, setCustom] = useState('');

  const parsed = useMemo(() => parsePayloadBytes(payload), [payload]);
  const badSet = useMemo(() => {
    const set = new Set(selected);
    for (const byte of parseBadCharSet(custom)) set.add(byte);
    return [...set].sort((left, right) => left - right);
  }, [selected, custom]);
  const report: BadCharReport | null = useMemo(
    () => (parsed.ok && payload.trim() ? checkBadChars(parsed.bytes, badSet) : null),
    [parsed, payload, badSet],
  );

  const toggle = (byte: number) => {
    setSelected(current => (current.includes(byte) ? current.filter(value => value !== byte) : [...current, byte]));
  };

  const visibleBytes: number[] = report && parsed.ok && report.total <= PAYLOAD_RENDER_LIMIT ? parsed.bytes : [];

  return (
    <section id="pwn-card-badchars" className="ff-card" aria-label={zh ? '坏字符检查' : 'Bad character check'}>
      <div className="ff-card-head">
        <strong>{zh ? '坏字符检查' : 'Bad character check'}</strong>
      </div>
      <p className="ff-note">
        {zh
          ? '粘贴 shellcode / payload（\\xNN 转义、裸 HEX、原始 ASCII 均可），勾选目标环境不能容忍的字节，命中处标红。'
          : 'Paste your shellcode/payload (\\xNN, bare HEX, or raw ASCII), tick bytes the target cannot tolerate — hits are highlighted.'}
      </p>
      <textarea
        className="ff-textarea"
        value={payload}
        placeholder={zh ? '例如 \\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68 …' : 'e.g. \\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68 …'}
        aria-label={zh ? 'payload 输入' : 'Payload input'}
        onChange={event => setPayload(event.target.value)}
      />
      <div className="ff-controls">
        <span className="ff-label">{zh ? '坏字符集' : 'Bad set'}</span>
        <div className="ff-checks">
          {COMMON_BAD_CHARS.map(entry => (
            <label key={entry.byte} className="ff-check">
              <input type="checkbox" checked={selected.includes(entry.byte)} onChange={() => toggle(entry.byte)} />
              {entry.label}
            </label>
          ))}
        </div>
      </div>
      <div className="ff-controls">
        <span className="ff-label">{zh ? '自定义' : 'Custom'}</span>
        <input
          className="ff-input ff-input-narrow"
          type="text"
          value={custom}
          placeholder={zh ? '\\x0b\\x22 或 3b 5c' : '\\x0b\\x22 or 3b 5c'}
          aria-label={zh ? '自定义坏字符' : 'Custom bad characters'}
          onChange={event => setCustom(event.target.value)}
        />
      </div>
      {!report && parsed.ok === false && payload.trim() && (
        <p className="ff-note">{parsed.error}</p>
      )}
      {report && (
        <>
          <div className="ff-row">
            <span className="ff-badge">{zh ? `共 ${report.total} 字节` : `${report.total} bytes`}</span>
            {report.hits.length === 0 ? (
              <span className="ff-badge ff-badge-ok">{zh ? '无坏字符命中，payload 可直接使用' : 'No bad characters — payload is safe to use'}</span>
            ) : (
              <span className="ff-badge ff-badge-warn">
                {zh
                  ? `命中 ${report.hits.length} 处（涉及 ${Array.from(report.uniqueBad).map(toHexByte).join(' ')}）`
                  : `${report.hits.length} hit(s) covering ${Array.from(report.uniqueBad).map(toHexByte).join(' ')}`}
              </span>
            )}
          </div>
          {visibleBytes.length > 0 ? (
            <div className="ff-bytes" role="list">
              {visibleBytes.map((byte, index) => {
                const hit = badSet.includes(byte);
                return (
                  <span
                    key={`${index}-${byte}`}
                    role="listitem"
                    className={hit ? 'ff-byte ff-byte-hit' : 'ff-byte'}
                    title={zh ? `偏移 ${index}` : `offset ${index}`}
                  >
                    {byte.toString(16).padStart(2, '0')}
                  </span>
                );
              })}
            </div>
          ) : (
            <p className="ff-note">{zh ? `payload 超过 ${PAYLOAD_RENDER_LIMIT} 字节，只做统计不逐字节渲染。` : `Payload exceeds ${PAYLOAD_RENDER_LIMIT} bytes; stats only, no per-byte rendering.`}</p>
          )}
        </>
      )}
    </section>
  );
}

// ---- 格式化字符串 offset ----

function FormatStringCard() {
  const { language } = useLanguage();
  const zh = language === 'zh';
  const [leak, setLeak] = useState('');
  const [target, setTarget] = useState('');

  const analysis: FormatStringLeak = useMemo(() => analyzeFormatStringLeak(leak, target), [leak, target]);
  const matched = analysis.matchedIndex;

  return (
    <section id="pwn-card-fmtstr" className="ff-card" aria-label={zh ? '格式化字符串 offset 计算' : 'Format string offset calculator'}>
      <div className="ff-card-head">
        <strong>{zh ? '格式化字符串：泄漏值 → 第 N 个参数' : 'Format string: leaked value → Nth argument'}</strong>
      </div>
      <p className="ff-note">
        {zh
          ? '发送 AAAA + 一串 %p（如 AAAA%p%p%p…），把完整输出粘到下面；再填目标值（canary / 返回地址），算出它是第几个参数。'
          : 'Send AAAA plus a chain of %p, paste the full output below, then enter the target value (canary/return address…) to get its argument index.'}
      </p>
      <textarea
        className="ff-textarea"
        value={leak}
        placeholder={zh ? '程序输出，如：AAAA 0x41414141 0x7ffd1234 0x7f…' : 'Program output, e.g.: AAAA 0x41414141 0x7ffd1234 0x7f…'}
        aria-label={zh ? '泄漏输出' : 'Leaked output'}
        onChange={event => setLeak(event.target.value)}
      />
      <div className="ff-controls">
        <input
          className="ff-input"
          type="text"
          value={target}
          placeholder={zh ? '目标值：0x7ffd1234 或 ASCII（如 AAAA）' : 'Target: 0x7ffd1234 or ASCII (e.g. AAAA)'}
          aria-label={zh ? '目标值' : 'Target value'}
          onChange={event => setTarget(event.target.value)}
        />
        {matched !== null && (
          <button
            type="button"
            className="ff-button ff-button-primary"
            onClick={() => copyText(`%${matched}$p`, zh)}
            title={zh ? '点击复制' : 'Click to copy'}
          >
            %{matched}$p
          </button>
        )}
      </div>
      {analysis.values.length > 0 && (
        <div className="pwn-leak-table" role="list">
          {analysis.values.map(entry => (
            <span
              key={entry.index}
              role="listitem"
              className={matched === entry.index ? 'ff-byte ff-byte-hit' : 'ff-byte'}
              title={`%${entry.index}$p`}
            >
              {`%${entry.index}$p`} = {entry.hex}
            </span>
          ))}
        </div>
      )}
      {matched !== null && (
        <p className="ff-note">
          {zh
            ? `目标值是第 ${matched} 个可变参数 → 在格式串中使用 %${matched}$p 读取它。`
            : `The target is vararg #${matched} → read it with %${matched}$p in your format string.`}
        </p>
      )}
      {analysis.targetNote && <p className="ff-note">{analysis.targetNote}</p>}
      <p className="ff-note">
        {zh
          ? '编号从 1 起数；64 位上前 5 个可变参数在寄存器（RSI/RDX/RCX/R8/R9），栈上通常从 %6$p 开始。'
          : 'Indices count varargs from 1; on 64-bit the first 5 come from registers (RSI/RDX/RCX/R8/R9), stack args typically start at %6$p.'}
      </p>
    </section>
  );
}

// ---- 文件分析区（checksec + libc + gadget 三卡）----

function BinaryWorkbench({ binary, zh, onClear }: { binary: LoadedBinary; zh: boolean; onClear: () => void }) {
  return (
    <>
      <section id="pwn-card-binary" className="ff-card">
        <div className="ff-card-head">
          <strong>{zh ? '二进制概要' : 'Binary summary'}</strong>
          <button type="button" className="ff-button" onClick={onClear}>{zh ? '清除' : 'Clear'}</button>
        </div>
        <div className="ff-summary">
          <span className="ff-name" title={binary.name}>{binary.name}</span>
          <span className="ff-size">{formatBytes(binary.size)}</span>
        </div>
        <div className="ff-row">
          <span className="ff-label">{zh ? '入口' : 'Entry'}</span>
          <span className="ff-mono">{toHexAddr(binary.elf.entry)}</span>
          <span className="ff-label">{zh ? '解释器' : 'Interpreter'}</span>
          <span className="ff-mono">{binary.elf.interp ?? '—'}</span>
          <span className="ff-label">{zh ? '依赖' : 'Needed'}</span>
          {binary.elf.needed.length > 0
            ? binary.elf.needed.map(name => <span key={name} className="ff-badge">{name}</span>)
            : <span className="ff-badge">—</span>}
        </div>
      </section>
      <ChecksecCard binary={binary} zh={zh} />
      <LibcCard binary={binary} zh={zh} />
      <GadgetCard binary={binary} zh={zh} />
    </>
  );
}

// Pwn 域工作台：文件分析（checksec/libc/gadget）+ payload 构造（cyclic/坏字符/格式化字符串/ROP/fmtstr 生成/shellcode/exp 模板）。
// 全部本地计算：ELF 解析纯 JS，反汇编走内置 capstone WASM（离线打包，零联网）。
function PwnWorkspace({ pendingFile, onFileConsumed }: {
  pendingFile?: { file: File; token: number } | null;
  onFileConsumed?: () => void;
}) {
  const { language } = useLanguage();
  const zh = language === 'zh';
  const { binary, error, loading, loadFile, clear, inputRef } = useBinaryLoader(zh);
  const lastTokenRef = useRef(0);

  useEffect(() => {
    if (!pendingFile || pendingFile.token === lastTokenRef.current) return;
    lastTokenRef.current = pendingFile.token;
    onFileConsumed?.();
    void loadFile(pendingFile.file);
  }, [pendingFile, onFileConsumed, loadFile]);

  const onDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    const file = event.dataTransfer.files?.[0];
    if (file) void loadFile(file);
  };

  return (
    <div className="file-forensics pwn-workspace" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
      <input
        ref={inputRef}
        type="file"
        aria-hidden="true"
        tabIndex={-1}
        style={{ display: 'none' }}
        onChange={event => {
          const file = event.target.files?.[0];
          if (file) void loadFile(file);
          event.target.value = '';
        }}
      />
      <div className="pwn-intro" role="note">
        <strong>{zh ? 'Pwn 工作台：checksec → 泄漏 → ROP 全链路' : 'Pwn workbench: checksec → leak → ROP'}</strong>
        <p>
          {zh
            ? '拖入 ELF（题目二进制或 libc）自动出 checksec 攻击路径建议、libc 符号偏移、gadget 扫描；下方 payload 计算器覆盖 cyclic/坏字符/格式化字符串/ROP 组装/exp 模板。全部本地计算，反汇编引擎随应用内置（capstone WASM，零联网）。'
            : 'Drop an ELF (challenge binary or libc) for checksec verdicts, libc offsets, and gadget scanning; payload calculators below cover cyclic, bad characters, format strings, ROP assembly, and exp templates. Fully local — the capstone WASM disassembler ships with the app.'}
        </p>
        <div className="ff-controls">
          <button type="button" className="ff-button ff-button-primary" onClick={() => inputRef.current?.click()}>
            {zh ? '选择 ELF 文件' : 'Choose ELF file'}
          </button>
          {binary && <span className="ff-badge">{binary.name}</span>}
        </div>
      </div>

      {error && (
        <div className="pwn-intro" role="alert">
          <strong>{zh ? '文件解析失败' : 'Parse failed'}</strong>
          <p>{error}</p>
        </div>
      )}
      {loading && <div className="ff-busy" role="status">{zh ? '解析中…' : 'Parsing…'}</div>}

      {binary ? (
        <BinaryWorkbench binary={binary} zh={zh} onClear={clear} />
      ) : (
        <p className="ff-note">
          {zh
            ? '还没有加载文件：cyclic / 坏字符 / 格式化字符串 / ROP / shellcode / exp 模板可直接使用；拖入 ELF 后解锁 checksec、libc、gadget 三卡。'
            : 'No file loaded yet: cyclic / bad-char / format-string / ROP / shellcode / exp tools below work standalone; dropping an ELF unlocks checksec, libc, and gadget cards.'}
        </p>
      )}

      <CyclicCard />
      <BadCharCard />
      <FormatStringCard />
      <FmtstrGenCard zh={zh} />
      <RopCard zh={zh} bits={64} />
      <ShellcodeCard zh={zh} />
      <ExpTemplateCard zh={zh} />
      <CheatsheetSection moduleId="pwn" variant="footer" />
    </div>
  );
}

export default memo(PwnWorkspace);
