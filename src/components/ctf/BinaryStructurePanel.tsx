import { memo, useCallback, useRef, useState } from 'react';
import type { PeInfo } from '../../utils/ctf/peParse';
import { vaddrToFileOffset } from '../../utils/ctf/elfParse';
import type { ElfInfo } from '../../utils/ctf/elfParse';
import { archForElf, disassembleBytes } from '../../utils/ctf/capstoneBridge';
import '../../styles/ctf-forensics.css';

const toHexAddr = (value: number): string => `0x${value.toString(16)}`;

// 二进制结构面板（批次 RV）：ELF（parseElf 产物直读）与 PE（parsePe）统一展示
// 节区表 / 程序头 / 导入导出 / 安全标志，全部本地解析零联网。
function BinaryStructurePanel({ elf, pe, bytes, language }: {
  elf: ElfInfo | null;
  pe: PeInfo | null;
  bytes: Uint8Array;
  language: 'zh' | 'en';
}) {
  const zh = language === 'zh';
  const [tab, setTab] = useState<'sections' | 'symbols' | 'imports' | 'disasm'>('sections');
  const [disasmAddr, setDisasmAddr] = useState('');
  const [disasmLines, setDisasmLines] = useState<Array<{ address: number; mnemonic: string; opStr: string }> | null>(null);
  const [disasmError, setDisasmError] = useState<string | null>(null);
  const disasmCache = useRef<Map<string, Array<{ address: number; mnemonic: string; opStr: string }>>>(new Map());

  const runDisasm = useCallback(async () => {
    if (!elf) return;
    const text = disasmAddr.trim().replace(/^0[xX]/, '');
    if (!/^[0-9a-fA-F]+$/.test(text)) {
      setDisasmError(zh ? '地址格式：0x401000 或 401000' : 'Address format: 0x401000 or 401000');
      return;
    }
    const vaddr = Number.parseInt(text, 16);
    const cached = disasmCache.current.get(text.toLowerCase());
    if (cached) { setDisasmLines(cached); setDisasmError(null); return; }
    setDisasmError(null);
    setDisasmLines(null);
    const fileOffset = vaddrToFileOffset(elf, vaddr);
    if (fileOffset === null) {
      setDisasmError(zh ? '该地址不在任何可加载段内。' : 'Address is not within any loadable segment.');
      return;
    }
    const arch = archForElf(elf);
    if (!arch) {
      setDisasmError(zh ? `暂不支持 ${elf.machine} 架构。` : `Architecture ${elf.machine} not supported.`);
      return;
    }
    const window = bytes.subarray(fileOffset, Math.min(bytes.length, fileOffset + 256));
    const lines = await disassembleBytes(window, vaddr, arch, 48);
    disasmCache.current.set(text.toLowerCase(), lines);
    setDisasmLines(lines);
  }, [disasmAddr, elf, bytes, zh]);

  if (!elf && !pe) return null;

  return (
    <section id="rv-card-structure" className="ff-card ff-card-flag" aria-label={zh ? '二进制结构' : 'Binary structure'}>
      <div className="ff-card-head">
        <strong>{zh ? '二进制结构面板' : 'Binary structure'}</strong>
        {elf && <span className="ff-size">ELF · {elf.machine} · {elf.eiType}</span>}
        {pe && <span className="ff-size">PE · {pe.machine} · {pe.is64Bit ? '64' : '32'}-bit · {pe.subsystem}{pe.isDll ? ' · DLL' : ''}</span>}
      </div>

      <div className="ff-controls">
        <button type="button" className={tab === 'sections' ? 'ff-button ff-button-primary' : 'ff-button'} onClick={() => setTab('sections')}>
          {zh ? '节区' : 'Sections'}
        </button>
        {elf && (
          <button type="button" className={tab === 'symbols' ? 'ff-button ff-button-primary' : 'ff-button'} onClick={() => setTab('symbols')}>
            {zh ? '导出符号' : 'Exports'}
          </button>
        )}
        <button type="button" className={tab === 'imports' ? 'ff-button ff-button-primary' : 'ff-button'} onClick={() => setTab('imports')}>
          {pe ? (zh ? '导入表' : 'Imports') : elf ? (zh ? '导入函数' : 'Imports') : ''}
        </button>
        {elf && (
          <button type="button" className={tab === 'disasm' ? 'ff-button ff-button-primary' : 'ff-button'} onClick={() => setTab('disasm')}>
            {zh ? '反汇编' : 'Disassemble'}
          </button>
        )}
      </div>

      {tab === 'sections' && elf && (
        <div className="ff-strings" role="list">
          {elf.sections.filter(s => s.name && s.size > 0).slice(0, 40).map(s => (
            <span key={s.name} role="listitem" className="ff-code">
              {s.name.padEnd(16)} {s.type.padEnd(10)} {toHexAddr(s.addr)} size={s.size} flags={s.flags}
            </span>
          ))}
          {elf.programHeaders.map(p => (
            <span key={`ph-${p.index}`} role="listitem" className="ff-code">
              PH {p.type.padEnd(12)} {p.flags} vaddr={toHexAddr(p.vaddr)} filesz={p.filesz}
            </span>
          ))}
        </div>
      )}
      {tab === 'sections' && pe && (
        <div className="ff-strings" role="list">
          {pe.sections.map(s => (
            <span key={s.name} role="listitem" className="ff-code">
              {s.name.padEnd(10)} VA={toHexAddr(s.virtualAddress)} vsize={s.virtualSize} raw={s.rawSize} {s.characteristics}
            </span>
          ))}
          <span role="listitem" className="ff-code">ImageBase={toHexAddr(pe.imageBase)} EP={toHexAddr(pe.entryPoint)}</span>
          {pe.security.map(item => (
            <span key={item.key} role="listitem" className="ff-code">
              {item.label}: {item.value} — {item.advice}
            </span>
          ))}
        </div>
      )}

      {tab === 'symbols' && elf && (
        <div className="ff-strings" role="list">
          {(() => {
            const exports = elf.dynamicSymbols.filter(s => s.defined && s.name && s.type === 'FUNC').slice(0, 300);
            if (exports.length === 0) return <p className="ff-note">{zh ? '无导出函数（stripped 导入型二进制）。' : 'No exported functions.'}</p>;
            return exports.map(s => (
              <span key={`${s.name}-${s.value}`} role="listitem" className="ff-code">
                {toHexAddr(s.value)} {s.name} ({s.bind})
              </span>
            ));
          })()}
        </div>
      )}
      {tab === 'symbols' && pe && (
        <div className="ff-strings" role="list">
          {pe.exports.length === 0
            ? <p className="ff-note">{zh ? '无导出。' : 'No exports.'}</p>
            : pe.exports.slice(0, 300).map(e => (
              <span key={`${e.name}-${e.ordinal}`} role="listitem" className="ff-code">{toHexAddr(e.rva)} {e.name}</span>
            ))}
        </div>
      )}

      {tab === 'imports' && (
        <div className="ff-strings" role="list">
          {elf && (() => {
            const imports = elf.dynamicSymbols.filter(s => !s.defined && s.name);
            if (imports.length === 0) return <p className="ff-note">{zh ? '无导入。' : 'No imports.'}</p>;
            return imports.slice(0, 300).map(s => (
              <span key={s.name} role="listitem" className="ff-code">{s.name}</span>
            ));
          })()}
          {pe && pe.imports.map(imp => (
            <span key={imp.dll} role="listitem" className="ff-code">
              {imp.dll}: {imp.functions.slice(0, 20).join(', ')}{imp.functions.length > 20 ? ` +${imp.functions.length - 20}` : ''}
            </span>
          ))}
        </div>
      )}

      {tab === 'disasm' && elf && (
        <>
          <div className="ff-controls">
            <input
              className="ff-input ff-input-narrow"
              type="text"
              value={disasmAddr}
              placeholder={zh ? '虚拟地址，如 0x401000' : 'Virtual address, e.g. 0x401000'}
              aria-label={zh ? '反汇编起始地址' : 'Disassembly start address'}
              onChange={event => setDisasmAddr(event.target.value)}
              onKeyDown={event => { if (event.key === 'Enter') void runDisasm(); }}
            />
            <button type="button" className="ff-button ff-button-primary" onClick={() => { void runDisasm(); }}>
              {zh ? '反汇编' : 'Disassemble'}
            </button>
          </div>
          {disasmError && <p className="ff-note">{disasmError}</p>}
          {disasmLines === null && !disasmError && (
            <p className="ff-note">{zh ? '输入地址从任意可执行位置反汇编（capstone 引擎，内置离线）。' : 'Enter an address to disassemble from (offline capstone engine).'}</p>
          )}
          {disasmLines && (
            <div className="ff-strings" role="list">
              {disasmLines.map(line => (
                <span key={line.address} role="listitem" className="ff-code">
                  {toHexAddr(line.address).padEnd(10)} {line.mnemonic} {line.opStr}
                </span>
              ))}
            </div>
          )}
        </>
      )}
      {tab === 'disasm' && !elf && (
        <p className="ff-note">{zh ? 'PE 反汇编视图即将上线：当前先用节区/导入表与安全标志。' : 'PE disassembly view coming later: use sections/imports/security flags for now.'}</p>
      )}
    </section>
  );
}

export default memo(BinaryStructurePanel);
