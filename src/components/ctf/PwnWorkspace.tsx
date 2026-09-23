import { memo, useEffect, useMemo, useState } from 'react';
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
import '../../styles/ctf-forensics.css';
import '../../styles/pwn-workspace.css';

const PAYLOAD_RENDER_LIMIT = 4096;

const toHexByte = (value: number): string => `\\x${value.toString(16).padStart(2, '0')}`;

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

  const copyPattern = () => {
    void copyToClipboard(pattern).then(ok => {
      if (!ok) notifications.show({ message: zh ? '复制失败，请手动全选。' : 'Copy failed; select manually.', color: 'red' });
      else notifications.show({ message: zh ? `已复制 ${pattern.length} 字符 pattern。` : `Copied ${pattern.length}-char pattern.`, color: 'teal', autoClose: 1600 });
    });
  };

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
          ? '第一步：生成 pattern 并作为填充发送，直到程序崩溃；第二步：把崩溃时 EIP/RIP（或目标寄存器）的值粘进下面的框，自动算出覆盖点 offset。'
          : 'Step 1: send the generated pattern as filler until the program crashes. Step 2: paste the crashed EIP/RIP value below to get the overwrite offset.'}
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
        <button type="button" className="ff-button" onClick={copyPattern}>{zh ? '复制 pattern' : 'Copy pattern'}</button>
      </div>
      <textarea className="ff-textarea" readOnly value={pattern} aria-label={zh ? '生成的 pattern' : 'Generated pattern'} />

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
          ? '粘贴 shellcode / payload（支持 \\xNN 转义、裸 HEX 或原始 ASCII），勾选目标环境不容忍的字节，命中处标红。'
          : 'Paste your shellcode/payload (\\xNN escapes, bare HEX, or raw ASCII), tick bytes the target cannot tolerate — hits are highlighted.'}
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
        <input
          className="ff-input ff-input-narrow"
          type="text"
          value={custom}
          placeholder={zh ? '自定义：\\x0b\\x22 或 3b 5c' : 'custom: \\x0b\\x22 or 3b 5c'}
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
          ? '发送 AAAA + 一串 %p（如 AAAA%p%p%p…），把程序的完整输出粘到下面；再填入你想定位的目标值（canary/返回地址等），算出它是第几个参数。值之间保持分隔。'
          : 'Send AAAA plus a chain of %p (e.g. AAAA%p%p%p…), paste the full output below, then enter the target value (canary/return address…) to get its argument index. Keep values separated.'}
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
            onClick={() => {
              void copyToClipboard(`%${matched}$p`).then(ok => {
                if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择文本复制。' : 'Copy failed; select the text manually.', color: 'red' });
                else notifications.show({ message: zh ? `已复制 %${matched}$p。` : `Copied %${matched}$p.`, color: 'teal', autoClose: 1600 });
              });
            }}
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
          ? '说明：编号从 1 起按可变参数计数。64 位平台上前几个可变参数来自寄存器（RSI/RDX/RCX/R8/R9），栈上参数需按调用约定换算；本题通常从第 6 个起对应栈。'
          : 'Note: indices count varargs from 1. On 64-bit the first varargs come from registers (RSI/RDX/RCX/R8/R9); stack args typically start at %6$p.'}
      </p>
    </section>
  );
}

// Pwn 域工作台：纯计算三件套（cyclic 反查 / 坏字符 / 格式化字符串）+ 底部题型速查。
// gadget 检索、交互式调试等依赖外部环境的工具不在本批次（见注册表 note）。
function PwnWorkspace() {
  const { language } = useLanguage();
  const zh = language === 'zh';

  return (
    <div className="file-forensics pwn-workspace">
      <div className="pwn-intro" role="note">
        <strong>{zh ? 'Pwn 纯计算工具台' : 'Pwn offline calculators'}</strong>
        <p>
          {zh
            ? '两步拿 offset、坏字符体检、格式化字符串定位——全部本地计算，无需联网。需要交互调试时用 GDB/pwndbg（见底部速查）。'
            : 'Two-step offsets, bad-character audits, and format-string indexing — all computed locally. For interactive debugging use GDB/pwndbg (see the cheat sheet).'}
        </p>
      </div>
      <CyclicCard />
      <BadCharCard />
      <FormatStringCard />
      <CheatsheetSection moduleId="pwn" variant="footer" />
    </div>
  );
}

export default memo(PwnWorkspace);
