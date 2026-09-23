import { useEffect, useMemo, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { hexdumpPreview } from '../../utils/ctf/fileDetect';

interface HexdumpCardProps {
  bytes: Uint8Array;
  size: number;
  language: 'zh' | 'en';
}

const HEX_PAGE_BYTES = 512;
const HEXDUMP_ROW = 16;

// hexdump 卡：偏移跳转（十进制 / 0x 前缀）、每页 512B 翻页、文本/HEX 搜索（命中跳页高亮行）。
// 翻页与搜索状态属于卡片局部，换文件由父组件 key remount 重置。
function HexdumpCard({ bytes, size, language }: HexdumpCardProps) {
  const zh = language === 'zh';
  const [offset, setOffset] = useState(0);
  const [jumpValue, setJumpValue] = useState('');
  const [query, setQuery] = useState('');
  const [mode, setMode] = useState<'text' | 'hex'>('text');
  const [hitLine, setHitLine] = useState<number | null>(null);
  const dumpRef = useRef<HTMLPreElement | null>(null);

  // 命中行可能在 320px 折叠线以下：高亮变化时滚动到可见（需求⑤"命中滚动定位"）。
  useEffect(() => {
    if (hitLine === null) return;
    const container = dumpRef.current;
    if (!container) return;
    const line = container.children[hitLine] as HTMLElement | undefined;
    line?.scrollIntoView({ block: 'center' });
  }, [hitLine, offset]);

  const indexOfSequence = (needle: Uint8Array, from: number): number => {
    if (needle.length === 0 || bytes.length < needle.length) return -1;
    let position = Math.max(0, from);
    while (position <= bytes.length - needle.length) {
      const found = bytes.indexOf(needle[0], position);
      if (found < 0 || found + needle.length > bytes.length) return -1;
      let matched = true;
      for (let index = 1; index < needle.length; index += 1) {
        if (bytes[found + index] !== needle[index]) {
          matched = false;
          break;
        }
      }
      if (matched) return found;
      position = found + 1;
    }
    return -1;
  };

  const parseNeedle = (): Uint8Array | null => {
    if (mode === 'text') {
      const out = new Uint8Array(query.length);
      for (let index = 0; index < query.length; index += 1) out[index] = query.charCodeAt(index) & 0xff;
      return out;
    }
    const cleaned = query.replace(/[\s,]+/g, '');
    if (cleaned.length === 0 || cleaned.length % 2 !== 0 || /[^0-9a-fA-F]/.test(cleaned)) return null;
    const out = new Uint8Array(cleaned.length / 2);
    for (let index = 0; index < out.length; index += 1) out[index] = Number.parseInt(cleaned.slice(index * 2, index * 2 + 2), 16);
    return out;
  };

  const runSearch = () => {
    const needle = parseNeedle();
    if (!needle) {
      notifications.show({
        message: zh
          ? '搜索格式有误：HEX 模式需要偶数个十六进制字符（如 89504E47）。'
          : 'Bad search input: hex mode needs an even number of hex digits (e.g. 89504E47).',
        color: 'red',
      });
      return;
    }
    const found = indexOfSequence(needle, offset + 1);
    if (found < 0) {
      notifications.show({ message: zh ? `从当前偏移向后未找到「${query}」。` : `"${query}" not found after the current offset.` });
      return;
    }
    setOffset(Math.floor(found / HEX_PAGE_BYTES) * HEX_PAGE_BYTES);
    setHitLine(Math.floor((found % HEX_PAGE_BYTES) / HEXDUMP_ROW));
  };

  const jump = () => {
    const cleaned = jumpValue.trim().toLowerCase();
    if (!cleaned) return;
    const value = cleaned.startsWith('0x') ? Number.parseInt(cleaned.slice(2), 16) : Number.parseInt(cleaned, 10);
    if (!Number.isFinite(value) || value < 0) {
      notifications.show({ message: zh ? '偏移格式：十进制（1024）或 0x 前缀十六进制（0x400）。' : 'Offset format: decimal (1024) or 0x-prefixed hex (0x400).' });
      return;
    }
    const clamped = Math.min(value, Math.max(0, size - 1));
    setOffset(Math.floor(clamped / HEX_PAGE_BYTES) * HEX_PAGE_BYTES);
    setHitLine(null);
  };

  const lines = useMemo(() => {
    const start = Math.min(offset, Math.max(0, size - 1));
    return hexdumpPreview(bytes, { offset: start, length: HEX_PAGE_BYTES }).split('\n');
  }, [bytes, offset, size]);

  const pageCount = Math.max(1, Math.ceil(size / HEX_PAGE_BYTES));
  const currentPage = Math.floor(Math.min(offset, Math.max(0, size - 1)) / HEX_PAGE_BYTES) + 1;

  return (
    <section id="ff-card-hexdump" className="ff-card" aria-label={zh ? 'hexdump 预览' : 'Hexdump'}>
      <div className="ff-card-head">
        <strong>{zh ? `hexdump 预览（第 ${currentPage} / ${pageCount} 页，每页 ${HEX_PAGE_BYTES} 字节）` : `Hexdump (page ${currentPage} / ${pageCount}, ${HEX_PAGE_BYTES} bytes each)`}</strong>
      </div>
      <div className="ff-controls">
        <input
          className="ff-input ff-input-narrow"
          type="text"
          value={jumpValue}
          placeholder={zh ? '跳转偏移 0x400 / 1024' : 'Jump to 0x400 / 1024'}
          aria-label={zh ? '跳转偏移' : 'Jump offset'}
          onChange={event => setJumpValue(event.target.value)}
          onKeyDown={event => {
            if (event.key === 'Enter') jump();
          }}
        />
        <button type="button" className="ff-button" onClick={jump}>{zh ? '跳转' : 'Jump'}</button>
        <button
          type="button"
          className="ff-button"
          disabled={offset === 0}
          onClick={() => {
            setOffset(Math.max(0, offset - HEX_PAGE_BYTES));
            setHitLine(null);
          }}
        >
          {zh ? '上一页' : 'Prev'}
        </button>
        <button
          type="button"
          className="ff-button"
          disabled={offset + HEX_PAGE_BYTES >= size}
          onClick={() => {
            setOffset(Math.min(offset + HEX_PAGE_BYTES, Math.max(0, size - 1)));
            setHitLine(null);
          }}
        >
          {zh ? '下一页' : 'Next'}
        </button>
      </div>
      <div className="ff-controls">
        <select
          className="ff-select"
          value={mode}
          aria-label={zh ? '搜索模式' : 'Search mode'}
          onChange={event => setMode(event.target.value as 'text' | 'hex')}
        >
          <option value="text">{zh ? '文本搜索' : 'Text'}</option>
          <option value="hex">{zh ? 'HEX 搜索' : 'HEX'}</option>
        </select>
        <input
          className="ff-input"
          type="search"
          value={query}
          placeholder={mode === 'text' ? (zh ? '搜索文本（从当前页向后）' : 'Search text (forward)') : (zh ? 'HEX 字节如 89504E47' : 'HEX bytes e.g. 89504E47')}
          aria-label={zh ? '搜索内容' : 'Search content'}
          onChange={event => setQuery(event.target.value)}
          onKeyDown={event => {
            if (event.key === 'Enter') runSearch();
          }}
        />
        <button type="button" className="ff-button ff-button-primary" onClick={runSearch}>{zh ? '查找下一个' : 'Find next'}</button>
      </div>
      <pre ref={dumpRef} className="ff-code ff-code-dump">
        {lines.map((line, index) => (
          <div key={`${offset}-${index}`} className={index === hitLine ? 'ff-dump-line ff-dump-hit' : 'ff-dump-line'}>{line || ' '}</div>
        ))}
      </pre>
    </section>
  );
}

export default HexdumpCard;
