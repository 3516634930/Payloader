import { useMemo, useState } from 'react';
import { hexdumpPreview } from '../../../utils/ctf/fileDetect';
import { formatBytes } from '../../../utils/ctf/pcap/format';
import type { TcpStream } from '../../../utils/ctf/pcap/analyze';
import { copyToClipboard } from '../../../utils/clipboard';

const HEX_PREVIEW_BYTES = 64 * 1024;
const ASCII_PREVIEW_CHARS = 256 * 1024;

interface StreamViewProps {
  streams: TcpStream[];
  streamTotal: number;
  language: 'zh' | 'en';
}

type Direction = 'a2b' | 'b2a';
type DisplayMode = 'ascii' | 'hex';

// TCP 流视图（批次 L）：流清单 + 逐流方向/格式切换查看。
function StreamView({ streams, streamTotal, language }: StreamViewProps) {
  const [selectedId, setSelectedId] = useState<number | null>(streams[0]?.id ?? null);
  const [direction, setDirection] = useState<Direction>('a2b');
  const [mode, setMode] = useState<DisplayMode>('ascii');
  const zh = language === 'zh';

  const selected = useMemo(
    () => streams.find(stream => stream.id === selectedId) ?? streams[0] ?? null,
    [streams, selectedId],
  );
  const content = useMemo(() => {
    if (!selected) return '';
    const buffer = direction === 'a2b' ? selected.bufferAtoB : selected.bufferBtoA;
    if (buffer.length === 0) return zh ? '（该方向无数据）' : '(no data in this direction)';
    if (mode === 'hex') {
      return hexdumpPreview(buffer, { length: Math.min(buffer.length, HEX_PREVIEW_BYTES) });
    }
    const text = new TextDecoder('latin1').decode(buffer.subarray(0, ASCII_PREVIEW_CHARS));
    return buffer.length > ASCII_PREVIEW_CHARS ? `${text}\n…` : text;
  }, [selected, direction, mode, zh]);

  if (streams.length === 0) {
    return <p className="pw-note">{zh ? '未发现任何 TCP 数据流。' : 'No TCP streams found.'}</p>;
  }

  return (
    <div className="pw-stream">
      <p className="pw-note">
        {zh
          ? `共 ${streamTotal} 条流${streamTotal > streams.length ? `，仅展示字节量最多的前 ${streams.length} 条` : ''}。`
          : `${streamTotal} streams total${streamTotal > streams.length ? `, showing the ${streams.length} largest` : ''}.`}
      </p>
      <div className="pw-stream-list" role="listbox" aria-label={zh ? 'TCP 流清单' : 'TCP stream list'}>
        {streams.map(stream => (
          <button
            key={stream.id}
            type="button"
            role="option"
            aria-selected={selected?.id === stream.id}
            className={`pw-stream-item${selected?.id === stream.id ? ' pw-stream-item-active' : ''}`}
            onClick={() => setSelectedId(stream.id)}
          >
            <span className="pw-stream-id">#{stream.id}</span>
            <span className="pw-stream-endpoints">
              {stream.endpointA} ⇄ {stream.endpointB}
            </span>
            <span className="pw-stream-meta">
              {stream.packetCount} pkt · {formatBytes(stream.byteCount)}
            </span>
            {stream.hasFlag && <span className="pw-badge pw-badge-flag">🚩 flag</span>}
            {stream.truncated && <span className="pw-badge pw-badge-warn">{zh ? '超限截断' : 'truncated'}</span>}
          </button>
        ))}
      </div>
      {selected && (
        <div className="pw-stream-detail">
          <div className="pw-stream-controls">
            <button
              type="button"
              className={`pw-button${direction === 'a2b' ? ' pw-button-active' : ''}`}
              onClick={() => setDirection('a2b')}
            >
              A → B
            </button>
            <button
              type="button"
              className={`pw-button${direction === 'b2a' ? ' pw-button-active' : ''}`}
              onClick={() => setDirection('b2a')}
            >
              B → A
            </button>
            <span className="pw-stream-sep" aria-hidden="true" />
            <button
              type="button"
              className={`pw-button${mode === 'ascii' ? ' pw-button-active' : ''}`}
              onClick={() => setMode('ascii')}
            >
              ASCII
            </button>
            <button
              type="button"
              className={`pw-button${mode === 'hex' ? ' pw-button-active' : ''}`}
              onClick={() => setMode('hex')}
            >
              HEX
            </button>
            <button
              type="button"
              className="pw-button"
              onClick={() => { void copyToClipboard(content); }}
            >
              {zh ? '复制当前视图' : 'Copy view'}
            </button>
          </div>
          <pre className="pw-stream-content">{content}</pre>
        </div>
      )}
      <style>{`
        .pw-stream {
          display: grid;
          gap: 10px;
          min-width: 0;
        }
        .pw-stream-list {
          display: grid;
          gap: 6px;
          max-height: 300px;
          overflow-y: auto;
          scrollbar-width: thin;
        }
        .pw-stream-item {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 8px;
          padding: 7px 10px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-card);
          color: var(--text-secondary);
          font-size: 12px;
          cursor: pointer;
          text-align: left;
        }
        .pw-stream-item:hover { border-color: var(--neon-cyan); }
        .pw-stream-item-active {
          border-color: var(--neon-cyan);
          background: rgba(0, 240, 255, 0.06);
        }
        .pw-stream-id {
          font-family: var(--font-mono, monospace);
          color: var(--neon-cyan);
          font-weight: 700;
        }
        .pw-stream-endpoints {
          font-family: var(--font-mono, monospace);
          word-break: break-all;
        }
        .pw-stream-meta {
          color: var(--text-muted);
        }
        .pw-badge {
          display: inline-flex;
          align-items: center;
          padding: 2px 8px;
          border: 1px solid var(--border-color);
          border-radius: 999px;
          font-size: 11px;
          font-weight: 700;
        }
        .pw-badge-flag {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }
        .pw-badge-warn {
          border-color: rgba(255, 190, 70, 0.55);
          color: rgb(255, 205, 100);
        }
        .pw-stream-detail {
          display: grid;
          gap: 8px;
        }
        .pw-stream-controls {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 6px;
        }
        .pw-stream-sep {
          width: 1px;
          height: 18px;
          background: var(--border-color);
        }
        .pw-button {
          min-height: 30px;
          padding: 5px 11px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: rgba(255, 255, 255, 0.035);
          color: var(--text-secondary);
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
        }
        .pw-button:hover { border-color: var(--neon-cyan); color: var(--neon-cyan); }
        .pw-button-active {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }
        .pw-stream-content {
          margin: 0;
          padding: 10px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-secondary);
          font-family: var(--font-mono, monospace);
          font-size: 11px;
          line-height: 1.5;
          overflow: auto;
          max-height: 420px;
          white-space: pre-wrap;
          word-break: break-all;
        }
        .pw-note {
          margin: 0;
          color: var(--text-muted);
          font-size: 12px;
        }
      `}</style>
    </div>
  );
}

export default StreamView;
