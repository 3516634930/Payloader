import { useMemo, useState } from 'react';
import { hexdumpPreview } from '../../../utils/ctf/fileDetect';
import { formatRelativeTime } from '../../../utils/ctf/pcap/format';
import type { PacketView } from '../../../utils/ctf/pcap/protocols';

const PAGE_SIZE = 100;

interface PacketTableProps {
  views: PacketView[];
  baseSeconds: number | null;
  language: 'zh' | 'en';
}

// 包列表（批次 L）：分页表格 + 行级详情（hexdump），大文件不卡死的分页方案。
function PacketTable({ views, baseSeconds, language }: PacketTableProps) {
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<number | null>(null);
  const pageCount = Math.max(1, Math.ceil(views.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const pageViews = useMemo(
    () => views.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE),
    [views, safePage],
  );
  const selectedView = useMemo(
    () => (selected === null ? null : views.find(view => view.index === selected) ?? null),
    [views, selected],
  );
  const zh = language === 'zh';

  const rowClass = (view: PacketView): string => {
    if (view.isHttpRequest) return 'pw-row-http-req';
    if (view.isHttpResponse) return 'pw-row-http-res';
    return '';
  };

  return (
    <div className="pw-table-block">
      <div className="pw-table-scroll">
        <table className="pw-table">
          <thead>
            <tr>
              <th>#</th>
              <th>{zh ? '时间' : 'Time'}</th>
              <th>{zh ? '源' : 'Source'}</th>
              <th>{zh ? '目标' : 'Destination'}</th>
              <th>{zh ? '协议' : 'Protocol'}</th>
              <th>{zh ? '长度' : 'Length'}</th>
              <th>{zh ? '摘要' : 'Info'}</th>
            </tr>
          </thead>
          <tbody>
            {pageViews.map(view => (
              <tr
                key={view.index}
                className={`${rowClass(view)}${selected === view.index ? ' pw-row-selected' : ''}`}
                onClick={() => setSelected(selected === view.index ? null : view.index)}
              >
                <td className="pw-mono">{view.index + 1}</td>
                <td className="pw-mono">{formatRelativeTime(view.tsSeconds, baseSeconds)}</td>
                <td className="pw-mono">{view.srcPort !== null ? `${view.src}:${view.srcPort}` : view.src}</td>
                <td className="pw-mono">{view.dstPort !== null ? `${view.dst}:${view.dstPort}` : view.dst}</td>
                <td>{view.proto}</td>
                <td className="pw-mono">{view.length}</td>
                <td className="pw-info">{view.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pw-pager">
        <span className="pw-note">{zh ? `共 ${views.length} 包` : `${views.length} packets`}</span>
        <button type="button" className="pw-button" disabled={safePage <= 1} onClick={() => setPage(safePage - 1)}>
          {zh ? '上一页' : 'Prev'}
        </button>
        <span className="pw-mono">{safePage} / {pageCount}</span>
        <button type="button" className="pw-button" disabled={safePage >= pageCount} onClick={() => setPage(safePage + 1)}>
          {zh ? '下一页' : 'Next'}
        </button>
      </div>
      {selectedView && (
        <div className="pw-detail" aria-label={zh ? '包详情' : 'Packet detail'}>
          <div className="pw-card-head">
            <strong>{zh ? `包 #${selectedView.index + 1} 详情` : `Packet #${selectedView.index + 1} detail`}</strong>
            <button type="button" className="pw-button" onClick={() => setSelected(null)}>{zh ? '关闭' : 'Close'}</button>
          </div>
          <div className="pw-row">
            <span className="pw-label">{zh ? '捕获/原始长度' : 'Captured / original'}</span>
            <span className="pw-mono">{selectedView.length} B</span>
            <span className="pw-label">TCP flags</span>
            <span className="pw-mono">{selectedView.tcpFlags === null ? '-' : `0x${selectedView.tcpFlags.toString(16).padStart(2, '0')}`}</span>
          </div>
          <pre className="pw-hexdump">{hexdumpPreview(selectedView.frame, { length: 512 })}</pre>
        </div>
      )}
      <style>{`
        .pw-table-block {
          min-width: 0;
        }
        .pw-table-scroll {
          overflow-x: auto;
          scrollbar-width: thin;
          -webkit-overflow-scrolling: touch;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-card);
        }
        .pw-table {
          width: 100%;
          min-width: 720px;
          border-collapse: collapse;
          font-size: 12px;
        }
        .pw-table th, .pw-table td {
          padding: 5px 9px;
          border-bottom: 1px solid var(--border-color);
          text-align: left;
          white-space: nowrap;
          color: var(--text-secondary);
        }
        .pw-table th {
          color: var(--text-muted);
          font-weight: 700;
          position: sticky;
          top: 0;
          background: var(--bg-card);
        }
        .pw-table td.pw-info {
          white-space: normal;
          word-break: break-all;
          min-width: 200px;
        }
        .pw-table tbody tr {
          cursor: pointer;
        }
        .pw-table tbody tr:hover {
          background: rgba(0, 240, 255, 0.05);
        }
        .pw-row-http-req td { color: var(--neon-cyan); }
        .pw-row-http-res td { color: rgb(80, 235, 170); }
        .pw-row-selected td { background: rgba(0, 240, 255, 0.08); }
        .pw-pager {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 10px;
        }
        .pw-detail {
          border: 1px solid var(--border-color);
          border-radius: 8px;
          background: var(--bg-card);
          padding: 11px;
          display: grid;
          gap: 8px;
        }
        .pw-card-head {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 8px;
        }
        .pw-card-head strong {
          color: var(--neon-cyan);
          font-size: 13px;
          font-weight: 800;
        }
        .pw-card-head .pw-button { margin-left: auto; }
        .pw-row {
          display: flex;
          flex-wrap: wrap;
          align-items: center;
          gap: 7px;
        }
        .pw-label {
          color: var(--text-muted);
          font-size: 12px;
        }
        .pw-mono {
          font-family: var(--font-mono, monospace);
          font-size: 12px;
          color: var(--text-secondary);
        }
        .pw-note {
          color: var(--text-muted);
          font-size: 12px;
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
          transition: border-color var(--transition-fast), color var(--transition-fast);
        }
        .pw-button:hover { border-color: var(--neon-cyan); color: var(--neon-cyan); }
        .pw-button:disabled { opacity: 0.45; cursor: not-allowed; }
        .pw-hexdump {
          margin: 0;
          padding: 8px;
          border: 1px solid var(--border-color);
          border-radius: 6px;
          background: var(--bg-secondary);
          color: var(--text-secondary);
          font-family: var(--font-mono, monospace);
          font-size: 11px;
          overflow: auto;
          max-height: 280px;
        }
      `}</style>
    </div>
  );
}

export default PacketTable;
