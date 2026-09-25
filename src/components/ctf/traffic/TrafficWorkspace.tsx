import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { SegmentedControl } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useLanguage } from '../../../appContext';
import { MAX_FILE_BYTES, scanSuspiciousContent, type SuspiciousScan } from '../../../utils/ctf/fileDetect';
import { WorkbenchMenuBar } from '../../codec/WorkbenchMenuBar';
import { formatBytes, formatDuration, formatTimestamp } from '../../../utils/ctf/pcap/format';
import { parseCapture } from '../../../utils/ctf/pcap/parser';
import { buildPacketViews, type PacketView } from '../../../utils/ctf/pcap/protocols';
import { analyzeCapture, assembleIcmpData, type CaptureAnalysis } from '../../../utils/ctf/pcap/analyze';
import { copyToClipboard } from '../../../utils/clipboard';
import PacketTable from './PacketTable';
import UsbHidCard from './UsbHidCard';
import StreamView from './StreamView';
import HttpObjects from './HttpObjects';
import '../../../styles/traffic-workspace.css';

interface TrafficReport {
  name: string;
  size: number;
  capture: ReturnType<typeof parseCapture>;
  views: PacketView[];
  analysis: CaptureAnalysis;
  suspicious: SuspiciousScan;
  icmpAssembled: ReturnType<typeof assembleIcmpData>;
  baseSeconds: number | null;
}

export interface TrafficWorkspaceProps {
  // 框架层传入的待分析文件（token 变化表示新文件到达），与杂项取证域同一入口契约。
  pendingFile?: { file: File; token: number } | null;
  // 通知框架文件已被取走，框架清空 pendingFile 防止残留重放。
  onFileConsumed?: () => void;
}

// 合并两份可疑扫描（整包 + ICMP 拼合）：三组数组去重合并，flags 按 prefix+sample 去重。
const mergeSuspiciousScans = (base: SuspiciousScan, extra: SuspiciousScan): SuspiciousScan => {
  const seenFlags = new Set(base.flags.map(hit => `${hit.prefix}|${hit.sample}`));
  const seenB64 = new Set(base.base64Candidates);
  const seenKeywords = new Set(base.keywordHits);
  return {
    flags: [...base.flags, ...extra.flags.filter(hit => !seenFlags.has(`${hit.prefix}|${hit.sample}`))],
    base64Candidates: [...base.base64Candidates, ...extra.base64Candidates.filter(item => !seenB64.has(item))],
    keywordHits: [...base.keywordHits, ...extra.keywordHits.filter(item => !seenKeywords.has(item))],
  };
};

const STAT_LABELS: Record<string, { zh: string; en: string }> = {
  TCP: { zh: 'TCP', en: 'TCP' },
  HTTP: { zh: 'HTTP（TCP 内）', en: 'HTTP (over TCP)' },
  UDP: { zh: 'UDP', en: 'UDP' },
  DNS: { zh: 'DNS（UDP/TCP 53）', en: 'DNS (port 53)' },
  ICMP: { zh: 'ICMP', en: 'ICMP' },
  ICMPv6: { zh: 'ICMPv6', en: 'ICMPv6' },
  ARP: { zh: 'ARP', en: 'ARP' },
  other: { zh: '其他 / 未解析', en: 'Other / unparsed' },
};

type ViewKey = 'packets' | 'stats' | 'streams' | 'http' | 'suspicious';

const VIEW_MENU_NAMES: Record<ViewKey, { zh: string; en: string }> = {
  packets: { zh: '包列表', en: 'Packets' },
  stats: { zh: '协议统计', en: 'Protocols' },
  streams: { zh: 'TCP 流', en: 'TCP streams' },
  http: { zh: 'HTTP 对象', en: 'HTTP objects' },
  suspicious: { zh: '可疑内容', en: 'Suspicious' },
};

// 流量分析域工作区（批次 L）：pcap/pcapng 拖入 → 本地解析 → 包列表 / 协议统计 / TCP 流 / HTTP 对象 / 可疑内容。
// 文件只读解析、不上传、不执行；超过 20MB 直接拒绝；解析限量见 parser.ts（超限显示已解析部分）。
function TrafficWorkspace({ pendingFile, onFileConsumed }: TrafficWorkspaceProps) {
  const { language } = useLanguage();
  const [report, setReport] = useState<TrafficReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<ViewKey>('packets');
  const inputRef = useRef<HTMLInputElement | null>(null);
  const lastTokenRef = useRef(0);
  // 请求级序列号：loadFile 两处 await 让出后校验，防止快速连续换文件时旧文件结果覆盖新文件。
  const loadSeqRef = useRef(0);
  const zh = language === 'zh';

  const loadFile = useCallback(async (file: File) => {
    const isPcapName = /\.(pcap|pcapng|cap|dmp)$/i.test(file.name);
    if (!isPcapName) {
      notifications.show({
        title: zh ? '文件类型可能不符' : 'Unexpected file type',
        message: zh
          ? `「${file.name}」不是 .pcap/.pcapng 抓包文件。仍会尝试按抓包格式解析，无法识别会给出提示。`
          : `"${file.name}" does not look like a .pcap/.pcapng capture. Parsing will still be attempted.`,
        color: 'yellow',
      });
    }
    if (file.size > MAX_FILE_BYTES) {
      notifications.show({
        title: zh ? '文件过大' : 'File too large',
        message: zh
          ? `「${file.name}」有 ${formatBytes(file.size)}，超过 20MB 上限。请先用 Wireshark/editcap 裁剪后再试。`
          : `"${file.name}" is ${formatBytes(file.size)}, over the 20MB limit. Trim it with Wireshark/editcap first.`,
        color: 'red',
      });
      return;
    }
    setBusy(true);
    setReport(null);
    const seq = loadSeqRef.current + 1;
    loadSeqRef.current = seq;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (loadSeqRef.current !== seq) return;
      // 让"正在解析"先渲染一帧，再执行同步解析（大文件约 0.5-2s）。
      await new Promise(resolve => setTimeout(resolve, 0));
      if (loadSeqRef.current !== seq) return;
      const capture = parseCapture(bytes);
      const views = buildPacketViews(capture);
      const analysis = analyzeCapture(views);
      // ICMP 数据外带：拼合全部 ICMP 载荷再扫一遍（整包扫描会被 pcap 记录头打断，分片 flag 拼不上）。
      const icmpAssembled = assembleIcmpData(views);
      const wholeFileScan = scanSuspiciousContent(new TextDecoder('latin1').decode(bytes));
      const suspicious = icmpAssembled
        ? mergeSuspiciousScans(wholeFileScan, scanSuspiciousContent(icmpAssembled.text))
        : wholeFileScan;
      const timestamps = capture.packets.map(packet => packet.tsSeconds).filter(value => Number.isFinite(value) && value > 0);
      setReport({
        name: file.name,
        size: file.size,
        capture,
        views,
        analysis,
        suspicious,
        icmpAssembled,
        baseSeconds: timestamps.length ? Math.min(...timestamps) : null,
      });
      setView('packets');
    } catch {
      if (loadSeqRef.current !== seq) return;
      notifications.show({
        title: zh ? '解析失败' : 'Parse failed',
        message: zh ? '读取或解析该文件时出错，请确认是有效的抓包文件。' : 'Something went wrong reading or parsing the file; make sure it is a valid capture.',
        color: 'red',
      });
    } finally {
      if (loadSeqRef.current === seq) setBusy(false);
    }
  }, [zh]);

  useEffect(() => {
    if (!pendingFile || pendingFile.token === lastTokenRef.current) return;
    lastTokenRef.current = pendingFile.token;
    onFileConsumed?.();
    void loadFile(pendingFile.file);
  }, [pendingFile, onFileConsumed, loadFile]);

  const openPicker = () => inputRef.current?.click();

  const onDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    // 阻止冒泡到 CtfToolkit 页面级 drop，避免同一文件被两处重复读取。
    event.stopPropagation();
    const file = event.dataTransfer.files?.[0];
    if (file) void loadFile(file);
  };

  const totalPackets = report?.capture.packets.length ?? 0;
  const statMax = useMemo(() => Math.max(1, ...(report?.analysis.stats.map(row => row.count) ?? [1])), [report]);
  const lastSeconds = useMemo(() => {
    if (!report || report.capture.packets.length === 0) return null;
    return report.capture.packets[report.capture.packets.length - 1].tsSeconds;
  }, [report]);

  const viewOptions = [
    { value: 'packets', label: zh ? `包列表 (${totalPackets})` : `Packets (${totalPackets})` },
    { value: 'stats', label: zh ? '协议统计' : 'Protocols' },
    { value: 'streams', label: zh ? `TCP 流 (${report?.analysis.streamTotal ?? 0})` : `TCP streams (${report?.analysis.streamTotal ?? 0})` },
    { value: 'http', label: zh ? `HTTP 对象 (${report?.analysis.httpTotal ?? 0})` : `HTTP objects (${report?.analysis.httpTotal ?? 0})` },
    { value: 'suspicious', label: zh ? '可疑内容' : 'Suspicious' },
  ];

  // 顶部菜单栏（域联动）：抓包分析菜单只在流量域展示；未加载文件时条目先打开选择器。
  const trafficMenus = useMemo(() => [{
    id: 'traffic-tools',
    name: { zh: '抓包分析', en: 'Capture' },
    groups: [{
      label: null,
      entries: [
        { key: 'pick', label: zh ? '【选择抓包文件】' : '[Choose capture]', onSelect: () => inputRef.current?.click() },
        ...(['packets', 'stats', 'streams', 'http', 'suspicious'] as ViewKey[]).map(key => ({
          key,
          label: zh ? `【${VIEW_MENU_NAMES[key].zh}】` : `[${VIEW_MENU_NAMES[key].en}]`,
          active: Boolean(report) && view === key,
          onSelect: () => {
            if (report) setView(key);
            else inputRef.current?.click();
          },
        })),
      ],
    }],
  }], [zh, report, view]);

  return (
    <div className="traffic-workspace" onDragOver={event => event.preventDefault()} onDrop={onDrop}>
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng,.cap,.dmp"
        aria-hidden="true"
        tabIndex={-1}
        style={{ display: 'none' }}
        onChange={event => {
          const file = event.target.files?.[0];
          if (file) void loadFile(file);
          event.target.value = '';
        }}
      />

      <WorkbenchMenuBar
        menus={trafficMenus}
        ariaLabel={zh ? '抓包分析菜单' : 'Capture analysis menu'}
        current={report ? VIEW_MENU_NAMES[view][language] : undefined}
      />

      {!report ? (
        <div className="pw-dropzone">
          <div className="pw-dropzone-icon" aria-hidden="true">📡</div>
          <strong>{zh ? '把 pcap / pcapng 拖到这里，或点击选择' : 'Drop a pcap / pcapng here, or click to browse'}</strong>
          <small>
            {zh
              ? '浏览器本地解析包列表、协议统计、TCP 流与 HTTP 对象，自动扫描 flag 线索；文件不会上传。上限 20MB、5 万包。'
              : 'Parses packet list, protocol stats, TCP streams, and HTTP objects locally in your browser, and scans for flag hints. Never uploaded. 20MB / 50k packets limit.'}
          </small>
          <button type="button" className="pw-button pw-button-primary" onClick={openPicker}>
            {zh ? '选择抓包文件' : 'Choose capture file'}
          </button>
        </div>
      ) : (
        <div className="pw-layout">
          <section className="pw-card" aria-label={zh ? '抓包概要' : 'Capture summary'}>
            <div className="pw-card-head">
              <strong>{zh ? '抓包概要' : 'Capture summary'}</strong>
              <button type="button" className="pw-button" onClick={openPicker}>{zh ? '换一个文件' : 'Replace'}</button>
            </div>
            <div className="pw-row">
              <span className="pw-name" title={report.name}>{report.name}</span>
              <span className="pw-note">{formatBytes(report.size)}</span>
              <span className="pw-badge">{report.capture.format === 'pcapng' ? 'pcapng' : `pcap (${report.capture.byteOrder === 'le' ? 'LE' : 'BE'}${report.capture.nanosecond ? ', ns' : ''})`}</span>
              <span className="pw-badge">{zh ? `已解析 ${totalPackets} 包` : `${totalPackets} packets`}</span>
              {report.capture.linkType === 1 ? <span className="pw-badge">Ethernet</span> : report.capture.linkType === 220 ? <span className="pw-badge">USB (usbmon)</span> : <span className="pw-badge pw-badge-warn">{zh ? `链路层类型 ${report.capture.linkType}（Ethernet/USB 外未支持）` : `Link type ${report.capture.linkType} (beyond Ethernet/USB)`}</span>}
            </div>
            {report.baseSeconds !== null && (
              <div className="pw-row">
                <span className="pw-label">{zh ? '起始时间' : 'Start'}</span>
                <span className="pw-mono">{formatTimestamp(report.baseSeconds)}</span>
                <span className="pw-label">{zh ? '时长' : 'Duration'}</span>
                <span className="pw-mono">{formatDuration((lastSeconds ?? report.baseSeconds) - report.baseSeconds, language)}</span>
              </div>
            )}
            {report.capture.truncated && (
              <p className="pw-warn">
                {zh
                  ? `⚠ 包数达到解析上限 ${report.capture.packetLimit}：仅显示前 ${totalPackets} 包，其余未解析。大文件请先在 Wireshark 中按过滤条件导出。`
                  : `⚠ Packet limit of ${report.capture.packetLimit} reached: only the first ${totalPackets} packets are shown. Export a filtered subset from Wireshark for large files.`}
              </p>
            )}
            {report.capture.corrupt && (
              <p className="pw-warn">
                {zh
                  ? `⚠ 解析在第 ${report.capture.corrupt.packetIndex + 1} 包附近停止：${report.capture.corrupt.reason}。以下结果基于已解析部分。`
                  : `⚠ Parsing stopped near packet ${report.capture.corrupt.packetIndex + 1}: ${report.capture.corrupt.reason}. Results below cover the parsed portion only.`}
              </p>
            )}
            {totalPackets === 0 && (
              <p className="pw-warn">{zh ? '没有解析出任何数据包。' : 'No packets were parsed.'}</p>
            )}
          </section>

          {(report.capture.linkType === 220 || report.capture.linkType === 239) && (
            <UsbHidCard
              key={`usbhid-${report.name}:${report.size}`}
              capture={report.capture}
              language={language}
            />
          )}

          {report.analysis.flags.length > 0 && (
            <section className="pw-card pw-card-flag" aria-label={zh ? 'flag 命中' : 'Flag hits'}>
              <div className="pw-card-head">
                <strong>{zh ? '🚩 从流量中定位到 flag' : '🚩 Flags located in traffic'}</strong>
              </div>
              <div className="pw-row">
                {report.analysis.flags.map(hit => (
                  <span key={`${hit.source}-${hit.sample}`} className="pw-badge pw-badge-flag" title={`${hit.source} · ${hit.sample}`}>
                    {hit.sample}
                    <small className="pw-badge-source">{hit.source}</small>
                  </span>
                ))}
              </div>
            </section>
          )}

          <div className="pw-view-nav-wrap">
            <SegmentedControl
              className="pw-view-nav"
              value={view}
              onChange={value => setView(value as ViewKey)}
              data={viewOptions}
              aria-label={zh ? '分析视图' : 'Analysis views'}
            />
          </div>

          {view === 'packets' && <PacketTable views={report.views} baseSeconds={report.baseSeconds} language={language} />}
          {view === 'stats' && (
            <section className="pw-card" aria-label={zh ? '协议统计' : 'Protocol statistics'}>
              <div className="pw-card-head"><strong>{zh ? '协议统计' : 'Protocol statistics'}</strong></div>
              {report.analysis.stats.map(row => (
                <div key={row.key} className="pw-stat-row">
                  <span className="pw-stat-label">{STAT_LABELS[row.key]?.[language] ?? row.key}</span>
                  <span className="pw-stat-bar" aria-hidden="true">
                    <span className="pw-stat-fill" style={{ width: `${Math.max(4, Math.round((row.count / statMax) * 100))}%` }} />
                  </span>
                  <span className="pw-mono">{row.count}</span>
                </div>
              ))}
              <p className="pw-note">{zh ? 'HTTP 与 DNS 是 TCP/UDP 内的细分计数，与其他行有重叠。' : 'HTTP and DNS are sub-counts inside TCP/UDP and overlap other rows.'}</p>
            </section>
          )}
          {view === 'streams' && (
            <StreamView streams={report.analysis.streams} streamTotal={report.analysis.streamTotal} language={language} />
          )}
          {view === 'http' && (
            <HttpObjects transactions={report.analysis.transactions} httpTotal={report.analysis.httpTotal} language={language} />
          )}
          {view === 'suspicious' && (
            <section className="pw-card" aria-label={zh ? '可疑内容' : 'Suspicious content'}>
              <div className="pw-card-head"><strong>{zh ? '可疑内容（全文件扫描）' : 'Suspicious content (whole-file scan)'}</strong></div>
              {report.icmpAssembled && (
                <div className="pw-tool">
                  <span className="pw-label">
                    {zh
                      ? `ICMP 数据外带拼合（${report.icmpAssembled.packetCount} 个带载荷的 ICMP 包，按包序连接后扫描）`
                      : `ICMP data assembled (${report.icmpAssembled.packetCount} packets with payload, scanned in order)`}
                  </span>
                  <code className="pw-code">{report.icmpAssembled.text.length > 400 ? `${report.icmpAssembled.text.slice(0, 400)}…` : report.icmpAssembled.text}</code>
                </div>
              )}
              {report.suspicious.flags.length > 0 ? (
                <div className="pw-row">
                  <span className="pw-label">{zh ? 'flag 格式' : 'Flag formats'}</span>
                  {report.suspicious.flags.map(hit => (
                    <span key={hit.prefix} className="pw-badge pw-badge-flag" title={hit.sample}>{hit.sample}</span>
                  ))}
                </div>
              ) : (
                <p className="pw-note">{zh ? '未发现 flag 格式字符串。' : 'No flag-format strings found.'}</p>
              )}
              {report.suspicious.base64Candidates.length > 0 && (
                <div className="pw-tool">
                  <span className="pw-label">{zh ? '疑似 Base64 片段（点击复制，可去「密码与编码」域解码）' : 'Base64-like fragments (click to copy; decode in Ciphers & Encoding)'}</span>
                  {report.suspicious.base64Candidates.map(candidate => (
                    <button
                      key={candidate}
                      type="button"
                      className="pw-code pw-code-click"
                      title={zh ? '点击复制' : 'Click to copy'}
                      onClick={() => { void copyToClipboard(candidate); }}
                    >
                      {candidate.length > 96 ? `${candidate.slice(0, 96)}…` : candidate}
                    </button>
                  ))}
                </div>
              )}
              {report.suspicious.keywordHits.length > 0 && (
                <div className="pw-row">
                  <span className="pw-label">{zh ? '关键词命中' : 'Keyword hits'}</span>
                  {report.suspicious.keywordHits.map(keyword => <span key={keyword} className="pw-badge">{keyword}</span>)}
                </div>
              )}
              {!report.suspicious.flags.length && !report.suspicious.base64Candidates.length && !report.suspicious.keywordHits.length && (
                <p className="pw-note">{zh ? '没有可疑特征，也许 flag 藏在加密流量或图片里。' : 'Nothing suspicious found; the flag may hide in encrypted traffic or embedded files.'}</p>
              )}
            </section>
          )}
        </div>
      )}

      {busy && <div className="pw-busy" role="status">{zh ? '正在解析抓包文件…' : 'Parsing capture…'}</div>}
    </div>
  );
}

export default memo(TrafficWorkspace);
