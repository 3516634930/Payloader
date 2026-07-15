import { useMemo } from 'react';
import { useAppContext } from '../appContext';
import type { PublicClientBuildInfo, PublicClientBuildItem, PublicClientTargetInfo } from '../types';

interface ClientDownloadsProps {
  clientBuildInfo: PublicClientBuildInfo | null;
}

const platformOrder = ['windows', 'macos', 'linux'];

const safeDownloadUrl = (value: string) => (
  String(value || '').startsWith('/api/client-build/download/')
    ? value
    : ''
);

const formatBytes = (value: number) => {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 MB';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
};

const formatDate = (value: string) => {
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
};

const platformIcon = (platform: string) => {
  if (platform === 'windows') return 'Win';
  if (platform === 'macos') return 'Mac';
  if (platform === 'linux') return 'Linux';
  return 'Client';
};

const targetStatusLabel = (target: PublicClientTargetInfo, language: 'zh' | 'en') => {
  if (target.supported) return language === 'zh' ? '当前主机可生成' : 'Available on this host';
  return language === 'zh' ? '需对应构建主机' : 'Requires matching build host';
};

const joinTargetMeta = (target: PublicClientTargetInfo) => (
  [target.cpuFamily, target.minOsVersion, target.installType || target.packageManager]
    .filter(Boolean)
    .join(' · ')
);

type ReleaseState = 'current' | 'stale' | 'failed' | 'unknown' | 'unavailable';

const getReleaseState = (info: PublicClientBuildInfo | null): ReleaseState => {
  if (info?.lastBuildFailed) return 'failed';
  if (!info?.available) return info?.staleLatest ? 'stale' : 'unavailable';
  if (info.freshness?.isCurrent === false) return 'stale';
  if (info.freshness?.isCurrent === true) return 'current';
  return 'unknown';
};

function ClientDownloads({ clientBuildInfo }: ClientDownloadsProps) {
  const { language, setActiveView } = useAppContext();
  const items = useMemo(() => {
    const list = clientBuildInfo?.items?.length
      ? clientBuildInfo.items
      : clientBuildInfo?.latest
        ? [clientBuildInfo.latest]
        : [];
    return [...list].sort((a, b) => {
      const pa = platformOrder.indexOf(a.platform);
      const pb = platformOrder.indexOf(b.platform);
      if (pa !== pb) return (pa === -1 ? 99 : pa) - (pb === -1 ? 99 : pb);
      return `${a.arch}-${a.format}`.localeCompare(`${b.arch}-${b.format}`);
    });
  }, [clientBuildInfo]);

  const grouped = useMemo(() => {
    const groups = new Map<string, PublicClientBuildItem[]>();
    for (const item of items) {
      const key = item.platform || 'other';
      groups.set(key, [...(groups.get(key) || []), item]);
    }
    return Array.from(groups.entries());
  }, [items]);

  const targets = useMemo(() => clientBuildInfo?.targets || [], [clientBuildInfo?.targets]);
  const availableTargets = useMemo(() => targets.filter(target => target.supported).length, [targets]);
  const releaseState = getReleaseState(clientBuildInfo);
  const releaseStatus = (() => {
    if (releaseState === 'current') {
      return {
        title: language === 'zh' ? '当前版本' : 'Current release',
        detail: language === 'zh' ? '客户端与当前前端源码、公开数据一致。' : 'The client matches the current frontend source and public data.',
      };
    }
    if (releaseState === 'stale') {
      return {
        title: language === 'zh' ? '版本已过期' : 'Stale release',
        detail: language === 'zh' ? '仍可下载最后一次成功版本，但源码或公开数据已变化，建议重新生成。' : 'The last successful release remains downloadable, but source or public data changed. Regeneration is recommended.',
      };
    }
    if (releaseState === 'failed') {
      return {
        title: language === 'zh' ? '最近生成失败' : 'Latest generation failed',
        detail: clientBuildInfo?.available
          ? (language === 'zh' ? '继续提供最后一次成功制品；请在后台检查失败任务并重新生成。' : 'The last successful artifacts remain available. Review the failed job in admin and rebuild.')
          : (language === 'zh' ? '当前没有可发布制品，请在后台检查生成状态。' : 'No publishable artifact is available. Check the generation status in admin.'),
      };
    }
    if (releaseState === 'unknown') {
      return {
        title: language === 'zh' ? '版本状态待确认' : 'Release status unverified',
        detail: language === 'zh' ? '下面展示最后一次成功制品；刷新状态后可确认是否与当前源码和公开数据一致。' : 'The last successful artifacts are listed below. Refresh status to confirm source and public-data freshness.',
      };
    }
    return {
      title: language === 'zh' ? '暂无可发布版本' : 'No publishable release',
      detail: language === 'zh' ? '后台完成一次成功生成后，这里会提供经过校验的下载。' : 'Validated downloads appear here after a successful admin build.',
    };
  })();
  const targetGroups = useMemo(() => {
    const groups = new Map<string, PublicClientTargetInfo[]>();
    for (const target of targets) {
      const key = target.platform || 'other';
      groups.set(key, [...(groups.get(key) || []), target]);
    }
    return Array.from(groups.entries()).sort(([a], [b]) => {
      const pa = platformOrder.indexOf(a);
      const pb = platformOrder.indexOf(b);
      return (pa === -1 ? 99 : pa) - (pb === -1 ? 99 : pb);
    });
  }, [targets]);

  const renderTargetMatrix = () => (
    targetGroups.length ? (
      <details className="client-targets-disclosure">
        <summary>{language === 'zh' ? `查看全平台目标矩阵（${targets.length}）` : `View target matrix (${targets.length})`}</summary>
        <section className="client-targets-section">
          <div className="client-section-head">
            <h3>{language === 'zh' ? '全平台客户端矩阵' : 'Client Target Matrix'}</h3>
            <p>{language === 'zh' ? '后台按操作系统、CPU 架构和安装格式生成客户端。当前主机只会直接生成受支持目标，Linux/macOS 目标建议放到对应系统或 CI 构建机执行。' : 'The admin builder generates clients by OS, CPU architecture, and package format. The current host only builds supported targets; Linux/macOS targets should run on matching OS or CI hosts.'}</p>
          </div>
          {targetGroups.map(([platform, groupTargets]) => (
            <div key={platform} className="client-target-group">
              <div className="client-platform-title compact">
                <span>{platformIcon(platform)}</span>
                <div>
                  <h3>{groupTargets[0]?.platformLabel || platform}</h3>
                  <p>{language === 'zh' ? `${groupTargets.length} 个目标版本` : `${groupTargets.length} target(s)`}</p>
                </div>
              </div>
              <div className="client-target-grid">
                {groupTargets.map(target => (
                  <article key={target.id} className={`client-target-card ${target.supported ? 'supported' : 'disabled'}`}>
                    <strong>{target.archLabel || target.arch}</strong>
                    <span>{target.format}</span>
                    {joinTargetMeta(target) ? <span>{joinTargetMeta(target)}</span> : null}
                    <small>{targetStatusLabel(target, language)}</small>
                    {target.reason ? <em>{target.reason}</em> : null}
                  </article>
                ))}
              </div>
            </div>
          ))}
        </section>
      </details>
    ) : null
  );

  if (!clientBuildInfo?.available || !items.length) {
    return (
      <div className="client-downloads-view">
        <div className="client-downloads-head">
          <div>
            <span>{language === 'zh' ? '客户端分发' : 'Client Distribution'}</span>
            <h2>{releaseStatus.title}</h2>
            <p>{releaseStatus.detail}</p>
          </div>
          <button type="button" onClick={() => setActiveView('workspace')}>{language === 'zh' ? '返回内容' : 'Back'}</button>
        </div>
        <div className={`client-release-status ${releaseState}`} role="status" aria-live="polite">
          <strong>{releaseStatus.title}</strong>
          <span>{releaseStatus.detail}</span>
        </div>
        <div className="client-empty-panel">
          <strong>{clientBuildInfo?.staleLatest ? (language === 'zh' ? '需要重建客户端' : 'Regeneration required') : (language === 'zh' ? '还没有客户端制品' : 'No artifacts available')}</strong>
          <span>{clientBuildInfo?.staleLatest
            ? (language === 'zh' ? `旧产物版本：contract ${clientBuildInfo.staleLatest.buildContractVersion || '-'}，当前页面不会继续推荐下载。` : `Old artifact contract: ${clientBuildInfo.staleLatest.buildContractVersion || '-'}; this page will not keep recommending it.`)
            : (language === 'zh' ? '请先在后台“客户端生成”模块生成可分发版本。' : 'Generate distributable builds from the admin Client Generation module first.')}
          </span>
        </div>
        {renderTargetMatrix()}
        <ClientDownloadStyles />
      </div>
    );
  }

  return (
    <div className="client-downloads-view">
      <div className="client-downloads-head">
        <div>
          <span>{language === 'zh' ? '客户端分发' : 'Client Distribution'}</span>
          <h2>{language === 'zh' ? '下载客户端' : 'Download Client'}</h2>
          <p>
            {language === 'zh'
              ? `当前提供 ${items.length} 个客户端版本，目标矩阵共 ${targets.length || items.length} 个版本，当前主机可直接生成 ${availableTargets} 个。`
              : `${items.length} client builds are available across ${availableTargets || targets.length || items.length} build targets.`}
          </p>
        </div>
        <button type="button" onClick={() => setActiveView('workspace')}>{language === 'zh' ? '返回内容' : 'Back'}</button>
      </div>

      <div className={`client-release-status ${releaseState}`} role="status" aria-live="polite">
        <strong>{releaseStatus.title}</strong>
        <span>{releaseStatus.detail}</span>
      </div>

      <div className="client-download-summary">
        <div>
          <span>{language === 'zh' ? '公开数据快照' : 'Public Snapshot'}</span>
          <strong>{Number(clientBuildInfo.publicStats?.payloads || 0)} Payload / {Number(clientBuildInfo.publicStats?.tools || 0)} Tools</strong>
        </div>
        <div>
          <span>{language === 'zh' ? '性能策略' : 'Performance'}</span>
          <strong>{language === 'zh' ? '延迟快照 / 流式校验' : 'Lazy snapshot / streaming hash'}</strong>
        </div>
        <div>
          <span>{language === 'zh' ? '签名状态' : 'Signing'}</span>
          <strong>{clientBuildInfo.codeSigningConfigured ? (language === 'zh' ? '已配置签名' : 'Signing configured') : (language === 'zh' ? '未签名' : 'Unsigned')}</strong>
        </div>
      </div>
      {grouped.map(([platform, groupItems]) => (
        <section key={platform} className="client-platform-section">
          <div className="client-platform-title">
            <span>{platformIcon(platform)}</span>
            <div>
              <h3>{groupItems[0]?.platformLabel || platform}</h3>
              <p>{language === 'zh' ? `${groupItems.length} 个可下载版本` : `${groupItems.length} available build(s)`}</p>
            </div>
          </div>

          <div className="client-download-grid">
            {groupItems.map(item => {
              const downloadUrl = safeDownloadUrl(item.downloadUrl);
              return (
                <article key={item.fileName} className="client-download-card">
                  <div className="client-card-head">
                    <div>
                      <span>{item.archLabel || item.arch}</span>
                      <h4>{item.platformLabel} {item.arch} {item.format}</h4>
                    </div>
                    <strong>{formatBytes(item.size)}</strong>
                  </div>
                  {downloadUrl ? (
                    <a className="client-download-action" href={downloadUrl} download>
                      {language === 'zh' ? '下载客户端' : 'Download'}
                    </a>
                  ) : (
                    <button className="client-download-action" type="button" disabled>
                      {language === 'zh' ? '下载不可用' : 'Unavailable'}
                    </button>
                  )}
                  <details className="client-card-details">
                    <summary>{language === 'zh' ? '校验与安装信息' : 'Verification and install details'}</summary>
                    <dl>
                      <div>
                        <dt>{language === 'zh' ? '文件' : 'File'}</dt>
                        <dd>{item.fileName}</dd>
                      </div>
                      <div>
                        <dt>{language === 'zh' ? '生成时间' : 'Generated'}</dt>
                        <dd>{formatDate(item.generatedAt)}</dd>
                      </div>
                      <div>
                        <dt>SHA256</dt>
                        <dd className="hash-value">{item.sha256 || '-'}</dd>
                      </div>
                      <div>
                        <dt>{language === 'zh' ? '签名' : 'Signing'}</dt>
                        <dd>{item.codeSigningConfigured ? (language === 'zh' ? '已配置' : 'Configured') : (language === 'zh' ? '未签名' : 'Unsigned')}</dd>
                      </div>
                      <div>
                        <dt>CPU</dt>
                        <dd>{item.cpuFamily || item.archLabel || item.arch}</dd>
                      </div>
                      <div>
                        <dt>{language === 'zh' ? '适用系统' : 'OS'}</dt>
                        <dd>{item.minOsVersion || item.platformLabel}</dd>
                      </div>
                      <div>
                        <dt>{language === 'zh' ? '安装方式' : 'Install'}</dt>
                        <dd>{item.installType || item.format}</dd>
                      </div>
                    </dl>
                    {[...(item.performanceNotes || []), ...(item.securityNotes || []), ...(item.notes || [])].length ? (
                      <ul className="client-notes">
                        {[...(item.performanceNotes || []), ...(item.securityNotes || []), ...(item.notes || [])].slice(0, 3).map(note => <li key={note}>{note}</li>)}
                      </ul>
                    ) : null}
                  </details>
                </article>
              );
            })}
          </div>
        </section>
      ))}

      {renderTargetMatrix()}

      <section className="client-security-note">
        <h3>{language === 'zh' ? '安全与误报处理' : 'Security and false positives'}</h3>
        <p>
          {language === 'zh'
            ? '客户端只包含公开前台和公开数据快照，不包含后台 API、SQLite 数据库、管理员凭据或上传接口。降低误报依赖代码签名、固定下载页、SHA256 校验、最小权限和透明元数据，不使用加壳、混淆、规避安全软件检测或隐蔽行为。'
            : 'The client contains only the public frontend and public snapshot. It excludes admin APIs, SQLite data, admin credentials, and upload endpoints. False-positive reduction relies on signing, stable downloads, SHA256 verification, least privilege, and transparent metadata, not packing, obfuscation, security-software evasion, or stealth behavior.'}
        </p>
      </section>
      <ClientDownloadStyles />
    </div>
  );
}

function ClientDownloadStyles() {
  return (
    <style>{`
      .client-downloads-view {
        width: min(100%, 1180px);
        margin: 0 auto;
        padding: 22px;
        min-height: 100%;
      }

      .client-downloads-head {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 16px;
        margin-bottom: 16px;
        padding-bottom: 14px;
        border-bottom: 1px solid var(--border-color);
      }

      .client-downloads-head span,
      .client-download-summary span,
      .client-card-head span {
        color: var(--text-muted);
        font-size: 12px;
        font-weight: 700;
      }

      .client-downloads-head h2 {
        margin: 4px 0 6px;
        font-size: 24px;
        line-height: 1.2;
      }

      .client-downloads-head p {
        color: var(--text-secondary);
        font-size: 13px;
      }

      .client-downloads-head button {
        min-height: 44px;
        padding: 8px 12px;
        border-radius: 6px;
        border: 1px solid var(--border-color);
        background: var(--bg-tertiary);
        color: var(--text-secondary);
        white-space: nowrap;
      }

      .client-downloads-head button:hover {
        border-color: var(--neon-cyan);
        color: var(--neon-cyan);
      }

      .client-release-status {
        display: grid;
        grid-template-columns: auto minmax(0, 1fr);
        align-items: baseline;
        gap: 8px 12px;
        margin-bottom: 16px;
        padding: 10px 12px;
        border: 1px solid var(--border-color);
        border-top-color: var(--text-muted);
        background: color-mix(in srgb, var(--text-muted) 7%, transparent);
      }

      .client-release-status strong {
        color: var(--text-primary);
        font-size: 13px;
      }

      .client-release-status span {
        color: var(--text-secondary);
        font-size: 12px;
        line-height: 1.5;
      }

      .client-release-status.current {
        border-top-color: var(--neon-green);
      }

      .client-release-status.stale {
        border-top-color: var(--neon-orange);
      }

      .client-release-status.failed {
        border-top-color: var(--neon-red);
      }

      .client-download-summary {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 10px;
        margin-bottom: 16px;
      }

      .client-download-summary > div,
      .client-download-card,
      .client-security-note,
      .client-empty-panel {
        min-width: 0;
        border: 1px solid var(--border-color);
        border-radius: 8px;
        background: var(--bg-card);
      }

      .client-download-summary > div {
        display: grid;
        gap: 5px;
        padding: 13px;
      }

      .client-download-summary strong {
        overflow-wrap: anywhere;
      }

      .client-platform-section {
        margin-top: 18px;
      }

      .client-targets-section {
        display: grid;
        gap: 14px;
        margin-top: 12px;
      }

      .client-targets-disclosure {
        margin-top: 22px;
        padding-top: 14px;
        border-top: 1px solid var(--border-color);
      }

      .client-targets-disclosure > summary,
      .client-card-details > summary {
        display: flex;
        align-items: center;
        min-height: 44px;
        color: var(--text-secondary);
        font-size: 13px;
        font-weight: 700;
        cursor: pointer;
      }

      .client-targets-disclosure > summary:hover,
      .client-card-details > summary:hover {
        color: var(--neon-cyan);
      }

      .client-section-head h3 {
        margin: 0 0 4px;
        font-size: 16px;
      }

      .client-section-head p {
        color: var(--text-secondary);
        font-size: 13px;
        line-height: 1.55;
      }

      .client-platform-title {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 10px;
      }

      .client-platform-title.compact {
        margin-bottom: 8px;
      }

      .client-platform-title > span {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 54px;
        height: 32px;
        padding: 0 9px;
        border-radius: 6px;
        background: rgba(0, 240, 255, 0.1);
        color: var(--neon-cyan);
        border: 1px solid rgba(0, 240, 255, 0.24);
        font-size: 12px;
        font-weight: 800;
      }

      .client-platform-title h3 {
        font-size: 17px;
        line-height: 1.25;
      }

      .client-platform-title p {
        color: var(--text-muted);
        font-size: 12px;
      }

      .client-download-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 10px;
      }

      .client-target-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 10px;
      }

      .client-target-card {
        display: grid;
        gap: 5px;
        min-width: 0;
        padding: 12px;
        border: 1px solid var(--border-color);
        border-radius: 8px;
        background: var(--bg-card);
      }

      .client-target-card.supported {
        border-color: rgba(0, 255, 136, 0.28);
      }

      .client-target-card.disabled {
        opacity: 0.72;
      }

      .client-target-card strong {
        font-size: 14px;
        overflow-wrap: anywhere;
      }

      .client-target-card span,
      .client-target-card small,
      .client-target-card em {
        color: var(--text-secondary);
        font-size: 12px;
        line-height: 1.45;
        overflow-wrap: anywhere;
      }

      .client-target-card small {
        color: var(--neon-cyan);
        font-style: normal;
        font-weight: 700;
      }

      .client-target-card em {
        color: var(--text-muted);
        font-style: normal;
      }

      .client-download-card {
        display: grid;
        gap: 12px;
        padding: 14px;
      }

      .client-card-head {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 12px;
      }

      .client-card-head h4 {
        margin-top: 3px;
        font-size: 15px;
        overflow-wrap: anywhere;
      }

      .client-card-head strong {
        flex: 0 0 auto;
        color: var(--neon-green);
        font-family: var(--font-mono);
        font-size: 12px;
      }

      .client-download-card dl {
        display: grid;
        gap: 8px;
      }

      .client-download-card dl > div {
        display: grid;
        grid-template-columns: 86px minmax(0, 1fr);
        gap: 10px;
      }

      .client-download-card dt {
        color: var(--text-muted);
        font-size: 12px;
      }

      .client-download-card dd {
        min-width: 0;
        color: var(--text-secondary);
        font-size: 12px;
        overflow-wrap: anywhere;
      }

      .hash-value {
        font-family: var(--font-mono);
      }

      .client-notes {
        display: grid;
        gap: 5px;
        margin: 0;
        padding-left: 18px;
        color: var(--text-muted);
        font-size: 12px;
        line-height: 1.45;
      }

      .client-download-action {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 44px;
        border-radius: 6px;
        border: 1px solid rgba(0, 255, 136, 0.3);
        background: rgba(0, 255, 136, 0.08);
        color: var(--neon-green);
        font-weight: 800;
        text-decoration: none;
      }

      .client-download-action:hover {
        color: var(--bg-primary);
        background: var(--neon-green);
      }

      .client-download-action:disabled {
        cursor: not-allowed;
        opacity: 0.55;
      }

      .client-card-details {
        border-top: 1px solid var(--border-color);
      }

      .client-card-details dl {
        margin-top: 8px;
      }

      .client-card-details .client-notes {
        margin-top: 10px;
      }

      .client-security-note,
      .client-empty-panel {
        margin-top: 18px;
        padding: 16px;
      }

      .client-security-note h3,
      .client-empty-panel strong {
        display: block;
        margin-bottom: 7px;
        font-size: 16px;
      }

      .client-security-note p,
      .client-empty-panel span {
        color: var(--text-secondary);
        font-size: 13px;
        line-height: 1.65;
      }

      @media (max-width: 900px) {
        .client-downloads-view {
          padding: 14px;
        }

        .client-downloads-head {
          flex-direction: column;
          align-items: stretch;
        }

        .client-downloads-head button {
          width: 100%;
        }

        .client-download-summary {
          grid-template-columns: 1fr;
        }

        .client-release-status {
          grid-template-columns: 1fr;
        }
      }

      @media (max-width: 520px) {
        .client-downloads-head h2 {
          font-size: 20px;
        }

        .client-download-card dl > div {
          grid-template-columns: 1fr;
          gap: 2px;
        }

        .client-target-grid,
        .client-download-grid {
          grid-template-columns: minmax(0, 1fr);
        }
      }
    `}</style>
  );
}

export default ClientDownloads;
