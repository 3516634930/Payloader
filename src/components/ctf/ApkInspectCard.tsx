import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { parseApk } from '../../utils/ctf/apkParse';
import type { ApkAnalysis } from '../../utils/ctf/apkParse';
import '../../styles/ctf-forensics.css';

const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

// APK 安卓逆向工作台（批次 AX）：APK 拖入即出 manifest 信息（包名/版本/权限/组件/导出/调试）、
// DEX 类列表与关键字符串、原生库与签名盘点。纯本地解析（jadx 静态信息子集），零联网。
function ApkInspectCard({ bytes, fileName, language }: { bytes: Uint8Array; fileName: string; language: 'zh' | 'en' }) {
  const zh = language === 'zh';
  const [analysis, setAnalysis] = useState<ApkAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [classFilter, setClassFilter] = useState('');
  const [stringFilter, setStringFilter] = useState('');
  const lastTokenRef = useRef('');
  const token = `${fileName}:${bytes.length}`;

  const run = useCallback(async () => {
    try {
      const result = await parseApk(fileName, bytes);
      if (result.ok) setAnalysis(result);
      else setError(result.error);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [bytes, fileName]);

  useEffect(() => {
    // 异步回调里 setState（react-hooks/set-state-in-effect 合规）；同文件不重复解析。
    if (lastTokenRef.current === token) return;
    lastTokenRef.current = token;
    void run();
  }, [run, token]);

  const dexClasses = useMemo(() => {
    if (!analysis) return [];
    const all = analysis.dexFiles.flatMap(d => d.info?.classes ?? []);
    const needle = classFilter.trim().toLowerCase();
    const filtered = needle ? all.filter(c => c.name.toLowerCase().includes(needle)) : all;
    return filtered.slice(0, 200);
  }, [analysis, classFilter]);

  const interesting = useMemo(() => {
    if (!analysis) return [];
    const needle = stringFilter.trim().toLowerCase();
    const filtered = needle
      ? analysis.interestingStrings.filter(s => s.toLowerCase().includes(needle))
      : analysis.interestingStrings;
    return filtered.slice(0, 60);
  }, [analysis, stringFilter]);

  if (error) {
    return (
      <section className="ff-card" aria-label={zh ? 'APK 分析' : 'APK analysis'}>
        <div className="ff-card-head"><strong>{zh ? 'APK 安卓逆向' : 'APK analysis'}</strong></div>
        <p className="ff-note">{error}</p>
      </section>
    );
  }
  if (!analysis) {
    return (
      <section className="ff-card" aria-label={zh ? 'APK 分析' : 'APK analysis'}>
        <div className="ff-card-head"><strong>{zh ? 'APK 安卓逆向' : 'APK analysis'}</strong></div>
        <p className="ff-note">{zh ? '解析中…' : 'Parsing…'}</p>
      </section>
    );
  }

  const m = analysis.manifest;

  return (
    <section className="ff-card ff-card-flag" aria-label={zh ? 'APK 安卓逆向' : 'APK analysis'}>
      <div className="ff-card-head">
        <strong>{zh ? 'APK 安卓逆向' : 'APK analysis'}</strong>
        <span className="ff-size">{analysis.fileName} · {formatBytes(analysis.fileSize)}</span>
      </div>

      {m && (
        <>
          <div className="ff-row">
            <span className="ff-label">{zh ? '包名' : 'Package'}</span>
            <span className="ff-mono">{m.packageName || '—'}</span>
            <span className="ff-label">{zh ? '版本' : 'Version'}</span>
            <span className="ff-mono">{m.versionName || '—'} ({m.versionCode || '—'})</span>
            <span className="ff-label">SDK</span>
            <span className="ff-mono">{m.minSdk || '?'} → {m.targetSdk || '?'}</span>
          </div>
          <div className="ff-row">
            {m.debuggable && <span className="ff-badge ff-badge-warn">debuggable {zh ? '开启（可 attach 调试）' : 'on (attachable)'}</span>}
            {m.allowBackup && <span className="ff-badge ff-badge-warn">allowBackup {zh ? '开启（可 adb backup 提数据）' : 'on (adb backup)'}</span>}
            {m.usesCleartextTraffic && <span className="ff-badge ff-badge-warn">usesCleartextTraffic</span>}
            {m.mainActivity && <span className="ff-badge ff-badge-ok">{zh ? '主入口' : 'Main'}: {m.mainActivity.split('.').pop()}</span>}
          </div>
          {m.permissions.length > 0 && (
            <div className="ff-row">
              <span className="ff-label">{zh ? '权限' : 'Permissions'}</span>
              {m.permissions.map(p => <span key={p} className="ff-badge" title={p}>{p.replace('android.permission.', 'android.')}</span>)}
            </div>
          )}
          <div className="ff-row">
            <span className="ff-label">{zh ? '组件' : 'Components'}</span>
            <span className="ff-badge">{zh ? `Activity ${m.activities.length}` : `Activities ${m.activities.length}`}</span>
            <span className="ff-badge">{zh ? `Service ${m.services.length}` : `Services ${m.services.length}`}</span>
            <span className="ff-badge">{zh ? `Receiver ${m.receivers.length}` : `Receivers ${m.receivers.length}`}</span>
            <span className="ff-badge">{zh ? `Provider ${m.providers.length}` : `Providers ${m.providers.length}`}</span>
            {[...m.activities, ...m.services, ...m.receivers, ...m.providers].filter(c => 'exported' in c && c.exported).length > 0 && (
              <span className="ff-badge ff-badge-warn">{zh ? '存在导出组件（注意 intent Fuzz）' : 'Exported components present (intent fuzz)'}</span>
            )}
          </div>
          {m.providers.length > 0 && (
            <div className="ff-row">
              <span className="ff-label">{zh ? 'Provider authorities' : 'Authorities'}</span>
              {m.providers.map(p => <span key={p.name} className="ff-mono">{p.authorities}</span>)}
            </div>
          )}
        </>
      )}
      {!m && analysis.manifestError && <p className="ff-note">manifest: {analysis.manifestError}</p>}

      {analysis.signatureScheme.length > 0 && (
        <div className="ff-row">
          <span className="ff-label">{zh ? '签名方案' : 'Signatures'}</span>
          {analysis.signatureScheme.map(s => <span key={s} className="ff-badge">{s}</span>)}
        </div>
      )}
      {analysis.nativeLibs.length > 0 && (
        <div className="ff-row">
          <span className="ff-label">{zh ? '原生库 ABI' : 'Native ABIs'}</span>
          {analysis.nativeLibs.map(abi => <span key={abi} className="ff-badge">{abi}</span>)}
        </div>
      )}

      {analysis.dexFiles.map(dex => (
        <div key={dex.name} className="ff-row">
          <span className="ff-mono">{dex.name}</span>
          {dex.info ? (
            <>
              <span className="ff-badge">DEX {dex.info.version}</span>
              <span className="ff-badge">{zh ? `${dex.info.classCount} 类` : `${dex.info.classCount} classes`}</span>
              <span className="ff-badge">{zh ? `${dex.info.stringCount} 字符串` : `${dex.info.stringCount} strings`}</span>
            </>
          ) : (
            <span className="ff-badge ff-badge-warn">{dex.error}</span>
          )}
        </div>
      ))}

      {analysis.interestingStrings.length > 0 && (
        <>
          <div className="ff-controls">
            <span className="ff-label">{zh ? '关键字符串（flag/密钥/URL/加密）' : 'Interesting strings (flag/keys/URLs/crypto)'}</span>
            <input
              className="ff-input ff-input-narrow"
              type="text"
              value={stringFilter}
              placeholder={zh ? '过滤…' : 'Filter…'}
              aria-label={zh ? '字符串过滤' : 'String filter'}
              onChange={event => setStringFilter(event.target.value)}
            />
          </div>
          <div className="ff-strings" role="list">
            {interesting.map((s, i) => (
              <span key={`${i}-${s.slice(0, 24)}`} role="listitem" className="ff-code">{s}</span>
            ))}
            {interesting.length === 0 && <p className="ff-note">{zh ? '无匹配。' : 'No match.'}</p>}
          </div>
        </>
      )}

      {dexClasses.length > 0 && (
        <>
          <div className="ff-controls">
            <span className="ff-label">{zh ? '类列表' : 'Classes'}</span>
            <input
              className="ff-input ff-input-narrow"
              type="text"
              value={classFilter}
              placeholder={zh ? '按类名过滤，如 flag / main / util' : 'Filter by name, e.g. flag / main / util'}
              aria-label={zh ? '类名过滤' : 'Class filter'}
              onChange={event => setClassFilter(event.target.value)}
            />
          </div>
          <div className="ff-strings" role="list">
            {dexClasses.map(c => (
              <span
                key={c.descriptor}
                role="listitem"
                className={`ff-code${c.isExportedComponent ? ' ff-code-click' : ''}`}
                title={`${c.accessFlags.join(' ')}${c.superName ? ` extends ${c.superName}` : ''}`}
              >
                {c.name}{c.superName ? <span className="ff-size"> : {c.superName.split('.').pop()}</span> : null}
              </span>
            ))}
            {dexClasses.length >= 200 && <p className="ff-note">{zh ? '仅显示前 200 条，输入过滤缩小范围。' : 'Showing first 200; filter to narrow down.'}</p>}
          </div>
        </>
      )}

      {analysis.entries.length > 0 && (
        <p className="ff-note">
          {zh
            ? `共 ${analysis.entries.length} 个条目列出（前 ${Math.min(analysis.entries.length, 200)}）；原生库可从 APK 解出后走逆向域 ELF 面板深度分析。`
            : `${analysis.entries.length} entries listed (first ${Math.min(analysis.entries.length, 200)}); extract native libs for the ELF panel in Reverse.`}
        </p>
      )}
    </section>
  );
}

export default memo(ApkInspectCard);
