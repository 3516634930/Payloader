import { useMemo } from 'react';
import { notifications } from '@mantine/notifications';
import { fixRarPseudoEncryption, fixRarSignature, inspectRar } from '../../utils/ctf/rarInspect';
import type { RarInspectResult } from '../../utils/ctf/rarInspect';
import { downloadBytes } from './ffDownload';

// RAR4 取证卡：条目表/结构线索/一键伪加密清位与签名重写（SimpleRAR 型头修复题），修复产物下载。
// 解析在 useMemo 同步（引擎自带红线）；解压预览待 rarExtract 上线后接入。
interface RarInspectCardProps {
  fileName: string;
  bytes: Uint8Array;
  language: 'zh' | 'en';
}

function RarInspectCard({ fileName, bytes, language }: RarInspectCardProps) {
  const zh = language === 'zh';
  const baseName = fileName.replace(/\.[^.]+$/, '');
  const result = useMemo<{ inspected?: RarInspectResult; error?: string }>(() => {
    try {
      return { inspected: inspectRar(bytes) };
    } catch (error) {
      return { error: (error as Error).message };
    }
  }, [bytes]);
  const signatureFix = useMemo(() => fixRarSignature(bytes), [bytes]);
  const pseudoFix = useMemo(() => fixRarPseudoEncryption(bytes), [bytes]);

  if (result.error) {
    return (
      <section id="ff-card-rar" className="ff-card" aria-label={zh ? 'RAR 解析' : 'RAR inspection'}>
        <div className="ff-card-head"><strong>{zh ? 'RAR 解析' : 'RAR inspection'}</strong></div>
        <p className="ff-note">{result.error}</p>
      </section>
    );
  }

  const inspected = result.inspected!;

  const downloadFixed = (fixed: Uint8Array, suffix: string) => {
    downloadBytes(fixed, `${baseName}-${suffix}.rar`);
    notifications.show({ message: zh ? '修复文件已开始下载。' : 'The fixed file download has started.', color: 'teal', autoClose: 2000 });
  };

  return (
    <section id="ff-card-rar" className="ff-card" aria-label={zh ? 'RAR 解析' : 'RAR inspection'}>
      <div className="ff-card-head">
        <strong>{zh ? 'RAR 解析' : 'RAR inspection'}</strong>
        <span className="ff-badge">{inspected.entries.length} {zh ? '条目' : 'entries'}</span>
      </div>
      {inspected.anomalies.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '结构线索' : 'Structural clues'}</span>
          {inspected.anomalies.map((anomaly, index) => (
            <p key={index} className="ff-note">• {anomaly}</p>
          ))}
        </div>
      )}
      {inspected.entries.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '条目表' : 'Entries'}</span>
          {inspected.entries.map((entry, index) => (
            <div key={`${entry.name}-${index}`} className="ff-row">
              <span className="ff-badge">{entry.isDirectory ? '📁' : '📄'} {entry.name}</span>
              <span className="ff-badge">{entry.method === 0x30 ? 'stored' : `method ${entry.method}`}</span>
              {entry.encrypted && <span className="ff-badge ff-badge-warn">{zh ? '加密位' : 'encrypted'}</span>}
            </div>
          ))}
        </div>
      )}
      {(signatureFix.fixed || pseudoFix.fixed) && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '修复工具' : 'Repair tools'}</span>
          <div className="ff-row">
            {signatureFix.fixed && (
              <button type="button" className="ff-button ff-button-primary" onClick={() => downloadFixed(signatureFix.fixed!, 'sig-fixed')}>
                {zh ? `重写签名（${signatureFix.changes.length} 处改动）` : `Rewrite signature (${signatureFix.changes.length})`}
              </button>
            )}
            {pseudoFix.fixed && (
              <button type="button" className="ff-button ff-button-primary" onClick={() => downloadFixed(pseudoFix.fixed!, 'unlocked')}>
                {zh ? `清除伪加密位（${pseudoFix.changes.length} 处）` : `Clear pseudo-encryption (${pseudoFix.changes.length})`}
              </button>
            )}
          </div>
          {pseudoFix.fixed && (
            <p className="ff-note">{zh ? '清位后用系统解压软件打开；若仍索要口令则是真加密（解压预览在后续版本提供）。' : 'Open the fixed file with a system unzipper; if it still asks for a password it was real encryption.'}</p>
          )}
        </div>
      )}
    </section>
  );
}

export default RarInspectCard;
