import { useMemo, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { fixRarPseudoEncryption, fixRarSignature, inspectRar } from '../../utils/ctf/rarInspect';
import type { RarInspectResult } from '../../utils/ctf/rarInspect';
import { bruteRarPassword, detectRarEncryptedEntries } from '../../utils/ctf/rarBrute';
import { downloadBytes } from './ffDownload';

// RAR4 取证卡：条目表/结构线索/一键伪加密清位与签名重写（SimpleRAR 型头修复题），修复产物下载。
// 带 salt 的真加密条目渲染 RAR3 口令爆破区（SHA-1 拉伸 + AES-128-CBC 快筛 + 解压 CRC 终验）。
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
  // 真加密条目（detect 抛错 = 无加密/RAR5/无盐伪加密，均不渲染爆破区）。
  const encryptedEntries = useMemo(() => {
    try { return detectRarEncryptedEntries(bytes); } catch { return []; }
  }, [bytes]);
  const [mode, setMode] = useState<'dictionary' | 'custom' | 'mask'>('dictionary');
  const [customList, setCustomList] = useState('');
  const [maskCharset, setMaskCharset] = useState('0123456789');
  const [maskMin, setMaskMin] = useState(4);
  const [maskMax, setMaskMax] = useState(6);
  const [budget, setBudget] = useState(60000);
  const [running, setRunning] = useState(false);
  const [progressText, setProgressText] = useState('');
  const [hit, setHit] = useState<{ password: string; tried: number; content: Uint8Array | null } | null>(null);

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

  const runBrute = async () => {
    if (running) return;
    setRunning(true);
    setProgressText(zh ? '正在派生密钥并验证口令（约 30ms/口令）…' : 'Deriving keys per password (~30ms each)…');
    setHit(null);
    try {
      const options: Parameters<typeof bruteRarPassword>[1] = {
        timeBudgetMs: budget,
        onProgress: update => setProgressText(zh ? `已试 ${update.tried} 个口令…` : `Tried ${update.tried} passwords…`),
      };
      if (mode === 'custom') {
        const list = customList.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
        if (!list.length) {
          notifications.show({ message: zh ? '自定义口令列表为空。' : 'The custom password list is empty.', color: 'red' });
          setRunning(false);
          return;
        }
        options.candidates = list;
      } else if (mode === 'mask') {
        const charset = Array.from(new Set(maskCharset.split('').filter(char => char.trim()))).join('');
        if (charset.length < 2) {
          notifications.show({ message: zh ? '掩码字符集至少需要 2 个不同字符。' : 'The mask charset needs at least 2 distinct characters.', color: 'red' });
          setRunning(false);
          return;
        }
        options.charset = charset;
        options.minLength = Math.max(1, maskMin);
        options.maxLength = Math.max(Math.max(1, maskMin), maskMax);
      }
      const outcome = await bruteRarPassword(bytes, options);
      if (outcome?.password) {
        setHit({ password: outcome.password, tried: outcome.tried, content: outcome.content ?? null });
        notifications.show({ message: zh ? `命中口令：${outcome.password}` : `Password found: ${outcome.password}`, color: 'teal' });
      } else {
        setProgressText(zh ? `预算内未命中（已试 ${outcome?.tried ?? 0} 个）——可提高预算或换候选源。` : `No hit within budget (${outcome?.tried ?? 0} tried); raise the budget or switch sources.`);
      }
    } catch (error) {
      notifications.show({ message: (error as Error).message, color: 'red' });
    } finally {
      setRunning(false);
    }
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
      {encryptedEntries.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? `RAR3 密码爆破（${encryptedEntries.length} 个带 salt 的真加密条目）` : `RAR3 password brute (${encryptedEntries.length} salted entries)`}</span>
          <div className="ff-row">
            {([
              ['dictionary', zh ? '内置字典' : 'Built-in dictionary'],
              ['custom', zh ? '自定义列表' : 'Custom list'],
              ['mask', zh ? '数字/掩码枚举' : 'Mask brute'],
            ] as const).map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={`ff-button${mode === value ? ' ff-button-primary' : ''}`}
                onClick={() => setMode(value)}
              >
                {label}
              </button>
            ))}
            <select className="ff-select" value={budget} aria-label={zh ? '时间预算' : 'Time budget'}
              onChange={event => setBudget(Number(event.target.value))}>
              <option value={30000}>{zh ? '预算 30 秒' : '30s budget'}</option>
              <option value={60000}>{zh ? '预算 60 秒' : '60s budget'}</option>
              <option value={300000}>{zh ? '预算 5 分钟' : '5min budget'}</option>
            </select>
          </div>
          {mode === 'custom' && (
            <textarea
              className="ff-input"
              rows={4}
              value={customList}
              aria-label={zh ? '自定义口令列表（每行一个）' : 'Custom passwords (one per line)'}
              placeholder={zh ? '每行一个口令' : 'One password per line'}
              onChange={event => setCustomList(event.target.value)}
            />
          )}
          {mode === 'mask' && (
            <div className="ff-row">
              <input className="ff-input" value={maskCharset} aria-label={zh ? '掩码字符集' : 'Mask charset'} onChange={event => setMaskCharset(event.target.value)} />
              <select className="ff-select" value={maskMin} aria-label={zh ? '最短长度' : 'Min length'}
                onChange={event => setMaskMin(Number(event.target.value))}>
                {[1, 2, 3, 4, 5, 6].map(len => <option key={len} value={len}>{len}</option>)}
              </select>
              <select className="ff-select" value={maskMax} aria-label={zh ? '最长长度' : 'Max length'}
                onChange={event => setMaskMax(Number(event.target.value))}>
                {[1, 2, 3, 4, 5, 6, 7, 8].map(len => <option key={len} value={len}>{len}</option>)}
              </select>
            </div>
          )}
          <div className="ff-row">
            <button type="button" className="ff-button ff-button-primary" disabled={running} onClick={() => { void runBrute(); }}>
              {running ? (zh ? '爆破中…' : 'Running…') : (zh ? '开始爆破' : 'Start brute force')}
            </button>
            <span className="ff-note">{progressText}</span>
          </div>
          {hit && (
            <div className="ff-tool">
              <div className="ff-row">
                <span className="ff-badge ff-badge-flag">{hit.password}</span>
                <span className="ff-note">{zh ? `（试 ${hit.tried} 个命中）` : `(found after ${hit.tried})`}</span>
                {hit.content && (
                  <button type="button" className="ff-button" onClick={() => downloadBytes(hit.content!, `${baseName}-${(encryptedEntries[0]?.name ?? 'entry').replace(/[\\/:*?"<>|]/g, '_')}`)}>
                    {zh ? '下载解密条目' : 'Download decrypted entry'}
                  </button>
                )}
              </div>
              {hit.content && <code className="ff-code">{Array.from(hit.content.subarray(0, 1024), b => String.fromCharCode(b)).join('')}</code>}
            </div>
          )}
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
            <p className="ff-note">{zh ? '注意：仅当条目无 salt 时才是伪加密；带 salt 的真加密请用上方爆破区。' : 'Only salt-less entries are pseudo-encrypted; salted real encryption goes through the brute-force section above.'}</p>
          )}
        </div>
      )}
    </section>
  );
}

export default RarInspectCard;
