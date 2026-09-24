import { useMemo, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import {
  bruteZipPassword,
  detectEncryptedEntries,
  dictionaryCandidates,
  maskCandidates,
} from '../../utils/ctf/zipBrute';
import type { BruteProgress, ZipEncryptedEntry } from '../../utils/ctf/zipBrute';
import { copyToClipboard } from '../../utils/clipboard';

// ZIP 密码爆破卡：上传流里检测到加密条目时渲染。三种候选源（内置字典 / 自定义列表 / 掩码笛卡尔积），
// 引擎自带时间预算与 onProgress 节流；换文件由父层 key remount 清状态。
interface ZipBruteCardProps {
  bytes: Uint8Array;
  language: 'zh' | 'en';
}

const METHOD_LABEL: Record<ZipEncryptedEntry['method'], string> = {
  zipcrypto: 'ZipCrypto',
  'aes-128': 'AES-128',
  'aes-192': 'AES-192',
  'aes-256': 'AES-256',
  unknown: '?',
};

function ZipBruteCard({ bytes, language }: ZipBruteCardProps) {
  const zh = language === 'zh';
  const entries = useMemo(() => {
    try {
      return detectEncryptedEntries(bytes);
    } catch {
      return null;
    }
  }, [bytes]);

  const [entryIndex, setEntryIndex] = useState(0);
  const [mode, setMode] = useState<'dictionary' | 'custom' | 'mask'>('dictionary');
  const [customList, setCustomList] = useState('');
  const [maskCharset, setMaskCharset] = useState('0123456789');
  const [maskMin, setMaskMin] = useState(4);
  const [maskMax, setMaskMax] = useState(6);
  const [budget, setBudget] = useState(15000);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<BruteProgress | null>(null);

  if (entries === null) {
    return (
      <section id="ff-card-zipbrute" className="ff-card" aria-label={zh ? 'ZIP 密码爆破' : 'ZIP password brute force'}>
        <div className="ff-card-head"><strong>{zh ? 'ZIP 密码爆破' : 'ZIP password brute force'}</strong></div>
        <p className="ff-note">{zh ? 'ZIP 目录结构异常，无法枚举加密条目。' : 'The ZIP directory structure is broken; encrypted entries cannot be listed.'}</p>
      </section>
    );
  }
  if (entries.length === 0) {
    return (
      <section id="ff-card-zipbrute" className="ff-card" aria-label={zh ? 'ZIP 密码爆破' : 'ZIP password brute force'}>
        <div className="ff-card-head"><strong>{zh ? 'ZIP 密码爆破' : 'ZIP password brute force'}</strong></div>
        <p className="ff-note">
          {zh
            ? '未检测到加密条目。若打不开但此处显示未加密，多半是伪加密——用上方「清除伪加密标志」或密码域的 CRC32 工具（zipHex=）修复。'
            : 'No encrypted entries detected. If the file still will not open, it is likely pseudo-encryption; clear the flags above or use the CRC32 tool (zipHex=).'}
        </p>
      </section>
    );
  }

  const entry = entries[Math.min(entryIndex, entries.length - 1)];

  const run = async () => {
    if (running || !entry) return;
    let candidates: Iterable<string>;
    if (mode === 'dictionary') candidates = dictionaryCandidates();
    else if (mode === 'custom') {
      const list = customList.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      if (!list.length) {
        notifications.show({ message: zh ? '自定义口令列表为空。' : 'The custom password list is empty.', color: 'red' });
        return;
      }
      candidates = list;
    } else {
      const charset = Array.from(new Set(maskCharset.split('').filter(char => char.trim()))).join('');
      if (charset.length < 2) {
        notifications.show({ message: zh ? '掩码字符集至少需要 2 个不同字符。' : 'The mask charset needs at least 2 distinct characters.', color: 'red' });
        return;
      }
      candidates = maskCandidates(charset, Math.max(1, maskMin), Math.max(Math.max(1, maskMin), maskMax));
    }
    setRunning(true);
    setProgress(null);
    try {
      const result = await bruteZipPassword(bytes, entry, candidates, {
        timeBudgetMs: budget,
        onProgress: update => setProgress({ ...update }),
      });
      setProgress(result);
      if (result.password) {
        notifications.show({
          message: zh ? `命中口令：${result.password}` : `Password found: ${result.password}`,
          color: 'teal',
        });
      }
    } catch (error) {
      notifications.show({ message: (error as Error).message, color: 'red' });
    } finally {
      setRunning(false);
    }
  };

  const totalText = progress?.total !== undefined && progress.total < Infinity ? progress.total.toLocaleString() : '∞';

  return (
    <section id="ff-card-zipbrute" className="ff-card" aria-label={zh ? 'ZIP 密码爆破' : 'ZIP password brute force'}>
      <div className="ff-card-head">
        <strong>{zh ? 'ZIP 密码爆破' : 'ZIP password brute force'}</strong>
        <span className="ff-badge ff-badge-warn">{zh ? `${entries.length} 个加密条目` : `${entries.length} encrypted entries`}</span>
      </div>
      <div className="ff-tool">
        <div className="ff-row">
          <select className="ff-select" value={entryIndex} aria-label={zh ? '加密条目' : 'Encrypted entry'}
            onChange={event => { setEntryIndex(Number(event.target.value)); setProgress(null); }}>
            {entries.map((item, index) => (
              <option key={`${item.fileName}:${index}`} value={index}>{item.fileName} · {METHOD_LABEL[item.method]}</option>
            ))}
          </select>
          <select className="ff-select" value={budget} aria-label={zh ? '时间预算' : 'Time budget'}
            onChange={event => setBudget(Number(event.target.value))}>
            <option value={5000}>{zh ? '预算 5 秒' : '5s budget'}</option>
            <option value={15000}>{zh ? '预算 15 秒' : '15s budget'}</option>
            <option value={60000}>{zh ? '预算 60 秒' : '60s budget'}</option>
          </select>
        </div>
        <div className="ff-row">
          {([
            ['dictionary', zh ? '内置字典' : 'Built-in dictionary'],
            ['custom', zh ? '自定义列表' : 'Custom list'],
            ['mask', zh ? '掩码枚举' : 'Mask brute'],
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
            <input
              className="ff-input"
              value={maskCharset}
              aria-label={zh ? '掩码字符集' : 'Mask charset'}
              onChange={event => setMaskCharset(event.target.value)}
            />
            <select className="ff-select" value={maskMin} aria-label={zh ? '最短长度' : 'Min length'}
              onChange={event => setMaskMin(Number(event.target.value))}>
              {[1, 2, 3, 4, 5, 6, 7, 8].map(len => <option key={len} value={len}>{zh ? `${len} 位起` : `from ${len}`}</option>)}
            </select>
            <select className="ff-select" value={maskMax} aria-label={zh ? '最长长度' : 'Max length'}
              onChange={event => setMaskMax(Number(event.target.value))}>
              {[1, 2, 3, 4, 5, 6, 7, 8].map(len => <option key={len} value={len}>{zh ? `${len} 位止` : `to ${len}`}</option>)}
            </select>
          </div>
        )}
        <div className="ff-row">
          <button type="button" className="ff-button ff-button-primary" disabled={running} onClick={() => { void run(); }}>
            {running ? (zh ? '爆破中…' : 'Running…') : zh ? '开始爆破' : 'Start brute force'}
          </button>
          {progress && (
            <span className="ff-badge">
              {zh ? `已试 ${progress.tried.toLocaleString()} / ${totalText}` : `Tried ${progress.tried.toLocaleString()} / ${totalText}`}
            </span>
          )}
        </div>
        {progress && progress.password && (
          <div className="ff-tool">
            <div className="ff-row">
              <span className="ff-badge ff-badge-ok">{zh ? '口令' : 'Password'}: {progress.password}</span>
              <button type="button" className="ff-button" onClick={() => { void copyToClipboard(progress.password!); }}>
                {zh ? '复制口令' : 'Copy password'}
              </button>
            </div>
            {progress.previewText && <code className="ff-code"><FlagAutoText text={progress.previewText} /></code>}
          </div>
        )}
        {progress && !progress.password && (
          <p className="ff-note">
            {zh
              ? `本轮未命中（已试 ${progress.tried.toLocaleString()} 个口令）。掩码模式可加长时间预算重跑，或换自定义列表。`
              : `No hit this round (${progress.tried.toLocaleString()} tried). Extend the budget in mask mode or try a custom list.`}
          </p>
        )}
      </div>
    </section>
  );
}

export default ZipBruteCard;
