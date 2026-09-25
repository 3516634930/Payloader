import { useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { steghideExtractBmp, steghideExtractWav } from '../../utils/ctf/steghideExtract';
import { downloadBytes } from './ffDownload';

// steghide 提取卡（批次 SI·B 线）：BMP/WAV 载体（原始字节解析，口令必填——CTF 高频"给定口令提取"）。
interface SteghideCardProps {
  bytes: Uint8Array;
  kind: 'bmp' | 'wav';
  language: 'zh' | 'en';
}

function SteghideCard({ bytes, kind, language }: SteghideCardProps) {
  const zh = language === 'zh';
  const [passphrase, setPassphrase] = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<{ text: string; data: Uint8Array | null } | null>(null);

  const run = async () => {
    if (running) return;
    if (passphrase === '') {
      notifications.show({ message: zh ? '请输入口令（steghide 提取需要口令）。' : 'A passphrase is required.', color: 'red' });
      return;
    }
    setRunning(true);
    setResult(null);
    try {
      const outcome = kind === 'bmp' ? await steghideExtractBmp(bytes, passphrase) : await steghideExtractWav(bytes, passphrase);
      const preview = new TextDecoder().decode(outcome.data.subarray(0, 400));
      setResult({ text: `${zh ? '提取成功' : 'Extracted'} ${outcome.fileName} (${outcome.data.length} B)${outcome.crcOk ? '' : '，CRC 校验未过（口令可能错误）'}\n${preview}`, data: outcome.data });
      if (outcome.crcOk) notifications.show({ message: zh ? 'steghide 提取成功，CRC 校验通过' : 'steghide extracted, CRC OK', color: 'teal' });
    } catch (error) {
      notifications.show({ message: (error as Error).message, color: 'red' });
    } finally {
      setRunning(false);
    }
  };

  return (
    <section id="ff-card-steghide" className="ff-card" aria-label={zh ? 'steghide 提取' : 'steghide extract'}>
      <div className="ff-card-head">
        <strong>{zh ? `steghide 提取（${kind === 'bmp' ? 'BMP' : 'WAV'} 载体）` : `steghide extract (${kind.toUpperCase()})`}</strong>
        <span className="ff-badge">{bytes.length.toLocaleString()} B</span>
      </div>
      <div className="ff-tool">
        <div className="ff-row">
          <input className="ff-input" style={{ width: 160 }} value={passphrase} aria-label={zh ? '口令' : 'Passphrase'} placeholder={zh ? '口令' : 'passphrase'} onChange={event => setPassphrase(event.target.value)} />
          <button type="button" className="ff-button ff-button-primary" disabled={running} onClick={() => { void run(); }}>
            {running ? (zh ? '提取中…' : 'Extracting…') : zh ? '提取' : 'Extract'}
          </button>
        </div>
        {result !== null && (
          <>
            <code className="ff-code"><FlagAutoText text={result.text} /></code>
            {result.data !== null && result.data.length > 0 && (
              <button type="button" className="ff-button" onClick={() => downloadBytes(result.data!, 'steghide-out.bin')}>
                {zh ? '下载提取内容' : 'Download'}
              </button>
            )}
          </>
        )}
      </div>
    </section>
  );
}

export default SteghideCard;
