import { useMemo, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { jstegReveal } from '../../utils/ctf/jsteg';

// JPEG DCT 域隐写卡（批次 SI·A 线）：jsteg 提取（跳过集 {0,±1}，含 -1 开关兼容原版 C jsteg）。
// F5/outguess/JPHS 提取器在后续批次接入同一系数层。
interface JpegStegoCardProps {
  bytes: Uint8Array;
  language: 'zh' | 'en';
}

function JpegStegoCard({ bytes, language }: JpegStegoCardProps) {
  const zh = language === 'zh';
  const [includeMinusOne, setIncludeMinusOne] = useState(false);
  const [result, setResult] = useState<{ findings: string; rawPreview: string; coefficientCount: number } | null>(null);

  const run = useMemo(() => {
    return () => {
      try {
        const outcome = jstegReveal(bytes, { includeMinusOne });
        if (outcome.findings.length === 0 && outcome.rawBits.length === 0) {
          setResult({ findings: zh ? '未提取到可用位流（无合格系数）' : 'No usable bit stream', rawPreview: '', coefficientCount: outcome.coefficientCount });
          return;
        }
        const findingLines = outcome.findings
          .map(finding => `${zh ? '命中' : 'hit'} [${finding.kind}] @${finding.offset}: ${finding.preview.slice(0, 200)}`)
          .join('\n');
        const rawText = Array.from(outcome.rawBits.subarray(0, 512), byte => String.fromCharCode(byte))
          .map(char => (char.charCodeAt(0) >= 0x20 && char.charCodeAt(0) <= 0x7e ? char : '.'))
          .join('');
        setResult({
          findings: findingLines !== '' ? findingLines : (zh ? '无 magic 命中，位流前 512 字节预览如下（人工判读）' : 'No magic hit; first 512 bytes below'),
          rawPreview: rawText,
          coefficientCount: outcome.coefficientCount,
        });
        if (outcome.findings.length > 0) {
          notifications.show({ message: `${zh ? 'jsteg 命中' : 'jsteg hit'}: ${outcome.findings[0].preview.slice(0, 100)}`, color: 'teal' });
        }
      } catch (error) {
        notifications.show({ message: (error as Error).message, color: 'red' });
      }
    };
  }, [bytes, includeMinusOne, zh]);

  return (
    <section id="ff-card-jpegstego" className="ff-card" aria-label={zh ? 'JPEG DCT 隐写' : 'JPEG DCT stego'}>
      <div className="ff-card-head">
        <strong>{zh ? 'JPEG DCT 隐写（jsteg）' : 'JPEG DCT stego (jsteg)'}</strong>
        <span className="ff-badge">{bytes.length.toLocaleString()} B</span>
      </div>
      <div className="ff-tool">
        <div className="ff-row">
          <button type="button" className="ff-button ff-button-primary" onClick={run}>
            {zh ? 'jsteg 提取' : 'jsteg reveal'}
          </button>
          <label className="ff-note" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <input type="checkbox" checked={includeMinusOne} onChange={event => setIncludeMinusOne(event.target.checked)} />
            {zh ? '含 -1 系数（原版 C jsteg 语义）' : 'Include -1 (original C jsteg)'}
          </label>
        </div>
        {result !== null && (
          <>
            <p className="ff-note">{zh ? `合格系数 ${result.coefficientCount} 个` : `${result.coefficientCount} usable coefficients`}</p>
            <code className="ff-code"><FlagAutoText text={result.findings} /></code>
            {result.rawPreview !== '' && <code className="ff-code">{result.rawPreview}</code>}
          </>
        )}
      </div>
    </section>
  );
}

export default JpegStegoCard;
