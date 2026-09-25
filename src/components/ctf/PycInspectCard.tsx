import { useMemo } from 'react';
import { extractPycInfo } from '../../utils/ctf/pycParse';
import { detectPycAnomaly, extractStegosaurus } from '../../utils/ctf/pycStego';
import { copyToClipboard } from '../../utils/clipboard';

// pyc 取证卡（批次 SB）：版本/常量挖掘（flag 最常见藏点）/Stegosaurus 死槽隐写提取/结构异常。
// 解析在 useMemo 同步（引擎自带 20MB 红线）；.pyc/.pyo 由扩展名路由进来（pyc 魔数随版本漂移，魔数探测不可行）。
interface PycInspectCardProps {
  bytes: Uint8Array;
  language: 'zh' | 'en';
}

const MAX_STRING_ITEMS = 40;
const MAX_BYTES_ITEMS = 12;

function PycInspectCard({ bytes, language }: PycInspectCardProps) {
  const zh = language === 'zh';
  const report = useMemo(() => {
    try {
      const info = extractPycInfo(bytes);
      let stego: ReturnType<typeof extractStegosaurus> | null = null;
      let anomaly: ReturnType<typeof detectPycAnomaly> | null = null;
      try {
        stego = extractStegosaurus(bytes);
        anomaly = detectPycAnomaly(bytes);
      } catch { /* 隐写路径失败不阻塞常量展示 */ }
      return { info, stego, anomaly };
    } catch (error) {
      return { error: (error as Error).message };
    }
  }, [bytes]);

  if ('error' in report) {
    return (
      <section id="ff-card-pyc" className="ff-card" aria-label={zh ? 'pyc 解析' : 'pyc inspection'}>
        <div className="ff-card-head"><strong>{zh ? 'pyc 解析' : 'pyc inspection'}</strong></div>
        <p className="ff-note">{report.error}</p>
      </section>
    );
  }

  const { info, stego, anomaly } = report;
  const strings = info.strings.slice(0, MAX_STRING_ITEMS);
  const bytesConsts = info.bytesConsts.slice(0, MAX_BYTES_ITEMS);

  return (
    <section id="ff-card-pyc" className="ff-card" aria-label={zh ? 'pyc 解析' : 'pyc inspection'}>
      <div className="ff-card-head">
        <strong>{zh ? 'pyc 解析' : 'pyc inspection'}</strong>
        <span className="ff-badge">Python {info.header.version}</span>
        <span className="ff-badge">{info.codeCount} code objects</span>
      </div>

      {info.flagCandidates.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? 'flag 候选（常量区命中）' : 'Flag candidates (constants)'}</span>
          {info.flagCandidates.map((candidate, index) => (
            <span
              key={`${candidate.value}-${index}`}
              className="ff-badge ff-badge-flag"
              title={`${candidate.pattern} @${candidate.where}`}
            >
              {candidate.value}
            </span>
          ))}
        </div>
      )}

      {stego && stego.payloads.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? `Stegosaurus 隐写提取（${stego.slotCount} 槽）` : `Stegosaurus extraction (${stego.slotCount} slots)`}</span>
          {stego.payloads.map((payload, index) => (
            <button
              key={`payload-${index}`}
              type="button"
              className="ff-code ff-code-click"
              title={zh ? '点击复制' : 'Click to copy'}
              onClick={() => { void copyToClipboard(payload); }}
            >
              {payload}
            </button>
          ))}
        </div>
      )}

      {anomaly && anomaly.stegoSuspect && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '隐写迹象' : 'Stego indicators'}</span>
          {anomaly.anomalies.map((line, index) => <p key={index} className="ff-note">• {line}</p>)}
        </div>
      )}

      {strings.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? `字符串常量（${info.strings.length}，截前 ${strings.length}）` : `String constants (${info.strings.length}, first ${strings.length})`}</span>
          {strings.map((item, index) => (
            <div key={`${item.where}-${index}`} className="ff-row">
              <span className="ff-mono ff-code" title={item.where}>{item.value.length > 160 ? `${item.value.slice(0, 160)}…` : item.value}</span>
            </div>
          ))}
        </div>
      )}

      {bytesConsts.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? `bytes 常量（${info.bytesConsts.length}，截前 ${bytesConsts.length}）` : `bytes constants (${info.bytesConsts.length}, first ${bytesConsts.length})`}</span>
          {bytesConsts.map((item, index) => (
            <div key={`${item.where}-${index}`} className="ff-row">
              <span className="ff-badge">{item.length}B</span>
              <span className="ff-mono ff-code" title={item.hex}>{item.latin1.length > 120 ? `${item.latin1.slice(0, 120)}…` : item.latin1}</span>
            </div>
          ))}
        </div>
      )}

      {info.names.length > 0 && (
        <div className="ff-row">
          <span className="ff-label">{zh ? '名字表' : 'Names'}</span>
          {info.names.slice(0, 30).map(name => <span key={name} className="ff-badge">{name}</span>)}
          {info.names.length > 30 && <span className="ff-note">+{info.names.length - 30}</span>}
        </div>
      )}

      {info.anomalies.length > 0 && (
        <div className="ff-tool">
          <span className="ff-label">{zh ? '结构异常' : 'Anomalies'}</span>
          {info.anomalies.map((line, index) => <p key={index} className="ff-note">• {line}</p>)}
        </div>
      )}

      <p className="ff-note">
        {zh
          ? '完整反编译为 py 源码是 uncompyle6 级工程（长期路线）；常量/名字提取覆盖 CTF pyc 题主要得分面。'
          : 'Full decompilation to source is a long-term item; constant/name extraction covers the main scoring surface of CTF pyc challenges.'}
      </p>
    </section>
  );
}

export default PycInspectCard;
