import { memo, useCallback, useEffect, useRef, useState } from 'react';
import { downloadBytes } from '../../utils/download';
import { parseUpx, upxDecompressAll } from '../../utils/ctf/upxTools';
import type { UpxInfo } from '../../utils/ctf/upxTools';
import { extractStrings } from '../../utils/ctf/fileDetect';
import '../../styles/ctf-forensics.css';

const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

// UPX 脱壳卡（批次 UX）：拖入 UPX 壳 ELF/PE → 特征解析（版本/方法/原始大小/块清单）+
// 浏览器内解压（NRV2B/2D/2E + calltrick filter 逆变换）→ strings 直接搜 flag。
// LZMA 壳与可执行重建走本地 upx -d 指导（成本收益红线）。
function UpxCard({ bytes, fileName, language }: { bytes: Uint8Array; fileName: string; language: 'zh' | 'en' }) {
  const zh = language === 'zh';
  const [info, setInfo] = useState<UpxInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decompressed, setDecompressed] = useState<Uint8Array | null>(null);
  const [decompressError, setDecompressError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const lastTokenRef = useRef('');

  const run = useCallback(async () => {
    const parsed = parseUpx(bytes);
    if (!parsed.ok) {
      setError(parsed.error);
      setInfo(null);
      setDecompressed(null);
      return;
    }
    setError(null);
    setInfo(parsed);
    const result = upxDecompressAll(bytes, parsed);
    setDecompressError(result.error ?? null);
    setDecompressed(result.data ?? null);
  }, [bytes]);

  useEffect(() => {
    const token = `${fileName}:${bytes.length}`;
    if (lastTokenRef.current === token) return;
    lastTokenRef.current = token;
    void run();
  }, [run, fileName, bytes]);

  const strings = decompressed
    ? extractStrings(decompressed, { limit: 3000, minLength: 6 }).values
    : [];
  const filtered = search.trim()
    ? strings.filter(s => s.toLowerCase().includes(search.trim().toLowerCase()))
    : strings.slice(0, 300);

  return (
    <section className="ff-card ff-card-flag" aria-label={zh ? 'UPX 脱壳' : 'UPX unpack'}>
      <div className="ff-card-head">
        <strong>{zh ? 'UPX 脱壳（浏览器内解压）' : 'UPX unpack (in-browser)'}</strong>
        <span className="ff-size">{fileName}</span>
        {decompressed && (
          <button
            type="button"
            className="ff-button"
            onClick={() => downloadBytes(decompressed, `${fileName.replace(/\.[^.]*$/, '')}-unpacked.bin`)}
          >
            {zh ? '下载解压产物' : 'Download unpacked'}
          </button>
        )}
      </div>
      {error && <p className="ff-note">{error}</p>}
      {info && (
        <div className="ff-row">
          <span className="ff-badge">UPX v{info.upxVersion}</span>
          <span className="ff-badge">{info.format}</span>
          <span className="ff-badge">{info.method}</span>
          <span className="ff-badge">{zh ? `原始 ${formatBytes(info.originalSize)}` : `original ${formatBytes(info.originalSize)}`}</span>
          <span className="ff-badge">{zh ? `壳后 ${formatBytes(info.packedSize)}` : `packed ${formatBytes(info.packedSize)}`}</span>
          <span className="ff-badge">{zh ? `${info.blocks.length} 压缩块` : `${info.blocks.length} blocks`}</span>
          {info.filter !== 0 && <span className="ff-badge ff-badge-warn">filter 0x{info.filter.toString(16)}</span>}
        </div>
      )}
      {decompressError && (
        <p className="ff-note">
          {decompressError}
          {zh ? ' —— 本地命令：upx -d -o unpacked.bin 文件名' : ' — local command: upx -d -o unpacked.bin <file>'}
        </p>
      )}
      {decompressed && !decompressError && (
        <>
          <div className="ff-controls">
            <span className="ff-label">{zh ? `解压 ${formatBytes(decompressed.length)}，strings 搜索` : `Unpacked ${formatBytes(decompressed.length)}, strings`}</span>
            <input
              className="ff-input ff-input-narrow"
              type="text"
              value={search}
              placeholder={zh ? 'flag / key / http…' : 'flag / key / http…'}
              aria-label={zh ? '字符串搜索' : 'String search'}
              onChange={event => setSearch(event.target.value)}
            />
            <span className="ff-badge">{zh ? `${filtered.length} 条` : `${filtered.length} hits`}</span>
          </div>
          <div className="ff-strings" role="list">
            {filtered.slice(0, 200).map((text, i) => (
              <span key={`${i}-${text.slice(0, 16)}`} role="listitem" className="ff-code">{text}</span>
            ))}
          </div>
          <p className="ff-note">
            {zh
              ? '说明：解压产物按 UPX 块序（= PT_LOAD 段序）拼接，代码与只读段逐字节还原；RW 数据段含运行时重排数据（upx -d 级重建需本地执行）。'
              : 'Note: output is the UPX block order (= PT_LOAD order); code and read-only segments restore byte-exact; the RW segment carries runtime-relocated data (run upx -d locally for a full rebuild).'}
          </p>
        </>
      )}
    </section>
  );
}

export default memo(UpxCard);
