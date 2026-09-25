import { memo, useCallback, useEffect, useRef, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { copyToClipboard } from '../../utils/clipboard';
import { analyzeRouterConfig } from '../../utils/ctf/routerConfig';
import type { RouterConfigResult } from '../../utils/ctf/routerConfig';
import '../../styles/ctf-forensics.css';

// 路由器备份文件密码提取卡（批次 RP，RouterPassView 对标）：拖入 TP-Link conf.bin /
// WR841N config.bin / rom-0 / Asus / D-Link / gzip 系，自动解密解压并抽取密码类字段。
// 全部本地计算（DES 走内置 crypto-js，密钥不出浏览器）。
function RouterConfigCard({ bytes, fileName, language }: { bytes: Uint8Array; fileName: string; language: 'zh' | 'en' }) {
  const zh = language === 'zh';
  const [result, setResult] = useState<RouterConfigResult | null>(null);
  const lastTokenRef = useRef('');
  const token = `${fileName}:${bytes.length}`;

  const run = useCallback(async () => {
    try {
      setResult(await analyzeRouterConfig(fileName, bytes));
    } catch (error) {
      setResult({ ok: false, typeName: '未知', steps: [], content: null, secrets: [], error: error instanceof Error ? error.message : String(error) });
    }
  }, [bytes, fileName]);

  useEffect(() => {
    if (lastTokenRef.current === token) return;
    lastTokenRef.current = token;
    void run();
  }, [run, token]);

  return (
    <section className="ff-card ff-card-flag" aria-label={zh ? '路由器备份分析' : 'Router config analysis'}>
      <div className="ff-card-head">
        <strong>{zh ? '路由器备份密码提取（RouterPassView 对标）' : 'Router backup password recovery'}</strong>
        <span className="ff-size">{fileName}</span>
      </div>
      {result === null && <p className="ff-note">{zh ? '解析中…' : 'Parsing…'}</p>}
      {result && (
        <>
          <div className="ff-row">
            <span className="ff-badge">{result.typeName}</span>
            {result.ok
              ? <span className="ff-badge ff-badge-ok">{zh ? '解密解压成功' : 'Decrypted'}</span>
              : <span className="ff-badge ff-badge-warn">{result.error ?? '解析失败'}</span>}
          </div>
          {result.steps.length > 0 && (
            <div className="ff-row">
              {result.steps.map((step, i) => <span key={i} className="ff-badge">{step}</span>)}
            </div>
          )}
          {result.secrets.length > 0 && (
            <>
              <div className="ff-row">
                <span className="ff-label">{zh ? `提取到 ${result.secrets.length} 个密码字段` : `${result.secrets.length} secret fields`}</span>
              </div>
              <div className="ff-strings" role="list">
                {result.secrets.map((secret, i) => (
                  <button
                    key={`${secret.field}-${i}`}
                    type="button"
                    role="listitem"
                    className="ff-button"
                    style={{ justifyContent: 'flex-start' }}
                    title={zh ? '点击复制值' : 'Copy value'}
                    onClick={() => {
                      void copyToClipboard(secret.value).then(ok => {
                        if (ok) notifications.show({ message: zh ? '已复制。' : 'Copied.', color: 'teal', autoClose: 1200 });
                      });
                    }}
                  >
                    <span className="ff-mono">{secret.field}</span>
                    <span className="ff-size"> = </span>
                    <span className="ff-mono">{secret.value}</span>
                  </button>
                ))}
              </div>
            </>
          )}
          {result.content && (
            <details className="pwn-details">
              <summary>{zh ? '查看完整配置内容' : 'View full config'}</summary>
              <div className="ff-code ff-code-dump">{result.content.slice(0, 20000)}</div>
            </details>
          )}
          {!result.ok && (
            <p className="ff-note">
              {zh
                ? '支持：TP-Link conf.bin（DES+LZSS）、WR841N 系 config.bin（DES+zlib）、rom-0（LZS）、Asus HDR1、D-Link 系、gzip/zlib/XML。ZTE/Huawei AES 系需机身 SN 当密钥，暂走速查命令指导。'
                : 'Supports TP-Link conf.bin (DES+LZSS), WR841N config.bin (DES+zlib), rom-0 (LZS), Asus HDR1, D-Link, gzip/zlib/XML. ZTE/Huawei AES variants need the device SN as key — see the cheat sheet.'}
            </p>
          )}
        </>
      )}
    </section>
  );
}

export default memo(RouterConfigCard);
