import { useState } from 'react';
import { useAppContext } from '../App';
import { t } from '../i18n';

type EncodingType = 'url' | 'base64' | 'hex' | 'html' | 'unicode' | 'jwt';

interface EncodingOption {
  id: EncodingType;
  nameKey: 'encoding.urlName' | 'encoding.base64Name' | 'encoding.hexName' | 'encoding.htmlName' | 'encoding.unicodeName' | 'encoding.jwtName';
  icon: string;
  descKey: 'encoding.urlDesc' | 'encoding.base64Desc' | 'encoding.hexDesc' | 'encoding.htmlDesc' | 'encoding.unicodeDesc' | 'encoding.jwtDesc';
}

const encodingOptions: EncodingOption[] = [
  { id: 'url', nameKey: 'encoding.urlName', icon: '🔗', descKey: 'encoding.urlDesc' },
  { id: 'base64', nameKey: 'encoding.base64Name', icon: '📦', descKey: 'encoding.base64Desc' },
  { id: 'hex', nameKey: 'encoding.hexName', icon: '🔢', descKey: 'encoding.hexDesc' },
  { id: 'html', nameKey: 'encoding.htmlName', icon: '📄', descKey: 'encoding.htmlDesc' },
  { id: 'unicode', nameKey: 'encoding.unicodeName', icon: '🌐', descKey: 'encoding.unicodeDesc' },
  { id: 'jwt', nameKey: 'encoding.jwtName', icon: '🔑', descKey: 'encoding.jwtDesc' },
];

function EncodingTools() {
  const { language } = useAppContext();
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [activeEncoding, setActiveEncoding] = useState<EncodingType>('url');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  const encode = () => {
    setError('');
    try {
      let result = '';
      switch (activeEncoding) {
        case 'url':
          result = encodeURIComponent(input);
          break;
        case 'base64':
          result = btoa(unescape(encodeURIComponent(input)));
          break;
        case 'hex':
          result = Array.from(new TextEncoder().encode(input))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
          break;
        case 'html':
          result = input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
          break;
        case 'unicode':
          result = Array.from(input)
            .map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
            .join('');
          break;
        case 'jwt':
          result = t('encoding.jwtNoEncode', language);
          break;
      }
      setOutput(result);
    } catch (e) {
      setError(t('encoding.encodeFailed', language) + (e as Error).message);
    }
  };

  const decode = () => {
    setError('');
    try {
      let result = '';
      switch (activeEncoding) {
        case 'url':
          result = decodeURIComponent(input);
          break;
        case 'base64':
          result = decodeURIComponent(escape(atob(input)));
          break;
        case 'hex':
          const bytes = input.match(/.{1,2}/g);
          if (bytes) {
            result = new TextDecoder().decode(new Uint8Array(bytes.map(b => parseInt(b, 16))));
          }
          break;
        case 'html':
          const textarea = document.createElement('textarea');
          textarea.innerHTML = input;
          result = textarea.value;
          break;
        case 'unicode':
          result = input.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => 
            String.fromCharCode(parseInt(hex, 16))
          );
          break;
        case 'jwt':
          const parts = input.split('.');
          if (parts.length !== 3) {
            throw new Error(t('encoding.invalidJwt', language));
          }
          const header = JSON.parse(atob(parts[0]));
          const payload = JSON.parse(atob(parts[1]));
          result = JSON.stringify({ header, payload, signature: parts[2] }, null, 2);
          break;
      }
      setOutput(result);
    } catch (e) {
      setError(t('encoding.decodeFailed', language) + (e as Error).message);
    }
  };

  const swapInputOutput = () => {
    const temp = input;
    setInput(output);
    setOutput(temp);
  };

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const clearAll = () => {
    setInput('');
    setOutput('');
    setError('');
  };

  return (
    <div className="encoding-tools">
      <div className="encoding-header">
        <h2>{t('encoding.title', language)}</h2>
        <p>{t('encoding.description', language)}</p>
      </div>

      <div className="encoding-tabs">
        {encodingOptions.map(option => (
          <button
            key={option.id}
            className={`encoding-tab ${activeEncoding === option.id ? 'active' : ''}`}
            onClick={() => { setActiveEncoding(option.id); clearAll(); }}
            title={t(option.descKey, language)}
          >
            <span className="tab-icon">{option.icon}</span>
            <span className="tab-name">{t(option.nameKey, language)}</span>
          </button>
        ))}
      </div>

      <div className="encoding-content">
        <div className="encoding-panel">
          <div className="panel-header">
            <label>{t('encoding.input', language)}</label>
            <button className="clear-btn" onClick={clearAll}>{t('encoding.clear', language)}</button>
          </div>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder={activeEncoding === 'jwt' ? t('encoding.inputPlaceholderJwt', language) : t('encoding.inputPlaceholder', language)}
            spellCheck={false}
          />
        </div>

        <div className="encoding-actions">
          <button className="action-btn encode" onClick={encode} disabled={activeEncoding === 'jwt'}>
            {t('encoding.encode', language)}
          </button>
          <button className="action-btn swap" onClick={swapInputOutput}>
            {t('encoding.swap', language)}
          </button>
          <button className="action-btn decode" onClick={decode}>
            {t('encoding.decode', language)}
          </button>
        </div>

        <div className="encoding-panel">
          <div className="panel-header">
            <label>{t('encoding.output', language)}</label>
            <button 
              className={`copy-btn ${copied ? 'copied' : ''}`}
              onClick={copyToClipboard}
              disabled={!output}
            >
              {copied ? t('encoding.copied', language) : t('encoding.copy', language)}
            </button>
          </div>
          <textarea
            value={error || output}
            readOnly
            className={error ? 'error' : ''}
            placeholder={t('encoding.resultPlaceholder', language)}
          />
        </div>
      </div>

      <div className="encoding-info">
        <h4>{t('encoding.usageTitle', language)}</h4>
        {activeEncoding === 'url' && (
          <p>{t('encoding.urlHelp', language)}</p>
        )}
        {activeEncoding === 'base64' && (
          <p>{t('encoding.base64Help', language)}</p>
        )}
        {activeEncoding === 'hex' && (
          <p>{t('encoding.hexHelp', language)}</p>
        )}
        {activeEncoding === 'html' && (
          <p>{t('encoding.htmlHelp', language)}</p>
        )}
        {activeEncoding === 'unicode' && (
          <p>{t('encoding.unicodeHelp', language)}</p>
        )}
        {activeEncoding === 'jwt' && (
          <p>{t('encoding.jwtHelp', language)}</p>
        )}
      </div>

      <style>{`
        .encoding-tools {
          padding: 24px;
          max-width: 1000px;
          margin: 0 auto;
        }

        .encoding-header {
          margin-bottom: 24px;
        }

        .encoding-header h2 {
          font-size: 24px;
          font-weight: 700;
          margin-bottom: 8px;
          background: var(--gradient-cyber);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }

        .encoding-header p {
          font-size: 14px;
          color: var(--text-muted);
        }

        .encoding-tabs {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          margin-bottom: 24px;
        }

        .encoding-tab {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 10px 16px;
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          color: var(--text-secondary);
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .encoding-tab:hover {
          border-color: var(--neon-cyan);
          color: var(--text-primary);
        }

        .encoding-tab.active {
          background: rgba(0, 240, 255, 0.1);
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .tab-icon {
          font-size: 16px;
        }

        .tab-name {
          font-size: 13px;
          font-weight: 500;
        }

        .encoding-content {
          display: grid;
          grid-template-columns: 1fr auto 1fr;
          gap: 16px;
          align-items: start;
        }

        .encoding-panel {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .panel-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .panel-header label {
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 1px;
          color: var(--text-muted);
        }

        .clear-btn, .copy-btn {
          background: transparent;
          border: 1px solid var(--border-color);
          color: var(--text-muted);
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 11px;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .clear-btn:hover, .copy-btn:hover {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .copy-btn.copied {
          background: rgba(0, 255, 136, 0.1);
          border-color: var(--neon-green);
          color: var(--neon-green);
        }

        .encoding-panel textarea {
          width: 100%;
          min-height: 200px;
          padding: 16px;
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          color: var(--text-primary);
          font-family: var(--font-mono);
          font-size: 13px;
          line-height: 1.6;
          resize: vertical;
          transition: border-color var(--transition-fast);
        }

        .encoding-panel textarea:focus {
          outline: none;
          border-color: var(--neon-cyan);
        }

        .encoding-panel textarea.error {
          border-color: var(--neon-red);
          color: var(--neon-red);
        }

        .encoding-panel textarea::placeholder {
          color: var(--text-muted);
        }

        .encoding-actions {
          display: flex;
          flex-direction: column;
          gap: 8px;
          padding-top: 32px;
        }

        .action-btn {
          padding: 12px 16px;
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 6px;
          color: var(--text-secondary);
          font-size: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all var(--transition-fast);
          white-space: nowrap;
        }

        .action-btn:hover:not(:disabled) {
          border-color: var(--neon-cyan);
          color: var(--neon-cyan);
        }

        .action-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .action-btn.encode:hover:not(:disabled) {
          background: rgba(0, 240, 255, 0.1);
        }

        .action-btn.decode:hover:not(:disabled) {
          background: rgba(255, 0, 255, 0.1);
          border-color: var(--neon-pink);
          color: var(--neon-pink);
        }

        .action-btn.swap {
          background: rgba(255, 102, 0, 0.1);
          border-color: var(--neon-orange);
          color: var(--neon-orange);
        }

        .encoding-info {
          margin-top: 24px;
          padding: 16px;
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
        }

        .encoding-info h4 {
          font-size: 13px;
          font-weight: 600;
          margin-bottom: 8px;
          color: var(--neon-yellow);
        }

        .encoding-info p {
          font-size: 13px;
          color: var(--text-secondary);
          line-height: 1.6;
        }

        @media (max-width: 768px) {
          .encoding-content {
            grid-template-columns: 1fr;
          }

          .encoding-actions {
            flex-direction: row;
            justify-content: center;
            padding-top: 0;
          }
        }
      `}</style>
    </div>
  );
}

export default EncodingTools;
