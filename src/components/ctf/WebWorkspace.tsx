import { memo, useCallback, useMemo, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { useLanguage } from '../../appContext';
import { copyToClipboard } from '../../utils/clipboard';
import CheatsheetSection from './CheatsheetSection';
import {
  SSTI_PAYLOADS, SSTI_PROBES, buildCommandBypasses, buildSqliMatrix,
  decodeFlaskSession, detectSstiEngine, judgePhpLoose, jwtWeakSecretCrack,
  parseCurl, parseHttpMessage, PHP_LOOSE_TABLE, MAGIC_HASHES,
  sendViaProxy, blindBooleanExtract, unionDump, probeDirectories,
} from '../../utils/ctf/webTools';
import type { ProxyResponse, BlindResult, UnionDumpResult, DirProbeHit } from '../../utils/ctf/webTools';
import '../../styles/ctf-forensics.css';

const copyBlock = (text: string, zh: boolean): void => {
  void copyToClipboard(text).then(ok => {
    if (!ok) notifications.show({ message: zh ? '复制失败，请手动选择复制。' : 'Copy failed; select manually.', color: 'red' });
    else notifications.show({ message: zh ? '已复制。' : 'Copied.', color: 'teal', autoClose: 1200 });
  });
};

// ---- SSTI 卡：判定 + payload 矩阵 ----

function SstiCard({ zh }: { zh: boolean }) {
  const [rendered, setRendered] = useState('');
  const candidates = useMemo(() => (rendered.trim() ? detectSstiEngine(rendered) : []), [rendered]);

  return (
    <section className="ff-card" aria-label={zh ? 'SSTI 引擎识别' : 'SSTI engine detection'}>
      <div className="ff-card-head"><strong>{zh ? 'SSTI：回显判定 + payload 矩阵' : 'SSTI: detect + payload matrix'}</strong></div>
      <p className="ff-note">
        {zh
          ? '第一步探语法：把探测串送进模板，回显结果贴到下面判引擎；判定后按矩阵取对应 RCE。'
          : 'Probe the syntax, paste the rendered output below to identify the engine, then pick the RCE row.'}
      </p>
      <div className="ff-row">
        {SSTI_PROBES.map(probe => (
          <button key={probe.probe} type="button" className="ff-button" onClick={() => copyBlock(probe.probe, zh)} title={zh ? '点击复制' : 'Copy'}>
            <span className="ff-mono">{probe.probe}</span>
            <span className="ff-size"> → {probe.expect}</span>
          </button>
        ))}
      </div>
      <div className="ff-controls">
        <input
          className="ff-input"
          type="text"
          value={rendered}
          placeholder={zh ? '粘贴页面回显（如 49 / 7777777）' : 'Paste the rendered output (e.g. 49 / 7777777)'}
          aria-label={zh ? '回显内容' : 'Rendered output'}
          onChange={event => setRendered(event.target.value)}
        />
      </div>
      {candidates.length > 0 && (
        <div className="ff-row">
          {candidates.map(candidate => (
            <span key={candidate.engine} className={`ff-badge ${candidate.confidence === 'high' ? 'ff-badge-ok' : 'ff-badge-warn'}`}>
              {candidate.engine}（{candidate.confidence === 'high' ? zh ? '高置信' : 'high' : zh ? '待确认' : 'medium'}）：{candidate.reason}
            </span>
          ))}
        </div>
      )}
      <div className="ff-strings" role="list">
        {SSTI_PAYLOADS.map(row => (
          <article key={row.engine} role="listitem" className="ff-code ff-code-click" onClick={() => copyBlock(row.rce, zh)} title={zh ? '点击复制 RCE' : 'Copy RCE'}>
            <div className="ff-row"><span className="ff-badge">{row.engine}</span><span className="ff-mono">{row.verify}</span></div>
            <pre className="cs-snippet">{row.rce}</pre>
            <span className="ff-note">{row.note}</span>
          </article>
        ))}
      </div>
    </section>
  );
}

// ---- 命令注入绕过卡 ----

function CmdBypassCard({ zh }: { zh: boolean }) {
  const [command, setCommand] = useState('cat /flag');
  const results = useMemo(() => (command.trim() ? buildCommandBypasses(command) : []), [command]);

  return (
    <section className="ff-card" aria-label={zh ? '命令注入绕过' : 'Command injection bypass'}>
      <div className="ff-card-head"><strong>{zh ? '命令注入绕过生成器' : 'Command injection bypasses'}</strong></div>
      <div className="ff-controls">
        <input
          className="ff-input"
          type="text"
          value={command}
          placeholder={zh ? '目标命令，如 cat /flag' : 'Target command, e.g. cat /flag'}
          aria-label={zh ? '命令' : 'Command'}
          onChange={event => setCommand(event.target.value)}
        />
      </div>
      {results.length > 0 && (
        <div className="ff-strings" role="list">
          {results.map((result, i) => (
            <button key={i} type="button" role="listitem" className="ff-button" style={{ justifyContent: 'flex-start' }} onClick={() => copyBlock(result.payload, zh)}>
              <span className="ff-badge">{result.category}</span>
              <span className="ff-mono">{result.payload}</span>
              <span className="ff-size"> — {result.note}</span>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

// ---- SQLi 矩阵卡 ----

function SqliCard({ zh }: { zh: boolean }) {
  const [target, setTarget] = useState<'union' | 'error' | 'blind' | 'time'>('union');
  const rows = useMemo(() => buildSqliMatrix(target), [target]);
  const targets: Array<{ id: typeof target; label: string }> = [
    { id: 'union', label: zh ? '联合查询' : 'UNION' },
    { id: 'error', label: zh ? '报错' : 'Error-based' },
    { id: 'blind', label: zh ? '布尔盲注' : 'Boolean blind' },
    { id: 'time', label: zh ? '时间盲注' : 'Time-based' },
  ];

  return (
    <section className="ff-card" aria-label={zh ? 'SQL 注入矩阵' : 'SQLi matrix'}>
      <div className="ff-card-head"><strong>{zh ? 'SQL 注入 payload 矩阵' : 'SQLi payload matrix'}</strong></div>
      <div className="ff-controls">
        {targets.map(item => (
          <button key={item.id} type="button" className={target === item.id ? 'ff-button ff-button-primary' : 'ff-button'} onClick={() => setTarget(item.id)}>{item.label}</button>
        ))}
      </div>
      <div className="ff-strings" role="list">
        {rows.map((row, i) => (
          <button key={i} type="button" role="listitem" className="ff-button" style={{ justifyContent: 'flex-start' }} onClick={() => copyBlock(row.payload, zh)} title={zh ? '点击复制' : 'Copy'}>
            <span className="ff-badge">{row.database}</span>
            <span className="ff-mono">{row.payload}</span>
            <span className="ff-size"> — {row.note}</span>
          </button>
        ))}
      </div>
    </section>
  );
}

// ---- Flask Session + JWT 爆破卡 ----

function TokenCard({ zh }: { zh: boolean }) {
  const [session, setSession] = useState('');
  const [jwt, setJwt] = useState('');
  const [jwtExtra, setJwtExtra] = useState('');
  const [jwtBusy, setJwtBusy] = useState(false);
  const [jwtResult, setJwtResult] = useState<string | null>(null);

  const flask = useMemo(() => (session.trim() ? decodeFlaskSession(session) : null), [session]);

  const runCrack = useCallback(async () => {
    setJwtBusy(true);
    setJwtResult(null);
    try {
      const extras = jwtExtra.split(/[,，\s]+/).map(s => s.trim()).filter(Boolean);
      const result = await jwtWeakSecretCrack(jwt, extras);
      setJwtResult('secret' in result
        ? (zh ? `命中密钥：${result.secret}（第 ${result.tried} 次尝试）` : `Secret found: ${result.secret} (attempt #${result.tried})`)
        : (zh ? `未命中：${result.error}` : `Missed: ${result.error}`));
    } finally {
      setJwtBusy(false);
    }
  }, [jwt, jwtExtra, zh]);

  return (
    <section className="ff-card" aria-label={zh ? 'Session 与 JWT' : 'Sessions & JWT'}>
      <div className="ff-card-head"><strong>{zh ? 'Flask Session 解码 / JWT 弱口令爆破' : 'Flask session / JWT weak-secret crack'}</strong></div>

      <div className="ff-controls">
        <span className="ff-label">Flask</span>
        <input
          className="ff-input"
          type="text"
          value={session}
          placeholder="eyJ1c2Vy....MTcw....c2ln"
          aria-label={zh ? 'Flask session 值' : 'Flask session value'}
          onChange={event => setSession(event.target.value)}
        />
      </div>
      {flask && (flask.ok ? (
        <>
          <div className="ff-row">
            <span className="ff-badge ff-badge-ok">{flask.compressed ? (zh ? 'zlib 压缩段' : 'zlib compressed') : (zh ? '明文 JSON' : 'plain JSON')}</span>
            {flask.timestamp && <span className="ff-badge">{flask.timestamp.iso}（{flask.timestamp.age}）</span>}
          </div>
          <div className="ff-code">{flask.decoded}</div>
        </>
      ) : <p className="ff-note">{flask.error}</p>)}

      <div className="ff-controls">
        <span className="ff-label">JWT</span>
        <input
          className="ff-input"
          type="text"
          value={jwt}
          placeholder="eyJhbGciOiJIUzI1NiIs..."
          aria-label={zh ? 'JWT token' : 'JWT token'}
          onChange={event => setJwt(event.target.value)}
        />
        <input
          className="ff-input ff-input-narrow"
          type="text"
          value={jwtExtra}
          placeholder={zh ? '追加字典（逗号分隔）' : 'extra secrets (comma-separated)'}
          aria-label={zh ? '追加字典' : 'Extra secrets'}
          onChange={event => setJwtExtra(event.target.value)}
        />
        <button type="button" className="ff-button ff-button-primary" onClick={() => { void runCrack(); }} disabled={jwtBusy || !jwt.trim()}>
          {jwtBusy ? (zh ? '爆破中…' : 'Cracking…') : zh ? '弱口令爆破' : 'Crack'}
        </button>
      </div>
      {jwtResult && <p className="ff-note">{jwtResult}</p>}
      <p className="ff-note">{zh ? '内置 50+ CTF 高频弱密钥（secret/jwt_secret/your-256-bit-secret…），HS256 离线重签验证，全程零联网。' : '50+ built-in CTF weak secrets, offline HS256 resign-and-compare, zero network.'}</p>
    </section>
  );
}

// ---- PHP 弱类型卡 ----

function PhpLooseCard({ zh }: { zh: boolean }) {
  const [left, setLeft] = useState('');
  const [right, setRight] = useState('');
  const verdict = useMemo(
    () => (left.trim() !== '' && right.trim() !== '' ? judgePhpLoose(left.trim(), right.trim()) : null),
    [left, right],
  );

  return (
    <section className="ff-card" aria-label={zh ? 'PHP 弱类型' : 'PHP loose comparison'}>
      <div className="ff-card-head"><strong>{zh ? 'PHP 弱类型 == 判定 + 0e 碰撞' : 'PHP loose == + magic hashes'}</strong></div>
      <div className="ff-controls">
        <input className="ff-input ff-input-narrow" type="text" value={left} placeholder="abc" aria-label={zh ? '左侧值' : 'Left value'} onChange={event => setLeft(event.target.value)} />
        <span className="ff-label">==</span>
        <input className="ff-input ff-input-narrow" type="text" value={right} placeholder="0" aria-label={zh ? '右侧值' : 'Right value'} onChange={event => setRight(event.target.value)} />
      </div>
      {verdict && (
        <div className="ff-row">
          <span className={`ff-badge ${verdict.equal ? 'ff-badge-ok' : 'ff-badge-warn'}`}>{verdict.equal ? '==' : '!='}</span>
          <span className="ff-note">{verdict.why}</span>
        </div>
      )}
      <div className="ff-strings" role="list">
        {PHP_LOOSE_TABLE.map((row, i) => (
          <span key={i} role="listitem" className="ff-code">{`${row.left} ${row.equal ? '==' : '!='} ${row.right} — ${row.why}`}</span>
        ))}
        {MAGIC_HASHES.map(magic => (
          <span key={magic.hash + magic.pair[0]} role="listitem" className="ff-code ff-code-click" onClick={() => copyBlock(magic.pair.join('\n'), zh)}>
            {`${magic.hash}：${magic.pair[0]} / ${magic.pair[1]} —— ${magic.note}`}
          </span>
        ))}
      </div>
    </section>
  );
}

// ---- HTTP 报文 / cURL 解析卡 ----

function HttpCard({ zh }: { zh: boolean }) {
  const [raw, setRaw] = useState('');
  const parsedHttp = useMemo(() => (raw.trim() ? parseHttpMessage(raw) : null), [raw]);
  const parsedCurl = useMemo(() => (raw.trim().toLowerCase().startsWith('curl') ? parseCurl(raw) : null), [raw]);

  return (
    <section className="ff-card" aria-label={zh ? 'HTTP 报文解析' : 'HTTP message parser'}>
      <div className="ff-card-head"><strong>{zh ? 'HTTP 报文 / cURL 命令解析' : 'HTTP message / cURL parser'}</strong></div>
      <p className="ff-note">{zh ? '粘贴原始请求/响应报文，或一条 curl 命令——自动结构化头部与参数。' : 'Paste a raw request/response or a curl command for structured parsing.'}</p>
      <textarea
        className="ff-textarea"
        value={raw}
        placeholder={'POST /login HTTP/1.1\nHost: ctf.example.com\n\nuser=admin\n\n或：curl -X POST http://... -d \'{"a":1}\''}
        aria-label={zh ? '报文或命令输入' : 'Message or command input'}
        onChange={event => setRaw(event.target.value)}
      />
      {parsedHttp && ('error' in parsedHttp ? <p className="ff-note">{parsedHttp.error}</p> : (
        <>
          <div className="ff-row">
            <span className="ff-badge">{parsedHttp.kind === 'request' ? (zh ? '请求' : 'Request') : zh ? '响应' : 'Response'}</span>
            {parsedHttp.method && <span className="ff-badge ff-badge-ok">{parsedHttp.method} {parsedHttp.path}</span>}
            {parsedHttp.status && <span className="ff-badge ff-badge-ok">{parsedHttp.status}</span>}
          </div>
          <div className="ff-strings" role="list">
            {parsedHttp.headers.map((header, i) => (
              <span key={i} role="listitem" className="ff-code">{`${header.name}: ${header.value}`}</span>
            ))}
            {parsedHttp.body && <span role="listitem" className="ff-code">{parsedHttp.body}</span>}
          </div>
        </>
      ))}
      {parsedCurl && ('error' in parsedCurl ? <p className="ff-note">{parsedCurl.error}</p> : (
        <div className="ff-row">
          <span className="ff-badge ff-badge-ok">{parsedCurl.method} {parsedCurl.url}</span>
          {parsedCurl.data && <span className="ff-badge">data: {parsedCurl.data.slice(0, 60)}</span>}
          {parsedCurl.notes.map(note => <span key={note} className="ff-badge ff-badge-warn">{note}</span>)}
        </div>
      ))}
    </section>
  );
}


// ---- Repeater 请求器卡（Burp Repeater 形态，经本地代理转发）----

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

function RepeaterCard({ zh }: { zh: boolean }) {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState('');
  const [body, setBody] = useState('');
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<ProxyResponse[]>([]);

  const send = useCallback(async () => {
    if (!url.trim()) return;
    setBusy(true);
    try {
      const headerMap: Record<string, string> = {};
      for (const line of headers.split('\n')) {
        const colon = line.indexOf(':');
        if (colon > 0) headerMap[line.slice(0, colon).trim()] = line.slice(colon + 1).trim();
      }
      const response = await sendViaProxy({
        url: url.trim(),
        method,
        headers: headerMap,
        body: method === 'GET' || method === 'HEAD' ? null : (body || null),
      });
      setHistory(current => [response, ...current].slice(0, 10));
    } finally {
      setBusy(false);
    }
  }, [url, method, headers, body]);

  const latest = history[0];

  return (
    <section className="ff-card ff-card-flag" aria-label={zh ? 'HTTP 请求器' : 'HTTP repeater'}>
      <div className="ff-card-head">
        <strong>{zh ? '请求器（Burp Repeater 形态）' : 'Request repeater'}</strong>
        <span className="ff-size">{zh ? '经本地代理转发，不受浏览器 CORS 限制' : 'via local proxy, no CORS limits'}</span>
      </div>
      <div className="ff-controls">
        <select className="ff-select" aria-label={zh ? '方法' : 'Method'} value={method} onChange={event => setMethod(event.target.value)}>
          {HTTP_METHODS.map(m => <option key={m} value={m}>{m}</option>)}
        </select>
        <input
          className="ff-input"
          type="text"
          value={url}
          placeholder="http://challenge.ctf.example:8080/api?user=admin"
          aria-label={zh ? '目标 URL' : 'Target URL'}
          onChange={event => setUrl(event.target.value)}
          onKeyDown={event => { if (event.key === 'Enter') void send(); }}
        />
        <button type="button" className="ff-button ff-button-primary" onClick={() => { void send(); }} disabled={busy || !url.trim()}>
          {busy ? (zh ? '发送中…' : 'Sending…') : zh ? '发送' : 'Send'}
        </button>
      </div>
      <textarea
        className="ff-textarea"
        style={{ minHeight: 56 }}
        value={headers}
        placeholder={zh ? '请求头（可选，每行 Name: Value）\nContent-Type: application/json\nCookie: session=abc' : 'Headers (optional, one Name: Value per line)'}
        aria-label={zh ? '请求头' : 'Request headers'}
        onChange={event => setHeaders(event.target.value)}
      />
      {method !== 'GET' && method !== 'HEAD' && (
        <textarea
          className="ff-textarea"
          style={{ minHeight: 56 }}
          value={body}
          placeholder={zh ? '请求体（POST/PUT…）' : 'Body (POST/PUT…)'}
          aria-label={zh ? '请求体' : 'Request body'}
          onChange={event => setBody(event.target.value)}
        />
      )}
      {latest && (
        <>
          <div className="ff-row">
            <span className={`ff-badge ${latest.ok ? 'ff-badge-ok' : 'ff-badge-warn'}`}>{latest.status} {latest.statusText}</span>
            <span className="ff-badge">{latest.elapsedMs} ms</span>
            <span className="ff-badge">{latest.bodyText.length} B</span>
            {latest.error && <span className="ff-badge ff-badge-warn">{latest.error}</span>}
          </div>
          <div className="ff-strings" role="list">
            {Object.entries(latest.headers).map(([name, value]) => (
              <span key={name} role="listitem" className="ff-code">{`${name}: ${value}`}</span>
            ))}
          </div>
          <div className="ff-code ff-code-dump">{latest.bodyText.slice(0, 20000) || (zh ? '（空响应体）' : '(empty body)')}</div>
          {history.length > 1 && (
            <p className="ff-note">{zh ? `历史 ${history.length} 条（最新在上）；状态码对比：${history.map(h => h.status).join(' → ')}` : `${history.length} in history; statuses: ${history.map(h => h.status).join(' → ')}`}</p>
          )}
        </>
      )}
      {!latest && <p className="ff-note">{zh ? '发一个请求试试——目标写题目环境地址（http/https）。' : 'Send a request — point it at your challenge box.'}</p>}
    </section>
  );
}

// ---- 布尔盲注自动化卡 ----

function BlindCard({ zh }: { zh: boolean }) {
  const [urlTemplate, setUrlTemplate] = useState('');
  const [successContains, setSuccessContains] = useState('');
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [result, setResult] = useState<BlindResult | null>(null);

  const run = useCallback(async () => {
    if (!urlTemplate.includes('{Q}')) {
      notifications.show({ message: zh ? 'URL 模板需含 {Q} 占位（注入断言会替换它）。' : 'URL template needs the {Q} placeholder.', color: 'red' });
      return;
    }
    setBusy(true);
    setResult(null);
    setProgress('');
    try {
      const outcome = await blindBooleanExtract({
        urlTemplate,
        successContains: successContains.trim() || undefined,
        onProgress: (found, tried) => setProgress(`${found}…（${tried} 请求）`),
      });
      setResult(outcome);
    } finally {
      setBusy(false);
    }
  }, [urlTemplate, successContains, zh]);

  return (
    <section className="ff-card" aria-label={zh ? '布尔盲注自动化' : 'Boolean blind automation'}>
      <div className="ff-card-head">
        <strong>{zh ? '布尔盲注自动化（逐字符二分）' : 'Boolean blind automation'}</strong>
      </div>
      <p className="ff-note">
        {zh
          ? '模板用 {Q} 占位注入断言，程序自动生成 ASCII(SUBSTR(...)>K) 二分序列逐字符猜 flag。'
          : 'Put {Q} in the template; the tool binary-searches each character via ASCII(SUBSTR(...)>K) probes.'}
      </p>
      <div className="ff-controls">
        <input
          className="ff-input"
          type="text"
          value={urlTemplate}
          placeholder="http://ctf.example/search?id=1' AND {Q}-- -"
          aria-label={zh ? 'URL 模板' : 'URL template'}
          onChange={event => setUrlTemplate(event.target.value)}
        />
      </div>
      <div className="ff-controls">
        <span className="ff-label">{zh ? '成功特征' : 'Success marker'}</span>
        <input
          className="ff-input ff-input-narrow"
          type="text"
          value={successContains}
          placeholder={zh ? '页面含（空=按 2xx 判定）' : 'page contains (empty = 2xx)'}
          aria-label={zh ? '成功特征' : 'Success marker'}
          onChange={event => setSuccessContains(event.target.value)}
        />
        <button type="button" className="ff-button ff-button-primary" onClick={() => { void run(); }} disabled={busy || !urlTemplate.trim()}>
          {busy ? (zh ? '猜解中…' : 'Extracting…') : zh ? '开始猜解' : 'Extract'}
        </button>
      </div>
      {progress !== null && busy && <p className="ff-note ff-mono">{progress}</p>}
      {result && (
        <div className="ff-row">
          <span className="ff-badge ff-badge-ok ff-badge-flag">{result.value}</span>
          <span className="ff-badge">{result.requests} {zh ? '请求' : 'requests'}</span>
          <span className="ff-badge">{result.stoppedAt}</span>
        </div>
      )}
    </section>
  );
}

// ---- 联合注入脱库卡 ----

function UnionDumpCard({ zh }: { zh: boolean }) {
  const [baseUrl, setBaseUrl] = useState('');
  const [database, setDatabase] = useState<'mysql' | 'sqlite' | 'postgresql'>('mysql');
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [result, setResult] = useState<UnionDumpResult | null>(null);

  const run = useCallback(async () => {
    if (!baseUrl.includes('{INJ}')) {
      notifications.show({ message: zh ? 'URL 需含 {INJ} 占位。' : 'URL needs the {INJ} placeholder.', color: 'red' });
      return;
    }
    setBusy(true);
    setResult(null);
    setProgress('');
    try {
      const outcome = await unionDump({
        baseUrl,
        database,
        onProgress: (step, detail) => setProgress(`${step}: ${detail}`),
      });
      setResult(outcome);
    } finally {
      setBusy(false);
    }
  }, [baseUrl, database, zh]);

  return (
    <section className="ff-card" aria-label={zh ? '联合注入脱库' : 'UNION dump'}>
      <div className="ff-card-head">
        <strong>{zh ? '联合注入自动脱库' : 'UNION auto-dump'}</strong>
      </div>
      <p className="ff-note">
        {zh
          ? 'URL 用 {INJ} 标注入点：自动 ORDER BY 探列数 → UNION 定回显位 → 拉库名/表/列/数据（marker 拼接法提取）。'
          : 'Mark the injectable spot with {INJ}: auto ORDER BY → UNION reflection → dump db/tables/columns/rows.'}
      </p>
      <div className="ff-controls">
        <input
          className="ff-input"
          type="text"
          value={baseUrl}
          placeholder="http://ctf.example/news?id=1{INJ}"
          aria-label={zh ? '注入点 URL' : 'Injection URL'}
          onChange={event => setBaseUrl(event.target.value)}
        />
        <select className="ff-select" aria-label={zh ? '数据库' : 'Database'} value={database} onChange={event => setDatabase(event.target.value as 'mysql' | 'sqlite' | 'postgresql')}>
          <option value="mysql">MySQL</option>
          <option value="sqlite">SQLite</option>
          <option value="postgresql">PostgreSQL</option>
        </select>
        <button type="button" className="ff-button ff-button-primary" onClick={() => { void run(); }} disabled={busy || !baseUrl.trim()}>
          {busy ? (zh ? '脱库中…' : 'Dumping…') : zh ? '自动脱库' : 'Dump'}
        </button>
      </div>
      {busy && progress !== null && <p className="ff-note ff-mono">{progress}</p>}
      {result && (result.ok ? (
        <>
          <div className="ff-row">
            <span className="ff-badge">{zh ? `列数 ${result.columnCount}` : `${result.columnCount} cols`}</span>
            <span className="ff-badge">{zh ? `回显位 ${result.reflectPositions?.join('/')}` : `reflect ${result.reflectPositions?.join('/')}`}</span>
            <span className="ff-badge">{result.currentDatabase}</span>
            <span className="ff-badge">{result.requests} {zh ? '请求' : 'requests'}</span>
          </div>
          <div className="ff-strings" role="list">
            {(result.tables ?? []).map(table => (
              <span key={table} role="listitem" className="ff-code">
                {table}({(result.columns?.[table] ?? []).join(', ')})
              </span>
            ))}
            {(result.rows ?? []).slice(0, 50).map((row, i) => (
              <span key={i} role="listitem" className="ff-code">{Object.entries(row).map(([k, v]) => `${k}=${v}`).join(' | ')}</span>
            ))}
          </div>
        </>
      ) : <p className="ff-note">{result.error}</p>)}
    </section>
  );
}

// ---- 目录探测卡 ----

function DirProbeCard({ zh }: { zh: boolean }) {
  const [baseUrl, setBaseUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [hits, setHits] = useState<DirProbeHit[] | null>(null);

  const run = useCallback(async () => {
    setBusy(true);
    setHits(null);
    setProgress('');
    try {
      const found = await probeDirectories(baseUrl.trim(), {
        onProgress: (done, total) => setProgress(`${done}/${total}`),
      });
      setHits(found);
    } finally {
      setBusy(false);
    }
  }, [baseUrl]);

  return (
    <section className="ff-card" aria-label={zh ? '目录探测' : 'Directory probe'}>
      <div className="ff-card-head">
        <strong>{zh ? '敏感目录探测（CTF 小字典 47 条）' : 'Directory probe (47-word CTF list)'}</strong>
      </div>
      <div className="ff-controls">
        <input
          className="ff-input"
          type="text"
          value={baseUrl}
          placeholder="http://ctf.example:8080"
          aria-label={zh ? '目标根 URL' : 'Base URL'}
          onChange={event => setBaseUrl(event.target.value)}
        />
        <button type="button" className="ff-button ff-button-primary" onClick={() => { void run(); }} disabled={busy || !baseUrl.trim()}>
          {busy ? (zh ? `探测中 ${progress}` : `Probing ${progress}`) : zh ? '开始探测' : 'Probe'}
        </button>
      </div>
      <p className="ff-note">{zh ? '字典覆盖 flag/备份文件/.git/.env/源码压缩包/管理后台等 CTF 高频路径，404/403 过滤。' : 'Covers flag/backup/.git/.env/src-zips/admin paths; 404/403 filtered.'}</p>
      {hits && (
        <div className="ff-strings" role="list">
          {hits.map(hit => (
            <span key={hit.path} role="listitem" className={`ff-code ${hit.status === 200 ? 'ff-code-click' : ''}`}>
              {`${hit.status} ${hit.path}（${hit.length}B）${hit.note}`}
            </span>
          ))}
          {hits.length === 0 && <p className="ff-note">{zh ? '全部 404/403——换字典思路或看响应差异。' : 'All 404/403.'}</p>}
        </div>
      )}
    </section>
  );
}

// Web 域工作台：实战工具台（请求器/盲注/脱库/探测经本地代理发请求到题目环境）+ 生成器卡 + 底部速查。
function WebWorkspace() {
  const { language } = useLanguage();
  const zh = language === 'zh';

  return (
    <div className="file-forensics">
      <div className="pwn-intro" role="note">
        <strong>{zh ? 'Web 轻量解题工具台' : 'Web light toolkit'}</strong>
        <p>
          {zh
            ? '请求器/盲注自动化/联合脱库/目录探测直连题目环境（本地代理转发，仅访问你指定的目标）；SSTI 判定、命令注入绕过、SQLi 矩阵、JWT 爆破、PHP 弱类型、报文解析本地完成。'
            : 'Repeater/blind-SQLi automation/UNION dump/dir probe hit your challenge box via a local proxy (only the targets you specify); SSTI/bypasses/JWT/PHP/HTTP run locally.'}
        </p>
      </div>
      <RepeaterCard zh={zh} />
      <BlindCard zh={zh} />
      <UnionDumpCard zh={zh} />
      <DirProbeCard zh={zh} />
      <SstiCard zh={zh} />
      <CmdBypassCard zh={zh} />
      <SqliCard zh={zh} />
      <TokenCard zh={zh} />
      <PhpLooseCard zh={zh} />
      <HttpCard zh={zh} />
      <CheatsheetSection moduleId="web" variant="footer" />
    </div>
  );
}

export default memo(WebWorkspace);
