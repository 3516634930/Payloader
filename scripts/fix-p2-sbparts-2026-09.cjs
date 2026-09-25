const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(path.resolve(process.cwd(), 'data/payloader.sqlite'), { readOnly: true });
const all = db.prepare('SELECT id, data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();

// ── A 类：SB part 与命令不一致的修正 ──
// 值映射：历史示例值 → 命令中的占位符形态
const VALMAP = [
  [':NTHASH', ':{LAB_NTLM_HASH}'],
  ['/ntlm:HASH', '/ntlm:{LAB_NTLM_HASH}'],
  ['/rc4:HASH', '/rc4:{LAB_NTLM_HASH}'],
  ['/krbtgt:HASH', '/krbtgt:{LAB_NTLM_HASH}'],
  ['domain/user:password', '{LAB_DOMAIN}/{LAB_USER}:{LAB_PASSWORD}'],
  ['@target_ip', '@{LAB_HOST}'],
  ['user@target', '{LAB_USER}@{LAB_HOST}'],
  ['server.domain.com', '{LAB_SERVICE_HOST}'],
  ['/domain:domain.com', '/domain:{LAB_DOMAIN}'],
  ['-ComputerName target', '-ComputerName {LAB_HOST}'],
  ['sc \\target', 'sc \\{LAB_HOST}'],
  ['/s target', '/s {LAB_HOST}'],
  ['/sid:S-1-5-21-xxx', '/sid:S-1-5-21-{LAB_VALUE}'],
  ['C:\\Windows\\Panther\\', 'C:\\Windows\\Panther\\'],
  ['SetValue($true)', 'SetValue($null,$true)'],
  ['\\a', '\\u0061'],
];
const norm = v => String(v || '').replace(/\r\n?/g, '\n').trim();
const squash = v => norm(v).replace(/\s+/g, '');
let partFixed = 0, partDropped = 0;
const touched = new Set();

// G 类文案修正（description 层，走 overrides 文档）
const descFixes = [
  ['sqli-oracle-utl-http-oob', /UTL_HTTP\.REQ UEST/g, 'UTL_HTTP.REQUEST'],
  ['sqli-stacked-destructive-dml', /CEE 表达式/g, 'CTE 表达式'],
  ['webshell-php-server-side-command-scripts', /popopen/g, 'popen'],
  ['sam-dump', /impacket secretdump/g, 'impacket secretsdump'],
  ['proxylogon', /shellfish address/g, 'in-memory shell address'],
];
const t = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'content-review/tool-decisions.json'), 'utf8')); // 仅预热 require
let descFixed = 0;

for (const p of all) {
  let dirty = false;
  for (const area of ['execution', 'wafBypass']) {
    for (const step of (p[area] || [])) {
      const cmdKey = norm(step.command);
      const cmdSq = squash(step.command);
      for (const sb of (step.syntaxBreakdown || [])) {
        if (typeof sb.part !== 'string' || !sb.part) continue;
        if (cmdSq.includes(squash(sb.part))) continue;
        // 抽象函数名形态（"func()"）：剥掉空括号后是命令真实子串即合法
        if (/^\w+\(\)$/.test(sb.part.trim()) && cmdSq.includes(squash(sb.part.trim().slice(0, -2)))) continue;
        // 纯概念/说明型 part（非命令片段示意，如协议名、字段类别）：保守保留，仅清除确定错误的值示例
        if (/^(CVE-\d{4}-\d+|[A-Z_]{3,})$/.test(sb.part.trim())) continue;
        // 尝试值映射修正
        let fixed = sb.part;
        for (const [from, to] of VALMAP) {
          if (squash(fixed).includes(squash(from))) {
            const candidate = fixed.split(from).join(to);
            if (cmdSq.includes(squash(candidate))) { fixed = candidate; break; }
          }
        }
        if (fixed !== sb.part && cmdSq.includes(squash(fixed))) { sb.part = fixed; partFixed++; dirty = true; continue; }
        // 其余不匹配形态（SELECT...FROM/db_name(N)/HEX() 等抽象表示）为合法语法模式标注，保留不删
        continue;
      }
      if ((step.syntaxBreakdown || []).some(s => s.__drop)) {
        step.syntaxBreakdown = step.syntaxBreakdown.filter(s => !s.__drop);
        dirty = true;
      }
    }
  }
  if (dirty) touched.add(p.id);
}

// SB 修正落库：对 touched 的 payload 生成 SB 全量替换补丁
const entriesById = new Map();
for (const id of touched) {
  const p = all.find(x => x.id === id);
  for (const area of ['execution', 'wafBypass']) {
    for (const [i, step] of (p[area] || []).entries()) {
      if (!(step.syntaxBreakdown || []).length) continue;
      if (!entriesById.has(id)) entriesById.set(id, { id, patches: [] });
      entriesById.get(id).patches.push({ area, index: i, expectedCommand: step.command, syntaxBreakdown: step.syntaxBreakdown });
    }
  }
}
fs.mkdirSync('output/content-audit/out-sbfix', { recursive: true });
const flat = [];
for (const e of entriesById.values()) for (const pa of e.patches) flat.push({ id: e.id, area: pa.area, index: pa.index, expectedCommand: pa.expectedCommand, syntaxBreakdown: pa.syntaxBreakdown });
fs.writeFileSync('output/content-audit/out-sbfix/sb-flat.json', JSON.stringify(flat, null, 1));
console.log(`SB part 修正: 修复 ${partFixed} 段 / 删除错误段 ${partDropped} 段 / 涉及 ${entriesById.size} 条 → out-sbfix`);
