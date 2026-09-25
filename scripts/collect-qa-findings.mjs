// 汇总 41 份 qa-report-p*.md：解析 F 块 → findings.json（类型分布/字段分布/按 payload 聚合）
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'output', 'content-audit');
const files = readdirSync(dir).filter(f => /^qa-report-p\d+\.md$/.test(f)).sort();
const FIELD_RE = /^(name|description|prerequisites\[\d+\]|execution\[\d+\]\.(?:title|command|description)|wafBypass\[\d+\]\.(?:title|command|description)|attackChain\[\d+\]\.(?:title|description|payload)|analysis|opsecTips\[\d+\]|tutorial\.(?:overview|vulnerability|exploitation|mitigation)|category)$/;
const TYPE_RE = /^(WRONG|UNCLEAR|UNUSABLE|VERIFY|CATEGORY_MISMATCH)$/;

const findings = [];
const stats = { total: 0, types: {}, fields: {}, parseIssues: [] };
for (const f of files) {
  const text = readFileSync(path.join(dir, f), 'utf8');
  const blocks = text.split(/^## F /m).slice(1);
  for (const raw of blocks) {
    const lines = raw.split('\n');
    const id = lines[0].trim();
    const kv = {};
    for (const l of lines.slice(1)) {
      const m = l.match(/^- (字段|类型|现文|问题|改文):\s?(.*)$/);
      if (m) kv[m[1]] = m[2].trim();
    }
    stats.total += 1;
    const t = kv['类型'] || 'MISSING_TYPE';
    stats.types[t] = (stats.types[t] || 0) + 1;
    const fl = kv['字段'] || 'MISSING_FIELD';
    stats.fields[fl] = (stats.fields[fl] || 0) + 1;
    const issues = [];
    if (!id) issues.push('no-id');
    if (!TYPE_RE.test(t)) issues.push('bad-type:' + t);
    if (!FIELD_RE.test(fl)) issues.push('bad-field:' + fl);
    if (t === 'WRONG' || t === 'UNCLEAR' || t === 'UNUSABLE') {
      if (!kv['改文'] || kv['改文'].length < 4) issues.push('missing-rewrite');
    }
    findings.push({ pack: f.replace('.md', ''), id, field: fl, type: t, cur: kv['现文'] || '', issue: kv['问题'] || '', rewrite: kv['改文'] || '', issues });
    if (issues.length) stats.parseIssues.push({ pack: f, id, issues });
  }
}
writeFileSync(path.join(dir, 'findings.json'), JSON.stringify({ stats, findings }, null, 1));
console.log('files:', files.length, 'findings:', stats.total);
console.log('types:', JSON.stringify(stats.types));
console.log('top fields:', Object.entries(stats.fields).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([k, v]) => `${k}:${v}`).join(' '));
console.log('parse issues:', stats.parseIssues.length, stats.parseIssues.slice(0, 10).map(p => `${p.pack} ${p.id} ${p.issues.join(',')}`).join(' | '));
// 改文超长截断风险
const longRw = findings.filter(f => f.rewrite.length > 1200).length;
console.log('rewrites >1200 chars:', longRw);
const byPayload = {};
for (const f of findings) byPayload[f.id] = (byPayload[f.id] || 0) + 1;
console.log('distinct payloads touched:', Object.keys(byPayload).length);
