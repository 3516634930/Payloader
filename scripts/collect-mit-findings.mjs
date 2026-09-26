// mitigation 代码落地 ①：解析 16 份 mit-report（多行改文支持）→ findings-mit.json
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'output', 'content-audit');
const files = readdirSync(dir).filter(f => /^mit-report-\d+\.md$/.test(f)).sort();
const findings = [];
for (const f of files) {
  const text = readFileSync(path.join(dir, f), 'utf8');
  for (const raw of text.split(/^## F /m).slice(1)) {
    const lines = raw.split('\n');
    const id = lines[0].trim().replace(/`/g, '');
    const kv = {};
    let cur = null;
    for (const l of lines.slice(1)) {
      const m = l.match(/^- (字段|类型|现文|问题|改文):\s?(.*)$/);
      if (m) { cur = m[1]; kv[cur] = m[2]; continue; }
      // 多行延续：缩进行并入当前字段
      if (cur && /^\s{2,}/.test(l) && kv[cur] !== undefined) kv[cur] += '\n' + l;
    }
    if (id && kv['字段'] === 'tutorial.mitigation' && (kv['改文'] || '').trim().length >= 50) {
      findings.push({ id, field: 'tutorial.mitigation', type: kv['类型'] || 'UNUSABLE', cur: kv['现文'] || '', issue: kv['问题'] || '', rewrite: kv['改文'].trim(), issues: [] });
    }
  }
}
writeFileSync(path.join(dir, 'findings-mit.json'), JSON.stringify({ stats: { total: findings.length }, findings }, null, 1));
// 统计与去重
const ids = new Set(findings.map(f => f.id));
console.log('findings:', findings.length, '/ distinct cards:', ids.size);
// 抽一条看多行保真
const s = findings.find(f => f.rewrite.includes('\n'));
console.log('样例多行改文保真:', s ? s.rewrite.split('\n').length + ' 行' : '无多行');
