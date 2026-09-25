// 第二波-B：把 fixreport-titles.md + fixreport-missing.md 合并为 findings2.json（沿用同一解析格式）
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'output', 'content-audit');
const parse = file => {
  const text = readFileSync(path.join(dir, file), 'utf8');
  const out = [];
  for (const raw of text.split(/^## F /m).slice(1)) {
    const lines = raw.split('\n');
    const id = lines[0].trim();
    const kv = {};
    for (const l of lines.slice(1)) {
      const m = l.match(/^- (字段|类型|现文|问题|改文):\s?(.*)$/);
      if (m) kv[m[1]] = m[2].trim();
    }
    if (id) out.push({ pack: file.replace('.md', ''), id, field: kv['字段'] || '', type: kv['类型'] || 'UNCLEAR', cur: kv['现文'] || '', issue: kv['问题'] || '', rewrite: kv['改文'] || '', issues: [] });
  }
  return out;
};
const titles = parse('fixreport-titles.md');
const missing = parse('fixreport-missing.md');
const all = [...titles, ...missing];
writeFileSync(path.join(dir, 'findings2.json'), JSON.stringify({ stats: { total: all.length, titles: titles.length, missing: missing.length }, findings: all }, null, 1));
console.log('wave2 findings:', all.length, '(titles', titles.length, '/ missing', missing.length + ')');
const badField = all.filter(f => !/^(name|description|prerequisites\[\d+\]|execution\[\d+\]\.(title|command|description)|wafBypass\[\d+\]\.(title|command|description)|attackChain\[\d+\]\.(title|description|payload)|analysis|opsecTips\[\d+\]|tutorial\.(overview|vulnerability|exploitation|mitigation))$/.test(f.field));
console.log('bad fields:', badField.length, badField.slice(0, 5).map(f => f.id + ' ' + f.field).join(' | '));
