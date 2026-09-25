// 第二波材料 dump：①42 卡模板 title 命名包 ②189 处缺改文补写包
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const byId = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();

// ① title 命名包
const tplRe = /清理后命令|校正命令|命令 ?\d*$/;
const tLines = [];
let tCount = 0;
for (const p of byId.values()) {
  const items = [];
  (p.execution || []).forEach((e, i) => { if (tplRe.test(e?.title?.zh || '')) items.push({ area: 'execution', index: i, title: e?.title?.zh || '', command: e?.command || '', desc: e?.description?.zh || '' }); });
  (p.wafBypass || []).forEach((w, i) => { if (tplRe.test(w?.title?.zh || '')) items.push({ area: 'wafBypass', index: i, title: w?.title?.zh || '', command: w?.command || '', desc: w?.description?.zh || '' }); });
  if (!items.length) continue;
  tCount++;
  tLines.push(`###### ${p.id} | ${p.name?.zh || ''}`);
  for (const it of items) {
    tLines.push(`- ${it.area}[${it.index}] 原 title: ${it.title}`);
    tLines.push(`  CMD: ${it.command.split('\n').join(' ⏎ ').slice(0, 400)}`);
    if (it.desc) tLines.push(`  判据: ${it.desc.slice(0, 200)}`);
  }
  tLines.push('');
}
writeFileSync(path.join(root, 'output/content-audit/fixpack-titles.md'), `# 模板 title 命名任务（${tCount} 卡）\n\n${tLines.join('\n')}`);
console.log('title pack:', tCount, 'cards');

// ② 缺改文补写包（从 wave1-rejects 的 dropped 提取 empty 缺失者）
const rejects = JSON.parse(readFileSync(path.join(root, 'output/content-audit/wave1-rejects.json'), 'utf8'));
const findings = JSON.parse(readFileSync(path.join(root, 'output/content-audit/findings.json'), 'utf8')).findings;
const missing = findings.filter(f => ['WRONG', 'UNUSABLE', 'UNCLEAR'].includes(f.type) && (!f.rewrite || f.rewrite.trim().length < 8));
const fLines = [];
const byIdGroup = new Map();
for (const f of missing) {
  if (!byIdGroup.has(f.id)) byIdGroup.set(f.id, []);
  byIdGroup.get(f.id).push(f);
}
for (const [id, fs] of byIdGroup) {
  const p = byId.get(id);
  if (!p) continue;
  fLines.push(`###### ${id} | ${p.name?.zh || ''}`);
  for (const f of fs) {
    fLines.push(`- 字段: ${f.field} | 类型: ${f.type}`);
    fLines.push(`  现文: ${f.cur.slice(0, 150)}`);
    fLines.push(`  问题: ${f.issue.slice(0, 200)}`);
    // 附命令上下文
    const m = f.field.match(/^(execution|wafBypass)\[(\d+)\]/);
    if (m) {
      const cmd = p[m[1]]?.[parseInt(m[2], 10)]?.command;
      if (cmd) fLines.push(`  CMD: ${cmd.split('\n').join(' ⏎ ').slice(0, 350)}`);
    }
  }
  fLines.push('');
}
writeFileSync(path.join(root, 'output/content-audit/fixpack-missing.md'), `# 缺改文补写任务（${missing.length} 处 / ${byIdGroup.size} 卡）\n\n${fLines.join('\n')}`);
console.log('missing pack:', missing.length, 'findings /', byIdGroup.size, 'cards');
