// 防护代码任务 dump：每卡 mitigation 上下文（根因/现状/技术栈线索）分片
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, 'output/content-audit');
mkdirSync(outDir, { recursive: true });
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'), { readOnly: true });
const rows = db.prepare('SELECT data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();

const block = p => {
  const L = [];
  L.push(`###### ${p.id} | ${p.name?.zh || ''}`);
  L.push(`[分支] ${p.category?.zh || ''} / ${p.subCategory?.zh || ''}`);
  L.push(`[标签] ${(p.tags || []).join(',')}`);
  L.push(`[漏洞根因] ${(p.tutorial?.vulnerability?.zh || '').slice(0, 200)}`);
  L.push(`[现防护建议] ${p.tutorial?.mitigation?.zh || ''}`);
  // 技术栈线索：执行命令首条（判断攻击面语言/平台）
  const cmds = (p.execution || []).slice(0, 2).map(e => (e?.command || '').split('\n').slice(0, 2).join(' ⏎ ')).filter(Boolean);
  if (cmds.length) L.push(`[载荷线索] ${cmds.join(' || ').slice(0, 300)}`);
  L.push('');
  return L.join('\n');
};
const PER = parseInt(process.argv[2] || '40', 10);
const blocks = rows.map(block);
let f = 0;
for (let i = 0; i < blocks.length; i += PER) {
  f++;
  writeFileSync(path.join(outDir, `mit-pack-${String(f).padStart(2, '0')}.md`), `# 防护代码任务 pack ${f}（${Math.min(PER, blocks.length - i)} 卡）\n\n${blocks.slice(i, i + PER).join('\n')}`);
}
console.log('mitigation packs:', f, '/ cards:', blocks.length);
