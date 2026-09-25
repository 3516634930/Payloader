#!/usr/bin/env node
/**
 * 恢复被 override 文档旧 wafBypass 回盖的 3 个合并目标（sqli2-/chunked/oracle）：
 * 从第一次 apply 后的备份取 carried 版 wafBypass → 回写所有权文档 → 再 apply 持久化。
 * 附带：oracle 字面量变量化 + 单行重复条目合并；谓词组 waf 去重走命令补丁（正确键 payloadCommandOverrideFiles）。
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);
const BAK = path.join(ROOT, 'data/backups/payloader-before-payload-curation-2026-09-25T14-20-59-878Z-eb7067ca.sqlite');

const bak = new DatabaseSync(BAK, { readOnly: true });
const getBak = id => { for (const r of bak.prepare('SELECT data FROM payloads').all()) { const p = JSON.parse(r.data); if (p.id === id) return p; } };

// ── 1) 三个目标的恢复版 wafBypass ──
const RESTORE = {};
for (const id of ['sqli2-', 'sqli-http-chunked-carrier']) RESTORE[id] = getBak(id).wafBypass;
const oracle = getBak('sqli-oracle-union-enumeration');
const VARIZED = '"; select * from {TARGET_TABLE} --\nsELecT * FrOm all_tables whERe OWNER = \'{DATABASE_NAME}\'';
let oracleDropped = 0;
RESTORE['sqli-oracle-union-enumeration'] = oracle.wafBypass.filter(w => {
  const c = String(w.command || '');
  if (c === '"; select * from {TARGET_TABLE} --') { oracleDropped++; return false; } // 单行 ⊂ 变量化 2 行，去重
  return true;
}).map(w => String(w.command || '').startsWith('"; select * from TARGET_TABLE') ? { ...w, command: VARIZED } : w);
console.log('恢复目标:', Object.keys(RESTORE).join(', '), '| oracle 去重单行', oracleDropped, '条');
bak.close();

// ── 2) 回写所有权文档（携带 wafBypass 字段的条目所在处）──
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const files = [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || [])];
let written = 0;
for (const f of files) {
  const full = CR(f);
  if (!fs.existsSync(full)) continue;
  const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
  let hit = false;
  const walk = o => {
    if (Array.isArray(o)) return o.forEach(walk);
    if (!o || typeof o !== 'object') return;
    if (typeof o.id === 'string' && RESTORE[o.id] && o.wafBypass !== undefined) {
      o.wafBypass = RESTORE[o.id]; hit = true; written++;
    }
    for (const k of Object.keys(o)) walk(o[k]);
  };
  walk(doc);
  if (hit) { fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n'); console.log('回写', f); }
}
if (written !== 3) { console.log('✗ 预期回写 3 处，实际', written); process.exit(1); }

// ── 3) 谓词组 waf 去重：命令补丁文档（正确注册键）──
const cur = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
let curBlind = null;
for (const r of cur.prepare('SELECT data FROM payloads').all()) { const p = JSON.parse(r.data); if (p.id === 'sqli2-blind-conditional-time-and-predicate-probes') curBlind = p; }
cur.close();
const BLIND_OLD = curBlind.wafBypass[0].command;
const BLIND_NEW = "1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')\n10 a%nd 1=0/(se%lect top 1 ta%ble_name fr%om info%rmation_schema.tables)";
fs.writeFileSync(CR('payload-command-overrides-sqlifix2-2026-09.json'), JSON.stringify({
  schemaVersion: 1,
  entries: [{ id: 'sqli2-blind-conditional-time-and-predicate-probes', patches: [{ area: 'wafBypass', index: 0, expectedCommand: BLIND_OLD, command: BLIND_NEW }] }],
}, null, 2) + '\n');
manifest.payloadCommandOverrideFiles = [...(manifest.payloadCommandOverrideFiles || []), 'payload-command-overrides-sqlifix2-2026-09.json'];
delete manifest.commandOverrideFiles; // 清掉误加的死键
fs.writeFileSync(CR('manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('谓词组补丁文档就绪（锚定当前 10 行现值）+ manifest 正确键注册 + 死键清理 ✓');
