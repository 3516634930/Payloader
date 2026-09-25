#!/usr/bin/env node
/** 修正 collection-splits.json 两处 replacement 的 wafBypass[0]：变量化 + 去重；撤销 sqlifix 补丁文档注册。 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

const csPath = CR('collection-splits.json');
const cs = JSON.parse(fs.readFileSync(csPath, 'utf8'));
const TARGETS = {
  'sqli2-direct-statement-and-catalog-selection':
    '"; select * from {TARGET_TABLE} --\nsELecT * FrOm all_tables whERe OWNER = \'{DATABASE_NAME}\'',
  'sqli2-blind-conditional-time-and-predicate-probes':
    "1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')\n10 a%nd 1=0/(se%lect top 1 ta%ble_name fr%om info%rmation_schema.tables)",
};
let fixed = 0;
const walk = o => {
  if (Array.isArray(o)) return o.forEach(walk);
  if (!o || typeof o !== 'object') return;
  if (typeof o.id === 'string' && TARGETS[o.id] && Array.isArray(o.wafBypass) && o.wafBypass[0]) {
    const before = String(o.wafBypass[0].command || '');
    if (before !== TARGETS[o.id]) {
      o.wafBypass[0] = { ...o.wafBypass[0], command: TARGETS[o.id] };
      fixed++;
    }
  }
  for (const k of Object.keys(o)) walk(o[k]);
};
walk(cs);
fs.writeFileSync(csPath, JSON.stringify(cs, null, 2) + '\n');
console.log('collection-splits wafBypass 修正:', fixed);

// 撤销补丁文档（其锚基于修正前内容，保留会 STALE_COMMAND 阻断 apply）
const docPath = CR('payload-command-overrides-sqlifix-2026-09.json');
fs.rmSync(docPath, { force: true });
const mPath = CR('manifest.json');
const m = JSON.parse(fs.readFileSync(mPath, 'utf8'));
const beforeN = (m.commandOverrideFiles || []).length;
m.commandOverrideFiles = (m.commandOverrideFiles || []).filter(f => f !== 'payload-command-overrides-sqlifix-2026-09.json');
fs.writeFileSync(mPath, JSON.stringify(m, null, 2) + '\n');
console.log('补丁文档撤销 | manifest:', beforeN, '→', m.commandOverrideFiles.length);
