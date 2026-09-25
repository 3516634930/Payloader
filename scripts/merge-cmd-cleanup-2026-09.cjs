#!/usr/bin/env node
/**
 * cleanup 补丁合并（v2）：id 已存在于其他 command-override 文档时，把原 entry 整体搬到 cleanup 文档，
 * 同 (area,index) 目标的 patch 合并为单补丁（command/title/platform 取 cleanup 侧，description 等保留原侧，
 * expectedCommand 不一致以 cleanup 侧为准并告警）。
 */
const fs = require('fs');
const path = require('path');
const CR = p => path.join(process.cwd(), 'content-review', p);

const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const CLEANUP = 'payload-command-overrides-cleanup-2026-09.json';
const otherNames = manifest.payloadCommandOverrideFiles.filter(f => f !== CLEANUP);
const cleanupDoc = JSON.parse(fs.readFileSync(CR(CLEANUP), 'utf8'));

const otherDocs = otherNames.map(f => ({ file: f, doc: JSON.parse(fs.readFileSync(CR(f), 'utf8')) }));
const key = pa => `${pa.area}|${pa.index}`;
// 与 ux 批次的 attackChain payload 锚冲突（纯标题收益，剔除避让）
const SKIP_IDS = new Set(['ai2-7-ssrf-via-llm', 'ai2-9-prompt-indirect-injection']);

const finalEntries = [];
let movedIds = 0, mergedPatches = 0;
const conflicts = [];
const touched = new Set();

for (const myEntry of cleanupDoc.entries) {
  if (SKIP_IDS.has(myEntry.id)) continue;
  const source = otherDocs.find(o => (o.doc.entries || []).some(e => e.id === myEntry.id));
  if (!source) { finalEntries.push(myEntry); continue; }
  const idx = source.doc.entries.findIndex(e => e.id === myEntry.id);
  const [origEntry] = source.doc.entries.splice(idx, 1);
  touched.add(source.file);
  movedIds++;
  const byKey = new Map(origEntry.patches.map(pa => [key(pa), { ...pa }]));
  for (const my of myEntry.patches) {
    const k = key(my);
    if (byKey.has(k)) {
      const orig = byKey.get(k);
      if (orig.expectedCommand !== my.expectedCommand) conflicts.push(`${myEntry.id} ${k} expectedCommand 不一致`);
      byKey.set(k, {
        ...orig,
        ...(my.command !== undefined ? { command: my.command } : {}),
        ...(my.title !== undefined ? { title: my.title } : {}),
        ...(my.platform !== undefined ? { platform: my.platform } : {}),
        expectedCommand: my.expectedCommand,
      });
      mergedPatches++;
    } else {
      byKey.set(k, my);
    }
  }
  origEntry.patches = [...byKey.values()];
  finalEntries.push(origEntry);
}

cleanupDoc.entries = finalEntries;
fs.writeFileSync(CR(CLEANUP), JSON.stringify(cleanupDoc, null, 2) + '\n');
for (const o of otherDocs) if (touched.has(o.file)) fs.writeFileSync(CR(o.file), JSON.stringify(o.doc, null, 2) + '\n');
console.log(`搬迁 ${movedIds} 个已有 entry 进 cleanup｜同目标合并 ${mergedPatches} 个补丁｜cleanup 总条目 ${finalEntries.length}`);
if (conflicts.length) console.log('⚠️ expectedCommand 冲突:\n' + conflicts.join('\n'));
