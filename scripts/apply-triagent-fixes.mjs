// 三路交付的 runtime 回写（字段级合并纪律：只换目标字段，不用源版覆盖整条避免策展退化）：
// ① syntaxBreakdown：源版 168 块修复 → runtime 对应 payload 只替换 syntaxBreakdown/execution 内该字段
// ② 工具合并：runtime 删 wfuzz-tool/searchsploit-tool，保留方并入新命令（从源版 toolCommands 取保留方条目，命令数组以策展版为基、追加源版独有）
// ③ navigation 已在源修复（主控早前回写过树，无需重复）
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { loadRawSeedData } from './default-seed-source.mjs';

const rootDir = fileURLToPath(new URL('..', import.meta.url));
const rt = new DatabaseSync(path.join(rootDir, 'data', 'payloader.sqlite'));
const nowIso = new Date().toISOString();
const seed = await loadRawSeedData();
const seedPayloadById = new Map(seed.payloads.map(p => [p.id, p]));

// ① syntaxBreakdown 字段级合并：对源里 syntaxBreakdown 非空且 runtime 有同 id 的条目，
//    仅当源该条 command 与 runtime 一致（内容没被策展改写）时替换 syntaxBreakdown。
const updatePayload = rt.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
let sbMerged = 0;
let sbSkippedCurated = 0;
for (const row of rt.prepare('SELECT id, data FROM payloads WHERE enabled = 1').all()) {
  const live = JSON.parse(row.data);
  const src = seedPayloadById.get(row.id);
  if (!src) continue;
  const areas = ['execution', 'wafBypass'];
  let changed = false;
  for (const area of areas) {
    const srcList = Array.isArray(src[area]) ? src[area] : [];
    const liveList = Array.isArray(live[area]) ? live[area] : [];
    // 按索引对齐：command 一致才把源版 syntaxBreakdown 拷过去
    for (let i = 0; i < Math.min(srcList.length, liveList.length); i++) {
      if (srcList[i].command === liveList[i].command && Array.isArray(srcList[i].syntaxBreakdown)
        && JSON.stringify(srcList[i].syntaxBreakdown) !== JSON.stringify(liveList[i].syntaxBreakdown ?? null)) {
        liveList[i].syntaxBreakdown = srcList[i].syntaxBreakdown;
        changed = true;
      }
    }
  }
  if (changed) {
    updatePayload.run(JSON.stringify(live), nowIso, row.id);
    sbMerged += 1;
  } else if (JSON.stringify(src).length !== JSON.stringify(live).length) {
    sbSkippedCurated += 1;
  }
}

// ② 工具合并回写：删除重复工具，保留方追加源版独有命令（按 command 去重）
const mergeMap = [
  { drop: 'wfuzz-tool', keep: 'wfuzz' },
  { drop: 'searchsploit-tool', keep: 'searchsploit' },
];
const seedToolById = new Map(seed.tools.map(t => [t.id, t]));
const updateTool = rt.prepare('UPDATE tools SET data = ?, updated_at = ? WHERE id = ?');
let mergedTools = 0;
for (const { drop, keep } of mergeMap) {
  const keepRow = rt.prepare('SELECT data FROM tools WHERE id = ?').get(keep);
  const srcKeep = seedToolById.get(keep);
  if (!keepRow || !srcKeep) { console.log('skip merge:', keep); continue; }
  const live = JSON.parse(keepRow.data);
  const liveCmds = new Set((live.commands ?? []).map(c => c.command));
  let added = 0;
  for (const cmd of srcKeep.commands ?? []) {
    if (!liveCmds.has(cmd.command)) { (live.commands ??= []).push(cmd); added += 1; }
  }
  updateTool.run(JSON.stringify(live), nowIso, keep);
  const dropped = rt.prepare('DELETE FROM tools WHERE id = ?').run(drop).changes;
  rt.prepare('DELETE FROM navigation_nodes WHERE id = ?').run(drop);
  mergedTools += 1;
  console.log(`merge ${drop} → ${keep}: +${added} 命令, 删重复工具 ${dropped}`);
}

console.log(`syntaxBreakdown 合并 ${sbMerged} 条 payload（策展差异跳过 ${sbSkippedCurated}），工具合并 ${mergedTools}`);
rt.close();
