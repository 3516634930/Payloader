// 内容修正回写运行库（硬编码治理批）：源文件 P1/P2 修好后，把涉及条目 upsert 进 runtime，
// 随后 build:seed --from-runtime-db 生成完整种子（保全 47 个 runtime-only 工具 + 内容 metadata）。
// 只 UPDATE 已存在的 id（不新增），navigation 两棵树全量替换（结构修复：嵌套 bug + 死链清理）。
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { loadRawSeedData } from './default-seed-source.mjs';

const rootDir = fileURLToPath(new URL('..', import.meta.url));
const runtimeDb = path.join(rootDir, 'data', 'payloader.sqlite');

// P1/P2 修正涉及的条目 id（源文件侧已修好，回写运行库对应行）
const payloadIds = new Set([
  'ssti-jinja2', 'ssti2-jinja2-python-flask',            // jinja2 unicode 转义
  'sqli-postgresql-server-file-write', 'sqli-stacked-postgresql', // PG COPY
  'ssrf-gopher', 'ssrf-redis', 'cmdi2-gopher-redis-resp-file-write-sequence', // gopher RESP
  'xxe-oob',                                              // CDATA XXE
  'evasion-powershell',                                   // 模板插值
]);
const toolIds = new Set(['kerbrute-tool', 'graphqlmap', 'smb-pentest', 'linux-privesc-gtfobins', 'linux-privesc', 'ctf-forensics-tools', 'decompilers', 'network-scanning-advanced', 'hash-cracking', 'exploit-dev-tools', 'exchange-m365-attacks', 'atomic-red-team', 'web-fuzzing-wordlists', 'privilege-escalation-tools', 'post-exploitation-tools', 'active-directory-enumeration', 'ctf-web-advanced', 'theharvester-tool', 'network-pivoting-tools', 'exploit-frameworks', 'priv-esc-windows', 'gitleaks', 'nmap']);

const seed = await loadRawSeedData();
const db = new DatabaseSync(runtimeDb);
const nowIso = new Date().toISOString();
let updatedPayloads = 0;
let updatedTools = 0;

const updateData = db.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
for (const payload of seed.payloads) {
  if (!payloadIds.has(payload.id)) continue;
  const exists = db.prepare('SELECT id FROM payloads WHERE id = ?').get(payload.id);
  if (!exists) { console.log('skip(不存在):', payload.id); continue; }
  updateData.run(JSON.stringify(payload), nowIso, payload.id);
  updatedPayloads += 1;
}
const updateTool = db.prepare('UPDATE tools SET data = ?, updated_at = ? WHERE id = ?');
for (const tool of seed.tools) {
  if (!toolIds.has(tool.id)) continue;
  const exists = db.prepare('SELECT id FROM tools WHERE id = ?').get(tool.id);
  if (!exists) { console.log('skip(不存在):', tool.id); continue; }
  updateTool.run(JSON.stringify(tool), nowIso, tool.id);
  updatedTools += 1;
}

// navigation 结构修复：两棵树全量替换（filterToolNavigation 同款过滤在种子构建时做，
// 这里直接 replaceContentData 语义的 navigation 部分手工实现）
const navReplace = db.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
let updatedNav = 0;
const replaceTree = (items, kind) => {
  for (const item of items) {
    const row = db.prepare('SELECT id FROM navigation_nodes WHERE id = ?').get(item.id);
    if (row) {
      navReplace.run(JSON.stringify(item), nowIso, item.id);
      updatedNav += 1;
    } else {
      // 结构修复新增的平级节点（15 个从 PS 组移出的）需要插入
      const next = db.prepare(`SELECT COALESCE(MAX(sort_order), -1) + 1 AS n FROM navigation_nodes WHERE kind = ?`).get(kind).n;
      db.prepare('INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)')
        .run(item.id, JSON.stringify(item), kind, next, nowIso, nowIso);
      updatedNav += 1;
    }
    if (Array.isArray(item.children)) replaceTree(item.children, kind);
  }
};
replaceTree(seed.navigation, 'payloads');
replaceTree(seed.toolNavigation, 'tools');
// 删除已清理的死链节点（源里已删，runtime 还挂着）
for (const dead of ['biz-flow-bypass-nav', 'biz-coupon-abuse-nav']) {
  db.prepare('DELETE FROM navigation_nodes WHERE id = ?').run(dead);
}
for (const dead of ['masscan', 'web-enum-tools']) {
  db.prepare('DELETE FROM navigation_nodes WHERE id = ? AND kind = \'tools\'').run(dead);
}

console.log(`payloads 更新 ${updatedPayloads}，tools 更新 ${updatedTools}，navigation 更新 ${updatedNav}`);
db.close();
