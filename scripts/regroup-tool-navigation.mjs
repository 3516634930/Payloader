// 工具导航重组：删 327 个重复平铺根 + 41 个无组工具归组（38 入既有组 + 新建 4 组）
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const db = new DatabaseSync(path.join(root, 'data/payloader.sqlite'));
const now = new Date().toISOString();

const navRows = db.prepare("SELECT id, sort_order, tree FROM navigation_nodes WHERE kind = 'tools' ORDER BY sort_order").all();
const toolsById = new Map(db.prepare('SELECT id, data FROM tools').all().map(r => { const t = JSON.parse(r.data); return [t.id, t]; }));

// 归组映射（41 工具 → 目标组）
const NEW_GROUPS = {
  'java-security-diagnostics': { name: { zh: '☕ Java 安全诊断', en: 'Java Security Diagnostics' }, tools: ['java-framework-version-audit', 'spring-management-diagnostics', 'spring-framework-security-diagnostics', 'struts2-security-diagnostics', 'weblogic-management-diagnostics', 'weblogic-protocol-diagnostics', 'shiro-security-diagnostics', 'jboss-management-diagnostics', 'tomcat-security-diagnostics'] },
  'api-security-testing': { name: { zh: '📡 API 安全测试', en: 'API Security Testing' }, tools: ['graphql-query-policy-testing', 'api-contract-testing-workflow', 'api-authorization-workflow', 'api-rate-baseline-testing', 'api-input-contract-workflow'] },
  'ai-security-testing': { name: { zh: '🤖 AI 安全测试', en: 'AI Security Testing' }, tools: ['ai-security-testing', 'model-privacy-testing', 'ml-adversarial-testing', 'rag-security-testing'] },
  'supply-chain-audit': { name: { zh: '📦 供应链安全', en: 'Supply Chain Security' }, tools: ['package-identity-audit', 'ci-pipeline-security-audit', 'dependency-resolution-audit'] },
};
const MOVE_EXISTING = {
  'web-extended-tools': ['csrf-defense-matrix-audit', 'samesite-cookie-browser-audit', 'csrf-token-binding-audit', 'cors-policy-audit', 'flask-security-diagnostics', 'frame-policy-audit', 'redirect-follow-policy-audit', 'clickjacking-xss-browser-audit', 'node-object-merge-audit', 'client-prototype-browser-audit', 'nosql-query-construction-audit', 'websocket-session-audit', 'proxy-upgrade-boundary-audit', 'websocket-auth-lifecycle-audit'],
  'tunneling-tools': ['ngrok-tunnel', 'earthworm-tunnel', 'venom-tunnel'],
  'domain-pentest-tools': ['windows-cached-credential-audit', 'adcs-http-enrollment-audit'],
  'blue-team-tools': ['windows-api-integrity-analysis'],
};

// 1. 删除纯叶重复根（与组内 children 的 toolId 重复）
const groupToolIds = new Set();
const parentRows = [];
for (const r of navRows) {
  const t = JSON.parse(r.tree);
  if ((t.children || []).length) { parentRows.push({ ...r, tree: t }); for (const c of t.children) if (c.toolId) groupToolIds.add(c.toolId); }
}
const delRow = db.prepare('DELETE FROM navigation_nodes WHERE id = ?');
let removedDup = 0;
for (const r of navRows) {
  const t = JSON.parse(r.tree);
  if (!(t.children || []).length && t.toolId && groupToolIds.has(t.toolId)) { delRow.run(r.id); removedDup++; }
}
console.log('删除重复平铺根:', removedDup);

// 2. 既有组追加工具
const updTree = db.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
const mkLeaf = id => ({ id: 'nav-tool-' + id, name: toolsById.get(id)?.name || { zh: id }, toolId: id });
let moved = 0;
for (const [gid, ids] of Object.entries(MOVE_EXISTING)) {
  const row = parentRows.find(r => r.tree.id === gid || r.id === gid);
  if (!row) { console.log('组缺失:', gid); continue; }
  for (const id of ids) {
    if (!toolsById.has(id)) { console.log('工具缺失:', id); continue; }
    if (row.tree.children.some(c => c.toolId === id)) continue;
    row.tree.children.push(mkLeaf(id));
    moved++;
  }
  updTree.run(JSON.stringify(row.tree), now, row.id);
}
console.log('归入既有组:', moved);

// 3. 新建 4 组（插在 misc-pentest-tools 之前）
const insertRow = db.prepare("INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at) VALUES (?, ?, 'tools', ?, 1, ?, ?)");
const maxOrder = db.prepare("SELECT COALESCE(MAX(sort_order), -1) AS n FROM navigation_nodes WHERE kind = 'tools'").get().n;
const miscRow = db.prepare("SELECT sort_order FROM navigation_nodes WHERE kind = 'tools' AND id = 'misc-pentest-tools'").get();
const shift = db.prepare('UPDATE navigation_nodes SET sort_order = sort_order + 4 WHERE kind = ? AND sort_order >= ?');
if (miscRow) shift.run('tools', miscRow.sort_order);
let baseOrder = miscRow ? miscRow.sort_order : maxOrder + 1;
let created = 0;
for (const [gid, def] of Object.entries(NEW_GROUPS)) {
  const children = def.tools.filter(id => toolsById.has(id)).map(mkLeaf);
  if (!children.length) continue;
  insertRow.run(gid, JSON.stringify({ id: gid, name: def.name, children }), baseOrder++, now, now);
  created += children.length;
}
console.log('新建组工具数:', created);

// 4. 终态校验：还有没有组外工具/平铺叶
const after = db.prepare("SELECT tree FROM navigation_nodes WHERE kind = 'tools'").all().map(r => JSON.parse(r.tree));
const inGroup = new Set();
let flatLeaf = 0;
for (const t of after) {
  if ((t.children || []).length) for (const c of t.children) if (c.toolId) inGroup.add(c.toolId);
  else flatLeaf++;
}
const uncovered = [...toolsById.keys()].filter(id => !inGroup.has(id));
console.log('终态：组数', after.filter(t => (t.children || []).length).length, '| 平铺叶', flatLeaf, '| 组外工具', uncovered.length, uncovered.slice(0, 5).join(','));
db.close();
