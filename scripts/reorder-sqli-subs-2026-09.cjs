#!/usr/bin/env node
/** sqli 子分支重排：DBMS 家族（MySQL→SQLServer→Oracle→PG→SQLite）前置聚拢，两库树同步改序。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const ORDER = ['sqli-mysql', 'sqli-mssql', 'sqli-oracle', 'sqli-postgresql', 'sqli-sqlite', 'sqli-nosql',
  'sqli-blind-bool', 'sqli-blind-time', 'sqli-exploit-union', 'sqli-exploit-stacked',
  'sqli-carrier-http', 'sqli-carrier-encoding', 'sqli-carrier-scenario'];

const reorder = tree => {
  const find = (n, id) => { if (n.id === id) return n; for (const k of (n.children || [])) { const r = find(k, id); if (r) return r; } return null; };
  const branch = find(tree, 'sqli');
  if (!branch) throw new Error('sqli branch missing');
  const byId = new Map(branch.children.map(c => [c.id, c]));
  const missing = ORDER.filter(id => !byId.has(id));
  if (missing.length) throw new Error('missing sub-branches: ' + missing.join(','));
  const rest = branch.children.filter(c => !ORDER.includes(c.id));
  branch.children = [...ORDER.map(id => byId.get(id)), ...rest];
  return branch.children.map(c => c.id).join(' | ');
};

for (const rel of ['data/payloader.sqlite', 'server/default-seed.sqlite']) {
  const p = path.join(ROOT, rel);
  const db = new DatabaseSync(p);
  const row = db.prepare("SELECT id, tree FROM navigation_nodes WHERE id = 'web'").get();
  const tree = JSON.parse(row.tree);
  const seq = reorder(tree);
  db.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?')
    .run(JSON.stringify(tree), new Date().toISOString(), 'web');
  db.close();
  console.log(rel, '→', seq);
}
