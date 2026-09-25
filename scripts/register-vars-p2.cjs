const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

// 1) ts 源注册
const tsPath = path.resolve(process.cwd(), 'src/data/globalVariables.ts');
let ts = fs.readFileSync(tsPath, 'utf8');
if (!ts.includes("key: 'TARGET_TABLE'")) {
  const anchor = "  { key: 'TARGET_HOST', value: '192.0.2.10', group: 'target',";
  const add = "  { key: 'TARGET_TABLE', value: 'users', group: 'target', description: { zh: '目标数据表名', en: 'Target database table name' } },\n  { key: 'DATABASE_NAME', value: 'webapp', group: 'target', description: { zh: '目标数据库名', en: 'Target database name' } },\n";
  ts = ts.replace(anchor, add + anchor);
  fs.writeFileSync(tsPath, ts);
  console.log('ts 注册 TARGET_TABLE/DATABASE_NAME');
} else console.log('ts 已有');

// 2) DB 双库 metadata global_variables
for (const dbf of ['data/payloader.sqlite', 'server/default-seed.sqlite']) {
  const db = new DatabaseSync(path.resolve(process.cwd(), dbf));
  const r = db.prepare("SELECT value FROM metadata WHERE key='global_variables'").get();
  const vars = r ? JSON.parse(r.value) : [];
  let added = 0;
  for (const v of [
    { key: 'TARGET_TABLE', value: 'users', group: 'target', description: { zh: '目标数据表名', en: 'Target database table name' } },
    { key: 'DATABASE_NAME', value: 'webapp', group: 'target', description: { zh: '目标数据库名', en: 'Target database name' } },
  ]) {
    if (!vars.some(x => x.key === v.key)) { vars.push(v); added++; }
  }
  if (added) {
    db.prepare("UPDATE metadata SET value=? WHERE key='global_variables'").run(JSON.stringify(vars));
    console.log(dbf, '注册', added, '个变量');
  } else console.log(dbf, '已有');
  db.close();
}
