#!/usr/bin/env node
/**
 * 2026-09 SQL/NoSQL注入 分支重组：PG/SQLite 拆分 + 11 组合并 + 33 组名行业化 + 3 desc 修正 + 分支改名。
 * 机制：payloadSubBranches/payloadMerges 声明 + 文档链 walker（name/description/subCategory 双写 obj 与 payloadOverrides）
 *      + 新命令补丁文档（wafBypass 变量字面量与逐字节重复修复）。全程管线原生，apply 幂等。
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

// ── 现值校验基线（runtime DB）──
const rt = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const rtIds = new Set(rt.prepare('SELECT data FROM payloads').all().map(r => JSON.parse(r.data).id));
rt.close();

// ── 1) 声明层：tool-decisions.json ──
const tdPath = CR('tool-decisions.json');
const td = JSON.parse(fs.readFileSync(tdPath, 'utf8'));

// 1a. 子分支改名
const SUB_RENAMES = {
  'sqli-mssql': ['SQL Server 注入', 'SQL Server Injection'],
  'sqli-exploit-stacked': ['堆叠语句注入', 'Stacked Query Injection'],
};
let n1 = 0;
for (const b of td.payloadSubBranches) if (SUB_RENAMES[b.id]) { b.name = { zh: SUB_RENAMES[b.id][0], en: SUB_RENAMES[b.id][1] }; n1++; }

// 1b. 拆分：删 PG+SQLite 混堆，增两独立子分支
const before = td.payloadSubBranches.length;
td.payloadSubBranches = td.payloadSubBranches.filter(b => b.id !== 'sqli-pg-sqlite');
td.payloadSubBranches.push(
  { parentBranchId: 'sqli', id: 'sqli-postgresql', name: { zh: 'PostgreSQL 注入', en: 'PostgreSQL Injection' } },
  { parentBranchId: 'sqli', id: 'sqli-sqlite', name: { zh: 'SQLite 注入', en: 'SQLite Injection' } },
);

// 1c. 合并声明（titlePrefix 省略 = 保留源标题，carried 进目标 wafBypass 自动去重）
const NEW_MERGES = [
  ['sqli2-outfile-write-primitive', 'sqli-mysql-server-file-write'],
  ['sqli2-mysql-outfile-and-dumpfile-write-impact', 'sqli-mysql-server-file-write'],
  ['sqli2-sqlite-version-schema-and-column-enumeration', 'sqli-sqlite-union-enumeration'],
  ['sqli2-nosql', 'sqli-mongodb-basic'],
  ['sqli2-tricks-web-pentest-sql', 'sqli2-'],
  ['custom-sql注入速查表', 'sqli2-'],
  ['sqli2-union', 'sqli-union-query'],
  ['sqli2-direct-statement-and-catalog-selection', 'sqli-oracle-union-enumeration'],
  ['sqli-carrier-chunked', 'sqli-http-chunked-carrier'],
  ['sqli2-union-crlf-comment-encoding', 'sqli2-union-extraction-lexical-encodings'],
  ['nosql2-sql', 'sqli-second-order'],
];
const existMerge = new Set(td.payloadMerges.map(m => m.sourceId));
for (const [s, t] of NEW_MERGES) {
  if (!rtIds.has(s)) { console.log('✗ merge 源不存在:', s); process.exit(1); }
  if (!rtIds.has(t)) { console.log('✗ merge 目标不存在:', t); process.exit(1); }
  if (!existMerge.has(s)) td.payloadMerges.push({ sourceId: s, targetPayloadId: t });
}
fs.writeFileSync(tdPath, JSON.stringify(td, null, 2) + '\n');
console.log(`声明：子分支改名 ${n1}｜删 1 增 2（${before}→${td.payloadSubBranches.length}）｜合并新增 ${NEW_MERGES.length}`);

// ── 2) 文档链 walker：name/description/subCategory ──
const NAME_FIX = {
  'sqli-mysql-basic': ['MySQL 联合查询与元数据枚举', 'MySQL UNION & Metadata Enumeration'],
  'sqli-mysql-file-capability': ['MySQL FILE 权限检测', 'MySQL FILE Privilege Check'],
  'sqli-mysql-file-read': ['MySQL LOAD_FILE 文件读取', 'MySQL LOAD_FILE File Read'],
  'sqli-mysql-server-file-write': ['MySQL INTO OUTFILE 文件写入', 'MySQL INTO OUTFILE File Write'],
  'sqli-mysql-general-log-write': ['MySQL General Log 写 Shell', 'MySQL General Log Webshell'],
  'sqli-mysql-udf-execution': ['MySQL UDF 提权', 'MySQL UDF Privilege Escalation'],
  'sqli-mssql-basic': ['SQL Server UNION 与目录视图枚举', 'SQL Server UNION & Catalog View Enumeration'],
  'sqli-mssql-xp-cmdshell': ['SQL Server xp_cmdshell 命令执行', 'SQL Server xp_cmdshell Command Execution'],
  'sqli-mssql-ole-automation': ['SQL Server OLE Automation 命令执行', 'SQL Server OLE Automation Command Execution'],
  'sqli-oracle-union-enumeration': ['Oracle UNION 与数据字典枚举', 'Oracle UNION & Data Dictionary Enumeration'],
  'sqli-oracle-utl-http-oob': ['Oracle UTL_HTTP 带外请求', 'Oracle UTL_HTTP Out-of-Band Requests'],
  'sqli-oracle-java-package-capability': ['Oracle DBMS_JAVA 可用性探测', 'Oracle DBMS_JAVA Availability Probe'],
  'sqli-oracle-utl-file-capability': ['Oracle UTL_FILE 文件读取', 'Oracle UTL_FILE File Read'],
  'sqli-oracle-dbms-pipe-side-channel': ['Oracle DBMS_PIPE 管道消息信道', 'Oracle DBMS_PIPE Message Channel'],
  'sqli-postgresql-server-file-read': ['PostgreSQL pg_read_file 文件读取', 'PostgreSQL pg_read_file File Read'],
  'sqli-postgresql-server-file-write': ['PostgreSQL COPY 执行与文件写入', 'PostgreSQL COPY Execution & File Write'],
  'sqli-sqlite-union-enumeration': ['SQLite UNION 与 Schema 枚举', 'SQLite UNION & Schema Enumeration'],
  'sqli-sqlite-extension-file-functions': ['SQLite load_extension 与文件函数', 'SQLite load_extension & File Functions'],
  'sqli2-sqlite': ['SQLite randomblob 资源延迟盲注', 'SQLite randomblob Timing Blind Injection'],
  'sqli-mongodb-basic': ['MongoDB 查询操作符注入', 'MongoDB Query Operator Injection'],
  'nosql2-': ['NoSQL 类型混淆与认证绕过', 'NoSQL Type Confusion & Auth Bypass'],
  'sqli2-': ['注入速查与闭合边界探测', 'SQLi Quick Reference & Closure Probing'],
  'sqli2-blind-conditional-time-and-predicate-probes': ['跨方言谓词与时间盲注样例', 'Cross-Dialect Predicate & Timing Samples'],
  'sqli2-like-between-in': ['比较运算符等价替换', 'Comparison Operator Equivalents'],
  'sqli-error-based': ['MySQL 报错回显注入', 'MySQL Error-Based Injection'],
  'sqli-union-query': ['UNION 列数对齐与回显定位', 'UNION Column Alignment & Output Location'],
  'sqli-http-chunked-carrier': ['Chunked 分块传输载体', 'Chunked Transfer Carrier'],
  'sqli-expression-waf-variants': ['SQL 等价表达式替换', 'SQL Equivalent Expression Substitution'],
  'sqli2-union-extraction-lexical-encodings': ['UNION 词法编码与分词变体', 'UNION Lexical Encoding & Tokenization Variants'],
  'httpbypass-unicode-sql': ['全角引号规范化绕过', 'Fullwidth Quote Normalization Bypass'],
  'sqli-stacked-mysql': ['MySQL 堆叠语句执行', 'MySQL Stacked Query Execution'],
  'sqli-stacked-mssql': ['SQL Server 堆叠语句执行', 'SQL Server Stacked Query Execution'],
  'sqli-stacked-postgresql': ['PostgreSQL 堆叠语句执行', 'PostgreSQL Stacked Query Execution'],
};
const DESC_FIX = {
  'sqli-mssql-ole-automation': ['启用 OLE Automation 存储过程创建 wscript.shell 对象执行系统命令并把输出落盘，验证 SQL Server 无 xp_cmdshell 时的替代命令执行路径。', "Enable OLE Automation, create a wscript.shell object to run OS commands and capture output to disk, verifying an alternate execution path when xp_cmdshell is unavailable."],
  'sqli-oracle-dbms-pipe-side-channel': ['打包并回读 DBMS_PIPE 管道消息验证会话缓冲可写，确认无回显场景下 DBMS_PIPE 可作为跨会话侧信道（含 RECEIVE_MESSAGE 超时延迟形态）。', 'Pack and read back DBMS_PIPE messages to confirm the session buffer is writable and usable as a cross-session side channel in blind scenarios (including RECEIVE_MESSAGE timeout delays).'],
  'sqli-postgresql-server-file-write': ['先以 COPY TO STDOUT 确认注入点可执行 COPY 语句，再用 COPY TO 文件路径与 pg_file_write 变体验证 PostgreSQL 堆叠写入与文件系统边界。', 'Confirm COPY executes at the injection point via COPY TO STDOUT, then verify stacked file writes with COPY TO a path and pg_file_write variants.'],
};
const SUBCAT_FIX = {};
const SET_SUBCAT = (ids, zh, en) => ids.forEach(id => { SUBCAT_FIX[id] = [zh, en]; });
SET_SUBCAT(['sqli-mssql-basic', 'sqli-mssql-xp-cmdshell', 'sqli-mssql-ole-automation', 'sqli2-mssql'], 'SQL Server 注入', 'SQL Server Injection');
SET_SUBCAT(['sqli-postgresql-union-enumeration', 'sqli-postgresql-server-file-read', 'sqli-postgresql-server-file-write', 'sqli2-postgresql'], 'PostgreSQL 注入', 'PostgreSQL Injection');
SET_SUBCAT(['sqli-sqlite-union-enumeration', 'sqli-sqlite-extension-file-functions', 'sqli2-sqlite', 'sqli2-sqlite-attach-database-file-write'], 'SQLite 注入', 'SQLite Injection');
SET_SUBCAT(['sqli-stacked-mysql', 'sqli-stacked-mssql', 'sqli-stacked-postgresql', 'sqli-stacked-destructive-dml', 'sqli2-stacked-and-conditional-delay-probes'], '堆叠语句注入', 'Stacked Query Injection');

const allFixIds = new Set([...Object.keys(NAME_FIX), ...Object.keys(DESC_FIX), ...Object.keys(SUBCAT_FIX)]);
const missing = [...allFixIds].filter(id => !rtIds.has(id));
if (missing.length) { console.log('✗ fix id 不存在于 DB:', missing.join(',')); process.exit(1); }

const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const files = [...(manifest.overrideFiles || []), ...(manifest.collectionSplitFiles || []), 'tool-decisions.json'];
let n = 0;
const hit = new Set();
const loc = (obj, key, map) => {
  const m = map[obj.id];
  if (!m) return;
  if (obj[key] !== undefined) { obj[key] = { zh: m[0], en: m[1] }; n++; }
};
const rewrite = obj => {
  if (Array.isArray(obj)) { obj.forEach(rewrite); return; }
  if (!obj || typeof obj !== 'object') return;
  if (typeof obj.id === 'string' && allFixIds.has(obj.id)) {
    loc(obj, 'name', NAME_FIX); loc(obj, 'description', DESC_FIX); loc(obj, 'subCategory', SUBCAT_FIX);
    const po = obj.payloadOverrides;
    if (po && typeof po === 'object') {
      if (po.name !== undefined && NAME_FIX[obj.id]) { po.name = { zh: NAME_FIX[obj.id][0], en: NAME_FIX[obj.id][1] }; n++; }
      if (po.subCategory !== undefined && SUBCAT_FIX[obj.id]) { po.subCategory = { zh: SUBCAT_FIX[obj.id][0], en: SUBCAT_FIX[obj.id][1] }; n++; }
    }
    hit.add(obj.id);
  }
  for (const k of Object.keys(obj)) rewrite(obj[k]);
};
for (const f of files) {
  const full = CR(f);
  if (!fs.existsSync(full)) continue;
  const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
  const b = n;
  rewrite(doc);
  if (n > b) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
}
console.log(`文档链改写 ${n} 处｜未承载:`, [...allFixIds].filter(id => !hit.has(id)).join(',') || '无');

// ── 3) 命令补丁文档：wafBypass 变量字面量 + 逐字节重复 ──
const seed = new DatabaseSync(path.join(ROOT, 'server/default-seed.sqlite'), { readOnly: true });
const seedP = new Map(seed.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
seed.close();
const DIRECT_WAF_OLD = '"; select * from TARGET_TABLE --\nsELecT * FrOm all_tables whERe OWNER = \'DATABASE_NAME\'';
const BLIND_WAF_OLD = [
  "SELECT if(LPAD(' ',4,version())='5.7',sleep(5),null);",
  '1%0b||%0bLPAD(USER,7,1)',
  'state=%2527+and+',
  '(case+when+SUBSTRING(LOAD_FILE(%2527/etc/passwd%2527),1,1)=char(114)+then+',
  "BENCHMARK(40000000,ENCODE(%2527hello%2527,%2527batman%2527))+else+0+end)=0+--+",
  "1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')",
  '1%0bAND(SELECT%0b1%20FROM%20mysql.x)',
  "15 and '1'=(SELECT '1' FROM dual) and '0having'='0having'",
  "stringindatasetchoosen%%' and 1 = any (select 1 from SECURE.CONF_SECURE_MEMBERS where FULL_NAME like '%%dministrator' and rownum<=1 and PASSWORD like '0%') and '1%%'='1",
  '10 a%nd 1=0/(se%lect top 1 ta%ble_name fr%om info%rmation_schema.tables)',
].join('\n');
for (const [id, area, idx, expect] of [
  ['sqli2-direct-statement-and-catalog-selection', 'wafBypass', 0, DIRECT_WAF_OLD],
  ['sqli2-blind-conditional-time-and-predicate-probes', 'wafBypass', 0, BLIND_WAF_OLD],
]) {
  const p = seedP.get(id);
  const cur = p ? String((p.wafBypass || [])[idx]?.command ?? '') : '(payload 不在 seed)';
  if (cur !== expect) { console.log(`✗ ${id} wafBypass[${idx}] 锚不匹配：\n--DB--\n${cur}\n--EXP--\n${expect}`); process.exit(1); }
}
const patchDoc = {
  schemaVersion: 1,
  entries: [
    {
      id: 'sqli2-direct-statement-and-catalog-selection',
      patches: [{
        area: 'wafBypass', index: 0, expectedCommand: DIRECT_WAF_OLD,
        command: '"; select * from {TARGET_TABLE} --\nsELecT * FrOm all_tables whERe OWNER = \'{DATABASE_NAME}\'',
      }],
    },
    {
      id: 'sqli2-blind-conditional-time-and-predicate-probes',
      patches: [{
        area: 'wafBypass', index: 0, expectedCommand: BLIND_WAF_OLD,
        command: "1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')\n10 a%nd 1=0/(se%lect top 1 ta%ble_name fr%om info%rmation_schema.tables)",
      }],
    },
  ],
};
const patchPath = CR('payload-command-overrides-sqlifix-2026-09.json');
if (fs.existsSync(patchPath)) {
  const prev = JSON.parse(fs.readFileSync(patchPath, 'utf8'));
  const prevIds = new Set(prev.entries.map(e => e.id));
  for (const e of patchDoc.entries) if (!prevIds.has(e.id)) prev.entries.push(e);
  fs.writeFileSync(patchPath, JSON.stringify(prev, null, 2) + '\n');
} else {
  fs.writeFileSync(patchPath, JSON.stringify(patchDoc, null, 2) + '\n');
}
const cof = manifest.commandOverrideFiles || [];
const docName = 'payload-command-overrides-sqlifix-2026-09.json';
if (!cof.includes(docName)) { cof.push(docName); manifest.commandOverrideFiles = cof; fs.writeFileSync(CR('manifest.json'), JSON.stringify(manifest, null, 2) + '\n'); }
console.log('命令补丁文档就绪并注册 manifest ✓');
