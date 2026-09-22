import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('data/payloader.sqlite');

const tools = [
  {
    id: 'mysql-sql-reference',
    name: { zh: 'MySQL SQL命令参考', en: 'MySQL SQL Reference' },
    description: { zh: 'MySQL数据库常用SQL命令速查', en: 'MySQL database SQL command reference' },
    category: { zh: '数据库工具', en: 'Database Tools' },
    commands: [
      { name: { zh: '查询数据', en: 'SELECT Data' }, command: 'SELECT * FROM table_name WHERE condition;', description: { zh: '基础查询，支持WHERE过滤', en: 'Basic query with WHERE filter' }, platform: 'all' },
      { name: { zh: '插入数据', en: 'INSERT Data' }, command: "INSERT INTO table_name (col1, col2) VALUES ('val1', 'val2');", description: { zh: '插入一行数据', en: 'Insert a single row' }, platform: 'all' },
      { name: { zh: '更新数据', en: 'UPDATE Data' }, command: "UPDATE table_name SET col1='val1' WHERE id=1;", description: { zh: '按条件更新记录', en: 'Update records by condition' }, platform: 'all' },
      { name: { zh: '删除数据', en: 'DELETE Data' }, command: 'DELETE FROM table_name WHERE condition;', description: { zh: '按条件删除记录', en: 'Delete records by condition' }, platform: 'all' },
      { name: { zh: '建表', en: 'CREATE TABLE' }, command: 'CREATE TABLE users (\n  id INT AUTO_INCREMENT PRIMARY KEY,\n  name VARCHAR(100) NOT NULL,\n  email VARCHAR(200) UNIQUE,\n  created_at DATETIME DEFAULT CURRENT_TIMESTAMP\n);', description: { zh: '创建新表', en: 'Create a new table' }, platform: 'all' },
      { name: { zh: '修改表结构', en: 'ALTER TABLE' }, command: 'ALTER TABLE table_name ADD COLUMN age INT;\nALTER TABLE table_name MODIFY COLUMN name VARCHAR(200);\nALTER TABLE table_name DROP COLUMN old_col;', description: { zh: '添加/修改/删除列', en: 'Add/modify/drop columns' }, platform: 'all' },
      { name: { zh: '事务控制', en: 'Transaction Control' }, command: 'START TRANSACTION;\nUPDATE accounts SET balance=balance-100 WHERE id=1;\nUPDATE accounts SET balance=balance+100 WHERE id=2;\nCOMMIT; -- or ROLLBACK;', description: { zh: '事务开始、提交或回滚', en: 'Begin, commit or rollback a transaction' }, platform: 'all' },
      { name: { zh: '创建索引', en: 'CREATE INDEX' }, command: 'CREATE INDEX idx_name ON table_name (column_name);\nCREATE UNIQUE INDEX idx_email ON users (email);', description: { zh: '创建普通或唯一索引', en: 'Create regular or unique index' }, platform: 'all' },
      { name: { zh: '创建视图', en: 'CREATE VIEW' }, command: 'CREATE VIEW active_users AS\nSELECT id, name FROM users WHERE status=1;', description: { zh: '创建虚拟视图', en: 'Create a virtual view' }, platform: 'all' },
      { name: { zh: '存储过程', en: 'Stored Procedure' }, command: "DELIMITER $$\nCREATE PROCEDURE get_user(IN uid INT)\nBEGIN\n  SELECT * FROM users WHERE id=uid;\nEND$$\nDELIMITER ;\nCALL get_user(1);", description: { zh: '创建并调用存储过程', en: 'Create and call a stored procedure' }, platform: 'all' },
      { name: { zh: '常用函数', en: 'Built-in Functions' }, command: "SELECT COUNT(*), AVG(salary), MAX(salary), MIN(salary), SUM(salary) FROM employees;\nSELECT NOW(), DATE_FORMAT(created_at,'%Y-%m-%d'), CONCAT(first,' ',last) FROM users;\nSELECT IFNULL(col,'default'), LENGTH(name), UPPER(name) FROM users;", description: { zh: '聚合、日期、字符串常用函数', en: 'Aggregate, date, string built-in functions' }, platform: 'all' },
      { name: { zh: 'JOIN联表查询', en: 'JOIN Query' }, command: 'SELECT u.name, o.total\nFROM users u\nINNER JOIN orders o ON u.id=o.user_id\nWHERE o.total > 100;', description: { zh: 'INNER/LEFT/RIGHT JOIN关联查询', en: 'INNER/LEFT/RIGHT JOIN query' }, platform: 'all' },
    ],
  },
  {
    id: 'postgresql-sql-reference',
    name: { zh: 'PostgreSQL SQL命令参考', en: 'PostgreSQL SQL Reference' },
    description: { zh: 'PostgreSQL数据库常用SQL命令速查', en: 'PostgreSQL database SQL command reference' },
    category: { zh: '数据库工具', en: 'Database Tools' },
    commands: [
      { name: { zh: '查询数据', en: 'SELECT Data' }, command: 'SELECT * FROM table_name WHERE condition LIMIT 100;', description: { zh: '基础查询', en: 'Basic query' }, platform: 'all' },
      { name: { zh: '插入并返回', en: 'INSERT RETURNING' }, command: "INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com') RETURNING id;", description: { zh: '插入后返回生成的字段', en: 'Insert and return generated fields' }, platform: 'all' },
      { name: { zh: '更新数据', en: 'UPDATE Data' }, command: "UPDATE users SET name='Bob' WHERE id=1 RETURNING *;", description: { zh: '更新并返回结果', en: 'Update and return result' }, platform: 'all' },
      { name: { zh: '删除数据', en: 'DELETE Data' }, command: 'DELETE FROM users WHERE id=1 RETURNING id;', description: { zh: '删除并返回', en: 'Delete and return' }, platform: 'all' },
      { name: { zh: '建表', en: 'CREATE TABLE' }, command: 'CREATE TABLE users (\n  id SERIAL PRIMARY KEY,\n  name VARCHAR(100) NOT NULL,\n  email TEXT UNIQUE,\n  created_at TIMESTAMPTZ DEFAULT NOW()\n);', description: { zh: '创建表，使用SERIAL自增主键', en: 'Create table with SERIAL primary key' }, platform: 'all' },
      { name: { zh: '修改表结构', en: 'ALTER TABLE' }, command: 'ALTER TABLE users ADD COLUMN age INT;\nALTER TABLE users ALTER COLUMN name TYPE TEXT;\nALTER TABLE users DROP COLUMN old_col;', description: { zh: '添加/修改/删除列', en: 'Add/alter/drop columns' }, platform: 'all' },
      { name: { zh: '事务控制', en: 'Transaction' }, command: 'BEGIN;\nUPDATE accounts SET balance=balance-100 WHERE id=1;\nUPDATE accounts SET balance=balance+100 WHERE id=2;\nCOMMIT; -- or ROLLBACK;', description: { zh: '事务控制', en: 'Transaction control' }, platform: 'all' },
      { name: { zh: '创建索引', en: 'CREATE INDEX' }, command: 'CREATE INDEX idx_email ON users (email);\nCREATE INDEX CONCURRENTLY idx_name ON users (name);', description: { zh: '创建索引，CONCURRENTLY不锁表', en: 'Create index, CONCURRENTLY avoids lock' }, platform: 'all' },
      { name: { zh: '创建视图', en: 'CREATE VIEW' }, command: 'CREATE VIEW active_users AS SELECT id, name FROM users WHERE active=true;\nCREATE MATERIALIZED VIEW stats AS SELECT COUNT(*) FROM orders;', description: { zh: '普通视图与物化视图', en: 'View and materialized view' }, platform: 'all' },
      { name: { zh: '函数/存储过程', en: 'Function / Procedure' }, command: "CREATE OR REPLACE FUNCTION get_user(uid INT) RETURNS TABLE(id INT, name TEXT) AS $$\nBEGIN\n  RETURN QUERY SELECT id, name FROM users WHERE id=uid;\nEND;\n$$ LANGUAGE plpgsql;\nSELECT * FROM get_user(1);", description: { zh: '创建PL/pgSQL函数', en: 'Create a PL/pgSQL function' }, platform: 'all' },
      { name: { zh: '常用函数', en: 'Built-in Functions' }, command: "SELECT COUNT(*), AVG(salary), MAX(salary), SUM(salary) FROM employees;\nSELECT NOW(), TO_CHAR(created_at,'YYYY-MM-DD'), CONCAT(first,' ',last) FROM users;\nSELECT COALESCE(col,'default'), LENGTH(name), UPPER(name) FROM users;", description: { zh: '聚合、日期、字符串函数', en: 'Aggregate, date, string functions' }, platform: 'all' },
      { name: { zh: 'UPSERT', en: 'UPSERT (ON CONFLICT)' }, command: "INSERT INTO users (id, name) VALUES (1, 'Alice')\nON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name;", description: { zh: '插入或更新（冲突时更新）', en: 'Insert or update on conflict' }, platform: 'all' },
    ],
  },
  {
    id: 'mssql-sql-reference',
    name: { zh: 'MSSQL SQL命令参考', en: 'MSSQL / SQL Server SQL Reference' },
    description: { zh: 'SQL Server常用SQL命令速查', en: 'SQL Server SQL command reference' },
    category: { zh: '数据库工具', en: 'Database Tools' },
    commands: [
      { name: { zh: '查询数据', en: 'SELECT Data' }, command: 'SELECT TOP 100 * FROM table_name WHERE condition;', description: { zh: '基础查询，TOP限制行数', en: 'Basic query with TOP row limit' }, platform: 'all' },
      { name: { zh: '插入数据', en: 'INSERT Data' }, command: "INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com');\nSELECT SCOPE_IDENTITY(); -- get last inserted id", description: { zh: '插入数据并获取自增ID', en: 'Insert and get last auto-increment ID' }, platform: 'all' },
      { name: { zh: '更新数据', en: 'UPDATE Data' }, command: "UPDATE users SET name='Bob' WHERE id=1;", description: { zh: '更新记录', en: 'Update records' }, platform: 'all' },
      { name: { zh: '删除数据', en: 'DELETE / TRUNCATE' }, command: 'DELETE FROM users WHERE id=1;\nTRUNCATE TABLE log_table; -- fast delete all', description: { zh: '删除记录或清空表', en: 'Delete records or truncate table' }, platform: 'all' },
      { name: { zh: '建表', en: 'CREATE TABLE' }, command: 'CREATE TABLE users (\n  id INT IDENTITY(1,1) PRIMARY KEY,\n  name NVARCHAR(100) NOT NULL,\n  email NVARCHAR(200) UNIQUE,\n  created_at DATETIME2 DEFAULT GETDATE()\n);', description: { zh: '创建表，IDENTITY自增主键', en: 'Create table with IDENTITY primary key' }, platform: 'all' },
      { name: { zh: '修改表结构', en: 'ALTER TABLE' }, command: 'ALTER TABLE users ADD age INT NULL;\nALTER TABLE users ALTER COLUMN name NVARCHAR(200);\nALTER TABLE users DROP COLUMN old_col;', description: { zh: '添加/修改/删除列', en: 'Add/alter/drop columns' }, platform: 'all' },
      { name: { zh: '事务控制', en: 'Transaction' }, command: 'BEGIN TRANSACTION;\nUPDATE accounts SET balance=balance-100 WHERE id=1;\nUPDATE accounts SET balance=balance+100 WHERE id=2;\nCOMMIT; -- or ROLLBACK;', description: { zh: '事务控制', en: 'Transaction control' }, platform: 'all' },
      { name: { zh: '创建索引', en: 'CREATE INDEX' }, command: 'CREATE INDEX idx_name ON users (name);\nCREATE UNIQUE NONCLUSTERED INDEX idx_email ON users (email);', description: { zh: '创建普通或唯一非聚集索引', en: 'Create regular or unique nonclustered index' }, platform: 'all' },
      { name: { zh: '创建视图', en: 'CREATE VIEW' }, command: 'CREATE VIEW active_users AS SELECT id, name FROM users WHERE active=1;\nGO', description: { zh: '创建视图', en: 'Create a view' }, platform: 'all' },
      { name: { zh: '存储过程', en: 'Stored Procedure' }, command: "CREATE PROCEDURE GetUser @uid INT\nAS\nBEGIN\n  SELECT * FROM users WHERE id=@uid;\nEND;\nGO\nEXEC GetUser @uid=1;", description: { zh: '创建并执行存储过程', en: 'Create and execute stored procedure' }, platform: 'all' },
      { name: { zh: '常用函数', en: 'Built-in Functions' }, command: "SELECT COUNT(*), AVG(salary), MAX(salary), SUM(salary) FROM employees;\nSELECT GETDATE(), FORMAT(created_at,'yyyy-MM-dd'), CONCAT(first,' ',last) FROM users;\nSELECT ISNULL(col,'default'), LEN(name), UPPER(name) FROM users;", description: { zh: '聚合、日期、字符串函数', en: 'Aggregate, date, string functions' }, platform: 'all' },
      { name: { zh: '分页查询', en: 'Pagination (OFFSET FETCH)' }, command: 'SELECT * FROM users\nORDER BY id\nOFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY;', description: { zh: 'SQL Server分页查询', en: 'SQL Server pagination query' }, platform: 'all' },
    ],
  },
  {
    id: 'oracle-sql-reference',
    name: { zh: 'Oracle SQL命令参考', en: 'Oracle SQL Reference' },
    description: { zh: 'Oracle数据库常用SQL命令速查', en: 'Oracle database SQL command reference' },
    category: { zh: '数据库工具', en: 'Database Tools' },
    commands: [
      { name: { zh: '查询数据', en: 'SELECT Data' }, command: 'SELECT * FROM table_name WHERE condition FETCH FIRST 100 ROWS ONLY;', description: { zh: '基础查询，限制行数', en: 'Basic query with row limit' }, platform: 'all' },
      { name: { zh: '插入数据', en: 'INSERT Data' }, command: "INSERT INTO users (id, name, email) VALUES (users_seq.NEXTVAL, 'Alice', 'a@b.com');", description: { zh: '使用序列插入自增ID', en: 'Insert with sequence for auto-increment ID' }, platform: 'all' },
      { name: { zh: '更新数据', en: 'UPDATE Data' }, command: "UPDATE users SET name='Bob' WHERE id=1;", description: { zh: '更新记录', en: 'Update records' }, platform: 'all' },
      { name: { zh: '删除数据', en: 'DELETE Data' }, command: 'DELETE FROM users WHERE id=1;\nTRUNCATE TABLE log_table;', description: { zh: '删除或清空表', en: 'Delete or truncate table' }, platform: 'all' },
      { name: { zh: '建表', en: 'CREATE TABLE' }, command: "CREATE TABLE users (\n  id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,\n  name VARCHAR2(100) NOT NULL,\n  email VARCHAR2(200) UNIQUE,\n  created_at TIMESTAMP DEFAULT SYSTIMESTAMP\n);", description: { zh: '创建表，IDENTITY自增主键', en: 'Create table with IDENTITY primary key' }, platform: 'all' },
      { name: { zh: '修改表结构', en: 'ALTER TABLE' }, command: 'ALTER TABLE users ADD age NUMBER;\nALTER TABLE users MODIFY name VARCHAR2(200);\nALTER TABLE users DROP COLUMN old_col;', description: { zh: '添加/修改/删除列', en: 'Add/modify/drop columns' }, platform: 'all' },
      { name: { zh: '事务控制', en: 'Transaction' }, command: '-- Oracle auto-starts transaction\nUPDATE accounts SET balance=balance-100 WHERE id=1;\nUPDATE accounts SET balance=balance+100 WHERE id=2;\nCOMMIT; -- or ROLLBACK;', description: { zh: '事务提交或回滚（Oracle自动开启事务）', en: 'Commit or rollback (Oracle auto-starts transaction)' }, platform: 'all' },
      { name: { zh: '创建索引', en: 'CREATE INDEX' }, command: 'CREATE INDEX idx_name ON users (name);\nCREATE UNIQUE INDEX idx_email ON users (email);', description: { zh: '创建普通或唯一索引', en: 'Create regular or unique index' }, platform: 'all' },
      { name: { zh: '创建视图', en: 'CREATE VIEW' }, command: 'CREATE OR REPLACE VIEW active_users AS SELECT id, name FROM users WHERE active=1;', description: { zh: '创建或替换视图', en: 'Create or replace view' }, platform: 'all' },
      { name: { zh: '存储过程', en: 'Stored Procedure' }, command: "CREATE OR REPLACE PROCEDURE get_user(p_uid IN NUMBER) AS\nBEGIN\n  FOR r IN (SELECT * FROM users WHERE id=p_uid) LOOP\n    DBMS_OUTPUT.PUT_LINE(r.name);\n  END LOOP;\nEND;\n/\nEXEC get_user(1);", description: { zh: '创建并调用PL/SQL存储过程', en: 'Create and call PL/SQL stored procedure' }, platform: 'all' },
      { name: { zh: '常用函数', en: 'Built-in Functions' }, command: "SELECT COUNT(*), AVG(salary), MAX(salary), SUM(salary) FROM employees;\nSELECT SYSDATE, TO_CHAR(created_at,'YYYY-MM-DD'), first||' '||last FROM users;\nSELECT NVL(col,'default'), LENGTH(name), UPPER(name) FROM users;", description: { zh: '聚合、日期、字符串函数', en: 'Aggregate, date, string functions' }, platform: 'all' },
      { name: { zh: '序列', en: 'Sequence' }, command: 'CREATE SEQUENCE users_seq START WITH 1 INCREMENT BY 1;\nSELECT users_seq.NEXTVAL FROM DUAL;', description: { zh: '创建和使用序列生成自增ID', en: 'Create and use sequence for auto-increment' }, platform: 'all' },
    ],
  },
  {
    id: 'sqlite-sql-reference',
    name: { zh: 'SQLite SQL命令参考', en: 'SQLite SQL Reference' },
    description: { zh: 'SQLite数据库常用SQL命令速查', en: 'SQLite database SQL command reference' },
    category: { zh: '数据库工具', en: 'Database Tools' },
    commands: [
      { name: { zh: '查询数据', en: 'SELECT Data' }, command: 'SELECT * FROM table_name WHERE condition LIMIT 100;', description: { zh: '基础查询', en: 'Basic query' }, platform: 'all' },
      { name: { zh: '插入数据', en: 'INSERT Data' }, command: "INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com');\nSELECT last_insert_rowid();", description: { zh: '插入并获取最后插入ID', en: 'Insert and get last inserted ID' }, platform: 'all' },
      { name: { zh: '更新数据', en: 'UPDATE Data' }, command: "UPDATE users SET name='Bob' WHERE id=1;", description: { zh: '更新记录', en: 'Update records' }, platform: 'all' },
      { name: { zh: '删除数据', en: 'DELETE Data' }, command: 'DELETE FROM users WHERE id=1;\nDELETE FROM users; -- delete all rows', description: { zh: '按条件或全量删除', en: 'Delete by condition or all rows' }, platform: 'all' },
      { name: { zh: '建表', en: 'CREATE TABLE' }, command: 'CREATE TABLE users (\n  id INTEGER PRIMARY KEY AUTOINCREMENT,\n  name TEXT NOT NULL,\n  email TEXT UNIQUE,\n  created_at TEXT DEFAULT (datetime(\'now\'))\n);', description: { zh: '创建表，INTEGER PRIMARY KEY自动为rowid别名', en: 'Create table, INTEGER PRIMARY KEY aliases rowid' }, platform: 'all' },
      { name: { zh: '修改表结构', en: 'ALTER TABLE' }, command: 'ALTER TABLE users ADD COLUMN age INTEGER;\n-- SQLite only supports ADD COLUMN and RENAME\nALTER TABLE users RENAME TO users_old;', description: { zh: 'SQLite仅支持ADD COLUMN和RENAME', en: 'SQLite only supports ADD COLUMN and RENAME' }, platform: 'all' },
      { name: { zh: '事务控制', en: 'Transaction' }, command: 'BEGIN TRANSACTION;\nUPDATE accounts SET balance=balance-100 WHERE id=1;\nUPDATE accounts SET balance=balance+100 WHERE id=2;\nCOMMIT; -- or ROLLBACK;', description: { zh: '事务控制', en: 'Transaction control' }, platform: 'all' },
      { name: { zh: '创建索引', en: 'CREATE INDEX' }, command: 'CREATE INDEX idx_name ON users (name);\nCREATE UNIQUE INDEX idx_email ON users (email);', description: { zh: '创建普通或唯一索引', en: 'Create regular or unique index' }, platform: 'all' },
      { name: { zh: '创建视图', en: 'CREATE VIEW' }, command: 'CREATE VIEW active_users AS SELECT id, name FROM users WHERE active=1;', description: { zh: '创建视图', en: 'Create a view' }, platform: 'all' },
      { name: { zh: '触发器', en: 'Trigger (replaces procedure)' }, command: "CREATE TRIGGER update_ts AFTER UPDATE ON users\nBEGIN\n  UPDATE users SET updated_at=datetime('now') WHERE id=NEW.id;\nEND;", description: { zh: 'SQLite无存储过程，用触发器替代', en: 'SQLite has no stored procedures, use triggers' }, platform: 'all' },
      { name: { zh: '常用函数', en: 'Built-in Functions' }, command: "SELECT COUNT(*), AVG(salary), MAX(salary), SUM(salary) FROM employees;\nSELECT datetime('now'), strftime('%Y-%m-%d', created_at), first||' '||last FROM users;\nSELECT COALESCE(col,'default'), LENGTH(name), UPPER(name) FROM users;", description: { zh: '聚合、日期、字符串函数', en: 'Aggregate, date, string functions' }, platform: 'all' },
      { name: { zh: 'UPSERT', en: 'UPSERT (INSERT OR REPLACE)' }, command: "INSERT INTO users (id, name) VALUES (1, 'Alice') ON CONFLICT(id) DO UPDATE SET name=excluded.name;\n-- or:\nINSERT OR REPLACE INTO users (id, name) VALUES (1, 'Alice');", description: { zh: '冲突时更新', en: 'Insert or update on conflict' }, platform: 'all' },
    ],
  },
];

const now = new Date().toISOString();
const maxSort = db.prepare('SELECT MAX(sort_order) as m FROM tools').get().m ?? 0;

const insertTool = db.prepare(
  'INSERT OR REPLACE INTO tools (id, data, sort_order, enabled, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)'
);

let toolCount = 0;
tools.forEach((tool, i) => {
  insertTool.run(tool.id, JSON.stringify(tool), maxSort + 1 + i, now, now);
  toolCount++;
});

// Create or update db-tools navigation node
const DB_NODE_ID = 'db-tools';
const existing = db.prepare('SELECT tree FROM navigation_nodes WHERE id=?').get(DB_NODE_ID);

const children = tools.map(t => ({
  id: t.id,
  name: t.name,
  toolId: t.id,
}));

const maxNavSort = db.prepare('SELECT MAX(sort_order) as m FROM navigation_nodes').get().m ?? 0;

if (existing) {
  const tree = JSON.parse(existing.tree);
  // Merge new children (avoid duplicates)
  const existingIds = new Set((tree.children || []).map(c => c.id));
  const toAdd = children.filter(c => !existingIds.has(c.id));
  tree.children = [...(tree.children || []), ...toAdd];
  db.prepare('UPDATE navigation_nodes SET tree=?, updated_at=? WHERE id=?')
    .run(JSON.stringify(tree), now, DB_NODE_ID);
  console.log(`Updated nav node "${DB_NODE_ID}", added ${toAdd.length} children`);
} else {
  const tree = {
    id: DB_NODE_ID,
    name: { zh: '🗄️ 数据库工具', en: '🗄️ Database Tools' },
    children,
  };
  db.prepare('INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)')
    .run(DB_NODE_ID, JSON.stringify(tree), 'tools', maxNavSort + 1, now, now);
  console.log(`Created nav node "${DB_NODE_ID}" with ${children.length} children`);
}

console.log(`Inserted/replaced ${toolCount} tools: ${tools.map(t => t.id).join(', ')}`);
