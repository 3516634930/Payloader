import { readFileSync, writeFileSync } from 'fs';
const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');
let ok = 0;

// Build attackChain/analysis/references and insert before tutorial
function enrich(id, data) {
  const idx = c.indexOf("id: '" + id + "',");
  if (idx < 0) { console.log('SKIP', id); return; }
  const block = c.slice(idx, idx + 10000);
  const tutIdx = block.indexOf('    tutorial: {');
  if (tutIdx < 0) { console.log('SKIP', id, '-no tutorial'); return; }

  const ac = data.ac.map(s =>
    `      { title: { zh: '${s[0]}', en: '${s[1]}' }, description: { zh: '${s[2]}', en: '${s[3]}' } },`
  ).join('\n');
  const ref = data.ref.map(r => `      '${r}',`).join('\n');
  const an = `    analysis: { zh: '${data.an[0].replace(/'/g,"\\'")}', en: '${data.an[1].replace(/'/g,"\\'")}' },`;

  const extra = `    attackChain: [\n${ac}\n    ],\n${an}\n    references: [\n${ref}\n    ],\n`;
  c = c.slice(0, idx + tutIdx) + extra + c.slice(idx + tutIdx);
  console.log('DONE', id);
  ok++;
}

// ======================== DATA ========================
const data = {
  'sqli-mysql-basic': {
    ac: [
      ['探测注入点','Detect injection point','使用单引号、双引号、反斜杠和布尔条件(OR 1=1/OR 1=2)探测是否存在SQL注入点。通过响应差异、报错信息或布尔状态变化确认。','Use single/double quotes, backslashes, and boolean conditions (OR 1=1/OR 1=2) to detect SQL injection. Confirm via response differences, errors, or boolean state changes.'],
      ['确定列数','Determine column count','使用ORDER BY递增、UNION SELECT NULL逐列增加或GROUP BY/ORDER BY报错确定查询列数。','Determine column count via ORDER BY increments, UNION SELECT NULL additions, or GROUP BY/ORDER BY errors.'],
      ['识别数据库类型与版本','Identify database type and version','通过数据库特有函数(database()/version()/@@version/user())和注释语法(--/#)识别后端数据库类型和版本。','Identify backend database type and version via DB-specific functions and comment syntax.'],
      ['枚举数据库结构','Enumerate database schema','查询information_schema/sys.tables/sys.columns等元数据表枚举数据库、表和列结构。','Enumerate databases, tables, and columns via information_schema and other metadata tables.'],
      ['提取数据','Extract data','使用UNION SELECT或盲注逐字符提取敏感数据(用户表、密码哈希、信用卡等)。','Extract sensitive data via UNION SELECT or blind injection character-by-character.'],
    ],
    an: ['MySQL注入是最常见的SQL注入类型。通过information_schema元数据库可完整枚举数据结构。MySQL支持UNION查询、多语句(需stacked query)、文件读写(LOAD_FILE/INTO OUTFILE需FILE权限)和UDF提权。注释语法支持--、#和/**/。','MySQL injection is the most common SQL injection type. information_schema enables full schema enumeration. MySQL supports UNION queries, stacked queries (when enabled), file read/write (LOAD_FILE/INTO OUTFILE), and UDF privilege escalation. Comment syntax: --, #, /**/.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://owasp.org/www-community/attacks/SQL_Injection','https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  'sqli-mysql-advanced': {
    ac: [
      ['确认高级利用条件','Confirm advanced exploitability','确认当前数据库用户是否具有FILE权限、能否堆叠查询、是否可创建函数(UDF)以及网络边界。','Confirm FILE privilege, stacked query support, UDF creation capability, and network boundaries.'],
      ['文件读写利用','File read/write exploitation','使用LOAD_FILE读取/etc/passwd等系统文件，或通过INTO OUTFILE/DUMPFILE写入WebShell到Web目录。','Read system files via LOAD_FILE or write WebShells via INTO OUTFILE/DUMPFILE to web directories.'],
      ['UDF提权','UDF privilege escalation','上传或写入UDF动态库创建sys_exec/sys_eval函数执行系统命令。','Upload/write UDF shared libraries to create sys_exec/sys_eval functions for system command execution.'],
      ['绕过安全限制','Bypass security restrictions','利用DNS外带(SELECT LOAD_FILE外带数据)、HTTP外带和OOB通道绕过输出限制。','Bypass output restrictions via DNS out-of-band, HTTP exfiltration, and OOB channels.'],
    ],
    an: ['MySQL高级注入利用FILE权限进行文件读写、UDF提权获取系统命令执行、DNS/HTTP外带绕过数据输出限制。这些技术需要更高的数据库权限，但能突破Web应用层的安全限制，直接操作系统层面。','Advanced MySQL injection exploits FILE privilege for file operations, UDF for system command execution, and DNS/HTTP out-of-band for data exfiltration. These techniques require higher DB privileges but can break through web-layer restrictions.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html'],
  },
  'sqli-mssql-basic': {
    ac: [
      ['探测注入点与数据库类型','Detect injection point and DB type','使用单引号/双引号探测，通过@@version、WAITFOR DELAY和特有错误信息(CONVERT/CAST)识别MSSQL。','Detect and identify MSSQL via @@version, WAITFOR DELAY, and distinctive error messages.'],
      ['UNION查询与列数确定','UNION query & column enumeration','使用ORDER BY和UNION SELECT NULL确定列数，利用MSSQL特有函数(@@version/db_name())探测。','Determine column count via ORDER BY/UNION SELECT NULL; use MSSQL-specific functions for recon.'],
      ['通过错误信息提取数据','Extract data via errors','利用CONVERT/CAST类型转换错误在错误消息中泄露数据。','Extract data via CONVERT/CAST type conversion errors that leak data in error messages.'],
      ['枚举数据库对象','Enumerate database objects','查询sys.databases/sys.tables/sys.columns等系统视图枚举所有数据库对象。','Enumerate all database objects via sys.databases, sys.tables, sys.columns system views.'],
      ['执行命令(xp_cmdshell)','Execute commands (xp_cmdshell)','如果xp_cmdshell可用，通过SQL注入直接执行操作系统命令。','Execute OS commands directly via SQL injection if xp_cmdshell is available.'],
    ],
    an: ['MSSQL注入通过sys.*系统视图枚举数据库结构。支持堆叠查询(stacked query)执行多语句、xp_cmdshell扩展存储过程执行系统命令、OPENROWSET/OPENDATASOURCE外带数据、以及CONVERT/CAST类型转换报错泄露数据。','MSSQL injection enumerates via sys.* views. Supports stacked queries for multi-statement execution, xp_cmdshell for OS commands, OPENROWSET/OPENDATASOURCE for data exfiltration, and CONVERT/CAST error-based data leakage.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  'sqli-mssql-advanced': {
    ac: [
      ['确认xp_cmdshell可用性','Confirm xp_cmdshell availability','检查xp_cmdshell是否启用，如被禁用则通过sp_configure重新激活。','Check if xp_cmdshell is enabled; if disabled, reactivate via sp_configure.'],
      ['执行系统命令','Execute system commands','通过xp_cmdshell执行whoami/systeminfo/ipconfig等系统命令，建立反向Shell或下载执行恶意程序。','Execute system commands via xp_cmdshell; establish reverse shells or download/execute malicious programs.'],
      ['利用OLE自动化','Exploit OLE automation','如xp_cmdshell不可用，使用sp_OACreate/sp_OAMethod通过OLE对象执行命令或操作文件。','If xp_cmdshell is unavailable, use sp_OACreate/sp_OAMethod via OLE objects for command execution or file operations.'],
      ['外带数据与横向移动','Data exfiltration & lateral movement','使用OPENROWSET/OPENDATASOURCE外带数据，或通过xp_dirtree/xp_fileexist进行SMB中继攻击获取NetNTLM哈希。','Exfiltrate via OPENROWSET/OPENDATASOURCE or capture NetNTLM hashes via xp_dirtree/xp_fileexist SMB relay.'],
    ],
    an: ['MSSQL高级注入利用xp_cmdshell获取OS命令执行、OLE自动化(sp_OACreate)绕过xp_cmdshell限制、OPENROWSET外带数据，以及xp_dirtree触发SMB认证捕获NetNTLM哈希。在域环境中可横向移动到域控制器。','Advanced MSSQL injection exploits xp_cmdshell for OS commands, OLE automation to bypass restrictions, OPENROWSET for data exfiltration, and xp_dirtree for SMB relay to capture NetNTLM hashes. Lateral movement to domain controllers is possible in domain environments.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html'],
  },
  'sqli-oracle-basic': {
    ac: [
      ['识别Oracle数据库','Identify Oracle database','通过Oracle特有函数(banner/ROWNUM)、DUAL表和错误信息识别后端为Oracle。','Identify Oracle via distinctive functions, DUAL table, and error messages.'],
      ['UNION查询与基础探测','UNION query & basic recon','Oracle UNION需要FROM子句(使用DUAL表)，通过NULL占位确定列数和数据类型。','Oracle UNION requires FROM clause (use DUAL table); determine column count and types via NULL placeholders.'],
      ['枚举数据库对象','Enumerate database objects','查询ALL_TABLES/ALL_TAB_COLUMNS等数据字典视图枚举所有可访问的对象。','Enumerate all accessible objects via ALL_TABLES, ALL_TAB_COLUMNS, and other data dictionary views.'],
      ['报错注入提取数据','Error-based data extraction','利用UTL_INADDR/CTXSYS/XMLType等Oracle特有报错函数泄露数据。','Leak data via Oracle-specific error functions (UTL_INADDR, CTXSYS, XMLType).'],
    ],
    an: ['Oracle注入需要FROM子句(使用DUAL表)配合UNION查询。通过ALL_TABLES/ALL_TAB_COLUMNS字典视图枚举结构。支持UTL_INADDR.get_host_name/CTXSYS.drithsx/XMLType报错注入、DBMS_PIPE.RECEIVE_MESSAGE时间盲注和UTL_HTTP外带。','Oracle injection requires FROM clause (DUAL table) for UNION. Enumerate via ALL_TABLES/ALL_TAB_COLUMNS views. Supports UTL_INADDR/CTXSYS/XMLType error-based, DBMS_PIPE time-based, and UTL_HTTP out-of-band.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://book.hacktricks.wiki/en/pentesting-web/sql-injection/oracle-sql-injection.html'],
  },
  'sqli-oracle-advanced': {
    ac: [
      ['权限提升与命令执行','Privilege escalation & command execution','利用DBMS_JAVA/DBMS_SCHEDULER等高级包创建Java存储过程执行系统命令。','Exploit DBMS_JAVA/DBMS_SCHEDULER to create Java stored procedures for OS command execution.'],
      ['文件读写操作','File read/write operations','使用UTL_FILE包读写服务器文件，通过外部表访问文件系统。','Read/write server files via UTL_FILE package; access filesystem through external tables.'],
      ['HTTP外带与网络利用','HTTP exfiltration & network exploitation','利用UTL_HTTP/HTTPURITYPE发起HTTP请求外带数据或SSRF攻击内网服务。','Use UTL_HTTP/HTTPURITYPE for HTTP requests to exfiltrate data or perform SSRF against internal services.'],
    ],
    an: ['Oracle高级注入利用PL/SQL包(DBMS_JAVA/DBMS_SCHEDULER/UTL_FILE/UTL_HTTP)实现命令执行、文件操作和网络攻击。Oracle Java存储过程可以突破数据库边界获取操作系统级别的控制。','Advanced Oracle injection leverages PL/SQL packages for command execution, file operations, and network attacks. Oracle Java stored procedures can break out of the database boundary for OS-level control.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://book.hacktricks.wiki/en/pentesting-web/sql-injection/oracle-sql-injection.html'],
  },
  'sqli-postgres-basic': {
    ac: [
      ['识别PostgreSQL','Identify PostgreSQL','通过pg_sleep/current_database()/version()和--注释语法识别PostgreSQL后端。','Identify PostgreSQL via pg_sleep, current_database(), version(), and -- comment syntax.'],
      ['UNION查询与结构枚举','UNION query & schema enumeration','确定列数后通过information_schema和pg_catalog枚举数据库、schema、表和列。','After determining column count, enumerate databases, schemas, tables, and columns via information_schema and pg_catalog.'],
      ['报错注入与数据提取','Error-based & data extraction','利用CAST类型转换错误泄露数据，或通过UNION SELECT直接提取。','Leak data via CAST type conversion errors or extract directly via UNION SELECT.'],
      ['高级特性利用','Advanced feature exploitation','利用COPY/lo_import读取文件，利用dblink访问其他数据库，利用pg_read_file读取系统文件。','Read files via COPY/lo_import, access other databases via dblink, read system files via pg_read_file.'],
    ],
    an: ['PostgreSQL注入通过pg_catalog和information_schema枚举数据库结构。支持堆叠查询、COPY/lo_import文件读取、dblink外部数据库访问、用户定义函数(C/PL/Python)创建和pg_read_file系统文件读取。pg_sleep用于时间盲注。','PostgreSQL injection enumerates via pg_catalog and information_schema. Supports stacked queries, COPY/lo_import file reading, dblink external DB access, UDF creation (C/PL/Python), and pg_read_file for system file access. pg_sleep is used for time-based blind.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://book.hacktricks.wiki/en/pentesting-web/sql-injection/postgresql-injection.html'],
  },
  'sqli-sqlite-basic': {
    ac: [
      ['识别SQLite','Identify SQLite','通过randomblob()/sqlite_version()和缺少information_schema的特征识别SQLite数据库。','Identify SQLite via randomblob(), sqlite_version(), and absence of information_schema.'],
      ['UNION查询与表枚举','UNION query & table enumeration','使用UNION SELECT查询sqlite_master表枚举所有表和列结构(无information_schema)。','Enumerate all tables and columns via UNION SELECT against the sqlite_master table (no information_schema).'],
      ['盲注与时间延迟','Blind injection & time delays','使用randomblob(大量)/LIKE+UPPER+HEX组合或SQLite特有函数实现时间盲注。','Implement time-based blind via randomblob() large allocations or LIKE+UPPER+HEX combinations.'],
      ['文件操作与利用','File operations & exploitation','利用ATTACH DATABASE附加外部数据库文件或通过特定配置写入文件系统。','Attach external database files via ATTACH DATABASE or write to filesystem through specific configurations.'],
    ],
    an: ['SQLite注入通过sqlite_master表(替代information_schema)枚举数据库结构。不支持堆叠查询但支持UNION。时间盲注使用randomblob()进行CPU密集型操作。ATTACH DATABASE可附加外部文件。常见于移动应用、嵌入式系统和客户端数据库场景。','SQLite injection enumerates via sqlite_master table (replaces information_schema). Supports UNION but not stacked queries. Time-based blind uses randomblob() for CPU-intensive delays. ATTACH DATABASE can attach external files. Common in mobile, embedded, and client-side DB scenarios.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection'],
  },
  'sqli-mongodb-basic': {
    ac: [
      ['识别NoSQL/JSON输入','Identify NoSQL/JSON input','通过JSON格式参数、Content-Type和响应特征确认后端是否使用MongoDB。','Confirm MongoDB backend via JSON-format parameters, Content-Type, and response characteristics.'],
      ['运算符注入($ne/$gt/$regex)','Operator injection ($ne/$gt/$regex)','使用$ne(不等于)、$gt(大于)、$regex(正则匹配)和$where(JS执行)操作符绕过认证和提取数据。','Use $ne (not equal), $gt (greater than), $regex (pattern match), and $where (JS execution) operators to bypass auth and extract data.'],
      ['盲注与布尔探测','Blind & boolean probing','利用$regex逐字符爆破和$where时间延迟(睡眠函数)进行盲注数据提取。','Extract data via $regex character-by-character brute-force and $where time delays (sleep function).'],
      ['SSJI服务端JS注入','SSJI server-side JS injection','如果$where可用，注入任意JavaScript代码实现服务端代码执行。','If $where is available, inject arbitrary JavaScript code for server-side code execution.'],
    ],
    an: ['MongoDB NoSQL注入利用$ne/$gt/$regex/$where等操作符绕过查询逻辑。$regex可逐字符爆破数据，$where允许注入JavaScript实现服务端代码执行(SSJI)。与SQL注入不同，NoSQL注入不依赖SQL语法而是JSON结构和操作符。','MongoDB NoSQL injection exploits $ne/$gt/$regex/$where operators to bypass query logic. $regex enables character-by-character data brute-force; $where allows JavaScript injection for server-side code execution (SSJI). Unlike SQL injection, NoSQL injection targets JSON structure and operators.'],
    ref: ['https://owasp.org/www-community/attacks/NoSQL_Injection','https://portswigger.net/web-security/nosql-injection','https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html'],
  },
  'sqli-redis': {
    ac: [
      ['探测Redis服务','Detect Redis service','通过SSRF或直接网络访问探测Redis未授权端口(6379)，使用INFO/PING命令确认。','Probe Redis unauthorized port (6379) via SSRF or direct network access; confirm with INFO/PING commands.'],
      ['信息收集','Information gathering','使用INFO/CONFIG GET/CONFIG GET dir/CONFIG GET dbfilename获取Redis配置和数据目录。','Gather Redis configuration and data directories via INFO, CONFIG GET dir, CONFIG GET dbfilename.'],
      ['写入WebShell','Write WebShell','通过CONFIG SET dir修改RDB持久化目录为Web路径，写入PHP/ASPX WebShell到磁盘。','Modify RDB persistence directory to web path via CONFIG SET dir and write PHP/ASPX WebShells to disk.'],
      ['SSH密钥写入','SSH authorized_keys write','通过Redis写入SSH公钥到/root/.ssh/authorized_keys实现免密SSH登录。','Write SSH public key to /root/.ssh/authorized_keys via Redis for passwordless SSH login.'],
      ['Crontab计划任务','Crontab scheduled tasks','写入Crontab计划任务文件到/var/spool/cron/实现定时反弹Shell。','Write crontab task files to /var/spool/cron/ for scheduled reverse shells.'],
    ],
    an: ['Redis未授权访问是特殊的NoSQL场景——通过RESP协议直接与Redis服务交互。攻击路径包括：CONFIG SET dir修改持久化目录、写入WebShell到Web路径、SSH authorized_keys注入和Crontab计划任务反弹Shell。利用SSRF访问内网Redis时使用gopher/dict协议编码RESP命令。','Redis unauthorized access is a special NoSQL scenario — direct interaction via RESP protocol. Attack paths: modify persistence directory via CONFIG SET dir, write WebShells to web paths, inject SSH authorized_keys, and create crontab reverse shells. Use gopher/dict protocol to encode RESP commands when exploiting via SSRF.'],
    ref: ['https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/index.html','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery'],
  },
  'sqli-blind': {
    ac: [
      ['确认布尔盲注条件','Confirm boolean blind conditions','通过TRUE/FALSE条件(AND 1=1/AND 1=2)对比响应差异，确认布尔盲注可行。','Confirm boolean blind injection via TRUE/FALSE condition response comparison (AND 1=1 vs AND 1=2).'],
      ['确定数据库与长度','Determine database and lengths','使用ASCII/SUBSTRING/LENGTH逐字符推断数据库名、表名、列名的长度和字符。','Infer database name, table name, and column name lengths and characters via ASCII/SUBSTRING/LENGTH character-by-character.'],
      ['逐字符提取数据','Character-by-character data extraction','使用二分法(ASCII>64/96/112...)加速逐字符数据提取。','Accelerate character-by-character extraction via binary search (ASCII>64/96/112...).'],
      ['自动化利用','Automated exploitation','使用sqlmap(Boolean-based blind模式)自动化布尔盲注数据提取。','Automate boolean blind data extraction via sqlmap boolean-based blind mode.'],
    ],
    an: ['布尔盲注通过TRUE/FALSE条件的响应差异逐位推断数据。使用ASCII/SUBSTRING/LENGTH函数和二分法可大幅提高提取效率。虽然速度较慢，但在无直接回显和报错信息时是最可靠的数据提取方式。','Boolean blind injection infers data bit-by-bit through TRUE/FALSE condition response differences. ASCII/SUBSTRING/LENGTH with binary search significantly improves extraction speed. While slower, it is the most reliable method when direct output and errors are unavailable.'],
    ref: ['https://portswigger.net/web-security/sql-injection/blind','https://owasp.org/www-community/attacks/Blind_SQL_Injection'],
  },
  'sqli-time-based': {
    ac: [
      ['确认时间盲注可行','Confirm time-based feasibility','使用数据库特有延迟函数(SLEEP/pg_sleep/WAITFOR DELAY/dbms_pipe.receive/randomblob)确认时间盲注可行。','Confirm time-based blind via DB-specific delay functions (SLEEP/pg_sleep/WAITFOR DELAY/dbms_pipe/randomblob).'],
      ['逐字符时间推断','Character-by-character timing','将时间延迟嵌入条件判断(IF/IIF/CASE WHEN)，根据延迟推断字符值。','Embed time delays in conditional logic (IF/IIF/CASE WHEN) to infer character values based on delay.'],
      ['IF/CASE语法适配','IF/CASE syntax adaptation','根据数据库类型使用不同的条件语法:MySQL IF()/MSSQL IIF()/PostgreSQL CASE WHEN/Oracle DECODE。','Use DB-specific conditional syntax: MySQL IF(), MSSQL IIF(), PostgreSQL CASE WHEN, Oracle DECODE.'],
      ['自动化利用','Automated exploitation','使用sqlmap(Time-based blind模式)自动化时间盲注数据提取。','Automate time-based blind data extraction via sqlmap time-based blind mode.'],
    ],
    an: ['时间盲注是最通用的盲注技术——通过数据库延迟函数(SLEEP/BENCHMARK/WAITFOR/pg_sleep/dbms_pipe)将数据逐位编码为时间延迟。适用于无响应差异且无报错回显的场景，但提取速度最慢。sqlmap Time-based盲注模式可自动化。','Time-based blind is the most universal blind technique — encoding data bit-by-bit as time delays via DB delay functions. Works when no response differences or errors are visible, but is the slowest extraction method. sqlmap time-based blind mode automates this.'],
    ref: ['https://portswigger.net/web-security/sql-injection/blind','https://owasp.org/www-community/attacks/Blind_SQL_Injection'],
  },
  'sqli-error-based': {
    ac: [
      ['触发报错回显','Trigger error output','确认目标是否返回详细数据库错误信息，判断报错注入可行性。','Confirm whether the target returns detailed DB error messages to determine error-based feasibility.'],
      ['利用数据库报错函数','Exploit DB error functions','MySQL: extractvalue/updatexml/exp/GTID_SUBSET; MSSQL: CONVERT/CAST; PostgreSQL: CAST; Oracle: UTL_INADDR/CTXSYS。','Use DB-specific error functions: MySQL extractvalue/updatexml/exp, MSSQL CONVERT/CAST, PostgreSQL CAST, Oracle UTL_INADDR/CTXSYS.'],
      ['在报错中嵌入数据','Embed data in errors','将目标数据拼接进报错函数的参数中，使数据库在错误消息中返回敏感数据。','Concatenate target data into error function parameters, causing the database to return sensitive data in error messages.'],
      ['双重查询与溢出','Double query & overflow','MySQL: 使用count+rand+floor双重查询报错; PostgreSQL: 使用CAST溢出; Oracle: CTXSYS.DRITHSX。','MySQL: count+rand+floor double query; PostgreSQL: CAST overflow; Oracle: CTXSYS.DRITHSX.'],
    ],
    an: ['报错注入通过触发数据库错误并将数据嵌入错误消息来快速提取数据——比盲注快数个数量级。每种数据库有特有报错函数:MySQL(extractvalue/updatexml/exp)、MSSQL(CONVERT/CAST)、PostgreSQL(CAST)、Oracle(UTL_INADDR/CTXSYS)。','Error-based injection extracts data by triggering DB errors with embedded data — orders of magnitude faster than blind injection. Each DB has specific functions: MySQL (extractvalue/updatexml/exp), MSSQL (CONVERT/CAST), PostgreSQL (CAST), Oracle (UTL_INADDR/CTXSYS).'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://owasp.org/www-community/attacks/SQL_Injection'],
  },
  'sqli-second-order': {
    ac: [
      ['识别二阶注入点','Identify second-order injection point','在注册/个人信息/留言等持久化输入点注入SQL payload，再访问触发该数据的页面确认执行。','Inject SQL payloads in persistent inputs (registration/profile/comments), then access pages that retrieve that data to confirm execution.'],
      ['构造存储型Payload','Craft stored payload','Payload需避免在首次存储时被转义/过滤，同时在被读取拼接进SQL时能触发注入。','Craft payloads that survive initial storage escaping/filtering while triggering injection when later concatenated into SQL.'],
      ['触发执行','Trigger execution','找到读取存储数据的页面/功能，触发二阶SQL注入执行。','Locate pages/functions that retrieve the stored data, triggering second-order SQL injection execution.'],
      ['数据提取','Data extraction','确认二阶注入成功后使用UNION/盲注/报错等技术提取数据。','After confirming second-order injection, extract data via UNION/blind/error-based techniques.'],
    ],
    an: ['二阶SQL注入是持久化输入被存储后，在后续数据库查询中未安全处理而触发的注入。因输入和触发分离，比一阶注入更难检测——WAF在第一阶段看到的是无害数据，SQL在第二阶段才被构造执行。','Second-order SQL injection occurs when stored input is unsafely used in later queries. Detection is harder than first-order because input and trigger are separated — WAF sees harmless data in stage one, SQL is constructed and executed in stage two.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://owasp.org/www-community/attacks/SQL_Injection'],
  },
  'sqli-union': {
    ac: [
      ['确定查询列数','Determine column count','使用ORDER BY递增或UNION SELECT NULL逐列增加确定原始查询的列数。','Determine original query column count via ORDER BY increment or UNION SELECT NULL additions.'],
      ['匹配数据类型','Match data types','使用NULL占位非字符串列，在显示位置插入数据库函数(database()/version()/user())确认数据类型兼容。','Use NULL placeholders for non-string columns; insert DB functions at display positions to confirm type compatibility.'],
      ['枚举与提取','Enumeration & extraction','在UNION SELECT中替换显示列为目标数据(表名/列名/敏感值)直接提取。','Replace display columns in UNION SELECT with target data (table names, column names, sensitive values) for direct extraction.'],
      ['跨数据库UNION','Cross-DB UNION','适配不同数据库的UNION语法差异:Oracle需FROM DUAL, MSSQL支持UNION ALL, MySQL可省略FROM。','Adapt UNION syntax to different databases: Oracle needs FROM DUAL, MSSQL supports UNION ALL, MySQL can omit FROM.'],
    ],
    an: ['UNION注入是最高效的SQL注入技术——直接将查询结果合并到页面回显中提取。需确定列数和数据类型后才能成功。Oracle需FROM DUAL, PostgreSQL类型检查严格, MySQL/MSSQL较宽松。','UNION injection is the most efficient SQL injection technique — directly merging query results into page output. Requires determining column count and data types first. Oracle needs FROM DUAL, PostgreSQL has strict type checks, MySQL/MSSQL are more lenient.'],
    ref: ['https://portswigger.net/web-security/sql-injection/union-attacks','https://owasp.org/www-community/attacks/SQL_Injection'],
  },
  'sqli-stacked': {
    ac: [
      ['确认堆叠查询支持','Confirm stacked query support','使用分号分隔执行多条语句(; SELECT 1; SELECT 2)确认数据库/驱动是否支持多语句查询。','Confirm multi-statement support via semicolon-separated queries (; SELECT 1; SELECT 2).'],
      ['通过堆叠查询写WebShell','Write WebShell via stacked queries','使用INTO OUTFILE(MySQL)或xp_cmdshell(MSSQL)通过堆叠查询写入WebShell到Web目录。','Write WebShells to web directories via INTO OUTFILE (MySQL) or xp_cmdshell (MSSQL) through stacked queries.'],
      ['数据修改与权限提升','Data modification & privilege escalation','通过堆叠查询UPDATE/INSERT/DELETE修改数据、创建管理员账户、修改权限或执行存储过程。','Modify data via UPDATE/INSERT/DELETE, create admin accounts, modify privileges, or execute stored procedures through stacked queries.'],
      ['跨数据库堆叠','Cross-DB stacked queries','不同数据库/驱动的堆叠支持不同:MySQL+PHP(mysqli支持/mysql不支持)、MSSQL全支持、PostgreSQL+PHP支持。','Stacked query support varies: MySQL+PHP (mysqli yes/mysql no), MSSQL fully supports, PostgreSQL+PHP supports.'],
    ],
    an: ['堆叠查询(stacked query)通过分号在一请求中执行多条SQL语句，攻击面远超单语句注入。支持写入文件(INTO OUTFILE)、执行系统命令(xp_cmdshell)、修改数据(UPDATE/DELETE/INSERT)和提权。MSSQL和PostgreSQL默认支持，MySQL取决于驱动。','Stacked queries execute multiple SQL statements via semicolons in a single request, far exceeding single-statement injection. Enables file writes, system command execution, data modification, and privilege escalation. MSSQL/PostgreSQL support by default; MySQL depends on driver.'],
    ref: ['https://portswigger.net/web-security/sql-injection','https://owasp.org/www-community/attacks/SQL_Injection'],
  },
  'sqli-waf-bypass': {
    ac: [
      ['探测WAF规则','Probe WAF rules','使用基础SQL payload探测WAF拦截规则——确认拦截的是关键字、特殊字符还是语法模式。','Probe WAF rules with basic SQL payloads — determine whether keywords, special chars, or syntax patterns are blocked.'],
      ['编码与注释绕过','Encoding & comment bypass','使用URL编码(%27)、Hex编码(0x3a)、注释分割(/**/)、内联注释(/*!50000*/)和大小写混写绕过关键字过滤。','Bypass keyword filters via URL encoding, hex encoding, comment splitting, inline comments, and case mixing.'],
      ['等价替换与语义绕过','Equivalent substitution & semantic bypass','将空格替换为%09/%0a/**/、将等号替换为LIKE/REGEXP/BETWEEN、将AND/OR替换为&&/||。','Replace spaces with %09/%0a/**, equals with LIKE/REGEXP/BETWEEN, AND/OR with &&/||.'],
      ['HTTP参数污染与分块','HTTP parameter pollution & chunking','使用HPP(同参数多值)、分块传输(Transfer-Encoding: chunked)和HTTP/2 multiplexing绕过WAF流检测。','Bypass WAF stream inspection via HTTP parameter pollution, chunked transfer encoding, and HTTP/2 multiplexing.'],
      ['高级混淆与等价函数','Advanced obfuscation & equivalent functions','使用等价函数替换(SUBSTRING→MID/SUBSTR)、浮点运算、变量赋值(@a:=)和缓冲区溢出绕过高级WAF。','Use equivalent function substitution, floating-point operations, variable assignments, and buffer overflow to bypass advanced WAF.'],
    ],
    an: ['SQL注入WAF绕过利用WAF与数据库解析器的不一致性——WAF可能不理解所有SQL方言、编码变体和等价语法。编码(URL/Hex/Unicode)、注释分割(/**/)、内联注释(/*!50000*/)、等价函数替换和HTTP参数污染是最有效的绕过技术。','SQL injection WAF bypass exploits inconsistency between WAF and DB parsers. WAF may not understand all SQL dialects, encodings, and equivalent syntax. Encoding (URL/Hex/Unicode), comment splitting, inline comments, function substitution, and HTTP parameter pollution are most effective.'],
    ref: ['https://owasp.org/www-community/attacks/SQL_Injection','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection'],
  },
};

// Apply all
for (const [id, d] of Object.entries(data)) {
  enrich(id, d);
}

writeFileSync(fp, c, 'utf8');
console.log('Total:', ok);
