# SQL/NoSQL注入 分支全量审计与重组方案（2026-09-25）

用户反馈：分类下的分类命名存疑、组内容正确性存疑、"堆在一起好还是分开好"待判定。要求先全方位调研再优化。

## 调研范围与方法

- 运行时库全量导出：12 子分支 / 75 组（每组=1 条 payload，含 execution/wafBypass/description 全文），产出 `output/content-audit/sqli-branch-full.txt`（563 行）。
- 8 个疑似缺陷组逐命令实证核对（`tmp-flagged.cjs` 已删）。
- 管线机制核对：组名=payload.name（`updatePayloadNavigationNames` 自动同步节点名）；payload.subCategory=子分支名（驱动归属）；`payloadMerges` 幂等退役源并 carried 去重进目标 wafBypass。

## 结论一：结构判断（堆/分）

**应拆分 ×1**：`sqli-pg-sqlite`（PostgreSQL 与 SQLite 注入）把两个 DBMS 的 9 个组混堆——兄弟分支 MySQL/MSSQL/Oracle 均独立成支，拆为 `sqli-postgresql`（4 组）+ `sqli-sqlite`（4 组）。

**应合并 ×11**（跨源重复簇，sqli/sqli2/nosql2/custom 四个来源各留一份）：

| 源（退役） | 目标（保留） | 重复主题 |
|---|---|---|
| sqli2-outfile-write-primitive | sqli-mysql-server-file-write | MySQL OUTFILE 写入 3 组并存 |
| sqli2-mysql-outfile-and-dumpfile-write-impact | sqli-mysql-server-file-write | 同上 |
| sqli2-sqlite-version-schema-and-column-enumeration | sqli-sqlite-union-enumeration | SQLite schema 枚举 2 组 |
| sqli2-nosql | sqli-mongodb-basic | MongoDB 操作符/运算符 2 组（同词异译） |
| sqli2-tricks-web-pentest-sql | sqli2- | 布尔闭合探测 3 组 |
| custom-sql注入速查表 | sqli2- | 同上（速查 3 命令与他组全重） |
| sqli2-union | sqli-union-query | UNION 列数对齐 2 组 |
| sqli2-direct-statement-and-catalog-selection | sqli-oracle-union-enumeration | 单命令弱组并入 Oracle 目录枚举 |
| sqli-carrier-chunked | sqli-http-chunked-carrier | Chunked 载体 2 组（仅端点名不同） |
| sqli2-union-crlf-comment-encoding | sqli2-union-extraction-lexical-encodings | 词法编码 2 组 |
| nosql2-sql | sqli-second-order | 二阶注入 2 组 |

**保持独立（不合并）的近似对**：时间盲注分支的 4 个"一秒延迟"方法论组 vs DBMS 分支的 WAITFOR/pg_sleep 变体组（方法论 vs 闭合变体，角度不同）；MySQL 联合查询组 vs UNION 分支跨库组（方言特定 vs 跨库通用）。

## 结论二：命名问题（33 组改名 + 3 分支改名）

系统性病灶：早期模板留下的"边界/可见性/能力边界/语义/语句"后缀（如"MySQL 服务端文件读取边界"），非行业术语。改为技术导向命名（LOAD_FILE 文件读取、UDF 提权、xp_cmdshell 命令执行……），完整映射见 `scripts/regroup4-sqli-2026-09.cjs` 的 NAME_FIX。

分支改名：MSSQL 注入→SQL Server 注入（与组前缀统一，微软官方称谓）；堆叠语句与写入→堆叠语句注入（"写入"名不副实，写入组均在各 DBMS 分支）；PG/SQLite 拆分同上。

## 结论三：内容缺陷（实证确认）

1. **OLE Automation 组 desc 名实不符**：说"读取本地文件"，命令实为 wscript.shell 执行 whoami 落盘 → desc 改为命令执行导向。
2. **Oracle DBMS_PIPE 组名实不符**：名/desc 说"RECEIVE_MESSAGE 条件延迟侧信道"，execution 实为 PACK_MESSAGE 缓冲回显（延迟形态在时间盲注分支）→ 改名"管道消息信道"+desc 修正。
3. **PostgreSQL COPY 组**：desc 说"写入文件"，execution 只有 COPY TO STDOUT（写入形态藏在 wafBypass）→ 改名"COPY 执行与文件写入"+desc 如实描述两级验证。
4. **sqli2-direct wafBypass 变量字面量**：`TARGET_TABLE`/`DATABASE_NAME` 缺花括号（此前变量化批次漏网）→ command-override 补丁修复（合并前修，carried 带修复版）。
5. **盲注谓词组 wafBypass 与 execution 逐字节重复**（8 行中 7 行相同）→ command-override 去重，仅保留真变体行。
6. **xp_cmdshell 组无缺陷**：截图所见 `^>` 转义缺失是 UI 层 JSON 转义显示，DB 内命令完好，不改。

## 落库路径（管线原生，全程文档链）

1. `tool-decisions.json`：payloadSubBranches 改名×2/删×1/增×2；payloadMerges 追加 11 条（titlePrefix 空，保留原标题）。
2. 文档链 walker（manifest 全部 override+collectionSplit 文档）：NAME_FIX×33 / DESC_FIX×3 / SUBCAT_FIX×17（MSSQL×4、PG×4、SQLite×4、堆叠×5），同步改写 obj 与 obj.payloadOverrides 两处。
3. 新增 `payload-command-overrides-sqlifix-2026-09.json`（2 补丁，expectedCommand 锚定 DB 现值），注册 manifest。
4. `node scripts/apply-payload-curation.mjs`（validate→--apply）→ verify → npm test → 浏览器验证 → 选择性 commit（不碰并行会话文件）。

预期终态：sqli 分支 13 子分支 / 64 组；全库 764-11=753 payloads。
