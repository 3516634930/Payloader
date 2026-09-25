# 全库内容治理第三轮：30 分支全量审计与重组（2026-09-25）

用户指令："所有都要看，所有类型的漏洞或者攻击都要看"——继 SQL/NoSQL注入 分支（aae27bf）后对其余全部 30 个分支 688 组做同标准三查（命名/名实/堆分）。

## 执行链路

1. **程序化全库扫描**（scripts/scan-all-branches.cjs）：模板腔命名 106 组、单命令弱组 15、变量字面量 11、waf 逐字重复 50+、近似组名信号——产出 global-scan-findings.txt。
2. **7 包并行语义审计**（output/content-audit/audit-pack1..7.md，4+3 两波子代理）：每包命令级证据 + 六维结论（RENAME/MERGE/SPLIT/MISMATCH/CONTENT/KEEP）。汇总：RENAME 197→采纳 150、MERGE 126+pack3 21→执行 121、MISMATCH 41 条裁决、CONTENT 60+ 条裁决。
3. **方案构建**（build-plan-round3.cjs → plan-round3.json）：主会话裁决内嵌（pack3 七项核验、D 类 11 处真伪判定、伪造 CC gadget 替换、REVIEW 脚手架标记置换、SPLIT 降档为低风险子分支重定位）。
4. **执行**（apply-audit-plan.cjs）：声明层 + 文档链 walker（247 处）+ 命令补丁（13 个含宿主防撞）+ 子分支排序。

## 结构终态

- **payloads 764 → 632**（SQL 轮 -11、本轮 -121），组 629、子分支 163、空组 0
- **最大重复簇收敛**：JWT 三主题三连套 9→3、SSRF file/DNS/Gopher 碎片 16 组收敛、XSS DOM Clobbering 4→1、data: URI 3→1、Polyglot 2→1、命令注入/WebShell 家族成片合并、走私基础形态 4→2、内网 Potato 三工具组并 1、noPac 双组并 1、"文件包含与流包装器"子分支 3 组跨分支重复全清、MySQL LOAD_FILE 组从文档渲染器错位归位 SQL 分支
- **改名 150 组**：全库"边界/可见性/能力边界/求值边界"模板腔清零（CSP 允许列表绕过/Potato 家族提权/GraphQL 内省暴露 这类行业术语化）
- **名实修复 29 组 desc + 5 组 exec**：OLE"读文件"实为命令执行、伪造 CC hex 流换真实 CC6 源码链、Shiro 默认密钥行补全、Redis WebShell 链补 CONFIG/SAVE、kernel CVE 名单换 searchsploit、cron fixture 换真实通配符注入、4 处 PAYLOADER_*_REVIEW_N 审计脚手架标记清除
- **waf 卫生**：50+ 逐字重复条目去重/删除（doc 路线与补丁路线按冲突规则分派）、27 处 `<string>` XML 序列化壳污染清洗、victim 字面量变量化
- **测试基线**：generator spec 清 10 个退役 id + 测试硬编码更新（710/710 全绿）

## 管线暗债（本轮新发现并修复）

- **多副本 wafBypass 后者胜**：同 id 的 wafBypass 可被多文档携带，重放取 manifest 顺序后者——对齐/回写必须全副本统一
- **双验证基底矛盾**：review 审计以 seed 为基底、curation 以重放后快照为基底——doc 改写与补丁并存时锚必冲突；解法=纯去重走补丁（exp=seed 旧文）、删条目走 doc 剪除+删补丁
- **review.decision 合法值**仅 payload/tool/split；合并源的 split 声明与 ledger/review 残留决策必须三处同步清理
- **链空 payload 步**：runtime 历史链存在无锚步骤，重写后触发 MISSING_CHAIN_PAYLOAD——收敛循环（converge-chains.cjs）按 exec/waf 命令回填锚

## 遗留（记账，下轮候选）

- 行级手术 defer ×12：privilege-token 三行 potato 工具行、linux-privesc 与专项组去重、domain-cross-trust 越域两行、silver-ticket 注释行、arg-spoofing/ppid-spoof 拼接修复、fileup-php-stream-wrapper 五类 wrapper 拆行、rce-code-exec 四族拆分、auth2-jwt 三主题拼盘拆解
- id 卫生：cmdi2-/ssti2-/httpbypass- 空尾、nosql2-spel-…-languag 截断、inject2-…-type-juggling-29 词缀、184/163-lines 行数残留——改动牵引用面，需专项
- 3 条 WAF 豁免维持（BeEF 等语义豁免）
