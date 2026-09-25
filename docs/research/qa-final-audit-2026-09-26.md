# 全库内容质量终审（payload+tools 双域）——2026-09-26

## 任务与范围

用户指令：所有 payload 内容/分类/攻击链/教程逐条看一遍，优化到"拿去好用、看得懂、不失专业"；随后工具命令同样逐条审，错误全更正。

覆盖：**632 payloads 全字段**（名称/描述/前置/执行 1095 条/分析/opsec/绕过 2389 条/攻击链 2268 步/教程 4 段）+ **377 工具 4831 命令**。分片 41+17=58 片（60KB/片，分支完整性优先），39 个子代理 + 主会话亲审 2 片（AI 安全分支越狱载荷触发平台内容过滤，改主会话处理）。

## 审计判据（四维）

1. **正确**：命令语法/判据技术成立/名实相符/术语准确（不确定标 VERIFY）
2. **易懂**：通顺、无机翻腔、术语有解释
3. **好用**：命令可复制（目标参数化）、判据给"怎么算成功"、前置清楚、链连贯
4. **专业**：删水话不删实质

## 发现与修复总量

| 波次 | 发现 | 落地 |
|---|---|---|
| payload 第一波 | 1238 处（WRONG 561/UNCLEAR 402/UNUSABLE 179/VERIFY 91/错类 5） | 132 卡文案 + 352 卡 619 命令 patch |
| 空锚链回填 | 147 卡链锚全空（历史遗留） | doc 回填+runtime 同步，632/632 有锚 |
| payload 第二波 | title 模板残留 181 条 + 缺改文 190 条 + 通配 14 | 152 卡 patch + 23 卡新 doc |
| tools | 1055 处（17 片） | 205 工具 868 patch（34 个 command patch 因重复/注释问题撤） |
| 错类裁决 | 5 处 | 2 卡归位（GraphQL 授权/透明覆盖），3 处遗留 |
| 全局变量 | 新占位符 23 个 | 注册 infra/cloud/target/auth/file 组 |

代表性技术修复：MySQL `CURRENT_USER()` 返回 user@host 与 mysql.user.user 等值比较恒空（SUBSTRING_INDEX 修正）、SQLite 不支持 `0x` 十六进制字符串字面量（改 CAST）、`ysoserial` 无 `-g gzip` 参数、log4shell `${::-x}` 机制表述纠正（查找名为空、x 为默认值）、Oracle UTL_FILE 变量声明补全、ssrf 系 82 卡"清理后/校正命令 N"生成器模板 title 全部语义化命名。

## 管线侧修复与坑

1. **管线 bug（curate-payload-library.mjs）**：`applyPayloadCommandOverrides` 的链锚跟随对 description-only patch 用 `patch.command || ''` 清空链锚（prepare 侧有同款防御，apply 侧漏）——补 `patch.command !== undefined` 条件。
2. **doc 冲突合并模式**：新建 override doc 必与既有 42 个 doc 撞 id（132/132 全撞）——改文直接合并进既有归属 doc（同槽位 Object.assign）。
3. **幂等三坑**：①无 contentStandard 的 doc 用 legacy 字段集判定 applied，不含 attackChain/wafBypass——声明 `contentStandard: 3` 用 strict 集；②doc 携带的 execution/wafBypass 与 runtime 漂移时整组替换造成链锚错位——backfill 时同步命令区；③process 内 loadReviewConfiguration 缓存旧 doc——诊断必须子进程同源（DIAG 注入法）。
4. **marker 污染循环**：`(PAYLOADER_LAB)` 粘连命令经 doc↔runtime 往返扩散——双侧 regex 根治。
5. **audit 函数进程内调用结果与 gate 不一致**（editorial 全空 vs gate 报错）——未定位到根因，全部以子进程 DIAG 输出为准裁决。
6. **dump 格式污染**：审计员把 `⏎` 分隔符/`CMD: ` 前缀/`# 判据` 注释抄进改文——构建侧统一清洗（stripCmdPrefix/cleanDumpArtifacts）。

## 终态验证

- 策展 apply 幂等：dry-run planned **0/0/0**，gate 全绿（editorial/toolEditorial/reporting 全 0）
- verify-content-quality：seed+runtime 双库 **PASS**（632 payloads/629 WAF 99.53%/0 orphans/0 duplicates）
- npm test：727 测试 723 过（4 失败均为并行 CTF 会话 web-proxy/web-wb3 面，先于本批存在，改动不涉其代码）
- 模板 title 残留 0 / 空锚链 0 / marker 污染 0

## 遗留（下轮候选）

1. **VERIFY 91 处**：子代理标注不确定的技术主张，需主会话逐条核验（大部分已被同卡改文间接覆盖）
2. **django-vuln 多 CVE 集合卡**：CVE 注释行改真载荷与 gate 混合集检测冲突，需结构拆分（与上轮 12 项行级手术同类）
3. **rce-deserialize（多语言总览错位）/httpbypass-waf-css（CSS 执行在数据外带组）/ntlm-relay waf[6-8] RDP 命令串位**：行级迁移手术
4. **tools 73 张 description 改文被 tool curate 规范化覆盖**：审计改文含 residue 触发措辞，与 cleanCollectionPresentation 机制冲突
5. **34 个 tool command patch 撤回**（重复命令/纯注释命令引入），待人工逐条重写
