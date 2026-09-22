# 计划：古典密码无密钥自动破译（6 种）接入智能解码回退链

日期：2026-09-21 ｜ 状态：执行中 ｜ 风险档：重（新算法功能 + 性能红线）

## 需求

为 Playfair、Bifid、Trifid、ADFGX、ADFGVX、列换位 6 种密码增加无密钥自动破译，接入智能解码"无命中"回退链。方向：密钥扰动 + 英文 n-gram 评分的爬山/模拟退火；长文本统计可解、短文本允许失败；单个样本秒级、不卡 UI。

## 调研结论（停止判据①②已满足）

**本地**：
- 带密钥解密可复用（最终输出用它们重解，保证与带密钥工具一致）：
  `playfairTransform(v,secret,decode)`、`columnarDecode(v,secret)`、`bifidTransform(v,secret,period,decode)`、`trifidTransform(v,secret,period,decode)`、`adfgxTransform(v,secret,keyword2,decode,variant)`（EncodingTools.tsx:6972/7162/7250/7289/7382）。
- 密钥语义可表达任意排列：`keyedSquare`/`keyedTrifidAlphabet`/`keyedAlphabet` = secret+base 去重；`columnOrder(secret)` = 关键词排序秩 → 搜索空间的任意状态都能编码回密钥字符串。
- 既有爬山（`trySmartSubstitutionBruteforce` 贪心交换）与 Vigenère（IC+卡方）可参考；`smartTextScore` 是启发式，强度不足以支撑退火 → 需要真 n-gram 评分表。
- 回退链插入点：`smartDecode` 末尾无命中返回前（~15962）。smartDecode 是 async，可让出主线程。
- 外部：爬山/退火 + 英文 n-gram 适应度是公认方法（Uni Kassel《A Methodology for the Cryptanalysis of Classical Ciphers》2018；ADFGVX ciphertext-only SA 论文 2024；practicalcryptography.com 同法）。适配度业界用 quadgram；本项目用**全量 26³ trigram 表**（17,576 项量化后 ~24KB base64，可全表内嵌），语料取 Gutenberg 公版书。

## 方案

### 1. 英文适应度
- 离线：`scripts/build-trigram-table.cjs` 拉 3 本公版书（~1.7MB）→ 计算 trigram 计数 → 量化 byte → base64。
- 运行时：`TRIGRAM_TABLE_B64` 常量惰性解码为 Float32Array LUT（log10 概率），评分 = 字母流 trigram 求和（跳过非字母）。

### 2. 搜索驱动（时间盒 + 确定性）
- `mulberry32` 种子 PRNG；种子 = 密文 FNV-1a 哈希 → 同输入同结果（回归可复现，防 flaky）。
- 模拟退火：重启制，温度按当前得分方差初始化、几何降温；每轮 restart 间 `await setTimeout(0)` 让出主线程。
- 总预算 `CLASSICAL_BREAK_TOTAL_BUDGET_MS ≈ 3500`，逐 cipher 切片（columnar 500 / playfair 800 / bifid 900 / trifid 800 / adfgx 1100 / adfgvx 1100），deadline 检查在 restart 边界。
- 高置信早退：best 每字母 trigram 均值 ≥ 阈值或含 flag 形 → 立即返回。

### 3. 各密码攻击（快原语在 Uint8Array 上，最终展示用带密钥函数重解）
| 密码 | 状态空间 | 形状门（快速失败） |
|---|---|---|
| columnar | 列数 k=2..16 × k-排列（swap 扰动） | 纯字母 ≥80，非已解英文 |
| playfair | 25 字母方阵排列 SA | 字母数偶数且 ≥160 |
| bifid | period 2..16 × 25 排列 | 字母 ≥140 |
| trifid | period 3..15 × 27 排列（A-Z+.) | 字母 ≥140 |
| adfgx | 列换位排列 + 25 方阵联合 SA | 仅 ADFGX 符号，pair 数 ≥120 |
| adfgvx | 列换位排列 + 36 方阵联合 SA | 仅 ADFGVX 符号，pair 数 ≥120 |
- 快原语逐字复刻对应带密钥函数数学（列长不齐逻辑一致），搜索热循环不走字符串正则。
- 采纳门槛：per-letter 评分 ≥ 阈值（经验校准）或 flag 形；**展示文本用既有带密钥函数 + 恢复的密钥重解**。
- 前置闸：`looksLikeResolvedSmartDecodeText(input)` 为真直接跳过（纯英文输入不烧预算）。

### 4. 接线
`smartDecode` 无命中收口前：`const keyless = await trySmartClassicalKeylessBreak(current); if (keyless) return keyless;` 输出格式与其他 trySmart* 一致（"智能识别: ..." + JSON：method/key/period/keyword2/score/decrypted/note）。

### 5. 回归（verify-encoding-tools.mjs 新块）
- 6 正向：固定长英文明文（含 flag{...}，240-400 字母）+ 固定密钥 → `transform(op,'encode',…)` 生成密文 → `transform('smart-decode',…)` 断言还原含 flag。
- 2 负向：短文本（<门限）不烧穿预算、不产伪 flag；总耗时断言（单样本 <15s 上限，防挂死）。
- 稳定性：种子确定性；开发期每用例重复跑 ≥3 次确认稳定后才定稿。

## 性能预算
- 单样本总预算 3.5s（6 形状互斥或门控分流，最坏纯字母触发 4 个攻击 ~3s）。
- 让出粒度：每个 restart chunk 后（~30-80ms 同步段），UI 不冻结。
- verify 全块预算：7 用例 × <10s 实测 ≈ <40s。

## 验收对照
1. 每种密码智能解码路径回归 ✅（上节）
2. verify:codec / npm test / typecheck / lint 全绿 ✅（收尾跑）
3. 附加（角色纪律）：agent-code-reviewer 独立复核 + 浏览器实景粘贴 Playfair/ADFGVX 密文破译 + self-verify-dev 自检。

## 已知风险
- ADFGVX 联合退火成功率对文本长度敏感 → 测试样本放宽到 300+ 字母；若不稳，先调 restart 数与降温参数，必要时加"先方阵后列序"两阶段策略。
- trigram 表质量取决于语料规模（~1.5M trigram 样本，平滑后可用）；弱表症状 = 收敛慢/误采，对策 = 换更大语料重建表。
