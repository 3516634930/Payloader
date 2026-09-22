# 计划：编解码工作台受众分流与 CTF 解题独立视图

日期：2026-09-22 ｜ 状态：实施中 ｜ 规模：重档（≥5 文件，前端跨模块）

## 背景与问题

编解码工作台（EncodingTools，Header 按钮弹出的 modal）混装"渗透 payload 处理"与"CTF 解题"两类场景：渗透用户翻工具被 CTF 杂项干扰，CTF 用户解题被工程向操作淹没。

## 目标（验收口径）

1. 顶部导航 tab 切换器支持三态：Payload / 工具命令 / CTF 解题；`ActiveTab` 增加 `'ctf'`；移动端同步不溢出。
2. 操作元数据加受众标记 `ctf | pentest | both`：编解码视图渲染 pentest+both，CTF 视图渲染 ctf+both。
3. 分流记账守恒：**两视图操作数之和 = ctf + both + pentest = operations 总数（154），无遗漏无重复**。
4. CTF 视图信息架构按解题流程：智能识别（smart-decode 置顶大输入框）→ 古典密码 → 现代密码攻击 → 编码与取证杂项；沿用批次 A 候选评分展示 + 导航分组二级菜单规则（optgroup 分组）。
5. smart-decode 已有 flag 格式识别逻辑以徽标形式在解码结果区展示（只展示，不新增算法）。
6. 编解码视图瘦身后空分类自动移除（预期仅 `smart` 分类被搬空）。
7. 两视图共用批次 G 引擎与同一工作台组件，同一操作零重复实现。
8. 门禁零回归：verify:codec / test / lint / typecheck / gap-test；浏览器实测桌面+移动端。

## 分流清单（与需求清单一一对应，无语义改动）

- **ctf（67）**：smart-decode；古典 24（vigenere…adfgvx、enigma、frequency-analysis）；ROT/XOR 破译 5（rot-bruteforce、rot8000、xor-bruteforce、xor-known-plaintext、magic-xor-helper）；杂项文本 5（brainfuck、ook、keyboard-shift、reverse-text、zero-width）；冷门取证 19（z-base-32、base45、base91、base32768、bech32、base58check、xxencode、uuencode、yenc、bubble-babble、a1z26、morse、nato-phonetic、baudot、bcd、gray-code、dna-code、gsm7、sms-pdu）；现代密码攻击 13（rsa-raw、rabin-raw、rsa-helper、coppersmith、discrete-log-helper、mt19937-helper、lcg-helper、lfsr-helper、hash-length-extension-helper、crypto-attack-helper、bip39-seed、pgp-parse、cbc-padding-demo）
- **both（28）**：base64、base64url、base32、base36、base62、base58、hex、binary、octal-codes、ascii-codes、ascii85、url-component、url-form、unicode-escape、js-string、html-entity、xml-entity、utf7、c-string、json-string、unix-time、quoted-printable、utf16-bytes、gzip、deflate、data-url、xor、rot
- **pentest（59）**：其余全部（JWT 族、hash/hmac/hash-identify、AES/DES/RC4/ChaCha/TEA/sm4 全系、OpenSSL、JSFuck/aaencode/jjencode、CBOR/MessagePack/Protobuf/BSON、PEM/ASN.1/JWK/SSH、Punycode、Basic Auth/QueryString、Fernet/HOTP/TOTP/otpauth、rsa-oaep、signature-nonce-helper）

CTF 视图四段内 both 操作的落位（IA 设计决策，受众不变）：rot→古典密码，xor→现代密码攻击，其余 26 个 both 编码归入"编码与取证杂项"并按 Base 家族/取证电报/文本隐写/Web 封装四个 optgroup 二级分组。

## 实施步骤

1. **引擎层（纯新增）**：`src/utils/codec/audience.ts` — `Audience` 类型 + `operationAudience: Record<OperationId, Audience>`（TS 穷尽校验）+ CTF 四段分组结构（含 optgroup 二级）+ 纯函数 `buildPentestGroups()` / `buildCtfGroups()`；`smartDecode.ts` 新增导出 `detectFlagFormats()`（复用既有 flag 前缀清单，只做展示）；`index.ts` 导出。
2. **共用工作台**：EncodingTools.tsx 主体（参数面板/检测条/输入输出/候选列表/测试 API）原样抽取为 `CodecWorkbench.tsx`，props 为 `groups + registerTestApi + focusOperation`；检测条按当前视图可见操作过滤；分组选择器渲染 optgroup 二级菜单。EncodingTools 瘦身为渗透视图包装（`buildPentestGroups()`）。
3. **CTF 视图**：新建 `CtfToolkit.tsx` — 智能识别 hero（大输入框 + 350ms 防抖自动智能解码 + flag 徽标 + 候选列表折叠 + 检测芯片跳转下方工具）+ `CodecWorkbench`（`buildCtfGroups()`）。MainContent 懒加载。
4. **导航接线**：`appContext.ActiveTab += 'ctf'`；Header 三态 tab + ctf 态隐藏 ☰；App 在 ctf 态不渲染 Sidebar/背板；MainContent ctf 分支（搜索态回退 payload 搜索）；i18n 增加 `header.tabCtf`。
5. **响应式**：Header ≤520px 改为搜索整行 + 三 tab 整行；≤360px 收字号；CTF 视图复用 workbench 既有断点。
6. **门禁扩展**：verify-encoding-tools.mjs 增加"受众记账守恒 + 视图集合等式 + 空分类 + flag 徽标"用例；eval/new Function 源码扫描覆盖 CodecWorkbench/CtfToolkit；frontend-contract 的移动端 44px 断言改指 CodecWorkbench。
7. **验证**：串行跑 typecheck → verify:codec → test → lint → `node output/ctf-gap-test/gap-test.mjs`（引擎基线 42/47，5 个 null-sample 占位项按设计必失败，只看无回归）；Playwright 独立浏览器按验收清单走桌面/移动端。

## 风险与边界

- verify:codec 对 EncodingTools.tsx 有 eval/new Function 源码扫描 → 新组件同步纳入扫描。
- 契约测试读 EncodingTools.tsx 样式块 → 断言文件随重构同步更新（测试跟代码走）。
- 智能解码检测芯片可能指向非本视图操作（如 pentest 视图里的 smart-decode）→ 检测条按视图可见集合过滤。
- 不新增依赖、不改引擎既有函数行为（全部纯新增导出）。
