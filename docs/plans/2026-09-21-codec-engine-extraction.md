# 计划：编解码引擎从 EncodingTools.tsx 剥离到 src/utils/codec/

- 日期：2026-09-21
- 需求：解码引擎（154 操作元数据、transform、参数处理、智能解码）从组件剥离为可复用共享模块，为批次 H「两个视图共用一个引擎」做准备；行为零变化。
- 分级：重档（跨模块重构、共享引擎层、强回归门禁）

## 基线（audit-workspace/codec-baseline/）

| 门禁 | 基线 |
|---|---|
| verify:codec | `Verified 123 EncodingTools regression checks.` exit=0 |
| npm test | 177 pass / 0 fail, exit=0 |
| typecheck | exit=0 无输出 |
| lint | 0 errors / 1 warning（Sidebar.tsx 既有 exhaustive-deps）, exit=0 |
| gap-test | 42/47（基线即含 5 个预期缺口，含「Enigma 带配置」已知错误）, exit=0 |

## 现状地图（src/components/EncodingTools.tsx, 18886 行）

- L1-3 imports（react/appContext）；L17459-18569 React 组件（含 style jsx）；L18571-18884 顶层 `async function transform()`；L18886 `export default EncodingTools`。
- 其余 L5-17458 全为纯引擎逻辑。三个门禁脚本用 `ts.transpileModule` + vm 沙箱直接加载组件文件文本，末尾追加 `module.exports = { transform, defaultParams, detectInput, ... }`。
- frontend-contract.test.mjs 检查组件内 `@media (max-width: 680px)` 移动端 CSS 与 App.tsx lazy import 路径 —— 组件留在原文件即零影响。

## 分块方案（连续行区间机械切分，函数体字节级不变）

| 新文件 | 源区间 | 内容 |
|---|---|---|
| types.ts | 5-191 | 类型/接口/categories |
| operations.ts | 192-1382 | operations 元数据 + defaultParams |
| alphabets.ts | 1383-1511 | 编码表常量 + Set |
| bases.ts | 1512-2269 | 字节工具 + Base 全家 + bech32 + uuencode |
| sandbox.ts | 2270-3935 | sx* JS 解释器 + JSFuck/aaencode/jjencode |
| textEncodings.ts | 3936-4960 | HTML/XML/Unicode/转义/二进制文本/Morse/GSM7 等 + CRC/MD5/MD4 |
| crypto.ts | 4961-6929 | 摘要/HMAC/AES/OpenSSL/CryptoJS/CTF 字段推理/noble/SM4/RC4/TEA |
| classical.ts | 6930-7562 | 古典密码全家 + XOR 家族 |
| tokens.ts | 7563-8129 | JWT/JWK/JWE/Fernet/OTP |
| binaryFormats.ts | 8130-9007 | CBOR/MsgPack/Protobuf/BSON/ASN.1/SSH/PEM/Punycode/SMS PDU |
| rsa.ts | 9008-12429 | RSA 推理/解析/攻击 + bigint 数学 |
| attacks.ts | 12430-12984 | LCG/LFSR/长度扩展/Brainfuck/cryptoAttackHelper |
| smartBase.ts | 12985-13453 | query/compress + smart 评分 + smart symmetric/XOR |
| smartClassical.ts | 13454-13773 | classical smart（结构化/带 key/bruteforce） |
| prng.ts | 13774-15215 | MT19937 + 签名 nonce 重用 + DLP |
| smartKeyless.ts | 15216-16493 | smart 辅助 + classical ngram keyless break |
| pgp.ts | 16494-16840 | PGP/OAEP/Coppersmith/CBC demo |
| smartDecode.ts | 16841-17458 | smartDecode + detectInput |
| transform.ts | 18571-18884 | transform switch 分发器 |
| index.ts | 手写 | 「本地绑定再导出」形式汇总 |

组件文件保留：3 行 import + 组件段（17459-18569）+ `import {...} from '../utils/codec'` + export default。目标 ~1200 行。

## 门禁适配（断言零改动，加载入口跟代码走）

- scripts/verify-encoding-tools.mjs 与 output/ctf-gap-test/gap-test.mjs：
  - 编译入口 `src/components/EncodingTools.tsx` → `src/utils/codec/index.ts`；
  - context.require 增加 shim：相对 `./x` 先查 codec 目录预转译缓存，未命中回落 nodeRequire；
  - 追加的 `module.exports = {...}` 语句原样（index.ts 本地绑定再导出，保证标识符可解析）；
  - eval/new Function 黑名单检查对象扩大为「codec 全部 .ts + 组件 tsx」源文本拼接（检查语义随代码移动扩大，文案不变）；
  - 污染探针 realm 机制不变。
- 导出面：verify 需 { transform, defaultParams, detectInput, inferRsaParamsFromText, inferDlpFromText, factorSmallRsaModulus, operations, gsm7DefaultAlphabet, gsm7ExtensionAlphabet }；gap-test 需前 4 项；其余导出面以组件 tsc 报错驱动补齐。

## 执行步骤

1. Node 一次性脚本按区间切 19 个引擎文件到 src/utils/codec/（脚本放 audit-workspace/codec-extract/，不入提交）。
2. tsc 报错驱动：解析 `Cannot find name` → 按符号→定义文件映射自动生成域间 import；`Duplicate identifier` 逐个处置。
3. import 图无环校验脚本（值依赖必须单向；类型环用 `import type`）。
4. 手写 index.ts（本地绑定再导出）。
5. 组件瘦身：保留视图，import codec。
6. 适配两个门禁脚本的加载入口。
7. 全量回归对照基线；超差即回滚修复。
8. 浏览器手测代表性操作（smart-decode/base64/AES/JWT/摩斯/Enigma/RSA）+ devWindow.__PAYLOADER_CODEC_TEST_API 抽查。
9. agent-code-reviewer 独立复核（不带实现上下文）。

## 风险与对策

- 循环依赖 → 步骤 3 显式校验；runtime 表现为 TDZ/undefined，verify 首跑即暴露。
- lint 新增 warning → 基线 1 warning 不得增加。
- verify vm realm 依赖 globals（Blob/CompressionStream 等）→ context.global = context 已传播，子模块同享。
- 动态 import('crypto-js')/import('protobufjs') → require shim 回落 nodeRequire，与现状同路径。
- 超长行（CLASSICAL_NGRAM_TABLE_B64 等）→ 按行切分无碍。

## 踩坑记录（随本次改动入库）

- **verify:codec 的「古典密码无密钥破译」断言内含 `CLASSICAL_BREAK_TOTAL_BUDGET_MS=15000` 墙钟预算参与控制流** → 回归时必须串行跑、机器高负载下 hill-climb 提前截止会偶发挂「无密钥还原失败」（症状：同一代码多次运行结果波动；与代码改动无关）。任何并行跑门禁的做法都可能触发。
- **TypeScript 对拆分后模块中的递归 const 箭头函数（如 decodeUnixTime）报 TS7023** → 在单文件脚本式作用域不报、拆模块后推断循环无法锚定；修法是给函数补显式返回类型注解（运行时零影响）。

## 验收（全部对照基线零差异）

1. verify:codec 123 项全过，输出行一致
2. npm test 177/177
3. typecheck exit=0
4. lint 0 errors / 1 warning（不新增）
5. gap-test 42/47 且逐项结果与基线一致
6. 组件文件 ≤5000 行（预期 ~1200）
7. UI 手测代表性操作结果与重构前一致、console 无新错误
