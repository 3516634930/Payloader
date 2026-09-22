# 批次 K：杂项取证域 + 中文密码组 实施计划

**Goal**：①杂项（Misc）域落地文件分析工作区（拖拽/选择 → 自动探测 → 按需分析，全浏览器本地）；②密码与编码域新增「中文密码」工具组（6 个操作进 CodecWorkbench 引擎）。
**Architecture**：中文密码 = 纯函数模块 `chineseCiphers.ts` 挂进 codec 引擎注册表（types/operations/transform/audience 五处联动）；文件域 = 纯函数探测引擎 `fileDetect.ts`/`fileTools.ts` + React 工作区组件替换 misc 占位页，框架层（CtfToolkit）传递 pendingFile。
**Tech Stack**：React 19 + Mantine 9 + TypeScript；AES-CBC 用 crypto-js（与 crypto.ts 一致）；deflate 用现有 `compressText/decompressText`（smartBase.ts，CompressionStream）；文件读取 `file.arrayBuffer()`；主线程 64KB 无需 Worker（调研：20MB 熵+strings <200ms）。

## 调研结论（决策依据，已验证）

- 佛曰 = UTF-16LE + AES-256-CBC(KEY=`XDXDtudou@KeyFansClub^_^Encode!!`, IV=`Potato@Key@_@=_=`) + 128字码表+12标记字；官方向量×2 已实测（audit-workspace/research-chinese-ciphers.md §1）
- 如是我闻 V2 = 256字码表 + 同 AES + **zip(LZMA)/7z 容器**（TudouSharp Compress.cs 用 CompressionType.LZMA）→ 浏览器端无 LZMA，**decode 降级**：码表+AES(NoPadding)+容器浅解析（store 条目直取；LZMA 条目给提示）；**encode 不做**（产 LZMA 容器无法互通保证）
- 熊曰 = deflate-raw + basE91(13/14bit) + 91字字典 + 逆序，前缀`熊曰：呋`；样本×2 实测（§3）；非千字文（任务书预设已证伪）
- 百家姓 = 73 姓↔base64 字符表；decode 双流派（先 base64 后替换 / 直接替换），encode 走 base64 流派（§4）
- 六十四卦 = 流派A 卦名(base64 字典, 官方向量) + 流派B U+4DC0 卦符(6bit 索引)；decode 按外观自动分流（§5）
- 天干地支 = 60 甲子 base-60 BigInt；官方向量实测（§6）
- pcmoe 新佛曰闭源（服务端已亡）→ 仅 smartDecode 输出提示，不做操作
- verify:codec vm 沙箱已注入 crypto/Blob/CompressionStream/DecompressionStream（scripts/verify-encoding-tools.mjs:23-44），回归用手动 `await run('描述', fn)` 块
- 守恒数字：scripts/verify-encoding-tools.mjs:2501 `ctf=67/both=28/pentest=59/total=154` → 新增 6 个 ctf 操作后改 `73/28/59/160`
- 熊曰压缩复用 smartBase.ts:59-71 `compressText/decompressText`（base64 中转），不自实现 inflate

## 文件清单

| 动作 | 路径 | 职责 |
|---|---|---|
| Create | `src/utils/codec/chineseCiphers.ts` | 6 个中文密码编解码纯函数 + 映射表常量 |
| Create | `src/utils/ctf/fileDetect.ts` | 魔数表/熵/strings/可疑扫描/hexdump/PNG/ZIP 探测纯函数 |
| Create | `src/components/ctf/FileForensicsWorkspace.tsx` | 杂项域文件分析工作区组件 |
| Create | `tests/file-forensics.test.mjs` | 文件引擎测试（内联 transpile 加载器，自造二进制） |
| Modify | `src/utils/codec/types.ts` | OperationId +6（`buddha`,`buddha-v2`,`bear-says`,`baijiaxing`,`hexagram`,`sexagesimal`）|
| Modify | `src/utils/codec/operations.ts` | 条目 +6 + defaultParams（hexagram 复用 `variant`）|
| Modify | `src/utils/codec/transform.ts` | case +6 |
| Modify | `src/utils/codec/audience.ts` | operationAudience +6（全 ctf）+ classical 段 subgroup「中文密码」|
| Modify | `src/utils/codec/smartDecode.ts` | detectInput 芯片 +6、candidates 4 条前缀直解、pcmoe 新佛曰提示 |
| Modify | `src/components/CodecWorkbench.tsx` | variant select 加 hexagram 分支（卦名/卦符）|
| Modify | `src/utils/ctf/modules.ts` | misc Workspace → FileForensicsWorkspace，删 note |
| Modify | `src/components/CtfToolkit.tsx` | pendingFile state + hidden input + 外层 drop 接管 + 传参 |
| Modify | `src/components/ctf/CtfHero.tsx` | 文件按钮文案上线版（去"后续版本上线"措辞）|
| Modify | `scripts/verify-encoding-tools.mjs` | 守恒数字 73/160 + 中文密码回归 run 块 |
| Modify | `package.json` scripts | test 通配已含 `tests/*.test.mjs`，无需改（确认即可）|

## 任务分解（依赖序，主线亲自执行保一致性）

### Task 1: chineseCiphers.ts（引擎纯函数）
**Files**: Create `src/utils/codec/chineseCiphers.ts`
- 常量：FO_KEY/FO_IV、TUDOU[128]、BYTEMARK[12]、RSWW[256]、XIONG[91]、BJX[73 对]、EIGHT_MAP[64]、STEM/BRANCH→GZ60[60]（全部照调研报告原文，简繁原样）
- AES：`CryptoJS.AES.encrypt/decrypt`（CBC；V1 默认 PKCS7；V2 `padding: CryptoJS.pad.NoPadding`）
- utf16le：手写 encode（charCodeAt 双字节小端，含 surrogate），decode 用 `TextDecoder('utf-16le')`
- 导出：`buddhaEncode/buddhaDecode`（支持佛曰/魔曰前缀，魔曰=字节反转）、`buddhaV2Decode`（容器浅解析：7z magic `377ABCAF271C` 走 kHeader/Copy-or-LZMA 分支；zip 走 LFH method 0 直取；LZMA 输出降级提示）、`bearEncode/bearDecode`（复用 compressText/decompressText('deflate-raw') + 自写 basE91 13/14bit，decode 用 `b += v * 2**n` 浮点）、`baijiaxingEncode(流派B)/baijiaxingDecode(双路)`、`hexagramEncode/Decode`（decode 外观分流）、`sexagesimalEncode/Decode`（BigInt divmod 60）
- 错误文案中文、说明"发生了什么+为什么"（前端文案纪律）
- **验证**：`npm run typecheck` 零错误

### Task 2: 引擎注册五处联动
**Files**: types.ts / operations.ts / transform.ts / audience.ts / CodecWorkbench.tsx
- operations 条目：buddha（encode+decode）、buddha-v2（decode-only）、bear-says（encode+decode）、baijiaxing（encode+decode）、hexagram（params:['variant']）、sexagesimal（encode+decode）——全部 category: 'classical'？不：categories 七分类无 classical——查现值：古典密码操作 category 用什么（vigenere 的 category 值，执行时 grep 对齐）
- audience：全 'ctf'；classical 段 subgroups 追加 `{ name:{zh:'中文密码',en:'Chinese Ciphers'}, ids:[6个] }`
- CodecWorkbench variant select：hexagram 分支选项 卦名/卦符（默认卦名）
- **验证**：`npm run typecheck`；临时 node 脚本 round-trip 6 操作（报告样本对）

### Task 3: 智能识别接入
**Files**: smartDecode.ts
- detectInput：前缀类（佛曰/魔曰、如是我闻、熊曰）priority 110；内容类（百家姓密度≥0.9、卦符 U+4DC0 密度≥0.8、卦名贪婪全覆盖、干支二字组∈GZ60）priority 90
- smartDecode candidates：4 条前缀密文 tryDecode 直解（评分采纳制不变）
- 输出提示：`/^新佛曰[:：]/` → 追加 pcmoe 闭源说明行
- 确认佛曰前缀不被噪声剥离正则吃掉（剥离词表无"佛曰"，已核实）
- **验证**：临时脚本：佛曰密文/熊曰密文/百家姓/卦/干支 → detectInput 命中 + smartDecode 解出

### Task 4: verify 回归 + 守恒数字
**Files**: scripts/verify-encoding-tools.mjs
- 2501 行 `67→73`、`154→160`
- 新 run 块「Chinese ciphers follow official test vectors and round-trip」：佛曰向量×2 decode + encode 往返、魔曰、熊曰向量×2 + 往返、百家姓 A/B 样本、六十四卦官方向量 + 卦符 round-trip、天干地支官方向量、如是我闻样本→容器判定非抛、detectInput 断言×5
- **验证**：`npm run verify:codec` 全绿（最重门禁先跑）

### Task 5: fileDetect.ts + fileTools.ts（文件引擎纯函数）
**Files**: Create `src/utils/ctf/fileDetect.ts`（引擎函数 + 工具合一，职责内聚）
- `MAGIC_TABLE`：32 条（调研报告 JS 常量：PNG/JPEG/GIF×2/BMP/WEBP/ICO/ZIP+JAR/DOCX/XLSX/APK/EPUB/RAR4/RAR5/7z/GZ/TAR/BZ2/XZ/ZSTD/PDF/PCAP/PCAPNG/ELF/MZ/Mach-O×2/SWF/MP4/OGG/WAV/FLAC/SQLITE/WASM）
- `detectFileType(bytes)` → 命中数组；`shannonEntropy(bytes)`；`extractStrings(bytes,{minLength:4,limit})`（ASCII 状态机 + UTF-16LE）；`scanSuspicious(text)`（flag 正则清单/base64 `[A-Za-z0-9+/]{20,}={0,2}`/CTF 关键词/`==` 结尾）；`hexdumpPreview(bytes,{offset,length})`
- PNG：`parsePngIhdr`（宽@16/高@20 u32BE、CRC@29、范围 12-29）+ `crc32` 表驱动 + `fixPngDimensions(bytes)`（分阶段枚举：仅宽≤8192 → 仅高≤8192 → 双向≤1024；每 4096 次 `await yieldToUi()`）
- ZIP：`detectZipEncryption(bytes)`（LFH@6-7 / CD@8-9 bit0 比对：全 0=正常、全 1=真加密或伪加密、不一致=伪加密特征）+ `fixZipFlags(bytes)`（bit0 清零）
- 零宽：`extractZeroWidthFromBytes(bytes)` → 文本解码 → 复用 codec `zeroWidthDecode` + 零宽字符计数
- `MAX_FILE_BYTES = 20 * 1024 * 1024` 常量导出
- **验证**：`npm run typecheck`

### Task 6: FileForensicsWorkspace.tsx + 框架接线
**Files**: Create `src/components/ctf/FileForensicsWorkspace.tsx`；Modify modules.ts / CtfToolkit.tsx / CtfHero.tsx
- 组件：空态拖拽区（虚线框、点击/Enter/Space 打开选择器、aria-label）→ 概要卡（文件名/大小/类型 Badge/扩展名一致性/熵值+判定文案）→ 清单（识别结果、strings ≤200 条、可疑内容含 flag 徽标、hexdump 512B）→ 工具卡按探测类型显隐（PNG 修复带下载按钮、ZIP 伪加密修复带下载、图片预览↔Base64 复用 codec base64、零宽提取）
- Mantine：Paper/Badge/Code/ScrollArea/Alert/Button/Stack/Group/Text/Divider/Tooltip；样式走 `var(--border-color)` 等 CSS 变量 + 组件内 `<style>`（跟随 CtfToolkit 惯例）；文案内联三元（跟随 ctf 组件惯例，不走 t()）
- 20MB 门禁：超限 `notifications.show` 警告色提示并拒绝；空文件允许并提示
- modules.ts：misc Workspace 替换，删 note
- CtfToolkit：`pendingFile` state `{file, token}` + hidden `<input type="file">` + 外层 `onDragOver`/`onDrop`（`e.dataTransfer.types.includes('Files')` 才接管，防文本拖拽误吞）→ 切 misc 域；`CtfWorkspaceProps` 增 `pendingFile?`；hero 按钮点击 → input.click()
- CtfHero：按钮 title/文案更新为上线版（"选择文件开始分析"）
- **验证**：`npm run typecheck` + `npm run build`

### Task 7: tests/file-forensics.test.mjs
**Files**: Create `tests/file-forensics.test.mjs`
- 内联 transpile 加载器（仿 verify:23-80，载 src/utils/ctf/fileDetect.ts）
- 自造二进制：手工拼 PNG（CRC 正确）→ 校验过；改宽 → 校验败 + fixPngDimensions 还原原宽；手工拼 ZIP（LFH+CD+EOCD，bit0=1）→ 伪加密命中 + 修复后 0；藏 `flag{forensics_test}` 文本 → strings+scanSuspicious 命中；PNG/JPEG/ZIP/PDF/PCAP/ELF/MZ 头 → 魔数正确；全 0/随机/文本 → 熵三分；零宽文本嵌入 → 提取解出；hexdump 格式
- **验证**：`node --test tests/file-forensics.test.mjs` 全绿

### Task 8: 四门禁 + 浏览器实测
- `npm run verify:codec` → `npm test` → `npm run typecheck` → `npm run lint`（串行）
- Playwright MCP（独立实例）：dev server 起后按用户旅程测——①拖 PNG/ZIP/藏 flag 文件 → 清单正确 flag 亮徽标；②与佛论禅密文粘贴 hero → 自动解出；③中文密码组在密码域 classical 段可见、6 操作可用；④防呆：>20MB 假文件（BigInt 稀疏构造）、空文件、拖文本、连点、刷新、直达深链、超长文件名；⑤移动端视口 375px：拖拽退化按钮可用；console/network 干净（无外发请求=不上传验证）
- 判据：主流程无阻塞 + P0/P1 必修 + 未测部分如实标注

### Task 9: 独立复核 + 自检 + 交付
- agent-code-reviewer（不带实现上下文，quality-code-review 六维）→ P0/P1 必修
- self-verify-dev 八门禁
- 交付汇报（dev-workflow 格式 + 前端一致性声明）

## 验收标准（AC）

| AC | 内容 | 证据 |
|---|---|---|
| AC-1 | 四门禁全绿 | Task 8 四命令输出 |
| AC-2 | 自造测试文件探测结论正确 | tests/file-forensics.test.mjs + 浏览器实测 |
| AC-3 | 佛曰/熊曰 round-trip 对照公开样本 | verify run 块（官方向量） |
| AC-4 | >20MB 拒绝并提示 | 浏览器防呆实测 |
| AC-5 | 移动端文件选择按钮可用 | 375px 视口实测 |
| AC-6 | 与佛论禅密文智能识别自动解出 | smartDecode 临时脚本 + 浏览器实测 |
| AC-7 | 中文密码组 6 操作在密码域可见可用 | 浏览器实测 + verify |
| AC-8 | 受众守恒数字同步（73/28/59/160） | verify:codec 断言 |
| AC-9 | 新操作不进渗透视图 | verify 两视图并集/交集断言（原有） |

## 场景与衍生问题检查（已回应）

- 空文件 → 概要 0 字节+提示，不崩；非文件拖入（文本）→ types 含 Files 才接管；重复拖入 → 替换状态；切域往返 → pendingFile 在框架层，重挂恢复
- 损坏 PNG（仅假头）→ fixPngDimensions 报错文案"未找到 IHDR 或已损坏"；真加密 zip → 提示区分"真加密（有压缩数据加密标志）"与伪加密
- 性能：20MB 主线程 <200ms（调研实测结论）；PNG 爆破分块 yield 防卡 UI
- 安全：只读字节不执行；无网络调用（浏览器实测 network 面板佐证"不上传"）；不引第三方运行时依赖（verify 禁 eval 扫描范围含 codec 目录，chineseCiphers.ts 遵守）
- 幂等/并发：单文件状态替换式，无并发写
- 存量影响：渗透视图零变化（新操作全 ctf，verify 原有并集/交集断言守护）；EncodingTools 不动
- 监控：纯前端静态工具无服务端，无监控需要
- 技术债登记：①如是我闻完整解码需 LZMA wasm（~100-200KB）；②pcmoe 新佛曰闭源不可解——均已在 UI 文案如实降级，进 docs/TECH_DEBT.md

## 已知风险

- CryptoJS AES 的 WordArray 与 Uint8Array 互转边界（现有 crypto.ts:604-612 有先例模式可抄）
- hexagram variant 与 base32 variant 共享 defaultParams.variant 单值（执行时读现值，hexagram encode 对未知值 fallback 'names'；decode 不依赖 variant 自动分流）
- CtfToolkit 外层 onDrop 与 Mantine 组件内部拖拽处理冲突（浏览器实测覆盖）
