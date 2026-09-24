# 技术债账本

偿还触发：①下次改动碰到同一模块顺手偿还；②被绕过 ≥3 次升级优先；③成为 bug/安全根因立即偿还；④里程碑盘点 P0/P1 排下一期。

## 技术债

- [ ] TD-001 | 如是我闻（佛曰 V2）完整解码需 LZMA/LZMA2 解压：当前只支持 zip-store/7z-Copy 条目直取，LZMA 条目输出容器 hex 供本地 7-Zip 接手 | 发现于 2026-09-22 批次 K | 影响 `src/utils/codec/chineseCiphers.ts` buddhaV2Decode | 建议修法：引入 ~100-200KB LZMA wasm（如 lzma-wasm）并走 7z 完整头解析 | P2
- [ ] TD-002 | pcmoe「新佛曰」（新约佛论禅）算法闭源无公开实现，仅做前缀识别与闭源提示，无法解码 | 发现于 2026-09-22 批次 K | 影响 smartDecode pcmoe 提示分支 | 建议修法：等待社区逆向（服务端 bear.php 已随站点下线，预期无解） | P3
- [ ] TD-003 | ZIP 加密标志检测为全文件逐字节扫 PK 签名：压缩数据巧合含 PK\x03\x04/PK\x01\x02 字节串时可误判/误清位（仅 zip 族文件触发，概率低） | 发现于 2026-09-22 批次 K（复核 P3-4）| 影响 `src/utils/ctf/fileDetect.ts` detectZipEncryption/fixZipPseudoEncryption | 建议修法：改为先定位 EOCD 再按中心目录 offset 结构化遍历 | P3
- [ ] TD-004 | pcap 首包记录头被截断时解析得到"健康 0 包"，无损坏/截断提示（中后段截断有提示，首记录缺口） | 发现于 2026-09-22 批次 L（reviewer P2） | 影响 `src/utils/ctf/pcap/parser.ts` 记录循环头部 | 建议修法：循环退出时区分"字节不足一条记录头"分支并输出截断标记 | P2
- [ ] TD-005 | 流重组/body 限量常量（MAX_STREAM_BYTES 等）无直接单测覆盖，仅经组件行为间接触达 | 发现于 2026-09-22 批次 L（reviewer P2） | 影响 `tests/pcap-analysis.test.mjs` | 建议修法：补 2 个构造超限样本的断言（超限截断标记 + 已解析部分可用） | P2
- [ ] TD-006 | 速查工具跳转未命中（id 不在运行库）时静默返回，无用户反馈；契约测试只护种子库，不护线上库漂移 | 发现于 2026-09-22 批次 M（reviewer P2） | 影响 `src/components/ctf/CheatsheetWorkspace.tsx` openEntry | 建议修法：未命中时 notifications 提示"条目不存在，可能已被策展合并"；测试可加可选的运行库对照 | P2
- [ ] TD-007 | handleFileSelected 在 await 读取头部后读取闭包 activeModuleId，极端时序下路由到过期域（理论竞态，实测未复现） | 发现于 2026-09-22 批次 L（reviewer P2） | 影响 `src/components/CtfToolkit.tsx` | 建议修法：路由判定改为读 activeModuleIdRef 或放在 await 之前 | P3
- [ ] TD-008 | TrafficWorkspace 单文件 500+ 行且 pw-* 主题样式在 4 个流量组件中重复定义（代码库既有"样式随组件"惯例的代价） | 发现于 2026-09-22 批次 L（reviewer P2） | 影响 `src/components/ctf/traffic/*.tsx` | 建议修法：下轮 UI 打磨批次提取共享样式模块或迁 Mantine 组件 | P3

## 技术债（批次 O 附带盘点）
- [ ] TD-批次O-1 | verify:codec bifid 无密钥破译块（scripts/verify-encoding-tools.mjs ≈:2294）为模拟退火概率性测试，偶发首跑失败、复跑即绿 | 发现于 2026-09-22 批次 O 全量门禁 | 影响 CI 稳定性（非本批次成因，隔离复现确认） | 建议修法：钉随机种子或降低断言严格度 | 优先级 P2

## 技术债（批次 W 附带盘点）
- [ ] TD-批次W-1 | primaryActionOfOperation 在操作同时缺 decode/encode 两侧时返回 undefined，modern 菜单整栏崩溃（当前 5 个单侧操作均有另一侧，不可达） | 发现于 2026-09-23 批次 W（reviewer P2） | 影响 `src/components/CodecWorkbench.tsx` modern 菜单条目映射 | 建议修法：空数组兜底跳过该条目或在 verify 加 operations 单侧互斥断言 | P2
- [ ] TD-批次W-2 | 三条批次 W 回归只钉纯函数，不钉 UI 接线：回灌调用点换成 stripCandidateSection、modern 条目单方向映射被改回双方向时 verify 依旧全绿（靠浏览器实测兜底） | 发现于 2026-09-23 批次 W（reviewer P2） | 影响 `src/components/CtfToolkit.tsx`/`CodecWorkbench.tsx` 接线 | 建议修法：接线路径补组件级测试或在 __PAYLOADER_CODEC_TEST_API 暴露菜单条目映射断言 | P2
- [ ] TD-批次W-3 | 工作台 run 无 token 防护，连点两个芯片/菜单时慢 transform 后 resolve 会覆盖后点结果（last-resolve-wins，菜单 runAction 既有模式，hero 侧有 runTokenRef 而工作台没有） | 发现于 2026-09-23 批次 W（reviewer P2） | 影响 `src/components/CodecWorkbench.tsx` run/focusOperation | 建议修法：工作台引入与 CtfToolkit 同款 runTokenRef 序号守卫 | P3

## 技术债（批次 U/V/W/X 附带盘点）
- [x] TD-批次UX-1 | CtfHero.tsx 522 行超 400 行阈值（内联 style 约 300 行占六成）；FileForensicsWorkspace.tsx 800 行（改前已 699 超限），本批次 +101 加重 | 发现于 2026-09-23 批次 U/V/W/X（reviewer P2） | 影响 `src/components/ctf/CtfHero.tsx`、`FileForensicsWorkspace.tsx` | 建议修法：抽 `CtfHeroStrip.tsx`（折叠条 + stripStatus）与 `RecommendBar` 组件，内联 CSS 迁独立样式文件，主文件回落约 250 行 | P2 | **清偿 2026-09-24**：F3 迁走 CtfHero 309L CSS（styles/ctf-hero.css）；F4 拆出 `CtfHeroStrip.tsx`（折叠条，6 props 含 heroRef——scrollIntoView 锚点必需），CtfHero 213→183 行；FileForensicsWorkspace 的 ffStyles/CSS 由 F3 迁出。RecommendBar 未单拆（recommendTools 条渲染体量小，暂留）。
- [ ] TD-批次UX-2 | hero 展开状态跨域保留与验收字面有张力：misc 展开后切 web 首屏是完整 hero 而非折叠条（代码注释已声明有意设计——单实例记忆） | 发现于 2026-09-23 批次 U/V/W/X（reviewer P2） | 影响 `src/components/ctf/CtfHero.tsx` expanded state | 建议修法：与产品二选一——验收文档明确"展开状态跨域保留"，或 heroMode 变化时重置 expanded | P3
- [ ] TD-批次UX-3 | recommendTools 强制 missingMessage 导致纯导航条目死配置：exe-constants 的"逆向域暂未打开"永远不会展示（targetModuleId 分支直接切域不读该字段） | 发现于 2026-09-23 批次 U/V/W/X（reviewer P2） | 影响 `src/utils/ctf/recommendTools.ts` ToolAnchor 接口 | 建议修法：missingMessage 改可选，纯导航条目删掉该字段 | P3
- [ ] TD-批次UX-4 | FileForensicsWorkspace loadFile 无 in-flight 防护（既有缺陷非本批引入）：两次快速投递并发加载，后完成者覆盖 state，可能"显示第一个文件、最后投的是第二个" | 发现于 2026-09-23 批次 U/V/W/X（reviewer P2） | 影响 `src/components/ctf/FileForensicsWorkspace.tsx` loadFile | 建议修法：setAnalysis 前用 ref 校验当前 file 是否仍为最新投递 | P2
- [ ] TD-批次UX-5 | onHandOffFile/onSwitchModule 每渲染新建闭包，3 个 keepMounted 面板随框架任意 state 变化 reconcile | 发现于 2026-09-23 批次 U/V/W/X（reviewer P2） | 影响 `src/components/CtfToolkit.tsx` workspaceProps | 建议修法：useCallback 稳定 + React.memo 包 Workspace | P3
- [ ] TD-批次UX-6 | 契约测试 cipher 负向断言窗口偏脆：`id: 'cipher'[\s\S]{0,200}?heroMode` 依赖 cipher→misc.heroMode 实测 347 字符距离（余量约 147），未来 cipher/misc 定义加字段可能误报 | 发现于 2026-09-23 批次 U/V/W/X（reviewer P2） | 影响 `tests/frontend-contract.test.mjs` | 建议修法：改为按对象块解析或缩小匹配窗口 | P3
- [ ] TD-批次UX-7 | PCAP handoff 后 misc 报告保留，重复点击重复 handoff（幂等无害，仅记录） | 发现于 2026-09-23 批次 U/V/W/X（reviewer P2） | 影响 `src/components/ctf/FileForensicsWorkspace.tsx` runToolAnchor | 建议修法：handoff 成功后清空 misc analysis 或接受现状 | P3

## 技术债（批次 MF 附带盘点：misc 域图片取证能力包）
- [ ] TD-批次MF-1 | StringsCard 大文件场景：minLength 切换同步重扫全文件（20MB 上限约 300ms）无 loading 遮罩；过滤已预算 lowercase 但 6 万条仍每次按键全量 includes | 发现于 2026-09-23 批次 MF（reviewer P2，实测无感故记账不修） | 影响 `src/components/ctf/StringsCard.tsx` | 建议修法：minLength 切换走 useDeferredValue 或加 analyzing 复用态；过滤改分片/防抖 | P3
- [ ] TD-批次MF-2 | zTXt/iTXt 解压为整段 inflate（已加 10MB 输入上限拦截解压炸弹巨流），10MB 内高膨胀比压缩流仍可能占内存 | 发现于 2026-09-23 批次 MF（reviewer P2） | 影响 `src/components/ctf/EmbeddedCard.tsx` inflateDeflate | 建议修法：如遇真实题目的超大 zTXt 再改流式截断（DecompressionStream + 读取上限） | P3
- [ ] TD-批次MF-3 | FileForensicsWorkspace.tsx 1051 行仍超 400 行阈值（基线 800 + 内联 CSS 约 550 行为项目既有"样式随组件"模式），本批次已拆出 6 个卡片/helper 组件、净增逻辑有限 | 发现于 2026-09-23 批次 MF | 影响 `src/components/ctf/FileForensicsWorkspace.tsx` | 建议修法：随 TD-批次UX-1 一并做内联 CSS 迁移后回落 | P3
- [ ] TD-批次MF-4 | hexdump 搜索只从当前页向后线性查找，无环形回绕与全部命中列表 | 发现于 2026-09-23 批次 MF（实现取舍） | 影响 `src/components/ctf/HexdumpCard.tsx` | 建议修法：如有需求加"从头搜索"按钮与命中计数 | P3
- [ ] TD-批次RV-1 | pwnTools.parseBadCharSet 单字符 token 的 hex 歧义：输入 `a` 解析为 0x0A 而非字面字符 0x61，想按字面标坏字符的用户会静默标错（注释与行为不一致） | 发现于 2026-09-23 逆向/Pwn 批次（reviewer P2） | 影响 `src/utils/ctf/pwnTools.ts` parseBadCharSet | 建议修法：单字符非成对 hex 场景按字面字节处理或 UI 行内提示两种解释 | P2
- [ ] TD-批次RV-2 | cyclic.ts/pwnTools.ts 的 error/detail 文案仅中文，EN 用户在反查失败/坏字符解析失败时看到中文指导文本 | 发现于 2026-09-23 逆向/Pwn 批次（reviewer P2） | 影响 `src/utils/ctf/cyclic.ts`、`src/utils/ctf/pwnTools.ts` | 建议修法：失败文案改 {zh,en} 结构随 language 渲染 | P3
- [ ] TD-批次RV-3 | parsePayloadBytes escape 通道静默丢弃非转义内容：`A junk B` 产出 [0x41,0x42] 无提示，粘贴带说明文字的 payload 会分析错字节 | 发现于 2026-09-23 逆向/Pwn 批次（reviewer P2） | 影响 `src/utils/ctf/pwnTools.ts` parsePayloadBytes | 建议修法：escape 通道对被忽略的非空白字符计数并提示 | P3
- [ ] TD-批次RV-4 | 可打印 hex 词（如 beef）被强制走 hex 通道，用户想搜子串 beef 得不到结果且无"试试当子串"指引 | 发现于 2026-09-23 逆向/Pwn 批次（reviewer P2） | 影响 `src/utils/ctf/cyclic.ts` findCyclicOffset | 建议修法：not-found 文案加"清除 0x 意图直接输入子串"提示或提供双通道按钮 | P3
- [ ] TD-批次RV-5 | ReverseWorkspace.loadFile 无序号守卫，快速连续加载两个文件时慢读取后完成者覆盖（先 drop A 再选 B 可能显示 A）；pendingFile 重放路径已由 lastTokenRef 挡住 | 发现于 2026-09-23 逆向/Pwn 批次（reviewer P2） | 影响 `src/components/ctf/ReverseWorkspace.tsx` loadFile | 建议修法：loadFile 内引入与 CtfToolkit 同款序号守卫 | P3
- [ ] TD-批次RV-6 | de Bruijn 62 字符表按字典序生成，前 200 万字符几乎全为小写区：含大写/数字的深 offset 崩溃值（周期 4 约 >90 万、周期 8 远超）反查返回 not-found；已知算法限制，UI 文案已提示 | 发现于 2026-09-23 逆向/Pwn 批次（设计取舍） | 影响 `src/utils/ctf/cyclic.ts` CYCLIC_SEARCH_LIMIT | 建议修法：如遇真实题目需求，改为 Lyndon 词数学定位（pwnlib 同款惰性求值）或加小写字母表选项 | P3
- [ ] TD-批次CTX-1 | CodecWorkbench 的 menuDefs 刻意不 useMemo（runAction 需捕获最新输入，既定决策），致 WorkbenchMenuBar 的 memo 在该消费方永不 bail | 发现于 2026-09-23 context 拆分批次（reviewer P2） | 影响 `src/components/CodecWorkbench.tsx:383` | 建议修法：不改（正确性优先于该处 memo 收益）；若未来 menuDefs 稳定化需连带验证 runAction 闭包时效 | P2
- [ ] TD-批次CTX-2 | CodecWorkbench/CtfHero 传给 WorkbenchOutputPanel 的 onUseAsInput/onClear 为内联箭头，该两处 memo 永不生效（无害） | 发现于 2026-09-23 context 拆分批次（reviewer P2） | 影响 `src/components/CodecWorkbench.tsx:835`、`src/components/ctf/CtfHero.tsx` | 建议修法：需要时 useCallback 包裹并依赖 [output] | P2
- [ ] TD-批次CTX-3 | useAppContext 兼容聚合层在 src/ 下已零消费者，纯安全网 | 发现于 2026-09-23 context 拆分批次（reviewer P2） | 影响 `src/appContext.ts:90-100` | 建议修法：迁移彻底稳定后随批删除，避免永久双轨 | P3
- [ ] TD-批次S-1 | setMetadataValue 被 withCacheInvalidation 全量包装：任意 metadata 写（含 version-status/credentials）整体失效 publicDataCache，mutation 结束的二次失效会清掉 bypassCache 刚回填的热缓存（旧版仅 settings 键失效且保持热缓存） | 发现于 2026-09-24 server 模块化批次（reviewer P2，安全方向仅多余重算） | 影响 `server/data-store.mjs` setMetadataValue、`server/store-cache.mjs` | 建议修法：如需找回热缓存语义，withCacheInvalidation 增加"失效后不重建"选项或 setMetadataValue 按键过滤 | P3
- [ ] TD-批次S-2 | S2 拆分时移除了无消费方的死导出 getDbFile（全仓零引用），与"36 导出全保留"字面不符 | 发现于 2026-09-24 server 模块化批次（reviewer 记账） | 影响 `server/data-store.mjs` | 建议修法：无需恢复；如外部脚本出现引用再补 re-export | P3
- [ ] TD-批次S-3 | router pattern 组内 first-match-wins：未来新增形状重叠的 pattern 路由时注册顺序决定 405 判定归属 | 发现于 2026-09-24 server 模块化批次（reviewer P2） | 影响 `server/router.mjs` | 建议修法：已在 router.mjs 头注释警示；新增重叠路由时合并方法集或先专用后宽泛 | P3
- [ ] TD-批次MISC1-1 | magicChain FLAG_LIKE_PATTERN 的 `\{[A-Za-z0-9_]{2,}:` 分支把任意 JSON 判为 flagLike（+1000 分）：url-decode 出 JSON 的浅层分支会同分压过更深的真 flag 链（同分链短者胜） | 发现于 2026-09-24 四引擎批次（reviewer P2） | 影响 `src/utils/codec/magicChain.ts:68` | 建议修法：该分支对冒号后值侧加可读性/长度要求，或确认"JSON 包 flag 值得置顶"为有意设计后关闭 | P2
- [ ] TD-批次MISC1-2 | crc32AttackReport 未知参数键静默丢弃（`lenght=4` 拼写错落默认值）、重复键 last-wins 无提示 | 发现于 2026-09-24 四引擎批次（reviewer P2） | 影响 `src/utils/codec/crc32Attack.ts:256-281` | 建议修法：未知键直接抛中文错误（与"无法解析参数段"同风格） | P2
- [ ] TD-批次MISC1-3 | magicChain tie-break 用无 locale 参数的 localeCompare，跨环境排序理论上可漂移（纯 ASCII 风险极低） | 发现于 2026-09-24 四引擎批次（reviewer P2） | 影响 `src/utils/codec/magicChain.ts:261` | 建议修法：换显式三向比较换完全确定 | P3
- [ ] TD-批次MISC2-1 | 视频容器枚举面空白：MP4 无 box 级枚举（moov/trak/mdat/udta）、AVI 连 RIFF....AVI 魔数都未收录、MKV EBML 头未收录（GIF 路摸底结论） | 发现于 2026-09-24 misc 批（sweep2 #19 附带项） | 影响 `src/utils/ctf/fileDetect.ts`、`embedScan.ts` | 建议修法：AVI 魔数一行补录优先，MP4 box 枚举次之（udta/atmo 注释、mdat 尾附是 CTF 视频隐写高频点） | P2
- [ ] TD-批次MISC2-2 | ZIP 爆破命中后仅 stored 条目出内容预览：deflate 条目无 inflate，命中口令后提示用系统解压工具 | 发现于 2026-09-24 misc 批 | 影响 `src/utils/ctf/zipBrute.ts` | 建议修法：长期接 CompressionStream('deflate-raw') 做本地解压预览 | P3
- [x] TD-审计0924-P2 | yEnc/UU/XX 解码以 UTF-8 输出致二进制载荷静默损坏（≥0x80 字节→U+FFFD） | 2026-09-24 算法审计 | 影响同左 | **清偿 2026-09-24**：alphabets.latin1Decoder 共享，yEnc/UU/XX 三处换用 latin1 输出 | P2
- [x] TD-审计0924-P2 | RSA 行内 c=[a,b] 只解第一块（推理层坍缩数组，parseRsaMessageValues 本身支持列表） | 2026-09-24 算法审计 | 影响同左 | **清偿 2026-09-24**：赋值正则加方括号数字列表分支，c=[..] 全块解密验证通过 | P2
- [x] TD-审计0924-P2 | 自动破译硬上限无提示：Vigenère keyLen≤20、XOR ≤32 且 ≤len/2，超限静默失败/错解 | 2026-09-24 算法审计 | 影响同左 | **清偿 2026-09-24**：两报告输出搜索上限值 + XOR 低 confidence 引导已知明文路径 | P2
- [x] TD-审计0924-P2 | CRC16 实为 MODBUS 变体（"123456789"→4b37 值对）但 UI 只标"CRC16" | 2026-09-24 算法审计 | 影响同左 | **清偿 2026-09-24**：下拉标签改 CRC16/MODBUS | P2
- [ ] TD-审计0924-P3 | 17 项 P3 清单（hex 全角丢弃/QP 截断/Base58 空串/Playfair 退化对/Hill 负 key/八进制丢 8,9/URL 无 %u/低指数根边界/rho~2^40/Base32 尾位/LCG 4 输出伪因子/p−1 双光滑/bytesFromTextOrHex/bech32 限长/Wiener 双实现/bigintToBytes(0) 等） | 2026-09-24 算法审计 | 详见 docs/research/algo-correctness-audit-2026-09-24.md | 按报告逐项 | P3
- [ ] TD-批次MISC2-3 | ZipBruteCard 爆破任务无 abort：换文件 remount 后旧任务跑满剩余预算（最长 60s），新旧任务并行浪费算力 | 2026-09-24 misc 批（reviewer P3） | `src/components/ctf/ZipBruteCard.tsx:71-109` | 修法：引擎 options 加 AbortSignal 或组件侧 epoch 计数丢弃过期进度 | P3
- [ ] TD-批次MISC2-4 | mp3 仅识别 ID3 头，裸 MPEG 帧同步（0xFF Ex）不挂音频卡；帧同步魔数短误报率高 | 2026-09-24 misc 批（reviewer P3） | `src/utils/ctf/fileDetect.ts` | 修法：需连续多帧同步确认，暂不硬补 | P3
- [ ] TD-批次MISC2-5 | AudioStegoCard 语言切换后 failed 文案语言陈旧（exhaustive-deps disable 的低频路径） | 2026-09-24 misc 批（reviewer P3） | `src/components/ctf/AudioStegoCard.tsx` | 修法：failed 存错误码而非文案，渲染时现算 | P3
- [ ] TD-批次PICKER-1 | onScrollToCard 用全文档 getElementById：ff-card-summary 被 ReverseWorkspace 复用且五域 keepMounted 常驻，当前仅靠模块顺序正确；调序或新增同名锚点会静默滚到 hidden 容器 | 2026-09-24 题型卡批（reviewer P2） | `FileForensicsWorkspace.tsx` scrollToCard/选择卡回调 | 修法：容器内 rootRef.querySelector 或锚点 id 加域前缀 | P2
- [ ] TD-批次PICKER-2 | 题型卡两处文案术语密度偏高（"zsteg 式 288 组合"/"DWT-DCT-SVD"）对新手不自解释 | 2026-09-24 题型卡批（reviewer P2） | `challengeCatalog.ts:77,113` | 修法：换大白话并保留术语在 title | P3
- [ ] TD-批次KP-1 | zipBrute 掩码吞吐：JS 单线程 ~3.3 万口令/s（setTimeout 让步在 Windows 15ms 量级开销大），8 位纯数字 1 亿口令需 ~50 分钟——22 题自动通关受阻 | 2026-09-25 已知明文批 | `src/utils/ctf/zipBrute.ts` 节流 | 修法：Worker 内跑免让步 + 让步间隔自适应（连续无 UI 时降频） | P1
