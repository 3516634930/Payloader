# 架构重构路线图（2026-09-23 全平台审查产出）

> 依据：三路并行架构审查（前端 / server / 脚本数据链），全部发现带 file:line 证据。
> 本轮已实施的低风险快赢见文末"已完成"；本文档记录**已识别但需独立排期**的中大型重构项。
> 前置建议：**先做一次完整本地 commit 再启动任何一项**——当前工作树有跨多批次的未提交改动，缺基线回滚困难。

## P1（高价值，建议 v2.0.2 之前插入）

### 1. codec 注册表动态化 —— 拆 1.4MB 懒加载 chunk
- 现状：`src/utils/codec/index.ts` 桶文件静态 import 全部 30 个运算模块（含 smartHelpers 673KB 大字表、rsa 3432 行、crypto 1976 行），点开编解码/CTF 工具即拉 **1307KB（gzip 394KB）** chunk。
- 方案：注册表按运算组拆分（crypto/古典/parity 中文/智能识别/基础），`operations` 数组改异步装配；首开只加载基础组，其余按需。
- 风险：中（注册是同步数组，verify:codec 沙箱依赖 index.ts 导出白名单，需同步改造）。工作量 ~12h。收益：CTF 工具首开体积 -70%。

### 2. Context 拆分 + 渲染隔离
- 现状：`appContext.ts` 单 context 29 字段，Provider value 未 useMemo（App.tsx:194-224），全仓 `React.memo` 为 0；搜索框每键入一字（Header.tsx:328）→ PayloadDetail（1156 行）/Sidebar（545 行）全树重渲染。
- 方案：按读写拆 Data/Nav/UI/Selection 3-4 个 context，value useMemo，Sidebar/MainContent/PayloadDetail 加 memo。
- 风险：低-中。工作量 ~6h。收益：大列表页交互流畅度。

### 3. admin-server 路由表化
- 现状：1708 行单文件 14 类职责，510 行 if-else 路由链（:1069-1578），鉴权/限流靠函数边界隐式约定；新增 API 改 2 处。
- 方案：`route(method, pattern, {auth, rateLimit}, handler)` 声明式注册表 + 中间件管道；顺带文档化"admin 凭据借 data-store metadata 表持久化"的跨模块通道。
- 风险：中（依赖 api-smoke/data-safety 回归）。工作量 6-8h。

### 4. data-store 职责拆分
- 现状：3660 行混 6 类职责（引擎 ~1100 / 种子内容 ~450 / 迁移 ~460 / 导入导出 ~310 / 重置备份 ~190 / sanitize ~320）；三套 upsert 写法并存；缓存失效调用散布 10+ 处。
- 方案：拆 `seed-content.mjs` / `migrations.mjs` / `import-export.mjs` / `sanitize.mjs` 四个内部模块（对外导出面不变）；CRUD 归一到 `upsertItems`，写路径统一 mutation wrapper 内失效缓存。
- 风险：中。工作量 8-13h。

## P2（值得做，排期灵活）

### 5. Header 子组件拆分
- 样式已迁出（本轮完成，2026→595 行）；剩余：拆 `HeaderVariablesPanel` / `HeaderEncodingDialog` / `HeaderMobileMenu` / `HeaderSearch` 四个子组件（现 9 个 ref 提升在顶层，任一面板开合重渲染整个 Header）。~4h。

### 6. 共享工具函数收敛
- 剪贴板复制 9 处独立实现、下载 3 处、防抖手写、**250 处 `language === 'zh' ? :` 内联三元绕过 i18n 层**。建 `src/utils/clipboard.ts` / `download.ts` / `debounce.ts`，i18n 三元渐进收敛进 getText。~6h。

### 7. cheatsheets 与 toolCommands 解引用
- 现状：CTF chunk（119KB）靠 tree-shaking 侥幸不包含 2.1MB 的 toolCommands 源码；任何 cheatsheet 直接引用 catalog 对象即膨胀 MB 级。
- 方案：cheatsheets 只存条目 id 常量，运行时从 context `allToolCommands` 解析。~2h。

### 8. utils→components 分层倒置修正
- `src/utils/ctf/modules.ts:3-6` 静态 import 4 个工作区组件（注册表属组件层职责）。下移注册表为 `components/ctf/registry.tsx`，utils 只留类型。~2h。

### 9. 16 个组件内联 `<style>` 迁出
- Header 已完成（本轮）；其余 15 个组件（CodecWorkbench/CtfToolkit/Sidebar 等）内联样式迁至 `src/styles/*.css`，构建产物可缓存。~7h。每迁一个改一次对应 frontend-contract 文本断言。

### 10. verify 脚本扩展成本优化
- 新增一个编解码操作要改 4 处（实现/向量/PARITY_OP_IDS 手工副本/智能识别块）。把"参与对拍的 op id 清单"改为从 src 模块导出读取（scripts/verify-encoding-tools.mjs:2572-2578），扩展成本降为"实现+向量"两步。~4h。

### 11. 测试夹具共享 + 契约测试瘦身
- api-smoke 与 data-safety 各自重复 ~40 行 server fixture，提 `tests/helpers/server-fixture.mjs`。~1h。
- frontend-contract 36 个源码文本断言仅保留 3-5 个挂载点检查，其余改行为断言。~6h。**注：本轮已把 2 个触控断言迁至 header.css。**

### 12. src/data 双维护收口
- src/data 实质冻结（唯一活跃写路径 = generate-command-catalogs.mjs）；在 DESIGN.md 声明"种子库为唯一源"，长期删除 default-seed-source 的 legacy 分支。~4h（需先确认无批量编辑需求）。

### 13. server 杂项
- `routeResource` 双份定义（admin-server.mjs 锚定正则 vs data-store.mjs 宽松 includes）语义不同，**不可直接合并**——统一到锚定语义需评估 data-store 侧调用方。~2h。
- data-store 手工 `{status}` 错误对象与 admin-server `HttpError` 靠鸭子类型约定，提共享错误基类。~2h。
- `json()` helper 增 extraHeaders 参数，收编登录/登出/export 等 5 处裸 writeHead。~2h。

## 已完成（本轮快赢，2026-09-23）

| 项 | 内容 | 效果 |
|---|---|---|
| 死代码迁移 | webPayloads/intranetPayloads（1.9MB）移至 scripts/legacy-seed/，default-seed-source 与 content-quality 测试同步改路径 | src/ 不再全量编译索引 1.9MB 前端死代码 |
| vendor 分包 | vite.config.ts manualChunks 函数式（rolldown-vite 仅支持函数） | 主包 index 478KB→**164KB**；vendor-react 178KB / vendor-mantine 198KB 独立缓存 |
| Header 样式解耦 | 1435 行内联 CSS（零插值，机械迁移）→ src/styles/header.css | Header.tsx 2026→**595 行**（-71%），样式可缓存 |
| image-inspect 拆分 | PNG/JPEG/WebP 尺寸嗅探纯函数（~100 行）迁 server/image-inspect.mjs | 独立可测，admin-server 职责-1 |
| 429 响应去重 | checkRateLimit 超限分支复用 respondTooManyRequests | 消除同文件复制 |
| 一次性脚本归档 | 23 个手术/翻译脚本 + 12 个 json 残留（~5,900 行）→ scripts/archive/content-batches-2026-09/（含 README 与绝对路径炸弹警示） | scripts/ 顶层只留常驻脚本 |
| 触控断言跟随 | frontend-contract 2 个触控测试改读 header.css | 契约与样式文件位置一致 |

审查中纠正的误判（避免后续重复调查）：巨型数据文件**并未**进主 bundle（数据经 /api/public-data 运行时注入）；server 并非全零依赖（HTTP 主链路零依赖，client 构建/版本检查用 semver/archiver/tar 等 4 个包）；"零依赖"红线维持不破。

## 门禁记录（本轮全部改动后）

verify:codec 129 ✓ / test 211 ✓ / typecheck ✓ / lint ✓ / vite build ✓ / 浏览器 Header+CTF 实测无回归 ✓
