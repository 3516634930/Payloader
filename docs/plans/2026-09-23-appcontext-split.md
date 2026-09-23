# appContext 拆 5 context + 消费面 memo 化（2026-09-23）

## 目标
搜索键入重渲染面从 20 组件缩到 3 个（Header/MainContent/Sidebar）；导航点击只重渲染受影响子树。门禁全绿 + 浏览器 Profiler 实测 5 个 keepMounted CTF 工作区键入零重渲染。

## 约束（用户红线）
- 不得顺手改任何组件渲染逻辑，只动 context 归属与 memo。
- appContext.ts 保留 `useAppContext` 兼容导出（聚合 5 context 返回旧形状）。

## 29 字段 → 5 context（逐字段已核实）
| Context | 字段 | 依据 |
|---|---|---|
| StaticData | allPayloads/allToolCommands/allPayloadNavigation/allToolNavigation/settings/dataLoading/dataError | 启动加载后恒定 |
| Language | language + setLanguage | 20 组件只读 |
| Nav | activeTab/activeView/selectedPayloadId/selectedToolId/bypassMode + setter ×5 | 写方=4 导航入口 |
| Search | searchQuery/setSearchQuery/deferredSearchQuery/searchMatches | 唯一高频族，消费面 3 处 |
| Session | globalVariables/theme/globalSecret + setter ×3 | 会话内可变 |

## 消费方迁移矩阵（grep 全量核实，useAppContext 共 22 个调用点）
- Header：Session(4)+Nav(7)+Search(2)+StaticData(settings)+Language —— 全 5 域
- MainContent：Nav(7)+Search(3)+StaticData(6)+Language —— 17 字段最重，优先迁移验证
- Sidebar 主组件：Nav(activeTab+selected×2 新增订阅)+Search(2)+Language+StaticData(4)
- Sidebar TreeNode(:74)：context 直读 → props isSelected/onSelect/branchSelected + memo；保留 useStaticData(allToolCommands)+useLanguage
- PayloadDetail：Session+Nav+Language+StaticData / ClientDownloads：Language+Nav / CodecWorkbench：Language+Session
- SyntaxModal/ToolDetail/SimpleTextDetail：各自按矩阵 / CtfHero：Language+Session / CheatsheetSection：Language+Nav+StaticData
- language-only ×9 文件：CtfToolkit、CheatsheetWorkspace、FileForensicsWorkspace、PwnWorkspace(内 4 调用点：CyclicCard/BadCharCard/FormatStringCard?/PwnWorkspace)、ReverseWorkspace、TrafficWorkspace、ModulePlaceholder、WorkbenchMenuBar、WorkbenchOutputPanel → useLanguage + React.memo

## memo 生效的最小使能改动（非渲染逻辑变更）
1. App.tsx：`onOpenClientDownloads`/`onNavigate` 内联箭头 → useCallback（否则 App 每次渲染击穿 Sidebar 子树 memo）
2. CtfToolkit.tsx：`onHandOffFile` 内联箭头 → useCallback（否则 hero 键入击穿 5 常驻工作区 memo）

## TreeNode memo 精确传播设计
props：item/level/matchedIds/forceExpand/isSelected/**branchSelected**(子树含选中叶子)/onSelect/isFirst/onNavigate + selectedPayloadId/selectedToolId（递归计算用）。
自定义比较器只比显示相关 props，忽略原始选中 id。选择跨枝移动：新旧叶子的祖先链 branchSelected 翻转 → 沿链重渲染 → 其余子树 bail。纯忽略 id 的写法有"跨枝取消选中不传播"bug，必须带 branchSelected。

## 验收
1. typecheck + lint + node --test 全绿（frontend-contract 契约断言不破坏：Sidebar aria 树/isFirst 精确串/WorkbenchMenuBar 命名导出/App 搜索索引模式）
2. 浏览器 Profiler/console 计数：搜索键入 → 5 CTF 工作区零重渲染
3. CTF 七域冒烟：切换/文件上传/识别芯片无回归
4. agent-code-reviewer 独立复核 + self-verify-dev 自检

## 门禁命令
`npm run typecheck` → `npm run lint` → `npm test`
