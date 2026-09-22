# 计划：CTF 工具箱顶部菜单栏 + flag 自动标红（2026-09-22）

## 需求

用户对照随波逐流实机提三条 UI 否定：①操作入口在页面下方应在顶部菜单栏；②按钮网格应改为下拉框；③输出里 flag/ctf/key 字样无标红扫不到。重构为「顶部菜单栏 + 下拉菜单，点击即执行」，输出区自动标红 flag 类字样。只动导航与展示层，操作实现与受众分流（operationAudience）不动。

## 现状（调研结论）

- CTF 密码域工作台 = `CipherWorkspace` → `CodecWorkbench`（groups=buildCtfGroups()，4 段 108 操作）；导航 = 左侧分类面板 + 分类内动作网格（`runAction` 一次点击=选中+执行，批次 M）；渗透视图 = `EncodingTools` → 同组件（默认模式）。
- 输出高亮 = `WorkbenchOutputPanel`：Uint8Array KIND 分段（搜索黄/flag 完整格式绿/当前橙），flag 覆盖搜索，无关键词级标红。
- `FLAG_FORMAT_PATTERN` 在 `smartDecode.ts`（前缀{4字符+}完整格式），`detectFlagFormats` 派生徽标。
- 杂项/流量域工作区各有本地状态（文件报告卡 / ViewKey 视图切换）。
- verify 脚本 vm 加载 `audience.ts` 并断言受众守恒；contract 测试读源码文本。

## 方案

### A. 顶部菜单栏（随波逐流形态：顶部 + 下拉 + 点击即执行）

1. **菜单数据**（`src/utils/codec/audience.ts`）：新增 `ctfMenuSpec`（9 菜单声明式清单）+ `buildCtfMenus()` 纯函数解析为操作。菜单：智能识别(1) / Base/Rot(16) / 古典密码(25，下拉内 5 个小节标签) / 中文字表(12) / 电报编码(9) / 编码转换(18) / 进制转换(4) / 现代密码(17) / 其他工具(6) = 108 全覆盖。守恒断言进 verify 脚本（并集=buildCtfGroups 操作集、无重复、无遗漏）。
2. **通用菜单栏组件**（`src/components/codec/WorkbenchMenuBar.tsx` 新建）：Mantine `Menu`（withinPortal 防横滚裁剪、自带方向键+Enter 键盘导航、点击选择后自动收起）；触发按钮横排，≤520px 横向滚动；条尾显示「当前：操作名」。
3. **CodecWorkbench 模式化**：新增 `mode?: 'pentest'|'ctf'`（默认 pentest，渗透视图零变化）。CTF 态：菜单栏置主面板顶部（hero 正下方=紧邻智能识别区）；菜单项点击=`runAction`（选中+立即执行，同步 activeGroupId）；左侧分类面板移除（菜单栏替代），动作网格折叠为 `<details>` 备用（默认收起）；标记法统一为【名解密】/【名加密】（随波逐流方括号标记法，en `[name dec]`）。
4. **域联动**：`FileForensicsWorkspace` 顶部「文件与图片」菜单（选择文件/概要/可疑内容/字符串/hexdump 定位，未加载文件时先开选择器，节缺失 toast 说明）；`TrafficWorkspace` 顶部「抓包分析」菜单（选择文件/五个视图切换，未加载文件时先开选择器）。各域菜单只在各自域渲染（工作区仅在激活域挂载，天然联动）。

### B. flag 自动标红（红色系，与搜索高亮共存）

1. **引擎层**（`smartDecode.ts`）：新增 `FLAG_KEYWORD_PATTERN`（`\b(?:flag|ctf|key)s?\b`，gi，工厂函数防 lastIndex）+ `findFlagAutoRanges(text)`：完整格式（优先级高，复用 FLAG_FORMAT_PATTERN 重建位置区间）+ 关键词（低优先级，与完整格式重叠处让位），经 index 导出。
2. **输出面板**（`WorkbenchOutputPanel`）：分段算法改为边界原子+双层渲染——外层按 auto 级别（无/关键词红/完整格式深红），内层叠加搜索命中（红区外=黄底，红区内=黄描边环，互不覆盖）；当前导航命中保持唯一 `data-current` 节点（红区内=橙环）。flag 命中从绿色改红色系。
3. **文件取证报告**（`FileForensicsWorkspace`）：strings 条目、hexdump、零宽 payload 经新共享组件 `FlagAutoText`（`components/codec/`，纯 auto 红无搜索层）标红；「发现 flag」卡保留。

### C. 验证与门禁

- verify:codec 新增断言块：菜单守恒（9 菜单/108 并集/无重复）、`findFlagAutoRanges` 向量（`flag{abcd}`=format、`FLAG{UP}`=keyword 短内容、`monkey` 不命中）。
- frontend-contract.test.mjs 新增源码断言：CipherWorkspace 传 `mode="ctf"`、EncodingTools 不传（渗透不变）、CodecWorkbench 引入 WorkbenchMenuBar。
- 四门禁 `npm run check` 串行全绿 → agent-code-reviewer 独立复核 → Playwright 浏览器实测（菜单即点即执行 / flag{test}+FLAG{UP} 标红 / 搜索共存 / 390px / console 零报错）。

## 风险与边界

- Mantine Menu 下拉在移动端必须 withinPortal，否则横滚容器裁剪下拉。
- 关键词 \b 边界：`monkey` 不命中；`keys` 命中（s? 容差）。
- 富视图 200K 上限逻辑不变，超限仍退纯文本。
- 渗透视图不改：mode 默认 pentest，EncodingTools 不传 mode；渲染分支与 CSS 仅 ctf 态生效。

## 验收（用户口径）

菜单栏点任一操作立即出结果（无需再点执行按钮）；输出含 flag{test} 与 FLAG{UP} 全部标红；正则搜索与自动标红共存不覆盖；390px 菜单可操作；console 零报错；四门禁全绿。
