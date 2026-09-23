# Payloader 项目协作者须知（AI/人共享）

## 踩坑记录（踩过一次就要防第二次）

- **ImageBitmap.close() 之后 width/height 归零**（症状：图片位平面/缩略图全部变成 1×1、`new ImageData()` 抛 `IndexSizeError: source width is zero` 并击穿整棵 React 树白屏）→ 必须**先**把 `bitmap.width`/`bitmap.height` 存进局部变量**再** `close()`；对 `createImageBitmap` 的返回值任何"close 后再读属性"的写法都是错的。位置：`FileForensicsWorkspace.tsx` 图片解码段。
- **node:vm 沙箱跨 realm 数组的 `assert.deepStrictEqual` 必失败**（症状：actual 与 expected 打印完全一致仍报 `prototype` 不同）→ 沙箱内模块返回的数组调用 `.map()` 产物是沙箱 realm 的 Array，原型与主 realm 不同。测试侧统一用**主 realm 的 `Array.from(sandboxArray, fn)`** 转换后再断言，不要用 `sandboxArray.map(fn)`。位置：`tests/file-forensics.test.mjs`。
- **`react-hooks/set-state-in-effect`（React 19 eslint 规则）禁止 effect 同步路径调用 setState**（症状：lint 报 `Avoid calling setState() directly within an effect`）→ 卡片局部状态的重置不要写进 effect 早期分支，改为：换文件时由父组件**改 key 强制 remount**（局部状态自然清零）；effect 内只允许异步回调（`.then`/async await 之后）里 setState。位置：`FileForensicsWorkspace.tsx`、`EmbeddedCard.tsx`。
- **兄弟组件 key 重复会导致 React DOM 残留复用错乱**（症状：同一卡片渲染多份、console 报 `Encountered two children with the same key`）→ 条件渲染的相邻兄弟组件 key 必须带组件前缀区分（如 `planes-`/`embedded-`），不要共用同一个 `${name}:${size}`。位置：`FileForensicsWorkspace.tsx` 卡片区。
- **PNG 解码验证不能把每行首字节当像素**（症状：自造 PNG 比对时行 1+ "全 0"）→ PNG 每行前置 filter byte，且浏览器 toBlob 编码常用 Up/Paeth filter（内容相同时 diff 为 0）；验证脚本必须按 PNG 规范还原 filter 再比对。
- **dev server 端口残留**：`TaskStop` 杀掉 npm 外壳后 vite 子进程可能残留占用端口（strictPort 再启报 `Port already in use`）→ 残留的 vite 仍服务最新磁盘代码（按需编译），可直接复用该端口测试；彻底清理需杀 node 进程。
- **memo 化树节点仅按"子树含选中"传播会在同枝移动选中时全部 bail**（症状：选中从枝内叶子 A 点到叶子 B，主内容切换了但树上高亮冻结在 A，生产构建同样复现）→ 自定义比较器必须加"叶子 id 变化且本枝（前或后）含选中 → 强制重渲染"规则（selectedLeafId 信号），仅 branchSelected 布尔翻转只覆盖跨枝场景，覆盖不了"祖先链 containment 恒 true、自身 isSelected 不变"的同枝移动。位置：`src/components/Sidebar.tsx` TreeNode 比较器。
- **组件 `<style>` 迁出为 CSS 文件后，级联胜负改由 bundle 内 import 顺序决定**（症状：`global.css` 的 `.code-block`（4px 圆角）反压 PayloadDetail/ToolDetail 自身的 6px 圆角规则，代码块圆角/内边距/溢出回归；生产构建产物可复现）→ 旧内联 `<style>` 渲染在 body 天然压过 head 样式表，迁移后这层保护消失：全局 CSS（`src/styles/global.css`）的 import 必须置于 `App.tsx` 组件 import **之前**；同一组件引多张 CSS 时保持原 `<style>` 注入顺序（同 specificity 后者胜）。位置：`src/App.tsx:3-4`（修复 commit c699589）。
