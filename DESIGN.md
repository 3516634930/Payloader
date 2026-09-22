# Design System

## Theme

管理端采用浅色工作区配深色导航的克制产品界面。背景不使用装饰性光晕或玻璃拟态；强调色只用于主操作、当前选择和信息状态。

## Color

- Canvas: `#f4f6f8`
- Surface: `#ffffff`
- Navigation: `#111820`
- Primary ink: `#18212b`
- Secondary ink: `#556170`
- Border: `#d9dfe6`
- Accent: `#1769e0`
- Success: `#157f4c`
- Warning: `#a45d08`
- Danger: `#c33c52`

所有颜色通过语义 CSS 变量使用，不在模块脚本中写组件颜色。

## Typography

使用 `Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`。正文 14px，辅助文字 12px，页面标题 20px，区块标题 14-16px。标签不使用装饰性全大写；代码和命令使用系统等宽字体。

## Layout

- Desktop: 224px 全局侧栏、页面标题栏、可折叠资源列表和主编辑区。
- Tablet: 侧栏可折叠，保留列表与编辑双栏。
- Mobile: 单一模块选择器、列表/编辑分段控件、底部上下文操作区。
- 侧栏只承担全局导航，不放统计卡；数据统计仅在有任务价值的概览或模块标题中出现。

## Components

- Primary button: 每个上下文最多一个，40px 高。
- Secondary/Ghost button: 用于取消、刷新和低风险辅助操作。
- More menu: 收纳导入、移动、重置和退出等低频操作，并分隔危险操作。
- Form controls: 标签始终可见，统一 40px 高、8px 圆角、清晰焦点环。
- Panels: 使用边框和留白分区，避免重复嵌套卡片。
- Status: 保存中、未保存、成功、错误均使用文本与颜色共同表达。
- Empty state: 说明当前为空并提供下一步操作。

## Motion

状态过渡 150-200ms，使用 ease-out；只用于菜单、选择和保存反馈。`prefers-reduced-motion: reduce` 下关闭非必要过渡。
