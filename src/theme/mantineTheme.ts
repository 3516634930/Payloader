import { createTheme } from '@mantine/core';

// 主色板以 global.css 的 --neon-cyan (#42ced0) 为基准展开十阶，
// index 3 与现有主色一致，供 Mantine 组件在深浅两种模式下取用。
const neon = [
  '#e0f7f8',
  '#c3eef1',
  '#87dde2',
  '#42ced0',
  '#2fb7ba',
  '#26999c',
  '#1f7d7f',
  '#1a6163',
  '#154547',
  '#102e2f',
] as const;

export const mantineTheme = createTheme({
  primaryColor: 'neon',
  primaryShade: 3,
  colors: { neon },
  defaultRadius: 'md',
  fontFamily: "'Segoe UI', 'Microsoft YaHei UI', Arial, sans-serif",
  fontFamilyMonospace: "'Cascadia Mono', 'Consolas', 'Courier New', monospace",
  headings: {
    fontFamily: "'Segoe UI', 'Microsoft YaHei UI', Arial, sans-serif",
  },
});
