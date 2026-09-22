import { useMemo } from 'react';
import { findFlagAutoRanges } from '../../utils/codec';

interface FlagAutoTextProps {
  text: string;
}

// 输出文本 flag 自动标红（关键词 + 完整格式，红色系）：供文件取证报告等
// 纯展示文本共用；富输出面板的搜索共存版本在 WorkbenchOutputPanel 内单独实现。
// 样式（.flag-auto-*）由消费方组件的样式块提供，避免列表场景重复渲染 style 标签。
export function FlagAutoText({ text }: FlagAutoTextProps) {
  const ranges = useMemo(() => findFlagAutoRanges(text), [text]);
  if (!ranges.length) return <>{text}</>;
  const nodes: React.ReactNode[] = [];
  let cursor = 0;
  for (const range of ranges) {
    if (range.start > cursor) nodes.push(text.slice(cursor, range.start));
    nodes.push(
      <mark
        key={`${range.start}-${range.level}`}
        className={`flag-auto ${range.level === 'format' ? 'flag-auto-format' : 'flag-auto-keyword'}`}
      >
        {text.slice(range.start, range.end)}
      </mark>,
    );
    cursor = range.end;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return <>{nodes}</>;
}
