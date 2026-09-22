// 富输出面板与候选列表的纯工具函数（组件外置，避免 fast-refresh 限制）。
export interface CandidateLayer {
  layer: number;
  chosen: string;
  options: Array<{ name: string; score: number; preview: string }>;
}

// 解析 smart-decode 输出尾部的机读候选段落。
export const parseCandidateLayers = (output: string): CandidateLayer[] | null => {
  const sectionStart = output.indexOf('=== 候选列表 ===');
  if (sectionStart < 0) return null;
  try {
    const parsed = JSON.parse(output.slice(sectionStart + '=== 候选列表 ==='.length).trim()) as CandidateLayer[];
    if (Array.isArray(parsed) && parsed.length > 0) return parsed;
  } catch {
    return null;
  }
  return null;
};

export const candidateHighlightKey = (layer: number, name: string): string => `${layer}::${name}`;

export const utf8ByteLength = (text: string): number => new TextEncoder().encode(text).length;

export const formatTextStats = (text: string, language: 'zh' | 'en'): string => {
  if (!text) return language === 'zh' ? '0 字符 / 0 字节' : '0 chars / 0 bytes';
  const chars = [...text].length;
  const bytes = utf8ByteLength(text);
  return language === 'zh' ? `${chars} 字符 / ${bytes} 字节` : `${chars} chars / ${bytes} bytes`;
};
