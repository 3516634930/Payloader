import type { RefObject } from 'react';

interface CtfHeroStripProps {
  // 折叠条状态摘要：一眼看到当前识别进展（由宿主按 running/输入/flag 命中等算好传入）。
  status: string;
  expanded: boolean;
  onExpand: () => void;
  // 折叠条上的"需要解编码？"引导：点击切回密码与编码域（速查域折叠条专用）。
  onSwitchToCipher?: () => void;
  language: 'zh' | 'en';
  // 折叠态下 hero 的唯一 DOM 锚点（CtfToolkit scrollIntoView 依赖），随折叠条 section 原样携带。
  heroRef: RefObject<HTMLDivElement | null>;
}

// 折叠条（heroMode === 'collapsed' 且未展开时替换整个 hero，文件/速查工作区升为该域首屏）。
// 展开状态由宿主 CtfHero 记忆（单实例跨域保留），expanded 时本组件不渲染。
function CtfHeroStrip({ status, expanded, onExpand, onSwitchToCipher, language, heroRef }: CtfHeroStripProps) {
  const isZh = language === 'zh';
  if (expanded) return null;

  return (
    <section className="ctf-hero ctf-hero-folded" ref={heroRef} aria-label={isZh ? '智能识别' : 'Smart identify'}>
      <div className="ctf-hero-strip">
        <button
          type="button"
          className="ctf-hero-strip-main"
          onClick={onExpand}
          aria-expanded={false}
          title={isZh ? '展开完整智能识别（粘贴即自动解码）' : 'Expand full Smart Identify (auto-decodes on paste)'}
        >
          <strong>⚡ {isZh ? '快速文本识别' : 'Quick Identify'}</strong>
          <span className="ctf-hero-strip-status">{status}</span>
          <span className="ctf-hero-strip-toggle" aria-hidden="true">{isZh ? '展开 ▾' : 'Expand ▾'}</span>
        </button>
        {onSwitchToCipher ? (
          <button
            type="button"
            className="ctf-hero-strip-guide"
            onClick={onSwitchToCipher}
            title={isZh ? '切到密码与编码域使用完整智能识别' : 'Switch to Ciphers & Encoding for full Smart Identify'}
          >
            {isZh ? '需要解编码？→' : 'Need decoding? →'}
          </button>
        ) : null}
      </div>
    </section>
  );
}

export { CtfHeroStrip };
