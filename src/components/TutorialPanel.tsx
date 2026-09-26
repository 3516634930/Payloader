import { getText } from '../i18n';
import type { PayloadItem, TutorialContent } from '../types';
import { label } from './payloadDetailText';

interface TutorialPanelProps {
  payload: PayloadItem;
  tutorial: TutorialContent;
  language: 'zh' | 'en';
}

interface ProseBlock { kind: 'prose' | 'code'; text: string }

// 教程段文本可携带缩进防护代码（连续 4 空格及以上缩进行）；HTML 默认折叠空白会毁掉代码结构，
// 这里拆成 prose/code 两类块分别渲染，代码块复用全局 .code-block 样式。
const splitProseCode = (raw: string): ProseBlock[] => {
  const lines = String(raw ?? '').replace(/\r\n?/g, '\n').split('\n');
  const blocks: ProseBlock[] = [];
  let prose: string[] = [];
  let code: string[] = [];
  const flushProse = () => {
    if (prose.length) { blocks.push({ kind: 'prose', text: prose.join(' ').replace(/\s{2,}/g, ' ').trim() }); prose = []; }
  };
  const flushCode = () => {
    if (code.length) {
      // 剥离块内最小公共缩进（tab 计 4 空格），代码顶格展示
      const width = (l: string) => { const m = l.match(/^[ \t]*/)?.[0] ?? ''; return m.replace(/\t/g, '    ').length; };
      const min = Math.min(...code.map(width));
      blocks.push({
        kind: 'code',
        text: code.map(l => l.replace(/^[ \t]*/, '').padStart(Math.max(0, width(l) - min))).join('\n').replace(/[ \t]+$/gm, ''),
      });
      code = [];
    }
  };
  for (const line of lines) {
    if (/^ {4,}|^\t/.test(line)) { flushProse(); code.push(line); }
    else if (/^\s*$/.test(line)) { if (code.length) code.push(''); else prose.push(''); }
    else { flushCode(); prose.push(line); }
  }
  flushProse();
  flushCode();
  return blocks.filter(b => b.text.length > 0);
};

export const ProseWithCode = ({ text }: { text: string }) => {
  const blocks = splitProseCode(text);
  if (!blocks.length) return null;
  return (
    <>
      {blocks.map((block, index) => block.kind === 'code'
        ? <pre key={index} className="code-block tutorial-code">{block.text}</pre>
        : <p key={index}>{block.text}</p>)}
    </>
  );
};

function TutorialPanel({ payload, tutorial, language }: TutorialPanelProps) {
  return (
    <div className="tutorial-section" role="tabpanel">
      <div className="tutorial-card">
        <h3>{label('overview', language)}</h3>
        <ProseWithCode text={getText(tutorial.overview, language)} />
      </div>
      <div className="tutorial-card">
        <h3>{label('vulnerability', language)}</h3>
        <ProseWithCode text={getText(tutorial.vulnerability, language)} />
      </div>
      <div className="tutorial-card">
        <h3>{label('exploitation', language)}</h3>
        <ProseWithCode text={getText(tutorial.exploitation, language)} />
      </div>
      <div className="tutorial-card">
        <h3>{label('mitigation', language)}</h3>
        <ProseWithCode text={getText(tutorial.mitigation, language)} />
      </div>
      <div className="analysis-card">
        <h3>{label('notesTitle', language)}</h3>
        <ProseWithCode text={payload.analysis ? getText(payload.analysis, language) : ''} />
        {!payload.analysis ? <p>{label('noNotes', language)}</p> : null}
      </div>
      {payload.opsecTips?.length ? (
        <div className="analysis-card warning">
          <h3>{label('opsec', language)}</h3>
          <ul>
            {payload.opsecTips.map((tip, index) => <li key={index}>{getText(tip, language)}</li>)}
          </ul>
        </div>
      ) : null}
      {payload.references?.length ? (
        <div className="analysis-card">
          <h3>{label('refs', language)}</h3>
          <ul className="references-list">
            {payload.references.map((ref, index) => (
              <li key={index}><a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a></li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

export default TutorialPanel;
