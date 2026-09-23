import { getText } from '../i18n';
import type { PayloadItem } from '../types';
import { label } from './payloadDetailText';
import type { DetailSection } from './payloadDetailText';

interface PayloadDetailHeaderProps {
  payload: PayloadItem;
  hasSubstantiveTutorial: boolean;
  language: 'zh' | 'en';
  activeSection: DetailSection;
  onSelectSection: (section: DetailSection) => void;
  copiedKey: string | null;
}

const getDifficultyColor = (difficulty: string) => {
  switch (difficulty) {
    case 'beginner': return 'var(--neon-green)';
    case 'intermediate': return 'var(--neon-cyan)';
    case 'advanced': return 'var(--neon-orange)';
    case 'expert': return 'var(--neon-red)';
    default: return 'var(--text-muted)';
  }
};

function PayloadDetailHeader({ payload, hasSubstantiveTutorial, language, activeSection, onSelectSection, copiedKey }: PayloadDetailHeaderProps) {
  return (
    <>
      <div className="payload-header">
        <div className="payload-title-section">
          <div className="payload-tags">
            {payload.tags.map(tag => (
              <span key={tag} className="tag">{tag}</span>
            ))}
          </div>
          <h1 className="payload-title">{getText(payload.name, language)}</h1>
          <p className="payload-description">{getText(payload.description, language)}</p>
        </div>
        <div className="payload-meta">
          <div className="meta-item">
            <span className="meta-label">{label('category', language)}</span>
            <span className="meta-value">{getText(payload.category, language)}</span>
          </div>
          {payload.subCategory && (
            <div className="meta-item">
              <span className="meta-label">{label('subCategory', language)}</span>
              <span className="meta-value">{getText(payload.subCategory, language)}</span>
            </div>
          )}
          {hasSubstantiveTutorial && payload.tutorial && (
            <div className="meta-item">
              <span className="meta-label">{label('difficulty', language)}</span>
              <span className="meta-value difficulty" style={{ color: getDifficultyColor(payload.tutorial.difficulty) }}>
                {payload.tutorial.difficulty.toUpperCase()}
              </span>
            </div>
          )}
        </div>
      </div>

      {payload.prerequisites?.length ? (
        <div className="prerequisites-section">
          <h3>{label('prerequisites', language)}</h3>
          <ul className="prerequisites-list">
            {payload.prerequisites.map((prereq, index) => (
              <li key={index}>{getText(prereq, language)}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="section-tabs" role="tablist" aria-label="Payload 内容">
        <button type="button" role="tab" aria-selected={activeSection === 'payloads'} className={`section-tab ${activeSection === 'payloads' ? 'active' : ''}`} onClick={() => onSelectSection('payloads')}>
          {label('tabPayloads', language)}
        </button>
        <button type="button" role="tab" aria-selected={activeSection === 'chain'} className={`section-tab ${activeSection === 'chain' ? 'active' : ''}`} onClick={() => onSelectSection('chain')}>
          {label('tabAttackChain', language)}
        </button>
        {hasSubstantiveTutorial && (
          <button type="button" role="tab" aria-selected={activeSection === 'tutorial'} className={`section-tab ${activeSection === 'tutorial' ? 'active' : ''}`} onClick={() => onSelectSection('tutorial')}>
            {label('tabTutorial', language)}
          </button>
        )}
      </div>

      <span className="sr-only" aria-live="polite">
        {copiedKey ? (copiedKey === 'all' ? label('copiedVisible', language) : label('copied', language)) : ''}
      </span>
    </>
  );
}

export default PayloadDetailHeader;
