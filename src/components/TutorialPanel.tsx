import { getText } from '../i18n';
import type { PayloadItem, TutorialContent } from '../types';
import { label } from './payloadDetailText';

interface TutorialPanelProps {
  payload: PayloadItem;
  tutorial: TutorialContent;
  language: 'zh' | 'en';
}

function TutorialPanel({ payload, tutorial, language }: TutorialPanelProps) {
  return (
    <div className="tutorial-section" role="tabpanel">
      <div className="tutorial-card">
        <h3>{label('overview', language)}</h3>
        <p>{getText(tutorial.overview, language)}</p>
      </div>
      <div className="tutorial-card">
        <h3>{label('vulnerability', language)}</h3>
        <p>{getText(tutorial.vulnerability, language)}</p>
      </div>
      <div className="tutorial-card">
        <h3>{label('exploitation', language)}</h3>
        <p>{getText(tutorial.exploitation, language)}</p>
      </div>
      <div className="tutorial-card">
        <h3>{label('mitigation', language)}</h3>
        <p>{getText(tutorial.mitigation, language)}</p>
      </div>
      <div className="analysis-card">
        <h3>{label('notesTitle', language)}</h3>
        <p>{payload.analysis ? getText(payload.analysis, language) : label('noNotes', language)}</p>
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
