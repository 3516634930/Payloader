import { useAppContext } from '../App';
import { t } from '../i18n';
import PayloadDetail from './PayloadDetail';
import ToolDetail from './ToolDetail';

function MainContent() {
  const { selectedPayloadId, selectedToolId, activeTab, language } = useAppContext();

  const renderContent = () => {
    if (activeTab === 'payloads') {
      if (selectedPayloadId) {
        return <PayloadDetail payloadId={selectedPayloadId} />;
      }
      return (
        <div className="empty-state">
          <div className="empty-icon">💀</div>
          <h2>{t('main.selectPayload', language)}</h2>
          <p>{t('main.selectPayloadHint', language)}</p>
          <div className="quick-tips">
            <h3>{t('main.quickTips', language)}</h3>
            <ul>
              <li>{t('main.tip1', language)}</li>
              <li>{t('main.tip2', language)}</li>
              <li>{t('main.tip3', language)}</li>
              <li>{t('main.tip4', language)}</li>
            </ul>
          </div>
        </div>
      );
    } else {
      if (selectedToolId) {
        return <ToolDetail toolId={selectedToolId} />;
      }
      return (
        <div className="empty-state">
          <div className="empty-icon">🛠️</div>
          <h2>{t('main.selectTool', language)}</h2>
          <p>{t('main.selectToolHint', language)}</p>
          <div className="quick-tips">
            <h3>{t('main.toolCategories', language)}</h3>
            <ul>
              <li>{t('main.toolCat1', language)}</li>
              <li>{t('main.toolCat2', language)}</li>
              <li>{t('main.toolCat3', language)}</li>
              <li>{t('main.toolCat4', language)}</li>
              <li>{t('main.toolCat5', language)}</li>
            </ul>
          </div>
        </div>
      );
    }
  };

  return (
    <main className="main-content">
      {renderContent()}
      <style>{`
        .main-content {
          flex: 1;
          height: calc(100vh - 60px);
          overflow-y: auto;
          background: var(--bg-primary);
        }

        .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 100%;
          padding: 40px;
          text-align: center;
        }

        .empty-icon {
          font-size: 64px;
          margin-bottom: 24px;
          filter: drop-shadow(0 0 20px var(--neon-cyan));
        }

        .empty-state h2 {
          font-size: 24px;
          font-weight: 600;
          margin-bottom: 12px;
          color: var(--text-primary);
        }

        .empty-state > p {
          font-size: 14px;
          color: var(--text-muted);
          margin-bottom: 40px;
        }

        .quick-tips {
          background: var(--bg-card);
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 24px;
          text-align: left;
          max-width: 500px;
        }

        .quick-tips h3 {
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 16px;
          color: var(--neon-cyan);
        }

        .quick-tips ul {
          list-style: none;
        }

        .quick-tips li {
          font-size: 13px;
          color: var(--text-secondary);
          padding: 8px 0;
          border-bottom: 1px solid var(--border-color);
        }

        .quick-tips li:last-child {
          border-bottom: none;
        }
      `}</style>
    </main>
  );
}

export default MainContent;
