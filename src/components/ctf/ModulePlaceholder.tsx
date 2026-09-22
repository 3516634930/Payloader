import { useAppContext } from '../../appContext';
import type { CtfWorkspaceProps } from '../../utils/ctf/modules';

// 题型域轻占位页（批次 J）：如实告知建设中并预告规划能力，批次 K/L/M 各自替换为真实工作区。
function ModulePlaceholder({ module }: CtfWorkspaceProps) {
  const { language } = useAppContext();
  return (
    <section className="ctf-module-placeholder" aria-label={module.name[language]}>
      <div className="ctf-module-placeholder-icon" aria-hidden="true">{module.icon}</div>
      <h3>{module.name[language]}</h3>
      <p>
        {language === 'zh'
          ? '该题型域的专属工具正在建设中。编码与密码类题目现在就可以在「密码与编码」域处理。'
          : 'Tools for this category are still in development. Encoding and cipher tasks are ready in Ciphers & Encoding.'}
      </p>
      {module.note ? <p className="ctf-module-placeholder-note">{module.note[language]}</p> : null}
      <style>{placeholderStyles}</style>
    </section>
  );
}

// 占位页样式跟随组件：同一时刻仅一个域工作区挂载，不会重复注入。
const placeholderStyles = `
  .ctf-module-placeholder {
    min-width: 0;
    display: grid;
    justify-items: center;
    gap: 8px;
    padding: 36px 16px;
    border: 1px dashed rgba(0, 240, 255, 0.3);
    border-radius: 8px;
    background: var(--bg-card);
    text-align: center;
  }

  .ctf-module-placeholder-icon {
    font-size: 34px;
    line-height: 1;
  }

  .ctf-module-placeholder h3 {
    margin: 0;
    color: var(--neon-cyan);
    font-size: 15px;
    font-weight: 800;
  }

  .ctf-module-placeholder p {
    margin: 0;
    max-width: 520px;
    color: var(--text-secondary);
    font-size: 13px;
    line-height: 1.7;
  }

  .ctf-module-placeholder-note {
    color: var(--text-muted);
    font-size: 12px;
  }
`;

export default ModulePlaceholder;
