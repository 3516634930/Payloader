import { memo } from 'react';
import { useLanguage } from '../../appContext';
import type { CtfWorkspaceProps } from '../../utils/ctf/modules';
import '../../styles/module-placeholder.css';

// 题型域轻占位页（批次 J）：如实告知建设中并预告规划能力，批次 K/L/M 各自替换为真实工作区。
const ModulePlaceholder = memo(function ModulePlaceholder({ module }: CtfWorkspaceProps) {
  const { language } = useLanguage();
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
    </section>
  );
});

export default ModulePlaceholder;
