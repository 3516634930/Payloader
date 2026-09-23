import { useId } from 'react';
import { useLanguage } from '../../appContext';

interface GlobalSecretBarProps {
  value: string;
  onChange: (value: string) => void;
  // 工作台与 hero 的引导文案有细微差异（"在下方参数里填了…" vs "下方工作台自动读取…"），经此传入。
  placeholder: { zh: string; en: string };
}

// 全局密钥栏（批次 M，原 CodecWorkbench / CtfHero 两处重复实现合并）：多步解密共用一把钥匙，
// 操作私有 secret 为空时回退到该值，私有值优先。
function GlobalSecretBar({ value, onChange, placeholder }: GlobalSecretBarProps) {
  const { language } = useLanguage();
  const secretFieldId = useId();

  return (
    <div className="global-secret-bar">
      <label htmlFor={secretFieldId}>{language === 'zh' ? '🔑 全局密钥' : '🔑 Global key'}</label>
      <input
        id={secretFieldId}
        value={value}
        onChange={event => onChange(event.target.value)}
        placeholder={language === 'zh' ? placeholder.zh : placeholder.en}
        spellCheck={false}
        autoComplete="off"
      />
    </div>
  );
}

export { GlobalSecretBar };
