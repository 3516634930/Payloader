import { useLanguage } from '../../appContext';
import type { Detection, OperationId } from '../../utils/codec/types';

interface DetectStripProps {
  detections: Detection[];
  onDetect: (id: OperationId) => void;
}

// 识别芯片条（原 CodecWorkbench / CtfHero 两处重复实现合并）：形状检测命中后渲染芯片按钮，点击直达对应操作。
function DetectStrip({ detections, onDetect }: DetectStripProps) {
  const { language } = useLanguage();
  if (!detections.length) return null;

  return (
    <div className="detect-strip" aria-label={language === 'zh' ? '自动识别结果' : 'Detected formats'}>
      <span>{language === 'zh' ? '识别' : 'Detected'}</span>
      {detections.map(detection => (
        <button key={`${detection.id}-${detection.label}`} type="button" onClick={() => onDetect(detection.id)}>
          {detection.label}
        </button>
      ))}
    </div>
  );
}

export { DetectStrip };
