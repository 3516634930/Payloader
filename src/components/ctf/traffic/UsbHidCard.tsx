import { useMemo, useRef, useEffect, useState } from 'react';
import { FlagAutoText } from '../../codec/FlagAutoText';
import { extractUsbHid } from '../../../utils/ctf/usbHid';
import type { ParsedCapture } from '../../../utils/ctf/pcap/parser';

// USB HID 恢复卡（流量域，linkType 220 usbmon 抓包）：击键序列（Shift 符号分支/小键盘）+ 鼠标轨迹
// 还原 canvas（按键按住段粗线——"鼠标画 flag"题的还原面）。引擎纯函数，本卡只渲染；换文件父层 key remount。
interface UsbHidCardProps {
  capture: ParsedCapture;
  language: 'zh' | 'en';
}

function UsbHidCard({ capture, language }: UsbHidCardProps) {
  const zh = language === 'zh';
  const result = useMemo(() => extractUsbHid(capture), [capture]);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [showTrack, setShowTrack] = useState(false);

  // 轨迹按需渲染（有鼠标样本才有按钮）；1000×1000 逻辑画布，按键按住段粗线还原"画字"笔迹。
  useEffect(() => {
    if (!showTrack || !result.mouse.length) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    canvas.width = 1000;
    canvas.height = 1000;
    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, 1000, 1000);
    ctx.strokeStyle = '#7ee787';
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    const points = result.mouseTrack.points;
    for (let index = 1; index < points.length; index += 1) {
      const from = points[index - 1];
      const to = points[index];
      const pressed = (to.buttons & 1) === 1;
      ctx.beginPath();
      ctx.lineWidth = pressed ? 4 : 1;
      ctx.globalAlpha = pressed ? 1 : 0.35;
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(to.x, to.y);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }, [showTrack, result]);

  return (
    <section className="pw-card" aria-label={zh ? 'USB HID 恢复' : 'USB HID recovery'}>
      <div className="pw-card-head">
        <strong>{zh ? 'USB HID 恢复（键盘 / 鼠标）' : 'USB HID recovery'}</strong>
        <span className="pw-badge">{zh ? `${result.dataPackets} 个 HID 报文` : `${result.dataPackets} HID packets`}</span>
      </div>
      {result.notes.map((note, index) => (
        <p key={index} className="pw-note">• {note}</p>
      ))}
      {result.keyboard.length > 0 ? (
        <div className="pw-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
          <span className="pw-label">{zh ? `击键序列（${result.keyboard.length} 键）` : `Keystrokes (${result.keyboard.length})`}</span>
          <code className="pw-code"><FlagAutoText text={result.text} /></code>
        </div>
      ) : (
        <p className="pw-note">{zh ? '未识别到键盘报文。' : 'No keyboard reports detected.'}</p>
      )}
      {result.mouse.length > 0 && (
        <div className="pw-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
          <div className="pw-row">
            <span className="pw-label">{zh ? `鼠标样本（${result.mouse.length} 个，含位移）` : `Mouse samples (${result.mouse.length})`}</span>
            <button type="button" className="pw-button" onClick={() => { setShowTrack(true); }}>
              {zh ? '还原轨迹' : 'Render track'}
            </button>
          </div>
          {showTrack && <canvas ref={canvasRef} className="pw-canvas" aria-label={zh ? '鼠标轨迹' : 'Mouse track'} />}
        </div>
      )}
    </section>
  );
}

export default UsbHidCard;
