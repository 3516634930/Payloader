import { useCallback, useEffect, useRef, useState } from 'react';

// 非安全上下文（http 内网部署等）下 Clipboard API 不可用，退回 execCommand textarea 降级。
function copyViaExecCommand(text: string): boolean {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  try {
    textarea.focus();
    textarea.select();
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    textarea.remove();
  }
}

// 剪贴板写入唯一入口：成功返回 true；两条路径都失败才返回 false。
export async function copyToClipboard(text: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // 权限被拒或上下文受限时走降级，不再向上抛。
    }
  }
  return copyViaExecCommand(text);
}

// 复制反馈 hook：copiedKey 记录最近一次成功复制的 key（不传 key 用 '' 哨兵，适合单按钮 boolean 判断），
// resetMs 后自动复位。全站统一 1800ms（此前 1500/1600/1800/2000 四种并存）。
export function useCopyFeedback(resetMs = 1800): {
  copiedKey: string | null;
  copy: (text: string, key?: string) => Promise<boolean>;
} {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  useEffect(() => () => {
    if (timerRef.current !== null) window.clearTimeout(timerRef.current);
  }, []);

  const copy = useCallback(async (text: string, key?: string): Promise<boolean> => {
    const ok = await copyToClipboard(text);
    if (!ok) return false;
    if (timerRef.current !== null) window.clearTimeout(timerRef.current);
    setCopiedKey(key ?? '');
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      setCopiedKey(null);
    }, resetMs);
    return true;
  }, [resetMs]);

  return { copiedKey, copy };
}
