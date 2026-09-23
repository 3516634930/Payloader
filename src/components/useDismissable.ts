import { useEffect, useRef } from 'react';
import type { RefObject } from 'react';

interface UseDismissableOptions {
  enabled: boolean;
  containerRef: RefObject<HTMLElement | null>;
  buttonRef: RefObject<HTMLElement | null>;
  onClose: () => void;
  getEscapeFocusTarget: () => HTMLElement | null;
}

// 弹层关闭逻辑（外点关闭 + Escape 关闭并归还焦点），行为与原 Header 内联 effect 一致：
// 仅在 enabled 翻转时注册/注销监听，回调经 ref 取最新值避免重复注册。
export function useDismissable({ enabled, containerRef, buttonRef, onClose, getEscapeFocusTarget }: UseDismissableOptions) {
  const handlersRef = useRef({ onClose, getEscapeFocusTarget });

  useEffect(() => {
    handlersRef.current = { onClose, getEscapeFocusTarget };
  });

  useEffect(() => {
    if (!enabled) return;

    const closeOnOutsidePointer = (event: MouseEvent) => {
      const target = event.target as Node;
      if (!containerRef.current?.contains(target) && !buttonRef.current?.contains(target)) {
        handlersRef.current.onClose();
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      handlersRef.current.onClose();
      handlersRef.current.getEscapeFocusTarget()?.focus();
    };

    document.addEventListener('mousedown', closeOnOutsidePointer);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('mousedown', closeOnOutsidePointer);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [enabled, containerRef, buttonRef]);
}
