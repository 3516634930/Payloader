import { useCallback, useEffect, useMemo, useRef } from 'react';

// 防抖回调：ms 内重复 run 只执行最后一次。cancel() 用于依赖变化后条件不再满足时撤销已排队的执行
//（对应此前 useEffect+setTimeout 模式里 cleanup 的行为）；组件卸载自动清理。
// 返回对象经 memo 稳定，可安全放进 effect 依赖数组。
export function useDebouncedCallback<A extends unknown[]>(fn: (...args: A) => void, ms: number): {
  run: (...args: A) => void;
  cancel: () => void;
} {
  const fnRef = useRef(fn);
  useEffect(() => {
    fnRef.current = fn;
  });

  const timerRef = useRef<number | null>(null);
  const cancel = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  useEffect(() => cancel, [cancel]);

  const run = useCallback((...args: A) => {
    cancel();
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      fnRef.current(...args);
    }, ms);
  }, [cancel, ms]);

  return useMemo(() => ({ run, cancel }), [run, cancel]);
}
