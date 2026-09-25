// ZIP 爆破 Worker 客户端（批次 KW：TD-批次KP-1 + TD-批次MISC2-3）。
// 主线程只负责创建/终止 worker 与转发进度：bytes 拷贝后 transfer（主线程视图不动），
// abort = worker.terminate() 立即收口（TD-批次MISC2-3：换文件 remount 不再跑满剩余预算）。
// Worker 构造失败（file:// 协议/旧环境）或脚本加载失败自动降级主线程引擎路径，能力不缺失只让步。
import { bruteZipPassword, dictionaryCandidates, maskCandidates } from './zipBrute';
import type { BruteProgress, ZipEncryptedEntry } from './zipBrute';
import type { ZipBruteSpec } from './zipBruteWorker';

export type ZipBruteWorkerProgress = BruteProgress & { aborted?: boolean };

export interface ZipBruteWorkerOptions {
  timeBudgetMs?: number;
  onProgress?: (progress: ZipBruteWorkerProgress) => void;
  signal?: AbortSignal;
}

// 与 worker 侧 buildCandidates 同语义的降级候选构建（主线程路径用）
const buildFallbackCandidates = (spec: ZipBruteSpec): Iterable<string> => {
  if (spec.kind === 'dictionary') return dictionaryCandidates();
  if (spec.kind === 'list') {
    if (!Array.isArray(spec.list)) throw new Error('自定义列表 spec 缺少 list 数组');
    return spec.list;
  }
  const charset = spec.charset ?? '';
  if (charset.length < 2) throw new Error('掩码 spec 的 charset 至少需要 2 个不同字符');
  const minLength = Math.max(1, spec.minLength ?? 1);
  return maskCandidates(charset, minLength, Math.max(minLength, spec.maxLength ?? minLength));
};

const EMPTY_PROGRESS: BruteProgress = { tried: 0, total: 0, password: null, previewText: null };

export const bruteZipPasswordWorker = (
  bytes: Uint8Array,
  entry: ZipEncryptedEntry,
  spec: ZipBruteSpec,
  options?: ZipBruteWorkerOptions,
): Promise<ZipBruteWorkerProgress> => {
  const timeBudgetMs = options?.timeBudgetMs;
  const onProgress = options?.onProgress;
  const signal = options?.signal;
  if (signal?.aborted === true) {
    return Promise.resolve({ ...EMPTY_PROGRESS, total: 0, aborted: true });
  }

  let worker: Worker;
  try {
    worker = new Worker(new URL('./zipBruteWorker.ts', import.meta.url), { type: 'module' });
  } catch {
    // 降级：主线程让步路径（行为与旧版一致），signal 照常生效；abort 后补标 aborted 走"已取消"文案
    return bruteZipPassword(bytes, entry, buildFallbackCandidates(spec), { timeBudgetMs, onProgress, signal }).then(
      result => (signal?.aborted === true ? { ...result, aborted: true } : result),
    );
  }

  return new Promise<ZipBruteWorkerProgress>((resolve, reject) => {
    let settled = false;
    let lastProgress: BruteProgress = EMPTY_PROGRESS;
    const cleanup = () => {
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      worker.terminate();
    };
    const settle = (value: ZipBruteWorkerProgress) => {
      if (settled) return;
      cleanup();
      resolve(value);
    };
    const onAbort = () => {
      settle({ ...lastProgress, password: null, previewText: null, aborted: true });
    };
    if (signal !== undefined) signal.addEventListener('abort', onAbort);

    worker.onmessage = (event: MessageEvent) => {
      // abort 收口后 terminate 不撤销已入主线程队列的消息事件：迟到消息直接丢弃（reviewer P2-1）
      if (settled) return;
      const data = event.data as
        | { type: 'progress'; tried: number; total: number; password: null }
        | { type: 'done'; result: BruteProgress }
        | { type: 'error'; message: string };
      if (data.type === 'progress') {
        lastProgress = { tried: data.tried, total: data.total, password: null, previewText: null };
        onProgress?.(lastProgress);
        return;
      }
      if (data.type === 'done') {
        onProgress?.(data.result);
        settle(data.result);
        return;
      }
      // worker 侧业务错误（spec 非法/条目结构异常）：reject 给调用方展示中文错误
      if (settled) return;
      cleanup();
      reject(new Error(data.message));
    };
    worker.onerror = () => {
      // 脚本加载失败等硬错误：降级主线程路径重跑（不吞能力）；竞态下已收口则忽略。
      // 注意不走 settle（其幂等旗标已被 cleanup 置位），直接用 executor 的 resolve/reject
      if (settled) return;
      settled = true;
      signal?.removeEventListener('abort', onAbort);
      worker.terminate();
      void bruteZipPassword(bytes, entry, buildFallbackCandidates(spec), { timeBudgetMs, onProgress, signal }).then(
        fallback => resolve(signal?.aborted === true ? { ...fallback, aborted: true } : fallback),
        error => reject(error instanceof Error ? error : new Error(String(error))),
      );
    };

    // bytes 拷贝后 transfer：原视图归主线程（父组件共享），worker 拿独立副本
    const payload = new Uint8Array(bytes);
    worker.postMessage(
      { bytes: payload, entry, spec, timeBudgetMs: timeBudgetMs ?? 15000 },
      [payload.buffer],
    );
  });
};
