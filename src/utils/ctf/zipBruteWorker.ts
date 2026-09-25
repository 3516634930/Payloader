// ZIP 密码爆破 Web Worker（批次 KW：TD-批次KP-1 Worker 化）。
// 紧循环跑满单核（yieldEvery: 0 免 setTimeout 让步，吞吐从 ~3.3 万口令/s 提升一个数量级），
// UI 主线程零阻塞；进度按 250ms 节流 postMessage 回传，命中/耗尽/异常即收口。
// 消息协议（请求）：{ bytes: Uint8Array, entry: ZipEncryptedEntry, spec: ZipBruteSpec, timeBudgetMs: number }
// 消息协议（响应）：{ type: 'progress'|'done'|'error', ... }
import { bruteZipPassword, dictionaryCandidates, maskCandidates } from './zipBrute';
import type { BruteProgress, ZipEncryptedEntry } from './zipBrute';

// 候选源描述：结构化可 postMessage 传输（Iterable 不能跨线程），worker 内重建生成器
export interface ZipBruteSpec {
  kind: 'dictionary' | 'list' | 'mask';
  list?: string[];
  charset?: string;
  minLength?: number;
  maxLength?: number;
}

interface WorkerRequest {
  bytes: Uint8Array;
  entry: ZipEncryptedEntry;
  spec: ZipBruteSpec;
  timeBudgetMs: number;
}

type WorkerResponse =
  | { type: 'progress'; tried: number; total: number; password: null }
  | { type: 'done'; result: BruteProgress }
  | { type: 'error'; message: string };

// 不引 webworker lib（与 DOM lib 同用会全局冲突）：以最小结构类型描述 worker 作用域
const workerScope = self as unknown as {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage(message: WorkerResponse): void;
};

const buildCandidates = (spec: ZipBruteSpec): Iterable<string> => {
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

workerScope.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const { bytes, entry, spec, timeBudgetMs } = event.data;
  try {
    const result = await bruteZipPassword(bytes, entry, buildCandidates(spec), {
      timeBudgetMs,
      yieldEvery: 0,
      onProgress: progress => {
        if (progress.password === null) {
          workerScope.postMessage({ type: 'progress', tried: progress.tried, total: progress.total, password: null });
        }
      },
    });
    workerScope.postMessage({ type: 'done', result });
  } catch (error) {
    workerScope.postMessage({ type: 'error', message: String((error as Error)?.message ?? error) });
  }
};
