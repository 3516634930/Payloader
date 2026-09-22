// 批次 O（随波逐流操作对齐）共享契约：五个 parity 模块（Base/Rot、字符类、中文类、带key、进制工具）
// 统一从这里取向量与形状探针类型，verify:codec 数据驱动回归块按同一结构消费。
import type { Direction, OperationId, ParamKey } from './types';

// 形状探针：高特征密文的智能识别谓词，与模块内码表同源（参照 chineseCiphers.ts looksLike* 模式）。
export interface ParityShapeProbe {
  id: OperationId;
  label: string;
  test: (value: string) => boolean;
}

// 回归向量：cipher 有值 = 权威向量（实现处注释必须给来源 URL）；无值 = 自造样本 round-trip。
// 单向（只解不编）操作必须给 direction: 'decode' 且同时提供 cipher 与 plain。
export interface ParityVector {
  id: OperationId;
  plain: string;
  cipher?: string;
  direction?: Direction;
  params?: Partial<Record<ParamKey, string>>;
}
