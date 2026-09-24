import { useEffect, useMemo, useRef, useState } from 'react';
import { buildCtfGroups, isOperationVisible } from '../../utils/codec/audience';
import {
  detectFlagFormats,
  detectInput,
  extractPureDecodeResult,
  smartDecode,
  stripCandidateSection,
} from '../../utils/codec/smartDecode';
import { hydrateCodecHeavyData } from '../../utils/codec/heavyData';
import type { OperationId } from '../../utils/codec/types';
import { useDebouncedCallback } from '../../utils/debounce';

export const AUTO_DECODE_LIMIT = 20000;

let cipherOperationIdsCache: Set<OperationId> | null = null;
const cipherOperationIds = () => {
  cipherOperationIdsCache ??= new Set<OperationId>(buildCtfGroups().flatMap(group => group.operations.map(item => item.id)));
  return cipherOperationIdsCache;
};

export interface SmartIdentifyState {
  detections: ReturnType<typeof detectInput>;
  flagHits: ReturnType<typeof detectFlagFormats>;
  output: string;
  displayOutput: string;
  pureResult: string;
  error: string;
  running: boolean;
  autoDisabled: boolean;
  clear: () => void;
}

// 智能识别状态机（自 CtfToolkit 抽出，hero 退役后供 SmartDetectBar 与非密码域折叠 hero 共用）：
// 粘贴后 350ms 防抖自动多层解码；超长输入（>20000 字符）不自动跑；评分表 chunk 就绪后再执行。
export const useSmartIdentify = (input: string): SmartIdentifyState => {
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const runTokenRef = useRef(0);

  const detections = useMemo(
    // 形状检测只依赖前缀特征：截断后再跑正则组，避免每次键入对全量文本做 60+ 次匹配。
    () => detectInput(input.slice(0, 4096)).filter(detection => cipherOperationIds().has(detection.id)),
    [input],
  );
  const displayOutput = useMemo(() => (error ? '' : stripCandidateSection(output)), [output, error]);
  const flagHits = useMemo(() => (error ? [] : detectFlagFormats(displayOutput)), [displayOutput, error]);
  const pureResult = useMemo(() => (output ? extractPureDecodeResult(output) : ''), [output]);

  const runSmartDecode = async () => {
    const token = runTokenRef.current + 1;
    runTokenRef.current = token;
    setRunning(true);
    setError('');
    try {
      // 评分表（609KB 异步 chunk）就绪后再跑：幂等，mount 预热后此处几乎总是立即返回。
      await hydrateCodecHeavyData();
      if (runTokenRef.current !== token) return;
      const result = await smartDecode(input);
      if (runTokenRef.current !== token) return;
      setOutput(result);
    } catch (reason) {
      if (runTokenRef.current !== token) return;
      setOutput('');
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (runTokenRef.current === token) setRunning(false);
    }
  };

  // 重数据预热：挂载即并行拉起评分表 chunk，不阻塞首屏渲染。
  useEffect(() => {
    void hydrateCodecHeavyData();
  }, []);

  const debounced = useDebouncedCallback(() => {
    void runSmartDecode();
  }, 350);
  useEffect(() => {
    if (!input.trim() || input.length > AUTO_DECODE_LIMIT) {
      debounced.cancel();
      return;
    }
    debounced.run();
    return () => debounced.cancel();
  }, [input, debounced]);

  const clear = () => {
    runTokenRef.current += 1;
    setOutput('');
    setError('');
    setRunning(false);
  };

  return {
    detections,
    flagHits,
    output,
    displayOutput,
    pureResult,
    error,
    running,
    autoDisabled: input.length > AUTO_DECODE_LIMIT,
    clear,
  };
};

export const isCipherDetection = (operationId: OperationId) => isOperationVisible(operationId, 'ctf');
