import {
  isOtpOperation,
  jwtHmacHashAlgorithms,
  label,
  otpHashAlgorithms,
} from '../../utils/codec';
import type { Direction, Operation, OperationId, ParamKey } from '../../utils/codec';
import { parityVariantDefaults, parityVariantOptions } from './variantOptions';

// 动作项的（操作 × 方向）标记：随波逐流【xx解密】方括号标记法，decode 优先（CTF 主链路），
// 仅支持一侧的操作只出一个动作；smart-decode 无方向语义，直接用名称。
export interface WorkbenchAction {
  id: OperationId;
  direction: Direction;
  mark: string;
  summary: { zh: string; en: string };
}

export const actionsOfOperation = (operation: Operation, language: 'zh' | 'en'): WorkbenchAction[] => {
  const actions: WorkbenchAction[] = [];
  const name = label(operation.name, language);
  if (operation.supportsDecode !== false) {
    const mark = operation.id === 'smart-decode'
      ? (language === 'zh' ? '【智能识别】' : '[Smart identify]')
      : language === 'zh' ? `【${name}解密】` : `[${name} dec]`;
    actions.push({ id: operation.id, direction: 'decode', mark, summary: operation.summary });
  }
  if (operation.supportsEncode !== false) {
    actions.push({ id: operation.id, direction: 'encode', mark: language === 'zh' ? `【${name}加密】` : `[${name} enc]`, summary: operation.summary });
  }
  return actions;
};

// 现代密码菜单的单方向条目：解密优先（CTF 主链路），仅支持编码侧的操作（hash/hmac/aes-cmac 等）
// 回退唯一方向——条目数减半，方向切换保留在工作台的编码/解码按钮。
export const primaryActionOfOperation = (operation: Operation, language: 'zh' | 'en'): WorkbenchAction => {
  const actions = actionsOfOperation(operation, language);
  return actions.find(action => action.direction === 'decode') ?? actions[0];
};

export const hashAlgorithmValueOf = (params: Record<ParamKey, string>, operationId: OperationId | ''): string => operationId !== '' && isOtpOperation(operationId) && !otpHashAlgorithms.has(params.hashAlgorithm)
  ? 'sha1'
  : operationId === 'jwt-hmac' && !jwtHmacHashAlgorithms.has(params.hashAlgorithm)
    ? 'sha256'
    : params.hashAlgorithm;

export const variantValueOf = (params: Record<ParamKey, string>, operationId: OperationId | ''): string => operationId === 'rabbit' && params.variant === 'hex'
  ? 'special'
  : operationId === 'hexagram' && params.variant !== 'names' && params.variant !== 'symbols'
    ? 'names'
  : parityVariantDefaults[operationId] && !parityVariantOptions[operationId]?.some(option => option.value === params.variant)
    ? parityVariantDefaults[operationId]
  : params.variant;
