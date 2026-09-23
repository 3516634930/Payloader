import type { CategoryId, Detection, Direction, Operation, OperationId, ParamKey } from './types';
import { categories } from './types';
import { defaultParams, operations } from './operations';
import { cryptoJsBlockCipherOperationIds, gsm7DefaultAlphabet, gsm7ExtensionAlphabet, isCryptoJsCipherOperation, isNobleAesOperation, isNobleNonceOperation, isOtpOperation, jwtHmacHashAlgorithms, otpHashAlgorithms } from './alphabets';
import { factorSmallRsaModulus, inferRsaParamsFromText } from './rsa';
import { inferDlpFromText } from './prng';
import { detectInput, detectFlagFormats, findFlagAutoRanges, extractPureDecodeResult, smartDecode, stripCandidateSection } from './smartDecode';
import type { FlagAutoRange, FlagFormatHit } from './smartDecode';
import { transform } from './transform';
import { buildCtfGroups, buildCtfMenus, buildPentestGroups, isOperationVisible, operationAudience } from './audience';
import type { Audience, CodecGroupData, CodecMenu } from './audience';
import { parityBaseVectors } from './parityBases';
import { parityCharVectors } from './parityCharCodes';
import { parityCnVectors } from './parityChinese';
import { parityKeyedVectors } from './parityKeyed';
import { parityNumVectors } from './parityNumeric';
import { parityProbes } from './smartDecode';
import { label } from './bases';

// 重数据注水：609KB 的古典密码 quadgram 评分表拆在 ngramTableData.ts（仅被动态 import，
// vite 拆为并行异步 chunk，不进 CodecWorkbench 主 chunk）。实现放在 heavyData.ts 与桶解耦，
// 组件可绕开桶直接 import；此处 re-export 保持既有导出面（verify:codec 白名单不变）。
export { hydrateCodecHeavyData } from './heavyData';

export {
  buildCtfGroups,
  buildCtfMenus,
  buildPentestGroups,
  categories,
  cryptoJsBlockCipherOperationIds,
  defaultParams,
  detectFlagFormats,
  detectInput,
  extractPureDecodeResult,
  factorSmallRsaModulus,
  findFlagAutoRanges,
  gsm7DefaultAlphabet,
  gsm7ExtensionAlphabet,
  inferDlpFromText,
  inferRsaParamsFromText,
  isCryptoJsCipherOperation,
  isNobleAesOperation,
  isNobleNonceOperation,
  isOperationVisible,
  isOtpOperation,
  jwtHmacHashAlgorithms,
  label,
  operationAudience,
  operations,
  otpHashAlgorithms,
  parityBaseVectors,
  parityCharVectors,
  parityCnVectors,
  parityKeyedVectors,
  parityNumVectors,
  parityProbes,
  smartDecode,
  stripCandidateSection,
  transform,
};

export type {
  Audience,
  CategoryId,
  CodecGroupData,
  CodecMenu,
  Detection,
  Direction,
  FlagAutoRange,
  FlagFormatHit,
  Operation,
  OperationId,
  ParamKey,
};
