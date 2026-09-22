import type { CategoryId, Detection, Direction, Operation, OperationId, ParamKey } from './types';
import { categories } from './types';
import { defaultParams, operations } from './operations';
import { cryptoJsBlockCipherOperationIds, gsm7DefaultAlphabet, gsm7ExtensionAlphabet, isCryptoJsCipherOperation, isNobleAesOperation, isNobleNonceOperation, isOtpOperation, jwtHmacHashAlgorithms, otpHashAlgorithms } from './alphabets';
import { factorSmallRsaModulus, inferRsaParamsFromText } from './rsa';
import { inferDlpFromText } from './prng';
import { detectInput, detectFlagFormats, findFlagAutoRanges, smartDecode, stripCandidateSection } from './smartDecode';
import type { FlagAutoRange, FlagFormatHit } from './smartDecode';
import { transform } from './transform';
import { buildCtfGroups, buildCtfMenus, buildPentestGroups, isOperationVisible, operationAudience } from './audience';
import type { Audience, CodecGroupData, CodecMenu } from './audience';
import { label } from './bases';

export {
  buildCtfGroups,
  buildCtfMenus,
  buildPentestGroups,
  categories,
  cryptoJsBlockCipherOperationIds,
  defaultParams,
  detectFlagFormats,
  detectInput,
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
