// 重数据注水通道：与桶（index.ts）解耦，供组件绕开桶直接 import，
// 避免"只要 hydrate 就拖全引擎"的反向耦合。桶内 re-export 保持既有导出面。
import { injectClassicalNgramTable } from './ngram';

let heavyDataPromise: Promise<void> | null = null;
export const hydrateCodecHeavyData = (): Promise<void> => {
  heavyDataPromise ??= import('./ngramTableData').then(module => {
    injectClassicalNgramTable(module.CLASSICAL_NGRAM_TABLE_B64);
  });
  return heavyDataPromise;
};
