// 公开数据快照缓存（自 data-store.mjs 收敛）：publicDataCache 单例集中读写失效；
// 写路径经 withCacheInvalidation 包裹，新增写函数不再依赖手工调用失效。

let publicDataCache;

export const readPublicDataCache = () => publicDataCache;

export const writePublicDataCache = value => {
  publicDataCache = value;
  return value;
};

export const invalidatePublicDataCache = () => {
  publicDataCache = undefined;
};

// 同步 throw 保持同步抛出（如 resetDefaultData 的参数校验）；写路径返回 promise 时，失效排在写完成之后
export const withCacheInvalidation = work => (...args) => {
  const result = work(...args);
  if (result && typeof result.then === 'function') {
    return result.then(value => {
      invalidatePublicDataCache();
      return value;
    });
  }
  invalidatePublicDataCache();
  return result;
};
