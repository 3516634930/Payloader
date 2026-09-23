// 客户端限流与可信代理解析（自 admin-server.mjs 拆出）：限流桶状态经 createRateLimiter() 工厂创建，
// 隔离粒度跟随宿主实例的组合（admin-server 模块级单组合根 + 测试侧唯一 URL import 各得独立状态）。

import { isIP } from 'node:net';
import { baseResponseHeaders } from './http-helpers.mjs';

export const createRateLimiter = () => {
  const rateBuckets = new Map();
  const adminRequestLimit = { windowMs: 60_000, max: 300 };
  const failedAuthLimit = { windowMs: 60_000, max: 12 };
  const failedLoginLimit = { windowMs: 60_000, max: 8 };
  const trustedProxyConfig = String(process.env.PAYLOADER_TRUSTED_PROXIES || '')
    .split(',')
    .map(item => item.trim().toLowerCase())
    .filter(Boolean);
  const trustedProxyAddresses = new Set();
  let trustLoopbackProxies = false;
  for (const entry of trustedProxyConfig) {
    if (entry === 'loopback') {
      trustLoopbackProxies = true;
    } else if (isIP(entry)) {
      trustedProxyAddresses.add(entry);
    } else {
      throw new Error(`Invalid PAYLOADER_TRUSTED_PROXIES entry: ${entry}`);
    }
  }

  const normalizeIpAddress = value => {
  let address = String(value || '').trim().toLowerCase();
  if (address.startsWith('[') && address.endsWith(']')) address = address.slice(1, -1);
  if (address.startsWith('::ffff:') && isIP(address.slice(7)) === 4) address = address.slice(7);
  return isIP(address) ? address : '';
};

  const isLoopbackAddress = address => address === '127.0.0.1' || address === '::1';

  const isTrustedProxyAddress = address => (
  trustedProxyAddresses.has(address) || (trustLoopbackProxies && isLoopbackAddress(address))
);

  const forwardedClientAddress = (request, peerAddress) => {
  if (!isTrustedProxyAddress(peerAddress)) return '';
  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded !== 'string' || forwarded.length > 2048) return '';
  const chain = forwarded.split(',').map(normalizeIpAddress);
  if (!chain.length || chain.some(address => !address)) return '';
  let resolved = peerAddress;
  for (let index = chain.length - 1; index >= 0 && isTrustedProxyAddress(resolved); index -= 1) {
    resolved = chain[index];
  }
  return resolved === peerAddress ? '' : resolved;
};

  const clientKey = request => {
  const peerAddress = normalizeIpAddress(request.socket.remoteAddress) || 'local';
  return forwardedClientAddress(request, peerAddress) || peerAddress;
};

  const checkRateLimit = (request, response, scope, limit) => {
  const key = `${scope}:${clientKey(request)}`;
  const timestamp = Date.now();
  const bucket = rateBuckets.get(key);
  const current = bucket && timestamp - bucket.startedAt < limit.windowMs
    ? bucket
    : { startedAt: timestamp, count: 0 };
  current.count += 1;
  rateBuckets.set(key, current);
  if (rateBuckets.size > 1_000) {
    const maxWindow = Math.max(adminRequestLimit.windowMs, failedAuthLimit.windowMs);
    for (const [itemKey, item] of rateBuckets.entries()) {
      if (timestamp - item.startedAt >= maxWindow) rateBuckets.delete(itemKey);
    }
  }
  if (current.count <= limit.max) return true;
  respondTooManyRequests(response, scope, limit);
  return false;
};

// 发送 429 但不改变限流计数——用于并发闸等需要廉价拒绝的路径；checkRateLimit 超限时也复用同一响应块。
  const respondTooManyRequests = (response, scope, limit) => {
  const contentType = scope.includes('login') || scope.includes('admin') ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8';
  response.writeHead(429, {
    ...baseResponseHeaders,
    'content-type': contentType,
    'cache-control': 'no-store',
    'retry-after': String(Math.ceil(limit.windowMs / 1000)),
  });
  response.end(contentType.startsWith('application/json') ? JSON.stringify({ error: '请求过于频繁，请稍后再试' }) : 'Too many requests');
};

  const clearRateLimit = (request, scope) => {
  rateBuckets.delete(`${scope}:${clientKey(request)}`);
};

  return {
    adminRequestLimit,
    checkRateLimit,
    clearRateLimit,
    clientKey,
    failedAuthLimit,
    failedLoginLimit,
    respondTooManyRequests,
  };
};
