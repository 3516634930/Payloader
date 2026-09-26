// CTF 常用端口扫描路由（批次 WB3）：TCP connect 扫描由本地 Node 服务端执行（浏览器无 TCP 能力）。
// 与 proxy 同一信任模型：只扫用户指定的题目主机，随应用本地启动、不依赖在线服务。
// 约束：单次请求最多 600 个端口；单端口超时 300-3000ms（默认 900）；并发 64；受管理员 CTF 模块开关门禁。

import { createConnection } from 'node:net';
import { json } from './http-helpers.mjs';

const MAX_PORTS = 600;
const CONCURRENCY = 64;
const DEFAULT_TIMEOUT_MS = 900;
const HOST_PATTERN = /^[a-zA-Z0-9._-]+$/;

const parsePortList = value => {
  const ports = [];
  if (Array.isArray(value)) {
    // 数组形式同样受 MAX_PORTS 上限（reviewer P1-1：数量校验对两种形式都必须闭环）
    if (value.length > MAX_PORTS) return null;
    for (const item of value) {
      const port = Number(item);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
      ports.push(port);
    }
  } else if (value && typeof value === 'object') {
    const from = Number(value.from);
    const to = Number(value.to);
    if (!Number.isInteger(from) || !Number.isInteger(to) || from < 1 || to > 65535 || from > to) return null;
    if (to - from + 1 > MAX_PORTS) return null;
    for (let port = from; port <= to; port += 1) ports.push(port);
  } else {
    return null;
  }
  return [...new Set(ports)].sort((a, b) => a - b);
};

const scanOnePort = (host, port, timeoutMs) => new Promise(resolve => {
  const startedAt = Date.now();
  const socket = createConnection({ host, port });
  const finish = (state, detail) => {
    socket.destroy();
    resolve({ port, state, ms: Date.now() - startedAt, ...(detail ? { detail } : {}) });
  };
  socket.setTimeout(timeoutMs, () => finish('filtered', `无响应（超时 ${timeoutMs}ms）`));
  socket.on('connect', () => finish('open'));
  socket.on('error', error => {
    if (error.code === 'ECONNREFUSED') finish('closed');
    else if (error.code === 'EHOSTUNREACH' || error.code === 'ENETUNREACH') finish('filtered', '主机不可达');
    else finish('error', error.code === 'ENOTFOUND' ? '域名解析失败' : (error.message || error.code || '连接失败'));
  });
});

export const createCtfPortscanRoutes = ({ isCtfEnabled = null } = {}) => {
  const registerCtfPortscanRoutes = router => {
    router.route(['POST', 'OPTIONS'], '/api/ctf/portscan', async (request, response) => {
      response.setHeader('access-control-allow-origin', '*');
      response.setHeader('access-control-allow-methods', 'POST, OPTIONS');
      response.setHeader('access-control-allow-headers', 'content-type');
      if (request.method === 'OPTIONS') {
        response.writeHead(204);
        response.end();
        return;
      }
      if (isCtfEnabled && !(await isCtfEnabled())) {
        json(response, 403, { error: 'CTF 解题模块已被管理员关闭。' });
        return;
      }
      let spec;
      try {
        spec = JSON.parse(await new Promise((resolve, reject) => {
          // 请求体 2MB 上限（与 proxy 端点一致，防无界缓冲——reviewer P1-1）
          const chunks = [];
          let size = 0;
          request.on('data', chunk => {
            size += chunk.length;
            if (size > 2 * 1024 * 1024) {
              reject(new Error('请求体超过 2MB 上限'));
              request.destroy();
              return;
            }
            chunks.push(chunk);
          });
          request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
          request.on('error', reject);
        }));
      } catch {
        json(response, 400, { error: '请求体不是合法 JSON（或超过 2MB 上限）。' });
        return;
      }
      const host = typeof spec.host === 'string' ? spec.host.trim() : '';
      if (!host || host.length > 253 || !HOST_PATTERN.test(host)) {
        json(response, 400, { error: '目标必须是主机名或 IP（不带协议与路径）。' });
        return;
      }
      const ports = parsePortList(spec.ports);
      if (!ports || ports.length === 0) {
        json(response, 400, { error: `端口列表非法：数组（1-65535）或 {from,to} 范围，单次最多 ${MAX_PORTS} 个。` });
        return;
      }
      const timeoutMs = Math.min(Math.max(Number(spec.timeoutMs) || DEFAULT_TIMEOUT_MS, 300), 3000);
      const startedAt = Date.now();
      const results = new Array(ports.length);
      let cursor = 0;
      const worker = async () => {
        while (cursor < ports.length) {
          const index = cursor;
          cursor += 1;
          results[index] = await scanOnePort(host, ports[index], timeoutMs);
        }
      };
      await Promise.all(Array.from({ length: Math.min(CONCURRENCY, ports.length) }, worker));
      json(response, 200, {
        ok: true,
        host,
        timeoutMs,
        scanned: ports.length,
        durationMs: Date.now() - startedAt,
        results,
      });
    }, { group: 'public' });
  };
  return { registerCtfPortscanRoutes };
};
