// CTF Web 请求代理路由（批次 WB2）：浏览器端 Repeater/盲注自动化/目录探测统一经此转发，
// 绕开浏览器 CORS（Node 侧无同源限制）。随应用本地启动，不依赖任何在线服务。
// 边界：仅 http/https；响应体 2MB 截断；超时默认 15s；请求并发不限制（CTF 目标是用户自己的题目环境）。

import { json } from './http-helpers.mjs';

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;

const readRequestBody = request => new Promise((resolve, reject) => {
  const chunks = [];
  let size = 0;
  request.on('data', chunk => {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      reject(new Error('请求体超过 2MB 上限'));
      request.destroy();
      return;
    }
    chunks.push(chunk);
  });
  request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  request.on('error', reject);
});

export const createCtfProxyRoutes = () => {
  const registerCtfProxyRoutes = router => {
    router.route(['POST', 'OPTIONS'], '/api/ctf/proxy', async (request, response) => {
      // CORS 预检（dev 前端在 5173、Electron 壳内同源直连）
      response.setHeader('access-control-allow-origin', '*');
      response.setHeader('access-control-allow-methods', 'POST, OPTIONS');
      response.setHeader('access-control-allow-headers', 'content-type');
      if (request.method === 'OPTIONS') {
        response.writeHead(204);
        response.end();
        return;
      }
      let spec;
      try {
        spec = JSON.parse(await readRequestBody(request));
      } catch {
        json(response, 400, { error: '请求体不是合法 JSON。' });
        return;
      }
      const { url, method = 'GET', headers = {}, body = null, timeoutMs = DEFAULT_TIMEOUT_MS } = spec;
      if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) {
        json(response, 400, { error: '目标必须是 http/https URL。' });
        return;
      }
      const startedAt = Date.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Math.min(Math.max(timeoutMs, 1000), 60_000));
      try {
        const fetchHeaders = { ...headers };
        // Node fetch 要求 host 头与 URL 一致，删掉可能带错的后端不会用到的问题头
        delete fetchHeaders.host;
        const response_ = await fetch(url, {
          method: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].includes(method) ? method : 'GET',
          headers: fetchHeaders,
          body: body === null || body === '' ? undefined : body,
          redirect: 'manual',
          signal: controller.signal,
        });
        const responseHeaders = {};
        response_.headers.forEach((value, name) => { responseHeaders[name] = value; });
        let bodyText = '';
        if (method !== 'HEAD') {
          const buffer = Buffer.from(await response_.arrayBuffer());
          bodyText = buffer.subarray(0, MAX_BODY_BYTES).toString('utf8');
          if (buffer.length > MAX_BODY_BYTES) bodyText += `\n…（截断，响应体共 ${buffer.length} 字节）`;
        }
        json(response, 200, {
          ok: response_.ok,
          status: response_.status,
          statusText: response_.statusText,
          headers: responseHeaders,
          bodyText,
          elapsedMs: Date.now() - startedAt,
          finalUrl: response_.url,
        });
      } catch (error) {
        const aborted = error.name === 'AbortError';
        json(response, 200, {
          ok: false,
          status: 0,
          statusText: aborted ? 'TIMEOUT' : 'NETWORK_ERROR',
          headers: {},
          bodyText: '',
          elapsedMs: Date.now() - startedAt,
          error: aborted
            ? `请求超时（${Math.min(Math.max(timeoutMs, 1000), 60_000)}ms）`
            : `请求失败：${error.cause?.message || error.message || String(error)}`,
        });
      } finally {
        clearTimeout(timer);
      }
    }, { group: 'public' });
  };
  return { registerCtfProxyRoutes };
};
