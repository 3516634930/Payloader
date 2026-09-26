// CTF 模块管理员开关（批次 TG）测试：
// ① sanitizeSettings 白名单往返（默认开/false 保留/脏值回落开）
// ② proxy 端点门禁：关闭→403 中文错误；开启→正常转发
// ③ portscan 端点：本地随机端口 open / 未监听端口 closed / 非法 host 400 / 超 600 端口 400 / 非法 JSON 400 / 门禁 403 / OPTIONS 预检 204
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import { Router } from '../server/router.mjs';
import { sanitizeSettings } from '../server/sanitize.mjs';
import { createCtfProxyRoutes } from '../server/routes-ctf-proxy.mjs';
import { createCtfPortscanRoutes } from '../server/routes-ctf-portscan.mjs';

const startServer = handler => new Promise(resolve => {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
});

const proxyOf = async ({ ctfEnabled = true, withPortscan = true } = {}) => {
  const router = new Router();
  const isCtfEnabled = async () => ctfEnabled;
  createCtfProxyRoutes({ isCtfEnabled }).registerCtfProxyRoutes(router);
  if (withPortscan) createCtfPortscanRoutes({ isCtfEnabled }).registerCtfPortscanRoutes(router);
  return startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    void router.dispatch(req, res, url, 'public', {}).then(dispatched => {
      if (!dispatched) { res.writeHead(404); res.end(); }
    });
  });
};

const post = async (port, pathname, payload) => fetch(`http://127.0.0.1:${port}${pathname}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(payload),
});

test('sanitizeSettings：ctfEnabled 默认关、true 保留、脏值回落关（需管理员显式开启）', () => {
  assert.equal(sanitizeSettings({}).ctfEnabled, false);
  assert.equal(sanitizeSettings({ ctfEnabled: false }).ctfEnabled, false);
  assert.equal(sanitizeSettings({ ctfEnabled: true }).ctfEnabled, true);
  assert.equal(sanitizeSettings({ ctfEnabled: 'nope' }).ctfEnabled, false);
  assert.equal(sanitizeSettings(null).ctfEnabled, false);
});

test('proxy 门禁：开关关闭 → 403 中文错误；开启 → 正常转发目标响应', async () => {
  const target = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('target-ok');
  });
  const off = await proxyOf({ ctfEnabled: false });
  const on = await proxyOf({ ctfEnabled: true, withPortscan: false });
  try {
    const spec = { url: `http://127.0.0.1:${target.port}/`, method: 'GET', headers: {}, body: null };
    const denied = await post(off.port, '/api/ctf/proxy', spec);
    assert.equal(denied.status, 403);
    const deniedBody = await denied.json();
    assert.match(deniedBody.error, /CTF 解题模块已被管理员关闭/);
    const allowed = await post(on.port, '/api/ctf/proxy', spec);
    assert.equal(allowed.status, 200);
    const allowedBody = await allowed.json();
    assert.equal(allowedBody.status, 200);
    assert.equal(allowedBody.bodyText, 'target-ok');
  } finally {
    target.server.close();
    off.server.close();
    on.server.close();
  }
});

test('portscan：本地端口 open、未监听 closed、非法 host/端口列表 400、非 JSON 400、OPTIONS 204', async () => {
  const listener = net.createServer(socket => socket.end());
  const listenPort = await new Promise(resolve => {
    listener.listen(0, '127.0.0.1', () => resolve(listener.address().port));
  });
  const proxy = await proxyOf({ ctfEnabled: true });
  try {
    const ok = await post(proxy.port, '/api/ctf/portscan', { host: '127.0.0.1', ports: [listenPort, 1] });
    assert.equal(ok.status, 200);
    const body = await ok.json();
    assert.equal(body.ok, true);
    const states = Object.fromEntries(body.results.map(r => [r.port, r.state]));
    assert.equal(states[listenPort], 'open');
    assert.equal(states[1], 'closed');
    assert.ok(body.durationMs >= 0);

    const badHost = await post(proxy.port, '/api/ctf/portscan', { host: 'http://x/', ports: [80] });
    assert.equal(badHost.status, 400);
    const badPorts = await post(proxy.port, '/api/ctf/portscan', { host: '127.0.0.1', ports: { from: 1, to: 700 } });
    assert.equal(badPorts.status, 400);
    // reviewer P1-1 回归：数组形式同样受 600 上限
    const tooManyArray = await post(proxy.port, '/api/ctf/portscan', { host: '127.0.0.1', ports: Array.from({ length: 601 }, (_, i) => i + 1) });
    assert.equal(tooManyArray.status, 400);
    const emptyPorts = await post(proxy.port, '/api/ctf/portscan', { host: '127.0.0.1', ports: [] });
    assert.equal(emptyPorts.status, 400);

    const notJson = await fetch(`http://127.0.0.1:${proxy.port}/api/ctf/portscan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not-json',
    });
    assert.equal(notJson.status, 400);

    const preflight = await fetch(`http://127.0.0.1:${proxy.port}/api/ctf/portscan`, { method: 'OPTIONS' });
    assert.equal(preflight.status, 204);
  } finally {
    listener.close();
    proxy.server.close();
  }
});

test('portscan 门禁：开关关闭 → 403', async () => {
  const proxy = await proxyOf({ ctfEnabled: false });
  try {
    const denied = await post(proxy.port, '/api/ctf/portscan', { host: '127.0.0.1', ports: [80] });
    assert.equal(denied.status, 403);
    const body = await denied.json();
    assert.match(body.error, /已被管理员关闭/);
  } finally {
    proxy.server.close();
  }
});
