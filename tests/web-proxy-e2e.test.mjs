// Web 请求链路真链路测试（批次 WB2）：进程内起两台 server——
// ① 目标模拟 server（实现布尔盲注/联合注入/目录探测的题目语义）
// ② 真产品代理（routes-ctf-proxy.mjs 的 Router 实例）
// 再 configureProxy 注入 node fetch + 代理地址，跑 sendViaProxy → blindBooleanExtract /
// unionDump / probeDirectories 全链路，断言自动解出 flag（真题风格端到端）。
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';
import { Router } from '../server/router.mjs';
import { createCtfProxyRoutes } from '../server/routes-ctf-proxy.mjs';

const { loadModule } = createTsModuleLoader();
const web = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'webTools.ts'));

const startServer = handler => new Promise(resolve => {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
});

const FLAG_BLIND = 'flag{blind_auto_ok}';
const FLAG_UNION = 'flag{union_dump_ok}';


test('端到端：布尔盲注自动化经真代理解出 flag', async () => {
  // ① 目标模拟：/?q=<payload>；ASCII(SUBSTR((SELECT flag...),N,1))>K → 200/500
  const target = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const q = decodeURIComponent(url.searchParams.get('q') ?? '');
    const match = q.match(/ASCII\(SUBSTR\(\(SELECT flag FROM flags LIMIT 1\),(\d+),1\)\)>(\d+)/);
    if (!match) { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><body>Welcome</body></html>'); return; }
    const position = Number(match[1]);
    const threshold = Number(match[2]);
    const charCode = position <= FLAG_BLIND.length ? FLAG_BLIND.charCodeAt(position - 1) : 0;
    if (charCode > threshold) { res.writeHead(200); res.end('success-page'); }
    else { res.writeHead(500); res.end('error-page'); }
  });
  // ② 真代理
  const router = new Router();
  createCtfProxyRoutes().registerCtfProxyRoutes(router);
  const proxy = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    void router.dispatch(req, res, url, 'public', {}).then(dispatched => {
      if (!dispatched) { res.writeHead(404); res.end(); }
    });
  });
  try {
    web.configureProxy(fetch, `http://127.0.0.1:${proxy.port}`);
    const result = await web.blindBooleanExtract({
      urlTemplate: `http://127.0.0.1:${target.port}/?q={Q}`,
      successStatus: 200,
      stopChars: '}',
    });
    assert.equal(result.value, FLAG_BLIND + '', `盲注结果：${result.value}（${result.requests} 请求）`);
    assert.equal(result.stoppedAt, 'stop-char');
    assert.ok(result.requests > 20 && result.requests < 400, `请求数异常：${result.requests}`);
  } finally {
    target.server.close();
    proxy.server.close();
  }
});

test('端到端：联合注入自动脱库（列数/回显位/库名/表/数据）', async () => {
  const COLUMN_COUNT = 3;
  const reflectHtml = value => `<html><body><div class="content">${value}</div></body></html>`;
  const target = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const q = decodeURIComponent(url.searchParams.get('q') ?? '');
    res.setHeader('content-type', 'text/html');
    // ORDER BY n：n<=3 正常，>3 报错
    const orderMatch = q.match(/ORDER BY (\d+)-- -$/);
    if (orderMatch) {
      if (Number(orderMatch[1]) > COLUMN_COUNT) { res.writeHead(500); res.end('SQL syntax error'); }
      else { res.writeHead(200); res.end(reflectHtml('normal-list')); }
      return;
    }
    // UNION SELECT (expr) 形态：把 (expr) 的结果放回显位
    const unionMatch = q.match(/UNION SELECT (.+)-- -$/);
    if (unionMatch) {
      const selectList = unionMatch[1];
      if (!selectList.includes('(')) {
        // 回显位探测形态（纯 marker 无子查询）：marker 原样回显
        res.writeHead(200);
        res.end(reflectHtml(selectList));
        return;
      }
      // marker 拼接法形态：CONCAT('77Nx',(子查询)) 占回显位（子查询可含逗号与嵌套括号——贪婪回退法）
      const concatRe = /CONCAT\('(77\d+x)',\((.*)\)\)(?:,|$)/;
      const tagged = selectList.match(concatRe) ?? selectList.match(/'(77\d+x)'\|\|\(((?:[^()]|\([^()]*\))+)\)/);
      if (tagged) {
        const markerPrefix = tagged[1];
        const query = tagged[2];
        let value = '';
        if (query === 'database()') value = 'ctfdb';
        else if (query.startsWith('SELECT GROUP_CONCAT(table_name)')) value = 'flags,users';
        else if (query.startsWith('SELECT GROUP_CONCAT(column_name)')) value = 'id,flag';
        else if (query.startsWith('SELECT GROUP_CONCAT(CONCAT_WS')) value = `1:${FLAG_UNION}`;
        else value = query;
        res.writeHead(200);
        res.end(reflectHtml(markerPrefix + value));
        return;
      }
    }
    res.writeHead(200);
    res.end(reflectHtml('default'));
  });
  const router = new Router();
  createCtfProxyRoutes().registerCtfProxyRoutes(router);
  const proxy = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    void router.dispatch(req, res, url, 'public', {}).then(dispatched => {
      if (!dispatched) { res.writeHead(404); res.end(); }
    });
  });
  try {
    web.configureProxy(fetch, `http://127.0.0.1:${proxy.port}`);
    const result = await web.unionDump({
      baseUrl: `http://127.0.0.1:${target.port}/?q=1 {INJ}`,
      database: 'mysql',
    });
    assert.equal(result.ok, true, result.error);
    assert.equal(result.columnCount, COLUMN_COUNT);
    assert.ok((result.reflectPositions ?? []).length >= 1);
    assert.equal(result.currentDatabase, 'ctfdb');
    // 沙箱跨 realm 数组须 Array.from 转换（AGENTS.md 坑位）
    const tables = Array.from(result.tables ?? []);
    assert.deepEqual(tables, ['flags', 'users']);
    assert.deepEqual(Array.from(result.columns?.flags ?? []), ['id', 'flag']);
    assert.equal(result.rows?.[0]?.flag, FLAG_UNION);
  } finally {
    target.server.close();
    proxy.server.close();
  }
});

test('端到端：目录探测命中敏感路径', async () => {
  const target = await startServer((req, res) => {
    const sensitive = { '/flag.txt': 'flag{dir_found}', '/robots.txt': 'Disallow: /admin', '/www.zip': 'PK'.repeat(5000), '/.git/config': '[core]' };
    if (sensitive[req.url]) { res.writeHead(200); res.end(sensitive[req.url]); return; }
    if (req.url === '/admin') { res.writeHead(301, { location: '/' }); res.end(); return; }
    res.writeHead(404); res.end('not found');
  });
  const router = new Router();
  createCtfProxyRoutes().registerCtfProxyRoutes(router);
  const proxy = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    void router.dispatch(req, res, url, 'public', {}).then(dispatched => {
      if (!dispatched) { res.writeHead(404); res.end(); }
    });
  });
  try {
    web.configureProxy(fetch, `http://127.0.0.1:${proxy.port}`);
    const hits = await web.probeDirectories(`http://127.0.0.1:${target.port}`);
    const paths = hits.map(h => h.path);
    assert.ok(paths.includes('/flag.txt'), `应命中 /flag.txt，实际：${paths.join(',')}`);
    assert.ok(paths.includes('/robots.txt'));
    assert.ok(paths.includes('/.git/config'));
    assert.ok(paths.includes('/admin'));
    assert.ok(!paths.some(p => p === '/login.php'), '404 不应出现');
  } finally {
    target.server.close();
    proxy.server.close();
  }
});

test('代理端点：非法协议拒绝 + 超时返回 TIMEOUT', async () => {
  const router = new Router();
  createCtfProxyRoutes().registerCtfProxyRoutes(router);
  const proxy = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    void router.dispatch(req, res, url, 'public', {}).then(dispatched => {
      if (!dispatched) { res.writeHead(404); res.end(); }
    });
  });
  try {
    web.configureProxy(fetch, `http://127.0.0.1:${proxy.port}`);
    const bad = await web.sendViaProxy({ url: 'file:///etc/passwd', method: 'GET', headers: {}, body: null });
    // 端点 4xx 透传（WB3 起带端点 HTTP 状态码）：非法协议 → 代理端点 400
    assert.equal(bad.status, 400);
    assert.match(bad.error, /http/);
    const timeout = await web.sendViaProxy({ url: 'http://10.255.255.1:81/', method: 'GET', headers: {}, body: null, timeoutMs: 2000 });
    assert.equal(timeout.statusText, 'TIMEOUT');
  } finally {
    proxy.server.close();
  }
});
