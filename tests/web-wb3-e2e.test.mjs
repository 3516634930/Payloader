// WB3 新能力真链路测试：网页查看（XFF 伪造）/Robots 解析/SQL 注入自动检测/端口扫描。
// 复用 WB2 模式：进程内起目标模拟 server + 真产品 Router（proxy + portscan 路由）+ configureProxy 注入。
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';
import { Router } from '../server/router.mjs';
import { createCtfProxyRoutes } from '../server/routes-ctf-proxy.mjs';
import { createCtfPortscanRoutes } from '../server/routes-ctf-portscan.mjs';

const { loadModule } = createTsModuleLoader();
const web = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'webTools.ts'));

const startServer = handler => new Promise(resolve => {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
});

const startProxy = async () => {
  const router = new Router();
  createCtfProxyRoutes({ isCtfEnabled: async () => true }).registerCtfProxyRoutes(router);
  createCtfPortscanRoutes({ isCtfEnabled: async () => true }).registerCtfPortscanRoutes(router);
  const proxy = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    void router.dispatch(req, res, url, 'public', {}).then(dispatched => {
      if (!dispatched) { res.writeHead(404); res.end(); }
    });
  });
  web.configureProxy(fetch, `http://127.0.0.1:${proxy.port}`);
  return proxy;
};

test('端到端：GET 查看网页（XFF 伪造 + 链接/表单/flag 提取）', async () => {
  const target = await startServer((req, res) => {
    if (req.url === '/page') {
      const xff = req.headers['x-forwarded-for'] ?? '';
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(
        `<html><body>hello ${xff}` +
        `<a href="/login">login</a><a href="https://ext.example/x">ext</a>` +
        `<form action="/search" method="post"><input name="q"><input id="kw"><select name="t"></select></form>` +
        `secret: flag{page_view_ok}</body></html>`,
      );
      return;
    }
    res.writeHead(404); res.end('nf');
  });
  const proxy = await startProxy();
  try {
    const plain = await web.fetchPageView({ url: `http://127.0.0.1:${target.port}/page` });
    assert.equal(plain.status, 200);
    assert.ok(plain.ok, 'HTTP 200 应 ok=true（⑧段 ok 语义修复）');
    assert.ok(plain.flags.includes('flag{page_view_ok}'), `flag 提取失败：${plain.flags}`);
    assert.ok(plain.links.some(link => link === `http://127.0.0.1:${target.port}/login`), '相对链接应解析为绝对');
    assert.ok(plain.links.includes('https://ext.example/x'));
    assert.equal(plain.forms.length, 1);
    assert.equal(plain.forms[0].method, 'POST');
    assert.equal(plain.forms[0].action, `http://127.0.0.1:${target.port}/search`);
    assert.deepEqual(Array.from(plain.forms[0].fields).sort(), ['kw', 'q', 't']);

    const spoofed = await web.fetchPageView({ url: `http://127.0.0.1:${target.port}/page`, xff: '127.0.0.1', xRealIp: '10.0.0.8' });
    assert.match(spoofed.bodyText, /hello 127\.0\.0\.1/, '伪造的 X-Forwarded-For 应回显到目标');
  } finally {
    target.server.close();
    proxy.server.close();
  }
});

test('parseRobots：分组/Sitemap/敏感路径解析', () => {
  const report = web.parseRobots([
    '# comment',
    'User-agent: *',
    'Disallow: /admin-backup',
    'Disallow: /.git/',
    'Allow: /public',
    '',
    'User-agent: Googlebot',
    'Disallow: /tmp',
    'Crawl-delay: 10',
    'Sitemap: https://x.example/sitemap.xml',
  ].join('\n'));
  assert.equal(report.groups.length, 2);
  assert.equal(report.groups[0].userAgent, '*');
  assert.equal(report.groups[0].entries.length, 3);
  assert.deepEqual(Array.from(report.suspiciousPaths), ['/admin-backup', '/.git/']);
  assert.deepEqual(Array.from(report.sitemaps), ['https://x.example/sitemap.xml']);
  assert.deepEqual(Array.from(report.crawlDelays), ['10']);
  const disallow = Array.from(report.groups[0].entries).filter(e => e.rule === 'disallow').map(e => e.path);
  assert.deepEqual(disallow, ['/admin-backup', '/.git/']);
});

test('parseRobots：同块多 agent 共享规则 + 规则后新 UA 开新块 + 同 UA 跨块合并（reviewer P2）', () => {
  const report = web.parseRobots([
    'User-agent: a',
    'User-agent: b',
    'Disallow: /shared',
    'User-agent: a',
    'Disallow: /second',
  ].join('\n'));
  const byName = {};
  for (const group of Array.from(report.groups)) byName[group.userAgent] = group;
  assert.deepEqual(Array.from(byName.a.entries).map(e => e.path), ['/shared', '/second'], 'a 应拿到同块规则 + 跨块合并');
  assert.deepEqual(Array.from(byName.b.entries).map(e => e.path), ['/shared'], '同块 agent 共享规则');
});

test('端到端：数字参数引号闭合变体检出（WHERE id=\'1\' 语义，reviewer P2-3）', async () => {
  const target = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const id = url.searchParams.get('id') ?? '';
    res.writeHead(200, { 'content-type': 'text/html' });
    // 应用侧按字符串引用（WHERE id='1'）：裸拼接 AND 被当字面量无差异；引号闭合变体才翻转布尔
    if (/'1'\s*=\s*'2/.test(id)) { res.end('<html>sql-error-user-not-found</html>'); return; }
    res.end('<html>user: admin profile-with-long-padding ......... tail</html>');
  });
  const proxy = await startProxy();
  try {
    const result = await web.detectSqliParams(`http://127.0.0.1:${target.port}/item.php?id=1`);
    assert.equal(result.ok, true, result.error);
    assert.equal(result.params[0].verdict, 'likely', JSON.stringify(result.params[0]));
  } finally {
    target.server.close();
    proxy.server.close();
  }
});

test('端到端：fetchRobots 经代理取回并解析', async () => {
  const target = await startServer((req, res) => {
    if (req.url === '/robots.txt') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('User-agent: *\nDisallow: /flag-admin\nDisallow: /uploads\n');
      return;
    }
    res.writeHead(404); res.end();
  });
  const proxy = await startProxy();
  try {
    const { status, report, error } = await web.fetchRobots(`http://127.0.0.1:${target.port}`);
    assert.equal(status, 200);
    assert.ok(report, error);
    assert.deepEqual(Array.from(report.suspiciousPaths), ['/flag-admin', '/uploads']);
    assert.equal(report.groups[0].entries.length, 2);
  } finally {
    target.server.close();
    proxy.server.close();
  }
});

test('端到端：GET SQL 注入检测——报错参数 likely / 干净参数 clean', async () => {
  const target = await startServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    if (!url.pathname.startsWith('/vuln')) { res.writeHead(404); res.end(); return; }
    const id = url.searchParams.get('id') ?? '';
    const cat = url.searchParams.get('cat') ?? '';
    res.writeHead(200, { 'content-type': 'text/html' });
    if (id.includes("'")) {
      res.end('<html>Warning: mysql_fetch_array(): You have an error in your SQL syntax near...');
      return;
    }
    // cat 无论注入与否都稳定回显同一结构（只有值不同→长度差小→相似度高）
    res.end(`<html><body>news cat=${cat} id=${id} [fixed-footer-content-padding]</body></html>`);
  });
  const proxy = await startProxy();
  try {
    const result = await web.detectSqliParams(`http://127.0.0.1:${target.port}/vuln.php?id=1&cat=2`);
    assert.equal(result.ok, true, result.error);
    const byName = Object.fromEntries(Array.from(result.params).map(f => [f.param, f]));
    assert.equal(byName.id.verdict, 'likely', `id 应疑似注入：${JSON.stringify(byName.id)}`);
    assert.ok(byName.id.evidence.some(line => line.includes('MySQL')), '证据应点名 MySQL');
    assert.equal(byName.cat.verdict, 'clean', `cat 应未检出：${JSON.stringify(byName.cat)}`);
    assert.ok(result.requests >= 6, `应至少发出基线+逐参数探测请求，实际 ${result.requests}`);
  } finally {
    target.server.close();
    proxy.server.close();
  }
});

test('端到端：布尔差异判定（true/false 页可区分 → likely）', async () => {
  const target = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const name = url.searchParams.get('name') ?? '';
    res.writeHead(200, { 'content-type': 'text/html' });
    if (/'1'\s*=\s*'2/.test(name)) { res.end('<html>wrong-user-not-found-empty</html>'); return; }
    res.end('<html>user: admin profile-page-with-long-content ......... padding</html>');
  });
  const proxy = await startProxy();
  try {
    const result = await web.detectSqliParams(`http://127.0.0.1:${target.port}/u.php?name=bob`);
    assert.equal(result.ok, true, result.error);
    assert.equal(result.params[0].verdict, 'likely', JSON.stringify(result.params[0]));
    assert.ok(result.params[0].payloadSamples.some(p => p.includes(`' AND '1'='1`)), '字符串参数应用引号闭合变体');
  } finally {
    target.server.close();
    proxy.server.close();
  }
});

test('端到端：端口扫描 open/closed + 代理不可达前 parsePortInput 校验', async () => {
  const listener = net.createServer(socket => socket.end());
  const listenPort = await new Promise(resolve => {
    listener.listen(0, '127.0.0.1', () => resolve(listener.address().port));
  });
  const proxy = await startProxy();
  try {
    const ok = await web.scanPorts('127.0.0.1', [listenPort, 1], 800);
    assert.equal(ok.ok, true, ok.error);
    const states = Object.fromEntries(Array.from(ok.results).map(line => [line.port, line.state]));
    assert.equal(states[listenPort], 'open');
    assert.equal(states[1], 'closed');

    const tooMany = await web.scanPorts('127.0.0.1', Array.from({ length: 601 }, (_, i) => i + 1));
    assert.equal(tooMany.ok, false);
    assert.match(tooMany.error, /1-600/);

    const badHost = await web.scanPorts('http://x/', [80]);
    assert.equal(badHost.ok, false);
  } finally {
    listener.close();
    proxy.server.close();
  }
});

test('parsePortInput：逗号/区间/去重/非法输入', () => {
  assert.deepEqual(Array.from(web.parsePortInput('80, 443，80').ports), [80, 443]);
  assert.deepEqual(Array.from(web.parsePortInput('8000-8003').ports), [8000, 8001, 8002, 8003]);
  assert.ok('error' in web.parsePortInput('0'));
  assert.ok('error' in web.parsePortInput('abc'));
  assert.ok('error' in web.parsePortInput(''));
  assert.ok('error' in web.parsePortInput('1-601'));
});

test('scanPorts：开关关闭 → 403 错误透传', async () => {
  const router = new Router();
  createCtfProxyRoutes({ isCtfEnabled: async () => false }).registerCtfProxyRoutes(router);
  createCtfPortscanRoutes({ isCtfEnabled: async () => false }).registerCtfPortscanRoutes(router);
  const proxy = await startServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    void router.dispatch(req, res, url, 'public', {}).then(dispatched => {
      if (!dispatched) { res.writeHead(404); res.end(); }
    });
  });
  try {
    web.configureProxy(fetch, `http://127.0.0.1:${proxy.port}`);
    const denied = await web.scanPorts('127.0.0.1', [80]);
    assert.equal(denied.ok, false);
    assert.match(denied.error, /已被管理员关闭/);
    const pageDenied = await web.fetchPageView({ url: 'http://127.0.0.1:1/x' });
    assert.equal(pageDenied.status, 403);
  } finally {
    proxy.server.close();
  }
});

test('sendViaProxy：ok 语义随真实响应（2xx→true / 4xx→false）', async () => {
  const target = await startServer((req, res) => {
    if (req.url === '/ok') { res.writeHead(200); res.end('fine'); return; }
    res.writeHead(500); res.end('boom');
  });
  const proxy = await startProxy();
  try {
    const good = await web.sendViaProxy({ url: `http://127.0.0.1:${target.port}/ok`, method: 'GET', headers: {}, body: null });
    assert.equal(good.ok, true);
    assert.equal(good.status, 200);
    const bad = await web.sendViaProxy({ url: `http://127.0.0.1:${target.port}/err`, method: 'GET', headers: {}, body: null });
    assert.equal(bad.ok, false);
    assert.equal(bad.status, 500);
  } finally {
    target.server.close();
    proxy.server.close();
  }
});
