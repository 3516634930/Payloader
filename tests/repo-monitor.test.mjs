// 订阅仓库监控（v2.0.1 GitHub 仓库监控线）测试：
// ① parseAtomFeed 解析（release/commit entry、XML 实体解码、无 entry→null）
// ② parseRepositoryReference 输入归一化与拒绝面（简写/完整 URL/.git；http、api.github.com、query、多余路径、空）
// ③ 引擎持久化：首次初始化种子 8 预置（metadata 缺失）/ 删空 '[]' 不重播种 / 状态重启往返
// ④ add/duplicate/remove 语义；移除未知 id → not-found
// ⑤ checkNow（mock fetch）：checked 状态字段、changed 快照对比、ETag 304 复用（force:false）、
//    releases.atom 404→无 Release、commits.atom 404→error、超时、超大响应、坏仓库不拖垮同批
// ⑥ interval 非法值 → interval-invalid；批量检查并发上限
// ⑦ 路由映射：RepoMonitorError → 400/404/409；check 静态路由不被 :id 吞；ID 含斜杠 400
import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { Router } from '../server/router.mjs';
import {
  PRESET_REPO_MONITORS,
  RepoMonitorError,
  createRepoMonitor,
  parseAtomFeed,
  parseRepositoryReference,
} from '../server/repo-monitor.mjs';
import { createRepoMonitorRoutes } from '../server/routes-repo-monitor.mjs';

const releaseEntry = ({ tag = 'v1.2.3', title = 'v1.2.3 by someone', updated = '2026-09-01T10:00:00Z' } = {}) => `
  <entry>
    <id>tag:github.com,2008:Repository/123/${tag}</id>
    <updated>${updated}</updated>
    <link rel="alternate" type="text/html" href="https://github.com/o/r/releases/tag/${tag}"/>
    <title>${title}</title>
    <content type="html">notes</content>
  </entry>`;

const commitEntry = ({ sha = 'a'.repeat(40), message = 'fix &amp; improve <things>', updated = '2026-09-02T11:00:00Z', author = 'Dev' } = {}) => `
  <entry>
    <id>tag:github.com,2008:Grit::Commit/${sha}</id>
    <updated>${updated}</updated>
    <link rel="alternate" type="text/html" href="https://github.com/o/r/commit/${sha}"/>
    <title>${message}</title>
    <author><name>${author}</name></author>
  </entry>`;

const atomResponse = (entries, options = {}) => new Response(
  `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">${entries}</feed>`,
  {
    status: options.status || 200,
    headers: {
      'content-type': 'application/atom+xml',
      ...(options.etag ? { etag: options.etag } : {}),
    },
  },
);

const createFeedMock = (feeds = new Map(), options = {}) => {
  const requests = [];
  const fetchImpl = async (url, requestOptions = {}) => {
    requests.push({ url, headers: { ...requestOptions.headers } });
    if (options.delayMs) await new Promise(resolve => setTimeout(resolve, options.delayMs));
    const feed = feeds.get(url);
    if (!feed) return new Response(null, { status: 404 });
    if (requestOptions.headers['if-none-match'] && feed.etag) return new Response(null, { status: 304 });
    return atomResponse(feed.entries, { etag: feed.etag });
  };
  return { fetchImpl, requests };
};

const createHarness = (overrides = {}) => {
  let storedSubscriptions = 'storedSubscriptions' in overrides ? overrides.storedSubscriptions : null;
  let storedStatuses = 'storedStatuses' in overrides ? overrides.storedStatuses : null;
  const feedMock = createFeedMock(overrides.feeds, overrides.fetchOptions);
  const monitor = createRepoMonitor({
    loadSubscriptions: async () => storedSubscriptions,
    saveSubscriptions: async value => { storedSubscriptions = value; },
    loadStatuses: async () => storedStatuses,
    saveStatuses: async value => { storedStatuses = value; },
    fetchImpl: overrides.fetchImpl || feedMock.fetchImpl,
    timeoutMs: overrides.timeoutMs ?? 2_000,
    maxResponseBytes: overrides.maxResponseBytes,
    intervalMs: 'intervalMs' in overrides ? overrides.intervalMs : undefined,
    environment: {},
    now: () => 1_800_000_000_000,
    random: () => 0.5,
  });
  return {
    monitor,
    requests: feedMock.requests,
    get storedSubscriptions() { return storedSubscriptions; },
    get storedStatuses() { return storedStatuses; },
  };
};

const sha1 = 'a'.repeat(40);
const sha2 = 'b'.repeat(40);
const feedsFor = (owner, repo, { sha = sha1, tag = 'v1.0.0' } = {}) => new Map([
  [`https://github.com/${owner}/${repo}/releases.atom`, { etag: '"rel"', entries: releaseEntry({ tag }) }],
  [`https://github.com/${owner}/${repo}/commits.atom`, { etag: '"com"', entries: commitEntry({ sha }) }],
]);

test('parseAtomFeed：解析 entry 字段与 XML 实体，无 entry 返回 null', () => {
  const feed = parseAtomFeed(`<?xml version="1.0"?><feed>${commitEntry({ message: 'a &amp; b &lt;x&gt;' })}</feed>`);
  assert.equal(feed.title, 'a & b <x>');
  assert.equal(feed.updated, '2026-09-02T11:00:00Z');
  assert.equal(feed.id, `tag:github.com,2008:Grit::Commit/${sha1}`);
  assert.equal(feed.link, `https://github.com/o/r/commit/${sha1}`);
  assert.equal(feed.author, 'Dev');
  assert.equal(parseAtomFeed('<feed></feed>'), null);
  assert.equal(parseAtomFeed(''), null);
});

test('parseRepositoryReference：简写/完整 URL/.git 归一化，非法目标拒绝', () => {
  assert.deepEqual(
    { owner: parseRepositoryReference('Octocat/Hello-World').owner, repository: parseRepositoryReference('Octocat/Hello-World').repository },
    { owner: 'Octocat', repository: 'Hello-World' },
  );
  assert.equal(parseRepositoryReference('https://github.com/foo/bar').repository, 'bar');
  assert.equal(parseRepositoryReference('https://github.com/foo/bar.git').repository, 'bar');
  for (const value of ['', '   ', 'https://api.github.com/x/y', 'http://github.com/x/y', 'https://github.com/x/y?ref=main', 'https://github.com/x/y/tree/main', 'justname']) {
    assert.throws(() => parseRepositoryReference(value), error => error instanceof RepoMonitorError && error.code === 'invalid-input', value);
  }
});

test('首次初始化种子预置仓库；删空后（存储为 []）不重播种', async () => {
  const h = createHarness();
  const first = await h.monitor.list();
  assert.equal(first.items.length, PRESET_REPO_MONITORS.length);
  assert.ok(first.items.every(item => item.preset === true));
  assert.match(h.storedSubscriptions, /swisskyrepo/);
  assert.match(h.storedSubscriptions, /SecLists/);

  for (const item of first.items) await h.monitor.remove(item.id);
  assert.equal((await h.monitor.list()).items.length, 0);
  assert.equal(h.storedSubscriptions, '[]');

  const restarted = createHarness({ storedSubscriptions: h.storedSubscriptions });
  assert.equal((await restarted.monitor.list()).items.length, 0);
});

test('add/remove：重复订阅 duplicate、移除未知 not-found、移除后列表不含', async () => {
  const h = createHarness({ storedSubscriptions: '[]' });
  const added = await h.monitor.add({ repository: 'Octocat/Hello-World.git' });
  assert.equal(added.owner, 'Octocat');
  assert.equal(added.repository, 'Hello-World');
  assert.equal(added.preset, false);
  assert.equal(added.status.state, 'idle');
  assert.equal(added.githubUrl, 'https://github.com/Octocat/Hello-World');

  await assert.rejects(() => h.monitor.add({ repository: 'octocat/hello-world' }), error => error.code === 'duplicate');
  await assert.rejects(() => h.monitor.remove('does-not-exist'), error => error.code === 'not-found');

  await h.monitor.remove(added.id);
  assert.equal((await h.monitor.list()).items.some(item => item.id === added.id), false);
});

test('checkNow：状态字段完整、changed 快照对比、ETag 304 复用缓存', async () => {
  const feeds = feedsFor('octocat', 'hello-world');
  const h = createHarness({ storedSubscriptions: '[]', feeds });
  await h.monitor.add({ repository: 'octocat/hello-world' });
  const id = (await h.monitor.list()).items[0].id;

  const first = await h.monitor.checkNow({ id });
  const status = first.items[0].status;
  assert.equal(status.state, 'checked');
  assert.equal(status.changed, false); // 首次检查为基线
  assert.equal(status.release.tag, 'v1.0.0');
  assert.equal(status.release.updatedAt, '2026-09-01T10:00:00.000Z');
  assert.equal(status.commit.sha, sha1);
  assert.equal(status.commit.shaShort, sha1.slice(0, 12));
  assert.match(status.commit.message, /fix & improve <things>/);
  assert.equal(status.commit.author, 'Dev');
  assert.ok(h.storedStatuses.includes(sha1));

  // force:false → ETag 条件请求命中 304，快照不变
  const before = h.requests.length;
  const cached = await h.monitor.checkNow({ force: false });
  assert.equal(cached.items[0].status.commit.sha, sha1);
  assert.equal(h.requests.length, before + 2);
  assert.ok(h.requests.slice(before).every(request => request.headers['if-none-match'] === '"com"' || request.headers['if-none-match'] === '"rel"'));

  // 远端新提交 → 手动（force）检查 → changed=true
  feeds.set('https://github.com/octocat/hello-world/commits.atom', { etag: '"com2"', entries: commitEntry({ sha: sha2 }) });
  const updated = await h.monitor.checkNow({ id });
  assert.equal(updated.items[0].status.changed, true);
  assert.equal(updated.items[0].status.commit.sha, sha2);
});

test('checkNow：releases.atom 404 → 无 Release 正常态；commits.atom 404 → 仓库不存在错误', async () => {
  const noRelease = new Map([['https://github.com/a/b/commits.atom', { etag: '"c"', entries: commitEntry() }]]);
  const h1 = createHarness({ storedSubscriptions: '[]', feeds: noRelease });
  await h1.monitor.add({ repository: 'a/b' });
  const checked = await h1.monitor.checkNow({});
  assert.equal(checked.items[0].status.state, 'checked');
  assert.equal(checked.items[0].status.release, null);

  const noCommits = new Map([['https://github.com/a/b/releases.atom', { etag: '"r"', entries: releaseEntry() }]]);
  const h2 = createHarness({ storedSubscriptions: '[]', feeds: noCommits });
  await h2.monitor.add({ repository: 'a/b' });
  const failed = await h2.monitor.checkNow({});
  assert.equal(failed.items[0].status.state, 'error');
  assert.equal(failed.items[0].status.error.code, 'not-found');
});

test('checkNow：超时与超大响应分别映射 timeout / response-too-large，坏仓库不拖垮同批其它仓库', async () => {
  const hangingFetch = async (url, requestOptions = {}) => new Promise((_, reject) => {
    // mock 无真实 socket，需自持 timer 保活事件循环（AbortSignal.timeout 的
    // timer 在 Node 22 为 unref，否则 Promise 尚未决而事件循环已空）。
    const keepAlive = setTimeout(() => reject(new Error('mock fetch keep-alive expired')), 30_000);
    requestOptions.signal?.addEventListener('abort', () => {
      clearTimeout(keepAlive);
      const error = new Error('aborted');
      error.name = 'AbortError';
      reject(error);
    });
  });
  const h1 = createHarness({ storedSubscriptions: '[]', timeoutMs: 40, fetchImpl: hangingFetch });
  await h1.monitor.add({ repository: 'a/b' });
  const timed = await h1.monitor.checkNow({});
  assert.equal(timed.items[0].status.state, 'error');
  assert.equal(timed.items[0].status.error.code, 'timeout');

  const h2 = createHarness({
    storedSubscriptions: '[]',
    maxResponseBytes: 64,
    feeds: new Map([['https://github.com/a/b/commits.atom', { entries: commitEntry() }]]),
  });
  await h2.monitor.add({ repository: 'a/b' });
  const oversized = await h2.monitor.checkNow({});
  assert.equal(oversized.items[0].status.state, 'error');
  assert.equal(oversized.items[0].status.error.code, 'response-too-large');

  const mixed = new Map([
    ['https://github.com/good/one/releases.atom', { entries: releaseEntry() }],
    ['https://github.com/good/one/commits.atom', { entries: commitEntry() }],
  ]);
  const h3 = createHarness({ storedSubscriptions: '[]', feeds: mixed });
  await h3.monitor.add({ repository: 'good/one' });
  await h3.monitor.add({ repository: 'broken/one' });
  const batch = await h3.monitor.checkNow({});
  assert.equal(batch.items.find(item => item.owner === 'good').status.state, 'checked');
  assert.equal(batch.items.find(item => item.owner === 'broken').status.state, 'error');
});

test('checkNow：仓库改名 301 → 受控跟随并更新订阅到新位置；越界重定向与超长跳链拒绝', async () => {
  const relocated = feedsFor('new-owner', 'new-repo');
  const redirectFetch = async (url, requestOptions = {}) => {
    if (url === 'https://github.com/old-owner/old-repo/commits.atom') {
      return new Response(null, { status: 301, headers: { location: 'https://github.com/new-owner/new-repo/commits.atom' } });
    }
    if (url === 'https://github.com/old-owner/old-repo/releases.atom') {
      // 相对 location 也要正确解析并保持 github.com 归一化
      return new Response(null, { status: 301, headers: { location: '/new-owner/new-repo/releases.atom' } });
    }
    const feed = relocated.get(url);
    if (!feed) return new Response(null, { status: 404 });
    if (requestOptions.headers['if-none-match'] && feed.etag) return new Response(null, { status: 304 });
    return atomResponse(feed.entries, { etag: feed.etag });
  };
  const h = createHarness({ storedSubscriptions: '[]', fetchImpl: redirectFetch });
  await h.monitor.add({ repository: 'old-owner/old-repo' });
  const result = await h.monitor.checkNow({});
  const item = result.items[0];
  assert.equal(item.owner, 'new-owner');
  assert.equal(item.repository, 'new-repo');
  assert.equal(item.status.state, 'checked');
  assert.equal(item.status.commit.sha, sha1);
  assert.match(h.storedSubscriptions, /new-owner/);
  assert.doesNotMatch(h.storedSubscriptions, /old-owner/);

  // 重定向逃出 github.com → invalid-response（配置改不了网络目的地）
  const evilFetch = async () => new Response(null, { status: 301, headers: { location: 'https://evil.invalid/x/y/commits.atom' } });
  const h2 = createHarness({ storedSubscriptions: '[]', fetchImpl: evilFetch });
  await h2.monitor.add({ repository: 'a/b' });
  const denied = await h2.monitor.checkNow({});
  assert.equal(denied.items[0].status.state, 'error');
  assert.equal(denied.items[0].status.error.code, 'invalid-response');

  // 每跳都合法但超过 3 跳 → too-many-redirects
  let hopCount = 0;
  const hopFetch = async () => {
    hopCount += 1;
    return new Response(null, { status: 302, headers: { location: `https://github.com/hop${hopCount}/repo/commits.atom` } });
  };
  const h3 = createHarness({ storedSubscriptions: '[]', fetchImpl: hopFetch });
  await h3.monitor.add({ repository: 'start/repo' });
  const chained = await h3.monitor.checkNow({});
  assert.equal(chained.items[0].status.state, 'error');
  assert.equal(chained.items[0].status.error.code, 'too-many-redirects');
});

test('状态持久化往返：重启实例恢复上次检查结果（changed 保留）；checking 瞬态加载后视为中断', async () => {
  const feeds = feedsFor('octocat', 'hello-world');
  const h = createHarness({ storedSubscriptions: '[]', feeds });
  await h.monitor.add({ repository: 'octocat/hello-world' });
  await h.monitor.checkNow({});
  feeds.set('https://github.com/octocat/hello-world/commits.atom', { etag: '"com2"', entries: commitEntry({ sha: sha2 }) });
  await h.monitor.checkNow({});

  const restarted = createHarness({ storedSubscriptions: h.storedSubscriptions, storedStatuses: h.storedStatuses, feeds });
  const items = (await restarted.monitor.list()).items;
  assert.equal(items.length, 1);
  assert.equal(items[0].status.commit.sha, sha2);
  assert.equal(items[0].status.changed, true);

  // 批量检查中途落盘的 'checking' 快照（纯内存瞬态）重启后不得卡死按钮：归为 interrupted
  const stored = JSON.parse(h.storedStatuses);
  const entry = Object.values(stored)[0];
  entry.state = 'checking';
  entry.error = null;
  const interrupted = createHarness({
    storedSubscriptions: h.storedSubscriptions,
    storedStatuses: JSON.stringify(stored),
    feeds,
  });
  const recovered = (await interrupted.monitor.list()).items[0].status;
  assert.equal(recovered.state, 'error');
  assert.equal(recovered.error.code, 'interrupted');
});

test('订阅数量上限：达到 200 后 add 抛 limit-reached', async () => {
  const h = createHarness({ storedSubscriptions: '[]' });
  for (let i = 0; i < 200; i += 1) {
    await h.monitor.add({ repository: `team${Math.floor(i / 50)}/repo-${i}` });
  }
  await assert.rejects(() => h.monitor.add({ repository: 'one/more' }), error => error instanceof RepoMonitorError && error.code === 'limit-reached');
});

test('interval 非法值抛 interval-invalid；批量检查并发受 worker 池约束', async () => {
  assert.throws(() => createRepoMonitor({ intervalMs: 1_000, environment: {} }), error => error instanceof RepoMonitorError && error.code === 'interval-invalid');

  let active = 0;
  let peak = 0;
  const trackingFetch = async () => {
    peak = Math.max(peak, ++active);
    try {
      await new Promise(resolve => setTimeout(resolve, 25));
      return new Response('<feed></feed>', { status: 404 });
    } finally {
      active -= 1;
    }
  };
  const h = createHarness({ storedSubscriptions: '[]', fetchImpl: trackingFetch });
  for (let i = 0; i < 6; i += 1) await h.monitor.add({ repository: `team/repo-${i}` });
  const batch = await h.monitor.checkNow({});
  assert.equal(batch.items.length, 6);
  assert.ok(peak <= 8, `并发峰值 ${peak} 超过 4 仓库 × 2 feed 上限`);
  assert.ok(peak >= 2, '并发应实际发生');
});

const startServer = handler => new Promise(resolve => {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
});

const post = (port, pathname, payload) => fetch(`http://127.0.0.1:${port}${pathname}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(payload),
});

test('路由：RepoMonitorError 映射 400/404/409，check 静态路由优先于 :id', async () => {
  const router = new Router();
  createRepoMonitorRoutes({
    repoMonitor: {
      list: async () => ({ items: [{ id: 'x', owner: 'o', repository: 'r' }], nextCheckAt: null }),
      add: async body => {
        if (!body?.repository) throw new RepoMonitorError('invalid-input', '请填写仓库（owner/repo 或 GitHub 仓库 URL）。');
        if (body.repository === 'dup') throw new RepoMonitorError('duplicate', '已在订阅列表中：o/r');
        return { id: 'new', owner: 'a', repository: 'b', status: { state: 'idle' } };
      },
      remove: async () => { throw new RepoMonitorError('not-found', '订阅不存在或已被移除。'); },
      checkNow: async () => ({ items: [] }),
    },
  }).registerRepoMonitorRoutes(router);
  const { server, port } = await startServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x');
      const dispatched = await router.dispatch(req, res, url, 'admin', {});
      if (!dispatched) { res.writeHead(404); res.end(); }
    } catch (error) {
      // 镜像 admin-server 的统一错误兜底，否则错误请求永远无响应并挂住进程
      const status = typeof error.status === 'number' ? error.status : 500;
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: error instanceof Error ? error.message : 'error' }));
    }
  });
  try {
    const listResponse = await fetch(`http://127.0.0.1:${port}/api/admin/repo-monitors`);
    assert.equal(listResponse.status, 200);
    assert.equal((await listResponse.json()).items.length, 1);

    const created = await post(port, '/api/admin/repo-monitors', { repository: 'a/b' });
    assert.equal(created.status, 201);

    const empty = await post(port, '/api/admin/repo-monitors', { repository: '' });
    assert.equal(empty.status, 400);
    assert.match((await empty.json()).error, /请填写仓库/);

    const duplicate = await post(port, '/api/admin/repo-monitors', { repository: 'dup' });
    assert.equal(duplicate.status, 409);

    const checkAll = await post(port, '/api/admin/repo-monitors/check', {});
    assert.equal(checkAll.status, 200);

    const checkOne = await post(port, '/api/admin/repo-monitors/abc/check', {});
    assert.equal(checkOne.status, 200);

    const badId = await post(port, '/api/admin/repo-monitors/bad%2Fid/check', {});
    assert.equal(badId.status, 400);

    const missing = await fetch(`http://127.0.0.1:${port}/api/admin/repo-monitors/nope`, { method: 'DELETE' });
    assert.equal(missing.status, 404);
  } finally {
    server.close();
  }
});
