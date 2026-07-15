import assert from 'node:assert/strict';
import test from 'node:test';

import {
  compareStableVersions,
  createGitHubVersionSource,
  createVersionChecker,
  normalizeVersion,
  parseGitHubRepository,
  selectStableCandidate,
} from '../server/version-checker.mjs';

const jsonResponse = (value, options = {}) => new Response(JSON.stringify(value), {
  status: options.status || 200,
  headers: {
    'content-type': 'application/json',
    ...(options.etag ? { etag: options.etag } : {}),
    ...(options.headers || {}),
  },
});

test('official repository parsing accepts one fixed GitHub repository and rejects unsafe destinations', () => {
  assert.deepEqual(parseGitHubRepository('https://github.com/example/payloader'), {
    owner: 'example',
    repository: 'payloader',
    apiBaseUrl: 'https://api.github.com/repos/example/payloader',
  });
  assert.equal(parseGitHubRepository('https://github.com/example/payloader.git').repository, 'payloader');

  for (const value of [
    'http://github.com/example/payloader',
    'https://api.github.com/repos/example/payloader',
    'https://github.com@example.invalid/example/payloader',
    'https://github.com/example/payloader/releases',
    'https://github.com/example/payloader?redirect=https://example.invalid',
    'https://127.0.0.1/example/payloader',
  ]) {
    assert.throws(() => parseGitHubRepository(value), /official GitHub repository URL/i, value);
  }
});

test('stable version selection prefers releases, then tags, then remote package metadata', () => {
  assert.equal(normalizeVersion('2.0'), '2.0.0');
  assert.equal(normalizeVersion('v1.4.3'), '1.4.3');
  assert.equal(normalizeVersion('release-2'), null);

  assert.deepEqual(selectStableCandidate({
    release: { tag_name: 'v1.2.0', draft: false, prerelease: false, body: 'Release notes' },
    tags: [{ name: 'v9.0.0' }],
    packageVersion: '8.0.0',
  }), {
    version: '1.2.0',
    source: 'release',
    tagName: 'v1.2.0',
    notes: 'Release notes',
    publishedAt: null,
  });

  assert.equal(selectStableCandidate({
    release: null,
    tags: [{ name: 'v1.0.0-beta.1' }, { name: 'v1.8.0' }, { name: '2.1' }],
    packageVersion: '9.0.0',
  }).version, '2.1.0');
  assert.equal(selectStableCandidate({ release: null, tags: [], packageVersion: '1.0' }).source, 'package');
  assert.equal(selectStableCandidate({ release: null, tags: [], packageVersion: 'not-versioned' }), null);
});

test('stable comparison recognizes the local 2.0 release as newer than GitHub 1.0', () => {
  assert.equal(compareStableVersions('2.0.0', '1.0.0'), 'local-newer');
  assert.equal(compareStableVersions('2.0.0', '2.0.0'), 'up-to-date');
  assert.equal(compareStableVersions('2.0.0', '2.1.0'), 'update-available');
  assert.equal(compareStableVersions('development', '2.1.0'), 'unknown');
});

test('GitHub source uses ETags and never exposes its token in public status', async () => {
  const requests = [];
  const payloads = new Map([
    ['/repos/example/payloader', { default_branch: 'main' }],
    ['/repos/example/payloader/releases/latest', {
      tag_name: 'v1.0.0',
      draft: false,
      prerelease: false,
      body: 'First public release',
      published_at: '2026-01-01T00:00:00.000Z',
    }],
    ['/repos/example/payloader/git/ref/heads/main', {
      object: { type: 'commit', sha: 'a'.repeat(40) },
    }],
    [`/repos/example/payloader/git/commits/${'a'.repeat(40)}`, {
      message: 'Release 1.0',
      author: { date: '2026-01-01T00:00:00.000Z' },
    }],
  ]);
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    const cacheHit = options.headers['if-none-match'] === `"${parsed.pathname}"`;
    requests.push({ path: parsed.pathname, headers: { ...options.headers }, cacheHit });
    if (cacheHit) return new Response(null, { status: 304 });
    return jsonResponse(payloads.get(parsed.pathname), { etag: `"${parsed.pathname}"` });
  };
  const source = createGitHubVersionSource({
    repositoryUrl: 'https://github.com/example/payloader',
    fetchImpl,
    token: 'server-only-token',
  });

  const first = await source.inspect({ currentVersion: '2.0.0', currentCommit: 'a'.repeat(40) });
  const second = await source.inspect({ currentVersion: '2.0.0', currentCommit: 'a'.repeat(40) });
  payloads.set('/repos/example/payloader/git/ref/heads/main', {
    object: { type: 'commit', sha: 'b'.repeat(40) },
  });
  payloads.set(`/repos/example/payloader/git/commits/${'b'.repeat(40)}`, {
    message: 'Release 2.0',
    author: { date: '2026-02-01T00:00:00.000Z' },
  });
  const forced = await source.inspect({
    currentVersion: '2.0.0',
    currentCommit: 'b'.repeat(40),
    force: true,
  });

  assert.equal(first.stable.state, 'local-newer');
  assert.equal(first.source.state, 'synchronized');
  assert.deepEqual(second, first);
  assert.equal(forced.source.state, 'synchronized');
  assert.equal(forced.source.commit, 'b'.repeat(40));
  assert.equal(requests.length, 12);
  assert.equal(requests.slice(4, 8).every(request => request.cacheHit), true);
  assert.equal(requests.slice(8).every(request => !request.headers['if-none-match']), true);
  assert.equal(requests.some(request => request.path.endsWith('/commits/main')), false);
  assert.equal(JSON.stringify(first).includes('server-only-token'), false);
  assert.equal(requests.every(request => request.headers.authorization === 'Bearer server-only-token'), true);
});

test('GitHub source falls back through tags and package metadata when no Release exists', async () => {
  const fetchImpl = async url => {
    const parsed = new URL(url);
    if (parsed.pathname.endsWith('/releases/latest')) return jsonResponse({ message: 'Not Found' }, { status: 404 });
    if (parsed.pathname.endsWith('/tags')) return jsonResponse([{ name: 'v1.0.0', commit: { sha: 'b'.repeat(40) } }]);
    if (parsed.pathname.endsWith('/git/ref/heads/main')) {
      return jsonResponse({ object: { type: 'commit', sha: 'b'.repeat(40) } });
    }
    if (parsed.pathname.endsWith(`/git/commits/${'b'.repeat(40)}`)) {
      return jsonResponse({ message: 'Main', author: { date: '2026-01-02T00:00:00.000Z' } });
    }
    if (parsed.pathname.endsWith('/payloader')) return jsonResponse({ default_branch: 'main' });
    throw new Error(`Unexpected request: ${parsed.pathname}`);
  };
  const source = createGitHubVersionSource({ repositoryUrl: 'https://github.com/example/payloader', fetchImpl });
  const status = await source.inspect({ currentVersion: '2.0.0', currentCommit: '' });

  assert.equal(status.stable.version, '1.0.0');
  assert.equal(status.stable.source, 'tag');
  assert.equal(status.stable.state, 'local-newer');
  assert.equal(status.source.state, 'unknown-local-commit');
});

test('development package metadata is not presented as a stable release', async () => {
  const fetchImpl = async url => {
    const parsed = new URL(url);
    if (parsed.pathname.endsWith('/releases/latest')) return jsonResponse({ message: 'Not Found' }, { status: 404 });
    if (parsed.pathname.endsWith('/tags')) return jsonResponse([]);
    if (parsed.pathname.endsWith('/contents/package.json')) return jsonResponse({ version: '0.0.0' });
    if (parsed.pathname.endsWith('/git/ref/heads/main')) {
      return jsonResponse({ object: { type: 'commit', sha: 'd'.repeat(40) } });
    }
    if (parsed.pathname.endsWith(`/git/commits/${'d'.repeat(40)}`)) {
      return jsonResponse({ message: 'Development', author: { date: '2026-01-03T00:00:00.000Z' } });
    }
    if (parsed.pathname.endsWith('/payloader')) return jsonResponse({ default_branch: 'main' });
    throw new Error(`Unexpected request: ${parsed.pathname}`);
  };
  const source = createGitHubVersionSource({ repositoryUrl: 'https://github.com/example/payloader', fetchImpl });
  const status = await source.inspect({ currentVersion: '2.0.0', currentCommit: '' });

  assert.equal(status.stable.version, null);
  assert.equal(status.stable.state, 'unavailable');
  assert.equal(status.stable.source, 'package');
  assert.equal(status.stable.developmentMetadata, true);
});

test('GitHub source returns bounded safe rate-limit and oversized-response errors', async () => {
  const rateLimited = createGitHubVersionSource({
    repositoryUrl: 'https://github.com/example/payloader',
    fetchImpl: async () => jsonResponse({ message: 'API rate limit exceeded for token secret-value' }, {
      status: 403,
      headers: { 'x-ratelimit-reset': '1784000000' },
    }),
    token: 'secret-value',
  });
  await assert.rejects(
    () => rateLimited.inspect({ currentVersion: '2.0.0', currentCommit: '' }),
    error => Boolean(error.code === 'rate-limited' && !error.message.includes('secret-value') && error.retryAt),
  );

  const oversized = createGitHubVersionSource({
    repositoryUrl: 'https://github.com/example/payloader',
    fetchImpl: async () => new Response('x'.repeat(2048), {
      status: 200,
      headers: { 'content-length': '2048' },
    }),
    maxResponseBytes: 1024,
  });
  await assert.rejects(
    () => oversized.inspect({ currentVersion: '2.0.0', currentCommit: '' }),
    error => error.code === 'response-too-large',
  );
});

test('version checker coalesces checks, persists safe status, and stops its timer', async () => {
  let inspectCalls = 0;
  let inspectedIdentity;
  let resolveInspect;
  const saved = [];
  const scheduled = [];
  const cleared = [];
  const versionSource = {
    inspect: identity => {
      inspectCalls += 1;
      inspectedIdentity = identity;
      return new Promise(resolve => { resolveInspect = resolve; });
    },
  };
  const checker = createVersionChecker({
    versionSource,
    currentVersion: '2.0.0',
    currentCommit: 'c'.repeat(40),
    projectRoute: '/api/r/p',
    loadStatus: async () => '{not-json',
    saveStatus: async value => saved.push(value),
    initialDelayMs: 1,
    intervalMs: 15 * 60 * 1000,
    setTimer: (callback, delay) => {
      const handle = { callback, delay, unref() {} };
      scheduled.push(handle);
      return handle;
    },
    clearTimer: handle => cleared.push(handle),
    random: () => 0.5,
  });

  await checker.start();
  assert.equal(scheduled.length, 1);
  const first = checker.checkNow();
  const second = checker.checkNow();
  const forced = checker.checkNow({ force: true });
  await Promise.resolve();
  assert.equal(inspectCalls, 1);
  assert.deepEqual(inspectedIdentity, {
    currentVersion: '2.0.0',
    currentCommit: 'c'.repeat(40),
  });
  resolveInspect({
    stable: { state: 'up-to-date', version: '2.0.0', source: 'release' },
    source: { state: 'synchronized', branch: 'main', commit: 'c'.repeat(40) },
  });
  const [firstStatus, secondStatus] = await Promise.all([first, second]);
  assert.deepEqual(firstStatus, secondStatus);
  assert.equal(firstStatus.installed.version, '2.0.0');
  assert.equal(firstStatus.projectRoute, '/api/r/p');
  assert.equal(saved.length, 1);

  await Promise.resolve();
  await Promise.resolve();
  assert.equal(inspectCalls, 2);
  assert.deepEqual(inspectedIdentity, {
    currentVersion: '2.0.0',
    currentCommit: 'c'.repeat(40),
    force: true,
  });
  resolveInspect({
    stable: { state: 'up-to-date', version: '2.0.0', source: 'release' },
    source: { state: 'synchronized', branch: 'main', commit: 'c'.repeat(40) },
  });
  await forced;
  assert.equal(saved.length, 2);

  checker.stop();
  assert.deepEqual(cleared, [scheduled[0]]);
});
