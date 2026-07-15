import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import test from 'node:test';
import { officialProjectUrl, publicProjectRoute } from '../server/project-attribution.mjs';

test('public runtime endpoints and admin boundary are available', async t => {
  const tempRoot = await mkdtemp(join(tmpdir(), 'payloader-api-smoke-'));
  process.env.PAYLOADER_DATA_DIR = join(tempRoot, 'data');
  process.env.PAYLOADER_CLIENT_BUILD_ROOT = join(tempRoot, 'client-builds');
  process.env.PAYLOADER_CLIENT_TMP_ROOT = join(tempRoot, 'client-tmp');
  process.env.PAYLOADER_ADMIN_USER = 'smoke-admin';
  process.env.PAYLOADER_ADMIN_PASSWORD = 'Smoke-Test-Password-123!';
  process.env.PAYLOADER_TRUSTED_PROXIES = 'loopback';
  process.env.PAYLOADER_UPDATE_CHECK_DISABLED = 'true';
  process.env.PAYLOADER_CLIENT_SHELLS_REMOTE_DISABLED = 'true';

  const [{ createAdminServer, __adminSecurityTest }, { closeStore }] = await Promise.all([
    import(`../server/admin-server.mjs?api-smoke=${Date.now()}`),
    import('../server/data-store.mjs'),
  ]);

  let manualVersionChecks = 0;
  const versionStatus = {
    state: 'local-newer',
    installed: { version: '2.0.0', commit: 'a'.repeat(40), commitShort: 'a'.repeat(12) },
    stable: { state: 'local-newer', version: '1.0.0', source: 'tag' },
    source: { state: 'local-ahead', branch: 'main', commit: 'b'.repeat(40), commitShort: 'b'.repeat(12) },
    projectRoute: publicProjectRoute,
    checkedAt: '2026-07-13T00:00:00.000Z',
    lastSuccessfulAt: '2026-07-13T00:00:00.000Z',
    nextCheckAt: null,
    error: null,
    rateLimit: { limit: 60, remaining: 59, resetAt: null },
  };
  const fakeVersionChecker = {
    getStatus: async () => versionStatus,
    checkNow: async () => {
      manualVersionChecks += 1;
      return versionStatus;
    },
    start: async () => versionStatus,
    stop() {},
  };
  const server = createAdminServer({ versionChecker: fakeVersionChecker });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const baseUrl = `http://127.0.0.1:${address.port}`;

  t.after(async () => {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await closeStore();
    await rm(tempRoot, { recursive: true, force: true });
  });

  const health = await fetch(`${baseUrl}/api/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: 'ok' });

  const projectRedirect = await fetch(`${baseUrl}${publicProjectRoute}`, { redirect: 'manual' });
  assert.equal(projectRedirect.status, 302);
  assert.equal(projectRedirect.headers.get('location'), officialProjectUrl);
  assert.equal(projectRedirect.headers.get('cache-control'), 'no-store');
  assert.equal(await projectRedirect.text(), '');

  const ready = await fetch(`${baseUrl}/api/ready`);
  assert.equal(ready.status, 200);
  assert.deepEqual(await ready.json(), { status: 'ready' });

  const publicData = await fetch(`${baseUrl}/api/public-data`, {
    headers: { 'accept-encoding': 'identity' },
  });
  assert.equal(publicData.status, 200);
  assert.equal(publicData.headers.get('content-encoding'), null);
  assert.equal(publicData.headers.get('cache-control'), 'public, max-age=0, must-revalidate');
  assert.match(publicData.headers.get('etag') || '', /^W\/"[a-f0-9]{64}"$/);
  assert.match(publicData.headers.get('vary') || '', /accept-encoding/i);
  const publicPayload = await publicData.json();
  assert.ok(Array.isArray(publicPayload.payloads));
  assert.ok(Array.isArray(publicPayload.tools));
  assert.ok(Array.isArray(publicPayload.navigation));

  const compressedPublicData = await fetch(`${baseUrl}/api/public-data`, {
    headers: { 'accept-encoding': 'gzip' },
  });
  assert.equal(compressedPublicData.status, 200);
  assert.equal(compressedPublicData.headers.get('content-encoding'), 'gzip');
  assert.ok(Number(compressedPublicData.headers.get('content-length')) < Number(publicData.headers.get('content-length')) / 4);
  assert.deepEqual(await compressedPublicData.json(), publicPayload);

  const notModifiedPublicData = await fetch(`${baseUrl}/api/public-data`, {
    headers: {
      'accept-encoding': 'br',
      'if-none-match': publicData.headers.get('etag'),
    },
  });
  assert.equal(notModifiedPublicData.status, 304);
  assert.equal(await notModifiedPublicData.text(), '');

  const clientBuild = await fetch(`${baseUrl}/api/client-build`);
  assert.equal(clientBuild.status, 200);
  const clientPayload = await clientBuild.json();
  assert.equal(typeof clientPayload.available, 'boolean');
  assert.equal(typeof clientPayload.lastBuildFailed, 'boolean');
  assert.equal('lastFailure' in clientPayload, false);

  const unauthorizedAdmin = await fetch(`${baseUrl}/api/admin/settings`);
  assert.equal(unauthorizedAdmin.status, 401);
  const unauthorizedVersionStatus = await fetch(`${baseUrl}/api/admin/version-status`);
  assert.equal(unauthorizedVersionStatus.status, 401);
  const unauthorizedVersionCheck = await fetch(`${baseUrl}/api/admin/version-check`, { method: 'POST' });
  assert.equal(unauthorizedVersionCheck.status, 401);

  const adminShell = await fetch(`${baseUrl}/admin`, { redirect: 'manual' });
  assert.equal(adminShell.status, 200);

  assert.equal(__adminSecurityTest.clientKey({
    socket: { remoteAddress: '203.0.113.90' },
    headers: { 'x-forwarded-for': '198.51.100.90' },
  }), '203.0.113.90');
  assert.equal(__adminSecurityTest.clientKey({
    socket: { remoteAddress: '127.0.0.1' },
    headers: { 'x-forwarded-for': '198.51.100.91, 203.0.113.91' },
  }), '203.0.113.91');
  assert.equal(__adminSecurityTest.clientKey({
    socket: { remoteAddress: '127.0.0.1' },
    headers: { 'x-forwarded-for': 'not-an-ip' },
  }), '127.0.0.1');

  const userAgent = 'payloader-api-smoke';
  const login = await fetch(`${baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': userAgent,
    },
    body: JSON.stringify({
      username: process.env.PAYLOADER_ADMIN_USER,
      password: process.env.PAYLOADER_ADMIN_PASSWORD,
    }),
  });
  assert.equal(login.status, 200);
  const loginPayload = await login.json();
  assert.equal(loginPayload.authenticated, true);
  assert.equal(loginPayload.user, 'smoke-admin');
  assert.equal(loginPayload.tokenType, 'Bearer');
  assert.equal(typeof loginPayload.accessToken, 'string');
  assert.match(loginPayload.accessToken, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.equal('csrfToken' in loginPayload, false);
  assert.equal(login.headers.get('set-cookie'), null);

  const cookieOnly = await fetch(`${baseUrl}/api/admin/settings`, {
    headers: {
      cookie: `payloader_admin_session=${encodeURIComponent(loginPayload.accessToken)}`,
      'user-agent': userAgent,
    },
  });
  assert.equal(cookieOnly.status, 401);

  const authenticatedHeaders = {
    authorization: `Bearer ${loginPayload.accessToken}`,
    'user-agent': userAgent,
  };

  const unauthorizedCustomContent = await fetch(`${baseUrl}/api/admin/custom-content`);
  assert.equal(unauthorizedCustomContent.status, 401);

  const createdCustomToolResponse = await fetch(`${baseUrl}/api/admin/custom-content`, {
    method: 'POST',
    headers: { ...authenticatedHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({ title: 'Smoke custom tool', content: 'echo smoke', destination: 'tools' }),
  });
  assert.equal(createdCustomToolResponse.status, 201);
  const createdCustomTool = await createdCustomToolResponse.json();
  assert.equal(createdCustomTool.destination, 'tools');

  const customContentResponse = await fetch(`${baseUrl}/api/admin/custom-content`, { headers: authenticatedHeaders });
  assert.equal(customContentResponse.status, 200);
  assert.ok((await customContentResponse.json()).items.some(item => item.id === createdCustomTool.id));

  const movedCustomContentResponse = await fetch(`${baseUrl}/api/admin/custom-content/${encodeURIComponent(createdCustomTool.id)}`, {
    method: 'PUT',
    headers: { ...authenticatedHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({
      sourceDestination: 'tools',
      destination: 'payloads',
      title: 'Smoke custom payload',
      content: 'echo moved',
    }),
  });
  assert.equal(movedCustomContentResponse.status, 200);
  assert.equal((await movedCustomContentResponse.json()).destination, 'payloads');

  const deletedCustomContentResponse = await fetch(
    `${baseUrl}/api/admin/custom-content/${encodeURIComponent(createdCustomTool.id)}?destination=payloads`,
    { method: 'DELETE', headers: authenticatedHeaders },
  );
  assert.equal(deletedCustomContentResponse.status, 200);

  const customPayloadsResponse = await fetch(`${baseUrl}/api/admin/custom-payloads`, { headers: authenticatedHeaders });
  assert.equal(customPayloadsResponse.status, 200);
  const customPayloads = await customPayloadsResponse.json();
  assert.ok(Array.isArray(customPayloads.items));
  assert.ok(customPayloads.items.every(item => item.id.startsWith('custom-') || item.category?.zh === '自定义'));

  const versionStatusResponse = await fetch(`${baseUrl}/api/admin/version-status`, { headers: authenticatedHeaders });
  assert.equal(versionStatusResponse.status, 200);
  const versionStatusPayload = await versionStatusResponse.json();
  assert.equal(versionStatusPayload.installed.version, '2.0.0');
  assert.equal(versionStatusPayload.stable.state, 'local-newer');
  assert.equal(versionStatusPayload.projectRoute, publicProjectRoute);
  assert.equal(JSON.stringify(versionStatusPayload).includes('PAYLOADER_GITHUB_TOKEN'), false);

  const manualVersionCheck = await fetch(`${baseUrl}/api/admin/version-check`, {
    method: 'POST',
    headers: authenticatedHeaders,
  });
  assert.equal(manualVersionCheck.status, 200);
  assert.equal((await manualVersionCheck.json()).installed.version, '2.0.0');
  assert.equal(manualVersionChecks, 1);

  const clientStatusResponse = await fetch(`${baseUrl}/api/admin/client-builds/status`, { headers: authenticatedHeaders });
  assert.equal(clientStatusResponse.status, 200);
  const clientStatus = await clientStatusResponse.json();
  assert.deepEqual(clientStatus.publicStats, {
    payloads: publicPayload.payloads.length,
    tools: publicPayload.tools.length,
    navigation: publicPayload.navigation.length,
    toolNavigation: publicPayload.toolNavigation.length,
  });

  const exportResponse = await fetch(`${baseUrl}/api/admin/export`, { headers: authenticatedHeaders });
  assert.equal(exportResponse.status, 200);
  assert.match(exportResponse.headers.get('content-disposition') || '', /^attachment; filename="payloader-export-/);
  const exportPayload = await exportResponse.json();
  assert.equal(exportPayload.format, 'payloader.export.v1');
  assert.ok(Array.isArray(exportPayload.data.payloads));
  assert.ok(Array.isArray(exportPayload.data.tools));
  assert.ok(Array.isArray(exportPayload.data.navigation));

  const impactResponse = await fetch(`${baseUrl}/api/admin/reset-impact?target=payloads`, { headers: authenticatedHeaders });
  assert.equal(impactResponse.status, 200);
  const impactPayload = await impactResponse.json();
  assert.equal(impactPayload.target, 'payloads');
  assert.ok(impactPayload.before.payloads > 0);
  assert.ok(impactPayload.seed.payloads > 0);

  const failedStatuses = [];
  for (let index = 0; index < 8; index += 1) {
    const failedLogin = await fetch(`${baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': userAgent,
        'x-forwarded-for': '198.51.100.10',
      },
      body: JSON.stringify({
        username: process.env.PAYLOADER_ADMIN_USER,
        password: `Wrong-Smoke-Password-${index}!`,
      }),
    });
    failedStatuses.push(failedLogin.status);
  }
  assert.deepEqual(failedStatuses, Array(8).fill(401));

  const recoveredLogin = await fetch(`${baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': userAgent,
      'x-forwarded-for': '198.51.100.10',
    },
    body: JSON.stringify({
      username: process.env.PAYLOADER_ADMIN_USER,
      password: process.env.PAYLOADER_ADMIN_PASSWORD,
    }),
  });
  assert.equal(recoveredLogin.status, 200);

  const isolatedClientLogin = await fetch(`${baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': userAgent,
      'x-forwarded-for': '203.0.113.20',
    },
    body: JSON.stringify({
      username: process.env.PAYLOADER_ADMIN_USER,
      password: process.env.PAYLOADER_ADMIN_PASSWORD,
    }),
  });
  assert.equal(isolatedClientLogin.status, 200);

  const saturatingClient = '192.0.2.60';
  for (let index = 0; index < 60; index += 1) {
    const anonymousLogin = await fetch(`${baseUrl}/api/admin/login`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': userAgent,
        'x-forwarded-for': saturatingClient,
      },
      body: JSON.stringify({
        username: 'x'.repeat(257),
        password: 'Invalid-Anonymous-Password-2026!',
      }),
    });
    assert.ok([401, 429].includes(anonymousLogin.status));
  }

  const loginAfterAnonymousFlood = await fetch(`${baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': userAgent,
      'x-forwarded-for': saturatingClient,
    },
    body: JSON.stringify({
      username: process.env.PAYLOADER_ADMIN_USER,
      password: process.env.PAYLOADER_ADMIN_PASSWORD,
    }),
  });
  assert.equal(loginAfterAnonymousFlood.status, 200);

  const logout = await fetch(`${baseUrl}/api/admin/logout`, {
    method: 'POST',
    headers: authenticatedHeaders,
  });
  assert.equal(logout.status, 200);
  assert.equal(logout.headers.get('set-cookie'), null);

  const revokedSession = await fetch(`${baseUrl}/api/admin/session`, { headers: authenticatedHeaders });
  assert.equal(revokedSession.status, 401);
});
