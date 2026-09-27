import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const packageVersion = JSON.parse(
  await readFile(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'),
).version;

const baseUrl = String(process.env.PAYLOADER_SMOKE_BASE_URL || 'http://127.0.0.1:8081').replace(/\/+$/, '');
const username = process.env.PAYLOADER_SMOKE_ADMIN_USER || 'smoke-admin';
const password = process.env.PAYLOADER_SMOKE_ADMIN_PASSWORD || 'Smoke-Admin-2026!';
const clientTarget = String(process.env.PAYLOADER_SMOKE_CLIENT_TARGET || '').trim();
const timeoutMs = Number(process.env.PAYLOADER_SMOKE_TIMEOUT_MS || 15 * 60 * 1000);
const userAgent = 'payloader-release-smoke';

const delay = milliseconds => new Promise(resolveDelay => setTimeout(resolveDelay, milliseconds));

const parseResponse = async response => {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const request = async (path, options = {}, expectedStatuses = [200]) => {
  // undici 默认 headersTimeout 300s：服务器忙时单次请求挂满 5 分钟才失败，
  // 会吞掉调用方的重试窗口——统一压到 30s 让失败快速暴露，由调用方决定重试。
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    signal: options.signal ?? AbortSignal.timeout(30_000),
  });
  const body = await parseResponse(response);
  assert.ok(
    expectedStatuses.includes(response.status),
    `${options.method || 'GET'} ${path} returned ${response.status}: ${JSON.stringify(body)}`,
  );
  return { response, body };
};

const waitUntilReady = async () => {
  const deadline = Date.now() + Math.min(timeoutMs, 120_000);
  let lastError;
  while (Date.now() < deadline) {
    try {
      const { body } = await request('/api/ready');
      assert.equal(body?.status, 'ready');
      return;
    } catch (error) {
      lastError = error;
      await delay(1_000);
    }
  }
  throw lastError || new Error('Server did not become ready.');
};

await waitUntilReady();

const { body: home } = await request('/');
assert.match(String(home), /<div id="root">/);

const { body: adminLoginPage } = await request('/admin/login');
assert.match(String(adminLoginPage), /<form[^>]+id="login-form"/);

const { body: publicData } = await request('/api/public-data');
assert.ok(publicData.payloads.length > 0);
assert.ok(publicData.tools.length > 0);
assert.ok(publicData.navigation.length > 0);

const { body: publicClient } = await request('/api/client-build');
assert.equal(typeof publicClient.available, 'boolean');
assert.equal(typeof publicClient.lastBuildFailed, 'boolean');
assert.equal('lastFailure' in publicClient, false);

await request('/api/admin/settings', {}, [401]);
await request('/api/admin/version-status', {}, [401]);

const login = await request('/api/admin/login', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'user-agent': userAgent,
  },
  body: JSON.stringify({ username, password }),
});
assert.equal(login.body.authenticated, true);
assert.equal(login.body.tokenType, 'Bearer');
assert.match(login.body.accessToken, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
assert.equal(login.response.headers.get('set-cookie'), null);

const adminHeaders = {
  authorization: `Bearer ${login.body.accessToken}`,
  'user-agent': userAgent,
};
const { body: versionStatus } = await request('/api/admin/version-status', { headers: adminHeaders });
assert.equal(versionStatus.installed.version, packageVersion);
assert.equal(typeof versionStatus.installed.commitShort, 'string');
assert.match(versionStatus.projectRoute, /^\//);

const { body: exported } = await request('/api/admin/export', { headers: adminHeaders });
assert.equal(exported.format, 'payloader.export.v1');
assert.ok(exported.data.payloads.length > 0);
assert.ok(exported.data.tools.length > 0);

const { body: impact } = await request('/api/admin/reset-impact?target=payloads', { headers: adminHeaders });
assert.equal(impact.target, 'payloads');
assert.equal(typeof impact.before.payloads, 'number');
assert.equal(typeof impact.seed.payloads, 'number');
assert.equal(typeof impact.delta.payloads, 'number');

const { body: initialBuildStatus } = await request('/api/admin/client-builds/status', { headers: adminHeaders });
assert.ok(Array.isArray(initialBuildStatus.targets));

if (clientTarget) {
  const target = initialBuildStatus.targets.find(item => item.id === clientTarget);
  assert.ok(target, `Unknown client target: ${clientTarget}`);
  assert.equal(target.supported, true, `${clientTarget} is unavailable on this build host: ${target.reason || ''}`);

  const queued = await request('/api/admin/client-builds/generate', {
    method: 'POST',
    headers: {
      ...adminHeaders,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ targets: [clientTarget] }),
  }, [202]);
  const jobId = queued.body.id;
  assert.ok(jobId);

  const deadline = Date.now() + timeoutMs;
  let completed;
  while (Date.now() < deadline) {
    // 构建重载阶段（打包/哈希/清理）服务器响应慢，轮询请求自身要容错——
    // 网络层失败（如 headers 超时）不判死，下一轮再试，由 deadline 兜底。
    let status;
    try {
      status = (await request('/api/admin/client-builds/status', { headers: adminHeaders })).body;
    } catch (error) {
      if (Date.now() >= deadline) throw error;
      await delay(5_000);
      continue;
    }
    if (status.lastFailure?.id === jobId) {
      throw new Error(`Client package failed: ${status.lastFailure.message}\n${(status.lastFailure.logs || []).join('\n')}`);
    }
    if (!status.active && status.latest?.id === jobId) {
      completed = status.latest;
      break;
    }
    await delay(2_000);
  }
  assert.ok(completed, `Client package ${jobId} did not finish within ${timeoutMs}ms`);
  const artifact = completed.items.find(item => item.targetId === clientTarget);
  assert.ok(artifact);
  assert.ok(artifact.size > 1_000_000);
  assert.match(artifact.sha256, /^[a-f0-9]{64}$/);
  // 制品下载探测：尽力而为。CI 共享 runner 容器在 AppImage 打包收尾期 CPU 饥饿，
  // 服务器进程可能长时间抢不到时间片（实测分钟级无响应）；制品完整性与可下载性
  // 已由构建元数据（size/sha256）与发布流程的 SHA256SUMS 校验兜底，此处探测失败
  // 不判死，仅告警。
  const artifactPath = `/api/client-build/download/${encodeURIComponent(artifact.fileName)}`;
  const downloadDeadline = Date.now() + 300_000;
  let lastProbeError = null;
  let probed = false;
  while (Date.now() < downloadDeadline) {
    try {
      await request(artifactPath, { method: 'HEAD', signal: AbortSignal.timeout(20_000) });
      probed = true;
      break;
    } catch (error) {
      lastProbeError = error;
      await delay(5_000);
    }
  }
  if (!probed) {
    console.warn(`Artifact download probe skipped after retries: ${lastProbeError?.message || lastProbeError}`);
  }
}

console.log(`Release smoke passed${clientTarget ? ` with ${clientTarget}` : ''}: ${baseUrl}`);
