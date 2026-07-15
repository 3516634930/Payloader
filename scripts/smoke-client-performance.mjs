import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const timeoutMs = Number(process.env.PAYLOADER_CLIENT_PERF_TIMEOUT_MS || 30_000);
const tempRoot = await mkdtemp(join(tmpdir(), 'payloader-client-performance-'));
const buildRoot = join(tempRoot, 'builds');
const workDir = join(tempRoot, 'work');
const profileDir = join(tempRoot, 'profile');
process.env.PAYLOADER_CLIENT_BUILD_ROOT = buildRoot;
const configuredExecutable = String(process.env.PAYLOADER_CLIENT_PERF_EXECUTABLE || '').trim();
const packagedExecutable = configuredExecutable && isAbsolute(configuredExecutable)
  ? resolve(configuredExecutable)
  : '';
const electronPath = packagedExecutable ? '' : (await import('electron')).default;

const platformKey = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
const sharedRunnerPerformancePolicy = Object.freeze({
  windows: Object.freeze({
    windowReadyMs: 5_000,
    searchSettledMs: 1_000,
    idleWorkingSetMb: 550,
    interactionWorkingSetMb: 650,
    privateMemoryMb: 500,
    privateMemoryGrowthMb: 150,
    idleCpuPercentOneCore: 5,
  }),
  linux: Object.freeze({
    windowReadyMs: 12_000,
    searchSettledMs: 750,
    idleWorkingSetMb: 750,
    interactionWorkingSetMb: 850,
    idleCpuPercentOneCore: 10,
  }),
  macos: Object.freeze({
    windowReadyMs: 5_000,
    searchSettledMs: 750,
    idleWorkingSetMb: 700,
    interactionWorkingSetMb: 800,
    idleCpuPercentOneCore: 10,
  }),
});
const performanceProfile = String(process.env.PAYLOADER_CLIENT_PERF_PROFILE || 'strict');
if (!['strict', 'shared-runner'].includes(performanceProfile)) {
  throw new Error(`Unknown client performance profile: ${performanceProfile}`);
}
const rendererStateTimeoutMs = performanceProfile === 'shared-runner' ? 20_000 : 10_000;
const moduleUrl = new URL('../server/client-builder.mjs', import.meta.url);
moduleUrl.searchParams.set('client-performance-smoke', `${Date.now()}-${Math.random()}`);
const builder = await import(moduleUrl.href);
const policy = performanceProfile === 'shared-runner'
  ? sharedRunnerPerformancePolicy[platformKey]
  : builder.__clientBuildTest.performancePolicy[platformKey];

const getOpenPort = async () => {
  const server = createServer();
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise(resolveClose => server.close(resolveClose));
  return port;
};

const waitFor = async (read, description, limit = timeoutMs) => {
  const started = Date.now();
  let lastError = null;
  while (Date.now() - started < limit) {
    try {
      const result = await read();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await delay(50);
  }
  throw new Error(`Timed out waiting for ${description}${lastError ? `: ${lastError.message}` : ''}`);
};

const waitForExit = (child, limit) => new Promise(resolveExit => {
  if (child.exitCode !== null) {
    resolveExit(true);
    return;
  }
  const timer = setTimeout(() => resolveExit(false), limit);
  child.once('exit', () => {
    clearTimeout(timer);
    resolveExit(true);
  });
});

const connectCdp = async webSocketUrl => {
  const socket = new WebSocket(webSocketUrl);
  let nextId = 0;
  const pending = new Map();
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (!message.id) return;
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(message.error.message));
    else waiter.resolve(message.result);
  };
  await new Promise((resolveOpen, rejectOpen) => {
    socket.onopen = resolveOpen;
    socket.onerror = rejectOpen;
  });
  return {
    close: () => socket.close(),
    send: (method, params = {}) => new Promise((resolveSend, rejectSend) => {
      const id = ++nextId;
      pending.set(id, { resolve: resolveSend, reject: rejectSend });
      socket.send(JSON.stringify({ id, method, params }));
    }),
  };
};

const assertBudget = (condition, message) => {
  if (!condition) throw new Error(message);
};

let client = null;
let cdp = null;
try {
  await mkdir(workDir, { recursive: true });
  const publicData = await builder.__clientBuildTest.buildPublicDataSnapshot();
  const prepared = packagedExecutable
    ? null
    : await builder.__clientBuildTest.prepareElectronApp(workDir, publicData);
  const expectedStats = prepared?.manifest?.stats || {
    payloads: publicData.payloads.length,
    tools: publicData.tools.length,
  };
  const port = await getOpenPort();
  const args = [
    ...(process.platform === 'linux' ? ['--no-sandbox'] : []),
    ...(process.platform === 'linux' ? ['--disable-gpu', '--disable-dev-shm-usage'] : []),
    ...(prepared ? [prepared.appDir] : []),
    `--user-data-dir=${profileDir}`,
    `--remote-debugging-port=${port}`,
    '--no-first-run',
  ];
  const stderr = [];
  const startedAt = Date.now();
  client = spawn(packagedExecutable || electronPath, args, {
    env: { ...process.env, PAYLOADER_CLIENT_PERF_SMOKE: '1' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  client.stderr.setEncoding('utf8');
  client.stderr.on('data', chunk => stderr.push(chunk));

  let target;
  try {
    target = await waitFor(async () => {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      if (!response.ok) return null;
      const targets = await response.json();
      return targets.find(candidate => String(candidate.url || '').startsWith('payloader://app/')) || null;
    }, 'Payloader renderer');
  } catch (error) {
    const stderrTail = stderr.join('').trim().slice(-2_000);
    throw new Error(`${error.message}${stderrTail ? `\nClient stderr:\n${stderrTail}` : ''}`);
  }
  const rendererConnectedMs = Date.now() - startedAt;

  cdp = await connectCdp(target.webSocketDebuggerUrl);
  await cdp.send('Runtime.enable');
  const focusPointResult = await cdp.send('Runtime.evaluate', {
    expression: `(async () => {
      const waitFor = async (predicate, timeout = ${rendererStateTimeoutMs}) => {
        const started = performance.now();
        while (!predicate()) {
          if (performance.now() - started > timeout) throw new Error('Timed out waiting for renderer input');
          await new Promise(resolve => setTimeout(resolve, 25));
        }
      };
      await waitFor(() => document.querySelector('.search-input') && !document.body.innerText.includes('正在加载数据'));
      const input = document.querySelector('.search-input');
      input.scrollIntoView({ block: 'center', inline: 'center' });
      const rect = input.getBoundingClientRect();
      return {
        x: rect.left + Math.min(24, Math.max(1, rect.width / 2)),
        y: rect.top + Math.min(12, Math.max(1, rect.height / 2)),
      };
    })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (focusPointResult.exceptionDetails) {
    const rendererError = focusPointResult.exceptionDetails.exception?.description
      || focusPointResult.exceptionDetails.text
      || 'Unknown renderer exception';
    throw new Error(`Renderer mouse-input smoke failed: ${rendererError}`);
  }
  const focusPoint = focusPointResult.result?.value;
  await cdp.send('Input.dispatchMouseEvent', {
    type: 'mouseMoved',
    x: focusPoint.x,
    y: focusPoint.y,
    button: 'none',
  });
  await cdp.send('Input.dispatchMouseEvent', {
    type: 'mousePressed',
    x: focusPoint.x,
    y: focusPoint.y,
    button: 'left',
    clickCount: 1,
  });
  await cdp.send('Input.dispatchMouseEvent', {
    type: 'mouseReleased',
    x: focusPoint.x,
    y: focusPoint.y,
    button: 'left',
    clickCount: 1,
  });
  const focusVerification = await cdp.send('Runtime.evaluate', {
    expression: `document.activeElement?.matches('.search-input') === true`,
    returnByValue: true,
  });
  assertBudget(focusVerification.result?.value === true, 'Mouse input did not focus the search box.');
  const smokeResult = await cdp.send('Runtime.evaluate', {
    expression: `(async () => {
      const waitFor = async (predicate, timeout = ${rendererStateTimeoutMs}) => {
        const started = performance.now();
        while (!predicate()) {
          if (performance.now() - started > timeout) throw new Error('Timed out waiting for renderer state');
          await new Promise(resolve => setTimeout(resolve, 25));
        }
      };
      await waitFor(() => document.querySelector('.search-input') && !document.body.innerText.includes('正在加载数据'));
      const [publicResponse, customResponse, buildResponse] = await Promise.all([
        fetch('/api/public-data'),
        fetch('/api/custom-tools'),
        fetch('/api/client-build'),
      ]);
      const publicData = await publicResponse.json();
      const customData = await customResponse.json();
      const buildData = await buildResponse.json();
      const input = document.querySelector('.search-input');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      const readMetrics = async () => (await fetch('/api/client-performance')).json();
      const waitForReadyMetrics = async (timeout = 5000) => {
        const requireHardwareAccelerationStatus = ${platformKey === 'windows'};
        const started = performance.now();
        let metrics = await readMetrics();
        while (
          !Number.isFinite(metrics.windowReadyMs)
          || (requireHardwareAccelerationStatus && typeof metrics.hardwareAccelerationEnabled !== 'boolean')
        ) {
          if (performance.now() - started > timeout) throw new Error('Timed out waiting for ready-to-show metrics');
          await new Promise(resolve => setTimeout(resolve, 50));
          metrics = await readMetrics();
        }
        return metrics;
      };
      await waitForReadyMetrics();
      await new Promise(resolve => setTimeout(resolve, 500));
      const initialMetrics = await readMetrics();
      const searchStarted = performance.now();
      setter.call(input, 'SQL');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      await waitFor(() => document.querySelectorAll('.result-item').length > 0);
      const searchSettledMs = performance.now() - searchStarted;
      for (const query of ['Windows', 'Linux', 'XSS', 'JWT', 'PowerShell', 'SQL']) {
        setter.call(input, query);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        await new Promise(resolve => setTimeout(resolve, 180));
      }
      await waitFor(() => document.querySelectorAll('.result-item').length > 0);
      const peakMetrics = await readMetrics();
      await new Promise(resolve => setTimeout(resolve, 5000));
      const metricSamples = [];
      for (let index = 0; index < 5; index += 1) {
        metricSamples.push(await readMetrics());
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      metricSamples.sort((left, right) => left.workingSetMb - right.workingSetMb);
      return {
        payloads: publicData.payloads.length,
        tools: publicData.tools.length,
        customCount: customData.categories.length,
        offlineClient: buildData.offlineClient,
        resultCount: document.querySelectorAll('.result-item').length,
        searchSettledMs,
        initialMetrics,
        peakMetrics,
        metrics: metricSamples[Math.floor(metricSamples.length / 2)],
      };
    })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (smokeResult.exceptionDetails) {
    const rendererError = smokeResult.exceptionDetails.exception?.description
      || smokeResult.exceptionDetails.text
      || 'Unknown renderer exception';
    const stderrTail = stderr.join('').trim().slice(-2_000);
    throw new Error(
      `Renderer performance smoke failed: ${rendererError}${stderrTail ? `\nClient stderr:\n${stderrTail}` : ''}`,
    );
  }
  const result = smokeResult.result?.value;
  if (!result || typeof result !== 'object') {
    throw new Error('Renderer performance smoke failed: CDP returned no serializable result.');
  }
  const windowReadyMs = result.initialMetrics.windowReadyMs;
  const privateMemoryGrowthMb = result.metrics.privateMemoryMb === null
    ? null
    : result.metrics.privateMemoryMb - result.initialMetrics.privateMemoryMb;

  const secondStartedAt = Date.now();
  const secondInstance = spawn(packagedExecutable || electronPath, args, {
    env: { ...process.env, PAYLOADER_CLIENT_PERF_SMOKE: '1' },
    stdio: 'ignore',
  });
  const secondExited = await waitForExit(secondInstance, 5_000);
  const secondInstanceExitMs = Date.now() - secondStartedAt;
  if (!secondExited) secondInstance.kill();

  console.log(JSON.stringify({
    platform: platformKey,
    performanceProfile,
    windowReadyMs,
    rendererConnectedMs,
    searchSettledMs: Number(result.searchSettledMs.toFixed(1)),
    idleWorkingSetMb: Number(result.initialMetrics.workingSetMb.toFixed(1)),
    peakWorkingSetMb: Number(result.peakMetrics.workingSetMb.toFixed(1)),
    stableWorkingSetMb: Number(result.metrics.workingSetMb.toFixed(1)),
    privateMemoryMb: result.metrics.privateMemoryMb === null ? null : Number(result.metrics.privateMemoryMb.toFixed(1)),
    privateMemoryGrowthMb: privateMemoryGrowthMb === null ? null : Number(privateMemoryGrowthMb.toFixed(1)),
    idleCpuPercent: Number(result.metrics.cpuPercent.toFixed(2)),
    hardwareAccelerationEnabled: result.metrics.hardwareAccelerationEnabled,
    processCount: result.metrics.processCount,
    secondInstanceExitMs,
    payloads: result.payloads,
    tools: result.tools,
  }, null, 2));

  assertBudget(result.payloads === expectedStats.payloads, 'Packaged payload count is incomplete.');
  assertBudget(result.tools === expectedStats.tools, 'Packaged tool count is incomplete.');
  assertBudget(result.offlineClient === true, 'Packaged client build endpoint is not offline.');
  assertBudget(result.resultCount > 0, 'Search did not return results.');
  assertBudget(secondExited, 'Second client instance did not exit.');
  assertBudget(Number.isFinite(windowReadyMs), 'Client did not report a ready-to-show window time.');
  assertBudget(windowReadyMs <= policy.windowReadyMs, `Window ready time ${windowReadyMs}ms exceeds ${policy.windowReadyMs}ms.`);
  assertBudget(result.searchSettledMs <= policy.searchSettledMs, `Search time ${result.searchSettledMs.toFixed(1)}ms exceeds ${policy.searchSettledMs}ms.`);
  assertBudget(result.initialMetrics.workingSetMb <= policy.idleWorkingSetMb, `Idle working set ${result.initialMetrics.workingSetMb.toFixed(1)}MB exceeds ${policy.idleWorkingSetMb}MB.`);
  assertBudget(result.metrics.workingSetMb <= policy.interactionWorkingSetMb, `Stable interaction working set ${result.metrics.workingSetMb.toFixed(1)}MB exceeds ${policy.interactionWorkingSetMb}MB.`);
  if (policy.privateMemoryMb && result.metrics.privateMemoryMb !== null) {
    assertBudget(result.metrics.privateMemoryMb <= policy.privateMemoryMb, `Private memory ${result.metrics.privateMemoryMb.toFixed(1)}MB exceeds ${policy.privateMemoryMb}MB.`);
    assertBudget(privateMemoryGrowthMb <= policy.privateMemoryGrowthMb, `Repeated search grew private memory by ${privateMemoryGrowthMb.toFixed(1)}MB, exceeding ${policy.privateMemoryGrowthMb}MB.`);
  }
  assertBudget(
    platformKey !== 'windows' || result.metrics.hardwareAccelerationEnabled === false,
    'Windows client hardware acceleration must stay disabled for input compatibility.',
  );
  assertBudget(result.metrics.cpuPercent <= policy.idleCpuPercentOneCore, `Idle CPU ${result.metrics.cpuPercent.toFixed(2)}% exceeds ${policy.idleCpuPercentOneCore}%.`);
  assertBudget(!stderr.join('').includes('Unrecognized Content-Security-Policy'), 'Client emitted an invalid CSP warning.');

  await cdp.send('Runtime.evaluate', {
    expression: `fetch('/api/client-performance/quit', { method: 'POST' })`,
    awaitPromise: true,
  });
  await waitForExit(client, 5_000);
} finally {
  cdp?.close();
  if (client && client.exitCode === null) client.kill();
  await rm(tempRoot, { recursive: true, force: true }).catch(() => {});
}
