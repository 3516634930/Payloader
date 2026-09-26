// 管理服务器壳：常量解析、四模块工厂组合（凭据/会话/限流/静态）、声明式路由注册表装配、
// 请求编排（public → auth-entry → admin 限流+鉴权 → 静态 → 前端回落）与进程入口。
// 路由声明分布在 routes-public / routes-auth / routes-admin / routes-logo / static 五个文件。

import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  closeStore,
  createDataExportPackage,
  deleteAdminItem,
  deleteCustomContent,
  ensureStoreReady,
  getMetadataValue,
  getPublicData,
  getResetImpact,
  getSettings,
  importDataPackage,
  listAdminItems,
  listCustomContent,
  listCustomPayloads,
  moveAdminItem,
  previewImportPackage,
  resetDefaultData,
  saveAdminItem,
  saveCustomContent,
  saveNavigationItem,
  saveSettings,
  setMetadataValue,
} from './data-store.mjs';
import {
  clientBuildDownload,
  getClientBuildStatus,
  getPublicClientBuildInfo,
  startClientBuild,
} from './client-builder.mjs';
import { officialProjectUrl, publicProjectRoute } from './project-attribution.mjs';
import { createShutdownController } from './server-lifecycle.mjs';
import { createVersionChecker, VERSION_STATUS_METADATA_KEY } from './version-checker.mjs';
import {
  createRepoMonitor,
  REPO_MONITOR_STATUS_METADATA_KEY,
  REPO_MONITOR_SUBSCRIPTIONS_METADATA_KEY,
} from './repo-monitor.mjs';
import { baseResponseHeaders, json, methodNotAllowed, safeErrorPayload, text } from './http-helpers.mjs';

export { readBody } from './http-helpers.mjs';
import { createPublicDataResponder } from './public-data-response.mjs';
import { createRateLimiter } from './rate-limit.mjs';
import { createCredentialStore } from './admin-credentials.mjs';
import { createSessionManager } from './admin-session.mjs';
import { Router } from './router.mjs';
import { createPublicRoutes } from './routes-public.mjs';
import { createAuthRoutes } from './routes-auth.mjs';
import { createAdminRoutes } from './routes-admin.mjs';
import { createLogoUploader } from './routes-logo.mjs';
import { createCtfProxyRoutes } from './routes-ctf-proxy.mjs';
import { createCtfPortscanRoutes } from './routes-ctf-portscan.mjs';
import { createRepoMonitorRoutes } from './routes-repo-monitor.mjs';
import { createStaticHandlers } from './static.mjs';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const distDir = join(rootDir, 'dist');
const adminDir = join(rootDir, 'admin');
const dataDir = resolve(process.env.PAYLOADER_DATA_DIR || join(rootDir, 'data'));
const uploadDir = join(dataDir, 'uploads');
const logoUploadDir = join(uploadDir, 'logo');

const host = process.env.PAYLOADER_HOST || '127.0.0.1';
const port = Number(process.env.PAYLOADER_PORT || 8081);
const configuredAdminUser = String(process.env.PAYLOADER_ADMIN_USER || '').trim();
const configuredAdminPassword = String(process.env.PAYLOADER_ADMIN_PASSWORD || '');
const loopbackHosts = new Set(['127.0.0.1', '::1', 'localhost']);
const allowInsecureDevCredentials = process.env.PAYLOADER_ALLOW_INSECURE_DEV_CREDENTIALS !== 'false'
  && process.env.NODE_ENV !== 'production'
  && loopbackHosts.has(host.toLowerCase());
const requiresExplicitInitialCredentials = !allowInsecureDevCredentials;
const defaultAdminUser = configuredAdminUser || 'admin';
const defaultAdminPassword = configuredAdminPassword || 'payloader-admin!';
const sessionTtlMs = Number(process.env.PAYLOADER_ADMIN_SESSION_TTL_MS || 8 * 60 * 60 * 1000);
const jwtSecretFile = join(dataDir, 'admin-jwt-secret.key');
const maxUrlLength = 4_096;

// ---- 组合根：每个服务器实例一组独立状态（凭据缓存/会话表/限流桶/密钥缓存） ----
const sessions = createSessionManager({
  jwtSecretFile,
  sessionTtlMs,
  getCredentials: () => getAdminCredentials(),
});
const { createAdminSession, getJwtSecret, readAdminSession, revokeAllSessions, revokeSession } = sessions;
const credentials = createCredentialStore({
  env: {
    requiresExplicitInitialCredentials,
    defaultAdminUser,
    defaultAdminPassword,
    configuredAdminUser,
    configuredAdminPassword,
  },
  onCredentialsSaved: revokeAllSessions,
});
const {
  endLoginVerify,
  getAdminCredentials,
  publicCredentialInfo,
  saveAdminCredentials,
  tryBeginLoginVerify,
  validAdminCredentials,
} = credentials;
const {
  adminRequestLimit,
  checkRateLimit,
  clearRateLimit,
  clientKey,
  failedAuthLimit,
  failedLoginLimit,
  respondTooManyRequests,
} = createRateLimiter();

const publicDataResponder = createPublicDataResponder({
  loadData: getPublicData,
  responseHeaders: baseResponseHeaders,
});

const staticHandlers = createStaticHandlers({
  distDir,
  adminDir,
  logoUploadDir,
  getSettings,
  checkRateLimit,
  adminRequestLimit,
});
const { safeResolve, serveFrontendFallback } = staticHandlers;

const requireAuth = async (request, response) => {
  if (await readAdminSession(request)) return true;
  if (!checkRateLimit(request, response, 'admin-auth-failed', failedAuthLimit)) return false;
  if (request.url && String(request.url).startsWith('/api/')) {
    json(response, 401, { error: '登录已失效，请重新登录' });
    return false;
  }
  response.writeHead(302, {
    ...baseResponseHeaders,
    location: '/admin/login',
    'cache-control': 'no-store',
  });
  response.end();
  return false;
};

// ---- 路由注册表装配 ----
const services = {
  versionChecker: createVersionChecker({
    repositoryUrl: officialProjectUrl,
    projectRoute: publicProjectRoute,
    loadStatus: () => getMetadataValue(VERSION_STATUS_METADATA_KEY, ''),
    saveStatus: value => setMetadataValue(VERSION_STATUS_METADATA_KEY, value),
  }),
  // 订阅仓库监控（v2.0.1）：Atom 通道多目标引擎，token 仅取环境变量，端点全走管理端鉴权
  repoMonitor: createRepoMonitor({
    loadSubscriptions: () => getMetadataValue(REPO_MONITOR_SUBSCRIPTIONS_METADATA_KEY, null),
    saveSubscriptions: value => setMetadataValue(REPO_MONITOR_SUBSCRIPTIONS_METADATA_KEY, value),
    loadStatuses: () => getMetadataValue(REPO_MONITOR_STATUS_METADATA_KEY, null),
    saveStatuses: value => setMetadataValue(REPO_MONITOR_STATUS_METADATA_KEY, value),
  }),
};

const router = new Router();
createPublicRoutes({
  publicDataResponder,
  ensureApplicationReady: (...args) => ensureApplicationReady(...args),
  officialProjectUrl,
  publicProjectRoute,
  getPublicClientBuildInfo,
  clientBuildDownload,
  getPublicData,
  baseResponseHeaders,
}).registerPublicRoutes(router);
createAuthRoutes({
  readAdminSession,
  createAdminSession,
  revokeSession,
  getAdminCredentials,
  validAdminCredentials,
  tryBeginLoginVerify,
  endLoginVerify,
  checkRateLimit,
  clearRateLimit,
  respondTooManyRequests,
  failedLoginLimit,
  adminRequestLimit,
}).registerAuthRoutes(router);
createAdminRoutes({
  services,
  createDataExportPackage,
  listCustomPayloads,
  listCustomContent,
  saveCustomContent,
  deleteCustomContent,
  getResetImpact,
  resetDefaultData,
  getSettings,
  saveSettings,
  importDataPackage,
  previewImportPackage,
  listAdminItems,
  saveAdminItem,
  saveNavigationItem,
  deleteAdminItem,
  moveAdminItem,
  getClientBuildStatus,
  startClientBuild,
  clientBuildDownload,
  getAdminCredentials,
  publicCredentialInfo,
  saveAdminCredentials,
}).registerAdminRoutes(router);
createLogoUploader({ logoUploadDir, safeResolve }).registerLogoRoutes(router);
// CTF 解题模块开关（批次 TG）：settings.ctfEnabled 缺省即开；proxy/portscan 端点服务端强制执行
const isCtfEnabled = async () => (await getSettings()).ctfEnabled !== false;
createCtfProxyRoutes({ isCtfEnabled }).registerCtfProxyRoutes(router);
createCtfPortscanRoutes({ isCtfEnabled }).registerCtfPortscanRoutes(router);
createRepoMonitorRoutes({ repoMonitor: services.repoMonitor }).registerRepoMonitorRoutes(router);
staticHandlers.registerStaticRoutes(router);

export const ensureApplicationReady = async () => {
  await Promise.all([
    ensureStoreReady(),
    getAdminCredentials(),
    getJwtSecret(),
    publicDataResponder.prepare(),
  ]);
  return true;
};

// ---- 请求编排：public → auth-entry → admin 限流+鉴权 → admin 受保护 → 静态 → 前端回落 ----
const handleRequest = async (request, response) => {
  try {
    if (String(request.url || '').length > maxUrlLength) {
      text(response, 414, 'URI too long');
      return;
    }
    const url = new URL(request.url || '/', 'http://payloader.local');
    const context = { baseResponseHeaders, services };

    if (await router.dispatch(request, response, url, 'public', context)) return;

    if (url.pathname.startsWith('/api/admin/')) {
      if (await router.dispatch(request, response, url, 'auth-entry', context)) return;
      if (!checkRateLimit(request, response, 'admin-request', adminRequestLimit)) return;
      if (!await requireAuth(request, response)) return;
      if (await router.dispatch(request, response, url, 'admin', context)) return;
      text(response, 404, 'Not found');
      return;
    }

    if (await router.dispatch(request, response, url, 'static', context)) return;

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      methodNotAllowed(response, ['GET', 'HEAD']);
      return;
    }
    await serveFrontendFallback(request, response, url);
  } catch (error) {
    const { status, payload } = safeErrorPayload(error);
    json(response, status, payload);
  }
};

export const createAdminServer = (options = {}) => {
  if (options.versionChecker) services.versionChecker = options.versionChecker;
  if (options.repoMonitor) services.repoMonitor = options.repoMonitor;
  const server = createServer((request, response) => handleRequest(request, response));
  server.once('close', () => {
    services.versionChecker.stop();
    services.repoMonitor.stop();
  });
  return server;
};

export const __adminSecurityTest = Object.freeze({ clientKey });

export const startAdminServer = async () => {
  await ensureApplicationReady();
  const credentials = await getAdminCredentials();
  await services.versionChecker.start();
  await services.repoMonitor.start();
  const server = createAdminServer({
    versionChecker: services.versionChecker,
    repoMonitor: services.repoMonitor,
  });
  await new Promise((resolveListen, rejectListen) => {
    const onError = error => {
      services.versionChecker.stop();
      services.repoMonitor.stop();
      rejectListen(error);
    };
    server.once('error', onError);
    server.listen(port, host, () => {
      server.off('error', onError);
      resolveListen();
    });
  });

  const address = server.address();
  const listeningPort = address && typeof address === 'object' ? address.port : port;
  console.log(`Payloader frontend: http://${host}:${listeningPort}/`);
  console.log(`Payloader admin:    http://${host}:${listeningPort}/admin`);
  console.log(`Admin user: ${credentials.username}`);
  console.log('Initial credentials can be set with PAYLOADER_ADMIN_USER and PAYLOADER_ADMIN_PASSWORD before first launch.');
  return server;
};

const modulePath = resolve(fileURLToPath(import.meta.url));
const entryPath = process.argv[1] ? resolve(process.argv[1]) : '';
const isMainModule = process.platform === 'win32'
  ? modulePath.toLowerCase() === entryPath.toLowerCase()
  : modulePath === entryPath;

if (isMainModule) {
  startAdminServer().then(server => {
    const shutdown = createShutdownController({ server, closeResources: closeStore });
    const requestShutdown = signal => shutdown.shutdown(signal).catch(error => {
      console.error(`Payloader shutdown failed: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 1;
    });
    process.once('SIGINT', () => requestShutdown('SIGINT'));
    process.once('SIGTERM', () => requestShutdown('SIGTERM'));
  }).catch(error => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Payloader startup failed: ${message}`);
    process.exitCode = 1;
  });
}
