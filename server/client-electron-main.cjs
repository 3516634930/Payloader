'use strict';

const { app, BrowserWindow, protocol, shell, session } = require('electron');
const { createHash, timingSafeEqual } = require('node:crypto');
const { readFile } = require('node:fs/promises');
const { createReadStream, existsSync } = require('node:fs');
const { Readable } = require('node:stream');
const { extname, isAbsolute, join, relative, resolve, sep } = require('node:path');
const {
  clientProjectRoute,
  officialProjectUrl,
} = require('./project-attribution.cjs');
const {
  loadExternalDeploymentPackage,
  resolveDeploymentPackageCandidates,
} = require('./client-deployment-runtime.cjs');

const appRoot = __dirname;
const distRoot = join(appRoot, 'dist');
const legacyAppDataRoot = join(appRoot, 'app');
const legacyManifestPath = join(legacyAppDataRoot, 'manifest.json');
let publicDataPath = join(legacyAppDataRoot, 'public-data.json');
let customToolsPath = join(legacyAppDataRoot, 'custom-tools.json');
const scheme = 'payloader';
const host = 'app';
const pathSeparator = sep;
const internalOrigin = `${scheme}://${host}`;
const internalUrlPrefix = `${internalOrigin}/`;
const protectedXeyeUrl = 'https://xss.icu/';
const guardedWebContents = new WeakSet();
const performanceSmokeEnabled = process.env.PAYLOADER_CLIENT_PERF_SMOKE === '1';
const processStartedAt = Date.now();
let windowReadyMs = null;
let hardwareAccelerationEnabled = null;
let deploymentPackage = null;

// Software compositing avoids GPU-driver and remote-desktop input stalls on Windows.
if (process.platform === 'win32') {
  app.disableHardwareAcceleration();
}
app.once('gpu-info-update', () => {
  hardwareAccelerationEnabled = app.isHardwareAccelerationEnabled();
});

protocol.registerSchemesAsPrivileged([
  {
    scheme,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: false,
      stream: true,
      codeCache: true,
    },
  },
]);

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
};

const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "child-src 'none'",
  "img-src 'self' data: blob:",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "connect-src 'self'",
  "worker-src 'self'",
  "media-src 'none'",
  "manifest-src 'self'",
  "form-action 'self'",
].join('; ');

const baseHeaders = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'content-security-policy': contentSecurityPolicy,
};

const readText = filePath => readFile(filePath, 'utf8');
const safeHashEquals = (actual, expected) => {
  const left = Buffer.from(String(actual || ''), 'hex');
  const right = Buffer.from(String(expected || ''), 'hex');
  return left.length === right.length && timingSafeEqual(left, right);
};

const hashFile = filePath => new Promise((resolveHash, rejectHash) => {
  const hash = createHash('sha256');
  const stream = createReadStream(filePath);
  stream.on('data', chunk => hash.update(chunk));
  stream.on('error', rejectHash);
  stream.on('end', () => resolveHash(hash.digest('hex')));
});

const response = (body, options = {}) => new Response(body, {
  status: options.status || 200,
  headers: {
    ...baseHeaders,
    'content-type': options.contentType || 'text/plain; charset=utf-8',
    'cache-control': options.cacheControl || 'no-store',
    ...options.headers,
  },
});

const jsonResponse = value => response(JSON.stringify(value), {
  contentType: 'application/json; charset=utf-8',
});

const isInside = (baseDir, target) => {
  const fromBase = relative(baseDir, target);
  return fromBase && fromBase !== '..' && !fromBase.startsWith(`..${pathSeparator}`) && !isAbsolute(fromBase);
};

const normalizeRoute = pathname => {
  try {
    return decodeURIComponent(pathname || '/');
  } catch {
    return '/';
  }
};

const isInternalAppUrl = value => {
  try {
    const url = new URL(String(value || ''));
    return url.protocol === `${scheme}:` && url.host === host && String(value || '').startsWith(internalUrlPrefix);
  } catch {
    return false;
  }
};

const normalizeAllowedExternalUrl = value => {
  if (value === clientProjectRoute) return officialProjectUrl;
  try {
    const url = new URL(String(value || ''));
    if (url.protocol !== 'https:' || url.username || url.password || url.search) return '';
    const pathname = url.pathname.replace(/\/+$/, '') || '/';
    if (url.hostname === 'xss.icu' && pathname === '/' && !url.hash) {
      return protectedXeyeUrl;
    }
    return '';
  } catch {
    return '';
  }
};

const openAllowedExternalUrl = value => {
  const safeUrl = normalizeAllowedExternalUrl(value);
  if (!safeUrl) return false;
  shell.openExternal(safeUrl).catch(() => {});
  return true;
};

const guardNavigation = (event, nextUrl) => {
  const targetUrl = typeof nextUrl === 'string' ? nextUrl : event?.url;
  if (isInternalAppUrl(targetUrl)) return;
  event.preventDefault();
};

const guardWebContents = contents => {
  if (!contents || guardedWebContents.has(contents)) return;
  guardedWebContents.add(contents);

  contents.setWindowOpenHandler(({ url }) => {
    openAllowedExternalUrl(url);
    return { action: 'deny' };
  });

  contents.on('will-navigate', guardNavigation);
  contents.on('will-frame-navigate', guardNavigation);
  contents.on('will-redirect', guardNavigation);
  contents.on('will-attach-webview', event => {
    event.preventDefault();
  });
  contents.on('did-create-window', childWindow => {
    childWindow.close();
  });
};

const configureOfflineSession = () => {
  const defaultSession = session.defaultSession;
  defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });
  defaultSession.setPermissionCheckHandler(() => false);
  defaultSession.webRequest.onBeforeRequest((details, callback) => {
    callback({ cancel: !isInternalAppUrl(details.url) });
  });
};

let manifest = null;
let startupErrorText = '';
const verifiedFiles = new Set();
const verificationPromises = new Map();

const escapeHtml = value => String(value || '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const startupErrorPage = () => `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Payloader 启动失败</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, "Microsoft YaHei", system-ui, sans-serif; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #0a0a0f;
      color: #eef2ff;
    }
    main {
      width: min(720px, calc(100vw - 32px));
      border: 1px solid rgba(148, 163, 184, 0.28);
      border-radius: 8px;
      background: #111827;
      padding: 24px;
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.42);
    }
    h1 { margin: 0 0 10px; font-size: 22px; }
    p { margin: 0 0 16px; color: #cbd5e1; line-height: 1.7; }
    pre {
      max-height: 280px;
      overflow: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      margin: 0;
      padding: 14px;
      border-radius: 8px;
      background: #020617;
      color: #fca5a5;
      font: 12px/1.6 ui-monospace, SFMono-Regular, Consolas, monospace;
    }
  </style>
</head>
<body>
  <main>
    <h1>Payloader 客户端启动失败</h1>
    <p>客户端已拦截外部网络访问。下面是本地离线资源或公开数据快照的加载错误，请重新在后台生成客户端。</p>
    <pre>${escapeHtml(startupErrorText || 'Unknown startup error')}</pre>
  </main>
</body>
</html>`;

const loadManifest = async () => {
  manifest = JSON.parse(await readText(legacyManifestPath));
  const candidates = resolveDeploymentPackageCandidates({
    configuredPath: process.env.PAYLOADER_CLIENT_DEPLOYMENT_DIR,
    platform: process.platform,
    execPath: process.execPath,
    appImagePath: process.env.APPIMAGE,
  });
  deploymentPackage = await loadExternalDeploymentPackage(candidates, {
    buildContractVersion: manifest.buildContractVersion,
  });
  if (deploymentPackage) {
    publicDataPath = deploymentPackage.publicDataPath;
    customToolsPath = deploymentPackage.customToolsPath;
  }
};

const verifyBundledFile = async (filePath, expectedHash, label) => {
  if (verifiedFiles.has(filePath)) return;
  if (verificationPromises.has(filePath)) return verificationPromises.get(filePath);
  const verification = (async () => {
    const actualHash = await hashFile(filePath);
    if (!expectedHash || !safeHashEquals(actualHash, expectedHash)) {
      throw new Error(`Payloader ${label} hash integrity check failed.`);
    }
    verifiedFiles.add(filePath);
  })().finally(() => {
    verificationPromises.delete(filePath);
  });
  verificationPromises.set(filePath, verification);
  return verification;
};

const isAdminPath = pathname => (
  pathname === '/admin' ||
  pathname.startsWith('/admin/') ||
  pathname === '/api/admin' ||
  pathname.startsWith('/api/admin/')
);

const safeAssetPath = route => {
  const deploymentAsset = deploymentPackage?.assets?.[route];
  if (deploymentAsset) return deploymentAsset;
  const asset = manifest?.routes?.[route]
    || (route === '/' ? manifest?.routes?.['/index.html'] : null);
  if (!asset || typeof asset.file !== 'string') return null;
  const target = resolve(appRoot, asset.file);
  const allowed = isInside(distRoot, target) || isInside(legacyAppDataRoot, target);
  return allowed ? { ...asset, target } : null;
};

const streamFileResponse = (filePath, options = {}) => response(
  options.head ? undefined : Readable.toWeb(createReadStream(filePath)),
  options,
);

const serveAsset = async (asset, head = false) => {
  if (asset.sha256) {
    await verifyBundledFile(asset.target, String(asset.sha256), 'deployment asset');
  }
  // Vite content-hashed assets (filename contains 8+ hex chars) are immutable.
  const isImmutable = /[.-][0-9a-f]{8,}\.(js|css|woff2?)$/i.test(asset.target);
  return streamFileResponse(asset.target, {
    head,
    contentType: asset.mimeType || mimeTypes[extname(asset.target).toLowerCase()] || 'application/octet-stream',
    cacheControl: isImmutable ? 'public, max-age=31536000, immutable' : (asset.cacheControl || 'public, max-age=3600'),
    headers: asset.size ? { 'content-length': String(asset.size) } : {},
  });
};

const handleProtocol = async request => {
  if (String(request.url || '').length > 4096) {
    return response('URI too long', { status: 414 });
  }

  const url = new URL(request.url);
  if (url.host !== host) {
    return response('Not found', { status: 404 });
  }

  const pathname = normalizeRoute(url.pathname);
  if (startupErrorText && pathname !== '/favicon.ico') {
    return response(startupErrorPage(), {
      status: 500,
      contentType: 'text/html; charset=utf-8',
      cacheControl: 'no-store',
    });
  }

  if (isAdminPath(pathname)) {
    return response('Not found', { status: 404 });
  }

  if (pathname === '/api/public-data') {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return response('Method not allowed', {
        status: 405,
        headers: { allow: 'GET, HEAD' },
      });
    }
    try {
      const descriptor = deploymentPackage?.manifest?.files?.['public-data.json'];
      await verifyBundledFile(
        publicDataPath,
        String(descriptor?.sha256 || manifest?.publicDataSha256 || ''),
        'offline snapshot',
      );
      return streamFileResponse(publicDataPath, {
        head: request.method === 'HEAD',
        contentType: descriptor?.mimeType || 'application/json; charset=utf-8',
        cacheControl: 'public, max-age=31536000, immutable',
        headers: descriptor?.size ? { 'content-length': String(descriptor.size) } : {},
      });
    } catch (error) {
      startupErrorText = error && error.stack ? error.stack : String(error || 'Unknown snapshot error');
      return response(startupErrorPage(), {
        status: 500,
        contentType: 'text/html; charset=utf-8',
        cacheControl: 'no-store',
      });
    }
  }

  if (pathname === '/api/custom-tools') {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return response('Method not allowed', {
        status: 405,
        headers: { allow: 'GET, HEAD' },
      });
    }
    try {
      const descriptor = deploymentPackage?.manifest?.files?.['custom-tools.json'];
      await verifyBundledFile(
        customToolsPath,
        String(descriptor?.sha256 || manifest?.customToolsSha256 || ''),
        'custom tools snapshot',
      );
      return streamFileResponse(customToolsPath, {
        head: request.method === 'HEAD',
        contentType: descriptor?.mimeType || 'application/json; charset=utf-8',
        cacheControl: 'public, max-age=31536000, immutable',
        headers: descriptor?.size ? { 'content-length': String(descriptor.size) } : {},
      });
    } catch (error) {
      startupErrorText = error && error.stack ? error.stack : String(error || 'Unknown snapshot error');
      return response(startupErrorPage(), {
        status: 500,
        contentType: 'text/html; charset=utf-8',
        cacheControl: 'no-store',
      });
    }
  }

  if (pathname === '/api/client-build') {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return response('Method not allowed', {
        status: 405,
        headers: { allow: 'GET, HEAD' },
      });
    }
    return jsonResponse({
      available: false,
      latest: null,
      items: [],
      offlineClient: true,
      runtime: 'electron-offline-client',
      distribution: 'packaged-offline-client',
      generatedAt: deploymentPackage?.manifest?.generatedAt || manifest?.generatedAt || '',
      productName: manifest?.productName || 'Payloader',
      targets: [],
      policies: {
        performance: manifest?.performancePolicy || {},
        security: manifest?.securityPolicy || {},
      },
    });
  }

  if (pathname === '/api/client-performance' && performanceSmokeEnabled) {
    const metrics = app.getAppMetrics();
    return jsonResponse({
      processCount: metrics.length,
      workingSetMb: metrics.reduce((total, metric) => total + metric.memory.workingSetSize, 0) / 1024,
      privateMemoryMb: process.platform === 'win32'
        ? metrics.reduce((total, metric) => total + (metric.memory.privateBytes || 0), 0) / 1024
        : null,
      cpuPercent: metrics.reduce((total, metric) => total + metric.cpu.percentCPUUsage, 0),
      hardwareAccelerationEnabled,
      windowReadyMs,
    });
  }

  if (pathname === '/api/client-performance/quit' && performanceSmokeEnabled) {
    if (request.method !== 'POST') {
      return response('Method not allowed', { status: 405, headers: { allow: 'POST' } });
    }
    setTimeout(() => app.quit(), 250);
    return jsonResponse({ quitting: true });
  }

  if (pathname.startsWith('/api/client-build/download/')) {
    return response('Client build download is available only from the web frontend.', { status: 404 });
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return response('Method not allowed', {
      status: 405,
      headers: { allow: 'GET, HEAD' },
    });
  }

  if (pathname === '/favicon.ico') {
    return new Response(null, { status: 204, headers: baseHeaders });
  }

  const asset = safeAssetPath(pathname);
  if (asset && existsSync(asset.target)) {
    if (request.method === 'HEAD') {
      return response(undefined, {
        contentType: asset.mimeType || mimeTypes[extname(asset.target).toLowerCase()] || 'application/octet-stream',
        cacheControl: asset.cacheControl || 'public, max-age=3600',
      });
    }
    return serveAsset(asset, request.method === 'HEAD');
  }

  const indexAsset = !pathname.startsWith('/api/') && !/\.[a-z0-9]{1,12}$/i.test(pathname)
    ? safeAssetPath('/index.html')
    : null;
  if (indexAsset && existsSync(indexAsset.target)) {
    return serveAsset({ ...indexAsset, cacheControl: 'no-store' }, request.method === 'HEAD');
  }

  return response('Not found', { status: 404 });
};

const createWindow = async () => {
  const win = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 390,
    minHeight: 620,
    title: manifest?.productName || 'Payloader',
    backgroundColor: '#0a0a0f',
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      devTools: false,
      v8CacheOptions: 'code',
      webviewTag: false,
      navigateOnDragDrop: false,
      spellcheck: false,
      backgroundThrottling: !performanceSmokeEnabled,
    },
  });

  guardWebContents(win.webContents);

  let shown = false;
  const showFallback = setTimeout(() => {
    if (!shown && !win.isDestroyed()) {
      win.show();
      shown = true;
      windowReadyMs ??= Date.now() - processStartedAt;
    }
  }, 3000);
  win.once('ready-to-show', () => {
    clearTimeout(showFallback);
    win.show();
    shown = true;
    windowReadyMs ??= Date.now() - processStartedAt;
  });

  await win.loadURL(`${scheme}://${host}/`);
  return win;
};

let mainWindow = null;
const hasSingleInstanceLock = app.requestSingleInstanceLock();

if (!hasSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  });

  app.whenReady().then(async () => {
  app.setAppUserModelId('com.payloader.client');
  protocol.handle(scheme, handleProtocol);
  configureOfflineSession();
  app.on('web-contents-created', (_event, contents) => {
    guardWebContents(contents);
  });

  try {
    await loadManifest();
  } catch (error) {
    startupErrorText = error && error.stack ? error.stack : String(error || 'Unknown startup error');
  }

  mainWindow = await createWindow();
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      void createWindow().then(window => {
        mainWindow = window;
      });
    }
  });
  });
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
