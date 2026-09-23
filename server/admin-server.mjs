import { createServer } from 'node:http';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { randomUUID } from 'node:crypto';


import { extname, isAbsolute, join, normalize, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  clientBuildDownload,
  getPublicClientBuildInfo,
  getClientBuildStatus,
  startClientBuild,
} from './client-builder.mjs';
import {
  createDataExportPackage,
  createImportTemplate,
  closeStore,
  deleteAdminItem,
  deleteCustomContent,
  ensureStoreReady,
  getMetadataValue,
  getResetImpact,
  getSettings,
  getPublicData,
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
import { createPublicDataResponder } from './public-data-response.mjs';
import { officialProjectUrl, publicProjectRoute } from './project-attribution.mjs';
import { readImageInfo } from './image-inspect.mjs';
import { baseResponseHeaders, HttpError, isJsonRequest, json, methodNotAllowed, parseJsonBody, safeErrorPayload, text } from './http-helpers.mjs';

export { readBody } from './http-helpers.mjs';

import { createRateLimiter } from './rate-limit.mjs';
import { createCredentialStore } from './admin-credentials.mjs';
import { createSessionManager } from './admin-session.mjs';
import { createShutdownController } from './server-lifecycle.mjs';
import { createVersionChecker, VERSION_STATUS_METADATA_KEY } from './version-checker.mjs';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const distDir = join(rootDir, 'dist');
const adminDir = join(rootDir, 'admin');
const dataDir = resolve(process.env.PAYLOADER_DATA_DIR || join(rootDir, 'data'));
const uploadDir = join(dataDir, 'uploads');
const logoUploadDir = join(uploadDir, 'logo');

const host = process.env.PAYLOADER_HOST || '127.0.0.1';
const port = Number(process.env.PAYLOADER_PORT || 8081);
const bundledDefaultAdminUser = 'admin';
const bundledDefaultAdminPassword = 'payloader-admin!';
const configuredAdminUser = String(process.env.PAYLOADER_ADMIN_USER || '').trim();
const configuredAdminPassword = String(process.env.PAYLOADER_ADMIN_PASSWORD || '');
const defaultAdminUser = configuredAdminUser || bundledDefaultAdminUser;
const defaultAdminPassword = configuredAdminPassword || bundledDefaultAdminPassword;
const loopbackHosts = new Set(['127.0.0.1', '::1', 'localhost']);
const allowInsecureDevCredentials = process.env.PAYLOADER_ALLOW_INSECURE_DEV_CREDENTIALS !== 'false'
  && process.env.NODE_ENV !== 'production'
  && loopbackHosts.has(host.toLowerCase());
const requiresExplicitInitialCredentials = !allowInsecureDevCredentials;
const pathSeparator = process.platform === 'win32' ? '\\' : '/';
const sessionTtlMs = Number(process.env.PAYLOADER_ADMIN_SESSION_TTL_MS || 8 * 60 * 60 * 1000);
const jwtSecretFile = join(dataDir, 'admin-jwt-secret.key');

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
};

const maxLogoBytes = 1_048_576;
const maxLogoDimension = 1024;
const maxLogoRequestBytes = 1_500_000;
const maxImportRequestBytes = 24 * 1024 * 1024;
const maxUrlLength = 4_096;
const acceptedLogoMimeTypes = new Set(['image/png', 'image/jpeg', 'image/webp']);
const publicDataResponder = createPublicDataResponder({
  loadData: getPublicData,
  responseHeaders: baseResponseHeaders,
});
const applicationVersionChecker = createVersionChecker({
  repositoryUrl: officialProjectUrl,
  projectRoute: publicProjectRoute,
  loadStatus: () => getMetadataValue(VERSION_STATUS_METADATA_KEY, ''),
  saveStatus: value => setMetadataValue(VERSION_STATUS_METADATA_KEY, value),
});





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
const { endLoginVerify, getAdminCredentials, publicCredentialInfo, saveAdminCredentials, tryBeginLoginVerify, validAdminCredentials } = credentials;
const { adminRequestLimit, checkRateLimit, clearRateLimit, clientKey, failedAuthLimit, failedLoginLimit, respondTooManyRequests } = createRateLimiter();

export const ensureApplicationReady = async () => {
  await Promise.all([
    ensureStoreReady(),
    getAdminCredentials(),
    getJwtSecret(),
    publicDataResponder.prepare(),
  ]);
  return true;
};


const isAuthorized = async request => Boolean(await readAdminSession(request));


const unauthorized = (request, response) => {
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

const requireAuth = async (request, response) => {
  if (await isAuthorized(request)) return true;
  if (!checkRateLimit(request, response, 'admin-auth-failed', failedAuthLimit)) return false;
  return unauthorized(request, response);
};

const decodeUrlPath = pathname => {
  try {
    return decodeURIComponent(pathname);
  } catch {
    throw new HttpError(400, 'Malformed URL path');
  }
};

const safeResolve = (baseDir, relativePath) => {
  const resolved = resolve(baseDir, normalize(relativePath));
  const fromBase = relative(baseDir, resolved);
  if (fromBase === '..' || fromBase.startsWith(`..${pathSeparator}`) || isAbsolute(fromBase)) return null;
  return resolved;
};

const adminStaticPath = pathname => {
  const decoded = decodeUrlPath(pathname);
  if (decoded !== '/admin' && !decoded.startsWith('/admin/')) return null;
  const relativePath = decoded === '/admin' || decoded === '/admin/' ? 'index.html' : decoded.slice('/admin/'.length);
  return safeResolve(adminDir, relativePath);
};

const frontendStaticPath = pathname => {
  const decoded = decodeUrlPath(pathname);
  const relativePath = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  return safeResolve(distDir, relativePath);
};

const logoStaticPath = pathname => {
  const decoded = decodeUrlPath(pathname);
  if (!decoded.startsWith('/uploads/logo/')) return null;
  const fileName = decoded.slice('/uploads/logo/'.length);
  if (!/^logo-[a-zA-Z0-9.-]+\.(png|jpe?g|webp)$/.test(fileName)) return null;
  return safeResolve(logoUploadDir, fileName);
};

const serveStatic = async (request, response, filePath, options = {}) => {
  try {
    const stats = await stat(filePath);
    if (!stats.isFile()) {
      text(response, 404, 'Not found');
      return;
    }
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': mimeTypes[extname(filePath).toLowerCase()] || 'application/octet-stream',
      'cache-control': options.cacheControl || 'no-store',
    });
    if (request.method === 'HEAD') {
      response.end();
      return;
    }
    createReadStream(filePath).pipe(response);
  } catch {
    text(response, 404, 'Not found');
  }
};

const stripXeyeIntegration = source => source
  .replace(/\s*<script id="xeye-structured-data"[\s\S]*?<\/script>/, '')
  .replace(/\s*<a data-xeye-platform-link[\s\S]*?<\/a>/, '');

const serveFrontendIndex = async (request, response, filePath) => {
  try {
    const [source, settings] = await Promise.all([
      readFile(filePath, 'utf8'),
      getSettings(),
    ]);
    const body = settings.xeyeEnabled ? source : stripXeyeIntegration(source);
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': Buffer.byteLength(body),
    });
    response.end(request.method === 'HEAD' ? undefined : body);
  } catch {
    text(response, 404, 'Not found');
  }
};

const normalizeLogoMimeType = value => {
  const mimeType = String(value || '').toLowerCase().trim();
  return acceptedLogoMimeTypes.has(mimeType) ? mimeType : '';
};

const estimateBase64Bytes = value => {
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  return Math.floor((value.length * 3) / 4) - padding;
};

const extractBase64Payload = body => {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const source = String(body.dataUrl || body.base64 || '');
  const commaIndex = source.indexOf(',');
  const hasRequestMimeType = Object.prototype.hasOwnProperty.call(body, 'mimeType') && String(body.mimeType).trim();
  const requestMimeType = normalizeLogoMimeType(body.mimeType);
  if (hasRequestMimeType && !requestMimeType) {
    throw new HttpError(415, 'Only PNG, JPEG, and WebP logo images are allowed');
  }
  let declaredMimeType = requestMimeType;
  if (source.startsWith('data:')) {
    if (commaIndex < 0) return null;
    const meta = source.slice(5, commaIndex).toLowerCase();
    const [mimeType, ...flags] = meta.split(';').map(item => item.trim()).filter(Boolean);
    if (!flags.includes('base64')) return null;
    declaredMimeType = normalizeLogoMimeType(mimeType);
    if (!declaredMimeType) {
      throw new HttpError(415, 'Only PNG, JPEG, and WebP logo images are allowed');
    }
    if (requestMimeType && requestMimeType !== declaredMimeType) {
      throw new HttpError(415, 'Logo file type does not match the uploaded image data');
    }
  }
  const base64 = commaIndex >= 0 ? source.slice(commaIndex + 1) : source;
  if (!/^[a-zA-Z0-9+/=\s]+$/.test(base64)) return null;
  const normalized = base64.replace(/\s/g, '');
  if (!normalized || normalized.length % 4 !== 0 || estimateBase64Bytes(normalized) > maxLogoBytes) return null;
  return { base64: normalized, declaredMimeType, requestMimeType };
};

const handleLogoUpload = async (request, response) => {
  if (!isJsonRequest(request)) {
    text(response, 415, 'Logo uploads must use application/json');
    return;
  }
  const contentLength = Number(request.headers['content-length'] || 0);
  if (contentLength > maxLogoRequestBytes) {
    text(response, 413, 'Logo upload request is too large');
    return;
  }
  const body = await parseJsonBody(request, maxLogoRequestBytes);
  const payload = extractBase64Payload(body);
  if (!payload) {
    text(response, 400, 'Missing image data');
    return;
  }
  const buffer = Buffer.from(payload.base64, 'base64');
  if (!buffer.length || buffer.length > maxLogoBytes) {
    text(response, 413, 'Logo image must be 1 MB or smaller');
    return;
  }
  const image = readImageInfo(buffer);
  if (!image) {
    text(response, 415, 'Only PNG, JPEG, and WebP logo images are allowed');
    return;
  }
  if (payload.declaredMimeType && payload.declaredMimeType !== image.mimeType) {
    text(response, 415, 'Logo file type does not match the uploaded image data');
    return;
  }
  if (payload.requestMimeType && payload.requestMimeType !== image.mimeType) {
    text(response, 415, 'Logo file type does not match the uploaded image data');
    return;
  }
  if (
    image.width < 1 ||
    image.height < 1 ||
    image.width > maxLogoDimension ||
    image.height > maxLogoDimension
  ) {
    text(response, 400, `Logo image dimensions must be ${maxLogoDimension}x${maxLogoDimension} or smaller`);
    return;
  }
  await mkdir(logoUploadDir, { recursive: true });
  const fileName = `logo-${Date.now()}-${randomUUID()}.${image.ext}`;
  const filePath = safeResolve(logoUploadDir, fileName);
  if (!filePath) {
    text(response, 500, 'Unable to store logo');
    return;
  }
  await writeFile(filePath, buffer, { flag: 'wx' });
  json(response, 200, {
    logoUrl: `/uploads/logo/${fileName}`,
    mimeType: image.mimeType,
    width: image.width,
    height: image.height,
    size: buffer.length,
  });
};

const getIdFromPath = (pathname, resource) => {
  const prefix = `/api/admin/${resource}/`;
  if (!pathname.startsWith(prefix)) return '';
  return decodeUrlPath(pathname.slice(prefix.length));
};

const parseAdminJsonBody = (request, maxBytes) => parseJsonBody(request, maxBytes, { requireJson: true });

const routeResource = path => {
  const match = path.match(/^\/api\/admin\/(payloads|tools|navigation)(?:\/|$)/);
  return match?.[1] || null;
};

const handleAdminAuthApi = async (request, response, url) => {
  if (url.pathname === '/api/admin/session') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    const session = await readAdminSession(request);
    if (!session) {
      json(response, 401, { error: '登录已失效，请重新登录' });
      return true;
    }
    const credentials = await getAdminCredentials();
    json(response, 200, {
      authenticated: true,
      user: credentials.username,
      expiresAt: session.expiresAt,
    });
    return true;
  }

  if (url.pathname === '/api/admin/login') {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    // scrypt 并发闸：错误登录洪水不占满线程池；正确凭据在低并发时仍可正常登录。
    if (!tryBeginLoginVerify()) {
      respondTooManyRequests(response, 'admin-login-failed', failedLoginLimit);
      return true;
    }
    const body = await parseJsonBody(request, 16_384, { requireJson: true });
    const user = typeof body.username === 'string' ? body.username : '';
    const password = typeof body.password === 'string' ? body.password : '';
    let invalidCredentials;
    try {
      invalidCredentials = user.length > 256 || password.length > 1024 || !await validAdminCredentials(user, password);
    } finally {
      endLoginVerify();
    }
    if (invalidCredentials) {
      if (!checkRateLimit(request, response, 'admin-login-failed', failedLoginLimit)) return true;
      json(response, 401, { error: '账号或密码不正确' });
      return true;
    }
    clearRateLimit(request, 'admin-login-failed');
    const credentials = await getAdminCredentials();
    const session = await createAdminSession(request);
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    response.end(JSON.stringify({
      authenticated: true,
      user: credentials.username,
      accessToken: session.token,
      tokenType: 'Bearer',
      expiresAt: session.expiresAt,
    }));
    return true;
  }

  if (url.pathname === '/api/admin/logout') {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    const session = await readAdminSession(request);
    if (session) revokeSession(session.jwtId);
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    response.end(JSON.stringify({ ok: true }));
    return true;
  }

  return false;
};

const handleAdminApi = async (request, response, url, services) => {
  if (!url.pathname.startsWith('/api/admin/')) return false;
  if (await handleAdminAuthApi(request, response, url)) return true;
  if (!checkRateLimit(request, response, 'admin-request', adminRequestLimit)) return true;
  if (!await requireAuth(request, response)) return true;

  if (url.pathname === '/api/admin/version-status') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    json(response, 200, await services.versionChecker.getStatus());
    return true;
  }

  if (url.pathname === '/api/admin/version-check') {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    json(response, 200, await services.versionChecker.checkNow({ force: true }));
    return true;
  }

  if (url.pathname === '/api/admin/export') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    const exportPackage = await createDataExportPackage();
    const body = JSON.stringify(exportPackage, null, 2);
    const date = exportPackage.generatedAt.slice(0, 10);
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': 'application/json; charset=utf-8',
      'content-length': String(Buffer.byteLength(body)),
      'content-disposition': `attachment; filename="payloader-export-${date}.json"`,
      'cache-control': 'no-store',
    });
    response.end(body);
    return true;
  }

  if (url.pathname === '/api/admin/custom-payloads') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    json(response, 200, { items: await listCustomPayloads() });
    return true;
  }

  if (url.pathname === '/api/admin/custom-content') {
    if (request.method === 'GET') {
      json(response, 200, { items: await listCustomContent() });
      return true;
    }
    if (request.method === 'POST') {
      json(response, 201, await saveCustomContent(await parseAdminJsonBody(request)));
      return true;
    }
    methodNotAllowed(response, ['GET', 'POST']);
    return true;
  }

  if (url.pathname.startsWith('/api/admin/custom-content/')) {
    const id = decodeUrlPath(url.pathname.slice('/api/admin/custom-content/'.length));
    if (!id || id.length > 160 || /[\\/\0]/.test(id)) {
      throw new HttpError(400, '自定义内容 ID 无效');
    }
    if (request.method === 'PUT') {
      const body = await parseAdminJsonBody(request);
      json(response, 200, await saveCustomContent({ ...body, id }));
      return true;
    }
    if (request.method === 'DELETE') {
      json(response, 200, await deleteCustomContent({
        id,
        destination: url.searchParams.get('destination'),
      }));
      return true;
    }
    methodNotAllowed(response, ['PUT', 'DELETE']);
    return true;
  }

  if (url.pathname === '/api/admin/reset-impact') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    json(response, 200, await getResetImpact(url.searchParams.get('target')));
    return true;
  }

  if (url.pathname === '/api/admin/logo') {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    await handleLogoUpload(request, response);
    return true;
  }

  if (url.pathname === '/api/admin/credentials') {
    if (request.method === 'GET') {
      json(response, 200, publicCredentialInfo(await getAdminCredentials()));
      return true;
    }
    if (request.method === 'PUT') {
      const body = await parseAdminJsonBody(request, 16_384);
      const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
      const confirmPassword = typeof body.confirmPassword === 'string' ? body.confirmPassword : '';
      if (newPassword || confirmPassword) {
        if (newPassword !== confirmPassword) {
          throw new HttpError(400, '两次输入的新密码不一致。');
        }
      }
      const saved = await saveAdminCredentials({
        username: body.username,
        currentPassword: body.currentPassword,
        newPassword,
      });
      response.writeHead(200, {
        ...baseResponseHeaders,
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
      });
      response.end(JSON.stringify({ ...saved, reauthRequired: true }));
      return true;
    }
    methodNotAllowed(response, ['GET', 'PUT']);
    return true;
  }

  if (url.pathname === '/api/admin/import-template') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'content-disposition': 'attachment; filename="payloader-import-template.json"',
    });
    response.end(JSON.stringify(createImportTemplate(), null, 2));
    return true;
  }

  if (url.pathname === '/api/admin/import/preview') {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    try {
      const body = await parseAdminJsonBody(request, maxImportRequestBytes);
      json(response, 200, previewImportPackage(body));
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 400;
      json(response, status, { error: error instanceof Error ? error.message : '导入文件格式不正确' });
    }
    return true;
  }

  if (url.pathname === '/api/admin/import') {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    try {
      const body = await parseAdminJsonBody(request, maxImportRequestBytes);
      const payload = body && typeof body === 'object' && body.data ? body.data : body;
      const mode = body && typeof body === 'object' && body.mode === 'replace' ? 'replace' : 'merge';
      json(response, 200, await importDataPackage(payload, { mode }));
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 400;
      json(response, status, { error: error instanceof Error ? error.message : '导入文件格式不正确' });
    }
    return true;
  }

  if (url.pathname === '/api/admin/reset-defaults') {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    const body = await parseAdminJsonBody(request);
    json(response, 200, await resetDefaultData(body.target));
    return true;
  }

  if (url.pathname === '/api/admin/settings') {
    if (request.method === 'GET') {
      json(response, 200, await getSettings());
      return true;
    }
    if (request.method === 'POST' || request.method === 'PUT') {
      const body = await parseAdminJsonBody(request);
      json(response, 200, await saveSettings(body));
      return true;
    }
    methodNotAllowed(response, ['GET', 'POST', 'PUT']);
    return true;
  }

  if (url.pathname === '/api/admin/client-builds/status') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    json(response, 200, await getClientBuildStatus());
    return true;
  }

  if (url.pathname === '/api/admin/client-builds/generate') {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    const body = await parseAdminJsonBody(request, 16_384);
    json(response, 202, await startClientBuild({ targets: Array.isArray(body.targets) ? body.targets : [] }));
    return true;
  }

  if (url.pathname.startsWith('/api/admin/client-builds/download/')) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      methodNotAllowed(response, ['GET', 'HEAD']);
      return true;
    }
    const fileName = decodeUrlPath(url.pathname.slice('/api/admin/client-builds/download/'.length));
    const download = await clientBuildDownload(fileName);
    if (!download) {
      text(response, 404, 'Not found');
      return true;
    }
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': download.mimeType || 'application/octet-stream',
      'content-length': String(download.size),
      'content-disposition': `attachment; filename="${download.fileName}"`,
      'cache-control': 'no-store',
    });
    if (request.method === 'HEAD') {
      response.end();
      return true;
    }
    download.stream().pipe(response);
    return true;
  }

  const resource = routeResource(url.pathname);
  if (!resource) {
    text(response, 404, 'Not found');
    return true;
  }

  if (url.pathname === `/api/admin/${resource}`) {
    if (request.method === 'GET') {
      json(response, 200, { items: await listAdminItems(resource) });
      return true;
    }
    if (request.method === 'POST') {
      const body = await parseAdminJsonBody(request);
      const saved = resource === 'navigation' ? await saveNavigationItem(body) : await saveAdminItem(resource, body);
      json(response, 200, saved);
      return true;
    }
    methodNotAllowed(response, ['GET', 'POST']);
    return true;
  }

  if (url.pathname.endsWith('/move')) {
    if (request.method !== 'POST') {
      methodNotAllowed(response, ['POST']);
      return true;
    }
    const id = getIdFromPath(url.pathname.replace(/\/move$/, ''), resource);
    const body = await parseAdminJsonBody(request);
    await moveAdminItem(resource, id, body.direction === 'down' ? 'down' : 'up');
    json(response, 200, { items: await listAdminItems(resource) });
    return true;
  }

  const id = getIdFromPath(url.pathname, resource);
  if (id) {
    if (request.method === 'PUT') {
      const body = await parseAdminJsonBody(request);
      const payload = { ...body, id };
      const saved = resource === 'navigation' ? await saveNavigationItem(payload) : await saveAdminItem(resource, payload);
      json(response, 200, saved);
      return true;
    }
    if (request.method === 'DELETE') {
      await deleteAdminItem(resource, id);
      json(response, 200, { ok: true });
      return true;
    }
    methodNotAllowed(response, ['PUT', 'DELETE']);
    return true;
  }

  text(response, 404, 'Not found');
  return true;
};

const handlePublicApi = async (request, response, url) => {
  if (url.pathname === '/api/health') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    json(response, 200, { status: 'ok' });
    return true;
  }

  if (url.pathname === '/api/ready') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    try {
      await ensureApplicationReady();
      json(response, 200, { status: 'ready' });
    } catch (error) {
      console.error('Readiness check failed:', error);
      json(response, 503, { status: 'not_ready' });
    }
    return true;
  }

  if (url.pathname === publicProjectRoute) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      methodNotAllowed(response, ['GET', 'HEAD']);
      return true;
    }
    response.writeHead(302, {
      ...baseResponseHeaders,
      location: officialProjectUrl,
      'cache-control': 'no-store',
    });
    response.end();
    return true;
  }

  if (url.pathname === '/api/public-data') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    await publicDataResponder.respond(request, response);
    return true;
  }

  if (url.pathname === '/api/client-build') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    json(response, 200, await getPublicClientBuildInfo());
    return true;
  }

  if (url.pathname === '/api/client-build/download/latest') {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      methodNotAllowed(response, ['GET', 'HEAD']);
      return true;
    }
    const info = await getPublicClientBuildInfo();
    const fileName = info.available && info.latest ? info.latest.fileName : '';
    const download = fileName ? await clientBuildDownload(fileName) : null;
    if (!download) {
      text(response, 404, 'Client build not available');
      return true;
    }
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': download.mimeType || 'application/octet-stream',
      'content-length': String(download.size),
      'content-disposition': `attachment; filename="${download.fileName}"`,
      'cache-control': 'no-store',
    });
    if (request.method === 'HEAD') {
      response.end();
      return true;
    }
    download.stream().pipe(response);
    return true;
  }

  if (url.pathname.startsWith('/api/client-build/download/')) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      methodNotAllowed(response, ['GET', 'HEAD']);
      return true;
    }
    const fileName = decodeUrlPath(url.pathname.slice('/api/client-build/download/'.length));
    const download = await clientBuildDownload(fileName);
    if (!download) {
      text(response, 404, 'Client build not available');
      return true;
    }
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': download.mimeType || 'application/octet-stream',
      'content-length': String(download.size),
      'content-disposition': `attachment; filename="${download.fileName}"`,
      'cache-control': 'no-store',
    });
    if (request.method === 'HEAD') {
      response.end();
      return true;
    }
    download.stream().pipe(response);
    return true;
  }

  if (url.pathname === '/api/custom-tools') {
    if (request.method !== 'GET') {
      methodNotAllowed(response, ['GET']);
      return true;
    }
    const data = await getPublicData();
    json(response, 200, { version: 1, categories: data.tools.filter(tool => String(tool.id).startsWith('custom-')) });
    return true;
  }

  return false;
};

const handleRequest = async (request, response, services) => {
  try {
    if (String(request.url || '').length > maxUrlLength) {
      text(response, 414, 'URI too long');
      return;
    }
    const url = new URL(request.url || '/', 'http://payloader.local');

    if (await handlePublicApi(request, response, url)) return;
    if (await handleAdminApi(request, response, url, services)) return;

    if (url.pathname === '/favicon.ico') {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        methodNotAllowed(response, ['GET', 'HEAD']);
        return;
      }
      response.writeHead(204, baseResponseHeaders);
      response.end();
      return;
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      methodNotAllowed(response, ['GET', 'HEAD']);
      return;
    }

    if (url.pathname.startsWith('/uploads/logo/')) {
      const logoPath = logoStaticPath(url.pathname);
      if (!logoPath) {
        text(response, 403, 'Forbidden');
        return;
      }
      await serveStatic(request, response, logoPath, { cacheControl: 'public, max-age=86400, immutable' });
      return;
    }

    if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
      if (!checkRateLimit(request, response, 'admin-page', adminRequestLimit)) return;
      if (url.pathname === '/admin/login') {
        await serveStatic(request, response, join(adminDir, 'login.html'));
        return;
      }
      const adminPath = adminStaticPath(url.pathname);
      if (!adminPath) {
        text(response, 403, 'Forbidden');
        return;
      }
      await serveStatic(request, response, adminPath);
      return;
    }

    const frontendPath = frontendStaticPath(url.pathname);
    if (!frontendPath) {
      text(response, 403, 'Forbidden');
      return;
    }
    if (frontendPath === join(distDir, 'index.html')) {
      await serveFrontendIndex(request, response, frontendPath);
      return;
    }
    await serveStatic(request, response, frontendPath, {
      cacheControl: extname(frontendPath).toLowerCase() === '.html'
        ? 'no-store'
        : 'public, max-age=3600',
    });
  } catch (error) {
    const { status, payload } = safeErrorPayload(error);
    json(response, status, payload);
  }
};

export const createAdminServer = (options = {}) => {
  const services = {
    versionChecker: options.versionChecker || applicationVersionChecker,
  };
  const server = createServer((request, response) => handleRequest(request, response, services));
  server.once('close', () => services.versionChecker.stop());
  return server;
};

export const __adminSecurityTest = Object.freeze({ clientKey });

export const startAdminServer = async () => {
  await ensureApplicationReady();
  const credentials = await getAdminCredentials();
  await applicationVersionChecker.start();
  const server = createAdminServer({ versionChecker: applicationVersionChecker });
  await new Promise((resolveListen, rejectListen) => {
    const onError = error => {
      applicationVersionChecker.stop();
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
