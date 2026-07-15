import { createServer } from 'node:http';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createHash, createHmac, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { isIP } from 'node:net';
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
const publishedExampleAdminPasswords = new Set([bundledDefaultAdminPassword, 'Change-Me-2026!']);
const pathSeparator = process.platform === 'win32' ? '\\' : '/';
const sessionTtlMs = Number(process.env.PAYLOADER_ADMIN_SESSION_TTL_MS || 8 * 60 * 60 * 1000);
const jwtSecretFile = join(dataDir, 'admin-jwt-secret.key');
const jwtIssuer = 'payloader-admin';
const jwtAudience = 'payloader-admin-panel';
const jwtClockSkewSec = 30;
const maxJwtBearerLength = 2048;
const credentialsMetadataKey = 'admin_credentials';
const credentialHashParams = Object.freeze({
  algorithm: 'scrypt',
  keyLength: 64,
  saltBytes: 24,
});
const defaultScryptCost = Object.freeze({ N: 32768, r: 8, p: 1 });
const scryptCostLimits = Object.freeze({ minN: 16384, maxN: 262144, maxR: 16, maxP: 4 });
const minAdminPasswordLength = 10;
const scrypt = promisify(scryptCallback);

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
const contentSecurityPolicy = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "img-src 'self' data: blob:",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "connect-src 'self'",
  "form-action 'self'",
].join('; ');
const baseResponseHeaders = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'content-security-policy': contentSecurityPolicy,
};
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
const rateBuckets = new Map();
const adminSessions = new Map();
const adminRequestLimit = { windowMs: 60_000, max: 300 };
const failedAuthLimit = { windowMs: 60_000, max: 12 };
const failedLoginLimit = { windowMs: 60_000, max: 8 };
const trustedProxyConfig = String(process.env.PAYLOADER_TRUSTED_PROXIES || '')
  .split(',')
  .map(item => item.trim().toLowerCase())
  .filter(Boolean);
const trustedProxyAddresses = new Set();
let trustLoopbackProxies = false;
for (const entry of trustedProxyConfig) {
  if (entry === 'loopback') {
    trustLoopbackProxies = true;
  } else if (isIP(entry)) {
    trustedProxyAddresses.add(entry);
  } else {
    throw new Error(`Invalid PAYLOADER_TRUSTED_PROXIES entry: ${entry}`);
  }
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const errorStatus = error => (
  error instanceof HttpError
    ? error.status
    : Number.isInteger(error?.status)
      ? error.status
      : 500
);

const safeErrorPayload = error => {
  const status = errorStatus(error);
  if (status >= 500) {
    console.error(error);
    return { status, payload: { error: 'Internal server error' } };
  }
  return {
    status,
    payload: { error: error instanceof Error ? error.message : 'Request failed' },
  };
};

const json = (response, status, payload) => {
  response.writeHead(status, {
    ...baseResponseHeaders,
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  response.end(JSON.stringify(payload));
};

const text = (response, status, body) => {
  response.writeHead(status, {
    ...baseResponseHeaders,
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
  });
  response.end(body);
};

const methodNotAllowed = (response, allowed) => {
  response.writeHead(405, {
    ...baseResponseHeaders,
    allow: allowed.join(', '),
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
  });
  response.end('Method not allowed');
};

export const readBody = (request, maxBytes = 4_000_000) => new Promise((resolveBody, rejectBody) => {
  const contentLength = Number.parseInt(String(request.headers['content-length'] || '0'), 10);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    rejectBody(new HttpError(413, 'Request body too large'));
    request.destroy();
    return;
  }
  const chunks = [];
  let received = 0;
  let settled = false;
  const rejectOnce = error => {
    if (settled) return;
    settled = true;
    rejectBody(error);
    request.destroy();
  };
  request.on('data', chunk => {
    if (settled) return;
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    received += buffer.length;
    if (received > maxBytes) {
      rejectOnce(new HttpError(413, 'Request body too large'));
      return;
    }
    chunks.push(buffer);
  });
  request.on('end', () => {
    if (settled) return;
    settled = true;
    resolveBody(Buffer.concat(chunks, received).toString('utf8'));
  });
  request.on('error', error => {
    if (settled) return;
    settled = true;
    rejectBody(error);
  });
});

const parseJsonBody = async (request, maxBytes, options = {}) => {
  if (options.requireJson && !isJsonRequest(request)) {
    throw new HttpError(415, 'Request body must use application/json');
  }
  const raw = await readBody(request, maxBytes);
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, 'Invalid JSON request body');
  }
};

const isJsonRequest = request => {
  const contentType = String(request.headers['content-type'] || '').toLowerCase();
  return contentType.includes('application/json');
};

const hashText = value => createHash('sha256').update(String(value), 'utf8').digest();

const safeTextEquals = (value, expectedHash) => {
  const actualHash = hashText(value);
  return timingSafeEqual(actualHash, expectedHash);
};

const isPlainObject = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const normalizeAdminUsername = value => String(value || '').trim();

const validateAdminUsername = value => {
  const username = normalizeAdminUsername(value);
  if (!/^[A-Za-z0-9._-]{3,64}$/.test(username)) {
    throw new HttpError(400, '管理员用户名只能包含字母、数字、点、下划线和短横线，长度为 3-64 位。');
  }
  return username;
};

const validateAdminPassword = value => {
  const password = String(value || '');
  if (password.length < minAdminPasswordLength || password.length > 128) {
    throw new HttpError(400, `管理员密码长度必须为 ${minAdminPasswordLength}-128 位。`);
  }
  const classes = [
    /[a-z]/.test(password),
    /[A-Z]/.test(password),
    /\d/.test(password),
    /[^A-Za-z0-9]/.test(password),
  ].filter(Boolean).length;
  if (classes < 3) {
    throw new HttpError(400, '管理员密码至少需要包含大小写字母、数字、符号中的三类。');
  }
  return password;
};

const isPowerOfTwo = value => Number.isInteger(value) && value > 0 && Math.log2(value) % 1 === 0;

const normalizeScryptCost = value => {
  const cost = isPlainObject(value) ? value : {};
  const N = Number(cost.N ?? defaultScryptCost.N);
  const r = Number(cost.r ?? defaultScryptCost.r);
  const p = Number(cost.p ?? defaultScryptCost.p);
  if (
    !isPowerOfTwo(N) ||
    N < scryptCostLimits.minN ||
    N > scryptCostLimits.maxN ||
    !Number.isInteger(r) ||
    r < 1 ||
    r > scryptCostLimits.maxR ||
    !Number.isInteger(p) ||
    p < 1 ||
    p > scryptCostLimits.maxP
  ) {
    throw new Error('Invalid admin credential hash parameters.');
  }
  return { N, r, p };
};

const decodeCredentialBuffer = (value, minLength) => {
  const encoded = String(value || '');
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return null;
  const buffer = Buffer.from(encoded, 'base64url');
  return buffer.length >= minLength ? buffer : null;
};

const normalizeStoredAdminCredentials = credentials => {
  if (!isPlainObject(credentials)) {
    throw new Error('Stored admin credential metadata is invalid.');
  }
  const username = validateAdminUsername(credentials.username);
  const passwordHash = credentials.passwordHash;
  if (!isPlainObject(passwordHash) || passwordHash.algorithm !== credentialHashParams.algorithm) {
    throw new Error('Stored admin credential hash is invalid.');
  }
  const keyLength = Number(passwordHash.keyLength || credentialHashParams.keyLength);
  if (!Number.isInteger(keyLength) || keyLength < 32 || keyLength > 128) {
    throw new Error('Stored admin credential key length is invalid.');
  }
  if (
    !decodeCredentialBuffer(passwordHash.salt, 16) ||
    !decodeCredentialBuffer(passwordHash.hash, 32)
  ) {
    throw new Error('Stored admin credential hash data is invalid.');
  }
  const version = String(credentials.version || '');
  if (!/^[A-Za-z0-9_-]{32,96}$/.test(version)) {
    throw new Error('Stored admin credential version is invalid.');
  }
  return {
    username,
    passwordHash: {
      algorithm: credentialHashParams.algorithm,
      salt: String(passwordHash.salt),
      hash: String(passwordHash.hash),
      keyLength,
      cost: normalizeScryptCost(passwordHash.cost),
    },
    version,
    createdAt: String(credentials.createdAt || credentials.updatedAt || new Date().toISOString()),
    updatedAt: String(credentials.updatedAt || credentials.createdAt || new Date().toISOString()),
    source: String(credentials.source || 'admin-panel'),
  };
};

const hashAdminPassword = async password => {
  const salt = randomBytes(credentialHashParams.saltBytes);
  const cost = defaultScryptCost;
  const key = await scrypt(password, salt, credentialHashParams.keyLength, {
    ...cost,
    maxmem: 64 * 1024 * 1024,
  });
  return {
    algorithm: credentialHashParams.algorithm,
    salt: salt.toString('base64url'),
    hash: Buffer.from(key).toString('base64url'),
    keyLength: credentialHashParams.keyLength,
    cost,
  };
};

const verifyAdminPasswordHash = async (password, passwordHash) => {
  try {
    if (!passwordHash || passwordHash.algorithm !== credentialHashParams.algorithm) return false;
    const salt = decodeCredentialBuffer(passwordHash.salt, 16);
    const expected = decodeCredentialBuffer(passwordHash.hash, 32);
    const keyLength = Number(passwordHash.keyLength || credentialHashParams.keyLength);
    if (!salt || !expected || !Number.isInteger(keyLength) || keyLength < 32 || keyLength > 128) return false;
    const cost = normalizeScryptCost(passwordHash.cost);
    const derived = await scrypt(String(password || ''), salt, keyLength, {
      ...cost,
      maxmem: 64 * 1024 * 1024,
    });
    const actual = Buffer.from(derived);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
};

const publicCredentialInfo = credentials => ({
  username: credentials.username,
  updatedAt: credentials.updatedAt,
  createdAt: credentials.createdAt,
});

let adminCredentialsPromise;

const loadAdminCredentials = async () => {
  const stored = await getMetadataValue(credentialsMetadataKey, '');
  if (stored) {
    try {
      const credentials = normalizeStoredAdminCredentials(JSON.parse(stored));
      if (requiresExplicitInitialCredentials) {
        for (const publishedPassword of publishedExampleAdminPasswords) {
          if (!await verifyAdminPasswordHash(publishedPassword, credentials.passwordHash)) continue;
          const label = publishedPassword === bundledDefaultAdminPassword ? 'bundled default' : 'published example';
          if (
            configuredAdminUser
            && configuredAdminPassword
            && !publishedExampleAdminPasswords.has(configuredAdminPassword)
          ) {
            const timestamp = new Date().toISOString();
            const migrated = {
              username: validateAdminUsername(configuredAdminUser),
              passwordHash: await hashAdminPassword(validateAdminPassword(configuredAdminPassword)),
              version: randomUUID(),
              createdAt: credentials.createdAt || timestamp,
              updatedAt: timestamp,
              source: 'published-password-migration',
            };
            await setMetadataValue(credentialsMetadataKey, JSON.stringify(migrated));
            return migrated;
          }
          throw new Error(`Stored administrator credentials still use the ${label} password. Provide new strong PAYLOADER_ADMIN_USER and PAYLOADER_ADMIN_PASSWORD values for one startup to migrate them.`);
        }
      }
      return credentials;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Stored admin credential metadata is invalid.';
      throw new Error(`${message} Refusing to fall back to default admin credentials.`);
    }
  }

  const timestamp = new Date().toISOString();
  if (requiresExplicitInitialCredentials && (!configuredAdminUser || !configuredAdminPassword)) {
    throw new Error('PAYLOADER_ADMIN_USER and PAYLOADER_ADMIN_PASSWORD are required for the first production or non-loopback startup.');
  }
  const username = validateAdminUsername(defaultAdminUser);
  const initialPassword = String(defaultAdminPassword || '');
  if (requiresExplicitInitialCredentials) {
    validateAdminPassword(initialPassword);
    if (publishedExampleAdminPasswords.has(initialPassword)) {
      throw new Error('PAYLOADER_ADMIN_PASSWORD must not use a published example password.');
    }
  } else if (initialPassword.length < 8 || initialPassword.length > 128) {
    throw new Error('Initial PAYLOADER_ADMIN_PASSWORD must be 8-128 characters.');
  }
  const passwordHash = await hashAdminPassword(initialPassword);
  const credentials = {
    username,
    passwordHash,
    version: randomUUID(),
    createdAt: timestamp,
    updatedAt: timestamp,
    source: 'initial-default',
  };
  await setMetadataValue(credentialsMetadataKey, JSON.stringify(credentials));
  return credentials;
};

const getAdminCredentials = () => {
  if (!adminCredentialsPromise) {
    const pending = loadAdminCredentials();
    const guarded = pending.catch(error => {
      if (adminCredentialsPromise === guarded) adminCredentialsPromise = undefined;
      throw error;
    });
    adminCredentialsPromise = guarded;
  }
  return adminCredentialsPromise;
};

const validAdminCredentials = async (user, password) => {
  const credentials = await getAdminCredentials();
  const usernameMatches = safeTextEquals(normalizeAdminUsername(user), hashText(credentials.username));
  const passwordMatches = await verifyAdminPasswordHash(password, credentials.passwordHash);
  return usernameMatches && passwordMatches;
};

const saveAdminCredentials = async ({ username, currentPassword, newPassword }) => {
  const current = await getAdminCredentials();
  if (!await verifyAdminPasswordHash(currentPassword, current.passwordHash)) {
    throw new HttpError(403, '当前密码不正确。');
  }
  const nextUsername = validateAdminUsername(username || current.username);
  const nextPassword = newPassword ? validateAdminPassword(newPassword) : '';
  if (nextPassword && await verifyAdminPasswordHash(nextPassword, current.passwordHash)) {
    throw new HttpError(400, '新密码不能和当前密码相同。');
  }
  const timestamp = new Date().toISOString();
  const credentials = {
    username: nextUsername,
    passwordHash: nextPassword ? await hashAdminPassword(nextPassword) : current.passwordHash,
    version: randomUUID(),
    createdAt: current.createdAt || timestamp,
    updatedAt: timestamp,
    source: 'admin-panel',
  };
  await setMetadataValue(credentialsMetadataKey, JSON.stringify(credentials));
  adminCredentialsPromise = Promise.resolve(credentials);
  adminSessions.clear();
  return publicCredentialInfo(credentials);
};

let jwtSecretPromise;

const base64UrlJson = value => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

const parseBase64UrlJson = value => {
  try {
    return JSON.parse(Buffer.from(String(value), 'base64url').toString('utf8'));
  } catch {
    return null;
  }
};

const loadJwtSecret = async () => {
  const envSecret = String(process.env.PAYLOADER_JWT_SECRET || '').trim();
  if (envSecret) {
    const decoded = /^[A-Za-z0-9_-]{43,}$/.test(envSecret)
      ? Buffer.from(envSecret, 'base64url')
      : Buffer.from(envSecret, 'utf8');
    if (decoded.length >= 32) return decoded;
    throw new Error('PAYLOADER_JWT_SECRET must be at least 32 bytes.');
  }

  try {
    const stored = (await readFile(jwtSecretFile, 'utf8')).trim();
    const decoded = Buffer.from(stored, 'base64url');
    if (decoded.length >= 32) return decoded;
  } catch {
    // Create a per-install secret below.
  }

  const generated = randomBytes(64);
  await mkdir(dataDir, { recursive: true });
  try {
    await writeFile(jwtSecretFile, `${generated.toString('base64url')}\n`, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const stored = (await readFile(jwtSecretFile, 'utf8')).trim();
    const decoded = Buffer.from(stored, 'base64url');
    if (decoded.length < 32) throw new Error('Stored Payloader JWT secret is invalid.');
    return decoded;
  }
  return generated;
};

const getJwtSecret = () => {
  if (!jwtSecretPromise) {
    const pending = loadJwtSecret();
    const guarded = pending.catch(error => {
      if (jwtSecretPromise === guarded) jwtSecretPromise = undefined;
      throw error;
    });
    jwtSecretPromise = guarded;
  }
  return jwtSecretPromise;
};

export const ensureApplicationReady = async () => {
  await Promise.all([
    ensureStoreReady(),
    getAdminCredentials(),
    getJwtSecret(),
    publicDataResponder.prepare(),
  ]);
  return true;
};

const signJwt = async payload => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlJson(header);
  const encodedPayload = base64UrlJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac('sha256', await getJwtSecret()).update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
};

const verifyJwt = async token => {
  const parts = String(token || '').split('.');
  if (parts.length !== 3 || parts.some(part => part.length === 0)) return null;
  const [encodedHeader, encodedPayload, signature] = parts;
  const header = parseBase64UrlJson(encodedHeader);
  if (!header || header.alg !== 'HS256' || header.typ !== 'JWT') return null;
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expected = createHmac('sha256', await getJwtSecret()).update(signingInput).digest('base64url');
  if (!timingSafeEqual(hashText(signature), hashText(expected))) return null;
  const payload = parseBase64UrlJson(encodedPayload);
  const credentials = await getAdminCredentials();
  if (!payload || payload.iss !== jwtIssuer || payload.aud !== jwtAudience || payload.sub !== credentials.username || payload.cv !== credentials.version) return null;
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.nbf) || !Number.isInteger(payload.exp)) return null;
  if (payload.nbf - jwtClockSkewSec > now || payload.exp + jwtClockSkewSec < now) return null;
  if (payload.iat - jwtClockSkewSec > now || payload.exp <= payload.iat) return null;
  if (typeof payload.jti !== 'string' || payload.jti.length < 32 || payload.jti.length > 96) return null;
  if (typeof payload.sid !== 'string' || payload.sid.length < 32 || payload.sid.length > 96) return null;
  return payload;
};

const cleanupSessions = () => {
  const now = Date.now();
  for (const [sessionId, session] of adminSessions.entries()) {
    if (session.expiresAt <= now) adminSessions.delete(sessionId);
  }
};

const newToken = bytes => randomBytes(bytes).toString('base64url');

const createAdminSession = async request => {
  cleanupSessions();
  const credentials = await getAdminCredentials();
  const sessionId = newToken(24);
  const jwtId = newToken(32);
  const now = Date.now();
  const nowSec = Math.floor(now / 1000);
  const expiresAt = now + sessionTtlMs;
  const token = await signJwt({
    iss: jwtIssuer,
    aud: jwtAudience,
    sub: credentials.username,
    cv: credentials.version,
    sid: sessionId,
    jti: jwtId,
    iat: nowSec,
    nbf: nowSec,
    exp: Math.floor(expiresAt / 1000),
  });
  adminSessions.set(jwtId, {
    sessionId,
    createdAt: now,
    expiresAt,
    tokenHash: hashText(token).toString('base64url'),
    userAgentHash: hashText(request.headers['user-agent'] || '').toString('base64url'),
  });
  return { sessionId, jwtId, token, expiresAt };
};

const readBearerToken = request => {
  const authorization = request.headers.authorization;
  if (typeof authorization !== 'string' || authorization.length > maxJwtBearerLength + 16) return '';
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i);
  return match?.[1] || '';
};

const readAdminSession = async request => {
  cleanupSessions();
  const token = readBearerToken(request);
  if (!token || token.length > maxJwtBearerLength) return null;
  const jwtPayload = await verifyJwt(token);
  if (!jwtPayload) return null;
  const session = adminSessions.get(jwtPayload.jti);
  if (!session || session.expiresAt <= Date.now()) {
    if (session) adminSessions.delete(jwtPayload.jti);
    return null;
  }
  if (session.sessionId !== jwtPayload.sid) return null;
  const expectedTokenHash = Buffer.from(session.tokenHash, 'base64url');
  if (expectedTokenHash.length !== 32 || !timingSafeEqual(hashText(token), expectedTokenHash)) return null;
  const requestAgentHash = hashText(request.headers['user-agent'] || '').toString('base64url');
  if (session.userAgentHash !== requestAgentHash) return null;
  return { jwtId: jwtPayload.jti, ...session };
};

const isAuthorized = async request => Boolean(await readAdminSession(request));

const normalizeIpAddress = value => {
  let address = String(value || '').trim().toLowerCase();
  if (address.startsWith('[') && address.endsWith(']')) address = address.slice(1, -1);
  if (address.startsWith('::ffff:') && isIP(address.slice(7)) === 4) address = address.slice(7);
  return isIP(address) ? address : '';
};

const isLoopbackAddress = address => address === '127.0.0.1' || address === '::1';

const isTrustedProxyAddress = address => (
  trustedProxyAddresses.has(address) || (trustLoopbackProxies && isLoopbackAddress(address))
);

const forwardedClientAddress = (request, peerAddress) => {
  if (!isTrustedProxyAddress(peerAddress)) return '';
  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded !== 'string' || forwarded.length > 2048) return '';
  const chain = forwarded.split(',').map(normalizeIpAddress);
  if (!chain.length || chain.some(address => !address)) return '';
  let resolved = peerAddress;
  for (let index = chain.length - 1; index >= 0 && isTrustedProxyAddress(resolved); index -= 1) {
    resolved = chain[index];
  }
  return resolved === peerAddress ? '' : resolved;
};

const clientKey = request => {
  const peerAddress = normalizeIpAddress(request.socket.remoteAddress) || 'local';
  return forwardedClientAddress(request, peerAddress) || peerAddress;
};

const checkRateLimit = (request, response, scope, limit) => {
  const key = `${scope}:${clientKey(request)}`;
  const timestamp = Date.now();
  const bucket = rateBuckets.get(key);
  const current = bucket && timestamp - bucket.startedAt < limit.windowMs
    ? bucket
    : { startedAt: timestamp, count: 0 };
  current.count += 1;
  rateBuckets.set(key, current);
  if (rateBuckets.size > 1_000) {
    const maxWindow = Math.max(adminRequestLimit.windowMs, failedAuthLimit.windowMs);
    for (const [itemKey, item] of rateBuckets.entries()) {
      if (timestamp - item.startedAt >= maxWindow) rateBuckets.delete(itemKey);
    }
  }
  if (current.count <= limit.max) return true;
  const contentType = scope.includes('login') || scope.includes('admin') ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8';
  response.writeHead(429, {
    ...baseResponseHeaders,
    'content-type': contentType,
    'cache-control': 'no-store',
    'retry-after': String(Math.ceil(limit.windowMs / 1000)),
  });
  response.end(contentType.startsWith('application/json') ? JSON.stringify({ error: '请求过于频繁，请稍后再试' }) : 'Too many requests');
  return false;
};

const clearRateLimit = (request, scope) => {
  rateBuckets.delete(`${scope}:${clientKey(request)}`);
};

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

const readPngDimensions = buffer => {
  if (
    buffer.length < 24 ||
    buffer.readUInt32BE(0) !== 0x89504e47 ||
    buffer.readUInt32BE(4) !== 0x0d0a1a0a ||
    buffer.toString('ascii', 12, 16) !== 'IHDR'
  ) return null;
  return {
    ext: 'png',
    mimeType: 'image/png',
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
};

const isJpegSofMarker = marker => (
  (marker >= 0xc0 && marker <= 0xc3) ||
  (marker >= 0xc5 && marker <= 0xc7) ||
  (marker >= 0xc9 && marker <= 0xcb) ||
  (marker >= 0xcd && marker <= 0xcf)
);

const readJpegDimensions = buffer => {
  if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) return null;
  let offset = 2;
  while (offset + 4 < buffer.length) {
    while (offset < buffer.length && buffer[offset] !== 0xff) offset += 1;
    while (offset < buffer.length && buffer[offset] === 0xff) offset += 1;
    if (offset >= buffer.length) break;
    const marker = buffer[offset];
    offset += 1;
    if (marker === 0xd9 || marker === 0xda) break;
    if (offset + 2 > buffer.length) break;
    const length = buffer.readUInt16BE(offset);
    if (length < 2 || offset + length > buffer.length) break;
    if (isJpegSofMarker(marker)) {
      if (length < 7) break;
      return {
        ext: 'jpg',
        mimeType: 'image/jpeg',
        height: buffer.readUInt16BE(offset + 3),
        width: buffer.readUInt16BE(offset + 5),
      };
    }
    offset += length;
  }
  return null;
};

const readWebpDimensions = buffer => {
  if (
    buffer.length < 30 ||
    buffer.toString('ascii', 0, 4) !== 'RIFF' ||
    buffer.toString('ascii', 8, 12) !== 'WEBP'
  ) return null;
  let offset = 12;
  while (offset + 8 <= buffer.length) {
    const chunkType = buffer.toString('ascii', offset, offset + 4);
    const chunkSize = buffer.readUInt32LE(offset + 4);
    const data = offset + 8;
    if (data + chunkSize > buffer.length) return null;
    if (chunkType === 'VP8X' && chunkSize >= 10) {
      return {
        ext: 'webp',
        mimeType: 'image/webp',
        width: 1 + buffer.readUIntLE(data + 4, 3),
        height: 1 + buffer.readUIntLE(data + 7, 3),
      };
    }
    if (chunkType === 'VP8L' && chunkSize >= 5) {
      const bits = buffer.readUInt32LE(data + 1);
      return {
        ext: 'webp',
        mimeType: 'image/webp',
        width: 1 + (bits & 0x3fff),
        height: 1 + ((bits >> 14) & 0x3fff),
      };
    }
    if (chunkType === 'VP8 ' && chunkSize >= 10 && buffer[data + 3] === 0x9d && buffer[data + 4] === 0x01 && buffer[data + 5] === 0x2a) {
      return {
        ext: 'webp',
        mimeType: 'image/webp',
        width: buffer.readUInt16LE(data + 6) & 0x3fff,
        height: buffer.readUInt16LE(data + 8) & 0x3fff,
      };
    }
    offset = data + chunkSize + (chunkSize % 2);
  }
  return null;
};

const readImageInfo = buffer => (
  readPngDimensions(buffer) ||
  readJpegDimensions(buffer) ||
  readWebpDimensions(buffer)
);

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
    const body = await parseJsonBody(request, 16_384, { requireJson: true });
    const user = typeof body.username === 'string' ? body.username : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (user.length > 256 || password.length > 1024 || !await validAdminCredentials(user, password)) {
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
    if (session) adminSessions.delete(session.jwtId);
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
