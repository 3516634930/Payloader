// 管理员凭据体系（自 admin-server.mjs 拆出）：scrypt 哈希校验、凭据归一化、
// 读取/保存（经 data-store metadata）与登录验证并发闸。状态随实例隔离，
// 经 createCredentialStore() 工厂创建（隔离粒度同上）；保存成功后经 onCredentialsSaved 通知（单向，供清空会话）。

import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { getMetadataValue, setMetadataValue } from './data-store.mjs';
import { HttpError } from './http-helpers.mjs';

const scrypt = promisify(scryptCallback);

const bundledDefaultAdminPassword = 'payloader-admin!';

const publishedExampleAdminPasswords = new Set([bundledDefaultAdminPassword, 'Change-Me-2026!']);

const credentialsMetadataKey = 'admin_credentials';
const credentialHashParams = Object.freeze({
  algorithm: 'scrypt',
  keyLength: 64,
  saltBytes: 24,
});
const defaultScryptCost = Object.freeze({ N: 32768, r: 8, p: 1 });
const scryptCostLimits = Object.freeze({ minN: 16384, maxN: 262144, maxR: 16, maxP: 4 });
const minAdminPasswordLength = 10;

export const hashText = value => createHash('sha256').update(String(value), 'utf8').digest();

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

export const createCredentialStore = ({ env, onCredentialsSaved }) => {
  const {
    requiresExplicitInitialCredentials,
    defaultAdminUser,
    defaultAdminPassword,
    configuredAdminUser,
    configuredAdminPassword,
  } = env;
  let adminCredentialsPromise;
  // 同时进行 scrypt 凭据校验的请求上限：libuv 线程池默认 4 线程，超过即廉价 429。
  const LOGIN_VERIFY_CONCURRENCY = 4;
  let loginVerifyInFlight = 0;
  const tryBeginLoginVerify = () => {
    if (loginVerifyInFlight >= LOGIN_VERIFY_CONCURRENCY) return false;
    loginVerifyInFlight += 1;
    return true;
  };
  const endLoginVerify = () => {
    loginVerifyInFlight -= 1;
  };

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
  onCredentialsSaved();
  return publicCredentialInfo(credentials);
  };

  return {
    endLoginVerify,
    getAdminCredentials,
    hashAdminPassword,
    publicCredentialInfo,
    saveAdminCredentials,
    tryBeginLoginVerify,
    validAdminCredentials,
  };
};
