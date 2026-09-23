// 管理员 JWT 与会话体系（自 admin-server.mjs 拆出）：HS256 JWT 签发/校验、
// 每安装密钥持久化（0o600）、服务端会话表与清理。状态随实例隔离，
// 经 createSessionManager() 工厂创建；凭据经 getCredentials 注入（单向，避免循环依赖）。

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { hashText } from './admin-credentials.mjs';

const jwtIssuer = 'payloader-admin';
const jwtAudience = 'payloader-admin-panel';
const jwtClockSkewSec = 30;
const maxJwtBearerLength = 2048;

export const createSessionManager = ({ jwtSecretFile, sessionTtlMs, getCredentials }) => {
  let jwtSecretPromise;
  const adminSessions = new Map();

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
    await mkdir(dirname(jwtSecretFile), { recursive: true });
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
    const credentials = await getCredentials();
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
    const credentials = await getCredentials();
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

  const revokeAllSessions = () => {
    adminSessions.clear();
  };

  const revokeSession = jwtId => {
    adminSessions.delete(jwtId);
  };

  return {
    createAdminSession,
    getJwtSecret,
    readAdminSession,
    readBearerToken,
    revokeAllSessions,
    revokeSession,
  };
};
