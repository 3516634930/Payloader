// 静态资源服务（自 admin-server.mjs 机械迁移 + 注册表化）：favicon、logo 上传文件、
// /admin 后台页面、前端 dist 回落。目录路径经工厂注入，Xeye 集成随设置摘除。

import { createReadStream } from 'node:fs';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { extname, isAbsolute, join, normalize, relative, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { readImageInfo } from './image-inspect.mjs';
import { baseResponseHeaders, HttpError, isJsonRequest, json, parseJsonBody, text } from './http-helpers.mjs';

const pathSeparator = process.platform === 'win32' ? '\\' : '/';

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
const acceptedLogoMimeTypes = new Set(['image/png', 'image/jpeg', 'image/webp']);

export const createStaticHandlers = ({ distDir, adminDir, logoUploadDir, getSettings, checkRateLimit, adminRequestLimit }) => {
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

  // 静态组路由：favicon / logo 文件 / /admin 页面 / 前端回落（前端回落需注册在最后，作为 fallback）
  const registerStaticRoutes = (router, { fallbackPattern = null } = {}) => {
    router.route(['GET', 'HEAD'], '/favicon.ico', (request, response) => {
      response.writeHead(204, baseResponseHeaders);
      response.end();
    }, { group: 'static' });

    router.route(['GET', 'HEAD'], '/uploads/logo/', (request, response, { url }) => {
      const logoPath = logoStaticPath(url.pathname);
      if (!logoPath) {
        text(response, 403, 'Forbidden');
        return;
      }
      return serveStatic(request, response, logoPath, { cacheControl: 'public, max-age=86400, immutable' });
    }, { match: 'prefix', group: 'static' });

    router.route(['GET', 'HEAD'], '/admin', (request, response, { url }) => {
      if (!checkRateLimit(request, response, 'admin-page', adminRequestLimit)) return;
      if (url.pathname === '/admin/login') {
        return serveStatic(request, response, join(adminDir, 'login.html'));
      }
      const adminPath = adminStaticPath(url.pathname);
      if (!adminPath) {
        text(response, 403, 'Forbidden');
        return;
      }
      return serveStatic(request, response, adminPath);
    }, { match: 'prefix', group: 'static' });

    if (fallbackPattern) {
      router.route(['GET', 'HEAD'], fallbackPattern, async (request, response, { url }) => {
        await serveFrontendFallback(request, response, url);
      }, { group: 'static' });
    }
  };

  const serveFrontendFallback = async (request, response, url) => {
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
      cacheControl: extname(frontendPath).toLowerCase() === '.html' ? 'no-store' : 'public, max-age=3600',
    });
  };

  return {
    decodeUrlPath,
    safeResolve,
    serveStatic,
    serveFrontendFallback,
    registerStaticRoutes,
  };
};
