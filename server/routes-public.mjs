// 公开 API 路由（自 admin-server.mjs 注册表化）：健康/就绪/项目跳转/公开数据/客户端构建。
// 依赖经工厂注入；publicProjectRoute 与官方跳转目标来自 project-attribution（不透明路由）。

import { json, text } from './http-helpers.mjs';

export const createPublicRoutes = ({
  publicDataResponder,
  ensureApplicationReady,
  officialProjectUrl,
  publicProjectRoute,
  getPublicClientBuildInfo,
  clientBuildDownload,
  getPublicData,
  baseResponseHeaders,
}) => {
  const sendDownload = (response, download) => {
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': download.mimeType || 'application/octet-stream',
      'content-length': String(download.size),
      'content-disposition': `attachment; filename="${download.fileName}"`,
      'cache-control': 'no-store',
    });
  };

  // SEO：站点 origin 取请求 Host（本地/公网部署一致），sitemap/robots 动态生成（内容在 DB）。
  const requestOrigin = request => `http://${request.headers?.host || '127.0.0.1:8081'}`;
  const xmlEscape = value => String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const registerPublicRoutes = router => {
    router.route(['GET', 'HEAD'], '/sitemap.xml', async (request, response) => {
      const origin = requestOrigin(request);
      const data = await getPublicData();
      const entry = loc => `  <url>\n    <loc>${xmlEscape(loc)}</loc>\n  </url>`;
      const urls = [
        entry(`${origin}/`),
        ...(data.payloads || []).map(p => entry(`${origin}/#/payload/${encodeURIComponent(p.id)}`)),
        ...(data.tools || []).map(t => entry(`${origin}/#/tool/${encodeURIComponent(t.id)}`)),
      ];
      const body = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`;
      response.writeHead(200, { ...baseResponseHeaders, 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=3600' });
      response.end(body);
    }, { group: 'public' });

    router.route(['GET', 'HEAD'], '/robots.txt', (request, response) => {
      const origin = requestOrigin(request);
      const body = [
        'User-agent: *',
        'Allow: /',
        'Disallow: /api/',
        'Disallow: /admin',
        'Disallow: /uploads/',
        '',
        `Sitemap: ${origin}/sitemap.xml`,
        '',
      ].join('\n');
      response.writeHead(200, { ...baseResponseHeaders, 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'public, max-age=3600' });
      response.end(body);
    }, { group: 'public' });

    router.route(['GET'], '/api/health', (request, response) => {
      json(response, 200, { status: 'ok' });
    }, { group: 'public' });

    router.route(['GET'], '/api/ready', async (request, response) => {
      try {
        await ensureApplicationReady();
        json(response, 200, { status: 'ready' });
      } catch (error) {
        console.error('Readiness check failed:', error);
        json(response, 503, { status: 'not_ready' });
      }
    }, { group: 'public' });

    router.route(['GET', 'HEAD'], publicProjectRoute, (request, response) => {
      response.writeHead(302, {
        ...baseResponseHeaders,
        location: officialProjectUrl,
        'cache-control': 'no-store',
      });
      response.end();
    }, { group: 'public' });

    router.route(['GET'], '/api/public-data', async (request, response) => {
      await publicDataResponder.respond(request, response);
    }, { group: 'public' });

    router.route(['GET'], '/api/client-build', async (request, response) => {
      json(response, 200, await getPublicClientBuildInfo());
    }, { group: 'public' });

    router.route(['GET', 'HEAD'], '/api/client-build/download/latest', async (request, response) => {
      const info = await getPublicClientBuildInfo();
      const fileName = info.available && info.latest ? info.latest.fileName : '';
      const download = fileName ? await clientBuildDownload(fileName) : null;
      if (!download) {
        text(response, 404, 'Client build not available');
        return;
      }
      sendDownload(response, download);
      if (request.method === 'HEAD') return;
      download.stream().pipe(response);
    }, { group: 'public' });

    router.route(['GET', 'HEAD'], '/api/client-build/download/:file', async (request, response, { params }) => {
      const download = await clientBuildDownload(params.file);
      if (!download) {
        text(response, 404, 'Client build not available');
        return;
      }
      sendDownload(response, download);
      if (request.method === 'HEAD') return;
      download.stream().pipe(response);
    }, { group: 'public' });

    router.route(['GET'], '/api/custom-tools', async (request, response) => {
      const data = await getPublicData();
      json(response, 200, { version: 1, categories: data.tools.filter(tool => String(tool.id).startsWith('custom-')) });
    }, { group: 'public' });
  };

  return { registerPublicRoutes };
};
