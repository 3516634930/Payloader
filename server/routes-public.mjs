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

  const registerPublicRoutes = router => {
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
