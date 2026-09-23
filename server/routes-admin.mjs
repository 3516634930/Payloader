// 受保护管理路由（自 admin-server.mjs 注册表化）：版本/导出/自定义内容/重置/导入/
// 设置/客户端构建/凭据/三类资源 CRUD。全部位于 admin-request 限流与 requireAuth 之后；
// 资源段用 constraint 模式（payloads|tools|navigation），move 语义由 :id/move 模式表达。
// 依赖经工厂注入；所有 handler 返回后由注册表继续，未命中路径由命名空间统一 404。

import { baseResponseHeaders, HttpError, json, parseJsonBody } from './http-helpers.mjs';
import { createImportTemplate } from './import-template.mjs';

const RESOURCES = 'payloads|tools|navigation';
const maxImportRequestBytes = 24 * 1024 * 1024;

export const createAdminRoutes = ({
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
}) => {
  const parseAdminJsonBody = (request, maxBytes) => parseJsonBody(request, maxBytes, { requireJson: true });

  const sendJson = (response, payload) => {
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    response.end(JSON.stringify(payload));
  };

  const sendAttachment = (response, { fileName, body }) => {
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': 'application/json; charset=utf-8',
      'content-length': String(Buffer.byteLength(body)),
      'content-disposition': `attachment; filename="${fileName}"`,
      'cache-control': 'no-store',
    });
    response.end(body);
  };

  const sendDownload = (response, download) => {
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': download.mimeType || 'application/octet-stream',
      'content-length': String(download.size),
      'content-disposition': `attachment; filename="${download.fileName}"`,
      'cache-control': 'no-store',
    });
  };

  const registerAdminRoutes = router => {
    router.route(['GET'], '/api/admin/version-status', async (request, response) => {
      json(response, 200, await services.versionChecker.getStatus());
    }, { group: 'admin' });

    router.route(['POST'], '/api/admin/version-check', async (request, response) => {
      json(response, 200, await services.versionChecker.checkNow({ force: true }));
    }, { group: 'admin' });

    router.route(['GET'], '/api/admin/export', async (request, response) => {
      const exportPackage = await createDataExportPackage();
      const body = JSON.stringify(exportPackage, null, 2);
      const date = exportPackage.generatedAt.slice(0, 10);
      sendAttachment(response, { fileName: `payloader-export-${date}.json`, body });
    }, { group: 'admin' });

    router.route(['GET'], '/api/admin/custom-payloads', async (request, response) => {
      json(response, 200, { items: await listCustomPayloads() });
    }, { group: 'admin' });

    router.route(['GET', 'POST'], '/api/admin/custom-content', async (request, response) => {
      if (request.method === 'GET') {
        json(response, 200, { items: await listCustomContent() });
        return;
      }
      json(response, 201, await saveCustomContent(await parseAdminJsonBody(request)));
    }, { group: 'admin' });

    router.route(['PUT', 'DELETE'], '/api/admin/custom-content/:id', async (request, response, { params, url }) => {
      const { id } = params;
      if (!id || id.length > 160 || /[\\/\0]/.test(id)) {
        throw new HttpError(400, '自定义内容 ID 无效');
      }
      if (request.method === 'PUT') {
        const body = await parseAdminJsonBody(request);
        json(response, 200, await saveCustomContent({ ...body, id }));
        return;
      }
      json(response, 200, await deleteCustomContent({
        id,
        destination: url.searchParams.get('destination'),
      }));
    }, { group: 'admin' });

    router.route(['GET'], '/api/admin/reset-impact', async (request, response, { url }) => {
      json(response, 200, await getResetImpact(url.searchParams.get('target')));
    }, { group: 'admin' });

    router.route(['POST'], '/api/admin/reset-defaults', async (request, response) => {
      const body = await parseAdminJsonBody(request);
      json(response, 200, await resetDefaultData(body.target));
    }, { group: 'admin' });

    router.route(['GET', 'POST', 'PUT'], '/api/admin/settings', async (request, response) => {
      if (request.method === 'GET') {
        json(response, 200, await getSettings());
        return;
      }
      const body = await parseAdminJsonBody(request);
      json(response, 200, await saveSettings(body));
    }, { group: 'admin' });

    router.route(['GET'], '/api/admin/client-builds/status', async (request, response) => {
      json(response, 200, await getClientBuildStatus());
    }, { group: 'admin' });

    router.route(['POST'], '/api/admin/client-builds/generate', async (request, response) => {
      const body = await parseAdminJsonBody(request, 16_384);
      json(response, 202, await startClientBuild({ targets: Array.isArray(body.targets) ? body.targets : [] }));
    }, { group: 'admin' });

    router.route(['GET', 'HEAD'], '/api/admin/client-builds/download/:file', async (request, response, { params }) => {
      const download = await clientBuildDownload(params.file);
      if (!download) {
        sendText(response, 404, 'Not found');
        return;
      }
      sendDownload(response, download);
      if (request.method === 'HEAD') return;
      download.stream().pipe(response);
    }, { group: 'admin' });

    router.route(['GET'], '/api/admin/import-template', async (request, response) => {
      sendAttachment(response, {
        fileName: 'payloader-import-template.json',
        body: JSON.stringify(createImportTemplate(), null, 2),
      });
    }, { group: 'admin' });

    router.route(['POST'], '/api/admin/import/preview', async (request, response) => {
      try {
        const body = await parseAdminJsonBody(request, maxImportRequestBytes);
        json(response, 200, previewImportPackage(body));
      } catch (error) {
        const status = error instanceof HttpError ? error.status : 400;
        json(response, status, { error: error instanceof Error ? error.message : '导入文件格式不正确' });
      }
    }, { group: 'admin' });

    router.route(['POST'], '/api/admin/import', async (request, response) => {
      try {
        const body = await parseAdminJsonBody(request, maxImportRequestBytes);
        const payload = body && typeof body === 'object' && body.data ? body.data : body;
        const mode = body && typeof body === 'object' && body.mode === 'replace' ? 'replace' : 'merge';
        json(response, 200, await importDataPackage(payload, { mode }));
      } catch (error) {
        const status = error instanceof HttpError ? error.status : 400;
        json(response, status, { error: error instanceof Error ? error.message : '导入文件格式不正确' });
      }
    }, { group: 'admin' });

    router.route(['GET'], '/api/admin/credentials', async (request, response) => {
      json(response, 200, publicCredentialInfo(await getAdminCredentials()));
    }, { group: 'admin' });

    router.route(['PUT'], '/api/admin/credentials', async (request, response) => {
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
      sendJson(response, { ...saved, reauthRequired: true });
    }, { group: 'admin' });

    // 资源集合：列表与新建
    router.route(['GET', 'POST'], `/api/admin/:resource(${RESOURCES})`, async (request, response, { params }) => {
      const { resource } = params;
      if (request.method === 'GET') {
        json(response, 200, { items: await listAdminItems(resource) });
        return;
      }
      const body = await parseAdminJsonBody(request);
      const saved = resource === 'navigation' ? await saveNavigationItem(body) : await saveAdminItem(resource, body);
      json(response, 200, saved);
    }, { group: 'admin' });

    // 顺序移动（原 endsWith('/move') 全局后缀陷阱收敛为模式匹配）
    router.route(['POST'], `/api/admin/:resource(${RESOURCES})/:id/move`, async (request, response, { params }) => {
      const body = await parseAdminJsonBody(request);
      await moveAdminItem(params.resource, params.id, body.direction === 'down' ? 'down' : 'up');
      json(response, 200, { items: await listAdminItems(params.resource) });
    }, { group: 'admin' });

    // 单条更新与删除
    router.route(['PUT', 'DELETE'], `/api/admin/:resource(${RESOURCES})/:id`, async (request, response, { params }) => {
      const { resource, id } = params;
      if (request.method === 'PUT') {
        const body = await parseAdminJsonBody(request);
        const payload = { ...body, id };
        const saved = resource === 'navigation' ? await saveNavigationItem(payload) : await saveAdminItem(resource, payload);
        json(response, 200, saved);
        return;
      }
      await deleteAdminItem(resource, id);
      json(response, 200, { ok: true });
    }, { group: 'admin' });
  };

  const sendText = (response, status, body) => {
    response.writeHead(status, {
      ...baseResponseHeaders,
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
    });
    response.end(body);
  }

  return { registerAdminRoutes };
};
