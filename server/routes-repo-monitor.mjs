// 订阅仓库监控路由（v2.0.1）：全部位于 /api/admin/repo-monitors* 下、group 'admin'
// （admin-server 的限流 + requireAuth 之后）。RepoMonitorError → HTTP 状态映射：
// invalid-input/interval-invalid→400、not-found→404、duplicate→409；其余原样抛给统一错误处理。
// '/check' 静态路由先注册，router 组内 exact 优先于 ':id/check' pattern，不会误吞。

import { HttpError, json, parseJsonBody } from './http-helpers.mjs';
import { RepoMonitorError } from './repo-monitor.mjs';

const maxBodyBytes = 16_384;
const idPattern = /^[A-Za-z0-9_-]{1,80}$/;

const mapMonitorError = error => {
  if (error instanceof RepoMonitorError) {
    const status = {
      'invalid-input': 400,
      'interval-invalid': 400,
      'limit-reached': 400,
      'not-found': 404,
      duplicate: 409,
    }[error.code] || 400;
    throw new HttpError(status, error.message);
  }
  throw error;
};

export const createRepoMonitorRoutes = ({ repoMonitor }) => {
  const registerRepoMonitorRoutes = router => {
    router.route(['GET', 'POST'], '/api/admin/repo-monitors', async (request, response) => {
      if (request.method === 'GET') {
        json(response, 200, await repoMonitor.list());
        return;
      }
      try {
        // body 为字面 null 时解构会抛 TypeError（500），统一回落空对象走 400 校验
        const body = await parseJsonBody(request, maxBodyBytes, { requireJson: true });
        json(response, 201, await repoMonitor.add(body || {}));
      } catch (error) {
        throw mapMonitorError(error);
      }
    }, { group: 'admin' });

    router.route(['POST'], '/api/admin/repo-monitors/check', async (request, response) => {
      json(response, 200, await repoMonitor.checkNow({}));
    }, { group: 'admin' });

    router.route(['POST'], '/api/admin/repo-monitors/:id/check', async (request, response, { params }) => {
      try {
        if (!idPattern.test(String(params.id || ''))) throw new HttpError(400, '订阅 ID 无效。');
        json(response, 200, await repoMonitor.checkNow({ id: params.id }));
      } catch (error) {
        throw mapMonitorError(error);
      }
    }, { group: 'admin' });

    router.route(['DELETE'], '/api/admin/repo-monitors/:id', async (request, response, { params }) => {
      try {
        if (!idPattern.test(String(params.id || ''))) throw new HttpError(400, '订阅 ID 无效。');
        json(response, 200, await repoMonitor.remove(params.id));
      } catch (error) {
        throw mapMonitorError(error);
      }
    }, { group: 'admin' });
  };

  return { registerRepoMonitorRoutes };
};
