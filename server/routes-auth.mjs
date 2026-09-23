// 认证入口路由（自 admin-server.mjs 注册表化）：session 查询、登录、登出。
// 这三条路由位于 /api/admin 命名空间的统一限流与 requireAuth 之前（entry 组），
// 登录失败限流与 scrypt 并发闸保持在 handler 内部（与原顺序语义一致）。

import { baseResponseHeaders, json, parseJsonBody } from './http-helpers.mjs';

export const createAuthRoutes = ({
  readAdminSession,
  createAdminSession,
  revokeSession,
  getAdminCredentials,
  validAdminCredentials,
  tryBeginLoginVerify,
  endLoginVerify,
  checkRateLimit,
  clearRateLimit,
  respondTooManyRequests,
  failedLoginLimit,
  adminRequestLimit,
}) => {
  const sendJson = (response, payload) => {
    response.writeHead(200, {
      ...baseResponseHeaders,
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    response.end(JSON.stringify(payload));
  };

  const registerAuthRoutes = router => {
    router.route(['GET'], '/api/admin/session', async (request, response) => {
      // session 可被无成本探测：与登录同级限流，超出常规频率即廉价 429
      if (!checkRateLimit(request, response, 'admin-session-probe', adminRequestLimit)) return;
      const session = await readAdminSession(request);
      if (!session) {
        json(response, 401, { error: '登录已失效，请重新登录' });
        return;
      }
      const credentials = await getAdminCredentials();
      json(response, 200, {
        authenticated: true,
        user: credentials.username,
        expiresAt: session.expiresAt,
      });
    }, { group: 'auth-entry' });

    router.route(['POST'], '/api/admin/login', async (request, response) => {
      // scrypt 并发闸：错误登录洪水不占满线程池；正确凭据在低并发时仍可正常登录。
      if (!tryBeginLoginVerify()) {
        respondTooManyRequests(response, 'admin-login-failed', failedLoginLimit);
        return;
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
        if (!checkRateLimit(request, response, 'admin-login-failed', failedLoginLimit)) return;
        json(response, 401, { error: '账号或密码不正确' });
        return;
      }
      clearRateLimit(request, 'admin-login-failed');
      const credentials = await getAdminCredentials();
      const session = await createAdminSession(request);
      sendJson(response, {
        authenticated: true,
        user: credentials.username,
        accessToken: session.token,
        tokenType: 'Bearer',
        expiresAt: session.expiresAt,
      });
    }, { group: 'auth-entry' });

    router.route(['POST'], '/api/admin/logout', async (request, response) => {
      if (!checkRateLimit(request, response, 'admin-session-probe', adminRequestLimit)) return;
      const session = await readAdminSession(request);
      if (session) revokeSession(session.jwtId);
      sendJson(response, { ok: true });
    }, { group: 'auth-entry' });
  };

  return { registerAuthRoutes };
};
