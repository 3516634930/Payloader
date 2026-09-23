// 声明式路由注册表（零依赖）：组内匹配优先级固定为 exact > 长前缀 > 短前缀 > pattern。
// pattern 支持 :name 与 :name(constraint) 参数段；匹配用原始 pathname，参数值 decodeURIComponent。
// 命中路径但 method 不在集合时自动 405 并携带 Allow；HEAD 从 GET 集合推导。
// 注意：pattern 组内按注册顺序 first-match-wins，重叠 pattern 的路由应合并方法集或确保顺序（先专用后宽泛）。

const compilePattern = pattern => {
  const names = [];
  const segments = [];
  for (const segment of pattern.split('/')) {
    if (segment === '') continue;
    const param = segment.match(/^:([A-Za-z_$][\w$]*)(?:\((.+)\))?$/);
    if (!param) {
      segments.push({ kind: 'literal', value: segment });
      continue;
    }
    names.push(param[1]);
    segments.push({
      kind: 'param',
      name: param[1],
      matcher: new RegExp(param[2] ? `^(?:${param[2]})$` : '^[^/]+$'),
    });
  }
  return { names, segments };
};

const decodeParam = value => {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
};

export class Router {
  #routes = [];

  // route(['GET'], '/api/health', handler)
  // route(['GET', 'HEAD'], '/uploads/logo/', handler, { match: 'prefix' })
  // route(['POST'], '/api/admin/:resource(payloads|tools|navigation)/:id/move', handler)
  route(methods, pattern, handler, options = {}) {
    const methodSet = new Set(methods.map(method => method.toUpperCase()));
    if (methodSet.has('GET')) methodSet.add('HEAD');
    const segments = compilePattern(pattern).segments;
    const type = options.match === 'prefix'
      ? 'prefix'
      : segments.some(segment => segment.kind === 'param')
        ? 'pattern'
        : 'exact';
    this.#routes.push({
      pattern,
      type,
      handler,
      methods: methodSet,
      allow: [...methodSet].filter(verb => verb !== 'HEAD' || methodSet.has('GET')).join(', '),
      segments,
      group: options.group || 'default',
    });
    return this;
  }

  // 在指定组内匹配并执行；返回 true 表示请求已被处理（含 405 响应），
  // 返回 false 表示组内没有路由命中该路径，由调用方决定下一组或回落。
  async dispatch(request, response, url, group, context = {}) {
    const pathname = url.pathname;
    const verb = request.method === 'HEAD' ? 'GET' : request.method;
    const candidates = this.#routes.filter(route => route.group === group);

    let matched = null;
    // exact
    for (const route of candidates) {
      if (route.type === 'exact' && route.pattern === pathname) {
        matched = { route, params: {} };
        break;
      }
    }
    // prefix（长前缀优先）
    if (!matched) {
      const prefixes = candidates
        .filter(route => route.type === 'prefix')
        .sort((a, b) => b.pattern.length - a.pattern.length);
      for (const route of prefixes) {
        const base = route.pattern.endsWith('/') ? route.pattern : `${route.pattern}/`;
        if (pathname === route.pattern || pathname.startsWith(base)) {
          matched = { route, params: {} };
          break;
        }
      }
    }
    // pattern
    if (!matched) {
      for (const route of candidates) {
        if (route.type !== 'pattern') continue;
        const params = this.#matchSegments(route, pathname);
        if (params) {
          matched = { route, params };
          break;
        }
      }
    }

    if (!matched) return false;
    const { route, params } = matched;
    if (!route.methods.has(verb)) {
      response.writeHead(405, {
        ...(context.baseResponseHeaders || {}),
        allow: route.allow,
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
      });
      response.end('Method not allowed');
      return true;
    }
    await route.handler(request, response, { params, url, ...context });
    return true;
  }

  #matchSegments(route, pathname) {
    const raw = pathname.split('/');
    if (raw[0] === '') raw.shift();
    const segments = route.segments;
    if (raw.length !== segments.length) return null;
    const params = {};
    for (let index = 0; index < segments.length; index += 1) {
      const segment = segments[index];
      const value = raw[index];
      if (segment.kind === 'literal') {
        if (value !== segment.value) return null;
        continue;
      }
      if (!segment.matcher.test(value)) return null;
      const decoded = decodeParam(value);
      if (decoded === null) return null;
      params[segment.name] = decoded;
    }
    return params;
  }
}
