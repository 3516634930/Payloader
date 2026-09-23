// HTTP 响应与请求体助手（自 admin-server.mjs 机械迁移）：错误类型、安全响应头、JSON/文本响应、
// 请求体读取与解析。无状态，独立可测。

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

export {
  baseResponseHeaders,
  contentSecurityPolicy,
  errorStatus,
  HttpError,
  isJsonRequest,
  json,
  methodNotAllowed,
  parseJsonBody,
  safeErrorPayload,
  text,
};
