// Logo 上传（自 admin-server.mjs 机械迁移 + 注册表化）：JSON/base64 图片上传，
// 魔数校验（PNG/JPEG/WebP）与尺寸上限；存储目录经工厂注入。

import { mkdir, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { readImageInfo } from './image-inspect.mjs';
import { HttpError, isJsonRequest, json, parseJsonBody, text } from './http-helpers.mjs';

const maxLogoBytes = 1_048_576;
const maxLogoDimension = 1024;
const maxLogoRequestBytes = 1_500_000;
const acceptedLogoMimeTypes = new Set(['image/png', 'image/jpeg', 'image/webp']);

export const createLogoUploader = ({ logoUploadDir, safeResolve }) => {
  const normalizeLogoMimeType = value => {
    const mimeType = String(value || '').toLowerCase().trim();
    return acceptedLogoMimeTypes.has(mimeType) ? mimeType : '';
  };

  const estimateBase64Bytes = value => {
    const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
    return Math.floor((value.length * 3) / 4) - padding;
  };

  const extractBase64Payload = body => {
    if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
    const source = String(body.dataUrl || body.base64 || '');
    const commaIndex = source.indexOf(',');
    const hasRequestMimeType = Object.prototype.hasOwnProperty.call(body, 'mimeType') && String(body.mimeType).trim();
    const requestMimeType = normalizeLogoMimeType(body.mimeType);
    if (hasRequestMimeType && !requestMimeType) {
      throw new HttpError(415, 'Only PNG, JPEG, and WebP logo images are allowed');
    }
    let declaredMimeType = requestMimeType;
    if (source.startsWith('data:')) {
      if (commaIndex < 0) return null;
      const meta = source.slice(5, commaIndex).toLowerCase();
      const [mimeType, ...flags] = meta.split(';').map(item => item.trim()).filter(Boolean);
      if (!flags.includes('base64')) return null;
      declaredMimeType = normalizeLogoMimeType(mimeType);
      if (!declaredMimeType) {
        throw new HttpError(415, 'Only PNG, JPEG, and WebP logo images are allowed');
      }
      if (requestMimeType && requestMimeType !== declaredMimeType) {
        throw new HttpError(415, 'Logo file type does not match the uploaded image data');
      }
    }
    const base64 = commaIndex >= 0 ? source.slice(commaIndex + 1) : source;
    if (!/^[a-zA-Z0-9+/=\s]+$/.test(base64)) return null;
    const normalized = base64.replace(/\s/g, '');
    if (!normalized || normalized.length % 4 !== 0 || estimateBase64Bytes(normalized) > maxLogoBytes) return null;
    return { base64: normalized, declaredMimeType, requestMimeType };
  };

  const handleLogoUpload = async (request, response) => {
    if (!isJsonRequest(request)) {
      text(response, 415, 'Logo uploads must use application/json');
      return;
    }
    const contentLength = Number(request.headers['content-length'] || 0);
    if (contentLength > maxLogoRequestBytes) {
      text(response, 413, 'Logo upload request is too large');
      return;
    }
    const body = await parseJsonBody(request, maxLogoRequestBytes);
    const payload = extractBase64Payload(body);
    if (!payload) {
      text(response, 400, 'Missing image data');
      return;
    }
    const buffer = Buffer.from(payload.base64, 'base64');
    if (!buffer.length || buffer.length > maxLogoBytes) {
      text(response, 413, 'Logo image must be 1 MB or smaller');
      return;
    }
    const image = readImageInfo(buffer);
    if (!image) {
      text(response, 415, 'Only PNG, JPEG, and WebP logo images are allowed');
      return;
    }
    if (payload.declaredMimeType && payload.declaredMimeType !== image.mimeType) {
      text(response, 415, 'Logo file type does not match the uploaded image data');
      return;
    }
    if (payload.requestMimeType && payload.requestMimeType !== image.mimeType) {
      text(response, 415, 'Logo file type does not match the uploaded image data');
      return;
    }
    if (
      image.width < 1 ||
      image.height < 1 ||
      image.width > maxLogoDimension ||
      image.height > maxLogoDimension
    ) {
      text(response, 400, `Logo image dimensions must be ${maxLogoDimension}x${maxLogoDimension} or smaller`);
      return;
    }
    await mkdir(logoUploadDir, { recursive: true });
    const fileName = `logo-${Date.now()}-${randomUUID()}.${image.ext}`;
    const filePath = safeResolve(logoUploadDir, fileName);
    if (!filePath) {
      text(response, 500, 'Unable to store logo');
      return;
    }
    await writeFile(filePath, buffer, { flag: 'wx' });
    json(response, 200, {
      logoUrl: `/uploads/logo/${fileName}`,
      mimeType: image.mimeType,
      width: image.width,
      height: image.height,
      size: buffer.length,
    });
  };

  const registerLogoRoutes = router => {
    router.route(['POST'], '/api/admin/logo', handleLogoUpload, { group: 'admin' });
  };

  return { handleLogoUpload, registerLogoRoutes };
};
