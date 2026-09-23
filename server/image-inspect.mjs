// 图片尺寸嗅探（纯函数，自 admin-server.mjs 机械迁移）：支持 PNG / JPEG / WebP(VP8X/VP8L/VP8)。
// 仅做字节级头部解析，无任何 IO 与副作用，独立可测。

export const readPngDimensions = buffer => {
  if (
    buffer.length < 24 ||
    buffer.readUInt32BE(0) !== 0x89504e47 ||
    buffer.readUInt32BE(4) !== 0x0d0a1a0a ||
    buffer.toString('ascii', 12, 16) !== 'IHDR'
  ) return null;
  return {
    ext: 'png',
    mimeType: 'image/png',
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
};

const isJpegSofMarker = marker => (
  (marker >= 0xc0 && marker <= 0xc3) ||
  (marker >= 0xc5 && marker <= 0xc7) ||
  (marker >= 0xc9 && marker <= 0xcb) ||
  (marker >= 0xcd && marker <= 0xcf)
);

export const readJpegDimensions = buffer => {
  if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) return null;
  let offset = 2;
  while (offset + 4 < buffer.length) {
    while (offset < buffer.length && buffer[offset] !== 0xff) offset += 1;
    while (offset < buffer.length && buffer[offset] === 0xff) offset += 1;
    if (offset >= buffer.length) break;
    const marker = buffer[offset];
    offset += 1;
    if (marker === 0xd9 || marker === 0xda) break;
    if (offset + 2 > buffer.length) break;
    const length = buffer.readUInt16BE(offset);
    if (length < 2 || offset + length > buffer.length) break;
    if (isJpegSofMarker(marker)) {
      if (length < 7) break;
      return {
        ext: 'jpg',
        mimeType: 'image/jpeg',
        height: buffer.readUInt16BE(offset + 3),
        width: buffer.readUInt16BE(offset + 5),
      };
    }
    offset += length;
  }
  return null;
};

export const readWebpDimensions = buffer => {
  if (
    buffer.length < 30 ||
    buffer.toString('ascii', 0, 4) !== 'RIFF' ||
    buffer.toString('ascii', 8, 12) !== 'WEBP'
  ) return null;
  let offset = 12;
  while (offset + 8 <= buffer.length) {
    const chunkType = buffer.toString('ascii', offset, offset + 4);
    const chunkSize = buffer.readUInt32LE(offset + 4);
    const data = offset + 8;
    if (data + chunkSize > buffer.length) return null;
    if (chunkType === 'VP8X' && chunkSize >= 10) {
      return {
        ext: 'webp',
        mimeType: 'image/webp',
        width: 1 + buffer.readUIntLE(data + 4, 3),
        height: 1 + buffer.readUIntLE(data + 7, 3),
      };
    }
    if (chunkType === 'VP8L' && chunkSize >= 5) {
      const bits = buffer.readUInt32LE(data + 1);
      return {
        ext: 'webp',
        mimeType: 'image/webp',
        width: 1 + (bits & 0x3fff),
        height: 1 + ((bits >> 14) & 0x3fff),
      };
    }
    if (chunkType === 'VP8 ' && chunkSize >= 10 && buffer[data + 3] === 0x9d && buffer[data + 4] === 0x01 && buffer[data + 5] === 0x2a) {
      return {
        ext: 'webp',
        mimeType: 'image/webp',
        width: buffer.readUInt16LE(data + 6) & 0x3fff,
        height: buffer.readUInt16LE(data + 8) & 0x3fff,
      };
    }
    offset = data + chunkSize + (chunkSize % 2);
  }
  return null;
};

export const readImageInfo = buffer => (
  readPngDimensions(buffer) ||
  readJpegDimensions(buffer) ||
  readWebpDimensions(buffer)
);
