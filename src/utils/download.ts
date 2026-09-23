// 字节/对象落盘下载唯一入口。bytes.slice() 先复制一份，避免调用方后续复用 buffer 触发 detached 异常。
export function downloadBytes(bytes: Uint8Array, filename: string, mime = 'application/octet-stream'): void {
  downloadBlob(new Blob([bytes.slice()], { type: mime }), filename);
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  // revoke 过早会把已入队下载置为失败，沿用各域原实现的 4s 延迟。
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
