// 文件取证域共用下载 helper（主工作区与各卡片共用）：bytes 落成浏览器下载。
export const downloadBytes = (bytes: Uint8Array, filename: string) => {
  const url = URL.createObjectURL(new Blob([bytes.slice()], { type: 'application/octet-stream' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
};
