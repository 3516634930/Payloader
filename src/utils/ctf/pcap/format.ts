// 流量分析域的展示格式化（批次 L）：字节量、抓包时长、绝对时间戳。
// 纯函数，供工作区壳与各视图共用，避免同款逻辑在组件间复制。

export const formatBytes = (value: number): string => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
};

export const formatDuration = (seconds: number, language: 'zh' | 'en'): string => {
  if (!Number.isFinite(seconds) || seconds <= 0) return language === 'zh' ? '0 秒（单包或无时间戳）' : '0s (single packet or no timestamps)';
  if (seconds < 60) return `${seconds.toFixed(3)}s`;
  let minutes = Math.floor(seconds / 60);
  let rest = Math.round(seconds % 60);
  // 59.6s 四舍五入得 60：进位到分钟，避免「1 分 60 秒」。
  if (rest === 60) {
    minutes += 1;
    rest = 0;
  }
  return language === 'zh' ? `${minutes} 分 ${rest} 秒` : `${minutes}m ${rest}s`;
};

export const formatTimestamp = (tsSeconds: number): string => {
  if (!Number.isFinite(tsSeconds) || tsSeconds <= 0) return '-';
  const date = new Date(tsSeconds * 1000);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toISOString().replace('T', ' ').replace('Z', '') + ' UTC';
};

// 相对首个包的时间，包列表常用展示。
export const formatRelativeTime = (tsSeconds: number, baseSeconds: number | null): string => {
  if (baseSeconds === null || !Number.isFinite(tsSeconds)) return '-';
  return `+${(tsSeconds - baseSeconds).toFixed(6)}s`;
};
