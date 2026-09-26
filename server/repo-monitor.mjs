// 订阅仓库监控引擎（v2.0.1 GitHub 仓库监控线）：多目标 Atom feed 通道，
// 安全骨架沿用 version-checker——固定 github.com host（订阅输入统一经
// parseGitHubRepository 校验，请求 URL 由服务端重建）、10 秒超时、512 KiB 响应上限、
// redirect: 'error'、ETag 条件请求（304 复用内存缓存）、token 仅取环境变量不落盘。
// 订阅清单与检查状态经注入的 load/save 持久化（metadata 键）；端点全部走管理端鉴权。

import {
  VersionCheckError,
  cleanText,
  parseGitHubRepository,
  readBoundedText,
} from './version-checker.mjs';

export const REPO_MONITOR_SUBSCRIPTIONS_METADATA_KEY = 'repo_monitor_subscriptions';
export const REPO_MONITOR_STATUS_METADATA_KEY = 'repo_monitor_status';
export const DEFAULT_REPO_MONITOR_INTERVAL_MS = 6 * 60 * 60 * 1000;
export const MIN_REPO_MONITOR_INTERVAL_MS = 15 * 60 * 1000;
export const MAX_REPO_MONITOR_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;

const defaultInitialDelayMs = 45_000;
const defaultMaxResponseBytes = 512 * 1024;
const maxConcurrentFeedFetches = 4;
const maxSubscriptions = 200;
const commitPattern = /^[0-9a-f]{7,64}$/i;
const subscriptionIdPattern = /^[A-Za-z0-9_-]{1,80}$/;

export class RepoMonitorError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'RepoMonitorError';
    this.code = code;
  }
}

// 预置精选 CTF 资源仓库：仅当订阅清单 metadata 缺失时种子一次（用户删空后是空数组，不重播）。
export const PRESET_REPO_MONITORS = [
  { id: 'preset-payloads-all-the-things', owner: 'swisskyrepo', repository: 'PayloadsAllTheThings', note: '攻击 payload 大全（Web 利用 / CTF 通用）', preset: true },
  { id: 'preset-seclists', owner: 'danielmiessler', repository: 'SecLists', note: '目录爆破 / 字典 / fuzz 列表合集', preset: true },
  { id: 'preset-rsactftool', owner: 'Ganapati', repository: 'RsaCtfTool', note: 'RSA 解题攻击工具', preset: true },
  { id: 'preset-stego-toolkit', owner: 'DominicBreuker', repository: 'stego-toolkit', note: '隐写取证工具集', preset: true },
  { id: 'preset-ctfd', owner: 'CTFd', repository: 'CTFd', note: 'CTF 竞赛平台', preset: true },
  { id: 'preset-awesome-ctf', owner: 'apsdehal', repository: 'awesome-ctf', note: 'CTF 工具与资源索引', preset: true },
  { id: 'preset-google-ctf', owner: 'google', repository: 'google-ctf', note: 'Google CTF 题目归档', preset: true },
  { id: 'preset-p4-ctf', owner: 'p4-team', repository: 'ctf', note: 'p4 战队 writeup 归档', preset: true },
];

// ---- Atom feed 解析（零依赖：只取第一个 <entry> 的字段） ----

const decodeXmlEntities = value => String(value || '')
  .replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
    const code = Number.parseInt(hex, 16);
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
  })
  .replace(/&#(\d+);/g, (_, decimal) => {
    const code = Number.parseInt(decimal, 10);
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
  })
  .replace(/&quot;/g, '"')
  .replace(/&apos;/g, "'")
  .replace(/&lt;/g, '<')
  .replace(/&gt;/g, '>')
  .replace(/&amp;/g, '&');

const entryChild = (entry, tag) => {
  const match = entry.match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, 'i'));
  return match ? match[1].trim() : '';
};

const entryLink = entry => {
  const match = entry.match(/<link\b[^>]*\bhref="([^"]*)"/i);
  return match ? decodeXmlEntities(match[1]).trim() : '';
};

export const parseAtomFeed = xml => {
  const entryMatch = String(xml || '').match(/<entry\b[^>]*>([\s\S]*?)<\/entry>/i);
  if (!entryMatch) return null;
  const entry = entryMatch[1];
  const authorMatch = entry.match(/<author\b[^>]*>[\s\S]*?<name\b[^>]*>([\s\S]*?)<\/name>/i);
  return {
    title: decodeXmlEntities(entryChild(entry, 'title')),
    updated: decodeXmlEntities(entryChild(entry, 'updated')),
    id: decodeXmlEntities(entryChild(entry, 'id')),
    link: entryLink(entry),
    author: authorMatch ? decodeXmlEntities(authorMatch[1].trim()) : '',
  };
};

// commits.atom 的 entry id 形如 tag:github.com,2008:Grit::Commit/<sha>
const commitShaFromEntryId = id => {
  const tail = String(id || '').split('/').pop() || '';
  return commitPattern.test(tail) ? tail.toLowerCase() : '';
};

// releases.atom 的 entry link 形如 .../releases/tag/<tag>
const releaseTagFromLink = link => {
  const match = String(link || '').match(/\/releases\/tag\/([^/?#]+)/);
  if (!match) return '';
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
};

const isoOrNull = value => {
  const text = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(text)) return null;
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

const safeClone = value => JSON.parse(JSON.stringify(value));

const idleStatus = id => ({
  id,
  state: 'idle',
  changed: false,
  release: null,
  commit: null,
  checkedAt: null,
  lastSuccessfulAt: null,
  error: null,
});

const sanitizeStatus = (id, value) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return idleStatus(id);
  const status = { ...idleStatus(id) };
  status.changed = value.changed === true;
  if (value.release && typeof value.release === 'object' && (value.release.tag || value.release.title)) {
    status.release = {
      title: cleanText(value.release.title, 200),
      tag: cleanText(value.release.tag, 128),
      updatedAt: isoOrNull(value.release.updatedAt),
      link: cleanText(value.release.link, 300),
    };
  }
  if (value.commit && typeof value.commit === 'object' && commitPattern.test(String(value.commit.sha || ''))) {
    status.commit = {
      sha: String(value.commit.sha).toLowerCase(),
      shaShort: String(value.commit.sha).slice(0, 12),
      message: cleanText(value.commit.message, 240),
      author: cleanText(value.commit.author, 80),
      committedAt: isoOrNull(value.commit.committedAt),
      link: cleanText(value.commit.link, 300),
    };
  }
  status.checkedAt = typeof value.checkedAt === 'string' ? value.checkedAt.slice(0, 40) : null;
  status.lastSuccessfulAt = typeof value.lastSuccessfulAt === 'string' ? value.lastSuccessfulAt.slice(0, 40) : null;
  // 'checking' 是纯内存瞬态：批量检查中途重启会把整批快照连同它落盘，加载时视为被中断，
  // 否则该订阅会永久卡在"检查中"且前端按钮禁用
  if (value.state === 'checked' || value.state === 'error') status.state = value.state;
  else if (value.state === 'checking') {
    status.state = 'error';
    status.error = { code: 'interrupted', message: '上次检查被中断，请重新检查。' };
  }
  if (value.error && typeof value.error === 'object') {
    status.error = { code: cleanText(value.error.code, 48) || 'check-failed', message: cleanText(value.error.message, 240) };
  }
  return status;
};

const sanitizeSubscription = value => {
  if (!value || typeof value !== 'object') return null;
  const id = String(value.id || '');
  const owner = String(value.owner || '');
  const repository = String(value.repository || '');
  if (!subscriptionIdPattern.test(id)) return null;
  try {
    const parsed = parseGitHubRepository(`https://github.com/${owner}/${repository}`);
    return {
      id,
      owner: parsed.owner,
      repository: parsed.repository,
      note: cleanText(value.note, 120),
      preset: value.preset === true,
      createdAt: typeof value.createdAt === 'string' ? value.createdAt.slice(0, 40) : null,
    };
  } catch {
    return null;
  }
};

const publicError = error => ({
  code: error instanceof VersionCheckError ? error.code : 'check-failed',
  message: error instanceof VersionCheckError ? error.message : 'Unable to check repository updates.',
});

const validateInterval = value => {
  const interval = value === undefined || value === null || value === ''
    ? DEFAULT_REPO_MONITOR_INTERVAL_MS
    : Number(value);
  if (!Number.isSafeInteger(interval) || interval < MIN_REPO_MONITOR_INTERVAL_MS || interval > MAX_REPO_MONITOR_INTERVAL_MS) {
    throw new RepoMonitorError(
      'interval-invalid',
      `PAYLOADER_REPO_MONITOR_INTERVAL_MS must be an integer between ${MIN_REPO_MONITOR_INTERVAL_MS} and ${MAX_REPO_MONITOR_INTERVAL_MS}.`,
    );
  }
  return interval;
};

export const parseRepositoryReference = value => {
  const reference = String(value || '').trim().replace(/\s+/g, '');
  if (!reference) throw new RepoMonitorError('invalid-input', '请填写仓库（owner/repo 或 GitHub 仓库 URL）。');
  const normalized = /^https?:\/\//i.test(reference) ? reference : `https://github.com/${reference}`;
  try {
    return parseGitHubRepository(normalized);
  } catch {
    throw new RepoMonitorError('invalid-input', '仓库地址无效：仅支持 github.com 公开仓库（owner/repo 形式或完整 URL）。');
  }
};

export const createRepoMonitor = options => {
  const environment = options.environment || process.env;
  const intervalMs = validateInterval(options.intervalMs ?? environment.PAYLOADER_REPO_MONITOR_INTERVAL_MS);
  const initialDelayMs = Number(options.initialDelayMs ?? defaultInitialDelayMs);
  const scheduledDisabled = options.disabled ?? environment.PAYLOADER_REPO_MONITOR_DISABLED === 'true';
  const loadSubscriptions = options.loadSubscriptions || (async () => null);
  const saveSubscriptions = options.saveSubscriptions || (async () => {});
  const loadStatuses = options.loadStatuses || (async () => null);
  const saveStatuses = options.saveStatuses || (async () => {});
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const token = String(options.token ?? (environment.PAYLOADER_GITHUB_TOKEN || '')).trim();
  const timeoutMs = Number(options.timeoutMs || 10_000);
  const maxResponseBytes = Number(options.maxResponseBytes || defaultMaxResponseBytes);
  const setTimer = options.setTimer || setTimeout;
  const clearTimer = options.clearTimer || clearTimeout;
  const now = options.now || Date.now;
  const random = options.random || Math.random;

  const feedCache = new Map();
  let subscriptions = [];
  let statuses = new Map();
  let nextCheckAt = null;
  let timer;
  let stopped = false;
  let initializedPromise;
  const inFlightById = new Map();

  const persistSubscriptions = () => saveSubscriptions(JSON.stringify(subscriptions));
  const persistStatuses = () => saveStatuses(JSON.stringify(Object.fromEntries(statuses.entries())));

  const initialize = () => {
    if (initializedPromise) return initializedPromise;
    initializedPromise = (async () => {
      let storedSubscriptions = null;
      try {
        storedSubscriptions = await loadSubscriptions();
        const parsed = typeof storedSubscriptions === 'string' && storedSubscriptions
          ? JSON.parse(storedSubscriptions)
          : storedSubscriptions;
        if (Array.isArray(parsed)) {
          subscriptions = parsed.map(sanitizeSubscription).filter(Boolean);
        }
      } catch {
        subscriptions = [];
      }
      if (storedSubscriptions === null || storedSubscriptions === undefined || storedSubscriptions === '') {
        // 首次初始化：种子预置 CTF 资源仓库（metadata 缺失才写；删空是 []，不重播）
        subscriptions = PRESET_REPO_MONITORS.map(sanitizeSubscription).filter(Boolean);
        await persistSubscriptions();
      }
      try {
        const storedStatuses = await loadStatuses();
        const parsedStatuses = typeof storedStatuses === 'string' && storedStatuses ? JSON.parse(storedStatuses) : storedStatuses;
        if (parsedStatuses && typeof parsedStatuses === 'object' && !Array.isArray(parsedStatuses)) {
          statuses = new Map(Object.entries(parsedStatuses)
            .filter(([id]) => subscriptionIdPattern.test(id))
            .map(([id, value]) => [id, sanitizeStatus(id, value)]));
        }
      } catch {
        statuses = new Map();
      }
      const knownIds = new Set(subscriptions.map(subscription => subscription.id));
      for (const id of [...statuses.keys()]) {
        if (!knownIds.has(id)) statuses.delete(id);
      }
    })();
    // 种子/加载持久化失败（如 DB 瞬时错误）时清空缓存，允许下次调用重试而非永久拒绝
    initializedPromise.catch(() => { initializedPromise = null; });
    return initializedPromise;
  };

  const feedUrl = (subscription, kind) => `https://github.com/${subscription.owner}/${subscription.repository}/${kind}.atom`;

  // 仓库改名/转移时 GitHub 对旧路径回 301。受控跟随：仅允许落在 github.com 的
  // owner/repo/{releases|commits}.atom 路径（固定 host、无凭据/query，owner/repo 字符集
  // 与 parseGitHubRepository 同规），最多 3 跳；越界一律拒绝，配置改不了网络目的地。
  const maxFeedRedirects = 3;
  const feedRedirectTarget = (currentUrl, location) => {
    let resolved;
    try {
      resolved = new URL(String(location || ''), currentUrl);
    } catch {
      throw new VersionCheckError('invalid-response', 'GitHub returned an invalid feed redirect.');
    }
    if (
      resolved.protocol !== 'https:'
      || resolved.hostname.toLowerCase() !== 'github.com'
      || resolved.username
      || resolved.password
      || resolved.search
      || resolved.hash
    ) {
      throw new VersionCheckError('invalid-response', 'GitHub feed redirect left the allowed destination.');
    }
    const match = resolved.pathname.match(/^\/([^/]+)\/([^/]+)\/(releases|commits)\.atom$/);
    const repository = match ? match[2].replace(/\.git$/i, '') : '';
    if (
      !match
      || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(match[1])
      || !/^[A-Za-z0-9._-]{1,100}$/.test(repository)
    ) {
      throw new VersionCheckError('invalid-response', 'GitHub feed redirect left the allowed destination.');
    }
    return {
      url: `https://github.com/${match[1]}/${repository}/${match[3]}.atom`,
      owner: match[1],
      repository,
    };
  };

  const fetchFeed = async (url, { force = false, hop = 0 } = {}) => {
    const cached = feedCache.get(url);
    const headers = {
      accept: 'application/atom+xml',
      'user-agent': 'Payloader-Repo-Monitor',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(!force && cached?.etag ? { 'if-none-match': cached.etag } : {}),
    };
    let response;
    try {
      response = await fetchImpl(url, {
        method: 'GET',
        headers,
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      if (error?.name === 'AbortError' || error?.name === 'TimeoutError') {
        throw new VersionCheckError('timeout', 'GitHub feed request timed out.');
      }
      throw new VersionCheckError('network-error', 'GitHub feed service is unavailable.');
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      response.body?.cancel().catch(() => {});
      if (hop >= maxFeedRedirects) {
        throw new VersionCheckError('too-many-redirects', 'GitHub feed redirect chain is too long.');
      }
      const target = feedRedirectTarget(url, response.headers.get('location'));
      const followed = await fetchFeed(target.url, { force, hop: hop + 1 });
      return followed.relocatedTo
        ? followed
        : { ...followed, relocatedTo: { owner: target.owner, repository: target.repository } };
    }
    if (response.status === 304) {
      if (!cached) throw new VersionCheckError('invalid-response', 'GitHub returned an unusable cache response.');
      return { entry: cached.value, relocatedTo: null };
    }
    if (response.status === 404) {
      response.body?.cancel().catch(() => {});
      return { entry: null, relocatedTo: null };
    }
    if (response.status === 403 || response.status === 429) {
      response.body?.cancel().catch(() => {});
      throw new VersionCheckError('rate-limited', 'GitHub feed requests are temporarily rate limited.');
    }
    if (!response.ok) {
      response.body?.cancel().catch(() => {});
      throw new VersionCheckError('github-error', `GitHub feed request failed with HTTP ${response.status}.`);
    }
    const value = parseAtomFeed(await readBoundedText(response, maxResponseBytes));
    const etag = response.headers.get('etag');
    if (etag) feedCache.set(url, { etag, value });
    else feedCache.delete(url);
    return { entry: value, relocatedTo: null };
  };

  const checkOne = async (subscription, { force = false } = {}) => {
    await initialize();
    const previous = statuses.get(subscription.id) || null;
    const checkedAt = new Date(now()).toISOString();
    statuses.set(subscription.id, { ...(previous || idleStatus(subscription.id)), state: 'checking', checkedAt, error: null });
    try {
      const [releaseResult, commitResult] = await Promise.all([
        fetchFeed(feedUrl(subscription, 'releases'), { force }).catch(error => ({ __error: error })),
        fetchFeed(feedUrl(subscription, 'commits'), { force }).catch(error => ({ __error: error })),
      ]);
      if (commitResult?.__error) throw commitResult.__error;
      const commitEntry = commitResult?.entry;
      if (!commitEntry) throw new VersionCheckError('not-found', '仓库不存在或为私有仓库。');
      const sha = commitShaFromEntryId(commitEntry.id);
      if (!sha) throw new VersionCheckError('invalid-response', 'GitHub returned an unusable commit feed.');

      // 仓库改名/转移：跟随重定向后把订阅更新到新位置（保留原 id 与预置标记）
      const relocatedTo = commitResult.relocatedTo || (releaseResult && !releaseResult.__error ? releaseResult.relocatedTo : null) || null;
      if (
        relocatedTo
        && (relocatedTo.owner !== subscription.owner || relocatedTo.repository !== subscription.repository)
      ) {
        subscription.owner = relocatedTo.owner;
        subscription.repository = relocatedTo.repository;
        await persistSubscriptions();
      }

      const releaseEntry = releaseResult && !releaseResult.__error ? releaseResult.entry : null;
      const release = releaseEntry
        ? {
          title: cleanText(releaseEntry.title, 200),
          tag: cleanText(releaseTagFromLink(releaseEntry.link), 128),
          updatedAt: isoOrNull(releaseEntry.updated),
          link: cleanText(releaseEntry.link, 300),
        }
        : null;
      const commit = {
        sha,
        shaShort: sha.slice(0, 12),
        message: cleanText(commitEntry.title, 240),
        author: cleanText(commitEntry.author, 80),
        committedAt: isoOrNull(commitEntry.updated),
        link: cleanText(commitEntry.link, 300),
      };
      const hadBaseline = Boolean(previous?.commit?.sha);
      const changed = hadBaseline
        && (previous.commit.sha !== sha || (previous.release?.tag || '') !== (release?.tag || ''));
      statuses.set(subscription.id, {
        id: subscription.id,
        state: 'checked',
        changed,
        release,
        commit,
        checkedAt,
        lastSuccessfulAt: checkedAt,
        error: null,
      });
    } catch (error) {
      statuses.set(subscription.id, {
        ...(previous || idleStatus(subscription.id)),
        id: subscription.id,
        state: 'error',
        checkedAt,
        error: publicError(error),
      });
    }
    // 检查期间订阅被移除：丢弃其状态，避免孤儿持久化
    if (!subscriptions.some(item => item.id === subscription.id)) statuses.delete(subscription.id);
    await persistStatuses();
    return safeClone(statuses.get(subscription.id) || idleStatus(subscription.id));
  };

  const checkNow = async (checkOptions = {}) => {
    await initialize();
    const targetId = typeof checkOptions.id === 'string' ? checkOptions.id : null;
    const force = checkOptions.force !== false;
    if (targetId) {
      const subscription = subscriptions.find(item => item.id === targetId);
      if (!subscription) throw new RepoMonitorError('not-found', '订阅不存在或已被移除。');
      const existing = inFlightById.get(targetId);
      if (existing) return { items: [listItem(subscription)] };
      const inFlight = checkOne(subscription, { force }).finally(() => inFlightById.delete(targetId));
      inFlightById.set(targetId, inFlight);
      await inFlight;
      return { items: [listItem(subscription)] };
    }

    const pending = subscriptions.filter(subscription => !inFlightById.has(subscription.id));
    let cursor = 0;
    const worker = async () => {
      while (cursor < pending.length) {
        const subscription = pending[cursor++];
        const inFlight = checkOne(subscription, { force }).finally(() => inFlightById.delete(subscription.id));
        inFlightById.set(subscription.id, inFlight);
        await inFlight;
      }
    };
    await Promise.all(Array.from({ length: Math.min(maxConcurrentFeedFetches, pending.length) }, worker));
    return { items: subscriptions.map(listItem) };
  };

  const listItem = subscription => ({
    ...subscription,
    githubUrl: `https://github.com/${subscription.owner}/${subscription.repository}`,
    status: safeClone(statuses.get(subscription.id) || idleStatus(subscription.id)),
  });

  const list = async () => {
    await initialize();
    return {
      items: subscriptions.map(listItem),
      nextCheckAt,
    };
  };

  const add = async ({ repository, note } = {}) => {
    await initialize();
    // 订阅上限：每周期 2N 个外发请求 + 批量检查 N 次全量状态写，无上限会自我 DoS
    if (subscriptions.length >= maxSubscriptions) {
      throw new RepoMonitorError('limit-reached', `订阅数量已达上限（${maxSubscriptions}），请先移除不再关注的仓库。`);
    }
    const parsed = parseRepositoryReference(repository);
    const duplicate = subscriptions.find(subscription =>
      subscription.owner.toLowerCase() === parsed.owner.toLowerCase()
      && subscription.repository.toLowerCase() === parsed.repository.toLowerCase());
    if (duplicate) {
      throw new RepoMonitorError('duplicate', `已在订阅列表中：${duplicate.owner}/${duplicate.repository}`);
    }
    // id 唯一性守卫：碰撞时回退自增计数后缀，保证有界终止（防同毫秒+弱随机源覆盖状态）
    let candidateId = `repo-${now().toString(36)}-${Math.floor(random() * 0xffffffff).toString(36).padStart(6, '0')}`;
    for (let attempt = 1; subscriptions.some(subscription => subscription.id === candidateId); attempt += 1) {
      candidateId = `repo-${now().toString(36)}-${attempt.toString(36)}`;
    }
    const subscription = {
      id: candidateId,
      owner: parsed.owner,
      repository: parsed.repository,
      note: cleanText(note, 120),
      preset: false,
      createdAt: new Date(now()).toISOString(),
    };
    subscriptions.push(subscription);
    await persistSubscriptions();
    return safeClone(listItem(subscription));
  };

  const remove = async id => {
    await initialize();
    const index = subscriptions.findIndex(subscription => subscription.id === id);
    if (index === -1) throw new RepoMonitorError('not-found', '订阅不存在或已被移除。');
    const [removed] = subscriptions.splice(index, 1);
    statuses.delete(removed.id);
    feedCache.delete(feedUrl(removed, 'releases'));
    feedCache.delete(feedUrl(removed, 'commits'));
    await Promise.all([persistSubscriptions(), persistStatuses()]);
    return { ok: true, removed: removed.id };
  };

  const jitteredInterval = () => Math.round(intervalMs * (0.95 + random() * 0.1));
  const schedule = delay => {
    if (stopped || scheduledDisabled) return;
    if (timer) clearTimer(timer);
    nextCheckAt = new Date(now() + delay).toISOString();
    timer = setTimer(() => {
      timer = null;
      void checkNow({ force: false }).finally(() => schedule(jitteredInterval()));
    }, delay);
    timer?.unref?.();
  };

  const start = async () => {
    stopped = false;
    await initialize();
    schedule(Math.max(0, initialDelayMs));
    return list();
  };

  const stop = () => {
    stopped = true;
    if (timer) clearTimer(timer);
    timer = null;
    nextCheckAt = null;
  };

  return Object.freeze({ start, stop, list, add, remove, checkNow });
};
