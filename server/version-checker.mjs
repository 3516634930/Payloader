import { execFile as execFileCallback } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import semver from 'semver';

const execFile = promisify(execFileCallback);
const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const packageFileUrl = new URL('../package.json', import.meta.url);

export const VERSION_STATUS_METADATA_KEY = 'github_version_status';
export const DEFAULT_UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
export const MIN_UPDATE_CHECK_INTERVAL_MS = 15 * 60 * 1000;
export const MAX_UPDATE_CHECK_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000;
const defaultInitialDelayMs = 30_000;
const defaultMaxResponseBytes = 512 * 1024;
const githubApiVersion = '2022-11-28';
const githubMediaType = 'application/vnd.github+json';
const versionPattern = /^v?(\d+)\.(\d+)(?:\.(\d+))?((?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;
const commitPattern = /^[0-9a-f]{7,64}$/i;

export class VersionCheckError extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'VersionCheckError';
    this.code = code;
    this.retryAt = options.retryAt || null;
  }
}

const safeClone = value => JSON.parse(JSON.stringify(value));
const shortenedCommit = value => commitPattern.test(String(value || '')) ? String(value).slice(0, 12) : '';
const cleanText = (value, maxLength) => String(value || '')
  .replace(/\p{Cc}/gu, character => '\t\n\r'.includes(character) ? character : '')
  .trim()
  .slice(0, maxLength);

export const parseGitHubRepository = value => {
  let parsed;
  try {
    parsed = new URL(String(value || ''));
  } catch {
    throw new Error('Invalid official GitHub repository URL.');
  }
  const segments = parsed.pathname.split('/').filter(Boolean);
  const owner = segments[0] || '';
  const repository = String(segments[1] || '').replace(/\.git$/i, '');
  if (
    parsed.protocol !== 'https:'
    || parsed.hostname.toLowerCase() !== 'github.com'
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || segments.length !== 2
    || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)
    || !/^[A-Za-z0-9._-]{1,100}$/.test(repository)
  ) {
    throw new Error('Invalid official GitHub repository URL.');
  }
  return {
    owner,
    repository,
    apiBaseUrl: `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}`,
  };
};

export const normalizeVersion = value => {
  const match = String(value || '').trim().match(versionPattern);
  if (!match) return null;
  const candidate = `${match[1]}.${match[2]}.${match[3] || '0'}${match[4] || ''}`;
  return semver.valid(candidate, { loose: false }) || null;
};

const stableVersion = value => {
  const normalized = normalizeVersion(value);
  return normalized && semver.prerelease(normalized) === null ? normalized : null;
};

export const selectStableCandidate = ({ release, tags, packageVersion }) => {
  const releaseVersion = !release?.draft && !release?.prerelease
    ? stableVersion(release?.tag_name)
    : null;
  if (releaseVersion) {
    return {
      version: releaseVersion,
      source: 'release',
      tagName: cleanText(release.tag_name, 128),
      notes: cleanText(release.body, 2_000),
      publishedAt: typeof release.published_at === 'string' ? release.published_at : null,
    };
  }

  const stableTags = (Array.isArray(tags) ? tags : [])
    .map(tag => ({ tag, version: stableVersion(tag?.name) }))
    .filter(item => item.version)
    .sort((left, right) => semver.rcompare(left.version, right.version));
  if (stableTags.length) {
    return {
      version: stableTags[0].version,
      source: 'tag',
      tagName: cleanText(stableTags[0].tag.name, 128),
      notes: '',
      publishedAt: null,
    };
  }

  const normalizedPackageVersion = stableVersion(packageVersion);
  return normalizedPackageVersion
    ? {
      version: normalizedPackageVersion,
      source: 'package',
      tagName: '',
      notes: '',
      publishedAt: null,
    }
    : null;
};

export const compareStableVersions = (currentVersion, remoteVersion) => {
  const current = stableVersion(currentVersion);
  const remote = stableVersion(remoteVersion);
  if (!current || !remote) return 'unknown';
  const comparison = semver.compare(current, remote);
  if (comparison < 0) return 'update-available';
  if (comparison > 0) return 'local-newer';
  return 'up-to-date';
};

const readBoundedText = async (response, maxBytes) => {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new VersionCheckError('response-too-large', 'GitHub returned an oversized version response.');
  }
  if (!response.body?.getReader) {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new VersionCheckError('response-too-large', 'GitHub returned an oversized version response.');
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new VersionCheckError('response-too-large', 'GitHub returned an oversized version response.');
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
};

const rateLimitFromHeaders = headers => {
  const parseHeaderNumber = name => {
    const value = headers.get(name);
    if (value === null || String(value).trim() === '') return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  };
  const limit = parseHeaderNumber('x-ratelimit-limit');
  const remaining = parseHeaderNumber('x-ratelimit-remaining');
  const resetSeconds = parseHeaderNumber('x-ratelimit-reset');
  return {
    limit,
    remaining,
    resetAt: resetSeconds !== null && resetSeconds > 0
      ? new Date(resetSeconds * 1000).toISOString()
      : null,
  };
};

export const createGitHubVersionSource = options => {
  const repository = parseGitHubRepository(options.repositoryUrl);
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const token = String(options.token || '').trim();
  const timeoutMs = Number(options.timeoutMs || 10_000);
  const maxResponseBytes = Number(options.maxResponseBytes || defaultMaxResponseBytes);
  const cache = new Map();
  let latestRateLimit = { limit: null, remaining: null, resetAt: null };

  const requestJson = async (path, requestOptions = {}) => {
    const accept = requestOptions.accept || githubMediaType;
    const cacheKey = `${accept}:${path}`;
    const cached = cache.get(cacheKey);
    const force = requestOptions.force === true;
    const headers = {
      accept,
      'user-agent': 'Payloader-Version-Checker',
      'x-github-api-version': githubApiVersion,
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(!force && cached?.etag ? { 'if-none-match': cached.etag } : {}),
    };
    let response;
    try {
      response = await fetchImpl(`${repository.apiBaseUrl}${path ? `/${path}` : ''}`, {
        method: 'GET',
        headers,
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      if (error?.name === 'AbortError' || error?.name === 'TimeoutError') {
        throw new VersionCheckError('timeout', 'GitHub version check timed out.');
      }
      throw new VersionCheckError('network-error', 'GitHub version service is unavailable.');
    }

    latestRateLimit = rateLimitFromHeaders(response.headers);
    if (response.status === 304) {
      if (!cached) throw new VersionCheckError('invalid-response', 'GitHub returned an unusable cache response.');
      return cached.value;
    }
    if (response.status === 404 && requestOptions.allowNotFound) return null;
    if (response.status === 403 || response.status === 429) {
      throw new VersionCheckError('rate-limited', 'GitHub version checks are temporarily rate limited.', {
        retryAt: latestRateLimit.resetAt,
      });
    }
    if (!response.ok) {
      throw new VersionCheckError('github-error', `GitHub version check failed with HTTP ${response.status}.`);
    }

    const text = await readBoundedText(response, maxResponseBytes);
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new VersionCheckError('invalid-response', 'GitHub returned invalid version metadata.');
    }
    const etag = response.headers.get('etag');
    if (etag) cache.set(cacheKey, { etag, value });
    return value;
  };

  const inspect = async ({ currentVersion, currentCommit, force = false }) => {
    const repositoryInfo = await requestJson('', { force });
    const branch = cleanText(repositoryInfo?.default_branch, 128);
    if (!branch) throw new VersionCheckError('invalid-response', 'GitHub repository metadata has no default branch.');

    const release = await requestJson('releases/latest', { allowNotFound: true, force });
    let tags = [];
    let packageVersion = null;
    if (!selectStableCandidate({ release, tags, packageVersion })) {
      tags = await requestJson('tags?per_page=100', { allowNotFound: true, force }) || [];
    }
    if (!selectStableCandidate({ release, tags, packageVersion })) {
      const packageMetadata = await requestJson('contents/package.json', {
        accept: 'application/vnd.github.raw+json',
        allowNotFound: true,
        force,
      });
      packageVersion = packageMetadata?.version || null;
    }
    const stable = selectStableCandidate({ release, tags, packageVersion });

    const branchReference = await requestJson(`git/ref/heads/${encodeURIComponent(branch)}`, { force });
    const branchTarget = branchReference?.object;
    const remoteCommit = branchTarget?.type === 'commit' && commitPattern.test(String(branchTarget.sha || ''))
      ? String(branchTarget.sha)
      : '';
    if (!remoteCommit) throw new VersionCheckError('invalid-response', 'GitHub returned invalid commit metadata.');
    const commitMetadata = await requestJson(`git/commits/${remoteCommit}`, { force });
    const normalizedCurrentCommit = commitPattern.test(String(currentCommit || '')) ? String(currentCommit) : '';
    let sourceState = 'unknown-local-commit';
    if (normalizedCurrentCommit === remoteCommit) {
      sourceState = 'synchronized';
    } else if (normalizedCurrentCommit) {
      const comparison = await requestJson(`compare/${encodeURIComponent(normalizedCurrentCommit)}...${encodeURIComponent(remoteCommit)}`, {
        allowNotFound: true,
        force,
      });
      sourceState = {
        identical: 'synchronized',
        ahead: 'remote-ahead',
        behind: 'local-ahead',
        diverged: 'diverged',
      }[comparison?.status] || 'unrelated';
    }

    const developmentMetadata = stable?.source === 'package' && stable.version === '0.0.0';
    return {
      stable: stable
        ? developmentMetadata
          ? {
            ...stable,
            version: null,
            state: 'unavailable',
            developmentMetadata: true,
          }
          : {
            ...stable,
            state: compareStableVersions(currentVersion, stable.version),
            developmentMetadata: false,
          }
        : {
          state: 'unavailable',
          version: null,
          source: null,
          tagName: '',
          notes: '',
          publishedAt: null,
          developmentMetadata: false,
        },
      source: {
        state: sourceState,
        branch,
        commit: remoteCommit,
        commitShort: shortenedCommit(remoteCommit),
        message: cleanText(commitMetadata?.message?.split(/\r?\n/, 1)[0], 240),
        committedAt: typeof commitMetadata?.author?.date === 'string'
          ? commitMetadata.author.date
          : null,
      },
      rateLimit: { ...latestRateLimit },
    };
  };

  return Object.freeze({ inspect });
};

const resolvePackageVersion = async () => {
  const metadata = JSON.parse(await readFile(packageFileUrl, 'utf8'));
  return metadata.version;
};

const resolveGitCommit = async ({ environment, execFileImpl, cwd }) => {
  const configured = String(environment.PAYLOADER_COMMIT_SHA || environment.GITHUB_SHA || '').trim();
  if (commitPattern.test(configured)) return configured;
  try {
    const result = await execFileImpl('git', ['rev-parse', 'HEAD'], {
      cwd,
      timeout: 2_000,
      windowsHide: true,
      maxBuffer: 16_384,
    });
    const commit = String(result?.stdout || '').trim();
    return commitPattern.test(commit) ? commit : '';
  } catch {
    return '';
  }
};

export const resolveInstalledIdentity = async (options = {}) => {
  const environment = options.environment || process.env;
  const configuredVersion = options.currentVersion ?? environment.PAYLOADER_VERSION;
  const packageVersion = configuredVersion || await resolvePackageVersion();
  const version = normalizeVersion(packageVersion) || cleanText(packageVersion, 64) || 'unknown';
  const commit = options.currentCommit !== undefined
    ? (commitPattern.test(String(options.currentCommit)) ? String(options.currentCommit) : '')
    : await resolveGitCommit({
      environment,
      execFileImpl: options.execFileImpl || execFile,
      cwd: options.cwd || rootDir,
    });
  return {
    version,
    commit,
    commitShort: shortenedCommit(commit),
  };
};

const validateInterval = value => {
  const interval = value === undefined || value === null || value === ''
    ? DEFAULT_UPDATE_CHECK_INTERVAL_MS
    : Number(value);
  if (!Number.isSafeInteger(interval) || interval < MIN_UPDATE_CHECK_INTERVAL_MS || interval > MAX_UPDATE_CHECK_INTERVAL_MS) {
    throw new Error(`PAYLOADER_UPDATE_CHECK_INTERVAL_MS must be an integer between ${MIN_UPDATE_CHECK_INTERVAL_MS} and ${MAX_UPDATE_CHECK_INTERVAL_MS}.`);
  }
  return interval;
};

const publicError = error => ({
  code: error instanceof VersionCheckError ? error.code : 'check-failed',
  message: error instanceof VersionCheckError ? error.message : 'Unable to check for Payloader updates.',
  retryAt: error instanceof VersionCheckError ? error.retryAt : null,
});

const defaultStatus = (installed, projectRoute) => ({
  state: 'idle',
  installed,
  stable: { state: 'unchecked', version: null, source: null },
  source: {
    state: installed.commit ? 'unchecked' : 'unknown-local-commit',
    branch: null,
    commit: null,
    commitShort: '',
  },
  checkedAt: null,
  lastSuccessfulAt: null,
  nextCheckAt: null,
  error: null,
  rateLimit: null,
  projectRoute,
});

const mergePersistedStatus = (base, persisted) => {
  if (!persisted || typeof persisted !== 'object' || Array.isArray(persisted)) return base;
  return {
    ...base,
    state: typeof persisted.state === 'string' ? persisted.state : base.state,
    stable: persisted.stable && typeof persisted.stable === 'object' ? persisted.stable : base.stable,
    source: persisted.source && typeof persisted.source === 'object' ? persisted.source : base.source,
    checkedAt: typeof persisted.checkedAt === 'string' ? persisted.checkedAt : null,
    lastSuccessfulAt: typeof persisted.lastSuccessfulAt === 'string' ? persisted.lastSuccessfulAt : null,
    error: persisted.error && typeof persisted.error === 'object' ? persisted.error : null,
    rateLimit: persisted.rateLimit && typeof persisted.rateLimit === 'object' ? persisted.rateLimit : null,
  };
};

const overallState = inspection => {
  if (inspection.stable.state === 'update-available') return 'update-available';
  if (inspection.source.state === 'remote-ahead' || inspection.source.state === 'diverged') return 'source-update-available';
  if (inspection.stable.state === 'local-newer') return 'local-newer';
  if (inspection.stable.state === 'up-to-date' && inspection.source.state === 'synchronized') return 'up-to-date';
  return 'checked';
};

export const createVersionChecker = options => {
  const environment = options.environment || process.env;
  const intervalMs = validateInterval(options.intervalMs ?? environment.PAYLOADER_UPDATE_CHECK_INTERVAL_MS);
  const initialDelayMs = Number(options.initialDelayMs ?? defaultInitialDelayMs);
  const scheduledDisabled = options.disabled ?? environment.PAYLOADER_UPDATE_CHECK_DISABLED === 'true';
  const loadStatus = options.loadStatus || (async () => '');
  const saveStatus = options.saveStatus || (async () => {});
  const setTimer = options.setTimer || setTimeout;
  const clearTimer = options.clearTimer || clearTimeout;
  const now = options.now || Date.now;
  const random = options.random || Math.random;
  const projectRoute = String(options.projectRoute || '');
  const versionSource = options.versionSource || createGitHubVersionSource({
    repositoryUrl: options.repositoryUrl,
    fetchImpl: options.fetchImpl,
    token: options.token ?? environment.PAYLOADER_GITHUB_TOKEN,
    timeoutMs: options.timeoutMs,
    maxResponseBytes: options.maxResponseBytes,
  });

  let initializedPromise;
  let installed;
  let status;
  let inFlight;
  let inFlightForce = false;
  let timer;
  let stopped = false;

  const initialize = () => {
    if (initializedPromise) return initializedPromise;
    initializedPromise = (async () => {
      installed = await resolveInstalledIdentity({
        environment,
        currentVersion: options.currentVersion,
        currentCommit: options.currentCommit,
        execFileImpl: options.execFileImpl,
        cwd: options.cwd,
      });
      const base = defaultStatus(installed, projectRoute);
      try {
        const stored = await loadStatus();
        const parsed = typeof stored === 'string' && stored ? JSON.parse(stored) : stored;
        status = mergePersistedStatus(base, parsed);
      } catch {
        status = base;
      }
      status.installed = installed;
      status.projectRoute = projectRoute;
      return status;
    })();
    return initializedPromise;
  };

  const persist = async () => {
    try {
      await saveStatus(JSON.stringify({ ...status, nextCheckAt: null }));
    } catch (error) {
      console.error('Unable to persist GitHub version status:', error);
    }
  };

  const checkNow = (checkOptions = {}) => {
    const force = checkOptions.force === true;
    if (inFlight) {
      if (!force || inFlightForce) return inFlight;
      return inFlight.then(() => checkNow({ force: true }));
    }
    inFlightForce = force;
    inFlight = (async () => {
      await initialize();
      const checkedAt = new Date(now()).toISOString();
      status = { ...status, state: 'checking', checkedAt, error: null };
      try {
        const inspection = await versionSource.inspect({
          currentVersion: installed.version,
          currentCommit: installed.commit,
          ...(force ? { force: true } : {}),
        });
        status = {
          ...status,
          ...inspection,
          state: overallState(inspection),
          installed,
          checkedAt,
          lastSuccessfulAt: checkedAt,
          error: null,
          projectRoute,
        };
      } catch (error) {
        status = {
          ...status,
          state: 'error',
          installed,
          checkedAt,
          error: publicError(error),
          projectRoute,
        };
      }
      await persist();
      return safeClone(status);
    })().finally(() => {
      inFlight = null;
      inFlightForce = false;
    });
    return inFlight;
  };

  const jitteredInterval = () => Math.round(intervalMs * (0.95 + random() * 0.1));
  const schedule = delay => {
    if (stopped || scheduledDisabled) return;
    if (timer) clearTimer(timer);
    status.nextCheckAt = new Date(now() + delay).toISOString();
    timer = setTimer(() => {
      timer = null;
      void checkNow().finally(() => schedule(jitteredInterval()));
    }, delay);
    timer?.unref?.();
  };

  const start = async () => {
    stopped = false;
    await initialize();
    schedule(Math.max(0, initialDelayMs));
    return safeClone(status);
  };

  const stop = () => {
    stopped = true;
    if (timer) clearTimer(timer);
    timer = null;
    if (status) status.nextCheckAt = null;
  };

  const getStatus = async () => {
    await initialize();
    return safeClone(status);
  };

  return Object.freeze({ start, stop, getStatus, checkNow });
};
