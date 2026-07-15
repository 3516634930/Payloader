import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream, statSync } from 'node:fs';
import { copyFile, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getPublicData } from './data-store.mjs';
import {
  CLIENT_BUILD_CONTRACT_VERSION,
  writeClientDeploymentPackage,
} from './client-deployment-package.mjs';
import {
  acquireClientShellArchive,
  assembleClientShell,
  loadClientShellCatalog,
  pruneClientShellCache,
  validateClientShellManifest,
} from './client-shells.mjs';
import { clientProjectRoute, officialProjectUrl, publicProjectRoute } from './project-attribution.mjs';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const serverDir = join(rootDir, 'server');
const distDir = join(rootDir, 'dist');
const dataDir = resolve(process.env.PAYLOADER_DATA_DIR || join(rootDir, 'data'));
const uploadDir = join(dataDir, 'uploads');
const buildRoot = process.env.PAYLOADER_CLIENT_BUILD_ROOT
  ? resolve(process.env.PAYLOADER_CLIENT_BUILD_ROOT)
  : join(dataDir, 'client-builds');
const tmpRoot = process.env.PAYLOADER_CLIENT_TMP_ROOT
  ? resolve(process.env.PAYLOADER_CLIENT_TMP_ROOT)
  : join(tmpdir(), 'payloader-client-builds');
const clientCacheRoot = process.env.PAYLOADER_CLIENT_CACHE_DIR
  ? resolve(process.env.PAYLOADER_CLIENT_CACHE_DIR)
  : join(buildRoot, '.builder-cache');
const latestFile = join(buildRoot, 'latest.json');
const lastFailureFile = join(buildRoot, 'last-failure.json');
const clientShellCatalogFile = join(clientCacheRoot, 'shell-catalog.json');
const electronMainTemplate = join(serverDir, 'client-electron-main.cjs');
const clientDeploymentRuntimeSource = join(serverDir, 'client-deployment-runtime.cjs');
const projectAttributionSource = join(serverDir, 'project-attribution.cjs');
const clientInstallerIncludeSource = join(serverDir, 'client-installer.nsh');
const clientBuilderSource = join(serverDir, 'client-builder.mjs');
const projectPackageJson = join(rootDir, 'package.json');
const tscCli = join(rootDir, 'node_modules', 'typescript', 'bin', 'tsc');
const viteCli = join(rootDir, 'node_modules', 'vite', 'bin', 'vite.js');
const electronBuilderCli = join(rootDir, 'node_modules', 'electron-builder', 'cli.js');
const electronPackageJson = join(rootDir, 'node_modules', 'electron', 'package.json');
const electronRuntimeDir = join(rootDir, 'node_modules', 'electron', 'dist');
const electronRuntimeConfig = (runtimeDir, enabled = true) => {
  if (!enabled) return {};
  const stats = statSync(runtimeDir, { throwIfNoEntry: false });
  return stats?.isDirectory() ? { electronDist: runtimeDir } : {};
};
const immutableProductionRuntime = process.env.NODE_ENV === 'production';
const productName = 'Payloader';
const copyright = 'Copyright (c) Payloader';
const pathSeparator = sep;
const protectedXeyeUrl = 'https://xss.icu/';
const protectedXssToolId = 'xss-platform';
const configuredElectronMirror = String(process.env.PAYLOADER_ELECTRON_MIRROR || process.env.ELECTRON_MIRROR || '').trim();
const configuredBuilderBinariesMirror = String(process.env.PAYLOADER_ELECTRON_BUILDER_BINARIES_MIRROR
  || process.env.ELECTRON_BUILDER_BINARIES_MIRROR
  || '').trim();
const configuredClientShellDirectory = String(process.env.PAYLOADER_CLIENT_SHELL_DIR || '').trim();
const remoteClientShellsDisabled = process.env.PAYLOADER_CLIENT_SHELLS_REMOTE_DISABLED === 'true';
const clientRuntime = 'electron-offline-client';
const clientDistribution = 'multi-platform-desktop-client';
const clientBuildContractVersion = CLIENT_BUILD_CONTRACT_VERSION;
const clientMetadataVersion = 3;
const configuredFreshnessCacheTtlMs = Number(process.env.PAYLOADER_CLIENT_FRESHNESS_CACHE_MS);
const freshnessCacheTtlMs = Number.isFinite(configuredFreshnessCacheTtlMs)
  ? Math.min(15_000, Math.max(5_000, configuredFreshnessCacheTtlMs))
  : 10_000;
const clientNetworkPolicy = Object.freeze({
  offline: true,
  internalOrigin: 'payloader://app',
  blockedSchemes: ['http:', 'https:', 'ws:', 'wss:', 'file:', 'ftp:', 'data:', 'blob:'],
  allowedExternalLinks: [clientProjectRoute, protectedXeyeUrl],
  note: 'The packaged client serves a static public snapshot from payloader://app and blocks renderer network requests. Only fixed user-click external links may be opened by the OS browser.',
});
const clientPerformancePolicy = Object.freeze({
  lazyPublicDataSnapshot: true,
  streamsPublicDataSnapshot: true,
  boundsMainProcessAssetCache: true,
  backgroundThrottling: true,
  singleInstance: true,
  skipsPackagedBuildPolling: true,
  streamingArtifactHashes: true,
  windowsSoftwareRendering: true,
  windowsInstallerCompression: '7z',
  windowsInstallerPerUser: true,
  reusesInstalledElectronRuntimeWhenAvailable: true,
  electronLanguages: Object.freeze(['zh-CN', 'en-US']),
  windows: Object.freeze({
    windowReadyMs: 1500,
    searchSettledMs: 350,
    idleWorkingSetMb: 500,
    interactionWorkingSetMb: 560,
    privateMemoryMb: 450,
    privateMemoryGrowthMb: 80,
    idleCpuPercentOneCore: 2,
  }),
  linux: Object.freeze({
    windowReadyMs: 2500,
    searchSettledMs: 350,
    idleWorkingSetMb: 600,
    interactionWorkingSetMb: 675,
    idleCpuPercentOneCore: 5,
  }),
  macos: Object.freeze({
    windowReadyMs: 2500,
    searchSettledMs: 350,
    idleWorkingSetMb: 600,
    interactionWorkingSetMb: 675,
    idleCpuPercentOneCore: 5,
  }),
  packageCompression: 'normal',
  appImageCompression: 'gzip',
  debCompression: 'gz',
  rpmCompression: 'gzip',
  runInstallerLaunchAfterFinish: false,
  note: 'The desktop client streams large snapshots and static assets instead of retaining duplicate buffers in the main process, throttles background rendering, prevents duplicate instances, skips packaged build polling, and streams artifact hashing.',
});
const clientSecurityPolicy = Object.freeze({
  noAutoStart: true,
  noUpdater: true,
  noPersistenceHooks: true,
  noShellInjection: true,
  codeSigningRecommended: true,
  integrityHashes: true,
  note: 'False-positive reduction is handled through code signing, stable metadata, transparent artifact hashes, least privilege, and a locked offline network policy. Project attribution uses a narrow authenticated-encryption module; executable packing, security-software evasion, injection, and stealth behavior are not added.',
});
const windowsNsisOptions = Object.freeze({
  oneClick: false,
  perMachine: false,
  allowElevation: false,
  allowToChangeInstallationDirectory: true,
  packElevateHelper: false,
  differentialPackage: false,
  useZip: false,
  include: 'installer.nsh',
  createDesktopShortcut: true,
  createStartMenuShortcut: true,
  runAfterFinish: false,
  deleteAppDataOnUninstall: false,
  artifactName: 'Payloader-Client-Setup-${version}-${arch}.${ext}',
});
const crossPlatformOverride = process.env.PAYLOADER_CLIENT_FORCE_CROSS_PLATFORM === 'true';
const clientTargetMatrix = Object.freeze([
  {
    id: 'win-x64-nsis',
    platform: 'windows',
    platformLabel: 'Windows',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'Windows Installer',
    extension: '.exe',
    builderPlatform: 'win',
    builderTargets: ['nsis'],
    builderArch: 'x64',
    mimeType: 'application/vnd.microsoft.portable-executable',
    hostPlatforms: ['win32'],
    recommended: true,
    cpuFamily: 'x86_64',
    minOsVersion: 'Windows 10/11 64-bit',
    installType: 'Assisted NSIS installer with custom directory',
  },
  {
    id: 'win-arm64-nsis',
    platform: 'windows',
    platformLabel: 'Windows',
    arch: 'arm64',
    archLabel: 'ARM64',
    format: 'Windows Installer',
    extension: '.exe',
    builderPlatform: 'win',
    builderTargets: ['nsis'],
    builderArch: 'arm64',
    mimeType: 'application/vnd.microsoft.portable-executable',
    hostPlatforms: ['win32'],
    recommended: true,
    cpuFamily: 'ARM64',
    minOsVersion: 'Windows 11 ARM64',
    installType: 'Assisted NSIS installer with custom directory',
  },
  {
    id: 'win-ia32-nsis',
    platform: 'windows',
    platformLabel: 'Windows',
    arch: 'ia32',
    archLabel: '32-bit x86',
    format: 'Windows Installer',
    extension: '.exe',
    builderPlatform: 'win',
    builderTargets: ['nsis'],
    builderArch: 'ia32',
    mimeType: 'application/vnd.microsoft.portable-executable',
    hostPlatforms: ['win32'],
    recommended: false,
    cpuFamily: 'x86 32-bit',
    minOsVersion: 'Windows 10 32-bit',
    installType: 'Assisted NSIS installer with custom directory',
  },
  {
    id: 'linux-x64-appimage',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'AppImage',
    extension: '.AppImage',
    builderPlatform: 'linux',
    builderTargets: ['AppImage'],
    builderArch: 'x64',
    mimeType: 'application/octet-stream',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'x86_64',
    minOsVersion: 'glibc-based Linux x64',
    installType: 'Portable AppImage',
  },
  {
    id: 'linux-arm64-appimage',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'arm64',
    archLabel: 'ARM64',
    format: 'AppImage',
    extension: '.AppImage',
    builderPlatform: 'linux',
    builderTargets: ['AppImage'],
    builderArch: 'arm64',
    mimeType: 'application/octet-stream',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'ARM64 / aarch64',
    minOsVersion: 'glibc-based Linux ARM64',
    installType: 'Portable AppImage',
  },
  {
    id: 'linux-armv7l-appimage',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'armv7l',
    archLabel: 'ARMv7 / armhf',
    format: 'AppImage',
    extension: '.AppImage',
    builderPlatform: 'linux',
    builderTargets: ['AppImage'],
    builderArch: 'armv7l',
    mimeType: 'application/octet-stream',
    hostPlatforms: ['linux'],
    recommended: false,
    cpuFamily: 'ARMv7 / armhf',
    minOsVersion: 'glibc-based Linux ARMv7',
    installType: 'Portable AppImage',
  },
  {
    id: 'linux-x64-deb',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'DEB',
    extension: '.deb',
    builderPlatform: 'linux',
    builderTargets: ['deb'],
    builderArch: 'x64',
    mimeType: 'application/vnd.debian.binary-package',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'x86_64',
    minOsVersion: 'Debian/Ubuntu x64',
    installType: 'dpkg/apt package',
    packageManager: 'dpkg / apt',
  },
  {
    id: 'linux-arm64-deb',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'arm64',
    archLabel: 'ARM64',
    format: 'DEB',
    extension: '.deb',
    builderPlatform: 'linux',
    builderTargets: ['deb'],
    builderArch: 'arm64',
    mimeType: 'application/vnd.debian.binary-package',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'ARM64 / aarch64',
    minOsVersion: 'Debian/Ubuntu ARM64',
    installType: 'dpkg/apt package',
    packageManager: 'dpkg / apt',
  },
  {
    id: 'linux-armv7l-deb',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'armv7l',
    archLabel: 'ARMv7 / armhf',
    format: 'DEB',
    extension: '.deb',
    builderPlatform: 'linux',
    builderTargets: ['deb'],
    builderArch: 'armv7l',
    mimeType: 'application/vnd.debian.binary-package',
    hostPlatforms: ['linux'],
    recommended: false,
    cpuFamily: 'ARMv7 / armhf',
    minOsVersion: 'Debian/Ubuntu armhf',
    installType: 'dpkg/apt package',
    packageManager: 'dpkg / apt',
  },
  {
    id: 'linux-x64-rpm',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'RPM',
    extension: '.rpm',
    builderPlatform: 'linux',
    builderTargets: ['rpm'],
    builderArch: 'x64',
    mimeType: 'application/x-rpm',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'x86_64',
    minOsVersion: 'Fedora/RHEL x64',
    installType: 'rpm/dnf package',
    packageManager: 'rpm / dnf',
  },
  {
    id: 'linux-arm64-rpm',
    platform: 'linux',
    platformLabel: 'Linux',
    arch: 'arm64',
    archLabel: 'ARM64',
    format: 'RPM',
    extension: '.rpm',
    builderPlatform: 'linux',
    builderTargets: ['rpm'],
    builderArch: 'arm64',
    mimeType: 'application/x-rpm',
    hostPlatforms: ['linux'],
    recommended: true,
    cpuFamily: 'ARM64 / aarch64',
    minOsVersion: 'Fedora/RHEL ARM64',
    installType: 'rpm/dnf package',
    packageManager: 'rpm / dnf',
  },
  {
    id: 'mac-x64-dmg',
    platform: 'macos',
    platformLabel: 'macOS',
    arch: 'x64',
    archLabel: 'Intel 64-bit',
    format: 'DMG',
    extension: '.dmg',
    builderPlatform: 'mac',
    builderTargets: ['dmg'],
    builderArch: 'x64',
    mimeType: 'application/x-apple-diskimage',
    hostPlatforms: ['darwin'],
    recommended: true,
    requiresSigningNote: 'macOS distribution should be signed and notarized on a macOS host.',
    cpuFamily: 'x86_64',
    minOsVersion: 'macOS Intel',
    installType: 'DMG disk image',
  },
  {
    id: 'mac-arm64-dmg',
    platform: 'macos',
    platformLabel: 'macOS',
    arch: 'arm64',
    archLabel: 'Apple Silicon',
    format: 'DMG',
    extension: '.dmg',
    builderPlatform: 'mac',
    builderTargets: ['dmg'],
    builderArch: 'arm64',
    mimeType: 'application/x-apple-diskimage',
    hostPlatforms: ['darwin'],
    recommended: true,
    requiresSigningNote: 'macOS distribution should be signed and notarized on a macOS host.',
    cpuFamily: 'Apple Silicon ARM64',
    minOsVersion: 'macOS Apple Silicon',
    installType: 'DMG disk image',
  },
  {
    id: 'mac-universal-dmg',
    platform: 'macos',
    platformLabel: 'macOS',
    arch: 'universal',
    archLabel: 'Universal',
    format: 'DMG',
    extension: '.dmg',
    builderPlatform: 'mac',
    builderTargets: ['dmg'],
    builderArch: 'universal',
    mimeType: 'application/x-apple-diskimage',
    hostPlatforms: ['darwin'],
    recommended: true,
    requiresSigningNote: 'macOS universal DMG should be signed and notarized on a macOS host after x64 and arm64 validation.',
    cpuFamily: 'Intel + Apple Silicon',
    minOsVersion: 'macOS Universal',
    installType: 'Universal DMG disk image',
  },
]);
const clientTargetById = new Map(clientTargetMatrix.map(target => [target.id, target]));
const clientTargetOrder = new Map(clientTargetMatrix.map((target, index) => [target.id, index]));

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8',
};
const downloadMimeTypes = {
  '.exe': 'application/vnd.microsoft.portable-executable',
  '.AppImage': 'application/octet-stream',
  '.appimage': 'application/octet-stream',
  '.dmg': 'application/x-apple-diskimage',
  '.zip': 'application/zip',
  '.gz': 'application/gzip',
  '.deb': 'application/vnd.debian.binary-package',
  '.rpm': 'application/x-rpm',
};

let currentJob = null;
let freshnessCache = null;
let freshnessHashProvider = null;
let shellCatalogCache = null;
let shellCatalogProvider = null;
let initialArtifactPrunePromise = null;

const now = () => new Date().toISOString();
const hashValue = value => createHash('sha256').update(value).digest('hex');
const hashFile = filePath => new Promise((resolveHash, rejectHash) => {
  const hash = createHash('sha256');
  const stream = createReadStream(filePath);
  stream.on('data', chunk => hash.update(chunk));
  stream.on('error', rejectHash);
  stream.on('end', () => resolveHash(hash.digest('hex')));
});
const publicDataStats = data => ({
  payloads: Array.isArray(data.payloads) ? data.payloads.length : 0,
  tools: Array.isArray(data.tools) ? data.tools.length : 0,
  navigation: Array.isArray(data.navigation) ? data.navigation.length : 0,
  toolNavigation: Array.isArray(data.toolNavigation) ? data.toolNavigation.length : 0,
});

const toPublicUrl = filePath => `/${filePath.split(/[\\/]+/).map(encodeURIComponent).join('/')}`;

const isInside = (baseDir, target) => {
  const fromBase = relative(baseDir, target);
  return fromBase && fromBase !== '..' && !fromBase.startsWith(`..${pathSeparator}`) && !isAbsolute(fromBase);
};

const shellTarget = (catalog, target) => catalog?.targets?.[target.id] || null;

const normalizeTargetAvailability = (target, catalog = null) => {
  const shell = shellTarget(catalog, target);
  const nativeSupported = crossPlatformOverride || target.hostPlatforms.includes(process.platform);
  const supported = Boolean(shell) || nativeSupported;
  let reason = '';
  if (!supported) {
    reason = catalog?.error ? '官方壳不可用' : '缺少兼容壳或本机工具链';
  }
  const portable = shell
    ? shell.outputFormat === 'zip'
      ? { format: 'Portable ZIP', extension: '.zip', installType: 'Portable directory', mimeType: 'application/zip' }
      : { format: 'Portable TAR.GZ', extension: '.tar.gz', installType: 'Portable directory', mimeType: 'application/gzip' }
    : null;
  return {
    id: target.id,
    platform: target.platform,
    platformLabel: target.platformLabel,
    arch: target.arch,
    archLabel: target.archLabel,
    format: portable?.format || target.format,
    extension: portable?.extension || target.extension,
    recommended: target.recommended,
    supported,
    selectedByDefault: supported && target.recommended !== false,
    reason,
    source: shell ? 'official-shell' : nativeSupported ? 'native-host' : 'unavailable',
    shellVersion: shell ? String(catalog?.manifest?.appVersion || '') : '',
    shellSigned: shell ? Boolean(shell.signed) : false,
    cpuFamily: target.cpuFamily || target.archLabel,
    minOsVersion: target.minOsVersion || '',
    installType: portable?.installType || target.installType || target.format,
    packageManager: portable ? '' : target.packageManager || '',
    mimeType: portable?.mimeType || target.mimeType,
    requiresSigningNote: target.requiresSigningNote || '',
  };
};

const defaultTargetIds = catalog => clientTargetMatrix
  .filter(target => normalizeTargetAvailability(target, catalog).supported && target.recommended !== false)
  .map(target => target.id);

const normalizeRequestedTargets = (value, catalog = null) => {
  const requested = Array.isArray(value) ? value.map(item => String(item || '').trim()) : [];
  const ids = requested.length ? requested : defaultTargetIds(catalog);
  const seen = new Set();
  const selected = [];
  const skipped = [];
  for (const id of ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    const target = clientTargetById.get(id);
    if (!target) {
      skipped.push({ id, status: 'unsupported', reason: 'Unknown client target.' });
      continue;
    }
    if (!normalizeTargetAvailability(target, catalog).supported) {
      skipped.push({
        id,
        status: 'unsupported',
        reason: normalizeTargetAvailability(target, catalog).reason,
      });
      continue;
    }
    selected.push(target);
  }
  return { selected, skipped };
};

const sanitizeFileName = value => {
  const fileName = basename(String(value || ''));
  return /^Payloader-Client-\d{8}-\d{6}-[a-f0-9]{8}-(win|linux|mac)-[a-z0-9]+-[a-z0-9-]+(?:\.[A-Za-z0-9]+)+$/i.test(fileName)
    || /^Payloader-Client-\d{8}-\d{6}-[a-f0-9]{8}\.exe$/i.test(fileName)
    ? fileName
    : '';
};

const readJsonFile = async (filePath, fallback) => {
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch {
    return fallback;
  }
};

const writeJsonFile = async (filePath, value) => {
  const parentDir = dirname(filePath);
  const temporaryFile = join(parentDir, `.${basename(filePath)}.${process.pid}.${randomUUID()}.tmp`);
  await mkdir(parentDir, { recursive: true });
  try {
    await writeFile(temporaryFile, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
    await rename(temporaryFile, filePath);
  } finally {
    await rm(temporaryFile, { force: true }).catch(() => {});
  }
};

const unavailableShellCatalog = error => ({
  source: 'unavailable',
  manifest: null,
  targets: {},
  error: error instanceof Error ? error.message : String(error || 'Official client shells are unavailable.'),
});

const readCachedShellCatalog = async () => {
  const cached = await readJsonFile(clientShellCatalogFile, null);
  if (!cached?.catalog?.manifest || !cached?.catalog?.targets) return null;
  try {
    const packageInfo = await readJsonFile(projectPackageJson, {});
    validateClientShellManifest(cached.catalog.manifest, {
      buildContractVersion: clientBuildContractVersion,
      appVersion: packageInfo.version,
    });
    return {
      ...cached.catalog,
      source: 'github-release-cache',
      cachedAt: cached.cachedAt || '',
    };
  } catch {
    return null;
  }
};

const loadShellCatalog = async (options = {}) => {
  if (shellCatalogProvider) return shellCatalogProvider();
  const currentTime = Date.now();
  if (!options.force && shellCatalogCache?.expiresAt > currentTime) return shellCatalogCache.promise;
  const promise = (async () => {
    if (remoteClientShellsDisabled && !configuredClientShellDirectory) {
      return unavailableShellCatalog('Official client shell checks are disabled.');
    }
    try {
      const packageInfo = await readJsonFile(projectPackageJson, {});
      const catalog = await loadClientShellCatalog({
        localDirectory: configuredClientShellDirectory,
        repositoryUrl: officialProjectUrl,
        token: process.env.PAYLOADER_GITHUB_TOKEN,
        timeoutMs: 8_000,
        buildContractVersion: clientBuildContractVersion,
        appVersion: packageInfo.version,
      });
      if (catalog.source === 'github-release') {
        await writeJsonFile(clientShellCatalogFile, { cachedAt: now(), catalog });
      }
      return catalog;
    } catch (error) {
      const cached = configuredClientShellDirectory ? null : await readCachedShellCatalog();
      return cached ? { ...cached, error: error.message } : unavailableShellCatalog(error);
    }
  })();
  shellCatalogCache = {
    promise,
    expiresAt: currentTime + (configuredClientShellDirectory ? 60_000 : 5 * 60_000),
  };
  return promise;
};

const artifactPlatformPrefix = target => target.platform === 'macos' ? 'mac' : target.platform === 'windows' ? 'win' : target.platform;

const artifactFileName = (target, stamp, buildId) => (
  `Payloader-Client-${stamp}-${buildId.slice(0, 8)}-${artifactPlatformPrefix(target)}-${target.arch}-${target.builderTargets[0].toLowerCase()}${target.extension}`
);

const portableArtifactFileName = (target, shell, stamp, buildId) => (
  `Payloader-Client-${stamp}-${buildId.slice(0, 8)}-${artifactPlatformPrefix(target)}-${target.arch}-portable${shell.outputFormat === 'zip' ? '.zip' : '.tar.gz'}`
);

const artifactScore = item => {
  const platform = String(item?.platform || '');
  const arch = String(item?.arch || '');
  const targetRank = clientTargetOrder.get(String(item?.targetId || ''));
  if (typeof targetRank === 'number') return targetRank;
  if (platform === 'windows' && arch === 'x64') return 0;
  if (platform === 'windows' && arch === 'arm64') return 1;
  if (platform === 'windows' && arch === 'ia32') return 2;
  if (platform === 'macos' && arch === 'universal') return 3;
  if (platform === 'macos' && arch === 'arm64') return 4;
  if (platform === 'macos' && arch === 'x64') return 5;
  if (platform === 'linux' && arch === 'x64') return 6;
  if (platform === 'linux' && arch === 'arm64') return 7;
  if (platform === 'linux' && arch === 'armv7l') return 8;
  return 999;
};

const displayArtifactFormat = (value, fallback) => {
  const format = String(value || fallback || '').trim();
  return format === 'NSIS EXE' ? 'Windows Installer' : format;
};

const normalizeArtifact = item => {
  if (!item || typeof item !== 'object' || !item.fileName) return null;
  if (item.status && item.status !== 'success') return null;
  const target = clientTargetById.get(item.targetId) || {};
  const fileName = sanitizeFileName(item.fileName);
  if (!fileName) return null;
  const extension = extname(fileName);
  return {
    targetId: item.targetId || '',
    platform: item.platform || target.platform || 'windows',
    platformLabel: item.platformLabel || target.platformLabel || 'Windows',
    arch: item.arch || target.arch || 'x64',
    archLabel: item.archLabel || target.archLabel || 'Intel / AMD 64-bit',
    format: displayArtifactFormat(item.format, target.format || 'Windows Installer'),
    fileName,
    size: Number(item.size || 0),
    sha256: typeof item.sha256 === 'string' ? item.sha256 : '',
    generatedAt: item.generatedAt || item.finishedAt || item.startedAt || '',
    runtime: item.runtime || clientRuntime,
    distribution: item.distribution || clientDistribution,
    buildContractVersion: Number(item.buildContractVersion || 0),
    codeSigningConfigured: Boolean(item.codeSigningConfigured),
    signingStatus: item.signingStatus || (item.codeSigningConfigured ? 'configured' : 'unsigned'),
    mimeType: item.mimeType || downloadMimeTypes[extension] || 'application/octet-stream',
    downloadUrl: item.downloadUrl || `/api/client-build/download/${encodeURIComponent(fileName)}`,
    cpuFamily: item.cpuFamily || target.cpuFamily || target.archLabel || '',
    minOsVersion: item.minOsVersion || target.minOsVersion || '',
    installType: item.installType || target.installType || item.format || '',
    packageManager: item.packageManager || target.packageManager || '',
    buildSource: item.buildSource || 'native-host',
    shellVersion: item.shellVersion || '',
    shellSha256: item.shellSha256 || '',
    performanceNotes: Array.isArray(item.performanceNotes) ? item.performanceNotes : [],
    securityNotes: Array.isArray(item.securityNotes) ? item.securityNotes : [],
    notes: Array.isArray(item.notes) ? item.notes : [],
  };
};

const normalizeMetadata = metadata => {
  if (!metadata || typeof metadata !== 'object') return null;
  const rawItems = Array.isArray(metadata.items)
    ? metadata.items.length
      ? metadata.items
      : Array.isArray(metadata.targetResults)
        ? metadata.targetResults
            .filter(item => item && item.status === 'success' && item.fileName)
            .map(item => {
              const target = clientTargetById.get(item.id) || {};
              return {
                targetId: item.id || '',
                platform: target.platform || 'windows',
                platformLabel: target.platformLabel || 'Windows',
                arch: target.arch || 'x64',
                archLabel: target.archLabel || 'Intel / AMD 64-bit',
                format: target.format || 'Windows Installer',
                fileName: item.fileName,
                size: item.size || 0,
                sha256: item.sha256 || '',
                generatedAt: metadata.finishedAt || metadata.startedAt || '',
                runtime: metadata.runtime,
                distribution: metadata.distribution,
                buildContractVersion: metadata.buildContractVersion,
                codeSigningConfigured: metadata.codeSigningConfigured,
                signingStatus: metadata.codeSigningConfigured ? 'configured' : 'unsigned',
                cpuFamily: target.cpuFamily || '',
                minOsVersion: target.minOsVersion || '',
                installType: target.installType || target.format || '',
                packageManager: target.packageManager || '',
              };
            })
        : metadata.items
    : metadata.status === 'success' && metadata.fileName
      ? [{
          targetId: 'win-x64-nsis',
          platform: 'windows',
          platformLabel: 'Windows',
          arch: 'x64',
          archLabel: 'Intel / AMD 64-bit',
          format: 'Windows Installer',
          fileName: metadata.fileName,
          size: metadata.size,
          sha256: metadata.sha256,
          generatedAt: metadata.finishedAt || metadata.startedAt,
          runtime: metadata.runtime,
          distribution: metadata.distribution,
          buildContractVersion: metadata.buildContractVersion,
          codeSigningConfigured: metadata.codeSigningConfigured,
          signingStatus: metadata.codeSigningConfigured ? 'configured' : 'unsigned',
        }]
      : [];
  const items = rawItems.map(normalizeArtifact).filter(Boolean).sort((a, b) => artifactScore(a) - artifactScore(b));
  const latest = normalizeArtifact(metadata.latest) || items[0] || null;
  const defaultSuccessMessage = items.length
    ? `Ready to download ${items.length} client build${items.length === 1 ? '' : 's'}`
    : 'Build completed without recognized artifacts';
  return {
    ...metadata,
    metadataVersion: metadata.metadataVersion || (items.length ? clientMetadataVersion : 1),
    status: metadata.status || (items.length ? 'success' : 'idle'),
    message: metadata.status === 'success'
      ? (items.length
          ? (/Ready to download 0 client builds/i.test(String(metadata.message || ''))
              ? defaultSuccessMessage
              : String(metadata.message || defaultSuccessMessage))
          : String(metadata.message || defaultSuccessMessage))
      : metadata.message,
    latest,
    items,
  };
};

const metadataMatchesCurrentContract = metadata => (
  Boolean(metadata) &&
  metadata.status === 'success' &&
  metadata.buildContractVersion === clientBuildContractVersion &&
  metadata.runtime === clientRuntime &&
  metadata.distribution === clientDistribution
);

const normalizeSuccessfulMetadata = metadata => {
  const normalized = normalizeMetadata(metadata);
  return normalized?.status === 'success' ? normalized : null;
};

const normalizeFailureMetadata = metadata => {
  if (!metadata || typeof metadata !== 'object' || metadata.status !== 'failed') return null;
  return {
    ...metadata,
    status: 'failed',
    message: String(metadata.message || 'Build failed'),
    selectedTargets: Array.isArray(metadata.selectedTargets) ? metadata.selectedTargets : [],
    skippedTargets: Array.isArray(metadata.skippedTargets) ? metadata.skippedTargets : [],
    logs: Array.isArray(metadata.logs) ? metadata.logs.filter(Boolean).slice(-12) : [],
  };
};

const metadataTimestamp = metadata => {
  const timestamp = Date.parse(metadata?.reusedAt || metadata?.finishedAt || metadata?.startedAt || '');
  return Number.isFinite(timestamp) ? timestamp : null;
};

const failureAfterLatestSuccess = (failure, latest) => {
  if (!failure || !latest) return failure;
  const failureTimestamp = metadataTimestamp(failure);
  const successTimestamp = metadataTimestamp(latest);
  if (failureTimestamp !== null && successTimestamp !== null && failureTimestamp <= successTimestamp) {
    return null;
  }
  return failure;
};

const readStoredBuildState = async () => {
  const [latestRaw, lastFailureRaw] = await Promise.all([
    readJsonFile(latestFile, null),
    readJsonFile(lastFailureFile, null),
  ]);
  const latest = normalizeSuccessfulMetadata(latestRaw);
  const storedFailure = normalizeFailureMetadata(lastFailureRaw) || normalizeFailureMetadata(latestRaw);
  if (!initialArtifactPrunePromise && !currentJob) {
    initialArtifactPrunePromise = pruneObsoleteClientArtifactsBestEffort(latest);
  }
  if (initialArtifactPrunePromise) await initialArtifactPrunePromise;
  return {
    latest,
    lastFailure: failureAfterLatestSuccess(storedFailure, latest),
  };
};

const invalidateFreshnessCache = () => {
  freshnessCache = null;
};

const evaluateFreshness = (metadata, currentHashes, checkedAt = now()) => {
  const latest = normalizeSuccessfulMetadata(metadata);
  const currentSourceHash = String(currentHashes?.sourceHash || '');
  const currentPublicDataHash = String(currentHashes?.publicDataHash || '');
  const sourceCurrent = Boolean(latest?.sourceHash)
    && Boolean(currentSourceHash)
    && latest.sourceHash === currentSourceHash;
  const publicDataCurrent = Boolean(latest?.publicDataHash)
    && Boolean(currentPublicDataHash)
    && latest.publicDataHash === currentPublicDataHash;
  const reasons = [];
  if (!latest) {
    reasons.push('no-successful-build');
  } else {
    if (!metadataMatchesCurrentContract(latest)) reasons.push('build-contract-changed');
    if (!sourceCurrent) reasons.push('frontend-source-changed');
    if (!publicDataCurrent) reasons.push('public-data-changed');
  }
  return {
    isCurrent: Boolean(latest) && metadataMatchesCurrentContract(latest) && sourceCurrent && publicDataCurrent,
    sourceCurrent,
    publicDataCurrent,
    reasons,
    checkedAt,
    currentSourceHash,
    currentPublicDataHash,
  };
};

const freshnessMetadataKey = metadata => {
  const latest = normalizeSuccessfulMetadata(metadata);
  return JSON.stringify(latest ? [
    latest.id || '',
    latest.buildContractVersion || 0,
    latest.runtime || '',
    latest.distribution || '',
    latest.sourceHash || '',
    latest.publicDataHash || '',
  ] : ['no-successful-build']);
};

const managedArtifactName = name => {
  const candidate = String(name || '');
  if (sanitizeFileName(candidate) === candidate) return candidate;
  if (!candidate.endsWith('.sha256.txt')) return '';
  const artifactName = candidate.slice(0, -'.sha256.txt'.length);
  return sanitizeFileName(artifactName) === artifactName ? candidate : '';
};

const pruneObsoleteClientArtifacts = async metadata => {
  const latest = normalizeSuccessfulMetadata(metadata);
  const retained = new Set(
    (latest?.items || []).flatMap(item => {
      const fileName = sanitizeFileName(item.fileName);
      return fileName ? [fileName, `${fileName}.sha256.txt`] : [];
    }),
  );
  const entries = await readdir(buildRoot, { withFileTypes: true }).catch(error => {
    if (error?.code === 'ENOENT') return [];
    throw error;
  });
  for (const entry of entries) {
    if (!entry.isFile() || !managedArtifactName(entry.name) || retained.has(entry.name)) continue;
    await rm(join(buildRoot, entry.name), { force: true });
  }
};

const pruneObsoleteClientArtifactsBestEffort = async metadata => {
  try {
    await pruneObsoleteClientArtifacts(metadata);
  } catch (error) {
    console.warn(`Unable to prune obsolete client artifacts: ${error.message}`);
  }
};

const persistSuccessfulMetadata = async metadata => {
  if (!normalizeSuccessfulMetadata(metadata)) {
    throw new TypeError('Successful client metadata must have status "success".');
  }
  await writeJsonFile(latestFile, metadata);
  await rm(lastFailureFile, { force: true }).catch(() => {});
  await pruneObsoleteClientArtifactsBestEffort(metadata);
  invalidateFreshnessCache();
};

const persistFailureMetadata = async metadata => {
  const failure = normalizeFailureMetadata(metadata);
  if (!failure) {
    throw new TypeError('Failed client metadata must have status "failed".');
  }
  await writeJsonFile(lastFailureFile, failure);
  const latest = normalizeSuccessfulMetadata(await readJsonFile(latestFile, null));
  await pruneObsoleteClientArtifactsBestEffort(latest);
};

const staleMetadataSummary = metadata => (metadata?.status === 'success' ? {
  buildContractVersion: metadata.buildContractVersion || 0,
  runtime: metadata.runtime || '',
  distribution: metadata.distribution || '',
  generatedAt: metadata.finishedAt || metadata.startedAt || metadata.latest?.generatedAt || '',
} : null);

const artifactExists = async item => {
  const fileName = sanitizeFileName(item?.fileName);
  if (!fileName) return false;
  const filePath = resolve(buildRoot, fileName);
  if (!isInside(buildRoot, filePath)) return false;
  const stats = await stat(filePath).catch(() => null);
  return Boolean(stats?.isFile());
};

const metadataHasRequestedArtifacts = async (metadata, targets, catalog = null) => {
  const normalized = normalizeMetadata(metadata);
  if (!normalized?.items?.length) return false;
  for (const target of targets) {
    const item = normalized.items.find(candidate => candidate.targetId === target.id);
    const expectedSource = shellTarget(catalog, target) ? 'official-shell' : 'native-host';
    if (item?.buildSource !== expectedSource) return false;
    if (!item || !await artifactExists(item)) return false;
  }
  return true;
};

const codeSigningSettings = (sourceEnv = process.env) => {
  const cscLink = sourceEnv.PAYLOADER_WINDOWS_CSC_LINK || sourceEnv.PAYLOADER_CSC_LINK || sourceEnv.WIN_CSC_LINK || sourceEnv.CSC_LINK || '';
  const cscKeyPassword = sourceEnv.PAYLOADER_WINDOWS_CSC_KEY_PASSWORD
    || sourceEnv.PAYLOADER_CSC_KEY_PASSWORD
    || sourceEnv.WIN_CSC_KEY_PASSWORD
    || sourceEnv.CSC_KEY_PASSWORD
    || '';
  const certificateSubjectName = sourceEnv.PAYLOADER_WINDOWS_CERT_SUBJECT || sourceEnv.WIN_CSC_NAME || sourceEnv.CSC_NAME || '';
  const certificateSha1 = sourceEnv.PAYLOADER_WINDOWS_CERT_SHA1 || sourceEnv.WIN_CSC_SHA1 || '';
  const configured = Boolean(cscLink || certificateSubjectName || certificateSha1);
  const signtoolOptions = {
    ...(certificateSubjectName ? { certificateSubjectName } : {}),
    ...(certificateSha1 ? { certificateSha1 } : {}),
  };
  return {
    configured,
    env: {
      ...(cscLink ? { CSC_LINK: cscLink } : {}),
      ...(cscKeyPassword ? { CSC_KEY_PASSWORD: cscKeyPassword } : {}),
    },
    winConfig: Object.keys(signtoolOptions).length ? { signtoolOptions } : {},
  };
};

const buildEnvironmentAllowlist = Object.freeze([
  'PATH', 'Path',
  'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT',
  'TEMP', 'TMP', 'TMPDIR',
  'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TERM', 'SHELL',
  'USER', 'USERNAME', 'LOGNAME',
  'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER',
  'CI', 'GITHUB_ACTIONS', 'RUNNER_OS', 'RUNNER_ARCH',
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
  'http_proxy', 'https_proxy', 'no_proxy',
  'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
]);
const signingEnvironmentAllowlist = Object.freeze([
  'APPLE_ID',
  'APPLE_APP_SPECIFIC_PASSWORD',
  'APPLE_TEAM_ID',
  'CSC_NAME',
]);

const createBuildEnvironment = (sourceEnv = process.env, options = {}) => {
  const environment = {};
  for (const key of buildEnvironmentAllowlist) {
    if (typeof sourceEnv[key] === 'string' && sourceEnv[key]) environment[key] = sourceEnv[key];
  }
  Object.assign(environment, {
    HOME: join(clientCacheRoot, 'home'),
    XDG_CACHE_HOME: join(clientCacheRoot, 'xdg-cache'),
    XDG_CONFIG_HOME: join(clientCacheRoot, 'xdg-config'),
    XDG_DATA_HOME: join(clientCacheRoot, 'xdg-data'),
    ELECTRON_CACHE: join(clientCacheRoot, 'electron'),
    ELECTRON_BUILDER_CACHE: join(clientCacheRoot, 'electron-builder'),
    electron_config_cache: join(clientCacheRoot, 'electron-builder'),
  });
  if (configuredElectronMirror) {
    environment.ELECTRON_MIRROR = configuredElectronMirror;
    environment.npm_config_electron_mirror = configuredElectronMirror;
  }
  if (configuredBuilderBinariesMirror) {
    environment.ELECTRON_BUILDER_BINARIES_MIRROR = configuredBuilderBinariesMirror;
    environment.NPM_CONFIG_ELECTRON_BUILDER_BINARIES_MIRROR = configuredBuilderBinariesMirror;
    environment.npm_config_electron_builder_binaries_mirror = configuredBuilderBinariesMirror;
  }
  if (options.includeSigning) {
    const signing = codeSigningSettings(sourceEnv);
    Object.assign(environment, signing.env);
    for (const key of signingEnvironmentAllowlist) {
      if (typeof sourceEnv[key] === 'string' && sourceEnv[key]) environment[key] = sourceEnv[key];
    }
  }
  return environment;
};

const sleep = ms => new Promise(resolveSleep => setTimeout(resolveSleep, ms));

const isRetryableWindowsPackageError = error => {
  const stdout = String(error?.result?.stdout || '');
  const stderr = String(error?.result?.stderr || '');
  const message = String(error?.message || '');
  const combined = `${message}\n${stdout}\n${stderr}`;
  return process.platform === 'win32'
    && /EPERM: operation not permitted, rename/i.test(combined)
    && /win-unpacked(?:\.tmp)?/i.test(combined);
};

const appendJobLog = (message, limit = 16) => {
  if (!currentJob) return;
  const logs = [...(Array.isArray(currentJob.logs) ? currentJob.logs : []), message].slice(-limit);
  currentJob = { ...currentJob, logs };
};

const run = (command, args, options = {}) => new Promise((resolveRun, rejectRun) => {
  const startedAt = Date.now();
  const child = spawn(command, args, {
    cwd: rootDir,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
  let stdout = '';
  let stderr = '';
  child.stdout?.on('data', chunk => {
    stdout += chunk.toString();
    if (stdout.length > 60_000) stdout = stdout.slice(-60_000);
  });
  child.stderr?.on('data', chunk => {
    stderr += chunk.toString();
    if (stderr.length > 60_000) stderr = stderr.slice(-60_000);
  });
  child.on('error', rejectRun);
  child.on('close', code => {
    const result = { code, stdout, stderr, elapsedMs: Date.now() - startedAt };
    if (code === 0) {
      resolveRun(result);
      return;
    }
    const error = new Error(`${command} ${args.join(' ')} failed with exit code ${code}`);
    error.result = result;
    rejectRun(error);
  });
});

const collectFiles = async baseDir => {
  const files = [];
  const visit = async dir => {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        await visit(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  };
  await visit(baseDir);
  return files;
};

const existingFile = async filePath => {
  const stats = await stat(filePath).catch(() => null);
  return Boolean(stats?.isFile());
};

const distReady = () => existingFile(join(distDir, 'index.html'));

const normalizeAllowedExternalUrl = value => {
  const source = String(value || '').trim();
  if (source === officialProjectUrl || source === publicProjectRoute || source === clientProjectRoute) {
    return clientProjectRoute;
  }
  try {
    const url = new URL(source);
    if (url.protocol !== 'https:' || url.username || url.password || url.search) return '';
    const pathname = url.pathname.replace(/\/+$/, '') || '/';
    if (url.hostname === 'xss.icu' && pathname === '/' && !url.hash) {
      return protectedXeyeUrl;
    }
    return '';
  } catch {
    return '';
  }
};

const sanitizedReferences = value => {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(normalizeAllowedExternalUrl).filter(Boolean))];
};

const sanitizeClientPayload = payload => {
  const next = { ...payload };
  const references = sanitizedReferences(next.references);
  if (references.length) {
    next.references = references;
  } else {
    delete next.references;
  }
  return next;
};

const sanitizeClientTool = tool => {
  const next = { ...tool };
  if (String(next.id || '') === protectedXssToolId) {
    next.externalUrl = protectedXeyeUrl;
    next.references = [protectedXeyeUrl];
    return next;
  }

  delete next.externalUrl;
  const references = sanitizedReferences(next.references);
  if (references.length) {
    next.references = references;
  } else {
    delete next.references;
  }
  return next;
};

const sanitizeClientPublicData = data => {
  const snapshot = data && typeof data === 'object' ? data : {};
  const settings = snapshot.settings && typeof snapshot.settings === 'object' ? snapshot.settings : {};
  return {
    ...snapshot,
    settings: {
      ...settings,
      projectUrl: clientProjectRoute,
      logoUrl: referencedLogoUrl(snapshot),
    },
    payloads: Array.isArray(snapshot.payloads) ? snapshot.payloads.map(sanitizeClientPayload) : [],
    tools: Array.isArray(snapshot.tools) ? snapshot.tools.map(sanitizeClientTool) : [],
    navigation: Array.isArray(snapshot.navigation) ? snapshot.navigation : [],
    toolNavigation: Array.isArray(snapshot.toolNavigation) ? snapshot.toolNavigation : [],
  };
};

const hashFiles = async files => {
  const hash = createHash('sha256');
  const safeFiles = files.filter(Boolean).sort();
  for (const file of safeFiles) {
    const stats = await stat(file).catch(() => null);
    if (!stats?.isFile()) continue;
    hash.update(relative(rootDir, file).split(pathSeparator).join('/'));
    hash.update(await readFile(file));
  }
  return hash.digest('hex');
};

const electronVersionFromSpec = value => {
  const match = String(value || '').match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/);
  if (!match) throw new Error('Unable to determine the configured Electron version.');
  return match[0];
};

const configuredElectronVersion = async () => {
  try {
    const installed = JSON.parse(await readFile(electronPackageJson, 'utf8'));
    return electronVersionFromSpec(installed.version);
  } catch {
    const projectPackage = JSON.parse(await readFile(projectPackageJson, 'utf8'));
    return electronVersionFromSpec(
      projectPackage.dependencies?.electron || projectPackage.devDependencies?.electron,
    );
  }
};

const frontendSourceFingerprint = async () => {
  const sourceFiles = await collectFiles(join(rootDir, 'src'));
  const projectFiles = [
    join(rootDir, 'index.html'),
    join(rootDir, 'package.json'),
    join(rootDir, 'package-lock.json'),
    join(rootDir, 'vite.config.ts'),
    join(rootDir, 'tsconfig.json'),
    join(rootDir, 'tsconfig.app.json'),
    electronMainTemplate,
    clientDeploymentRuntimeSource,
    projectAttributionSource,
    clientInstallerIncludeSource,
    clientBuilderSource,
  ];
  return hashFiles([...sourceFiles, ...projectFiles]);
};

const buildPublicDataSnapshot = async () => {
  const snapshot = sanitizeClientPublicData(JSON.parse(JSON.stringify(await getPublicData())));
  const logoUrl = referencedLogoUrl(snapshot);
  const logoFile = referencedLogoFile(logoUrl);
  if (logoUrl && (!logoFile || !(await existingFile(logoFile)))) {
    snapshot.settings.logoUrl = '';
  }
  return snapshot;
};

const computeCurrentBuildHashes = async () => {
  if (freshnessHashProvider) return freshnessHashProvider();
  const [sourceHash, publicData] = await Promise.all([
    frontendSourceFingerprint(),
    buildPublicDataSnapshot(),
  ]);
  return {
    sourceHash,
    publicDataHash: hashValue(JSON.stringify(publicData)),
  };
};

const getBuildFreshness = metadata => {
  if (!normalizeSuccessfulMetadata(metadata)) {
    return Promise.resolve(evaluateFreshness(null, {}, now()));
  }
  const cacheKey = freshnessMetadataKey(metadata);
  const currentTime = Date.now();
  if (
    freshnessCache?.key === cacheKey
    && (!freshnessCache.settled || freshnessCache.expiresAt > currentTime)
  ) {
    return freshnessCache.promise;
  }

  const checkedAt = now();
  const entry = {
    key: cacheKey,
    settled: false,
    expiresAt: 0,
    promise: null,
  };
  entry.promise = (async () => {
    try {
      return evaluateFreshness(metadata, await computeCurrentBuildHashes(), checkedAt);
    } catch {
      return {
        ...evaluateFreshness(metadata, {}, checkedAt),
        reasons: ['freshness-check-failed'],
      };
    }
  })();
  entry.promise.then(() => {
    entry.settled = true;
    entry.expiresAt = Date.now() + freshnessCacheTtlMs;
  });
  freshnessCache = entry;
  return entry.promise;
};

const referencedLogoUrl = data => {
  const logoUrl = String(data?.settings?.logoUrl || '').trim();
  return /^\/uploads\/logo\/logo-[a-zA-Z0-9.-]+\.(png|jpe?g|webp)$/.test(logoUrl) ? logoUrl : '';
};

const referencedLogoFile = logoUrl => {
  if (!logoUrl) return null;
  const fileName = basename(logoUrl);
  const target = resolve(uploadDir, 'logo', fileName);
  return isInside(join(uploadDir, 'logo'), target) ? target : null;
};

const prepareElectronApp = async (workDir, publicData, options = {}) => {
  const appDir = join(workDir, 'electron-app');
  const bundledDistDir = join(appDir, 'dist');
  const bundledAppDir = join(appDir, 'app');
  const buildResourcesDir = join(appDir, 'build');
  const deploymentPackageDir = join(workDir, 'deployment.payloader');
  const buildOutputDir = join(workDir, 'electron-output');
  const routes = {};
  const fingerprint = createHash('sha256');
  const distFiles = await collectFiles(distDir);
  if (!distFiles.some(file => basename(file) === 'index.html')) {
    throw new Error('dist/index.html not found. Frontend build did not produce an index file.');
  }

  await mkdir(bundledDistDir, { recursive: true });
  await mkdir(bundledAppDir, { recursive: true });
  await mkdir(buildResourcesDir, { recursive: true });

  const fileInfos = await Promise.all(distFiles.map(async file => {
    const relativePath = relative(distDir, file).split(pathSeparator).join('/');
    if (!relativePath || relativePath.startsWith('..') || relativePath.includes('/../')) {
      throw new Error(`Unsafe dist asset path: ${relativePath}`);
    }
    const target = join(bundledDistDir, relativePath);
    const stats = await stat(file);
    return { file, relativePath, target, stats };
  }));
  await Promise.all(fileInfos.map(async ({ file, target }) => {
    await mkdir(resolve(target, '..'), { recursive: true });
    await copyFile(file, target);
  }));
  for (const { file, relativePath, stats } of fileInfos) {
    const route = toPublicUrl(relativePath);
    routes[route] = {
      file: `dist/${relativePath}`,
      mimeType: mimeTypes[extname(file).toLowerCase()] || 'application/octet-stream',
      size: stats.size,
      cacheControl: relativePath === 'index.html' ? 'no-store' : 'public, max-age=31536000, immutable',
    };
    fingerprint.update(relativePath);
    fingerprint.update(String(stats.size));
    fingerprint.update(String(stats.mtimeMs));
  }

  const publicDataPath = join(bundledAppDir, 'public-data.json');
  let publicDataJson = JSON.stringify(publicData);
  await writeFile(publicDataPath, publicDataJson, 'utf8');
  fingerprint.update(publicDataJson);

  const logoUrl = referencedLogoUrl(publicData);
  const logoFile = referencedLogoFile(logoUrl);
  if (logoUrl && logoFile) {
    try {
      const stats = await stat(logoFile);
      if (stats.isFile()) {
        const logoTarget = join(bundledDistDir, logoUrl.replace(/^\/+/, ''));
        await mkdir(resolve(logoTarget, '..'), { recursive: true });
        await copyFile(logoFile, logoTarget);
        routes[logoUrl] = {
          file: `dist/${logoUrl.replace(/^\/+/, '')}`,
          mimeType: mimeTypes[extname(logoFile).toLowerCase()] || 'application/octet-stream',
          size: stats.size,
          cacheControl: 'public, max-age=31536000, immutable',
        };
        fingerprint.update(logoUrl);
        fingerprint.update(String(stats.size));
        fingerprint.update(String(stats.mtimeMs));
      }
    } catch {
      publicData.settings.logoUrl = '';
      publicDataJson = JSON.stringify(publicData);
      await writeFile(publicDataPath, publicDataJson, 'utf8');
    }
  }

  const customToolsJson = JSON.stringify({
    version: 1,
    categories: publicData.tools.filter(tool => String(tool.id || '').startsWith('custom-')),
  });
  await writeFile(join(bundledAppDir, 'custom-tools.json'), customToolsJson, 'utf8');
  fingerprint.update(customToolsJson);

  const generatedAt = now();
  const deploymentPackage = await writeClientDeploymentPackage({
    destination: deploymentPackageDir,
    publicData,
    logoFile: referencedLogoFile(referencedLogoUrl(publicData)),
    generatedAt,
    buildContractVersion: clientBuildContractVersion,
  });
  fingerprint.update(JSON.stringify(deploymentPackage.manifest));

  const manifest = {
    productName,
    copyright,
    generatedAt,
    buildContractVersion: clientBuildContractVersion,
    runtime: clientRuntime,
    distribution: clientDistribution,
    networkPolicy: clientNetworkPolicy,
    performancePolicy: clientPerformancePolicy,
    securityPolicy: clientSecurityPolicy,
    publicDataSha256: hashValue(publicDataJson),
    customToolsSha256: hashValue(customToolsJson),
    routes,
    stats: publicDataStats(publicData),
    excludes: [
      'admin backend UI and authenticated management APIs',
      'server-side SQLite datastore and private runtime configuration',
      'local database files and non-public uploads',
    ],
  };
  const manifestPath = join(bundledAppDir, 'manifest.json');
  await writeJsonFile(manifestPath, manifest);
  fingerprint.update(JSON.stringify(manifest.routes));

  await copyFile(electronMainTemplate, join(appDir, 'main.cjs'));
  await copyFile(clientDeploymentRuntimeSource, join(appDir, 'client-deployment-runtime.cjs'));
  await copyFile(projectAttributionSource, join(appDir, 'project-attribution.cjs'));
  await copyFile(clientInstallerIncludeSource, join(buildResourcesDir, 'installer.nsh'));

  const electronVersion = await configuredElectronVersion();
  const packageInfo = await readJsonFile(projectPackageJson, {});
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(String(packageInfo.version || ''))) {
    throw new Error('Project package version is invalid.');
  }
  const signing = codeSigningSettings();
  const appPackage = {
    name: 'payloader-client',
    version: packageInfo.version,
    productName,
    description: 'Payloader offline desktop client',
    main: 'main.cjs',
    author: 'Payloader',
    license: 'UNLICENSED',
    private: true,
    devDependencies: {
      electron: electronVersion,
    },
    build: {
      appId: 'com.payloader.client',
      productName,
      copyright,
      electronVersion,
      ...electronRuntimeConfig(electronRuntimeDir, options.useBundledElectronRuntime !== false),
      electronLanguages: clientPerformancePolicy.electronLanguages,
      directories: {
        output: buildOutputDir,
        buildResources: buildResourcesDir,
      },
      files: [
        'main.cjs',
        'client-deployment-runtime.cjs',
        'project-attribution.cjs',
        'dist/**/*',
        'app/**/*',
        'package.json',
      ],
      asar: true,
      compression: clientPerformancePolicy.packageCompression,
      npmRebuild: false,
      nodeGypRebuild: false,
      win: {
        target: ['nsis'],
        executableName: 'Payloader',
        artifactName: 'Payloader-Client-Setup-${version}-${arch}.${ext}',
        requestedExecutionLevel: 'asInvoker',
        ...signing.winConfig,
      },
      linux: {
        target: ['AppImage', 'deb', 'rpm'],
        executableName: 'payloader',
        category: 'Utility',
        synopsis: 'Payloader offline desktop client',
        description: 'Payloader offline desktop client with public snapshot data only.',
        maintainer: 'Payloader <noreply@example.local>',
        vendor: 'Payloader',
        artifactName: 'Payloader-Client-${version}-${arch}.${ext}',
      },
      appImage: {
        artifactName: 'Payloader-Client-${version}-${arch}.${ext}',
        compression: clientPerformancePolicy.appImageCompression,
      },
      deb: {
        artifactName: 'Payloader-Client-${version}-${arch}.${ext}',
        compression: clientPerformancePolicy.debCompression,
      },
      rpm: {
        artifactName: 'Payloader-Client-${version}-${arch}.${ext}',
        compression: clientPerformancePolicy.rpmCompression,
      },
      mac: {
        target: ['dmg'],
        category: 'public.app-category.developer-tools',
        hardenedRuntime: true,
        gatekeeperAssess: false,
        artifactName: 'Payloader-Client-${version}-${arch}.${ext}',
      },
      dmg: {
        artifactName: 'Payloader-Client-${version}-${arch}.${ext}',
        sign: false,
      },
      nsis: windowsNsisOptions,
    },
  };
  await writeJsonFile(join(appDir, 'package.json'), appPackage);

  return {
    appDir,
    buildOutputDir,
    deploymentPackageDir,
    deploymentManifest: deploymentPackage.manifest,
    manifest,
    fingerprint: fingerprint.digest('hex'),
  };
};

const makeFailureStatus = (started, error) => ({
  id: started.id,
  status: 'failed',
  message: error instanceof Error ? error.message : 'Build failed',
  startedAt: started.startedAt,
  finishedAt: now(),
  selectedTargets: started.selectedTargets || [],
  skippedTargets: started.skippedTargets || [],
  logs: [
    ...(started.logs || []),
    error?.result?.stdout ? `stdout:\n${error.result.stdout}` : '',
    error?.result?.stderr ? `stderr:\n${error.result.stderr}` : '',
  ].filter(Boolean).slice(-12),
});

const buildCommandArgs = target => [
  electronBuilderCli,
  `--${target.builderPlatform}`,
  ...target.builderTargets,
  `--${target.builderArch}`,
  '--publish',
  'never',
];

const findBuiltArtifact = (files, outputDir, target) => {
  const extension = target.extension.toLowerCase();
  const candidates = files
    .filter(file => extname(file).toLowerCase() === extension)
    .filter(file => !relative(outputDir, file).split(pathSeparator).join('/').includes('-unpacked/'))
    .filter(file => !basename(file).toLowerCase().includes('blockmap'))
    .sort((a, b) => {
      const sizeDelta = (statSyncSafe(b)?.size || 0) - (statSyncSafe(a)?.size || 0);
      return sizeDelta || basename(b).length - basename(a).length;
    });
  return candidates[0] || null;
};

const statSyncSafe = filePath => {
  try {
    return statSync(filePath);
  } catch {
    return null;
  }
};

const artifactNotes = (target, signing) => [
  ...(target.requiresSigningNote ? [target.requiresSigningNote] : []),
  ...(target.platform === 'windows' && !signing.configured ? ['Unsigned Windows builds are more likely to receive reputation warnings until signed and distributed from a stable download page.'] : []),
  ...(target.id.includes('appimage') ? ['Linux AppImage may need executable permission after download: chmod +x Payloader-Client-*.AppImage.'] : []),
  ...(target.format === 'DEB' ? ['Install with dpkg or apt on Debian/Ubuntu-family systems after verifying SHA256.'] : []),
  ...(target.format === 'RPM' ? ['Install with rpm or dnf on Fedora/RHEL-family systems after verifying SHA256.'] : []),
];

const runElectronBuilderWithRetry = async (target, appDir, buildEnv) => {
  const maxAttempts = process.platform === 'win32' ? 3 : 1;
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      if (attempt > 1) {
        appendJobLog(`Retrying ${target.id} packaging after Windows file-lock error (${attempt}/${maxAttempts}).`);
      }
      return await run(process.execPath, buildCommandArgs(target), {
        cwd: appDir,
        env: buildEnv,
      });
    } catch (error) {
      lastError = error;
      if (!isRetryableWindowsPackageError(error) || attempt >= maxAttempts) {
        throw error;
      }

      appendJobLog(`Windows packaging hit EPERM rename during ${target.id}; waiting before retry.`);
      await sleep(2000 * attempt);
    }
  }

  throw lastError;
};

const runBuild = async started => {
  const workDir = join(tmpRoot, started.id);
  invalidateFreshnessCache();

  try {
    await mkdir(workDir, { recursive: true });
    await mkdir(buildRoot, { recursive: true });
    await mkdir(clientCacheRoot, { recursive: true });
    const shellCatalog = await loadShellCatalog();
    await pruneClientShellCache(
      join(clientCacheRoot, 'client-shells'),
      shellCatalog.manifest ? shellCatalog.targets : null,
    ).catch(error => console.warn(`Unable to prune obsolete client shell cache: ${error.message}`));
    const { selected: selectedTargets, skipped: skippedTargets } = normalizeRequestedTargets(
      started.requestedTargets,
      shellCatalog,
    );
    if (!selectedTargets.length) {
      const reason = skippedTargets[0]?.reason || 'No supported client build targets are available on this host.';
      throw new Error(reason);
    }
    const selectedTargetIds = selectedTargets.map(target => target.id);
    currentJob = { ...started, status: 'building', message: 'Checking public data and frontend fingerprint', logs: [] };
    const [sourceHash, publicData] = await Promise.all([
      frontendSourceFingerprint(),
      buildPublicDataSnapshot(),
    ]);
    const publicDataHash = hashValue(JSON.stringify(publicData));
    const cached = normalizeSuccessfulMetadata(await readJsonFile(latestFile, null));
    if (
      metadataMatchesCurrentContract(cached) &&
      cached.sourceHash === sourceHash &&
      cached.publicDataHash === publicDataHash &&
      await metadataHasRequestedArtifacts(cached, selectedTargets, shellCatalog)
    ) {
      const reused = {
        ...normalizeMetadata(cached),
        message: 'Latest build already matches current public data and frontend source',
        reusedAt: now(),
        selectedTargets: selectedTargetIds,
        skippedTargets,
      };
      await persistSuccessfulMetadata(reused);
      currentJob = null;
      return reused;
    }

    const frontendDistReady = await distReady();
    if (!frontendDistReady && immutableProductionRuntime) {
      throw new Error('dist/index.html is missing from the immutable production runtime. Rebuild the deployment image.');
    }
    if (!frontendDistReady || (!immutableProductionRuntime && cached?.sourceHash !== sourceHash)) {
      currentJob = { ...currentJob, message: 'Building frontend assets' };
      const compileEnvironment = createBuildEnvironment(process.env);
      await run(process.execPath, [tscCli, '-b'], { env: compileEnvironment });
      await run(process.execPath, [viteCli, 'build'], { env: compileEnvironment });
    } else {
      currentJob = { ...currentJob, message: 'Reusing current frontend assets' };
    }

    currentJob = { ...currentJob, message: 'Collecting public-only data snapshot' };
    const {
      appDir,
      buildOutputDir,
      deploymentPackageDir,
      manifest,
      fingerprint,
    } = await prepareElectronApp(workDir, publicData, { useBundledElectronRuntime: false });

    currentJob = { ...currentJob, message: 'Packaging desktop clients', selectedTargets: selectedTargetIds, skippedTargets };
    const signing = codeSigningSettings();
    const stamp = new Date().toISOString()
      .replace(/[-:]/g, '')
      .replace(/\..+$/, '')
      .replace('T', '-');
    const items = [];
    const targetResults = [...skippedTargets];
    const buildEnv = {
      ...createBuildEnvironment(process.env, { includeSigning: true }),
      CSC_IDENTITY_AUTO_DISCOVERY: signing.configured ? 'true' : 'false',
    };

    for (const target of selectedTargets) {
      const shell = shellTarget(shellCatalog, target);
      await rm(buildOutputDir, { recursive: true, force: true }).catch(() => {});
      currentJob = {
        ...currentJob,
        message: `Packaging ${target.platformLabel} ${target.archLabel}`,
        activeTarget: target.id,
        targetResults,
      };
      const buildStartedAt = Date.now();
      let finalName;
      let finalPath;
      let artifactStats;
      let sha256;
      let format = target.format;
      let mimeType = target.mimeType;
      let installType = target.installType;
      let packageManager = target.packageManager || '';
      let buildSource = 'native-host';
      let shellSha256 = '';
      let shellVersion = '';
      let artifactSigningConfigured = signing.configured;

      if (shell) {
        const shellArchive = await acquireClientShellArchive(shell, {
          cacheRoot: join(clientCacheRoot, 'client-shells'),
          token: process.env.PAYLOADER_GITHUB_TOKEN,
        });
        finalName = portableArtifactFileName(target, shell, stamp, started.id);
        finalPath = join(buildRoot, finalName);
        const assembled = await assembleClientShell({
          shellArchive,
          shell,
          deploymentPackageDir,
          destination: finalPath,
          workRoot: workDir,
        });
        artifactStats = { size: assembled.size };
        sha256 = assembled.sha256;
        format = shell.outputFormat === 'zip' ? 'Portable ZIP' : 'Portable TAR.GZ';
        mimeType = shell.outputFormat === 'zip' ? 'application/zip' : 'application/gzip';
        installType = 'Portable directory';
        packageManager = '';
        buildSource = 'official-shell';
        shellSha256 = shell.sha256;
        shellVersion = String(shellCatalog.manifest?.appVersion || '');
        artifactSigningConfigured = Boolean(shell.signed);
      } else {
        await runElectronBuilderWithRetry(target, appDir, buildEnv);
        const builtFiles = await collectFiles(buildOutputDir);
        const artifact = findBuiltArtifact(builtFiles, buildOutputDir, target);
        if (!artifact) {
          throw new Error(`electron-builder did not produce ${target.platformLabel} ${target.archLabel} ${target.format}`);
        }
        finalName = artifactFileName(target, stamp, started.id);
        finalPath = join(buildRoot, finalName);
        await copyFile(artifact, finalPath);
        artifactStats = await stat(finalPath);
        sha256 = await hashFile(finalPath);
      }
      await writeFile(`${finalPath}.sha256.txt`, `${sha256}  ${finalName}\n`, 'utf8');
      const item = {
        targetId: target.id,
        platform: target.platform,
        platformLabel: target.platformLabel,
        arch: target.arch,
        archLabel: target.archLabel,
        format,
        fileName: finalName,
        size: artifactStats.size,
        sha256,
        generatedAt: now(),
        runtime: clientRuntime,
        distribution: clientDistribution,
        buildContractVersion: clientBuildContractVersion,
        codeSigningConfigured: artifactSigningConfigured,
        signingStatus: artifactSigningConfigured ? 'configured' : 'unsigned',
        mimeType,
        cpuFamily: target.cpuFamily,
        minOsVersion: target.minOsVersion,
        installType,
        packageManager,
        buildSource,
        shellVersion,
        shellSha256,
        elapsedMs: Date.now() - buildStartedAt,
        performanceNotes: [
          'Artifact SHA256 is computed with a file stream to keep builder memory stable.',
          buildSource === 'official-shell'
            ? 'The server replaces only the external deployment package and does not rebuild the official shell.'
            : target.platform === 'windows'
            ? 'NSIS uses a compact 7z payload, keeps only supported Electron locales, skips the install-scope page, and does not auto-launch after install.'
            : target.platform === 'linux'
              ? `${target.format} uses faster package compression where supported.`
              : 'macOS DMG packaging is generated on macOS so signing and notarization can be handled by the host.',
        ],
        securityNotes: [
          'No autostart, updater, shell injection, packing, obfuscation, or security-software evasion is added by the builder.',
          'Use code signing, stable download URLs, and SHA256 verification for reputation and integrity.',
        ],
        notes: buildSource === 'official-shell'
          ? ['Extract the portable archive and run Payloader from the extracted directory.']
          : artifactNotes(target, signing),
      };
      items.push(item);
      targetResults.push({
        id: target.id,
        status: 'success',
        fileName: finalName,
        size: artifactStats.size,
        elapsedMs: item.elapsedMs,
        buildSource,
      });
    }

    const normalizedItems = items.map(normalizeArtifact).filter(Boolean).sort((a, b) => artifactScore(a) - artifactScore(b));
    const metadata = {
      id: started.id,
      status: 'success',
      message: `Ready to download ${normalizedItems.length} client build${normalizedItems.length === 1 ? '' : 's'}`,
      startedAt: started.startedAt,
      finishedAt: now(),
      metadataVersion: clientMetadataVersion,
      selectedTargets: selectedTargetIds,
      skippedTargets,
      targetResults,
      latest: normalizedItems[0] || null,
      items: normalizedItems,
      runtime: clientRuntime,
      distribution: clientDistribution,
      buildContractVersion: clientBuildContractVersion,
      codeSigningConfigured: normalizedItems.length > 0
        && normalizedItems.every(item => item.codeSigningConfigured),
      signingStatus: normalizedItems.length > 0
        && normalizedItems.every(item => item.codeSigningConfigured)
        ? 'configured'
        : 'unsigned',
      fingerprint,
      sourceHash,
      publicDataHash,
      networkPolicy: clientNetworkPolicy,
      performancePolicy: clientPerformancePolicy,
      securityPolicy: clientSecurityPolicy,
      productName,
      copyright,
      publicStats: manifest.stats,
      exclusions: manifest.excludes,
      shellCatalog: {
        source: shellCatalog.source,
        appVersion: shellCatalog.manifest?.appVersion || '',
        generatedAt: shellCatalog.manifest?.generatedAt || '',
      },
    };
    await persistSuccessfulMetadata(metadata);
    currentJob = null;
    return metadata;
  } catch (error) {
    const failure = makeFailureStatus({
      ...started,
      selectedTargets: currentJob?.selectedTargets || started.selectedTargets,
      skippedTargets: currentJob?.skippedTargets || started.skippedTargets,
      logs: currentJob?.logs || started.logs,
    }, error);
    try {
      await persistFailureMetadata(failure);
    } finally {
      currentJob = null;
    }
    throw error;
  } finally {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
};

export const getClientBuildStatus = async () => {
  await mkdir(buildRoot, { recursive: true });
  const [{ latest: storedLatest, lastFailure }, publicData, shellCatalog] = await Promise.all([
    readStoredBuildState(),
    getPublicData(),
    loadShellCatalog(),
  ]);
  const freshness = await getBuildFreshness(storedLatest);
  const currentLatest = metadataMatchesCurrentContract(storedLatest);
  const latest = currentLatest
    ? storedLatest
    : storedLatest
      ? {
          ...storedLatest,
          status: 'stale',
          message: 'Existing client builds use an older build contract. Regenerate clients to publish the optimized multi-platform client list.',
          latest: null,
          items: [],
        }
      : null;
  const signing = codeSigningSettings();
  return {
    active: currentJob,
    latest,
    items: currentLatest ? storedLatest?.items || [] : [],
    lastFailure,
    publicStats: publicDataStats(publicData),
    freshness,
    staleLatest: currentLatest ? null : staleMetadataSummary(storedLatest),
    targets: clientTargetMatrix.map(target => normalizeTargetAvailability(target, shellCatalog)),
    canGenerate: !currentJob,
    environment: {
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      runtime: clientRuntime,
      distribution: clientDistribution,
      buildContractVersion: clientBuildContractVersion,
      metadataVersion: clientMetadataVersion,
      opensOwnWindow: true,
      requiresSystemBrowser: false,
      requiresUserNode: false,
      codeSigningConfigured: signing.configured,
      crossPlatformOverride,
      electronMirror: configuredElectronMirror || 'official-upstream',
      electronBuilderBinariesMirror: configuredBuilderBinariesMirror || 'official-upstream',
      shellSource: shellCatalog.source,
      shellVersion: shellCatalog.manifest?.appVersion || '',
      shellError: shellCatalog.error || '',
    },
    policies: {
      network: clientNetworkPolicy,
      performance: clientPerformancePolicy,
      security: clientSecurityPolicy,
    },
  };
};

export const getPublicClientBuildInfo = async () => {
  await mkdir(buildRoot, { recursive: true });
  const [{ latest: metadata, lastFailure }, shellCatalog] = await Promise.all([
    readStoredBuildState(),
    loadShellCatalog(),
  ]);
  const freshness = await getBuildFreshness(metadata);
  if (!metadataMatchesCurrentContract(metadata) || !metadata.items.length) {
    return {
      available: false,
      latest: null,
      items: [],
      generatedAt: '',
      productName,
      runtime: clientRuntime,
      distribution: clientDistribution,
      buildContractVersion: clientBuildContractVersion,
      codeSigningConfigured: false,
      lastBuildFailed: Boolean(lastFailure),
      publicStats: publicDataStats({}),
      targets: clientTargetMatrix.map(target => normalizeTargetAvailability(target, shellCatalog)),
      staleLatest: staleMetadataSummary(metadata),
      freshness,
      policies: {
        performance: clientPerformancePolicy,
        security: clientSecurityPolicy,
      },
    };
  }
  const items = [];
  for (const item of metadata.items) {
    const download = await clientBuildDownload(item.fileName);
    if (!download) continue;
    items.push({
      ...item,
      size: download.size,
      downloadUrl: `/api/client-build/download/${encodeURIComponent(download.fileName)}`,
    });
  }
  const latest = items[0] || null;
  return {
    available: Boolean(items.length),
    latest,
    items,
    generatedAt: metadata.finishedAt || metadata.startedAt || latest?.generatedAt || '',
    productName,
    runtime: metadata.runtime || clientRuntime,
    distribution: metadata.distribution || clientDistribution,
    buildContractVersion: metadata.buildContractVersion || 0,
    codeSigningConfigured: Boolean(metadata.codeSigningConfigured),
    lastBuildFailed: Boolean(lastFailure),
    publicStats: metadata.publicStats || publicDataStats({}),
    targets: clientTargetMatrix.map(target => normalizeTargetAvailability(target, shellCatalog)),
    freshness,
    policies: {
      performance: clientPerformancePolicy,
      security: clientSecurityPolicy,
    },
  };
};

export const startClientBuild = async (options = {}) => {
  await mkdir(tmpRoot, { recursive: true });
  if (currentJob) return currentJob;
  const requestedTargets = Array.isArray(options?.targets) ? options.targets : [];
  const shellCatalog = await loadShellCatalog();
  const { selected, skipped } = normalizeRequestedTargets(requestedTargets, shellCatalog);
  const started = {
    id: randomUUID().replace(/-/g, ''),
    status: 'queued',
    message: 'Queued',
    startedAt: now(),
    requestedTargets,
    selectedTargets: selected.map(target => target.id),
    skippedTargets: skipped,
  };
  invalidateFreshnessCache();
  currentJob = started;
  runBuild(started).catch(error => {
    console.error(error);
  });
  return started;
};

export const clientBuildDownload = async fileName => {
  const latest = normalizeSuccessfulMetadata(await readJsonFile(latestFile, null));
  if (!metadataMatchesCurrentContract(latest)) return null;
  const requestedName = String(fileName || '') === 'latest' ? latest?.latest?.fileName : fileName;
  const safeName = sanitizeFileName(requestedName);
  if (!safeName) return null;
  if (!latest || latest.status !== 'success' || !latest.items.some(item => item.fileName === safeName)) return null;
  const filePath = resolve(buildRoot, safeName);
  if (!isInside(buildRoot, filePath)) return null;
  const stats = await stat(filePath).catch(() => null);
  if (!stats?.isFile()) return null;
  const extension = extname(safeName);
  const item = latest.items.find(candidate => candidate.fileName === safeName) || null;
  return {
    fileName: safeName,
    filePath,
    size: stats.size,
    mimeType: item?.mimeType || downloadMimeTypes[extension] || 'application/octet-stream',
    stream: () => createReadStream(filePath),
  };
};

export const __clientBuildTest = Object.freeze({
  contract: Object.freeze({
    runtime: clientRuntime,
    distribution: clientDistribution,
    buildContractVersion: clientBuildContractVersion,
    metadataVersion: clientMetadataVersion,
  }),
  paths: Object.freeze({
    buildRoot,
    latestFile,
    lastFailureFile,
  }),
  freshnessCacheTtlMs,
  performancePolicy: clientPerformancePolicy,
  electronRuntimeConfig,
  targetMatrix: clientTargetMatrix,
  windowsNsisOptions,
  prepareElectronApp,
  buildPublicDataSnapshot,
  createBuildEnvironment,
  sanitizeClientPublicData,
  evaluateFreshness,
  persistSuccessfulMetadata,
  persistFailureMetadata,
  invalidateFreshnessCache,
  setFreshnessHashProvider(provider) {
    freshnessHashProvider = typeof provider === 'function' ? provider : null;
    invalidateFreshnessCache();
  },
  setShellCatalogProvider(provider) {
    shellCatalogProvider = typeof provider === 'function' ? provider : null;
    shellCatalogCache = null;
  },
});
