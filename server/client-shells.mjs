import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import {
  copyFile,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { createGunzip, createGzip } from 'node:zlib';
import { ZipArchive } from 'archiver';
import { c as createTar, t as listTar, x as extractTar } from 'tar';
import tarStream from 'tar-stream';

import {
  CLIENT_BUILD_CONTRACT_VERSION,
  CLIENT_DEPLOYMENT_PACKAGE_VERSION,
} from './client-deployment-package.mjs';
import { parseGitHubRepository } from './version-checker.mjs';

export const CLIENT_SHELL_FORMAT = 'payloader.client-shells.v1';
export const CLIENT_SHELL_MANIFEST_VERSION = 1;
export const CLIENT_SHELL_MANIFEST_FILE = 'payloader-client-shells.json';

const maxManifestBytes = 512 * 1024;
const maxShellArchiveBytes = 768 * 1024 * 1024;
const maxArchiveEntryBytes = 2 * 1024 * 1024 * 1024;
const maxExtractedBytes = 2 * 1024 * 1024 * 1024;
const maxArchiveEntries = 20_000;
const maxRedirects = 5;
const minimumShellDownloadTimeoutMs = 10 * 60_000;
const maximumShellDownloadTimeoutMs = 30 * 60_000;
const minimumExpectedDownloadBytesPerSecond = 128 * 1024;
const sha256Pattern = /^[a-f0-9]{64}$/;
const archiveNamePattern = /^payloader-shell-[a-z0-9-]+\.tar\.gz$/;
const allowedDownloadHosts = new Set([
  'api.github.com',
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
]);
const downloadInflight = new Map();
const destinationInflight = new Set();
const windowsSystemDownloader = fileURLToPath(new URL('./download-client-shell.ps1', import.meta.url));

export const clientShellDownloadTransport = (platform = process.platform, hasInjectedFetch = false) => (
  platform === 'win32' && !hasInjectedFetch ? 'windows-system-http' : 'fetch'
);

export const clientShellDownloadTimeoutMs = (size, override) => {
  const configured = Number(override);
  if (Number.isFinite(configured) && configured > 0) return Math.trunc(configured);
  const expectedSize = Number(size);
  const transferMs = Number.isFinite(expectedSize) && expectedSize > 0
    ? Math.ceil((expectedSize / minimumExpectedDownloadBytesPerSecond) * 1000)
    : 0;
  return Math.min(
    maximumShellDownloadTimeoutMs,
    Math.max(minimumShellDownloadTimeoutMs, transferMs + 60_000),
  );
};

export const CLIENT_SHELL_TARGETS = Object.freeze({
  'win-x64-nsis': Object.freeze({ platform: 'windows', arch: 'x64', outputFormat: 'zip' }),
  'win-arm64-nsis': Object.freeze({ platform: 'windows', arch: 'arm64', outputFormat: 'zip' }),
  'win-ia32-nsis': Object.freeze({ platform: 'windows', arch: 'ia32', outputFormat: 'zip' }),
  'linux-x64-appimage': Object.freeze({ platform: 'linux', arch: 'x64', outputFormat: 'tar.gz' }),
  'linux-arm64-appimage': Object.freeze({ platform: 'linux', arch: 'arm64', outputFormat: 'tar.gz' }),
  'linux-armv7l-appimage': Object.freeze({ platform: 'linux', arch: 'armv7l', outputFormat: 'tar.gz' }),
  'mac-x64-dmg': Object.freeze({ platform: 'macos', arch: 'x64', outputFormat: 'tar.gz' }),
  'mac-arm64-dmg': Object.freeze({ platform: 'macos', arch: 'arm64', outputFormat: 'tar.gz' }),
  'mac-universal-dmg': Object.freeze({ platform: 'macos', arch: 'universal', outputFormat: 'tar.gz' }),
});

const hashFile = filePath => new Promise((resolveHash, rejectHash) => {
  const hash = createHash('sha256');
  const stream = createReadStream(filePath);
  stream.on('data', chunk => hash.update(chunk));
  stream.on('error', rejectHash);
  stream.on('end', () => resolveHash(hash.digest('hex')));
});

const fileDetails = async filePath => {
  const fileStats = await stat(filePath);
  if (!fileStats.isFile()) throw new Error('Client shell archive is not a file.');
  if (fileStats.size <= 0 || fileStats.size > maxShellArchiveBytes) {
    throw new Error('Client shell archive is oversized.');
  }
  return { size: fileStats.size, sha256: await hashFile(filePath) };
};

const validateShellDescriptor = (targetId, descriptor) => {
  const expected = CLIENT_SHELL_TARGETS[targetId];
  if (!expected) throw new Error(`Unknown client shell target: ${targetId}`);
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
    throw new Error(`Invalid client shell descriptor: ${targetId}`);
  }
  if (!archiveNamePattern.test(String(descriptor.archive || ''))) {
    throw new Error(`Unsafe client shell archive name: ${targetId}`);
  }
  if (!Number.isSafeInteger(descriptor.size) || descriptor.size <= 0 || descriptor.size > maxShellArchiveBytes) {
    throw new Error(`Invalid client shell archive size: ${targetId}`);
  }
  if (!sha256Pattern.test(String(descriptor.sha256 || ''))) {
    throw new Error(`Invalid client shell archive hash: ${targetId}`);
  }
  for (const key of ['platform', 'arch', 'outputFormat']) {
    if (descriptor[key] !== expected[key]) {
      throw new Error(`Invalid client shell ${key}: ${targetId}`);
    }
  }
  if (typeof descriptor.signed !== 'boolean') {
    throw new Error(`Invalid client shell signing status: ${targetId}`);
  }
  return descriptor;
};

export const validateClientShellManifest = (manifest, options = {}) => {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('Invalid client shell manifest.');
  }
  if (manifest.format !== CLIENT_SHELL_FORMAT || manifest.manifestVersion !== CLIENT_SHELL_MANIFEST_VERSION) {
    throw new Error('Unsupported client shell manifest format.');
  }
  if (manifest.buildContractVersion !== (options.buildContractVersion ?? CLIENT_BUILD_CONTRACT_VERSION)) {
    throw new Error('Incompatible client shell build contract.');
  }
  if (manifest.deploymentPackageVersion !== CLIENT_DEPLOYMENT_PACKAGE_VERSION) {
    throw new Error('Incompatible client shell deployment package version.');
  }
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(String(manifest.appVersion || ''))) {
    throw new Error('Invalid client shell application version.');
  }
  if (options.appVersion && manifest.appVersion !== options.appVersion) {
    throw new Error('Incompatible client shell application version.');
  }
  if (!manifest.targets || typeof manifest.targets !== 'object' || Array.isArray(manifest.targets)) {
    throw new Error('Invalid client shell target map.');
  }
  const entries = Object.entries(manifest.targets);
  if (!entries.length || entries.length > Object.keys(CLIENT_SHELL_TARGETS).length) {
    throw new Error('Invalid client shell target count.');
  }
  const archiveNames = new Set();
  for (const [targetId, descriptor] of entries) {
    validateShellDescriptor(targetId, descriptor);
    if (archiveNames.has(descriptor.archive)) throw new Error('Duplicate client shell archive name.');
    archiveNames.add(descriptor.archive);
  }
  return manifest;
};

const safeArchivePath = value => {
  const raw = String(value || '');
  if (
    !raw
    || raw.includes('\0')
    || raw.includes('\\')
    || raw.startsWith('/')
    || /^[A-Za-z]:/.test(raw)
  ) return '';
  if (raw.split('/').includes('..')) return '';
  const normalized = posix.normalize(raw.replace(/^\.\//, ''));
  if (!normalized || normalized === '.' || normalized === '..' || normalized.startsWith('../')) return '';
  return normalized.replace(/\/$/, '');
};

export const validateShellArchiveEntry = entry => {
  const safePath = safeArchivePath(entry?.path);
  if (!safePath) throw new Error(`Unsafe shell archive path: ${String(entry?.path || '')}`);
  const type = String(entry?.type || '');
  if (type === 'SymbolicLink') {
    const linkPath = String(entry?.linkpath || '');
    if (
      !linkPath
      || linkPath.includes('\0')
      || linkPath.includes('\\')
      || linkPath.startsWith('/')
      || /^[A-Za-z]:/.test(linkPath)
    ) {
      throw new Error('Unsafe client shell symbolic link.');
    }
    const resolvedLink = posix.normalize(posix.join(posix.dirname(safePath), linkPath));
    if (resolvedLink === '..' || resolvedLink.startsWith('../')) {
      throw new Error('Client shell symbolic link escapes the archive root.');
    }
    return true;
  }
  if (type === 'Link') {
    throw new Error('Client shell hard links are not allowed.');
  }
  if (!['File', 'OldFile', 'Directory'].includes(type)) {
    throw new Error(`Unsupported client shell archive entry type: ${type}`);
  }
  const size = Number(entry?.size || 0);
  if (!Number.isSafeInteger(size) || size < 0 || size > maxArchiveEntryBytes) {
    throw new Error('Client shell archive entry is oversized.');
  }
  return true;
};

const inspectShellArchive = async archivePath => {
  const paths = new Set();
  const pathTypes = new Map();
  const entries = new Map();
  const deploymentRoots = new Set();
  let entryCount = 0;
  let extractedBytes = 0;
  await listTar({
    file: archivePath,
    strict: true,
    onentry: entry => {
      validateShellArchiveEntry(entry);
      const safePath = safeArchivePath(entry.path);
      entryCount += 1;
      extractedBytes += Number(entry.size || 0);
      if (entryCount > maxArchiveEntries) throw new Error('Client shell archive has too many entries.');
      if (extractedBytes > maxExtractedBytes) throw new Error('Client shell archive expands beyond the allowed size.');
      if (paths.has(safePath)) throw new Error(`Duplicate client shell archive entry: ${safePath}`);
      paths.add(safePath);
      const type = String(entry.type || '') === 'OldFile' ? 'File' : String(entry.type || '');
      pathTypes.set(safePath, type);
      entries.set(safePath, {
        type,
        size: Number(entry.size || 0),
        linkpath: String(entry.linkpath || ''),
      });
      const parts = safePath.split('/');
      const deploymentIndex = parts.indexOf('deployment.payloader');
      if (deploymentIndex >= 0) {
        deploymentRoots.add(parts.slice(0, deploymentIndex + 1).join('/'));
      }
    },
  });
  if (deploymentRoots.size !== 1) {
    throw new Error('Client shell must contain exactly one deployment.payloader directory.');
  }
  for (const archivePath of paths) {
    let parent = posix.dirname(archivePath);
    while (parent && parent !== '.') {
      if (pathTypes.get(parent) === 'SymbolicLink') {
        throw new Error(`Client shell archive entry is nested below a symbolic link: ${archivePath}`);
      }
      parent = posix.dirname(parent);
    }
  }
  const deploymentRoot = [...deploymentRoots][0];
  if (pathTypes.get(deploymentRoot) !== 'Directory') {
    throw new Error('Client shell deployment.payloader entry must be a directory.');
  }
  return { deploymentRoot, entries, paths };
};

const extractShellArchive = async (archivePath, destination, inspection) => {
  const allowedPaths = inspection?.paths || (await inspectShellArchive(archivePath)).paths;
  await mkdir(destination, { recursive: true });
  await extractTar({
    file: archivePath,
    cwd: destination,
    strict: true,
    preservePaths: false,
    filter: path => allowedPaths.has(safeArchivePath(path)),
  });
};

const validateExtractedLinks = async root => {
  const directories = [root];
  const realRoot = await realpath(root);
  let visited = 0;
  for (let index = 0; index < directories.length; index += 1) {
    const directory = directories[index];
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      visited += 1;
      if (visited > maxArchiveEntries) throw new Error('Extracted client shell has too many files.');
      const target = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        const realTarget = await realpath(target);
        const fromRoot = relative(realRoot, realTarget);
        if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
          throw new Error('Extracted client shell link escapes the archive root.');
        }
        continue;
      }
      if (entry.isDirectory()) directories.push(target);
    }
  }
};

const writeZip = async (sourceDirectory, destination) => new Promise((resolveArchive, rejectArchive) => {
  const output = createWriteStream(destination, { flags: 'wx' });
  const archive = new ZipArchive({ zlib: { level: 6 } });
  const fail = error => rejectArchive(error);
  output.on('close', resolveArchive);
  output.on('error', fail);
  archive.on('warning', fail);
  archive.on('error', fail);
  archive.pipe(output);
  archive.directory(sourceDirectory, false);
  void archive.finalize();
});

const writeTarGzip = async (sourceDirectory, destination) => {
  const entries = (await readdir(sourceDirectory)).sort();
  if (!entries.length) throw new Error('Client shell archive is empty.');
  await createTar({
    file: destination,
    cwd: sourceDirectory,
    gzip: true,
    portable: true,
    noMtime: true,
    strict: true,
  }, entries);
};

const isArchivePathWithin = (archivePath, root) => (
  archivePath === root || archivePath.startsWith(`${root}/`)
);

const tarStreamEntryForValidation = header => {
  const type = {
    directory: 'Directory',
    file: 'File',
    link: 'Link',
    symlink: 'SymbolicLink',
  }[String(header?.type || '')] || String(header?.type || '');
  return {
    path: header?.name,
    type,
    linkpath: header?.linkname,
    size: header?.size,
  };
};

const copyTarStreamEntry = async (pack, header, source) => new Promise((resolveEntry, rejectEntry) => {
  let settled = false;
  const finish = error => {
    if (settled) return;
    settled = true;
    if (error) rejectEntry(error);
    else resolveEntry();
  };
  let destination;
  try {
    destination = pack.entry({ ...header }, finish);
  } catch (error) {
    finish(error);
    return;
  }
  source.once('error', finish);
  destination.once('error', finish);
  source.pipe(destination);
});

const addTarStreamEntry = async (pack, header, sourcePath) => {
  if (!sourcePath) {
    await new Promise((resolveEntry, rejectEntry) => {
      try {
        pack.entry(header, error => (error ? rejectEntry(error) : resolveEntry()));
      } catch (error) {
        rejectEntry(error);
      }
    });
    return;
  }
  await copyTarStreamEntry(pack, header, createReadStream(sourcePath));
};

const appendDeploymentToTarStream = async (pack, sourceDirectory, archiveRoot) => {
  const appendDirectory = async (source, archivePath) => {
    const directoryStats = await lstat(source);
    if (!directoryStats.isDirectory()) throw new Error('Client deployment package contains an invalid directory.');
    await addTarStreamEntry(pack, {
      name: `${archivePath.replace(/\/$/, '')}/`,
      type: 'directory',
      mode: directoryStats.mode & 0o777,
      uid: 0,
      gid: 0,
      size: 0,
      mtime: new Date(0),
    });
    const entries = (await readdir(source, { withFileTypes: true }))
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const sourcePath = join(source, entry.name);
      const entryArchivePath = `${archivePath.replace(/\/$/, '')}/${entry.name}`;
      const entryStats = await lstat(sourcePath);
      if (entryStats.isSymbolicLink()) {
        throw new Error('Client deployment package symbolic links are not allowed.');
      }
      if (entryStats.isDirectory()) {
        await appendDirectory(sourcePath, entryArchivePath);
        continue;
      }
      if (!entryStats.isFile()) {
        throw new Error('Client deployment package contains an unsupported filesystem entry.');
      }
      await addTarStreamEntry(pack, {
        name: entryArchivePath,
        type: 'file',
        mode: entryStats.mode & 0o777,
        uid: 0,
        gid: 0,
        size: entryStats.size,
        mtime: new Date(0),
      }, sourcePath);
    }
  };
  await appendDirectory(sourceDirectory, archiveRoot);
};

const repackTarGzipWithDeployment = async options => {
  const {
    shellArchive,
    destination,
    inspection,
    replacementRoot,
  } = options;
  const input = createReadStream(shellArchive);
  const gunzip = createGunzip();
  const extract = tarStream.extract();
  const pack = tarStream.pack();
  const gzip = createGzip({ level: 6 });
  const output = createWriteStream(destination, { flags: 'wx' });
  const inputResult = pipeline(input, gunzip, extract);
  const outputResult = pipeline(pack, gzip, output);
  const seen = new Set();
  let entryCount = 0;
  let extractedBytes = 0;
  try {
    for await (const entry of extract) {
      const archiveEntry = tarStreamEntryForValidation(entry.header);
      validateShellArchiveEntry(archiveEntry);
      const safePath = safeArchivePath(archiveEntry.path);
      const expectedEntry = inspection.entries.get(safePath);
      if (!expectedEntry || seen.has(safePath)) {
        throw new Error(`Unexpected client shell archive entry: ${safePath}`);
      }
      seen.add(safePath);
      entryCount += 1;
      extractedBytes += Number(archiveEntry.size || 0);
      if (entryCount > maxArchiveEntries || extractedBytes > maxExtractedBytes) {
        throw new Error('Client shell archive changed after validation.');
      }
      const actualEntry = {
        type: archiveEntry.type === 'OldFile' ? 'File' : archiveEntry.type,
        size: Number(archiveEntry.size || 0),
        linkpath: String(archiveEntry.linkpath || ''),
      };
      if (
        actualEntry.type !== expectedEntry.type
        || actualEntry.size !== expectedEntry.size
        || actualEntry.linkpath !== expectedEntry.linkpath
      ) {
        throw new Error(`Client shell archive entry changed after validation: ${safePath}`);
      }
      if (isArchivePathWithin(safePath, inspection.deploymentRoot)) {
        entry.resume();
        continue;
      }
      await copyTarStreamEntry(pack, entry.header, entry);
    }
    await inputResult;
    if (seen.size !== inspection.paths.size) {
      throw new Error('Client shell archive changed after validation.');
    }
    const deploymentSource = join(replacementRoot, ...inspection.deploymentRoot.split('/'));
    await appendDeploymentToTarStream(pack, deploymentSource, inspection.deploymentRoot);
    pack.finalize();
    await outputResult;
  } catch (error) {
    input.destroy(error);
    gunzip.destroy(error);
    extract.destroy(error);
    pack.destroy(error);
    gzip.destroy(error);
    output.destroy(error);
    await Promise.allSettled([inputResult, outputResult]);
    throw error;
  }
};

const publishArchive = async (temporary, destination) => {
  await mkdir(dirname(destination), { recursive: true });
  await rename(temporary, destination);
};

const acquireDestinationLock = async (destination, action) => {
  const key = resolve(destination);
  if (destinationInflight.has(key)) {
    throw new Error(`Client shell destination is already being ${action}: ${key}`);
  }
  destinationInflight.add(key);
  const lockPath = `${key}.lock`;
  let lockHandle;
  try {
    await mkdir(dirname(key), { recursive: true });
    try {
      lockHandle = await open(lockPath, 'wx');
    } catch (error) {
      if (error?.code === 'EEXIST') {
        throw new Error(`Client shell destination is already being ${action}: ${key}`);
      }
      throw error;
    }
    await lockHandle.writeFile(`${process.pid}\n`, 'utf8');
  } catch (error) {
    await lockHandle?.close().catch(() => {});
    if (lockHandle) await rm(lockPath, { force: true }).catch(() => {});
    destinationInflight.delete(key);
    throw error;
  }
  return async () => {
    try {
      await lockHandle.close();
    } finally {
      await rm(lockPath, { force: true }).catch(() => {});
      destinationInflight.delete(key);
    }
  };
};

export const assembleClientShell = async options => {
  const shellArchive = resolve(String(options?.shellArchive || ''));
  const deploymentPackageDir = resolve(String(options?.deploymentPackageDir || ''));
  const destination = resolve(String(options?.destination || ''));
  const shell = options?.shell;
  if (!shellArchive || !deploymentPackageDir || !destination || !shell) {
    throw new Error('Client shell assembly options are incomplete.');
  }
  const releaseLock = await acquireDestinationLock(destination, 'assembled');
  let workDirectory = '';
  let temporaryOutput = '';
  try {
    const deploymentStats = await stat(deploymentPackageDir).catch(() => null);
    if (!deploymentStats?.isDirectory()) throw new Error('Client deployment package is missing.');
    const workRoot = resolve(String(options.workRoot || tmpdir()));
    await mkdir(workRoot, { recursive: true });
    workDirectory = await mkdtemp(join(workRoot, 'payloader-shell-assemble-'));
    const shellArchiveSnapshot = join(workDirectory, 'official-shell.tar.gz');
    const extractedRoot = join(workDirectory, 'extracted');
    const replacementRoot = join(workDirectory, 'replacement');
    temporaryOutput = `${destination}.tmp-${randomUUID()}`;
    await copyFile(shellArchive, shellArchiveSnapshot, 1);
    const details = await fileDetails(shellArchiveSnapshot);
    if (details.size !== shell.size) throw new Error('Client shell archive size mismatch.');
    if (details.sha256 !== shell.sha256) throw new Error('Client shell archive hash mismatch.');
    const inspection = await inspectShellArchive(shellArchiveSnapshot);
    await mkdir(dirname(temporaryOutput), { recursive: true });
    if (shell.outputFormat === 'zip') {
      await extractShellArchive(shellArchiveSnapshot, extractedRoot, inspection);
      await validateExtractedLinks(extractedRoot);
      const deploymentTarget = join(extractedRoot, ...inspection.deploymentRoot.split('/'));
      await rm(deploymentTarget, { recursive: true, force: true });
      await cp(deploymentPackageDir, deploymentTarget, { recursive: true, errorOnExist: true });
      await writeZip(extractedRoot, temporaryOutput);
    } else if (shell.outputFormat === 'tar.gz') {
      const deploymentTarget = join(replacementRoot, ...inspection.deploymentRoot.split('/'));
      await mkdir(dirname(deploymentTarget), { recursive: true });
      await cp(deploymentPackageDir, deploymentTarget, { recursive: true, errorOnExist: true });
      await repackTarGzipWithDeployment({
        shellArchive: shellArchiveSnapshot,
        destination: temporaryOutput,
        inspection,
        replacementRoot,
      });
    } else {
      throw new Error('Unsupported portable client output format.');
    }
    await fileDetails(temporaryOutput);
    await publishArchive(temporaryOutput, destination);
    const outputDetails = await fileDetails(destination);
    return {
      filePath: destination,
      outputFormat: shell.outputFormat,
      size: outputDetails.size,
      sha256: outputDetails.sha256,
      shellSha256: shell.sha256,
    };
  } finally {
    if (workDirectory) await rm(workDirectory, { recursive: true, force: true }).catch(() => {});
    if (temporaryOutput) await rm(temporaryOutput, { force: true }).catch(() => {});
    await releaseLock();
  }
};

const writeSourceFiles = async (root, files) => {
  for (const [relativePath, value] of Object.entries(files || {})) {
    const safePath = safeArchivePath(relativePath);
    if (!safePath) throw new Error(`Unsafe client shell source path: ${relativePath}`);
    const destination = join(root, ...safePath.split('/'));
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, value);
  }
};

export const createClientShellTransport = async options => {
  const destination = resolve(String(options?.destination || ''));
  const deploymentPackageDir = resolve(String(options?.deploymentPackageDir || ''));
  const platform = String(options?.platform || '');
  if (!destination || !deploymentPackageDir || !['windows', 'linux', 'macos'].includes(platform)) {
    throw new Error('Client shell transport options are incomplete.');
  }
  const sourceRoot = options.shellRoot ? resolve(String(options.shellRoot)) : '';
  const sourceStats = sourceRoot ? await stat(sourceRoot).catch(() => null) : null;
  if (!sourceStats?.isDirectory() && !options.sourceFiles) {
    throw new Error('Client shell source directory is missing.');
  }
  const releaseLock = await acquireDestinationLock(destination, 'created');
  let workDirectory = '';
  let temporaryOutput = '';
  try {
    await mkdir(dirname(destination), { recursive: true });
    workDirectory = await mkdtemp(join(dirname(destination), '.payloader-shell-'));
    const stage = join(workDirectory, 'stage');
    temporaryOutput = `${destination}.tmp-${randomUUID()}`;
    await mkdir(stage, { recursive: true });
    if (platform === 'macos') {
      const appName = sourceRoot ? basename(sourceRoot) : 'Payloader.app';
      const appTarget = join(stage, appName);
      if (sourceStats?.isDirectory()) await cp(sourceRoot, appTarget, { recursive: true, verbatimSymlinks: true });
      else await writeSourceFiles(appTarget, options.sourceFiles);
      await cp(deploymentPackageDir, join(stage, 'deployment.payloader'), { recursive: true });
    } else {
      const appTarget = join(stage, 'Payloader');
      if (sourceStats?.isDirectory()) await cp(sourceRoot, appTarget, { recursive: true, verbatimSymlinks: true });
      else await writeSourceFiles(appTarget, options.sourceFiles);
      await cp(deploymentPackageDir, join(appTarget, 'deployment.payloader'), { recursive: true });
    }
    await writeTarGzip(stage, temporaryOutput);
    await fileDetails(temporaryOutput);
    await publishArchive(temporaryOutput, destination);
    return { filePath: destination, ...(await fileDetails(destination)) };
  } finally {
    if (workDirectory) await rm(workDirectory, { recursive: true, force: true }).catch(() => {});
    if (temporaryOutput) await rm(temporaryOutput, { force: true }).catch(() => {});
    await releaseLock();
  }
};

const validateDownloadUrl = value => {
  let parsed;
  try {
    parsed = new URL(String(value || ''));
  } catch {
    throw new Error('Invalid official client shell asset URL.');
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username
    || parsed.password
    || !allowedDownloadHosts.has(parsed.hostname.toLowerCase())
  ) {
    throw new Error('Untrusted official client shell asset URL.');
  }
  return parsed;
};

const fetchWithSafeRedirects = async (initialUrl, options) => {
  let url = validateDownloadUrl(initialUrl);
  for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount += 1) {
    const apiRequest = url.hostname.toLowerCase() === 'api.github.com';
    const response = await options.fetchImpl(url, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(options.timeoutMs),
      headers: {
        accept: options.accept,
        'user-agent': 'Payloader-Client-Shells',
        ...(apiRequest && options.token ? { authorization: `Bearer ${options.token}` } : {}),
        ...(apiRequest ? { 'x-github-api-version': '2022-11-28' } : {}),
      },
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location || redirectCount === maxRedirects) throw new Error('Invalid client shell download redirect.');
      url = validateDownloadUrl(new URL(location, url).href);
      continue;
    }
    return response;
  }
  throw new Error('Too many client shell download redirects.');
};

const responseBytes = async (response, maxBytes) => {
  if (!response.ok) throw new Error(`Official client shell request failed (${response.status}).`);
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error('Official client shell response is oversized.');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maxBytes) throw new Error('Official client shell response is oversized.');
  return bytes;
};

const requestJson = async (url, options) => {
  const response = await fetchWithSafeRedirects(url, {
    ...options,
    accept: 'application/vnd.github+json',
  });
  const bytes = await responseBytes(response, maxManifestBytes);
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('Official client shell response is invalid JSON.');
  }
};

const attachReleaseAssets = (manifest, assets, repository) => {
  const byName = new Map(
    (Array.isArray(assets) ? assets : [])
      .filter(asset => Number.isSafeInteger(asset?.id) && typeof asset?.name === 'string')
      .map(asset => [asset.name, asset]),
  );
  const targets = {};
  for (const [targetId, descriptor] of Object.entries(manifest.targets)) {
    const asset = byName.get(descriptor.archive);
    if (!asset || asset.size !== descriptor.size) {
      throw new Error(`Official client shell release asset is missing: ${descriptor.archive}`);
    }
    targets[targetId] = {
      ...descriptor,
      assetApiUrl: `${repository.apiBaseUrl}/releases/assets/${asset.id}`,
    };
  }
  return targets;
};

const readBoundedJsonFile = async filePath => {
  const details = await stat(filePath);
  if (!details.isFile() || details.size <= 0 || details.size > maxManifestBytes) {
    throw new Error('Client shell manifest file is oversized.');
  }
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch {
    throw new Error('Client shell manifest file is invalid JSON.');
  }
};

export const loadClientShellCatalog = async options => {
  const localDirectory = String(options?.localDirectory || '').trim();
  if (localDirectory) {
    const root = resolve(localDirectory);
    const manifest = validateClientShellManifest(
      await readBoundedJsonFile(join(root, CLIENT_SHELL_MANIFEST_FILE)),
      options,
    );
    const targets = Object.fromEntries(Object.entries(manifest.targets).map(([targetId, descriptor]) => [
      targetId,
      { ...descriptor, localPath: join(root, descriptor.archive) },
    ]));
    return { source: 'local', manifest, targets };
  }

  const repository = parseGitHubRepository(options?.repositoryUrl);
  const fetchImpl = options?.fetchImpl || globalThis.fetch;
  const token = String(options?.token || '').trim();
  const timeoutMs = Number(options?.timeoutMs || 20_000);
  const requestOptions = { fetchImpl, token, timeoutMs };
  const appVersion = String(options?.appVersion || '').trim();
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(appVersion)) {
    throw new Error('Client shell application version is required for the remote catalog.');
  }
  const releaseTag = `v${appVersion}`;
  const release = await requestJson(
    `${repository.apiBaseUrl}/releases/tags/${encodeURIComponent(releaseTag)}`,
    requestOptions,
  );
  if (release?.draft || release?.prerelease || !Array.isArray(release?.assets)) {
    throw new Error('Official client shell Release is unavailable.');
  }
  const manifestAsset = release.assets.find(asset => asset?.name === CLIENT_SHELL_MANIFEST_FILE);
  if (!manifestAsset || !Number.isSafeInteger(manifestAsset.id)) {
    throw new Error('Official client shell manifest asset is unavailable.');
  }
  const manifestResponse = await fetchWithSafeRedirects(
    `${repository.apiBaseUrl}/releases/assets/${manifestAsset.id}`,
    { ...requestOptions, accept: 'application/octet-stream' },
  );
  const manifestBytes = await responseBytes(manifestResponse, maxManifestBytes);
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch {
    throw new Error('Official client shell manifest is invalid JSON.');
  }
  validateClientShellManifest(manifest, options);
  return {
    source: 'github-release',
    release: {
      id: Number.isSafeInteger(release.id) ? release.id : null,
      tagName: String(release.tag_name || '').slice(0, 128),
      publishedAt: String(release.published_at || '').slice(0, 64),
    },
    manifest,
    targets: attachReleaseAssets(manifest, release.assets, repository),
  };
};

const streamResponseToFile = async (response, destination, expectedSize) => {
  if (!response.ok || !response.body) throw new Error(`Official client shell download failed (${response.status}).`);
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared !== expectedSize) {
    throw new Error('Client shell download size mismatch.');
  }
  let received = 0;
  const limiter = new Transform({
    transform(chunk, _encoding, callback) {
      received += chunk.length;
      if (received > expectedSize || received > maxShellArchiveBytes) {
        callback(new Error('Client shell download exceeded the declared size.'));
        return;
      }
      callback(null, chunk);
    },
  });
  const input = typeof response.body.getReader === 'function'
    ? Readable.fromWeb(response.body)
    : Readable.from(response.body);
  await pipeline(input, limiter, createWriteStream(destination, { flags: 'wx' }));
  if (received !== expectedSize) throw new Error('Client shell download size mismatch.');
};

const downloadWithWindowsSystemHttp = ({ url, destination, expectedSize, timeoutMs, token }) => new Promise((resolveDownload, rejectDownload) => {
  const args = [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    windowsSystemDownloader,
    '-Url',
    String(url),
    '-Destination',
    String(destination),
    '-ExpectedSize',
    String(expectedSize),
    '-TimeoutMs',
    String(timeoutMs),
  ];
  const child = spawn('powershell.exe', args, {
    env: {
      ...process.env,
      PAYLOADER_CLIENT_SHELL_TOKEN: String(token || '').trim(),
    },
    windowsHide: true,
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let errorOutput = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => {
    errorOutput = `${errorOutput}${chunk}`.slice(-8_192);
  });
  child.once('error', rejectDownload);
  child.once('close', code => {
    if (code === 0) {
      resolveDownload();
      return;
    }
    const detail = errorOutput.trim().split(/\r?\n/).filter(Boolean).at(-1) || `exit code ${code}`;
    rejectDownload(new Error(`Windows system client shell download failed: ${detail}`));
  });
});

const acquireUncachedArchive = async (entry, options, cacheFile) => {
  const temporary = `${cacheFile}.tmp-${randomUUID()}`;
  try {
    await mkdir(dirname(cacheFile), { recursive: true });
    if (entry.localPath) {
      await copyFile(entry.localPath, temporary, 1);
    } else {
      const timeoutMs = clientShellDownloadTimeoutMs(entry.size, options.timeoutMs);
      const transport = clientShellDownloadTransport(process.platform, Boolean(options.fetchImpl));
      if (transport === 'windows-system-http') {
        await downloadWithWindowsSystemHttp({
          url: entry.assetApiUrl,
          destination: temporary,
          expectedSize: entry.size,
          timeoutMs,
          token: options.token,
        });
      } else {
        const response = await fetchWithSafeRedirects(entry.assetApiUrl, {
          fetchImpl: options.fetchImpl || globalThis.fetch,
          token: String(options.token || '').trim(),
          timeoutMs,
          accept: 'application/octet-stream',
        });
        await streamResponseToFile(response, temporary, entry.size);
      }
    }
    const details = await fileDetails(temporary);
    if (details.size !== entry.size) throw new Error('Client shell archive size mismatch.');
    if (details.sha256 !== entry.sha256) throw new Error('Client shell archive hash mismatch.');
    await rename(temporary, cacheFile).catch(async error => {
      if ((await stat(cacheFile).catch(() => null))?.isFile()) return;
      throw error;
    });
    return cacheFile;
  } finally {
    await rm(temporary, { force: true }).catch(() => {});
  }
};

export const acquireClientShellArchive = async (entry, options = {}) => {
  if (!entry || !sha256Pattern.test(String(entry.sha256 || ''))) {
    throw new Error('Invalid client shell cache descriptor.');
  }
  if (!Number.isSafeInteger(entry.size) || entry.size <= 0 || entry.size > maxShellArchiveBytes) {
    throw new Error('Invalid client shell cache size.');
  }
  const cacheRoot = resolve(String(options.cacheRoot || join(tmpdir(), 'payloader-client-shells')));
  const cacheFile = join(cacheRoot, `${entry.sha256}.tar.gz`);
  const existing = await stat(cacheFile).catch(() => null);
  if (existing?.isFile() && existing.size === entry.size && await hashFile(cacheFile) === entry.sha256) {
    return cacheFile;
  }
  if (existing) await rm(cacheFile, { force: true });
  const key = `${cacheFile}:${entry.size}`;
  if (!downloadInflight.has(key)) {
    downloadInflight.set(key, acquireUncachedArchive(entry, options, cacheFile).finally(() => {
      downloadInflight.delete(key);
    }));
  }
  return downloadInflight.get(key);
};

export const pruneClientShellCache = async (cacheRootValue, targets) => {
  if (!targets || typeof targets !== 'object' || Array.isArray(targets)) return { removed: 0 };
  const retained = new Set(
    Object.values(targets)
      .map(entry => String(entry?.sha256 || ''))
      .filter(value => sha256Pattern.test(value))
      .map(value => `${value}.tar.gz`),
  );
  if (!retained.size) return { removed: 0 };
  const cacheRoot = resolve(String(cacheRootValue || ''));
  const entries = await readdir(cacheRoot, { withFileTypes: true }).catch(error => {
    if (error?.code === 'ENOENT') return [];
    throw error;
  });
  let removed = 0;
  for (const entry of entries) {
    if (!entry.isFile() || !/^[a-f0-9]{64}\.tar\.gz$/.test(entry.name) || retained.has(entry.name)) continue;
    await rm(join(cacheRoot, entry.name), { force: true });
    removed += 1;
  }
  return { removed };
};
