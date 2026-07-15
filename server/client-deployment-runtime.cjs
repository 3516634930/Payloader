'use strict';

const { readFile, realpath, stat } = require('node:fs/promises');
const { posix, win32, relative, resolve, isAbsolute, sep } = require('node:path');

const CLIENT_BUILD_CONTRACT_VERSION = 7;
const CLIENT_DEPLOYMENT_FORMAT = 'payloader.deployment.v1';
const CLIENT_DEPLOYMENT_PACKAGE_VERSION = 1;
const maxManifestBytes = 256 * 1024;
const maxPackageFileBytes = 128 * 1024 * 1024;
const sha256Pattern = /^[a-f0-9]{64}$/;
const safeLogoRoutePattern = /^\/uploads\/logo\/logo-[A-Za-z0-9.-]+\.(?:png|jpe?g|webp)$/;
const safeAssetFilePattern = /^assets\/uploads\/logo\/logo-[A-Za-z0-9.-]+\.(?:png|jpe?g|webp)$/;

const unique = values => [...new Set(values.filter(Boolean))];

const resolveDeploymentPackageCandidates = options => {
  const platform = options?.platform || process.platform;
  const pathApi = platform === 'win32' ? win32 : posix;
  const execPath = String(options?.execPath || process.execPath || '');
  const appImagePath = String(options?.appImagePath || '');
  const configuredPath = String(options?.configuredPath || '');
  const candidates = [];

  if (configuredPath && pathApi.isAbsolute(configuredPath)) {
    candidates.push(pathApi.normalize(configuredPath));
  }
  if (platform === 'linux' && appImagePath && pathApi.isAbsolute(appImagePath)) {
    candidates.push(pathApi.join(pathApi.dirname(appImagePath), 'deployment.payloader'));
  }
  if (execPath && pathApi.isAbsolute(execPath)) {
    const executableDirectory = pathApi.dirname(execPath);
    candidates.push(platform === 'darwin'
      ? pathApi.resolve(executableDirectory, '..', '..', '..', 'deployment.payloader')
      : pathApi.join(executableDirectory, 'deployment.payloader'));
  }
  return unique(candidates);
};

const validateDescriptor = (descriptor, label, filePattern) => {
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
    throw new Error(`Invalid deployment file descriptor: ${label}`);
  }
  if (filePattern && !filePattern.test(String(descriptor.file || ''))) {
    throw new Error(`Unsafe deployment asset path: ${label}`);
  }
  if (!sha256Pattern.test(String(descriptor.sha256 || ''))) {
    throw new Error(`Invalid deployment SHA256: ${label}`);
  }
  if (!Number.isSafeInteger(descriptor.size) || descriptor.size < 0 || descriptor.size > maxPackageFileBytes) {
    throw new Error(`Invalid deployment file size: ${label}`);
  }
};

const validateManifest = (manifest, expectedContract = CLIENT_BUILD_CONTRACT_VERSION) => {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('Invalid deployment manifest.');
  }
  if (manifest.format !== CLIENT_DEPLOYMENT_FORMAT || manifest.packageVersion !== CLIENT_DEPLOYMENT_PACKAGE_VERSION) {
    throw new Error('Unsupported deployment package format.');
  }
  if (manifest.buildContractVersion !== expectedContract) {
    throw new Error('Incompatible deployment build contract.');
  }
  if (!manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files)) {
    throw new Error('Invalid deployment file map.');
  }
  for (const fileName of ['public-data.json', 'custom-tools.json']) {
    validateDescriptor(manifest.files[fileName], fileName);
  }
  if (Object.keys(manifest.files).some(fileName => !['public-data.json', 'custom-tools.json'].includes(fileName))) {
    throw new Error('Unexpected deployment file entry.');
  }
  if (!manifest.assets || typeof manifest.assets !== 'object' || Array.isArray(manifest.assets)) {
    throw new Error('Invalid deployment asset map.');
  }
  for (const [route, descriptor] of Object.entries(manifest.assets)) {
    if (!safeLogoRoutePattern.test(route)) throw new Error(`Unsafe deployment asset route: ${route}`);
    validateDescriptor(descriptor, route, safeAssetFilePattern);
  }
  return manifest;
};

const isInside = (baseDir, target) => {
  const fromBase = relative(baseDir, target);
  return Boolean(fromBase) && fromBase !== '..' && !fromBase.startsWith(`..${sep}`) && !isAbsolute(fromBase);
};

const resolveVerifiedFile = async (root, realRoot, relativeFile, expectedSize) => {
  const target = resolve(root, relativeFile);
  if (!isInside(root, target)) throw new Error(`Unsafe deployment file path: ${relativeFile}`);
  const realTarget = await realpath(target);
  if (!isInside(realRoot, realTarget)) throw new Error(`Deployment file escapes package root: ${relativeFile}`);
  const fileStats = await stat(realTarget);
  if (!fileStats.isFile()) throw new Error(`Deployment entry is not a file: ${relativeFile}`);
  if (fileStats.size !== expectedSize) throw new Error(`Deployment file size mismatch: ${relativeFile}`);
  return realTarget;
};

const loadExternalDeploymentPackage = async (candidates, options = {}) => {
  for (const candidate of unique(Array.isArray(candidates) ? candidates : [])) {
    const rootStats = await stat(candidate).catch(() => null);
    if (!rootStats) continue;
    if (!rootStats.isDirectory()) throw new Error(`Deployment package is not a directory: ${candidate}`);

    const realRoot = await realpath(candidate);
    const manifestPath = resolve(candidate, 'manifest.json');
    const manifestStats = await stat(manifestPath).catch(() => null);
    if (!manifestStats?.isFile()) throw new Error(`Deployment manifest is missing: ${candidate}`);
    if (manifestStats.size <= 0 || manifestStats.size > (options.maxManifestBytes || maxManifestBytes)) {
      throw new Error('Deployment manifest is oversized.');
    }
    const realManifestPath = await realpath(manifestPath);
    if (!isInside(realRoot, realManifestPath)) {
      throw new Error('Deployment manifest escapes package root.');
    }

    let manifest;
    try {
      manifest = JSON.parse(await readFile(realManifestPath, 'utf8'));
    } catch {
      throw new Error('Deployment manifest is invalid JSON.');
    }
    validateManifest(manifest, options.buildContractVersion ?? CLIENT_BUILD_CONTRACT_VERSION);

    const publicDataPath = await resolveVerifiedFile(
      candidate,
      realRoot,
      'public-data.json',
      manifest.files['public-data.json'].size,
    );
    const customToolsPath = await resolveVerifiedFile(
      candidate,
      realRoot,
      'custom-tools.json',
      manifest.files['custom-tools.json'].size,
    );
    const assets = {};
    for (const [route, descriptor] of Object.entries(manifest.assets)) {
      assets[route] = {
        ...descriptor,
        target: await resolveVerifiedFile(candidate, realRoot, descriptor.file, descriptor.size),
      };
    }
    return {
      root: candidate,
      realRoot,
      manifest,
      manifestPath,
      publicDataPath,
      customToolsPath,
      assets,
    };
  }
  return null;
};

module.exports = Object.freeze({
  CLIENT_BUILD_CONTRACT_VERSION,
  CLIENT_DEPLOYMENT_FORMAT,
  CLIENT_DEPLOYMENT_PACKAGE_VERSION,
  loadExternalDeploymentPackage,
  resolveDeploymentPackageCandidates,
  validateManifest,
});
