import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, mkdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, extname, join } from 'node:path';

export const CLIENT_BUILD_CONTRACT_VERSION = 7;
export const CLIENT_DEPLOYMENT_FORMAT = 'payloader.deployment.v1';
export const CLIENT_DEPLOYMENT_PACKAGE_VERSION = 1;

const maxPackageFileBytes = 128 * 1024 * 1024;
const sha256Pattern = /^[a-f0-9]{64}$/;
const safeLogoRoutePattern = /^\/uploads\/logo\/logo-[A-Za-z0-9.-]+\.(?:png|jpe?g|webp)$/;
const safeAssetFilePattern = /^assets\/uploads\/logo\/logo-[A-Za-z0-9.-]+\.(?:png|jpe?g|webp)$/;
const requiredFiles = Object.freeze(['public-data.json', 'custom-tools.json']);

const jsonBytes = value => Buffer.from(JSON.stringify(value), 'utf8');
const hashBytes = value => createHash('sha256').update(value).digest('hex');
const isFile = async filePath => Boolean((await stat(filePath).catch(() => null))?.isFile());
const isDirectory = async filePath => Boolean((await stat(filePath).catch(() => null))?.isDirectory());

const hashFile = filePath => new Promise((resolveHash, rejectHash) => {
  const hash = createHash('sha256');
  const stream = createReadStream(filePath);
  stream.on('data', chunk => hash.update(chunk));
  stream.on('error', rejectHash);
  stream.on('end', () => resolveHash(hash.digest('hex')));
});

const publicStats = data => ({
  payloads: Array.isArray(data?.payloads) ? data.payloads.length : 0,
  tools: Array.isArray(data?.tools) ? data.tools.length : 0,
  navigation: Array.isArray(data?.navigation) ? data.navigation.length : 0,
  toolNavigation: Array.isArray(data?.toolNavigation) ? data.toolNavigation.length : 0,
});

const mimeTypeForLogo = fileName => ({
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
}[extname(fileName).toLowerCase()] || 'application/octet-stream');

const validateFileDescriptor = (value, label, filePattern) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Invalid deployment file descriptor: ${label}`);
  }
  if (filePattern && !filePattern.test(String(value.file || ''))) {
    throw new Error(`Unsafe deployment asset path: ${label}`);
  }
  if (!sha256Pattern.test(String(value.sha256 || ''))) {
    throw new Error(`Invalid deployment SHA256: ${label}`);
  }
  if (!Number.isSafeInteger(value.size) || value.size < 0 || value.size > maxPackageFileBytes) {
    throw new Error(`Invalid deployment file size: ${label}`);
  }
};

export const validateClientDeploymentManifest = (manifest, options = {}) => {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('Invalid deployment manifest.');
  }
  if (manifest.format !== CLIENT_DEPLOYMENT_FORMAT) {
    throw new Error('Invalid deployment manifest format.');
  }
  if (manifest.packageVersion !== CLIENT_DEPLOYMENT_PACKAGE_VERSION) {
    throw new Error('Unsupported deployment package version.');
  }
  const expectedContract = options.buildContractVersion ?? CLIENT_BUILD_CONTRACT_VERSION;
  if (manifest.buildContractVersion !== expectedContract) {
    throw new Error('Incompatible deployment build contract.');
  }
  if (!manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files)) {
    throw new Error('Invalid deployment file map.');
  }
  for (const fileName of requiredFiles) {
    validateFileDescriptor(manifest.files[fileName], fileName);
  }
  if (Object.keys(manifest.files).some(fileName => !requiredFiles.includes(fileName))) {
    throw new Error('Unexpected deployment file entry.');
  }
  if (!manifest.assets || typeof manifest.assets !== 'object' || Array.isArray(manifest.assets)) {
    throw new Error('Invalid deployment asset map.');
  }
  for (const [route, descriptor] of Object.entries(manifest.assets)) {
    if (!safeLogoRoutePattern.test(route)) throw new Error(`Unsafe deployment asset route: ${route}`);
    validateFileDescriptor(descriptor, route, safeAssetFilePattern);
  }
  if (!manifest.stats || typeof manifest.stats !== 'object' || Array.isArray(manifest.stats)) {
    throw new Error('Invalid deployment statistics.');
  }
  for (const key of ['payloads', 'tools', 'navigation', 'toolNavigation']) {
    if (!Number.isSafeInteger(manifest.stats[key]) || manifest.stats[key] < 0) {
      throw new Error(`Invalid deployment statistic: ${key}`);
    }
  }
  if (!Array.isArray(manifest.excludes) || !manifest.excludes.every(value => typeof value === 'string')) {
    throw new Error('Invalid deployment exclusions.');
  }
  return manifest;
};

const publishDirectory = async (temporary, destination, backup) => {
  const destinationExists = await isDirectory(destination);
  if (destinationExists) await rename(destination, backup);
  try {
    await rename(temporary, destination);
  } catch (error) {
    if (destinationExists && !await isDirectory(destination) && await isDirectory(backup)) {
      await rename(backup, destination).catch(() => {});
    }
    throw error;
  }
  await rm(backup, { recursive: true, force: true });
};

export const writeClientDeploymentPackage = async options => {
  const destination = String(options?.destination || '');
  const publicData = options?.publicData;
  if (!destination) throw new Error('Deployment package destination is required.');
  if (!publicData || typeof publicData !== 'object' || Array.isArray(publicData)) {
    throw new Error('Deployment public data must be an object.');
  }

  const logoUrl = String(publicData?.settings?.logoUrl || '');
  if (logoUrl && !safeLogoRoutePattern.test(logoUrl)) {
    throw new Error('Unsafe logo route in deployment public data.');
  }
  if (logoUrl && (!options.logoFile || !await isFile(options.logoFile))) {
    throw new Error('Deployment logo file is missing.');
  }

  const suffix = randomUUID();
  const temporary = `${destination}.tmp-${suffix}`;
  const backup = `${destination}.backup-${suffix}`;
  const publicDataBytes = jsonBytes(publicData);
  const customTools = {
    version: 1,
    categories: Array.isArray(publicData.tools)
      ? publicData.tools.filter(tool => String(tool?.id || '').startsWith('custom-'))
      : [],
  };
  const customToolsBytes = jsonBytes(customTools);

  try {
    await mkdir(temporary, { recursive: false });
    await writeFile(join(temporary, 'public-data.json'), publicDataBytes);
    await writeFile(join(temporary, 'custom-tools.json'), customToolsBytes);

    const assets = {};
    if (logoUrl) {
      const logoName = basename(logoUrl);
      const relativeFile = `assets/uploads/logo/${logoName}`;
      const destinationLogo = join(temporary, 'assets', 'uploads', 'logo', logoName);
      await mkdir(dirname(destinationLogo), { recursive: true });
      await copyFile(options.logoFile, destinationLogo);
      const logoStats = await stat(destinationLogo);
      if (logoStats.size > maxPackageFileBytes) throw new Error('Deployment logo is oversized.');
      assets[logoUrl] = {
        file: relativeFile,
        sha256: await hashFile(destinationLogo),
        size: logoStats.size,
        mimeType: mimeTypeForLogo(logoName),
      };
    }

    const manifest = {
      format: CLIENT_DEPLOYMENT_FORMAT,
      packageVersion: CLIENT_DEPLOYMENT_PACKAGE_VERSION,
      buildContractVersion: options.buildContractVersion ?? CLIENT_BUILD_CONTRACT_VERSION,
      generatedAt: options.generatedAt || new Date().toISOString(),
      files: {
        'public-data.json': {
          sha256: hashBytes(publicDataBytes),
          size: publicDataBytes.length,
          mimeType: 'application/json; charset=utf-8',
        },
        'custom-tools.json': {
          sha256: hashBytes(customToolsBytes),
          size: customToolsBytes.length,
          mimeType: 'application/json; charset=utf-8',
        },
      },
      assets,
      stats: publicStats(publicData),
      excludes: [
        'administrator credentials and JWT material',
        'server environment variables and signing credentials',
        'SQLite databases, backups, and private uploads',
      ],
    };
    validateClientDeploymentManifest(manifest, { buildContractVersion: manifest.buildContractVersion });
    await writeFile(join(temporary, 'manifest.json'), jsonBytes(manifest));
    await mkdir(dirname(destination), { recursive: true });
    await publishDirectory(temporary, destination, backup);
    return { destination, manifest };
  } catch (error) {
    await rm(temporary, { recursive: true, force: true }).catch(() => {});
    if (await isDirectory(backup) && !await isDirectory(destination)) {
      await rename(backup, destination).catch(() => {});
    }
    await rm(backup, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
};
