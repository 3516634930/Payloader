import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, extname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  CLIENT_SHELL_FORMAT,
  CLIENT_SHELL_MANIFEST_VERSION,
  CLIENT_SHELL_TARGETS,
  createClientShellTransport,
  validateClientShellManifest,
} from '../server/client-shells.mjs';
import { verifyClientExecutableArchitecture } from './client-binary-architecture.mjs';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const packageJson = JSON.parse(await readFile(join(rootDir, 'package.json'), 'utf8'));
const electronBuilderCli = join(rootDir, 'node_modules', 'electron-builder', 'cli.js');
const outputDirectory = resolve(process.env.PAYLOADER_CLIENT_SHELL_OUTPUT_DIR || join(rootDir, 'artifacts', 'client-shells'));
const platformName = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
const targetConfig = Object.freeze({
  'win-x64-nsis': { builderPlatform: 'win', builderTarget: 'nsis', builderArch: 'x64', executable: 'Payloader.exe', nativeExtension: '.exe' },
  'win-arm64-nsis': { builderPlatform: 'win', builderTarget: 'nsis', builderArch: 'arm64', executable: 'Payloader.exe', nativeExtension: '.exe' },
  'win-ia32-nsis': { builderPlatform: 'win', builderTarget: 'nsis', builderArch: 'ia32', executable: 'Payloader.exe', nativeExtension: '.exe' },
  'linux-x64-appimage': { builderPlatform: 'linux', builderTarget: 'AppImage', builderArch: 'x64', executable: 'payloader', nativeExtension: '.AppImage' },
  'linux-arm64-appimage': { builderPlatform: 'linux', builderTarget: 'AppImage', builderArch: 'arm64', executable: 'payloader', nativeExtension: '.AppImage' },
  'linux-armv7l-appimage': { builderPlatform: 'linux', builderTarget: 'AppImage', builderArch: 'armv7l', executable: 'payloader', nativeExtension: '.AppImage' },
  'mac-x64-dmg': { builderPlatform: 'mac', builderTarget: 'dmg', builderArch: 'x64', executable: 'Payloader.app', nativeExtension: '.dmg' },
  'mac-arm64-dmg': { builderPlatform: 'mac', builderTarget: 'dmg', builderArch: 'arm64', executable: 'Payloader.app', nativeExtension: '.dmg' },
  'mac-universal-dmg': { builderPlatform: 'mac', builderTarget: 'dmg', builderArch: 'universal', executable: 'Payloader.app', nativeExtension: '.dmg' },
});

const versionPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

export const clientShellBuildArguments = targetId => {
  const config = targetConfig[targetId];
  if (!config) throw new Error(`Unknown client shell target: ${targetId}`);
  return [
    `--${config.builderPlatform}`,
    config.builderTarget,
    `--${config.builderArch}`,
    '--publish',
    'never',
  ];
};

export const nativePackageName = (targetId, version) => {
  const config = targetConfig[targetId];
  if (!config) throw new Error(`Unknown client shell target: ${targetId}`);
  if (!versionPattern.test(String(version || ''))) throw new Error(`Invalid client version: ${version}`);
  const prefix = config.builderPlatform === 'win' ? 'Payloader-Client-Setup' : 'Payloader-Client';
  return `${prefix}-${version}-${config.builderArch}${config.nativeExtension}`;
};

export const findNativePackage = async (outputDir, targetId) => {
  const config = targetConfig[targetId];
  if (!config) throw new Error(`Unknown client shell target: ${targetId}`);
  const entries = await readdir(outputDir, { withFileTypes: true });
  const matches = entries
    .filter(entry => entry.isFile() && extname(entry.name).toLowerCase() === config.nativeExtension.toLowerCase())
    .map(entry => join(outputDir, entry.name));
  if (matches.length !== 1) {
    throw new Error(`Expected one root-level ${config.builderTarget} package, found ${matches.length}.`);
  }
  return matches[0];
};

const requestedTargets = String(process.env.PAYLOADER_CLIENT_SHELL_TARGETS || '')
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);
const selectedTargets = requestedTargets.length
  ? requestedTargets
  : Object.keys(CLIENT_SHELL_TARGETS).filter(targetId => CLIENT_SHELL_TARGETS[targetId].platform === platformName);

const run = (command, args, options = {}) => new Promise((resolveRun, rejectRun) => {
  const child = spawn(command, args, {
    cwd: rootDir,
    stdio: 'inherit',
    windowsHide: true,
    ...options,
  });
  child.on('error', rejectRun);
  child.on('exit', code => code === 0
    ? resolveRun()
    : rejectRun(new Error(`${command} exited with code ${code}`)));
});

const walkDirectories = async root => {
  const directories = [root];
  for (let index = 0; index < directories.length; index += 1) {
    const directory = directories[index];
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) directories.push(join(directory, entry.name));
    }
  }
  return directories;
};

const findShellRoot = async (outputDir, config) => {
  const directories = await walkDirectories(outputDir);
  if (platformName === 'macos') {
    const apps = directories.filter(directory => basename(directory) === config.executable);
    if (apps.length !== 1) throw new Error(`Expected one macOS application bundle, found ${apps.length}.`);
    return apps[0];
  }
  const matches = [];
  for (const directory of directories) {
    const executable = join(directory, config.executable);
    if ((await stat(executable).catch(() => null))?.isFile()) matches.push(directory);
  }
  if (matches.length !== 1) throw new Error(`Expected one unpacked client directory, found ${matches.length}.`);
  return matches[0];
};

const shellExecutablePath = (shellRoot, config) => platformName === 'macos'
  ? join(shellRoot, 'Contents', 'MacOS', 'Payloader')
  : join(shellRoot, config.executable);

const archiveName = targetId => `payloader-shell-${targetId
  .replace(/^win-/, 'windows-')
  .replace(/-nsis$|-appimage$|-dmg$/g, '')}.tar.gz`;

const hashFile = filePath => new Promise((resolveHash, rejectHash) => {
  const hash = createHash('sha256');
  const input = createReadStream(filePath);
  input.on('data', chunk => hash.update(chunk));
  input.on('error', rejectHash);
  input.on('end', () => resolveHash(hash.digest('hex')));
});

const shellBuildEnvironment = () => {
  const environment = { ...process.env };
  const prefix = platformName === 'windows' ? 'PAYLOADER_SHELL_WINDOWS_' : 'PAYLOADER_SHELL_MACOS_';
  environment.PAYLOADER_CSC_LINK = environment[`${prefix}CSC_LINK`] || '';
  environment.PAYLOADER_CSC_KEY_PASSWORD = environment[`${prefix}CSC_KEY_PASSWORD`] || '';
  environment.CSC_NAME = environment[`${prefix}CSC_NAME`] || '';
  if (platformName === 'macos') {
    environment.APPLE_ID = environment.PAYLOADER_SHELL_MACOS_APPLE_ID || '';
    environment.APPLE_APP_SPECIFIC_PASSWORD = environment.PAYLOADER_SHELL_MACOS_APP_PASSWORD || '';
    environment.APPLE_TEAM_ID = environment.PAYLOADER_SHELL_MACOS_TEAM_ID || '';
  } else {
    delete environment.APPLE_ID;
    delete environment.APPLE_APP_SPECIFIC_PASSWORD;
    delete environment.APPLE_TEAM_ID;
  }
  return environment;
};

const main = async () => {
  if (!selectedTargets.length) throw new Error('No client shell targets were selected.');
  for (const targetId of selectedTargets) {
    const expected = CLIENT_SHELL_TARGETS[targetId];
    if (!expected || expected.platform !== platformName || !targetConfig[targetId]) {
      throw new Error(`Target ${targetId} cannot be built on ${process.platform}.`);
    }
  }

  const workRoot = await mkdtemp(join(tmpdir(), 'payloader-client-shell-build-'));
  process.env.PAYLOADER_DATA_DIR = join(workRoot, 'data');
  process.env.PAYLOADER_CLIENT_BUILD_ROOT = join(workRoot, 'client-builds');
  process.env.PAYLOADER_CLIENT_TMP_ROOT = join(workRoot, 'client-tmp');
  process.env.PAYLOADER_CLIENT_CACHE_DIR ||= join(workRoot, 'client-cache');
  process.env.PAYLOADER_CLIENT_SHELLS_REMOTE_DISABLED = 'true';

  try {
    await mkdir(outputDirectory, { recursive: true });
    const builder = await import(`../server/client-builder.mjs?shell-build=${randomUUID()}`);
    const { closeStore } = await import('../server/data-store.mjs');
    try {
      const publicData = await builder.__clientBuildTest.buildPublicDataSnapshot();
      const prepared = await builder.__clientBuildTest.prepareElectronApp(
        join(workRoot, 'prepared'),
        publicData,
        { useBundledElectronRuntime: false },
      );
      const signingSource = shellBuildEnvironment();
      const hasCodeSigningIdentity = Boolean(signingSource.PAYLOADER_CSC_LINK || signingSource.CSC_NAME);
      const buildEnvironment = {
        ...builder.__clientBuildTest.createBuildEnvironment(signingSource, { includeSigning: true }),
        CSC_IDENTITY_AUTO_DISCOVERY: hasCodeSigningIdentity ? 'true' : 'false',
      };
      const targets = {};

      for (const targetId of selectedTargets) {
        const config = targetConfig[targetId];
        await rm(prepared.buildOutputDir, { recursive: true, force: true });
        await run(process.execPath, [
          electronBuilderCli,
          ...clientShellBuildArguments(targetId),
        ], { cwd: prepared.appDir, env: buildEnvironment });
        const shellRoot = await findShellRoot(prepared.buildOutputDir, config);
        await verifyClientExecutableArchitecture(shellExecutablePath(shellRoot, config), targetId);
        const nativeSource = await findNativePackage(prepared.buildOutputDir, targetId);
        const nativeName = nativePackageName(targetId, packageJson.version);
        const nativeDestination = join(outputDirectory, nativeName);
        await copyFile(nativeSource, nativeDestination);
        const nativeStats = await stat(nativeDestination);
        if (!nativeStats.isFile() || nativeStats.size <= 0) {
          throw new Error(`Native client package is empty: ${nativeName}`);
        }
        const nativeSha256 = await hashFile(nativeDestination);
        await writeFile(
          join(outputDirectory, `${nativeName}.sha256.txt`),
          `${nativeSha256}  ${nativeName}\n`,
          'utf8',
        );
        const archive = archiveName(targetId);
        const transport = await createClientShellTransport({
          shellRoot,
          deploymentPackageDir: prepared.deploymentPackageDir,
          destination: join(outputDirectory, archive),
          platform: platformName,
        });
        targets[targetId] = {
          archive,
          platform: CLIENT_SHELL_TARGETS[targetId].platform,
          arch: CLIENT_SHELL_TARGETS[targetId].arch,
          outputFormat: CLIENT_SHELL_TARGETS[targetId].outputFormat,
          signed: hasCodeSigningIdentity,
          size: transport.size,
          sha256: transport.sha256,
        };
        await writeFile(join(outputDirectory, `${archive}.sha256.txt`), `${transport.sha256}  ${archive}\n`, 'utf8');
      }

      const manifest = {
        format: CLIENT_SHELL_FORMAT,
        manifestVersion: CLIENT_SHELL_MANIFEST_VERSION,
        appVersion: packageJson.version,
        generatedAt: new Date().toISOString(),
        buildContractVersion: builder.__clientBuildTest.contract.buildContractVersion,
        deploymentPackageVersion: 1,
        targets,
      };
      validateClientShellManifest(manifest);
      const partialName = `payloader-client-shells-${platformName}.json`;
      await writeFile(join(outputDirectory, partialName), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
      process.stdout.write(`${join(outputDirectory, partialName)}\n`);
    } finally {
      await closeStore();
    }
  } finally {
    await rm(workRoot, { recursive: true, force: true }).catch(() => {});
  }
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) await main();
