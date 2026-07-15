import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { findNativePackage, nativePackageName } from './build-client-shells.mjs';
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
const signingMetadataFile = 'windows-signing-input.json';
const signingMetadataFormat = 'payloader-windows-signing-input';
const signingMetadataVersion = 1;
const versionPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const windowsTargets = Object.freeze({
  'win-x64-nsis': Object.freeze({ arch: 'x64', executable: 'Payloader.exe' }),
  'win-arm64-nsis': Object.freeze({ arch: 'arm64', executable: 'Payloader.exe' }),
  'win-ia32-nsis': Object.freeze({ arch: 'ia32', executable: 'Payloader.exe' }),
});

export const preparedApplicationRelativePath = targetId => {
  const target = windowsTargets[targetId];
  if (!target) throw new Error(`Windows signing target is invalid: ${targetId}`);
  return `apps/${target.arch}`;
};

export const createWindowsSigningMetadata = ({ appVersion, buildContractVersion, targetIds }) => ({
  format: signingMetadataFormat,
  version: signingMetadataVersion,
  appVersion,
  buildContractVersion,
  targets: targetIds.map(targetId => ({
    id: targetId,
    arch: windowsTargets[targetId]?.arch || '',
    applicationPath: preparedApplicationRelativePath(targetId),
    executable: windowsTargets[targetId]?.executable || '',
  })),
});

export const validateWindowsSigningMetadata = metadata => {
  if (!metadata || metadata.format !== signingMetadataFormat || metadata.version !== signingMetadataVersion) {
    throw new Error('Windows signing metadata format is invalid.');
  }
  if (!versionPattern.test(String(metadata.appVersion || ''))) {
    throw new Error('Windows signing app version is invalid.');
  }
  if (!Number.isInteger(metadata.buildContractVersion) || metadata.buildContractVersion <= 0) {
    throw new Error('Windows signing build contract version is invalid.');
  }
  if (!Array.isArray(metadata.targets) || metadata.targets.length === 0) {
    throw new Error('Windows signing targets are missing.');
  }
  const seen = new Set();
  for (const target of metadata.targets) {
    const expected = windowsTargets[target?.id];
    if (
      !expected
      || seen.has(target.id)
      || target.arch !== expected.arch
      || target.applicationPath !== preparedApplicationRelativePath(target.id)
      || target.executable !== expected.executable
    ) {
      throw new Error(`Windows signing target metadata is invalid: ${target?.id || 'unknown'}`);
    }
    seen.add(target.id);
  }
  return metadata;
};

const selectedTargetIds = () => {
  const requested = String(process.env.PAYLOADER_CLIENT_SHELL_TARGETS || '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
  const targetIds = requested.length ? requested : Object.keys(windowsTargets);
  for (const targetId of targetIds) preparedApplicationRelativePath(targetId);
  if (new Set(targetIds).size !== targetIds.length) throw new Error('Windows signing targets contain duplicates.');
  return targetIds;
};

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

const hashFile = filePath => new Promise((resolveHash, rejectHash) => {
  const hash = createHash('sha256');
  const input = createReadStream(filePath);
  input.on('data', chunk => hash.update(chunk));
  input.on('error', rejectHash);
  input.on('end', () => resolveHash(hash.digest('hex')));
});

const walkDirectories = async root => {
  const directories = [root];
  for (let index = 0; index < directories.length; index += 1) {
    for (const entry of await readdir(directories[index], { withFileTypes: true })) {
      if (entry.isDirectory()) directories.push(join(directories[index], entry.name));
    }
  }
  return directories;
};

const findUnpackedApplication = async (outputDir, executable) => {
  const matches = [];
  for (const directory of await walkDirectories(outputDir)) {
    if ((await stat(join(directory, executable)).catch(() => null))?.isFile()) matches.push(directory);
  }
  if (matches.length !== 1) {
    throw new Error(`Expected one unpacked Windows application, found ${matches.length}.`);
  }
  return matches[0];
};

const findUniqueFileByName = async (root, name) => {
  const matches = [];
  const directories = [root];
  for (let index = 0; index < directories.length; index += 1) {
    for (const entry of await readdir(directories[index], { withFileTypes: true })) {
      const entryPath = join(directories[index], entry.name);
      if (entry.isDirectory()) directories.push(entryPath);
      else if (entry.isFile() && entry.name === name) matches.push(entryPath);
    }
  }
  if (matches.length !== 1) throw new Error(`Expected exactly one ${name}, found ${matches.length}.`);
  return matches[0];
};

const archiveName = targetId => `payloader-shell-${targetId.replace(/^win-/, 'windows-').replace(/-nsis$/, '')}.tar.gz`;

const configureIsolatedBuild = workRoot => {
  process.env.PAYLOADER_DATA_DIR = join(workRoot, 'data');
  process.env.PAYLOADER_CLIENT_BUILD_ROOT = join(workRoot, 'client-builds');
  process.env.PAYLOADER_CLIENT_TMP_ROOT = join(workRoot, 'client-tmp');
  process.env.PAYLOADER_CLIENT_CACHE_DIR ||= join(workRoot, 'client-cache');
  process.env.PAYLOADER_CLIENT_SHELLS_REMOTE_DISABLED = 'true';
};

const unsignedBuildEnvironment = builder => ({
  ...builder.__clientBuildTest.createBuildEnvironment(process.env, { includeSigning: false }),
  CSC_IDENTITY_AUTO_DISCOVERY: 'false',
});

const withBuildContext = async callback => {
  if (process.platform !== 'win32') throw new Error('Windows signing stages must run on Windows.');
  const workRoot = await mkdtemp(join(tmpdir(), 'payloader-windows-signing-'));
  configureIsolatedBuild(workRoot);
  try {
    const builder = await import(`../server/client-builder.mjs?windows-signing=${randomUUID()}`);
    const { closeStore } = await import('../server/data-store.mjs');
    try {
      const publicData = await builder.__clientBuildTest.buildPublicDataSnapshot();
      const prepared = await builder.__clientBuildTest.prepareElectronApp(
        join(workRoot, 'prepared'),
        publicData,
        { useBundledElectronRuntime: false },
      );
      return await callback({ builder, prepared, workRoot });
    } finally {
      await closeStore();
    }
  } finally {
    await rm(workRoot, { recursive: true, force: true }).catch(() => {});
  }
};

const prepareWindowsApplications = async () => {
  const outputDirectory = resolve(
    process.env.PAYLOADER_WINDOWS_PREPARED_OUTPUT_DIR || join(rootDir, 'artifacts', 'windows-prepared'),
  );
  const targetIds = selectedTargetIds();
  await mkdir(outputDirectory, { recursive: true });
  await rm(join(outputDirectory, 'apps'), { recursive: true, force: true });
  await rm(join(outputDirectory, signingMetadataFile), { force: true });

  await withBuildContext(async ({ builder, prepared }) => {
    const environment = unsignedBuildEnvironment(builder);
    for (const targetId of targetIds) {
      const target = windowsTargets[targetId];
      await rm(prepared.buildOutputDir, { recursive: true, force: true });
      await run(process.execPath, [
        electronBuilderCli,
        '--win',
        '--dir',
        `--${target.arch}`,
        '--publish',
        'never',
      ], { cwd: prepared.appDir, env: environment });
      const unpacked = await findUnpackedApplication(prepared.buildOutputDir, target.executable);
      await verifyClientExecutableArchitecture(join(unpacked, target.executable), targetId);
      const destination = join(outputDirectory, ...preparedApplicationRelativePath(targetId).split('/'));
      await mkdir(resolve(destination, '..'), { recursive: true });
      await cp(unpacked, destination, { recursive: true, verbatimSymlinks: true });
      const executableStats = await stat(join(destination, target.executable));
      if (!executableStats.isFile() || executableStats.size <= 0) {
        throw new Error(`Prepared Windows executable is empty: ${targetId}`);
      }
    }

    const metadata = createWindowsSigningMetadata({
      appVersion: packageJson.version,
      buildContractVersion: builder.__clientBuildTest.contract.buildContractVersion,
      targetIds,
    });
    validateWindowsSigningMetadata(metadata);
    await writeFile(join(outputDirectory, signingMetadataFile), `${JSON.stringify(metadata, null, 2)}\n`, 'utf8');
  });
  process.stdout.write(`${join(outputDirectory, signingMetadataFile)}\n`);
};

const resolveSignedApplication = async (inputRoot, target) => {
  const expectedSuffix = target.applicationPath.split('/').join(sep);
  const candidates = [];
  for (const directory of await walkDirectories(inputRoot)) {
    const relativePath = relative(inputRoot, directory);
    if (
      (relativePath === expectedSuffix || relativePath.endsWith(`${sep}${expectedSuffix}`))
      && (await stat(join(directory, target.executable)).catch(() => null))?.isFile()
    ) {
      candidates.push(directory);
    }
  }
  if (candidates.length !== 1) {
    throw new Error(`Expected exactly one signed application for ${target.id}, found ${candidates.length}.`);
  }
  return candidates[0];
};

const finalizeWindowsApplications = async () => {
  const signedInput = resolve(String(process.env.PAYLOADER_WINDOWS_SIGNED_APP_DIR || ''));
  if (!String(process.env.PAYLOADER_WINDOWS_SIGNED_APP_DIR || '').trim()) {
    throw new Error('PAYLOADER_WINDOWS_SIGNED_APP_DIR is required.');
  }
  const outputDirectory = resolve(
    process.env.PAYLOADER_CLIENT_SHELL_OUTPUT_DIR || join(rootDir, 'artifacts', 'client-shells'),
  );
  const metadataPath = await findUniqueFileByName(signedInput, signingMetadataFile);
  const metadata = validateWindowsSigningMetadata(JSON.parse(await readFile(metadataPath, 'utf8')));
  if (metadata.appVersion !== packageJson.version) throw new Error('Signed application version does not match package.json.');
  await mkdir(outputDirectory, { recursive: true });

  await withBuildContext(async ({ builder, prepared }) => {
    if (metadata.buildContractVersion !== builder.__clientBuildTest.contract.buildContractVersion) {
      throw new Error('Signed application build contract does not match the current builder.');
    }
    const environment = unsignedBuildEnvironment(builder);
    const manifestTargets = {};
    for (const metadataTarget of metadata.targets) {
      const target = windowsTargets[metadataTarget.id];
      const signedApplication = await resolveSignedApplication(signedInput, metadataTarget);
      await rm(prepared.buildOutputDir, { recursive: true, force: true });
      await run(process.execPath, [
        electronBuilderCli,
        '--win',
        'nsis',
        `--${target.arch}`,
        '--prepackaged',
        signedApplication,
        '--publish',
        'never',
      ], { cwd: prepared.appDir, env: environment });

      const installerSource = await findNativePackage(prepared.buildOutputDir, metadataTarget.id);
      const installerName = nativePackageName(metadataTarget.id, metadata.appVersion);
      const installerDestination = join(outputDirectory, installerName);
      await copyFile(installerSource, installerDestination);
      const installerStats = await stat(installerDestination);
      if (!installerStats.isFile() || installerStats.size <= 0) {
        throw new Error(`Unsigned Windows installer is empty: ${installerName}`);
      }
      const installerSha256 = await hashFile(installerDestination);
      await writeFile(
        join(outputDirectory, `${installerName}.sha256.txt`),
        `${installerSha256}  ${installerName}\n`,
        'utf8',
      );

      const archive = archiveName(metadataTarget.id);
      const transport = await createClientShellTransport({
        shellRoot: signedApplication,
        deploymentPackageDir: prepared.deploymentPackageDir,
        destination: join(outputDirectory, archive),
        platform: 'windows',
      });
      manifestTargets[metadataTarget.id] = {
        archive,
        platform: CLIENT_SHELL_TARGETS[metadataTarget.id].platform,
        arch: CLIENT_SHELL_TARGETS[metadataTarget.id].arch,
        outputFormat: CLIENT_SHELL_TARGETS[metadataTarget.id].outputFormat,
        signed: true,
        size: transport.size,
        sha256: transport.sha256,
      };
      await writeFile(join(outputDirectory, `${archive}.sha256.txt`), `${transport.sha256}  ${archive}\n`, 'utf8');
    }

    const manifest = {
      format: CLIENT_SHELL_FORMAT,
      manifestVersion: CLIENT_SHELL_MANIFEST_VERSION,
      appVersion: metadata.appVersion,
      generatedAt: new Date().toISOString(),
      buildContractVersion: metadata.buildContractVersion,
      deploymentPackageVersion: 1,
      targets: manifestTargets,
    };
    validateClientShellManifest(manifest);
    await writeFile(
      join(outputDirectory, 'payloader-client-shells-windows.json'),
      `${JSON.stringify(manifest, null, 2)}\n`,
      'utf8',
    );
    await copyFile(metadataPath, join(outputDirectory, signingMetadataFile));
  });
  process.stdout.write(`${join(outputDirectory, 'payloader-client-shells-windows.json')}\n`);
};

const main = async () => {
  const stage = String(process.argv[2] || '').trim().toLowerCase();
  if (stage === 'prepare') return prepareWindowsApplications();
  if (stage === 'finalize') return finalizeWindowsApplications();
  throw new Error('Windows signing stage must be prepare or finalize.');
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) await main();
