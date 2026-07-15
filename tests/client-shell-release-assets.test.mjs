import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  clientShellBuildArguments,
  findNativePackage,
  nativePackageName,
} from '../scripts/build-client-shells.mjs';
import {
  createWindowsSigningMetadata,
  preparedApplicationRelativePath,
  validateWindowsSigningMetadata,
} from '../scripts/build-windows-signing-stages.mjs';
import {
  findUniqueFileByName,
  windowsInstallerNames,
} from '../scripts/apply-signed-windows-installers.mjs';
import { writeReleaseChecksumManifest } from '../scripts/merge-client-shell-manifests.mjs';
import {
  CLIENT_SHELL_FORMAT,
  CLIENT_SHELL_MANIFEST_FILE,
  CLIENT_SHELL_MANIFEST_VERSION,
  CLIENT_SHELL_TARGETS,
} from '../server/client-shells.mjs';

test('official shell targets map to canonical native Release package names', () => {
  assert.equal(nativePackageName('win-x64-nsis', '2.0.0'), 'Payloader-Client-Setup-2.0.0-x64.exe');
  assert.equal(nativePackageName('win-arm64-nsis', '2.0.0'), 'Payloader-Client-Setup-2.0.0-arm64.exe');
  assert.equal(nativePackageName('win-ia32-nsis', '2.0.0'), 'Payloader-Client-Setup-2.0.0-ia32.exe');
  assert.equal(nativePackageName('linux-x64-appimage', '2.0.0'), 'Payloader-Client-2.0.0-x64.AppImage');
  assert.equal(nativePackageName('linux-arm64-appimage', '2.0.0'), 'Payloader-Client-2.0.0-arm64.AppImage');
  assert.equal(nativePackageName('linux-armv7l-appimage', '2.0.0'), 'Payloader-Client-2.0.0-armv7l.AppImage');
  assert.equal(nativePackageName('mac-x64-dmg', '2.0.0'), 'Payloader-Client-2.0.0-x64.dmg');
  assert.equal(nativePackageName('mac-arm64-dmg', '2.0.0'), 'Payloader-Client-2.0.0-arm64.dmg');
  assert.equal(nativePackageName('mac-universal-dmg', '2.0.0'), 'Payloader-Client-2.0.0-universal.dmg');
  assert.throws(() => nativePackageName('unknown', '2.0.0'), /Unknown client shell target/);
  assert.throws(() => nativePackageName('win-x64-nsis', 'latest'), /Invalid client version/);
});

test('official shell builds request the Electron runtime for every target architecture', () => {
  const expected = {
    'win-x64-nsis': ['--win', 'nsis', '--x64', '--publish', 'never'],
    'win-arm64-nsis': ['--win', 'nsis', '--arm64', '--publish', 'never'],
    'win-ia32-nsis': ['--win', 'nsis', '--ia32', '--publish', 'never'],
    'linux-x64-appimage': ['--linux', 'AppImage', '--x64', '--publish', 'never'],
    'linux-arm64-appimage': ['--linux', 'AppImage', '--arm64', '--publish', 'never'],
    'linux-armv7l-appimage': ['--linux', 'AppImage', '--armv7l', '--publish', 'never'],
    'mac-x64-dmg': ['--mac', 'dmg', '--x64', '--publish', 'never'],
    'mac-arm64-dmg': ['--mac', 'dmg', '--arm64', '--publish', 'never'],
    'mac-universal-dmg': ['--mac', 'dmg', '--universal', '--publish', 'never'],
  };

  for (const [targetId, args] of Object.entries(expected)) {
    assert.deepEqual(clientShellBuildArguments(targetId), args);
  }
  assert.throws(() => clientShellBuildArguments('unknown'), /Unknown client shell target/);
});

test('Windows signing stages use one prepared application per supported architecture', () => {
  assert.equal(preparedApplicationRelativePath('win-x64-nsis'), 'apps/x64');
  assert.equal(preparedApplicationRelativePath('win-arm64-nsis'), 'apps/arm64');
  assert.equal(preparedApplicationRelativePath('win-ia32-nsis'), 'apps/ia32');
  assert.throws(() => preparedApplicationRelativePath('linux-x64-appimage'), /Windows signing target/);

  const metadata = createWindowsSigningMetadata({
    appVersion: '2.0.0',
    buildContractVersion: 7,
    targetIds: ['win-x64-nsis', 'win-arm64-nsis', 'win-ia32-nsis'],
  });
  assert.deepEqual(validateWindowsSigningMetadata(metadata), metadata);
  assert.throws(
    () => validateWindowsSigningMetadata({ ...metadata, appVersion: 'latest' }),
    /app version/,
  );
  assert.deepEqual(windowsInstallerNames(metadata), [
    'Payloader-Client-Setup-2.0.0-x64.exe',
    'Payloader-Client-Setup-2.0.0-arm64.exe',
    'Payloader-Client-Setup-2.0.0-ia32.exe',
  ]);
});

test('signed installer discovery requires exactly one file with each expected name', async t => {
  const root = await mkdtemp(join(tmpdir(), 'payloader-signed-installer-discovery-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const nested = join(root, 'signed');
  await mkdir(nested, { recursive: true });
  const expected = 'Payloader-Client-Setup-2.0.0-x64.exe';
  const expectedPath = join(nested, expected);
  await writeFile(expectedPath, 'signed installer');
  assert.equal(await findUniqueFileByName(root, expected), expectedPath);

  const duplicate = join(root, 'duplicate');
  await mkdir(duplicate, { recursive: true });
  await writeFile(join(duplicate, expected), 'duplicate installer');
  await assert.rejects(findUniqueFileByName(root, expected), /exactly one signed installer/);
  await assert.rejects(findUniqueFileByName(root, 'missing.exe'), /exactly one signed installer/);
});

test('native package discovery accepts one root package and rejects missing or ambiguous output', async t => {
  const root = await mkdtemp(join(tmpdir(), 'payloader-native-release-'));
  t.after(() => rm(root, { recursive: true, force: true }));

  const unpacked = join(root, 'win-unpacked');
  await mkdir(unpacked, { recursive: true });
  await writeFile(join(unpacked, 'Payloader.exe'), 'unpacked executable');
  const installer = join(root, 'Payloader-Client-Setup-2.0.0-x64.exe');
  await writeFile(installer, 'installer');

  assert.equal(await findNativePackage(root, 'win-x64-nsis'), installer);

  await writeFile(join(root, 'duplicate.exe'), 'duplicate');
  await assert.rejects(
    findNativePackage(root, 'win-x64-nsis'),
    /Expected one root-level .* package, found 2/,
  );

  const empty = await mkdtemp(join(tmpdir(), 'payloader-native-release-empty-'));
  t.after(() => rm(empty, { recursive: true, force: true }));
  await assert.rejects(
    findNativePackage(empty, 'linux-x64-appimage'),
    /Expected one root-level .* package, found 0/,
  );
});

test('release checksum manifest covers exactly the native clients, shell transports, and combined manifest', async t => {
  const root = await mkdtemp(join(tmpdir(), 'payloader-release-checksums-'));
  t.after(() => rm(root, { recursive: true, force: true }));

  const targets = {};
  const expectedNames = [CLIENT_SHELL_MANIFEST_FILE];
  for (const [targetId, target] of Object.entries(CLIENT_SHELL_TARGETS)) {
    const archive = `payloader-shell-${targetId
      .replace(/^win-/, 'windows-')
      .replace(/-nsis$|-appimage$|-dmg$/g, '')}.tar.gz`;
    targets[targetId] = {
      archive,
      ...target,
      signed: false,
      size: 7,
      sha256: 'a'.repeat(64),
    };
    expectedNames.push(nativePackageName(targetId, '2.0.0'), archive);
  }

  for (const name of expectedNames) {
    await writeFile(join(root, name), `content:${name}`, 'utf8');
  }
  await writeFile(join(root, 'temporary.sha256.txt'), 'must not be published', 'utf8');

  const manifest = {
    format: CLIENT_SHELL_FORMAT,
    manifestVersion: CLIENT_SHELL_MANIFEST_VERSION,
    appVersion: '2.0.0',
    generatedAt: new Date().toISOString(),
    buildContractVersion: 7,
    deploymentPackageVersion: 1,
    targets,
  };
  const outputPath = await writeReleaseChecksumManifest(root, manifest);
  const lines = (await readFile(outputPath, 'utf8')).trim().split('\n');
  const expectedSortedNames = expectedNames.sort((left, right) => left.localeCompare(right));

  assert.equal(lines.length, 19);
  assert.deepEqual(lines.map(line => line.slice(66)), expectedSortedNames);
  assert.doesNotMatch(lines.join('\n'), /temporary\.sha256\.txt/);
  for (const name of expectedSortedNames) {
    const expectedHash = createHash('sha256').update(`content:${name}`).digest('hex');
    assert.ok(lines.includes(`${expectedHash}  ${name}`));
  }

  const [firstTargetId] = Object.keys(CLIENT_SHELL_TARGETS);
  await assert.rejects(
    writeReleaseChecksumManifest(root, {
      ...manifest,
      targets: { [firstTargetId]: targets[firstTargetId] },
    }),
    /Missing client shell targets/,
  );
});
