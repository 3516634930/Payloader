import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { mkdtemp } from 'node:fs/promises';
import { Header, Pack, ReadEntry, t as listTar, x as extractTar } from 'tar';

import * as clientShellModule from '../server/client-shells.mjs';

import {
  CLIENT_SHELL_FORMAT,
  acquireClientShellArchive,
  assembleClientShell,
  createClientShellTransport,
  loadClientShellCatalog,
  pruneClientShellCache,
  validateClientShellManifest,
  validateShellArchiveEntry,
} from '../server/client-shells.mjs';
import { writeClientDeploymentPackage } from '../server/client-deployment-package.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const makeTemp = label => mkdtemp(join(tmpdir(), `payloader-shell-${label}-`));
const publicData = marker => ({
  payloads: [{ id: marker }],
  tools: [],
  navigation: [],
  toolNavigation: [],
  settings: { logoUrl: '' },
});

const validManifest = entry => ({
  format: CLIENT_SHELL_FORMAT,
  manifestVersion: 1,
  appVersion: '2.0.0',
  generatedAt: '2026-07-13T00:00:00.000Z',
  buildContractVersion: 7,
  deploymentPackageVersion: 1,
  targets: {
    'win-x64-nsis': {
      archive: 'payloader-shell-win-x64.tar.gz',
      platform: 'windows',
      arch: 'x64',
      outputFormat: 'zip',
      signed: false,
      ...entry,
    },
  },
});

const writeSyntheticTar = async (filePath, entries) => {
  const pack = new Pack({ gzip: true, portable: true, noMtime: true, strict: true });
  const chunks = [];
  pack.on('data', chunk => chunks.push(Buffer.from(chunk)));
  const ended = once(pack, 'end');
  for (const descriptor of entries) {
    const body = Buffer.from(descriptor.body || '');
    const entry = new ReadEntry(new Header({
      path: descriptor.path,
      type: descriptor.type,
      mode: descriptor.mode || (descriptor.type === 'Directory' ? 0o755 : 0o644),
      size: body.length,
      linkpath: descriptor.linkpath,
    }));
    pack.add(entry);
    entry.end(body);
  }
  pack.end();
  await ended;
  await writeFile(filePath, Buffer.concat(chunks));
};

test('official shell download timeout scales with release asset size', () => {
  assert.equal(typeof clientShellModule.clientShellDownloadTimeoutMs, 'function');
  const small = clientShellModule.clientShellDownloadTimeoutMs(1);
  const windowsArm64 = clientShellModule.clientShellDownloadTimeoutMs(140_850_196);
  const macUniversal = clientShellModule.clientShellDownloadTimeoutMs(209_539_824);

  assert.equal(small, 10 * 60_000);
  assert.ok(windowsArm64 > 120_000);
  assert.ok(macUniversal > windowsArm64);
  assert.ok(macUniversal <= 30 * 60_000);
  assert.equal(clientShellModule.clientShellDownloadTimeoutMs(macUniversal, 12_345), 12_345);
});

test('Windows shell downloads use the system HTTP transport outside injected tests', async () => {
  assert.equal(typeof clientShellModule.clientShellDownloadTransport, 'function');
  assert.equal(clientShellModule.clientShellDownloadTransport('win32', false), 'windows-system-http');
  assert.equal(clientShellModule.clientShellDownloadTransport('win32', true), 'fetch');
  assert.equal(clientShellModule.clientShellDownloadTransport('linux', false), 'fetch');

  const script = await readFile(new URL('../server/download-client-shell.ps1', import.meta.url), 'utf8');
  assert.match(script, /HttpClientHandler/);
  assert.doesNotMatch(script, /CopyToAsync/);
  assert.match(script, /\$received -gt \$ExpectedSize/);
  assert.match(script, /ExpectedSize/);
  assert.match(script, /release-assets\.githubusercontent\.com/);
  assert.match(script, /PAYLOADER_CLIENT_SHELL_TOKEN/);
  assert.match(script, /AuthenticationHeaderValue/);
  assert.match(script, /api\.github\.com/);
  const serverSource = await readFile(new URL('../server/client-shells.mjs', import.meta.url), 'utf8');
  assert.match(serverSource, /PAYLOADER_CLIENT_SHELL_TOKEN:\s*String\(token/);
  assert.doesNotMatch(serverSource, /['"]-Token['"]/);
});

test('shell manifest accepts fixed compatible targets and rejects unsafe entries', () => {
  const manifest = validManifest({ size: 12, sha256: 'a'.repeat(64) });
  assert.equal(validateClientShellManifest(manifest).targets['win-x64-nsis'].arch, 'x64');
  assert.throws(
    () => validateClientShellManifest({ ...manifest, targets: { unknown: manifest.targets['win-x64-nsis'] } }),
    /Unknown client shell target/,
  );
  assert.throws(
    () => validateClientShellManifest(validManifest({ archive: '../escape.tar.gz', size: 12, sha256: 'a'.repeat(64) })),
    /Unsafe client shell archive name/,
  );
  assert.throws(
    () => validateClientShellManifest({ ...manifest, buildContractVersion: 6 }),
    /Incompatible client shell build contract/,
  );
  assert.throws(
    () => validateClientShellManifest(manifest, { appVersion: '2.1.0' }),
    /Incompatible client shell application version/,
  );
});

test('remote shell catalog is pinned to the running application version tag', async () => {
  const manifest = validManifest({ size: 12, sha256: 'a'.repeat(64) });
  const requests = [];
  const fetchImpl = async url => {
    requests.push(String(url));
    if (String(url).endsWith('/releases/tags/v2.0.0')) {
      return new Response(JSON.stringify({
        id: 42,
        tag_name: 'v2.0.0',
        draft: false,
        prerelease: false,
        published_at: '2026-07-15T00:00:00.000Z',
        assets: [
          { id: 1, name: 'payloader-client-shells.json', size: 1 },
          { id: 2, name: 'payloader-shell-win-x64.tar.gz', size: 12 },
        ],
      }), { status: 200 });
    }
    if (String(url).endsWith('/releases/assets/1')) {
      return new Response(JSON.stringify(manifest), { status: 200 });
    }
    return new Response('not found', { status: 404 });
  };

  const catalog = await loadClientShellCatalog({
    repositoryUrl: 'https://github.com/example/payloader',
    appVersion: '2.0.0',
    fetchImpl,
  });

  assert.equal(requests[0], 'https://api.github.com/repos/example/payloader/releases/tags/v2.0.0');
  assert.equal(catalog.release.tagName, 'v2.0.0');
  assert.equal(catalog.targets['win-x64-nsis'].assetApiUrl, 'https://api.github.com/repos/example/payloader/releases/assets/2');
});

test('archive entry validation rejects traversal, unsafe links, and oversized entries', () => {
  assert.equal(validateShellArchiveEntry({ path: 'Payloader/resources/app.asar', type: 'File', size: 12 }), true);
  assert.equal(validateShellArchiveEntry({
    path: 'Payloader/Framework/Versions/Current',
    linkpath: 'A',
    type: 'SymbolicLink',
    size: 0,
  }), true);
  assert.throws(() => validateShellArchiveEntry({ path: '../escape', type: 'File', size: 1 }), /Unsafe shell archive path/);
  assert.throws(() => validateShellArchiveEntry({ path: 'Payloader/../escape', type: 'File', size: 1 }), /Unsafe shell archive path/);
  assert.throws(() => validateShellArchiveEntry({ path: '/absolute', type: 'File', size: 1 }), /Unsafe shell archive path/);
  assert.throws(() => validateShellArchiveEntry({
    path: 'Payloader/link',
    linkpath: '../../escape',
    type: 'SymbolicLink',
    size: 0,
  }), /escapes the archive root/);
  assert.throws(() => validateShellArchiveEntry({ path: 'Payloader/link', type: 'Link', size: 0 }), /hard links are not allowed/);
  assert.throws(() => validateShellArchiveEntry({ path: 'Payloader/huge', type: 'File', size: 3 * 1024 ** 3 }), /oversized/);
});

test('shell assembly rejects deployment entries nested below symbolic links', async t => {
  const root = await makeTemp('symlink-ancestor');
  t.after(() => rm(root, { recursive: true, force: true }));
  const shellArchive = join(root, 'unsafe-shell.tar.gz');
  const deployment = join(root, 'deployment.payloader');
  await writeClientDeploymentPackage({ destination: deployment, publicData: publicData('safe') });
  await writeSyntheticTar(shellArchive, [
    { path: 'Payloader.app/', type: 'Directory' },
    { path: 'Payloader.app/Contents/', type: 'Directory' },
    {
      path: 'Payloader.app/Contents/Resources',
      type: 'SymbolicLink',
      linkpath: '../SharedResources',
    },
    { path: 'Payloader.app/Contents/Resources/deployment.payloader/', type: 'Directory' },
    { path: 'Payloader.app/Contents/Resources/deployment.payloader/public-data.json', type: 'File', body: '{}' },
  ]);
  const bytes = await readFile(shellArchive);

  await assert.rejects(() => assembleClientShell({
    shellArchive,
    shell: {
      archive: 'unsafe-shell.tar.gz',
      platform: 'macos',
      arch: 'x64',
      outputFormat: 'tar.gz',
      size: bytes.length,
      sha256: hash(bytes),
    },
    deploymentPackageDir: deployment,
    destination: join(root, 'unsafe-output.tar.gz'),
    workRoot: root,
  }), /nested below a symbolic link/);
});

test('shell assembly replaces the deployment directory and produces a portable tar archive', async t => {
  const root = await makeTemp('assemble-tar');
  t.after(() => rm(root, { recursive: true, force: true }));
  const shellRoot = join(root, 'shell-root');
  const oldDeployment = join(root, 'old-deployment');
  const newDeployment = join(root, 'new-deployment');
  await writeFile(join(root, 'placeholder'), 'x');
  await writeClientDeploymentPackage({ destination: oldDeployment, publicData: publicData('old') });
  await writeClientDeploymentPackage({ destination: newDeployment, publicData: publicData('new') });
  await createClientShellTransport({
    shellRoot,
    sourceFiles: {
      'payloader': Buffer.from('#!/bin/sh\n'),
      'resources/app.asar': Buffer.from('immutable-code'),
    },
    deploymentPackageDir: oldDeployment,
    destination: join(root, 'shell.tar.gz'),
    platform: 'linux',
  });

  const shellBytes = await readFile(join(root, 'shell.tar.gz'));
  const entry = {
    archive: 'shell.tar.gz',
    platform: 'linux',
    arch: 'x64',
    outputFormat: 'tar.gz',
    signed: false,
    size: shellBytes.length,
    sha256: hash(shellBytes),
  };
  const result = await assembleClientShell({
    shellArchive: join(root, 'shell.tar.gz'),
    shell: entry,
    deploymentPackageDir: newDeployment,
    destination: join(root, 'Payloader-linux-x64.tar.gz'),
    workRoot: root,
  });
  assert.equal(result.outputFormat, 'tar.gz');
  assert.equal(result.sha256.length, 64);

  const inspect = join(root, 'inspect');
  await mkdir(inspect, { recursive: true });
  await extractTar({ file: result.filePath, cwd: inspect });
  const packagedData = JSON.parse(await readFile(join(inspect, 'Payloader', 'deployment.payloader', 'public-data.json'), 'utf8'));
  const code = await readFile(join(inspect, 'Payloader', 'resources', 'app.asar'), 'utf8');
  assert.equal(packagedData.payloads[0].id, 'new');
  assert.equal(code, 'immutable-code');
});

test('Windows shell assembly emits a ZIP without rebuilding the shell', async t => {
  const root = await makeTemp('assemble-zip');
  t.after(() => rm(root, { recursive: true, force: true }));
  const deployment = join(root, 'deployment');
  await writeClientDeploymentPackage({ destination: deployment, publicData: publicData('windows') });
  const transport = join(root, 'shell.tar.gz');
  await createClientShellTransport({
    sourceFiles: { 'Payloader.exe': Buffer.from('MZ-not-a-real-binary') },
    deploymentPackageDir: deployment,
    destination: transport,
    platform: 'windows',
  });
  const bytes = await readFile(transport);
  const result = await assembleClientShell({
    shellArchive: transport,
    shell: {
      archive: 'shell.tar.gz',
      platform: 'windows',
      arch: 'x64',
      outputFormat: 'zip',
      size: bytes.length,
      sha256: hash(bytes),
    },
    deploymentPackageDir: deployment,
    destination: join(root, 'Payloader-windows-x64.zip'),
    workRoot: root,
  });
  const output = await readFile(result.filePath);
  assert.equal(output.subarray(0, 2).toString('ascii'), 'PK');
  assert.ok((await stat(result.filePath)).size > 100);
});

test('shell assembly rejects concurrent writes to the same destination', async t => {
  const root = await makeTemp('assemble-concurrent-destination');
  t.after(() => rm(root, { recursive: true, force: true }));
  const oldDeployment = join(root, 'old-deployment');
  const firstDeployment = join(root, 'first-deployment');
  const secondDeployment = join(root, 'second-deployment');
  await writeClientDeploymentPackage({ destination: oldDeployment, publicData: publicData('old') });
  await writeClientDeploymentPackage({ destination: firstDeployment, publicData: publicData('first') });
  await writeClientDeploymentPackage({ destination: secondDeployment, publicData: publicData('second') });
  const shellArchive = join(root, 'shell.tar.gz');
  await createClientShellTransport({
    sourceFiles: { 'resources/app.asar': randomBytes(4 * 1024 * 1024) },
    deploymentPackageDir: oldDeployment,
    destination: shellArchive,
    platform: 'linux',
  });
  const bytes = await readFile(shellArchive);
  const shell = {
    archive: 'shell.tar.gz',
    platform: 'linux',
    arch: 'x64',
    outputFormat: 'tar.gz',
    size: bytes.length,
    sha256: hash(bytes),
  };
  const destination = join(root, 'Payloader-linux-x64.tar.gz');
  const results = await Promise.allSettled([
    assembleClientShell({ shellArchive, shell, deploymentPackageDir: firstDeployment, destination, workRoot: root }),
    assembleClientShell({ shellArchive, shell, deploymentPackageDir: secondDeployment, destination, workRoot: root }),
  ]);
  const fulfilled = results.filter(result => result.status === 'fulfilled');
  const rejected = results.filter(result => result.status === 'rejected');

  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.match(String(rejected[0].reason?.message || rejected[0].reason), /already being assembled/);
  const output = await readFile(destination);
  assert.equal(fulfilled[0].value.size, output.length);
  assert.equal(fulfilled[0].value.sha256, hash(output));
});

test('macOS shell assembly preserves framework symlinks without host symlink privileges', async t => {
  const root = await makeTemp('mac-symlink');
  t.after(() => rm(root, { recursive: true, force: true }));
  const shellArchive = join(root, 'mac-shell.tar.gz');
  const deployment = join(root, 'deployment.payloader');
  await writeClientDeploymentPackage({ destination: deployment, publicData: publicData('new-mac-data') });
  await writeSyntheticTar(shellArchive, [
    { path: 'Payloader.app/', type: 'Directory' },
    { path: 'Payloader.app/Contents/', type: 'Directory' },
    { path: 'Payloader.app/Contents/Frameworks/', type: 'Directory' },
    { path: 'Payloader.app/Contents/Frameworks/Electron Framework.framework/', type: 'Directory' },
    {
      path: 'Payloader.app/Contents/Frameworks/Electron Framework.framework/Electron Framework',
      type: 'SymbolicLink',
      linkpath: 'Versions/Current/Electron Framework',
    },
    { path: 'Payloader.app/Contents/Resources/', type: 'Directory' },
    { path: 'Payloader.app/Contents/Resources/deployment.payloader/', type: 'Directory' },
    {
      path: 'Payloader.app/Contents/Resources/deployment.payloader/obsolete.txt',
      type: 'File',
      body: 'old-data',
    },
  ]);
  const bytes = await readFile(shellArchive);
  const destination = join(root, 'Payloader-mac-x64.tar.gz');
  const result = await assembleClientShell({
    shellArchive,
    shell: {
      archive: 'mac-shell.tar.gz',
      platform: 'macos',
      arch: 'x64',
      outputFormat: 'tar.gz',
      size: bytes.length,
      sha256: hash(bytes),
    },
    deploymentPackageDir: deployment,
    destination,
    workRoot: root,
  });
  const entries = [];
  await listTar({
    file: result.filePath,
    strict: true,
    onReadEntry: entry => entries.push({ path: entry.path, type: entry.type, linkpath: entry.linkpath }),
  });

  assert.ok(entries.some(entry => entry.type === 'SymbolicLink'
    && entry.path.endsWith('Electron Framework.framework/Electron Framework')
    && entry.linkpath === 'Versions/Current/Electron Framework'));
  assert.ok(entries.some(entry => entry.path.endsWith('deployment.payloader/manifest.json')));
  assert.ok(!entries.some(entry => entry.path.endsWith('deployment.payloader/obsolete.txt')));
});

test('tar shell assembly drains many zero-length framework entries before large files', async t => {
  const root = await makeTemp('tar-zero-entry-backpressure');
  t.after(() => rm(root, { recursive: true, force: true }));
  const shellArchive = join(root, 'mac-shell.tar.gz');
  const deployment = join(root, 'deployment.payloader');
  await writeClientDeploymentPackage({ destination: deployment, publicData: publicData('backpressure-proof') });
  const frameworkDirectories = Array.from({ length: 48 }, (_, index) => ({
    path: `Payloader.app/Contents/Frameworks/Framework-${index}/`,
    type: 'Directory',
  }));
  await writeSyntheticTar(shellArchive, [
    { path: 'Payloader.app/', type: 'Directory' },
    { path: 'Payloader.app/Contents/', type: 'Directory' },
    { path: 'Payloader.app/Contents/Frameworks/', type: 'Directory' },
    {
      path: 'Payloader.app/Contents/Resources/app.asar',
      type: 'File',
      body: randomBytes(2 * 1024 * 1024),
    },
    ...frameworkDirectories,
    {
      path: 'Payloader.app/Contents/Frameworks/Electron Framework',
      type: 'File',
      body: randomBytes(2 * 1024 * 1024),
    },
    { path: 'Payloader.app/Contents/Resources/', type: 'Directory' },
    { path: 'Payloader.app/Contents/Resources/deployment.payloader/', type: 'Directory' },
    { path: 'Payloader.app/Contents/Resources/deployment.payloader/obsolete.txt', type: 'File', body: 'old' },
  ]);
  const bytes = await readFile(shellArchive);
  const destination = join(root, 'Payloader-mac-x64.tar.gz');
  const timeout = new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error('tar shell assembly stalled on zero-length entries')), 5_000);
    timer.unref();
  });
  const result = await Promise.race([
    assembleClientShell({
      shellArchive,
      shell: {
        archive: 'mac-shell.tar.gz',
        platform: 'macos',
        arch: 'x64',
        outputFormat: 'tar.gz',
        size: bytes.length,
        sha256: hash(bytes),
      },
      deploymentPackageDir: deployment,
      destination,
      workRoot: root,
    }),
    timeout,
  ]);

  assert.ok(result.size > 0);
  assert.equal((await stat(result.filePath)).size, result.size);
});

test('remote shell cache coalesces downloads and rejects hash mismatches', async t => {
  const root = await makeTemp('cache');
  t.after(() => rm(root, { recursive: true, force: true }));
  const payload = Buffer.from('verified-shell-archive');
  let requests = 0;
  const fetchImpl = async () => {
    requests += 1;
    await new Promise(resolve => setTimeout(resolve, 20));
    return new Response(payload, {
      status: 200,
      headers: { 'content-length': String(payload.length) },
    });
  };
  const entry = {
    archive: 'payloader-shell-win-x64.tar.gz',
    size: payload.length,
    sha256: hash(payload),
    assetApiUrl: 'https://api.github.com/repos/example/payloader/releases/assets/1',
  };
  const [first, second] = await Promise.all([
    acquireClientShellArchive(entry, { cacheRoot: root, fetchImpl }),
    acquireClientShellArchive(entry, { cacheRoot: root, fetchImpl }),
  ]);
  assert.equal(first, second);
  assert.equal(requests, 1);

  await assert.rejects(
    acquireClientShellArchive({ ...entry, sha256: 'f'.repeat(64) }, { cacheRoot: join(root, 'bad'), fetchImpl }),
    /hash mismatch/,
  );
});

test('shell cache pruning keeps only current catalog archives and ignores unknown files', async t => {
  const root = await makeTemp('cache-pruning');
  t.after(() => rm(root, { recursive: true, force: true }));
  const currentHash = 'a'.repeat(64);
  const obsoleteHash = 'b'.repeat(64);
  const current = join(root, `${currentHash}.tar.gz`);
  const obsolete = join(root, `${obsoleteHash}.tar.gz`);
  const unknown = join(root, 'operator-notes.txt');
  await writeFile(current, 'current', 'utf8');
  await writeFile(obsolete, 'obsolete', 'utf8');
  await writeFile(unknown, 'preserve', 'utf8');

  await pruneClientShellCache(root, {
    'win-x64-nsis': { sha256: currentHash },
  });
  assert.equal((await stat(current)).isFile(), true);
  await assert.rejects(stat(obsolete), error => error?.code === 'ENOENT');
  assert.equal((await stat(unknown)).isFile(), true);

  await writeFile(obsolete, 'offline-cache', 'utf8');
  await pruneClientShellCache(root, null);
  assert.equal((await stat(obsolete)).isFile(), true);
});
