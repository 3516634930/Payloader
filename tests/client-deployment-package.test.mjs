import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  CLIENT_BUILD_CONTRACT_VERSION,
  CLIENT_DEPLOYMENT_FORMAT,
  CLIENT_DEPLOYMENT_PACKAGE_VERSION,
  validateClientDeploymentManifest,
  writeClientDeploymentPackage,
} from '../server/client-deployment-package.mjs';

const require = createRequire(import.meta.url);
const {
  loadExternalDeploymentPackage,
  resolveDeploymentPackageCandidates,
} = require('../server/client-deployment-runtime.cjs');

const makeTemp = label => mkdtemp(join(tmpdir(), `payloader-deployment-${label}-`));

const publicDataFixture = logoUrl => ({
  settings: {
    title: { zh: '测试站点', en: 'Test site' },
    logoUrl,
  },
  payloads: [{ id: 'payload-1', name: { zh: '测试', en: 'Test' } }],
  tools: [
    { id: 'tool-1', name: { zh: '工具', en: 'Tool' } },
    { id: 'custom-tool-1', name: { zh: '自定义', en: 'Custom' } },
  ],
  navigation: [{ id: 'root' }],
  toolNavigation: [{ id: 'tool-root' }],
});

test('deployment package writes deterministic public files, hashes, stats, and safe assets', async t => {
  const root = await makeTemp('write');
  t.after(() => rm(root, { recursive: true, force: true }));
  const logoFile = join(root, 'source-logo.png');
  const destination = join(root, 'deployment.payloader');
  await writeFile(logoFile, Buffer.from([0x89, 0x50, 0x4e, 0x47]));

  const result = await writeClientDeploymentPackage({
    destination,
    publicData: publicDataFixture('/uploads/logo/logo-safe.png'),
    logoFile,
    generatedAt: '2026-07-13T00:00:00.000Z',
  });

  const manifest = JSON.parse(await readFile(join(destination, 'manifest.json'), 'utf8'));
  const publicData = JSON.parse(await readFile(join(destination, 'public-data.json'), 'utf8'));
  const customTools = JSON.parse(await readFile(join(destination, 'custom-tools.json'), 'utf8'));
  const logo = await readFile(join(destination, 'assets', 'uploads', 'logo', 'logo-safe.png'));

  assert.equal(result.destination, destination);
  assert.equal(manifest.format, CLIENT_DEPLOYMENT_FORMAT);
  assert.equal(manifest.packageVersion, CLIENT_DEPLOYMENT_PACKAGE_VERSION);
  assert.equal(manifest.buildContractVersion, CLIENT_BUILD_CONTRACT_VERSION);
  assert.equal(manifest.generatedAt, '2026-07-13T00:00:00.000Z');
  assert.deepEqual(manifest.stats, { payloads: 1, tools: 2, navigation: 1, toolNavigation: 1 });
  assert.deepEqual(publicData, publicDataFixture('/uploads/logo/logo-safe.png'));
  assert.deepEqual(customTools, { version: 1, categories: [publicData.tools[1]] });
  assert.deepEqual([...logo], [0x89, 0x50, 0x4e, 0x47]);
  assert.match(manifest.files['public-data.json'].sha256, /^[a-f0-9]{64}$/);
  assert.equal(manifest.files['public-data.json'].size, Buffer.byteLength(JSON.stringify(publicData)));
  assert.equal(manifest.assets['/uploads/logo/logo-safe.png'].file, 'assets/uploads/logo/logo-safe.png');
  assert.equal(manifest.excludes.includes('administrator credentials and JWT material'), true);
  assert.equal(JSON.stringify(manifest).includes(root), false);
  assert.deepEqual(validateClientDeploymentManifest(manifest), manifest);
});

test('deployment package rejects unsafe asset routes and malformed manifests', async t => {
  const root = await makeTemp('unsafe');
  t.after(() => rm(root, { recursive: true, force: true }));

  await assert.rejects(() => writeClientDeploymentPackage({
    destination: join(root, 'deployment.payloader'),
    publicData: publicDataFixture('/uploads/logo/../../secret.png'),
    logoFile: join(root, 'secret.png'),
  }), /unsafe logo route/i);

  assert.throws(() => validateClientDeploymentManifest({
    format: CLIENT_DEPLOYMENT_FORMAT,
    packageVersion: CLIENT_DEPLOYMENT_PACKAGE_VERSION,
    buildContractVersion: CLIENT_BUILD_CONTRACT_VERSION - 1,
    files: {},
    assets: {},
  }), /build contract/i);
});

test('deployment package atomically replaces an existing package without leaving temporary directories', async t => {
  const root = await makeTemp('replace');
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = join(root, 'deployment.payloader');

  await writeClientDeploymentPackage({
    destination,
    publicData: publicDataFixture(''),
    generatedAt: '2026-07-13T00:00:00.000Z',
  });
  await writeFile(join(destination, 'obsolete.txt'), 'obsolete', 'utf8');
  await writeClientDeploymentPackage({
    destination,
    publicData: { ...publicDataFixture(''), payloads: [] },
    generatedAt: '2026-07-13T01:00:00.000Z',
  });

  const files = await readdir(destination);
  const siblings = await readdir(root);
  const manifest = JSON.parse(await readFile(join(destination, 'manifest.json'), 'utf8'));
  assert.equal(files.includes('obsolete.txt'), false);
  assert.equal(siblings.some(name => name.includes('.tmp-') || name.includes('.backup-')), false);
  assert.equal(manifest.stats.payloads, 0);
});

test('runtime discovers executable-adjacent packages and the macOS bundle sibling', () => {
  assert.deepEqual(resolveDeploymentPackageCandidates({
    platform: 'win32',
    execPath: 'C:\\Payloader\\Payloader.exe',
    appImagePath: '',
  }), ['C:\\Payloader\\deployment.payloader']);
  assert.deepEqual(resolveDeploymentPackageCandidates({
    platform: 'linux',
    execPath: '/opt/payloader/Payloader',
    appImagePath: '/downloads/Payloader.AppImage',
  }), [
    '/downloads/deployment.payloader',
    '/opt/payloader/deployment.payloader',
  ]);
  assert.deepEqual(resolveDeploymentPackageCandidates({
    platform: 'darwin',
    execPath: '/Applications/Payloader.app/Contents/MacOS/Payloader',
    appImagePath: '',
  }), ['/Applications/deployment.payloader']);
});

test('runtime validates an external package and rejects a tampered file descriptor', async t => {
  const root = await makeTemp('runtime');
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = join(root, 'deployment.payloader');
  await writeClientDeploymentPackage({
    destination,
    publicData: publicDataFixture(''),
    generatedAt: '2026-07-13T00:00:00.000Z',
  });

  const loaded = await loadExternalDeploymentPackage([destination]);
  assert.equal(loaded.root, destination);
  assert.equal(loaded.publicDataPath, join(destination, 'public-data.json'));
  assert.equal(loaded.customToolsPath, join(destination, 'custom-tools.json'));

  const manifestPath = join(destination, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.files['public-data.json'].size += 1;
  await writeFile(manifestPath, JSON.stringify(manifest), 'utf8');
  await assert.rejects(() => loadExternalDeploymentPackage([destination]), /size mismatch/i);
});
