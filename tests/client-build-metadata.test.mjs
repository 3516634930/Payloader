import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const importBuilder = async (buildRoot, label) => {
  process.env.PAYLOADER_CLIENT_BUILD_ROOT = buildRoot;
  process.env.PAYLOADER_CLIENT_SHELLS_REMOTE_DISABLED = 'true';
  const moduleUrl = new URL('../server/client-builder.mjs', import.meta.url);
  moduleUrl.searchParams.set('client-build-metadata-test', `${label}-${Date.now()}-${Math.random()}`);
  return import(moduleUrl.href);
};

test('official shells make foreign targets available without cross-platform native packaging', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('shell-target');
  t.after(() => rm(temp.root, { recursive: true, force: true }));
  const builder = await importBuilder(temp.buildRoot, 'shell-target');
  builder.__clientBuildTest.setShellCatalogProvider(async () => ({
    source: 'github-release',
    manifest: { appVersion: '2.0.0' },
    targets: {
      'mac-arm64-dmg': {
        platform: 'macos',
        arch: 'arm64',
        outputFormat: 'tar.gz',
        signed: false,
      },
    },
  }));
  const status = await builder.getClientBuildStatus();
  const target = status.targets.find(item => item.id === 'mac-arm64-dmg');
  assert.equal(target.supported, true);
  assert.equal(target.source, 'official-shell');
  assert.equal(target.format, 'Portable TAR.GZ');
  assert.equal(status.environment.shellVersion, '2.0.0');
});

const makeTempBuildRoot = async label => {
  const root = await mkdtemp(join(tmpdir(), `payloader-client-build-${label}-`));
  return { root, buildRoot: join(root, 'client-builds') };
};

const artifactFileName = 'Payloader-Client-20260711-000000-deadbeef-win-x64-nsis.exe';

const makeSuccess = (builder, overrides = {}) => {
  const { contract } = builder.__clientBuildTest;
  const item = {
    targetId: 'win-x64-nsis',
    platform: 'windows',
    platformLabel: 'Windows',
    arch: 'x64',
    archLabel: 'Intel / AMD 64-bit',
    format: 'Windows Installer',
    fileName: artifactFileName,
    size: 8,
    sha256: 'abc123',
    generatedAt: '2026-07-11T00:00:00.000Z',
    runtime: contract.runtime,
    distribution: contract.distribution,
    buildContractVersion: contract.buildContractVersion,
    mimeType: 'application/vnd.microsoft.portable-executable',
  };
  return {
    id: 'success-build',
    status: 'success',
    message: 'Ready to download 1 client build',
    startedAt: '2026-07-11T00:00:00.000Z',
    finishedAt: '2026-07-11T00:00:10.000Z',
    metadataVersion: contract.metadataVersion,
    runtime: contract.runtime,
    distribution: contract.distribution,
    buildContractVersion: contract.buildContractVersion,
    sourceHash: 'stored-source',
    publicDataHash: 'stored-public-data',
    latest: item,
    items: [item],
    ...overrides,
  };
};

const fileExists = async filePath => {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
};

test('a failed build is persisted separately without replacing the last successful release', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('failure');
  const builder = await importBuilder(temp.buildRoot, 'failure-writer');
  t.after(async () => {
    await rm(temp.root, { recursive: true, force: true });
  });

  const success = makeSuccess(builder);
  await mkdir(temp.buildRoot, { recursive: true });
  await writeFile(join(temp.buildRoot, artifactFileName), 'artifact', 'utf8');
  await builder.__clientBuildTest.persistSuccessfulMetadata(success);

  const failure = {
    id: 'failed-build',
    status: 'failed',
    message: 'packaging failed',
    startedAt: '2026-07-11T00:01:00.000Z',
    finishedAt: '2026-07-11T00:01:05.000Z',
    logs: ['stderr: simulated failure'],
  };
  await builder.__clientBuildTest.persistFailureMetadata(failure);

  const latestOnDisk = JSON.parse(await readFile(builder.__clientBuildTest.paths.latestFile, 'utf8'));
  const failureOnDisk = JSON.parse(await readFile(builder.__clientBuildTest.paths.lastFailureFile, 'utf8'));
  assert.equal(latestOnDisk.id, success.id);
  assert.equal(latestOnDisk.status, 'success');
  assert.equal(failureOnDisk.id, failure.id);
  assert.equal((await builder.clientBuildDownload(artifactFileName))?.fileName, artifactFileName);

  const restarted = await importBuilder(temp.buildRoot, 'failure-reader');
  restarted.__clientBuildTest.setFreshnessHashProvider(async () => ({
    sourceHash: success.sourceHash,
    publicDataHash: success.publicDataHash,
  }));
  const status = await restarted.getClientBuildStatus();
  assert.equal(status.active, null);
  assert.equal(status.latest.id, success.id);
  assert.equal(status.lastFailure.id, failure.id);
  assert.deepEqual(status.lastFailure.logs, failure.logs);
  const publicInfo = await restarted.getPublicClientBuildInfo();
  const serializedPublicInfo = JSON.stringify(publicInfo);
  assert.equal(Object.hasOwn(publicInfo, 'lastFailure'), false);
  assert.equal(publicInfo.lastBuildFailed, true);
  assert.equal(serializedPublicInfo.includes(failure.message), false);
  assert.equal(serializedPublicInfo.includes(failure.logs[0]), false);

  const nextSuccess = makeSuccess(restarted, {
    id: 'next-success-build',
    startedAt: '2026-07-11T00:02:00.000Z',
    finishedAt: '2026-07-11T00:02:10.000Z',
  });
  await restarted.__clientBuildTest.persistSuccessfulMetadata(nextSuccess);
  const recoveredStatus = await restarted.getClientBuildStatus();
  assert.equal(recoveredStatus.latest.id, nextSuccess.id);
  assert.equal(recoveredStatus.lastFailure, null);
  assert.equal(await fileExists(restarted.__clientBuildTest.paths.lastFailureFile), false);
  assert.equal((await restarted.getPublicClientBuildInfo()).lastBuildFailed, false);
});

test('client build persistence prunes obsolete artifacts without touching the active release or unknown files', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('artifact-pruning');
  const builder = await importBuilder(temp.buildRoot, 'artifact-pruning');
  t.after(() => rm(temp.root, { recursive: true, force: true }));

  const active = artifactFileName;
  const obsolete = 'Payloader-Client-20260710-000000-feedbeef-win-x64-nsis.exe';
  const failedPartial = 'Payloader-Client-20260712-000000-cafebabe-mac-arm64-portable.tar.gz';
  const unknown = 'operator-notes.txt';
  const cacheFile = join(temp.buildRoot, '.builder-cache', 'preserve.bin');
  await mkdir(join(temp.buildRoot, '.builder-cache'), { recursive: true });
  for (const name of [active, `${active}.sha256.txt`, obsolete, `${obsolete}.sha256.txt`, unknown]) {
    await writeFile(join(temp.buildRoot, name), name, 'utf8');
  }
  await writeFile(cacheFile, 'cache', 'utf8');

  await builder.__clientBuildTest.persistSuccessfulMetadata(makeSuccess(builder));
  assert.equal(await fileExists(join(temp.buildRoot, active)), true);
  assert.equal(await fileExists(join(temp.buildRoot, `${active}.sha256.txt`)), true);
  assert.equal(await fileExists(join(temp.buildRoot, obsolete)), false);
  assert.equal(await fileExists(join(temp.buildRoot, `${obsolete}.sha256.txt`)), false);
  assert.equal(await fileExists(join(temp.buildRoot, unknown)), true);
  assert.equal(await fileExists(cacheFile), true);

  await writeFile(join(temp.buildRoot, failedPartial), 'partial', 'utf8');
  await writeFile(join(temp.buildRoot, `${failedPartial}.sha256.txt`), 'partial', 'utf8');
  await builder.__clientBuildTest.persistFailureMetadata({
    id: 'failed-partial-build',
    status: 'failed',
    message: 'simulated failure',
    startedAt: '2026-07-12T00:00:00.000Z',
    finishedAt: '2026-07-12T00:00:01.000Z',
  });
  assert.equal(await fileExists(join(temp.buildRoot, failedPartial)), false);
  assert.equal(await fileExists(join(temp.buildRoot, `${failedPartial}.sha256.txt`)), false);
  assert.equal((await builder.clientBuildDownload(active))?.fileName, active);
});

test('freshness classifies frontend and public-data hash mismatches independently', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('classification');
  const builder = await importBuilder(temp.buildRoot, 'classification');
  t.after(async () => {
    await rm(temp.root, { recursive: true, force: true });
  });
  const success = makeSuccess(builder);

  const sourceMismatch = builder.__clientBuildTest.evaluateFreshness(
    success,
    { sourceHash: 'current-source', publicDataHash: success.publicDataHash },
    '2026-07-11T01:00:00.000Z',
  );
  assert.deepEqual(sourceMismatch, {
    isCurrent: false,
    sourceCurrent: false,
    publicDataCurrent: true,
    reasons: ['frontend-source-changed'],
    checkedAt: '2026-07-11T01:00:00.000Z',
    currentSourceHash: 'current-source',
    currentPublicDataHash: success.publicDataHash,
  });

  const publicDataMismatch = builder.__clientBuildTest.evaluateFreshness(
    success,
    { sourceHash: success.sourceHash, publicDataHash: 'current-public-data' },
    '2026-07-11T01:01:00.000Z',
  );
  assert.equal(publicDataMismatch.sourceCurrent, true);
  assert.equal(publicDataMismatch.publicDataCurrent, false);
  assert.deepEqual(publicDataMismatch.reasons, ['public-data-changed']);
});

test('status without a successful build skips expensive freshness hashing', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('no-build-short-circuit');
  const builder = await importBuilder(temp.buildRoot, 'no-build-short-circuit');
  t.after(() => rm(temp.root, { recursive: true, force: true }));
  let computations = 0;
  builder.__clientBuildTest.setFreshnessHashProvider(async () => {
    computations += 1;
    return { sourceHash: 'unused', publicDataHash: 'unused' };
  });

  const publicInfo = await builder.getPublicClientBuildInfo();

  assert.equal(publicInfo.available, false);
  assert.deepEqual(publicInfo.freshness.reasons, ['no-successful-build']);
  assert.equal(computations, 0);
});

test('current-contract artifacts remain downloadable when freshness is stale', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('stale-download');
  const builder = await importBuilder(temp.buildRoot, 'stale-download');
  t.after(async () => {
    await rm(temp.root, { recursive: true, force: true });
  });
  const success = makeSuccess(builder);
  await mkdir(temp.buildRoot, { recursive: true });
  await writeFile(join(temp.buildRoot, artifactFileName), 'artifact', 'utf8');
  await builder.__clientBuildTest.persistSuccessfulMetadata(success);
  builder.__clientBuildTest.setFreshnessHashProvider(async () => ({
    sourceHash: 'changed-source',
    publicDataHash: 'changed-public-data',
  }));

  const [status, publicInfo, download] = await Promise.all([
    builder.getClientBuildStatus(),
    builder.getPublicClientBuildInfo(),
    builder.clientBuildDownload(artifactFileName),
  ]);

  assert.equal(status.latest.status, 'success');
  assert.equal(status.items.length, 1);
  assert.equal(status.freshness.isCurrent, false);
  assert.deepEqual(status.freshness.reasons, ['frontend-source-changed', 'public-data-changed']);
  assert.equal(publicInfo.available, true);
  assert.equal(publicInfo.items.length, 1);
  assert.equal(publicInfo.freshness.isCurrent, false);
  assert.equal(download?.fileName, artifactFileName);
});

test('old-contract and legacy failed latest metadata never enter the download allowlist', { concurrency: false }, async t => {
  const oldContractTemp = await makeTempBuildRoot('old-contract');
  const oldContractBuilder = await importBuilder(oldContractTemp.buildRoot, 'old-contract');
  const oldContractSuccess = makeSuccess(oldContractBuilder, {
    buildContractVersion: oldContractBuilder.__clientBuildTest.contract.buildContractVersion - 1,
  });
  oldContractSuccess.items = oldContractSuccess.items.map(item => ({
    ...item,
    buildContractVersion: oldContractSuccess.buildContractVersion,
  }));
  oldContractSuccess.latest = oldContractSuccess.items[0];
  await mkdir(oldContractTemp.buildRoot, { recursive: true });
  await writeFile(join(oldContractTemp.buildRoot, artifactFileName), 'artifact', 'utf8');
  await oldContractBuilder.__clientBuildTest.persistSuccessfulMetadata(oldContractSuccess);
  oldContractBuilder.__clientBuildTest.setFreshnessHashProvider(async () => ({
    sourceHash: oldContractSuccess.sourceHash,
    publicDataHash: oldContractSuccess.publicDataHash,
  }));

  const oldContractInfo = await oldContractBuilder.getPublicClientBuildInfo();
  assert.equal(oldContractInfo.available, false);
  assert.equal(oldContractInfo.staleLatest.buildContractVersion, oldContractSuccess.buildContractVersion);
  assert.equal(oldContractInfo.freshness.isCurrent, false);
  assert.ok(oldContractInfo.freshness.reasons.includes('build-contract-changed'));
  assert.equal(await oldContractBuilder.clientBuildDownload(artifactFileName), null);

  const legacyFailureTemp = await makeTempBuildRoot('legacy-failure');
  const legacyFailureBuilder = await importBuilder(legacyFailureTemp.buildRoot, 'legacy-failure');
  await mkdir(legacyFailureTemp.buildRoot, { recursive: true });
  await writeFile(legacyFailureBuilder.__clientBuildTest.paths.latestFile, JSON.stringify({
    id: 'legacy-failure',
    status: 'failed',
    message: 'old process failed',
    startedAt: '2026-07-11T02:00:00.000Z',
    finishedAt: '2026-07-11T02:00:01.000Z',
  }), 'utf8');
  legacyFailureBuilder.__clientBuildTest.setFreshnessHashProvider(async () => ({
    sourceHash: 'current-source',
    publicDataHash: 'current-public-data',
  }));
  const legacyStatus = await legacyFailureBuilder.getClientBuildStatus();
  assert.equal(legacyStatus.latest, null);
  assert.equal(legacyStatus.staleLatest, null);
  assert.equal(legacyStatus.lastFailure.id, 'legacy-failure');
  assert.equal(await legacyFailureBuilder.clientBuildDownload('latest'), null);

  t.after(async () => {
    await Promise.all([
      rm(oldContractTemp.root, { recursive: true, force: true }),
      rm(legacyFailureTemp.root, { recursive: true, force: true }),
    ]);
  });
});

test('concurrent status requests share one cached freshness computation', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('freshness-cache');
  const builder = await importBuilder(temp.buildRoot, 'freshness-cache');
  t.after(async () => {
    await rm(temp.root, { recursive: true, force: true });
  });
  const success = makeSuccess(builder);
  await mkdir(temp.buildRoot, { recursive: true });
  await writeFile(join(temp.buildRoot, artifactFileName), 'artifact', 'utf8');
  await builder.__clientBuildTest.persistSuccessfulMetadata(success);

  let computations = 0;
  builder.__clientBuildTest.setFreshnessHashProvider(async () => {
    computations += 1;
    await new Promise(resolve => setTimeout(resolve, 20));
    return {
      sourceHash: success.sourceHash,
      publicDataHash: success.publicDataHash,
    };
  });

  const [first, second, publicInfo] = await Promise.all([
    builder.getClientBuildStatus(),
    builder.getClientBuildStatus(),
    builder.getPublicClientBuildInfo(),
  ]);

  assert.equal(computations, 1);
  assert.equal(first.freshness.isCurrent, true);
  assert.equal(second.freshness.checkedAt, first.freshness.checkedAt);
  assert.equal(publicInfo.freshness.checkedAt, first.freshness.checkedAt);
  assert.equal(await fileExists(builder.__clientBuildTest.paths.lastFailureFile), false);
});

test('persisting a success invalidates freshness cache and the TTL stays within the polling bound', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('freshness-invalidation');
  const builder = await importBuilder(temp.buildRoot, 'freshness-invalidation');
  t.after(async () => {
    await rm(temp.root, { recursive: true, force: true });
  });
  const success = makeSuccess(builder);
  await builder.__clientBuildTest.persistSuccessfulMetadata(success);

  let computations = 0;
  builder.__clientBuildTest.setFreshnessHashProvider(async () => {
    computations += 1;
    return {
      sourceHash: success.sourceHash,
      publicDataHash: success.publicDataHash,
    };
  });
  assert.ok(builder.__clientBuildTest.freshnessCacheTtlMs >= 5_000);
  assert.ok(builder.__clientBuildTest.freshnessCacheTtlMs <= 15_000);

  const first = await builder.getClientBuildStatus();
  assert.equal(first.freshness.isCurrent, true);
  assert.equal(computations, 1);

  await builder.__clientBuildTest.persistSuccessfulMetadata({
    ...success,
    message: 'Same release confirmed again',
    finishedAt: '2026-07-11T00:03:00.000Z',
  });
  const second = await builder.getClientBuildStatus();
  assert.equal(second.freshness.isCurrent, true);
  assert.equal(computations, 2);
});

test('admin failed-build rendering reads the independent lastFailure field', async () => {
  const adminSource = await readFile(new URL('../admin/admin.js', import.meta.url), 'utf8');
  const helperSource = adminSource.match(/const clientBuildFailed = \(\) => \{[\s\S]*?\n\};/)?.[0] || '';
  assert.match(helperSource, /state\.clientBuildStatus\?\.lastFailure/);
  assert.doesNotMatch(helperSource, /latest\?\.status === 'failed'/);
});

test('packaged client keeps large snapshots and assets off the main-process heap', async () => {
  const electronSource = await readFile(new URL('../server/client-electron-main.cjs', import.meta.url), 'utf8');
  const builderSource = await readFile(new URL('../server/client-builder.mjs', import.meta.url), 'utf8');

  assert.match(electronSource, /createReadStream/);
  assert.match(electronSource, /Readable\.toWeb/);
  assert.match(electronSource, /require\(['"]\.\/client-deployment-runtime\.cjs['"]\)/);
  assert.match(electronSource, /resolveDeploymentPackageCandidates/);
  assert.match(electronSource, /loadExternalDeploymentPackage/);
  assert.match(electronSource, /deploymentPackage\?\.manifest/);
  assert.match(electronSource, /custom-tools\.json/);
  assert.doesNotMatch(electronSource, /const assetCache = new Map\(\)/);
  assert.doesNotMatch(electronSource, /void loadPublicDataSnapshot\(\)/);
  assert.doesNotMatch(electronSource, /Pre-read hashed JS\/CSS bundles/);
  assert.match(builderSource, /custom-tools\.json/);
  assert.match(builderSource, /projectAttributionSource/);
  assert.match(builderSource, /copyFile\(projectAttributionSource/);
  assert.match(builderSource, /copyFile\(clientDeploymentRuntimeSource/);
  assert.match(builderSource, /project-attribution\.cjs/);
  assert.match(builderSource, /client-deployment-runtime\.cjs/);
  assert.match(electronSource, /require\(['"]\.\/project-attribution\.cjs['"]\)/);
  assert.match(electronSource, /value === clientProjectRoute/);
});

test('packaged client enables background throttling and prevents duplicate instances', async () => {
  const electronSource = await readFile(new URL('../server/client-electron-main.cjs', import.meta.url), 'utf8');

  assert.match(electronSource, /requestSingleInstanceLock\(\)/);
  assert.match(electronSource, /app\.on\(['"]second-instance['"]/);
  assert.match(electronSource, /backgroundThrottling:\s*!performanceSmokeEnabled/);
  assert.match(electronSource, /v8CacheOptions:\s*['"]code['"]/);
  assert.doesNotMatch(electronSource, /navigate-to/);
});

test('packaged Windows client uses software rendering without mouse capture APIs', async () => {
  const electronSource = await readFile(new URL('../server/client-electron-main.cjs', import.meta.url), 'utf8');
  const builderSource = await readFile(new URL('../server/client-builder.mjs', import.meta.url), 'utf8');
  const rendererRoot = fileURLToPath(new URL('../src/', import.meta.url));
  const rendererFiles = (await readdir(rendererRoot, { recursive: true }))
    .filter(file => /\.(?:css|js|jsx|ts|tsx)$/.test(file));
  const rendererSource = (await Promise.all(
    rendererFiles.map(file => readFile(join(rendererRoot, file), 'utf8')),
  )).join('\n');

  assert.match(
    electronSource,
    /process\.platform === ['"]win32['"][\s\S]{0,160}app\.disableHardwareAcceleration\(\)/,
  );
  assert.match(
    electronSource,
    /app\.(?:on|once)\(['"]gpu-info-update['"][\s\S]{0,160}hardwareAccelerationEnabled\s*=\s*app\.isHardwareAccelerationEnabled\(\)/,
  );
  assert.match(electronSource, /hardwareAccelerationEnabled,\s*\n\s*windowReadyMs/);
  assert.doesNotMatch(
    `${electronSource}\n${rendererSource}`,
    /requestPointerLock|exitPointerLock|setPointerCapture|releasePointerCapture|setIgnoreMouseEvents|cursor:\s*none/,
  );
  assert.match(builderSource, /windowsSoftwareRendering:\s*true/);
});

test('Windows assisted installers use the fast per-user path and allow every architecture to choose a directory', { concurrency: false }, async t => {
  const temp = await makeTempBuildRoot('windows-installer-options');
  t.after(() => rm(temp.root, { recursive: true, force: true }));
  const builder = await importBuilder(temp.buildRoot, 'windows-installer-options');
  const nsis = builder.__clientBuildTest.windowsNsisOptions;
  const windowsTargets = builder.__clientBuildTest.targetMatrix.filter(target => target.platform === 'windows');
  const installerInclude = await readFile(new URL('../server/client-installer.nsh', import.meta.url), 'utf8');

  assert.equal(nsis.oneClick, false);
  assert.equal(nsis.perMachine, false);
  assert.equal(nsis.allowElevation, false);
  assert.equal(nsis.allowToChangeInstallationDirectory, true);
  assert.equal(nsis.packElevateHelper, false);
  assert.equal(nsis.differentialPackage, false);
  assert.equal(nsis.useZip, false);
  assert.equal(nsis.include, 'installer.nsh');
  assert.match(installerInclude, /!macro\s+customInstallMode[\s\S]*StrCpy\s+\$isForceCurrentInstall\s+"1"[\s\S]*!macroend/);
  assert.equal(windowsTargets.length, 3);
  for (const target of windowsTargets) {
    assert.equal(target.installType, 'Assisted NSIS installer with custom directory');
  }
});

test('client build subprocess environment excludes server and host secrets', async t => {
  const temp = await makeTempBuildRoot('environment-isolation');
  t.after(() => rm(temp.root, { recursive: true, force: true }));
  const builder = await importBuilder(temp.buildRoot, 'environment-isolation');
  const environment = builder.__clientBuildTest.createBuildEnvironment({
    Path: 'C:\\Windows\\System32',
    SystemRoot: 'C:\\Windows',
    TEMP: 'C:\\Temp',
    LANG: 'zh_CN.UTF-8',
    HTTPS_PROXY: 'http://proxy.example:8080',
    PAYLOADER_ADMIN_PASSWORD: 'must-not-leak',
    PAYLOADER_JWT_SECRET: 'must-not-leak',
    PAYLOADER_DATA_DIR: 'C:\\sensitive-data',
    GH_TOKEN: 'must-not-leak',
    GITHUB_TOKEN: 'must-not-leak',
    PAYLOADER_GITHUB_TOKEN: 'must-not-leak',
    AWS_SECRET_ACCESS_KEY: 'must-not-leak',
    AZURE_CLIENT_SECRET: 'must-not-leak',
    GOOGLE_APPLICATION_CREDENTIALS: 'C:\\cloud-secret.json',
    PAYLOADER_WINDOWS_CSC_LINK: 'C:\\signing-cert.p12',
    PAYLOADER_WINDOWS_CSC_KEY_PASSWORD: 'signing-password',
  }, { includeSigning: true });

  assert.equal(environment.Path, 'C:\\Windows\\System32');
  assert.equal(environment.SystemRoot, 'C:\\Windows');
  assert.equal(environment.LANG, 'zh_CN.UTF-8');
  assert.equal(environment.HTTPS_PROXY, 'http://proxy.example:8080');
  assert.equal(environment.CSC_LINK, 'C:\\signing-cert.p12');
  assert.equal(environment.CSC_KEY_PASSWORD, 'signing-password');
  for (const secret of [
    'PAYLOADER_ADMIN_PASSWORD',
    'PAYLOADER_JWT_SECRET',
    'PAYLOADER_DATA_DIR',
    'GH_TOKEN',
    'GITHUB_TOKEN',
    'PAYLOADER_GITHUB_TOKEN',
    'AWS_SECRET_ACCESS_KEY',
    'AZURE_CLIENT_SECRET',
    'GOOGLE_APPLICATION_CREDENTIALS',
    'PAYLOADER_WINDOWS_CSC_LINK',
    'PAYLOADER_WINDOWS_CSC_KEY_PASSWORD',
  ]) {
    assert.equal(Object.prototype.hasOwnProperty.call(environment, secret), false, `${secret} leaked into the build environment`);
  }
});

test('client performance policy declares measurable runtime budgets', async t => {
  const temp = await makeTempBuildRoot('performance-policy');
  t.after(() => rm(temp.root, { recursive: true, force: true }));
  const builder = await importBuilder(temp.buildRoot, 'performance-policy');
  const policy = builder.__clientBuildTest.performancePolicy;

  assert.equal(policy.streamsPublicDataSnapshot, true);
  assert.equal(policy.boundsMainProcessAssetCache, true);
  assert.equal(policy.backgroundThrottling, true);
  assert.equal(policy.singleInstance, true);
  assert.equal(policy.windowsSoftwareRendering, true);
  assert.equal(policy.windowsInstallerCompression, '7z');
  assert.equal(policy.windowsInstallerPerUser, true);
  assert.equal(policy.reusesInstalledElectronRuntimeWhenAvailable, true);
  assert.deepEqual(policy.electronLanguages, ['zh-CN', 'en-US']);
  assert.deepEqual(builder.__clientBuildTest.electronRuntimeConfig(temp.root), { electronDist: temp.root });
  assert.deepEqual(builder.__clientBuildTest.electronRuntimeConfig(temp.root, false), {});
  assert.deepEqual(builder.__clientBuildTest.electronRuntimeConfig(join(temp.root, 'missing-electron-dist')), {});
  assert.ok(policy.windows?.windowReadyMs <= 1500);
  assert.equal(policy.windows?.searchSettledMs, 350);
  assert.ok(policy.windows?.idleWorkingSetMb <= 500);
  assert.equal(policy.windows?.interactionWorkingSetMb, 560);
  assert.equal(policy.windows?.privateMemoryMb, 450);
  assert.ok(policy.windows?.privateMemoryGrowthMb <= 80);
  assert.ok(policy.windows?.idleCpuPercentOneCore <= 2);
  assert.ok(policy.linux?.windowReadyMs <= 2500);
  assert.ok(policy.macos?.windowReadyMs <= 2500);
});
