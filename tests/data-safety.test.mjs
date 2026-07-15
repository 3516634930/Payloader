import assert from 'node:assert/strict';
import { access, copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const defaultSeedPath = fileURLToPath(new URL('../server/default-seed.sqlite', import.meta.url));

const uniqueModuleUrl = (path, label) => (
  new URL(`${path}?data-safety=${encodeURIComponent(`${label}-${Date.now()}-${Math.random()}`)}`, import.meta.url).href
);

const importStore = async ({ dataDir, seedPath = defaultSeedPath, label }) => {
  process.env.PAYLOADER_DATA_DIR = dataDir;
  process.env.PAYLOADER_SEED_DB = seedPath;
  return import(uniqueModuleUrl('../server/data-store.mjs', label));
};

const makeTempDataDir = async label => {
  const root = await mkdtemp(join(tmpdir(), `payloader-${label}-`));
  return { root, dataDir: join(root, 'data') };
};

const fileExists = async path => {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
};

const isInvalidTargetError = error => error?.status === 400 && /target/i.test(error.message);

const deferred = () => {
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return { promise, resolve: resolvePromise, reject: rejectPromise };
};

test('database initialization is shared until seed and migrations complete', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('init-race');
  const store = await importStore({ ...temp, label: 'init-race' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  const defaults = await store.loadDefaultData();
  const [publicData, adminPayloads, settings] = await Promise.all([
    store.getPublicData(),
    store.listAdminItems('payloads'),
    store.getSettings(),
    store.getMetadataValue('seeded'),
  ]);

  assert.equal(adminPayloads.length, defaults.payloads.length);
  assert.ok(publicData.payloads.length > 0);
  const xssPlatform = publicData.tools.find(item => item.id === 'xss-platform');
  assert.equal(xssPlatform?.externalUrl, 'https://xss.icu/');
  assert.equal(xssPlatform?.systemLocked, true);
  assert.ok(publicData.toolNavigation.some(item => item.toolId === 'xss-platform'));
  assert.equal(settings.siteTitle.zh, 'PAYLOADER');
  assert.equal(await store.getMetadataValue('seeded'), '1');
});

test('fresh initialization preserves the validated seed content exactly', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('seed-baseline');
  const store = await importStore({ ...temp, label: 'seed-baseline' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  const defaults = await store.loadDefaultData();
  await store.ensureStoreReady();

  assert.deepEqual(store.loadContentDataFromDatabase(store.getRuntimeDbFile()), defaults);
  for (const migrationKey of store.seedIncludedMigrationKeys) {
    assert.equal(await store.getMetadataValue(migrationKey), '1');
    assert.ok(await store.getMetadataValue(`${migrationKey}_at`));
  }
});

test('existing databases migrate plaintext project attribution to the opaque route', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('project-attribution-migration');
  const initialStore = await importStore({ ...temp, label: 'project-attribution-migration-before' });
  const legacyProjectUrl = Buffer.from([
    104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99,
    111, 109, 47, 51, 53, 49, 54, 54, 51, 52, 57, 51, 48, 47, 80, 97,
    121, 108, 111, 97, 100, 101, 114,
  ]).toString('utf8');
  t.after(async () => {
    initialStore.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  await initialStore.ensureStoreReady();
  await initialStore.setMetadataValue('settings', JSON.stringify({
    ...(await initialStore.getSettings()),
    projectUrl: legacyProjectUrl,
  }));
  await initialStore.setMetadataValue('migration_project_attribution_v1', '0');
  initialStore.closeStore();

  const migratedStore = await importStore({ ...temp, label: 'project-attribution-migration-after' });
  await migratedStore.ensureStoreReady();
  assert.equal((await migratedStore.getSettings()).projectUrl, '/api/r/p');
  assert.ok(!(await migratedStore.getMetadataValue('settings')).includes(legacyProjectUrl));
  assert.equal(await migratedStore.getMetadataValue('migration_project_attribution_v1'), '1');
  migratedStore.closeStore();
});

test('admin writes reject demo placeholder content', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('placeholder-rejection');
  const store = await importStore({ ...temp, label: 'placeholder-rejection' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  const placeholderPayload = {
    id: 'placeholder-payload',
    name: { zh: '新 Payload', en: 'New Payload' },
    description: { zh: '', en: '' },
    category: { zh: '未分类', en: 'Uncategorized' },
    execution: [{ title: { zh: '新命令', en: 'New command' }, command: 'echo TODO' }],
  };

  await assert.rejects(
    store.saveAdminItem('payloads', placeholderPayload),
    error => error?.status === 400 && /占位内容/.test(error.message),
  );
  await assert.rejects(
    store.importDataPackage({ payloads: [placeholderPayload] }),
    error => error?.status === 400 && /占位内容/.test(error.message),
  );
});

test('administrators can remove and restore the default Xeye entry', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('xeye-removal');
  const store = await importStore({ ...temp, label: 'xeye-removal' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  assert.ok((await store.listAdminItems('tools')).some(item => item.id === 'xss-platform'));
  await store.deleteAdminItem('tools', 'xss-platform');

  const removed = await store.getPublicData();
  assert.equal(removed.settings.xeyeEnabled, false);
  assert.ok(!removed.tools.some(item => item.id === 'xss-platform'));
  assert.ok(!removed.toolNavigation.some(item => item.toolId === 'xss-platform'));
  assert.ok(!(await store.listAdminItems('tools')).some(item => item.id === 'xss-platform'));

  const impact = await store.getResetImpact('tools');
  assert.deepEqual(impact.integrations.xeye, {
    affected: true,
    before: false,
    seed: true,
    changed: true,
  });

  await store.resetDefaultData('tools');
  const restored = await store.getPublicData();
  assert.equal(restored.settings.xeyeEnabled, true);
  assert.ok(restored.tools.some(item => item.id === 'xss-platform'));
  assert.ok(restored.toolNavigation.some(item => item.toolId === 'xss-platform'));
});

test('failed database initialization closes the candidate and can be retried', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('init-retry');
  const missingSeedPath = join(temp.root, 'seed', 'default-seed.sqlite');
  const store = await importStore({ ...temp, seedPath: missingSeedPath, label: 'init-retry' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  await assert.rejects(store.getPublicData(), /Default seed database not found/);

  await mkdir(dirname(missingSeedPath), { recursive: true });
  await copyFile(defaultSeedPath, missingSeedPath);
  const payloads = await store.listAdminItems('payloads');

  assert.ok(payloads.length > 0);
  assert.equal(await store.getMetadataValue('seeded'), '1');
});

test('closeStore invalidates an in-flight initializer before it can publish the database', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('init-close-race');
  const store = await importStore({ ...temp, label: 'init-close-race' });
  const publishReached = deferred();
  const releasePublish = deferred();
  t.after(async () => {
    store.setStoreTestHooks(null);
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  store.setStoreTestHooks({
    beforeInitializationPublish: async () => {
      publishReached.resolve();
      await releasePublish.promise;
    },
  });
  const firstInitialization = store.ensureStoreReady();
  await publishReached.promise;

  store.closeStore();
  releasePublish.resolve();

  await assert.rejects(
    firstInitialization,
    error => error?.code === 'ERR_STORE_INITIALIZATION_CANCELLED',
  );
  store.setStoreTestHooks(null);
  assert.equal(await store.ensureStoreReady(), true);
});

test('reset impact is read-only and reset creates a restorable WAL-safe backup', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('reset-backup');
  const store = await importStore({ ...temp, label: 'reset-backup' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  const defaults = await store.loadDefaultData();
  const customPayload = {
    id: 'custom-before-reset',
    name: { zh: '重置前自定义项', en: 'Custom item before reset' },
    description: { zh: '用于验证重置备份', en: 'Used to verify reset backups' },
    category: { zh: '测试', en: 'Test' },
    execution: [{
      title: 'Reset backup regression command',
      description: 'Creates deterministic test output without changing the environment.',
      command: 'echo PAYLOADER_RESET_BACKUP_TEST',
    }],
  };
  await store.saveAdminItem('payloads', customPayload);

  const impact = await store.getResetImpact('payloads');
  assert.equal(impact.target, 'payloads');
  assert.deepEqual(impact.affected, ['payloads']);
  assert.equal(impact.before.payloads, defaults.payloads.length + 1);
  assert.equal(impact.seed.payloads, defaults.payloads.length);
  assert.equal(impact.delta.payloads, -1);
  assert.equal(impact.changes.payloads.removed, 1);
  assert.ok((await store.listAdminItems('payloads')).some(item => item.id === customPayload.id));

  const exported = await store.createDataExportPackage();
  assert.equal(exported.format, 'payloader.export.v1');
  assert.ok(exported.data.payloads.some(item => item.id === customPayload.id));
  assert.equal(exported.summary.payloads, defaults.payloads.length + 1);

  await assert.rejects(
    store.getResetImpact('../all'),
    error => error?.status === 400 && /target/i.test(error.message),
  );

  const reset = await store.resetDefaultData('payloads');
  assert.equal(reset.impact.target, 'payloads');
  assert.deepEqual(reset.before, impact.before);
  assert.deepEqual(reset.seed, impact.seed);
  assert.deepEqual(reset.delta, impact.delta);
  assert.ok(reset.data && Array.isArray(reset.data.payloads));
  assert.equal(reset.backup.integrity, 'ok');
  assert.ok(['node:sqlite.backup', 'checkpoint-vacuum-into'].includes(reset.backup.method));
  assert.equal(isAbsolute(reset.backup.path), false);
  assert.match(reset.backup.fileName, /^payloader-before-reset-payloads-[a-zA-Z0-9-]+\.sqlite$/);

  const backupPath = resolve(temp.dataDir, reset.backup.path);
  const backupRelativePath = relative(resolve(temp.dataDir, 'backups'), backupPath);
  assert.ok(backupRelativePath && !backupRelativePath.startsWith('..') && !isAbsolute(backupRelativePath));
  assert.equal(await fileExists(backupPath), true);
  assert.ok(store.loadContentDataFromDatabase(backupPath).payloads.some(item => item.id === customPayload.id));
  assert.ok(!(await store.listAdminItems('payloads')).some(item => item.id === customPayload.id));
});

test('reset targets require an exact supported string for direct calls', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('reset-targets');
  const store = await importStore({ ...temp, label: 'reset-targets' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  const invalidTargets = [undefined, null, '', ['all'], { target: 'all' }];
  for (const target of invalidTargets) {
    await assert.rejects(store.getResetImpact(target), isInvalidTargetError);
  }
  for (const target of invalidTargets) {
    assert.throws(() => store.resetDefaultData(target), isInvalidTargetError);
  }
});

test('reset leaves all content untouched when the pre-reset backup fails', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('backup-failure');
  const store = await importStore({ ...temp, label: 'backup-failure' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  await store.ensureStoreReady();
  await store.saveAdminItem('payloads', {
    id: 'must-survive-backup-failure',
    name: 'Must survive backup failure',
    description: 'Backup failure regression item',
    category: 'Test',
    execution: [{
      title: 'Backup failure regression command',
      description: 'Creates deterministic test output without changing the environment.',
      command: 'echo PAYLOADER_BACKUP_FAILURE_TEST',
    }],
  });
  await writeFile(join(temp.dataDir, 'backups'), 'not a directory', { flag: 'wx' });

  const readCounts = async () => ({
    payloads: (await store.listAdminItems('payloads')).length,
    tools: (await store.listAdminItems('tools')).length,
    navigation: (await store.listAdminItems('navigation')).length,
  });
  const before = await readCounts();

  await assert.rejects(store.resetDefaultData('all'));

  assert.deepEqual(await readCounts(), before);
  assert.ok((await store.listAdminItems('payloads')).some(item => item.id === 'must-survive-backup-failure'));
});

test('writes queue behind the complete reset backup and mutation transaction', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('reset-mutation-queue');
  const store = await importStore({ ...temp, label: 'reset-mutation-queue' });
  const backupReached = deferred();
  const releaseBackup = deferred();
  t.after(async () => {
    store.setStoreTestHooks(null);
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  await store.ensureStoreReady();
  store.setStoreTestHooks({
    beforeResetBackup: async () => {
      backupReached.resolve();
      await releaseBackup.promise;
    },
  });

  const resetPromise = store.resetDefaultData('payloads');
  await backupReached.promise;
  let saveSettled = false;
  const savePromise = store.saveAdminItem('payloads', {
    id: 'queued-during-reset',
    name: 'Queued during reset',
    description: 'Must be written after reset completes',
    category: 'Test',
    execution: [{
      title: 'Queued write regression command',
      description: 'Creates deterministic test output without changing the environment.',
      command: 'echo PAYLOADER_QUEUED_WRITE_TEST',
    }],
  }).finally(() => {
    saveSettled = true;
  });
  await new Promise(resolveImmediate => setImmediate(resolveImmediate));
  assert.equal(saveSettled, false);

  releaseBackup.resolve();
  const reset = await resetPromise;
  await savePromise;

  const backupPath = resolve(temp.dataDir, reset.backup.path);
  assert.ok(!store.loadContentDataFromDatabase(backupPath).payloads.some(item => item.id === 'queued-during-reset'));
  assert.ok((await store.listAdminItems('payloads')).some(item => item.id === 'queued-during-reset'));
});

test('custom content can be stored in and moved between payloads and tools', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('custom-content');
  const store = await importStore({ ...temp, label: 'custom-content' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  const created = await store.saveCustomContent({
    title: '自定义速查',
    content: '# first\necho first',
    destination: 'payloads',
  });
  assert.equal(created.destination, 'payloads');
  assert.match(created.id, /^custom-/);
  assert.ok((await store.listAdminItems('payloads')).some(item => item.id === created.id));
  assert.ok(!(await store.listAdminItems('tools')).some(item => item.id === created.id));

  const moved = await store.saveCustomContent({
    id: created.id,
    sourceDestination: 'payloads',
    destination: 'tools',
    title: '自定义速查（工具）',
    content: 'echo second',
  });
  assert.equal(moved.destination, 'tools');
  assert.ok(!(await store.listAdminItems('payloads')).some(item => item.id === created.id));
  const storedTool = (await store.listAdminItems('tools')).find(item => item.id === created.id);
  assert.equal(storedTool.commands[0].command, 'echo second');
  assert.deepEqual(
    (await store.listCustomContent()).find(item => item.id === created.id),
    {
      id: created.id,
      title: '自定义速查（工具）',
      content: 'echo second',
      destination: 'tools',
    },
  );

  await store.deleteCustomContent({ id: created.id, destination: 'tools' });
  assert.ok(!(await store.listAdminItems('tools')).some(item => item.id === created.id));
});

test('custom content validates required fields and move conflicts', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('custom-content-validation');
  const store = await importStore({ ...temp, label: 'custom-content-validation' });
  t.after(async () => {
    store.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  await assert.rejects(
    store.saveCustomContent({ title: '', content: 'x', destination: 'payloads' }),
    error => error?.status === 400 && /标题/.test(error.message),
  );
  await assert.rejects(
    store.saveCustomContent({ title: 'x', content: '', destination: 'tools' }),
    error => error?.status === 400 && /内容/.test(error.message),
  );
  await assert.rejects(
    store.saveCustomContent({ title: 'x', content: 'x', destination: '../tools' }),
    error => error?.status === 400 && /归属/.test(error.message),
  );

  const created = await store.saveCustomContent({ title: '源记录', content: 'one', destination: 'payloads' });
  await store.saveAdminItem('tools', {
    id: created.id,
    name: { zh: '冲突记录', en: 'Conflict' },
    description: { zh: '冲突记录', en: 'Conflict' },
    category: { zh: '自定义', en: 'Custom' },
    commands: [{
      name: { zh: '冲突记录', en: 'Conflict' },
      command: 'two',
      description: { zh: '冲突', en: 'Conflict' },
      platform: 'all',
    }],
  });

  await assert.rejects(
    store.saveCustomContent({
      id: created.id,
      sourceDestination: 'payloads',
      destination: 'tools',
      title: '不能覆盖',
      content: 'three',
    }),
    error => error?.status === 409,
  );
  assert.ok((await store.listAdminItems('payloads')).some(item => item.id === created.id));

  await store.saveAdminItem('payloads', {
    id: 'ordinary-payload',
    name: { zh: '普通记录', en: 'Ordinary item' },
    description: { zh: '普通记录', en: 'Ordinary item' },
    category: { zh: 'Web', en: 'Web' },
    tags: [],
    execution: [{ title: { zh: '命令', en: 'Command' }, command: 'echo ordinary', platform: 'all' }],
  });
  await assert.rejects(
    store.saveCustomContent({
      id: 'ordinary-payload',
      sourceDestination: 'payloads',
      destination: 'tools',
      title: '不能迁移普通记录',
      content: 'echo blocked',
    }),
    error => error?.status === 404,
  );
  await assert.rejects(
    store.deleteCustomContent({ id: 'ordinary-payload', destination: 'payloads' }),
    error => error?.status === 404,
  );
  assert.ok((await store.listAdminItems('payloads')).some(item => item.id === 'ordinary-payload'));
});

test('body decoding and health, readiness, and authenticated safety APIs honor boundaries', { concurrency: false }, async t => {
  const temp = await makeTempDataDir('admin-api');
  const missingSeedPath = join(temp.root, 'seed', 'default-seed.sqlite');
  process.env.PAYLOADER_DATA_DIR = temp.dataDir;
  process.env.PAYLOADER_SEED_DB = missingSeedPath;
  process.env.PAYLOADER_ADMIN_USER = 'data-safety-admin';
  process.env.PAYLOADER_ADMIN_PASSWORD = 'Data-Safety-Password-2026!';
  process.env.PAYLOADER_PORT = '0';

  const admin = await import(uniqueModuleUrl('../server/admin-server.mjs', 'admin-api'));
  const canonicalStore = await import('../server/data-store.mjs');
  const server = admin.createAdminServer();
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', resolveListen);
  });
  t.after(async () => {
    await new Promise(resolveClose => server.close(resolveClose));
    canonicalStore.closeStore();
    await rm(temp.root, { recursive: true, force: true });
  });

  const utf8Body = Buffer.from('{"message":"你好，Payloader 🙂"}', 'utf8');
  const splitAt = Buffer.from('{"message":"你', 'utf8').length - 1;
  const request = Readable.from([utf8Body.subarray(0, splitAt), utf8Body.subarray(splitAt)]);
  request.headers = {};
  assert.equal(await admin.readBody(request), utf8Body.toString('utf8'));

  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const runtimeDbPath = join(temp.dataDir, 'payloader.sqlite');
  assert.equal(await fileExists(runtimeDbPath), false);

  const health = await fetch(`${baseUrl}/api/health`);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, 'ok');
  assert.equal(await fileExists(runtimeDbPath), false);

  const unavailable = await fetch(`${baseUrl}/api/ready`);
  assert.equal(unavailable.status, 503);
  assert.equal((await unavailable.json()).status, 'not_ready');

  await mkdir(dirname(missingSeedPath), { recursive: true });
  await copyFile(defaultSeedPath, missingSeedPath);
  const ready = await fetch(`${baseUrl}/api/ready`);
  assert.equal(ready.status, 200);
  assert.equal((await ready.json()).status, 'ready');

  const unauthorizedExport = await fetch(`${baseUrl}/api/admin/export`);
  assert.equal(unauthorizedExport.status, 401);

  const login = await fetch(`${baseUrl}/api/admin/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'data-safety-admin', password: 'Data-Safety-Password-2026!' }),
  });
  assert.equal(login.status, 200);
  const session = await login.json();
  assert.equal(session.tokenType, 'Bearer');
  assert.equal(typeof session.accessToken, 'string');
  assert.equal(login.headers.get('set-cookie'), null);
  const authorization = `Bearer ${session.accessToken}`;

  const exportResponse = await fetch(`${baseUrl}/api/admin/export`, { headers: { authorization } });
  assert.equal(exportResponse.status, 200);
  assert.match(exportResponse.headers.get('content-disposition'), /^attachment; filename="payloader-export-/);
  assert.equal((await exportResponse.json()).format, 'payloader.export.v1');

  const impactResponse = await fetch(`${baseUrl}/api/admin/reset-impact?target=payloads`, { headers: { authorization } });
  assert.equal(impactResponse.status, 200);
  assert.equal((await impactResponse.json()).target, 'payloads');

  const invalidImpact = await fetch(`${baseUrl}/api/admin/reset-impact?target=..%2Fall`, { headers: { authorization } });
  assert.equal(invalidImpact.status, 400);

  const missingImpact = await fetch(`${baseUrl}/api/admin/reset-impact`, { headers: { authorization } });
  assert.equal(missingImpact.status, 400);

  const emptyImpact = await fetch(`${baseUrl}/api/admin/reset-impact?target=`, { headers: { authorization } });
  assert.equal(emptyImpact.status, 400);

  const invalidReset = await fetch(`${baseUrl}/api/admin/reset-defaults`, {
    method: 'POST',
    headers: {
      authorization,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ target: '../all' }),
  });
  assert.equal(invalidReset.status, 400);

  for (const body of [{}, { target: '' }, { target: ['all'] }]) {
    const response = await fetch(`${baseUrl}/api/admin/reset-defaults`, {
      method: 'POST',
      headers: {
        authorization,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });
    assert.equal(response.status, 400);
  }
});

test('readBody destroys requests rejected by the Content-Length preflight', { concurrency: false }, async () => {
  const admin = await import(uniqueModuleUrl('../server/admin-server.mjs', 'body-preflight'));
  let destroyed = false;
  const request = {
    headers: { 'content-length': '101' },
    destroy: () => {
      destroyed = true;
    },
  };

  await assert.rejects(
    admin.readBody(request, 100),
    error => error?.status === 413,
  );
  assert.equal(destroyed, true);
});
