import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const projectRoot = resolve(import.meta.dirname, '..');
const serverEntrypoint = join(projectRoot, 'server', 'admin-server.mjs');
const seedDatabase = join(projectRoot, 'server', 'default-seed.sqlite');

const runServer = ({ dataDir, nodeEnv, host, username, password, allowInsecureDefaults = false, waitForListening = false }) => new Promise((resolveRun, rejectRun) => {
  const env = {
    ...process.env,
    NODE_ENV: nodeEnv,
    PAYLOADER_HOST: host,
    PAYLOADER_PORT: '0',
    PAYLOADER_DATA_DIR: dataDir,
    PAYLOADER_SEED_DB: seedDatabase,
  };
  delete env.PAYLOADER_ADMIN_USER;
  delete env.PAYLOADER_ADMIN_PASSWORD;
  delete env.PAYLOADER_JWT_SECRET;
  delete env.PAYLOADER_ALLOW_INSECURE_DEV_CREDENTIALS;
  if (username !== undefined) env.PAYLOADER_ADMIN_USER = username;
  if (password !== undefined) env.PAYLOADER_ADMIN_PASSWORD = password;
  if (allowInsecureDefaults) env.PAYLOADER_ALLOW_INSECURE_DEV_CREDENTIALS = 'true';

  const child = spawn(process.execPath, [serverEntrypoint], {
    cwd: projectRoot,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let output = '';
  let settled = false;
  let listeningObserved = false;
  const finish = result => {
    if (settled) return;
    settled = true;
    clearTimeout(timeout);
    resolveRun({ ...result, output });
  };
  const inspectOutput = chunk => {
    output += chunk.toString('utf8');
    const startupSummaryComplete = output.includes('Payloader frontend:')
      && output.includes('Admin user:');
    if (waitForListening && !listeningObserved && startupSummaryComplete) {
      listeningObserved = true;
      child.kill();
    }
  };
  child.stdout.on('data', inspectOutput);
  child.stderr.on('data', inspectOutput);
  child.once('error', error => {
    if (settled) return;
    settled = true;
    clearTimeout(timeout);
    rejectRun(error);
  });
  child.once('exit', code => finish({ listened: listeningObserved, code }));
  const timeout = setTimeout(() => {
    child.kill();
    if (settled) return;
    settled = true;
    rejectRun(new Error(`Server startup probe timed out. Output:\n${output}`));
  }, 15_000);
});

test('loopback development startup uses the stable local administrator credentials', async t => {
  const root = await mkdtemp(join(tmpdir(), 'payloader-startup-explicit-'));
  t.after(() => rm(root, { recursive: true, force: true }));

  const result = await runServer({
    dataDir: root,
    nodeEnv: 'development',
    host: '127.0.0.1',
    waitForListening: true,
  });
  assert.equal(result.listened, true, result.output);
  assert.match(result.output, /Admin user: admin/);
});

test('production startup rejects missing, weak, bundled, and documented example credentials', async t => {
  const root = await mkdtemp(join(tmpdir(), 'payloader-startup-policy-'));
  t.after(() => rm(root, { recursive: true, force: true }));

  const cases = [
    { name: 'missing', username: undefined, password: undefined, message: /are required/ },
    { name: 'weak', username: 'admin', password: 'short', message: /密码长度/ },
    { name: 'bundled', username: 'admin', password: 'payloader-admin!', message: /密码至少需要包含/ },
    { name: 'documented', username: 'admin', password: 'Change-Me-2026!', message: /must not use a published example password/ },
  ];

  for (const item of cases) {
    const result = await runServer({
      dataDir: join(root, item.name),
      nodeEnv: 'production',
      host: '0.0.0.0',
      username: item.username,
      password: item.password,
      waitForListening: true,
    });
    assert.notEqual(result.code, 0, `${item.name} credentials unexpectedly started the server`);
    assert.equal(result.listened, false);
    assert.match(result.output, item.message);
  }
});

test('production startup rejects an old bundled password until explicit strong credentials migrate it', async t => {
  const root = await mkdtemp(join(tmpdir(), 'payloader-startup-persisted-'));
  t.after(() => rm(root, { recursive: true, force: true }));

  const local = await runServer({
    dataDir: root,
    nodeEnv: 'development',
    host: '127.0.0.1',
    allowInsecureDefaults: true,
    waitForListening: true,
  });
  assert.equal(local.listened, true, local.output);

  const production = await runServer({
    dataDir: root,
    nodeEnv: 'production',
    host: '0.0.0.0',
    username: 'admin',
    password: 'Change-Me-2026!',
  });
  assert.notEqual(production.code, 0);
  assert.equal(production.listened, false);
  assert.match(production.output, /bundled default password/);

  const migrated = await runServer({
    dataDir: root,
    nodeEnv: 'production',
    host: '0.0.0.0',
    username: 'migrated-admin',
    password: 'Migrated-Admin-Password-2026!',
    waitForListening: true,
  });
  assert.equal(migrated.listened, true, migrated.output);

  const persisted = await runServer({
    dataDir: root,
    nodeEnv: 'production',
    host: '0.0.0.0',
    waitForListening: true,
  });
  assert.equal(persisted.listened, true, persisted.output);
});
