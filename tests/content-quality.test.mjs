import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import {
  auditDatabase,
  auditSnapshot,
  formatHumanSummary,
  hasBlockingErrors,
} from '../scripts/verify-content-quality.mjs';
import {
  planContentRepairs,
  refreshSeedFromRuntime,
  repairDatabase,
} from '../scripts/repair-content-quality.mjs';

const i18n = (zh, en = zh) => ({ zh, en });

const basePayload = (id, overrides = {}) => ({
  id,
  name: i18n(id, id),
  description: i18n('description', 'description'),
  category: i18n('SQL/NoSQL', 'SQL/NoSQL'),
  tags: [],
  execution: [{ title: i18n('run', 'run'), command: 'SELECT 1', platform: 'all' }],
  ...overrides,
});

const baseTool = (id, overrides = {}) => ({
  id,
  name: i18n(id, id),
  description: i18n('description', 'description'),
  category: i18n('tool', 'tool'),
  commands: [{ name: i18n('run', 'run'), command: 'echo ok', description: i18n('ok', 'ok'), platform: 'all' }],
  ...overrides,
});

const createFixtureDatabase = async ({
  payloads = [],
  tools = [],
  navigation = [],
  toolNavigation = [],
  metadata = {},
  invalidRows = [],
  extraSql = '',
} = {}) => {
  const directory = await mkdtemp(join(tmpdir(), 'payloader-content-'));
  const file = join(directory, 'content.sqlite');
  const database = new DatabaseSync(file);
  database.exec(`
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE payloads (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE tools (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE navigation_nodes (
      id TEXT PRIMARY KEY,
      tree TEXT NOT NULL,
      kind TEXT NOT NULL,
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  if (extraSql) database.exec(extraSql);
  const now = new Date(0).toISOString();
  const insertPayload = database.prepare('INSERT INTO payloads VALUES (?, ?, ?, 1, ?, ?)');
  const insertTool = database.prepare('INSERT INTO tools VALUES (?, ?, ?, 1, ?, ?)');
  const insertNavigation = database.prepare('INSERT INTO navigation_nodes VALUES (?, ?, ?, ?, 1, ?, ?)');
  payloads.forEach((item, index) => insertPayload.run(item.id, JSON.stringify(item), index, now, now));
  tools.forEach((item, index) => insertTool.run(item.id, JSON.stringify(item), index, now, now));
  navigation.forEach((item, index) => insertNavigation.run(item.id, JSON.stringify(item), 'payloads', index, now, now));
  toolNavigation.forEach((item, index) => insertNavigation.run(item.id, JSON.stringify(item), 'tools', index, now, now));
  const insertMetadata = database.prepare('INSERT INTO metadata (key, value) VALUES (?, ?)');
  Object.entries(metadata).forEach(([key, value]) => insertMetadata.run(key, String(value)));
  for (const row of invalidRows) {
    if (row.table === 'payloads') insertPayload.run(row.id, row.value, payloads.length, now, now);
    if (row.table === 'tools') insertTool.run(row.id, row.value, tools.length, now, now);
    if (row.table === 'navigation_nodes') insertNavigation.run(row.id, row.value, row.kind || 'payloads', navigation.length, now, now);
  }
  database.close();
  return { directory, file };
};

const readPayload = (file, id) => {
  const database = new DatabaseSync(file, { readOnly: true });
  try {
    return JSON.parse(database.prepare('SELECT data FROM payloads WHERE id = ?').get(id).data);
  } finally {
    database.close();
  }
};

test('auditDatabase blocks malformed or unsafe content and deterministically reports editorial debt', async () => {
  const sourceFragment = 'before,\n        syntaxBreakdown: [\n          { part: "x" }\n        ]\nafter';
  const payloads = [
    basePayload('clean', { name: i18n('same', 'same') }),
    basePayload('duplicate', { name: i18n('same', 'same') }),
    basePayload('corrupt', {
      name: i18n('corrupt', '\u4e2d\u6587'),
      execution: [{ title: i18n('run'), command: `${sourceFragment}\uFFFD`, platform: 'solaris' }],
      tutorial: {
        overview: i18n('overview'),
        vulnerability: i18n('vulnerability'),
        exploitation: i18n('\u9009\u62e9\u5bf9\u5e94payload\u6d4b\u8bd5'),
        mitigation: i18n('mitigation'),
        difficulty: 'beginner',
      },
    }),
    basePayload('empty', { execution: [{ title: i18n('run'), command: '   ', platform: 'all' }] }),
    basePayload('orphan'),
  ];
  const { file } = await createFixtureDatabase({
    payloads,
    tools: [baseTool('tool-empty', { commands: [{ name: i18n('run'), command: '', description: i18n('empty') }] })],
    navigation: [{
      id: 'web',
      name: i18n('web'),
      children: [
        { id: 'clean-nav', name: i18n('clean'), payloadId: 'clean' },
        { id: 'missing-nav', name: i18n('missing'), payloadId: 'missing-payload' },
      ],
    }],
    metadata: {
      settings: JSON.stringify({ browserTitle: i18n(`broken\uFFFDtitle`, 'clean title') }),
    },
    invalidRows: [{ table: 'payloads', id: 'invalid-json', value: '{not json' }],
  });

  const first = auditDatabase(file);
  const second = auditDatabase(file);

  assert.equal(hasBlockingErrors(first), true);
  assert.equal(first.blocking.invalidJson.count, 1);
  assert.equal(first.blocking.replacementCharacter.count, 2);
  assert.equal(first.blocking.sourceFragment.count, 1);
  assert.equal(first.blocking.emptyCommand.count, 2);
  assert.equal(first.blocking.invalidPlatform.count, 1);
  assert.equal(first.blocking.danglingNavigation.count, 1);
  assert.equal(first.reporting.englishContainsHan.count, 2);
  assert.equal(first.reporting.orphanPayloads.count, 4);
  assert.equal(first.reporting.duplicateNames.count, 1);
  assert.equal(first.reporting.genericTutorials.count, 1);
  assert.equal(first.reporting.wafCoverage.total, 5);
  assert.equal(JSON.stringify(first), JSON.stringify(second));
  assert.match(formatHumanSummary(first), /blocking errors: 8/i);
});

test('auditSnapshot keeps legacy JWT and protected XSS records while resolving legacy aliases', () => {
  const snapshot = {
    payloads: [basePayload('jwt-none-attack'), basePayload('jwt-none-alg')],
    tools: [baseTool('xss-platform', { commands: [], externalUrl: 'https://xss.icu/', systemLocked: true })],
    navigation: [{ id: 'jwt', name: i18n('jwt'), payloadId: 'jwt-none-algo' }],
    toolNavigation: [{ id: 'system-xss-platform', name: i18n('Xeye'), toolId: 'xss-platform' }],
  };

  const report = auditSnapshot(snapshot, { source: 'memory' });
  const plan = planContentRepairs(snapshot);

  assert.equal(report.blocking.danglingNavigation.count, 0);
  assert.deepEqual(plan.snapshot.tools, snapshot.tools);
  assert.equal(plan.snapshot.payloads.some(item => item.id === 'jwt-none-alg'), true);
  assert.equal(plan.snapshot.toolNavigation[0].toolId, 'xss-platform');
});

test('repairDatabase is dry-run by default and apply creates a valid backup before mutation', async () => {
  const contaminated = basePayload('auth-bypass', {
    prerequisites: [i18n('\u76ee\u6807\uFFFD\uFFFD\uFFFD\u5728\u5bf9\u5e94\u6ce8\u5165\u70b9', 'target')],
    execution: [
      { title: i18n('baseline'), command: 'SELECT 1', platform: 'all' },
      { title: i18n('array'), command: 'user[]=admin', platform: 'all' },
      {
        title: i18n('run'),
        command: 'before,\n        syntaxBreakdown: [\n          { part: "x" }\n        ]\nafter',
        platform: 'all',
      },
    ],
    tutorial: {
      overview: i18n('overview'),
      vulnerability: i18n('vulnerability'),
      exploitation: i18n('\u9009\u62e9\u5bf9\u5e94payload\u6d4b\u8bd5'),
      mitigation: i18n('mitigation'),
      difficulty: 'beginner',
    },
  });
  const { directory, file } = await createFixtureDatabase({
    payloads: [contaminated],
    navigation: [{ id: 'web', name: i18n('web'), children: [{ id: 'auth', name: i18n('auth'), payloadId: 'auth-bypass' }] }],
  });
  const backupDir = join(directory, 'backups');
  const original = await readFile(file);

  const dryRun = await repairDatabase(file, { backupDir });
  assert.equal(dryRun.applied, false);
  assert.deepEqual(await readFile(file), original);
  await assert.rejects(readdir(backupDir), /ENOENT/);

  const applied = await repairDatabase(file, { apply: true, backupDir });
  const repaired = readPayload(file, 'auth-bypass');
  const backupFile = join(backupDir, applied.backup.fileName);
  const backupDatabase = new DatabaseSync(backupFile, { readOnly: true });
  const backupIntegrity = backupDatabase.prepare('PRAGMA integrity_check').get().integrity_check;
  backupDatabase.close();

  assert.equal(applied.applied, true);
  assert.equal(backupIntegrity, 'ok');
  assert.doesNotMatch(repaired.execution[2].command, /syntaxBreakdown\s*:/);
  assert.equal(JSON.stringify(repaired).includes('\uFFFD'), false);
  assert.equal('tutorial' in repaired, false);
  assert.equal(readPayload(backupFile, 'auth-bypass').execution[2].command, contaminated.execution[2].command);
});

test('repairDatabase refuses malformed JSON before creating a backup or changing the database', async () => {
  const { directory, file } = await createFixtureDatabase({
    payloads: [basePayload('clean')],
    navigation: [{ id: 'web', name: i18n('web'), payloadId: 'clean' }],
    invalidRows: [{ table: 'payloads', id: 'broken', value: '{broken json' }],
  });
  const backupDir = join(directory, 'backups');
  const before = await readFile(file);

  await assert.rejects(repairDatabase(file, { apply: true, backupDir }), /JSON|Unexpected/i);

  assert.deepEqual(await readFile(file), before);
  await assert.rejects(readdir(backupDir), /ENOENT/);
});

test('planContentRepairs attaches the three confirmed orphans and conservatively relocates obvious categories', () => {
  const payloads = [
    basePayload('ai2-mixed-case-bypass', { category: i18n('AI security', 'AI Security') }),
    basePayload('ai2-virtual-scenario-bypass', { category: i18n('AI security', 'AI Security') }),
    basePayload('nosql2-ognl-struts2'),
    basePayload('inject2-clickjacking-163-lines'),
    basePayload('inject2-http-request-smuggling-request'),
  ];
  const snapshot = {
    payloads,
    tools: [],
    navigation: [{
      id: 'web',
      name: i18n('web'),
      children: [
        {
          id: 'sqli',
          name: i18n('sqli'),
          children: [
            { id: 'clickjacking-wrong', name: i18n('clickjacking'), payloadId: 'inject2-clickjacking-163-lines' },
            { id: 'smuggling-wrong', name: i18n('smuggling'), payloadId: 'inject2-http-request-smuggling-request' },
          ],
        },
        { id: 'clickjacking', name: i18n('clickjacking'), children: [] },
        { id: 'web-smuggling', name: i18n('smuggling'), children: [] },
        { id: 'framework-vulns', name: i18n('framework'), children: [] },
        { id: 'ai-security', name: i18n('AI'), children: [] },
      ],
    }],
    toolNavigation: [],
  };

  const plan = planContentRepairs(snapshot);
  const report = auditSnapshot(plan.snapshot, { source: 'planned' });
  const web = plan.snapshot.navigation.find(item => item.id === 'web');
  const branch = id => web.children.find(item => item.id === id);

  assert.deepEqual(branch('ai-security').children.map(item => item.payloadId).sort(), [
    'ai2-mixed-case-bypass',
    'ai2-virtual-scenario-bypass',
  ]);
  assert.equal(branch('framework-vulns').children.some(item => item.payloadId === 'nosql2-ognl-struts2'), true);
  assert.equal(branch('clickjacking').children.some(item => item.payloadId === 'inject2-clickjacking-163-lines'), true);
  assert.equal(branch('web-smuggling').children.some(item => item.payloadId === 'inject2-http-request-smuggling-request'), true);
  assert.equal((branch('sqli').children || []).some(item => item.payloadId === 'inject2-clickjacking-163-lines'), false);
  assert.equal(report.blocking.danglingNavigation.count, 0);
  assert.equal(plan.changes.orphansAttached, 3);
  assert.equal(plan.changes.navigationRelocations, 2);
});

test('repair planning preserves ordinary user records even when their ids match test fixture names', () => {
  const ids = ['custom-before-reset', 'must-survive-backup-failure', 'queued-during-reset'];
  const snapshot = {
    payloads: ids.map(id => basePayload(id)),
    tools: [],
    navigation: [{
      id: 'user-content',
      name: i18n('user content'),
      children: ids.map(id => ({ id: `${id}-nav`, name: i18n(id), payloadId: id })),
    }],
    toolNavigation: [],
  };

  const plan = planContentRepairs(snapshot);
  const report = auditSnapshot(plan.snapshot);

  assert.deepEqual(plan.snapshot.payloads.map(item => item.id).sort(), [...ids].sort());
  assert.deepEqual(plan.snapshot.navigation, snapshot.navigation);
  assert.equal(report.summary.blockingErrors, 0);
});

test('navigation repair refuses non-leaf and multiply referenced moves without duplicating subtrees', () => {
  const clickId = 'inject2-clickjacking-163-lines';
  const smugglingId = 'inject2-http-request-smuggling-request';
  const snapshot = {
    payloads: [basePayload(clickId), basePayload(smugglingId)],
    tools: [],
    navigation: [{
      id: 'web',
      name: i18n('web'),
      children: [
        {
          id: 'sqli',
          name: i18n('sqli'),
          children: [
            {
              id: 'non-leaf-reference',
              name: i18n('non leaf'),
              payloadId: clickId,
              children: [{ id: 'must-not-copy', name: i18n('child'), payloadId: 'child-payload' }],
            },
            { id: 'smuggling-ref-a', name: i18n('a'), payloadId: smugglingId },
            { id: 'smuggling-ref-b', name: i18n('b'), payloadId: smugglingId },
          ],
        },
        { id: 'clickjacking', name: i18n('clickjacking'), children: [] },
        { id: 'web-smuggling', name: i18n('smuggling'), children: [] },
      ],
    }],
    toolNavigation: [],
  };

  const plan = planContentRepairs(snapshot);
  const serialized = JSON.stringify(plan.snapshot.navigation);

  assert.equal((serialized.match(/must-not-copy/g) || []).length, 1);
  assert.equal((serialized.match(/smuggling-ref-/g) || []).length, 2);
  assert.equal(plan.changes.navigationRelocations, 0);
  assert.deepEqual(plan.warnings.map(item => item.reason).sort(), ['multiple-references', 'non-leaf-reference']);
});

test('refreshSeedFromRuntime backs up the old seed and atomically publishes the validated runtime snapshot', async () => {
  const ordinaryIds = ['custom-before-reset', 'must-survive-backup-failure', 'queued-during-reset'];
  const runtime = await createFixtureDatabase({
    payloads: [basePayload('runtime-payload'), ...ordinaryIds.map(id => basePayload(id))],
    navigation: [{
      id: 'web',
      name: i18n('web'),
      children: [
        { id: 'runtime-nav', name: i18n('runtime'), payloadId: 'runtime-payload' },
        ...ordinaryIds.map(id => ({ id: `${id}-nav`, name: i18n(id), payloadId: id })),
      ],
    }],
    metadata: {
      settings: JSON.stringify({ browserTitle: i18n('runtime') }),
      migration_example_v1: '1',
      operational_note: 'must not ship',
    },
    extraSql: `
      CREATE TABLE admin_credentials (id TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
      INSERT INTO admin_credentials VALUES ('admin', 'secret-hash');
    `,
  });
  const seed = await createFixtureDatabase({
    payloads: [basePayload('old-seed')],
    navigation: [{ id: 'web', name: i18n('web'), payloadId: 'old-seed' }],
    metadata: { stale_operational_key: 'old value' },
  });
  const backupDir = join(runtime.directory, 'backups');

  const result = await refreshSeedFromRuntime(runtime.file, seed.file, { backupDir });
  const seedDatabase = new DatabaseSync(seed.file, { readOnly: true });
  const payloadIds = seedDatabase.prepare('SELECT id FROM payloads ORDER BY id').all().map(row => row.id);
  const metadataRows = seedDatabase.prepare('SELECT key, value FROM metadata ORDER BY key').all();
  const tables = seedDatabase.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(row => row.name);
  seedDatabase.close();

  assert.deepEqual(payloadIds, [...ordinaryIds, 'runtime-payload'].sort());
  assert.deepEqual(metadataRows.map(row => row.key), ['content_kind', 'generated_at', 'seed_schema_version', 'source']);
  assert.deepEqual(tables, ['metadata', 'navigation_nodes', 'payloads', 'tools']);
  assert.equal(readPayload(join(backupDir, result.backup.fileName), 'old-seed').id, 'old-seed');
  const backupDatabase = new DatabaseSync(join(backupDir, result.backup.fileName), { readOnly: true });
  assert.equal(backupDatabase.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
  backupDatabase.close();
  assert.equal(auditDatabase(seed.file).summary.blockingErrors, 0);
});

test('seed refresh never publishes partial output and always removes temporary artifacts on failure', async t => {
  const runtime = await createFixtureDatabase({
    payloads: [basePayload('runtime-payload')],
    navigation: [{ id: 'web', name: i18n('web'), payloadId: 'runtime-payload' }],
  });
  const seed = await createFixtureDatabase({
    payloads: [basePayload('old-seed')],
    navigation: [{ id: 'web', name: i18n('web'), payloadId: 'old-seed' }],
  });
  const backupDir = join(runtime.directory, 'backups');
  const seedTemps = async () => (await readdir(seed.directory)).filter(name => name.startsWith('.content-seed-'));
  const assertOldSeedPreserved = () => assert.equal(readPayload(seed.file, 'old-seed').id, 'old-seed');

  await t.test('build failure', async () => {
    await assert.rejects(
      refreshSeedFromRuntime(runtime.file, seed.file, {
        backupDir,
        writeSeedDatabase: async (_data, temporarySeed) => {
          await writeFile(temporarySeed, 'partial seed');
          throw new Error('seed build failed');
        },
      }),
      /seed build failed/,
    );
    assertOldSeedPreserved();
    assert.deepEqual(await seedTemps(), []);
  });

  await t.test('validation failure', async () => {
    await assert.rejects(
      refreshSeedFromRuntime(runtime.file, seed.file, {
        backupDir,
        afterBuild: temporarySeed => {
          const database = new DatabaseSync(temporarySeed);
          database.prepare('INSERT INTO metadata (key, value) VALUES (?, ?)').run('migration_forbidden', '1');
          database.close();
        },
      }),
      /metadata|allowlist/i,
    );
    assertOldSeedPreserved();
    assert.deepEqual(await seedTemps(), []);
  });

  await t.test('publish failure', async () => {
    await assert.rejects(
      refreshSeedFromRuntime(runtime.file, seed.file, {
        backupDir,
        publishSeed: async () => {
          throw new Error('seed publish failed');
        },
      }),
      /seed publish failed/,
    );
    assertOldSeedPreserved();
    assert.deepEqual(await seedTemps(), []);
  });
});

test('legacy TypeScript source no longer embeds internal syntax metadata in the four confirmed commands', async () => {
  const source = await readFile(join(process.cwd(), 'src', 'data', 'webPayloads.ts'), 'utf8');
  const confirmedFragments = [
    /Content-Type: application\/json,\r?\n\s*\r?\n\s*syntaxBreakdown\s*:/,
    /<html><body>,\r?\n\s*syntaxBreakdown\s*:/,
    /\u5b57\u7b26\u4e32\u7ed3\u5c3e\),\r?\n\s*syntaxBreakdown\s*:/,
    /<\/iframe>,\r?\n\s*syntaxBreakdown\s*:/,
  ];

  confirmedFragments.forEach(pattern => assert.doesNotMatch(source, pattern));
});
