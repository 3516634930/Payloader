import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';

import { curateDatabase, loadReviewConfiguration, parseCurationCli, prepareCurationOptions } from '../scripts/apply-payload-curation.mjs';

const i18n = (zh, en = zh) => ({ zh, en });

test('curation CLI can require a fully review-ready dry run', () => {
  const defaults = parseCurationCli([]);
  const required = parseCurationCli(['--require-ready', '--seed-only', '--json']);

  assert.equal(defaults.requireReady, false);
  assert.equal(defaults.seedOnly, false);
  assert.equal(required.requireReady, true);
  assert.equal(required.seedOnly, true);
  assert.equal(required.json, true);
  assert.throws(
    () => parseCurationCli(['--seed-only', '--apply']),
    /cannot be combined/i,
  );
});

const payload = id => ({
  id,
  name: i18n(id),
  description: i18n(`${id} 描述`, `${id} description`),
  category: i18n('隧道代理', 'Tunneling and Proxy'),
  subCategory: i18n('工具手册', 'Tool Manual'),
  execution: [{
    title: i18n('启动服务端', 'Start server'),
    command: './tool server --port 8000',
    description: i18n('启动隧道服务端。', 'Start the tunnel server.'),
  }],
  wafBypass: [],
  attackChain: [],
  references: [],
});

const tool = id => ({
  id,
  name: i18n(id),
  description: i18n(`${id} 命令`, `${id} commands`),
  category: i18n('隧道代理', 'Tunneling and Proxy'),
  commands: [],
  references: [],
});

const createDatabase = async () => {
  const directory = await mkdtemp(join(tmpdir(), 'payloader-curation-'));
  const file = join(directory, 'payloader.sqlite');
  const database = new DatabaseSync(file);
  const now = new Date().toISOString();
  database.exec(`
    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE payloads (id TEXT PRIMARY KEY, data TEXT NOT NULL, sort_order INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE tools (id TEXT PRIMARY KEY, data TEXT NOT NULL, sort_order INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE navigation_nodes (id TEXT PRIMARY KEY, tree TEXT NOT NULL, kind TEXT NOT NULL, sort_order INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  `);
  const insertPayload = database.prepare('INSERT INTO payloads VALUES (?, ?, ?, 1, ?, ?)');
  [payload('tunnel-tool'), payload('kept')].forEach((item, index) => insertPayload.run(item.id, JSON.stringify(item), index, now, now));
  const existingTool = tool('tool-reference');
  delete existingTool.references;
  database.prepare('INSERT INTO tools VALUES (?, ?, 0, 1, ?, ?)').run(existingTool.id, JSON.stringify(existingTool), now, now);
  database.prepare('INSERT INTO navigation_nodes VALUES (?, ?, ?, ?, 1, ?, ?)').run(
    'payload-root',
    JSON.stringify({
      id: 'payload-root',
      name: i18n('Payload'),
      children: [
        { id: 'tunnel-tool-nav', name: i18n('Tool'), payloadId: 'tunnel-tool' },
        { id: 'kept-nav', name: i18n('Kept'), payloadId: 'kept' },
      ],
    }),
    'payloads',
    0,
    now,
    now,
  );
  database.prepare('INSERT INTO navigation_nodes VALUES (?, ?, ?, ?, 1, ?, ?)').run(
    'tool-root',
    JSON.stringify({ id: 'tool-root', name: i18n('Tools'), children: [] }),
    'tools',
    0,
    now,
    now,
  );
  database.close();
  return { directory, file };
};

const digest = async file => createHash('sha256').update(await readFile(file)).digest('hex');

const readSnapshot = file => {
  const database = new DatabaseSync(file, { readOnly: true });
  try {
    const read = (table, column, where = '') => database.prepare(`SELECT ${column} FROM ${table} ${where} ORDER BY sort_order, id`).all().map(row => JSON.parse(row[column]));
    return {
      payloads: read('payloads', 'data'),
      tools: read('tools', 'data'),
      navigation: read('navigation_nodes', 'tree', "WHERE kind = 'payloads'"),
      toolNavigation: read('navigation_nodes', 'tree', "WHERE kind = 'tools'"),
      integrity: database.prepare('PRAGMA integrity_check').get().integrity_check,
    };
  } finally {
    database.close();
  }
};

test('database curation is dry-run by default and applies one WAL-safe backed-up transaction', async () => {
  const fixture = await createDatabase();
  const backupDir = join(fixture.directory, 'backups');
  const options = {
    backupDir,
    payloadCommandOverrides: {
      schemaVersion: 1,
      entries: [{
        id: 'tunnel-tool',
        patches: [{
          area: 'execution',
          index: 0,
          expectedCommand: './tool server --port 8000',
          command: './tool server --port 8000 --lab',
        }],
      }, {
        id: 'kept',
        patches: [{
          area: 'execution',
          index: 0,
          expectedCommand: './tool server --port 8000',
          command: './tool server --port 8000 --keep',
        }],
      }],
    },
    toolMigrations: [{
      sourceId: 'tunnel-tool',
      targetToolId: 'tool-reference',
      navRootId: 'tool-root',
    }],
    toolOverrides: [{
      id: 'tool-reference',
      patches: [{
        op: 'add',
        path: 'references',
        value: ['https://example.test/tool-reference'],
      }],
    }],
  };
  const beforeDigest = await digest(fixture.file);

  const dryRun = await curateDatabase(fixture.file, options);
  assert.equal(dryRun.applied, false);
  assert.equal(await digest(fixture.file), beforeDigest);
  await assert.rejects(readdir(backupDir), /ENOENT/);
  assert.equal(dryRun.changes.payloads.removed, 1);

  const applied = await curateDatabase(fixture.file, { ...options, apply: true });
  const current = readSnapshot(fixture.file);
  const backup = readSnapshot(applied.backup.path);

  assert.equal(applied.applied, true);
  assert.equal(applied.backup.integrity, 'ok');
  assert.equal(current.integrity, 'ok');
  assert.deepEqual(current.payloads.map(item => item.id), ['kept']);
  assert.equal(current.tools[0].commands.some(item => item.command === './tool server --port 8000 --lab'), true);
  assert.deepEqual(current.tools[0].references, ['https://example.test/tool-reference']);
  assert.equal(current.payloads[0].execution[0].command, './tool server --port 8000 --keep');
  assert.doesNotMatch(JSON.stringify(current.navigation), /tunnel-tool/);
  assert.match(JSON.stringify(current.toolNavigation), /tool-reference/);
  assert.deepEqual(backup.payloads.map(item => item.id), ['tunnel-tool', 'kept']);

  const repeatedDryRun = await curateDatabase(fixture.file, options);
  assert.deepEqual(repeatedDryRun.changes, {
    payloads: { added: 0, removed: 0, updated: 0 },
    tools: { added: 0, removed: 0, updated: 0 },
    navigation: { added: 0, removed: 0, updated: 0 },
    toolNavigation: { added: 0, removed: 0, updated: 0 },
  });
});

test('review configuration composes independently owned override and split files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'payloader-review-config-'));
  const manifest = {
    schemaVersion: 1,
    overrideFiles: [],
    decisionsFile: 'tool-decisions.json',
    toolOverrideFiles: ['tool-overrides.json', 'tool-overrides-web.json'],
    payloadCommandOverrideFiles: ['payload-command-overrides.json', 'payload-command-overrides-web.json'],
    collectionSplitFiles: ['collection-splits.json', 'collection-splits-web.json'],
  };
  await Promise.all([
    writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest), 'utf8'),
    writeFile(join(directory, 'tool-overrides.json'), JSON.stringify({
      schemaVersion: 1,
      entries: [{ id: 'first', patches: [] }],
    }), 'utf8'),
    writeFile(join(directory, 'tool-overrides-web.json'), JSON.stringify({
      schemaVersion: 1,
      entries: [{ id: 'second', patches: [] }],
    }), 'utf8'),
    writeFile(join(directory, 'payload-command-overrides.json'), JSON.stringify({
      schemaVersion: 1,
      entries: [{ id: 'payload-first', patches: [] }],
    }), 'utf8'),
    writeFile(join(directory, 'payload-command-overrides-web.json'), JSON.stringify({
      schemaVersion: 1,
      entries: [{ id: 'payload-second', patches: [] }],
    }), 'utf8'),
    writeFile(join(directory, 'collection-splits.json'), JSON.stringify({
      schemaVersion: 1,
      contentStandard: 2,
      collectionSplits: [{ sourceId: 'collection-first' }],
      payloadBranches: [{ sourceId: 'branch-first' }],
    }), 'utf8'),
    writeFile(join(directory, 'collection-splits-web.json'), JSON.stringify({
      schemaVersion: 1,
      contentStandard: 2,
      toolMigrations: [{ sourceId: 'tool-first' }],
      payloadSplits: [{ sourceId: 'split-first' }],
      toolMerges: [{ sourceToolId: 'merge-first' }],
    }), 'utf8'),
  ]);

  const configuration = await loadReviewConfiguration(directory);

  assert.deepEqual(configuration.sourceFiles.toolOverrides, [
    'tool-overrides.json',
    'tool-overrides-web.json',
  ]);
  assert.deepEqual(configuration.toolOverrides.map(entry => entry.id), ['first', 'second']);
  assert.deepEqual(configuration.sourceFiles.payloadCommandOverrides, [
    'payload-command-overrides.json',
    'payload-command-overrides-web.json',
  ]);
  assert.deepEqual(configuration.payloadCommandOverrides.entries.map(entry => entry.id), [
    'payload-first',
    'payload-second',
  ]);
  assert.deepEqual(configuration.sourceFiles.collectionSplits, [
    'collection-splits.json',
    'collection-splits-web.json',
  ]);
  assert.deepEqual(configuration.collectionSplits.map(entry => entry.sourceId), ['collection-first']);
  assert.deepEqual(configuration.payloadBranches.map(entry => entry.sourceId), ['branch-first']);
  assert.deepEqual(configuration.toolMigrations.map(entry => entry.sourceId), ['tool-first']);
  assert.deepEqual(configuration.payloadSplits.map(entry => entry.sourceId), ['split-first']);
  assert.deepEqual(configuration.toolMerges.map(entry => entry.sourceToolId), ['merge-first']);
});

test('prepareCurationOptions keeps an override when its attack chain changed', () => {
  const current = {
    ...payload('chain-update'),
    prerequisites: [i18n('授权实验。', 'Authorized lab.')],
    tutorial: {
      overview: i18n('概览内容。', 'Overview content.'),
      vulnerability: i18n('漏洞内容。', 'Vulnerability content.'),
      exploitation: i18n('验证内容。', 'Validation content.'),
      mitigation: i18n('修复内容。', 'Mitigation content.'),
      difficulty: 'intermediate',
    },
    analysis: i18n('分析内容。', 'Analysis content.'),
    opsecTips: [i18n('限制范围。', 'Limit scope.')],
    attackChain: [{
      title: i18n('旧的技术前提', 'Old mechanism prerequisite'),
      description: i18n('记录原始基线。', 'Record the original baseline.'),
    }],
  };
  const changedChain = structuredClone(current.attackChain);
  changedChain[0].title = i18n('新的技术前提', 'New mechanism prerequisite');
  const entry = { ...structuredClone(current), attackChain: changedChain };
  const options = prepareCurationOptions({
    overrideDocuments: [{
      schemaVersion: 1,
      contentStandard: 3,
      sourceIds: [current.id],
      entries: [entry],
    }],
  }, [current], []);

  assert.deepEqual(options.overrideDocuments[0].sourceIds, [current.id]);
  assert.deepEqual(options.overrideDocuments[0].entries.map(item => item.id), [current.id]);
});

test('prepareCurationOptions recognizes an attack chain updated by an applied command patch', () => {
  const reviewed = {
    ...payload('command-chain-update'),
    prerequisites: [i18n('授权实验。', 'Authorized lab.')],
    tutorial: {
      overview: i18n('概览内容。', 'Overview content.'),
      vulnerability: i18n('漏洞内容。', 'Vulnerability content.'),
      exploitation: i18n('验证内容。', 'Validation content.'),
      mitigation: i18n('修复内容。', 'Mitigation content.'),
      difficulty: 'intermediate',
    },
    analysis: i18n('分析内容。', 'Analysis content.'),
    opsecTips: [i18n('限制范围。', 'Limit scope.')],
    attackChain: [{
      title: i18n('运行原始命令', 'Run the original command'),
      description: i18n('记录命令输出。', 'Record command output.'),
      payload: './tool server --port 8000',
    }],
  };
  const current = structuredClone(reviewed);
  current.execution[0].command = './tool server --port 8000 --lab';
  current.attackChain[0].payload = './tool server --port 8000 --lab';
  const options = prepareCurationOptions({
    overrideDocuments: [{
      schemaVersion: 1,
      contentStandard: 3,
      sourceIds: [reviewed.id],
      entries: [reviewed],
    }],
    payloadCommandOverrides: {
      schemaVersion: 1,
      entries: [{
        id: reviewed.id,
        patches: [{
          area: 'execution',
          index: 0,
          expectedCommand: './tool server --port 8000',
          command: './tool server --port 8000 --lab',
        }],
      }],
    },
  }, [current], []);

  assert.deepEqual(options.overrideDocuments, []);
  assert.deepEqual(options.alreadyAppliedOverrideIds, [reviewed.id]);
});

test('prepareCurationOptions normalizes a pending attack chain to an already patched command', () => {
  const reviewed = {
    ...payload('pending-content-command-chain'),
    prerequisites: [i18n('授权实验。', 'Authorized lab.')],
    tutorial: {
      overview: i18n('新的概览内容。', 'New overview content.'),
      vulnerability: i18n('漏洞内容。', 'Vulnerability content.'),
      exploitation: i18n('验证内容。', 'Validation content.'),
      mitigation: i18n('修复内容。', 'Mitigation content.'),
      difficulty: 'intermediate',
    },
    analysis: i18n('分析内容。', 'Analysis content.'),
    opsecTips: [i18n('限制范围。', 'Limit scope.')],
    attackChain: [{
      title: i18n('运行原始命令', 'Run the original command'),
      description: i18n('记录命令输出。', 'Record command output.'),
      payload: './tool server --port 8000',
    }],
  };
  const current = structuredClone(reviewed);
  current.tutorial.overview = i18n('旧的概览内容。', 'Old overview content.');
  current.execution[0].command = './tool server --port 8000 --lab';
  current.attackChain[0].payload = './tool server --port 8000 --lab';
  const options = prepareCurationOptions({
    overrideDocuments: [{ schemaVersion: 1, contentStandard: 3, sourceIds: [reviewed.id], entries: [reviewed] }],
    payloadCommandOverrides: {
      schemaVersion: 1,
      entries: [{
        id: reviewed.id,
        patches: [{
          area: 'execution',
          index: 0,
          expectedCommand: './tool server --port 8000',
          command: './tool server --port 8000 --lab',
        }],
      }],
    },
  }, [current], []);

  assert.equal(options.overrideDocuments.length, 1);
  assert.equal(options.overrideDocuments[0].entries[0].attackChain[0].payload, './tool server --port 8000 --lab');
});

test('prepareCurationOptions filters applied command patches without dropping pending patches', () => {
  const current = payload('partial-command-update');
  current.execution.push({
    ...current.execution[0],
    command: './tool client --host target.test --lab',
  });
  const options = prepareCurationOptions({
    payloadCommandOverrides: {
      schemaVersion: 1,
      entries: [{
        id: current.id,
        patches: [{
          area: 'execution',
          index: 0,
          expectedCommand: './tool server --port 8000',
          command: './tool server --port 8000 --lab',
        }, {
          area: 'execution',
          index: 1,
          expectedCommand: './tool client --host target.test',
          command: './tool client --host target.test --lab',
        }],
      }],
    },
  }, [current], []);

  assert.equal(options.payloadCommandOverrides.entries.length, 1);
  assert.deepEqual(options.payloadCommandOverrides.entries[0].patches.map(patch => patch.index), [0]);
});
