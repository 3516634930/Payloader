import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  curatePayloadLibrary,
  normalizeReferenceUrls,
} from '../scripts/curate-payload-library.mjs';
import { buildCoreToolMigrationDocuments } from '../scripts/generate-core-tool-migrations.mjs';
import { restoreCoreToolMigrationSources } from '../scripts/generate-core-tool-migrations.mjs';

const i18n = (zh, en) => ({ zh, en });
const sourcePayload = (id, executionCount, wafBypassCount = 0) => ({
  id,
  name: i18n(id, id),
  description: i18n(`${id} old description`, `${id} legacy description`),
  category: i18n('Information gathering', 'Information Gathering'),
  subCategory: i18n('Tool manual', 'Tool Manual'),
  execution: Array.from({ length: executionCount }, (_, index) => ({
    title: i18n(`Old command ${index}`, `Legacy command ${index}`),
    command: `source-execution-${index}`,
    description: i18n('Old command description', 'Legacy command description'),
  })),
  wafBypass: Array.from({ length: wafBypassCount }, (_, index) => ({
    title: i18n(`Old variant ${index}`, `Legacy variant ${index}`),
    command: `source-waf-${index}`,
    description: i18n('Old variant description', 'Legacy variant description'),
  })),
});

const profileCounts = new Map([
  ['domain-recon', [8, 0]],
  ['cdn-bypass', [5, 1]],
  ['spn-scan', [5, 0]],
  ['port-scan', [8, 0]],
  ['network-recon', [8, 0]],
  ['share-enum', [6, 0]],
  ['user-enum', [6, 0]],
  ['group-enum', [6, 0]],
  ['gpo-enum', [5, 0]],
  ['trust-enum', [4, 0]],
  ['exchange-enum', [4, 0]],
  ['sharepoint-enum', [4, 0]],
  ['sharepoint-file-access', [4, 0]],
  ['tunnel-dns', [3, 0]],
  ['tunnel-icmp', [2, 0]],
  ['socks-proxy', [4, 0]],
  ['lateral-ssh', [3, 0]],
  ['lateral-winrm', [3, 0]],
  ['lateral-winrs', [2, 0]],
  ['windows-privesc', [4, 0]],
  ['linux-privesc', [4, 0]],
  ['kernel-exploit', [3, 0]],
  ['potato-attack', [7, 0]],
  ['process-injection', [3, 0]],
  ['applocker-bypass', [4, 0]],
  ['evasion-signed-binary', [4, 0]],
  ['persistence-scheduled', [4, 0]],
  ['exchange-mailbox-access', [4, 0]],
  ['unattended-creds', [6, 0]],
  ['custom-sql注入速查表', [1, 0]],
]);

const expectedIds = [...profileCounts.keys()];
const retainedIds = new Set([
  'lateral-ssh', 'lateral-winrm', 'lateral-winrs', 'windows-privesc', 'linux-privesc',
  'kernel-exploit', 'potato-attack', 'process-injection', 'applocker-bypass',
  'evasion-signed-binary', 'persistence-scheduled', 'exchange-mailbox-access',
  'unattended-creds', 'custom-sql注入速查表',
]);
const migrationIds = expectedIds.filter(id => !retainedIds.has(id));
const makeSources = () => expectedIds.map(id => {
  const [executionCount, wafBypassCount] = profileCounts.get(id);
  return sourcePayload(id, executionCount, wafBypassCount);
});

const routingKeys = migration => migration.targets.flatMap(target => [
  ...target.commandIndexes.map(index => `execution:${index}:${target.targetToolId}`),
  ...target.wafBypassIndexes.map(index => `wafBypass:${index}:${target.targetToolId}`),
]);

test('core tool migrations move command manuals out of payloads with bounded replacements', () => {
  const sources = makeSources();
  const documents = buildCoreToolMigrationDocuments(sources);

  assert.equal(documents.overrides.contentStandard, 3);
  assert.deepEqual(documents.overrides.entries.map(entry => entry.id), expectedIds);
  assert.deepEqual(documents.migrations.toolMigrations.map(entry => entry.sourceId), migrationIds);
  assert.equal(documents.overrides.entries.filter(entry => entry.review.decision === 'payload').length, retainedIds.size);
  assert.equal(documents.commandOverrides.entries.every(entry => !retainedIds.has(entry.id)), true);
  assert.equal(documents.overrides.entries.filter(entry => retainedIds.has(entry.id)).every(entry => !entry.review.targetToolIds), true);

  const patches = documents.commandOverrides.entries.flatMap(entry => entry.patches);
  assert.equal(patches.length, 83);
  assert.equal(patches.every(patch => patch.command !== patch.expectedCommand), true);
  assert.doesNotMatch(
    patches.map(patch => patch.command).join('\n'),
    /DownloadString|Invoke-WebRequest|certutil\s+-urlcache|192\.168\.|10\.0\.0\.|evil\.com|attacker|--script\s+vuln|-p-|1-65535|\bmasscan\b|user:password|password@|beacon>\s+socks\s+1080|schtasks\s+\/create|Register-ScheduledTask|\bcrontab\s+-e\b|net\s+user\s+\S+\s+\S+\s+\/add|nc\.exe|\s-e\s+cmd/i,
  );
  assert.equal(patches.every(patch => patch.title.zh && patch.title.en), true);
  assert.equal(patches.every(patch => patch.description.zh.length >= 12 && patch.description.en.length >= 30), true);

  for (const migration of documents.migrations.toolMigrations) {
    const entry = documents.commandOverrides.entries.find(item => item.id === migration.sourceId);
    const routed = routingKeys(migration);
    assert.equal(new Set(routed).size, routed.length, `${migration.sourceId} routes each command once`);
    assert.deepEqual(
      routed.map(value => value.split(':').slice(0, 2).join(':')).sort(),
      entry.patches.map(patch => `${patch.area}:${patch.index}`).sort(),
      `${migration.sourceId} routes every source command`,
    );
    assert.equal(
      migration.targets.every(target => target.targetToolId && target.targetReferences.length >= 1),
      true,
      `${migration.sourceId} has explicit target tools and references`,
    );
  }
});

test('core tool migration generation is deterministic and checked-in documents retain source coverage', () => {
  const sources = makeSources();
  const first = buildCoreToolMigrationDocuments(sources);
  const second = buildCoreToolMigrationDocuments(structuredClone(sources));
  assert.deepEqual(second, first);

  const overrides = JSON.parse(readFileSync('content-review/overrides-core-tool-migrations.json', 'utf8'));
  const commandOverrides = JSON.parse(readFileSync('content-review/payload-command-overrides-core-tool-migrations.json', 'utf8'));
  const migrations = JSON.parse(readFileSync('content-review/collection-splits-core-tool-migrations.json', 'utf8'));
  assert.deepEqual(overrides.sourceIds, expectedIds);
  const commandOverrideIds = commandOverrides.entries.map(entry => entry.id);
  assert.equal(commandOverrideIds.every(id => expectedIds.includes(id)), true);
  assert.equal(new Set(commandOverrideIds).size, commandOverrideIds.length);
  assert.deepEqual(migrations.toolMigrations.map(entry => entry.sourceId), migrationIds);
});

test('migration target references are unioned with existing tool references', () => {
  const sources = makeSources();
  const documents = buildCoreToolMigrationDocuments(sources);
  const existingReference = 'https://example.test/existing-tool-reference';
  const roots = [...new Set(documents.migrations.toolMigrations.flatMap(migration => (
    migration.targets.map(target => target.navRootId)
  )))];
  const result = curatePayloadLibrary({
    payloads: sources,
    tools: [{
      id: 'active-directory-enumeration',
      name: i18n('AD enumeration', 'AD Enumeration'),
      description: i18n('Existing tool description long enough for review.', 'Existing tool description retained during migration.'),
      category: i18n('Domain tools', 'Domain Tools'),
      commands: [],
      references: [existingReference],
    }],
    navigation: [],
    toolNavigation: roots.map(id => ({ id, name: i18n(id, id), children: [] })),
  }, {
    payloadCommandOverrides: documents.commandOverrides,
    toolMigrations: documents.migrations.toolMigrations,
  });
  const target = result.snapshot.tools.find(tool => tool.id === 'active-directory-enumeration');
  const expectedReferences = documents.migrations.toolMigrations
    .flatMap(migration => migration.targets)
    .filter(item => item.targetToolId === target.id)
    .flatMap(item => item.targetReferences);
  assert.equal(target.references.includes(existingReference), true);
  assert.equal(normalizeReferenceUrls(expectedReferences).every(reference => target.references.includes(reference)), true);
  assert.equal(new Set(target.references).size, target.references.length);
});

test('retained security mechanisms receive mechanism-specific tutorials and attack chains', () => {
  const documents = buildCoreToolMigrationDocuments(makeSources());
  const entries = new Map(documents.overrides.entries.map(entry => [entry.id, entry]));
  const ids = [
    'windows-privesc',
    'linux-privesc',
    'kernel-exploit',
    'potato-attack',
    'lateral-ssh',
    'lateral-winrm',
    'lateral-winrs',
    'process-injection',
    'applocker-bypass',
    'evasion-signed-binary',
    'exchange-mailbox-access',
    'unattended-creds',
  ];
  const chainFingerprints = ids.map(id => JSON.stringify(entries.get(id).attackChain));

  assert.equal(new Set(chainFingerprints).size, ids.length);
  assert.match(entries.get('windows-privesc').tutorial.vulnerability.en, /service|ACL|token/i);
  assert.match(entries.get('linux-privesc').tutorial.vulnerability.en, /SUID|sudo|capabilit/i);
  assert.match(entries.get('kernel-exploit').tutorial.vulnerability.en, /kernel|patch|distribution/i);
  assert.match(entries.get('potato-attack').tutorial.vulnerability.en, /impersonation|token|COM/i);
  assert.match(entries.get('unattended-creds').tutorial.vulnerability.en, /unattend|credential|secret/i);
  assert.doesNotMatch(entries.get('unattended-creds').tutorial.vulnerability.en, /Exchange|SharePoint/i);
});

test('generator restores migrated source commands from checked-in expected commands', () => {
  const sources = makeSources();
  const original = buildCoreToolMigrationDocuments(sources);
  const curatedSources = sources.filter(source => source.id !== 'domain-recon').map(source => {
    const override = original.commandOverrides.entries.find(entry => entry.id === source.id);
    if (!override) return source;
    const next = structuredClone(source);
    for (const patch of override.patches) next[patch.area][patch.index].command = patch.command;
    return next;
  });

  const restored = restoreCoreToolMigrationSources(curatedSources, original.commandOverrides);
  const regenerated = buildCoreToolMigrationDocuments(restored);

  assert.deepEqual(regenerated.commandOverrides, original.commandOverrides);
  assert.deepEqual(regenerated.migrations, original.migrations);
});
