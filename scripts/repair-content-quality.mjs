import { existsSync } from 'node:fs';
import { mkdir, rename, rm, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as sqlite from 'node:sqlite';

import {
  PAYLOAD_BRANCH_RULES,
  auditDatabase,
  auditSnapshot,
  formatHumanSummary,
  hasBlockingErrors,
} from './verify-content-quality.mjs';
import { loadContentDataFromDatabase } from '../server/data-store.mjs';

const { DatabaseSync } = sqlite;
const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const defaultRuntimeFile = resolve(projectRoot, 'data', 'payloader.sqlite');
const defaultSeedFile = resolve(projectRoot, 'server', 'default-seed.sqlite');
const defaultBackupDir = resolve(projectRoot, 'data', 'backups');
const genericTutorialText = new Set([
  '\u9009\u62e9\u5bf9\u5e94payload\u6d4b\u8bd5',
  '\u9009\u62e9\u7ed5\u8fc7\u6280\u672f',
]);
const orphanAttachmentIds = new Set([
  'ai2-mixed-case-bypass',
  'ai2-virtual-scenario-bypass',
  'nosql2-ognl-struts2',
]);
const knownCommandLocations = new Set([
  'auth-bypass:execution:2',
  'clickjacking-basic:wafBypass:2',
  'file-null-byte:execution:0',
  'clickjacking-xss:wafBypass:1',
]);
const internalCommandFragment = /,\s*\r?\n\s*syntaxBreakdown\s*:\s*\[\s*\r?\n(?:\s*\{[^\r\n]*\},?\s*\r?\n)+\s*\]\s*/g;
const replacementTextFixes = new Map([
  ['\u76ee\u6807\uFFFD\uFFFD\uFFFD\u5728\u5bf9\u5e94\u6ce8\u5165\u70b9', '\u76ee\u6807\u5b58\u5728\u5bf9\u5e94\u6ce8\u5165\u70b9'],
  ['Leetspeak\u7ed5\u8fc7\uff0c\u51716\u6761\uFFFD\uFFFD\uFFFD\u5c55\u793a\u524d6\u6761', 'Leetspeak \u7ed5\u8fc7\uff0c\u5171 6 \u6761\uff0c\u5c55\u793a\u524d 6 \u6761'],
  ['16. \u5de5\u5177/\uFFFD\uFFFD\u6570\u6ee5\u7528 (Tool/Function Abuse)', '16. \u5de5\u5177/\u51fd\u6570\u6ee5\u7528 (Tool/Function Abuse)'],
  ['PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uFFFD\uFFFD\uFFFD\u6765\u6e90\uff1aShell/Session\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002', 'PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aShell/Session\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aNetAdapter\u3002\u8be5\u6761\u76ee\u53ea\uFFFD\uFFFD\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002', 'PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aNetAdapter\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aNetSecurity\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\uFFFD\uFFFD\u539f\u547d\u4ee4\u3002', 'PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aNetSecurity\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aNetSecurity\u3002\u8be5\u6761\u76ee\u53ea\uFFFD\uFFFD\uFFFD\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002', 'PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aNetSecurity\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['PowerShell \uFFFD\uFFFD\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aSmbShare\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002', 'PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aSmbShare\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['PowerShell \u51fd\uFFFD\uFFFD\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aStorage\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002', 'PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aStorage\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\uFFFD\uFFFD\uff1aStorage\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002', 'PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aStorage\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aVpnClient\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\uFFFD\uFFFD\u6267\u884c\u539f\u547d\u4ee4\u3002', 'PowerShell \u51fd\u6570\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aVpnClient\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['PowerShell \u522b\u540d\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aShell/Session\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\uFFFD\uFFFD\uFFFD\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002', 'PowerShell \u522b\u540d\u7d22\u5f15\u9879\uff1b\u6765\u6e90\uff1aShell/Session\u3002\u8be5\u6761\u76ee\u53ea\u6253\u5f00\u5e2e\u52a9\u6216\u522b\u540d\u4fe1\u606f\uff0c\u4e0d\u76f4\u63a5\u6267\u884c\u539f\u547d\u4ee4\u3002'],
  ['\u8ba4\u8bc1\u6821\u9a8c\uFFFD\uFFFD\uFFFD\u9677', '\u8ba4\u8bc1\u6821\u9a8c\u7f3a\u9677'],
]);

const categoryByBranch = new Map([
  ['rce', { zh: '\u0052\u0043\u0045\u8fdc\u7a0b\u4ee3\u7801\u6267\u884c', en: 'RCE Remote Code Execution' }],
  ['clickjacking', { zh: '\u70b9\u51fb\u52ab\u6301', en: 'Clickjacking' }],
  ['web-redirect', { zh: '\u5f00\u653e\u91cd\u5b9a\u5411', en: 'Open Redirect' }],
  ['web-smuggling', { zh: '\u8bf7\u6c42\u8d70\u79c1', en: 'Request Smuggling' }],
  ['prototype-pollution', { zh: '\u539f\u578b\u94fe\u6c61\u67d3', en: 'Prototype Pollution' }],
  ['web-cache', { zh: '\u7f13\u5b58\u4e0eCDN\u5b89\u5168', en: 'Cache & CDN Security' }],
  ['ssrf', { zh: 'SSRF\u670d\u52a1\u7aef\u8bf7\u6c42\u4f2a\u9020', en: 'Server-side request forgery (SSRF)' }],
  ['framework-vulns', { zh: '\u6846\u67b6\u6f0f\u6d1e', en: 'Framework Vulnerabilities' }],
]);

const isObject = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const asList = value => Array.isArray(value) ? value : [];
const clone = value => structuredClone(value);
const displayText = value => typeof value === 'string' ? value : (value?.zh || value?.en || '');
const jsonEqual = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const timestamp = () => new Date().toISOString().replace(/[^0-9A-Za-z-]/g, '-');

const repairStrings = (value, changes) => {
  if (typeof value === 'string') {
    const fixed = replacementTextFixes.get(value);
    if (fixed != null) {
      changes.replacementCharacters += 1;
      return fixed;
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(item => repairStrings(item, changes));
  if (isObject(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, repairStrings(item, changes)]));
  }
  return value;
};

const repairKnownCommandFragments = (payload, changes) => {
  for (const area of ['execution', 'wafBypass']) {
    asList(payload[area]).forEach((entry, index) => {
      const location = `${payload.id}:${area}:${index}`;
      if (!knownCommandLocations.has(location) || typeof entry?.command !== 'string') return;
      const repaired = entry.command.replace(internalCommandFragment, '\n');
      if (repaired !== entry.command) {
        entry.command = repaired;
        changes.sourceFragments += 1;
      }
    });
  }
};

const findNode = (nodes, id) => {
  for (const node of asList(nodes)) {
    if (node.id === id) return node;
    const nested = findNode(node.children, id);
    if (nested) return nested;
  }
  return null;
};

const collectPayloadReferences = (nodes, payloadId, path = [], output = []) => {
  for (const node of asList(nodes)) {
    const nextPath = [...path, node.id];
    if (node.payloadId === payloadId) output.push({ node, path: nextPath });
    collectPayloadReferences(node.children, payloadId, nextPath, output);
  }
  return output;
};

const detachLeafAtPath = (nodes, path, depth = 0) => asList(nodes).flatMap(node => {
  if (node.id !== path[depth]) return [clone(node)];
  if (depth === path.length - 1) return [];
  const next = clone(node);
  const children = detachLeafAtPath(next.children, path, depth + 1);
  if (children.length) next.children = children;
  else delete next.children;
  return [next];
});

const makeNavigationNode = payload => ({
  id: `${payload.id}-nav`,
  name: clone(payload.name || payload.id),
  payloadId: payload.id,
});

const movePayloadToBranch = (navigation, payload, branchId, changes, warnings) => {
  const references = collectPayloadReferences(navigation, payload.id);
  if (references.length === 1 && references[0].path.includes(branchId)) return navigation;
  const refuse = reason => {
    changes.navigationMigrationRefusals += 1;
    warnings.push({
      payloadId: payload.id,
      targetBranch: branchId,
      reason,
      references: references.map(reference => reference.path.join('/')),
    });
    return navigation;
  };
  if (references.length > 1) return refuse('multiple-references');
  if (references.length === 1 && asList(references[0].node.children).length) return refuse('non-leaf-reference');
  if (!references.length && !orphanAttachmentIds.has(payload.id)) return refuse('unreferenced-nonattachment');
  if (!findNode(navigation, branchId)) return refuse('target-branch-missing');

  const nextNavigation = references.length
    ? detachLeafAtPath(navigation, references[0].path)
    : clone(navigation);
  const target = findNode(nextNavigation, branchId);
  const node = references[0]?.node || makeNavigationNode(payload);
  target.children = [...asList(target.children), { ...clone(node), payloadId: payload.id }];
  if (!references.length) changes.orphansAttached += 1;
  else changes.navigationRelocations += 1;
  return nextNavigation;
};

const emptyChanges = () => ({
  sourceFragments: 0,
  replacementCharacters: 0,
  genericTutorialsRemoved: 0,
  orphansAttached: 0,
  navigationRelocations: 0,
  navigationMigrationRefusals: 0,
  categoryCorrections: 0,
  rowsUpdated: 0,
});

export const planContentRepairs = input => {
  const changes = emptyChanges();
  const warnings = [];
  const snapshot = {
    payloads: clone(asList(input?.payloads)),
    tools: clone(asList(input?.tools)),
    navigation: clone(asList(input?.navigation)),
    toolNavigation: clone(asList(input?.toolNavigation)),
    settings: isObject(input?.settings) ? clone(input.settings) : null,
  };
  snapshot.payloads = snapshot.payloads.map(payload => {
    let next = repairStrings(payload, changes);
    repairKnownCommandFragments(next, changes);
    const tutorialText = displayText(next.tutorial?.exploitation).trim();
    if (genericTutorialText.has(tutorialText)) {
      delete next.tutorial;
      changes.genericTutorialsRemoved += 1;
    }
    const rule = PAYLOAD_BRANCH_RULES.find(item => item.payloadId === next.id);
    const category = rule && categoryByBranch.get(rule.branchId);
    if (category && !jsonEqual(next.category, category)) {
      next.category = clone(category);
      changes.categoryCorrections += 1;
    }
    return next;
  });
  snapshot.tools = snapshot.tools.map(tool => repairStrings(tool, changes));
  snapshot.navigation = snapshot.navigation.map(item => repairStrings(item, changes));
  snapshot.toolNavigation = snapshot.toolNavigation.map(item => repairStrings(item, changes));

  const payloadById = new Map(snapshot.payloads.map(payload => [payload.id, payload]));
  for (const rule of PAYLOAD_BRANCH_RULES) {
    const payload = payloadById.get(rule.payloadId);
    if (!payload) continue;
    snapshot.navigation = movePayloadToBranch(snapshot.navigation, payload, rule.branchId, changes, warnings);
  }
  return { snapshot, changes, warnings };
};

const loadDatabaseSnapshot = file => {
  const database = new DatabaseSync(resolve(file), { readOnly: true });
  try {
    const parseRows = (query, column) => database.prepare(query).all().map(row => JSON.parse(row[column]));
    const payloads = parseRows('SELECT data FROM payloads ORDER BY sort_order, id', 'data');
    const tools = parseRows('SELECT data FROM tools ORDER BY sort_order, id', 'data');
    const navigation = parseRows("SELECT tree FROM navigation_nodes WHERE kind = 'payloads' ORDER BY sort_order, id", 'tree');
    const toolNavigation = parseRows("SELECT tree FROM navigation_nodes WHERE kind = 'tools' ORDER BY sort_order, id", 'tree');
    const settingsValue = database.prepare("SELECT value FROM metadata WHERE key = 'settings'").get()?.value;
    const settings = settingsValue ? JSON.parse(settingsValue) : null;
    return { payloads, tools, navigation, toolNavigation, settings };
  } finally {
    database.close();
  }
};

const verifySqliteIntegrity = file => {
  const database = new DatabaseSync(file, { readOnly: true });
  try {
    const rows = database.prepare('PRAGMA integrity_check').all();
    const valid = rows.length === 1 && Object.values(rows[0])[0] === 'ok';
    if (!valid) throw new Error(`SQLite integrity check failed for ${file}`);
  } finally {
    database.close();
  }
};

const backupOpenDatabase = async (database, destination) => {
  if (typeof sqlite.backup === 'function') {
    return {
      pages: await sqlite.backup(database, destination),
      method: 'node:sqlite.backup',
    };
  }
  const checkpoint = database.prepare('PRAGMA wal_checkpoint(FULL)').get();
  if (Number(checkpoint?.busy || 0) !== 0) {
    throw new Error('Unable to checkpoint the SQLite WAL before backup.');
  }
  database.prepare('VACUUM INTO ?').run(destination);
  return { pages: null, method: 'checkpoint-vacuum-into' };
};

const createDatabaseBackup = async (file, backupDir, label) => {
  await mkdir(backupDir, { recursive: true });
  const fileName = `${label}-${timestamp()}-${randomUUID().slice(0, 8)}.sqlite`;
  const backupFile = join(backupDir, fileName);
  const database = new DatabaseSync(file);
  let backupResult;
  try {
    database.exec('PRAGMA busy_timeout = 5000;');
    backupResult = await backupOpenDatabase(database, backupFile);
  } catch (error) {
    await rm(backupFile, { force: true }).catch(() => {});
    throw error;
  } finally {
    database.close();
  }
  verifySqliteIntegrity(backupFile);
  const details = await stat(backupFile);
  return {
    fileName,
    path: backupFile,
    sizeBytes: details.size,
    pages: backupResult.pages,
    method: backupResult.method,
    integrity: 'ok',
  };
};

const updateDatabaseSnapshot = (file, before, after) => {
  const database = new DatabaseSync(file);
  const now = new Date().toISOString();
  const updates = {
    payloads: database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?'),
    tools: database.prepare('UPDATE tools SET data = ?, updated_at = ? WHERE id = ?'),
    navigation: database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?'),
  };
  let rowsUpdated = 0;
  const updateItems = (oldItems, newItems, statement) => {
    const beforeById = new Map(oldItems.map(item => [item.id, item]));
    for (const item of newItems) {
      if (jsonEqual(beforeById.get(item.id), item)) continue;
      rowsUpdated += Number(statement.run(JSON.stringify(item), now, item.id).changes || 0);
    }
  };
  try {
    database.exec('PRAGMA busy_timeout = 5000; BEGIN IMMEDIATE;');
    updateItems(before.payloads, after.payloads, updates.payloads);
    updateItems(before.tools, after.tools, updates.tools);
    updateItems([...before.navigation, ...before.toolNavigation], [...after.navigation, ...after.toolNavigation], updates.navigation);
    database.exec('COMMIT;');
    return rowsUpdated;
  } catch (error) {
    try {
      database.exec('ROLLBACK;');
    } catch {
      // Keep the original mutation error.
    }
    throw error;
  } finally {
    database.close();
  }
};

const assertRepairable = (currentReport, plannedReport) => {
  if (currentReport.blocking.databaseIntegrity.count || currentReport.blocking.invalidJson.count) {
    throw new Error('Database integrity or JSON errors must be resolved before automated content repair.');
  }
  if (hasBlockingErrors(plannedReport)) {
    throw new Error(`Planned repair still has ${plannedReport.summary.blockingErrors} blocking content errors.`);
  }
};

export const repairDatabase = async (file, options = {}) => {
  const absoluteFile = resolve(file);
  const backupDir = resolve(options.backupDir || defaultBackupDir);
  const before = loadDatabaseSnapshot(absoluteFile);
  const currentReport = auditDatabase(absoluteFile);
  const plan = planContentRepairs(before);
  const plannedReport = auditSnapshot(plan.snapshot, { source: `${absoluteFile} (planned)` });
  assertRepairable(currentReport, plannedReport);
  if (!options.apply) {
    return {
      applied: false,
      file: absoluteFile,
      changes: plan.changes,
      warnings: plan.warnings,
      currentReport,
      plannedReport,
    };
  }
  const backup = await createDatabaseBackup(absoluteFile, backupDir, `${basename(absoluteFile, '.sqlite')}-before-content-repair`);
  const rowsUpdated = updateDatabaseSnapshot(absoluteFile, before, plan.snapshot);
  const report = auditDatabase(absoluteFile);
  if (hasBlockingErrors(report)) {
    throw new Error(`Content repair completed but verification found ${report.summary.blockingErrors} blocking errors. Backup: ${backup.path}`);
  }
  return {
    applied: true,
    file: absoluteFile,
    backup,
    changes: { ...plan.changes, rowsUpdated },
    warnings: plan.warnings,
    report,
  };
};

const seedTables = ['metadata', 'navigation_nodes', 'payloads', 'tools'];
const seedMetadataKeys = ['content_kind', 'generated_at', 'seed_schema_version', 'source'];

const writeCleanSeedDatabase = async (content, file, source) => {
  const database = new DatabaseSync(file);
  const createdAt = new Date().toISOString();
  try {
    database.exec(`
      PRAGMA journal_mode = DELETE;
      PRAGMA synchronous = FULL;
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
        kind TEXT NOT NULL CHECK(kind IN ('payloads', 'tools')),
        sort_order INTEGER NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      BEGIN IMMEDIATE;
    `);
    const insertItem = (table, column, items) => {
      const statement = database.prepare(`
        INSERT INTO ${table} (id, ${column}, sort_order, enabled, created_at, updated_at)
        VALUES (?, ?, ?, 1, ?, ?)
      `);
      asList(items).forEach((item, index) => statement.run(item.id, JSON.stringify(item), index, createdAt, createdAt));
    };
    insertItem('payloads', 'data', content.payloads);
    insertItem('tools', 'data', content.tools);
    const insertNavigation = database.prepare(`
      INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, 1, ?, ?)
    `);
    const usedNavigationIds = new Set();
    const addNavigation = (items, kind) => asList(items).forEach((item, index) => {
      if (usedNavigationIds.has(item.id)) throw new Error(`Duplicate seed navigation id: ${item.id}`);
      usedNavigationIds.add(item.id);
      insertNavigation.run(item.id, JSON.stringify(item), kind, index, createdAt, createdAt);
    });
    addNavigation(content.navigation, 'payloads');
    addNavigation(content.toolNavigation, 'tools');
    const insertMetadata = database.prepare('INSERT INTO metadata (key, value) VALUES (?, ?)');
    insertMetadata.run('seed_schema_version', '1');
    insertMetadata.run('content_kind', 'curated-defaults');
    insertMetadata.run('generated_at', createdAt);
    insertMetadata.run('source', source);
    database.exec('COMMIT;');
  } catch (error) {
    try {
      database.exec('ROLLBACK;');
    } catch {
      // Keep the original metadata error.
    }
    throw error;
  } finally {
    database.close();
  }
};

const assertCleanSeedShape = file => {
  const database = new DatabaseSync(file, { readOnly: true });
  try {
    const tables = database
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
      .all()
      .map(row => row.name);
    if (!jsonEqual(tables, seedTables)) {
      throw new Error(`Seed table allowlist mismatch: ${tables.join(', ')}`);
    }
    const metadata = database.prepare('SELECT key, value FROM metadata ORDER BY key').all();
    const keys = metadata.map(row => row.key);
    if (!jsonEqual(keys, seedMetadataKeys)) {
      throw new Error(`Seed metadata allowlist mismatch: ${keys.join(', ')}`);
    }
    const values = Object.fromEntries(metadata.map(row => [row.key, row.value]));
    if (values.seed_schema_version !== '1' || values.content_kind !== 'curated-defaults') {
      throw new Error('Seed metadata contract mismatch.');
    }
  } finally {
    database.close();
  }
};

export const refreshSeedFromRuntime = async (runtimeFile, seedFile, options = {}) => {
  const runtime = resolve(runtimeFile);
  const seed = resolve(seedFile);
  const backupDir = resolve(options.backupDir || defaultBackupDir);
  const runtimeReport = auditDatabase(runtime);
  if (hasBlockingErrors(runtimeReport)) {
    throw new Error(`Runtime database has ${runtimeReport.summary.blockingErrors} blocking errors; seed refresh aborted.`);
  }
  const backup = existsSync(seed)
    ? await createDatabaseBackup(seed, backupDir, `${basename(seed, '.sqlite')}-before-content-refresh`)
    : null;
  await mkdir(dirname(seed), { recursive: true });
  const temporarySeed = join(dirname(seed), `.content-seed-${randomUUID()}.sqlite`);
  const content = loadContentDataFromDatabase(runtime);
  const writeSeedDatabase = options.writeSeedDatabase || writeCleanSeedDatabase;
  const publishSeed = options.publishSeed || rename;
  let published = false;
  try {
    await writeSeedDatabase(content, temporarySeed, 'validated runtime content-quality snapshot');
    if (options.afterBuild) await options.afterBuild(temporarySeed);
    verifySqliteIntegrity(temporarySeed);
    assertCleanSeedShape(temporarySeed);
    const temporaryReport = auditDatabase(temporarySeed);
    if (hasBlockingErrors(temporaryReport)) {
      throw new Error(`Generated seed has ${temporaryReport.summary.blockingErrors} blocking errors.`);
    }
    temporaryReport.source = seed;
    const result = { runtime, seed, backup, report: temporaryReport };
    await publishSeed(temporarySeed, seed);
    published = true;
    return result;
  } finally {
    if (!published) await rm(temporarySeed, { force: true }).catch(() => {});
  }
};

const parseCli = argv => {
  const options = {
    apply: false,
    json: false,
    runtimeFile: defaultRuntimeFile,
    seedFile: defaultSeedFile,
    backupDir: defaultBackupDir,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--apply') options.apply = true;
    else if (argument === '--json') options.json = true;
    else if (['--runtime', '--seed', '--backup-dir'].includes(argument)) {
      const value = argv[index + 1];
      if (!value) throw new Error(`${argument} requires a path`);
      if (argument === '--runtime') options.runtimeFile = resolve(value);
      if (argument === '--seed') options.seedFile = resolve(value);
      if (argument === '--backup-dir') options.backupDir = resolve(value);
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return options;
};

const runCli = async argv => {
  const options = parseCli(argv);
  if (!existsSync(options.runtimeFile)) throw new Error(`Runtime database not found: ${options.runtimeFile}`);
  const repair = await repairDatabase(options.runtimeFile, options);
  let seedRefresh = null;
  if (options.apply) {
    seedRefresh = await refreshSeedFromRuntime(options.runtimeFile, options.seedFile, options);
  }
  const result = {
    version: 1,
    mode: options.apply ? 'apply' : 'dry-run',
    ok: options.apply ? repair.report.ok && seedRefresh.report.ok : repair.plannedReport.ok,
    repair,
    seedRefresh,
  };
  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else if (options.apply) {
    console.log(`Content repair applied to ${repair.file}`);
    console.log(`Runtime backup: ${repair.backup.path}`);
    console.log(`Seed backup: ${seedRefresh.backup?.path || 'not required'}`);
    console.log(`Changes: ${JSON.stringify(repair.changes)}`);
    if (repair.warnings.length) console.log(`Navigation warnings: ${JSON.stringify(repair.warnings)}`);
    console.log(`\n${formatHumanSummary(repair.report)}\n\n${formatHumanSummary(seedRefresh.report)}`);
  } else {
    console.log('Content repair dry-run; no files were changed and no backups were created.');
    console.log(`Planned changes: ${JSON.stringify(repair.changes)}`);
    if (repair.warnings.length) console.log(`Navigation warnings: ${JSON.stringify(repair.warnings)}`);
    console.log(`\n${formatHumanSummary(repair.currentReport)}\n\nAfter planned repair:\n${formatHumanSummary(repair.plannedReport)}`);
  }
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  try {
    await runCli(process.argv.slice(2));
  } catch (error) {
    console.error(`Content quality repair failed: ${error.message}`);
    process.exitCode = 2;
  }
}
