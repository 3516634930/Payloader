import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as sqlite from 'node:sqlite';

import {
  curatePayloadLibrary,
  validatePayloadCommandOverrideDocument,
  validatePayloadOverrideDocument,
} from './curate-payload-library.mjs';
import { auditPayloadEditorialQuality } from './payload-editorial-review.mjs';
import { auditToolEditorialQuality } from './tool-editorial-review.mjs';
import { refreshSeedFromRuntime } from './repair-content-quality.mjs';
import { auditSnapshot, hasBlockingErrors } from './verify-content-quality.mjs';

const { DatabaseSync } = sqlite;
const asList = value => Array.isArray(value) ? value : [];
const clone = value => structuredClone(value);
const timestamp = () => new Date().toISOString().replace(/[:.]/g, '-');
const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const defaultRuntimeFile = resolve(projectRoot, 'data', 'payloader.sqlite');
const defaultSeedFile = resolve(projectRoot, 'server', 'default-seed.sqlite');
const defaultReviewDir = resolve(projectRoot, 'content-review');
const defaultBackupDir = resolve(projectRoot, 'data', 'backups');
const defaultLedgerFile = resolve(defaultReviewDir, 'review-ledger.json');

export const auditCurationCoverage = (payloadsInput, options = {}) => {
  const sortedIds = values => [...new Set(asList(values).map(value => String(value || '').trim()).filter(Boolean))].sort();
  const toolTargetsFor = decision => sortedIds([
    decision?.targetToolId,
    ...asList(decision?.targetToolIds),
    ...asList(decision?.targets).map(target => target?.targetToolId),
    ...asList(decision?.toolTargets).map(target => target?.targetToolId),
  ]);
  const payloadTargetsFor = decision => sortedIds([
    decision?.targetPayloadId,
    ...asList(decision?.targetPayloadIds),
    ...asList(decision?.replacements).map(replacement => replacement?.id),
    ...asList(decision?.targets).map(target => target?.targetPayloadId),
  ]);
  const payloadIds = new Set(asList(payloadsInput).map(item => item.id));
  const reviewCounts = new Map();
  const reviewedEntries = [];
  for (const document of asList(options.overrideDocuments)) {
    for (const entry of asList(document?.entries)) {
      const id = String(entry?.id || '').trim();
      if (!id) continue;
      reviewedEntries.push(entry);
      reviewCounts.set(id, (reviewCounts.get(id) || 0) + 1);
    }
  }
  const decisions = [
    ...asList(options.toolMigrations),
    ...asList(options.payloadSplits),
    ...asList(options.collectionSplits),
  ];
  const decisionsBySource = new Map();
  for (const decision of asList(options.toolMigrations)) {
    if (decision?.sourceId && !decisionsBySource.has(decision.sourceId)) {
      decisionsBySource.set(decision.sourceId, { decision: 'tool', value: decision });
    }
  }
  for (const decision of [...asList(options.payloadSplits), ...asList(options.collectionSplits)]) {
    if (decision?.sourceId && !decisionsBySource.has(decision.sourceId)) {
      decisionsBySource.set(decision.sourceId, { decision: 'split', value: decision });
    }
  }
  const decisionCounts = new Map();
  for (const decision of decisions) {
    const id = String(decision?.sourceId || '').trim();
    if (id) decisionCounts.set(id, (decisionCounts.get(id) || 0) + 1);
  }
  const generatedPayloadIds = new Set([
    ...asList(options.payloadSplits),
    ...asList(options.collectionSplits),
  ].flatMap(payloadTargetsFor));
  const retiredDecisionIds = new Set(
    [...decisionCounts.keys()].filter(id => !payloadIds.has(id)),
  );
  const reviewedIds = new Set([
    ...reviewCounts.keys(),
    ...decisionCounts.keys(),
    ...generatedPayloadIds,
    ...asList(options.alreadyAppliedOverrideIds),
  ]);
  const toolDecisionIds = new Set(asList(options.toolMigrations).map(item => item.sourceId));
  const splitDecisionIds = new Set([
    ...asList(options.payloadSplits).map(item => item.sourceId),
    ...asList(options.collectionSplits).map(item => item.sourceId),
  ]);
  const unmatchedReviewDecisions = reviewedEntries.flatMap(entry => {
    if (entry?.review?.decision === 'tool' && !toolDecisionIds.has(entry.id)) {
      return [{ id: entry.id, decision: 'tool' }];
    }
    if (entry?.review?.decision === 'split' && !splitDecisionIds.has(entry.id)) {
      return [{ id: entry.id, decision: 'split' }];
    }
    return [];
  }).sort((left, right) => left.id.localeCompare(right.id, 'en'));
  const routeMismatches = reviewedEntries.flatMap(entry => {
    if (!['tool', 'split'].includes(entry?.review?.decision)) return [];
    const actual = decisionsBySource.get(entry.id);
    if (!actual) return [];
    const declaredToolIds = sortedIds([
      entry.review.targetToolId,
      ...asList(entry.review.targetToolIds),
    ]);
    const declaredPayloadIds = sortedIds([
      entry.review.targetPayloadId,
      ...asList(entry.review.targetPayloadIds),
    ]);
    const actualToolIds = toolTargetsFor(actual.value);
    const actualPayloadIds = payloadTargetsFor(actual.value);
    if (
      actual.decision === entry.review.decision
      && JSON.stringify(declaredToolIds) === JSON.stringify(actualToolIds)
      && JSON.stringify(declaredPayloadIds) === JSON.stringify(actualPayloadIds)
    ) return [];
    return [{
      id: entry.id,
      decision: entry.review.decision,
      declaredPayloadIds,
      actualPayloadIds,
      declaredToolIds,
      actualToolIds,
    }];
  }).sort((left, right) => left.id.localeCompare(right.id, 'en'));
  const missingReviewIds = [...payloadIds].filter(id => !reviewedIds.has(id)).sort();
  const unknownReviewedIds = [...reviewedIds].filter(id => (
    !payloadIds.has(id)
    && !retiredDecisionIds.has(id)
    && !generatedPayloadIds.has(id)
  )).sort();
  const duplicateReviewIds = [...reviewCounts].filter(([, count]) => count > 1).map(([id]) => id).sort();
  const duplicateDecisionIds = [...decisionCounts].filter(([, count]) => count > 1).map(([id]) => id).sort();
  const complete = ![
    missingReviewIds,
    unknownReviewedIds,
    duplicateReviewIds,
    duplicateDecisionIds,
    unmatchedReviewDecisions,
    routeMismatches,
  ].some(items => items.length);
  return {
    complete,
    missingReviewIds,
    unknownReviewedIds,
    duplicateReviewIds,
    duplicateDecisionIds,
    unmatchedReviewDecisions,
    routeMismatches,
  };
};

const readJson = async file => JSON.parse(await readFile(file, 'utf8'));

const manifestDocumentNames = (manifest, fileNames, options) => {
  const hasPlural = Object.prototype.hasOwnProperty.call(manifest, options.pluralKey);
  if (hasPlural && manifest[options.singularKey]) {
    throw new Error(`Review manifest must use ${options.pluralKey} or ${options.singularKey}, not both.`);
  }
  if (hasPlural && !Array.isArray(manifest[options.pluralKey])) {
    throw new Error(`Review manifest ${options.pluralKey} must be an array.`);
  }
  const names = hasPlural
    ? manifest[options.pluralKey].map(String)
    : (manifest[options.singularKey] ? [String(manifest[options.singularKey])] : []);
  if (new Set(names).size !== names.length) {
    throw new Error(`Review manifest contains duplicate ${options.label} files.`);
  }
  for (const fileName of names) {
    if (!options.pattern.test(fileName) || !fileNames.has(fileName)) {
      throw new Error(`Review manifest references an invalid or missing ${options.label} file: ${fileName}`);
    }
  }
  return names;
};

export const loadReviewConfiguration = async directoryInput => {
  const directory = resolve(directoryInput);
  const fileNames = new Set(await readdir(directory));
  const manifestFile = join(directory, 'manifest.json');
  if (!fileNames.has('manifest.json')) throw new Error(`Review manifest not found: ${manifestFile}`);
  const manifest = await readJson(manifestFile);
  if (manifest.schemaVersion !== 1) throw new Error('Review manifest schemaVersion must equal 1.');
  const overrideFiles = asList(manifest.overrideFiles).map(String);
  if (new Set(overrideFiles).size !== overrideFiles.length) throw new Error('Review manifest contains duplicate override files.');
  for (const fileName of overrideFiles) {
    if (!/^overrides-[a-z0-9-]+\.json$/i.test(fileName) || !fileNames.has(fileName)) {
      throw new Error(`Review manifest references an invalid or missing override file: ${fileName}`);
    }
  }
  const overrideDocuments = await Promise.all(overrideFiles.map(fileName => readJson(join(directory, fileName))));
  const decisionsName = String(manifest.decisionsFile || 'tool-decisions.json');
  const toolOverrideNames = manifestDocumentNames(manifest, fileNames, {
    pluralKey: 'toolOverrideFiles',
    singularKey: 'toolOverridesFile',
    label: 'tool override',
    pattern: /^tool-overrides(?:-[a-z0-9-]+)?\.json$/i,
  });
  const payloadCommandOverrideNames = manifestDocumentNames(manifest, fileNames, {
    pluralKey: 'payloadCommandOverrideFiles',
    singularKey: 'payloadCommandOverridesFile',
    label: 'payload command override',
    pattern: /^payload-command-overrides(?:-[a-z0-9-]+)?\.json$/i,
  });
  const collectionSplitNames = manifestDocumentNames(manifest, fileNames, {
    pluralKey: 'collectionSplitFiles',
    singularKey: 'collectionSplitsFile',
    label: 'collection split',
    pattern: /^collection-splits(?:-[a-z0-9-]+)?\.json$/i,
  });
  const decisionsFile = join(directory, decisionsName);
  const decisions = existsSync(decisionsFile) ? await readJson(decisionsFile) : {};
  const toolOverrideDocuments = await Promise.all(toolOverrideNames.map(async fileName => {
    const document = await readJson(join(directory, fileName));
    if (document?.schemaVersion !== 1) {
      throw new Error(`Tool override document schemaVersion must equal 1: ${fileName}`);
    }
    return document;
  }));
  const payloadCommandOverrideDocuments = await Promise.all(payloadCommandOverrideNames.map(async fileName => {
    const document = await readJson(join(directory, fileName));
    if (document?.schemaVersion !== 1) {
      throw new Error(`Payload command override document schemaVersion must equal 1: ${fileName}`);
    }
    return document;
  }));
  const collectionSplitDocuments = await Promise.all(collectionSplitNames.map(async fileName => {
    const document = await readJson(join(directory, fileName));
    if (document?.schemaVersion !== 1 || document?.contentStandard !== 2) {
      throw new Error(`Collection split document must use schemaVersion 1 and contentStandard 2: ${fileName}`);
    }
    return document;
  }));
  const collectionEntries = key => collectionSplitDocuments.flatMap(document => asList(document[key]));
  const payloadCommandOverrides = {
    schemaVersion: 1,
    entries: payloadCommandOverrideDocuments.flatMap(document => asList(document.entries)),
  };
  return {
    schemaVersion: 1,
    reviewDirectory: directory,
    sourceFiles: {
      overrides: overrideFiles,
      decisions: existsSync(decisionsFile) ? decisionsName : null,
      toolOverrides: toolOverrideNames,
      payloadCommandOverrides: payloadCommandOverrideNames,
      collectionSplits: collectionSplitNames,
    },
    overrideDocuments,
    toolMigrations: [...asList(decisions.toolMigrations), ...collectionEntries('toolMigrations')],
    payloadSplits: [...asList(decisions.payloadSplits), ...collectionEntries('payloadSplits')],
    collectionSplits: [...asList(decisions.collectionSplits), ...collectionEntries('collectionSplits')],
    payloadBranches: [...asList(decisions.payloadBranches), ...collectionEntries('payloadBranches')],
    toolMerges: [...asList(decisions.toolMerges), ...collectionEntries('toolMerges')],
    toolOverrides: toolOverrideDocuments.flatMap(document => asList(document.entries)),
    payloadCommandOverrides,
  };
};

export const auditReviewConfiguration = (payloads, configuration) => {
  const coverage = auditCurationCoverage(payloads, configuration);
  const overrideErrors = asList(configuration.overrideDocuments).flatMap(document => (
    validatePayloadOverrideDocument(document, payloads).map(error => ({
      sourcePrefix: document?.sourcePrefix || '',
      ...error,
    }))
  ));
  const payloadCommandOverrideErrors = validatePayloadCommandOverrideDocument(
    configuration.payloadCommandOverrides || { schemaVersion: 1, entries: [] },
    payloads,
  );
  const contentStandardErrors = asList(configuration.overrideDocuments)
    .filter(document => ![2, 3].includes(document?.contentStandard))
    .map(document => ({
      sourcePrefix: document?.sourcePrefix || '',
      code: 'LEGACY_CONTENT_STANDARD',
      detail: 'contentStandard must equal 2 or 3',
    }));
  const invalidReviewItems = overrideErrors.length
    + payloadCommandOverrideErrors.length
    + contentStandardErrors.length;
  return {
    complete: coverage.complete && invalidReviewItems === 0,
    coverage,
    overrideErrors,
    payloadCommandOverrideErrors,
    contentStandardErrors,
    invalidReviewItems,
  };
};

export const prepareCurationOptions = (options = {}, payloadsInput = [], toolsInput = []) => {
  const currentPayloads = asList(payloadsInput);
  const currentPayloadIds = new Set(currentPayloads.map(item => String(item?.id || '').trim()));
  const currentPayloadsById = new Map(currentPayloads.map(item => [String(item?.id || '').trim(), item]));
  const currentToolsById = new Map(asList(toolsInput).map(item => [String(item?.id || '').trim(), item]));
  const retiredMergedToolIds = new Set(asList(options.toolMerges)
    .map(item => String(item?.sourceToolId || '').trim())
    .filter(id => id && !currentToolsById.has(id)));
  const managedSourceIds = new Set([
    ...asList(options.toolMigrations),
    ...asList(options.payloadSplits),
    ...asList(options.collectionSplits),
  ].map(item => String(item?.sourceId || '').trim()).filter(Boolean));
  const isRetiredManagedSource = id => {
    const normalized = String(id || '').trim();
    return normalized && !currentPayloadIds.has(normalized) && managedSourceIds.has(normalized);
  };
  const legacyOverrideStateFields = [
    'description', 'prerequisites',
    'tutorial', 'analysis', 'opsecTips', 'references',
  ];
  const strictOverrideStateFields = [
    'name', 'description', 'category', 'subCategory', 'prerequisites',
    'tutorial', 'attackChain', 'analysis', 'opsecTips', 'references',
  ];
  const commandPatchesById = new Map(asList(options.payloadCommandOverrides?.entries)
    .map(item => [String(item?.id || '').trim(), asList(item?.patches)]));
  const expectedAttackChain = (entry, current) => {
    const patches = commandPatchesById.get(String(entry?.id || '').trim()) || [];
    return asList(entry?.attackChain).map(step => {
      if (step?.payloadRef && ['execution', 'wafBypass'].includes(step.payloadRef.area)
        && Number.isInteger(step.payloadRef.index)) {
        const payload = current?.[step.payloadRef.area]?.[step.payloadRef.index]?.command;
        if (typeof payload !== 'string') return step;
        const resolved = { ...step, payload };
        delete resolved.payloadRef;
        return resolved;
      }
      if (typeof step?.payload !== 'string') return step;
      const patch = patches.find(item => String(item?.expectedCommand || '') === step.payload);
      return patch ? { ...step, payload: String(patch.command || '') } : step;
    });
  };
  const alreadyAppliedOverrideIds = new Set();
  const isAlreadyAppliedOverride = (entry, contentStandard) => {
    const id = String(entry?.id || '').trim();
    const current = currentPayloadsById.get(id);
    const fields = contentStandard >= 3 ? strictOverrideStateFields : legacyOverrideStateFields;
    const applied = Boolean(current) && fields.every(field => (
      JSON.stringify(current[field]) === JSON.stringify(
        field === 'attackChain' ? expectedAttackChain(entry, current) : entry?.[field],
      )
    ));
    if (applied) alreadyAppliedOverrideIds.add(id);
    return applied;
  };
  const readObjectPath = (target, path) => {
    let current = target;
    for (const segment of String(path || '').split('.').filter(Boolean)) {
      if (current == null || !Object.prototype.hasOwnProperty.call(current, segment)) {
        return { exists: false, value: undefined };
      }
      current = current[segment];
    }
    return { exists: true, value: current };
  };
  const includesExpectedItems = (current, expected) => (
    Array.isArray(current)
    && Array.isArray(expected)
    && expected.every(item => current.some(candidate => JSON.stringify(candidate) === JSON.stringify(item)))
  );
  const toolOverrides = asList(options.toolOverrides).map(override => {
    const currentTool = currentToolsById.get(String(override?.id || '').trim());
    if (!currentTool && retiredMergedToolIds.has(String(override?.id || '').trim())) return null;
    const patches = asList(override?.patches).filter(patch => {
      const current = readObjectPath(currentTool, patch?.path);
      const rootCollectionPatch = ['commands', 'references'].includes(String(patch?.path || ''));
      const applied = current.exists && (
        JSON.stringify(current.value) === JSON.stringify(patch?.value)
        || (rootCollectionPatch && includesExpectedItems(current.value, patch?.value))
      );
      return !applied;
    });
    return patches.length ? { ...override, patches } : null;
  }).filter(Boolean);
  const toolMerges = asList(options.toolMerges).filter(merge => {
    const sourceId = String(merge?.sourceToolId || '').trim();
    const targetId = String(merge?.targetToolId || '').trim();
    return currentToolsById.has(sourceId) || !currentToolsById.has(targetId);
  });
  const overrideDocuments = asList(options.overrideDocuments).map(document => {
    const entries = asList(document?.entries).filter(entry => (
      !isRetiredManagedSource(entry?.id) && !isAlreadyAppliedOverride(entry, document?.contentStandard)
    )).map(entry => {
      const current = currentPayloadsById.get(String(entry?.id || '').trim());
      return current ? { ...entry, attackChain: expectedAttackChain(entry, current) } : entry;
    });
    if (!Array.isArray(document?.sourceIds)) {
      if (!document?.sourcePrefix) return { ...document, entries };
      const activeEntryIds = entries
        .map(entry => String(entry?.id || '').trim())
        .filter(id => currentPayloadIds.has(id));
      const allEntriesHandled = asList(document?.entries).length > 0
        && asList(document?.entries).every(entry => (
          isRetiredManagedSource(entry?.id) || alreadyAppliedOverrideIds.has(String(entry?.id || '').trim())
        ));
      if (!activeEntryIds.length && allEntriesHandled) {
        return null;
      }
      const withoutPrefix = { ...document };
      delete withoutPrefix.sourcePrefix;
      return { ...withoutPrefix, sourceIds: activeEntryIds, entries };
    }
    if (!document.sourceIds.length) return { ...document, entries };
    const sourceIds = document.sourceIds.filter(id => (
      !isRetiredManagedSource(id) && !alreadyAppliedOverrideIds.has(String(id || '').trim())
    ));
    if (!sourceIds.length && document.sourceIds.every(id => (
      isRetiredManagedSource(id) || alreadyAppliedOverrideIds.has(String(id || '').trim())
    ))) return null;
    return {
      ...document,
      sourceIds,
      entries,
    };
  }).filter(Boolean);
  const payloadCommandOverrides = {
    ...(options.payloadCommandOverrides || { schemaVersion: 1 }),
    entries: asList(options.payloadCommandOverrides?.entries)
      .filter(entry => !isRetiredManagedSource(entry?.id))
      .map(entry => {
        const current = currentPayloadsById.get(String(entry?.id || '').trim());
        const patches = asList(entry?.patches).filter(patch => (
          String(current?.[patch?.area]?.[patch?.index]?.command || '') !== String(patch?.command || '')
        ));
        return patches.length ? { ...entry, patches } : null;
      })
      .filter(Boolean),
  };
  return {
    ...options,
    overrideDocuments,
    alreadyAppliedOverrideIds: [...alreadyAppliedOverrideIds].sort(),
    payloadCommandOverrides,
    toolOverrides,
    toolMerges,
  };
};

const readRows = (database, table, column, where = '') => database
  .prepare(`SELECT ${column} FROM ${table} ${where} ORDER BY sort_order, id`)
  .all()
  .map(row => JSON.parse(row[column]));

export const loadCurationSnapshot = file => {
  const database = new DatabaseSync(resolve(file), { readOnly: true });
  try {
    return {
      payloads: readRows(database, 'payloads', 'data'),
      tools: readRows(database, 'tools', 'data'),
      navigation: readRows(database, 'navigation_nodes', 'tree', "WHERE kind = 'payloads'"),
      toolNavigation: readRows(database, 'navigation_nodes', 'tree', "WHERE kind = 'tools'"),
    };
  } finally {
    database.close();
  }
};

const countCollectionChanges = (before, after) => {
  const beforeById = new Map(asList(before).map(item => [item.id, item]));
  const afterById = new Map(asList(after).map(item => [item.id, item]));
  return {
    added: [...afterById.keys()].filter(id => !beforeById.has(id)).length,
    removed: [...beforeById.keys()].filter(id => !afterById.has(id)).length,
    updated: [...afterById].filter(([id, item]) => (
      beforeById.has(id) && JSON.stringify(beforeById.get(id)) !== JSON.stringify(item)
    )).length,
  };
};

const summarizeChanges = (before, after) => ({
  payloads: countCollectionChanges(before.payloads, after.payloads),
  tools: countCollectionChanges(before.tools, after.tools),
  navigation: countCollectionChanges(before.navigation, after.navigation),
  toolNavigation: countCollectionChanges(before.toolNavigation, after.toolNavigation),
});

const verifyIntegrity = file => {
  const database = new DatabaseSync(resolve(file), { readOnly: true });
  try {
    const rows = database.prepare('PRAGMA integrity_check').all();
    if (rows.length !== 1 || Object.values(rows[0])[0] !== 'ok') {
      throw new Error(`SQLite integrity check failed for ${resolve(file)}`);
    }
  } finally {
    database.close();
  }
};

const createBackup = async (file, backupDir) => {
  const absoluteFile = resolve(file);
  const absoluteBackupDir = resolve(backupDir);
  await mkdir(absoluteBackupDir, { recursive: true });
  const fileName = `${basename(absoluteFile, '.sqlite')}-before-payload-curation-${timestamp()}-${randomUUID().slice(0, 8)}.sqlite`;
  const destination = join(absoluteBackupDir, fileName);
  const database = new DatabaseSync(absoluteFile);
  let method = 'node:sqlite.backup';
  let pages = null;
  try {
    database.exec('PRAGMA busy_timeout = 5000;');
    if (typeof sqlite.backup === 'function') {
      pages = await sqlite.backup(database, destination);
    } else {
      const checkpoint = database.prepare('PRAGMA wal_checkpoint(FULL)').get();
      if (Number(checkpoint?.busy || 0) !== 0) throw new Error('Unable to checkpoint the SQLite WAL before backup.');
      database.prepare('VACUUM INTO ?').run(destination);
      method = 'checkpoint-vacuum-into';
    }
  } catch (error) {
    await rm(destination, { force: true }).catch(() => {});
    throw error;
  } finally {
    database.close();
  }
  verifyIntegrity(destination);
  const details = await stat(destination);
  return {
    fileName,
    path: destination,
    method,
    pages,
    sizeBytes: details.size,
    integrity: 'ok',
  };
};

const synchronizeItems = (database, table, column, items) => {
  const desired = asList(items);
  const desiredIds = new Set(desired.map(item => item.id));
  const deleteStatement = database.prepare(`DELETE FROM ${table} WHERE id = ?`);
  for (const row of database.prepare(`SELECT id FROM ${table}`).all()) {
    if (!desiredIds.has(row.id)) deleteStatement.run(row.id);
  }
  const now = new Date().toISOString();
  const upsert = database.prepare(`
    INSERT INTO ${table} (id, ${column}, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      ${column} = excluded.${column},
      sort_order = excluded.sort_order,
      updated_at = excluded.updated_at
  `);
  desired.forEach((item, index) => upsert.run(item.id, JSON.stringify(item), index, now, now));
};

const synchronizeNavigation = (database, kind, items) => {
  const desired = asList(items);
  const desiredIds = new Set(desired.map(item => item.id));
  const deleteStatement = database.prepare('DELETE FROM navigation_nodes WHERE id = ? AND kind = ?');
  for (const row of database.prepare('SELECT id FROM navigation_nodes WHERE kind = ?').all(kind)) {
    if (!desiredIds.has(row.id)) deleteStatement.run(row.id, kind);
  }
  const now = new Date().toISOString();
  const upsert = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      tree = excluded.tree,
      kind = excluded.kind,
      sort_order = excluded.sort_order,
      updated_at = excluded.updated_at
  `);
  desired.forEach((item, index) => upsert.run(item.id, JSON.stringify(item), kind, index, now, now));
};

const writeSnapshot = (file, snapshot) => {
  const database = new DatabaseSync(resolve(file));
  try {
    database.exec('PRAGMA busy_timeout = 5000; BEGIN IMMEDIATE;');
    synchronizeItems(database, 'payloads', 'data', snapshot.payloads);
    synchronizeItems(database, 'tools', 'data', snapshot.tools);
    synchronizeNavigation(database, 'payloads', snapshot.navigation);
    synchronizeNavigation(database, 'tools', snapshot.toolNavigation);
    database.exec('COMMIT;');
  } catch (error) {
    try {
      database.exec('ROLLBACK;');
    } catch {
      // Preserve the original mutation error.
    }
    throw error;
  } finally {
    database.close();
  }
};

const snapshotsEqual = (left, right) => JSON.stringify(left) === JSON.stringify(right);

export const curateDatabase = async (file, options = {}) => {
  const absoluteFile = resolve(file);
  const before = loadCurationSnapshot(absoluteFile);
  const curationOptions = prepareCurationOptions(options, before.payloads, before.tools);
  const result = curatePayloadLibrary(before, curationOptions);
  const planned = result.snapshot;
  const changes = summarizeChanges(before, planned);
  if (!options.apply) {
    return {
      applied: false,
      file: absoluteFile,
      changes,
      ledger: result.ledger,
      snapshot: clone(planned),
    };
  }

  const backupDir = options.backupDir || join(resolve(absoluteFile, '..'), 'backups');
  const backup = await createBackup(absoluteFile, backupDir);
  writeSnapshot(absoluteFile, planned);
  verifyIntegrity(absoluteFile);
  const written = loadCurationSnapshot(absoluteFile);
  if (!snapshotsEqual(written, planned)) {
    throw new Error(`Payload curation verification mismatch. Backup: ${backup.path}`);
  }
  return {
    applied: true,
    file: absoluteFile,
    backup,
    changes,
    ledger: result.ledger,
    snapshot: clone(written),
  };
};

const editorialBlockingKeys = [
  'genericAttackChains',
  'missingTutorials',
  'shallowTutorials',
  'localizedEnglish',
  'collectionResidue',
  'mixedCollections',
  'toolLikeCandidates',
  'proseInCommands',
  'danglingAttackChainPayloads',
  'reusedAttackChains',
  'genericSyntaxExplanations',
  'brokenEnglish',
  'invalidRespPayloads',
];

const toolEditorialBlockingKeys = [
  'missingReferences',
  'shortDescriptions',
  'shortCommandDescriptions',
  'localizedEnglish',
  'corruptText',
  'duplicateCommandsWithinTool',
  'commentOnlyCommands',
  'proseInCommands',
];

const qualityGateFor = (formal, editorial, toolEditorial) => {
  const editorialBlocking = Object.fromEntries(editorialBlockingKeys.map(key => [
    key,
    Number(editorial?.summary?.issueCounts?.[key] || 0),
  ]));
  const reportingBlocking = {
    englishContainsHan: Number(formal?.reporting?.englishContainsHan?.count || 0),
    duplicateNames: Number(formal?.reporting?.duplicateNames?.count || 0),
    categoryTreeMismatch: Number(formal?.reporting?.categoryTreeMismatch?.count || 0),
    actionableOrphans: Number(formal?.reporting?.orphanPayloads?.actionable || 0),
  };
  const toolEditorialBlocking = Object.fromEntries(toolEditorialBlockingKeys.map(key => [
    key,
    Number(toolEditorial?.summary?.issueCounts?.[key] || 0),
  ]));
  const blockingErrors = Number(formal?.summary?.blockingErrors || 0);
  return {
    pass: blockingErrors === 0
      && Object.values(editorialBlocking).every(count => count === 0)
      && Object.values(toolEditorialBlocking).every(count => count === 0)
      && Object.values(reportingBlocking).every(count => count === 0),
    blockingErrors,
    editorialBlocking,
    toolEditorialBlocking,
    reportingBlocking,
    mixedCollectionCandidates: Number(editorial?.summary?.issueCounts?.mixedCollections || 0),
    crossToolDuplicateCommands: Number(toolEditorial?.summary?.issueCounts?.duplicateCommandsAcrossTools || 0),
  };
};

export const parseCurationCli = argv => {
  const options = {
    apply: false,
    json: false,
    requireReady: false,
    seedOnly: false,
    runtimeFile: defaultRuntimeFile,
    seedFile: defaultSeedFile,
    reviewDir: defaultReviewDir,
    backupDir: defaultBackupDir,
    ledgerFile: defaultLedgerFile,
  };
  const pathArguments = new Map([
    ['--db', 'runtimeFile'],
    ['--database', 'runtimeFile'],
    ['--seed', 'seedFile'],
    ['--review-dir', 'reviewDir'],
    ['--backup-dir', 'backupDir'],
    ['--ledger', 'ledgerFile'],
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--apply') options.apply = true;
    else if (argument === '--json') options.json = true;
    else if (argument === '--require-ready') options.requireReady = true;
    else if (argument === '--seed-only') options.seedOnly = true;
    else if (pathArguments.has(argument)) {
      const value = argv[index + 1];
      if (!value) throw new Error(`${argument} requires a path`);
      options[pathArguments.get(argument)] = resolve(value);
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  if (options.seedOnly && options.apply) {
    throw new Error('--seed-only cannot be combined with --apply');
  }
  return options;
};

const compactCurationResult = result => ({
  applied: result.applied,
  file: result.file,
  backup: result.backup || null,
  changes: result.changes,
  ledgerEntries: result.ledger.length,
});

const runCli = async argv => {
  const options = parseCurationCli(argv);
  const sourceFile = options.seedOnly ? options.seedFile : options.runtimeFile;
  const sourceLabel = options.seedOnly ? 'Seed' : 'Runtime';
  if (!existsSync(sourceFile)) throw new Error(`${sourceLabel} database not found: ${sourceFile}`);
  const source = loadCurationSnapshot(sourceFile);
  const configuration = await loadReviewConfiguration(options.reviewDir);
  const curationOptions = prepareCurationOptions(configuration, source.payloads, source.tools);
  const review = auditReviewConfiguration(source.payloads, curationOptions);
  const dryRun = await curateDatabase(sourceFile, {
    ...configuration,
    backupDir: options.backupDir,
  });
  const formal = auditSnapshot(dryRun.snapshot, { source: `${sourceFile} (curation plan)` });
  const editorial = auditPayloadEditorialQuality(dryRun.snapshot.payloads, dryRun.snapshot.tools);
  const toolEditorial = auditToolEditorialQuality(dryRun.snapshot.tools);
  const qualityGate = qualityGateFor(formal, editorial, toolEditorial);
  const canApply = review.complete && qualityGate.pass && !hasBlockingErrors(formal);

  let applied = null;
  let seedRefresh = null;
  if (options.apply) {
    if (!canApply) {
      throw new Error(
        `Curation apply blocked: ${review.coverage.missingReviewIds.length} unreviewed, `
        + `${review.invalidReviewItems} invalid review items, ${qualityGate.blockingErrors} blocking errors.`,
      );
    }
    applied = await curateDatabase(options.runtimeFile, {
      ...configuration,
      backupDir: options.backupDir,
      apply: true,
    });
    seedRefresh = await refreshSeedFromRuntime(options.runtimeFile, options.seedFile, {
      backupDir: options.backupDir,
    });
    await mkdir(dirname(options.ledgerFile), { recursive: true });
    await writeFile(options.ledgerFile, `${JSON.stringify({
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      sourceDatabase: relative(projectRoot, options.runtimeFile).replaceAll('\\', '/'),
      reviewSources: configuration.sourceFiles,
      entries: applied.ledger,
    }, null, 2)}\n`, 'utf8');
  }

  const output = {
    version: 1,
    mode: options.apply ? 'apply' : 'dry-run',
    canApply,
    review,
    qualityGate,
    toolEditorial,
    planned: compactCurationResult(dryRun),
    applied: applied ? compactCurationResult(applied) : null,
    seedRefresh: seedRefresh ? {
      seed: seedRefresh.seed,
      backup: seedRefresh.backup,
      blockingErrors: seedRefresh.report.summary.blockingErrors,
    } : null,
    ledgerFile: options.apply ? options.ledgerFile : null,
  };
  if (options.json) console.log(JSON.stringify(output, null, 2));
  else {
    console.log(`Payload curation ${output.mode}: ${canApply ? 'ready' : 'blocked'}`);
    console.log(`Reviewed: ${source.payloads.length - review.coverage.missingReviewIds.length}/${source.payloads.length}`);
    console.log(`Invalid review items: ${review.invalidReviewItems}`);
    console.log(`Quality gate: ${JSON.stringify(qualityGate)}`);
    console.log(`Planned changes: ${JSON.stringify(dryRun.changes)}`);
    if (review.coverage.missingReviewIds.length) {
      console.log(`Next unreviewed IDs: ${review.coverage.missingReviewIds.slice(0, 20).join(', ')}`);
    }
    if (applied) console.log(`Runtime backup: ${applied.backup.path}`);
    if (seedRefresh) console.log(`Seed backup: ${seedRefresh.backup?.path || 'not required'}`);
  }
  if (options.requireReady && !canApply) {
    throw new Error(
      `Curation readiness check failed: ${review.coverage.missingReviewIds.length} unreviewed, `
      + `${review.invalidReviewItems} invalid review items, ${qualityGate.blockingErrors} blocking errors.`,
    );
  }
  return output;
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  try {
    await runCli(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack : error);
    process.exitCode = 1;
  }
}
