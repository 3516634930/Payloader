// 导入/导出/重置域（自 data-store.mjs 拆出）：reset 影响与备份、导入包归一化与执行。
// db 句柄与 backupDir/钩子经参数注入，串行队列（enqueueMutation）与缓存失效由引擎壳负责。

import { mkdir, rm, stat } from 'node:fs/promises';
import { isAbsolute, join, relative } from 'node:path';
import * as sqlite from 'node:sqlite';
import {
  insertNavigation,
  insertNavigationKind,
  insertPayloads,
  insertTools,
  isSystemToolId,
  isXeyeEnabled,
  makeSeedArtifactId,
  prepareContentItemForInsert,
  pruneSystemNavigationItem,
  readJsonMetadata,
  rowsToItems,
  runTransaction,
  upsertItems,
  writeMetadata,
  xeyeDisabledMetadataKey,
} from './migrations.mjs';
import {
  defaultSettings,
  sanitizeNavItem,
  sanitizePayload,
  sanitizeSettings,
  sanitizeTool,
} from './sanitize.mjs';
import { isObject, normalizeList } from './text-quality.mjs';
import { importArrayLimits, importSummary, maxImportNavigationDepth, maxImportNavigationNodes } from './import-template.mjs';

const now = () => new Date().toISOString();
const json = value => JSON.stringify(value ?? null);
const { DatabaseSync } = sqlite;

const resetTargets = new Set(['all', 'payloads', 'tools', 'navigation', 'settings']);
const resetScopeKeys = ['payloads', 'tools', 'navigation', 'toolNavigation', 'settings'];

const validateResetTarget = value => {
  if (typeof value !== 'string' || !resetTargets.has(value)) {
    const error = new Error('Invalid reset target.');
    error.status = 400;
    throw error;
  }
  return value;
};

const affectedResetScopes = target => {
  if (target === 'all') return [...resetScopeKeys];
  if (target === 'navigation') return ['navigation', 'toolNavigation'];
  return [target];
};

const readResetState = database => ({
  payloads: rowsToItems(database.prepare('SELECT data FROM payloads ORDER BY sort_order, id').all()),
  tools: rowsToItems(database.prepare('SELECT data FROM tools ORDER BY sort_order, id').all())
    .filter(item => !isSystemToolId(item.id)),
  navigation: rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE kind = 'payloads' ORDER BY sort_order, id").all()),
  toolNavigation: rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE kind = 'tools' ORDER BY sort_order, id").all())
    .map(pruneSystemNavigationItem)
    .filter(Boolean),
  settings: sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings)),
  xeyeEnabled: isXeyeEnabled(database),
});

const makeSeedResetState = defaults => ({
  payloads: normalizeList(defaults.payloads).map(item => prepareContentItemForInsert(item, sanitizePayload, true)),
  tools: normalizeList(defaults.tools)
    .map(item => prepareContentItemForInsert(item, sanitizeTool, true))
    .filter(item => !isSystemToolId(item.id)),
  navigation: normalizeList(defaults.navigation).map(item => prepareContentItemForInsert(item, sanitizeNavItem, true)),
  toolNavigation: normalizeList(defaults.toolNavigation)
    .map(item => prepareContentItemForInsert(item, sanitizeNavItem, true))
    .map(pruneSystemNavigationItem)
    .filter(Boolean),
  settings: sanitizeSettings(defaultSettings),
  xeyeEnabled: true,
});

const countResetState = state => ({
  payloads: state.payloads.length,
  tools: state.tools.length,
  navigation: state.navigation.length,
  toolNavigation: state.toolNavigation.length,
  settings: 1,
});

const diffResetItems = (beforeItems, seedItems, affected) => {
  const beforeById = new Map(beforeItems.map(item => [String(item.id || ''), json(item)]));
  const seedById = new Map(seedItems.map(item => [String(item.id || ''), json(item)]));
  let added = 0;
  let removed = 0;
  let changed = 0;
  let unchanged = 0;

  for (const [id, value] of beforeById) {
    if (!seedById.has(id)) removed += 1;
    else if (seedById.get(id) === value) unchanged += 1;
    else changed += 1;
  }
  for (const id of seedById.keys()) {
    if (!beforeById.has(id)) added += 1;
  }
  return { affected, added, removed, changed, unchanged };
};

const createResetImpact = (target, beforeState, seedState) => {
  const affected = affectedResetScopes(target);
  const affectedSet = new Set(affected);
  const before = countResetState(beforeState);
  const seed = countResetState(seedState);
  const delta = Object.fromEntries(resetScopeKeys.map(key => [
    key,
    affectedSet.has(key) ? seed[key] - before[key] : 0,
  ]));
  return {
    target,
    affected,
    before,
    seed,
    delta,
    changes: {
      payloads: diffResetItems(beforeState.payloads, seedState.payloads, affectedSet.has('payloads')),
      tools: diffResetItems(beforeState.tools, seedState.tools, affectedSet.has('tools')),
      navigation: diffResetItems(beforeState.navigation, seedState.navigation, affectedSet.has('navigation')),
      toolNavigation: diffResetItems(beforeState.toolNavigation, seedState.toolNavigation, affectedSet.has('toolNavigation')),
      settings: {
        affected: affectedSet.has('settings'),
        changed: json(beforeState.settings) !== json(seedState.settings),
      },
    },
    integrations: {
      xeye: {
        affected: affectedSet.has('tools'),
        before: beforeState.xeyeEnabled,
        seed: seedState.xeyeEnabled,
        changed: affectedSet.has('tools') && beforeState.xeyeEnabled !== seedState.xeyeEnabled,
      },
    },
  };
};

const makeResetBackupFileName = target => {
  const timestamp = now().replace(/[^0-9A-Za-z-]/g, '-');
  return `payloader-before-reset-${target}-${timestamp}-${makeSeedArtifactId()}.sqlite`;
};

const assertBackupPath = (path, backupDir) => {
  const pathFromBackupDir = relative(backupDir, path);
  const firstSegment = pathFromBackupDir.split(/[\\/]/, 1)[0];
  if (!pathFromBackupDir || isAbsolute(pathFromBackupDir) || firstSegment === '..') {
    throw new Error('Unable to create reset backup outside the backup directory.');
  }
};

const verifyBackupIntegrity = path => {
  const backupDatabase = new DatabaseSync(path, { readOnly: true });
  try {
    const results = backupDatabase.prepare('PRAGMA integrity_check').all();
    const valid = results.length === 1 && Object.values(results[0])[0] === 'ok';
    if (!valid) throw new Error('Reset backup failed SQLite integrity validation.');
  } finally {
    backupDatabase.close();
  }
};

const createResetBackup = async ({ database, target, backupDir, beforeResetBackup }) => {
  await mkdir(backupDir, { recursive: true });
  const fileName = makeResetBackupFileName(target);
  const path = join(backupDir, fileName);
  assertBackupPath(path, backupDir);
  const createdAt = now();
  let method;
  let pages = null;

  try {
    if (typeof beforeResetBackup === 'function') {
      await beforeResetBackup({ target });
    }
    if (typeof sqlite.backup === 'function') {
      pages = await sqlite.backup(database, path);
      method = 'node:sqlite.backup';
    } else {
      const checkpoint = database.prepare('PRAGMA wal_checkpoint(FULL)').get();
      if (Number(checkpoint?.busy || 0) !== 0) {
        throw new Error('Unable to checkpoint the SQLite WAL before reset backup.');
      }
      database.prepare('VACUUM INTO ?').run(path);
      method = 'checkpoint-vacuum-into';
    }
    verifyBackupIntegrity(path);
    const file = await stat(path);
    return {
      fileName,
      path: `backups/${fileName}`,
      createdAt,
      sizeBytes: file.size,
      pages,
      method,
      integrity: 'ok',
    };
  } catch (error) {
    await rm(path, { force: true }).catch(() => {});
    throw error;
  }
};

const executeReset = ({ database, target, seedState }) => {
  runTransaction(database, () => {
    const timestamp = now();
    if (target === 'all' || target === 'payloads') {
      database.prepare('DELETE FROM payloads').run();
      insertPayloads(database, seedState.payloads, { trusted: true });
    }
    if (target === 'all' || target === 'tools') {
      database.prepare('DELETE FROM tools').run();
      insertTools(database, seedState.tools, { trusted: true });
      writeMetadata(database, xeyeDisabledMetadataKey, '0');
    }
    if (target === 'all' || target === 'navigation') {
      database.prepare('DELETE FROM navigation_nodes').run();
      insertNavigation(database, seedState.navigation, seedState.toolNavigation, { trusted: true });
    }
    if (target === 'all' || target === 'settings') {
      writeMetadata(database, 'settings', json(seedState.settings));
    }
    writeMetadata(database, `reset_${target}_at`, timestamp);
  });
};

const uniqueItems = (items, label, warnings) => {
  const usedIds = new Set();
  return items.map((item, index) => {
    const normalized = { ...item };
    if (usedIds.has(normalized.id)) {
      const originalId = normalized.id;
      normalized.id = `${normalized.id}-${index}`;
      warnings.push(`${label} 存在重复 ID「${originalId}」，第 ${index + 1} 条已自动改为「${normalized.id}」。`);
    }
    usedIds.add(normalized.id);
    return normalized;
  });
};

const readImportArray = (candidate, key, label) => {
  if (!Object.prototype.hasOwnProperty.call(candidate, key)) {
    return { included: false, items: [] };
  }
  if (!Array.isArray(candidate[key])) {
    throw new Error(`${label} 必须是数组。`);
  }
  const maxItems = importArrayLimits[key];
  if (maxItems && candidate[key].length > maxItems) {
    throw new Error(`${label} 一次最多导入 ${maxItems} 条，请拆分文件后分批导入。`);
  }
  return { included: true, items: candidate[key] };
};

const assertNavigationImportShape = (items, label) => {
  let count = 0;
  const stack = normalizeList(items).map(item => ({ item, depth: 1 }));
  while (stack.length) {
    const { item, depth } = stack.pop();
    if (!isObject(item)) continue;
    count += 1;
    if (count > maxImportNavigationNodes) {
      throw new Error(`${label} 导航节点一次最多导入 ${maxImportNavigationNodes} 个，请拆分文件后分批导入。`);
    }
    if (depth > maxImportNavigationDepth) {
      throw new Error(`${label} 导航层级不能超过 ${maxImportNavigationDepth} 层。`);
    }
    for (const child of normalizeList(item.children)) {
      stack.push({ item: child, depth: depth + 1 });
    }
  }
};

const normalizeImportPackage = value => {
  if (!isObject(value)) {
    throw new Error('导入文件必须是 JSON 对象。');
  }
  const warnings = [];
  const format = typeof value.format === 'string' ? value.format.trim() : '';
  if (format && format !== 'payloader.import.v1') {
    warnings.push(`模板标识为「${format}」，当前按 payloader.import.v1 兼容导入。`);
  }
  const payloadSource = readImportArray(value, 'payloads', 'payloads');
  const toolSource = readImportArray(value, 'tools', 'tools');
  const navigationSource = readImportArray(value, 'navigation', 'navigation');
  const toolNavigationSource = readImportArray(value, 'toolNavigation', 'toolNavigation');
  const included = {
    payloads: payloadSource.included,
    tools: toolSource.included,
    navigation: navigationSource.included,
    toolNavigation: toolNavigationSource.included,
  };
  if (Object.prototype.hasOwnProperty.call(value, 'settings')) {
    warnings.push('平台信息不参与导入，settings 已自动忽略。');
  }
  if (!Object.values(included).some(Boolean)) {
    throw new Error('导入文件没有包含可导入的数据，请至少提供 payloads、tools、navigation 或 toolNavigation。');
  }
  assertNavigationImportShape(navigationSource.items, 'navigation');
  assertNavigationImportShape(toolNavigationSource.items, 'toolNavigation');
  const payloads = uniqueItems(payloadSource.items.map(sanitizePayload), 'payloads', warnings);
  const tools = uniqueItems(toolSource.items.map(sanitizeTool), 'tools', warnings)
    .filter(item => {
      if (!isSystemToolId(item.id)) return true;
      warnings.push('系统内置 XSS 平台不可通过导入覆盖，已自动忽略。');
      return false;
    });
  const navigation = uniqueItems(navigationSource.items.map(sanitizeNavItem), 'navigation', warnings)
    .map(pruneSystemNavigationItem)
    .filter(Boolean);
  const toolNavigation = uniqueItems(toolNavigationSource.items.map(sanitizeNavItem), 'toolNavigation', warnings)
    .map(pruneSystemNavigationItem)
    .filter(Boolean);
  return {
    format: format || 'payloader.import.v1',
    included,
    payloads,
    tools,
    navigation,
    toolNavigation,
    warnings,
  };
};

const demoPlaceholderValues = new Set([
  'echo todo',
  'new payload',
  '新 payload',
  'new tool',
  '新工具',
  'new command',
  '新命令',
  'uncategorized',
  '未分类',
]);

const findDemoPlaceholder = value => {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return demoPlaceholderValues.has(normalized) ? value.trim() : null;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const match = findDemoPlaceholder(item);
      if (match) return match;
    }
    return null;
  }
  if (isObject(value)) {
    for (const item of Object.values(value)) {
      const match = findDemoPlaceholder(item);
      if (match) return match;
    }
  }
  return null;
};

const assertNoDemoPlaceholderContent = value => {
  const placeholder = findDemoPlaceholder(value);
  if (!placeholder) return;
  const error = new Error(`检测到未完成的占位内容：${placeholder}`);
  error.status = 400;
  throw error;
};

const executeImport = ({ database, normalized, mode }) => {
  runTransaction(database, () => {
    if (mode === 'replace') {
      if (normalized.included.payloads) {
        database.prepare('DELETE FROM payloads').run();
        insertPayloads(database, normalized.payloads);
      }
      if (normalized.included.tools) {
        database.prepare('DELETE FROM tools').run();
        insertTools(database, normalized.tools);
      }
      if (normalized.included.navigation) {
        database.prepare("DELETE FROM navigation_nodes WHERE kind = 'payloads'").run();
        insertNavigationKind(database, normalized.navigation, 'payloads');
      }
      if (normalized.included.toolNavigation) {
        database.prepare("DELETE FROM navigation_nodes WHERE kind = 'tools'").run();
        insertNavigationKind(database, normalized.toolNavigation, 'tools');
      }
    } else {
      if (normalized.included.payloads) upsertItems(database, 'payloads', normalized.payloads);
      if (normalized.included.tools) upsertItems(database, 'tools', normalized.tools);
      if (normalized.included.navigation) upsertItems(database, 'navigation', normalized.navigation, { kind: 'payloads' });
      if (normalized.included.toolNavigation) upsertItems(database, 'navigation', normalized.toolNavigation, { kind: 'tools' });
    }
    writeMetadata(database, 'last_import_at', now());
    writeMetadata(database, 'last_import_mode', mode);
  });
};

const previewImportPackage = value => {
  const normalized = normalizeImportPackage(value);
  return {
    format: normalized.format,
    summary: importSummary(normalized),
    warnings: normalized.warnings,
  };
};

export {
  previewImportPackage,
  assertBackupPath,
  assertNavigationImportShape,
  assertNoDemoPlaceholderContent,
  affectedResetScopes,
  countResetState,
  createResetBackup,
  createResetImpact,
  diffResetItems,
  executeImport,
  executeReset,
  findDemoPlaceholder,
  makeResetBackupFileName,
  makeSeedResetState,
  normalizeImportPackage,
  readImportArray,
  readResetState,
  resetScopeKeys,
  resetTargets,
  uniqueItems,
  validateResetTarget,
  verifyBackupIntegrity,
};
