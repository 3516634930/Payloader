// 内容治理与迁移层（自 data-store.mjs 拆出）：可见性常量、system 保护、导航剪枝、
// 插入/upsert 原语（upsertItems 单实现，冲突保留 sort_order；navigation 冲突更新 kind）、
// 种子读写（file 参数化，不读 PAYLOADER_DATA_DIR）、数据迁移（mergeDefaultItems 归一四处补默认循环）。
// 依赖注入：applyDataMigrations/seedIfNeeded 经 { loadDefaults } 注入种子加载，db 句柄经参数传入。

import { mkdir, rename } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  applyVisibleChineseDisplayOverrides,
  isObject,
  looksLikeSentenceTitle,
  normalizeList,
  normalizeVisibleCommandDescription,
  normalizeVisibleCommandTitle,
  scrubDestructivePayloadCommands,
  scrubLowQualityEnglishContent,
  scrubRetiredEdrContent,
  textLooksNonProfessionalZh,
  textValue,
} from './text-quality.mjs';
import {
  cloneValue,
  defaultSettings,
  protectedExternalUrl,
  protectedXssToolId,
  sanitizeNavItem,
  sanitizePayload,
  sanitizeSettings,
  sanitizeStoredPublicPayload,
  sanitizeTool,
  systemToolIds,
} from './sanitize.mjs';

const now = () => new Date().toISOString();
const json = value => JSON.stringify(value ?? null);
const parseJson = value => {
  if (typeof value !== 'string' || value.length === 0) return null;
  return JSON.parse(value);
};

const defaultSeedSchemaVersion = '1';
const defaultSeedContentKind = 'curated-defaults';
const makeSeedArtifactId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

const protectedXssNavId = 'system-xss-platform';

const protectedXssPlatformTool = Object.freeze({
  id: protectedXssToolId,
  name: { zh: 'XSS 平台', en: 'XSS Platform' },
  description: { zh: 'Payloader 默认提供的 Xeye 平台入口。', en: 'Default Xeye platform entry provided by Payloader.' },
  category: { zh: '平台跳转', en: 'Platform Links' },
  commands: [],
  externalUrl: protectedExternalUrl,
  systemLocked: true,
  references: [protectedExternalUrl],
});
const protectedXssPlatformNavigation = Object.freeze({
  id: protectedXssNavId,
  name: { zh: 'XSS 平台', en: 'XSS Platform' },
  toolId: protectedXssToolId,
});
const systemNavigationNodeIds = new Set([protectedXssNavId]);

const xeyeDisabledMetadataKey = 'xeye_platform_disabled';
const isXeyeEnabled = database => readMetadata(database, xeyeDisabledMetadataKey) !== '1';

const rowsToItems = rows => rows.map(row => parseJson(row.data ?? row.tree)).filter(Boolean);

const initializeContentDatabase = database => {
  database.exec(`
    CREATE TABLE IF NOT EXISTS metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS payloads (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tools (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS navigation_nodes (
      id TEXT PRIMARY KEY,
      tree TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('payloads', 'tools')),
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
};

const tableForResource = resource => {
  if (resource === 'payloads') return { table: 'payloads', dataColumn: 'data', sanitizer: sanitizePayload };
  if (resource === 'tools') return { table: 'tools', dataColumn: 'data', sanitizer: sanitizeTool };
  throw new Error(`Unsupported resource: ${resource}`);
};

const readMetadata = (database, key) => (
  database.prepare('SELECT value FROM metadata WHERE key = ?').get(key)?.value
);

const writeMetadata = (database, key, value) => {
  database.prepare(`
    INSERT INTO metadata (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, value);
};

const readJsonMetadata = (database, key, fallback) => {
  const value = readMetadata(database, key);
  if (!value) return fallback;
  try {
    return parseJson(value) ?? fallback;
  } catch {
    return fallback;
  }
};

const runTransaction = (database, work) => {
  database.exec('BEGIN');
  try {
    const result = work();
    database.exec('COMMIT');
    return result;
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
};

const ensureSeedDatabaseMetadata = (database, file) => {
  const schemaVersion = readMetadata(database, 'seed_schema_version');
  const contentKind = readMetadata(database, 'content_kind');
  if (schemaVersion !== defaultSeedSchemaVersion || contentKind !== defaultSeedContentKind) {
    throw new Error(`Invalid default seed database metadata in ${file}`);
  }
};

const loadDefaultDataFromSeedDb = file => {
  if (!existsSync(file)) {
    throw new Error(`Default seed database not found: ${file}`);
  }
  const seedDatabase = new DatabaseSync(file, { readOnly: true });
  try {
    ensureSeedDatabaseMetadata(seedDatabase, file);
    return readContentDataFromOpenDatabase(seedDatabase);
  } finally {
    seedDatabase.close();
  }
};

const readContentDataFromOpenDatabase = database => ({
  payloads: rowsToItems(database.prepare('SELECT data FROM payloads WHERE enabled = 1 ORDER BY sort_order, id').all()),
  tools: rowsToItems(database.prepare('SELECT data FROM tools WHERE enabled = 1 ORDER BY sort_order, id').all()),
  navigation: rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'payloads' ORDER BY sort_order, id").all()),
  toolNavigation: rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'tools' ORDER BY sort_order, id").all()),
});

const loadContentDataFromDatabase = file => {
  if (!existsSync(file)) {
    throw new Error(`Content database not found: ${file}`);
  }
  const sourceDatabase = new DatabaseSync(file, { readOnly: true });
  try {
    return readContentDataFromOpenDatabase(sourceDatabase);
  } finally {
    sourceDatabase.close();
  }
};

const isSystemToolId = id => systemToolIds.has(String(id || ''));
const isSystemNavigationNodeId = id => systemNavigationNodeIds.has(String(id || ''));

const navigationTouchesSystemItem = item => {
  if (!isObject(item)) return false;
  if (isSystemNavigationNodeId(item.id) || isSystemToolId(item.toolId)) return true;
  return normalizeList(item.children).some(navigationTouchesSystemItem);
};

const pruneSystemNavigationItem = item => {
  if (!isObject(item)) return null;
  if (isSystemNavigationNodeId(item.id) || isSystemToolId(item.toolId)) return null;
  const next = { ...item };
  const children = normalizeList(next.children).map(pruneSystemNavigationItem).filter(Boolean);
  if (children.length) next.children = children;
  else delete next.children;
  return next;
};

const protectedSystemTool = () => sanitizeTool(cloneValue(protectedXssPlatformTool));
const protectedSystemNavigationItem = () => sanitizeNavItem(cloneValue(protectedXssPlatformNavigation));

const withProtectedSystemTools = tools => [
  protectedSystemTool(),
  ...normalizeList(tools).filter(item => !isSystemToolId(item.id)),
];

const withProtectedSystemToolNavigation = navigation => [
  protectedSystemNavigationItem(),
  ...normalizeList(navigation).map(pruneSystemNavigationItem).filter(Boolean),
];

const excludedPublicPayloadRootIds = new Set(['evasion', 'intranet']);
const excludedPublicPayloadIds = new Set([
  'file-upload-bypass',
  'sqli-waf-bypass',
  'xss-filter-bypass',
  'xss-csp-bypass',
  'ssrf-bypass',
  'csrf-bypass',
  'csrf-token-bypass',
  'csrf-referer-bypass',
  'jwt-none-alg',
  'sqli-redis',
  'xss-beef',
]);
const excludedPublicPayloadNodeIds = new Set([
  'file-upload-bypass',
  'sqli-waf-bypass',
  'xss-filter-bypass',
  'xss-csp-bypass',
  'ssrf-bypass',
  'csrf-bypass',
  'csrf-token-bypass',
  'csrf-referer-bypass',
  'jwt-none-alg',
  'sqli-redis',
  'xss-beef',
]);
const excludedPublicPayloadCategories = new Set([
  '免杀与规避',
  'Evasion & Anti-Detection',
  'Evasion & AV Bypass',
]);
const showAllPublicPayloads = true;
const payloadVisibilityRules = {
  rootIds: excludedPublicPayloadRootIds,
  payloadIds: excludedPublicPayloadIds,
  nodeIds: excludedPublicPayloadNodeIds,
  categories: excludedPublicPayloadCategories,
};
const excludedPublicToolIds = new Set(['powershell-amsi']);
const payloadRefAliases = new Map([
  ['biz-price-tamper', 'biz-payment-tamper'],
  ['jwt-none-alg', 'jwt-none-attack'],
  ['jwt-none-algo', 'jwt-none-attack'],
  ['jwt-weak-secret', 'jwt-secret-bruteforce'],
  ['jwt-kid-injection', 'jwt-key-confusion'],
  ['jwt-jku-spoofing', 'jwt-jku-x5u-injection'],
]);

const modeOnlyPayloadMergeTargets = new Map([
  ['sqli-waf-bypass', ['sqli-mysql-basic', 'sqli-union', 'sqli-blind', 'sqli-time-based', 'sqli-error-based']],
  ['xss-filter-bypass', ['xss-reflected', 'xss-stored', 'xss-dom']],
  ['xss-csp-bypass', ['xss-reflected', 'xss-stored', 'xss-dom']],
  ['ssrf-bypass', ['ssrf-basic', 'ssrf-cloud-aws', 'ssrf-gopher', 'ssrf-redis', 'ssrf-dns-rebinding']],
  ['csrf-bypass', ['csrf-basic', 'csrf-json', 'csrf-samesite']],
  ['csrf-token-bypass', ['csrf-basic', 'csrf-json']],
  ['csrf-referer-bypass', ['csrf-basic', 'csrf-samesite']],
  ['redirect-bypass', ['redirect-basic']],
]);
const modeOnlyPayloadIds = new Set(modeOnlyPayloadMergeTargets.keys());

const legacyJwtPayloadIds = new Set([
  'jwt-none-alg',
  'jwt-none-algo',
  'jwt-weak-secret',
  'jwt-kid-injection',
  'jwt-jku-spoofing',
]);

const jwtCanonicalPayloadIds = [
  'jwt-security',
  'jwt-none-attack',
  'jwt-secret-bruteforce',
  'jwt-key-confusion',
  'jwt-jku-x5u-injection',
];

const i18n = (zh, en = zh) => ({ zh, en });

const publicNavigationNameOverrides = new Map([
  ['auth-bypass', i18n('认证校验缺陷', 'Authentication validation flaws')],
  ['cdn-bypass', i18n('源站暴露', 'Origin exposure')],
  ['redirect-bypass', i18n('重定向校验缺陷', 'Redirect validation flaws')],
  ['biz-flow-bypass-nav', i18n('流程越权', 'Workflow authorization flaws')],
  ['ws-auth-bypass-nav', i18n('WebSocket 授权缺陷', 'WebSocket authorization flaws')],
]);

const businessLogicPayloadIds = new Set();
const legacyNavigationPayloadRefMigrations = [
  { nodeId: 'jwt-none-algo-nav', from: 'jwt-none-algo', to: 'jwt-none-attack' },
  { nodeId: 'jwt-none-alg-nav', from: 'jwt-none-alg', to: 'jwt-none-attack' },
  { nodeId: 'jwt-weak-secret-nav', from: 'jwt-weak-secret', to: 'jwt-secret-bruteforce' },
  { nodeId: 'jwt-kid-injection-nav', from: 'jwt-kid-injection', to: 'jwt-key-confusion' },
  { nodeId: 'jwt-jku-spoofing-nav', from: 'jwt-jku-spoofing', to: 'jwt-jku-x5u-injection' },
];
const ensureBusinessLogicNavigation = navigation => ({ items: navigation, changed: false });
const ensureJwtSecurityNavigation = navigation => ({ items: navigation, changed: false });

const isPublicPayloadCandidate = payload => isObject(payload) && typeof payload.id === 'string' && payload.id.trim();

const filterToolNavigation = (items, toolIds) => normalizeList(items).flatMap(item => {
  const children = filterToolNavigation(item.children, toolIds);
  const hasValidTool = item.toolId && toolIds.has(item.toolId);
  if (item.toolId && !hasValidTool && !children.length) return [];
  const next = { ...item };
  if (children.length) next.children = children;
  else delete next.children;
  if (!hasValidTool) delete next.toolId;
  return next.toolId || next.children?.length ? [next] : [];
});

const filterStoredPayloadNavigation = (items, payloadIds, options = {}) => {
  const seen = options.seen || new Set();
  const depth = options.depth || 0;
  return normalizeList(items).flatMap(item => {
    const mappedPayloadId = item.payloadId ? (payloadRefAliases.get(item.payloadId) || item.payloadId) : '';
    if (shouldExcludePayloadNavigationItem(item, mappedPayloadId, depth)) return [];
    const children = filterStoredPayloadNavigation(item.children, payloadIds, { seen, depth: depth + 1 });
    const hasValidPayload = mappedPayloadId && payloadIds.has(mappedPayloadId) && !seen.has(mappedPayloadId);
    if (mappedPayloadId && !hasValidPayload && !children.length) return [];
    const next = { ...item };
    if (publicNavigationNameOverrides.has(next.id)) next.name = publicNavigationNameOverrides.get(next.id);
    if (children.length) next.children = children;
    else delete next.children;
    if (hasValidPayload) {
      next.payloadId = mappedPayloadId;
      seen.add(mappedPayloadId);
    } else {
      delete next.payloadId;
    }
    return next.payloadId || next.children?.length ? [next] : [];
  });
};

const prepareStoredPublicPayloadData = (payloads, navigation) => {
  const normalizedPayloads = normalizeList(payloads)
    .filter(payload => isObject(payload) && typeof payload.id === 'string' && payload.id.trim())
    .map(sanitizeStoredPublicPayload)
    .map(scrubDestructivePayloadCommands)
    .map(payload => scrubLowQualityEnglishContent(scrubRetiredEdrContent(payload).value).value)
    .map(sanitizeStoredPublicPayload)
    .filter(payload => normalizeList(payload.execution).length);
  const normalizedIds = new Set(normalizedPayloads.map(item => item.id));
  const publicPayloads = normalizedPayloads.filter(payload => {
    const canonicalId = payloadRefAliases.get(payload.id);
    return !(legacyJwtPayloadIds.has(payload.id) && canonicalId && normalizedIds.has(canonicalId));
  });
  const candidateIds = new Set(publicPayloads.map(item => item.id));
  return {
    payloads: publicPayloads,
    navigation: filterStoredPayloadNavigation(navigation, candidateIds),
  };
};

const curateSeedData = seedData => {
  const payloads = normalizeList(seedData.payloads)
    .filter(isPublicPayloadCandidate)
    .map(sanitizeStoredPublicPayload)
    .filter(payload => normalizeList(payload.execution).length);
  const payloadIds = new Set(payloads.map(item => item.id));
  const tools = normalizeList(seedData.tools).map(sanitizeTool).filter(item => !excludedPublicToolIds.has(item.id) && !isSystemToolId(item.id));
  const toolIds = new Set(tools.map(item => item.id));
  return {
    ...seedData,
    payloads,
    navigation: filterStoredPayloadNavigation(normalizeList(seedData.navigation).map(sanitizeNavItem), payloadIds),
    tools,
    toolNavigation: filterToolNavigation(normalizeList(seedData.toolNavigation).map(pruneSystemNavigationItem).filter(Boolean), toolIds),
  };
};

const prepareContentItemForInsert = (item, sanitizer, trusted) => (
  trusted ? parseJson(json(item)) : sanitizer(item)
);

const insertPayloads = (database, payloads, { trusted = false } = {}) => {
  const statement = database.prepare(`
    INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  const timestamp = now();
  const usedIds = new Set();
  payloads.forEach((payload, index) => {
    const normalized = prepareContentItemForInsert(payload, sanitizePayload, trusted);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), index, timestamp, timestamp);
  });
};

const insertTools = (database, tools, { trusted = false } = {}) => {
  const statement = database.prepare(`
    INSERT INTO tools (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  const timestamp = now();
  const usedIds = new Set();
  tools.forEach((tool, index) => {
    const normalized = prepareContentItemForInsert(tool, sanitizeTool, trusted);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), index, timestamp, timestamp);
  });
};

const insertNavigation = (database, navigation, toolNavigation = [], { trusted = false } = {}) => {
  const statement = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
  `);
  const timestamp = now();
  const usedIds = new Set();
  navigation.forEach((item, index) => {
    const normalized = prepareContentItemForInsert(item, sanitizeNavItem, trusted);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), 'payloads', index, timestamp, timestamp);
  });
  toolNavigation.forEach((item, index) => {
    const normalized = prepareContentItemForInsert(item, sanitizeNavItem, trusted);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), 'tools', index, timestamp, timestamp);
  });
};

const insertNavigationKind = (database, navigation, kind) => {
  const statement = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
  `);
  const timestamp = now();
  const usedIds = new Set();
  navigation.forEach((item, index) => {
    const normalized = sanitizeNavItem(item);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), kind, index, timestamp, timestamp);
  });
};

const replaceContentData = (database, seedData, { trusted = false } = {}) => {
  database.prepare('DELETE FROM payloads').run();
  database.prepare('DELETE FROM tools').run();
  database.prepare('DELETE FROM navigation_nodes').run();
  insertPayloads(database, normalizeList(seedData.payloads), { trusted });
  insertTools(database, normalizeList(seedData.tools), { trusted });
  insertNavigation(database, normalizeList(seedData.navigation), normalizeList(seedData.toolNavigation), { trusted });
};

const writeDefaultSeedDatabase = async (seedData, file, source = 'database content seed') => {
  await mkdir(dirname(file), { recursive: true });
  const tempFile = join(dirname(file), `.default-seed-${makeSeedArtifactId()}.sqlite`);
  const seedDatabase = new DatabaseSync(tempFile);
  try {
    seedDatabase.exec('PRAGMA journal_mode = DELETE;');
    seedDatabase.exec('PRAGMA synchronous = FULL;');
    initializeContentDatabase(seedDatabase);
    runTransaction(seedDatabase, () => {
      replaceContentData(seedDatabase, seedData);
      writeMetadata(seedDatabase, 'seed_schema_version', defaultSeedSchemaVersion);
      writeMetadata(seedDatabase, 'content_kind', defaultSeedContentKind);
      writeMetadata(seedDatabase, 'generated_at', now());
      writeMetadata(seedDatabase, 'source', source);
    });
  } finally {
    seedDatabase.close();
  }
  await rename(tempFile, file);
  return file;
};

const upsertItems = (database, resource, items, { trusted = false, kind } = {}) => {
  const timestamp = now();
  if (resource === 'navigation') {
    if (kind !== 'payloads' && kind !== 'tools') {
      throw new Error(`Unsupported navigation kind: ${kind}`);
    }
    let nextSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = ?').get(kind).next;
    const existingStatement = database.prepare('SELECT sort_order FROM navigation_nodes WHERE id = ?');
    const statement = database.prepare(`
      INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        tree = excluded.tree,
        kind = excluded.kind,
        updated_at = excluded.updated_at
    `);
    items.forEach(item => {
      const normalized = trusted ? parseJson(json(item)) : sanitizeNavItem(item);
      const existing = existingStatement.get(normalized.id);
      const sortOrder = existing?.sort_order ?? nextSortOrder++;
      statement.run(normalized.id, json(normalized), kind, sortOrder, timestamp, timestamp);
    });
    return;
  }
  const { table, dataColumn, sanitizer } = tableForResource(resource);
  let nextSortOrder = database.prepare(`SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM ${table}`).get().next;
  const existingStatement = database.prepare(`SELECT sort_order FROM ${table} WHERE id = ?`);
  const statement = database.prepare(`
    INSERT INTO ${table} (id, ${dataColumn}, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      ${dataColumn} = excluded.${dataColumn},
      updated_at = excluded.updated_at
  `);
  items.forEach(item => {
    const normalized = trusted ? parseJson(json(item)) : sanitizer(item);
    const existing = existingStatement.get(normalized.id);
    const sortOrder = existing?.sort_order ?? nextSortOrder++;
    statement.run(normalized.id, json(normalized), sortOrder, timestamp, timestamp);
  });
};

const findById = (items, id) => normalizeList(items).find(item => item?.id === id);

const shouldExcludePayload = payload => (
  modeOnlyPayloadIds.has(payload?.id) ||
  (
    !showAllPublicPayloads &&
    (
      payloadVisibilityRules.payloadIds.has(payload?.id) ||
      String(payload?.id || '').startsWith('evasion-') ||
      payloadVisibilityRules.categories.has(textValue(payload?.category))
    )
  )
);

const shouldExcludePayloadNavigationItem = (item, payloadId, depth = 0) => (
  modeOnlyPayloadIds.has(payloadId) ||
  (
    !showAllPublicPayloads &&
    (
      depth === 0 && payloadVisibilityRules.rootIds.has(item?.id) ||
      payloadVisibilityRules.nodeIds.has(item?.id) ||
      payloadVisibilityRules.payloadIds.has(payloadId)
    )
  )
);

const prunePayloadNavigation = item => {
  let changed = false;
  const next = { ...item };
  const currentPayloadId = next.payloadId ? (payloadRefAliases.get(next.payloadId) || next.payloadId) : '';

  if (shouldExcludePayloadNavigationItem(next, currentPayloadId)) {
    return { item: null, changed: true };
  }

  for (const migration of legacyNavigationPayloadRefMigrations) {
    if (next.id === migration.nodeId && next.payloadId === migration.from) {
      next.payloadId = migration.to;
      changed = true;
    }
  }

  const children = [];
  for (const child of normalizeList(next.children)) {
    const result = prunePayloadNavigation(child);
    if (result.changed) changed = true;
    if (result.item) children.push(result.item);
  }
  if (children.length) next.children = children;
  else if (next.children) {
    delete next.children;
    changed = true;
  }

  return { item: next, changed };
};

const mergeDefaultNavigationItem = (currentItem, defaultItem) => {
  let changed = false;
  const next = { ...currentItem };
  if (!next.icon && defaultItem.icon) {
    next.icon = defaultItem.icon;
    changed = true;
  }
  if (!next.payloadId && defaultItem.payloadId) {
    next.payloadId = defaultItem.payloadId;
    changed = true;
  }
  if (!next.toolId && defaultItem.toolId) {
    next.toolId = defaultItem.toolId;
    changed = true;
  }

  const children = normalizeList(next.children).map(child => ({ ...child }));
  const defaultChildren = normalizeList(defaultItem.children);
  for (const defaultChild of defaultChildren) {
    const existingIndex = children.findIndex(child => child.id === defaultChild.id);
    if (existingIndex === -1) {
      children.push(cloneValue(defaultChild));
      changed = true;
      continue;
    }
    const merged = mergeDefaultNavigationItem(children[existingIndex], defaultChild);
    if (merged.changed) {
      children[existingIndex] = merged.item;
      changed = true;
    }
  }

  if (children.length) next.children = children;
  else delete next.children;

  return { item: next, changed };
};

const mergeDefaultItems = (database, table, defaults, { shouldReplace = null } = {}) => {
  const timestamp = now();
  const sanitizer = table === 'tools' ? sanitizeTool : sanitizePayload;
  const existingIds = new Set(database.prepare(`SELECT id FROM ${table}`).all().map(row => row.id));
  const insertItem = database.prepare(`
    INSERT INTO ${table} (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextSortOrder = database.prepare(`SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM ${table}`).get().next;
  const selectItem = database.prepare(`SELECT data FROM ${table} WHERE id = ?`);
  const updateItem = database.prepare(`UPDATE ${table} SET data = ?, updated_at = ? WHERE id = ?`);

  for (const item of defaults) {
    const normalized = sanitizer(item);
    if (!existingIds.has(normalized.id)) {
      insertItem.run(normalized.id, json(normalized), nextSortOrder++, timestamp, timestamp);
      existingIds.add(normalized.id);
      continue;
    }
    if (!shouldReplace) continue;
    const current = parseJson(selectItem.get(normalized.id)?.data);
    if (current && shouldReplace(current)) {
      updateItem.run(json(normalized), timestamp, normalized.id);
    }
  }
};

const restoreAllPayloadPublicData = (database, defaults) => {
  const timestamp = now();
  mergeDefaultItems(database, 'payloads', normalizeList(defaults.payloads));

  const navigationRows = database.prepare(`
    SELECT id, tree, sort_order
    FROM navigation_nodes
    WHERE kind = 'payloads'
    ORDER BY sort_order, id
  `).all();
  const navigationRowsById = new Map(navigationRows.map(row => [row.id, row]));
  const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
  const insertNavigation = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, 'payloads', ?, 1, ?, ?)
  `);
  let nextNavigationSortOrder = database.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = 'payloads'").get().next;

  for (const defaultItem of normalizeList(defaults.navigation)) {
    const normalizedDefault = sanitizeNavItem(defaultItem);
    const row = navigationRowsById.get(normalizedDefault.id);
    if (!row) {
      insertNavigation.run(normalizedDefault.id, json(normalizedDefault), nextNavigationSortOrder++, timestamp, timestamp);
      continue;
    }
    const current = sanitizeNavItem(parseJson(row.tree) || normalizedDefault);
    const merged = mergeDefaultNavigationItem(current, normalizedDefault);
    const patched = patchLegacyNavigationPayloadRefs(merged.item);
    if (merged.changed || patched.changed) {
      updateNavigation.run(json(sanitizeNavItem(patched.item)), timestamp, normalizedDefault.id);
    }
  }
};

const mergeDefaultToolNavigationItem = (currentItem, defaultItem) => {
  let changed = false;
  const next = { ...currentItem };
  if (!next.icon && defaultItem.icon) {
    next.icon = defaultItem.icon;
    changed = true;
  }
  if (!next.toolId && defaultItem.toolId) {
    next.toolId = defaultItem.toolId;
    changed = true;
  }

  const children = normalizeList(next.children).map(child => ({ ...child }));
  const defaultChildren = normalizeList(defaultItem.children);
  for (const defaultChild of defaultChildren) {
    const existingIndex = children.findIndex(child => child.id === defaultChild.id);
    if (existingIndex === -1) {
      children.push(cloneValue(defaultChild));
      changed = true;
      continue;
    }
    const merged = mergeDefaultToolNavigationItem(children[existingIndex], defaultChild);
    if (merged.changed) {
      children[existingIndex] = merged.item;
      changed = true;
    }
  }

  if (children.length) next.children = children;
  else delete next.children;

  return { item: next, changed };
};

const migrateMissingDefaultTools = (database, defaults) => {
  const timestamp = now();
  mergeDefaultItems(database, 'tools', normalizeList(defaults.tools));

  const toolNavigationRows = database.prepare(`
    SELECT id, tree, sort_order
    FROM navigation_nodes
    WHERE kind = 'tools'
    ORDER BY sort_order, id
  `).all();
  const toolNavigationRowsById = new Map(toolNavigationRows.map(row => [row.id, row]));
  const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
  const insertNavigationNode = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, 'tools', ?, 1, ?, ?)
  `);
  let nextNavigationSortOrder = database.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = 'tools'").get().next;

  for (const defaultItem of normalizeList(defaults.toolNavigation)) {
    const normalizedDefault = sanitizeNavItem(defaultItem);
    const row = toolNavigationRowsById.get(normalizedDefault.id);
    if (!row) {
      insertNavigationNode.run(normalizedDefault.id, json(normalizedDefault), nextNavigationSortOrder++, timestamp, timestamp);
      continue;
    }
    const current = sanitizeNavItem(parseJson(row.tree) || normalizedDefault);
    const merged = mergeDefaultToolNavigationItem(current, normalizedDefault);
    if (merged.changed) updateNavigation.run(json(sanitizeNavItem(merged.item)), timestamp, normalizedDefault.id);
  }
};

const patchLegacyNavigationPayloadRefs = item => {
  let changed = false;
  const next = { ...item };
  for (const migration of legacyNavigationPayloadRefMigrations) {
    if (next.id === migration.nodeId && next.payloadId === migration.from) {
      next.payloadId = migration.to;
      changed = true;
    }
  }
  const children = normalizeList(next.children).map(child => {
    const result = patchLegacyNavigationPayloadRefs(child);
    if (result.changed) changed = true;
    return result.item;
  });
  if (children.length) next.children = children;
  else delete next.children;
  return { item: next, changed };
};

const shouldUpgradeBusinessLogicPayload = payload => {
  if (!businessLogicPayloadIds.has(payload?.id)) return false;
  return (
    !normalizeList(payload.attackChain).length ||
    !payload.analysis ||
    !payload.tutorial ||
    !normalizeList(payload.references).length
  );
};

const migrateBusinessLogicPayloads = (database, defaults) => {
  const timestamp = now();
  mergeDefaultItems(database, 'payloads', defaults.payloads.filter(payload => businessLogicPayloadIds.has(payload.id)), { shouldReplace: shouldUpgradeBusinessLogicPayload });

  const navigationRows = database.prepare(`
    SELECT id, tree, sort_order
    FROM navigation_nodes
    WHERE kind = 'payloads'
    ORDER BY sort_order, id
  `).all();
  const navigation = navigationRows.map(row => parseJson(row.tree)).filter(Boolean);
  const ensured = ensureBusinessLogicNavigation(navigation);
  if (!ensured.changed) return;

  const existingNavigationRows = new Map(navigationRows.map(row => [row.id, row]));
  const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
  const insertNavigation = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, 'payloads', ?, 1, ?, ?)
  `);
  let nextNavigationSortOrder = database.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = 'payloads'").get().next;
  for (const item of ensured.items) {
    const normalized = sanitizeNavItem(item);
    const row = existingNavigationRows.get(normalized.id);
    if (row) {
      updateNavigation.run(json(normalized), timestamp, normalized.id);
    } else {
      insertNavigation.run(normalized.id, json(normalized), nextNavigationSortOrder++, timestamp, timestamp);
    }
  }
};

const shouldUpgradeJwtPayload = payload => {
  if (!jwtCanonicalPayloadIds.includes(payload?.id)) return false;
  return (
    !normalizeList(payload.execution).length ||
    !normalizeList(payload.attackChain).length ||
    !payload.tutorial ||
    !payload.tutorial.overview ||
    !payload.tutorial.vulnerability ||
    !payload.tutorial.mitigation
  );
};

const migrateJwtSecurityDefaults = (database, defaults) => {
  const timestamp = now();
  mergeDefaultItems(database, 'payloads', jwtCanonicalPayloadIds.map(id => findById(defaults.payloads, id)).filter(Boolean), { shouldReplace: shouldUpgradeJwtPayload });

  const navigationRows = database.prepare(`
    SELECT id, tree, sort_order
    FROM navigation_nodes
    WHERE kind = 'payloads'
    ORDER BY sort_order, id
  `).all();
  const navigation = navigationRows.map(row => parseJson(row.tree)).filter(Boolean);
  const ensured = ensureJwtSecurityNavigation(navigation);
  if (!ensured.changed) return;

  const existingNavigationRows = new Map(navigationRows.map(row => [row.id, row]));
  const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
  const insertNavigation = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, 'payloads', ?, 1, ?, ?)
  `);
  let nextNavigationSortOrder = database.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = 'payloads'").get().next;
  for (const item of ensured.items) {
    const normalized = sanitizeNavItem(item);
    const row = existingNavigationRows.get(normalized.id);
    if (row) {
      updateNavigation.run(json(normalized), timestamp, normalized.id);
    } else {
      insertNavigation.run(normalized.id, json(normalized), nextNavigationSortOrder++, timestamp, timestamp);
    }
  }
};

const normalizePayloadContentPresentation = payload => {
  if (!isObject(payload)) return payload;
  const normalizeEntry = entry => {
    if (!isObject(entry)) return entry;
    const title = applyVisibleChineseDisplayOverrides(normalizeVisibleCommandTitle(entry.title));
    const description = applyVisibleChineseDisplayOverrides(normalizeVisibleCommandDescription(entry.description));
    const nextTitle = isObject(title) ? { ...title } : title;
    const nextDescription = isObject(description) ? { ...description } : description;
    if (isObject(nextTitle) && textLooksNonProfessionalZh(nextTitle.zh)) {
      if (typeof nextTitle.en === 'string' && nextTitle.en.trim() && !textLooksNonProfessionalZh(nextTitle.en)) nextTitle.zh = nextTitle.en;
      else if (isObject(nextDescription) && typeof nextDescription.zh === 'string' && nextDescription.zh.trim()) nextTitle.zh = nextDescription.zh;
    }
    if (isObject(nextTitle) && looksLikeSentenceTitle(nextTitle.zh) && isObject(nextDescription) && typeof nextDescription.zh === 'string' && nextDescription.zh.trim()) {
      if (/函数拆分|回调|反射/.test(nextDescription.zh)) nextTitle.zh = '函数拆分与回调调用变体';
      if (/Content-Type/.test(nextDescription.zh)) nextTitle.zh = 'Content-Type 变体';
      if (/SSRF|本地地址|gopher|dict/.test(nextDescription.zh)) nextTitle.zh = 'SSRF 目标样例';
    }
    if (isObject(nextDescription) && textLooksNonProfessionalZh(nextDescription.zh)) {
      if (typeof nextDescription.en === 'string' && nextDescription.en.trim() && !textLooksNonProfessionalZh(nextDescription.en)) nextDescription.zh = nextDescription.en;
    }
    return {
      ...entry,
      title: nextTitle,
      description: nextDescription,
    };
  };
  const next = {
    ...payload,
    execution: normalizeList(payload.execution).map(normalizeEntry),
    wafBypass: normalizeList(payload.wafBypass).map(normalizeEntry),
  };
  return next;
};

const migratePayloadContentPresentation = database => {
  const timestamp = now();
  const rows = database.prepare('SELECT id, data FROM payloads').all();
  const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
  for (const row of rows) {
    const payload = parseJson(row.data);
    if (!payload) continue;
    const normalized = sanitizePayload(normalizePayloadContentPresentation(payload));
    const serialized = json(normalized);
    if (serialized !== row.data) updatePayload.run(serialized, timestamp, row.id);
  }
};

const seedIncludedMigrationKeys = Object.freeze([
  'migration_file_upload_basic',
  'migration_remove_edr_evasion',
  'migration_scrub_retired_edr_text',
  'migration_restore_all_payload_public_data_v1',
  'migration_business_logic_quality_v1',
  'migration_jwt_security_navigation_v1',
  'migration_payload_quality_defaults_v1',
  'migration_payload_quality_context_v2',
  'migration_payload_domain_quality_v3',
  'migration_extended_burp_dictionary_payloads_v1',
  'migration_payload_content_presentation_v4',
  'migration_missing_default_tools_v3',
  'migration_project_attribution_v1',
]);

const applyDataMigrations = async (database, { loadDefaults }) => {
  const defaults = await loadDefaults();
  const uploadBasicPayload = findById(defaults.payloads, 'file-upload-basic');

  if (readMetadata(database, 'migration_file_upload_basic') !== '1') {
    runTransaction(database, () => {
      const timestamp = now();
      if (uploadBasicPayload) {
        const exists = database.prepare('SELECT id FROM payloads WHERE id = ?').get(uploadBasicPayload.id);
        if (!exists) {
          const nextSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM payloads').get().next;
          const normalized = sanitizePayload(uploadBasicPayload);
          database.prepare(`
            INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
          `).run(normalized.id, json(normalized), nextSortOrder, timestamp, timestamp);
        }
      }

      const rows = database.prepare("SELECT id, tree FROM navigation_nodes WHERE kind = 'payloads'").all();
      const update = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
      for (const row of rows) {
        const tree = parseJson(row.tree);
        if (!tree) continue;
        const result = patchLegacyNavigationPayloadRefs(tree);
        if (result.changed) update.run(json(sanitizeNavItem(result.item)), timestamp, row.id);
      }
      writeMetadata(database, 'migration_file_upload_basic', '1');
      writeMetadata(database, 'migration_file_upload_basic_at', timestamp);
    });
  }

  if (readMetadata(database, 'migration_remove_edr_evasion') !== '1') {
    runTransaction(database, () => {
      const timestamp = now();
      const deletePayload = database.prepare('DELETE FROM payloads WHERE id = ?');
      const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
      const payloadRows = database.prepare('SELECT id, data FROM payloads').all();
      for (const row of payloadRows) {
        const payload = parseJson(row.data);
        if (!payload) continue;
        if (shouldExcludePayload(payload)) {
          deletePayload.run(row.id);
          continue;
        }
        if (Object.prototype.hasOwnProperty.call(payload, 'edrBypass')) {
          delete payload.edrBypass;
          updatePayload.run(json(sanitizePayload(payload)), timestamp, row.id);
        }
      }

      const deleteTool = database.prepare('DELETE FROM tools WHERE id = ?');
      for (const id of excludedPublicToolIds) {
        deleteTool.run(id);
      }

      const rows = database.prepare("SELECT id, tree FROM navigation_nodes WHERE kind = 'payloads'").all();
      const deleteNavigation = database.prepare('DELETE FROM navigation_nodes WHERE id = ?');
      const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
      for (const row of rows) {
        const tree = parseJson(row.tree);
        if (!tree) continue;
        const result = prunePayloadNavigation(tree);
        if (!result.item) {
          deleteNavigation.run(row.id);
        } else if (result.changed) {
          updateNavigation.run(json(sanitizeNavItem(result.item)), timestamp, row.id);
        }
      }

      const toolRows = database.prepare("SELECT id, tree FROM navigation_nodes WHERE kind = 'tools'").all();
      for (const row of toolRows) {
        const tree = parseJson(row.tree);
        if (!tree) continue;
        const filtered = filterToolNavigation([tree], new Set(
          rowsToItems(database.prepare('SELECT data FROM tools WHERE enabled = 1 ORDER BY sort_order, id').all()).map(item => item.id)
        ));
        if (!filtered.length) deleteNavigation.run(row.id);
        else updateNavigation.run(json(sanitizeNavItem(filtered[0])), timestamp, row.id);
      }

      writeMetadata(database, 'migration_remove_edr_evasion', '1');
      writeMetadata(database, 'migration_remove_edr_evasion_at', timestamp);
    });
  }

  if (readMetadata(database, 'migration_scrub_retired_edr_text') !== '1') {
    runTransaction(database, () => {
      const timestamp = now();
      const deletePayload = database.prepare('DELETE FROM payloads WHERE id = ?');
      const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
      const payloadRows = database.prepare('SELECT id, data FROM payloads').all();
      for (const row of payloadRows) {
        const payload = parseJson(row.data);
        if (!payload) continue;
        if (shouldExcludePayload(payload)) {
          deletePayload.run(row.id);
          continue;
        }
        const scrubbed = scrubRetiredEdrContent(payload);
        if (scrubbed.changed) updatePayload.run(json(sanitizePayload(scrubbed.value)), timestamp, row.id);
      }

      const deleteTool = database.prepare('DELETE FROM tools WHERE id = ?');
      const updateTool = database.prepare('UPDATE tools SET data = ?, updated_at = ? WHERE id = ?');
      const toolRows = database.prepare('SELECT id, data FROM tools').all();
      for (const row of toolRows) {
        const tool = parseJson(row.data);
        if (!tool) continue;
        if (excludedPublicToolIds.has(row.id) || excludedPublicToolIds.has(tool.id)) {
          deleteTool.run(row.id);
          continue;
        }
        const scrubbed = scrubRetiredEdrContent(tool);
        if (scrubbed.changed) updateTool.run(json(sanitizeTool(scrubbed.value)), timestamp, row.id);
      }

      const deleteNavigation = database.prepare('DELETE FROM navigation_nodes WHERE id = ?');
      const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
      const navigationRows = database.prepare('SELECT id, kind, tree FROM navigation_nodes').all();
      for (const row of navigationRows) {
        const tree = parseJson(row.tree);
        if (!tree) continue;
        let next = tree;
        let changed = false;
        if (row.kind === 'payloads') {
          const pruned = prunePayloadNavigation(next);
          if (!pruned.item) {
            deleteNavigation.run(row.id);
            continue;
          }
          next = pruned.item;
          changed = pruned.changed;
        }
        const scrubbed = scrubRetiredEdrContent(next);
        changed = changed || scrubbed.changed;
        if (changed) updateNavigation.run(json(sanitizeNavItem(scrubbed.value)), timestamp, row.id);
      }

      writeMetadata(database, 'migration_scrub_retired_edr_text', '1');
      writeMetadata(database, 'migration_scrub_retired_edr_text_at', timestamp);
    });
  }

  if (readMetadata(database, 'migration_restore_all_payload_public_data_v1') !== '1') {
    runTransaction(database, () => {
      restoreAllPayloadPublicData(database, defaults);
      writeMetadata(database, 'migration_restore_all_payload_public_data_v1', '1');
      writeMetadata(database, 'migration_restore_all_payload_public_data_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_business_logic_quality_v1') !== '1') {
    runTransaction(database, () => {
      migrateBusinessLogicPayloads(database, defaults);
      writeMetadata(database, 'migration_business_logic_quality_v1', '1');
      writeMetadata(database, 'migration_business_logic_quality_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_jwt_security_navigation_v1') !== '1') {
    runTransaction(database, () => {
      migrateJwtSecurityDefaults(database, defaults);
      writeMetadata(database, 'migration_jwt_security_navigation_v1', '1');
      writeMetadata(database, 'migration_jwt_security_navigation_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_payload_quality_defaults_v1') !== '1') {
    runTransaction(database, () => {
      writeMetadata(database, 'migration_payload_quality_defaults_v1', '1');
      writeMetadata(database, 'migration_payload_quality_defaults_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_payload_quality_context_v2') !== '1') {
    runTransaction(database, () => {
      writeMetadata(database, 'migration_payload_quality_context_v2', '1');
      writeMetadata(database, 'migration_payload_quality_context_v2_at', now());
    });
  }

  if (readMetadata(database, 'migration_payload_domain_quality_v3') !== '1') {
    runTransaction(database, () => {
      writeMetadata(database, 'migration_payload_domain_quality_v3', '1');
      writeMetadata(database, 'migration_payload_domain_quality_v3_at', now());
    });
  }

  if (readMetadata(database, 'migration_extended_burp_dictionary_payloads_v1') !== '1') {
    runTransaction(database, () => {
      writeMetadata(database, 'migration_extended_burp_dictionary_payloads_v1', '1');
      writeMetadata(database, 'migration_extended_burp_dictionary_payloads_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_payload_content_presentation_v4') !== '1') {
    runTransaction(database, () => {
      migratePayloadContentPresentation(database);
      writeMetadata(database, 'migration_payload_content_presentation_v4', '1');
      writeMetadata(database, 'migration_payload_content_presentation_v4_at', now());
    });
  }

  if (readMetadata(database, 'migration_missing_default_tools_v3') !== '1') {
    runTransaction(database, () => {
      migrateMissingDefaultTools(database, defaults);
      writeMetadata(database, 'migration_missing_default_tools_v3', '1');
      writeMetadata(database, 'migration_missing_default_tools_v3_at', now());
    });
  }

  if (readMetadata(database, 'migration_project_attribution_v1') !== '1') {
    runTransaction(database, () => {
      const settings = sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings));
      writeMetadata(database, 'settings', json(settings));
      writeMetadata(database, 'migration_project_attribution_v1', '1');
      writeMetadata(database, 'migration_project_attribution_v1_at', now());
    });
  }
};

const seedIfNeeded = async (database, { loadDefaults }) => {
  if (readMetadata(database, 'seeded') === '1') return;
  const defaults = await loadDefaults();
  runTransaction(database, () => {
    const timestamp = now();
    replaceContentData(database, defaults, { trusted: true });
    writeMetadata(database, 'settings', json(defaultSettings));
    writeMetadata(database, 'seeded', '1');
    writeMetadata(database, 'seeded_at', timestamp);
    writeMetadata(database, 'schema_version', '1');
    for (const migrationKey of seedIncludedMigrationKeys) {
      writeMetadata(database, migrationKey, '1');
      writeMetadata(database, `${migrationKey}_at`, timestamp);
    }
  });
};

export {
  applyDataMigrations,
  excludedPublicToolIds,
  makeSeedArtifactId,
  curateSeedData,
  filterStoredPayloadNavigation,
  filterToolNavigation,
  initializeContentDatabase,
  insertNavigation,
  insertNavigationKind,
  insertPayloads,
  insertTools,
  isPublicPayloadCandidate,
  isSystemNavigationNodeId,
  isSystemToolId,
  isXeyeEnabled,
  loadContentDataFromDatabase,
  loadDefaultDataFromSeedDb,
  mergeDefaultItems,
  navigationTouchesSystemItem,
  prepareContentItemForInsert,
  prepareStoredPublicPayloadData,
  prunePayloadNavigation,
  pruneSystemNavigationItem,
  protectedSystemNavigationItem,
  protectedSystemTool,
  readJsonMetadata,
  readMetadata,
  replaceContentData,
  rowsToItems,
  runTransaction,
  seedIfNeeded,
  seedIncludedMigrationKeys,
  shouldExcludePayload,
  tableForResource,
  upsertItems,
  withProtectedSystemToolNavigation,
  withProtectedSystemTools,
  writeDefaultSeedDatabase,
  writeMetadata,
  xeyeDisabledMetadataKey,
};