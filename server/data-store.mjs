import { mkdir, rename, rm, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as sqlite from 'node:sqlite';
import {
  applyVisibleChineseDisplayOverrides,
  ensureDisplayTextObject,
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
import { importArrayLimits, importSummary, maxImportNavigationDepth, maxImportNavigationNodes } from './import-template.mjs';
import {
  cloneValue,
  defaultSettings,
  makeId,
  protectedExternalUrl,
  protectedXssToolId,
  sanitizeNavItem,
  sanitizePayload,
  sanitizeSettings,
  sanitizeStoredPublicPayload,
  sanitizeTool,
  systemToolIds,
} from './sanitize.mjs';
import { invalidatePublicDataCache, readPublicDataCache, withCacheInvalidation, writePublicDataCache } from './store-cache.mjs';

export { sanitizeNavItem, sanitizePayload, sanitizeSettings, sanitizeTool } from './sanitize.mjs';

export { createImportTemplate } from './import-template.mjs';

const { DatabaseSync } = sqlite;

const rootDir = fileURLToPath(new URL('..', import.meta.url));
const dataDir = resolve(process.env.PAYLOADER_DATA_DIR || join(rootDir, 'data'));
const dbFile = join(dataDir, 'payloader.sqlite');
const backupDir = join(dataDir, 'backups');
const defaultSeedDbFile = resolve(process.env.PAYLOADER_SEED_DB || join(rootDir, 'server', 'default-seed.sqlite'));
const defaultSeedSchemaVersion = '1';
const defaultSeedContentKind = 'curated-defaults';
const makeSeedArtifactId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

let db;
let dbInitialization;
let storeGeneration = 0;
let mutationQueue = Promise.resolve();
let storeTestHooks = {};

const now = () => new Date().toISOString();
const json = value => JSON.stringify(value ?? null);
const parseJson = value => {
  if (typeof value !== 'string' || value.length === 0) return null;
  return JSON.parse(value);
};

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

const protectedStoreError = message => {
  const error = new Error(message);
  error.status = 403;
  return error;
};

const rowsToItems = rows => rows.map(row => parseJson(row.data ?? row.tree)).filter(Boolean);
export const getDefaultSeedDbFile = () => defaultSeedDbFile;
export const getRuntimeDbFile = () => dbFile;

export const setStoreTestHooks = hooks => {
  const candidate = hooks && typeof hooks === 'object' ? hooks : {};
  storeTestHooks = {
    ...(typeof candidate.beforeInitializationPublish === 'function'
      ? { beforeInitializationPublish: candidate.beforeInitializationPublish }
      : {}),
    ...(typeof candidate.beforeResetBackup === 'function'
      ? { beforeResetBackup: candidate.beforeResetBackup }
      : {}),
  };
};

export const closeStore = () => {
  storeGeneration += 1;
  const initialized = Boolean(db);
  if (db) {
    db.close();
    db = undefined;
  }
  if (initialized || !dbInitialization) dbInitialization = undefined;
  invalidatePublicDataCache();
};

const enqueueMutation = work => {
  const operation = mutationQueue.then(work, work);
  mutationQueue = operation.then(() => undefined, () => undefined);
  return operation;
};


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

const initializeStore = async generation => {
  await mkdir(dataDir, { recursive: true });
  const candidate = new DatabaseSync(dbFile);
  try {
    candidate.exec('PRAGMA busy_timeout = 5000;');
    candidate.exec('PRAGMA journal_mode = WAL;');
    candidate.exec('PRAGMA synchronous = NORMAL;');
    candidate.exec('PRAGMA foreign_keys = ON;');
    initializeContentDatabase(candidate);
    await seedIfNeeded(candidate);
    await applyDataMigrations(candidate);
    if (typeof storeTestHooks.beforeInitializationPublish === 'function') {
      await storeTestHooks.beforeInitializationPublish();
    }
    if (generation !== storeGeneration) {
      const error = new Error('Store initialization was cancelled by closeStore().');
      error.code = 'ERR_STORE_INITIALIZATION_CANCELLED';
      throw error;
    }
    db = candidate;
    return candidate;
  } catch (error) {
    try {
      candidate.close();
    } catch {
      // Preserve the initialization error; the connection is already unusable.
    }
    throw error;
  }
};

const getDb = () => {
  if (!dbInitialization) {
    const pending = initializeStore(storeGeneration);
    dbInitialization = pending;
    pending.catch(() => {
      if (dbInitialization === pending) dbInitialization = undefined;
    });
  }
  return dbInitialization;
};

export const ensureStoreReady = async () => {
  await getDb();
  return true;
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

export const getMetadataValue = async (key, fallback = null) => {
  const database = await getDb();
  return readMetadata(database, key) ?? fallback;
};

export const setMetadataValue = withCacheInvalidation(async (key, value) => {
  return enqueueMutation(async () => {
    const database = await getDb();
    writeMetadata(database, key, String(value ?? ''));
    if (key === 'settings') invalidatePublicDataCache();
    return value;
  });
});

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

export const loadDefaultDataFromSeedDb = (file = defaultSeedDbFile) => {
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

export const loadContentDataFromDatabase = (file = dbFile) => {
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

export const loadDefaultData = async () => {
  return loadDefaultDataFromSeedDb(defaultSeedDbFile);
};

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

export const curateSeedData = seedData => {
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

export const writeDefaultSeedDatabase = async (seedData, file = defaultSeedDbFile, source = 'database content seed') => {
  return enqueueMutation(async () => {
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
  });
};

const upsertItems = (database, resource, items) => {
  const { table, dataColumn, sanitizer } = tableForResource(resource);
  const timestamp = now();
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
    const normalized = sanitizer(item);
    const existing = existingStatement.get(normalized.id);
    const sortOrder = existing?.sort_order ?? nextSortOrder++;
    statement.run(normalized.id, json(normalized), sortOrder, timestamp, timestamp);
  });
};

const upsertNavigationKind = (database, navigation, kind) => {
  const timestamp = now();
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
  navigation.forEach(item => {
    const normalized = sanitizeNavItem(item);
    const existing = existingStatement.get(normalized.id);
    const sortOrder = existing?.sort_order ?? nextSortOrder++;
    statement.run(normalized.id, json(normalized), kind, sortOrder, timestamp, timestamp);
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

const restoreAllPayloadPublicData = (database, defaults) => {
  const timestamp = now();
  const existingPayloadIds = new Set(database.prepare('SELECT id FROM payloads').all().map(row => row.id));
  const insertPayload = database.prepare(`
    INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextPayloadSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM payloads').get().next;

  for (const payload of normalizeList(defaults.payloads)) {
    const normalized = sanitizePayload(payload);
    if (existingPayloadIds.has(normalized.id)) continue;
    insertPayload.run(normalized.id, json(normalized), nextPayloadSortOrder++, timestamp, timestamp);
    existingPayloadIds.add(normalized.id);
  }

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
  const existingToolIds = new Set(database.prepare('SELECT id FROM tools').all().map(row => row.id));
  const insertTool = database.prepare(`
    INSERT INTO tools (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextToolSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM tools').get().next;

  for (const tool of normalizeList(defaults.tools)) {
    const normalized = sanitizeTool(tool);
    if (existingToolIds.has(normalized.id)) continue;
    insertTool.run(normalized.id, json(normalized), nextToolSortOrder++, timestamp, timestamp);
    existingToolIds.add(normalized.id);
  }

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
  const defaultsById = new Map(defaults.payloads
    .filter(payload => businessLogicPayloadIds.has(payload.id))
    .map(payload => [payload.id, sanitizePayload(payload)]));
  const selectPayload = database.prepare('SELECT id, data FROM payloads WHERE id = ?');
  const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
  const insertPayload = database.prepare(`
    INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextPayloadSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM payloads').get().next;

  for (const [id, payload] of defaultsById) {
    const row = selectPayload.get(id);
    if (!row) {
      insertPayload.run(payload.id, json(payload), nextPayloadSortOrder++, timestamp, timestamp);
      continue;
    }
    const current = parseJson(row.data);
    if (shouldUpgradeBusinessLogicPayload(current)) {
      updatePayload.run(json(payload), timestamp, id);
    }
  }

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
  const defaultsById = new Map(defaults.payloads
    .filter(payload => jwtCanonicalPayloadIds.includes(payload.id))
    .map(payload => [payload.id, sanitizePayload(payload)]));
  const selectPayload = database.prepare('SELECT id, data FROM payloads WHERE id = ?');
  const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
  const insertPayload = database.prepare(`
    INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextPayloadSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM payloads').get().next;

  for (const id of jwtCanonicalPayloadIds) {
    const payload = defaultsById.get(id);
    if (!payload) continue;
    const row = selectPayload.get(id);
    if (!row) {
      insertPayload.run(payload.id, json(payload), nextPayloadSortOrder++, timestamp, timestamp);
      continue;
    }
    const current = parseJson(row.data);
    if (shouldUpgradeJwtPayload(current)) {
      updatePayload.run(json(payload), timestamp, id);
    }
  }

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

export const seedIncludedMigrationKeys = Object.freeze([
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

const applyDataMigrations = async database => {
  const defaults = await loadDefaultData();
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

const seedIfNeeded = async database => {
  if (readMetadata(database, 'seeded') === '1') return;
  const defaults = await loadDefaultData();
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

const assertBackupPath = path => {
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

const createResetBackup = async (database, target) => {
  await mkdir(backupDir, { recursive: true });
  const fileName = makeResetBackupFileName(target);
  const path = join(backupDir, fileName);
  assertBackupPath(path);
  const createdAt = now();
  let method;
  let pages = null;

  try {
    if (typeof storeTestHooks.beforeResetBackup === 'function') {
      await storeTestHooks.beforeResetBackup({ target });
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

export const getResetImpact = async value => {
  const target = validateResetTarget(value);
  const [database, defaults] = await Promise.all([getDb(), loadDefaultData()]);
  return createResetImpact(target, readResetState(database), makeSeedResetState(defaults));
};

export const createDataExportPackage = async () => {
  const database = await getDb();
  const state = readResetState(database);
  const summary = countResetState(state);
  return {
    format: 'payloader.export.v1',
    version: 1,
    generatedAt: now(),
    summary,
    data: {
      settings: state.settings,
      payloads: state.payloads,
      tools: state.tools,
      navigation: state.navigation,
      toolNavigation: state.toolNavigation,
    },
  };
};

export const resetDefaultData = withCacheInvalidation(value => {
  const target = validateResetTarget(value);
  return enqueueMutation(async () => {
    const [database, defaults] = await Promise.all([getDb(), loadDefaultData()]);
    const seedState = makeSeedResetState(defaults);
    const backup = await createResetBackup(database, target);
    const impact = createResetImpact(target, readResetState(database), seedState);

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

    const data = await getPublicData({ bypassCache: true });
    return {
      data,
      impact,
      before: impact.before,
      seed: impact.seed,
      delta: impact.delta,
      backup,
    };
  });
});

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

const isXeyeEnabled = database => readMetadata(database, xeyeDisabledMetadataKey) !== '1';

const assertMutableAdminItem = (resource, idOrItem) => {
  const id = isObject(idOrItem) ? idOrItem.id : idOrItem;
  if (resource === 'tools' && isSystemToolId(id)) {
    throw protectedStoreError('默认 XSS 平台入口不可编辑或移动，可在工具列表中删除。');
  }
  if (resource === 'navigation') {
    if (isSystemNavigationNodeId(id) || navigationTouchesSystemItem(idOrItem)) {
      throw protectedStoreError('系统内置 XSS 平台导航不可在后台编辑、移动或删除。');
    }
  }
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

export const previewImportPackage = value => {
  const normalized = normalizeImportPackage(value);
  return {
    format: normalized.format,
    summary: importSummary(normalized),
    warnings: normalized.warnings,
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

export const importDataPackage = withCacheInvalidation(async (value, options = {}) => {
  const normalized = normalizeImportPackage(value);
  assertNoDemoPlaceholderContent([
    ...normalized.payloads,
    ...normalized.tools,
    ...normalized.navigation,
    ...normalized.toolNavigation,
  ]);
  const mode = options.mode === 'replace' ? 'replace' : 'merge';
  return enqueueMutation(async () => {
    const database = await getDb();
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
        if (normalized.included.navigation) upsertNavigationKind(database, normalized.navigation, 'payloads');
        if (normalized.included.toolNavigation) upsertNavigationKind(database, normalized.toolNavigation, 'tools');
      }

      writeMetadata(database, 'last_import_at', now());
      writeMetadata(database, 'last_import_mode', mode);
    });

    return {
      mode,
      summary: importSummary(normalized),
      warnings: normalized.warnings,
      data: await getPublicData({ bypassCache: true }),
    };
  });
});

export const getPublicData = async ({ bypassCache = false } = {}) => {
  const cached = readPublicDataCache();
  if (cached && !bypassCache) return cached;
  const database = await getDb();
  const xeyeEnabled = isXeyeEnabled(database);
  const settings = {
    ...sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings)),
    xeyeEnabled,
  };
  const payloads = rowsToItems(database.prepare('SELECT data FROM payloads WHERE enabled = 1 ORDER BY sort_order, id').all());
  const tools = rowsToItems(database.prepare('SELECT data FROM tools WHERE enabled = 1 ORDER BY sort_order, id').all());
  const navigation = rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'payloads' ORDER BY sort_order, id").all());
  const toolNavigation = rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'tools' ORDER BY sort_order, id").all());
  const publicPayloadData = prepareStoredPublicPayloadData(payloads, navigation);
  const storedPublicTools = tools
    .filter(item => !excludedPublicToolIds.has(item.id))
    .map(item => sanitizeTool(item));
  const publicTools = xeyeEnabled ? withProtectedSystemTools(storedPublicTools) : storedPublicTools;
  const toolIds = new Set(publicTools.map(item => item.id));
  return writePublicDataCache({
    settings,
    payloads: publicPayloadData.payloads,
    tools: publicTools,
    navigation: publicPayloadData.navigation,
    toolNavigation: filterToolNavigation(
      xeyeEnabled ? withProtectedSystemToolNavigation(toolNavigation) : toolNavigation,
      toolIds,
    ),
  });
};

export const getSettings = async () => {
  const database = await getDb();
  return {
    ...sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings)),
    xeyeEnabled: isXeyeEnabled(database),
  };
};

export const saveSettings = withCacheInvalidation(async value => {
  const settings = sanitizeSettings(value);
  return enqueueMutation(async () => {
    const database = await getDb();
    writeMetadata(database, 'settings', json(settings));
    writeMetadata(database, 'settings_updated_at', now());
    return { ...settings, xeyeEnabled: isXeyeEnabled(database) };
  });
});

export const listAdminItems = async resource => {
  const database = await getDb();
  if (resource === 'payloads') {
    return rowsToItems(database.prepare('SELECT data FROM payloads ORDER BY sort_order, id').all());
  }
  if (resource === 'tools') {
    const items = rowsToItems(database.prepare('SELECT data FROM tools ORDER BY sort_order, id').all())
      .filter(item => !isSystemToolId(item.id));
    return isXeyeEnabled(database) ? withProtectedSystemTools(items) : items;
  }
  if (resource === 'navigation') {
    return database.prepare('SELECT id, tree, kind, sort_order AS sortOrder, enabled FROM navigation_nodes ORDER BY kind, sort_order, id')
      .all()
      .map(row => ({ ...parseJson(row.tree), kind: row.kind, enabled: Boolean(row.enabled), sortOrder: row.sortOrder }))
      .map(item => {
        const pruned = pruneSystemNavigationItem(item);
        return pruned ? { ...pruned, kind: item.kind, enabled: item.enabled, sortOrder: item.sortOrder } : null;
      })
      .filter(Boolean);
  }
  throw new Error(`Unsupported resource: ${resource}`);
};

export const listCustomPayloads = async () => {
  const database = await getDb();
  return rowsToItems(database.prepare(`
    SELECT data
    FROM payloads
    WHERE id LIKE 'custom-%'
      OR json_extract(data, '$.category.zh') = '自定义'
      OR json_extract(data, '$.category.en') = 'Custom'
    ORDER BY sort_order, id
  `).all());
};

const customContentDestinations = new Set(['payloads', 'tools']);

const customContentError = (status, message) => {
  const error = new Error(message);
  error.status = status;
  return error;
};

const requireCustomDestination = value => {
  const destination = String(value || '');
  if (!customContentDestinations.has(destination)) {
    throw customContentError(400, '自定义内容归属无效');
  }
  return destination;
};

const normalizeCustomContentInput = value => {
  const candidate = isObject(value) ? value : {};
  const title = String(candidate.title || '').trim();
  const content = String(candidate.content || '').trim();
  if (!title) throw customContentError(400, '请填写标题');
  if (!content) throw customContentError(400, '请填写内容');
  return {
    id: String(candidate.id || '').trim(),
    title,
    content,
    destination: requireCustomDestination(candidate.destination),
    sourceDestination: candidate.sourceDestination == null
      ? null
      : requireCustomDestination(candidate.sourceDestination),
  };
};

const isCustomContentItem = item => {
  const category = ensureDisplayTextObject(item?.category);
  return String(item?.id || '').startsWith('custom-')
    || category.zh === '自定义'
    || category.en === 'Custom';
};

const customContentView = (item, destination) => ({
  id: item.id,
  title: textValue(item.name).trim(),
  content: destination === 'tools'
    ? String(item.commands?.[0]?.command || '')
    : String(item.execution?.[0]?.command || ''),
  destination,
});

const customItemForDestination = ({ id, title, content, destination }) => (
  destination === 'tools'
    ? sanitizeTool({
        id,
        name: { zh: title, en: title },
        description: { zh: `自定义：${title}`, en: `Custom: ${title}` },
        category: { zh: '自定义', en: 'Custom' },
        commands: [{
          name: { zh: title, en: title },
          command: content,
          description: { zh: '自定义内容', en: 'Custom content' },
          platform: 'all',
        }],
        references: [],
      })
    : sanitizePayload({
        id,
        name: { zh: title, en: title },
        description: { zh: `自定义：${title}`, en: `Custom: ${title}` },
        category: { zh: '自定义', en: 'Custom' },
        tags: ['custom'],
        prerequisites: [],
        execution: [{
          title: { zh: title, en: title },
          command: content,
          description: { zh: '自定义内容', en: 'Custom content' },
          platform: 'all',
        }],
        wafBypass: [],
      })
);

export const listCustomContent = async () => {
  const database = await getDb();
  const payloads = rowsToItems(database.prepare('SELECT data FROM payloads ORDER BY sort_order, id').all())
    .filter(isCustomContentItem)
    .map(item => customContentView(item, 'payloads'));
  const tools = rowsToItems(database.prepare('SELECT data FROM tools ORDER BY sort_order, id').all())
    .filter(item => !isSystemToolId(item.id) && isCustomContentItem(item))
    .map(item => customContentView(item, 'tools'));
  return [...payloads, ...tools];
};

export const saveCustomContent = withCacheInvalidation(async value => {
  const input = normalizeCustomContentInput(value);
  const id = input.id || makeId('custom', input.title);
  const item = customItemForDestination({ ...input, id });
  assertMutableAdminItem(input.destination, item);
  assertNoDemoPlaceholderContent(item);

  return enqueueMutation(async () => {
    const database = await getDb();
    const source = input.sourceDestination || input.destination;
    const sourceTable = tableForResource(source).table;
    const targetTable = tableForResource(input.destination).table;
    const moving = source !== input.destination;
    const sourceRow = input.id
      ? database.prepare(`SELECT data FROM ${sourceTable} WHERE id = ?`).get(id)
      : null;
    const sourceItem = sourceRow ? parseJson(sourceRow.data) : null;
    if (input.id && (!sourceItem || !isCustomContentItem(sourceItem))) {
      throw customContentError(404, '自定义内容不存在');
    }
    if (moving && database.prepare(`SELECT id FROM ${targetTable} WHERE id = ?`).get(id)) {
      throw customContentError(409, '目标栏目已存在相同 ID 的内容');
    }

    runTransaction(database, () => {
      upsertItems(database, input.destination, [item]);
      if (moving) database.prepare(`DELETE FROM ${sourceTable} WHERE id = ?`).run(id);
    });
    return customContentView(item, input.destination);
  });
});

export const deleteCustomContent = withCacheInvalidation(async value => {
  const id = String(value?.id || '').trim();
  const destination = requireCustomDestination(value?.destination);
  if (!id) throw customContentError(400, '缺少自定义内容 ID');
  assertMutableAdminItem(destination, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    const table = tableForResource(destination).table;
    const row = database.prepare(`SELECT data FROM ${table} WHERE id = ?`).get(id);
    const item = row ? parseJson(row.data) : null;
    if (!item || !isCustomContentItem(item)) {
      throw customContentError(404, '自定义内容不存在');
    }
    database.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
    return { ok: true };
  });
});

const tableForResource = resource => {
  if (resource === 'payloads') return { table: 'payloads', dataColumn: 'data', sanitizer: sanitizePayload };
  if (resource === 'tools') return { table: 'tools', dataColumn: 'data', sanitizer: sanitizeTool };
  throw new Error(`Unsupported resource: ${resource}`);
};

export const saveAdminItem = withCacheInvalidation(async (resource, item) => {
  const { table, dataColumn, sanitizer } = tableForResource(resource);
  const normalized = sanitizer(item);
  assertMutableAdminItem(resource, normalized);
  assertNoDemoPlaceholderContent(normalized);
  return enqueueMutation(async () => {
    const database = await getDb();
    const timestamp = now();
    const existing = database.prepare(`SELECT sort_order FROM ${table} WHERE id = ?`).get(normalized.id);
    const sortOrder = existing?.sort_order ?? (database.prepare(`SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM ${table}`).get().next);
    database.prepare(`
      INSERT INTO ${table} (id, ${dataColumn}, sort_order, enabled, created_at, updated_at)
      VALUES (?, ?, ?, 1, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        ${dataColumn} = excluded.${dataColumn},
        updated_at = excluded.updated_at
    `).run(normalized.id, json(normalized), sortOrder, timestamp, timestamp);
    return normalized;
  });
});

export const saveNavigationItem = withCacheInvalidation(async item => {
  const normalized = sanitizeNavItem(item);
  const kind = item.kind === 'tools' ? 'tools' : 'payloads';
  assertMutableAdminItem('navigation', { ...normalized, kind });
  return enqueueMutation(async () => {
    const database = await getDb();
    const timestamp = now();
    const existing = database.prepare('SELECT sort_order FROM navigation_nodes WHERE id = ?').get(normalized.id);
    const sortOrder = existing?.sort_order ?? (database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = ?').get(kind).next);
    database.prepare(`
      INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        tree = excluded.tree,
        kind = excluded.kind,
        updated_at = excluded.updated_at
    `).run(normalized.id, json(normalized), kind, sortOrder, timestamp, timestamp);
    return { ...normalized, kind };
  });
});

export const deleteAdminItem = withCacheInvalidation(async (resource, id) => {
  if (!id) throw new Error('Missing id');
  if (resource === 'tools' && isSystemToolId(id)) {
    return enqueueMutation(async () => {
      const database = await getDb();
      writeMetadata(database, xeyeDisabledMetadataKey, '1');
      writeMetadata(database, `${xeyeDisabledMetadataKey}_at`, now());
    });
  }
  assertMutableAdminItem(resource, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    if (resource === 'navigation') {
      database.prepare('DELETE FROM navigation_nodes WHERE id = ?').run(id);
      return;
    }
    const { table } = tableForResource(resource);
    database.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
  });
});

export const moveAdminItem = withCacheInvalidation(async (resource, id, direction) => {
  if (!id) throw new Error('Missing id');
  assertMutableAdminItem(resource, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    const table = resource === 'navigation' ? 'navigation_nodes' : tableForResource(resource).table;
    const current = database.prepare(`SELECT id, sort_order, ${resource === 'navigation' ? 'kind' : "'all' AS kind"} FROM ${table} WHERE id = ?`).get(id);
    if (!current) return;
    const operator = direction === 'up' ? '<' : '>';
    const order = direction === 'up' ? 'DESC' : 'ASC';
    const kindClause = resource === 'navigation' ? 'AND kind = ?' : '';
    const args = resource === 'navigation' ? [current.sort_order, current.kind] : [current.sort_order];
    const other = database.prepare(`SELECT id, sort_order FROM ${table} WHERE sort_order ${operator} ? ${kindClause} ORDER BY sort_order ${order} LIMIT 1`).get(...args);
    if (!other) return;
    runTransaction(database, () => {
      database.prepare(`UPDATE ${table} SET sort_order = ? WHERE id = ?`).run(other.sort_order, current.id);
      database.prepare(`UPDATE ${table} SET sort_order = ? WHERE id = ?`).run(current.sort_order, other.id);
    });
  });
});

export const routeResource = path => {
  if (path.includes('/payloads')) return 'payloads';
  if (path.includes('/tools')) return 'tools';
  if (path.includes('/navigation')) return 'navigation';
  return null;
};
