import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const defaultSeedFile = resolve(projectRoot, 'server', 'default-seed.sqlite');
const defaultRuntimeFile = resolve(projectRoot, 'data', 'payloader.sqlite');
const maxSamples = 50;
const validPlatforms = new Set(['all', 'windows', 'linux']);
const genericTutorialText = new Set([
  '\u9009\u62e9\u5bf9\u5e94payload\u6d4b\u8bd5',
  '\u9009\u62e9\u7ed5\u8fc7\u6280\u672f',
]);
const intentionalOrphanIds = new Set([
  'sqli-waf-bypass',
  'xss-filter-bypass',
  'xss-csp-bypass',
  'ssrf-bypass',
  'csrf-bypass',
  'csrf-token-bypass',
  'csrf-referer-bypass',
  'redirect-bypass',
  'jwt-none-alg',
  'jwt-none-algo',
  'jwt-weak-secret',
  'jwt-kid-injection',
  'jwt-jku-spoofing',
]);
const payloadRefAliases = new Map([
  ['biz-price-tamper', 'biz-payment-tamper'],
  ['jwt-none-alg', 'jwt-none-attack'],
  ['jwt-none-algo', 'jwt-none-attack'],
  ['jwt-weak-secret', 'jwt-secret-bruteforce'],
  ['jwt-kid-injection', 'jwt-key-confusion'],
  ['jwt-jku-spoofing', 'jwt-jku-x5u-injection'],
]);
const categoryBranchExceptions = new Map([
  ['rce-file-upload', 'file-vulns'],
]);

export const PAYLOAD_BRANCH_RULES = Object.freeze([
  { payloadId: 'ai2-mixed-case-bypass', branchId: 'ai-security' },
  { payloadId: 'ai2-virtual-scenario-bypass', branchId: 'ai-security' },
  { payloadId: 'nosql2-ognl-struts2', branchId: 'framework-vulns' },
  { payloadId: 'nosql2-python-pickle', branchId: 'rce' },
  { payloadId: 'nosql2-ruby-marshal', branchId: 'rce' },
  { payloadId: 'inject2-clickjacking-163-lines', branchId: 'clickjacking' },
  { payloadId: 'inject2-open-redirect-184-lines', branchId: 'web-redirect' },
  { payloadId: 'inject2-http-request-smuggling-request', branchId: 'web-smuggling' },
  { payloadId: 'inject2-prototype-pollution-prototype', branchId: 'prototype-pollution' },
  { payloadId: 'inject2-web-cache-deception-211-lines', branchId: 'web-cache' },
  { payloadId: 'inject2-wkhtmltopdf-ssrf', branchId: 'ssrf' },
  { payloadId: 'inject2-wkhtmltopdf-gopher-ssrf', branchId: 'ssrf' },
  { payloadId: 'inject2-puppeteer-headless-chrome-ssrf', branchId: 'ssrf' },
  { payloadId: 'inject2-weasyprint-ssrf', branchId: 'ssrf' },
  { payloadId: 'inject2-prince-xml-ssrf', branchId: 'ssrf' },
]);

const categoryBranches = new Map([
  ['SQL/NoSQL\u6ce8\u5165', 'sqli'],
  ['SQL/NoSQL Injection', 'sqli'],
  ['XSS\u8de8\u7ad9\u811a\u672c', 'xss'],
  ['XSS Cross-Site Scripting', 'xss'],
  ['SSRF\u670d\u52a1\u7aef\u8bf7\u6c42\u4f2a\u9020', 'ssrf'],
  ['Server-side request forgery (SSRF)', 'ssrf'],
  ['RCE\u8fdc\u7a0b\u4ee3\u7801\u6267\u884c', 'rce'],
  ['RCE Remote Code Execution', 'rce'],
  ['\u70b9\u51fb\u52ab\u6301', 'clickjacking'],
  ['Clickjacking', 'clickjacking'],
  ['\u5f00\u653e\u91cd\u5b9a\u5411', 'web-redirect'],
  ['Open Redirect', 'web-redirect'],
  ['\u8bf7\u6c42\u8d70\u79c1', 'web-smuggling'],
  ['Request Smuggling', 'web-smuggling'],
  ['\u539f\u578b\u94fe\u6c61\u67d3', 'prototype-pollution'],
  ['Prototype Pollution', 'prototype-pollution'],
  ['\u7f13\u5b58\u4e0eCDN\u5b89\u5168', 'web-cache'],
  ['Cache & CDN Security', 'web-cache'],
  ['\u6846\u67b6\u6f0f\u6d1e', 'framework-vulns'],
  ['Framework Vulnerabilities', 'framework-vulns'],
  ['AI\u5b89\u5168', 'ai-security'],
  ['AI Security', 'ai-security'],
]);

const isObject = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const asList = value => Array.isArray(value) ? value : [];
const displayText = value => {
  if (typeof value === 'string') return value;
  if (isObject(value)) return value.zh || value.en || '';
  return '';
};
const hasHan = value => /\p{Script=Han}/u.test(String(value || ''));
const normalizedName = value => displayText(value).trim().toLocaleLowerCase('en-US');
const stableIssueKey = item => JSON.stringify(item);
const sorted = items => [...items].sort((left, right) => stableIssueKey(left).localeCompare(stableIssueKey(right), 'en'));
const issueGroup = (items, extra = {}) => ({
  count: items.length,
  items: sorted(items).slice(0, maxSamples),
  ...extra,
});

const walkStrings = (value, visit, path = []) => {
  if (typeof value === 'string') {
    visit(value, path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkStrings(item, visit, [...path, String(index)]));
    return;
  }
  if (isObject(value)) {
    Object.entries(value).forEach(([key, item]) => walkStrings(item, visit, [...path, key]));
  }
};

const walkI18n = (value, visit, path = []) => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkI18n(item, visit, [...path, String(index)]));
    return;
  }
  if (!isObject(value)) return;
  if (typeof value.en === 'string') visit(value, path);
  Object.entries(value).forEach(([key, item]) => walkI18n(item, visit, [...path, key]));
};

const sourceFragmentMatch = command => {
  const match = String(command || '').match(/\r?\n\s*syntaxBreakdown\s*:\s*\[/);
  return match ? 'internal-syntax-breakdown-property' : '';
};

const collectCommandIssues = (snapshot, replacementCharacter, sourceFragment, emptyCommand, invalidPlatform) => {
  for (const payload of asList(snapshot.payloads)) {
    const entries = asList(payload.execution);
    if (!entries.length) {
      emptyCommand.push({ resource: 'payload', id: payload.id, path: 'execution' });
    }
    for (const area of ['execution', 'wafBypass']) {
      asList(payload[area]).forEach((entry, index) => {
        const path = `${area}.${index}`;
        const command = typeof entry?.command === 'string' ? entry.command : '';
        if (!command.trim()) emptyCommand.push({ resource: 'payload', id: payload.id, path: `${path}.command` });
        const fragment = sourceFragmentMatch(command);
        if (fragment) sourceFragment.push({ resource: 'payload', id: payload.id, path: `${path}.command`, signature: fragment });
        if (entry?.platform != null && !validPlatforms.has(entry.platform)) {
          invalidPlatform.push({ resource: 'payload', id: payload.id, path: `${path}.platform`, value: entry.platform });
        }
      });
    }
  }
  for (const tool of asList(snapshot.tools)) {
    const entries = asList(tool.commands);
    if (!entries.length && !tool.externalUrl) emptyCommand.push({ resource: 'tool', id: tool.id, path: 'commands' });
    entries.forEach((entry, index) => {
      const path = `commands.${index}`;
      const command = typeof entry?.command === 'string' ? entry.command : '';
      if (!command.trim()) emptyCommand.push({ resource: 'tool', id: tool.id, path: `${path}.command` });
      const fragment = sourceFragmentMatch(command);
      if (fragment) sourceFragment.push({ resource: 'tool', id: tool.id, path: `${path}.command`, signature: fragment });
      if (entry?.platform != null && !validPlatforms.has(entry.platform)) {
        invalidPlatform.push({ resource: 'tool', id: tool.id, path: `${path}.platform`, value: entry.platform });
      }
    });
  }
  for (const [resource, items] of [
    ['payload', snapshot.payloads],
    ['tool', snapshot.tools],
    ['payload-navigation', snapshot.navigation],
    ['tool-navigation', snapshot.toolNavigation],
  ]) {
    for (const item of asList(items)) {
      walkStrings(item, (value, path) => {
        if (value.includes('\uFFFD')) replacementCharacter.push({
          resource,
          id: item.id,
          path: path.join('.'),
          value: value.slice(0, 180),
        });
      });
    }
  }
  if (snapshot.settings) {
    walkStrings(snapshot.settings, (value, path) => {
      if (value.includes('\uFFFD')) replacementCharacter.push({
        resource: 'metadata',
        id: 'settings',
        path: path.join('.'),
        value: value.slice(0, 180),
      });
    });
  }
};

const collectNavigation = (nodes, placements, references, path = []) => {
  for (const node of asList(nodes)) {
    const nextPath = [...path, node.id || '<missing-id>'];
    if (node.payloadId) {
      references.push({ kind: 'payload', id: node.payloadId, nodeId: node.id, path: nextPath.join('/') });
      placements.set(payloadRefAliases.get(node.payloadId) || node.payloadId, nextPath);
    }
    if (node.toolId) references.push({ kind: 'tool', id: node.toolId, nodeId: node.id, path: nextPath.join('/') });
    collectNavigation(node.children, placements, references, nextPath);
  }
};

const expectedBranch = payload => {
  if (categoryBranchExceptions.has(payload.id)) return categoryBranchExceptions.get(payload.id);
  const explicit = PAYLOAD_BRANCH_RULES.find(rule => rule.payloadId === payload.id);
  if (explicit) return explicit.branchId;
  const category = displayText(payload.category).trim();
  return categoryBranches.get(category) || '';
};

const branchFromPath = path => path[0] === 'web' && path.length > 1 ? path[1] : (path[0] || '');

export const auditSnapshot = (input, options = {}) => {
  const snapshot = {
    payloads: asList(input?.payloads),
    tools: asList(input?.tools),
    navigation: asList(input?.navigation),
    toolNavigation: asList(input?.toolNavigation),
    settings: isObject(input?.settings) ? input.settings : null,
  };
  const replacementCharacter = [];
  const sourceFragment = [];
  const emptyCommand = [];
  const invalidPlatform = [];
  collectCommandIssues(snapshot, replacementCharacter, sourceFragment, emptyCommand, invalidPlatform);

  const payloadIds = new Set(snapshot.payloads.map(item => item?.id).filter(Boolean));
  const toolIds = new Set(snapshot.tools.map(item => item?.id).filter(Boolean));
  const placements = new Map();
  const references = [];
  collectNavigation(snapshot.navigation, placements, references);
  collectNavigation(snapshot.toolNavigation, placements, references);
  const danglingNavigation = references.flatMap(reference => {
    if (reference.kind === 'payload') {
      const resolved = payloadRefAliases.get(reference.id) || reference.id;
      return payloadIds.has(reference.id) || payloadIds.has(resolved) ? [] : [reference];
    }
    return toolIds.has(reference.id) ? [] : [reference];
  });

  const referencedPayloadIds = new Set(
    references
      .filter(reference => reference.kind === 'payload')
      .map(reference => payloadRefAliases.get(reference.id) || reference.id),
  );
  const orphanPayloads = snapshot.payloads
    .filter(payload => payload?.id && !referencedPayloadIds.has(payload.id))
    .map(payload => ({
      id: payload.id,
      name: displayText(payload.name),
      category: displayText(payload.category),
      intentional: intentionalOrphanIds.has(payload.id),
      custom: payload.id.startsWith('custom-'),
    }));

  const englishContainsHan = [];
  for (const [resource, items] of [
    ['payload', snapshot.payloads],
    ['tool', snapshot.tools],
    ['payload-navigation', snapshot.navigation],
    ['tool-navigation', snapshot.toolNavigation],
  ]) {
    for (const item of items) {
      walkI18n(item, (value, path) => {
        if (hasHan(value.en)) englishContainsHan.push({ resource, id: item.id, path: [...path, 'en'].join('.') });
      });
    }
  }
  if (snapshot.settings) {
    walkI18n(snapshot.settings, (value, path) => {
      if (hasHan(value.en)) englishContainsHan.push({ resource: 'metadata', id: 'settings', path: [...path, 'en'].join('.') });
    });
  }
  const englishAffectedResources = new Set(englishContainsHan.map(item => `${item.resource}:${item.id}`)).size;

  const duplicateNames = [];
  for (const [resource, items] of [['payload', snapshot.payloads], ['tool', snapshot.tools]]) {
    const groups = new Map();
    for (const item of items) {
      const name = normalizedName(item.name);
      if (!name) continue;
      if (!groups.has(name)) groups.set(name, []);
      groups.get(name).push(item.id);
    }
    for (const [name, ids] of groups) {
      if (ids.length > 1) duplicateNames.push({ resource, name, ids: [...ids].sort() });
    }
  }

  const genericTutorials = snapshot.payloads.flatMap(payload => {
    const exploitation = displayText(payload?.tutorial?.exploitation).trim();
    return genericTutorialText.has(exploitation) ? [{ id: payload.id, exploitation }] : [];
  });

  const categoryTreeMismatch = snapshot.payloads.flatMap(payload => {
    const expected = expectedBranch(payload);
    const path = placements.get(payload.id);
    if (!expected || !path) return [];
    const actual = branchFromPath(path);
    return actual === expected ? [] : [{ id: payload.id, expectedBranch: expected, actualBranch: actual, path: path.join('/') }];
  });

  const withWafVariants = snapshot.payloads.filter(payload => asList(payload.wafBypass).some(entry => String(entry?.command || '').trim())).length;
  const totalPayloads = snapshot.payloads.length;
  const blocking = {
    databaseIntegrity: issueGroup([]),
    invalidJson: issueGroup([]),
    replacementCharacter: issueGroup(replacementCharacter),
    sourceFragment: issueGroup(sourceFragment),
    emptyCommand: issueGroup(emptyCommand),
    invalidPlatform: issueGroup(invalidPlatform),
    danglingNavigation: issueGroup(danglingNavigation),
  };
  const reporting = {
    englishContainsHan: issueGroup(englishContainsHan, { affectedResources: englishAffectedResources }),
    orphanPayloads: issueGroup(orphanPayloads, {
      intentional: orphanPayloads.filter(item => item.intentional).length,
      custom: orphanPayloads.filter(item => item.custom).length,
      actionable: orphanPayloads.filter(item => !item.intentional && !item.custom).length,
    }),
    duplicateNames: issueGroup(duplicateNames),
    genericTutorials: issueGroup(genericTutorials),
    categoryTreeMismatch: issueGroup(categoryTreeMismatch),
    wafCoverage: {
      total: totalPayloads,
      withVariants: withWafVariants,
      withoutVariants: totalPayloads - withWafVariants,
      percent: totalPayloads ? Number(((withWafVariants / totalPayloads) * 100).toFixed(2)) : 100,
    },
  };
  const blockingErrors = Object.values(blocking).reduce((sum, group) => sum + group.count, 0);
  return {
    version: 1,
    source: options.source || 'snapshot',
    ok: blockingErrors === 0,
    summary: {
      blockingErrors,
      payloads: snapshot.payloads.length,
      tools: snapshot.tools.length,
      payloadNavigationRoots: snapshot.navigation.length,
      toolNavigationRoots: snapshot.toolNavigation.length,
    },
    blocking,
    reporting,
  };
};

const tableExists = (database, table) => Boolean(
  database.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(table),
);

const readRows = (database, table, column, invalidJson, kind) => {
  if (!tableExists(database, table)) {
    invalidJson.push({ resource: kind, id: '<table>', path: column, error: `Missing table: ${table}` });
    return [];
  }
  const rows = database.prepare(`SELECT id, ${column} AS json FROM ${table} ORDER BY sort_order, id`).all();
  return rows.flatMap(row => {
    try {
      const value = JSON.parse(row.json);
      return isObject(value) ? [value] : (() => {
        invalidJson.push({ resource: kind, id: row.id, path: column, error: 'JSON root must be an object' });
        return [];
      })();
    } catch (error) {
      invalidJson.push({ resource: kind, id: row.id, path: column, error: error.message });
      return [];
    }
  });
};

export const auditDatabase = file => {
  const absoluteFile = resolve(file);
  const database = new DatabaseSync(absoluteFile, { readOnly: true });
  try {
    const integrityRows = database.prepare('PRAGMA integrity_check').all();
    const integrityIssues = integrityRows
      .map(row => Object.values(row)[0])
      .filter(value => value !== 'ok')
      .map(value => ({ resource: 'database', id: '<database>', path: '', error: String(value) }));
    const invalidJson = [];
    const payloads = readRows(database, 'payloads', 'data', invalidJson, 'payload');
    const tools = readRows(database, 'tools', 'data', invalidJson, 'tool');
    const navigationRows = tableExists(database, 'navigation_nodes')
      ? database.prepare('SELECT id, tree AS json, kind FROM navigation_nodes ORDER BY kind, sort_order, id').all()
      : [];
    if (!tableExists(database, 'navigation_nodes')) {
      invalidJson.push({ resource: 'navigation', id: '<table>', path: 'tree', error: 'Missing table: navigation_nodes' });
    }
    const navigation = [];
    const toolNavigation = [];
    for (const row of navigationRows) {
      try {
        const value = JSON.parse(row.json);
        if (!isObject(value)) throw new Error('JSON root must be an object');
        (row.kind === 'tools' ? toolNavigation : navigation).push(value);
      } catch (error) {
        invalidJson.push({ resource: `${row.kind || 'unknown'}-navigation`, id: row.id, path: 'tree', error: error.message });
      }
    }
    let settings = null;
    if (tableExists(database, 'metadata')) {
      const settingsValue = database.prepare("SELECT value FROM metadata WHERE key = 'settings'").get()?.value;
      if (settingsValue) {
        try {
          settings = JSON.parse(settingsValue);
        } catch (error) {
          invalidJson.push({ resource: 'metadata', id: 'settings', path: 'value', error: error.message });
        }
      }
    }
    const report = auditSnapshot({ payloads, tools, navigation, toolNavigation, settings }, { source: absoluteFile });
    report.blocking.databaseIntegrity = issueGroup(integrityIssues);
    report.blocking.invalidJson = issueGroup(invalidJson);
    report.summary.blockingErrors = Object.values(report.blocking).reduce((sum, group) => sum + group.count, 0);
    report.ok = report.summary.blockingErrors === 0;
    return report;
  } finally {
    database.close();
  }
};

export const hasBlockingErrors = report => Number(report?.summary?.blockingErrors || 0) > 0;

export const formatHumanSummary = report => {
  const lines = [
    `Content quality: ${report.ok ? 'PASS' : 'FAIL'}`,
    `Database: ${report.source}`,
    `Resources: ${report.summary.payloads} payloads, ${report.summary.tools} tools, ${report.summary.payloadNavigationRoots} payload nav roots, ${report.summary.toolNavigationRoots} tool nav roots`,
    `Blocking errors: ${report.summary.blockingErrors}`,
  ];
  for (const [name, group] of Object.entries(report.blocking)) {
    if (group.count) lines.push(`  - ${name}: ${group.count}`);
  }
  lines.push(
    `Reporting: English-with-Han ${report.reporting.englishContainsHan.count}, orphans ${report.reporting.orphanPayloads.count} (${report.reporting.orphanPayloads.actionable} actionable), duplicate names ${report.reporting.duplicateNames.count}, generic tutorials ${report.reporting.genericTutorials.count}, category mismatches ${report.reporting.categoryTreeMismatch.count}`,
    `WAF coverage: ${report.reporting.wafCoverage.withVariants}/${report.reporting.wafCoverage.total} (${report.reporting.wafCoverage.percent}%)`,
  );
  return lines.join('\n');
};

const parseCli = argv => {
  const files = [];
  let json = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--json') json = true;
    else if (argument === '--database') {
      const file = argv[index + 1];
      if (!file) throw new Error('--database requires a path');
      files.push(resolve(file));
      index += 1;
    } else if (argument === '--seed-only') {
      files.push(defaultSeedFile);
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  if (!files.length) {
    files.push(defaultSeedFile);
    if (existsSync(defaultRuntimeFile)) files.push(defaultRuntimeFile);
  }
  return { files: [...new Set(files)], json };
};

const runCli = argv => {
  const { files, json } = parseCli(argv);
  const missing = files.filter(file => !existsSync(file));
  if (missing.length) throw new Error(`Content database not found: ${missing.join(', ')}`);
  const reports = files.map(auditDatabase);
  const result = {
    version: 1,
    ok: reports.every(report => report.ok),
    databases: reports,
  };
  if (json) console.log(JSON.stringify(result, null, 2));
  else console.log(reports.map(formatHumanSummary).join('\n\n'));
  if (!result.ok) process.exitCode = 1;
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    console.error(`Content quality verifier failed: ${error.message}`);
    process.exitCode = 2;
  }
}
