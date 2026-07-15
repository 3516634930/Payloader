import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

import { payloadContentHash } from './payload-editorial-review.mjs';

const validDecisions = new Set(['keep', 'merge', 'retire', 'system']);
const hanPattern = /\p{Script=Han}/u;
const repeatedQuestionPattern = /\?{2,}|\uFFFD/;
const isObject = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const asList = value => Array.isArray(value) ? value : [];
const normalizedId = value => String(value || '').trim();
const localizedText = (value, language) => typeof value === 'string'
  ? (language === 'zh' ? value : '')
  : String(value?.[language] || '');
const commandKey = value => String(value || '').replace(/\r\n?/g, '\n').trim();
const commandCommentPattern = /^(?:#|\/\/|\/\*|\*|<!--|REM\b|::)/i;
const byId = (left, right) => left.id.localeCompare(right.id, 'en');

export const toolContentHash = tool => payloadContentHash(tool);

const walkLocalized = (value, visit, path = []) => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkLocalized(item, visit, [...path, index]));
    return;
  }
  if (!isObject(value)) return;
  if (Object.prototype.hasOwnProperty.call(value, 'zh') || Object.prototype.hasOwnProperty.call(value, 'en')) {
    visit(value, path);
  }
  for (const [key, item] of Object.entries(value)) {
    if (key === 'zh' || key === 'en') continue;
    walkLocalized(item, visit, [...path, key]);
  }
};

const compact = (tool, extra = {}) => ({
  id: normalizedId(tool.id),
  name: localizedText(tool.name, 'zh') || localizedText(tool.name, 'en'),
  category: localizedText(tool.category, 'zh') || localizedText(tool.category, 'en'),
  ...extra,
});

export const auditToolEditorialQuality = toolsInput => {
  const tools = asList(toolsInput).filter(isObject);
  const issues = {
    missingReferences: [],
    shortDescriptions: [],
    shortCommandDescriptions: [],
    localizedEnglish: [],
    corruptText: [],
    duplicateCommandsWithinTool: [],
    duplicateCommandsAcrossTools: [],
    commentOnlyCommands: [],
    proseInCommands: [],
  };
  const commandOwners = new Map();

  for (const tool of tools) {
    if (!asList(tool.references).length && !String(tool.externalUrl || '').trim()) {
      issues.missingReferences.push(compact(tool));
    }
    const descriptionFields = ['zh', 'en'].filter(language => localizedText(tool.description, language).trim().length < (language === 'zh' ? 20 : 40));
    if (descriptionFields.length) issues.shortDescriptions.push(compact(tool, { fields: descriptionFields }));

    const shortCommands = asList(tool.commands).flatMap((entry, index) => {
      const fields = ['zh', 'en'].filter(language => localizedText(entry?.description, language).trim().length < (language === 'zh' ? 12 : 30));
      return fields.length ? [{ index, fields }] : [];
    });
    if (shortCommands.length) issues.shortCommandDescriptions.push(compact(tool, { commands: shortCommands }));

    const commentOnlyCommands = [];
    const proseCommands = [];
    asList(tool.commands).forEach((entry, index) => {
      const lines = String(entry?.command || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      if (lines.length && lines.every(line => commandCommentPattern.test(line))) {
        commentOnlyCommands.push(index);
      }
      const proseLines = lines.filter(line => /^\p{Script=Han}/u.test(line) && !commandCommentPattern.test(line));
      if (proseLines.length) proseCommands.push({ index, proseLines });
    });
    if (commentOnlyCommands.length) issues.commentOnlyCommands.push(compact(tool, { commands: commentOnlyCommands }));
    if (proseCommands.length) issues.proseInCommands.push(compact(tool, { commands: proseCommands }));

    const localizedPaths = [];
    const corruptPaths = [];
    walkLocalized(tool, (value, path) => {
      if (hanPattern.test(localizedText(value, 'en'))) localizedPaths.push([...path, 'en'].join('.'));
      for (const language of ['zh', 'en']) {
        if (repeatedQuestionPattern.test(localizedText(value, language))) {
          corruptPaths.push([...path, language].join('.'));
        }
      }
    });
    if (localizedPaths.length) issues.localizedEnglish.push(compact(tool, { paths: localizedPaths }));
    if (corruptPaths.length) issues.corruptText.push(compact(tool, { paths: corruptPaths }));

    const localCommands = new Map();
    asList(tool.commands).forEach((entry, index) => {
      const key = commandKey(entry?.command);
      if (!key) return;
      if (!localCommands.has(key)) localCommands.set(key, []);
      localCommands.get(key).push(index);
      if (!commandOwners.has(key)) commandOwners.set(key, []);
      commandOwners.get(key).push({ id: tool.id, index });
    });
    const duplicates = [...localCommands].filter(([, indexes]) => indexes.length > 1)
      .map(([command, indexes]) => ({ command: command.slice(0, 160), indexes }));
    if (duplicates.length) issues.duplicateCommandsWithinTool.push(compact(tool, { duplicates }));
  }

  issues.duplicateCommandsAcrossTools = [...commandOwners]
    .map(([command, owners]) => ({
      command: command.slice(0, 160),
      owners,
      toolIds: [...new Set(owners.map(owner => owner.id))].sort(),
    }))
    .filter(item => item.toolIds.length > 1)
    .sort((left, right) => left.command.localeCompare(right.command, 'en'));

  for (const [name, items] of Object.entries(issues)) {
    if (name !== 'duplicateCommandsAcrossTools') items.sort(byId);
  }
  return {
    summary: {
      tools: tools.length,
      commands: tools.reduce((sum, tool) => sum + asList(tool.commands).length, 0),
      issueCounts: Object.fromEntries(Object.entries(issues).map(([name, items]) => [name, items.length])),
    },
    issues,
  };
};

export const auditToolReviewLedger = (toolsInput, ledgerInput) => {
  const tools = asList(toolsInput).filter(isObject);
  const ledger = asList(ledgerInput).filter(isObject);
  const toolsById = new Map(tools.map(tool => [normalizedId(tool.id), tool]));
  const counts = new Map();
  for (const entry of ledger) {
    const id = normalizedId(entry.id);
    counts.set(id, (counts.get(id) || 0) + 1);
  }
  const missing = [...toolsById.keys()].filter(id => !counts.has(id)).sort();
  const extra = [...counts.keys()].filter(id => !toolsById.has(id)).sort();
  const duplicates = [...counts].filter(([, count]) => count > 1).map(([id]) => id).sort();
  const stale = ledger
    .filter(entry => toolsById.has(normalizedId(entry.id)))
    .filter(entry => entry.contentHash !== toolContentHash(toolsById.get(normalizedId(entry.id))))
    .map(entry => normalizedId(entry.id));
  const invalid = ledger
    .filter(entry => !validDecisions.has(entry.decision) || !/^[a-f0-9]{64}$/.test(String(entry.contentHash || '')))
    .map(entry => normalizedId(entry.id));
  return {
    missing,
    extra,
    duplicates,
    stale: [...new Set(stale)].sort(),
    invalid: [...new Set(invalid)].sort(),
  };
};

const readTools = file => {
  const database = new DatabaseSync(resolve(file), { readOnly: true });
  try {
    return database.prepare('SELECT data FROM tools WHERE enabled = 1 ORDER BY sort_order, id').all()
      .map(row => JSON.parse(row.data));
  } finally {
    database.close();
  }
};

const runCli = argv => {
  let database = resolve('data', 'payloader.sqlite');
  let ledgerFile = '';
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--db') database = resolve(argv[index + 1] || '');
    if (argv[index] === '--ledger') ledgerFile = resolve(argv[index + 1] || '');
  }
  const tools = readTools(database);
  const report = auditToolEditorialQuality(tools);
  const output = { source: database, ...report };
  if (ledgerFile) {
    const ledger = JSON.parse(readFileSync(ledgerFile, 'utf8'));
    output.ledger = auditToolReviewLedger(tools, ledger.entries || ledger);
  }
  console.log(JSON.stringify(output, null, 2));
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) runCli(process.argv.slice(2));
