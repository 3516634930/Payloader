import assert from 'node:assert/strict';
import { test } from 'node:test';

import { loadCurationSnapshot } from '../scripts/apply-payload-curation.mjs';
import {
  buildRemainingWebReviewDocuments,
  remainingWebCorrectionTargets,
  remainingWebReviewSpecs,
} from '../scripts/generate-remaining-web-reviews.mjs';
import {
  applyPayloadCommandOverrides,
  validatePayloadCommandOverrideDocument,
  validatePayloadOverrideDocument,
} from '../scripts/curate-payload-library.mjs';

const i18n = (zh, en) => ({ zh, en });
const sourcePayload = spec => ({
  id: spec.id,
  name: spec.name,
  description: i18n(`${spec.name.zh}旧说明`, `${spec.name.en} legacy description`),
  category: i18n('旧分类', 'Legacy Category'),
  subCategory: i18n('旧子分类', 'Legacy Subcategory'),
  execution: Array.from({ length: spec.executionCount }, (_, index) => ({
    title: i18n(`旧验证 ${index}`, `Legacy validation ${index}`),
    command: `${spec.id}-execution-${index}`,
    description: i18n('旧验证说明', 'Legacy validation description'),
    syntaxBreakdown: [{ part: 'legacy', explanation: i18n('旧说明', 'Legacy explanation'), type: 'value' }],
  })),
  wafBypass: Array.from({ length: spec.wafBypassCount }, (_, index) => ({
    title: i18n(`旧变体 ${index}`, `Legacy variant ${index}`),
    command: `${spec.id}-waf-${index}`,
    description: i18n('旧变体说明', 'Legacy variant description'),
    syntaxBreakdown: [{ part: 'legacy', explanation: i18n('旧说明', 'Legacy explanation'), type: 'value' }],
  })),
});

const commandLocations = payloads => payloads.flatMap(payload => (
  ['execution', 'wafBypass'].flatMap(area => (payload[area] || []).map((entry, index) => ({
    key: `${payload.id}:${area}:${index}`,
    command: entry.command,
  })))
));

test('remaining web reviews preserve valid attack variants and patch only confirmed semantic errors', () => {
  const sources = remainingWebReviewSpecs.map(sourcePayload);
  const documents = buildRemainingWebReviewDocuments(sources);
  const expectedIds = remainingWebReviewSpecs.map(spec => spec.id);
  const expectedCorrectionKeys = remainingWebReviewSpecs.flatMap(spec => (
    remainingWebCorrectionTargets
      .filter(item => item.id === spec.id)
      .map(item => `${item.id}:${item.area}:${item.index}`)
  ));
  const actualCorrectionKeys = documents.commandOverrides.entries.flatMap(entry => (
    entry.patches.map(patch => `${entry.id}:${patch.area}:${patch.index}`)
  ));

  assert.equal(expectedIds.length, 54);
  assert.deepEqual(documents.overrides.sourceIds, expectedIds);
  assert.deepEqual(documents.overrides.entries.map(entry => entry.id), expectedIds);
  assert.deepEqual(actualCorrectionKeys, expectedCorrectionKeys);
  assert.deepEqual(validatePayloadOverrideDocument(documents.overrides, sources), []);
  assert.deepEqual(validatePayloadCommandOverrideDocument(documents.commandOverrides, sources), []);

  const patches = documents.commandOverrides.entries.flatMap(entry => entry.patches);
  assert.equal(patches.length, expectedCorrectionKeys.length);
  assert.equal(patches.every(patch => patch.command !== patch.expectedCommand), true);
  assert.equal(patches.every(patch => Array.isArray(patch.syntaxBreakdown) && patch.syntaxBreakdown.length === 0), true);
  assert.equal(patches.every(patch => ['all', 'linux'].includes(patch.platform) && patch.requiresAdmin === false), true);

  const correctedCommands = patches.map(patch => patch.command).join('\n');
  assert.doesNotMatch(
    correctedCommands,
    /MySQL协议数据包|FastCGI数据包|xmlns="\.\.\."|file:\/\/\/etc\/passwd|GET \/admin|GET \/internal|使用非最短UTF-8|使用全角字符绕过|写入WebShell|shell\.php/i,
  );
  for (const keyword of [
    '＜script＞alert(1)＜/script＞',
    '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    '%C0%BCscript%C0%BE',
    'PAYLOADER_CACHE_VARIANT',
    'PAYLOADER_MYSQL_REACHABILITY',
    'FCGI_MAX_CONNS',
    'expect://printf%20PAYLOADER_XXE_EXPECT',
    'wordprocessingml/2006/main',
    'spreadsheetml/2006/main',
    'Content-Length: 4',
    'PAYLOADER_SMUGGLE_CL_CL',
  ]) {
    assert.match(correctedCommands, new RegExp(keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }

  const resolved = applyPayloadCommandOverrides(sources, documents.commandOverrides);
  const correctionKeySet = new Set(expectedCorrectionKeys);
  const sourceLocations = new Map(commandLocations(sources).map(item => [item.key, item.command]));
  const resolvedLocations = commandLocations(resolved);
  assert.equal(resolvedLocations.length, sourceLocations.size);
  for (const item of resolvedLocations) {
    assert.equal(
      item.command === sourceLocations.get(item.key),
      !correctionKeySet.has(item.key),
      `${item.key} must ${correctionKeySet.has(item.key) ? 'change' : 'remain unchanged'}`,
    );
  }

  for (const entry of documents.overrides.entries) {
    assert.equal(entry.review.decision, 'payload');
    assert.equal(entry.attackChain.length, 4);
    assert.equal(entry.attackChain.some(step => step.payloadRef), true);
    assert.equal(entry.references.length >= 2, true);
    assert.equal(entry.references.every(reference => reference.startsWith('https://')), true);
    assert.equal(entry.prerequisites.length >= 2, true);
    assert.equal(entry.opsecTips.length >= 2, true);
    assert.match(entry.description.zh, /授权实验/);
    assert.match(entry.description.en, /authorized lab/i);
    assert.match(entry.analysis.zh, /服务端日志/);
    assert.match(entry.analysis.en, /server-side logs/i);
    for (const field of ['overview', 'vulnerability', 'exploitation', 'mitigation']) {
      assert.equal(entry.tutorial[field].zh.length >= 50, true, `${entry.id}.${field}.zh`);
      assert.equal(entry.tutorial[field].en.length >= 80, true, `${entry.id}.${field}.en`);
    }
  }
});

test('real reviewed snapshot keeps complete Web payload coverage and important attack syntax', () => {
  const snapshot = loadCurationSnapshot('data/payloader.sqlite');
  const sourceIds = new Set(remainingWebReviewSpecs.map(spec => spec.id));
  const sources = snapshot.payloads.filter(payload => sourceIds.has(payload.id));
  assert.equal(sources.length, sourceIds.size);

  const commands = commandLocations(sources).map(item => item.command).join('\n');
  for (const keyword of [
    '<script>alert(1)</script>',
    'document.cookie',
    'gopher://127.0.0.1:6379',
    'config%20set%20dir',
    "system('whoami')",
    'php://filter',
    '<!ENTITY',
    'Transfer-Encoding: chunked',
    'Authorization: Bearer {TOKEN}',
    'asyncio',
    'FCGI_MAX_CONNS',
  ]) {
    assert.match(commands, new RegExp(keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'));
  }
});
