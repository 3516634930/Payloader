import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildCoreWebSemanticReviewDocuments } from '../scripts/generate-core-web-semantic-reviews.mjs';

const i18n = (zh, en) => ({ zh, en });
const sourcePayload = (id, executionCount, wafBypassCount) => ({
  id,
  name: i18n(id, id),
  description: i18n(`${id} 旧说明`, `${id} legacy description`),
  category: i18n('Web 安全', 'Web Security'),
  subCategory: i18n('旧分类', 'Legacy Category'),
  execution: Array.from({ length: executionCount }, (_, index) => ({
    title: i18n(`旧验证 ${index}`, `Legacy validation ${index}`),
    command: `${id}-execution-${index}`,
    description: i18n('旧验证说明', 'Legacy validation description'),
  })),
  wafBypass: Array.from({ length: wafBypassCount }, (_, index) => ({
    title: i18n(`旧变体 ${index}`, `Legacy variant ${index}`),
    command: `${id}-waf-${index}`,
    description: i18n('旧变体说明', 'Legacy variant description'),
  })),
});

test('core web semantic reviews replace obsolete claims and placeholder payloads', () => {
  const documents = buildCoreWebSemanticReviewDocuments([
    sourcePayload('csrf-json', 4, 2),
    sourcePayload('csrf-flash', 4, 1),
    sourcePayload('ssrf-cloud-azure', 5, 1),
    sourcePayload('ssrf-cloud-gcp', 6, 1),
    sourcePayload('ssrf-mysql', 4, 1),
  ]);

  assert.deepEqual(documents.overrides.entries.map(entry => entry.id), [
    'csrf-json',
    'csrf-flash',
    'ssrf-cloud-azure',
    'ssrf-cloud-gcp',
    'ssrf-mysql',
  ]);
  const patches = documents.commandOverrides.entries.flatMap(entry => entry.patches);
  assert.equal(patches.length, 29);
  assert.equal(patches.every(patch => patch.command !== patch.expectedCommand), true);
  assert.equal(patches.every(patch => Array.isArray(patch.syntaxBreakdown)), true);
  assert.doesNotMatch(
    patches.map(patch => patch.command).join('\n'),
    /MySQL Protocol Data|LAB_MYSQL_PACKET|INTO OUTFILE|eval\(|Flash can bypass|绕过Metadata|Instance Metadata API v2|attacker@evil/i,
  );

  const azureCommands = documents.commandOverrides.entries.find(entry => entry.id === 'ssrf-cloud-azure').patches;
  assert.equal(azureCommands.filter(patch => patch.command.includes('Metadata:true')).length >= 5, true);
  const gcpCommands = documents.commandOverrides.entries.find(entry => entry.id === 'ssrf-cloud-gcp').patches;
  assert.equal(gcpCommands.every(patch => patch.command.includes('computeMetadata/v1')), true);
  assert.equal(gcpCommands.filter(patch => patch.command.includes('Metadata-Flavor: Google')).length >= 6, true);

  for (const entry of documents.overrides.entries) {
    assert.equal(entry.review.decision, 'payload');
    assert.equal(entry.attackChain.length >= 4, true);
    assert.equal(entry.attackChain.some(step => step.payloadRef), true);
    assert.equal(entry.references.every(reference => reference.startsWith('https://')), true);
    for (const field of ['overview', 'vulnerability', 'exploitation', 'mitigation']) {
      assert.equal(entry.tutorial[field].zh.length >= 50, true, `${entry.id}.${field}.zh`);
      assert.equal(entry.tutorial[field].en.length >= 80, true, `${entry.id}.${field}.en`);
    }
  }
});
