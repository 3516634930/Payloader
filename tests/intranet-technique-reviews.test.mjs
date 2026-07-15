import assert from 'node:assert/strict';
import { test } from 'node:test';

import { loadCurationSnapshot } from '../scripts/apply-payload-curation.mjs';
import {
  buildIntranetTechniqueReviewDocuments,
  intranetTechniqueReviewSpecs,
} from '../scripts/generate-intranet-technique-reviews.mjs';
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
    command: `technique-${spec.id}-${index} --lab {LAB_HOST}`,
    description: i18n('旧验证说明', 'Legacy validation description'),
    syntaxBreakdown: [{ part: 'legacy', explanation: i18n('旧说明', 'Legacy explanation'), type: 'value' }],
    platform: spec.platform,
    requiresAdmin: true,
  })),
  wafBypass: [],
});

const patchFor = (documents, id, index) => documents.commandOverrides.entries
  .find(entry => entry.id === id)?.patches.find(patch => patch.index === index);

test('intranet technique reviews patch only malformed commands and preserve valid capabilities', () => {
  const sources = intranetTechniqueReviewSpecs.map(sourcePayload);
  sources.find(source => source.id === 'rdp-relay').execution[0].command = '使用Impacket:\npython ntlmrelayx.py -tf targets.txt -smb2support';
  sources.find(source => source.id === 'dll-hijack').execution[0].command = '使用Procmon监控DLL加载';
  sources.find(source => source.id === 'persistence-backdoor-user').execution[0].command = 'Get-LocalUser | Select-Object -First 20 Name\n使用批准账号清单复核';

  const documents = buildIntranetTechniqueReviewDocuments(sources);
  const expectedIds = intranetTechniqueReviewSpecs.map(spec => spec.id);

  assert.equal(expectedIds.length, 72);
  assert.deepEqual(documents.overrides.sourceIds, expectedIds);
  assert.deepEqual(documents.overrides.entries.map(entry => entry.id), expectedIds);
  assert.deepEqual(
    documents.commandOverrides.entries.map(entry => entry.id),
    ['rdp-relay', 'dll-hijack', 'persistence-backdoor-user'],
  );
  assert.deepEqual(validatePayloadOverrideDocument(documents.overrides, sources), []);
  assert.deepEqual(validatePayloadCommandOverrideDocument(documents.commandOverrides, sources), []);

  const patches = documents.commandOverrides.entries.flatMap(entry => entry.patches);
  assert.equal(patches.length, 3);
  assert.equal(patches.every(patch => patch.command !== patch.expectedCommand), true);
  assert.equal(patches.every(patch => !/\p{Script=Han}/u.test(patch.command)), true);
  assert.match(patchFor(documents, 'rdp-relay', 0).command, /ntlmrelayx\.py/);
  assert.match(patchFor(documents, 'persistence-backdoor-user', 0).command, /Get-LocalUser/);
  assert.doesNotMatch(patches.map(patch => patch.command).join('\n'), /PAYLOADER_[A-Z0-9_]*BACKDOOR/i);

  const applied = applyPayloadCommandOverrides(sources, documents.commandOverrides);
  for (const source of sources) {
    const output = applied.find(payload => payload.id === source.id);
    source.execution.forEach((command, index) => {
      if (!patchFor(documents, source.id, index)) assert.equal(output.execution[index].command, command.command);
    });
  }

  for (const entry of documents.overrides.entries) {
    assert.equal(entry.review.decision, 'payload');
    assert.match(entry.description.en, /preserves the original reproducible technique commands/i);
    assert.match(entry.tutorial.exploitation.en, /isolated lab/i);
    assert.match(entry.tutorial.exploitation.en, /blue-team evidence/i);
    assert.equal(entry.attackChain.length, 4);
    assert.equal(entry.attackChain.some(step => step.payloadRef), true);
    assert.equal(entry.references.length >= 2, true);
    assert.equal(entry.prerequisites.length >= 2, true);
    assert.equal(entry.opsecTips.length >= 2, true);
  }
});

test('published intranet snapshot retains offensive technique coverage', () => {
  const snapshot = loadCurationSnapshot('data/payloader.sqlite');
  const expectedIds = new Set(intranetTechniqueReviewSpecs.map(spec => spec.id));
  const reviewed = snapshot.payloads.filter(payload => expectedIds.has(payload.id));
  assert.equal(reviewed.length, expectedIds.size);

  const capabilities = new Map([
    ['kerberoasting', /KerberosRequestorSecurityToken|kerberoast|kerberos::list/i],
    ['sam-dump', /reg save|secretsdump|lsadump::sam/i],
    ['ntds-dump', /ntdsutil|secretsdump|dcsync/i],
    ['lateral-psexec', /psexec/i],
    ['pass-the-hash', /sekurlsa::pth|-hashes|Invoke-SMBClient/i],
    ['ntlm-relay', /ntlmrelayx|responder|mitm6/i],
    ['privilege-token', /token::elevate|JuicyPotato|PrintSpoofer|GodPotato/i],
    ['uac-bypass', /reg add|fodhelper|eventvwr|Akagi/i],
    ['persistence-registry', /reg add|sc create/i],
    ['persistence-wmi', /New-WmiEvent|New-WmiFilterToConsumerBinding/i],
    ['dcsync-attack', /dcsync|secretsdump/i],
    ['golden-ticket', /kerberos::golden/i],
    ['resource-delegation', /New-MachineAccount|Rubeus/i],
    ['dcshadow-attack', /dcshadow/i],
    ['amsi-bypass', /AmsiUtils|Invoke-AmsiBypass/i],
    ['evasion-powershell', /powershell|IEX|DownloadString/i],
    ['proxylogon', /proxylogon|X-AnonResource/i],
    ['proxyshell', /proxyshell|autodiscover/i],
    ['exchange-proxytoken', /proxytoken|X-ClientApplication/i],
  ]);
  for (const [id, pattern] of capabilities) {
    const payload = reviewed.find(item => item.id === id);
    assert.match(payload.execution.map(command => command.command).join('\n'), pattern, `${id} capability retained`);
  }
  assert.doesNotMatch(JSON.stringify(reviewed), /PAYLOADER_[A-Z0-9_]*BACKDOOR/i);
});
