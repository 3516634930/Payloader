import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { loadCurationSnapshot } from '../scripts/apply-payload-curation.mjs';
import { applyToolOverrides } from '../scripts/curate-payload-library.mjs';
import {
  buildToolQualityCompletionDocument,
  describeToolCommand,
} from '../scripts/generate-tool-quality-completion.mjs';
import { auditToolEditorialQuality } from '../scripts/tool-editorial-review.mjs';

const i18n = (zh, en) => ({ zh, en });

const command = (nameZh, nameEn, value, descriptionZh, descriptionEn, platform = 'all') => ({
  name: i18n(nameZh, nameEn),
  command: value,
  description: i18n(descriptionZh, descriptionEn),
  platform,
});

const tool = (id, nameZh, nameEn, commands) => ({
  id,
  name: i18n(nameZh, nameEn),
  description: i18n('工具说明', 'Tool reference'),
  category: i18n('系统命令', 'System Commands'),
  commands,
  references: ['https://example.com/reference'],
});

test('quality completion writes command-specific bilingual descriptions deterministically', () => {
  const tools = [
    tool('service-query', '服务查询', 'Service Query', [
      command('查询服务', 'Query services', 'Get-Service | Sort-Object Status,Name', '查看服务。', 'Show services.', 'windows'),
    ]),
    tool('bounded-scan', '有界扫描', 'Bounded Scan', [
      command('扫描常用端口', 'Scan common ports', 'nmap -sV -p 22,80,443 {TARGET}', '扫描端口。', 'Scan ports.'),
    ]),
    tool('artifact-copy', '制品复制', 'Artifact Copy', [
      command('复制证据文件', 'Copy evidence file', 'Copy-Item evidence.log archive/evidence.log', '复制文件。', 'Copy a file.', 'windows'),
    ]),
  ];

  const document = buildToolQualityCompletionDocument(tools);
  const repeated = buildToolQualityCompletionDocument(tools);
  assert.deepEqual(repeated, document);

  const updated = applyToolOverrides(tools, document.entries);
  const audit = auditToolEditorialQuality(updated);
  assert.equal(audit.summary.issueCounts.shortDescriptions, 0);
  assert.equal(audit.summary.issueCounts.shortCommandDescriptions, 0);
  assert.deepEqual(
    updated.map(item => item.commands.map(entry => entry.command)),
    tools.map(item => item.commands.map(entry => entry.command)),
  );

  const service = describeToolCommand(tools[0], tools[0].commands[0]);
  const scan = describeToolCommand(tools[1], tools[1].commands[0]);
  const copy = describeToolCommand(tools[2], tools[2].commands[0]);
  assert.match(service.zh, /服务|状态/);
  assert.match(service.en, /service|state/i);
  assert.match(scan.zh, /端口|扫描/);
  assert.match(scan.en, /port|scan/i);
  assert.match(copy.zh, /文件|目标路径/);
  assert.match(copy.en, /file|destination/i);
  assert.equal(new Set([service.en, scan.en, copy.en]).size, 3);

  const fileHash = describeToolCommand(tools[2], command(
    '计算文件哈希',
    'Calculate file hash',
    'certutil -hashfile evidence.log SHA256',
    '计算哈希。',
    'Calculate hash.',
    'windows',
  ));
  const driverQuery = describeToolCommand(tools[0], command(
    '查询驱动',
    'Query drivers',
    'driverquery /v',
    '查看驱动。',
    'Show drivers.',
    'windows',
  ));
  assert.match(fileHash.en, /hash|artifact/i);
  assert.doesNotMatch(fileHash.en, /destination path/i);
  assert.doesNotMatch(driverQuery.en, /returned row|connection context/i);
});

test('published tool catalog retains completed editorial quality without changing commands', () => {
  const source = loadCurationSnapshot('data/payloader.sqlite');
  const document = JSON.parse(readFileSync('content-review/tool-overrides-quality-completion.json', 'utf8'));
  const after = auditToolEditorialQuality(source.tools);
  assert.deepEqual(after.summary.issueCounts, {
    missingReferences: 0,
    shortDescriptions: 0,
    shortCommandDescriptions: 0,
    localizedEnglish: 0,
    corruptText: 0,
    duplicateCommandsWithinTool: 0,
    duplicateCommandsAcrossTools: 0,
    commentOnlyCommands: 0,
    proseInCommands: 0,
  });
  const patches = document.entries.flatMap(entry => entry.patches);
  const localizedValues = patches.map(patch => patch.value).filter(value => value && typeof value === 'object');
  assert.equal(localizedValues.every(value => value.zh.length >= 12 && value.en.length >= 30), true);
  assert.equal(localizedValues.every(value => !/\p{Script=Han}/u.test(value.en)), true);
  assert.equal(new Set(localizedValues.map(value => value.en)).size / localizedValues.length > 0.9, true);
  assert.doesNotMatch(
    localizedValues.map(value => value.en).join('\n'),
    /\b(?:Io T|mac OS|App Armor|Java Script|Virus Total|Alien Vault|Free BSD|Open BSD|lib Fuzzer|will Result Save to File|Start CS Server-Side)\b/,
  );
});
