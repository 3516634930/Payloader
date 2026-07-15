import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  auditToolEditorialQuality,
  auditToolReviewLedger,
  toolContentHash,
} from '../scripts/tool-editorial-review.mjs';

const i18n = (zh, en) => ({ zh, en });

const command = (name, value, description = i18n('在授权环境中执行该命令并记录版本、参数和结果。', 'Run this command in an authorized environment and record its version, arguments, and result.')) => ({
  name: i18n(name, 'Validation command'),
  command: value,
  description,
  platform: 'all',
});

const tool = (id, overrides = {}) => ({
  id,
  name: i18n('测试工具', 'Test Tool'),
  description: i18n('用于在授权实验环境中执行可重复的测试命令，并记录明确的输入、版本和输出。', 'Runs repeatable test commands in an authorized lab while recording explicit inputs, versions, and outputs.'),
  category: i18n('Web渗透', 'Web Penetration'),
  commands: [command('基线命令', 'tool --target {TARGET}')],
  references: ['https://example.com/tool'],
  ...overrides,
});

test('tool editorial audit reports weak metadata, corruption, and command duplication', () => {
  const good = tool('good');
  const weak = tool('weak', {
    description: i18n('太短??', '中文残留'),
    commands: [
      command('重复一', 'shared --help', i18n('短', 'short')),
      command('重复二', 'shared --help', i18n('短', 'short')),
    ],
    references: [],
  });
  const duplicate = tool('duplicate', {
    commands: [command('跨卡重复', 'shared --help')],
  });
  const instructionOnly = tool('instruction-only', {
    commands: [
      command('只有注释', '# Open the graphical interface\n# Enter the target in the dialog'),
      command('夹杂说明', 'tool --help\n在界面中输入目标地址'),
    ],
  });

  const report = auditToolEditorialQuality([good, weak, duplicate, instructionOnly]);

  assert.equal(report.summary.tools, 4);
  assert.deepEqual(report.issues.missingReferences.map(item => item.id), ['weak']);
  assert.deepEqual(report.issues.shortDescriptions.map(item => item.id), ['weak']);
  assert.deepEqual(report.issues.shortCommandDescriptions.map(item => item.id), ['weak']);
  assert.deepEqual(report.issues.localizedEnglish.map(item => item.id), ['weak']);
  assert.deepEqual(report.issues.corruptText.map(item => item.id), ['weak']);
  assert.deepEqual(report.issues.duplicateCommandsWithinTool.map(item => item.id), ['weak']);
  assert.deepEqual(report.issues.commentOnlyCommands.map(item => item.id), ['instruction-only']);
  assert.deepEqual(report.issues.proseInCommands.map(item => item.id), ['instruction-only']);
  assert.equal(report.issues.duplicateCommandsAcrossTools.length, 1);
  assert.deepEqual(report.issues.duplicateCommandsAcrossTools[0].toolIds, ['duplicate', 'weak']);
});

test('tool review ledger covers every current tool and rejects stale hashes', () => {
  const first = tool('first');
  const second = tool('second');
  const ledger = [first, second].map(item => ({ id: item.id, contentHash: toolContentHash(item), decision: 'keep' }));

  assert.deepEqual(auditToolReviewLedger([first, second], ledger), {
    missing: [],
    extra: [],
    duplicates: [],
    stale: [],
    invalid: [],
  });

  const changed = { ...second, description: i18n('内容已变化，需要重新审校。', 'Content changed and requires another review.') };
  const result = auditToolReviewLedger([first, changed], [...ledger, ledger[0], { id: 'ghost', contentHash: 'bad', decision: 'unknown' }]);
  assert.deepEqual(result.missing, []);
  assert.deepEqual(result.extra, ['ghost']);
  assert.deepEqual(result.duplicates, ['first']);
  assert.deepEqual(result.stale, ['second']);
  assert.deepEqual(result.invalid, ['ghost']);
});
