import assert from 'node:assert/strict';
import { test } from 'node:test';

import { completeMissingEnglish } from '../scripts/curate-payload-library.mjs';

const hasHan = value => /\p{Script=Han}/u.test(String(value || ''));

const collectEmptyEnglish = (value, path = [], output = []) => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectEmptyEnglish(item, [...path, index], output));
    return output;
  }
  if (!value || typeof value !== 'object') return output;
  if (Object.hasOwn(value, 'en') && !String(value.en || '').trim()) output.push(path.join('.'));
  for (const [key, item] of Object.entries(value)) {
    if (key !== 'en') collectEmptyEnglish(item, [...path, key], output);
  }
  return output;
};

test('missing English fields are completed with contextual, non-localized text', () => {
  const value = {
    id: 'demo-payload',
    name: { zh: '演示条目', en: '' },
    description: { zh: '演示说明', en: '' },
    execution: [{
      title: { zh: '验证输入', en: '' },
      description: { zh: '验证说明', en: '' },
      syntaxBreakdown: [{
        part: 'marker',
        explanation: { zh: '标记说明', en: '' },
        type: 'value',
      }],
    }],
    tutorial: { overview: { zh: '教程概览', en: '' } },
  };

  const completed = completeMissingEnglish(value);
  assert.deepEqual(collectEmptyEnglish(completed), []);
  assert.equal(hasHan(completed.name.en), false);
  assert.match(completed.execution[0].title.en, /Validation step/);
  assert.match(completed.execution[0].description.en, /authorized lab/);
  assert.match(completed.execution[0].syntaxBreakdown[0].explanation.en, /value segment/);
  assert.match(completed.execution[0].syntaxBreakdown[0].explanation.en, /marker/);
  assert.match(completed.tutorial.overview.en, /reviewed entry/);
});

test('legacy generic syntax explanations are upgraded with the actual segment', () => {
  const value = {
    id: 'legacy-explanation',
    syntaxBreakdown: [{
      part: '--scope',
      explanation: {
        zh: '限制目标范围。',
        en: 'Explains the parameter segment used by this reviewed validation command.',
      },
      type: 'parameter',
    }],
  };

  const completed = completeMissingEnglish(value);

  assert.match(completed.syntaxBreakdown[0].explanation.en, /parameter segment/);
  assert.match(completed.syntaxBreakdown[0].explanation.en, /--scope/);
  assert.doesNotMatch(completed.syntaxBreakdown[0].explanation.en, /^Explains the parameter segment used/);
});

test('known broken English fragments are repaired without changing technical identifiers', () => {
  const value = {
    id: 'legacy-english',
    execution: [{
      description: { zh: '检查当前权限', en: 'Checkcurrent Permission' },
      syntaxBreakdown: [{
        part: '-l 1337',
        explanation: { zh: '本地监听端口', en: 'Locallistening Port' },
        type: 'parameter',
      }],
    }],
  };

  const completed = completeMissingEnglish(value);

  assert.equal(completed.execution[0].description.en, 'Check current privileges.');
  assert.equal(completed.execution[0].syntaxBreakdown[0].explanation.en, 'Local listening port.');
  assert.equal(completed.execution[0].syntaxBreakdown[0].part, '-l 1337');
});

test('syntax explanation does not copy localized parts into English', () => {
  const value = {
    id: 'localized-part',
    syntaxBreakdown: [{
      part: '{目标地址}',
      explanation: { zh: '目标地址占位符。', en: '' },
      type: 'value',
    }],
  };

  const completed = completeMissingEnglish(value);

  assert.equal(hasHan(completed.syntaxBreakdown[0].explanation.en), false);
  assert.match(completed.syntaxBreakdown[0].explanation.en, /value segment/);
});
