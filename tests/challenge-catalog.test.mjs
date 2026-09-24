// 题型目录一致性测试（reviewer P1-1 加固版）：锚点集与模块集从实现源码/契约真实提取，
// 不用手工镜像白名单；soon 条目的预留 cardId 单独放行（上线时摘 soon 必须先有真实卡片）。
// 附加钉住：cipher 条目在 ctf 视图可见（isOperationVisible），防未来目录引入死按钮。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';
import { readFileSync, readdirSync } from 'node:fs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { challengeCatalog } = loadModule(path.join(srcDir, 'utils', 'ctf', 'challengeCatalog.ts'));
const { operations } = loadModule(path.join(srcDir, 'utils', 'codec', 'operations.ts'));
const { isOperationVisible } = loadModule(path.join(srcDir, 'utils', 'codec', 'audience.ts'));
const { ctfModuleContracts } = loadModule(path.join(srcDir, 'utils', 'ctf', 'moduleContracts.ts'));

// 从 misc 域组件源码真实提取全部 ff-card- 锚点（Review：白名单会漂移，源码提取不会）。
const componentDir = path.join(srcDir, 'components', 'ctf');
const renderedCardIds = new Set();
for (const file of readdirSync(componentDir)) {
  if (!file.endsWith('.tsx')) continue;
  const source = readFileSync(path.join(componentDir, file), 'utf8');
  for (const match of source.matchAll(/id=["'](ff-card-[a-z0-9-]+)["']/g)) renderedCardIds.add(match[1]);
}
// soon 条目的预留卡（尚未有组件渲染）：只允许出现在 soon: true 的条目上。
const plannedCardIds = new Set(
  challengeCatalog.flatMap(category => category.tools
    .filter(tool => tool.soon && tool.cardId)
    .map(tool => tool.cardId)),
);

test('目录基础结构：非空、id/icon/双语字段齐全、类别与工具 id 唯一', () => {
  assert.ok(challengeCatalog.length >= 6, `类别数 ${challengeCatalog.length} 应 ≥6`);
  const categoryIds = new Set();
  const toolIds = new Set();
  for (const category of challengeCatalog) {
    assert.ok(!categoryIds.has(category.id), `类别 id 重复: ${category.id}`);
    categoryIds.add(category.id);
    for (const field of ['icon', 'label', 'hint']) assert.ok(category[field], `${category.id}.${field} 缺失`);
    for (const locale of ['zh', 'en']) {
      assert.ok(category.label[locale].trim(), `${category.id}.label.${locale} 为空`);
      assert.ok(category.hint[locale].trim(), `${category.id}.hint.${locale} 为空`);
    }
    assert.ok(category.tools.length > 0, `${category.id} 无工具`);
    for (const tool of category.tools) {
      assert.ok(!toolIds.has(tool.id), `工具 id 重复: ${tool.id}`);
      toolIds.add(tool.id);
      assert.ok(tool.label.zh.trim() && tool.label.en.trim(), `${tool.id} 双语 label 缺失`);
      assert.ok(tool.description.zh.trim() && tool.description.en.trim(), `${tool.id} 双语 description 缺失`);
    }
  }
});

test('file 条目 cardId 必须真实渲染；未渲染的只能是 soon 预留卡', () => {
  assert.ok(renderedCardIds.size >= 10, `源码锚点提取异常（仅 ${renderedCardIds.size} 个）`);
  for (const category of challengeCatalog) {
    for (const tool of category.tools) {
      if (tool.kind !== 'file') continue;
      assert.ok(tool.cardId, `${tool.id} (file) 缺 cardId`);
      if (tool.soon) continue;
      assert.ok(renderedCardIds.has(tool.cardId),
        `${tool.id} 的 cardId "${tool.cardId}" 未被任何 misc 组件渲染且非 soon 预留——目录与实现漂移`);
    }
  }
});

test('soon 预留卡摘除 soon 前必须先有真实组件（预留集合与渲染集合不得暗中扩大）', () => {
  for (const id of plannedCardIds) {
    if (renderedCardIds.has(id)) continue; // 已实现：目录应已摘 soon
    const owner = challengeCatalog.flatMap(c => c.tools).find(t => t.cardId === id);
    assert.ok(owner?.soon, `预留卡 ${id} 已有组件渲染，目录应摘掉 soon 标记`);
  }
});

test('cipher 条目 operationId 已注册且在 ctf 视图可见（防死按钮）', () => {
  const operationIds = new Set(operations.map(op => op.id));
  for (const category of challengeCatalog) {
    for (const tool of category.tools) {
      if (tool.kind !== 'cipher') continue;
      assert.ok(tool.operationId, `${tool.id} (cipher) 缺 operationId`);
      assert.ok(operationIds.has(tool.operationId), `${tool.id} 的 operationId "${tool.operationId}" 未在 operations.ts 注册`);
      assert.ok(isOperationVisible(tool.operationId, 'ctf'), `${tool.id} 的操作 "${tool.operationId}" 在 ctf 视图不可见，点击将是死按钮`);
    }
  }
});

test('module 条目 targetModuleId 来自真实模块契约', () => {
  const moduleIds = new Set(ctfModuleContracts.map(contract => contract.id));
  for (const category of challengeCatalog) {
    for (const tool of category.tools) {
      if (tool.kind !== 'module') continue;
      assert.ok(tool.targetModuleId, `${tool.id} (module) 缺 targetModuleId`);
      assert.ok(moduleIds.has(tool.targetModuleId), `${tool.id} 的 targetModuleId "${tool.targetModuleId}" 不在模块契约中`);
    }
  }
});

test('核心工具面覆盖：压缩包/图片/音频/GIF/文本/流量主力工具均在目录中', () => {
  const allToolIds = new Set(challengeCatalog.flatMap(c => c.tools.map(t => t.id)));
  for (const required of ['zip-brute', 'crc32-preimage', 'bitplane-scan', 'audio-suite', 'gif-inspect', 'zero-width', 'traffic-handoff']) {
    assert.ok(allToolIds.has(required), `目录缺少核心工具条目: ${required}`);
  }
});
