// 批次 M 速查域契约测试：条目数量、文案完整性、跳转目标必须真实存在于知识库（防死链）。
// 加载方式与 tests/file-forensics.test.mjs 一致：ts.transpileModule + vm 沙箱逐模块加载 src 源码。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';

const require_ = createRequire(import.meta.url);
const srcDir = path.resolve('src');

const context = {
  module: { exports: {} },
  exports: {},
  require: require_,
  console,
  process,
  Buffer,
  crypto: globalThis.crypto,
  atob: value => Buffer.from(value, 'base64').toString('binary'),
  btoa: value => Buffer.from(value, 'binary').toString('base64'),
  TextEncoder,
  TextDecoder,
  Uint8Array,
  URL,
  URLSearchParams,
  Blob,
  CompressionStream,
  DecompressionStream,
  setTimeout,
  clearTimeout,
  globalThis: { Blob, CompressionStream, DecompressionStream },
};
context.global = context;
vm.createContext(context);

const moduleCache = new Map();
const loadModule = fileName => {
  const key = path.resolve(fileName);
  if (moduleCache.has(key)) return moduleCache.get(key).exports;
  const source = fs.readFileSync(key, 'utf8').replace(/^\uFEFF/, '');
  const compiled = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
    fileName: key,
  }).outputText;
  const mod = { exports: {} };
  moduleCache.set(key, mod);
  const localRequire = specifier => {
    if (specifier.startsWith('.')) {
      const base = path.resolve(path.dirname(key), specifier);
      for (const candidate of [base, `${base}.ts`, path.join(base, 'index.ts')]) {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return loadModule(candidate);
      }
      throw new Error(`module not found: ${specifier} (from ${key})`);
    }
    return require_(specifier);
  };
  const wrapper = vm.runInContext(`(function (exports, require, module, __filename, __dirname) {\n${compiled}\n})`, context, { filename: key });
  wrapper(mod.exports, localRequire, mod, key, path.dirname(key));
  return mod.exports;
};

const cheatsheets = loadModule(path.join(srcDir, 'utils', 'ctf', 'cheatsheets', 'index.ts'));

// 跳转目标的真源是策展后的载荷/工具库（服务端 /api/public-data 的内容），
// 而不是 src/data 源文件——策展管线会改写 id（如 sqli-union → sqli-union-query）。
// 这里直接读随仓库分发的种子库（default-seed.sqlite，由 runtime 刷新），与全新部署的服务内容一致。
const { DatabaseSync } = await import('node:sqlite');
const seedFile = path.resolve('server', 'default-seed.sqlite');
const database = new DatabaseSync(seedFile, { readOnly: true });
const payloadIds = new Set(database.prepare('SELECT id FROM payloads').all().map(row => row.id));
const toolIds = new Set(database.prepare('SELECT id FROM tools').all().map(row => row.id));
database.close();
assert.ok(payloadIds.size > 100, `种子载荷库应非空，实际 ${payloadIds.size}`);
assert.ok(toolIds.size > 50, `种子工具库应非空，实际 ${toolIds.size}`);
const CHEATSHEET_MODULES = ['web', 'reverse', 'pwn', 'ai'];

test('四个速查域全部注册且条目数在 5-10 条之间（宁缺毋滥）', () => {
  for (const moduleId of CHEATSHEET_MODULES) {
    const sheet = cheatsheets.ctfCheatSheets[moduleId];
    assert.ok(sheet, `域 ${moduleId} 应有速查数据`);
    assert.ok(sheet.entries.length >= 5 && sheet.entries.length <= 10, `域 ${moduleId} 条目数应在 5-10，实际 ${sheet.entries.length}`);
  }
});

test('条目文案双语齐全、snippet 非空、id 唯一', () => {
  const seenIds = new Set();
  for (const moduleId of CHEATSHEET_MODULES) {
    for (const entry of cheatsheets.ctfCheatSheets[moduleId].entries) {
      const label = `${moduleId}/${entry.id}`;
      assert.ok(!seenIds.has(entry.id), `条目 id 重复：${entry.id}`);
      seenIds.add(entry.id);
      assert.ok(entry.title.zh && entry.title.en, `${label} 标题双语缺失`);
      assert.ok(entry.summary.zh && entry.summary.en, `${label} 摘要双语缺失`);
      if (entry.snippet !== undefined) {
        assert.ok(entry.snippet.trim().length > 0, `${label} snippet 为空`);
      }
      if (entry.tip !== undefined) {
        assert.ok(entry.tip.zh && entry.tip.en, `${label} 提示双语缺失`);
      }
      assert.ok(entry.snippet || entry.tip, `${label} 既无 snippet 也无 tip，内容为空壳`);
    }
  }
});

test('跳转目标必须真实存在于知识库（防死链）', () => {
  let jumpCount = 0;
  for (const moduleId of CHEATSHEET_MODULES) {
    for (const entry of cheatsheets.ctfCheatSheets[moduleId].entries) {
      if (!entry.jump) continue;
      jumpCount += 1;
      const label = `${moduleId}/${entry.id}`;
      if (entry.jump.kind === 'payload') {
        assert.ok(payloadIds.has(entry.jump.id), `${label} 跳转的载荷条目不存在：${entry.jump.id}`);
      } else if (entry.jump.kind === 'tool') {
        assert.ok(toolIds.has(entry.jump.id), `${label} 跳转的工具命令集不存在：${entry.jump.id}`);
      } else {
        assert.fail(`${label} 未知跳转类型：${entry.jump.kind}`);
      }
    }
  }
  assert.ok(jumpCount >= 10, `可跳转条目应形成主体（≥10），实际 ${jumpCount}`);
});
