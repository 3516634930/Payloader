// 统一 TS→CJS 测试加载器（T4 测试基建收敛）：vm 沙箱 + ts.transpileModule + localRequire。
// 取代 verify-encoding-tools.mjs 与 tests/ 各测试文件各自的雷同拷贝（同一加载语义只写一遍）。
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import ts from 'typescript';

const require_ = createRequire(import.meta.url);

export const projectRoot = path.resolve(import.meta.dirname, '..', '..');

/**
 * 创建独立沙箱加载器：每次调用一个 vm context + module cache，多份加载互不污染。
 * injectExports: { [cwd 相对路径]: 追加到该模块源尾的 CJS 片段 } —— 用于给 barrel 入口
 * 补挂白名单导出（getter 型 re-export 无法被 shorthand 引用，见 verify 的 hydrateCodecHeavyData）。
 * sandboxGlobal: 合并进沙箱 globalThis 的键值（沙箱全局与主 realm 隔离，模块内读
 * globalThis.X 只能看到这里注入的键；verify 用它传古典破译预算覆盖）。
 */
export const createTsModuleLoader = (options = {}) => {
  const injectExports = options.injectExports ?? {};
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
    globalThis: { Blob, CompressionStream, DecompressionStream, ...(options.sandboxGlobal ?? {}) },
  };
  context.global = context;
  vm.createContext(context);

  const moduleCache = new Map();
  const loadModule = fileName => {
    const key = path.resolve(fileName);
    if (moduleCache.has(key)) return moduleCache.get(key).exports;
    let source = fs.readFileSync(key, 'utf8').replace(/^\uFEFF/, '');
    const inject = injectExports[path.relative(projectRoot, key).replaceAll('\\', '/')];
    if (inject) source += inject;
    const compiled = ts.transpileModule(source, {
      compilerOptions: {
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.CommonJS,
        jsx: ts.JsxEmit.ReactJSX,
        esModuleInterop: true,
      },
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
    const wrapper = vm.runInContext(
      `(function (exports, require, module, __filename, __dirname) {\n${compiled}\n})`,
      context,
      { filename: key },
    );
    wrapper(mod.exports, localRequire, mod, key, path.dirname(key));
    return mod.exports;
  };

  return { context, loadModule };
};

/** 一次性加载单个入口（独立沙箱），返回其 exports。 */
export const loadTsModule = (entryPath, options) =>
  createTsModuleLoader(options).loadModule(path.resolve(entryPath));
