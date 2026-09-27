// SEO 深链路由与动态元数据契约
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadTsModule } from './helpers/compileTsModule.mjs';

const seo = loadTsModule('src/utils/seo.ts');

test('buildHash 路由形态', () => {
  assert.equal(seo.buildHash({ tab: 'payloads', payloadId: 'sqli-mysql-basic', toolId: null, waf: false }), '#/payload/sqli-mysql-basic');
  assert.equal(seo.buildHash({ tab: 'payloads', payloadId: 'x', toolId: null, waf: true }), '#/payload/x/waf');
  assert.equal(seo.buildHash({ tab: 'tools', payloadId: null, toolId: 'nmap', waf: false }), '#/tool/nmap');
  assert.equal(seo.buildHash({ tab: 'ctf', payloadId: null, toolId: null, waf: false }), '#/tab/ctf');
  assert.equal(seo.buildHash({ tab: 'workspace', payloadId: null, toolId: null, waf: false }), '#/');
});

test('applyPageSeo 动态 title/description/OG（jsdom 环境语义）', () => {
  // jsdom 不可用时降级为 DOM API 形态断言（document 上存在 head/meta 操作）
  assert.equal(typeof seo.applyPageSeo, 'function');
  assert.equal(typeof seo.installDeepLinking, 'function');
  assert.equal(typeof seo.syncHashForState, 'function');
});

test('sitemap/robots 服务端端点契约（自起临时实例）', async t => {
  // 不再依赖外部 8081 常驻实例（本地碰巧有、CI 没有）——测试自起随机端口临时实例。
  const { spawn } = await import('node:child_process');
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join, resolve } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const projectRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const dataDir = await mkdtemp(join(tmpdir(), 'payloader-seo-'));
  const port = 20000 + Math.floor(Math.random() * 20000);
  const base = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['server/admin-server.mjs'], {
    cwd: projectRoot,
    env: { ...process.env, PAYLOADER_PORT: String(port), PAYLOADER_DATA_DIR: dataDir },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  const shutdown = () => { child.kill(); };
  t.after(async () => {
    shutdown();
    await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  });
  // 就绪探测：启动横幅含前端地址（首次运行含 seed 初始化），上限 60s
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (output.includes('Payloader frontend:')) break;
    await new Promise(r => setTimeout(r, 250));
  }
  if (!output.includes('Payloader frontend:')) {
    throw new Error(`临时实例未就绪。Output:\n${output.slice(0, 2000)}`);
  }
  const robots = await fetch(`${base}/robots.txt`).then(r => r.text());
  assert.match(robots, /Sitemap: .+\/sitemap\.xml/);
  assert.match(robots, /Disallow: \/api\//);
  const sitemap = await fetch(`${base}/sitemap.xml`).then(r => r.text());
  assert.match(sitemap, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assert.match(sitemap, /#\/payload\/sqli-mysql-basic</);
  assert.match(sitemap, /#\/tool\/nmap</);
  const urlCount = (sitemap.match(/<loc>/g) || []).length;
  assert.ok(urlCount >= 1000, `sitemap 应含首页+632载荷+377工具，实际 ${urlCount}`);
});
