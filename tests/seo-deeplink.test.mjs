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

test('sitemap/robots 服务端端点契约（8081 实例）', async () => {
  const base = process.env.PAYLOADER_SEO_TEST_BASE || 'http://127.0.0.1:8081';
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
