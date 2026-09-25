// Web 域工具测试（批次 WB）：SSTI 判定树 / 命令注入绕过 / SQLi 矩阵 / Flask session /
// JWT 弱口令（真 HMAC-SHA256 签名锚定）/ PHP 弱类型 / HTTP 报文与 cURL 解析。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const web = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'webTools.ts'));
const {
  detectSstiEngine, SSTI_PAYLOADS, buildCommandBypasses, buildSqliMatrix,
  decodeFlaskSession, jwtWeakSecretCrack, judgePhpLoose, PHP_LOOSE_TABLE,
  parseHttpMessage, parseCurl, MAGIC_HASHES,
} = web;

test('SSTI：回显判定树（Jinja2 字符串重复特征 / 多候选）', () => {
  const jinja = detectSstiEngine('49');
  assert.ok(jinja.length > 0);
  assert.ok(jinja.some(c => c.engine.includes('Jinja2')));
  // '7777777' 单独出现（无 49）判定 Twig medium——合理歧义；'4977777777' 才是 Jinja2 高置信
  const strict = detectSstiEngine('4977777777');
  assert.ok(strict.some(c => c.confidence === 'high' && c.engine.includes('Jinja2')));
  const none = detectSstiEngine('hello world');
  assert.equal(none.length, 0);
  // payload 矩阵七引擎齐备
  assert.ok(SSTI_PAYLOADS.length >= 7);
  assert.ok(SSTI_PAYLOADS.every(p => p.rce.includes('flag') || p.rce.includes('system') || p.rce.includes('Runtime') || p.rce.includes('exec') || p.rce.includes('popen')));
});

test('命令注入绕过：空格/关键字/编码/外带四族', () => {
  const results = buildCommandBypasses('cat /flag');
  const categories = new Set(results.map(r => r.category));
  assert.ok(categories.has('空格绕过'));
  assert.ok(categories.has('关键字绕过'));
  assert.ok(categories.has('整体编码'));
  assert.ok(categories.has('无回显外带'));
  // $IFS 形态
  const ifs = results.find(r => r.payload.includes('$IFS'));
  assert.ok(ifs, '$IFS 形态必须存在');
  // base64 编码形态
  const b64 = results.find(r => r.payload.includes('base64 -d'));
  assert.ok(b64, 'base64 外带形态必须存在');
  // 空命令拒绝
  assert.equal(buildCommandBypasses('   ').length, 0);
});

test('SQLi 矩阵：四型 × 多库', () => {
  const union = buildSqliMatrix('union');
  assert.ok(union.length >= 8);
  assert.ok(union.some(r => r.database === 'MySQL' && r.payload.includes('ORDER BY')));
  assert.ok(union.some(r => r.database === 'SQLite' && r.payload.includes('sqlite_master')));
  const error = buildSqliMatrix('error');
  assert.ok(error.some(r => r.payload.includes('extractvalue')));
  assert.ok(error.some(r => r.database === 'PostgreSQL'));
  const time = buildSqliMatrix('time');
  assert.ok(time.some(r => r.payload.includes('SLEEP')));
  assert.ok(time.some(r => r.payload.includes('pg_sleep')));
  const all = buildSqliMatrix('all');
  assert.ok(all.length > union.length);
});

test('Flask session：三段式解码 + 时间戳 + 非 Flask 拒绝', () => {
  // 构造真格式：payload JSON base64url + 大端时间戳 + 签名占位
  const payloadJson = JSON.stringify({ user: 'admin' });
  const b64url = (bytes) => Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  const payloadB64 = b64url(new TextEncoder().encode(payloadJson));
  const ts = Math.floor(Date.now() / 1000);
  const tsBytes = [];
  let t = ts;
  while (t > 0) { tsBytes.unshift(t & 0xff); t = Math.floor(t / 256); }
  const tsB64 = b64url(Uint8Array.from(tsBytes));
  const token = `${payloadB64}.${tsB64}.deadbeef`;
  const info = decodeFlaskSession(token);
  assert.equal(info.ok, true);
  if (info.ok) {
    assert.equal(info.decoded.includes('"admin"'), true);
    assert.equal(info.compressed, false);
    assert.equal(info.timestamp?.value, ts);
    assert.ok(info.timestamp?.iso.includes('T') || info.timestamp?.iso.includes(' '));
  }
  // 拒绝
  assert.equal(decodeFlaskSession('not.a').ok, false);
  assert.equal(decodeFlaskSession('a.b.c.d').ok, false);
});

test('JWT 弱口令爆破：真 HS256 签名命中弱密钥', async () => {
  const b64url = (bytes) => Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const payload = b64url(new TextEncoder().encode(JSON.stringify({ user: 'admin', role: 'root' })));
  const signingInput = `${header}.${payload}`;
  const secret = 'jwt_secret';
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput)));
  const token = `${signingInput}.${b64url(sig)}`;
  const hit = await jwtWeakSecretCrack(token);
  assert.equal('secret' in hit, true, `应命中，实际 ${JSON.stringify(hit)}`);
  if ('secret' in hit) assert.equal(hit.secret, secret);
  // 错误签名不命中
  const miss = await jwtWeakSecretCrack(`${signingInput}.${b64url(new Uint8Array(32))}`);
  assert.equal('error' in miss, true);
  // 非 HS256 拒绝
  const esHeader = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const rej = await jwtWeakSecretCrack(`${esHeader}.${payload}.sig`);
  assert.equal('error' in rej, true);
  assert.match(rej.error, /HS256/);
});

test('PHP 弱类型判定：数字串/前导数字/字符串严格三态', () => {
  const loose = judgePhpLoose('abc', '0');
  assert.equal(loose.equal, true);
  assert.ok(loose.why.includes('0'));
  assert.equal(judgePhpLoose('1abc', '1').equal, true);
  assert.equal(judgePhpLoose('123', '456').equal, false);
  assert.equal(judgePhpLoose('abc', 'abd').equal, false);
  // 速查表与碰撞对存在
  assert.ok(PHP_LOOSE_TABLE.length >= 5);
  assert.ok(MAGIC_HASHES.some(h => h.hash === 'md5' && h.pair.includes('QNKCDZO')));
});

test('HTTP 报文解析：请求与响应双形态', () => {
  const request = parseHttpMessage('POST /login HTTP/1.1\r\nHost: ctf.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pw=1');
  assert.equal('error' in request, false);
  if ('method' in request) {
    assert.equal(request.method, 'POST');
    assert.equal(request.path, '/login');
    assert.equal(request.headers.length, 2);
    assert.equal(request.headers[0].name, 'Host');
    assert.equal(request.body, 'user=admin&pw=1');
  }
  const response = parseHttpMessage('HTTP/1.1 200 OK\r\nSet-Cookie: session=abc\r\n\r\nok');
  assert.equal('error' in response, false);
  if ('status' in response) {
    assert.equal(response.status, '200 OK');
    assert.equal(response.headers[0].name, 'Set-Cookie');
  }
  assert.match((parseHttpMessage('garbage first line')).error, /无法解析/);
});

test('cURL 解析：-X/-H/-d 与隐含 POST', () => {
  const parsed = parseCurl('curl -X POST http://ctf.example.com/api -H "Content-Type: application/json" -d \'{"a":1}\'');
  assert.equal('error' in parsed, false);
  if ('method' in parsed) {
    assert.equal(parsed.method, 'POST');
    assert.equal(parsed.url, 'http://ctf.example.com/api');
    assert.equal(parsed.headers[0].value, 'application/json');
    assert.equal(parsed.data, '{"a":1}');
  }
  const implied = parseCurl('curl http://x.com/login -d "user=admin"');
  assert.equal('error' in implied, false);
  if ('method' in implied) {
    assert.equal(implied.method, 'POST');
    assert.ok(implied.notes.some(n => n.includes('隐含')));
  }
  assert.match((parseCurl('wget http://x.com')).error, /curl/);
});
