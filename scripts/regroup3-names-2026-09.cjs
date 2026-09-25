#!/usr/bin/env node
/**
 * 2026-09 分类命名终审：JWT 归一 + CORS/Java框架并分支 + 12 组名/分支名行业化修正。
 * 机制：payloadSubBranches/payloadBranches 声明改名刷新；条目 subCategory（+category）改写走文档链。
 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const all = db.prepare('SELECT id, data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();
const byId = new Map(all.map(p => [p.id, p]));

// ── 1) 声明更新 ──
const tdPath = CR('tool-decisions.json');
const td = JSON.parse(fs.readFileSync(tdPath, 'utf8'));

// 1a. 组改名（新名 = 行业化）
const SUB_RENAMES = {
  'sqli-carrier-encoding': ['WAF 绕过与编码变形', 'WAF Bypass & Encoding Variants'],
  'xxe-wrapper-rce': ['expect:// 命令执行', 'expect:// Command Execution'],
  'xxe-ssrf': ['XXE 到 SSRF 利用', 'XXE to SSRF'],
  'sqli-carrier-http': ['参数污染与请求载体', 'Parameter Pollution & Request Carriers'],
  'lfi-rfi-wrapper-runtime': ['运行时流包装器', 'Runtime Stream Wrappers'],
  'auth-vulns-cred-injection': ['登录绕过与凭据攻击', 'Login Bypass & Credential Attacks'],
  'smuggling-clte-tecl': ['CL.TE 与 TE.CL 走私形态', 'CL.TE & TE.CL Smuggling'],
  'xss-csp-exfil-frame': ['链接预取与 Frame 滥用', 'Link Prefetch & Frame Abuse'],
  'rce-include': ['文件包含到 RCE 链', 'File Inclusion to RCE'],
  'file-traversal-read-targets': ['敏感文件目标与场景', 'Sensitive File Targets & Scenarios'],
  'rce-code-exec': ['代码执行入口与函数滥用', 'Code Execution Sinks & Function Abuse'],
  'jwt-security-key-header': ['密钥注入与信任边界', 'Key Injection & Trust Boundaries'],
};
let renamed = 0;
for (const b of td.payloadSubBranches) {
  if (SUB_RENAMES[b.id]) { b.name = { zh: SUB_RENAMES[b.id][0], en: SUB_RENAMES[b.id][1] }; renamed++; }
}

// 1b. 删除被迁空的组声明
const REMOVE_SUB = ['api-jwt-validation', 'auth-vulns-jwt-alg'];
const beforeSub = td.payloadSubBranches.length;
td.payloadSubBranches = td.payloadSubBranches.filter(b => !REMOVE_SUB.includes(b.id));

// 1c. 分支改名/新增声明
td.payloadBranches = td.payloadBranches || [];
let bRenamed = 0;
for (const b of td.payloadBranches) if (b.id === 'nav-cat-evasion-powershell') { b.name = { zh: '终端防护规避', en: 'Endpoint Evasion' }; bRenamed++; }
if (!td.payloadBranches.some(b => b.id === 'credential-theft')) {
  td.payloadBranches.push({ rootId: 'intranet', id: 'credential-theft', name: { zh: '凭据窃取', en: 'Credential Theft' } });
  bRenamed++;
}
fs.writeFileSync(tdPath, JSON.stringify(td, null, 2) + '\n');
console.log(`声明：组改名 ${renamed}｜删组 ${beforeSub - td.payloadSubBranches.length}｜分支 ${bRenamed}`);

// ── 2) 条目 subCategory/category 改写映射 ──
const JWT_ALG = ['JWT 算法混淆与签名绕过', 'JWT Alg Confusion & Signature Bypass'];
const JWT_KEY = ['JWT 密钥注入与信任边界', 'JWT Key Injection & Trust Boundary'];
const JWT_CLAIM = ['JWT 声明伪造与会话攻击', 'JWT Claim Forgery & Session Attacks'];
// JWT 归一（22 条的分组）
const MOVE = {
  // API jwt 组 8 条 → jwt-security
  'api-jwt-claim-profile': JWT_CLAIM, 'api-jwt-embedded-jwk': JWT_KEY, 'api-jwt-x5c-chain': JWT_KEY,
  'api-jwt-none-rejection': JWT_ALG, 'api-jwt-alg-key-binding': JWT_ALG, 'api-jwt-kid-allowlist': JWT_KEY,
  'api-jwt-jku-source': JWT_KEY, 'api-jwt-x5u-source': JWT_KEY,
  // 认证 jwt 组 5 条 → jwt-security
  'auth-jwt-none': JWT_ALG, 'auth-jwt-alg-confusion': JWT_ALG, 'auth-jwt-kid-validation': JWT_KEY,
  'auth-jwt-jwk-jku-trust': JWT_KEY, 'auth-jwt-claim-validation': JWT_CLAIM,
  // jwt-security 现组对齐新组名（原 9 条）
  'jwt-none-algorithm-rejection': JWT_ALG, 'jwt-rsa-hmac-confusion': JWT_ALG, 'jwt-signature-negative': JWT_ALG,
  'jwt-kid-key-injection': JWT_KEY, 'jwt-alg-jwk-privilege': JWT_KEY, 'jwt-validation-boundary': JWT_KEY,
  'jwt-unsigned-claim-tamper': JWT_CLAIM, 'jwt-audience-scope': JWT_CLAIM, 'jwt-url-leak': JWT_CLAIM,
  // CORS 单条 → API CORS 组
  'cors-credentialed-read-boundary': ['CORS 跨源配置攻击', 'CORS Misconfiguration Attacks'],
  // Java框架 8 条 → 框架漏洞三组
  'log4j-message-lookup-policy-boundary': ['框架 RCE 利用', 'Framework RCE Exploitation'],
  'spring-spel-simple-eval': ['框架 RCE 利用', 'Framework RCE Exploitation'],
  'struts-ognl-simple-eval': ['框架 RCE 利用', 'Framework RCE Exploitation'],
  'fastjson-autotype-policy-boundary': ['组件与库漏洞', 'Component & Library Vulns'],
  'weblogic-workcontext-reject': ['组件与库漏洞', 'Component & Library Vulns'],
  'spring-gateway-mgmt-access': ['暴露面与 HTTP 攻击', 'Exposure & HTTP Attacks'],
  'jboss-console-access': ['暴露面与 HTTP 攻击', 'Exposure & HTTP Attacks'],
  'tomcat-manager-access': ['暴露面与 HTTP 攻击', 'Exposure & HTTP Attacks'],
};
// category 需要同步改的（跨分支移动）
const CAT_CHANGE = {
  'api-jwt-claim-profile': 'JWT安全', 'api-jwt-embedded-jwk': 'JWT安全', 'api-jwt-x5c-chain': 'JWT安全',
  'api-jwt-none-rejection': 'JWT安全', 'api-jwt-alg-key-binding': 'JWT安全', 'api-jwt-kid-allowlist': 'JWT安全',
  'api-jwt-jku-source': 'JWT安全', 'api-jwt-x5u-source': 'JWT安全',
  'auth-jwt-none': 'JWT安全', 'auth-jwt-alg-confusion': 'JWT安全', 'auth-jwt-kid-validation': 'JWT安全',
  'auth-jwt-jwk-jku-trust': 'JWT安全', 'auth-jwt-claim-validation': 'JWT安全',
  'cors-credentialed-read-boundary': 'API安全',
  'log4j-message-lookup-policy-boundary': '框架漏洞', 'spring-spel-simple-eval': '框架漏洞', 'struts-ognl-simple-eval': '框架漏洞',
  'fastjson-autotype-policy-boundary': '框架漏洞', 'weblogic-workcontext-reject': '框架漏洞',
  'spring-gateway-mgmt-access': '框架漏洞', 'jboss-console-access': '框架漏洞', 'tomcat-manager-access': '框架漏洞',
};

// 校验 id 全部存在
const missing = Object.keys(MOVE).filter(id => !byId.has(id));
if (missing.length) { console.log('✗ 不存在:', missing.join(',')); process.exit(1); }

// ── 3) 文档链改写（subCategory + category）──
const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
const files = [...manifest.overrideFiles, ...(manifest.collectionSplitFiles || []), 'tool-decisions.json'];
let n = 0;
const hitIds = new Set();
const rewrite = obj => {
  if (Array.isArray(obj)) { obj.forEach(rewrite); return; }
  if (!obj || typeof obj !== 'object') return;
  if (typeof obj.id === 'string' && MOVE[obj.id]) {
    if (obj.subCategory !== undefined) { obj.subCategory = { zh: MOVE[obj.id][0], en: MOVE[obj.id][1] }; n++; }
    if (CAT_CHANGE[obj.id] && obj.category !== undefined) {
      obj.category = { zh: CAT_CHANGE[obj.id], en: CAT_CHANGE[obj.id] === 'JWT安全' ? 'JWT Security' : CAT_CHANGE[obj.id] === 'API安全' ? 'API Security' : 'Framework Vulnerabilities' };
      n++;
    }
    hitIds.add(obj.id);
  }
  for (const k of Object.keys(obj)) rewrite(obj[k]);
};
for (const f of files) {
  const full = CR(f);
  if (!fs.existsSync(full)) continue;
  const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
  const b = n;
  rewrite(doc);
  if (n > b) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
}
console.log(`文档链改写 ${n} 处｜未承载:`, Object.keys(MOVE).filter(id => !hitIds.has(id)).join(',') || '无');
