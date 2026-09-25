#!/usr/bin/env node
/**
 * 2026-09 终审批次 2：单条组碎片归并（SSTI 10 引擎组并族、全单条组分支合组等，40 条 → 11 组）。
 * 一次性脚本：跑完即弃。
 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

// 40 条 id → 目标组（zh/en）。现有组用树上的精确名；新组在此定义。
const M = {
  // SSTI → 4 个现有族组
  'ssti-jinja2': ['Jinja2 与 Python 系', 'Jinja2 & Python Family'],
  'ssti-mako': ['Jinja2 与 Python 系', 'Jinja2 & Python Family'],
  'ssti-tornado': ['Jinja2 与 Python 系', 'Jinja2 & Python Family'],
  'ssti-django': ['Jinja2 与 Python 系', 'Jinja2 & Python Family'],
  'ssti-freemarker': ['Java 模板引擎族', 'Java Template Engines'],
  'ssti-velocity': ['Java 模板引擎族', 'Java Template Engines'],
  'ssti-thymeleaf': ['Java 模板引擎族', 'Java Template Engines'],
  'ssti-smarty': ['PHP 模板引擎族', 'PHP Template Engines'],
  'ssti-erb': ['其他引擎与二阶注入', 'Other Engines & Second-Order'],
  'ssti-pug': ['其他引擎与二阶注入', 'Other Engines & Second-Order'],
  // WebSocket → 新 2 组
  'websocket-cross-origin-boundary': ['跨站劫持与握手校验', 'Cross-Site Hijack & Handshake'],
  'browser-ws-cswsh-origin': ['跨站劫持与握手校验', 'Cross-Site Hijack & Handshake'],
  'browser-ws-host-origin': ['跨站劫持与握手校验', 'Cross-Site Hijack & Handshake'],
  'websocket-channel-authorization-boundary': ['消息级授权与生命周期', 'Message AuthZ & Lifecycle'],
  'browser-ws': ['消息级授权与生命周期', 'Message AuthZ & Lifecycle'],
  // HTTP 响应分割 → 新 1 组
  'httpbypass-crlf': ['CRLF 注入与响应分割', 'CRLF Injection & Response Splitting'],
  'httpbypass-crlf-set-cookie': ['CRLF 注入与响应分割', 'CRLF Injection & Response Splitting'],
  'httpbypass-crlf-location': ['CRLF 注入与响应分割', 'CRLF Injection & Response Splitting'],
  'inject2-crlf-injection-crlf-injection': ['CRLF 注入与响应分割', 'CRLF Injection & Response Splitting'],
  'auth2-set-cookie-crlf': ['CRLF 注入与响应分割', 'CRLF Injection & Response Splitting'],
  // Host Header → 新 1 组
  'httpbypass-host': ['Host 头路由绕过', 'Host Header Routing Bypass'],
  'httpbypass-uri': ['Host 头路由绕过', 'Host Header Routing Bypass'],
  // DoS → 新 1 组
  'bizlogic-javascript-redos': ['正则表达式拒绝服务', 'Regex Denial of Service'],
  'bizlogic-evil-regex': ['正则表达式拒绝服务', 'Regex Denial of Service'],
  'bizlogic-redos': ['正则表达式拒绝服务', 'Regex Denial of Service'],
  // Exchange → 新 1 组
  'proxylogon': ['已知利用链与访问边界', 'Known Exploit Chains & Access'],
  'proxyshell': ['已知利用链与访问边界', 'Known Exploit Chains & Access'],
  'exchange-proxytoken': ['已知利用链与访问边界', 'Known Exploit Chains & Access'],
  'exchange-mailbox-access': ['已知利用链与访问边界', 'Known Exploit Chains & Access'],
  // CSRF → 1 新组 + 2 现有组
  'csrf-basic': ['载荷构造与请求形状', 'Payload Crafting & Request Shapes'],
  'csrf-json': ['载荷构造与请求形状', 'Payload Crafting & Request Shapes'],
  'auth2-get-based-csrf-via-img-script': ['载荷构造与请求形状', 'Payload Crafting & Request Shapes'],
  'csrf-referer-bypass': ['核心防护绕过', 'Core Protection Bypass'],
  'csrf-flash': ['OAuth 与遗留跨域边界', 'OAuth & Legacy Cross-Origin'],
  // 重定向 → 新 1 组
  'redirect-basic': ['基础解析与验证样例', 'Basic Parsing & Validation Samples'],
  'redirect-bypass': ['基础解析与验证样例', 'Basic Parsing & Validation Samples'],
  // SSRF → 现有组
  'ssrf-cloud-gcp': ['云元数据获取', 'Cloud Metadata Fetch'],
  'ssrf-cloud-azure': ['云元数据获取', 'Cloud Metadata Fetch'],
  'ssrf-mysql': ['Dict、FTP 与服务可达性', 'Dict, FTP & Service Reachability'],
  // 文件 → 现有组
  'rce-file-upload': ['上传解析绕过', 'Upload Parsing Bypass'],
};

// 新组声明（现有族组不在其中）
const NEW_DECLS = [
  { parentBranchId: 'websocket-security', id: 'ws-hijack-handshake', zh: '跨站劫持与握手校验', en: 'Cross-Site Hijack & Handshake' },
  { parentBranchId: 'websocket-security', id: 'ws-msg-authz-lifecycle', zh: '消息级授权与生命周期', en: 'Message AuthZ & Lifecycle' },
  { parentBranchId: 'http-response-splitting', id: 'crlf-splitting', zh: 'CRLF 注入与响应分割', en: 'CRLF Injection & Response Splitting' },
  { parentBranchId: 'host-header-security', id: 'host-routing-bypass', zh: 'Host 头路由绕过', en: 'Host Header Routing Bypass' },
  { parentBranchId: 'denial-of-service', id: 'redos', zh: '正则表达式拒绝服务', en: 'Regex Denial of Service' },
  { parentBranchId: 'exchange-attack', id: 'exchange-known-chains', zh: '已知利用链与访问边界', en: 'Known Exploit Chains & Access' },
  { parentBranchId: 'csrf', id: 'csrf-payload-shapes', zh: '载荷构造与请求形状', en: 'Payload Crafting & Request Shapes' },
  { parentBranchId: 'web-redirect', id: 'redirect-basic-samples', zh: '基础解析与验证样例', en: 'Basic Parsing & Validation Samples' },
];

// 被拆空待删的旧单条组（按组名删声明）
const REMOVE_BY_NAME = [
  'Jinja 模板求值边界', 'FreeMarker 模板求值边界', 'Velocity 模板求值边界', 'Thymeleaf 模板求值边界',
  'Smarty 模板求值边界', 'Mako 模板求值边界', 'Tornado 模板求值边界', 'Django 模板求值边界',
  'ERB 模板求值边界', 'Pug 模板求值边界',
  '跨站 WebSocket 会话边界验证', 'WebSocket 会话生命周期与频道授权', '跨站 WebSocket 劫持的 Origin 校验',
  'WebSocket 握手 Host 与 Origin 路由校验', 'WebSocket 消息级认证与授权绕过',
  'CRLF 分隔符编码探测', '通用响应 Set-Cookie CRLF 注入', 'CRLF Location 重定向注入',
  'HTTP CRLF 响应头注入', '认证会话 Set-Cookie CRLF 注入',
  'Host 头内部虚拟主机绕过', '绝对形式 Request-Target 路由绕过',
  'JavaScript 正则表达式拒绝服务', 'ReDoS 长度阶梯验证输入', '通用正则表达式拒绝服务输入',
  'Exchange ProxyLogon 补丁回归', 'Exchange ProxyShell 补丁回归', 'Exchange ProxyToken 授权回归',
  'Exchange 邮箱访问边界预检',
  'CSRF 请求形状基础验证', 'JSON 接口 CSRF 边界验证', 'CSRF Referer 校验边界', 'Flash 跨域策略遗留审计',
  '基础开放重定向目标解析', '开放重定向解析差异样例',
  'GCP Compute Metadata SSRF 验证', 'Azure 实例元数据 SSRF 验证', 'MySQL 端口 SSRF 可达性验证',
  '文件上传存储与处理器边界验证',
];

const main = () => {
  const mapIds = new Set(Object.keys(M));
  // 1) tool-decisions：删旧声明（按名）+ 增新声明（插到同父分支声明后）
  const tdPath = CR('tool-decisions.json');
  const td = JSON.parse(fs.readFileSync(tdPath, 'utf8'));
  const before = td.payloadSubBranches.length;
  td.payloadSubBranches = td.payloadSubBranches.filter(b => !REMOVE_BY_NAME.includes(b.name?.zh));
  const byParent = new Map();
  for (const d of NEW_DECLS) {
    if (!byParent.has(d.parentBranchId)) byParent.set(d.parentBranchId, []);
    byParent.get(d.parentBranchId).push({ parentBranchId: d.parentBranchId, id: d.id, name: { zh: d.zh, en: d.en } });
  }
  for (const [parent, decls] of byParent) {
    let lastIdx = -1;
    td.payloadSubBranches.forEach((b, i) => { if (b.parentBranchId === parent) lastIdx = i; });
    if (lastIdx === -1) td.payloadSubBranches.push(...decls);
    else td.payloadSubBranches.splice(lastIdx + 1, 0, ...decls);
  }
  fs.writeFileSync(tdPath, JSON.stringify(td, null, 2) + '\n');
  console.log(`payloadSubBranches ${before} → ${td.payloadSubBranches.length}`);

  // 2) 文档链 subCategory 改写
  const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
  const files = [...manifest.overrideFiles, ...(manifest.collectionSplitFiles || [])];
  let n = 0;
  const hitIds = new Set();
  const rewrite = obj => {
    if (Array.isArray(obj)) { obj.forEach(rewrite); return; }
    if (!obj || typeof obj !== 'object') return;
    if (typeof obj.id === 'string' && mapIds.has(obj.id) && obj.subCategory !== undefined) {
      obj.subCategory = { zh: M[obj.id][0], en: M[obj.id][1] };
      n++; hitIds.add(obj.id);
    }
    for (const k of Object.keys(obj)) rewrite(obj[k]);
  };
  for (const f of files) {
    const full = CR(f);
    const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
    const b = n;
    rewrite(doc);
    if (n > b) { fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n'); }
  }
  console.log(`改写 ${n} 处；无文档承载的 id：`, [...mapIds].filter(id => !hitIds.has(id)).join(',') || '无');
};

main();
