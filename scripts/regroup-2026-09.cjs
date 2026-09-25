#!/usr/bin/env node
/**
 * 2026-09 大组重组：18 个 ≥10 条的主题组 → 50 个 3-9 条小组。
 * 机制：subCategory.{zh,en} = 新主题名 → synchronize relocate；文档链三处改写。
 * 一次性脚本：跑完即弃，不入 CI。
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

// ── 50 个新组声明（parentBranchId / id / 双语名）────────────────────────
const NEW_GROUPS = [
  // SQL
  { parentBranchId: 'sqli', id: 'sqli-blind-bool', zh: '布尔盲注与条件探测', en: 'Boolean Blind & Conditional Probing' },
  { parentBranchId: 'sqli', id: 'sqli-blind-time', zh: '时间盲注与带外', en: 'Time-Based Blind & Out-of-Band' },
  { parentBranchId: 'sqli', id: 'sqli-exploit-union', zh: 'UNION 与报错提取', en: 'UNION & Error-Based Extraction' },
  { parentBranchId: 'sqli', id: 'sqli-exploit-stacked', zh: '堆叠语句与写入', en: 'Stacked Queries & Writes' },
  { parentBranchId: 'sqli', id: 'sqli-carrier-http', zh: 'HTTP 载体与参数污染', en: 'HTTP Carriers & Parameter Pollution' },
  { parentBranchId: 'sqli', id: 'sqli-carrier-encoding', zh: '编码与 WAF 等价变体', en: 'Encoding & WAF Equivalents' },
  { parentBranchId: 'sqli', id: 'sqli-carrier-scenario', zh: '二阶与场景化注入', en: 'Second-Order & Contextual Injection' },
  // XSS
  { parentBranchId: 'xss', id: 'xss-dom-sink', zh: 'DOM XSS 源到汇', en: 'DOM XSS Source-to-Sink' },
  { parentBranchId: 'xss', id: 'xss-dom-mutation-framework', zh: '解析突变与前端框架', en: 'Mutation XSS & Frontend Frameworks' },
  { parentBranchId: 'xss', id: 'xss-encoding-bypass-encoding', zh: '编码与规范化绕过', en: 'Encoding & Normalization Bypass' },
  { parentBranchId: 'xss', id: 'xss-encoding-bypass-polyglot', zh: 'Polyglot 速查合集', en: 'Polyglot Cheatsheets' },
  { parentBranchId: 'xss', id: 'xss-csp-script-src', zh: '信任脚本源与回调滥用', en: 'Trusted Script Sources & Callback Abuse' },
  { parentBranchId: 'xss', id: 'xss-csp-base-nav', zh: 'base 与导航劫持', en: 'Base URI & Navigation Hijacking' },
  { parentBranchId: 'xss', id: 'xss-csp-exfil-frame', zh: '资源外联与帧', en: 'Resource Hints & Frames' },
  // SSRF
  { parentBranchId: 'ssrf', id: 'ssrf-protocol-file', zh: 'file 协议本地读取', en: 'file:// Local File Read' },
  { parentBranchId: 'ssrf', id: 'ssrf-protocol-gopher', zh: 'Gopher 内网协议攻击', en: 'Gopher Intranet Protocol Attacks' },
  { parentBranchId: 'ssrf', id: 'ssrf-protocol-reach', zh: 'Dict、FTP 与服务可达性', en: 'Dict, FTP & Service Reachability' },
  // RCE
  { parentBranchId: 'rce', id: 'rce-cmdi-basic', zh: '命令注入基础与盲注', en: 'Command Injection Basics & Blind' },
  { parentBranchId: 'rce', id: 'rce-cmdi-variant', zh: '分隔符与编码执行变体', en: 'Separator & Encoding Variants' },
  { parentBranchId: 'rce', id: 'rce-cmdi-context', zh: '场景化命令执行', en: 'Contextual Command Execution' },
  { parentBranchId: 'rce', id: 'rce-deser-java-dotnet', zh: 'Java 与 .NET 反序列化', en: 'Java & .NET Deserialization' },
  { parentBranchId: 'rce', id: 'rce-deser-php', zh: 'PHP 反序列化', en: 'PHP Deserialization' },
  { parentBranchId: 'rce', id: 'rce-deser-python-yaml', zh: 'Python 与 YAML 反序列化', en: 'Python & YAML Deserialization' },
  { parentBranchId: 'rce', id: 'rce-deser-ruby-node', zh: 'Ruby 与 Node.js 反序列化', en: 'Ruby & Node.js Deserialization' },
  { parentBranchId: 'rce', id: 'rce-webshell-php', zh: 'PHP WebShell', en: 'PHP WebShells' },
  { parentBranchId: 'rce', id: 'rce-webshell-asp', zh: 'ASP 与 .NET WebShell', en: 'ASP & .NET WebShells' },
  { parentBranchId: 'rce', id: 'rce-webshell-jsp', zh: 'JSP WebShell', en: 'JSP WebShells' },
  { parentBranchId: 'rce', id: 'rce-webshell-multi', zh: '多语言 WebShell', en: 'Multi-Language WebShells' },
  // XXE
  { parentBranchId: 'xxe', id: 'xxe-file-read-generic', zh: '通用与 XSLT 文件读取', en: 'Generic XML & XSLT File Read' },
  { parentBranchId: 'xxe', id: 'xxe-file-read-svg', zh: 'SVG 载体文件读取', en: 'SVG Carrier File Read' },
  { parentBranchId: 'xxe', id: 'xxe-file-read-office', zh: '办公文档文件读取', en: 'Office Document File Read' },
  { parentBranchId: 'xxe', id: 'xxe-blind-oob-blind', zh: 'Blind XXE 与带外验证', en: 'Blind XXE & OOB Validation' },
  { parentBranchId: 'xxe', id: 'xxe-blind-oob-dtd', zh: '外部 DTD 载体获取', en: 'External DTD Carrier Fetch' },
  // LFI/RFI
  { parentBranchId: 'lfi-rfi', id: 'lfi-rfi-wrapper-filter', zh: 'PHP Filter 源码读取', en: 'php://filter Source Read' },
  { parentBranchId: 'lfi-rfi', id: 'lfi-rfi-wrapper-data-expect', zh: 'data 与 expect 包装器', en: 'data:// & expect:// Wrappers' },
  { parentBranchId: 'lfi-rfi', id: 'lfi-rfi-wrapper-runtime', zh: '运行时流与包装器综合', en: 'Runtime Streams & Wrapper Misc' },
  { parentBranchId: 'lfi-rfi', id: 'lfi-rfi-wrapper-rfi', zh: 'RFI 远程包含', en: 'RFI Remote Inclusion' },
  // API
  { parentBranchId: 'api-security', id: 'api-graphql-authz', zh: 'GraphQL 授权与 IDOR', en: 'GraphQL Authorization & IDOR' },
  { parentBranchId: 'api-security', id: 'api-graphql-abuse', zh: '批量查询与资源滥用', en: 'Batch Queries & Resource Abuse' },
  // 认证
  { parentBranchId: 'auth-vulns', id: 'auth-vulns-jwt-alg', zh: 'JWT 算法与信任链', en: 'JWT Algorithms & Trust Chains' },
  { parentBranchId: 'auth-vulns', id: 'auth-vulns-jwt-persistent', zh: '持久登录令牌', en: 'Persistent Login Tokens' },
  { parentBranchId: 'auth-vulns', id: 'auth-vulns-jwt-weak', zh: '令牌强度与缺陷检测', en: 'Token Strength & Weakness Detection' },
  { parentBranchId: 'auth-vulns', id: 'auth-vulns-access-path', zh: '路径与方法授权绕过', en: 'Path & Method Authorization Bypass' },
  { parentBranchId: 'auth-vulns', id: 'auth-vulns-access-header', zh: '可信头与代理信任', en: 'Trusted Headers & Proxy Trust' },
  // 文件漏洞
  { parentBranchId: 'file-vulns', id: 'file-traversal-read-download', zh: '文件下载接口', en: 'File Download Interfaces' },
  { parentBranchId: 'file-vulns', id: 'file-traversal-read-normalize', zh: '路径穿越规范化', en: 'Path Traversal Normalization' },
  { parentBranchId: 'file-vulns', id: 'file-traversal-read-encoding', zh: '编码与过滤差异', en: 'Encoding & Filter Differentials' },
  { parentBranchId: 'file-vulns', id: 'file-traversal-read-targets', zh: '敏感目标与场景', en: 'Sensitive Targets & Scenarios' },
  // AI
  { parentBranchId: 'ai-security', id: 'ai-jailbreak-roleplay', zh: '角色扮演与渐进越狱', en: 'Roleplay & Progressive Jailbreak' },
  { parentBranchId: 'ai-security', id: 'ai-jailbreak-encoding', zh: '编码混淆与对抗后缀', en: 'Encoding Obfuscation & Adversarial Suffixes' },
];

// 被拆空的 18 个旧主题声明 id（从 payloadSubBranches 移除）
const REMOVED_SUBBRANCH_IDS = [
  'sqli-blind', 'sqli-exploit', 'sqli-carrier',
  'xss-dom-mutation', 'xss-encoding-bypass', 'xss-csp-bypass',
  'ssrf-protocol',
  'rce-cmdi', 'rce-deser', 'rce-webshell',
  'xxe-file-read', 'xxe-blind-oob',
  'lfi-rfi-wrapper',
  'api-graphql-abuse',
  'auth-vulns-jwt-token', 'auth-vulns-access-bypass',
  'file-traversal-read',
  'ai-jailbreak-bypass',
];

// WebShell PHP WAF 变体并入 webshell-php 的 wafBypass（模式切换）
const NEW_MERGES = [
  { sourceId: 'webshell-php-waf-ext', targetPayloadId: 'webshell-php', titlePrefix: 'WAF 绕过：' },
  { sourceId: 'webshell-php-waf-base64', targetPayloadId: 'webshell-php', titlePrefix: 'WAF 绕过：' },
  { sourceId: 'webshell-php-waf-str-rot13', targetPayloadId: 'webshell-php', titlePrefix: 'WAF 绕过：' },
  { sourceId: 'webshell-php-waf-rce', targetPayloadId: 'webshell-php', titlePrefix: 'WAF 绕过：' },
];

// ── 223 条 id → 新主题名（subCategory 双语）────────────────────────────
const g = (groupId) => {
  const grp = NEW_GROUPS.find(x => x.id === groupId);
  if (!grp) throw new Error(`unknown group ${groupId}`);
  return { zh: grp.zh, en: grp.en };
};
const ID_MAP = {
  // SQL·布尔盲注与条件探测 (6)
  'sqli-boolean-blind': g('sqli-blind-bool'),
  'sqli2-blind-conditional-time-and-predicate-probes': g('sqli-blind-bool'),
  'sqli2-like-between-in': g('sqli-blind-bool'),
  'sqli2-limit': g('sqli-blind-bool'),
  'sqli2-tricks-web-pentest-sql': g('sqli-blind-bool'),
  'sqli2-': g('sqli-blind-bool'),
  // SQL·时间盲注与带外 (5)
  'sqli-time-mysql': g('sqli-blind-time'),
  'sqli-time-mssql': g('sqli-blind-time'),
  'sqli-time-postgresql': g('sqli-blind-time'),
  'sqli-time-oracle': g('sqli-blind-time'),
  'sqli2-time-based-blind-sqli': g('sqli-blind-time'),
  // SQL·UNION 与报错提取 (5)
  'sqli-union-query': g('sqli-exploit-union'),
  'sqli2-union': g('sqli-exploit-union'),
  'sqli2-information-schema-table-and-column-enumeration': g('sqli-exploit-union'),
  'sqli-error-based': g('sqli-exploit-union'),
  'sqli2--ext': g('sqli-exploit-union'),
  // SQL·堆叠语句与写入 (6)
  'sqli-stacked-mysql': g('sqli-exploit-stacked'),
  'sqli-stacked-mssql': g('sqli-exploit-stacked'),
  'sqli-stacked-postgresql': g('sqli-exploit-stacked'),
  'sqli-stacked-destructive-dml': g('sqli-exploit-stacked'),
  'sqli2-direct-statement-and-catalog-selection': g('sqli-exploit-stacked'),
  'sqli2-stacked-and-conditional-delay-probes': g('sqli-exploit-stacked'),
  // SQL·HTTP 载体与参数污染 (5)
  'sqli-http-chunked-carrier': g('sqli-carrier-http'),
  'sqli-carrier-chunked': g('sqli-carrier-http'),
  'sqli-carrier-http-parameter-pollution': g('sqli-carrier-http'),
  'sqli-carrier-multipart': g('sqli-carrier-http'),
  'sqli-carrier-json': g('sqli-carrier-http'),
  // SQL·编码与 WAF 等价变体 (5)
  'sqli-expression-waf-variants': g('sqli-carrier-encoding'),
  'sqli-padding-comment-bypass': g('sqli-carrier-encoding'),
  'sqli2-union-extraction-lexical-encodings': g('sqli-carrier-encoding'),
  'sqli2-union-crlf-comment-encoding': g('sqli-carrier-encoding'),
  'httpbypass-unicode-sql': g('sqli-carrier-encoding'),
  // SQL·二阶与场景化注入 (8)
  'sqli-second-order': g('sqli-carrier-scenario'),
  'nosql2-sql': g('sqli-carrier-scenario'),
  'ai2-react-sql-via-agent': g('sqli-carrier-scenario'),
  'sqli2-wordpress-url-wrapped-union-query': g('sqli-carrier-scenario'),
  'auth2-login-sql-injection': g('sqli-carrier-scenario'),
  'browser-websocket-sql': g('sqli-carrier-scenario'),
  'api2-variable-sql-boundary': g('sqli-carrier-scenario'),
  'custom-sql注入速查表': g('sqli-carrier-scenario'),
  // XSS·DOM XSS 源到汇 (8)
  'xss-dom': g('xss-dom-sink'),
  'xss2-dom-xss': g('xss-dom-sink'),
  'xss2-document-write': g('xss-dom-sink'),
  'xss2-innerhtml': g('xss-dom-sink'),
  'xss2-eval-function': g('xss-dom-sink'),
  'xss2-location': g('xss-dom-sink'),
  'browser-websocket': g('xss-dom-sink'),
  'browser-ws-xss-via-websocket': g('xss-dom-sink'),
  // XSS·解析突变与前端框架 (2)
  'xss-mxss': g('xss-dom-mutation-framework'),
  'bizlogic-angularjs-1-6': g('xss-dom-mutation-framework'),
  // XSS·编码与规范化绕过 (9)
  'xss-unicode': g('xss-encoding-bypass-encoding'),
  'xss-filter-bypass': g('xss-encoding-bypass-encoding'),
  'xss-encoding': g('xss-encoding-bypass-encoding'),
  'xss2-html': g('xss-encoding-bypass-encoding'),
  'xss2-unicode-hex': g('xss-encoding-bypass-encoding'),
  'xss2-js': g('xss-encoding-bypass-encoding'),
  'httpbypass-waf-html': g('xss-encoding-bypass-encoding'),
  'httpbypass-waf-unicode-utf-8': g('xss-encoding-bypass-encoding'),
  'httpbypass-unicode-xss': g('xss-encoding-bypass-encoding'),
  // XSS·Polyglot 速查合集 (3)
  'xss-polyglot': g('xss-encoding-bypass-polyglot'),
  'xss2-xss-polyglot': g('xss-encoding-bypass-polyglot'),
  'xss2-xss-polyglot-payloads': g('xss-encoding-bypass-polyglot'),
  // XSS·信任脚本源与回调滥用 (4)
  'xss2-csp-external-script-source': g('xss-csp-script-src'),
  'xss2-csp-jsonp': g('xss-csp-script-src'),
  'xss2-csp-bypass-patterns': g('xss-csp-script-src'),
  'xss-csp-bypass': g('xss-csp-script-src'),
  // XSS·base 与导航劫持 (4)
  'xss2-csp-base-uri-retarget': g('xss-csp-base-nav'),
  'xss2-csp-base': g('xss-csp-base-nav'),
  'xss2-csp-meta-refresh-active-url': g('xss-csp-base-nav'),
  'xss2-csp-meta': g('xss-csp-base-nav'),
  // XSS·资源外联与帧 (3)
  'xss2-csp-resource-hint-egress': g('xss-csp-exfil-frame'),
  'xss2-csp-link': g('xss-csp-exfil-frame'),
  'xss2-csp-frame-active-content': g('xss-csp-exfil-frame'),
  // SSRF·file 协议本地读取 (4)
  'ssrf-protocol': g('ssrf-protocol-file'),
  'ssrf-file': g('ssrf-protocol-file'),
  'fileup-ssrf-file-uri-local-read': g('ssrf-protocol-file'),
  'cmdi2-ssrf-local-resource-uri-schemes': g('ssrf-protocol-file'),
  // SSRF·Gopher 内网协议攻击 (5)
  'ssrf-gopher': g('ssrf-protocol-gopher'),
  'cmdi2-ssrf-gopher-redis-protocol': g('ssrf-protocol-gopher'),
  'cmdi2-gopher-redis-resp-file-write-sequence': g('ssrf-protocol-gopher'),
  'cmdi2-gopher-mysql-handshake-fragment': g('ssrf-protocol-gopher'),
  'cmdi2-gopher-fastcgi-record-fragment': g('ssrf-protocol-gopher'),
  // SSRF·Dict、FTP 与服务可达性 (3)
  'ssrf-dict': g('ssrf-protocol-reach'),
  'ssrf-redis': g('ssrf-protocol-reach'),
  'cmdi2-ssrf-ftp-and-tftp-schemes': g('ssrf-protocol-reach'),
  // RCE·命令注入基础与盲注 (2)
  'rce-command-injection': g('rce-cmdi-basic'),
  'rce-cmd-blind': g('rce-cmdi-basic'),
  // RCE·分隔符与编码执行变体 (7)
  'cmdi2-': g('rce-cmdi-variant'),
  'cmdi2--ext': g('rce-cmdi-variant'),
  'cmdi2-command-separators': g('rce-cmdi-variant'),
  'cmdi2-hex': g('rce-cmdi-variant'),
  'cmdi2-base64': g('rce-cmdi-variant'),
  'cmdi2-waf-bypass-base64': g('rce-cmdi-variant'),
  'cmdi2-waf-bypass-variable-expansion': g('rce-cmdi-variant'),
  // RCE·场景化命令执行 (5)
  'bizlogic-rce': g('rce-cmdi-context'),
  'webshell-shellshock-via-curl-d4t4s3c': g('rce-cmdi-context'),
  'sqli2-sqlserver-xp-cmdshell-impact': g('rce-cmdi-context'),
  'cmdi2-php-expect-wrapper-command-boundary': g('rce-cmdi-context'),
  'browser-websocket-ext': g('rce-cmdi-context'),
  // RCE·Java 与 .NET 反序列化 (4)
  'rce-deserialize-java': g('rce-deser-java-dotnet'),
  'nosql2-java-commons-collections': g('rce-deser-java-dotnet'),
  'nosql2-net': g('rce-deser-java-dotnet'),
  'rce-deserialize': g('rce-deser-java-dotnet'),
  // RCE·PHP 反序列化 (3)
  'rce-deserialize-php': g('rce-deser-php'),
  'nosql2-php-phar': g('rce-deser-php'),
  'webshell-php-ext': g('rce-deser-php'),
  // RCE·Python 与 YAML 反序列化 (5)
  'nosql2-python-pickle': g('rce-deser-python-yaml'),
  'webshell-python-pickle-rce': g('rce-deser-python-yaml'),
  'webshell-ruby-yaml': g('rce-deser-python-yaml'),
  'webshell-python-pyyaml-object-apply-boundary': g('rce-deser-python-yaml'),
  'nosql2-yaml': g('rce-deser-python-yaml'),
  // RCE·Ruby 与 Node.js 反序列化 (4)
  'nosql2-ruby-marshal': g('rce-deser-ruby-node'),
  'webshell-ruby-ext': g('rce-deser-ruby-node'),
  'nosql2-node-js': g('rce-deser-ruby-node'),
  'webshell-node-js': g('rce-deser-ruby-node'),
  // RCE·PHP WebShell (4)
  'webshell-php': g('rce-webshell-php'),
  'webshell-php-short-echo-backtick-boundary': g('rce-webshell-php'),
  'webshell-php-flag': g('rce-webshell-php'),
  'webshell-php-server-side-command-scripts': g('rce-webshell-php'),
  // RCE·ASP 与 .NET WebShell (4)
  'webshell-asp-inline-expression-boundary': g('rce-webshell-asp'),
  'webshell-asp-aspx': g('rce-webshell-asp'),
  'webshell-asp': g('rce-webshell-asp'),
  'webshell-asp-dotnet-dynamic-execution-boundary': g('rce-webshell-asp'),
  // RCE·JSP WebShell (3)
  'webshell-jsp-java': g('rce-webshell-jsp'),
  'webshell-jsp': g('rce-webshell-jsp'),
  'webshell-jsp-runtime-exec-boundary': g('rce-webshell-jsp'),
  // RCE·多语言 WebShell (5)
  'webshell-python': g('rce-webshell-multi'),
  'webshell-node-js-express': g('rce-webshell-multi'),
  'webshell-ruby': g('rce-webshell-multi'),
  'webshell-go': g('rce-webshell-multi'),
  'webshell-perl': g('rce-webshell-multi'),
  // XXE·通用与 XSLT 文件读取 (4)
  'xxe-file-read': g('xxe-file-read-generic'),
  'ssti2-xxe-generic-xml-local-file-entities': g('xxe-file-read-generic'),
  'ssti2-generic-xml-xxe-resource-entity': g('xxe-file-read-generic'),
  'inject2-xslt-ext': g('xxe-file-read-generic'),
  // XXE·SVG 载体文件读取 (5)
  'ssti2-xxe-svg-local-file-entity': g('xxe-file-read-svg'),
  'ssti2-svg-xxe': g('xxe-file-read-svg'),
  'ssti2-xxe-svg-xxe': g('xxe-file-read-svg'),
  'ssti2-svg-xxe-general-entity-resources': g('xxe-file-read-svg'),
  'ssti2-svg-xxe-php-filter-entity': g('xxe-file-read-svg'),
  // XXE·办公文档文件读取 (5)
  'ssti2-xxe-spreadsheet-local-file-entity': g('xxe-file-read-office'),
  'ssti2-docx-xxe-general-entity-resources': g('xxe-file-read-office'),
  'ssti2-docx-xxe-php-filter-entity': g('xxe-file-read-office'),
  'ssti2-xlsx-sharedstrings-xxe-general-entity-resources': g('xxe-file-read-office'),
  'ssti2-xlsx-sharedstrings-xxe-php-filter-entity': g('xxe-file-read-office'),
  // XXE·Blind XXE 与带外验证 (7)
  'xxe-blind': g('xxe-blind-oob-blind'),
  'xxe-oob': g('xxe-blind-oob-blind'),
  'xxe-dtd': g('xxe-blind-oob-blind'),
  'ssti2-xxe-blind-out-of-band': g('xxe-blind-oob-blind'),
  'ssti2-xxe-error-based': g('xxe-blind-oob-blind'),
  'ssti2-xxe': g('xxe-blind-oob-blind'),
  'ssti2-xxe-cdata': g('xxe-blind-oob-blind'),
  // XXE·外部 DTD 载体获取 (4)
  'ssti2-xxe-external-dtd-fetches': g('xxe-blind-oob-dtd'),
  'ssti2-docx-xxe-external-dtd': g('xxe-blind-oob-dtd'),
  'ssti2-xlsx-sharedstrings-xxe-external-dtd': g('xxe-blind-oob-dtd'),
  'ssti2-svg-xxe-external-dtd': g('xxe-blind-oob-dtd'),
  // LFI·PHP Filter 源码读取 (4)
  'lfi-filter-source-read-boundary': g('lfi-rfi-wrapper-filter'),
  'fileup-php-filter-source-read-boundary': g('lfi-rfi-wrapper-filter'),
  'cmdi2-php-filter-source-read': g('lfi-rfi-wrapper-filter'),
  'fileup-lfi-filter-transform-boundary': g('lfi-rfi-wrapper-filter'),
  // LFI·data 与 expect 包装器 (5)
  'lfi-data-wrapper-read-boundary': g('lfi-rfi-wrapper-data-expect'),
  'fileup-php-data-wrapper-include-boundary': g('lfi-rfi-wrapper-data-expect'),
  'fileup-lfi-data-wrapper-include-boundary': g('lfi-rfi-wrapper-data-expect'),
  'fileup-php-expect-wrapper-extension-boundary': g('lfi-rfi-wrapper-data-expect'),
  'fileup-lfi-expect-wrapper-extension-boundary': g('lfi-rfi-wrapper-data-expect'),
  // LFI·运行时流与包装器综合 (3)
  'lfi-input-stream-read-boundary': g('lfi-rfi-wrapper-runtime'),
  'cmdi2-php-runtime-stream-boundaries': g('lfi-rfi-wrapper-runtime'),
  'fileup-php-stream-wrapper-inclusion': g('lfi-rfi-wrapper-runtime'),
  // LFI·RFI 远程包含 (2)
  'rfi-http-marker-include-boundary': g('lfi-rfi-wrapper-rfi'),
  'rfi-http-scheme-case-boundary': g('lfi-rfi-wrapper-rfi'),
  // API·GraphQL 授权与 IDOR (6)
  'api2-mutation-idor': g('api-graphql-authz'),
  'api2-': g('api-graphql-authz'),
  'api2-directive': g('api-graphql-authz'),
  'auth2-graphql': g('api-graphql-authz'),
  'api2-variable-mass-assignment': g('api-graphql-authz'),
  'api2-subscription': g('api-graphql-authz'),
  // API·批量查询与资源滥用 (6)
  'api2-alias': g('api-graphql-abuse'),
  'api2-batch-query': g('api-graphql-abuse'),
  'api2-dos': g('api-graphql-abuse'),
  'api2-variable-query-cost': g('api-graphql-abuse'),
  'api2-fragment': g('api-graphql-abuse'),
  'api2-variable-structured-filter': g('api-graphql-abuse'),
  // 认证·JWT 算法与信任链 (5)
  'auth-jwt-none': g('auth-vulns-jwt-alg'),
  'auth-jwt-alg-confusion': g('auth-vulns-jwt-alg'),
  'auth-jwt-kid-validation': g('auth-vulns-jwt-alg'),
  'auth-jwt-jwk-jku-trust': g('auth-vulns-jwt-alg'),
  'auth-jwt-claim-validation': g('auth-vulns-jwt-alg'),
  // 认证·持久登录令牌 (3)
  'auth-remember-token-integrity': g('auth-vulns-jwt-persistent'),
  'auth-remember-token-replay': g('auth-vulns-jwt-persistent'),
  'auth-shiro-rememberme-deserialization': g('auth-vulns-jwt-persistent'),
  // 认证·令牌强度与缺陷检测 (7)
  'auth2-token': g('auth-vulns-jwt-weak'),
  'auth2-bearer-null-token-handling': g('auth-vulns-jwt-weak'),
  'auth2-referer-token': g('auth-vulns-jwt-weak'),
  'auth2-token-ext': g('auth-vulns-jwt-weak'),
  'auth2-token-token': g('auth-vulns-jwt-weak'),
  'auth2-base64-token': g('auth-vulns-jwt-weak'),
  'bizlogic-token-session': g('auth-vulns-jwt-weak'),
  // 认证·路径与方法授权绕过 (6)
  'auth-method-path-normalization': g('auth-vulns-access-path'),
  'auth2-401-403-bypass-techniques': g('auth-vulns-access-path'),
  'httpbypass-': g('auth-vulns-access-path'),
  'httpbypass-url': g('auth-vulns-access-path'),
  'httpbypass-trusted-header-and-wordpress-route-bypass': g('auth-vulns-access-path'),
  'auth2-client-controlled-privilege-parameters': g('auth-vulns-access-path'),
  // 认证·可信头与代理信任 (6)
  'auth-trusted-proxy-header': g('auth-vulns-access-header'),
  'httpbypass--ext': g('auth-vulns-access-header'),
  'httpbypass-referer-origin': g('auth-vulns-access-header'),
  'auth2-referer': g('auth-vulns-access-header'),
  'httpbypass-crlf-proxy-header-injection': g('auth-vulns-access-header'),
  'httpbypass-host-override-header-trust': g('auth-vulns-access-header'),
  // 文件·文件下载接口 (3)
  'file-download-path-normalization': g('file-traversal-read-download'),
  'file-download-stream-wrapper-boundary': g('file-traversal-read-download'),
  'file-download-legacy-terminator': g('file-traversal-read-download'),
  // 文件·路径穿越规范化 (4)
  'file-traversal-posix-normalization': g('file-traversal-read-normalize'),
  'file-traversal-windows-normalization': g('file-traversal-read-normalize'),
  'file-traversal-unc-path-resolution': g('file-traversal-read-normalize'),
  'file-traversal-legacy-terminator': g('file-traversal-read-normalize'),
  // 文件·编码与过滤差异 (5)
  'fileup-path-traversal-encoding-variants': g('file-traversal-read-encoding'),
  'httpbypass-path-traversal-filter-differentials': g('file-traversal-read-encoding'),
  'httpbypass-iis-cgi-double-encoded-traversal': g('file-traversal-read-encoding'),
  'httpbypass-unicode': g('file-traversal-read-encoding'),
  'httpbypass-punycode': g('file-traversal-read-encoding'),
  // 文件·敏感目标与场景 (3)
  'fileup-sensitive-local-file-targets': g('file-traversal-read-targets'),
  'auth2-session-id-path-traversal': g('file-traversal-read-targets'),
  'api2-variable-path-boundary': g('file-traversal-read-targets'),
  // AI·角色扮演与渐进越狱 (5)
  'ai2-dan-do-anything-now': g('ai-jailbreak-roleplay'),
  'ai2-grandma': g('ai-jailbreak-roleplay'),
  'ai2-virtual-scenario-bypass': g('ai-jailbreak-roleplay'),
  'ai2-15-reverse-psychology': g('ai-jailbreak-roleplay'),
  'ai2-crescendo': g('ai-jailbreak-roleplay'),
  // AI·编码混淆与对抗后缀 (7)
  'ai2-hex': g('ai-jailbreak-encoding'),
  'ai2-unicode': g('ai-jailbreak-encoding'),
  'ai2-19-emoji': g('ai-jailbreak-encoding'),
  'ai2-mixed-case-bypass': g('ai-jailbreak-encoding'),
  'ai2-typo-tricks': g('ai-jailbreak-encoding'),
  'ai2-12-multi-language': g('ai-jailbreak-encoding'),
  'ai2-18-adversarial-suffix': g('ai-jailbreak-encoding'),
};

// ── 执行 ──────────────────────────────────────────────────────────────
const main = () => {
  const mapIds = new Set(Object.keys(ID_MAP));
  const mergeIds = new Set(NEW_MERGES.map(m => m.sourceId));
  for (const id of mapIds) {
    if (mergeIds.has(id)) throw new Error(`${id} 同时在 ID_MAP 和 NEW_MERGES：merge source 不需要 subCategory patch`);
  }

  // 1) tool-decisions.json
  const decisionsPath = CR('tool-decisions.json');
  const decisions = JSON.parse(fs.readFileSync(decisionsPath, 'utf8'));
  const before = decisions.payloadSubBranches.length;
  decisions.payloadSubBranches = decisions.payloadSubBranches.filter(b => !REMOVED_SUBBRANCH_IDS.includes(b.id));
  // 新声明按 parentBranchId 插到该分支最后一个声明之后（保持树内同分支相邻）
  const declFor = grp => ({ parentBranchId: grp.parentBranchId, id: grp.id, name: { zh: grp.zh, en: grp.en } });
  const byParent = new Map();
  for (const grp of NEW_GROUPS) {
    if (!byParent.has(grp.parentBranchId)) byParent.set(grp.parentBranchId, []);
    byParent.get(grp.parentBranchId).push(declFor(grp));
  }
  for (const [parent, decls] of byParent) {
    let lastIdx = -1;
    decisions.payloadSubBranches.forEach((b, i) => { if (b.parentBranchId === parent) lastIdx = i; });
    if (lastIdx === -1) decisions.payloadSubBranches.push(...decls);
    else decisions.payloadSubBranches.splice(lastIdx + 1, 0, ...decls);
  }
  decisions.payloadMerges.push(...NEW_MERGES);
  fs.writeFileSync(decisionsPath, JSON.stringify(decisions, null, 2) + '\n');
  console.log(`tool-decisions: payloadSubBranches ${before} → ${decisions.payloadSubBranches.length}（-18/+50），payloadMerges +${NEW_MERGES.length}`);

  // 2) 文档链 subCategory 改写（overrideFiles + collectionSplitFiles）
  const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
  const files = [...manifest.overrideFiles, ...(manifest.collectionSplitFiles || [])];
  const stats = { touchedFiles: 0, replaced: 0, cs2OnlyIds: new Set() };
  const replacedIn = new Map(); // id → [file...]

  const rewrite = (obj, file) => {
    if (Array.isArray(obj)) { obj.forEach(v => rewrite(v, file)); return; }
    if (!obj || typeof obj !== 'object') return;
    if (typeof obj.id === 'string' && mapIds.has(obj.id) && obj.subCategory !== undefined) {
      obj.subCategory = { ...ID_MAP[obj.id] };
      stats.replaced++;
      if (!replacedIn.has(obj.id)) replacedIn.set(obj.id, []);
      replacedIn.get(obj.id).push(file);
    }
    for (const key of Object.keys(obj)) rewrite(obj[key], file);
  };

  for (const file of files) {
    const full = CR(file);
    const raw = fs.readFileSync(full, 'utf8');
    const doc = JSON.parse(raw);
    const before2 = stats.replaced;
    rewrite(doc, file);
    if (stats.replaced > before2) {
      fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
      stats.touchedFiles++;
    }
  }

  // 3) 覆盖审计：哪些 id 没有任何可生效的改写点 / 只落在 cs2 文档
  const missing = [];
  const cs2Only = [];
  for (const id of mapIds) {
    const spots = replacedIn.get(id) || [];
    if (!spots.length) { missing.push(id); continue; }
    const spotDocs = spots.map(f => JSON.parse(fs.readFileSync(CR(f), 'utf8')));
    const inSplit = spots.some((f, i) => (JSON.parse(fs.readFileSync(CR(f), 'utf8')).collectionSplits !== undefined));
    const inCs3 = spotDocs.some(d => d.contentStandard >= 3);
    if (!inSplit && !inCs3) cs2Only.push(id);
  }
  console.log(`文档链改写：${stats.touchedFiles} 个文件 / ${stats.replaced} 处 subCategory`);
  console.log(`未找到改写点的 id（${missing.length}）:`, missing.join(', ') || '无');
  console.log(`仅 cs2 文档承载（需 bump 或换承载）的 id（${cs2Only.length}）:`, cs2Only.join(', ') || '无');
};

main();
