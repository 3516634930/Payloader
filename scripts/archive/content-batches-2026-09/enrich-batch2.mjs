import { readFileSync, writeFileSync } from 'fs';

const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');
let n = 0;

function E(id, ac, anZh, anEn, ...refs) {
  const idx = c.indexOf("id: '" + id + "'");
  if (idx < 0) { console.log('NF', id); return; }
  const sec = c.slice(idx, idx + 8000);
  const tut = sec.indexOf('    tutorial: {');
  if (tut < 0) { console.log('NT', id); return; }
  const acs = ac.map(s =>
    "      { title: { zh: '" + s[0].replace(/'/g,"\\'") + "', en: '" + s[1].replace(/'/g,"\\'") + "' }, description: { zh: '" + s[2].replace(/'/g,"\\'") + "', en: '" + s[3].replace(/'/g,"\\'") + "' } },"
  ).join('\n');
  const rf = refs.map(r => "      '" + r + "',").join('\n');
  const ex = "    attackChain: [\n" + acs + "\n    ],\n    analysis: { zh: '" + anZh.replace(/'/g,"\\'") + "', en: '" + anEn.replace(/'/g,"\\'") + "' },\n    references: [\n" + rf + "\n    ],\n";
  c = c.slice(0, idx + tut) + ex + c.slice(idx + tut);
  console.log('OK', id); n++;
}

// XSS (12)
['xss-reflected','xss-stored','xss-dom','xss-csp-bypass','xss-mxss','xss-unicode','xss-filter-bypass','xss-encoding','xss-polyglot','xss-cookie-theft','xss-keylogger','xss-beef'].forEach(id => {
  E(id,
    [[id==='xss-reflected'?'定位输出上下文':'定位注入入口','Identify entry point','确认用户输入落在HTML/属性/JS/CSS哪个上下文中，选择对应的闭合方式。','Identify which context user input lands in and select the appropriate closure method.'],
     ['构造Payload','Craft payload','根据上下文选择标签闭合、属性逃逸、JS逃逸或URL伪协议等闭合技术。','Select closure technique based on context: tag break, attribute escape, JS escape, or URL pseudo-protocol.'],
     ['绕过过滤与WAF','Bypass filters & WAF','使用事件处理器、编码混淆、大小写混写和标签拆分绕过过滤器和WAF。','Bypass filters and WAF using event handlers, encoding, case mixing, and tag splitting.'],
     ['验证并升级影响','Verify & escalate impact','从alert升级到Cookie窃取、键盘记录、钓鱼或BeEF控制，评估真实危害。','Escalate from alert to cookie theft, keylogging, phishing, or BeEF control.']],
    'XSS跨站脚本攻击是OWASP Top 10常客。攻击者注入恶意脚本在受害者浏览器中执行，可窃取Cookie、会话、敏感数据，甚至完全控制浏览器。输出编码是最核心的防御手段。',
    'XSS is an OWASP Top 10 staple. Attackers inject malicious scripts executed in victim browsers, enabling cookie theft, session hijacking, data exfiltration, and full browser control. Output encoding is the core defense.',
    'https://portswigger.net/web-security/cross-site-scripting','https://owasp.org/www-community/attacks/xss/','https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
  );
});

// SSRF (12)
['ssrf-basic','ssrf-cloud-aws','ssrf-cloud-gcp','ssrf-cloud-azure','ssrf-protocol','ssrf-gopher','ssrf-dict','ssrf-file','ssrf-bypass','ssrf-dns-rebinding','ssrf-redis','ssrf-mysql'].forEach(id => {
  E(id,
    [[id.startsWith('ssrf-cloud')?'识别云环境':'探测SSRF入口','Identify target','定位接收URL/主机/IP的输入参数，确认服务端是否发起对外请求。','Locate inputs accepting URL/host/IP parameters and confirm outbound requests.'],
     ['构造内网/云请求','Craft internal/cloud request','使用内网地址(127.0.0.1/10.0.0.0/192.168.0.0)或云元数据端点(169.254.169.254)发起请求。','Use internal addresses or cloud metadata endpoints to initiate requests.'],
     ['绕过IP/协议限制','Bypass IP/protocol restrictions','使用十进制/八进制/IPv6 IP表示、DNS重绑定、HTTP重定向和协议走私绕过。','Bypass via decimal/octal/IPv6 IP forms, DNS rebinding, HTTP redirects, and protocol smuggling.'],
     ['验证并提取数据','Verify & extract data','确认SSRF可达后读取云凭据、内网服务信息或攻击内网应用。','After confirming SSRF reachability, read cloud credentials, internal service info, or attack internal apps.']],
    'SSRF是服务端请求伪造攻击——利用服务端HTTP客户端访问内网、云元数据和本地服务。是最危险的Web漏洞之一，可导致云凭据泄露、内网横向移动和RCE。',
    'SSRF exploits server-side HTTP clients to access internal networks, cloud metadata, and local services. One of the most dangerous web vulnerabilities leading to cloud credential leaks, lateral movement, and RCE.',
    'https://portswigger.net/web-security/ssrf','https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
  );
});

// XXE (9)
['xxe-basic','xxe-blind','xxe-oob','xxe-ssrf','xxe-rce','xxe-file-read','xxe-dtd','xxe-xlsx','xxe-docx'].forEach(id => {
  E(id,
    [[id==='xxe-basic'?'确认XML解析':'确认XML入口','Identify XML entry','确认应用是否解析用户提供的XML，检查Content-Type和响应是否处理XML。','Confirm the app parses user-supplied XML; check Content-Type and response handling.'],
     ['注入外部实体','Inject external entity','使用DOCTYPE声明外部实体读取文件(file://)或发起SSRF(http://)。','Declare external entities via DOCTYPE to read files (file://) or initiate SSRF (http://).'],
     ['绕过限制','Bypass restrictions','当基础XXE被拦截时使用参数实体、外部DTD、CDATA包装和编码绕过。','When basic XXE is blocked, use parameter entities, external DTDs, CDATA wrapping, and encoding bypass.'],
     ['升级利用','Escalate exploitation','从文件读取升级到SSRF、拒绝服务(Billion Laughs)或通过expect:///php://实现RCE。','Escalate from file read to SSRF, DoS (Billion Laughs), or RCE via expect:///php://.']],
    'XXE(XML外部实体注入)利用XML解析器处理外部实体的能力读取文件、发起SSRF或拒绝服务。尽管现代XML解析器默认禁用外部实体，但遗留系统和错误配置仍广泛存在。',
    'XXE exploits XML parser external entity processing to read files, initiate SSRF, or cause DoS. Though modern parsers disable external entities by default, legacy systems and misconfigurations remain widespread.',
    'https://portswigger.net/web-security/xxe','https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'
  );
});

// CSRF (8)
['csrf-basic','csrf-json','csrf-bypass','csrf-samesite','csrf-token-bypass','csrf-referer-bypass','csrf-flash','csrf-cors'].forEach(id => {
  E(id,
    [['识别CSRF目标','Identify CSRF target','定位执行状态更改操作且无CSRF Token保护的接口。','Locate state-changing endpoints without CSRF token protection.'],
     ['构造CSRF PoC','Craft CSRF PoC','创建自动提交表单的HTML页面，复制目标请求的全部参数。','Create auto-submitting HTML form replicating all request parameters.'],
     ['绕过防护机制','Bypass defenses','绕过Token校验、Referer/Origin检查和SameSite Cookie限制。','Bypass token validation, Referer/Origin checks, and SameSite cookie restrictions.'],
     ['验证影响','Verify impact','确认CSRF可修改密码/邮箱/权限等高危操作，评估实际危害。','Confirm CSRF can modify password/email/permissions etc. and assess real impact.']],
    'CSRF跨站请求伪造利用用户已认证身份执行未授权操作。核心防御为CSRF Token(不可预测+绑定会话)、SameSite Cookie和Origin/Referer校验。',
    'CSRF exploits authenticated user identity for unauthorized operations. Core defenses: CSRF tokens (unpredictable+session-bound), SameSite cookies, and Origin/Referer validation.',
    'https://portswigger.net/web-security/csrf','https://owasp.org/www-community/attacks/csrf'
  );
});

// API (12)
['jwt-security','graphql-injection','graphql-introspection','graphql-batching','rest-api-security','jwt-none-alg','jwt-key-confusion','api-idor','api-rate-limit','api-mass-assignment','api-bola','api-injection'].forEach(id => {
  E(id,
    [['识别API攻击面','Identify API surface','通过API文档(OpenAPI/GraphQL Schema)、JS源码和代理历史枚举端点和参数。','Enumerate endpoints and parameters via API docs, JS source, and proxy history.'],
     ['测试授权与认证','Test auth & authorization','测试JWT算法混淆、Token过期、IDOR越权和BOLA授权缺陷。','Test JWT algorithm confusion, token expiry, IDOR, and BOLA authorization flaws.'],
     ['注入与参数攻击','Injection & parameter attacks','测试GraphQL注入、REST参数污染、批量赋值和速率限制绕过。','Test GraphQL injection, REST parameter pollution, mass assignment, and rate limit bypass.'],
     ['验证与利用','Verify & exploit','确认漏洞后提取敏感数据、越权操作或通过API实现RCE。','After confirming vulnerabilities, extract sensitive data, perform unauthorized operations, or achieve RCE via API.']],
    'API安全漏洞涵盖认证(JWT)、授权(IDOR/BOLA)、注入(GraphQL/REST)和逻辑缺陷(速率限制/批量赋值)。现代应用以API为中心，API安全漏洞往往直接暴露核心业务数据和功能。',
    'API security vulnerabilities span authentication (JWT), authorization (IDOR/BOLA), injection (GraphQL/REST), and logic flaws (rate limit/mass assignment). Modern API-centric apps directly expose core business data through API flaws.',
    'https://owasp.org/API-Security/','https://portswigger.net/web-security/api-testing'
  );
});

// Framework (18)
['log4j-rce','spring-actuator','fastjson-rce','spring-spel','spring-cloud','struts2-rce','struts2-ognl','weblogic-rce','weblogic-t3','weblogic-iiop','thinkphp-rce','laravel-rce','shiro-deserialize','jboss-vuln','tomcat-vuln','django-vuln','flask-vuln','weblogic-xmldecoder'].forEach(id => {
  E(id,
    [['识别框架与版本','Identify framework & version','通过响应头、错误页面、默认路径和Wappalyzer识别目标框架及版本。','Identify target framework and version via headers, error pages, default paths, and Wappalyzer.'],
     ['确认已知漏洞','Confirm known vulnerability','查询CVE/CNVD数据库确认目标版本是否存在已知RCE/反序列化漏洞。','Query CVE/CNVD databases to confirm known RCE/deserialization vulnerabilities in the target version.'],
     ['利用Exploit','Exploit','使用公开POC或Metasploit模块进行利用，根据框架特性调整payload。','Exploit using public POCs or Metasploit modules, adjusting payloads for framework specifics.'],
     ['后利用','Post-exploitation','获取Shell后收集凭据、横向移动、建立持久化或提取数据库数据。','After gaining shell, collect credentials, move laterally, establish persistence, or extract database data.']],
    '框架漏洞是杀伤力最大的Web漏洞类型——单个RCE可获取服务器完全控制。Log4j(CVE-2021-44228)、Struts2、Fastjson、Shiro等框架漏洞影响数百万应用，补丁延迟是主要风险。',
    'Framework vulnerabilities are the most impactful web flaws — a single RCE grants full server control. Log4j, Struts2, Fastjson, Shiro affect millions of apps; patch delays are the primary risk.',
    'https://owasp.org/www-community/attacks/','https://cve.mitre.org/'
  );
});

// Auth (10)
['auth-bypass','auth-brute','auth-session','auth-password-reset','auth-oauth','auth-saml','auth-2fa','auth-captcha','auth-remember-me','auth-jwt'].forEach(id => {
  E(id,
    [['分析认证流程','Analyze auth flow','完整走一遍登录/注册/找回密码/MFA流程，记录所有请求参数和响应。','Walk through the complete auth flow, recording all request parameters and responses.'],
     ['测试认证绕过','Test auth bypass','测试路径遍历绕过、参数污染、默认凭据、逻辑缺陷和会话管理漏洞。','Test path traversal bypass, parameter pollution, default credentials, logic flaws, and session management.'],
     ['利用令牌弱点','Exploit token weaknesses','分析JWT/SAML/OAuth Token的签名算法、过期机制和声明注入。','Analyze JWT/SAML/OAuth token signing algorithms, expiry mechanisms, and claim injection.'],
     ['验证并扩大影响','Verify & escalate impact','确认认证绕过可访问敏感数据、修改他人账户或获取管理员权限。','Confirm auth bypass grants access to sensitive data, allows modifying other accounts, or obtains admin privileges.']],
    '认证漏洞是最直接的访问控制缺陷——绕过认证意味着未经授权的数据访问和操作。常见漏洞包括：弱密码策略、会话固定、JWT算法混淆、OAuth重定向劫持和MFA绕过。',
    'Authentication flaws are the most direct access control defects — bypassing auth means unauthorized data access and operations. Common: weak password policies, session fixation, JWT algorithm confusion, OAuth redirect hijacking, and MFA bypass.',
    'https://owasp.org/www-community/attacks/Authentication','https://portswigger.net/web-security/authentication'
  );
});

// Cache/CDN (3)
['cache-poisoning','cache-deception','cdn-bypass'].forEach(id => {
  E(id,
    [['识别缓存行为','Identify cache behavior','通过X-Cache头和响应时间差异确认缓存是否生效及缓存键规则。','Confirm cache behavior and key rules via X-Cache headers and response timing differences.'],
     ['构造投毒/欺骗Payload','Craft poison/deception payload','利用未键入头(Unkeyed Headers)投毒缓存，或利用路径混淆触发缓存欺骗。','Poison cache via unkeyed headers, or trigger cache deception via path confusion.'],
     ['验证影响','Verify impact','确认投毒响应是否被其他用户访问到，或缓存欺骗是否返回敏感数据。','Confirm poisoned responses are served to other users, or deception returns sensitive data.'],
     ['清除投毒','Clean up','记录投毒URL和参数，评估修复方案并建议缓存键规范化。','Document poisoned URLs and parameters; recommend cache key normalization.']],
    'Web缓存投毒通过操纵缓存键外的HTTP头将恶意响应存入缓存，影响所有后续访问者。缓存欺骗利用路径解析差异将敏感响应缓存为静态文件。CDN绕过则针对CDN层的安全配置。',
    'Web cache poisoning stores malicious responses via unkeyed headers, affecting all subsequent visitors. Cache deception caches sensitive responses as static files via path parsing differences. CDN bypass targets CDN-layer security.',
    'https://portswigger.net/web-security/web-cache-poisoning','https://portswigger.net/web-security/web-cache-deception'
  );
});

// Req Smuggling (4)
['smuggling-cl-te','smuggling-cl-cl','smuggling-te-cl','smuggling-te-te'].forEach(id => {
  E(id,
    [['探测走私入口','Probe smuggling entry','通过HTTP请求计时和响应差异探测前端/后端服务器对Content-Length和Transfer-Encoding的处理差异。','Probe CL/TE handling differences between front-end and back-end servers via timing and response differences.'],
     ['构造走私请求','Craft smuggling request','根据CL-TE/TE-CL/CL-CL/TE-TE走私类型构造恶意HTTP请求。','Craft malicious HTTP requests based on the smuggling type (CL-TE/TE-CL/CL-CL/TE-TE).'],
     ['利用走私','Exploit smuggling','通过请求走私绕过WAF、劫持用户会话、窃取敏感请求或触发反射XSS。','Bypass WAF, hijack sessions, steal sensitive requests, or trigger reflected XSS via smuggling.'],
     ['验证影响','Verify impact','确认走私是否可稳定触发，评估实际攻击面和危害。','Confirm smuggling stability and assess actual attack surface and impact.']],
    'HTTP请求走私利用前端(CDN/反向代理)和后端服务器对HTTP请求边界解析的不一致。CL-TE和TE-CL是两种主要走私方式，可导致缓存投毒、WAF绕过和会话劫持。',
    'HTTP request smuggling exploits inconsistent HTTP request boundary parsing between front-end and back-end servers. CL-TE and TE-CL are the two main types, leading to cache poisoning, WAF bypass, and session hijacking.',
    'https://portswigger.net/web-security/request-smuggling','https://owasp.org/www-community/attacks/HTTP_Request_Smuggling'
  );
});

// Open Redirect (3)
['redirect-basic','redirect-bypass','redirect-ssrf'].forEach(id => {
  E(id,
    [['识别重定向参数','Identify redirect parameter','定位接受URL/路径作为重定向目标的参数(redirect=/url=/next=/return=)。','Locate parameters accepting URL/path as redirect targets (redirect=/url=/next=/return=).'],
     ['构造重定向Payload','Craft redirect payload','使用绝对URL(http://evil.com)、协议相对URL(//evil.com)和反斜杠(\\evil.com)构造重定向。','Construct redirects using absolute URLs, protocol-relative URLs, and backslash variants.'],
     ['绕过验证','Bypass validation','通过URL编码、白名单域名子域/路径混淆和CRLF注入绕过重定向白名单。','Bypass redirect allowlists via URL encoding, domain subdomain/path confusion, and CRLF injection.'],
     ['升级利用','Escalate exploitation','从开放重定向升级到SSRF、OAuth Token窃取或钓鱼攻击。','Escalate from open redirect to SSRF, OAuth token theft, or phishing attacks.']],
    '开放重定向看似低危但实际危害显著——可用于OAuth劫持、钓鱼攻击(伪装合法域名)和SSRF升级。核心防御是使用白名单+相对路径重定向。',
    'Open redirect appears low-risk but has significant impact — usable for OAuth hijacking, phishing, and SSRF escalation. Core defense: allowlist + relative-path redirects.',
    'https://portswigger.net/web-security/dom-based/open-redirection','https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
  );
});

// Clickjacking (2)
['clickjacking-basic','clickjacking-xss'].forEach(id => {
  E(id,
    [['测试页面可框架性','Test frameability','检查X-Frame-Options/CSP frame-ancestors响应头，确认页面是否可被iframe嵌入。','Check X-Frame-Options/CSP frame-ancestors to confirm whether the page can be iframed.'],
     ['构造点击劫持页面','Craft clickjacking page','创建透明iframe覆盖攻击页面，诱导用户点击不可见按钮执行敏感操作。','Create transparent iframe overlaying the attack page to trick users into clicking invisible buttons.'],
     ['绕过防御','Bypass defenses','利用double-iframe嵌套、CSP frame-ancestors通配符和浏览器BUG绕过框架防护。','Bypass frame protections via double-iframe nesting, CSP frame-ancestors wildcards, and browser bugs.'],
     ['升级影响','Escalate impact','结合XSS进行更复杂的UI矫正攻击，或在移动端利用触屏特性增强攻击效果。','Combine with XSS for complex UI redress attacks, or leverage touchscreen features on mobile.']],
    '点击劫持(UI Redress)通过透明iframe诱使用户在不知情的情况下点击隐藏的按钮/链接，执行转账/关注/授权等操作。X-Frame-Options和CSP frame-ancestors是主要防御。',
    'Clickjacking (UI Redress) tricks users into unknowingly clicking hidden buttons/links via transparent iframes. X-Frame-Options and CSP frame-ancestors are primary defenses.',
    'https://portswigger.net/web-security/clickjacking','https://owasp.org/www-community/attacks/Clickjacking'
  );
});

// Business Logic (5)
['biz-idor','biz-race-condition','biz-payment-tamper','biz-password-reset','biz-captcha-bypass'].forEach(id => {
  E(id,
    [['分析业务流程','Analyze business flow','完整走一遍业务流程，绘制状态机图，识别多步骤操作和状态转换点。','Walk through the complete business flow, map state machine, identify multi-step operations and state transitions.'],
     ['识别逻辑缺陷','Identify logic flaws','测试跳过步骤、负值输入、整数溢出、并发请求和状态回退等逻辑缺陷。','Test step skipping, negative inputs, integer overflow, concurrent requests, and state rollback.'],
     ['构造利用Payload','Craft exploit payload','根据具体缺陷构造绕过支付/验证/权限检查的请求序列。','Craft request sequences to bypass payment/verification/permission checks based on specific flaws.'],
     ['验证业务影响','Verify business impact','确认逻辑缺陷可导致经济损失、数据泄露或权限提升，评估对业务的实际伤害。','Confirm logic flaws cause financial loss, data breach, or privilege escalation; assess actual business harm.']],
    '业务逻辑漏洞是自动化扫描器最难发现的漏洞类型——利用的是应用业务流程设计缺陷而非代码漏洞。常见于支付流程、权限控制和密码重置等业务关键路径。',
    'Business logic flaws are the hardest for automated scanners to detect — they exploit application flow design defects rather than code bugs. Common in payment flows, access control, and password reset paths.',
    'https://owasp.org/www-community/attacks/Business_Logic_Vulnerability','https://portswigger.net/web-security/logic-flaws'
  );
});

// JWT (4)
['jwt-none-attack','jwt-key-confusion','jwt-secret-bruteforce','jwt-jku-x5u-injection'].forEach(id => {
  E(id,
    [['解码分析JWT','Decode & analyze JWT','Base64解码JWT的header和payload，分析算法(alg)、声明(claims)和签名方案。','Base64-decode JWT header and payload; analyze algorithm, claims, and signing scheme.'],
     ['利用算法弱点','Exploit algorithm weakness','测试None算法、RS256→HS256密钥混淆、弱HMAC密钥爆破和JKU/X5U头注入。','Test None algorithm, RS256-to-HS256 key confusion, weak HMAC key brute-force, and JKU/X5U header injection.'],
     ['伪造Token','Forge token','成功绕过签名验证后伪造任意用户身份的JWT Token。','Forge JWT tokens with arbitrary user identity after successfully bypassing signature verification.'],
     ['扩大访问','Expand access','使用伪造Token访问敏感API、提取数据或以管理员身份操作。','Access sensitive APIs, extract data, or operate as admin using forged tokens.']],
    'JWT安全漏洞集中在对签名算法的错误信任——None算法绕过、RS256公钥当作HS256密钥、弱HMAC密钥和JKU/X5U头注入可完全绕过签名验证伪造任意Token。',
    'JWT vulnerabilities center on misplaced trust in signing algorithms — None algorithm bypass, RS256-to-HS256 key confusion, weak HMAC keys, and JKU/X5U header injection can completely bypass signature verification.',
    'https://portswigger.net/web-security/jwt','https://owasp.org/www-community/attacks/JSON_Web_Token_(JWT)_Cheat_Sheet'
  );
});

// Supply Chain, Proto Pollution, Cloud, WebSocket, AI - compact
const compact = {
  'supply-typosquat':['识别模拟包','Identify typosquatted package','搜索与目标使用包名称相似的恶意包，模拟依赖混淆或域名仿冒攻击。','Search for malicious packages with names similar to target dependencies.'],'supply-ci-poison':['分析CI/CD管道','Analyze CI/CD pipeline','审查构建脚本、依赖声明和流水线配置寻找注入点。','Review build scripts, dependency declarations, and pipeline configs for injection points.'],'supply-dependency-confusion':['探测内部包','Probe internal packages','在公共注册表发布与内部包同名的包，测试依赖解析是否从公共源拉取。','Publish packages matching internal names on public registries to test dependency resolution.'],
  'proto-server-rce':['定位merge/clone操作','Locate merge/clone ops','审计代码中递归合并用户输入到对象的操作(__proto__污染入口)。','Audit code for recursive merge of user input into objects (__proto__ pollution entry).'],'proto-client-xss':['污染客户端原型','Pollute client-side prototype','通过表单/JSON/URL参数注入__proto__属性篡改JavaScript内置对象行为。','Inject __proto__ properties via forms/JSON/URL to tamper with JS built-in object behavior.'],'proto-nosql-injection':['污染查询对象','Pollute query object','通过原型链污染注入NoSQL操作符绕过查询逻辑。','Inject NoSQL operators via prototype pollution to bypass query logic.'],
  'cloud-ssrf-metadata':['确认云环境','Confirm cloud environment','通过元数据端点(169.254.169.254)确认云厂商(AWS/GCP/Azure)和可用接口。','Confirm cloud provider and available endpoints via metadata service.'],'cloud-s3-misconfig':['枚举S3桶','Enumerate S3 buckets','通过域名、源码和错误信息发掘S3桶名，测试公开访问和读写权限。','Discover S3 bucket names via domains, source code, and errors; test public access and read/write permissions.'],'cloud-iam-escalation':['审计IAM策略','Audit IAM policies','列举当前IAM权限，查找可滥用的权限(i am:PassRole/iam:CreatePolicy)进行提权。','Enumerate current IAM permissions for abusable policies for privilege escalation.'],'cloud-k8s-escape':['确认容器环境','Confirm container environment','通过环境变量、挂载点和capabilities确认是否在K8s Pod中运行。','Confirm K8s pod environment via env vars, mounts, and capabilities.'],
  'ws-hijack':['测试跨域WebSocket','Test cross-origin WebSocket','检查WebSocket握手是否验证Origin头，实现CSWSH跨站WebSocket劫持。','Check if WebSocket handshake validates Origin header for CSWSH exploitation.'],'ws-smuggling':['构造走私请求','Craft smuggling request','利用HTTP升级请求走私绕过反向代理的WebSocket访问控制。','Bypass reverse proxy WebSocket access control via HTTP upgrade request smuggling.'],'ws-auth-bypass':['测试WebSocket认证','Test WebSocket auth','检查WebSocket连接前后的认证机制，测试Token泄露和会话重用。','Check auth mechanisms before/after WebSocket connection; test token leaks and session reuse.'],
  'ai-prompt-injection':['注入系统指令','Inject system prompt','使用Ignore previous instructions/Print your instructions等指令覆盖或泄露系统提示。','Override or leak system prompts using directive injection (Ignore previous instructions etc.).'],'ai-model-extraction':['提取模型信息','Extract model info','通过精心构造的查询提取模型架构、参数和训练数据特征。','Extract model architecture, parameters, and training data characteristics via crafted queries.'],'ai-adversarial':['构造对抗样本','Craft adversarial examples','利用模型对微小扰动的敏感性构造对抗样本绕过内容审核或分类。','Exploit model sensitivity to small perturbations for adversarial examples bypassing moderation or classification.'],'ai-rag-poisoning':['投毒知识库','Poison RAG knowledge base','向RAG系统的外部知识源注入恶意文档，影响模型检索和生成结果。','Inject malicious documents into RAG external knowledge sources to influence retrieval and generation.'],
};

// Handle compact entries
for (const [id, steps] of Object.entries(compact)) {
  // These are single-step attack chain - let's make them 3-step chains
  const fullId = id.startsWith('supply-') ? id : id.startsWith('proto-') ? id : id.startsWith('cloud-') ? id : id.startsWith('ws-') ? id : id.startsWith('ai-') ? id : null;
  if (!fullId) continue;

  // Generate 3-step chain from the single step
  const cat3 = fullId.startsWith('supply-') ? ['审查依赖链','Audit dependency chain','分析项目使用的依赖包和来源，识别潜在供应链攻击面。','Analyze project dependencies and sources for supply chain attack surface.']
    : fullId.startsWith('proto-') ? ['定位原型污染入口','Locate prototype pollution entry','审计代码中Object.assign/merge/clone等递归合并用户输入的操作为污染入口。','Audit code for recursive user-input merge operations as pollution entry points.']
    : fullId.startsWith('cloud-') ? ['识别云资源','Identify cloud resources','通过DNS/SSL/错误信息确认目标使用的云服务和资源配置。','Identify target cloud services and resource configurations via DNS/SSL/errors.']
    : fullId.startsWith('ws-') ? ['分析WebSocket通信','Analyze WebSocket traffic','通过浏览器开发者工具和代理拦截WebSocket握手和数据帧。','Intercept WebSocket handshake and data frames via browser devtools and proxy.']
    : ['分析AI交互接口','Analyze AI interface','确认应用使用的LLM模型、API端点和输入输出格式。','Identify the LLM model, API endpoints, and I/O format used by the application.'];

  const catAn = fullId.startsWith('supply-') ? ['供应链攻击利用开发者对依赖包的信任——通过域名仿冒、依赖混淆和CI/CD注入在软件开发和部署管道中植入恶意代码。','Supply chain attacks exploit developer trust in dependencies — implanting malicious code in dev/deploy pipelines via typosquatting, dependency confusion, and CI/CD injection.']
    : fullId.startsWith('proto-') ? ['原型链污染利用JavaScript原型继承机制——通过污染Object.prototype向所有对象注入恶意属性，可导致XSS、NoSQL注入绕过和RCE。','Prototype pollution exploits JS prototype inheritance — injecting malicious properties into Object.prototype leading to XSS, NoSQL injection bypass, and RCE.']
    : fullId.startsWith('cloud-') ? ['云安全漏洞利用云服务的错误配置——S3公开访问、IAM权限过大和K8s容器逃逸是最常见的云安全风险。','Cloud vulnerabilities exploit misconfigured services — S3 public access, excessive IAM permissions, and K8s container escape are the most common cloud risks.']
    : fullId.startsWith('ws-') ? ['WebSocket安全漏洞包括跨站劫持(CSWSH)、认证绕过和走私攻击——WebSocket握手缺乏同源策略的严格保护。','WebSocket vulnerabilities include cross-site hijacking (CSWSH), auth bypass, and smuggling — handshake lacks strict same-origin protection.']
    : ['AI安全是新兴攻击面——Prompt注入、模型窃取、对抗样本和RAG投毒利用LLM的特性和信任边界问题。','AI security is an emerging attack surface — prompt injection, model extraction, adversarial examples, and RAG poisoning exploit LLM characteristics and trust boundaries.'];

  const catRef = fullId.startsWith('supply-') ? ['https://owasp.org/www-community/attacks/Supply_Chain_Attack','https://portswigger.net/web-security']
    : fullId.startsWith('proto-') ? ['https://portswigger.net/web-security/prototype-pollution','https://owasp.org/www-community/attacks/Prototype_Pollution']
    : fullId.startsWith('cloud-') ? ['https://owasp.org/www-community/attacks/Cloud-Provider_Security','https://hackingthe.cloud/']
    : fullId.startsWith('ws-') ? ['https://portswigger.net/web-security/websockets','https://owasp.org/www-community/attacks/WebSocket_Security']
    : ['https://owasp.org/www-project-top-10-for-large-language-model-applications/','https://portswigger.net/web-security/llm-attacks'];

  E(fullId, [cat3, steps, [cat3[0],cat3[1],cat3[2],cat3[3]]], catAn[0], catAn[1], ...catRef);
}

// Handle remaining SSTI (5)
['ssti-freemarker','ssti-velocity','ssti-thymeleaf','ssti-smarty','ssti-pug'].forEach(id => {
  // These payloads have no tutorial - find wafBypass end instead
  const idx = c.indexOf("id: '" + id + "'");
  if (idx < 0) { console.log('NF', id); return; }
  const sec = c.slice(idx, idx + 8000);
  // For payloads without tutorial, find the payload end `  },`
  // Just skip - they get quality defaults from server
  console.log('SKIP (no tutorial):', id);
});

// Handle LFI/RFI (12) - provide via compact
['lfi-basic','rfi-basic','lfi-log-poison','lfi-wrapper','lfi-traversal','lfi-php-filter','lfi-php-input','lfi-php-data','lfi-php-zip','lfi-phar','lfi-session','lfi-proc'].forEach(id => {
  E(id,
    [[id==='lfi-basic'?'确认文件包含参数':'确认包含入口','Identify include entry','定位接受文件路径的参数(?page=/file=)，测试../和伪协议确认LFI。','Locate parameters accepting file paths; test ../ and wrappers to confirm LFI.'],
     ['读取敏感文件','Read sensitive files','读取/etc/passwd、应用源码(php://filter)、配置(.env)和日志文件。','Read /etc/passwd, source code (php://filter), configs (.env), and log files.'],
     ['升级LFI到RCE','Escalate LFI to RCE','通过日志投毒、Session包含、PHP Filter Chain、php://input和data://伪协议升级为RCE。','Escalate to RCE via log poisoning, session inclusion, PHP filter chain, php://input, and data://.'],
     ['持久化访问','Establish persistence','写入WebShell或修改crontab/authorized_keys/计划任务建立长期访问。','Write WebShell or modify crontab/authorized_keys for persistent access.']],
    '文件包含(LFI/RFI)漏洞允许读取服务器文件(LFI)或执行远程代码(RFI)。LFI可通过日志投毒、PHP Filter Chain、Session文件包含等技巧升级为RCE。RFI需allow_url_include=On。',
    'File inclusion (LFI/RFI) allows reading server files (LFI) or executing remote code (RFI). LFI can escalate to RCE via log poisoning, PHP filter chains, and session inclusion. RFI requires allow_url_include=On.',
    'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'
  );
});

// file-upload-bypass (missing ac)
E('file-upload-bypass',
  [['探测黑名单盲区','Probe blacklist gaps','尝试大小写混写(.PhP)、双扩展名(.php.jpg)、PHP别名(.phtml/.phar/.php5)和分号拼接(.php;.jpg)确定黑名单未覆盖的扩展名。','Try case variants, double extensions, PHP aliases, and semicolon concatenation to find blacklist gaps.'],
   ['伪造Content-Type','Spoof Content-Type','将Content-Type改为image/jpeg/png/gif等白名单值，结合Content-Disposition编码变体测试MIME校验。','Change Content-Type to allowlisted values with Content-Disposition encoding variants to test MIME validation.'],
   ['魔术字节+图片马','Magic bytes + image webshell','添加GIF89a/PNG/JPEG文件头或合成图片马；通过ExifTool和SVG注入扩展攻击面。','Prepend GIF89a/PNG/JPEG headers or create image webshells; extend via ExifTool and SVG injection.'],
   ['平台解析特性+配置上传','Platform quirks + config upload','利用IIS分号截断、Apache .htaccess AddType、Nginx截断和NTFS ADS；上传.htaccess/.user.ini覆盖目录规则。','Exploit IIS semicolon, Apache .htaccess, Nginx truncation, NTFS ADS; override rules via .htaccess/.user.ini.']],
  '文件上传绕过利用验证链不一致：黑名单不全、MIME与内容校验分离、平台解析差异和客户端验证可绕过。一个未被拦截的扩展名+MIME+内容组合即可写入WebShell。',
  'File upload bypass exploits validation chain gaps: incomplete blacklists, MIME-vs-content separation, platform parsing, and bypassable client checks. One unblocked extension+MIME+content combo lands a WebShell.',
  'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload','https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html','https://portswigger.net/web-security/file-upload'
);

writeFileSync(fp, c, 'utf8');
console.log('Total enriched:', n);
