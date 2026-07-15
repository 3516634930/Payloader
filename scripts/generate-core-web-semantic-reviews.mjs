import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadCurationSnapshot } from './apply-payload-curation.mjs';

const i18n = (zh, en) => ({ zh, en });
const asList = value => Array.isArray(value) ? value : [];

const profiles = [
  {
    id: 'csrf-json',
    name: i18n('JSON 接口 CSRF 边界验证', 'JSON Endpoint CSRF Boundary Validation'),
    description: i18n(
      '验证浏览器能否在携带受害者会话的同时，以简单请求兼容格式触发会改变状态的 JSON 接口；CORS、XSSI、JSONP 与 CSRF 分别记录，不再混为同一机制。',
      'Validates whether a browser can trigger a state-changing JSON endpoint with the victim session through a simple-request-compatible format. CORS, XSSI, JSONP, and CSRF are evaluated as separate mechanisms.',
    ),
    category: i18n('CSRF 跨站请求伪造', 'Cross-Site Request Forgery'),
    subCategory: i18n('JSON 接口与简单请求', 'JSON Endpoints and Simple Requests'),
    prerequisites: [
      i18n('使用专用测试账号和可回滚的资料字段，并确认 Cookie 的 SameSite、Secure 和 Domain 属性。', 'Use a dedicated test account and a reversible profile field, and record the cookie SameSite, Secure, and Domain attributes.'),
      i18n('在受控跨站页面与实验接口中使用唯一标记，保留浏览器网络记录、服务端日志和状态变更前后值。', 'Use a unique marker in a controlled cross-site page and lab endpoint, preserving browser network traces, server logs, and before-and-after state.'),
    ],
    tutorial: {
      overview: i18n(
        'JSON 接口并不会天然免疫 CSRF。真正需要验证的是：浏览器是否能跨站发出服务器会接受的简单请求格式，受害者会话是否随请求发送，以及服务器是否在没有一次性 CSRF 证明时完成了状态变更。application/json 预检、CORS 读权限和 XSSI 数据读取是相邻但不同的问题。',
        'JSON endpoints are not inherently immune to CSRF. The relevant question is whether a browser can send a cross-site simple-request-compatible body that the server accepts, whether the victim session accompanies it, and whether state changes without a one-time CSRF proof. An application/json preflight, CORS read access, and XSSI data disclosure are adjacent but distinct issues.',
      ),
      vulnerability: i18n(
        '当接口把 text/plain、表单编码或 multipart 内容继续当作 JSON 解析，同时仅依赖环境 Cookie 认证且不校验 CSRF Token、Origin 或可信 Referer 时，跨站页面可能制造有效写请求。宽松 CORS 不是确认 CSRF 的必要条件，反之允许读取响应也不能单独证明发生了状态变更。',
        'The boundary fails when an endpoint parses text/plain, form-encoded, or multipart input as JSON while relying on ambient cookies and omitting a CSRF token plus Origin or trusted Referer validation. Permissive CORS is not required to confirm CSRF, and permission to read a response does not by itself prove a state change.',
      ),
      exploitation: i18n(
        '先使用同源正常请求记录字段、Cookie 和服务端日志，再从受控的不同站点分别提交 text/plain、HTML 表单、multipart 和 application/json 对照。每次只写入 PAYLOADER-CSRF-MARKER，阳性必须同时满足浏览器携带目标会话、服务端接受请求、资料值实际改变，并可由审计日志关联。',
        'Record the normal same-origin request, cookies, fields, and server logs first. From a controlled different site, compare text/plain, an HTML form, multipart data, and application/json. Write only PAYLOADER-CSRF-MARKER. A positive result requires the target session to be sent, the server to accept the request, the stored value to change, and audit logs to correlate the event.',
      ),
      mitigation: i18n(
        '对写接口严格限定 Content-Type 和结构，不把简单请求内容隐式解析成 JSON；对每次状态变更校验不可预测并绑定会话的 CSRF Token，同时验证 Origin，设置合适的 SameSite Cookie。CORS 继续按最小来源配置，但不能代替 CSRF 防护。',
        'Strictly constrain the Content-Type and schema of write endpoints and do not implicitly parse simple-request bodies as JSON. Validate an unpredictable session-bound CSRF token and Origin on every state change, and set an appropriate SameSite cookie policy. Keep CORS narrowly scoped, but do not treat it as a replacement for CSRF protection.',
      ),
      difficulty: 'intermediate',
    },
    execution: [
      {
        command: '<script>fetch("https://{LAB_APP}/api/profile",{method:"POST",credentials:"include",headers:{"Content-Type":"text/plain"},body:JSON.stringify({displayName:"PAYLOADER-CSRF-MARKER"})});</script>',
        title: i18n('验证 text/plain 兼容解析', 'Validate text/plain Compatibility Parsing'),
        description: i18n('从受控跨站页面向实验资料接口发送唯一标记，检查服务端是否把 text/plain 请求体继续解析为 JSON 并改变状态。', 'Send one unique marker from a controlled cross-site page to the lab profile endpoint and determine whether the server parses a text/plain body as JSON and changes state.'),
      },
      {
        command: '<form action="https://{LAB_APP}/api/profile-form" method="POST"><input name="displayName" value="PAYLOADER-CSRF-MARKER"><button type="submit">Submit</button></form>',
        title: i18n('验证 HTML 表单写入边界', 'Validate the HTML Form Write Boundary'),
        description: i18n('使用标准跨站表单提交可回滚的资料标记，验证接口是否只凭环境 Cookie 接受状态变更。', 'Submit a reversible profile marker with a standard cross-site form and verify whether the endpoint accepts a state change based only on ambient cookies.'),
      },
      {
        command: '<script>fetch("https://{LAB_APP}/api/profile",{method:"POST",credentials:"include",headers:{"Content-Type":"application/json"},body:JSON.stringify({displayName:"PAYLOADER-CSRF-MARKER"})});</script>',
        title: i18n('记录 application/json 预检对照', 'Record the application/json Preflight Control'),
        description: i18n('以相同标记提交 application/json 请求，记录浏览器是否发起 OPTIONS 预检以及服务端是否错误放行，不把预检结果直接等同于 CSRF。', 'Submit the same marker as application/json, record whether the browser sends an OPTIONS preflight and whether the server permits it, and do not equate the preflight result with CSRF.'),
      },
      {
        command: '<script>const body=new FormData();body.append("displayName","PAYLOADER-CSRF-MARKER");fetch("https://{LAB_APP}/api/profile-multipart",{method:"POST",credentials:"include",body});</script>',
        title: i18n('验证 multipart 表单兼容解析', 'Validate multipart Form Compatibility Parsing'),
        description: i18n('使用浏览器生成的 multipart 请求写入同一可回滚标记，确认后端是否跨内容类型复用不安全的 JSON 绑定逻辑。', 'Use a browser-generated multipart request to write the same reversible marker and determine whether the backend reuses unsafe JSON binding across content types.'),
      },
    ],
    wafBypass: [
      {
        command: 'curl -sS -i -X OPTIONS "https://{LAB_APP}/api/profile" -H "Origin: https://{LAB_ORIGIN}" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: content-type"',
        title: i18n('记录 JSON 预检响应', 'Record the JSON Preflight Response'),
        description: i18n('从命令行保存预检响应头作为 CORS 配置证据；该请求不携带浏览器会话，也不能单独确认或排除 CSRF。', 'Preserve preflight response headers as CORS configuration evidence; this command-line request has no browser session and cannot confirm or exclude CSRF by itself.'),
      },
      {
        command: `curl -sS -i -X POST "https://{LAB_APP}/api/profile" -H "Origin: https://{LAB_ORIGIN}" -H "Content-Type: text/plain" --data-binary '{"displayName":"PAYLOADER-CSRF-MARKER"}'`,
        title: i18n('复测服务端来源与令牌校验', 'Retest Server-Side Origin and Token Validation'),
        description: i18n('在无登录 Cookie 的对照请求中确认接口拒绝缺少会话绑定令牌或可信来源的写入，再用真实浏览器完成最终回归。', 'Use a no-cookie control to confirm that the endpoint rejects writes lacking a session-bound token or trusted origin, then complete the final regression in a real browser.'),
      },
    ],
    chain: [
      ['记录同源正常写入基线', 'Record the Same-Origin Write Baseline', '使用专用账号正常修改可回滚字段，保存请求、Cookie 属性、响应、数据库前后值和服务端审计事件。', 'Use a dedicated account to change a reversible field normally, preserving the request, cookie attributes, response, before-and-after value, and server audit event.'],
      ['运行 text/plain 单变量样例', 'Run the text/plain Single-Variable Case', '从受控跨站页面只运行第一条样例，并确认浏览器实际发送目标会话以及服务器如何解析请求体。', 'Run only the first sample from a controlled cross-site page and confirm whether the browser sends the target session and how the server parses the body.', true],
      ['确认状态变化而非仅有响应', 'Confirm a State Change Rather Than a Response', '关联资料字段、写入日志和唯一标记；页面加载、网络请求成功或 CORS 响应头都不能单独确认 CSRF。', 'Correlate the stored profile field, write log, and unique marker; page load, network success, or CORS response headers alone do not confirm CSRF.'],
      ['修复并重放四种内容类型', 'Remediate and Replay Four Content Types', '启用会话绑定令牌、Origin 校验和严格内容类型后，重放四种对照并确认正常同源业务仍可用。', 'Enable a session-bound token, Origin validation, and strict content types, then replay all four controls and confirm normal same-origin behavior remains available.'],
    ],
    analysis: i18n('有效证据必须证明浏览器携带受害者会话、服务器接受跨站写请求且持久状态发生变化。请求可发送、响应可读取、预检成功、XSSI 或 JSONP 行为都不能替代这三项证据。', 'Valid evidence must prove that the browser sent the victim session, the server accepted the cross-site write, and persistent state changed. Request delivery, response readability, a successful preflight, XSSI, or JSONP behavior cannot replace those three facts.'),
    opsecTips: [
      i18n('只修改专用测试账号的可回滚字段，并为每次请求使用不同标记。', 'Modify only a reversible field on a dedicated test account and use a distinct marker for every request.'),
      i18n('一旦出现非预期写入、通知或下游任务就停止，并立即恢复原字段值。', 'Stop on any unexpected write, notification, or downstream job, and immediately restore the original field value.'),
    ],
    references: [
      'https://owasp.org/www-community/attacks/csrf',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
    ],
    rationale: '将 JSON CSRF 与 CORS、XSSI、JSONP 和已淘汰的 Flash 路径分离，并以真实浏览器状态变更作为确认标准。',
  },
  {
    id: 'csrf-flash',
    name: i18n('Flash 跨域策略遗留审计', 'Legacy Flash Cross-Domain Policy Audit'),
    description: i18n('面向仍保留 SWF 资产或跨域策略文件的遗留系统审计；用于发现历史配置残留，不再描述为现代浏览器中的通用 CSRF 或 CORS 绕过。', 'Audits legacy systems that still expose SWF assets or cross-domain policy files. It identifies historical configuration residue and is not presented as a general CSRF or CORS bypass in modern browsers.'),
    category: i18n('CSRF 跨站请求伪造', 'Cross-Site Request Forgery'),
    subCategory: i18n('遗留 Flash 策略', 'Legacy Flash Policy'),
    prerequisites: [
      i18n('资产负责人确认目标确实存在受支持的遗留 Flash 运行环境、专用兼容终端或待退役 SWF 业务。', 'Have the asset owner confirm an actually supported legacy Flash runtime, dedicated compatibility endpoint, or SWF workload awaiting retirement.'),
      i18n('仅下载公开策略与静态资产头部，不运行未知 SWF，不启用已停用插件，也不向生产写接口提交请求。', 'Retrieve only public policy files and static-asset headers; do not run unknown SWF files, enable a retired plugin, or submit requests to production write endpoints.'),
    ],
    tutorial: {
      overview: i18n('Flash Player 已结束生命周期，主流浏览器不再提供通用 Flash 运行时。本条目保留的价值是审计遗留 crossdomain.xml、clientaccesspolicy.xml、SWF 静态资产和后端兼容路由，判断它们是否仍扩大信任边界或误导维护人员，而不是指导现代浏览器利用。', 'Flash Player has reached end of life and mainstream browsers no longer provide a general Flash runtime. This entry is retained to audit legacy crossdomain.xml, clientaccesspolicy.xml, SWF assets, and compatibility routes for residual trust expansion or maintenance confusion, not to describe a modern-browser exploitation path.'),
      vulnerability: i18n('只有在组织仍运行明确的兼容客户端或服务端消费这些策略时，过宽的 allow-access-from、allow-http-request-headers-from 或遗留代理接口才可能形成实际边界问题。策略文件仍可访问、存在 SWF 文件或返回 application/x-shockwave-flash 本身只是资产清理信号。', 'An overly broad allow-access-from or allow-http-request-headers-from rule, or a legacy proxy endpoint, creates an active boundary only when an explicitly supported compatibility client or service still consumes it. A reachable policy file, an SWF asset, or an application/x-shockwave-flash response alone is an inventory and retirement signal.'),
      exploitation: i18n('先向资产负责人确认运行时与业务依赖，再只读获取两个策略文件、SWF 响应头和代码库引用。解析允许域、允许头、端口和 secure 属性，并与现行资产清单和代理日志对照；没有受支持运行时和实际请求证据时，结论应记为遗留配置而非可利用 CSRF。', 'Confirm the runtime and business dependency with the asset owner, then retrieve the two policy files, SWF response headers, and code references read-only. Parse allowed domains, headers, ports, and secure attributes and correlate them with current inventory and proxy logs. Without a supported runtime and observed requests, classify the result as legacy configuration rather than exploitable CSRF.'),
      mitigation: i18n('优先移除 SWF 资产、停用兼容代理并删除不再消费的策略文件；确需短期保留时只允许精确 HTTPS 来源和必要头部，禁止通配域，并设置退役日期、隔离网络和访问审计。现代写接口仍需独立使用 CSRF Token、Origin 校验和 SameSite Cookie。', 'Remove SWF assets, disable compatibility proxies, and delete unconsumed policy files. If temporary retention is required, allow only exact HTTPS origins and necessary headers, prohibit wildcard domains, and define a retirement date, network isolation, and access auditing. Modern write endpoints still require independent CSRF tokens, Origin validation, and SameSite cookies.'),
      difficulty: 'intermediate',
    },
    execution: [
      { command: 'curl -sS -D crossdomain.headers -o crossdomain.xml "https://{LAB_APP}/crossdomain.xml"', title: i18n('获取 crossdomain.xml', 'Retrieve crossdomain.xml'), description: i18n('只读保存实验站点的 Flash 跨域策略和响应头，供离线核对允许域、允许头与缓存策略。', 'Save the lab Flash cross-domain policy and response headers read-only for offline review of allowed domains, headers, and caching behavior.') },
      { command: 'curl -sS -D clientaccesspolicy.headers -o clientaccesspolicy.xml "https://{LAB_APP}/clientaccesspolicy.xml"', title: i18n('获取 clientaccesspolicy.xml', 'Retrieve clientaccesspolicy.xml'), description: i18n('保存可能遗留的 Silverlight/兼容策略文件，区分它与 Flash 策略并检查是否仍有客户端消费。', 'Save a possible Silverlight or compatibility policy file, distinguish it from Flash policy, and determine whether any supported client still consumes it.') },
      { command: 'rg -n --glob "*.swf" --glob "*.html" --glob "*.js" "crossdomain\\.xml|clientaccesspolicy\\.xml|application/x-shockwave-flash|\\.swf" "{LEGACY_WEB_ROOT}"', title: i18n('定位遗留资产引用', 'Locate Legacy Asset References'), description: i18n('在已授权的本地代码副本中查找 SWF、策略文件和旧 MIME 引用，不下载或执行未知 Flash 内容。', 'Search an authorized local code copy for SWF, policy-file, and legacy MIME references without downloading or running unknown Flash content.') },
      { command: 'curl -sS -I "https://{LAB_APP}/assets/legacy.swf"', title: i18n('记录 SWF 资产响应头', 'Record SWF Asset Response Headers'), description: i18n('仅请求实验 SWF 资产的响应头，记录状态、类型、缓存和安全头，不执行文件内容。', 'Request only response headers for the lab SWF asset and record status, type, caching, and security headers without executing its content.') },
    ],
    wafBypass: [
      { command: 'curl -sS -i "https://{LAB_APP}/crossdomain.xml" -H "Origin: https://{LAB_ORIGIN}"', title: i18n('复测遗留策略退役状态', 'Retest Legacy Policy Retirement'), description: i18n('修复后确认策略文件已移除或仅保留精确批准来源，并将结果与代理访问日志和资产清单对照。', 'After remediation, confirm that the policy is removed or limited to exact approved origins, and compare the result with proxy access logs and the asset inventory.') },
    ],
    chain: [
      ['确认是否存在受支持运行时', 'Confirm Whether a Supported Runtime Exists', '由资产负责人确认兼容终端、业务依赖、退役日期和网络边界；没有运行时就按遗留资产问题处理。', 'Have the asset owner confirm compatibility endpoints, business dependencies, retirement date, and network boundary; without a runtime, treat the item as legacy residue.'],
      ['只读获取跨域策略基线', 'Retrieve the Cross-Domain Policy Read-Only', '运行第一条命令保存策略与响应头，不执行 SWF，也不向任何写接口发起会话请求。', 'Run the first command to preserve the policy and headers without executing SWF content or sending a session request to any write endpoint.', true],
      ['关联资产、代码与访问日志', 'Correlate Assets, Code, and Access Logs', '核对策略允许项、SWF 引用、兼容代理和近期访问日志，判断配置是活跃信任边界还是未清理残留。', 'Compare policy permissions, SWF references, compatibility proxies, and recent access logs to decide whether this is an active trust boundary or unremoved residue.'],
      ['退役或收紧并验证现代防护', 'Retire or Constrain and Verify Modern Controls', '移除遗留组件或收紧精确来源后，确认现代写接口仍独立执行令牌、Origin 和 Cookie 策略。', 'Remove the legacy component or constrain exact origins, then verify that modern write endpoints independently enforce token, Origin, and cookie policies.'],
    ],
    analysis: i18n('确认风险需要受支持的运行时、仍被消费的策略和实际跨域请求证据。策略文件存在、SWF MIME 类型或旧源代码片段只能证明遗留资产，不能证明现代浏览器可绕过 CORS 或完成 CSRF。', 'Risk confirmation requires a supported runtime, a policy that is still consumed, and evidence of actual cross-domain requests. A policy file, SWF MIME type, or old source fragment proves legacy residue only and does not prove that modern browsers bypass CORS or complete CSRF.'),
    opsecTips: [
      i18n('不安装或重新启用 Flash Player，不在分析主机运行未知 SWF。', 'Do not install or re-enable Flash Player and do not run unknown SWF files on the analysis host.'),
      i18n('仅保留策略文本、响应头和文件哈希，避免收集无关静态内容或用户数据。', 'Retain only policy text, response headers, and file hashes, avoiding unrelated static content or user data.'),
    ],
    references: [
      'https://www.adobe.com/products/flashplayer/end-of-life.html',
      'https://owasp.org/www-community/attacks/csrf',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
    ],
    rationale: '把已结束生命周期的 Flash 技术改为遗留配置审计，删除现代通用预检绕过和恶意 SWF 制作叙述。',
  },
  {
    id: 'ssrf-cloud-azure',
    name: i18n('Azure 实例元数据 SSRF 验证', 'Azure Instance Metadata SSRF Validation'),
    description: i18n('在自有 Azure 实验虚拟机中验证 SSRF 客户端是否能够设置必需的 Metadata:true 请求头并到达实例元数据服务；不获取托管身份访问令牌。', 'Validates on an owned Azure lab VM whether an SSRF client can set the required Metadata:true header and reach the instance metadata service, without retrieving managed-identity access tokens.'),
    category: i18n('SSRF 服务端请求伪造', 'Server-Side Request Forgery'),
    subCategory: i18n('Azure 实例元数据', 'Azure Instance Metadata'),
    prerequisites: [
      i18n('仅在自有 Azure 实验虚拟机和专用测试应用中执行，并确认元数据响应不会被返回给非授权用户。', 'Run only on an owned Azure lab VM and dedicated test application, and ensure metadata responses cannot be returned to unauthorized users.'),
      i18n('先关闭请求重试并设置短超时；禁止查询 identity/oauth2/token、userData 或任何可能含凭据的字段。', 'Disable retries and set a short timeout first; do not query identity/oauth2/token, userData, or any field that may contain credentials.'),
    ],
    tutorial: {
      overview: i18n('Azure Instance Metadata Service 位于链路本地地址 169.254.169.254，并要求请求包含 Metadata:true。条目验证的是应用是否允许用户输入控制最终目标和敏感请求头，而不是把任意 URL 接受、重定向或一次网络错误当作元数据访问成功。所有样例都限定为低敏感度实例信息。', 'Azure Instance Metadata Service is hosted at link-local 169.254.169.254 and requires Metadata:true. This entry tests whether user input can control both the final destination and a sensitive request header, rather than treating URL acceptance, a redirect, or a network error as successful metadata access. Every sample is limited to lower-sensitivity instance information.'),
      vulnerability: i18n('当服务端取回功能允许访问链路本地地址，且攻击者可以注入或继承 Metadata:true 时，SSRF 才可能读取 IMDS。官方服务拒绝带 X-Forwarded-For 的请求，普通重定向不会自动生成必需头，因此“通过重定向绕过 Metadata 头”不能作为通用结论。', 'SSRF can read IMDS only when the server-side fetcher can reach the link-local address and an attacker can inject or inherit Metadata:true. The service rejects requests containing X-Forwarded-For, and an ordinary redirect does not synthesize the required header, so a generic claim that redirects bypass the metadata header is incorrect.'),
      exploitation: i18n('先对受控外部标记端点建立正常取回基线，再运行第一条命令或让实验 SSRF 代理复现同等请求。阳性需要应用出站日志显示最终连接到 169.254.169.254、IMDS 返回预期 JSON，并确认请求头确实为 Metadata:true；只保存实例名称、区域和标识等最小字段。', 'Establish a normal fetch baseline against a controlled external marker, then run the first command or reproduce the equivalent request through the lab SSRF proxy. A positive result requires outbound logs showing the final connection to 169.254.169.254, the expected IMDS JSON, and an actual Metadata:true header. Preserve only minimal fields such as instance name, region, and identifiers.'),
      mitigation: i18n('在 URL 解析和每次重定向后重新校验 scheme、解析地址、端口与最终连接 IP，阻止链路本地、回环和私网目标；不允许用户控制 Metadata 等敏感头，并在网络层限制工作负载访问 IMDS。应用使用最小权限托管身份并审计异常元数据请求。', 'Validate scheme, resolved address, port, and final connected IP after URL parsing and every redirect, blocking link-local, loopback, and private destinations. Do not let users control sensitive headers such as Metadata, restrict workload access to IMDS at the network layer, use least-privilege managed identities, and audit anomalous metadata requests.'),
      difficulty: 'advanced',
    },
    execution: [
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"', title: i18n('读取实例元数据根对象', 'Read the Instance Metadata Root Object'), description: i18n('在自有 Azure 实验虚拟机上读取实例对象并保存最小字段，确认必需请求头与链路本地目标均受控。', 'Read the instance object on an owned Azure lab VM and preserve minimal fields, confirming control of both the required header and link-local destination.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata:true" "http://169.254.169.254/metadata/identity/info?api-version=2019-11-01"', title: i18n('读取托管身份公开标识', 'Read Managed-Identity Public Identifiers'), description: i18n('只读取托管身份标识信息以验证端点边界，不请求 OAuth 访问令牌，也不调用 Azure 管理 API。', 'Read only managed-identity identifiers to validate the endpoint boundary without requesting an OAuth access token or calling an Azure management API.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"', title: i18n('读取计算元数据对象', 'Read the Compute Metadata Object'), description: i18n('获取实验虚拟机的计算元数据并限制保存范围，用于与 Azure 控制面资产记录进行一致性核对。', 'Retrieve compute metadata for the lab VM with limited retention and compare it with the Azure control-plane asset record.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata:true" "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01"', title: i18n('读取网络元数据对象', 'Read the Network Metadata Object'), description: i18n('读取实验虚拟机的网络元数据并仅保存验证所需地址，避免把响应扩展到其他资源或订阅。', 'Read network metadata for the lab VM and preserve only addresses required for validation without expanding to other resources or subscriptions.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata:true" "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01&format=text"', title: i18n('读取单个实例名称字段', 'Read One Instance Name Field'), description: i18n('使用 format=text 只读取实例名称作为最小阳性证据，降低记录完整元数据对象带来的数据暴露。', 'Use format=text to read only the instance name as minimal positive evidence and reduce exposure from retaining a complete metadata object.') },
    ],
    wafBypass: [
      { command: 'curl -sS --max-time 3 --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"; curl -sS --max-time 3 --noproxy "*" -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"', title: i18n('对比缺失与存在 Metadata 头', 'Compare Missing and Present Metadata Headers'), description: i18n('在同一实验虚拟机中对比无头与有头请求，证明服务端要求 Metadata:true，而不是把重定向或响应差异描述为绕过。', 'Compare requests without and with Metadata:true on the same lab VM to prove the service requirement rather than describing a redirect or response difference as a bypass.') },
    ],
    chain: [
      ['建立受控外部取回基线', 'Establish a Controlled External Fetch Baseline', '让实验应用请求带唯一标记的自有 HTTPS 端点，保存最终连接地址、请求头和响应摘要。', 'Have the lab application request an owned HTTPS marker endpoint and preserve the final connected address, request headers, and response summary.'],
      ['验证必需头与链路本地目标', 'Validate the Required Header and Link-Local Target', '运行第一条最小元数据请求，并同步检查应用出站日志中 Metadata:true 和最终目标地址。', 'Run the first minimal metadata request and simultaneously verify Metadata:true and the final destination in application egress logs.', true],
      ['排除重定向和代理假阳性', 'Exclude Redirect and Proxy False Positives', '确认响应来自 IMDS，X-Forwarded-For 未被加入，且代理缓存、统一错误页或字符串回显没有伪造结果。', 'Confirm that the response came from IMDS, X-Forwarded-For was not added, and proxy caches, generic error pages, or string reflection did not fabricate the result.'],
      ['阻断元数据路径并重放', 'Block the Metadata Path and Replay', '收紧目标地址、敏感头和网络出口后重放正常外部请求与元数据请求，确认前者可用而后者被拒绝。', 'Constrain destination addresses, sensitive headers, and egress, then replay the normal external and metadata requests to confirm the former works and the latter is rejected.'],
    ],
    analysis: i18n('阳性必须包含服务端最终连接地址、实际发送的 Metadata:true、IMDS 响应结构和应用到响应的可控传播路径。URL 被接受、出现 401/400、普通重定向或客户端本机直连都不能证明应用 SSRF 到达 Azure IMDS。', 'A positive result requires the server-side final connection address, the actual Metadata:true header, an IMDS response structure, and a controlled propagation path into the application response. URL acceptance, a 401 or 400, an ordinary redirect, or a direct request from the tester workstation does not prove application SSRF to Azure IMDS.'),
    opsecTips: [
      i18n('不请求访问令牌、userData 或完整订阅信息，只保留最小实例字段。', 'Do not request access tokens, userData, or full subscription information; retain only minimal instance fields.'),
      i18n('检测到身份令牌、凭据样式内容或非实验订阅标识时立即停止并清除响应。', 'Stop immediately and purge the response if an identity token, credential-like content, or non-lab subscription identifier appears.'),
    ],
    references: [
      'https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service',
      'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
    ],
    rationale: '纠正 Metadata:true、X-Forwarded-For 和重定向边界，删除托管身份令牌获取叙述并改为最小元数据验证。',
  },
  {
    id: 'ssrf-cloud-gcp',
    name: i18n('GCP Compute Metadata SSRF 验证', 'GCP Compute Metadata SSRF Validation'),
    description: i18n('在自有 GCP 实验实例中验证 SSRF 客户端是否能设置 Metadata-Flavor: Google 并访问 computeMetadata/v1；不读取 OAuth Token、SSH 密钥或 kube-env。', 'Validates on an owned GCP lab instance whether an SSRF client can set Metadata-Flavor: Google and access computeMetadata/v1, without retrieving OAuth tokens, SSH keys, or kube-env.'),
    category: i18n('SSRF 服务端请求伪造', 'Server-Side Request Forgery'),
    subCategory: i18n('GCP Compute Metadata', 'GCP Compute Metadata'),
    prerequisites: [
      i18n('仅在自有 GCP 实验项目与专用虚拟机执行，并为服务账号移除非验证所需权限。', 'Run only in an owned GCP lab project and dedicated VM, removing permissions that the service account does not need for validation.'),
      i18n('设置短超时、关闭重试和响应持久化，禁止请求 token、SSH keys、kube-env 或其他敏感属性值。', 'Set a short timeout, disable retries and response persistence, and prohibit requests for token, SSH keys, kube-env, or other sensitive attribute values.'),
    ],
    tutorial: {
      overview: i18n('GCP Compute Engine 元数据端点使用 metadata.google.internal 或链路本地地址，并在 computeMetadata/v1 路径上要求 Metadata-Flavor: Google 请求头。这里没有通用的“Instance Metadata API v2”切换项；验证重点是服务端取回器是否允许最终目标和请求头同时受用户控制。', 'GCP Compute Engine metadata is available through metadata.google.internal or a link-local address and requires Metadata-Flavor: Google on the computeMetadata/v1 path. There is no generic Instance Metadata API v2 switch for this boundary; validation focuses on whether a server-side fetcher lets user input control both the final target and required header.'),
      vulnerability: i18n('如果应用可访问元数据地址、允许添加 Metadata-Flavor: Google，并将响应返回给用户，就可能暴露实例、项目或服务账号元数据。仅能访问主机名、收到要求请求头的错误或在测试者电脑上运行 curl 都不确认 SSRF；必须证明应用进程的最终连接和请求头。', 'An application may expose instance, project, or service-account metadata when it can reach the metadata address, add Metadata-Flavor: Google, and return the response to a user. Reaching the hostname, receiving an error that asks for the header, or running curl on the tester workstation does not confirm SSRF; the application process final connection and header must be proven.'),
      exploitation: i18n('先用自有 HTTPS 标记服务确认请求器的重定向、DNS 和请求头行为，再通过实验应用请求元数据根目录或低敏感度字段。每次只运行一个样例，阳性由出站连接、Metadata-Flavor 请求头、computeMetadata/v1 响应和唯一请求标记共同确认；不读取访问令牌。', 'First use an owned HTTPS marker service to characterize redirects, DNS, and header behavior. Then request the metadata root or a lower-sensitivity field through the lab application. Run one sample at a time. Confirm a positive result with the outbound connection, Metadata-Flavor header, computeMetadata/v1 response, and a unique request marker, without reading an access token.'),
      mitigation: i18n('在解析后和每次重定向后阻止链路本地、回环与私网地址，固定允许的协议、主机和端口，并禁止用户控制 Metadata-Flavor 等敏感头；通过防火墙或工作负载边界限制元数据访问，采用最小权限服务账号并监控异常 computeMetadata/v1 请求。', 'Block link-local, loopback, and private addresses after resolution and every redirect; allowlist schemes, hosts, and ports; and prevent user control of sensitive headers such as Metadata-Flavor. Restrict metadata access at the firewall or workload boundary, use least-privilege service accounts, and monitor anomalous computeMetadata/v1 requests.'),
      difficulty: 'advanced',
    },
    execution: [
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"', title: i18n('读取元数据根目录', 'Read the Metadata Root Directory'), description: i18n('在自有 GCP 实验实例上读取元数据目录名称，不递归获取属性值或服务账号令牌。', 'Read metadata directory names on an owned GCP lab instance without recursively retrieving attribute values or service-account tokens.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"', title: i18n('读取服务账号邮箱标识', 'Read the Service-Account Email Identifier'), description: i18n('只读取实验服务账号邮箱以确认端点边界，不请求 default/token，也不使用该身份访问其他 API。', 'Read only the lab service-account email to validate the endpoint boundary without requesting default/token or using the identity against another API.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"', title: i18n('读取服务账号作用域列表', 'Read the Service-Account Scope List'), description: i18n('读取实验服务账号作用域名称并与项目基线比较，不获取凭据、令牌或资源数据。', 'Read scope names for the lab service account and compare them with the project baseline without retrieving credentials, tokens, or resource data.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id"', title: i18n('读取实验项目标识', 'Read the Lab Project Identifier'), description: i18n('只读取实验项目 ID 作为最小证据，并避免继续枚举组织、资源或其他项目。', 'Read only the lab project ID as minimal evidence and avoid enumerating organizations, resources, or other projects.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/attributes/"', title: i18n('列出项目属性键名', 'List Project Attribute Keys'), description: i18n('只列出实验项目属性键名，不读取 ssh-keys 或其他可能包含敏感配置的属性值。', 'List only lab project attribute key names without reading ssh-keys or other attribute values that may contain sensitive configuration.') },
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/"', title: i18n('列出实例属性键名', 'List Instance Attribute Keys'), description: i18n('只列出实验实例属性键名，不读取 kube-env、启动脚本、SSH 密钥或其他属性内容。', 'List only lab instance attribute key names without reading kube-env, startup scripts, SSH keys, or other attribute contents.') },
    ],
    wafBypass: [
      { command: 'curl -sS --max-time 3 --noproxy "*" -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"; curl -sS --max-time 3 --noproxy "*" -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/"', title: i18n('对比主机名与链路本地地址', 'Compare Hostname and Link-Local Address'), description: i18n('在同一实验实例中比较两个官方寻址形式，验证修复必须按最终连接地址分类，而不是只过滤主机字符串。', 'Compare the two documented addressing forms on one lab instance to verify that remediation classifies the final connected address rather than filtering only a hostname string.') },
    ],
    chain: [
      ['记录服务端取回器网络基线', 'Record the Server-Side Fetcher Network Baseline', '使用自有 HTTPS 标记端点记录 DNS、重定向、最终连接 IP、请求头和响应传播方式。', 'Use an owned HTTPS marker endpoint to record DNS, redirects, final connected IP, headers, and response propagation.'],
      ['提交最小元数据根目录请求', 'Submit the Minimal Metadata Root Request', '通过实验应用运行第一条样例，并在出站日志确认 computeMetadata/v1 与 Metadata-Flavor: Google。', 'Run the first sample through the lab application and confirm computeMetadata/v1 plus Metadata-Flavor: Google in egress logs.', true],
      ['关联 GCP 审计与响应证据', 'Correlate GCP Audit and Response Evidence', '确认响应结构、实验实例身份和唯一标记一致，并排除本机 curl、代理错误页、DNS 缓存或字符串回显。', 'Confirm that response structure, lab instance identity, and unique marker agree, excluding workstation curl, proxy error pages, DNS cache, or string reflection.'],
      ['阻断元数据地址并回归', 'Block Metadata Addresses and Regress', '对解析地址、重定向和敏感头实施限制后，重放外部正常请求与两种元数据地址对照。', 'Constrain resolved addresses, redirects, and sensitive headers, then replay the normal external request and both metadata address controls.'],
    ],
    analysis: i18n('阳性需要应用进程最终连接到 GCP 元数据地址、实际发送 Metadata-Flavor: Google，并把 computeMetadata/v1 响应传播到可控输出。要求请求头的错误、域名解析、HTTP 状态或测试者本机访问均不足以确认。', 'A positive result requires the application process to connect to a GCP metadata address, actually send Metadata-Flavor: Google, and propagate a computeMetadata/v1 response into a controlled output. An error requesting the header, DNS resolution, HTTP status, or tester-workstation access is insufficient.'),
    opsecTips: [
      i18n('不访问 default/token、SSH keys、kube-env、启动脚本或递归属性输出。', 'Do not access default/token, SSH keys, kube-env, startup scripts, or recursive attribute output.'),
      i18n('发现非实验项目、凭据样式内容或超出最小字段的响应时立即停止并清除。', 'Stop and purge the response if it identifies a non-lab project, resembles credentials, or exceeds the minimal fields.'),
    ],
    references: [
      'https://cloud.google.com/compute/docs/metadata/querying-metadata',
      'https://cloud.google.com/compute/docs/metadata/overview',
      'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
    ],
    rationale: '统一使用 computeMetadata/v1 和必需请求头，删除不存在的通用 v2 说法以及 Token、SSH 密钥和 kube-env 获取内容。',
  },
  {
    id: 'ssrf-mysql',
    name: i18n('MySQL 端口 SSRF 可达性验证', 'MySQL Port SSRF Reachability Validation'),
    description: i18n('使用隔离实验 MySQL 监听器和无害标记验证服务端取回器能否把非 HTTP scheme 连接到 3306；不构造认证报文、不执行 SQL，也不写入文件。', 'Uses an isolated lab MySQL listener and harmless markers to test whether a server-side fetcher can connect a non-HTTP scheme to port 3306, without crafting authentication packets, executing SQL, or writing files.'),
    category: i18n('SSRF 服务端请求伪造', 'Server-Side Request Forgery'),
    subCategory: i18n('非 HTTP Scheme 与 MySQL 可达性', 'Non-HTTP Schemes and MySQL Reachability'),
    prerequisites: [
      i18n('目标必须是无业务数据、无生产凭据的隔离 MySQL 协议夹具或仅记录字节的 TCP 监听器。', 'The target must be an isolated MySQL protocol fixture or byte-recording TCP listener with no business data or production credentials.'),
      i18n('使用固定 LAB_MYSQL_HOST、短超时和唯一标记；禁止空密码尝试、认证报文生成、SQL 语句和文件写入。', 'Use a fixed LAB_MYSQL_HOST, short timeout, and unique marker; prohibit empty-password attempts, authentication-packet generation, SQL statements, and file writes.'),
    ],
    tutorial: {
      overview: i18n('MySQL 使用服务端先发送握手包的有状态二进制协议。gopher 或 dict URL 能否让取回器建立到 3306 的 TCP 连接，只能证明非 HTTP scheme 与网络可达性，不能证明完成 MySQL 握手、认证或执行 SQL。本条目因此改为受控端口边界验证。', 'MySQL uses a stateful binary protocol in which the server sends the handshake first. A gopher or dict URL that causes a fetcher to connect to port 3306 proves only non-HTTP scheme handling and network reachability; it does not prove completion of the MySQL handshake, authentication, or SQL execution. This entry is therefore scoped to a controlled port-boundary validation.'),
      vulnerability: i18n('风险根因是服务端取回器允许不受信输入选择 gopher、dict 等 scheme，并能连接回环、私网或任意端口。MySQL 的挑战响应认证、能力协商和包序号使固定占位字符串不可能成为通用可执行载荷；“空密码即可执行 SQL”也必须由真实数据库认证证据单独证明。', 'The root cause is a server-side fetcher allowing untrusted input to select schemes such as gopher or dict and connect to loopback, private networks, or arbitrary ports. MySQL challenge-response authentication, capability negotiation, and packet sequencing mean a fixed placeholder string is not a universal executable payload; an empty-password SQL claim would also require separate database authentication evidence.'),
      exploitation: i18n('先让实验取回器访问正常 HTTPS 标记端点，再分别提交 gopher 和 dict 的固定实验主机 URL。阳性只记录取回器最终连接到 LAB_MYSQL_HOST:3306、监听器收到唯一标记或连接事件，以及应用返回的可控错误差异。不要把握手字节、连接重置或超时解释为 SQL 执行。', 'First have the lab fetcher access a normal HTTPS marker endpoint, then submit gopher and dict URLs for the fixed lab host. Record only that the fetcher connected to LAB_MYSQL_HOST:3306, that the listener observed the unique marker or connection event, and that the application produced a controlled error difference. Do not interpret handshake bytes, connection reset, or timeout as SQL execution.'),
      mitigation: i18n('只允许业务必需的 http/https scheme，解析后及每次重定向都阻止回环、链路本地和私网地址，并限制允许端口；在网络层禁止 Web 工作负载访问数据库网段。MySQL 继续要求强认证、最小账号权限和受信绑定，但数据库加固不能替代 SSRF 出站控制。', 'Allow only business-required http and https schemes, block loopback, link-local, and private addresses after resolution and every redirect, and allowlist ports. Prevent web workloads from reaching database networks at the network layer. MySQL should still require strong authentication, least-privilege accounts, and trusted binding, but database hardening does not replace SSRF egress controls.'),
      difficulty: 'advanced',
    },
    execution: [
      { command: 'gopher://{LAB_MYSQL_HOST}:3306/_PAYLOADER_MYSQL_REACHABILITY%0D%0A', title: i18n('发送 Gopher 无害标记', 'Send a Harmless Gopher Marker'), description: i18n('让实验取回器向固定的字节记录监听器发送唯一文本标记，只验证 scheme 与端口可达性。', 'Have the lab fetcher send one unique text marker to a fixed byte-recording listener, validating only scheme and port reachability.') },
      { command: 'dict://{LAB_MYSQL_HOST}:3306/PAYLOADER_MYSQL_REACHABILITY', title: i18n('验证 dict Scheme 端口边界', 'Validate the dict Scheme Port Boundary'), description: i18n('使用同一隔离监听器测试 dict scheme 是否被允许连接 3306，不把返回字节解释为数据库响应。', 'Use the same isolated listener to test whether the dict scheme can connect to port 3306 without interpreting returned bytes as a database response.') },
      { command: 'curl -sS --max-time 3 "http://{LAB_SSRF_APP}/fetch?url=gopher%3A%2F%2F%7BLAB_MYSQL_HOST%7D%3A3306%2F_PAYLOADER_MYSQL_REACHABILITY%250D%250A" -o mysql-gopher-result.json', title: i18n('通过实验取回接口提交 Gopher URL', 'Submit a Gopher URL Through the Lab Fetch Endpoint'), description: i18n('向专用实验取回接口提交编码后的固定主机 URL，保存结果和出站日志，不生成 MySQL 报文。', 'Submit an encoded fixed-host URL to the dedicated lab fetch endpoint and preserve the result plus egress logs without generating MySQL packets.') },
      { command: 'curl -sS --max-time 3 "http://{LAB_SSRF_APP}/fetch?url=dict%3A%2F%2F%7BLAB_MYSQL_HOST%7D%3A3306%2FPAYLOADER_MYSQL_REACHABILITY" -o mysql-dict-result.json', title: i18n('通过实验取回接口提交 dict URL', 'Submit a dict URL Through the Lab Fetch Endpoint'), description: i18n('以相同固定主机和唯一标记复测另一非 HTTP scheme，比较拒绝策略和最终连接证据。', 'Retest another non-HTTP scheme with the same fixed host and unique marker, comparing rejection behavior and final-connection evidence.') },
    ],
    wafBypass: [
      { command: 'curl -sS --max-time 3 "http://{LAB_SSRF_APP}/fetch?url=gopher%3A%2F%2F%7BLAB_MYSQL_HOST%7D%3A3306%2F_PAYLOADER_MYSQL_BLOCKED" -o mysql-egress-regression.json', title: i18n('复测非 HTTP Scheme 与数据库出口阻断', 'Retest Non-HTTP Scheme and Database Egress Blocking'), description: i18n('修复后重放固定实验 URL，确认应用拒绝 gopher 或网络层阻断 3306，同时正常 HTTPS 取回仍可用。', 'Replay the fixed lab URL after remediation to confirm that the application rejects gopher or the network blocks port 3306 while normal HTTPS fetching still works.') },
    ],
    chain: [
      ['建立正常 HTTPS 取回基线', 'Establish a Normal HTTPS Fetch Baseline', '使用自有标记端点记录取回器进程、DNS、最终连接地址、超时和应用响应映射。', 'Use an owned marker endpoint to record the fetcher process, DNS, final connection address, timeout, and application response mapping.'],
      ['提交无害 Gopher 标记', 'Submit the Harmless Gopher Marker', '运行第一条样例并在隔离监听器查找唯一文本标记，只确认非 HTTP scheme 到 3306 的可达性。', 'Run the first sample and look for the unique text marker on the isolated listener, confirming only non-HTTP reachability to port 3306.', true],
      ['区分连接、握手与 SQL 执行', 'Separate Connection, Handshake, and SQL Execution', '把 TCP 连接、MySQL 服务端握手、客户端认证和 SQL 命令视为四个独立阶段；本条目只确认第一阶段。', 'Treat TCP connection, the server handshake, client authentication, and SQL commands as four separate stages; this entry confirms only the first.'],
      ['限制 Scheme 与数据库出口后回归', 'Regress After Scheme and Database Egress Restrictions', '只允许 http/https 并阻断数据库网段后重放 gopher、dict 和正常 HTTPS 对照，确认边界准确。', 'Allow only http and https and block database-network egress, then replay gopher, dict, and normal HTTPS controls to confirm the boundary precisely.'],
    ],
    analysis: i18n('阳性证据仅表示应用进程连接了固定实验主机的 3306 端口，并由监听器记录唯一标记或连接。MySQL 握手、错误横幅、连接重置、超时、空密码假设或占位协议字符串都不能证明认证成功或 SQL 被执行。', 'Positive evidence means only that the application process connected to port 3306 on the fixed lab host and the listener recorded a unique marker or connection. A MySQL handshake, error banner, reset, timeout, empty-password assumption, or protocol placeholder does not prove authentication or SQL execution.'),
    opsecTips: [
      i18n('目标监听器不得连接生产数据库、保存业务数据或接受真实账号凭据。', 'The target listener must not connect to a production database, store business data, or accept real account credentials.'),
      i18n('出现认证提示、SQL 解析日志或非实验地址连接时立即停止并关闭取回器。', 'Stop and shut down the fetcher if authentication prompts, SQL parser logs, or a connection to a non-lab address appears.'),
    ],
    references: [
      'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
      'https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basics.html',
      'https://www.rfc-editor.org/rfc/rfc1436.html',
    ],
    rationale: '删除伪造协议占位、空密码通用化、任意 SQL 和 WebShell 写入内容，改为可证伪的端口可达性边界。',
  },
];

const attackChainFor = profile => profile.chain.map(([titleZh, titleEn, descriptionZh, descriptionEn, payload]) => ({
  title: i18n(titleZh, titleEn),
  description: i18n(descriptionZh, descriptionEn),
  ...(payload ? { payloadRef: { area: 'execution', index: 0 } } : {}),
}));

const reviewEntry = profile => ({
  id: profile.id,
  name: profile.name,
  description: profile.description,
  category: profile.category,
  subCategory: profile.subCategory,
  prerequisites: profile.prerequisites,
  tutorial: profile.tutorial,
  attackChain: attackChainFor(profile),
  analysis: profile.analysis,
  opsecTips: profile.opsecTips,
  references: profile.references,
  review: {
    decision: 'payload',
    rationale: profile.rationale,
    issuesResolved: [
      'corrected-protocol-and-browser-semantics',
      'removed-obsolete-or-placeholder-content',
      'bounded-validation-to-owned-lab-fixtures',
      'added-positive-and-negative-evidence-criteria',
      'added-authoritative-references',
    ],
  },
});

const commandPatches = (source, profile) => {
  const patches = [];
  for (const area of ['execution', 'wafBypass']) {
    const originals = asList(source?.[area]);
    const replacements = asList(profile?.[area]);
    if (originals.length !== replacements.length) {
      throw new Error(`${source.id} ${area} count changed: expected ${originals.length}, configured ${replacements.length}`);
    }
    replacements.forEach((replacement, index) => {
      const expectedCommand = String(originals[index]?.command || '');
      if (replacement.command === expectedCommand) {
        throw new Error(`${source.id} ${area}.${index} replacement is a no-op`);
      }
      patches.push({
        area,
        index,
        expectedCommand,
        command: replacement.command,
        title: replacement.title,
        description: replacement.description,
        syntaxBreakdown: [],
      });
    });
  }
  return patches;
};

export const buildCoreWebSemanticReviewDocuments = payloadsInput => {
  const sourceById = new Map(asList(payloadsInput).map(payload => [payload.id, payload]));
  const reviewed = profiles.map(profile => {
    const source = sourceById.get(profile.id);
    if (!source) throw new Error(`Missing source payload: ${profile.id}`);
    return { profile, source };
  });
  return {
    overrides: {
      schemaVersion: 1,
      contentStandard: 2,
      sourceIds: reviewed.map(({ profile }) => profile.id),
      entries: reviewed.map(({ profile }) => reviewEntry(profile)),
    },
    commandOverrides: {
      schemaVersion: 1,
      entries: reviewed.map(({ profile, source }) => ({
        id: profile.id,
        patches: commandPatches(source, profile),
      })),
    },
  };
};

const outputFiles = [
  ['overrides-core-web-semantic.json', 'overrides'],
  ['payload-command-overrides-core-web-semantic.json', 'commandOverrides'],
];

const run = () => {
  const root = resolve(process.cwd());
  const snapshot = loadCurationSnapshot(join(root, 'data', 'payloader.sqlite'));
  const documents = buildCoreWebSemanticReviewDocuments(snapshot.payloads);
  for (const [fileName, key] of outputFiles) {
    const file = join(root, 'content-review', fileName);
    writeFileSync(file, `${JSON.stringify(documents[key], null, 2)}\n`, 'utf8');
    console.log(`wrote ${fileName}`);
  }
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) run();
