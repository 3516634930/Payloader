import { payloadContentHash } from './payload-editorial-review.mjs';

const genericChainPattern = /\u5229\u7528\u6b65\u9aa4|\u9009\u62e9\u5bf9\u5e94\s*payload\s*\u6d4b\u8bd5|\u9009\u62e9\u7ed5\u8fc7\u6280\u672f|select the corresponding payload to test|select a bypass technique/i;
const collectionResiduePattern = /\(\s*[^()]{0,80}\b\d+\s*lines?\s*\)|\u7684\s*Payload\s*\u96c6\u5408|Payload\s*\u96c6\u5408|\u5171\s*\d+\s*\u6761[\s\S]{0,20}\u5c55\u793a\u524d\s*\d+\s*\u6761/i;
const validDifficulties = new Set(['beginner', 'intermediate', 'advanced', 'expert']);
const tutorialFields = ['overview', 'vulnerability', 'exploitation', 'mitigation'];
const referenceUrlReplacements = new Map([
  ['https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/test-wsman', 'https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman'],
  ['https://github.com/bwbwbwbw/linux-exploit-suggester-2', 'https://github.com/The-Z-Labs/linux-exploit-suggester'],
  ['https://learn.microsoft.com/en-us/exchange/clients/outlook/connectivity-with-microsoft-365', 'https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-service-description'],
  ['https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/group-policy-preferences', 'https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025'],
  ['https://owasp.org/www-community/attacks/HTTP_Request_Smuggling', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Request_Smuggling'],
  ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_pollution', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution'],
  ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_SSI_Injection', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/08-Testing_for_SSI_Injection'],
  ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_IMAP_SMTP_Injection', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/10-Testing_for_IMAP_SMTP_Injection'],
  ['https://cheatsheetseries.owasp.org/cheatsheets/HTML_Sanitization_Cheat_Sheet.html', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
  ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_SQL_Injection', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection'],
  ['https://dev.mysql.com/doc/refman/8.4/en/adding-loadable-function.html', 'https://dev.mysql.com/doc/refman/8.4/en/adding-functions.html'],
  ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection'],
  ['https://github.com/feihong-cs/JNDIExploit', 'https://github.com/artsploit/rogue-jndi'],
  ['https://github.com/0xthirteen/SharpSMBClient', 'https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbshare'],
  ['https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/Common/support/analyzeHeadlessREADME.html', 'https://github.com/NationalSecurityAgency/ghidra'],
  ['https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-share', 'https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbshare'],
  ['https://github.com/EricZimmerman/Tools', 'https://ericzimmerman.github.io/'],
  ['https://bloodhound.readthedocs.io/en/latest/data-analysis/queries.html', 'https://bloodhound.specterops.io/analyze-data/cypher-search'],
  ['https://owasp.org/www-project-testing-guide/', 'https://owasp.org/www-project-web-security-testing-guide/'],
  ['https://github.com/pentestmonkey/pdf-export', 'https://attack.mitre.org/techniques/T1048/'],
  ['https://www.sans.org/blog/linux-forensics-cheat-sheet/', 'https://www.kernel.org/doc/html/latest/admin-guide/index.html'],
  ['https://www.sans.org/posters/linux-knowledge-base-and-cheat-sheet/', 'https://www.kernel.org/doc/html/latest/admin-guide/index.html'],
  ['https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net', 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-user'],
  ['https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nltest', 'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomaincontroller'],
  ['https://www.tencentcloud.com/document/product/1013/33495', 'https://www.tencentcloud.com/document/product/598/10583'],
  ['https://github.com/digininja/autorecon', 'https://github.com/Tib3rius/AutoRecon'],
  ['https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/', 'https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/'],
  ['https://genai.owasp.org/llmrisk/llm05-improper-output-handling/', 'https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/'],
  ['https://genai.owasp.org/llmrisk/llm06-excessive-agency/', 'https://genai.owasp.org/llmrisk/llm062025-excessive-agency/'],
]);

const i18n = (zh, en) => ({ zh, en });
const isObject = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const asList = value => Array.isArray(value) ? value : [];
const displayText = value => typeof value === 'string' ? value : String(value?.zh || value?.en || '');
const localizedText = (value, language) => typeof value === 'string'
  ? (language === 'zh' ? value : '')
  : String(value?.[language] || '');
const clone = value => structuredClone(value);
const hasHan = value => /\p{Script=Han}/u.test(String(value || ''));
const requiredOverrideContentFields = ['name', 'description', 'category', 'subCategory', 'tutorial', 'attackChain', 'references'];
const optionalOverrideContentFields = ['prerequisites', 'analysis', 'opsecTips'];
const overrideContentFields = [...requiredOverrideContentFields, ...optionalOverrideContentFields];
export const normalizeReferenceUrls = references => [...new Set(asList(references)
  .map(reference => referenceUrlReplacements.get(String(reference)) || String(reference))
  .filter(Boolean))];
const categoryKey = value => displayText(value).toLocaleLowerCase().replace(/\s+/g, '');
const canonicalCategories = new Map([
  ['sql/nosql注入', i18n('SQL/NoSQL注入', 'SQL/NoSQL Injection')],
  ['xss跨站脚本', i18n('XSS跨站脚本', 'XSS Cross-Site Scripting')],
  ['ssrf服务端请求伪造', i18n('SSRF服务端请求伪造', 'SSRF Server-Side Request Forgery')],
  ['rce远程代码执行', i18n('RCE远程代码执行', 'RCE Remote Code Execution')],
  ['xxe实体注入', i18n('XXE实体注入', 'XXE XML Entity Injection')],
  ['xxexml外部实体', i18n('XXE实体注入', 'XXE XML Entity Injection')],
  ['ssti模板注入', i18n('SSTI模板注入', 'SSTI Template Injection')],
  ['ssti服务端模板注入', i18n('SSTI模板注入', 'SSTI Template Injection')],
  ['api安全', i18n('API安全', 'API Security')],
  ['认证漏洞', i18n('认证漏洞', 'Authentication Vulnerabilities')],
  ['认证安全', i18n('认证漏洞', 'Authentication Vulnerabilities')],
  ['文件漏洞', i18n('文件漏洞', 'File Vulnerabilities')],
  ['csrf跨站请求伪造', i18n('CSRF跨站请求伪造', 'CSRF Cross-Site Request Forgery')],
  ['jwt安全', i18n('JWT安全', 'JWT Security')],
  ['框架漏洞', i18n('框架漏洞', 'Framework Vulnerabilities')],
  ['wordpressxml-rpc', i18n('框架漏洞', 'Framework Vulnerabilities')],
  ['xslt注入', i18n('RCE远程代码执行', 'RCE Remote Code Execution')],
  ['原型链污染', i18n('原型链污染', 'Prototype Pollution')],
  ['业务逻辑漏洞', i18n('业务逻辑漏洞', 'Business Logic Vulnerabilities')],
  ['云安全漏洞', i18n('云安全漏洞', 'Cloud Security Vulnerabilities')],
  ['点击劫持', i18n('点击劫持', 'Clickjacking')],
  ['开放重定向', i18n('开放重定向', 'Open Redirect')],
  ['请求走私', i18n('请求走私', 'HTTP Request Smuggling')],
  ['http请求走私', i18n('请求走私', 'HTTP Request Smuggling')],
]);
const canonicalCategory = value => clone(canonicalCategories.get(categoryKey(value)) || value);

const editorialProfiles = [
  {
    pattern: /SQL|NoSQL|\u6570\u636e\u5e93/i,
    difficulty: 'intermediate',
    principleZh: '\u672a\u53d7\u4fe1\u4efb\u8f93\u5165\u88ab\u62fc\u63a5\u6216\u89e3\u6790\u4e3a\u6570\u636e\u5e93\u67e5\u8be2\u3001\u8fd0\u7b97\u7b26\u6216\u8868\u8fbe\u5f0f\uff0c\u4e1a\u52a1\u53c2\u6570\u4e0e\u67e5\u8be2\u8bed\u4e49\u4e4b\u95f4\u7f3a\u5c11\u53c2\u6570\u5316\u548c\u7c7b\u578b\u7ea6\u675f\u3002',
    principleEn: 'Untrusted input is concatenated or interpreted as a database query, operator, or expression without parameterization and type constraints at the trust boundary.',
    mitigationZh: '\u4f7f\u7528\u53c2\u6570\u5316\u67e5\u8be2\u548c\u4e25\u683c\u7c7b\u578b\u7ed1\u5b9a\uff0c\u7981\u6b62\u52a8\u6001\u62fc\u63a5\u67e5\u8be2\u7247\u6bb5\uff0c\u6536\u7d27\u6570\u636e\u5e93\u8d26\u53f7\u6743\u9650\uff0c\u5e76\u5ba1\u8ba1\u5f02\u5e38\u67e5\u8be2\u7ed3\u6784\u548c\u9519\u8bef\u3002',
    mitigationEn: 'Use parameterized queries and strict type binding, prohibit dynamic query fragments, reduce database privileges, and audit anomalous query structures and errors.',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection'],
  },
  {
    pattern: /XSS|\u8de8\u7ad9\u811a\u672c/i,
    difficulty: 'intermediate',
    principleZh: '\u4e0d\u53ef\u4fe1\u6570\u636e\u8fdb\u5165 HTML\u3001\u5c5e\u6027\u3001URL \u6216 JavaScript \u4e0a\u4e0b\u6587\u65f6\u672a\u505a\u4e0e\u8f93\u51fa\u4f4d\u7f6e\u5339\u914d\u7684\u7f16\u7801\u548c\u6d88\u6bd2\uff0c\u5bfc\u81f4\u6d4f\u89c8\u5668\u5c06\u6570\u636e\u89e3\u91ca\u4e3a\u53ef\u6267\u884c\u5185\u5bb9\u3002',
    principleEn: 'Untrusted data reaches HTML, attribute, URL, or JavaScript contexts without context-aware encoding or sanitization, so the browser interprets data as executable content.',
    mitigationZh: '\u6309\u8f93\u51fa\u4e0a\u4e0b\u6587\u7f16\u7801\uff0c\u4f7f\u7528\u6210\u719f HTML \u6d88\u6bd2\u5668\uff0c\u907f\u514d\u5371\u9669 DOM API\uff0c\u90e8\u7f72\u4e25\u683c CSP\uff0c\u5e76\u5bf9\u53cd\u5c04\u3001\u5b58\u50a8\u548c DOM \u6570\u636e\u6d41\u5206\u522b\u56de\u5f52\u6d4b\u8bd5\u3002',
    mitigationEn: 'Apply context-aware output encoding, use a maintained HTML sanitizer, avoid dangerous DOM APIs, deploy a strict CSP, and regression-test reflected, stored, and DOM data flows separately.',
    references: ['https://owasp.org/www-community/attacks/xss/'],
  },
  {
    pattern: /SSRF|\u670d\u52a1\u7aef\u8bf7\u6c42/i,
    difficulty: 'advanced',
    principleZh: '\u670d\u52a1\u7aef\u4ee3\u8868\u7528\u6237\u53d1\u8d77\u7f51\u7edc\u8bf7\u6c42\uff0c\u4f46\u672a\u5728 DNS \u89e3\u6790\u3001\u534f\u8bae\u3001\u5730\u5740\u6bb5\u3001\u91cd\u5b9a\u5411\u548c\u6700\u7ec8\u8fde\u63a5\u76ee\u6807\u4e0a\u5efa\u7acb\u4e00\u81f4\u7684\u51fa\u7ad9\u8fb9\u754c\u3002',
    principleEn: 'The server makes network requests on behalf of a user without consistently enforcing protocol, DNS, address-range, redirect, and final-destination controls.',
    mitigationZh: '\u5bf9\u534f\u8bae\u3001\u4e3b\u673a\u548c\u7aef\u53e3\u4f7f\u7528\u5141\u8bb8\u5217\u8868\uff0c\u89e3\u6790\u540e\u518d\u68c0\u67e5 IP \u5f52\u5c5e\uff0c\u7981\u6b62\u8de8\u4fe1\u4efb\u57df\u91cd\u5b9a\u5411\uff0c\u901a\u8fc7\u7f51\u7edc\u5c42\u9650\u5236\u5143\u6570\u636e\u548c\u5185\u7f51\u76ee\u6807\uff0c\u5e76\u8bb0\u5f55\u51fa\u7ad9\u8bf7\u6c42\u3002',
    mitigationEn: 'Allowlist protocols, hosts, and ports; validate resolved addresses; reject cross-boundary redirects; block metadata and internal destinations at the network layer; and log outbound requests.',
    references: ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
  },
  {
    pattern: /RCE|\u4ee3\u7801\u6267\u884c|\u547d\u4ee4\u6267\u884c|SSTI|\u6a21\u677f\u6ce8\u5165|\u53cd\u5e8f\u5217\u5316/i,
    difficulty: 'advanced',
    principleZh: '\u7528\u6237\u53ef\u63a7\u6570\u636e\u8fdb\u5165\u547d\u4ee4\u89e3\u91ca\u5668\u3001\u6a21\u677f\u5f15\u64ce\u3001\u53cd\u5e8f\u5217\u5316\u5668\u6216\u52a8\u6001\u8c03\u7528\u8fb9\u754c\uff0c\u4e14\u6267\u884c\u6743\u9650\u3001\u5141\u8bb8\u7c7b\u578b\u6216\u53c2\u6570\u8303\u56f4\u6ca1\u6709\u88ab\u670d\u52a1\u7aef\u9650\u5b9a\u3002',
    principleEn: 'User-controlled data reaches a command interpreter, template engine, deserializer, or dynamic invocation boundary without server-side constraints on operations, types, or arguments.',
    mitigationZh: '\u79fb\u9664\u52a8\u6001\u6267\u884c\u8def\u5f84\uff0c\u4f7f\u7528\u56fa\u5b9a API \u548c\u5141\u8bb8\u5217\u8868\uff0c\u7981\u6b62\u53cd\u5e8f\u5217\u5316\u4e0d\u53ef\u4fe1\u5bf9\u8c61\uff0c\u5728\u6700\u5c0f\u6743\u9650\u9694\u79bb\u73af\u5883\u4e2d\u8fd0\u884c\uff0c\u5e76\u76d1\u63a7\u5f02\u5e38\u5b50\u8fdb\u7a0b\u548c\u7f51\u7edc\u884c\u4e3a\u3002',
    mitigationEn: 'Remove dynamic execution paths, use fixed APIs and allowlists, never deserialize untrusted object graphs, run with least privilege and isolation, and monitor anomalous child processes and network activity.',
    references: ['https://owasp.org/www-community/attacks/Command_Injection'],
  },
  {
    pattern: /XXE|XML/i,
    difficulty: 'advanced',
    principleZh: 'XML \u89e3\u6790\u5668\u5141\u8bb8\u5916\u90e8\u5b9e\u4f53\u3001DTD \u6216\u5916\u90e8\u8d44\u6e90\u52a0\u8f7d\uff0c\u4e0d\u53ef\u4fe1 XML \u56e0\u6b64\u53ef\u4ee5\u89e6\u53d1\u6587\u4ef6\u8bfb\u53d6\u3001\u670d\u52a1\u7aef\u8bf7\u6c42\u6216\u8d44\u6e90\u6d88\u8017\u3002',
    principleEn: 'The XML parser permits external entities, DTDs, or external resource loading, allowing untrusted XML to trigger file reads, server-side requests, or resource exhaustion.',
    mitigationZh: '\u7981\u7528 DTD \u548c\u5916\u90e8\u5b9e\u4f53\uff0c\u4f7f\u7528\u5b89\u5168\u89e3\u6790\u5668\u9884\u8bbe\uff0c\u9650\u5236\u51fa\u7ad9\u7f51\u7edc\u548c\u6587\u4ef6\u7cfb\u7edf\u6743\u9650\uff0c\u5e76\u5bf9\u4e0a\u4f20\u6587\u6863\u5185\u7684 XML \u90e8\u4ef6\u6267\u884c\u540c\u7b49\u6821\u9a8c\u3002',
    mitigationEn: 'Disable DTDs and external entities, use secure parser defaults, restrict outbound network and filesystem access, and apply the same controls to XML parts embedded in uploaded documents.',
    references: ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'],
  },
  {
    pattern: /\u8ba4\u8bc1|JWT|OAuth|SAML|API|CSRF|\u4e1a\u52a1\u903b\u8f91/i,
    difficulty: 'intermediate',
    principleZh: '\u8eab\u4efd\u3001\u4f1a\u8bdd\u3001\u5bf9\u8c61\u6743\u9650\u6216\u4e1a\u52a1\u72b6\u6001\u53ea\u5728\u5ba2\u6237\u7aef\u6216\u5355\u4e2a\u6b65\u9aa4\u6821\u9a8c\uff0c\u670d\u52a1\u7aef\u6ca1\u6709\u5bf9\u6bcf\u4e2a\u8bf7\u6c42\u91cd\u65b0\u7ed1\u5b9a\u4e3b\u4f53\u3001\u5bf9\u8c61\u3001\u52a8\u4f5c\u548c\u72b6\u6001\u8f6c\u79fb\u3002',
    principleEn: 'Identity, session, object authorization, or business state is validated only on the client or at one step, rather than rebinding subject, object, action, and state on every server-side request.',
    mitigationZh: '\u5bf9\u6bcf\u6b21\u8bf7\u6c42\u6267\u884c\u670d\u52a1\u7aef\u8ba4\u8bc1\u548c\u5bf9\u8c61\u7ea7\u6388\u6743\uff0c\u4e25\u683c\u6821\u9a8c\u4ee4\u724c\u7b97\u6cd5\u3001\u7b7e\u540d\u3001\u53d7\u4f17\u548c\u65f6\u6548\uff0c\u4f7f\u7528\u4e00\u6b21\u6027\u9632\u91cd\u653e\u503c\uff0c\u5e76\u4e3a\u654f\u611f\u72b6\u6001\u8f6c\u79fb\u5efa\u7acb\u5ba1\u8ba1\u3002',
    mitigationEn: 'Authenticate and authorize every request at object level, strictly validate token algorithms, signatures, audiences, and lifetime, use one-time anti-replay values, and audit sensitive state transitions.',
    references: ['https://owasp.org/www-project-api-security/'],
  },
  {
    pattern: /\u6587\u4ef6|LFI|RFI|\u8def\u5f84\u904d\u5386/i,
    difficulty: 'intermediate',
    principleZh: '\u7528\u6237\u63d0\u4f9b\u7684\u6587\u4ef6\u540d\u3001\u8def\u5f84\u3001\u7c7b\u578b\u6216\u5f52\u6863\u5185\u90e8\u8def\u5f84\u4e0e\u670d\u52a1\u7aef\u5b58\u50a8\u3001\u89e3\u6790\u6216\u4e0b\u8f7d\u903b\u8f91\u76f4\u63a5\u7ed1\u5b9a\uff0c\u5f52\u4e00\u5316\u540e\u7684\u5b9e\u9645\u8def\u5f84\u548c\u5185\u5bb9\u7c7b\u578b\u672a\u88ab\u9650\u5236\u3002',
    principleEn: 'User-controlled names, paths, types, or archive members are bound directly to storage, parsing, or download logic without validating the canonical path and actual content type.',
    mitigationZh: '\u4f7f\u7528\u670d\u52a1\u7aef\u751f\u6210\u7684\u5bf9\u8c61 ID \u4ee3\u66ff\u7528\u6237\u8def\u5f84\uff0c\u5bf9\u5f52\u4e00\u5316\u8def\u5f84\u6267\u884c\u6839\u76ee\u5f55\u6821\u9a8c\uff0c\u540c\u65f6\u6821\u9a8c\u6269\u5c55\u540d\u3001MIME \u548c\u5185\u5bb9\uff0c\u5e76\u5c06\u4e0a\u4f20\u76ee\u5f55\u8bbe\u4e3a\u4e0d\u53ef\u6267\u884c\u3002',
    mitigationEn: 'Use server-generated object IDs instead of user paths, enforce a canonical root directory, validate extension, MIME, and content together, and keep upload storage non-executable.',
    references: ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'],
  },
  {
    pattern: /AI|LLM|Prompt|RAG|\u6a21\u578b/i,
    difficulty: 'advanced',
    principleZh: '\u6a21\u578b\u5c06\u7cfb\u7edf\u6307\u4ee4\u3001\u7528\u6237\u8f93\u5165\u3001\u68c0\u7d22\u5185\u5bb9\u548c\u5de5\u5177\u7ed3\u679c\u7ec4\u5408\u5230\u540c\u4e00\u4e0a\u4e0b\u6587\uff0c\u5982\u679c\u7cfb\u7edf\u53ea\u4f9d\u8d56\u81ea\u7136\u8bed\u8a00\u4f18\u5148\u7ea7\u800c\u6ca1\u6709\u5de5\u5177\u6743\u9650\u3001\u8f93\u51fa\u7ea6\u675f\u548c\u6570\u636e\u8fb9\u754c\uff0c\u4e0d\u53ef\u4fe1\u5185\u5bb9\u5c31\u53ef\u80fd\u5f71\u54cd\u6a21\u578b\u51b3\u7b56\u3002',
    principleEn: 'System instructions, user input, retrieved content, and tool results share model context; without tool authorization, output constraints, and data boundaries, untrusted content can influence decisions.',
    mitigationZh: '\u5c06\u4e0d\u53ef\u4fe1\u5185\u5bb9\u6807\u8bb0\u4e3a\u6570\u636e\u800c\u975e\u6307\u4ee4\uff0c\u5bf9\u5de5\u5177\u8c03\u7528\u6267\u884c\u72ec\u7acb\u6388\u6743\u548c\u53c2\u6570\u9a8c\u8bc1\uff0c\u9650\u5236\u68c0\u7d22\u8303\u56f4\u548c\u654f\u611f\u8f93\u51fa\uff0c\u5e76\u4f7f\u7528\u53ef\u91cd\u653e\u7684\u5bf9\u6297\u6d4b\u8bd5\u96c6\u3002',
    mitigationEn: 'Treat untrusted content as data rather than instructions, authorize and validate tool calls independently, constrain retrieval and sensitive output, and maintain replayable adversarial regression cases.',
    references: ['https://owasp.org/www-project-top-10-for-large-language-model-applications/'],
  },
  {
    pattern: /\u4fe1\u606f\u6536\u96c6|\u51ed\u8bc1|\u6a2a\u5411|\u57df\u6e17\u900f|ADCS|Exchange|SharePoint|\u6743\u9650\u63d0\u5347|\u6743\u9650\u7ef4\u6301|\u96a7\u9053|\u7ec8\u7aef\u5b89\u5168/i,
    difficulty: 'advanced',
    principleZh: '\u8be5\u6280\u672f\u4f9d\u8d56\u5df2\u6388\u6743\u8eab\u4efd\u3001\u672c\u5730\u6216\u8fdc\u7a0b\u7cfb\u7edf\u80fd\u529b\u4ee5\u53ca\u7f51\u7edc\u4fe1\u4efb\u5173\u7cfb\uff0c\u5173\u952e\u98ce\u9669\u6765\u81ea\u6743\u9650\u8303\u56f4\u8fc7\u5927\u3001\u51ed\u8bc1\u66b4\u9732\u3001\u7f51\u7edc\u8fb9\u754c\u8fc7\u5bbd\u6216\u654f\u611f\u64cd\u4f5c\u7f3a\u5c11\u72ec\u7acb\u5ba1\u6279\u548c\u5ba1\u8ba1\u3002',
    principleEn: 'The technique depends on an authorized identity, local or remote system capabilities, and network trust; risk comes from excessive privileges, exposed credentials, broad network boundaries, or unaudited sensitive operations.',
    mitigationZh: '\u5b9e\u65bd\u6700\u5c0f\u6743\u9650\u548c\u5206\u5c42\u7ba1\u7406\uff0c\u4fdd\u62a4\u51ed\u8bc1\u6750\u6599\uff0c\u9650\u5236\u8fdc\u7a0b\u7ba1\u7406\u548c\u8de8\u7f51\u6bb5\u8bbf\u95ee\uff0c\u5bf9\u8d26\u53f7\u3001\u670d\u52a1\u3001\u8ba1\u5212\u4efb\u52a1\u3001\u8bc1\u4e66\u548c\u5f02\u5e38\u96a7\u9053\u5efa\u7acb\u884c\u4e3a\u5ba1\u8ba1\u4e0e\u544a\u8b66\u3002',
    mitigationEn: 'Apply least privilege and tiered administration, protect credential material, restrict remote management and cross-segment access, and audit anomalous accounts, services, scheduled tasks, certificates, and tunnels.',
    references: ['https://attack.mitre.org/'],
  },
  {
    pattern: /.*/,
    difficulty: 'intermediate',
    principleZh: '\u4e0d\u53ef\u4fe1\u8f93\u5165\u3001\u914d\u7f6e\u6216\u4e1a\u52a1\u72b6\u6001\u8de8\u8d8a\u4fe1\u4efb\u8fb9\u754c\u65f6\u6ca1\u6709\u6267\u884c\u4e0e\u540e\u7eed\u89e3\u6790\u548c\u6743\u9650\u6a21\u578b\u4e00\u81f4\u7684\u670d\u52a1\u7aef\u6821\u9a8c\uff0c\u56e0\u6b64\u4ea7\u751f\u53ef\u91cd\u590d\u7684\u5b89\u5168\u5dee\u5f02\u3002',
    principleEn: 'Untrusted input, configuration, or business state crosses a trust boundary without server-side validation aligned with downstream parsing and authorization, creating a repeatable security difference.',
    mitigationZh: '\u5728\u670d\u52a1\u7aef\u4f7f\u7528\u5141\u8bb8\u5217\u8868\u3001\u89c4\u8303\u5316\u548c\u663e\u5f0f\u6388\u6743\uff0c\u6536\u7d27\u8fd0\u884c\u6743\u9650\uff0c\u5bf9\u5f02\u5e38\u8f93\u5165\u548c\u654f\u611f\u72b6\u6001\u8f6c\u79fb\u5efa\u7acb\u5ba1\u8ba1\uff0c\u5e76\u4f7f\u7528\u540c\u4e00\u57fa\u7ebf\u6837\u4f8b\u6267\u884c\u4fee\u590d\u56de\u5f52\u3002',
    mitigationEn: 'Use server-side allowlists, canonicalization, and explicit authorization, reduce runtime privileges, audit anomalous input and sensitive state transitions, and regression-test fixes with the same baseline case.',
    references: ['https://owasp.org/www-project-web-security-testing-guide/'],
  },
];

const cleanLineCount = value => String(value || '')
  .replace(/\(\s*[^()]{0,80}\b\d+\s*lines?\s*\)/gi, '')
  .replace(/\s+/g, ' ')
  .trim();

const cleanLabel = value => {
  if (typeof value === 'string') return cleanLineCount(value);
  if (!isObject(value)) return value;
  return {
    ...value,
    zh: cleanLineCount(value.zh),
    en: cleanLineCount(value.en),
  };
};

const clearLocalizedEnglish = value => {
  if (Array.isArray(value)) return value.map(clearLocalizedEnglish);
  if (!isObject(value)) return value;
  const next = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'en' && typeof item === 'string' && hasHan(item)) next[key] = '';
    else next[key] = clearLocalizedEnglish(item);
  }
  return next;
};

const nearestIndex = path => [...path].reverse().find(segment => Number.isInteger(segment));
const genericSyntaxExplanationPattern = /^Explains the (?:parameter|command|value|keyword|type) segment used by this reviewed validation command\.?$/i;
const knownEnglishRepairs = new Map([
  ['Checkcurrent Permission', 'Check current privileges.'],
  ['Checkwritable Service', 'Check writable services.'],
  ['COM Serverlistening Port', 'COM server listening port.'],
  ['Need with SYSTEM Permission Execute Program', 'Program to execute with SYSTEM privileges.'],
  ['with SYSTEM Permission Execute Command', 'Command to execute with SYSTEM privileges.'],
  ['Need Execute Program Path', 'Program path to execute.'],
  ['Locallistening Port', 'Local listening port.'],
]);

const syntaxExplanation = parent => {
  const type = String(parent?.type || 'value').trim() || 'value';
  const rawPart = String(parent?.part || '').replace(/\s+/g, ' ').trim();
  const asciiPart = hasHan(rawPart) ? '' : rawPart;
  const part = asciiPart.length > 96 ? `${asciiPart.slice(0, 93)}...` : asciiPart;
  return part
    ? `Describes how the ${type} segment ${JSON.stringify(part)} participates in this validation command.`
    : `Describes the ${type} segment used by this reviewed validation command.`;
};

const englishFallbackFor = (key, path, root, parent, ancestors) => {
  const localizedName = localizedText(root?.name, 'en').trim();
  const asciiId = String(root?.id || '').replace(/[^a-z0-9._-]+/gi, ' ').replace(/[-_]+/g, ' ').trim();
  const rootName = localizedName && !hasHan(localizedName) ? localizedName : (asciiId || 'the reviewed entry');
  const index = nearestIndex(path);
  const ordinal = Number.isInteger(index) ? index + 1 : 1;
  const type = ancestors.find(item => item && typeof item.type === 'string')?.type || 'value';
  if (key === 'name') return `Reviewed ${rootName}`;
  if (key === 'description') {
    if (path.includes('commands') || path.includes('execution') || path.includes('wafBypass')) {
      return `Run this ${rootName} validation command in an authorized lab, preserve the output, and compare it with the documented baseline.`;
    }
    return `${rootName} documents a bounded validation case for an authorized security review.`;
  }
  if (key === 'title') return `Validation step ${ordinal} for ${rootName}`;
  if (key === 'explanation') {
    const syntaxPart = ancestors.find(item => item && (typeof item.part === 'string' || typeof item.type === 'string'));
    return syntaxExplanation(syntaxPart) || `Describes the ${type} segment used by this reviewed validation command.`;
  }
  if (key === 'overview') return `The reviewed entry ${rootName} documents its prerequisites, normal baseline, controlled input, and server-side evidence.`;
  if (key === 'vulnerability') return `The security difference occurs when untrusted input crosses a parsing, authorization, or execution boundary without a matching server-side control.`;
  if (key === 'exploitation') return `In an authorized lab, establish a normal baseline, run one controlled sample, correlate server-side evidence, and stop on unintended changes.`;
  if (key === 'mitigation') return `Apply least privilege, strict validation, and the documented boundary control, then replay normal and negative cases to verify the fix.`;
  if (key === 'analysis') return `Interpret this result with the normal control, server-side logs, exact version, and a reproducible negative case; one response is not sufficient evidence.`;
  if (key === 'prerequisites') return `Confirm authorization, exact scope, component version, and a reversible test fixture before running this validation.`;
  if (key === 'opsecTips') return `Limit scope and request rate, retain only minimum evidence, and stop on credentials, non-lab data, or irreversible changes.`;
  if (key === 'category' || key === 'subCategory') return 'Reviewed security validation';
  if (key === 'review') return 'Reviewed decision and evidence record';
  return `English explanation for the reviewed ${rootName} field.`;
};

const completeEnglishNode = (value, root, path = [], ancestors = []) => {
  if (Array.isArray(value)) return value.map((item, index) => completeEnglishNode(item, root, [...path, index], ancestors));
  if (!isObject(value)) return value;
  const next = {};
  for (const [key, item] of Object.entries(value)) {
    if (key === 'en' && typeof item === 'string' && knownEnglishRepairs.has(item.trim())) {
      next[key] = knownEnglishRepairs.get(item.trim());
    } else if (key === 'en' && typeof item === 'string' && (
      !item.trim()
      || hasHan(item)
      || (path.at(-1) === 'explanation' && genericSyntaxExplanationPattern.test(item.trim()))
    )) {
      const field = path.at(-1) || '';
      next[key] = englishFallbackFor(field, path, root, value, ancestors);
    } else {
      next[key] = completeEnglishNode(item, root, [...path, key], [value, ...ancestors]);
    }
  }
  return next;
};

export const completeMissingEnglish = value => completeEnglishNode(clone(value), value);

const profileFor = payload => {
  const identity = `${displayText(payload.category)} ${displayText(payload.subCategory)} ${displayText(payload.name)}`;
  return editorialProfiles.find(profile => profile.pattern.test(identity)) || editorialProfiles.at(-1);
};

const substantive = value => displayText(value).trim().length >= 20;
const meaningfulChain = chain => {
  const items = asList(chain);
  if (items.length < 3) return false;
  const serialized = items.map(step => `${displayText(step.title)} ${displayText(step.description)}`).join('\n');
  if (genericChainPattern.test(serialized)) return false;
  const duplicateDescriptions = items.filter(step => displayText(step.title).trim() === displayText(step.description).trim()).length;
  return duplicateDescriptions / items.length < 0.5;
};

const firstPrerequisite = payload => displayText(asList(payload.prerequisites)[0])
  || '\u5df2\u786e\u8ba4\u6388\u6743\u8303\u56f4\u3001\u6d4b\u8bd5\u8d26\u53f7\u548c\u53ef\u56de\u6eda\u7684\u57fa\u7ebf\u6570\u636e';

const generatedTutorial = (payload, profile) => {
  const nameZh = displayText(payload.name) || '\u5f53\u524d\u5b89\u5168\u6280\u672f';
  const nameEn = localizedText(payload.name, 'en') || 'this security technique';
  const descriptionZh = displayText(payload.description);
  const executionTitlesZh = asList(payload.execution).slice(0, 3).map(item => displayText(item.title)).filter(Boolean).join('\u3001');
  const executionTitlesEn = asList(payload.execution).slice(0, 3).map(item => localizedText(item.title, 'en')).filter(Boolean).join(', ');
  return {
    overview: i18n(
      `${nameZh}\u805a\u7126\u7684\u662f${descriptionZh || '\u8f93\u5165\u3001\u89e3\u6790\u6216\u6743\u9650\u8fb9\u754c\u4e2d\u7684\u53ef\u91cd\u590d\u5b89\u5168\u5dee\u5f02'}\u3002\u5ba1\u67e5\u65f6\u9700\u540c\u65f6\u8bb0\u5f55\u9002\u7528\u6761\u4ef6\u3001\u6b63\u5e38\u57fa\u7ebf\u3001\u5f02\u5e38\u8f93\u5165\u548c\u670d\u52a1\u7aef\u8bc1\u636e\uff0c\u4e0d\u80fd\u53ea\u4f9d\u636e\u5355\u6b21\u54cd\u5e94\u4e0b\u7ed3\u8bba\u3002`,
      `${nameEn} focuses on a repeatable difference at an input, parsing, or authorization boundary. Review the preconditions, normal baseline, changed input, and server-side evidence together rather than relying on one response.`,
    ),
    vulnerability: i18n(profile.principleZh, profile.principleEn),
    exploitation: i18n(
      `\u5728\u6388\u6743\u6d4b\u8bd5\u73af\u5883\u4e2d\uff0c\u5148\u4f7f\u7528\u6b63\u5e38\u8f93\u5165\u5efa\u7acb\u72b6\u6001\u7801\u3001\u54cd\u5e94\u4f53\u3001\u5904\u7406\u65f6\u95f4\u548c\u65e5\u5fd7\u57fa\u7ebf\uff0c\u518d\u9010\u9879\u6267\u884c${executionTitlesZh || '\u5f53\u524d\u6761\u76ee\u4e2d\u7684\u9a8c\u8bc1\u6837\u4f8b'}\u3002\u6bcf\u6b21\u53ea\u6539\u53d8\u4e00\u4e2a\u53d8\u91cf\uff0c\u6838\u5bf9\u9884\u671f\u7ed3\u679c\u4e0e\u5047\u9633\u6027\u6761\u4ef6\uff0c\u4e00\u65e6\u51fa\u73b0\u975e\u9884\u671f\u5199\u5165\u3001\u6267\u884c\u6216\u6570\u636e\u53d8\u66f4\u5c31\u7acb\u5373\u505c\u6b62\u5e76\u56de\u6eda\u3002`,
      `In an authorized test environment, establish status, body, timing, and log baselines with normal input, then run ${executionTitlesEn || 'the listed validation samples'} one at a time. Change one variable, check expected evidence and false-positive conditions, and stop and roll back on unintended writes, execution, or data changes.`,
    ),
    mitigation: i18n(profile.mitigationZh, profile.mitigationEn),
    difficulty: profile.difficulty,
  };
};

const generatedChain = (payload, tutorial) => {
  const nameZh = displayText(payload.name) || '\u5f53\u524d\u6761\u76ee';
  const nameEn = localizedText(payload.name, 'en') || 'the current technique';
  const firstExecution = asList(payload.execution)[0];
  const firstTitleZh = displayText(firstExecution?.title) || '\u7b2c\u4e00\u4e2a\u9a8c\u8bc1\u6837\u4f8b';
  const firstTitleEn = localizedText(firstExecution?.title, 'en') || 'the first validation sample';
  return [
    {
      title: i18n('\u786e\u8ba4\u6388\u6743\u4e0e\u9002\u7528\u8fb9\u754c', 'Confirm authorization and scope'),
      description: i18n(`\u6838\u5bf9 ${nameZh} \u7684\u6d4b\u8bd5\u5bf9\u8c61\u3001\u8d26\u53f7\u3001\u6570\u636e\u548c\u505c\u6b62\u6761\u4ef6\uff1b\u5f53\u524d\u9996\u8981\u524d\u7f6e\u6761\u4ef6\u662f\u201c${firstPrerequisite(payload)}\u201d\u3002`, `Confirm the target, account, data, and stop conditions for ${nameEn}, including the documented prerequisites.`),
    },
    {
      title: i18n('\u5efa\u7acb\u6b63\u5e38\u4e1a\u52a1\u57fa\u7ebf', 'Establish a normal baseline'),
      description: i18n('\u4f7f\u7528\u6b63\u5e38\u8f93\u5165\u8bb0\u5f55\u8bf7\u6c42\u3001\u72b6\u6001\u7801\u3001\u54cd\u5e94\u4f53\u3001\u5904\u7406\u65f6\u95f4\u548c\u670d\u52a1\u7aef\u65e5\u5fd7\uff0c\u4e3a\u540e\u7eed\u5355\u53d8\u91cf\u5bf9\u7167\u63d0\u4f9b\u53ef\u91cd\u590d\u8bc1\u636e\u3002', 'Record the normal request, status, body, timing, and server logs so later single-variable comparisons have repeatable evidence.'),
    },
    {
      title: i18n(`\u6267\u884c\u201c${firstTitleZh}\u201d\u9a8c\u8bc1`, `Run the ${firstTitleEn} check`),
      description: i18n(`\u53ea\u66ff\u6362 ${nameZh} \u5bf9\u5e94\u7684\u4e00\u4e2a\u8f93\u5165\uff0c\u5bf9\u7167\u547d\u4ee4\u8bf4\u660e\u89c2\u5bdf\u89e3\u6790\u3001\u6388\u6743\u6216\u6267\u884c\u5dee\u5f02\uff0c\u5e76\u6392\u9664\u7f13\u5b58\u3001\u91cd\u8bd5\u548c\u968f\u673a\u5ef6\u8fdf\u7b49\u5047\u9633\u6027\u3002`, `Change one input for ${nameEn}, observe the documented parsing, authorization, or execution difference, and exclude cache, retry, and random-delay false positives.`),
      ...(firstExecution?.command ? { payload: firstExecution.command } : {}),
    },
    {
      title: i18n('\u4fdd\u5b58\u8bc1\u636e\u5e76\u6267\u884c\u4fee\u590d\u56de\u5f52', 'Preserve evidence and retest remediation'),
      description: i18n(`\u4fdd\u5b58\u6700\u5c0f\u8bf7\u6c42\u3001\u54cd\u5e94\u548c\u65e5\u5fd7\u8bc1\u636e\uff0c\u6309\u201c${displayText(tutorial.mitigation)}\u201d\u5b8c\u6210\u4fee\u590d\u540e\uff0c\u91cd\u653e\u6b63\u5e38\u4e0e\u5f02\u5e38\u57fa\u7ebf\uff0c\u786e\u8ba4\u4e1a\u52a1\u529f\u80fd\u4fdd\u7559\u4e14\u5b89\u5168\u5dee\u5f02\u6d88\u5931\u3002`, `Preserve the minimal request, response, and log evidence, apply the documented mitigation, and replay normal and abnormal baselines to confirm behavior remains available while the security difference disappears.`),
    },
  ];
};

const cleanCollectionPresentation = payload => {
  const next = clone(payload);
  next.name = cleanLabel(next.name);
  if (next.subCategory) next.subCategory = cleanLabel(next.subCategory);
  for (const area of ['execution', 'wafBypass']) {
    next[area] = asList(next[area]).map(entry => {
      const item = { ...entry, title: cleanLabel(entry.title) };
      const description = displayText(item.description);
      if (collectionResiduePattern.test(description)) {
        const titleZh = displayText(item.title) || displayText(next.name);
        const titleEn = localizedText(item.title, 'en') || localizedText(next.name, 'en') || 'Validation samples';
        item.description = i18n(`${titleZh}\u5305\u542b\u591a\u4e2a\u53ef\u590d\u73b0\u8f93\u5165\u6837\u4f8b\uff1b\u5e94\u9010\u6761\u6d4b\u8bd5\u5e76\u8bb0\u5f55\u54cd\u5e94\u4e0e\u65e5\u5fd7\u5dee\u5f02\u3002`, `${titleEn} contains multiple reproducible input samples; test them individually and record response and log differences.`);
      }
      return item;
    });
  }
  if (collectionResiduePattern.test(displayText(next.description))) {
    const nameZh = displayText(next.name);
    const nameEn = localizedText(next.name, 'en') || 'This entry';
    next.description = i18n(`${nameZh}\u6536\u5f55\u540c\u4e00\u6280\u672f\u8fb9\u754c\u4e0b\u7684\u8f93\u5165\u53d8\u4f53\uff0c\u7528\u4e8e\u5728\u6388\u6743\u73af\u5883\u4e2d\u5bf9\u7167\u9a8c\u8bc1\u89e3\u6790\u3001\u89c4\u8303\u5316\u548c\u6743\u9650\u5904\u7406\u5dee\u5f02\u3002`, `${nameEn} collects input variants for one technical boundary so parsing, normalization, and authorization differences can be compared in an authorized environment.`);
  }
  return next;
};

export const curatePayloadContent = source => {
  let payload = cleanCollectionPresentation(source);
  payload = clearLocalizedEnglish(payload);
  payload.category = canonicalCategory(payload.category);
  const profile = profileFor(payload);
  const generated = generatedTutorial(payload, profile);
  const currentTutorial = isObject(payload.tutorial) ? payload.tutorial : {};
  payload.tutorial = Object.fromEntries(tutorialFields.map(field => [
    field,
    substantive(currentTutorial[field]) ? currentTutorial[field] : generated[field],
  ]));
  payload.tutorial.difficulty = validDifficulties.has(currentTutorial.difficulty)
    ? currentTutorial.difficulty
    : generated.difficulty;

  if (!meaningfulChain(payload.attackChain)) {
    payload.attackChain = generatedChain(payload, payload.tutorial);
  }
  if (!substantive(payload.analysis)) {
    payload.analysis = i18n(
      `\u5bf9\u7167 ${displayText(payload.name)} \u7684\u6b63\u5e38\u4e0e\u5f02\u5e38\u8f93\u5165\uff0c\u7ed3\u5408\u72b6\u6001\u7801\u3001\u54cd\u5e94\u5dee\u5f02\u3001\u5904\u7406\u65f6\u95f4\u548c\u670d\u52a1\u7aef\u65e5\u5fd7\u5224\u5b9a\u7ed3\u679c\uff1b\u5355\u4e00\u5f02\u5e38\u54cd\u5e94\u4e0d\u8db3\u4ee5\u8bc1\u660e\u95ee\u9898\u3002`,
      `Compare normal and abnormal input for ${localizedText(payload.name, 'en') || 'this entry'} using status, response differences, timing, and server logs; one anomalous response alone is not sufficient evidence.`,
    );
  }
  if (!asList(payload.opsecTips).length) {
    payload.opsecTips = [
      i18n('\u4ec5\u4f7f\u7528\u6388\u6743\u7684\u6d4b\u8bd5\u6570\u636e\uff0c\u5e76\u9884\u5148\u786e\u8ba4\u505c\u6b62\u4e0e\u56de\u6eda\u6761\u4ef6\u3002', 'Use authorized test data only and define stop and rollback conditions in advance.'),
      i18n('\u63a7\u5236\u8bf7\u6c42\u901f\u7387\u548c\u5e76\u53d1\u5ea6\uff0c\u4fdd\u7559\u65f6\u95f4\u6233\u4ee5\u4fbf\u5173\u8054\u670d\u52a1\u7aef\u65e5\u5fd7\u3002', 'Control request rate and concurrency, and retain timestamps for server-log correlation.'),
    ];
  }
  if (!asList(payload.references).length) payload.references = [...profile.references];
  return completeMissingEnglish(clearLocalizedEnglish(payload));
};

const commandKey = value => String(value || '').replace(/\r\n?/g, '\n').trim();
const payloadCommandAreas = new Set(['execution', 'wafBypass']);

const commandLines = value => String(value ?? '').replace(/\r\n?/g, '\n').split('\n');

const commandLinesFromEntries = entries => asList(entries).flatMap(entry => commandLines(entry?.command));

const lineCounts = lines => {
  const counts = new Map();
  for (const line of lines) counts.set(line, (counts.get(line) || 0) + 1);
  return counts;
};

const validateCollectionSplitRouting = (source, replacements, toolTargets, retiredCommands) => {
  for (const retired of retiredCommands) {
    const zh = localizedText(retired?.reason, 'zh').trim();
    const en = localizedText(retired?.reason, 'en').trim();
    if (typeof retired?.command !== 'string' || commandLines(retired.command).length !== 1) {
      throw new Error(`Collection split retired command must be one exact source line: ${source.id}`);
    }
    if (zh.length < 12 || en.length < 20) {
      throw new Error(`Collection split retired command requires a bilingual reason: ${source.id}`);
    }
  }

  const sourceLines = commandLinesFromEntries([
    ...asList(source.execution),
    ...asList(source.wafBypass),
  ]);
  const routedPayloadLines = replacements.flatMap(replacement => {
    const result = { ...source, ...replacement };
    return commandLinesFromEntries([
      ...asList(result.execution),
      ...asList(result.wafBypass),
    ]);
  });
  const routedToolLines = toolTargets.flatMap(target => commandLinesFromEntries(target.commands));
  const retiredLines = retiredCommands.map(item => item.command);
  const available = lineCounts(sourceLines);
  const routed = lineCounts([...routedPayloadLines, ...routedToolLines, ...retiredLines]);

  for (const [line, count] of routed) {
    if (count > (available.get(line) || 0)) {
      throw new Error(`Collection split command line is routed more than once or is not in the source: ${source.id}: ${JSON.stringify(line)}`);
    }
  }
  for (const [line, count] of available) {
    if ((routed.get(line) || 0) < count) {
      throw new Error(`Collection split does not conserve source command lines: ${source.id}: ${JSON.stringify(line)}`);
    }
  }
};

const commandFromPayloadReference = (source, reference) => {
  if (!isObject(reference) || !payloadCommandAreas.has(reference.area) || !Number.isInteger(reference.index)) {
    return undefined;
  }
  const entry = asList(source?.[reference.area])[reference.index];
  return entry && typeof entry.command === 'string' ? entry.command : undefined;
};

const resolveAttackChainPayloadRefs = payload => ({
  ...payload,
  attackChain: asList(payload.attackChain).map(step => {
    if (step?.payloadRef === undefined) return step;
    if (step.payload !== undefined) {
      throw new Error(`Attack-chain step cannot contain payload and payloadRef: ${payload.id}`);
    }
    const referencedCommand = commandFromPayloadReference(payload, step.payloadRef);
    if (referencedCommand === undefined) {
      throw new Error(`Attack-chain payloadRef is unresolved: ${payload.id}`);
    }
    const resolved = { ...step, payload: referencedCommand };
    delete resolved.payloadRef;
    return resolved;
  }),
});

const collectLocalizedEnglishPaths = (value, path = [], output = []) => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectLocalizedEnglishPaths(item, [...path, index], output));
    return output;
  }
  if (!isObject(value)) return output;
  if (typeof value.en === 'string' && hasHan(value.en)) output.push([...path, 'en'].join('.'));
  for (const [key, item] of Object.entries(value)) {
    if (key === 'en') continue;
    collectLocalizedEnglishPaths(item, [...path, key], output);
  }
  return output;
};

const hasCorruptText = value => {
  const text = String(value || '');
  if (/\?{2,}|\uFFFD/.test(text)) return true;
  return [...text].some(character => {
    const code = character.codePointAt(0);
    return code <= 8 || code === 11 || code === 12 || (code >= 14 && code <= 31) || code === 127;
  });
};

const collectCorruptLocalizedPaths = (value, path = [], output = []) => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectCorruptLocalizedPaths(item, [...path, index], output));
    return output;
  }
  if (!isObject(value)) return output;
  for (const language of ['zh', 'en']) {
    if (typeof value[language] === 'string' && hasCorruptText(value[language])) {
      output.push([...path, language].join('.'));
    }
  }
  for (const [key, item] of Object.entries(value)) {
    if (key === 'zh' || key === 'en') continue;
    collectCorruptLocalizedPaths(item, [...path, key], output);
  }
  return output;
};

const overrideError = (code, id, detail = '') => ({ code, id, ...(detail ? { detail } : {}) });

export const validatePayloadOverrideDocument = (document, sourcePayloadsInput) => {
  const sourcePayloads = asList(sourcePayloadsInput);
  const sourceById = new Map(sourcePayloads.map(item => [item.id, item]));
  const prefix = String(document?.sourcePrefix || '').trim();
  const explicitIds = asList(document?.sourceIds).map(id => String(id || '').trim()).filter(Boolean);
  const usesExplicitIds = explicitIds.length > 0;
  const entries = asList(document?.entries);
  const errors = [];
  if (document?.schemaVersion !== 1) errors.push(overrideError('INVALID_SCHEMA', '', 'schemaVersion must equal 1'));
  if (!prefix && !usesExplicitIds) errors.push(overrideError('INVALID_SOURCE_SELECTOR', '', 'sourcePrefix or sourceIds is required'));
  if (prefix && usesExplicitIds) errors.push(overrideError('AMBIGUOUS_SOURCE_SELECTOR', '', 'use sourcePrefix or sourceIds, not both'));
  if (new Set(explicitIds).size !== explicitIds.length) errors.push(overrideError('DUPLICATE_SOURCE_ID', ''));
  for (const id of explicitIds) {
    if (!sourceById.has(id)) errors.push(overrideError('UNKNOWN_SOURCE_ID', id));
  }

  const expectedIds = (usesExplicitIds
    ? explicitIds.filter(id => sourceById.has(id))
    : sourcePayloads.map(item => item.id).filter(id => id === prefix || id.startsWith(`${prefix}-`)))
    .sort();
  const expectedIdSet = new Set(expectedIds);
  const counts = new Map();
  for (const entry of entries) counts.set(entry?.id, (counts.get(entry?.id) || 0) + 1);
  for (const id of expectedIds) {
    if (!counts.has(id)) errors.push(overrideError('MISSING_ID', id));
  }
  for (const [id, count] of counts) {
    if (!sourceById.has(id) || !expectedIdSet.has(id)) errors.push(overrideError('UNKNOWN_ID', id));
    if (count > 1) errors.push(overrideError('DUPLICATE_ID', id));
  }

  for (const entry of entries) {
    const id = String(entry?.id || '');
    const source = sourceById.get(id);
    if (!source) continue;
    if (!displayText(entry.name) || !displayText(entry.description) || !displayText(entry.category) || !displayText(entry.subCategory)) {
      errors.push(overrideError('MISSING_CONTENT', id));
    }

    const invalidTutorialFields = tutorialFields.filter(field => {
      const zh = localizedText(entry?.tutorial?.[field], 'zh').trim();
      return zh.length < 50;
    });
    if (
      invalidTutorialFields.length
      || !validDifficulties.has(entry?.tutorial?.difficulty)
    ) {
      errors.push(overrideError('INVALID_TUTORIAL', id, invalidTutorialFields.join(',')));
    }

    const chain = asList(entry.attackChain);
    const invalidChain = chain.length < 3 || chain.length > 6 || chain.some(step => (
      !displayText(step.title)
      || localizedText(step.description, 'zh').trim().length < 20
      || displayText(step.title).trim() === displayText(step.description).trim()
    ));
    if (invalidChain) errors.push(overrideError('INVALID_CHAIN', id));

    const commandSet = new Set([...asList(source.execution), ...asList(source.wafBypass)].map(item => commandKey(item.command)));
    for (const step of chain) {
      const referencedCommand = commandFromPayloadReference(source, step?.payloadRef);
      if (step?.payload && step?.payloadRef !== undefined) {
        errors.push(overrideError('AMBIGUOUS_CHAIN_PAYLOAD', id));
        break;
      }
      if (step?.payloadRef !== undefined && referencedCommand === undefined) {
        errors.push(overrideError('DANGLING_CHAIN_PAYLOAD_REF', id));
        break;
      }
      if (step.payload && !commandSet.has(commandKey(step.payload))) {
        errors.push(overrideError('DANGLING_CHAIN_PAYLOAD', id, String(step.payload).slice(0, 120)));
        break;
      }
    }
    if (!chain.some(step => (
      (step.payload && commandSet.has(commandKey(step.payload)))
      || commandFromPayloadReference(source, step?.payloadRef) !== undefined
    ))) {
      errors.push(overrideError('MISSING_CHAIN_PAYLOAD', id));
    }

    const localizedPaths = overrideContentFields.flatMap(field => collectLocalizedEnglishPaths(entry[field], [field]));
    if (localizedPaths.length) errors.push(overrideError('LOCALIZED_ENGLISH', id, localizedPaths.join(',')));

    const corruptPaths = overrideContentFields.flatMap(field => collectCorruptLocalizedPaths(entry[field], [field]));
    if (hasCorruptText(entry?.review?.rationale)) corruptPaths.push('review.rationale');
    if (corruptPaths.length) errors.push(overrideError('CORRUPT_TEXT', id, corruptPaths.join(',')));

    const references = asList(entry.references);
    if (!references.length || references.some(reference => {
      try {
        return new URL(reference).protocol !== 'https:';
      } catch {
        return true;
      }
    })) {
      errors.push(overrideError('INVALID_REFERENCE', id));
    }
    if (!['payload', 'tool', 'split'].includes(entry?.review?.decision)) {
      errors.push(overrideError('INVALID_DECISION', id));
    }
    if (document?.contentStandard === 2 && entry?.review?.decision === 'payload') {
      const prerequisites = asList(entry.prerequisites);
      const opsecTips = asList(entry.opsecTips);
      const operationalContentValid = prerequisites.length >= 2
        && prerequisites.every(item => localizedText(item, 'zh').trim().length >= 10 && localizedText(item, 'en').trim().length >= 10)
        && localizedText(entry.analysis, 'zh').trim().length >= 40
        && localizedText(entry.analysis, 'en').trim().length >= 40
        && opsecTips.length >= 2
        && opsecTips.every(item => localizedText(item, 'zh').trim().length >= 10 && localizedText(item, 'en').trim().length >= 10);
      if (!operationalContentValid) errors.push(overrideError('INCOMPLETE_OPERATIONAL_CONTENT', id));
    }
  }

  return errors.sort((left, right) => (
    left.id.localeCompare(right.id, 'en') || left.code.localeCompare(right.code, 'en')
  ));
};

export const applyPayloadOverrides = (payloadsInput, documentsInput, options = {}) => {
  const payloads = asList(payloadsInput).map(clone);
  const documents = asList(documentsInput);
  const entriesById = new Map();
  for (const document of documents) {
    const errors = validatePayloadOverrideDocument(document, payloads);
    if (errors.length && options.allowInvalid !== true) {
      const preview = errors.slice(0, 8).map(error => `${error.code}:${error.id}`).join(', ');
      throw new Error(`Invalid payload override document ${document?.sourcePrefix || '<unknown>'}: ${preview}`);
    }
    for (const entry of asList(document?.entries)) {
      if (entriesById.has(entry.id)) throw new Error(`Payload override appears in multiple documents: ${entry.id}`);
      entriesById.set(entry.id, entry);
    }
  }
  return payloads.map(payload => {
    const entry = entriesById.get(payload.id);
    if (!entry) return payload;
    const next = { ...payload };
    for (const field of requiredOverrideContentFields) next[field] = clone(entry[field]);
    for (const field of optionalOverrideContentFields) {
      if (entry[field] !== undefined) next[field] = clone(entry[field]);
    }
    return resolveAttackChainPayloadRefs(next);
  });
};

export const validatePayloadCommandOverrideDocument = (document, sourcePayloadsInput) => {
  const payloadsById = new Map(asList(sourcePayloadsInput).map(item => [item.id, item]));
  const entries = asList(document?.entries);
  const errors = [];
  if (document?.schemaVersion !== 1) errors.push(overrideError('INVALID_SCHEMA', '', 'schemaVersion must equal 1'));
  const counts = new Map();
  for (const entry of entries) counts.set(entry?.id, (counts.get(entry?.id) || 0) + 1);
  for (const [id, count] of counts) {
    if (!payloadsById.has(id)) errors.push(overrideError('UNKNOWN_ID', id));
    if (count > 1) errors.push(overrideError('DUPLICATE_ID', id));
  }
  for (const entry of entries) {
    const id = String(entry?.id || '');
    const source = payloadsById.get(id);
    if (!source) continue;
    const patches = asList(entry?.patches);
    if (!patches.length) {
      errors.push(overrideError('MISSING_PATCH', id));
      continue;
    }
    const patchKeys = new Set();
    for (const patch of patches) {
      const area = String(patch?.area || '');
      const index = patch?.index;
      if (!payloadCommandAreas.has(area) || !Number.isInteger(index) || index < 0 || index >= asList(source[area]).length) {
        errors.push(overrideError('INVALID_PATCH_TARGET', id, `${area}.${index}`));
        continue;
      }
      const key = `${area}.${index}`;
      if (patchKeys.has(key)) errors.push(overrideError('DUPLICATE_PATCH_TARGET', id, key));
      patchKeys.add(key);
      const sourceCommand = String(source[area][index]?.command || '');
      if (String(patch?.expectedCommand ?? '') !== sourceCommand) {
        errors.push(overrideError('STALE_COMMAND', id, key));
      }
      const nextCommand = String(patch?.command ?? '');
      if (!nextCommand.trim()) errors.push(overrideError('EMPTY_COMMAND', id, key));
      if (nextCommand === sourceCommand) errors.push(overrideError('NOOP_COMMAND', id, key));
      if (patch.title !== undefined) {
        const zh = localizedText(patch.title, 'zh').trim();
        const en = localizedText(patch.title, 'en').trim();
        if (!zh || !en || hasHan(en)) errors.push(overrideError('INVALID_PATCH_TITLE', id, key));
      }
      if (patch.description !== undefined) {
        const zh = localizedText(patch.description, 'zh').trim();
        const en = localizedText(patch.description, 'en').trim();
        if (zh.length < 12 || en.length < 30 || hasHan(en)) {
          errors.push(overrideError('INVALID_PATCH_DESCRIPTION', id, key));
        }
      }
      if (patch.syntaxBreakdown !== undefined && !Array.isArray(patch.syntaxBreakdown)) {
        errors.push(overrideError('INVALID_PATCH_SYNTAX_BREAKDOWN', id, key));
      }
      if (patch.platform !== undefined && !['all', 'linux', 'windows'].includes(patch.platform)) {
        errors.push(overrideError('INVALID_PATCH_PLATFORM', id, key));
      }
      if (patch.requiresAdmin !== undefined && typeof patch.requiresAdmin !== 'boolean') {
        errors.push(overrideError('INVALID_PATCH_REQUIRES_ADMIN', id, key));
      }
    }
  }
  return errors.sort((left, right) => (
    left.id.localeCompare(right.id, 'en') || left.code.localeCompare(right.code, 'en')
  ));
};

export const applyPayloadCommandOverrides = (payloadsInput, document, options = {}) => {
  const payloads = asList(payloadsInput).map(clone);
  const errors = validatePayloadCommandOverrideDocument(document || { schemaVersion: 1, entries: [] }, payloads);
  if (errors.length && options.allowInvalid !== true) {
    const preview = errors.slice(0, 8).map(error => `${error.code}:${error.id}`).join(', ');
    throw new Error(`Invalid payload command override document: ${preview}`);
  }
  const patchesById = new Map(asList(document?.entries).map(entry => [entry.id, asList(entry.patches)]));
  return payloads.map(payload => {
    const patches = patchesById.get(payload.id);
    if (!patches?.length) return payload;
    const next = clone(payload);
    for (const patch of patches) {
      const current = next[patch.area]?.[patch.index];
      if (!current) continue;
      const previousCommand = String(current.command || '');
      const nextCommand = String(patch.command || '');
      current.command = nextCommand;
      if (patch.title !== undefined) current.title = clone(patch.title);
      if (patch.description !== undefined) current.description = clone(patch.description);
      if (patch.syntaxBreakdown !== undefined) current.syntaxBreakdown = clone(patch.syntaxBreakdown);
      if (patch.platform !== undefined) current.platform = patch.platform;
      if (patch.requiresAdmin !== undefined) current.requiresAdmin = patch.requiresAdmin;
      next.attackChain = asList(next.attackChain).map(step => (
        step?.payload && commandKey(step.payload) === commandKey(previousCommand)
          ? { ...step, payload: nextCommand }
          : step
      ));
    }
    return next;
  });
};

const applyObjectPatch = (target, patch, ownerId) => {
  const operation = patch?.op || 'replace';
  if (!['replace', 'add'].includes(operation)) throw new Error(`Invalid tool override operation for ${ownerId}: ${operation}`);
  const segments = String(patch?.path || '').split('.').filter(Boolean);
  if (!segments.length) throw new Error(`Invalid tool override path for ${ownerId}`);
  let current = target;
  for (let index = 0; index < segments.length - 1; index += 1) {
    const segment = segments[index];
    if (current == null || !Object.prototype.hasOwnProperty.call(current, segment)) {
      throw new Error(`Tool override path does not exist for ${ownerId}: ${patch.path}`);
    }
    current = current[segment];
  }
  const finalSegment = segments.at(-1);
  if (current == null) {
    throw new Error(`Tool override path does not exist for ${ownerId}: ${patch.path}`);
  }
  const exists = Object.prototype.hasOwnProperty.call(current, finalSegment);
  if ((operation === 'replace' && !exists) || (operation === 'add' && exists)) {
    throw new Error(`Tool override path cannot be ${operation}ed for ${ownerId}: ${patch.path}`);
  }
  current[finalSegment] = clone(patch.value);
};

export const applyToolOverrides = (toolsInput, overridesInput) => {
  const tools = asList(toolsInput).map(clone);
  const byId = new Map(tools.map(tool => [tool.id, tool]));
  const patchPathsById = new Map();
  for (const override of asList(overridesInput)) {
    if (!override?.id) throw new Error('Missing tool override ID.');
    const tool = byId.get(override.id);
    if (!tool) throw new Error(`Unknown tool override ID: ${override.id}`);
    const seenPaths = patchPathsById.get(override.id) || new Set();
    for (const patch of asList(override.patches)) {
      if (seenPaths.has(patch?.path)) {
        throw new Error(`Duplicate tool override path for ${override.id}: ${patch?.path || ''}`);
      }
      applyObjectPatch(tool, patch, override.id);
      seenPaths.add(patch?.path);
    }
    patchPathsById.set(override.id, seenPaths);
  }
  return tools;
};

const reviewedToolCommandDescription = (entry, source) => {
  const description = entry?.description;
  const entryZh = localizedText(description, 'zh').trim();
  const entryEn = localizedText(description, 'en').trim();
  if (entryZh.length >= 24 && entryEn.length >= 32 && !hasHan(entryEn)) return clone(description);

  const sourceZh = localizedText(source?.description, 'zh').trim();
  const sourceEn = localizedText(source?.description, 'en').trim();
  if (sourceZh.length >= 24 && sourceEn.length >= 32 && !hasHan(sourceEn)) {
    const title = entry?.name || entry?.title;
    const titleZh = localizedText(title, 'zh').trim() || '审核命令';
    const titleEn = localizedText(title, 'en').trim();
    return i18n(`${titleZh}：${sourceZh}`, `${hasHan(titleEn) || !titleEn ? 'Reviewed command' : titleEn}: ${sourceEn}`);
  }
  return i18n('从 Payload 分类迁移的已审核工具命令；执行前需核对占位符、环境前提和回滚条件。', 'Reviewed tool command migrated from the Payload catalog; verify placeholders, environment prerequisites, and rollback conditions before execution.');
};

const toToolCommand = (entry, source) => ({
  name: clone(entry.name || entry.title || source?.name),
  command: String(entry.command || ''),
  description: reviewedToolCommandDescription(entry, source),
  ...(asList(entry.syntaxBreakdown).length ? { syntaxBreakdown: clone(entry.syntaxBreakdown) } : {}),
  ...(entry.platform ? { platform: entry.platform } : {}),
});

const mergeCommandEntries = (target, entries, source) => {
  const commands = asList(target.commands).map(clone);
  const seen = new Set(commands.map(item => commandKey(item.command)));
  for (const entry of entries) {
    const key = commandKey(entry.command);
    if (!key || seen.has(key)) continue;
    commands.push(toToolCommand(entry, source));
    seen.add(key);
  }
  return { ...target, commands };
};

const selectedEntries = (source, target) => [
  ...asList(target.commandIndexes).map(index => asList(source.execution)[index]).filter(Boolean),
  ...asList(target.wafBypassIndexes).map(index => asList(source.wafBypass)[index]).filter(Boolean),
  ...asList(target.commands).map(clone),
];

const validateIndexes = (source, values, field, length) => {
  const indexes = asList(values);
  const invalid = indexes.find(index => !Number.isInteger(index) || index < 0 || index >= length);
  if (invalid !== undefined) {
    throw new Error(`Invalid ${field} index ${invalid} for ${source.id}`);
  }
  if (new Set(indexes).size !== indexes.length) {
    throw new Error(`Duplicate ${field} index for ${source.id}`);
  }
  return indexes;
};

const validateCommandRouting = (source, targets, retained = {}) => {
  const routedExecution = new Set(validateIndexes(
    source,
    retained.execution,
    'retained execution',
    asList(source.execution).length,
  ));
  const routedWafBypass = new Set(validateIndexes(
    source,
    retained.wafBypass,
    'retained WAF bypass',
    asList(source.wafBypass).length,
  ));

  for (const target of targets) {
    if (!target?.targetToolId) throw new Error(`Missing targetToolId for ${source.id}`);
    for (const index of validateIndexes(source, target.commandIndexes, 'execution command', asList(source.execution).length)) {
      if (routedExecution.has(index)) throw new Error(`Execution command ${index} is routed more than once for ${source.id}`);
      routedExecution.add(index);
    }
    for (const index of validateIndexes(source, target.wafBypassIndexes, 'WAF bypass command', asList(source.wafBypass).length)) {
      if (routedWafBypass.has(index)) throw new Error(`WAF bypass command ${index} is routed more than once for ${source.id}`);
      routedWafBypass.add(index);
    }
  }
};

const removePayloadReferences = (nodes, payloadIds) => asList(nodes).flatMap(node => {
  if (node.payloadId && payloadIds.has(node.payloadId)) return [];
  const next = clone(node);
  if (Array.isArray(next.children)) next.children = removePayloadReferences(next.children, payloadIds);
  return [next];
});

const removeToolReferences = (nodes, toolIds) => asList(nodes).flatMap(node => {
  if (node.toolId && toolIds.has(node.toolId)) return [];
  const next = clone(node);
  if (Array.isArray(next.children)) next.children = removeToolReferences(next.children, toolIds);
  return [next];
});

const updateToolNavigationNames = (nodes, toolById) => asList(nodes).map(node => {
  const next = clone(node);
  const tool = toolById.get(next.toolId);
  if (tool) next.name = clone(tool.name);
  if (Array.isArray(next.children)) next.children = updateToolNavigationNames(next.children, toolById);
  return next;
});

const treeContainsTool = (nodes, toolId) => asList(nodes).some(node => (
  node.toolId === toolId || treeContainsTool(node.children, toolId)
));

const appendToolNavigation = (nodes, rootId, leaf) => asList(nodes).map(node => {
  const next = clone(node);
  if (next.id === rootId) {
    next.children = [...asList(next.children), leaf];
    return next;
  }
  if (Array.isArray(next.children)) next.children = appendToolNavigation(next.children, rootId, leaf);
  return next;
});

const navigationLabelKeys = value => [localizedText(value, 'zh'), localizedText(value, 'en'), displayText(value)]
  .map(item => item.trim().toLocaleLowerCase().replace(/\s+/g, ''))
  .filter(Boolean);

const payloadBranches = navigation => {
  const branches = new Map();
  for (const root of asList(navigation)) {
    for (const branch of asList(root.children)) {
      for (const key of navigationLabelKeys(branch.name)) branches.set(key, branch.id);
    }
  }
  return branches;
};

const collectPayloadReferences = navigation => {
  const references = new Map();
  const walk = (node, branchId) => {
    if (node.payloadId) {
      if (!references.has(node.payloadId)) references.set(node.payloadId, []);
      references.get(node.payloadId).push({ node: clone(node), branchId });
    }
    for (const child of asList(node.children)) walk(child, branchId);
  };
  for (const root of asList(navigation)) {
    for (const branch of asList(root.children)) walk(branch, branch.id);
  }
  return references;
};

const ensurePayloadBranches = (navigation, branchesInput) => {
  const branches = asList(branchesInput);
  const ids = branches.map(branch => String(branch?.id || '').trim());
  if (ids.some(id => !id) || new Set(ids).size !== ids.length) {
    throw new Error('Payload branch configuration contains a missing or duplicate ID.');
  }
  let next = asList(navigation).map(clone);
  const allIds = new Set();
  const collectIds = nodes => {
    for (const node of asList(nodes)) {
      allIds.add(node.id);
      collectIds(node.children);
    }
  };
  collectIds(next);
  for (const branch of branches) {
    if (allIds.has(branch.id)) {
      let updated = false;
      next = next.map(root => {
        if (root.id !== branch.rootId) return root;
        const children = asList(root.children).map(child => {
          if (child.id !== branch.id) return child;
          updated = true;
          return { ...child, name: clone(branch.name) };
        });
        return { ...root, children };
      });
      if (!updated) throw new Error(`Payload branch ${branch.id} is not a direct child of ${branch.rootId}`);
      continue;
    }
    let foundRoot = false;
    next = next.map(root => {
      if (root.id !== branch.rootId) return root;
      foundRoot = true;
      return {
        ...root,
        children: [...asList(root.children), {
          id: branch.id,
          name: clone(branch.name),
          children: [],
        }],
      };
    });
    if (!foundRoot) throw new Error(`Payload branch root not found: ${branch.rootId}`);
    allIds.add(branch.id);
  }
  return next;
};

const appendPayloadNavigation = (nodes, branchId, leaf) => asList(nodes).map(node => {
  const next = clone(node);
  if (next.id === branchId) {
    next.children = [...asList(next.children), clone(leaf)];
    return next;
  }
  if (Array.isArray(next.children)) next.children = appendPayloadNavigation(next.children, branchId, leaf);
  return next;
});

const updatePayloadNavigationNames = (nodes, payloadById) => asList(nodes).map(node => {
  const next = clone(node);
  const payload = payloadById.get(next.payloadId);
  if (payload) next.name = clone(payload.name);
  if (Array.isArray(next.children)) next.children = updatePayloadNavigationNames(next.children, payloadById);
  return next;
});

const synchronizePayloadNavigation = (navigation, payloads) => {
  let next = asList(navigation).map(clone);
  const branchByCategory = payloadBranches(next);
  const references = collectPayloadReferences(next);
  const payloadById = new Map(asList(payloads).map(payload => [payload.id, payload]));
  for (const payload of asList(payloads)) {
    const payloadReferences = references.get(payload.id) || [];
    if (!payloadReferences.length) continue;
    const branchId = navigationLabelKeys(payload.category)
      .map(key => branchByCategory.get(key))
      .find(Boolean);
    if (!branchId || payloadReferences.every(reference => reference.branchId === branchId)) continue;
    next = removePayloadReferences(next, new Set([payload.id]));
    const leaf = {
      ...payloadReferences[0].node,
      name: clone(payload.name),
      payloadId: payload.id,
    };
    delete leaf.children;
    next = appendPayloadNavigation(next, branchId, leaf);
  }
  return updatePayloadNavigationNames(next, payloadById);
};

const appendCollectionSplitNavigation = (navigation, splits, payloadById) => {
  let next = asList(navigation).map(clone);
  const sourceReferences = collectPayloadReferences(next);
  const sourceIds = new Set(splits.map(split => split.sourceId));
  next = removePayloadReferences(next, sourceIds);
  const branchByCategory = payloadBranches(next);
  const existingPayloadIds = new Set(collectPayloadReferences(next).keys());
  const usedNodeIds = new Set();
  const collectNodeIds = nodes => {
    for (const node of asList(nodes)) {
      usedNodeIds.add(node.id);
      collectNodeIds(node.children);
    }
  };
  collectNodeIds(next);

  for (const split of splits) {
    const originalReference = sourceReferences.get(split.sourceId)?.[0]?.node;
    asList(split.replacements).forEach((replacement, index) => {
      const payload = payloadById.get(replacement.id);
      if (!payload || existingPayloadIds.has(payload.id)) return;
      const branchId = navigationLabelKeys(payload.category)
        .map(key => branchByCategory.get(key))
        .find(Boolean);
      if (!branchId) return;
      let nodeId = index === 0 && originalReference?.id ? originalReference.id : `nav-${payload.id}`;
      while (usedNodeIds.has(nodeId)) nodeId = `${nodeId}-split`;
      usedNodeIds.add(nodeId);
      next = appendPayloadNavigation(next, branchId, {
        id: nodeId,
        name: clone(payload.name),
        payloadId: payload.id,
      });
      existingPayloadIds.add(payload.id);
    });
  }
  return next;
};

const newToolFromMigration = (source, target) => ({
  id: target.targetToolId,
  name: clone(target.targetName || source.name),
  description: clone(target.targetDescription || source.description),
  category: clone(target.targetCategory || source.category),
  commands: [],
  references: [...asList(source.references)],
});

const migrationTargets = migration => asList(migration.targets).length
  ? asList(migration.targets)
  : [migration];

const mergeMigrationTarget = (snapshot, toolsById, source, target, entries) => {
  const existing = toolsById.get(target.targetToolId);
  const base = existing?.item || newToolFromMigration(source, target);
  const tool = {
    ...base,
    ...(target.targetName ? { name: clone(target.targetName) } : {}),
    ...(target.targetDescription ? { description: clone(target.targetDescription) } : {}),
    ...(target.targetCategory ? { category: clone(target.targetCategory) } : {}),
    ...(target.targetReferences ? {
      references: [...new Set([...asList(base.references), ...asList(target.targetReferences)])],
    } : {}),
    ...(target.replaceCommands ? { commands: [] } : {}),
  };
  const merged = clearLocalizedEnglish(mergeCommandEntries(tool, entries, source));
  if (existing) {
    snapshot.tools[existing.index] = merged;
    existing.item = merged;
  } else {
    const index = snapshot.tools.length;
    snapshot.tools.push(merged);
    toolsById.set(merged.id, { item: merged, index });
  }

  if (!treeContainsTool(snapshot.toolNavigation, target.targetToolId)) {
    const leaf = {
      id: target.navId || target.targetToolId,
      name: clone(target.navName || target.targetName || source.name),
      toolId: target.targetToolId,
    };
    snapshot.toolNavigation = appendToolNavigation(snapshot.toolNavigation, target.navRootId, leaf);
  }
};

const applyToolMerges = (snapshot, mergesInput) => {
  const removedIds = new Set();
  for (const merge of asList(mergesInput)) {
    if (!merge?.sourceToolId || !merge?.targetToolId || merge.sourceToolId === merge.targetToolId) {
      throw new Error('Tool merge requires distinct sourceToolId and targetToolId values.');
    }
    const source = snapshot.tools.find(tool => tool.id === merge.sourceToolId && !removedIds.has(tool.id));
    const targetIndex = snapshot.tools.findIndex(tool => tool.id === merge.targetToolId && !removedIds.has(tool.id));
    if (!source || targetIndex < 0) throw new Error(`Tool merge source or target not found: ${merge.sourceToolId} -> ${merge.targetToolId}`);
    const target = snapshot.tools[targetIndex];
    const commands = asList(target.commands).map(clone);
    const seen = new Set(commands.map(command => commandKey(command.command)));
    if (merge.includeSourceCommands !== false) {
      for (const command of asList(source.commands)) {
        const key = commandKey(command.command);
        if (!key || seen.has(key)) continue;
        commands.push(clone(command));
        seen.add(key);
      }
    }
    snapshot.tools[targetIndex] = {
      ...target,
      commands,
      references: [...new Set([
        ...asList(target.references),
        ...(merge.includeSourceReferences === false ? [] : asList(source.references)),
      ])],
    };
    removedIds.add(source.id);
  }
  if (removedIds.size) {
    snapshot.tools = snapshot.tools.filter(tool => !removedIds.has(tool.id));
    snapshot.toolNavigation = removeToolReferences(snapshot.toolNavigation, removedIds);
  }
};

export const curatePayloadLibrary = (input, options = {}) => {
  const snapshot = {
    payloads: asList(input.payloads).map(clone),
    tools: asList(input.tools).map(clone),
    navigation: asList(input.navigation).map(clone),
    toolNavigation: asList(input.toolNavigation).map(clone),
  };
  const originalById = new Map(snapshot.payloads.map(item => [item.id, clone(item)]));
  snapshot.navigation = ensurePayloadBranches(snapshot.navigation, options.payloadBranches);
  const migrations = new Map(asList(options.toolMigrations).map(item => [item.sourceId, item]));
  const splits = new Map(asList(options.payloadSplits).map(item => [item.sourceId, item]));
  const collectionSplits = new Map(asList(options.collectionSplits).map(item => [item.sourceId, item]));
  snapshot.payloads = applyPayloadOverrides(snapshot.payloads, options.overrideDocuments || []);
  snapshot.payloads = applyPayloadCommandOverrides(snapshot.payloads, options.payloadCommandOverrides);
  snapshot.tools = applyToolOverrides(snapshot.tools, options.toolOverrides || []);
  const toolsById = new Map(snapshot.tools.map((item, index) => [item.id, { item, index }]));
  const migratedIds = new Set();
  const keptPayloads = [];
  const ledger = [];

  for (const source of snapshot.payloads) {
    const migration = migrations.get(source.id);
    const split = splits.get(source.id);
    const collectionSplit = collectionSplits.get(source.id);
    const decisions = [migration, split, collectionSplit].filter(Boolean);
    if (decisions.length > 1) throw new Error(`Payload cannot have multiple curation decisions: ${source.id}`);
    if (collectionSplit) {
      const replacements = asList(collectionSplit.replacements);
      const toolTargets = asList(collectionSplit.toolTargets);
      const retiredCommands = asList(collectionSplit.retiredCommands);
      if (!replacements.length && !toolTargets.length) {
        throw new Error(`Collection split requires at least one payload or tool target: ${source.id}`);
      }
      const replacementIds = replacements.map(item => String(item?.id || '').trim());
      if (replacementIds.some(id => !id) || new Set(replacementIds).size !== replacementIds.length) {
        throw new Error(`Collection split contains missing or duplicate replacement IDs: ${source.id}`);
      }
      for (const target of toolTargets) {
        if (!target?.targetToolId || !asList(target.commands).length) {
          throw new Error(`Collection split tool target requires a targetToolId and commands: ${source.id}`);
        }
      }
      validateCollectionSplitRouting(source, replacements, toolTargets, retiredCommands);
      const resultContentHashes = {};
      for (const replacement of replacements) {
        const existing = originalById.get(replacement.id);
        if (existing && replacement.id !== source.id) {
          throw new Error(`Collection split replacement ID already exists: ${replacement.id}`);
        }
        const payload = curatePayloadContent(resolveAttackChainPayloadRefs({
          ...clone(source),
          ...clone(replacement),
          id: replacement.id,
        }));
        keptPayloads.push(payload);
        resultContentHashes[payload.id] = payloadContentHash(payload);
      }
      for (const target of toolTargets) {
        mergeMigrationTarget(snapshot, toolsById, source, target, asList(target.commands));
      }
      ledger.push({
        id: source.id,
        decision: 'split',
        targetPayloadIds: replacementIds,
        ...(toolTargets.length ? { targetToolIds: toolTargets.map(target => target.targetToolId) } : {}),
        ...(retiredCommands.length ? { retiredCommands: clone(retiredCommands) } : {}),
        contentHash: payloadContentHash(originalById.get(source.id) || source),
        resultContentHashes,
      });
      continue;
    }
    if (!migration && !split) {
      const curated = curatePayloadContent(source);
      keptPayloads.push(curated);
      ledger.push({
        id: source.id,
        decision: 'payload',
        contentHash: payloadContentHash(originalById.get(source.id) || source),
        resultContentHash: payloadContentHash(curated),
      });
      continue;
    }

    if (migration) {
      const targets = migrationTargets(migration);
      const usesReviewedRouting = asList(migration.targets).length > 0;
      validateCommandRouting(source, targets);
      for (const target of targets) {
        const entries = usesReviewedRouting ? selectedEntries(source, target) : [
          ...asList(source.execution),
          ...asList(source.wafBypass),
        ];
        mergeMigrationTarget(snapshot, toolsById, source, target, entries);
      }
      migratedIds.add(source.id);
      const targetToolIds = targets.map(target => target.targetToolId);
      ledger.push({
        id: source.id,
        decision: 'tool',
        ...(targetToolIds.length === 1 ? { targetToolId: targetToolIds[0] } : {}),
        targetToolIds,
        contentHash: payloadContentHash(originalById.get(source.id) || source),
      });
      continue;
    }

    const targets = migrationTargets(split);
    const retainExecutionIndexes = validateIndexes(
      source,
      split.retainExecutionIndexes,
      'retained execution',
      asList(source.execution).length,
    );
    const retainWafBypassIndexes = split.retainWafBypassIndexes === undefined
      ? asList(source.wafBypass).map((_, index) => index)
      : validateIndexes(
        source,
        split.retainWafBypassIndexes,
        'retained WAF bypass',
        asList(source.wafBypass).length,
      );
    validateCommandRouting(source, targets, {
      execution: retainExecutionIndexes,
      wafBypass: retainWafBypassIndexes,
    });
    for (const target of targets) {
      mergeMigrationTarget(snapshot, toolsById, source, target, selectedEntries(source, target));
    }
    const retained = {
      ...source,
      ...clone(split.payloadOverrides || {}),
      execution: [
        ...retainExecutionIndexes.map(index => clone(source.execution[index])),
        ...asList(split.retainCommands).map(clone),
      ],
      wafBypass: retainWafBypassIndexes.map(index => clone(source.wafBypass[index])),
    };
    const curated = curatePayloadContent(resolveAttackChainPayloadRefs(retained));
    keptPayloads.push(curated);
    ledger.push({
      id: source.id,
      decision: 'split',
      targetToolIds: targets.map(target => target.targetToolId),
      contentHash: payloadContentHash(originalById.get(source.id) || source),
      resultContentHash: payloadContentHash(curated),
    });
  }

  snapshot.payloads = keptPayloads;
  snapshot.navigation = removePayloadReferences(snapshot.navigation, migratedIds);
  snapshot.navigation = appendCollectionSplitNavigation(
    snapshot.navigation,
    asList(options.collectionSplits),
    new Map(snapshot.payloads.map(payload => [payload.id, payload])),
  );
  snapshot.navigation = synchronizePayloadNavigation(snapshot.navigation, snapshot.payloads);
  applyToolMerges(snapshot, options.toolMerges);
  snapshot.toolNavigation = updateToolNavigationNames(
    snapshot.toolNavigation,
    new Map(snapshot.tools.map(tool => [tool.id, tool])),
  );
  snapshot.payloads = snapshot.payloads.map(payload => completeMissingEnglish(payload));
  snapshot.tools = snapshot.tools.map(tool => completeMissingEnglish(tool));
  snapshot.payloads = snapshot.payloads.map(payload => ({ ...payload, references: normalizeReferenceUrls(payload.references) }));
  snapshot.tools = snapshot.tools.map(tool => ({ ...tool, references: normalizeReferenceUrls(tool.references) }));
  snapshot.navigation = snapshot.navigation.map(node => completeMissingEnglish(node));
  snapshot.toolNavigation = snapshot.toolNavigation.map(node => completeMissingEnglish(node));
  return { snapshot, ledger, migratedIds: [...migratedIds] };
};
