import type { NavItem } from '../types';

export const navigationData: NavItem[] = [
  {
    id: 'web',
    name: { zh: '🌐 Web应用攻防', en: '🌐 Web Application' },
    children: [
      {
        id: 'sqli',
        name: { zh: 'SQL/NoSQL注入', en: 'SQL/NoSQL Injection' },
        children: [
          { id: 'sqli-mysql', name: { zh: 'MySQL注入', en: 'MySQL Injection' }, payloadId: 'sqli-mysql-basic' },
          { id: 'sqli-mysql-advanced', name: { zh: 'MySQL高级注入', en: 'MySQL Advanced Injection' }, payloadId: 'sqli-mysql-advanced' },
          { id: 'sqli-mssql', name: { zh: 'MSSQL注入', en: 'MSSQL Injection' }, payloadId: 'sqli-mssql-basic' },
          { id: 'sqli-mssql-advanced', name: { zh: 'MSSQL高级注入', en: 'MSSQL Advanced Injection' }, payloadId: 'sqli-mssql-advanced' },
          { id: 'sqli-oracle', name: { zh: 'Oracle注入', en: 'Oracle Injection' }, payloadId: 'sqli-oracle-basic' },
          { id: 'sqli-oracle-advanced', name: { zh: 'Oracle高级注入', en: 'Oracle Advanced Injection' }, payloadId: 'sqli-oracle-advanced' },
          { id: 'sqli-postgres', name: { zh: 'PostgreSQL注入', en: 'PostgreSQL Injection' }, payloadId: 'sqli-postgres-basic' },
          { id: 'sqli-sqlite', name: { zh: 'SQLite注入', en: 'SQLite Injection' }, payloadId: 'sqli-sqlite-basic' },
          { id: 'sqli-mongodb', name: { zh: 'MongoDB注入', en: 'MongoDB Injection' }, payloadId: 'sqli-mongodb-basic' },
          { id: 'sqli-redis', name: { zh: 'Redis注入', en: 'Redis Injection' }, payloadId: 'sqli-redis' },
          { id: 'sqli-blind', name: { zh: '布尔盲注', en: 'Boolean Blind Injection' }, payloadId: 'sqli-blind' },
          { id: 'sqli-time', name: { zh: '时间盲注', en: 'Time-based Blind Injection' }, payloadId: 'sqli-time-based' },
          { id: 'sqli-error', name: { zh: '报错注入', en: 'Error-based Injection' }, payloadId: 'sqli-error-based' },
          { id: 'sqli-second-order', name: { zh: '二阶注入', en: 'Second-order Injection' }, payloadId: 'sqli-second-order' },
          { id: 'sqli-union', name: { zh: '联合查询注入', en: 'Union-based Injection' }, payloadId: 'sqli-union' },
          { id: 'sqli-stacked', name: { zh: '堆叠查询注入', en: 'Stacked Queries Injection' }, payloadId: 'sqli-stacked' },
          { id: 'sqli-waf-bypass', name: { zh: 'WAF绕过技术', en: 'WAF Bypass Techniques' }, payloadId: 'sqli-waf-bypass' }
        ]
      },
      {
        id: 'xss',
        name: { zh: 'XSS跨站脚本', en: 'XSS Cross-Site Scripting' },
        children: [
          { id: 'xss-reflected', name: { zh: '反射型XSS', en: 'Reflected XSS' }, payloadId: 'xss-reflected' },
          { id: 'xss-stored', name: { zh: '存储型XSS', en: 'Stored XSS' }, payloadId: 'xss-stored' },
          { id: 'xss-dom', name: { zh: 'DOM型XSS', en: 'DOM-based XSS' }, payloadId: 'xss-dom' },
          { id: 'xss-mxss', name: { zh: '突变型XSS(mXSS)', en: 'Mutation XSS (mXSS)' }, payloadId: 'xss-mxss' },
          { id: 'xss-unicode', name: 'Unicode XSS', payloadId: 'xss-unicode' },
          { id: 'xss-csp-bypass', name: { zh: 'CSP绕过', en: 'CSP Bypass' }, payloadId: 'xss-csp-bypass' },
          { id: 'xss-filter-bypass', name: { zh: '过滤器绕过', en: 'Filter Bypass' }, payloadId: 'xss-filter-bypass' },
          { id: 'xss-encoding', name: { zh: '编码绕过', en: 'Encoding Bypass' }, payloadId: 'xss-encoding' },
          { id: 'xss-polyglot', name: 'Polyglot XSS', payloadId: 'xss-polyglot' },
          { id: 'xss-cookie-theft', name: { zh: 'Cookie窃取', en: 'Cookie Theft' }, payloadId: 'xss-cookie-theft' },
          { id: 'xss-keylogger', name: { zh: '键盘记录', en: 'Keylogger' }, payloadId: 'xss-keylogger' },
          { id: 'xss-beef', name: { zh: 'BeEF利用', en: 'BeEF Exploitation' }, payloadId: 'xss-beef' }
        ]
      },
      {
        id: 'ssrf',
        name: { zh: 'SSRF服务端请求伪造', en: 'SSRF Server-Side Request Forgery' },
        children: [
          { id: 'ssrf-basic', name: { zh: '基础SSRF攻击', en: 'Basic SSRF Attack' }, payloadId: 'ssrf-basic' },
          { id: 'ssrf-cloud-aws', name: { zh: 'AWS元数据攻击', en: 'AWS Metadata Attack' }, payloadId: 'ssrf-cloud-aws' },
          { id: 'ssrf-cloud-gcp', name: { zh: 'GCP元数据攻击', en: 'GCP Metadata Attack' }, payloadId: 'ssrf-cloud-gcp' },
          { id: 'ssrf-cloud-azure', name: { zh: 'Azure元数据攻击', en: 'Azure Metadata Attack' }, payloadId: 'ssrf-cloud-azure' },
          { id: 'ssrf-protocol', name: { zh: '协议利用', en: 'Protocol Exploitation' }, payloadId: 'ssrf-protocol' },
          { id: 'ssrf-gopher', name: { zh: 'Gopher攻击', en: 'Gopher Attack' }, payloadId: 'ssrf-gopher' },
          { id: 'ssrf-dict', name: { zh: 'Dict协议攻击', en: 'Dict Protocol Attack' }, payloadId: 'ssrf-dict' },
          { id: 'ssrf-file', name: { zh: 'File协议攻击', en: 'File Protocol Attack' }, payloadId: 'ssrf-file' },
          { id: 'ssrf-bypass', name: { zh: 'SSRF绕过技术', en: 'SSRF Bypass Techniques' }, payloadId: 'ssrf-bypass' },
          { id: 'ssrf-dns-rebinding', name: { zh: 'DNS重绑定', en: 'DNS Rebinding' }, payloadId: 'ssrf-dns-rebinding' },
          { id: 'ssrf-redis', name: { zh: 'SSRF攻击Redis', en: 'SSRF to Redis' }, payloadId: 'ssrf-redis' },
          { id: 'ssrf-mysql', name: { zh: 'SSRF攻击MySQL', en: 'SSRF to MySQL' }, payloadId: 'ssrf-mysql' }
        ]
      },
      {
        id: 'rce',
        name: { zh: 'RCE远程代码执行', en: 'RCE Remote Code Execution' },
        children: [
          { id: 'rce-php', name: { zh: 'PHP代码执行', en: 'PHP Code Execution' }, payloadId: 'rce-php' },
          { id: 'rce-php-filter', name: { zh: 'PHP Filter链', en: 'PHP Filter Chain' }, payloadId: 'rce-php-filter' },
          { id: 'rce-cmd', name: { zh: '命令注入', en: 'Command Injection' }, payloadId: 'rce-command-injection' },
          { id: 'rce-cmd-blind', name: { zh: '盲命令注入', en: 'Blind Command Injection' }, payloadId: 'rce-cmd-blind' },
          { id: 'rce-deserialize', name: { zh: '反序列化漏洞', en: 'Deserialization Vulnerability' }, payloadId: 'rce-deserialize' },
          { id: 'rce-deserialize-php', name: { zh: 'PHP反序列化', en: 'PHP Deserialization' }, payloadId: 'rce-deserialize-php' },
          { id: 'rce-deserialize-java', name: { zh: 'Java反序列化', en: 'Java Deserialization' }, payloadId: 'rce-deserialize-java' },
          { id: 'rce-include', name: { zh: '文件包含RCE', en: 'File Inclusion RCE' }, payloadId: 'rce-include' },
          { id: 'rce-log-poison', name: { zh: '日志投毒RCE', en: 'Log Poisoning RCE' }, payloadId: 'rce-log-poison' },
          { id: 'rce-image', name: { zh: '图片马RCE', en: 'Image Webshell RCE' }, payloadId: 'rce-image' },
          { id: 'rce-htaccess', name: { zh: '.htaccess利用', en: '.htaccess Exploitation' }, payloadId: 'rce-htaccess' }
        ]
      },
      {
        id: 'xxe',
        name: { zh: 'XXE实体注入', en: 'XXE XML Entity Injection' },
        children: [
          { id: 'xxe-basic', name: { zh: '基础XXE攻击', en: 'Basic XXE Attack' }, payloadId: 'xxe-basic' },
          { id: 'xxe-blind', name: { zh: '盲注XXE', en: 'Blind XXE' }, payloadId: 'xxe-blind' },
          { id: 'xxe-oob', name: { zh: 'OOB外带攻击', en: 'OOB Out-of-Band Attack' }, payloadId: 'xxe-oob' },
          { id: 'xxe-ssrf', name: { zh: 'XXE+SSRF组合', en: 'XXE + SSRF Combo' }, payloadId: 'xxe-ssrf' },
          { id: 'xxe-rce', name: { zh: 'XXE到RCE', en: 'XXE to RCE' }, payloadId: 'xxe-rce' },
          { id: 'xxe-file-read', name: { zh: '文件读取', en: 'File Read' }, payloadId: 'xxe-file-read' },
          { id: 'xxe-dtd', name: { zh: '外部DTD利用', en: 'External DTD Exploitation' }, payloadId: 'xxe-dtd' },
          { id: 'xxe-xlsx', name: { zh: 'XLSX文件XXE', en: 'XLSX File XXE' }, payloadId: 'xxe-xlsx' },
          { id: 'xxe-docx', name: { zh: 'DOCX文件XXE', en: 'DOCX File XXE' }, payloadId: 'xxe-docx' }
        ]
      },
      {
        id: 'ssti',
        name: { zh: 'SSTI模板注入', en: 'SSTI Template Injection' },
        children: [
          { id: 'ssti-jinja2', name: 'Jinja2/Twig', payloadId: 'ssti-jinja2' },
          { id: 'ssti-freemarker', name: 'FreeMarker', payloadId: 'ssti-freemarker' },
          { id: 'ssti-velocity', name: 'Velocity', payloadId: 'ssti-velocity' },
          { id: 'ssti-thymeleaf', name: 'Thymeleaf', payloadId: 'ssti-thymeleaf' },
          { id: 'ssti-smarty', name: 'Smarty', payloadId: 'ssti-smarty' },
          { id: 'ssti-mako', name: 'Mako', payloadId: 'ssti-mako' },
          { id: 'ssti-tornado', name: 'Tornado', payloadId: 'ssti-tornado' },
          { id: 'ssti-django', name: 'Django', payloadId: 'ssti-django' },
          { id: 'ssti-erb', name: 'ERB (Ruby)', payloadId: 'ssti-erb' },
          { id: 'ssti-pug', name: 'Pug/Jade', payloadId: 'ssti-pug' }
        ]
      },
      {
        id: 'lfi-rfi',
        name: { zh: 'LFI/RFI文件包含', en: 'LFI/RFI File Inclusion' },
        children: [
          { id: 'lfi-basic', name: { zh: '本地文件包含', en: 'Local File Inclusion' }, payloadId: 'lfi-basic' },
          { id: 'rfi-basic', name: { zh: '远程文件包含', en: 'Remote File Inclusion' }, payloadId: 'rfi-basic' },
          { id: 'lfi-log', name: { zh: '日志投毒', en: 'Log Poisoning' }, payloadId: 'lfi-log-poison' },
          { id: 'lfi-wrapper', name: { zh: '伪协议利用', en: 'Wrapper Exploitation' }, payloadId: 'lfi-wrapper' },
          { id: 'lfi-traversal', name: { zh: '目录遍历', en: 'Directory Traversal' }, payloadId: 'lfi-traversal' },
          { id: 'lfi-php-filter', name: 'PHP Filter', payloadId: 'lfi-php-filter' },
          { id: 'lfi-php-input', name: 'PHP Input', payloadId: 'lfi-php-input' },
          { id: 'lfi-php-data', name: 'PHP Data', payloadId: 'lfi-php-data' },
          { id: 'lfi-php-zip', name: 'PHP Zip', payloadId: 'lfi-php-zip' },
          { id: 'lfi-phar', name: { zh: 'Phar反序列化', en: 'Phar Deserialization' }, payloadId: 'lfi-phar' },
          { id: 'lfi-session', name: { zh: 'Session文件包含', en: 'Session File Inclusion' }, payloadId: 'lfi-session' },
          { id: 'lfi-proc', name: { zh: 'Proc文件系统', en: 'Proc Filesystem' }, payloadId: 'lfi-proc' }
        ]
      },
      {
        id: 'csrf',
        name: { zh: 'CSRF跨站请求伪造', en: 'CSRF Cross-Site Request Forgery' },
        children: [
          { id: 'csrf-basic', name: { zh: '基础CSRF攻击', en: 'Basic CSRF Attack' }, payloadId: 'csrf-basic' },
          { id: 'csrf-json', name: 'JSON CSRF', payloadId: 'csrf-json' },
          { id: 'csrf-bypass', name: { zh: '绕过技术', en: 'Bypass Techniques' }, payloadId: 'csrf-bypass' },
          { id: 'csrf-samesite', name: { zh: 'SameSite绕过', en: 'SameSite Bypass' }, payloadId: 'csrf-samesite' },
          { id: 'csrf-token-bypass', name: { zh: 'Token绕过', en: 'Token Bypass' }, payloadId: 'csrf-token-bypass' },
          { id: 'csrf-referer-bypass', name: { zh: 'Referer绕过', en: 'Referer Bypass' }, payloadId: 'csrf-referer-bypass' },
          { id: 'csrf-flash', name: { zh: 'Flash CSRF', en: 'Flash CSRF' }, payloadId: 'csrf-flash' },
          { id: 'csrf-cors', name: { zh: 'CORS配置错误', en: 'CORS Misconfiguration' }, payloadId: 'csrf-cors' }
        ]
      },
      {
        id: 'api-security',
        name: { zh: 'API安全', en: 'API Security' },
        children: [
          { id: 'graphql', name: { zh: 'GraphQL安全', en: 'GraphQL Security' }, payloadId: 'graphql-injection' },
          { id: 'graphql-introspection', name: { zh: 'GraphQL内省', en: 'GraphQL Introspection' }, payloadId: 'graphql-introspection' },
          { id: 'graphql-batching', name: { zh: 'GraphQL批量查询', en: 'GraphQL Batching' }, payloadId: 'graphql-batching' },
          { id: 'rest-api', name: { zh: 'REST API安全', en: 'REST API Security' }, payloadId: 'rest-api-security' },
          { id: 'api-idor', name: { zh: 'IDOR漏洞', en: 'IDOR Vulnerability' }, payloadId: 'api-idor' },
          { id: 'api-rate-limit', name: { zh: '速率限制绕过', en: 'Rate Limit Bypass' }, payloadId: 'api-rate-limit' },
          { id: 'api-mass-assignment', name: { zh: '批量赋值', en: 'Mass Assignment' }, payloadId: 'api-mass-assignment' },
          { id: 'api-bola', name: { zh: 'BOLA漏洞', en: 'BOLA Vulnerability' }, payloadId: 'api-bola' },
          { id: 'api-injection', name: { zh: 'API注入', en: 'API Injection' }, payloadId: 'api-injection' }
        ]
      },
      {
        id: 'framework-vulns',
        name: { zh: '框架漏洞', en: 'Framework Vulnerabilities' },
        children: [
          { id: 'spring', name: 'Spring Actuator', payloadId: 'spring-actuator' },
          { id: 'spring-spel', name: { zh: 'Spring SpEL注入', en: 'Spring SpEL Injection' }, payloadId: 'spring-spel' },
          { id: 'spring-cloud', name: 'Spring Cloud', payloadId: 'spring-cloud' },
          { id: 'struts2', name: 'Struts2 RCE', payloadId: 'struts2-rce' },
          { id: 'struts2-ognl', name: 'Struts2 OGNL', payloadId: 'struts2-ognl' },
          { id: 'weblogic', name: 'WebLogic RCE', payloadId: 'weblogic-rce' },
          { id: 'weblogic-t3', name: { zh: 'WebLogic T3协议', en: 'WebLogic T3 Protocol' }, payloadId: 'weblogic-t3' },
          { id: 'weblogic-iiop', name: 'WebLogic IIOP', payloadId: 'weblogic-iiop' },
          { id: 'thinkphp', name: 'ThinkPHP RCE', payloadId: 'thinkphp-rce' },
          { id: 'laravel', name: 'Laravel RCE', payloadId: 'laravel-rce' },
          { id: 'fastjson', name: 'Fastjson RCE', payloadId: 'fastjson-rce' },
          { id: 'log4j', name: 'Log4j RCE', payloadId: 'log4j-rce' },
          { id: 'shiro', name: 'Apache Shiro', payloadId: 'shiro-deserialize' },
          { id: 'weblogic-xmldecoder', name: 'WebLogic XMLDecoder', payloadId: 'weblogic-xmldecoder' },
          { id: 'jboss', name: { zh: 'JBoss漏洞', en: 'JBoss Vulnerability' }, payloadId: 'jboss-vuln' },
          { id: 'tomcat', name: { zh: 'Tomcat漏洞', en: 'Tomcat Vulnerability' }, payloadId: 'tomcat-vuln' },
          { id: 'django', name: { zh: 'Django漏洞', en: 'Django Vulnerability' }, payloadId: 'django-vuln' },
          { id: 'flask', name: { zh: 'Flask漏洞', en: 'Flask Vulnerability' }, payloadId: 'flask-vuln' }
        ]
      },
      {
        id: 'auth-vulns',
        name: { zh: '认证漏洞', en: 'Authentication Vulnerabilities' },
        children: [
          { id: 'auth-bypass', name: { zh: '认证绕过', en: 'Auth Bypass' }, payloadId: 'auth-bypass' },
          { id: 'auth-brute', name: { zh: '暴力破解', en: 'Brute Force' }, payloadId: 'auth-brute' },
          { id: 'auth-session', name: { zh: '会话劫持', en: 'Session Hijacking' }, payloadId: 'auth-session' },
          { id: 'auth-password', name: { zh: '密码重置漏洞', en: 'Password Reset Vulnerability' }, payloadId: 'auth-password-reset' },
          { id: 'auth-oauth', name: { zh: 'OAuth漏洞', en: 'OAuth Vulnerability' }, payloadId: 'auth-oauth' },
          { id: 'auth-saml', name: { zh: 'SAML漏洞', en: 'SAML Vulnerability' }, payloadId: 'auth-saml' },
          { id: 'auth-2fa', name: { zh: '2FA绕过', en: '2FA Bypass' }, payloadId: 'auth-2fa' },
          { id: 'auth-captcha', name: { zh: '验证码绕过', en: 'CAPTCHA Bypass' }, payloadId: 'auth-captcha' },
          { id: 'auth-remember-me', name: { zh: '记住我漏洞', en: 'Remember-Me Vulnerability' }, payloadId: 'auth-remember-me' },
          { id: 'auth-jwt', name: { zh: 'JWT认证漏洞', en: 'JWT Auth Vulnerability' }, payloadId: 'auth-jwt' }
        ]
      },
      {
        id: 'file-vulns',
        name: { zh: '文件漏洞', en: 'File Vulnerabilities' },
        children: [
          { id: 'file-upload', name: { zh: '文件上传', en: 'File Upload' }, payloadId: 'file-upload-bypass' },
          { id: 'file-upload-rce', name: { zh: '文件上传代码执行', en: 'File Upload RCE' }, payloadId: 'rce-file-upload' },
          { id: 'file-download', name: { zh: '任意文件下载', en: 'Arbitrary File Download' }, payloadId: 'file-download' },
          { id: 'file-competition', name: { zh: '条件竞争', en: 'Race Condition' }, payloadId: 'file-competition' },
          { id: 'file-traversal', name: { zh: '路径遍历', en: 'Path Traversal' }, payloadId: 'file-traversal' },
          { id: 'file-zip-slip', name: 'Zip Slip', payloadId: 'file-zip-slip' },
          { id: 'file-mime', name: { zh: 'MIME类型绕过', en: 'MIME Type Bypass' }, payloadId: 'file-mime' },
          { id: 'file-null-byte', name: { zh: '空字节截断', en: 'Null Byte Truncation' }, payloadId: 'file-null-byte' }
        ]
      },
      {
        id: 'web-cache',
        name: { zh: '缓存与CDN安全', en: 'Cache & CDN Security' },
        children: [
          { id: 'cache-poisoning', name: { zh: '缓存投毒', en: 'Cache Poisoning' }, payloadId: 'cache-poisoning' },
          { id: 'cache-deception', name: { zh: '缓存欺骗', en: 'Cache Deception' }, payloadId: 'cache-deception' },
          { id: 'cdn-bypass', name: { zh: 'CDN绕过', en: 'CDN Bypass' }, payloadId: 'cdn-bypass' }
        ]
      },
      {
        id: 'web-smuggling',
        name: { zh: '请求走私', en: 'HTTP Request Smuggling' },
        children: [
          { id: 'smuggling-cl-cl', name: { zh: 'CL-CL走私', en: 'CL-CL Smuggling' }, payloadId: 'smuggling-cl-cl' },
          { id: 'smuggling-cl-te', name: { zh: 'CL-TE走私', en: 'CL-TE Smuggling' }, payloadId: 'smuggling-cl-te' },
          { id: 'smuggling-te-cl', name: { zh: 'TE-CL走私', en: 'TE-CL Smuggling' }, payloadId: 'smuggling-te-cl' },
          { id: 'smuggling-te-te', name: { zh: 'TE-TE走私', en: 'TE-TE Smuggling' }, payloadId: 'smuggling-te-te' }
        ]
      },
      {
        id: 'web-redirect',
        name: { zh: '开放重定向', en: 'Open Redirect' },
        children: [
          { id: 'redirect-basic', name: { zh: '基础重定向', en: 'Basic Redirect' }, payloadId: 'redirect-basic' },
          { id: 'redirect-bypass', name: { zh: '重定向绕过', en: 'Redirect Bypass' }, payloadId: 'redirect-bypass' },
          { id: 'redirect-ssrf', name: { zh: '重定向到SSRF', en: 'Redirect to SSRF' }, payloadId: 'redirect-ssrf' }
        ]
      },
      {
        id: 'clickjacking',
        name: { zh: '点击劫持', en: 'Clickjacking' },
        children: [
          { id: 'clickjacking-basic', name: { zh: '基础点击劫持', en: 'Basic Clickjacking' }, payloadId: 'clickjacking-basic' },
          { id: 'clickjacking-xss', name: { zh: '点击劫持+XSS', en: 'Clickjacking + XSS' }, payloadId: 'clickjacking-xss' }
        ]
      },
      {
        id: 'biz-logic',
        name: { zh: '业务逻辑漏洞', en: 'Business Logic Vulnerabilities' },
        children: [
          { id: 'biz-idor-nav', name: { zh: 'IDOR越权遍历', en: 'IDOR Enumeration' }, payloadId: 'biz-idor' },
          { id: 'biz-race-condition-nav', name: { zh: '竞态条件攻击', en: 'Race Condition Attack' }, payloadId: 'biz-race-condition' },
          { id: 'biz-price-tamper-nav', name: { zh: '价格篡改', en: 'Price Tampering' }, payloadId: 'biz-price-tamper' },
          { id: 'biz-flow-bypass-nav', name: { zh: '流程绕过', en: 'Flow Bypass' }, payloadId: 'biz-flow-bypass' },
          { id: 'biz-coupon-abuse-nav', name: { zh: '优惠券滥用', en: 'Coupon Abuse' }, payloadId: 'biz-coupon-abuse' },
          { id: 'biz-password-reset-nav', name: { zh: '密码重置逻辑缺陷', en: 'Password Reset Logic Flaws' }, payloadId: 'biz-password-reset' },
          { id: 'biz-captcha-bypass-nav', name: { zh: '验证码绕过技术', en: 'CAPTCHA Bypass Techniques' }, payloadId: 'biz-captcha-bypass' }
        ]
      },
      {
        id: 'jwt-security',
        name: { zh: 'JWT安全', en: 'JWT Security' },
        children: [
          { id: 'jwt-basics-nav', name: { zh: 'JWT基础与声明篡改', en: 'JWT basics and claim tampering' }, payloadId: 'jwt-security' },
          { id: 'jwt-none-algo-nav', name: { zh: 'None算法攻击', en: 'None algorithm attack' }, payloadId: 'jwt-none-attack' },
          { id: 'jwt-weak-secret-nav', name: { zh: '弱密钥爆破', en: 'Weak secret brute force' }, payloadId: 'jwt-secret-bruteforce' },
          { id: 'jwt-kid-injection-nav', name: { zh: 'KID注入/密钥混淆', en: 'KID injection and key confusion' }, payloadId: 'jwt-key-confusion' },
          { id: 'jwt-jku-spoofing-nav', name: { zh: 'JKU/X5U远程密钥', en: 'JKU/X5U remote key injection' }, payloadId: 'jwt-jku-x5u-injection' }
        ]
      },
      {
        id: 'supply-chain',
        name: { zh: '供应链攻击', en: 'Supply Chain Attacks' },
        children: [
          { id: 'supply-typosquat-nav', name: { zh: '拼写抢注攻击', en: 'Typosquatting Attack' }, payloadId: 'supply-typosquat' },
          { id: 'supply-ci-poison-nav', name: { zh: 'CI/CD投毒', en: 'CI/CD Poisoning' }, payloadId: 'supply-ci-poison' },
          { id: 'supply-dep-confusion-nav', name: { zh: '依赖混淆攻击', en: 'Dependency Confusion' }, payloadId: 'supply-dependency-confusion' }
        ]
      },
      {
        id: 'prototype-pollution',
        name: { zh: '原型链污染', en: 'Prototype Pollution' },
        children: [
          { id: 'proto-server-rce-nav', name: { zh: '服务端RCE', en: 'Server-side RCE' }, payloadId: 'proto-server-rce' },
          { id: 'proto-client-xss-nav', name: { zh: '客户端XSS', en: 'Client-side XSS' }, payloadId: 'proto-client-xss' },
          { id: 'proto-nosql-injection-nav', name: { zh: 'NoSQL注入', en: 'NoSQL Injection' }, payloadId: 'proto-nosql-injection' }
        ]
      },
      {
        id: 'cloud-security',
        name: { zh: '云安全漏洞', en: 'Cloud Security Vulnerabilities' },
        children: [
          { id: 'cloud-ssrf-metadata-nav', name: { zh: 'SSRF元数据攻击', en: 'SSRF Metadata Attack' }, payloadId: 'cloud-ssrf-metadata' },
          { id: 'cloud-s3-misconfig-nav', name: { zh: 'S3存储桶错配', en: 'S3 Bucket Misconfiguration' }, payloadId: 'cloud-s3-misconfig' },
          { id: 'cloud-iam-escalation-nav', name: { zh: 'IAM权限提升', en: 'IAM Privilege Escalation' }, payloadId: 'cloud-iam-escalation' },
          { id: 'cloud-k8s-escape-nav', name: { zh: 'K8s容器逃逸', en: 'K8s Container Escape' }, payloadId: 'cloud-k8s-escape' },
      { id: 'aws-advanced-attacks', name: { zh: 'AWS高级攻击', en: 'AWS Advanced Attacks' }, toolId: 'aws-advanced-attacks' },
      { id: 'cloud-misc-tools', name: { zh: '云平台杂项工具', en: 'Cloud Misc Tools' }, toolId: 'cloud-misc-tools' }
        ]
      },
      {
        id: 'websocket-security',
        name: { zh: 'WebSocket安全', en: 'WebSocket Security' },
        children: [
          { id: 'ws-hijack-nav', name: { zh: 'WebSocket劫持', en: 'WebSocket Hijacking' }, payloadId: 'ws-hijack' },
          { id: 'ws-smuggling-nav', name: { zh: 'WebSocket走私', en: 'WebSocket Smuggling' }, payloadId: 'ws-smuggling' },
          { id: 'ws-auth-bypass-nav', name: { zh: '认证绕过', en: 'Auth Bypass' }, payloadId: 'ws-auth-bypass' }
        ]
      },
      {
        id: 'ai-security',
        name: { zh: 'AI安全', en: 'AI Security' },
        children: [
          { id: 'ai-prompt-injection-nav', name: { zh: 'Prompt注入', en: 'Prompt Injection' }, payloadId: 'ai-prompt-injection' },
          { id: 'ai-model-extraction-nav', name: { zh: '模型窃取', en: 'Model Extraction' }, payloadId: 'ai-model-extraction' },
          { id: 'ai-adversarial-nav', name: { zh: '对抗样本攻击', en: 'Adversarial Attack' }, payloadId: 'ai-adversarial' },
          { id: 'ai-rag-poisoning-nav', name: { zh: 'RAG投毒攻击', en: 'RAG Poisoning Attack' }, payloadId: 'ai-rag-poisoning' }
        ]
      }
    ]
  },
  {
    id: 'intranet',
    name: { zh: '🏢 内网渗透与横向移动', en: '🏢 Internal Network & Lateral Movement' },
    children: [
      {
        id: 'recon',
        name: { zh: '信息收集', en: 'Reconnaissance' },
        children: [
          { id: 'bloodhound', name: { zh: 'BloodHound域分析', en: 'BloodHound Domain Analysis' }, payloadId: 'bloodhound-enumeration' },
          { id: 'spn-scan', name: { zh: 'SPN扫描', en: 'SPN Scanning' }, payloadId: 'spn-scan' },
          { id: 'port-scan', name: { zh: '端口扫描', en: 'Port Scanning' }, payloadId: 'port-scan' },
          { id: 'domain-recon', name: { zh: '域信息收集', en: 'Domain Reconnaissance' }, payloadId: 'domain-recon' },
          { id: 'network-recon', name: { zh: '网络信息收集', en: 'Network Reconnaissance' }, payloadId: 'network-recon' },
          { id: 'share-enum', name: { zh: '共享枚举', en: 'Share Enumeration' }, payloadId: 'share-enum' },
          { id: 'user-enum', name: { zh: '用户枚举', en: 'User Enumeration' }, payloadId: 'user-enum' },
          { id: 'group-enum', name: { zh: '组枚举', en: 'Group Enumeration' }, payloadId: 'group-enum' },
          { id: 'gpo-enum', name: { zh: 'GPO枚举', en: 'GPO Enumeration' }, payloadId: 'gpo-enum' },
          { id: 'acl-enum', name: { zh: 'ACL枚举', en: 'ACL Enumeration' }, payloadId: 'acl-enum' },
          { id: 'trust-enum', name: { zh: '信任关系枚举', en: 'Trust Relationship Enumeration' }, payloadId: 'trust-enum' },
          { id: 'computer-enum', name: { zh: '计算机枚举', en: 'Computer Enumeration' }, payloadId: 'computer-enum' }
        ]
      },
      {
        id: 'credential-theft',
        name: { zh: '凭证窃取', en: 'Credential Theft' },
        children: [
          { id: 'mimikatz', name: { zh: 'Mimikatz凭证抓取', en: 'Mimikatz Credential Dumping' }, payloadId: 'mimikatz-creds' },
          { id: 'mimikatz-advanced', name: { zh: 'Mimikatz高级技巧', en: 'Mimikatz Advanced Techniques' }, payloadId: 'mimikatz-advanced' },
          { id: 'kerberoasting', name: 'Kerberoasting', payloadId: 'kerberoasting' },
          { id: 'asreproasting', name: 'AS-REP Roasting', payloadId: 'asreproasting' },
          { id: 'lazagne', name: 'LaZagne', payloadId: 'lazagne-creds' },
          { id: 'browser-dump', name: { zh: '浏览器凭证', en: 'Browser Credentials' }, payloadId: 'browser-creds' },
          { id: 'sam-dump', name: { zh: 'SAM数据库导出', en: 'SAM Database Dump' }, payloadId: 'sam-dump' },
          { id: 'ntds-dump', name: { zh: 'NTDS.dit导出', en: 'NTDS.dit Dump' }, payloadId: 'ntds-dump' },
          { id: 'dpapi-creds', name: { zh: 'DPAPI凭证', en: 'DPAPI Credentials' }, payloadId: 'dpapi-creds' },
          { id: 'rdp-creds', name: { zh: 'RDP凭证', en: 'RDP Credentials' }, payloadId: 'rdp-creds' },
          { id: 'wifi-creds', name: { zh: 'WiFi凭证', en: 'WiFi Credentials' }, payloadId: 'wifi-creds' },
          { id: 'vault-creds', name: 'Windows Vault', payloadId: 'vault-creds' },
          { id: 'keepass-dump', name: { zh: 'KeePass凭证', en: 'KeePass Credentials' }, payloadId: 'keepass-dump' },
          { id: 'gpp-password', name: { zh: 'GPP密码', en: 'GPP Password' }, payloadId: 'gpp-password' },
          { id: 'lsa-secrets', name: 'LSA Secrets', payloadId: 'lsa-secrets' },
          { id: 'cached-creds', name: { zh: '缓存凭证', en: 'Cached Credentials' }, payloadId: 'cached-creds' }
        ]
      },
      {
        id: 'lateral-movement',
        name: { zh: '横向移动', en: 'Lateral Movement' },
        children: [
          { id: 'psexec', name: 'PsExec', payloadId: 'lateral-psexec' },
          { id: 'wmi', name: 'WMI', payloadId: 'lateral-wmi' },
          { id: 'pth', name: 'Pass-the-Hash', payloadId: 'pass-the-hash' },
          { id: 'ntlm-relay', name: 'NTLM Relay', payloadId: 'ntlm-relay' },
          { id: 'winrm', name: 'WinRM', payloadId: 'lateral-winrm' },
          { id: 'dcom', name: 'DCOM', payloadId: 'lateral-dcom' },
          { id: 'lateral-ssh-tunnel', name: { zh: 'SSH隧道', en: 'SSH Tunnel' }, payloadId: 'lateral-ssh' },
          { id: 'rdp-hijack', name: { zh: 'RDP劫持', en: 'RDP Hijacking' }, payloadId: 'rdp-hijack' },
          { id: 'over-pth', name: 'Overpass-the-Hash', payloadId: 'overpass-the-hash' },
          { id: 'ptt', name: 'Pass-the-Ticket', payloadId: 'pass-the-ticket' },
          { id: 'smbexec', name: 'SMBExec', payloadId: 'lateral-smbexec' },
          { id: 'atexec', name: 'ATExec', payloadId: 'lateral-atexec' },
          { id: 'dcom-excel', name: 'Excel DCOM', payloadId: 'lateral-dcom-excel' },
          { id: 'dcom-mmc', name: 'MMC DCOM', payloadId: 'lateral-dcom-mmc' },
          { id: 'rdp-relay', name: 'RDP Relay', payloadId: 'rdp-relay' },
          { id: 'winrs', name: 'WinRS', payloadId: 'lateral-winrs' }
        ]
      },
      {
        id: 'privilege-escalation',
        name: { zh: '权限提升', en: 'Privilege Escalation' },
        children: [
          { id: 'token-manipulation', name: { zh: '令牌窃取与模拟', en: 'Token Theft & Impersonation' }, payloadId: 'privilege-token' },
          { id: 'windows-privesc', name: { zh: 'Windows提权', en: 'Windows Privilege Escalation' }, payloadId: 'windows-privesc' },
          { id: 'linux-privesc', name: { zh: 'Linux提权', en: 'Linux Privilege Escalation' }, payloadId: 'linux-privesc' },
          { id: 'uac-bypass', name: { zh: 'UAC绕过', en: 'UAC Bypass' }, payloadId: 'uac-bypass' },
          { id: 'dll-hijack', name: { zh: 'DLL劫持', en: 'DLL Hijacking' }, payloadId: 'dll-hijack' },
          { id: 'service-exploit', name: { zh: '服务提权', en: 'Service Exploitation' }, payloadId: 'service-exploit' },
          { id: 'always-install', name: 'AlwaysInstallElevated', payloadId: 'always-install' },
          { id: 'unattended', name: { zh: '无人值守安装', en: 'Unattended Install' }, payloadId: 'unattended-creds' },
          { id: 'potato', name: { zh: 'Potato攻击', en: 'Potato Attack' }, payloadId: 'potato-attack' },
          { id: 'juicy-potato', name: 'Juicy Potato', payloadId: 'juicy-potato' },
          { id: 'printspoofer', name: 'PrintSpoofer', payloadId: 'printspoofer' },
          { id: 'godpotato', name: 'GodPotato', payloadId: 'godpotato' },
          { id: 'suid-exploit', name: { zh: 'SUID提权', en: 'SUID Privilege Escalation' }, payloadId: 'suid-exploit' },
          { id: 'sudo-exploit', name: { zh: 'Sudo提权', en: 'Sudo Privilege Escalation' }, payloadId: 'sudo-exploit' },
          { id: 'cron-exploit', name: { zh: 'Cron提权', en: 'Cron Privilege Escalation' }, payloadId: 'cron-exploit' },
          { id: 'kernel-exploit', name: { zh: '内核漏洞提权', en: 'Kernel Exploit Escalation' }, payloadId: 'kernel-exploit' }
        ]
      },
      {
        id: 'persistence',
        name: { zh: '权限维持', en: 'Persistence' },
        children: [
          { id: 'registry-persistence', name: { zh: '注册表持久化', en: 'Registry Persistence' }, payloadId: 'persistence-registry' },
          { id: 'scheduled-task', name: { zh: '计划任务', en: 'Scheduled Task' }, payloadId: 'persistence-scheduled' },
          { id: 'wmi-event', name: { zh: 'WMI事件订阅', en: 'WMI Event Subscription' }, payloadId: 'persistence-wmi' },
          { id: 'golden-ticket', name: { zh: '黄金票据', en: 'Golden Ticket' }, payloadId: 'golden-ticket' },
          { id: 'silver-ticket', name: { zh: '白银票据', en: 'Silver Ticket' }, payloadId: 'silver-ticket' },
          { id: 'skeleton-key', name: 'Skeleton Key', payloadId: 'skeleton-key' },
          { id: 'dsrm-backdoor', name: { zh: 'DSRM后门', en: 'DSRM Backdoor' }, payloadId: 'dsrm-backdoor' },
          { id: 'sid-history', name: 'SID History', payloadId: 'sid-history' },
          { id: 'startup-folder', name: { zh: '启动文件夹', en: 'Startup Folder' }, payloadId: 'persistence-startup' },
          { id: 'service-persistence', name: { zh: '服务持久化', en: 'Service Persistence' }, payloadId: 'persistence-service' },
          { id: 'dll-injection', name: { zh: 'DLL注入', en: 'DLL Injection' }, payloadId: 'persistence-dll-injection' },
          { id: 'process-hollowing', name: { zh: '进程镂空', en: 'Process Hollowing' }, payloadId: 'persistence-process-hollowing' },
          { id: 'backdoor-user', name: { zh: '后门用户', en: 'Backdoor User' }, payloadId: 'persistence-backdoor-user' },
          { id: 'hidden-user', name: { zh: '隐藏用户', en: 'Hidden User' }, payloadId: 'persistence-hidden-user' }
        ]
      },
      {
        id: 'tunnel-proxy',
        name: { zh: '隧道代理', en: 'Tunneling & Proxy' },
        children: [
          { id: 'frp', name: { zh: 'FRP内网穿透', en: 'FRP Intranet Tunneling' }, payloadId: 'tunnel-frp' },
          { id: 'chisel', name: 'Chisel', payloadId: 'tunnel-chisel' },
          { id: 'regeorg', name: 'ReGeorg', payloadId: 'tunnel-regeorg' },
          { id: 'ssh-tunnel-proxy', name: { zh: 'SSH本地/远程转发', en: 'SSH Local/Remote Forwarding' }, payloadId: 'tunnel-ssh-local' },
          { id: 'ssh-remote', name: { zh: 'SSH远程转发', en: 'SSH Remote Forwarding' }, payloadId: 'tunnel-ssh-remote' },
          { id: 'ssh-dynamic', name: { zh: 'SSH动态转发', en: 'SSH Dynamic Forwarding' }, payloadId: 'tunnel-ssh-dynamic' },
          { id: 'dns-tunnel', name: { zh: 'DNS隧道', en: 'DNS Tunnel' }, payloadId: 'tunnel-dns' },
          { id: 'icmp-tunnel', name: { zh: 'ICMP隧道', en: 'ICMP Tunnel' }, payloadId: 'tunnel-icmp' },
          { id: 'socks-proxy', name: { zh: 'SOCKS代理', en: 'SOCKS Proxy' }, payloadId: 'socks-proxy' },
          { id: 'ligolo', name: 'Ligolo', payloadId: 'tunnel-ligolo' },
          { id: 'ngrok', name: 'Ngrok', payloadId: 'tunnel-ngrok' },
          { id: 'ew-tunnel', name: { zh: 'EW隧道', en: 'EW Tunnel' }, payloadId: 'tunnel-ew' },
          { id: 'venom', name: 'Venom', payloadId: 'tunnel-venom' }
        ]
      },
      {
        id: 'ad-attack',
        name: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
        children: [
          { id: 'zerologon', name: 'Zerologon', payloadId: 'zerologon' },
          { id: 'printnightmare', name: 'PrintNightmare', payloadId: 'printnightmare' },
          { id: 'petitpotam', name: 'PetitPotam', payloadId: 'petitpotam' },
          { id: 'samaccountname', name: 'noPac/SAMAccountName', payloadId: 'samaccountname' },
          { id: 'adcs-abuse', name: { zh: 'ADCS滥用', en: 'ADCS Abuse' }, payloadId: 'adcs-abuse' },
          { id: 'adcs-esc1', name: 'ADCS ESC1', payloadId: 'adcs-esc1' },
          { id: 'adcs-esc2', name: 'ADCS ESC2', payloadId: 'adcs-esc2' },
          { id: 'adcs-esc3', name: 'ADCS ESC3', payloadId: 'adcs-esc3' },
          { id: 'adcs-esc4', name: 'ADCS ESC4', payloadId: 'adcs-esc4' },
          { id: 'adcs-esc6', name: 'ADCS ESC6', payloadId: 'adcs-esc6' },
          { id: 'adcs-esc8', name: 'ADCS ESC8', payloadId: 'adcs-esc8' },
          { id: 'constrained-delegation', name: { zh: '约束委派', en: 'Constrained Delegation' }, payloadId: 'constrained-delegation' },
          { id: 'resource-delegation', name: { zh: '基于资源的约束委派', en: 'Resource-based Constrained Delegation' }, payloadId: 'resource-delegation' },
          { id: 'dcsync', name: { zh: 'DCSync攻击', en: 'DCSync Attack' }, payloadId: 'dcsync-attack' },
          { id: 'dcshadow', name: { zh: 'DCShadow攻击', en: 'DCShadow Attack' }, payloadId: 'dcshadow-attack' },
          { id: 'sam-the-admin', name: 'SAM The Admin', payloadId: 'sam-the-admin' },
          { id: 'noauth', name: { zh: 'NoAuth攻击', en: 'NoAuth Attack' }, payloadId: 'noauth' },
          { id: 'group-policy', name: { zh: '组策略滥用', en: 'Group Policy Abuse' }, payloadId: 'group-policy-abuse' },
          { id: 'domain-priv-esc', name: { zh: '域内权限提升', en: 'Domain Privilege Escalation' }, payloadId: 'domain-privilege-escalation' },
          { id: 'domain-cross-trust-nav', name: { zh: '跨域信任攻击', en: 'Cross-Domain Trust Attack' }, payloadId: 'domain-cross-trust' }
        ]
      },
            {
        id: 'exchange-attack',
        name: { zh: 'Exchange攻击', en: 'Exchange Attacks' },
        children: [
          { id: 'proxylogon', name: 'ProxyLogon', payloadId: 'proxylogon' },
          { id: 'proxyshell', name: 'ProxyShell', payloadId: 'proxyshell' },
          { id: 'proxytoken', name: 'ProxyToken', payloadId: 'exchange-proxytoken' },
          { id: 'exchange-enum', name: { zh: 'Exchange枚举', en: 'Exchange Enumeration' }, payloadId: 'exchange-enum' },
          { id: 'exchange-mailbox', name: { zh: '邮箱访问', en: 'Mailbox Access' }, payloadId: 'exchange-mailbox-access' }
        ]
      },
      {
        id: 'sharepoint-attack',
        name: { zh: 'SharePoint攻击', en: 'SharePoint Attacks' },
        children: [
          { id: 'sharepoint-enum', name: { zh: 'SharePoint枚举', en: 'SharePoint Enumeration' }, payloadId: 'sharepoint-enum' },
          { id: 'sharepoint-file', name: { zh: '文件访问', en: 'File Access' }, payloadId: 'sharepoint-file-access' }
        ]
      }
    ]
  },
];

export const toolNavigationData: NavItem[] = [
  {
    id: 'recon-tools',
    name: { zh: '🔍 信息收集工具', en: '🔍 Recon Tools' },
    children: [
      { id: 'nmap', name: 'Nmap', toolId: 'nmap' },
      { id: 'masscan', name: 'Masscan', toolId: 'masscan' },
      { id: 'gobuster', name: 'Gobuster', toolId: 'gobuster' },
      { id: 'ffuf', name: 'FFUF', toolId: 'ffuf' },
      { id: 'dirsearch', name: 'Dirsearch', toolId: 'dirsearch' },
      { id: 'feroxbuster', name: 'FeroxBuster', toolId: 'feroxbuster' },
      { id: 'massdns', name: 'MassDNS', toolId: 'massdns' },
      { id: 'amass', name: 'Amass', toolId: 'amass' },
      { id: 'subfinder', name: 'Subfinder', toolId: 'subfinder' },
      { id: 'assetfinder', name: 'Assetfinder', toolId: 'assetfinder' },
      { id: 'dnsx', name: 'dnsx', toolId: 'dnsx' },
      { id: 'httpx', name: 'HTTPX', toolId: 'httpx' },
      { id: 'tlsx', name: 'tlsx', toolId: 'tlsx' },
      { id: 'naabu', name: 'Naabu', toolId: 'naabu' },
      { id: 'nuclei', name: 'Nuclei', toolId: 'nuclei' },
      { id: 'katana', name: 'Katana', toolId: 'katana' },
      { id: 'gau', name: 'gau', toolId: 'gau' },
      { id: 'hakrawler', name: 'Hakrawler', toolId: 'hakrawler' },
      { id: 'subdomainizer', name: 'SubDomainizer', toolId: 'subdomainizer' },
      { id: 'whatweb', name: 'WhatWeb', toolId: 'whatweb' },
      { id: 'wafw00f', name: 'WAFW00F', toolId: 'wafw00f' },
      { id: 'dnsrecon', name: 'DNSRecon', toolId: 'dnsrecon' },
      { id: 'dnsenum', name: 'DNSEnum', toolId: 'dnsenum' },
      { id: 'theharvester', name: 'theHarvester', toolId: 'theharvester' }
    ]
  },
  {
    id: 'web-tools',
    name: { zh: '🌐 Web渗透工具', en: '🌐 Web Pentest Tools' },
    children: [
      { id: 'sqlmap', name: 'SQLMap', toolId: 'sqlmap' },
      { id: 'burpsuite', name: 'Burp Suite', toolId: 'burpsuite' },
      { id: 'nikto', name: 'Nikto', toolId: 'nikto' },
      { id: 'zap', name: 'OWASP ZAP', toolId: 'zap' },
      { id: 'arjun', name: 'Arjun', toolId: 'arjun' },
      { id: 'wfuzz', name: 'WFuzz', toolId: 'wfuzz' },
      { id: 'commix', name: 'Commix', toolId: 'commix' },
      { id: 'dalfox', name: 'Dalfox', toolId: 'dalfox' },
      { id: 'xsstrike', name: 'XSStrike', toolId: 'xsstrike' },
      { id: 'gopherus', name: 'Gopherus', toolId: 'gopherus' },
      { id: 'smuggler', name: 'Smuggler', toolId: 'smuggler' },
      { id: 'jwt-tool', name: 'JWT Tool', toolId: 'jwt-tool' },
      { id: 'graphqlmap', name: 'GraphQLmap', toolId: 'graphqlmap' },
      { id: 'cadaver', name: 'Cadaver', toolId: 'cadaver' }
    ]
  },
  {
    id: 'exploit-tools',
    name: { zh: '💥 漏洞利用工具', en: '💥 Exploitation Tools' },
    children: [
      { id: 'metasploit', name: 'Metasploit', toolId: 'metasploit' },
      { id: 'searchsploit', name: 'Searchsploit', toolId: 'searchsploit' },
      { id: 'exploitdb', name: 'ExploitDB', toolId: 'exploitdb' },
      { id: 'ysoserial', name: 'ysoserial', toolId: 'ysoserial' },
      { id: 'ysoserial-net', name: 'ysoserial.net', toolId: 'ysoserial-net' },
      { id: 'marshalsec', name: 'Marshalsec', toolId: 'marshalsec' },
      { id: 'jndi-exploit', name: 'JNDIExploit', toolId: 'jndi-exploit' },
      { id: 'rogue-jndi', name: 'Rogue JNDI', toolId: 'rogue-jndi' },
      { id: 'cobalt-strike', name: 'Cobalt Strike', toolId: 'cobalt-strike' },
      { id: 'sliver', name: 'Sliver', toolId: 'sliver' },
      { id: 'mythic', name: 'Mythic', toolId: 'mythic' }
    ]
  },
  {
    id: 'password-tools',
    name: { zh: '🔐 密码攻击工具', en: '🔐 Password Attack Tools' },
    children: [
      { id: 'hydra', name: 'Hydra', toolId: 'hydra' },
      { id: 'john', name: 'John the Ripper', toolId: 'john' },
      { id: 'hashcat', name: 'Hashcat', toolId: 'hashcat' },
      { id: 'medusa', name: 'Medusa', toolId: 'medusa' },
      { id: 'ncrack', name: 'Ncrack', toolId: 'ncrack' },
      { id: 'crowbar', name: 'Crowbar', toolId: 'crowbar' },
      { id: 'patator', name: 'Patator', toolId: 'patator' },
      { id: 'crackstation', name: 'CrackStation', toolId: 'crackstation' },
      { id: 'seclists', name: { zh: 'SecLists字典', en: 'SecLists Wordlist' }, toolId: 'seclists' },
      { id: 'rockyou', name: { zh: 'RockYou字典', en: 'RockYou Wordlist' }, toolId: 'rockyou' }
    ]
  },
  {
    id: 'intranet-tools',
    name: { zh: '🏢 内网渗透工具', en: '🏢 Internal Pentest Tools' },
    children: [
      { id: 'crackmapexec', name: 'CrackMapExec', toolId: 'crackmapexec' },
      { id: 'netexec', name: 'NetExec', toolId: 'netexec' },
      { id: 'impacket', name: 'Impacket', toolId: 'impacket' },
      { id: 'responder', name: 'Responder', toolId: 'responder' },
      { id: 'evil-winrm', name: 'Evil-WinRM', toolId: 'evil-winrm' },
      { id: 'proxychains', name: 'ProxyChains', toolId: 'proxychains' },
      { id: 'chisel-tool', name: 'Chisel', toolId: 'chisel-tool' },
      { id: 'ligolo-ng', name: 'Ligolo-ng', toolId: 'ligolo-ng' },
      { id: 'sharphound', name: 'SharpHound', toolId: 'sharphound' },
      { id: 'bloodhound-python', name: 'BloodHound-Python', toolId: 'bloodhound-python' },
      { id: 'rubeus', name: 'Rubeus', toolId: 'rubeus' },
      { id: 'certipy', name: 'Certipy', toolId: 'certipy' },
      { id: 'mimikatz-tool', name: 'Mimikatz', toolId: 'mimikatz-tool' },
      { id: 'lazagne-tool', name: 'LaZagne', toolId: 'lazagne-tool' },
      { id: 'seatbelt', name: 'Seatbelt', toolId: 'seatbelt' },
      { id: 'winpeas', name: 'WinPEAS', toolId: 'winpeas' },
      { id: 'linpeas', name: 'LinPEAS', toolId: 'linpeas' }
    ]
  },
  {
    id: 'os-tools',
    name: { zh: '💻 系统命令', en: '💻 System Commands' },
    children: [
      { id: 'powershell-pentest', name: { zh: 'PowerShell渗透命令', en: 'PowerShell Pentest Commands' }, toolId: 'powershell-pentest' },
      { id: 'powershell-amsi', name: { zh: 'PowerShell AMSI绕过', en: 'PowerShell AMSI Bypass' }, toolId: 'powershell-amsi' },
      { id: 'linux-privilege', name: { zh: 'Linux提权命令', en: 'Linux Privilege Escalation Commands' }, toolId: 'linux-privilege' },
      { id: 'windows-cmd', name: { zh: 'Windows CMD命令', en: 'Windows CMD Commands' }, toolId: 'windows-cmd' },
      { id: 'wmic-cmd', name: { zh: 'WMIC命令', en: 'WMIC Commands' }, toolId: 'wmic-cmd' },
      { id: 'net-commands', name: { zh: 'NET命令', en: 'NET Commands' }, toolId: 'net-commands' },
      { id: 'dsquery', name: { zh: 'DSQuery命令', en: 'DSQuery Commands' }, toolId: 'dsquery' },
      { id: 'adexplorer', name: 'AD Explorer', toolId: 'adexplorer' },
      { id: 'ldeep', name: 'ldeep', toolId: 'ldeep' },
      { id: 'bloodhound-cypher', name: 'BloodHound Cypher', toolId: 'bloodhound-cypher' },
      {
        id: 'powershell-full-command-index-group',
        name: { zh: 'PowerShell 全命令索引', en: 'PowerShell Full Command Index' },
        children: [
          { id: 'powershell-command-discovery', name: { zh: 'PowerShell 全命令动态枚举', en: 'PowerShell Full Command Discovery' }, toolId: 'powershell-command-discovery' },
          { id: 'powershell-all-cmdlets-index', name: { zh: 'PowerShell 全 Cmdlet 索引', en: 'PowerShell All Cmdlets Index' }, toolId: 'powershell-all-cmdlets-index' },
          { id: 'powershell-all-functions-index', name: { zh: 'PowerShell 全 Function 索引', en: 'PowerShell All Functions Index' }, toolId: 'powershell-all-functions-index' },
          { id: 'powershell-all-aliases-index', name: { zh: 'PowerShell 全 Alias 索引', en: 'PowerShell All Aliases Index' }, toolId: 'powershell-all-aliases-index' },
      { id: 'macos-commands', name: { zh: 'macOS系统命令', en: 'macOS Commands' }, toolId: 'macos-commands' },
      { id: 'macos-security-deep', name: { zh: 'macOS深度安全', en: 'macOS Deep Security' }, toolId: 'macos-security-deep' },
      { id: 'freebsd-solaris-commands', name: { zh: 'FreeBSD/Solaris命令', en: 'FreeBSD/Solaris Commands' }, toolId: 'freebsd-solaris-commands' },
      { id: 'windows-cmd-advanced', name: { zh: 'Windows CMD高级', en: 'Windows CMD Advanced' }, toolId: 'windows-cmd-advanced' },
      { id: 'windows-commands-advanced', name: { zh: 'Windows高级命令', en: 'Windows Advanced Commands' }, toolId: 'windows-commands-advanced' },
      { id: 'windows-lolbas', name: 'LOLBins', toolId: 'windows-lolbas' },
      { id: 'windows-pentest-advanced', name: { zh: 'Windows高级渗透', en: 'Windows Pentest Advanced' }, toolId: 'windows-pentest-advanced' },
      { id: 'windows-registry', name: { zh: 'Windows注册表', en: 'Windows Registry' }, toolId: 'windows-registry' },
      { id: 'windows-system-commands', name: { zh: 'Windows系统命令全览', en: 'Windows System Commands' }, toolId: 'windows-system-commands' },
      { id: 'linux-commands-advanced', name: { zh: 'Linux高级命令', en: 'Linux Advanced Commands' }, toolId: 'linux-commands-advanced' },
      { id: 'linux-command-tricks', name: { zh: 'Linux命令技巧', en: 'Linux Command Tricks' }, toolId: 'linux-command-tricks' },
      { id: 'linux-networking-commands', name: { zh: 'Linux网络命令', en: 'Linux Networking Commands' }, toolId: 'linux-networking-commands' },
      { id: 'powershell-remoting', name: { zh: 'PowerShell远程管理', en: 'PowerShell Remoting' }, toolId: 'powershell-remoting' },
      { id: 'nmap-advanced', name: { zh: 'Nmap高级用法', en: 'Nmap Advanced' }, toolId: 'nmap-advanced' },
      { id: 'advanced-nmap-scripts', name: { zh: 'Nmap NSE脚本', en: 'Nmap NSE Scripts' }, toolId: 'advanced-nmap-scripts' }
        ]
      },
      {
        id: 'linux-full-command-index-group',
        name: { zh: 'Linux 全命令索引', en: 'Linux Full Command Index' },
        children: [
          { id: 'linux-all-command-discovery', name: { zh: 'Linux 全命令动态枚举', en: 'Linux Full Command Discovery' }, toolId: 'linux-all-command-discovery' },
          { id: 'linux-shell-builtins-index', name: { zh: 'Linux Shell Builtins 索引', en: 'Linux Shell Builtins Index' }, toolId: 'linux-shell-builtins-index' },
          { id: 'linux-posix-gnu-command-index', name: { zh: 'Linux POSIX/GNU 命令索引', en: 'Linux POSIX/GNU Command Index' }, toolId: 'linux-posix-gnu-command-index' },
          { id: 'linux-admin-daemon-command-index', name: { zh: 'Linux 系统管理命令索引', en: 'Linux Administration Command Index' }, toolId: 'linux-admin-daemon-command-index' },
          { id: 'linux-network-storage-command-index', name: { zh: 'Linux 网络与存储命令索引', en: 'Linux Network & Storage Command Index' }, toolId: 'linux-network-storage-command-index' },
          { id: 'linux-package-dev-container-command-index', name: { zh: 'Linux 包管理/开发/容器命令索引', en: 'Linux Package, Dev & Container Command Index' }, toolId: 'linux-package-dev-container-command-index' }
        ]
      },
      {
        id: 'linux-command-reference-group',
        name: { zh: 'Linux 命令参考', en: 'Linux Command Reference' },
        children: [
          { id: 'linux-command-reference', name: { zh: 'Linux 常用命令总览', en: 'Linux Command Reference' }, toolId: 'linux-command-reference' },
          { id: 'linux-text-processing-reference', name: { zh: 'Linux 文本处理命令', en: 'Linux Text Processing Commands' }, toolId: 'linux-text-processing-reference' },
          { id: 'linux-process-service-reference', name: { zh: 'Linux 进程与服务排查', en: 'Linux Process & Service Diagnostics' }, toolId: 'linux-process-service-reference' },
          { id: 'linux-network-reference', name: { zh: 'Linux 网络与防火墙排查', en: 'Linux Network & Firewall Diagnostics' }, toolId: 'linux-network-reference' },
          { id: 'linux-package-container-reference', name: { zh: 'Linux 包管理与容器命令', en: 'Linux Package & Container Commands' }, toolId: 'linux-package-container-reference' },
          { id: 'linux-security-baseline-reference', name: { zh: 'Linux 安全基线查询', en: 'Linux Security Baseline Queries' }, toolId: 'linux-security-baseline-reference' }
        ]
      },
      {
        id: 'windows-command-reference-group',
        name: { zh: 'Windows 命令参考', en: 'Windows Command Reference' },
        children: [
          { id: 'windows-cmd-reference', name: { zh: 'Windows CMD 命令总览', en: 'Windows CMD Command Reference' }, toolId: 'windows-cmd-reference' },
          { id: 'powershell-admin-reference', name: { zh: 'PowerShell 管理命令', en: 'PowerShell Administration Commands' }, toolId: 'powershell-admin-reference' },
          { id: 'windows-event-network-reference', name: { zh: 'Windows 日志、网络与防火墙查询', en: 'Windows Event, Network & Firewall Queries' }, toolId: 'windows-event-network-reference' },
          { id: 'windows-sysinternals-reference', name: { zh: 'Windows Sysinternals 工具', en: 'Windows Sysinternals Tools' }, toolId: 'windows-sysinternals-reference' },
          { id: 'windows-security-baseline-reference', name: { zh: 'Windows 安全基线查询', en: 'Windows Security Baseline Queries' }, toolId: 'windows-security-baseline-reference' }
        ]
      },
      {
        id: 'diagnostic-toolkit-group',
        name: { zh: '诊断与取证工具箱', en: 'Diagnostics & DFIR Toolkits' },
        children: [
          { id: 'modern-cli-toolkit', name: { zh: '跨平台效率命令工具', en: 'Modern Cross-platform CLI Toolkit' }, toolId: 'modern-cli-toolkit' },
          { id: 'network-diagnostics-toolkit', name: { zh: '网络诊断工具箱', en: 'Network Diagnostics Toolkit' }, toolId: 'network-diagnostics-toolkit' },
          { id: 'dfir-toolkit-reference', name: { zh: '蓝队取证工具箱', en: 'Blue Team DFIR Toolkit' }, toolId: 'dfir-toolkit-reference' },
          { id: 'file-analysis-toolkit', name: { zh: '文件分析与取证工具', en: 'File Analysis & Forensics Tools' }, toolId: 'file-analysis-toolkit' }
        ]
      }
    ]
  },
  {
    id: 'reverse-shell',
    name: { zh: '🐚 反弹Shell', en: '🐚 Reverse Shell' },
    children: [
      { id: 'bash-reverse', name: { zh: 'Bash反弹', en: 'Bash Reverse Shell' }, toolId: 'bash-reverse' },
      { id: 'python-reverse', name: { zh: 'Python反弹', en: 'Python Reverse Shell' }, toolId: 'python-reverse' },
      { id: 'powershell-reverse', name: { zh: 'PowerShell反弹', en: 'PowerShell Reverse Shell' }, toolId: 'powershell-reverse' },
      { id: 'nc-reverse', name: { zh: 'Netcat反弹', en: 'Netcat Reverse Shell' }, toolId: 'nc-reverse' },
      { id: 'php-reverse', name: { zh: 'PHP反弹', en: 'PHP Reverse Shell' }, toolId: 'php-reverse' },
      { id: 'java-reverse', name: { zh: 'Java反弹', en: 'Java Reverse Shell' }, toolId: 'java-reverse' },
      { id: 'perl-reverse', name: { zh: 'Perl反弹', en: 'Perl Reverse Shell' }, toolId: 'perl-reverse' },
      { id: 'ruby-reverse', name: { zh: 'Ruby反弹', en: 'Ruby Reverse Shell' }, toolId: 'ruby-reverse' },
      { id: 'nodejs-reverse', name: { zh: 'Node.js反弹', en: 'Node.js Reverse Shell' }, toolId: 'nodejs-reverse' },
      { id: 'groovy-reverse', name: { zh: 'Groovy反弹', en: 'Groovy Reverse Shell' }, toolId: 'groovy-reverse' },
      { id: 'lua-reverse', name: { zh: 'Lua反弹', en: 'Lua Reverse Shell' }, toolId: 'lua-reverse' },
      { id: 'awk-reverse', name: { zh: 'AWK反弹', en: 'AWK Reverse Shell' }, toolId: 'awk-reverse' }
    ]
  },
  {
    id: 'encoding-tools',
    name: { zh: '🔧 编码解码工具', en: '🔧 Encoding/Decoding Tools' },
    children: [
      { id: 'base64-encode', name: { zh: 'Base64编码', en: 'Base64 Encoding' }, toolId: 'base64-encode' },
      { id: 'url-encode', name: { zh: 'URL编码', en: 'URL Encoding' }, toolId: 'url-encode' },
      { id: 'hex-encode', name: { zh: 'Hex编码', en: 'Hex Encoding' }, toolId: 'hex-encode' },
      { id: 'html-encode', name: { zh: 'HTML编码', en: 'HTML Encoding' }, toolId: 'html-encode' },
      { id: 'unicode-encode', name: { zh: 'Unicode编码', en: 'Unicode Encoding' }, toolId: 'unicode-encode' },
      { id: 'jwt-decode', name: { zh: 'JWT解码', en: 'JWT Decoding' }, toolId: 'jwt-decode' }
    ]
  },

  {
    id: 'ctf-tools',
    name: { zh: '🏴 CTF工具', en: '🏴 CTF Tools' },
    children: [
      { id: 'pwntools', name: 'Pwntools', toolId: 'pwntools' },
      { id: 'gdb-enhanced', name: { zh: 'GDB增强插件', en: 'GDB Enhanced' }, toolId: 'gdb-enhanced' },
      { id: 'ghidra', name: 'Ghidra', toolId: 'ghidra' },
      { id: 'radare2', name: 'Radare2', toolId: 'radare2' },
      { id: 'angr', name: 'angr', toolId: 'angr' },
      { id: 'binwalk', name: 'Binwalk', toolId: 'binwalk' },
      { id: 'volatility3', name: 'Volatility3', toolId: 'volatility3' },
      { id: 'steganography-tools', name: { zh: '隐写术工具集', en: 'Steganography Toolkit' }, toolId: 'steganography-tools' },
      { id: 'ctf-crypto-tools', name: { zh: 'CTF密码学工具', en: 'CTF Crypto Tools' }, toolId: 'ctf-crypto-tools' },
      { id: 'rsactftool', name: 'RsaCtfTool', toolId: 'rsactftool' },
      { id: 'scapy', name: 'Scapy', toolId: 'scapy' },
      { id: 'wireshark-tshark', name: 'Wireshark / tshark', toolId: 'wireshark-tshark' },
      { id: 'ecc-lattice-attacks', name: { zh: 'ECC/格密码攻击', en: 'ECC & Lattice Attacks' }, toolId: 'ecc-lattice-attacks' },
      { id: 'ctf-blockchain', name: { zh: 'CTF区块链', en: 'CTF Blockchain' }, toolId: 'ctf-blockchain' },
      { id: 'ctf-web-tools', name: { zh: 'CTF Web工具', en: 'CTF Web Tools' }, toolId: 'ctf-web-tools' },
      { id: 'ctf-pwn-techniques', name: { zh: 'CTF PWN技术', en: 'CTF PWN Techniques' }, toolId: 'ctf-pwn-techniques' },
      { id: 'ctf-pwn-heap', name: { zh: '堆漏洞利用', en: 'CTF Heap Exploitation' }, toolId: 'ctf-pwn-heap' },
      { id: 'ctf-rev-tools', name: { zh: 'CTF逆向工具', en: 'CTF Reverse Tools' }, toolId: 'ctf-rev-tools' },
      { id: 'ctf-forensics-tools', name: { zh: 'CTF取证工具', en: 'CTF Forensics Tools' }, toolId: 'ctf-forensics-tools' },
      { id: 'ctf-forensics-advanced', name: { zh: 'CTF取证高级', en: 'CTF Forensics Advanced' }, toolId: 'ctf-forensics-advanced' },
      { id: 'ctf-misc-tools', name: { zh: 'CTF Misc工具', en: 'CTF Misc Tools' }, toolId: 'ctf-misc-tools' },
      { id: 'ctf-network-tools', name: { zh: 'CTF网络题工具', en: 'CTF Network Tools' }, toolId: 'ctf-network-tools' },
      { id: 'ctf-cryptography', name: { zh: 'CTF密码学速查', en: 'CTF Cryptography' }, toolId: 'ctf-cryptography' },
      { id: 'ctf-tools-linux', name: { zh: 'CTF Linux工具', en: 'CTF Linux Tools' }, toolId: 'ctf-tools-linux' },
      { id: 'ctf-web-advanced', name: { zh: 'CTF Web高级', en: 'CTF Web Advanced' }, toolId: 'ctf-web-advanced' },
      { id: 'decompilers', name: { zh: '反编译工具', en: 'Decompilers' }, toolId: 'decompilers' },
      { id: 'reverse-engineering-tricks', name: { zh: '逆向工程技巧', en: 'RE Tricks' }, toolId: 'reverse-engineering-tricks' },
      { id: 'exploit-dev-tools', name: { zh: '漏洞开发辅助', en: 'Exploit Dev Tools' }, toolId: 'exploit-dev-tools' }
    ]
  },
  {
    id: 'cloud-security',
    name: { zh: '☁️ 云安全工具', en: '☁️ Cloud Security Tools' },
    children: [
      { id: 'cloud-aws-pentest', name: { zh: 'AWS安全测试', en: 'AWS Security Testing' }, toolId: 'cloud-aws-pentest' },
      { id: 'pacu', name: 'Pacu', toolId: 'pacu' },
      { id: 'cloud-azure-pentest', name: { zh: 'Azure安全测试', en: 'Azure Security Testing' }, toolId: 'cloud-azure-pentest' },
      { id: 'azure-ad-attacks', name: { zh: 'Azure AD攻击', en: 'Azure AD Attacks' }, toolId: 'azure-ad-attacks' },
      { id: 'cloud-gcp-pentest', name: { zh: 'GCP安全测试', en: 'GCP Security Testing' }, toolId: 'cloud-gcp-pentest' },
      { id: 'aliyun-tencent-cloud', name: { zh: '阿里云/腾讯云', en: 'Alibaba/Tencent Cloud' }, toolId: 'aliyun-tencent-cloud' },
      { id: 'cloud-security-tools', name: { zh: '云安全工具集', en: 'Cloud Security Toolkit' }, toolId: 'cloud-security-tools' },
      { id: 'docker-security', name: { zh: 'Docker安全', en: 'Docker Security' }, toolId: 'docker-security' },
      { id: 'kubernetes-security', name: { zh: 'Kubernetes安全', en: 'Kubernetes Security' }, toolId: 'kubernetes-security' },
      { id: 'container-escape', name: { zh: '容器逃逸', en: 'Container Escape' }, toolId: 'container-escape' },
      { id: 'container-orchestration-attacks', name: { zh: '容器编排攻击', en: 'Container Orchestration' }, toolId: 'container-orchestration-attacks' },
      { id: 'kubernetes-advanced', name: { zh: 'Kubernetes高级', en: 'Kubernetes Advanced' }, toolId: 'kubernetes-advanced' }
    ]
  },
  {
    id: 'mobile-security',
    name: { zh: '📱 移动安全工具', en: '📱 Mobile Security Tools' },
    children: [
      { id: 'adb-commands', name: 'ADB', toolId: 'adb-commands' },
      { id: 'ios-pentest', name: { zh: 'iOS安全测试', en: 'iOS Security Testing' }, toolId: 'ios-pentest' },
      { id: 'mobile-pentest-tools', name: { zh: '移动端测试工具集', en: 'Mobile Pentest Toolkit' }, toolId: 'mobile-pentest-tools' }
    ]
  },
  {
    id: 'special-attack-tools',
    name: { zh: '🎯 专项攻击工具', en: '🎯 Specialized Attack Tools' },
    children: [
      { id: 'voip-sip-security', name: { zh: 'VoIP/SIP安全', en: 'VoIP/SIP Security' }, toolId: 'voip-sip-security' },
      { id: 'ics-scada-security', name: { zh: 'ICS/SCADA工控安全', en: 'ICS/SCADA Security' }, toolId: 'ics-scada-security' },
      { id: 'bluetooth-security', name: { zh: '蓝牙安全', en: 'Bluetooth Security' }, toolId: 'bluetooth-security' },
      { id: 'sdr-wireless', name: { zh: 'SDR无线电安全', en: 'SDR Wireless Security' }, toolId: 'sdr-wireless' },
      { id: 'wifiphisher-attacks', name: { zh: 'Wi-Fi钓鱼攻击', en: 'Wi-Fi Phishing Attacks' }, toolId: 'wifiphisher-attacks' },
      { id: 'iot-security', name: { zh: 'IoT设备安全', en: 'IoT Device Security' }, toolId: 'iot-security' },
      { id: 'hardware-security', name: { zh: '硬件安全测试', en: 'Hardware Security Testing' }, toolId: 'hardware-security' },
      { id: 'social-engineering-tools', name: { zh: '社会工程学工具', en: 'Social Engineering Tools' }, toolId: 'social-engineering-tools' }
    ]
  },
  {
    id: 'blue-team-tools',
    name: { zh: '🛡️ 蓝队取证工具', en: '🛡️ Blue Team & DFIR' },
    children: [
      { id: 'linux-forensics', name: { zh: 'Linux取证', en: 'Linux Forensics' }, toolId: 'linux-forensics' },
      { id: 'windows-forensics', name: { zh: 'Windows取证', en: 'Windows Forensics' }, toolId: 'windows-forensics' },
      { id: 'threat-hunting', name: { zh: '威胁狩猎', en: 'Threat Hunting' }, toolId: 'threat-hunting' },
      { id: 'network-forensics-advanced', name: { zh: '网络取证分析', en: 'Network Forensics' }, toolId: 'network-forensics-advanced' },
      { id: 'threat-intel-tools', name: { zh: '威胁情报工具', en: 'Threat Intel Tools' }, toolId: 'threat-intel-tools' },
      { id: 'endpoint-security', name: { zh: '端点安全检测', en: 'Endpoint Security' }, toolId: 'endpoint-security' },
      { id: 'linux-system-hardening-check', name: { zh: 'Linux安全基线', en: 'Linux Security Baseline' }, toolId: 'linux-system-hardening-check' },
      { id: 'windows-security-check', name: { zh: 'Windows安全基线', en: 'Windows Security Baseline' }, toolId: 'windows-security-check' },
      { id: 'macro-analysis', name: { zh: '恶意宏分析', en: 'Malicious Macro Analysis' }, toolId: 'macro-analysis' },
      { id: 'pentest-reporting', name: { zh: '渗透报告工具', en: 'Pentest Reporting' }, toolId: 'pentest-reporting' }
    ]
  },
  {
    id: 'post-exploit-tools',
    name: { zh: '⚡ 后渗透工具', en: '⚡ Post-Exploitation' },
    children: [
      { id: 'post-exploitation-linux', name: { zh: 'Linux后渗透', en: 'Linux Post-Exploitation' }, toolId: 'post-exploitation-linux' },
      { id: 'post-exploitation-windows', name: { zh: 'Windows后渗透', en: 'Windows Post-Exploitation' }, toolId: 'post-exploitation-windows' },
      { id: 'linux-privesc-techniques', name: { zh: 'Linux提权技术', en: 'Linux Privesc Techniques' }, toolId: 'linux-privesc-techniques' },
      { id: 'windows-privesc-techniques', name: { zh: 'Windows提权技术', en: 'Windows Privesc Techniques' }, toolId: 'windows-privesc-techniques' },
      { id: 'linux-privesc-gtfobins', name: 'GTFOBins', toolId: 'linux-privesc-gtfobins' },
      { id: 'linux-priv-esc-check', name: { zh: 'Linux提权检测', en: 'Linux Privesc Checklist' }, toolId: 'linux-priv-esc-check' },
      { id: 'privilege-escalation-tools', name: { zh: '提权辅助工具集', en: 'Privesc Toolkit' }, toolId: 'privilege-escalation-tools' },
      { id: 'kernel-exploits', name: { zh: 'Linux内核漏洞', en: 'Linux Kernel Exploits' }, toolId: 'kernel-exploits' },
      { id: 'kernel-exploitation', name: { zh: '内核漏洞利用', en: 'Kernel Exploitation' }, toolId: 'kernel-exploitation' },
      { id: 'post-exploitation-tools', name: { zh: '后渗透框架', en: 'Post-Exploit Frameworks' }, toolId: 'post-exploitation-tools' },
      { id: 'evasion-techniques', name: { zh: 'AV/EDR绕过', en: 'AV/EDR Evasion' }, toolId: 'evasion-techniques' },
      { id: 'anti-av-techniques', name: { zh: '免杀技术', en: 'AV Evasion Techniques' }, toolId: 'anti-av-techniques' },
      { id: 'fileless-antiforensics', name: { zh: '无文件攻击', en: 'Fileless Attacks' }, toolId: 'fileless-antiforensics' },
      { id: 'windows-av-bypass-advanced', name: { zh: 'Windows AV高级绕过', en: 'Advanced AV Bypass' }, toolId: 'windows-av-bypass-advanced' },
      { id: 'persistence-techniques', name: { zh: '持久化技术速查', en: 'Persistence Techniques' }, toolId: 'persistence-techniques' },
      { id: 'linux-forensics-advanced', name: { zh: 'Linux取证高级', en: 'Linux Forensics Advanced' }, toolId: 'linux-forensics-advanced' }
    ]
  },
  {
    id: 'domain-pentest-tools',
    name: { zh: '🏛️ 域渗透工具', en: '🏛️ Domain Pentest Tools' },
    children: [
      { id: 'powerview-adrecon', name: 'PowerView', toolId: 'powerview-adrecon' },
      { id: 'windows-lateral-commands', name: { zh: 'Windows横向移动', en: 'Windows Lateral Movement' }, toolId: 'windows-lateral-commands' },
      { id: 'ad-persistence', name: { zh: 'AD持久化', en: 'AD Persistence' }, toolId: 'ad-persistence' },
      { id: 'active-directory-attacks', name: { zh: 'AD攻击速查', en: 'AD Attack Reference' }, toolId: 'active-directory-attacks' },
      { id: 'active-directory-enumeration', name: { zh: 'AD域内枚举', en: 'AD Enumeration' }, toolId: 'active-directory-enumeration' },
      { id: 'active-directory-tools', name: { zh: 'AD工具集', en: 'AD Toolkit' }, toolId: 'active-directory-tools' },
      { id: 'bloodhound-queries', name: { zh: 'BloodHound查询', en: 'BloodHound Queries' }, toolId: 'bloodhound-queries' },
      { id: 'exchange-m365-attacks', name: { zh: 'Exchange/M365攻击', en: 'Exchange/M365 Attacks' }, toolId: 'exchange-m365-attacks' },
      { id: 'donpapi-tool', name: 'DonPAPI', toolId: 'donpapi-tool' },
      { id: 'kerbrute-tool', name: 'Kerbrute', toolId: 'kerbrute-tool' },
      { id: 'powersploit-tool', name: 'PowerSploit', toolId: 'powersploit-tool' },
      { id: 'sharpsmbclient-tool', name: 'SharpSMBClient', toolId: 'sharpsmbclient-tool' }
    ]
  },
  {
    id: 'tunneling-tools',
    name: { zh: '🔗 隧道代理工具', en: '🔗 Tunneling & Pivoting' },
    children: [
      { id: 'frp-tunnel', name: 'FRP', toolId: 'frp-tunnel' },
      { id: 'regeorg', name: 'Neo-reGeorg', toolId: 'regeorg' },
      { id: 'network-pivoting', name: { zh: '网络枢转技术', en: 'Network Pivoting' }, toolId: 'network-pivoting' },
      { id: 'pivoting-techniques', name: { zh: '枢转技术速查', en: 'Pivoting Techniques' }, toolId: 'pivoting-techniques' },
      { id: 'pivoting-tools', name: { zh: '内网枢转工具', en: 'Pivoting Tools' }, toolId: 'pivoting-tools' },
      { id: 'network-pivoting-tools', name: { zh: '代理工具对比', en: 'Proxy Tools Reference' }, toolId: 'network-pivoting-tools' },
      { id: 'ssh-tunneling-advanced', name: { zh: 'SSH隧道高级', en: 'SSH Tunneling Advanced' }, toolId: 'ssh-tunneling-advanced' },
      { id: 'ssh-pentest', name: { zh: 'SSH渗透测试', en: 'SSH Pentest' }, toolId: 'ssh-pentest' },
      { id: 'smb-pentest', name: { zh: 'SMB渗透测试', en: 'SMB Pentest' }, toolId: 'smb-pentest' },
      { id: 'internal-recon', name: { zh: '内网侦察命令集', en: 'Internal Recon Commands' }, toolId: 'internal-recon' },
      { id: 'linux-exploit-suggester', name: 'Linux Exploit Suggester', toolId: 'linux-exploit-suggester' },
      { id: 'pspy', name: 'pspy', toolId: 'pspy' }
    ]
  },
  {
    id: 'web-extended-tools',
    name: { zh: '🔍 Web扩展工具', en: '🔍 Web Extended Tools' },
    children: [
      { id: 'gobuster-advanced', name: { zh: 'Gobuster高级', en: 'Gobuster Advanced' }, toolId: 'gobuster-advanced' },
      { id: 'nuclei-advanced', name: { zh: 'Nuclei高级', en: 'Nuclei Advanced' }, toolId: 'nuclei-advanced' },
      { id: 'burpsuite-advanced', name: { zh: 'Burp Suite高级', en: 'Burp Suite Advanced' }, toolId: 'burpsuite-advanced' },
      { id: 'sqlmap-advanced', name: { zh: 'SQLMap高级', en: 'SQLMap Advanced' }, toolId: 'sqlmap-advanced' },
      { id: 'shodan-advanced', name: { zh: 'Shodan高级', en: 'Shodan Advanced' }, toolId: 'shodan-advanced' },
      { id: 'shodan-fofa-tools', name: { zh: '空间测绘工具', en: 'Cyberspace Mapping' }, toolId: 'shodan-fofa-tools' },
      { id: 'web-recon-tools', name: { zh: 'Web侦察工具集', en: 'Web Recon Toolkit' }, toolId: 'web-recon-tools' },
      { id: 'web-enum-tools', name: { zh: 'Web枚举工具', en: 'Web Enum Tools' }, toolId: 'web-enum-tools' },
      { id: 'git-pentest', name: { zh: 'Git信息泄露', en: 'Git Info Disclosure' }, toolId: 'git-pentest' },
      { id: 'interactsh', name: 'Interactsh', toolId: 'interactsh' },
      { id: 'osint-tools', name: { zh: 'OSINT工具集', en: 'OSINT Toolkit' }, toolId: 'osint-tools' },
      { id: 'social-media-osint', name: { zh: '社交媒体OSINT', en: 'Social Media OSINT' }, toolId: 'social-media-osint' },
      { id: 'information-gathering-passive', name: { zh: '被动信息收集', en: 'Passive Recon' }, toolId: 'information-gathering-passive' },
      { id: 'active-recon-tools', name: { zh: '主动侦察工具', en: 'Active Recon Tools' }, toolId: 'active-recon-tools' },
      { id: 'bug-bounty-tools', name: { zh: 'Bug Bounty工具链', en: 'Bug Bounty Toolkit' }, toolId: 'bug-bounty-tools' },
      { id: 'web-recon-advanced', name: { zh: 'Web侦察高级', en: 'Web Recon Advanced' }, toolId: 'web-recon-advanced' },
      { id: 'web-enumeration-tools', name: { zh: 'Web枚举工具', en: 'Web Enum Tools' }, toolId: 'web-enumeration-tools' },
      { id: 'web-fuzzing-wordlists', name: { zh: 'Web字典资源', en: 'Web Fuzzing Wordlists' }, toolId: 'web-fuzzing-wordlists' }
    ]
  },
  {
    id: 'web-attack-techniques',
    name: { zh: '💉 Web攻击技术', en: '💉 Web Attack Techniques' },
    children: [
      { id: 'lfi-rfi-tools', name: { zh: 'LFI/RFI工具', en: 'LFI/RFI Tools' }, toolId: 'lfi-rfi-tools' },
      { id: 'xss-tools', name: { zh: 'XSS利用工具', en: 'XSS Tools' }, toolId: 'xss-tools' },
      { id: 'jwt-attacks', name: { zh: 'JWT攻击工具', en: 'JWT Attack Tools' }, toolId: 'jwt-attacks' },
      { id: 'file-upload-attacks', name: { zh: '文件上传攻击', en: 'File Upload Attacks' }, toolId: 'file-upload-attacks' },
      { id: 'ssrf-exploitation', name: { zh: 'SSRF利用', en: 'SSRF Exploitation' }, toolId: 'ssrf-exploitation' },
      { id: 'xxe-tools', name: { zh: 'XXE攻击工具', en: 'XXE Attack Tools' }, toolId: 'xxe-tools' },
      { id: 'web-cache-tools', name: { zh: 'Web缓存攻击', en: 'Web Cache Attacks' }, toolId: 'web-cache-tools' },
      { id: 'command-injection-advanced', name: { zh: '命令注入高级', en: 'Command Injection Adv' }, toolId: 'command-injection-advanced' },
      { id: 'web-authentication-bypass', name: { zh: '认证绕过技术', en: 'Auth Bypass Techniques' }, toolId: 'web-authentication-bypass' },
      { id: 'web-cms-attacks', name: { zh: 'CMS攻击速查', en: 'CMS Attack Reference' }, toolId: 'web-cms-attacks' },
      { id: 'web-deserialization', name: { zh: '反序列化攻击', en: 'Deserialization Attacks' }, toolId: 'web-deserialization' },
      { id: 'php-attacks', name: { zh: 'PHP安全攻击', en: 'PHP Security Attacks' }, toolId: 'php-attacks' },
      { id: 'java-pentest', name: { zh: 'Java应用渗透', en: 'Java App Pentest' }, toolId: 'java-pentest' },
      { id: 'sql-injection-advanced', name: { zh: 'SQL注入高级', en: 'SQL Injection Advanced' }, toolId: 'sql-injection-advanced' },
      { id: 'oauth-oidc-attacks', name: { zh: 'OAuth/OIDC攻击', en: 'OAuth/OIDC Attacks' }, toolId: 'oauth-oidc-attacks' },
      { id: 'api-security-tools', name: { zh: 'API安全测试', en: 'API Security Testing' }, toolId: 'api-security-tools' },
      { id: 'grpc-websocket-security', name: { zh: 'gRPC/WebSocket安全', en: 'gRPC/WebSocket Security' }, toolId: 'grpc-websocket-security' },
      { id: 'web-advanced-attacks', name: { zh: 'Web高级攻击', en: 'Web Advanced Attacks' }, toolId: 'web-advanced-attacks' },
      { id: 'web-api-testing', name: { zh: 'Web API安全测试', en: 'Web API Testing' }, toolId: 'web-api-testing' },
      { id: 'web-cache-attacks', name: { zh: 'Web缓存攻击', en: 'Web Cache Attacks' }, toolId: 'web-cache-attacks' },
      { id: 'web-security-headers', name: { zh: 'HTTP安全头测试', en: 'Security Headers Testing' }, toolId: 'web-security-headers' }
    ]
  },
  {
    id: 'red-team-ops',
    name: { zh: '🔴 红队工具', en: '🔴 Red Team Tools' },
    children: [
      { id: 'red-team-operations', name: { zh: '红队行动速查', en: 'Red Team Operations' }, toolId: 'red-team-operations' },
      { id: 'red-team-infrastrucutre', name: { zh: '红队基础设施', en: 'Red Team Infrastructure' }, toolId: 'red-team-infrastrucutre' },
      { id: 'process-injection', name: { zh: '进程注入技术', en: 'Process Injection' }, toolId: 'process-injection' },
      { id: 'atomic-red-team', name: 'Atomic Red Team', toolId: 'atomic-red-team' },
      { id: 'pentest-automation-frameworks', name: { zh: '渗透自动化框架', en: 'Pentest Automation' }, toolId: 'pentest-automation-frameworks' }
    ]
  },
  {
    id: 'misc-pentest-tools',
    name: { zh: '🔧 其他渗透工具', en: '🔧 Misc Pentest Tools' },
    children: [
      { id: 'netcat-advanced', name: { zh: 'Netcat高级', en: 'Netcat Advanced' }, toolId: 'netcat-advanced' },
      { id: 'metasploit-advanced', name: { zh: 'Metasploit高级', en: 'Metasploit Advanced' }, toolId: 'metasploit-advanced' },
      { id: 'impacket-advanced', name: { zh: 'Impacket高级', en: 'Impacket Advanced' }, toolId: 'impacket-advanced' },
      { id: 'john-enhanced', name: { zh: 'John高级用法', en: 'John Advanced' }, toolId: 'john-enhanced' },
      { id: 'hash-cracking', name: { zh: '哈希破解速查', en: 'Hash Cracking Reference' }, toolId: 'hash-cracking' },
      { id: 'password-spraying', name: { zh: '密码喷洒工具', en: 'Password Spraying' }, toolId: 'password-spraying' },
      { id: 'proxy-tools', name: { zh: '代理工具速查', en: 'Proxy Tools Reference' }, toolId: 'proxy-tools' },
      { id: 'file-transfer-techniques', name: { zh: '文件传输技术', en: 'File Transfer Techniques' }, toolId: 'file-transfer-techniques' },
      { id: 'exfiltration-techniques', name: { zh: '数据外带技术', en: 'Data Exfiltration' }, toolId: 'exfiltration-techniques' },
      { id: 'web-shells', name: { zh: 'WebShell工具', en: 'WebShell Tools' }, toolId: 'web-shells' },
      { id: 'web-shell-payloads', name: { zh: 'WebShell集合', en: 'WebShell Collection' }, toolId: 'web-shell-payloads' },
      { id: 'exploit-db-search', name: { zh: 'Exploit搜索速查', en: 'Exploit Search' }, toolId: 'exploit-db-search' },
      { id: 'vulnerability-research', name: { zh: '漏洞研究工具', en: 'Vuln Research Tools' }, toolId: 'vulnerability-research' },
      { id: 'exploit-development', name: { zh: '漏洞利用开发', en: 'Exploit Development' }, toolId: 'exploit-development' },
      { id: 'network-enum-tools', name: { zh: '网络枚举工具', en: 'Network Enum Tools' }, toolId: 'network-enum-tools' },
      { id: 'database-pentest-tools', name: { zh: '数据库渗透工具', en: 'Database Pentest' }, toolId: 'database-pentest-tools' },
      { id: 'mysql-pentest', name: { zh: 'MySQL渗透', en: 'MySQL Pentest' }, toolId: 'mysql-pentest' },
      { id: 'redis-pentest', name: { zh: 'Redis渗透', en: 'Redis Pentest' }, toolId: 'redis-pentest' },
      { id: 'mssql-pentest', name: { zh: 'MSSQL渗透', en: 'MSSQL Pentest' }, toolId: 'mssql-pentest' },
      { id: 'secure-coding-flaws', name: { zh: '代码审计速查', en: 'Code Audit Reference' }, toolId: 'secure-coding-flaws' },
      { id: 'misc-useful-commands', name: { zh: '实用命令集', en: 'Useful Commands' }, toolId: 'misc-useful-commands' },
      { id: 'supply-chain-security', name: { zh: '供应链安全', en: 'Supply Chain Security' }, toolId: 'supply-chain-security' },
      { id: 'semgrep', name: 'Semgrep', toolId: 'semgrep' },
      { id: 'gitleaks', name: 'Gitleaks', toolId: 'gitleaks' },
      { id: 'trufflehog', name: 'TruffleHog', toolId: 'trufflehog' },
      { id: 'trivy', name: 'Trivy', toolId: 'trivy' },
      { id: 'syft', name: 'Syft', toolId: 'syft' },
      { id: 'grype', name: 'Grype', toolId: 'grype' },
      { id: 'osv-scanner', name: 'OSV-Scanner', toolId: 'osv-scanner' },
      { id: 'checkov', name: 'Checkov', toolId: 'checkov' },
      { id: 'tfsec', name: 'tfsec', toolId: 'tfsec' },
      { id: 'prowler', name: 'Prowler', toolId: 'prowler' },
      { id: 'cloud-misc-tools', name: { zh: '云平台杂项工具', en: 'Cloud Misc Tools' }, toolId: 'cloud-misc-tools' },
      { id: 'aws-advanced-attacks', name: { zh: 'AWS高级攻击', en: 'AWS Advanced Attacks' }, toolId: 'aws-advanced-attacks' },
      { id: 'enumeration-automation', name: { zh: '枚举自动化', en: 'Enum Automation' }, toolId: 'enumeration-automation' },
      { id: 'exploit-frameworks', name: { zh: '漏洞利用框架', en: 'Exploit Frameworks' }, toolId: 'exploit-frameworks' },
      { id: 'git-operations', name: { zh: 'Git安全操作', en: 'Git Security Ops' }, toolId: 'git-operations' },
      { id: 'network-protocols', name: { zh: '网络协议渗透', en: 'Network Protocol Pentest' }, toolId: 'network-protocols' },
      { id: 'network-scanning-advanced', name: { zh: '高级网络扫描', en: 'Advanced Network Scanning' }, toolId: 'network-scanning-advanced' },
      { id: 'openvas-vulnerability-scan', name: 'OpenVAS', toolId: 'openvas-vulnerability-scan' },
      { id: 'python-pentest-scripts', name: { zh: 'Python渗透脚本', en: 'Python Pentest Scripts' }, toolId: 'python-pentest-scripts' },
      { id: 'wfuzz-tool', name: 'WFuzz', toolId: 'wfuzz-tool' },
      { id: 'searchsploit-tool', name: 'SearchSploit', toolId: 'searchsploit-tool' },
      { id: 'wireless-attacks', name: { zh: 'Wi-Fi安全测试', en: 'Wi-Fi Security Testing' }, toolId: 'wireless-attacks' },
      { id: 'network-attacks', name: { zh: '网络层攻击', en: 'Network Layer Attacks' }, toolId: 'network-attacks' },
      { id: 'dns-attacks', name: { zh: 'DNS攻击技术', en: 'DNS Attack Techniques' }, toolId: 'dns-attacks' },
      { id: 'docker-commands', name: { zh: 'Docker管理命令', en: 'Docker Management' }, toolId: 'docker-commands' }
    ]
  }

];

export default navigationData;
