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
          { id: 'rce-upload', name: { zh: '文件上传漏洞', en: 'File Upload Vulnerability' }, payloadId: 'rce-file-upload' },
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
          { id: 'jwt', name: { zh: 'JWT安全', en: 'JWT Security' }, payloadId: 'jwt-security' },
          { id: 'jwt-none-alg', name: { zh: 'JWT None算法', en: 'JWT None Algorithm' }, payloadId: 'jwt-none-alg' },
          { id: 'jwt-key-confusion', name: { zh: 'JWT密钥混淆', en: 'JWT Key Confusion' }, payloadId: 'jwt-key-confusion' },
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
          { id: 'file-upload', name: { zh: '文件上传基础', en: 'File Upload Basics' }, payloadId: 'file-upload-bypass' },
          { id: 'file-upload-bypass', name: { zh: '上传绕过技术', en: 'Upload Bypass Techniques' }, payloadId: 'file-upload-bypass' },
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
          { id: 'biz-coupon-abuse-nav', name: { zh: '优惠券滥用', en: 'Coupon Abuse' }, payloadId: 'biz-coupon-abuse' }
        ]
      },
      {
        id: 'jwt-security',
        name: { zh: 'JWT安全', en: 'JWT Security' },
        children: [
          { id: 'jwt-none-algo-nav', name: { zh: 'None算法攻击', en: 'None Algorithm Attack' }, payloadId: 'jwt-none-algo' },
          { id: 'jwt-weak-secret-nav', name: { zh: '弱密钥爆破', en: 'Weak Secret Brute Force' }, payloadId: 'jwt-weak-secret' },
          { id: 'jwt-kid-injection-nav', name: { zh: 'KID注入攻击', en: 'KID Injection Attack' }, payloadId: 'jwt-kid-injection' },
          { id: 'jwt-jku-spoofing-nav', name: { zh: 'JKU欺骗攻击', en: 'JKU Spoofing Attack' }, payloadId: 'jwt-jku-spoofing' }
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
          { id: 'cloud-k8s-escape-nav', name: { zh: 'K8s容器逃逸', en: 'K8s Container Escape' }, payloadId: 'cloud-k8s-escape' }
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
        id: 'evasion',
        name: { zh: '免杀与规避', en: 'Evasion & AV Bypass' },
        children: [
          { id: 'amsi-bypass', name: { zh: 'AMSI绕过', en: 'AMSI Bypass' }, payloadId: 'amsi-bypass' },
          { id: 'etw-patch', name: 'ETW Patch', payloadId: 'etw-patch' },
          { id: 'blockdlls', name: 'BlockDLLs', payloadId: 'evasion-blockdlls' },
          { id: 'unhooking', name: 'API Unhooking', payloadId: 'api-unhooking' },
          { id: 'shellcode-encrypt', name: { zh: 'Shellcode加密', en: 'Shellcode Encryption' }, payloadId: 'evasion-shellcode-encrypt' },
          { id: 'process-masq', name: { zh: '进程伪装', en: 'Process Masquerading' }, payloadId: 'evasion-process-masq' },
          { id: 'ppid-spoofing', name: { zh: 'PPID欺骗', en: 'PPID Spoofing' }, payloadId: 'evasion-ppid-spoof' },
          { id: 'dll-side-loading', name: { zh: 'DLL侧加载', en: 'DLL Side-Loading' }, payloadId: 'evasion-dll-sideloading' },
          { id: 'process-injection', name: { zh: '进程注入', en: 'Process Injection' }, payloadId: 'process-injection' },
          { id: 'argument-spoof', name: { zh: '参数欺骗', en: 'Argument Spoofing' }, payloadId: 'evasion-arg-spoofing' },
          { id: 'signed-binary', name: { zh: '签名二进制利用', en: 'Signed Binary Abuse' }, payloadId: 'evasion-signed-binary' },
          { id: 'clr-injection', name: { zh: 'CLR注入', en: 'CLR Injection' }, payloadId: 'evasion-clr-injection' },
          { id: 'applocker-bypass', name: { zh: 'AppLocker绕过', en: 'AppLocker Bypass' }, payloadId: 'applocker-bypass' },
          { id: 'evasion-powershell-nav', name: { zh: 'PowerShell免杀', en: 'PowerShell Evasion' }, payloadId: 'evasion-powershell' }
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
  }
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
      { id: 'httpx', name: 'HTTPX', toolId: 'httpx' },
      { id: 'nuclei', name: 'Nuclei', toolId: 'nuclei' },
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
      { id: 'bloodhound-cypher', name: 'BloodHound Cypher', toolId: 'bloodhound-cypher' }
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
  }
];

export default navigationData;
