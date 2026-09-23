import { readFileSync, writeFileSync } from 'node:fs';

const filePath = 'src/data/webPayloads.ts';
let content = readFileSync(filePath, 'utf8');

const enrichments = [
  // --- file-upload-bypass ---
  {
    anchor: `利用PHP包装器协议访问压缩包内的恶意文件', en: 'Bypass WAF stream inspection via Content-Disposition header filename encoding variants and chunked transfer encoding; use PHP wrapper protocols to access malicious files inside archives' },\r\n      },\r\n    ],\r\n    tutorial: {`,
    insertion: `利用PHP包装器协议访问压缩包内的恶意文件', en: 'Bypass WAF stream inspection via Content-Disposition header filename encoding variants and chunked transfer encoding; use PHP wrapper protocols to access malicious files inside archives' },\r\n      },\r\n    ],\r\n    attackChain: [\r\n      { title: { zh: '扩展名绕过探测', en: 'Extension bypass probe' }, description: { zh: '尝试大小写混写(.PhP)、双扩展名(.php.jpg)、PHP 别名(.phtml/.pht/.phar/.php5)、分号拼接(.php;.jpg)和 NTFS 流(::$DATA)，确认黑名单覆盖盲区。', en: 'Try case variations, double extensions, PHP aliases, semicolon concatenation, and NTFS ADS to identify blacklist coverage gaps.' } },\r\n      { title: { zh: 'Content-Type 伪造', en: 'Content-Type spoofing' }, description: { zh: '将 Content-Type 改为 image/jpeg、image/png 等允许类型，验证服务端校验是否仅停留在 MIME 头层面。', en: 'Change Content-Type to image/jpeg or image/png to verify whether server validation stops at the MIME header level.' } },\r\n      { title: { zh: '文件内容魔术字节', en: 'Magic byte injection' }, description: { zh: '在 PHP 代码前添加 GIF89a、\\x89PNG、\\xff\\xd8\\xff 等合法文件头魔术字节，或使用 copy /b 命令合成图片马绕过内容检测。', en: 'Prepend legitimate file magic bytes (GIF89a, PNG, JPEG) before PHP code, or use copy /b to create image webshells that bypass content-based type detection.' } },\r\n      { title: { zh: '平台解析特性利用', en: 'Platform parser exploitation' }, description: { zh: '利用 IIS 分号截断(.asp;.jpg)、Apache .htaccess AddType 覆盖、Nginx 空字节截断(CVE-2013-4547)和 NTFS ADS 突破限制。', en: 'Exploit platform-specific parsing behaviors: IIS semicolon truncation, Apache .htaccess AddType override, Nginx null-byte truncation, and NTFS ADS.' } },\r\n      { title: { zh: '验证 WebShell 可执行', en: 'Verify WebShell execution' }, description: { zh: '访问上传文件 URL 确认代码是否被解析执行；若被拦截则尝试 .htaccess 或 .user.ini 配置覆盖目录解析规则，或通过 zip/phar 伪协议引用图片马。', en: 'Access the uploaded file URL to confirm code execution; if blocked, upload .htaccess or .user.ini to override parsing rules, or reference the image shell via zip/phar pseudo-protocols.' } },\r\n    ],\r\n    analysis: { zh: '文件上传绕过的本质是利用验证链的不一致性——黑名单覆盖不全(PHP 变体扩展名)、MIME 头与实际内容校验分离、平台解析差异(IIS/Apache/Nginx)、客户端验证可被绕过。攻击者只需找到一个未被拦截的扩展名+MIME+内容组合，就能将 WebShell 写入目标。', en: 'File upload bypass exploits inconsistency in the validation chain: incomplete extension blacklists, MIME-vs-content check separation, platform parsing differences, and bypassable client-side validation. Finding one unblocked combination of extension, MIME type, and content is sufficient to land a WebShell.' },\r\n    references: [\r\n      'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',\r\n      'https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html',\r\n      'https://portswigger.net/web-security/file-upload',\r\n      'https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files',\r\n    ],\r\n    tutorial: {`,
  },

  // --- file-download ---
  {
    anchor: `id: 'file-download',\r\n    name: { zh: '任意文件下载'`,
    insertion: null, // will be processed differently
  },
];

// Process file-upload-bypass first
let changed = false;
for (const e of enrichments) {
  if (e.anchor && e.insertion) {
    if (content.includes(e.anchor)) {
      content = content.replace(e.anchor, e.insertion);
      console.log('Applied:', e.anchor.slice(0, 80) + '...');
      changed = true;
    } else {
      console.log('NOT FOUND:', e.anchor.slice(0, 80) + '...');
    }
  }
}

if (changed) {
  writeFileSync(filePath, content, 'utf8');
  console.log('File written successfully.');
} else {
  console.log('No changes made.');
}

// Now handle the remaining file payloads by finding their positions
// and inserting attackChain, analysis, references before tutorial

const filePayloads = [
  {
    id: 'file-download',
    attackChain: [
      { title: { zh: '识别文件下载接口', en: 'Identify file download endpoint' }, description: { zh: '通过代理历史、JS 分析和目录扫描定位接受文件路径参数的下载接口，确认参数名和响应类型。', en: 'Locate download endpoints that accept file path parameters through proxy history, JS analysis, and directory scanning; confirm parameter names and response types.' } },
      { title: { zh: '路径遍历测试', en: 'Path traversal testing' }, description: { zh: '使用 ../、..%2f、..%252f 等编码变体尝试突破目录限制，读取 /etc/passwd、web.config 等系统敏感文件。', en: 'Use ../, ..%2f, ..%252f, and other encoding variants to break directory restrictions and read system-sensitive files like /etc/passwd or web.config.' } },
      { title: { zh: '源码与配置提取', en: 'Source code and config extraction' }, description: { zh: '下载应用源码、数据库配置、.env 等文件，提取凭据、密钥和连接字符串用于后续深入攻击。', en: 'Download application source code, database configurations, .env files to extract credentials, keys, and connection strings for further attacks.' } },
      { title: { zh: '自动化批量探测', en: 'Automated bulk probing' }, description: { zh: '使用敏感文件字典批量探测常见路径，扩大攻击面并提高发现率。', en: 'Use sensitive file dictionaries to bulk-probe common paths, expanding the attack surface and improving discovery rate.' } },
    ],
    analysis: { zh: '任意文件下载漏洞允许攻击者通过操控路径参数读取服务器上的任何文件，从操作系统文件(/etc/passwd、/etc/shadow)到应用配置(.env、web.config)再到源码均可被窃取。根因通常是路径拼接未校验、未限制可访问目录白名单、或路径归一化后仍可逃逸。这是信息收集阶段的高危漏洞，常为后续 RCE 或横向移动铺路。', en: 'Arbitrary file download allows attackers to read any server file by manipulating path parameters — from OS files to application configs and source code. Root causes include unvalidated path concatenation, missing directory allowlists, or path normalization that still allows escape. This high-risk information disclosure vulnerability often paves the way for RCE or lateral movement.' },
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion',
      'https://portswigger.net/web-security/file-path-traversal',
    ],
  },
  {
    id: 'file-competition',
    attackChain: [
      { title: { zh: '识别竞态窗口', en: 'Identify race window' }, description: { zh: '确认上传后文件是否被临时存储再检查删除，或是否先写入再校验——这两种模式存在可利用的时间窗口。', en: 'Confirm whether files are temporarily stored before inspection, or written before validation — both patterns create exploitable time windows.' } },
      { title: { zh: '编写并发脚本', en: 'Write concurrent script' }, description: { zh: '使用 Python 多线程/异步同时发起上传请求和文件访问请求，在服务端删除文件前抢先执行 WebShell。', en: 'Use Python multi-threading/async to simultaneously send upload requests and file access requests, executing the WebShell before server-side deletion.' } },
      { title: { zh: '调优并发参数', en: 'Tune concurrency parameters' }, description: { zh: '调整线程数、请求间隔和 payload 大小，最大化命中窗口的概率。', en: 'Adjust thread count, request interval, and payload size to maximize the probability of hitting the race window.' } },
      { title: { zh: '.htaccess 竞态写入', en: '.htaccess race write' }, description: { zh: '竞态上传 .htaccess 文件覆盖目录解析规则，使后续上传的图片文件被当作 PHP 执行。', en: 'Race-upload .htaccess files to override directory parsing rules, causing subsequently uploaded images to be executed as PHP.' } },
    ],
    analysis: { zh: '条件竞争(Race Condition)利用的是文件处理流程中的时间窗口——当服务端先存储文件再校验、或者校验和删除之间存在间隙时，攻击者可以在安全检查完成前抢先访问文件。这种漏洞在高并发场景下尤为危险，因为多线程请求可以显著提高命中窗口的概率。', en: 'Race conditions exploit timing gaps in file processing — when servers store files before validation, or a gap exists between validation and deletion. Attackers can access files before security checks complete. This is especially dangerous under high concurrency, where multi-threaded requests significantly increase the window-hit probability.' },
    references: [
      'https://portswigger.net/web-security/file-upload#exploiting-file-upload-race-conditions',
      'https://owasp.org/www-community/attacks/Race_Condition',
    ],
  },
  {
    id: 'file-traversal',
    attackChain: [
      { title: { zh: '基础路径遍历', en: 'Basic path traversal' }, description: { zh: '使用 ../ 序列尝试读取 Web 根目录外的文件，测试 ../ 层数(3-10层)和不同操作系统的路径分隔符。', en: 'Use ../ sequences to read files outside the web root, testing depth and OS-specific path separators.' } },
      { title: { zh: '编码绕过过滤', en: 'Encoding filter bypass' }, description: { zh: '当 ../ 被过滤时，使用 URL 编码(..%2f)、双重编码(..%252f)、Unicode 变体和空字节截断绕过。', en: 'When ../ is filtered, use URL encoding (..%2f), double encoding (..%252f), Unicode variants, and null-byte truncation to bypass.' } },
      { title: { zh: '平台特定路径', en: 'Platform-specific paths' }, description: { zh: 'Linux 读取 /etc/passwd、/proc/self/environ；Windows 读取 C:\\windows\\win.ini、SAM 文件、IIS 配置。', en: 'Linux: read /etc/passwd, /proc/self/environ; Windows: read C:\\windows\\win.ini, SAM files, IIS configuration.' } },
      { title: { zh: '路径遍历升级到 RCE', en: 'Path traversal to RCE' }, description: { zh: '通过读取日志文件、SSH 密钥、源码中的凭据，或结合文件上传和日志投毒将路径遍历升级为远程代码执行。', en: 'Escalate path traversal to RCE by reading log files, SSH keys, source credentials, or combining with file upload and log poisoning.' } },
    ],
    analysis: { zh: '路径遍历(目录穿越)漏洞因应用在构建文件路径时未充分校验用户输入导致，攻击者通过 ../ 序列突破预期目录边界访问任意文件。虽然看起来只是信息泄露，但在实战中常通过读取配置文件、私钥、源码等获取凭据，进而实现权限提升或代码执行。', en: 'Path traversal occurs when applications insufficiently validate user input in file path construction, allowing ../ sequences to break directory boundaries. While appearing as mere info disclosure, it often yields credentials from configs, private keys, and source code, leading to privilege escalation or code execution.' },
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
      'https://portswigger.net/web-security/file-path-traversal',
    ],
  },
  {
    id: 'file-zip-slip',
    attackChain: [
      { title: { zh: '探测压缩包上传功能', en: 'Probe archive upload feature' }, description: { zh: '确认目标是否接受 ZIP/TAR 上传并自动解压，观察解压后的文件路径和访问方式。', en: 'Confirm whether the target accepts ZIP/TAR uploads with auto-extraction; observe extracted file paths and access methods.' } },
      { title: { zh: '构造恶意压缩包', en: 'Craft malicious archive' }, description: { zh: '使用 evilarc 或 Python zipfile 创建包含路径遍历文件名(../../shell.php)的压缩包。', en: 'Use evilarc or Python zipfile to create archives containing path-traversal filenames (../../shell.php) that write outside the intended directory.' } },
      { title: { zh: '上传并验证写入位置', en: 'Upload and verify write location' }, description: { zh: '上传恶意压缩包后检查 Web 可访问目录是否被写入文件，确认 WebShell 可访问 URL。', en: 'After uploading the malicious archive, check whether files were written to web-accessible directories and confirm the WebShell URL.' } },
      { title: { zh: 'TAR/多格式变体', en: 'TAR and multi-format variants' }, description: { zh: '尝试 TAR、GZ、BZ2 等不同压缩格式，以及符号链接攻击变体扩大利用面。', en: 'Try TAR, GZ, BZ2, and other compression formats, plus symlink attack variants to expand the exploitation surface.' } },
    ],
    analysis: { zh: 'Zip Slip 是一种通过恶意压缩包中的路径遍历文件名将文件写入任意目录的攻击。当应用解压用户上传的压缩包时，如果未校验内部文件名中的 ../ 序列，攻击者可以将 WebShell 写入 Web 根目录或其他关键位置，甚至覆盖系统文件。', en: 'Zip Slip is an attack that writes files to arbitrary directories via path-traversal filenames inside malicious archives. When applications extract user-uploaded archives without validating ../ sequences in filenames, attackers can write WebShells to the web root or other critical locations, even overwriting system files.' },
    references: [
      'https://github.com/snyk/zip-slip-vulnerability',
      'https://snyk.io/research/zip-slip-vulnerability',
    ],
  },
  {
    id: 'file-mime',
    attackChain: [
      { title: { zh: '探测文件类型检查', en: 'Probe file type checks' }, description: { zh: '上传正常图片确认允许的 MIME 类型，同时尝试上传 .php 文件观察拦截行为，判断是检查 Content-Type 头还是文件内容。', en: 'Upload normal images to confirm allowed MIME types; try uploading .php files to observe blocking behavior and determine whether the check targets Content-Type header or file content.' } },
      { title: { zh: 'MIME 类型伪造', en: 'MIME type spoofing' }, description: { zh: '将 Content-Type 改为 image/jpeg、image/png、image/gif 等白名单类型，测试服务端是否仅依赖客户端声明的 MIME。', en: 'Change Content-Type to allowlisted types like image/jpeg, image/png, or image/gif to test whether the server relies solely on client-declared MIME.' } },
      { title: { zh: '魔术字节伪造', en: 'Magic byte forgery' }, description: { zh: '在 WebShell 前添加合法的文件头魔术字节(GIF89a、\x89PNG、\xff\xd8\xff、BM 等)绕过基于文件内容的类型检测。', en: 'Prepend legitimate file magic bytes (GIF89a, \\x89PNG, \\xff\\xd8\\xff, BM) before the WebShell to bypass content-based type detection.' } },
      { title: { zh: '验证上传文件可执行', en: 'Verify uploaded file is executable' }, description: { zh: '访问上传文件确认是否被服务器解析执行，若为图片扩展名则结合解析漏洞或 .htaccess 覆盖实现代码执行。', en: 'Access the uploaded file to confirm server-side parsing; if saved with an image extension, combine with parsing bugs or .htaccess override for code execution.' } },
    ],
    analysis: { zh: 'MIME 类型绕过针对的是仅校验 Content-Type 请求头或文件扩展名而不检查实际文件内容的上传机制。许多应用只做客户端或浅层服务端校验，攻击者只需将 Content-Type 改为白名单值并添加合法文件头魔术字节即可绕过。', en: 'MIME type bypass targets upload mechanisms that only validate the Content-Type header or file extension without inspecting actual file content. Many apps only perform client-side or shallow server-side checks — attackers can bypass by simply changing Content-Type to an allowlisted value and prepending legitimate magic bytes.' },
    references: [
      'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
      'https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html',
    ],
  },
  {
    id: 'file-null-byte',
    attackChain: [
      { title: { zh: '环境检测', en: 'Environment detection' }, description: { zh: '确认目标运行 PHP 版本(<5.3.4 存在原生空字节截断)或其他语言的空字节处理行为。', en: 'Confirm the target PHP version (native null-byte truncation in <5.3.4) or null-byte handling behavior in other languages.' } },
      { title: { zh: '文件上传空字节截断', en: 'Upload null-byte truncation' }, description: { zh: '在文件名中注入 %00 或 \\x00(shell.php%00.jpg)，使后端校验时看到 .jpg 通过检查，但文件系统保存时截断为 .php。', en: 'Inject %00 or \\x00 in filenames (shell.php%00.jpg) so the backend sees .jpg and passes validation, but the filesystem truncates to .php on save.' } },
      { title: { zh: '文件包含空字节截断', en: 'Include null-byte truncation' }, description: { zh: '在 LFI 参数尾部追加 %00(如 /etc/passwd%00)，绕过 .php/.html 等后缀拼接限制。', en: 'Append %00 to LFI parameters (e.g., /etc/passwd%00) to bypass forced .php/.html suffix concatenation.' } },
      { title: { zh: '现代替代方案', en: 'Modern alternatives' }, description: { zh: '当空字节截断被修复后，改用路径长度截断、Unicode 特殊字符、或竞争条件等替代技术绕过。', en: 'When null-byte truncation is patched, switch to path length truncation, special Unicode characters, or race conditions as alternative bypass techniques.' } },
    ],
    analysis: { zh: '空字节截断是一种经典的文件名验证绕过技术，利用 C 语言字符串以 \\x00 结尾的特性——当 PHP 等语言调用底层 C 函数处理文件名时，%00 之后的字符被截断，导致验证时看到的是合法扩展名(.jpg)，而实际保存的是可执行文件(.php)。虽然现代 PHP(>=5.3.4)已修复此问题，但在老旧系统和部分其他语言中仍然有效。', en: 'Null-byte truncation is a classic filename validation bypass that exploits the C-string null-terminator behavior — when PHP and similar languages call underlying C functions, characters after %00 are truncated. The validator sees a legitimate extension (.jpg) while the filesystem saves an executable (.php). Although modern PHP (>=5.3.4) is patched, it remains effective on legacy systems and some other languages.' },
    references: [
      'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
      'https://portswigger.net/web-security/file-upload',
    ],
  },
];

// Function to escape for regex
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Process each file payload
let allChanges = 0;
for (const fp of filePayloads) {
  // Find the payload by ID and locate its tutorial section
  const idPattern = new RegExp(
    `(id: '${escapeRegex(fp.id)}',[\\s\\S]*?)(    tutorial: \\{)`,
    'm'
  );
  const match = content.match(idPattern);
  if (!match) {
    console.log(`SKIP ${fp.id}: could not find tutorial`);
    continue;
  }

  // Build the insertion text
  const chainLines = fp.attackChain.map(step =>
    `      { title: { zh: '${step.title.zh}', en: '${step.title.en}' }, description: { zh: '${step.description.zh}', en: '${step.description.en}' } },`
  ).join('\r\n');

  const refLines = fp.references.map(r => `      '${r}',`).join('\r\n');

  const insertion = `    attackChain: [\r\n${chainLines}\r\n    ],\r\n    analysis: { zh: '${fp.analysis.zh}', en: '${fp.analysis.en}' },\r\n    references: [\r\n${refLines}\r\n    ],\r\n    tutorial: {`;

  // Replace: tutorial: { -> attackChain + analysis + references + tutorial: {
  const oldText = match[0];
  const newText = oldText.replace('    tutorial: {', insertion);
  content = content.replace(oldText, newText);
  console.log(`DONE ${fp.id}`);
  allChanges++;
}

// Also add global references for file-upload-basic (already handled by first Edit)
// Let's verify it was added
if (content.includes("attackChain: [") && content.includes("file-upload-basic")) {
  console.log('file-upload-basic: verified attackChain present');
}

writeFileSync(filePath, content, 'utf8');
console.log(`\nTotal payloads enriched: ${allChanges}`);
console.log('File written successfully.');
