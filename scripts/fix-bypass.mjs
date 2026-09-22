import { readFileSync, writeFileSync } from 'fs';
const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');

const anchor = '利用PHP包装器协议访问压缩包内的恶意文件';
const idx = c.indexOf(anchor);
if (idx < 0) { console.log('ANCHOR NOT FOUND'); process.exit(1); }

// Find the pattern: after anchor, there should be `' },` then `      },` then `    ],` then `    tutorial: {`
const after = c.slice(idx);
const m = after.match(/' \},\s*\},\s*\],\s*tutorial: \{/s);
if (!m) { console.log('Pattern not found. After anchor:', after.slice(0, 200)); process.exit(1); }

const fullMatch = anchor + m[0];

const ac = [
  "      { title: { zh: '扩展名绕过探测', en: 'Extension bypass probe' }, description: { zh: '尝试大小写混写、双扩展名、PHP别名(.phtml/.pht/.phar/.php5)、分号拼接(.php;.jpg)、NTFS流、双写绕过和编辑器路径，全面探测黑名单盲区。', en: 'Try case variations, double extensions, PHP aliases, semicolon concatenation, NTFS ADS, double-write, and editor paths to map blacklist gaps.' } },",
  "      { title: { zh: 'Content-Type伪造', en: 'Content-Type spoofing' }, description: { zh: '将Content-Type改为image/jpeg/png等白名单值，结合Content-Disposition编码变体和分块传输测试MIME校验。', en: 'Change Content-Type to allowlisted values with Content-Disposition encoding variants and chunked transfer to test MIME validation.' } },",
  "      { title: { zh: '魔术字节与图片马', en: 'Magic bytes & image webshells' }, description: { zh: '在PHP代码前加GIF89a/PNG/JPEG/BMP/PDF文件头，或用copy /b合成图片马；通过ExifTool和SVG注入扩展攻击面。', en: 'Prepend GIF89a/PNG/JPEG/BMP/PDF headers or use copy /b; extend via ExifTool and SVG injection.' } },",
  "      { title: { zh: '平台解析特性利用', en: 'Platform parser exploitation' }, description: { zh: '利用IIS分号截断(.asp;.jpg)、Apache .htaccess AddType覆盖、Nginx空字节截断(CVE-2013-4547)和NTFS ADS突破限制。', en: 'Exploit IIS semicolon truncation, Apache .htaccess AddType, Nginx null-byte, and NTFS ADS.' } },",
  "      { title: { zh: '验证WebShell可执行', en: 'Verify WebShell execution' }, description: { zh: '访问上传URL确认代码被解析；若被拦截尝试.htaccess/.user.ini覆盖或zip/phar伪协议引用图片马。', en: 'Access uploaded URL to confirm parsing; if blocked, override via .htaccess/.user.ini or reference via zip/phar.' } },",
];

const insertion = anchor + m[0].replace('tutorial: {', '') +
  "    attackChain: [\n" + ac.join('\n') + "\n    ],\n" +
  "    analysis: { zh: '文件上传绕过本质是利用验证链不一致性：黑名单覆盖不全、MIME头与内容校验分离、平台解析差异（IIS/Apache/Nginx）、客户端验证可绕过。攻击者只需找到未被拦截的扩展名+MIME+内容组合即可将WebShell写入目标。', en: 'File upload bypass exploits validation chain inconsistency: incomplete blacklists, MIME-vs-content check separation, platform parsing differences, and bypassable client-side validation. One unblocked combo of extension, MIME, and content lands a WebShell.' },\n" +
  "    references: [\n" +
  "      'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',\n" +
  "      'https://book.hacktricks.wiki/en/pentesting-web/file-upload/index.html',\n" +
  "      'https://portswigger.net/web-security/file-upload',\n" +
  "      'https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files',\n" +
  "    ],\n" +
  "    tutorial: {";

c = c.replace(fullMatch, insertion);
writeFileSync(fp, c, 'utf8');
console.log('DONE file-upload-bypass enrichment');
