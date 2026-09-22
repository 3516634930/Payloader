import { loadDefaultData } from '../server/data-store.mjs';
import { readFile } from 'node:fs/promises';

const args = new Set(process.argv.slice(2));
const summaryMode = args.has('--summary') || args.has('-s');
const includeLegacySource = args.has('--include-legacy-src-data');

const text = value => {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') return value.zh || value.en || '';
  return '';
};

const asList = value => Array.isArray(value) ? value : [];
const hasHan = value => /\p{Script=Han}/u.test(String(value || ''));
const hasShellPrefix = value => /^(sudo\s+|curl\s+|wget\s+|python\d?\s+|php\s+|bash\s+|sh\s+|powershell\s+|cmd\s+|certutil\s+|nc\s+|ncat\s+|socat\s+|msfconsole\s+|sqlmap\s+|nmap\s+|ffuf\s+|gobuster\s+|dirsearch\s+|hydra\s+|john\s+|hashcat\s+|impacket-|crackmapexec\s+|netexec\s+|bloodhound-python\s+|SharpHound\.exe|mimikatz|redis-cli\s+|mysql\s+|psql\s+|ldapsearch\s+|wmic\s+|winrm\s+|evil-winrm\s+|proxychains\d?\s+|chisel(\.exe)?\s+|frpc?\s+|ssh\s+|scp\s+)/i.test(String(value || '').trim());
const hasPayloadChars = value => /(<script|onerror=|onload=|javascript:|UNION\s+SELECT|SELECT\s+|OR\s+1=1|SLEEP\(|WAITFOR|\/\.\.\/|<!ENTITY|<\?xml|{{|}}|\$\{|%[0-9a-f]{2}|\\u[0-9a-f]{4}|base64|gopher:\/\/|file:\/\/|dict:\/\/|ldap:\/\/|php:\/\/|data:\/\/|zip:\/\/|phar:\/\/|expect:\/\/|https?:\/\/|Content-Type:|Authorization:|Set-Cookie:|Transfer-Encoding:|eyJ|<svg|<img|cmd=|exec\(|system\(|Runtime\.getRuntime|ProcessBuilder|powershell|bash\s+-c|\/bin\/sh)/i.test(String(value || ''));
const retiredEdrPattern = /\bEDR\b|\u514d\u6740|AV-evasion|Anti-Detection|Evasion & AV|edrBypass/i;
const mojibakePattern = /\uFFFD|[\u951B\u94B4\u923F\u9428\u95AB\u95BD\u9429\u7EFE\u9A9E\u9352\u93C8\u935B\u701B\u701A\u6D93\u5A34\u74BA\u60E7\u93C0]/u;
const machineTranslatedEnglishPattern = /(Targethas|CanTraverse|APIMiddle|UseNumber|UsersToken|ManagementMember|Original[A-Z]|Current[A-Z]|AttackPerson|Automatic-ize|BelowSingle|CanInterception|NumberGroups|ModifyUsers|QueryDatabase|LoginUsers|CanTampering|ResourceAccess|Privilege escalationTest|Identify Can Exploitation|iframenested|sandboxproperty|Bypassoperation|Defaultkey|Internal network Can Access|Exploitation (?:ESC|Shiro|XXE)|Java Script|post Message|j Query|AP Is|UR Ls|Re Georg|remember Me|delete Me|html \(\)|extend \(\)|Codeline)/;

const commandAreas = ['execution', 'wafBypass'];
const allowedLiteralVariables = new Set(['IFS']);
const toolCategoryNames = new Set([
  '信息收集',
  '横向移动',
  '权限提升',
  '权限维持',
  '域渗透攻击',
  '隧道代理',
  '凭证窃取',
  'Exchange攻击',
  'ADCS攻击',
  'SharePoint攻击',
]);

const rawPayloadRefAliases = new Map([
  ['biz-price-tamper', 'biz-payment-tamper'],
  ['jwt-none-algo', 'jwt-none-attack'],
  ['jwt-weak-secret', 'jwt-secret-bruteforce'],
  ['jwt-kid-injection', 'jwt-key-confusion'],
  ['jwt-jku-spoofing', 'jwt-jku-x5u-injection'],
]);

const resolvedPayloadId = id => rawPayloadRefAliases.get(id) || id;

const hasResolvedPayload = (payloadIds, defaultPayloadIds, id) => {
  const resolved = resolvedPayloadId(id);
  return payloadIds.has(resolved) || defaultPayloadIds.has(resolved);
};

const likelyToolCommand = command => {
  const line = String(command || '').trim().split(/\r?\n/).find(Boolean) || '';
  return hasShellPrefix(line) && !hasPayloadChars(line);
};

const likelyPayloadLine = line => {
  const trimmed = String(line || '').trim();
  if (!trimmed) return false;
  if (/PAYLOADER_LAB|X-AI-Lab|user_request|retrieved_text|tool-result/i.test(trimmed)) return true;
  if (hasPayloadChars(trimmed) || hasShellPrefix(trimmed)) return true;
  if (/^(['"`)]?\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|EXEC|WAITFOR|SLEEP|ORDER\s+BY)\b)/i.test(trimmed)) return true;
  if (/^[<>{}[\]'"`;&|$%\\/.-]/.test(trimmed) && !hasHan(trimmed)) return true;
  return false;
};

const destructiveDbCleanupPattern = /\b(DROP\s+TABLE|TRUNCATE\s+TABLE|FLUSHALL|FLUSHDB)\b/i;
const workflowCommandPattern = destructiveDbCleanupPattern;
const copyListResiduePattern = destructiveDbCleanupPattern;
const highRiskResiduePattern = destructiveDbCleanupPattern;
const highRiskMetadataPattern = /\b(DROP\s+TABLE|TRUNCATE\s+TABLE|FLUSHALL|FLUSHDB)\b|清库|删库|删表/i;
const scriptResiduePattern = /a^/;
const placeholderResiduePattern = /a^/;

const collectWorkflowCommandIssues = payload => {
  const issues = [];
  for (const area of commandAreas) {
    asList(payload[area]).forEach((entry, index) => {
      const lines = String(entry.command || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      const workflowLines = lines.filter(line => workflowCommandPattern.test(line) || copyListResiduePattern.test(line) || highRiskResiduePattern.test(line) || scriptResiduePattern.test(line) || placeholderResiduePattern.test(line));
      if (workflowLines.length) {
        issues.push({
          area,
          index,
          title: text(entry.title),
          workflowLines: workflowLines.slice(0, 8),
          command: entry.command,
        });
      }
    });
  }
  asList(payload.attackChain).forEach((step, index) => {
    const lines = String(step.payload || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    const workflowLines = lines.filter(line => workflowCommandPattern.test(line) || copyListResiduePattern.test(line) || highRiskResiduePattern.test(line) || scriptResiduePattern.test(line) || placeholderResiduePattern.test(line));
    if (workflowLines.length) {
      issues.push({
        area: 'attackChain',
        index,
        title: text(step.title),
        workflowLines: workflowLines.slice(0, 8),
        command: step.payload,
      });
    }
  });
  return issues;
};

const collectHighRiskMetadataIssues = payload => {
  const issues = [];
  for (const area of commandAreas) {
    asList(payload[area]).forEach((entry, index) => {
      const metadata = [text(entry.title), text(entry.description)].filter(Boolean).join('\n');
      if (highRiskMetadataPattern.test(metadata)) {
        issues.push({
          area,
          index,
          title: text(entry.title),
          metadata: metadata.slice(0, 240),
        });
      }
    });
  }
  asList(payload.attackChain).forEach((step, index) => {
    const metadata = [text(step.title), text(step.description)].filter(Boolean).join('\n');
    if (highRiskMetadataPattern.test(metadata)) {
      issues.push({
        area: 'attackChain',
        index,
        title: text(step.title),
        metadata: metadata.slice(0, 240),
      });
    }
  });
  return issues;
};

const semanticPlacementRules = [
  {
    id: 'file-basic-rce-residue',
    payloadIds: new Set(['file-upload-basic', 'file-mime', 'file-competition', 'file-null-byte', 'file-zip-slip', 'file-download', 'file-traversal']),
    pattern: /WebShell|webshell|\bRCE\b|auto_prepend_file|AddHandler|SetHandler|php_value|php_flag|shell_exec|system\s*\(|Runtime\.getRuntime|ProcessBuilder|xp_cmdshell|反弹|木马|后门|代码执行|命令执行|升级\s*RCE|升级为RCE|写入[^。；，,\n\r]{0,60}\.php/i,
    message: '基础/边界型文件漏洞条目不应承载 WebShell、RCE、持久化或执行链内容；这些内容应归入 RCE、.htaccess 利用、图片马或文件包含执行类条目。',
  },
  {
    id: 'config-upload-execution-residue',
    payloadIds: new Set(['file-upload-config']),
    pattern: /WebShell|webshell|auto_prepend_file|AddHandler|SetHandler|php_value|php_flag|后门|持久化利用|代码执行|命令执行|上传含 PHP 代码/i,
    message: '配置文件上传条目应验证目录级配置是否可被用户影响，不应直接包含改变解释器或落地后门的链路。',
  },
  {
    id: 'svg-upload-exfil-or-lfi-residue',
    payloadIds: new Set(['file-upload-svg']),
    pattern: /document\.cookie|file:\/\/\/etc\/passwd|169\.254\.169\.254|127\.0\.0\.1|结合 LFI|嵌入 PHP|会话窃取/i,
    message: 'SVG 上传条目应使用无害渲染、实体和外部引用标记，不应承载会话窃取、云元数据、本地文件读取或 LFI 升级链。',
  },
  {
    id: 'sql-redis-misplacement',
    categoryPattern: /^SQL\/NoSQL注入$/,
    pattern: /Redis未授权|redis-cli|FLUSHALL|CONFIG\s+SET|authorized_keys|crontab/i,
    message: 'Redis 服务暴露不属于 SQL/NoSQL 注入，应归入中间件与服务暴露或 SSRF-to-Redis 的对应条目。',
  },
];

const collectSemanticPlacementIssues = payload => {
  const content = JSON.stringify(payload);
  const category = text(payload.category);
  return semanticPlacementRules
    .filter(rule => {
      if (rule.payloadIds && !rule.payloadIds.has(payload.id)) return false;
      if (rule.categoryPattern && !rule.categoryPattern.test(category)) return false;
      return rule.pattern.test(content);
    })
    .map(rule => ({
      rule: rule.id,
      message: rule.message,
      match: content.match(rule.pattern)?.[0] || '',
    }));
};

const templateChainResiduePattern = /在授权靶场中先确认当前条目关注的是|从正常业务流程出发|只使用实验标记、只读响应、日志或时间线|把证据映射到|In an authorized lab, confirm this item focuses on|Start from the normal workflow|Use only lab markers, read-only responses|Map evidence to|确认授权资产与账号边界|复制标准 Payload 建立基线|梳理身份与权限边界|复制标准请求 Payload|定位执行入口|Locate execution sink/i;

const hasLocalizedEnglishResidue = step => {
  const titleZh = step?.title?.zh || '';
  const titleEn = step?.title?.en || '';
  const descriptionZh = step?.description?.zh || '';
  const descriptionEn = step?.description?.en || '';
  return (
    (titleZh && titleZh === titleEn && hasHan(titleEn)) ||
    (descriptionZh && descriptionZh === descriptionEn && hasHan(descriptionEn))
  );
};

const collectTemplateChainResidueIssues = payload => {
  const issues = [];
  asList(payload.attackChain).forEach((step, index) => {
    const content = [text(step.title), text(step.description), String(step.payload || '')].filter(Boolean).join('\n');
    const match = content.match(templateChainResiduePattern);
    if (match) {
      issues.push({
        area: 'attackChain',
        index,
        title: text(step.title),
        match: match[0],
      });
    }
    if (hasLocalizedEnglishResidue(step)) {
      issues.push({
        area: 'attackChain',
        index,
        title: text(step.title),
        match: 'localized attack-chain English residue',
      });
    }
  });
  return issues;
};

const sensitivePathPattern = /\/etc\/passwd|\/etc\/shadow|\/root\/\.ssh|\/var\/www/i;
const redisWritePattern = /CONFIG\s*SET|config%20set|(?:^|\n)[^\n]*(?:SLAVEOF|REPLICAOF)\b|redis-rogue|authorized_keys\s*>>|>\s*[^\n]*authorized_keys/i;
const webshellPattern = /<\?php[\s\S]{0,180}(?:\beval\s*\(|\bassert\s*\(|\bsystem\s*\(|\bexec\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|fsockopen\s*\(|base64_decode\s*\(|call_user_func\s*\(|`|\$_(?:GET|POST|REQUEST))|Runtime\.getRuntime\(\)\.exec|new\s+java\.lang\.ProcessBuilder|ProcessBuilder\([^)]*cmd|EXEC(?:UTE)?\s+(?:master\.\.)?xp_cmdshell/i;
const jwtForeignPattern = /redirect_uri=|code_verifier|response_type=|grant_type=|<saml|<Response><Assertion|SubjectConfirmationData|SignatureMethod|CONFIG\s*SET|SLAVEOF|REPLICAOF|\/etc\/passwd|<\?php/i;
const hardcodedVariableRules = [
  ['target_ip', /(?<!\{)\btarget_ip\b(?!\})/i],
  ['attacker_ip', /(?<!\{)\battacker_ip\b(?!\})/i],
  ['attacker.test', /\battacker\.test\b/i],
  ['attacker.com', /\battacker\.com\b/i],
  ['domain.com', /\bdomain\.com\b/i],
  ['DC_IP', /(?<!\{)\bDC_IP\b(?!\})/],
  ['DC_NAME', /(?<!\{)\bDC_NAME\b(?!\})/],
  ['CA_NAME', /(?<!\{)\bCA_NAME\b(?!\})/],
  ['CA_SERVER', /(?<!\{)\bCA_SERVER\b(?!\})/],
];
const safeAuditCommandPattern = /(?:credential-audit|kerberos-audit|remote-management-audit|persistence-audit|egress-audit|proxy-audit|dns-egress|callback-audit|readonly-audit|template-audit|include-audit|rce-lab|framework-audit|file-audit|database-audit|network-policy-audit|telemetry-audit|identity-audit|browser-audit|csrf-audit|command-audit|xxe-audit|supply-chain-audit):\/\/|(?:lesson|lateral-boundary|credential-audit|credential-boundary|persistence-audit)=|expected=|log_field=/i;
const operationalCommandRiskRules = [
  ['credential-tool', /mimikatz|sekurlsa|lsadump|DCSync|kerberoast|asreproast|GetNPUsers|GetUserSPNs|LaZagne|procdump|comsvcs\.dll|ntdsutil|vssadmin|reg\s+save\s+HKLM\\(?:SAM|SYSTEM|SECURITY)|hashcat|john\s|secretsdump|certipy\s+(?:find|req|auth|template)|(?:smbmap|smbclient|crackmapexec|netexec)\s+[^\n]*(?:-p\s+password|-H\s+NTHASH|user%password)|(?:noPac|NoAuth)\.py[^\n]*(?:user:password|-p\s+pass)|New-MachineAccount/i],
  ['ticket-forgery', /golden\s*ticket|silver\s*ticket|kerberos::golden|ticketer\.py|Rubeus(?:\.exe)?\s+(?:s4u|asktgt|asktgs|ptt|kerberoast|asreproast)/i],
  ['remote-exec', /PsExec|psexec\.py|wmiexec\.py|wmic\s+.*process\s+call\s+create|Invoke-WMIExec|evil-winrm|winrs\s+-r|sc\s+\\[^\s]+\s+create|schtasks\s+\/create\s+\/S|atexec\.py|smbexec\.py|dcomexec\.py|crackmapexec.*--exec|netexec.*--exec|PrintSpoofer|RoguePotato|JuicyPotato|GodPotato|(?:noPac|NoAuth)\.py[^\n]*(?:-shell|-command)/i],
  ['persistence', /schtasks\s+\/create|reg\s+add\s+.*\\Run|New-LocalUser|net\s+user\s+.*\/add|net\s+localgroup\s+administrators|sc\s+create|wmic\s+.*eventconsumer|Set-ItemProperty.*Run|backdoor|skeleton\s*key|sidHistory/i],
  ['reverse-shell', /reverse\s+shell|bash\s+-i|nc\s+.*-e|ncat\s+.*-e|powershell\s+-enc|Invoke-PowerShellTcp|\/dev\/tcp|meterpreter/i],
  ['remote-download-exec', /IEX\s*\(|DownloadString|downloadString|curl\s+[^\n|;&]+(?:\|\s*(?:bash|sh)|shell\.sh)|wget\s+[^\n|;&]+(?:\|\s*(?:bash|sh)|shell\.sh)|ysoserial[^\n]*(?:curl|bash|\/dev\/tcp)|http:\/\/attacker\/[^\s'"]+\.ps1/i],
  ['forced-auth-relay', /ntlmrelayx|Responder\s+-|mitm6|PetitPotam|petitpotam\.py|printerbug|coerce/i],
  ['broad-scanner', /masscan|nmap\s+[^\n]*(?:\/24|-p-|--top-ports|--rate)|hydra|ffuf|gobuster|dirsearch|wpscan/i],
  ['template-exec', /os\.popen\(|__import__\(['"]os['"]\)|IO\.popen\(|subprocess[^\n]{0,80}check_output|getattr\(__import__\(["']os["']\),["']popen["']\)/i],
  ['query-cmd', /[?&](?:cmd|c)=(?:id|whoami|cat(?:\s|%20)|bash|sh(?:\s|%20)|powershell)/i],
  ['tunnel-exposure', /frpc?(?:\.exe)?\s|chisel(?:\.exe)?\s|ligolo|reGeorg|venom(?:\.exe)?\s|ew_for|ngrok(?:\.exe)?\s|socks\s/i],
  ['encoded-shell', /powershell\s+-e\b|BASE64_CMD|meterpreter|reverse_tcp/i],
  ['destructive-or-exfil', /rm\s+-rf|del\s+\/f|rmdir\s+\/s|copy\s+.*\\ntds\.dit|download\s+.*ntds|exfil|dump\s+password/i],
];

const operationalCommandRisks = command => {
  const value = String(command || '');
  if (!value || safeAuditCommandPattern.test(value)) return [];
  return operationalCommandRiskRules.filter(([, pattern]) => pattern.test(value)).map(([id]) => id);
};

const webExecutionResidueRules = [
  ['php-webshell', /<\?(?:php|=)[\s\S]{0,520}(?:\$_(?:GET|POST|REQUEST)|preg_replace\s*\([^)]*\/e|create_function\s*\(|array_map\s*\(\s*\$_|call_user_func\s*\(\s*\$_|eval\s*\(|assert\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(|base64_decode\s*\(|fsockopen\s*\(|`)/i],
  ['php-dynamic-call', /(?:preg_replace\s*\([^)]*\/e|create_function\s*\(|array_map\s*\(\s*\$_|call_user_func\s*\(\s*\$_|call_user_func\s*\(\s*['"][^'"]*sys|popen\s*\(\s*['"]whoami|proc_open\s*\(\s*['"]whoami|ReflectionFunction\s*\(\s*['"]system|sh['"]\s*\.\s*['"]ell|sys['"]\s*\.\s*['"]tem|\$_GET\s*\[\s*['"]cmd['"]|\$_POST\s*\[\s*cmd|\$_POST\s*\[\s*['"]cmd['"]|\$_GET\s*\[\s*['"]func['"])/i],
  ['jsp-aspx-webshell', /<%[\s\S]{0,720}(?:request\.getParameter\s*\(\s*["']cmd["']|ProcessBuilder|Runtime\.getRuntime|cmd\.exe|\/bin\/sh|ProcessStartInfo|Response\.Write\s*\([^)]*Request)/i],
  ['interpreter-config', /\b(?:AddHandler|SetHandler|AddType\s+application\/x-httpd-php|php_value\s+auto_prepend_file|auto_prepend_file|user_ini\.filename)\b/i],
  ['template-exec', /(?:Runtime\.getRuntime\s*\(\)|T\(java\.lang\.Runtime\)\.getRuntime|Class\)\.forName\(["']java\.lang\.Runtime|getMethod\(["']exec|javax\.script\.ScriptEngineManager|ProcessBuilder|freemarker\.template\.utility\.Execute|ObjectConstructor[\s\S]{0,160}Runtime|IO\.popen|os\.popen|subprocess[^\n]{0,120}check_output|__import__\(["']os["']\))/i],
  ['deserialization-exec', /(?:ysoserial|gASV[A-Za-z0-9+/=]{20,}|posix[\s\S]{0,120}system|O:\d+:"[^"]+"[\s\S]{0,180}\b(?:cmd|system|exec|assert)\b)/i],
  ['upload-exec-polyglot', /(?:shell\.php|filename="[^"]+\.(?:php|jsp|aspx|phtml)"[\s\S]{0,420}<\?|copy\s+\S+\/b\s+\+\s+shell\.php|cat\s+\S+\s+shell\.php|cmd=whoami|cmd=id)/i],
  ['sql-os-or-file', /\b(?:xp_cmdshell|INTO\s+OUTFILE|LOAD_FILE\s*\(|secure_file_priv|UTL_HTTP|DBMS_SCHEDULER|COPY\s+\([^)]+\)\s+TO\s+PROGRAM)\b/i],
  ['xxe-expect-exec', /(?:expect:\/\/(?:id|whoami|cat|\/bin\/sh|echo|uname)|<!ENTITY[\s\S]{0,180}SYSTEM\s+["']expect:\/\/)/i],
  ['command-separator-exec', /(?:^|\n)\s*(?:[;&|`]|&&|\|\||\$\(|%0a|%26%26|%7c%7c|\$\{IFS\})(?:[^\n]{0,40})\b(?:id|whoami|sleep|timeout|ping)\b|(?:^|\n)\s*(?:sleep\s+\d+|timeout\s+\/T\s+\d+|ping\s+-(?:c|n)\s+\d+)/i],
  ['browser-hook', /(?:hook\.js|BeEF|createElement\s*\(\s*['"]script|import\s*\(\s*['"]\/\/|<script\s+src=["']?(?:https?:)?\/\/\{ATTACKER_HOST\}|127\.0\.0\.1:3000\/hook\.js)/i],
  ['browser-cookie-read', /(?:document\.cookie|document\s*\[\s*['"]cookie['"]\s*\]|document\s*\[\s*k\s*\]|["']coo["']\s*\+\s*["']kie["']|btoa\s*\(\s*document\.cookie|dataset\.cookie|alert\s*\(\s*document\.cookie)/i],
  ['browser-key-capture', /(?:addEventListener\s*\(\s*["']keydown|onkeypress|onkeydown|event\.key|log\?key=)/i],
  ['credentialed-fetch', /(?:fetch\s*\([\s\S]{0,260}credentials\s*:\s*["']include|XMLHttpRequest[\s\S]{0,160}withCredentials)/i],
  ['supply-build-inject', /(?:node\s+inject\.js|fs\.readdirSync\s*\(\s*['"]\.\/build|build\/static\/js|postinstall[\s\S]{0,120}(?:curl|node|powershell|bash))/i],
];

const webExecutionResidueRisks = value => {
  const textValue = String(value || '');
  if (!textValue || safeAuditCommandPattern.test(textValue)) return [];
  return webExecutionResidueRules.filter(([, pattern]) => pattern.test(textValue)).map(([id]) => id);
};

const collectSuspiciousCommandIssues = payload => {
  const issues = [];
  const category = text(payload.category);
  const jwtEntry = category.includes('JWT') || String(payload.id || '').startsWith('jwt-');
  for (const area of commandAreas) {
    asList(payload[area]).forEach((entry, index) => {
      const command = String(entry.command || '');
      if (!command) return;
      const matches = [];
      if (command.length > 5000) matches.push('oversized-command-dictionary');
      if (sensitivePathPattern.test(command)) matches.push('real-sensitive-path');
      if (redisWritePattern.test(command)) matches.push('redis-write-chain');
      if (webshellPattern.test(command)) matches.push('webshell-or-os-exec-chain');
      if (jwtEntry && jwtForeignPattern.test(command)) matches.push('jwt-cross-domain-content');
      if (!matches.length) return;
      issues.push({
        area,
        index,
        title: text(entry.title),
        matches,
        length: command.length,
        preview: command.slice(0, 220),
      });
    });
  }
  return issues;
};

const collectOperationalCommandRiskIssues = payload => {
  const issues = [];
  for (const area of commandAreas) {
    asList(payload[area]).forEach((entry, index) => {
      const risks = operationalCommandRisks(entry.command);
      if (!risks.length) return;
      issues.push({
        area,
        index,
        title: text(entry.title),
        risks,
        command: String(entry.command || '').slice(0, 260),
      });
    });
  }
  return issues;
};

const collectWebExecutionResidueIssues = payload => {
  const issues = [];
  for (const area of commandAreas) {
    asList(payload[area]).forEach((entry, index) => {
      const risks = webExecutionResidueRisks(entry.command);
      if (!risks.length) return;
      issues.push({
        area,
        index,
        title: text(entry.title),
        risks,
        command: String(entry.command || '').slice(0, 260),
      });
    });
  }
  asList(payload.attackChain).forEach((step, index) => {
    const risks = webExecutionResidueRisks(step.payload);
    if (!risks.length) return;
    issues.push({
      area: 'attackChain',
      index,
      title: text(step.title),
      risks,
      command: String(step.payload || '').slice(0, 260),
    });
  });
  return issues;
};

const collectNavRefs = (items, key, refs = new Set()) => {
  for (const item of asList(items)) {
    if (item[key]) refs.add(item[key]);
    collectNavRefs(item.children, key, refs);
  }
  return refs;
};

const collectNavRefRows = (items, key, path = []) => {
  const rows = [];
  for (const item of asList(items)) {
    const name = text(item.name) || item.id || 'unnamed';
    const itemPath = [...path, name];
    if (item[key]) rows.push({ id: item.id, name, ref: item[key], path: itemPath.join(' > ') });
    rows.push(...collectNavRefRows(item.children, key, itemPath));
  }
  return rows;
};

const collectDuplicateNavRefs = (items, key) => {
  const groups = new Map();
  for (const row of collectNavRefRows(items, key)) {
    const list = groups.get(row.ref) || [];
    list.push(row);
    groups.set(row.ref, list);
  }
  return [...groups.entries()]
    .filter(([, refs]) => refs.length > 1)
    .map(([ref, refs]) => ({ ref, refs }));
};

const collectStringEntries = (value, path = '') => {
  if (typeof value === 'string') return [{ path, value }];
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectStringEntries(item, `${path}[${index}]`));
  }
  return Object.entries(value).flatMap(([key, item]) => collectStringEntries(item, path ? `${path}.${key}` : key));
};

const collectEnglishEntries = (value, path = '') => {
  if (!value || typeof value !== 'object') return [];
  const rows = [];
  if (typeof value.en === 'string') rows.push({ path: path ? `${path}.en` : 'en', value: value.en });
  if (Array.isArray(value)) {
    rows.push(...value.flatMap((item, index) => collectEnglishEntries(item, `${path}[${index}]`)));
  } else {
    rows.push(...Object.entries(value).flatMap(([key, item]) => {
      if (key === 'en') return [];
      return collectEnglishEntries(item, path ? `${path}.${key}` : key);
    }));
  }
  return rows;
};

const collectCommandIssues = payload => {
  const issues = [];
  for (const area of commandAreas) {
    asList(payload[area]).forEach((entry, index) => {
      const lines = String(entry.command || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
      const proseLines = lines.filter(line => hasHan(line) && !likelyPayloadLine(line));
      const mixedLines = lines.length > 1 && proseLines.length > 0 && proseLines.length < lines.length;
      if (proseLines.length) {
        issues.push({
          type: mixedLines ? 'mixed-prose-in-command' : 'prose-command',
          area,
          index,
          title: text(entry.title),
          proseLines,
          command: entry.command,
        });
      }
    });
  }
  return issues;
};

const normalizeSignature = value => String(value || '')
  .replace(/\{[A-Z_]+\}/g, '{VAR}')
  .replace(/https?:\/\/[^\s"'<>]+/gi, 'http://example')
  .replace(/\s+/g, ' ')
  .trim();

const attackChainSignature = payload => asList(payload.attackChain)
  .map(step => [
    text(step.title),
    text(step.description),
  ].map(normalizeSignature).join(' :: '))
  .filter(Boolean)
  .join(' || ');

const tutorialFields = ['overview', 'vulnerability', 'exploitation', 'mitigation'];

const tutorialSignature = tutorial => {
  if (!tutorial || typeof tutorial !== 'object') return '';
  return tutorialFields
    .map(field => normalizeSignature(text(tutorial[field])))
    .filter(Boolean)
    .join(' || ');
};

const analysisSignature = analysis => {
  if (!analysis || typeof analysis !== 'object') return '';
  return normalizeSignature(text(analysis));
};

const collectShortTutorialFields = payload => {
  if (!payload.tutorial || typeof payload.tutorial !== 'object') return [];
  return tutorialFields
    .map(field => ({
      field,
      value: text(payload.tutorial[field]),
    }))
    .filter(item => normalizeSignature(item.value).length < 34);
};

const collectFrontendVariableKeys = async () => {
  const source = await readFile('src/data/globalVariables.ts', 'utf8');
  return new Set([...source.matchAll(/\{\s*key:\s*['"]([A-Z0-9_]+)['"]/g)].map(match => match[1]));
};

const collectDataStoreMapKeys = async (mapName, nextAnchor) => {
  const source = await readFile('server/data-store.mjs', 'utf8');
  const start = source.indexOf(`const ${mapName} = new Map([`);
  const end = source.indexOf(nextAnchor, start);
  if (start < 0 || end < 0) return [];
  const section = source.slice(start, end);
  return [...section.matchAll(/\n\s*\['([^']+)'\s*,/g)].map(match => match[1]);
};

const collectSupplementLayerKeys = async (layerName, nextAnchor) => {
  const source = await readFile('server/data-store.mjs', 'utf8');
  const start = source.indexOf(`const ${layerName} = [`);
  const end = source.indexOf(nextAnchor, start);
  if (start < 0 || end < 0) return [];
  const section = source.slice(start, end);
  return [...section.matchAll(/\n\s*\['([^']+)'\s*,/g)].map(match => match[1]);
};

const collectPayloadSpecificExecutionSupplementKeys = () => collectDataStoreMapKeys(
  'payloadSpecificExecutionSupplementEntries',
  'const additionalPayloadSpecificExecutionSupplementEntries'
);

const collectPayloadSpecificWafSupplementKeys = () => collectDataStoreMapKeys(
  'payloadSpecificWafSupplementEntries',
  'const additionalPayloadSpecificWafSupplementEntries'
);

const collectPayloadSpecificExecutionSupplementLayerKeys = () => collectSupplementLayerKeys(
  'additionalPayloadSpecificExecutionSupplementEntries',
  'for (const [payloadId, entries] of additionalPayloadSpecificExecutionSupplementEntries)'
);

const collectPayloadSpecificWafSupplementLayerKeys = () => collectSupplementLayerKeys(
  'additionalPayloadSpecificWafSupplementEntries',
  'for (const [payloadId, entries] of additionalPayloadSpecificWafSupplementEntries)'
);

const collectExcludedPublicPayloadIds = async () => {
  const source = await readFile('server/data-store.mjs', 'utf8');
  const start = source.indexOf('const excludedPublicPayloadIds = new Set([');
  const end = source.indexOf(']);', start);
  if (start < 0 || end < 0) return new Set();
  return new Set([...source.slice(start, end).matchAll(/'([^']+)'/g)].map(match => match[1]));
};

const collectCommandVariables = payload => {
  const rows = [];
  const variablePattern = /(?<!\\u)\{([A-Z_][A-Z0-9_]*)\}/g;
  for (const area of commandAreas) {
    asList(payload[area]).forEach((entry, index) => {
      for (const match of String(entry.command || '').matchAll(variablePattern)) {
        rows.push({
          key: match[1],
          area,
          index,
          title: text(entry.title),
        });
      }
    });
  }
  asList(payload.attackChain).forEach((step, index) => {
    for (const match of String(step.payload || '').matchAll(variablePattern)) {
      rows.push({
        key: match[1],
        area: 'attackChain',
        index,
        title: text(step.title),
      });
    }
  });
  return rows;
};

const compactPayload = payload => ({
  id: payload.id,
  name: text(payload.name),
  category: text(payload.category),
});

const sample = (items, limit = 60) => items.slice(0, limit);

const main = async () => {
  const defaults = await loadDefaultData();
  const raw = includeLegacySource
    ? await (await import('./default-seed-source.mjs')).loadRawSeedData()
    : defaults;
  const frontendVariableKeys = await collectFrontendVariableKeys();
  const executionSupplementKeys = await collectPayloadSpecificExecutionSupplementKeys();
  const supplementKeys = await collectPayloadSpecificWafSupplementKeys();
  const executionSupplementLayerKeys = await collectPayloadSpecificExecutionSupplementLayerKeys();
  const supplementLayerKeys = await collectPayloadSpecificWafSupplementLayerKeys();
  const excludedPublicPayloadIds = await collectExcludedPublicPayloadIds();
  const payloads = asList(defaults.payloads);
  const payloadIds = new Set(payloads.map(item => item.id));
  const rawPayloadIds = new Set(asList(raw.payloads).map(item => item.id));
  const navRefs = collectNavRefs(defaults.navigation, 'payloadId');
  const rawNavRefs = collectNavRefs(raw.navigation, 'payloadId');
  const toolRefs = collectNavRefs(defaults.toolNavigation, 'toolId');
  const tools = asList(defaults.tools);
  const toolIds = new Set(tools.map(item => item.id));
  const rawToolIds = new Set(asList(raw.tools).map(item => item.id));
  const rawToolRefs = collectNavRefs(raw.toolNavigation, 'toolId');

  const missingPayloadRefs = [...navRefs].filter(id => !payloadIds.has(id));
  const missingRawPayloadRefs = [...rawNavRefs].filter(id => !hasResolvedPayload(rawPayloadIds, payloadIds, id));
  const rawRefsResolvedByDefaults = [...rawNavRefs]
    .filter(id => !rawPayloadIds.has(resolvedPayloadId(id)) && payloadIds.has(resolvedPayloadId(id)))
    .map(id => ({ from: id, to: resolvedPayloadId(id) }));
  const aliasedRawPayloadRefs = [...rawNavRefs]
    .filter(id => rawPayloadRefAliases.has(id) && rawPayloadIds.has(rawPayloadRefAliases.get(id)))
    .map(id => ({ from: id, to: rawPayloadRefAliases.get(id) }));
  const missingToolRefs = [...toolRefs].filter(id => !toolIds.has(id));
  const missingRawToolRefs = [...rawToolRefs].filter(id => !rawToolIds.has(id));
  const duplicateRawPayloadNavRefs = collectDuplicateNavRefs(raw.navigation, 'payloadId');
  const duplicatePublicPayloadNavRefs = collectDuplicateNavRefs(defaults.navigation, 'payloadId');
  const duplicateRawToolNavRefs = collectDuplicateNavRefs(raw.toolNavigation, 'toolId');
  const duplicatePublicToolNavRefs = collectDuplicateNavRefs(defaults.toolNavigation, 'toolId');
  const groupDuplicateKeys = keys => [...keys.reduce((groups, key) => {
    const list = groups.get(key) || [];
    list.push(key);
    groups.set(key, list);
    return groups;
  }, new Map()).entries()]
    .filter(([, refs]) => refs.length > 1)
    .map(([key, refs]) => ({ key, count: refs.length }));
  const allExecutionSupplementKeys = [...executionSupplementKeys, ...executionSupplementLayerKeys];
  const allSupplementKeys = [...supplementKeys, ...supplementLayerKeys];
  const unusedExecutionSupplementKeys = allExecutionSupplementKeys.filter(key => !payloadIds.has(key) && !excludedPublicPayloadIds.has(key));
  const duplicateExecutionSupplementKeys = groupDuplicateKeys(executionSupplementKeys);
  const unusedWafSupplementKeys = allSupplementKeys.filter(key => !payloadIds.has(key) && !excludedPublicPayloadIds.has(key));
  const duplicateWafSupplementKeys = groupDuplicateKeys(supplementKeys);

  const duplicateCommandMap = new Map();
  const duplicateAttackChainMap = new Map();
  const duplicateTutorialMap = new Map();
  const duplicateAnalysisMap = new Map();
  for (const payload of payloads) {
    for (const area of commandAreas) {
      for (const entry of asList(payload[area])) {
        const normalized = String(entry.command || '').trim().replace(/\s+/g, ' ');
        if (!normalized) continue;
        const list = duplicateCommandMap.get(normalized) || [];
        list.push({ id: payload.id, title: text(entry.title), area });
        duplicateCommandMap.set(normalized, list);
      }
    }

    const chainSignature = attackChainSignature(payload);
    if (chainSignature) {
      const list = duplicateAttackChainMap.get(chainSignature) || [];
      list.push(compactPayload(payload));
      duplicateAttackChainMap.set(chainSignature, list);
    }

    const guideSignature = tutorialSignature(payload.tutorial);
    if (guideSignature) {
      const list = duplicateTutorialMap.get(guideSignature) || [];
      list.push(compactPayload(payload));
      duplicateTutorialMap.set(guideSignature, list);
    }

    const payloadAnalysisSignature = analysisSignature(payload.analysis);
    if (payloadAnalysisSignature) {
      const list = duplicateAnalysisMap.get(payloadAnalysisSignature) || [];
      list.push(compactPayload(payload));
      duplicateAnalysisMap.set(payloadAnalysisSignature, list);
    }
  }

  const commandIssues = [];
  const workflowCommandIssues = [];
  const singleWafPayloads = [];
  const likelyTools = [];
  const missingAttackChain = [];
  const missingWafBypass = [];
  const missingAnalysis = [];
  const missingReferences = [];
  const shortTutorials = [];
  const undefinedVariableMap = new Map();
  const retiredEdrSamples = [];
  const mojibakeSamples = [];
  const localizedEnglishSamples = [];
  const machineTranslatedEnglishSamples = [];
  const semanticPlacementIssues = [];
  const templateChainResidueIssues = [];
  const suspiciousCommandIssues = [];
  const operationalCommandRiskIssues = [];
  const webExecutionResidueIssues = [];
  const hardcodedVariableIssues = [];

  for (const payload of payloads) {
    const category = text(payload.category);
    const areaIssues = collectCommandIssues(payload);
    if (areaIssues.length) commandIssues.push({ ...compactPayload(payload), issues: areaIssues });
    const workflowIssues = collectWorkflowCommandIssues(payload);
    if (workflowIssues.length) workflowCommandIssues.push({ ...compactPayload(payload), issues: workflowIssues });
    const metadataIssues = collectHighRiskMetadataIssues(payload);
    if (metadataIssues.length) {
      workflowCommandIssues.push({
        ...compactPayload(payload),
        issues: metadataIssues.map(issue => ({
          ...issue,
          workflowLines: [issue.metadata],
          command: issue.metadata,
        })),
      });
    }
    const placementIssues = collectSemanticPlacementIssues(payload);
    if (placementIssues.length) {
      semanticPlacementIssues.push({ ...compactPayload(payload), issues: placementIssues });
    }
    const templateIssues = collectTemplateChainResidueIssues(payload);
    if (templateIssues.length) {
      templateChainResidueIssues.push({ ...compactPayload(payload), issues: templateIssues });
    }
    const suspiciousIssues = collectSuspiciousCommandIssues(payload);
    if (suspiciousIssues.length) {
      suspiciousCommandIssues.push({ ...compactPayload(payload), issues: suspiciousIssues });
    }
    const operationalIssues = collectOperationalCommandRiskIssues(payload);
    if (operationalIssues.length) {
      operationalCommandRiskIssues.push({ ...compactPayload(payload), issues: operationalIssues });
    }
    const webResidueIssues = collectWebExecutionResidueIssues(payload);
    if (webResidueIssues.length) {
      webExecutionResidueIssues.push({ ...compactPayload(payload), issues: webResidueIssues });
    }

    const commands = commandAreas.flatMap(area => asList(payload[area]).map(entry => entry.command));
    const toolLikeCommands = commands.filter(likelyToolCommand).length;
    const commandTotal = commands.length || 1;
    if (toolCategoryNames.has(category) || toolLikeCommands / commandTotal >= 0.6) {
      likelyTools.push({
        ...compactPayload(payload),
        toolLikeCommands,
        commandTotal,
        firstCommand: String(commands.find(Boolean) || '').slice(0, 180),
      });
    }

    if (!asList(payload.attackChain).length) missingAttackChain.push(compactPayload(payload));
    if (!asList(payload.wafBypass).length) missingWafBypass.push(compactPayload(payload));
    if (asList(payload.wafBypass).length === 1) singleWafPayloads.push(compactPayload(payload));
    if (!payload.analysis) missingAnalysis.push(compactPayload(payload));
    if (!asList(payload.references).length) missingReferences.push(compactPayload(payload));

    const shortFields = collectShortTutorialFields(payload);
    if (shortFields.length) shortTutorials.push({ ...compactPayload(payload), fields: shortFields });

    for (const variable of collectCommandVariables(payload)) {
      if (frontendVariableKeys.has(variable.key) || allowedLiteralVariables.has(variable.key)) continue;
      const list = undefinedVariableMap.get(variable.key) || [];
      list.push({ ...compactPayload(payload), ...variable });
      undefinedVariableMap.set(variable.key, list);
    }

    const allText = collectStringEntries(payload);
    const hardcodedMatches = [];
    for (const entry of allText) {
      const matches = hardcodedVariableRules.filter(([, pattern]) => pattern.test(entry.value)).map(([id]) => id);
      if (matches.length) hardcodedMatches.push({ path: entry.path, matches, value: entry.value.slice(0, 180) });
    }
    if (hardcodedMatches.length) {
      hardcodedVariableIssues.push({ ...compactPayload(payload), issues: hardcodedMatches.slice(0, 12) });
    }
    const edrHit = allText.find(entry => retiredEdrPattern.test(entry.value));
    if (edrHit) retiredEdrSamples.push({ ...compactPayload(payload), path: edrHit.path, value: edrHit.value.slice(0, 180) });
    const mojibakeHit = allText.find(entry => mojibakePattern.test(entry.value));
    if (mojibakeHit) mojibakeSamples.push({ ...compactPayload(payload), path: mojibakeHit.path, value: mojibakeHit.value.slice(0, 180) });
    const englishEntries = collectEnglishEntries(payload);
    const localizedEnglishHits = englishEntries.filter(entry => hasHan(entry.value));
    if (localizedEnglishHits.length) {
      localizedEnglishSamples.push({
        ...compactPayload(payload),
        count: localizedEnglishHits.length,
        samples: localizedEnglishHits.slice(0, 8).map(entry => ({
          path: entry.path,
          value: entry.value.slice(0, 180),
        })),
      });
    }
    const englishHit = englishEntries.find(entry => machineTranslatedEnglishPattern.test(entry.value));
    if (englishHit) machineTranslatedEnglishSamples.push({ ...compactPayload(payload), path: englishHit.path, value: englishHit.value.slice(0, 180) });
  }

  const duplicateCommands = [...duplicateCommandMap.entries()]
    .filter(([, refs]) => refs.length > 1)
    .map(([command, refs]) => ({ command: command.slice(0, 220), count: refs.length, refs: refs.slice(0, 8) }));

  const duplicateAttackChains = [...duplicateAttackChainMap.entries()]
    .filter(([, refs]) => refs.length > 1)
    .map(([signature, refs]) => ({ signature: signature.slice(0, 260), count: refs.length, refs: refs.slice(0, 12) }));

  const duplicateTutorials = [...duplicateTutorialMap.entries()]
    .filter(([, refs]) => refs.length > 1)
    .map(([signature, refs]) => ({ signature: signature.slice(0, 260), count: refs.length, refs: refs.slice(0, 12) }));

  const duplicateAnalyses = [...duplicateAnalysisMap.entries()]
    .filter(([, refs]) => refs.length > 1)
    .map(([signature, refs]) => ({ signature: signature.slice(0, 260), count: refs.length, refs: refs.slice(0, 12) }));

  const undefinedVariables = [...undefinedVariableMap.entries()]
    .map(([key, refs]) => ({ key, count: refs.length, refs: refs.slice(0, 12) }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));

  const byCategory = new Map();
  for (const payload of payloads) {
    const category = text(payload.category);
    byCategory.set(category, (byCategory.get(category) || 0) + 1);
  }

  const report = {
    totals: {
      payloads: payloads.length,
      tools: tools.length,
      payloadNavRefs: navRefs.size,
      toolNavRefs: toolRefs.size,
      commandIssuePayloads: commandIssues.length,
      workflowCommandPayloads: workflowCommandIssues.length,
      workflowCommandEntries: workflowCommandIssues.reduce((total, item) => total + item.issues.length, 0),
      likelyToolPayloads: likelyTools.length,
      duplicateCommandGroups: duplicateCommands.length,
      duplicateAttackChainGroups: duplicateAttackChains.length,
      duplicateTutorialGroups: duplicateTutorials.length,
      duplicateAnalysisGroups: duplicateAnalyses.length,
      duplicateRawPayloadNavRefs: duplicateRawPayloadNavRefs.length,
      duplicatePublicPayloadNavRefs: duplicatePublicPayloadNavRefs.length,
      duplicateRawToolNavRefs: duplicateRawToolNavRefs.length,
      duplicatePublicToolNavRefs: duplicatePublicToolNavRefs.length,
      unusedExecutionSupplementKeys: unusedExecutionSupplementKeys.length,
      duplicateExecutionSupplementKeyGroups: duplicateExecutionSupplementKeys.length,
      unusedWafSupplementKeys: unusedWafSupplementKeys.length,
      duplicateWafSupplementKeyGroups: duplicateWafSupplementKeys.length,
      missingAttackChain: missingAttackChain.length,
      missingWafBypass: missingWafBypass.length,
      singleWafPayloads: singleWafPayloads.length,
      missingAnalysis: missingAnalysis.length,
      missingReferences: missingReferences.length,
      shortTutorials: shortTutorials.length,
      undefinedVariableGroups: undefinedVariables.length,
      retiredEdrSamples: retiredEdrSamples.length,
      mojibakeSamples: mojibakeSamples.length,
      localizedEnglishPayloads: localizedEnglishSamples.length,
      localizedEnglishFields: localizedEnglishSamples.reduce((total, item) => total + item.count, 0),
      machineTranslatedEnglishSamples: machineTranslatedEnglishSamples.length,
      semanticPlacementIssues: semanticPlacementIssues.length,
      templateChainResiduePayloads: templateChainResidueIssues.length,
      suspiciousCommandPayloads: suspiciousCommandIssues.length,
      suspiciousCommandEntries: suspiciousCommandIssues.reduce((total, item) => total + item.issues.length, 0),
      operationalRiskPayloads: operationalCommandRiskIssues.length,
      operationalRiskEntries: operationalCommandRiskIssues.reduce((total, item) => total + item.issues.length, 0),
      webExecutionResiduePayloads: webExecutionResidueIssues.length,
      webExecutionResidueEntries: webExecutionResidueIssues.reduce((total, item) => total + item.issues.length, 0),
      hardcodedVariablePayloads: hardcodedVariableIssues.length,
    },
    categories: [...byCategory.entries()].sort((a, b) => b[1] - a[1]),
    aliasedRawPayloadRefs,
    rawRefsResolvedByDefaults,
    missingRawPayloadRefs,
    missingPayloadRefs,
    missingRawToolRefs,
    missingToolRefs,
    duplicateRawPayloadNavRefs,
    duplicatePublicPayloadNavRefs,
    duplicateRawToolNavRefs,
    duplicatePublicToolNavRefs,
    unusedExecutionSupplementKeys,
    duplicateExecutionSupplementKeys,
    unusedWafSupplementKeys,
    duplicateWafSupplementKeys,
    likelyToolPayloadSamples: sample(likelyTools, 80),
    qualitySamples: {
      missingAttackChain: sample(missingAttackChain),
      missingWafBypass: sample(missingWafBypass),
      missingAnalysis: sample(missingAnalysis),
      missingReferences: sample(missingReferences),
      shortTutorials: sample(shortTutorials, 60),
      mojibake: sample(mojibakeSamples, 40),
      localizedEnglish: sample(localizedEnglishSamples, 40),
      machineTranslatedEnglish: sample(machineTranslatedEnglishSamples, 40),
    },
    retiredEdrSamples: sample(retiredEdrSamples, 40),
    commandIssueSamples: sample(commandIssues, 60),
    workflowCommandSamples: sample(workflowCommandIssues, 80),
    semanticPlacementIssueSamples: sample(semanticPlacementIssues, 80),
    templateChainResidueSamples: sample(templateChainResidueIssues, 80),
    suspiciousCommandSamples: sample(suspiciousCommandIssues, 80),
    operationalCommandRiskSamples: sample(operationalCommandRiskIssues, 80),
    webExecutionResidueSamples: sample(webExecutionResidueIssues, 80),
    hardcodedVariableSamples: sample(hardcodedVariableIssues, 80),
    duplicateCommandSamples: sample(duplicateCommands, 40),
    duplicateAttackChainSamples: sample(duplicateAttackChains, 40),
    duplicateTutorialSamples: sample(duplicateTutorials, 40),
    duplicateAnalysisSamples: sample(duplicateAnalyses, 40),
    undefinedVariableSamples: sample(undefinedVariables, 40),
  };

  const summary = {
    totals: report.totals,
    topCategories: report.categories.slice(0, 12),
    structure: {
      missingPayloadRefs: report.missingPayloadRefs,
      missingToolRefs: report.missingToolRefs,
      duplicatePublicPayloadNavRefs: report.duplicatePublicPayloadNavRefs,
      duplicatePublicToolNavRefs: report.duplicatePublicToolNavRefs,
      unusedExecutionSupplementKeys: report.unusedExecutionSupplementKeys,
      duplicateExecutionSupplementKeys: report.duplicateExecutionSupplementKeys,
      unusedWafSupplementKeys: report.unusedWafSupplementKeys,
      duplicateWafSupplementKeys: report.duplicateWafSupplementKeys,
    },
    samples: {
      likelyToolPayloads: report.likelyToolPayloadSamples.slice(0, 8),
      missingWafBypass: report.qualitySamples.missingWafBypass.slice(0, 12),
      singleWafPayloads: sample(singleWafPayloads, 20),
      missingAttackChain: report.qualitySamples.missingAttackChain.slice(0, 12),
      workflowCommands: report.workflowCommandSamples.slice(0, 12),
      semanticPlacementIssues: report.semanticPlacementIssueSamples.slice(0, 12),
      templateChainResidue: report.templateChainResidueSamples.slice(0, 12),
      suspiciousCommands: report.suspiciousCommandSamples.slice(0, 12),
      operationalRisks: report.operationalCommandRiskSamples.slice(0, 12),
      webExecutionResidues: report.webExecutionResidueSamples.slice(0, 12),
      hardcodedVariables: report.hardcodedVariableSamples.slice(0, 12),
      shortTutorials: report.qualitySamples.shortTutorials.slice(0, 12),
      localizedEnglish: report.qualitySamples.localizedEnglish.slice(0, 8),
      machineTranslatedEnglish: report.qualitySamples.machineTranslatedEnglish.slice(0, 8),
      duplicateCommands: report.duplicateCommandSamples.slice(0, 8),
      duplicateAttackChains: report.duplicateAttackChainSamples.slice(0, 8),
      duplicateTutorials: report.duplicateTutorialSamples.slice(0, 8),
      duplicateAnalyses: report.duplicateAnalysisSamples.slice(0, 8),
      undefinedVariables: report.undefinedVariableSamples.slice(0, 12),
      retiredEdr: report.retiredEdrSamples,
    },
  };

  console.log(JSON.stringify(summaryMode ? summary : report, null, 2));

  if (
    missingPayloadRefs.length ||
    missingRawPayloadRefs.length ||
    missingToolRefs.length ||
    duplicateRawPayloadNavRefs.length ||
    duplicatePublicPayloadNavRefs.length ||
    duplicateRawToolNavRefs.length ||
    duplicatePublicToolNavRefs.length ||
    unusedExecutionSupplementKeys.length ||
    duplicateExecutionSupplementKeys.length ||
    unusedWafSupplementKeys.length ||
    duplicateWafSupplementKeys.length ||
    duplicateAnalyses.length ||
    commandIssues.length ||
    workflowCommandIssues.length ||
    semanticPlacementIssues.length ||
    templateChainResidueIssues.length ||
    suspiciousCommandIssues.length ||
    operationalCommandRiskIssues.length ||
    webExecutionResidueIssues.length ||
    hardcodedVariableIssues.length ||
    undefinedVariables.length ||
    localizedEnglishSamples.length ||
    machineTranslatedEnglishSamples.length ||
    retiredEdrSamples.length
  ) {
    process.exitCode = 1;
  }
};

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
