import { mkdir, rename, rm, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as sqlite from 'node:sqlite';
import { publicProjectRoute } from './project-attribution.mjs';

const { DatabaseSync } = sqlite;

const rootDir = fileURLToPath(new URL('..', import.meta.url));
const dataDir = resolve(process.env.PAYLOADER_DATA_DIR || join(rootDir, 'data'));
const dbFile = join(dataDir, 'payloader.sqlite');
const backupDir = join(dataDir, 'backups');
const defaultSeedDbFile = resolve(process.env.PAYLOADER_SEED_DB || join(rootDir, 'server', 'default-seed.sqlite'));
const defaultSeedSchemaVersion = '1';
const defaultSeedContentKind = 'curated-defaults';
const makeSeedArtifactId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

let db;
let dbInitialization;
let publicDataCache;
let storeGeneration = 0;
let mutationQueue = Promise.resolve();
let storeTestHooks = {};

const now = () => new Date().toISOString();
const json = value => JSON.stringify(value ?? null);
const parseJson = value => {
  if (typeof value !== 'string' || value.length === 0) return null;
  return JSON.parse(value);
};

const projectUrl = publicProjectRoute;

const protectedExternalUrl = 'https://xss.icu/';
const protectedXssToolId = 'xss-platform';
const protectedXssNavId = 'system-xss-platform';

const defaultSettings = {
  siteTitle: { zh: 'PAYLOADER', en: 'PAYLOADER' },
  siteSubtitle: { zh: '渗透测试辅助平台', en: 'Pentest Assistance Platform' },
  browserTitle: { zh: 'Payloader - 渗透测试辅助平台', en: 'Payloader - Pentest Assistance Platform' },
  logoIcon: '⚡',
  logoUrl: '',
  projectUrl,
};

const protectedXssPlatformTool = Object.freeze({
  id: protectedXssToolId,
  name: { zh: 'XSS 平台', en: 'XSS Platform' },
  description: { zh: 'Payloader 默认提供的 Xeye 平台入口。', en: 'Default Xeye platform entry provided by Payloader.' },
  category: { zh: '平台跳转', en: 'Platform Links' },
  commands: [],
  externalUrl: protectedExternalUrl,
  systemLocked: true,
  references: [protectedExternalUrl],
});
const protectedXssPlatformNavigation = Object.freeze({
  id: protectedXssNavId,
  name: { zh: 'XSS 平台', en: 'XSS Platform' },
  toolId: protectedXssToolId,
});
const systemToolIds = new Set([protectedXssToolId]);
const systemNavigationNodeIds = new Set([protectedXssNavId]);
const xeyeDisabledMetadataKey = 'xeye_platform_disabled';

const protectedStoreError = message => {
  const error = new Error(message);
  error.status = 403;
  return error;
};

const isObject = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const isText = value => (
  typeof value === 'string' ||
  Boolean(isObject(value) && typeof value.zh === 'string' && typeof value.en === 'string')
);
const toText = value => {
  const textValue = String(value ?? '').trim();
  return { zh: textValue, en: textValue };
};
const normalizeText = value => (isText(value) ? value : toText(value));
const isPlatform = value => value === 'windows' || value === 'linux' || value === 'all';
const normalizeList = value => Array.isArray(value) ? value : [];
const rowsToItems = rows => rows.map(row => parseJson(row.data ?? row.tree)).filter(Boolean);
const textValue = value => {
  if (typeof value === 'string') return value;
  if (isObject(value)) return value.zh || value.en || '';
  return '';
};
const scrubRetiredEdrText = value => {
  if (typeof value !== 'string') return value;
  const hasHan = /\p{Script=Han}/u.test(value);
  const endpointMonitoring = hasHan ? '终端安全监控' : 'endpoint monitoring';
  const variant = hasHan ? '变形' : 'variant';
  return value
    .replace(/AV-evasion one-liner webshell/g, 'Variant one-liner webshell')
    .replace(/AV-evasion/g, variant)
    .replace(/EDR免杀/g, hasHan ? '终端安全检测' : 'endpoint security testing')
    .replace(/免杀Payload/g, '变形 Payload')
    .replace(/免杀一句话木马/g, '函数名拼接变形一句话木马')
    .replace(/免杀一句话/g, '变形一句话')
    .replace(/免杀与规避/g, '终端安全防护')
    .replace(/PowerShell免杀/g, 'PowerShell 安全检测')
    .replace(/Evasion & Anti-Detection/g, 'Endpoint Security')
    .replace(/Evasion & AV Bypass/g, 'Endpoint Security')
    .replace(/EDR/g, endpointMonitoring)
    .replace(/免杀/g, variant);
};
const scrubRetiredEdrContent = value => {
  let changed = false;
  const scrub = input => {
    if (typeof input === 'string') {
      const next = scrubRetiredEdrText(input);
      if (next !== input) changed = true;
      return next;
    }
    if (Array.isArray(input)) return input.map(scrub);
    if (isObject(input)) {
      const output = {};
      for (const [key, item] of Object.entries(input)) {
        if (key === 'edrBypass') {
          changed = true;
          continue;
        }
        output[key] = scrub(item);
      }
      return output;
    }
    return input;
  };
  return { value: scrub(value), changed };
};
const lowQualityEnglishPattern = /(Targethas|CanTraverse|APIMiddle|UseNumber|UsersToken|ManagementMember|Original[A-Z]|Current[A-Z]|AttackPerson|Automatic-ize|BelowSingle|CanInterception|NumberGroups|ModifyUsers|QueryDatabase|LoginUsers|CanTampering|ResourceAccess|Privilege escalationTest|Sequencecolumn|Deserializationprocess|not yet|Canby|Canthrough|CanDirectly|When间|Domain name|Server-Side|\bMiddle\b|Extensionname|NTFSData|AnalyzeTools|Resetworkflow|CollectMultiple|SuccesstimesNumber|Package括|Response操纵|InterceptionFailureResponseModify|Data流|Upload$)/i;
const scrubLowQualityEnglishContent = value => {
  let changed = false;
  const scrub = input => {
    if (Array.isArray(input)) return input.map(scrub);
    if (isObject(input)) {
      const output = {};
      for (const [key, item] of Object.entries(input)) {
        output[key] = scrub(item);
      }
      if (
        typeof output.zh === 'string' &&
        typeof output.en === 'string' &&
        (lowQualityEnglishPattern.test(output.en) || /\p{Script=Han}/u.test(output.en)) &&
        output.zh.trim()
      ) {
        output.en = output.zh;
        changed = true;
      }
      return output;
    }
    return input;
  };
  return { value: scrub(value), changed };
};
const brokenDisplayEnglishPattern = /Automatic-ize|AnalyzeTools|Use(?:Python|Impacket|PowerShell|Nmap|Unicode)|specified|Needpoint|PropertyDownload|ConnectionTarget|Portscope|Portnumber|tableexpression|Samestep|Perform\b|DecodingMethod|EncodingMethod|SecurityCheckNeedpoint|Obtain(?:all|Specify|current|Run|Network|User|Operating|Website|complete)?|Determine(?:column|Operating)?|FormatOutput|through[A-Z]|JSONFormat|basicUse|DetectXSSInjectionpoint|EventprocessingTool(?:Bypass|Variant)?|tagBypass|HTMLEntityEncoding|CommentObfuscation|EmptybyteTruncate|JSONPBypass|AnalyzeCSP(?:Strategy|Configuration)|IPFormatBypass|ReadLocalFile|AccessInternal networkService|ScanInternal networkPort|RedirectBypass|IPv6Bypass|GroupsCombine(?:Multiple)?Bypass|CriticalCharacterBypass|RS256→HS256AlgorithmObfuscationAttack|KIDParameterInjection|HS256keyBrute force|Algorithm NoneAttack|JWK\/JKUHeaderkeyInjection|AlgorithmDowngrade and nestedTokenExploitation|Out-of-bandData|DetectCommand Injection(?:point)?|LinuxCommand Injection|WindowsCommand Injection|LinuxSystemCommand Injection|WindowsSystemCommand Injection|pointnumberBypass|NTFS ADSBypass/i;
const repairBrokenEnglishText = value => {
  const text = normalizeText(value);
  if (
    isObject(text) &&
    typeof text.zh === 'string' &&
    typeof text.en === 'string' &&
    text.zh.trim() &&
    (/\p{Script=Han}/u.test(text.en) || brokenDisplayEnglishPattern.test(text.en))
  ) {
    return { ...text, en: text.zh };
  }
  return text;
};
const awkwardEnglishExactText = new Map([
  ['1. DetectInjectionpoint', '1. Detect injection point'],
  ['5. EnumerationallDatabase', '5. Enumerate all databases'],
  ['HTTPParameterPollution(HPP)', 'HTTP parameter pollution (HPP)'],
  ['JSONInjection', 'JSON injection'],
  ['Chunked transferEncoding', 'Chunked transfer encoding'],
  ['Content-Type variantsSpoofing', 'Content-Type variant spoofing'],
  ['UseEncodingFunctionBypassCriticalCharacterDetection', 'Use encoding functions to bypass critical-character detection'],
  ['ExploitationChunked transferBypass WAF Detection', 'Use chunked transfer encoding to test WAF bypass behavior'],
  ['ExploitationspecificDatabaseFeatureBypassuniversalRule', 'Use database-specific features to bypass generic rules'],
  ['ExploitationmultipartBypassDetection', 'Use multipart variants to test upload-filter detection'],
  ['MySQLDatabaseInjectionBasicDetect and DataExtractTechnique', 'MySQL database-injection basics and data-extraction techniques'],
  ['UseUDFPrivilege escalationExecuteSystem Commands', 'Use UDF privileges to execute system commands'],
  ['3. ReadSensitive Files', '3. Read sensitive files'],
  ['Useload_fileReadSystemSensitive Files', 'Use load_file to read sensitive system files'],
  ['Hex EncodingWrite', 'Hex-encoded file write'],
  ['UsehexadecimalEncoding BypassCriticalCharacterDetection', 'Use hexadecimal encoding to bypass critical-character detection'],
  ['CharEncoding Bypass', 'CHAR() encoding bypass'],
  ['UseCHARFunctionEncoding Bypass', 'Use CHAR() function encoding to bypass filters'],
  ['Microsoft SQL ServerDatabaseInjectionTechnique', 'Microsoft SQL Server injection techniques'],
  ['BasicInjectionDetect', 'Basic injection detection'],
  ['UseHex EncodingBypass', 'Use hex encoding to bypass filters'],
  ['CommentBypass', 'Comment bypass'],
  ['UseComment and EmptybyteBypass', 'Use comments and null bytes to bypass filters'],
  ['MSSQLAdvancedInjection: xp_cmdshell, SP_OACREATECommand Execution', 'Advanced MSSQL injection with xp_cmdshell and SP_OACreate command execution'],
  ['such as Resultxp_cmdshell by Disable, AttemptEnable', 'If xp_cmdshell is disabled, attempt to enable it first'],
  ['3. ExecuteSystem Commands', '3. Execute system commands'],
  ['Usexp_cmdshellExecuteSystem Commands', 'Use xp_cmdshell to execute system commands'],
  ['OracleDatabaseInjectionBasicTechnique', 'Oracle injection basics'],
  ['DetectInjectionpointType', 'Detect injection point type'],
  ['ExtracttableData', 'Extract table data'],
  ['OracleAdvancedInjectionTechnique: Javastorageprocess, UTL_FILEFile Operations', 'Advanced Oracle injection with Java stored procedures and UTL_FILE operations'],
  ['2. CreateJavaExecuteFunction', '2. Create Java execution function'],
  ['UseJavaExecuteSystem Commands', 'Use Java to execute system commands'],
  ['1. DetectionJavaPermission', '1. Detect Java permissions'],
  ['3. UTL_FILEReadFile', '3. Read files with UTL_FILE'],
  ['UseUTL_FILEoperationFile', 'Use UTL_FILE operations to access files'],
  ['OracleComment and Encoding Bypass', 'Oracle comment and encoding bypass'],
  ['PostgreSQLDatabaseInjectionTechnique', 'PostgreSQL injection techniques'],
  ['6. WriteFile', '6. Write file'],
  ['UseCOPYWriteFile', 'Use COPY to write files'],
  ['Usepg_read_fileReadFile', 'Use pg_read_file to read files'],
  ['UsechrFunctionEncoding', 'Use chr() function encoding'],
  ['SQLiteDatabaseInjectionAttack', 'SQLite injection techniques'],
  ['ReadFile(requiresExtension)', 'Read file (requires extension support)'],
  ['SQLitecharacterEncoding Bypass', 'SQLite character-encoding bypass'],
  ['NoSQLDatabaseInjectionAttackTechnique', 'NoSQL injection techniques'],
  ['DetectMongoDB Injection', 'Detect MongoDB injection'],
  ['2. BypassAuthentication', '2. Bypass authentication'],
  ['BypassLoginAuthentication', 'Bypass login authentication'],
  ['4. RegexInjection', '4. Regex injection'],
  ['5. $whereInjection', '5. $where injection'],
  ['6. Blind InjectionExtract Data', '6. Blind-injection data extraction'],
  ['UnicodeBypass', 'Unicode encoding bypass'],
  ['3. WriteWebshell', '3. Write webshell'],
  ['WriteWebshell', 'Write webshell'],
  ['5. WriteCron Jobs', '5. Write cron jobs'],
  ['WriteCron Jobs', 'Write cron jobs'],
  ['RedisCommandObfuscationBypass', 'Redis command-obfuscation bypass'],
  ['Redis LuaScriptExecuteBypass', 'Redis Lua-script execution bypass'],
  ['1. ConfirmBlind Injection', '1. Confirm blind injection'],
  ['ConfirmBoolean Blind Injection', 'Confirm boolean blind injection'],
  ['1. ConfirmTime-Based Blind Injection', '1. Confirm time-based blind injection'],
  ['ConfirmTime-Based Blind Injection', 'Confirm time-based blind injection'],
  ['ExploitationErrorInformationExtract Data SQLInjection', 'Use error messages for SQL injection data extraction'],
  ['1. ConfirmError-Based Injection', '1. Confirm error-based injection'],
  ['TestError-Based Injection', 'Test error-based injection'],
  ['otherError-Based InjectionMethod', 'Other error-based injection methods'],
  ['storageAfterTrigger SQLInjectionAttack', 'Stored-data-triggered SQL injection attack'],
  ['1. DetectSecond-Order Injection', '1. Detect second-order injection'],
  ['DetectSecond-Order Injectionpoint', 'Detect second-order injection points'],
  ['2. UsernameInjection', '2. Username injection'],
  ['UsernameTriggerInjection', 'Username-triggered injection'],
  ['3. PasswordResetInjection', '3. Password-reset injection'],
  ['PasswordResetFunctionInjection', 'Password-reset function injection'],
  ['EncodingstorageTriggerBypass', 'Stored-encoding trigger bypass'],
  ['DetectionVulnerability', 'Detect vulnerability'],
  ['ExploitationVulnerability', 'Exploit vulnerability'],
  ['CollectEnvironmentInformation', 'Collect environment information'],
  ['stringConcatenate', 'String concatenation'],
  ['UseEncoding Bypass', 'Encoding bypass'],
  ['UsestringConcatenateBypass', 'Use string concatenation to bypass filters'],
  ['ReflectionBypass', 'Reflection-based bypass'],
  ['PowerViewEnumeration', 'PowerView enumeration'],
  ['UseMimikatz', 'Use Mimikatz'],
  ['DownloadbinaryFile', 'Download binary file'],
  ['UseIPv6AddressBypass', 'Use IPv6 address variants to bypass filters'],
  ['URL EncodingBypass', 'URL-encoding bypass'],
  ['UseCertificate Authentication', 'Certificate-based authentication'],
  ['BypassOriginVerify', 'Bypass Origin validation'],
  ['ExecuteSystem Commands', 'Execute system commands'],
  ['DoubleURL EncodingBypass', 'Double URL-encoding bypass'],
  ['3. OriginVerifyBypass', '3. Origin-validation bypass'],
  ['2. RefererVerifyBypass', '2. Referer-validation bypass'],
  ['BypassRefererVerify', 'Bypass Referer validation'],
  ['4. SameSiteBypass', '4. SameSite bypass'],
  ['BypassSameSiteRestrict', 'Bypass SameSite restrictions'],
  ['InjectionTicket', 'Inject ticket'],
  ['ClientConnection', 'Client connection'],
  ['GenerateGolden Ticket', 'Generate Golden Ticket'],
  ['DetectVulnerability', 'Detect vulnerability'],
  ['SaveScanResult', 'Save scan results'],
  ['Compile or DownloadbinaryFile', 'Compile or download binary files'],
  ['BypassCriticalCharacterFilter', 'Bypass critical-character filters'],
  ['UseosModuleExecute Command', 'Use the os module to execute commands'],
  ['UsesubprocessExecute Command', 'Use subprocess to execute commands'],
  ['Use__import__ImportModule', 'Use __import__ to import modules'],
  ['ReadLinuxSensitive Files', 'Read sensitive Linux files'],
  ['Usephp://inputExecuteCode', 'Use php://input to execute code'],
  ['Usedata://ProtocolExecuteCode', 'Use the data:// wrapper to execute code'],
  ['1. BasicExecute', '1. Basic execution'],
  ['PharDeserialization', 'Phar deserialization'],
  ['Pseudo-ProtocolGroupsCombine', 'Pseudo-protocol combination'],
  ['5. TokenDeleteBypass', '5. Token-deletion bypass'],
  ['DeleteToken Bypass', 'Token-deletion bypass'],
  ['3. TokenLeak', '3. Token leak'],
  ['ExploitationTokenLeak', 'Token-leak exploitation'],
  ['2. EmptyReferer Bypass', '2. Empty Referer bypass'],
  ['SendEmptyReferer', 'Send an empty Referer'],
  ['iframeBypass', 'iframe bypass'],
  ['1. RegexMatchBypass', '1. Regex-match bypass'],
  ['4. Referrer-PolicyExploitation', '4. Referrer-Policy exploitation'],
  ['ExploitationReferrer-Policy', 'Exploit Referrer-Policy handling'],
  ['ClientRedirect', 'Client-side redirect'],
  ['ExecuteSensitiveoperation', 'Execute sensitive operations'],
  ['AlgorithmObfuscationAttack', 'Algorithm-obfuscation attack'],
  ['ReadWebApplicationConfiguration', 'Read web-application configuration'],
  ['FileHeaderBypass', 'File-header bypass'],
  ['UseParameterEntity', 'Use parameter entities'],
  ['ModifyContent_Types', 'Modify Content-Type values'],
  ['IDVariantBypass', 'ID-variant bypass'],
  ['PathTraverse', 'Path traversal'],
  ['1. SQLInjection', '1. SQL injection'],
  ['characterEncoding Bypass', 'Character-encoding bypass'],
  ['PathEncoding Bypass', 'Path-encoding bypass'],
  ['2. DebugModeInformationLeak', '2. Debug-mode information leak'],
  ['DebugModeInformationLeak', 'Debug-mode information leak'],
  ['PathBypass', 'Path bypass'],
  ['EndpointVariant', 'Endpoint variants'],
  ['FilenameBypass', 'Filename bypass'],
  ['SSTIBypass', 'SSTI bypass'],
  ['Encoding BypassPathFilter', 'Encoding-based path-filter bypass'],
  ['3. jwt_toolAutomaticAttack', '3. jwt_tool automated attack'],
  ['QueryDomainInsideallSPN', 'Query all SPNs in the domain'],
  ['ListDomain Users', 'List domain users'],
  ['DomainTrust Relationships', 'Domain trust relationships'],
  ['ListDomainTrust Relationships', 'List domain trust relationships'],
  ['FindHighPermissionGroups', 'Find high-privilege groups'],
  ['FindWriteDACL', 'Find WriteDACL paths'],
  ['FindWriteDACLPermission', 'Find WriteDACL permissions'],
  ['FindGenericAll', 'Find GenericAll paths'],
  ['FindGenericAllPermission', 'Find GenericAll permissions'],
  ['EnumerationDomainTrust Relationships', 'Enumerate domain trust relationships'],
  ['FindDomainController', 'Find domain controllers'],
  ['ListDomainComputers', 'List domain computers'],
  ['GenerateSilver TicketAccessspecificService', 'Generate Silver Tickets for specific services'],
  ['RubeusRequest', 'Rubeus request'],
  ['TriggerAuthentication', 'Trigger authentication'],
  ['Using HashConnection', 'Connect with a hash'],
  ['in TargetMachineExecute Command', 'Execute commands on the target machine'],
  ['PrintSpoofer Privilege Escalation', 'PrintSpoofer privilege escalation'],
  ['EstablishReverse SOCKS Proxy', 'Establish a reverse SOCKS proxy'],
  ['AddDCSyncPermission', 'Add DCSync permissions'],
  ['CheckServicePermission', 'Check service permissions'],
  ['CreateMaliciousDLL', 'Create a malicious DLL'],
  ['GenerateMaliciousDLL', 'Generate a malicious DLL'],
  ['commonExploitation', 'Common exploitation techniques'],
  ['CreateUsers', 'Create users'],
  ['RecoveryPassword', 'Recover passwords'],
  ['CreateMachineAccount', 'Create a machine account'],
  ['RegisterForgeDC', 'Register a forged DC'],
  ['ExploitationScript', 'Exploitation script'],
  ['ModifyTemplateConfiguration', 'Modify template configuration'],
  ['RecoveryTemplateConfiguration', 'Restore template configuration'],
  ['REST APIAccess', 'REST API access'],
  ['BasicDirectory Brute Force', 'Basic directory brute force'],
  ['POSTDataTest', 'POST data test'],
  ['HostHeaderTest', 'Host-header test'],
  ['Python Reverse ShellShell', 'Python reverse-shell commands'],
  ['EnumerationDomain Users', 'Enumerate domain users'],
  ['ExecutecompletePrivilege escalationScan', 'Run a complete privilege-escalation scan'],
  ['DownloadScriptFile', 'Download script file'],
  ['HTTPScan', 'HTTP scan'],
  ['HTTPServiceVulnerabilityScan', 'HTTP service vulnerability scan'],
  ['Fast Scan, only ScanCommonPort', 'Fast scan of common ports only'],
  ['will ScanResultSave to File', 'Save scan results to a file'],
  ['ExtractSpecify column Data', 'Extract data from specified columns'],
  ['Specify Injection TechniqueType', 'Specify injection technique type'],
  ['SearchrelatedVulnerabilityModule', 'Search related vulnerability modules'],
  ['DisplayModuleConfigurationoption', 'Display module configuration options'],
  ['SetModuleParameter', 'Set module parameters'],
  ['SetAttackPayload', 'Set the payload'],
  ['in Admin PanelExecute Attack', 'Run the attack in the background'],
  ['UsemsfvenomGenerateMaliciousFile', 'Use msfvenom to generate a payload file'],
  ['MeterpreterCommand', 'Meterpreter commands'],
  ['NetworkLoginCrackTools', 'Network login cracking tool'],
  ['UseUsername and PasswordDictionaryBrute forceSSH', 'Use username and password dictionaries to brute-force SSH'],
  ['Brute forceHTTPtableSingleLogin', 'Brute-force a single HTTP form login'],
  ['Brute forceMySQLDatabase', 'Brute-force MySQL credentials'],
  ['PasswordCrackTools', 'Password cracking tool'],
  ['UseDictionaryCrack Hash', 'Crack hashes with a dictionary'],
  ['Display already Crack Password', 'Show cracked passwords'],
  ['CrackLinuxPasswordFile', 'Crack Linux password files'],
  ['CrackZIPFilePassword', 'Crack ZIP archive passwords'],
  ['CrackRARFilePassword', 'Crack RAR archive passwords'],
  ['CrackSSHprivate keyPassword', 'Crack SSH private-key passphrases'],
  ['UseBrute ForceMode', 'Use brute-force mode'],
  ['PythonNetworkProtocoldatabase', 'Python network protocol toolkit'],
  ['PsExecRemote Execution', 'PsExec remote execution'],
  ['ExportallCredentials', 'Dump all credentials'],
  ['AS-REP RoastingAttack', 'AS-REP roasting'],
  ['NTLMRelayAttack', 'NTLM relay attack'],
  ['BypassExecuteStrategyRunScript', 'Bypass execution policy and run a script'],
  ['from RemoteDownload and ExecuteScript', 'Download and execute a remote script'],
  ['UseBase64 EncodingExecute Command', 'Execute a Base64-encoded command'],
  ['Get ServicesInformation', 'Get service information'],
  ['simplePort Scanning', 'Simple port scan'],
  ['SearchSensitive Files', 'Search sensitive files'],
  ['BypassAMSIDetection', 'AMSI bypass'],
  ['LinuxPrivilege escalationCommand', 'Linux privilege-escalation commands'],
  ['LinuxSystemPrivilege escalationCommonCommand', 'Common Linux privilege-escalation commands'],
  ['FindSUIDPermissionFile', 'Find SUID files'],
  ['FindWritable Directories', 'Find writable directories'],
  ['SearchKernel Exploits', 'Search for kernel exploits'],
  ['FindSensitive Files', 'Find sensitive files'],
  ['DetectionDockerEnvironment', 'Detect a Docker environment'],
  ['Directory and Subdomain Brute ForceTools', 'Directory and subdomain brute-force tool'],
  ['Brute forceWebsiteDirectory', 'Brute-force website directories'],
  ['Brute forceSub-Domain name', 'Brute-force subdomains'],
  ['Using CookieAuthentication', 'Use cookie-based authentication'],
  ['AddCustomHeader', 'Add a custom header'],
  ['Setthread count', 'Set thread count'],
  ['WebSecurityTestPlatform', 'Web security testing platform'],
  ['DownloadInstallationPackage', 'Download the installation package'],
  ['Configure Proxylistening', 'Configure the proxy listener'],
  ['EnableRequestInterception', 'Enable request interception'],
  ['AddFileExtensionname', 'Add file extensions'],
  ['GETParameterTest', 'GET parameter test'],
  ['MatchspecificstatusCode', 'Match specific status codes'],
  ['FilterspecificResponsesize', 'Filter specific response sizes'],
  ['recursiveDirectoryScan', 'Recursive directory scan'],
  ['WinRMRemoteManagementTools', 'WinRM remote-management tool'],
  ['UsePassword Connection', 'Connect with a password'],
  ['from TargetDownload File', 'Download a file from the target'],
  ['LoadPowerShellScript', 'Load a PowerShell script'],
  ['Execute PowerShellCommand', 'Execute a PowerShell command'],
  ['ProxyChainTools', 'Proxy chaining tool'],
  ['ConfigurationSOCKS Proxy', 'Configure a SOCKS proxy'],
  ['自动化SQL注入工具', 'Automated SQL injection tool'],
  ['自动化命令注入漏洞检测和利用工具', 'Automated command-injection detection and exploitation tool'],
  ['基于Go的高性能XSS漏洞扫描和参数分析工具', 'High-performance XSS scanner and parameter analysis tool built with Go'],
  ['JWT(JSON Web Token)解码和分析工具', 'JWT (JSON Web Token) decoding and analysis tool'],
]);
const awkwardEnglishPattern = /(?:[a-z][A-Z]|[A-Z]{2,}[a-z][A-Z]|Injectionpoint|transferEncoding|relatedVulnerability|RemoteManagementTools|LoginCrackTools|Protocoldatabase|variantsSpoofing|multipartBypass|Privilege escalation|binaryFile|Content_Types|SSRFAttack|PHPPseudo-Protocol|Free Marker|Math ML|Reverse Shell|Http Only|Same Site|XML Decoder|Work Context|Web Logic|I Pv6|Be EF)/;
const normalizeAwkwardEnglishString = value => {
  let next = String(value ?? '').trim();
  if (!next) return next;
  if (awkwardEnglishExactText.has(next)) return awkwardEnglishExactText.get(next);
  if (!awkwardEnglishPattern.test(next)) return next;
  next = next
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .replace(/([A-Za-z])\(/g, '$1 (')
    .replace(/\)([A-Za-z])/g, ') $1')
    .replace(/\bMy SQL\b/g, 'MySQL')
    .replace(/\bPostgre SQL\b/g, 'PostgreSQL')
    .replace(/\bMongo DB\b/g, 'MongoDB')
    .replace(/\bPower Shell\b/g, 'PowerShell')
    .replace(/\bShare Point\b/g, 'SharePoint')
    .replace(/\bWin RM\b/g, 'WinRM')
    .replace(/\bPs Exec\b/g, 'PsExec')
    .replace(/\bGraph QL\b/g, 'GraphQL')
    .replace(/\bFree Marker\b/g, 'FreeMarker')
    .replace(/\bMath ML\b/g, 'MathML')
    .replace(/\bXML Decoder\b/g, 'XMLDecoder')
    .replace(/\bWork Context\b/g, 'WorkContext')
    .replace(/\bWeb Logic\b/g, 'WebLogic')
    .replace(/\bHttp Only\b/g, 'HttpOnly')
    .replace(/\bSame Site\b/g, 'SameSite')
    .replace(/\bI Pv6\b/g, 'IPv6')
    .replace(/\bBe EF\b/g, 'BeEF')
    .replace(/\bAlways Install Elevated\b/g, 'AlwaysInstallElevated')
    .replace(/\bAT Exec\b/g, 'ATExec')
    .replace(/\bDC Shadow\b/g, 'DCShadow')
    .replace(/\bNo Auth\b/g, 'NoAuth')
    .replace(/\bGod Potato\b/g, 'GodPotato')
    .replace(/\bPrint Spoofer\b/g, 'PrintSpoofer')
    .replace(/\bProxy Token\b/g, 'ProxyToken')
    .replace(/\bProxy Logon\b/g, 'ProxyLogon')
    .replace(/\bProxy Shell\b/g, 'ProxyShell')
    .replace(/\bBlood Hound\b/g, 'BloodHound')
    .replace(/\bLa Zagne\b/g, 'LaZagne')
    .replace(/\bRe Georg\b/g, 'ReGeorg')
    .replace(/\bNo SQL\b/g, 'NoSQL')
    .replace(/\bSQL Injection\b/g, 'SQL injection')
    .replace(/\bJSON Injection\b/g, 'JSON injection')
    .replace(/\bRegex Injection\b/g, 'Regex injection')
    .replace(/\bSSRF Attack\b/g, 'SSRF attack')
    .replace(/\bPHP Pseudo-Protocol\b/g, 'PHP pseudo-protocol')
    .replace(/\binjection point\b/gi, 'injection point')
    .replace(/\btransfer Encoding\b/g, 'transfer encoding')
    .replace(/\ball Database\b/g, 'all databases')
    .replace(/\bData Extract Technique\b/g, 'data extraction technique')
    .replace(/\bBasic Detect\b/g, 'basic detection')
    .replace(/\bPrivilege escalation\b/g, 'privilege escalation')
    .replace(/\bbinary File\b/g, 'binary file')
    .replace(/\bShell Shell\b/g, 'shell commands')
    .replace(/\bRemote Management Tools\b/g, 'remote-management tool')
    .replace(/\bLogin Crack Tools\b/g, 'login cracking tool')
    .replace(/\bProxy Chain Tools\b/g, 'proxy chaining tool')
    .replace(/\bReverse Shell\b/g, 'reverse shell')
    .replace(/\s{2,}/g, ' ')
    .trim();
  return awkwardEnglishExactText.get(next) || next;
};
const normalizeAwkwardEnglishText = value => {
  if (typeof value === 'string') return normalizeAwkwardEnglishString(value);
  if (isObject(value) && typeof value.zh === 'string' && typeof value.en === 'string') {
    return { ...value, en: normalizeAwkwardEnglishString(value.en) };
  }
  return value;
};
const finalizeDisplayText = value => {
  const text = normalizeAwkwardEnglishText(repairBrokenEnglishText(value));
  const normalizeString = input => String(input ?? '').trim()
    .replace(/Content-Type(?:\s+variants?)+(?:\s+bypass)?/gi, match => /bypass/i.test(match) ? 'Content-Type variants bypass' : 'Content-Type variants')
    .replace(/\bvariants(?:\s+variants)+\b/gi, 'variants')
    .replace(/\bPo C\b/g, 'PoC')
    .replace(/Data URIBypass/gi, 'Data URI bypass')
    .replace(/UseData URI/gi, 'Use data URI')
    .replace(/Exploitationunsafe-inlineConfiguration/gi, 'Validate CSP unsafe-inline handling')
    .replace(/Exploitationunsafe-inline/gi, 'unsafe-inline variants')
    .replace(/ExploitationAngularJSBypassCSP/gi, 'Use AngularJS expressions to test CSP bypasses')
    .replace(/AngularJSBypass/gi, 'AngularJS bypass')
    .replace(/pointnumberBypass/gi, 'Trailing-dot bypass')
    .replace(/NTFS stream/gi, 'NTFS alternate data streams')
    .replace(/NTFS ADSBypass/gi, 'Use NTFS alternate data streams to bypass extension checks')
    .replace(/Image Webshell/gi, 'Image polyglot sample')
    .replace(/MeterpreterSessionMiddle CommonCommand/gi, 'Common commands for a Meterpreter session')
    .replace(/through not SameRouteExecute Command or Reverse Shell/gi, 'Execute commands or a reverse shell through different routes')
    .replace(/ExtractSAM\/LSA\/NTDSMiddle Credentials/gi, 'Extract credentials from SAM, LSA, or NTDS')
    .replace(/in SQLInjection and XSSMiddleUsehexadecimalEncoding/gi, 'Use hexadecimal encoding in SQL injection and XSS scenarios');
  if (typeof text === 'string') return normalizeString(text);
  if (isObject(text) && typeof text.zh === 'string' && typeof text.en === 'string') {
    const zh = text.zh
      .trim()
      .replace(/\u53d8\u4f53(?:\s*\u53d8\u4f53)+/g, '\u53d8\u4f53')
      .replace(/Content-Type(?:\s+\u53d8\u4f53)+(?:\s*\u7ed5\u8fc7)?/g, match => /\u7ed5\u8fc7/.test(match) ? 'Content-Type 变体绕过' : 'Content-Type 变体')
      .replace(/Data URI\u7ed5\u8fc7/g, 'Data URI 绕过')
      .replace(/AngularJS\u7ed5\u8fc7/g, 'AngularJS 绕过')
      .replace(/NTFS\u6d41/g, 'NTFS 数据流');
    const en = normalizeString(text.en);
    return { ...text, zh, en };
  }
  return text;
};
const knownPayloadEnglishText = new Map([
  ['应先确认 Django 版本、部署模式和关键安全配置，再结合实际功能判断是信息泄露、认证边界、模板注入、查询风险还是签名数据风险。把“框架默认安全”与“业务侧误用框架能力”区分开来看。', 'First confirm the Django version, deployment mode, and key security settings, then determine whether the real risk lies in disclosure, authentication boundaries, template injection, query behavior, or signed-data handling. Separate Django’s default protections from how the application misuses framework capabilities.'],
  ['学习时应先理解 Kerberos AS-REQ/AS-REP 交换流程，再区分普通账户与禁用预身份验证账户的差异，最后结合目录查询和日志判断哪些请求真正构成风险暴露。', 'When studying the issue, first understand the Kerberos AS-REQ/AS-REP exchange, then distinguish standard accounts from those with pre-authentication disabled, and finally use directory queries plus logs to determine which requests actually expose risk.'],
  ['Overpass-the-Hash 利用 NTLM 哈希去获取 Kerberos 票据，本质上是把已掌握的凭证材料转换成新的认证上下文。它常出现在攻击者已经拿到哈希、但仍希望进入 Kerberos 生态继续横向的场景。', 'Overpass-the-Hash uses an NTLM hash to obtain Kerberos tickets, effectively converting already captured credential material into a new authentication context. It commonly appears when an attacker already has a hash but wants to keep moving inside the Kerberos ecosystem.'],
]);
const localizeKnownPayloadEnglish = value => {
  if (typeof value === 'string' && knownPayloadEnglishText.has(value.trim())) {
    return knownPayloadEnglishText.get(value.trim());
  }
  if (isObject(value) && typeof value.zh === 'string' && typeof value.en === 'string' && knownPayloadEnglishText.has(value.en.trim())) {
    return { ...value, en: knownPayloadEnglishText.get(value.en.trim()) };
  }
  return value;
};
const knownPayloadEnglishOverrides = new Map([
  ['判断漏洞时以服务端状态变化、敏感数据回显、可重复执行证据或安全边界绕过为准，不能只依赖拦截器提示。', 'Judge impact by server-side state changes, sensitive-data disclosure, repeatable execution evidence, or a clear boundary bypass; do not rely only on proxy hints.'],
  ['API/认证类漏洞以越权读取、越权修改、流程跳过或 Token 校验缺失为证据；前端按钮隐藏不算服务端授权。', 'For API and authentication issues, the evidence should be unauthorized reads, unauthorized writes, workflow bypass, or missing token validation; hiding buttons in the frontend is not server-side authorization.'],
  ['SSRF服务端请求伪造', 'Server-side request forgery (SSRF)'],
  ['SSTI 需要证明表达式在服务端模板引擎求值；单纯原样回显或前端渲染不是 SSTI。', 'SSTI requires proof that the expression is evaluated by a server-side template engine; plain reflection or frontend rendering alone is not SSTI.'],
  ['在JSON数据中注入', 'Inject into JSON data'],
  ['IBM/Oracle特有', 'IBM/Oracle-specific variants'],
  ['组合多种绕过技术', 'Combine multiple bypass techniques'],
  ['获取反弹Shell', 'Obtain a reverse shell'],
  ['1. IP格式绕过', '1. IP-format bypass'],
  ['3. 重定向绕过', '3. Redirect bypass'],
  ['5. IPv6绕过', '5. IPv6 bypass'],
  ['组合绕过', 'Combined bypass variants'],
  ['2. 获取版本信息', '2. Enumerate version information'],
  ['3. 获取表名', '3. Enumerate table names'],
  ['使用注释混淆', 'Use comment obfuscation'],
  ['空字节截断绕过', 'Null-byte truncation bypass'],
  ['利用JSONP绕过', 'Use JSONP to bypass filters'],
  ['分析CSP配置', 'Analyze CSP configuration'],
  ['Content-Disposition 变体与分块上传', 'Content-Disposition variants and chunked upload'],
  ['双扩展名与NTFS数据流绕过', 'Double-extension and NTFS ADS bypass'],
  ['使用Impacket', 'Use Impacket'],
  ['请求管理员证书', 'Request an administrator certificate'],
  ['4. 获取数据库信息', '4. Enumerate database information'],
  ['3. 获取用户信息', '3. Enumerate user information'],
  ['获取表名', 'Enumerate table names'],
  ['使用Unicode编码绕过', 'Use Unicode encoding to bypass filters'],
  ['3. 注释混淆', '3. Comment obfuscation'],
  ['4. 空字节截断', '4. Null-byte truncation'],
  ['6. 事件处理器变体', '6. Event-handler variants'],
  ['4. JSONP绕过', '4. JSONP bypass'],
  ['1. 分析CSP策略', '1. Analyze CSP policy'],
  ['空字节截断', 'Null-byte truncation'],
  ['JSON格式', 'JSON format'],
  ['JSON格式绕过', 'JSON-format bypass'],
  ['3. 子域名绕过', '3. Subdomain bypass'],
  ['利用子域名', 'Use subdomains'],
  ['2. HTML实体编码', '2. HTML-entity encoding'],
  ['2. 获取访问令牌', '2. Obtain access tokens'],
  ['DNS外带数据', 'DNS out-of-band exfiltration'],
  ['HTTP外带数据', 'HTTP out-of-band exfiltration'],
  ['文件上传', 'File upload'],
  ['Content-Type 变体 variants 变体', 'Content-Type variants'],
  ['点号绕过', 'Trailing-dot bypass'],
  ['NTFS ADS绕过', 'NTFS ADS bypass'],
  ['使用哈希获取Kerberos票据', 'Use a hash to obtain Kerberos tickets'],
  ['检查当前权限', 'Check current privileges'],
  ['自动化提权检查', 'Automated privilege-escalation check'],
  ['获取域SID', 'Get the domain SID'],
  ['获取注册代理证书', 'Obtain an enrollment-agent certificate'],
  ['利用WebLogic Server中XMLDecoder反序列化漏洞(CVE-2017-10271/CVE-2017-3506)实现远程代码执行', 'Achieve remote code execution through WebLogic Server XMLDecoder deserialization flaws (CVE-2017-10271/CVE-2017-3506).'],
  ['通过SOAP请求中的WorkContext注入XMLDecoder反序列化payload实现命令执行', 'Inject an XMLDecoder deserialization payload into the SOAP WorkContext field to execute commands.'],
  ['基础透明iframe覆盖POC', 'Basic transparent-iframe overlay PoC'],
  ['多步骤拖拽劫持(Drag-and-Drop)', 'Multi-step drag-and-drop clickjacking'],
  ['通过iframe sandbox属性的allow-top-navigation和allow-scripts组合绕过部分frame-busting脚本', 'Bypass some frame-busting scripts through iframe sandbox combinations such as allow-top-navigation and allow-scripts.'],
  ['X-Frame-Options ALLOW-FROM不一致', 'X-Frame-Options ALLOW-FROM inconsistencies'],
  ['2. 确定列数', '2. Determine column count'],
  ['3. 确定显示位置', '3. Identify reflected columns'],
  ['获取当前数据库名、用户、版本等基础信息', 'Enumerate the current database name, user, version, and other basic information.'],
  ['获取MySQL服务器上所有数据库名', 'Enumerate all database names on the MySQL server.'],
  ['获取指定数据库中的所有表名', 'Enumerate all table names in the specified database.'],
  ['获取指定表的所有列名', 'Enumerate all column names in the specified table.'],
  ['从目标表中提取敏感数据', 'Extract sensitive data from the target table.'],
  ['MySQL 基础判断 payload', 'MySQL basic detection payloads'],
  ['标准模式补充登录框、数字参数和真假条件对比常用 payload。', 'Standard mode adds common payloads for login forms, numeric parameters, and true/false condition testing.'],
  ['MySQL 登录框绕过精选', 'MySQL login-form bypass variants'],
  ['从本地 SQL 字典筛出登录框、数字参数和括号闭合场景常用的注释、编码、括号变体。', 'Curated from the local SQL dictionary: comment, encoding, and parenthesis variants commonly used for login forms, numeric parameters, and bracket-closing contexts.'],
  ['通过开启general_log写入Shell', 'Write a shell by enabling general_log.'],
  ['检测当前用户是否有FILE权限', 'Check whether the current user has FILE privileges.'],
  ['2. 获取网站路径', '2. Discover web root paths'],
  ['通过错误信息或读取文件获取网站路径', 'Use error messages or file reads to discover website paths.'],
  ['获取MSSQL版本信息', 'Enumerate MSSQL version information.'],
  ['获取当前用户及权限信息', 'Enumerate the current user and effective privileges.'],
  ['获取所有数据库名', 'Enumerate all database names.'],
  ['5. 获取表名', '5. Enumerate table names'],
  ['获取用户表名', 'Enumerate user table names.'],
  ['6. 获取列名', '6. Enumerate column names'],
  ['获取指定表的列名', 'Enumerate columns in the specified table.'],
  ['提取表中的数据', 'Extract data from the table.'],
  ['MSSQL 延时与执行包装变体', 'MSSQL delay and execution-wrapper variants'],
  ['验证 MSSQL 关键字、空白和 EXEC 包装在过滤链中的归一化差异。', 'Validate how MSSQL keywords, whitespace, and EXEC wrappers are normalized by the filter chain.'],
  ['获取Oracle版本', 'Enumerate Oracle version information.'],
  ['获取数据库用户', 'Enumerate database users.'],
  ['4. 获取表名', '4. Enumerate table names'],
  ['5. 获取列名', '5. Enumerate column names'],
  ['获取列名和数据类型', 'Enumerate column names and data types.'],
  ['使用UTL_HTTP外带数据', 'Use UTL_HTTP for out-of-band exfiltration.'],
  ['Oracle 拼接与注释变体', 'Oracle concatenation and comment variants'],
  ['验证 Oracle 字符串拼接、行限制和注释处理差异。', 'Validate Oracle string concatenation, row-limiting, and comment-handling differences.'],
  ['获取数据库信息', 'Enumerate database information.'],
  ['获取public模式下的表', 'Enumerate tables in the public schema.'],
  ['4. 获取列名', '4. Enumerate column names'],
  ['获取列名', 'Enumerate column names.'],
  ['PostgreSQL 换行与函数变体', 'PostgreSQL newline and function variants'],
  ['验证 PostgreSQL 函数、换行和注释绕过形式。', 'Validate PostgreSQL function, newline, and comment-based bypass variants.'],
  ['2. 获取版本', '2. Enumerate version information'],
  ['获取SQLite版本', 'Enumerate the SQLite version.'],
  ['获取所有表名', 'Enumerate all table names.'],
  ['正则表达式注入', 'Regex injection'],
  ['MongoDB 操作符编码变体', 'MongoDB operator-encoding variants'],
  ['验证 JSON 与表单解析时 NoSQL 操作符是否被一致限制。', 'Validate whether NoSQL operators are restricted consistently across JSON and form parsing.'],
  ['2. 未授权访问', '2. Unauthenticated access'],
  ['未授权访问Redis', 'Unauthenticated Redis access.'],
  ['使用sqlmap自动化', 'Use sqlmap for automation.'],
  ['2. 获取数据库名长度', '2. Determine database-name length'],
  ['使用HEX/CONV进行编码比较、位与运算(&)判断字符范围、POW()数学函数混淆、DIV替代AND', 'Use HEX/CONV encoding comparisons, bitwise operations, POW() obfuscation, and DIV in place of AND.'],
  ['布尔盲注条件表达式替代', 'Boolean blind-condition alternatives'],
  ['布尔盲注条件变体', 'Boolean blind-condition variants'],
  ['补充长度、ASCII、CASE、BETWEEN 条件表达式，方便在无回显场景直接替换判断条件。', 'Adds length, ASCII, CASE, and BETWEEN expressions that can be dropped into blind scenarios without direct output.'],
  ['时间盲注基础 payload', 'Time-based blind payloads'],
  ['标准模式补充 MySQL、MSSQL、PostgreSQL 延时判断 payload。', 'Standard mode adds timing-based payloads for MySQL, MSSQL, and PostgreSQL.'],
  ['时间盲注绕过精选', 'Time-based blind bypass variants'],
  ['补充 MySQL、MSSQL、PostgreSQL 的延时函数和条件延时变体。', 'Adds delay functions and conditional-delay variants for MySQL, MSSQL, and PostgreSQL.'],
  ['报错注入基础 payload', 'Error-based injection payloads'],
  ['标准模式补充 MySQL 常用报错函数，便于直接复制判断回显。', 'Standard mode adds common MySQL error-based functions for direct copy-and-check workflows.'],
  ['2. 获取数据库信息', '2. Enumerate database information'],
  ['获取基础信息', 'Enumerate basic information.'],
  ['4. 获取数据', '4. Extract data'],
  ['报错注入函数变体', 'Error-based function variants'],
  ['补充 MySQL XML、RAND/GROUP 和 GTID 报错函数，适合标准报错被过滤后的验证。', 'Adds MySQL XML, RAND/GROUP, and GTID error-based functions for cases where standard error paths are filtered.'],
  ['1. 确定列数', '1. Determine column count'],
  ['确定列数', 'Determine column count.'],
  ['2. 确定显示列', '2. Identify reflected columns'],
  ['确定显示位置', 'Identify reflected columns.'],
  ['UNION 列数与回显探测', 'UNION column-count and reflection probes'],
  ['标准模式补充列数探测、NULL 占位和数据库信息回显 payload。', 'Standard mode adds column-count probes, NULL placeholders, and database-information reflection payloads.'],
  ['UNION注入关键字绕过', 'UNION keyword-bypass variants'],
  ['UNION 查询绕过精选', 'Curated UNION-query bypass variants'],
  ['覆盖内联注释、MySQL 版本注释、关键字分块和换行编码，便于直接复制到 UNION 查询测试点。', 'Covers inline comments, MySQL version comments, keyword splitting, and newline encoding for direct UNION-query testing.'],
  ['反射型 XSS 基础 payload', 'Reflected XSS basic payloads'],
  ['标准模式补充 HTML、属性闭合、事件处理器、SVG 和 URL 协议上下文 payload。', 'Standard mode adds payloads for HTML context breaks, attribute closure, event handlers, SVG, and URL-scheme contexts.'],
  ['使用HTML实体编码绕过', 'Use HTML-entity encoding to bypass filters.'],
  ['反射型 XSS 事件绕过精选', 'Curated reflected-XSS event-handler bypasses'],
  ['从本地 XSS 字典筛出事件处理器、标签闭合和 URL 编码形式，覆盖常见反射输出上下文。', 'Curated from the local XSS dictionary: event handlers, tag closures, and URL-encoding variants for common reflected-output contexts.'],
  ['SVG标签绕过', 'SVG-tag bypass'],
  ['使用SVG标签绕过', 'Use SVG tags to bypass filters.'],
  ['Math标签绕过', 'MathML-tag bypass'],
  ['存储型 XSS 标签变体', 'Stored-XSS tag variants'],
  ['补充适合评论、昵称、富文本等存储场景的 SVG、MathML、链接和表单事件变体。', 'Adds SVG, MathML, link, and form-event variants suited to comments, nicknames, and rich-text storage sinks.'],
  ['DOM XSS 基础 payload', 'DOM XSS basic payloads'],
  ['标准模式补充 hash、query、跳转参数和 callback 场景 payload。', 'Standard mode adds payloads for hash, query, redirect-parameter, and callback contexts.'],
  ['DOM XSS source/sink 变体', 'DOM XSS source and sink variants'],
  ['补充 hash、query、HTML sink、callback 和跳转参数场景，便于测试前端直接拼接 DOM 的入口。', 'Adds hash, query, HTML-sink, callback, and redirect-parameter variants for client-side DOM concatenation points.'],
  ['SVG/MathML标签与事件处理器绕过', 'SVG/MathML tag and event-handler bypasses'],
  ['服务端请求伪造基础攻击技术', 'Basic server-side request forgery techniques'],
  ['访问内网服务', 'Access internal services.'],
  ['读取本地文件', 'Read local files.'],
  ['SSRF 基础目标 payload', 'Basic SSRF target payloads'],
  ['标准模式补充回环地址、本机地址、IPv6、file 和 dict 协议 payload。', 'Standard mode adds loopback, localhost, IPv6, file, and dict protocol payloads.'],
  ['SSRF 地址解析绕过精选', 'Curated SSRF address-parsing bypasses'],
  ['补充十进制、八进制、十六进制、短 IP、IPv6 映射和 fragment/userinfo 解析差异。', 'Adds decimal, octal, hexadecimal, short-IP, IPv6-mapped, and fragment/userinfo parsing variants.'],
  ['2. 获取IAM凭证', '2. Obtain IAM credentials'],
  ['获取IAM临时凭证', 'Obtain temporary IAM credentials.'],
  ['3. 获取用户数据', '3. Retrieve user data'],
  ['获取实例用户数据', 'Retrieve instance user data.'],
  ['AWS 元数据基础 payload', 'AWS metadata basic payloads'],
  ['标准模式补充 AWS 元数据常见路径 payload。', 'Standard mode adds common AWS metadata-path payloads.'],
  ['通过十进制、十六进制、八进制及IPv6映射等IP地址编码方式绕过169.254.169.254黑名单检测', 'Use decimal, hexadecimal, octal, and IPv6-mapped IP encodings to bypass 169.254.169.254 blacklist checks.'],
  ['AWS 元数据访问变体', 'AWS metadata access variants'],
  ['补充标准地址、编码地址、IPv6 映射、凭据路径和 IMDSv2 token 头验证。', 'Adds standard addresses, encoded addresses, IPv6 mappings, credential paths, and IMDSv2 token-header checks.'],
  ['Linux系统命令注入', 'Linux command injection'],
  ['Windows系统命令注入', 'Windows command injection'],
  ['命令注入基础 payload', 'Command-injection basic payloads'],
  ['标准模式补充常见命令分隔符、命令替换和基础回显 payload。', 'Standard mode adds common command separators, command-substitution forms, and basic reflection payloads.'],
  ['补充分号、管道、换行、IFS、命令替换和 Tab 编码，覆盖 Linux 参数拼接场景。', 'Adds semicolon, pipe, newline, IFS, command-substitution, and tab-encoding variants for Linux argument-concatenation cases.'],
  ['利用XXE进行SSRF', 'Use XXE to trigger SSRF.'],
  ['XXE 基础读取 payload', 'Basic XXE file-read payloads'],
  ['标准模式补充 Linux/Windows 文件读取和 HTTP 外部实体 payload。', 'Standard mode adds Linux/Windows file-read and HTTP external-entity payloads.'],
]);
knownPayloadEnglishOverrides.set('使用ORDER BY或UNION SELECT NULL确定查询列数', 'Use ORDER BY or UNION SELECT NULL to determine the column count.');
knownPayloadEnglishOverrides.set('补充适合评论、昵称、富文本等存储场景的 SVG、Math ML、链接和表单事件变体。', 'Adds SVG, MathML, link, and form-event variants suited to comments, nicknames, and rich-text storage sinks.');
knownPayloadEnglishOverrides.set('SVG/Math ML标签与事件处理器绕过', 'SVG/MathML tag and event-handler bypasses');
knownPayloadEnglishOverrides.set('XXE 基础实体精选', 'Curated basic XXE entity payloads');
knownPayloadEnglishOverrides.set('补充文件实体、UTF-16 编码、HTTP 外部实体和参数实体场景。', 'Adds file entities, UTF-16 encoding, HTTP external entities, and parameter-entity scenarios.');
knownPayloadEnglishOverrides.set('Jinja2 基础 payload', 'Jinja2 basic payloads');
knownPayloadEnglishOverrides.set('标准模式补充探测、对象枚举和命令执行对象链 payload。', 'Standard mode adds probe payloads, object-enumeration payloads, and command-execution object chains.');
knownPayloadEnglishOverrides.set('Jinja2 对象链精选', 'Curated Jinja2 object-chain variants');
knownPayloadEnglishOverrides.set('补充探测、对象链、globals 和 attr 过滤器变体，适合 Jinja2 模板注入快速验证。', 'Adds probe payloads, object-chain variants, and globals/attr filter variants for fast Jinja2 template-injection validation.');
knownPayloadEnglishOverrides.set('Free Marker Execute 变体', 'FreeMarker Execute variants');
knownPayloadEnglishOverrides.set('补充 Free Marker 表达式探测、Execute 工具类和 Java 反射调用形式。', 'Adds FreeMarker expression probes, Execute utility-class calls, and Java reflection-call variants.');
knownPayloadEnglishOverrides.set('使用Unicode', 'Use Unicode encoding');
knownPayloadEnglishOverrides.set('3. 命令执行 - Spring表达式', '3. Command execution via Spring expressions');
knownPayloadEnglishOverrides.set('使用Spring表达式执行命令', 'Execute commands with Spring expressions.');
knownPayloadEnglishOverrides.set('使用字节数组绕过', 'Use byte-array variants to bypass filters.');
knownPayloadEnglishOverrides.set('通过handler访问', 'Access through the handler object.');
knownPayloadEnglishOverrides.set('3. 命令执行 - 通过settings', '3. Command execution via settings');
knownPayloadEnglishOverrides.set('尝试通过settings访问', 'Attempt access through settings.');
knownPayloadEnglishOverrides.set('通过日志投毒实现LFI到RCE', 'Escalate LFI to RCE through log poisoning.');
knownPayloadEnglishOverrides.set('在User-Agent中注入代码', 'Inject code through the User-Agent header.');
knownPayloadEnglishOverrides.set('在请求路径中注入代码', 'Inject code into the request path.');
knownPayloadEnglishOverrides.set('日志路径编码变体', 'Log-path encoding variants');
knownPayloadEnglishOverrides.set('验证日志包含路径、URL 编码和 php filter 读取差异。', 'Validate differences in log include paths, URL encoding, and php://filter reads.');
knownPayloadEnglishOverrides.set('利用PHP伪协议进行LFI攻击', 'Use PHP pseudo-protocols for LFI attacks.');
knownPayloadEnglishOverrides.set('利用PHP Filter链进行LFI攻击', 'Use PHP filter chains for LFI attacks.');
knownPayloadEnglishOverrides.set('利用zip://协议进行LFI攻击', 'Use the zip:// wrapper for LFI attacks.');
knownPayloadEnglishOverrides.set('使用图片马上传', 'Upload a polyglot image sample.');
knownPayloadEnglishOverrides.set('利用Phar反序列化进行RCE', 'Use Phar deserialization to reach RCE.');
knownPayloadEnglishOverrides.set('Phar 包装器路径变体', 'Phar wrapper path variants');
knownPayloadEnglishOverrides.set('验证 phar/zip 包装器和片段符号在文件包含入口的处理差异。', 'Validate how phar/zip wrappers and fragment markers are handled at file-include sinks.');
knownPayloadEnglishOverrides.set('利用Session文件进行LFI攻击', 'Use session files for LFI attacks.');
knownPayloadEnglishOverrides.set('利用/proc文件系统进行LFI攻击', 'Use the /proc filesystem for LFI attacks.');
knownPayloadEnglishOverrides.set('读取当前进程信息', 'Read current process information.');
knownPayloadEnglishOverrides.set('3. 通过fd读取日志', '3. Read logs through file descriptors');
knownPayloadEnglishOverrides.set('通过fd读取日志', 'Read logs through file descriptors.');
knownPayloadEnglishOverrides.set('Proc 伪文件读取变体', 'Proc pseudo-file read variants');
knownPayloadEnglishOverrides.set('验证 proc 伪文件、空字节和编码读取路径。', 'Validate proc pseudo-files, null-byte variants, and encoded read paths.');
knownPayloadEnglishOverrides.set('JSON格式的CSRF攻击', 'JSON-formatted CSRF attack.');
knownPayloadEnglishOverrides.set('CSRF 简单请求变体', 'CSRF simple-request variants');
knownPayloadEnglishOverrides.set('验证简单请求、Origin null 和 Fetch Metadata 校验是否完整。', 'Validate whether simple requests, Origin: null, and Fetch Metadata checks are handled completely.');
knownPayloadEnglishOverrides.set('利用Flash进行CSRF攻击', 'Use Flash to perform CSRF attacks.');
knownPayloadEnglishOverrides.set('发送JSON格式请求', 'Send JSON-formatted requests.');
knownPayloadEnglishOverrides.set('利用CORS配置错误进行CSRF攻击', 'Exploit CORS misconfiguration to perform CSRF attacks.');
knownPayloadEnglishOverrides.set('JWT 基础头部 payload', 'JWT basic header payloads');
knownPayloadEnglishOverrides.set('标准模式补充 JWT 算法、kid 和 none 空签名样例。', 'Standard mode adds JWT algorithm, kid, and unsigned none-sample payloads.');
knownPayloadEnglishOverrides.set('JWT 头部绕过精选', 'Curated JWT header-bypass variants');
knownPayloadEnglishOverrides.set('补充 none 大小写、kid 路径、jku 远程密钥和空签名 token 样例。', 'Adds none case variants, kid path variants, remote-key jku examples, and unsigned token samples.');
knownPayloadEnglishOverrides.set('使用嵌套表达式绕过', 'Use nested expressions to bypass filters.');
knownPayloadEnglishOverrides.set('通过env端点执行命令', 'Execute commands through the env endpoint.');
knownPayloadEnglishOverrides.set('2. 获取敏感信息', '2. Retrieve sensitive information');
knownPayloadEnglishOverrides.set('获取环境变量和配置', 'Retrieve environment variables and configuration.');
knownPayloadEnglishOverrides.set('HTTP方法覆盖与Content-Type 变体绕过', 'HTTP method-override and Content-Type variant bypasses');
knownPayloadEnglishOverrides.set('路径遍历与分号参数技巧', 'Path-traversal and semicolon-parameter tricks');
knownPayloadEnglishOverrides.set('4. DOM clobbering配合', '4. DOM clobbering combination');
knownPayloadEnglishOverrides.set('嵌套标签绕过', 'Nested-tag bypass');
knownPayloadEnglishOverrides.set('m XSS 命名空间变体', 'mXSS namespace variants');
knownPayloadEnglishOverrides.set('验证浏览器重写 DOM 后产生的突变型执行上下文。', 'Validate mutation-based execution contexts created after the browser rewrites the DOM.');
knownPayloadEnglishOverrides.set('3. Unicode规范化攻击', '3. Unicode-normalization attacks');
knownPayloadEnglishOverrides.set('HTML实体编码', 'HTML-entity encoding');
knownPayloadEnglishOverrides.set('1. 经典Polyglot', '1. Classic polyglot');
const localizePayloadEnglishOverrides = value => {
  if (typeof value === 'string' && knownPayloadEnglishOverrides.has(value.trim())) {
    return knownPayloadEnglishOverrides.get(value.trim());
  }
  if (isObject(value) && typeof value.zh === 'string' && typeof value.en === 'string' && knownPayloadEnglishOverrides.has(value.en.trim())) {
    return { ...value, en: knownPayloadEnglishOverrides.get(value.en.trim()) };
  }
  return value;
};
const payloadVisibleZhOverrides = new Map([
  ['Burp SQL login and boolean payloads', 'Burp SQL 登录与布尔验证样例'],
  ['SQLi tamper WAF variants', 'SQL 注入 WAF 绕过变体'],
  ['Burp SQLi WAF tamper payloads', 'Burp SQL 注入绕过样例'],
  ['JWK/JKU header samples', 'JWK/JKU 请求头样例'],
  ['x5c/x5u header samples', 'x5c/x5u 请求头样例'],
  ['SSRF target samples', 'SSRF 目标样例'],
  ['SSRF bypass variants', 'SSRF 绕过变体'],
  ['SSRF parser-bypass variants', 'SSRF 解析绕过变体'],
  ['XMLDecoder raw SOAP payload', 'XMLDecoder 原始 SOAP 请求'],
  ['XMLDecoder command proof sample', 'XMLDecoder 命令验证样例'],
  ['MSSQL direct proof payloads', 'MSSQL 直接验证样例'],
  ['MSSQL WAF variants', 'MSSQL WAF 绕过变体'],
  ['MSSQL command proof variants', 'MSSQL 命令验证变体'],
  ['Oracle direct proof payloads', 'Oracle 直接验证样例'],
  ['Oracle WAF variants', 'Oracle WAF 绕过变体'],
  ['PostgreSQL direct proof payloads', 'PostgreSQL 直接验证样例'],
  ['PostgreSQL WAF variants', 'PostgreSQL WAF 绕过变体'],
  ['SQLite direct proof payloads', 'SQLite 直接验证样例'],
  ['SQLite WAF variants', 'SQLite WAF 绕过变体'],
  ['MongoDB auth bypass payloads', 'MongoDB 认证绕过样例'],
  ['Burp NoSQL operator payloads', 'Burp NoSQL 操作符样例'],
  ['Boolean blind condition payloads', '布尔盲注条件样例'],
  ['Time blind length payloads', '时间盲注长度样例'],
  ['Burp time-delay probes', 'Burp 延时验证样例'],
  ['Burp UNION column probes', 'Burp UNION 列探测样例'],
  ['Burp DOM XSS payloads', 'Burp DOM XSS 样例'],
  ['Burp XXE file-read payloads', 'Burp XXE 文件读取样例'],
  ['Burp XXE WAF variants', 'Burp XXE WAF 绕过变体'],
  ['Burp Jinja2 execution payloads', 'Burp Jinja2 执行样例'],
  ['Jinja2 WAF object-chain variants', 'Jinja2 WAF 对象链变体'],
  ['Burp SSTI WAF variants', 'Burp SSTI WAF 绕过变体'],
  ['FreeMarker command proof variants', 'FreeMarker 命令验证变体'],
  ['FreeMarker WAF variants', 'FreeMarker WAF 绕过变体'],
  ['Velocity command proof variants', 'Velocity 命令验证变体'],
  ['Velocity direct proof payloads', 'Velocity 直接验证样例'],
  ['Thymeleaf command proof variants', 'Thymeleaf 命令验证变体'],
  ['Thymeleaf direct execution payloads', 'Thymeleaf 直接执行样例'],
  ['Thymeleaf WAF variants', 'Thymeleaf WAF 绕过变体'],
  ['Smarty direct execution payloads', 'Smarty 直接执行样例'],
  ['Mako direct execution payloads', 'Mako 直接执行样例'],
  ['Tornado command proof variants', 'Tornado 命令验证变体'],
  ['ERB command proof variants', 'ERB 命令验证变体'],
  ['ERB direct execution payloads', 'ERB 直接执行样例'],
  ['LFI WAF traversal variants', 'LFI WAF 路径绕过变体'],
  ['data:// wrapper proof payloads', 'data:// 包装器验证样例'],
  ['JSON CSRF text/plain form payloads', 'JSON CSRF text/plain 表单样例'],
  ['SameSite top-level navigation payloads', 'SameSite 顶级导航样例'],
  ['Log4j callback proof payloads', 'Log4j 回连验证样例'],
  ['Fastjson AutoType bypass variants', 'Fastjson AutoType 绕过变体'],
  ['Cookie property access variants', 'Cookie 属性访问变体'],
  ['Keyboard event proof payloads', '键盘事件验证样例'],
  ['Form event proof payloads', '表单事件验证样例'],
]);
const localizePayloadVisibleZh = value => {
  if (typeof value === 'string') return payloadVisibleZhOverrides.get(value.trim()) || value;
  if (isObject(value) && typeof value.zh === 'string' && typeof value.en === 'string') {
    const translated = payloadVisibleZhOverrides.get(value.zh.trim());
    if (translated) return { ...value, zh: translated };
  }
  return value;
};
const ensureDisplayTextObject = value => {
  const normalized = localizePayloadVisibleZh(localizePayloadEnglishOverrides(localizeKnownPayloadEnglish(finalizeDisplayText(value))));
  return isObject(normalized) ? normalized : toText(normalized);
};
const knownToolEnglishText = new Map([
  ['指定端口扫描', 'Specified port scan'],
  ['指定参数测试', 'Specified parameter test'],
  ['使用Cookie', 'Use cookies'],
  ['获取Debug权限', 'Acquire debug privilege'],
  ['使用哈希进行认证', 'Authenticate with a hash'],
  ['通过WinRM执行命令', 'Execute commands via WinRM'],
  ['通过LSA枚举用户', 'Enumerate users via LSA'],
  ['获取运行进程', 'List running processes'],
  ['获取网络连接', 'List network connections'],
  ['获取用户信息', 'Get user information'],
  ['获取系统版本信息', 'Get OS version information'],
  ['指定文件扩展名', 'Specify file extensions'],
  ['通过代理运行工具', 'Run tools through a proxy'],
  ['获取完整TTY', 'Get a full TTY'],
  ['指定漏洞严重级别', 'Specify vulnerability severity'],
  ['JSON格式输出', 'Output in JSON format'],
  ['获取对象ACL', 'Get object ACLs'],
  ['获取页面标题和状态码', 'Fetch page titles and status codes'],
  ['支持JSON/XML/Grepable格式输出', 'Support JSON/XML/Grepable output'],
  ['输出JSON格式结果', 'Output results in JSON format'],
  ['批量生成子域名并JSON格式输出', 'Generate subdomains and output in JSON'],
  ['过滤指定状态码并显示服务器信息', 'Filter by status code and show server info'],
  ['批量探测指定路径', 'Probe a specified path in batch'],
  ['列出或指定使用特定插件', 'List or use a specific plugin'],
  ['使用指定数据源搜集', 'Gather using the specified data source'],
  ['对目标进行全面Web漏洞扫描', 'Run a comprehensive web vulnerability scan against the target'],
  ['通过Burp代理进行扫描', 'Scan through the Burp proxy'],
  ['仅运行指定的测试插件', 'Run only the specified test plugins'],
  ['指定POST参数进行注入测试', 'Test injection against a specified POST parameter'],
  ['执行系统命令或获取交互式Shell', 'Execute OS commands or obtain an interactive shell'],
  ['通过自省查询导出完整Schema', 'Export the full schema via introspection'],
  ['使用指定Gadget Chain生成反序列化Payload', 'Generate a deserialization payload with the specified gadget chain'],
  ['通过JRMP协议进行远程利用', 'Exploit remotely via JRMP'],
  ['获取Beacon后的常用后渗透命令', 'Common post-exploitation commands after obtaining a Beacon'],
  ['直接导入Nmap扫描结果进行破解', 'Import Nmap scan results directly for cracking'],
  ['通过SMB/WinRM执行命令', 'Execute commands via SMB or WinRM'],
  ['收集指定子域的信息', 'Collect information for the specified domain'],
  ['使用NTLM哈希进行Pass-the-Hash收集', 'Collect with NTLM hashes using pass-the-hash'],
  ['使用证书进行PKINIT认证获取NT Hash', 'Authenticate with a certificate via PKINIT to obtain an NT hash'],
  ['运行指定的检查模块', 'Run the specified check module'],
  ['获取操作系统和计算机信息', 'Get operating system and computer information'],
  ['使用TCP连接方式进行端口扫描', 'Scan ports by establishing full TCP connections'],
  ['使用SYN包进行隐蔽扫描，需要root权限', 'Perform a stealth SYN scan; root privileges are required'],
  ['启用高级功能进行全面扫描', 'Enable advanced detection features for a comprehensive scan'],
  ['只扫描指定的端口', 'Scan only the specified ports'],
  ['扫描指定范围的端口', 'Scan ports within the specified range'],
  ['使用Nmap脚本引擎进行漏洞扫描', 'Use the Nmap Scripting Engine for vulnerability checks'],
  ['对URL进行SQL注入测试', 'Test the target URL for SQL injection'],
  ['只测试指定的参数', 'Test only the specified parameter'],
  ['使用Cookie进行认证', 'Authenticate by sending the provided cookie'],
  ['指定后端数据库类型', 'Specify the backend database type'],
  ['获取所有数据库名', 'Enumerate all database names'],
  ['获取指定数据库的表', 'Enumerate tables in the specified database'],
  ['获取指定表的列', 'Enumerate columns in the specified table'],
  ['尝试获取操作系统Shell', 'Attempt to obtain an operating system shell'],
  ['通过代理发送请求', 'Send requests through the configured proxy'],
  ['指定线程数', 'Set the thread count'],
  ['指定哈希格式', 'Specify the hash format'],
  ['使用规则文件进行破解', 'Crack hashes with a rule file'],
  ['指定DNS服务器进行枚举', 'Enumerate using the specified DNS server'],
  ['Unicode解码方法', 'Unicode decoding methods'],
  ['Shadow Credentials攻击获取目标用户凭证', 'Use the Shadow Credentials technique to obtain target user credentials'],
  ['查找指定用户到域管的最短攻击路径', 'Find the shortest attack path from the specified user to Domain Admin'],
  ['查找可进行Kerberoasting的用户', 'Find users vulnerable to Kerberoasting'],
  ['查找可进行AS-REP Roasting的用户', 'Find users vulnerable to AS-REP roasting'],
  ['各平台Base64编码方法', 'Base64 encoding methods on different platforms'],
  ['各平台Base64解码方法', 'Base64 decoding methods on different platforms'],
  ['URL编码方法(单次/双重)', 'URL encoding methods (single/double)'],
  ['URL解码方法', 'URL decoding methods'],
  ['十六进制编码方法', 'Hex encoding methods'],
  ['十六进制解码方法', 'Hex decoding methods'],
  ['使用Unicode编码绕过WAF/过滤', 'Use Unicode encoding to bypass WAFs or filters'],
  ['使用Python命令行解码JWT', 'Decode JWTs with the Python CLI'],
  ['JWT结构分析和安全检查要点', 'JWT structure analysis and security checkpoints'],
  ['按指定合规基线筛选检查项。', 'Filter checks by the specified compliance baseline.'],
]);
const localizeKnownToolEnglish = value => {
  const text = ensureDisplayTextObject(value);
  if (typeof text.en === 'string' && /\p{Script=Han}/u.test(text.en) && knownToolEnglishText.has(text.zh)) {
    return { ...text, en: knownToolEnglishText.get(text.zh) };
  }
  return text;
};
const sanitizeLogoUrl = value => {
  const logoUrl = String(value ?? '').trim();
  return /^\/uploads\/logo\/logo-[a-zA-Z0-9.-]+\.(png|jpe?g|webp)$/.test(logoUrl) ? logoUrl : '';
};

const makeId = (prefix, fallback = 'item') => {
  const source = String(fallback || 'item')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  const suffix = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${source || 'item'}-${suffix}`;
};

export const getDbFile = () => dbFile;
export const getDefaultSeedDbFile = () => defaultSeedDbFile;
export const getRuntimeDbFile = () => dbFile;

export const setStoreTestHooks = hooks => {
  const candidate = hooks && typeof hooks === 'object' ? hooks : {};
  storeTestHooks = {
    ...(typeof candidate.beforeInitializationPublish === 'function'
      ? { beforeInitializationPublish: candidate.beforeInitializationPublish }
      : {}),
    ...(typeof candidate.beforeResetBackup === 'function'
      ? { beforeResetBackup: candidate.beforeResetBackup }
      : {}),
  };
};

export const closeStore = () => {
  storeGeneration += 1;
  const initialized = Boolean(db);
  if (db) {
    db.close();
    db = undefined;
  }
  if (initialized || !dbInitialization) dbInitialization = undefined;
  publicDataCache = undefined;
};

const enqueueMutation = work => {
  const operation = mutationQueue.then(work, work);
  mutationQueue = operation.then(() => undefined, () => undefined);
  return operation;
};

const invalidatePublicDataCache = () => {
  publicDataCache = undefined;
};

const initializeContentDatabase = database => {
  database.exec(`
    CREATE TABLE IF NOT EXISTS metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS payloads (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tools (
      id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS navigation_nodes (
      id TEXT PRIMARY KEY,
      tree TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('payloads', 'tools')),
      sort_order INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
};

const initializeStore = async generation => {
  await mkdir(dataDir, { recursive: true });
  const candidate = new DatabaseSync(dbFile);
  try {
    candidate.exec('PRAGMA busy_timeout = 5000;');
    candidate.exec('PRAGMA journal_mode = WAL;');
    candidate.exec('PRAGMA synchronous = NORMAL;');
    candidate.exec('PRAGMA foreign_keys = ON;');
    initializeContentDatabase(candidate);
    await seedIfNeeded(candidate);
    await applyDataMigrations(candidate);
    if (typeof storeTestHooks.beforeInitializationPublish === 'function') {
      await storeTestHooks.beforeInitializationPublish();
    }
    if (generation !== storeGeneration) {
      const error = new Error('Store initialization was cancelled by closeStore().');
      error.code = 'ERR_STORE_INITIALIZATION_CANCELLED';
      throw error;
    }
    db = candidate;
    return candidate;
  } catch (error) {
    try {
      candidate.close();
    } catch {
      // Preserve the initialization error; the connection is already unusable.
    }
    throw error;
  }
};

const getDb = () => {
  if (!dbInitialization) {
    const pending = initializeStore(storeGeneration);
    dbInitialization = pending;
    pending.catch(() => {
      if (dbInitialization === pending) dbInitialization = undefined;
    });
  }
  return dbInitialization;
};

export const ensureStoreReady = async () => {
  await getDb();
  return true;
};

const readMetadata = (database, key) => (
  database.prepare('SELECT value FROM metadata WHERE key = ?').get(key)?.value
);

const writeMetadata = (database, key, value) => {
  database.prepare(`
    INSERT INTO metadata (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, value);
};

const readJsonMetadata = (database, key, fallback) => {
  const value = readMetadata(database, key);
  if (!value) return fallback;
  try {
    return parseJson(value) ?? fallback;
  } catch {
    return fallback;
  }
};

export const getMetadataValue = async (key, fallback = null) => {
  const database = await getDb();
  return readMetadata(database, key) ?? fallback;
};

export const setMetadataValue = async (key, value) => {
  return enqueueMutation(async () => {
    const database = await getDb();
    writeMetadata(database, key, String(value ?? ''));
    if (key === 'settings') invalidatePublicDataCache();
    return value;
  });
};

const runTransaction = (database, work) => {
  database.exec('BEGIN');
  try {
    const result = work();
    database.exec('COMMIT');
    return result;
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
};

const ensureSeedDatabaseMetadata = (database, file) => {
  const schemaVersion = readMetadata(database, 'seed_schema_version');
  const contentKind = readMetadata(database, 'content_kind');
  if (schemaVersion !== defaultSeedSchemaVersion || contentKind !== defaultSeedContentKind) {
    throw new Error(`Invalid default seed database metadata in ${file}`);
  }
};

export const loadDefaultDataFromSeedDb = (file = defaultSeedDbFile) => {
  if (!existsSync(file)) {
    throw new Error(`Default seed database not found: ${file}`);
  }
  const seedDatabase = new DatabaseSync(file, { readOnly: true });
  try {
    ensureSeedDatabaseMetadata(seedDatabase, file);
    return readContentDataFromOpenDatabase(seedDatabase);
  } finally {
    seedDatabase.close();
  }
};

const readContentDataFromOpenDatabase = database => ({
  payloads: rowsToItems(database.prepare('SELECT data FROM payloads WHERE enabled = 1 ORDER BY sort_order, id').all()),
  tools: rowsToItems(database.prepare('SELECT data FROM tools WHERE enabled = 1 ORDER BY sort_order, id').all()),
  navigation: rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'payloads' ORDER BY sort_order, id").all()),
  toolNavigation: rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'tools' ORDER BY sort_order, id").all()),
});

export const loadContentDataFromDatabase = (file = dbFile) => {
  if (!existsSync(file)) {
    throw new Error(`Content database not found: ${file}`);
  }
  const sourceDatabase = new DatabaseSync(file, { readOnly: true });
  try {
    return readContentDataFromOpenDatabase(sourceDatabase);
  } finally {
    sourceDatabase.close();
  }
};

export const loadDefaultData = async () => {
  return loadDefaultDataFromSeedDb(defaultSeedDbFile);
};

const excludedPublicPayloadRootIds = new Set(['evasion', 'intranet']);
const excludedPublicPayloadIds = new Set([
  'file-upload-bypass',
  'sqli-waf-bypass',
  'xss-filter-bypass',
  'xss-csp-bypass',
  'ssrf-bypass',
  'csrf-bypass',
  'csrf-token-bypass',
  'csrf-referer-bypass',
  'jwt-none-alg',
  'sqli-redis',
  'xss-beef',
]);
const excludedPublicPayloadNodeIds = new Set([
  'file-upload-bypass',
  'sqli-waf-bypass',
  'xss-filter-bypass',
  'xss-csp-bypass',
  'ssrf-bypass',
  'csrf-bypass',
  'csrf-token-bypass',
  'csrf-referer-bypass',
  'jwt-none-alg',
  'sqli-redis',
  'xss-beef',
]);
const excludedPublicPayloadCategories = new Set([
  '免杀与规避',
  'Evasion & Anti-Detection',
  'Evasion & AV Bypass',
]);
const showAllPublicPayloads = true;
const payloadVisibilityRules = {
  rootIds: excludedPublicPayloadRootIds,
  payloadIds: excludedPublicPayloadIds,
  nodeIds: excludedPublicPayloadNodeIds,
  categories: excludedPublicPayloadCategories,
};
const excludedPublicToolIds = new Set(['powershell-amsi']);
const payloadRefAliases = new Map([
  ['biz-price-tamper', 'biz-payment-tamper'],
  ['jwt-none-alg', 'jwt-none-attack'],
  ['jwt-none-algo', 'jwt-none-attack'],
  ['jwt-weak-secret', 'jwt-secret-bruteforce'],
  ['jwt-kid-injection', 'jwt-key-confusion'],
  ['jwt-jku-spoofing', 'jwt-jku-x5u-injection'],
]);

const modeOnlyPayloadMergeTargets = new Map([
  ['sqli-waf-bypass', ['sqli-mysql-basic', 'sqli-union', 'sqli-blind', 'sqli-time-based', 'sqli-error-based']],
  ['xss-filter-bypass', ['xss-reflected', 'xss-stored', 'xss-dom']],
  ['xss-csp-bypass', ['xss-reflected', 'xss-stored', 'xss-dom']],
  ['ssrf-bypass', ['ssrf-basic', 'ssrf-cloud-aws', 'ssrf-gopher', 'ssrf-redis', 'ssrf-dns-rebinding']],
  ['csrf-bypass', ['csrf-basic', 'csrf-json', 'csrf-samesite']],
  ['csrf-token-bypass', ['csrf-basic', 'csrf-json']],
  ['csrf-referer-bypass', ['csrf-basic', 'csrf-samesite']],
  ['redirect-bypass', ['redirect-basic']],
]);
const modeOnlyPayloadIds = new Set(modeOnlyPayloadMergeTargets.keys());

const legacyJwtPayloadIds = new Set([
  'jwt-none-alg',
  'jwt-none-algo',
  'jwt-weak-secret',
  'jwt-kid-injection',
  'jwt-jku-spoofing',
]);

const jwtCanonicalPayloadIds = [
  'jwt-security',
  'jwt-none-attack',
  'jwt-secret-bruteforce',
  'jwt-key-confusion',
  'jwt-jku-x5u-injection',
];

const i18n = (zh, en = zh) => ({ zh, en });

const publicNavigationNameOverrides = new Map([
  ['auth-bypass', i18n('认证校验缺陷', 'Authentication validation flaws')],
  ['cdn-bypass', i18n('源站暴露', 'Origin exposure')],
  ['redirect-bypass', i18n('重定向校验缺陷', 'Redirect validation flaws')],
  ['biz-flow-bypass-nav', i18n('流程越权', 'Workflow authorization flaws')],
  ['ws-auth-bypass-nav', i18n('WebSocket 授权缺陷', 'WebSocket authorization flaws')],
]);

const businessLogicPayloadIds = new Set();
const legacyNavigationPayloadRefMigrations = [
  { nodeId: 'jwt-none-algo-nav', from: 'jwt-none-algo', to: 'jwt-none-attack' },
  { nodeId: 'jwt-none-alg-nav', from: 'jwt-none-alg', to: 'jwt-none-attack' },
  { nodeId: 'jwt-weak-secret-nav', from: 'jwt-weak-secret', to: 'jwt-secret-bruteforce' },
  { nodeId: 'jwt-kid-injection-nav', from: 'jwt-kid-injection', to: 'jwt-key-confusion' },
  { nodeId: 'jwt-jku-spoofing-nav', from: 'jwt-jku-spoofing', to: 'jwt-jku-x5u-injection' },
];
const ensureBusinessLogicNavigation = navigation => ({ items: navigation, changed: false });
const ensureJwtSecurityNavigation = navigation => ({ items: navigation, changed: false });

const destructiveDbCleanupPattern = /(DROP(?:\s|%20|\+)+(?:TABLE|DATABASE|SCHEMA)|TRUNCATE(?:\s|%20|\+)+TABLE|FLUSHALL|FLUSHDB)/i;
const trimBlankEdges = lines => {
  const result = [...lines];
  while (result.length && !String(result[0]).trim()) result.shift();
  while (result.length && !String(result[result.length - 1]).trim()) result.pop();
  return result;
};

const normalizeCommandLines = lines => {
  const result = [];
  let previousBlank = false;
  for (const line of trimBlankEdges(lines)) {
    const blank = !String(line).trim();
    if (blank && previousBlank) continue;
    result.push(line);
    previousBlank = blank;
  }
  return result;
};

const scrubDestructiveText = value => {
  const lines = String(value || '').split(/\r?\n/);
  return normalizeCommandLines(lines.filter(line => !destructiveDbCleanupPattern.test(line))).join('\n');
};

const scrubDestructiveI18nText = value => {
  if (typeof value === 'string') return scrubDestructiveText(value);
  if (!isObject(value)) return value;
  const next = { ...value };
  for (const key of ['zh', 'en']) {
    if (typeof next[key] === 'string') next[key] = scrubDestructiveText(next[key]);
  }
  return finalizeDisplayText(next);
};

const compactCommandDescriptionText = value => {
  const text = scrubDestructiveText(value).trim();
  if (!text) return text;
  return text.replace(/\s+说明：[\s\S]*$/u, '').trim() || text;
};

const compactCommandDescription = value => {
  if (typeof value === 'string') return compactCommandDescriptionText(value);
  if (!isObject(value)) return value;
  const next = { ...value };
  for (const key of ['zh', 'en']) {
    if (typeof next[key] === 'string') next[key] = compactCommandDescriptionText(next[key]);
  }
  return next;
};

const scrubDestructiveSyntaxPart = part => {
  if (!isObject(part)) return null;
  const next = { ...part };
  for (const key of ['part', 'explanation']) {
    if (typeof next[key] === 'string') next[key] = scrubDestructiveText(next[key]);
    else if (isObject(next[key])) next[key] = scrubDestructiveI18nText(next[key]);
  }
  if (typeof next.part === 'string' && !next.part.trim()) return null;
  return next;
};

const scrubDestructiveCommandEntry = entry => {
  if (!entry?.command) return entry;
  const command = scrubDestructiveText(entry.command);
  if (!command) return null;
  const next = {
    ...entry,
    title: scrubDestructiveI18nText(entry.title),
    description: compactCommandDescription(entry.description),
    command,
  };
  const syntaxBreakdown = normalizeList(entry.syntaxBreakdown).map(scrubDestructiveSyntaxPart).filter(Boolean);
  if (syntaxBreakdown.length) next.syntaxBreakdown = syntaxBreakdown;
  else delete next.syntaxBreakdown;
  return next;
};

const scrubDestructiveAttackChainStep = step => {
  if (!isObject(step)) return null;
  const next = {
    ...step,
    title: scrubDestructiveI18nText(step.title),
    description: scrubDestructiveI18nText(step.description),
  };
  if (step.payload) {
    const payload = scrubDestructiveText(step.payload);
    if (payload) next.payload = payload;
    else delete next.payload;
  }
  return next;
};

const scrubDestructivePayloadCommands = payload => {
  if (!isObject(payload)) return payload;
  const next = { ...payload };
  next.execution = normalizeList(next.execution).map(scrubDestructiveCommandEntry).filter(Boolean);
  const wafBypass = normalizeList(next.wafBypass).map(scrubDestructiveCommandEntry).filter(Boolean);
  if (wafBypass.length) next.wafBypass = wafBypass;
  else delete next.wafBypass;
  const attackChain = normalizeList(next.attackChain).map(scrubDestructiveAttackChainStep).filter(Boolean);
  if (attackChain.length) next.attackChain = attackChain;
  else delete next.attackChain;
  return next;
};

const commandSignature = value => String(value || '').trim().replace(/\s+/g, ' ');

const dedupeCommandEntries = entries => {
  const result = [];
  const seen = new Set();
  for (const entry of normalizeList(entries)) {
    const signature = commandSignature(entry?.command);
    if (!signature || seen.has(signature)) continue;
    seen.add(signature);
    result.push(entry);
  }
  return result;
};

const replaceI18nPhrase = (value, zhNeedle, zhReplacement, enNeedle, enReplacement) => {
  if (typeof value === 'string') {
    return value
      .replaceAll(zhNeedle, zhReplacement)
      .replaceAll(enNeedle, enReplacement);
  }
  if (isObject(value) && typeof value.zh === 'string' && typeof value.en === 'string') {
    return {
      ...value,
      zh: value.zh.replaceAll(zhNeedle, zhReplacement),
      en: value.en.replaceAll(enNeedle, enReplacement),
    };
  }
  return value;
};

const normalizeVisibleCommandTitle = title => {
  let next = replaceI18nPhrase(title, 'Burp 扩展名字典精选', '上传后缀与解析变体', 'Curated Burp extension list', 'Upload suffix and parser variants');
  next = replaceI18nPhrase(next, 'Burp WebShell 精选', 'PHP WebShell 一句话', 'Curated Burp webshell payloads', 'PHP webshell one-liners');
  next = replaceI18nPhrase(next, 'Burp PHP webshell one-liners', 'PHP WebShell 一句话', 'Burp PHP webshell one-liners', 'PHP webshell one-liners');
  next = replaceI18nPhrase(next, 'Burp upload WAF variants', '文件上传绕过变体', 'Burp upload WAF variants', 'File upload WAF variants');
  next = replaceI18nPhrase(next, 'Burp upload suffix coverage', '上传后缀覆盖集', 'Burp upload suffix coverage', 'Upload suffix coverage');
  next = replaceI18nPhrase(next, 'Burp upload WAF suffix matrix', '上传绕过后缀矩阵', 'Burp upload WAF suffix matrix', 'Upload bypass suffix matrix');
  next = replaceI18nPhrase(next, 'Burp upload body samples', '上传请求体样例', 'Burp upload body samples', 'Upload body samples');
  next = replaceI18nPhrase(next, 'Complete PHP webshell payloads', '完整 PHP WebShell 样例', 'Complete PHP webshell payloads', 'Complete PHP webshell samples');
  next = replaceI18nPhrase(next, 'Upload request bodies with webshell content', '带 WebShell 内容的上传请求体', 'Upload request bodies with webshell content', 'Upload request bodies with webshell content');
  next = replaceI18nPhrase(next, 'Content-Disposition操纵与分块上传', 'Content-Disposition 变体与分块上传', 'Content-Disposition操纵 and 分块Upload', 'Content-Disposition variants and chunked upload');
  next = replaceI18nPhrase(next, '扩展名绕过', '扩展名绕过变体', 'ExtensionnameBypass', 'Extension bypass variants');
  next = replaceI18nPhrase(next, 'Content-Type', 'Content-Type 变体', 'Content-Type', 'Content-Type variants');
  next = replaceI18nPhrase(next, 'Content-Type variants 变体', 'Content-Type 变体', 'Content-Type variants 变体', 'Content-Type variants');
  next = replaceI18nPhrase(next, 'Redirect URI', '重定向地址参数', 'Redirect URI', 'Redirect URI parameter');
  next = replaceI18nPhrase(next, 'DeleteParameter', '删除参数校验', 'DeleteParameter', 'Missing-parameter validation');
  next = replaceI18nPhrase(next, 'UseFormData', 'FormData 提交', 'UseFormData', 'FormData submission');
  next = replaceI18nPhrase(next, 'DetectFileTypeCheckMechanism', '探测文件类型检查机制', 'DetectFileTypeCheckMechanism', 'Detect file-type validation logic');
  next = replaceI18nPhrase(next, 'RequestCertificate', '请求证书', 'RequestCertificate', 'Request certificate');
  next = replaceI18nPhrase(next, 'SensitiveDataSearch', '敏感数据搜索', 'SensitiveDataSearch', 'Sensitive data search');
  next = replaceI18nPhrase(next, 'File UploadEmptybyteTruncate', '文件上传空字节截断', 'File UploadEmptybyteTruncate', 'File upload null-byte truncation');
  next = replaceI18nPhrase(next, 'Cookie readability proof payloads', 'Cookie 可读性验证样例', 'Cookie readability proof payloads', 'Cookie readability proof payloads');
  next = replaceI18nPhrase(next, 'GraphQL request bodies', 'GraphQL 请求体样例', 'GraphQL request bodies', 'GraphQL request bodies');
  next = replaceI18nPhrase(next, 'API injection request bodies', 'API 注入请求体样例', 'API injection request bodies', 'API injection request bodies');
  next = replaceI18nPhrase(next, 'API injection WAF variants', 'API 注入绕过变体', 'API injection WAF variants', 'API injection WAF variants');
  next = replaceI18nPhrase(next, 'JWT direct token variants', 'JWT 直接令牌样例', 'JWT direct token variants', 'JWT direct token variants');
  next = replaceI18nPhrase(next, 'AWD persistence command payloads', 'AWD 持久化命令样例', 'AWD persistence command payloads', 'AWD persistence command payloads');
  next = replaceI18nPhrase(next, 'Reverse callback command payloads', '反连命令样例', 'Reverse callback command payloads', 'Reverse callback command payloads');
  next = replaceI18nPhrase(next, 'JSP and JSPX webshell payloads', 'JSP/JSPX WebShell 样例', 'JSP and JSPX webshell payloads', 'JSP/JSPX webshell payloads');
  next = replaceI18nPhrase(next, 'ASP and ASP.NET webshell payloads', 'ASP/ASP.NET WebShell 样例', 'ASP and ASP.NET webshell payloads', 'ASP/ASP.NET webshell payloads');
  next = replaceI18nPhrase(next, 'Image polyglot webshell payloads', '图片马样例', 'Image polyglot webshell payloads', 'Image polyglot webshell payloads');
  next = replaceI18nPhrase(next, 'Magic-byte image webshell bodies', '图片文件头伪装样例', 'Magic-byte image webshell bodies', 'Magic-byte image webshell bodies');
  next = replaceI18nPhrase(next, 'Uploaded archive webshell wrappers', '压缩包包含包装器样例', 'Uploaded archive webshell wrappers', 'Uploaded archive wrapper samples');
  next = replaceI18nPhrase(next, 'Archive include wrapper targets', '压缩包包含目标样例', 'Archive include wrapper targets', 'Archive include wrapper targets');
  next = replaceI18nPhrase(next, 'Burp API injection bodies', 'API 注入请求体样例', 'Burp API injection bodies', 'API injection request body samples');
  next = replaceI18nPhrase(next, 'Burp API parser payloads', 'API 解析差异样例', 'Burp API parser payloads', 'API parser-difference samples');
  next = replaceI18nPhrase(next, 'Burp API parser WAF variants', 'API 解析绕过变体', 'Burp API parser WAF variants', 'API parser-bypass variants');
  next = replaceI18nPhrase(next, 'Burp API parser WAF extended', 'API 解析绕过扩展变体', 'Burp API parser WAF extended', 'Extended API parser-bypass variants');
  next = replaceI18nPhrase(next, 'Burp HTTP auth bypass request set', '认证绕过请求样例', 'Burp HTTP auth bypass request set', 'Auth-bypass request samples');
  next = replaceI18nPhrase(next, 'HTTP 403/401 bypass headers', '403/401 绕过请求头样例', 'HTTP 403/401 bypass headers', '403/401 bypass header variants');
  next = replaceI18nPhrase(next, 'Burp JWT attack payloads', 'JWT 攻击样例', 'Burp JWT attack payloads', 'JWT attack samples');
  next = replaceI18nPhrase(next, 'Burp JWT kid and role samples', 'JWT kid 与角色样例', 'Burp JWT kid and role samples', 'JWT kid and role samples');
  next = replaceI18nPhrase(next, 'Burp JWT WAF variants', 'JWT 绕过变体', 'Burp JWT WAF variants', 'JWT bypass variants');
  next = replaceI18nPhrase(next, 'Burp JWT encoded kid variants', 'JWT 编码 kid 变体', 'Burp JWT encoded kid variants', 'Encoded kid JWT variants');
  next = replaceI18nPhrase(next, 'JWT WAF header variants', 'JWT 请求头绕过变体', 'JWT WAF header variants', 'JWT header-bypass variants');
  next = replaceI18nPhrase(next, 'Burp GraphQL payloads', 'GraphQL 样例', 'Burp GraphQL payloads', 'GraphQL samples');
  next = replaceI18nPhrase(next, 'Burp GraphQL field and fragment payloads', 'GraphQL 字段与片段样例', 'Burp GraphQL field and fragment payloads', 'GraphQL field and fragment samples');
  next = replaceI18nPhrase(next, 'GraphQL WAF bypass bodies', 'GraphQL 绕过请求体', 'GraphQL WAF bypass bodies', 'GraphQL bypass request bodies');
  next = replaceI18nPhrase(next, 'Burp GraphQL WAF variants', 'GraphQL 绕过变体', 'Burp GraphQL WAF variants', 'GraphQL bypass variants');
  next = replaceI18nPhrase(next, 'Burp GraphQL batching and depth variants', 'GraphQL 批处理与深度变体', 'Burp GraphQL batching and depth variants', 'GraphQL batching and depth variants');
  next = replaceI18nPhrase(next, 'Burp command injection separators', '命令注入分隔符样例', 'Burp command injection separators', 'Command-injection separator samples');
  next = replaceI18nPhrase(next, 'Burp command WAF variants', '命令注入绕过变体', 'Burp command WAF variants', 'Command-injection bypass variants');
  next = replaceI18nPhrase(next, 'Burp command WAF separators extended', '命令注入绕过扩展变体', 'Burp command WAF separators extended', 'Extended command-injection bypass variants');
  next = replaceI18nPhrase(next, 'Burp SSRF target payloads', 'SSRF 目标样例', 'Burp SSRF target payloads', 'SSRF target samples');
  next = replaceI18nPhrase(next, 'Burp SSRF WAF variants', 'SSRF 绕过变体', 'Burp SSRF WAF variants', 'SSRF bypass variants');
  next = replaceI18nPhrase(next, 'Burp SSRF parser bypass set', 'SSRF 解析绕过变体', 'Burp SSRF parser bypass set', 'SSRF parser-bypass variants');
  next = replaceI18nPhrase(next, 'Burp XSS polyglot context set', 'XSS Polyglot 上下文样例', 'Burp XSS polyglot context set', 'XSS polyglot context samples');
  next = replaceI18nPhrase(next, 'Burp basic XSS payloads', '基础 XSS 样例', 'Burp basic XSS payloads', 'Basic XSS samples');
  next = replaceI18nPhrase(next, 'Burp XSS WAF variants', 'XSS 绕过变体', 'Burp XSS WAF variants', 'XSS bypass variants');
  next = replaceI18nPhrase(next, 'Burp XSS filter bypass extended', 'XSS 过滤绕过扩展变体', 'Burp XSS filter bypass extended', 'Extended XSS filter-bypass variants');
  next = replaceI18nPhrase(next, 'Burp Unicode and entity XSS variants', 'Unicode 与实体 XSS 变体', 'Burp Unicode and entity XSS variants', 'Unicode and entity XSS variants');
  next = replaceI18nPhrase(next, 'Stored XSS copyable probes', '存储型 XSS 样例', 'Stored XSS copyable probes', 'Stored XSS samples');
  next = replaceI18nPhrase(next, 'Comment-split, string-concat, callback, call_user_func_array, and reflection variants from the local WebShell dictionary.', '函数拆分与回调调用变体', 'Comment-split, string-concat, callback, call_user_func_array, and reflection variants from the local WebShell dictionary.', 'Split-function and callback-call variants');
  return next;
};

const normalizeVisibleCommandDescription = description => {
  let next = replaceI18nPhrase(description, '来自本地 Burp 文件上传字典，保留常见可执行扩展名、截断、NTFS ADS、分号和大小写变体。', '覆盖常见可执行扩展名、截断、NTFS ADS、分号后缀和大小写变体，适合排查上传过滤规则。', 'Curated from the local Burp upload dictionary, covering executable extensions, truncation, NTFS ADS, semicolon suffixes, and case variants.', 'Covers executable extensions, truncation, NTFS ADS, semicolon suffixes, and case variants for testing upload filters.');
  next = replaceI18nPhrase(next, 'Complete PHP webshell one-liners curated from the local Burp WebShell dictionary.', '可直接复制的 PHP 一句话 WebShell 样例，适合上传到执行链路验证。', 'Complete PHP webshell one-liners curated from the local Burp WebShell dictionary.', 'Copyable PHP webshell one-liners for validating upload-to-execution flows.');
  next = replaceI18nPhrase(next, 'Complete multipart examples with filename, MIME type, and body payload.', '完整 multipart 上传样例，包含文件名、MIME 类型和文件内容。', 'Complete multipart examples with filename, MIME type, and body payload.', 'Complete multipart upload samples with filename, MIME type, and body payload.');
  next = replaceI18nPhrase(next, '修改Content-Type', '修改请求中的 Content-Type 以验证服务端是否只依赖 MIME 类型判断文件类型。', 'ModifyContent-Type', 'Change the request Content-Type to verify whether the server relies only on MIME type checks.');
  next = replaceI18nPhrase(next, 'Localhost, file, dict, and gopher SSRF targets from the local Burp SSRF dictionary.', '覆盖本地地址、文件协议、dict 与 gopher 目标样例，适合验证服务端请求目的地限制。', 'Localhost, file, dict, and gopher SSRF targets from the local Burp SSRF dictionary.', 'Covers localhost, file, dict, and gopher target samples for validating outbound-request restrictions.');
  next = replaceI18nPhrase(next, 'Comment-split, string-concat, callback, call_user_func_array, and reflection variants from the local WebShell dictionary.', '覆盖注释拆分、字符串拼接、回调、call_user_func_array 与反射调用等函数名绕过写法。', 'Comment-split, string-concat, callback, call_user_func_array, and reflection variants from the local WebShell dictionary.', 'Covers comment-splitting, string concatenation, callback, call_user_func_array, and reflection-based function-name bypasses.');
  return next;
};

const visibleChineseDisplayOverrides = new Map([
  ['Burp SQL login and boolean payloads', 'Burp SQL 登录与布尔验证样例'],
  ['SQLi tamper WAF variants', 'SQL 注入 WAF 绕过变体'],
  ['Burp SQLi WAF tamper payloads', 'Burp SQL 注入绕过样例'],
  ['JWK/JKU header samples', 'JWK/JKU 请求头样例'],
  ['x5c/x5u header samples', 'x5c/x5u 请求头样例'],
  ['SSRF target samples', 'SSRF 目标样例'],
  ['SSRF bypass variants', 'SSRF 绕过变体'],
  ['SSRF parser-bypass variants', 'SSRF 解析绕过变体'],
  ['XMLDecoder raw SOAP payload', 'XMLDecoder 原始 SOAP 请求'],
  ['XMLDecoder command proof sample', 'XMLDecoder 命令验证样例'],
  ['Math ML', 'MathML'],
  ['Free Marker', 'FreeMarker'],
  ['Po C', 'PoC'],
]);

visibleChineseDisplayOverrides.set('MSSQL direct proof payloads', 'MSSQL 直接验证样例');
visibleChineseDisplayOverrides.set('MSSQL WAF variants', 'MSSQL WAF 绕过变体');
visibleChineseDisplayOverrides.set('MSSQL command proof variants', 'MSSQL 命令验证变体');
visibleChineseDisplayOverrides.set('Oracle direct proof payloads', 'Oracle 直接验证样例');
visibleChineseDisplayOverrides.set('Oracle WAF variants', 'Oracle WAF 绕过变体');
visibleChineseDisplayOverrides.set('PostgreSQL direct proof payloads', 'PostgreSQL 直接验证样例');
visibleChineseDisplayOverrides.set('PostgreSQL WAF variants', 'PostgreSQL WAF 绕过变体');
visibleChineseDisplayOverrides.set('SQLite direct proof payloads', 'SQLite 直接验证样例');
visibleChineseDisplayOverrides.set('SQLite WAF variants', 'SQLite WAF 绕过变体');
visibleChineseDisplayOverrides.set('MongoDB auth bypass payloads', 'MongoDB 认证绕过样例');
visibleChineseDisplayOverrides.set('Burp NoSQL operator payloads', 'Burp NoSQL 操作符样例');
visibleChineseDisplayOverrides.set('Boolean blind condition payloads', '布尔盲注条件样例');
visibleChineseDisplayOverrides.set('Time blind length payloads', '时间盲注长度样例');
visibleChineseDisplayOverrides.set('Burp time-delay probes', 'Burp 延时验证样例');
visibleChineseDisplayOverrides.set('Burp UNION column probes', 'Burp UNION 列探测样例');
visibleChineseDisplayOverrides.set('Burp DOM XSS payloads', 'Burp DOM XSS 样例');
visibleChineseDisplayOverrides.set('Burp XXE file-read payloads', 'Burp XXE 文件读取样例');
visibleChineseDisplayOverrides.set('Burp XXE WAF variants', 'Burp XXE WAF 绕过变体');
visibleChineseDisplayOverrides.set('Burp Jinja2 execution payloads', 'Burp Jinja2 执行样例');
visibleChineseDisplayOverrides.set('Jinja2 WAF object-chain variants', 'Jinja2 WAF 对象链变体');
visibleChineseDisplayOverrides.set('Burp SSTI WAF variants', 'Burp SSTI WAF 绕过变体');
visibleChineseDisplayOverrides.set('FreeMarker command proof variants', 'FreeMarker 命令验证变体');
visibleChineseDisplayOverrides.set('FreeMarker WAF variants', 'FreeMarker WAF 绕过变体');
visibleChineseDisplayOverrides.set('Velocity command proof variants', 'Velocity 命令验证变体');
visibleChineseDisplayOverrides.set('Velocity direct proof payloads', 'Velocity 直接验证样例');
visibleChineseDisplayOverrides.set('Thymeleaf command proof variants', 'Thymeleaf 命令验证变体');
visibleChineseDisplayOverrides.set('Thymeleaf direct execution payloads', 'Thymeleaf 直接执行样例');
visibleChineseDisplayOverrides.set('Thymeleaf WAF variants', 'Thymeleaf WAF 绕过变体');
visibleChineseDisplayOverrides.set('Smarty direct execution payloads', 'Smarty 直接执行样例');
visibleChineseDisplayOverrides.set('Mako direct execution payloads', 'Mako 直接执行样例');
visibleChineseDisplayOverrides.set('Tornado command proof variants', 'Tornado 命令验证变体');
visibleChineseDisplayOverrides.set('ERB command proof variants', 'ERB 命令验证变体');
visibleChineseDisplayOverrides.set('ERB direct execution payloads', 'ERB 直接执行样例');
visibleChineseDisplayOverrides.set('LFI WAF traversal variants', 'LFI WAF 路径绕过变体');
visibleChineseDisplayOverrides.set('data:// wrapper proof payloads', 'data:// 包装器验证样例');
visibleChineseDisplayOverrides.set('JSON CSRF text/plain form payloads', 'JSON CSRF text/plain 表单样例');
visibleChineseDisplayOverrides.set('SameSite top-level navigation payloads', 'SameSite 顶级导航样例');
visibleChineseDisplayOverrides.set('Log4j callback proof payloads', 'Log4j 回连验证样例');
visibleChineseDisplayOverrides.set('Fastjson AutoType bypass variants', 'Fastjson AutoType 绕过变体');
visibleChineseDisplayOverrides.set('Cookie property access variants', 'Cookie 属性访问变体');
visibleChineseDisplayOverrides.set('Keyboard event proof payloads', '键盘事件验证样例');
visibleChineseDisplayOverrides.set('Form event proof payloads', '表单事件验证样例');
const applyVisibleChineseDisplayOverrides = value => {
  if (typeof value === 'string') {
    let next = value;
    for (const [from, to] of visibleChineseDisplayOverrides) next = next.replaceAll(from, to);
    return next;
  }
  if (isObject(value) && typeof value.zh === 'string' && typeof value.en === 'string') {
    let zh = value.zh;
    for (const [from, to] of visibleChineseDisplayOverrides) zh = zh.replaceAll(from, to);
    return { ...value, zh };
  }
  return value;
};

const textLooksNonProfessionalZh = value => {
  const text = String(value || '').trim();
  if (!text) return false;
  return (
    /^Burp\b/i.test(text) ||
    /Extensionname|NTFSData|AnalyzeTools|Resetworkflow|DetectFileTypeCheckMechanism|DeleteParameter|UseFormData|RequestCertificate|SensitiveDataSearch|Emptybyte|ResponsePackage|UseImpacket|UsePowerShell|through|Obtain|Execute Command|Proxy$/i.test(text) ||
    (/^[A-Za-z0-9 .:_/\-()]+$/.test(text) && !/[a-z]{2,}/i.test(text.replace(/\b(?:SQL|JWT|XSS|SSRF|XXE|RCE|API|HTTP|HTML|XML|JSON|SOAP|SAML|OAuth|MIME|NTFS|ASP|JSP|PHP|ASP\.NET|GraphQL|Redis|MySQL|MSSQL|PostgreSQL|Oracle|Kerberos|DNS|LDAP|SMB|WMI|WinRM|DCOM|UAC|Cron|GTFOBins|Impacket|Rubeus|Mimikatz|BloodHound|Cobalt Strike|Metasploit|ThinkPHP|Spring|WeBlogic|Tomcat|Flash|BeEF)\b/g, '')))
  );
};

const looksLikeSentenceTitle = value => {
  const text = String(value || '').trim();
  if (!text) return false;
  return text.length > 36 || /dictionary|payloads|variants|sample|samples|requests|targets|probes/i.test(text);
};

const isPublicPayloadCandidate = payload => isObject(payload) && typeof payload.id === 'string' && payload.id.trim();

const filterToolNavigation = (items, toolIds) => normalizeList(items).flatMap(item => {
  const children = filterToolNavigation(item.children, toolIds);
  const hasValidTool = item.toolId && toolIds.has(item.toolId);
  if (item.toolId && !hasValidTool && !children.length) return [];
  const next = { ...item };
  if (children.length) next.children = children;
  else delete next.children;
  if (!hasValidTool) delete next.toolId;
  return next.toolId || next.children?.length ? [next] : [];
});

const filterStoredPayloadNavigation = (items, payloadIds, options = {}) => {
  const seen = options.seen || new Set();
  const depth = options.depth || 0;
  return normalizeList(items).flatMap(item => {
    const mappedPayloadId = item.payloadId ? (payloadRefAliases.get(item.payloadId) || item.payloadId) : '';
    if (shouldExcludePayloadNavigationItem(item, mappedPayloadId, depth)) return [];
    const children = filterStoredPayloadNavigation(item.children, payloadIds, { seen, depth: depth + 1 });
    const hasValidPayload = mappedPayloadId && payloadIds.has(mappedPayloadId) && !seen.has(mappedPayloadId);
    if (mappedPayloadId && !hasValidPayload && !children.length) return [];
    const next = { ...item };
    if (publicNavigationNameOverrides.has(next.id)) next.name = publicNavigationNameOverrides.get(next.id);
    if (children.length) next.children = children;
    else delete next.children;
    if (hasValidPayload) {
      next.payloadId = mappedPayloadId;
      seen.add(mappedPayloadId);
    } else {
      delete next.payloadId;
    }
    return next.payloadId || next.children?.length ? [next] : [];
  });
};

const prepareStoredPublicPayloadData = (payloads, navigation) => {
  const normalizedPayloads = normalizeList(payloads)
    .filter(payload => isObject(payload) && typeof payload.id === 'string' && payload.id.trim())
    .map(sanitizeStoredPublicPayload)
    .map(scrubDestructivePayloadCommands)
    .map(payload => scrubLowQualityEnglishContent(scrubRetiredEdrContent(payload).value).value)
    .map(sanitizeStoredPublicPayload)
    .filter(payload => normalizeList(payload.execution).length);
  const normalizedIds = new Set(normalizedPayloads.map(item => item.id));
  const publicPayloads = normalizedPayloads.filter(payload => {
    const canonicalId = payloadRefAliases.get(payload.id);
    return !(legacyJwtPayloadIds.has(payload.id) && canonicalId && normalizedIds.has(canonicalId));
  });
  const candidateIds = new Set(publicPayloads.map(item => item.id));
  return {
    payloads: publicPayloads,
    navigation: filterStoredPayloadNavigation(navigation, candidateIds),
  };
};

export const curateSeedData = seedData => {
  const payloads = normalizeList(seedData.payloads)
    .filter(isPublicPayloadCandidate)
    .map(sanitizeStoredPublicPayload)
    .filter(payload => normalizeList(payload.execution).length);
  const payloadIds = new Set(payloads.map(item => item.id));
  const tools = normalizeList(seedData.tools).map(sanitizeTool).filter(item => !excludedPublicToolIds.has(item.id) && !isSystemToolId(item.id));
  const toolIds = new Set(tools.map(item => item.id));
  return {
    ...seedData,
    payloads,
    navigation: filterStoredPayloadNavigation(normalizeList(seedData.navigation).map(sanitizeNavItem), payloadIds),
    tools,
    toolNavigation: filterToolNavigation(normalizeList(seedData.toolNavigation).map(pruneSystemNavigationItem).filter(Boolean), toolIds),
  };
};

const prepareContentItemForInsert = (item, sanitizer, trusted) => (
  trusted ? parseJson(json(item)) : sanitizer(item)
);

const insertPayloads = (database, payloads, { trusted = false } = {}) => {
  const statement = database.prepare(`
    INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  const timestamp = now();
  const usedIds = new Set();
  payloads.forEach((payload, index) => {
    const normalized = prepareContentItemForInsert(payload, sanitizePayload, trusted);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), index, timestamp, timestamp);
  });
};

const insertTools = (database, tools, { trusted = false } = {}) => {
  const statement = database.prepare(`
    INSERT INTO tools (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  const timestamp = now();
  const usedIds = new Set();
  tools.forEach((tool, index) => {
    const normalized = prepareContentItemForInsert(tool, sanitizeTool, trusted);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), index, timestamp, timestamp);
  });
};

const insertNavigation = (database, navigation, toolNavigation = [], { trusted = false } = {}) => {
  const statement = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
  `);
  const timestamp = now();
  const usedIds = new Set();
  navigation.forEach((item, index) => {
    const normalized = prepareContentItemForInsert(item, sanitizeNavItem, trusted);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), 'payloads', index, timestamp, timestamp);
  });
  toolNavigation.forEach((item, index) => {
    const normalized = prepareContentItemForInsert(item, sanitizeNavItem, trusted);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), 'tools', index, timestamp, timestamp);
  });
};

const insertNavigationKind = (database, navigation, kind) => {
  const statement = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
  `);
  const timestamp = now();
  const usedIds = new Set();
  navigation.forEach((item, index) => {
    const normalized = sanitizeNavItem(item);
    if (usedIds.has(normalized.id)) {
      normalized.id = `${normalized.id}-${index}`;
    }
    usedIds.add(normalized.id);
    statement.run(normalized.id, json(normalized), kind, index, timestamp, timestamp);
  });
};

const replaceContentData = (database, seedData, { trusted = false } = {}) => {
  database.prepare('DELETE FROM payloads').run();
  database.prepare('DELETE FROM tools').run();
  database.prepare('DELETE FROM navigation_nodes').run();
  insertPayloads(database, normalizeList(seedData.payloads), { trusted });
  insertTools(database, normalizeList(seedData.tools), { trusted });
  insertNavigation(database, normalizeList(seedData.navigation), normalizeList(seedData.toolNavigation), { trusted });
};

export const writeDefaultSeedDatabase = async (seedData, file = defaultSeedDbFile, source = 'database content seed') => {
  return enqueueMutation(async () => {
    await mkdir(dirname(file), { recursive: true });
    const tempFile = join(dirname(file), `.default-seed-${makeSeedArtifactId()}.sqlite`);
    const seedDatabase = new DatabaseSync(tempFile);
    try {
      seedDatabase.exec('PRAGMA journal_mode = DELETE;');
      seedDatabase.exec('PRAGMA synchronous = FULL;');
      initializeContentDatabase(seedDatabase);
      runTransaction(seedDatabase, () => {
        replaceContentData(seedDatabase, seedData);
        writeMetadata(seedDatabase, 'seed_schema_version', defaultSeedSchemaVersion);
        writeMetadata(seedDatabase, 'content_kind', defaultSeedContentKind);
        writeMetadata(seedDatabase, 'generated_at', now());
        writeMetadata(seedDatabase, 'source', source);
      });
    } finally {
      seedDatabase.close();
    }
    await rename(tempFile, file);
    return file;
  });
};

const upsertItems = (database, resource, items) => {
  const { table, dataColumn, sanitizer } = tableForResource(resource);
  const timestamp = now();
  let nextSortOrder = database.prepare(`SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM ${table}`).get().next;
  const existingStatement = database.prepare(`SELECT sort_order FROM ${table} WHERE id = ?`);
  const statement = database.prepare(`
    INSERT INTO ${table} (id, ${dataColumn}, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      ${dataColumn} = excluded.${dataColumn},
      updated_at = excluded.updated_at
  `);
  items.forEach(item => {
    const normalized = sanitizer(item);
    const existing = existingStatement.get(normalized.id);
    const sortOrder = existing?.sort_order ?? nextSortOrder++;
    statement.run(normalized.id, json(normalized), sortOrder, timestamp, timestamp);
  });
};

const upsertNavigationKind = (database, navigation, kind) => {
  const timestamp = now();
  let nextSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = ?').get(kind).next;
  const existingStatement = database.prepare('SELECT sort_order FROM navigation_nodes WHERE id = ?');
  const statement = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      tree = excluded.tree,
      kind = excluded.kind,
      updated_at = excluded.updated_at
  `);
  navigation.forEach(item => {
    const normalized = sanitizeNavItem(item);
    const existing = existingStatement.get(normalized.id);
    const sortOrder = existing?.sort_order ?? nextSortOrder++;
    statement.run(normalized.id, json(normalized), kind, sortOrder, timestamp, timestamp);
  });
};

const findById = (items, id) => normalizeList(items).find(item => item?.id === id);

const shouldExcludePayload = payload => (
  modeOnlyPayloadIds.has(payload?.id) ||
  (
    !showAllPublicPayloads &&
    (
      payloadVisibilityRules.payloadIds.has(payload?.id) ||
      String(payload?.id || '').startsWith('evasion-') ||
      payloadVisibilityRules.categories.has(textValue(payload?.category))
    )
  )
);

const shouldExcludePayloadNavigationItem = (item, payloadId, depth = 0) => (
  modeOnlyPayloadIds.has(payloadId) ||
  (
    !showAllPublicPayloads &&
    (
      depth === 0 && payloadVisibilityRules.rootIds.has(item?.id) ||
      payloadVisibilityRules.nodeIds.has(item?.id) ||
      payloadVisibilityRules.payloadIds.has(payloadId)
    )
  )
);

const prunePayloadNavigation = item => {
  let changed = false;
  const next = { ...item };
  const currentPayloadId = next.payloadId ? (payloadRefAliases.get(next.payloadId) || next.payloadId) : '';

  if (shouldExcludePayloadNavigationItem(next, currentPayloadId)) {
    return { item: null, changed: true };
  }

  for (const migration of legacyNavigationPayloadRefMigrations) {
    if (next.id === migration.nodeId && next.payloadId === migration.from) {
      next.payloadId = migration.to;
      changed = true;
    }
  }

  const children = [];
  for (const child of normalizeList(next.children)) {
    const result = prunePayloadNavigation(child);
    if (result.changed) changed = true;
    if (result.item) children.push(result.item);
  }
  if (children.length) next.children = children;
  else if (next.children) {
    delete next.children;
    changed = true;
  }

  return { item: next, changed };
};

const mergeDefaultNavigationItem = (currentItem, defaultItem) => {
  let changed = false;
  const next = { ...currentItem };
  if (!next.icon && defaultItem.icon) {
    next.icon = defaultItem.icon;
    changed = true;
  }
  if (!next.payloadId && defaultItem.payloadId) {
    next.payloadId = defaultItem.payloadId;
    changed = true;
  }
  if (!next.toolId && defaultItem.toolId) {
    next.toolId = defaultItem.toolId;
    changed = true;
  }

  const children = normalizeList(next.children).map(child => ({ ...child }));
  const defaultChildren = normalizeList(defaultItem.children);
  for (const defaultChild of defaultChildren) {
    const existingIndex = children.findIndex(child => child.id === defaultChild.id);
    if (existingIndex === -1) {
      children.push(cloneValue(defaultChild));
      changed = true;
      continue;
    }
    const merged = mergeDefaultNavigationItem(children[existingIndex], defaultChild);
    if (merged.changed) {
      children[existingIndex] = merged.item;
      changed = true;
    }
  }

  if (children.length) next.children = children;
  else delete next.children;

  return { item: next, changed };
};

const restoreAllPayloadPublicData = (database, defaults) => {
  const timestamp = now();
  const existingPayloadIds = new Set(database.prepare('SELECT id FROM payloads').all().map(row => row.id));
  const insertPayload = database.prepare(`
    INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextPayloadSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM payloads').get().next;

  for (const payload of normalizeList(defaults.payloads)) {
    const normalized = sanitizePayload(payload);
    if (existingPayloadIds.has(normalized.id)) continue;
    insertPayload.run(normalized.id, json(normalized), nextPayloadSortOrder++, timestamp, timestamp);
    existingPayloadIds.add(normalized.id);
  }

  const navigationRows = database.prepare(`
    SELECT id, tree, sort_order
    FROM navigation_nodes
    WHERE kind = 'payloads'
    ORDER BY sort_order, id
  `).all();
  const navigationRowsById = new Map(navigationRows.map(row => [row.id, row]));
  const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
  const insertNavigation = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, 'payloads', ?, 1, ?, ?)
  `);
  let nextNavigationSortOrder = database.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = 'payloads'").get().next;

  for (const defaultItem of normalizeList(defaults.navigation)) {
    const normalizedDefault = sanitizeNavItem(defaultItem);
    const row = navigationRowsById.get(normalizedDefault.id);
    if (!row) {
      insertNavigation.run(normalizedDefault.id, json(normalizedDefault), nextNavigationSortOrder++, timestamp, timestamp);
      continue;
    }
    const current = sanitizeNavItem(parseJson(row.tree) || normalizedDefault);
    const merged = mergeDefaultNavigationItem(current, normalizedDefault);
    const patched = patchLegacyNavigationPayloadRefs(merged.item);
    if (merged.changed || patched.changed) {
      updateNavigation.run(json(sanitizeNavItem(patched.item)), timestamp, normalizedDefault.id);
    }
  }
};

const mergeDefaultToolNavigationItem = (currentItem, defaultItem) => {
  let changed = false;
  const next = { ...currentItem };
  if (!next.icon && defaultItem.icon) {
    next.icon = defaultItem.icon;
    changed = true;
  }
  if (!next.toolId && defaultItem.toolId) {
    next.toolId = defaultItem.toolId;
    changed = true;
  }

  const children = normalizeList(next.children).map(child => ({ ...child }));
  const defaultChildren = normalizeList(defaultItem.children);
  for (const defaultChild of defaultChildren) {
    const existingIndex = children.findIndex(child => child.id === defaultChild.id);
    if (existingIndex === -1) {
      children.push(cloneValue(defaultChild));
      changed = true;
      continue;
    }
    const merged = mergeDefaultToolNavigationItem(children[existingIndex], defaultChild);
    if (merged.changed) {
      children[existingIndex] = merged.item;
      changed = true;
    }
  }

  if (children.length) next.children = children;
  else delete next.children;

  return { item: next, changed };
};

const migrateMissingDefaultTools = (database, defaults) => {
  const timestamp = now();
  const existingToolIds = new Set(database.prepare('SELECT id FROM tools').all().map(row => row.id));
  const insertTool = database.prepare(`
    INSERT INTO tools (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextToolSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM tools').get().next;

  for (const tool of normalizeList(defaults.tools)) {
    const normalized = sanitizeTool(tool);
    if (existingToolIds.has(normalized.id)) continue;
    insertTool.run(normalized.id, json(normalized), nextToolSortOrder++, timestamp, timestamp);
    existingToolIds.add(normalized.id);
  }

  const toolNavigationRows = database.prepare(`
    SELECT id, tree, sort_order
    FROM navigation_nodes
    WHERE kind = 'tools'
    ORDER BY sort_order, id
  `).all();
  const toolNavigationRowsById = new Map(toolNavigationRows.map(row => [row.id, row]));
  const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
  const insertNavigationNode = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, 'tools', ?, 1, ?, ?)
  `);
  let nextNavigationSortOrder = database.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = 'tools'").get().next;

  for (const defaultItem of normalizeList(defaults.toolNavigation)) {
    const normalizedDefault = sanitizeNavItem(defaultItem);
    const row = toolNavigationRowsById.get(normalizedDefault.id);
    if (!row) {
      insertNavigationNode.run(normalizedDefault.id, json(normalizedDefault), nextNavigationSortOrder++, timestamp, timestamp);
      continue;
    }
    const current = sanitizeNavItem(parseJson(row.tree) || normalizedDefault);
    const merged = mergeDefaultToolNavigationItem(current, normalizedDefault);
    if (merged.changed) updateNavigation.run(json(sanitizeNavItem(merged.item)), timestamp, normalizedDefault.id);
  }
};

const patchLegacyNavigationPayloadRefs = item => {
  let changed = false;
  const next = { ...item };
  for (const migration of legacyNavigationPayloadRefMigrations) {
    if (next.id === migration.nodeId && next.payloadId === migration.from) {
      next.payloadId = migration.to;
      changed = true;
    }
  }
  const children = normalizeList(next.children).map(child => {
    const result = patchLegacyNavigationPayloadRefs(child);
    if (result.changed) changed = true;
    return result.item;
  });
  if (children.length) next.children = children;
  else delete next.children;
  return { item: next, changed };
};

const shouldUpgradeBusinessLogicPayload = payload => {
  if (!businessLogicPayloadIds.has(payload?.id)) return false;
  return (
    !normalizeList(payload.attackChain).length ||
    !payload.analysis ||
    !payload.tutorial ||
    !normalizeList(payload.references).length
  );
};

const migrateBusinessLogicPayloads = (database, defaults) => {
  const timestamp = now();
  const defaultsById = new Map(defaults.payloads
    .filter(payload => businessLogicPayloadIds.has(payload.id))
    .map(payload => [payload.id, sanitizePayload(payload)]));
  const selectPayload = database.prepare('SELECT id, data FROM payloads WHERE id = ?');
  const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
  const insertPayload = database.prepare(`
    INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextPayloadSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM payloads').get().next;

  for (const [id, payload] of defaultsById) {
    const row = selectPayload.get(id);
    if (!row) {
      insertPayload.run(payload.id, json(payload), nextPayloadSortOrder++, timestamp, timestamp);
      continue;
    }
    const current = parseJson(row.data);
    if (shouldUpgradeBusinessLogicPayload(current)) {
      updatePayload.run(json(payload), timestamp, id);
    }
  }

  const navigationRows = database.prepare(`
    SELECT id, tree, sort_order
    FROM navigation_nodes
    WHERE kind = 'payloads'
    ORDER BY sort_order, id
  `).all();
  const navigation = navigationRows.map(row => parseJson(row.tree)).filter(Boolean);
  const ensured = ensureBusinessLogicNavigation(navigation);
  if (!ensured.changed) return;

  const existingNavigationRows = new Map(navigationRows.map(row => [row.id, row]));
  const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
  const insertNavigation = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, 'payloads', ?, 1, ?, ?)
  `);
  let nextNavigationSortOrder = database.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = 'payloads'").get().next;
  for (const item of ensured.items) {
    const normalized = sanitizeNavItem(item);
    const row = existingNavigationRows.get(normalized.id);
    if (row) {
      updateNavigation.run(json(normalized), timestamp, normalized.id);
    } else {
      insertNavigation.run(normalized.id, json(normalized), nextNavigationSortOrder++, timestamp, timestamp);
    }
  }
};

const shouldUpgradeJwtPayload = payload => {
  if (!jwtCanonicalPayloadIds.includes(payload?.id)) return false;
  return (
    !normalizeList(payload.execution).length ||
    !normalizeList(payload.attackChain).length ||
    !payload.tutorial ||
    !payload.tutorial.overview ||
    !payload.tutorial.vulnerability ||
    !payload.tutorial.mitigation
  );
};

const migrateJwtSecurityDefaults = (database, defaults) => {
  const timestamp = now();
  const defaultsById = new Map(defaults.payloads
    .filter(payload => jwtCanonicalPayloadIds.includes(payload.id))
    .map(payload => [payload.id, sanitizePayload(payload)]));
  const selectPayload = database.prepare('SELECT id, data FROM payloads WHERE id = ?');
  const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
  const insertPayload = database.prepare(`
    INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, ?, 1, ?, ?)
  `);
  let nextPayloadSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM payloads').get().next;

  for (const id of jwtCanonicalPayloadIds) {
    const payload = defaultsById.get(id);
    if (!payload) continue;
    const row = selectPayload.get(id);
    if (!row) {
      insertPayload.run(payload.id, json(payload), nextPayloadSortOrder++, timestamp, timestamp);
      continue;
    }
    const current = parseJson(row.data);
    if (shouldUpgradeJwtPayload(current)) {
      updatePayload.run(json(payload), timestamp, id);
    }
  }

  const navigationRows = database.prepare(`
    SELECT id, tree, sort_order
    FROM navigation_nodes
    WHERE kind = 'payloads'
    ORDER BY sort_order, id
  `).all();
  const navigation = navigationRows.map(row => parseJson(row.tree)).filter(Boolean);
  const ensured = ensureJwtSecurityNavigation(navigation);
  if (!ensured.changed) return;

  const existingNavigationRows = new Map(navigationRows.map(row => [row.id, row]));
  const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
  const insertNavigation = database.prepare(`
    INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
    VALUES (?, ?, 'payloads', ?, 1, ?, ?)
  `);
  let nextNavigationSortOrder = database.prepare("SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = 'payloads'").get().next;
  for (const item of ensured.items) {
    const normalized = sanitizeNavItem(item);
    const row = existingNavigationRows.get(normalized.id);
    if (row) {
      updateNavigation.run(json(normalized), timestamp, normalized.id);
    } else {
      insertNavigation.run(normalized.id, json(normalized), nextNavigationSortOrder++, timestamp, timestamp);
    }
  }
};

const normalizePayloadContentPresentation = payload => {
  if (!isObject(payload)) return payload;
  const normalizeEntry = entry => {
    if (!isObject(entry)) return entry;
    const title = applyVisibleChineseDisplayOverrides(normalizeVisibleCommandTitle(entry.title));
    const description = applyVisibleChineseDisplayOverrides(normalizeVisibleCommandDescription(entry.description));
    const nextTitle = isObject(title) ? { ...title } : title;
    const nextDescription = isObject(description) ? { ...description } : description;
    if (isObject(nextTitle) && textLooksNonProfessionalZh(nextTitle.zh)) {
      if (typeof nextTitle.en === 'string' && nextTitle.en.trim() && !textLooksNonProfessionalZh(nextTitle.en)) nextTitle.zh = nextTitle.en;
      else if (isObject(nextDescription) && typeof nextDescription.zh === 'string' && nextDescription.zh.trim()) nextTitle.zh = nextDescription.zh;
    }
    if (isObject(nextTitle) && looksLikeSentenceTitle(nextTitle.zh) && isObject(nextDescription) && typeof nextDescription.zh === 'string' && nextDescription.zh.trim()) {
      if (/函数拆分|回调|反射/.test(nextDescription.zh)) nextTitle.zh = '函数拆分与回调调用变体';
      if (/Content-Type/.test(nextDescription.zh)) nextTitle.zh = 'Content-Type 变体';
      if (/SSRF|本地地址|gopher|dict/.test(nextDescription.zh)) nextTitle.zh = 'SSRF 目标样例';
    }
    if (isObject(nextDescription) && textLooksNonProfessionalZh(nextDescription.zh)) {
      if (typeof nextDescription.en === 'string' && nextDescription.en.trim() && !textLooksNonProfessionalZh(nextDescription.en)) nextDescription.zh = nextDescription.en;
    }
    return {
      ...entry,
      title: nextTitle,
      description: nextDescription,
    };
  };
  const next = {
    ...payload,
    execution: normalizeList(payload.execution).map(normalizeEntry),
    wafBypass: normalizeList(payload.wafBypass).map(normalizeEntry),
  };
  return next;
};

const migratePayloadContentPresentation = database => {
  const timestamp = now();
  const rows = database.prepare('SELECT id, data FROM payloads').all();
  const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
  for (const row of rows) {
    const payload = parseJson(row.data);
    if (!payload) continue;
    const normalized = sanitizePayload(normalizePayloadContentPresentation(payload));
    const serialized = json(normalized);
    if (serialized !== row.data) updatePayload.run(serialized, timestamp, row.id);
  }
};

export const seedIncludedMigrationKeys = Object.freeze([
  'migration_file_upload_basic',
  'migration_remove_edr_evasion',
  'migration_scrub_retired_edr_text',
  'migration_restore_all_payload_public_data_v1',
  'migration_business_logic_quality_v1',
  'migration_jwt_security_navigation_v1',
  'migration_payload_quality_defaults_v1',
  'migration_payload_quality_context_v2',
  'migration_payload_domain_quality_v3',
  'migration_extended_burp_dictionary_payloads_v1',
  'migration_payload_content_presentation_v4',
  'migration_missing_default_tools_v3',
  'migration_project_attribution_v1',
]);

const applyDataMigrations = async database => {
  const defaults = await loadDefaultData();
  const uploadBasicPayload = findById(defaults.payloads, 'file-upload-basic');

  if (readMetadata(database, 'migration_file_upload_basic') !== '1') {
    runTransaction(database, () => {
      const timestamp = now();
      if (uploadBasicPayload) {
        const exists = database.prepare('SELECT id FROM payloads WHERE id = ?').get(uploadBasicPayload.id);
        if (!exists) {
          const nextSortOrder = database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM payloads').get().next;
          const normalized = sanitizePayload(uploadBasicPayload);
          database.prepare(`
            INSERT INTO payloads (id, data, sort_order, enabled, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
          `).run(normalized.id, json(normalized), nextSortOrder, timestamp, timestamp);
        }
      }

      const rows = database.prepare("SELECT id, tree FROM navigation_nodes WHERE kind = 'payloads'").all();
      const update = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
      for (const row of rows) {
        const tree = parseJson(row.tree);
        if (!tree) continue;
        const result = patchLegacyNavigationPayloadRefs(tree);
        if (result.changed) update.run(json(sanitizeNavItem(result.item)), timestamp, row.id);
      }
      writeMetadata(database, 'migration_file_upload_basic', '1');
      writeMetadata(database, 'migration_file_upload_basic_at', timestamp);
    });
  }

  if (readMetadata(database, 'migration_remove_edr_evasion') !== '1') {
    runTransaction(database, () => {
      const timestamp = now();
      const deletePayload = database.prepare('DELETE FROM payloads WHERE id = ?');
      const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
      const payloadRows = database.prepare('SELECT id, data FROM payloads').all();
      for (const row of payloadRows) {
        const payload = parseJson(row.data);
        if (!payload) continue;
        if (shouldExcludePayload(payload)) {
          deletePayload.run(row.id);
          continue;
        }
        if (Object.prototype.hasOwnProperty.call(payload, 'edrBypass')) {
          delete payload.edrBypass;
          updatePayload.run(json(sanitizePayload(payload)), timestamp, row.id);
        }
      }

      const deleteTool = database.prepare('DELETE FROM tools WHERE id = ?');
      for (const id of excludedPublicToolIds) {
        deleteTool.run(id);
      }

      const rows = database.prepare("SELECT id, tree FROM navigation_nodes WHERE kind = 'payloads'").all();
      const deleteNavigation = database.prepare('DELETE FROM navigation_nodes WHERE id = ?');
      const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
      for (const row of rows) {
        const tree = parseJson(row.tree);
        if (!tree) continue;
        const result = prunePayloadNavigation(tree);
        if (!result.item) {
          deleteNavigation.run(row.id);
        } else if (result.changed) {
          updateNavigation.run(json(sanitizeNavItem(result.item)), timestamp, row.id);
        }
      }

      const toolRows = database.prepare("SELECT id, tree FROM navigation_nodes WHERE kind = 'tools'").all();
      for (const row of toolRows) {
        const tree = parseJson(row.tree);
        if (!tree) continue;
        const filtered = filterToolNavigation([tree], new Set(
          rowsToItems(database.prepare('SELECT data FROM tools WHERE enabled = 1 ORDER BY sort_order, id').all()).map(item => item.id)
        ));
        if (!filtered.length) deleteNavigation.run(row.id);
        else updateNavigation.run(json(sanitizeNavItem(filtered[0])), timestamp, row.id);
      }

      writeMetadata(database, 'migration_remove_edr_evasion', '1');
      writeMetadata(database, 'migration_remove_edr_evasion_at', timestamp);
    });
  }

  if (readMetadata(database, 'migration_scrub_retired_edr_text') !== '1') {
    runTransaction(database, () => {
      const timestamp = now();
      const deletePayload = database.prepare('DELETE FROM payloads WHERE id = ?');
      const updatePayload = database.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
      const payloadRows = database.prepare('SELECT id, data FROM payloads').all();
      for (const row of payloadRows) {
        const payload = parseJson(row.data);
        if (!payload) continue;
        if (shouldExcludePayload(payload)) {
          deletePayload.run(row.id);
          continue;
        }
        const scrubbed = scrubRetiredEdrContent(payload);
        if (scrubbed.changed) updatePayload.run(json(sanitizePayload(scrubbed.value)), timestamp, row.id);
      }

      const deleteTool = database.prepare('DELETE FROM tools WHERE id = ?');
      const updateTool = database.prepare('UPDATE tools SET data = ?, updated_at = ? WHERE id = ?');
      const toolRows = database.prepare('SELECT id, data FROM tools').all();
      for (const row of toolRows) {
        const tool = parseJson(row.data);
        if (!tool) continue;
        if (excludedPublicToolIds.has(row.id) || excludedPublicToolIds.has(tool.id)) {
          deleteTool.run(row.id);
          continue;
        }
        const scrubbed = scrubRetiredEdrContent(tool);
        if (scrubbed.changed) updateTool.run(json(sanitizeTool(scrubbed.value)), timestamp, row.id);
      }

      const deleteNavigation = database.prepare('DELETE FROM navigation_nodes WHERE id = ?');
      const updateNavigation = database.prepare('UPDATE navigation_nodes SET tree = ?, updated_at = ? WHERE id = ?');
      const navigationRows = database.prepare('SELECT id, kind, tree FROM navigation_nodes').all();
      for (const row of navigationRows) {
        const tree = parseJson(row.tree);
        if (!tree) continue;
        let next = tree;
        let changed = false;
        if (row.kind === 'payloads') {
          const pruned = prunePayloadNavigation(next);
          if (!pruned.item) {
            deleteNavigation.run(row.id);
            continue;
          }
          next = pruned.item;
          changed = pruned.changed;
        }
        const scrubbed = scrubRetiredEdrContent(next);
        changed = changed || scrubbed.changed;
        if (changed) updateNavigation.run(json(sanitizeNavItem(scrubbed.value)), timestamp, row.id);
      }

      writeMetadata(database, 'migration_scrub_retired_edr_text', '1');
      writeMetadata(database, 'migration_scrub_retired_edr_text_at', timestamp);
    });
  }

  if (readMetadata(database, 'migration_restore_all_payload_public_data_v1') !== '1') {
    runTransaction(database, () => {
      restoreAllPayloadPublicData(database, defaults);
      writeMetadata(database, 'migration_restore_all_payload_public_data_v1', '1');
      writeMetadata(database, 'migration_restore_all_payload_public_data_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_business_logic_quality_v1') !== '1') {
    runTransaction(database, () => {
      migrateBusinessLogicPayloads(database, defaults);
      writeMetadata(database, 'migration_business_logic_quality_v1', '1');
      writeMetadata(database, 'migration_business_logic_quality_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_jwt_security_navigation_v1') !== '1') {
    runTransaction(database, () => {
      migrateJwtSecurityDefaults(database, defaults);
      writeMetadata(database, 'migration_jwt_security_navigation_v1', '1');
      writeMetadata(database, 'migration_jwt_security_navigation_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_payload_quality_defaults_v1') !== '1') {
    runTransaction(database, () => {
      writeMetadata(database, 'migration_payload_quality_defaults_v1', '1');
      writeMetadata(database, 'migration_payload_quality_defaults_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_payload_quality_context_v2') !== '1') {
    runTransaction(database, () => {
      writeMetadata(database, 'migration_payload_quality_context_v2', '1');
      writeMetadata(database, 'migration_payload_quality_context_v2_at', now());
    });
  }

  if (readMetadata(database, 'migration_payload_domain_quality_v3') !== '1') {
    runTransaction(database, () => {
      writeMetadata(database, 'migration_payload_domain_quality_v3', '1');
      writeMetadata(database, 'migration_payload_domain_quality_v3_at', now());
    });
  }

  if (readMetadata(database, 'migration_extended_burp_dictionary_payloads_v1') !== '1') {
    runTransaction(database, () => {
      writeMetadata(database, 'migration_extended_burp_dictionary_payloads_v1', '1');
      writeMetadata(database, 'migration_extended_burp_dictionary_payloads_v1_at', now());
    });
  }

  if (readMetadata(database, 'migration_payload_content_presentation_v4') !== '1') {
    runTransaction(database, () => {
      migratePayloadContentPresentation(database);
      writeMetadata(database, 'migration_payload_content_presentation_v4', '1');
      writeMetadata(database, 'migration_payload_content_presentation_v4_at', now());
    });
  }

  if (readMetadata(database, 'migration_missing_default_tools_v3') !== '1') {
    runTransaction(database, () => {
      migrateMissingDefaultTools(database, defaults);
      writeMetadata(database, 'migration_missing_default_tools_v3', '1');
      writeMetadata(database, 'migration_missing_default_tools_v3_at', now());
    });
  }

  if (readMetadata(database, 'migration_project_attribution_v1') !== '1') {
    runTransaction(database, () => {
      const settings = sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings));
      writeMetadata(database, 'settings', json(settings));
      writeMetadata(database, 'migration_project_attribution_v1', '1');
      writeMetadata(database, 'migration_project_attribution_v1_at', now());
    });
  }
};

const seedIfNeeded = async database => {
  if (readMetadata(database, 'seeded') === '1') return;
  const defaults = await loadDefaultData();
  runTransaction(database, () => {
    const timestamp = now();
    replaceContentData(database, defaults, { trusted: true });
    writeMetadata(database, 'settings', json(defaultSettings));
    writeMetadata(database, 'seeded', '1');
    writeMetadata(database, 'seeded_at', timestamp);
    writeMetadata(database, 'schema_version', '1');
    for (const migrationKey of seedIncludedMigrationKeys) {
      writeMetadata(database, migrationKey, '1');
      writeMetadata(database, `${migrationKey}_at`, timestamp);
    }
  });
};

const resetTargets = new Set(['all', 'payloads', 'tools', 'navigation', 'settings']);
const resetScopeKeys = ['payloads', 'tools', 'navigation', 'toolNavigation', 'settings'];

const validateResetTarget = value => {
  if (typeof value !== 'string' || !resetTargets.has(value)) {
    const error = new Error('Invalid reset target.');
    error.status = 400;
    throw error;
  }
  return value;
};

const affectedResetScopes = target => {
  if (target === 'all') return [...resetScopeKeys];
  if (target === 'navigation') return ['navigation', 'toolNavigation'];
  return [target];
};

const readResetState = database => ({
  payloads: rowsToItems(database.prepare('SELECT data FROM payloads ORDER BY sort_order, id').all()),
  tools: rowsToItems(database.prepare('SELECT data FROM tools ORDER BY sort_order, id').all())
    .filter(item => !isSystemToolId(item.id)),
  navigation: rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE kind = 'payloads' ORDER BY sort_order, id").all()),
  toolNavigation: rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE kind = 'tools' ORDER BY sort_order, id").all())
    .map(pruneSystemNavigationItem)
    .filter(Boolean),
  settings: sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings)),
  xeyeEnabled: isXeyeEnabled(database),
});

const makeSeedResetState = defaults => ({
  payloads: normalizeList(defaults.payloads).map(item => prepareContentItemForInsert(item, sanitizePayload, true)),
  tools: normalizeList(defaults.tools)
    .map(item => prepareContentItemForInsert(item, sanitizeTool, true))
    .filter(item => !isSystemToolId(item.id)),
  navigation: normalizeList(defaults.navigation).map(item => prepareContentItemForInsert(item, sanitizeNavItem, true)),
  toolNavigation: normalizeList(defaults.toolNavigation)
    .map(item => prepareContentItemForInsert(item, sanitizeNavItem, true))
    .map(pruneSystemNavigationItem)
    .filter(Boolean),
  settings: sanitizeSettings(defaultSettings),
  xeyeEnabled: true,
});

const countResetState = state => ({
  payloads: state.payloads.length,
  tools: state.tools.length,
  navigation: state.navigation.length,
  toolNavigation: state.toolNavigation.length,
  settings: 1,
});

const diffResetItems = (beforeItems, seedItems, affected) => {
  const beforeById = new Map(beforeItems.map(item => [String(item.id || ''), json(item)]));
  const seedById = new Map(seedItems.map(item => [String(item.id || ''), json(item)]));
  let added = 0;
  let removed = 0;
  let changed = 0;
  let unchanged = 0;

  for (const [id, value] of beforeById) {
    if (!seedById.has(id)) removed += 1;
    else if (seedById.get(id) === value) unchanged += 1;
    else changed += 1;
  }
  for (const id of seedById.keys()) {
    if (!beforeById.has(id)) added += 1;
  }
  return { affected, added, removed, changed, unchanged };
};

const createResetImpact = (target, beforeState, seedState) => {
  const affected = affectedResetScopes(target);
  const affectedSet = new Set(affected);
  const before = countResetState(beforeState);
  const seed = countResetState(seedState);
  const delta = Object.fromEntries(resetScopeKeys.map(key => [
    key,
    affectedSet.has(key) ? seed[key] - before[key] : 0,
  ]));
  return {
    target,
    affected,
    before,
    seed,
    delta,
    changes: {
      payloads: diffResetItems(beforeState.payloads, seedState.payloads, affectedSet.has('payloads')),
      tools: diffResetItems(beforeState.tools, seedState.tools, affectedSet.has('tools')),
      navigation: diffResetItems(beforeState.navigation, seedState.navigation, affectedSet.has('navigation')),
      toolNavigation: diffResetItems(beforeState.toolNavigation, seedState.toolNavigation, affectedSet.has('toolNavigation')),
      settings: {
        affected: affectedSet.has('settings'),
        changed: json(beforeState.settings) !== json(seedState.settings),
      },
    },
    integrations: {
      xeye: {
        affected: affectedSet.has('tools'),
        before: beforeState.xeyeEnabled,
        seed: seedState.xeyeEnabled,
        changed: affectedSet.has('tools') && beforeState.xeyeEnabled !== seedState.xeyeEnabled,
      },
    },
  };
};

const makeResetBackupFileName = target => {
  const timestamp = now().replace(/[^0-9A-Za-z-]/g, '-');
  return `payloader-before-reset-${target}-${timestamp}-${makeSeedArtifactId()}.sqlite`;
};

const assertBackupPath = path => {
  const pathFromBackupDir = relative(backupDir, path);
  const firstSegment = pathFromBackupDir.split(/[\\/]/, 1)[0];
  if (!pathFromBackupDir || isAbsolute(pathFromBackupDir) || firstSegment === '..') {
    throw new Error('Unable to create reset backup outside the backup directory.');
  }
};

const verifyBackupIntegrity = path => {
  const backupDatabase = new DatabaseSync(path, { readOnly: true });
  try {
    const results = backupDatabase.prepare('PRAGMA integrity_check').all();
    const valid = results.length === 1 && Object.values(results[0])[0] === 'ok';
    if (!valid) throw new Error('Reset backup failed SQLite integrity validation.');
  } finally {
    backupDatabase.close();
  }
};

const createResetBackup = async (database, target) => {
  await mkdir(backupDir, { recursive: true });
  const fileName = makeResetBackupFileName(target);
  const path = join(backupDir, fileName);
  assertBackupPath(path);
  const createdAt = now();
  let method;
  let pages = null;

  try {
    if (typeof storeTestHooks.beforeResetBackup === 'function') {
      await storeTestHooks.beforeResetBackup({ target });
    }
    if (typeof sqlite.backup === 'function') {
      pages = await sqlite.backup(database, path);
      method = 'node:sqlite.backup';
    } else {
      const checkpoint = database.prepare('PRAGMA wal_checkpoint(FULL)').get();
      if (Number(checkpoint?.busy || 0) !== 0) {
        throw new Error('Unable to checkpoint the SQLite WAL before reset backup.');
      }
      database.prepare('VACUUM INTO ?').run(path);
      method = 'checkpoint-vacuum-into';
    }
    verifyBackupIntegrity(path);
    const file = await stat(path);
    return {
      fileName,
      path: `backups/${fileName}`,
      createdAt,
      sizeBytes: file.size,
      pages,
      method,
      integrity: 'ok',
    };
  } catch (error) {
    await rm(path, { force: true }).catch(() => {});
    throw error;
  }
};

export const getResetImpact = async value => {
  const target = validateResetTarget(value);
  const [database, defaults] = await Promise.all([getDb(), loadDefaultData()]);
  return createResetImpact(target, readResetState(database), makeSeedResetState(defaults));
};

export const createDataExportPackage = async () => {
  const database = await getDb();
  const state = readResetState(database);
  const summary = countResetState(state);
  return {
    format: 'payloader.export.v1',
    version: 1,
    generatedAt: now(),
    summary,
    data: {
      settings: state.settings,
      payloads: state.payloads,
      tools: state.tools,
      navigation: state.navigation,
      toolNavigation: state.toolNavigation,
    },
  };
};

export const resetDefaultData = value => {
  const target = validateResetTarget(value);
  return enqueueMutation(async () => {
    const [database, defaults] = await Promise.all([getDb(), loadDefaultData()]);
    const seedState = makeSeedResetState(defaults);
    const backup = await createResetBackup(database, target);
    const impact = createResetImpact(target, readResetState(database), seedState);

    runTransaction(database, () => {
      const timestamp = now();
      if (target === 'all' || target === 'payloads') {
        database.prepare('DELETE FROM payloads').run();
        insertPayloads(database, seedState.payloads, { trusted: true });
      }
      if (target === 'all' || target === 'tools') {
        database.prepare('DELETE FROM tools').run();
        insertTools(database, seedState.tools, { trusted: true });
        writeMetadata(database, xeyeDisabledMetadataKey, '0');
      }
      if (target === 'all' || target === 'navigation') {
        database.prepare('DELETE FROM navigation_nodes').run();
        insertNavigation(database, seedState.navigation, seedState.toolNavigation, { trusted: true });
      }
      if (target === 'all' || target === 'settings') {
        writeMetadata(database, 'settings', json(seedState.settings));
      }
      writeMetadata(database, `reset_${target}_at`, timestamp);
    });

    invalidatePublicDataCache();
    const data = await getPublicData();
    return {
      data,
      impact,
      before: impact.before,
      seed: impact.seed,
      delta: impact.delta,
      backup,
    };
  });
};

export const sanitizeSettings = value => {
  const candidate = isObject(value) ? value : {};
  const merged = { ...defaultSettings, ...candidate };
  return {
    siteTitle: normalizeText(merged.siteTitle),
    siteSubtitle: normalizeText(merged.siteSubtitle),
    browserTitle: normalizeText(merged.browserTitle),
    logoIcon: String(merged.logoIcon ?? defaultSettings.logoIcon).trim() || defaultSettings.logoIcon,
    logoUrl: sanitizeLogoUrl(merged.logoUrl),
    projectUrl,
  };
};

const sanitizePayloadExecution = value => {
  const candidate = isObject(value) ? value : {};
  return {
    title: ensureDisplayTextObject(candidate.title),
    command: String(candidate.command ?? '').trim(),
    description: candidate.description == null ? undefined : ensureDisplayTextObject(candidate.description),
    syntaxBreakdown: normalizeList(candidate.syntaxBreakdown).map(sanitizeSyntaxPart).filter(Boolean),
    platform: isPlatform(candidate.platform) ? candidate.platform : 'all',
    requiresAdmin: Boolean(candidate.requiresAdmin),
  };
};

const sanitizeSyntaxPart = value => {
  if (!isObject(value)) return null;
  const part = String(value.part ?? '').trim();
  if (!part) return null;
  return {
    part,
    explanation: ensureDisplayTextObject(value.explanation),
    type: typeof value.type === 'string' ? value.type : undefined,
  };
};

const sanitizeAttackChainStep = value => {
  if (!isObject(value)) return null;
  const payload = String(value.payload ?? '').trim();
  const step = {
    title: ensureDisplayTextObject(value.title),
    description: ensureDisplayTextObject(value.description),
  };
  if (payload) step.payload = payload;
  return step;
};

const sanitizeStoredPublicPayload = value => {
  const candidate = isObject(value) ? value : {};
  const name = ensureDisplayTextObject(candidate.name);
  const id = typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('payload', name.zh || name.en || 'payload');
  return {
    id,
    name,
    description: ensureDisplayTextObject(candidate.description),
    category: ensureDisplayTextObject(candidate.category),
    subCategory: candidate.subCategory == null ? undefined : ensureDisplayTextObject(candidate.subCategory),
    tags: normalizeList(candidate.tags).map(String).map(item => item.trim()).filter(Boolean),
    prerequisites: normalizeList(candidate.prerequisites).map(ensureDisplayTextObject),
    execution: dedupeCommandEntries(normalizeList(candidate.execution).map(sanitizePayloadExecution).filter(item => item.command)),
    analysis: candidate.analysis == null ? undefined : ensureDisplayTextObject(candidate.analysis),
    opsecTips: normalizeList(candidate.opsecTips).map(ensureDisplayTextObject),
    wafBypass: dedupeCommandEntries(normalizeList(candidate.wafBypass).map(sanitizePayloadExecution).filter(item => item.command)),
    attackChain: normalizeList(candidate.attackChain).map(sanitizeAttackChainStep).filter(Boolean),
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
    tutorial: isObject(candidate.tutorial) ? {
      overview: ensureDisplayTextObject(candidate.tutorial.overview),
      vulnerability: ensureDisplayTextObject(candidate.tutorial.vulnerability),
      exploitation: ensureDisplayTextObject(candidate.tutorial.exploitation),
      mitigation: ensureDisplayTextObject(candidate.tutorial.mitigation),
      difficulty: ['beginner', 'intermediate', 'advanced', 'expert'].includes(candidate.tutorial.difficulty) ? candidate.tutorial.difficulty : 'beginner',
    } : undefined,
  };
};

export const sanitizePayload = value => {
  const scrubbed = scrubLowQualityEnglishContent(scrubRetiredEdrContent(value).value).value;
  const candidate = isObject(scrubbed) ? scrubbed : {};
  const name = ensureDisplayTextObject(candidate.name);
  const execution = normalizeList(candidate.execution).map(sanitizePayloadExecution).filter(item => item.command);
  return {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('payload', name.zh || name.en || 'payload'),
    name,
    description: ensureDisplayTextObject(candidate.description),
    category: ensureDisplayTextObject(candidate.category),
    subCategory: candidate.subCategory == null ? undefined : ensureDisplayTextObject(candidate.subCategory),
    tags: normalizeList(candidate.tags).map(String).map(item => item.trim()).filter(Boolean),
    prerequisites: normalizeList(candidate.prerequisites).map(ensureDisplayTextObject),
    execution: execution.length ? execution : [{ title: toText('Command'), command: String(candidate.command ?? 'echo TODO').trim() || 'echo TODO', platform: 'all' }],
    analysis: candidate.analysis == null ? undefined : ensureDisplayTextObject(candidate.analysis),
    opsecTips: normalizeList(candidate.opsecTips).map(ensureDisplayTextObject),
    wafBypass: normalizeList(candidate.wafBypass).map(sanitizePayloadExecution).filter(item => item.command),
    attackChain: normalizeList(candidate.attackChain).map(sanitizeAttackChainStep).filter(Boolean),
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
    tutorial: isObject(candidate.tutorial) ? {
      overview: ensureDisplayTextObject(candidate.tutorial.overview),
      vulnerability: ensureDisplayTextObject(candidate.tutorial.vulnerability),
      exploitation: ensureDisplayTextObject(candidate.tutorial.exploitation),
      mitigation: ensureDisplayTextObject(candidate.tutorial.mitigation),
      difficulty: ['beginner', 'intermediate', 'advanced', 'expert'].includes(candidate.tutorial.difficulty) ? candidate.tutorial.difficulty : 'beginner',
    } : undefined,
  };
};

const sanitizeToolCommandItem = value => {
  const candidate = isObject(value) ? value : {};
  const command = String(candidate.command ?? '').trim();
  if (!command) return null;
  let name = localizeKnownToolEnglish(candidate.name);
  const description = localizeKnownToolEnglish(candidate.description);
  if (isObject(name) && !name.zh.trim() && !name.en.trim()) {
    const fallbackLabel = textValue(description).trim() || command.split(/\r?\n/, 1)[0].trim() || 'Command';
    name = localizeKnownToolEnglish(toText(fallbackLabel));
  }
  return {
    name,
    command,
    description,
    syntaxBreakdown: normalizeList(candidate.syntaxBreakdown).map(sanitizeSyntaxPart).filter(Boolean),
    examples: normalizeList(candidate.examples).map(localizeKnownToolEnglish),
    platform: isPlatform(candidate.platform) ? candidate.platform : 'all',
  };
};

export const sanitizeTool = value => {
  const candidate = isObject(value) ? value : {};
  const name = localizeKnownToolEnglish(candidate.name);
  const commands = normalizeList(candidate.commands).map(sanitizeToolCommandItem).filter(Boolean);
  const id = typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('tool', name.zh || name.en || 'tool');
  const externalUrl = candidate.externalUrl === protectedExternalUrl && systemToolIds.has(id) ? protectedExternalUrl : '';
  const description = localizeKnownToolEnglish(candidate.description);
  const category = localizeKnownToolEnglish(candidate.category);
  const installation = candidate.installation == null ? undefined : localizeKnownToolEnglish(candidate.installation);
  const item = {
    id,
    name,
    description,
    category,
    commands: commands.length ? commands : (externalUrl ? [] : [{ name: toText('Command'), command: 'echo TODO', description: toText('TODO'), platform: 'all' }]),
    installation,
    references: normalizeList(candidate.references).map(String).map(item => item.trim()).filter(Boolean),
  };
  if (externalUrl) {
    item.externalUrl = externalUrl;
    item.systemLocked = true;
  }
  return item;
};

export const sanitizeNavItem = value => {
  const candidate = isObject(value) ? value : {};
  const name = normalizeText(candidate.name);
  const item = {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : makeId('nav', name.zh || name.en || 'node'),
    name,
  };
  if (typeof candidate.icon === 'string' && candidate.icon.trim()) item.icon = candidate.icon.trim();
  if (typeof candidate.payloadId === 'string' && candidate.payloadId.trim()) item.payloadId = candidate.payloadId.trim();
  if (typeof candidate.toolId === 'string' && candidate.toolId.trim()) item.toolId = candidate.toolId.trim();
  const children = normalizeList(candidate.children).map(sanitizeNavItem);
  if (children.length) item.children = children;
  return item;
};

const cloneValue = value => parseJson(json(value));
const isSystemToolId = id => systemToolIds.has(String(id || ''));
const isSystemNavigationNodeId = id => systemNavigationNodeIds.has(String(id || ''));

const navigationTouchesSystemItem = item => {
  if (!isObject(item)) return false;
  if (isSystemNavigationNodeId(item.id) || isSystemToolId(item.toolId)) return true;
  return normalizeList(item.children).some(navigationTouchesSystemItem);
};

const pruneSystemNavigationItem = item => {
  if (!isObject(item)) return null;
  if (isSystemNavigationNodeId(item.id) || isSystemToolId(item.toolId)) return null;
  const next = { ...item };
  const children = normalizeList(next.children).map(pruneSystemNavigationItem).filter(Boolean);
  if (children.length) next.children = children;
  else delete next.children;
  return next;
};

const protectedSystemTool = () => sanitizeTool(cloneValue(protectedXssPlatformTool));
const protectedSystemNavigationItem = () => sanitizeNavItem(cloneValue(protectedXssPlatformNavigation));

const withProtectedSystemTools = tools => [
  protectedSystemTool(),
  ...normalizeList(tools).filter(item => !isSystemToolId(item.id)),
];

const withProtectedSystemToolNavigation = navigation => [
  protectedSystemNavigationItem(),
  ...normalizeList(navigation).map(pruneSystemNavigationItem).filter(Boolean),
];

const isXeyeEnabled = database => readMetadata(database, xeyeDisabledMetadataKey) !== '1';

const assertMutableAdminItem = (resource, idOrItem) => {
  const id = isObject(idOrItem) ? idOrItem.id : idOrItem;
  if (resource === 'tools' && isSystemToolId(id)) {
    throw protectedStoreError('默认 XSS 平台入口不可编辑或移动，可在工具列表中删除。');
  }
  if (resource === 'navigation') {
    if (isSystemNavigationNodeId(id) || navigationTouchesSystemItem(idOrItem)) {
      throw protectedStoreError('系统内置 XSS 平台导航不可在后台编辑、移动或删除。');
    }
  }
};

const uniqueItems = (items, label, warnings) => {
  const usedIds = new Set();
  return items.map((item, index) => {
    const normalized = { ...item };
    if (usedIds.has(normalized.id)) {
      const originalId = normalized.id;
      normalized.id = `${normalized.id}-${index}`;
      warnings.push(`${label} 存在重复 ID「${originalId}」，第 ${index + 1} 条已自动改为「${normalized.id}」。`);
    }
    usedIds.add(normalized.id);
    return normalized;
  });
};

const importArrayLimits = {
  payloads: 10_000,
  tools: 10_000,
  navigation: 2_000,
  toolNavigation: 2_000,
};
const maxImportNavigationNodes = 20_000;
const maxImportNavigationDepth = 12;

const readImportArray = (candidate, key, label) => {
  if (!Object.prototype.hasOwnProperty.call(candidate, key)) {
    return { included: false, items: [] };
  }
  if (!Array.isArray(candidate[key])) {
    throw new Error(`${label} 必须是数组。`);
  }
  const maxItems = importArrayLimits[key];
  if (maxItems && candidate[key].length > maxItems) {
    throw new Error(`${label} 一次最多导入 ${maxItems} 条，请拆分文件后分批导入。`);
  }
  return { included: true, items: candidate[key] };
};

const assertNavigationImportShape = (items, label) => {
  let count = 0;
  const stack = normalizeList(items).map(item => ({ item, depth: 1 }));
  while (stack.length) {
    const { item, depth } = stack.pop();
    if (!isObject(item)) continue;
    count += 1;
    if (count > maxImportNavigationNodes) {
      throw new Error(`${label} 导航节点一次最多导入 ${maxImportNavigationNodes} 个，请拆分文件后分批导入。`);
    }
    if (depth > maxImportNavigationDepth) {
      throw new Error(`${label} 导航层级不能超过 ${maxImportNavigationDepth} 层。`);
    }
    for (const child of normalizeList(item.children)) {
      stack.push({ item: child, depth: depth + 1 });
    }
  }
};

const normalizeImportPackage = value => {
  if (!isObject(value)) {
    throw new Error('导入文件必须是 JSON 对象。');
  }
  const warnings = [];
  const format = typeof value.format === 'string' ? value.format.trim() : '';
  if (format && format !== 'payloader.import.v1') {
    warnings.push(`模板标识为「${format}」，当前按 payloader.import.v1 兼容导入。`);
  }
  const payloadSource = readImportArray(value, 'payloads', 'payloads');
  const toolSource = readImportArray(value, 'tools', 'tools');
  const navigationSource = readImportArray(value, 'navigation', 'navigation');
  const toolNavigationSource = readImportArray(value, 'toolNavigation', 'toolNavigation');
  const included = {
    payloads: payloadSource.included,
    tools: toolSource.included,
    navigation: navigationSource.included,
    toolNavigation: toolNavigationSource.included,
  };
  if (Object.prototype.hasOwnProperty.call(value, 'settings')) {
    warnings.push('平台信息不参与导入，settings 已自动忽略。');
  }
  if (!Object.values(included).some(Boolean)) {
    throw new Error('导入文件没有包含可导入的数据，请至少提供 payloads、tools、navigation 或 toolNavigation。');
  }
  assertNavigationImportShape(navigationSource.items, 'navigation');
  assertNavigationImportShape(toolNavigationSource.items, 'toolNavigation');
  const payloads = uniqueItems(payloadSource.items.map(sanitizePayload), 'payloads', warnings);
  const tools = uniqueItems(toolSource.items.map(sanitizeTool), 'tools', warnings)
    .filter(item => {
      if (!isSystemToolId(item.id)) return true;
      warnings.push('系统内置 XSS 平台不可通过导入覆盖，已自动忽略。');
      return false;
    });
  const navigation = uniqueItems(navigationSource.items.map(sanitizeNavItem), 'navigation', warnings)
    .map(pruneSystemNavigationItem)
    .filter(Boolean);
  const toolNavigation = uniqueItems(toolNavigationSource.items.map(sanitizeNavItem), 'toolNavigation', warnings)
    .map(pruneSystemNavigationItem)
    .filter(Boolean);
  return {
    format: format || 'payloader.import.v1',
    included,
    payloads,
    tools,
    navigation,
    toolNavigation,
    warnings,
  };
};

const importSummary = normalized => ([
  { key: 'payloads', label: 'Payload', included: normalized.included.payloads, count: normalized.payloads.length },
  { key: 'tools', label: '工具命令', included: normalized.included.tools, count: normalized.tools.length },
  { key: 'navigation', label: 'Payload 导航', included: normalized.included.navigation, count: normalized.navigation.length },
  { key: 'toolNavigation', label: '工具导航', included: normalized.included.toolNavigation, count: normalized.toolNavigation.length },
]);

export const createImportTemplate = () => ({
  format: 'payloader.import.v1',
  generatedAt: now(),
  guide: {
    title: 'Payloader 导入模板填写说明',
    summary: '导入文件必须是一个 JSON 对象。真正会导入的只有 payloads、tools、navigation、toolNavigation 四个数组；guide、fieldReference、limits、instructions 这些说明字段会被后台忽略，可以保留也可以删除。',
    steps: [
      '1. 保留 format 为 payloader.import.v1。',
      '2. 在 payloads 数组里写 Payload 数据；在 tools 数组里写工具命令数据。',
      '3. 如果想让左侧导航出现这些数据，需要同时在 navigation 或 toolNavigation 里添加节点，并用 payloadId/toolId 指向对应 id。',
      '4. 一个文件可以一次写很多条数据；数组里每个对象就是一条记录。',
      '5. 上传前先点“预览文件”，确认数量和提醒没有问题后再执行导入。',
    ],
    importModes: {
      merge: '合并更新：id 已存在就更新这条数据，id 不存在就新增。',
      replace: '覆盖所选模块：只覆盖导入文件中出现的模块。例如文件里只有 payloads，就只覆盖 Payload 数据，不会动 tools。',
    },
    i18nTextFormat: {
      description: '所有显示文本字段都支持两种写法，推荐使用中英双语对象。',
      simpleString: '只写字符串时会被当作中文，例如 "SQL 注入"。',
      bilingualObject: '推荐写成 {"zh":"中文","en":"English"}，前台切换语言时会自动显示对应语言。',
    },
    dynamicVariables: {
      description: 'Payload 命令和工具命令可以直接使用全局变量，占位符会在前台展示和复制时自动替换。',
      examples: ['{URL}', '{TARGET}', '{PATH}', '{PARAM}', '{PARAM_VALUE}', '{COOKIE}', '{HEADER_AUTH}', '{ATTACKER_IP}', '{LPORT}', '{WORDLIST}'],
      exampleCommand: 'curl -sk "{URL}" -H "Cookie: {COOKIE}" -H "{HEADER_AUTH}"',
    },
    commonMistakes: [
      'payloads、tools、navigation、toolNavigation 必须是数组，不能写成对象。',
      'payload.execution 和 tool.commands 也必须是数组。',
      'navigation 子节点要写 payloadId，值必须等于 payloads 里某条数据的 id。',
      'toolNavigation 子节点要写 toolId，值必须等于 tools 里某条数据的 id。',
      'platform 只能写 all、windows、linux；不写会默认 all。',
      'tutorial.difficulty 只能写 beginner、intermediate、advanced、expert。',
      'JSON 不能有注释、不能有多余逗号；多行命令请使用 \\n 换行。',
      '站点标题、Logo、GitHub、Xeye 等平台信息不会导入，不要写 settings。',
    ],
  },
  fieldReference: {
    topLevel: {
      format: '可选但建议保留，固定写 payloader.import.v1。',
      payloads: 'Payload 数组，可省略；每一项是一条前台 Payload。',
      tools: '工具命令数组，可省略；每一项是一个工具，工具下面可以有多条 commands。',
      navigation: 'Payload 左侧导航树，可省略；通过 payloadId 关联 payloads.id。',
      toolNavigation: '工具左侧导航树，可省略；通过 toolId 关联 tools.id。',
    },
    payload: {
      required: ['id', 'name', 'description', 'category', 'execution'],
      optional: ['subCategory', 'tags', 'prerequisites', 'analysis', 'opsecTips', 'wafBypass', 'attackChain', 'references', 'tutorial'],
      id: '唯一 ID，只建议使用英文、数字、短横线，例如 sqli-custom-login。',
      execution: '标准模式 Payload 列表，数组；每项必须有 title 和 command。',
      wafBypass: 'WAF 绕过模式 Payload 列表，数组；结构和 execution 一样。',
      attackChain: '攻击链步骤，数组；payload 字段可放关联命令，前台可复制。',
    },
    payloadExecution: {
      title: '命令标题，I18nText。',
      command: '可直接复制的 Payload 或命令字符串，支持 {URL} 等变量。',
      description: '命令用途说明，I18nText。',
      platform: 'all、windows、linux 之一。',
      requiresAdmin: '是否需要管理员权限，true 或 false。',
      syntaxBreakdown: '语法解析数组，可为空；part 是要解释的片段，explanation 是说明，type 是展示类型。',
    },
    tutorial: {
      overview: '漏洞或攻击方式概述，I18nText。',
      vulnerability: '原理说明，I18nText。',
      exploitation: '使用方法或验证流程，I18nText。',
      mitigation: '防护建议，I18nText。',
      difficulty: 'beginner、intermediate、advanced、expert 之一。',
    },
    tool: {
      required: ['id', 'name', 'description', 'category', 'commands'],
      optional: ['installation', 'references'],
      commands: '工具命令数组；每项必须有 name、command、description。',
      note: '系统内置 XSS 平台不可通过导入覆盖，也不要写 externalUrl。',
    },
    navigationNode: {
      id: '导航节点唯一 ID。',
      name: '导航显示名称，I18nText。',
      icon: '可选图标字符。',
      children: '子节点数组。',
      payloadId: 'Payload 导航叶子节点使用，必须等于 payloads 中某条 id。',
      toolId: '工具导航叶子节点使用，必须等于 tools 中某条 id。',
    },
  },
  limits: {
    maxFileSize: '20 MiB',
    maxPayloads: importArrayLimits.payloads,
    maxTools: importArrayLimits.tools,
    maxNavigationRoots: importArrayLimits.navigation,
    maxToolNavigationRoots: importArrayLimits.toolNavigation,
    maxNavigationNodes: maxImportNavigationNodes,
    maxNavigationDepth: maxImportNavigationDepth,
  },
  instructions: [
    '下载后按示例结构填写数据，再在后台“导入数据”中选择此 JSON 文件。',
    '模板只导入 Payload、工具命令、Payload 导航和工具导航；站点标题、Logo、GitHub/Xeye 等平台信息不会被导入。',
    'payloads、tools、navigation、toolNavigation 都是数组，可以一次放入多条数据；大批量导入请先预览确认数量。',
    '导入支持“合并更新”和“覆盖所选模块”：覆盖只会覆盖文件里包含的模块。',
    'id 用来判断更新同一条数据；新 id 会新增记录，重复 id 会自动改名并给出提示。',
    '命令里建议使用 {URL}、{COOKIE}、{ATTACKER_IP} 等全局变量；前台展示和复制时会自动替换。',
    '如果不需要导入某个模块，可以删除对应数组字段，或保留空数组。',
  ],
  payloads: [
    {
      id: 'sqli-login-example',
      name: { zh: 'SQL 注入登录参数示例', en: 'SQL injection login parameter example' },
      description: { zh: '用于演示如何导入一组可复制、可切换变量的 SQL 注入测试 Payload。', en: 'Shows how to import copyable SQL injection payloads with dynamic variables.' },
      category: { zh: 'Web 漏洞', en: 'Web vulnerabilities' },
      subCategory: { zh: 'SQL 注入', en: 'SQL injection' },
      tags: ['sql-injection', 'login', 'template'],
      prerequisites: [{ zh: '确认测试 URL、参数名和授权范围。', en: 'Confirm test URL, parameter name, and authorized scope.' }],
      execution: [
        {
          title: { zh: '布尔盲注基础探测', en: 'Boolean-based probe' },
          command: '{PARAM_VALUE}\' AND \'1\'=\'1\n{PARAM_VALUE}\' AND \'1\'=\'2',
          description: { zh: '把当前参数值替换为真假条件，观察响应差异。', en: 'Replace the current parameter value with true/false conditions and compare responses.' },
          platform: 'all',
          requiresAdmin: false,
          syntaxBreakdown: [
            { part: '{PARAM_VALUE}', explanation: { zh: '参数值变量，可在前台全局变量里修改。', en: 'Parameter value variable from the global variable panel.' }, type: 'variable' },
            { part: 'AND', explanation: { zh: '拼接布尔条件。', en: 'Adds a boolean condition.' }, type: 'operator' },
          ],
        },
        {
          title: { zh: 'sqlmap 带参 URL', en: 'sqlmap URL with parameter' },
          command: 'sqlmap -u "{URL}" -p {PARAM} --batch --dbs',
          description: { zh: '直接使用全局 URL 和参数名变量。', en: 'Uses the global URL and parameter name variables directly.' },
          platform: 'all',
          requiresAdmin: false,
          syntaxBreakdown: [
            { part: '{URL}', explanation: { zh: '完整目标 URL，例如 https://target.com/api/users?id=1。', en: 'Full target URL, for example https://target.com/api/users?id=1.' }, type: 'variable' },
            { part: '{PARAM}', explanation: { zh: '指定注入参数名。', en: 'Specifies the injectable parameter name.' }, type: 'variable' },
          ],
        },
      ],
      analysis: { zh: '如果真假条件响应长度、状态码、内容或时间差异稳定，说明该参数可能进入 SQL 查询。', en: 'Stable differences in response length, status code, content, or timing suggest the parameter may reach a SQL query.' },
      opsecTips: [{ zh: '只在授权环境和测试账号上使用，先从只读探测开始。', en: 'Use only in authorized environments and start with read-only probes.' }],
      wafBypass: [
        {
          title: { zh: '大小写和注释变体', en: 'Case and comment variant' },
          command: '{PARAM_VALUE}\'/**/AnD/**/\'1\'/**/=/**/\'1',
          description: { zh: 'WAF 绕过模式下展示的变体示例。', en: 'Example variant shown in WAF bypass mode.' },
          platform: 'all',
          requiresAdmin: false,
          syntaxBreakdown: [],
        },
      ],
      attackChain: [
        {
          title: { zh: '确认入口', en: 'Confirm entry point' },
          description: { zh: '先用 {URL} 确认参数 {PARAM} 可控，并记录正常响应。', en: 'Use {URL} to confirm {PARAM} is controllable and record the normal response.' },
          payload: 'curl -sk "{URL}" -H "Cookie: {COOKIE}"',
        },
        {
          title: { zh: '复制 Payload 验证差异', en: 'Copy payloads and compare differences' },
          description: { zh: '从 Payload 列表复制真假条件，替换参数值后比较响应。', en: 'Copy true/false conditions from the payload list, replace the parameter value, and compare responses.' },
        },
      ],
      references: ['https://example.com/reference'],
      tutorial: {
        overview: { zh: 'SQL 注入通常发生在用户输入被拼接进 SQL 查询时。', en: 'SQL injection usually happens when user input is concatenated into SQL queries.' },
        vulnerability: { zh: '根因是未使用参数化查询、输入类型校验不足或动态 SQL 拼接。', en: 'Root causes include missing parameterized queries, weak type validation, or dynamic SQL concatenation.' },
        exploitation: { zh: '先确认参数可控，再使用布尔、报错、时间或联合查询方式验证。', en: 'Confirm controllability first, then test boolean, error, time, or union-based techniques.' },
        mitigation: { zh: '使用参数化查询、最小权限数据库账号、输入类型约束和统一错误处理。', en: 'Use parameterized queries, least-privilege database accounts, strict input types, and consistent error handling.' },
        difficulty: 'beginner',
      },
    },
  ],
  tools: [
    {
      id: 'http-probe-example',
      name: { zh: 'HTTP 请求验证示例', en: 'HTTP request probe example' },
      description: { zh: '演示工具命令如何使用全局变量。', en: 'Shows how tool commands use global variables.' },
      category: { zh: 'Web 工具', en: 'Web tools' },
      installation: { zh: '系统自带 curl 或安装 curl。', en: 'Use system curl or install curl.' },
      commands: [
        {
          name: { zh: '携带 Cookie 请求', en: 'Request with cookie' },
          command: 'curl -sk "{URL}" -H "Cookie: {COOKIE}" -H "{HEADER_AUTH}" -A "{USER_AGENT}"',
          description: { zh: '使用全局 URL、Cookie、Authorization 和 User-Agent 变量。', en: 'Uses global URL, Cookie, Authorization, and User-Agent variables.' },
          platform: 'all',
          syntaxBreakdown: [
            { part: '{URL}', explanation: { zh: '完整目标 URL。', en: 'Full target URL.' }, type: 'variable' },
            { part: '{COOKIE}', explanation: { zh: '完整 Cookie 值。', en: 'Full Cookie value.' }, type: 'variable' },
          ],
          examples: [{ zh: 'curl -sk "{URL}" -H "Cookie: {COOKIE}"', en: 'curl -sk "{URL}" -H "Cookie: {COOKIE}"' }],
        },
      ],
      references: ['https://example.com/tool'],
    },
  ],
  navigation: [
    {
      id: 'nav-payload-example',
      name: { zh: 'Web 漏洞', en: 'Web vulnerabilities' },
      icon: '📁',
      children: [
        { id: 'nav-payload-example-item', name: { zh: 'SQL 注入登录参数示例', en: 'SQL injection login parameter example' }, payloadId: 'sqli-login-example' },
      ],
    },
  ],
  toolNavigation: [
    {
      id: 'nav-tool-example',
      name: { zh: 'Web 工具', en: 'Web tools' },
      icon: '🧰',
      children: [
        { id: 'nav-tool-example-item', name: { zh: 'HTTP 请求验证示例', en: 'HTTP request probe example' }, toolId: 'http-probe-example' },
      ],
    },
  ],
});

export const previewImportPackage = value => {
  const normalized = normalizeImportPackage(value);
  return {
    format: normalized.format,
    summary: importSummary(normalized),
    warnings: normalized.warnings,
  };
};

const demoPlaceholderValues = new Set([
  'echo todo',
  'new payload',
  '新 payload',
  'new tool',
  '新工具',
  'new command',
  '新命令',
  'uncategorized',
  '未分类',
]);

const findDemoPlaceholder = value => {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return demoPlaceholderValues.has(normalized) ? value.trim() : null;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const match = findDemoPlaceholder(item);
      if (match) return match;
    }
    return null;
  }
  if (isObject(value)) {
    for (const item of Object.values(value)) {
      const match = findDemoPlaceholder(item);
      if (match) return match;
    }
  }
  return null;
};

const assertNoDemoPlaceholderContent = value => {
  const placeholder = findDemoPlaceholder(value);
  if (!placeholder) return;
  const error = new Error(`检测到未完成的占位内容：${placeholder}`);
  error.status = 400;
  throw error;
};

export const importDataPackage = async (value, options = {}) => {
  const normalized = normalizeImportPackage(value);
  assertNoDemoPlaceholderContent([
    ...normalized.payloads,
    ...normalized.tools,
    ...normalized.navigation,
    ...normalized.toolNavigation,
  ]);
  const mode = options.mode === 'replace' ? 'replace' : 'merge';
  return enqueueMutation(async () => {
    const database = await getDb();
    runTransaction(database, () => {
      if (mode === 'replace') {
        if (normalized.included.payloads) {
          database.prepare('DELETE FROM payloads').run();
          insertPayloads(database, normalized.payloads);
        }
        if (normalized.included.tools) {
          database.prepare('DELETE FROM tools').run();
          insertTools(database, normalized.tools);
        }
        if (normalized.included.navigation) {
          database.prepare("DELETE FROM navigation_nodes WHERE kind = 'payloads'").run();
          insertNavigationKind(database, normalized.navigation, 'payloads');
        }
        if (normalized.included.toolNavigation) {
          database.prepare("DELETE FROM navigation_nodes WHERE kind = 'tools'").run();
          insertNavigationKind(database, normalized.toolNavigation, 'tools');
        }
      } else {
        if (normalized.included.payloads) upsertItems(database, 'payloads', normalized.payloads);
        if (normalized.included.tools) upsertItems(database, 'tools', normalized.tools);
        if (normalized.included.navigation) upsertNavigationKind(database, normalized.navigation, 'payloads');
        if (normalized.included.toolNavigation) upsertNavigationKind(database, normalized.toolNavigation, 'tools');
      }

      writeMetadata(database, 'last_import_at', now());
      writeMetadata(database, 'last_import_mode', mode);
    });

    invalidatePublicDataCache();
    return {
      mode,
      summary: importSummary(normalized),
      warnings: normalized.warnings,
      data: await getPublicData(),
    };
  });
};

export const getPublicData = async () => {
  if (publicDataCache) return publicDataCache;
  const database = await getDb();
  const xeyeEnabled = isXeyeEnabled(database);
  const settings = {
    ...sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings)),
    xeyeEnabled,
  };
  const payloads = rowsToItems(database.prepare('SELECT data FROM payloads WHERE enabled = 1 ORDER BY sort_order, id').all());
  const tools = rowsToItems(database.prepare('SELECT data FROM tools WHERE enabled = 1 ORDER BY sort_order, id').all());
  const navigation = rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'payloads' ORDER BY sort_order, id").all());
  const toolNavigation = rowsToItems(database.prepare("SELECT tree FROM navigation_nodes WHERE enabled = 1 AND kind = 'tools' ORDER BY sort_order, id").all());
  const publicPayloadData = prepareStoredPublicPayloadData(payloads, navigation);
  const storedPublicTools = tools
    .filter(item => !excludedPublicToolIds.has(item.id))
    .map(item => sanitizeTool(item));
  const publicTools = xeyeEnabled ? withProtectedSystemTools(storedPublicTools) : storedPublicTools;
  const toolIds = new Set(publicTools.map(item => item.id));
  publicDataCache = {
    settings,
    payloads: publicPayloadData.payloads,
    tools: publicTools,
    navigation: publicPayloadData.navigation,
    toolNavigation: filterToolNavigation(
      xeyeEnabled ? withProtectedSystemToolNavigation(toolNavigation) : toolNavigation,
      toolIds,
    ),
  };
  return publicDataCache;
};

export const getSettings = async () => {
  const database = await getDb();
  return {
    ...sanitizeSettings(readJsonMetadata(database, 'settings', defaultSettings)),
    xeyeEnabled: isXeyeEnabled(database),
  };
};

export const saveSettings = async value => {
  const settings = sanitizeSettings(value);
  return enqueueMutation(async () => {
    const database = await getDb();
    writeMetadata(database, 'settings', json(settings));
    writeMetadata(database, 'settings_updated_at', now());
    invalidatePublicDataCache();
    return { ...settings, xeyeEnabled: isXeyeEnabled(database) };
  });
};

export const listAdminItems = async resource => {
  const database = await getDb();
  if (resource === 'payloads') {
    return rowsToItems(database.prepare('SELECT data FROM payloads ORDER BY sort_order, id').all());
  }
  if (resource === 'tools') {
    const items = rowsToItems(database.prepare('SELECT data FROM tools ORDER BY sort_order, id').all())
      .filter(item => !isSystemToolId(item.id));
    return isXeyeEnabled(database) ? withProtectedSystemTools(items) : items;
  }
  if (resource === 'navigation') {
    return database.prepare('SELECT id, tree, kind, sort_order AS sortOrder, enabled FROM navigation_nodes ORDER BY kind, sort_order, id')
      .all()
      .map(row => ({ ...parseJson(row.tree), kind: row.kind, enabled: Boolean(row.enabled), sortOrder: row.sortOrder }))
      .map(item => {
        const pruned = pruneSystemNavigationItem(item);
        return pruned ? { ...pruned, kind: item.kind, enabled: item.enabled, sortOrder: item.sortOrder } : null;
      })
      .filter(Boolean);
  }
  throw new Error(`Unsupported resource: ${resource}`);
};

export const listCustomPayloads = async () => {
  const database = await getDb();
  return rowsToItems(database.prepare(`
    SELECT data
    FROM payloads
    WHERE id LIKE 'custom-%'
      OR json_extract(data, '$.category.zh') = '自定义'
      OR json_extract(data, '$.category.en') = 'Custom'
    ORDER BY sort_order, id
  `).all());
};

const customContentDestinations = new Set(['payloads', 'tools']);

const customContentError = (status, message) => {
  const error = new Error(message);
  error.status = status;
  return error;
};

const requireCustomDestination = value => {
  const destination = String(value || '');
  if (!customContentDestinations.has(destination)) {
    throw customContentError(400, '自定义内容归属无效');
  }
  return destination;
};

const normalizeCustomContentInput = value => {
  const candidate = isObject(value) ? value : {};
  const title = String(candidate.title || '').trim();
  const content = String(candidate.content || '').trim();
  if (!title) throw customContentError(400, '请填写标题');
  if (!content) throw customContentError(400, '请填写内容');
  return {
    id: String(candidate.id || '').trim(),
    title,
    content,
    destination: requireCustomDestination(candidate.destination),
    sourceDestination: candidate.sourceDestination == null
      ? null
      : requireCustomDestination(candidate.sourceDestination),
  };
};

const isCustomContentItem = item => {
  const category = ensureDisplayTextObject(item?.category);
  return String(item?.id || '').startsWith('custom-')
    || category.zh === '自定义'
    || category.en === 'Custom';
};

const customContentView = (item, destination) => ({
  id: item.id,
  title: textValue(item.name).trim(),
  content: destination === 'tools'
    ? String(item.commands?.[0]?.command || '')
    : String(item.execution?.[0]?.command || ''),
  destination,
});

const customItemForDestination = ({ id, title, content, destination }) => (
  destination === 'tools'
    ? sanitizeTool({
        id,
        name: { zh: title, en: title },
        description: { zh: `自定义：${title}`, en: `Custom: ${title}` },
        category: { zh: '自定义', en: 'Custom' },
        commands: [{
          name: { zh: title, en: title },
          command: content,
          description: { zh: '自定义内容', en: 'Custom content' },
          platform: 'all',
        }],
        references: [],
      })
    : sanitizePayload({
        id,
        name: { zh: title, en: title },
        description: { zh: `自定义：${title}`, en: `Custom: ${title}` },
        category: { zh: '自定义', en: 'Custom' },
        tags: ['custom'],
        prerequisites: [],
        execution: [{
          title: { zh: title, en: title },
          command: content,
          description: { zh: '自定义内容', en: 'Custom content' },
          platform: 'all',
        }],
        wafBypass: [],
      })
);

export const listCustomContent = async () => {
  const database = await getDb();
  const payloads = rowsToItems(database.prepare('SELECT data FROM payloads ORDER BY sort_order, id').all())
    .filter(isCustomContentItem)
    .map(item => customContentView(item, 'payloads'));
  const tools = rowsToItems(database.prepare('SELECT data FROM tools ORDER BY sort_order, id').all())
    .filter(item => !isSystemToolId(item.id) && isCustomContentItem(item))
    .map(item => customContentView(item, 'tools'));
  return [...payloads, ...tools];
};

export const saveCustomContent = async value => {
  const input = normalizeCustomContentInput(value);
  const id = input.id || makeId('custom', input.title);
  const item = customItemForDestination({ ...input, id });
  assertMutableAdminItem(input.destination, item);
  assertNoDemoPlaceholderContent(item);

  return enqueueMutation(async () => {
    const database = await getDb();
    const source = input.sourceDestination || input.destination;
    const sourceTable = tableForResource(source).table;
    const targetTable = tableForResource(input.destination).table;
    const moving = source !== input.destination;
    const sourceRow = input.id
      ? database.prepare(`SELECT data FROM ${sourceTable} WHERE id = ?`).get(id)
      : null;
    const sourceItem = sourceRow ? parseJson(sourceRow.data) : null;
    if (input.id && (!sourceItem || !isCustomContentItem(sourceItem))) {
      throw customContentError(404, '自定义内容不存在');
    }
    if (moving && database.prepare(`SELECT id FROM ${targetTable} WHERE id = ?`).get(id)) {
      throw customContentError(409, '目标栏目已存在相同 ID 的内容');
    }

    runTransaction(database, () => {
      upsertItems(database, input.destination, [item]);
      if (moving) database.prepare(`DELETE FROM ${sourceTable} WHERE id = ?`).run(id);
    });
    invalidatePublicDataCache();
    return customContentView(item, input.destination);
  });
};

export const deleteCustomContent = async value => {
  const id = String(value?.id || '').trim();
  const destination = requireCustomDestination(value?.destination);
  if (!id) throw customContentError(400, '缺少自定义内容 ID');
  assertMutableAdminItem(destination, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    const table = tableForResource(destination).table;
    const row = database.prepare(`SELECT data FROM ${table} WHERE id = ?`).get(id);
    const item = row ? parseJson(row.data) : null;
    if (!item || !isCustomContentItem(item)) {
      throw customContentError(404, '自定义内容不存在');
    }
    database.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
    invalidatePublicDataCache();
    return { ok: true };
  });
};

const tableForResource = resource => {
  if (resource === 'payloads') return { table: 'payloads', dataColumn: 'data', sanitizer: sanitizePayload };
  if (resource === 'tools') return { table: 'tools', dataColumn: 'data', sanitizer: sanitizeTool };
  throw new Error(`Unsupported resource: ${resource}`);
};

export const saveAdminItem = async (resource, item) => {
  const { table, dataColumn, sanitizer } = tableForResource(resource);
  const normalized = sanitizer(item);
  assertMutableAdminItem(resource, normalized);
  assertNoDemoPlaceholderContent(normalized);
  return enqueueMutation(async () => {
    const database = await getDb();
    const timestamp = now();
    const existing = database.prepare(`SELECT sort_order FROM ${table} WHERE id = ?`).get(normalized.id);
    const sortOrder = existing?.sort_order ?? (database.prepare(`SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM ${table}`).get().next);
    database.prepare(`
      INSERT INTO ${table} (id, ${dataColumn}, sort_order, enabled, created_at, updated_at)
      VALUES (?, ?, ?, 1, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        ${dataColumn} = excluded.${dataColumn},
        updated_at = excluded.updated_at
    `).run(normalized.id, json(normalized), sortOrder, timestamp, timestamp);
    invalidatePublicDataCache();
    return normalized;
  });
};

export const saveNavigationItem = async item => {
  const normalized = sanitizeNavItem(item);
  const kind = item.kind === 'tools' ? 'tools' : 'payloads';
  assertMutableAdminItem('navigation', { ...normalized, kind });
  return enqueueMutation(async () => {
    const database = await getDb();
    const timestamp = now();
    const existing = database.prepare('SELECT sort_order FROM navigation_nodes WHERE id = ?').get(normalized.id);
    const sortOrder = existing?.sort_order ?? (database.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS next FROM navigation_nodes WHERE kind = ?').get(kind).next);
    database.prepare(`
      INSERT INTO navigation_nodes (id, tree, kind, sort_order, enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        tree = excluded.tree,
        kind = excluded.kind,
        updated_at = excluded.updated_at
    `).run(normalized.id, json(normalized), kind, sortOrder, timestamp, timestamp);
    invalidatePublicDataCache();
    return { ...normalized, kind };
  });
};

export const deleteAdminItem = async (resource, id) => {
  if (!id) throw new Error('Missing id');
  if (resource === 'tools' && isSystemToolId(id)) {
    return enqueueMutation(async () => {
      const database = await getDb();
      writeMetadata(database, xeyeDisabledMetadataKey, '1');
      writeMetadata(database, `${xeyeDisabledMetadataKey}_at`, now());
      invalidatePublicDataCache();
    });
  }
  assertMutableAdminItem(resource, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    if (resource === 'navigation') {
      database.prepare('DELETE FROM navigation_nodes WHERE id = ?').run(id);
      invalidatePublicDataCache();
      return;
    }
    const { table } = tableForResource(resource);
    database.prepare(`DELETE FROM ${table} WHERE id = ?`).run(id);
    invalidatePublicDataCache();
  });
};

export const moveAdminItem = async (resource, id, direction) => {
  if (!id) throw new Error('Missing id');
  assertMutableAdminItem(resource, id);
  return enqueueMutation(async () => {
    const database = await getDb();
    const table = resource === 'navigation' ? 'navigation_nodes' : tableForResource(resource).table;
    const current = database.prepare(`SELECT id, sort_order, ${resource === 'navigation' ? 'kind' : "'all' AS kind"} FROM ${table} WHERE id = ?`).get(id);
    if (!current) return;
    const operator = direction === 'up' ? '<' : '>';
    const order = direction === 'up' ? 'DESC' : 'ASC';
    const kindClause = resource === 'navigation' ? 'AND kind = ?' : '';
    const args = resource === 'navigation' ? [current.sort_order, current.kind] : [current.sort_order];
    const other = database.prepare(`SELECT id, sort_order FROM ${table} WHERE sort_order ${operator} ? ${kindClause} ORDER BY sort_order ${order} LIMIT 1`).get(...args);
    if (!other) return;
    runTransaction(database, () => {
      database.prepare(`UPDATE ${table} SET sort_order = ? WHERE id = ?`).run(other.sort_order, current.id);
      database.prepare(`UPDATE ${table} SET sort_order = ? WHERE id = ?`).run(current.sort_order, other.id);
    });
    invalidatePublicDataCache();
  });
};

export const routeResource = path => {
  if (path.includes('/payloads')) return 'payloads';
  if (path.includes('/tools')) return 'tools';
  if (path.includes('/navigation')) return 'navigation';
  return null;
};
