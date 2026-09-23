// 文本质量修补与展示文本归一（纯函数，自 data-store.mjs 机械迁移）：
// EDR 术语清洗 / 低质与坏英文修复 / awkward 英文映射 / knownPayload·payloadVisibleZh·knownTool 映射表 /
// 破坏性命令清洗 / 可见标题归一。零 db 与 IO 依赖，独立可测；基础小工具随迁并导出，供引擎与 sanitize 复用。

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

export {
  applyVisibleChineseDisplayOverrides,
  awkwardEnglishExactText,
  awkwardEnglishPattern,
  brokenDisplayEnglishPattern,
  commandSignature,
  compactCommandDescription,
  compactCommandDescriptionText,
  dedupeCommandEntries,
  destructiveDbCleanupPattern,
  ensureDisplayTextObject,
  finalizeDisplayText,
  isObject,
  isPlatform,
  isText,
  knownPayloadEnglishOverrides,
  knownPayloadEnglishText,
  knownToolEnglishText,
  localizeKnownPayloadEnglish,
  localizeKnownToolEnglish,
  localizePayloadEnglishOverrides,
  localizePayloadVisibleZh,
  looksLikeSentenceTitle,
  lowQualityEnglishPattern,
  normalizeAwkwardEnglishString,
  normalizeAwkwardEnglishText,
  normalizeCommandLines,
  normalizeList,
  normalizeText,
  normalizeVisibleCommandDescription,
  normalizeVisibleCommandTitle,
  payloadVisibleZhOverrides,
  repairBrokenEnglishText,
  replaceI18nPhrase,
  scrubDestructiveAttackChainStep,
  scrubDestructiveCommandEntry,
  scrubDestructiveI18nText,
  scrubDestructivePayloadCommands,
  scrubDestructiveSyntaxPart,
  scrubDestructiveText,
  scrubLowQualityEnglishContent,
  scrubRetiredEdrContent,
  scrubRetiredEdrText,
  textLooksNonProfessionalZh,
  textValue,
  toText,
  trimBlankEdges,
  visibleChineseDisplayOverrides,
};
