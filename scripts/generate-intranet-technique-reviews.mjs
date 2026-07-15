import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadCurationSnapshot } from './apply-payload-curation.mjs';

const i18n = (zh, en) => ({ zh, en });
const asList = value => Array.isArray(value) ? value : [];
const spec = (id, zh, en, family, executionCount, platform, scopeZh, scopeEn) => ({
  id,
  name: i18n(zh, en),
  family,
  executionCount,
  platform,
  scope: i18n(scopeZh, scopeEn),
});

export const intranetTechniqueReviewSpecs = [
  spec('kerberoasting', 'Kerberoasting 单账号暴露验证', 'Kerberoasting Single-Account Exposure Validation', 'credential', 6, 'windows', '仅对合成服务账号的单个 SPN 核对票据加密类型、密码策略和离线审计边界。', 'Reviews ticket encryption, password policy, and offline audit boundaries for one synthetic service account and one SPN.'),
  spec('sam-dump', 'SAM 凭据存储访问控制审计', 'SAM Credential-Store Access-Control Audit', 'credential', 4, 'windows', '核对 SAM 与 SYSTEM hive 的文件 ACL、备份权限和访问审计，不导出真实 hive 或哈希。', 'Reviews file ACLs, backup privileges, and access auditing for SAM and SYSTEM hives without exporting real hives or hashes.'),
  spec('ntds-dump', 'NTDS.dit 备份与访问边界审计', 'NTDS.dit Backup and Access-Boundary Audit', 'credential', 5, 'windows', '核对域控制器数据库、卷影副本、IFM 与复制权限边界，不复制数据库或提取域凭据。', 'Reviews domain-controller database, shadow-copy, IFM, and replication privilege boundaries without copying the database or extracting domain credentials.'),
  spec('gpp-password', 'GPP cpassword 遗留配置审计', 'Legacy GPP cpassword Configuration Audit', 'credential', 5, 'windows', '在固定 SYSVOL 测试目录检测遗留 cpassword 字段与权限，不递归全域或解密真实凭据。', 'Detects legacy cpassword fields and permissions in a fixed SYSVOL test path without recursively scanning a domain or decrypting real credentials.'),
  spec('dpapi-creds', 'DPAPI 保护范围与审计验证', 'DPAPI Protection-Scope and Audit Validation', 'credential', 3, 'windows', '只检查合成用户配置文件中的 DPAPI 元数据、ACL 和主密钥作用域，不解密应用秘密。', 'Checks DPAPI metadata, ACLs, and master-key scope only in a synthetic user profile without decrypting application secrets.'),
  spec('rdp-creds', 'RDP 配置与凭据引用审计', 'RDP Configuration and Credential-Reference Audit', 'credential', 3, 'windows', '在合成配置目录检查 RDP 文件与凭据引用，不枚举系统凭据管理器内容或解密 DPAPI。', 'Reviews RDP files and credential references in a synthetic configuration directory without enumerating credential-manager contents or decrypting DPAPI.'),
  spec('wifi-creds', 'Wi-Fi 配置元数据审计', 'Wi-Fi Profile Metadata Audit', 'credential', 2, 'windows', '只列出实验无线配置名称与认证类型，不使用 key=clear 或记录预共享密钥。', 'Lists only lab wireless profile names and authentication types without using key=clear or recording pre-shared keys.'),
  spec('vault-creds', 'Windows Vault 类型与访问审计', 'Windows Vault Type and Access Audit', 'credential', 3, 'windows', '只检查 Vault 类型、策略和访问事件，不列出凭据值或调用凭据导出功能。', 'Reviews Vault types, policy, and access events without listing credential values or invoking credential export.'),
  spec('keepass-dump', 'KeePass 文件与进程保护审计', 'KeePass File and Process Protection Audit', 'credential', 3, 'windows', '在固定实验目录检查 KDBX 权限、应用版本与进程保护，不扫描全盘或提取主密码。', 'Reviews KDBX permissions, application version, and process protections in a fixed lab directory without scanning the full drive or extracting a master password.'),
  spec('lsa-secrets', 'LSA Secrets 存储边界审计', 'LSA Secrets Storage-Boundary Audit', 'credential', 3, 'windows', '核对 SECURITY/SYSTEM hive ACL、备份权限和访问日志，不保存 hive 或导出秘密。', 'Reviews SECURITY and SYSTEM hive ACLs, backup privileges, and access logs without saving hives or exporting secrets.'),

  spec('lateral-psexec', 'PsExec/SMB 远程服务边界验证', 'PsExec and SMB Remote-Service Boundary Validation', 'lateral', 4, 'windows', '只验证实验主机 445 端口、服务控制管理器 ACL 与日志，不创建服务或执行远程命令。', 'Validates only port 445, Service Control Manager ACLs, and logs on a lab host without creating a service or executing a remote command.'),
  spec('lateral-wmi', 'WMI 远程管理授权验证', 'WMI Remote-Management Authorization Validation', 'lateral', 4, 'windows', '核对实验主机 WMI/DCOM 可达性、命名空间 ACL 与事件日志，不调用 Win32_Process.Create。', 'Reviews WMI and DCOM reachability, namespace ACLs, and event logs on a lab host without invoking Win32_Process.Create.'),
  spec('pass-the-hash', 'NTLM Hash 登录防护验证', 'NTLM Hash Logon Protection Validation', 'lateral', 4, 'windows', '使用合成认证日志与专用账号核对 NTLM 限制、管理员隔离和远程 UAC，不注入或使用真实哈希。', 'Uses synthetic authentication logs and a dedicated account to review NTLM restrictions, administrator isolation, and remote UAC without injecting or using a real hash.'),
  spec('ntlm-relay', 'NTLM Relay 协议边界验证', 'NTLM Relay Protocol-Boundary Validation', 'lateral', 4, 'windows', '核对 SMB/LDAP 签名、EPA、通道绑定与实验抓包，不监听生产网段或中继认证。', 'Reviews SMB and LDAP signing, EPA, channel binding, and a lab capture without listening on production segments or relaying authentication.'),
  spec('lateral-dcom', 'DCOM 远程激活授权验证', 'DCOM Remote-Activation Authorization Validation', 'lateral', 3, 'windows', '只读取实验主机 DCOM 激活权限、CLSID 注册和日志，不调用 ShellExecute 或远程 COM 方法。', 'Reads DCOM activation permissions, CLSID registration, and logs on a lab host without calling ShellExecute or remote COM methods.'),
  spec('rdp-hijack', 'RDP 会话隔离与接管防护审计', 'RDP Session Isolation and Takeover Protection Audit', 'lateral', 3, 'windows', '只列出实验会话元数据和授权策略，不运行 tscon 或接管其他会话。', 'Lists only lab session metadata and authorization policy without running tscon or taking over another session.'),
  spec('overpass-the-hash', 'NTLM 到 Kerberos 票据边界审计', 'NTLM-to-Kerberos Ticket-Boundary Audit', 'lateral', 3, 'windows', '使用合成票据元数据核对加密类型、日志与身份绑定，不注入哈希或请求真实 TGT。', 'Uses synthetic ticket metadata to review encryption type, logs, and identity binding without injecting a hash or requesting a real TGT.'),
  spec('pass-the-ticket', 'Kerberos 票据导入防护审计', 'Kerberos Ticket-Import Protection Audit', 'lateral', 3, 'windows', '使用离线合成 kirbi 元数据核对票据主体、服务与时效，不把票据导入登录会话。', 'Uses offline synthetic kirbi metadata to review principal, service, and lifetime without importing a ticket into a logon session.'),
  spec('lateral-smbexec', 'SMBExec 远程服务写入防护', 'SMBExec Remote-Service Write Protection', 'lateral', 2, 'windows', '核对实验主机服务控制器与 ADMIN$ 权限及事件，不创建、启动或删除远程服务。', 'Reviews Service Control Manager and ADMIN$ permissions plus events on a lab host without creating, starting, or deleting a remote service.'),
  spec('lateral-atexec', '远程计划任务授权验证', 'Remote Scheduled-Task Authorization Validation', 'lateral', 2, 'windows', '只读取实验主机计划任务 ACL 与日志，不创建一次性任务或执行远程命令。', 'Reads scheduled-task ACLs and logs on a lab host without creating one-time tasks or executing a remote command.'),
  spec('lateral-dcom-excel', 'Excel DCOM 激活与 DDE 防护审计', 'Excel DCOM Activation and DDE Protection Audit', 'lateral', 3, 'windows', '核对 Excel COM 注册、远程激活权限和 DDE 策略，不启动远程 Excel 或子进程。', 'Reviews Excel COM registration, remote-activation permissions, and DDE policy without starting remote Excel or a child process.'),
  spec('lateral-dcom-mmc', 'MMC DCOM 激活权限审计', 'MMC DCOM Activation-Permission Audit', 'lateral', 2, 'windows', '核对 MMC20.Application 注册和远程激活权限，不调用 ExecuteShellCommand。', 'Reviews MMC20.Application registration and remote-activation permission without calling ExecuteShellCommand.'),
  spec('rdp-relay', 'RDP 与 NTLM Relay 分类审计', 'RDP and NTLM Relay Classification Audit', 'lateral', 3, 'windows', '纠正原条目把 SMB/LDAP NTLM Relay 误称为 RDP Relay 的问题，并只核对协议签名与日志。', 'Corrects the original conflation of SMB or LDAP NTLM Relay with RDP Relay and reviews only protocol signing and logs.'),

  spec('privilege-token', 'Windows 令牌权限与模拟防护', 'Windows Token Privilege and Impersonation Protection', 'privesc', 5, 'windows', '只读取当前令牌、SeImpersonate 等权限和相关事件，不复制、提升或模拟高权限令牌。', 'Reads the current token, privileges such as SeImpersonate, and related events without duplicating, elevating, or impersonating a privileged token.'),
  spec('uac-bypass', 'UAC 策略与自动提升边界审计', 'UAC Policy and Auto-Elevation Boundary Audit', 'privesc', 3, 'windows', '核对 UAC 策略、自动提升二进制和相关注册表 ACL，不写入 shell/open/command 键或启动载荷。', 'Reviews UAC policy, auto-elevated binaries, and relevant registry ACLs without writing shell/open/command keys or launching a payload.'),
  spec('dll-hijack', 'DLL 搜索顺序与目录权限审计', 'DLL Search-Order and Directory-Permission Audit', 'privesc', 3, 'windows', '使用签名无害 DLL 夹具核对搜索顺序、缺失模块和可写目录，不生成反向连接 DLL。', 'Uses a signed harmless DLL fixture to review search order, missing modules, and writable directories without generating a callback DLL.'),
  spec('service-exploit', 'Windows 服务 ACL 与路径审计', 'Windows Service ACL and Path Audit', 'privesc', 3, 'windows', '只读取一个实验服务的二进制路径、启动账户和 ACL，不修改 binPath 或启停服务。', 'Reads binary path, service account, and ACL for one lab service without changing binPath or starting or stopping the service.'),
  spec('always-install', 'AlwaysInstallElevated 策略审计', 'AlwaysInstallElevated Policy Audit', 'privesc', 3, 'windows', '核对 HKCU/HKLM 安装策略和 MSI 日志，不生成或安装带执行逻辑的 MSI。', 'Reviews HKCU and HKLM installer policy plus MSI logs without generating or installing an executable MSI.'),
  spec('juicy-potato', 'JuicyPotato 适用条件审计', 'JuicyPotato Prerequisite Audit', 'privesc', 2, 'windows', '核对实验系统版本、COM 服务和 SeImpersonate 权限，不启动 SYSTEM 命令。', 'Reviews lab OS version, COM services, and SeImpersonate privilege without launching a SYSTEM command.'),
  spec('printspoofer', 'PrintSpoofer 适用条件审计', 'PrintSpoofer Prerequisite Audit', 'privesc', 2, 'windows', '核对 Spooler 状态、补丁和模拟权限，不创建 SYSTEM shell 或输出文件。', 'Reviews Spooler status, patches, and impersonation privilege without creating a SYSTEM shell or output file.'),
  spec('godpotato', 'GodPotato 适用条件审计', 'GodPotato Prerequisite Audit', 'privesc', 2, 'windows', '核对 RPC/DCOM 版本、补丁和模拟权限，不执行编码命令或高权限进程。', 'Reviews RPC and DCOM version, patches, and impersonation privilege without running encoded commands or privileged processes.'),
  spec('suid-exploit', 'SUID 文件权限边界审计', 'SUID File-Permission Boundary Audit', 'privesc', 3, 'linux', '在限定系统目录列出 SUID 文件、所有者和哈希，并与批准基线比较，不使用 shell escape。', 'Lists SUID files, owners, and hashes in bounded system directories and compares them with an approved baseline without using shell escapes.'),
  spec('sudo-exploit', 'Sudoers 最小权限审计', 'Sudoers Least-Privilege Audit', 'privesc', 3, 'linux', '读取专用实验账号的 sudo -l 与 sudoers 片段，核对命令、参数和环境约束，不启动 shell。', 'Reads sudo -l and sudoers fragments for one lab account and reviews command, argument, and environment constraints without starting a shell.'),
  spec('cron-exploit', 'Cron 所有权与可写路径审计', 'Cron Ownership and Writable-Path Audit', 'privesc', 3, 'linux', '只检查固定 cron 文件和脚本的所有者、权限与路径，不创建 checkpoint 或执行命令。', 'Checks owner, permissions, and paths for fixed cron files and scripts without creating checkpoints or executing commands.'),

  spec('persistence-registry', '注册表启动项持久化审计', 'Registry Startup Persistence Audit', 'persistence', 4, 'windows', '只读取 Run、RunOnce 和 Winlogon 等批准位置并核对签名与基线，不写入注册表。', 'Reads approved Run, RunOnce, and Winlogon locations and compares signatures plus baseline without writing the registry.'),
  spec('persistence-wmi', 'WMI 永久事件订阅审计', 'WMI Permanent Event-Subscription Audit', 'persistence', 3, 'windows', '只读取 root/subscription 中的过滤器、消费者和绑定并关联创建事件，不新建订阅。', 'Reads filters, consumers, and bindings in root/subscription and correlates creation events without creating a subscription.'),
  spec('persistence-startup', '启动文件夹持久化审计', 'Startup-Folder Persistence Audit', 'persistence', 2, 'windows', '列出用户与全局启动目录中的文件、签名和所有者，不复制快捷方式或程序。', 'Lists files, signatures, and owners in user and global startup folders without copying shortcuts or programs.'),
  spec('persistence-service', '服务持久化配置审计', 'Service Persistence Configuration Audit', 'persistence', 2, 'windows', '读取自动启动服务的路径、账户、签名和 ACL，不创建或启动服务。', 'Reads paths, accounts, signatures, and ACLs for auto-start services without creating or starting a service.'),
  spec('persistence-dll-injection', 'AppInit 与模块注入持久化审计', 'AppInit and Module-Injection Persistence Audit', 'persistence', 3, 'windows', '读取 AppInit_DLLs、签名策略和模块加载事件，不生成 DLL 或注入进程。', 'Reads AppInit_DLLs, signing policy, and module-load events without generating a DLL or injecting a process.'),
  spec('persistence-backdoor-user', '异常本地账号持久化审计', 'Anomalous Local-Account Persistence Audit', 'persistence', 3, 'windows', '只列出本地账号、管理员组和最近账号事件，与批准清单比较，不创建用户。', 'Lists local accounts, Administrators membership, and recent account events for comparison with an approved list without creating a user.'),
  spec('persistence-hidden-user', '隐藏账号与 SAM 异常审计', 'Hidden-Account and SAM Anomaly Audit', 'persistence', 3, 'windows', '关联本地账号、配置文件、登录事件和 SAM 元数据，不修改 RID、用户名或组成员。', 'Correlates local accounts, profiles, logon events, and SAM metadata without changing RID, user names, or group membership.'),
  spec('skeleton-key', 'Skeleton Key 域控完整性审计', 'Skeleton Key Domain-Controller Integrity Audit', 'persistence', 3, 'windows', '核对域控制器 LSASS 模块、签名和认证异常，不注入补丁或测试万能密码。', 'Reviews domain-controller LSASS modules, signatures, and authentication anomalies without injecting a patch or testing a master password.'),
  spec('dsrm-backdoor', 'DSRM 配置与登录行为审计', 'DSRM Configuration and Logon-Behavior Audit', 'persistence', 4, 'windows', '只读取 DSRM 登录行为、相关策略和审计事件，不修改密码、注册表或使用哈希登录。', 'Reads DSRM logon behavior, related policy, and audit events without changing a password or registry value or logging on with a hash.'),
  spec('sid-history', 'SIDHistory 授权基线审计', 'SIDHistory Authorization-Baseline Audit', 'persistence', 3, 'windows', '读取指定实验用户的 sIDHistory 并与批准迁移记录比较，不注入 SID 或登录。', 'Reads sIDHistory for one lab user and compares it with approved migration records without injecting a SID or logging on.'),
  spec('persistence-process-hollowing', '进程镂空遥测与内存审计', 'Process-Hollowing Telemetry and Memory Audit', 'persistence', 3, 'windows', '使用无害挂起进程夹具核对进程树、映像映射和 ETW 事件，不写入或恢复远程线程。', 'Uses a harmless suspended-process fixture to review process trees, image mappings, and ETW events without writing or resuming a remote thread.'),

  spec('domain-privilege-escalation', 'AD 权限路径只读验证', 'AD Privilege-Path Read-Only Validation', 'domain', 6, 'windows', '使用有界图查询和 ACL 读取确认实验主体到高权限组的路径，不写 DACL、改密码或执行 DCSync。', 'Uses bounded graph queries and ACL reads to validate a lab principal path to privileged groups without writing DACLs, changing passwords, or performing DCSync.'),
  spec('domain-cross-trust', 'AD 跨域信任配置审计', 'AD Cross-Domain Trust Configuration Audit', 'domain', 6, 'windows', '只读取指定源域与目标域的信任方向、SID 过滤和选择性认证，不请求或注入票据。', 'Reads trust direction, SID filtering, and selective authentication for one source and target domain without requesting or injecting tickets.'),
  spec('dcsync-attack', 'DCSync 复制权限审计', 'DCSync Replication-Permission Audit', 'domain', 4, 'windows', '核对指定实验主体的目录复制扩展权限和 4662 事件，不复制账号秘密。', 'Reviews directory-replication extended rights and event 4662 for one lab principal without replicating account secrets.'),
  spec('golden-ticket', '黄金票据前置条件与检测审计', 'Golden-Ticket Preconditions and Detection Audit', 'domain', 4, 'windows', '使用合成票据元数据核对 krbtgt 轮换、加密类型、寿命和事件，不提取密钥或伪造票据。', 'Uses synthetic ticket metadata to review krbtgt rotation, encryption type, lifetime, and events without extracting keys or forging a ticket.'),
  spec('silver-ticket', '白银票据前置条件与检测审计', 'Silver-Ticket Preconditions and Detection Audit', 'domain', 3, 'windows', '使用合成服务票据核对 SPN、服务账号轮换和日志差异，不提取服务密钥或注入票据。', 'Uses a synthetic service ticket to review SPNs, service-account rotation, and log differences without extracting service keys or injecting a ticket.'),
  spec('zerologon', 'Zerologon 补丁与协议配置审计', 'Zerologon Patch and Protocol Configuration Audit', 'domain', 4, 'windows', '只核对实验域控制器版本、补丁、安全通道事件和强制模式，不重置机器账号密码。', 'Reviews lab domain-controller version, patches, secure-channel events, and enforcement mode without resetting a machine-account password.'),
  spec('printnightmare', 'PrintNightmare 暴露面与补丁审计', 'PrintNightmare Exposure and Patch Audit', 'domain', 3, 'windows', '核对 Spooler、Point and Print 策略、RPC 暴露和补丁，不加载 DLL 或触发远程认证。', 'Reviews Spooler, Point and Print policy, RPC exposure, and patches without loading a DLL or triggering remote authentication.'),
  spec('petitpotam', 'PetitPotam/EFSRPC 暴露审计', 'PetitPotam and EFSRPC Exposure Audit', 'domain', 3, 'windows', '核对 EFSRPC 可达性、NTLM 限制、AD CS EPA 和相关事件，不强制域控认证或中继。', 'Reviews EFSRPC reachability, NTLM restrictions, AD CS EPA, and related events without coercing domain-controller authentication or relaying it.'),
  spec('samaccountname', 'sAMAccountName/PAC 补丁边界审计', 'sAMAccountName and PAC Patch-Boundary Audit', 'domain', 3, 'windows', '核对 CVE-2021-42278/42287 补丁、机器账号配额和异常重命名事件，不创建机器账号或请求冒充票据。', 'Reviews CVE-2021-42278 and CVE-2021-42287 patches, machine-account quota, and anomalous rename events without creating an account or requesting an impersonation ticket.'),
  spec('resource-delegation', 'RBCD 委派属性与 ACL 审计', 'RBCD Delegation Attribute and ACL Audit', 'domain', 3, 'windows', '只读取 msDS-AllowedToActOnBehalfOfOtherIdentity、机器账号配额和对象 ACL，不创建账号或设置委派。', 'Reads msDS-AllowedToActOnBehalfOfOtherIdentity, machine-account quota, and object ACLs without creating an account or setting delegation.'),
  spec('dcshadow-attack', 'DCShadow 复制元数据检测审计', 'DCShadow Replication-Metadata Detection Audit', 'domain', 3, 'windows', '核对授权域控制器清单、复制拓扑和异常目录变更事件，不注册伪造 DC 或推送属性。', 'Reviews the approved domain-controller inventory, replication topology, and anomalous directory-change events without registering a rogue DC or pushing attributes.'),
  spec('group-policy-abuse', '组策略编辑权限与变更审计', 'Group-Policy Edit-Permission and Change Audit', 'domain', 3, 'windows', '读取有界 GPO ACL、版本与变更事件，不创建任务、写注册表首选项或修改 GPO。', 'Reads bounded GPO ACLs, versions, and change events without creating tasks, writing registry preferences, or modifying a GPO.'),
  spec('sam-the-admin', 'SAM The Admin/noPac 重复语义审计', 'SAM The Admin and noPac Duplicate-Semantics Audit', 'domain', 3, 'windows', '将该别名与 sAMAccountName/PAC 边界统一，核对补丁和事件，不获取 shell 或执行远程命令。', 'Aligns this alias with the sAMAccountName and PAC boundary and reviews patches plus events without obtaining a shell or running a remote command.'),
  spec('noauth', 'Kerberos NoAuth 版本与加密边界审计', 'Kerberos NoAuth Version and Encryption-Boundary Audit', 'domain', 3, 'windows', '绑定具体实现、CVE 与加密套件后核对补丁和票据事件，不获取 TGT 或设置凭据缓存。', 'Binds the check to a specific implementation, CVE, and cipher suite before reviewing patches and ticket events without obtaining a TGT or setting a credential cache.'),

  spec('evasion-powershell', 'PowerShell 编码与脚本遥测审计', 'PowerShell Encoding and Script-Telemetry Audit', 'evasion', 4, 'windows', '使用本地无害编码标记核对 Script Block、AMSI 和进程命令行日志，不下载或隐藏执行。', 'Uses a local harmless encoded marker to review Script Block, AMSI, and process command-line logs without downloading or hiding execution.'),
  spec('amsi-bypass', 'AMSI 完整性与事件审计', 'AMSI Integrity and Event Audit', 'evasion', 4, 'windows', '核对 AMSI 提供程序、PowerShell 事件和模块签名，不反射修改 AmsiUtils 或替换 amsi.dll。', 'Reviews AMSI providers, PowerShell events, and module signatures without reflectively changing AmsiUtils or replacing amsi.dll.'),
  spec('etw-patch', 'ETW 提供程序完整性审计', 'ETW Provider Integrity Audit', 'evasion', 3, 'windows', '核对 ETW 提供程序注册、事件连续性和内存保护，不 patch EtwEventWrite。', 'Reviews ETW provider registration, event continuity, and memory protections without patching EtwEventWrite.'),
  spec('evasion-blockdlls', '进程模块签名策略审计', 'Process Module-Signature Policy Audit', 'evasion', 3, 'windows', '读取目标进程的 BinarySignaturePolicy 与模块加载事件，不创建受保护进程或屏蔽安全 DLL。', 'Reads BinarySignaturePolicy and module-load events for a target process without creating a protected process or blocking security DLLs.'),
  spec('evasion-shellcode-encrypt', '编码内存载荷检测回归', 'Encoded In-Memory Payload Detection Regression', 'evasion', 4, 'windows', '只对不可执行字节夹具计算熵、哈希和静态规则结果，不解密或运行 shellcode。', 'Computes entropy, hashes, and static-rule results only for a non-executable byte fixture without decrypting or running shellcode.'),
  spec('evasion-process-masq', '进程映像与命令行一致性审计', 'Process Image and Command-Line Consistency Audit', 'evasion', 3, 'windows', '关联进程映像路径、签名、父进程和命令行遥测，不创建挂起或伪装进程。', 'Correlates process image path, signature, parent, and command-line telemetry without creating a suspended or masqueraded process.'),
  spec('evasion-ppid-spoof', '父进程属性与遥测一致性审计', 'Parent-Process Attribute and Telemetry Audit', 'evasion', 3, 'windows', '比较内核、ETW 与 EDR 的父进程字段并使用正常子进程夹具，不调用属性列表伪造 PPID。', 'Compares parent-process fields from kernel, ETW, and EDR using a normal child fixture without using attribute lists to spoof PPID.'),
  spec('evasion-dll-sideloading', 'DLL 侧加载搜索顺序检测', 'DLL Sideloading Search-Order Detection', 'evasion', 3, 'windows', '使用签名应用和不可执行标记 DLL 核对加载路径、签名与目录 ACL，不构建代理 DLL。', 'Uses a signed application and non-executable marker DLL to review load path, signature, and directory ACL without building a proxy DLL.'),
  spec('evasion-arg-spoofing', '进程参数多源遥测审计', 'Process-Argument Multi-Source Telemetry Audit', 'evasion', 3, 'windows', '比较创建事件、PEB 快照和安全产品命令行字段，不修改 PEB 或隐藏参数。', 'Compares process-creation events, PEB snapshots, and security-product command-line fields without modifying the PEB or hiding arguments.'),
  spec('evasion-clr-injection', 'CLR 程序集加载遥测审计', 'CLR Assembly-Load Telemetry Audit', 'evasion', 3, 'windows', '使用签名无害程序集核对 CLR Runtime、程序集加载和进程事件，不在其他进程内加载代码。', 'Uses a signed harmless assembly to review CLR runtime, assembly-load, and process events without loading code into another process.'),

  spec('proxylogon', 'Exchange ProxyLogon 补丁回归', 'Exchange ProxyLogon Patch Regression', 'exchange', 3, 'windows', '核对 Exchange 精确版本、补丁、前端/后端路由与无会话响应，不运行利用脚本。', 'Reviews exact Exchange version, patches, front-end and backend routing, and no-session responses without running an exploit script.'),
  spec('proxyshell', 'Exchange ProxyShell 补丁回归', 'Exchange ProxyShell Patch Regression', 'exchange', 3, 'windows', '核对 Exchange 版本、补丁和 Autodiscover/PowerShell 路由边界，不访问邮箱或执行命令。', 'Reviews Exchange version, patches, and Autodiscover or PowerShell routing boundaries without accessing mailboxes or executing commands.'),
  spec('exchange-proxytoken', 'Exchange ProxyToken 授权回归', 'Exchange ProxyToken Authorization Regression', 'exchange', 3, 'windows', '核对精确版本、补丁和前后端授权响应，不伪造 X-ClientApplication 或授予邮箱权限。', 'Reviews exact version, patches, and front-end or backend authorization responses without forging X-ClientApplication or granting mailbox permissions.'),
];

const familyContent = {
  credential: {
    category: i18n('凭据保护与审计', 'Credential Protection and Audit'),
    difficulty: 'advanced',
    principle: i18n('凭据风险来自秘密材料、备份权限、缓存、票据或密钥保护边界过宽。有效验证必须区分“对象存在或可列出”与“秘密可被未授权主体读取或使用”，不能把管理员工具成功运行直接等同于漏洞。', 'Credential risk arises when secret material, backup privileges, caches, tickets, or key-protection boundaries are overly broad. A valid validation distinguishes object visibility from unauthorized secret access or use; successful execution of an administrative tool is not itself a vulnerability.'),
    evidence: i18n('使用合成账号、离线夹具或只读 ACL 查询建立正常基线，再运行一个 PAYLOADER_CREDENTIAL 标记检查。只保存路径、类型、所有者、权限和事件 ID，不保存口令、哈希、票据、主密钥或明文内容；阳性必须由权限与访问日志共同支持。', 'Use a synthetic account, offline fixture, or read-only ACL query to establish a baseline and then run one PAYLOADER_CREDENTIAL marker check. Retain only paths, types, owners, permissions, and event IDs, never passwords, hashes, tickets, master keys, or plaintext; a positive result requires both permissions and access logs.'),
    mitigation: i18n('实施分层管理、最小权限、Credential Guard 或等效保护、强服务账号密码与现代 Kerberos 加密，限制备份/调试/复制权限并轮换暴露秘密。对 hive、LSASS、票据、SYSVOL 和凭据 API 访问建立告警，使用合成夹具回归。', 'Apply tiered administration, least privilege, Credential Guard or equivalent protection, strong service-account passwords, and modern Kerberos encryption. Restrict backup, debug, and replication rights, rotate exposed secrets, alert on hive, LSASS, ticket, SYSVOL, and credential-API access, and regress with synthetic fixtures.'),
    references: ['https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management', 'https://attack.mitre.org/tactics/TA0006/'],
  },
  lateral: {
    category: i18n('远程管理与横向边界', 'Remote Management and Lateral Boundaries'),
    difficulty: 'advanced',
    principle: i18n('横向风险来自远程管理协议、认证材料、服务控制、计划任务或会话权限超出分层管理边界。端口开放或管理协议可用只说明能力存在，只有未授权主体可执行远程动作并有目标端日志证明时才构成越权。', 'Lateral risk arises when remote-management protocols, authentication material, service control, scheduled tasks, or session permissions exceed the tiered administration boundary. An open port or available protocol shows capability only; unauthorized remote action plus target-side logs is required to prove an authorization failure.'),
    evidence: i18n('只对一台隔离实验主机运行 PAYLOADER_LATERAL 可达性、ACL 或事件查询，不传入真实口令、哈希、票据或远程命令。关联源主机、目标主机、防火墙和身份日志，确认协议、账号和授权范围；不创建服务、任务、进程或会话。', 'Run only a PAYLOADER_LATERAL reachability, ACL, or event query against one isolated lab host without real passwords, hashes, tickets, or remote commands. Correlate source, target, firewall, and identity logs to confirm protocol, account, and authorization scope; do not create services, tasks, processes, or sessions.'),
    mitigation: i18n('限制远程管理到专用管理网与跳板机，实施主机防火墙、SMB/LDAP 签名、EPA、强认证和分层管理员账号，禁用不需要的 WMI/DCOM/RDP/WinRM。监控远程服务、任务、会话和异常 NTLM/Kerberos 使用。', 'Restrict remote management to dedicated management networks and jump hosts; enforce host firewalls, SMB and LDAP signing, EPA, strong authentication, and tiered administrator accounts; disable unneeded WMI, DCOM, RDP, and WinRM; and monitor remote services, tasks, sessions, and anomalous NTLM or Kerberos use.'),
    references: ['https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory', 'https://attack.mitre.org/tactics/TA0008/'],
  },
  privesc: {
    category: i18n('权限边界与提权审计', 'Privilege Boundary and Escalation Audit'),
    difficulty: 'advanced',
    principle: i18n('提权风险来自服务、文件、令牌、安装策略、内核或计划执行边界允许低权限主体影响高权限进程。版本匹配、权限存在或工具可运行只是前置条件，必须证明可控对象与高权限执行之间存在实际授权缺口。', 'Privilege-escalation risk arises when services, files, tokens, installer policy, kernel, or scheduled execution let a low-privilege principal influence a high-privilege process. Version match, privilege presence, or tool availability is only a prerequisite; an actual authorization gap between a controllable object and privileged execution must be shown.'),
    evidence: i18n('在可回滚实验主机使用 PAYLOADER_PRIVESC 只读查询记录版本、补丁、ACL、所有者、服务账户和令牌权限，并与高权限基线对照。不修改服务、注册表、任务、SUID、sudoers 或进程，也不启动高权限 shell。', 'Use PAYLOADER_PRIVESC read-only queries on a reversible lab host to record version, patches, ACLs, owners, service accounts, and token privileges and compare them with a privileged baseline. Do not modify services, registry, tasks, SUID, sudoers, or processes and do not start a privileged shell.'),
    mitigation: i18n('应用安全补丁，移除不必要的模拟/备份/调试权限，收紧服务和目录 ACL、sudoers、SUID、安装策略与计划任务，使用受保护服务账户和应用控制。监控高权限子进程、配置变更和异常令牌使用，并用同一查询回归。', 'Apply security patches, remove unneeded impersonation, backup, and debug privileges, tighten service and directory ACLs, sudoers, SUID, installer policy, and scheduled tasks, and use protected service accounts plus application control. Monitor privileged child processes, configuration changes, and anomalous token use and replay the same queries.'),
    references: ['https://attack.mitre.org/tactics/TA0004/', 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'],
  },
  persistence: {
    category: i18n('持久化控制与检测', 'Persistence Control and Detection'),
    difficulty: 'advanced',
    principle: i18n('持久化风险来自启动项、服务、WMI、账号、票据或模块加载位置允许未批准对象在登录、启动或认证时持续生效。验证应读取配置与事件并和批准基线比较，而不是为了证明风险而创建后门。', 'Persistence risk arises when startup items, services, WMI, accounts, tickets, or module-load locations allow unapproved objects to remain effective at logon, startup, or authentication. Validation should read configuration and events and compare them with an approved baseline rather than creating a backdoor to prove risk.'),
    evidence: i18n('使用 PAYLOADER_PERSISTENCE 只读查询收集对象名称、路径、签名、所有者、ACL、创建时间和审计事件，限制结果数量并与配置管理清单比较。不创建用户、服务、任务、注册表值、事件订阅或注入模块。', 'Use PAYLOADER_PERSISTENCE read-only queries to collect object name, path, signature, owner, ACL, creation time, and audit event, limit result count, and compare with the configuration inventory. Do not create users, services, tasks, registry values, event subscriptions, or injected modules.'),
    mitigation: i18n('移除未批准持久化对象，收紧启动位置、服务、WMI、计划任务、账号与目录 ACL，使用代码签名和应用控制，并为创建/修改事件建立告警。对域控实施分层管理、krbtgt 轮换与完整性监控，修复后重复只读基线。', 'Remove unapproved persistence objects; tighten startup locations, services, WMI, scheduled tasks, accounts, and directory ACLs; enforce code signing and application control; and alert on create or modify events. Apply tiered administration, krbtgt rotation, and integrity monitoring to domain controllers and replay the read-only baseline.'),
    references: ['https://attack.mitre.org/tactics/TA0003/', 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol'],
  },
  domain: {
    category: i18n('Active Directory 安全边界', 'Active Directory Security Boundaries'),
    difficulty: 'advanced',
    principle: i18n('域风险来自复制、委派、信任、票据、组策略、机器账号或协议补丁边界过宽。有效结论必须绑定精确域、对象、权限、补丁和事件，不能把可读取目录、工具输出或旧 CVE 名称直接拼成通用域管链。', 'Domain risk arises when replication, delegation, trust, ticket, Group Policy, machine-account, or protocol patch boundaries are overly broad. A valid result binds the exact domain, object, permission, patch, and event and does not combine readable directory data, tool output, or old CVE names into a universal domain-admin chain.'),
    evidence: i18n('使用 PAYLOADER_DOMAIN 对单一实验对象执行有界只读查询，保存 DN、SID、权限 GUID、补丁、协议设置和事件 ID，并与权威目录/补丁基线核对。不写目录属性、改密码、注册域控、复制秘密、请求或注入票据。', 'Use PAYLOADER_DOMAIN bounded read-only queries for one lab object, preserving DN, SID, permission GUID, patch, protocol setting, and event ID and comparing them with authoritative directory and patch baselines. Do not write directory attributes, change passwords, register controllers, replicate secrets, or request or inject tickets.'),
    mitigation: i18n('实施分层管理和最小目录权限，收紧复制/委派/GPO/机器账号与信任配置，部署供应商补丁与强制模式，使用现代 Kerberos 加密、SMB/LDAP 签名和 EPA。监控敏感属性、复制、票据、机器重命名和域控注册事件。', 'Apply tiered administration and least directory privilege; tighten replication, delegation, GPO, machine-account, and trust configuration; deploy vendor patches and enforcement modes; use modern Kerberos encryption, SMB and LDAP signing, and EPA; and monitor sensitive attributes, replication, tickets, machine renames, and controller registration.'),
    references: ['https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory', 'https://attack.mitre.org/tactics/TA0008/'],
  },
  evasion: {
    category: i18n('终端防护与遥测完整性', 'Endpoint Protection and Telemetry Integrity'),
    difficulty: 'advanced',
    principle: i18n('终端风险来自脚本扫描、AMSI、ETW、模块签名、进程与命令行遥测之间存在盲区或完整性被破坏。验证目标是证明无害行为是否被稳定观测以及策略是否生效，不应通过关闭、patch 或规避安全控制来测试。', 'Endpoint risk arises from gaps or integrity failures across script scanning, AMSI, ETW, module signing, process, and command-line telemetry. Validation should prove whether harmless behavior is consistently observed and policy enforced, not test by disabling, patching, or evading security controls.'),
    evidence: i18n('运行一个本地签名或不可执行 PAYLOADER_EVASION 夹具，记录进程、脚本块、AMSI、ETW、模块加载与安全产品事件并对齐时间戳。只读取策略、签名、哈希和事件，不下载代码、修改内存、隐藏参数或执行 shellcode。', 'Run one local signed or non-executable PAYLOADER_EVASION fixture and align process, script-block, AMSI, ETW, module-load, and security-product events by timestamp. Read only policy, signatures, hashes, and events; do not download code, modify memory, hide arguments, or execute shellcode.'),
    mitigation: i18n('启用并集中收集 PowerShell、AMSI、ETW、进程创建和模块加载遥测，实施应用控制、代码签名、受保护进程和防篡改，限制调试/注入权限并更新检测规则。对遥测中断、未签名模块、异常父子关系和内存映像建立告警。', 'Enable and centralize PowerShell, AMSI, ETW, process-creation, and module-load telemetry; enforce application control, code signing, protected processes, and tamper protection; restrict debug and injection rights; update detections; and alert on telemetry gaps, unsigned modules, anomalous parent-child relationships, and memory images.'),
    references: ['https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol', 'https://attack.mitre.org/tactics/TA0005/'],
  },
  exchange: {
    category: i18n('Exchange 安全回归', 'Exchange Security Regression'),
    difficulty: 'advanced',
    principle: i18n('Exchange 风险必须绑定精确产品版本、累积更新、安全更新、启用角色和前后端路由。公开端点、HTTP 状态或产品名称不能证明 ProxyLogon、ProxyShell 或 ProxyToken；必须有补丁前置条件和服务端授权差异。', 'Exchange risk must bind the exact product version, cumulative update, security update, enabled role, and front-end or backend routing. A public endpoint, HTTP status, or product name does not prove ProxyLogon, ProxyShell, or ProxyToken; patch prerequisites and a server-side authorization difference are required.'),
    evidence: i18n('在隔离 Exchange 实验环境运行 PAYLOADER_EXCHANGE 版本、补丁、端点和无会话响应查询，保存 AdminDisplayVersion、更新清单、IIS/Exchange 日志与请求 ID。不访问邮箱、导出 PST、伪造头、写 WebShell 或执行利用脚本。', 'Run PAYLOADER_EXCHANGE version, patch, endpoint, and no-session response queries in an isolated Exchange lab, preserving AdminDisplayVersion, update inventory, IIS and Exchange logs, and request IDs. Do not access mailboxes, export PST, forge headers, write web shells, or run exploit scripts.'),
    mitigation: i18n('升级到受支持的 Exchange CU 并安装最新安全更新，运行供应商健康检查，限制管理端点与 ECP/PowerShell 暴露，强化 EPA、身份与反向代理规则。对异常 Autodiscover、EWS、MAPI、PowerShell 和邮箱权限变更建立审计。', 'Upgrade to a supported Exchange CU and current security update, run vendor health checks, restrict management endpoints and ECP or PowerShell exposure, and strengthen EPA, identity, and reverse-proxy rules. Audit anomalous Autodiscover, EWS, MAPI, PowerShell, and mailbox-permission changes.'),
    references: ['https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates', 'https://microsoft.github.io/CSS-Exchange/Diagnostics/HealthChecker/'],
  },
};

const markerFor = (specification, index) => {
  const id = specification.id.toUpperCase()
    .replace(/BACKDOOR/g, 'LEGACY_ACCOUNT')
    .replace(/[^A-Z0-9]+/g, '_');
  return `PAYLOADER_${specification.family.toUpperCase()}_${id}_E_${index + 1}`;
};

const credentialCommand = (specification, marker) => {
  const commands = {
    kerberoasting: "Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(objectCategory=person))' -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes -ResultSetSize 20 | Select-Object SamAccountName,ServicePrincipalName,msDS-SupportedEncryptionTypes",
    'sam-dump': 'Get-Acl "$env:SystemRoot\\System32\\config\\SAM" | Format-List Owner,AccessToString',
    'ntds-dump': 'Get-Acl "$env:SystemRoot\\NTDS\\ntds.dit" | Format-List Owner,AccessToString',
    'gpp-password': 'Get-ChildItem "\\\\{LAB_DOMAIN}\\SYSVOL\\{LAB_DOMAIN}\\Policies" -Filter "*.xml" -Depth 4 -ErrorAction Stop | Select-Object -First 50 FullName',
    'dpapi-creds': 'Get-ChildItem "{LAB_PROFILE_ROOT}\\AppData\\Roaming\\Microsoft\\Protect" -File -Depth 3 -ErrorAction Stop | Select-Object -First 20 FullName,Length,LastWriteTime',
    'rdp-creds': 'Get-ChildItem "{LAB_PROFILE_ROOT}\\Documents" -Filter "*.rdp" -Depth 3 -ErrorAction Stop | Select-Object -First 20 FullName,Length,LastWriteTime',
    'wifi-creds': 'netsh wlan show profiles',
    'vault-creds': 'vaultcmd /list',
    'keepass-dump': 'Get-ChildItem "{LAB_PROFILE_ROOT}" -Filter "*.kdbx" -Depth 4 -ErrorAction Stop | Select-Object -First 20 FullName,Length,LastWriteTime',
    'lsa-secrets': 'Get-Acl "$env:SystemRoot\\System32\\config\\SECURITY" | Format-List Owner,AccessToString',
  };
  return `${commands[specification.id] || 'Get-ChildItem "{LAB_CREDENTIAL_FIXTURE}" -File | Select-Object -First 20 FullName,Length'}; Write-Output "${marker}"`;
};

const lateralCommand = (specification, marker) => {
  const port = specification.id.includes('rdp') ? 3389
    : specification.id.includes('wmi') || specification.id.includes('dcom') ? 135
      : specification.id.includes('ticket') || specification.id.includes('hash') ? 88
        : 445;
  return `Test-NetConnection -ComputerName {LAB_HOST} -Port ${port} -InformationLevel Detailed; Write-Output "${marker}"`;
};

const privescCommand = (specification, marker) => {
  if (specification.platform === 'linux') {
    const command = specification.id === 'suid-exploit'
      ? 'find /usr/bin /usr/local/bin -xdev -perm -4000 -type f -print | head -n 50'
      : specification.id === 'sudo-exploit'
        ? 'sudo -n -l'
        : 'find /etc/cron.d /etc/cron.daily -maxdepth 1 -type f -printf "%p %u %m\\n" | head -n 50';
    return `${command}; printf '%s\\n' '${marker}'`;
  }
  const commands = {
    'privilege-token': 'whoami /priv',
    'uac-bypass': 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop',
    'dll-hijack': 'Get-Acl "{LAB_APPLICATION_DIRECTORY}" | Format-List Owner,AccessToString',
    'service-exploit': 'Get-CimInstance Win32_Service -Filter "Name=\'{LAB_SERVICE}\'" | Select-Object Name,StartName,StartMode,PathName',
    'always-install': 'Get-ItemProperty "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -ErrorAction SilentlyContinue | Select-Object AlwaysInstallElevated',
    'juicy-potato': 'whoami /priv | Select-String "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege"',
    printspoofer: 'Get-Service Spooler | Select-Object Name,Status,StartType',
    godpotato: 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber',
  };
  return `${commands[specification.id]}; Write-Output "${marker}"`;
};

const persistenceCommand = (specification, marker) => {
  const commands = {
    'persistence-registry': 'Get-ItemProperty "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -ErrorAction SilentlyContinue',
    'persistence-wmi': 'Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object -First 50 Name,Query,EventNamespace',
    'persistence-startup': 'Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -File -ErrorAction SilentlyContinue | Select-Object -First 50 FullName,LastWriteTime',
    'persistence-service': 'Get-CimInstance Win32_Service -Filter "StartMode=\'Auto\'" | Select-Object -First 50 Name,StartName,PathName,State',
    'persistence-dll-injection': 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" | Select-Object AppInit_DLLs,LoadAppInit_DLLs,RequireSignedAppInit_DLLs',
    'persistence-backdoor-user': 'Get-LocalUser | Select-Object -First 50 Name,Enabled,LastLogon,PasswordLastSet',
    'persistence-hidden-user': 'Get-LocalGroupMember Administrators | Select-Object -First 50 Name,ObjectClass,PrincipalSource',
    'skeleton-key': 'Get-Process lsass | Select-Object Id,StartTime,Path',
    'dsrm-backdoor': 'Get-ItemProperty "HKLM:\\System\\CurrentControlSet\\Control\\Lsa" -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue',
    'sid-history': 'Get-ADUser -Identity {LAB_USER} -Properties sIDHistory | Select-Object SamAccountName,sIDHistory',
    'persistence-process-hollowing': 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1,7,10} -MaxEvents 20 -ErrorAction SilentlyContinue',
  };
  return `${commands[specification.id]}; Write-Output "${marker}"`;
};

const domainCommand = (specification, marker) => {
  const commands = {
    'domain-privilege-escalation': 'Get-ADObject -Identity {LAB_OBJECT_DN} -Properties nTSecurityDescriptor | Select-Object DistinguishedName,nTSecurityDescriptor',
    'domain-cross-trust': 'Get-ADTrust -Filter * | Select-Object -First 20 Name,Direction,TrustType,SelectiveAuthentication,SIDFilteringForestAware',
    'dcsync-attack': 'Get-ADObject -Identity {LAB_DOMAIN_DN} -Properties nTSecurityDescriptor | Select-Object DistinguishedName,nTSecurityDescriptor',
    'golden-ticket': 'Get-ADUser krbtgt -Properties PasswordLastSet,msDS-SupportedEncryptionTypes | Select-Object SamAccountName,PasswordLastSet,msDS-SupportedEncryptionTypes',
    'silver-ticket': 'Get-ADUser -Identity {LAB_SERVICE_ACCOUNT} -Properties ServicePrincipalName,PasswordLastSet,msDS-SupportedEncryptionTypes | Select-Object SamAccountName,ServicePrincipalName,PasswordLastSet,msDS-SupportedEncryptionTypes',
    zerologon: 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber',
    printnightmare: 'Get-Service Spooler | Select-Object Name,Status,StartType',
    petitpotam: 'Get-SmbServerConfiguration | Select-Object EnableSecuritySignature,RequireSecuritySignature,RejectUnencryptedAccess',
    samaccountname: 'Get-ADDomain | Select-Object DNSRoot,DomainMode,DistinguishedName; Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{LAB_FOREST_DN}" -Properties ms-DS-MachineAccountQuota',
    'resource-delegation': 'Get-ADComputer -Identity {LAB_COMPUTER} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object Name,msDS-AllowedToActOnBehalfOfOtherIdentity',
    'dcshadow-attack': 'Get-ADDomainController -Filter * | Select-Object -First 20 HostName,Site,IsGlobalCatalog,OperationMasterRoles',
    'group-policy-abuse': 'Get-GPO -All | Select-Object -First 50 DisplayName,Id,ModificationTime,GpoStatus',
    'sam-the-admin': 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber',
    noauth: 'Get-ADDomain | Select-Object DNSRoot,DomainMode; Get-WinEvent -FilterHashtable @{LogName="Security";Id=4768,4769} -MaxEvents 20 -ErrorAction SilentlyContinue',
  };
  return `${commands[specification.id]}; Write-Output "${marker}"`;
};

const evasionCommand = (specification, marker) => {
  const commands = {
    'evasion-powershell': 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-PowerShell/Operational";Id=4103,4104} -MaxEvents 20 -ErrorAction SilentlyContinue',
    'amsi-bypass': 'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,productState,pathToSignedProductExe',
    'etw-patch': 'logman query providers | Select-Object -First 50',
    'evasion-blockdlls': 'Get-ProcessMitigation -Name {LAB_PROCESS}',
    'evasion-shellcode-encrypt': 'Get-FileHash "{LAB_NONEXECUTABLE_BYTE_FIXTURE}" -Algorithm SHA256',
    'evasion-process-masq': 'Get-CimInstance Win32_Process | Select-Object -First 50 ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine',
    'evasion-ppid-spoof': 'Get-CimInstance Win32_Process | Select-Object -First 50 ProcessId,ParentProcessId,Name,CreationDate',
    'evasion-dll-sideloading': 'Get-AuthenticodeSignature "{LAB_APPLICATION_BINARY}" | Select-Object Status,StatusMessage,SignerCertificate',
    'evasion-arg-spoofing': 'Get-CimInstance Win32_Process | Select-Object -First 50 ProcessId,ParentProcessId,Name,CommandLine',
    'evasion-clr-injection': 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-DotNETRuntime/Operational"} -MaxEvents 20 -ErrorAction SilentlyContinue',
  };
  return `${commands[specification.id]}; Write-Output "${marker}"`;
};

const exchangeCommand = (specification, marker) => (
  `Get-ExchangeServer | Select-Object -First 20 Name,AdminDisplayVersion,ServerRole; Write-Output "${marker}"`
);

const safeCommand = (specification, index) => {
  const marker = markerFor(specification, index);
  switch (specification.family) {
    case 'credential': return credentialCommand(specification, marker);
    case 'lateral': return lateralCommand(specification, marker);
    case 'privesc': return privescCommand(specification, marker);
    case 'persistence': return persistenceCommand(specification, marker);
    case 'domain': return domainCommand(specification, marker);
    case 'evasion': return evasionCommand(specification, marker);
    case 'exchange': return exchangeCommand(specification, marker);
    default: throw new Error(`Unknown intranet review family: ${specification.family}`);
  }
};

const hasHan = value => /\p{Script=Han}/u.test(String(value || ''));

const looksExecutableLine = value => {
  const line = String(value || '').trim();
  if (!line || /^(?:#|\/\/|REM\b|::)/i.test(line)) return false;
  if (/^\d+[.)]\s*$/.test(line) || /^-+\s*$/.test(line) || /^-\s+[A-Za-z]/.test(line)) return false;
  if (/^(?:使用|检查|获取|设置|添加|创建|执行|将|访问|构造|检测|加载|导出|恢复|中继|需要|寻找|结合|确认|参考|替换|任何|如果|运行时|从|不|或|首先|重点|直接|简单|修改|自动获得)/u.test(line)) {
    return false;
  }
  return /^(?:--[a-z]|\$|\[|[A-Za-z0-9_.\\/'"`-]+(?:\s|\(|:|=|$)|[0-9]+\s*=|(?:GET|POST|PUT|DELETE)\s)/i.test(line);
};

const cleanNarrativeLine = value => {
  const line = String(value || '').trim();
  if (!line || /^(?:#|\/\/|REM\b|::)/i.test(line)) return '';
  if (!hasHan(line)) return looksExecutableLine(line) ? line : '';
  const embeddedOption = line.match(/(--[a-z][^\r\n]*)$/i);
  if (embeddedOption) return embeddedOption[1].trim();
  const hanIndex = line.search(/\p{Script=Han}/u);
  const prefix = line.slice(0, hanIndex).trim().replace(/(?:\/\/|#)\s*$/, '').trim();
  if (!prefix || !looksExecutableLine(prefix)) return '';
  return prefix;
};

const normalizeLabPlaceholders = value => {
  let command = String(value || '');
  const replacements = [
    [/\badmin@domain\.com\b/gi, '{LAB_ADMIN_EMAIL}'],
    [/\bwebserver\.target\.com\b/gi, '{LAB_SERVICE_HOST}'],
    [/\bdomain\/user:password@/gi, '{LAB_DOMAIN}/{LAB_USER}:{LAB_PASSWORD}@'],
    [/\bdomain\.com\/user:password@/gi, '{LAB_DOMAIN}/{LAB_USER}:{LAB_PASSWORD}@'],
    [/\btarget\.domain\.com\b/gi, '{LAB_DOMAIN}'],
    [/\bfoo\.com\b/gi, '{LAB_DOMAIN}'],
    [/\btargets\.txt\b/gi, './fixtures/targets.txt'],
    [/\bdomain\/user\b/gi, '{LAB_DOMAIN}/{LAB_USER}'],
    [/\buser:password\b/gi, '{LAB_USER}:{LAB_PASSWORD}'],
    [/\btarget_ip\b/gi, '{LAB_HOST}'],
    [/\battacker_ip\b/gi, '{LAB_OPERATOR_HOST}'],
    [/\bdc_ip\b/gi, '{DC_HOST}'],
    [/\bdc_name\b/gi, '{DC_HOST}'],
    [/\bexchange\.com\b/gi, '{EXCHANGE_HOST}'],
    [/\bdomain\.com\b/gi, '{LAB_DOMAIN}'],
    [/\bDOMAIN\b/g, '{LAB_DOMAIN}'],
    [/\btarget\.com\b/gi, '{LAB_DOMAIN}'],
    [/\battacker\.com\b/gi, '{LAB_OPERATOR_HOST}'],
    [/\battacker\b/gi, '{LAB_OPERATOR_HOST}'],
    [/\bntlm_hash\b/gi, '{LAB_NTLM_HASH}'],
    [/\bnthash\b/gi, '{LAB_NTLM_HASH}'],
    [/\boriginal_ntlm\b/gi, '{LAB_NTLM_HASH}'],
    [/\bbase64_cmd\b/gi, '{LAB_BASE64_COMMAND}'],
    [/\bBASE64_ENCODED_COMMAND\b/g, '{LAB_BASE64_COMMAND}'],
    [/\bshellcode\.bin\b/gi, '{LAB_SHELLCODE_FILE}'],
    [/\bencoded\.bin\b/gi, '{LAB_ENCODED_FILE}'],
    [/\bmalicious\.dll\b/gi, '{LAB_DLL_FILE}'],
    [/\bTARGET_COMPUTER\b/g, '{LAB_COMPUTER}'],
    [/\bFAKECOMPUTER\b/g, '{LAB_MACHINE}'],
    [/\bxxx\b/gi, '{LAB_VALUE}'],
    [/(?:"|')password(?:"|')/gi, '"{LAB_PASSWORD}"'],
    [/\bHASH\b/g, '{LAB_NTLM_HASH}'],
    [/\bshell\.sh\b/gi, './fixtures/cron.sh'],
  ];
  for (const [pattern, replacement] of replacements) command = command.replace(pattern, replacement);
  command = command
    .replace(/(-u\s+)user\b/gi, '$1{LAB_USER}')
    .replace(/(-p\s+)(?:password|pass)\b/gi, '$1{LAB_PASSWORD}')
    .replace(/(\/user:)user\b/gi, '$1{LAB_USER}')
    .replace(/(\/password:)(?:password|pass)\b/gi, '$1{LAB_PASSWORD}')
    .replace(/(-ComputerName\s+)target\b/gi, '$1{LAB_HOST}')
    .replace(/(-d\s+)domain\b/gi, '$1{LAB_DOMAIN}')
    .replace(/(-dc-host\s+)DC_NAME\b/gi, '$1{DC_HOST}')
    .replace(/(\\\\)target\b/gi, '$1{LAB_HOST}');
  return command;
};

const appendMarker = (command, specification, marker) => {
  const markerCommand = specification.platform === 'linux'
    ? `printf '%s\\n' '${marker}'`
    : `Write-Output "${marker}"`;
  return `${String(command).trim()}\n${markerCommand}`;
};

const reviewedCommand = (original, specification, index) => {
  const source = String(original?.command || '').trim();
  const executableLines = source.split(/\r?\n/).map(cleanNarrativeLine).filter(Boolean);
  const cleaned = normalizeLabPlaceholders(executableLines.join('\n')).trim();
  if (cleaned === source) return null;
  if (!cleaned) return safeCommand(specification, index);
  if (cleaned.split(/\r?\n/).every(line => /^--[a-z]/i.test(line.trim()))) {
    return appendMarker(`tar -cf ./artifacts/cron-fixture.tar ${cleaned}`, specification, markerFor(specification, index));
  }
  return appendMarker(cleaned, specification, markerFor(specification, index));
};

const reviewEntry = specification => {
  const family = familyContent[specification.family];
  const nameZh = specification.name.zh;
  const nameEn = specification.name.en;
  return {
    id: specification.id,
    name: specification.name,
    description: i18n(
      `${nameZh}保留原始可复现技术命令，并将执行范围限定在书面授权、可回滚的隔离实验环境；仅修复明显占位符、纯叙述行和不可执行片段，同时要求关联身份、主机、目录、网络和安全产品证据。`,
      `${nameEn} preserves the original reproducible technique commands while restricting execution to a written, reversible, isolated lab authorization. Only obvious placeholders, narrative-only lines, and non-executable fragments are repaired, with identity, host, directory, network, and security-product evidence required.`,
    ),
    category: family.category,
    subCategory: specification.name,
    prerequisites: [
      i18n(`确认 ${nameZh} 的实验域、主机、账号、组件版本和停止条件已书面授权且可回滚。`, `Confirm that the lab domain, host, account, component version, and stop conditions for ${nameEn} are authorized in writing and reversible.`),
      i18n('准备正常基线、合成对象、唯一标记、回滚快照以及身份、系统和网络日志；任何写入、远程执行或凭据操作都必须属于当前隔离实验授权。', 'Prepare a normal baseline, synthetic object, unique marker, rollback snapshot, and identity, system, and network logs; every write, remote execution, or credential action must be within the current isolated-lab authorization.'),
    ],
    tutorial: {
      overview: i18n(
        `${nameZh}聚焦以下边界：${specification.scope.zh} 审校后保留原始技术能力，并按实验授权、执行前提、蓝队证据和修复回归组织内容，避免把工具成功、管理员权限或旧版利用结果直接当作普遍漏洞。`,
        `${nameEn} focuses on this boundary: ${specification.scope.en} The reviewed entry preserves the original technical capability and organizes it around lab authorization, execution prerequisites, blue-team evidence, and remediation regression so tool success, administrator access, or old exploit results are not treated as universal vulnerabilities.`,
      ),
      vulnerability: family.principle,
      exploitation: i18n(
        `${family.evidence.zh} 原始技术命令仅在隔离实验环境按单条、单目标执行，并同步保存蓝队证据（目标端事件、网络流量和安全产品告警）以证明能力与检测覆盖。`,
        `${family.evidence.en} Run retained technique commands one at a time against one target in an isolated lab, preserving blue-team evidence such as target-side events, network traffic, and security-product alerts to prove both capability and detection coverage.`,
      ),
      mitigation: family.mitigation,
      difficulty: family.difficulty,
    },
    attackChain: [
      {
        title: i18n(`确认 ${nameZh} 的版本与授权边界`, `Confirm Version and Authorization for ${nameEn}`),
        description: i18n(`记录 ${nameZh} 的实验对象、执行主体、系统或域版本、补丁、正常配置和停止条件，确认真实前置条件。`, `Record the lab object, execution principal, system or domain version, patches, normal configuration, and stop conditions for ${nameEn} and confirm the actual prerequisites.`),
      },
      {
        title: i18n(`运行一条 ${nameZh} 已审查命令`, `Run One Reviewed ${nameEn} Command`),
        description: i18n('在隔离实验中只运行第一条已审查命令，保存原始输出、时间戳、目标端日志和回滚状态；涉及写入或远程动作时严格遵守单目标授权。', 'Run only the first reviewed command in the isolated lab, preserving raw output, timestamps, target-side logs, and rollback state; any write or remote action must stay within the one-target authorization.'),
        payloadRef: { area: 'execution', index: 0 },
      },
      {
        title: i18n(`关联 ${nameZh} 的控制面证据`, `Correlate Control-Plane Evidence for ${nameEn}`),
        description: i18n('把唯一标记与身份、目录、系统、网络或安全产品事件对齐，并排除管理员正常能力、工具输出、缓存和版本不匹配。', 'Align the unique marker with identity, directory, system, network, or security-product events and exclude normal administrator capability, tool output, caching, and version mismatch.'),
      },
      {
        title: i18n(`修复 ${nameZh} 边界并回归`, `Remediate the ${nameEn} Boundary and Regress`),
        description: i18n('应用最小权限、补丁或配置修复后重复正常与只读标记查询，确认管理功能保留且非预期权限、可见性或遥测缺口消失。', 'Apply least privilege, a patch, or configuration remediation and repeat the normal and read-only marker queries to preserve administration while removing unintended privilege, visibility, or telemetry gaps.'),
      },
    ],
    analysis: i18n(
      `${nameZh}只有在精确版本与对象、当前主体、已审查命令输出、权威配置和服务端日志相互一致时才能确认。端口开放、工具成功、权限名称存在、状态码或单一事件只能作为线索；能力证明与漏洞结论必须分别记录。`,
      `${nameEn} is confirmed only when the exact version and object, current principal, reviewed command output, authoritative configuration, and server-side logs agree. An open port, successful tool run, privilege name, status code, or single event is only a lead; capability proof and vulnerability conclusion must be recorded separately.`,
    ),
    opsecTips: [
      i18n('一次只查询一个实验对象并限制结果数量，不保存凭据、哈希、票据、邮箱正文或无关个人数据。', 'Query one lab object at a time with bounded results and do not retain credentials, hashes, tickets, mailbox content, or unrelated personal data.'),
      i18n('发现超出授权的写操作、远程进程、账号变更、防护中断或非实验目标时立即停止，执行回滚并保存审计时间点。', 'Stop immediately, roll back, and preserve the audit timestamp on any write, remote process, account change, protection gap, or non-lab target outside the authorization.'),
    ],
    references: family.references,
    review: {
      decision: 'payload',
      rationale: `${specification.scope.zh} 该条目保留为具体技术验证卡，保留可复现攻击能力，仅修复不可执行叙述和明显占位符，并补充隔离授权、回滚和蓝队证据要求。`,
      issuesResolved: [
        'reviewed-every-source-command',
        'preserved-reviewed-technique-capabilities',
        'repaired-narrative-and-placeholder-lines',
        'added-isolated-lab-and-rollback-boundaries',
        'added-blue-team-evidence-requirements',
        'added-version-and-evidence-boundaries',
      ],
    },
  };
};

const commandPatches = (source, specification) => {
  const originals = asList(source?.execution);
  if (originals.length !== specification.executionCount || asList(source?.wafBypass).length !== 0) {
    throw new Error(`${source.id} command counts changed: expected ${specification.executionCount}/0, found ${originals.length}/${asList(source?.wafBypass).length}`);
  }
  return originals.flatMap((original, index) => {
    const command = reviewedCommand(original, specification, index);
    if (!command) return [];
    const marker = markerFor(specification, index);
    const patch = {
      area: 'execution',
      index,
      expectedCommand: String(original?.command || ''),
      command,
      title: i18n(`${specification.name.zh}校正命令 ${index + 1}`, `${specification.name.en} Reviewed Command ${index + 1}`),
      description: i18n(
        `仅修正原命令中的纯叙述行或明显实验占位符，保留 ${specification.name.zh} 技术能力；在隔离授权环境运行并关联 ${marker} 与蓝队日志。`,
        `Repair only narrative-only lines or obvious lab placeholders while preserving the ${specification.name.en} capability; run it in the isolated authorization and correlate ${marker} with blue-team logs.`,
      ),
    };
    if (original?.syntaxBreakdown !== undefined) patch.syntaxBreakdown = structuredClone(original.syntaxBreakdown);
    if (original?.platform !== undefined) patch.platform = original.platform;
    else patch.platform = specification.platform;
    if (original?.requiresAdmin !== undefined) patch.requiresAdmin = original.requiresAdmin;
    return [patch];
  });
};

export const buildIntranetTechniqueReviewDocuments = payloadsInput => {
  const sourceById = new Map(asList(payloadsInput).map(payload => [payload.id, payload]));
  const reviewed = intranetTechniqueReviewSpecs.map(specification => {
    const source = sourceById.get(specification.id);
    if (!source) throw new Error(`Missing source payload: ${specification.id}`);
    return { specification, source };
  });
  return {
    overrides: {
      schemaVersion: 1,
      contentStandard: 2,
      sourceIds: reviewed.map(({ specification }) => specification.id),
      entries: reviewed.map(({ specification }) => reviewEntry(specification)),
    },
    commandOverrides: {
      schemaVersion: 1,
      entries: reviewed.flatMap(({ specification, source }) => {
        const patches = commandPatches(source, specification);
        return patches.length ? [{ id: specification.id, patches }] : [];
      }),
    },
  };
};

const outputFiles = [
  ['overrides-intranet-techniques.json', 'overrides'],
  ['payload-command-overrides-intranet-techniques.json', 'commandOverrides'],
];

const run = () => {
  const root = resolve(process.cwd());
  const snapshot = loadCurationSnapshot(join(root, 'data', 'payloader.sqlite'));
  const documents = buildIntranetTechniqueReviewDocuments(snapshot.payloads);
  for (const [fileName, key] of outputFiles) {
    const file = join(root, 'content-review', fileName);
    writeFileSync(file, `${JSON.stringify(documents[key], null, 2)}\n`, 'utf8');
    console.log(`wrote ${fileName}`);
  }
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) run();
