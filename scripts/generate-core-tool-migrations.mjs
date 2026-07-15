import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadCurationSnapshot } from './apply-payload-curation.mjs';

const i18n = (zh, en) => ({ zh, en });
const asList = value => Array.isArray(value) ? value : [];
const reviewedCommand = (command, titleZh, titleEn, descriptionZh, descriptionEn) => ({
  command,
  title: i18n(titleZh, titleEn),
  description: i18n(descriptionZh, descriptionEn),
});
const migrationTarget = (targetToolId, navRootId, commandIndexes, references, wafBypassIndexes = []) => ({
  targetToolId,
  navRootId,
  commandIndexes,
  wafBypassIndexes,
  references,
});

const directoryEditorial = {
  vulnerability: i18n('目录、SPN、用户、组、GPO、信任和共享查询结果本身不是漏洞。只有查询身份获得了超出既定职责的对象、属性或共享可见性，并由目录 ACL、审计日志和批准基线共同证明时，才构成有效发现。', 'Directory, SPN, user, group, GPO, trust, and share query results are not vulnerabilities by themselves. A valid finding requires visibility beyond the querying identity\'s approved role, supported by directory ACLs, audit logs, and the approved baseline.'),
  mitigation: i18n('按职责收紧目录读取、共享 ACL 和高权限组成员关系，清理过期 SPN、GPO 与信任配置，并记录高价值对象查询。修复后使用同一身份、SearchBase、对象和结果上限重复只读查询。', 'Apply role-based directory visibility, share ACLs, and privileged-group membership; remove stale SPNs, GPOs, and trusts; and audit high-value object queries. Retest with the same identity, SearchBase, object, and result limit.'),
  evidence: i18n('把结果与目录 ACL、对象属性、共享权限、变更记录和域控制器审计日志对照，区分正常目录可见性、历史配置和真实越权。', 'Compare results with directory ACLs, object attributes, share permissions, change history, and domain-controller audit logs to distinguish normal visibility, legacy configuration, and actual authorization failures.'),
  analysis: i18n('结论必须标明查询身份、SearchBase 或单一目标、结果上限、工具版本和权威目录证据。命令成功、对象存在或 adminCount 标记不能单独证明权限风险。', 'A conclusion must identify the query identity, SearchBase or single target, result limit, tool version, and authoritative directory evidence. Command success, object existence, or an adminCount flag alone does not prove privilege risk.'),
};

const networkEditorial = {
  vulnerability: i18n('本机接口、路由、邻居缓存和授权主机端口状态是运维数据，不是漏洞。只有暴露面与资产清单、分段策略或监听基线不一致，并由防火墙、主机和网络日志共同证实时，才构成发现。', 'Local interfaces, routes, neighbor caches, and port state on an authorized host are operational data rather than vulnerabilities. A finding requires a mismatch with inventory, segmentation policy, or the listener baseline corroborated by firewall, host, and network logs.'),
  mitigation: i18n('移除不需要的监听与路由，按资产角色收紧主机防火墙和分段策略，并对扫描速率、来源和失败连接建立审计。使用同一单主机、端口列表和速率上限执行回归。', 'Remove unnecessary listeners and routes, enforce host firewall and segmentation by asset role, and audit scan rate, source, and failed connections. Retest with the same single host, port list, and rate limits.'),
  evidence: i18n('把只读主机信息或有界探测结果与 CMDB、防火墙策略、监听进程和流量日志对照，避免把超时、过滤或服务横幅直接判定为漏洞。', 'Compare read-only host information or bounded probes with CMDB records, firewall policy, listening processes, and traffic logs instead of treating timeouts, filtering, or service banners as vulnerabilities.'),
  analysis: i18n('报告必须包含单一授权主机、显式端口集合、速率和重试上限、时间窗口及主机或网络侧证据；不得从一次开放端口或横幅推断可利用性。', 'Reports must include one authorized host, an explicit port set, rate and retry limits, a time window, and host- or network-side evidence; one open port or banner does not establish exploitability.'),
};

const serviceEditorial = {
  vulnerability: i18n('Exchange 或 SharePoint 端点、站点、列表和版本元数据的可见性本身不是漏洞。有效发现需要证明当前测试身份读取了超出已批准租户、站点或角色边界的数据，并能与服务端授权决策和审计日志关联。', 'Visibility of Exchange or SharePoint endpoints, sites, lists, and version metadata is not a vulnerability by itself. A valid finding requires proof that the test identity read data beyond its approved tenant, site, or role boundary, correlated with server authorization decisions and audit logs.'),
  mitigation: i18n('按租户、站点和邮箱角色实施最小权限，禁用遗留认证，限制 Autodiscover、OAB、REST 和搜索返回字段，并保留管理与读取审计。修复后重放同一只读元数据请求。', 'Enforce least privilege by tenant, site, and mailbox role; disable legacy authentication; constrain Autodiscover, OAB, REST, and search fields; and retain administrative and read auditing. Replay the same metadata-only request after remediation.'),
  evidence: i18n('把固定条数的元数据响应与租户配置、站点权限、Exchange RBAC 和统一审计日志对照，不下载邮件正文、文档内容或离线通讯录。', 'Compare a fixed-size metadata response with tenant configuration, site permissions, Exchange RBAC, and unified audit logs without downloading mail bodies, document content, or offline address books.'),
  analysis: i18n('证据必须包含测试身份、租户或站点、请求字段、结果上限和服务端授权日志；HTTP 200、产品版本或对象名称不能单独证明越权。', 'Evidence must identify the test identity, tenant or site, requested fields, result limit, and server authorization logs. HTTP 200, a product version, or an object name alone does not prove unauthorized access.'),
};

const tunnelEditorial = {
  vulnerability: i18n('隧道、代理或客户端帮助输出不是漏洞。风险来自监听绑定超出回环、缺少认证、允许未批准目标、持久化启动或绕过分段策略，必须由进程参数、监听套接字、路由和流量日志证明。', 'Tunnel, proxy, or client help output is not a vulnerability. Risk comes from listeners beyond loopback, missing authentication, unapproved destinations, persistent startup, or segmentation bypass and must be proven through process arguments, sockets, routes, and traffic logs.'),
  mitigation: i18n('默认绑定回环，限制单一 marker 服务和短时会话，启用身份校验、失败退出和集中日志，禁止全网段路由与持久化服务。回归时先检查参数和监听范围，再发送一个本地 marker 请求。', 'Bind to loopback by default, limit testing to one marker service and a short-lived session, require identity checks and failure-on-forward, centralize logs, and prohibit broad routes or persistent services. Retest arguments and listener scope before one local marker request.'),
  evidence: i18n('核对帮助或预检输出、进程参数、回环监听、单一 marker 流量和清理结果；不得启动远程 Agent、全流量路由或对未声明网段执行探测。', 'Correlate help or preflight output, process arguments, loopback listeners, one marker flow, and cleanup results without starting remote agents, full-traffic routing, or probes against undeclared networks.'),
  analysis: i18n('有效结论需要监听地址、端口、目标服务、会话时长、认证方式和清理证据。工具存在、帮助可用或 SOCKS 端口可创建都不代表分段被绕过。', 'A valid conclusion requires listener address, port, destination service, session duration, authentication method, and cleanup evidence. Tool availability, help output, or the ability to create a SOCKS port does not establish segmentation bypass.'),
};

const remoteAccessEditorial = {
  vulnerability: i18n('远程管理工具、WinRM/SSH 可达性和帮助输出本身不是漏洞。有效发现需要证明未经批准的身份或网络边界可以执行远程操作，并由服务端授权、主机日志和网络策略共同证实。', 'Remote-management tools, WinRM or SSH reachability, and help output are not vulnerabilities by themselves. A valid finding requires proof that an unapproved identity or network boundary can perform remote operations, corroborated by server authorization, host logs, and network policy.'),
  mitigation: i18n('按主机角色限制 SSH、WinRM 和 WinRS 来源，强制密钥或短期凭证、最小权限与分段策略，关闭不需要的远程服务并审计会话。修复后以同一身份和单一实验主机重复预检。', 'Restrict SSH, WinRM, and WinRS sources by host role; enforce keys or short-lived credentials, least privilege, and segmentation; disable unneeded services and audit sessions. Repeat the preflight with the same identity and one lab host after remediation.'),
  evidence: i18n('把配置展开、单主机响应、身份、端口、认证方式与 Windows/OpenSSH 审计日志对照，不把连接成功或客户端存在直接视为越权。', 'Correlate configuration expansion, one-host responses, identity, port, authentication method, and Windows or OpenSSH audit logs without treating client availability or connection success as unauthorized access.'),
  analysis: i18n('结论必须记录单一目标、身份、认证方式、监听地址、命令输出和服务端审计事件；帮助文本或端口开放不能单独证明横向移动风险。', 'Conclusions must record one target, identity, authentication method, listener address, command output, and server audit events; help text or an open port alone does not prove lateral-movement risk.'),
};

const windowsPrivilegeEditorial = {
  vulnerability: i18n('Windows 令牌权限、服务清单或未引用路径只是枚举结果。只有低权限主体能够修改由高权限服务加载的二进制、目录、注册表参数或服务配置，并且重启或触发条件可达时，才形成可利用的提权边界。', 'Windows token privileges, service inventory, and unquoted paths are enumeration results only. An exploitable boundary requires a low-privilege principal to modify a binary, directory, registry argument, or service configuration loaded by a privileged service, with a reachable restart or trigger condition.'),
  mitigation: i18n('收紧服务对象、二进制目录和注册表 ACL，引用包含空格的服务路径，移除不必要的令牌权限并使用受管服务账号。修复后以同一低权限主体重复 ACL 与服务基线查询。', 'Tighten service-object, binary-directory, and registry ACLs; quote service paths containing spaces; remove unnecessary token privileges; and use managed service identities. Repeat the ACL and service baseline with the same low-privilege principal after remediation.'),
  evidence: i18n('关联 whoami 令牌、服务 StartName/PathName、服务对象 ACL、文件与父目录 ACL、启动方式以及 4688、4697、7045 或 EDR 事件；仅有 Everyone 字样或未引用路径不能证明可提权。', 'Correlate the whoami token, service StartName and PathName, service-object ACLs, file and parent-directory ACLs, start method, and 4688, 4697, 7045, or EDR events. An Everyone entry or unquoted path alone does not prove privilege escalation.'),
  analysis: i18n('结论必须指出低权限主体、可写对象、高权限加载方、触发条件和可回滚证据；缺少任一环节时只能记为待核配置。', 'A conclusion must identify the low-privilege principal, writable object, privileged loader, trigger condition, and reversible evidence; without every link, classify it as configuration requiring review.'),
};

const linuxPrivilegeEditorial = {
  vulnerability: i18n('SUID、sudo、Linux capabilities、Cron 或 systemd 条目本身不是漏洞。只有当前低权限主体可控制高权限程序的可执行文件、参数、环境变量、搜索路径或被加载资源，并能稳定到达高权限执行点时，才构成提权链。', 'SUID files, sudo rules, Linux capabilities, Cron entries, and systemd units are not vulnerabilities by themselves. Privilege escalation requires the current low-privilege principal to control a privileged program, argument, environment variable, search path, or loaded resource and reliably reach the privileged execution point.'),
  mitigation: i18n('移除非必要 SUID/SGID 与 file capabilities，使用精确 sudo 命令和参数约束，修复 Cron/systemd 文件及父目录所有权，并清理可写 PATH 与动态库搜索路径。修复后以同一 UID/GID 重放只读枚举。', 'Remove unnecessary SUID or SGID bits and file capabilities, constrain sudo commands and arguments precisely, correct Cron or systemd file and parent-directory ownership, and remove writable PATH or library-search entries. Replay read-only enumeration with the same UID and GID after remediation.'),
  evidence: i18n('关联 UID/GID、mount 选项、sudoers 展开结果、文件及父目录 mode/owner/capabilities、任务运行身份和 auditd/journal 事件；仅匹配 GTFOBins 条目不能证明目标配置可利用。', 'Correlate UID and GID, mount options, expanded sudoers rules, file and parent-directory mode, owner and capabilities, task identity, and auditd or journal events. A GTFOBins match alone does not prove that the target configuration is exploitable.'),
  analysis: i18n('结论必须给出主体、具体文件或规则、可控输入、高权限消费者和触发方式；只列出 SUID 文件、sudo -l 或内核版本属于发现线索而非提权证据。', 'A conclusion must identify the principal, exact file or rule, controllable input, privileged consumer, and trigger. A SUID list, sudo -l output, or kernel version is a lead rather than privilege-escalation proof.'),
};

const kernelRiskEditorial = {
  vulnerability: i18n('内核版本字符串或漏洞扫描器命中不能直接证明可利用。发行版可能回移补丁，实际适用性取决于内核包构建、架构、配置项、命名空间与 LSM、容器边界以及攻击者当前权限。', 'A kernel version string or scanner match does not prove exploitability. Distributions may backport fixes, and applicability depends on the exact kernel package build, architecture, configuration, namespaces and LSMs, container boundary, and the attacker\'s current privileges.'),
  mitigation: i18n('按发行版公告和已安装包版本确认修复状态，升级受支持内核并完成必要重启，禁用不需要的用户命名空间或高风险模块，并监控异常崩溃和提权行为。修复后重新采集同一版本与包基线。', 'Use distribution advisories and installed package versions to confirm fix status, upgrade to a supported kernel and reboot when required, disable unnecessary user namespaces or risky modules, and monitor anomalous crashes and elevation. Recollect the same version and package baseline after remediation.'),
  evidence: i18n('关联 uname、发行版与内核包版本、供应商公告、启动中的实际内核、关键配置和补丁状态；不得用 Searchsploit 结果或上游版本范围替代发行版适用性判断。', 'Correlate uname output, distribution and kernel package versions, vendor advisories, the actually booted kernel, relevant configuration, and patch state. Do not substitute Searchsploit results or upstream version ranges for distribution-specific applicability.'),
  analysis: i18n('报告必须标明发行版、精确包构建、架构、启动内核、适用公告与前置权限；缺少供应商适用性证据时只能记录待核 CVE。', 'Reports must identify the distribution, exact package build, architecture, booted kernel, applicable advisory, and prerequisite privileges. Without vendor applicability evidence, record only a CVE requiring review.'),
};

const potatoEditorial = {
  vulnerability: i18n('Potato 系列依赖具体的 Token 模拟权限、服务身份、Windows 版本、COM/RPC 或命名管道行为以及补丁状态。存在 SeImpersonatePrivilege 或某个工具二进制并不等于任意版本都可提权。', 'Potato-family techniques depend on specific token-impersonation privileges, service identities, Windows versions, COM or RPC or named-pipe behavior, and patch state. SeImpersonatePrivilege or a tool binary does not mean every variant can elevate on every version.'),
  mitigation: i18n('移除不需要的 SeImpersonatePrivilege 与 SeAssignPrimaryTokenPrivilege，避免高权限服务向低信任主体暴露可模拟的本地接口，应用系统与 .NET 补丁，并监控异常命名管道、COM/RPC、令牌复制和 SYSTEM 子进程。', 'Remove unnecessary SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege, prevent privileged services from exposing impersonable local interfaces to low-trust principals, apply OS and .NET patches, and monitor anomalous named pipes, COM or RPC, token duplication, and SYSTEM child processes.'),
  evidence: i18n('关联当前服务账号、有效令牌权限、OS build、工具支持矩阵、命名管道或 COM/RPC 事件、4688/Sysmon 进程树与最终 Token；账户创建、下载和回连动作必须与最小权限证明分开记录。', 'Correlate the service identity, effective token privileges, OS build, tool support matrix, named-pipe or COM or RPC events, 4688 or Sysmon process trees, and resulting token. Record account creation, downloads, and callbacks separately from minimal privilege proof.'),
  analysis: i18n('有效链路必须证明前置权限、适用技术变体、高权限 Token 或进程结果及清理状态；工具帮助、权限名称或失败进程不能单独确认提权。', 'A valid chain must prove the prerequisite privilege, applicable technique variant, privileged token or process result, and cleanup state. Tool help, a privilege name, or a failed process does not confirm elevation.'),
};

const unattendedCredentialEditorial = {
  vulnerability: i18n('无人值守 XML、Sysprep、GPP、部署脚本或连接字符串只有在低权限主体可读且仍包含可用秘密时才形成凭据暴露。文件名、字段名、Base64 或 cpassword 标记本身不能证明存在有效凭据。', 'Unattended XML, Sysprep, Group Policy Preferences, deployment scripts, or connection strings expose credentials only when a low-privilege principal can read a still-usable secret. A filename, field name, Base64 value, or cpassword marker alone does not prove valid credential exposure.'),
  mitigation: i18n('从镜像、部署共享和历史 GPO 中移除秘密，轮换已暴露账号，使用 LAPS、gMSA 或密钥保管服务，限制 Panther 与部署目录 ACL，并对敏感字段和异常读取建立审计。', 'Remove secrets from images, deployment shares, and historical GPOs; rotate exposed identities; use LAPS, gMSA, or a secret vault; restrict Panther and deployment-directory ACLs; and audit sensitive fields and anomalous reads.'),
  evidence: i18n('记录文件路径、所有者、ACL、部署来源、字段类型和秘密生命周期；正文只保留脱敏哈希或专用测试值，并用身份系统日志确认是否仍有效，禁止在报告中保存真实密码。', 'Record the file path, owner, ACL, deployment source, field type, and secret lifecycle. Retain only a redacted hash or dedicated test value, and use identity logs to confirm validity without storing a real password in the report.'),
  analysis: i18n('结论必须同时证明未授权可读、秘密材料存在且仍具业务效力，并记录轮换与清理；仅发现配置文件或编码字段属于资产卫生问题。', 'A conclusion must prove unauthorized readability, the presence of secret material, and current business validity, with rotation and cleanup recorded. Finding a configuration file or encoded field alone is an asset-hygiene issue.'),
};

const executionControlEditorial = {
  vulnerability: i18n('签名二进制、AppLocker 规则和进程注入 API 的存在或签名状态不是漏洞。有效发现需要证明策略允许未授权代码执行、跨边界进程写入或绕过审计，并由策略、令牌、进程树和日志证实。', 'The presence or signature state of signed binaries, AppLocker rules, and process-injection APIs is not a vulnerability by itself. A valid finding requires proof that policy permits unauthorized code execution, cross-boundary process writes, or audit bypass, corroborated by policy, tokens, process trees, and logs.'),
  mitigation: i18n('按路径和发布者收紧 AppLocker/WDAC 规则，阻止用户可写目录中的代理执行，启用进程访问审计与 EDR 规则并限制调试权限。修复后只做签名和策略预检。', 'Tighten AppLocker or WDAC rules by path and publisher, block proxy execution from user-writable directories, enable process-access auditing and EDR rules, and restrict debug privileges. Re-run signature and policy preflights after remediation.'),
  evidence: i18n('保存签名状态、策略命中、进程路径、父子关系、令牌和审计事件，区分合法系统组件调用与未授权代码执行。', 'Preserve signature status, policy decisions, process paths, parent-child relationships, tokens, and audit events to distinguish legitimate system-component use from unauthorized code execution.'),
  analysis: i18n('结论必须说明发布者、路径、策略规则、主体令牌和执行/写入证据；二进制存在或帮助输出不能单独证明绕过。', 'Conclusions must state publisher, path, policy rule, principal token, and execution or write evidence; binary presence or help output alone does not prove a bypass.'),
};

const persistenceEditorial = {
  vulnerability: i18n('计划任务、Cron 条目和管理 cmdlet 是持久化管理面，不是漏洞本身。有效发现需要证明低权限主体可创建或修改高权限触发器，且该路径绕过审批或审计。', 'Scheduled tasks, Cron entries, and management cmdlets are persistence administration surfaces, not vulnerabilities by themselves. A valid finding requires proof that a low-privilege principal can create or modify a privileged trigger outside approved change and audit controls.'),
  mitigation: i18n('限制任务和 Cron 文件的写权限，按服务身份执行最小权限，启用创建/修改审计并清理遗留条目。修复后仅读取同一任务路径和审计事件，确认正常运维仍可用。', 'Restrict write access to task and Cron definitions, run service identities with least privilege, audit creation and modification, and remove stale entries. Re-read the same task path and audit events after remediation while preserving legitimate operations.'),
  evidence: i18n('关联任务路径、触发器、运行身份、动作路径、文件 ACL、变更审批和系统日志，不执行动作或注册新任务。', 'Correlate task path, trigger, run identity, action path, file ACL, change approval, and system logs without executing an action or registering a new task.'),
  analysis: i18n('报告应记录任务/条目、主体、触发时间、动作文件、权限差异和清理证据；命令帮助或现有任务名称不能单独证明持久化漏洞。', 'Reports should record the task or entry, principal, trigger time, action file, permission delta, and cleanup evidence; command help or an existing task name alone does not prove a persistence vulnerability.'),
};

const sqlEditorial = {
  vulnerability: i18n('SQL 语法样例和数据库产品信息不是漏洞。有效发现需要在授权的合成数据或单一测试记录上证明输入到查询结构的未参数化边界，并保存请求、响应和数据库审计证据。', 'SQL syntax samples and database product information are not vulnerabilities. A valid finding requires proof of an unparameterized input-to-query boundary on authorized synthetic data or one test record, with request, response, and database-audit evidence preserved.'),
  mitigation: i18n('使用参数化查询、类型约束、最小数据库账号和统一错误处理，限制测试账号与合成数据范围并记录查询审计。修复后仅重放同一只读基线，不扩大数据集或权限。', 'Use parameterized queries, type constraints, least-privilege database accounts, and uniform error handling; constrain the test identity to synthetic data and retain query audits. Replay only the same read-only baseline after remediation without expanding data or privileges.'),
  evidence: i18n('对照预期查询模板、参数绑定日志、固定 marker 响应和数据库审计，区分错误处理、搜索语法与真实结构注入。', 'Compare the expected query template, parameter-binding logs, fixed-marker response, and database audit to distinguish error handling or search syntax from true structural injection.'),
  analysis: i18n('结论必须包含单一端点、测试记录、参数、响应差异、数据库版本和日志关联；仅有字符串样例或错误页面不能证明 SQL 注入。', 'Conclusions must identify one endpoint, test record, parameter, response delta, database version, and log correlation; a string sample or error page alone does not prove SQL injection.'),
};

const migrationProfiles = [
  {
    id: 'domain-recon',
    targetToolId: 'active-directory-enumeration',
    navRootId: 'domain-pentest-tools',
    labelZh: 'Active Directory 只读枚举命令',
    labelEn: 'Read-Only Active Directory Enumeration Commands',
    category: i18n('域渗透工具', 'Active Directory Tools'),
    rationale: '原条目由 net、nltest 和 PowerView 枚举命令组成，属于工具命令手册；迁入 AD 域内枚举工具卡，不再作为独立 Payload 展示。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net',
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nltest',
      'https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1',
    ],
    execution: [
      {
        command: 'net config workstation\nwhoami /upn',
        title: i18n('确认工作站域上下文', 'Confirm the Workstation Domain Context'),
        description: i18n('读取当前工作站的域、登录域和系统配置摘要，先确认命令运行在哪个授权域上下文。', 'Read the workstation domain, logon domain, and configuration summary to confirm the authorized domain context before further queries.'),
      },
      {
        command: 'nltest /dclist:{DOMAIN}',
        title: i18n('列出指定域的域控制器', 'List Domain Controllers for One Domain'),
        description: i18n('仅查询占位符 {DOMAIN} 对应域的域控制器列表，并把结果与 DNS SRV 记录和资产清单交叉核对。', 'Query domain controllers only for {DOMAIN}, then compare the result with DNS SRV records and the authorized asset inventory.'),
      },
      {
        command: 'net user /domain\nwhoami /groups',
        title: i18n('读取域用户与当前组上下文', 'Read Domain Users and the Current Group Context'),
        description: i18n('读取域用户名称清单并记录当前主体的组令牌，用于区分目录可见性和本机有效授权，不尝试任何认证。', 'Read the domain user-name list and current principal group token to distinguish directory visibility from effective local authorization without attempting authentication.'),
      },
      {
        command: 'Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name,SamAccountName,ObjectClass',
        title: i18n('核对域管理员组成员', 'Review Domain Admins Membership'),
        description: i18n('读取 Domain Admins 当前成员并与批准的高权限账号基线比较，不修改组成员关系。', 'Read current Domain Admins membership and compare it with the approved privileged-account baseline without changing group membership.'),
      },
      {
        command: 'nltest /domain_trusts /all_trusts',
        title: i18n('读取域信任摘要', 'Read the Domain Trust Summary'),
        description: i18n('读取当前域可见的信任关系摘要，记录方向、类型和目标域，并以目录配置为最终依据。', 'Read the visible trust summary for the current domain, recording direction, type, and target domain while treating directory configuration as authoritative.'),
      },
      {
        command: 'Import-Module .\\PowerView.ps1\nGet-Domain -Domain {DOMAIN}',
        title: i18n('从本地模块读取域对象', 'Read the Domain Object from a Local Module'),
        description: i18n('从已审查的本地 PowerView 文件导入模块并读取 {DOMAIN} 域对象，禁止通过网络下载并直接执行脚本。', 'Import a reviewed local PowerView file and read the {DOMAIN} domain object; do not download and execute scripts over the network.'),
      },
      {
        command: 'Get-DomainPolicy -Domain {DOMAIN}',
        title: i18n('读取域策略基线', 'Read the Domain Policy Baseline'),
        description: i18n('使用已加载的 PowerView 模块读取指定域策略，重点核对口令、锁定和 Kerberos 配置，不做任何策略修改。', 'Use the loaded PowerView module to read password, lockout, and Kerberos policy for one domain without modifying policy.'),
      },
      {
        command: 'Get-DomainController -Domain {DOMAIN}',
        title: i18n('读取域控制器对象', 'Read Domain Controller Objects'),
        description: i18n('使用已加载的 PowerView 模块读取指定域的控制器对象，并与 nltest 和 DNS 结果交叉验证。', 'Use the loaded PowerView module to read domain-controller objects for one domain and cross-check them against nltest and DNS results.'),
      },
    ],
  },
  {
    id: 'cdn-bypass',
    targetToolId: 'web-recon-tools',
    navRootId: 'web-extended-tools',
    labelZh: 'CDN 源站暴露与配置审计',
    labelEn: 'CDN Origin Exposure and Configuration Audit',
    category: i18n('Web 侦察工具', 'Web Reconnaissance Tools'),
    rationale: '原条目是 DNS、证书透明度、HTTP 和源站配置命令集合，并非单一 Payload；迁入 Web 侦察工具卡并删除注入、全端口扫描、伪造代理头和修改 hosts 等内容。',
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/',
      'https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/',
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host',
    ],
    execution: [
      {
        command: 'dig +short {DOMAIN} A\ndig +short {DOMAIN} AAAA\ndig +short {DOMAIN} CNAME',
        title: i18n('记录当前 DNS 基线', 'Record the Current DNS Baseline'),
        description: i18n('读取授权域名当前的 A、AAAA 和 CNAME 记录，记录时间与解析器，用于和资产清单及 CDN 配置对照。', 'Read current A, AAAA, and CNAME records for the authorized domain, recording time and resolver for comparison with the asset inventory and CDN configuration.'),
      },
      {
        command: 'dig +short {DOMAIN} MX\ndig +short {DOMAIN} TXT',
        title: i18n('核对邮件与 TXT 记录', 'Review Mail and TXT Records'),
        description: i18n('读取 MX 与 TXT 记录以识别公开邮件和策略端点，只记录公开 DNS 元数据，不触发邮件或业务流程。', 'Read MX and TXT records to identify public mail and policy endpoints while recording public DNS metadata only and without triggering mail or business workflows.'),
      },
      {
        command: 'curl -sS "https://crt.sh/?q=%25.{DOMAIN}&output=json" | jq -r \'.[].name_value\' | sort -u',
        title: i18n('查询证书透明度名称', 'Query Certificate Transparency Names'),
        description: i18n('从公开证书透明度数据提取与授权域名相关的名称候选，结果仍需通过 DNS 和资产所有权复核。', 'Extract names related to the authorized domain from public certificate-transparency data, then verify candidates through DNS and asset ownership.'),
      },
      {
        command: 'subfinder -silent -d {DOMAIN} | sort -u',
        title: i18n('生成被动子域候选', 'Generate Passive Subdomain Candidates'),
        description: i18n('使用被动数据源生成授权域名的子域候选，只把可解析且属于资产清单的名称纳入后续检查。', 'Generate passive subdomain candidates for the authorized domain and retain only names that resolve and belong to the approved asset inventory.'),
      },
      {
        command: 'curl -sS -D edge.headers -o edge.body "https://{DOMAIN}/healthz"\ncurl -sS -D origin.headers -o origin.body --resolve "{DOMAIN}:443:{ORIGIN_IP}" "https://{DOMAIN}/healthz"',
        title: i18n('对比边缘与登记源站健康响应', 'Compare Edge and Registered-Origin Health Responses'),
        description: i18n('仅对自有登记源站的固定 healthz 路径比较边缘与直连响应，保存状态、证书和响应头，不扫描其他端口或路径。', 'Compare edge and direct responses only for a fixed health endpoint on a registered owned origin, preserving status, certificate, and headers without scanning other ports or paths.'),
      },
    ],
    wafBypass: [
      {
        command: 'curl -sS -o edge-health.body -w "edge=%{http_code}\\n" "https://{DOMAIN}/healthz"\ncurl -sS -o origin-health.body -w "origin=%{http_code}\\n" --resolve "{DOMAIN}:443:{ORIGIN_IP}" "https://{DOMAIN}/healthz"',
        title: i18n('复测源站访问控制', 'Retest Origin Access Control'),
        description: i18n('修复后对同一健康检查分别访问 CDN 和登记源站，确认边缘可用且源站按预期拒绝未授权直连。', 'After remediation, request the same health endpoint through the CDN and the registered origin to confirm edge availability and expected rejection of unauthorized direct access.'),
      },
    ],
  },
  {
    id: 'spn-scan',
    labelZh: 'SPN 与服务账号只读核对',
    labelEn: 'Read-Only SPN and Service-Account Review',
    category: i18n('域渗透工具', 'Active Directory Tools'),
    rationale: '原条目是 setspn、ActiveDirectory 模块和 Impacket 命令手册；迁入 AD 枚举与 Impacket 工具卡，并将全域查询、明文凭证和票据请求替换为单服务、SearchBase 限定或帮助检查。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn',
      'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser',
      'https://github.com/fortra/impacket',
    ],
    editorial: directoryEditorial,
    targets: [
      migrationTarget('active-directory-enumeration', 'domain-pentest-tools', [0, 1, 3, 4], [
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn',
        'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser',
      ]),
      migrationTarget('impacket', 'intranet-tools', [2], ['https://github.com/fortra/impacket']),
    ],
    execution: [
      reviewedCommand(
        'setspn -Q HTTP/{SERVICE_HOST}',
        '查询单一 HTTP 服务 SPN',
        'Query One HTTP Service SPN',
        '仅查询授权服务主机对应的 HTTP SPN，并记录登记主体，不再使用 */* 枚举整个域。',
        'Query the HTTP SPN for one authorized service host and record its registered principal instead of enumerating every SPN in the domain.',
      ),
      reviewedCommand(
        "Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -SearchBase '{SEARCH_BASE}' -ResultSetSize 100 -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName",
        '在 SearchBase 内读取 SPN 用户',
        'Read SPN Users Within One SearchBase',
        '把查询限制到批准的 SearchBase 和最多 100 个结果，只输出账号与 SPN 属性。',
        'Limit the query to the approved SearchBase and at most 100 results, returning only account and SPN properties.',
      ),
      reviewedCommand(
        'impacket-GetUserSPNs -h',
        '查看 Impacket SPN 查询参数',
        'Inspect Impacket SPN Query Arguments',
        '只查看已安装版本的参数，不在命令行嵌入域凭证或请求任何服务票据。',
        'Inspect arguments for the installed version without embedding domain credentials or requesting service tickets.',
      ),
      reviewedCommand(
        'setspn -T {DOMAIN} -Q HTTP/{SERVICE_HOST}',
        '在指定域核对 HTTP SPN',
        'Review an HTTP SPN in One Domain',
        '在单一授权域中核对一个 HTTP 服务主机，避免通配服务和全域结果集。',
        'Review one HTTP service host in one authorized domain without wildcard services or domain-wide result sets.',
      ),
      reviewedCommand(
        'setspn -T {DOMAIN} -Q MSSQLSvc/{SERVICE_HOST}:{SERVICE_PORT}',
        '核对单一 MSSQL 服务 SPN',
        'Review One MSSQL Service SPN',
        '查询一个已登记主机和端口的 MSSQLSvc SPN，并与服务账号清单核对。',
        'Query the MSSQLSvc SPN for one registered host and port and compare it with the service-account inventory.',
      ),
    ],
  },
  {
    id: 'port-scan',
    labelZh: '有界单主机端口核对',
    labelEn: 'Bounded Single-Host Port Review',
    category: i18n('信息收集工具', 'Reconnaissance Tools'),
    rationale: '原条目包含 /24、全 65535 端口、Masscan 和 vuln NSE 的无界主动扫描；迁入 Nmap 与网络枚举工具卡，并限定为单一实验主机、显式端口、低速率和非侵入脚本。',
    references: [
      'https://nmap.org/book/man.html',
      'https://nmap.org/book/man-performance.html',
      'https://nmap.org/book/nse-usage.html',
    ],
    editorial: networkEditorial,
    targets: [
      migrationTarget('nmap', 'recon-tools', [0, 1, 2, 3, 5, 6, 7], [
        'https://nmap.org/book/man.html',
        'https://nmap.org/book/man-performance.html',
        'https://nmap.org/book/nse-usage.html',
      ]),
      migrationTarget('network-enum-tools', 'tunneling-tools', [4], ['https://nmap.org/book/man.html']),
    ],
    execution: [
      reviewedCommand(
        'nmap -sT -Pn --top-ports 20 --max-rate 20 --max-retries 1 {LAB_HOST}',
        '低速核对常见 TCP 端口',
        'Review Common TCP Ports at a Low Rate',
        '仅对单一实验主机检查常见 20 个 TCP 端口，并限制速率和重试次数。',
        'Check the 20 most common TCP ports on one lab host with explicit rate and retry limits.',
      ),
      reviewedCommand(
        'nmap -sT -Pn -p 22,80,443,445,3389 --max-rate 10 --max-retries 1 {LAB_HOST}',
        '核对批准的 TCP 端口集合',
        'Review an Approved TCP Port Set',
        '使用显式五端口列表替代全端口扫描，目标固定为一个授权实验主机。',
        'Replace the full-port scan with an explicit five-port list against one authorized lab host.',
      ),
      reviewedCommand(
        'nmap -sT -sV --version-light -Pn -p 22,80,443 --max-rate 10 {LAB_HOST}',
        '轻量识别三个服务端口',
        'Lightly Identify Three Service Ports',
        '只对三个批准端口执行轻量版本识别，不运行默认或漏洞 NSE 脚本。',
        'Run light version detection on three approved ports without default or vulnerability NSE scripts.',
      ),
      reviewedCommand(
        'nmap -sn --max-rate 5 --max-retries 1 {LAB_HOST}',
        '确认单一实验主机可达性',
        'Confirm Reachability of One Lab Host',
        '只检查一个登记主机是否可达，不枚举整个网段。',
        'Check reachability for one registered host without enumerating a network range.',
      ),
      reviewedCommand(
        'nmap -sT -Pn -p 80,443 --max-rate 5 --max-retries 1 {LAB_HOST}',
        '以有界 Nmap 代替 Masscan',
        'Replace Masscan with a Bounded Nmap Check',
        '移除高速全端口 Masscan，仅对一个实验主机的两个 Web 端口执行低速检查。',
        'Remove high-speed full-port Masscan and check only two web ports on one lab host at a low rate.',
      ),
      reviewedCommand(
        'nmap -O --osscan-limit --max-os-tries 1 --max-rate 5 --max-retries 1 --host-timeout 30s -Pn -p 22,80,443 {LAB_HOST}',
        '限制操作系统指纹尝试',
        'Limit Operating-System Fingerprint Attempts',
        '仅对有响应端口的单一实验主机执行一次受限 OS 指纹尝试。',
        'Run one limited OS fingerprint attempt against a single lab host with responsive ports.',
      ),
      reviewedCommand(
        'nmap -sU --top-ports 5 --max-rate 5 --max-retries 1 {LAB_HOST}',
        '低速核对五个 UDP 端口',
        'Review Five UDP Ports at a Low Rate',
        '把 UDP 检查限定到一个实验主机、五个常见端口和一次重试。',
        'Limit UDP review to one lab host, five common ports, and one retry.',
      ),
      reviewedCommand(
        'nmap -sT -Pn -p 80,443 --script http-title,http-headers --max-rate 5 {LAB_HOST}',
        '运行非侵入 HTTP 元数据脚本',
        'Run Non-Intrusive HTTP Metadata Scripts',
        '使用 http-title 和 http-headers 替代 vuln 脚本，只收集两个 Web 端口的响应元数据。',
        'Use http-title and http-headers instead of vulnerability scripts and collect response metadata from two web ports only.',
      ),
    ],
  },
  {
    id: 'network-recon',
    labelZh: '本机网络状态只读核对',
    labelEn: 'Read-Only Local Network State Review',
    category: i18n('信息收集工具', 'Reconnaissance Tools'),
    rationale: '原条目是 Windows/Linux 本机网络诊断命令集合；迁入 internal-recon 工具卡，保留只读状态查询，并把 traceroute 限定为实验网关、五跳和短超时。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig',
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/route_ws2008',
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert',
      'https://man7.org/linux/man-pages/man8/ip.8.html',
    ],
    editorial: networkEditorial,
    targets: [
      migrationTarget('internal-recon', 'tunneling-tools', [0, 1, 2, 3, 4, 5, 6, 7], [
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig',
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/route_ws2008',
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert',
        'https://man7.org/linux/man-pages/man8/ip.8.html',
      ]),
    ],
    execution: [
      reviewedCommand('Get-NetIPConfiguration -Detailed | Select-Object -First 50 InterfaceAlias,IPv4Address,IPv6Address,DNSServer,NetProfile', '读取有界 Windows 接口配置', 'Read a Bounded Windows Interface Configuration', '使用 PowerShell 读取最多 50 条本机接口、地址、DNS 和网络配置摘要，不修改网络配置。', 'Use PowerShell to read at most 50 local interface, address, DNS, and network configuration summaries without modifying network configuration.'),
      reviewedCommand('Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object -First 50 DestinationPrefix,NextHop,InterfaceAlias,RouteMetric', '读取有界 Windows 路由表', 'Read a Bounded Windows Route Table', '按路由度量读取最多 50 条 IPv4 路由与接口信息，和批准的分段基线比较。', 'Read at most 50 IPv4 routes and interface details ordered by metric, then compare them with the approved segmentation baseline.'),
      reviewedCommand('Get-NetNeighbor -AddressFamily IPv4 | Select-Object -First 100 IPAddress,LinkLayerAddress,State,InterfaceAlias', '读取有界本机邻居缓存', 'Read a Bounded Local Neighbor Cache', '读取最多 100 条现有 IPv4 邻居缓存，不发送额外探测包。', 'Read at most 100 existing IPv4 neighbor-cache entries without sending additional probes.'),
      reviewedCommand("Get-NetTCPConnection | Where-Object State -in 'Listen','Established' | Select-Object -First 100 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess", '读取有限 TCP 连接清单', 'Read a Limited TCP Connection List', '读取最多 100 条监听或已建立连接，并关联本机进程。', 'Read at most 100 listening or established connections and correlate them with local processes.'),
      reviewedCommand('Get-DnsClientCache | Select-Object -First 100 Entry,RecordName,RecordType,Status', '读取有界 Windows DNS 缓存', 'Read a Bounded Windows DNS Cache', '读取最多 100 条本机 DNS 缓存记录用于故障排查，不触发远程解析。', 'Read at most 100 local DNS cache records for troubleshooting without triggering remote resolution.'),
      reviewedCommand('ip -brief address', '读取 Linux 接口摘要', 'Read the Linux Interface Summary', '使用 iproute2 输出本机接口与地址摘要，不使用已弃用的 ifconfig。', 'Use iproute2 to show local interface and address summaries instead of deprecated ifconfig output.'),
      reviewedCommand('ip -4 route show table main | head -n 50', '读取有界 Linux 路由表', 'Read a Bounded Linux Route Table', '读取 Linux 主路由表最多 50 行并与实验拓扑核对，不修改路由。', 'Read at most 50 lines from the Linux main route table and compare them with the lab topology without changing routes.'),
      reviewedCommand('tracert -d -h 5 -w 500 {LAB_GATEWAY}', '限制到实验网关的路由跟踪', 'Trace a Route Only to the Lab Gateway', '仅对登记实验网关执行最多五跳、每跳 500 毫秒的路由跟踪。', 'Trace only the registered lab gateway with at most five hops and a 500 millisecond timeout per hop.'),
    ],
  },
  {
    id: 'share-enum',
    labelZh: 'SMB 共享可见性只读核对',
    labelEn: 'Read-Only SMB Share Visibility Review',
    category: i18n('域渗透工具', 'Active Directory Tools'),
    rationale: '原条目混合 net、SMBMap、CrackMapExec、smbclient 和 PowerView；迁入 SMB 与 PowerView 工具卡，移除明文凭证、旧 CME 名称和递归敏感文件搜索。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-share',
      'https://www.samba.org/samba/docs/current/man-html/smbclient.1.html',
      'https://www.netexec.wiki/',
      'https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon',
    ],
    editorial: directoryEditorial,
    targets: [
      migrationTarget('smb-pentest', 'tunneling-tools', [0, 1, 2, 3, 4], [
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-share',
        'https://www.samba.org/samba/docs/current/man-html/smbclient.1.html',
        'https://www.netexec.wiki/',
      ]),
      migrationTarget('powerview-adrecon', 'domain-pentest-tools', [5], ['https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon']),
    ],
    execution: [
      reviewedCommand('Get-SmbShare -ErrorAction SilentlyContinue | Select-Object -First 50 Name,Path,Description', '读取有界本机共享清单', 'Read a Bounded Local Share List', '使用 SMB 模块读取最多 50 个本机已发布共享及其路径，不创建、删除或修改共享。', 'Use the SMB module to read at most 50 local published shares and paths without creating, deleting, or modifying shares.'),
      reviewedCommand('net view \\\\{LAB_HOST}', '读取单一实验主机共享', 'Read Shares on One Lab Host', '只查询一个授权实验主机公布的共享名称，不扩展到工作组或网段。', 'Query published share names on one authorized lab host without expanding to a workgroup or network range.'),
      reviewedCommand('smbclient -L //{LAB_HOST}/ -U {LAB_USER}', '使用交互凭证列出共享', 'List Shares with Interactive Credentials', '对单一实验主机使用专用测试账号并交互输入凭证，避免把密码写入命令。', 'Use a dedicated test identity against one lab host and enter credentials interactively instead of placing a password in the command.'),
      reviewedCommand('nxc smb {LAB_HOST} -u {LAB_USER} -p ./fixtures/lab-password.txt --shares --timeout 5', '使用 NetExec 核对共享权限', 'Review Share Permissions with NetExec', '使用本地实验凭证文件对一个主机执行一次共享查询，并设置五秒超时。', 'Use a local lab credential file for one share query against one host with a five-second timeout.'),
      reviewedCommand("smbclient -L //{LAB_HOST}/ -U {LAB_USER} --option='client min protocol=SMB2'", '以 SMB2 最低协议列出共享', 'List Shares with SMB2 as the Minimum Protocol', '对一个实验主机列出共享并显式禁用 SMB1 协商，不读取文件内容。', 'List shares on one lab host while disabling SMB1 negotiation and without reading file content.'),
      reviewedCommand('Find-DomainShare -Domain {DOMAIN} -CheckShareAccess | Select-Object -First 20 Name,ComputerName', '限制 PowerView 共享查询结果', 'Limit PowerView Share Query Results', '只返回指定域最多 20 个当前身份可见的共享，不递归搜索共享文件。', 'Return at most 20 shares visible to the current identity in one domain without recursively searching files.'),
    ],
  },
  {
    id: 'user-enum',
    labelZh: '域用户对象有界核对',
    labelEn: 'Bounded Domain User Object Review',
    category: i18n('域渗透工具', 'Active Directory Tools'),
    rationale: '原条目混合 net、PowerView 和 Impacket 的全域用户枚举；迁入 AD、PowerView 与 Impacket 工具卡，限定 SearchBase、单一实验用户和结果上限，并移除明文凭证。',
    references: [
      'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser',
      'https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon',
      'https://github.com/fortra/impacket',
    ],
    editorial: directoryEditorial,
    targets: [
      migrationTarget('active-directory-enumeration', 'domain-pentest-tools', [0, 1, 4], ['https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser']),
      migrationTarget('powerview-adrecon', 'domain-pentest-tools', [2, 3], ['https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon']),
      migrationTarget('impacket', 'intranet-tools', [5], ['https://github.com/fortra/impacket']),
    ],
    execution: [
      reviewedCommand("Get-ADUser -Filter * -SearchBase '{SEARCH_BASE}' -ResultSetSize 100 | Select-Object SamAccountName,Enabled,DistinguishedName", '在 SearchBase 内读取用户摘要', 'Read User Summaries Within One SearchBase', '限定批准的 SearchBase 和最多 100 个结果，只输出账号、启用状态和 DN。', 'Limit the query to the approved SearchBase and at most 100 results, returning account, enabled state, and distinguished name only.'),
      reviewedCommand('Get-ADUser -Identity {LAB_USER} -Properties Enabled,LastLogonDate,MemberOf | Select-Object SamAccountName,Enabled,LastLogonDate,MemberOf', '读取单一实验用户属性', 'Read One Lab User Object', '读取专用实验用户的有限属性，不遍历其他账号或认证数据。', 'Read a limited property set for one dedicated lab user without traversing other identities or authentication data.'),
      reviewedCommand('Get-DomainUser -Identity {LAB_USER} -Domain {DOMAIN} | Select-Object SamAccountName,Enabled,AdminCount', '使用 PowerView 读取实验用户', 'Read a Lab User with PowerView', '使用已审查的本地 PowerView 模块读取一个实验用户对象。', 'Use a reviewed local PowerView module to read one lab user object.'),
      reviewedCommand("Get-DomainUser -LDAPFilter '(adminCount=1)' -Domain {DOMAIN} | Select-Object -First 50 SamAccountName,AdminCount", '限制高权限标记用户查询', 'Limit the Privileged-Flag User Query', '最多返回 50 个 adminCount 标记对象，并以实际组成员和 ACL 复核，不把标记直接视为管理员权限。', 'Return at most 50 adminCount-marked objects and verify them against actual group membership and ACLs instead of treating the flag as administrative access.'),
      reviewedCommand("Get-ADUser -Filter 'Enabled -eq $true' -SearchBase '{SEARCH_BASE}' -ResultSetSize 50 -Properties LastLogonDate | Select-Object SamAccountName,LastLogonDate", '读取有限活跃用户基线', 'Read a Limited Active-User Baseline', '在批准 SearchBase 内最多读取 50 个启用账号及其登录时间，用于和账号生命周期基线比较。', 'Read at most 50 enabled identities and their logon dates within the approved SearchBase for comparison with the identity-lifecycle baseline.'),
      reviewedCommand('impacket-GetADUsers -h', '查看 Impacket 用户查询参数', 'Inspect Impacket User Query Arguments', '只查看已安装版本参数，不在命令行嵌入域密码或执行全域查询。', 'Inspect arguments for the installed version without embedding a domain password or running a domain-wide query.'),
    ],
  },
  {
    id: 'group-enum',
    labelZh: '域组与成员关系有界核对',
    labelEn: 'Bounded Domain Group and Membership Review',
    category: i18n('域渗透工具', 'Active Directory Tools'),
    rationale: '原条目由 net 与 PowerView 全域组枚举组成；迁入 AD 和 PowerView 工具卡，使用 SearchBase、单一实验组、结果上限和只读递归成员核对。',
    references: [
      'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup',
      'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember',
      'https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon',
    ],
    editorial: directoryEditorial,
    targets: [
      migrationTarget('active-directory-enumeration', 'domain-pentest-tools', [0, 1, 3, 5], [
        'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup',
        'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroupmember',
      ]),
      migrationTarget('powerview-adrecon', 'domain-pentest-tools', [2, 4], ['https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon']),
    ],
    execution: [
      reviewedCommand("Get-ADGroup -Filter * -SearchBase '{SEARCH_BASE}' -ResultSetSize 100 | Select-Object Name,GroupScope,GroupCategory", '在 SearchBase 内读取组摘要', 'Read Group Summaries Within One SearchBase', '在批准 SearchBase 内最多读取 100 个组的名称、范围和类型。', 'Read names, scopes, and categories for at most 100 groups within the approved SearchBase.'),
      reviewedCommand('Get-ADGroupMember -Identity {LAB_GROUP} | Select-Object -First 100 Name,SamAccountName,ObjectClass', '读取单一实验组成员', 'Read Members of One Lab Group', '读取一个实验组最多 100 个直接成员，不更改成员关系。', 'Read at most 100 direct members of one lab group without changing membership.'),
      reviewedCommand('Get-DomainGroup -Identity {LAB_GROUP} -Domain {DOMAIN} | Select-Object SamAccountName,GroupType,AdminCount', '使用 PowerView 读取实验组', 'Read a Lab Group with PowerView', '使用本地已审查模块读取一个实验组的有限属性。', 'Use a reviewed local module to read a limited property set for one lab group.'),
      reviewedCommand("Get-ADGroup -LDAPFilter '(adminCount=1)' -SearchBase '{SEARCH_BASE}' -ResultSetSize 50 | Select-Object Name,DistinguishedName", '限制高权限标记组查询', 'Limit the Privileged-Flag Group Query', '最多返回 50 个 adminCount 标记组，并用成员关系与 ACL 复核。', 'Return at most 50 adminCount-marked groups and verify them against membership and ACLs.'),
      reviewedCommand('Get-DomainGroupMember -Identity {LAB_GROUP} -Domain {DOMAIN} | Select-Object -First 100 MemberName,MemberObjectClass', '使用 PowerView 读取组成员', 'Read Group Members with PowerView', '读取一个实验组最多 100 个成员，不递归扩展到其他组。', 'Read at most 100 members of one lab group without recursively expanding other groups.'),
      reviewedCommand('Get-ADGroupMember -Identity {LAB_GROUP} -Recursive | Select-Object -First 100 Name,SamAccountName,ObjectClass', '限制递归成员结果', 'Limit Recursive Membership Results', '只对一个实验组递归解析，并把输出限制为 100 个对象。', 'Recursively resolve one lab group only and limit output to 100 objects.'),
    ],
  },
  {
    id: 'gpo-enum',
    labelZh: 'GPO 配置与作用域只读核对',
    labelEn: 'Read-Only GPO Configuration and Scope Review',
    category: i18n('域渗透工具', 'Active Directory Tools'),
    rationale: '原条目混合 GPO 全量枚举、GPP 密码提取和可利用路径搜索；迁入 AD 与 PowerView 工具卡，限定为一个实验 GPO、离线 cpassword fixture 和只读 RSOP 报告。',
    references: [
      'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo',
      'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpresultantsetofpolicy',
      'https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon',
    ],
    editorial: directoryEditorial,
    targets: [
      migrationTarget('active-directory-enumeration', 'domain-pentest-tools', [0, 3, 4], [
        'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo',
        'https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpresultantsetofpolicy',
      ]),
      migrationTarget('powerview-adrecon', 'domain-pentest-tools', [1, 2], ['https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon']),
    ],
    execution: [
      reviewedCommand("Get-GPO -Name '{LAB_GPO}' | Select-Object DisplayName,Id,GpoStatus,ModificationTime", '读取单一实验 GPO', 'Read One Lab GPO', '读取一个指定实验 GPO 的状态与修改时间，不枚举或修改全部策略。', 'Read status and modification time for one named lab GPO without enumerating or changing every policy.'),
      reviewedCommand("Get-DomainGPO -Identity '{LAB_GPO}' -Domain {DOMAIN} | Select-Object DisplayName,Name,GPCFileSysPath", '使用 PowerView 读取实验 GPO', 'Read a Lab GPO with PowerView', '使用本地已审查 PowerView 模块读取一个 GPO 对象及其 SYSVOL 路径。', 'Use a reviewed local PowerView module to read one GPO object and its SYSVOL path.'),
      reviewedCommand("Get-DomainGPOLocalGroup -Identity '{LAB_GPO}' | Select-Object GPODisplayName,GroupName,GroupMembers", '读取实验 GPO 本地组映射', 'Read Local-Group Mappings for One Lab GPO', '只读取一个实验 GPO 定义的本地组映射，并与批准基线比较。', 'Read local-group mappings for one lab GPO and compare them with the approved baseline.'),
      reviewedCommand("Select-String -Path '.\\fixtures\\gpo\\Groups.xml' -Pattern 'cpassword'", '离线检查 GPP fixture', 'Inspect an Offline GPP Fixture', '只在本地合成 Groups.xml fixture 中检查 cpassword 标记，不读取 SYSVOL 凭证文件。', 'Check for the cpassword marker only in a local synthetic Groups.xml fixture without reading credential files from SYSVOL.'),
      reviewedCommand("Get-GPResultantSetOfPolicy -ReportType Xml -Path '.\\artifacts\\rsop.xml' -User {LAB_USER} -Computer {LAB_COMPUTER}", '生成实验主体 RSOP 报告', 'Generate an RSOP Report for Lab Principals', '为一个实验用户和计算机生成本地 XML 报告，用于核对 GPO 作用域，不修改策略。', 'Generate a local XML report for one lab user and computer to review GPO scope without changing policy.'),
    ],
  },
  {
    id: 'trust-enum',
    labelZh: '域与森林信任只读核对',
    labelEn: 'Read-Only Domain and Forest Trust Review',
    category: i18n('域渗透工具', 'Active Directory Tools'),
    rationale: '原条目由 nltest 和 PowerView 信任枚举命令组成；迁入 AD 与 PowerView 工具卡，保留只读方向、类型和目标核对，不生成跨域访问或票据。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nltest',
      'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust',
      'https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon',
    ],
    editorial: directoryEditorial,
    targets: [
      migrationTarget('active-directory-enumeration', 'domain-pentest-tools', [0, 2], [
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nltest',
        'https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust',
      ]),
      migrationTarget('powerview-adrecon', 'domain-pentest-tools', [1, 3], ['https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon']),
    ],
    execution: [
      reviewedCommand('nltest /domain_trusts /all_trusts', '读取当前域信任摘要', 'Read the Current Domain Trust Summary', '读取当前域可见的信任方向和类型，不尝试跨域认证。', 'Read visible trust directions and types for the current domain without attempting cross-domain authentication.'),
      reviewedCommand('Get-DomainTrust -Domain {DOMAIN} | Select-Object SourceName,TargetName,TrustDirection,TrustType', '使用 PowerView 读取域信任', 'Read Domain Trusts with PowerView', '使用本地已审查模块读取一个指定域的信任对象和方向。', 'Use a reviewed local module to read trust objects and directions for one specified domain.'),
      reviewedCommand('Get-ADTrust -Filter * -Server {DC_HOST} | Select-Object -First 50 Source,Target,Direction,TrustType,ForestTransitive', '限制 ADTrust 查询结果', 'Limit ADTrust Query Results', '从一个登记域控制器读取最多 50 条信任记录，并与目录配置核对。', 'Read at most 50 trust records from one registered domain controller and compare them with directory configuration.'),
      reviewedCommand('Get-ForestTrust -Forest {FOREST} | Select-Object SourceName,TargetName,TrustDirection,TrustType', '使用 PowerView 读取森林信任', 'Read Forest Trusts with PowerView', '读取一个指定实验森林的信任摘要，不遍历外部森林资源。', 'Read the trust summary for one specified lab forest without traversing external forest resources.'),
    ],
  },
  {
    id: 'exchange-enum',
    labelZh: 'Exchange 配置与端点只读核对',
    labelEn: 'Read-Only Exchange Configuration and Endpoint Review',
    category: i18n('域渗透工具', 'Active Directory Tools'),
    rationale: '原条目混合 OWA、Autodiscover、OAB 下载和 NTLM 信息命令；迁入 Exchange/M365 工具卡，移除证书忽略、明文基本认证、邮箱枚举和通讯录下载，只保留端点头与管理元数据。',
    references: [
      'https://learn.microsoft.com/en-us/exchange/architecture/client-access/autodiscover',
      'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exchangeserver',
      'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-offlineaddressbook',
    ],
    editorial: serviceEditorial,
    targets: [
      migrationTarget('exchange-m365-attacks', 'domain-pentest-tools', [0, 1, 2, 3], [
        'https://learn.microsoft.com/en-us/exchange/architecture/client-access/autodiscover',
        'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exchangeserver',
        'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-offlineaddressbook',
      ]),
    ],
    execution: [
      reviewedCommand('curl --fail --silent --show-error --max-time 5 -D ./artifacts/owa.headers -o ./artifacts/owa.body https://{EXCHANGE_HOST}/owa/', '保存 OWA 基线响应', 'Preserve an OWA Baseline Response', '对一个登记 Exchange 主机的 OWA 根路径执行一次证书校验请求，并把头与正文写入本地 artifacts。', 'Make one certificate-validated request to the OWA root on a registered Exchange host and preserve headers and body in local artifacts.'),
      reviewedCommand('curl --fail --silent --show-error --max-time 5 -D ./artifacts/autodiscover.headers -o /dev/null https://{EXCHANGE_HOST}/autodiscover/autodiscover.xml', '读取 Autodiscover 响应头', 'Read Autodiscover Response Headers', '只读取一个登记主机的 Autodiscover 响应头，不发送用户名、密码或邮箱地址。', 'Read response headers from Autodiscover on one registered host without sending a username, password, or mailbox address.'),
      reviewedCommand('Get-OfflineAddressBook -ResultSize 20 | Select-Object Name,AddressLists,VirtualDirectories', '读取 OAB 配置摘要', 'Read the OAB Configuration Summary', '通过已授权 Exchange 管理会话读取最多 20 个 OAB 配置对象，不下载通讯录内容。', 'Read at most 20 OAB configuration objects through an authorized Exchange management session without downloading address-book content.'),
      reviewedCommand('Get-ExchangeServer -Identity {EXCHANGE_SERVER} -Status | Format-List Name,Edition,AdminDisplayVersion,ServerRole', '读取单一 Exchange 服务器元数据', 'Read Metadata for One Exchange Server', '读取一个登记 Exchange 服务器的版本、版本类型和角色，用于补丁基线核对。', 'Read version, edition, and roles for one registered Exchange server for comparison with the patch baseline.'),
    ],
  },
  {
    id: 'sharepoint-enum',
    labelZh: 'SharePoint 站点元数据有界核对',
    labelEn: 'Bounded SharePoint Site Metadata Review',
    category: i18n('Web 侦察工具', 'Web Reconnaissance Tools'),
    rationale: '原条目混合站点、用户、文档库和 password 搜索；迁入 Web 枚举工具卡，使用专用实验 Token、字段投影、固定 top/rowlimit 和 PAYLOADER_MARKER，禁止敏感关键词搜索。',
    references: [
      'https://learn.microsoft.com/en-us/sharepoint/dev/sp-add-ins/get-to-know-the-sharepoint-rest-service',
      'https://learn.microsoft.com/en-us/sharepoint/dev/general-development/sharepoint-search-rest-api-overview',
    ],
    editorial: serviceEditorial,
    targets: [
      migrationTarget('web-enumeration-tools', 'web-extended-tools', [0, 1, 2, 3], [
        'https://learn.microsoft.com/en-us/sharepoint/dev/sp-add-ins/get-to-know-the-sharepoint-rest-service',
        'https://learn.microsoft.com/en-us/sharepoint/dev/general-development/sharepoint-search-rest-api-overview',
      ]),
    ],
    execution: [
      reviewedCommand("curl --fail --silent --show-error --max-time 5 -H \"Authorization: Bearer {LAB_TOKEN}\" -H \"Accept: application/json\" 'https://{SHAREPOINT_HOST}/_api/web/webs?$select=Id,Title,Url&$top=20'", '读取有限子站点元数据', 'Read Limited Subsite Metadata', '使用专用实验 Token 读取最多 20 个子站点的 ID、标题和 URL，不读取站点内容。', 'Use a dedicated lab token to read IDs, titles, and URLs for at most 20 subsites without reading site content.'),
      reviewedCommand("curl --fail --silent --show-error --max-time 5 -H \"Authorization: Bearer {LAB_TOKEN}\" -H \"Accept: application/json\" 'https://{SHAREPOINT_HOST}/_api/web/siteusers?$select=Id,Title,LoginName&$top=20'", '读取有限站点用户元数据', 'Read Limited Site-User Metadata', '读取当前实验站点最多 20 个用户的有限标识字段，并与站点权限基线核对。', 'Read limited identity fields for at most 20 users in the lab site and compare them with the site-permission baseline.'),
      reviewedCommand("curl --fail --silent --show-error --max-time 5 -H \"Authorization: Bearer {LAB_TOKEN}\" -H \"Accept: application/json\" 'https://{SHAREPOINT_HOST}/_api/web/lists?$filter=BaseTemplate%20eq%20101&$select=Id,Title,ItemCount&$top=20'", '读取有限文档库元数据', 'Read Limited Document-Library Metadata', '读取最多 20 个文档库的 ID、标题与项目数，不列出或下载文件。', 'Read IDs, titles, and item counts for at most 20 document libraries without listing or downloading files.'),
      reviewedCommand('curl --fail --silent --show-error --max-time 5 -H "Authorization: Bearer {LAB_TOKEN}" -H "Accept: application/json" "https://{SHAREPOINT_HOST}/_api/search/query?querytext=%27PAYLOADER_MARKER%27&rowlimit=10&trimduplicates=true"', '搜索固定实验 marker', 'Search for a Fixed Lab Marker', '只搜索预先创建的 PAYLOADER_MARKER 并限制为 10 条结果，不使用 password 等敏感关键词。', 'Search only for the pre-created PAYLOADER_MARKER with a 10-result limit instead of using sensitive keywords such as password.'),
    ],
  },
  {
    id: 'sharepoint-file-access',
    labelZh: 'SharePoint 文档库授权边界核对',
    labelEn: 'SharePoint Document-Library Authorization Review',
    category: i18n('Web 侦察工具', 'Web Reconnaissance Tools'),
    rationale: '原条目把浏览器下载、基本认证 REST、CSOM 明文凭证和 OneDrive 全量同步作为 Payload；迁入 Web 枚举工具卡，只读取文档库元数据和本地合成 fixture。',
    references: [
      'https://learn.microsoft.com/en-us/sharepoint/dev/sp-add-ins/working-with-lists-and-list-items-with-rest',
      'https://pnp.github.io/powershell/cmdlets/Get-PnPList.html',
    ],
    editorial: serviceEditorial,
    targets: [
      migrationTarget('web-enumeration-tools', 'web-extended-tools', [0, 1, 2, 3], [
        'https://learn.microsoft.com/en-us/sharepoint/dev/sp-add-ins/working-with-lists-and-list-items-with-rest',
        'https://pnp.github.io/powershell/cmdlets/Get-PnPList.html',
      ]),
    ],
    execution: [
      reviewedCommand('curl --fail --silent --show-error --max-time 5 --head "https://{SHAREPOINT_HOST}/sites/{LAB_SITE}/Shared%20Documents/Forms/AllItems.aspx"', '读取实验文档库页面头', 'Read Headers for the Lab Library Page', '只对实验站点文档库页面发送 HEAD 请求，记录授权和缓存头，不下载文档。', 'Send a HEAD request only to the lab site document-library page and record authorization and cache headers without downloading documents.'),
      reviewedCommand("curl --fail --silent --show-error --max-time 5 -H \"Authorization: Bearer {LAB_TOKEN}\" -H \"Accept: application/json\" 'https://{SHAREPOINT_HOST}/_api/web/lists/getbytitle(%27Documents%27)/items?$select=Id,FileLeafRef,FileRef&$top=20'", '读取有限文档项目元数据', 'Read Limited Document Item Metadata', '读取实验文档库最多 20 个项目的 ID 与路径元数据，不请求文件正文。', 'Read ID and path metadata for at most 20 items in the lab library without requesting file content.'),
      reviewedCommand("Get-PnPList -Identity 'Documents' | Select-Object Title,ItemCount,RootFolder", '读取 PnP 文档库摘要', 'Read a PnP Document-Library Summary', '在预先建立的实验 PnP 会话中读取一个文档库的标题、项目数和根目录。', 'Read title, item count, and root folder for one document library through a pre-established lab PnP session.'),
      reviewedCommand("Get-ChildItem '.\\fixtures\\sharepoint' -Depth 2 -File | Select-Object -First 20 FullName,Length,LastWriteTime", '检查本地 SharePoint fixture', 'Inspect Local SharePoint Fixtures', '只检查本地合成 fixture 两层目录内最多 20 个文件的路径与大小，不递归同步租户文档。', 'Inspect paths and sizes for at most 20 files within two fixture-directory levels without synchronizing tenant documents.'),
    ],
  },
  {
    id: 'tunnel-dns',
    labelZh: 'DNS 隧道参数与文档预检',
    labelEn: 'DNS Tunnel Argument and Documentation Preflight',
    category: i18n('隧道代理工具', 'Tunneling and Pivoting Tools'),
    rationale: '原条目直接启动 dnscat2 服务端、客户端和转发监听；迁入 network-pivoting 工具卡，仅保留帮助与离线文档预检，不启动 DNS 隧道或监听器。',
    references: [
      'https://github.com/iagox86/dnscat2',
      'https://attack.mitre.org/techniques/T1071/004/',
    ],
    editorial: tunnelEditorial,
    targets: [
      migrationTarget('network-pivoting', 'tunneling-tools', [0, 1, 2], [
        'https://github.com/iagox86/dnscat2',
        'https://attack.mitre.org/techniques/T1071/004/',
      ]),
    ],
    execution: [
      reviewedCommand('ruby dnscat2.rb --help', '查看 dnscat2 服务端参数', 'Inspect dnscat2 Server Arguments', '只查看本地受控副本的服务端参数，不绑定 53 端口或指定外部域名。', 'Inspect server arguments from a controlled local copy without binding port 53 or specifying an external domain.'),
      reviewedCommand('./dnscat2 --help', '查看 dnscat2 客户端参数', 'Inspect dnscat2 Client Arguments', '只查看客户端 DNS、密钥和日志参数，不连接任何服务端。', 'Inspect client DNS, key, and logging arguments without connecting to a server.'),
      reviewedCommand("rg -n -m 20 'session|listen' ./README.md ./doc", '离线查阅会话与监听文档', 'Review Session and Listener Documentation Offline', '在本地项目文档中最多返回 20 个 session/listen 匹配，不启动会话或端口转发。', 'Return at most 20 session or listen matches from local project documentation without starting a session or port forward.'),
    ],
  },
  {
    id: 'tunnel-icmp',
    labelZh: 'ICMP 隧道能力与接口预检',
    labelEn: 'ICMP Tunnel Capability and Interface Preflight',
    category: i18n('隧道代理工具', 'Tunneling and Pivoting Tools'),
    rationale: '原条目直接启动 ICMP 隧道服务端和外部客户端；迁入 network-pivoting 工具卡，只查看帮助、文件能力和现有 TUN/TAP 接口，不发送 ICMP 隧道流量。',
    references: [
      'https://github.com/jamesbarlow/icmptunnel',
      'https://attack.mitre.org/techniques/T1095/',
    ],
    editorial: tunnelEditorial,
    targets: [
      migrationTarget('network-pivoting', 'tunneling-tools', [0, 1], [
        'https://github.com/jamesbarlow/icmptunnel',
        'https://attack.mitre.org/techniques/T1095/',
      ]),
    ],
    execution: [
      reviewedCommand('./icmptunnel --help', '查看 icmptunnel 参数', 'Inspect icmptunnel Arguments', '只查看本地二进制的服务端和客户端参数，不创建 TUN 设备或发送 ICMP 数据。', 'Inspect server and client arguments for the local binary without creating a TUN device or sending ICMP data.'),
      reviewedCommand('getcap ./icmptunnel\nip tuntap show', '检查文件能力与现有 TUN 接口', 'Inspect File Capabilities and Existing TUN Interfaces', '只读取二进制文件能力与当前 TUN/TAP 接口，用于确认实验前提，不启动客户端。', 'Read binary capabilities and current TUN or TAP interfaces to confirm lab prerequisites without starting a client.'),
    ],
  },
  {
    id: 'socks-proxy',
    labelZh: 'SOCKS 与代理工具安全预检',
    labelEn: 'Safe SOCKS and Proxy Tool Preflight',
    category: i18n('隧道代理工具', 'Tunneling and Pivoting Tools'),
    rationale: '原条目直接启动 SSH、Cobalt Strike 和 Metasploit SOCKS，并修改全局 ProxyChains 配置后扫描目标；迁入四个对应工具卡，改为配置展开、一次性回环 marker 配置和帮助检查。',
    references: [
      'https://man.openbsd.org/ssh',
      'https://github.com/rofl0r/proxychains-ng',
      'https://www.cobaltstrike.com/help-socks-proxy-pivoting',
      'https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html',
    ],
    editorial: tunnelEditorial,
    targets: [
      migrationTarget('ssh-tunneling-advanced', 'tunneling-tools', [0], ['https://man.openbsd.org/ssh']),
      migrationTarget('proxychains', 'intranet-tools', [1], ['https://github.com/rofl0r/proxychains-ng']),
      migrationTarget('cobalt-strike', 'red-team-ops', [2], ['https://www.cobaltstrike.com/help-socks-proxy-pivoting']),
      migrationTarget('metasploit', 'exploit-tools', [3], ['https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html']),
    ],
    execution: [
      reviewedCommand("ssh -G -D 127.0.0.1:1080 lab-jump | rg '^(hostname|user|port) '", '展开 SSH 动态代理配置', 'Expand SSH Dynamic-Proxy Configuration', '只展开专用实验跳板机的 SSH 配置，核对最终主机、用户、端口和回环监听，不建立连接。', 'Expand SSH configuration for the dedicated lab jump host and review host, user, port, and loopback listener without opening a connection.'),
      reviewedCommand("printf '%s\\n' 'strict_chain' 'proxy_dns' '[ProxyList]' 'socks5 127.0.0.1 1080' > ./proxychains-lab.conf\nproxychains4 -q -f ./proxychains-lab.conf curl --max-time 5 http://127.0.0.1:8080/PAYLOADER_MARKER", '使用一次性 ProxyChains 配置', 'Use a Disposable ProxyChains Configuration', '在工作目录创建一次性配置并只请求回环 marker，不修改 /etc 配置或扫描网段。', 'Create a disposable configuration in the working directory and request one loopback marker without editing /etc configuration or scanning a network.'),
      reviewedCommand('beacon> help socks', '查看 Cobalt Strike SOCKS 帮助', 'Inspect Cobalt Strike SOCKS Help', '只在专用实验 Beacon 控制台查看 socks 参数，不启动监听器、路由或远程会话。', 'Read socks arguments in a dedicated lab Beacon console without starting a listener, route, or remote session.'),
      reviewedCommand("msfconsole -q -x 'info auxiliary/server/socks_proxy; exit'", '查看 Metasploit SOCKS 模块信息', 'Inspect Metasploit SOCKS Module Information', '只查看当前模块参数后退出，不运行模块或创建监听器。', 'Inspect current module arguments and exit without running the module or creating a listener.'),
    ],
  },
  {
    id: 'lateral-ssh',
    retainPayload: true,
    labelZh: 'SSH 横向管理安全预检',
    labelEn: 'Safe SSH Lateral-Management Preflight',
    category: i18n('横向移动工具', 'Lateral Movement Tools'),
    rationale: '原条目直接使用账号、私钥和跳板建立 SSH 会话；迁入 ssh-pentest 工具卡，改为配置展开和本地受控配置检查，不建立远程连接。',
    references: [
      'https://man.openbsd.org/ssh',
      'https://www.openssh.com/manual.html',
    ],
    editorial: remoteAccessEditorial,
    targets: [
      migrationTarget('ssh-pentest', 'tunneling-tools', [0, 1, 2], [
        'https://man.openbsd.org/ssh',
        'https://www.openssh.com/manual.html',
      ]),
    ],
    execution: [
      reviewedCommand("ssh -G {LAB_HOST} | rg '^(hostname|user|port|proxyjump) '", '展开单一 SSH 主机配置', 'Expand One SSH Host Configuration', '只展开一个实验主机的最终 SSH 配置，核对主机、用户、端口和跳板，不建立连接。', 'Expand the final SSH configuration for one lab host and review host, user, port, and jump settings without opening a connection.'),
      reviewedCommand("ssh -G -F ./fixtures/ssh_config {LAB_HOST} | rg '^(identityfile|identitiesonly|user|port) '", '检查受控 SSH 身份配置', 'Inspect a Controlled SSH Identity Configuration', '从本地受控配置读取身份文件和认证选项，不读取私钥内容或发起认证。', 'Read identity-file and authentication options from a controlled local configuration without reading key contents or authenticating.'),
      reviewedCommand("ssh -G -J {LAB_JUMP} {LAB_HOST} | rg '^(hostname|user|port|proxyjump) '", '展开 SSH 跳板配置', 'Expand SSH Jump-Host Configuration', '仅展开一个实验跳板与目标主机的连接链路，不连接跳板或目标服务。', 'Expand the connection chain for one lab jump host and target without connecting to either service.'),
    ],
  },
  {
    id: 'lateral-winrm',
    retainPayload: true,
    labelZh: 'WinRM 远程管理安全预检',
    labelEn: 'Safe WinRM Remote-Management Preflight',
    category: i18n('横向移动工具', 'Lateral Movement Tools'),
    rationale: '原条目建立 PowerShell 远程会话并把凭证写入命令，另含 Evil-WinRM 连接；迁入 PowerShell Remoting 与 Evil-WinRM 工具卡，只保留服务探测、帮助和参数检查。',
    references: [
      'https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting',
      'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/test-wsman',
      'https://github.com/Hackplayers/evil-winrm',
    ],
    editorial: remoteAccessEditorial,
    targets: [
      migrationTarget('powershell-remoting', 'powershell-full-command-index-group', [0, 1], [
        'https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting',
        'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/test-wsman',
      ]),
      migrationTarget('evil-winrm', 'intranet-tools', [2], ['https://github.com/Hackplayers/evil-winrm']),
    ],
    execution: [
      reviewedCommand('Test-WSMan -ComputerName {LAB_HOST} -Authentication Default', '探测单一 WinRM 服务', 'Probe One WinRM Service', '仅对一个授权实验主机执行 WinRM 能力探测，不建立交互会话或发送凭证。', 'Probe WinRM capability on one authorized lab host without creating an interactive session or sending credentials.'),
      reviewedCommand("Get-Help Invoke-Command -Examples | Select-Object -First 20", '查看远程命令示例', 'Inspect Remote-Command Examples', '只查看本机 PowerShell 的 Invoke-Command 示例并限制输出，不执行远程脚本。', 'Read local PowerShell Invoke-Command examples with a bounded output and without executing a remote script.'),
      reviewedCommand('evil-winrm -h', '查看 Evil-WinRM 参数', 'Inspect Evil-WinRM Arguments', '只查看已安装 Evil-WinRM 的参数帮助，不连接目标或加载脚本。', 'Inspect help for the installed Evil-WinRM version without connecting to a target or loading a script.'),
    ],
  },
  {
    id: 'lateral-winrs',
    retainPayload: true,
    labelZh: 'WinRS 横向管理能力预检',
    labelEn: 'WinRS Lateral-Management Capability Preflight',
    category: i18n('横向移动工具', 'Lateral Movement Tools'),
    rationale: '原条目使用明文用户、密码建立 WinRS 远程命令和 Shell；迁入 Windows 横向命令工具卡，改为本机帮助与二进制版本检查。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs',
      'https://attack.mitre.org/techniques/T1021/006/',
    ],
    editorial: remoteAccessEditorial,
    targets: [
      migrationTarget('windows-lateral-commands', 'domain-pentest-tools', [0, 1], [
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs',
        'https://attack.mitre.org/techniques/T1021/006/',
      ]),
    ],
    execution: [
      reviewedCommand('winrs /?', '查看 WinRS 参数帮助', 'Inspect WinRS Argument Help', '只查看本机 WinRS 参数和认证选项，不连接远程主机或执行命令。', 'Inspect local WinRS arguments and authentication options without connecting to a remote host or executing a command.'),
      reviewedCommand("Get-Command winrs.exe -ErrorAction SilentlyContinue | Select-Object Name,Source,Version", '读取 WinRS 二进制信息', 'Read WinRS Binary Metadata', '读取本机 WinRS 二进制的来源与版本，不传入目标、用户或密码参数。', 'Read local WinRS binary source and version without supplying a target, user, or password parameter.'),
    ],
  },
  {
    id: 'windows-privesc',
    retainPayload: true,
    labelZh: 'Windows 提权边界只读核对',
    labelEn: 'Read-Only Windows Privilege-Boundary Review',
    category: i18n('权限提升工具', 'Privilege Escalation Tools'),
    rationale: '原条目混合权限枚举、WinPEAS 执行、服务 ACL 和未引用路径检查；迁入 Windows 提权工具卡，替换为有限本机审计和本地 fixture 检查，不执行提权工具。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami',
      'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service',
      'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation',
    ],
    editorial: windowsPrivilegeEditorial,
    targets: [
      migrationTarget('windows-privesc-techniques', 'post-exploit-tools', [0, 1, 2, 3], [
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami',
        'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service',
        'https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation',
      ]),
    ],
    execution: [
      reviewedCommand('whoami /priv & whoami /groups', '读取当前令牌权限', 'Read the Current Token Privileges', '读取当前主体的特权和组令牌，不修改权限或启动新进程。', 'Read privileges and group-token data for the current principal without changing rights or starting a new process.'),
      reviewedCommand("Get-Command .\\winpeas.exe -ErrorAction SilentlyContinue | Select-Object Name,Source,Version", '检查本地 WinPEAS 文件', 'Inspect a Local WinPEAS File', '只读取工作目录中 WinPEAS 文件的命令元数据，不执行自动化提权扫描。', 'Read command metadata for a WinPEAS file in the working directory without executing an automated escalation scan.'),
      reviewedCommand('accesschk.exe -uwcqv "Everyone" .\\fixtures\\services\\*', '检查合成服务 ACL', 'Inspect Synthetic Service ACLs', '仅对本地合成服务 fixture 读取 Everyone 的写权限，不枚举或修改系统服务。', 'Read Everyone write permissions only for local synthetic service fixtures without enumerating or changing system services.'),
      reviewedCommand("Get-CimInstance Win32_Service | Where-Object StartMode -eq 'Auto' | Select-Object -First 50 Name,PathName,StartName", '读取有界自动服务清单', 'Read a Bounded Automatic-Service List', '读取最多 50 个自动服务的路径和启动身份，用于和服务基线比较，不修改服务。', 'Read paths and start identities for at most 50 automatic services for baseline comparison without changing services.'),
    ],
  },
  {
    id: 'linux-privesc',
    retainPayload: true,
    labelZh: 'Linux 提权边界只读核对',
    labelEn: 'Read-Only Linux Privilege-Boundary Review',
    category: i18n('权限提升工具', 'Privilege Escalation Tools'),
    rationale: '原条目包含根目录 SUID 扫描、sudo 交互、Cron 检查和 LinPEAS 执行；迁入 Linux 提权工具卡，限定目录、输出和本地脚本内容，不执行提权程序。',
    references: [
      'https://man7.org/linux/man-pages/man1/find.1.html',
      'https://man7.org/linux/man-pages/man8/sudo.8.html',
      'https://gtfobins.github.io/',
    ],
    editorial: linuxPrivilegeEditorial,
    targets: [
      migrationTarget('linux-privesc-techniques', 'post-exploit-tools', [0, 1, 2, 3], [
        'https://man7.org/linux/man-pages/man1/find.1.html',
        'https://man7.org/linux/man-pages/man8/sudo.8.html',
        'https://gtfobins.github.io/',
      ]),
    ],
    execution: [
      reviewedCommand('find /usr /opt -xdev -perm -4000 -type f -print 2>/dev/null | head -n 50', '读取有界 SUID 文件清单', 'Read a Bounded SUID File List', '只在 /usr 和 /opt 文件系统内查找最多 50 个 SUID 文件，不遍历所有挂载点。', 'Find at most 50 SUID files under /usr and /opt without traversing every mounted filesystem.'),
      reviewedCommand('sudo -n -l 2>/dev/null | head -n 50', '读取非交互 sudo 规则', 'Read Non-Interactive Sudo Rules', '使用非交互模式读取当前主体的 sudo 规则，最多保留 50 行，不提示或提交密码。', 'Read sudo rules for the current principal in non-interactive mode, retaining at most 50 lines without prompting for or submitting a password.'),
      reviewedCommand("cat /etc/crontab; find /etc/cron.d -maxdepth 1 -type f -print 2>/dev/null | head -n 50", '读取有界 Cron 配置', 'Read Bounded Cron Configuration', '读取系统 crontab 和 /etc/cron.d 顶层最多 50 个文件名，不创建或编辑计划任务。', 'Read the system crontab and at most 50 top-level filenames under /etc/cron.d without creating or editing scheduled tasks.'),
      reviewedCommand("test -f ./linpeas.sh && sha256sum ./linpeas.sh && head -n 50 ./linpeas.sh", '检查本地 LinPEAS 内容', 'Inspect Local LinPEAS Content', '只校验并查看本地 LinPEAS 脚本前 50 行，不执行脚本或发起系统扫描。', 'Hash and inspect the first 50 lines of a local LinPEAS script without executing it or scanning the system.'),
    ],
  },
  {
    id: 'kernel-exploit',
    retainPayload: true,
    labelZh: 'Linux 内核风险只读核对',
    labelEn: 'Read-Only Linux Kernel Risk Review',
    category: i18n('权限提升工具', 'Privilege Escalation Tools'),
    rationale: '原条目混合内核版本读取、Searchsploit 查询和漏洞名称清单；迁入 Linux 内核工具卡，改为版本基线、帮助检查和 CVE 参考列表，不运行漏洞利用。',
    references: [
      'https://www.kernel.org/doc/html/latest/admin-guide/README.html',
      'https://github.com/bwbwbwbw/linux-exploit-suggester-2',
      'https://attack.mitre.org/techniques/T1068/',
    ],
    editorial: kernelRiskEditorial,
    targets: [
      migrationTarget('kernel-exploits', 'post-exploit-tools', [0, 1, 2], [
        'https://www.kernel.org/doc/html/latest/admin-guide/README.html',
        'https://github.com/bwbwbwbw/linux-exploit-suggester-2',
        'https://attack.mitre.org/techniques/T1068/',
      ]),
    ],
    execution: [
      reviewedCommand("uname -srvm; sed -n '1,5p' /proc/version", '记录内核版本基线', 'Record the Kernel Version Baseline', '读取内核发布、架构和版本文件前五行，用于和补丁清单核对，不加载模块。', 'Read kernel release, architecture, and the first five version-file lines for patch comparison without loading modules.'),
      reviewedCommand("searchsploit --help | head -n 50", '查看 Searchsploit 参数', 'Inspect Searchsploit Arguments', '只查看本地 Searchsploit 参数帮助，不下载、编译或执行漏洞代码。', 'Inspect local Searchsploit argument help without downloading, compiling, or executing exploit code.'),
      reviewedCommand("printf '%s\\n' 'CVE-2016-5195' 'CVE-2022-0847' 'CVE-2021-4034' | sort", '记录内核 CVE 参考清单', 'Record a Kernel CVE Reference List', '输出固定的 CVE 参考标识并排序，供补丁核对使用，不运行任何利用程序。', 'Print and sort fixed CVE reference identifiers for patch review without running an exploit.'),
    ],
  },
  {
    id: 'potato-attack',
    retainPayload: true,
    labelZh: 'Potato 工具能力安全预检',
    labelEn: 'Safe Potato-Tool Capability Preflight',
    category: i18n('权限提升工具', 'Privilege Escalation Tools'),
    rationale: '原条目包含下载、令牌模拟、创建管理员、反弹 Shell 和远程中继；迁入提权工具卡，只保留权限读取、帮助检查和本地 fixture 清单。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami',
      'https://github.com/ohpe/juicy-potato',
      'https://github.com/BeichenDream/GodPotato',
      'https://attack.mitre.org/techniques/T1134/001/',
    ],
    editorial: potatoEditorial,
    targets: [
      migrationTarget('privilege-escalation-tools', 'post-exploit-tools', [0, 1, 2, 3, 4, 5, 6], [
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami',
        'https://github.com/ohpe/juicy-potato',
        'https://github.com/BeichenDream/GodPotato',
        'https://attack.mitre.org/techniques/T1134/001/',
      ]),
    ],
    execution: [
      reviewedCommand('whoami /priv | findstr /i "SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege"', '核对令牌模拟权限', 'Review Token-Impersonation Privileges', '只读取当前主体是否具有两个令牌模拟特权，不创建 COM 服务或启动高权限进程。', 'Read whether the current principal has either token-impersonation privilege without creating a COM service or starting a privileged process.'),
      reviewedCommand('JuicyPotato.exe -h', '查看 JuicyPotato 帮助', 'Inspect JuicyPotato Help', '只查看本地 JuicyPotato 参数，不下载、运行或指定服务监听。', 'Inspect local JuicyPotato arguments without downloading, running, or specifying a service listener.'),
      reviewedCommand('PrintSpoofer.exe -h', '查看 PrintSpoofer 帮助', 'Inspect PrintSpoofer Help', '只查看本地 PrintSpoofer 参数，不创建命名管道或执行命令。', 'Inspect local PrintSpoofer arguments without creating a named pipe or executing a command.'),
      reviewedCommand('SweetPotato.exe -h', '查看 SweetPotato 帮助', 'Inspect SweetPotato Help', '只查看本地 SweetPotato 参数，不选择攻击方式或启动子进程。', 'Inspect local SweetPotato arguments without selecting an attack method or starting a child process.'),
      reviewedCommand('GodPotato.exe -h', '查看 GodPotato 帮助', 'Inspect GodPotato Help', '只查看本地 GodPotato 参数，不调用令牌模拟或 PowerShell。', 'Inspect local GodPotato arguments without invoking token impersonation or PowerShell.'),
      reviewedCommand('RoguePotato.exe -h', '查看 RoguePotato 帮助', 'Inspect RoguePotato Help', '只查看本地 RoguePotato 参数，不连接远程解析器或启动中继。', 'Inspect local RoguePotato arguments without contacting a remote resolver or starting a relay.'),
      reviewedCommand("Get-ChildItem .\\fixtures\\potato -File -ErrorAction SilentlyContinue | Select-Object -First 20 Name,Length,LastWriteTime", '检查本地 Potato fixture', 'Inspect Local Potato Fixtures', '只列出本地合成 Potato fixture 中最多 20 个文件，不执行二进制或下载组件。', 'List at most 20 files in local synthetic Potato fixtures without executing binaries or downloading components.'),
    ],
  },
  {
    id: 'process-injection',
    retainPayload: true,
    labelZh: '进程注入能力安全预检',
    labelEn: 'Safe Process-Injection Capability Preflight',
    category: i18n('终端安全工具', 'Endpoint Security Tools'),
    rationale: '原条目直接调用 OpenProcess、VirtualAllocEx、WriteProcessMemory 和 APC 注入；迁入同名进程注入工具卡，只保留进程元数据和本地设计文档检查。',
    references: [
      'https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess',
      'https://attack.mitre.org/techniques/T1055/',
      'https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex',
    ],
    editorial: executionControlEditorial,
    targets: [
      migrationTarget('process-injection', 'red-team-ops', [0, 1, 2], [
        'https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess',
        'https://attack.mitre.org/techniques/T1055/',
        'https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex',
      ]),
    ],
    execution: [
      reviewedCommand("Get-Process -Name notepad -ErrorAction SilentlyContinue | Select-Object -First 1 Id,Name,Path", '读取单一进程元数据', 'Read One Process Metadata Record', '只读取一个 notepad 进程的 ID、名称和路径，不打开句柄或写入进程内存。', 'Read the ID, name, and path for one notepad process without opening a handle or writing process memory.'),
      reviewedCommand("Get-ChildItem .\\fixtures\\process-injection -File -ErrorAction SilentlyContinue | Select-Object -First 20 Name,Length,LastWriteTime", '检查进程注入设计 fixture', 'Inspect Process-Injection Design Fixtures', '只列出本地合成设计 fixture 中最多 20 个文件，不编译或加载 DLL。', 'List at most 20 files in local synthetic design fixtures without compiling or loading a DLL.'),
      reviewedCommand("Get-Command QueueUserAPC -ErrorAction SilentlyContinue | Select-Object Name,CommandType,Source", '检查 APC API 可见性', 'Inspect APC API Visibility', '只检查 PowerShell 命令解析器是否提供 QueueUserAPC 名称，不调用线程注入 API。', 'Check whether the PowerShell command resolver exposes QueueUserAPC without calling a thread-injection API.'),
    ],
  },
  {
    id: 'applocker-bypass',
    retainPayload: true,
    labelZh: 'AppLocker 与 LOLBin 策略预检',
    labelEn: 'AppLocker and LOLBin Policy Preflight',
    category: i18n('终端安全工具', 'Endpoint Security Tools'),
    rationale: '原条目直接调用 regsvr32、mshta、certutil、InstallUtil 和 MSBuild 载荷；迁入 Windows LOLBins 工具卡，只验证签名和命令元数据，不执行代理代码。',
    references: [
      'https://lolbas-project.github.io/',
      'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview',
      'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature',
    ],
    editorial: executionControlEditorial,
    targets: [
      migrationTarget('windows-lolbas', 'powershell-full-command-index-group', [0, 1, 2, 3], [
        'https://lolbas-project.github.io/',
        'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview',
        'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature',
      ]),
    ],
    execution: [
      reviewedCommand("Get-AuthenticodeSignature \"$env:WINDIR\\System32\\spoolsv.exe\" | Select-Object Status,StatusMessage,SignerCertificate", '核验系统白名单签名', 'Verify a System-Allowlisted Signature', '只读取 spoolsv.exe 的 Authenticode 状态和签名者，不启动二进制或绕过 AppLocker。', 'Read Authenticode status and signer data for spoolsv.exe without starting the binary or bypassing AppLocker.'),
      reviewedCommand("Get-Command regsvr32.exe,mshta.exe,certutil.exe -ErrorAction SilentlyContinue | Select-Object Name,Source,Version", '读取 LOLBin 元数据', 'Read LOLBin Metadata', '只读取三个系统 LOLBin 的来源和版本，不传入 URL、脚本或远程资源。', 'Read source and version metadata for three system LOLBins without supplying a URL, script, or remote resource.'),
      reviewedCommand("Get-AuthenticodeSignature \"$env:WINDIR\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe\" | Select-Object Status,StatusMessage,SignerCertificate", '核验 InstallUtil 签名', 'Verify the InstallUtil Signature', '只读取 InstallUtil 的签名状态，不加载程序集或执行卸载参数。', 'Read InstallUtil signature status without loading an assembly or executing an uninstall parameter.'),
      reviewedCommand("Get-AuthenticodeSignature \"$env:WINDIR\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe\" | Select-Object Status,StatusMessage,SignerCertificate", '核验 MSBuild 签名', 'Verify the MSBuild Signature', '只读取 MSBuild 的签名状态，不加载项目或执行嵌入代码。', 'Read MSBuild signature status without loading a project or executing embedded code.'),
    ],
  },
  {
    id: 'evasion-signed-binary',
    retainPayload: true,
    labelZh: '签名二进制策略安全预检',
    labelEn: 'Safe Signed-Binary Policy Preflight',
    category: i18n('终端安全工具', 'Endpoint Security Tools'),
    rationale: '原条目把 MSBuild、InstallUtil、Regsvcs/Regasm 和 Rundll32 作为代码执行载体；迁入 Windows LOLBins 工具卡，替换为签名状态和工具元数据检查。',
    references: [
      'https://lolbas-project.github.io/',
      'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature',
      'https://attack.mitre.org/techniques/T1218/',
    ],
    editorial: executionControlEditorial,
    targets: [
      migrationTarget('windows-lolbas', 'powershell-full-command-index-group', [0, 1, 2, 3], [
        'https://lolbas-project.github.io/',
        'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature',
        'https://attack.mitre.org/techniques/T1218/',
      ]),
    ],
    execution: [
      reviewedCommand("Get-AuthenticodeSignature \"$env:WINDIR\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe\" | Select-Object Status,StatusMessage,SignerCertificate", '读取 MSBuild 签名基线', 'Read the MSBuild Signature Baseline', '记录系统 MSBuild 的签名状态和签名者，不加载恶意项目或执行 C#。', 'Record system MSBuild signature status and signer without loading a malicious project or executing C#.'),
      reviewedCommand("Get-AuthenticodeSignature \"$env:WINDIR\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe\" | Select-Object Status,StatusMessage,SignerCertificate", '读取 InstallUtil 签名基线', 'Read the InstallUtil Signature Baseline', '记录系统 InstallUtil 的签名状态，不加载 DLL 或使用卸载参数。', 'Record system InstallUtil signature status without loading a DLL or using an uninstall parameter.'),
      reviewedCommand("Get-Command regsvcs.exe,regasm.exe -ErrorAction SilentlyContinue | Select-Object Name,Source,Version", '读取 Regsvcs 与 Regasm 元数据', 'Read Regsvcs and Regasm Metadata', '只读取 Regsvcs 和 Regasm 的来源与版本，不载入程序集。', 'Read Regsvcs and Regasm source and version metadata without loading an assembly.'),
      reviewedCommand("Get-AuthenticodeSignature \"$env:WINDIR\\System32\\rundll32.exe\" | Select-Object Status,StatusMessage,SignerCertificate", '读取 Rundll32 签名基线', 'Read the Rundll32 Signature Baseline', '记录系统 Rundll32 的签名状态，不传入 DLL、JavaScript 或控制面板参数。', 'Record system Rundll32 signature status without supplying a DLL, JavaScript, or control-panel argument.'),
    ],
  },
  {
    id: 'persistence-scheduled',
    retainPayload: true,
    labelZh: '计划任务持久化安全核对',
    labelEn: 'Safe Scheduled-Task Persistence Review',
    category: i18n('持久化工具', 'Persistence Tools'),
    rationale: '原条目直接创建登录、定时和 Cron 后门任务；迁入持久化工具卡，只读取现有任务和本地 Cron 条目，不创建或注册任务。',
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks',
      'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask',
      'https://attack.mitre.org/techniques/T1053/005/',
    ],
    editorial: persistenceEditorial,
    targets: [
      migrationTarget('persistence-techniques', 'post-exploit-tools', [0, 1, 2, 3], [
        'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks',
        'https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask',
        'https://attack.mitre.org/techniques/T1053/005/',
      ]),
    ],
    execution: [
      reviewedCommand("Get-ScheduledTask -TaskPath '\\' | Select-Object -First 50 TaskName,State,Author", '读取有界登录任务清单', 'Read a Bounded Scheduled-Task List', '读取根任务路径最多 50 个任务的名称、状态和作者，不创建或修改任务。', 'Read names, states, and authors for at most 50 tasks in the root task path without creating or modifying tasks.'),
      reviewedCommand("Get-ScheduledTask | Select-Object -First 50 TaskName,TaskPath,State", '读取有界计划任务基线', 'Read a Bounded Scheduled-Task Baseline', '读取最多 50 个现有任务的路径和状态，用于和批准清单比较，不触发任务。', 'Read paths and states for at most 50 existing tasks for comparison with the approved list without triggering a task.'),
      reviewedCommand("Get-ScheduledTask -TaskName '{LAB_TASK}' -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo | Select-Object TaskName,LastRunTime,NextRunTime,LastTaskResult", '读取单一任务运行信息', 'Read One Scheduled-Task Runtime Record', '只读取一个授权任务的最近运行信息，不注册任务或改变触发器。', 'Read recent runtime information for one authorized task without registering a task or changing a trigger.'),
      reviewedCommand('crontab -l 2>/dev/null | head -n 50', '读取有界用户 Cron 条目', 'Read Bounded User Cron Entries', '只读取当前用户最多 50 行 Cron 配置，不编辑或安装计划任务。', 'Read at most 50 lines of the current user Cron configuration without editing or installing a scheduled task.'),
    ],
  },
  {
    id: 'exchange-mailbox-access',
    retainPayload: true,
    labelZh: 'Exchange 邮箱访问边界预检',
    labelEn: 'Exchange Mailbox-Access Boundary Preflight',
    category: i18n('Exchange 工具', 'Exchange Tools'),
    rationale: '原条目包含 OWA/EWS 登录、MAPI 访问和 PST 导出；迁入 Exchange/M365 工具卡，只保留端点头、帮助和权限边界检查，不读取邮箱内容或导出数据。',
    references: [
      'https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/start-using-web-services-in-exchange',
      'https://learn.microsoft.com/en-us/exchange/clients/outlook/connectivity-with-microsoft-365',
      'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-mailboxexportrequest',
    ],
    editorial: serviceEditorial,
    targets: [
      migrationTarget('exchange-m365-attacks', 'domain-pentest-tools', [0, 1, 2, 3], [
        'https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/start-using-web-services-in-exchange',
        'https://learn.microsoft.com/en-us/exchange/clients/outlook/connectivity-with-microsoft-365',
        'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-mailboxexportrequest',
      ]),
    ],
    execution: [
      reviewedCommand('curl --fail --silent --show-error --max-time 5 -I https://{EXCHANGE_HOST}/owa/', '读取 OWA 端点头', 'Read OWA Endpoint Headers', '对一个登记 Exchange 主机只发送 HEAD 请求，验证端点和安全头，不提交凭证。', 'Send a HEAD request only to one registered Exchange host to verify endpoint and security headers without submitting credentials.'),
      reviewedCommand('curl --fail --silent --show-error --max-time 5 -I https://{EXCHANGE_HOST}/ews/exchange.asmx', '读取 EWS 端点头', 'Read EWS Endpoint Headers', '对一个登记 Exchange 主机只读取 EWS 响应头，不建立邮箱会话或读取邮件。', 'Read only EWS response headers on one registered Exchange host without opening a mailbox session or reading mail.'),
      reviewedCommand("Get-Help New-MailboxExportRequest -Examples | Select-Object -First 30", '查看邮箱导出参数', 'Inspect Mailbox-Export Parameters', '只查看 Exchange 管理模块的导出示例并限制输出，不创建导出请求。', 'Read bounded Exchange management examples for mailbox export without creating an export request.'),
      reviewedCommand("Get-Command New-MailboxExportRequest -ErrorAction SilentlyContinue | Select-Object Name,Module,Version", '读取邮箱导出 cmdlet 元数据', 'Read Mailbox-Export Cmdlet Metadata', '只读取本地 Exchange cmdlet 的名称、模块和版本，不访问邮箱或写入 PST。', 'Read the local Exchange cmdlet name, module, and version without accessing a mailbox or writing a PST.'),
    ],
  },
  {
    id: 'unattended-creds',
    retainPayload: true,
    labelZh: '无人值守凭证文件安全核对',
    labelEn: 'Safe Unattended-Credential File Review',
    category: i18n('凭证审计工具', 'Credential Audit Tools'),
    rationale: '原条目包含全盘递归、明文/Base64 密码提取、GPP/IIS/Wi-Fi 凭证读取和 Metasploit 自动化；迁入 Windows 后渗透工具卡，只检查本地合成 fixture 与默认目录元数据。',
    references: [
      'https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend',
      'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/group-policy-preferences',
      'https://attack.mitre.org/techniques/T1552/001/',
    ],
    editorial: unattendedCredentialEditorial,
    targets: [
      migrationTarget('post-exploitation-windows', 'post-exploit-tools', [0, 1, 2, 3, 4, 5], [
        'https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend',
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/group-policy-preferences',
        'https://attack.mitre.org/techniques/T1552/001/',
      ]),
    ],
    execution: [
      reviewedCommand("Get-ChildItem -Path \"$env:WINDIR\\Panther\" -Filter '*unattend*.xml' -File -ErrorAction SilentlyContinue | Select-Object -First 20 FullName,Length,LastWriteTime", '读取默认无人值守文件元数据', 'Read Default Unattended-File Metadata', '只读取 Panther 目录最多 20 个无人值守文件的路径和时间，不打开或输出凭证字段。', 'Read paths and timestamps for at most 20 unattended files under Panther without opening or outputting credential fields.'),
      reviewedCommand("Get-ChildItem -Path .\\fixtures\\unattended -Depth 2 -Include '*unattend*','*sysprep*','*autounattend*' -File -ErrorAction SilentlyContinue | Select-Object -First 50 FullName,Length", '检查本地无人值守 fixture', 'Inspect Local Unattended Fixtures', '只在本地合成 fixture 两层目录内列出最多 50 个候选文件，不进行全盘搜索。', 'List at most 50 candidate files within two levels of local synthetic fixtures without searching the whole disk.'),
      reviewedCommand("Select-String -Path .\\fixtures\\unattended\\*.xml -Pattern 'Password|AutoLogon|AdminPassword' -SimpleMatch | Select-Object -First 50 Path,LineNumber,Line", '定位合成凭证字段', 'Locate Synthetic Credential Fields', '只在合成 XML 中定位字段名并限制 50 条结果，不输出或解码真实凭证。', 'Locate field names in synthetic XML with a 50-result limit without outputting or decoding real credentials.'),
      reviewedCommand("Get-FileHash .\\fixtures\\unattended\\encoded.txt -Algorithm SHA256 -ErrorAction SilentlyContinue", '校验本地编码 fixture', 'Hash a Local Encoded Fixture', '只计算本地合成编码文件哈希，不解码、打印或写回凭证内容。', 'Hash a local synthetic encoded file without decoding, printing, or writing credential content.'),
      reviewedCommand("Select-String -Path .\\fixtures\\unattended\\*.xml -Pattern 'cpassword|connectionString|Password' | Select-Object -First 50 Path,LineNumber", '检查合成敏感字段标记', 'Check Synthetic Sensitive-Field Markers', '只在合成 XML 中检查敏感字段标记并限制 50 条结果，不读取 IIS、注册表或 Wi-Fi 凭证。', 'Check sensitive-field markers in synthetic XML with a 50-result limit without reading IIS, registry, or Wi-Fi credentials.'),
      reviewedCommand("msfconsole -q -x 'info post/windows/gather/enum_unattend; exit'", '查看 Metasploit 模块信息', 'Inspect Metasploit Module Information', '只查看 enum_unattend 模块信息后退出，不运行模块或收集主机凭证。', 'Inspect enum_unattend module information and exit without running the module or collecting host credentials.'),
    ],
  },
  {
    id: 'custom-sql注入速查表',
    retainPayload: true,
    labelZh: 'SQL 注入只读测试预检',
    labelEn: 'Read-Only SQL Injection Test Preflight',
    category: i18n('Web 渗透工具', 'Web Penetration Tools'),
    rationale: '原条目是未绑定目标的 SQL 注入字符串集合；迁入高级 SQL 注入工具卡，替换为只读基线和参数化查询核对，不把攻击字符串直接发送到服务。',
    references: [
      'https://portswigger.net/web-security/sql-injection',
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_SQL_Injection',
    ],
    editorial: sqlEditorial,
    targets: [
      migrationTarget('sql-injection-advanced', 'web-attack-techniques', [0], [
        'https://portswigger.net/web-security/sql-injection',
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_SQL_Injection',
      ]),
    ],
    execution: [
      reviewedCommand("printf '%s\\n' 'SELECT 1' 'SELECT 1 WHERE 1=0' | tee ./artifacts/sql-readonly-baseline.txt", '记录只读 SQL 基线', 'Record a Read-Only SQL Baseline', '仅生成固定只读 SQL 基线并保存本地 artifact，不把注入字符串发送到业务端点。', 'Generate fixed read-only SQL baselines in a local artifact without sending injection strings to a business endpoint.'),
    ],
  },
];

const targetsForProfile = profile => asList(profile.targets).length
  ? profile.targets
  : [migrationTarget(
      profile.targetToolId,
      profile.navRootId,
      profile.execution.map((_, index) => index),
      profile.references,
      asList(profile.wafBypass).map((_, index) => index),
    )];

const referencesForProfile = profile => [...new Set([
  ...asList(profile.references),
  ...targetsForProfile(profile).flatMap(target => asList(target.references)),
])];

const validateProfileRouting = profile => {
  const expected = [
    ...asList(profile.execution).map((_, index) => `execution:${index}`),
    ...asList(profile.wafBypass).map((_, index) => `wafBypass:${index}`),
  ].sort();
  const routed = targetsForProfile(profile).flatMap(target => {
    if (!target.targetToolId || !target.navRootId || !asList(target.references).length) {
      throw new Error(`${profile.id} requires target tool, navigation root, and references.`);
    }
    return [
      ...asList(target.commandIndexes).map(index => `execution:${index}`),
      ...asList(target.wafBypassIndexes).map(index => `wafBypass:${index}`),
    ];
  });
  if (new Set(routed).size !== routed.length || JSON.stringify([...routed].sort()) !== JSON.stringify(expected)) {
    throw new Error(`${profile.id} must route every replacement command exactly once.`);
  }
  for (const entry of [...asList(profile.execution), ...asList(profile.wafBypass)]) {
    if (!String(entry?.command || '').trim() || !entry?.title?.zh || !entry?.title?.en
      || !entry?.description?.zh || !entry?.description?.en) {
      throw new Error(`${profile.id} contains an incomplete bilingual command.`);
    }
  }
};

const reviewEntry = profile => {
  const editorial = profile.editorial || {};
  const retained = profile.retainPayload === true;
  return ({
  id: profile.id,
  name: retained
    ? i18n(profile.labelZh, profile.labelEn)
    : i18n(`${profile.labelZh}（工具迁移）`, `${profile.labelEn} (Tool Migration)`),
  description: retained
    ? i18n('该条目保留为技术验证 Payload，保留原始可复现命令，仅补充授权实验、占位符边界、蓝队证据和回滚要求。', 'This entry remains a technical-validation payload with its reproducible commands preserved, adding only lab authorization, placeholder boundaries, blue-team evidence, and rollback requirements.')
    : i18n('该条目由多条产品或系统命令组成，已迁入对应工具卡维护命令、参数、前置条件和证据，不再作为独立 Payload 展示。', 'This entry contains multiple product or system commands and is migrated to the corresponding tool card for commands, parameters, prerequisites, and evidence rather than remaining a standalone payload.'),
  category: profile.category,
  subCategory: i18n(profile.labelZh, profile.labelEn),
  prerequisites: [
    i18n('确认资产、账号、域名或目录范围属于当前授权任务，并记录工具版本与查询时间。', 'Confirm that assets, identities, domains, and directory scope belong to the authorized task, recording tool versions and query time.'),
    retained
      ? i18n('保留命令只可在书面授权、隔离、可回滚的实验中逐条执行；写入、认证、远程动作和凭据处理必须记录目标、主体与停止条件。', 'Run retained commands one at a time only in a written, isolated, reversible lab authorization; record target, principal, and stop conditions for writes, authentication, remote actions, or credential handling.')
      : i18n('默认执行只读查询；任何写入、认证尝试、全端口扫描或配置变更必须另行批准。', 'Use read-only queries by default; writes, authentication attempts, full-port scans, and configuration changes require separate approval.'),
  ],
  tutorial: {
    overview: retained
      ? i18n(`${profile.labelZh} 保留为可独立复现的技术验证卡。原始命令能力不被删除；审校只处理明显叙述、占位符或不可执行片段，并要求隔离授权、回滚和蓝队证据。`, `${profile.labelEn} remains an independently reproducible technical-validation card. Original command capability is retained; review only repairs obvious narrative, placeholder, or non-executable fragments and requires isolated authorization, rollback, and blue-team evidence.`)
      : i18n(`${profile.labelZh} 原卡片本质上是命令手册而不是可独立验证的输入载荷。迁移后，工具区统一维护安装、占位符、范围、预期输出和停止条件，Payload 区只保留可复现的技术边界。`, `The original ${profile.labelEn} card is a command manual rather than an independently testable input payload. After migration, installation, placeholders, scope, expected output, and stop conditions are maintained in the tool section while the payload section retains reproducible technical boundaries.`),
    vulnerability: editorial.vulnerability || i18n('查询结果、公开 DNS 记录、目录对象或源站响应本身不是漏洞；只有它们与授权边界、资产归属、访问控制或预期配置不一致，并有服务器端或控制面证据支持时，才构成有效发现。', 'Query results, public DNS records, directory objects, or origin responses are not vulnerabilities by themselves. A finding requires a mismatch with authorization, ownership, access control, or expected configuration supported by server-side or control-plane evidence.'),
    exploitation: retained
      ? i18n('先确认身份、范围、回滚点和蓝队采集，再按原始命令逐条执行；把能力结果与资产清单、目录配置、网络流量、端点遥测和服务端日志交叉核对。', 'Confirm identity, scope, rollback point, and blue-team collection first, then run the retained commands one at a time; correlate capability results with inventory, directory configuration, network traffic, endpoint telemetry, and server logs.')
      : i18n('先确认身份与范围，再一次运行一条只读命令并保存原始输出；把结果与资产清单、目录配置、DNS、HTTP 头或审计日志交叉核对。出现非授权资产、敏感正文、状态变更或过量请求时立即停止。', 'Confirm identity and scope, run one read-only command at a time, preserve raw output, and compare it with inventories, directory configuration, DNS, HTTP headers, or audit logs. Stop on unauthorized assets, sensitive bodies, state changes, or excessive requests.'),
    mitigation: editorial.mitigation || i18n('按实际发现收紧目录查询与高权限组、隐藏源站并限制仅 CDN 网段访问、统一证书和 Host 路由配置，并为异常枚举、直连尝试和配置漂移建立审计。修复后使用同一只读命令回归。', 'Tighten directory queries and privileged groups, restrict origins to CDN networks, align certificate and Host routing configuration, and audit anomalous enumeration, direct-origin attempts, and drift. Re-run the same read-only commands after remediation.'),
    difficulty: 'intermediate',
  },
  attackChain: [
    {
      title: i18n(`建立${profile.labelZh}前置条件基线`, `Establish the ${profile.labelEn} Prerequisite Baseline`),
      description: i18n(`记录 ${profile.labelZh} 的当前主体、单一授权资产、组件或工具版本、适用条件、正常基线和停止条件；不把工具存在或查询成功直接判定为漏洞。`, `Record the principal, one authorized asset, component or tool version, applicability conditions, normal baseline, and stop conditions for ${profile.labelEn}; do not treat tool availability or query success as a vulnerability.`),
    },
    {
      title: retained ? i18n(`运行一条${profile.labelZh}验证命令`, `Run One ${profile.labelEn} Validation Command`) : i18n(`运行一条${profile.labelZh}基线命令`, `Run One ${profile.labelEn} Baseline Command`),
      description: retained
        ? i18n(`只在授权实验中运行 ${profile.labelZh} 的第一条已审查命令，保存原始输出、时间戳、目标端日志和回滚状态，不串联其他动作。`, `Run only the first reviewed ${profile.labelEn} command in the authorized lab, preserving raw output, timestamps, target-side logs, and rollback state without chaining other actions.`)
        : i18n(`只运行 ${profile.labelZh} 的第一条只读命令并保存原始输出、时间戳和查询上下文，不并发扩展到其他资产。`, `Run only the first read-only ${profile.labelEn} command and preserve raw output, timestamps, and query context without expanding concurrently to other assets.`),
      payloadRef: { area: 'execution', index: 0 },
    },
    {
      title: i18n(`关联${profile.labelZh}权威证据`, `Correlate Authoritative ${profile.labelEn} Evidence`),
      description: editorial.evidence || i18n('把命令结果与目录、DNS、CDN 控制面、资产清单和审计日志对照，区分正常可见性、配置漂移和真实越权。', 'Compare command output with directory, DNS, CDN control-plane, asset-inventory, and audit-log evidence to distinguish normal visibility, drift, and actual authorization failures.'),
    },
    {
      title: i18n(`修复并回归${profile.labelZh}`, `Remediate and Retest ${profile.labelEn}`),
      description: i18n(`完成 ${profile.labelZh} 对应的最小权限、补丁或配置修复后，以相同主体和同一条命令回归，确认正常管理能力保留且原证据链不再成立。`, `After the least-privilege, patch, or configuration remediation for ${profile.labelEn}, retest with the same principal and command to confirm legitimate administration remains available and the original evidence chain no longer holds.`),
    },
  ],
  analysis: editorial.analysis || (retained
    ? i18n('有效结论必须同时包含执行主体、精确目标、原始技术输出、能力影响、回滚状态和权威配置或日志。命令成功、权限名称或工具存在只能证明能力，不能单独证明安全问题。', 'A valid conclusion requires principal, exact target, raw technical output, capability impact, rollback state, and authoritative configuration or logs. Command success, a privilege name, or tool availability proves capability only and does not alone prove a security issue.')
    : i18n('有效结论必须同时包含查询身份、明确范围、原始输出和权威配置或日志。命令成功、域对象存在、公开 DNS 记录或 HTTP 200 都不能单独证明安全问题。', 'A valid conclusion requires query identity, explicit scope, raw output, and authoritative configuration or logs. Command success, a directory object, a public DNS record, or HTTP 200 alone does not prove a security issue.')),
  opsecTips: [
    i18n('限制查询次数和输出字段，不保存凭证、Token、邮件正文或无关用户属性。', 'Limit query count and output fields, and do not retain credentials, tokens, mail bodies, or unrelated user attributes.'),
    i18n('检测到超出授权的写操作、认证尝试、非授权资产或异常请求量时立即停止、回滚并保存审计时间点。', 'Stop, roll back, and preserve the audit timestamp on writes, authentication attempts, unauthorized assets, or abnormal request volume outside the authorization.'),
  ],
  references: referencesForProfile(profile),
  review: {
    decision: retained ? 'payload' : 'tool',
    rationale: retained
      ? `${profile.labelZh} 保留为技术验证 Payload；原始攻击语法继续保留，仅清理不可执行叙述并补充隔离授权、回滚和蓝队证据。`
      : profile.rationale,
    issuesResolved: retained
      ? ['preserved-technical-command-capability', 'added-lab-authorization-and-rollback', 'added-blue-team-evidence', 'normalized-review-boundaries']
      : ['corrected-tool-classification', 'removed-state-changing-or-unbounded-commands', 'added-bounded-read-only-commands', 'added-authoritative-references'],
    ...(retained ? {} : { targetToolIds: [...new Set(targetsForProfile(profile).map(target => target.targetToolId))] }),
  },
  });
};

const coreHan = value => /\p{Script=Han}/u.test(String(value || ''));

const coreExecutableLine = value => {
  const line = String(value || '').trim();
  if (!line || /^(?:#|\/\/|REM\b|::)/i.test(line)) return false;
  if (/^\d+[.)]\s*$/.test(line) || /^-+\s*$/.test(line) || /^-\s+[A-Za-z]/.test(line)) return false;
  if (/^(?:使用|检查|获取|设置|添加|创建|执行|将|访问|构造|检测|加载|导出|恢复|中继|需要|寻找|结合|确认|参考|替换|任何|如果|运行时|从|不|或|首先|重点|直接|简单|修改|自动获得)/u.test(line)) return false;
  return /^(?:--[a-z]|\$|\[|[A-Za-z0-9_.\\/'"`-]+(?:\s|\(|:|=|$)|[0-9]+\s*=|(?:GET|POST|PUT|DELETE)\s)/i.test(line);
};

const repairRetainedLine = value => {
  const line = String(value || '').trim();
  if (!line || /^(?:#|\/\/|REM\b|::)/i.test(line)) return '';
  if (!coreHan(line)) return coreExecutableLine(line) ? line : '';
  if (/['"][^'"]*\p{Script=Han}[^'"]*['"]/u.test(line)) {
    return line.replace(/\p{Script=Han}+/gu, '{LAB_LABEL}');
  }
  const option = line.match(/(--[a-z][^\r\n]*)$/i);
  if (option) return option[1].trim();
  const hanIndex = line.search(/\p{Script=Han}/u);
  const prefix = line.slice(0, hanIndex).trim().replace(/(?:\/\/|#)\s*$/, '').trim();
  if (!prefix || !coreExecutableLine(prefix)) return '';
  return prefix;
};

const repairRetainedCommand = (sourceCommand, profile, index) => {
  const lines = String(sourceCommand || '').split(/\r?\n/).map(repairRetainedLine).filter(Boolean);
  const repaired = lines.join('\n').trim();
  if (repaired === sourceCommand) return null;
  if (repaired) return repaired;
  const markerId = profile.id.toUpperCase().replace(/BACKDOOR/g, 'LEGACY_ACCOUNT').replace(/[^A-Z0-9]+/g, '_');
  return profile.platform === 'linux'
    ? `printf '%s\\n' 'PAYLOADER_${markerId}_REVIEW_${index + 1}'`
    : `Write-Output 'PAYLOADER_${markerId}_REVIEW_${index + 1}'`;
};

const commandPatches = (source, profile) => {
  if (profile.retainPayload) {
    const patches = [];
    for (const area of ['execution', 'wafBypass']) {
      for (const [index, original] of asList(source[area]).entries()) {
        const sourceCommand = String(original?.command || '').trim();
        const command = repairRetainedCommand(sourceCommand, profile, index);
        if (!command || command === sourceCommand) continue;
        patches.push({
          area,
          index,
          expectedCommand: sourceCommand,
          command,
          title: i18n(`${profile.labelZh}命令校正 ${index + 1}`, `${profile.labelEn} Command Repair ${index + 1}`),
          description: i18n(
            `仅移除纯叙述或修正实验占位符，保留 ${profile.labelZh} 的可复现技术语法；执行时记录授权、回滚和蓝队证据。`,
            `Remove narrative-only text or repair lab placeholders while preserving reproducible ${profile.labelEn} syntax; record authorization, rollback, and blue-team evidence during execution.`,
          ),
          ...(original?.syntaxBreakdown !== undefined ? { syntaxBreakdown: structuredClone(original.syntaxBreakdown) } : {}),
          ...(original?.platform !== undefined ? { platform: original.platform } : {}),
          ...(original?.requiresAdmin !== undefined ? { requiresAdmin: original.requiresAdmin } : {}),
        });
      }
    }
    return patches;
  }
  const patches = [];
  for (const area of ['execution', 'wafBypass']) {
    const replacements = asList(profile[area]);
    const original = asList(source[area]);
    if (replacements.length !== original.length) {
      throw new Error(`${source.id} ${area} count changed: expected ${replacements.length}, found ${original.length}`);
    }
    replacements.forEach((replacement, index) => {
      patches.push({
        area,
        index,
        expectedCommand: String(original[index]?.command || ''),
        command: replacement.command,
        title: replacement.title,
        description: replacement.description,
      });
    });
  }
  return patches;
};

export const buildCoreToolMigrationDocuments = payloadsInput => {
  const sourceById = new Map(asList(payloadsInput).map(payload => [payload.id, payload]));
  const profiles = migrationProfiles.map(profile => {
    validateProfileRouting(profile);
    const source = sourceById.get(profile.id);
    if (!source) throw new Error(`Missing source payload: ${profile.id}`);
    return { profile, source };
  });
  return {
    overrides: {
      schemaVersion: 1,
      contentStandard: 3,
      sourceIds: profiles.map(({ profile }) => profile.id),
      entries: profiles.map(({ profile }) => reviewEntry(profile)),
    },
    commandOverrides: {
      schemaVersion: 1,
      entries: profiles.flatMap(({ profile, source }) => {
        const patches = commandPatches(source, profile);
        return patches.length ? [{ id: profile.id, patches }] : [];
      }),
    },
    migrations: {
      schemaVersion: 1,
      contentStandard: 2,
      toolMigrations: profiles.filter(({ profile }) => !profile.retainPayload).map(({ profile }) => ({
        sourceId: profile.id,
        targets: targetsForProfile(profile).map(target => ({
          targetToolId: target.targetToolId,
          navRootId: target.navRootId,
          targetReferences: [...new Set(asList(target.references))],
          commandIndexes: [...asList(target.commandIndexes)],
          wafBypassIndexes: [...asList(target.wafBypassIndexes)],
        })),
        review: {
          rationale: profile.rationale,
          commandDisposition: 'all-reviewed-commands-migrated-to-tool-card',
        },
      })),
    },
  };
};

export const restoreCoreToolMigrationSources = (payloadsInput, commandOverridesInput) => {
  const sourcesById = new Map(asList(payloadsInput).map(payload => [payload.id, structuredClone(payload)]));
  const overridesById = new Map(asList(commandOverridesInput?.entries).map(entry => [entry.id, entry]));
  for (const profile of migrationProfiles) {
    let source = sourcesById.get(profile.id);
    if (!source) {
      source = {
        id: profile.id,
        execution: asList(profile.execution).map(() => ({})),
        wafBypass: asList(profile.wafBypass).map(() => ({})),
      };
      sourcesById.set(profile.id, source);
    }
    const override = overridesById.get(profile.id);
    for (const patch of asList(override?.patches)) {
      if (!['execution', 'wafBypass'].includes(patch?.area) || !Number.isInteger(patch?.index)) continue;
      while (asList(source[patch.area]).length <= patch.index) source[patch.area].push({});
      source[patch.area][patch.index] = {
        ...source[patch.area][patch.index],
        command: String(patch.expectedCommand || ''),
      };
    }
  }
  return [...sourcesById.values()];
};

const outputFiles = [
  ['overrides-core-tool-migrations.json', 'overrides'],
  ['payload-command-overrides-core-tool-migrations.json', 'commandOverrides'],
  ['collection-splits-core-tool-migrations.json', 'migrations'],
];

const run = () => {
  const root = resolve(process.cwd());
  const snapshot = loadCurationSnapshot(join(root, 'data', 'payloader.sqlite'));
  const commandOverrideFile = join(root, 'content-review', 'payload-command-overrides-core-tool-migrations.json');
  const commandOverrides = JSON.parse(readFileSync(commandOverrideFile, 'utf8'));
  const sources = restoreCoreToolMigrationSources(snapshot.payloads, commandOverrides);
  const documents = buildCoreToolMigrationDocuments(sources);
  for (const [fileName, key] of outputFiles) {
    const file = join(root, 'content-review', fileName);
    writeFileSync(file, `${JSON.stringify(documents[key], null, 2)}\n`, 'utf8');
    console.log(`wrote ${fileName}`);
  }
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) run();
