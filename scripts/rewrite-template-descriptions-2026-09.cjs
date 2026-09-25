#!/usr/bin/env node
/**
 * 2026-09 终审批次 3：150 条拆分模板描述重写。
 * - 123 条纯模板（splitRoute/verifyCard/retainCmd）→ 逐条手写技术描述（zh；en 保留不动）
 * - 27 条 oldSet（"X将旧集合限定为单一验证边界：实质尾"）→ 剥头保尾
 * 落点：content-review 文档链全部承载点（entries + replacements + payloadOverrides）。
 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const CR = p => path.join(ROOT, 'content-review', p);

const REWRITE = {
  // ── SQL 系（splitRoute 17）──
  'sqli-boolean-blind': '成对提交真/假条件并携带唯一 Marker，以响应内容或长度差确认输入被拼入 SQL 查询；记录两侧完整证据再下结论。',
  'sqli-time-mysql': '在注入点提交携带 Marker 的 SLEEP(1) 载荷，以响应耗时稳定增加约 1 秒判定 MySQL 时间盲注成立。',
  'sqli-time-mssql': "用 WAITFOR DELAY '0:0:1' 构造条件延迟，以约 1 秒的响应偏移确认 SQL Server 时间盲注。",
  'sqli-time-postgresql': '提交 SELECT pg_sleep(1) 变体载荷，以响应延迟确认 PostgreSQL 时间盲注。',
  'sqli-time-oracle': '用 DBMS_LOCK.SLEEP 或 DBMS_PIPE.RECEIVE_MESSAGE 构造 1 秒延迟，确认 Oracle 时间盲注。',
  'sqli-union-query': '以 ORDER BY/NULL 逐步对齐列数后注入 UNION SELECT Marker，定位回显位并验证只读数据可提取。',
  'sqli-http-chunked-carrier': '用 Transfer-Encoding: chunked 分块传输 SQL Marker，验证代理按重组体解析时是否放行被分帧打散的注入。',
  'sqli-stacked-mysql': '注入分号分隔的第二条语句（PREPARE/EXECUTE 形态），验证 MySQL 连接是否允许多语句执行。',
  'sqli-stacked-mssql': '注入分号加 sp_executesql 形态的堆叠语句，验证 SQL Server 是否执行额外语句。',
  'sqli-stacked-postgresql': '注入分号加 COPY/DO 块形态的堆叠语句，验证 PostgreSQL 多语句执行边界。',
  'sqli-stacked-destructive-dml': '在显式事务内执行 Marker DML 后回滚，以数据库状态不变证明堆叠执行成立且不留持久变更。',
  'sqli-carrier-chunked': '发送手工构造的完整 Chunked HTTP 请求携带 SQL Marker，对比代理与后端对分帧请求的解释差异。',
  'sqli-carrier-http-parameter-pollution': '同名参数一净一污分别提交，验证后端取值顺序是否让污染值进入查询。',
  'sqli-expression-waf-variants': '用 CASE/DECODE 等价表达式与内联注释重写同一攻击语义，验证仅匹配关键字的防护是否放行。',
  'sqli-padding-comment-bypass': '用有界注释拉长载荷打散特征串，验证基于长度或连续特征的检测是否失效。',
  'sqli-carrier-multipart': '把 SQL Marker 放入 multipart 文件名字段提交，验证解析链是否对 multipart 部件内容做注入检查。',
  'sqli-carrier-json': '在 JSON 请求体的字符串字段提交 SQL Marker，验证 API 是否把 JSON 值直接拼入数据库查询。',
  // ── 认证系（verifyCard 34）──
  'auth-sql-login-bypass': '对登录表单提交引号、恒真条件与注释闭合变体，以差异响应或成功登录判定凭据是否被拼接进 SQL。',
  'auth-php-credential-type-confusion': '把用户名/密码提交为数组、true 或 0 形态，利用 PHP 松散比较绕过凭据校验。',
  'auth-nosql-credential-operator': "把登录字段替换为 {$ne:''} 等对象操作符，验证 MongoDB 查询是否接受客户端构造的匹配条件。",
  'auth-trusted-proxy-header': '伪造 X-Forwarded-For 等代理头，验证应用是否以可伪造的请求头做身份或内网信任判定。',
  'auth-method-path-normalization': '用大小写、尾斜杠与编码变体访问同一受保护路径并切换 HTTP 方法，验证代理与应用的授权判定是否一致。',
  'auth-session-fixation': '预置已知 Session ID 再完成登录，验证会话标识在认证成功后是否被服务端轮换。',
  'auth-cookie-tossing': '向子域或父域路径投掷同名 Cookie，验证会话或 CSRF 判定是否读取到攻击者写入的值。',
  'auth-samesite-navigation': '以顶级导航、子资源、弹窗回调等场景携带 Cookie，验证 SameSite 属性在各路径下的实际拦截边界。',
  'auth-reset-host-header': '篡改 Host 头触发密码重置邮件，验证重置链接是否从不可信 Host 派生并劫持令牌。',
  'auth-reset-token-binding': '用 A 账号申请的重置令牌尝试重置 B 账号，验证令牌与目标账户的绑定强度。',
  'auth-reset-flow-state': '跳步直接调用重置流程的后端端点，验证服务端状态机是否强制按序执行。',
  'auth-reset-token-replay': '重复提交已消费的重置令牌，验证其单次使用约束是否生效。',
  'auth-oauth-state-binding': '篡改、复用或移除 state 参数，验证授权请求与回调浏览器会话的绑定是否成立。',
  'auth-oauth-redirect-uri': '提交外部域、路径穿越与 @ 混淆等 redirect_uri 变体，验证授权服务器是否对预注册回调精确匹配。',
  'auth-oauth-scope-audience': '请求超范围 scope 或跨资源 audience 的令牌，验证签发与资源侧校验是否收紧。',
  'auth-saml-signature-validation': '修改断言属性后重放响应，验证 SP 是否校验实际使用的断言签名而非仅响应签名。',
  'auth-saml-replay': '重放已使用的 Assertion（含 NotOnOrAfter 时间边界），验证服务提供方的重放防护。',
  'auth-saml-xsw': '构造 XML 签名包装变体（移动签名引用对象），验证签名校验是否可被结构欺骗。',
  'xxe-saml-parser': '在 SAMLResponse 中注入外部实体引用，验证 SAML 解析链是否禁用 DTD 与外部实体加载。',
  'auth-saml-nameid-canonicalization': '提交大小写与编码规范化变体的 NameID，验证身份映射是否可被规范化差异欺骗。',
  'auth-2fa-state-enforcement': '绕过前端直接请求 2FA 之后的端点，验证服务端是否强制完成第二因素验证。',
  'auth-2fa-input-schema': '提交空值、类型异常与超长验证码，验证 2FA 输入校验与失败锁定行为。',
  'auth-2fa-recovery-code': '并发提交同一恢复码，验证其消费的原子性与单次性约束。',
  'auth-captcha-replay': '重复提交已通过验证的 CAPTCHA 会话，验证挑战与单次提交的绑定。',
  'auth-captcha-input-schema': '提交空值与类型异常的验证码答案，验证是否可跳过校验直接通过。',
  'auth-captcha-route-consistency': '对比有无 CAPTCHA 的等价路由，验证验证码策略覆盖是否一致。',
  'auth-remember-token-integrity': '拆解持久登录令牌结构，验证是否含可预测分量或未签名数据。',
  'auth-remember-token-replay': '重放已注销的 RememberMe 令牌，验证服务端撤销是否即时生效。',
  'auth-shiro-rememberme-deserialization': '用已知默认密钥构造加密的 Shiro RememberMe 值，验证反序列化边界（限授权实验环境）。',
  'auth-jwt-none': '提交 alg=none 及其大小写变体的空签名令牌，验证验证器是否拒绝无签名访问。',
  'auth-jwt-alg-confusion': '用服务端 RSA 公钥作 HMAC 密钥签名令牌，验证算法与密钥类型绑定是否被绕过。',
  'auth-jwt-kid-validation': '提交任意、超长与路径形态的 kid，验证密钥查找是否限定在允许列表内。',
  'auth-jwt-jwk-jku-trust': '在头部内嵌 JWK 或指向外部 JKU 端点，验证验证器是否信任令牌自带的密钥材料。',
  'auth-jwt-claim-validation': '篡改 exp/sub 等声明并构造嵌套 JWT，验证必需声明与嵌套令牌的校验强度。',
  // ── 内网系（retainCmd 72）──
  'kerberoasting': '用 Rubeus/GetUserSPNs 请求目标 SPN 的服务票据并导出离线破解，以破解成功证明服务账号口令强度不足。',
  'sam-dump': '以 SYSTEM 权限导出 SAM/SYSTEM 注册表 hive 或用 impacket secretdump 提取本地哈希，验证终端凭据存储边界。',
  'ntds-dump': '通过 ntdsutil、卷影副本或 DCSync 提取 NTDS.dit，验证域控数据库的访问与备份边界。',
  'gpp-password': '在 SYSVOL 共享中定位 Groups.xml 并解密 cpassword 字段，验证组策略遗留凭据的可读性。',
  'lateral-psexec': '以授权凭据经 SMB/ADMIN$ 部署服务执行命令，验证远程服务执行边界与对应检测信号。',
  'lateral-wmi': '通过 WMI（wmic/Invoke-CimMethod）远程执行管理操作，验证管理协议的授权与遥测覆盖。',
  'pass-the-hash': '以窃取的 NTLM 哈希直接完成认证（pth 工具链），验证 NTLM 禁用策略与哈希传递防护。',
  'ntlm-relay': '把捕获的 NTLM 认证中继到 SMB/HTTP/LDAP 目标，验证 SMB 签名与 EPA 配置的中继面。',
  'privilege-token': '枚举当前进程令牌特权（SeImpersonate/SeAssignPrimaryToken 等），评估服务账户的模拟风险面。',
  'persistence-registry': '审计 Run/RunOnce 等自启动键的新增与异常项，验证注册表启动项持久化痕迹。',
  'evasion-powershell': '以编码、变量拼接方式执行固定 Marker 命令，对比 AMSI 与脚本块日志的捕获差异。',
  'domain-privilege-escalation': '用 BloodHound/SharpHound 枚举 ACL 到域管的可提权路径，验证危险权限链是否可达。',
  'domain-cross-trust': '枚举域与林信任的方向、传递性与 TGT 转发能力，验证跨信任边界的防护强度。',
  'dpapi-creds': '定位 Master Key 与加密 Blob 并解密（授权环境），验证 DPAPI 保护的应用凭据边界。',
  'rdp-creds': '解析 .rdp 文件与凭据管理器中的 RDP 条目，验证远程桌面凭据的引用与存储方式。',
  'wifi-creds': '以管理员导出 WLAN Profile XML（key=clear），验证 Wi-Fi 共享密钥的本地保护强度。',
  'vault-creds': '枚举 Windows Vault 与凭据管理器条目，验证通用凭据的存储与访问边界。',
  'keepass-dump': '定位 .kdbx 数据库与进程内存中的主密钥材料，验证密码管理器的文件与内存保护。',
  'lsa-secrets': '读取 LSA Secrets 注册表存储，验证服务账号口令与自动登录凭据的暴露面。',
  'lateral-dcom': '通过 DCOM（MMC20/ShellWindows 等）远程激活执行命令，验证 COM 服务器的授权配置。',
  'rdp-hijack': '以 SYSTEM 权限用 tscon 接管其他用户的断开会话，验证 RDP 会话隔离机制。',
  'overpass-the-hash': '用 NTLM 哈希向 KDC 换取 Kerberos TGT，验证哈希到票据的协议转换边界。',
  'pass-the-ticket': '导入窃取的 TGT/TGS 票据访问目标服务，验证票据与主体绑定的检测能力。',
  'lateral-smbexec': '通过 SMB 命名管道半交互执行命令，验证服务写入路径与 EDR 检测面。',
  'lateral-atexec': '通过 Task Scheduler（at/schtasks）远程创建任务执行，验证计划任务通道授权。',
  'uac-bypass': '验证 UAC 虚拟化、自动提升配置与已知绕过路径（fodhelper 等）的适用前提。',
  'dll-hijack': '审计服务目录可写性与 DLL 搜索顺序，验证劫持加载提权的可行面。',
  'service-exploit': '审计服务的 binpath、服务 ACL 与未引用路径，验证服务重配置提权路径。',
  'always-install': '检查 AlwaysInstallElevated 策略位，验证 MSI 以 SYSTEM 安装的提权前提。',
  'juicy-potato': '验证 SeImpersonate 特权与 RPC/COM 激活条件（CLSID、端口占用），评估 JuicyPotato 适用性。',
  'printspoofer': '验证打印机服务命名管道的模拟触发条件，评估 PrintSpoofer 提权适用性。',
  'godpotato': '验证 Windows 令牌捕获原语与 potatoes 家族前提，评估 GodPotato 提权适用性。',
  'suid-exploit': '全盘枚举 SUID 二进制并对照 GTFOBins 利用清单，验证 SUID 提权面。',
  'sudo-exploit': '审计 sudoers 规则（NOPASSWD、ALL 与受限命令），验证 sudo 提权路径。',
  'cron-exploit': '审计 cron 任务定义、可写脚本与通配符注入点，验证计划任务提权。',
  'persistence-wmi': '枚举 WMI 永久事件订阅（__EventFilter/Consumer/Binding），验证无文件持久化痕迹。',
  'persistence-startup': '审计用户与公共启动文件夹的持久化条目，验证自启动滥用面。',
  'persistence-service': '审计服务 binpath 与恢复动作配置，验证服务形态的持久化滥用。',
  'persistence-dll-injection': '审计 AppInit_DLLs 与进程注入类持久化配置，验证模块加载痕迹。',
  'persistence-backdoor-user': '枚举新增、异常权限与异常登录时间的本地账号，验证账户后门。',
  'persistence-hidden-user': '检查 $ 后缀隐藏账户、注册表特殊账户与 SAM 异常，验证隐藏后门。',
  'dcsync-attack': '以授权身份执行 DCSync（mimikatz lsadump::dcsync），验证目录复制权限的最小化。',
  'golden-ticket': '验证 krbtgt 哈希可获取性（需域管级授权）与伪造黄金票据的检测面，评估该链前提。',
  'silver-ticket': '验证服务密钥已知前提下的白银票据伪造面，评估不经过 KDC 的访问风险。',
  'amsi-bypass': '测试 AMSI 初始化与扫描完整性（amsiInitFailed、内存补丁），验证 EDR 捕获边界。',
  'lateral-dcom-excel': '通过 Excel DCOM 自动化与 DDE 字段执行命令，验证 Office 横向滥用面。',
  'lateral-dcom-mmc': '通过 MMC20.Application COM 接口远程执行，验证管理控制台的横向能力。',
  'rdp-relay': '验证 RDP Restricted Admin 与 CredSSP 配置下的 NTLM 中继分类，评估 RDP 中继面。',
  'skeleton-key': '检查域控 LSASS 中的 Skeleton Key 注入痕迹（注入后万能口令），验证域控完整性监控。',
  'dsrm-backdoor': '审计 DSRM 账户密码与登录策略配置，验证域控恢复模式后门面。',
  'sid-history': '枚举用户与组的 SIDHistory 属性，验证跨域提权与历史迁移残留痕迹。',
  'persistence-process-hollowing': '对比进程映像与内存执行体不一致的镂空特征，验证内存注入遥测。',
  'zerologon': '验证 CVE-2020-1472 补丁状态与 Netlogon 安全通道配置，评估置空机器账户密码链前提。',
  'printnightmare': '验证 PrintNightmare（CVE-2021-34527）补丁状态与打印服务暴露面。',
  'petitpotam': '验证 PetitPotam/EFSRPC 强制认证路径可用性与补丁状态，评估中继前提。',
  'samaccountname': '验证 noPac 链（CVE-2021-42278/42287）的机器账户改名与提权前提。',
  'resource-delegation': '审计 RBCD 属性（msDS-AllowedToActOnBehalfOfOtherIdentity）的写入 ACL，验证基于约束委派的接管面。',
  'dcshadow-attack': '检测伪造域控的注册痕迹（异常 SPN、复制元数据与站点对象），验证 DCShadow 检测能力。',
  'group-policy-abuse': '审计 GPO 编辑与链接权限，验证策略下发通道的滥用面。',
  'etw-patch': '验证 ETW 提供程序完整性（providerguid 补丁、禁用痕迹），验证遥测绕过面。',
  'proxylogon': '验证 ProxyLogon（CVE-2021-26855）SSRF 前提到 Exchange 后台的补丁回归。',
  'proxyshell': '验证 ProxyShell 链（CVE-2021-34473 等）各环节的补丁状态。',
  'sam-the-admin': '验证 SAM The Admin/noPac 重复语义链（改名+提权）的适用前提与补丁状态。',
  'noauth': '验证 Kerberos CVE-2022-33679（NoAuth/银证书）加密降级链的前提条件。',
  'evasion-blockdlls': '验证进程模块签名策略（blockdlls、签名加载限制）下的加载绕过面。',
  'evasion-shellcode-encrypt': '提交异或/AES 编码的内存载荷样本，对比 EDR 静态与行为检测的回归表现。',
  'evasion-process-masq': '验证进程映像改写与命令行伪装的遥测一致性检测。',
  'evasion-ppid-spoof': '验证父进程欺骗（PPID Spoof）后父子链遥测的一致性检测能力。',
  'evasion-dll-sideloading': '验证合法程序加载恶意 DLL 的侧加载路径与搜索顺序检测。',
  'evasion-arg-spoofing': '验证进程参数欺骗后多源遥测（PEB/命令行）的差异检测。',
  'evasion-clr-injection': '验证 CLR 程序集注入（Unmanaged PowerShell）的加载遥测。',
  'exchange-proxytoken': '验证 ProxyToken 简化认证混淆的授权绕过与补丁回归。',
};

// oldSet 型：剥掉"…将旧集合限定为单一验证边界："前缀保留实质尾
const stripOldSet = zh => {
  const m = /^.*?将旧集合限定为单一验证边界：(.+)$/s.exec(zh || '');
  return m ? m[1].trim() : null;
};

const main = () => {
  const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
  const files = [...manifest.overrideFiles, ...(manifest.collectionSplitFiles || []), 'tool-decisions.json'];
  let manual = 0, stripped = 0;
  const hitIds = new Set();
  const apply = (obj, id) => {
    if (typeof obj.description?.zh === 'string') {
      if (REWRITE[id]) { obj.description = { ...obj.description, zh: REWRITE[id] }; manual++; }
      else { const tail = stripOldSet(obj.description.zh); if (tail && tail.length >= 10) { obj.description = { ...obj.description, zh: tail }; stripped++; } }
      hitIds.add(id);
    }
  };
  const walk = obj => {
    if (Array.isArray(obj)) { obj.forEach(walk); return; }
    if (!obj || typeof obj !== 'object') return;
    if (typeof obj.id === 'string') apply(obj, obj.id);
    for (const k of Object.keys(obj)) walk(obj[k]);
  };
  for (const f of files) {
    const full = CR(f);
    if (!fs.existsSync(full)) continue;
    const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
    const before = manual + stripped;
    walk(doc);
    if (manual + stripped > before) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
  }
  console.log(`手写重写 ${manual} 处｜剥头保留 ${stripped} 处`);
  const missing = Object.keys(REWRITE).filter(id => !hitIds.has(id));
  if (missing.length) console.log('文档链未承载（需检查）:', missing.join(','));
  else console.log('全部承载点已覆盖');
};

main();
