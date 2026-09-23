import { DatabaseSync } from 'node:sqlite';
const db = new DatabaseSync('data/payloader.sqlite');
const sel = db.prepare('SELECT data FROM payloads WHERE id=?');
const upd = db.prepare("UPDATE payloads SET data=?, updated_at=datetime('now') WHERE id=?");

const trans = [
  {
    id: 'lateral-smbexec',
    ov_en: 'SMBExec executes commands by creating a service over SMB.',
    vu_en: 'SMB allows remote service management.',
    ex_en: 'Exploitation steps: 1) Connect via SMB 2) Create a service 3) Execute commands',
    mi_en: 'Mitigations: 1) Disable SMB 2) Restrict remote service creation 3) Monitor service logs'
  },
  {
    id: 'lateral-atexec',
    ov_en: 'ATExec executes commands via scheduled tasks.',
    vu_en: 'Scheduled tasks allow remote creation and execution.',
    ex_en: 'Exploitation steps: 1) Connect to target 2) Create a task 3) Execute commands',
    mi_en: 'Mitigations: 1) Restrict remote task creation 2) Monitor task logs'
  },
  {
    id: 'lateral-winrs',
    ov_en: 'WinRS is a Windows Remote Shell tool built on WinRM.',
    vu_en: 'When WinRM is enabled, commands can be executed via WinRS.',
    ex_en: 'Exploitation steps: 1) Confirm WinRM is enabled 2) Connect with credentials 3) Execute commands',
    mi_en: 'Mitigations: 1) Restrict WinRM access 2) Monitor WinRM logs'
  },
  {
    id: 'uac-bypass',
    ov_en: 'UAC can be bypassed through specific programs or registry manipulations.',
    vu_en: 'Certain system programs auto-elevate privileges.',
    ex_en: 'Exploitation steps: 1) Identify bypass method 2) Modify registry 3) Trigger execution',
    mi_en: 'Mitigations: 1) Set UAC to highest level 2) Monitor registry modifications'
  },
  {
    id: 'juicy-potato',
    ov_en: 'Juicy Potato abuses COM objects and SeImpersonatePrivilege to escalate privileges.',
    vu_en: 'COM objects can be abused to obtain SYSTEM privileges.',
    ex_en: 'Exploitation steps: 1) Check privileges 2) Select a CLSID 3) Execute privilege escalation',
    mi_en: 'Mitigations: 1) Remove SeImpersonatePrivilege 2) Upgrade Windows'
  },
  {
    id: 'printspoofer',
    ov_en: 'PrintSpoofer abuses the Print Spooler service to obtain SYSTEM privileges.',
    vu_en: 'The Print Spooler service allows privileged impersonation.',
    ex_en: 'Exploitation steps: 1) Check privileges 2) Execute PrintSpoofer',
    mi_en: 'Mitigations: 1) Remove SeImpersonatePrivilege 2) Disable Print Spooler service'
  },
  {
    id: 'kernel-exploit',
    ov_en: 'Kernel vulnerabilities can be exploited to directly obtain root privileges.',
    vu_en: 'The kernel code contains exploitable vulnerabilities.',
    ex_en: 'Exploitation steps: 1) Identify kernel version 2) Find a matching exploit 3) Compile and execute',
    mi_en: 'Mitigations: 1) Keep kernel up to date 2) Use SELinux 3) Restrict compilation environments'
  },
  {
    id: 'tunnel-regeorg',
    ov_en: 'ReGeorg establishes a SOCKS proxy tunnel via a web shell.',
    vu_en: 'Scripts can be uploaded and executed on the web server.',
    ex_en: 'Exploitation steps: 1) Upload tunnel script 2) Establish tunnel 3) Access targets through the proxy',
    mi_en: 'Mitigations: 1) Restrict file uploads 2) Monitor anomalous requests'
  },
  {
    id: 'tunnel-ssh-dynamic',
    ov_en: 'SSH dynamic port forwarding creates a SOCKS proxy to reach arbitrary targets.',
    vu_en: 'SSH access can be leveraged to set up a SOCKS proxy.',
    ex_en: 'Exploitation steps: 1) Establish SSH connection 2) Create SOCKS proxy 3) Access targets through the proxy',
    mi_en: 'Mitigations: 1) Restrict SSH port forwarding 2) Monitor SSH connections'
  },
  {
    id: 'tunnel-dns',
    ov_en: 'DNS tunneling uses the DNS protocol to transmit data and bypass firewalls.',
    vu_en: 'DNS traffic is typically permitted through firewalls.',
    ex_en: 'Exploitation steps: 1) Configure domain 2) Start server 3) Connect from client',
    mi_en: 'Mitigations: 1) Restrict DNS queries 2) Monitor anomalous DNS traffic'
  },
  {
    id: 'tunnel-icmp',
    ov_en: 'ICMP tunneling encodes data inside ICMP Echo packets.',
    vu_en: 'ICMP traffic is typically permitted through firewalls.',
    ex_en: 'Exploitation steps: 1) Start server 2) Connect from client 3) Establish tunnel',
    mi_en: 'Mitigations: 1) Restrict ICMP 2) Monitor anomalous ICMP traffic'
  },
  {
    id: 'dcsync-attack',
    ov_en: 'DCSync simulates domain controller replication to harvest all credentials.',
    vu_en: 'The domain replication protocol lacks sufficient authentication verification.',
    ex_en: 'Exploitation steps: 1) Obtain elevated privileges 2) Execute DCSync 3) Retrieve all password hashes',
    mi_en: 'Mitigations: 1) Monitor DCSync activity 2) Principle of least privilege 3) Audit replication rights'
  },
  {
    id: 'golden-ticket',
    ov_en: 'A golden ticket provides persistent access to the entire domain.',
    vu_en: 'The krbtgt password is rarely changed and tickets have long validity periods.',
    ex_en: 'Exploitation steps: 1) Obtain krbtgt hash 2) Forge ticket 3) Maintain persistent access',
    mi_en: 'Mitigations: 1) Rotate krbtgt password regularly 2) Monitor anomalous tickets 3) Use PAM'
  },
  {
    id: 'silver-ticket',
    ov_en: 'A silver ticket targets a specific service and is stealthier than a golden ticket.',
    vu_en: 'Service account passwords can be obtained.',
    ex_en: 'Exploitation steps: 1) Obtain service hash 2) Forge ticket 3) Access the service',
    mi_en: 'Mitigations: 1) Use strong service account passwords 2) Monitor anomalous tickets 3) Rotate passwords regularly'
  },
  {
    id: 'skeleton-key',
    ov_en: 'Skeleton Key injects a master password into memory without affecting the original password.',
    vu_en: 'The domain controller LSASS process can be injected into.',
    ex_en: 'Exploitation steps: 1) Obtain domain admin privileges 2) Access DC 3) Implant backdoor',
    mi_en: 'Mitigations: 1) Protect DCs 2) Monitor LSASS 3) Use Credential Guard'
  },
  {
    id: 'dsrm-backdoor',
    ov_en: 'DSRM is the local administrator account on domain controllers and can serve as a backdoor.',
    vu_en: 'The DSRM account is independent of domain accounts and is often overlooked.',
    ex_en: 'Exploitation steps: 1) Obtain DSRM hash 2) Synchronize password 3) Enable remote login',
    mi_en: 'Mitigations: 1) Monitor DSRM password changes 2) Audit registry settings 3) Perform regular audits'
  },
  {
    id: 'socks-proxy',
    ov_en: 'A SOCKS proxy can tunnel into an internal network to reach additional resources.',
    vu_en: 'An accessible internal network entry point exists.',
    ex_en: 'Exploitation steps: 1) Obtain a pivot host 2) Establish SOCKS proxy 3) Access internal network',
    mi_en: 'Mitigations: 1) Network segmentation 2) Monitor anomalous connections 3) Restrict outbound traffic'
  },
  {
    id: 'tunnel-ngrok',
    ov_en: 'Ngrok exposes internal network services to the public internet.',
    vu_en: 'The internal network can reach the internet.',
    ex_en: 'Exploitation steps: 1) Install Ngrok 2) Create tunnel 3) Access internal services',
    mi_en: 'Mitigations: 1) Monitor outbound connections 2) Block Ngrok domains 3) Network segmentation'
  },
  {
    id: 'adcs-abuse',
    ov_en: 'ADCS can be abused to obtain user certificates for authentication.',
    vu_en: 'Certificate templates are misconfigured.',
    ex_en: 'Exploitation steps: 1) Enumerate ADCS 2) Request certificate 3) Pass-the-Cert',
    mi_en: 'Mitigations: 1) Audit certificate templates 2) Restrict template permissions 3) Monitor certificate requests'
  },
  {
    id: 'adcs-esc1',
    ov_en: 'ESC1 allows specifying an arbitrary Subject Alternative Name (SAN) in a certificate request.',
    vu_en: 'The template permits user-specified SANs and is enabled for client authentication.',
    ex_en: 'Exploitation steps: 1) Identify ESC1-vulnerable template 2) Specify domain admin SAN 3) Obtain domain admin certificate',
    mi_en: 'Mitigations: 1) Disable user-specified SANs 2) Restrict template permissions 3) Monitor certificate requests'
  },
  {
    id: 'constrained-delegation',
    ov_en: 'Constrained delegation allows an account to impersonate users when accessing specific services.',
    vu_en: 'Constrained delegation configurations can be abused.',
    ex_en: 'Exploitation steps: 1) Find delegation-configured account 2) Obtain ticket via S4U 3) Access target service',
    mi_en: 'Mitigations: 1) Audit delegation configurations 2) Use Protected Users group 3) Monitor S4U requests'
  },
  {
    id: 'resource-delegation',
    ov_en: 'Resource-based Constrained Delegation (RBCD) allows configuring delegation from the target object.',
    vu_en: 'Having WriteDACL on an object enables configuring RBCD.',
    ex_en: 'Exploitation steps: 1) Create machine account 2) Configure RBCD 3) Obtain elevated ticket',
    mi_en: 'Mitigations: 1) Audit ACL permissions 2) Protect sensitive objects 3) Monitor RBCD configuration changes'
  },
  {
    id: 'dcshadow-attack',
    ov_en: 'DCShadow can impersonate a DC to inject data into the real DC.',
    vu_en: 'The AD replication mechanism can be abused.',
    ex_en: 'Exploitation steps: 1) Obtain domain admin privileges 2) Register a rogue DC 3) Push malicious data',
    mi_en: 'Mitigations: 1) Monitor DC registrations 2) Audit replication events 3) Protect domain admin accounts'
  },
  {
    id: 'api-unhooking',
    ov_en: 'Endpoint security tools monitor program behavior by hooking API calls.',
    vu_en: 'User-mode hooks can be removed.',
    ex_en: 'Exploitation steps: 1) Load a clean copy of the DLL 2) Overwrite the hooked code 3) Restore original API',
    mi_en: 'Mitigations: 1) Kernel-level monitoring 2) Detect unhooking attempts 3) Multi-layered defenses'
  },
  {
    id: 'proxylogon',
    ov_en: 'ProxyLogon is an SSRF vulnerability in Microsoft Exchange.',
    vu_en: 'The Exchange front-end contains an SSRF vulnerability.',
    ex_en: 'Exploitation steps: 1) Probe Exchange 2) Craft SSRF request 3) Gain access',
    mi_en: 'Mitigations: 1) Apply patches 2) Network segmentation 3) Monitor anomalous requests'
  },
  {
    id: 'proxyshell',
    ov_en: 'ProxyShell is a chained RCE vulnerability in Microsoft Exchange.',
    vu_en: 'Exchange contains SSRF and RCE vulnerabilities.',
    ex_en: 'Exploitation steps: 1) Probe vulnerabilities 2) Obtain access token 3) Execute commands',
    mi_en: 'Mitigations: 1) Apply patches 2) Network segmentation 3) Monitor anomalous requests'
  },
  {
    id: 'exchange-enum',
    ov_en: 'Exchange enumeration can reveal a large amount of information.',
    vu_en: 'Exchange exposes excessive information.',
    ex_en: 'Exploitation steps: 1) Probe version 2) Enumerate users 3) Retrieve configuration',
    mi_en: 'Mitigations: 1) Hide version information 2) Restrict access 3) Monitor anomalous requests'
  },
  {
    id: 'adcs-esc3',
    ov_en: 'ESC3 allows an enrollment agent to request certificates on behalf of other users.',
    vu_en: 'The certificate template allows the enrollment agent capability.',
    ex_en: 'Exploitation steps: 1) Obtain enrollment agent certificate 2) Request certificate on behalf of an admin 3) Use certificate for authentication',
    mi_en: 'Mitigations: 1) Restrict enrollment agent permissions 2) Audit agent certificates 3) Monitor anomalous requests'
  },
  {
    id: 'adcs-esc6',
    ov_en: 'ESC6 allows specifying an arbitrary SAN in a certificate request.',
    vu_en: 'The CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag configured.',
    ex_en: 'Exploitation steps: 1) Probe CA configuration 2) Request a certificate with admin SAN 3) Authenticate',
    mi_en: 'Mitigations: 1) Remove the EDITF_ATTRIBUTESUBJECTALTNAME2 flag 2) Monitor certificate requests 3) Audit CA configuration'
  },
  {
    id: 'adcs-esc8',
    ov_en: 'ESC8 abuses the ADCS HTTP endpoint for NTLM relay attacks.',
    vu_en: 'The ADCS HTTP endpoint supports NTLM authentication without signing enabled.',
    ex_en: 'Exploitation steps: 1) Set up relay server 2) Trigger target authentication 3) Obtain certificate',
    mi_en: 'Mitigations: 1) Enable channel binding 2) Disable HTTP endpoint 3) Enable Extended Protection for Authentication'
  },
  {
    id: 'sam-the-admin',
    ov_en: 'SAM the Admin exploits sAMAccountName spoofing and PAC validation bypass to escalate privileges.',
    vu_en: 'The domain controller is missing the relevant patches.',
    ex_en: 'Exploitation steps: 1) Create machine account 2) Modify sAMAccountName 3) Request TGT 4) Delete account 5) Request S4U2Self',
    mi_en: 'Mitigations: 1) Install KB5008102 patch 2) Monitor anomalous account creation 3) Audit sAMAccountName modifications'
  },
  {
    id: 'noauth',
    ov_en: 'noPac exploits a flaw in Kerberos RC4 encryption validation.',
    vu_en: 'Kerberos RC4 encryption validation contains a flaw.',
    ex_en: 'Exploitation steps: 1) Detect target RC4 key 2) Craft malicious request 3) Obtain TGT',
    mi_en: 'Mitigations: 1) Apply patches 2) Disable RC4 encryption 3) Enforce AES encryption'
  },
  {
    id: 'evasion-ppid-spoof',
    ov_en: 'PPID spoofing falsifies the parent-child relationship of a process.',
    vu_en: 'Windows allows specifying a parent process at creation time.',
    ex_en: 'Exploitation steps: 1) Obtain PID of a legitimate process 2) Specify the parent process when creating the new process 3) Bypass detection',
    mi_en: 'Mitigations: 1) Inspect process trees 2) Monitor anomalous parent-child relationships 3) ETW tracing'
  },
  {
    id: 'evasion-clr-injection',
    ov_en: 'CLR injection allows executing .NET assemblies directly from memory.',
    vu_en: 'The .NET CLR allows dynamic assembly loading.',
    ex_en: 'Exploitation steps: 1) Obtain CLR interface 2) Load assembly 3) Execute code',
    mi_en: 'Mitigations: 1) AMSI monitoring 2) Memory scanning 3) ETW tracing'
  },
  {
    id: 'exchange-mailbox-access',
    ov_en: 'Exchange mailboxes can be accessed via multiple protocols.',
    vu_en: 'Once credentials are obtained, full mailbox control is possible.',
    ex_en: 'Exploitation steps: 1) Obtain credentials 2) Choose access method 3) Access mailbox data',
    mi_en: 'Mitigations: 1) MFA authentication 2) Monitor anomalous logins 3) Audit mailbox access'
  },
  {
    id: 'sharepoint-file-access',
    ov_en: 'SharePoint files can be accessed via multiple methods.',
    vu_en: 'Once credentials are obtained, all authorized documents are accessible.',
    ex_en: 'Exploitation steps: 1) Obtain credentials 2) Access document library 3) Download sensitive files',
    mi_en: 'Mitigations: 1) Least-privilege access 2) Monitor file access 3) Data classification and protection'
  },
  {
    id: 'unattended-creds',
    ov_en: 'Unattended installation files (Unattend.xml) are used for automated Windows deployments and may contain administrator credentials.',
    vu_en: 'Unattend.xml files generated by Windows deployment tools (e.g., MDT, SCCM) store passwords in plaintext or weak encoding (Base64), and these files often remain on the system after deployment.',
    ex_en: 'Exploitation steps: 1) Search for Unattend/Sysprep files in default paths 2) Extract Password/AutoLogon fields 3) Decode Base64 passwords 4) Use obtained credentials for lateral movement',
    mi_en: 'Mitigations: 1) Delete Unattend files immediately after deployment 2) Avoid storing domain admin passwords in Unattend files 3) Use LAPS to manage local administrator passwords 4) Regularly audit for sensitive files'
  },
  {
    id: 'potato-attack',
    ov_en: 'The Potato family of attacks are classic Windows techniques for escalating from a service account to SYSTEM, exploiting token impersonation and NTLM relay.',
    vu_en: 'Windows service accounts (IIS, SQL Server, etc.) have SeImpersonatePrivilege by default. Attackers can use this privilege to coerce SYSTEM account authentication via DCOM or named pipes, then impersonate its token to escalate privileges.',
    ex_en: 'Exploitation steps: 1) Confirm Impersonate privilege with whoami /priv 2) Choose the appropriate Potato tool based on OS version 3) Execute Potato to obtain SYSTEM 4) Proceed with post-exploitation',
    mi_en: 'Mitigations: 1) Least privilege — remove unnecessary SeImpersonatePrivilege 2) Run services with gMSA accounts 3) Monitor anomalous token operations and named pipe creation 4) Keep Windows patched'
  }
];

let n = 0;
for (const t of trans) {
  const row = sel.get(t.id);
  if (!row) continue;
  const p = JSON.parse(row.data);
  if (!p.tutorial) continue;
  if (t.ov_en) p.tutorial.overview = { zh: p.tutorial.overview?.zh || '', en: t.ov_en };
  if (t.vu_en) p.tutorial.vulnerability = { zh: p.tutorial.vulnerability?.zh || '', en: t.vu_en };
  if (t.ex_en) p.tutorial.exploitation = { zh: p.tutorial.exploitation?.zh || '', en: t.ex_en };
  if (t.mi_en) p.tutorial.mitigation = { zh: p.tutorial.mitigation?.zh || '', en: t.mi_en };
  upd.run(JSON.stringify(p), t.id);
  n++;
}
db.close();
console.log('updated:' + n);
