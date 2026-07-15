import type { I18nText, ToolCommand, ToolCommandItem } from '../types';

const toolText = (zh: string, en: string): I18nText => ({ zh, en });

const toolCommand = (
  zhName: string,
  enName: string,
  command: string,
  zhDescription: string,
  enDescription: string,
  platform: ToolCommandItem['platform'] = 'all',
  examples?: string[]
): ToolCommandItem => ({
  name: toolText(zhName, enName),
  command,
  description: toolText(zhDescription, enDescription),
  platform,
  examples: examples?.map(example => toolText(example, example))
});

const systemCategory = toolText('系统命令', 'System Commands');
const adminCategory = toolText('系统管理', 'System Administration');
const blueTeamCategory = toolText('蓝队取证', 'Blue Team & DFIR');
const utilityCategory = toolText('效率工具', 'Utility Tools');

export const osToolCommandExtensions: ToolCommand[] = [
  {
    id: 'linux-command-reference',
    name: toolText('Linux 常用命令总览', 'Linux Command Reference'),
    description: toolText(
      '覆盖 Linux 文件、目录、权限、系统信息、磁盘和基础运维命令，适合课堂实验环境做命令速查。',
      'Broad reference for Linux file, directory, permission, system information, disk, and basic operations commands.'
    ),
    category: systemCategory,
    installation: toolText('Linux 发行版内置命令为主，常见依赖包括 coreutils、findutils、util-linux、procps。', 'Mostly built in on Linux distributions; common packages include coreutils, findutils, util-linux, and procps.'),
    commands: [
      toolCommand('查看当前目录', 'Print working directory', 'pwd', '显示当前 shell 所在目录。', 'Print the current working directory.', 'linux'),
      toolCommand('列出详细文件', 'List detailed files', 'ls -lah', '以人类可读大小列出隐藏文件和详细属性。', 'List hidden files with detailed metadata and human-readable sizes.', 'linux'),
      toolCommand('查看 inode', 'Show inode numbers', 'ls -li', '显示 inode，便于排查硬链接和文件系统问题。', 'Show inode numbers for hard-link and filesystem troubleshooting.', 'linux'),
      toolCommand('切换日志目录', 'Change to log directory', 'cd /var/log', '进入常见系统日志目录。', 'Change into a common system log directory.', 'linux'),
      toolCommand('目录树', 'Directory tree', 'tree -L 2', '按两层深度展示目录结构。', 'Display a directory tree with depth limited to two levels.', 'linux'),
      toolCommand('查找配置文件', 'Find config files', 'find /etc -maxdepth 2 -type f -name "*.conf"', '在 /etc 下查找常见配置文件。', 'Find common configuration files under /etc.', 'linux'),
      toolCommand('定位文件', 'Locate file', 'locate nginx.conf', '使用 locate 数据库快速查找文件路径。', 'Search indexed file paths with locate.', 'linux'),
      toolCommand('文件属性', 'File metadata', 'stat /etc/passwd', '显示文件权限、时间戳、inode 等元数据。', 'Show permissions, timestamps, inode, and other file metadata.', 'linux'),
      toolCommand('识别文件类型', 'Identify file type', 'file sample.bin', '根据魔术字节识别文件类型。', 'Identify file type using magic bytes.', 'linux'),
      toolCommand('创建空文件', 'Create empty file', 'touch notes.txt', '创建空文件或更新时间戳。', 'Create an empty file or update timestamps.', 'linux'),
      toolCommand('创建多级目录', 'Create nested directories', 'mkdir -p labs/output', '创建不存在的父目录和目标目录。', 'Create parent directories and the target directory if missing.', 'linux'),
      toolCommand('保留属性复制', 'Archive copy', 'cp -av source_dir backup_dir', '递归复制并保留权限、时间戳等属性。', 'Copy recursively while preserving permissions and timestamps.', 'linux'),
      toolCommand('同步目录', 'Synchronize directory', 'rsync -avh source/ backup/', '增量同步目录内容，适合备份和迁移实验。', 'Synchronize directories incrementally for backup or migration labs.', 'linux'),
      toolCommand('重命名文件', 'Rename file', 'mv old_name new_name', '移动或重命名文件。', 'Move or rename a file.', 'linux'),
      toolCommand('交互删除', 'Interactive delete', 'rm -i file.txt', '删除前逐项确认，避免误删。', 'Prompt before removing a file to avoid mistakes.', 'linux'),
      toolCommand('创建软链接', 'Create symlink', 'ln -s /opt/app current', '创建指向目标路径的符号链接。', 'Create a symbolic link to a target path.', 'linux'),
      toolCommand('查看归档内容', 'List archive content', 'tar -tf archive.tar.gz', '不解压直接列出 tar 归档内容。', 'List tar archive contents without extracting.', 'linux'),
      toolCommand('创建压缩包', 'Create tarball', 'tar -czf backup.tar.gz folder', '将目录打包为 gzip 压缩 tar 文件。', 'Package a directory into a gzip-compressed tar archive.', 'linux'),
      toolCommand('保留原文件压缩', 'Compress and keep input', 'gzip -k access.log', '压缩文件并保留原始文件。', 'Compress a file while keeping the original input.', 'linux'),
      toolCommand('查看 zip 内容', 'List zip content', 'unzip -l archive.zip', '列出 zip 文件内容但不解压。', 'List zip archive contents without extracting.', 'linux'),
      toolCommand('目录占用', 'Directory usage', 'du -sh *', '查看当前目录下各项磁盘占用。', 'Show disk usage for entries in the current directory.', 'linux'),
      toolCommand('文件系统空间', 'Filesystem space', 'df -hT', '查看挂载文件系统类型和剩余空间。', 'Show mounted filesystem types and free space.', 'linux'),
      toolCommand('块设备', 'Block devices', 'lsblk -f', '查看磁盘、分区、文件系统和 UUID。', 'Show disks, partitions, filesystems, and UUIDs.', 'linux'),
      toolCommand('挂载点表', 'Mount table', 'findmnt', '以树状方式查看挂载关系。', 'Show mount relationships as a tree.', 'linux'),
      toolCommand('修改权限', 'Change mode', 'chmod 640 file.txt', '按最小权限原则设置文件读写权限。', 'Set file permissions with a least-privilege mode.', 'linux'),
      toolCommand('修改属主', 'Change owner', 'chown user:group file.txt', '修改文件属主和属组。', 'Change file owner and group.', 'linux'),
      toolCommand('查看 ACL', 'Read ACL', 'getfacl file.txt', '查看扩展访问控制列表。', 'Show extended access control lists.', 'linux'),
      toolCommand('设置 ACL', 'Set ACL', 'setfacl -m u:student:r file.txt', '为指定用户增加只读 ACL。', 'Grant a read-only ACL entry to a specific user.', 'linux'),
      toolCommand('当前身份', 'Current identity', 'id', '显示当前用户 UID、GID 和组信息。', 'Show the current user UID, GID, and group membership.', 'linux'),
      toolCommand('登录用户', 'Logged-in users', 'who', '查看当前登录会话。', 'Show current login sessions.', 'linux'),
      toolCommand('系统负载概览', 'System load overview', 'w', '查看登录用户、运行命令和系统负载。', 'Show logged-in users, active commands, and load averages.', 'linux'),
      toolCommand('最近登录', 'Recent logins', 'last -n 20', '查看最近 20 条登录记录。', 'Show the latest 20 login records.', 'linux'),
      toolCommand('系统版本', 'OS release', 'cat /etc/os-release', '查看 Linux 发行版信息。', 'Show Linux distribution information.', 'linux'),
      toolCommand('内核版本', 'Kernel version', 'uname -a', '查看内核、架构和主机信息。', 'Show kernel, architecture, and host information.', 'linux'),
      toolCommand('主机信息', 'Host information', 'hostnamectl', '查看主机名、内核、虚拟化和系统版本信息。', 'Show hostname, kernel, virtualization, and OS information.', 'linux'),
      toolCommand('时间配置', 'Time settings', 'timedatectl', '查看时区、NTP 和系统时间状态。', 'Show timezone, NTP, and system clock status.', 'linux'),
      toolCommand('环境变量', 'Environment variables', 'printenv', '列出当前环境变量。', 'List current environment variables.', 'linux'),
      toolCommand('查找可执行文件', 'Find executable', 'command -v python3', '查看命令解析到的实际路径。', 'Show the executable path resolved by the shell.', 'linux'),
      toolCommand('查阅手册', 'Open manual page', 'man ls', '查看命令的本地手册页。', 'Open the local manual page for a command.', 'linux')
    ],
    references: [
      'https://www.gnu.org/software/coreutils/manual/',
      'https://man7.org/linux/man-pages/'
    ]
  },
  {
    id: 'linux-text-processing-reference',
    name: toolText('Linux 文本处理命令', 'Linux Text Processing Commands'),
    description: toolText(
      '覆盖 grep、sed、awk、sort、cut、diff 等常见文本处理命令，适合日志分析、CTF 文本题和运维排查。',
      'Reference for grep, sed, awk, sort, cut, diff, and other text-processing commands used in logs, CTF text tasks, and operations.'
    ),
    category: systemCategory,
    installation: toolText('常见命令来自 coreutils、grep、sed、gawk、diffutils。', 'Common commands come from coreutils, grep, sed, gawk, and diffutils.'),
    commands: [
      toolCommand('查看文件', 'Print file', 'cat file.txt', '输出小文件内容。', 'Print a small file to stdout.', 'linux'),
      toolCommand('分页查看', 'Page file', 'less file.txt', '分页查看大文件。', 'Page through a large file.', 'linux'),
      toolCommand('文件开头', 'File head', 'head -n 20 access.log', '查看文件前 20 行。', 'Show the first 20 lines of a file.', 'linux'),
      toolCommand('文件结尾', 'File tail', 'tail -n 50 access.log', '查看文件最后 50 行。', 'Show the last 50 lines of a file.', 'linux'),
      toolCommand('实时跟踪', 'Follow file', 'tail -f app.log', '实时观察追加写入的日志。', 'Follow appended log lines in real time.', 'linux'),
      toolCommand('统计行词字节', 'Count lines words bytes', 'wc -lwm file.txt', '统计行数、词数和字符数。', 'Count lines, words, and characters.', 'linux'),
      toolCommand('排序', 'Sort lines', 'sort names.txt', '按字典序排序文本行。', 'Sort lines lexicographically.', 'linux'),
      toolCommand('去重计数', 'Count unique lines', 'sort access.log | uniq -c | sort -nr', '统计重复行频次并倒序排序。', 'Count repeated lines and sort by frequency.', 'linux'),
      toolCommand('提取字段', 'Cut field', 'cut -d "," -f 1,3 data.csv', '从 CSV 中提取指定字段。', 'Extract selected fields from CSV-like text.', 'linux'),
      toolCommand('合并列', 'Paste columns', 'paste users.txt scores.txt', '按行合并多个文件的列。', 'Merge files line by line as columns.', 'linux'),
      toolCommand('字符转换', 'Translate chars', 'tr "[:lower:]" "[:upper:]" < input.txt', '将小写字符转换为大写。', 'Translate lowercase characters to uppercase.', 'linux'),
      toolCommand('正则过滤', 'Regex filter', 'grep -RIn "error" logs/', '递归搜索匹配行并显示行号。', 'Search recursively with line numbers.', 'linux'),
      toolCommand('反向过滤', 'Invert match', 'grep -v "^#" config.conf', '过滤掉注释行。', 'Exclude comment lines.', 'linux'),
      toolCommand('sed 替换', 'Sed replace', 'sed "s/old/new/g" file.txt', '替换文本中的匹配内容。', 'Replace matching text.', 'linux'),
      toolCommand('sed 打印范围', 'Sed print range', 'sed -n "10,30p" file.txt', '打印指定行范围。', 'Print a selected line range.', 'linux'),
      toolCommand('awk 字段统计', 'Awk field count', 'awk -F "," "{count[$1]++} END {for (k in count) print k,count[k]}" data.csv', '按第一列统计出现次数。', 'Count occurrences grouped by the first column.', 'linux'),
      toolCommand('xargs 批处理', 'Batch with xargs', 'printf "%s\\n" *.log | xargs -r wc -l', '将输入批量传给后续命令。', 'Pass input items to another command in batches.', 'linux'),
      toolCommand('同时输出和保存', 'Tee output', 'command | tee output.txt', '将输出同时显示在终端并写入文件。', 'Display output and save it to a file at the same time.', 'linux'),
      toolCommand('统一 diff', 'Unified diff', 'diff -u old.txt new.txt', '生成便于审阅的统一 diff。', 'Generate a unified diff for review.', 'linux'),
      toolCommand('比较排序文件', 'Compare sorted files', 'comm -3 <(sort a.txt) <(sort b.txt)', '比较两个排序后的文件差异。', 'Compare differences between two sorted files.', 'linux'),
      toolCommand('按列对齐', 'Column align', 'column -t -s "," data.csv', '按分隔符将文本对齐成表格。', 'Align delimited text into columns.', 'linux'),
      toolCommand('编码转换', 'Convert encoding', 'iconv -f gbk -t utf-8 input.txt > output.txt', '转换文本编码。', 'Convert text encoding.', 'linux'),
      toolCommand('Base64 编码', 'Base64 encode', 'base64 input.bin > input.b64', '将二进制或文本编码为 Base64。', 'Encode binary or text content as Base64.', 'linux'),
      toolCommand('Base64 解码', 'Base64 decode', 'base64 -d input.b64 > output.bin', '将 Base64 还原为原始数据。', 'Decode Base64 back to raw data.', 'linux'),
      toolCommand('十六进制视图', 'Hex view', 'xxd -g 1 -l 128 sample.bin', '查看文件前 128 字节的十六进制内容。', 'View the first 128 bytes as hex.', 'linux'),
      toolCommand('提取可见字符串', 'Extract strings', 'strings -a sample.bin | head', '从二进制文件中提取可见字符串。', 'Extract printable strings from a binary file.', 'linux'),
      toolCommand('拆分大文件', 'Split file', 'split -b 100M large.bin part-', '按大小拆分大文件。', 'Split a large file by size.', 'linux')
    ],
    references: [
      'https://www.gnu.org/software/coreutils/manual/',
      'https://www.gnu.org/software/sed/manual/',
      'https://www.gnu.org/software/gawk/manual/'
    ]
  },
  {
    id: 'linux-process-service-reference',
    name: toolText('Linux 进程与服务排查', 'Linux Process & Service Diagnostics'),
    description: toolText(
      '覆盖进程、资源、systemd、journalctl 和常见性能观察命令，适合定位卡顿、服务异常和日志问题。',
      'Process, resource, systemd, journalctl, and performance observation commands for diagnosing slowness and service issues.'
    ),
    category: adminCategory,
    installation: toolText('常见依赖包括 procps、psmisc、sysstat、lsof、systemd。', 'Common dependencies include procps, psmisc, sysstat, lsof, and systemd.'),
    commands: [
      toolCommand('进程快照', 'Process snapshot', 'ps aux --sort=-%cpu | head', '按 CPU 占用查看进程。', 'Show processes sorted by CPU usage.', 'linux'),
      toolCommand('进程树', 'Process tree', 'pstree -ap', '以树状结构查看父子进程关系。', 'Show parent-child process relationships.', 'linux'),
      toolCommand('查找进程', 'Find process', 'pgrep -af nginx', '按名称查找进程及命令行。', 'Find processes and command lines by name.', 'linux'),
      toolCommand('交互监控', 'Interactive monitor', 'top', '实时查看 CPU、内存和进程状态。', 'Monitor CPU, memory, and processes interactively.', 'linux'),
      toolCommand('内存概览', 'Memory overview', 'free -h', '查看内存和 swap 使用情况。', 'Show memory and swap usage.', 'linux'),
      toolCommand('系统运行时间', 'Uptime', 'uptime', '查看运行时间和平均负载。', 'Show uptime and load averages.', 'linux'),
      toolCommand('虚拟内存统计', 'Virtual memory stats', 'vmstat 1 5', '按 1 秒间隔采样 CPU、内存、IO 状态。', 'Sample CPU, memory, and IO state every second.', 'linux'),
      toolCommand('磁盘 IO', 'Disk IO stats', 'iostat -xz 1 5', '观察磁盘延迟、利用率和吞吐。', 'Observe disk latency, utilization, and throughput.', 'linux'),
      toolCommand('进程 IO', 'Process IO stats', 'pidstat -d 1 5', '按进程观察 IO 活动。', 'Observe per-process IO activity.', 'linux'),
      toolCommand('打开文件', 'Open files', 'lsof -p PID', '查看进程打开的文件和 socket。', 'Show files and sockets opened by a process.', 'linux'),
      toolCommand('端口占用进程', 'Process using port', 'lsof -i :8080', '查看占用指定端口的进程。', 'Show the process using a specific port.', 'linux'),
      toolCommand('服务状态', 'Service status', 'systemctl status nginx', '查看 systemd 服务状态和最近日志。', 'Show service status and recent logs.', 'linux'),
      toolCommand('失败服务', 'Failed services', 'systemctl --failed', '列出启动失败的服务单元。', 'List failed systemd units.', 'linux'),
      toolCommand('服务单元文件', 'Service unit file', 'systemctl cat nginx', '查看服务单元合并后的配置。', 'Show the merged systemd unit configuration.', 'linux'),
      toolCommand('列出服务', 'List services', 'systemctl list-units --type=service --state=running', '列出正在运行的服务。', 'List running services.', 'linux'),
      toolCommand('列出定时器', 'List timers', 'systemctl list-timers --all', '查看 systemd timer 计划任务。', 'Show systemd timer schedules.', 'linux'),
      toolCommand('服务日志', 'Service logs', 'journalctl -u nginx --since "1 hour ago"', '查看最近一小时服务日志。', 'Show service logs from the last hour.', 'linux'),
      toolCommand('本次启动告警', 'Current boot warnings', 'journalctl -p warning -b', '查看本次启动以来 warning 及以上日志。', 'Show warning-or-higher logs from the current boot.', 'linux'),
      toolCommand('日志占用', 'Journal disk usage', 'journalctl --disk-usage', '查看 journald 日志占用空间。', 'Show disk usage of the systemd journal.', 'linux'),
      toolCommand('内核日志', 'Kernel logs', 'dmesg -T | tail -n 50', '查看最近内核日志。', 'Show recent kernel logs with human-readable timestamps.', 'linux'),
      toolCommand('定时任务', 'User crontab', 'crontab -l', '查看当前用户 crontab。', 'Show the current user crontab.', 'linux'),
      toolCommand('系统定时目录', 'System cron dirs', 'ls -lah /etc/cron.*', '查看系统 cron 目录。', 'List system cron directories.', 'linux'),
      toolCommand('会话列表', 'Login sessions', 'loginctl list-sessions', '查看 systemd-logind 会话。', 'List login sessions.', 'linux'),
      toolCommand('启动耗时', 'Boot timing', 'systemd-analyze blame | head', '查看启动耗时最高的单元。', 'Show units contributing most to boot time.', 'linux')
    ],
    references: [
      'https://www.freedesktop.org/software/systemd/man/latest/systemctl.html',
      'https://www.freedesktop.org/software/systemd/man/latest/journalctl.html'
    ]
  },
  {
    id: 'linux-network-reference',
    name: toolText('Linux 网络与防火墙排查', 'Linux Network & Firewall Diagnostics'),
    description: toolText(
      '覆盖 ip、ss、dig、curl、tcpdump、iptables/nftables 等网络连通性和防火墙排查命令。',
      'Network connectivity and firewall diagnostics with ip, ss, dig, curl, tcpdump, iptables, and nftables.'
    ),
    category: adminCategory,
    installation: toolText('常见依赖包括 iproute2、bind-utils/dnsutils、curl、tcpdump、mtr、openssl。', 'Common dependencies include iproute2, bind-utils/dnsutils, curl, tcpdump, mtr, and openssl.'),
    commands: [
      toolCommand('IP 地址', 'IP addresses', 'ip addr show', '查看网卡地址和状态。', 'Show interface addresses and state.', 'linux'),
      toolCommand('路由表', 'Routes', 'ip route show', '查看内核路由表。', 'Show the kernel routing table.', 'linux'),
      toolCommand('邻居表', 'Neighbor table', 'ip neigh show', '查看 ARP/ND 邻居缓存。', 'Show ARP/ND neighbor cache.', 'linux'),
      toolCommand('接口统计', 'Interface stats', 'ip -s link', '查看网卡收发包和错误计数。', 'Show interface packet and error counters.', 'linux'),
      toolCommand('监听端口', 'Listening ports', 'ss -lntup', '查看监听端口及关联进程。', 'Show listening ports and related processes.', 'linux'),
      toolCommand('连接状态统计', 'Socket summary', 'ss -s', '汇总 TCP/UDP socket 状态。', 'Summarize TCP and UDP socket states.', 'linux'),
      toolCommand('连通性测试', 'Ping test', 'ping -c 4 8.8.8.8', '发送 4 个 ICMP 包测试连通性。', 'Send four ICMP packets to test connectivity.', 'linux'),
      toolCommand('路由跟踪', 'Traceroute', 'traceroute example.com', '查看到目标的网络路径。', 'Trace the network path to a target.', 'linux'),
      toolCommand('连续路由质量', 'MTR report', 'mtr -rw example.com', '生成延迟和丢包报告。', 'Generate a latency and packet-loss route report.', 'linux'),
      toolCommand('DNS 查询', 'DNS lookup', 'dig example.com A +short', '查询 A 记录。', 'Query A records.', 'linux'),
      toolCommand('DNS 配置', 'Resolver status', 'resolvectl status', '查看 systemd-resolved DNS 配置。', 'Show systemd-resolved DNS configuration.', 'linux'),
      toolCommand('HTTP 头', 'HTTP headers', 'curl -I https://example.com', '只请求响应头，验证 HTTP 服务可达性。', 'Request only response headers to verify HTTP reachability.', 'linux'),
      toolCommand('证书握手', 'TLS handshake', 'openssl s_client -connect example.com:443 -servername example.com', '查看 TLS 握手和证书链。', 'Inspect TLS handshake and certificate chain.', 'linux'),
      toolCommand('端口探测', 'TCP port check', 'nc -vz example.com 443', '检查 TCP 端口是否可连接。', 'Check whether a TCP port is reachable.', 'linux'),
      toolCommand('抓包预览', 'Packet capture sample', 'tcpdump -i any -nn -c 20', '抓取 20 个包用于排查网络问题。', 'Capture 20 packets for network troubleshooting.', 'linux'),
      toolCommand('过滤 HTTP 抓包', 'HTTP packet filter', 'tcpdump -i any -nn port 80 -c 50', '按端口过滤抓包样本。', 'Capture a port-filtered packet sample.', 'linux'),
      toolCommand('iptables 规则', 'iptables rules', 'iptables -S', '查看 iptables 规则。', 'Show iptables rules.', 'linux'),
      toolCommand('nftables 规则', 'nftables rules', 'nft list ruleset', '查看 nftables 规则集。', 'Show nftables ruleset.', 'linux'),
      toolCommand('UFW 状态', 'UFW status', 'ufw status verbose', '查看 UFW 防火墙策略。', 'Show UFW firewall policy.', 'linux'),
      toolCommand('firewalld 状态', 'firewalld status', 'firewall-cmd --list-all', '查看 firewalld 当前区域规则。', 'Show current firewalld zone rules.', 'linux'),
      toolCommand('网卡能力', 'Interface capabilities', 'ethtool eth0', '查看网卡速率、双工和链路状态。', 'Show link speed, duplex, and interface capabilities.', 'linux'),
      toolCommand('NetworkManager 状态', 'NetworkManager status', 'nmcli device status', '查看 NetworkManager 设备状态。', 'Show NetworkManager device state.', 'linux'),
      toolCommand('域名信息', 'Domain registration info', 'whois example.com', '查询域名注册信息，适合 OSINT 基础教学。', 'Query domain registration information for basic OSINT lessons.', 'linux')
    ],
    references: [
      'https://man7.org/linux/man-pages/',
      'https://curl.se/docs/manpage.html',
      'https://www.tcpdump.org/manpages/tcpdump.1.html'
    ]
  },
  {
    id: 'linux-package-container-reference',
    name: toolText('Linux 包管理与容器命令', 'Linux Package & Container Commands'),
    description: toolText(
      '覆盖主流 Linux 包管理器、Docker、Podman、Kubernetes 和 Helm 的只读排查与实验命令。',
      'Read-oriented package manager, Docker, Podman, Kubernetes, and Helm commands for troubleshooting and labs.'
    ),
    category: adminCategory,
    installation: toolText('按发行版安装 apt/dnf/yum/pacman/zypper/apk；容器命令依赖 Docker、Podman、kubectl、Helm。', 'Install package managers by distribution; container commands depend on Docker, Podman, kubectl, and Helm.'),
    commands: [
      toolCommand('APT 已安装包', 'APT installed packages', 'apt list --installed', '列出 Debian/Ubuntu 已安装包。', 'List installed packages on Debian/Ubuntu.', 'linux'),
      toolCommand('APT 包策略', 'APT package policy', 'apt-cache policy nginx', '查看包版本来源和候选版本。', 'Show package sources and candidate versions.', 'linux'),
      toolCommand('DPKG 文件归属', 'DPKG file owner', 'dpkg -S /usr/bin/curl', '查询文件属于哪个 Debian 包。', 'Find which Debian package owns a file.', 'linux'),
      toolCommand('DNF 包信息', 'DNF package info', 'dnf info nginx', '查看 RHEL/Fedora 包信息。', 'Show package information on RHEL/Fedora.', 'linux'),
      toolCommand('DNF 历史', 'DNF history', 'dnf history', '查看包管理操作历史。', 'Show package manager transaction history.', 'linux'),
      toolCommand('YUM 仓库', 'YUM repositories', 'yum repolist', '列出启用的软件仓库。', 'List enabled repositories.', 'linux'),
      toolCommand('RPM 包列表', 'RPM packages', 'rpm -qa | sort', '列出 RPM 已安装包。', 'List installed RPM packages.', 'linux'),
      toolCommand('Pacman 搜索', 'Pacman search', 'pacman -Qs nginx', '搜索 Arch 已安装包。', 'Search installed packages on Arch.', 'linux'),
      toolCommand('Zypper 搜索', 'Zypper search', 'zypper se nginx', '搜索 openSUSE 软件包。', 'Search packages on openSUSE.', 'linux'),
      toolCommand('APK 包列表', 'APK packages', 'apk info', '列出 Alpine 已安装包。', 'List installed packages on Alpine.', 'linux'),
      toolCommand('Snap 列表', 'Snap list', 'snap list', '列出 Snap 包。', 'List installed Snap packages.', 'linux'),
      toolCommand('Flatpak 列表', 'Flatpak list', 'flatpak list', '列出 Flatpak 应用。', 'List installed Flatpak applications.', 'linux'),
      toolCommand('Docker 容器', 'Docker containers', 'docker ps --format "table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}"', '以表格展示运行中的容器。', 'Show running containers in a compact table.', 'linux'),
      toolCommand('Docker 镜像', 'Docker images', 'docker images', '列出本地镜像。', 'List local images.', 'linux'),
      toolCommand('Docker 详细信息', 'Docker inspect', 'docker inspect container_name', '查看容器或镜像元数据。', 'Inspect container or image metadata.', 'linux'),
      toolCommand('Docker 日志', 'Docker logs', 'docker logs --tail 100 container_name', '查看容器最近日志。', 'Show recent container logs.', 'linux'),
      toolCommand('Docker 资源', 'Docker stats', 'docker stats --no-stream', '查看容器资源占用快照。', 'Show a snapshot of container resource usage.', 'linux'),
      toolCommand('Compose 状态', 'Docker Compose ps', 'docker compose ps', '查看 Compose 服务状态。', 'Show Docker Compose service state.', 'linux'),
      toolCommand('Podman 容器', 'Podman containers', 'podman ps --format "{{.Names}} {{.Image}} {{.Status}}"', '查看 Podman 运行容器。', 'Show running Podman containers.', 'linux'),
      toolCommand('Kubernetes Pod', 'Kubernetes pods', 'kubectl get pods -A -o wide', '跨命名空间查看 Pod 和节点信息。', 'Show pods and node placement across namespaces.', 'linux'),
      toolCommand('Kubernetes 事件', 'Kubernetes events', 'kubectl get events -A --sort-by=.lastTimestamp', '按时间排序查看集群事件。', 'Show cluster events sorted by time.', 'linux'),
      toolCommand('Kubernetes 日志', 'Kubernetes logs', 'kubectl logs -n default deploy/app --tail=100', '查看工作负载最近日志。', 'Show recent workload logs.', 'linux'),
      toolCommand('Helm 发布', 'Helm releases', 'helm list -A', '列出所有命名空间 Helm 发布。', 'List Helm releases across namespaces.', 'linux')
    ],
    references: [
      'https://docs.docker.com/reference/',
      'https://kubernetes.io/docs/reference/kubectl/',
      'https://helm.sh/docs/helm/'
    ]
  },
  {
    id: 'windows-cmd-reference',
    name: toolText('Windows CMD 命令总览', 'Windows CMD Command Reference'),
    description: toolText(
      '覆盖 Windows 命令提示符中的文件、网络、进程、服务、计划任务、日志和系统信息命令。',
      'Reference for Windows Command Prompt file, network, process, service, scheduled task, log, and system information commands.'
    ),
    category: systemCategory,
    installation: toolText('Windows 10/11 与 Windows Server 内置。', 'Built into Windows 10/11 and Windows Server.'),
    commands: [
      toolCommand('命令帮助', 'Command help', 'help', '列出 CMD 内置命令帮助入口。', 'List built-in CMD command help.', 'windows'),
      toolCommand('指定命令帮助', 'Specific command help', 'ipconfig /?', '查看指定命令参数说明。', 'Show help for a specific command.', 'windows'),
      toolCommand('当前目录', 'Current directory', 'cd', '显示当前目录。', 'Print current directory.', 'windows'),
      toolCommand('目录列表', 'Directory listing', 'dir /a /q', '列出隐藏文件和文件所有者。', 'List hidden files and file owners.', 'windows'),
      toolCommand('目录树', 'Directory tree', 'tree /f', '展示目录树和文件。', 'Show directory tree with files.', 'windows'),
      toolCommand('查找命令路径', 'Find command path', 'where powershell', '查找可执行文件路径。', 'Find executable paths.', 'windows'),
      toolCommand('输出文件', 'Print file', 'type file.txt', '输出文本文件内容。', 'Print a text file.', 'windows'),
      toolCommand('分页查看', 'Page output', 'more file.txt', '分页查看文本。', 'Page through text output.', 'windows'),
      toolCommand('搜索文本', 'Search text', 'findstr /spin /c:"error" *.log', '递归搜索日志中的文本。', 'Search logs recursively for text.', 'windows'),
      toolCommand('比较文件', 'Compare text files', 'fc file1.txt file2.txt', '比较两个文本文件差异。', 'Compare two text files.', 'windows'),
      toolCommand('稳健复制', 'Robust copy', 'robocopy source backup /E /COPY:DAT /R:1 /W:1', '复制目录并保留数据、属性和时间戳。', 'Copy directories while preserving data, attributes, and timestamps.', 'windows'),
      toolCommand('文件属性', 'File attributes', 'attrib file.txt', '查看文件属性。', 'Show file attributes.', 'windows'),
      toolCommand('文件 ACL', 'File ACL', 'icacls file.txt', '查看 NTFS 权限。', 'Show NTFS permissions.', 'windows'),
      toolCommand('文件哈希', 'File hash', 'certutil -hashfile file.exe SHA256', '计算文件 SHA256。', 'Calculate a file SHA256 hash.', 'windows'),
      toolCommand('系统信息', 'System information', 'systeminfo', '查看系统版本、补丁和硬件摘要。', 'Show OS version, patches, and hardware summary.', 'windows'),
      toolCommand('主机名', 'Hostname', 'hostname', '显示计算机名。', 'Print computer name.', 'windows'),
      toolCommand('当前用户', 'Current user', 'whoami /all', '查看当前用户、组和权限标识。', 'Show current user, groups, and privileges.', 'windows'),
      toolCommand('环境变量', 'Environment variables', 'set', '列出当前环境变量。', 'List environment variables.', 'windows'),
      toolCommand('PATH', 'PATH value', 'echo %PATH%', '显示 PATH 搜索路径。', 'Print PATH search paths.', 'windows'),
      toolCommand('网络配置', 'Network config', 'ipconfig /all', '查看 IP、DNS、网关和网卡信息。', 'Show IP, DNS, gateway, and adapter information.', 'windows'),
      toolCommand('连通性测试', 'Ping', 'ping -n 4 8.8.8.8', '发送 4 个 ICMP 包测试连通性。', 'Send four ICMP packets to test connectivity.', 'windows'),
      toolCommand('路由跟踪', 'Trace route', 'tracert example.com', '查看到目标的网络路径。', 'Trace the network path to a target.', 'windows'),
      toolCommand('路径质量', 'Path quality', 'pathping example.com', '结合路由跟踪和丢包统计。', 'Combine route tracing and packet-loss statistics.', 'windows'),
      toolCommand('DNS 查询', 'DNS lookup', 'nslookup example.com', '查询域名解析结果。', 'Query DNS resolution results.', 'windows'),
      toolCommand('路由表', 'Route table', 'route print', '查看 IPv4/IPv6 路由表。', 'Show IPv4/IPv6 route table.', 'windows'),
      toolCommand('ARP 缓存', 'ARP cache', 'arp -a', '查看邻居缓存。', 'Show neighbor cache.', 'windows'),
      toolCommand('网络连接', 'Network connections', 'netstat -ano', '查看连接、监听端口和 PID。', 'Show connections, listening ports, and PIDs.', 'windows'),
      toolCommand('进程列表', 'Task list', 'tasklist /v', '查看进程和窗口标题。', 'Show processes and window titles.', 'windows'),
      toolCommand('进程服务映射', 'Task services', 'tasklist /svc', '查看进程关联服务。', 'Show services hosted by processes.', 'windows'),
      toolCommand('服务列表', 'Service query', 'sc query type= service state= all', '列出服务状态。', 'List service states.', 'windows'),
      toolCommand('服务配置', 'Service config', 'sc qc Spooler', '查看服务启动配置。', 'Show service startup configuration.', 'windows'),
      toolCommand('驱动列表', 'Driver query', 'driverquery /v', '查看驱动程序信息。', 'Show driver information.', 'windows'),
      toolCommand('计划任务', 'Scheduled tasks', 'schtasks /query /fo LIST /v', '查看计划任务详情。', 'Show scheduled task details.', 'windows'),
      toolCommand('事件日志列表', 'Event log list', 'wevtutil el', '列出事件日志通道。', 'List event log channels.', 'windows'),
      toolCommand('最近系统日志', 'Recent system events', 'wevtutil qe System /c:20 /f:text', '查看最近 20 条系统事件。', 'Show the latest 20 System events.', 'windows'),
      toolCommand('审计策略', 'Audit policy', 'auditpol /get /category:*', '查看本机审计策略。', 'Show local audit policy.', 'windows'),
      toolCommand('组策略结果', 'Group policy result', 'gpresult /r', '查看当前用户/计算机组策略摘要。', 'Show user and computer Group Policy summary.', 'windows'),
      toolCommand('磁盘卷', 'Volumes', 'wmic logicaldisk get Caption,FileSystem,FreeSpace,Size,VolumeName', '查看卷、文件系统和空间。', 'Show volumes, filesystems, and space.', 'windows'),
      toolCommand('补丁列表', 'Hotfixes', 'wmic qfe list brief', '查看已安装补丁。', 'Show installed hotfixes.', 'windows')
    ],
    references: ['https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands']
  },
  {
    id: 'powershell-admin-reference',
    name: toolText('PowerShell 管理命令', 'PowerShell Administration Commands'),
    description: toolText(
      '覆盖 PowerShell 帮助、对象管道、文件、网络、事件日志、服务、进程和系统基线查询命令。',
      'PowerShell help, object pipeline, file, network, event log, service, process, and baseline query commands.'
    ),
    category: systemCategory,
    installation: toolText('Windows PowerShell 内置；PowerShell 7 可从 Microsoft 安装。', 'Windows PowerShell is built in; PowerShell 7 can be installed from Microsoft.'),
    commands: [
      toolCommand('查找命令', 'Find commands', 'Get-Command *Service*', '按名称搜索可用命令。', 'Search available commands by name.', 'windows'),
      toolCommand('查看帮助', 'Get help', 'Get-Help Get-Process -Full', '查看命令完整帮助。', 'Show full command help.', 'windows'),
      toolCommand('查看示例', 'Help examples', 'Get-Help Get-WinEvent -Examples', '查看命令示例。', 'Show command examples.', 'windows'),
      toolCommand('对象成员', 'Object members', 'Get-Process | Get-Member', '查看管道对象属性和方法。', 'Inspect pipeline object properties and methods.', 'windows'),
      toolCommand('筛选对象', 'Filter objects', 'Get-Service | Where-Object Status -eq Running', '筛选正在运行的服务。', 'Filter running services.', 'windows'),
      toolCommand('选择字段', 'Select fields', 'Get-Process | Select-Object Name,Id,CPU -First 10', '选择对象字段。', 'Select object fields.', 'windows'),
      toolCommand('排序对象', 'Sort objects', 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 10', '按 CPU 占用排序。', 'Sort processes by CPU usage.', 'windows'),
      toolCommand('导出 CSV', 'Export CSV', 'Get-Service | Export-Csv services.csv -NoTypeInformation', '导出结构化 CSV。', 'Export structured CSV.', 'windows'),
      toolCommand('导出 JSON', 'Export JSON', 'Get-Process | Select-Object -First 5 | ConvertTo-Json', '将对象转换为 JSON。', 'Convert objects to JSON.', 'windows'),
      toolCommand('递归列目录', 'Recursive listing', 'Get-ChildItem -Force -Recurse -Depth 2', '递归查看目录内容。', 'List directory content recursively.', 'windows'),
      toolCommand('搜索文本', 'Search text', 'Select-String -Path *.log -Pattern "error"', '搜索文件中的文本。', 'Search text in files.', 'windows'),
      toolCommand('跟踪日志', 'Follow log', 'Get-Content .\\app.log -Tail 100 -Wait', '跟踪追加写入的日志。', 'Follow appended log lines.', 'windows'),
      toolCommand('文件哈希', 'File hash', 'Get-FileHash .\\file.exe -Algorithm SHA256', '计算文件哈希。', 'Calculate a file hash.', 'windows'),
      toolCommand('签名状态', 'Authenticode signature', 'Get-AuthenticodeSignature .\\file.exe', '查看文件 Authenticode 签名。', 'Inspect Authenticode signature status.', 'windows'),
      toolCommand('访问控制', 'ACL', 'Get-Acl .\\file.txt | Format-List', '查看文件 ACL。', 'Show file ACL.', 'windows'),
      toolCommand('进程列表', 'Processes', 'Get-Process', '查看进程。', 'List processes.', 'windows'),
      toolCommand('进程详情', 'Process details', 'Get-Process -Id PID | Format-List *', '查看指定进程详情。', 'Show details for a process.', 'windows'),
      toolCommand('服务列表', 'Services', 'Get-Service', '查看服务。', 'List services.', 'windows'),
      toolCommand('服务配置', 'Service config', 'Get-CimInstance Win32_Service | Select-Object Name,StartMode,State,PathName', '查看服务启动模式和路径。', 'Show service startup mode and executable path.', 'windows'),
      toolCommand('系统信息', 'Computer info', 'Get-ComputerInfo', '查看系统硬件和 OS 信息。', 'Show system hardware and OS information.', 'windows'),
      toolCommand('操作系统 CIM', 'OS CIM', 'Get-CimInstance Win32_OperatingSystem', '查询操作系统 CIM 信息。', 'Query OS information through CIM.', 'windows'),
      toolCommand('磁盘 CIM', 'Disk CIM', 'Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,FileSystem,FreeSpace,Size', '查看逻辑磁盘空间。', 'Show logical disk space.', 'windows'),
      toolCommand('补丁列表', 'Hotfixes', 'Get-HotFix', '查看系统补丁。', 'List installed hotfixes.', 'windows'),
      toolCommand('网络适配器', 'Network adapters', 'Get-NetAdapter', '查看网卡状态。', 'Show network adapter state.', 'windows'),
      toolCommand('IP 配置', 'IP configuration', 'Get-NetIPConfiguration', '查看 IP、DNS 和网关。', 'Show IP, DNS, and gateway configuration.', 'windows'),
      toolCommand('TCP 连接', 'TCP connections', 'Get-NetTCPConnection | Select-Object -First 20', '查看 TCP 连接。', 'Show TCP connections.', 'windows'),
      toolCommand('端口连通性', 'Port connectivity', 'Test-NetConnection example.com -Port 443', '测试 TCP 端口连通性。', 'Test TCP port connectivity.', 'windows'),
      toolCommand('DNS 解析', 'DNS resolve', 'Resolve-DnsName example.com', '解析 DNS 记录。', 'Resolve DNS records.', 'windows'),
      toolCommand('事件日志', 'Event logs', 'Get-WinEvent -LogName System -MaxEvents 20', '读取最近系统事件。', 'Read recent System events.', 'windows'),
      toolCommand('事件筛选', 'Filtered events', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624; StartTime=(Get-Date).AddDays(-1)}', '按事件 ID 和时间筛选日志。', 'Filter events by ID and time.', 'windows'),
      toolCommand('本地用户', 'Local users', 'Get-LocalUser', '查看本地用户。', 'List local users.', 'windows'),
      toolCommand('管理员组成员', 'Administrators members', 'Get-LocalGroupMember Administrators', '查看本地管理员组成员。', 'Show local Administrators group members.', 'windows'),
      toolCommand('计划任务', 'Scheduled tasks', 'Get-ScheduledTask | Select-Object TaskName,State,TaskPath', '查看计划任务状态。', 'Show scheduled task state.', 'windows'),
      toolCommand('启动项', 'Startup commands', 'Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location', '查看系统启动项。', 'Show startup commands.', 'windows'),
      toolCommand('Defender 状态', 'Defender status', 'Get-MpComputerStatus', '查看 Microsoft Defender 保护状态。', 'Show Microsoft Defender protection status.', 'windows')
    ],
    references: [
      'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-command',
      'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-help'
    ]
  },
  {
    id: 'windows-event-network-reference',
    name: toolText('Windows 日志、网络与防火墙查询', 'Windows Event, Network & Firewall Queries'),
    description: toolText(
      '面向防守和运维的 Windows 事件日志、网络配置、防火墙、SMB、BitLocker 和基线查询命令。',
      'Defensive Windows event log, network configuration, firewall, SMB, BitLocker, and baseline query commands.'
    ),
    category: blueTeamCategory,
    installation: toolText('Windows 10/11、Windows Server 和 PowerShell NetSecurity 模块。', 'Windows 10/11, Windows Server, and the PowerShell NetSecurity module.'),
    commands: [
      toolCommand('事件通道', 'Event channels', 'wevtutil el', '列出事件日志通道。', 'List event log channels.', 'windows'),
      toolCommand('日志配置', 'Log configuration', 'wevtutil gli Security', '查看指定日志通道配置。', 'Show configuration for an event log channel.', 'windows'),
      toolCommand('安全登录事件', 'Security logons', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 20', '查看最近成功登录事件。', 'Show recent successful logon events.', 'windows'),
      toolCommand('登录失败事件', 'Failed logons', 'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 20', '查看最近登录失败事件。', 'Show recent failed logon events.', 'windows'),
      toolCommand('服务安装事件', 'Service install events', 'Get-WinEvent -FilterHashtable @{LogName="System"; Id=7045} -MaxEvents 20', '查看最近服务安装事件。', 'Show recent service installation events.', 'windows'),
      toolCommand('PowerShell 日志', 'PowerShell events', 'Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 20', '查看 Windows PowerShell 日志。', 'Show Windows PowerShell event logs.', 'windows'),
      toolCommand('防火墙配置文件', 'Firewall profiles', 'Get-NetFirewallProfile', '查看防火墙配置文件状态。', 'Show firewall profile state.', 'windows'),
      toolCommand('防火墙规则', 'Firewall rules', 'Get-NetFirewallRule | Select-Object DisplayName,Enabled,Direction,Action -First 30', '查看防火墙规则摘要。', 'Show firewall rule summary.', 'windows'),
      toolCommand('netsh 防火墙', 'netsh firewall', 'netsh advfirewall show allprofiles', '用 netsh 查看防火墙配置文件。', 'Show firewall profiles through netsh.', 'windows'),
      toolCommand('网卡详细配置', 'Adapter IP details', 'Get-NetIPConfiguration -Detailed', '查看网卡 IP、DNS、网关等详细信息。', 'Show detailed adapter IP, DNS, and gateway information.', 'windows'),
      toolCommand('DNS 服务器', 'DNS servers', 'Get-DnsClientServerAddress', '查看 DNS 服务器配置。', 'Show DNS server configuration.', 'windows'),
      toolCommand('DNS 缓存', 'DNS cache', 'Get-DnsClientCache | Select-Object -First 20', '查看 DNS 客户端缓存。', 'Show DNS client cache.', 'windows'),
      toolCommand('路由表', 'Routes', 'Get-NetRoute | Sort-Object RouteMetric | Select-Object -First 20', '按 Metric 查看路由。', 'Show routes sorted by metric.', 'windows'),
      toolCommand('TCP 监听', 'Listening TCP', 'Get-NetTCPConnection -State Listen', '查看 TCP 监听端口。', 'Show listening TCP ports.', 'windows'),
      toolCommand('SMB 共享', 'SMB shares', 'Get-SmbShare', '查看本机 SMB 共享。', 'Show local SMB shares.', 'windows'),
      toolCommand('SMB 会话', 'SMB sessions', 'Get-SmbSession', '查看当前 SMB 会话。', 'Show current SMB sessions.', 'windows'),
      toolCommand('BitLocker 卷', 'BitLocker volumes', 'Get-BitLockerVolume', '查看 BitLocker 加密状态。', 'Show BitLocker encryption state.', 'windows'),
      toolCommand('TPM 状态', 'TPM status', 'Get-Tpm', '查看 TPM 状态。', 'Show TPM state.', 'windows'),
      toolCommand('AppLocker 策略', 'AppLocker policy', 'Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections', '查看有效 AppLocker 规则集合。', 'Show effective AppLocker rule collections.', 'windows'),
      toolCommand('执行策略', 'Execution policy', 'Get-ExecutionPolicy -List', '查看 PowerShell 执行策略范围。', 'Show PowerShell execution policy by scope.', 'windows'),
      toolCommand('系统缓解策略', 'System mitigations', 'Get-ProcessMitigation -System', '查看系统进程缓解策略。', 'Show system process mitigation policy.', 'windows')
    ],
    references: [
      'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil',
      'https://learn.microsoft.com/en-us/powershell/module/netsecurity/'
    ]
  },
  {
    id: 'windows-sysinternals-reference',
    name: toolText('Windows Sysinternals 工具', 'Windows Sysinternals Tools'),
    description: toolText(
      '覆盖 Process Explorer、Autoruns、Procmon、TCPView、Sigcheck、Handle 等微软官方排障工具的安全查询用法。',
      'Safe query-oriented usage for Microsoft Sysinternals tools such as Process Explorer, Autoruns, Procmon, TCPView, Sigcheck, and Handle.'
    ),
    category: blueTeamCategory,
    installation: toolText('从 Microsoft Sysinternals 下载或使用 winget install Microsoft.Sysinternals。', 'Download from Microsoft Sysinternals or install with winget install Microsoft.Sysinternals.'),
    commands: [
      toolCommand('启动 Process Explorer', 'Launch Process Explorer', 'procexp.exe', '交互式查看进程树、句柄、DLL 和签名。', 'Interactively inspect process tree, handles, DLLs, and signatures.', 'windows'),
      toolCommand('启动 Process Monitor', 'Launch Procmon', 'procmon.exe', '交互式观察文件、注册表、网络和进程活动。', 'Interactively observe file, registry, network, and process activity.', 'windows'),
      toolCommand('Procmon 后台采集', 'Procmon backing file', 'procmon.exe /AcceptEula /Quiet /BackingFile trace.pml', '将排查样本写入 PML 文件，实验结束后应停止采集。', 'Write diagnostic samples to a PML file; stop capture after the lab.', 'windows'),
      toolCommand('停止 Procmon', 'Terminate Procmon', 'procmon.exe /Terminate', '停止 Procmon 后台采集。', 'Stop a Procmon background capture.', 'windows'),
      toolCommand('自启动项 CSV', 'Autoruns CSV', 'autorunsc.exe -accepteula -a * -c', '以 CSV 输出自启动项，适合基线比对。', 'Export autoruns as CSV for baseline comparison.', 'windows'),
      toolCommand('隐藏微软项', 'Autoruns non-Microsoft', 'autorunsc.exe -accepteula -a * -m', '重点查看非微软自启动项。', 'Focus on non-Microsoft autoruns.', 'windows'),
      toolCommand('签名和哈希', 'Sigcheck hash and signature', 'sigcheck.exe -accepteula -h -m file.exe', '查看哈希、签名和清单信息。', 'Show hashes, signature, and manifest information.', 'windows'),
      toolCommand('目录签名扫描', 'Sigcheck directory', 'sigcheck.exe -accepteula -e -u -s C:\\Tools', '递归列出未签名可执行文件。', 'Recursively list unsigned executable files.', 'windows'),
      toolCommand('打开句柄', 'Open handles', 'handle.exe -accepteula file.txt', '查询哪个进程打开了指定文件。', 'Find which process has opened a file.', 'windows'),
      toolCommand('进程 DLL', 'Loaded DLLs', 'listdlls.exe -accepteula process.exe', '查看进程加载的 DLL。', 'Show DLLs loaded by a process.', 'windows'),
      toolCommand('TCPView', 'TCPView', 'tcpview.exe', '交互式查看网络连接。', 'Interactively inspect network connections.', 'windows'),
      toolCommand('命令行 TCP 连接', 'TCP connections CLI', 'tcpvcon.exe -accepteula -a', '命令行输出 TCP/UDP 连接。', 'Print TCP/UDP connections in the command line.', 'windows'),
      toolCommand('系统信息', 'PsInfo', 'psinfo.exe -accepteula -h -s', '查看系统和补丁摘要。', 'Show system and hotfix summary.', 'windows'),
      toolCommand('进程列表', 'PsList', 'pslist.exe -accepteula -t', '按树状结构列出进程。', 'List processes as a tree.', 'windows'),
      toolCommand('目录大小', 'DU', 'du.exe -accepteula -q -l 2 C:\\Data', '查看目录空间占用。', 'Show directory space usage.', 'windows'),
      toolCommand('备用数据流', 'Streams', 'streams.exe -accepteula -s C:\\Data', '查找 NTFS Alternate Data Streams。', 'Find NTFS alternate data streams.', 'windows'),
      toolCommand('权限检查', 'AccessChk', 'accesschk.exe -accepteula -d C:\\Data', '检查目录访问权限。', 'Check directory access permissions.', 'windows')
    ],
    references: ['https://learn.microsoft.com/en-us/sysinternals/']
  },
  {
    id: 'modern-cli-toolkit',
    name: toolText('跨平台效率命令工具', 'Modern Cross-platform CLI Toolkit'),
    description: toolText(
      '收录 rg、fd、bat、fzf、jq、yq、xsv、mlr、hyperfine 等现代命令行工具，提升搜索、数据处理和性能对比效率。',
      'Modern CLI tools such as rg, fd, bat, fzf, jq, yq, xsv, mlr, and hyperfine for search, data processing, and benchmarking.'
    ),
    category: utilityCategory,
    installation: toolText('可通过 apt、brew、winget、scoop、cargo 或各项目 Release 安装。', 'Install through apt, brew, winget, scoop, cargo, or project releases.'),
    commands: [
      toolCommand('快速搜索文本', 'Fast text search', 'rg -n "TODO" src', '用 ripgrep 递归搜索文本。', 'Search text recursively with ripgrep.', 'all'),
      toolCommand('搜索文件名', 'Find filenames', 'fd "\\.tsx$" src', '用 fd 按模式查找文件。', 'Find files by pattern with fd.', 'all'),
      toolCommand('彩色查看文件', 'Pretty print file', 'bat src/App.tsx', '带语法高亮查看文件。', 'View files with syntax highlighting.', 'all'),
      toolCommand('交互选择', 'Fuzzy select', 'rg --files | fzf', '从文件列表中交互式选择。', 'Interactively select from a file list.', 'all'),
      toolCommand('JSON 格式化', 'Format JSON', 'jq . data.json', '格式化 JSON。', 'Format JSON.', 'all'),
      toolCommand('JSON 提取', 'Extract JSON field', 'jq -r ".items[].name" data.json', '提取 JSON 数组字段。', 'Extract fields from a JSON array.', 'all'),
      toolCommand('YAML 查询', 'Query YAML', 'yq ".services" docker-compose.yml', '查询 YAML 节点。', 'Query YAML nodes.', 'all'),
      toolCommand('结构化替换', 'Structured replace', 'sd "old" "new" file.txt', '用 sd 执行更友好的文本替换。', 'Replace text with sd.', 'all'),
      toolCommand('CSV 统计', 'CSV stats', 'xsv stats data.csv', '快速统计 CSV 字段。', 'Quickly compute CSV field statistics.', 'all'),
      toolCommand('CSV 查询', 'CSV query', 'mlr --csv filter "$status == \\"ok\\"" data.csv', '用 Miller 过滤 CSV。', 'Filter CSV with Miller.', 'all'),
      toolCommand('性能对比', 'Benchmark commands', 'hyperfine "rg error logs" "grep -R error logs"', '对比命令运行时间。', 'Compare command runtime.', 'all'),
      toolCommand('源码行统计', 'Code statistics', 'tokei src', '统计代码行数。', 'Count source lines.', 'all'),
      toolCommand('磁盘占用树', 'Disk usage tree', 'dust -d 2', '用树状视图查看磁盘占用。', 'Show disk usage as a tree.', 'all'),
      toolCommand('磁盘空间仪表', 'Disk free dashboard', 'duf', '以更清晰表格查看磁盘空间。', 'Show disk free space in a readable table.', 'all'),
      toolCommand('进程仪表', 'Process dashboard', 'btm', '交互式查看 CPU、内存、磁盘和进程。', 'Interactively inspect CPU, memory, disk, and processes.', 'all'),
      toolCommand('Git diff 高亮', 'Delta diff', 'git diff | delta', '用 delta 查看高亮 diff。', 'View highlighted git diffs with delta.', 'all')
    ],
    references: [
      'https://github.com/BurntSushi/ripgrep',
      'https://jqlang.github.io/jq/',
      'https://mikefarah.gitbook.io/yq/'
    ]
  },
  {
    id: 'network-diagnostics-toolkit',
    name: toolText('网络诊断工具箱', 'Network Diagnostics Toolkit'),
    description: toolText(
      '收录 curl、HTTPie、OpenSSL、dig、mtr、iperf3、tcpdump、tshark 等网络排障工具。',
      'Network troubleshooting tools including curl, HTTPie, OpenSSL, dig, mtr, iperf3, tcpdump, and tshark.'
    ),
    category: adminCategory,
    installation: toolText('可通过 apt、brew、winget、choco 或发行版包管理器安装。', 'Install through apt, brew, winget, choco, or distribution package managers.'),
    commands: [
      toolCommand('HTTP 头检查', 'HTTP header check', 'curl -I https://example.com', '查看 HTTP 响应头。', 'Inspect HTTP response headers.', 'all'),
      toolCommand('详细请求', 'Verbose request', 'curl -v https://example.com', '查看连接、TLS 和 HTTP 过程。', 'Inspect connection, TLS, and HTTP details.', 'all'),
      toolCommand('HTTPie GET', 'HTTPie GET', 'http GET https://example.com', '用更易读格式发送 GET 请求。', 'Send a readable GET request with HTTPie.', 'all'),
      toolCommand('下载测试', 'Wget spider', 'wget --spider https://example.com/file.zip', '只检查资源是否存在，不保存文件。', 'Check whether a resource exists without saving it.', 'linux'),
      toolCommand('TLS 证书', 'TLS certificate', 'openssl s_client -showcerts -connect example.com:443 -servername example.com', '查看证书链和握手信息。', 'Inspect certificate chain and handshake details.', 'all'),
      toolCommand('DNS A 记录', 'DNS A record', 'dig example.com A +short', '查询 A 记录。', 'Query A records.', 'all'),
      toolCommand('DNS MX 记录', 'DNS MX record', 'dig example.com MX +short', '查询 MX 记录。', 'Query MX records.', 'all'),
      toolCommand('路径跟踪', 'Route trace', 'mtr -rw example.com', '生成路径延迟和丢包报告。', 'Generate route latency and packet-loss report.', 'linux'),
      toolCommand('带宽测试服务端', 'iperf3 server', 'iperf3 -s', '在授权实验网段启动带宽测试服务端。', 'Start an iperf3 server inside an authorized lab network.', 'all'),
      toolCommand('带宽测试客户端', 'iperf3 client', 'iperf3 -c 192.168.1.10 -t 10', '连接实验服务端测试吞吐。', 'Connect to a lab server and test throughput.', 'all'),
      toolCommand('抓包到文件', 'Capture to pcap', 'tcpdump -i any -nn -w capture.pcap -c 200', '抓取有限数量网络包到 pcap。', 'Capture a limited packet sample into a pcap.', 'linux'),
      toolCommand('读取 pcap 摘要', 'Read pcap summary', 'tshark -r capture.pcap -q -z conv,tcp', '统计 pcap 中 TCP 会话。', 'Summarize TCP conversations in a pcap.', 'all'),
      toolCommand('HTTP 包字段', 'HTTP packet fields', 'tshark -r capture.pcap -Y http -T fields -e ip.src -e http.host -e http.request.uri', '提取 HTTP 请求字段。', 'Extract HTTP request fields from a pcap.', 'all')
    ],
    references: [
      'https://curl.se/docs/manpage.html',
      'https://www.tcpdump.org/manpages/tcpdump.1.html',
      'https://www.wireshark.org/docs/man-pages/tshark.html'
    ]
  },
  {
    id: 'dfir-toolkit-reference',
    name: toolText('蓝队取证工具箱', 'Blue Team DFIR Toolkit'),
    description: toolText(
      '收录 osquery、KAPE、Velociraptor、Chainsaw、Hayabusa、Volatility3、Plaso 等取证与日志分析工具的课堂安全用法。',
      'Classroom-safe DFIR usage for osquery, KAPE, Velociraptor, Chainsaw, Hayabusa, Volatility3, and Plaso.'
    ),
    category: blueTeamCategory,
    installation: toolText('按项目官方文档安装；Windows 工具建议在隔离实验目录运行。', 'Install from official project documentation; run Windows tools in an isolated lab directory.'),
    commands: [
      toolCommand('osquery 交互模式', 'osquery interactive shell', 'osqueryi', '进入 osquery 交互式查询环境。', 'Enter the osquery interactive shell.', 'all'),
      toolCommand('进程查询', 'osquery processes', 'osqueryi "select pid,name,path from processes limit 20;"', '查询进程表。', 'Query the process table.', 'all'),
      toolCommand('监听端口查询', 'osquery listening ports', 'osqueryi "select port,protocol,address,pid from listening_ports;"', '查询监听端口。', 'Query listening ports.', 'all'),
      toolCommand('KAPE 采集目标', 'KAPE target collection', 'kape.exe --tsource C: --tdest .\\KAPEOut --target !BasicCollection', '在实验机采集基础取证目标。', 'Collect basic forensic targets from a lab host.', 'windows'),
      toolCommand('KAPE 模块处理', 'KAPE module processing', 'kape.exe --msource .\\KAPEOut --mdest .\\ModuleOut --module !EZParser', '对采集结果执行解析模块。', 'Run parsing modules against collected artifacts.', 'windows'),
      toolCommand('Velociraptor GUI', 'Velociraptor GUI', 'velociraptor gui', '启动本地 Velociraptor 实验界面。', 'Start a local Velociraptor lab GUI.', 'all'),
      toolCommand('Velociraptor artifacts', 'Velociraptor artifacts', 'velociraptor artifacts list', '列出可用取证 Artifact。', 'List available forensic artifacts.', 'all'),
      toolCommand('Chainsaw Sigma', 'Chainsaw Sigma', 'chainsaw hunt .\\evtx --sigma .\\sigma --mapping .\\mappings\\sigma-event-logs-all.yml', '用 Sigma 规则分析 EVTX。', 'Analyze EVTX files with Sigma rules.', 'windows'),
      toolCommand('Hayabusa 时间线', 'Hayabusa timeline', 'hayabusa.exe csv-timeline -d .\\evtx -o timeline.csv', '从 EVTX 生成 CSV 时间线。', 'Generate a CSV timeline from EVTX files.', 'windows'),
      toolCommand('Volatility 进程列表', 'Volatility process list', 'vol -f memory.raw windows.pslist.PsList', '从内存镜像列出进程。', 'List processes from a memory image.', 'all'),
      toolCommand('Volatility 网络扫描', 'Volatility network scan', 'vol -f memory.raw windows.netscan.NetScan', '从内存镜像提取网络连接线索。', 'Extract network connection clues from a memory image.', 'all'),
      toolCommand('Plaso 时间线', 'Plaso timeline', 'log2timeline.py timeline.plaso disk_image.E01', '从磁盘镜像生成时间线数据库。', 'Generate a timeline database from a disk image.', 'all'),
      toolCommand('psort 输出', 'psort output', 'psort.py -o l2tcsv timeline.plaso > timeline.csv', '将 Plaso 时间线导出为 CSV。', 'Export a Plaso timeline as CSV.', 'all')
    ],
    references: [
      'https://osquery.readthedocs.io/',
      'https://docs.velociraptor.app/',
      'https://github.com/WithSecureLabs/chainsaw',
      'https://github.com/Yamato-Security/hayabusa'
    ]
  },
  {
    id: 'file-analysis-toolkit',
    name: toolText('文件分析与取证工具', 'File Analysis & Forensics Tools'),
    description: toolText(
      '面向 CTF 和取证教学的文件类型识别、元数据、哈希、二进制查看、压缩包和固件分析工具。',
      'File type, metadata, hash, binary viewing, archive, and firmware analysis tools for CTF and forensics education.'
    ),
    category: blueTeamCategory,
    installation: toolText('可通过 apt、brew、winget、choco 或项目 Release 安装。', 'Install through apt, brew, winget, choco, or project releases.'),
    commands: [
      toolCommand('文件类型', 'File type', 'file sample.bin', '识别文件类型。', 'Identify file type.', 'linux'),
      toolCommand('文件哈希 Linux', 'Linux file hash', 'sha256sum sample.bin', '计算 SHA256 哈希。', 'Calculate SHA256 hash.', 'linux'),
      toolCommand('文件哈希 Windows', 'Windows file hash', 'Get-FileHash .\\sample.bin -Algorithm SHA256', '在 PowerShell 中计算 SHA256。', 'Calculate SHA256 in PowerShell.', 'windows'),
      toolCommand('十六进制视图', 'Hex view', 'xxd -g 1 -l 256 sample.bin', '查看文件前 256 字节。', 'Show first 256 bytes as hex.', 'linux'),
      toolCommand('二进制字符串', 'Binary strings', 'strings -a sample.bin | head -n 50', '提取可见字符串。', 'Extract printable strings.', 'linux'),
      toolCommand('Exif 元数据', 'Exif metadata', 'exiftool image.jpg', '查看图片或文档元数据。', 'Inspect image or document metadata.', 'all'),
      toolCommand('Exif 时间线字段', 'Exif timeline fields', 'exiftool -time:all -a -G0:1 image.jpg', '查看所有时间相关元数据。', 'Show all time-related metadata.', 'all'),
      toolCommand('Binwalk 签名', 'Binwalk signatures', 'binwalk firmware.bin', '扫描固件或二进制中的嵌入文件签名。', 'Scan embedded file signatures in firmware or binaries.', 'linux'),
      toolCommand('Binwalk 解包', 'Binwalk extract', 'binwalk -e firmware.bin', '在实验样本上解包嵌入内容。', 'Extract embedded content from lab samples.', 'linux'),
      toolCommand('7z 列表', '7-Zip list', '7z l archive.7z', '列出压缩包内容。', 'List archive contents.', 'all'),
      toolCommand('Zip 详情', 'Zip info', 'zipinfo archive.zip', '查看 zip 条目详情。', 'Show detailed zip entries.', 'linux'),
      toolCommand('PDF 信息', 'PDF info', 'pdfinfo document.pdf', '查看 PDF 元数据和页数。', 'Show PDF metadata and page count.', 'all'),
      toolCommand('图片识别', 'Image identify', 'identify image.png', '查看图片格式、尺寸和色彩信息。', 'Show image format, dimensions, and color information.', 'all'),
      toolCommand('YARA 扫描', 'YARA scan', 'yara -r rules.yar samples/', '用规则扫描本地样本目录。', 'Scan a local sample directory with rules.', 'all')
    ],
    references: [
      'https://exiftool.org/',
      'https://github.com/ReFirmLabs/binwalk',
      'https://yara.readthedocs.io/'
    ]
  },
  {
    id: 'linux-security-baseline-reference',
    name: toolText('Linux 安全基线查询', 'Linux Security Baseline Queries'),
    description: toolText(
      '面向防守的 Linux 账号、权限、服务、审计、SSH、防火墙和内核参数基线查询命令。',
      'Defensive Linux account, permission, service, audit, SSH, firewall, and kernel parameter baseline queries.'
    ),
    category: blueTeamCategory,
    installation: toolText('常见依赖包括 lynis、auditd、fail2ban、libcap、apparmor-utils、policycoreutils。', 'Common dependencies include lynis, auditd, fail2ban, libcap, apparmor-utils, and policycoreutils.'),
    commands: [
      toolCommand('Lynis 基线审计', 'Lynis baseline audit', 'lynis audit system', '执行本机安全基线审计。', 'Run a local security baseline audit.', 'linux'),
      toolCommand('审计规则', 'Audit rules', 'auditctl -l', '查看 auditd 当前规则。', 'Show current auditd rules.', 'linux'),
      toolCommand('审计摘要', 'Audit summary', 'aureport --summary', '查看审计日志摘要。', 'Show audit log summary.', 'linux'),
      toolCommand('认证事件', 'Authentication events', 'ausearch -m USER_LOGIN -ts today', '查询当天登录相关审计事件。', 'Query login-related audit events from today.', 'linux'),
      toolCommand('Fail2ban 状态', 'Fail2ban status', 'fail2ban-client status', '查看 Fail2ban jail 状态。', 'Show Fail2ban jail state.', 'linux'),
      toolCommand('SSH 有效配置', 'Effective SSH config', 'sshd -T | sort', '查看 sshd 解析后的有效配置。', 'Show parsed effective sshd configuration.', 'linux'),
      toolCommand('SSH Root 登录配置', 'SSH root login setting', 'grep -R "^PermitRootLogin" /etc/ssh/sshd_config*', '检查 SSH root 登录策略配置。', 'Check SSH root login policy configuration.', 'linux'),
      toolCommand('密码状态', 'Password status', 'passwd -S -a', '查看本机账号密码状态摘要。', 'Show local account password status summary.', 'linux'),
      toolCommand('账号老化策略', 'Account aging', 'chage -l username', '查看指定账号密码过期策略。', 'Show password aging policy for an account.', 'linux'),
      toolCommand('开放能力', 'File capabilities', 'getcap -r /usr/bin 2>/dev/null', '查找带 Linux capabilities 的文件。', 'Find files with Linux capabilities.', 'linux'),
      toolCommand('SUID 审计', 'SUID audit', 'find / -xdev -perm -4000 -type f -ls 2>/dev/null', '审计当前文件系统中的 SUID 文件。', 'Audit SUID files on the current filesystem.', 'linux'),
      toolCommand('SELinux 状态', 'SELinux status', 'sestatus', '查看 SELinux 状态。', 'Show SELinux status.', 'linux'),
      toolCommand('AppArmor 状态', 'AppArmor status', 'aa-status', '查看 AppArmor Profile 状态。', 'Show AppArmor profile state.', 'linux'),
      toolCommand('内核 ASLR', 'Kernel ASLR', 'sysctl kernel.randomize_va_space', '查看 ASLR 内核参数。', 'Show the kernel ASLR setting.', 'linux'),
      toolCommand('危险 world-writable 目录', 'World-writable dirs', 'find / -xdev -type d -perm -0002 -ls 2>/dev/null | head', '抽样检查全局可写目录。', 'Sample world-writable directories for review.', 'linux')
    ],
    references: [
      'https://cisofy.com/documentation/lynis/',
      'https://man7.org/linux/man-pages/'
    ]
  },
  {
    id: 'windows-security-baseline-reference',
    name: toolText('Windows 安全基线查询', 'Windows Security Baseline Queries'),
    description: toolText(
      '面向防守的 Windows Defender、补丁、本地用户、管理员组、审计策略、执行策略、BitLocker 和启动项查询命令。',
      'Defensive Windows Defender, patch, local user, administrator group, audit policy, execution policy, BitLocker, and startup query commands.'
    ),
    category: blueTeamCategory,
    installation: toolText('Windows 10/11、Windows Server 与 PowerShell 管理模块。', 'Windows 10/11, Windows Server, and PowerShell administration modules.'),
    commands: [
      toolCommand('Defender 状态', 'Defender status', 'Get-MpComputerStatus', '查看 Defender 引擎、签名和实时保护状态。', 'Show Defender engine, signature, and real-time protection state.', 'windows'),
      toolCommand('系统补丁', 'Installed hotfixes', 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20', '查看最近安装补丁。', 'Show recently installed hotfixes.', 'windows'),
      toolCommand('本地用户状态', 'Local user state', 'Get-LocalUser | Select-Object Name,Enabled,LastLogon', '查看本地用户启用状态和最近登录。', 'Show local user enabled state and last logon.', 'windows'),
      toolCommand('管理员组', 'Administrators group', 'Get-LocalGroupMember Administrators', '查看本地管理员组成员。', 'Show local Administrators group members.', 'windows'),
      toolCommand('审计策略', 'Audit policy', 'AuditPol /get /category:*', '查看本机审计策略。', 'Show local audit policy.', 'windows'),
      toolCommand('导出安全策略', 'Export security policy', 'secedit /export /cfg security-baseline.inf', '导出本机安全策略用于审阅。', 'Export local security policy for review.', 'windows'),
      toolCommand('组策略摘要', 'Group policy summary', 'gpresult /r', '查看当前组策略应用摘要。', 'Show applied Group Policy summary.', 'windows'),
      toolCommand('执行策略', 'PowerShell execution policy', 'Get-ExecutionPolicy -List', '查看 PowerShell 执行策略范围。', 'Show PowerShell execution policy by scope.', 'windows'),
      toolCommand('系统缓解策略', 'Process mitigation', 'Get-ProcessMitigation -System', '查看系统进程缓解策略。', 'Show system process mitigations.', 'windows'),
      toolCommand('BitLocker 状态', 'BitLocker state', 'Get-BitLockerVolume', '查看磁盘加密状态。', 'Show disk encryption state.', 'windows'),
      toolCommand('TPM 状态', 'TPM state', 'Get-Tpm', '查看 TPM 可用性。', 'Show TPM availability.', 'windows'),
      toolCommand('启动项', 'Startup entries', 'Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User', '查看系统启动项。', 'Show startup entries.', 'windows'),
      toolCommand('服务路径', 'Service paths', 'Get-CimInstance Win32_Service | Select-Object Name,StartMode,State,PathName', '查看服务路径和启动类型。', 'Show service executable paths and startup type.', 'windows'),
      toolCommand('共享目录', 'SMB shares', 'Get-SmbShare | Select-Object Name,Path,Description', '查看 SMB 共享目录。', 'Show SMB shares.', 'windows'),
      toolCommand('文件权限', 'NTFS permissions', 'icacls C:\\Data', '查看目录 NTFS 权限。', 'Show NTFS permissions for a directory.', 'windows')
    ],
    references: [
      'https://learn.microsoft.com/en-us/windows/security/',
      'https://learn.microsoft.com/en-us/powershell/'
    ]
  }
];
