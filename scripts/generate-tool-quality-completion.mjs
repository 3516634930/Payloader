import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadCurationSnapshot, loadReviewConfiguration } from './apply-payload-curation.mjs';
import { curatePayloadLibrary } from './curate-payload-library.mjs';

export const toolQualityCompletionFileName = 'tool-overrides-quality-completion.json';
const hanPattern = /\p{Script=Han}/u;
const asList = value => Array.isArray(value) ? value : [];
const localizedText = (value, language) => typeof value === 'string'
  ? value
  : String(value?.[language] || '');

const cleanEnglish = value => String(value || '')
  .replace(/\bIo T\b/g, 'IoT')
  .replace(/\bmac OS\b/g, 'macOS')
  .replace(/\bApp Armor\b/g, 'AppArmor')
  .replace(/\bJava Script\b/g, 'JavaScript')
  .replace(/\bVirus Total\b/g, 'VirusTotal')
  .replace(/\bAlien Vault\b/g, 'AlienVault')
  .replace(/\bFree BSD\b/g, 'FreeBSD')
  .replace(/\bOpen BSD\b/g, 'OpenBSD')
  .replace(/\blib Fuzzer\b/g, 'libFuzzer')
  .replace(/\bPower View\b/g, 'PowerView')
  .replace(/\bProxy Chains\b/g, 'ProxyChains')
  .replace(/\bSearch Sploit\b/g, 'SearchSploit')
  .replace(/\bwill Result Save to File\b/gi, 'Save the result to a file')
  .replace(/\bStart CS Server-Side\b/gi, 'Start the Cobalt Strike team server');

const sentenceZh = (base, detail) => {
  const value = String(base || '').trim().replace(/[；，。.!?]+$/u, '');
  return value ? `${value}；${detail}` : detail;
};

const sentenceEn = (base, detail) => {
  const value = cleanEnglish(base).trim().replace(/[.!?]+$/u, '');
  return value ? `${value}. ${detail}` : detail;
};

const englishText = (value, fallback) => {
  const text = cleanEnglish(value).trim();
  return text && !hanPattern.test(text) ? text : fallback;
};

const executableNames = command => {
  const names = [];
  const seen = new Set();
  for (const rawLine of String(command || '').split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line || /^(?:#|\/\/|\/\*|\*|<!--|REM\b|::)/i.test(line)) continue;
    if (/^(?:PY|EOF|END|END_SCRIPT|END_JSON|END_XML|JSON|YAML|XML)$/i.test(line)) continue;
    line = line
      .replace(/^(?:beacon|meterpreter|msf\d*|C:\\[^>]+|PS\s+[^>]+)>\s*/i, '')
      .replace(/^(?:sudo\s+|env\s+(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)+)/i, '')
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)+/, '');
    if (/^(?:from|import|class|def|if|elif|else|for|while|try|except|finally|with|return|raise|pass|assert|print)\b/i.test(line)) continue;
    if (/^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?\s*=/.test(line)) continue;
    if (/^[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_][A-Za-z0-9_]*\s*\(/.test(line)) continue;
    const match = line.match(/^&?\s*['"]?([A-Za-z0-9_.+\-\\/]+)/);
    if (!match) continue;
    const name = match[1].split(/[\\/]/).at(-1).replace(/\.(?:exe|py|ps1|sh|rb)$/i, '');
    if (!name || seen.has(name.toLowerCase())) continue;
    if (/^[a-z_$][A-Za-z0-9_$]*\./.test(name)) continue;
    seen.add(name.toLowerCase());
    names.push(name);
    if (names.length === 3) break;
  }
  return names;
};

const commandEvidence = (tool, entry) => {
  const nameZh = localizedText(entry?.name, 'zh').trim() || '该命令';
  const nameEn = englishText(localizedText(entry?.name, 'en'), 'this command');
  const command = String(entry?.command || '');
  const toolIdentity = `${String(tool?.id || '')} ${englishText(localizedText(tool?.name, 'en'), '')}`;
  const text = `${toolIdentity}\n${nameEn}\n${command}`.toLowerCase();
  const commandText = command.toLowerCase();

  if (/\b(?:get-help|man\s+|help\s+|--help\b|-h\b|command\s+-v|type\s+-a|whatis\b)/i.test(text)) {
    return {
      zh: '打开本地帮助、语法或命令来源信息，不执行被查询命令的业务操作。',
      en: 'Open local help, syntax, or command-source metadata without executing the referenced operation.',
    };
  }
  if (/\b(?:nmap|masscan|naabu|scan|fuzz|ffuf|gobuster|dirsearch|feroxbuster|nuclei|nikto|wpscan|enum4linux|assetfinder|subfinder|amass)\b/i.test(text)) {
    return {
      zh: '记录限定目标、所选端口或路径以及识别结果，便于比较探测前后的服务状态。',
      en: 'Record the bounded target, selected ports or paths, and detected results for repeatable comparison.',
    };
  }
  if (/\b(?:curl|wget|httpx|whatweb|wafw00f|Invoke-WebRequest|Invoke-RestMethod)\b|https?:\/\//i.test(command)) {
    return {
      zh: '保存请求地址、响应状态、关键响应头和输出文件，便于核对实际 HTTP 行为。',
      en: 'Preserve the request URL, response status, relevant headers, and output artifact to review actual HTTP behavior.',
    };
  }
  if (/\b(?:flushdns|dscacheutil\s+-flushcache|killall\s+-hup\s+mdnsresponder)\b/i.test(commandText)) {
    return {
      zh: '记录刷新前后的解析缓存状态和命令结果，确认变更只影响本机 DNS 缓存。',
      en: 'Record resolver-cache state and command status before and after the flush, confirming that only the local DNS cache changed.',
    };
  }
  if (/(?:^|[\r\n;&|]\s*)(?:sudo\s+)?(?:dig|nslookup|host\s+\S|dnsrecon|dnsenum|resolvectl)\b/i.test(commandText)) {
    return {
      zh: '记录查询的名称、记录类型、解析器和返回值，用于复核 DNS 解析结果。',
      en: 'Record the queried name, record type, resolver, and returned values to verify DNS resolution.',
    };
  }
  if (/\b(?:get-ad|get-(?:net)?domain|net\s+(?:user|group)|nltest|ldapsearch|bloodhound|sharphound|powerview|roadrecon|ldeep|kerberos|rubeus|certipy|spn)\b/i.test(text)) {
    return {
      zh: '记录查询身份、目录范围和返回对象，只把与授权目录基线不一致的结果列为发现。',
      en: 'Record the query identity, directory scope, and returned objects, treating only deviations from the authorized directory baseline as findings.',
    };
  }
  if (/\b(?:responder)\b/i.test(text)) {
    return {
      zh: '记录监听接口、运行模式、协议事件和输出文件，并将采集范围限制在授权网段。',
      en: 'Record the listening interface, operating mode, protocol events, and output files while limiting collection to the authorized network segment.',
    };
  }
  if (/\b(?:smbclient|smbmap|sharpsmbclient|net\s+(?:use|share|view)|get-smbshare)\b/i.test(text)) {
    return {
      zh: '记录 SMB 目标、身份、共享名称和返回权限，区分目录可见性与实际读写能力。',
      en: 'Record the SMB target, identity, share name, and returned permissions, distinguishing directory visibility from actual read or write access.',
    };
  }
  if (/\b(?:copy-item|copy|cp|scp|rsync|robocopy|move-item|move|mv|upload|download|transfer)\b/i.test(`${nameEn}\n${commandText}`)) {
    return {
      zh: '核对源文件、目标路径、传输状态和最终文件属性，避免把路径错误当作成功。',
      en: 'Verify the source file, destination path, transfer status, and resulting file attributes before treating the operation as successful.',
    };
  }
  if (/\b(?:driverquery|systeminfo|hostname|ver\b|uname|lscpu|lsblk|dmidecode|get-computerinfo|get-ciminstance|get-wmiobject|get-hotfix|wmic\s+(?:os|cpu|computersystem|qfe))\b/i.test(commandText)) {
    return {
      zh: '记录主机、操作系统、硬件或驱动清单及采集上下文，并与资产基线核对。',
      en: 'Record the host, operating-system, hardware, or driver inventory with collection context and compare it with the asset baseline.',
    };
  }
  if (/\b(?:wifiphisher|hostapd|airmon-ng|airodump-ng|aireplay-ng|aircrack-ng|wash\s|reaver\s|bully\s)\b/i.test(commandText)) {
    return {
      zh: '记录无线接口、目标标识、信道和输出制品，并将测试限制在批准的无线实验范围。',
      en: 'Record the wireless interface, target identifier, channel, and output artifacts while limiting testing to the approved wireless lab scope.',
    };
  }
  if (/\b(?:hashcat|john|hydra|medusa|ncrack|kerbrute|evil-winrm|passwordspray|bruteuser)\b/i.test(text)) {
    return {
      zh: '记录输入凭据材料、模式、字典和结果摘要，并限制在已授权的测试账户范围内。',
      en: 'Record the credential material, mode, wordlist, and result summary while limiting execution to authorized test accounts.',
    };
  }
  if (/\b(?:seatbelt|winpeas|linpeas|lynis)\b/i.test(text)
    && !/\b(?:output to file|save (?:the )?result|log=|outfile)\b/i.test(text)) {
    return {
      zh: '记录检查范围、主机上下文、工具版本和发现摘要，再按系统基线逐项确认。',
      en: 'Record the check scope, host context, tool version, and finding summary before validating each item against the system baseline.',
    };
  }
  if (/\b(?:firewall|iptables|nft|ufw|auditpol|secedit|get-mpcomputerstatus|bitlocker|selinux|apparmor|hardening|security baseline|account security)\b/i.test(text)) {
    return {
      zh: '记录当前安全策略与启用状态，并与批准的防护基线逐项比较。',
      en: 'Record the current security policy and enabled state, then compare each result with the approved protection baseline.',
    };
  }
  if (/\b(?:volatility|autopsy|sleuth|plaso|log2timeline|evtx|forensic|memory image|disk image|yara|suspicious process)\b/i.test(text)) {
    return {
      zh: '保留证据来源、采集时间、工具版本和输出路径，维持可复核的取证记录。',
      en: 'Preserve the evidence source, acquisition time, tool version, and output path to maintain a reviewable forensic record.',
    };
  }
  if (/\b(?:output to file|save (?:the )?result|log=|outfile)\b/i.test(text)) {
    return {
      zh: '记录输出文件路径、写入状态和文件大小，并确认结果来自本次命令运行。',
      en: 'Record the output path, write status, and file size, confirming that the result came from the current command run.',
    };
  }
  if (/\b(?:sha(?:1|224|256|384|512)?sum|md5sum|get-filehash|certutil\s+-hashfile|hashfile|strings\s|binwalk|firmware|exiftool|foremost|xxd|hexdump|readelf|objdump)\b/i.test(text)
    || /^(?:file|cat|less|head|tail|type|attrib|icacls)\b/im.test(commandText)) {
    return {
      zh: '保留输入制品的路径、哈希或解析结果，以便在不改动原件的情况下复核。',
      en: 'Preserve the input path, hash, or parsed findings so the artifact can be reviewed without modifying the original.',
    };
  }
  if (/\b(?:copy-item|copy|cp|scp|rsync|robocopy|move-item|move|mv|upload|download|transfer)\b/i.test(text)) {
    return {
      zh: '核对源文件、目标路径、传输状态和最终文件属性，避免把路径错误当作成功。',
      en: 'Verify the source file, destination path, transfer status, and resulting file attributes before treating the operation as successful.',
    };
  }
  if (/\b(?:grep|findstr|select-string|awk|sed|cut|sort|uniq|jq|yq|mlr|format-table|select-object|where-object)\b/i.test(text)) {
    return {
      zh: '记录筛选条件、输入来源和输出字段，确保文本处理结果能够重复验证。',
      en: 'Record the filter expression, input source, and selected output fields so the text-processing result is reproducible.',
    };
  }
  if (/\b(?:tar|zip|unzip|7z|expand-archive|compress-archive|archive)\b/i.test(text)) {
    return {
      zh: '核对归档路径、条目清单和解压目标，并保留原始归档用于完整性检查。',
      en: 'Verify the archive path, entry list, and extraction destination while retaining the original archive for integrity checks.',
    };
  }
  if (/\b(?:reg(?:\.exe)?\s+(?:query|add|delete|save)|get-itemproperty|new-itemproperty|registry)\b/i.test(text)) {
    return {
      zh: '记录注册表配置单元、键路径、值名和操作结果，并明确区分查询与写入步骤。',
      en: 'Record the registry hive, key path, value name, and operation result while clearly distinguishing queries from writes.',
    };
  }
  if (/\b(?:schtasks|scheduled task|get-scheduledtask)\b/i.test(text)) {
    return {
      zh: '记录任务名称、触发器、运行身份和当前状态，并核对命令是否只查询还是修改任务。',
      en: 'Record the task name, trigger, run identity, and current state, noting whether the command only queries or changes the task.',
    };
  }
  if (/\b(?:osqueryi)\b/i.test(commandText)) {
    return {
      zh: '记录查询的虚拟表、筛选条件和返回行，便于复核主机状态快照。',
      en: 'Record the queried virtual table, filters, and returned rows so the host-state snapshot can be reviewed.',
    };
  }
  if (/\b(?:docker|podman|kubectl|helm|kubeadm|crictl|container|image|pod\b)\b/i.test(text)) {
    return {
      zh: '记录容器或集群上下文、资源名称、命名空间和返回状态，避免跨环境误判。',
      en: 'Record the container or cluster context, resource name, namespace, and returned state to avoid cross-environment misinterpretation.',
    };
  }
  if (/\b(?:apt|apt-get|yum|dnf|rpm|dpkg|apk|brew|pip|npm|cargo|gem|package|install)\b/i.test(text)) {
    return {
      zh: '记录软件源、包名、解析版本和安装结果，确保后续命令使用可追溯的工具版本。',
      en: 'Record the repository, package name, resolved version, and installation result so later commands use a traceable tool version.',
    };
  }
  if (/\b(?:mysql|psql|sqlite3|sqlcmd|redis-cli|mongo|msfdb)\b/i.test(commandText)) {
    return {
      zh: '记录连接上下文、查询语句和返回行数，并区分只读结果与实际状态变化。',
      en: 'Record the connection context, query text, and returned row count while distinguishing read-only output from state changes.',
    };
  }
  if (/\b(?:psexec|wmiexec|smbexec|atexec|winrs|invoke-command|remote execution|lateral movement)\b/i.test(text)) {
    return {
      zh: '记录远程主机、执行身份、调用方式和返回状态，并限制在已批准的管理目标。',
      en: 'Record the remote host, execution identity, invocation method, and returned status while limiting use to approved administration targets.',
    };
  }
  if (/\b(?:gdb|lldb|radare2|r2\s|ghidra|ida|debug|disassembl|decompil|checksec|ropgadget)\b/i.test(text)) {
    return {
      zh: '记录样本架构、加载地址、断点或分析输出，确保调试结论对应同一制品。',
      en: 'Record the sample architecture, load address, breakpoints, or analysis output so debugging conclusions remain tied to the same artifact.',
    };
  }
  if (/\b(?:aws|az\s|gcloud|cloud|s3|iam|subscription|tenant)\b/i.test(text)) {
    return {
      zh: '记录当前账号、区域或订阅上下文以及返回资源，避免把其他云环境的数据混入结果。',
      en: 'Record the active account, region or subscription context, and returned resources to avoid mixing results from another cloud environment.',
    };
  }
  if (/\b(?:git|repository|commit|branch)\b/i.test(text)) {
    return {
      zh: '记录仓库路径、分支、提交标识和命令输出，使版本库检查能够定位到确定状态。',
      en: 'Record the repository path, branch, commit identifier, and command output so the review remains tied to a definite revision.',
    };
  }
  if (/\b(?:shodan|fofa|theharvester|searchsploit|site:|intitle:|inurl:|osint)\b/i.test(text)) {
    return {
      zh: '记录搜索语法、数据源、查询时间和候选结果，并在使用前复核资产归属。',
      en: 'Record the search expression, data source, query time, and candidate results, then verify asset ownership before use.',
    };
  }
  if (/\b(?:encode|decode|base64|hex|unicode|urlencode|jwt)\b/i.test(text)) {
    return {
      zh: '保存原始输入、转换方式和输出值，以便逐字节验证编码或解码结果。',
      en: 'Preserve the original input, transformation method, and output value for byte-level verification of the encoding or decoding result.',
    };
  }
  if (/\b(?:start|server|listener|listen|daemon|team server|launch|run\b)\b/i.test(text)) {
    return {
      zh: '记录启动参数、监听地址、进程状态和停止方式，便于实验结束后完整清理。',
      en: 'Record startup arguments, listening address, process state, and shutdown procedure so the lab can be cleaned up completely.',
    };
  }
  if (/\b(?:get-service|systemctl|service\s|sc\s+(?:query|qc|start|stop)|tasklist|pstree|journalctl|wmic\s+(?:process|service)\s+(?:list|get|where))\b/i.test(commandText)) {
    return {
      zh: '记录服务或进程的名称、状态和关联路径，便于与系统运行基线比较。',
      en: 'Record service or process names, states, and associated paths for comparison with the system runtime baseline.',
    };
  }
  if (/\b(?:ipconfig|ifconfig|route\s+(?:print|-n)|arp\s+-a|netstat|ping|traceroute|tracert|mtr|test-netconnection|tcpdump|tshark|ip\s+(?:addr|route|link|neigh)|ss\s+-)\b/i.test(commandText)) {
    return {
      zh: '保存接口、地址、路由或连通性输出，并标记采集时间和使用的网络上下文。',
      en: 'Preserve interface, address, route, or connectivity output together with the collection time and network context.',
    };
  }

  const executables = executableNames(command);
  const commandLabelZh = executables.length ? executables.join('、') : nameZh;
  const commandLabelEn = executables.length ? executables.join(', ') : nameEn;
  const stepNameEn = nameEn.replace(/[.!?]+$/u, '');
  const commandPossessiveZh = /[A-Za-z0-9_.+-]$/u.test(commandLabelZh)
    ? `${commandLabelZh} 的`
    : `${commandLabelZh}的`;
  return {
    zh: `记录 ${commandPossessiveZh}关键参数、退出状态和输出，并按“${nameZh}”步骤复核结果。`,
    en: `Record arguments, exit status, and output for ${commandLabelEn}; review the ${stepNameEn} step against its intended result.`,
  };
};

const commandNames = (tool, language) => asList(tool?.commands)
  .map(command => englishText(localizedText(command?.name, language), ''))
  .filter(Boolean)
  .slice(0, 3);

const describeTool = tool => {
  const currentZh = localizedText(tool?.description, 'zh');
  const currentEn = cleanEnglish(localizedText(tool?.description, 'en'));
  const namesZh = asList(tool?.commands)
    .map(command => localizedText(command?.name, 'zh').trim())
    .filter(Boolean)
    .slice(0, 3);
  const namesEn = commandNames(tool, 'en');
  const toolNameZh = localizedText(tool?.name, 'zh').trim() || String(tool?.id || '工具');
  const toolNameEn = englishText(localizedText(tool?.name, 'en'), String(tool?.id || 'tool'));
  const zhDetail = namesZh.length
    ? `覆盖 ${namesZh.join('、')} 等命令流程，并保留实际输出供复核。`
    : `围绕${toolNameZh}整理可重复执行的命令、参数和结果检查流程。`;
  const englishList = namesEn.length > 1
    ? `${namesEn.slice(0, -1).join(', ')}, and ${namesEn.at(-1)}`
    : namesEn[0];
  const enDetail = namesEn.length
    ? `It covers workflows for ${englishList} and preserves observable output for repeatable review.`
    : `It organizes repeatable ${toolNameEn} commands, arguments, and result checks.`;
  return {
    zh: currentZh.trim().length >= 20 && hanPattern.test(currentZh) ? currentZh : sentenceZh(currentZh, zhDetail),
    en: currentEn.trim().length >= 40 && !hanPattern.test(currentEn)
      ? currentEn
      : sentenceEn(englishText(currentEn, toolNameEn), enDetail),
  };
};

export const describeToolCommand = (tool, entry) => {
  const currentZh = localizedText(entry?.description, 'zh');
  const currentEn = cleanEnglish(localizedText(entry?.description, 'en'));
  const detail = commandEvidence(tool, entry);
  return {
    zh: currentZh.trim().length >= 12 ? currentZh : sentenceZh(currentZh, detail.zh),
    en: currentEn.trim().length >= 30 && !hanPattern.test(currentEn)
      ? currentEn
      : sentenceEn(englishText(currentEn, englishText(localizedText(entry?.name, 'en'), 'Command')), detail.en),
  };
};

export const buildToolQualityCompletionDocument = toolsInput => {
  const entries = [];
  for (const tool of [...asList(toolsInput)].sort((left, right) => String(left.id).localeCompare(String(right.id), 'en'))) {
    const patches = [];
    const descriptionZh = localizedText(tool?.description, 'zh').trim();
    const descriptionEn = localizedText(tool?.description, 'en').trim();
    if (descriptionZh.length < 20 || descriptionEn.length < 40 || hanPattern.test(descriptionEn)) {
      patches.push({ path: 'description', value: describeTool(tool) });
    }
    asList(tool?.commands).forEach((entry, index) => {
      const commandZh = localizedText(entry?.description, 'zh').trim();
      const commandEn = localizedText(entry?.description, 'en').trim();
      if (commandZh.length < 12 || commandEn.length < 30 || hanPattern.test(commandEn)) {
        patches.push({ path: `commands.${index}.description`, value: describeToolCommand(tool, entry) });
      }
    });
    if (patches.length) entries.push({ id: tool.id, patches });
  }
  return { schemaVersion: 1, entries };
};

export const withoutExistingToolQualityCompletion = configuration => {
  if (!asList(configuration?.sourceFiles?.toolOverrides).includes(toolQualityCompletionFileName)) return configuration;
  const outputFile = resolve(configuration.reviewDirectory, toolQualityCompletionFileName);
  if (!existsSync(outputFile)) return configuration;
  const existing = JSON.parse(readFileSync(outputFile, 'utf8'));
  const signatures = new Set(asList(existing.entries).map(entry => JSON.stringify(entry)));
  return {
    ...configuration,
    toolOverrides: asList(configuration.toolOverrides).filter(entry => !signatures.has(JSON.stringify(entry))),
  };
};

const run = async () => {
  const root = resolve(process.cwd());
  const configuration = withoutExistingToolQualityCompletion(
    await loadReviewConfiguration(join(root, 'content-review')),
  );
  const source = loadCurationSnapshot(join(root, 'data', 'payloader.sqlite'));
  const planned = curatePayloadLibrary(source, configuration).snapshot;
  const document = buildToolQualityCompletionDocument(planned.tools);
  const outputFile = join(root, 'content-review', toolQualityCompletionFileName);
  writeFileSync(outputFile, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  const patchCount = document.entries.reduce((sum, entry) => sum + entry.patches.length, 0);
  console.log(`wrote ${toolQualityCompletionFileName}`);
  console.log(`tools: ${document.entries.length}`);
  console.log(`patches: ${patchCount}`);
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) await run();
