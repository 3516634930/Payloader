export type Language = 'zh' | 'en';

const translations = {
  // === Header ===
  'header.logo': { zh: 'PAYLOADER', en: 'PAYLOADER' },
  'header.subtitle': { zh: '渗透测试辅助平台', en: 'Pentest Assistance Platform' },
  'header.searchPlaceholder': { zh: '搜索 Payload / 工具 / 标签...', en: 'Search Payload / Tool / Tag...' },
  'header.tabPayloads': { zh: '💀 渗透Payload', en: '💀 Payloads' },
  'header.tabTools': { zh: '🛠️ 工具命令', en: '🛠️ Tools' },
  'header.themeToggleDark': { zh: '切换到亮色模式', en: 'Switch to Light Mode' },
  'header.themeToggleLight': { zh: '切换到暗色模式', en: 'Switch to Dark Mode' },
  'header.encoding': { zh: '🔐 编解码', en: '🔐 Codec' },
  'header.encodingTitle': { zh: '打开编解码工具', en: 'Open Encoding Tools' },
  'header.modeLabel': { zh: '模式:', en: 'Mode:' },
  'header.modeNormal': { zh: '标准', en: 'Normal' },
  'header.modeWaf': { zh: 'WAF绕过', en: 'WAF Bypass' },
  'header.modeEdr': { zh: 'EDR免杀', en: 'EDR Evasion' },
  'header.variables': { zh: '🔧 全局变量', en: '🔧 Variables' },
  'header.variablesTitle': { zh: '全局动态变量', en: 'Global Dynamic Variables' },
  'header.variablesHint': { zh: '在Payload中使用 {变量名} 自动替换', en: 'Use {VAR_NAME} in Payload for auto-replacement' },
  'header.encodingModalTitle': { zh: '🔐 智能编解码工具', en: '🔐 Smart Encoding Tools' },
  'header.copyright': { zh: '© Payloader - 渗透测试辅助平台', en: '© Payloader - Pentest Assistance Platform' },

  // === Sidebar ===
  'sidebar.attackCategories': { zh: '攻击分类', en: 'Attack Categories' },
  'sidebar.toolCategories': { zh: '工具分类', en: 'Tool Categories' },
  'sidebar.searchFound': { zh: '找到 {count} 个结果', en: 'Found {count} results' },
  'sidebar.noResults': { zh: '没有找到匹配的结果', en: 'No matching results found' },
  'sidebar.noResultsHint': { zh: '尝试不同的关键词', en: 'Try different keywords' },

  // === MainContent (empty state) ===
  'main.selectPayload': { zh: '选择一个Payload', en: 'Select a Payload' },
  'main.selectPayloadHint': { zh: '从左侧导航树中选择一个攻击类型查看详细信息', en: 'Select an attack type from the sidebar to view details' },
  'main.quickTips': { zh: '快速提示', en: 'Quick Tips' },
  'main.tip1': { zh: '💡 使用顶部全局变量可以快速替换Payload中的参数', en: '💡 Use global variables at the top to quickly replace Payload parameters' },
  'main.tip2': { zh: '🛡️ 切换WAF/EDR绕过模式获取免杀Payload', en: '🛡️ Switch WAF/EDR bypass mode for evasion Payloads' },
  'main.tip3': { zh: '📋 点击Payload可复制到剪贴板', en: '📋 Click Payload to copy to clipboard' },
  'main.tip4': { zh: '📖 每个Payload都有详细的语法解析和教学', en: '📖 Each Payload has detailed syntax analysis and tutorial' },
  'main.selectTool': { zh: '选择一个工具', en: 'Select a Tool' },
  'main.selectToolHint': { zh: '从左侧导航树中选择一个工具查看命令详情', en: 'Select a tool from the sidebar to view command details' },
  'main.toolCategories': { zh: '工具分类', en: 'Tool Categories' },
  'main.toolCat1': { zh: '🔍 信息收集 - Nmap, Gobuster, MassDNS等', en: '🔍 Recon - Nmap, Gobuster, MassDNS, etc.' },
  'main.toolCat2': { zh: '🌐 Web渗透 - SQLMap, Burp Suite, Nikto等', en: '🌐 Web Pentest - SQLMap, Burp Suite, Nikto, etc.' },
  'main.toolCat3': { zh: '💥 漏洞利用 - Metasploit, Searchsploit等', en: '💥 Exploitation - Metasploit, Searchsploit, etc.' },
  'main.toolCat4': { zh: '🔐 密码攻击 - Hydra, John, Hashcat等', en: '🔐 Password Attacks - Hydra, John, Hashcat, etc.' },
  'main.toolCat5': { zh: '🏢 内网渗透 - CrackMapExec, Impacket等', en: '🏢 Internal - CrackMapExec, Impacket, etc.' },

  // === PayloadDetail ===
  'payload.notFound': { zh: 'Payload未找到', en: 'Payload Not Found' },
  'payload.category': { zh: '分类', en: 'Category' },
  'payload.subCategory': { zh: '子分类', en: 'Sub-category' },
  'payload.difficulty': { zh: '难度', en: 'Difficulty' },
  'payload.prerequisites': { zh: '📋 前置条件', en: '📋 Prerequisites' },
  'payload.tabExecution': { zh: '💻 执行命令', en: '💻 Execution' },
  'payload.tabChain': { zh: '🔗 攻击链', en: '🔗 Attack Chain' },
  'payload.tabAnalysis': { zh: '📊 结果分析', en: '📊 Analysis' },
  'payload.tabTutorial': { zh: '📖 详细教学', en: '📖 Tutorial' },
  'payload.wafNotice': { zh: 'WAF绕过模式 - 使用编码和混淆技术绕过Web应用防火墙', en: 'WAF Bypass Mode - Using encoding and obfuscation to bypass WAF' },
  'payload.edrNotice': { zh: 'EDR免杀模式 - 使用免杀技术绕过终端检测响应系统', en: 'EDR Evasion Mode - Using evasion techniques to bypass EDR' },
  'payload.copyAll': { zh: '📋 一键复制全部命令', en: '📋 Copy All Commands' },
  'payload.copiedAll': { zh: '✓ 已复制全部命令', en: '✓ All Commands Copied' },
  'payload.steps': { zh: '{count} 个步骤', en: '{count} steps' },
  'payload.allPlatforms': { zh: '🌐 全平台', en: '🌐 All Platforms' },
  'payload.windows': { zh: '🪟 Windows', en: '🪟 Windows' },
  'payload.linux': { zh: '🐧 Linux', en: '🐧 Linux' },
  'payload.requiresAdmin': { zh: '⚠️ 需要管理员权限', en: '⚠️ Requires Admin' },
  'payload.syntaxAnalysis': { zh: '📖 语法解析', en: '📖 Syntax Analysis' },
  'payload.copy': { zh: '📋 复制', en: '📋 Copy' },
  'payload.copied': { zh: '✓ 已复制', en: '✓ Copied' },
  'payload.chainTitle': { zh: '🔗 攻击链可视化', en: '🔗 Attack Chain Visualization' },
  'payload.chainDesc': { zh: '展示从侦察到利用的完整攻击流程，每个节点代表一个执行步骤', en: 'Shows the complete attack flow from recon to exploitation, each node represents an execution step' },
  'payload.analysisTitle': { zh: '📊 预期结果分析', en: '📊 Expected Result Analysis' },
  'payload.noAnalysis': { zh: '暂无分析信息', en: 'No analysis available' },
  'payload.opsecTitle': { zh: '⚠️ OpSec提示', en: '⚠️ OpSec Tips' },
  'payload.referencesTitle': { zh: '🔗 参考资料', en: '🔗 References' },
  'payload.tutOverview': { zh: '📚 概述', en: '📚 Overview' },
  'payload.tutVulnerability': { zh: '🔓 漏洞原理', en: '🔓 Vulnerability Principle' },
  'payload.tutExploitation': { zh: '⚔️ 利用方法', en: '⚔️ Exploitation Method' },
  'payload.tutMitigation': { zh: '🛡️ 防御措施', en: '🛡️ Mitigation' },

  // === ToolDetail ===
  'tool.notFound': { zh: '工具未找到', en: 'Tool Not Found' },
  'tool.category': { zh: '分类', en: 'Category' },
  'tool.installation': { zh: '📦 安装方法', en: '📦 Installation' },
  'tool.commands': { zh: '💻 常用命令', en: '💻 Common Commands' },
  'tool.references': { zh: '🔗 参考资料', en: '🔗 References' },
  'tool.examples': { zh: '示例说明:', en: 'Examples:' },

  // === EncodingTools ===
  'encoding.title': { zh: '🔧 智能编解码工具', en: '🔧 Smart Encoding Tools' },
  'encoding.description': { zh: '支持多种编码格式的实时转换，助力渗透测试中的Payload编码需求', en: 'Real-time encoding format conversion for pentest Payload encoding needs' },
  'encoding.input': { zh: '输入', en: 'Input' },
  'encoding.output': { zh: '输出', en: 'Output' },
  'encoding.clear': { zh: '清空', en: 'Clear' },
  'encoding.encode': { zh: '编码 →', en: 'Encode →' },
  'encoding.swap': { zh: '⇄ 交换', en: '⇄ Swap' },
  'encoding.decode': { zh: '← 解码', en: '← Decode' },
  'encoding.copied': { zh: '✓ 已复制', en: '✓ Copied' },
  'encoding.copy': { zh: '📋 复制', en: '📋 Copy' },
  'encoding.usageTitle': { zh: '💡 使用说明', en: '💡 Usage Guide' },
  'encoding.jwtNoEncode': { zh: 'JWT不支持编码，请使用解码功能', en: 'JWT encoding not supported, use decode instead' },
  'encoding.encodeFailed': { zh: '编码失败: ', en: 'Encoding failed: ' },
  'encoding.decodeFailed': { zh: '解码失败: ', en: 'Decoding failed: ' },
  'encoding.invalidJwt': { zh: '无效的JWT格式', en: 'Invalid JWT format' },
  'encoding.resultPlaceholder': { zh: '转换结果将显示在这里...', en: 'Conversion result will appear here...' },
  'encoding.urlName': { zh: 'URL编码', en: 'URL Encode' },
  'encoding.urlDesc': { zh: 'URL编码/解码', en: 'URL encode/decode' },
  'encoding.base64Name': { zh: 'Base64', en: 'Base64' },
  'encoding.base64Desc': { zh: 'Base64编码/解码', en: 'Base64 encode/decode' },
  'encoding.hexName': { zh: 'Hex十六进制', en: 'Hex' },
  'encoding.hexDesc': { zh: '十六进制编码/解码', en: 'Hexadecimal encode/decode' },
  'encoding.htmlName': { zh: 'HTML实体', en: 'HTML Entity' },
  'encoding.htmlDesc': { zh: 'HTML实体编码/解码', en: 'HTML entity encode/decode' },
  'encoding.unicodeName': { zh: 'Unicode', en: 'Unicode' },
  'encoding.unicodeDesc': { zh: 'Unicode编码/解码', en: 'Unicode encode/decode' },
  'encoding.jwtName': { zh: 'JWT解码', en: 'JWT Decode' },
  'encoding.jwtDesc': { zh: 'JWT Token解析', en: 'JWT Token parsing' },
  'encoding.urlHelp': { zh: 'URL编码将特殊字符转换为%XX格式，常用于绕过WAF对特殊字符的过滤。', en: 'URL encoding converts special characters to %XX format, commonly used to bypass WAF character filtering.' },
  'encoding.base64Help': { zh: 'Base64是一种二进制到文本的编码方案，常用于数据传输和简单的混淆。', en: 'Base64 is a binary-to-text encoding scheme, commonly used for data transfer and simple obfuscation.' },
  'encoding.hexHelp': { zh: '十六进制编码将每个字节转换为两位十六进制字符，常用于Shellcode编码。', en: 'Hex encoding converts each byte to two hex characters, commonly used for shellcode encoding.' },
  'encoding.htmlHelp': { zh: 'HTML实体编码将特殊字符转换为HTML实体，常用于XSS绕过。', en: 'HTML entity encoding converts special characters to HTML entities, commonly used for XSS bypass.' },
  'encoding.unicodeHelp': { zh: 'Unicode编码将字符转换为\\uXXXX格式，常用于绕过字符过滤。', en: 'Unicode encoding converts characters to \\uXXXX format, commonly used to bypass character filtering.' },
  'encoding.jwtHelp': { zh: 'JWT解码器可以解析JWT Token的Header和Payload部分（不验证签名）。', en: 'JWT decoder can parse JWT Token Header and Payload sections (without signature verification).' },
  'encoding.inputPlaceholder': { zh: '输入要编码/解码的内容...', en: 'Enter content to encode/decode...' },
  'encoding.inputPlaceholderJwt': { zh: '输入要解码的JWT Token...', en: 'Enter JWT Token to decode...' },

  // === SyntaxModal ===
  'syntax.title': { zh: '📖 语法解析 - ', en: '📖 Syntax Analysis - ' },
  // SyntaxPart type names
  'syntax.command': { zh: '命令', en: 'Command' },
  'syntax.parameter': { zh: '参数', en: 'Parameter' },
  'syntax.value': { zh: '值', en: 'Value' },
  'syntax.operator': { zh: '操作符', en: 'Operator' },
  'syntax.variable': { zh: '变量', en: 'Variable' },
  'syntax.header': { zh: 'HTTP头', en: 'HTTP Header' },
  'syntax.method': { zh: '方法', en: 'Method' },
  'syntax.domain': { zh: '域名', en: 'Domain' },
  'syntax.path': { zh: '路径', en: 'Path' },
  'syntax.tag': { zh: '标签', en: 'Tag' },
  'syntax.json': { zh: 'JSON', en: 'JSON' },
  'syntax.encoding': { zh: '编码', en: 'Encoding' },
  'syntax.technique': { zh: '技术', en: 'Technique' },
  'syntax.format': { zh: '格式', en: 'Format' },
  'syntax.function': { zh: '函数', en: 'Function' },
  'syntax.keyword': { zh: '关键字', en: 'Keyword' },
  'syntax.concept': { zh: '概念', en: 'Concept' },
  'syntax.char': { zh: '字符', en: 'Character' },
  'syntax.tool-mode': { zh: '工具模式', en: 'Tool Mode' },
  'syntax.other': { zh: '其他', en: 'Other' },

  // === Global variable descriptions ===
  'var.targetIp': { zh: '目标IP地址', en: 'Target IP Address' },
  'var.targetDomain': { zh: '目标域名', en: 'Target Domain' },
  'var.attackerIp': { zh: '攻击者IP', en: 'Attacker IP' },
  'var.username': { zh: '用户名', en: 'Username' },
  'var.password': { zh: '密码', en: 'Password' },
  'var.domain': { zh: '域名', en: 'Domain' },

  // === Language toggle ===
  'lang.toggle': { zh: '中文/EN', en: 'EN/中文' },
  'lang.toggleTitle': { zh: 'Switch to English', en: '切换到中文' },
} as const;

export type TranslationKey = keyof typeof translations;

export function t(key: TranslationKey, lang: Language, params?: Record<string, string | number>): string {
  const entry = translations[key];
  if (!entry) return key;
  let text = entry[lang] || entry['zh'];
  if (params) {
    for (const [pk, pv] of Object.entries(params)) {
      text = text.replace(`{${pk}}`, String(pv));
    }
  }
  return text;
}

/** Resolve an I18nText value (string | { zh, en }) to a plain string for the given language */
export function getText(value: string | { zh: string; en: string } | undefined | null, lang: Language): string {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  return value[lang] || value.zh || '';
}
