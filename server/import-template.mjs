// 导入模板生成（纯模板，自 data-store.mjs 机械迁移）：createImportTemplate 输出 payloader.import.v1 格式样例。
// 零 db 与 IO 依赖，独立可测。

const now = () => new Date().toISOString();

const importArrayLimits = {
  payloads: 10_000,
  tools: 10_000,
  navigation: 2_000,
  toolNavigation: 2_000,
};
const maxImportNavigationNodes = 20_000;
const maxImportNavigationDepth = 12;

const importSummary = normalized => ([
  { key: 'payloads', label: 'Payload', included: normalized.included.payloads, count: normalized.payloads.length },
  { key: 'tools', label: '工具命令', included: normalized.included.tools, count: normalized.tools.length },
  { key: 'navigation', label: 'Payload 导航', included: normalized.included.navigation, count: normalized.navigation.length },
  { key: 'toolNavigation', label: '工具导航', included: normalized.included.toolNavigation, count: normalized.toolNavigation.length },
]);

export const createImportTemplate = () => ({
  format: 'payloader.import.v1',
  generatedAt: now(),
  guide: {
    title: 'Payloader 导入模板填写说明',
    summary: '导入文件必须是一个 JSON 对象。真正会导入的只有 payloads、tools、navigation、toolNavigation 四个数组；guide、fieldReference、limits、instructions 这些说明字段会被后台忽略，可以保留也可以删除。',
    steps: [
      '1. 保留 format 为 payloader.import.v1。',
      '2. 在 payloads 数组里写 Payload 数据；在 tools 数组里写工具命令数据。',
      '3. 如果想让左侧导航出现这些数据，需要同时在 navigation 或 toolNavigation 里添加节点，并用 payloadId/toolId 指向对应 id。',
      '4. 一个文件可以一次写很多条数据；数组里每个对象就是一条记录。',
      '5. 上传前先点“预览文件”，确认数量和提醒没有问题后再执行导入。',
    ],
    importModes: {
      merge: '合并更新：id 已存在就更新这条数据，id 不存在就新增。',
      replace: '覆盖所选模块：只覆盖导入文件中出现的模块。例如文件里只有 payloads，就只覆盖 Payload 数据，不会动 tools。',
    },
    i18nTextFormat: {
      description: '所有显示文本字段都支持两种写法，推荐使用中英双语对象。',
      simpleString: '只写字符串时会被当作中文，例如 "SQL 注入"。',
      bilingualObject: '推荐写成 {"zh":"中文","en":"English"}，前台切换语言时会自动显示对应语言。',
    },
    dynamicVariables: {
      description: 'Payload 命令和工具命令可以直接使用全局变量，占位符会在前台展示和复制时自动替换。',
      examples: ['{URL}', '{TARGET}', '{PATH}', '{PARAM}', '{PARAM_VALUE}', '{COOKIE}', '{HEADER_AUTH}', '{ATTACKER_IP}', '{LPORT}', '{WORDLIST}'],
      exampleCommand: 'curl -sk "{URL}" -H "Cookie: {COOKIE}" -H "{HEADER_AUTH}"',
    },
    commonMistakes: [
      'payloads、tools、navigation、toolNavigation 必须是数组，不能写成对象。',
      'payload.execution 和 tool.commands 也必须是数组。',
      'navigation 子节点要写 payloadId，值必须等于 payloads 里某条数据的 id。',
      'toolNavigation 子节点要写 toolId，值必须等于 tools 里某条数据的 id。',
      'platform 只能写 all、windows、linux；不写会默认 all。',
      'tutorial.difficulty 只能写 beginner、intermediate、advanced、expert。',
      'JSON 不能有注释、不能有多余逗号；多行命令请使用 \\n 换行。',
      '站点标题、Logo、GitHub、Xeye 等平台信息不会导入，不要写 settings。',
    ],
  },
  fieldReference: {
    topLevel: {
      format: '可选但建议保留，固定写 payloader.import.v1。',
      payloads: 'Payload 数组，可省略；每一项是一条前台 Payload。',
      tools: '工具命令数组，可省略；每一项是一个工具，工具下面可以有多条 commands。',
      navigation: 'Payload 左侧导航树，可省略；通过 payloadId 关联 payloads.id。',
      toolNavigation: '工具左侧导航树，可省略；通过 toolId 关联 tools.id。',
    },
    payload: {
      required: ['id', 'name', 'description', 'category', 'execution'],
      optional: ['subCategory', 'tags', 'prerequisites', 'analysis', 'opsecTips', 'wafBypass', 'attackChain', 'references', 'tutorial'],
      id: '唯一 ID，只建议使用英文、数字、短横线，例如 sqli-custom-login。',
      execution: '标准模式 Payload 列表，数组；每项必须有 title 和 command。',
      wafBypass: 'WAF 绕过模式 Payload 列表，数组；结构和 execution 一样。',
      attackChain: '攻击链步骤，数组；payload 字段可放关联命令，前台可复制。',
    },
    payloadExecution: {
      title: '命令标题，I18nText。',
      command: '可直接复制的 Payload 或命令字符串，支持 {URL} 等变量。',
      description: '命令用途说明，I18nText。',
      platform: 'all、windows、linux 之一。',
      requiresAdmin: '是否需要管理员权限，true 或 false。',
      syntaxBreakdown: '语法解析数组，可为空；part 是要解释的片段，explanation 是说明，type 是展示类型。',
    },
    tutorial: {
      overview: '漏洞或攻击方式概述，I18nText。',
      vulnerability: '原理说明，I18nText。',
      exploitation: '使用方法或验证流程，I18nText。',
      mitigation: '防护建议，I18nText。',
      difficulty: 'beginner、intermediate、advanced、expert 之一。',
    },
    tool: {
      required: ['id', 'name', 'description', 'category', 'commands'],
      optional: ['installation', 'references'],
      commands: '工具命令数组；每项必须有 name、command、description。',
      note: '系统内置 XSS 平台不可通过导入覆盖，也不要写 externalUrl。',
    },
    navigationNode: {
      id: '导航节点唯一 ID。',
      name: '导航显示名称，I18nText。',
      icon: '可选图标字符。',
      children: '子节点数组。',
      payloadId: 'Payload 导航叶子节点使用，必须等于 payloads 中某条 id。',
      toolId: '工具导航叶子节点使用，必须等于 tools 中某条 id。',
    },
  },
  limits: {
    maxFileSize: '20 MiB',
    maxPayloads: importArrayLimits.payloads,
    maxTools: importArrayLimits.tools,
    maxNavigationRoots: importArrayLimits.navigation,
    maxToolNavigationRoots: importArrayLimits.toolNavigation,
    maxNavigationNodes: maxImportNavigationNodes,
    maxNavigationDepth: maxImportNavigationDepth,
  },
  instructions: [
    '下载后按示例结构填写数据，再在后台“导入数据”中选择此 JSON 文件。',
    '模板只导入 Payload、工具命令、Payload 导航和工具导航；站点标题、Logo、GitHub/Xeye 等平台信息不会被导入。',
    'payloads、tools、navigation、toolNavigation 都是数组，可以一次放入多条数据；大批量导入请先预览确认数量。',
    '导入支持“合并更新”和“覆盖所选模块”：覆盖只会覆盖文件里包含的模块。',
    'id 用来判断更新同一条数据；新 id 会新增记录，重复 id 会自动改名并给出提示。',
    '命令里建议使用 {URL}、{COOKIE}、{ATTACKER_IP} 等全局变量；前台展示和复制时会自动替换。',
    '如果不需要导入某个模块，可以删除对应数组字段，或保留空数组。',
  ],
  payloads: [
    {
      id: 'sqli-login-example',
      name: { zh: 'SQL 注入登录参数示例', en: 'SQL injection login parameter example' },
      description: { zh: '用于演示如何导入一组可复制、可切换变量的 SQL 注入测试 Payload。', en: 'Shows how to import copyable SQL injection payloads with dynamic variables.' },
      category: { zh: 'Web 漏洞', en: 'Web vulnerabilities' },
      subCategory: { zh: 'SQL 注入', en: 'SQL injection' },
      tags: ['sql-injection', 'login', 'template'],
      prerequisites: [{ zh: '确认测试 URL、参数名和授权范围。', en: 'Confirm test URL, parameter name, and authorized scope.' }],
      execution: [
        {
          title: { zh: '布尔盲注基础探测', en: 'Boolean-based probe' },
          command: '{PARAM_VALUE}\' AND \'1\'=\'1\n{PARAM_VALUE}\' AND \'1\'=\'2',
          description: { zh: '把当前参数值替换为真假条件，观察响应差异。', en: 'Replace the current parameter value with true/false conditions and compare responses.' },
          platform: 'all',
          requiresAdmin: false,
          syntaxBreakdown: [
            { part: '{PARAM_VALUE}', explanation: { zh: '参数值变量，可在前台全局变量里修改。', en: 'Parameter value variable from the global variable panel.' }, type: 'variable' },
            { part: 'AND', explanation: { zh: '拼接布尔条件。', en: 'Adds a boolean condition.' }, type: 'operator' },
          ],
        },
        {
          title: { zh: 'sqlmap 带参 URL', en: 'sqlmap URL with parameter' },
          command: 'sqlmap -u "{URL}" -p {PARAM} --batch --dbs',
          description: { zh: '直接使用全局 URL 和参数名变量。', en: 'Uses the global URL and parameter name variables directly.' },
          platform: 'all',
          requiresAdmin: false,
          syntaxBreakdown: [
            { part: '{URL}', explanation: { zh: '完整目标 URL，例如 https://target.com/api/users?id=1。', en: 'Full target URL, for example https://target.com/api/users?id=1.' }, type: 'variable' },
            { part: '{PARAM}', explanation: { zh: '指定注入参数名。', en: 'Specifies the injectable parameter name.' }, type: 'variable' },
          ],
        },
      ],
      analysis: { zh: '如果真假条件响应长度、状态码、内容或时间差异稳定，说明该参数可能进入 SQL 查询。', en: 'Stable differences in response length, status code, content, or timing suggest the parameter may reach a SQL query.' },
      opsecTips: [{ zh: '只在授权环境和测试账号上使用，先从只读探测开始。', en: 'Use only in authorized environments and start with read-only probes.' }],
      wafBypass: [
        {
          title: { zh: '大小写和注释变体', en: 'Case and comment variant' },
          command: '{PARAM_VALUE}\'/**/AnD/**/\'1\'/**/=/**/\'1',
          description: { zh: 'WAF 绕过模式下展示的变体示例。', en: 'Example variant shown in WAF bypass mode.' },
          platform: 'all',
          requiresAdmin: false,
          syntaxBreakdown: [],
        },
      ],
      attackChain: [
        {
          title: { zh: '确认入口', en: 'Confirm entry point' },
          description: { zh: '先用 {URL} 确认参数 {PARAM} 可控，并记录正常响应。', en: 'Use {URL} to confirm {PARAM} is controllable and record the normal response.' },
          payload: 'curl -sk "{URL}" -H "Cookie: {COOKIE}"',
        },
        {
          title: { zh: '复制 Payload 验证差异', en: 'Copy payloads and compare differences' },
          description: { zh: '从 Payload 列表复制真假条件，替换参数值后比较响应。', en: 'Copy true/false conditions from the payload list, replace the parameter value, and compare responses.' },
        },
      ],
      references: ['https://example.com/reference'],
      tutorial: {
        overview: { zh: 'SQL 注入通常发生在用户输入被拼接进 SQL 查询时。', en: 'SQL injection usually happens when user input is concatenated into SQL queries.' },
        vulnerability: { zh: '根因是未使用参数化查询、输入类型校验不足或动态 SQL 拼接。', en: 'Root causes include missing parameterized queries, weak type validation, or dynamic SQL concatenation.' },
        exploitation: { zh: '先确认参数可控，再使用布尔、报错、时间或联合查询方式验证。', en: 'Confirm controllability first, then test boolean, error, time, or union-based techniques.' },
        mitigation: { zh: '使用参数化查询、最小权限数据库账号、输入类型约束和统一错误处理。', en: 'Use parameterized queries, least-privilege database accounts, strict input types, and consistent error handling.' },
        difficulty: 'beginner',
      },
    },
  ],
  tools: [
    {
      id: 'http-probe-example',
      name: { zh: 'HTTP 请求验证示例', en: 'HTTP request probe example' },
      description: { zh: '演示工具命令如何使用全局变量。', en: 'Shows how tool commands use global variables.' },
      category: { zh: 'Web 工具', en: 'Web tools' },
      installation: { zh: '系统自带 curl 或安装 curl。', en: 'Use system curl or install curl.' },
      commands: [
        {
          name: { zh: '携带 Cookie 请求', en: 'Request with cookie' },
          command: 'curl -sk "{URL}" -H "Cookie: {COOKIE}" -H "{HEADER_AUTH}" -A "{USER_AGENT}"',
          description: { zh: '使用全局 URL、Cookie、Authorization 和 User-Agent 变量。', en: 'Uses global URL, Cookie, Authorization, and User-Agent variables.' },
          platform: 'all',
          syntaxBreakdown: [
            { part: '{URL}', explanation: { zh: '完整目标 URL。', en: 'Full target URL.' }, type: 'variable' },
            { part: '{COOKIE}', explanation: { zh: '完整 Cookie 值。', en: 'Full Cookie value.' }, type: 'variable' },
          ],
          examples: [{ zh: 'curl -sk "{URL}" -H "Cookie: {COOKIE}"', en: 'curl -sk "{URL}" -H "Cookie: {COOKIE}"' }],
        },
      ],
      references: ['https://example.com/tool'],
    },
  ],
  navigation: [
    {
      id: 'nav-payload-example',
      name: { zh: 'Web 漏洞', en: 'Web vulnerabilities' },
      icon: '📁',
      children: [
        { id: 'nav-payload-example-item', name: { zh: 'SQL 注入登录参数示例', en: 'SQL injection login parameter example' }, payloadId: 'sqli-login-example' },
      ],
    },
  ],
  toolNavigation: [
    {
      id: 'nav-tool-example',
      name: { zh: 'Web 工具', en: 'Web tools' },
      icon: '🧰',
      children: [
        { id: 'nav-tool-example-item', name: { zh: 'HTTP 请求验证示例', en: 'HTTP request probe example' }, toolId: 'http-probe-example' },
      ],
    },
  ],
});

export { importArrayLimits, importSummary, maxImportNavigationDepth, maxImportNavigationNodes };
