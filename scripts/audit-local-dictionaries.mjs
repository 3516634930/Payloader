import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

import { getPublicData } from '../server/data-store.mjs';

const dictionaryRoot = process.argv[2] || 'F:\\Safety\\字典\\payload字典大全';

const text = value => {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') return value.zh || value.en || '';
  return '';
};

const payloadSearchText = payload => [
  payload.id,
  text(payload.name),
  text(payload.category),
  text(payload.subCategory),
  text(payload.description),
  ...(Array.isArray(payload.tags) ? payload.tags : []),
].join(' ').toLowerCase();

const includesAny = (value, needles) => needles.some(needle => value.includes(needle));

const dictionaryMatchers = [
  {
    file: '01-SQL与XPath注入',
    topic: 'SQL / XPath 注入',
    match: payload => includesAny(payloadSearchText(payload), ['sqli', 'sql', 'nosql', 'xpath', 'mongodb', 'redis']),
  },
  {
    file: '02-XSS跨站脚本大全',
    topic: 'XSS 与浏览器脚本执行',
    match: payload => includesAny(payloadSearchText(payload), ['xss', 'beef', 'clickjacking']),
  },
  {
    file: '03-文件上传',
    topic: '文件上传与解析链',
    match: payload => includesAny(payloadSearchText(payload), ['file-upload', 'webshell', '文件上传', '上传', 'mime', 'zip-slip']),
  },
  {
    file: '04-命令注入与SSRF',
    topic: '命令注入与 SSRF',
    match: payload => includesAny(payloadSearchText(payload), ['command-injection', 'rce', 'ssrf', 'gopher', 'dict协议', '命令注入']),
  },
  {
    file: '05-SSTI与XXE',
    topic: 'SSTI 与 XXE',
    match: payload => includesAny(payloadSearchText(payload), ['ssti', 'xxe', 'freemarker', 'thymeleaf', 'velocity', 'jinja2', 'xmldecoder']),
  },
  {
    file: '06-HTTP请求绕过大全',
    topic: 'HTTP 解析与边界绕过',
    match: payload => includesAny(payloadSearchText(payload), ['smuggling', 'cache', 'redirect', 'cors', 'csrf', 'proxy', 'header', 'http']),
  },
  {
    file: '07-WebShell与服务端利用',
    topic: '服务端利用与高风险脚本主题',
    match: payload => includesAny(payloadSearchText(payload), ['weblogic', 'spring', 'struts', 'thinkphp', 'laravel', 'tomcat', 'jboss', 'deserialize', 'webshell']),
  },
  {
    file: '08-认证与Token攻击',
    topic: '认证、授权与 Token',
    match: payload => includesAny(payloadSearchText(payload), ['jwt', 'auth-', 'oauth', 'saml', '2fa', 'remember-me', 'session', 'noauth']),
  },
  {
    file: '09-注入大全',
    topic: '综合注入主题',
    match: payload => includesAny(payloadSearchText(payload), ['injection', '注入', 'graphql', 'sql', 'ssti', 'xxe', 'prompt']),
  },
  {
    file: '10-业务逻辑与高级攻击',
    topic: '业务逻辑与流程边界',
    match: payload => includesAny(payloadSearchText(payload), ['biz-', '业务逻辑', 'idor', 'payment', 'workflow', 'coupon', 'price']),
  },
  {
    file: '11-AI安全与Prompt注入',
    topic: 'AI 安全与提示注入',
    match: payload => includesAny(payloadSearchText(payload), ['ai-', 'prompt', 'llm', 'rag', '模型', 'agent']),
  },
  {
    file: '13-注入新方向',
    topic: '现代应用与新型注入面',
    match: payload => includesAny(payloadSearchText(payload), ['prototype', 'websocket', 'cloud', 'graphql', 'modern', 'api-']),
  },
  {
    file: '14-浏览器安全',
    topic: '浏览器与前端边界',
    match: payload => includesAny(payloadSearchText(payload), ['浏览器', 'xss', 'cors', 'clickjacking', 'csrf', 'cookie', 'dom']),
  },
  {
    file: '15-API安全测试',
    topic: 'API、GraphQL 与对象授权',
    match: payload => includesAny(payloadSearchText(payload), ['api-', 'graphql', 'rest api', 'jwt', 'oauth', 'idor', 'bola']),
  },
  {
    file: '16-高级服务端攻击',
    topic: '高级服务端与框架组件',
    match: payload => includesAny(payloadSearchText(payload), ['weblogic', 'shiro', 'fastjson', 'spring', 'tomcat', 'jboss', 'log4j', 'xmldecoder']),
  },
];

const readHeadings = async filePath => {
  try {
    const source = await readFile(filePath, 'utf8');
    return source
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line.startsWith('#'))
      .slice(0, 6);
  } catch {
    return [];
  }
};

const main = async () => {
  const data = await getPublicData();
  const payloads = Array.isArray(data.payloads) ? data.payloads : [];
  const files = (await readdir(dictionaryRoot))
    .filter(name => name.toLowerCase().endsWith('.txt'))
    .sort((a, b) => a.localeCompare(b, 'zh-CN'));

  const report = [];
  for (const file of files) {
    const matcher = dictionaryMatchers.find(item => file.startsWith(item.file));
    const matched = matcher ? payloads.filter(payload => matcher.match(payload)) : [];
    const headings = await readHeadings(path.join(dictionaryRoot, file));
    report.push({
      file,
      topic: matcher?.topic || '未建立映射',
      matchedCount: matched.length,
      samplePayloads: matched.slice(0, 12).map(payload => ({
        id: payload.id,
        name: text(payload.name),
        category: text(payload.category),
      })),
      headings,
      note: 'This audit intentionally reports topic coverage only and does not import raw payload strings.',
    });
  }

  const uncovered = report
    .filter(item => item.matchedCount === 0)
    .map(item => ({ file: item.file, topic: item.topic }));

  console.log(JSON.stringify({
    dictionaryRoot,
    payloadCount: payloads.length,
    reports: report,
    uncovered,
  }, null, 2));
};

await main();
