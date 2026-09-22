import type { I18nText, NavItem } from '../types';

// 树叶子自动分组：当同一层级的叶子条目过多时，按标题关键词插入一层虚拟分组节点，
// 避免一棵子树下面平铺几十个叶子无法定位。虚拟分组只在渲染层生效，不改动导航数据。

const LEAF_GROUP_THRESHOLD = 15;

interface GroupRule {
  match: RegExp;
  zh: string;
  en: string;
}

const PAYLOAD_GROUP_RULES: GroupRule[] = [
  { match: /^mysql|mysql/i, zh: 'MySQL', en: 'MySQL' },
  { match: /sql server|mssql/i, zh: 'SQL Server', en: 'SQL Server' },
  { match: /postgres/i, zh: 'PostgreSQL', en: 'PostgreSQL' },
  { match: /oracle/i, zh: 'Oracle', en: 'Oracle' },
  { match: /sqlite/i, zh: 'SQLite', en: 'SQLite' },
  { match: /mongo|nosql|redis|memcached/i, zh: 'NoSQL 与缓存', en: 'NoSQL & Cache' },
  { match: /ldap|xpath|graphql|orm/i, zh: '其他注入面', en: 'Other Injection Surfaces' },
  { match: /outfile|dumpfile|load_file|attach|文件读取|文件写入|写文件/i, zh: '文件读写', en: 'File Read & Write' },
  { match: /盲注|时间|延迟|waitfor|pg_sleep|谓词/i, zh: '盲注与时间探测', en: 'Blind & Time-based' },
  { match: /waf|绕过|规范化|编码变体|分词|填充|全角|替代/i, zh: 'WAF 绕过与变体', en: 'WAF Bypass Variants' },
  { match: /chunked|multipart|json.*载体|http|websocket|参数载体/i, zh: 'HTTP 载体', en: 'HTTP Carriers' },
  { match: /堆叠|事务/i, zh: '堆叠与事务', en: 'Stacked & Transactions' },
];

const TOOL_GROUP_RULES: GroupRule[] = [
  { match: /nmap|masscan|rustscan|zmap/i, zh: '端口与服务扫描', en: 'Port & Service Scans' },
  { match: /gobuster|ffuf|ferox|dirsearch|dirb|wfuzz/i, zh: '目录与内容发现', en: 'Directory Discovery' },
  { match: /subfinder|amass|subdomain|assetfinder|dns|massdns|dnsx/i, zh: '子域与 DNS', en: 'Subdomain & DNS' },
  { match: /whatweb|wafw00f|fingerprint|nikto/i, zh: '指纹与识别', en: 'Fingerprinting' },
  { match: /nuclei|katana|hakrawler|gau|wayback|crawl/i, zh: '扫描与爬取', en: 'Scanning & Crawling' },
  { match: /httpx|curl|requests/i, zh: 'HTTP 探测', en: 'HTTP Probing' },
];

const isLeaf = (item: NavItem): boolean => !item.children || item.children.length === 0;

const matchesRule = (name: I18nText, rule: RegExp): boolean =>
  rule.test(typeof name === 'string' ? name : `${name.zh}\n${name.en}`);

const buildVirtualGroup = (
  parent: NavItem,
  slug: string,
  name: I18nText,
  leaves: NavItem[],
): NavItem => ({
  id: `${parent.id}::group-${slug}`,
  name,
  children: leaves.map(leaf => ({
    ...leaf,
    id: `${parent.id}::group-${slug}:${leaf.id}`,
  })),
});

const groupWithRules = (parent: NavItem, leaves: NavItem[], rules: GroupRule[]): NavItem[] => {
  const buckets = new Map<string, { name: { zh: string; en: string }; leaves: NavItem[] }>();
  const fallback: NavItem[] = [];
  for (const leaf of leaves) {
    const rule = rules.find(candidate => matchesRule(leaf.name, candidate.match));
    if (!rule) {
      fallback.push(leaf);
      continue;
    }
    const bucket = buckets.get(rule.zh) ?? { name: { zh: rule.zh, en: rule.en }, leaves: [] };
    bucket.leaves.push(leaf);
    buckets.set(rule.zh, bucket);
  }
  const groups: NavItem[] = [];
  for (const [, bucket] of buckets) {
    groups.push(buildVirtualGroup(parent, bucket.name.zh, bucket.name, bucket.leaves));
  }
  // 关键词未覆盖的叶子并入一个"其他"组，保持总数守恒、查找路径一致。
  if (fallback.length > 0) {
    groups.push(buildVirtualGroup(parent, 'other', { zh: '其他', en: 'Others' }, fallback));
  }
  return groups;
};

export const groupDenseLeaves = (
  parent: NavItem,
  children: NavItem[],
  kind: 'payload' | 'tool',
): NavItem[] => {
  // 虚拟分组节点内部不再嵌套分组。
  if (parent.id.includes('::group-')) return children;
  const leaves = children.filter(isLeaf);
  if (leaves.length < LEAF_GROUP_THRESHOLD) return children;
  if (leaves.length === children.length) {
    // 整层都是叶子：直接整层分组。
    return kind === 'payload'
      ? groupWithRules(parent, leaves, PAYLOAD_GROUP_RULES)
      : groupWithRules(parent, leaves, TOOL_GROUP_RULES);
  }
  // 混合层：仅把连续的叶子段包进虚拟分组，组节点保持原位。
  const result: NavItem[] = [];
  let segment: NavItem[] = [];
  const flush = () => {
    if (segment.length < LEAF_GROUP_THRESHOLD) {
      result.push(...segment);
    } else {
      result.push(...groupWithRules(parent, segment, kind === 'payload' ? PAYLOAD_GROUP_RULES : TOOL_GROUP_RULES));
    }
    segment = [];
  };
  for (const child of children) {
    if (isLeaf(child)) {
      segment.push(child);
    } else {
      flush();
      result.push(child);
    }
  }
  flush();
  return result;
};
