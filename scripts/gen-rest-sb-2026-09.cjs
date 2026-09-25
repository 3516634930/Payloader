const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(path.resolve(process.cwd(), 'data/payloader.sqlite'), { readOnly: true });
const all = db.prepare('SELECT id, data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();

const cut = (cmd, probe) => {
  // 取命令中真实连续片段（按探测词定位，截其后 ~26 字符）
  const i = cmd.indexOf(probe);
  if (i < 0) return null;
  return cmd.slice(i, Math.min(cmd.length, i + 26)).replace(/\s+$/, '');
};
const firstLine = cmd => (cmd.split('\n')[0] || '').slice(0, 26);

function segments(cmd) {
  const segs = [];
  const has = (p) => cmd.includes(p);
  if (/^(POST|GET|PUT|DELETE|OPTIONS|PATCH) /.test(cmd) || /\r\n/.test(cmd)) {
    // 原始 HTTP 报文
    const m = /^([A-Z]+) (\S+)/.exec(cmd);
    if (m) segs.push({ part: firstLine(cmd), explanation: { zh: `${m[1]} 请求行与路径`, en: 'Request line and path' }, type: 'control' });
    if (has('\r\nHost:') || /\nHost:/.test(cmd)) segs.push({ part: cut(cmd, 'Host:'), explanation: { zh: 'Host 头指定目标', en: 'Host header' }, type: 'header' });
    for (const h of ['Content-Length', 'Transfer-Encoding', 'Content-Type', 'Cookie', 'Authorization', 'Referer', 'X-Forwarded-']) {
      if (cmd.includes(h)) { segs.push({ part: cut(cmd, h), explanation: { zh: `${h} 头`, en: `${h} header` }, type: 'header' }); break; }
    }
    const body = cmd.split('\n\n')[1];
    if (body) segs.push({ part: body.split('\n')[0].slice(0, 26), explanation: { zh: '请求体载荷', en: 'Request body payload' }, type: 'payload' });
    else if (cmd.includes('\n\n')) segs.push({ part: cut(cmd, '\n\n').trim().slice(0, 20), explanation: { zh: '报文体分隔后内容', en: 'Content after blank line' }, type: 'payload' });
  } else if (/^\s*curl/.test(cmd)) {
    segs.push({ part: cut(cmd, 'curl'), explanation: { zh: 'curl 发起请求', en: 'curl request' }, type: 'function' });
    const m = /-X\s+(GET|POST|PUT|DELETE|PATCH)/.exec(cmd);
    if (m) segs.push({ part: m[0], explanation: { zh: `${m[1]} 方法`, en: `${m[1]} method` }, type: 'flag' });
    const u = /https?:\/\/\S{1,30}/.exec(cmd);
    if (u) segs.push({ part: u[0], explanation: { zh: '目标 URL', en: 'Target URL' }, type: 'url' });
    const h = /-H\s+"[^"]{1,30}/.exec(cmd);
    if (h) segs.push({ part: h[0], explanation: { zh: '自定义请求头', en: 'Custom header' }, type: 'header' });
    const d = /-d\s+'{0,1}[^'\s]{1,24}/.exec(cmd);
    if (d) segs.push({ part: d[0], explanation: { zh: '请求体数据', en: 'Request body data' }, type: 'payload' });
  } else if (/^python3?\s/.test(cmd) || /\bpython3?\s+\S+\.py\b/.test(cmd)) {
    const t = /(\S+\.py)/.exec(cmd);
    if (t) segs.push({ part: t[1], explanation: { zh: '工具脚本', en: 'Tool script' }, type: 'function' });
    const flags = [...cmd.matchAll(/(-{1,2}[a-zA-Z][\w-]*)/g)].slice(0, 2);
    for (const fl of flags) segs.push({ part: fl[1], explanation: { zh: '工具参数', en: 'Tool flag' }, type: 'flag' });
    if (segs.length < 2) segs.push({ part: firstLine(cmd), explanation: { zh: '命令主体', en: 'Command body' }, type: 'control' });
  } else {
    segs.push({ part: firstLine(cmd), explanation: { zh: '载荷首行', en: 'Payload first line' }, type: 'payload' });
    const second = (cmd.split('\n')[1] || '').slice(0, 24);
    if (second) segs.push({ part: second, explanation: { zh: '载荷后续行', en: 'Payload next line' }, type: 'payload' });
    if (/<[a-zA-Z]+[\s>]/.test(cmd)) segs.push({ part: cut(cmd, '<').slice(0, 24), explanation: { zh: '标记结构', en: 'Markup structure' }, type: 'control' });
  }
  // 去重 + 限 2-6 段
  const seen = new Set();
  return segs.filter(s => s.part && s.part.length > 0 && !seen.has(s.part) && seen.add(s.part)).slice(0, 6);
}

const entriesById = new Map();
let count = 0;
for (const p of all) {
  for (const area of ['execution', 'wafBypass']) {
    for (const [i, step] of (p[area] || []).entries()) {
      if ((step.syntaxBreakdown || []).length) continue;
      const sb = segments(step.command || '');
      if (!sb.length) continue;
      if (!entriesById.has(p.id)) entriesById.set(p.id, { id: p.id, patches: [] });
      entriesById.get(p.id).patches.push({ area, index: i, expectedCommand: step.command, syntaxBreakdown: sb });
      count++;
    }
  }
}
const doc = { schemaVersion: 1, entries: [...entriesById.values()] };
fs.mkdirSync('output/content-audit/out-rest', { recursive: true });
fs.writeFileSync('output/content-audit/out-rest/sb.json', JSON.stringify(doc, null, 1));
console.log('程序化 SB 补写:', count, '步 /', doc.entries.length, '条');
