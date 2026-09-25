#!/usr/bin/env node
/** 生成 7 个审计包 dump：结构 + 组名 + desc + 命令首两行 + waf 数（供子代理只读审计）。 */
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const ROOT = path.resolve(__dirname, '..');
const db = new DatabaseSync(path.join(ROOT, 'data/payloader.sqlite'), { readOnly: true });
const trees = ['web', 'intranet'].map(id => JSON.parse(db.prepare('SELECT tree FROM navigation_nodes WHERE id = ?').get(id).tree));
const payloads = new Map(db.prepare('SELECT data FROM payloads').all().map(r => { const p = JSON.parse(r.data); return [p.id, p]; }));
db.close();

const PACKS = {
  'pack1-xss': ['XSS跨站脚本', '点击劫持', '开放重定向', 'WebSocket安全'],
  'pack2-rce': ['RCE远程代码执行', 'SSTI模板注入', 'LFI/RFI文件包含'],
  'pack3-ssrf': ['SSRF服务端请求伪造', 'XXE实体注入'],
  'pack4-auth': ['认证漏洞', 'JWT安全'],
  'pack5-api': ['API安全', '框架漏洞', 'CSRF跨站请求伪造', '缓存与CDN安全', '请求走私', 'Host Header安全', 'HTTP响应分割', '拒绝服务', '业务逻辑漏洞', '原型链污染'],
  'pack6-file-ai': ['文件漏洞', 'AI安全'],
  'pack7-intranet': ['Exchange攻击', '凭据窃取', '域渗透攻击', '横向移动', '权限提升', '权限维持', '终端防护规避'],
};
const zh = o => (o && typeof o === 'object' ? (o.zh || '') : o) || '';
const cmdsOf = p => (Array.isArray(p.execution) ? p.execution : []).map(e => String(typeof e === 'string' ? e : (e?.command || '')));

for (const [pack, branches] of Object.entries(PACKS)) {
  const out = [];
  for (const tree of trees) {
    for (const branch of (tree.children || [])) {
      if (!branches.includes(zh(branch.name))) continue;
      out.push('# ' + zh(branch.name) + ' {' + branch.id + '}');
      for (const sub of (branch.children || [])) {
        out.push('  # ' + zh(sub.name) + ' {' + sub.id + '}');
        for (const g of (sub.children || [])) {
          if (!g.payloadId) continue;
          const p = payloads.get(g.payloadId);
          out.push('    ## ' + zh(g.name) + '  {p:' + g.payloadId + '}');
          if (!p) { out.push('      !! payload missing'); continue; }
          out.push('      desc: ' + zh(p.description).replace(/\n/g, ' ').slice(0, 180));
          const cs = cmdsOf(p);
          out.push('      exec[' + cs.length + ']:');
          for (const c of cs) out.push('        | ' + c.split('\n').slice(0, 2).join(' ⏎ ').slice(0, 150));
          out.push('      waf[' + (Array.isArray(p.wafBypass) ? p.wafBypass.length : 0) + ']');
        }
      }
      out.push('');
    }
  }
  const f = path.join(ROOT, 'output', 'content-audit', pack + '.txt');
  fs.writeFileSync(f, out.join('\n'));
  console.log(pack, ':', (out.join('\n').match(/## /g) || []).length, '组,', out.length, '行');
}
