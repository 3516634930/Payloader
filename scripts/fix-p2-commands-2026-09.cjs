const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(path.resolve(process.cwd(), 'data/payloader.sqlite'), { readOnly: true });
const all = db.prepare('SELECT id, data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();
const byId = new Map(all.map(p => [p.id, p]));

const entriesById = new Map();
const push = (id, patch) => {
  if (!entriesById.has(id)) entriesById.set(id, { id, patches: [] });
  entriesById.get(id).patches.push(patch);
};
let ok = 0, fail = 0;
const apply = (id, area, index, fn, label) => {
  const p = byId.get(id);
  const step = p && (p[area] || [])[index];
  if (!p || !step) { console.log('MISS target:', id, area, index); fail++; return; }
  const cmd = step.command || '';
  const next = fn(cmd);
  if (next === null || next === undefined || next === cmd) { console.log('MISS/NOOP:', label); fail++; return; }
  push(id, { area, index, expectedCommand: cmd, command: next });
  ok++;
};

// ── E 类：占位符规范化 ──
for (const i of [1, 2, 4, 5]) apply('potato-attack', 'execution', i, c => c.includes('{{ATTACKER_IP}}') ? c.split('{{ATTACKER_IP}}').join('{ATTACKER_IP}') : null, 'potato ' + i);
apply('rce-cmd-blind', 'wafBypass', 4, c => c.includes('10.10.14.4') ? c.split('10.10.14.4').join('{ATTACKER_HOST}').split('/1234').join('/{LPORT}') : null, 'cmd-blind IP');
apply('wifi-creds', 'execution', 1, c => c.includes('WiFi_Name') ? c.split('WiFi_Name').join('{LAB_SSID}') : null, 'wifi SSID');
apply('overpass-the-hash', 'execution', 2, c => c.includes('{LAB_DOMAIN}/user -hashes') ? c.replace('{LAB_DOMAIN}/user -hashes', '{LAB_DOMAIN}/{LAB_USER} -hashes') : null, 'ophash user');
apply('sqli2-direct-statement-and-catalog-selection', 'execution', 0, c => /\bTARGET_TABLE\b/.test(c) ? c.split('TARGET_TABLE').join('{TARGET_TABLE}').split('DATABASE_NAME').join('{DATABASE_NAME}') : null, 'sqli2-direct tables');
apply('sqli2-outfile-write-primitive', 'execution', 0, c => c.includes("'xxx'") ? c.split("'xxx'").join("'{FILE_PATH}'") : null, 'outfile xxx');

// ── D 类：裸 Python heredoc ×7 ──
for (const id of ['file-archive-member-path-normalization', 'file-archive-symlink-target', 'file-archive-filename-encoding-differential', 'file-upload-signature-content-mismatch', 'file-upload-multipart-content-type-differential', 'file-upload-null-byte-filename', 'file-windows-trailing-name-normalization']) {
  apply(id, 'execution', 0, c => {
    if (!/^import /m.test(c) || c.includes("<<'PY'")) return null;
    let out = "python3 - <<'PY'\n" + c;
    out = out.replace(/\n(# Expected[^\n]*)\n?$/, '\nPY\n$1\n');
    if (!out.includes('\nPY\n')) out = out.replace(/\n?$/, '\nPY\n');
    return out;
  }, 'heredoc ' + id);
}

// ── B 类：基线对照 command 修正为 execution[0] ×8 ──
for (const [id, wi] of [['xss-filter-bypass', 5], ['xss-filter-bypass', 7], ['xss-filter-bypass', 9], ['xss-filter-bypass', 11], ['xss-filter-bypass', 13], ['sqli-time-mysql', 2], ['sqli-error-based', 3], ['sqli2-union-extraction-lexical-encodings', 2]]) {
  const p = byId.get(id);
  const waf = p && (p.wafBypass || [])[wi];
  const base = p && (p.execution || [])[0];
  if (!waf || !base) { console.log('MISS base:', id, wi); fail++; continue; }
  if (!/与 execution\[0\]|逐字节相同|baseline/i.test(JSON.stringify(waf.description || '') + JSON.stringify(waf.title || ''))) { console.log('SKIP 非基线语义:', id, wi); continue; }
  if (waf.command === base.command) continue;
  push(id, { area: 'wafBypass', index: wi, expectedCommand: waf.command, command: base.command });
  ok++;
}

// ── C 类：清单命令注释化 ×3 ──
apply('bizlogic-id', 'execution', 0, c => /^\d/.test(c) ? '# 对象 ID 顺序候选清单（逐个替换到同条目探测请求的 id 参数中比对授权差异）\n# ' + c.split('\n').join('\n# ') : null, 'bizlogic-id');
apply('bizlogic-', 'execution', 0, c => /^COUPON/.test(c) ? '# 优惠券码顺序候选清单（逐个替换到兑换请求的 coupon 参数中验证可预测性）\n# ' + c.split('\n').join('\n# ') : null, 'bizlogic-');
apply('bizlogic--ext', 'execution', 0, c => /^-?\d/m.test(c) && !/^curl|^python|^http/.test(c) ? '# 金额边界值清单（逐个替换到下单金额字段验证服务端校验与舍入）\n# ' + c.split('\n').join('\n# ') : null, 'bizlogic--ext');

// ── H 类：requiresAdmin 修正 ──
for (const [id, area, index] of [['pass-the-ticket', 'execution', 0], ['rdp-hijack', 'execution', 1], ['rdp-hijack', 'execution', 2], ['wifi-creds', 'execution', 1]]) {
  const p = byId.get(id);
  const step = p && (p[area] || [])[index];
  if (!step) { console.log('MISS ra:', id); fail++; continue; }
  if (step.requiresAdmin === true) continue;
  push(id, { area, index, expectedCommand: step.command, requiresAdmin: true });
  ok++;
}

// ── G 类：命令内文案（title 层）──
// ntds-dump exec[0] 英文标题粘连
{
  const p = byId.get('ntds-dump');
  const s = p.execution[0];
  const en = s.title?.en || '';
  if (/\b[a-z][A-Z]/.test(en)) {
    const fixed = en
      .replace(/ntdsutilsnapshot/i, 'ntdsutil snapshot')
      .replace(/([a-z])([A-Z])/g, '$1 $2');
    push('ntds-dump', { area: 'execution', index: 0, expectedCommand: s.command, title: { zh: s.title.zh, en: fixed } });
    ok++;
  }
}

const doc = { schemaVersion: 1, entries: [...entriesById.values()] };
fs.writeFileSync('content-review/payload-command-overrides-p2fix-2026-09.json', JSON.stringify(doc, null, 2) + '\n');
const manifest = JSON.parse(fs.readFileSync('content-review/manifest.json', 'utf8'));
if (!manifest.payloadCommandOverrideFiles.includes('payload-command-overrides-p2fix-2026-09.json')) {
  manifest.payloadCommandOverrideFiles.push('payload-command-overrides-p2fix-2026-09.json');
  manifest.payloadCommandOverrideFiles.sort();
  fs.writeFileSync('content-review/manifest.json', JSON.stringify(manifest, null, 2) + '\n');
}
console.log(`P2 command 修复: ${ok} 成功 / ${fail} 失败 / ${doc.entries.length} 条`);
