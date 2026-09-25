#!/usr/bin/env node
/**
 * 生成 payload-command-overrides-cleanup-2026-09.json：
 * 批次1 移除 Write-Output "PAYLOADER_..." 标记行；批次2 步骤标题剥手动编号；批次3 rce-image .htaccess 澄清。
 * expectedCommand 从 DB 现值逐字锚定。
 */
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const db = new DatabaseSync('data/payloader.sqlite', { readOnly: true });
const all = db.prepare('SELECT id, data FROM payloads').all().map(r => JSON.parse(r.data));
db.close();

const stripNumZh = t => String(t || '').replace(/^[0-9]{1,2}[.、)．]\s*/, '').replace(/^第[0-9一二三四五六七八九十]+步[:：]?\s*/, '');
const stripNumEn = t => String(t || '').replace(/^[0-9]{1,2}[.)]\s+/, '');
const cleanWO = cmd => cmd
  .split('\n')
  .filter(line => !/^\s*(;\s*)?Write-Output\s+"PAYLOADER[^"]*"\s*(;.*)?\s*$/.test(line))
  .join('\n')
  .replace(/\n{3,}/g, '\n\n')
  .trim();

const entriesById = new Map();
const push = (id, patch) => {
  if (!entriesById.has(id)) entriesById.set(id, { id, patches: [] });
  entriesById.get(id).patches.push(patch);
};

for (const p of all) {
  for (const [i, step] of (p.execution || []).entries()) {
    const cmd = step.command || '';
    const nextCmd = /Write-Output\s+"PAYLOADER/.test(cmd) ? cleanWO(cmd) : null;
    const zh = stripNumZh(step.title?.zh);
    const en = stripNumEn(step.title?.en);
    const titleChanged = zh !== step.title?.zh || en !== step.title?.en;
    if (nextCmd !== null && nextCmd !== cmd && nextCmd) {
      push(p.id, { area: 'execution', index: i, expectedCommand: cmd, command: nextCmd, ...(titleChanged ? { title: { zh, en: step.title?.en } } : {}) });
    } else if (titleChanged) {
      push(p.id, { area: 'execution', index: i, expectedCommand: cmd, title: { zh, en } });
    }
  }
  // 批次 3：rce-image .htaccess 步骤
  if (p.id === 'rce-image') {
    for (const [i, step] of (p.execution || []).entries()) {
      if (typeof step.command === 'string' && step.command.startsWith('AddType')) {
        push(p.id, {
          area: 'execution', index: i, expectedCommand: step.command,
          command: '# 写入 Web 根目录 .htaccess（Apache 且 AllowOverride 开启时生效）\nAddType application/x-httpd-php .jpg\n# 之后直接访问图片马\nhttp://{LAB_APP}/upload/shell.jpg',
          platform: 'all',
        });
      }
    }
  }
}

const doc = { schemaVersion: 1, entries: [...entriesById.values()] };
fs.writeFileSync('content-review/payload-command-overrides-cleanup-2026-09.json', JSON.stringify(doc, null, 2) + '\n');
const manifestPath = 'content-review/manifest.json';
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
if (!manifest.payloadCommandOverrideFiles.includes('payload-command-overrides-cleanup-2026-09.json')) {
  manifest.payloadCommandOverrideFiles.push('payload-command-overrides-cleanup-2026-09.json');
  manifest.payloadCommandOverrideFiles.sort();
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
}
let nCmd = 0, nTitle = 0;
for (const e of doc.entries) for (const pa of e.patches) { if (pa.command) nCmd++; else nTitle++; }
console.log(`生成 ${doc.entries.length} 条 / ${nCmd} 个命令补丁 + ${nTitle} 个标题补丁，manifest 已注册`);
