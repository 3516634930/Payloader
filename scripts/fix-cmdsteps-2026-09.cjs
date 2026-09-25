#!/usr/bin/env node
/**
 * 2026-09 内容终审修复：批次 1-3
 * 1) 移除步骤命令里的 Write-Output "PAYLOADER_..." 证据标记行（bash/Linux 下复制即报错，win 下也是凑行）
 * 2) 步骤标题剥手动编号前缀（zh：N./N、/N）/第N步；en：N. ）——UI 已有步骤序号
 * 3) rce-image exec[3]：.htaccess 指令补写文件语境注释，platform 修正
 */
const fs = require('fs');
const path = require('path');
const CR = p => path.join(process.cwd(), 'content-review', p);

const stripNumZh = t => String(t || '').replace(/^[0-9]{1,2}[.、)．]\s*/, '').replace(/^第[0-9一二三四五六七八九十]+步[:：]?\s*/, '');
const stripNumEn = t => String(t || '').replace(/^[0-9]{1,2}[.)]\s+/, '');

const main = () => {
  const manifest = JSON.parse(fs.readFileSync(CR('manifest.json'), 'utf8'));
  const files = [...manifest.overrideFiles, ...(manifest.collectionSplitFiles || []), 'tool-decisions.json'];
  const stats = { woLines: 0, titlesZh: 0, titlesEn: 0, rceImage: 0 };

  const fixExecArray = (exec, id) => {
    for (const step of (exec || [])) {
      // 批次 1：移除 Write-Output PAYLOADER 标记行（独立行或分号拼接）
      if (typeof step.command === 'string' && /Write-Output\s+"PAYLOADER/.test(step.command)) {
        const before = step.command;
        step.command = step.command
          .split('\n')
          .filter(line => !/^\s*(;\s*)?Write-Output\s+"PAYLOADER[^"]*"\s*(;.*)?\s*$/.test(line))
          .join('\n')
          .replace(/\n{3,}/g, '\n\n')
          .trim();
        if (step.command !== before) stats.woLines++;
        // 若该步只剩空命令则告警（不应发生：标记行都是附加行）
        if (!step.command) console.log('⚠️ 步骤命令被清空:', id, step.title?.zh);
      }
      // 批次 2：标题剥编号
      if (step.title) {
        const zh = typeof step.title.zh === 'string' ? stripNumZh(step.title.zh) : step.title.zh;
        const en = typeof step.title.en === 'string' ? stripNumEn(step.title.en) : step.title.en;
        if (zh !== step.title.zh) stats.titlesZh++;
        if (en !== step.title.en) stats.titlesEn++;
        if (zh !== step.title.zh || en !== step.title.en) step.title = { ...step.title, zh, en };
      }
    }
  };

  const walk = (obj, id) => {
    if (Array.isArray(obj)) { obj.forEach(v => walk(v, id)); return; }
    if (!obj || typeof obj !== 'object') return;
    if (typeof obj.id === 'string') id = obj.id;
    if (Array.isArray(obj.execution)) fixExecArray(obj.execution, id);
    if (Array.isArray(obj.wafBypass)) fixExecArray(obj.wafBypass, id);
    // 批次 3：rce-image 的 .htaccess 步骤澄清
    if (id === 'rce-image' && Array.isArray(obj.execution)) {
      for (const step of obj.execution) {
        if (typeof step.command === 'string' && step.command.startsWith('AddType')) {
          step.command = '# 写入 Web 根目录 .htaccess（Apache 且 AllowOverride 开启时生效）\nAddType application/x-httpd-php .jpg\n# 之后直接访问图片马\nhttp://{LAB_APP}/upload/shell.jpg';
          step.platform = 'all';
          stats.rceImage++;
        }
      }
    }
    for (const k of Object.keys(obj)) walk(obj[k], id);
  };

  for (const f of files) {
    const full = CR(f);
    if (!fs.existsSync(full)) continue;
    const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
    const before = JSON.stringify(stats);
    walk(doc, null);
    if (JSON.stringify(stats) !== before) fs.writeFileSync(full, JSON.stringify(doc, null, 2) + '\n');
  }
  console.log(`批次1 Write-Output 移除: ${stats.woLines} 步｜批次2 标题剥编号: zh ${stats.titlesZh} + en ${stats.titlesEn}｜批次3 rce-image: ${stats.rceImage}`);
};

main();
