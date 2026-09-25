#!/usr/bin/env node
/** 从 generator 的 spec 数组按块删除退役 id。 */
const fs = require('fs');
const DROP = {
  'scripts/generate-intranet-technique-reviews.mjs': ['lateral-dcom-excel', 'lateral-dcom-mmc', 'rdp-relay', 'juicy-potato', 'printspoofer', 'godpotato', 'persistence-hidden-user', 'sam-the-admin'],
  'scripts/generate-remaining-web-reviews.mjs': ['rce-cmd-blind', 'rce-log-poison'],
};
for (const [file, drop] of Object.entries(DROP)) {
  const src = fs.readFileSync(file, 'utf8').split('\n');
  const out = [];
  let skipping = false, removed = 0;
  for (const line of src) {
    if (!skipping) {
      const m = line.match(/^\s*\{\s*id:\s*'([^']+)',/);
      if (m && drop.includes(m[1])) { skipping = true; removed++; continue; }
      out.push(line);
    } else {
      if (/^\s*\},?\s*$/.test(line)) { skipping = false; continue; }
    }
  }
  fs.writeFileSync(file, out.join('\n'));
  console.log(file, '删除', removed, '个 spec 块');
}
