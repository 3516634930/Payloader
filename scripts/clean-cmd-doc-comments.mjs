// 后处理：command-override doc 的 patch.command 中文注释剥离（头部注释行 + 行内 # 中文尾注）
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(readFileSync(path.join(root, 'content-review/manifest.json'), 'utf8'));
const han = /\p{Script=Han}/u;
let n = 0;
for (const f of manifest.payloadCommandOverrideFiles) {
  const file = path.join(root, 'content-review', f);
  const doc = JSON.parse(readFileSync(file, 'utf8'));
  let dirty = false;
  for (const entry of (doc.entries || [])) {
    for (const p of (entry.patches || [])) {
      if (typeof p.command !== 'string' || !han.test(p.command)) continue;
      const lines = p.command.split('\n');
      const cleaned = lines
        .filter(l => !(l.trim() && han.test(l) && (/^\s*#/.test(l) || !/[a-zA-Z0-9"'{}()\[\]\/\.:,=+\-*_]/.test(l.trim().replace(/[\u4e00-\u9fff（）\s]/g, '')))))
        .map(l => {
          const m = l.match(/^(.*?\S)\s+#\s*[\u4e00-\u9fff].*$/);
          return m ? m[1] : l;
        });
      const next = cleaned.join('\n').replace(/\n{3,}/g, '\n\n').trim();
      if (next !== p.command && next.length >= 4) { p.command = next; n++; dirty = true; }
    }
  }
  if (dirty) writeFileSync(file, JSON.stringify(doc, null, 1) + '\n');
}
console.log('patched commands cleaned:', n);
