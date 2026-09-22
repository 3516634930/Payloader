import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');
const dictDir = 'F:/Safety/字典/payload字典大全';

const map = {
  '01-SQL与XPath注入.txt': ['sqli-mysql-basic','sqli-mysql-advanced'],
  '02-XSS跨站脚本大全.txt': ['xss-reflected','xss-stored'],
  '04-命令注入与SSRF.txt': ['rce-command-injection','ssrf-basic'],
  '05-SSTI与XXE.txt': ['ssti-jinja2','xxe-basic'],
  '06-HTTP请求绕过大全.txt': ['auth-bypass','smuggling-cl-te'],
  '08-认证与Token攻击.txt': ['jwt-security','jwt-none-attack'],
  '09-注入大全.txt': ['sqli-union','sqli-error-based'],
  '10-业务逻辑与高级攻击.txt': ['biz-idor','biz-race-condition'],
  '11-AI安全与Prompt注入.txt': ['ai-prompt-injection','ai-model-extraction'],
  '13-注入新方向.txt': ['sqli-blind','sqli-time-based'],
  '14-浏览器安全.txt': ['ws-hijack','clickjacking-basic'],
  '15-API安全测试.txt': ['rest-api-security','api-bola'],
  '16-高级服务端攻击.txt': ['rce-deserialize','rce-deserialize-java'],
};

let done = 0;
for (const [file, payloadIds] of Object.entries(map)) {
  const dictPath = join(dictDir, file);
  let raw;
  try { raw = readFileSync(dictPath, 'utf8'); }
  catch(e) { console.log('MISSING:', file); continue; }

  const lines = raw.split(/\r?\n/).filter(l => {
    const t = l.trim();
    return t && !t.startsWith('#') && t.length > 1 && t.length < 500;
  });
  if (lines.length === 0) { console.log('EMPTY:', file); continue; }
  const uniq = [...new Set(lines)].slice(0, 600);

  // Try each target payload, use the first one that succeeds
  for (const pid of payloadIds) {
    const idIdx = c.indexOf("id: '" + pid + "'");
    if (idIdx < 0) continue;

    // Find the first command template literal
    const cmdIdx = c.indexOf('command: `', idIdx);
    if (cmdIdx < 0) continue;
    const cmdStart = cmdIdx + 10;

    // Find matching closing backtick
    let cmdEnd = cmdStart;
    let escape = false;
    for (let i = cmdStart; i < Math.min(c.length, cmdStart + 50000); i++) {
      if (escape) { escape = false; continue; }
      if (c[i] === '\\') { escape = true; continue; }
      if (c[i] === '`') { cmdEnd = i; break; }
    }
    if (cmdEnd <= cmdStart) continue;

    // Append dict content before the closing backtick
    const header = pid.endsWith('2') ? '\n\n# === 字典补充: ' + file + ' ===\n' : '\n\n# === ' + file + ' ===\n';
    const append = header + uniq.join('\n');
    const escaped = append
      .replace(/\\/g, '\\\\')
      .replace(/`/g, '\\`')
      .replace(/\$/g, '\\$');

    c = c.slice(0, cmdEnd) + escaped + c.slice(cmdEnd);
    console.log('DONE:', file, '->', pid, '(' + uniq.length + ' payloads)');
    done++;
    break; // only apply to first successful target
  }
}

writeFileSync(fp, c, 'utf8');
console.log('\nTotal:', done);
