import { readFileSync, writeFileSync } from 'fs';
const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');

// In template literals, ${...} is JS interpolation. We need \${...} for literal ${}
const fixes = [
  ['${jndi:', '\\${jndi:'],
  ['${rmi:', '\\${rmi:'],
  ['${dns:', '\\${dns:'],
  ['${ndi:', '\\${ndi:'],
  ['${i:ldap', '\\${i:ldap'],
  ['${bcel:', '\\${bcel:'],
];
for (const [from, to] of fixes) {
  const before = c.length;
  c = c.replaceAll(from, to);
  if (c.length !== before) console.log('Fixed:', from, '->', to, '(changed', before - c.length, 'bytes)');
}
writeFileSync(fp, c, 'utf8');
console.log('Done');
