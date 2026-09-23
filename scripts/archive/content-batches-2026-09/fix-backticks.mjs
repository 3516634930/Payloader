import { readFileSync, writeFileSync } from 'fs';
const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');

// The issue: PHP code within JS template literals contains backtick chars that break the template.
// PHP backtick (`) is the shell exec operator.
// In JS template literals, backtick must be escaped as \`

// Fix 1: Remove the non-alphanumeric RCE line with XOR + backtick
const badLine1 = "<?php $_=('%01'^";
let idx = c.indexOf(badLine1);
while (idx >= 0) {
  // Find end of this PHP tag (next ?>)
  const end = c.indexOf('?>', idx);
  if (end < 0) break;
  // Check if it contains backtick issue
  const chunk = c.slice(idx, end + 2);
  // Replace with simplified non-alpha RCE
  c = c.slice(0, idx) + '<?php $x=base64_decode(str_rot13($_POST[1]));eval($x);' + c.slice(end + 2);
  idx = c.indexOf(badLine1, idx + 50);
}

// Fix 2: Find any remaining template literal closure issues
// The pattern '\`' in PHP inside a JS template literal breaks things
// Look for sequences like: '\' + backtick + '
const pattern = /'.*?\\\\`.*?'/g;
let match;
while ((match = pattern.exec(c)) !== null) {
  // Only fix if inside a template literal (check context)
  const pos = match.index;
  const before = c.slice(Math.max(0, pos - 100), pos);
  if (before.includes('command: `')) {
    // This is inside a template literal - replace backtick with alternative char
    const replacement = match[0].replace(/\\\\`/g, "'`'");
    c = c.slice(0, pos) + replacement + c.slice(pos + match[0].length);
  }
}

// Fix 3: Replace any remaining <?=\\` sequence with PHP short echo alternative
c = c.replace(/<\\?=\\\\/g, '<?php echo ');
// c = c.replace(/\\\\`\\?>/g, '; ?>');

writeFileSync(fp, c, 'utf8');
console.log('Fixed backtick issues');
