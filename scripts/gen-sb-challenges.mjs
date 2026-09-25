// 批次 SB 真题向量生成器：用产品引擎自造通关题到 tests/real-challenges/sb/。
// 每道题 README.md 写预期 flag，供 solve-real-challenges.mjs 对拍。
// 用法：node scripts/gen-sb-challenges.mjs
import { execSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createTsModuleLoader } from '../tests/helpers/compileTsModule.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { loadModule } = createTsModuleLoader();
const src = (...p) => path.join(projectRoot, 'src', ...p);
const outRoot = path.join(projectRoot, 'tests', 'real-challenges', 'sb');

const snowStego = loadModule(src('utils', 'codec', 'snowStego.ts'));
const cloakify = loadModule(src('utils', 'codec', 'cloakify.ts'));
const ttlStego = loadModule(src('utils', 'ctf', 'ttlStego.ts'));
const pycParse = loadModule(src('utils', 'ctf', 'pycParse.ts'));
const pycStego = loadModule(src('utils', 'ctf', 'pycStego.ts'));

const mkdir = dir => { rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true }); };
const readme = (dir, title, flag, steps) => writeFileSync(path.join(dir, 'README.md'),
  `# ${title}\n\n- 来源：批次 SB 随波逐流能力对标自造真题（用产品引擎 encode 方向生成，闭环验证 decode 方向）\n- 预期 flag：\`${flag}\`\n- 解题步骤：\n${steps.map((s, i) => `  ${i + 1}. ${s}`).join('\n')}\n`, 'utf8');

// —— 01 snow 空白隐写 ——
{
  const dir = path.join(outRoot, '01-snow-blank'); mkdir(dir);
  const poem = ['The wind blows low across the plain,', 'and snowflakes settle on the rail;', 'a quiet signal hides in white,', 'for those who look beyond the pale.'].join('\n');
  const text = snowStego.embedSnow(poem, 'flag{sn0w_1n_th3_bl4nk}', 'bit');
  writeFileSync(path.join(dir, 'poem.txt'), text, 'latin1');
  readme(dir, 'snow 空白隐写', 'flag{sn0w_1n_th3_bl4nk}', ['文本行尾空白是空格/tab 序列（snow 隐写）。', '提取空白二进制（space=0, tab=1）按 8bit 组字节还原。']);
}

// —— 02 Cloakify 词表隐写 ——
{
  const dir = path.join(outRoot, '02-cloakify-desserts'); mkdir(dir);
  const menu = cloakify.cloakifyEncode(new TextEncoder().encode('flag{cl0ak_d3ss3rt}'), 'desserts', 'b64');
  writeFileSync(path.join(dir, 'menu.txt'), menu + '\n', 'utf8');
  readme(dir, 'Cloakify 词表隐写（desserts）', 'flag{cl0ak_d3ss3rt}', ['每行一个甜品名，形态是 Cloakify 词表隐写。', '用 desserts 词表把词映射回 base64 字符再解码。']);
}

// —— 03 TTL 隐写 pcap ——
{
  const dir = path.join(outRoot, '03-ttl-stego'); mkdir(dir);
  const ttls = ttlStego.encodeTtl2bit('flag{ttl_st3g0}');
  // pcap 全局头 24 字节：magic d4c3b2a1（LE）+ ver 2.4 + thiszone 0 + sigfigs 0 + snaplen 0xffff + network 1（Ethernet）
  const globalHeader = Buffer.alloc(24);
  globalHeader.set([0xd4, 0xc3, 0xb2, 0xa1], 0);
  globalHeader.writeUInt16LE(2, 4); globalHeader.writeUInt16LE(4, 6);
  globalHeader.writeUInt32LE(0xffff, 16); globalHeader.writeUInt32LE(1, 20);
  const chunks = [globalHeader];
  ttls.forEach((ttl, index) => {
    const ip = Buffer.alloc(20);
    ip[0] = 0x45; ip.writeUInt16BE(28, 2); ip[4] = (index >> 8) & 0xff; ip[5] = index & 0xff;
    ip[8] = ttl; ip[9] = 0x01; ip.writeUInt32BE(0x0a000001, 12); ip.writeUInt32BE(0x08080808, 16);
    const icmp = Buffer.alloc(8); icmp[0] = 8; icmp[4] = 1; icmp[5] = 1;
    const eth = Buffer.concat([Buffer.alloc(12), Buffer.from([0x08, 0x00]), ip, icmp]);
    const ts = Buffer.alloc(16);
    ts.writeUInt32LE(1700000000 + index, 0); ts.writeUInt32LE(index * 1000, 4);
    ts.writeUInt32LE(eth.length, 8); ts.writeUInt32LE(eth.length, 12);
    chunks.push(ts, eth);
  });
  writeFileSync(path.join(dir, 'trace.pcap'), Buffer.concat(chunks));
  readme(dir, 'TTL 隐写（ICMP）', 'flag{ttl_st3g0}', ['ICMP 包 TTL 值只在 63/127/191/255 四个值间变化。', '每个 TTL 取高 2bit 拼 8bit 组字符。']);
}

// —— 04 BMP 宽高修复 + LSB ——
{
  const dir = path.join(outRoot, '04-bmp-dimensions'); mkdir(dir);
  const w = 64, h = 32;
  const flag = 'flag{bmp_r3p41r}';
  const bits = [];
  for (const ch of new TextEncoder().encode(flag)) for (let b = 7; b >= 0; b -= 1) bits.push((ch >> b) & 1);
  const stride = w * 3;
  const pixels = Buffer.alloc(stride * h);
  for (let i = 0; i < stride * h; i += 3) { pixels[i] = 0xf0; pixels[i + 1] = 0xe0; pixels[i + 2] = 0xd0; }
  // B 通道 LSB 藏 bit 流：写到文件序最后一行（= 图像顶行 = 采样流开头，避免落在提取窗口尾部）
  for (let i = 0; i < bits.length; i += 1) {
    const x = i % w, y = h - 1 - Math.floor(i / w);
    pixels[y * stride + x * 3] = (pixels[y * stride + x * 3] & 0xfe) | bits[i];
  }
  const bmp = Buffer.alloc(54);
  bmp.write('BM'); bmp.writeUInt32LE(54 + pixels.length, 2); bmp.writeUInt32LE(54, 10);
  bmp.writeUInt32LE(40, 14); bmp.writeInt32LE(w, 18); bmp.writeInt32LE(h, 22);
  bmp.writeUInt16LE(1, 26); bmp.writeUInt16LE(24, 28); bmp.writeUInt32LE(pixels.length, 34);
  const good = Buffer.concat([bmp, pixels]);
  // 破坏：宽改 1（高保留 32）——repairBmp 按"幸存高"反推唯一 (64,32)
  const broken = Buffer.from(good);
  broken.writeInt32LE(1, 18);
  writeFileSync(path.join(dir, 'broken.bmp'), broken);
  writeFileSync(path.join(dir, 'reference-good.bmp'), good);
  readme(dir, 'BMP 宽高修复 + LSB', 'flag{bmp_r3p41r}', ['BMP 宽度字段被改成 1，按文件大小反推真实宽高。', '修复后位平面 R 通道 LSB 提取隐藏字节流。']);
}

// —— 05 NTFS ADS（冒号虚拟条目）——
{
  const dir = path.join(outRoot, '05-ntfs-ads'); mkdir(dir);
  const host = Buffer.from('read me first: nothing here.\n', 'latin1');
  const stream = Buffer.from('flag{ntfs_str3am}', 'latin1');
  const crc32Of = data => {
    let c = ~0;
    for (let i = 0; i < data.length; i += 1) {
      c ^= data[i];
      for (let k = 0; k < 8; k += 1) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    }
    return ~c >>> 0;
  };
  const entry = (name, data) => {
    const nameBuf = Buffer.from(name, 'latin1');
    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4);
    local.writeUInt32LE(0x1e070dbd, 14); local.writeUInt32LE(crc32Of(data), 18);
    local.writeUInt32LE(data.length, 22); local.writeUInt32LE(data.length, 26);
    nameBuf.copy(local, 30);
    return Buffer.concat([local, data]);
  };
  const central = (name, data, localOffset) => {
    const nameBuf = Buffer.from(name, 'latin1');
    const cd = Buffer.alloc(46 + nameBuf.length);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6);
    cd.writeUInt32LE(0x1e070dbd, 12); cd.writeUInt32LE(crc32Of(data), 16);
    cd.writeUInt32LE(data.length, 20); cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28); cd.writeUInt32LE(localOffset, 42);
    nameBuf.copy(cd, 46);
    return cd;
  };
  const hostLocal = entry('readme.txt', host);
  const streamLocal = entry('readme.txt:secret.txt', stream);
  const cdHost = central('readme.txt', host, 0);
  const cdStream = central('readme.txt:secret.txt', stream, hostLocal.length);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(2, 8); eocd.writeUInt16LE(2, 10);
  eocd.writeUInt16LE(cdHost.length + cdStream.length, 12);
  eocd.writeUInt32LE(hostLocal.length + streamLocal.length, 16);
  writeFileSync(path.join(dir, 'streams.zip'), Buffer.concat([hostLocal, streamLocal, cdHost, cdStream, eocd]));
  readme(dir, 'NTFS 数据流（ZIP 冒号条目）', 'flag{ntfs_str3am}', ['zip 里有 readme.txt:secret.txt 冒号虚拟条目（Windows NTFS ADS 打包形态）。', '提取流内容即 flag。']);
}

// —— 06 RAR3 密码爆破（自造加密向量，加密方向复刻 rar-brute 测试工厂：node:crypto AES + rarCrypt 派生）——
{
  const dir = path.join(outRoot, '06-rar-brute'); mkdir(dir);
  const crypto = await import('node:crypto');
  const rarCrypt = loadModule(src('utils', 'ctf', 'rarCrypt.ts'));
  const latin1 = text => Uint8Array.from(text, ch => ch.charCodeAt(0) & 0xff);
  const u16 = v => [v & 0xff, (v >> 8) & 0xff];
  const u32 = v => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];
  const crcOf = data => {
    let c = ~0;
    for (let i = 0; i < data.length; i += 1) {
      c ^= data[i];
      for (let k = 0; k < 8; k += 1) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    }
    return ~c >>> 0;
  };
  const buildEncryptedStoredRar = ({ name, content, password, salt }) => {
    const contentBytes = latin1(content);
    const saltBytes = latin1(salt);
    const unpSize = contentBytes.length;
    const paddedLength = Math.max(16, Math.ceil(unpSize / 16) * 16);
    const padded = new Uint8Array(paddedLength);
    padded.set(contentBytes);
    const keys = rarCrypt.deriveRar3Keys(password, saltBytes);
    const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(keys.aesKey), Buffer.from(keys.iv));
    cipher.setAutoPadding(false);
    const cipherBytes = Uint8Array.from(Buffer.concat([cipher.update(Buffer.from(padded)), cipher.final()]));
    const nameBytes = latin1(name);
    const headSize = 32 + nameBytes.length + 8;
    const head = [
      ...u16(0), 0x74, ...u16(0x8000 | 0x0400 | 0x0004), ...u16(headSize),
      ...u32(cipherBytes.length), ...u32(unpSize), 2, ...u32(crcOf(contentBytes)), ...u32(0),
      20, 0x30, ...u16(nameBytes.length), ...u32(0x20),
      ...nameBytes, ...saltBytes,
    ];
    const marker = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
    const mainHead = [...u16(0x1f3c), 0x73, ...u16(0), ...u16(13), ...u16(0), ...u32(0)];
    const endArc = [...u16(0x3dc4), 0x7b, ...u16(0x4000), ...u16(7), ...u16(0), ...u32(0)];
    return Uint8Array.from([...marker, ...mainHead, ...head, ...cipherBytes, ...endArc]);
  };
  const rar = buildEncryptedStoredRar({ name: 'flag.txt', content: 'flag{r4r_br3ak}', password: 'password', salt: 'SALT1234' });
  writeFileSync(path.join(dir, 'secret.rar'), Buffer.from(rar));
  readme(dir, 'RAR3 密码爆破', 'flag{r4r_br3ak}', ['RAR3 加密条目（salt + AES-128-CBC），弱口令。', '字典爆破口令后解密条目内容。']);
}

// —— 08/09 pyc 两道（本机 py -3.10 可用时生成）——
{
  const dirC = path.join(outRoot, '08-pyc-constants'); mkdir(dirC);
  const dirS = path.join(outRoot, '09-pyc-stegosaurus'); mkdir(dirS);
  let hasPython = false;
  try { execSync('py -3.10 -c "print(1)"', { stdio: 'pipe' }); hasPython = true; } catch { hasPython = false; }
  if (!hasPython) {
    readme(dirC, 'pyc 常量挖掘（本机无 python，跳过）', 'flag{pyc_c0nst}', ['本机无 py 启动器时该向量跳过。']);
    readme(dirS, 'pyc Stegosaurus 死槽隐写（本机无 python，跳过）', 'flag{st3g0_pyc}', ['本机无 py 启动器时该向量跳过。']);
    console.log('generated under', outRoot, '(no python, pyc skipped)');
    process.exit(0);
  }
  const pyCommon = 'def add(a, b):\n    return a + b\n\n\ndef main():\n    total = add(1, 2)\n    print(total)\n\n\nmain()\n';
  const compileInto = (dir, source, outName) => {
    const pyFile = path.join(dir, 'task.py');
    writeFileSync(pyFile, source, 'utf8');
    execSync(`py -3.10 -m py_compile "${pyFile}"`);
    const pycache = path.join(dir, '__pycache__');
    const generated = readdirSync(pycache).find(f => f.endsWith('.pyc'));
    const pycBytes = readFileSync(path.join(pycache, generated));
    writeFileSync(path.join(dir, outName), pycBytes);
    rmSync(pycache, { recursive: true, force: true });
    rmSync(pyFile, { force: true });
    return pycBytes;
  };
  compileInto(dirC, `SECRET = "flag{pyc_c0nst}"\n` + pyCommon, 'task.pyc');
  readme(dirC, 'pyc 常量挖掘', 'flag{pyc_c0nst}', ['task.pyc 的 co_consts 字符串常量里藏 flag。', '解析 marshal code object 树提取常量。']);

  // Stegosaurus 死槽 = 无参指令（opcode<90）的 arg 字节；加法链每步一个 BINARY_ADD 槽，
  // 40 步保证 14 字节 payload + 0x00 终止后仍有富余槽清零。
  const mixLines = Array.from({ length: 40 }, (_, i) => `    v = v + ${i + 1}`);
  const stegoSource = `def mix(x):\n    v = x\n${mixLines.join('\n')}\n    return v\n\n\ndef main():\n    print(mix(1))\n\n\nmain()\n`;
  const base = compileInto(dirS, stegoSource, 'base.pyc');
  const parsed = pycParse.parsePyc(new Uint8Array(base));
  const payload = new TextEncoder().encode('flag{st3g0_pyc}');
  const slots = pycStego.iterateStegoSlots(pycParse.walkCodeObjects(parsed.root));
  const patched = Buffer.from(base);
  let cursor = 0;
  for (const slot of slots) {
    patched[slot.code.codeOffset + slot.slotIndex] = cursor < payload.length ? payload[cursor] : 0;
    cursor += 1;
  }
  rmSync(path.join(dirS, 'base.pyc'), { force: true });
  writeFileSync(path.join(dirS, 'task.pyc'), patched);
  readme(dirS, 'pyc Stegosaurus 死槽隐写', 'flag{st3g0_pyc}', ['task.pyc 的指令参数死槽藏了 payload（strings 看不到）。', '按 Stegosaurus 协议提取槽字节，0x00 终止。']);
  console.log('generated under', outRoot);
}
