// 文本类隐写三引擎测试：snow 空白隐写 / Cloakify 词表隐写 / TTL 隐写。
// 语义依据：
// - snow：darkside.com.au/snow description.html + 作者镜像 mattkwan-zz/snow encode.c
//   （3bit/组、tab 分隔、位序反转、起始 tab 标记、行末裸空格组收尾）。
// - Cloakify：TryCatchHCF/Cloakify cloakify.py/decloakify.py（MIT）
//   （array64 小写在前、'='→词表第 65 行、list.index() 首次出现位置）。
// - TTL：四值 2bit（63/127/191/255 取高 2 位，写法见 cnblogs BlueTeam 取证 TTL 隐写）、
//   chr(ttl)、低 4 位拼字节/hex 字符流。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const srcDir = path.join(projectRoot, 'src');
const { loadModule } = createTsModuleLoader();
const { extractSnow, embedSnow, snowStegoReport } = loadModule(path.join(srcDir, 'utils', 'codec', 'snowStego.ts'));
const {
  cloakifyDecode, cloakifyEncode, autoCloakifyDecode, cloakifyAutoReport, parseWordList, CLOAKIFY_ARRAY64,
} = loadModule(path.join(srcDir, 'utils', 'codec', 'cloakify.ts'));
const { CLOAKIFY_CIPHERS } = loadModule(path.join(srcDir, 'utils', 'codec', 'cloakLists.ts'));
const { decodeTtl, extractTtlFromText, encodeTtl2bit, ttlStegoReport } = loadModule(path.join(srcDir, 'utils', 'ctf', 'ttlStego.ts'));

const CARRIER = 'Steganography is the practice of concealing secret messages within ordinary looking carrier text.\n'
  + 'Whitespace at the end of lines survives almost every text editor and mail gateway intact,\n'
  + 'which makes trailing spaces and tabs a classic covert channel for hidden payloads.\n'
  + 'The snow utility formalised this channel in 1999 and CTF authors keep rediscovering it.\n';

// ---- snow ----

test('snow：embedSnow(bit) → extractSnow 朴素映射往返', () => {
  const stego = embedSnow(CARRIER, 'flag{snow_bit_roundtrip}');
  assert.ok(stego.length > CARRIER.length);
  const result = extractSnow(stego);
  assert.ok(result.bytes.length > 0);
  const best = result.variants[0];
  assert.ok(best.text.includes('flag{snow_bit_roundtrip}'), `best=${best.mapping} text=${JSON.stringify(best.text)}`);
  assert.equal(best.printableRatio, 1);
  assert.equal(best.printable, true);
});

test('snow：embedSnow(snow3) → 官方规范严格变体往返', () => {
  const payload = 'flag{snow3_spec_roundtrip}';
  const stego = embedSnow(CARRIER, payload, 'snow3');
  const result = extractSnow(stego);
  const spec = result.variants.find(variant => variant.mapping.includes('官方规范'));
  assert.ok(spec, 'variants 应包含官方规范变体');
  assert.equal(spec.text, payload);
  assert.equal(spec.printableRatio, 1);
});

test('snow：官方 3bit 位序与分组结构逐字符核对（C 源码语义手工向量）', () => {
  // 字节 'A'=0x41=01000001 → 组 (0,1,0)(0,0,0)(0,1,pad0) → nspc 2/0/2
  // → 载体：起始 tab + "  " + 分隔 tab + 零值裸 tab + "  "（零值组仍带分隔符）
  const embedded = embedSnow('abc', 'A', 'snow3');
  assert.equal(embedded, 'abc\t  \t\t  ');
  const result = extractSnow(embedded);
  const spec = result.variants.find(variant => variant.mapping.includes('官方规范'));
  assert.equal(spec.text, 'A');
  assert.equal(spec.bits, 9); // 8 数据位 + 1 官方补零位
});

test('snow：\\r\\n 行尾用例（\\r 是行终止符，不算载体）', () => {
  // 手工构造：行 'abc \t  \t\t\t\t' 的行尾空白 ' \t  \t\t\t\t' → 0,1,0,0,1,1,1,1 = 0x4F 'O'
  const text = 'abc \t  \t\t\t\t\r\nplain line\r\n';
  const result = extractSnow(text);
  const naive = result.variants.find(variant => variant.mapping === 'space=0,tab=1（行尾空白）');
  assert.equal(naive.text, 'O');
  assert.equal(naive.bits, 8);
  // 孤立 \r 出现在行尾空白中段：'x  \r \t' 的行尾空白取 '\r' 之后的 ' \t'（\r 不算载体字符）
  const mixed = extractSnow('x  \r \t\n');
  const mixedRuns = mixed.variants.find(variant => variant.mapping === 'space=0,tab=1（行尾空白）');
  assert.equal(mixedRuns.bits, 2); // ' ','\t' → 0,1；\r 前的 '  ' 被行内容截断不属于行尾空白
});

test('snow：全文空白变体（非行尾）提取', () => {
  // 'x \t \t \t \ty' 的全文空白序列恰为 (' ','\t')×4 → 0,1,0,1,0,1,0,1 = 0x55 'U'
  const result = extractSnow('x \t \t \t \ty');
  const allWs = result.variants.find(variant => variant.mapping === 'space=0,tab=1（全文空白）');
  assert.equal(allWs.bits, 8);
  assert.equal(allWs.text, 'U');
  // 行尾没有空白，行尾变体必须为 0 位
  const lineEnd = result.variants.find(variant => variant.mapping === 'space=0,tab=1（行尾空白）');
  assert.equal(lineEnd.bits, 0);
});

test('snow：无空白载体与空输入安全', () => {
  const result = extractSnow('no trailing whitespace here');
  // 行中普通空格会给"全文空白"变体贡献少量比特，但不足以组成任何字节
  assert.equal(result.bytes.length, 0);
  assert.ok(result.variants.every(variant => variant.bytes.length === 0));
  const empty = extractSnow('');
  assert.equal(empty.bytes.length, 0);
});

test('snow：gzip 魔数检测报告', () => {
  const stego = embedSnow('cover text line\n', new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x11, 0x22]), 'bit');
  const report = JSON.parse(snowStegoReport(stego));
  assert.equal(report.tool, 'snow-whitespace-stego');
  assert.equal(report.gzipLayer, true);
  assert.ok(report.variants.length === 8);
  assert.ok(report.variants.every(variant => typeof variant.printableRatio === 'number'));
});

test('snow：超过 20MB 输入拒绝', () => {
  assert.throws(() => extractSnow('x'.repeat(20 * 1024 * 1024 + 1)), /20MB/);
});

// ---- cloakify ----

test('cloakify：六套内置词表 b64 语义 encode→decode 往返', () => {
  const payload = new TextEncoder().encode('flag{cloak_roundtrip}');
  for (const cipher of CLOAKIFY_CIPHERS) {
    const cloaked = cloakifyEncode(payload, cipher.key, 'b64');
    const decoded = cloakifyDecode(cloaked, cipher.key, 'b64');
    assert.ok(decoded, `${cipher.key} 解码失败`);
    assert.equal(decoded.mode, 'b64');
    assert.equal(decoded.text, 'flag{cloak_roundtrip}');
    assert.deepEqual(Array.from(decoded.bytes), Array.from(payload));
    assert.equal(decoded.gzipLayer, false);
  }
});

test('cloakify：byte 简化语义 encode→decode 往返（auto 自动命中）', () => {
  // 'flag' = [102,108,97,103]，需词数 > 108 的内置词表（hashesMd5 113 词）
  const payload = new Uint8Array([0x66, 0x6c, 0x61, 0x67]);
  const cloaked = cloakifyEncode(payload, 'hashesMd5', 'byte');
  const explicit = cloakifyDecode(cloaked, 'hashesMd5', 'byte');
  assert.deepEqual(Array.from(explicit.bytes), Array.from(payload));
  // byte 模式产物在 b64 语义下索引 ≥65 必然非法，auto 应落到 byte
  const auto = cloakifyDecode(cloaked, 'hashesMd5');
  assert.equal(auto.mode, 'byte');
  assert.equal(auto.text, 'flag');
});

test('cloakify：上游真实样例语义核对（array64 小写在前 + 行号映射）', () => {
  // 仓库 ciphers/desserts 前四行实为 honey/jelly/lollipop/spumoni（上游文件逐行核对）
  // base64 'abcd' → array64 索引 0/1/2/3 → 前四词；解码等价 Buffer.from('abcd','base64')
  const cloaked = 'honey\njelly\nlollipop\nspumoni';
  const decoded = cloakifyDecode(cloaked, 'desserts', 'b64');
  assert.equal(decoded.bytesHex, Buffer.from('abcd', 'base64').toString('hex'));
  assert.equal(CLOAKIFY_ARRAY64.indexOf('a'), 0);
  assert.equal(CLOAKIFY_ARRAY64.indexOf('A'), 26); // 小写在前：大写 A 在 26
  assert.equal(CLOAKIFY_ARRAY64.indexOf('='), 64); // '=' 填充符是第 65 行
});

test('cloakify：base64 填充符 "=" 映射到词表第 65 行', () => {
  // payload 'hi'（2 字节）→ base64 'aGk=' → 词 [0]/[32]/[10]/[64] = honey/biscuits/pineapple/snickerdoodles
  const cloaked = cloakifyEncode(new Uint8Array([0x68, 0x69]), 'desserts', 'b64');
  assert.equal(cloaked, 'honey\nbiscuits\npineapple\nsnickerdoodles');
  const decoded = cloakifyDecode(cloaked, 'desserts', 'b64');
  assert.equal(decoded.text, 'hi');
});

test('cloakify：autoCloakifyDecode 对 encode 产物按 flag 形态命中正确词表', () => {
  const payload = 'flag{auto_cloak_hit}';
  const cloaked = cloakifyEncode(new TextEncoder().encode(payload), 'pokemonGo', 'b64');
  const candidates = autoCloakifyDecode(cloaked);
  assert.ok(candidates.length > 0);
  assert.equal(candidates[0].list, 'pokemonGo');
  assert.equal(candidates[0].mode, 'b64');
  assert.equal(candidates[0].flagLike, true);
  assert.equal(candidates[0].text, payload);
});

test('cloakify：gzip 魔数层检测（PacketWhisper 式预压缩）', () => {
  const gzipped = new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b]);
  const cloaked = cloakifyEncode(gzipped, 'topWebsites', 'b64');
  const decoded = cloakifyDecode(cloaked, 'topWebsites', 'b64');
  assert.equal(decoded.gzipLayer, true);
  const report = JSON.parse(cloakifyAutoReport(cloaked));
  assert.ok(report.gzipNote.includes('gzip'));
  // gzip 载荷按可打印率排序未必排第一，但必须出现在候选里
  const gz = report.candidates.find(candidate => candidate.gzipLayer);
  assert.ok(gz, `候选中应含 gzip 层：${JSON.stringify(report.candidates.map(c => c.list + ':' + c.mode))}`);
  assert.equal(gz.list, 'topWebsites');
});

test('cloakify：自定义词表文本与重复行首次出现语义', () => {
  const custom = Array.from({ length: 65 }, (_, index) => `w${index}`).join('\n');
  assert.equal(parseWordList(custom).length, 65);
  const payload = 'flag{custom_list}';
  const cloaked = cloakifyEncode(new TextEncoder().encode(payload), custom, 'b64');
  const decoded = cloakifyDecode(cloaked, custom, 'b64');
  assert.equal(decoded.text, payload);
  // 上游 list.index() 语义：重复行取首次出现位置（'dup' 行号 0，第二次出现不可达）
  const dupList = 'dup\ndup\nsecond';
  const dupDecoded = cloakifyDecode('dup\ndup', dupList, 'b64');
  assert.equal(dupDecoded.bytesHex, Buffer.from('aa', 'base64').toString('hex'));
  // 单行逗号分隔输入容错
  const comma = cloakifyEncode(new TextEncoder().encode('hi'), 'desserts', 'b64').replaceAll('\n', ',');
  assert.equal(cloakifyDecode(comma, 'desserts', 'b64').text, 'hi');
});

test('cloakify：词表过短与空输入防护', () => {
  assert.throws(() => cloakifyEncode(new Uint8Array([65]), 'a\nb\nc', 'b64'), /65/);
  assert.equal(cloakifyDecode('', 'desserts'), null);
  assert.equal(cloakifyDecode('完全不在词表里的词\n另一个', 'desserts', 'b64'), null);
});

test('cloakify：超过 20MB 输入拒绝', () => {
  assert.throws(() => autoCloakifyDecode('x'.repeat(20 * 1024 * 1024 + 1)), /20MB/);
});

// ---- TTL ----

test('ttl：encodeTtl2bit(63/127/191/255) → decodeTtl 2bit 升序法解出 flag', () => {
  const values = encodeTtl2bit('flag{ttl}');
  assert.ok(values.every(ttl => [63, 127, 191, 255].includes(ttl)));
  const results = decodeTtl(values);
  assert.ok(results.length > 0);
  assert.equal(results[0].text, 'flag{ttl}');
  assert.ok(results[0].method.includes('2bit'));
  assert.ok(results[0].method.includes('升序'));
});

test('ttl：3/2/1/0 变体（降序映射）覆盖反排出题人', () => {
  const values = encodeTtl2bit('flag{ttl}', [3, 2, 1, 0]);
  assert.ok(values.every(ttl => [0, 1, 2, 3].includes(ttl)));
  const results = decodeTtl(values);
  const hit = results.find(result => result.text === 'flag{ttl}');
  assert.ok(hit, `应有一个变体解出 flag，得到 ${JSON.stringify(results.map(r => r.method))}`);
  assert.ok(hit.method.includes('降序'));
});

test('ttl：chr(ttl) 法（TTL 即 ASCII 码）', () => {
  const values = Array.from('flag', char => char.charCodeAt(0));
  const results = decodeTtl(values);
  const chr = results.find(result => result.method.includes('chr'));
  assert.ok(chr);
  assert.equal(chr.text, 'flag');
  // 四值不成立（f/l/a/g 是 4 个不同值但构成 2bit 流时无 flag 形态），chr 法应存在且可打印
  assert.ok(chr.printable > 0.5);
});

test('ttl：低 4 位两两拼字节与 hex 字符流双命中', () => {
  // 'flag' 的 hex 是 666c6167：TTL 低 4 位依次 6,6,6,c,6,1,6,7（高 4 位任取 3）
  const values = [0x36, 0x36, 0x36, 0x3c, 0x36, 0x31, 0x36, 0x37];
  const results = decodeTtl(values);
  const nibblePairs = results.find(result => result.method.includes('拼字节'));
  assert.equal(nibblePairs.text, 'flag');
  const hexStream = results.find(result => result.method.includes('hex 字符流'));
  assert.equal(hexStream.text, '666c6167');
});

test('ttl：extractTtlFromText 按行/逗号/空格抽取并过滤非 TTL 数字', () => {
  const multiline = 'No.\tTime\tTTL\n1\t0.000\t63\n2\t0.001\t127\n3\t0.002\t191\n4\t0.003\t255\n';
  const extracted = Array.from(extractTtlFromText(multiline));
  // 行内 Time 列的 0.000 会被 \d+ 拆出（0 000 等 0-255 数字），TTL 值仍完整保留
  assert.deepEqual(extracted.filter(ttl => ttl > 60), [63, 127, 191, 255]);
  assert.deepEqual(Array.from(extractTtlFromText('63, 127 191\t255')), [63, 127, 191, 255]);
  assert.deepEqual(Array.from(extractTtlFromText('80 443 8080 63')), [80, 63]); // 443/8080 > 255（TTL 是 u8 字段）被过滤
  assert.deepEqual(Array.from(extractTtlFromText('no digits')), []);
});

test('ttl：ttlStegoReport JSON 结构与空输入提示', () => {
  const report = JSON.parse(ttlStegoReport('63\n127\n191\n255\n63\n127\n191\n255'));
  assert.equal(report.tool, 'ttl-stego');
  assert.ok(Array.isArray(report.candidates));
  assert.ok(report.count > 0);
  const empty = JSON.parse(ttlStegoReport('nothing here'));
  assert.equal(empty.count, 0);
  assert.ok(empty.note.length > 0);
});
