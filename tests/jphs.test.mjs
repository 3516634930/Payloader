// jphide/jpseek 提取器测试（批次 SI·A 线）。向量策略：
// - Blowfish 用 Schneier 公开向量（与 output/jphs-bf.c 自带 TEST 向量同源：两支）+ 经典全零向量；
// - 密钥流/资格状态机用受控伪流（脚本位）逐分支断言极性与消费数；
// - 端到端闭环：测试侧自行实现 jphide 嵌入方向（merge_word 为 demerge 逆操作、
//   长度头 Blowfish ECB 加密、数据 XOR 流 1 MSB-first），嵌入自造系数网格后提取还原。
//   原版 jphide 产物对拍无本地工具，留待真题阶段。
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { createTsModuleLoader, projectRoot } from './helpers/compileTsModule.mjs';

const { loadModule } = createTsModuleLoader();
const jphs = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'jphs.ts'));
const ltabMod = loadModule(path.join(projectRoot, 'src', 'utils', 'ctf', 'jphsLtab.ts'));

const latin1 = (text, cap) =>
  Uint8Array.from(text.slice(0, cap ?? text.length), ch => ch.charCodeAt(0) & 255);

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

const xorshift32 = seed => {
  let x = seed >>> 0;
  return () => {
    x ^= (x << 13) >>> 0;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= (x << 5) >>> 0;
    x >>>= 0;
    return x;
  };
};

// 受控伪流：按脚本循环出位，并统计消费数（资格状态机断言用）
const scriptedStream = script => {
  const state = { consumed: 0 };
  return {
    state,
    getCodeBit: () => script[state.consumed++ % script.length],
  };
};

const throwingStream = {
  getCodeBit: () => {
    throw new Error('此场景不应消费任何流位');
  },
};

// 每分量 1×1 块的网格：每个 ltab 表项恰好贡献 1 个位置（spos ≤ 63 ≤ wib=63）
const singleBlockGrids = fill => {
  const blocks = Int32Array.from({ length: 64 }, (_, i) => fill(i));
  const component = { blocks, widthInBlocks: 1, heightInBlocks: 1 };
  return [component, { ...component, blocks: blocks.slice() }, { ...component, blocks: blocks.slice() }];
};

const walkAll = (grids, stream) => {
  const scanner = jphs.createJphsWordScanner(grids, stream);
  const accepted = [];
  for (let cand = scanner.next(); cand !== null; cand = scanner.next()) accepted.push(cand);
  return accepted;
};

// ---- Blowfish 公开向量（bf.c TEST 同源 + Schneier 经典全零向量）----

test('Blowfish：Schneier 公开向量（含 bf.c 自带两支）加密锚定 + 解密往返', () => {
  const vectors = [
    {
      key: 'abcdefghijklmnopqrstuvwxyz',
      plain: [0x42, 0x4c, 0x4f, 0x57, 0x46, 0x49, 0x53, 0x48], // "BLOWFISH"
      cipher: [0x32, 0x4e, 0xd0, 0xfe, 0xf4, 0x13, 0xa2, 0x03],
    },
    {
      key: 'Who is John Galt?',
      plain: [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
      cipher: [0xcc, 0x91, 0x73, 0x2b, 0x80, 0x22, 0xf6, 0x84],
    },
    {
      key: '\0\0\0\0\0\0\0\0',
      plain: [0, 0, 0, 0, 0, 0, 0, 0],
      cipher: [0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78],
    },
  ];
  for (const { key, plain, cipher } of vectors) {
    const expanded = jphs.bfExpandUserKey(latin1(key));
    const encrypted = jphs.bfEncryptBytes(Uint8Array.from(plain), expanded);
    assert.equal(hex(encrypted), hex(Uint8Array.from(cipher)), `key=${JSON.stringify(key)} 加密向量`);
    const decrypted = jphs.bfDecryptBytes(encrypted, expanded);
    assert.equal(hex(decrypted), hex(Uint8Array.from(plain)), '解密往返');
  }
});

test('Blowfish：随机块加解密往返 + 字级/字节级接口一致', () => {
  const rnd = xorshift32(0xC0FFEE);
  const expanded = jphs.bfExpandUserKey(latin1('stegano'));
  for (let round = 0; round < 16; round += 1) {
    const block = Uint8Array.from({ length: 8 }, () => rnd() & 255);
    const roundTrip = jphs.bfDecryptBytes(jphs.bfEncryptBytes(block, expanded), expanded);
    assert.equal(hex(roundTrip), hex(block));
  }
});

// ---- 密钥流：双重初始加密、旋转、64 位链式再加密、确定性 ----

test('密钥流：流 i 首 64 位 = E(E(rot_i(IV))) 字节 MSB-first，第 65 位进入 E^3，三流按左旋区分', () => {
  const iv = Uint8Array.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
  const key = jphs.bfExpandUserKey(latin1('swordfish'));
  const keystream = jphs.createJphsKeystreams(iv, key);
  const rotations = [
    iv,
    Uint8Array.from([0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11]),
    Uint8Array.from([0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22]),
  ];
  for (let k = 0; k < 3; k += 1) {
    const block2 = jphs.bfEncryptBytes(jphs.bfEncryptBytes(rotations[k], key), key);
    for (let i = 0; i < 64; i += 1) {
      assert.equal(keystream.getCodeBit(k), (block2[i >> 3] >> (7 - (i & 7))) & 1, `流 ${k} 第 ${i} 位`);
    }
    const block3 = jphs.bfEncryptBytes(block2, key);
    assert.equal(keystream.getCodeBit(k), block3[0] >> 7, `流 ${k} 第 64 位应进入第三重加密块`);
  }
});

test('密钥流：同 IV 同口令两次构造序列一致；不同 IV 序列不同', () => {
  const key = jphs.bfExpandUserKey(latin1('determinism'));
  const iv = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 9]);
  const first = jphs.createJphsKeystreams(iv, key);
  const second = jphs.createJphsKeystreams(Uint8Array.from(iv), key);
  const other = jphs.createJphsKeystreams(Uint8Array.from([9, 8, 7, 6, 5, 4, 3, 2]), key);
  let diverged = false;
  for (let i = 0; i < 300; i += 1) {
    const a = first.getCodeBit(i % 3);
    assert.equal(a, second.getCodeBit(i % 3), `第 ${i} 位确定性`);
    if (a !== other.getCodeBit(i % 3)) diverged = true;
  }
  assert.ok(diverged, '不同 IV 必须产生不同密钥流');
});

// ---- 资格状态机（受控伪流逐分支）----

test('扫描计划：mode 0/1 大系数直通用且零流位消费，顺序与 ltab 一致，首块 IV 区被跳过', () => {
  const grids = singleBlockGrids(() => 5);
  const scanner = jphs.createJphsWordScanner(grids, throwingStream);
  const expected = ltabMod.JPHS_LTAB.filter(([coef, spos]) => coef !== 0 || spos > 7);
  let index = 0;
  for (const [coef, spos, mode] of expected) {
    if (mode > 1 || mode < 0) break; // 到首个 mode≥2 表项（[2,10,2]）前都不该消费流位
    const cand = scanner.next();
    assert.notEqual(cand, null);
    assert.equal(cand.coef, coef, `第 ${index} 个候选分量`);
    assert.equal(cand.lw, spos, `第 ${index} 个候选块内位置`);
    assert.equal(cand.lh, 0);
    assert.equal(cand.mode, mode);
    index += 1;
  }
  // 首个 mode 2 表项：大系数路径需要 1 个流 0 位，全 0 流应被拒绝
  const zeroStream = scriptedStream([0]);
  const acceptedModes = walkAll(grids, zeroStream).map(cand => cand.mode);
  assert.ok(!acceptedModes.includes(2), 'mode 2 大系数在全 0 流下不可用（门位须为 1）');
  assert.ok(!acceptedModes.includes(3), 'mode 3 预检门在全 0 流下不可用');
});

test('资格门极性：mode 2/3 门位须为 1，mode<0 两位须非 00，全 0 流只放行 mode 0/1', () => {
  const bigGrids = singleBlockGrids(() => 5); // |y|=5：过 -3 幅值门，不过 -7/-15
  const oneAccepted = new Set(walkAll(bigGrids, scriptedStream([1])).map(cand => cand.mode));
  assert.ok(oneAccepted.has(2), '全 1 流：mode 2 大系数应可用');
  assert.ok(oneAccepted.has(3), '全 1 流：mode 3（预检 1 + 终门 1）应可用');
  assert.ok(oneAccepted.has(-3), '全 1 流：-3 段两位 11（≠00）应可用');
  for (const mode of oneAccepted) {
    assert.ok(mode === 0 || mode === 1 || mode === 2 || mode === 3 || mode === -3, `意外接受 mode=${mode}`);
  }

  // 全 0 流：mode 0/1 大系数免门直通，其余门位极性全部拦截（含 -3 的 00 组合）
  const zeroAccepted = new Set(walkAll(bigGrids, scriptedStream([0])).map(cand => cand.mode));
  assert.deepEqual([...zeroAccepted].sort(), [0, 1], '全 0 流只应放行 mode 0/1');

  // 幅值门：|y|=2 时任何负 mode 都不可用（2 ≤ |mode|）
  const smallGrids = singleBlockGrids(() => 2);
  const amplitudeAccepted = walkAll(smallGrids, scriptedStream([1])).map(cand => cand.mode);
  assert.ok(amplitudeAccepted.every(mode => mode >= 0), '|y|=2 不应进入任何负 mode 段');

  // |y|=20 过全部幅值门（-3/-7/-15），全 1 流下负 mode 段均可用
  const hugeGrids = singleBlockGrids(() => 20);
  const negativeAccepted = new Set(walkAll(hugeGrids, scriptedStream([1])).map(cand => cand.mode));
  assert.ok(
    negativeAccepted.has(-3) && negativeAccepted.has(-7) && negativeAccepted.has(-15),
    '幅值过关的负 mode 段在两位 11 下应可用',
  );
});

test('mode 0 小系数（|y|≤1）：1 个流 0 位须为 0；mode 1 小系数：2 连续 0 位', () => {
  // 分量 0 位置 8（表项 [0,8,0]）设为 1，其余全大
  const grids = singleBlockGrids(() => 5);
  grids[0].blocks[8] = 1;

  const zeros = scriptedStream([0]);
  let scanner = jphs.createJphsWordScanner(grids, zeros);
  let cand = scanner.next(); // 表项 1 [2,0,0]
  cand = scanner.next(); // 表项 2 [1,0,0]
  cand = scanner.next(); // 表项 3 [0,8,0]：y=1，1 个 0 位 → 接受
  assert.equal(cand.coef, 0);
  assert.equal(cand.lw, 8);
  assert.equal(cand.mode, 0);
  assert.equal(zeros.state.consumed, 1, 'mode 0 小系数恰好消费 1 位');

  const ones = scriptedStream([1]);
  scanner = jphs.createJphsWordScanner(grids, ones);
  scanner.next();
  scanner.next();
  cand = scanner.next(); // [0,8,0] y=1 被拒 → 跳过 [0,1,0]（IV 区）→ [0,9,0] 大系数直通
  assert.equal(cand.lw, 9, '1 位为 1 时 mode 0 小系数被拒');
  assert.equal(ones.state.consumed, 1);

  // mode 1（表项 11 [2,1,1]）：分量 2 位置 1 设为 1
  const mode1Grids = singleBlockGrids(() => 5);
  mode1Grids[2].blocks[1] = 1;
  const zero2 = scriptedStream([0, 0]);
  scanner = jphs.createJphsWordScanner(mode1Grids, zero2);
  let ninth = null;
  for (let i = 0; i < 9; i += 1) ninth = scanner.next();
  assert.equal(ninth.coef, 2);
  assert.equal(ninth.lw, 1);
  assert.equal(ninth.mode, 1);
  assert.equal(zero2.state.consumed, 2, 'mode 1 小系数恰好消费 2 位');

  const one2 = scriptedStream([1, 1]);
  scanner = jphs.createJphsWordScanner(mode1Grids, one2);
  for (let i = 0; i < 9; i += 1) ninth = scanner.next();
  assert.equal(ninth.coef, 1, '非 00 位时 mode 1 小系数被拒，落到下一表项 [1,1,1] 的大系数');
  assert.equal(one2.state.consumed, 2);
});

test('mode 2 小系数三段路径：00 后还需第 3 位为 1；首位为 1 时只消费 2 位即拒', () => {
  const target = ltabMod.JPHS_LTAB.findIndex(([coef, spos]) => coef === 2 && spos === 10);
  assert.ok(target > 0);

  // 走到首个消费流位的机会（此前的 mode 0/1 大系数均零消费），该次接受即覆盖表项 [2,10,2] 的判定
  const run = script => {
    const grids = singleBlockGrids(() => 5);
    grids[2].blocks[10] = 1;
    const stream = scriptedStream(script);
    const scanner = jphs.createJphsWordScanner(grids, stream);
    for (let i = 0; i < 40; i += 1) {
      const next = scanner.next();
      assert.notEqual(next, null, '计划内必有接受');
      if (stream.state.consumed > 0) return { cand: next, consumed: stream.state.consumed };
    }
    throw new Error('未到达 mode 2 表项');
  };

  // 脚本 001：y=1 → b1b2=00 → 第 3 位 1 → 接受，共 3 位
  const accepted = run([0, 0, 1]);
  assert.equal(accepted.cand.coef, 2);
  assert.equal(accepted.cand.lw, 10);
  assert.equal(accepted.cand.mode, 2);
  assert.equal(accepted.consumed, 3, '001 路径消费 3 位');

  // 脚本 000：y=1 三位后仍 0 → 拒；随后 [1,10,2]/[2,17,2]/[1,17,2] 大系数各 1 位被拒 → [0,12,0] 直通
  const rejected = run([0]);
  assert.equal(rejected.cand.lw, 12, '000 时 mode 2 小系数被拒，落到后续 mode 0 表项');
  assert.equal(rejected.consumed, 6, '3 位（小系数路径）+ 3 位（三个 mode 2 大系数门）');

  // 脚本 1：y=1 → b1=1 → (1<<1)|b2 ≠ 0 → 拒，只消费 2 位；随后 [1,10,2] 大系数 1 位为 1 → 接受
  const earlyOut = run([1]);
  assert.equal(earlyOut.cand.coef, 1);
  assert.equal(earlyOut.cand.lw, 10);
  assert.equal(earlyOut.cand.mode, 2);
  assert.equal(earlyOut.consumed, 3, '2 位（首位 1 提前拒）+ 1 位（下一表项大系数门）');
});

test('尾部门：tail_on=1/2/3 时每候选额外消费同数个流 2 位且须为 1；全 0 时整计划无接受', () => {
  const grids = singleBlockGrids(() => 5);
  for (const on of [1, 2, 3]) {
    const stream = scriptedStream([1]);
    const scanner = jphs.createJphsWordScanner(grids, stream);
    scanner.tail.on = on;
    let accepted = 0;
    while (scanner.next() !== null) accepted += 1;
    // 首个 mode 2 表项（索引 32）之前的 29 个接受均为 mode 0/1 大系数（0 个模式位 + on 个尾部位）
    assert.ok(accepted > 29, `tail_on=${on} 应仍有大量接受`);
    assert.equal(stream.state.consumed >= accepted * on, true, `tail_on=${on} 消费数不少于 接受数×${on}`);
    // 精确核对第一个候选：mode 0 大系数 0 位 + 尾部位 on 位
    const precise = scriptedStream([1]);
    const preciseScanner = jphs.createJphsWordScanner(grids, precise);
    preciseScanner.tail.on = on;
    const first = preciseScanner.next();
    assert.equal(first.coef, 2, '首个候选仍是表项 [2,0,0]');
    assert.equal(precise.state.consumed, on, `tail_on=${on} 首个 mode 0 候选恰好消费 ${on} 个尾部位`);
  }
  const zeroStream = scriptedStream([0]);
  const scanner = jphs.createJphsWordScanner(grids, zeroStream);
  scanner.tail.on = 1;
  assert.equal(scanner.next(), null, '尾部位为 0 时任何候选都不可用');
});

test('尾部升级：tail<0 时每越过一个表项边界升一级（0→1/1200 → 2/120 → 3/999999）', () => {
  const grids = singleBlockGrids(() => 5);
  const scanner = jphs.createJphsWordScanner(grids, scriptedStream([1]));
  // 首个 next()：表项 0 是 IV 区跳过 → 越界推进到表项 1 时触发 0→1
  scanner.tail.value = -1;
  scanner.tail.on = 0;
  let cand = scanner.next();
  assert.equal(cand.coef, 2);
  assert.equal(scanner.tail.on, 1);
  assert.equal(scanner.tail.value, 1200);
  scanner.tail.value = -1;
  cand = scanner.next(); // 表项 1 行尽 → 推进到表项 2 触发 1→2
  assert.equal(cand.coef, 1);
  assert.equal(scanner.tail.on, 2);
  assert.equal(scanner.tail.value, 120);
  scanner.tail.value = -1;
  cand = scanner.next(); // 2→3
  assert.equal(cand.lw, 8); // 表项 3 [0,8,0]
  assert.equal(scanner.tail.on, 3);
  assert.equal(scanner.tail.value, 999999);
});

// ---- 端到端闭环：测试侧实现 jphide 嵌入方向，再由 jphsSeek 提取 ----

const mergeWord = (y, bit, mode) => {
  if (mode < 0) {
    const magnitude = Math.abs(y);
    const merged = (magnitude & ~2) | (bit << 1);
    return y < 0 ? -merged : merged;
  }
  if (y === 0) return bit; // 提取只看 |y|，符号任取
  if (y === 1 || y === -1) return bit === 1 ? y : 0;
  const magnitude = Math.abs(y);
  const merged = (magnitude & ~1) | bit;
  return y < 0 ? -merged : merged;
};

// 规格对称的嵌入端：与 jpseek 相同的扫描/资格/流状态机，位写入方向相反
const embedJphide = (grids, passphrase, payload) => {
  const iv = Uint8Array.from({ length: 8 }, (_, i) => grids[0].blocks[i] & 255);
  const key = jphs.bfExpandUserKey(latin1(passphrase, 120));
  const keystream = jphs.createJphsKeystreams(iv, key);
  const scanner = jphs.createJphsWordScanner(grids, keystream);
  const modesUsed = new Set();

  const putBit = bit => {
    const cand = scanner.next();
    if (cand === null) throw new Error('测试嵌入：扫描计划耗尽（网格容量不足）');
    modesUsed.add(cand.mode);
    const grid = grids[cand.coef];
    grid.blocks[cand.lh * grid.widthInBlocks * 64 + cand.lw] = mergeWord(cand.y, bit, cand.mode);
  };

  // 长度头：len 大端 3 字节 + 0 填充 → Blowfish ECB → LSB-first 拆 64 位嵌入
  const headerPlain = new Uint8Array(8);
  headerPlain[0] = payload.length >> 16;
  headerPlain[1] = (payload.length >> 8) & 255;
  headerPlain[2] = payload.length & 255;
  const headerCipher = jphs.bfEncryptBytes(headerPlain, key);
  for (let i = 0; i < 8; i += 1) {
    for (let j = 0; j < 8; j += 1) putBit((headerCipher[i] >> j) & 1);
  }

  scanner.tail.value = payload.length * 8 - ltabMod.JPHS_TAIL1;
  scanner.tail.on = 0;

  // 数据位：明文 MSB-first XOR 流 1（流间独立，与提取端每流内部序列一致）
  for (let count = 0; count < payload.length; count += 1) {
    for (let j = 7; j >= 0; j -= 1) {
      const plainBit = (payload[count] >> j) & 1;
      const ksBit = keystream.getCodeBit(1);
      putBit(plainBit ^ ksBit);
      scanner.tail.value -= 1;
    }
  }
  return modesUsed;
};

const makeGrids = (widthBlocks, heightBlocks, seed) => {
  const rnd = xorshift32(seed);
  const build = () => {
    const blocks = new Int32Array(widthBlocks * heightBlocks * 64);
    for (let i = 0; i < blocks.length; i += 1) {
      const roll = rnd() % 100;
      const magnitude = roll < 70 ? 2 + (rnd() % 29) : roll < 85 ? rnd() % 2 : 4 + (rnd() % 37);
      blocks[i] = rnd() & 1 ? magnitude : -magnitude;
    }
    return { blocks, widthInBlocks: widthBlocks, heightInBlocks: heightBlocks };
  };
  return [build(), build(), build()];
};

const ivSnapshot = grids => Array.from(grids[0].blocks.subarray(0, 8));

test('端到端闭环（小载荷）：嵌入 → 提取还原 flag 文本；IV 区系数不被改动', () => {
  const grids = makeGrids(8, 8, 0x5EE0);
  const passphrase = 'correct horse battery staple';
  const payload = Uint8Array.from(
    Array.from('flag{jphide_si_a_round_trip_ok}', ch => ch.charCodeAt(0)),
  );
  const before = ivSnapshot(grids);
  embedJphide(grids, passphrase, payload);
  assert.deepEqual(ivSnapshot(grids), before, '首块前 8 系数（IV 区）必须原样保留');
  const extracted = jphs.jphsSeek(grids, passphrase);
  assert.deepEqual(Array.from(extracted), Array.from(payload));
});

test('端到端闭环（大载荷 800B）：走穿 mode 2/3 与负 mode 段（bit1 语义）后完整还原', () => {
  // mode 3 全部位于表尾（167+ 项），需要载荷超过前段产出才能把扫描推到那里：
  // 20×20 网格每表项 400 位置，800B 载荷恰好推穿 mode 3 区，同时留有余量不至耗尽
  const grids = makeGrids(20, 20, 0xD17C);
  const passphrase = ' passphrase with  spaces ';
  const rnd = xorshift32(0xFEED);
  const flag = Array.from('flag{deep_walk_covers_negative_modes}', ch => ch.charCodeAt(0));
  const payload = Uint8Array.from([
    ...flag,
    ...Array.from({ length: 800 - flag.length }, () => rnd() & 255),
  ]);
  const modesUsed = embedJphide(grids, passphrase, payload);
  assert.ok(modesUsed.has(2) && modesUsed.has(3), '载荷应走穿 mode 2/3 段');
  assert.ok(Array.from(modesUsed).some(mode => mode < 0), '载荷应走穿负 mode 段（bit1 写入语义）');
  const extracted = jphs.jphsSeek(grids, passphrase);
  assert.deepEqual(Array.from(extracted), Array.from(payload));
});

test('端到端闭环：错误口令与未嵌入网格都不能还原载荷', () => {
  const grids = makeGrids(8, 8, 0xBAD1);
  const passphrase = 'right one';
  const payload = Uint8Array.from(Array.from('flag{auth_fail_expected}', ch => ch.charCodeAt(0)));
  embedJphide(grids, passphrase, payload);

  const trySeek = (targetGrids, pass) => {
    try {
      return Array.from(jphs.jphsSeek(targetGrids, pass));
    } catch (error) {
      assert.match(error.message, /未完整恢复|长度头|3 分量/, `错误应为可诊断中文：${error.message}`);
      return null;
    }
  };
  const wrongPass = trySeek(grids, 'wrong one');
  assert.ok(wrongPass === null || wrongPass.some((b, i) => b !== payload[i]), '错误口令不得还原载荷');
  const cleanGrids = makeGrids(8, 8, 0xBAD1);
  const clean = trySeek(cleanGrids, passphrase);
  assert.ok(clean === null || clean.some((b, i) => b !== payload[i]), '未嵌入网格不得产出载荷');
});

// ---- 入口校验 ----

test('分量数校验：非 3 分量抛中文错误（灰度/CMYK 不适用 jphide）', () => {
  const one = makeGrids(2, 2, 1).slice(0, 1);
  assert.throws(() => jphs.jphsSeek(one, 'x'), /3 分量/);
  const four = [...makeGrids(2, 2, 2), makeGrids(2, 2, 3)[0]];
  assert.throws(() => jphs.jphsSeek(four, 'x'), /3 分量.*4 个分量/);
});
