// CBC PKCS#7 padding oracle 真实攻击引擎（mpgen/padding-oracle-attack 的 block_search_byte 算法移植）。
// oracle 以回调注入：probePrev 是伪造的"前块/IV"，target 是被攻击的密文块，回调返回
// "以 probePrev 为 IV 解密 target 单块后 PKCS#7 padding 是否合法"。引擎不接触密钥，只消费布尔应答。
import { bytesToBuffer, bytesToHex, hexToBytes } from './bases';
import { utf8Decoder, utf8Encoder } from './alphabets';

export type PaddingOracle = (probePrev: Uint8Array, target: Uint8Array) => boolean | Promise<boolean>;

export interface PaddingOracleAttackResult {
  plaintext: Uint8Array;
  queries: number;
  blockCount: number;
  paddingInvalid: boolean;
  steps: string[];
}

const BLOCK_SIZE = 16;

// WebCrypto 入口：node ≥19 与浏览器全局均有；vm 测试沙箱把 globalThis 换成了瘦身对象，需回退裸 crypto 标识符
const runtimeCrypto = (): Crypto => globalThis.crypto ?? crypto;

export const paddingOracleDecrypt = async (
  cipher: Uint8Array,
  oracle: PaddingOracle,
  iv?: Uint8Array,
): Promise<PaddingOracleAttackResult> => {
  if (cipher.length === 0) throw new Error('密文为空：padding oracle 攻击需要至少一个 16 字节密文块');
  if (cipher.length % BLOCK_SIZE !== 0) throw new Error(`密文长度 ${cipher.length} 不是 16 的整数倍（AES-CBC 块大小 16），无法逐块攻击`);
  if (iv !== undefined && iv.length !== BLOCK_SIZE) throw new Error(`IV 长度 ${iv.length} 无效：AES-CBC 需要 16 字节 IV`);
  const blockCount = cipher.length / BLOCK_SIZE;
  if (iv === undefined && blockCount < 2) throw new Error('缺少 IV 且密文只有 1 块：第一块明文 = D(C1) xor IV，无 IV 时没有任何可恢复块');
  // 查询预算：每字节最多 256 次扫描 × 16 字节 × 块数，×3 余量覆盖歧义消解二轮探测；超限视为 oracle 行为异常，防死循环
  const maxQueries = BLOCK_SIZE * 256 * blockCount * 3;
  let queries = 0;
  const probe = async (prev: Uint8Array, target: Uint8Array): Promise<boolean> => {
    if (queries >= maxQueries) throw new Error(`oracle 查询数已达预算上限 ${maxQueries}（16×256×${blockCount}×3）：oracle 不符合标准 PKCS#7 语义，中止以防死循环`);
    queries += 1;
    return await oracle(prev, target);
  };
  const firstBlock = iv === undefined ? 1 : 0;
  const steps: string[] = [`输入 ${blockCount} 个密文块（${cipher.length} 字节），查询预算 ${maxQueries}${iv === undefined ? '；无 IV，跳过第 1 块（其明文依赖 IV）' : '；含 IV，可恢复全部明文'}`];
  const intermediates = new Map<number, Uint8Array>();
  // 从最后一个块攻到第一个块：每块独立恢复中间值 D(C_block)，与顺序无关，倒序保持与"末块 padding 剥离"叙述一致
  for (let block = blockCount - 1; block >= firstBlock; block -= 1) {
    const target = cipher.slice(block * BLOCK_SIZE, (block + 1) * BLOCK_SIZE);
    const intermediate = new Uint8Array(BLOCK_SIZE);
    const queriesAtBlockStart = queries;
    let ambiguities = 0;
    for (let position = BLOCK_SIZE - 1; position >= 0; position -= 1) {
      const pad = BLOCK_SIZE - position; // 当前位置期望的 pad 值：position=15 → 1，position=0 → 16
      const base = new Uint8Array(BLOCK_SIZE); // base[0..position-1] 恒为 0：确定性构造，保证歧义分析可复现
      for (let tail = position + 1; tail < BLOCK_SIZE; tail += 1) base[tail] = intermediate[tail] ^ pad; // 已知中间值 ^ pad → 该位置解密出 pad
      const candidates: number[] = [];
      for (let guess = 0; guess < 256; guess += 1) {
        base[position] = guess;
        if (await probe(base, target)) candidates.push(guess);
      }
      if (candidates.length === 0) throw new Error(`块 ${block + 1}/${blockCount} 位置 ${position} 扫描 0x00-0xff 全部无效：oracle 不符合 PKCS#7 padding 语义或密文块损坏`);
      let chosen = candidates[0];
      if (candidates.length > 1) {
        // 歧义消解：pad=1 处真候选（末字节=0x01）是单字节 padding，对前面字节不敏感；碰巧合法的多字节 padding
        // （末字节 v≥2）要求其前一字节严格等于 v —— 把 position-1 处换成任意非 0x00 扰动值后必失效，
        // 二轮探测的唯一幸存者即真候选（数学上确定性区分，不依赖概率）
        if (position === 0) throw new Error(`块 ${block + 1}/${blockCount} 位置 0 出现 ${candidates.length} 个候选：pad=16 时解唯一，oracle 语义异常`);
        const survivors: number[] = [];
        for (const candidate of candidates) {
          const verify = Uint8Array.from(base);
          verify[position] = candidate;
          verify[position - 1] = 0x80 ^ pad; // pad∈1..16 时恒非零，等价于把该位置字节换成另一个值
          if (await probe(verify, target)) survivors.push(candidate);
        }
        if (survivors.length !== 1) throw new Error(`块 ${block + 1}/${blockCount} 位置 ${position} 歧义消解后剩 ${survivors.length} 个候选（期望唯一）：oracle 语义异常`);
        chosen = survivors[0];
        ambiguities += 1;
      }
      intermediate[position] = chosen ^ pad;
    }
    intermediates.set(block, intermediate);
    steps.push(`块 ${block + 1}/${blockCount}：16 个中间值字节全部恢复（查询 ${queries - queriesAtBlockStart} 次${ambiguities > 0 ? `，歧义消解 ${ambiguities} 处` : ''}）`);
  }
  const recoveredBlocks = blockCount - firstBlock;
  const plaintext = new Uint8Array(recoveredBlocks * BLOCK_SIZE);
  for (let block = firstBlock; block < blockCount; block += 1) {
    const previous = block === 0 ? iv! : cipher.slice((block - 1) * BLOCK_SIZE, block * BLOCK_SIZE);
    const intermediate = intermediates.get(block)!;
    for (let offset = 0; offset < BLOCK_SIZE; offset += 1) plaintext[(block - firstBlock) * BLOCK_SIZE + offset] = intermediate[offset] ^ previous[offset];
  }
  // 末块真实 PKCS#7 padding 剥离：pad=明文末字节，须 1..16 且尾部 pad 个字节全等于 pad；校验失败不剥（paddingInvalid 标注）
  const padValue = plaintext[plaintext.length - 1];
  let paddingInvalid = true;
  if (padValue >= 1 && padValue <= BLOCK_SIZE) {
    paddingInvalid = false;
    for (let offset = plaintext.length - padValue; offset < plaintext.length; offset += 1) if (plaintext[offset] !== padValue) paddingInvalid = true;
  }
  const stripped = paddingInvalid ? plaintext : plaintext.slice(0, plaintext.length - padValue);
  steps.push(`明文重组：${recoveredBlocks} 块与前块/IV 异或完成；末块 padding=${padValue}${paddingInvalid ? ' 校验失败（paddingInvalid，保留原始尾部）' : ' 校验通过并剥离'}；共 ${queries} 次 oracle 查询`);
  return { plaintext: stripped, queries, blockCount, paddingInvalid, steps };
};

const REPORT_PLAINTEXT_LIMIT = 64; // 模式A明文截断上限：控制 oracle 查询量（每块约 4096+ 次探测）
const MODE_B_MAX_BLOCKS = 64; // 模式B密文块数上限：64 块 ≈ 26 万次探测已属重演示，更大输入应分段
const AES_KEY_HEX_LENGTHS = [32, 48, 64]; // hex 字符数 → AES-128/192/256

const latin1Of = (bytes: Uint8Array) => Array.from(bytes, byte => String.fromCharCode(byte)).join('');

const importAesCbcKey = async (keyBytes: Uint8Array, usages: KeyUsage[]) =>
  await runtimeCrypto().subtle.importKey('raw', bytesToBuffer(keyBytes), { name: 'AES-CBC' }, false, usages);

// 本地 padding oracle：解密 (probePrev 作 IV + target 单块)，PKCS#7 非法则 WebCrypto 抛错 → false，模拟 vulnerable server
const makeLocalAesCbcOracle = (aesKey: CryptoKey): PaddingOracle => async (probePrev, target) => {
  try {
    await runtimeCrypto().subtle.decrypt({ name: 'AES-CBC', iv: bytesToBuffer(probePrev) }, aesKey, bytesToBuffer(target));
    return true;
  } catch {
    return false;
  }
};

// 一键报告入口：模式A（纯文本 → 本地随机 key/IV 加密后自验证演示）/ 模式B（cipherHex=...&ivHex=...&keyHex=... 字段攻击给定密文）
export const paddingOracleReport = async (value: string): Promise<string> => {
  const fieldHex = (key: string): string | null => {
    const match = value.match(new RegExp('(?:^|[^A-Za-z0-9_])' + key + '[ \t]*[=:][ \t]*([0-9a-fA-F]+)', 'm'));
    return match ? match[1] : null;
  };
  const cipherHex = fieldHex('cipherHex');
  if (cipherHex !== null) {
    const keyHex = fieldHex('keyHex');
    if (keyHex === null) throw new Error('输入含 cipherHex 字段（模式B）：还需 keyHex=<hex>（32/48/64 hex 字符 = AES-128/192/256）用于构造本地 oracle');
    if (!AES_KEY_HEX_LENGTHS.includes(keyHex.length)) throw new Error(`keyHex 长度 ${keyHex.length} 无效：必须是 32/48/64（AES-128/192/256）`);
    if (cipherHex.length < 32 || cipherHex.length % 32 !== 0) throw new Error(`cipherHex 长度 ${cipherHex.length} 无效：必须是 32 的倍数（每块 16 字节 = 32 hex）`);
    // 块数上限：每块约 4096 次串行 await 探测，超限在人类时间内永不收敛（查询预算防不住的大输入区间）。
    if (cipherHex.length > 32 * MODE_B_MAX_BLOCKS) throw new Error(`cipherHex 超 ${MODE_B_MAX_BLOCKS} 块上限（${cipherHex.length / 32} 块）：请只贴目标密文片段或分段攻击`);
    const ivHex = fieldHex('ivHex');
    if (ivHex !== null && ivHex.length !== 32) throw new Error(`ivHex 长度 ${ivHex.length} 无效：必须是 32 hex 字符（16 字节）`);
    const aesKey = await importAesCbcKey(hexToBytes(keyHex), ['decrypt']);
    const result = await paddingOracleDecrypt(hexToBytes(cipherHex), makeLocalAesCbcOracle(aesKey), ivHex === null ? undefined : hexToBytes(ivHex));
    return JSON.stringify({
      mode: 'B：给定密文攻击（keyHex 在本地构造 oracle，模拟 padding error 可区分的 vulnerable server）',
      cipherHex: cipherHex.toLowerCase(),
      ivHex: ivHex === null ? null : ivHex.toLowerCase(),
      keyHex: keyHex.toLowerCase(),
      blocks: result.blockCount,
      queries: result.queries,
      recovered: utf8Decoder.decode(result.plaintext),
      recoveredHex: bytesToHex(result.plaintext),
      recoveredLatin1: latin1Of(result.plaintext),
      matched: null,
      paddingInvalid: result.paddingInvalid,
      steps: result.steps,
      note: `字段用 = 或 : 赋值，; 或换行分隔${ivHex === null ? '；未提供 ivHex：第 1 块明文依赖 IV，已跳过（recovered 从第 2 块起）' : ''}。matched=null：无参考明文可比。`,
    }, null, 2);
  }
  // 模式A：随机 AES-256 key/IV 加密输入文本，再仅凭 oracle 布尔回调完整还原（自验证 matched）
  const text = value.trim().slice(0, REPORT_PLAINTEXT_LIMIT) || 'flag{p4dding_0racle_r34l_attack}';
  const keyBytes = runtimeCrypto().getRandomValues(new Uint8Array(32));
  const ivBytes = runtimeCrypto().getRandomValues(new Uint8Array(16));
  const aesKey = await importAesCbcKey(keyBytes, ['encrypt', 'decrypt']);
  const plainBytes = utf8Encoder.encode(text);
  const cipherBytes = new Uint8Array(await runtimeCrypto().subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, aesKey, plainBytes));
  const result = await paddingOracleDecrypt(cipherBytes, makeLocalAesCbcOracle(aesKey), ivBytes);
  const matched = result.plaintext.length === plainBytes.length && plainBytes.every((byte, index) => result.plaintext[index] === byte);
  return JSON.stringify({
    mode: 'A：本地自验证演示（随机 AES-256 key/IV 加密输入文本，攻击仅消费 oracle 布尔回调即完整还原）',
    plaintext: text,
    truncated: value.trim().length > REPORT_PLAINTEXT_LIMIT,
    keyHex: bytesToHex(keyBytes),
    ivHex: bytesToHex(ivBytes),
    cipherHex: bytesToHex(cipherBytes),
    blocks: result.blockCount,
    queries: result.queries,
    recovered: utf8Decoder.decode(result.plaintext),
    recoveredHex: bytesToHex(result.plaintext),
    matched,
    paddingInvalid: result.paddingInvalid,
    steps: result.steps,
    note: `输入按明文处理（截断至 ${REPORT_PLAINTEXT_LIMIT} 字节控制查询量）；输入含 cipherHex=... 字段则切换模式B。`,
    mitigation: '防御：使用 AEAD（AES-GCM）或 encrypt-then-MAC；解密失败统一报错，绝不让 padding 错误与其他错误可区分。',
  }, null, 2);
};
