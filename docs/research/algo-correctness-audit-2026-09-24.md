# Payloader 算法正确性与能力边界审计报告

- 日期：2026-09-24
- 范围：已提交的既有算法实现（**不含**并行改动中的 paddingOracle.ts / magicChain.ts / crc32Attack.ts / bitPlaneScan.ts 及其测试）
- 方式：只读源码审计 + 临时 node 对拍脚本（%TEMP%，已清理）。TS 模块经 `tests/helpers/compileTsModule.mjs` 沙箱加载，与仓库测试同语义。
- 对拍基准：RFC 4648/9285/3394、BIP-173/350、维基教科书向量、RsaCtfTool 语义、独立参考实现（basE91 / ascii85 / Enigma I / bubble-babble / yEnc 从零重写对照）。
- 审计对象：`src/utils/codec/` 下 rsa.ts(2648L)、numberTheory.ts(423L)、math.ts(236L)、classical.ts(646L)、textEncodings.ts(1028L)、bases.ts(760L)、alphabets.ts(131L)、autoSolve.ts(953L)、attacks.ts(554L)、crypto.ts(AES 部分)、operations.ts(标签)。
- 共执行对拍断言约 **220 项**，其中实锤实现问题 2 个 P1、4 个 P2；其余失败项经手工复核均为本报告撰写过程中的期望值笔误，实现正确。

---

## 一、确认正确的项（对拍向量）

### RSA / 数论（numberTheory.ts / math.ts / rsa.ts）

| 项目 | 向量 / 方法 | 结果 |
|---|---|---|
| `bigintIsqrt` / `bigIntSqrt` | 0..20000 穷举不变量 + 50 组随机 64..512bit | ✓ |
| `bigintIroot` | n≤4000 × k=2..10 穷举 + 随机 640bit k=3/5/7 | ✓ 无 off-by-one |
| `bigintGcdext` / `bigintInvMod` | Bezout 恒等式、非互素返回 null | ✓ |
| `bigintIsPrime` | 素数 {2,3,104729,2^61-1,2^127-1…}；合数含 Carmichael 561/41041、强伪素数 3215031751 / 3825123056546413051 / 2^67-1 | ✓ 全部正确判定 |
| 连分数/收敛子 | cf(355,113) 末收敛=355/113 | ✓ |
| `crtPair`/`crtList` | 2≡mod3,3≡mod5→8 mod15；三式→23 mod105；非互素→null | ✓ |
| **Wiener（numberTheory.wienerAttack）** | 经典构造（q<p<2q，d≈n^0.25/10），128bit 素数对，恢复 d；e=3 时无误报 | ✓ |
| **Wiener（rsa.ts tryRsaWienerAttack）** | 同构造，512bit，恢复 d 与明文，0ms | ✓ |
| `fermatFactor` | 近素数分解、偶数、完全平方（p=p） | ✓ |
| `pollardRho`（Brent） | 10403=101×103 | ✓ |
| **`pollardPMinus1`** | n=40961×1000003（p-1=2^13·5）：B=10000/8192 → 40961；B=100 → null。语义=对每个 ≤B 素数取 ≤B 最大幂连乘（等价 lcm(1..B)），与 RsaCtfTool 一致 | ✓ |
| `solvePartialQ`（dp 泄露） | dp=d mod (p-1) → 恢复 q | ✓ |
| `hastadBroadcast` | e=3 ×3 互素模数 → 恢复 m；记录不足（溢出场景）→ null | ✓ |
| `commonFactorGcd` / `tryRsaSharedPrimeAttack` | 共享素数双解密 | ✓ |
| `tryRsaCommonModulusAttack` | e1=1114111,e2=65537 扩展欧几里得（含负指数 rsaModPowSigned） | ✓ |
| `tryRsaExponentReduction` | e=4, gcd(e,φ)=4, m^4<n → 精确 4 次根 | ✓ |
| `tryRsaLowExponentRoots` | miniRSA k=7（≤2000 界内）；未取模 c=m^3 | ✓ |
| `rsaCrtDecrypt` | p/q/dp/dq/qinv 路径 = 直接 d 解密 | ✓ |
| `tonelliShanksRoot` | p≡1 mod 4 大素数 QR 开方 | ✓ |
| `m≥n` 防呆 | 编码方向显式 throw "RSA input must be smaller than modulus n"（双向都查） | ✓ |
| `rsaHelper` | 小 n 直解正确；大 n（不可分解）无错误 directRecovery | ✓ |

### 古典密码（classical.ts / textEncodings.ts）

| 项目 | 向量 | 结果 |
|---|---|---|
| Vigenère | ATTACKATDAWN/LEMON → LXFOPVEFRNHR（经典） | ✓ |
| Beaufort / Autokey | 独立实现对照 / roundtrip | ✓ |
| **Playfair** | key=MONARCHY 方阵 `MONARCHYBDEFGIKLPQSTUVWXZ`；INSTRUMENTS → `GATLMZCLRQXA`（X 填充约定，手工逐对核验）；BALLOON → BA/LX/LO/ON | ✓（约定见边界 §3.1） |
| Hill 2×2 | [[3,3],[2,5]] "HELP"→"HIAT"（教科书） | ✓ |
| **Affine** | a=5,b=8 "AFFINE"→"IHHWVC"（维基前缀一致）；a 与 26 互素校验（a=2 拒绝）双向校验 | ✓ |
| Bacon | 24 变体（J=I 码）与 26 变体（J=AABAB? 实为 ABAAB=index9）均与字母表定义自洽；0/1 记法兼容 | ✓ |
| Polybius / TapCode | J→24（I/J 合并）；K→C（tap 惯例） | ✓ |
| Rail Fence | 经典向量 `WECRLTEERDSOEEFEAOCAIVDEN` 解码 → WEAREDISCOVEREDFLEEATONCE | ✓ |
| **Porta** | 维基表逐项：key A: a↔n；key C: a↔o，互合性成立 | ✓ |
| Columnar（不均匀列）/ Bifid / Trifid / FourSquare / Nihilist | roundtrip | ✓ |
| **ADFGX / ADFGVX** | 代换+列置换 roundtrip（含 36 字符 6×6 ADFGVX） | ✓ |
| **Enigma I** | 与从零独立实现（含 ring 设置、双步进）5 组随机设置全部一致；文献向量 AAAAA→BDZGO ✓；转子接线/缺口/反射体逐项核对无误 | ✓ |
| Caesar / Atbash / rot47 / rot18 / Trithemius | rot47("hello")="96==@" 手算一致 | ✓ |

### 编码系列（bases.ts / textEncodings.ts）

| 项目 | 向量 | 结果 |
|---|---|---|
| Base64/Base64URL | RFC 4648 Man/Ma/M（TWFu/TWE=/TQ==）；无 padding 解码 | ✓ |
| **Base32/Base32Hex** | RFC 4648 全 8 向量（""/f/fo/foo/foob/fooba/foobar） | ✓ |
| Crockford Base32 | I/L→1、O→0 容错；U 拒绝 | ✓ |
| **Base45** | RFC 9285 官方向量："AB"→"BB8"、"Hello!!"→"%69 VD92EX0"（datatracker 原文核对）；c1c2c3 低位序正确 | ✓ |
| Base58 | 前导零 [0,0,1]→"112" | ✓ |
| Base62 / Base36 | roundtrip、大小写、前导零 | ✓ |
| **basE91** | 与独立参考实现对照（含 97 字节长串）；"test"→"fDI,kVL"、"Hello World"→">OwJh>Io0Tv!8P" | ✓ |
| Ascii85 | 与独立参考实现对照（z 空块、部分尾组） | ✓ |
| **UUencode** | "Cat"→`#0V%T`（手工逐 6bit 组核验）；45 字节行长标记；ASCII roundtrip | ✓（二进制载荷见 P2-1） |
| XXencode | 6bit 组 + xx 字母表自洽；roundtrip | ✓ |
| z-base-32 / **Base32768** | roundtrip；表规模 15bit=32768 / 7bit=128（qntm v5 语义） | ✓ |
| **Bech32/Bech32m** | BIP-173 P2WPKH 编码 `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` ✓；BIP340 风格空数据向量 ✓；bech32m 识别 ✓；损坏向量响亮抛错 ✓ | ✓（地址解码见 P1-2） |
| Quoted-Printable | é→=C3=A9；软换行 ≤76（73+3 规则）；roundtrip | ✓ |
| UTF-7 | £→`+AKM-`（与 Python utf-7 一致） | ✓ |
| Bubble Babble | spec 公式独立实现对照；""→xexax、"1234567890"→xesef-disof-gytuf-katof-movif-baxux | ✓ |
| **CRC32** | "123456789"→`cbf43926`（IEEE 802.3，init/xorout/refin 全对）；空串→00000000 | ✓ |
| **CRC16** | "123456789"→`4b37` = **CRC-16/MODBUS**（poly 0x8005 反射、init 0xFFFF、xorout 0）——值正确，标签问题见 P2-4 | ✓ |
| Adler-32 | "Wikipedia"→`11e60398` | ✓ |
| **MD5（手写）** | RFC 1321 全部 4 组 + 空串 | ✓ |
| **MD4 / NTLM** | RFC 1320（"",abc）；NTLM("password")=8846f7…（UTF-16LE→MD4） | ✓ |
| SHA-256 | WebCrypto 通道 abc→ba7816bf… | ✓ |
| **GSM 7-bit** | "hello" → packed `e8329bfd06`（手工按 7bit 装包核验；扩展表 ESC 码逐项与 GSM 03.38 一致） | ✓ |
| Morse/NATO/A1Z26/八进制/十进制 ASCII/Unicode 转义 | roundtrip + 6-12-1-7→FLAG | ✓ |
| AES/分组 | 原语全部委托 @noble/ciphers 与 WebCrypto（未重写）；ECB/CBC variant→PKCS7 开关、非精确长度 key 的候选枚举兜底设计合理 | ✓（边界见 §3） |
| OpenSSL EVP_BytesToKey | MD5 迭代派生 48 字节（key32+iv16），Salted__ 头解析（读码确认，未运行） | ✓ |
| **XOR 自动破译** | 9 字节密钥 150 字节英文恢复 + knownHint（hint>key 周期验证）+ 单字节 | ✓ |
| **Vigenère 自动破译** | 14/20 字母 key 完整恢复（conf 0.99）；因子族 alternate 候选设计 | ✓ |
| **替换爬山** | 260 字母随机字母表恢复率 99%（cribs 锚点） | ✓ |
| LCG 恢复 | 8 输出恢复 a/c/m/next（1664525/1013904223/2^32） | ✓ |
| Berlekamp-Massey | x^4+x^4? 实为 x^4+x+1 序列 → 复杂度 4、连接多项式 [1,0,0,1,1]（s[n]=s[n-3]+s[n-4] 方向正确） | ✓ |

---

## 二、问题清单

### P1-1：RSA Raw 解密在 n 无法本地分解时，用 φ=n−1 静默算出错误私钥并输出乱码"明文"

- **位置**：
  - 根因 `src/utils/codec/math.ts:199-223`（`factorSmallCompositeModulus`）：`factorSmallRsaModulus` 返回 null 有两种含义——"是素数"与"所有分解手段（试除/Fermat≤128bit/rho 8×20000 迭代）都失败"，该函数一律把当前值**当素数**压入因子表。n 超过 maxBits(190) 时更是**必然**返回 `[n]`。
  - 放大点 `src/utils/codec/rsa.ts:1665-1674`（`rsaRawTransform`）：`factorList=[n]` → `rsaPhiFromPrimeFactors([n])` = `(n−1)` → `derivedD = e⁻¹ mod (n−1)`（通常存在）→ `exponent = d` 非空 → 直接 `c^d mod n` 输出，且 JSON 里 `derivedPrivateExponent: true`，**无任何警告**。
- **复现**（临时脚本实测 5 组，190bit/256bit/87bit 均触发）：
  ```
  n = <190bit 平衡半素数>   # 两个 95bit 素数，rho 打不动
  e = 65537
  c = <m^e mod n, m=flag{test}01>
  ```
  实际输出：`output.hex = 09b9a4651d40558d689a63f6510ace3d…`（乱码）；与 `c^(e⁻¹ mod (n−1))` 逐位一致（证明 φ=n−1 路径）。期望：报错"n 无法本地分解，请用 RsaCtfTool/factordb"或至少标注 φ 不可信。
- **加重因素**：`rsa.ts:1691` 的低指数精确根与 gcd(e,φ) 约简路径条件是 `typeof exponent !== 'bigint'`——伪 derivedD 非空使这些**正确**路径被跳过。实测 e=3 的 miniRSA 题（3∤(n−1) 时）会得到乱码而非本可恢复的明文（Q 组）。
- **对拍基准**：RsaCtfTool / sympy `factorint` 从不输出未验证分解下的解密结果。
- **修复建议**：① `factorSmallCompositeModulus` 内对 `factorSmallRsaModulus` null 的分支先做 `isProbablePrime(current)`，素数才入表，否则整体返回 null；② `rsaRawTransform` 在 `phi` 来自本地分解时先验证 `factorList` 中每个因子确为素数，否则不派生 derivedD，改走低指数/报错路径。③ 补回归测试：190bit 不可分解 n + e/c → 必须 throw。
- **工作量**：小（约 20 行 + 测试）。

### P1-2：Bech32 解码把 witness version 字并入 5→8 位转换——segwit 地址不可解或静默错位

- **位置**：`src/utils/codec/bases.ts:300`（`decodeBech32`）：`convertBits(words, 5, 8, false)` 作用于**全部** data words（含首词 witness version）。
- **复现**（实测）：
  - `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`（BIP-173 P2WPKH，工具自己编码产物）→ **THROW** `Bech32 padding 非零或不完整`；
  - `tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpdxf63q`（P2WSH）→ 同样 THROW；
  - `bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0`（Taproot）→ 不抛错，但 `dataHex` 为 33 字节错位数据且**静默丢弃 1 个填充位**（期望 32 字节 x-only key）。
- **期望**（BIP-173 参考实现 `segwit_addr.decode`）：`witver = words[0]`，`program = convertBits(words[1:], 5, 8, strict)`。
- **修复建议**：识别 segwit 场景（hrp ∈ {bc, tb, bcrt, tbs} 且 words[0] ≤ 16）时剥离首词，输出 `witnessVersion` + `programHex`；非地址场景维持现行为。工具自身 `encodeBech32`（无 version word）roundtrip 不受影响。
- **工作量**：小（约 15 行）。

### P2-1：yEnc / UUencode / XXencode 解码以 UTF-8 解码输出——二进制载荷静默损坏

- **位置**：`textEncodings.ts:626`（yEncDecode）、`bases.ts:556`（decodeUuencode）、`bases.ts:610`（decodeXxencode）结尾均为 `utf8Decoder.decode(bytes)`。
- **复现**（实测）：256 字节全值 yEnc 编码再解码，所有 ≥0x80 的字节（除恰为合法 UTF-8 续段的）全部变 U+FFFD→0xFD；UUencode 45 字节二进制 roundtrip **26/45 字节错**。
- **影响**：yEnc/uudecode 的核心用途就是 8-bit 干净传输（usenet 附件、CTF 里的二进制题）；用户拿到的"解码结果"已被替换字符污染且无提示。
- **期望**：CyberChef FromYEnc/Uudecode 保留字节流（hex/latin1 呈现）。
- **修复建议**：输出侧按 latin1 呈现或附带 `outputHex`；至少检测到 U+FFFD 时提示"载荷非 UTF-8，已损失，请用 hex 输出"。
- **工作量**：小-中（三个出口 + UI 展示配合）。

### P2-2：RSA Raw 行内 `c = [a, b]` 列表只解第一块（静默部分解密）

- **位置**：推理层（`rsa.ts` `parseKeyValueNumbers`/`parseLooseCtfFields` 路径）把数组值坍缩为首个元素；而 `parseRsaMessageValues`（textUtils）本身完全支持列表（直接调用实测返回 2 块）。
- **复现**（实测）：`n=…\ne=…\nd=…\nc = [<c1>, <c2>]` → 输出仅 m1 的单块结果，无任何"还有未处理块"提示；`c = <c1>, <c2>` 同样。
- **修复建议**：`params.c` 值含逗号/括号列表时透传原串给 `parseRsaMessageValues`（其已能处理）；或在输出 JSON 中标注 `unparsedBlocks`。
- **工作量**：小。

### P2-3：自动破译的硬上限无用户可见提示（Vigenère keyLen≤20、XOR keyLen≤32 且 ≤len/2、XOR 短密文）

- **位置**：`autoSolve.ts:582`（`Math.min(20, …)`）、`autoSolve.ts:393`（`Math.min(options.maxKeyLen ?? 32, Math.floor(bytes.length / 2))`）。
- **复现**（实测）：22 字母 Vigenère key 长英文 → 恢复出错误 key（conf 0.16），无"超出上限"提示；12 字节密文 + 8 字节 XOR key → 静默错解（conf 0.28，keyLen=3）。
- **期望**：xortool 默认搜索更长；结果对象应携带 `keyLenCapped: true` 之类的告警字段（confidence 已压低但不解释原因）。
- **修复建议**：结果中加告警；文档标注 <80 字节密文 XOR 与 >20 字母 key 不可靠。
- **工作量**：小。

### P2-4：CRC16 实为 CRC-16/MODBUS，UI 只标 "CRC16"

- **位置**：`alphabets.ts:127-131`（poly 0xA001 反射、init 0xFFFF、无 xorout = MODBUS 参数组）+ `crypto.ts:174`；UI 标签 `src/components/codec/OperationParamsPanel.tsx:201` `<option value="crc16">CRC16</option>` 无变体说明。
- **实测**："123456789" → `4b37`（CRC-16/MODBUS 标准检查值）。期望 CCITT/XMODEM 的用户会拿到意外值且无从发现。
- **修复建议**：标签改为 `CRC-16/MODBUS`，或提供变体下拉（CCITT-FALSE `31 63`? 实为 0x29B1 对 XMODEM "123456789"=0x31C3/CCITT-FALSE=0x29B1）。工作量：极小。

### P3 概览（低危/边界，建议排期或文档化）

1. `hexToBytes`（bases.ts:7-12）全角/宽字符**静默丢弃**：`"ｆｆ41"` → `[0x41]`，空清洗结果不报错返回空数组。建议：非 ASCII 字符出现时报错或 NFKC 归一。
2. QP 解码（textEncodings.ts:713-728）：`>0xFF` 字符 charCodeAt 后静默 mod 256（实测 `中` → 0x2D）；行尾空格/tab 编码侧未按 RFC 2045 强制转义（实测 `"A "` → `"A "`，严格解码器可能丢尾空格）；不支持 RFC 2047 `_`→空格 变体。
3. Base58 空输入编码为 `"1"`（应为空串；`"1"` 解码回 1 字节 NUL，自反但不符 Bitcoin 惯例）。
4. Playfair：filler 固定 X，双 X（"XX"、尾字母 X）产生退化对 `XX`（实测 playfairPairs('XX') = ["XX","XX"]? 实为 ["XX"] 单对，加解密自洽但跨工具与 Z-filler 实现不互通）；奇数长度**密文**解密时悬空字符静默与 `square[0]` 组对。
5. Hill 负数密钥编码：`(a*x+b*y)%26` 可为负 → `alphabet[负]` = undefined，输出串含 "undefined"（实测 key `-1 0 0 1` 编码 'AB' → 'AB' 未触发但构造负积即触发）；建议编码侧也做 mod 26 归一。
6. 八进制解码（textEncodings.ts:237-247）：无分隔长数字串按 ≤3 位贪心切分；含 8/9 的 token 被静默丢弃。
7. URL 解码不支持 `%uXXXX`（IE 变体）——`decodeURIComponent` 直接抛 URIError（响亮失败，可接受，建议文案提示）。
8. Trithemius 解码移位用**全字符**位置索引（textEncodings.ts:841-850 注释已声明）；dcode 等多按"仅字母序"——跨工具结果不同，含空格密文时必错位。
9. `tryRsaLowExponentRoots`：e≤17、k≤2000 的上限未在输出中说明；e=65537+短填充不可解（应提示 hashpumpy 式思路不适用、建议二分 k 或外部工具）。
10. `factorSmallRsaModulus`（math.ts:90-197）实际可解范围 ≈ 最小因子 ≤2^40（rho 8×20k 迭代）或 ≤10^5（试除）或差值近（Fermat ≤128bit）；87bit 平衡半素数已失败（实测）。建议 rsaHelper 对未分解 n 明确提示 factordb/yafu（notes 已部分覆盖）。
11. Base32 解码不校验尾随位非零（RFC 4648 SHOULD）；`"MZ"` 静默丢 2 位。
12. `lcgHelper` 恰 4 个输出时 derivedModulus 是单一 `t2t0−t1²` 值（可能是 m 的倍数），next 会算错；≥5 输出无此问题（gcd 生效）。建议把最低要求提到 5 或标注。
13. `pollardPMinus1` 两个因子都 B-光滑时 gcd=n 返回 null（标准限制，无法区分）；建议 notes 说明换 B 或用 rho。
14. `bytesFromTextOrHex`（bases.ts:134-138）启发式：纯 hex 形态文本（如口令 "abcdef"）会被当 hex——aesRaw 解码路径已通过候选枚举自愈（crypto.ts:1382-1439 注释自知），但 base58check/bech32 编码入口仍可能吃错。
15. Bech32 无 90 字符长度上限校验（BIP-173 规定）；混大小写已有校验 ✓。
16. Wiener 双实现并存（numberTheory.wienerAttack 带 m^(ed)≡m 双点终验 vs rsa.ts tryRsaWienerAttack 仅 p·q=n 校验）：后者校验已足够，但两份代码漂移风险，建议合并复用。
17. `rsaNumberResult`/`bigintToBytes` 对 0 值输出 `[0]` 单字节（bigintToBytes(0n)=[0]），hex 为 "00"——长整数转字节惯例应最小表示，flag 解码场景偶发前导 00 干扰（`rsaValuesResult` 拼接 hex 时可见）。待验证实际影响。

---

## 三、能力边界文档化建议（应"提示而非静默错"的输入形态）

1. **RSA**：仅 n/e/c 且 n 超出本地分解能力（>190bit 或平衡半素数 >~87bit）→ 必须提示"需外部分解（factordb/RsaCtfTool/yafu）"，禁止输出基于未验证 φ 的解密结果（对应 P1-1）。e=3/5/17 时优先尝试 miniRSA 根并**先于**私钥推导判断。
2. **Bech32**：输入是 bc/tb/tb 前缀地址时按 segwit 语义解码（version+program），否则按通用 payload；两者都不行时报错文案应区分"checksum 错"与"padding 非零"。
3. **yEnc/uu/xx**：解码结果含 U+FFFD 或 NUL 时提示"二进制载荷，文本视图有损，请切换 hex 输出"。
4. **自动破译**：密文 <80 字节（XOR）或字母数 <120（Vigenère）或 keyLen 触顶时，在结果 JSON 中输出 `limitations` 字段。
5. **CRC16**：标注 MODBUS 变体；如有需求补 CCITT/XMODEM/ARC。
6. **Hex 输入**：检测到被丢弃的非 ASCII 字符（全角、间隔符）时计数并提示。
7. **QP**：输入含 >0xFF 原始字符时提示 latin1 语义；或干脆要求 QP 输入为 ASCII。
8. **Trithemius/Playfair**：说明所用约定（全字符索引 / X 填充），与 dcode 默认的差异写在工具描述里。
9. **AES 原始密钥**：key/IV 长度不精确时的零填/截断已标注 `keyFormat`（现状可），建议在 UI 侧把 `zero-padded/truncated` 渲染为醒目告警而非普通字段。
10. **Pollard p-1 / rho**：在 rsaHelper notes 中给出实际可解规模（p−1 的最大素因子 ≲B；rho 因子 ≲2^40），避免用户误以为 1024bit n "跑一下就能出"。

---

## 四、方法与清理记录

- 临时脚本（均在系统临时目录，仓库外，已删除）：`payloader-audit-nt.mjs`、`payloader-audit-rsa.mjs`、`payloader-audit-rsa2.mjs`、`payloader-audit-classical.mjs`、`payloader-audit-final.mjs`、`dbg-bech32.mjs`、`dbg-bech32b.mjs`、`dbg-enigma-yenc.mjs`、`dbg-last.mjs`、`patch.mjs`。
- 审计期间仓库工作树零改动（本报告文件除外）。
- "待验证"项：P3-17（bigintToBytes(0) 前导 00 的实际展示影响）；AES OpenSSL EVP 路径为读码确认未运行（依赖 WebCrypto 环境）；Rabin raw 为组件级验证（tonelliShanks+crtCombinePair 全过，未端到端跑 rabinRawTransform）。
