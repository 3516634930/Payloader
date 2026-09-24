# GitHub CTF 算法级 sweep 第二轮（2026-09-24）

> 续接 `github-algo-sweep-2026-09-24.md`（第一轮 Top 15，编号续接从 16 起）与 `ctf-tools-landscape-2026-09.md`（全景）。
> 本轮定位：**第一轮未覆盖的十个方向**（ECC 攻击、轻量格/线性代数、隐写扩面、USB/音频取证、编码补面、hashcat 模式静态知识、RSA 补面确认、序列密码确认、Pwn 纯文本件、2024-2026 新星）。
> 全部结论基于本轮实际访问 GitHub 页面/Web 搜索确认；星数与许可证为访问当日数值。

## 〇、先决澄清：第一轮项的完成度复查（本轮代码 grep 确认，不再列入缺口）

| 项 | 现状证据 |
|----|----------|
| Franklin-Reiter | ✅ 已本地实现：`src/utils/codec/rsa.ts:1945` `polyGcdCompositeModulus` + `:2058` `rsa-franklin-reiter` 结果对象（含 m₁ᵉ≡c₁ 回验） |
| common modulus | ✅ 已本地实现：`src/utils/codec/rsa.ts:2214` `tryRsaCommonModulusAttack` |
| 低指数开方（e=3 小明文/三块拼接） | ✅ `rsa.ts:1692` `tryRsaLowExponentRoots`（分块开方，覆盖拼接题） |
| Rabin | ✅ `rsa.ts:1433` `rabinRawTransform`（含模素数平方根） |
| MT19937 | ✅ `src/utils/codec/prng.ts:168/177` `mt19937Untemper`/`mt19937PredictFromOutputs`（624 输出克隆） |
| RC4 / ChaCha20 | ✅ `crypto.ts:1601` `rc4Transform`；ChaCha20/Salsa20 家族走 noble（识别+加密均在） |
| cyclic 自定义字母表 | ✅ `src/utils/ctf/cyclic.ts:22` `buildDeBruijn(period, maxLen, alphabet)` 已参数化 —— 第一轮 #15 可勾销 |
| Brainfuck/Ook/JSFuck/AAencode/JJencode/Whitespace/Deadfish/Spoon | ✅ `src/utils/codec/audience.ts:417/496` 全在 |
| Bacon/Polybius/Nihilist/ADFGVX/Tap code | ✅ `src/utils/codec/classical.ts:158-508` |
| hash 识别（部分） | ✅ `crypto.ts:208` `identifyHash`（本轮 #25 只做"接 hashcat -m 编号"补强） |
| fmtstr 泄漏 offset 分析 | ✅ `src/utils/ctf/pwnTools.ts:110` `analyzeFormatStringLeak`（%p 输出反查 offset）—— 本轮 #21 补的是 **payload 构造器**，另一面 |
| DSA/ECDSA nonce 重用恢复 | ✅ `prng.ts:874` `trySmartSignatureNonceReuse`（重复 R → 恢复 k 与私钥） |
| 有限域 DLP（BSGS + 平滑阶 Pohlig-Hellman） | ✅ `prng.ts:1032` `trySmartDiscreteLog` —— **注意：仅有限域乘法群版，ECC 点群版没有**（本轮 #16） |
| Escape/Unescape | ✅ `unicode-escape` 等已在编码清单（audience.ts:496） |

第一轮长期项（Coppersmith/LLL、bkcrack、capstone ROP）维持原结论不动。

## 一、可移植算法源清单（本轮新确认）

### 1. jvdsn/crypto-attacks（★1.3k，MIT，活跃）
- `attacks/ecc/smart_attack.py`：Smart's attack（anomalous 曲线 trace=1）。Sage 实现用 `Qq`（p-adic）做提升，但 **n==1（素域）情形与通行 writeup 的 `EllipticCurve(Zmod(p**2), [a,b])` 纯提升版数学等价**——直译为 JS 时在 Z/p² 上手写 Weierstrass 点运算即可（点加/倍/标量乘公式与素域同形，只是模数换 p²）。论文锚点：Smart 1999 "The DLP on Elliptic Curves of Trace One"；失败分支（canonical lift 奇异，需提 p⁴ 或线性换元）见 TSG CTF 2024 "Easy? ECDLP" writeup。
- `attacks/ecc/singular_curve.py`：判别式=0 奇异曲线。cusp（三重根）→ 群同构加法群，`l = v/u` 纯除法；node（二重+单重根）→ 同构乘法群，需 GF(p) 开方（Tonelli-Shanks）+ GF(p) DLP（我们的 BSGS 直接复用）。三次多项式 GF(p) 求根用 `gcd(f, x^p−x)` 幂算法（BigInt 模多项式运算，百行内）。
- `attacks/ecc/mov_attack.py` / `frey_ruck_attack.py`：Weil/Tate pairing → 依赖 Miller loop + 扩域 DLP，列长期。
- `attacks/ecc/ecdsa_nonce_reuse.py`、`parameter_recovery.py`：已有等价能力（见上表）。
- 其他相关目录：`attacks/hnp/`（extended_hnp.py、lattice_attack.py——需 LLL，列长期）、`attacks/shamir_secret_sharing/`、`attacks/lcg/`、`attacks/mersenne_twister/`。
- ⚠️ 仓库无独立测试向量目录（页面上未见 tests/），**验证途径靠公开真题参数**（见缺口 #16）。

### 2. ecpy（cslashm/ecpy，★41，Apache-2.0，纯 Python）
- 自述 pure python ECC 库：Weierstrass 点运算（加/倍/标量乘）、曲线注册表、ECDSA/EdDSA 签名。
- 用途：#16 的**点运算底座参考实现**（Apache-2.0 可直译）。页面上无 Smart's attack 实现（早期搜索摘要提到的 ecpy Smart's attack 系 writeup 作者自行添加，不是库本体——已核实）。

### 3. guofei9987/blind_watermark（★14.8k，MIT）
- DWT-DCT-SVD 盲水印（国内赛高频）。`blind_watermark/` 包内含 embed/extract 模块（页面未列细名，移植时以仓库内 `blind_watermark/` 源码为准）；`examples/` 有 lena 全套攻击样例（裁剪/噪声/亮度）→ **现成对拍向量**。
- 依赖 numpy/opencv，但核心变换都是小矩阵运算：Haar DWT（纯 JS 简单）+ 8×8 分块 DCT（纯 JS 标准）+ SVD（小矩阵 Jacobi，主要工作量）+ Arnold 置乱（mod n 坐标变换）。

### 4. 音频三件套
- **ribt/dtmf-decoder**（★328，无 LICENSE 文件）：`dtmf.py` 单文件，FFT 分帧 + DTMF 行列双频匹配。DTMF 频率表是 ITU 公开标准——**思路借鉴自写**（用 Goertzel 更省）。repo 自带两个示例 wav → 测试向量。
- **colaclanth/sstv**（★283，GPL-3.0）：Martin 1/2、Scottie 1/2/DX、Robot 36/72，`sstv/` 目录纯 Python。GPL-3.0 **不可直译**；SSTV 时序（VIS 头 1200/1300Hz + 逐线 1500→2300Hz 扫频）是公开 amateur radio 标准，自写。
- **smolgroot/sstv-decoder**：浏览器 JS 实时 SSTV 解码（麦克风输入）——**浏览器形态可行性直接佐证**（许可证未核，仅作存在性证据）。
- 频谱图/摩尔斯/WAV LSB：WebAudio AnalyserNode FFT + PCM 解析，无移植源需求（自写）。

### 5. altf4/untwister（★390，GPL-3.0，C++）
- 支持 glibc rand()、MT19937、php_mt_rand、Ruby rand、java.util.Random 的 seed 爆破（多线程枚举 seed 对拍，支持 Unix 时间戳窗口）。
- GPL-3.0 **不可直译**；但五种 PRNG 的状态转移都是公开标准（glibc TYPE_3 加法反馈 r[i]=r[i−3]+r[i−31] 截 32 位；Java 48-bit LCG `seed = (0x5DEECE66D·seed+0xB) & (2⁴⁸−1)`，输出 `seed>>>16/32`）——教科书算法自写。**Java Random 两个连续输出解线性方程可免爆破直接恢复 seed**（纯 BigInt 位运算）。

### 6. pwntools pwnlib/fmtstr（Gallopsled/pwntools，★12k+，MIT）
- `pwnlib/fmtstr.py`：`fmtstr_payload(offset, writes, numbwritten, arch)`——%c 填充 + %hn/%hhn 写链 + 小端地址排序，纯字符串/整数计算，无 I/O，直译无障碍。验证：官方文档示例（docs.pwntools.com pwnlib.fmtstr 页）有确定输出。

### 7. 数据/知识表类
- **中文电码**：GitHub 无成品 JSON 码表仓库（已搜）；机器可读源 = Wiktionary "Appendix:Chinese telegraph code/Mainland 1983"（全表）+ 台湾表变体；在线对拍源 ChaseDream（基于《标准电码本（修订本）》）。
- **hashcat 模式表**：`hashcat --example-hashes` 官方输出 / hashcat.net wiki example_hashes（本轮访问 502，数据本身是模式编号事实数据，MIT 仓库 `tools/example_hashes.sh` 亦可）。链条模式（如 `-m 2600 = md5(md5($pass))`、`-m 3500 = md5(md5(md5($pass)))`）做成离线静态查询表。
- **HID Usage Table**：USB.org 公开标准（键盘 keycode→ASCII + 修饰键字节）。HackTricks "USB Keystrokes" 章有经典 tshark 管线（`usb.capdata && usb.data_len == 8` → 第 3 字节 keycode → 查表，含 Shift）。自动化参考 bolisettynihith/USB-Keyboard-Parser（许可证未核实——按思路自写，HID 表本身是公开标准，无版权问题）。
- **GIF 帧延时**：GIF89a 规范（GCE 块 0xF9 的 delay 字段）。原理参考 dtm.uk "GIF Steganography from First Principles"（2023）；真题场景 SAS CTF 2025 Quals "Lirili Larila"。

### 8. PDF 分析
- jesparza/peepdf（许可证未在页面确认——思路借鉴）+ Didier Stevens PDFiD：关键词计数（/JS /JavaScript /OpenAction /AA /EmbeddedFile，含十六进制名混淆计数）+ 对象流 FlateDecode 解码（我们已有 DecompressionStream）+ 版本对比。可移植部分：纯文本扫描与流解码，S/M 工作量。

### 9. stegseek（RickdeJager/stegseek，★1.3k，GPL-2.0）
- steghide 字典爆破（2 秒跑完 rockyou.txt）。GPL-2.0 + C++ steghide 内核 → 只进命令库条目（`stegseek file.jpg wordlist.txt`、`--seed` 无密码模式）。

## 二、新缺口清单（编号续接第一轮 Top 15，按实战频次排序）

### #16 ECC 攻击包：点运算底座 + Smart's attack + 奇异曲线 + 曲线上 Pohlig-Hellman（L）
- **价值**：ECC 题是 RSA 之后第二大 crypto 题库；anomalous（n=p）/ singular（c=a³+b²…=0）/ 小阶平滑曲线三件套覆盖国内赛 ECC 大多数"非交互"题。现有 `smartHelpers.ts:183` 已能**判定**判别式=0 并提示去 Sage——差最后一步求解。
- **纯 JS 可行性**：高。BigInt 仿射点运算（jacobian 不需要，p<2²⁵⁶ 仿射即可）+ Z/p² 提升（Smart）+ Tonelli-Shanks（node 情形）+ GF(p) 三次多项式求根（gcd(f,x^p−x) 幂算法）+ BSGS（复用 `prng.ts` 有限域版骨架，把群运算换成点运算）。
- **移植来源**：jvdsn `smart_attack.py`/`singular_curve.py`（MIT，数学等价改写为 Zmod(p²) 版）；点运算参考 ecpy（Apache-2.0）。
- **验证途径**：公开真题参数——CryptoCTF 2021 "Hard"（anomalous）、De1CTF 2020 ECDH（Smart）、CryptoCTF 2021 "TinyECC"（singular）、SharifCTF 2016 "British Elevator"（Smart 论文原版场景）；这些 writeup 均带完整 (p,a,b,G,P) 与答案。S/M 拆分：底座+Smart+S M 档，Pohlig-Hellman on curve +S。
- **边界**：曲线阶计算（Schoof/SEA）不可行——限定"n 已给出或 n=p 可判"场景（CTF 常态）；TSG CTF 2024 的 p⁴ 提升失败分支列边界不做。

### #17 USB pcap HID 流量恢复：键盘 + 鼠标（M）
- **价值**：USB 流量是 BUUCTF/攻防世界 misc 高频考点（键盘打字恢复 flag、鼠标轨迹画图），目前 `pcap/protocols.ts` 只剥 Ethernet/IP/TCP/UDP，`linkType` 已解析但 USB 链路（LINKTYPE_USB_LINUX=220/usbmon）完全未支持。
- **纯 JS 可行性**：高。usbmon pseudo-header（64 字节）解析 → capdata 提取 → 键盘：8 字节报文第 0 字节 Shift/Ctrl 修饰 + 第 2 字节起 keycode，查 HID 表还原 ASCII；鼠标：位移字节积分画 Canvas 轨迹。
- **移植来源**：HID Usage Table（公开标准）+ HackTricks 管线思路；映射表 ~120 项数据自建。
- **验证途径**：自造 pcap 回环（手写 usb.capdata 字节 + 已知 flag 文本）+ HackTricks 文档样例数据。
- **附带**：`--usbhid.capdata` 变体（URB 结构差异）与 pcapng 的 isb 接口段兼容（parser.ts 已支持 pcapng 接口枚举）。

### #18 音频隐写套件：频谱图 + WAV LSB + DTMF + 摩尔斯（+SSTV 列 L 档子项）（M）
- **价值**：全景报告已定论"频谱图永远第一步"；音频题三件套（频谱藏字、WAV LSB、摩尔斯/DTMF 编码）是 BUUCTF misc 常驻题型。现有 `fileDetect.ts:47` 已识别 WAV/FLAC 但无任何音频内容分析。
- **纯 JS 可行性**：高。WAV PCM 解析（RIFF 手写）→ WebAudio `AnalyserNode` FFT 频谱图（Canvas 热图）；LSB 按声道×位深枚举（复用 zsteg 扫描器思路）；DTMF 用 Goertzel 单频检测（比 FFT 分帧省算力，ribt 思路+ITU 频率表）；摩尔斯用能量阈值分段（通/断 → dash/dot + 帧同步）。
- **移植来源**：ribt/dtmf-decoder（无 license，思路自写）；SSTV 时序标准自写（colaclanth GPL 不可抄）；浏览器可行性有 smolgroot/sstv-decoder 佐证。
- **验证途径**：ribt repo 自带 example wav（DTMF）；摩尔斯/频谱自造回环（WebAudio 合成→解码）；SSTV 用 PySSTV 合成 Martin M1 标准音对拍（开发期）。
- **工作量拆分**：频谱+WAV LSB+摩尔斯 = M；DTMF = S；SSTV = L（列子项，可延后）。

### #19 GIF 帧分离 + 帧延时隐写提取（S）
- **价值**：GIF 分帧（逐帧 diff 找 flag 碎片）+ 帧延时藏 bit（delay 低位编码）是 misc 经典；`constFingerprints.ts:235` 已能提示"carve the GIF"但没有工具接住。
- **纯 JS 可行性**：极高。块扫描（0x21 GCE → 0x2C 图像描述符）提取每帧 delay（2 字节）与图像数据；帧数据转 Canvas/Blob 预览；delay 序列 → 按阈值二值化 → 每 8 位拼字节。纯标准解析，无外部依赖。
- **移植来源**：GIF89a 规范；dtm.uk 原理文章。
- **验证途径**：自造多帧 GIF（Node 脚本手工编码 GCE delay 序列）回环；SAS CTF 2025 "Lirili Larila" 题型对照。

### #20 盲水印提取 DWT-DCT-SVD（M/L）
- **价值**：国内赛高频（"两张图一张有水印一张没有"标准题面），全景报告已列 WASM 档——**本轮重新判定：纯 JS 可行**（Haar DWT + 8×8 DCT 是小矩阵运算；SVD 用 Jacobi 迭代，嵌入只改奇异值，精度 double 够）。
- **移植来源**：guofei9987/blind_watermark（MIT，★14.8k）。
- **验证途径**：repo `examples/` 的 lena 攻击样例图即现成测试向量（嵌入→裁剪/噪声→提取对拍，开发期本地跑 Python 版对拍 JS 版相关性）。
- **边界**：只做**提取**（解 CTF 场景），嵌入端可后补；需要 wm_shape 与两个密码参数的输入面板。

### #21 fmtstr_payload 格式化字符串写链构造器（S/M）
- **价值**：pwn 高频；现有 `analyzeFormatStringLeak` 只解决"offset 是多少"，没解决"payload 怎么写"。
- **纯 JS 可行性**：极高。`pwnlib/fmtstr.py`（MIT）纯计算直译：给定 (offset, {addr: value}, numbwritten, 字长) → 自动 %c 填充 + %hhn/%hn 排序（小端短写优化）+ 地址前置/后置两种布局。
- **验证途径**：pwntools 官方文档示例输入输出逐字节对拍。
- **附带**：32/64 位两种模式 + `%n`/`%hn`/`%hhn` 粒度选择。

### #22 PRNG 扩面：glibc rand / java.util.Random 状态恢复 + MT19937 seed 爆破窗口（S/M）
- **价值**：`mt19937PredictFromOutputs` 已覆盖"624 连续输出克隆"，但 CTF 常见另三形态没接：① glibc rand() 31 输出恢复状态；② Java Random 两输出解 seed（LCG 线性方程，免爆破）；③ 时间种子窗口爆破（srand(time(0)) ±N 小时枚举）。
- **纯 JS 可行性**：高。三种状态转移都是公开标准（untwister GPL 不可抄，算法教科书级）；Java 版两个 48-bit 输出解线性同余方程 BigInt 直解。
- **验证途径**：本地 C `rand()`/Java `Random`/Python `random.seed(t)` 生成序列对拍（开发期）；Web Worker 并行枚举时间窗。
- **附带**：php_mt_rand（untwister 同款状态机）顺手带上。

### #23 PDF 隐写分析：关键词计数 + 流解码 + 对象浏览（S/M）
- **价值**：PDF 藏 JS、藏白字、藏附件是 misc 中频题型；现有 fileDetect 只识别魔数。
- **纯 JS 可行性**：高。PDFiD 式关键词计数（含 hex 名混淆检测）+ /FlateDecode 流解压（DecompressionStream 已有）+ 顶层对象/xref 结构列表 + 嵌入文件提取。
- **移植来源**：PDFiD/peepdf 思路（许可证未确认，按功能自写——PDF 规范本身公开）。
- **验证途径**：自造 PDF（手写带 /OpenAction+FlateDecode JS 的最小文件）回环。

### #24 GF(p) 模线性方程组求解器 + 带关系 CRT + Shamir 分享恢复（S）
- **价值**：轻量线性代数是"非 LLL 格题"的地基：Shamir 秘密分享恢复（jvdsn 有专门目录，MIT）、LWE 小样本手解、HNP 无噪声版、带模关系的 CRT（模不互素，gcd 化归）。现有数论底座（numberTheory.ts）缺 gaussSolveModP。
- **纯 JS 可行性**：极高。模素数高斯消元（主元取逆元）教科书算法，~80 行；带关系 CRT 是 gcdext 组合。
- **移植来源**：教科书（sympy `solve_mod` 作对拍基准）；Shamir 恢复参考 jvdsn `attacks/shamir_secret_sharing/`。
- **验证途径**：sympy 对拍随机方程组；Shamir 用 (k,n) 门限自造回环。

### #25 hashcat 模式静态查询表（识别 → hashcat -m 编号与链条模式说明）（S）
- **价值**：`identifyHash` 已出候选，但"接下来用什么 hashcat 模式/john 格式"断了；链条模式（md5(md5($pass))=2600、sha1($pass.$salt)=110、bcrypt 等 ~200 条常用）是纯静态知识，离线查询无任何爆破（合规红线内）。
- **纯 JS 可行性**：极高，纯数据表 + 查询 UI。
- **移植来源**：hashcat example_hashes 官方输出（事实数据）。
- **验证途径**：与 `hashcat --example-hashes` 输出抽样比对（开发期）。

### #26 中文电码（四码电报）双向转换（S）
- **价值**：国内 misc 偶发（一串四位数字→汉字）；与已有的当铺/猪圈同族，是中文编码矩阵最后一块常用拼图。
- **纯 JS 可行性**：极高，~10000 项码表（大陆 1983 + 可选台湾表）查表。数据体积约 60-100KB（可 gzip 进 heavyData 模式，参照现有 ngramTableData 做法）。
- **移植来源**：Wiktionary 1983 附录（完整机器可读）。
- **验证途径**：ChaseDream/聚合数据在线查询抽样对拍（开发期）。

### #27 工具命令库补条目（stegseek / SilentEye / wbStego / DeepSound）（S）
- **价值**：指导页价值；`toolCommands.ts` 已有 steghide/mp3stego 条目，缺 stegseek（★1.3k，`stegseek file.jpg rockyou.txt`、`--seed` 模式）、SilentEye、wbStego、deepsound2john。
- **纯 JS 可行性**：纯静态数据条目。
- **验证途径**：命令语法对官方 README 逐一核对（stegseek 已本轮核实）。

## 三、不建议做清单

1. **steghide/stegseek 提取本体**：GPL-2.0（steghide 内核传染）+ C++ DCT 系数挑选/图论匹配自适应嵌入，纯 JS 复刻工程大且正确性难验（无数变体参数）。→ 命令库 + 指导页覆盖（#27）。
2. **MOV / Frey-Rück pairing 攻击**：需要 Miller loop + F_p^k 扩域算术 + 扩域 DLP 全链，工程量 L+，实战频次低于 Smart/singular（国内赛 pairing 题占比低，出现了通常也有 sage 预期）。jvdsn 实现深度绑定 Sage。→ 列长期（若 #16 完成后 ECC 题源仍不够再做）。
3. **invalid curve attack 交互本体**：攻击形态是与服务器 oracle 多轮交互（发畸形点→收响应），浏览器禁联网形态不匹配。→ 只在 #16 中做"本地计算器"边界（给定 twist 曲线 b' 与小阶点，本地解 ECDLP 供人工交互使用）。
4. **mp3stego 提取本体**：需完整 MP3 帧/Huffman 解码重算，工程大且题目密码通常直接给；命令库已够（且见下节语法修正）。
5. **DeepSound 提取本体**：私有容器 + AES，deepsound2john 场景归 john；频次低。
6. **Book cipher**：无固定码表（密本即题目文本），通用工具价值趋零——dcode.fr 也只是交互式文本粘贴。→ 不做独立工具（smart-decode 加一条识别提示即可）。
7. **SSTV 独立项**：保留在 #18 内做 L 档子项，不单列（避免半成品大项）。
8. **volatility 内存取证本体 / NTFS ADS**：符号表与文件系统驱动的工程远超收益，全景报告已归指导页，维持。
9. **jvdsn 的 hnp/lattice/lwe 目录直译**：全部依赖 LLL/BKZ，第一轮已把 LLL 列长期（WASM/自建 BigInt-LLL），维持不重复立项；#24 的无噪声 GF(p) 求解器是其轻量前置件。
10. **新星方向**：2024-2026 topic 扫描（ctf-tools/steganography/crypto solver 按更新排序）未发现新算法类工具——仍是 AI Agent 套壳与老工具集成，第一轮结论维持："零依赖本地跑"路线正确，无新增追赶项。

## 四、对既有能力的补强点

1. **mp3stego 命令语法修正（bug 级）**：`toolCommands.ts:4250` 现为 `mp3stego-decode -f output.txt audio.mp3`——不存在 `-f` 选项。官方语法（petitcolas.net 已核实）：`decode -X -P <pass> audio.mp3`（Windows `Decode.exe -X -P pass audio.mp3`，Docker 版 `mp3stego-decode -X -P pass in.mp3 out.pcm`）。CTF 实例：ISCC2016 `decode.exe -X ISCC2016.mp3 -P bfsiscc2016`。
2. **ECC 信号接求解**：`smartHelpers.ts:183` 判别式=0 检测、`:180` 小域提示已存在——#16 落地后把这两处"建议去 Sage"升级为"本地直接解"按钮，识别→求解一条龙（复制 RSA 攻击自动轮询的交互模式）。
3. **BSGS 复用**：`prng.ts` 有限域 BSGS 的 baby-step 表结构可直接换群运算复用给 ECC（#16），避免重写。
4. **identifyHash → hashcat 跳转**：`crypto.ts:255` 的空结果分支已给 `hashcat --identify` 命令提示——#25 落地后改为本地查表直接给 -m 编号。
5. **prng.ts 模块化扩展点**：`mt19937PredictFromOutputs` 是 #22 的挂载位，同文件加 glibc/java/php_mt 三个状态机 + seed 窗口枚举（Web Worker），smartDecode 自动识别正则同步扩展。
6. **fileDetect → 音频入口**：`fileDetect.ts:47-48` WAV/FLAC 识别已有——#18 的 UI 挂在 FileForensicsWorkspace 的卡片区（key 前缀规范见 AGENTS.md 踩坑记录）。
7. **pcap linkType 已解析**：`parser.ts:73/95/156` linkType 字段已有——#17 在 protocols.ts 加 LINKTYPE 220/147 分支 + usbmon 头解析，不动 parser 主体。
8. **zsteg 扫描器思路复用**（第一轮 #13 若已含）：#18 的 WAV LSB 枚举（声道×位平面×采样位宽）用同一"组合枚举+魔数判定"骨架。

## 五、执行建议（频次/成本比排序）

第一批（S 档，先行）：#19 GIF 帧延时 → #21 fmtstr → #25 hashcat 表 → #27 命令补条 → #24 GF(p)。
第二批（M 档，主线）：#17 USB pcap → #18 音频套件（SSTV 子项缓）→ #22 PRNG 扩面 → #23 PDF → #26 电码。
第三批（L 档，攻坚）：#16 ECC 攻击包 → #20 盲水印（SVD 是主要工程点）。

## 主要来源

[jvdsn/crypto-attacks](https://github.com/jvdsn/crypto-attacks)（★1.3k MIT）· [cslashm/ecpy](https://github.com/cslashm/ecpy)（Apache-2.0）· [guofei9987/blind_watermark](https://github.com/guofei9987/blind_watermark)（★14.8k MIT）· [RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)（★1.3k GPL-2.0）· [altf4/untwister](https://github.com/altf4/untwister)（★390 GPL-3.0）· [Gallopsled/pwntools fmtstr](https://github.com/Gallopsled/pwntools/blob/master/pwnlib/fmtstr.py)（MIT）· [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)（★328 无 license）· [colaclanth/sstv](https://github.com/colaclanth/sstv)（★283 GPL-3.0）· [smolgroot/sstv-decoder](https://github.com/smolgroot/sstv-decoder)（浏览器佐证）· [jesparza/peepdf](https://github.com/jesparza/peepdf) · [HackTricks USB Keystrokes](https://hacktricks.wiki) · [Wiktionary 中文电码 1983 附录](https://en.wiktionary.org/wiki/Appendix:Chinese_telegraph_code/Mainland_1983) · [MP3Stego 官方](https://www.petitcolas.net/steganography/mp3stego/) · [dtm.uk GIF Steganography](https://dtm.uk) · Smart 1999 / TSG CTF 2024 / CryptoCTF 2021 writeups（向量源）
