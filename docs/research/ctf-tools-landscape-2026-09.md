# CTF 开源解题工具生态全景调研报告

> 调研日期：2026-09-22。四个并行研究线（密码编码 / 杂项取证 / Web+Pwn / 逆向+新兴题型），锚点 awesome-ctf、CyberChef、RsaCtfTool、AperiSolve、随波逐流 V8.0.1 等。
> 目标：为"Payloader CTF 工具箱能拿去打所有 CTF 比赛"提供能力地图与浏览器可行性判定。
> 结论先行：**高频考点约七成可纯 JS（含 BigInt）离线复刻；z3/capstone/keystone/pycdc 有成熟或已验证的 WASM 路径；动态调试、重型反编译、真发包攻击归指导页。**

## 〇、总判定：三层可行性模型

| 层 | 判定 | 覆盖 |
|----|------|------|
| L1 纯 JS | BigInt/位运算/字节解析/正则/Canvas，零外部依赖 | 编码/古典 100%、RSA 误用类 ~80%、PRNG 100%、哈希识别/长度扩展 100%、LSB/文件探测 ~80%、JWT/SSTI/payload 构造 ~90%、checksec/libc 识别 100%、EVM 反汇编 100% |
| L2 WASM | 算法成熟，有现成或已验证移植 | z3（npm z3-solver，官方参与，成熟）、capstone/keystone（capstone-wasm/keystone-wasm，半成熟）、pycdc（pyobfuscate.com 已证明可 wasm 化）、steghide/outguess/F5（emscripten 可编）、bkcrack（纯 32 位运算）、SIQS（≤128bit 分解）、小维 LLL |
| L3 指导页 | 需真实进程/GPU/重型环境 | Ghidra/IDA/angr、frida/qiling/gdb 系、volatility3、hashcat GPU 规模、GNFS、真发包攻击面（sqlmap/ffuf/Burp）、反连平台本体 |

技术基石清单（npm 可用）：`z3-solver`、`capstone-wasm`/`keystone-wasm`、`wabt`（WASM 反汇编，官方）、`hash-wasm`、`jsQR`、`exifr`、`file-type`/`magic-bytes`、curlconverter；原生 API：`DecompressionStream`（zlib/gzip/deflate）、WebCrypto（RSA/ECDSA/AES/HMAC 全套）、BigInt、WebAudio（FFT/频谱图）、Canvas（位平面/通道视图）。

## 一、密码与编码（Crypto/Encoding）

### 考点全景
- **编码套娃**：Base16-100 全家（含换表/偏移/大小写变体）、Hex/进制/Morse/Braille/DNA/A1Z26、URL 双重/HTML 实体/Unicode 规范化骗局、uuencode/xxencode、brainfuck/Ook/JSFuck、多层嵌套识别（Ciphey 用 A*+quadgram，15071 篇 writeup 建测试集）
- **古典**：凯撒/ROT 族/Atbash/仿射/栅栏/列置换/Bacon/Bifid/Trifid/Playfair/Hill/Vigenère 家族/Enigma（CyberChef 还有 Bombe/Typex/Lorenz/SIGABA 模拟）、单表替换自动破译（quipqiup 级 CSP/退火）
- **RSA（最大题库）**：分解类（Fermat/Pollard p-1、rho、Williams p+1/ECM/QS/SIQS/ROCA/多钥 gcd/Mersenne 等形素数）；指数类（Håstad/广播/Wiener/Boneh-Durfee）；结构类（共模/Franklin-Reiter/Coppersmith 已知前缀与 short-pad/部分泄露）；oracle 类（LSB/奇偶/Bleichenbacher BB98）；签名伪造（e=3 无哈希）
- **格密码（占比上升，2025 年 NTRU/LWE 题已进正式赛）**：LLL/BKZ、Babai CVP、HNP/截断 nonce、低密度背包、GGH/NTRU/LWE 小维（rkm0959 Inequality_Solving_with_CVP 为标准参考）
- **ECC/DLP/DSA**：Smart's attack、Pohlig-Hellman、MOV/SSSA、Invalid curve、k 重用恢复私钥、Breitner-Heninger 偏置 nonce 格攻击
- **哈希**：识别（hashid 220+）、长度扩展（MD4/5、SHA1/2 族）、生日/选择前缀碰撞、弱密钥 JWT
- **对称/流**：ECB 图像检测、CBC bit-flipping、padding oracle、GCM nonce 重用、TEA 族、RC4、ChaCha/Salsa、openssl enc EVP_BytesToKey 变体、SM4
- **PRNG**：MT19937 untemper（624 输出）、截断输出、glibc/PHP/Java Random、时间种子爆破
- **其他**：ZIP 已知明文（bkcrack）、meet-in-the-middle、Shamir 分享、z3 约束题

### 关键工具与复刻判定
| 工具 | 核心 | 判定 |
|------|------|------|
| RsaCtfTool（5k stars 持续更新） | 40+ RSA 攻击自动轮询 | **纯 JS+BigInt 移植大部分**（Wiener/共模/Fermat/p-1/rho/gcd/开方/部分泄露）；QS/SIQS ≤128bit 边缘可行；ECM/Boneh-Durfee 需 JS-LLL 或 WASM |
| CyberChef（30k stars，Apache-2.0，纯浏览器） | 505 操作 | **直接参照系+可复用源码**：RSA/ECDSA/SM2/X.509/PGP/EVP key/PRNG/Magic 全有 |
| Ciphey（18k stars） | A* 搜索 + 解码器优先级学习 + quadgram 明文判定 | 架构已复刻（我们的 smart-decode 同思路），补 A* 多层规划与敏感信息正则库 |
| FeatherDuster/Cryptanalib | 自动密文分类（ECB/流/低熵/长度扩展标记/OpenSSL 格式）+ Batch GCD/many-time pad | **纯 JS 全部可行**，做"自动分析面板"功能清单 |
| factordb | 分解缓存库 | 在线桥接（注意 CORS，可走本地服务端代理） |
| hashid / hash-identifier | 签名表识别 | 纯 JS 抄签名表；接 hashcat -m 指导跳转 |
| hash_extender | 长度扩展一键生成 | 纯 JS（核心是中间状态续算） |
| untwister / randcrack | PRNG 状态恢复 | 纯 JS（MT19937 就是移位+掩码） |
| rsatool | p,q→PEM | 纯 JS（BigInt + ASN.1 DER 编码百行）——必备基础设施 |
| bkcrack / pkcrack | ZIP Biham-Kocher 已知明文 | 纯 32 位整数运算，JS/WASM 均可 |
| jvdsn/crypto-attacks | Sage 攻击算法库 | 作为"攻击向导页"目录蓝本 |
| JS-LLL（自建） | ≤40-60 维 BigInt LLL + Babai | **覆盖 80% CTF 格题**（HNP/背包/小维 NTRU）；高维 BKZ 归指导 |
| quipqiup/dcode.fr | 替换密码自动破译 | 纯 JS（四元组 hill-climbing，我们已有） |

### 密码线结论
纯 JS 可直接建设：RSA 误用全家（除大分解）、ECC/DSA nonce 恢复（k 重用/连分数）、PRNG 全套、哈希识别+长度扩展、对称逻辑题（ECB/bit-flipping/GCM 重用）、EVP 变体、JS-LLL 小维格题。WASM：SIQS 小分解、ECM、bkcrack。指导：GNFS、hashcat GPU 规模（识别后给 hashcat -m 命令）、SageMath 级数学环境、真 oracle 交互（做本地模拟器）。

## 二、杂项 / 取证 / 隐写（Misc/Forensics/Stego）

### 考点全景（按子方向）
- **文件**：魔数+polyglot（ZIP 字节反转双向合法）、尾部追加（IEND/EOF 后）、嵌套压缩链、文件雕刻（foremost 配置化/photorec 440+ 签名/bulk_extractor 全字节特征）、熵图与字节分布（ImHex 式）、二进制 diff
- **图片**：PNG chunk 级（宽高 CRC 爆破、tEXt/iTXt/zTXt、PLTE 调色板）；LSB 全家族（通道×位序×像素序×位宽组合，zsteg 式枚举 + 生成器位置序列 + 素数取样）；位平面图/通道分离（Stegsolve 视图）；JPEG 五大隐写（steghide/outguess/jphide/F5/jsteg）；双图 XOR/差分；GIF 分帧；FFT 频域隐写；盲水印（DWT-DCT-SVD，国内高频）；专用工具特征识别（OurSecret 40 字节魔数、wbStego、OpenStego、Camouflage）
- **音频**：频谱图永远第一步（2-15kHz）；WAV LSB（含前置静音、1/2-bit）；DTMF（Goertzel，输出常为 # 分隔 ASCII 码）；自定义双音频率表；音频摩斯；SSTV（1500 同步+1200/1900 扫频）；DeepSound（WAV+AES，deepsound2john）；声道差分消音取残；FFT 音符识别拼字母；MIDI note 配对编码
- **压缩包**：伪加密修复；CRC32 碰撞秒超短明文（≤5-6 字节）；bkcrack 明文攻击（≥12 字节已知明文恢复内部密钥→全解/改密重打包/反推 8 位密码）；zip2john→字典爆破；RAR/7z 仅爆破
- **内存/系统**：volatility3（符号表驱动）→ 指导；注册表/Shellbags/USB 痕迹 → 指导
- **PDF/文档**：pdfid 关键词计数；peepdf 对象树+流解码；qpdf 结构重写（WASM）；docx/xlsx=ZIP 解包查 XML/白字/批注/宏（olevba）；NTFS ADS → 指导
- **编码杂项（中文特色）**：博多/当铺（笔画数→ASCII）/猪圈及 Freemason 变体/银河字母/tap code/键盘坐标/枪码/核心价值观/兽音/与佛论禅/零宽/行尾空白（snow）/AAencode/JSFuck/Ook

### 关键工具与复刻判定
| 工具 | 判定 |
|------|------|
| zsteg | 纯 JS（LSB 全枚举 + DecompressionStream 试解压 + 魔数/字符串判定）——**Misc 第一优先** |
| Stegsolve | 纯 JS Canvas（位平面/通道/Data Extract/GIF 分帧） |
| steghide | WASM 最高优先（JPEG DCT+图论匹配；提取路径 emscripten 可编）——必考场景 |
| outguess / F5 / openstego | WASM |
| jsteg / LSBSteg / stegano / stegpy | 纯 JS（配 JS JPEG 解码器） |
| snow | 纯 JS（ICE 有 JS 实现） |
| Cloakify | 纯 JS（词表映射，极易） |
| blind_watermark | WASM（国内高频，值得投） |
| binwalk v3 | 纯 JS 覆盖签名扫描/熵/gzip-zlib-tar 提取 |
| foremost/photorec（carving 部分）/bulk_extractor | 纯 JS |
| exiftool | 纯 JS（exifr 覆盖大半） |
| pngcheck/pcrt | 纯 JS |
| pdfid/peepdf（流解码部分） | 纯 JS（pako inflate） |
| multimon-ng（DTMF/Morse） | 纯 JS/WASM（Goertzel 简单） |
| 频谱图/SSTV | 纯 JS（WebAudio FFT；SSTV 算法明确：逐线测频） |
| zbar | 纯 JS（jsQR 现成） |
| ImHex | **官方已有 Web 版**（web.imhex.werwolv.net）——hex 检查器/熵热图/pattern language 可整体借鉴 |
| AperiSolve | 架构借鉴：内容哈希去重 + 并行分析器 + 单文件插件基类；配套方法论（频谱图先行→LSB 兜底→未知格式先跑"熵图+签名+strings"三件套） |
| volatility3 / testdisk / NTFS ADS / mp3stego | 指导页 |

## 三、Web + Pwn

### Web 考点
注入类（SQL 六技术/命令/SSTI/XSLT）、XSS/CSRF/CORS/CSP/原型链、文件上传/包含（php://filter/phar）、SSRF/XXE、反序列化（PHP POP/Python Pickle/pyYAML）、认证逻辑（JWT/Cookie/GraphQL）、框架审计、盲打基建（OOB/反弹 shell）。

### Web 工具判定
| 工具 | 判定 |
|------|------|
| jwt_tool | **纯计算，高度可浏览器化**：6 组 CVE 攻击（alg:none/公钥混淆/JWKS/Psychic Signature 等）+ 篡改 + 签名 + 字典爆破，WebCrypto 原生支持 |
| sqlmap（96 tamper 脚本） | tamper 本质纯字符串变换链 → **tamper 变换器 + payload 生成器**；自动注入归指导 |
| tplmap/SSTImap | **payload 矩阵静态化**：探测语法树（`{{7*'7'}}`→锁定 Jinja2）+ 按引擎分组 RCE payload |
| SecLists/fuzzdb/PayloadsAllTheThings | 结构化离线收录 + FUZZ/%EXT% 变换 + fuzz 规划器（执行交回 Burp/ffuf） |
| curlconverter | **npm 纯 JS 直接复用**（27+ 语言） |
| inql/graphw00f | GraphQL 内省构造/schema 解析可视化，纯前端可行 |
| nuclei | 模板解析/编辑可前端化，扫描执行在线 |
| Burp/ZAP/反连平台 | 请求构造器 + 生成指向用户自有反连平台的 payload 串 |

### Pwn 考点
栈（ret2libc/ROP/SROP/栈迁移/整数溢出）、格式化字符串（偏移确定/payload 构造）、堆（UAF/tcache/fastbin/house of 系列/IO_FILE）、seccomp 沙箱（ORW）、kernel。

### Pwn 工具判定
| 工具 | 判定 |
|------|------|
| checksec | **纯 JS 完全可行**（ELF 头解析：NX/PIE/Canary/RELRO/RPATH），文件拖入即出——入口级功能 |
| ROPgadget/ropper | **可浏览器化**：字节搜 `0xc3` + capstone-wasm 向前反汇编（含未对齐 gadget）+ 分类 |
| one_gadget | **查表模式可离线**：自带按 BuildID 预构建数据库（Ubuntu LTS 常见 glibc 全覆盖） |
| LibcSearcher/libc-database/libc.rip | **完全可浏览器化**：泄露地址低 12 位匹配 + 离线 libc 索引 |
| pwntools（asm/cyclic/fmtstr/rop/elf 模块） | 前 5 项纯计算可浏览器化；tubes（连接）不可行 |
| keystone/capstone/unicorn | **keystone-wasm/capstone-wasm npm 已存在**；unicorn.js（19MB 老）与 unicorn-wasm（PoC）仅轻量模拟；r2wasm 官方维护 |
| pwndbg/GEF/PEDA、angr、patchelf/glibc-all-in-one | 确认不可行，指导页 |
| shell-storm 库 | 可静态镜像为离线检索库 |

## 四、逆向 + 新兴题型

### 逆向考点（按流程）
识别（魔数/嵌入内容/熵）→ 脱壳（UPX NRV/LZMA、PyInstaller MEI 归档——国内高频、自定义 XOR 壳）→ 反汇编（x86/ARM/EVM/WASM 字节码/自研 VM opcode 框架）→ 反编译（native 重型归指导；pyc→pycdc-wasm 已验证；EVM→伪 Solidity 归 Dedaub 外链）→ 脚本还原（pyc/marshal 解析纯 JS、JS AST 反混淆浏览器天然、Java class/Lua 字节码）→ 约束求解（z3）→ 动态调试归指导。

### 逆向工具判定
| 工具 | 判定 |
|------|------|
| z3 | **npm z3-solver 成熟**（官方维护者参与，38k 周下载；需 SharedArrayBuffer+COOP/COEP）——第二层性价比最高单点 |
| capstone | capstone.js/capstone-wasm 存在（半成熟，锁版本自测；兜底手写 x86/ARM 子集） |
| radare2 | **r2wasm 官方维护**（radare.org/w 在线 demo 证明），体量需评估 |
| wabt | **官方 npm `wabt`，成熟**（wasm2wat/wasm-decompile——WASM 题必备） |
| pyinstxtractor + pycdc | **纯 JS 解包（zip+TOC+marshal 头修复）+ pycdc-wasm（pyobfuscate.com 已验证）**——国内 CTF 高频套路，零竞品覆盖，优先 |
| Detect It Easy / libmagic | 纯 JS 签名库内置 |
| UPX | 简化脱壳可行（JS LZMA + NRV 移植；重定位/import 重建难） |
| Ghidra/IDA/Binary Ninja/retdec/angr/frida/qiling | 指导页（Ghidra headless 可做服务端批量导出——远期可挂本地服务） |
| JADX | 项目已有 jadx-mcp 服务端，Android 线已解决 |
| EVM 反汇编/交易/ABI 解码 | 纯 JS（opcode 表 + ethers.js/viem）——区块链题核心，高频 |
| slither/mythril/heimdall | 指导页（Dedaub 网页外链） |

### 新兴题型
- **AI/ML**（2023-2026 主流形态）：prompt injection 多级提取（Gandalf 类）、越狱、间接注入/RAG 投毒、system prompt 提取、对抗样本。平台：HackAPrompt、Wiz AI CTF、OWASP LLM Top 10 CTF。工具 garak/PyRIT/Chatter 需调 LLM API → 浏览器做 **prompt 攻击工作台**（payload 库 + 编码变换链 + 交互式提交记录）+ 指导。
- **区块链**：EVM 字节码逆向是最大考点（ctf-blockchain 收录 200+ 题解）；整数溢出/重入/随机数可预测；比特币 forensics/交易解析/助记词（bip39 已有）。浏览器补：EVM 反汇编器 + raw tx/ABI 解码 + opcode 速查。
- **移动**：APK 静态解包（zip+AndroidManifest 二进制 XML）纯 JS；动态（frida/objection）指导；jadx 走既有服务端。
- **OSINT**：站点模板矩阵（Sherlock/WhatsMyName 3000+ 站点列表内置，外链批量生成）+ EXIF 解析 + dork 速查。

## 五、汇总：浏览器覆盖度矩阵（按题型）

| 题型 | 纯 JS 可覆盖 | WASM 增量 | 仅指导 | 离线覆盖率估计 |
|------|-------------|-----------|--------|----------------|
| 编码/古典 | 全部 | — | — | ~100% |
| 密码（现代） | RSA 误用全家/ECC nonce/PRNG/哈希/对称逻辑/小维格 | SIQS≤128bit、ECM、bkcrack | GNFS、hashcat GPU、Sage、真 oracle | ~75-80% |
| 杂项/取证 | LSB 全家/位平面/文件雕刻/熵/strings/PNG 修复/zip 攻击/PDF/二维码/编码杂项大全 | steghide/outguess/F5/盲水印 | volatility/文件系统修复/NTFS ADS | ~70% |
| 音频 | 频谱/LSB/DTMF/摩斯/音符/MIDI | SSTV、DeepSound、AudioStego | mp3stego | ~80% |
| Web | JWT 攻击构造/tamper 变换/SSTI 矩阵/payload 库/curl 转换/GraphQL 构造 | — | 真发包（sqlmap/ffuf/Burp 执行）、反连本体 | 构造面 ~90%，攻击面 0（形态使然） |
| Pwn | checksec/libc 识别/one_gadget 查表/fmtstr/cyclic/ROP 组装/shellcode 库 | capstone/keystone 反汇编汇编、轻量 unicorn 模拟 | 调试器/angr/真进程 | 静态+构造 ~65% |
| 逆向 | 文件识别/熵/PyInstaller+pyc 链/JS 反混淆/APK 结构/EVM/WASM 反汇编 | pycdc-wasm、r2wasm、UPX 简化、z3 | Ghidra/IDA 级反编译、动态调试 | 静态 ~60% |
| AI/区块链/OSINT | prompt 工作台/EVM+交易解码/OSINT 链接矩阵 | z3 | 自动化扫描器、审计器 | 按题型 ~60% |

**战略定位**：浏览器离线工作台覆盖"分析-解码-构造-计算"全链路（比赛现场 70%+ 的时间消耗），动态调试/重型反编译/自动攻击归"指导页 + 本地工具桥"。差异化价值在 CyberChef 没有的部分：题型→攻击决策树向导（RsaCtfTool/jvdsn 蓝本）、FeatherDuster 式自动分析面板、AperiSolve 式一键全分析器编排、libc/one_gadget 离线索引、z3-wasm 约束工作台、中文特色密码全家桶。

### 主要来源
[RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) · [CyberChef](https://github.com/gchq/CyberChef) · [Ciphey](https://github.com/bee-san/ciphey) · [FeatherDuster](https://github.com/nccgroup/featherduster) · [Inequality_Solving_with_CVP](https://github.com/rkm0959/Inequality_Solving_with_CVP) · [jvdsn/crypto-attacks](https://github.com/jvdsn/crypto-attacks) · [AperiSolve](https://github.com/Zeecka/AperiSolve) · [stego-toolkit](https://github.com/dominicbreuker/stego-toolkit) · [bkcrack](https://github.com/kimci86/bkcrack) · [ImHex](https://github.com/WerWolv/ImHex)（官方 Web 版 web.imhex.werwolv.net）· [binwalk v3](https://github.com/ReFirmLabs/binwalk) · [volatility3](https://github.com/volatilityfoundation/volatility3) · [jwt_tool](https://github.com/ticarpi/jwt_tool) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) · [SSTImap](https://github.com/vladanoff/SSTImap) · [curlconverter](https://github.com/curlconverter/curlconverter) · [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) · [one_gadget](https://github.com/david942j/one_gadget) · [libc-database](https://github.com/niklasb/libc-database) · [npm z3-solver](https://www.npmjs.com/package/z3-solver) · [capstone.js](https://github.com/AlexAltea/capstone.js) · [r2wasm](https://github.com/radareorg/r2wasm) · [wabt](https://github.com/WebAssembly/wabt) · [pycdc](https://github.com/zrax/pycdc)（wasm 化验证：pyobfuscate.com）· [pyinstxtractor-ng](https://github.com/extremecoders-re/pyinstxtractor-ng) · [ctf-blockchain](https://github.com/minaminao/ctf-blockchain) · [awesome-ctf](https://github.com/apsdehal/awesome-ctf) · [CTF-Wiki](https://ctf-wiki.org) · [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
