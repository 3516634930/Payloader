# CTF 全题型能力路线图（打比赛级工具箱）

> 依据：`docs/research/ctf-tools-landscape-2026-09.md` 全景调研。
> 总目标：CTF 解题工具箱覆盖**比赛现场"分析-解码-构造-计算"全链路**——离线可解 70%+ 的题型需求，动态/重型/攻击面以"指导页 + 本地工具桥"兜底。
> 三层可行性模型：L1 纯 JS（立即建设）/ L2 WASM（成熟即集成）/ L3 指导页（诚实标注+外链）。
>
> **硬约束：CTF 工具箱运行时零联网**（2026-09-22 用户拍板）。
> - 解题链路上的任何功能不得发起网络请求：无在线 API、无分解库查询、无 CDN 资源——WASM/字典/素数库等资产全部随应用本地打包。
> - 指导页允许放**手动外链**（用户自己点击跳转 factordb/Dedaub 等），工具本身不出网。
> - 平台管理侧功能（系统更新检查器、内容源订阅）与 CTF 工具链物理隔离，不受此约束，但不得为 CTF 功能提供代理通道。

## 基线：v2.0.1（进行中）

批次 A-M：智能解码评分、154 操作、受众分流三 tab、七域框架（题域导航+模块插件化）、杂项取证域 MVP（文件探测/LSB 基础）、流量分析域 MVP（pcap 解析）、中文密码组、Web/逆向/Pwn/AI 速查占位。

以下每阶段 = 一个版本（v2.0.2 起），阶段内批次给外部 AI 执行，完成一版验收一版。原平台功能路线（EXP 目录/源码库/发布池等）在 CTF 弧线完成后顺延重排。

## 阶段 1（v2.0.2）：密码攻击纵深 —— "RSA 题一键决策树"

**目标能力**：拿到公钥/密文，自动走攻击决策树（factordb→形素数→Fermat→Wiener→共模→低指数→……），覆盖 RsaCtfTool 的主流攻击面 + 格题小维求解。

- RSA 决策树向导：输入 n/e/c 自动逐攻击尝试并展示推理链（Wiener/共模/Håstad/Fermat/Pollard p-1/rho/多钥 gcd/部分泄露/低指数开方/ROCA 检测）
- 本地素数资产库：内置 RsaCtfTool pastctfprimes/noveltyprimes 风格的历史比赛素数表（离线 JSON），命中即分解
- JS-LLL 格工作台：≤60 维 BigInt LLL + Babai CVP，预置 HNP/背包/截断 nonce 模板（rkm0959 套路）
- ECC/DSA：k 重用恢复私钥、连分数 nonce 攻击（WebCrypto/noble-curves）
- PRNG 工作台：MT19937 untemper/预测、时间种子爆破、glibc/Java Random
- rsatool 基础设施：p,q→PEM（ASN.1 DER）、公钥解析全参数 dump
- FeatherDuster 式自动分析面板：批量密文分类（ECB/流/低熵/长度扩展标记）
- 哈希识别→hashcat 命令生成（L3 指导链）；长度扩展攻击计算器
- 大数分解边界：中小型 n 本地分解（SIQS ≤128bit，WASM）；超大半素数给手动 factordb 外链（用户自己开浏览器，工具不出网）
- 覆盖率验收：自建 60 道 RSA/格/PRNG 真题风格用例，决策树自动解出 ≥80%

## 阶段 2（v2.0.3）：杂项取证纵深 —— "AperiSolve 式一键全分析"

**目标能力**：拖入任意文件，一键跑全部分析器，结果聚合去重呈现。

- 一键全分析编排（AperiSolve 模式：内容哈希去重 + 分析器插件基类 + 并行跑 + 单页聚合报告）
- zsteg 式 LSB 全枚举（通道×位序×像素序×位宽 + DecompressionStream 试解压 + 魔数/字符串判定）
- Stegsolve 式可视化：位平面图/通道分离/Data Extract/GIF 分帧（Canvas）
- 音频工作台：频谱图（WebAudio FFT）、WAV LSB、DTMF（Goertzel）、音频摩斯、声道差分
- zip 攻击三件套：CRC32 短明文碰撞、伪加密修复、Biham-Kocher 明文攻击（纯 32 位运算）
- steghide/outguess/F5 提取（emscripten WASM 编译集成）
- PDF/文档分析：pdfid 关键词、流 inflate、docx/xlsx 解包查隐写
- 编码杂项大全补齐：当铺/猪圈系/tap code/键盘坐标/枪码/核心价值观/兽音等中文特色编码（±20 个操作）
- 覆盖率验收：自建 40 道杂项真题风格用例（藏 LSB/宽高/伪加密/音频频谱 flag），自动或两步内解出 ≥75%

## 阶段 3（v2.0.4）：Pwn/逆向静态工作台 —— "capstone-wasm 基石"

**目标能力**：ELF/字节码拖入即出静态分析结果，payload 计算器全家桶。

- checksec（ELF 头解析，L1）
- gadget 扫描器：字节搜 + capstone-wasm 反汇编（含未对齐）
- libc 识别器：地址尾 12 位 + 离线 libc-database 索引（内置常见 Ubuntu/Debian glibc）
- one_gadget 查表（按 BuildID 预构建数据离线内置）
- fmtstr 偏移计算器 + cyclic（De Bruijn）+ ROP 链组装器 + SigreturnFrame
- 汇编/反汇编工作台（keystone-wasm + capstone-wasm）、shellcode 库检索（shell-storm 镜像）
- pyc/PyInstaller 链：MEI 归档解包（纯 JS）+ pycdc-wasm 反编译 + pyc 反汇编
- EVM 反汇编器 + opcode 速查 + 以太坊 raw tx/ABI 解码（ethers.js/viem）
- WASM 反汇编（官方 wabt）
- z3-solver 约束求解工作台（注意 COOP/COEP 部署要求）
- 覆盖率验收：自建 30 道 pwn/逆向静态分析用例，checksec/libc 识别/fmtstr 全对，pyc 链解出 ≥80%

## 阶段 4（v2.0.5）：Web 构造器纵深 + 新题型工作台

**目标能力**：Web 题构造面全离线；AI/区块链/OSINT 三工作台落地。

- JWT 攻击构造器（jwt_tool 6 组 CVE + 篡改 + 签名 + 弱密钥爆破）
- SQL 注入 payload 生成器 + tamper 变换链（96 个 tamper 逻辑，链式组合+说明）
- SSTI 引擎识别速查 + payload 矩阵（探测语法树→引擎锁定→RCE payload）
- payload 库管理器（SecLists/PayloadsAllTheThings 结构化收录 + FUZZ 变换）
- curl↔请求构造器（curlconverter npm 复用，只构造不发送）
- AI 题 prompt 攻击工作台：payload 库 + 编码变换链 + 交互记录（对接指导：garak/PyRIT）
- OSINT 链接矩阵（Sherlock/WhatsMyName 站点模板内置）
- 区块链工作台收尾（EVM 已在阶段 3，补 Bitcoin 交易解析）
- 覆盖率验收：Web 构造场景 25 用例全过；三新兴工作台各有 ≥5 条可用工具

## 阶段 5（v2.0.6）：比赛模式收口

**目标能力**：从"工具集合"到"比赛操作系统"。

- 题目工作区：按比赛组织的多题并行状态（每题输入/分析结果/候选 flag 收藏夹）
- flag 候选全局聚合：所有分析器扫出的 flag 统一去重展示
- 解题链录制：把"粘贴→智能识别→两步解码→flag"的链路保存为可复用 recipe（CyberChef recipe 模式）
- 离线打包：全功能单文件离线客户端（比赛现场无网可用）
- 性能门禁：100MB pcap / 20MB 二进制 / 500+ 操作全库加载不卡死（Worker 化）
- 指导页体系统一：L3 工具全部有"为什么浏览器做不了 + 本地命令怎么敲（kali-run 桥） + 外链"三段式
- 终验：全题型用例库（150+ 用例）总通过率 ≥75%，未覆盖题型 100% 有指导页

## 风险与红线

1. **零联网红线**：CTF 工具链运行时零网络请求——代码评审 grep 外加运行时断言（dev 模式监控 fetch/XHR 调用，CTF 域激活时出现外呼即报错）；WASM/字典/素数库全部本地打包，禁止 CDN 引用。
2. **WASM 供应链**：capstone-wasm/keystone-wasm 维护弱（锁版本自测）；z3-solver 需 COOP/COEP 响应头（本地服务端可配，离线客户端需验证）
3. **体积预算**：WASM 全家桶（z3 ~5MB、capstone ~3.5MB、unicorn 19MB 不进）+ libc 索引 + payload 库——需要懒加载架构（按域分包，首屏不进 WASM）
4. **steghide/blind_watermark 编译**：emscripten 编译工作量最大的一块，若受阻降级为"检测特征 + 指导"

## 验收总纲

每阶段：四门禁全绿 + 浏览器实景 + 自建真题风格用例库通过率达标 + 零 eval/限量红线 + **零联网验证（网络面板审查 CTF 域全程零请求）** + 受众守恒不破坏 + 移动端可用 + L3 能力 100% 有指导页。
