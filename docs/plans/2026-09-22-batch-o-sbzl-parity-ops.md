# 计划：v2.0.1 批次 O——随波逐流操作大扩充（对应 sbzl-prompts 批次 M4，2026-09-22）

**Goal**：随波逐流字符/Base/Rot/带key/进制菜单中除在线与重型隐写外的操作全部进入本工具菜单栏且可用；智能识别对新增字表类密文自动认出大半。
**Architecture**：延续注册三件套（types.ts OperationId → operations.ts 元数据 → transform.ts 分发）+ audience.ts 双视图守恒 + ctfMenuSpec 顶部菜单表。五个新 parity 模块承载表数据与实现（参照 alphabets.ts/chineseCiphers.ts 的"码表+shape 谓词+编解码"模式），verify:codec 增加数据驱动向量回归块。
**Tech Stack**：纯 TypeScript，零新依赖，零联网，零 eval/new Function。RC2（RFC 2268）、RC6（Rivest et al. 1998）、M-209（主流参数档）手写实现。

## 基线（批次 N 落库后）

- 操作总数 167（ctf=80 / both=28 / pentest=59），verify:codec 127 块，test 211。
- 本批次新增 **75 个操作**（全部受众 'ctf'，类别与菜单见下表），完成后总数 **242（ctf=155 / both=28 / pentest=59）**。
- 权威向量要求：每 lane ≥40% 操作给 `cipher` 权威对拍（来源 URL 注释），全批 ≥30/75；全部操作有 round-trip 或单向 decode 向量。

## 五个 parity 模块与导出契约（lane 写集不相交）

| 模块 | lane | 导出前缀 |
|---|---|---|
| `src/utils/codec/parityBases.ts` | A（Base/Rot 11） | `parityBase{Operations,DefaultParams,Transform,LooksLike,Vectors}` |
| `src/utils/codec/parityCharCodes.ts` | B（字符类 18） | `parityChar{...}` |
| `src/utils/codec/parityChinese.ts`（超大表拆 `parityChineseTables.ts`） | C（中文类 23） | `parityCn{...}` |
| `src/utils/codec/parityKeyed.ts` | D（带key 10） | `parityKeyed{...}` |
| `src/utils/codec/parityNumeric.ts` | E（进制/工具 13） | `parityNum{...}` |

统一签名：

```ts
export const parityXxOperations: Operation[];
export const parityXxDefaultParams: Partial<Record<ParamKey, string>>;
export async function parityXxTransform(id: OperationId, direction: Direction, input: string, params: Record<ParamKey, string>): Promise<string>;
export const parityXxLooksLike: ParityShapeProbe[];   // 高特征形状探针（来自 ./parityTypes）
export const parityXxVectors: ParityVector[];
```

共享类型在 `src/utils/codec/parityTypes.ts`（已建）：`ParityShapeProbe{id,label,test}`、`ParityVector{id,plain,cipher?,direction?,params?}`。

## 新增操作清单（75）

受众全部 'ctf'；params 只用 `variant`/`secret`/`separator`/`shift`/`keyBits`（keyBits 为本批次新增 ParamKey，其余全部复用既有）。

### Lane A · parityBases.ts（category=binary，rot 两项 crypto）
| id | zh / en | params | 向量来源方向 |
|---|---|---|---|
| base92 | Base92 | — | base92 参考实现对拍 |
| base100 | Base100（Emoji）/ Base100 (Emoji) | — | AdamNiederer/base100 算法（U+1F400+byte）权威向量 |
| base85-rfc1924 | Base85(b) / Base85(b) RFC1924 | — | RFC 1924 字母表样例 |
| base62-ascii | Base62 ASCII 变体 / Base62 (ASCII order) | — | round-trip + 变体对拍 |
| base64-multiline | Base64 多行 / Base64 Multiline | — | 76 列折行 RFC 4648·2045 |
| base64-case-mangled | Base64 大小写错乱解码 / Base64 Case-Mangled Decoding | — | supportsDecode only；启发式打分恢复大小写 |
| base64-to-hex | Base64 转 Hex / Base64 to Hex | — | 与 node Buffer 对拍 |
| base-custom | Base 自定义表 / Base Custom Alphabet | secret | round-trip（自造表）+ 标准 32/64 表交叉对拍 |
| base-multi-decode | Base 混合多重解码 / Base16-32-64-91 Multi-Decoding | — | supportsDecode only；递归剥离多层 |
| rot18 | Rot18 | — | Rot13+Rot5 权威样例 |
| rot-special | Rot Special | — | 调研随波逐流/dcode 定义后对拍 |

### Lane B · parityCharCodes.ts（category=crypto，dvorak/keycode/bwt/quadoo 为 text）
| id | zh / en | params |
|---|---|---|
| pigpen | 猪圈密码 / Pigpen Cipher | —（Unicode 符号映射 + 对照表说明） |
| keyboard-keycode | 键盘 KeyCode / Keyboard KeyCode | — |
| handycode | 九宫格 Handycode / Keypad Handycode | — |
| chinesecode | 汉码 / Chinese Handy Code | — |
| backslash-code | 反斜杠密码 / Backslash Code | — |
| slash-pipe | 斜杠管道密码 / Slash and Pipe | — |
| tomtom | 汤姆码 / Tomtom Code | — |
| clock-code | 表盘码 / Clock Code | — |
| goldbug | 金甲虫密码 / Gold-Bug Cipher | — |
| kenny | 肯尼密码 / Kenny Speak | — |
| abaddon | 深渊天使 / Abaddon | — |
| dvorak | Dvorak 键盘 / Dvorak Layout | variant=qwerty↔dvorak 方向 |
| five-needle | 五针电报 / Five-Needle Telegraph | — |
| hodor | Hodor 语 / Hodor Speak | — |
| duckspeak | 鸭语 / Duckspeak | — |
| numberpad-lines | NumberPadLines | — |
| quadoo | Quadoo 点字键盘 / Quadoo | — |
| bwt | Burrows-Wheeler 变换 / Burrows-Wheeler Transform | —（$ 哨兵） |

### Lane C · parityChinese.ts（category=crypto；mars-text/emoji-encoder 为 text）
| id | zh / en | params |
|---|---|---|
| core-values | 社会主义核心价值观编码 / Core Socialist Values Encoding | — |
| hanzi-stroke | 汉字笔画码 / Hanzi Stroke Code | — |
| yinyang-qi | 阴阳怪气编码 / Passive-Aggressive Encoding | — |
| bagua-symbols | 八卦符 / Eight Trigram Symbols | — |
| telecode | 中文电码 / Chinese Telegraph Code | —（标准电码本，表拆 parityChineseTables.ts） |
| xiangyue | 想曰 / Xiangyue | —（Abracadabra 词典流派） |
| makabaka | 玛卡巴卡 / Makka Pakka | — |
| yinyin | 音音译者 / Yinyin Translator | — |
| shouyin | 兽音译者 / Beast-Speak Translator | — |
| periodic-table | 元素周期表编码 / Periodic Table Encoding | — |
| mars-text | 火星文 / Martian Text | —（映射层） |
| braille | 盲文 / Braille | —（U+2800-28FF 六点字） |
| music-notes | 音符密码 / Music Notes Code | — |
| flower-code | 花朵密码 / Flower Code | — |
| letter-code | 字母密码 / Letter Symbols Code | — |
| arrow-code | 箭头密码 / Arrow Code | — |
| hanzi-code | 汉字密码 / Hanzi Cipher | — |
| ipa-code | 国际音标密码 / IPA Code | — |
| whitespace-code | Whitespace 空白符编码 / Whitespace Encoding | —（tab/space/newline） |
| deadfish | Deadfish | —（i/d/s/o，256 回绕） |
| spoon | Spoon（BrainFuck 变体） / Spoon (BrainFuck Derivative) | —（解释器限定栈上限） |
| manchester | 曼彻斯特编码 / Manchester Encoding | variant=ge-thomas/ieee |
| emoji-encoder | Emoji 编码器 / Emoji Encoder | — |

### Lane D · parityKeyed.ts（category=crypto；全部接全局密钥栏 params.secret）
| id | zh / en | params |
|---|---|---|
| otp | 一次一密 / One-Time Pad | secret（XOR，hex 输出） |
| multiplicative | 乘法密码 / Multiplicative Cipher | secret（mod 26 可逆乘数） |
| fractionated-morse | 分组摩斯 / Fractionated Morse | secret（混合表关键词，可空=ABC…Z） |
| fenham | 费娜姆（Vernam）/ Fenham (Vernam) | secret（5-bit 异或） |
| running-key | 滚动密钥 / Running Key | secret（长文本密钥，不循环） |
| bazeries | Bazeries | secret（数字键+换位） |
| kamasutra | 迦玛索罗 / Kamasutra | secret（8 对 16 字母） |
| m209 | M-209 | secret（可选引钉/凸柱描述，缺省主流参数档） |
| rc2 | RC2 | secret + keyBits（默认 64，ECB，RFC 2268） |
| rc6 | RC6 | secret（RC6-32/20/b，ECB，密钥 ≤256 字节） |

### Lane E · parityNumeric.ts（category=binary）
| id | zh / en | params |
|---|---|---|
| ieee754 | IEEE754 浮点互转 / IEEE754 Float Conversion | variant=float32/float64 |
| twos-complement | 二进制补码 / Two's Complement | variant=8/16/32 |
| ones-complement | 二进制反码 / One's Complement | variant=8/16/32 |
| radix-xor | 进制异或 / Radix XOR | variant=2/8/10/16 + secret |
| bit-split | 位分割 / Bit Split | variant=2/3/4/7 |
| hamming | 海明码校验 / Hamming Code | —（(7,4) 编解码+纠错定位） |
| qwe-keyboard | QWE=ABC 键盘对应 / QWE=ABC Mapping | — |
| gcd | GCD 最大公约数 / GCD | — |
| prime-factor | 素数分解 / Prime Factorization | —（试除+Pollard rho，BigInt） |
| fibonacci-code | 斐波那契数列解密 / Fibonacci Decoding | —（Zeckendorf） |
| pickle-parse | Pickle 反序列化 / Pickle Deserialization | —（supportsDecode only，受限基础类型，禁 GLOBAL/REDUCE） |
| ascii-control | ASCII 控制字符 / ASCII Control Chars | — |
| quwei | 区位码 ↔ 汉字 / GB2312 Qu-Wei Code | —（TextDecoder gb2312 + 反查表懒加载） |

## 智能识别接入（中央集成阶段统一接线）

各 lane 的 `parityXxLooksLike` 形状探针在集成时接入 `smartDecode.ts detectInput`（芯片）；高特征且可自动解的（base100、braille、bagua、core-values、telecode、music-notes、arrow-code、kenny、hodor、manchester、whitespace、deadfish、shouyin/xiangyue/makabaka 前缀流、hexagram 族已存在）接入 `smartDecode` 主链（佛曰先例：命中前缀或形状→直接给出解码结果段）。探针必须与码表同源、带最低长度阈值防误报，样本实测命中写进各 lane 向量。

## 中央集成清单（lane 交付后主线执行）

1. `operations.ts`：`export const operations = [...既有, ...parityBaseOperations, ...parityCharOperations, ...parityCnOperations, ...parityKeyedOperations, ...parityNumOperations]`；`defaultParams` 加 spread 合并 + `keyBits: '64'`。
2. `transform.ts`：import 五个 dispatch，switch 加分组 case 委派。
3. `audience.ts`：`operationAudience` 加 75 条 `'ctf'`；`ctfSections` 各 subgroup 补 id；`ctfMenuSpec` 扩菜单（Base/Rot 扩 9、字符类并入古典/新增"字表字符"菜单、中文类并入中文字表、带key 新增"带key解密"菜单、进制工具并入进制转换）。
4. `smartDecode.ts`：detectInput 接 5 组 LooksLike + smartDecode 主链接高特征自动解。
5. `index.ts` barrel：re-export 五组 Vectors（供 verify 脚本）。
6. `scripts/verify-encoding-tools.mjs`：module.exports 注入行加 5 组 Vectors；新增"批次 O 数据驱动回归"块（遍历全部向量：有 cipher 先对拍再 round-trip，direction=decode 单向验证；断言向量总数与权威数 ≥ 门槛）；守恒数字改 `total===242 && ctf===155 && both===28 && pentest===59`；菜单数量断言同步。
7. 四门禁 → 修复循环 → reviewer → 浏览器实测（菜单可达、样本命中）→ `npm run check` 八门禁 → commit。

## 场景与衍生问题检查（穷举要点）

- **边界**：空输入一律返回空串（既有一致约定）；单字符/最长输入（工作台 4096 截断）；base-custom 表长度<16 或含重复字符→抛中文错误消息；m209 secret 非法描述→报错并列出缺省档；pickle 遇 GLOBAL/REDUCE/EXTEND→拒绝并提示"受限解析只支持基础类型"；rc6 密钥>255 字节→报错；hamming 输入非 0/1 或长度≠7→明确报错；quwei 区/位越界（>94）→报错。
- **异常与失败**：所有 transform 抛 Error（中文优先），工作台既有错误展示链路承接；不吞错、不返回半成品。
- **非功能**：纯计算零联网；大表（电码本约 8k 条）拆独立文件并惰性构建 Map；whitespace/spoon 解释器设步数与深度上限防卡死（参照 jsfuck 安全上限先例）。
- **衍生问题**：监控=门禁向量块即回归基线；幂等=纯函数天然幂等；存量=只增不改，既有 167 操作零行为变化（verify 块全部保留）；降级/失效=无外部依赖；防滥用=输入长度上限沿用工作台截断。

## 验收标准（AC）

- AC-1 四门禁全绿（typecheck / lint / test / verify:codec），最终 `npm run check` 八门禁全绿。
- AC-2 每个新操作 ≥1 条 round-trip（或单向 decode）向量，verify:codec 数据驱动块全过；权威向量（cipher 对拍）全批 ≥30 条、每 lane ≥40%，来源以 URL 注释可查。
- AC-3 受众守恒：total=242 / ctf=155 / both=28 / pentest=59 断言通过；菜单栏断言（全覆盖无重复）通过。
- AC-4 智能识别：高特征新增探针样本实测命中（写进 verify 向量块），`detectInput` 与 `smartDecode` 双层各至少覆盖核心 12 类。
- AC-5 浏览器实测：顶部菜单可找到全部 75 个新操作并点击执行成功；智能识别区对样本命中芯片；console 零报错。
- AC-6 独立复核：agent-code-reviewer 无 P0/P1 未处置。

## 已知风险

- 冷门字表（abaddon/tomtom/clock/numberpad/quadoo/花朵/字母/汉字密码等）公开权威实现稀缺：以 CyberChef/dcode/GitHub 可查实现为准对拍；查不到权威源的操作以 round-trip + 来源注释说明（"无公开权威向量，按 <来源> 定义实现"），AC-2 的全批 30 条门槛由此兜底。
- M-209 完整机实现复杂：按主流参数档（标准 6 轮引钉布局 + 可配置凸柱）交付，secret 可覆盖配置；不承诺历史全部机型变体。
- 电码本表数据体积：拆独立文件 + 惰性 Map，关注 bundle 体积（build 门禁兜底）。

---
## 执行台账（进度勾选）

- [x] 批次 N 落库 a91da87
- [x] 中央前置：types.ts +75 id / +keyBits；parityTypes.ts
- [x] Lane A parityBases.ts（11 操作 / 19 向量·权威 7 / 探针 2；base100 按 AdamNiederer 源码 U+1F3F7 基；rot-special=ROT13+ROT5+ROT47 最佳可得定义）
- [x] Lane B parityCharCodes.ts（18 操作 / 28 向量·权威 26 / 探针 13；chinesecode 为最佳可得定义）
- [x] Lane C parityChinese.ts+Tables（23 操作 / 28 向量·权威 12 / 探针 15；xiangyue/yinyin 等为最佳可得定义，已注明）
- [x] Lane D parityKeyed.ts（10 操作 / 18 向量·权威 9（rc2 RFC2268×5、rc6 IETF、m209 wiki）；rc2/rc6 带 variant pkcs7/raw，默认 pkcs7）
- [x] Lane E parityNumeric.ts（13 操作 / 30 向量·权威 24 / 探针 5；pickle 受限状态机 45+ opcode，GLOBAL/REDUCE 等 fail-closed）
- [x] 中央集成 1-6（operations/transform/audience/smartDecode/index/verify 全部接线完成）
- [x] 四门禁全绿（typecheck / lint / test 211 / verify:codec 129，含批次 O 数据驱动向量回归 + 智能识别正反例 + 数字串误直解回归钉）
- [x] reviewer 复核（agent-code-reviewer 独立对抗复核，结论 COMMENT）：
  - P1×2 已修：slash-pipe v 码与 j 重复（改真表 `||\\` + 含 v 向量防再犯）；数字形探针（telecode/quwei/numberpad-lines）退出直解路径（形状不特异，只出芯片+候选层打分），普通数字串保持原行为，verify 加负样本钉
  - P2 已修：RC6 密钥调度混合次数改 3*max(44,c)（密钥>176B 与标准互通）；rc2/rc6 raw 模式改严格整块（非对齐抛中文错，UI/summary 文案同步）；rc6 variant 下拉补进 CodecWorkbench；bwtEncode 补 "$" 哨兵输入校验；清理 lane DefaultParams 中被全局字面量覆盖的死配置键；base62-ascii 自造向量撤除 cipher 避免权威计数注水
  - P2 记账：verify bifid 模拟退火概率性块为既有 flake → docs/TECH_DEBT.md TD-批次O-1
- [x] 浏览器实测：10 菜单（含新增「字表字符」）全部可达；Base100 加密输出与权威向量一致；智能识别对 emoji/中文电码自动解出+芯片命中、核心价值观芯片命中；RC2 全局密钥栏往返成功；肯尼（字表字符域）解密成功；console 零错误
- [x] 八门禁 + commit（npm run check exit 0）
