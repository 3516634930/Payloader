# 批次 SB：随波逐流能力对标补齐（已交付）

日期：2026-09-24（当日交付完毕）
来源：用户提供随波逐流（V8.0.1，长弓三皮）功能截图逐项对标 + `docs/research/ctf-tool-navigation-2026-09-24.md` 官网/说明书调研
范围：截图可见 31 项能力 → 已有 22 / 部分 3 / 缺失 6，本批全部补齐。

## 交付终态（对照下方施工单）

- 引擎 10 个新文件 + 测试 68 用例（rar-brute 15 / file-repair 20 / text-stego 23 / pyc-stego 10）全绿；全套 npm test 521/521
- codec 操作 249→252（snow-stego/cloakify/ttl-stego，audience=ctf），verify-encoding-tools 133 回归一致
- 通关执行器新增 8 条链（BMP 修复/GIF 修复/NTFS ADS/snow/Cloakify/TTL/pyc 常量/Stegosaurus/RAR 爆破）
- 真题通关：`tests/real-challenges/sb/` 9 项全 PASS（向量由 `scripts/gen-sb-challenges.mjs` 用产品引擎 encode 方向生成闭环）；全套基线对账 21 PASS 零丢失（+9 净增）
- 浏览器实测：snow/Cloakify/TTL 操作选择与运行、NTFS 卡 flag 命中、pyc 卡（Python 3.10 识别+flag 候选）、RAR 爆破区 0.5s 命中、BMP 修复还原 64×32，console 零错误
- 执行器 RAR 分支顺序修正：先探测真加密（带 salt）再决定伪加密清位——防真加密被清位毁掉（easycap 回归已修复对账）
- 协议事实更正（调研产物）：① RAR3 无 RAR5 式头内口令校验字段，快筛走 john 首块结构检查 + 解压 CRC 终验双段；② pyc 3.11+ exceptiontable 位于 marshal 字段末位（网上流传"紧跟 code"说法有误，真实 CPython 编译产物验证）；③ 真实 ZIP ADS = 冒号虚拟条目（unxed/zipper + ACTF 真题），0x000a extra field 官方只存时间戳

## 对标矩阵与施工决策

| # | 随波逐流功能 | 对标状态 | 批次 |
|---|---|---|---|
| 1-7 | 文件总入口/Hexdump/Binwalk/Foremost/DTMF/wav摩斯 | ✅ 已有（文件取证工作台/HexdumpCard/EmbeddedCard/AudioStegoCard） | — |
| 8 | mp3stego 读写提取 | ⚠️ 命令参考（C++ 外部工具，闭源协议不可纯前端实现） | 记账 |
| 9 | Cloakify 隐写提取 | ❌ 缺 | **SB-C** |
| 10 | snow 雪花隐写提取 | ❌ 缺 | **SB-C** |
| 11 | Stegosaurus pyc/pyo 隐写提取 | ❌ 缺 | **SB-D** |
| 12 | 修复文件头（png/bmp/gif/zip/rar/jpg） | ⚠️ PNG/ZIP/RAR 已有，BMP/GIF/JPG 缺 | **SB-B** |
| 13-15 | 进制流/Base64 文件/Base64 隐写 | ✅ 已有（codec/嵌入扫描/base64Stego） | — |
| 16-22 | zip 信息/伪加密/爆破/CRC32/嵌套/批量 | ✅ 已有（zipInspect/zipBrute/crc32-attack/CD 驱动解包） | — |
| 19 | rar 密码字典爆破 | ❌ 缺 | **SB-A** |
| 23-25 | pcap USB 键盘/鼠标/流量分析 | ✅ 已有（usbHid/TrafficWorkspace） | — |
| 26 | TTL 隐写解码 | ❌ 缺 | **SB-C** |
| 27 | xortool 加解密 | ✅ 已有（xor-auto-solve 等） | — |
| 28 | pyc/pyo 文件转 py | ❌ 缺（本批交付常量提取+结构诊断；完整反编译为 uncompyle6 级工程，长期记账） | **SB-D** |
| 29 | NTFS 数据流 | ❌ 缺 | **SB-B** |
| 30 | OpenPuff 隐写 | ❌ 缺（**闭源 freeware**，embeddedsw.net 不开源、无公开算法规范，无法"用开源算法合并"；其 LSB 域已被位平面扫描覆盖） | 记账 |
| 31 | 文件尾附加一句话木马 | ⚠️ 命令参考（渗透域，非 misc 解题） | 记账 |

## 子任务分配（4 并行子智能体，硬文件隔离）

- **SB-A**：`rarCrypt.ts` + `rarBrute.ts`——RAR3 SHA-1 拉伸（0x40000 轮）+ AES-128-CBC + 2 字节 quick check；字典/掩码复用 zipBrute；向量=libarchive 加密 fixture + 自造对称向量
- **SB-B**：`fileRepair.ts`（BMP 宽高反推/GIF 头+宽高/JPG SOI-EOI+SOF 诊断）+ `ntfsAds.ts`（ZIP extra field 0x000a STREAM 属性）
- **SB-C**：`snowStego.ts`（空白二进制，双映射+全变体）+ `cloakify.ts`（内置词表 4-6 套+auto 模式）+ `ttlStego.ts`（4 值 2bit/chr/低 4 位多映射）
- **SB-D**：`pycParse.ts`（magic 表+marshal TYPE_CODE 递归+FLAG_REF）+ `pycStego.ts`（Stegosaurus 协议提取+异常检测）

## 主控接线（子智能体完成后）

1. codec 操作注册：snow-decode/cloakify/ttl-decode（批次 O 展开导入模式：模块内导出 operations 片段）
2. challengeCatalog 更新：archive 类加 rar-brute；text 类加 snow/cloakify/ttl；新增取证条目（file-repair 扩展/pyc）
3. UI：RarInspectCard 爆破模式、FileForensicsWorkspace 修复区扩展、pyc 落点（ReverseWorkspace 或文件取证）
4. pcap TTL 列提取接线（TrafficWorkspace → ttlStego）
5. 通关执行器集成：RAR 爆破链/pyc 常量链/ADS 链/snow 链进 solve-real-challenges.mjs

## 验证门禁

- 每引擎 node --test 全绿（子智能体自测）
- 通关执行器对新真题全通（libarchive 加密 RAR / stegosaurus 样例 / 自造 TTL pcap 等）
- agent-code-reviewer 独立复核（≥3 文件门禁）
- self-verify-dev 八门禁

## 边界记账（不开发项）

| 项 | 原因 | 缓解 |
|---|---|---|
| OpenPuff | 闭源无公开规范 | 位平面扫描覆盖 LSB 域；出现真题时按样本逆向 |
| mp3stego 引擎 | C++ 闭源外部工具 | 命令参考卡已有（工具命令 tab） |
| pyc→py 完整反编译 | uncompyle6/decompyle3 级大工程（Python 语义完整重建） | 本批交付常量/字符串提取（flag 最常见藏点）+结构诊断+隐写提取；长期路线 v2.0.x |
| 一句话木马附加 | 渗透域功能 | 工具命令参考已有 |
