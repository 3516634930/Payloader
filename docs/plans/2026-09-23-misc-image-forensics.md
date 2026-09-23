# 计划：misc 域图片取证与嵌入提取能力包（位平面/色道/嵌入扫描/chunk 枚举/strings·hexdump 增强）

日期：2026-09-23 ｜ 分级：重档（≥5 文件、跨模块） ｜ 约束：纯前端零依赖零网络

## 需求一句话

选手上传一张 PNG/JPG：位平面浏览 + LSB 提取出 flag、尾附 zip 直接下载、tEXt chunk 内容标红展示——全程不离开浏览器；strings/hexdump 从"只读前几条"升级为可搜索、可导出、可翻页。

## 已对齐的验收标准（来自需求方，构造样本验收）

1. PNG IEND 后附 `PK\x03\x04` 头 zip → 嵌入卡片检出并下载。
2. PNG tEXt chunk 写 `flag{chunk_test}` → chunk 卡片标红显示（FlagAutoText）。
3. 8×8 纯色 PNG 最低位平面嵌文本 → LSB 提取出文本。
4. 全门禁绿 + 新增回归绿 + 手机端位平面网格可横向滚动。

## 设计约束（性能红线）

- 嵌入扫描：前 8MB、签名首字节 `indexOf` 跳转（非朴素滑窗）。
- 位平面：4MP 上限；超限 `createImageBitmap` 降采样 + 提示；平面灰度**惰性现算**（不缓存 32 份全尺寸灰度，内存峰值 = RGBA 16MB + 单平面 4MB）。
- LSB 提取：单次上限 64KB 字节；预览截断 2KB。
- >1s 同步计算走现成 analyzing 占位模式。

## 任务分解

### T1 imagePlanes.ts（纯函数，无 DOM 依赖，node 可测）

- `MAX_ANALYSIS_PIXELS = 4_000_000`
- `extractBitPlane(rgba: Uint8Array, channel: 0|1|2|3, bit: 0..7)` → Uint8Array（0/255 灰度，惰性现算）
- `extractChannelPlane(rgba, channel)` → 单通道灰度数组（色道导出用）
- `extractLsbBytes(rgba, {channel, bit, maxBytes})` → 按行序逐像素取 bit，MSB-first 组字节
- `bytesToPreviewText(bytes, maxChars)` → latin1 预览文本
- 导出 `PLANE_CHANNELS = ['R','G','B','A']` 供 UI 渲染选择器

### T2 embedScan.ts（纯函数）

- `scanEmbeddedSignatures(bytes, {scanLimit=8MB, maxHits=16})` → `[{ext,name,offset}]`；跳过 offset=0；签名表：zip(`PK\x03\x04`)/png/jpeg(`\xFF\xD8\xFF`)/gz(`\x1F\x8B\x08`)/rar4/7z；每类型同偏移只记首个（嵌套去重：zip 命中后跳过其数据段？——不做数据段跳转，只按 `maxHitsPerType=4` 限流）
- `findPngTrailer(bytes)` → IEND chunk 结束（含 4B CRC）后仍有剩余 → `{offset, trailing}`
- `findJpegTrailer(bytes)` → marker 链解析（段长度跳转；SOS 后熵编码跳过 `FF00`/`FFD0-D7`）到 EOI → `{offset, trailing}`
- `enumeratePngChunks(bytes, {maxChunks=256})` → `[{type,length,crcOk,dataStart}]`；tEXt → `{keyword,text}`（latin1）；zTXt → `{keyword,compressedBytes}`；iTXt → `{keyword,compressionFlag,compressedBytes|text}`——解压由 UI 层 async DecompressionStream 做（先例 smartBase.ts:59-68），纯函数层只做结构解析
- 复用 fileDetect 的 `crc32Bytes` 与 PNG 签名常量

### T3 UI 并入 FileForensicsWorkspace.tsx（ff-card 模式）

- report 增加 `embedded` 字段（loadFile 同步算，快）
- 新卡片：
  - `ff-card-bitplanes`：`createImageBitmap` 解码（>4MP 降采样 + 提示 badge）→ 4 通道×8bit = 32 缩略图网格（每平面 128px 缩略，横向可滚动容器，手机端 media query）→ 点选平面放大渲染 → LSB 提取区（通道/位下拉 + 提取按钮 + FlagAutoText 预览 + 下载）
  - `ff-card-channels`：R/G/B/A(/灰度 L) 导出按钮（canvas.putImageData → toBlob 下载单通道 PNG，选中通道值填 RGB 三通道，A 通道 alpha=255）
  - `ff-card-embedded`：嵌入命中列表（类型 + 偏移 + 提取下载按钮）+ PNG IEND/JPEG EOI 尾附卡（N 字节 + hex 预览 + 下载）；无命中不渲染卡
  - `ff-card-chunks`：chunk 表（类型/长度/CRC 徽章），tEXt/zTXt/iTXt 内容行过 FlagAutoText；zTXt/iTXt async 解压（DecompressionStream，失败显示压缩数据大小 + 下载原始）
- strings 卡增强：搜索框（子串大小写不敏感）+ minLength 选择（4/6/8，重跑 extractStrings limit 20000）+ 复制全部 + 导出 txt + 分页（>500 条，每页 200）
- hexdump 卡增强：偏移跳转输入 + 前后翻页（512B/页）+ 搜索（hex 串/文本两模式，从当前偏移向后找，命中跳页高亮）
- 菜单 fileMenus 追加：位平面/嵌入/chunks 条目

### T4 recommendTools.ts 摘牌

- `png-bitplanes`/`png-channels`/`png-chunks`/`archive-embedded`：删 `soon: true`（cardId 已对）
- `jpg-eoi`：删 `soon`，cardId 改 `ff-card-embedded`
- `jpg-metadata`：保持 soon（不在本需求）
- 同步更新 tests 中 `assert.ok(tools[1].soon)` 等断言

### T5 测试（tests/file-forensics.test.mjs 追加）

- 构造 PNG（makePng 已有）+ IEND 后附 zip 头 → `scanEmbeddedSignatures` 命中 zip + offset 断言；`findPngTrailer` 断言 offset/trailing 长度
- 构造最小 JPEG（SOI+APP0+SOS+熵编码+EOI+尾附）→ `findJpegTrailer`
- makePng + 手工 tEXt chunk（`flag{chunk_test}`）→ `enumeratePngChunks` 类型/长度/crcOk/text 断言
- 构造 8×8 RGBA 低 1 位嵌 "flag{lsb}" → `extractLsbBytes` 提取回原文断言（encode 与 decode 对称）；`extractBitPlane` 全零/全 1 平面断言
- recommendTools：PNG 组全量上线断言（无 soon）+ jpg-eoi cardId 断言

### T6 验证与收尾

- `npm test` → `npm run typecheck` → `npm run lint` → `npm run check`（串行，记忆：门禁必须串行）
- 浏览器验证：node 脚本生成 3 个构造样本 → MCP 浏览器上传走完 3 条验收 + 手机视口（≤680px）位平面网格横向滚动 + 防呆（超大图降采样提示、非图片文件无位平面卡、空搜索、超长粘贴）
- agent-code-reviewer 独立复核（不带实现上下文）
- self-verify-dev 八门禁 + 交付汇报

## 非目标

- JPEG 元数据提取（jpg-metadata 保持 soon）
- PAcss/stego 高级算法（F5/steghide 等需后端或 WASM，属 v2.0.2+ 能力弧线）
- zTXt 解压的 node 侧回归（浏览器专属 API，结构解析已测）
