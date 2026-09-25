# 批次 SI：随波逐流·图片隐写菜单 32 项对标补齐

来源：用户第二张随波逐流截图（图片隐写菜单，32 项），指令同批次 SB（"我们都要有，放进对应分类，开源直接合并/用算法，按流程，真题测试"）。
前序：批次 SB（docs/plans/sb-suibo-parity-2026-09-24.md，随波逐流第一张截图 31 项）已交付；本批是其图片隐写菜单的完整对标。

## 一、32 项对标矩阵（初稿，随调研回填）

| # | 随波逐流项 | 现状 | 批次 SI 处置 | 线 |
|---|---|---|---|---|
| 1 | 图片 StegSolve LSB | ✅ 已有（bitPlaneScan 288 组合 + imagePlanes.extractLsbBytes） | 无需动 | — |
| 2 | 双图组合 Image Combiner | ❌ 缺 | 新增：XOR/AND/OR/ADD/SUB/MUL 双图 rgba 逐像素运算 + 结果预览/下载 | D |
| 3 | 图片 Stereogram Solver | ❌ 缺 | 调研 C 定（低频题，简单偏移相关算法或边界记账） | C |
| 4 | gif 分帧查看 Stegsolve FrameBrowser | ✅ 已有（gifInspect 帧分解 + 帧查看） | 无需动 | — |
| 5 | gif 动图分解帧 | ✅ 已有（decodeGifFrames + 帧导出） | 无需动 | — |
| 6 | 图片转 Base64 | ✅ 已有（codec data URL 操作） | 无需动 | — |
| 7 | Base64 转图片 | ✅ 已有（同上） | 无需动 | — |
| 8 | 图片拼上、反转、反色、修改高度 | ◐ 部分（修改高度=repairBmp） | 新增：拼接（横向/纵向）、水平/垂直翻转、反色（rgb 255-n）；修改高度引导现有修复卡 | D |
| 9 | npiet Piet 位图提取 | ❌ 缺 | 新增：Piet 解释器（codel 块遍历 + DP/CC 规则 + 栈机） | C |
| 10 | F5 隐写提取(Java) | ❌ 缺 | 新增：JPEG DCT 系数读取 + F5 矩阵编码提取 | A |
| 11 | jsteg 隐写提取 | ❌ 缺 | 新增：同上 + jsteg LSB(跳0/1) 提取 | A |
| 12 | JPHS 图片隐写 | ❌ 缺 | 调研 A 定（jphide 算法复杂度） | A |
| 13 | steghide 隐写提取 | ❌ 缺 | 调研 B 定（Rijndael-256 + 位置序列复现重量级评估） | B |
| 14 | stegpy 隐写提取 | ❌ 缺 | 调研 B 定 | B |
| 15 | bftools BrainTools | ❌ 缺 | 新增：图像→BF 指令串（黑白块阈值）+ BF 解释器（纯 JS ~50 行） | C |
| 16 | PNG lsb 数据提取 | ✅ 已有（extractLsbBytes 多通道/位序） | 无需动 | — |
| 17 | ImageSteganography 提取 | ✅ 同类已有（Ruby LSB 与 #16 同族） | 记同类归并 | — |
| 18 | JS:PixelJihad 加解密 | ❌ 缺 | 开源 JS（oakes/PixelJihad）算法直译 | B |
| 19 | JS:QrazyBox QR 解码 | ✅ 已有（qrDecode + 位平面扫描） | 无需动 | — |
| 20 | QR 码补定位角 | ❌ 缺 | 新增：canvas 绘三定位角（尺寸自适应）+ 直接过现有 qrDecode | D |
| 21 | 光栅图隐写提取 | ❌ 缺 | 调研 C 定形态（条带遮罩/双图叠加） | C |
| 22 | 1,0 字符串转图 | ❌ 缺 | 新增：01 串（支持分隔/宽度参数）→黑白图，联动 QR 解码 | D |
| 23 | X,Y 坐标串转图 | ❌ 缺 | 新增：坐标对序列→散点画布，联动 QR 解码 | D |
| 24 | RGB 数据串转图 | ❌ 缺 | 新增：RGB(hex/十进制)序列→图片 | D |
| 25 | 图片转 RGB 数据 | ❌ 缺 | 新增：rgba→RGB 串导出 | D |
| 26 | 图片转文本 Novel_In_Image | ❌ 缺 | 新增：像素→字符映射（Novel_In_Image 兼容格式） | D |
| 27 | 文本转图片 Novel_In_Image | ❌ 缺 | 新增：反向嵌入 | D |
| 28 | flood-fill 式图片掩码提取(key%) | ❌ 缺 | 新增：seed 坐标 flood-fill 相邻同色区域提掩码 | D |
| 29 | 图片盲水印 >>> | ❌ 缺（challengeCatalog 仅 soon 占位） | 新增：DWT-DCT-SVD 提取/嵌入（chldknd 算法链） | C |
| 30 | openstego.jar | ❌ 缺 | 调研 B 定（LSB+java Random PRNG 复刻提取） | B |
| 31 | Arnold 猫脸变换加解密 | ❌ 缺 | 新增：正/逆变换 + 周期枚举（CTF 高频） | C |
| 32 | WSL outguess/Jzsteg | ❌ 缺 | outguess=A 线（jsteg 变体）；Jzsteg=jsteg 同族 | A |

汇总：**已有 8 / 部分归并 1（#8 部分、#17 同类） / 缺失 23**。

## 二、分线施工（四线并行，硬文件隔离，主控统一接线）

- **线 A（JPEG 域，最重）**：自研 baseline JPEG DCT 系数读取器（huffman/量化表/重启标记，估 300-500 行）→ jsteg / F5 / JPHS / outguess 四工具提取。前置调研 A 回填。
- **线 B（带口令 LSB 系）**：PixelJihad（JS 直译）/ stegpy / openstego / steghide（视调研定提取可行性）。前置调研 B 回填。
- **线 C（数学变换与 esolang）**：Arnold / 盲水印（DWT-DCT-SVD 纯 JS 数学）/ Piet / bftools(BF) / 光栅 / Stereogram。前置调研 C 回填。
- **线 D（简单转换与 QR + UI）**：双图组合 / 拼接翻转反色 / 01 串→图 / XY→图 / RGB↔图 / Novel_In_Image / flood-fill / QR 补定位角。全部纯 JS 无前置。

## 三、验证要求

- 每能力至少 1 组程序化构造向量（自造闭环）+ 真题对拍（调研 D 清单，附件不可得的按 writeup 特征构造等效向量）
- 全量门禁：tsc/eslint/npm test（新引擎测试）/verify 133 不动/生产构建/通关基线零回归（sb 9/9、全套 30/18）
- 浏览器实测：新卡片按用户旅程走 + console 零错误
- reviewer 独立复核

## 四、边界候选（调研后定稿）

- steghide 提取若需复刻完整图论嵌入（无法仅靠 PRNG 序列提取）→ 记边界（闭源级行为）
- Stereogram/光栅若 CTF 出题频率极低且无标准格式 → 简化实现或记账
- JPHS(jphide) 若规格不可完整获得 → 记边界
- JPEG progressive 格式 → 首版仅 baseline，progressive 记账
