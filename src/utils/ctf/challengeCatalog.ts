// 杂项取证域「题型 → 工具」目录（challenge picker 数据层）：对齐中文社区惯用 misc 子类
// （调研报告 ctf-tool-navigation-2026-09-24.md：压缩包/图片/音频/视频与 GIF/文本/流量/通用兜底）。
// 纯数据零依赖；卡内三类入口——file（需上传文件，未上传点击弹选择器）/ cipher（跳密码域定位操作）/
// module（切域）。cardId/operationId 由 tests/challenge-catalog.test.mjs 钉住与实现一致，防目录漂移。

export type CatalogEntryKind = 'file' | 'cipher' | 'module';

export interface CatalogTool {
  id: string;
  label: { zh: string; en: string };
  description: { zh: string; en: string };
  kind: CatalogEntryKind;
  // kind=file：上传后在域内滚动到的卡片锚点（与组件卡片 id 一致）。
  cardId?: string;
  // kind=cipher：密码域操作 id（CodecWorkbench.focusOperation 定位）。
  operationId?: string;
  // kind=module：目标域 id（traffic 等）。
  targetModuleId?: string;
  // kind=module 专属：已上传文件时把文件移交目标域（pcap → 流量域），与推荐条的 handoffFile 行为一致；
  // 未置位则纯切域。
  handoffFileOnNavigate?: boolean;
  // 规划中：弱化展示，点击提示。上线后摘掉即成普通条目。
  soon?: boolean;
}

export interface ChallengeCategory {
  id: string;
  icon: string;
  label: { zh: string; en: string };
  hint: { zh: string; en: string };
  tools: CatalogTool[];
}

export const challengeCatalog: ChallengeCategory[] = [
  {
    id: 'archive',
    icon: '🗜️',
    label: { zh: '压缩包', en: 'Archives' },
    hint: { zh: '伪加密、弱口令、CRC32 反推与嵌入文件是压缩包题四板斧。', en: 'Pseudo-encryption, weak passwords, CRC32 recovery, and embedded files.' },
    tools: [
      {
        id: 'zip-brute',
        label: { zh: 'ZIP 密码爆破', en: 'ZIP password brute force' },
        description: { zh: 'ZipCrypto/AES 字典与掩码爆破，内置 CTF 弱口令表，10 万口令约 3 秒。', en: 'ZipCrypto/AES dictionary and mask brute force with a built-in CTF wordlist.' },
        kind: 'file',
        cardId: 'ff-card-zipbrute',
      },
      {
        id: 'zip-pseudo',
        label: { zh: '伪加密修复', en: 'Pseudo-encryption fix' },
        description: { zh: '清除 ZIP 加密标志位（flag bit0），一键下载修复后的文件。', en: 'Clears the ZIP encryption flag bit and downloads the fixed file.' },
        kind: 'file',
        cardId: 'ff-card-repair',
      },
      {
        id: 'crc32-preimage',
        label: { zh: 'CRC32 反推内容', en: 'CRC32 preimage' },
        description: { zh: '已知 CRC32 反推 2-5 字节短内容（flag 片段/PIN），毫秒级。', en: 'Recovers 2-5 byte contents from a known CRC32 in milliseconds.' },
        kind: 'cipher',
        operationId: 'crc32-attack',
      },
      {
        id: 'archive-embedded',
        label: { zh: '嵌入文件提取', en: 'Embedded files' },
        description: { zh: '文件尾附加数据与嵌入文件签名扫描（压缩包套压缩包题）。', en: 'Trailing-data and embedded-signature scan for nested archives.' },
        kind: 'file',
        cardId: 'ff-card-embedded',
      },
      {
        id: 'rar-repair',
        label: { zh: 'RAR 修复', en: 'RAR repair' },
        description: { zh: 'RAR4 签名重写与伪加密清位（SimpleRAR 型头修复题），修复文件直接下载。', en: 'RAR4 signature rewrite and pseudo-encryption clearing with fixed-file download.' },
        kind: 'file',
        cardId: 'ff-card-rar',
      },
      {
        id: 'rar-brute',
        label: { zh: 'RAR 密码爆破', en: 'RAR password brute force' },
        description: { zh: 'RAR3 真加密条目口令爆破（SHA-1 拉伸 + AES-128-CBC 快筛 + 解压 CRC 终验），字典/自定义/掩码三源。', en: 'RAR3 password brute force (SHA-1 stretching + AES-128-CBC quick check + inflate CRC verification) with dictionary, custom, and mask sources.' },
        kind: 'file',
        cardId: 'ff-card-rar',
      },
      {
        id: 'ntfs-ads',
        label: { zh: 'NTFS 数据流', en: 'NTFS data streams' },
        description: { zh: 'ZIP 载体的 ADS 提取（file:stream 冒号条目与 0x000a extra field 两种形态），流内容下载。', en: 'Extracts NTFS ADS from ZIP carriers (colon entries and 0x000a extra fields) with stream download.' },
        kind: 'file',
        cardId: 'ff-card-ntfs',
      },
    ],
  },
  {
    id: 'image',
    icon: '🖼️',
    label: { zh: '图片隐写', en: 'Image steganography' },
    hint: { zh: 'LSB 位平面与结构修复并重；先自动扫描再目检。', en: 'LSB bit planes plus structure repair; auto-scan first, then eyeball.' },
    tools: [
      {
        id: 'bitplane-scan',
        label: { zh: '位平面 + 全组合自动扫描', en: 'Bit planes + auto scan' },
        description: { zh: '32 平面目检 + zsteg 式 288 组合自动评分命中（zlib/flag/可打印）。', en: '32 planes plus zsteg-style 288-combination auto-scan scoring.' },
        kind: 'file',
        cardId: 'ff-card-bitplanes',
      },
      {
        id: 'qr-scan',
        label: { zh: '二维码识别（含位平面）', en: 'QR scan (bit planes)' },
        description: { zh: '原图 + 32 个位平面逐个识别二维码（LSB 隐写的二维码可解），GIF 帧拼合识别。', en: 'Scans the image and all 32 bit planes for QR codes; GIF frames stitch too.' },
        kind: 'file',
        cardId: 'ff-card-bitplanes',
      },
      {
        id: 'channel-split',
        label: { zh: '色道分离', en: 'Channel splitting' },
        description: { zh: 'R/G/B/A 单通道导出灰度图，异色通道藏信息直接现形。', en: 'Export one channel as grayscale; odd channels reveal hidden data.' },
        kind: 'file',
        cardId: 'ff-card-channels',
      },
      {
        id: 'png-repair',
        label: { zh: 'PNG 宽高修复', en: 'PNG dimension repair' },
        description: { zh: 'CRC 校验失败的 IHDR 宽高暴力还原并下载修复图。', en: 'Brute-forces broken IHDR dimensions and downloads the fixed PNG.' },
        kind: 'file',
        cardId: 'ff-card-repair',
      },
      {
        id: 'image-repair',
        label: { zh: 'BMP/GIF/JPG 头修复', en: 'BMP/GIF/JPG repair' },
        description: { zh: 'BMP 魔数重建+宽高按文件大小反推、GIF 头重建+画布推断（可手工指定）、JPG SOI/EOI 重写与段结构诊断。', en: 'BMP magic rebuild plus size inference, GIF header/canvas repair with manual override, and JPG SOI/EOI rewrite with segment diagnosis.' },
        kind: 'file',
        cardId: 'ff-card-repair',
      },
      {
        id: 'png-chunks',
        label: { zh: 'PNG chunk 枚举', en: 'PNG chunk list' },
        description: { zh: '逐 chunk 列出类型与长度，tEXt 注释段直接展示。', en: 'Lists every chunk with lengths; tEXt comments shown inline.' },
        kind: 'file',
        cardId: 'ff-card-chunks',
      },
      {
        id: 'jpg-metadata',
        label: { zh: 'JPG 元数据', en: 'JPG metadata' },
        description: { zh: 'EXIF/注释段提取。', en: 'EXIF and comment-segment extraction.' },
        kind: 'file',
        cardId: 'ff-card-jpg-metadata',
        soon: true,
      },
      {
        id: 'image-ops',
        label: { zh: '图像运算与转换', en: 'Image operations' },
        description: { zh: '双图异或/加减、翻转反色拼接、0/1 串与坐标串转图、RGB 串互转、字符画、连通域提取、二维码补定位角。', en: 'Combine/flip/invert, 0/1 or XY text to image, RGB text, ASCII art, flood fill, QR finder repair.' },
        kind: 'file',
        cardId: 'ff-card-imageops',
      },
      {
        id: 'image-stego',
        label: { zh: '置乱与频域隐写', en: 'Scramble & frequency stego' },
        description: { zh: 'Arnold 猫脸置乱还原、光栅相位扫描、立体图偏移求解、盲水印双图提取、PixelJihad、Brainloller/Braincopter 执行。', en: 'Arnold cat map, raster phases, stereogram solver, blind watermark, PixelJihad, brainloller/braincopter.' },
        kind: 'file',
        cardId: 'ff-card-imagestego',
      },
      {
        id: 'jpeg-dct',
        label: { zh: 'JPEG DCT 隐写（jsteg）', en: 'JPEG DCT stego (jsteg)' },
        description: { zh: 'DCT 系数 LSB 提取（跳过 0/±1），CLI 载荷/flag 自动识别；F5/outguess/JPHS 后续批次接入。', en: 'DCT coefficient LSB extraction with magic auto-scan; F5/outguess/JPHS arrive in later batches.' },
        kind: 'file',
        cardId: 'ff-card-jpegstego',
      },
      {
        id: 'blind-watermark',
        label: { zh: '盲水印提取', en: 'Blind watermark' },
        description: { zh: '频域（FFT，兼容 chishaxie/BlindWaterMark）盲水印双图提取，seed/alpha 可调。', en: 'Frequency-domain (FFT, chishaxie-compatible) blind watermark extraction.' },
        kind: 'file',
        cardId: 'ff-card-imagestego',
      },
    ],
  },
  {
    id: 'audio',
    icon: '🎧',
    label: { zh: '音频隐写', en: 'Audio steganography' },
    hint: { zh: '频谱图永远第一步；DTMF/摩尔斯/WAV-LSB 一张卡全覆盖。', en: 'Spectrogram first; DTMF, Morse, and WAV-LSB in one card.' },
    tools: [
      {
        id: 'audio-suite',
        label: { zh: '音频隐写分析', en: 'Audio steganography suite' },
        description: { zh: '频谱图（看隐藏文字）/DTMF 拨号音/摩尔斯电码/WAV LSB 四件套。', en: 'Spectrogram, DTMF tones, Morse code, and WAV LSB in one card.' },
        kind: 'file',
        cardId: 'ff-card-audio',
      },
    ],
  },
  {
    id: 'video',
    icon: '🎞️',
    label: { zh: '视频与 GIF', en: 'Video & GIF' },
    hint: { zh: 'GIF 帧延时与注释段是高频考点；视频先查工具命令库 ffmpeg。', en: 'GIF frame delays and comments are classic; videos go through ffmpeg recipes.' },
    tools: [
      {
        id: 'gif-inspect',
        label: { zh: 'GIF 深度解析', en: 'GIF inspection' },
        description: { zh: '帧分离下载/帧延时三口径解读/注释与文本扩展段提取。', en: 'Frame export, three delay readings, and comment extraction.' },
        kind: 'file',
        cardId: 'ff-card-gif',
      },
      {
        id: 'video-ffmpeg',
        label: { zh: 'ffmpeg 帧提取/音轨分离', en: 'ffmpeg frames & audio' },
        description: { zh: '视频类到应用顶部「工具命令」tab 查 ffmpeg 逐帧/抽音轨命令（本域不解析视频容器）。', en: 'Videos go through ffmpeg recipes in the top-level Tools tab.' },
        kind: 'file',
        cardId: 'ff-card-summary',
        soon: true,
      },
    ],
  },
  {
    id: 'document',
    icon: '📄',
    label: { zh: '文档与程序取证', en: 'Documents & bytecode' },
    hint: { zh: 'PDF 风险指标/注释/流；pyc 常量挖掘与 Stegosaurus 隐写。', en: 'PDF indicators, comments, streams; pyc constants and Stegosaurus stego.' },
    tools: [
      {
        id: 'pdf-inspect',
        label: { zh: 'PDF 取证分析', en: 'PDF forensics' },
        description: { zh: '风险指标（JS/动作/嵌入文件）/注释/可疑文本/FlateDecode 流解压。', en: 'Risk indicators, comments, suspicious text, and stream inflation.' },
        kind: 'file',
        cardId: 'ff-card-pdf',
      },
      {
        id: 'pyc-inspect',
        label: { zh: 'pyc 常量挖掘 + Stegosaurus', en: 'pyc constants & Stegosaurus' },
        description: { zh: 'Python 版本识别、co_consts 字符串/bytes 常量提取（flag 藏点）、死槽隐写提取与结构异常诊断。', en: 'Python version, co_consts extraction (flag hot spots), dead-slot stego extraction, and anomaly diagnosis.' },
        kind: 'file',
        cardId: 'ff-card-pyc',
      },
      {
        id: 'pdf-password',
        label: { zh: 'PDF 解密（弱口令）', en: 'PDF decryption' },
        description: { zh: '加密 PDF 的口令爆破（RC4/AES）规划中，当前可先 strings 找线索。', en: 'Encrypted-PDF password brute force is planned; strings may help meanwhile.' },
        kind: 'file',
        cardId: 'ff-card-strings',
        soon: true,
      },
    ],
  },
  {
    id: 'text',
    icon: '🔤',
    label: { zh: '文本隐写', en: 'Text steganography' },
    hint: { zh: '零宽字符与不可见水印；纯输入工具即点即用。', en: 'Zero-width characters and invisible watermarks; pure-input tools.' },
    tools: [
      {
        id: 'zero-width',
        label: { zh: '零宽字符解码', en: 'Zero-width decode' },
        description: { zh: 'ZWSP/ZWNJ/ZWJ 序列解码（纯输入，粘贴即解）。', en: 'Decodes ZWSP/ZWNJ/ZWJ sequences; paste and go.' },
        kind: 'cipher',
        operationId: 'zero-width',
      },
      {
        id: 'snow-stego',
        label: { zh: 'snow 空白隐写', en: 'Snow whitespace stego' },
        description: { zh: '空格/tab 隐写 8 变体提取（官方 3bit 规范 + 朴素 0/1 映射），粘贴含可疑空白的文本。', en: 'Eight whitespace-stego variants (official 3-bit spec plus naive mappings); paste suspicious text.' },
        kind: 'cipher',
        operationId: 'snow-stego',
      },
      {
        id: 'cloakify-stego',
        label: { zh: 'Cloakify 词表隐写', en: 'Cloakify word-list stego' },
        description: { zh: '词表映射还原：内置 6 套词表自动扫描，自定义词表粘到密钥栏。', en: 'Word-list recovery: auto-scans 6 built-in lists; paste custom lists into the key field.' },
        kind: 'cipher',
        operationId: 'cloakify',
      },
      {
        id: 'ttl-stego',
        label: { zh: 'TTL 隐写解码', en: 'TTL stego decode' },
        description: { zh: '粘贴 Wireshark TTL 列或数字序列，2bit 四值/chr/低 4 位全映射尝试。', en: 'Paste Wireshark TTL columns or numbers; 2-bit quaternary, chr, and low-nibble mappings.' },
        kind: 'cipher',
        operationId: 'ttl-stego',
      },
      {
        id: 'suspicious-scan',
        label: { zh: '可疑内容扫描', en: 'Suspicious content' },
        description: { zh: '上传文本文件扫 flag/Base64 片段/关键词/零宽计数。', en: 'Upload a text file to scan for flags, Base64 fragments, keywords, and zero-width characters.' },
        kind: 'file',
        cardId: 'ff-card-suspicious',
      },
    ],
  },
  {
    id: 'traffic',
    icon: '📡',
    label: { zh: '流量分析', en: 'Traffic analysis' },
    hint: { zh: 'pcap/pcapng 在流量域解析：包列表/协议统计/TCP 流/HTTP 对象。', en: 'pcap/pcapng parsing lives in the Traffic module.' },
    tools: [
      {
        id: 'traffic-handoff',
        label: { zh: '转到流量分析域', en: 'Open Traffic Analysis' },
        description: { zh: '已上传文件会随行移交并按魔数自动路由；pcap/pcapng 在流量域解析包列表与 TCP 流。', en: 'Hands the current file off and auto-routes by magic; pcap parsing lives in the Traffic module.' },
        kind: 'module',
        targetModuleId: 'traffic',
        handoffFileOnNavigate: true,
      },
    ],
  },
  {
    id: 'generic',
    icon: '🧰',
    label: { zh: '文件基础 · 通用取证', en: 'File basics & forensics' },
    hint: { zh: '类型未知时从这里开始：熵/字符串/hexdump 三件套定性。', en: 'Start here for unknown files: entropy, strings, and hexdump.' },
    tools: [
      {
        id: 'gen-entropy',
        label: { zh: '信息熵定性', en: 'Entropy check' },
        description: { zh: '熵≈8 且无结构 → 加密/压缩；低熵 → 文本或隐写容器。', en: 'Entropy ~8 means encrypted/compressed; low entropy means text or a container.' },
        kind: 'file',
        cardId: 'ff-card-summary',
      },
      {
        id: 'gen-strings',
        label: { zh: '可读字符串', en: 'Strings' },
        description: { zh: 'flag/URL/文件头线索一网打尽，支持过滤。', en: 'Flags, URLs, and header hints with filtering.' },
        kind: 'file',
        cardId: 'ff-card-strings',
      },
      {
        id: 'gen-hexdump',
        label: { zh: 'hexdump', en: 'Hexdump' },
        description: { zh: '文件头魔数与结构目检。', en: 'Inspect magic bytes and structure by eye.' },
        kind: 'file',
        cardId: 'ff-card-hexdump',
      },
      {
        id: 'gen-embedded',
        label: { zh: '嵌入签名扫描', en: 'Embedded signatures' },
        description: { zh: '全文件滑窗找 PNG/ZIP/RAR 等嵌入与尾附数据。', en: 'Sliding-window scan for embedded PNG/ZIP/RAR and trailing data.' },
        kind: 'file',
        cardId: 'ff-card-embedded',
      },
    ],
  },
];
