# 成熟 CTF 工具箱"题型→工具"导航交互范式调研

日期：2026-09-24
目的：为离线 CTF 工具箱 Payloader（React+TS+Mantine，三域：密码与编码 / 杂项取证 / 流量分析）设计 misc 域"题型→工具"导航提供参考。
方法：WebSearch + WebFetch + firecrawl 实际访问 + 官网截图视觉分析，所有结论均落到具体页面；无凭记忆编造内容。

---

## 一、各项目导航交互的事实描述

### 1. 随波逐流 CTF 编码工具（V8.0.1，长弓三皮）

来源：
- 官网产品页（功能总表）：<http://1o1o.xyz/bo_ctfcode.html>
- 官方使用说明书（20 章完整文档）：<http://1o1o.xyz/help/%5B%E9%9A%8F%E6%B3%A2%E9%80%90%E6%B5%81%5DCTF%E7%BC%96%E7%A0%81%E5%B7%A5%E5%85%B7_%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E%E4%B9%A6.html>
- 官网界面截图（AI 视觉分析）：`http://1o1o.xyz/img/ctf_code1.jpg`、`http://1o1o.xyz/img/img_ctfcode2.jpg`

**信息架构（三层混合，"中文工具的经典交互"）：**

1. **顶部菜单栏（≈顶级 Tab，共 14 个入口）**：`Base/Rot、字密1~4、编码转换、带key解密、多key解密、在线解密、进制转换、其他工具、文件、图片`（说明书 CH01"菜单栏：……等顶级菜单入口"；截图视觉分析确认顶部一排 Tab：`Base/Rot、字符1-4、编码转换、带key解密、多key解密、在线解密、进制转换、其他工具、文件、图片`）。
2. **左侧功能树（菜单树）**：截图分析确认——侧栏根节点 `全部功能(465)`，分类节点带计数（如 `Base/Rot (43)`、`带key解密 (30)`），顶部有**搜索框**（说明书 CH02B：输入关键字实时过滤、命中项父菜单自动展开、清空恢复全树；支持中英关键字，输 "morse" 能找到摩斯）和**全部展开/收缩**按钮；存在**收藏★节点**（侧栏可见星标分类）。说明书统计：功能总数 472+。
3. **主工作区（"上输入/下输出"单舞台）**：密文输入区（上部）→ 结果输出区（下部）；输入/输出区标题栏各带自己的按钮组（清空/复制/粘贴/导入文件/**⚡一键解码**/编辑密文下拉/结果搜索正则高亮/↑结果↑互换/导出）。
4. **全局密钥行**：`密钥 key/str/url:` 输入框横贯输入区上方，行首 8 个图标快捷按钮（进制转换器/ASCII 对照表/扫码/代码运行器/图形密码/网址导航/比赛工具/writeup），行尾"选择文件（填路径）"与"向右展开操作历史面板"。
5. **一键解码（智能识别）**：蓝色主按钮，自动穷举多种解码方式（说明书 CH18 专章）；另有"多轮探测引擎，可自动识别进制转换、非常规Base编码及复合结构"（官网产品页自述）。

**与"文件"相关的组织（对 Payloader misc 域最有参考价值）：**
- 官网功能总表把文件类功能归入两个类别：**"文件与图片"**（zip 伪加密/多层解压/字典爆破/CRC32 碰撞、binwalk、StegSolve LBS、gif 分帧、pcap 查看、wav 摩斯、DTMF、盲水印、 Arnold 猫脸等 60+ 项）与**"文件自动探测"**（独立类别：文件头与后缀一致性检测、CTF 关键词可疑字符串、EXIF/XMP 元数据、JPG `FF D9` 结束标志后数据、zip 伪加密判断并自动修复、PNG 高度判断并自动修复、PNG/BMP LSB 文本隐写、base64 图片提取还原——即"上传→自动全检"的被动分析组）。
- 说明书 CH15"文件操作菜单"（36 项）按**子菜单组**分：文件分析/查看（4，含 `★文件及图片及隐写` 综合入口"自动识别类型后调用对应分析工具"）、文件提取（binwalk/foremost）、音频分析（DTMF/mp3stego/wav 摩斯）、隐写提取（Cloakify/snow/Stegosaurus）、文件操作/转换（头修复/进制流/Base64 文件）、ZIP/RAR（8 项：信息读取/伪加密/伪加密修复/嵌套解压/批量读取/zip 字典爆破/rar 字典爆破/CRC32 爆破）、流量分析（pcap USB 键盘/鼠标/`★pacp流量分析`）、其他（pyc 反编译/NTFS 流/OpenPuff 等）。
- 说明书 CH16"图片工具菜单"（45 项）分 9 个子菜单组：图片隐写分析（StegSolve LSB/双图组合/立体图求解）、GIF/图片转换（分帧查看/分解帧/Base64 互转）等。

**要点**：它没有独立顶部工具栏（说明书 CH02 明确"没有独立的顶部工具栏控件……图标按钮分散在四处"），但功能组织是完整的"顶级菜单（Tab）→ 左侧分类树（计数+搜索+收藏）→ 单舞台输入输出"；文件工具通过"选择文件"进入独立 GUI 子窗口（StegSolve、Hex Viewer 等）；"文件自动探测"是独立于菜单树的被动分析入口。

### 2. CTFCrackTools / CTF-Tools GUI 系列（GitHub）

- **0Chencc/CTFCrackTools**（"国内首个 CTF 工具框架"）：<https://github.com/0Chencc/CTFCrackTools>
  - 新版 **CTFCrackTools X**：Rust + Tauri（前端 React+Vite+TS）。主界面**不是下拉也不是 tab，而是可视化节点画布**：空白画布右键添加节点（Input → 编码节点 → Output），连线后执行——方向接近 Blender/节点编辑器，可视为 CyberChef recipe 链的画布化。
  - 旧版 V4：Java"传统表单"界面（输入框+功能按钮/菜单），需 JRE、50MB+。
  - 43+ 内置算法按 **5 组**归类：编码(15)/古典密码(11)/现代加密(5)/哈希&KDF(6)/文本处理(7)。
- **RemusDBD/ctftools-all-in-one**（Gitee 镜像）：<https://github.com/RemusDBD/ctftools-all-in-one>；介绍文 <https://blog.csdn.net/wyb17870531028/article/details/144870434>
  - 按题型大类组织：**AI / MICS(Misc) / WEB / PWN / 逆向 / 密码 / Mobile**（介绍文列出的分类标题）；特点是内置离线 AI 大模型（可联动本地 Ollama）。
- **ProbiusOfficial/CTFtools-wiki**：<https://github.com/ProbiusOfficial/CTFtools-wiki>
  - 文档式导航（MkDocs 类），按题型章节组织工具目录；Release 提供**基于 Maye Lite 相对路径封装的"基础工具箱"**——即"文档索引 + 快捷启动器"组合：网页查目录、启动器按分类点开即用。
- **结论**：GUI 系列没有统一范式——表单式（V4）、节点画布式（X）、启动器分组式（Maye Lite 封装）并存；但"先按题型大类分组、组内列工具"这一层是共同的。没有一个成功项目把主界面做成单一"题型下拉框"。

### 3. CyberChef（GCHQ）

来源：
- README：<https://github.com/gchq/CyberChef>
- 分类配置源码：<https://raw.githubusercontent.com/gchq/CyberChef/master/src/core/config/Categories.json>

**事实：**
- 四区布局（README）：最左 **Operations 列表**（"categorised lists, or by searching"——分类折叠列表 + 搜索）；中间 **Recipe** 区（拖入操作、设参数）；右上**输入**（粘贴/拖放文件，最大 2GB）；右下**输出**。Auto Bake 改动即算。
- **Categories.json 共 15+ 个分类**（含每类操作数）：`Favourites（空数组，用户收藏区）、Data format(73)、Encryption/Encoding(104)、Public Key(33)、Arithmetic/Logic(31)、Networking(39)、Language(7)、Utils(50)、Date/Time(10)、Extractors(21)、Compression(21)、Hashing(49)、Code tidy(30)、Forensics(12)、Multimedia(29)、Other(22)、Flow control(10)`。收藏是一个**排在最前的空分类**，用户星标操作后落入其中。
- **"不知道用哪个操作"的解法 = Magic**：位于 `Flow control` 分类；自动尝试多种技术猜测编码，若找到有意义结果，在**输出字段显示"magic"图标**，点击即按猜出的操作链解码（README"it displays the 'magic' icon in the Output field which you can click"）。
- 搜索即输即过滤；配方可保存到本地存储、可经 URL 深链（`#recipe=...&input=base64`）分享。
- 定位：纯输入驱动（文本/文件都变成输入流），无"上传文件→按类型出面板"的概念。

### 4. zardus/ctf-tools（★9.5k）

来源：<https://github.com/zardus/ctf-tools>

**事实：**
- 已从早期 setup-scripts 演化为 **Nix flake 打包项目**（"This is a Nix flake packaging various security research tools"），非 GUI 工具箱。
- 信息架构：**README 两个 Markdown 大表**（自行打包的 + 直接取自 nixpkgs 的），三列 `Category | Tool | Description`；分类为 **binary / mobile / forensics / crypto / networking / web / stego / osint / misc / game** 十类。没有每工具的 install/use 逐步说明——安装统一走 `nix profile install github:zardus/ctf-tools#工具名`（Usage 单独成章）；个别工具特殊说明附在描述或"Downloads outside Nix"。
- 参考点：**"每类一行、每工具一句描述"的表格信息架构**本身就是一种导航（文档型），适合"工具名录+一句话用途"的呈现粒度。

### 5. AperiSolve

来源：
- 官网：<https://aperisolve.com/>
- GitHub：<https://github.com/Zeecka/AperiSolve>

**事实：**
- **上传驱动的自动化范式**：首页即拖放框（"Drag and drop a file here or click to select"）+ 可选密码框（供 steghide 等用）+ "深度分析"勾选（"slower, more thorough"）→ 点 `Analyze File` → 进度条 → 结果页。
- **16 个分析器并行**，输出**按工具分组显示**，每个工具有 **success / no-result 徽章**，提取出的文件**一键下载**（GitHub README："Runs 16 analyzers in parallel and displays their output, with per-tool success/no-result badges and one-click download of extracted files"）。分析器清单：binwalk、exiftool、file、GraphicsMagick identify、foremost、jsteg、jpseek/jphide、openstego、outguess、pcrt（PNG 检查修复）、pngcheck、steghide、strings、zsteg。
- 另有位平面可视化：按 R/G/B/Alpha 通道逐位平面查看（LSB 及更高位），随机调色板重映射 8 变体。
- 架构：Flask web + RQ worker（每个提交扇出线程、重工具隔离）+ redis 队列 + postgres；结果临时存储、定时清理；同内容哈希去重。
- 支持格式（官网）：PNG, JPG, GIF, BMP, JPEG, JFIF, JPE, TIFF...（以图像为主）。
- **交互特征：没有"选题型"步骤**——用户只管丢文件，模块全集自动跑，按模块出结果。这是与 CyberChef 完全相反的一极。

### 6. 中文社区的题型/子类分类习惯

- **BUUCTF**（<https://buuoj.cn/challenges>，现处归档模式并迁移至 ctf2.dasctf.com）：挑战页按五大方向分组（PWN/Web/Crypto/Misc/Reverse，顶部下拉+分区；CTFd 系惯用"分类下拉→题目网格"）。题库贡献指南（<https://www.zhaoj.in> 收录）同样按五类划分。Misc 题解汇总（腾讯云/阿里云社区文章）显示其 Misc 题覆盖 LSB 隐写、流量分析、伪加密、Base64、摩斯密码等 30 余种小题型。
- **攻防世界**（adworld.xctf.org.cn）：所有题型分初级/高级模式（知乎《CTF在线练习场推荐》介绍），方向同为 Web/RE/Pwn/Crypto/Misc。
- **CTFHub**（<https://www.ctfhub.com/>）：主导航"首页/赛事中心/**技能树**/历年真题/**工具**/排行榜/WriteUp"；技能树为分层树状学习路径（登录可见），公开 writeup 显示其分支如"技能树-Misc-数据隐写"（CSDN <https://blog.csdn.net/weixin_43486981/article/details/108057934>）。另有独立"工具"页（"看看 CTFer 都在用什么"）。
- **CTF-Wiki Misc 目录**（<https://ctf-wiki.org/misc/introduction/>）：`杂项简介 / 信息搜集技术 / 编码分析（通信/计算机/现实编码） / 取证隐写前置技术 / 图片分析（PNG/JPG/GIF）/ 音频隐写 / 流量包分析（PCAP修复/协议分析/数据提取）/ 压缩包分析（ZIP/RAR）/ 磁盘内存分析 / Other（pyc）`。
- **Hello-CTF（ProbiusOfficial）MISC 目录**（<https://hello-ctf.com/contents/>）：`MISC入门 / 信息收集 / 编码扩展 / 文件基础 / 压缩包 / 图片隐写 / 文件隐写 / 音频隐写 / 流量分析 / 工控类 / 内存取证 / 附:文件签名表`。
- **腾讯云《CTF竞赛MISC题型深入解析》**（<https://developer.cloud.tencent.com/article/2588981>）：MISC 分为 隐写术（图像/音频/文本）、取证分析（磁盘/内存/网络）、流量分析、其他杂项（编码转换/压缩包破解/脚本/信息收集/数学谜题）；并给出"初步分析→信息收集→工具选择→深入分析"的解题流程。
- **CTF Tools（ctf-wiki 军火库）Misc 页**（<https://ctf-wiki.github.io/ctf-tools/misc/>）：工具按"图片隐写/压缩包/无线密码"等子类分节。

---

## 二、四问回答

### A. 中文社区 misc 子类的通用分类名与粒度

汇总 CTF-Wiki、Hello-CTF、BUUCTF 题解、CTFHub writeup、腾讯云解析、随波逐流工具自身分组六个来源，社区惯用子类（按出现频率与共识度排序）：

| 社区惯用子类名 | 覆盖内容（粒度） | 出现来源 |
|---|---|---|
| **压缩包** | ZIP/RAR：伪加密、密码爆破、明文攻击、CRC32 碰撞、多层嵌套 | CTF-Wiki、Hello-CTF、CTF Tools、随波逐流（CH15 独立子菜单组 8 项） |
| **图片隐写** | PNG/JPG/GIF：LSB/位平面、宽高（IHDR）篡改、文件尾附加数据、双图运算、盲水印、EXIF/元数据 | CTF-Wiki（按 PNG/JPG/GIF 再细分）、Hello-CTF、腾讯云、随波逐流（CH16 9 个子组） |
| **音频隐写** | 频谱、波形、摩斯、DTMF、LSB、mp3stego | CTF-Wiki、Hello-CTF、腾讯云、随波逐流（音频分析组） |
| **文件基础/文件头与结构** | 文件签名识别、头修复、十六进制查看、嵌入文件（binwalk/foremost）、文件分离 | Hello-CTF（"文件基础"+"文件签名表"附录）、腾讯云、随波逐流（"文件自动探测"） |
| **文本隐写/零宽字符** | 零宽字符、snow 空格隐写、大小写编码 | 腾讯云（文本隐写）、随波逐流（JS:零宽字符 系列） |
| **流量分析** | PCAP 修复、协议分析（HTTP/DNS/USB…）、数据提取、USB 键鼠还原 | CTF-Wiki（专章）、Hello-CTF（专章）、随波逐流（流量分析组） |
| **内存取证/磁盘取证** | Volatility、磁盘镜像、文件恢复 | CTF-Wiki（"磁盘内存分析"）、Hello-CTF（"内存取证"）、腾讯云 |
| **视频与 GIF** | 分帧、帧延迟 | CTF-Wiki（图片分析含 GIF）、随波逐流（GIF/图片转换组） |
| **编码扩展** | 与密码域重叠的编码类 | Hello-CTF、CTF-Wiki（编码分析） |
| **信息收集/OSINT、工控类、文档取证（PDF/Office）** | 边缘子类 | Hello-CTF（信息收集/工控类）、社区文章 |

**粒度结论**：社区通用的是**两级结构（方向 → 子类）**，misc 子类惯用规模 **8~12 个**；粒度以"文件载体"（压缩包/图片/音频/视频）为主轴，"技术手段"（编码/取证/零宽）为辅轴。随波逐流作为工具（而非题库）额外多出一个"**文件自动探测**"组（上传→自动全检），这是工具特有、题库没有的第三种组织维度。

### B. 四种交互范式对比

| 范式 | 实例（证据） | 优点 | 缺点 | 对浏览器工具的适配性 |
|---|---|---|---|---|
| ①题型下拉框→工具列表 | BUUCTF（CTFd 系下拉筛选题目）；CTFCrackTools V4 传统表单 | 极省空间；一次聚焦一类 | 发现性差（看不见没选的类）；切换成本高；类别一多下拉变长列表 | 移动端友好，但适合"题目"不适合"工具"——工具需要被同时总览与收藏 |
| ②侧栏题型树 | 随波逐流左侧功能树（465 项、计数、搜索、收藏★）；CTF-Wiki/Hello-CTF 章节树；CTFHub 技能树 | 全局可见、可折叠、带计数与层级、可挂收藏节点；扩展性最好 | 桌面占宽；条目极多时必须配搜索（随波逐流正是这么做的） | 桌面侧栏 + 移动端收进抽屉（Drawer）/手风琴，Mantine 都有现成组件 |
| ③顶部 Tab | 随波逐流 14 个顶级菜单（Tab 栏）；ctftools-all-in-one 七大类；CTFHub 顶导 | 切换最快、认知负担低 | 类别一多就溢出（随波逐流 14 个已靠分组菜单栏+左侧树分担）；放不下二级结构 | 适合 ≤8 个大域；作为"域级"导航合适，作为"子类级"导航过浅 |
| ④搜索为主+题型过滤 | CyberChef（Operations 搜索即输即过滤 + 分类折叠） | 直达；与收藏/Magic 协同；无层级负担 | 需先知道名字或关键字；新手冷启动难（CyberChef 用 Magic 兜底） | 全设备最均匀；必须配合自动猜测（Magic/一键解码）弥补冷启动 |

**结论**：没有任何一个成功项目采用单一范式——**行业事实标准是"②树/折叠分类 + ④搜索 + 收藏 + 自动猜测"的混合**：CyberChef＝分类折叠列表＋搜索＋Favourites＋Magic；随波逐流＝顶部 Tab（域）＋左侧分类树（计数/搜索/收藏★）＋一键解码（自动识别）。对 Payloader：**域级用顶部 Tab（已有三域），域内子类用"可折叠分类列表/树 + 搜索 + 收藏"，并保留被动探测作为"Magic 等价物"**；移动端把子类树收进抽屉。

### C. "需要文件"与"纯输入"两类工具如何混合呈现

两个极端范式（均有实证）：
- **AperiSolve（上传驱动）**：一切工具皆文件工具，上传后 16 个分析器全跑，按模块出结果+成功/无结果徽章+一键下载。优点零选择成本；缺点只覆盖图像类、纯文本场景（零宽字符、编码）无法进入。
- **CyberChef（输入驱动）**：一切皆输入流（文本可粘贴、文件可拖放），工具是"操作"，可串链。优点文本/文件统一；缺点对"一键全检"类被动需求要手动拼链（Magic 部分弥补）。
- **随波逐流的混合方案（最值得参考）**：主舞台是"输入区/输出区 + 密钥行"（纯输入工具即时可用），文件类工具通过"选择文件"按钮/子窗口 GUI（StegSolve、Hex Viewer）进入；另设独立的"文件自动探测"组承担 AperiSolve 式被动分析。即**同一舞台、两种入口：文本工具点菜单即算，文件工具点菜单后弹文件选择；被动探测另立一个总入口**。

**对 Payloader 的映射**：现有"上传→按探测类型出卡片"＝AperiSolve 范式，保留为主驱动；零宽字符等纯文本工具应**解除文件依赖**（允许未上传时直接粘贴文本使用，入口常驻）；文件类工具在未上传时置灰并提示"选择文件后可用"（点击直接弹文件选择，学随波逐流点菜单即弹选择框，而不是只禁用）。

### D. 空状态设计（未上传文件时题型面板展示什么）

实证：
- **AperiSolve 空状态**＝大拖放框 + 说明文字 + 可选密码/深度分析选项（页面本身就是空状态，无单独"空面板"）。
- **CyberChef** 无文件概念，不存在空状态；新手冷启动靠 Magic + 分类浏览。
- **随波逐流**：文件类工具点击后才弹文件选择框；左侧功能树永远满编可见（含计数），即"空状态也是完整目录状态"。
- **CTFHub 技能树**：每个节点带说明与题目入口（学习型空状态）。

**结论**：空状态不应是空白。推荐三层内容：
1. **工具目录照常展示**（学随波逐流满编树/学 CyberChef 分类列表）——空状态＝浏览状态的延续；
2. 每个工具带一句话说明（学 zardus/ctf-tools 表格的 Category|Tool|Description 粒度），文件类工具标注"需要文件"徽标；
3. 顶部给拖放/选择文件的引导区（学 AperiSolve），并可附"不知道从哪开始？丢进来自动分析"的入口（把被动探测当 Magic 卖点）。

---

## 三、对 Payloader 的具体建议：misc 域"题型→工具"导航

### 3.1 推荐交互（综合结论）

**"被动探测为主、题型面板为辅、搜索+收藏贯穿"的双轨制：**

1. **保留并强化 AperiSolve 式被动主驱动**：上传→探测→按类型出卡片（现状），卡片上加 per-tool **成功/无发现徽章**与一键操作（AperiSolve 的"16 分析器并行+徽章"已被验证为最好的结果可读性方案）。
2. **新增"题型面板"作为主动导航**（弥补被动模式"探测不到的工具永远看不见"的缺陷）：
   - 形态：**可折叠的分类列表（Accordion/侧栏树），桌面常驻左栏、移动端收进抽屉**——不采用"题型下拉框"（范式①发现性差，且 Payloader 是工具不是题库）；
   - 每个分类节点带**工具计数**（学随波逐流 `Base/Rot (43)`）；
   - 顶部一个**搜索框**过滤工具名/别名（中英都索引：如"零宽/zero-width/zwsp"）；
   - 一个**收藏★区**置顶（学 CyberChef Favourites 空分类 + 随波逐流收藏节点）。
3. **空状态**（问 D 结论落地）：未上传时题型面板满编展示目录，每个工具一句话说明 + "需要文件"徽标；纯文本工具直接可用；顶部保留拖放引导+"自动分析"入口。
4. **跨域链接**：压缩包子类里的"流量"条目、以及流量相关条目直接深链到流量域（CTFHub 把工具独立成页、随波逐流把 pcap 放文件菜单内——Payloader 三域架构下用链接优于复制入口）。

### 3.2 misc 子类清单 + 工具映射草案

对齐社区惯用名（问 A 清单），映射 Payloader 现有工具面：

| 子类（社区惯用名） | Payloader 工具映射 | 输入类型 |
|---|---|---|
| **压缩包** | ZIP 密码爆破、CRC32 碰撞、伪加密检测/修复 | 文件 |
| **图片隐写 — 位平面/LSB** | 位平面扫描、zsteg（PNG/BMP LSB） | 文件 |
| **图片隐写 — 结构与几何** | 宽高修复（IHDR/JPG 高度）、PNG chunk 枚举 | 文件 |
| **图片隐写 — 附加数据** | 嵌入扫描（文件尾/FF D9 后附加数据） | 文件 |
| **视频与 GIF** | GIF 解析（分帧/帧信息） | 文件 |
| **音频隐写** | 音频四件套（频谱/波形/摩斯/DTMF） | 文件 |
| **文本隐写** | 零宽字符 | **纯文本**（不依赖文件） |
| **文件基础/通用取证** | 字符串提取、hexdump、嵌入扫描（binwalk 式）、chunk 枚举 | 文件 |
| **流量分析** | （深链至流量域） | — |

粒度说明：控制在 **8~9 个子类**（社区惯用 8~12）；"图片隐写"内部用**三级细分**（位平面/结构几何/附加数据），学 CTF-Wiki 在"图片分析"下按 PNG/JPG/GIF 再细分、随波逐流 CH16 拆 9 个子组的做法，但不必在导航树露出全部三级——用卡片内分组即可。

### 3.3 与现有两域的一致性

- 密码域已是"单舞台：算法下拉+分组菜单栏"＝随波逐流/CyberChef 范式，misc 域的题型面板应**复用其视觉语言**（分组菜单栏的分组名可与子类清单对齐），避免两域两套心智。
- 杂项取证域的双轨（被动卡片 + 主动题型面板）实际等价于随波逐流"文件自动探测 + 文件/图片菜单树"的分工，交互上用户已有先验，学习成本低。

---

## 附：全部来源 URL

- 随波逐流官网首页 <http://1o1o.xyz>；CTF 编码工具产品页 <http://1o1o.xyz/bo_ctfcode.html>；使用说明书 <http://1o1o.xyz/help/%5B%E9%9A%8F%E6%B3%A2%E9%80%90%E6%B5%81%5DCTF%E7%BC%96%E7%A0%81%E5%B7%A5%E5%85%B7_%E4%BD%BF%E7%94%A8%E8%AF%B4%E6%98%8E%E4%B9%A6.html>；截图 <http://1o1o.xyz/img/ctf_code1.jpg>、<http://1o1o.xyz/img/img_ctfcode2.jpg>
- 0Chencc/CTFCrackTools <https://github.com/0Chencc/CTFCrackTools>
- RemusDBD/ctftools-all-in-one <https://github.com/RemusDBD/ctftools-all-in-one>；CSDN 介绍 <https://blog.csdn.net/wyb17870531028/article/details/144870434>
- ProbiusOfficial/CTFtools-wiki <https://github.com/ProbiusOfficial/CTFtools-wiki>
- CyberChef README <https://github.com/gchq/CyberChef>；Categories.json <https://raw.githubusercontent.com/gchq/CyberChef/master/src/core/config/Categories.json>
- zardus/ctf-tools <https://github.com/zardus/ctf-tools>
- AperiSolve 官网 <https://aperisolve.com/>；GitHub <https://github.com/Zeecka/AperiSolve>
- BUUCTF <https://buuoj.cn/challenges>（归档迁移公告实测）；攻防世界介绍（知乎《CTF在线练习场推荐》）
- CTFHub <https://www.ctfhub.com/>；CTFHub 技能树 Misc-数据隐写 writeup <https://blog.csdn.net/weixin_43486981/article/details/108057934>
- CTF-Wiki Misc <https://ctf-wiki.org/misc/introduction/>；CTF Tools Misc <https://ctf-wiki.github.io/ctf-tools/misc/>
- Hello-CTF 目录 <https://hello-ctf.com/contents/>
- 腾讯云《CTF竞赛MISC题型深入解析》 <https://developer.cloud.tencent.com/article/2588981>
