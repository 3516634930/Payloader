# 技术债账本

偿还触发：①下次改动碰到同一模块顺手偿还；②被绕过 ≥3 次升级优先；③成为 bug/安全根因立即偿还；④里程碑盘点 P0/P1 排下一期。

## 技术债

- [ ] TD-001 | 如是我闻（佛曰 V2）完整解码需 LZMA/LZMA2 解压：当前只支持 zip-store/7z-Copy 条目直取，LZMA 条目输出容器 hex 供本地 7-Zip 接手 | 发现于 2026-09-22 批次 K | 影响 `src/utils/codec/chineseCiphers.ts` buddhaV2Decode | 建议修法：引入 ~100-200KB LZMA wasm（如 lzma-wasm）并走 7z 完整头解析 | P2
- [ ] TD-002 | pcmoe「新佛曰」（新约佛论禅）算法闭源无公开实现，仅做前缀识别与闭源提示，无法解码 | 发现于 2026-09-22 批次 K | 影响 smartDecode pcmoe 提示分支 | 建议修法：等待社区逆向（服务端 bear.php 已随站点下线，预期无解） | P3
- [ ] TD-003 | ZIP 加密标志检测为全文件逐字节扫 PK 签名：压缩数据巧合含 PK\x03\x04/PK\x01\x02 字节串时可误判/误清位（仅 zip 族文件触发，概率低） | 发现于 2026-09-22 批次 K（复核 P3-4）| 影响 `src/utils/ctf/fileDetect.ts` detectZipEncryption/fixZipPseudoEncryption | 建议修法：改为先定位 EOCD 再按中心目录 offset 结构化遍历 | P3
- [ ] TD-004 | pcap 首包记录头被截断时解析得到"健康 0 包"，无损坏/截断提示（中后段截断有提示，首记录缺口） | 发现于 2026-09-22 批次 L（reviewer P2） | 影响 `src/utils/ctf/pcap/parser.ts` 记录循环头部 | 建议修法：循环退出时区分"字节不足一条记录头"分支并输出截断标记 | P2
- [ ] TD-005 | 流重组/body 限量常量（MAX_STREAM_BYTES 等）无直接单测覆盖，仅经组件行为间接触达 | 发现于 2026-09-22 批次 L（reviewer P2） | 影响 `tests/pcap-analysis.test.mjs` | 建议修法：补 2 个构造超限样本的断言（超限截断标记 + 已解析部分可用） | P2
- [ ] TD-006 | 速查工具跳转未命中（id 不在运行库）时静默返回，无用户反馈；契约测试只护种子库，不护线上库漂移 | 发现于 2026-09-22 批次 M（reviewer P2） | 影响 `src/components/ctf/CheatsheetWorkspace.tsx` openEntry | 建议修法：未命中时 notifications 提示"条目不存在，可能已被策展合并"；测试可加可选的运行库对照 | P2
- [ ] TD-007 | handleFileSelected 在 await 读取头部后读取闭包 activeModuleId，极端时序下路由到过期域（理论竞态，实测未复现） | 发现于 2026-09-22 批次 L（reviewer P2） | 影响 `src/components/CtfToolkit.tsx` | 建议修法：路由判定改为读 activeModuleIdRef 或放在 await 之前 | P3
- [ ] TD-008 | TrafficWorkspace 单文件 500+ 行且 pw-* 主题样式在 4 个流量组件中重复定义（代码库既有"样式随组件"惯例的代价） | 发现于 2026-09-22 批次 L（reviewer P2） | 影响 `src/components/ctf/traffic/*.tsx` | 建议修法：下轮 UI 打磨批次提取共享样式模块或迁 Mantine 组件 | P3

## 技术债（批次 O 附带盘点）
- [ ] TD-批次O-1 | verify:codec bifid 无密钥破译块（scripts/verify-encoding-tools.mjs ≈:2294）为模拟退火概率性测试，偶发首跑失败、复跑即绿 | 发现于 2026-09-22 批次 O 全量门禁 | 影响 CI 稳定性（非本批次成因，隔离复现确认） | 建议修法：钉随机种子或降低断言严格度 | 优先级 P2
