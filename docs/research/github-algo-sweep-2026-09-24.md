# GitHub CTF 算法级 sweep（2026-09-24，主控会话调研②）

> 服务于"CTF 解题能力增强"任务（进行中）；与 ctf-tools-landscape-2026-09.md（工具全景）互补，本篇是**算法级可移植性**结论。

## 可移植算法源（许可证 ✓）

**RsaCtfTool（★7.1k，MIT，活跃）**——纯数论可直译 JS（不依赖 sage）：
- `lib/algos.py`：wiener（连分数）/fermat/pollard_rho/pollard_P_1/hart/lehman/SQUFOF/dixon/quadratic_sieve/solve_partial_q（dp/dq 泄露）/williams_pp1
- `lib/number_theory.py`：gmpy2 纯 Python 等价层（gcdext/isqrt/iroot/miller_rabin/next_prime/eratosthenes）——JS BigInt 底座逐函数直译
- `multi_keys/`：common_factors（共因子 GCD）/common_modulus_related_message（gcdext 版）/hastads/same_n_huge_e
- 每个攻击类自带 test() 测试向量 → 直接抽成 JS 回归
- 仅思路借鉴（需 sage/重格归约）：boneh_durfee/small_crt_exp/smallfraction/lattice

**Crypton（MIT）**：franklin-reiter 纯 Python 多项式 GCD（m2=a·m1+b）可直译。

**Padding-oracle-attack（mpgn，MIT）**：单文件 block_search_byte 倒序逐字节枚举，oracle 为回调 → 浏览器版可接演示服务器。PadBuster（Perl）同思路。

**CyberChef Magic.mjs（Apache-2.0，已读源码 1122 行）**：detectLanguage（40 语言字节频率 chi-squared）+ calcEntropy + findMatchingInputOps（entropyRange+正则初筛）+ speculativeExecution 递归链 + 结果剪枝排序 + intensive 前 100 字节暴力。语言频率表+评分器纯 JS 直译。

**binwalk（MIT）v3 magic.rs**：111 条签名带 parser/extractor；我们 30 种，补 squashfs/LZMA/xz/7z/JFFS2/UBI/cramfs/DER 到 ~60。

## 思路借鉴（无 license，算法自写）

- **xortool**：①key 长度=按候选长度分列统计等值字节占比；②key=每列最频字节 XOR most-common-char（文本 0x20/二进制 0x00）。100 行内 JS 复刻。
- **zsteg**：order×channels×bits×lsb/msb 组合扫描 + zlib/OpenStego 检出；`-a` 默认 256 字节 limit。StegOnline（纯浏览器 StegSolve 移植）取位逻辑可参考。
- **quipqiup 等价**：本体闭源（Edwin Olson 论文）；theikkila SA-solver（模拟退火+trigram）思路 → quadgram 表+shotgun hill-climbing 自写。
- **Vigenère 自动破译**：Kasiski+IC 定长 + 每列 chi-squared 出 key（教科书管线自写）。
- **ZIP CRC32 4 字节冲突爆破**：95⁴≈81M Web Worker；bkcrack（Biham-Kocher 明文攻击）C++ 移植成本高列长期。
- **cyclic 对齐 pwntools**：de Bruijn 输出逐字节比对。

## Top 15 缺口（BUUCTF/XCTF 实战频次序）

1. RSA 共模/related-message（抄 number_theory.common_modulus_related_message）
2. Wiener 连分数（algos.wiener，自带 PEM 向量）
3. dp/dq 泄露 partial q（algos.solve_partial_q）
4. Fermat 相近分解 + 小素数试除（fermat/smallq）
5. Hastad 小 e 未填充（multi_keys/hastads，e=3 经典向量）
6. 多密钥共因子 GCD（common_factors）
7. BigInt 数论底座（gmpy2 等价层：iroot/gcdext/invert/isprime/nextprime/连分数）
8. 多字节重复密钥 XOR 自动破译（xortool 思路）
9. Padding oracle 真攻击（mpgn block_search_byte）
10. 替换密码自动求解（quadgram+爬山，cryptogram 通过率>80% 验收）
11. Vigenère 自动破译（Kasiski+IC+chi-squared）
12. 编码自动识别 Magic 等价（chi-squared 语言评分+递归链，与 CyberChef top1 对拍）
13. zsteg 式位平面全组合扫描（已知 LSB 样图必中）
14. ZIP CRC32 冲突爆破 + 伪加密一键（自造题回环）
15. cyclic 完整功能面（自定义字母表，与 pwntools 逐字节比对）

长期项：Coppersmith/LLL、bkcrack 明文攻击、capstone.js ROP（均需 WASM/大工程）。

结论：2024-2026 新星全是 AI Agent 方向，算法无新意——"零依赖本地跑"路线本身正确。
