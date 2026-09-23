# 归档：一次性内容批次脚本（2026-09 归档）

本目录存放已完成历史使命的一次性脚本与数据残留（约 2026-09 归档，共 35 个文件）：

- `enrich-*` / `add-*` / `append-*` / `apply-dict-*` / `fix-*` / `update-*`：对 `scripts/legacy-seed/*.ts`（原 `src/data/`）与种子库做正则手术的内容富化脚本，对应批次已完成。
- `translate-*` / `trans-batch*.json` / `translations.json`：一次性翻译批次，**注意其中两个脚本含硬编码绝对路径（`C:/Users/Hezihao/Desktop/...`），换机即坏，仅作历史参考**。
- `audit-payload-data.mjs`：内容质量规则的旧实现，已被 `verify-content-quality.mjs`（npm run verify:content）取代；现行权威规则在 `payload-editorial-review.mjs`。
- `generate-cloud-workflow-curation.mjs`：一次性评审稿生成。

**不要在本目录新增或执行脚本**。仍在役的常驻门禁/构建脚本全部在 `scripts/` 顶层。需要找回历史版本走 git 历史。
