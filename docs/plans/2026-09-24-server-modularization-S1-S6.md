# S3 拆分计划：migrations + import-export + upsert/mergeDefaultItems 归一

日期：2026-09-24 ｜ 状态：执行中 ｜ 前置：S1(7fc13c7) S2(9ce97bc) 已提交

## 目标文件结构

- `server/migrations.mjs`（内容治理层，底层）：可见性常量（excludedPublic*/payloadVisibilityRules/payloadRefAliases/modeOnly*/jwt*/i18n/publicNavigationNameOverrides/businessLogicPayloadIds/legacyNavigationPayloadRefMigrations/ensureBusiness|JwtSecurityNavigation）、system 保护（isSystemToolId/isSystemNavigationNodeId/navigationTouchesSystemItem/pruneSystemNavigationItem/protectedSystemTool*/withProtectedSystemTools/withProtectedSystemToolNavigation/isXeyeEnabled/xeyeDisabledMetadataKey）、剪枝（isPublicPayloadCandidate/filterToolNavigation/filterStoredPayloadNavigation/prepareStoredPublicPayloadData/findById/shouldExcludePayload/shouldExcludePayloadNavigationItem/prunePayloadNavigation/patchLegacyNavigationPayloadRefs）、插入与 upsert（prepareContentItemForInsert/insertPayloads/insertTools/insertNavigation/insertNavigationKind/replaceContentData/**归一后 upsertItems(database, resource, items, {trusted, kind})**）、种子读写（curateSeedData/loadContentDataFromDatabase/ensureSeedDatabaseMetadata/loadDefaultDataFromSeedDb/initializeContentDatabase/writeDefaultSeedDatabase，**file 必填参数化，不设 env 默认值**）、迁移（mergeDefaultNavigationItem/restoreAllPayloadPublicData/mergeDefaultToolNavigationItem/migrateMissingDefaultTools/shouldUpgrade|migrateBusinessLogic|Jwt/normalizePayloadContentPresentation/migratePayloadContentPresentation/seedIncludedMigrationKeys/applyDataMigrations(database,{loadDefaults})/seedIfNeeded(database,{loadDefaults})/**新帮手 mergeDefaultItems(database, table, defaults, {shouldReplace})**）
- `server/import-export.mjs`：reset 全家（validateResetTarget..createResetBackup，backupDir/storeTestHooks 参数注入）、import 全家（uniqueItems/readImportArray/assertNavigationImportShape/normalizeImportPackage/demoPlaceholder 三件）、getResetImpact/createDataExportPackage/resetDefaultData/previewImportPackage/importDataPackage（壳接受 {getDb, enqueueMutation, loadDefaultData, backupDir, beforeResetBackup, getPublicData} 依赖对象工厂或参数注入）
- `server/data-store.mjs`（~600-900 行引擎+门面）：db 生命周期/enqueueMutation/metadata/缓存桥/CRUD 写壳（保持 withCacheInvalidation+enqueueMutation+getDb 于引擎）/routeResource/tableForResource/全部 36 导出 re-export

## 语义红线（验收时逐条对照）

1. upsert 冲突**保留 sort_order**（payloads/tools）；navigation 冲突**更新 kind**
2. enqueueMutation 串行队列留引擎、唯一写入口（子模块不自行包装）
3. 子模块顶层不读 PAYLOADER_DATA_DIR（file/backupDir/db 句柄全参数注入）
4. saveAdminItem/saveNavigationItem 内联 upsert 改单元素调用；saveAdminItem 用 trusted:true（原不再 sanitize）；import/custom 路径保持再 sanitize（原行为）
5. mergeDefaultItems 收敛 4 处循环：restoreAll(无 replace)/missingTools(无 replace)/businessLogic(shouldUpgradeBusinessLogic)/jwt(shouldUpgradeJwt)；插入序与 sort_order 递增行为不变
6. 项目归因：不透明路由断言文件清单若受影响需同步

## 执行步骤

- [ ] A1 生成 migrations.mjs（行级提取 + upsert 归一 + mergeDefaultItems 帮手改造）
- [ ] A2 data-store 改壳 + 跑 content-quality/payload-curation/data-safety/core-tool-migrations
- [ ] B1 生成 import-export.mjs（依赖注入改造）
- [ ] B2 data-store 改壳 + 跑 data-safety/api-smoke + 全量
- [ ] 每步 lint + node --check；完成后 commit

## 验收门

npm test 全量 + verify:content + core-tool-migrations；data-store.mjs ≤ ~900 行（引擎+门面）
