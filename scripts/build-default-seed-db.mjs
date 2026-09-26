import {
  getDefaultSeedDbFile,
  getRuntimeDbFile,
  loadContentDataFromDatabase,
  loadDefaultDataFromSeedDb,
  writeDefaultSeedDatabase,
} from '../server/data-store.mjs';

const args = new Set(process.argv.slice(2));
const seedPath = getDefaultSeedDbFile();

const source = (() => {
  if (args.has('--from-runtime-db')) {
    return {
      label: `runtime DB (${getRuntimeDbFile()})`,
      load: () => loadContentDataFromDatabase(getRuntimeDbFile()),
      cleanup: async () => {},
    };
  }
  // --from-legacy-src-data 已退役：legacy 源文件（webPayloads/intranetPayloads/toolCommands）
  // 与 DB 内容长期脱钩（源 305 卡 vs DB 632 卡），运行内容唯一权威是 DB（管理员后台可编辑），
  // 用旧硬编码源重建 seed 会静默回退全部治理成果。
  if (args.has('--from-legacy-src-data')) {
    throw new Error('--from-legacy-src-data is retired: content authority lives in the databases (admin-editable). Use --from-runtime-db or the default seed-DB mode.');
  }
  return {
    label: `existing seed DB (${seedPath})`,
    load: () => loadDefaultDataFromSeedDb(seedPath),
    cleanup: async () => {},
  };
})();

const seedData = await source.load();
const seedFile = await writeDefaultSeedDatabase(seedData, seedPath, source.label);

// Optionally apply content optimizations (structure, translations, labels)
if (args.has('--with-optimize')) {
  const { optimizePayloadDatabases } = await import('./optimize-payload-content.mjs');
  const doDeWeaponize = args.has('--with-deweaponize');
  const [optimization] = await optimizePayloadDatabases({
    files: [seedFile],
    backup: false,
    skipDeWeaponize: !doDeWeaponize,
  });
  console.log(`Payload optimizations applied: ${optimization?.changed ?? 0}`);
}

await source.cleanup();

console.log(`Default seed DB written: ${seedFile}`);
console.log(`Source: ${source.label}`);
console.log(`Payloads: ${seedData.payloads.length}`);
console.log(`Tools: ${seedData.tools.length}`);
console.log(`Payload navigation roots: ${seedData.navigation.length}`);
console.log(`Tool navigation roots: ${seedData.toolNavigation.length}`);
console.log(`Configured seed path: ${seedPath}`);
