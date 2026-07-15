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
  if (args.has('--from-legacy-src-data')) {
    return {
      label: 'legacy src/data TypeScript seed source',
      load: async () => {
        const { loadDefaultDataFromSource } = await import('./default-seed-source.mjs');
        return loadDefaultDataFromSource();
      },
      cleanup: async () => {
        const { cleanupSeedCache } = await import('./default-seed-source.mjs');
        await cleanupSeedCache();
      },
    };
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
