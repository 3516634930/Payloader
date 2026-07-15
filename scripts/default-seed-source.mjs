import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';
import { curateSeedData } from '../server/data-store.mjs';

const rootDir = fileURLToPath(new URL('..', import.meta.url));
const seedDir = join(rootDir, 'data', '.seed-cache');
const makeSeedArtifactId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

const seedEntrypoint = `
import { webPayloads } from '../../src/data/webPayloads.ts';
import { intranetPayloads } from '../../src/data/intranetPayloads.ts';
import { toolCommands } from '../../src/data/toolCommands.ts';
import { navigationData, toolNavigationData } from '../../src/data/navigation.ts';

export const seedData = {
  payloads: [...webPayloads, ...intranetPayloads],
  tools: toolCommands,
  navigation: navigationData,
  toolNavigation: toolNavigationData,
};
`;

const compileSeedData = async () => {
  await mkdir(seedDir, { recursive: true });
  const artifactId = makeSeedArtifactId();
  const sourceFile = join(seedDir, `seed-entry-${artifactId}.ts`);
  const outputFile = join(seedDir, `seed-data-${artifactId}.mjs`);
  await writeFile(sourceFile, seedEntrypoint, 'utf8');
  const files = [
    join(rootDir, 'src/data/webPayloads.ts'),
    join(rootDir, 'src/data/intranetPayloads.ts'),
    join(rootDir, 'src/data/commandCatalogTools.ts'),
    join(rootDir, 'src/data/osToolCommandExtensions.ts'),
    join(rootDir, 'src/data/toolCommands.ts'),
    join(rootDir, 'src/data/navigation.ts'),
    sourceFile,
  ];
  const output = [];
  for (const file of files) {
    const raw = await readFile(file, 'utf8');
    const compiled = ts.transpileModule(raw, {
      compilerOptions: {
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ES2022,
        jsx: ts.JsxEmit.ReactJSX,
        importsNotUsedAsValues: ts.ImportsNotUsedAsValues.Remove,
      },
      fileName: file,
    }).outputText
      .replace(/import\s+type\s+[^;]+;/g, '')
      .replace(/import\s+[^;]+from\s+['"][^'"]+types['"];?\s*/g, '')
      .replace(/export\s+default\s+[A-Za-z0-9_$]+;?\s*/g, '');
    output.push(compiled);
  }
  const bundled = output
    .join('\n')
    .replace(/import\s+\{\s*webPayloads\s*\}\s+from\s+['"][^'"]+webPayloads\.ts['"];?\s*/g, '')
    .replace(/import\s+\{\s*intranetPayloads\s*\}\s+from\s+['"][^'"]+intranetPayloads\.ts['"];?\s*/g, '')
    .replace(/import\s+\{\s*commandCatalogTools\s*\}\s+from\s+['"][^'"]+commandCatalogTools(?:\.ts)?['"];?\s*/g, '')
    .replace(/import\s+\{\s*osToolCommandExtensions\s*\}\s+from\s+['"][^'"]+osToolCommandExtensions(?:\.ts)?['"];?\s*/g, '')
    .replace(/import\s+\{\s*toolCommands\s*\}\s+from\s+['"][^'"]+toolCommands\.ts['"];?\s*/g, '')
    .replace(/import\s+\{\s*navigationData,\s*toolNavigationData\s*\}\s+from\s+['"][^'"]+navigation\.ts['"];?\s*/g, '')
    .replace(/export\s+const\s+webPayloads/g, 'const webPayloads')
    .replace(/export\s+const\s+intranetPayloads/g, 'const intranetPayloads')
    .replace(/export\s+const\s+commandCatalogTools/g, 'const commandCatalogTools')
    .replace(/export\s+const\s+osToolCommandExtensions/g, 'const osToolCommandExtensions')
    .replace(/export\s+const\s+toolCommands/g, 'const toolCommands')
    .replace(/export\s+const\s+navigationData/g, 'const navigationData')
    .replace(/export\s+const\s+toolNavigationData/g, 'const toolNavigationData');
  await writeFile(outputFile, bundled, 'utf8');
  return pathToFileURL(outputFile).href;
};

export const loadRawSeedData = async () => {
  const seedUrl = await compileSeedData();
  const imported = await import(`${seedUrl}?v=${Date.now()}`);
  return imported.seedData;
};

export const loadDefaultDataFromSource = async () => curateSeedData(await loadRawSeedData());

export const cleanupSeedCache = async () => {
  if (existsSync(seedDir)) {
    await rm(seedDir, { recursive: true, force: true });
  }
};
