import { readdir, readFile } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { officialProjectUrl } from '../server/project-attribution.mjs';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const expectedTarget = Buffer.from([
  104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99,
  111, 109, 47, 51, 53, 49, 54, 54, 51, 52, 57, 51, 48, 47, 80, 97,
  121, 108, 111, 97, 100, 101, 114,
]);
const runtimeFiles = [
  'server/project-attribution.cjs',
  'server/project-attribution.mjs',
  'server/data-store.mjs',
  'server/admin-server.mjs',
  'server/client-builder.mjs',
  'server/client-electron-main.cjs',
  'server/default-seed.sqlite',
  'src/data/publicData.ts',
];
const scannableDistExtensions = new Set(['.html', '.js', '.json', '.map', '.txt']);

const collectDistFiles = async directory => {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async entry => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return collectDistFiles(path);
    return scannableDistExtensions.has(extname(entry.name).toLowerCase()) ? [path] : [];
  }));
  return nested.flat();
};

const assertNoPlaintextTarget = async files => {
  const findings = [];
  for (const file of files) {
    const content = await readFile(file);
    if (content.includes(expectedTarget)) findings.push(file);
  }
  if (findings.length) {
    throw new Error(`Project attribution plaintext detected in: ${findings.join(', ')}`);
  }
};

export const verifyProjectAttribution = async ({ includeDist = false } = {}) => {
  if (Buffer.from(officialProjectUrl, 'utf8').compare(expectedTarget) !== 0) {
    throw new Error('Payloader project attribution integrity check failed.');
  }
  const files = runtimeFiles.map(file => join(rootDir, file));
  if (includeDist) files.push(...await collectDistFiles(join(rootDir, 'dist')));
  await assertNoPlaintextTarget(files);
  return { checked: files.length, includeDist };
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  const result = await verifyProjectAttribution({ includeDist: process.argv.includes('--dist') });
  console.log(`Project attribution protection: PASS (${result.checked} files)`);
}
