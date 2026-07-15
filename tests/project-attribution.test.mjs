import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

const read = relativePath => readFile(new URL(`../${relativePath}`, import.meta.url), 'utf8');
const expectedTarget = Buffer.from([
  104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99,
  111, 109, 47, 51, 53, 49, 54, 54, 51, 52, 57, 51, 48, 47, 80, 97,
  121, 108, 111, 97, 100, 101, 114,
]).toString('utf8');

test('runtime source and renderer data use only opaque project routes', async () => {
  const sources = await Promise.all([
    'server/project-attribution.cjs',
    'server/project-attribution.mjs',
    'server/data-store.mjs',
    'server/admin-server.mjs',
    'server/client-builder.mjs',
    'server/client-electron-main.cjs',
    'src/data/publicData.ts',
  ].map(read));

  for (const source of sources) assert.ok(!source.includes(expectedTarget));
  assert.match(sources[2], /publicProjectRoute/);
  assert.match(sources[3], /officialProjectUrl/);
  assert.match(sources[4], /clientProjectRoute/);
  assert.match(sources[5], /clientProjectRoute/);
  assert.match(sources[6], /publicProjectRoute/);
});

test('encrypted project attribution resolves only the fixed target', async () => {
  const attribution = await import(`../server/project-attribution.mjs?test=${Date.now()}`);

  assert.equal(attribution.officialProjectUrl, expectedTarget);
  assert.equal(attribution.publicProjectRoute, '/api/r/p');
  assert.equal(attribution.clientProjectRoute, 'payloader://project');
});

test('tampering with encrypted project attribution stops module evaluation', async t => {
  const source = await read('server/project-attribution.cjs');
  const match = source.match(/const encryptedTarget = '([^']+)'/);
  assert.ok(match?.[1]);
  const replacement = `${match[1][0] === 'A' ? 'B' : 'A'}${match[1].slice(1)}`;
  const tamperedSource = source.replace(match[1], replacement);
  const tempDir = await mkdtemp(join(tmpdir(), 'payloader-project-attribution-'));
  const tamperedModule = join(tempDir, 'project-attribution.cjs');
  t.after(() => rm(tempDir, { recursive: true, force: true }));
  await writeFile(tamperedModule, tamperedSource, 'utf8');

  await assert.rejects(
    import(`${pathToFileURL(tamperedModule).href}?tampered=${Date.now()}`),
    /Payloader project attribution integrity check failed/,
  );
});
