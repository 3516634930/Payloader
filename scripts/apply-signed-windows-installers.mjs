import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { nativePackageName } from './build-client-shells.mjs';
import { validateWindowsSigningMetadata } from './build-windows-signing-stages.mjs';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const signingMetadataFile = 'windows-signing-input.json';

const walkFiles = async root => {
  const files = [];
  const directories = [root];
  for (let index = 0; index < directories.length; index += 1) {
    for (const entry of await readdir(directories[index], { withFileTypes: true })) {
      const entryPath = join(directories[index], entry.name);
      if (entry.isDirectory()) directories.push(entryPath);
      else if (entry.isFile()) files.push(entryPath);
    }
  }
  return files;
};

export const findUniqueFileByName = async (root, name) => {
  const matches = (await walkFiles(root)).filter(file => file.endsWith(`\\${name}`) || file.endsWith(`/${name}`));
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one signed installer named ${name}, found ${matches.length}.`);
  }
  return matches[0];
};

export const windowsInstallerNames = metadata => validateWindowsSigningMetadata(metadata).targets
  .map(target => nativePackageName(target.id, metadata.appVersion));

const hashFile = filePath => new Promise((resolveHash, rejectHash) => {
  const hash = createHash('sha256');
  const input = createReadStream(filePath);
  input.on('data', chunk => hash.update(chunk));
  input.on('error', rejectHash);
  input.on('end', () => resolveHash(hash.digest('hex')));
});

const main = async () => {
  const signedInputValue = String(process.env.PAYLOADER_WINDOWS_SIGNED_INSTALLER_DIR || '').trim();
  if (!signedInputValue) throw new Error('PAYLOADER_WINDOWS_SIGNED_INSTALLER_DIR is required.');
  const signedInput = resolve(signedInputValue);
  const outputDirectory = resolve(
    process.env.PAYLOADER_CLIENT_SHELL_OUTPUT_DIR || join(rootDir, 'artifacts', 'client-shells'),
  );
  if (signedInput === outputDirectory) throw new Error('Signed installer input must be separate from release output.');
  const metadata = validateWindowsSigningMetadata(JSON.parse(
    await readFile(join(outputDirectory, signingMetadataFile), 'utf8'),
  ));
  await mkdir(outputDirectory, { recursive: true });

  const applied = [];
  for (const name of windowsInstallerNames(metadata)) {
    const source = await findUniqueFileByName(signedInput, name);
    const sourceStats = await stat(source);
    if (!sourceStats.isFile() || sourceStats.size <= 0) throw new Error(`Signed installer is empty: ${name}`);
    const destination = join(outputDirectory, name);
    const temporary = `${destination}.tmp-${randomUUID()}`;
    try {
      await copyFile(source, temporary);
      await rename(temporary, destination);
    } finally {
      await rm(temporary, { force: true }).catch(() => {});
    }
    const sha256 = await hashFile(destination);
    await writeFile(join(outputDirectory, `${name}.sha256.txt`), `${sha256}  ${name}\n`, 'utf8');
    applied.push({ name, size: sourceStats.size, sha256 });
  }
  await writeFile(
    join(outputDirectory, 'windows-signing-complete.json'),
    `${JSON.stringify({ version: 1, appVersion: metadata.appVersion, installers: applied }, null, 2)}\n`,
    'utf8',
  );
  process.stdout.write(`${applied.length} signed Windows installers applied.\n`);
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) await main();
