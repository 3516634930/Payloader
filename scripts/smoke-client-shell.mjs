import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { t as listTar, x as extractTar } from 'tar';

import {
  validateClientShellManifest,
  validateShellArchiveEntry,
} from '../server/client-shells.mjs';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const outputDirectory = resolve(
  process.env.PAYLOADER_CLIENT_SHELL_OUTPUT_DIR || join(rootDir, 'artifacts', 'client-shells'),
);
const platformName = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
const nativeTargets = Object.freeze({
  'win32:x64': 'win-x64-nsis',
  'win32:arm64': 'win-arm64-nsis',
  'win32:ia32': 'win-ia32-nsis',
  'linux:x64': 'linux-x64-appimage',
  'linux:arm64': 'linux-arm64-appimage',
  'linux:arm': 'linux-armv7l-appimage',
  'darwin:x64': 'mac-x64-dmg',
  'darwin:arm64': 'mac-arm64-dmg',
});

const hashFile = filePath => new Promise((resolveHash, rejectHash) => {
  const hash = createHash('sha256');
  const input = createReadStream(filePath);
  input.on('data', chunk => hash.update(chunk));
  input.on('error', rejectHash);
  input.on('end', () => resolveHash(hash.digest('hex')));
});

const run = (command, args, options = {}) => new Promise((resolveRun, rejectRun) => {
  const child = spawn(command, args, {
    cwd: rootDir,
    stdio: 'inherit',
    windowsHide: true,
    ...options,
  });
  child.on('error', rejectRun);
  child.on('exit', code => code === 0
    ? resolveRun()
    : rejectRun(new Error(`${command} exited with code ${code}`)));
});

const findMacExecutable = async extractedRoot => {
  const queue = [{ directory: extractedRoot, depth: 0 }];
  const matches = [];
  for (let index = 0; index < queue.length; index += 1) {
    const current = queue[index];
    for (const entry of await readdir(current.directory, { withFileTypes: true })) {
      const target = join(current.directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isFile() && entry.name === 'Payloader' && current.directory.endsWith(join('Contents', 'MacOS'))) {
        matches.push(target);
      } else if (entry.isDirectory() && current.depth < 5) {
        queue.push({ directory: target, depth: current.depth + 1 });
      }
    }
  }
  if (matches.length !== 1) throw new Error(`Expected one native macOS executable, found ${matches.length}.`);
  return matches[0];
};

const targetId = nativeTargets[`${process.platform}:${process.arch}`];
if (!targetId) throw new Error(`No native shell smoke target for ${process.platform}/${process.arch}.`);

const manifestFile = join(outputDirectory, `payloader-client-shells-${platformName}.json`);
const manifest = validateClientShellManifest(JSON.parse(await readFile(manifestFile, 'utf8')));
const descriptor = manifest.targets[targetId];
if (!descriptor) throw new Error(`Native client shell target is missing: ${targetId}.`);

const archivePath = join(outputDirectory, descriptor.archive);
const archiveStats = await stat(archivePath);
if (!archiveStats.isFile() || archiveStats.size !== descriptor.size) {
  throw new Error(`Native client shell archive size mismatch: ${targetId}.`);
}
if (await hashFile(archivePath) !== descriptor.sha256) {
  throw new Error(`Native client shell archive hash mismatch: ${targetId}.`);
}

const workDirectory = await mkdtemp(join(tmpdir(), 'payloader-client-shell-smoke-'));
try {
  await listTar({
    file: archivePath,
    strict: true,
    onentry: validateShellArchiveEntry,
  });
  await extractTar({
    file: archivePath,
    cwd: workDirectory,
    strict: true,
    preservePaths: false,
  });
  const executable = platformName === 'macos'
    ? await findMacExecutable(workDirectory)
    : join(workDirectory, 'Payloader', platformName === 'windows' ? 'Payloader.exe' : 'payloader');
  if (!(await stat(executable).catch(() => null))?.isFile()) {
    throw new Error(`Native client shell executable is missing: ${targetId}.`);
  }
  await run(process.execPath, [join(rootDir, 'scripts', 'smoke-client-performance.mjs')], {
    env: {
      ...process.env,
      PAYLOADER_CLIENT_PERF_EXECUTABLE: executable,
    },
  });
} finally {
  await rm(workDirectory, { recursive: true, force: true }).catch(() => {});
}
