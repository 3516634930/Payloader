import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyProjectAttribution } from './verify-project-attribution.mjs';

const localModule = relativePath => fileURLToPath(new URL(`../node_modules/${relativePath}`, import.meta.url));
const commands = [
  [localModule('typescript/bin/tsc'), ['-b']],
  [localModule('vite/bin/vite.js'), ['build']],
];

await verifyProjectAttribution();

for (const [entrypoint, args] of commands) {
  const result = spawnSync(process.execPath, [entrypoint, ...args], {
    cwd: process.cwd(),
    env: process.env,
    stdio: 'inherit',
  });

  if (result.error) {
    console.error(`Unable to start ${entrypoint}:`, result.error.message);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

await verifyProjectAttribution({ includeDist: true });
