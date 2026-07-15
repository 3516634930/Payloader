import { spawnSync } from 'node:child_process';

const steps = [
  'verify:attribution',
  'typecheck',
  'lint',
  'verify:codec',
  'verify:curation',
  'verify:content',
  'test',
  'build',
];

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error('Run the quality gate through `npm run check`.');
  process.exit(1);
}

for (const step of steps) {
  console.log(`\n==> npm run ${step}`);
  const result = spawnSync(process.execPath, [npmCli, 'run', step], {
    cwd: process.cwd(),
    env: process.env,
    stdio: 'inherit',
  });

  if (result.error) {
    console.error(`Unable to start quality step ${step}:`, result.error.message);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
