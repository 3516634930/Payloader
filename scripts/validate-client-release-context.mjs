import { execFileSync } from 'node:child_process';
import { appendFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const rootDir = resolve(fileURLToPath(new URL('..', import.meta.url)));
const releaseTagPattern = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const commitPattern = /^[0-9a-f]{40}$/i;

const normalizeCommit = (value, label) => {
  const commit = String(value || '').trim();
  if (!commitPattern.test(commit)) throw new Error(`Invalid ${label} commit SHA.`);
  return commit.toLowerCase();
};

export const validateClientReleaseContext = ({
  releaseTag,
  packageVersion,
  headCommit,
  tagCommit,
}) => {
  const tag = String(releaseTag || '').trim();
  const version = String(packageVersion || '').trim();
  if (!releaseTagPattern.test(tag)) throw new Error('Release tag must be a semantic v* tag.');
  if (tag !== `v${version}`) {
    throw new Error(`Release tag ${tag} does not match package version ${version}.`);
  }
  const head = normalizeCommit(headCommit, 'HEAD');
  const tagged = normalizeCommit(tagCommit, 'tag');
  if (head !== tagged) throw new Error(`Checked out commit ${head} does not match ${tag} commit ${tagged}.`);
  return { releaseTag: tag, packageVersion: version, commitSha: head };
};

const git = args => execFileSync('git', args, { cwd: rootDir, encoding: 'utf8' }).trim();

const main = async () => {
  const releaseTag = String(process.argv[2] || process.env.RELEASE_TAG || '').trim();
  const packageJson = JSON.parse(await readFile(resolve(rootDir, 'package.json'), 'utf8'));
  const result = validateClientReleaseContext({
    releaseTag,
    packageVersion: packageJson.version,
    headCommit: git(['rev-parse', 'HEAD']),
    tagCommit: git(['rev-list', '-n', '1', releaseTag]),
  });
  const output = [
    `release_tag=${result.releaseTag}`,
    `package_version=${result.packageVersion}`,
    `commit_sha=${result.commitSha}`,
  ].join('\n');
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `${output}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify(result)}\n`);
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) await main();
