import assert from 'node:assert/strict';
import test from 'node:test';

import { validateClientReleaseContext } from '../scripts/validate-client-release-context.mjs';

const commit = 'a'.repeat(40);

test('client release context accepts one immutable semantic version tag', () => {
  assert.deepEqual(validateClientReleaseContext({
    releaseTag: 'v2.0.0',
    packageVersion: '2.0.0',
    headCommit: commit,
    tagCommit: commit.toUpperCase(),
  }), {
    releaseTag: 'v2.0.0',
    packageVersion: '2.0.0',
    commitSha: commit,
  });
});

test('client release context rejects invalid, mismatched, or stale tags', () => {
  assert.throws(() => validateClientReleaseContext({
    releaseTag: 'latest',
    packageVersion: '2.0.0',
    headCommit: commit,
    tagCommit: commit,
  }), /semantic v\* tag/);
  assert.throws(() => validateClientReleaseContext({
    releaseTag: 'v9.9.9',
    packageVersion: '2.0.0',
    headCommit: commit,
    tagCommit: commit,
  }), /does not match package version/);
  assert.throws(() => validateClientReleaseContext({
    releaseTag: 'v2.0.0',
    packageVersion: '2.0.0',
    headCommit: commit,
    tagCommit: 'b'.repeat(40),
  }), /does not match v2\.0\.0 commit/);
  assert.throws(() => validateClientReleaseContext({
    releaseTag: 'v2.0.0',
    packageVersion: '2.0.0',
    headCommit: 'short',
    tagCommit: commit,
  }), /Invalid HEAD commit SHA/);
});
