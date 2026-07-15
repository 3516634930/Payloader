import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const readProjectFile = relativePath => readFile(new URL(`../${relativePath}`, import.meta.url), 'utf8');

test('package exposes one cross-platform production quality gate on supported Node', async () => {
  const [packageSource, qualityRunner, performanceRunner, performanceSmoke, productionBuilder] = await Promise.all([
    readProjectFile('package.json'),
    readProjectFile('scripts/run-quality-gate.mjs'),
    readProjectFile('scripts/run-client-performance-check.mjs'),
    readProjectFile('scripts/smoke-client-performance.mjs'),
    readProjectFile('scripts/run-production-build.mjs'),
  ]);
  const packageJson = JSON.parse(packageSource);
  assert.equal(packageJson.version, '2.0.0');
  assert.equal(typeof packageJson.dependencies?.semver, 'string');
  assert.equal(packageJson.engines?.node, '>=22.13.0');
  assert.match(packageJson.devDependencies?.vite || '', /^\^8\./);
  assert.doesNotMatch(packageJson.devDependencies?.vite || '', /(?:alpha|beta|rc)/i);
  assert.match(packageJson.devDependencies?.['@vitejs/plugin-react'] || '', /^\^(?:5\.(?:[2-9]|\d{2,})|[6-9])\./);
  assert.equal(typeof packageJson.dependencies?.['electron-builder'], 'string');
  assert.equal(typeof packageJson.dependencies?.archiver, 'string');
  assert.equal(typeof packageJson.dependencies?.tar, 'string');
  assert.equal(typeof packageJson.devDependencies?.electron, 'string');
  for (const script of ['typecheck', 'test', 'verify:codec', 'verify:content', 'check']) {
    assert.equal(typeof packageJson.scripts?.[script], 'string', `missing npm script: ${script}`);
  }
  assert.equal(packageJson.scripts.check, 'node scripts/run-quality-gate.mjs');
  assert.equal(packageJson.scripts.build, 'node scripts/run-production-build.mjs');
  assert.equal(packageJson.scripts['verify:attribution'], 'node scripts/verify-project-attribution.mjs');
  assert.equal(
    packageJson.scripts['verify:curation'],
    'node scripts/apply-payload-curation.mjs --require-ready --seed-only',
  );
  assert.equal(packageJson.scripts['verify:client-performance'], 'node scripts/run-client-performance-check.mjs');
  assert.equal(packageJson.scripts['build:client-shells'], 'node scripts/build-client-shells.mjs');
  assert.equal(packageJson.scripts['merge:client-shells'], 'node scripts/merge-client-shell-manifests.mjs');
  assert.equal(packageJson.scripts['verify:client-release-context'], 'node scripts/validate-client-release-context.mjs');
  for (const command of Object.values(packageJson.scripts)) {
    assert.doesNotMatch(command, /&&|\|\|/);
  }
  for (const step of ['verify:attribution', 'typecheck', 'lint', 'verify:codec', 'verify:curation', 'verify:content', 'test', 'build']) {
    assert.match(qualityRunner, new RegExp(`['"]${step.replace(':', '\\:')}['"]`));
  }
  assert.doesNotMatch(qualityRunner, /['"]curate:content['"]/);
  assert.match(qualityRunner, /spawnSync\(process\.execPath/);
  assert.match(performanceRunner, /['"]build['"]/);
  assert.match(performanceRunner, /['"]verify:client-performance:runtime['"]/);
  assert.match(performanceSmoke, /waitForReadyMetrics/);
  assert.match(performanceSmoke, /Number\.isFinite\(metrics\.windowReadyMs\)/);
  assert.match(performanceSmoke, /await new Promise\(resolve => setTimeout\(resolve, 500\)\)/);
  assert.match(performanceSmoke, /process\.platform === 'linux' \? \['--no-sandbox'\] : \[\]/);
  assert.match(performanceSmoke, /process\.platform === 'linux' \? \['--disable-gpu', '--disable-dev-shm-usage'\] : \[\]/);
  assert.match(performanceSmoke, /sharedRunnerPerformancePolicy/);
  assert.match(
    performanceSmoke,
    /sharedRunnerPerformancePolicy[\s\S]*?windows:[\s\S]*?windowReadyMs:\s*5_000[\s\S]*?searchSettledMs:\s*1_000/,
  );
  assert.match(
    performanceSmoke,
    /sharedRunnerPerformancePolicy[\s\S]*?linux:[\s\S]*?windowReadyMs:\s*12_000[\s\S]*?searchSettledMs:\s*750/,
  );
  assert.match(performanceSmoke, /PAYLOADER_CLIENT_PERF_PROFILE/);
  assert.match(performanceSmoke, /hardwareAccelerationEnabled/);
  assert.match(performanceSmoke, /typeof metrics\.hardwareAccelerationEnabled !== ['"]boolean['"]/);
  assert.match(performanceSmoke, /platformKey !== ['"]windows['"] \|\| result\.metrics\.hardwareAccelerationEnabled === false/);
  assert.match(performanceSmoke, /Input\.dispatchMouseEvent/);
  assert.match(performanceSmoke, /document\.activeElement/);
  assert.match(performanceSmoke, /const rendererStateTimeoutMs = performanceProfile === 'shared-runner'/);
  assert.match(performanceSmoke, /smokeResult\.exceptionDetails/);
  assert.match(performanceSmoke, /Renderer performance smoke failed/);
  assert.match(performanceSmoke, /packagedExecutable \? '' : \(await import\('electron'\)\)\.default/);
  assert.doesNotMatch(performanceSmoke, /import electronPath from ['"]electron['"]/);
  assert.match(productionBuilder, /verifyProjectAttribution/);
  assert.match(productionBuilder, /includeDist:\s*true/);
});

test('official client shells use native runners, smoke native archives, and publish one validated release manifest', async () => {
  const [packageSource, workflow, releaseContextValidator, builder, windowsSigningStages, signedInstallerApplier, merger, shellSmoke, shellTransport, clientBuilder, windowsSignatureVerifier, appSigningConfig, installerSigningConfig] = await Promise.all([
    readProjectFile('package.json'),
    readProjectFile('.github/workflows/client-shells.yml'),
    readProjectFile('scripts/validate-client-release-context.mjs'),
    readProjectFile('scripts/build-client-shells.mjs'),
    readProjectFile('scripts/build-windows-signing-stages.mjs'),
    readProjectFile('scripts/apply-signed-windows-installers.mjs'),
    readProjectFile('scripts/merge-client-shell-manifests.mjs'),
    readProjectFile('scripts/smoke-client-shell.mjs'),
    readProjectFile('server/client-shells.mjs'),
    readProjectFile('server/client-builder.mjs'),
    readProjectFile('scripts/verify-windows-authenticode.ps1'),
    readProjectFile('signpath/windows-apps.xml'),
    readProjectFile('signpath/windows-installers.xml'),
  ]);
  const packageJson = JSON.parse(packageSource);
  assert.equal(packageJson.scripts['verify:client-shell'], 'node scripts/smoke-client-shell.mjs');
  assert.equal(packageJson.scripts['build:windows-signing:prepare'], 'node scripts/build-windows-signing-stages.mjs prepare');
  assert.equal(packageJson.scripts['build:windows-signing:finalize'], 'node scripts/build-windows-signing-stages.mjs finalize');
  assert.equal(packageJson.scripts['apply:windows-signing'], 'node scripts/apply-signed-windows-installers.mjs');
  for (const runner of ['windows-latest', 'ubuntu-latest', 'macos-latest']) {
    assert.match(workflow, new RegExp(runner));
  }
  for (const target of [
    'win-x64-nsis',
    'win-arm64-nsis',
    'win-ia32-nsis',
    'linux-x64-appimage',
    'linux-arm64-appimage',
    'linux-armv7l-appimage',
    'mac-x64-dmg',
    'mac-arm64-dmg',
    'mac-universal-dmg',
  ]) {
    assert.match(workflow, new RegExp(target));
  }
  assert.match(workflow, /actions\/upload-artifact@v4/);
  assert.match(workflow, /actions\/download-artifact@v4/);
  assert.match(workflow, /npm run verify:client-shell/);
  assert.match(workflow, /xvfb-run --auto-servernum npm run verify:client-shell/);
  assert.match(workflow, /PAYLOADER_CLIENT_PERF_PROFILE:\s*shared-runner/);
  assert.match(workflow, /Verify Windows Authenticode trust/);
  assert.match(workflow, /verify-windows-authenticode\.ps1/);
  assert.equal((workflow.match(/SignPath\/github-action-submit-signing-request@b9d91eadd323de506c0c81cf0c7fe7438f3360fd/g) || []).length, 2);
  for (const signPathSetting of [
    'SIGNPATH_API_TOKEN',
    'SIGNPATH_ORGANIZATION_ID',
    'SIGNPATH_PROJECT_SLUG',
    'SIGNPATH_SIGNING_POLICY_SLUG',
    'SIGNPATH_APP_ARTIFACT_CONFIGURATION_SLUG',
    'SIGNPATH_INSTALLER_ARTIFACT_CONFIGURATION_SLUG',
  ]) {
    assert.match(workflow, new RegExp(signPathSetting));
  }
  assert.match(workflow, /github-artifact-id:/);
  assert.match(workflow, /build:windows-signing:prepare/);
  assert.match(workflow, /build:windows-signing:finalize/);
  assert.match(workflow, /apply:windows-signing/);
  assert.match(workflow, /PreparedApplicationDirectory/);
  assert.match(workflow, /npm run merge:client-shells/);
  assert.match(workflow, /release_tag:/);
  assert.match(workflow, /publish_unsigned_windows:/);
  assert.match(workflow, /publish_unsigned_windows:[\s\S]*?required:\s*true[\s\S]*?default:\s*false[\s\S]*?type:\s*boolean/);
  assert.match(workflow, /name:\s*Validate immutable release context/);
  assert.match(workflow, /validate-client-release-context\.mjs/);
  assert.match(workflow, /ref:\s*\$\{\{ needs\.release-context\.outputs\.release_tag \}\}/);
  assert.match(workflow, /Build unsigned Windows clients[\s\S]*?inputs\.publish_unsigned_windows[\s\S]*?npm run build:client-shells/);
  assert.match(workflow, /matrix\.platform == 'windows' && !inputs\.publish_unsigned_windows/);
  assert.doesNotMatch(workflow, /push:\s*[\r\n]+\s+tags:/);
  assert.match(releaseContextValidator, /tag !== `v\$\{version\}`/);
  assert.match(releaseContextValidator, /head !== tagged/);
  assert.match(workflow, /GH_REPO:\s*\$\{\{ github\.repository \}\}/);
  assert.match(workflow, /RELEASE_TAG:/);
  assert.match(workflow, /Direct client downloads/);
  assert.match(workflow, /Payloader-Client-Setup-__RELEASE_VERSION__-x64\.exe/);
  assert.match(workflow, /Payloader-Client-__RELEASE_VERSION__-universal\.dmg/);
  assert.match(workflow, /Windows installers in this release are unsigned/);
  assert.match(workflow, /Windows installers are Authenticode-signed/);
  assert.match(workflow, /sha256sum -c SHA256SUMS\.txt/);
  assert.match(workflow, /Release asset set mismatch/);
  assert.match(workflow, /gh release edit "\$RELEASE_TAG" --notes-file/);
  assert.match(workflow, /gh release upload "\$RELEASE_TAG"/);
  assert.match(workflow, /name:\s*Merge and verify release assets[\s\S]*?timeout-minutes:\s*45/);
  assert.match(workflow, /name:\s*Publish client Release[\s\S]*?timeout-minutes:\s*60/);
  assert.ok((workflow.match(/compression-level:\s*0/g) || []).length >= 4);
  assert.match(workflow, /<<'RELEASE_NOTES'/);
  assert.doesNotMatch(workflow, /<<EOF/);
  assert.doesNotMatch(workflow, /`SHA256SUMS\.txt`/);
  assert.match(workflow, /## __RELEASE_VERSION__ 相比 1\.0\.0/);
  assert.doesNotMatch(workflow, /## 2\.0\.0 相比 1\.0\.0/);
  assert.match(workflow, /gh release create[^\n]*--draft/);
  assert.match(workflow, /isDraft/);
  assert.match(workflow, /Refusing to overwrite a published Release/);
  assert.match(workflow, /gh release edit[^\n]*--draft=false/);
  for (const releaseAssetPattern of [
    'Payloader-Client-Setup-*.exe',
    'Payloader-Client-*.AppImage',
    'Payloader-Client-*.dmg',
    'payloader-shell-*.tar.gz',
    'payloader-client-shells.json',
    'SHA256SUMS.txt',
  ]) {
    assert.match(workflow, new RegExp(releaseAssetPattern.replaceAll('.', '\\.').replaceAll('*', '.*')));
  }
  assert.doesNotMatch(
    workflow,
    /name:\s*client-shells-release\s+path:\s*artifacts\/client-shells\/\*/,
  );
  assert.match(workflow, /gh release delete-asset "\$RELEASE_TAG" "\$asset" --yes/);
  assert.match(workflow, /Expected exactly 20 release assets/);
  assert.match(workflow, /\/tmp\/release-assets\.expected/);
  assert.match(builder, /createBuildEnvironment\(signingSource, \{ includeSigning: true \}\)/);
  assert.match(builder, /useBundledElectronRuntime:\s*false/);
  assert.match(builder, /verifyClientExecutableArchitecture/);
  assert.match(builder, /PAYLOADER_SHELL_WINDOWS_/);
  assert.match(builder, /PAYLOADER_SHELL_MACOS_/);
  assert.doesNotMatch(builder, /['"]--dir['"]/);
  assert.match(builder, /config\.builderTarget/);
  assert.match(builder, /nativePackageName/);
  assert.match(builder, /findNativePackage/);
  assert.match(builder, /copyFile/);
  assert.match(builder, /\.sha256\.txt/);
  assert.match(clientBuilder, /version:\s*packageInfo\.version/);
  assert.doesNotMatch(clientBuilder, /version:\s*['"]1\.0\.0['"]/);
  assert.match(builder, /createClientShellTransport/);
  assert.match(builder, /basename\(directory\) === config\.executable/);
  assert.match(merger, /validateClientShellManifest/);
  assert.match(merger, /missingTargets/);
  assert.match(merger, /writeReleaseChecksumManifest/);
  assert.match(merger, /SHA256SUMS\.txt/);
  assert.match(shellSmoke, /validateClientShellManifest/);
  assert.match(shellSmoke, /PAYLOADER_CLIENT_SHELL_OUTPUT_DIR/);
  assert.match(shellSmoke, /PAYLOADER_CLIENT_PERF_EXECUTABLE/);
  assert.match(shellSmoke, /smoke-client-performance\.mjs/);
  assert.match(shellSmoke, /createHash\(['"]sha256['"]\)/);
  assert.match(shellSmoke, /extractTar/);
  assert.match(shellTransport, /verbatimSymlinks:\s*true/);
  assert.match(windowsSigningStages, /--prepackaged/);
  assert.match(windowsSigningStages, /useBundledElectronRuntime:\s*false/);
  assert.match(windowsSigningStages, /verifyClientExecutableArchitecture/);
  assert.match(windowsSigningStages, /createClientShellTransport/);
  assert.match(windowsSigningStages, /windows-signing-input\.json/);
  assert.match(signedInstallerApplier, /windows-signing-input\.json/);
  assert.match(windowsSignatureVerifier, /Get-AuthenticodeSignature/);
  assert.match(windowsSignatureVerifier, /SignatureStatus\]::Valid/);
  assert.match(windowsSignatureVerifier, /Payloader-Client-Setup-\*\.exe/);
  assert.match(windowsSignatureVerifier, /payloader-shell-windows-\*\.tar\.gz/);
  assert.match(windowsSignatureVerifier, /Get-ChildItem[\s\S]*-Filter '\*\.exe'/);
  assert.match(windowsSignatureVerifier, /PreparedApplicationDirectory/);
  assert.match(appSigningConfig, /apps\/x64\/Payloader\.exe/);
  assert.match(appSigningConfig, /apps\/arm64\/Payloader\.exe/);
  assert.match(appSigningConfig, /apps\/ia32\/Payloader\.exe/);
  assert.match(installerSigningConfig, /Payloader-Client-Setup-\$\{version\}-x64\.exe/);
  assert.match(installerSigningConfig, /Payloader-Client-Setup-\$\{version\}-arm64\.exe/);
  assert.match(installerSigningConfig, /Payloader-Client-Setup-\$\{version\}-ia32\.exe/);
});

test('container runs the Node application as a non-root user', async () => {
  const dockerfile = await readProjectFile('Dockerfile');
  assert.match(dockerfile, /FROM node:22(?:\.[0-9]+)*(?:-alpine)?/);
  assert.match(dockerfile, /USER node/);
  assert.match(dockerfile, /EXPOSE 8081/);
  assert.match(dockerfile, /VOLUME \["\/app\/data"\]/);
  assert.match(dockerfile, /HEALTHCHECK/);
  assert.match(dockerfile, /\/api\/ready/);
  assert.doesNotMatch(dockerfile, /fetch\('http:\/\/127\.0\.0\.1:8081\/api\/health'/);
  assert.match(dockerfile, /CMD \["node", "server\/admin-server\.mjs"\]/);
  assert.match(dockerfile, /\/app\/node_modules/);
  assert.match(dockerfile, /\/app\/src/);
  assert.match(dockerfile, /\/app\/server/);
  assert.match(dockerfile, /npm prune --omit=dev/);
  assert.match(dockerfile, /ELECTRON_SKIP_BINARY_DOWNLOAD=1/);
  assert.match(dockerfile, /ARG PAYLOADER_COMMIT_SHA/);
  assert.match(dockerfile, /PAYLOADER_COMMIT_SHA=\$PAYLOADER_COMMIT_SHA/);
  assert.match(
    dockerfile,
    /COPY scripts\/run-production-build\.mjs scripts\/verify-project-attribution\.mjs \.\/scripts\//,
  );
  assert.doesNotMatch(dockerfile, /COPY --from=builder --chown=node:node/);
  assert.doesNotMatch(dockerfile, /nginx/);
  assert.doesNotMatch(dockerfile, /\bwine\b/i);
  assert.doesNotMatch(dockerfile, /xcode|notarytool/i);
});

test('CI, Docker context, and documentation describe the real runtime', async () => {
  const [workflow, dockerignore, gitignore, readme, smokeScript] = await Promise.all([
    readProjectFile('.github/workflows/quality.yml'),
    readProjectFile('.dockerignore'),
    readProjectFile('.gitignore'),
    readProjectFile('README.md'),
    readProjectFile('scripts/smoke-running-server.mjs'),
  ]);
  assert.match(workflow, /node-version: ['"]22['"]/);
  assert.match(workflow, /npm ci/);
  assert.match(workflow, /npm run check/);
  assert.match(workflow, /docker build --build-arg PAYLOADER_COMMIT_SHA="\$\{\{ github\.sha \}\}" --tag payloader:ci/);
  assert.match(workflow, /--read-only/);
  assert.match(workflow, /\/tmp:rw,exec,mode=1777/);
  assert.match(workflow, /\/app\/data:rw,uid=1000,gid=1000,mode=0700/);
  assert.match(workflow, /linux-x64-appimage/);
  assert.match(workflow, /smoke-running-server\.mjs/);
  assert.match(workflow, /client-performance:/);
  assert.match(workflow, /windows-latest/);
  assert.match(workflow, /ubuntu-latest/);
  assert.match(workflow, /macos-latest/);
  assert.match(workflow, /client-performance:[\s\S]*PAYLOADER_CLIENT_PERF_PROFILE:\s*shared-runner/);
  assert.match(workflow, /verify:client-performance/);
  assert.match(workflow, /xvfb-run --auto-servernum/);
  assert.match(dockerignore, /node_modules/);
  assert.match(dockerignore, /data/);
  assert.match(dockerignore, /artifacts/);
  assert.match(dockerignore, /output/);
  assert.match(dockerignore, /!scripts\/verify-project-attribution\.mjs/);
  assert.match(dockerignore, /\.playwright-cli/);
  assert.match(dockerignore, /\*\.bak-\*/);
  for (const ignoredPath of ['coverage', 'playwright-report', 'blob-report', '.nyc_output', '.playwright']) {
    assert.ok(dockerignore.includes(ignoredPath), `Docker context must exclude ${ignoredPath}`);
    assert.ok(gitignore.includes(ignoredPath), `Git must ignore ${ignoredPath}`);
  }
  for (const ignoredPath of ['server/*.sqlite-journal', 'server/.default-seed-*.sqlite*', '/docs/superpowers/', '*.attempt']) {
    assert.ok(gitignore.includes(ignoredPath), `Git must ignore ${ignoredPath}`);
  }
  assert.match(smokeScript, /\/api\/admin\/reset-impact/);
  assert.match(smokeScript, /\/api\/admin\/client-builds\/generate/);
  assert.match(smokeScript, /\/api\/admin\/version-status/);
  assert.match(smokeScript, /installed\.version/);
  assert.match(readme, /Node\.js 22\.13/);
  assert.match(readme, /\/api\/health/);
  assert.match(readme, /\/api\/ready/);
  assert.match(readme, /data\/payloader\.sqlite/);
  assert.match(readme, /data\/backups/);
  assert.match(readme, /原生性能烟测/);
  assert.match(readme, /windows-latest/);
  assert.match(readme, /ubuntu-latest/);
  assert.match(readme, /macos-latest/);
  assert.match(readme, /系统更新/);
  assert.match(readme, /PAYLOADER_UPDATE_CHECK_INTERVAL_MS/);
  assert.match(readme, /PAYLOADER_GITHUB_TOKEN/);
  assert.match(readme, /PAYLOADER_CLIENT_SHELL_DIR/);
  assert.match(readme, /deployment\.payloader/);
  assert.match(readme, /payloader-client-shells\.json/);
});

test('all mutable server artifacts honor the configured data directory', async () => {
  const [adminServer, clientBuilder] = await Promise.all([
    readProjectFile('server/admin-server.mjs'),
    readProjectFile('server/client-builder.mjs'),
  ]);
  assert.match(adminServer, /const uploadDir = join\(dataDir, 'uploads'\)/);
  assert.match(clientBuilder, /const dataDir = resolve\(process\.env\.PAYLOADER_DATA_DIR \|\| join\(rootDir, 'data'\)\)/);
  assert.match(clientBuilder, /const clientCacheRoot = process\.env\.PAYLOADER_CLIENT_CACHE_DIR/);
  assert.match(clientBuilder, /XDG_CACHE_HOME: join\(clientCacheRoot, 'xdg-cache'\)/);
  assert.match(adminServer, /writeFile\(jwtSecretFile,[\s\S]*?mode:\s*0o600/);
});

test('public metadata does not claim an unconfigured domain or stale inventory', async () => {
  const [indexHtml, appSource, robots] = await Promise.all([
    readProjectFile('index.html'),
    readProjectFile('src/App.tsx'),
    readProjectFile('public/robots.txt'),
  ]);
  assert.doesNotMatch(indexHtml, /payloader\.app/i);
  assert.doesNotMatch(indexHtml, /178\s*(?:个)?Web Payload|129\s*(?:条)?内网|114\s*(?:条)?工具/);
  assert.doesNotMatch(appSource, /178\s*(?:个)?Web Payload|129\s*(?:条)?内网|114\s*(?:条)?工具/);
  assert.doesNotMatch(robots, /^Sitemap:/im);
  assert.match(indexHtml, /安全测试知识与编解码工作台/);
});

test('public repository documents its open-source signing and privacy contract', async () => {
  const [packageSource, lockSource, readme, license, signingPolicy, privacyPolicy, onboarding, workflow] = await Promise.all([
    readProjectFile('package.json'),
    readProjectFile('package-lock.json'),
    readProjectFile('README.md'),
    readProjectFile('LICENSE'),
    readProjectFile('CODE_SIGNING_POLICY.md'),
    readProjectFile('PRIVACY.md'),
    readProjectFile('SIGNPATH_ONBOARDING.md'),
    readProjectFile('.github/workflows/client-shells.yml'),
  ]);
  const packageJson = JSON.parse(packageSource);
  const packageLock = JSON.parse(lockSource);
  assert.equal(packageJson.license, 'AGPL-3.0-only');
  assert.equal(packageLock.packages?.['']?.license, 'AGPL-3.0-only');
  assert.match(packageJson.repository?.url || '', /github\.com\/3516634930\/Payloader\.git$/);
  assert.match(license, /GNU AFFERO GENERAL PUBLIC LICENSE/);
  assert.match(license, /Version 3, 19 November 2007/);
  assert.match(readme, /## 代码签名/);
  assert.match(readme, /CODE_SIGNING_POLICY\.md/);
  assert.match(readme, /PRIVACY\.md/);
  assert.match(signingPolicy, /Free code signing provided by \[SignPath\.io\]/);
  assert.match(signingPolicy, /certificate by \[SignPath Foundation\]/);
  assert.match(signingPolicy, /Authors and committers/);
  assert.match(signingPolicy, /Reviewers/);
  assert.match(signingPolicy, /Approvers/);
  assert.match(signingPolicy, /3516634930/);
  assert.match(signingPolicy, /manual approval/i);
  assert.match(signingPolicy, /multi-factor authentication/i);
  assert.match(privacyPolicy, /does not collect telemetry/i);
  assert.match(privacyPolicy, /PAYLOADER_UPDATE_CHECK_DISABLED/);
  assert.match(privacyPolicy, /sessionStorage/);
  assert.match(onboarding, /SIGNPATH_API_TOKEN/);
  assert.match(onboarding, /SIGNPATH_ORGANIZATION_ID/);
  assert.match(onboarding, /SIGNPATH_PROJECT_SLUG/);
  assert.match(onboarding, /SIGNPATH_SIGNING_POLICY_SLUG/);
  assert.match(onboarding, /prepared application/i);
  assert.match(onboarding, /NSIS installer/i);
  assert.match(onboarding, /two signing requests/i);
  assert.match(onboarding, /manual approval/i);
  assert.match(workflow, /Free code signing provided by SignPath\.io/);
  assert.match(workflow, /CODE_SIGNING_POLICY\.md/);
  assert.match(workflow, /PRIVACY\.md/);
});
