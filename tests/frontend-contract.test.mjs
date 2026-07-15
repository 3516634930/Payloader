import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

const read = relativePath => readFile(new URL(`../${relativePath}`, import.meta.url), 'utf8');

test('encoding tools are loaded on demand from App', async () => {
  const [app, header] = await Promise.all([
    read('src/App.tsx'),
    read('src/components/Header.tsx'),
  ]);

  assert.match(app, /lazy\(\(\)\s*=>\s*import\(['"]\.\/components\/EncodingTools['"]\)\)/);
  assert.match(app, /<Suspense\b/);
  assert.doesNotMatch(header, /import\s+EncodingTools\s+from/);
});

test('public shell exposes skip navigation and a labelled main landmark', async () => {
  const [app, main] = await Promise.all([
    read('src/App.tsx'),
    read('src/components/MainContent.tsx'),
  ]);

  assert.match(app, /href=["']#main-content["']/);
  assert.match(main, /<main\b[^>]*id=["']main-content["']/s);
});

test('deployed HTML exposes the existing Xeye link to non-JavaScript crawlers', async () => {
  const [html, header, protectedLinks, dataStore, clientBuilder, readme] = await Promise.all([
    read('index.html'),
    read('src/components/Header.tsx'),
    read('src/protectedLinks.ts'),
    read('server/data-store.mjs'),
    read('server/client-builder.mjs'),
    read('README.md'),
  ]);

  const staticLink = html.match(/<a\b[^>]*href=["']https:\/\/xss\.icu\/["'][^>]*>\s*Xeye XSS 平台\s*<\/a>/s)?.[0] || '';
  assert.ok(staticLink, 'the initial HTML must contain the visible Xeye anchor');
  assert.doesNotMatch(staticLink, /rel=["'][^"']*(?:nofollow|sponsored|ugc)/i);
  assert.doesNotMatch(staticLink, /noreferrer/i);
  assert.match(staticLink, /referrerpolicy=["']origin["']/i);
  assert.match(header, /<a[\s\S]*?href=\{protectedExternalLinks\.xeye\.href\}/);
  assert.match(header, /settings\.xeyeEnabled !== false/);
  assert.match(header, /href=\{protectedExternalLinks\.xeye\.href\}[\s\S]*?referrerPolicy=["']origin["']/);
  assert.doesNotMatch(protectedLinks, /window\.open\(href, '_blank', 'noopener,noreferrer'\)/);
  assert.doesNotMatch(protectedLinks, /decodeProtectedText|xeyeUrlBytes/);
  assert.doesNotMatch(dataStore, /verifyProtectedLinkSource|protectedIntegrity|assertProtectedHash/);
  assert.doesNotMatch(clientBuilder, /decodeProtectedText/);
  assert.doesNotMatch(readme, /xss\.icu|Xeye XSS 平台/i);

  const structuredDataSource = html.match(/<script[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/)?.[1] || '';
  const structuredData = JSON.parse(structuredDataSource);
  assert.equal(structuredData.mentions?.url, 'https://xss.icu/');
  assert.equal(structuredData.mentions?.name, 'Xeye XSS 平台');
});

test('the production server removes static Xeye metadata after an administrator deletes the entry', async () => {
  const [server, html] = await Promise.all([
    read('server/admin-server.mjs'),
    read('index.html'),
  ]);

  assert.match(html, /id=["']xeye-structured-data["']/);
  assert.match(html, /data-xeye-platform-link/);
  assert.match(server, /settings\.xeyeEnabled/);
  assert.match(server, /xeye-structured-data/);
  assert.match(server, /data-xeye-platform-link/);
});

test('sidebar uses an accessible tree with semantic controls', async () => {
  const sidebar = await read('src/components/Sidebar.tsx');

  assert.match(sidebar, /role=["']tree["']/);
  assert.match(sidebar, /role=["']treeitem["']/);
  assert.match(sidebar, /aria-expanded=/);
  assert.match(sidebar, /aria-selected=/);
  assert.match(sidebar, /ArrowDown/);
  assert.match(sidebar, /Home/);
  assert.match(sidebar, /<button\b[^>]*className=.*tree-item/s);
});

test('sidebar search keeps one roving tab stop on the first visible root', async () => {
  const sidebar = await read('src/components/Sidebar.tsx');

  assert.match(sidebar, /firstVisibleRootId/);
  assert.match(sidebar, /isTreeItemVisible/);
  assert.match(sidebar, /isFirst=\{item\.id === firstVisibleRootId\}/);
  assert.doesNotMatch(sidebar, /isFirst=\{index === 0\}/);
});

test('dialogs are labelled, modal, keyboard closable, and focus managed', async () => {
  const [header, syntaxModal] = await Promise.all([
    read('src/components/Header.tsx'),
    read('src/components/SyntaxModal.tsx'),
  ]);

  for (const source of [header, syntaxModal]) {
    assert.match(source, /role=["']dialog["']/);
    assert.match(source, /aria-modal=["']true["']/);
    assert.match(source, /Escape/);
    assert.match(source, /previousFocus|previouslyFocused/);
  }
});

test('encoding dialog close control meets the minimum touch target', async () => {
  const header = await read('src/components/Header.tsx');
  const closeButtonRule = header.match(/\.close-btn\s*\{([^}]*)\}/)?.[1] || '';

  assert.match(closeButtonRule, /width:\s*44px/);
  assert.match(closeButtonRule, /height:\s*44px/);
});

test('mobile search input meets the minimum touch target', async () => {
  const header = await read('src/components/Header.tsx');

  assert.match(header, /\.search-input\s*\{[^}]*height:\s*44px/s);
  assert.doesNotMatch(header, /\.search-input\s*\{[^}]*height:\s*42px/s);
});

test('public search controls expose stable form names', async () => {
  const [header, payloadDetail] = await Promise.all([
    read('src/components/Header.tsx'),
    read('src/components/PayloadDetail.tsx'),
  ]);

  assert.match(header, /name=["']content-search["']/);
  assert.match(header, /name=["']variable-search["']/);
  assert.match(payloadDetail, /name=["']payload-command-search["']/);
});

test('mobile encoding controls meet the minimum touch target', async () => {
  const encodingTools = await read('src/components/EncodingTools.tsx');
  const mobileStyles = encodingTools.slice(encodingTools.indexOf('@media (max-width: 680px)'));

  assert.match(mobileStyles, /\.operation-select-field select,[\s\S]*?\.copy-btn\s*\{[^}]*min-height:\s*44px/);
  assert.doesNotMatch(mobileStyles, /min-height:\s*(?:3\d|4[0-3])px/);
});

test('payload tutorial and WAF states are content driven', async () => {
  const detail = await read('src/components/PayloadDetail.tsx');

  assert.match(detail, /hasSubstantiveTutorial/);
  assert.match(detail, /hasWafContent/);
  assert.match(detail, /hasSubstantiveTutorial\s*&&/);
});

test('payload filtering is keyed to selection and tool copy has a clipboard fallback', async () => {
  const [payloadDetail, toolDetail] = await Promise.all([
    read('src/components/PayloadDetail.tsx'),
    read('src/components/ToolDetail.tsx'),
  ]);

  assert.match(payloadDetail, /payloadQueryState\.payloadId === payloadId \? payloadQueryState\.value : ''/);
  assert.match(payloadDetail, /setPayloadQueryState\(\{ payloadId, value: event\.target\.value \}\)/);
  assert.match(toolDetail, /navigator\.clipboard\.writeText\(processedText\)[\s\S]*?document\.execCommand\('copy'\)/);
});

test('generated-review placeholders are editable global variables', async () => {
  const variables = await read('src/data/globalVariables.ts');

  for (const key of [
    'LAB_DOMAIN', 'LAB_HOST', 'LAB_USER', 'LAB_PASSWORD', 'LAB_NTLM_HASH', 'EXCHANGE_HOST',
    'LAB_APP', 'LAB_ORIGIN', 'LAB_SSRF_APP', 'LAB_MYSQL_HOST', 'LAB_FASTCGI_HOST', 'LAB_OAST',
    'LAB_REBIND_DOMAIN', 'LAB_SMUGGLE_HOST', 'LAB_SMUGGLE_PORT', 'LAB_SIGNING_KEY', 'LAB_NODE',
    'LAB_GATEWAY', 'LAB_GPO', 'LAB_GROUP', 'LAB_JUMP', 'LAB_LABEL', 'LAB_MACHINE', 'LAB_SITE',
    'LAB_TASK', 'LAB_TOKEN', 'LAB_VALUE', 'LAB_DLL_FILE', 'LAB_ENCODED_FILE', 'LAB_SHELLCODE_FILE',
  ]) {
    assert.match(variables, new RegExp(`key: '${key}'`));
  }
});

test('every business command placeholder has an editable global variable', async () => {
  const variables = await read('src/data/globalVariables.ts');
  const registered = new Set([...variables.matchAll(/key:\s*'([^']+)'/g)].map(match => match[1]));
  const database = new DatabaseSync(new URL('../server/default-seed.sqlite', import.meta.url), { readOnly: true });
  const ignoredShellTokens = new Set(['IFS', 'DOESNOTEXIST']);
  const missing = new Set();

  try {
    for (const [table, column, areas] of [
      ['payloads', 'data', ['execution', 'wafBypass']],
      ['tools', 'data', ['commands']],
    ]) {
      for (const row of database.prepare(`SELECT ${column} AS json FROM ${table} WHERE enabled = 1`).all()) {
        const item = JSON.parse(row.json);
        for (const area of areas) {
          for (const entry of Array.isArray(item[area]) ? item[area] : []) {
            for (const match of String(entry.command || '').matchAll(/\{([A-Z][A-Z0-9_]+)\}/g)) {
              const key = match[1];
              if (!registered.has(key) && !ignoredShellTokens.has(key)) missing.add(key);
            }
          }
        }
      }
    }
  } finally {
    database.close();
  }

  assert.deepEqual([...missing].sort(), []);
});

test('commands and attack chains use canonical variable placeholders', () => {
  const database = new DatabaseSync(new URL('../server/default-seed.sqlite', import.meta.url), { readOnly: true });
  const legacyVariable = /<(?:host|port|payload|command|ip|target|url|domain|file|path|username|password)>/i;
  const findings = [];

  try {
    for (const [table, areas] of [
      ['payloads', ['execution', 'wafBypass', 'attackChain']],
      ['tools', ['commands']],
    ]) {
      for (const row of database.prepare(`SELECT id, data FROM ${table} WHERE enabled = 1`).all()) {
        const item = JSON.parse(row.data);
        for (const area of areas) {
          for (const entry of Array.isArray(item[area]) ? item[area] : []) {
            const text = area === 'attackChain' ? String(entry.payload || '') : String(entry.command || '');
            if (legacyVariable.test(text)) findings.push(`${table}:${row.id}:${area}`);
          }
        }
      }
    }
  } finally {
    database.close();
  }

  assert.deepEqual(findings, []);
});

test('global-variable panel returns focus to its own toggle', async () => {
  const header = await read('src/components/Header.tsx');

  const payloadTab = header.match(/<button\s+[^>]*role="tab"[\s\S]*?\{t\('header\.tabPayloads', language\)\}/)?.[0] || '';
  const variableToggle = header.match(/<button\s+[^>]*className="variables-toggle"[\s\S]*?\{t\('header\.variables', language\)\}/)?.[0] || '';

  assert.doesNotMatch(payloadTab, /ref=\{variablesToggleRef\}/);
  assert.match(variableToggle, /ref=\{variablesToggleRef\}/);
});

test('download artifacts render before the secondary target matrix', async () => {
  const downloads = await read('src/components/ClientDownloads.tsx');
  const artifactIndex = downloads.indexOf('{grouped.map');
  const matrixIndex = downloads.lastIndexOf('{renderTargetMatrix()}');

  assert.ok(artifactIndex >= 0, 'download artifact list is missing');
  assert.ok(matrixIndex > artifactIndex, 'target matrix must follow available downloads');
  assert.match(downloads, /freshness\?\.isCurrent/);
  assert.match(downloads, /lastBuildFailed/);
  assert.doesNotMatch(downloads, /info\?\.lastFailure/);
});

test('global styles preserve visible keyboard focus', async () => {
  const styles = await read('src/styles/global.css');

  assert.match(styles, /:focus-visible/);
  assert.doesNotMatch(styles, /button\s*\{[^}]*outline\s*:\s*none/s);
});

test('admin custom content is rendered through text-safe DOM APIs', async () => {
  const customModule = await read('admin/custom-module.js');

  assert.match(customModule, /textContent\s*=/);
  assert.match(customModule, /replaceChildren\(/);
  assert.doesNotMatch(customModule, /listEl\.innerHTML\s*=\s*customs\.map/);
});

test('admin client target cards retain their grid contract', async () => {
  const polish = await read('admin/admin-polish.css');

  assert.doesNotMatch(polish, /\[aria-label=["']客户端生成目标矩阵["']\]\s*>\s*\*\s*\{[^}]*display\s*:\s*flex/s);
  assert.match(polish, /client-target-card[^{]*\{[^}]*overflow-wrap|client-target-card[\s\S]*overflow-wrap/);
});

test('admin mobile controls meet touch targets and polish CSS is balanced', async () => {
  const polish = await read('admin/admin-polish.css');
  const withoutComments = polish.replace(/\/\*[\s\S]*?\*\//g, '');
  let braceBalance = 0;
  let minimumBalance = 0;
  for (const character of withoutComments) {
    if (character === '{') braceBalance += 1;
    if (character === '}') braceBalance -= 1;
    minimumBalance = Math.min(minimumBalance, braceBalance);
  }

  assert.equal(braceBalance, 0);
  assert.equal(minimumBalance, 0);
  assert.match(polish, /@media \(max-width: 860px\)[\s\S]*?\.module-btn,[\s\S]*?min-height:\s*44px !important/);
  assert.match(polish, /input:not\(\[type="file"\]\)[\s\S]*?min-height:\s*44px !important/);
});

test('admin shell uses enterprise action hierarchy and mobile module selection', async () => {
  const [html, login, admin] = await Promise.all([
    read('admin/index.html'),
    read('admin/login.html'),
    read('admin/admin.js'),
  ]);

  assert.match(html, /id=["']admin-module-select["']/);
  assert.match(html, /id=["']more-actions["']/);
  assert.match(html, /class=["'][^"']*more-actions-menu/);
  assert.doesNotMatch(html, /class=["']stats-grid["']/);
  assert.match(html, /aria-label=["']更多后台操作["']/);
  assert.match(login, /<h1[^>]*id=["']login-title["'][^>]*>Payloader Admin<\/h1>/);
  assert.doesNotMatch(login, /login-intro|login-capabilities|login-security/);
  assert.doesNotMatch(login, /统一维护|面向管理员|内容管理|结构治理|发布交付|管理员身份验证|会话使用/);
  assert.doesNotMatch(html, /管理前台展示的内容和结构|正在编辑/);
  for (const subtitle of ['标题、Logo', '命令、教程、引用', '工具分类和命令库', '前台左侧分类结构', '版本与源码状态', '快速添加文本内容']) {
    assert.doesNotMatch(html, new RegExp(`<small>${subtitle}</small>`));
  }
  assert.doesNotMatch(admin, /\bdesc:\s*['"][^'"]*['"]/);
  assert.doesNotMatch(admin, /Payloader Update Center|检查当前部署版本、官方稳定版本和默认分支源码状态/);
});

test('admin exposes a responsive and text-safe system update center', async () => {
  const [html, admin, styles] = await Promise.all([
    read('admin/index.html'),
    read('admin/admin.js'),
    read('admin/admin.css'),
  ]);

  assert.match(html, /<option value=["']updates["']>系统更新<\/option>/);
  assert.match(html, /class=["'][^"']*module-btn[^"']*["'][^>]*data-module=["']updates["']/);
  assert.match(admin, /updates:\s*\{[\s\S]*?api:\s*['"]\/api\/admin\/version-status['"]/);
  assert.match(admin, /const singletonModules = new Set\(\[[^\]]*['"]updates['"]/);
  assert.match(admin, /const summarizeReleaseNotes = value =>/);
  assert.match(admin, /const renderVersionUpdateCenter = \(\) =>/);
  assert.match(admin, /api\(['"]\/api\/admin\/version-check['"],\s*\{ method:\s*['"]POST['"] \}\)/);
  assert.match(admin, /summarizeReleaseNotes\(stable\.notes\)/);
  assert.doesNotMatch(admin, /<pre>\$\{escapeHtml\(stable\.notes\)/);
  assert.match(admin, /version-update-note-list/);
  assert.match(admin, /version-update-note-notices/);
  assert.match(admin, /releaseNotes\.notices\.map\(notice => `<p>\$\{escapeHtml\(notice\)\}<\/p>`\)/);
  assert.match(admin, /notices:\s*\[\.\.\.new Set\(notices\)\]\.slice\(0, 2\)/);
  assert.match(admin, /state\.versionChecking/);
  assert.match(admin, /官方发布版本/);
  assert.match(admin, /未发现 Release \/ Tag/);
  assert.match(admin, /formatVersionDate\(stable\.publishedAt, '未发布'\)/);
  assert.match(admin, /readOnlyStatusModule/);
  assert.match(styles, /\.version-update-shell\s*\{/);
  assert.match(styles, /\.version-update-timeline\s*\{[\s\S]*?grid-template-columns:\s*repeat\(3,/);
  assert.match(styles, /\.version-update-note-notices\s*\{[\s\S]*?grid-template-columns:\s*repeat\(2,/);
  assert.match(styles, /@media \(max-width: 860px\)[\s\S]*?\.version-update-grid[\s\S]*?grid-template-columns:\s*1fr/);

  const summaryHelpers = admin.slice(
    admin.indexOf('const plainReleaseNote = value =>'),
    admin.indexOf('const safeProjectRoute = value =>'),
  );
  const summarize = new Function(`${summaryHelpers}; return summarizeReleaseNotes;`)();
  const summary = summarize(`
## Direct client downloads
- 新增后台管理

Windows installers are unsigned and may trigger <b>SmartScreen</b>.

macOS packages are not notarized; verify SHA-256 before running.

Checksum details are available in SHA256SUMS.txt.

| System | Download |
| --- | --- |
| Windows | EXE |
  `);
  assert.equal(summary.title, '正式版本发布');
  assert.deepEqual(summary.items, ['新增后台管理']);
  assert.deepEqual(summary.notices, [
    'Windows installers are unsigned and may trigger <b>SmartScreen</b>.',
    'macOS packages are not notarized; verify SHA-256 before running.',
  ]);
});

test('admin content lists use bounded incremental rendering', async () => {
  const admin = await read('admin/admin.js');

  assert.match(admin, /const itemListPageSize = 120/);
  assert.match(admin, /items\.slice\(0, visibleItemLimit\)/);
  assert.match(admin, /data-action="load-more-items"/);
  assert.match(admin, /state\.visibleItemLimit \+= itemListPageSize/);
});

test('admin editor validates publishable content before saving', async () => {
  const admin = await read('admin/admin.js');

  assert.match(admin, /const validateContentInput = item =>/);
  assert.match(admin, /请补全中英文名称/);
  assert.match(admin, /请至少添加一条完整的执行命令/);
  assert.match(admin, /请补全教程的中英文内容/);
  assert.match(admin, /if \(!validateContentInput\(item\)\) return/);
  assert.doesNotMatch(admin, /command:\s*['"]echo TODO['"]/);
});

test('admin keeps the default Xeye item deletable while locking edits and reordering', async () => {
  const admin = await read('admin/admin.js');

  assert.match(admin, /const lockedSelection = Boolean\(selectedItem\(\)\?\.systemLocked\)/);
  assert.match(admin, /\$\('delete-item'\)\.disabled = busy \|\| !dataActions \|\| !selectedItem\(\)/);
});

test('legacy custom admin entry reuses the authenticated admin module', async () => {
  const html = await read('admin/custom.html');
  const script = await read('admin/custom.js');
  const customModule = await read('admin/custom-module.js');

  assert.doesNotMatch(html, /<style>/);
  assert.doesNotMatch(html, /type=["']password["']/);
  assert.match(script, /payloader-admin-initial-module/);
  assert.match(script, /location\.replace\(['"]\/admin['"]\)/);
  assert.doesNotMatch(customModule, /<style>/);
  assert.doesNotMatch(customModule, /style\.cssText/);
});

test('admin shell is public while admin data uses explicit Bearer authorization', async () => {
  const login = await read('admin/login.html');
  const loginScript = await read('admin/login.js');
  const server = await read('server/admin-server.mjs');
  const admin = await read('admin/admin.js');

  assert.match(login, /admin-polish\.css/);
  assert.doesNotMatch(login, /Bearer JWT/);
  assert.doesNotMatch(login, /HttpOnly Cookie/);
  assert.match(loginScript, /body\.tokenType !== 'Bearer'/);
  assert.match(loginScript, /sessionStorage\.setItem\(tokenStorageKey, body\.accessToken\)/);
  assert.doesNotMatch(loginScript, /正在建立安全会话|登录成功，正在进入后台|进入后台/);
  assert.match(server, /url\.pathname === '\/admin'[\s\S]*?serveStatic\(request, response, adminPath\)/);
  assert.match(server, /handleAdminApi[\s\S]*?requireAuth\(request, response\)/);
  assert.match(server, /authorization\.match\(\/\^Bearer/);
  assert.match(admin, /sessionStorage\.getItem\(adminTokenStorageKey\)/);
  assert.match(admin, /headers\.authorization = `Bearer \$\{state\.accessToken\}`/);
  assert.doesNotMatch(admin, /localStorage\.setItem\([^\n]*access-token/);
  assert.doesNotMatch(server, /parseCookies|sessionCookie|set-cookie/);
});

test('admin reset previews impact, creates a backup, and reports its location', async () => {
  const admin = await read('admin/admin.js');

  assert.match(admin, /\/api\/admin\/reset-impact\?target=/);
  assert.match(admin, /impact\.before/);
  assert.match(admin, /impact\.seed/);
  assert.match(admin, /impact\.delta/);
  assert.match(admin, /impact\.integrations\?\.xeye/);
  assert.match(admin, /Xeye 平台入口/);
  assert.match(admin, /重置后恢复/);
  assert.match(admin, /backup\?\.(?:path|fileName)|backup\.(?:path|fileName)/);
  assert.doesNotMatch(admin, /此操作不可撤销/);
  assert.doesNotMatch(admin, /const renderClientBuildForm =/);
});

test('large catalog search builds one shared index and defers result rendering', async () => {
  const app = await read('src/App.tsx');
  const sidebar = await read('src/components/Sidebar.tsx');
  const mainContent = await read('src/components/MainContent.tsx');
  const searchIndex = await read('src/searchIndex.ts');

  assert.match(app, /useDeferredValue/);
  assert.match(app, /buildSearchIndex/);
  assert.match(app, /searchMatches/);
  assert.match(app, /setTimeout\([\s\S]*?setSettledSearchQuery\(searchQuery\)[\s\S]*?searchQuery \? 80 : 0/);
  assert.doesNotMatch(app, /if \(!searchQuery\)[\s\S]{0,120}setSettledSearchQuery\(''\)/);
  assert.match(searchIndex, /buildSearchIndex/);
  assert.match(searchIndex, /matchSearchIndex/);
  assert.match(searchIndex, /payloadEntries:\s*readonly SearchEntry\[\]/);
  assert.match(searchIndex, /toolEntries:\s*readonly SearchEntry\[\]/);
  assert.match(searchIndex, /searchableText/);
  assert.match(searchIndex, /entry\.text\.includes\(normalizedQuery\)/);
  assert.doesNotMatch(searchIndex, /filter\(payload => payloadMatches/);
  assert.doesNotMatch(searchIndex, /filter\(tool => toolMatches/);
  assert.doesNotMatch(sidebar, /const searchable\s*=/);
  assert.doesNotMatch(mainContent, /const searchable\s*=/);
});

test('admin custom content uses its authenticated narrow endpoint', async () => {
  const customModule = await read('admin/custom-module.js');

  assert.match(customModule, /\/api\/admin\/custom-content/);
  assert.doesNotMatch(customModule, /authorizedFetch\(['"]\/api\/admin\/custom-payloads/);
  assert.match(customModule, /const authorizedFetch = async/);
  assert.match(customModule, /response\.status === 401[\s\S]*?sessionStorage\.removeItem\(tokenStorageKey\)[\s\S]*?location\.replace\(['"]\/admin\/login['"]\)/);
  assert.doesNotMatch(customModule, /fetch\(['"]\/api\/public-data['"]\)/);
});

test('admin custom content supports payload and tool destinations through the narrow API', async () => {
  const customModule = await read('admin/custom-module.js');

  assert.match(customModule, /id="cp-destination"/);
  assert.match(customModule, /value="payloads"/);
  assert.match(customModule, /value="tools"/);
  assert.match(customModule, /sourceDestination/);
  assert.match(customModule, /recordByKey/);
  assert.match(customModule, /const moduleDescription = document\.getElementById\('module-desc'\)/);
  assert.match(customModule, /if \(moduleDescription\)/);
  assert.doesNotMatch(customModule, /dataset\.content/);
});

test('sidebar derives custom entries from the active payload or tool collection', async () => {
  const sidebar = await read('src/components/Sidebar.tsx');

  assert.match(sidebar, /allToolCommands/);
  assert.match(sidebar, /toolId: item\.id/);
  assert.match(sidebar, /payloadId: item\.id/);
  assert.doesNotMatch(
    sidebar,
    /activeTab !== 'payloads' && activeTab !== 'tools'[\s\S]*return allPayloads/,
  );
});
