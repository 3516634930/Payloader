// TutorialPanel 防护代码渲染契约：含缩进代码的教程段必须渲染为 pre.code-block（换行缩进不被折叠）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderToStaticMarkup } from 'react-dom/server';
import { createElement } from 'react';
import { loadTsModule } from './helpers/compileTsModule.mjs';

const TutorialPanel = loadTsModule('src/components/TutorialPanel.tsx').default;

const payload = {
  id: 'render-test',
  analysis: '对照正常与异常输入判定结果。',
  opsecTips: [{ zh: '仅使用授权测试数据', en: 'authorized data only' }],
  references: ['https://example.com/'],
};
const tutorial = {
  overview: { zh: '总览文字', en: 'overview' },
  vulnerability: { zh: '原理文字', en: 'vuln' },
  exploitation: { zh: '利用步骤文字', en: 'exploit' },
  mitigation: {
    zh: '参数化绑定并最小授权：\n    // PHP\n    $st = $pdo->prepare(\'SELECT id FROM users WHERE email = ?\');\n    $st->execute([$email]);\n    // Java JDBC\n    try (PreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE email = ?")) { ps.setString(1, email); }\n    修复后重放载荷验证。',
    en: 'Use parameter binding.',
  },
  difficulty: 'intermediate',
};

test('mitigation 防护代码渲染为 code-block 且保留换行缩进', () => {
  const html = renderToStaticMarkup(createElement(TutorialPanel, { payload, tutorial, language: 'zh' }));
  assert.match(html, /<pre class="code-block tutorial-code">/);
  assert.match(html, /\$st = \$pdo-&gt;prepare\((?:&#x27;|')SELECT id FROM users WHERE email = \?(?:&#x27;|')\)/);
  assert.match(html, /PreparedStatement ps/);
  const pre = html.match(/<pre class="code-block tutorial-code">([\s\S]*?)<\/pre>/)?.[1] ?? '';
  assert.ok(!/\n {4}/.test(pre.replace(/^.*?\n/, '').replace(/ {8,}/g, '    ')), '公共缩进应剥离（嵌套缩进≤4 基准）');
  assert.match(html, /参数化绑定并最小授权/);
  assert.match(html, /修复后重放载荷验证/);
});

test('纯文字教程段不产生代码块（回归保护）', () => {
  const plain = { ...tutorial, mitigation: { zh: '仅文字建议，无代码。', en: 'text only' } };
  const html = renderToStaticMarkup(createElement(TutorialPanel, { payload, tutorial: plain, language: 'zh' }));
  assert.ok(!html.includes('code-block'));
  assert.match(html, /仅文字建议，无代码。/);
});
