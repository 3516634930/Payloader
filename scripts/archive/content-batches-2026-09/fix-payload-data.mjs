import { DatabaseSync } from 'node:sqlite';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const db = new DatabaseSync(join(rootDir, 'data', 'payloader.sqlite'));
const chineseRe = /[一-鿿]/;

// 从散文格式exploitation提取攻击链
function parseChainFromProse(text) {
  if (!text) return [];

  // 方案1：句子拆分（中文句号/分号分隔，每句作为一步）
  // 先清理"首先""然后""其次""最后"等引导词
  const cleaned = text
    .replace(/^[^，,：:。\n]*[：:]\s*/, '') // 去掉 "XXX步骤：" 前缀
    .replace(/\n+/g, '，');

  // 按连接词和句号切分
  const parts = cleaned.split(/[,，；;。]\s*(?=然后|接着|其次|最后|之后|接下来|同时|并|再|随后|继续|尝试|使用|通过|利用|如果|当|)/)
    .map(s => s.replace(/^(首先|然后|接着|其次|最后|之后|接下来|同时|再|随后|继续)[，,]?\s*/, '').trim())
    .filter(s => s.length > 4 && s.length < 80);

  if (parts.length >= 2) {
    return parts.slice(0, 6).map(s => ({
      title: { zh: s.length > 18 ? s.slice(0, 18) : s, en: s.length > 18 ? s.slice(0, 18) : s },
      description: { zh: s, en: s }
    }));
  }

  // 方案2：把整个exploitation作为单步
  const summary = text.slice(0, 60).replace(/\n/g, ' ');
  return [{ title: { zh: '利用步骤', en: '利用步骤' }, description: { zh: summary, en: summary } }];
}

// 修复tutorial中en字段含中文（用zh值覆盖，保证语言一致性）
function fixTutorialEn(tutorial) {
  if (!tutorial || typeof tutorial !== 'object') return tutorial;
  const t = { ...tutorial };
  for (const key of ['overview', 'vulnerability', 'exploitation', 'mitigation']) {
    if (t[key] && typeof t[key] === 'object') {
      if (chineseRe.test(t[key].en || '')) {
        t[key] = { zh: t[key].zh, en: t[key].zh };
      }
    }
  }
  return t;
}

// 修复execution中en含中文
function fixExecutionEn(execution) {
  if (!Array.isArray(execution)) return execution;
  return execution.map(ex => {
    const next = { ...ex };
    if (next.description && typeof next.description === 'object') {
      if (chineseRe.test(next.description.en || '')) {
        next.description = { zh: next.description.zh, en: next.description.zh };
      }
    }
    if (next.title && typeof next.title === 'object') {
      if (chineseRe.test(next.title.en || '')) {
        next.title = { zh: next.title.zh, en: next.title.zh };
      }
    }
    if (Array.isArray(next.syntaxBreakdown)) {
      next.syntaxBreakdown = next.syntaxBreakdown.map(sb => {
        if (sb.explanation && chineseRe.test(sb.explanation.en || '')) {
          return { ...sb, explanation: { zh: sb.explanation.zh, en: sb.explanation.zh } };
        }
        return sb;
      });
    }
    return next;
  });
}

const rows = db.prepare('SELECT id, data FROM payloads').all();
const update2 = db.prepare('UPDATE payloads SET data=?, updated_at=? WHERE id=?');

let attackChainFixed = 0, tutorialEnFixed = 0, execEnFixed = 0;
const now = new Date().toISOString();

for (const row of rows) {
  const p = JSON.parse(row.data);
  let changed = false;

  // 1. 修 attackChain
  if (!p.attackChain || p.attackChain.length === 0) {
    const chain = parseChainFromProse(p.tutorial?.exploitation?.zh);
    if (chain.length > 0) {
      p.attackChain = chain;
      changed = true;
      attackChainFixed++;
    }
  }

  // 2. 修 tutorial.en 含中文
  if (p.tutorial) {
    const fixed = fixTutorialEn(p.tutorial);
    const s1 = JSON.stringify(p.tutorial);
    const s2 = JSON.stringify(fixed);
    if (s1 !== s2) { p.tutorial = fixed; changed = true; tutorialEnFixed++; }
  }

  // 3. 修 execution/wafBypass en 含中文
  const execFixed = fixExecutionEn(p.execution);
  if (JSON.stringify(execFixed) !== JSON.stringify(p.execution)) {
    p.execution = execFixed; changed = true; execEnFixed++;
  }
  const wafFixed = fixExecutionEn(p.wafBypass);
  if (JSON.stringify(wafFixed) !== JSON.stringify(p.wafBypass)) {
    p.wafBypass = wafFixed; changed = true;
  }

  if (changed) {
    update2.run(JSON.stringify(p), now, row.id);
  }
}

db.close();
console.log(JSON.stringify({ attackChainFixed, tutorialEnFixed, execEnFixed }));
