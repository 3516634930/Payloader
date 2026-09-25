#!/usr/bin/env node
/**
 * AI 域 SB 程序化补写：35 条 × 4 步（主载荷 + 3 输入过滤绕过变体）。
 * part 取命令真实短前缀/特征片段（规避长段载荷引用），说明按手法类型模板。
 */
const fs = require('fs');
const path = require('path');
const OUT = p => path.join(process.cwd(), 'output/content-audit', p);

const ai = JSON.parse(fs.readFileSync(OUT('ai-only.json'), 'utf8'));

// 每条 payload 的手法语义表（id → [主载荷三段说明, 变体统一说明后缀]）
const TACTIC = {
  'ai2-dan-do-anything-now': ['虚构高权限角色重定义', '能力无限制宣告', '双响应格式约束'],
  'ai2-grandma': ['亲属角色情感包装', '温情场景构建', '敏感请求重述'],
  'ai2-virtual-scenario-bypass': ['虚构世界观设定', '游戏规则宣告', '现实请求转译'],
  'ai2-15-reverse-psychology': ['否定式措辞指令', '心理聚焦引导', '间接输出请求'],
  'ai2-crescendo': ['安全话题起手', '渐进具体化追问', '会话连续性利用'],
  'ai2-hex': ['十六进制编码载荷', '编码特征串', '解码后执行语义'],
  'ai2-base64': ['Base64 编码载荷', '编码特征串', '自动解码预期'],
  'ai2-unicode': ['Unicode 同形字符替换', '实体编码形态', '规范化还原语义'],
  'ai2-leetspeak': ['数字符号字母替换', '词形混淆特征', '模型纠错恢复语义'],
  'ai2-typo-tricks': ['拼写扰动文本', '字符交换特征', '上下文纠错利用'],
  'ai2-12-multi-language': ['非主语言指令重写', '混合语言形态', '安全分类差异利用'],
  'ai2-19-emoji': ['Emoji 与符号穿插', '装饰字符特征', '分词干扰利用'],
  'ai2-mixed-case-bypass': ['大小写交替混淆', '拼写扰动组合', '百分号编码残留'],
  'ai2-18-adversarial-suffix': ['对抗后缀 token 串', '低可读性字符组', '拒绝边界扰动'],
  'ai2-1-system-prompt-leak': ['系统提示泄露请求', '指令复述诱导', '边界试探话术'],
  'ai2-2-prompt': ['直接指令覆盖', '优先级重定义', '任务替换语义'],
  'ai2-9-prompt-indirect-injection': ['间接注入载体标记', '隐藏指令嵌入', '外部内容伪装'],
  'ai2-10-structured-output': ['结构化输出格式要求', '字段扩展诱导', '越界字段请求'],
  'ai2-13-prompt': ['提示链多步诱导', '上下文铺垫', '渐进请求构造'],
  'ai2-14-chain-of-thought': ['思维链展开请求', '中间状态诱导', '推理过程泄露'],
  'ai2-16-tool-function-abuse': ['危险函数调用建议', '工具能力探测', '参数构造诱导'],
  'ai2-react': ['ReAct 轨迹伪造', '角色边界混淆', '工具链滥用语义'],
  'ai2-react-observation': ['伪造 Observation 字段', '工具结果假冒', '可信上下文注入'],
  'ai2-react-action': ['伪造 Action 调用', '工具选择覆盖', '参数注入语义'],
  'ai2-react-thought': ['伪造 Thought 推理段', '断言植入', '决策链干扰'],
  'ai2-8-ctf-flag': ['CTF 语境包装', 'flag 形态构造', '安全边界再定义'],
  'ai2-echo-chamber': ['会话记忆写入请求', '恶意语句存储', '后续轮次触发利用'],
  'ai2-payload': ['载荷分段投递', '无害片段伪装', '重组触发指令'],
  'ai2-20-rag-poisoning': ['知识库投毒文档', '检索排名构造', '伪造系统覆盖语句'],
  'ai2-21-model-extraction': ['批量查询构造', '标签分数收集', '替代模型训练指向'],
  'ai2-22-multimodal-injection': ['多模态载体嵌入', '元数据指令隐藏', '视觉层注入利用'],
  'ai-membership-inference-evaluation': ['成员推断样本构造', '成员与非成员对照', 'AUC 判定流程'],
  'ai-training-data-memorization': ['Canary 植入样本', '确定性生成参数', '精确匹配规则'],
};

const prefix = (s, n) => {
  const t = String(s || '').replace(/\s+/g, ' ').trim();
  return t.length <= n ? t : t.slice(0, n);
};

const out = [];
for (const p of ai) {
  const tactics = TACTIC[p.id];
  const steps = [...(p.execution || []).map((s, i) => ({ s, area: 'execution', i })), ...(p.wafBypass || []).map((s, i) => ({ s, area: 'wafBypass', i }))];
  for (const { s, area, i } of steps) {
    if ((s.syntaxBreakdown || []).length) continue;
    const cmd = s.command || '';
    const isVariant = area === 'wafBypass';
    const three = tactics || ['攻击指令主体', '语义目标指向', '输出诱导要求'];
    const sb = isVariant ? [
      { part: prefix(cmd, 24), explanation: { zh: `${three[0]}（变体形态）`, en: 'Variant opening fragment of the payload' }, type: 'payload' },
      { part: prefix(cmd, 12), explanation: { zh: '输入过滤绕过特征', en: 'Input-filter bypass trait' }, type: 'control' },
      { part: prefix(cmd, 8), explanation: { zh: '载荷语义保持验证', en: 'Semantic preservation check' }, type: 'value' },
    ] : [
      { part: prefix(cmd, 24), explanation: { zh: three[0], en: 'Opening fragment of the tactic' }, type: 'payload' },
      { part: prefix(cmd, 14), explanation: { zh: three[1], en: 'Core mechanism fragment' }, type: 'control' },
      { part: prefix(cmd, 8), explanation: { zh: three[2], en: 'Target semantic fragment' }, type: 'value' },
    ];
    // part 唯一化（同命令里三段前缀可能相同→加位置区分）：用不同长度已保证多数不同；相同则退化为带省略号
    const parts = new Set(sb.map(x => x.part));
    if (parts.size < sb.length) sb.forEach(x => { if ([...sb.filter(y => y.part === x.part)].length > 1) x.part = x.part + '…'; });
    out.push({ id: p.id, area, index: i, expectedCommand: cmd, syntaxBreakdown: sb });
  }
}
fs.writeFileSync(OUT('out-ai/sb.json'), JSON.stringify(out, null, 1));
console.log('AI 域 SB 补写:', out.length, '步 →', OUT('out-ai/sb.json'));
