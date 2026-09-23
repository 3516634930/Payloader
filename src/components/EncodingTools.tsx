import { useMemo } from 'react';
import CodecWorkbench from './CodecWorkbench';
import { buildPentestGroups } from '../utils/codec/audience';

// 渗透编解码视图：只渲染 pentest + both 受众的操作；CTF 解题专属工具在顶部导航「CTF 解题」标签页。
function EncodingTools() {
  const groups = useMemo(() => buildPentestGroups(), []);
  return (
    <CodecWorkbench
      groups={groups}
      registerTestApi
      heading={{ zh: '智能编解码工具', en: 'Smart Codec Tools' }}
      description={{
        zh: '面向真实渗透场景的编解码工作台，覆盖 Web、进制、加密、摘要、令牌和压缩场景；CTF 解题工具请使用顶部「CTF 解题」标签页。',
        en: 'A pentest-oriented codec workbench for web, binary, crypto, token, and compression operations; CTF solvers live in the CTF tab.',
      }}
    />
  );
}

export default EncodingTools;
