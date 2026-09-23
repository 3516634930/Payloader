import { useEffect, useMemo, useRef } from 'react';
import { buildCtfGroups } from '../../utils/codec/audience';
import type { OperationId } from '../../utils/codec/types';
import type { CtfWorkspaceProps } from '../../utils/ctf/modules';
import CodecWorkbench from '../CodecWorkbench';
import type { CodecWorkbenchHandle } from '../CodecWorkbench';

// 密码与编码域工作区：buildCtfGroups 四分组工作台迁入，顶部菜单栏主导航（随波逐流形态）。
// 行为红线：分组结构、操作清单与受众分流不变；mode="ctf" 只改导航与展示层形态。
function CipherWorkspace({ registerFocus }: CtfWorkspaceProps) {
  const groups = useMemo(() => buildCtfGroups(), []);
  const workbenchRef = useRef<CodecWorkbenchHandle | null>(null);

  useEffect(() => {
    registerFocus?.((id: OperationId, seedInput?: string) => workbenchRef.current?.focusOperation(id, seedInput));
    return () => registerFocus?.(null);
  }, [registerFocus]);

  return <CodecWorkbench ref={workbenchRef} groups={groups} mode="ctf" />;
}

export default CipherWorkspace;
