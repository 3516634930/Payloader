import { useEffect, useMemo, useRef } from 'react';
import { buildCtfGroups } from '../../utils/codec';
import type { OperationId } from '../../utils/codec';
import type { CtfWorkspaceProps } from '../../utils/ctf/modules';
import CodecWorkbench from '../CodecWorkbench';
import type { CodecWorkbenchHandle } from '../CodecWorkbench';

// 密码与编码域工作区：buildCtfGroups 四分组工作台原样迁入。
// 行为红线（批次 J）：分组结构、操作清单与重构前完全一致，仅由注册表挂载。
function CipherWorkspace({ registerFocus }: CtfWorkspaceProps) {
  const groups = useMemo(() => buildCtfGroups(), []);
  const workbenchRef = useRef<CodecWorkbenchHandle | null>(null);

  useEffect(() => {
    registerFocus?.((id: OperationId, seedInput?: string) => workbenchRef.current?.focusOperation(id, seedInput));
    return () => registerFocus?.(null);
  }, [registerFocus]);

  return <CodecWorkbench ref={workbenchRef} groups={groups} />;
}

export default CipherWorkspace;
