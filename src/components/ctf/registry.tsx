import type { ComponentType } from 'react';
import type { CtfWorkspaceProps, ModuleContract } from '../../utils/ctf/moduleContracts';
import { ctfModuleContracts } from '../../utils/ctf/moduleContracts';
import CipherWorkspace from './CipherWorkspace';
import CheatsheetWorkspace from './CheatsheetWorkspace';
import WebWorkspace from './WebWorkspace';
import FileForensicsWorkspace from './FileForensicsWorkspace';
import PwnWorkspace from './PwnWorkspace';
import ReverseWorkspace from './ReverseWorkspace';
import TrafficWorkspace from './traffic/TrafficWorkspace';

// CTF 模块注册表（组件层，T2 分层解耦）：把 moduleContracts 的纯数据契约与工作区组件组装成
// 完整注册表。utils/ctf 层保持零组件依赖（类型与数据可独立测试），组件引用只存在于本文件。
export interface ToolkitModule extends ModuleContract {
  Workspace: ComponentType<CtfWorkspaceProps>;
}

const WORKSPACES: Record<string, ComponentType<CtfWorkspaceProps>> = {
  cipher: CipherWorkspace,
  misc: FileForensicsWorkspace,
  traffic: TrafficWorkspace,
  web: WebWorkspace,
  reverse: ReverseWorkspace,
  pwn: PwnWorkspace,
  ai: CheatsheetWorkspace,
};

const workspaceFor = (id: string): ComponentType<CtfWorkspaceProps> => {
  const workspace = WORKSPACES[id];
  if (!workspace) throw new Error(`CTF 模块 ${id} 未在 registry 注册工作区组件`);
  return workspace;
};

export const ctfModules: ToolkitModule[] = ctfModuleContracts.map(contract => ({
  ...contract,
  Workspace: workspaceFor(contract.id),
}));
