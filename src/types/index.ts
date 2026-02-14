/** Bilingual text: either a plain string (treated as zh) or { zh, en } object */
export type I18nText = string | { zh: string; en: string };

export interface PayloadItem {
  id: string;
  name: I18nText;
  description: I18nText;
  category: I18nText;
  subCategory?: I18nText;
  tags: string[];
  prerequisites?: I18nText[];
  execution: PayloadExecution[];
  analysis?: I18nText;
  opsecTips?: I18nText[];
  wafBypass?: PayloadExecution[];
  edrBypass?: PayloadExecution[];
  references?: string[];
  tutorial?: TutorialContent;
}

export interface PayloadExecution {
  title: I18nText;
  command: string;
  syntaxBreakdown?: SyntaxPart[];
  description?: I18nText;
  platform?: 'windows' | 'linux' | 'all';
  requiresAdmin?: boolean;
}

export interface SyntaxPart {
  part: string;
  explanation: I18nText;
  type?: 'command' | 'parameter' | 'value' | 'operator' | 'variable' | 'header' | 'technique' | 'format' | 'function' | 'keyword' | 'encoding' | 'method' | 'domain' | 'tag' | 'path' | 'json' | 'concept' | 'char' | 'tool-mode';
}

export interface TutorialContent {
  overview: I18nText;
  vulnerability: I18nText;
  exploitation: I18nText;
  mitigation: I18nText;
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
}

export interface ToolCommand {
  id: string;
  name: I18nText;
  description: I18nText;
  category: I18nText;
  commands: ToolCommandItem[];
  installation?: I18nText;
  references?: string[];
}

export interface ToolCommandItem {
  name: I18nText;
  command: string;
  description: I18nText;
  syntaxBreakdown?: SyntaxPart[];
  examples?: I18nText[];
  platform?: 'windows' | 'linux' | 'all';
}

export interface NavItem {
  id: string;
  name: I18nText;
  icon?: string;
  children?: NavItem[];
  payloadId?: string;
  toolId?: string;
}

export interface GlobalVariable {
  key: string;
  value: string;
  description: I18nText;
}

export interface TreeNode {
  id: string;
  name: I18nText;
  children?: TreeNode[];
  isExpanded?: boolean;
  isSelected?: boolean;
  payloadId?: string;
  toolId?: string;
  icon?: string;
}
