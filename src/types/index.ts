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
  attackChain?: AttackChainStep[];
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

export interface AttackChainStep {
  title: I18nText;
  description: I18nText;
  payload?: string;
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
  externalUrl?: string;
  systemLocked?: boolean;
}

export interface ToolCommandItem {
  name: I18nText;
  command: string;
  description: I18nText;
  syntaxBreakdown?: SyntaxPart[];
  examples?: I18nText[];
  platform?: 'windows' | 'linux' | 'all';
}

export interface ManagedCommand {
  id: string;
  name: I18nText;
  description: I18nText;
  command: string;
  platform: 'windows' | 'linux' | 'all';
  createdAt: string;
  updatedAt: string;
}

export interface ManagedToolCategory {
  id: string;
  name: I18nText;
  description?: I18nText;
  commands: ManagedCommand[];
  createdAt: string;
  updatedAt: string;
}

export interface SiteSettings {
  siteTitle: I18nText;
  siteSubtitle: I18nText;
  browserTitle: I18nText;
  logoIcon: string;
  logoUrl: string;
  projectUrl: string;
  xeyeEnabled: boolean;
}

export interface PublicData {
  settings: SiteSettings;
  payloads: PayloadItem[];
  tools: ToolCommand[];
  navigation: NavItem[];
  toolNavigation: NavItem[];
}

export interface PublicClientBuildItem {
  targetId?: string;
  platform: 'windows' | 'linux' | 'macos' | string;
  platformLabel: string;
  arch: string;
  archLabel: string;
  format: string;
  fileName: string;
  size: number;
  sha256: string;
  generatedAt: string;
  productName?: string;
  runtime?: string;
  distribution?: string;
  buildContractVersion?: number;
  codeSigningConfigured?: boolean;
  signingStatus?: 'configured' | 'unsigned' | string;
  mimeType?: string;
  downloadUrl: string;
  cpuFamily?: string;
  minOsVersion?: string;
  installType?: string;
  packageManager?: string;
  buildSource?: 'native-host' | 'official-shell' | string;
  shellVersion?: string;
  shellSha256?: string;
  performanceNotes?: string[];
  securityNotes?: string[];
  notes?: string[];
}

export interface PublicClientTargetInfo {
  id: string;
  platform: string;
  platformLabel: string;
  arch: string;
  archLabel: string;
  format: string;
  extension: string;
  recommended?: boolean;
  supported?: boolean;
  selectedByDefault?: boolean;
  reason?: string;
  cpuFamily?: string;
  minOsVersion?: string;
  installType?: string;
  packageManager?: string;
  requiresSigningNote?: string;
  source?: 'native-host' | 'official-shell' | 'unavailable' | string;
  shellVersion?: string;
  shellSigned?: boolean;
}

export interface PublicClientBuildInfo {
  available: boolean;
  latest: PublicClientBuildItem | null;
  offlineClient?: boolean;
  items?: PublicClientBuildItem[];
  generatedAt?: string;
  productName?: string;
  runtime?: string;
  distribution?: string;
  buildContractVersion?: number;
  codeSigningConfigured?: boolean;
  lastBuildFailed?: boolean;
  publicStats?: {
    payloads?: number;
    tools?: number;
    navigation?: number;
    toolNavigation?: number;
  };
  staleLatest?: {
    buildContractVersion?: number;
    runtime?: string;
    distribution?: string;
    generatedAt?: string;
  } | null;
  freshness?: {
    isCurrent: boolean;
    sourceCurrent: boolean;
    publicDataCurrent: boolean;
    reasons: string[];
    checkedAt: string;
  };
  targets?: PublicClientTargetInfo[];
  policies?: {
    performance?: Record<string, unknown>;
    security?: Record<string, unknown>;
  };
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
  group?: string;
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
