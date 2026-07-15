import type { GlobalVariable } from '../types';
import { defaultVariableValueMap } from '../data/globalVariables';

export interface ResolvedVariablePart {
  text: string;
  key?: string;
  raw?: string;
  value?: string;
}

const variableDefaults: Record<string, string> = defaultVariableValueMap;

const literalReplacementOrder = [
  'URL',
  'REDIR_URL',
  'CALLBACK_URL',
  'CALLBACK',
  'OOB_URL',
  'SSRF_URL',
  'BASE',
  'QUERY_STRING',
  'ENDPOINT',
  'PATH',
  'PROXY',
  'TARGET_IP',
  'DC_IP',
  'REAL_IP',
  'LHOST',
  'ATTACKER_IP',
  'ATTACKER_HOST',
  'TARGET',
  'HOST_HEADER',
  'TARGET_DOMAIN',
  'DC_HOST',
  'DNSLOG_DOMAIN',
  'OOB_DOMAIN',
  'COOKIE',
  'TOKEN',
  'API_KEY',
  'JWT_TOKEN',
  'HEADER_AUTH',
  'USERNAME',
  'PASSWORD',
  'DOMAIN',
  'SESSION_COOKIE',
  'PHPSESSID',
  'SID',
  'CONTENT_TYPE',
  'USER_AGENT',
  'REFERER',
  'ORIGIN',
  'X_FORWARDED_FOR',
  'WORDLIST',
  'USERLIST',
  'PASSLIST',
  'HASH_FILE',
  'FILE_PATH',
  'WINDOWS_FILE',
  'WEB_ROOT',
  'SHELL_NAME',
  'UPLOAD_PATH',
  'COMMAND',
  'PORT',
  'LPORT',
];

const legacyLiteralAliases: Array<{ literal: string; key: string }> = [
  { literal: 'target_ip', key: 'TARGET_IP' },
  { literal: 'TARGET_IP', key: 'TARGET_IP' },
  { literal: 'dc_ip', key: 'DC_IP' },
  { literal: 'attacker_ip', key: 'ATTACKER_IP' },
  { literal: 'ATTACKER_IP', key: 'ATTACKER_IP' },
  { literal: 'PORT', key: 'PORT' },
  { literal: 'attacker.com', key: 'ATTACKER_HOST' },
  { literal: 'attacker.test', key: 'ATTACKER_HOST' },
  { literal: 'your_dnslog.com', key: 'DNSLOG_DOMAIN' },
  { literal: 'your-xss-hunter.com', key: 'OOB_DOMAIN' },
  { literal: 'evil.com', key: 'ATTACKER_HOST' },
  { literal: 'http://127.0.0.1:8080', key: 'PROXY' },
  { literal: '127.0.0.1:8080', key: 'PROXY' },
  { literal: 'PHPSESSID=xxx', key: 'COOKIE' },
  { literal: 'PHPSESSID=abc123', key: 'COOKIE' },
  { literal: 'session=abc', key: 'SESSION_COOKIE' },
  { literal: 'Authorization: Bearer token', key: 'HEADER_AUTH' },
  { literal: 'Authorization: Bearer xxx', key: 'HEADER_AUTH' },
  { literal: 'Authorization: Bearer eyJ...', key: 'HEADER_AUTH' },
  { literal: 'wordlist.txt', key: 'WORDLIST' },
  { literal: 'users.txt', key: 'USERLIST' },
  { literal: 'passwords.txt', key: 'PASSLIST' },
  { literal: 'hash.txt', key: 'HASH_FILE' },
  { literal: '/etc/passwd', key: 'FILE_PATH' },
  { literal: 'C:/windows/win.ini', key: 'WINDOWS_FILE' },
  { literal: 'C:\\windows\\win.ini', key: 'WINDOWS_FILE' },
  { literal: '/var/www/html', key: 'WEB_ROOT' },
  { literal: 'shell.php', key: 'SHELL_NAME' },
];

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const buildVariableMap = (variables: GlobalVariable[]) => new Map(
  variables
    .filter(variable => variable.key)
    .map(variable => [variable.key, String(variable.value ?? '')])
);

const normalizeUrlInput = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    return new URL(trimmed);
  } catch {
    try {
      return new URL(`https://${trimmed.replace(/^\/+/, '')}`);
    } catch {
      return null;
    }
  }
};

const hasCustomValue = (variableMap: Map<string, string>, key: string) => {
  const value = variableMap.get(key);
  if (typeof value !== 'string' || !value.trim()) return false;
  return variableDefaults[key] ? value !== variableDefaults[key] : true;
};

const deriveUrlVariables = (variables: GlobalVariable[]) => {
  const variableMap = buildVariableMap(variables);
  const urlValue = variableMap.get('URL');
  const hasCustomUrl = hasCustomValue(variableMap, 'URL');
  const parsedUrl = urlValue ? normalizeUrlInput(urlValue) : null;

  if (hasCustomUrl && parsedUrl) {
    if (!hasCustomValue(variableMap, 'PROTOCOL')) variableMap.set('PROTOCOL', parsedUrl.protocol.replace(/:$/, ''));
    if (!hasCustomValue(variableMap, 'TARGET')) variableMap.set('TARGET', parsedUrl.host);
    if (!hasCustomValue(variableMap, 'TARGET_DOMAIN')) variableMap.set('TARGET_DOMAIN', parsedUrl.hostname);
    if (!hasCustomValue(variableMap, 'TARGET_PORT')) {
      variableMap.set('TARGET_PORT', parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80'));
    }
    if (!hasCustomValue(variableMap, 'HOST_HEADER')) variableMap.set('HOST_HEADER', parsedUrl.host);
    if (!hasCustomValue(variableMap, 'BASE')) variableMap.set('BASE', `${parsedUrl.protocol}//${parsedUrl.host}`);
    if (!hasCustomValue(variableMap, 'PATH')) variableMap.set('PATH', parsedUrl.pathname || '/');
    if (!hasCustomValue(variableMap, 'ENDPOINT')) variableMap.set('ENDPOINT', parsedUrl.pathname || '/');
    if (!hasCustomValue(variableMap, 'QUERY_STRING')) variableMap.set('QUERY_STRING', parsedUrl.search.replace(/^\?/, ''));
    if (!hasCustomValue(variableMap, 'REFERER')) variableMap.set('REFERER', `${parsedUrl.protocol}//${parsedUrl.host}/`);
    const firstParam = parsedUrl.searchParams.entries().next().value as [string, string] | undefined;
    if (firstParam) {
      if (!hasCustomValue(variableMap, 'PARAM')) variableMap.set('PARAM', firstParam[0]);
      if (!hasCustomValue(variableMap, 'PARAM_VALUE')) variableMap.set('PARAM_VALUE', firstParam[1]);
    }
  }

  const target = variableMap.get('TARGET') || variableDefaults.TARGET;
  if (!hasCustomValue(variableMap, 'BASE') && target) {
    variableMap.set('BASE', `https://${target}`);
  }

  if (!hasCustomValue(variableMap, 'HOST_HEADER') && target) {
    variableMap.set('HOST_HEADER', target);
  }

  const param = variableMap.get('PARAM');
  const paramValue = variableMap.get('PARAM_VALUE');
  if (param && paramValue && !hasCustomValue(variableMap, 'QUERY_STRING')) {
    variableMap.set('QUERY_STRING', `${param}=${paramValue}`);
  }

  if (!hasCustomUrl && target) {
    const base = variableMap.get('BASE') || `https://${target}`;
    const path = variableMap.get('PATH') || '/';
    const query = variableMap.get('QUERY_STRING') || '';
    variableMap.set('URL', `${base}${path.startsWith('/') ? path : `/${path}`}${query ? `?${query}` : ''}`);
  }

  const token = variableMap.get('TOKEN');
  if (token && !hasCustomValue(variableMap, 'HEADER_AUTH')) {
    variableMap.set('HEADER_AUTH', `Authorization: Bearer ${token}`);
  }

  const lport = variableMap.get('LPORT');
  if (lport && !hasCustomValue(variableMap, 'PORT')) {
    variableMap.set('PORT', lport);
  }

  const phpsessid = variableMap.get('PHPSESSID');
  const sessionCookie = variableMap.get('SESSION_COOKIE');
  if (!hasCustomValue(variableMap, 'COOKIE')) {
    variableMap.set('COOKIE', [
      phpsessid ? `PHPSESSID=${phpsessid}` : '',
      sessionCookie || '',
    ].filter(Boolean).join('; '));
  }

  const attackerHost = variableMap.get('ATTACKER_HOST');
  if (attackerHost && !hasCustomValue(variableMap, 'CALLBACK_URL')) {
    variableMap.set('CALLBACK_URL', `https://${attackerHost}/callback`);
  }

  if (attackerHost && !hasCustomValue(variableMap, 'CALLBACK')) {
    variableMap.set('CALLBACK', attackerHost);
  }

  const oobDomain = variableMap.get('OOB_DOMAIN');
  if (oobDomain && !hasCustomValue(variableMap, 'OOB_URL')) {
    variableMap.set('OOB_URL', `https://${oobDomain}/ping`);
  }

  return variableMap;
};

const placeholderPatterns = (key: string) => {
  const escaped = escapeRegExp(key);
  return [
    new RegExp(`\\{\\{\\s*${escaped}\\s*\\}\\}`, 'g'),
    new RegExp(`\\$\\{\\s*${escaped}\\s*\\}`, 'g'),
    new RegExp(`\\{\\s*${escaped}\\s*\\}`, 'g'),
    new RegExp(`%${escaped}%`, 'g'),
  ];
};

const literalPattern = (literal: string) => (
  new RegExp(`(^|[^A-Za-z0-9_])(${escapeRegExp(literal)})(?=$|[^A-Za-z0-9_])`, 'g')
);

const queryAssignmentPattern = (name: string, value: string) => (
  new RegExp(`(^|[?&\\s])(${escapeRegExp(name)}=${escapeRegExp(value)})(?=$|[&#\\s%'";)<>+\\-])`, 'g')
);

const targetUrlWithQueryPattern = () => (
  new RegExp(`(^|[^A-Za-z0-9_])((?:https?:\\/\\/)?${escapeRegExp(variableDefaults.TARGET)}(?::\\d+)?(?:\\/[^\\s"'<>?\`)]+)?\\?[^\\s"'<>?\`)]+)`, 'g')
);

const defaultQueryAssignmentSearch = () => (
  new RegExp(`(^|[?&])${escapeRegExp(variableDefaults.PARAM)}=${escapeRegExp(variableDefaults.PARAM_VALUE)}(?=$|[&#%'";)<>+\\-]|%[0-9a-fA-F]{2})`)
);

const replaceParts = (
  parts: ResolvedVariablePart[],
  pattern: RegExp,
  key: string,
  value: string
): ResolvedVariablePart[] => parts.flatMap(part => {
  if (part.key || !part.text) return [part];

  const nextParts: ResolvedVariablePart[] = [];
  let lastIndex = 0;

  for (const match of part.text.matchAll(pattern)) {
    const fullMatch = match[0] || '';
    const raw = match[2] || fullMatch;
    const rawOffset = match[2] ? fullMatch.indexOf(raw) : 0;
    const rawStart = (match.index || 0) + rawOffset;
    const rawEnd = rawStart + raw.length;

    if (rawStart > lastIndex) {
      nextParts.push({ text: part.text.slice(lastIndex, rawStart) });
    }

    nextParts.push({ text: value, key, raw, value });
    lastIndex = rawEnd;
  }

  if (!nextParts.length) return [part];
  if (lastIndex < part.text.length) {
    nextParts.push({ text: part.text.slice(lastIndex) });
  }
  return nextParts;
});

const changedDefaultKeys = (variableMap: Map<string, string>) => literalReplacementOrder.filter(key => {
  const defaultValue = variableDefaults[key];
  const currentValue = variableMap.get(key);
  return typeof defaultValue === 'string' && typeof currentValue === 'string' && currentValue !== defaultValue;
});

const replaceLegacyLiteralParts = (
  parts: ResolvedVariablePart[],
  variableMap: Map<string, string>
) => {
  let nextParts = parts;

  for (const { literal, key } of legacyLiteralAliases) {
    const currentValue = variableMap.get(key);
    if (!currentValue || currentValue === literal) continue;
    nextParts = replaceParts(nextParts, literalPattern(literal), key, currentValue);
  }

  return nextParts;
};

const hasUserCustomValue = (variables: GlobalVariable[], key: string) => (
  hasCustomValue(buildVariableMap(variables), key)
);

const replaceTargetUrlParts = (
  parts: ResolvedVariablePart[],
  variableMap: Map<string, string>,
  sourceVariables: GlobalVariable[]
) => {
  const currentUrl = variableMap.get('URL');
  if (!currentUrl || !hasUserCustomValue(sourceVariables, 'URL')) return parts;

  return replaceParts(
    parts,
    targetUrlWithQueryPattern(),
    'URL',
    currentUrl
  ).map(part => {
    if (part.key !== 'URL' || !part.raw) return part;
    if (!part.raw.includes(variableDefaults.TARGET)) return part;
    return defaultQueryAssignmentSearch().test(part.raw)
      ? part
      : { text: part.raw };
  });
};

const replaceQueryAssignmentParts = (
  parts: ResolvedVariablePart[],
  variableMap: Map<string, string>
) => {
  const param = variableMap.get('PARAM');
  const paramValue = variableMap.get('PARAM_VALUE');
  if (!param || !paramValue) return parts;
  if (param === variableDefaults.PARAM && paramValue === variableDefaults.PARAM_VALUE) return parts;

  return replaceParts(
    parts,
    queryAssignmentPattern(variableDefaults.PARAM, variableDefaults.PARAM_VALUE),
    'QUERY_STRING',
    `${param}=${paramValue}`
  );
};

export const resolveVariableParts = (text: string, variables: GlobalVariable[]): ResolvedVariablePart[] => {
  const variableMap = deriveUrlVariables(variables);
  let parts: ResolvedVariablePart[] = [{ text: String(text ?? '') }];

  for (const [key, value] of variableMap.entries()) {
    for (const pattern of placeholderPatterns(key)) {
      parts = replaceParts(parts, pattern, key, value);
    }
  }

  parts = replaceTargetUrlParts(parts, variableMap, variables);

  for (const key of changedDefaultKeys(variableMap)) {
    const defaultValue = variableDefaults[key];
    const currentValue = variableMap.get(key);
    if (!defaultValue || typeof currentValue !== 'string') continue;
    parts = replaceParts(parts, literalPattern(defaultValue), key, currentValue);
  }

  parts = replaceLegacyLiteralParts(parts, variableMap);

  return replaceQueryAssignmentParts(parts, variableMap);
};

export const resolveVariableText = (text: string, variables: GlobalVariable[]) => (
  resolveVariableParts(text, variables).map(part => part.text).join('')
);
