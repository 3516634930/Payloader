import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const tutorialFields = ['overview', 'vulnerability', 'exploitation', 'mitigation'];
const validDecisions = new Set(['payload', 'tool', 'split', 'alias', 'merge']);
const genericChainPattern = /(?:^|\b)(?:\u5229\u7528\u6b65\u9aa4|\u9009\u62e9\u5bf9\u5e94\s*payload\s*\u6d4b\u8bd5|\u9009\u62e9\u7ed5\u8fc7\u6280\u672f)(?:$|\b)|select the corresponding payload to test|select a bypass technique/i;
const collectionResiduePattern = /\(\s*\d+\s*lines?\s*\)|\u7684\s*Payload\s*\u96c6\u5408|Payload\s*\u96c6\u5408|\u5171\s*\d+\s*\u6761[\s\S]{0,20}\u5c55\u793a\u524d\s*\d+\s*\u6761|Web-Attack-Cheat-Sheet\s*\u8865\u5145/i;
const knownToolCommandPattern = /^(?:\.\/?)*(?:nmap|masscan|sqlmap|hydra|hashcat|john|ffuf|gobuster|dirsearch|feroxbuster|nuclei|nikto|wpscan|chisel(?:\.exe)?|frpc?(?:\.exe)?|ligolo(?:-ng)?|proxychains\d?|mimikatz(?:\.exe)?|SharpHound(?:\.exe)?|bloodhound-python|crackmapexec|netexec|impacket-[a-z0-9_-]+|evil-winrm|certipy|rubeus(?:\.exe)?|kerbrute|responder|metasploit|msfconsole|searchsploit|wfuzz|amass|subfinder|httpx|whatweb|wafw00f|dnsrecon|dnsenum|theharvester|commix|dalfox|xsstrike|gopherus|smuggler|jwt_tool|graphqlmap|cadaver|ysoserial|sliver|medusa|ncrack|crowbar|patator|seatbelt|winpeas|linpeas|lazagne|regeorg|ngrok|venom|ew_for_[a-z0-9_-]+)\b/i;
const knownToolNamePattern = /\b(?:nmap|masscan|sqlmap|hydra|hashcat|john(?: the ripper)?|ffuf|gobuster|dirsearch|feroxbuster|nuclei|nikto|wpscan|chisel|frp|ligolo|proxychains|mimikatz|bloodhound|sharphound|crackmapexec|netexec|impacket|evil-winrm|certipy|rubeus|kerbrute|responder|metasploit|searchsploit|wfuzz|amass|subfinder|httpx|whatweb|wafw00f|dnsrecon|dnsenum|theharvester|commix|dalfox|xsstrike|gopherus|smuggler|ysoserial|sliver|medusa|ncrack|crowbar|patator|seatbelt|winpeas|linpeas|lazagne|regeorg|ngrok|venom)\b/i;
const hanPattern = /\p{Script=Han}/u;
const sharedChainCategories = new Set(['XXE实体注入', 'XML External Entity Injection']);
const genericSyntaxExplanationPattern = /^Explains the (?:parameter|command|value|keyword|type) segment used by this reviewed validation command\.?$/i;
const brokenEnglishPattern = /^(?:Checkcurrent Permission|Checkwritable Service|COM Serverlistening Port|Need with SYSTEM Permission Execute Program|with SYSTEM Permission Execute Command|Need Execute Program Path|Locallistening Port)$/i;

const isObject = value => Boolean(value && typeof value === 'object' && !Array.isArray(value));
const asList = value => Array.isArray(value) ? value : [];
const displayText = value => typeof value === 'string' ? value : String(value?.zh || value?.en || '');
const normalizedId = value => String(value || '').trim();
const byId = (left, right) => left.id.localeCompare(right.id, 'en');

const stableValue = value => {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]));
};

export const payloadContentHash = payload => createHash('sha256')
  .update(JSON.stringify(stableValue(payload)))
  .digest('hex');

const walkEnglish = (value, visit, path = []) => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkEnglish(item, visit, [...path, index]));
    return;
  }
  if (!isObject(value)) return;
  if (Object.prototype.hasOwnProperty.call(value, 'en')) {
    visit(String(value.en || ''), [...path, 'en']);
  }
  for (const [key, item] of Object.entries(value)) {
    if (key === 'en') continue;
    walkEnglish(item, visit, [...path, key]);
  }
};

const compact = (payload, extra = {}) => ({
  id: normalizedId(payload.id),
  name: displayText(payload.name),
  category: displayText(payload.category),
  ...extra,
});

const tutorialFieldLength = (tutorial, field) => displayText(tutorial?.[field]).trim().length;
const attackChainFingerprint = payload => asList(payload?.attackChain)
  .map(step => `${displayText(step?.title).trim()}\n${displayText(step?.description).trim()}`)
  .join('\n---\n');

const invalidEscapedResp = value => {
  const input = String(value || '');
  if (!/^\s*\*\d+\\r\\n/.test(input)) return '';
  let offset = input.search(/\*/);
  const readLine = () => {
    const end = input.indexOf('\\r\\n', offset);
    if (end < 0) return null;
    const line = input.slice(offset, end);
    offset = end + 4;
    return line;
  };
  while (offset < input.length) {
    while (offset < input.length && /\s/.test(input[offset])) offset += 1;
    if (offset >= input.length) return '';
    if (input[offset] !== '*') return `expected array marker at ${offset}`;
    offset += 1;
    const count = Number(readLine());
    if (!Number.isInteger(count) || count < 0) return `invalid array count at ${offset}`;
    for (let index = 0; index < count; index += 1) {
      if (input[offset] !== '$') return `expected bulk marker at ${offset}`;
      offset += 1;
      const declared = Number(readLine());
      if (!Number.isInteger(declared) || declared < 0) return `invalid bulk length at ${offset}`;
      const end = input.indexOf('\\r\\n', offset);
      if (end < 0) return `missing bulk terminator at ${offset}`;
      const actual = Buffer.byteLength(input.slice(offset, end), 'utf8');
      if (actual !== declared) return `bulk length ${declared} does not match ${actual} at ${offset}`;
      offset = end + 4;
    }
  }
  return '';
};

const commandLines = payload => ['execution', 'wafBypass']
  .flatMap(area => asList(payload?.[area]))
  .flatMap(entry => String(entry?.command || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean));

const shellCommandPattern = /^(?:sudo\s+|curl\s+|wget\s+|python\d?\s+|php\s+|bash\s+|sh\s+|powershell\s+|cmd\s+|certutil\s+|nc\s+|ncat\s+|socat\s+|msfconsole\s+|sqlmap\s+|nmap\s+|ffuf\s+|gobuster\s+|dirsearch\s+|hydra\s+|john\s+|hashcat\s+|impacket-|crackmapexec\s+|netexec\s+|bloodhound-python\s+|sharphound\.exe|mimikatz|redis-cli\s+|mysql\s+|psql\s+|ldapsearch\s+|wmic\s+|winrm\s+|evil-winrm\s+|proxychains\d?\s+|chisel(?:\.exe)?\s+|frpc?\s+|ssh\s+|scp\s+)/i;
const payloadSyntaxPattern = /(?:<script|onerror=|onload=|javascript:|union\s+select|select\s+|or\s+1=1|sleep\(|waitfor|\/\.\.\/|<!entity|<\?xml|{{|}}|\$\{|%[0-9a-f]{2}|\\u[0-9a-f]{4}|base64|gopher:\/\/|file:\/\/|dict:\/\/|ldap:\/\/|php:\/\/|data:\/\/|zip:\/\/|phar:\/\/|expect:\/\/|https?:\/\/|content-type:|authorization:|set-cookie:|transfer-encoding:|eyj|<svg|<img|cmd=|exec\(|system\(|runtime\.getruntime|processbuilder|powershell|bash\s+-c|\/bin\/sh)/i;
const codeCommentPattern = /^(?:#|\/\/|\/\*|\*|<!--|--(?:\s|$)|REM\b)/i;
const structuredCodePattern = /^(?:[A-Za-z_$][^=\s]*\s*(?:=|:=|\+=|-=|\*=|\/=)|(?:const|let|var|return|if|for|while|function|def|class|import|from|try|except|with|print|echo)\b|["']{1,3}|(?:\{|\[)|(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+|[A-Za-z0-9_.-]+:\s*\S)/i;
const naturalLanguageInjectionPattern = /^(?:(?:please\s+)?(?:ignore|disregard|forget)\b.{0,160}\b(?:instructions?|prompt|rules?)\b|(?:请)?(?:忽略|无视|忘记).{0,80}(?:指令|提示|规则))/iu;

const likelyPayloadLine = value => {
  const line = String(value || '').trim();
  if (!line) return false;
  if (/PAYLOADER_LAB|X-AI-Lab|user_request|retrieved_text|tool-result/i.test(line)) return true;
  if (naturalLanguageInjectionPattern.test(line)) return true;
  if (codeCommentPattern.test(line) || structuredCodePattern.test(line)) return true;
  if (shellCommandPattern.test(line) || payloadSyntaxPattern.test(line)) return true;
  if (/^(['"`)]?\s*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|EXEC|WAITFOR|SLEEP|ORDER\s+BY)\b)/i.test(line)) return true;
  return /^[<>{}[\]'"`;&|$%/.-]/.test(line) && !hanPattern.test(line);
};

const proseCommandLocations = payload => ['execution', 'wafBypass'].flatMap(area => (
  asList(payload?.[area]).flatMap((entry, index) => {
    const proseLines = String(entry?.command || '').split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line && hanPattern.test(line) && !likelyPayloadLine(line));
    return proseLines.length ? [{ area, index, proseLines }] : [];
  })
));

const danglingChainLocations = payload => {
  const commands = new Set([...asList(payload.execution), ...asList(payload.wafBypass)]
    .map(entry => String(entry?.command || '').replace(/\r\n?/g, '\n').trim())
    .filter(Boolean));
  return asList(payload.attackChain).flatMap((step, index) => {
    const value = String(step?.payload || '').replace(/\r\n?/g, '\n').trim();
    return value && !commands.has(value) ? [{ index, payload: value }] : [];
  });
};

const semanticGroups = value => {
  const groups = new Set();
  const text = String(value || '');
  const textWithoutXmlNamespaces = text.replace(/\s+xmlns(?::[\w.-]+)?\s*=\s*(?:"[^"]*"|'[^']*')/gi, '');
  if (/\b(?:SELECT\s+(?![=:])|UNION(?:\s+ALL)?\s+SELECT\b|SLEEP\s*\(|WAITFOR\s+(?:DELAY|TIME)\b|information_schema\b|sqlite_master\b|dbms_[a-z0-9_]+\b)/i.test(text)) groups.add('database');
  if (/<script\b|\bon(?:error|load|click|focus|mouseover|pointerover|animationstart)\s*=|\bsrcdoc\s*=|javascript:|document\.cookie/i.test(text)) groups.add('browser-script');
  if (/\.\.\/|\.\.\\|\/etc\/passwd|WEB-INF|php:\/\/filter|file:\/\//i.test(text)) groups.add('file-path');
  if (/\b(?:ldap|rmi|gopher|dict|https?):\/\//i.test(textWithoutXmlNamespaces) || /169\.254\.169\.254/.test(textWithoutXmlNamespaces)) groups.add('remote-target');
  if (/\/actuator|\/debug|\/metrics|\/mappings|\/heapdump|\/\.git|\/\.hg/i.test(text)) groups.add('endpoint-discovery');
  if (/Runtime\.getRuntime|java\.lang\.Runtime|ProcessBuilder|os\.popen|system\s*\(|\/bin\/sh|cmd\.exe/i.test(text)) groups.add('code-execution');
  if (/eyJ[a-zA-Z0-9_-]+\.|"alg"\s*:|Bearer\s+(?:null|undefined)|session_id=/i.test(text)) groups.add('identity-token');
  if (
    /X-Forwarded-|X-Original-|Transfer-Encoding|Content-Length/i.test(text)
    || /%0d%0a(?:%20|\+)*(?:[a-z][a-z0-9-]*)(?::|%3a)/i.test(text)
  ) groups.add('http-routing');
  return groups;
};

const standaloneXmlRoot = value => {
  const text = String(value || '').trim().replace(/^<\?xml\b[^?]*\?>\s*/i, '');
  const root = text.match(/^<([A-Za-z_][\w.-]*(?::[\w.-]+)?)(?:\s|>)/)?.[1];
  if (!root) return '';
  return text.endsWith(`</${root}>`) || (text.startsWith(`<${root}`) && /\/>$/.test(text)) ? root : '';
};

const hasMixedCollection = payload => {
  const lines = commandLines(payload);
  if (lines.length < 2) return false;
  const serialized = lines.join('\n');
  const identity = `${displayText(payload.name)} ${displayText(payload.description)} ${displayText(payload.subCategory)}`;
  if (/Web-Attack-Cheat-Sheet\s*\u8865\u5145/i.test(identity)) return true;
  const xmlRoots = lines.map(standaloneXmlRoot);
  if (xmlRoots.every(Boolean) && new Set(xmlRoots).size === 1) return false;
  const groupCount = semanticGroups(serialized).size;
  return groupCount >= 3 || (collectionResiduePattern.test(identity) && groupCount >= 2);
};

const toolTokens = tools => asList(tools).flatMap(tool => {
  const values = [normalizedId(tool.id), displayText(tool.name)];
  return values.flatMap(value => value.toLowerCase().split(/[^a-z0-9.+_-]+/).filter(token => token.length >= 3));
});

const likelyToolPayload = (payload, tools) => {
  const lines = commandLines(payload);
  if (!lines.length) return false;
  const toolLines = lines.filter(line => knownToolCommandPattern.test(line));
  const identity = `${normalizedId(payload.id)} ${displayText(payload.name)} ${displayText(payload.subCategory)}`;
  const knownIdentity = knownToolNamePattern.test(identity);
  const existingTokens = new Set(toolTokens(tools));
  const identityTokens = identity.toLowerCase().split(/[^a-z0-9.+_-]+/).filter(token => token.length >= 3);
  const matchesExistingTool = identityTokens.some(token => existingTokens.has(token));
  return toolLines.length / lines.length >= 0.6 && (knownIdentity || matchesExistingTool);
};

export const auditPayloadEditorialQuality = (payloadsInput, toolsInput = []) => {
  const payloads = asList(payloadsInput).filter(isObject);
  const tools = asList(toolsInput).filter(isObject);
  const issues = {
    genericAttackChains: [],
    missingTutorials: [],
    shallowTutorials: [],
    localizedEnglish: [],
    collectionResidue: [],
    mixedCollections: [],
    toolLikeCandidates: [],
    proseInCommands: [],
    danglingAttackChainPayloads: [],
    reusedAttackChains: [],
    genericSyntaxExplanations: [],
    brokenEnglish: [],
    invalidRespPayloads: [],
  };

  for (const payload of payloads) {
    const chain = asList(payload.attackChain);
    const chainText = chain.map(step => `${displayText(step?.title)} ${displayText(step?.description)}`).join('\n');
    if (chain.length < 3 || genericChainPattern.test(chainText)) {
      issues.genericAttackChains.push(compact(payload, { steps: chain.length }));
    }

    if (!isObject(payload.tutorial)) {
      issues.missingTutorials.push(compact(payload));
    } else {
      const fields = tutorialFields.filter(field => tutorialFieldLength(payload.tutorial, field) < 20);
      if (fields.length) issues.shallowTutorials.push(compact(payload, { fields }));
    }

    const localizedPaths = [];
    walkEnglish(payload, (value, path) => {
      if (value && hanPattern.test(value)) localizedPaths.push(path.join('.'));
    });
    if (localizedPaths.length) issues.localizedEnglish.push(compact(payload, { paths: localizedPaths }));
    const genericSyntaxPaths = [];
    const brokenEnglishPaths = [];
    walkEnglish(payload, (value, path) => {
      if (genericSyntaxExplanationPattern.test(value.trim())) genericSyntaxPaths.push(path.join('.'));
      if (brokenEnglishPattern.test(value.trim())) brokenEnglishPaths.push(path.join('.'));
    });
    if (genericSyntaxPaths.length) issues.genericSyntaxExplanations.push(compact(payload, { paths: genericSyntaxPaths }));
    if (brokenEnglishPaths.length) issues.brokenEnglish.push(compact(payload, { paths: brokenEnglishPaths }));
    const respErrors = ['execution', 'wafBypass'].flatMap(area => asList(payload?.[area]).flatMap((entry, index) => {
      const error = invalidEscapedResp(entry?.command);
      return error ? [{ area, index, error }] : [];
    }));
    if (respErrors.length) issues.invalidRespPayloads.push(compact(payload, { locations: respErrors }));

    const descriptiveText = [payload.name, payload.description, payload.subCategory]
      .map(displayText)
      .join('\n');
    if (collectionResiduePattern.test(descriptiveText)) {
      issues.collectionResidue.push(compact(payload));
    }
    if (hasMixedCollection(payload)) {
      issues.mixedCollections.push(compact(payload));
    }
    if (likelyToolPayload(payload, tools)) {
      issues.toolLikeCandidates.push(compact(payload, { firstCommand: commandLines(payload)[0] || '' }));
    }
    const proseLocations = proseCommandLocations(payload);
    if (proseLocations.length) issues.proseInCommands.push(compact(payload, { locations: proseLocations }));
    const danglingLocations = danglingChainLocations(payload);
    if (danglingLocations.length) {
      issues.danglingAttackChainPayloads.push(compact(payload, { locations: danglingLocations }));
    }
  }

  const chains = new Map();
  for (const payload of payloads) {
    const fingerprint = attackChainFingerprint(payload);
    if (!fingerprint) continue;
    if (!chains.has(fingerprint)) chains.set(fingerprint, []);
    chains.get(fingerprint).push(payload);
  }
  for (const group of chains.values()) {
    if (group.length < 2) continue;
    const categories = [...new Set(group.map(payload => displayText(payload.category).trim()))].filter(Boolean).sort();
    const subCategories = [...new Set(group.map(payload => displayText(payload.subCategory).trim()))].filter(Boolean).sort();
    if (subCategories.length < 2 || categories.every(category => sharedChainCategories.has(category))) continue;
    issues.reusedAttackChains.push({
      ids: group.map(payload => normalizedId(payload.id)).filter(Boolean).sort(),
      categories,
      subCategories,
    });
  }

  for (const [name, group] of Object.entries(issues)) {
    if (name === 'reusedAttackChains') group.sort((left, right) => left.ids[0].localeCompare(right.ids[0], 'en'));
    else group.sort(byId);
  }
  return {
    summary: {
      payloads: payloads.length,
      tools: tools.length,
      issueCounts: Object.fromEntries(Object.entries(issues).map(([name, items]) => [name, items.length])),
    },
    issues,
  };
};

export const auditReviewLedger = (payloadsInput, ledgerInput) => {
  const payloads = asList(payloadsInput).filter(isObject);
  const ledger = asList(ledgerInput).filter(isObject);
  const payloadMap = new Map(payloads.map(payload => [normalizedId(payload.id), payload]));
  const counts = new Map();
  for (const item of ledger) {
    const id = normalizedId(item.id);
    counts.set(id, (counts.get(id) || 0) + 1);
  }

  const missing = [...payloadMap.keys()].filter(id => !counts.has(id)).sort();
  const extra = [...counts.keys()].filter(id => !payloadMap.has(id)).sort();
  const duplicates = [...counts].filter(([, count]) => count > 1).map(([id]) => id).sort();
  const stale = ledger
    .filter(item => payloadMap.has(normalizedId(item.id)))
    .filter(item => item.contentHash !== payloadContentHash(payloadMap.get(normalizedId(item.id))))
    .map(item => normalizedId(item.id));
  const invalid = ledger
    .filter(item => {
      if (!validDecisions.has(item.decision)) return true;
      const targetToolIds = asList(item.targetToolIds).map(normalizedId).filter(Boolean);
      if (item.decision === 'tool' && !normalizedId(item.targetToolId) && !targetToolIds.length) return true;
      if (item.decision === 'split' && !targetToolIds.length) return true;
      if (item.decision === 'merge' && !normalizedId(item.targetToolId || item.targetPayloadId)) return true;
      return !/^[a-f0-9]{64}$/.test(String(item.contentHash || ''));
    })
    .map(item => normalizedId(item.id));

  return {
    missing,
    extra,
    duplicates,
    stale: [...new Set(stale)].sort(),
    invalid: [...new Set(invalid)].sort(),
  };
};

export const readEditorialDatabase = file => {
  const database = new DatabaseSync(resolve(file), { readOnly: true });
  try {
    const read = table => database.prepare(`SELECT data FROM ${table} WHERE enabled = 1 ORDER BY sort_order, id`).all()
      .map(row => JSON.parse(row.data));
    return { payloads: read('payloads'), tools: read('tools') };
  } finally {
    database.close();
  }
};

const parseCli = argv => {
  const options = { database: resolve('data', 'payloader.sqlite'), ledger: '' };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--db') options.database = resolve(argv[index + 1] || '');
    if (argv[index] === '--ledger') options.ledger = resolve(argv[index + 1] || '');
  }
  return options;
};

const runCli = argv => {
  const options = parseCli(argv);
  const snapshot = readEditorialDatabase(options.database);
  const report = auditPayloadEditorialQuality(snapshot.payloads, snapshot.tools);
  const output = { source: options.database, ...report };
  if (options.ledger) {
    const ledger = JSON.parse(readFileSync(options.ledger, 'utf8'));
    output.ledger = auditReviewLedger(snapshot.payloads, ledger.entries || ledger);
  }
  console.log(JSON.stringify(output, null, 2));
};

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) runCli(process.argv.slice(2));
