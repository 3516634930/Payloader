import { getText } from './i18n';
import type { Language } from './i18n';
import type { PayloadItem, ToolCommand } from './types';

export interface SearchIndex {
  payloadEntries: readonly SearchEntry[];
  toolEntries: readonly SearchEntry[];
}

export interface SearchMatches {
  payloadIds: ReadonlySet<string>;
  toolIds: ReadonlySet<string>;
}

interface SearchEntry {
  id: string;
  text: string;
}

const searchableText = (values: Array<string | undefined>) => values
  .filter((value): value is string => Boolean(value))
  .join('\n')
  .toLowerCase();

const payloadSearchText = (payload: PayloadItem, language: Language) => searchableText([
  getText(payload.name, language),
  getText(payload.description, language),
  getText(payload.category, language),
  getText(payload.subCategory, language),
  ...payload.tags,
  ...(payload.prerequisites || []).map(item => getText(item, language)),
  ...payload.execution.flatMap(command => [
    getText(command.title, language),
    getText(command.description, language),
    command.command,
  ]),
  ...(payload.wafBypass || []).flatMap(command => [
    getText(command.title, language),
    getText(command.description, language),
    command.command,
  ]),
]);

const toolSearchText = (tool: ToolCommand, language: Language) => searchableText([
  getText(tool.name, language),
  getText(tool.description, language),
  getText(tool.category, language),
  ...tool.commands.flatMap(command => [
    getText(command.name, language),
    getText(command.description, language),
    command.command,
  ]),
]);

const matchingIds = (entries: readonly SearchEntry[], normalizedQuery: string) => new Set(entries
  .filter(entry => entry.text.includes(normalizedQuery))
  .map(entry => entry.id));

export const buildSearchIndex = (
  payloads: PayloadItem[],
  tools: ToolCommand[],
  language: Language,
): SearchIndex => ({
  payloadEntries: payloads.map(payload => ({ id: payload.id, text: payloadSearchText(payload, language) })),
  toolEntries: tools.map(tool => ({ id: tool.id, text: toolSearchText(tool, language) })),
});

export const matchSearchIndex = (index: SearchIndex, query: string): SearchMatches => {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return { payloadIds: new Set(), toolIds: new Set() };
  }

  return {
    payloadIds: matchingIds(index.payloadEntries, normalizedQuery),
    toolIds: matchingIds(index.toolEntries, normalizedQuery),
  };
};
