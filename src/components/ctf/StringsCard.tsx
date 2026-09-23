import { useMemo, useState } from 'react';
import { notifications } from '@mantine/notifications';
import { FlagAutoText } from '../codec/FlagAutoText';
import { extractStrings } from '../../utils/ctf/fileDetect';
import { downloadBytes } from './ffDownload';

interface StringsCardProps {
  fileName: string;
  bytes: Uint8Array;
  // loadFile 全量提取的总条数（minLength=4），用于头部计数展示。
  language: 'zh' | 'en';
}

const STRINGS_EXTRACT_LIMIT = 20000;
const STRINGS_PAGE_SIZE = 200;
const STRINGS_PAGINATION_THRESHOLD = 500;

// 可读字符串卡：搜索过滤（子串大小写不敏感）、最小长度 4/6/8（重跑提取）、
// 复制全部、导出 txt、超过阈值分页。过滤/翻页状态属于卡片局部，换文件由父组件 key remount 重置。
function StringsCard({ fileName, bytes, language }: StringsCardProps) {
  const zh = language === 'zh';
  const [query, setQuery] = useState('');
  const [minLength, setMinLength] = useState(4);
  const [page, setPage] = useState(0);

  const values = useMemo(() => {
    if (minLength === 4) {
      // loadFile 的提取与 minLength=4 相同参数，直接复用避免重跑。
      return extractStrings(bytes, { limit: STRINGS_EXTRACT_LIMIT }).values;
    }
    return extractStrings(bytes, { minLength, limit: STRINGS_EXTRACT_LIMIT }).values;
  }, [bytes, minLength]);

  // lowercase 一次性预算：避免每次按键对全部条目（可达数万条）重复 toLowerCase。
  const loweredValues = useMemo(() => values.map(value => value.toLowerCase()), [values]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return values;
    const hits: string[] = [];
    for (let index = 0; index < loweredValues.length; index += 1) {
      if (loweredValues[index].includes(q)) hits.push(values[index]);
    }
    return hits;
  }, [values, loweredValues, query]);

  const paged = filtered.length > STRINGS_PAGINATION_THRESHOLD;
  const pageCount = Math.max(1, Math.ceil(filtered.length / STRINGS_PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const visible = useMemo(
    () => (paged ? filtered.slice(safePage * STRINGS_PAGE_SIZE, (safePage + 1) * STRINGS_PAGE_SIZE) : filtered),
    [filtered, paged, safePage],
  );

  const exportStrings = (mode: 'copy' | 'download') => {
    if (filtered.length === 0) return;
    const text = filtered.join('\n');
    if (mode === 'copy') {
      void navigator.clipboard.writeText(text).then(
        () => notifications.show({ message: zh ? `已复制 ${filtered.length} 条字符串。` : `Copied ${filtered.length} strings.`, color: 'teal', autoClose: 1600 }),
        () => notifications.show({ message: zh ? '复制失败，请改用导出。' : 'Copy failed; use export instead.', color: 'red' }),
      );
      return;
    }
    downloadBytes(new TextEncoder().encode(text), `${fileName.replace(/\.[^.]+$/, '')}-strings.txt`);
  };

  return (
    <section id="ff-card-strings" className="ff-card" aria-label={zh ? '可读字符串' : 'Strings'}>
      <div className="ff-card-head">
        <strong>{zh ? `可读字符串（${values.length} 条）` : `Strings (${values.length})`}</strong>
      </div>
      <div className="ff-controls">
        <input
          className="ff-input"
          type="search"
          value={query}
          placeholder={zh ? '搜索子串（大小写不敏感）' : 'Search substring (case-insensitive)'}
          aria-label={zh ? '搜索字符串' : 'Search strings'}
          onChange={event => {
            setQuery(event.target.value);
            setPage(0);
          }}
        />
        <select
          className="ff-select"
          value={minLength}
          aria-label={zh ? '最小长度' : 'Minimum length'}
          onChange={event => {
            setMinLength(Number(event.target.value));
            setPage(0);
          }}
        >
          {[4, 6, 8].map(length => (
            <option key={length} value={length}>{zh ? `最小长度 ${length}` : `min ${length}`}</option>
          ))}
        </select>
        <button type="button" className="ff-button" onClick={() => exportStrings('copy')}>{zh ? '复制全部' : 'Copy all'}</button>
        <button type="button" className="ff-button" onClick={() => exportStrings('download')}>{zh ? '导出 txt' : 'Export txt'}</button>
      </div>
      <p className="ff-note">
        {query.trim()
          ? (zh ? `匹配 ${filtered.length} / 共 ${values.length} 条。` : `${filtered.length} of ${values.length} strings match.`)
          : (zh ? `共 ${values.length} 条。` : `${values.length} strings in total.`)}
      </p>
      <div className="ff-strings">
        {visible.map((value, index) => (
          <code key={`${safePage}-${index}-${value}`} className="ff-code"><FlagAutoText text={value.length > 160 ? `${value.slice(0, 160)}…` : value} /></code>
        ))}
        {filtered.length === 0 && (
          <span className="ff-note">{zh ? '没有匹配当前条件的字符串。' : 'No strings match the current filters.'}</span>
        )}
      </div>
      {paged && (
        <div className="ff-row">
          <button type="button" className="ff-button" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>{zh ? '上一页' : 'Prev'}</button>
          <span className="ff-note">{zh ? `第 ${safePage + 1} / ${pageCount} 页` : `Page ${safePage + 1} / ${pageCount}`}</span>
          <button type="button" className="ff-button" disabled={safePage >= pageCount - 1} onClick={() => setPage(safePage + 1)}>{zh ? '下一页' : 'Next'}</button>
        </div>
      )}
    </section>
  );
}

export default StringsCard;
