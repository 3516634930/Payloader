// CODEC-IMPORTS
import type { SxNativeFn, SxPlainObj, SxValue } from './bases';
// CODEC-IMPORTS-END
export const sxMaxInputLength = 500_000;
export const sxMaxSteps = 400_000;
export const sxMaxParserDepth = 2_000;
export const sxMaxEvalDepth = 64;
export const sxMaxStringLength = 2_000_000;
export const sxMaxExecutions = 16;

class SxHalt extends Error {
  readonly fallback: string;
  constructor(fallback: string) {
    super('sx-halt');
    this.fallback = fallback;
  }
}

class SxError extends Error {}

export const sxIsObj = (value: SxValue): value is SxPlainObj =>
  typeof value === 'object' && value !== null && !Array.isArray(value) && !('kind' in value);

export const sxConstructorName = (object: SxValue): string => {
  if (typeof object === 'string') return 'String';
  if (typeof object === 'number') return 'Number';
  if (typeof object === 'boolean') return 'Boolean';
  if (Array.isArray(object)) return 'Array';
  if (object !== null && typeof object === 'object') {
    if (sxIsObj(object)) return 'Object';
    if (object.kind === 'regex') return 'RegExp';
    return 'Function';
  }
  return 'Function';
};

export const sxToString = (value: SxValue): string => {
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (Array.isArray(value)) return value.map(item => (item === null || item === undefined ? '' : sxToString(item))).join(',');
  if (sxIsObj(value)) return '[object Object]';
  if (value.kind === 'regex') {
    // 与 V8 的 RegExp.prototype.toString 一致：正则源码中的 / 需要转义
    return `/${value.source.replace(/\//g, '\\/')}/${value.flags}`;
  }
  if (value.kind === 'native' || value.kind === 'opaque') return `function ${value.name}() { [native code] }`;
  if (value.kind === 'ctor') return `function ${value.name}() { [native code] }`;
  return 'function () { [native code] }';
};

export const sxToNumber = (value: SxValue): number => {
  if (typeof value === 'number') return value;
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (value === null) return 0;
  if (value === undefined) return Number.NaN;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return 0;
    if (/^[+-]?0x[0-9a-f]+$/i.test(trimmed)) return parseInt(trimmed, 16);
    if (/^[+-]?0[0-7]+$/.test(trimmed)) return parseInt(trimmed, 8);
    if (/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(trimmed)) return Number(trimmed);
    if (trimmed === 'Infinity' || trimmed === '+Infinity') return Number.POSITIVE_INFINITY;
    if (trimmed === '-Infinity') return Number.NEGATIVE_INFINITY;
    return Number.NaN;
  }
  if (Array.isArray(value)) return sxToNumber(sxToString(value));
  return Number.NaN;
};

export const sxToBoolean = (value: SxValue): boolean => {
  if (value === false || value === 0 || value === '' || value === null || value === undefined) return false;
  if (typeof value === 'number' && Number.isNaN(value)) return false;
  return true;
};

export const sxToInt32 = (value: SxValue): number => sxToNumber(value) | 0;

// ToPrimitive：对象类值（数组/对象/函数标记/正则）在 + 运算中先转字符串
export const sxToPrimitive = (value: SxValue): string | number | boolean | undefined | null => {
  if (typeof value === 'object' && value !== null) return sxToString(value);
  return value;
};

export const sxEquals = (left: SxValue, right: SxValue): boolean => {
  if (typeof left === 'string' && typeof right === 'string') return left === right;
  const lPrim = Array.isArray(left) || sxIsObj(left) ? sxToString(left) : left;
  const rPrim = Array.isArray(right) || sxIsObj(right) ? sxToString(right) : right;
  if (typeof lPrim === 'string' || typeof rPrim === 'string') {
    if (typeof lPrim === 'string' && typeof rPrim === 'string') return lPrim === rPrim;
    return sxToNumber(lPrim) === sxToNumber(rPrim);
  }
  if (typeof lPrim === 'boolean' || typeof rPrim === 'boolean') return sxToNumber(lPrim) === sxToNumber(rPrim);
  if (lPrim === null || lPrim === undefined) return lPrim === rPrim || (rPrim === null || rPrim === undefined);
  if (rPrim === null || rPrim === undefined) return false;
  return lPrim === rPrim;
};

// ---- 求值器 AST ----
export type SxNode =
  | { t: 'num'; v: number }
  | { t: 'str'; v: string }
  | { t: 'regex'; source: string; flags: string }
  | { t: 'ident'; name: string }
  | { t: 'this' }
  | { t: 'arr'; items: SxNode[] }
  | { t: 'obj'; entries: Array<{ key: string; value: SxNode }> }
  | { t: 'un'; op: string; operand: SxNode }
  | { t: 'update'; op: string; target: SxNode; prefix: boolean }
  | { t: 'bin'; op: string; left: SxNode; right: SxNode }
  | { t: 'logic'; op: string; left: SxNode; right: SxNode }
  | { t: 'cond'; test: SxNode; consequent: SxNode; alternate: SxNode }
  | { t: 'assign'; target: SxNode; value: SxNode }
  | { t: 'member'; object: SxNode; property: SxNode; computed: boolean; optionalDotName?: string }
  | { t: 'call'; callee: SxNode; args: SxNode[] }
  | { t: 'var'; decls: Array<{ name: string; init?: SxNode }> }
  | { t: 'exprStmt'; expr: SxNode }
  | { t: 'return'; value?: SxNode };

export const sxPunctuators = ['>>>', '===', '!==', '**', '<<', '>>', '<=', '>=', '==', '!=', '&&', '||', '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '+', '-', '*', '/', '%', '!', '~', '^', '&', '|', '<', '>', '=', '?', ':', ';', ',', '.', '(', ')', '[', ']', '{', '}'];

export interface SxToken { type: 'num' | 'str' | 'regex' | 'ident' | 'punct'; value: string; flags?: string }

export const sxIsIdentStart = (ch: string) => /[\p{L}_$]/u.test(ch);
export const sxIsIdentPart = (ch: string) => /[\p{L}\p{N}_$]/u.test(ch);

// 这些关键字之后 / 是正则字面量起点（而非除法）
export const sxRegexPrecedingKeywords = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'case', 'delete', 'void', 'do']);

class SxTokenizer {
  private pos = 0;
  private lastSignificant: SxToken | null = null;
  readonly tokens: SxToken[] = [];
  private readonly source: string;
  constructor(source: string) {
    this.source = source;
  }

  private regexAllowed(): boolean {
    const prev = this.lastSignificant;
    if (!prev) return true;
    if (prev.type === 'num' || prev.type === 'str' || prev.type === 'regex') return false;
    if (prev.type === 'ident') return sxRegexPrecedingKeywords.has(prev.value);
    return prev.value !== ')' && prev.value !== ']' && prev.value !== '++' && prev.value !== '--';
  }

  tokenize(): SxToken[] {
    while (this.pos < this.source.length) {
      const ch = this.source[this.pos];
      if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v' || ch === '\u00a0' || ch === '\ufeff') {
        this.pos += 1;
        continue;
      }
      if (ch === '/' && this.source[this.pos + 1] === '/') {
        while (this.pos < this.source.length && this.source[this.pos] !== '\n') this.pos += 1;
        continue;
      }
      if (ch === '/' && this.source[this.pos + 1] === '*') {
        const end = this.source.indexOf('*/', this.pos + 2);
        if (end < 0) throw new SxError('未闭合的块注释');
        this.pos = end + 2;
        continue;
      }
      if (ch === '/' && this.regexAllowed()) {
        this.readRegex();
        continue;
      }
      if (ch === '"' || ch === "'") {
        this.readString(ch);
        continue;
      }
      if (/\d/.test(ch) || (ch === '.' && /\d/.test(this.source[this.pos + 1] || ''))) {
        this.readNumber();
        continue;
      }
      if (sxIsIdentStart(ch)) {
        let end = this.pos + 1;
        while (end < this.source.length && sxIsIdentPart(this.source[end])) end += 1;
        this.push({ type: 'ident', value: this.source.slice(this.pos, end) });
        this.pos = end;
        continue;
      }
      const punct = sxPunctuators.find(p => this.source.startsWith(p, this.pos));
      if (!punct) throw new SxError(`无法识别的字符: ${ch}`);
      this.push({ type: 'punct', value: punct });
      this.pos += punct.length;
    }
    return this.tokens;
  }

  private push(token: SxToken) {
    this.lastSignificant = token;
    this.tokens.push(token);
  }

  private readRegex(): SxToken {
    const start = this.pos + 1;
    let i = start;
    let inClass = false;
    for (; i < this.source.length; i += 1) {
      const ch = this.source[i];
      if (ch === '\\') { i += 1; continue; }
      if (ch === '[') inClass = true;
      else if (ch === ']') inClass = false;
      else if (ch === '/' && !inClass) break;
      else if (ch === '\n') throw new SxError('正则字面量未闭合');
    }
    if (i >= this.source.length) throw new SxError('正则字面量未闭合');
    const source = this.source.slice(start, i);
    let flagsEnd = i + 1;
    while (flagsEnd < this.source.length && /[a-z]/.test(this.source[flagsEnd])) flagsEnd += 1;
    const flags = this.source.slice(i + 1, flagsEnd);
    this.pos = flagsEnd;
    const token: SxToken = { type: 'regex', value: source, flags };
    this.push(token);
    return token;
  }

  private readString(quote: string): SxToken {
    this.pos += 1;
    let out = '';
    while (this.pos < this.source.length && this.source[this.pos] !== quote) {
      const ch = this.source[this.pos];
      if (ch === '\\') {
        this.pos += 1;
        const esc = this.source[this.pos];
        if (esc === 'n') { out += '\n'; this.pos += 1; }
        else if (esc === 't') { out += '\t'; this.pos += 1; }
        else if (esc === 'r') { out += '\r'; this.pos += 1; }
        else if (esc === 'b') { out += '\b'; this.pos += 1; }
        else if (esc === 'f') { out += '\f'; this.pos += 1; }
        else if (esc === 'v') { out += '\v'; this.pos += 1; }
        else if (esc === '0' && !/\d/.test(this.source[this.pos + 1] || '')) { out += '\0'; this.pos += 1; }
        else if (esc === 'x') { out += String.fromCharCode(parseInt(this.source.slice(this.pos + 1, this.pos + 3), 16)); this.pos += 3; }
        else if (esc === 'u') {
          if (this.source[this.pos + 1] === '{') {
            const end = this.source.indexOf('}', this.pos + 2);
            out += String.fromCodePoint(parseInt(this.source.slice(this.pos + 2, end), 16));
            this.pos = end + 1;
          } else {
            out += String.fromCharCode(parseInt(this.source.slice(this.pos + 1, this.pos + 5), 16));
            this.pos += 5;
          }
        } else if (/[0-7]/.test(esc)) {
          let digits = '';
          while (digits.length < 3 && /[0-7]/.test(this.source[this.pos] || '')) { digits += this.source[this.pos]; this.pos += 1; }
          out += String.fromCharCode(parseInt(digits, 8));
        } else { out += esc; this.pos += 1; }
        continue;
      }
      out += ch;
      this.pos += 1;
    }
    if (this.pos >= this.source.length) throw new SxError('字符串未闭合');
    this.pos += 1;
    const token: SxToken = { type: 'str', value: out };
    this.push(token);
    return token;
  }

  private readNumber(): SxToken {
    let end = this.pos;
    if (this.source[end] === '0' && /[xX]/.test(this.source[end + 1] || '')) {
      end += 2;
      while (end < this.source.length && /[0-9a-fA-F]/.test(this.source[end])) end += 1;
      const token: SxToken = { type: 'num', value: this.source.slice(this.pos, end) };
      this.pos = end;
      this.push(token);
      return token;
    }
    while (end < this.source.length && /\d/.test(this.source[end])) end += 1;
    if (this.source[end] === '.' ) { end += 1; while (end < this.source.length && /\d/.test(this.source[end])) end += 1; }
    if (/[eE]/.test(this.source[end] || '') && /[\d+-]/.test(this.source[end + 1] || '')) {
      end += 1;
      if (/[+-]/.test(this.source[end])) end += 1;
      while (end < this.source.length && /\d/.test(this.source[end])) end += 1;
    }
    const token: SxToken = { type: 'num', value: this.source.slice(this.pos, end) };
    this.pos = end;
    this.push(token);
    return token;
  }
}

class SxParser {
  private pos = 0;
  private depth = 0;
  private readonly tokens: SxToken[];
  constructor(tokens: SxToken[]) {
    this.tokens = tokens;
  }

  private peek(): SxToken | null { return this.tokens[this.pos] ?? null; }
  private next(): SxToken { const token = this.tokens[this.pos]; this.pos += 1; return token; }
  private isPunct(value: string): boolean { const token = this.peek(); return token !== null && token.type === 'punct' && token.value === value; }
  private isIdent(value: string): boolean { const token = this.peek(); return token !== null && token.type === 'ident' && token.value === value; }
  private expectPunct(value: string) { if (!this.isPunct(value)) throw new SxError(`期望 "${value}"，实际为 "${this.peek()?.value ?? 'EOF'}"`); this.next(); }

  parseProgram(): SxNode[] {
    const statements: SxNode[] = [];
    while (this.peek() !== null) {
      if (this.isPunct(';')) { this.next(); continue; }
      if (this.isIdent('var') || this.isIdent('let') || this.isIdent('const')) {
        this.next();
        const decls: Array<{ name: string; init?: SxNode }> = [];
        do {
          const nameToken = this.next();
          if (nameToken.type !== 'ident') throw new SxError('var 声明缺少标识符');
          const decl: { name: string; init?: SxNode } = { name: nameToken.value };
          if (this.isPunct('=')) { this.next(); decl.init = this.parseAssignment(); }
          decls.push(decl);
        } while (this.isPunct(',') && (this.next(), true));
        statements.push({ t: 'var', decls });
        this.expectStatementEnd();
        continue;
      }
      if (this.isIdent('return')) {
        this.next();
        const token = this.peek();
        if (token === null || (token.type === 'punct' && token.value === ';')) {
          this.next();
          statements.push({ t: 'return' });
        } else {
          const value = this.parseExpression();
          statements.push({ t: 'return', value });
          this.expectStatementEnd();
        }
        continue;
      }
      if (this.isIdent('function') || this.isIdent('if') || this.isIdent('for') || this.isIdent('while')) {
        throw new SxError(`静态求值不支持 "${this.next().value}" 语法`);
      }
      const expr = this.parseExpression();
      statements.push({ t: 'exprStmt', expr });
      this.expectStatementEnd();
    }
    return statements;
  }

  private expectStatementEnd() {
    if (this.isPunct(';')) { this.next(); return; }
    if (this.peek() === null) return;
    throw new SxError(`语句后期望 ";"，实际为 "${this.peek()?.value}"`);
  }

  private enter(): boolean {
    this.depth += 1;
    if (this.depth > sxMaxParserDepth) throw new SxError('表达式嵌套深度超出安全上限');
    return true;
  }

  private parseExpression(): SxNode {
    this.enter();
    try {
      const expr = this.parseAssignment();
      if (this.isPunct(',')) throw new SxError('静态求值不支持逗号运算符');
      return expr;
    } finally { this.depth -= 1; }
  }

  private parseAssignment(): SxNode {
    this.enter();
    try {
      const left = this.parseConditional();
      const token = this.peek();
      if (token !== null && token.type === 'punct' && (token.value === '=' || sxCompoundOps.has(token.value))) {
        this.next();
        const value = this.parseAssignment();
        if (left.t !== 'ident' && left.t !== 'member') throw new SxError('赋值目标必须是标识符或成员');
        if (token.value === '=') return { t: 'assign', target: left, value };
        return { t: 'assign', target: left, value: { t: 'bin', op: token.value.slice(0, -1), left, right: value } };
      }
      return left;
    } finally { this.depth -= 1; }
  }

  private parseConditional(): SxNode {
    const test = this.parseBinary(0);
    if (this.isPunct('?')) {
      this.next();
      const consequent = this.parseAssignment();
      this.expectPunct(':');
      const alternate = this.parseAssignment();
      return { t: 'cond', test, consequent, alternate };
    }
    return test;
  }

  private parseBinary(minPrecedence: number): SxNode {
    this.enter();
    try {
      let left = this.parseUnary();
      for (;;) {
        const token = this.peek();
        if (token === null || token.type !== 'punct') break;
        const info = sxBinaryOps[token.value];
        if (!info || info.precedence < minPrecedence) break;
        this.next();
        const right = info.right ? this.parseBinary(info.precedence) : this.parseBinary(info.precedence + 1);
        if (info.logic) left = { t: 'logic', op: token.value, left, right };
        else left = { t: 'bin', op: token.value, left, right };
      }
      return left;
    } finally { this.depth -= 1; }
  }

  private parseUnary(): SxNode {
    this.enter();
    try {
      const token = this.peek();
      if (token !== null && token.type === 'punct' && (token.value === '!' || token.value === '~' || token.value === '+' || token.value === '-')) {
        this.next();
        return { t: 'un', op: token.value, operand: this.parseUnary() };
      }
      if (token !== null && token.type === 'punct' && (token.value === '++' || token.value === '--')) {
        this.next();
        const target = this.parseUnary();
        return { t: 'update', op: token.value, target, prefix: true };
      }
      if (this.isIdent('typeof')) { this.next(); return { t: 'un', op: 'typeof', operand: this.parseUnary() }; }
      if (this.isIdent('new')) {
        this.next();
        const callee = this.parseCallAccess();
        return callee;
      }
      return this.parsePostfix();
    } finally { this.depth -= 1; }
  }

  private parsePostfix(): SxNode {
    const target = this.parseCallAccess();
    if (this.isPunct('++') || this.isPunct('--')) {
      const op = this.next().value;
      return { t: 'update', op, target, prefix: false };
    }
    return target;
  }

  private parseCallAccess(): SxNode {
    let node = this.parsePrimary();
    for (;;) {
      if (this.isPunct('.')) {
        this.next();
        const name = this.next();
        if (name.type !== 'ident') throw new SxError('点号后必须是标识符');
        node = { t: 'member', object: node, property: { t: 'str', v: name.value }, computed: false };
      } else if (this.isPunct('[')) {
        this.next();
        const property = this.parseExpression();
        this.expectPunct(']');
        node = { t: 'member', object: node, property, computed: true };
      } else if (this.isPunct('(')) {
        this.next();
        const args: SxNode[] = [];
        while (!this.isPunct(')')) {
          args.push(this.parseAssignment());
          if (this.isPunct(',')) { this.next(); continue; }
          break;
        }
        this.expectPunct(')');
        node = { t: 'call', callee: node, args };
      } else break;
    }
    return node;
  }

  private parsePrimary(): SxNode {
    const token = this.peek();
    if (token === null) throw new SxError('表达式意外结束');
    if (token.type === 'num') { this.next(); return { t: 'num', v: token.value.startsWith('0x') || token.value.startsWith('0X') ? parseInt(token.value, 16) : Number(token.value) }; }
    if (token.type === 'str') { this.next(); return { t: 'str', v: token.value }; }
    if (token.type === 'regex') { this.next(); return { t: 'regex', source: token.value, flags: token.flags ?? '' }; }
    if (token.type === 'ident') {
      if (token.value === 'true') { this.next(); return { t: 'un', op: '!', operand: { t: 'un', op: '!', operand: { t: 'arr', items: [] } } }; }
      if (token.value === 'false') { this.next(); return { t: 'un', op: '!', operand: { t: 'arr', items: [] } }; }
      if (token.value === 'null') { this.next(); return { t: 'ident', name: 'null' }; }
      if (token.value === 'this') { this.next(); return { t: 'this' }; }
      this.next();
      return { t: 'ident', name: token.value };
    }
    if (this.isPunct('(')) {
      this.next();
      const expr = this.parseExpression();
      this.expectPunct(')');
      return expr;
    }
    if (this.isPunct('[')) {
      this.next();
      const items: SxNode[] = [];
      while (!this.isPunct(']')) {
        items.push(this.parseAssignment());
        if (this.isPunct(',')) { this.next(); continue; }
        break;
      }
      this.expectPunct(']');
      return { t: 'arr', items };
    }
    if (this.isPunct('{')) {
      this.next();
      const entries: Array<{ key: string; value: SxNode }> = [];
      while (!this.isPunct('}')) {
        const keyToken = this.next();
        let key: string;
        if (keyToken.type === 'ident' || keyToken.type === 'str' || keyToken.type === 'num') key = keyToken.value;
        else throw new SxError(`对象字面量键不支持: ${keyToken.value}`);
        this.expectPunct(':');
        entries.push({ key, value: this.parseAssignment() });
        if (this.isPunct(',')) { this.next(); continue; }
        break;
      }
      this.expectPunct('}');
      return { t: 'obj', entries };
    }
    throw new SxError(`意外的记号: ${token.value}`);
  }
}

export const sxBinaryOps: Record<string, { precedence: number; logic?: boolean; right?: boolean }> = {
  '||': { precedence: 1, logic: true },
  '&&': { precedence: 2, logic: true },
  '|': { precedence: 3 },
  '^': { precedence: 4 },
  '&': { precedence: 5 },
  '==': { precedence: 6 }, '!=': { precedence: 6 }, '===': { precedence: 6 }, '!==': { precedence: 6 },
  '<': { precedence: 7 }, '>': { precedence: 7 }, '<=': { precedence: 7 }, '>=': { precedence: 7 },
  '<<': { precedence: 8 }, '>>': { precedence: 8 }, '>>>': { precedence: 8 },
  '+': { precedence: 9 }, '-': { precedence: 9 },
  '*': { precedence: 10 }, '/': { precedence: 10 }, '%': { precedence: 10 },
};

export const sxCompoundOps = new Set(['+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=', '>>>=']);

// 真实存在但静态求值不支持调用的方法名：仍可被字符串化/取 constructor（与 V8 一致），调用则报错
export const sxStringStubMethods = new Set(['anchor', 'big', 'blink', 'bold', 'fixed', 'link', 'small', 'strike', 'sub', 'sup', 'toLocaleLowerCase', 'toLocaleUpperCase', 'localeCompare', 'normalize', 'match', 'matchAll', 'search', 'replaceAll', 'isWellFormed', 'toWellFormed']);
export const sxArrayStubMethods = new Set(['copyWithin', 'every', 'fill', 'filter', 'find', 'findIndex', 'findLast', 'findLastIndex', 'flat', 'flatMap', 'forEach', 'includes', 'lastIndexOf', 'map', 'reduce', 'reduceRight', 'shift', 'some', 'sort', 'splice', 'toLocaleString', 'toReversed', 'toSorted', 'toSpliced', 'unshift', 'with']);
export const sxNumberStubMethods = new Set(['toExponential', 'toLocaleString', 'toPrecision']);

class SxReturnSignal {
  readonly value: SxValue;
  constructor(value: SxValue) {
    this.value = value;
  }
}

class SxInterpreter {
  private steps = 0;
  private evalDepth = 0;
  readonly captures: string[] = [];
  private readonly global: Map<string, SxValue> = new Map();
  private readonly natives: Record<string, SxNativeFn> = {};

  constructor() {
    const native = (name: string, call: (args: SxValue[]) => SxValue): SxNativeFn => ({ kind: 'native', name, call });
    this.natives = {
      escape: native('escape', args => sxEscape(sxToString(args[0] ?? ''))),
      unescape: native('unescape', args => sxUnescape(sxToString(args[0] ?? ''))),
      atob: native('atob', args => sxAtob(sxToString(args[0] ?? ''))),
      btoa: native('btoa', args => sxBtoa(sxToString(args[0] ?? ''))),
      decodeURI: native('decodeURI', args => sxDecodePercent(sxToString(args[0] ?? ''), false)),
      decodeURIComponent: native('decodeURIComponent', args => sxDecodePercent(sxToString(args[0] ?? ''), true)),
      encodeURI: native('encodeURI', args => sxEncodePercent(sxToString(args[0] ?? ''), false)),
      encodeURIComponent: native('encodeURIComponent', args => sxEncodePercent(sxToString(args[0] ?? ''), true)),
      parseInt: native('parseInt', args => parseInt(sxToString(args[0] ?? '').trim(), args[1] === undefined ? Number.NaN : sxToNumber(args[1])) || 0),
      parseFloat: native('parseFloat', args => Number.parseFloat(sxToString(args[0] ?? '').trim())),
      isNaN: native('isNaN', args => Number.isNaN(sxToNumber(args[0] ?? Number.NaN))),
      isFinite: native('isFinite', args => Number.isFinite(sxToNumber(args[0] ?? Number.NaN))),
      alert: native('alert', args => { throw new SxHalt(sxToString(args[0] ?? undefined)); }),
      confirm: native('confirm', args => { throw new SxHalt(sxToString(args[0] ?? undefined)); }),
      prompt: native('prompt', args => { throw new SxHalt(sxToString(args[0] ?? undefined)); }),
      String: native('String', args => args.length === 0 ? '' : sxToString(args[0])),
      Number: native('Number', args => args.length === 0 ? 0 : sxToNumber(args[0])),
      Boolean: native('Boolean', args => sxToBoolean(args[0] ?? false)),
      Array: native('Array', () => [] as SxValue[]),
      Object: native('Object', () => ({})),
      RegExp: native('RegExp', args => ({ kind: 'regex', source: args[0] === undefined ? '(?:)' : sxToString(args[0]), flags: args[1] === undefined ? '' : sxToString(args[1]) })),
      Date: native('Date', () => 'Thu Jan 01 1970 00:00:00 GMT+0000 (Coordinated Universal Time)'),
    };
    const globalFns: Record<string, SxValue> = { ...this.natives };
    globalFns.Math = {
      floor: native('floor', args => Math.floor(sxToNumber(args[0] ?? 0))),
      ceil: native('ceil', args => Math.ceil(sxToNumber(args[0] ?? 0))),
      round: native('round', args => Math.round(sxToNumber(args[0] ?? 0))),
      abs: native('abs', args => Math.abs(sxToNumber(args[0] ?? 0))),
      max: native('max', args => Math.max(...args.map(sxToNumber))),
      min: native('min', args => Math.min(...args.map(sxToNumber))),
      pow: native('pow', args => Math.pow(sxToNumber(args[0] ?? 0), sxToNumber(args[1] ?? 0))),
      sqrt: native('sqrt', args => Math.sqrt(sxToNumber(args[0] ?? 0))),
      random: native('random', () => { throw new SxError('Math.random 不可用于静态求值'); }),
    };
    globalFns.console = { log: native('log', () => undefined) };
    globalFns.NaN = Number.NaN;
    globalFns.Infinity = Number.POSITIVE_INFINITY;
    globalFns.undefined = undefined;
    globalFns.null = null;
    globalFns.this = {};
    globalFns.String = this.stringCtor();
    globalFns.Number = this.numberCtor();
    globalFns.Boolean = this.natives.Boolean;
    globalFns.Array = this.natives.Array;
    globalFns.Object = this.natives.Object;
    globalFns.RegExp = this.natives.RegExp;
    globalFns.Date = this.natives.Date;
    for (const [key, value] of Object.entries(globalFns)) this.global.set(key, value);
  }

  private stringCtor(): SxNativeFn {
    return { kind: 'native', name: 'String', call: args => {
      if (args.length === 0) return '';
      return sxToString(args[0]);
    } };
  }

  private numberCtor(): SxNativeFn {
    return { kind: 'native', name: 'Number', call: args => args.length === 0 ? 0 : sxToNumber(args[0]) };
  }

  private step() {
    this.steps += 1;
    if (this.steps > sxMaxSteps) throw new SxError(`求值步数超出 ${sxMaxSteps} 上限`);
  }

  private lookup(name: string): SxValue {
    const value = this.global.get(name);
    if (value === undefined && !this.global.has(name)) {
      if (name === 'null') return null;
      throw new SxError(`未定义的标识符: ${name}（静态求值环境不提供浏览器全局对象）`);
    }
    return value;
  }

  run(source: string): SxValue {
    const tokens = new SxTokenizer(source).tokenize();
    const statements = new SxParser(tokens).parseProgram();
    return this.runStatements(statements, this.global);
  }

  private runStatements(statements: SxNode[], scope: Map<string, SxValue>): SxValue {
    let last: SxValue = undefined;
    for (const statement of statements) {
      this.step();
      if (statement.t === 'var') {
        for (const decl of statement.decls) {
          const value = decl.init ? this.evaluate(decl.init, scope) : undefined;
          scope.set(decl.name, value);
        }
        continue;
      }
      if (statement.t === 'return') {
        const value = statement.value ? this.evaluate(statement.value, scope) : undefined;
        throw new SxReturnSignal(value);
      }
      if (statement.t === 'exprStmt') {
        last = this.evaluate(statement.expr, scope);
        continue;
      }
      last = this.evaluate(statement, scope);
    }
    return last;
  }

  private evaluate(node: SxNode, scope: Map<string, SxValue>): SxValue {
    this.step();
    switch (node.t) {
      case 'num': return node.v;
      case 'str': return node.v;
      case 'regex': return { kind: 'regex', source: node.source, flags: node.flags };
      case 'ident': {
        if (node.name === 'null') return null;
        return this.lookup(node.name);
      }
      case 'this': return scope.get('this') ?? {};
      case 'arr': return node.items.map(item => this.evaluate(item, scope));
      case 'obj': {
        const obj: SxPlainObj = {};
        for (const entry of node.entries) obj[entry.key] = this.evaluate(entry.value, scope);
        return obj;
      }
      case 'un': {
        const value = this.evaluate(node.operand, scope);
        if (node.op === '!') return !sxToBoolean(value);
        if (node.op === '+') return sxToNumber(value);
        if (node.op === '-') return -sxToNumber(value);
        if (node.op === '~') return ~sxToInt32(value);
        if (node.op === 'typeof') {
          if (typeof value === 'object' && value !== null) {
            if ('kind' in value && (value.kind === 'native' || value.kind === 'opaque' || value.kind === 'ctor' || value.kind === 'exec')) return 'function';
            return 'object';
          }
          return typeof value;
        }
        throw new SxError(`不支持的一元运算符: ${node.op}`);
      }
      case 'update': {
        const current = sxToNumber(this.evaluate(node.target, scope));
        const next = node.op === '++' ? current + 1 : current - 1;
        this.assignTo(node.target, next, scope);
        return node.prefix ? next : current;
      }
      case 'bin': return this.binary(node.op, node.left, node.right, scope);
      case 'logic': {
        const left = this.evaluate(node.left, scope);
        if (node.op === '&&') return sxToBoolean(left) ? this.evaluate(node.right, scope) : left;
        return sxToBoolean(left) ? left : this.evaluate(node.right, scope);
      }
      case 'cond': return sxToBoolean(this.evaluate(node.test, scope)) ? this.evaluate(node.consequent, scope) : this.evaluate(node.alternate, scope);
      case 'assign': {
        const value = this.evaluate(node.value, scope);
        this.assignTo(node.target, value, scope);
        return value;
      }
      case 'member': return this.member(this.evaluate(node.object, scope), this.memberKey(node, scope));
      case 'call': return this.call(node, scope);
      default: throw new SxError('不支持的语句位于表达式位置');
    }
  }

  private binary(op: string, leftNode: SxNode, rightNode: SxNode, scope: Map<string, SxValue>): SxValue {
    if (op === ',') { this.evaluate(leftNode, scope); return this.evaluate(rightNode, scope); }
    const left = this.evaluate(leftNode, scope);
    const right = this.evaluate(rightNode, scope);
    switch (op) {
      case '+': {
        const leftPrim = sxToPrimitive(left);
        const rightPrim = sxToPrimitive(right);
        if (typeof leftPrim === 'string' || typeof rightPrim === 'string') {
          return this.concatGuard(sxToString(leftPrim) + sxToString(rightPrim));
        }
        return sxToNumber(leftPrim) + sxToNumber(rightPrim);
      }
      case '-': return sxToNumber(left) - sxToNumber(right);
      case '*': return sxToNumber(left) * sxToNumber(right);
      case '/': return sxToNumber(left) / sxToNumber(right);
      case '%': return sxToNumber(left) % sxToNumber(right);
      case '==': return sxEquals(left, right);
      case '!=': return !sxEquals(left, right);
      case '===': return left === right;
      case '!==': return left !== right;
      case '<': case '>': case '<=': case '>=': {
        const ls = sxToString(left);
        const rs = sxToString(right);
        const bothStrings = typeof left === 'string' && typeof right === 'string';
        if (bothStrings) {
          if (op === '<') return ls < rs;
          if (op === '>') return ls > rs;
          if (op === '<=') return ls <= rs;
          return ls >= rs;
        }
        const ln = sxToNumber(left);
        const rn = sxToNumber(right);
        if (op === '<') return ln < rn;
        if (op === '>') return ln > rn;
        if (op === '<=') return ln <= rn;
        return ln >= rn;
      }
      case '&': return sxToInt32(left) & sxToInt32(right);
      case '|': return sxToInt32(left) | sxToInt32(right);
      case '^': return sxToInt32(left) ^ sxToInt32(right);
      case '<<': return sxToInt32(left) << (sxToInt32(right) & 31);
      case '>>': return sxToInt32(left) >> (sxToInt32(right) & 31);
      case '>>>': return (sxToInt32(left) >>> (sxToInt32(right) & 31)) >>> 0;
      default: throw new SxError(`不支持的运算符: ${op}`);
    }
  }

  private concatGuard(result: SxValue): SxValue {
    if (typeof result === 'string' && result.length > sxMaxStringLength) {
      throw new SxError(`字符串长度超出 ${sxMaxStringLength} 上限`);
    }
    return result;
  }

  private memberKey(node: Extract<SxNode, { t: 'member' }>, scope: Map<string, SxValue>): SxValue {
    if (node.computed) return this.evaluate(node.property, scope);
    return node.property.t === 'str' ? node.property.v : undefined;
  }

  private member(object: SxValue, key: SxValue): SxValue {
    const name = sxToString(key);
    if (object === null || object === undefined) {
      if (name === 'undefined') return undefined;
      throw new SxError(`无法读取 ${sxToString(object)} 的属性 ${name}`);
    }
    // 自有属性优先于 constructor 标记：obfuscator 会用 obj["constructor"]="..." 做遮蔽
    if (sxIsObj(object) && Object.prototype.hasOwnProperty.call(object, name)) return object[name];
    if (name === 'constructor') return { kind: 'ctor', name: sxConstructorName(object) };
    if (typeof object === 'string') return this.stringMember(object, name);
    if (typeof object === 'number') return this.numberMember(object, name);
    if (typeof object === 'boolean') {
      if (name === 'toString') return { kind: 'native', name: 'toString', call: () => sxToString(object) };
      return { kind: 'opaque', name };
    }
    if (Array.isArray(object)) return this.arrayMember(object, name);
    if (sxIsObj(object)) {
      // 只暴露自有属性（3020 已拦截自有命中，走到这里的一律不给继承读）：
      // 继承读会经 __proto__ 把宿主 Object.prototype 泄入求值器，可被写穿造成原型污染
      if (name === 'toString') return { kind: 'native', name: 'toString', call: () => '[object Object]' };
      if (name === 'hasOwnProperty') return { kind: 'native', name: 'hasOwnProperty', call: args => Object.prototype.hasOwnProperty.call(object, sxToString(args[0] ?? '')) };
      return undefined;
    }
    if (object.kind === 'regex') {
      if (name === 'source') return object.source;
      if (name === 'flags') return object.flags;
      if (name === 'toString') return { kind: 'native', name: 'toString', call: () => sxToString(object) };
      if (name === 'test' || name === 'exec') throw new SxError('静态求值不允许执行正则（防 ReDoS）');
      return undefined;
    }
    if (object.kind === 'native' || object.kind === 'opaque') {
      if (name === 'name') return object.name;
      if (object.kind === 'native' && name === 'call') {
        return { kind: 'native', name: 'call', call: args => object.call(args.slice(1)) };
      }
      return undefined;
    }
    if (object.kind === 'ctor') {
      if (name === 'name') return object.name;
      if (object.name === 'String' && (name === 'fromCharCode' || name === 'fromCodePoint')) {
        return { kind: 'native', name, call: args => String.fromCodePoint(...args.map(sxToNumber)) };
      }
      return undefined;
    }
    return undefined;
  }

  private stringMember(self: string, name: string): SxValue {
    const method = (fnName: string, fn: (args: SxValue[]) => SxValue): SxValue => ({ kind: 'native', name: fnName, call: fn });
    if (/^\d+$/.test(name)) {
      const ch = self[Number(name)];
      return ch === undefined ? undefined : ch;
    }
    switch (name) {
      case 'length': return self.length;
      case 'charAt': return method('charAt', args => self.charAt(sxToNumber(args[0] ?? 0)));
      case 'charCodeAt': return method('charCodeAt', args => self.charCodeAt(sxToNumber(args[0] ?? 0)));
      case 'codePointAt': return method('codePointAt', args => { const cp = self.codePointAt(sxToNumber(args[0] ?? 0)); return cp === undefined ? undefined : cp; });
      case 'at': return method('at', args => { const idx = Math.trunc(sxToNumber(args[0] ?? 0)); const resolved = idx < 0 ? self.length + idx : idx; const ch = self[resolved]; return ch === undefined ? undefined : ch; });
      case 'slice': return method('slice', args => self.slice(sxToNumber(args[0] ?? 0), args[1] === undefined ? undefined : sxToNumber(args[1])));
      case 'substring': return method('substring', args => self.substring(sxToNumber(args[0] ?? 0), args[1] === undefined ? undefined : sxToNumber(args[1])));
      case 'substr': return method('substr', args => self.substr(sxToNumber(args[0] ?? 0), args[1] === undefined ? undefined : sxToNumber(args[1])));
      case 'split': return method('split', args => { if (args[0] === undefined) return [self]; return self.split(sxToString(args[0])); });
      case 'concat': return method('concat', args => self.concat(...args.map(sxToString)));
      case 'indexOf': return method('indexOf', args => self.indexOf(sxToString(args[0] ?? ''), args[1] === undefined ? 0 : sxToNumber(args[1])));
      case 'lastIndexOf': return method('lastIndexOf', args => self.lastIndexOf(sxToString(args[0] ?? '')));
      case 'toLowerCase': return method('toLowerCase', () => self.toLowerCase());
      case 'toUpperCase': return method('toUpperCase', () => self.toUpperCase());
      case 'trim': return method('trim', () => self.trim());
      case 'repeat': return method('repeat', args => { const count = sxToNumber(args[0] ?? 0); if (count * self.length > sxMaxStringLength) throw new SxError(`字符串长度超出 ${sxMaxStringLength} 上限`); return self.repeat(count); });
      case 'padStart': return method('padStart', args => { const targetLength = sxToNumber(args[0] ?? 0); if (targetLength > sxMaxStringLength) throw new SxError(`字符串长度超出 ${sxMaxStringLength} 上限`); return self.padStart(targetLength, args[1] === undefined ? ' ' : sxToString(args[1])); });
      case 'padEnd': return method('padEnd', args => { const targetLength = sxToNumber(args[0] ?? 0); if (targetLength > sxMaxStringLength) throw new SxError(`字符串长度超出 ${sxMaxStringLength} 上限`); return self.padEnd(targetLength, args[1] === undefined ? ' ' : sxToString(args[1])); });
      case 'replace': return method('replace', args => self.replace(sxToString(args[0] ?? ''), sxToString(args[1] ?? '')));
      case 'startsWith': return method('startsWith', args => self.startsWith(sxToString(args[0] ?? '')));
      case 'endsWith': return method('endsWith', args => self.endsWith(sxToString(args[0] ?? '')));
      case 'toString': case 'valueOf': return method(name, () => self);
      case 'italics': return method('italics', () => `<i>${self}</i>`);
      case 'bold': return method('bold', () => `<b>${self}</b>`);
      case 'fontcolor': return method('fontcolor', args => {
        const color = sxToString(args[0] ?? '').replace(/"/g, '&quot;');
        return `<font color="${color}">${self}</font>`;
      });
      case 'fontsize': return method('fontsize', args => `<font size="${sxToString(args[0] ?? '')}">${self}</font>`);
      case 'constructor': return { kind: 'ctor', name: 'String' };
      case 'undefined': return undefined;
      default: return sxStringStubMethods.has(name) ? { kind: 'opaque', name } : undefined;
    }
  }

  private numberMember(self: number, name: string): SxValue {
    switch (name) {
      case 'toString': return { kind: 'native', name: 'toString', call: args => { const radix = args[0] === undefined ? 10 : sxToNumber(args[0]); if (!Number.isInteger(radix) || radix < 2 || radix > 36) throw new SxError('toString 进制参数必须是 2-36 的整数'); return self.toString(radix); } };
      case 'toFixed': return { kind: 'native', name: 'toFixed', call: args => self.toFixed(sxToNumber(args[0] ?? 0)) };
      case 'valueOf': return { kind: 'native', name: 'valueOf', call: () => self };
      case 'constructor': return { kind: 'ctor', name: 'Number' };
      default: return sxNumberStubMethods.has(name) ? { kind: 'opaque', name } : undefined;
    }
  }

  private arrayMember(self: SxValue[], name: string): SxValue {
    if (/^\d+$/.test(name)) {
      const element = self[Number(name)];
      return element === undefined ? undefined : element;
    }
    switch (name) {
      case 'length': return self.length;
      case 'join': return { kind: 'native', name: 'join', call: args => self.map(item => (item === null || item === undefined ? '' : sxToString(item))).join(args[0] === undefined ? ',' : sxToString(args[0])) };
      case 'concat': return { kind: 'native', name: 'concat', call: args => self.concat(...args.map(arg => (Array.isArray(arg) ? arg : [arg]))) };
      case 'slice': return { kind: 'native', name: 'slice', call: args => self.slice(sxToNumber(args[0] ?? 0), args[1] === undefined ? undefined : sxToNumber(args[1])) };
      case 'indexOf': return { kind: 'native', name: 'indexOf', call: args => self.indexOf(args[0]) };
      case 'push': return { kind: 'native', name: 'push', call: args => { self.push(...args); return self.length; } };
      case 'pop': return { kind: 'native', name: 'pop', call: () => self.pop() };
      case 'reverse': return { kind: 'native', name: 'reverse', call: () => self.reverse() };
      case 'at': return { kind: 'native', name: 'at', call: args => { const idx = Math.trunc(sxToNumber(args[0] ?? 0)); const resolved = idx < 0 ? self.length + idx : idx; return self[resolved] ?? undefined; } };
      case 'entries': case 'keys': case 'values': {
        // 返回可调用的迭代器工厂：调用产物仅保留 "[object Object]" 字符串化行为
        return { kind: 'native', name, call: () => ({ __sxArrayIterator: true }) };
      }
      case 'toString': return { kind: 'native', name: 'toString', call: () => sxToString(self) };
      case 'constructor': return { kind: 'ctor', name: 'Array' };
      default: return sxArrayStubMethods.has(name) ? { kind: 'opaque', name } : undefined;
    }
  }

  private call(node: Extract<SxNode, { t: 'call' }>, scope: Map<string, SxValue>): SxValue {
    if (this.evalDepth + this.captures.length > sxMaxEvalDepth) throw new SxError('调用嵌套深度超出安全上限');
    const callee = this.evaluate(node.callee, scope);
    const args = node.args.map(arg => this.evaluate(arg, scope));
    return this.invoke(callee, args);
  }

  private invoke(callee: SxValue, args: SxValue[]): SxValue {
    // SxValue 类型层面不含函数，但这是宿主函数经求值路径泄漏的最后调用防线（as never 仅为绕过 TS 恒假比较检查）
    if (typeof callee === 'function' as never) throw new SxError('非法函数值');
    if (callee === undefined || callee === null || typeof callee !== 'object' || Array.isArray(callee) || sxIsObj(callee)) {
      throw new SxError(`尝试调用非函数值: ${sxToString(callee)}`);
    }
    if (callee.kind === 'native') return callee.call(args);
    if (callee.kind === 'opaque') throw new SxError(`静态求值不支持调用 ${callee.name}()`);
    if (callee.kind === 'ctor') {
      const body = args.length === 0 ? '' : sxToString(args[args.length - 1]);
      return { kind: 'exec', body };
    }
    if (callee.kind === 'exec') {
      if (this.captures.length >= sxMaxExecutions) throw new SxError(`执行点数量超出 ${sxMaxExecutions} 上限`);
      const body = callee.body;
      const innerError = this.evalCapturedBody(body);
      if (innerError === null) {
        const result = this.lastBodyResult;
        this.lastBodyResult = undefined;
        return result;
      }
      this.captures.push(body);
      if (innerError instanceof SxHalt) throw new SxHalt(this.captures[this.captures.length - 1] ?? innerError.fallback);
      return undefined;
    }
    throw new SxError('尝试调用不支持的值: kind=' + callee.kind + ' str=' + sxToString(callee).slice(0, 60) + ' keys=' + JSON.stringify(Object.keys(callee)).slice(0, 60));
  }

  private lastBodyResult: SxValue = undefined;

  private evalCapturedBody(body: string): Error | null {
    this.evalDepth += 1;
    try {
      const tokens = new SxTokenizer(body).tokenize();
      const statements = new SxParser(tokens).parseProgram();
      const innerScope = new Map(this.global);
      this.lastBodyResult = this.runStatements(statements, innerScope);
      return null;
    } catch (error) {
      if (error instanceof SxReturnSignal) { this.lastBodyResult = error.value; return null; }
      return error instanceof Error ? error : new SxError('函数体求值失败');
    } finally {
      this.evalDepth -= 1;
    }
  }

  private assignTo(target: SxNode, value: SxValue, scope: Map<string, SxValue>) {
    if (target.t === 'ident') {
      scope.set(target.name, value);
      return;
    }
    if (target.t === 'member') {
      const object = this.evaluate(target.object, scope);
      const key = sxToString(this.memberKey(target, scope));
      if (key === '__proto__') {
        throw new SxError('静态求值禁止写入 __proto__（防原型污染）');
      }
      if (sxIsObj(object)) { object[key] = value; return; }
      if (Array.isArray(object) && /^\d+$/.test(key)) { object[Number(key)] = value; return; }
      throw new SxError('静态求值不支持对原始值属性赋值');
    }
    throw new SxError('非法赋值目标');
  }
}

export const sxBase64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export const sxAtob = (value: string): string => {
  const compact = value.replace(/\s+/g, '');
  if (compact.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) throw new SxError('atob 输入不是合法 Base64');
  let bits = 0;
  let acc = 0;
  const bytes: number[] = [];
  for (const ch of compact) {
    if (ch === '=') break;
    acc = (acc << 6) | sxBase64Chars.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bytes.push((acc >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Array.from(new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes))).join('');
};

export const sxBtoa = (value: string): string => {
  const bytes = new TextEncoder().encode(value);
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b1 = bytes[i];
    const b2 = bytes[i + 1];
    const b3 = bytes[i + 2];
    out += sxBase64Chars[b1 >> 2];
    out += sxBase64Chars[((b1 & 3) << 4) | ((b2 ?? 0) >> 4)];
    out += b2 === undefined ? '=' : sxBase64Chars[((b2 & 15) << 2) | ((b3 ?? 0) >> 6)];
    out += b3 === undefined ? '=' : sxBase64Chars[b3 & 63];
  }
  return out;
};

export const sxEscape = (value: string): string => value.replace(/[^A-Za-z0-9@*_+\-./]/g, ch => {
  const code = ch.charCodeAt(0);
  return code < 256 ? `%${code.toString(16).padStart(2, '0').toUpperCase()}` : `%u${code.toString(16).padStart(4, '0').toUpperCase()}`;
});

export const sxUnescape = (value: string): string => value.replace(/%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})/g, (_, u4, u2) => String.fromCharCode(parseInt(u4 ?? u2, 16)));

export const sxDecodePercent = (value: string, component: boolean): string => {
  const bytes: number[] = [];
  let i = 0;
  while (i < value.length) {
    const ch = value[i];
    if (ch === '%') {
      const hex = value.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new SxError('URI 解码遇到非法百分号序列');
      bytes.push(parseInt(hex, 16));
      i += 3;
      continue;
    }
    const encoded = Array.from(new TextEncoder().encode(ch));
    if (!component && '/;,:@&=+$#?'.includes(ch)) { bytes.push(...encoded); i += 1; continue; }
    if (/[A-Za-z0-9\-_.!~*'()]/.test(ch)) { bytes.push(...encoded); i += 1; continue; }
    bytes.push(...encoded);
    i += 1;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
};

export const sxEncodePercent = (value: string, component: boolean): string => {
  let out = '';
  for (const ch of value) {
    if (/[A-Za-z0-9\-_.!~*'()]/.test(ch) || (!component && '/;,:@&=+$#?'.includes(ch))) { out += ch; continue; }
    for (const byte of new TextEncoder().encode(ch)) out += `%${byte.toString(16).padStart(2, '0').toUpperCase()}`;
  }
  return out;
};

export const sxRun = (source: string, label: string): string => {
  if (!source.trim()) throw new Error(`请输入${label}内容`);
  if (source.length > sxMaxInputLength) throw new Error(`${label}输入超过 ${sxMaxInputLength} 字符上限`);
  const interpreter = new SxInterpreter();
  let finalValue: SxValue = undefined;
  try {
    finalValue = interpreter.run(source);
  } catch (error) {
    if (error instanceof SxHalt) {
      const body = interpreter.captures[interpreter.captures.length - 1];
      return sxPostProcess(body ?? error.fallback ?? '', sxMaxStringLength);
    }
    if (interpreter.captures.length > 0) return sxPostProcess(interpreter.captures[interpreter.captures.length - 1], sxMaxStringLength);
    throw error instanceof Error ? new Error(`${label}静态求值失败: ${error.message}`) : error;
  }
  if (interpreter.captures.length > 0) return sxPostProcess(interpreter.captures[interpreter.captures.length - 1], sxMaxStringLength);
  if (typeof finalValue === 'string') return sxPostProcess(finalValue, sxMaxStringLength);
  throw new Error(`${label}中未定位到可还原的执行点（未发现 Function 构造调用或 alert 类调用）`);
};

export const sxEncodedTextPattern = /\b(atob|unescape)\(\s*(['"])((?:(?!\2).)*)\2\s*\)/g;
export const sxPrintable = (value: string) => {
  if (value.length === 0) return false;
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if ((code >= 0 && code <= 8) || (code >= 14 && code <= 31) || code === 0xfffd) return false;
  }
  return true;
};

export const sxPostProcess = (code: string, maxLength: number): string => {
  const trimmed = code.length > maxLength ? `${code.slice(0, maxLength)}\n…[输出超出长度上限，已截断]` : code;
  const found: string[] = [];
  for (const match of trimmed.matchAll(sxEncodedTextPattern)) {
    try {
      const decoded = match[1] === 'atob' ? sxAtob(match[3]) : sxUnescape(match[3]);
      if (sxPrintable(decoded) && !found.includes(decoded)) found.push(decoded);
    } catch {
      // 无法解码的片段保持原样
    }
  }
  if (found.length === 0) return trimmed;
  return `${trimmed}\n\n=== 内嵌编码文本 ===\n${found.join('\n')}`;
};

export const decodeJsfuck = (value: string) => sxRun(value, 'JSFuck');
export const decodeAaencode = (value: string) => sxRun(value, 'aaencode');
export const decodeJjencode = (value: string) => sxRun(value, 'jjencode');

// 符号类混淆形状独占性极强，必须在 RSA 参数推断等宽泛启发式之前判定
export const trySmartSymbolObfuscation = (value: string): string | null => {
  const compact = value.replace(/\s+/g, '');
  if (compact.length >= 100 && /^[[\]!+()]+$/.test(compact)) {
    try { return decodeJsfuck(value); } catch { /* 非 JSFuck，继续 */ }
  }
  if (/^\$=~\[\];/.test(value.trim())) {
    try { return decodeJjencode(value); } catch { /* 非 jjencode，继续 */ }
  }
  if (value.length >= 80) {
    const marks = (value.match(/[\uFF9F\uFF70\u0414\u0398\u03C9\u03B5]/gu) || []).length;
    if (marks >= 20) {
      try { return decodeAaencode(value); } catch { /* 非 aaencode，继续 */ }
    }
  }
  return null;
};

// ---- jjencode 编码器：逐字移植 utf-8.jp (C) Yosuke Hasegawa 的原始实现 ----
export const encodeJjencodeRaw = (gv: string, text: string): string =>
{
    let r="";
    let n = 0;
    const b=[ "___", "__$", "_$_", "_$$", "$__", "$_$", "$$_", "$$$", "$___", "$__$", "$_$_", "$_$$", "$$__", "$$_$", "$$$_", "$$$$", ];
    let s = "";
    for( let i = 0; i < text.length; i++ ){
        n = text.charCodeAt( i );
        if( n == 0x22 || n == 0x5c ){
            s += "\\\\\\" + text.charAt(i);
        }else if( (0x21 <= n && n <= 0x2f) || (0x3A <= n && n <= 0x40) || ( 0x5b <= n && n <= 0x60 ) || ( 0x7b <= n && n <= 0x7f ) ){
        //}else if( (0x20 <= n && n <= 0x2f) || (0x3A <= n == 0x40) || ( 0x5b <= n && n <= 0x60 ) || ( 0x7b <= n && n <= 0x7f ) ){
            s += text.charAt( i );
        }else if( (0x30 <= n && n <= 0x39 ) || (0x61 <= n && n <= 0x66 ) ){
            if( s ) r += "\"" + s +"\"+";
            r += gv + "." + b[ n < 0x40 ? n - 0x30 : n - 0x57 ] + "+";
            s="";
        }else if( n == 0x6c ){ // 'l'
            if( s ) r += "\"" + s + "\"+";
            r += "(![]+\"\")[" + gv + "._$_]+";
            s = "";
        }else if( n == 0x6f ){ // 'o'
            if( s ) r += "\"" + s + "\"+";
            r += gv + "._$+";
            s = "";
        }else if( n == 0x74 ){ // 'u'
            if( s ) r += "\"" + s + "\"+";
            r += gv + ".__+";
            s = "";
        }else if( n == 0x75 ){ // 'u'
            if( s ) r += "\"" + s + "\"+";
            r += gv + "._+";
            s = "";
        }else if( n < 128 ){
            if( s ) r += "\"" + s;
            else r += "\"";
            r += "\\\\\"+" + n.toString( 8 ).replace( /[0-7]/g, function(c: string){ return gv + "."+b[ Number(c) ]+"+" } );
            s = "";
        }else{
            if( s ) r += "\"" + s;
            else r += "\"";
            r += "\\\\\"+" + gv + "._+" + n.toString(16).replace( /[0-9a-f]/gi, function(c){ return gv + "."+b[parseInt(c,16)]+"+"} );
            s = "";
        }
    }
    if( s ) r += "\"" + s + "\"+";

    r = 
    gv + "=~[];" + 
    gv + "={___:++" + gv +",$$$$:(![]+\"\")["+gv+"],__$:++"+gv+",$_$_:(![]+\"\")["+gv+"],_$_:++"+
    gv+",$_$$:({}+\"\")["+gv+"],$$_$:("+gv+"["+gv+"]+\"\")["+gv+"],_$$:++"+gv+",$$$_:(!\"\"+\"\")["+
    gv+"],$__:++"+gv+",$_$:++"+gv+",$$__:({}+\"\")["+gv+"],$$_:++"+gv+",$$$:++"+gv+",$___:++"+gv+",$__$:++"+gv+"};"+
    gv+".$_="+
    "("+gv+".$_="+gv+"+\"\")["+gv+".$_$]+"+
    "("+gv+"._$="+gv+".$_["+gv+".__$])+"+
    "("+gv+".$$=("+gv+".$+\"\")["+gv+".__$])+"+
    "((!"+gv+")+\"\")["+gv+"._$$]+"+
    "("+gv+".__="+gv+".$_["+gv+".$$_])+"+
    "("+gv+".$=(!\"\"+\"\")["+gv+".__$])+"+
    "("+gv+"._=(!\"\"+\"\")["+gv+"._$_])+"+
    gv+".$_["+gv+".$_$]+"+
    gv+".__+"+
    gv+"._$+"+
    gv+".$;"+
    gv+".$$="+
    gv+".$+"+
    "(!\"\"+\"\")["+gv+"._$$]+"+
    gv+".__+"+
    gv+"._+"+
    gv+".$+"+
    gv+".$$;"+
    gv+".$=("+gv+".___)["+gv+".$_]["+gv+".$_];"+
    gv+".$("+gv+".$("+gv+".$$+\"\\\"\"+" + r + "\"\\\"\")())();";

    return r;
}

export const encodeAaencodeRaw = (text: string): string =>
{
    let t = "";
    let n = 0;
    const b = [
		"(c^_^o)",
		"(ﾟΘﾟ)",
		"((o^_^o) - (ﾟΘﾟ))",
		"(o^_^o)",
		"(ﾟｰﾟ)",
		"((ﾟｰﾟ) + (ﾟΘﾟ))",
		"((o^_^o) +(o^_^o))",
		"((ﾟｰﾟ) + (o^_^o))",
		"((ﾟｰﾟ) + (ﾟｰﾟ))",
		"((ﾟｰﾟ) + (ﾟｰﾟ) + (ﾟΘﾟ))",
		"(ﾟДﾟ) .ﾟωﾟﾉ",
		"(ﾟДﾟ) .ﾟΘﾟﾉ",
		"(ﾟДﾟ) ['c']",
		"(ﾟДﾟ) .ﾟｰﾟﾉ",
		"(ﾟДﾟ) .ﾟДﾟﾉ",
		"(ﾟДﾟ) [ﾟΘﾟ]"
        ];
	let r = "ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); "; 
	
	if( /ひだまりスケッチ×(365|３５６)\s*来週も見てくださいね[!！]/.test( text ) ){
		r += "X=_=3; ";
		r += "\r\n\r\n    X / _ / X < \"来週も見てくださいね!\";\r\n\r\n";
	}
    r += "(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);"+
        "(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] "+
        ",ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] "+
        ",ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];"+
        "(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];"+
        "(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];"+
        "(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + "+
        "((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+"+
        "((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+"+
        "((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+"+
        "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];"+
        "(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+"+
        "((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+"+
        "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; "+
        "(ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\\\'; "+
        "(ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];"+ 
		"(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];"+//TODO
        "(ﾟДﾟ) [ﾟoﾟ]='\\\"';"+ 
        "(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+";
    r += "(ﾟДﾟ)[ﾟoﾟ]+ ";
    for( let i = 0; i < text.length; i++ ){
        n = text.charCodeAt( i );
        t = "(ﾟДﾟ)[ﾟεﾟ]+";
		if( n <= 127 ){
			t += n.toString( 8 ).replace( /[0-7]/g, function(c: string){ return b[ Number(c) ] + "+ "; } );
		}else{
			const m = (/[0-9a-f]{4}$/.exec( "000" + n.toString(16 ) ) || [""])[0];
			t += "(oﾟｰﾟo)+ " + m.replace( /[0-9a-f]/gi, function(c){ return b[ parseInt( c,16 ) ] + "+ "; } );
		}
        r += t;

    }
    r += "(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');";
    return r;


};

// encode 侧同样设上限：JSFuck 最坏膨胀 ~3600x/字符，线性编码器 ~8x，防主线程长时间阻塞
export const sxMaxEncodeInputLength = 20_000;
export const sxMaxLinearEncodeInputLength = 200_000;

export const encodeJjencode = (value: string) => {
  if (value.length > sxMaxLinearEncodeInputLength) throw new SxError(`jjencode 编码输入超过 ${sxMaxLinearEncodeInputLength} 字符上限`);
  return encodeJjencodeRaw("$", value);
};

export const encodeAaencode = (value: string) => {
  if (value.length > sxMaxLinearEncodeInputLength) throw new SxError(`aaencode 编码输入超过 ${sxMaxLinearEncodeInputLength} 字符上限`);
  return encodeAaencodeRaw(value);
};

// ---- JSFuck 编码器：移植自 aemkei/jsfuck 0.5.0 (MIT, http://jsfuck.com)，仅保留纯字符串构建路径 ----
// 上游 escapeSequenceForReplace/split-join 优化路径依赖真实 RegExp 执行，静态求值下不可用，已按等义简化
let jsfuckEncoder: ((input: string, wrapWithEval: boolean) => string) | null = null;

export const buildJsfuckEncoder = (): (input: string, wrapWithEval: boolean) => string => {
  if (jsfuckEncoder) return jsfuckEncoder;
    const MIN = 32, MAX = 126;
  
    const SIMPLE: Record<string, string> = {
      'false':      '![]',
      'true':       '!![]',
      'undefined':  '[][[]]',
      'NaN':        '+[![]]',
      'Infinity':   '+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]]+[+[]])' // +"1e1000"
    };
  
    const CONSTRUCTORS: Record<string, string> = {
      'Array':    '[]',
      'Number':   '(+[])',
      'String':   '([]+[])',
      'Boolean':  '(![])',
      'Function': '[]["at"]',
      'RegExp':   'Function("return/"+false+"/")()'
    };
  
    const MAPPING: Record<string | number, string | null> = {
      'a':   '(false+"")[1]',
      'b':   '([]["entries"]()+"")[2]',
      'c':   '([]["at"]+"")[3]',
      'd':   '(undefined+"")[2]',
      'e':   '(true+"")[3]',
      'f':   '(false+"")[0]',
      'g':   '(false+[0]+String)[20]',
      'h':   '(+(101))["to"+String["name"]](21)[1]',
      'i':   '([false]+undefined)[10]',
      'j':   '([]["entries"]()+"")[3]',
      'k':   '(+(20))["to"+String["name"]](21)',
      'l':   '(false+"")[2]',
      'm':   '(Number+"")[11]',
      'n':   '(undefined+"")[1]',
      'o':   '(true+[]["at"])[10]',
      'p':   '(+(211))["to"+String["name"]](31)[1]',
      'q':   '("")["fontcolor"]([0]+false+")[20]',
      'r':   '(true+"")[1]',
      's':   '(false+"")[3]',
      't':   '(true+"")[0]',
      'u':   '(undefined+"")[0]',
      'v':   '(+(31))["to"+String["name"]](32)',
      'w':   '(+(32))["to"+String["name"]](33)',
      'x':   '(+(101))["to"+String["name"]](34)[1]',
      'y':   '(NaN+[Infinity])[10]',
      'z':   '(+(35))["to"+String["name"]](36)',
  
      'A':   '(NaN+[]["entries"]())[11]',
      'B':   '(+[]+Boolean)[10]',
      'C':   'Function("return escape")()(("")["italics"]())[2]',
      'D':   'Function("return escape")()([]["at"])["at"]("-1")',
      'E':   '(RegExp+"")[12]',
      'F':   '(+[]+Function)[10]',
      'G':   '(false+Function("return Date")()())[30]',
      'H':   null,
      'I':   '(Infinity+"")[0]',
      'J':   null,
      'K':   null,
      'L':   null,
      'M':   '(true+Function("return Date")()())[30]',
      'N':   '(NaN+"")[0]',
      'O':   null,
      'P':   null,
      'Q':   null,
      'R':   '(+[]+RegExp)[10]',
      'S':   '(+[]+String)[10]',
      'T':   '(NaN+Function("return Date")()())[30]',
      'U':   null,
      'V':   null,
      'W':   null,
      'X':   null,
      'Y':   null,
      'Z':   null,
  
      ' ':   '(NaN+[]["at"])[11]',
      '!':   null,
      '"':   '("")["fontcolor"]()[12]',
      '#':   null,
      '$':   null,
      '%':   'Function("return escape")()([]["at"])[22]',
      '&':   '("")["fontcolor"](")[13]',
      '\'':  null,
      '(':   '([]["at"]+"")[11]',
      ')':   '(""+[]["at"])[12]',
      '*':   null,
      '+':   '(+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]])+[])[2]',
      ',':   '[[]]["concat"]([[]])+""',
      '-':   '(+(.+[0000001])+"")[2]',
      '.':   '(+(+!+[]+[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+[!+[]+!+[]]+[+[]])+[])[+!+[]]',
      '/':   '(false+[0])["italics"]()[10]',
      ':':   '(RegExp()+"")[3]',
      ';':   '("")["fontcolor"](NaN+")[21]',
      '<':   '("")["italics"]()[0]',
      '=':   '("")["fontcolor"]()[11]',
      '>':   '("")["italics"]()[2]',
      '?':   '(RegExp()+"")[2]',
      '@':   null,
      '[':   '([]["entries"]()+"")[0]',
      '\\':  '(RegExp("/")+"")[1]',
      ']':   '([]["entries"]()+"")[22]',
      '^':   null,
      '_':   null,
      '`':   null,
      '{':   '([0]+false+[]["at"])[20]',
      '|':   null,
      '}':   '([]["at"]+"")["at"]("-1")',
      '~':   null
    };
  
    const GLOBAL = 'Function("return this")()';
  
    function fillMissingDigits(){
      let output = ""; let number = 0; let i = 0;
  
      for (number = 0; number < 10; number++){
  
        output = "+[]";
  
        if (number > 0){ output = "+!" + output; }
        for (i = 1; i < number; i++){ output = "+!+[]" + output; }
        if (number > 1){ output = output.substr(1); }
  
        MAPPING[number] = "[" + output + "]";
      }
    }
  
    function replaceMap(){
      let character = ""; let value: string | null = ""; let i = 0; let key: string;

      function replace(pattern: string, replacement: string | ((substring: string, ...rest: string[]) => string)) {
        const escaped = new RegExp(pattern, "gi");
        if (typeof replacement === "function") {
          value = String(value).replace(escaped, replacement);
        } else {
          value = String(value).replace(escaped, replacement);
        }
      }
  
      function digitReplacer(_x: string, x: string) { return MAPPING[x] ?? ""; }
  
      function numberReplacer(_a: string, y: string) {
        const values = y.split("");
        const head = Number(values.shift());
        let output = "+[]";
  
        if (head > 0){ output = "+!" + output; }
        for (i = 1; i < head; i++){ output = "+!+[]" + output; }
        if (head > 1){ output = output.substr(1); }
  
        return [output].concat(values).join("+").replace(/(\d)/g, (d: string) => digitReplacer(d, d));
      }
  
      for (i = MIN; i <= MAX; i += 1){
        character = String.fromCharCode(i);
        value = MAPPING[character];
        if(!value) {continue;}
  
        for (key of Object.keys(CONSTRUCTORS)){
          replace("\\b" + key, CONSTRUCTORS[key] + '["constructor"]');
        }
  
        for (key in SIMPLE){
          replace(key, SIMPLE[key]);
        }
  
        replace('(\\d\\d+)', numberReplacer);
        replace('\\((\\d)\\)', digitReplacer);
        replace('\\[(\\d)\\]', digitReplacer);
  
        replace("GLOBAL", GLOBAL);
        replace('\\+""', "+[]");
        replace('""', "[]+[]");
  
        MAPPING[character] = value;
      }
    }
  
    function replaceStrings(){
      const regEx = /[^[\]()!+]{1}/g;
      let all = "";
      let value: string | null = "";
      let missing: Record<string, string> = {};
      let count = MAX - MIN;

      function findMissing(): boolean{
        let all = "";
        let value: string | null = "";
        let done = false;

        missing = {};

        for (all of Object.keys(MAPPING)){
          value = MAPPING[all];

          if (value && value.match(regEx)){
            missing[all] = value;
            done = true;
          }
        }

        return done;
      }

      function mappingReplacer(_a: string, b: string) {
        return b.split("").join("+");
      }

      function valueReplacer(c: string) {
        const hit = missing[c] ? c : MAPPING[c];
        return hit ?? "";
      }

      for (all of Object.keys(MAPPING)){
        const current = MAPPING[all];
        if (current){
          MAPPING[all] = current.replace(/"([^"]+)"/gi, mappingReplacer);
        }
      }

      while (findMissing()){
        for (all in missing){
          value = MAPPING[all];
          value = (value ?? "").replace(regEx, valueReplacer);

          MAPPING[all] = value;
          missing[all] = value;
        }

        if (count-- === 0){
          throw new SxError("JSFuck 映射构建失败");
        }
      }
    }
  
    function escapeSequence(c: string) {
      const cc = c.charCodeAt(0);
      if (cc < 256) {
        return '\\' + cc.toString(8);
      } else {
        const cc16 = cc.toString(16);
        return '\\u' + ('0000' + cc16).substring(cc16.length);  
      }
    }
  
    function escapeSequenceForReplace(c: string) {
      return escapeSequence(c).replace('\\', 't');
    }
  
    function encode(input: string, wrapWithEval: boolean, runInParentScope?: boolean): string{
      const parts: string[] = [];
      let output = "";
  
      if (!input){
        return "";
      }
  
      let unmappped: string | RegExp = ''
      for(const k in MAPPING) {
        if (MAPPING[k]){
          unmappped += k;
        }
      }
      unmappped = unmappped.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      unmappped = new RegExp('[^' + unmappped + ']','g');
      const unmappedCharactersCount = (input.match(unmappped) || []).length;
      if (unmappedCharactersCount > 1) {
        // Without this optimization one unmapped character has encoded length
        // of about 3600 characters. Every additional unmapped character adds 
        // 2000 to the total length. For example, the length of `~` is 3605,
        // `~~` is 5600, and `~~~` is 7595.
        // 
        // The loader with replace has encoded length of about 5300 characters
        // and every additional character adds 100 to the total length. 
        // In the same example the length of `~~` becomes 5371 and `~~~` -- 5463.
        // 
        // So, when we have more than one unmapped character we want to encode whole input
        // except select characters (that have encoded length less than about 70)
        // into an escape sequence.
        //
        // NOTE: `t` should be escaped!
        input = input.replace(/[^0123456789.adefilnrsuN]/g, escapeSequenceForReplace);
      } else if (unmappedCharactersCount > 0) {
        //Because we will wrap the input into a string we need to escape Backslash 
        // and Double quote characters (we do not need to worry about other characters 
        // because they are not mapped explicitly).
        // The JSFuck-encoded representation of `\` is 2121 symbols,
        // so escaped `\` is 4243 symbols and escaped `"` is 2261 symbols
        // however the escape sequence of that characters are 
        // 2168 and 2155 symbols respectively, so it's more practical to 
        // rewrite them as escape sequences.
        input = input.replace(/["\\]/g, escapeSequence);
        //Convert all unmapped characters to escape sequence
        input = input.replace(unmappped, escapeSequence);
      }
  
      let r = "";
      for (const si of Object.keys(SIMPLE))
      {
        r += si + "|";
      }
      r+= ".";
  
      input.replace(new RegExp(r, 'g'), (c: string): string => {
        let replacement = SIMPLE[c];
        if (replacement) {
          parts.push("(" + replacement + "+[])");
        } else {
          replacement = MAPPING[c] ?? "";
          if (replacement) {
            parts.push(replacement);
          } else {
            // 未映射字符按需自愈：String.fromCharCode 等价式补映射，保证编解码闭环
            const selfHealed = "([]+[])[" + encode('constructor', false) + "][" + encode('fromCharCode', false) + "](" + encode(String(c.charCodeAt(0)), false) + ")";
            MAPPING[c] = selfHealed;
            parts.push(selfHealed);
          }
        }
        return "";
      });
  
      output = parts.join("+");
  
      if (/^\d$/.test(input)){
        output += "+[]";
      }
  
      if (unmappedCharactersCount > 1) {
        // replace `t` with `\\`
        output = "(" + output + ")[" + encode("split", false) + "](" + encode("t", false) + ")[" + encode("join", false) +"](" + encode("\\", false) + ")";
      }
  
      if (unmappedCharactersCount > 0) {
        output = "[][" + encode("at", false) + "]"+
        "[" + encode("constructor", false) + "]" +
        "(" + encode("return\"", false) + "+" + output + "+" + encode("\"", false) + ")()";
      }
  
      if (wrapWithEval){
        if (runInParentScope){
          output = "[][" + encode("at", false) + "]" +
            "[" + encode("constructor", false) + "]" +
            "(" + encode("return eval", false) + ")()" +
            "(" + output + ")";
        } else {
          output = "[][" + encode("at", false) + "]" +
            "[" + encode("constructor", false) + "]" +
            "(" + output + ")()";
        }
      }
  
      return output;
    }
  
    fillMissingDigits();
    replaceMap();
    replaceStrings();
      // 上游 0.5.0 的 \ 映射展开后依赖真实 RegExp 调用链（静态不可求值），此处以等价的
      // String.fromCharCode(92) 纯符号表达式重建，行为与原义一致
      MAPPING['\\'] = '([]+[])[' + encode('constructor', false) + '][' + encode('fromCharCode', false) + '](' + encode('9', false) + '+' + encode('2', false) + ')';
  
      // 自愈：全可打印 ASCII 单字符往返校验，失败映射以 String.fromCharCode 等价式重建
      // （上游 0.5.0 部分 entry 展开后在 V8 中语义破损，如 & : ; ? A ] q，自愈保证编解码闭环）
      for (let healCode = 32; healCode <= 126; healCode += 1) {
        const healCh = String.fromCharCode(healCode);
        const before = MAPPING[healCh];
        if (before === null || before === undefined) continue;
        let ok = false;
        try {
          ok = decodeJsfuck(encode(healCh, false)) === healCh;
        } catch {
          ok = false;
        }
        if (!ok) {
          MAPPING[healCh] = '([]+[])[' + encode('constructor', false) + '][' + encode('fromCharCode', false) + '](' + encode(String(healCode), false) + ')';
        }
      }
  
    
  jsfuckEncoder = encode;
  return encode;
};

export const encodeJsfuck = (value: string): string => {
  if (value.length > sxMaxEncodeInputLength) throw new SxError(`JSFuck 编码输入超过 ${sxMaxEncodeInputLength} 字符上限`);
  return buildJsfuckEncoder()(value, true);
};





