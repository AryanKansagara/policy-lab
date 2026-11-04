// HuJSON (JSON with comments + trailing commas) parser that keeps source spans
// for every value so rules can be highlighted back in the editor.

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json }
export interface Span { start: number; end: number }
export interface ParseError { message: string; offset: number; line: number; col: number }
export interface ParseResult {
  value?: Json
  error?: ParseError
  spans: Map<string, Span> // path ("acls.3.src.0") -> value span
  keySpans: Map<string, Span> // path -> span of the key string
  duplicates: { path: string; span: Span }[]
}

export function lineCol(text: string, offset: number) {
  let line = 1
  let last = -1
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) { line++; last = i }
  return { line, col: offset - last }
}

class Fail extends Error {
  offset: number
  constructor(message: string, offset: number) {
    super(message)
    this.offset = offset
  }
}

export function parseHuJSON(text: string): ParseResult {
  const spans = new Map<string, Span>()
  const keySpans = new Map<string, Span>()
  const duplicates: { path: string; span: Span }[] = []
  let i = 0

  const ws = () => {
    for (;;) {
      const c = text[i]
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '﻿') i++
      else if (c === '/' && text[i + 1] === '/') {
        while (i < text.length && text[i] !== '\n') i++
      } else if (c === '/' && text[i + 1] === '*') {
        const end = text.indexOf('*/', i + 2)
        if (end < 0) throw new Fail('Unterminated block comment', i)
        i = end + 2
      } else return
    }
  }

  const describe = (c: string | undefined) => (c === undefined ? 'end of input' : `'${c}'`)

  const str = (): string => {
    const start = i
    i++ // opening quote
    let out = ''
    for (;;) {
      if (i >= text.length) throw new Fail('Unterminated string', start)
      const c = text[i]
      if (c === '"') { i++; return out }
      if (c === '\n') throw new Fail('Newline inside string (missing closing quote?)', i)
      if (c === '\\') {
        const e = text[i + 1]
        const map: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
        if (e in map) { out += map[e]; i += 2 }
        else if (e === 'u' && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) {
          out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16))
          i += 6
        } else throw new Fail(`Invalid escape '\\${e ?? ''}'`, i)
      } else { out += c; i++ }
    }
  }

  const value = (path: string): Json => {
    ws()
    const start = i
    const c = text[i]
    let v: Json
    if (c === '{') {
      i++
      const obj: Record<string, Json> = {}
      ws()
      while (text[i] !== '}') {
        if (text[i] !== '"') throw new Fail(`Expected a quoted key or '}' but found ${describe(text[i])}`, i)
        const ks = i
        const k = str()
        const kp = path ? `${path}.${k}` : k
        if (Object.prototype.hasOwnProperty.call(obj, k)) duplicates.push({ path: kp, span: { start: ks, end: i } })
        keySpans.set(kp, { start: ks, end: i })
        ws()
        if (text[i] !== ':') throw new Fail(`Expected ':' after key "${k}" but found ${describe(text[i])}`, i)
        i++
        obj[k] = value(kp)
        ws()
        if (text[i] === ',') { i++; ws() }
        else if (text[i] !== '}') throw new Fail(`Expected ',' or '}' but found ${describe(text[i])} (missing comma?)`, i)
      }
      i++
      v = obj
    } else if (c === '[') {
      i++
      const arr: Json[] = []
      ws()
      while (text[i] !== ']') {
        if (i >= text.length) throw new Fail("Expected ']' but reached end of input", start)
        arr.push(value(path ? `${path}.${arr.length}` : String(arr.length)))
        ws()
        if (text[i] === ',') { i++; ws() }
        else if (text[i] !== ']') throw new Fail(`Expected ',' or ']' but found ${describe(text[i])} (missing comma?)`, i)
      }
      i++
      v = arr
    } else if (c === '"') v = str()
    else if (c === '-' || (c >= '0' && c <= '9')) {
      const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i))
      if (!m) throw new Fail('Invalid number', i)
      i += m[0].length
      v = Number(m[0])
    } else if (text.startsWith('true', i)) { i += 4; v = true }
    else if (text.startsWith('false', i)) { i += 5; v = false }
    else if (text.startsWith('null', i)) { i += 4; v = null }
    else if (c === "'") throw new Fail('Strings must use double quotes', i)
    else throw new Fail(`Unexpected ${describe(c)}`, i)
    spans.set(path, { start, end: i })
    return v
  }

  try {
    const v = value('')
    ws()
    if (i < text.length) throw new Fail(`Unexpected ${describe(text[i])} after the top-level value`, i)
    return { value: v, spans, keySpans, duplicates }
  } catch (e) {
    if (!(e instanceof Fail)) throw e
    const { line, col } = lineCol(text, e.offset)
    return { error: { message: e.message, offset: e.offset, line, col }, spans, keySpans, duplicates }
  }
}

// Syntax tokens for the editor overlay.
export type Tok = { t: 'str' | 'key' | 'num' | 'kw' | 'com' | 'pun' | 'ws' | 'sel'; s: string }

export function tokenize(text: string): Tok[] {
  const out: Tok[] = []
  const re = /(\/\/[^\n]*|\/\*[\s\S]*?(?:\*\/|$))|("(?:[^"\\\n]|\\.)*"?)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(true|false|null)|([{}[\]:,])|(\s+)|(.)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text))) {
    if (m[1]) out.push({ t: 'com', s: m[1] })
    else if (m[2]) {
      const after = /^\s*:/.test(text.slice(re.lastIndex, re.lastIndex + 40))
      const sel = /^"(group|tag|autogroup|ipset|user|localpart|svc):/.test(m[2])
      out.push({ t: after ? 'key' : sel ? 'sel' : 'str', s: m[2] })
    } else if (m[3]) out.push({ t: 'num', s: m[3] })
    else if (m[4]) out.push({ t: 'kw', s: m[4] })
    else if (m[5]) out.push({ t: 'pun', s: m[5] })
    else out.push({ t: 'ws', s: m[6] ?? m[7] })
  }
  return out
}
