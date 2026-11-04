import { useEffect, useMemo, useRef, type KeyboardEvent, type ReactNode } from 'react'
import { lineCol, tokenize } from './hujson.ts'

export type Tone = 'hit' | 'near' | 'err' | 'info'
export interface Mark { start: number; end: number; tone: Tone; inline?: boolean }
const LINE = 20
const RANK: Tone[] = ['info', 'near', 'hit', 'err']

function renderLines(text: string, marks: Mark[]) {
  const inline = marks.filter((m) => m.inline).sort((a, b) => a.start - b.start)
  const tones = new Map<number, Tone>()
  for (const m of marks) {
    if (m.inline) continue
    const a = lineCol(text, m.start).line
    const b = lineCol(text, Math.max(m.start, m.end - 1)).line
    for (let l = a; l <= b; l++) {
      const cur = tones.get(l)
      if (!cur || RANK.indexOf(m.tone) > RANK.indexOf(cur)) tones.set(l, m.tone)
    }
  }
  const lines: ReactNode[][] = [[]]
  let off = 0
  let key = 0
  const emit = (t: string, s: string, start: number) => {
    // Split a same-line piece at inline-mark boundaries.
    const cuts = new Set([0, s.length])
    for (const m of inline) {
      if (m.start > start && m.start < start + s.length) cuts.add(m.start - start)
      if (m.end > start && m.end < start + s.length) cuts.add(m.end - start)
    }
    const c = [...cuts].sort((a, b) => a - b)
    for (let i = 0; i + 1 < c.length; i++) {
      const piece = s.slice(c[i], c[i + 1])
      const mark = inline.find((m) => m.start <= start + c[i] && m.end >= start + c[i + 1])
      lines[lines.length - 1].push(<span key={key++} className={`t-${t}${mark ? ` mk-${mark.tone}` : ''}`}>{piece}</span>)
    }
  }
  for (const tok of tokenize(text)) {
    const parts = tok.s.split('\n')
    parts.forEach((part, i) => {
      if (i > 0) { lines.push([]); off++ }
      if (part) emit(tok.t, part, off)
      off += part.length
    })
  }
  return { lines, tones }
}

export function Editor({ value, onChange, marks = [], revealOffset, revealNonce, label, peek }: {
  value: string
  onChange?: (v: string) => void
  marks?: Mark[]
  revealOffset?: number
  revealNonce?: string | number
  label: string
  peek?: boolean
}) {
  const ta = useRef<HTMLTextAreaElement>(null)
  const over = useRef<HTMLDivElement>(null)
  const gut = useRef<HTMLDivElement>(null)
  const escaped = useRef(false)
  const { lines, tones } = useMemo(() => renderLines(value, marks), [value, marks])

  const sync = () => {
    const el = ta.current
    if (!el) return
    if (over.current) over.current.style.transform = `translate(${-el.scrollLeft}px, ${-el.scrollTop}px)`
    if (gut.current) gut.current.style.transform = `translateY(${-el.scrollTop}px)`
  }
  useEffect(sync, [value])
  useEffect(() => {
    const el = ta.current
    if (!el || revealOffset === undefined) return
    const { line } = lineCol(value, revealOffset)
    // Only scrolls the editor's own textarea, never the page.
    el.scrollTop = Math.max(0, (line - 3) * LINE)
    sync()
  }, [revealNonce])

  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    // Tab indents; Esc then Tab leaves the editor so keyboard users are not trapped.
    if (e.key === 'Escape') { escaped.current = true; return }
    if (e.key === 'Tab' && !e.shiftKey && !escaped.current) {
      e.preventDefault()
      document.execCommand('insertText', false, '  ')
    }
    escaped.current = false
  }

  return (
    <div className={`editor${peek ? ' peek' : ''}`}>
      <div className="ed-gutter" aria-hidden="true">
        <div ref={gut} className="ed-gutter-in">
          {lines.map((_, i) => <div key={i} className={tones.get(i + 1) ? `gl gl-${tones.get(i + 1)}` : 'gl'}>{i + 1}</div>)}
        </div>
      </div>
      <div className="ed-body">
        <div className="ed-overlay" ref={over} aria-hidden="true">
          {lines.map((l, i) => <div key={i} className={tones.get(i + 1) ? `ln ln-${tones.get(i + 1)}` : 'ln'}>{l.length ? l : ' '}</div>)}
        </div>
        <textarea
          ref={ta}
          className="ed-input"
          aria-label={label}
          aria-hidden={peek || undefined}
          tabIndex={peek ? -1 : undefined}
          readOnly={peek || !onChange}
          value={value}
          wrap="off"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          onChange={(e) => onChange?.(e.target.value)}
          onScroll={sync}
          onKeyDown={onKey}
        />
      </div>
    </div>
  )
}
